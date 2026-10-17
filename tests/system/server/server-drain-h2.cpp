/**
 * @file qbm/http/tests/system/server/server-drain-h2.cpp
 * @brief The HTTP/2 server's drain(deadline) over real TLS sockets (Huly QB-91).
 *
 * drain() closes the listener and ends each HTTP/2 connection in two phases (RFC 9113 section 6.8): a GOAWAY
 * naming the largest stream id and a PING, then, on the PING's ACK, the final GOAWAY naming the last stream the
 * client opened. A stream opened between the two is served, one above the final id is refused, and a peer that
 * never answers the PING is ended at the deadline with the final GOAWAY. A connection that reaches HTTP/2 during
 * the drain serves nothing: its only GOAWAY names stream 0.
 *
 * The drain is started from a route, so it runs on the server's loop. Most clients are raw TLS sockets that speak
 * HTTP/2 frame by frame -- what goes over the wire is what is asserted, and a raw client can leave a PING
 * unanswered; one case runs the module's own HTTP/2 client against the drain.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <qb/io/async.h>
#include <qb/io/tcp/ssl/socket.h>

#include <qbm/http/http.h>

#include "../../shared/http2_fake_io.h"
#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

using namespace std::chrono_literals;

namespace server_drain_h2_test {

namespace h2 = qb::protocol::http2;

using H2Server       = qb::http2::Server<>;
using H2ServerThread = qb::http::test::ServerThread<H2Server>;
using H2Context      = std::shared_ptr<qb::http::Context<qb::http2::DefaultSession>>;

/// What the drain reported: -1 before it ends, then the drain_outcome's value; how many times it ran.
std::atomic<int> g_outcome{-1};
std::atomic<int> g_reports{0};
/// The requests that reached `/count`.
std::atomic<int> g_counted{0};

void
reset_globals() {
    g_outcome = -1;
    g_reports = 0;
    g_counted = 0;
}

bool
wait_for_report(std::chrono::milliseconds budget = 5000ms) {
    const auto end = std::chrono::steady_clock::now() + budget;
    while (g_reports.load() == 0 && std::chrono::steady_clock::now() < end)
        std::this_thread::sleep_for(1ms);
    return g_reports.load() != 0;
}

/// The bytes a raw client sends, built with the shared frame writers (they append to `input`).
struct Wire {
    qb::allocator::pipe<char> input;
};

/// One frame a raw client received.
struct Frame {
    std::uint8_t              type      = 0;
    std::uint8_t              flags     = 0;
    std::uint32_t             stream_id = 0;
    std::vector<std::uint8_t> payload;
};

struct Goaway {
    std::uint32_t last_stream_id = 0;
    std::uint32_t error          = 0;
};

[[nodiscard]] std::uint32_t
be32(std::uint8_t const *p) {
    return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) | std::uint32_t{p[3]};
}

/// A raw HTTP/2 client over TLS: it sends the frames a test writes and keeps every byte the server sends.
class H2RawClient {
    qb::io::tcp::ssl::socket _sock;
    std::string              _received;

    void
    send(Wire const &wire) {
        std::size_t off  = 0;
        const auto  size = wire.input.size();
        const auto  end  = std::chrono::steady_clock::now() + 5s;
        while (off < size && std::chrono::steady_clock::now() < end) {
            const int n = _sock.write(wire.input.cbegin() + off, size - off);
            if (n > 0)
                off += static_cast<std::size_t>(n);
            else if (n < 0)
                return;
            else
                std::this_thread::sleep_for(1ms);
        }
    }

public:
    bool connected = false;
    bool closed    = false; ///< The server ended the connection (EOF or an error)

    /**
     * @param port      The server's port.
     * @param alpn      The one protocol offered.
     * @param handshake Whether to run the TLS handshake now; otherwise only the TCP connection is made, and
     *                  complete_handshake() runs it later.
     */
    explicit H2RawClient(std::uint16_t port, std::string const &alpn = "h2", bool handshake = true) {
        _sock.set_insecure();
        (void) _sock.set_alpn_protocols({alpn});
        if (handshake) {
            connected = _sock.connect_v4("127.0.0.1", port) == 0 && _sock.handshake_complete();
            if (connected)
                _sock.set_nonblocking(true);
        } else {
            // A connect in progress answers non-zero on some systems (Windows): the handshake tells.
            connected = _sock.n_connect_v4("127.0.0.1", port) == 0 || _sock.is_open();
        }
    }

    bool
    complete_handshake(std::chrono::milliseconds budget = 5000ms) {
        const auto end = std::chrono::steady_clock::now() + budget;
        while (std::chrono::steady_clock::now() < end) {
            const int status = _sock.handshake_status();
            if (status == 1) {
                _sock.set_nonblocking(true);
                return true;
            }
            if (status < 0)
                return false;
            std::this_thread::sleep_for(1ms);
        }
        return false;
    }

    [[nodiscard]] std::string
    alpn() {
        return _sock.get_alpn_selected_protocol();
    }

    /// The client preface and an empty SETTINGS.
    void
    preface() {
        Wire wire;
        qb::http::test::push_preface(wire);
        qb::http::test::push_frame(wire, h2::FrameType::SETTINGS, 0, 0, {});
        send(wire);
    }

    void
    get(std::uint32_t stream_id, std::string const &path) {
        Wire wire;
        qb::http::test::push_frame(wire, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, stream_id,
                                   qb::http::test::encode_hpack_headers(qb::http::test::default_request_headers(path)));
        send(wire);
    }

    void
    ping_ack(std::vector<std::uint8_t> const &data) {
        Wire wire;
        qb::http::test::push_frame(wire, h2::FrameType::PING, h2::FLAG_ACK, 0, data);
        send(wire);
    }

    /// Reads until @p done holds, the connection ends, or @p budget elapses.
    template <typename Pred>
    void
    read_until(Pred &&done, std::chrono::milliseconds budget = 5000ms) {
        char       buffer[16384];
        const auto end = std::chrono::steady_clock::now() + budget;
        while (!done() && !closed && std::chrono::steady_clock::now() < end) {
            const int got = _sock.read(buffer, sizeof(buffer));
            if (got > 0) {
                _received.append(buffer, static_cast<std::size_t>(got));
                continue;
            }
            if (got < 0) {
                closed = true;
                break;
            }
            std::this_thread::sleep_for(1ms);
        }
    }

    void
    read_to_close(std::chrono::milliseconds budget = 5000ms) {
        read_until([] { return false; }, budget);
    }

    [[nodiscard]] std::size_t
    bytes_received() const {
        return _received.size();
    }

    /// The complete frames received so far.
    [[nodiscard]] std::vector<Frame>
    frames() const {
        std::vector<Frame> out;
        auto const        *data = reinterpret_cast<std::uint8_t const *>(_received.data());
        std::size_t        off  = 0;
        while (off + 9 <= _received.size()) {
            const std::size_t length = (std::size_t{data[off]} << 16) | (std::size_t{data[off + 1]} << 8) | data[off + 2];
            if (off + 9 + length > _received.size())
                break;
            Frame frame;
            frame.type      = data[off + 3];
            frame.flags     = data[off + 4];
            frame.stream_id = be32(data + off + 5) & 0x7FFFFFFFu;
            frame.payload.assign(data + off + 9, data + off + 9 + length);
            out.push_back(std::move(frame));
            off += 9 + length;
        }
        return out;
    }

    [[nodiscard]] std::vector<Goaway>
    goaways() const {
        std::vector<Goaway> out;
        for (auto const &frame : frames()) {
            if (frame.type == static_cast<std::uint8_t>(h2::FrameType::GOAWAY) && frame.payload.size() >= 8)
                out.push_back({be32(frame.payload.data()) & 0x7FFFFFFFu, be32(frame.payload.data() + 4)});
        }
        return out;
    }

    /// The data of the first PING the server sent (not an ACK).
    [[nodiscard]] std::optional<std::vector<std::uint8_t>>
    ping() const {
        for (auto const &frame : frames()) {
            if (frame.type == static_cast<std::uint8_t>(h2::FrameType::PING) && (frame.flags & h2::FLAG_ACK) == 0)
                return frame.payload;
        }
        return std::nullopt;
    }

    /// Whether a response on @p stream_id has ended (a HEADERS or DATA frame with END_STREAM).
    [[nodiscard]] bool
    stream_ended(std::uint32_t stream_id) const {
        for (auto const &frame : frames()) {
            const bool carries =
                frame.type == static_cast<std::uint8_t>(h2::FrameType::HEADERS) || frame.type == static_cast<std::uint8_t>(h2::FrameType::DATA);
            if (carries && frame.stream_id == stream_id && (frame.flags & h2::FLAG_END_STREAM))
                return true;
        }
        return false;
    }

    /// The error code of a RST_STREAM the server sent on @p stream_id.
    [[nodiscard]] std::optional<std::uint32_t>
    reset_of(std::uint32_t stream_id) const {
        for (auto const &frame : frames()) {
            if (frame.type == static_cast<std::uint8_t>(h2::FrameType::RST_STREAM) && frame.stream_id == stream_id && frame.payload.size() == 4)
                return be32(frame.payload.data());
        }
        return std::nullopt;
    }

    void
    close() {
        _sock.close();
    }
};

/// An HTTP/2 server whose routes start the drain: `/ping` answers, `/count` counts, `/slow?ms=N` answers N ms later,
/// `/drain?ms=N` drains with an N ms deadline, then answers.
class DrainH2Server {
public:
    std::unique_ptr<H2ServerThread> thread;
    std::uint16_t                   port = 0;

    DrainH2Server() {
        reset_globals();
        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();
        thread                 = std::make_unique<H2ServerThread>([] { return qb::http2::make_server(); },
                                                                  [cert, key](H2Server &srv) -> bool {
                                                      auto tls = qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"});
                                                      if (!tls.ok())
                                                          return false;
                                                      srv.transport().init(std::move(tls));
                                                      srv.router().get("/ping", [](H2Context ctx) { ctx->text("pong"); });
                                                      srv.router().get("/count", [](H2Context ctx) {
                                                          ++g_counted;
                                                          ctx->text("counted");
                                                      });
                                                      srv.router().get("/slow", [](H2Context ctx) {
                                                          const auto ms = std::stoi(ctx->request().query_or("ms", "300"));
                                                          qb::io::async::callback([ctx] { ctx->text("slow"); }, std::chrono::milliseconds(ms));
                                                      });
                                                      srv.router().get("/drain", [&srv](H2Context ctx) {
                                                          const auto ms = std::stoi(ctx->request().query_or("ms", "5000"));
                                                          srv.drain(std::chrono::milliseconds(ms), [](qb::http::drain_outcome outcome) {
                                                              g_outcome = static_cast<int>(outcome);
                                                              ++g_reports;
                                                          });
                                                          ctx->text("draining");
                                                      });
                                                      srv.router().compile();
                                                      if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                                                          return false;
                                                      srv.start();
                                                      return true;
                                                                  });
        if (thread->ready())
            port = thread->port();
    }
};

constexpr std::uint32_t kLargestStreamId = 0x7FFFFFFFu;
constexpr std::uint32_t kNoError         = 0x0;
constexpr std::uint32_t kRefusedStream   = 0x7;

} // namespace server_drain_h2_test

using namespace server_drain_h2_test;

// A stream the client opens after the notice, before it answers the PING, is served, and the final GOAWAY names it;
// a stream opened after the final GOAWAY, above its id, is refused and never reaches the router. The connection
// closes once the last stream is answered, and the drain reports `drained`.
TEST(Http2ServerDrain, AStreamOpenedBetweenTheGoawaysIsServedAndOneAboveTheFinalIdIsRefused) {
    ASSERT_TRUE(qb::http::test::certs_available());
    DrainH2Server server;
    ASSERT_NE(server.port, 0);

    H2RawClient client(server.port);
    ASSERT_TRUE(client.connected);
    ASSERT_EQ(client.alpn(), "h2");
    client.preface();
    client.get(1, "/drain?ms=5000");
    client.read_until([&] { return client.ping().has_value(); });
    const auto ping = client.ping();
    ASSERT_TRUE(ping.has_value()) << "the notice's PING";
    auto goaways = client.goaways();
    ASSERT_EQ(goaways.size(), 1u);
    EXPECT_EQ(goaways[0].last_stream_id, kLargestStreamId) << "the notice names the largest stream id";
    EXPECT_EQ(goaways[0].error, kNoError);

    client.get(3, "/slow?ms=400"); // after the notice, before the PING's ACK
    client.ping_ack(*ping);
    client.read_until([&] { return client.goaways().size() >= 2; });
    goaways = client.goaways();
    ASSERT_EQ(goaways.size(), 2u) << "the PING's ACK sends the final GOAWAY";
    EXPECT_EQ(goaways[1].last_stream_id, 3u) << "it names the stream opened between the two";
    EXPECT_EQ(goaways[1].error, kNoError);

    client.get(5, "/count");
    client.read_until([&] { return client.reset_of(5).has_value(); });
    EXPECT_EQ(client.reset_of(5), kRefusedStream) << "a stream above the final id is refused";

    client.read_until([&] { return client.stream_ended(3); });
    EXPECT_TRUE(client.stream_ended(3)) << "the stream opened between the GOAWAYs is answered";
    EXPECT_TRUE(client.stream_ended(1));
    client.read_to_close();
    EXPECT_TRUE(client.closed) << "the connection closes after its last stream";
    client.close();

    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::drained));
    EXPECT_EQ(g_reports.load(), 1);
    EXPECT_EQ(g_counted.load(), 0) << "the refused stream never reached the router";
}

// A peer that never answers the PING stays in the notice; the deadline sends it the final GOAWAY -- naming the last
// stream it opened -- and closes the connection. The drain reports `deadline`, not before it.
TEST(Http2ServerDrain, APeerThatNeverAnswersThePingIsEndedAtTheDeadline) {
    ASSERT_TRUE(qb::http::test::certs_available());
    DrainH2Server server;
    ASSERT_NE(server.port, 0);

    H2RawClient client(server.port);
    ASSERT_TRUE(client.connected);
    const auto started = std::chrono::steady_clock::now();
    client.preface();
    client.get(1, "/drain?ms=300");
    client.read_until([&] { return client.ping().has_value() && client.stream_ended(1); });
    ASSERT_TRUE(client.ping().has_value());
    ASSERT_EQ(client.goaways().size(), 1u);

    client.read_to_close(); // the PING is never answered
    EXPECT_TRUE(client.closed) << "the deadline closes the connection";
    const auto goaways = client.goaways();
    ASSERT_EQ(goaways.size(), 2u) << "after the final GOAWAY";
    EXPECT_EQ(goaways[1].last_stream_id, 1u);
    EXPECT_EQ(goaways[1].error, kNoError);
    client.close();

    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::deadline));
    EXPECT_GE(std::chrono::steady_clock::now() - started, 250ms) << "not before the deadline";
}

// A connection accepted before the drain whose TLS handshake ends during it serves nothing: its one GOAWAY names
// stream 0 -- no stream of its was processed -- its request never reaches the router, and it closes.
TEST(Http2ServerDrain, AConnectionThatReachesHttp2DuringTheDrainServesNothing) {
    ASSERT_TRUE(qb::http::test::certs_available());
    DrainH2Server server;
    ASSERT_NE(server.port, 0);

    H2RawClient late(server.port, "h2", /*handshake=*/false);
    ASSERT_TRUE(late.connected);
    std::this_thread::sleep_for(100ms); // accepted; its TLS handshake has not begun

    H2RawClient caller(server.port);
    ASSERT_TRUE(caller.connected);
    caller.preface();
    caller.get(1, "/drain?ms=5000");
    caller.read_until([&] { return caller.ping().has_value() && caller.stream_ended(1); });
    ASSERT_TRUE(caller.ping().has_value());
    caller.ping_ack(*caller.ping());

    ASSERT_TRUE(late.complete_handshake());
    EXPECT_EQ(late.alpn(), "h2");
    late.preface();
    late.get(1, "/count");
    late.read_to_close();
    EXPECT_TRUE(late.closed);
    const auto goaways = late.goaways();
    ASSERT_EQ(goaways.size(), 1u) << "no notice: the final GOAWAY at once";
    EXPECT_EQ(goaways[0].last_stream_id, 0u) << "no stream of the client's was processed";
    EXPECT_EQ(goaways[0].error, kNoError);
    late.close();

    caller.read_to_close();
    caller.close();
    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::drained));
    EXPECT_EQ(g_counted.load(), 0) << "the late connection's request never reached the router";
}

// An HTTP/1.1 connection of the ALPN fallback that has received nothing is closed by the drain, without a byte.
TEST(Http2ServerDrain, AnIdleHttp1FallbackConnectionIsClosed) {
    ASSERT_TRUE(qb::http::test::certs_available());
    DrainH2Server server;
    ASSERT_NE(server.port, 0);

    H2RawClient idle(server.port, "http/1.1");
    ASSERT_TRUE(idle.connected);
    EXPECT_EQ(idle.alpn(), "http/1.1");
    std::this_thread::sleep_for(100ms);

    H2RawClient caller(server.port);
    ASSERT_TRUE(caller.connected);
    caller.preface();
    caller.get(1, "/drain?ms=5000");
    caller.read_until([&] { return caller.ping().has_value() && caller.stream_ended(1); });
    ASSERT_TRUE(caller.ping().has_value());
    caller.ping_ack(*caller.ping());

    idle.read_to_close();
    EXPECT_TRUE(idle.closed) << "the idle fallback connection is closed";
    EXPECT_EQ(idle.bytes_received(), 0u) << "and nothing is sent on it";
    idle.close();

    caller.read_to_close();
    caller.close();
    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::drained));
}

// The module's own HTTP/2 client against the drain: it answers the PING, the requests it sent are all answered, the
// connection closes, and the drain reports `drained`.
TEST(Http2ServerDrain, TheModuleClientsRequestsAreAllAnswered) {
    ASSERT_TRUE(qb::http::test::certs_available());
    qb::io::async::init();
    DrainH2Server server;
    ASSERT_NE(server.port, 0);

    const std::string base   = "https://localhost:" + std::to_string(server.port);
    auto              client = std::make_shared<qb::http2::Client>(base);
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);

    std::atomic<int>   answered{0};
    qb::http::Response slow;
    qb::http::Response draining;
    qb::http::Request  slow_request{{base + "/slow?ms=300"}};
    qb::http::Request  drain_request{{base + "/drain?ms=5000"}};
    ASSERT_TRUE(client->push_request(std::move(slow_request), [&](qb::http::Response r) {
        slow = std::move(r);
        ++answered;
    }));
    ASSERT_TRUE(client->push_request(std::move(drain_request), [&](qb::http::Response r) {
        draining = std::move(r);
        ++answered;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(H2ServerThread::pump_until([&] { return answered.load() == 2; }, 10s));
    EXPECT_EQ(slow.status(), qb::http::status::OK);
    EXPECT_EQ(slow.body().as<std::string>(), "slow");
    EXPECT_EQ(draining.status(), qb::http::status::OK);

    ASSERT_TRUE(H2ServerThread::pump_until([&] { return g_reports.load() == 1; }, 10s));
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::drained));
    client->disconnect();
}

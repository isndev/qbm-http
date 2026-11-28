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
 * The last delivery -- the final GOAWAY the deadline sends -- has qb-io's linger bound, counted from the deadline
 * (Huly QB-1248): the cases at the end of the file hold a client that takes a little at a time to it, leave a delivery
 * completed within it its lingering close, extract a session during it, and end one in the pass of the bound.
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
#include "../../shared/http2_raw_client.h"
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

[[nodiscard]] bool
wait_for_report(std::chrono::milliseconds budget = 5000ms, std::source_location const where = std::source_location::current()) {
    qb::http::test::fail_wait::called_from const caller{where};
    return qb::http::test::wait_until([&] { return g_reports.load() != 0; }, budget, "wait_until", qb::http::test::fail_wait::nap{1ms});
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
    send(Wire const &wire, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        std::size_t                                  off    = 0;
        const auto                                   size   = wire.input.size();
        bool                                         failed = false;
        qb::http::test::discard(qb::http::test::wait_until([&] { return failed || off >= size; }, 5s, "send",
                                                           [&] {
                                                               const int n = _sock.write(wire.input.cbegin() + off, size - off);
                                                               if (n > 0)
                                                                   off += static_cast<std::size_t>(n);
                                                               else if (n < 0)
                                                                   failed = true;
                                                               else
                                                                   std::this_thread::sleep_for(1ms);
                                                           }),
                                "a write the draining server may refuse: the case reads the answer, or the close, that follows");
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
    complete_handshake(std::chrono::milliseconds budget = 5000ms, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        int                                          status = 0;
        qb::http::test::discard(qb::http::test::wait_until(
                                    [&] {
                                        status = _sock.handshake_status();
                                        return status == 1 || status < 0;
                                    },
                                    budget, "complete_handshake", qb::http::test::fail_wait::nap{1ms}),
                                "status says how it ended: done, failed, or still at it when the budget ran out");
        if (status != 1)
            return false;
        _sock.set_nonblocking(true);
        return true;
    }

    [[nodiscard]] std::string
    alpn() {
        return _sock.get_alpn_selected_protocol();
    }

    /// The client preface and an empty SETTINGS.
    void
    preface(std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        Wire                                         wire;
        qb::http::test::push_preface(wire);
        qb::http::test::push_frame(wire, h2::FrameType::SETTINGS, 0, 0, {});
        send(wire);
    }

    void
    get(std::uint32_t stream_id, std::string const &path, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        Wire                                         wire;
        qb::http::test::push_frame(wire, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, stream_id,
                                   qb::http::test::encode_hpack_headers(qb::http::test::default_request_headers(path)));
        send(wire);
    }

    void
    ping_ack(std::vector<std::uint8_t> const &data, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        Wire                                         wire;
        qb::http::test::push_frame(wire, h2::FrameType::PING, h2::FLAG_ACK, 0, data);
        send(wire);
    }

    /// Reads until @p done holds, the connection ends, or @p budget elapses.
    template <typename Pred>
    void
    read_until(Pred &&done, std::chrono::milliseconds budget = 5000ms, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        char                                         buffer[16384];
        qb::http::test::discard(qb::http::test::wait_until([&] { return closed || done(); }, budget, "read_until",
                                                           [&] {
                                                               const int got = _sock.read(buffer, sizeof(buffer));
                                                               if (got > 0) {
                                                                   _received.append(buffer, static_cast<std::size_t>(got));
                                                                   return;
                                                               }
                                                               if (got < 0) {
                                                                   closed = true;
                                                                   return;
                                                               }
                                                               std::this_thread::sleep_for(1ms);
                                                           }),
                                "the caller reads what came, or that the connection closed");
    }

    void
    read_to_close(std::chrono::milliseconds budget = 5000ms, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
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

    const std::string base = "https://localhost:" + std::to_string(server.port);
    // Before the client, which answers what it still holds when it is destroyed: a case that fails returns early.
    std::atomic<int>   answered{0};
    qb::http::Response slow;
    qb::http::Response draining;
    auto               client = std::make_shared<qb::http2::Client>(base);
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);

    qb::http::Request slow_request{{base + "/slow?ms=300"}};
    qb::http::Request drain_request{{base + "/drain?ms=5000"}};
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

// ---------------------------------------------------------------------------------------------------------------------
// The drain's last delivery and its bound (Huly QB-91, QB-1248).
//
// At the drain's deadline a connection that never answered the PING is sent its final GOAWAY and closes once that is
// delivered, within qb-io's linger bound. That bound was the session's inactivity timeout, set to the linger: it
// restarts at every write that leaves octets queued, so a client whose reading made the server write within each
// linger kept the session -- its contexts, its output -- for as long as it wished (the ninth independent review of
// QB-1248 measured one still up nine seconds after the deadline, under a linger of two). It is a timer of the
// session's own, counted from the deadline.
//
// Each case starts the drain on the server's thread and watches the session from that thread, every 20 ms. What a
// case needs done in the very pass of the deadline -- an extraction, a hold-up of the thread such as a report handler
// that takes its time makes -- the drain's report does: it runs on the server's thread right after the deadline
// aborted the sessions, before the loop writes anything.
namespace server_drain_h2_delivery_test {

using Raw   = qb::http::test::Http2RawClient;
using Clock = std::chrono::steady_clock;

/// The session's inactivity timeout from the watch's first run -- the default until then, so that nothing hurries the
/// connection's first exchange: the watch holds it off until the drain.
constexpr auto kSessionTimeout = 150ms;
constexpr auto kDrainDeadline  = 40ms; ///< under that timeout: the deadline comes first, whatever holds the thread up
/// The send buffer asked for the session's socket (Linux grants twice that): small, so that what the session has to
/// write stays in its output, and the server writes again whenever its client's reading makes room -- some 32 KiB every
/// 43 ms, the largest gap 50 ms, as the eleventh independent review measured, against a linger of 800 ms. With the
/// system's own, megabytes wait in the kernel and the server writes once in a while, whatever the client reads (the
/// tenth review measured its writes 600 ms apart under a client taking 240 KiB every 250 ms).
constexpr int kSendBuffer = 16 * 1024;

[[nodiscard]] Clock::rep
ticks(Clock::time_point at) {
    return at.time_since_epoch().count();
}

[[nodiscard]] std::chrono::milliseconds
between(Clock::rep from, Clock::rep to) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::duration(to - from));
}

/// What the test asks of the server's thread, and what that thread saw: the run's own. The times are steady-clock
/// ticks, 0 until the thing happened.
struct Asked {
    std::atomic<bool> drain{false};   ///< start the drain
    std::atomic<bool> extract{false}; ///< in the pass of the deadline: extract the session
    std::atomic<int>  end_with{0};    ///< in the pass of the deadline: leave a callback that disconnects it, this reason
    std::atomic<int>  hold_ms{0};     ///< in the pass of the deadline: hold the server's thread this long
    std::atomic<int>  deadline_ms{static_cast<int>(kDrainDeadline.count())}; ///< the drain's deadline
    std::atomic<bool> arm_at_linger{false}; ///< past the drain's start, the timeout held off until the session lingers

    std::atomic<bool>        queued{false}; ///< /large's response is in the session's output
    std::atomic<bool>        send_buffer_set{false};
    std::atomic<bool>        extracted{false};
    std::atomic<bool>        observed{false}; ///< the extracted session was read, past the bound its delivery had
    std::atomic<bool>        up_past_the_bound{false};
    std::atomic<std::size_t> queued_at_deadline{0}; ///< the session's output when the report ran
    std::atomic<int>         outcome{-1};           ///< the drain's report
    std::atomic<int>         reason{-1};            ///< the session's disconnection reason, as last read
    std::atomic<Clock::rep>  drain_at{0};
    std::atomic<Clock::rep>  deadline_at{0};  ///< the drain's report began: the sessions are aborted
    std::atomic<Clock::rep>  lingering_at{0}; ///< the session was first seen closing after its peer
    std::atomic<Clock::rep>  released_at{0};  ///< the session was first seen ended
};

class DeliveryServer;
class DeliverySession : public qb::http2::use<DeliverySession>::session<DeliveryServer> {
public:
    explicit DeliverySession(DeliveryServer &server);
    /// What the server's thread reads and does of its session, by name.
    [[nodiscard]] bool
    up() noexcept {
        return this->is_connected();
    }
    [[nodiscard]] bool
    closing_after_its_peer() noexcept {
        return this->lingering();
    }
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
    [[nodiscard]] std::size_t
    queued() noexcept {
        return this->out().size();
    }
    [[nodiscard]] bool
    small_send_buffer() noexcept {
        return this->transport().set_optval(SOL_SOCKET, SO_SNDBUF, kSendBuffer) == 0;
    }
    /// Set again, not only restarted: the timer is armed afresh, past the next run of the watch that calls this, so
    /// that the timeout never comes first out of a hold-up of the server's thread.
    void
    hold_timeout() noexcept {
        this->setTimeout(kSessionTimeout);
    }
};
class DeliveryServer : public qb::http2::use<DeliveryServer>::server<DeliverySession> {
public:
    Asked       *asked = nullptr; ///< the run's, set before start()
    qb::duration linger{2s};      ///< each session's linger bound
    std::size_t  large = 0;       ///< the octets of /large's body
    /// An extracted session's transport: it ends with the server.
    std::optional<DeliverySession::transport_io_type> taken;

    DeliveryServer() {
        router().get("/first", [this](auto ctx) {
            _watched               = ctx->session();
            asked->send_buffer_set = ctx->session()->small_send_buffer();
            watch(ctx->session(), this);
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router().get("/large", [this](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::string(large, 'l');
            ctx->complete();
            asked->queued = true;
        });
        router().compile();
    }

private:
    std::weak_ptr<DeliverySession> _watched; ///< the session /first came on

    /// The drain's report, on the server's thread in the pass of the deadline: the sessions are aborted -- the final
    /// GOAWAY queued, the bound of its delivery armed -- and nothing is written yet. What the case asked for.
    void
    at_the_deadline() {
        const auto session = _watched.lock();
        if (!session)
            return;
        asked->queued_at_deadline = session->queued();
        if (asked->extract.load()) {
            auto transfer    = extractSession(session->id());
            asked->extracted = transfer.second;
            taken.emplace(std::move(transfer.first));
            qb::io::async::callback(
                [session, seen = asked] {
                    seen->reason            = session->ended_for();
                    seen->up_past_the_bound = session->up();
                    seen->observed          = true;
                },
                linger + 300ms);
        }
        if (const int reason = asked->end_with.load(); reason != 0)
            qb::io::async::callback([session, reason] { session->disconnect(reason); }, 30ms);
        if (const int hold = asked->hold_ms.load(); hold > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(hold));
    }

    /// Every 20 ms on the server's thread, while @p session is connected and this server's: until the drain its
    /// timeout is held off; the drain the test asked for starts; and what the session reads of itself is recorded.
    static void
    watch(std::shared_ptr<DeliverySession> session, DeliveryServer *server) {
        Asked *const asked = server->asked;
        const auto   now   = Clock::now();
        if (!session->up()) {
            asked->reason      = session->ended_for(); // before the time, which is what the test waits for
            asked->released_at = ticks(now);
            return;
        }
        if (asked->extracted.load())
            return; // read once more by the callback its extraction left
        const bool holding            = asked->drain_at.load() == 0;
        const bool not_seen_lingering = asked->lingering_at.load() == 0;
        if (holding && asked->drain.exchange(false)) {
            asked->drain_at = ticks(now);
            (void) server->drain(std::chrono::milliseconds(asked->deadline_ms.load()), [asked, server](qb::http::drain_outcome outcome) {
                asked->deadline_at = ticks(Clock::now());
                if (outcome == qb::http::drain_outcome::deadline)
                    server->at_the_deadline();
                asked->outcome = static_cast<int>(outcome); // last: the test's thread waits for it
            });
        }
        if (not_seen_lingering && session->closing_after_its_peer())
            asked->lingering_at = ticks(now);
        // Held off until the drain -- or, asked, until the session is first seen lingering, that run included: a slow
        // pass between the drain and the linger must not time it out before it lingers (the fourteenth independent
        // review of Huly QB-1248).
        const bool             hold_off = holding || (asked->arm_at_linger.load() && not_seen_lingering);
        DeliverySession *const held     = hold_off ? session.get() : nullptr; // the next run's callback keeps it alive
        qb::io::async::callback([session = std::move(session), server]() mutable { watch(std::move(session), server); }, 20ms);
        if (held)
            held->hold_timeout(); // the run's last act, the next run armed: the timeout always expires after that run
    }
};
DeliverySession::DeliverySession(DeliveryServer &server)
    : session(server) {
    this->set_linger(server.linger);
}

class Http2ServerDrainDelivery : public ::testing::Test {
protected:
    Asked                                                         asked; // declared before the server's thread: it outlives it
    std::unique_ptr<qb::http::test::ServerThread<DeliveryServer>> thread;
    Raw                                                           raw;
    std::uint32_t                                                 first = 0; ///< /first's stream
    std::uint32_t                                                 large = 0; ///< /large's stream

    template <typename Pred>
    [[nodiscard]] static bool
    watch_until(Pred &&pred, std::chrono::milliseconds budget, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        return qb::http::test::wait_until(std::forward<Pred>(pred), budget, "watch_until", qb::http::test::fail_wait::nap{2ms});
    }

    /// A server whose sessions have @p linger; a client whose windows take a response whole; /first answered -- the
    /// watch runs from there. With @p octets, /large is then queued in the session's output; either way the client
    /// reads nothing from there, so that the PING of the drain's notice is never answered.
    void
    connect(std::chrono::milliseconds linger, std::size_t octets = 0, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        ASSERT_TRUE(qb::http::test::certs_available());
        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();
        thread = std::make_unique<qb::http::test::ServerThread<DeliveryServer>>([cert, key, linger, octets, this](DeliveryServer &srv) -> bool {
            srv.asked  = &asked;
            srv.linger = linger;
            srv.large  = octets;
            srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread->ready());
        raw.keep_frames = false;
        ASSERT_TRUE(raw.connect(thread->port(), {{Raw::SETTINGS_INITIAL_WINDOW_SIZE, 0x7FFFFFFFu}}));
        ASSERT_TRUE(raw.window_update(0, 0x7FFF0000u));
        ASSERT_TRUE(raw.read_until([this] { return raw.settings_acked; }, 3s));
        first = raw.request("/first");
        ASSERT_NE(first, 0u);
        qb::http::test::discard(raw.read_until([this] { return raw.streams[first].end_stream || raw.eof; }, 3s),
                                "the case asserts the first answer right after");
        ASSERT_TRUE(raw.streams[first].end_stream) << "the first request was not answered";
        ASSERT_TRUE(asked.send_buffer_set.load()) << "the session's socket refused its send buffer";
        if (octets == 0)
            return;
        large = raw.request("/large");
        ASSERT_NE(large, 0u);
        ASSERT_TRUE(watch_until([this] { return asked.queued.load(); }, 10s)) << "/large was not answered";
    }

    /// The drain, to its deadline's report (which a case may have asked to take its time).
    void
    drain_to_the_deadline(std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        asked.drain = true;
        ASSERT_TRUE(watch_until([this] { return asked.outcome.load() >= 0; }, 5s)) << "the drain did not report";
        ASSERT_EQ(asked.outcome.load(), static_cast<int>(qb::http::drain_outcome::deadline));
    }
};

} // namespace server_drain_h2_delivery_test

using server_drain_h2_delivery_test::Http2ServerDrainDelivery;

// A client that takes a little of the output at a time does not keep the session past the bound of its last delivery.
// It takes 256 KiB every quarter of a second, well within each linger, and each amount makes the server write again
// (the session's socket has a small send buffer): on the code as it was every such write restarted the bound, and the
// session outlived the three seconds of the case -- and any number, while output was left. It is aborted a linger
// after the deadline: not before, the delivery has its bound whole; not long after, the bound is the linger; and it
// says what ended it.
TEST_F(Http2ServerDrainDelivery, AClientThatTakesALittleAtATimeIsAbortedAtTheBound) {
    using namespace server_drain_h2_delivery_test;
    constexpr auto        kLinger = 800ms;
    constexpr auto        kLate   = 660ms; // what a hold-up of the server's thread may add; two lingers are past it
    constexpr std::size_t kLarge  = std::size_t{32} << 20;
    constexpr std::size_t kTake   = std::size_t{256} << 10;
    ASSERT_NO_FATAL_FAILURE(connect(kLinger, kLarge));
    ASSERT_NO_FATAL_FAILURE(drain_to_the_deadline());
    qb::http::test::expect_until([this] { return asked.released_at.load() != 0; }, 3s, "the release",
                                 [&] {
                                     raw.read_octets(kTake, 100ms);
                                     std::this_thread::sleep_for(250ms);
                                 });
    ASSERT_NE(asked.released_at.load(), 0) << "the session outlived the bound of its last delivery: each write restarted it";
    EXPECT_LT(raw.streams[large].data_bytes, kLarge) << "the client took the whole response: the case proves nothing";
    const auto ended = between(asked.drain_at.load(), asked.released_at.load());
    EXPECT_GE(ended, kLinger) << "the delivery did not have its bound: the session ended " << ended.count() << " ms after the drain began";
    EXPECT_LT(ended, kDrainDeadline + kLinger + kLate)
        << "the delivery's bound is not the linger: the session ended " << ended.count() << " ms after the drain began";
    EXPECT_EQ(asked.reason.load(), static_cast<int>(qb::http::DisconnectedReason::ServerDraining))
        << "a session the drain's deadline aborted reports another reason";
}

// A delivery that completes within the bound is not cut by it. The session is then in qb-io's lingering close -- its
// sending side shut down, what the client still sends read and dropped -- which waits for the client for the linger
// bound again, counted from the delivery: ended at the delivery's own bound, the socket would close under a client
// that may not have read what it was just sent. The drain's report takes 150 ms -- nothing is written meanwhile --,
// so the final GOAWAY is delivered 150 ms after the deadline; the client reads it and keeps its side open. The
// session ends a linger after the delivery, by itself, not at the bound.
TEST_F(Http2ServerDrainDelivery, ADeliveryCompletedWithinTheBoundHasItsLingeringCloseWhole) {
    using namespace server_drain_h2_delivery_test;
    constexpr auto kLinger = 400ms;
    constexpr auto kHold   = 150ms;
    ASSERT_NO_FATAL_FAILURE(connect(kLinger));
    asked.hold_ms = static_cast<int>(kHold.count());
    ASSERT_NO_FATAL_FAILURE(drain_to_the_deadline());
    qb::http::test::discard(raw.read_until([this] { return raw.eof; }, 5s), "a read to the connection's end: the case expects it right after");
    EXPECT_TRUE(raw.eof) << "the server did not end its side after the delivery";
    EXPECT_TRUE(raw.goaway_seen);
    EXPECT_EQ(raw.goaway_code, kNoError);
    EXPECT_EQ(raw.goaway_last_stream, first) << "the final GOAWAY names the last stream the client opened";
    ASSERT_TRUE(watch_until([this] { return asked.released_at.load() != 0; }, kLinger + 3s)) << "the session never ended";
    EXPECT_NE(asked.lingering_at.load(), 0) << "the session was never seen closing after its peer";
    EXPECT_NE(asked.reason.load(), static_cast<int>(qb::http::DisconnectedReason::ServerDraining))
        << "the delivery's bound ended a session that was delivered: its lingering close ends by itself";
    const auto ended = between(asked.deadline_at.load(), asked.released_at.load());
    EXPECT_GE(ended, kHold + kLinger - 20ms) << "the delivery's bound cut the lingering close: the session ended " << ended.count()
                                             << " ms after the deadline, the delivery " << kHold.count() << " ms after it";
}

// A session extracted during its last delivery has no bound left: its connection is its next owner's, and the timer
// stops with the connection's leaving, as the sweep's does. The drain's report extracts the session in the pass of
// the deadline -- its final GOAWAY queued, nothing written; read a linger and 300 ms later, it is as the extraction
// left it.
TEST_F(Http2ServerDrainDelivery, NoBoundRunsOnASessionExtractedDuringItsLastDelivery) {
    using namespace server_drain_h2_delivery_test;
    constexpr auto kLinger = 300ms;
    ASSERT_NO_FATAL_FAILURE(connect(kLinger));
    asked.extract = true;
    ASSERT_NO_FATAL_FAILURE(drain_to_the_deadline());
    ASSERT_TRUE(watch_until([this] { return asked.observed.load(); }, 5s)) << "the extracted session was not read";
    ASSERT_TRUE(asked.extracted.load()) << "no session was extracted: the case proves nothing";
    EXPECT_TRUE(asked.up_past_the_bound.load()) << "a timer of the session disconnected it after its connection had left it, with the reason "
                                                << asked.reason.load() << " (ServerDraining, "
                                                << static_cast<int>(qb::http::DisconnectedReason::ServerDraining)
                                                << ": the bound of its last delivery; ByTimeout, "
                                                << static_cast<int>(qb::http::DisconnectedReason::ByTimeout) << ": its inactivity timeout)";
}

// A session that something else ended in the pass of the bound keeps the reason it ended with. The drain's report
// leaves a callback that disconnects the session 30 ms later, then holds the server's thread past the bound. Coming
// out of the hold-up the loop polls -- the session's watcher is made pending there: its final frames are queued, and
// its socket, with nothing else in it, takes them -- then runs the expired timers, the callback first (the earlier
// expiry), then the bound's; the session's release comes last, from the watcher the poll made pending, which the
// callback's disconnection joined. The bound found the session ended, and left it. The order needs that condition
// (the eleventh independent review): with the watcher not pending, the disconnection is handled at once, before the
// bound, whose stop clears its tick, and the case proves nothing -- so with nothing queued, or with more queued than
// the socket takes. What the report saw queued is asserted: the final frames, and nothing behind them.
TEST_F(Http2ServerDrainDelivery, ASessionAlreadyEndedKeepsItsReasonAtTheBound) {
    using namespace server_drain_h2_delivery_test;
    constexpr auto kLinger = 200ms;
    const int      kReason = static_cast<int>(qb::http::DisconnectedReason::Undefined);
    ASSERT_NO_FATAL_FAILURE(connect(kLinger));
    asked.end_with = kReason;
    asked.hold_ms  = static_cast<int>((kLinger + 100ms).count());
    ASSERT_NO_FATAL_FAILURE(drain_to_the_deadline());
    ASSERT_TRUE(watch_until([this] { return asked.released_at.load() != 0; }, 3s)) << "the session never ended";
    ASSERT_GT(asked.queued_at_deadline.load(), 0u) << "nothing queued at the deadline: its watcher is not pending, the case proves nothing";
    ASSERT_LT(asked.queued_at_deadline.load(), 4096u) << "more than the final frames queued at the deadline: the case proves nothing";
    EXPECT_EQ(asked.lingering_at.load(), 0) << "the session was delivered before the bound: the case proves nothing";
    EXPECT_EQ(asked.reason.load(), kReason) << "the bound of the last delivery ended again a session that had ended, under its own reason";
}

// A session in qb-io's lingering close is not cut by its inactivity timeout (the thirteenth independent review of Huly
// QB-1248): the linger has its own bound. The drain ends gracefully -- the client answers the notice's PING, the final
// GOAWAY ends a connection with no stream left, and the session, delivered, closes after its client --, and the client
// keeps its end open a second, under the watch's timeout of 150 ms (held off until the session is first seen
// lingering, then left to run: a slow pass before the linger does not time it out first) and a linger of 2 s: the
// session ends at the client's close, not by its timeout.
TEST_F(Http2ServerDrainDelivery, ALingeringSessionIsNotCutByItsInactivityTimeout) {
    using namespace server_drain_h2_delivery_test;
    constexpr auto kLinger = 2000ms;
    ASSERT_NO_FATAL_FAILURE(connect(kLinger));
    asked.deadline_ms   = 5000; // the client answers the PING long before: a graceful end
    asked.arm_at_linger = true;
    asked.drain         = true;
    ASSERT_TRUE(raw.read_until([this] { return raw.eof; }, 3s)) << "the server did not end its side after its final GOAWAY";
    const auto eof_at = Clock::now();
    EXPECT_TRUE(raw.goaway_seen);
    EXPECT_EQ(raw.goaway_code, kNoError);
    ASSERT_TRUE(watch_until([this] { return asked.lingering_at.load() != 0 || asked.released_at.load() != 0; }, 1s));
    EXPECT_NE(asked.lingering_at.load(), 0) << "the session was never seen closing after its peer";
    std::this_thread::sleep_for(1000ms); // the client keeps its end open
    raw.close();
    ASSERT_TRUE(watch_until([this] { return asked.released_at.load() != 0; }, 3s)) << "the session never ended";
    EXPECT_NE(asked.reason.load(), static_cast<int>(qb::http::DisconnectedReason::ByTimeout))
        << "the lingering session was ended by its inactivity timeout";
    const auto ended = between(ticks(eof_at), asked.released_at.load());
    EXPECT_GE(ended, 900ms) << "the session ended " << ended.count() << " ms after its end of stream, before its client closed";
}

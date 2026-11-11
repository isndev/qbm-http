/**
 * @file qbm/http/tests/system/http2/http2-control-replies.cpp
 * @brief The HTTP/2 guard of the replies a peer solicits, over real TLS sockets, on the server and on the client (Huly
 *        QB-1270).
 *
 * The guard counts the replies a peer solicited for nothing that are still QUEUED in the session's output -- a PONG, a
 * SETTINGS ACK and, on the server, the reset of a stream the client never opened, from the moment each is written until
 * the socket has taken its last byte -- and closes the connection with GOAWAY(ENHANCE_YOUR_CALM) at the 1001st. What the protocol reads for
 * that is its session's own count of bytes written
 * (`qb::io::async::io::bytes_written()`) and the size of its output: the unit suites prove the arithmetic on a fake io,
 * and this file proves the wiring -- that a real session's socket, a real partial write and a real peer that stops
 * reading give the protocol what the fake gave it.
 *
 *   - the server, a client that reads (the raw HTTP/2 client of `shared/http2_raw_client.h`): 3000 PINGs, then 3000
 *     SETTINGS, in batches whose replies it reads before it asks again -- every one answered, no GOAWAY, and a request
 *     is still served. Between two units of progress the 1001st closed the connection;
 *   - the server, a client that never reads: rounds of 999 PINGs (then SETTINGS, then empty DATA on a closed stream,
 *     each of which draws a reset) and a request the server answers, which forgave the budget -- the replies queued for
 *     as long as the client sent, up to qb-io's write cap. Once the socket's buffers are full a thousand replies queue
 *     and the connection is closed: what the session's output held at that moment is read on the server -- no more
 *     than a thousand replies and, behind them, the guard's GOAWAY, which a client whose buffers are full cannot be
 *     handed;
 *   - the client (`qb::http2::Client`), a server that pings it 3000 times and reads each batch of PONGs: never closed.
 *     With no response in progress the client closed the connection at the 1001st.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "../../shared/http2_raw_client.h"
#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

#include <qb/io/tcp/ssl/listener.h>
#include <qbm/http/2/client.h>
#include <qbm/http/http.h>

using namespace std::chrono_literals;
using qb::http::test::Http2RawClient;
using qb::http::test::ServerThread;

namespace http2_control_replies_test {

class GuardServer;

class GuardSession : public qb::http2::use<GuardSession>::session<GuardServer> {
public:
    explicit GuardSession(GuardServer &server)
        : session(server) {}
};

/// What the output of a session held when the session was closed with bytes still queued, for the test's thread.
struct Closed {
    std::mutex  mutex;
    bool        seen = false;
    std::string output;

    void
    reset() {
        std::lock_guard lock(mutex);
        seen = false;
        output.clear();
    }
    [[nodiscard]] std::optional<std::string>
    read() {
        std::lock_guard lock(mutex);
        return seen ? std::optional<std::string>(output) : std::nullopt;
    }
};
Closed g_closed;

/// One route, answered at once and without a body: nothing of its response waits on a flow-control window, so a client
/// that never reads still has every request served -- each one a stream it opened.
class GuardServer : public qb::http2::use<GuardServer>::server<GuardSession> {
public:
    GuardServer() {
        router().get("/served", [](auto ctx) {
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });
        router().compile();
    }

    /// Session hook: a session is gone. One that left bytes in its output is kept for the test, as it was.
    void
    disconnected(qb::uuid ident) {
        if (const auto it = this->sessions().find(ident); it != this->sessions().end() && it->second) {
            auto const &out = it->second->out();
            if (out.size() > 0) {
                std::lock_guard lock(g_closed.mutex);
                g_closed.output.assign(out.cbegin(), out.size());
                g_closed.seen = true;
            }
        }
        qb::http2::use<GuardServer>::server<GuardSession>::disconnected(ident);
    }
};

/// The error code and the debug data of the GOAWAY frame @p output ends on, if it ends on one.
[[nodiscard]] std::optional<std::pair<std::uint32_t, std::string>>
last_goaway(std::string_view output) {
    const auto byte = [&](std::size_t i) {
        return static_cast<std::uint32_t>(static_cast<unsigned char>(output[i]));
    };
    for (std::size_t payload = 8; payload + 9 <= output.size() && payload <= 8 + 256; ++payload) {
        const std::size_t at = output.size() - 9 - payload;
        if (((byte(at) << 16) | (byte(at + 1) << 8) | byte(at + 2)) == payload && byte(at + 3) == 0x7) {
            return std::pair{
                (byte(at + 13) << 24) | (byte(at + 14) << 16) | (byte(at + 15) << 8) | byte(at + 16), std::string(output.substr(at + 17))
            };
        }
    }
    return std::nullopt;
}

/// How many times @p frame occurs in @p output.
[[nodiscard]] std::size_t
occurrences(std::string_view output, std::string_view frame) {
    std::size_t n = 0;
    for (std::size_t at = output.find(frame); at != std::string_view::npos; at = output.find(frame, at + frame.size()))
        ++n;
    return n;
}

static_assert(
    requires(GuardSession const &session) { session.bytes_written(); },
    "the server's session counts what its socket took: the protocol reads it (Huly QB-1270)");

constexpr std::uint32_t kEnhanceYourCalm = 0xb;

class Http2ControlRepliesWireTest : public ::testing::Test {
protected:
    std::uint16_t                              port{0};
    std::unique_ptr<ServerThread<GuardServer>> server;

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "Missing TLS test certificates (" << qb::http::test::ssl_cert_path() << ")";
        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();
        server                 = std::make_unique<ServerThread<GuardServer>>([cert, key](GuardServer &srv) -> bool {
            srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(server->ready());
        port = server->port();
        ASSERT_NE(port, 0);
    }

    void
    TearDown() override {
        server.reset();
    }
};

// A client that reads: 500 PINGs in one write, their 500 PONGs read, six times over -- then the same with SETTINGS. The
// replies of a batch have left the server before the next batch is sent, so no more than 500 are ever queued: 3000 are
// answered, no GOAWAY, and the connection serves a request afterwards. The client opened no stream meanwhile: counted
// between two units of progress, its 1001st PING closed the connection.
TEST_F(Http2ControlRepliesWireTest, AClientThatReadsMaySolicitRepliesPastTheThousandth) {
    // Each kind on a connection of its own, and judged on its own: a fatal assertion ends that kind, not the test.
    const auto reads = [&](const bool settings) {
        SCOPED_TRACE(settings ? "SETTINGS" : "PING");
        Http2RawClient client;
        ASSERT_TRUE(client.connect(port));
        ASSERT_TRUE(client.read_until([&] { return client.settings_acked; }));
        const auto replies = [&] {
            return settings ? client.settings_acks : client.pongs;
        };
        const std::size_t before = replies();
        std::size_t       asked  = 0;
        for (int batch = 0; batch < 6 && !client.goaway_seen && !client.eof; ++batch) {
            ASSERT_TRUE(client.solicit(500, settings ? Http2RawClient::soliciting::settings : Http2RawClient::soliciting::pings));
            asked += 500;
            ASSERT_TRUE(client.read_until([&] { return replies() - before == asked || client.goaway_seen; }, 30s))
                << (replies() - before) << " replies read of " << asked << " solicited";
        }
        EXPECT_FALSE(client.goaway_seen) << "a client that read every reply was closed with GOAWAY code " << client.goaway_code << " after "
                                         << (replies() - before) << " replies";
        EXPECT_FALSE(client.eof);
        EXPECT_EQ(replies() - before, 3000u);
        const auto served = client.request("/served");
        ASSERT_NE(served, 0u);
        ASSERT_TRUE(client.read_until([&] { return client.stream(served).end_stream; })) << "the connection no longer serves";
        EXPECT_EQ(client.stream(served).status(), 204);
        client.close();
    };
    reads(false);
    reads(true);
}

// A client that never reads: rounds of 999 PINGs and one request, each round in the two writes of a client that reads
// nothing back -- then the same with SETTINGS, and with empty DATA frames on a closed stream, each of which draws a
// reset. The request is served -- a stream the client opened, which forgave every budget -- so the server answered for
// as long as the client sent: 64 MiB of replies solicited, every one of them written to an output nobody drained, and
// the connection still serving. The socket's buffers take what they can hold; past them the replies queue in the
// session's output, and the thousandth queued is the last: the protocol writes its GOAWAY behind them and the session
// closes the connection -- without waiting for a client that takes nothing, so the GOAWAY stays in the output it closed
// with. That output is read on the server: no more than a thousand replies, then GOAWAY(ENHANCE_YOUR_CALM) naming the
// flood. (How many of the thousand are still there is the socket's business: it may take a few more between the
// protocol's verdict and the close.) The client, when it reads at last, finds the end of the connection and far fewer
// replies than it solicited.
TEST_F(Http2ControlRepliesWireTest, AClientThatNeverReadsIsCutOnceAThousandRepliesAreQueued) {
    constexpr std::size_t kFlood = 64u << 20; // of replies solicited: more than any loopback socket buffers hold
    using soliciting             = Http2RawClient::soliciting;
    struct flood {
        const char      *name;
        soliciting       what;
        std::string_view reply;  // the reply each frame draws, as the server writes it
        const char      *goaway; // the debug data of the GOAWAY that closes it
    };
    const flood floods[] = {
        {"PING", soliciting::pings, std::string_view("\x00\x00\x08\x06\x01\x00\x00\x00\x00\x51\x42\x31\x32\x37\x30\x00\x00", 17),
         "Excessive PING control frames (flood)"},
        {"SETTINGS", soliciting::settings, std::string_view("\x00\x00\x00\x04\x01\x00\x00\x00\x00", 9),
         "Excessive SETTINGS control frames (flood)"},
        {"DATA on a closed stream", soliciting::data_on_a_closed_stream,
         std::string_view("\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x05", 13), // RST_STREAM(STREAM_CLOSED) on stream 1
         "Excessive frames on closed streams (HTTP/2 reset flood)"},
    };
    // Each flood on a connection of its own, and judged on its own: a fatal assertion ends that flood, not the test.
    const auto never_reads = [&](const flood &each) {
        SCOPED_TRACE(each.name);
        const soliciting       what  = each.what;
        const std::string_view reply = each.reply;
        g_closed.reset();
        Http2RawClient client;
        client.keep_frames  = false;
        client.write_budget = 120s; // a write of the flood stops when the connection is broken, not when the host is slow
        ASSERT_TRUE(client.connect(port));
        ASSERT_TRUE(client.read_until([&] { return client.settings_acked; }));
        const std::uint32_t closed = client.request("/served"); // stream 1: answered, so closed for the server
        ASSERT_EQ(closed, 1u);
        ASSERT_TRUE(client.read_until([&] { return client.stream(closed).end_stream; }));
        const auto read = [&] {
            return what == soliciting::pings ? client.pongs : what == soliciting::settings ? client.settings_acks : client.resets;
        };
        const std::size_t before    = read();
        std::size_t       solicited = 0;
        bool              taking    = true; // the server still takes what the client writes
        while (taking && solicited * reply.size() < kFlood) {
            taking = client.solicit(999, what, closed) && client.request("/served") != 0;
            solicited += 999;
        }
        // Now the client reads. A server that still serves answers one last request, after everything else it wrote.
        const std::uint32_t last = taking ? client.request("/served") : 0;
        (void) client.read_until([&] { return client.eof || (last != 0 && client.stream(last).end_stream); }, 120s);
        const std::size_t replies = read() - before;
        ASSERT_TRUE(client.eof) << "a client that never read drew " << replies << " replies of " << solicited
                                << " solicited and the connection still serves: they queued in the server's output";
        EXPECT_LT(replies, solicited) << "the server answered everything the client sent";
        if (client.goaway_seen) {
            EXPECT_EQ(client.goaway_code, kEnhanceYourCalm);
        }
        client.close();

        std::optional<std::string> held;
        const auto                 deadline = std::chrono::steady_clock::now() + 10s;
        while (!(held = g_closed.read()) && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(1ms);
        ASSERT_TRUE(held.has_value()) << "the session did not close with bytes queued";
        const auto goaway = last_goaway(*held);
        ASSERT_TRUE(goaway.has_value()) << "the output the session closed with does not end on a GOAWAY";
        EXPECT_EQ(goaway->first, kEnhanceYourCalm);
        EXPECT_EQ(goaway->second, each.goaway);
        const std::size_t queued = occurrences(*held, reply);
        EXPECT_LE(queued, 1000u) << "more than a thousand replies were queued when the connection was closed";
        EXPECT_GT(queued, 0u) << "no reply was queued when the connection was closed";
    };
    for (const flood &each : floods) {
        never_reads(each);
    }
}

/// One-connection TLS + HTTP/2 server peer on its own thread (non-blocking sockets, polled, every wait bounded): it
/// negotiates ALPN h2, sends its SETTINGS and acknowledges the client's, then pings the client -- `batches` rounds of
/// `per_batch` PING frames in one write, each round sent once every PONG of the rounds before it was read. It records
/// the PONGs, a GOAWAY the client sends, and the end of the connection.
class PingingPeer {
public:
    PingingPeer(int batches, int per_batch)
        : _batches(batches)
        , _per_batch(per_batch) {
        _listener.init(qb::io::ssl::Context::server(qb::http::test::ssl_cert_path(), qb::http::test::ssl_key_path()).alpn({"h2"}));
        if (_listener.listen_v4(0, "127.0.0.1") != 0)
            return;
        _listener.set_nonblocking(true);
        _port   = _listener.local_endpoint().port();
        _thread = std::thread([this] { run(); });
    }
    ~PingingPeer() {
        _release = true;
        if (_thread.joinable())
            _thread.join();
    }
    PingingPeer(const PingingPeer &)            = delete;
    PingingPeer &operator=(const PingingPeer &) = delete;

    [[nodiscard]] std::uint16_t
    port() const noexcept {
        return _port;
    }
    [[nodiscard]] std::size_t
    pongs() const noexcept {
        return _pongs.load();
    }
    /// Every PING of every round was answered.
    [[nodiscard]] bool
    done() const noexcept {
        return _done.load();
    }
    [[nodiscard]] bool
    goaway() const noexcept {
        return _goaway.load();
    }
    [[nodiscard]] std::uint32_t
    goaway_code() const noexcept {
        return _goaway_code.load();
    }
    [[nodiscard]] bool
    eof() const noexcept {
        return _eof.load();
    }

private:
    static void
    append_frame(std::vector<uint8_t> &out, std::uint8_t type, std::uint8_t flags, std::vector<uint8_t> const &payload) {
        const auto n = static_cast<std::uint32_t>(payload.size());
        out.insert(out.end(), {static_cast<uint8_t>(n >> 16), static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n), type, flags, 0, 0, 0, 0});
        out.insert(out.end(), payload.begin(), payload.end());
    }

    bool
    write_all(qb::io::tcp::ssl::socket &sock, std::vector<uint8_t> const &bytes) {
        std::size_t off = 0;
        while (off < bytes.size() && !_release) {
            const int n = sock.write(reinterpret_cast<char const *>(bytes.data() + off), bytes.size() - off);
            if (n < 0)
                return false;
            if (n == 0)
                std::this_thread::sleep_for(1ms);
            off += static_cast<std::size_t>(n);
        }
        return off == bytes.size();
    }

    void
    run() {
        const auto               deadline = std::chrono::steady_clock::now() + 60s;
        qb::io::tcp::ssl::socket sock;
        while (!_release && std::chrono::steady_clock::now() < deadline) {
            if (_listener.accept(sock) == 0 && sock.is_open())
                break;
            std::this_thread::sleep_for(1ms);
        }
        if (!sock.is_open())
            return;
        sock.set_nonblocking(true);

        constexpr std::size_t preface_size = 24;
        std::vector<uint8_t>  in;
        bool                  preface_seen = false;
        bool                  answered     = false; // our SETTINGS and the ACK of the client's are sent
        bool                  acked        = false; // the client acknowledged our SETTINGS
        std::size_t           sent         = 0;     // PINGs written
        char                  buffer[16384];
        while (!_release && std::chrono::steady_clock::now() < deadline) {
            if (acked && !_goaway && _pongs == sent && sent < static_cast<std::size_t>(_batches) * static_cast<std::size_t>(_per_batch)) {
                std::vector<uint8_t> pings;
                for (int i = 0; i < _per_batch; ++i)
                    append_frame(pings, 0x6, 0, {0x70, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x00});
                if (!write_all(sock, pings)) {
                    _eof = true;
                    break;
                }
                sent += static_cast<std::size_t>(_per_batch);
            }
            const int n = sock.read(buffer, sizeof(buffer));
            if (n < 0) {
                _eof = true;
                break;
            }
            if (n == 0) {
                std::this_thread::sleep_for(1ms);
                continue;
            }
            in.insert(in.end(), buffer, buffer + n);
            if (!preface_seen) {
                if (in.size() < preface_size)
                    continue;
                in.erase(in.begin(), in.begin() + preface_size);
                preface_seen = true;
            }
            std::size_t at = 0;
            while (in.size() - at >= 9) {
                const std::uint8_t *head   = in.data() + at;
                const std::size_t   length = (std::size_t{head[0]} << 16) | (std::size_t{head[1]} << 8) | head[2];
                if (in.size() - at < 9 + length)
                    break;
                const std::uint8_t type = head[3], flags = head[4];
                if (type == 0x4 && (flags & 0x1) != 0) {
                    acked = true;
                } else if (type == 0x4 && !answered) {
                    std::vector<uint8_t> reply;
                    append_frame(reply, 0x4, 0, {});   // our SETTINGS
                    append_frame(reply, 0x4, 0x1, {}); // the ACK of the client's
                    if (!write_all(sock, reply)) {
                        _eof = true;
                        return;
                    }
                    answered = true;
                } else if (type == 0x6 && (flags & 0x1) != 0) {
                    ++_pongs;
                } else if (type == 0x7 && length >= 8) {
                    _goaway_code =
                        (std::uint32_t{head[13]} << 24) | (std::uint32_t{head[14]} << 16) | (std::uint32_t{head[15]} << 8) | head[16];
                    _goaway = true;
                }
                at += 9 + length;
            }
            in.erase(in.begin(), in.begin() + static_cast<std::ptrdiff_t>(at));
            if (_pongs == static_cast<std::size_t>(_batches) * static_cast<std::size_t>(_per_batch))
                _done = true;
        }
        sock.disconnect();
        sock.close();
    }

    int                        _batches;
    int                        _per_batch;
    qb::io::tcp::ssl::listener _listener;
    std::uint16_t              _port = 0;
    std::atomic<bool>          _release{false};
    std::atomic<std::size_t>   _pongs{0};
    std::atomic<bool>          _done{false};
    std::atomic<bool>          _goaway{false};
    std::atomic<std::uint32_t> _goaway_code{0};
    std::atomic<bool>          _eof{false};
    std::thread                _thread;
};

class Http2ClientControlRepliesWireTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "Missing TLS test certificates (" << qb::http::test::ssl_cert_path() << ")";
        qb::io::async::init();
    }
};

// The module's client, a server that pings it: 500 PINGs in one write, their 500 PONGs read, six times over, and no
// request in flight. The client's replies leave its output between two batches: 3000 are answered and the client stays
// connected. With no response progress to forgive them, the client closed the connection at the 1001st PING.
TEST_F(Http2ClientControlRepliesWireTest, AServerThatPingsItsClientPastTheThousandthIsNeverCut) {
    static_assert(
        requires(qb::http2::Client const &client) { client.bytes_written(); },
        "the client's session counts what its socket took: the protocol reads it (Huly QB-1270)");
    PingingPeer peer(6, 500);
    ASSERT_NE(peer.port(), 0);
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(peer.port()));
    client->set_verify_peer(false); // self-signed test cert
    client->set_connect_timeout(5s);
    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread<GuardServer>::pump_until([&] { return connected; }));
    ASSERT_TRUE(ServerThread<GuardServer>::pump_until([&] { return peer.done() || peer.goaway() || peer.eof(); }, 60s))
        << peer.pongs() << " PONGs read";
    EXPECT_FALSE(peer.goaway()) << "the client closed the connection with GOAWAY code " << peer.goaway_code() << " after " << peer.pongs()
                                << " PONGs";
    EXPECT_EQ(peer.pongs(), 3000u);
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    EXPECT_TRUE(ServerThread<GuardServer>::pump_until([&] { return peer.eof(); }, 10s));
}

} // namespace http2_control_replies_test

/**
 * @file qbm/http/tests/system/http2/http2-control-replies.cpp
 * @brief The HTTP/2 guard of the replies a peer solicits, over real TLS sockets, on the server and on the client (Huly
 *        QB-1270).
 *
 * The guard counts the replies a peer solicited for nothing that are still QUEUED in the session's output -- a PONG, a
 * SETTINGS ACK, on the server the reset of a stream the client never opened and on the client the reset of anything but
 * a request in flight, from the moment each is written until the socket has taken its last byte -- and closes the
 * connection with GOAWAY(ENHANCE_YOUR_CALM) at the 1001st. What the protocol reads for
 * that is its session's own count of bytes written
 * (`qb::io::async::io::bytes_written()`) and the size of its output: the unit suites prove the arithmetic on a fake io,
 * and this file proves the wiring -- that a real session's socket, a real partial write and a real peer that stops
 * reading give the protocol what the fake gave it.
 *
 *   - the server, a client that reads (the raw HTTP/2 client of `shared/http2_raw_client.h`): 3000 PINGs, then 3000
 *     SETTINGS, in batches whose replies it reads before it asks again -- every one answered, no GOAWAY, and a request
 *     is still served. Between two units of progress the 1001st closed the connection;
 *   - the server, a client that never reads: behind a response its connection's buffers never take whole, which it
 *     asked for and reads only the head of, rounds of 999 PINGs (then SETTINGS, then DATA on a closed stream, each of
 *     which draws a reset) and a request the server answers. A thousand replies queue and the connection is closed at
 *     once: what the session's output held at that moment is read on the server -- the rest of the response, a thousand
 *     replies and, behind them, the guard's GOAWAY, which a client whose buffers are full cannot be handed. (Before the
 *     guard counted the replies queued, each request forgave it, and the replies queued for as long as the client
 *     sent, up to qb-io's write cap.);
 *   - the client (`qb::http2::Client`), a server that pings it 3000 times and reads each batch of PONGs: never closed.
 *     With no response in progress the client closed the connection at the 1001st;
 *   - the client, a server whose HEADERS fall on a stream that has closed, 3000 of them, and that reads each batch of
 *     resets: never closed;
 *   - the client, a server that sends such HEADERS and reads nothing: the resets were in no count and queued for as
 *     long as the server sent. Once the socket's buffers are full a thousand queue and the client closes the
 *     connection: the request it had in flight fails with the guard's reason, named once as the client's.
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
    /// The output kept, once: moved out, not copied (it holds most of a large body).
    [[nodiscard]] std::optional<std::string>
    take() {
        std::lock_guard lock(mutex);
        if (!seen)
            return std::nullopt;
        seen = false;
        return std::optional<std::string>(std::move(output));
    }
};
Closed g_closed;

/// The body of `/large`: far more than a connection whose client reads nothing takes -- 4.2 MB on Linux and 180 KB on
/// Windows once full (measured, `http2-close-after-peer.cpp`), and on macOS no more than the 4 MiB each way its
/// autotuning may grow the two buffers to (`net.inet.tcp.autosndbufmax`, `autorcvbufmax` on the runner) -- so that the
/// body never leaves the session's output whole, and what the session writes after it waits there (Huly QB-1270). It
/// relies on the server writing a buffered response into the output whole, as far as the windows allow, whatever the
/// socket takes (`send_response_body()`, `protocol/server.h`).
constexpr std::size_t kLargeBody = std::size_t{32} << 20;

/// Two routes, answered at once: `/served` without a body -- nothing of its response waits on a flow-control window, so
/// a client that never reads still has every request served, each one a stream it opened -- and `/large`, kLargeBody
/// octets, for a client that opened its windows to it.
class GuardServer : public qb::http2::use<GuardServer>::server<GuardSession> {
public:
    GuardServer() {
        router().get("/served", [](auto ctx) {
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });
        router().get("/large", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::string(kLargeBody, 'x');
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

// A client that never reads. It asks first for a response its connection's buffers never take whole (kLargeBody), its
// windows opened to it, and reads only the head of it: what the session writes from then on waits in its output behind
// the rest of that body. Then rounds of 999 PINGs and one request, each round in the two writes of a client that reads
// nothing back -- then the same with SETTINGS, and with DATA frames of one octet on a closed stream, each of which draws
// a reset (of one octet, so that they take no token of the bucket of the frames that make no progress). The request is
// served, a stream the client opened; before the guard counted the replies queued, it forgave them, and the server
// answered for as long as the client sent -- 64 MiB of replies solicited, every one written to an output nobody
// drained, and the connection still serving. Now each reply counts from the moment it is written, and none leaves:
// the thousandth queued is the last, the protocol writes its GOAWAY behind it and the session closes the connection at
// once -- without waiting for a client that takes nothing, so the GOAWAY stays in the output it closed with. That
// output is read on the server: the rest of the large body, a thousand replies exactly, then GOAWAY(ENHANCE_YOUR_CALM)
// naming the flood. The client's next write fails on the closed connection, and when it reads at last it finds the
// end of it and none of the replies, still behind the body.
//
// Without the body ahead, the replies filled the socket themselves, and the case took a socket so filled to take
// nothing more. macOS does not keep it so: a socket that refused part of a write takes more a millisecond later, its
// reader's receive buffer growing whatever SO_RCVBUF that reader set (measured on the runner, isndev/qbm-http run
// 43489561448). The write that followed the verdict took the thousand replies AND the GOAWAY, with OpenSSL 4.1.0 and
// 3.5.9 alike, and the session closed at once with nothing queued -- the bound kept, the connection ended, and nothing
// left here to read (Huly QB-1270). The path a session takes then, closed at once with nothing queued, is
// http2-close-after-peer's (AFloodingConnectionIsClosedAtOnceAndNeverReachesTheLoop); the replies a socket takes being
// forgiven is AClientThatReadsMaySolicitRepliesPastTheThousandth's, above.
TEST_F(Http2ControlRepliesWireTest, AClientThatNeverReadsIsCutOnceAThousandRepliesAreQueued) {
    constexpr std::size_t kFlood = 64u << 20; // of replies solicited: more than any loopback socket buffers hold
    // The windows the client opens, the stream's and the connection's: the large body and room to spare.
    constexpr std::uint32_t kWindow = static_cast<std::uint32_t>(kLargeBody + (std::size_t{1} << 20));
    // A write the server does not take: a broken connection fails it at once, and a host that stalls does not hold it
    // this long. Half the session's inactivity timeout, so that a server that stopped reading and kept the connection
    // until then leaves the client's write waiting out its budget instead of failing it.
    constexpr auto kBudget = 30s;
    static_assert(kBudget * 2 <= qb::http2::constants::DEFAULT_SESSION_TIMEOUT);
    static_assert(kLargeBody % 16384 == 0, "the body ends on a DATA frame of the default SETTINGS_MAX_FRAME_SIZE");
    using soliciting = Http2RawClient::soliciting;
    struct flood {
        const char      *name;
        const char      *key; // of its RecordProperty
        soliciting       what;
        std::string_view reply;  // the reply each frame draws, as the server writes it
        const char      *goaway; // the debug data of the GOAWAY that closes it
    };
    const flood floods[] = {
        {"PING", "ping", soliciting::pings, std::string_view("\x00\x00\x08\x06\x01\x00\x00\x00\x00\x51\x42\x31\x32\x37\x30\x00\x00", 17),
         "Excessive PING control frames (flood)"},
        {"SETTINGS", "settings", soliciting::settings, std::string_view("\x00\x00\x00\x04\x01\x00\x00\x00\x00", 9),
         "Excessive SETTINGS control frames (flood)"},
        {"DATA on a closed stream", "reset", soliciting::data_on_a_closed_stream,
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
        client.write_budget = kBudget;
        ASSERT_TRUE(client.connect(port, {{Http2RawClient::SETTINGS_INITIAL_WINDOW_SIZE, kWindow}}));
        ASSERT_TRUE(client.window_update(0, kWindow - 65535));
        ASSERT_TRUE(client.read_until([&] { return client.settings_acked; }));
        const std::uint32_t closed = client.request("/served"); // stream 1: answered, so closed for the server
        ASSERT_EQ(closed, 1u);
        ASSERT_TRUE(client.read_until([&] { return client.stream(closed).end_stream; }));
        const std::uint32_t large = client.request("/large");
        ASSERT_NE(large, 0u);
        // The head of the large response, and whatever came with it in one read: the server wrote the body whole.
        ASSERT_TRUE(client.read_until([&] { return client.stream(large).status() == 200; }, kBudget)) << "the large response did not begin";
        const auto read = [&] {
            return what == soliciting::pings ? client.pongs : what == soliciting::settings ? client.settings_acks : client.resets;
        };
        ASSERT_FALSE(client.write_failed);
        const std::size_t before    = read();
        std::size_t       solicited = 0;
        bool              taking    = true; // the server still takes what the client writes
        while (taking && solicited * reply.size() < kFlood) {
            taking = client.solicit(999, what, closed) && client.request("/served") != 0;
            solicited += 999;
        }
        // The flood ends on a write the closed connection refuses: the session closed it at the verdict.
        EXPECT_TRUE(client.write_failed) << "the flood stopped after " << solicited << " solicited without the connection breaking";
        // Now the client reads. A server that still serves answers one last request, after everything else it wrote.
        const std::uint32_t last = taking ? client.request("/served") : 0;
        (void) client.read_until([&] { return client.eof || (last != 0 && client.stream(last).end_stream); }, kBudget);
        const std::size_t replies = read() - before;
        ASSERT_TRUE(client.eof) << "a client that never read drew " << replies << " replies of " << solicited
                                << " solicited and the connection still serves: they queued in the server's output";
        EXPECT_EQ(replies, 0u) << "a reply reached the client ahead of the large body it never read";
        EXPECT_FALSE(client.goaway_seen) << "a GOAWAY reached the client ahead of the large body it never read";
        client.close();

        std::optional<std::string> held;
        const auto                 deadline = std::chrono::steady_clock::now() + 10s;
        while (!(held = g_closed.take()) && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(1ms);
        ASSERT_TRUE(held.has_value()) << "the session did not close with bytes queued";
        RecordProperty(std::string("held_octets_") + each.key, std::to_string(held->size()));
        // The premise: nothing written after the large body left -- its last DATA frame, END_STREAM, is still there.
        const char end_of_large[] = {
            '\x00',
            '\x40',
            '\x00',
            '\x00',
            '\x01',
            static_cast<char>(large >> 24),
            static_cast<char>(large >> 16),
            static_cast<char>(large >> 8),
            static_cast<char>(large)
        };
        const std::size_t end_at = held->find(std::string_view(end_of_large, sizeof end_of_large));
        ASSERT_NE(end_at, std::string::npos) << "the large body left the session's output whole: " << held->size() << " octets held";
        ASSERT_LT(end_at, held->find(reply)) << "a reply was queued ahead of the end of the large body";
        const auto goaway = last_goaway(*held);
        ASSERT_TRUE(goaway.has_value()) << "the output the session closed with does not end on a GOAWAY";
        EXPECT_EQ(goaway->first, kEnhanceYourCalm);
        EXPECT_EQ(goaway->second, each.goaway);
        EXPECT_EQ(occurrences(*held, reply), 1000u) << "the connection was not closed at the 1001st reply queued";
    };
    for (const flood &each : floods) {
        never_reads(each);
    }
}

/// One-connection TLS + HTTP/2 server peer on its own thread (non-blocking sockets, polled, every wait bounded): it
/// negotiates ALPN h2, sends its SETTINGS and acknowledges the client's, then solicits replies from the client -- PONGs
/// with PING frames, or RST_STREAMs with HEADERS frames on stream 1, once it has answered the client's request there
/// (204, END_STREAM: the stream is closed) and seen as many requests as its plan waits for; it answers no other. A
/// peer that reads sends `batches` rounds of `per_batch` frames in one write, each round once every reply of the
/// rounds before it was read; one that does not read writes every round first -- or until the client ends the
/// connection, or the test tells it to stop (stop_writing()) -- and only then reads what the client had sent. It
/// records the replies, a GOAWAY the client sends, and the end of the connection.
class SolicitingPeer {
public:
    enum class soliciting { pongs, resets };
    struct plan {
        soliciting  what;
        std::size_t batches;
        std::size_t per_batch;
        bool        reads    = true; ///< false: every round is written before the first reply is read
        std::size_t requests = 0;    ///< the client's requests to see before the first round (resets: 1 at least)
    };

    explicit SolicitingPeer(plan what)
        : _plan(what) {
        _listener.init(qb::io::ssl::Context::server(qb::http::test::ssl_cert_path(), qb::http::test::ssl_key_path()).alpn({"h2"}));
        if (_listener.listen_v4(0, "127.0.0.1") != 0)
            return;
        _listener.set_nonblocking(true);
        _port   = _listener.local_endpoint().port();
        _thread = std::thread([this] { run(); });
    }
    ~SolicitingPeer() {
        _release = true;
        if (_thread.joinable())
            _thread.join();
    }
    SolicitingPeer(const SolicitingPeer &)            = delete;
    SolicitingPeer &operator=(const SolicitingPeer &) = delete;

    [[nodiscard]] std::uint16_t
    port() const noexcept {
        return _port;
    }
    /// The replies read: PONGs, or RST_STREAMs.
    [[nodiscard]] std::size_t
    replies() const noexcept {
        return _replies.load();
    }
    /// The frames written that each solicit one reply.
    [[nodiscard]] std::size_t
    solicited() const noexcept {
        return _solicited.load();
    }
    /// A peer that does not read stops offering frames and reads what the client had sent: the test calls it once the
    /// client has closed the connection, which a peer that only writes cannot learn on every platform (a write to a
    /// connection its other end closed fails at once on Linux and blocks on Windows).
    void
    stop_writing() noexcept {
        _stop_writing = true;
    }
    /// Every frame of every round was written and answered.
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
    append_frame(std::vector<uint8_t> &out, std::uint8_t type, std::uint8_t flags, std::uint32_t stream, std::vector<uint8_t> const &payload) {
        const auto n = static_cast<std::uint32_t>(payload.size());
        out.insert(out.end(), {static_cast<uint8_t>(n >> 16), static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n), type, flags,
                               static_cast<uint8_t>(stream >> 24), static_cast<uint8_t>(stream >> 16), static_cast<uint8_t>(stream >> 8),
                               static_cast<uint8_t>(stream)});
        out.insert(out.end(), payload.begin(), payload.end());
    }

    enum class written { all, stopped, failed };

    written
    write_all(qb::io::tcp::ssl::socket &sock, std::vector<uint8_t> const &bytes, std::chrono::steady_clock::time_point deadline) {
        std::size_t off = 0;
        while (off < bytes.size() && !_release && !_stop_writing && std::chrono::steady_clock::now() < deadline) {
            const int n = sock.write(reinterpret_cast<char const *>(bytes.data() + off), bytes.size() - off);
            if (n < 0)
                return written::failed;
            if (n == 0)
                std::this_thread::sleep_for(1ms);
            off += static_cast<std::size_t>(n);
        }
        return off == bytes.size() ? written::all : written::stopped;
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
        const std::size_t     total        = _plan.batches * _plan.per_batch;
        std::vector<uint8_t>  round; // the frames of one round
        for (std::size_t i = 0; i < _plan.per_batch; ++i) {
            if (_plan.what == soliciting::pongs)
                append_frame(round, 0x6, 0, 0, {0x70, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x00});
            else
                append_frame(round, 0x1, 0x4, 1, {0x88}); // HEADERS, END_HEADERS, stream 1: `:status: 200`
        }
        std::vector<uint8_t> in;
        bool                 preface_seen = false;
        bool                 answered     = false; // our SETTINGS and the ACK of the client's are sent
        bool                 acked        = false; // the client acknowledged our SETTINGS
        bool                 closed_one   = false; // the client's request on stream 1 is answered: the stream is closed
        std::size_t          requests     = 0;     // the client's HEADERS frames seen
        std::size_t          sent         = 0;     // frames written that each solicit a reply
        bool                 gave_up      = false; // told to stop, or out of time: nothing more is written
        char                 buffer[16384];
        while (!_release && std::chrono::steady_clock::now() < deadline) {
            const bool ready = acked && requests >= _plan.requests && (_plan.what == soliciting::pongs || closed_one);
            gave_up          = gave_up || _stop_writing;
            if (ready && !gave_up && !_goaway && sent < total && (!_plan.reads || _replies == sent)) {
                const written round_written = write_all(sock, round, deadline);
                if (round_written == written::failed) {
                    _eof = true; // the client ended the connection
                    break;
                }
                sent += _plan.per_batch; // a round cut short counts whole: an upper bound on what was solicited
                _solicited = sent;
                gave_up    = round_written == written::stopped;
                if (!_plan.reads && !gave_up && sent < total)
                    continue; // a peer that does not read: the next round, nothing read
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
                const std::uint8_t  type = head[3], flags = head[4];
                const std::uint32_t stream =
                    ((std::uint32_t{head[5]} << 24) | (std::uint32_t{head[6]} << 16) | (std::uint32_t{head[7]} << 8) | head[8]) & 0x7fffffffu;
                if (type == 0x4 && (flags & 0x1) != 0) {
                    acked = true;
                } else if (type == 0x4 && !answered) {
                    std::vector<uint8_t> reply;
                    append_frame(reply, 0x4, 0, 0, {});   // our SETTINGS
                    append_frame(reply, 0x4, 0x1, 0, {}); // the ACK of the client's
                    if (write_all(sock, reply, deadline) != written::all) {
                        _eof = true;
                        return;
                    }
                    answered = true;
                } else if (type == 0x1) {
                    ++requests;
                    if (stream == 1 && !closed_one) {
                        std::vector<uint8_t> response;
                        append_frame(response, 0x1, 0x5, 1, {0x89}); // HEADERS, END_STREAM | END_HEADERS: `:status: 204`
                        if (write_all(sock, response, deadline) != written::all) {
                            _eof = true;
                            return;
                        }
                        closed_one = true;
                    }
                } else if (_plan.what == soliciting::pongs ? (type == 0x6 && (flags & 0x1) != 0) : type == 0x3) {
                    ++_replies;
                } else if (type == 0x7 && length >= 8) {
                    _goaway_code =
                        (std::uint32_t{head[13]} << 24) | (std::uint32_t{head[14]} << 16) | (std::uint32_t{head[15]} << 8) | head[16];
                    _goaway = true;
                }
                at += 9 + length;
            }
            in.erase(in.begin(), in.begin() + static_cast<std::ptrdiff_t>(at));
            if (!gave_up && sent == total && _replies == total)
                _done = true;
        }
        sock.disconnect();
        sock.close();
    }

    plan                       _plan;
    qb::io::tcp::ssl::listener _listener;
    std::uint16_t              _port = 0;
    std::atomic<bool>          _release{false};
    std::atomic<bool>          _stop_writing{false};
    std::atomic<std::size_t>   _replies{0};
    std::atomic<std::size_t>   _solicited{0};
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
    SolicitingPeer peer({SolicitingPeer::soliciting::pongs, 6, 500});
    ASSERT_NE(peer.port(), 0);
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(peer.port()));
    client->set_verify_peer(false); // self-signed test cert
    client->set_connect_timeout(5s);
    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread<GuardServer>::pump_until([&] { return connected; }));
    ASSERT_TRUE(ServerThread<GuardServer>::pump_until([&] { return peer.done() || peer.goaway() || peer.eof(); }, 60s))
        << peer.replies() << " PONGs read";
    EXPECT_FALSE(peer.goaway()) << "the client closed the connection with GOAWAY code " << peer.goaway_code() << " after " << peer.replies()
                                << " PONGs";
    EXPECT_EQ(peer.replies(), 3000u);
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    EXPECT_TRUE(ServerThread<GuardServer>::pump_until([&] { return peer.eof(); }, 10s));
}

// The module's client, a server whose frames fall on a stream that has closed -- and that reads: the client's request
// on stream 1 is answered and the stream closed, then 500 HEADERS on it in one write, their 500 resets read, six times
// over. The client's resets leave its output between two rounds: 3000 are sent, no GOAWAY, and the client stays
// connected. The resets a server solicits count while they are QUEUED (Huly QB-1270): one that reads is never cut.
TEST_F(Http2ClientControlRepliesWireTest, AServerWhoseFramesFallOnAClosedStreamIsNeverCutWhileItReads) {
    SolicitingPeer peer({SolicitingPeer::soliciting::resets, 6, 500, true, 1});
    ASSERT_NE(peer.port(), 0);
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(peer.port()));
    client->set_verify_peer(false); // self-signed test cert
    client->set_connect_timeout(5s);
    client->disable_auto_reconnect();
    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread<GuardServer>::pump_until([&] { return connected; }));
    bool answered = false;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/closed")},
                                     [&](qb::http::Response response) { answered = response.status() == qb::http::status::NO_CONTENT; }));
    ASSERT_TRUE(ServerThread<GuardServer>::pump_until([&] { return peer.done() || peer.goaway() || peer.eof(); }, 60s))
        << peer.replies() << " resets read of " << peer.solicited() << " solicited";
    EXPECT_TRUE(answered) << "the request on stream 1 was not answered 204";
    EXPECT_FALSE(peer.goaway()) << "the client closed the connection with GOAWAY code " << peer.goaway_code() << " after " << peer.replies()
                                << " resets";
    EXPECT_EQ(peer.replies(), 3000u);
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    EXPECT_TRUE(ServerThread<GuardServer>::pump_until([&] { return peer.eof(); }, 10s));
}

// The attack on the client, over real sockets: a server that answers a request, then sends HEADERS on that closed
// stream and reads nothing -- 64 MiB of resets solicited, a 13-octet RST_STREAM for each 10-octet frame. They were in
// no count: the client queued every one of them and stayed connected, its second request still waiting. Once the
// server's side of the socket takes no more, a thousand resets wait in the client's output and the next one closes the
// connection: the request in flight fails with the guard's reason, and the server -- told then to stop writing and
// read at last, where its write has not failed already -- finds the connection ended and fewer resets than it
// solicited.
TEST_F(Http2ClientControlRepliesWireTest, AServerThatNeverReadsIsCutOnceAThousandResetsAreQueued) {
    // One write of the server is one TLS record, one read of the client: fewer than a thousand frames in it, since the
    // frames of one read are answered before the output is written -- a thousand solicited within one read would close
    // the connection whatever the server had read. What closes it here is what the socket no longer takes.
    constexpr std::size_t per_round = 999;
    constexpr std::size_t rounds    = (std::size_t{64} << 20) / 13 / per_round + 1; // 64 MiB of RST_STREAM frames
    SolicitingPeer        peer({SolicitingPeer::soliciting::resets, rounds, per_round, false, 2});
    ASSERT_NE(peer.port(), 0);
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(peer.port()));
    client->set_verify_peer(false); // self-signed test cert
    client->set_connect_timeout(5s);
    client->set_request_timeout(120s); // the request in flight ends with the connection, not on its own
    client->disable_auto_reconnect();
    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread<GuardServer>::pump_until([&] { return connected; }));
    bool                       answered = false;
    std::optional<std::string> in_flight; // how the request the server never answers ended
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/closed")},
                                     [&](qb::http::Response response) { answered = response.status() == qb::http::status::NO_CONTENT; }));
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/in-flight")},
                                     [&](qb::http::Response response) { in_flight = response.body().as<std::string>(); }));
    ASSERT_TRUE(ServerThread<GuardServer>::pump_until([&] { return in_flight.has_value() || peer.done() || peer.eof(); }, 60s))
        << peer.replies() << " resets read of " << peer.solicited() << " solicited";
    EXPECT_TRUE(answered) << "the request on stream 1 was not answered 204";
    EXPECT_FALSE(peer.done()) << "a server that never read drew " << peer.replies() << " resets of " << peer.solicited()
                              << " solicited and the client is still connected: they queued in the client's output";
    ASSERT_TRUE(in_flight.has_value()) << "the connection was not closed: the request in flight is still waiting";
    // The client's own reason, named once: it read « Server sent GOAWAY: GOAWAY sent by client: ... » (Huly QB-1270).
    EXPECT_EQ(*in_flight, "GOAWAY sent by client: Excessive stream resets solicited (server flood)")
        << "the connection was closed for another reason, or the reason is not the client's alone";
    EXPECT_FALSE(client->is_connected());
    peer.stop_writing(); // the client is gone: the server reads what it had been sent
    EXPECT_TRUE(ServerThread<GuardServer>::pump_until([&] { return peer.eof(); }, 30s)) << "the server did not see the connection end";
    EXPECT_LT(peer.replies(), peer.solicited());
    RecordProperty("resets_solicited", std::to_string(peer.solicited())); // an upper bound: a round cut short counts whole
    RecordProperty("resets_read", std::to_string(peer.replies()));
    client->disconnect();
}

} // namespace http2_control_replies_test

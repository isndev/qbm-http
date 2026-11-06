/**
 * @file qbm/http/tests/system/http2/http2-response-stream.cpp
 * @brief `Context::begin_stream()` / `ResponseStream` over a real HTTP/2 session, frame by frame (Huly QB-86).
 *
 * A real HTTP/2 server runs on a worker thread (the shared `ServerThread` harness, a port the system assigns); the
 * client is the raw HTTP/2 client of `shared/http2_raw_client.h` on the test thread -- TLS, ALPN h2, the client's own
 * SETTINGS -- so every assertion is on the frames of the wire and the client decides what it grants: the initial
 * window, each WINDOW_UPDATE, a RST_STREAM or a GOAWAY mid-body. What the server saw (the framing, a write verdict, a
 * parked drain and its verdict, the peak of a stream's pending bytes, a cancellation, what an observer read) is
 * published through atomics.
 *
 * One witness per decision of the design on HTTP/2:
 *   - the HEADERS leave at once and each piece follows as DATA frames: the client reads them BEFORE the stream ends,
 *     `end_of_stream` framing (no Transfer-Encoding, no Content-Length), END_STREAM at `end()`;
 *   - a window-limited client: the stream window bounds what leaves, the producer parks on `drain()` past its high
 *     mark, a WINDOW_UPDATE lets the next pieces go and resumes it with `true`, the body arrives whole;
 *   - a client that never updates its window: the session's inactivity timeout ends the stream, the drain resumes
 *     `false`;
 *   - RST_STREAM mid-body cancels the stream and the context (the producer's next write answers `closed`, the
 *     observer reads the bytes streamed) and the connection serves the next request; a GOAWAY with an error, and a
 *     GOAWAY followed by the client's close, cancel it the same way;
 *   - HEAD: the HEADERS alone, END_STREAM on them, the producer counted and the connection serving on;
 *   - trailers set at the end leave as a trailing HEADERS frame with END_STREAM, after the last DATA frame;
 *   - a declared Content-Length: identity, END_STREAM on the last byte; one not reached resets the stream;
 *   - a streamed stream holds its concurrency slot until its END_STREAM (the 51st concurrent stream is refused
 *     while it is open, accepted once it ended).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <qb/uuid.h>
#include <gtest/gtest.h>

#include "../../shared/http2_raw_client.h"
#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

#include <qb/io/async/coroutine.h>
#include <qbm/http/http.h>
#include <qbm/http/middleware/static_files.h>

using namespace std::chrono_literals;
using qb::http::test::Http2RawClient;
using qb::http::test::ServerThread;

namespace http2_stream_wire_test {

class WireServer;

class WireSession : public qb::http2::use<WireSession>::session<WireServer> {
public:
    explicit WireSession(WireServer &server)
        : session(server) {}
};

using Ctx    = qb::http::Context<WireSession>;
using Stream = qb::http::ResponseStream<WireSession>;

static_assert(qb::http::streaming_session<WireSession>, "the HTTP/2 session streams (Huly QB-86)");

// ------------------------------------------------------------------------------------------------ what the server saw
struct Seen {
    std::atomic<int>         framing{-1};
    std::atomic<bool>        release{false};      ///< the test lets a held producer go on
    std::atomic<bool>        release_held{false}; ///< the test lets the held (unanswered) requests answer
    std::atomic<int>         head_counted{0};     ///< pieces a HEAD's producer counted after the head left
    std::atomic<std::size_t> max_pending{0};
    std::atomic<int>         waits{0};
    std::atomic<bool>        parked{false};
    std::atomic<int>         drain_verdict{-1};
    std::atomic<bool>        closed_seen{false}; ///< a producer's write answered `closed`
    std::atomic<std::size_t> written_at_close{0};
    std::atomic<bool>        wait_verdict_seen{false};

    void
    reset() {
        framing           = -1;
        release           = false;
        release_held      = false;
        head_counted      = 0;
        max_pending       = 0;
        waits             = 0;
        parked            = false;
        drain_verdict     = -1;
        closed_seen       = false;
        written_at_close  = 0;
        wait_verdict_seen = false;
    }
};
inline Seen g;

struct Responded {
    int         status    = 0;
    std::size_t streamed  = 0;
    bool        cancelled = false;
};
inline std::mutex                        g_responded_mutex;
inline std::map<std::string, Responded>  g_responded;   ///< by path: what the observer read at the end
inline std::vector<std::shared_ptr<Ctx>> g_held;        ///< the requests `/hold` keeps unanswered (server thread only)
inline std::filesystem::path             g_static_root; ///< a directory with big.bin for the static files' deadline cases (Huly QB-1212)
inline constexpr std::size_t             kBigFile = std::size_t{16} * 1024 * 1024; ///< big.bin's size

struct Observer : qb::http::IRequestObserver<WireSession> {
    void
    on_response(Ctx const &ctx, qb::http::RequestEnd const &) noexcept override {
        std::lock_guard lock(g_responded_mutex);
        g_responded[std::string(ctx.request().uri().path())] = {ctx.response().status().code(), ctx.streamed_bytes(), ctx.is_cancelled()};
    }
};

[[nodiscard]] Responded
responded(std::string const &path) {
    std::lock_guard lock(g_responded_mutex);
    return g_responded[path];
}

/// `n` pieces, one per turn; held at `hold_at` until the test releases it; then end().
void
pieces(std::shared_ptr<Stream> stream, int i, int n, int hold_at) {
    if (stream->cancelled())
        return;
    if (i == n) {
        stream->end();
        return;
    }
    if (i == hold_at && !g.release) {
        qb::io::async::callback([stream, i, n, hold_at] { pieces(stream, i, n, hold_at); }, 2ms);
        return;
    }
    (void) stream->write("piece-" + std::to_string(i) + ";");
    if (stream->head_only())
        g.head_counted = static_cast<int>(stream->written() / 8);
    qb::io::async::callback([stream, i, n, hold_at] { pieces(stream, i + 1, n, hold_at); }, 1ms);
}

/// A producer that never ends: 64 KiB pieces while the stream takes them, parked on on_drain() above the high mark, so
/// the connection's output stays between the marks for as long as the peer reads -- what a sibling is measured against.
void
bulk(std::shared_ptr<Stream> stream) {
    static const std::string piece(64 * 1024, 'b');
    while (!stream->cancelled() && !stream->needs_drain()) {
        if (stream->write(piece) != Stream::write_result::taken)
            return;
    }
    if (!stream->cancelled())
        stream->on_drain([stream] { bulk(stream); });
}

/// One cycle of a client that reads a bulk sibling in SIPS: at least `bytes` of stream `b` (a read pass takes up to 64 KiB
/// more), the windows re-credited so `b` never runs dry, then `pause`. Returns how much `b` grew in the cycle -- the
/// output held between the marks and drained a sip at a time is what the sibling cases are measured against.
template <typename Stop>
std::size_t
sip(Http2RawClient &c, std::uint32_t b, std::size_t bytes, std::chrono::milliseconds pause, std::uint64_t &credited, Stop &&stop) {
    const auto before = c.stream(b).data_bytes;
    c.read_until([&] { return c.stream(b).data_bytes >= before + bytes || stop() || c.eof; }, 500ms);
    if (c.stream(b).data_bytes + (std::uint64_t{4} << 20) > credited) {
        (void) c.window_update(0, 8u << 20);
        (void) c.window_update(b, 8u << 20);
        credited += 8u << 20;
    }
    std::this_thread::sleep_for(pause);
    return c.stream(b).data_bytes - before;
}

/// A tick every 5 ms until the stream is closed under it.
void
forever(std::shared_ptr<Stream> stream) {
    const auto verdict = stream->write("tick;");
    if (verdict == Stream::write_result::closed) {
        g.closed_seen      = true;
        g.written_at_close = stream->written();
        return; // the handle dies here: a cancelled stream aborts nothing
    }
    qb::io::async::callback([stream] { forever(stream); }, 5ms);
}

void
answer_held_when_released() {
    if (!g.release_held) {
        qb::io::async::callback([] { answer_held_when_released(); }, 5ms);
        return;
    }
    for (auto &ctx : g_held)
        ctx->text("held");
    g_held.clear();
}

class WireServer : public qb::http2::use<WireServer>::server<WireSession> {
public:
    WireServer() {
        router().add_observer(std::make_shared<Observer>());
        if (!g_static_root.empty()) // /static/big.bin streams, and a client that stops taking bytes is cut at 500 ms
            router().use(qb::http::static_files_middleware<WireSession>(qb::http::StaticFilesOptions(g_static_root)
                                                                            .with_path_prefix_to_strip("/static")
                                                                            .with_stream_threshold(std::size_t{64} * 1024)
                                                                            .with_stream_idle_deadline(500ms)));

        const auto pieces_route = [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Type", "text/plain");
            auto stream = ctx->begin_stream();
            g.framing   = static_cast<int>(stream->framing());
            pieces(std::move(stream), 0, 6, 3);
        };
        router().get("/pieces", pieces_route);
        router().head("/pieces", pieces_route);

        router().get("/window", [](std::shared_ptr<Ctx> ctx) -> qb::io::async::task<void> {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Type", "application/octet-stream");
            auto stream = ctx->begin_stream();
            stream->set_watermarks(32 * 1024, 16 * 1024);
            const std::string piece(16 * 1024, 'w');
            for (int i = 0; i < 16; ++i) {
                const auto verdict = stream->write(piece);
                if (verdict == Stream::write_result::wait)
                    g.wait_verdict_seen = true;
                if (verdict == Stream::write_result::closed) {
                    g.closed_seen = true;
                    co_return;
                }
                const auto pending = stream->pending();
                if (pending > g.max_pending)
                    g.max_pending = pending;
                if (stream->needs_drain()) {
                    ++g.waits;
                    g.parked        = true;
                    const bool ok   = co_await stream->drain();
                    g.parked        = false;
                    g.drain_verdict = ok ? 1 : 0;
                    if (!ok)
                        co_return;
                }
            }
            stream->end();
        });

        router().get("/window-timeout", [](std::shared_ptr<Ctx> ctx) -> qb::io::async::task<void> {
            ctx->session()->setTimeout(300ms); // a short inactivity timeout for this connection
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            stream->set_watermarks(8 * 1024, 4 * 1024);
            const std::string piece(8 * 1024, 't');
            for (int i = 0; i < 8; ++i) {
                (void) stream->write(piece);
                if (stream->needs_drain()) {
                    ++g.waits;
                    g.parked        = true;
                    const bool ok   = co_await stream->drain();
                    g.parked        = false;
                    g.drain_verdict = ok ? 1 : 0;
                    if (!ok)
                        co_return;
                }
            }
            stream->end();
        });

        router().get("/forever", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            forever(ctx->begin_stream());
        });
        router().get("/bulk", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            bulk(ctx->begin_stream());
        });

        router().get("/chunked-said", [](std::shared_ptr<Ctx> ctx) { // a handler written for HTTP/1.1
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Transfer-Encoding", "chunked");
            auto stream = ctx->begin_stream();
            g.framing   = static_cast<int>(stream->framing());
            (void) stream->write("said;");
            (void) stream->write("chunked;");
            stream->end();
        });

        router().get("/trailers", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            (void) stream->write("first;");
            qb::io::async::callback(
                [stream, ctx] {
                    (void) stream->write("second;");
                    ctx->response().trailers().set_header("x-checksum", "beef"); // set after the head left
                    stream->end();
                },
                2ms);
        });

        router().get("/declared", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "24");
            auto stream = ctx->begin_stream();
            g.framing   = static_cast<int>(stream->framing());
            (void) stream->write("12345678");
            qb::io::async::callback(
                [stream] {
                    (void) stream->write("abcdefgh");
                    qb::io::async::callback(
                        [stream] {
                            (void) stream->write("ABCDEFGH");
                            stream->end();
                        },
                        1ms);
                },
                1ms);
        });
        router().get("/declared-short", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "24");
            auto stream = ctx->begin_stream();
            (void) stream->write("12345678");
            stream->end(); // 16 bytes short: the message cannot be completed
        });

        router().get("/hold", [](std::shared_ptr<Ctx> ctx) {
            if (g_held.empty())
                answer_held_when_released();
            g_held.push_back(std::move(ctx));
        });

        router().get("/plain", [](std::shared_ptr<Ctx> ctx) { ctx->text("still served"); });
        // A producer slower than its own idle deadline (a piece, then one more and the end 700 ms later, under 250 ms):
        // nothing of ITS waits between the pieces, whatever its siblings put through the connection (Huly QB-1212).
        router().get("/slow-producer", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            stream->set_idle_deadline(250ms);
            (void) stream->write("first;");
            qb::io::async::callback(
                [stream] {
                    (void) stream->write("second;");
                    stream->end();
                },
                700ms);
        });
        router().compile();
    }
};

class Http2StreamWireTest : public ::testing::Test {
protected:
    std::uint16_t                             port{0};
    std::unique_ptr<ServerThread<WireServer>> server;

    /// A directory with big.bin, 16 MiB of pseudo-random bytes (more than any loopback socket buffers hold, whatever the
    /// host's TCP tuning), for the static files' deadline cases (Huly QB-1212): written once for the suite, mounted by
    /// every WireServer under /static.
    static void
    SetUpTestSuite() {
        g_static_root = std::filesystem::temp_directory_path() / ("qbm-h2-deadline-" + uuids::to_string(qb::generate_random_uuid()));
        std::filesystem::create_directories(g_static_root);
        std::string   big(kBigFile, '\0');
        std::uint32_t x = 7u;
        for (auto &ch : big) {
            x  = x * 1664525u + 1013904223u;
            ch = static_cast<char>(x >> 24);
        }
        std::ofstream out(g_static_root / "big.bin", std::ios::binary);
        out.write(big.data(), static_cast<std::streamsize>(big.size()));
        out.close();
        ASSERT_TRUE(out.good()) << "big.bin was not written under " << g_static_root;
    }
    static void
    TearDownTestSuite() {
        std::error_code ec;
        std::filesystem::remove_all(g_static_root, ec);
        g_static_root.clear();
    }

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "Missing TLS test certificates (" << qb::http::test::ssl_cert_path() << ")";
        g.reset();
        {
            std::lock_guard lock(g_responded_mutex);
            g_responded.clear();
        }
        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();
        server                 = std::make_unique<ServerThread<WireServer>>([cert, key](WireServer &srv) -> bool {
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
        g.release      = true;
        g.release_held = true;
        server.reset();
    }

    template <typename Pred>
    static bool
    wait_for(Pred &&pred, std::chrono::milliseconds budget = 5s) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!pred()) {
            if (std::chrono::steady_clock::now() >= deadline)
                return false;
            std::this_thread::sleep_for(1ms);
        }
        return true;
    }
};

TEST_F(Http2StreamWireTest, DataFramesArriveBeforeTheStreamEnds) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto id = c.request("/pieces");
    ASSERT_NE(id, 0u);
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).data.size() >= 3; }));
    const auto &s = c.stream(id);
    EXPECT_EQ(s.status(), 200);
    EXPECT_FALSE(s.end_stream) << "three pieces read while the producer is held: the response is not over";
    EXPECT_EQ(s.body(), "piece-0;piece-1;piece-2;");
    EXPECT_TRUE(s.header("transfer-encoding").empty()) << "no coding on HTTP/2";
    EXPECT_TRUE(s.header("content-length").empty()) << "the end of the stream delimits the body";
    EXPECT_EQ(g.framing.load(), static_cast<int>(qb::http::stream_framing::end_of_stream));
    g.release = true;
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).end_stream; }));
    EXPECT_EQ(c.stream(id).body(), "piece-0;piece-1;piece-2;piece-3;piece-4;piece-5;");
    EXPECT_FALSE(c.stream(id).reset);
    const auto seen = responded("/pieces");
    EXPECT_EQ(seen.status, 200);
    EXPECT_EQ(seen.streamed, 48u) << "the observer reads the bytes streamed";
    EXPECT_FALSE(seen.cancelled);
    c.close();
}

TEST_F(Http2StreamWireTest, TheStreamWindowBoundsTheServerAndAWindowUpdateResumesTheDrain) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port, {{Http2RawClient::SETTINGS_INITIAL_WINDOW_SIZE, 16384}}));
    const auto id = c.request("/window");
    ASSERT_NE(id, 0u);
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).data_bytes >= 16384; }));
    c.read_for(200ms);
    EXPECT_EQ(c.stream(id).data_bytes, 16384u) << "the stream window: not a byte more until a WINDOW_UPDATE";
    EXPECT_FALSE(c.stream(id).end_stream);
    ASSERT_TRUE(wait_for([] { return g.parked.load(); })) << "the producer waits on drain() past its high mark";
    EXPECT_GE(g.max_pending.load(), std::size_t{32} * 1024) << "the windows held the pieces: pending() counts them";
    EXPECT_FALSE(g.wait_verdict_seen) << "nothing is refused for a window: `wait` is for the hard cap";
    // Grant the window piece by piece: each update lets 16 KiB more go, and the connection's window too.
    for (int i = 0; i < 20 && !c.stream(id).end_stream; ++i) {
        ASSERT_TRUE(c.window_update(id, 16384));
        ASSERT_TRUE(c.window_update(0, 16384));
        c.read_for(30ms);
    }
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).end_stream; }));
    EXPECT_EQ(c.stream(id).data_bytes, std::size_t{256} * 1024);
    EXPECT_GE(g.waits.load(), 1);
    EXPECT_EQ(g.drain_verdict.load(), 1) << "the drain resumed to write on";
    EXPECT_FALSE(c.stream(id).reset);
    for (auto const &piece : c.stream(id).data)
        EXPECT_LE(piece.size(), 16384u) << "a frame never passes the peer's frame size";
    c.close();
}

TEST_F(Http2StreamWireTest, AClientThatNeverUpdatesItsWindowIsEndedByTheInactivityTimeout) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port, {{Http2RawClient::SETTINGS_INITIAL_WINDOW_SIZE, 16384}}));
    const auto id = c.request("/window-timeout");
    ASSERT_NE(id, 0u);
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).data_bytes >= 16384; }));
    ASSERT_TRUE(wait_for([] { return g.parked.load(); }));
    ASSERT_TRUE(c.read_until([&] { return c.eof; }, 3s)) << "the session timed out and closed the connection";
    EXPECT_TRUE(wait_for([] { return g.drain_verdict.load() == 0; })) << "the parked drain resumed with false";
    EXPECT_FALSE(c.stream(id).end_stream);
}

TEST_F(Http2StreamWireTest, AResetFromThePeerCancelsTheStreamAndTheConnectionServesOn) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto id = c.request("/forever");
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).data.size() >= 2; }));
    ASSERT_TRUE(c.rst_stream(id, 0x8)); // CANCEL
    ASSERT_TRUE(wait_for([] { return g.closed_seen.load(); })) << "the producer's next write answered `closed`";
    const auto next = c.request("/plain");
    ASSERT_TRUE(c.read_until([&] { return c.stream(next).end_stream; }));
    EXPECT_EQ(c.stream(next).status(), 200);
    EXPECT_EQ(c.stream(next).body(), "still served");
    EXPECT_FALSE(c.eof) << "the stream was reset, never the connection";
    const auto seen = responded("/forever");
    EXPECT_TRUE(seen.cancelled);
    EXPECT_EQ(seen.status, 200) << "the head's status, as it left";
    EXPECT_EQ(seen.streamed, g.written_at_close.load()) << "the bytes streamed before the reset";
    EXPECT_GE(seen.streamed, 10u);
    c.close();
}

TEST_F(Http2StreamWireTest, AGoawayWithAnErrorCancelsTheStream) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto id = c.request("/forever");
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).data.size() >= 2; }));
    ASSERT_TRUE(c.goaway(id, 0x2)); // INTERNAL_ERROR: the server ends the connection
    ASSERT_TRUE(wait_for([] { return g.closed_seen.load(); }));
    EXPECT_TRUE(c.read_until([&] { return c.eof; }));
    EXPECT_TRUE(responded("/forever").cancelled);
}

TEST_F(Http2StreamWireTest, AGoawayThenTheClientsCloseCancelsTheStream) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto id = c.request("/forever");
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).data.size() >= 2; }));
    ASSERT_TRUE(c.goaway(id, 0x0)); // NO_ERROR: the streams open are still served...
    c.close();                      // ...until the peer leaves
    ASSERT_TRUE(wait_for([] { return g.closed_seen.load(); }));
    EXPECT_TRUE(responded("/forever").cancelled);
}

TEST_F(Http2StreamWireTest, HeadGetsTheHeadersAloneAndTheProducerRunsOn) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto id = c.request("/pieces", "HEAD");
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).end_stream; }));
    EXPECT_EQ(c.stream(id).status(), 200);
    EXPECT_TRUE(c.stream(id).data.empty()) << "no DATA frame for a HEAD";
    EXPECT_EQ(c.stream(id).header_blocks, 1);
    const auto next = c.request("/plain");
    ASSERT_TRUE(c.read_until([&] { return c.stream(next).end_stream; })) << "the connection serves on while the producer counts";
    EXPECT_EQ(c.stream(next).body(), "still served");
    g.release = true;
    EXPECT_TRUE(wait_for([] { return g.head_counted.load() >= 6; })) << "the producer counted its pieces, none written";
    EXPECT_TRUE(c.stream(id).data.empty());
    c.close();
}

TEST_F(Http2StreamWireTest, TrailersSetAtTheEndLeaveAsATrailingHeadersFrame) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto id = c.request("/trailers");
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).end_stream; }));
    const auto &s = c.stream(id);
    EXPECT_EQ(s.body(), "first;second;");
    EXPECT_EQ(s.header_blocks, 2) << "the head, then the trailer section";
    EXPECT_EQ(s.trailer("x-checksum"), "beef");
    // The last DATA frame did not end the stream: the trailers' HEADERS did.
    bool data_ended = false;
    for (auto const &f : c.frames)
        if (f.type == Http2RawClient::DATA && f.stream_id == id && (f.flags & Http2RawClient::END_STREAM))
            data_ended = true;
    EXPECT_FALSE(data_ended);
    c.close();
}

TEST_F(Http2StreamWireTest, ADeclaredLengthStreamsIdentityAndEndsOnItsLastByte) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto id = c.request("/declared");
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).end_stream; }));
    EXPECT_EQ(g.framing.load(), static_cast<int>(qb::http::stream_framing::content_length));
    EXPECT_EQ(c.stream(id).header("content-length"), "24");
    EXPECT_EQ(c.stream(id).body(), "12345678abcdefghABCDEFGH");
    EXPECT_FALSE(c.stream(id).reset);
    // Each piece left as it was written (the window open), before end(): END_STREAM rides an empty fourth DATA frame.
    ASSERT_EQ(c.stream(id).data.size(), 4u);
    EXPECT_TRUE(c.stream(id).data.back().empty());
    bool end_on_last = false;
    for (auto const &f : c.frames)
        if (f.type == Http2RawClient::DATA && f.stream_id == id && (f.flags & Http2RawClient::END_STREAM))
            end_on_last = f.payload.empty();
    EXPECT_TRUE(end_on_last) << "END_STREAM on the empty frame, on no other";
    c.close();
}

TEST_F(Http2StreamWireTest, AStaticDownloadWhosePeerStopsTakingBytesIsResetAtTheIdleDeadline) {
    // The peer's window takes the first 16 KiB and never grows: no byte is accepted past them. The static files'
    // idle deadline (500 ms here) aborts the stream -- RST_STREAM(INTERNAL_ERROR), the file released -- and the
    // connection serves on (Huly QB-1212).
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port, {{Http2RawClient::SETTINGS_INITIAL_WINDOW_SIZE, 16384}}));
    const auto t0 = std::chrono::steady_clock::now();
    const auto id = c.request("/static/big.bin");
    ASSERT_NE(id, 0u);
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).data_bytes >= 16384; }));
    const auto parked = std::chrono::steady_clock::now();
    EXPECT_EQ(c.stream(id).status(), 200);
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).reset; }, 3s)) << "the stalled download was never cut";
    const auto now      = std::chrono::steady_clock::now();
    const auto cut      = std::chrono::duration_cast<std::chrono::milliseconds>(now - parked);
    const auto since_t0 = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0);
    std::cout << "[  cut   ] HTTP/2 stalled download reset " << cut.count() << " ms after the window filled (deadline 500 ms)\n";
    EXPECT_GE(since_t0, 500ms) << "not before the deadline has passed since the request: " << since_t0.count() << " ms";
    EXPECT_LE(cut, 900ms) << "within the deadline and 400 ms of loop latency (twice it: a whole deadline re-armed): " << cut.count() << " ms";
    EXPECT_EQ(c.stream(id).reset_code, 0x2u) << "INTERNAL_ERROR: the stream was aborted";
    EXPECT_EQ(c.stream(id).data_bytes, 16384u) << "nothing past the window";
    EXPECT_FALSE(c.eof) << "the stream, never the connection";
    const auto next = c.request("/plain");
    ASSERT_TRUE(c.read_until([&] { return c.stream(next).end_stream; })) << "the connection serves on";
    EXPECT_EQ(c.stream(next).body(), "still served");
    EXPECT_TRUE(wait_for([] { return responded("/static/big.bin").cancelled; })) << "the context was cancelled";
    EXPECT_LT(responded("/static/big.bin").streamed, kBigFile);
    c.close();
}

TEST_F(Http2StreamWireTest, APeerThatStopsReadingTheConnectionUnderAWideWindowIsCutAtTheIdleDeadline) {
    // The other stall of HTTP/2: the windows are wide open, so every piece leaves the stream for the connection's output,
    // and the peer stops reading the SOCKET -- the output stays full, nothing of the stream leaves it. The stream's
    // own share of the output is what the watch reads (Huly QB-1212): the download is reset at the deadline, and the
    // reset reaches the peer once it reads again, behind the data.
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port, {{Http2RawClient::SETTINGS_INITIAL_WINDOW_SIZE, 1u << 24}}));
    ASSERT_TRUE(c.window_update(0, 1u << 24));
    const auto id = c.request("/static/big.bin");
    ASSERT_NE(id, 0u);
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).data_bytes >= 64 * 1024; }));
    std::this_thread::sleep_for(1500ms); // nothing read: the socket's buffers fill and stay full for three deadlines
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).reset; }, 5s)) << "the download whose peer stopped reading was never cut";
    EXPECT_EQ(c.stream(id).reset_code, 0x2u) << "INTERNAL_ERROR: the stream was aborted";
    EXPECT_LT(c.stream(id).data_bytes, kBigFile) << "the file did not go whole";
    EXPECT_FALSE(c.eof) << "the stream, never the connection";
    const auto next = c.request("/plain");
    ASSERT_TRUE(c.read_until([&] { return c.stream(next).end_stream; })) << "the connection serves on";
    EXPECT_EQ(c.stream(next).body(), "still served");
    EXPECT_TRUE(wait_for([] { return responded("/static/big.bin").cancelled; })) << "the context was cancelled";
    c.close();
}

TEST_F(Http2StreamWireTest, AStalledDownloadIsCutWhileASiblingStreamKeepsTheConnectionBusy) {
    // The connection's output is shared: a sibling stream flowing on it must not count as the stalled stream's
    // acceptance (Huly QB-1212). Stream A: the static file behind a 16 KiB window never updated. Stream B: a bulk
    // producer, its windows re-credited as it goes, read in sips of 256 KiB with 50 ms between them, so the output
    // holds B's pieces between the marks and every write pass reports less of it -- what a shared count would read as
    // A's progress. A is reset at its deadline all the same, B flowing to the last cycle; B is untouched.
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port, {{Http2RawClient::SETTINGS_INITIAL_WINDOW_SIZE, 16384}}));
    const auto t0 = std::chrono::steady_clock::now();
    const auto a  = c.request("/static/big.bin");
    ASSERT_NE(a, 0u);
    ASSERT_TRUE(c.read_until([&] { return c.stream(a).data_bytes >= 16384; }));
    const auto parked = std::chrono::steady_clock::now();
    const auto b      = c.request("/bulk");
    ASSERT_NE(b, 0u);
    std::uint64_t credited = 16384;
    ASSERT_TRUE(c.window_update(0, 8u << 20));
    ASSERT_TRUE(c.window_update(b, 8u << 20));
    credited += 8u << 20;
    ASSERT_TRUE(c.read_until([&] { return c.stream(b).data_bytes >= 64 * 1024; })) << "the sibling flows";
    const auto  give_up      = std::chrono::steady_clock::now() + 4s;
    std::size_t last_growth  = 0;
    std::size_t prior_growth = 0;
    while (!c.stream(a).reset && !c.eof && std::chrono::steady_clock::now() < give_up) {
        prior_growth = last_growth;
        last_growth  = sip(c, b, 256 * 1024, 50ms, credited, [&] { return c.stream(a).reset; });
    }
    ASSERT_TRUE(c.stream(a).reset) << "the stalled download was never cut beside a flowing sibling";
    const auto now      = std::chrono::steady_clock::now();
    const auto cut      = std::chrono::duration_cast<std::chrono::milliseconds>(now - parked);
    const auto since_t0 = std::chrono::duration_cast<std::chrono::milliseconds>(now - t0);
    std::cout << "[  cut   ] HTTP/2 stalled download beside a flowing sibling reset " << cut.count()
              << " ms after its window filled (deadline 500 ms), B at " << c.stream(b).data_bytes << " bytes\n";
    EXPECT_GE(since_t0, 500ms) << since_t0.count() << " ms since the request";
    EXPECT_LE(cut, 1500ms) << cut.count() << " ms (the reset waits its turn behind B's frames in the output, sipped)";
    EXPECT_EQ(c.stream(a).reset_code, 0x2u) << "INTERNAL_ERROR: the stream was aborted";
    EXPECT_EQ(c.stream(a).data_bytes, 16384u) << "nothing past the window";
    EXPECT_GT(prior_growth + last_growth, 0u) << "the sibling flowed in the cycle A was cut in";
    EXPECT_GT(c.stream(b).data_bytes, std::size_t{2} << 20) << "the sibling flowed all along: " << c.stream(b).data_bytes;
    EXPECT_FALSE(c.stream(b).reset) << "the sibling is untouched";
    EXPECT_FALSE(c.eof) << "the stream, never the connection";
    EXPECT_TRUE(wait_for([] { return responded("/static/big.bin").cancelled; })) << "the context was cancelled";
    c.close();
}

TEST_F(Http2StreamWireTest, AHealthyReaderTakingItsDownloadInBurstsFinishesUnderTheDeadline) {
    // The positive control of the HTTP/2 share (Huly QB-1212): windows wide open, the client takes 1 MiB then pauses
    // 100 ms, for 16 MiB -- several deadlines long, bytes of the stream waiting in the output at every pause -- and
    // the download ends with END_STREAM, never reset: each burst drains the stream's own frames from the output.
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port, {{Http2RawClient::SETTINGS_INITIAL_WINDOW_SIZE, 1u << 24}}));
    ASSERT_TRUE(c.window_update(0, 1u << 24));
    const auto started = std::chrono::steady_clock::now();
    const auto id      = c.request("/static/big.bin");
    ASSERT_NE(id, 0u);
    int bursts = 0;
    while (!c.stream(id).end_stream && !c.stream(id).reset && !c.eof) {
        const auto before = c.stream(id).data_bytes;
        ASSERT_TRUE(
            c.read_until([&] { return c.stream(id).data_bytes >= before + (1u << 20) || c.stream(id).end_stream || c.stream(id).reset; }, 5s))
            << "burst " << bursts << " never came";
        if (c.stream(id).end_stream || c.stream(id).reset)
            break;
        std::this_thread::sleep_for(100ms);
        ++bursts;
    }
    const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    EXPECT_FALSE(c.stream(id).reset) << "a healthy reader is not a stalled peer";
    EXPECT_TRUE(c.stream(id).end_stream);
    EXPECT_EQ(c.stream(id).data_bytes, kBigFile);
    EXPECT_GE(bursts, 8) << "the client did pause on the way";
    EXPECT_GT(took, 1s) << "several deadlines long: " << took.count() << " ms";
    EXPECT_FALSE(c.eof);
    EXPECT_TRUE(wait_for([] { return responded("/static/big.bin").streamed == kBigFile; }));
    EXPECT_FALSE(responded("/static/big.bin").cancelled);
    c.close();
}

TEST_F(Http2StreamWireTest, AnIdleProducerBesideABusySiblingIsNeverCut) {
    // The mirror of the sibling case (Huly QB-1212): the same bulk sibling B holds the output between the marks, read in
    // sips, while stream A's producer writes a piece, pauses 700 ms under a 250 ms deadline, writes again and ends.
    // Nothing of A's waits once its frame has left the output -- B's bytes behind it are B's -- so A is never cut: its
    // share of the output is its last frame's distance from leaving, which reaches 0, not a count pinned by B's.
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port, {{Http2RawClient::SETTINGS_INITIAL_WINDOW_SIZE, 1u << 24}}));
    std::uint64_t credited = 65535;
    ASSERT_TRUE(c.window_update(0, 8u << 20));
    credited += 8u << 20;
    const auto b = c.request("/bulk");
    ASSERT_NE(b, 0u);
    ASSERT_TRUE(c.read_until([&] { return c.stream(b).data_bytes >= 64 * 1024; })) << "the sibling flows";
    const auto a = c.request("/slow-producer");
    ASSERT_NE(a, 0u);
    const auto  give_up     = std::chrono::steady_clock::now() + 5s;
    std::size_t last_growth = 0;
    while (!c.stream(a).end_stream && !c.stream(a).reset && !c.eof && std::chrono::steady_clock::now() < give_up)
        last_growth = sip(c, b, 256 * 1024, 50ms, credited, [&] { return c.stream(a).end_stream || c.stream(a).reset; });
    EXPECT_FALSE(c.stream(a).reset) << "an idle producer is not a stalled peer";
    EXPECT_TRUE(c.stream(a).end_stream) << "A never ended";
    EXPECT_EQ(c.stream(a).body(), "first;second;");
    EXPECT_GT(c.stream(b).data_bytes, std::size_t{2} << 20) << "the sibling flowed all along: " << c.stream(b).data_bytes;
    EXPECT_FALSE(c.stream(b).reset);
    EXPECT_FALSE(c.eof);
    (void) last_growth;
    c.close();
}

TEST_F(Http2StreamWireTest, AChunkedCodingTheHandlerSaidIsDroppedAndTheStreamIsEndOfStreamFramed) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto id = c.request("/chunked-said");
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).end_stream; }));
    EXPECT_EQ(g.framing.load(), static_cast<int>(qb::http::stream_framing::end_of_stream));
    EXPECT_EQ(c.stream(id).status(), 200) << "the head was not refused for a connection-specific field";
    EXPECT_TRUE(c.stream(id).header("transfer-encoding").empty()) << "the field a handler wrote for HTTP/1.1 is gone";
    EXPECT_EQ(c.stream(id).body(), "said;chunked;");
    EXPECT_FALSE(c.stream(id).reset);
    c.close();
}

TEST_F(Http2StreamWireTest, APeerResetWhileTheProducerWaitsOnDrainResumesItWithFalse) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port, {{Http2RawClient::SETTINGS_INITIAL_WINDOW_SIZE, 16384}}));
    const auto id = c.request("/window");
    ASSERT_NE(id, 0u);
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).data_bytes >= 16384; }));
    ASSERT_TRUE(wait_for([] { return g.parked.load(); })) << "the producer waits on drain() behind the window";
    ASSERT_TRUE(c.rst_stream(id, 0x8)); // CANCEL
    EXPECT_TRUE(wait_for([] { return g.drain_verdict.load() == 0; })) << "the parked drain resumed with false";
    EXPECT_TRUE(wait_for([] { return responded("/window").cancelled; }));
    const auto next = c.request("/plain");
    ASSERT_TRUE(c.read_until([&] { return c.stream(next).end_stream; })) << "the connection serves on";
    EXPECT_EQ(c.stream(next).body(), "still served");
    EXPECT_FALSE(c.eof);
    c.close();
}

TEST_F(Http2StreamWireTest, AnEndShortOfTheDeclaredLengthResetsTheStream) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto id = c.request("/declared-short");
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).reset; }));
    EXPECT_EQ(c.stream(id).reset_code, 0x2u) << "INTERNAL_ERROR: the message could not be completed";
    EXPECT_FALSE(c.stream(id).end_stream);
    EXPECT_EQ(c.stream(id).status(), 200) << "the head had left";
    const auto next = c.request("/plain");
    ASSERT_TRUE(c.read_until([&] { return c.stream(next).end_stream; })) << "the connection serves on";
    EXPECT_TRUE(responded("/declared-short").cancelled);
    c.close();
}

TEST_F(Http2StreamWireTest, AStreamedStreamHoldsItsConcurrencySlotUntilItsEndStream) {
    Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto streamed = c.request("/pieces");
    ASSERT_TRUE(c.read_until([&] { return c.stream(streamed).data.size() >= 3; }));
    std::vector<std::uint32_t> held;
    for (int i = 0; i < 49; ++i)
        held.push_back(c.request("/hold"));
    c.read_for(100ms);
    const auto refused = c.request("/plain");
    ASSERT_TRUE(c.read_until([&] { return c.stream(refused).reset; })) << "the 51st concurrent stream is refused";
    EXPECT_EQ(c.stream(refused).reset_code, 0x7u) << "REFUSED_STREAM";
    g.release = true; // the streamed stream ends: its slot is free
    ASSERT_TRUE(c.read_until([&] { return c.stream(streamed).end_stream; }));
    const auto served = c.request("/plain");
    ASSERT_TRUE(c.read_until([&] { return c.stream(served).end_stream || c.stream(served).reset; }));
    EXPECT_FALSE(c.stream(served).reset) << "accepted once the streamed stream ended";
    EXPECT_EQ(c.stream(served).body(), "still served");
    g.release_held = true;
    ASSERT_TRUE(c.read_until([&] { return std::all_of(held.begin(), held.end(), [&](std::uint32_t h) { return c.stream(h).end_stream; }); }));
    c.close();
}

} // namespace http2_stream_wire_test

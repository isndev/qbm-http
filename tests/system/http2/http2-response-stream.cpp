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

#include <gtest/gtest.h>

#include "../../shared/http2_raw_client.h"
#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

#include <qb/io/async/coroutine.h>
#include <qbm/http/http.h>

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
inline std::map<std::string, Responded>  g_responded; ///< by path: what the observer read at the end
inline std::vector<std::shared_ptr<Ctx>> g_held;      ///< the requests `/hold` keeps unanswered (server thread only)

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
        router().compile();
    }
};

class Http2StreamWireTest : public ::testing::Test {
protected:
    std::uint16_t                             port{0};
    std::unique_ptr<ServerThread<WireServer>> server;

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

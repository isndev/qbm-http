/**
 * @file qbm/http/tests/system/routing/response-stream.cpp
 * @brief `Context::begin_stream()` / `ResponseStream` over a real HTTP/1.1 loopback session (Huly QB-86).
 *
 * A real server runs on a worker thread (the shared @ref qb::http::test::ServerThread harness, on a port the system assigns);
 * the client is a RAW non-blocking TCP socket on the test thread, so every assertion is on the exact bytes of the wire
 * -- the framing (chunked or identity), the order of pipelined responses, an EOF where the server must close -- and
 * the client controls when it reads, which is what backpressure needs. What the server saw (the framing chosen, the
 * hooks run, the peak of its output buffer, a cancellation) is published through atomics and read after a predicate.
 *
 * One witness per decision of the design:
 *   - chunked over many turns; a declared Content-Length, identity framing, keep-alive kept;
 *   - a Content-Length body whose last byte drained before `end()` still ends (the write path is re-armed);
 *   - HEAD on a streamed route: the head alone, and the connection serves the next request;
 *   - a SYNCHRONOUS handler streams (the context being routed is adopted by its session);
 *   - backpressure: a client that does not read bounds the server's output, the producer waits, then completes;
 *   - a server torn down under a producer stalled on `on_drain()` releases the stream the callback holds (a session
 *     destroyed with its io_handler gets no disconnected event);
 *   - a coroutine producer on `co_await drain()`, and a second concurrent `drain()` refused with `false`;
 *   - the peer leaving mid-stream cancels the stream and the context; a stream dropped before `end()` closes the
 *     connection without a last-chunk;
 *   - a pipelined request is answered after the streamed one, in order;
 *   - HTTP/1.0 without a length and a 204 are BUFFERED, whole, with their hooks run at completion;
 *   - PRE_RESPONSE_SEND runs once (at the head of a stream), POST_RESPONSE_SEND once (after its last byte).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * @ingroup Http
 */
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>

#include <gtest/gtest.h>

#include "../../shared/loopback_server.h"

#include <qbm/http/http.h>

#include <qb/io/tcp/socket.h>

using namespace std::chrono_literals;
using qb::http::test::ServerThread;

namespace response_stream_test {

// ------------------------------------------------------------------------------------------------ what the server saw
struct Observed {
    std::atomic<int>         framing{-1}; ///< the last stream's stream_framing, as an int
    std::atomic<bool>        streaming{false};
    std::atomic<int>         pre_hooks{0};
    std::atomic<int>         post_hooks{0};
    std::atomic<bool>        cancelled{false};
    std::atomic<bool>        context_cancelled{false};
    std::atomic<std::size_t> max_pending{0};
    std::atomic<int>         waits{0};
    std::atomic<int>         first_drain{-1};  ///< a parked drain()'s verdict: 1 resumed to write on
    std::atomic<int>         second_drain{-1}; ///< a concurrent second drain()'s verdict: 0 refused
    std::atomic<bool>        producer_done{false};
    std::atomic<bool>        handler_parked{false}; ///< the coroutine handler is inside its own drain()
    std::atomic<bool>        handler_resumed{false};
    std::atomic<bool>        helper_saw_parked{false}; ///< the second drain() ran while the first was parked

    void
    reset() {
        framing           = -1;
        streaming         = false;
        pre_hooks         = 0;
        post_hooks        = 0;
        cancelled         = false;
        context_cancelled = false;
        max_pending       = 0;
        waits             = 0;
        first_drain       = -1;
        second_drain      = -1;
        producer_done     = false;
        handler_parked    = false;
        handler_resumed   = false;
        helper_saw_parked = false;
    }
};
inline Observed g_seen;

class StreamServer;

class StreamSession : public qb::http::use<StreamSession>::session<StreamServer> {
public:
    explicit StreamSession(StreamServer &server_ref)
        : session(server_ref) {}
};

using Ctx    = qb::http::Context<StreamSession>;
using Stream = qb::http::ResponseStream<StreamSession>;

// The session of this suite streams: were it to fall back to buffering, every case below would read wrong.
static_assert(qb::http::streaming_session<StreamSession>);

// The drain awaiter registers itself and retracts in its destructor: neither copyable nor movable (Huly QB-1000).
using DrainAwaiter = decltype(std::declval<Stream &>().drain());
static_assert(!std::is_copy_constructible_v<DrainAwaiter> && !std::is_move_constructible_v<DrainAwaiter>);
static_assert(!std::is_copy_assignable_v<DrainAwaiter> && !std::is_move_assignable_v<DrainAwaiter>);

/// The stream of `/stall`, observed weakly: set on the server's thread by its handler, read on the test's thread once
/// the server's thread is joined.
inline std::weak_ptr<Stream> g_stalled;

void
count_hooks(std::shared_ptr<Ctx> const &ctx) {
    ctx->add_lifecycle_hook([](Ctx &, qb::http::HookPoint point) {
        if (point == qb::http::HookPoint::PRE_RESPONSE_SEND)
            ++g_seen.pre_hooks;
        else if (point == qb::http::HookPoint::POST_RESPONSE_SEND)
            ++g_seen.post_hooks;
    });
}

void
record(std::shared_ptr<Ctx> const &ctx, std::shared_ptr<Stream> const &stream) {
    g_seen.framing   = static_cast<int>(stream->framing());
    g_seen.streaming = ctx->is_streaming();
}

/// `n` pieces, one per event-loop turn (1 ms apart), then end().
void
pieces_over_turns(std::shared_ptr<Stream> stream, int i, int n) {
    if (i == n) {
        stream->end();
        return;
    }
    (void) stream->write("piece-" + std::to_string(i) + ";");
    qb::io::async::callback([stream = std::move(stream), i, n]() mutable { pieces_over_turns(std::move(stream), i + 1, n); }, 1ms);
}

/// A producer without a coroutine: `total` bytes in `piece`-byte writes, waiting on on_drain() whenever the output
/// holds too much. The peak of the session's output buffer is recorded at every write.
struct BulkProducer : std::enable_shared_from_this<BulkProducer> {
    std::shared_ptr<Stream> stream;
    std::size_t             left;
    std::size_t             piece;

    BulkProducer(std::shared_ptr<Stream> s, std::size_t total, std::size_t p)
        : stream(std::move(s))
        , left(total)
        , piece(p) {}

    void
    run() {
        const std::string chunk(piece, 'x');
        while (left) {
            if (stream->cancelled() || stream->ended())
                return;
            if (stream->needs_drain()) {
                ++g_seen.waits;
                stream->on_drain([self = shared_from_this()] { self->run(); });
                return;
            }
            const auto n = std::min(left, piece);
            const auto r = stream->write(std::string_view{chunk.data(), n});
            if (r == Stream::write_result::wait) {
                ++g_seen.waits;
                stream->on_drain([self = shared_from_this()] { self->run(); });
                return;
            }
            if (r != Stream::write_result::taken)
                return;
            left -= n;
            g_seen.max_pending = std::max(g_seen.max_pending.load(), stream->pending());
        }
        stream->end();
        g_seen.producer_done = true;
    }
};

class StreamServer : public qb::http::use<StreamServer>::server<StreamSession> {
public:
    StreamServer() {
        // Chunked, eight pieces over eight turns.
        router().get("/chunked", [](std::shared_ptr<Ctx> ctx) {
            count_hooks(ctx);
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Type", "text/plain");
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            pieces_over_turns(std::move(stream), 0, 8);
        });

        // The same producer answering HEAD (the router serves HEAD only where it is registered): its head goes out,
        // its pieces are counted and discarded, no last-chunk follows.
        router().head("/chunked", [](std::shared_ptr<Ctx> ctx) {
            count_hooks(ctx);
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Type", "text/plain");
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            pieces_over_turns(std::move(stream), 0, 8);
        });

        // A declared Content-Length: identity framing, four pieces over four turns.
        router().get("/length", [](std::shared_ptr<Ctx> ctx) {
            count_hooks(ctx);
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "32"); // 4 x "piece-N;" = 4 x 8
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            pieces_over_turns(std::move(stream), 0, 4);
        });

        // A declared Content-Length, every byte written at once, end() 30 ms later: the output has drained by then,
        // and nothing is left for end() to write (review B2).
        router().get("/length-drained", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "11");
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("drained-all");
            qb::io::async::callback([stream]() { stream->end(); }, 30ms);
        });

        // A synchronous handler: begin, write and end inside the handler, while the session is still routing (B1).
        router().get("/sync", [](std::shared_ptr<Ctx> ctx) {
            count_hooks(ctx);
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("one;");
            (void) stream->write("two;");
            (void) stream->write("three;");
            stream->end();
        });

        // Backpressure: 16 MiB in 64 KiB pieces, watermarks 256 / 128 KiB.
        router().get("/bulk", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            stream->set_watermarks(256 * 1024, 128 * 1024);
            std::make_shared<BulkProducer>(std::move(stream), std::size_t{16} << 20, std::size_t{64} << 10)->run();
        });

        // The same producer with a body that never ends, for a client that never reads: it parks on on_drain() with
        // a callback that holds it, and through it the stream -- a cycle only the callback's run or release breaks.
        router().get("/stall", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            stream->set_watermarks(256 * 1024, 128 * 1024);
            g_stalled = stream;
            std::make_shared<BulkProducer>(std::move(stream), std::size_t{1} << 30, std::size_t{64} << 10)->run();
        });

        // A coroutine producer that waits with co_await drain(). The output is filled past the high mark in this very
        // turn (nothing reaches the socket before the loop runs), a helper is spawned, and the handler parks in its
        // own drain() at once: the helper, run by the scheduler while the handler is parked, is the concurrent second
        // drain() and must be refused at once.
        router().get("/coro-drain", [](std::shared_ptr<Ctx> ctx) -> qb::io::async::task<void> {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            stream->set_watermarks(64 * 1024, 32 * 1024);
            if (stream->framing() == qb::http::stream_framing::buffered)
                co_return; // a buffered stream never needs a drain: nothing to fill (the test then fails on the framing)
            const std::string piece(64 * 1024, 'c');
            while (!stream->needs_drain())
                if (stream->write(piece) != Stream::write_result::taken)
                    co_return;
            qb::io::async::coro_scheduler().spawn([stream]() -> qb::io::async::task<void> {
                g_seen.helper_saw_parked = g_seen.handler_parked.load() && !g_seen.handler_resumed.load();
                g_seen.second_drain      = (co_await stream->drain()) ? 1 : 0;
            });
            g_seen.handler_parked  = true;
            const bool may_write   = co_await stream->drain();
            g_seen.handler_resumed = true;
            g_seen.first_drain     = may_write ? 1 : 0;
            if (may_write)
                (void) stream->write("tail");
            stream->end();
            g_seen.producer_done = true;
        });

        // A producer that writes forever until the stream is cancelled under it.
        router().get("/forever", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            ctx->add_lifecycle_hook([](Ctx &c, qb::http::HookPoint) {
                if (c.is_cancelled())
                    g_seen.context_cancelled = true;
            });
            struct Forever {
                static void
                tick(std::shared_ptr<Stream> s) {
                    if (s->write("tick;") == Stream::write_result::closed || s->cancelled()) {
                        g_seen.cancelled = true;
                        return;
                    }
                    qb::io::async::callback([s = std::move(s)]() mutable { tick(std::move(s)); }, 2ms);
                }
            };
            Forever::tick(std::move(stream));
        });

        // A stream dropped before end(): the connection must close, without a last-chunk.
        router().get("/drop", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("partial;");
            // `stream` goes out of scope here: its producer is gone.
        });

        // A route answered the ordinary way, for the pipelined request.
        router().get("/plain", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "plain-body";
            ctx->complete();
        });

        // A 204 cannot carry a body: the stream is buffered.
        router().get("/no-content", [](std::shared_ptr<Ctx> ctx) {
            count_hooks(ctx);
            ctx->response().status() = qb::http::status::NO_CONTENT;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            stream->end();
        });

        router().compile();
    }
};

// ------------------------------------------------------------------------------------------------ the raw client
class RawClient {
    qb::io::tcp::socket _sock;

public:
    std::string buffer;
    bool        eof = false;

    bool
    connect(std::uint16_t port) {
        return _sock.connect_v4("127.0.0.1", port) == 0 && _sock.set_nonblocking(true) == 0;
    }

    bool
    send(std::string_view data, std::chrono::milliseconds budget = 2s) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!data.empty()) {
            const int n = _sock.write(data.data(), data.size());
            if (n > 0) {
                data.remove_prefix(static_cast<std::size_t>(n));
                continue;
            }
            if (std::chrono::steady_clock::now() >= deadline)
                return false;
            std::this_thread::sleep_for(1ms);
        }
        return true;
    }

    /// Read what is there, once; true when something came. EOF is recorded.
    bool
    read_some() {
        char      tmp[64 * 1024];
        const int n = _sock.read(tmp, sizeof tmp);
        if (n > 0) {
            buffer.append(tmp, static_cast<std::size_t>(n));
            return true;
        }
        if (n == 0 || !qb::io::socket::not_recv_error(qb::io::socket::get_last_errno()))
            eof = true; // an orderly close, or a reset: the connection is over either way
        return false;
    }

    template <typename Pred>
    bool
    read_until(Pred &&pred, std::chrono::milliseconds budget = 5s) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!pred()) {
            if (eof || std::chrono::steady_clock::now() >= deadline)
                return pred();
            if (!read_some())
                std::this_thread::sleep_for(1ms);
        }
        return true;
    }

    void
    close() {
        _sock.disconnect();
    }
};

/// One response parsed from the front of `wire`. `complete` once its whole body (by its own framing) is there.
struct Parsed {
    bool        complete = false;
    int         status   = 0;
    std::string head;
    std::string body;
    bool        chunked            = false;
    int         chunks             = 0; ///< data chunks (the last-chunk excluded)
    bool        has_content_length = false;
    std::size_t consumed           = 0;

    [[nodiscard]] bool
    header_is(std::string_view name, std::string_view value) const {
        std::string h     = head, n(name), v(value);
        auto        lower = [](std::string &s) {
            std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        };
        lower(h);
        lower(n);
        lower(v);
        return h.find("\r\n" + n + ": " + v + "\r\n") != std::string::npos;
    }
};

Parsed
parse_response(std::string_view wire, bool head_request = false) {
    Parsed     p;
    const auto end_of_head = wire.find("\r\n\r\n");
    if (end_of_head == std::string_view::npos)
        return p;
    p.head                 = std::string(wire.substr(0, end_of_head + 2));
    p.status               = std::atoi(std::string(wire.substr(9, 3)).c_str());
    std::size_t pos        = end_of_head + 4;
    p.chunked              = p.header_is("transfer-encoding", "chunked");
    std::string lower_head = p.head;
    std::transform(lower_head.begin(), lower_head.end(), lower_head.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    const auto cl        = lower_head.find("\r\ncontent-length: ");
    p.has_content_length = cl != std::string::npos;
    if (head_request || p.status == 204 || p.status == 304) {
        p.complete = true;
        p.consumed = pos;
        return p;
    }
    if (p.chunked) {
        while (true) {
            const auto line_end = wire.find("\r\n", pos);
            if (line_end == std::string_view::npos)
                return p;
            const std::size_t size = std::stoul(std::string(wire.substr(pos, line_end - pos)), nullptr, 16);
            if (wire.size() < line_end + 2 + size + 2)
                return p;
            if (size == 0) {
                p.complete = true;
                p.consumed = line_end + 4;
                return p;
            }
            p.body.append(wire.substr(line_end + 2, size));
            ++p.chunks;
            pos = line_end + 2 + size + 2;
        }
    }
    if (p.has_content_length) {
        const std::size_t length = std::stoul(lower_head.substr(cl + 18));
        if (wire.size() < pos + length)
            return p;
        p.body     = std::string(wire.substr(pos, length));
        p.complete = true;
        p.consumed = pos + length;
    }
    return p;
}

// ------------------------------------------------------------------------------------------------ the fixture
class ResponseStreamTest : public ::testing::Test {
protected:
    std::uint16_t                               port = 0;
    std::unique_ptr<ServerThread<StreamServer>> server;

    void
    SetUp() override {
        g_seen.reset();
        g_stalled.reset();
        server = std::make_unique<ServerThread<StreamServer>>([](StreamServer &s) {
            if (s.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            s.start();
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

    static std::string
    get(std::string_view path, std::string_view version = "HTTP/1.1", std::string_view method = "GET") {
        return std::string(method) + " " + std::string(path) + " " + std::string(version) + "\r\nHost: 127.0.0.1\r\n\r\n";
    }
};

} // namespace response_stream_test

using namespace response_stream_test;

TEST_F(ResponseStreamTest, ChunkedOverManyTurnsArrivesWholeAndKeepsTheConnection) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/chunked")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 200);
    EXPECT_TRUE(r.chunked) << r.head;
    EXPECT_FALSE(r.has_content_length) << "a chunked message carries no Content-Length";
    EXPECT_EQ(r.chunks, 8) << "one chunk per write";
    EXPECT_EQ(r.body, "piece-0;piece-1;piece-2;piece-3;piece-4;piece-5;piece-6;piece-7;");
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::chunked));
    EXPECT_TRUE(g_seen.streaming.load());

    // The connection serves the next request.
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(get("/plain")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    EXPECT_EQ(parse_response(c.buffer).body, "plain-body");
    EXPECT_TRUE(wait_for([] { return g_seen.post_hooks.load() == 1; })) << "POST_RESPONSE_SEND once, after the last byte";
    EXPECT_EQ(g_seen.pre_hooks.load(), 1) << "PRE_RESPONSE_SEND once, at the head";
}

TEST_F(ResponseStreamTest, DeclaredContentLengthStreamsIdentityAndKeepsTheConnection) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/length")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_FALSE(r.chunked);
    EXPECT_TRUE(r.header_is("content-length", "32")) << r.head;
    EXPECT_EQ(r.body, "piece-0;piece-1;piece-2;piece-3;");
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::content_length));
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(get("/plain")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << "keep-alive after an identity stream";
}

TEST_F(ResponseStreamTest, AContentLengthBodyAlreadyDrainedBeforeEndStillEnds) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/length-drained")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.body, "drained-all");
    c.buffer.erase(0, r.consumed);
    // The response is over for the SESSION only if end() re-armed the write path: otherwise the eos that completes a
    // response never comes, and the next request waits for the inactivity timeout.
    ASSERT_TRUE(c.send(get("/plain")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }, 2s)) << "the session never ended the drained response";
    EXPECT_EQ(parse_response(c.buffer).body, "plain-body");
}

TEST_F(ResponseStreamTest, HeadOnAStreamedRouteSendsTheHeadAloneAndServesTheNextRequest) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/chunked", "HTTP/1.1", "HEAD")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer, true).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer, true);
    EXPECT_EQ(r.status, 200);
    EXPECT_TRUE(r.chunked) << "the head announces the framing a GET would carry: " << r.head;
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::chunked));
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(get("/plain")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    EXPECT_EQ(parse_response(c.buffer).body, "plain-body") << "no body byte of the HEAD response may precede the next answer";
}

TEST_F(ResponseStreamTest, ASynchronousHandlerStreamsInsteadOfBuffering) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/sync")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_TRUE(r.chunked) << "a handler that does not suspend still streams: " << r.head;
    EXPECT_EQ(r.chunks, 3);
    EXPECT_EQ(r.body, "one;two;three;");
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::chunked));
    EXPECT_TRUE(g_seen.streaming.load());
}

TEST_F(ResponseStreamTest, AClientThatDoesNotReadBoundsTheServerOutputAndTheProducerWaits) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/bulk")));
    std::this_thread::sleep_for(300ms); // read nothing: the socket buffers fill, then the session's output
    EXPECT_FALSE(g_seen.producer_done.load()) << "16 MiB cannot all leave to a client that reads nothing";
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }, 20s)) << "the stream never completed";
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.body.size(), std::size_t{16} << 20);
    EXPECT_EQ(r.body.find_first_not_of('x'), std::string::npos);
    EXPECT_TRUE(g_seen.producer_done.load());
    EXPECT_GT(g_seen.waits.load(), 0) << "the producer never had to wait";
    EXPECT_LE(g_seen.max_pending.load(), std::size_t{256} * 1024 + std::size_t{64} * 1024 + 32)
        << "the output exceeded the high mark by more than one piece";
}

TEST_F(ResponseStreamTest, AServerTornDownUnderAStalledProducerReleasesTheStreamItsCallbackHolds) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/stall")));
    ASSERT_TRUE(wait_for([] { return g_seen.waits.load() > 0; })) << "the producer never had to wait";
    std::this_thread::sleep_for(200ms); // the socket buffers settle full: the producer sits parked on on_drain()
    EXPECT_FALSE(g_seen.producer_done.load());
    // The client is still connected: the session is live when the server is destroyed, and a session destroyed with
    // its io_handler gets no disconnected event. The server's thread is joined here, its listener with it.
    server.reset();
    EXPECT_TRUE(g_stalled.expired()) << "the stream outlived its session: the on_drain() callback holds it in a cycle";
}

TEST_F(ResponseStreamTest, ACoroutineProducerWaitsOnDrainAndASecondConcurrentDrainIsRefused) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/coro-drain")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }, 20s)) << "the stream never completed";
    const auto r = parse_response(c.buffer);
    EXPECT_TRUE(r.chunked);
    EXPECT_EQ(r.body.size() % (64 * 1024), 4u) << "whole 64 KiB pieces, then the 4-byte tail";
    EXPECT_EQ(r.body.substr(r.body.size() - 4), "tail");
    EXPECT_TRUE(g_seen.helper_saw_parked.load()) << "the second drain() did not run while the first was parked: the case was not exercised";
    EXPECT_EQ(g_seen.second_drain.load(), 0) << "a second concurrent drain() must be refused at once";
    EXPECT_EQ(g_seen.first_drain.load(), 1) << "the parked drain() resumes to write on once the output drains";
    EXPECT_TRUE(g_seen.producer_done.load());
}

TEST_F(ResponseStreamTest, ThePeerLeavingMidStreamCancelsTheStreamAndTheContext) {
    {
        RawClient c;
        ASSERT_TRUE(c.connect(port));
        ASSERT_TRUE(c.send(get("/forever")));
        ASSERT_TRUE(c.read_until([&] { return c.buffer.find("tick;") != std::string::npos; })) << c.buffer;
        c.close();
    }
    EXPECT_TRUE(wait_for([] { return g_seen.cancelled.load(); })) << "the producer was never told the peer left";
    EXPECT_TRUE(wait_for([] { return g_seen.context_cancelled.load(); })) << "the context was not cancelled";
}

TEST_F(ResponseStreamTest, AStreamDroppedBeforeEndClosesTheConnectionWithoutALastChunk) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/drop")));
    // disconnect() is an abort: what was still queued may never leave. The contract is the close, and that no
    // last-chunk ever tells the peer the message is whole.
    EXPECT_TRUE(c.read_until([&] { return c.eof; })) << "the server must close a message its producer abandoned";
    EXPECT_FALSE(parse_response(c.buffer).complete) << "no last-chunk: the peer must not take the message for whole";
}

TEST_F(ResponseStreamTest, APipelinedRequestIsAnsweredAfterTheStreamedOneInOrder) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/chunked") + get("/plain")));
    ASSERT_TRUE(c.read_until([&] {
        const auto first = parse_response(c.buffer);
        return first.complete && parse_response(std::string_view(c.buffer).substr(first.consumed)).complete;
    })) << c.buffer;
    const auto first  = parse_response(c.buffer);
    const auto second = parse_response(std::string_view(c.buffer).substr(first.consumed));
    EXPECT_EQ(first.body, "piece-0;piece-1;piece-2;piece-3;piece-4;piece-5;piece-6;piece-7;");
    EXPECT_EQ(second.body, "plain-body");
}

TEST_F(ResponseStreamTest, AnHttp10RequestWithoutALengthIsBufferedWhole) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/chunked", "HTTP/1.0")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_FALSE(r.chunked) << "an HTTP/1.0 client cannot read chunked: " << r.head;
    EXPECT_TRUE(r.has_content_length);
    EXPECT_EQ(r.body, "piece-0;piece-1;piece-2;piece-3;piece-4;piece-5;piece-6;piece-7;");
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::buffered));
    EXPECT_FALSE(g_seen.streaming.load());
    EXPECT_TRUE(wait_for([] { return g_seen.pre_hooks.load() == 1; })) << "a buffered stream runs its hooks at completion, once";
}

TEST_F(ResponseStreamTest, ANoContentStatusIsBufferedNeverStreamed) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/no-content")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 204);
    EXPECT_FALSE(r.chunked) << "a 204 never declares a Transfer-Encoding";
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::buffered));
    EXPECT_EQ(g_seen.pre_hooks.load(), 1);
}

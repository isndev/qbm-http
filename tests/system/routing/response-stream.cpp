/**
 * @file qbm/http/tests/system/routing/response-stream.cpp
 * @brief `Context::begin_stream()` / `ResponseStream` over a real HTTP/1.1 loopback session (Huly QB-86).
 *
 * A real server runs on a worker thread (the shared @ref qb::http::test::ServerThread harness, on a port the system assigns);
 * the client is a RAW non-blocking socket on the test thread -- TCP, or TLS for the HTTPS cases -- so every assertion is
 * on the exact bytes of the wire -- the framing (chunked or identity), the order of pipelined responses, an EOF where
 * the server must close -- and the client controls when it reads, which is what backpressure needs. What the server saw
 * (the framing chosen, the hooks run, the peak of its output buffer, a cancellation, a write verdict, an access-log
 * record) is published through atomics and read after a predicate.
 *
 * One witness per decision of the design:
 *   - chunked over many turns; a declared Content-Length, identity framing, keep-alive kept;
 *   - a Content-Length body whose last byte drained before `end()` still ends (the write path is re-armed), over TCP
 *     and over TLS, where the empty re-arm reaches qb-io's stream (Huly QB-1176);
 *   - HEAD on a streamed route: the head alone, the exchange over at its head -- the next request is answered while the
 *     producer still runs -- over TCP and over TLS; a HEAD producer that writes past its declared length is counted,
 *     never aborted;
 *   - a SYNCHRONOUS handler streams (the context being routed is adopted by its session at its head);
 *   - backpressure: a client that does not read bounds the server's output, the producer waits, then completes;
 *     watermarks are clamped under the hard cap, `wait` is lifted by a drain, a piece that cannot fit after one is
 *     `too_large`; a session's high watermark reaches the streams it begins;
 *   - a server torn down under a producer stalled on `on_drain()` releases the stream the callback holds (a session
 *     destroyed with its io_handler gets no disconnected event); a stream dropped with a callback still registered
 *     releases it without running it;
 *   - a coroutine producer on `co_await drain()`, and a second concurrent `drain()` refused with `false`;
 *   - the stream owns the completion: a coroutine handler that hands its stream on and returns is not completed under
 *     it, buffered (HTTP/1.0) or streamed; a handler that throws after handing it on leaves the answer to it; one that
 *     throws with its stream still in hand aborts it; `begin_stream()` refuses a context whose completion is held back;
 *   - the framing is decided after PRE_RESPONSE_SEND: a body already in the response is the first piece; compression
 *     at the head leaves a streamed body alone; a length a hook rewrote is the one enforced; a hook that makes the head
 *     unstreamable buffers it, its hooks run once; a handler's own `Transfer-Encoding: chunked` streams chunked;
 *   - the end of a stream: a piece past a declared length, an `end()` short of it, an explicit `abort()` and a
 *     dropped stream close the connection without a terminator; the peer leaving, an application `cancel()`, an
 *     extraction and the inactivity timeout cancel the stream and the context; a piece refreshes the timeout;
 *   - what observers read of a streamed response: the head's status, the streamed bytes (AccessLog, RequestMetrics),
 *     a stream its producer dropped mid-body included;
 *   - a pipelined request is answered after the streamed one, in order;
 *   - buffered: HTTP/1.0 without a length and a 204, whole, with their hooks run at completion; a buffered `abort()`
 *     answers 500 without the failed body's headers, and leaves a cancelled answer alone; a buffered body stops at
 *     `protocol_limits::MAX_BODY_SIZE` (a target of its own, labelled huge-body);
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
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>

#include <gtest/gtest.h>

#include "../../shared/loopback_server.h"

#include <qbm/http/http.h>
#include <qbm/http/middleware/access_log.h>
#include <qbm/http/middleware/compression.h>
#include <qbm/http/middleware/metrics.h>

#include <qb/io/async/coroutine.h>
#include <qb/io/tcp/socket.h>

#ifdef QB_HAS_SSL
#include <qb/io/tcp/ssl/socket.h>

#include "../../shared/tls_identity.h"
#endif

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
    std::atomic<bool>        helper_saw_parked{false};     ///< the second drain() ran while the first was parked
    std::atomic<int>         post_handler_saw_ended{-1};   ///< POST_HANDLER_EXECUTION ran with the stream ended (1) or open (0)
    std::atomic<int>         post_send_status{0};          ///< the status a POST_RESPONSE_SEND hook read
    std::atomic<int>         verdicts[8]{};                ///< write verdicts a route records, in order (int + 1; 0 = none)
    std::atomic<std::size_t> high{0};                      ///< a stream's high watermark, as it kept it
    std::atomic<std::size_t> low{0};                       ///< its low watermark
    std::atomic<bool>        release{false};               ///< the test lets a slow producer end
    std::atomic<bool>        stream_cancelled_seen{false}; ///< a producer found its stream cancelled
    std::atomic<bool>        closed_verdict_seen{false};   ///< a producer's write was answered `closed`
    std::atomic<std::size_t> written_at_close{0};          ///< what a ticking producer's stream had taken when it was closed
    std::atomic<int>         refused_stream{-1};           ///< begin_stream() under a held-back completion: 1 refused, 0 a stream
    std::atomic<bool>        dropped_callback_ran{false};  ///< the on_drain() callback of a dropped stream ran
    std::atomic<bool>        dropped_callback_set{false};  ///< it was registered, not deferred at once

    void
    reset() {
        framing                = -1;
        streaming              = false;
        pre_hooks              = 0;
        post_hooks             = 0;
        cancelled              = false;
        context_cancelled      = false;
        max_pending            = 0;
        waits                  = 0;
        first_drain            = -1;
        second_drain           = -1;
        producer_done          = false;
        handler_parked         = false;
        handler_resumed        = false;
        helper_saw_parked      = false;
        post_handler_saw_ended = -1;
        post_send_status       = 0;
        for (auto &v : verdicts)
            v = 0;
        high                  = 0;
        low                   = 0;
        release               = false;
        stream_cancelled_seen = false;
        closed_verdict_seen   = false;
        written_at_close      = 0;
        refused_stream        = -1;
        dropped_callback_ran  = false;
        dropped_callback_set  = false;
    }
};
inline Observed g_seen;

/// What the access log recorded per request target: its status and its bytes (the observer of a streamed response).
struct AccessRecord {
    int           status = 0;
    std::uint64_t bytes  = 0;
};
inline std::mutex                          g_access_mutex;
inline std::map<std::string, AccessRecord> g_access;

inline void
reset_access() {
    std::lock_guard lock(g_access_mutex);
    g_access.clear();
}

inline std::optional<AccessRecord>
access_of(std::string const &target) {
    std::lock_guard lock(g_access_mutex);
    const auto      it = g_access.find(target);
    if (it == g_access.end())
        return std::nullopt;
    return it->second;
}

/// The hard output cap the session of this suite reports to its streams: qb-io's by default, smaller for the cases
/// that exercise the admission arithmetic -- always at most qb-io's, so publish() never disconnects for it.
inline std::atomic<std::size_t> g_cap{QB_MAX_WRITE_BUFFER_SIZE};

class StreamServer;

class StreamSession : public qb::http::use<StreamSession>::session<StreamServer> {
public:
    explicit StreamSession(StreamServer &server_ref)
        : session(server_ref) {}

    /// Hides the session's own cap (qb-io's) for the cases that need a small one.
    [[nodiscard]] static std::size_t
    stream_write_cap() noexcept {
        return g_cap.load();
    }
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

template <typename C>
void
count_hooks(std::shared_ptr<C> const &ctx) {
    ctx->add_lifecycle_hook([](C &, qb::http::HookPoint point) {
        if (point == qb::http::HookPoint::PRE_RESPONSE_SEND)
            ++g_seen.pre_hooks;
        else if (point == qb::http::HookPoint::POST_RESPONSE_SEND)
            ++g_seen.post_hooks;
    });
}

template <typename C, typename S>
void
record(std::shared_ptr<C> const &ctx, std::shared_ptr<S> const &stream) {
    g_seen.framing   = static_cast<int>(stream->framing());
    g_seen.streaming = ctx->is_streaming();
}

inline void
record_verdict(int index, Stream::write_result r) {
    g_seen.verdicts[index] = static_cast<int>(r) + 1;
}

[[nodiscard]] inline int
verdict(Stream::write_result r) {
    return static_cast<int>(r) + 1;
}

/// `n` pieces, one per event-loop turn (1 ms apart), then end().
template <typename S>
void
pieces_over_turns(std::shared_ptr<S> stream, int i, int n) {
    if (i == n) {
        stream->end();
        g_seen.producer_done = true;
        return;
    }
    if (stream->write("piece-" + std::to_string(i) + ";") == S::write_result::closed)
        g_seen.closed_verdict_seen = true;
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

/// The admission arithmetic under a 1 MiB cap (/clamp): pieces written without asking needs_drain(), the verdicts
/// recorded, then a drain and the refused piece again.
struct ClampProducer : std::enable_shared_from_this<ClampProducer> {
    std::shared_ptr<Stream> stream;
    std::string             piece;
    int                     next = 2;

    void
    run() {
        while (next < 6) {
            const auto r = stream->write(piece);
            record_verdict(next++, r);
            if (r == Stream::write_result::wait) {
                stream->on_drain([self = shared_from_this()] {
                    record_verdict(self->next++, self->stream->write(self->piece)); // the same piece, after the drain
                    self->stream->end();
                    g_seen.producer_done = true;
                });
                return;
            }
            if (r != Stream::write_result::taken)
                return;
        }
    }
};

/// Ticks a piece every `period` until the stream is closed under it (it then reports how).
template <typename S>
void
tick_until_closed(std::shared_ptr<S> s, std::chrono::milliseconds period) {
    const auto r = s->write("tick;");
    if (r == S::write_result::closed || s->cancelled()) {
        g_seen.written_at_close      = s->written(); // published before `cancelled`, which the cases wait on
        g_seen.cancelled             = true;
        g_seen.stream_cancelled_seen = s->cancelled();
        g_seen.closed_verdict_seen   = r == S::write_result::closed;
        return;
    }
    qb::io::async::callback([s = std::move(s), period]() mutable { tick_until_closed(std::move(s), period); }, period);
}

/// Writes nothing; looks every 10 ms whether its stream was cancelled under it (up to 5 s).
inline void
watch_quietly(std::shared_ptr<Stream> s, int left) {
    if (s->cancelled() || left == 0) {
        g_seen.stream_cancelled_seen = s->cancelled();
        g_seen.cancelled             = true;
        return;
    }
    qb::io::async::callback([s = std::move(s), left]() mutable { watch_quietly(std::move(s), left - 1); }, 10ms);
}

/// The /slow producer: a piece every 2 ms until the test releases it (or 10 s), then end().
inline void
slow_until_released(std::shared_ptr<Stream> s, int left) {
    if (g_seen.release.load() || left == 0) {
        s->end();
        g_seen.producer_done = true;
        return;
    }
    (void) s->write("slow;");
    qb::io::async::callback([s = std::move(s), left]() mutable { slow_until_released(std::move(s), left - 1); }, 2ms);
}

/// Records the access-log status and bytes of every request, by target, and counts them by route and status.
inline void
observe(qb::http::Router<StreamSession> &router, std::shared_ptr<qb::http::RequestMetrics<StreamSession>> metrics) {
    // The metrics first: the access log's lock then orders their counts before the test's read of the record.
    router.add_observer(std::move(metrics));
    auto sink = [](std::string_view) {
    };
    auto record = [](qb::http::AccessLogRecord const &r, std::string &line) {
        std::lock_guard lock(g_access_mutex);
        g_access[std::string(r.target)] = AccessRecord{r.status, r.bytes};
        line.clear();
    };
    router.add_observer(std::make_shared<qb::http::AccessLog<StreamSession>>(sink, record));
}

class StreamServer : public qb::http::use<StreamServer>::server<StreamSession> {
public:
    std::shared_ptr<qb::http::RequestMetrics<StreamSession>> metrics = std::make_shared<qb::http::RequestMetrics<StreamSession>>();

    StreamServer() {
        observe(router(), metrics);

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

        // HEAD on a producer that runs until the test releases it: the exchange ends at the head, the connection is
        // free for the next request at once (review m1).
        router().head("/slow", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            slow_until_released(std::move(stream), 5000);
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

        // Backpressure: 256 MiB declared and streamed in 64 KiB pieces, watermarks 256 / 128 KiB -- far above what any
        // loopback socket buffers absorb, so a client that reads nothing must stop the producer (review n9).
        router().get("/bulk", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", std::to_string(std::size_t{256} << 20));
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            stream->set_watermarks(256 * 1024, 128 * 1024);
            std::make_shared<BulkProducer>(std::move(stream), std::size_t{256} << 20, std::size_t{64} << 10)->run();
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

        // The admission under a 1 MiB cap (review m4, m7): marks asked far above it are clamped, a piece that cannot fit
        // after a drain is too_large, pieces written without asking needs_drain() reach `wait`, and the same piece is
        // taken after the drain.
        router().get("/clamp", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            stream->set_watermarks(std::size_t{1} << 30, std::size_t{512} << 20);
            g_seen.high = stream->high_watermark();
            g_seen.low  = stream->low_watermark();
            record_verdict(0, stream->write(std::string(std::size_t{512} * 1024, 'z'))); // > cap - high - last-chunk
            record_verdict(1, stream->write(std::string_view{}));                        // an empty piece: always taken
            auto producer    = std::make_shared<ClampProducer>();
            producer->stream = std::move(stream);
            producer->piece  = std::string(std::size_t{400} * 1024, 'y');
            producer->run();
        });

        // A session's high watermark reaches the streams it begins (clamped like any other).
        router().get("/session-mark", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            if (auto session = ctx->session())
                session->stream_high_watermark(96 * 1024);
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            g_seen.high = stream->high_watermark();
            g_seen.low  = stream->low_watermark();
            stream->end();
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

        // The stream owns the completion (review M2): a coroutine handler hands its stream to a timer chain and
        // returns. Its POST_HANDLER_EXECUTION hook says whether the stream had ended by then.
        router().get("/handoff", [](std::shared_ptr<Ctx> ctx) -> qb::io::async::task<void> {
            count_hooks(ctx);
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            ctx->add_lifecycle_hook([weak = std::weak_ptr<Stream>(stream)](Ctx &c, qb::http::HookPoint point) {
                if (point == qb::http::HookPoint::POST_HANDLER_EXECUTION) {
                    const auto s                  = c.stream();
                    g_seen.post_handler_saw_ended = (!s || s->ended()) ? 1 : 0;
                }
            });
            (void) stream->write("piece-0;");
            pieces_over_turns(std::move(stream), 1, 4);
            co_return;
        });

        // The same hand-off, then the handler throws: the producer still owns the answer.
        router().get("/handoff-throw", [](std::shared_ptr<Ctx> ctx) -> qb::io::async::task<void> {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("piece-0;");
            pieces_over_turns(std::move(stream), 1, 4);
            if (ctx)
                throw std::runtime_error("the handler failed after handing its stream on");
            co_return;
        });

        // A handler that throws with its stream still in hand: the unwinding drops the producer's handle, the stream
        // is aborted -- 500 when buffered, the connection closed when streamed.
        router().get("/throw-open", [](std::shared_ptr<Ctx> ctx) -> qb::io::async::task<void> {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("piece-0;");
            co_await qb::io::async::sleep(1ms);
            throw std::runtime_error("the source failed mid-body");
        });

        // The framing is decided after the hooks (review M3): a body already in the response is the first piece.
        router().get("/preamble", [](std::shared_ptr<Ctx> ctx) {
            count_hooks(ctx);
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "pre;";
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("a;");
            (void) stream->write("b;");
            stream->end();
        });

        // ... and is counted against a declared length.
        router().get("/preamble-length", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "8");
            ctx->response().body() = "pre;";
            auto stream            = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("a;");
            (void) stream->write("b;");
            stream->end();
        });

        // A PRE_RESPONSE_SEND hook rewrites the declared length: the length that leaves is the one enforced.
        router().get("/length-rewritten", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "4");
            ctx->add_lifecycle_hook([](Ctx &c, qb::http::HookPoint point) {
                if (point == qb::http::HookPoint::PRE_RESPONSE_SEND)
                    c.response().set_header("Content-Length", "12");
            });
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("piece-0;");
            (void) stream->write("tail");
            stream->end();
        });

        // HTTP/1.0 with a declared length streams identity -- unless a hook drops the length: the head can then no
        // longer frame a stream to HTTP/1.0, the stream is buffered, and the hooks are not run a second time.
        router().get("/http10-length-dropped", [](std::shared_ptr<Ctx> ctx) {
            count_hooks(ctx);
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "6");
            ctx->add_lifecycle_hook([](Ctx &c, qb::http::HookPoint point) {
                if (point == qb::http::HookPoint::PRE_RESPONSE_SEND)
                    c.response().remove_header("Content-Length");
            });
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("abc");
            (void) stream->write("def");
            stream->end();
        });

        // The handler set `Transfer-Encoding: chunked` itself: it streams chunked, with no second header (review m6).
        router().get("/te-chunked", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Transfer-Encoding", "chunked");
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            pieces_over_turns(std::move(stream), 0, 3);
        });

        // Compression at the head of a stream (review M3): the hooks see an empty body, so CompressionMiddleware leaves
        // the 1 KiB preamble -- the first piece -- and every later one alone.
        {
            qb::http::CompressionOptions options;
            options.compress_responses(true).min_size_to_compress(1024).preferred_encodings({"gzip", "deflate"});
            auto compressed = router().group("/mw");
            compressed->use(std::make_shared<qb::http::CompressionMiddleware<StreamSession>>(options));
            compressed->get("/preamble", [](std::shared_ptr<Ctx> ctx) {
                count_hooks(ctx);
                ctx->response().status() = qb::http::status::OK;
                ctx->response().set_header("Content-Type", "text/plain");
                ctx->response().body() = std::string(1024, 'p');
                auto stream            = ctx->begin_stream();
                record(ctx, stream);
                (void) stream->write("tail;");
                stream->end();
            });
        }

        // A piece past a declared length: the stream is aborted, the connection closed (review m7).
        router().get("/overrun", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "8");
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            record_verdict(0, stream->write("123456789"));
            g_seen.producer_done = stream->aborted();
        });

        // An end() short of a declared length: the connection is closed instead.
        router().get("/short", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "20");
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("short");
            stream->end();
            g_seen.producer_done = stream->aborted();
        });

        // An explicit abort() under a chunked stream.
        router().get("/abort", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("partial;");
            stream->abort();
            g_seen.producer_done = stream->aborted();
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
            tick_until_closed(std::move(stream), 2ms);
        });

        // The application cancels a streamed context: the connection closes, the producer is told, the observers keep
        // the head's status (review m5).
        router().get("/app-cancel", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("x;");
            qb::io::async::callback([ctx]() { ctx->cancel("the application changed its mind"); }, 5ms);
            tick_until_closed(std::move(stream), 2ms);
        });

        // The session is extracted from its server under a live stream: the producer and the context are told.
        router().get("/extract", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            ctx->add_lifecycle_hook([](Ctx &c, qb::http::HookPoint) {
                if (c.is_cancelled())
                    g_seen.context_cancelled = true;
            });
            qb::io::async::callback(
                [weak = std::weak_ptr<StreamSession>(ctx->session())]() {
                    if (auto session = weak.lock())
                        (void) session->server().extractSession(session->id()); // the socket it returns closes here
                },
                10ms);
            tick_until_closed(std::move(stream), 2ms);
        });

        // A quiet stream under a short inactivity timeout: the session times out and ends it like a peer that left.
        router().get("/quiet", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("q;");
            if (auto session = ctx->session())
                session->setTimeout(300ms);
            watch_quietly(std::move(stream), 500);
        });

        // The same timeout, a piece every 30 ms for twice as long: each piece refreshes it, and the stream completes.
        router().get("/heartbeat", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            if (auto session = ctx->session())
                session->setTimeout(300ms);
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            struct Beat {
                static void
                next(std::shared_ptr<Stream> s, int i) {
                    if (i == 20) {
                        s->end();
                        g_seen.producer_done = true;
                        return;
                    }
                    (void) s->write("beat;");
                    qb::io::async::callback([s = std::move(s), i]() mutable { next(std::move(s), i + 1); }, 30ms);
                }
            };
            Beat::next(std::move(stream), 0);
        });

        // A stream dropped before end(): the connection must close, without a last-chunk.
        router().get("/drop", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("partial;");
            // `stream` goes out of scope here: its producer is gone.
        });

        // A producer that writes 24 bytes over two turns, then drops its handle mid-body: observers read the bytes that
        // left, though the stream they would be read from is gone by the time the context is cancelled.
        router().get("/drop-counted", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("piece-0;");
            qb::io::async::callback(
                [stream = std::move(stream)]() mutable {
                    (void) stream->write("piece-1;");
                    (void) stream->write("piece-2;");
                    stream.reset(); // the producer drops its handle
                },
                1ms);
        });

        // A buffered stream (HTTP/1.0) aborted: a 500 without the failed body's headers (review m3).
        router().get("/abort-buffered", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Encoding", "br");
            ctx->response().set_header("X-Kept", "yes");
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("doomed");
            stream->abort();
        });

        // A buffered stream whose context the application cancelled, then aborted: the 503 sent is left alone.
        router().get("/cancel-then-abort", [](std::shared_ptr<Ctx> ctx) {
            ctx->add_lifecycle_hook([](Ctx &c, qb::http::HookPoint point) {
                if (point == qb::http::HookPoint::POST_RESPONSE_SEND)
                    g_seen.post_send_status = static_cast<int>(c.response().status());
            });
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            (void) stream->write("gathered");
            ctx->cancel("cancelled before the end");
            stream->abort();
        });

        // A buffered body stops at the protocol's bound (review m2). HTTP/1.0: buffered from the start.
        router().get("/huge", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            const std::size_t bound = qb::http::protocol_limits::MAX_BODY_SIZE;
            const std::string big(bound + 1, 'h');
            record_verdict(0, stream->write(big));                                 // alone past the bound
            record_verdict(1, stream->write(std::string_view(big.data(), bound))); // exactly the bound
            record_verdict(2, stream->write("!"));                                 // one byte past it
            stream->abort();                                                       // a 500, not a 100 MiB answer
        });

        // HEAD with a declared length, and a producer that writes past it (review n7): the response was whole at its
        // head, so the pieces are counted and discarded -- never faulted against the length, which would close the
        // connection under the next request.
        router().head("/head-length", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "4");
            auto stream = ctx->begin_stream();
            record(ctx, stream);
            record_verdict(0, stream->write("12345678")); // twice the declared length
            stream->end();
            g_seen.producer_done = true;
        });

        // begin_stream() while the completion is held back (review n5): a finalisation is pending, so there is no
        // stream to begin -- the response completed the ordinary way leaves once the hold is released, alone.
        router().get("/held", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "held-body";
            auto hold                = ctx->defer_finalization_scope();
            ctx->complete();
            auto stream           = ctx->begin_stream();
            g_seen.refused_stream = stream ? 0 : 1;
        });

        // A stream dropped while its on_drain() callback is registered (review n3): the callback reports on a stream
        // that is gone, so it is released without running. The output holds far more than the low mark, so the
        // callback is registered rather than deferred at once.
        router().get("/drop-waiting", [](std::shared_ptr<Ctx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream();
            record(ctx, stream);
            stream->set_watermarks(1024, 512);
            (void) stream->write(std::string(std::size_t{64} * 1024, 'w'));
            std::weak_ptr<Stream> weak = stream;
            stream->on_drain([weak] {
                g_seen.dropped_callback_ran = true;
                (void) weak.lock();
            });
            g_seen.dropped_callback_set = stream->pending() > stream->low_watermark();
            // `stream` goes out of scope here, with its callback registered.
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

// ------------------------------------------------------------------------------------------------ the raw clients
/// A raw non-blocking client: TCP (`qb::io::tcp::socket`), or TLS (`qb::io::tcp::ssl::socket`, the server's self-signed
/// certificate accepted). TLS reads answer 0 while OpenSSL waits for more bytes, and -1 once the connection is over.
template <typename Socket>
class BasicRawClient {
    Socket _sock;

    static constexpr bool tls = !std::is_same_v<Socket, qb::io::tcp::socket>;

public:
    std::string buffer;
    bool        eof = false;

    bool
    connect(std::uint16_t port) {
        if constexpr (tls)
            _sock.set_insecure(); // the server's certificate is self-signed
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

    /// Read what is there, once, into `out`; true when something came. EOF is recorded.
    bool
    read_into(std::string &out) {
        char      tmp[64 * 1024];
        const int n = _sock.read(tmp, sizeof tmp);
        if (n > 0) {
            out.append(tmp, static_cast<std::size_t>(n));
            return true;
        }
        if constexpr (tls) {
            if (n < 0)
                eof = true; // the TLS socket reports the end of the connection as -1, and "nothing yet" as 0
        } else {
            if (n == 0 || !qb::io::socket::not_recv_error(qb::io::socket::get_last_errno()))
                eof = true; // an orderly close, or a reset: the connection is over either way
        }
        return false;
    }

    bool
    read_some() {
        return read_into(buffer);
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

    /// Reads `n` body bytes past what `buffer` holds without keeping them; true when all came and every one is `fill`.
    bool
    count_body(std::size_t n, char fill, std::chrono::milliseconds budget) {
        const auto  deadline = std::chrono::steady_clock::now() + budget;
        std::size_t seen     = buffer.size();
        bool        clean    = buffer.find_first_not_of(fill) == std::string::npos;
        buffer.clear();
        std::string piece;
        while (seen < n) {
            if (eof || std::chrono::steady_clock::now() >= deadline)
                return false;
            piece.clear();
            if (!read_into(piece)) {
                std::this_thread::sleep_for(1ms);
                continue;
            }
            seen += piece.size();
            clean = clean && piece.find_first_not_of(fill) == std::string::npos;
        }
        return seen == n && clean;
    }

    void
    close() {
        _sock.disconnect();
    }
};

using RawClient = BasicRawClient<qb::io::tcp::socket>;

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

    /// How many times the header `name` appears in the head.
    [[nodiscard]] int
    header_count(std::string_view name) const {
        std::string h = head, n = "\r\n" + std::string(name) + ":";
        std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        int count = 0;
        for (auto pos = h.find(n); pos != std::string::npos; pos = h.find(n, pos + 1))
            ++count;
        return count;
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

std::string
get(std::string_view path, std::string_view version = "HTTP/1.1", std::string_view method = "GET", std::string_view extra = "") {
    return std::string(method) + " " + std::string(path) + " " + std::string(version) + "\r\nHost: 127.0.0.1\r\n" + std::string(extra) + "\r\n";
}

template <typename Pred>
bool
wait_for(Pred &&pred, std::chrono::milliseconds budget = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(1ms);
    }
    return true;
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
        g_cap = QB_MAX_WRITE_BUFFER_SIZE;
        reset_access();
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
        g_seen.release = true;
        server.reset();
    }
};

} // namespace response_stream_test

using namespace response_stream_test;

#ifndef QBM_TEST_RESPONSE_STREAM_HUGE_BODY

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

TEST_F(ResponseStreamTest, AHeadExchangeEndsAtItsHeadSoTheNextRequestIsAnsweredWhileTheProducerRuns) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/slow", "HTTP/1.1", "HEAD")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer, true).complete; })) << c.buffer;
    c.buffer.erase(0, parse_response(c.buffer, true).consumed);
    ASSERT_TRUE(c.send(get("/plain")));
    EXPECT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }, 2s))
        << "the GET behind a HEAD waited for a producer whose every byte is discarded: " << c.buffer;
    EXPECT_FALSE(g_seen.producer_done.load()) << "the HEAD producer had to be still running for this to prove anything";
    EXPECT_EQ(parse_response(c.buffer).body, "plain-body");
    g_seen.release = true;
    EXPECT_TRUE(wait_for([] { return g_seen.producer_done.load(); })) << "the producer ends when released, its stream counting alone";
}

TEST_F(ResponseStreamTest, AHeadProducerPastItsDeclaredLengthIsCountedNotAborted) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/head-length", "HTTP/1.1", "HEAD")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer, true).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer, true);
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::content_length));
    ASSERT_TRUE(c.read_until([&] { return g_seen.producer_done.load(); }));
    EXPECT_EQ(g_seen.verdicts[0].load(), verdict(Stream::write_result::taken)) << "a HEAD piece is counted, never faulted";
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(get("/plain")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }))
        << "the connection did not survive the HEAD producer's extra bytes (eof=" << c.eof << "): " << c.buffer;
    EXPECT_EQ(parse_response(c.buffer).body, "plain-body");
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
    // Read nothing: the socket buffers fill, then the session's output reaches the high mark, and the producer has to
    // wait -- 256 MiB cannot all leave to a client that reads nothing, whatever the host's socket buffers.
    ASSERT_TRUE(wait_for([] { return g_seen.waits.load() > 0; }, 20s)) << "the producer never had to wait";
    std::this_thread::sleep_for(300ms); // the socket buffers fill: 256 MiB is far past any of them
    EXPECT_FALSE(g_seen.producer_done.load()) << "the producer finished for a client that read nothing";
    ASSERT_TRUE(c.read_until([&] { return c.buffer.find("\r\n\r\n") != std::string::npos; })) << c.buffer;
    const auto head = parse_response(c.buffer.substr(0, c.buffer.find("\r\n\r\n") + 4));
    EXPECT_TRUE(head.header_is("content-length", std::to_string(std::size_t{256} << 20))) << head.head;
    c.buffer.erase(0, c.buffer.find("\r\n\r\n") + 4);
    EXPECT_TRUE(c.count_body(std::size_t{256} << 20, 'x', 120s)) << "the body is not 256 MiB of the producer's bytes";
    EXPECT_TRUE(wait_for([] { return g_seen.producer_done.load(); }));
    EXPECT_LE(g_seen.max_pending.load(), std::size_t{256} * 1024 + std::size_t{64} * 1024)
        << "the output exceeded the high mark by more than one piece";
}

TEST_F(ResponseStreamTest, WatermarksAreClampedUnderTheCapAndAPieceThatCannotFitAfterADrainIsTooLarge) {
    g_cap = std::size_t{1} << 20; // 1 MiB: the marks asked for (1 GiB / 512 MiB) are far above it
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/clamp")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }, 20s)) << c.buffer.substr(0, 256);
    EXPECT_EQ(g_seen.high.load(), std::size_t{512} * 1024) << "the high mark is at most half the hard cap";
    EXPECT_EQ(g_seen.low.load(), std::size_t{256} * 1024) << "a low mark not under the high one is half of it";
    EXPECT_EQ(g_seen.verdicts[0].load(), verdict(Stream::write_result::too_large))
        << "a piece that would not fit even into a drained output is refused for good";
    EXPECT_EQ(g_seen.verdicts[1].load(), verdict(Stream::write_result::taken));
    EXPECT_EQ(g_seen.verdicts[2].load(), verdict(Stream::write_result::taken));
    EXPECT_EQ(g_seen.verdicts[3].load(), verdict(Stream::write_result::taken));
    EXPECT_EQ(g_seen.verdicts[4].load(), verdict(Stream::write_result::wait)) << "a third 400 KiB piece does not fit under 1 MiB";
    EXPECT_EQ(g_seen.verdicts[5].load(), verdict(Stream::write_result::taken)) << "the same piece fits once drained";
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.body, std::string(std::size_t{1200} * 1024, 'y'));
    EXPECT_TRUE(g_seen.producer_done.load());
}

TEST_F(ResponseStreamTest, ASessionHighWatermarkReachesTheStreamsItBegins) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/session-mark")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    EXPECT_EQ(g_seen.high.load(), std::size_t{96} * 1024);
    EXPECT_EQ(g_seen.low.load(), std::size_t{48} * 1024);
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

TEST_F(ResponseStreamTest, ACoroutineHandlerThatHandsItsBufferedStreamOnIsNotCompletedUnderIt) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/handoff", "HTTP/1.0")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::buffered));
    EXPECT_EQ(r.status, 200);
    EXPECT_EQ(r.body, "piece-0;piece-1;piece-2;piece-3;") << "the response left when the handler returned, not at end()";
    EXPECT_EQ(g_seen.post_handler_saw_ended.load(), 1) << "POST_HANDLER_EXECUTION ran before the stream ended";
    EXPECT_FALSE(g_seen.closed_verdict_seen.load()) << "a piece was refused: the context was over under the producer";
    EXPECT_TRUE(wait_for([] { return g_seen.pre_hooks.load() == 1; })) << "a buffered stream runs its hooks at completion, once";
}

TEST_F(ResponseStreamTest, ACoroutineHandlerThatHandsItsStreamOnKeepsStreamingAndCompletesAtEnd) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/handoff")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_TRUE(r.chunked) << r.head;
    EXPECT_EQ(r.body, "piece-0;piece-1;piece-2;piece-3;");
    EXPECT_EQ(g_seen.post_handler_saw_ended.load(), 1) << "the context was completed when the handler returned, under its stream";
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(get("/plain")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
}

TEST_F(ResponseStreamTest, AHandlerThatThrowsAfterHandingItsStreamOnLeavesTheAnswerToIt) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/handoff-throw", "HTTP/1.0")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 200) << "the handler's failure took the answer from the producer that owns it";
    EXPECT_EQ(r.body, "piece-0;piece-1;piece-2;piece-3;");
}

TEST_F(ResponseStreamTest, AHandlerThatThrowsWithItsStreamInHandAbortsIt) {
    {
        RawClient c; // buffered (HTTP/1.0): a 500
        ASSERT_TRUE(c.connect(port));
        ASSERT_TRUE(c.send(get("/throw-open", "HTTP/1.0")));
        ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
        const auto r = parse_response(c.buffer);
        EXPECT_EQ(r.status, 500);
        EXPECT_TRUE(r.body.empty()) << r.body;
    }
    {
        RawClient c; // streamed: the connection closes, no last-chunk
        ASSERT_TRUE(c.connect(port));
        ASSERT_TRUE(c.send(get("/throw-open")));
        EXPECT_TRUE(c.read_until([&] { return c.eof; })) << c.buffer;
        EXPECT_FALSE(parse_response(c.buffer).complete) << c.buffer;
    }
}

TEST_F(ResponseStreamTest, BeginStreamUnderAHeldBackCompletionIsRefusedAndTheAnswerLeavesAlone) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/held") + get("/plain")));
    ASSERT_TRUE(c.read_until([&] {
        const auto first = parse_response(c.buffer);
        return first.complete && parse_response(std::string_view(c.buffer).substr(first.consumed)).complete;
    })) << c.buffer;
    EXPECT_EQ(g_seen.refused_stream.load(), 1) << "a stream was begun on a context whose completion was pending";
    const auto first  = parse_response(c.buffer);
    const auto second = parse_response(std::string_view(c.buffer).substr(first.consumed));
    EXPECT_EQ(first.status, 200);
    EXPECT_FALSE(first.chunked) << first.head;
    EXPECT_EQ(first.body, "held-body");
    EXPECT_EQ(second.body, "plain-body");
}

TEST_F(ResponseStreamTest, ABodyAlreadyInTheResponseIsTheFirstPiece) {
    {
        RawClient c;
        ASSERT_TRUE(c.connect(port));
        ASSERT_TRUE(c.send(get("/preamble")));
        ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
        const auto r = parse_response(c.buffer);
        EXPECT_TRUE(r.chunked) << r.head;
        EXPECT_EQ(r.body, "pre;a;b;") << "the streaming path dropped the body the handler had set";
        EXPECT_EQ(r.chunks, 3);
        EXPECT_EQ(g_seen.pre_hooks.load(), 1);
    }
    {
        RawClient c; // the same, buffered
        ASSERT_TRUE(c.connect(port));
        ASSERT_TRUE(c.send(get("/preamble", "HTTP/1.0")));
        ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
        EXPECT_EQ(parse_response(c.buffer).body, "pre;a;b;");
    }
    {
        RawClient c; // counted against a declared length
        ASSERT_TRUE(c.connect(port));
        ASSERT_TRUE(c.send(get("/preamble-length")));
        ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
        const auto r = parse_response(c.buffer);
        EXPECT_TRUE(r.header_is("content-length", "8")) << r.head;
        EXPECT_EQ(r.body, "pre;a;b;");
        c.buffer.erase(0, r.consumed);
        ASSERT_TRUE(c.send(get("/plain")));
        ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << "the length was not met: " << c.buffer;
    }
}

TEST_F(ResponseStreamTest, CompressionAtTheHeadOfAStreamLeavesItsBodyAlone) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/mw/preamble", "HTTP/1.1", "GET", "Accept-Encoding: gzip\r\n")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << "no response at all: " << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(r.status, 200);
    EXPECT_TRUE(r.chunked) << r.head;
    EXPECT_FALSE(r.has_content_length) << r.head;
    EXPECT_EQ(r.header_count("content-encoding"), 0) << "a streamed body is not compressed: " << r.head;
    EXPECT_EQ(r.body, std::string(1024, 'p') + "tail;");
    EXPECT_EQ(g_seen.pre_hooks.load(), 1);
}

TEST_F(ResponseStreamTest, ALengthAHookRewroteIsTheLengthEnforced) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/length-rewritten")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_TRUE(r.header_is("content-length", "12")) << r.head;
    EXPECT_EQ(r.body, "piece-0;tail");
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::content_length));
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(get("/plain")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << "the stream did not end at the length it sent";
    EXPECT_EQ(parse_response(c.buffer).body, "plain-body");
}

TEST_F(ResponseStreamTest, AHookThatLeavesAnUnstreamableHeadBuffersItWithItsHooksRunOnce) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/http10-length-dropped", "HTTP/1.0")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete || c.eof; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::buffered));
    EXPECT_TRUE(r.has_content_length) << "an HTTP/1.0 response that could not stream is sent whole, with its length: " << r.head;
    EXPECT_EQ(r.body, "abcdef");
    EXPECT_TRUE(wait_for([] { return g_seen.post_hooks.load() == 1; }));
    EXPECT_EQ(g_seen.pre_hooks.load(), 1) << "the completion ran the hooks begin_stream() had already run";
}

TEST_F(ResponseStreamTest, AHandlerTransferEncodingChunkedStreamsChunked) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/te-chunked")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::chunked)) << "a handler's own chunked was buffered";
    EXPECT_EQ(r.header_count("transfer-encoding"), 1) << r.head;
    EXPECT_EQ(r.chunks, 3);
    EXPECT_EQ(r.body, "piece-0;piece-1;piece-2;");
}

TEST_F(ResponseStreamTest, APiecePastADeclaredLengthClosesTheConnection) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/overrun")));
    EXPECT_TRUE(c.read_until([&] { return c.eof; })) << c.buffer;
    EXPECT_FALSE(parse_response(c.buffer).complete) << c.buffer;
    EXPECT_EQ(g_seen.verdicts[0].load(), verdict(Stream::write_result::closed));
    EXPECT_TRUE(g_seen.producer_done.load()) << "the stream was not aborted";
}

TEST_F(ResponseStreamTest, AnEndShortOfADeclaredLengthClosesTheConnection) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/short")));
    EXPECT_TRUE(c.read_until([&] { return c.eof; })) << c.buffer;
    EXPECT_FALSE(parse_response(c.buffer).complete) << c.buffer;
    EXPECT_TRUE(g_seen.producer_done.load()) << "the stream was not aborted";
}

TEST_F(ResponseStreamTest, AnExplicitAbortClosesTheConnectionWithoutALastChunk) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/abort")));
    EXPECT_TRUE(c.read_until([&] { return c.eof; })) << c.buffer;
    EXPECT_FALSE(parse_response(c.buffer).complete) << c.buffer;
    EXPECT_TRUE(g_seen.producer_done.load());
    ASSERT_TRUE(wait_for([] { return access_of("/abort").has_value(); })) << "no access-log record";
    EXPECT_EQ(access_of("/abort")->bytes, 8u) << "the bytes streamed before the abort";
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
    ASSERT_TRUE(wait_for([] { return access_of("/forever").has_value(); })) << "no access-log record";
    EXPECT_EQ(access_of("/forever")->status, 200) << "the head that left said 200";
    EXPECT_GT(access_of("/forever")->bytes, 0u) << "a streamed response logged as an empty body";
    EXPECT_EQ(access_of("/forever")->bytes, g_seen.written_at_close.load()) << "the bytes the stream had taken when the peer left";
}

TEST_F(ResponseStreamTest, AnApplicationCancelClosesAStreamedConnectionAndObserversKeepTheHeadsStatus) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/app-cancel")));
    EXPECT_TRUE(c.read_until([&] { return c.eof; })) << "a cancelled context under a streamed head must close: " << c.buffer;
    EXPECT_FALSE(parse_response(c.buffer).complete) << c.buffer;
    EXPECT_TRUE(wait_for([] { return g_seen.cancelled.load(); })) << "the producer was never told";
    EXPECT_TRUE(g_seen.closed_verdict_seen.load() || g_seen.stream_cancelled_seen.load());
    ASSERT_TRUE(wait_for([] { return access_of("/app-cancel").has_value(); })) << "no access-log record";
    EXPECT_EQ(access_of("/app-cancel")->status, 200);
    EXPECT_GE(access_of("/app-cancel")->bytes, 2u) << "the bytes streamed before the cancel";
    EXPECT_EQ(access_of("/app-cancel")->bytes, g_seen.written_at_close.load()) << "the bytes the stream had taken when it was cancelled";
    EXPECT_EQ(server->server().metrics->count(qb::http::method::GET, "/app-cancel", 200), 1u);
    EXPECT_EQ(server->server().metrics->count(qb::http::method::GET, "/app-cancel", 503), 0u);
}

TEST_F(ResponseStreamTest, AnExtractionUnderALiveStreamTellsTheProducerAndTheContext) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/extract")));
    EXPECT_TRUE(wait_for([] { return g_seen.cancelled.load(); })) << "the producer was never told";
    EXPECT_TRUE(g_seen.stream_cancelled_seen.load() || g_seen.closed_verdict_seen.load());
    EXPECT_TRUE(wait_for([] { return g_seen.context_cancelled.load(); })) << "the context was not cancelled";
    EXPECT_TRUE(c.read_until([&] { return c.eof; })) << c.buffer;
}

TEST_F(ResponseStreamTest, TheInactivityTimeoutEndsAQuietStreamAndEachPieceRefreshesIt) {
    {
        RawClient c;
        ASSERT_TRUE(c.connect(port));
        ASSERT_TRUE(c.send(get("/quiet")));
        EXPECT_TRUE(wait_for([] { return g_seen.cancelled.load(); })) << "the producer was never told";
        EXPECT_TRUE(g_seen.stream_cancelled_seen.load()) << "a quiet stream outlived the session's inactivity timeout";
        EXPECT_TRUE(c.read_until([&] { return c.eof; })) << c.buffer;
    }
    g_seen.reset();
    {
        RawClient c;
        ASSERT_TRUE(c.connect(port));
        ASSERT_TRUE(c.send(get("/heartbeat")));
        ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }, 5s)) << c.buffer;
        const auto r = parse_response(c.buffer);
        EXPECT_EQ(r.chunks, 20) << "a piece every 30 ms keeps a 300 ms timeout from ending a 600 ms stream";
        EXPECT_TRUE(g_seen.producer_done.load());
    }
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

TEST_F(ResponseStreamTest, AStreamDroppedWithACallbackRegisteredReleasesItWithoutRunningIt) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/drop-waiting")));
    EXPECT_TRUE(c.read_until([&] { return c.eof; })) << "a dropped stream closes the connection";
    // Turns of the server's loop pass before a second connection is answered: a callback deferred by the drop would
    // have run by then.
    RawClient d;
    ASSERT_TRUE(d.connect(port));
    ASSERT_TRUE(d.send(get("/plain")));
    ASSERT_TRUE(d.read_until([&] { return parse_response(d.buffer).complete; })) << d.buffer;
    EXPECT_TRUE(g_seen.dropped_callback_set.load()) << "the callback was not registered: the case proves nothing";
    EXPECT_FALSE(g_seen.dropped_callback_ran.load()) << "the callback of a stream that is gone ran";
}

TEST_F(ResponseStreamTest, AStreamDroppedMidBodyReportsTheBytesItStreamedToObservers) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/drop-counted")));
    EXPECT_TRUE(c.read_until([&] { return c.eof; })) << "a dropped stream closes the connection";
    ASSERT_TRUE(wait_for([] { return access_of("/drop-counted").has_value(); })) << "no access-log record";
    EXPECT_EQ(access_of("/drop-counted")->status, 200) << "the head that left";
    EXPECT_EQ(access_of("/drop-counted")->bytes, 24u) << "the bytes the stream handed to its session before its producer dropped it";
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

TEST_F(ResponseStreamTest, ABufferedAbortAnswers500WithoutTheFailedBodysHeaders) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/abort-buffered", "HTTP/1.0")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::buffered));
    EXPECT_EQ(r.status, 500);
    EXPECT_TRUE(r.body.empty()) << r.body;
    EXPECT_EQ(r.header_count("content-encoding"), 0) << "the 500 kept the coding of a body it does not carry: " << r.head;
    EXPECT_TRUE(r.header_is("x-kept", "yes")) << r.head;
}

TEST_F(ResponseStreamTest, ABufferedAbortAfterACancellationLeavesTheAnswerSentAlone) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/cancel-then-abort", "HTTP/1.0")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    EXPECT_EQ(parse_response(c.buffer).status, 503);
    EXPECT_TRUE(wait_for([] { return g_seen.post_send_status.load() != 0; }));
    EXPECT_EQ(g_seen.post_send_status.load(), 503) << "the abort rewrote the response that had been sent";
}

#ifdef QB_HAS_SSL
// ------------------------------------------------------------------------------------------------ over TLS (review M1)
// The same session over transport::stcp: a response that ends with nothing left to write arms an empty write to be told
// eos, which reached SSL_write() with 0 bytes until qb-io's stream stopped handing a transport an empty write
// (Huly QB-1176).
namespace response_stream_test {

using SecureServer = qb::http::ssl::Server<>;
using SecureCtx    = qb::http::Context<qb::http::ssl::DefaultSecureSession>;
using TlsClient    = BasicRawClient<qb::io::tcp::ssl::socket>;

class ResponseStreamTlsTest : public ::testing::Test {
protected:
    qb::http::test::tls_identity                identity{"qbm-response-stream"};
    std::uint16_t                               port = 0;
    std::unique_ptr<ServerThread<SecureServer>> server;

    void
    SetUp() override {
        ASSERT_TRUE(identity.ok());
        g_seen.reset();
        server = std::make_unique<ServerThread<SecureServer>>([this](SecureServer &s) {
            s.router().get("/length-drained", [](std::shared_ptr<SecureCtx> ctx) {
                ctx->response().status() = qb::http::status::OK;
                ctx->response().set_header("Content-Length", "11");
                auto stream = ctx->begin_stream();
                record(ctx, stream);
                (void) stream->write("drained-all");
                qb::io::async::callback([stream]() { stream->end(); }, 30ms);
            });
            s.router().head("/chunked", [](std::shared_ptr<SecureCtx> ctx) {
                ctx->response().status() = qb::http::status::OK;
                auto stream              = ctx->begin_stream();
                record(ctx, stream);
                pieces_over_turns(std::move(stream), 0, 8);
            });
            s.router().get("/plain", [](std::shared_ptr<SecureCtx> ctx) {
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body()   = "plain-body";
                ctx->complete();
            });
            s.router().compile();
            return s.listen(qb::io::uri{"tcp://127.0.0.1:0"}, identity.context());
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

} // namespace response_stream_test

TEST_F(ResponseStreamTlsTest, OverTlsAContentLengthBodyAlreadyDrainedBeforeEndStillEnds) {
    TlsClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/length-drained")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer);
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::content_length));
    EXPECT_EQ(r.body, "drained-all");
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(get("/plain")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }, 2s))
        << "the session never ended the drained response over TLS (eof=" << c.eof << "): " << c.buffer;
    EXPECT_EQ(parse_response(c.buffer).body, "plain-body");
}

TEST_F(ResponseStreamTlsTest, OverTlsAHeadOnAStreamedRouteServesTheNextRequest) {
    TlsClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/chunked", "HTTP/1.1", "HEAD")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer, true).complete; })) << c.buffer;
    const auto r = parse_response(c.buffer, true);
    EXPECT_EQ(r.status, 200);
    EXPECT_TRUE(r.chunked) << r.head;
    c.buffer.erase(0, r.consumed);
    ASSERT_TRUE(c.send(get("/plain")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }, 2s))
        << "the HEAD exchange never ended over TLS (eof=" << c.eof << "): " << c.buffer;
    EXPECT_EQ(parse_response(c.buffer).body, "plain-body");
}
#endif // QB_HAS_SSL

#else // QBM_TEST_RESPONSE_STREAM_HUGE_BODY

// The buffered body's bound allocates ~200 MiB: this case alone is the target qbm-http-test-system-response-stream-huge-body,
// built from this source with QBM_TEST_RESPONSE_STREAM_HUGE_BODY and labelled huge-body (`ctest -LE huge-body` drops it
// on a small runner), and the ordinary target does not build it.
TEST_F(ResponseStreamTest, ABufferedBodyStopsAtTheProtocolBound) {
    RawClient c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/huge", "HTTP/1.0")));
    ASSERT_TRUE(c.read_until([&] { return parse_response(c.buffer).complete; }, 60s)) << c.buffer.substr(0, 256);
    EXPECT_EQ(g_seen.framing.load(), static_cast<int>(qb::http::stream_framing::buffered));
    EXPECT_EQ(g_seen.verdicts[0].load(), verdict(Stream::write_result::too_large)) << "a piece alone past the bound was taken";
    EXPECT_EQ(g_seen.verdicts[1].load(), verdict(Stream::write_result::taken));
    EXPECT_EQ(g_seen.verdicts[2].load(), verdict(Stream::write_result::too_large)) << "the body grew past the bound";
    EXPECT_EQ(parse_response(c.buffer).status, 500);
}

#endif // QBM_TEST_RESPONSE_STREAM_HUGE_BODY

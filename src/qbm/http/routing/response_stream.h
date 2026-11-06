/**
 * @file qbm/http/src/qbm/http/routing/response_stream.h
 * @brief A response body produced incrementally, with backpressure (Huly QB-86).
 *
 * A handler that cannot, or should not, hold its whole body in memory before answering -- a large
 * file, a stream of events, a body computed over time -- begins a stream on its `Context`: the head
 * goes to the wire at once, the body follows in the pieces the handler writes, the session's output
 * buffer bounds how far the handler may run ahead of the peer, and `end()` closes the message. The
 * stream is the handler's view of that; the session it writes through implements the hooks the
 * `streaming_session` concept names (the HTTP/1.1 server session does). A response that cannot be
 * streamed -- a session without the hooks, an HTTP/1.0 client with no declared length, a status
 * that carries no body -- gives the handler a BUFFERED stream with the same interface: the pieces
 * gather in the response body and leave whole at `end()`, through the ordinary completion. A
 * handler is therefore written once for every protocol.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * @ingroup Http
 */

#ifndef QB_MODULE_HTTP_ROUTING_RESPONSE_STREAM_H
#define QB_MODULE_HTTP_ROUTING_RESPONSE_STREAM_H

#include <algorithm>
#include <array>
#include <chrono>
#include <concepts>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string_view>
#include <utility>

#include <qb/io/async/coroutine/scheduler.h> // qb::io::async::schedule_via_current
#include <qb/io/async/coroutine/tracking.h>  // qb::io::async::track_suspension
#include <qb/io/async/io.h>                  // qb::io::async::with_timeout: the stall watch's timer (Huly QB-1212)
#include <qb/io/async/listener.h>            // qb::io::async::defer
#include <qb/system/time.h>                  // qb::duration, qb::mono_now

#include "../1.1/protocol/base.h" // qb::http::protocol_limits::MAX_BODY_SIZE (a buffered body's bound)
#include "../chunk.h"
#include "../types.h" // qb::http::status
#include "./types.h"  // AsyncTaskResult

namespace qb::http {

template <typename SessionType>
class Context;
template <typename SessionType>
class ResponseStream;

/// How the body of a streamed response reaches the wire (Huly QB-86).
enum class stream_framing : std::uint8_t {
    buffered,       ///< not streamed: the pieces gather in the body and leave whole at `end()`, through the ordinary completion
    content_length, ///< a `Content-Length` was declared: the pieces go as they are, counted against it
    chunked,        ///< `Transfer-Encoding: chunked`: every piece a chunk, `end()` the last-chunk
    end_of_stream   ///< HTTP/2, HTTP/3: the pieces go as DATA frames as they are, the end of the stream (END_STREAM, FIN) ends them
};

/// The bytes a producer may leave queued in the session's output before it should wait for `drain()`.
inline constexpr std::size_t default_stream_high_watermark = std::size_t{1} << 20; // 1 MiB

namespace detail {
/// A status whose response carries no content (RFC 9110 15: 1xx, 204, 304): such a response is never streamed --
/// the same rule the HTTP/1.1 serializer enforces (`response_must_not_carry_body`).
[[nodiscard]] constexpr bool
status_carries_no_body(int code) noexcept {
    return (code >= 100 && code < 200) || code == 204 || code == 304;
}
} // namespace detail

/**
 * @brief The hooks a session offers a `ResponseStream` (the HTTP/1.1, HTTP/2 and HTTP/3 server sessions do;
 *        `Context::begin_stream()` probes them and gives a buffered stream on a session without them). A hook about
 *        one stream takes it: an HTTP/2 or HTTP/3 session serves many at once, told apart by `stream_id()`.
 *
 * - `stream_can_answer(ctx)`: whether the session can stream the response to `ctx` now -- it is a context the
 *   session answers, or the one being routed for it, and no stream is live on it. A query: nothing changes.
 * - `stream_request_is_head(ctx)`: the request being answered is a HEAD: the head goes out, the body never does.
 * - `stream_delimits_messages()`: the protocol ends a message itself (HTTP/2 END_STREAM, HTTP/3 FIN): a head with no
 *   framing header streams as `stream_framing::end_of_stream`, and no `Transfer-Encoding` (hop-by-hop) is added.
 * - `stream_head(ctx, stream)`: writes the head of `ctx.response()` now -- adopting `ctx` when it is the context
 *   being routed for the session -- and keeps a WEAK reference to `stream` to notify it, except for a HEAD, whose
 *   exchange ends at its head; `false` when the head could not be written (the session then ends the exchange).
 * - `stream_write(stream, bytes)` / `stream_write(stream, chunk)`: appends to the session's output.
 * - `stream_pending(stream)`: the bytes queued for the peer that it has not taken -- the socket's output; on HTTP/2
 *   the pieces the stream's windows hold back too; on HTTP/3 the bytes the peer has not acknowledged.
 * - `stream_high_watermark()`: the bytes a producer may queue before it should wait for `drain()`.
 * - `stream_write_cap()`: the hard cap of the output (qb-io's write-buffer cap: `publish()` DISCONNECTS past it).
 * - `stream_end(stream, chunked)`: the terminator when chunked, then what follows any response's last byte.
 * - `stream_abort(stream)`: the message cannot be completed correctly any more: the connection closes (HTTP/1.1),
 *   the stream is reset (HTTP/2, HTTP/3).
 */
template <typename S>
concept streaming_session = requires(S &s, Context<S> &ctx, ResponseStream<S> const &stream, std::shared_ptr<ResponseStream<S>> handle,
                                     std::string_view bytes, Chunk const &chunk, bool chunked) {
    { s.stream_can_answer(ctx) } -> std::convertible_to<bool>;
    { s.stream_request_is_head(ctx) } -> std::convertible_to<bool>;
    { s.stream_delimits_messages() } -> std::convertible_to<bool>;
    { s.stream_head(ctx, handle) } -> std::convertible_to<bool>;
    s.stream_write(stream, bytes);
    s.stream_write(stream, chunk);
    { s.stream_pending(stream) } -> std::convertible_to<std::size_t>;
    { s.stream_high_watermark() } -> std::convertible_to<std::size_t>;
    { s.stream_write_cap() } -> std::convertible_to<std::size_t>;
    s.stream_end(stream, chunked);
    s.stream_abort(stream);
};

/// A session whose output is shared by many streams keeps, per stream, what the peer has not taken of THAT stream's
/// bytes (HTTP/2: the pieces its windows hold back and its share of the output as a FIFO bound): the stall watch reads
/// it instead of the shared report, so another stream's traffic is never this one's acceptance (Huly QB-1212).
template <typename S>
concept per_stream_waiting = requires(S &s, ResponseStream<S> const &stream) {
    { s.stream_waiting(stream) } -> std::convertible_to<std::size_t>;
};

/**
 * @brief A response body written piece by piece, with backpressure (Huly QB-86).
 * @tparam SessionType The session type of the `Context` that began the stream.
 *
 * Obtained from `Context::begin_stream()`, never constructed by hand. THE PRODUCER OWNS IT: `begin_stream()`
 * hands out the only strong reference, the context and the session keep weak ones. A producer that drops its
 * handle without `end()` ends the message the only correct way left -- it is aborted: on the wire the exchange ends
 * (HTTP/1.1 closes the connection, HTTP/2 and HTTP/3 reset the stream), so a peer never waits for bytes that will not
 * come; buffered, the context answers 500. The stream holds nothing strongly: producer -> stream (shared); stream ->
 * context and session (weak); context -> stream (weak); session -> context (shared, until the response is delivered).
 * A producer that waits through `on_drain()` with a callback that owns it -- the static files' streamer does -- makes a
 * cycle, stream -> callback -> producer -> stream, which the stream breaks on every way out: the callback is run, or
 * released without running, at a drain, an `end()`, an `abort()`, a cancellation (the peer leaving, the context's, an
 * extraction, the inactivity timeout) and the session's destruction (Huly QB-101). A producer that keeps itself alive
 * any other way while it waits leaks itself and all it holds.
 *
 * THE STREAM OWNS THE COMPLETION: from `begin_stream()` until the stream ends, a `complete()` on its context is
 * ignored -- the coroutine adapters' automatic completion and a handler's own call alike -- and only `end()`,
 * `abort()`, the stream's destruction or a cancellation completes it. A handler may therefore hand its stream to a
 * producer (a timer chain, a subscription) and return, on every protocol; a handler that throws while its stream is
 * still open leaves the response to it. The response to a HEAD request is the exception: complete at its head, its
 * context completes there and the stream only counts what it is given.
 *
 * The contract, in the order a producer meets it:
 *
 * 1. `write(bytes)` appends to the wire (or to the body, buffered) and returns at once, with a verdict: `taken`;
 *    `wait` (the session's output holds too much already: nothing was written, wait for `drain()` and write it
 *    again -- after a drain it always fits); `too_large` (the piece alone cannot fit even into a drained output,
 *    or, buffered, the gathered body would pass `protocol_limits::MAX_BODY_SIZE`: split it, or end the response);
 *    `closed` (the peer is gone, the context is over, or the stream is -- a piece that would exceed a declared
 *    `Content-Length` ends the stream too, by aborting it: a message cannot be lengthened). The framing bytes of a
 *    chunk count against the caps with its payload, and the last-chunk's room is kept for `end()`. On HTTP/2 a piece
 *    wider than the peer's frame size is split into frames, and what the stream's or the connection's window cannot
 *    take yet waits in the session, counted by `pending()`, until a WINDOW_UPDATE lets it go; nothing is refused for
 *    a window. On HTTP/3 the pieces wait the same way for the QUIC transport and `pending()` counts what the peer
 *    has not acknowledged.
 * 2. Backpressure: when `needs_drain()` -- the session holds `high_watermark()` bytes or more that the peer has not
 *    taken yet -- the producer waits: `co_await drain()` in a coroutine, `on_drain(fn)` otherwise. Both resume
 *    once the session's output falls to `low_watermark()` (half the high one by default), or when the stream is
 *    cancelled or ended -- the coroutine form says which through its `bool`, the callback reads `cancelled()` /
 *    `ended()`. The callback always runs at the end of an event-loop turn (`qb::io::async::defer`), never inside the
 *    session's own I/O handlers and never recursively; a callback still registered when the stream dies is released
 *    without running (capture the stream weakly, or own it). ONE producer at a time: a second `drain()` while one
 *    is parked resumes the newcomer at once with `false`. The marks stay under the session's hard output cap: the
 *    high one at most half of it, the low one under the high one.
 * 3. `end()` closes the message -- the last-chunk when chunked, END_STREAM (with the response's `trailers()` as a
 *    trailing HEADERS when it has any) on HTTP/2, FIN on HTTP/3; a declared length not reached ABORTS the exchange
 *    instead, since the message cannot be completed -- and completes the context.
 * 4. The peer may go away at any time -- the connection, or on HTTP/2 and HTTP/3 its stream alone (RST_STREAM, a
 *    GOAWAY that ends it, a QUIC stream reset): the session cancels the stream, a parked `drain()` resumes with
 *    `false`, the next `write()` returns `closed`, and the context is cancelled; the producer's only duty is to stop.
 *    A `ctx->cancel()` -- or a `complete(AsyncTaskResult::CANCELLED)`, a middleware's after `next()` included (Huly
 *    QB-101) -- does the same from the application's side, and aborts the exchange under a streamed head (the
 *    connection closes on HTTP/1.1, the stream is reset on HTTP/2 and HTTP/3, never the connection); a
 *    buffered stream, or one a `PRE_RESPONSE_SEND` hook cancels inside `begin_stream()`, answers 503 with no body and
 *    without the representation headers its head declared -- type, framing, coding, range, validators, caching
 *    (Huly QB-101).
 *
 * Framing (`framing()`) is decided by `begin_stream()` from the head as the `PRE_RESPONSE_SEND` hooks leave it: a
 * valid `Content-Length` is honoured and enforced on every protocol; a `Transfer-Encoding` whose only coding is
 * `chunked`, or none at all, gives chunked framing on HTTP/1.1 (never to HTTP/1.0) and `end_of_stream` framing on a
 * session that delimits its messages (HTTP/2, HTTP/3: DATA frames, no coding). A body already in `response()` when the stream begins is its
 * first piece, on every path. The response to a HEAD request streams its head alone: the pieces are counted and discarded, never faulted
 * against a length. A response that cannot be streamed gets a BUFFERED stream: same interface, the body leaves whole at `end()` through the
 * ordinary completion, `pending()` reads 0 and `drain()` never waits. `PRE_RESPONSE_SEND` hooks run once: at `begin_stream()` when the response
 * may stream -- they see the head that leaves and an empty body, so a body-rewriting hook (compression) leaves a streamed body alone -- and at
 * the ordinary completion when the response is buffered from the start, so compression, logging and timing see
 * the body they are owed. `POST_RESPONSE_SEND` runs when the last byte is delivered, as for any response. A session
 * whose inactivity timeout runs while a producer writes nothing ends the stream like a peer that left: a stream of
 * events writes a heartbeat, or the session's timeout is raised.
 */
template <typename SessionType>
class ResponseStream : public std::enable_shared_from_this<ResponseStream<SessionType>> {
    friend class Context<SessionType>;

public:
    using context_type = Context<SessionType>;

    /// What `write()` did with a piece.
    enum class write_result : std::uint8_t {
        taken,     ///< on its way (or gathered, buffered)
        wait,      ///< the output holds too much: wait for `drain()`, then write it again
        too_large, ///< the piece alone cannot fit (into a drained output, or under the buffered bound): split it
        closed     ///< the stream is over or the peer is gone (or the piece would exceed the declared length: aborted)
    };

    /**
     * @brief The awaitable of `drain()`: suspends the producer until the session's output falls to
     *        `low_watermark()`, the stream is cancelled, or it is ended; resumes with `true` when it may write on.
     *
     * Neither copyable nor movable (the rule of every awaiter that registers itself, Huly QB-1000): it parks its own
     * address in the stream and its destructor retracts it, so a copy destroyed first retracted the live wait. It
     * holds the stream alive while parked. `drain()` returns a prvalue: `co_await` what it returns.
     */
    struct drain_awaiter {
        std::shared_ptr<ResponseStream> stream;
        std::coroutine_handle<>         handle{};       ///< set while parked; the stream clears it as it resumes us
        bool                            refused{false}; ///< a second producer: resumed at once, told to stop

        explicit drain_awaiter(std::shared_ptr<ResponseStream> s) noexcept
            : stream(std::move(s)) {}
        drain_awaiter(const drain_awaiter &)            = delete;
        drain_awaiter(drain_awaiter &&)                 = delete;
        drain_awaiter &operator=(const drain_awaiter &) = delete;
        drain_awaiter &operator=(drain_awaiter &&)      = delete;

        /// Reclaimed while parked (the producer's frame destroyed): nothing may resume it.
        ~drain_awaiter() {
            if (stream && stream->_waiter == this)
                stream->_waiter = nullptr;
        }

        [[nodiscard]] bool
        await_ready() const noexcept {
            return stream->_cancelled || stream->_ended || stream->pending() <= stream->_low_watermark;
        }

        void
        await_suspend(std::coroutine_handle<> h) {
            qb::io::async::track_suspension(h, "http response stream drain");
            if (stream->_waiter) {
                // Two producers at once is a logic error: the newcomer is told at once, rather than parked over the
                // first one, which would then never resume.
                refused = true;
                qb::io::async::schedule_via_current(h);
                return;
            }
            handle          = h;
            stream->_waiter = this;
        }

        [[nodiscard]] bool
        await_resume() noexcept {
            handle = {};
            if (stream->_waiter == this) // resumed by something else than the stream (a reclaim, a scheduler drain)
                stream->_waiter = nullptr;
            if (refused)
                return false; // the second producer of a one-producer stream: told to stop, not to write
            return !stream->_cancelled && !stream->_ended;
        }
    };

    /// Built by `Context::begin_stream()` only. `write_cap` is the session's hard output cap (none when buffered); the
    /// watermarks are clamped under it. `stream_id` is the request's (0 on HTTP/1.1, the stream on HTTP/2 and HTTP/3).
    ResponseStream(std::weak_ptr<context_type> ctx, std::weak_ptr<SessionType> session, stream_framing framing, std::size_t declared_length,
                   bool head_only, std::size_t high_watermark, std::size_t write_cap, std::uint64_t stream_id = 0) noexcept
        : _ctx(std::move(ctx))
        , _session(std::move(session))
        , _framing(framing)
        , _declared(declared_length)
        , _head_only(head_only)
        , _write_cap(write_cap)
        , _high_watermark(clamped_high(high_watermark))
        , _low_watermark(_high_watermark / 2)
        , _stream_id(stream_id) {}

    ResponseStream(const ResponseStream &)            = delete;
    ResponseStream &operator=(const ResponseStream &) = delete;
    ResponseStream(ResponseStream &&)                 = delete;
    ResponseStream &operator=(ResponseStream &&)      = delete;

    /// The producer dropped its handle: a message still open cannot be completed, so it is aborted. A drain callback
    /// still registered is released without running: the stream it would report on is gone. Dropped on the session's
    /// loop thread, as every use of the stream is made there: the abort reaches the session, and the stall watch's
    /// timer belongs to that loop.
    ~ResponseStream() {
        _on_drain = nullptr;
        if (!_ended && !_cancelled)
            abort();
    }

    // --- the producer's side ---------------------------------------------------------------------------------

    /**
     * @brief Append a piece of the body.
     * @return `taken`, `wait`, `too_large` or `closed`: see the class contract. An empty piece is always taken.
     */
    [[nodiscard]] write_result
    write(std::string_view bytes) {
        if (_cancelled || _ended)
            return write_result::closed;
        if (bytes.empty())
            return write_result::taken;
        if (_framing == stream_framing::buffered)
            return write_buffered(bytes);
        if (_head_only) { // the response to HEAD: counted, never written, never faulted against a length
            _written += bytes.size();
            return write_result::taken;
        }
        if (_framing == stream_framing::content_length && bytes.size() > _declared - _written) {
            abort(); // a message cannot be lengthened past its declared Content-Length
            return write_result::closed;
        }
        auto session = _session.lock();
        if (!session) {
            _cancelled = true;
            stop_watch();
            return write_result::closed;
        }
        if constexpr (streaming_session<SessionType>) {
            // The framing bytes travel with the piece: a chunk is its hexadecimal size, CRLF, the bytes, CRLF; and the
            // last-chunk end() writes keeps its room, so end() never overruns the cap a write was admitted under.
            const bool        chunked = _framing == stream_framing::chunked;
            const std::size_t framed  = chunked ? bytes.size() + chunk_overhead(bytes.size()) : bytes.size();
            const std::size_t reserve = chunked ? chunk_overhead(0) : 0;
            if (_write_cap != static_cast<std::size_t>(-1)) {
                // A piece that would not fit after a drain either -- the output falls under the low mark, under the
                // high one, which is at most half the cap -- is refused for good: waiting for it would loop for ever.
                const std::size_t room = _write_cap - _high_watermark > reserve ? _write_cap - _high_watermark - reserve : 0;
                if (framed > room)
                    return write_result::too_large;
                if (session->stream_pending(*this) > _write_cap - reserve - framed)
                    return write_result::wait; // publish() would disconnect the peer for the producer's haste
            }
            if (chunked)
                session->stream_write(*this, Chunk{bytes.data(), bytes.size()});
            else
                session->stream_write(*this, bytes);
            if (_watching) {
                if (_last_pending == 0)
                    _progress_at = qb::mono_now(); // nothing waited until now: the wait for the socket starts here
                _last_pending = waiting_now(*session, session->stream_pending(*this));
            }
        }
        _written += bytes.size();
        return write_result::taken;
    }

    [[nodiscard]] write_result
    write(char const *data, std::size_t size) {
        return write(std::string_view{data, size});
    }

    /**
     * @brief Close the message and complete the context. Idempotent.
     * @details Chunked: the last-chunk goes out; `end_of_stream`: END_STREAM or FIN, after the response's `trailers()`
     *          when it has any. Declared length: reached, nothing more is needed; NOT reached, the exchange is aborted
     *          instead (`abort()`), since the peer would wait for bytes that never come. Buffered: the whole body
     *          leaves now through the ordinary completion. HEAD: nothing -- its response was complete at its head.
     */
    void
    end() {
        if (_ended)
            return;
        if (_cancelled || _head_only) {
            _ended = true;
            stop_watch();
            drop_waiters();
            return;
        }
        if (_framing == stream_framing::content_length && _written != _declared) {
            abort();
            return;
        }
        _ended = true;
        stop_watch();
        if (_framing != stream_framing::buffered) {
            if (auto session = _session.lock()) {
                if constexpr (streaming_session<SessionType>)
                    session->stream_end(*this, _framing == stream_framing::chunked);
            }
        }
        drop_waiters();
        if (auto ctx = _ctx.lock())
            ctx->stream_finished_internal(_written);
    }

    /**
     * @brief The message cannot be completed correctly (a source that failed mid-body, a declared length that will
     *        not be reached, a producer gone): end the exchange -- the connection closes on HTTP/1.1, the stream is
     *        reset on HTTP/2 and HTTP/3 -- rather than deliver a message the peer would take for whole. Buffered:
     *        nothing has left, the context answers 500 -- an empty body, its framing and content-coding headers
     *        dropped -- unless it is already over (cancelled). HEAD: nothing to undo, its response was complete at
     *        its head. Idempotent.
     */
    void
    abort() {
        if (_ended)
            return;
        _ended   = true;
        _aborted = true;
        stop_watch();
        drop_waiters();
        if (_head_only)
            return;
        auto ctx = _ctx.lock();
        if (_framing == stream_framing::buffered) {
            if (ctx && !ctx->is_completed() && !ctx->is_cancelled()) {
                auto &response    = ctx->response();
                response.status() = qb::http::status::INTERNAL_SERVER_ERROR;
                response.body().clear();
                response.remove_header("Content-Length");
                response.remove_header("Transfer-Encoding");
                response.remove_header("Content-Encoding");
                ctx->stream_finished_internal(0);
            }
            return;
        }
        // The bytes that left are recorded here: the context's cancel() reads them from the stream only while it is
        // alive, and the abort of a producer that dropped its handle runs from the destructor, when it no longer is.
        if (ctx && ctx->_streamed)
            ctx->_streamed_bytes = _written;
        if (auto session = _session.lock()) {
            if constexpr (streaming_session<SessionType>)
                session->stream_abort(*this); // cancels the context, then ends the exchange
        }
        if (ctx && !ctx->is_completed())
            ctx->cancel("the streamed response was aborted"); // the session was already gone
    }

    /// Whether the producer should wait for `drain()` before writing on.
    [[nodiscard]] bool
    needs_drain() const noexcept {
        return pending() >= _high_watermark;
    }

    /// Wait (in a coroutine) until the output falls to `low_watermark()`, the stream is cancelled or ended.
    [[nodiscard]] drain_awaiter
    drain() noexcept {
        return drain_awaiter{this->shared_from_this()};
    }

    /**
     * @brief The same wait as a callback, for a producer without a coroutine: `fn` runs once, at the end of an
     *        event-loop turn -- the one in which the output falls to `low_watermark()`, the stream is cancelled or
     *        ended, or the current one when that already holds -- never inside the session's I/O handlers and never
     *        recursively. `fn` reads `cancelled()` / `ended()` first. A second `on_drain` replaces the first; a
     *        callback still registered when the stream is destroyed is released without running.
     */
    void
    on_drain(std::function<void()> fn) {
        if (!fn)
            return;
        if (_cancelled || _ended || pending() <= _low_watermark) {
            _on_drain = nullptr;
            qb::io::async::defer(std::move(fn));
            return;
        }
        _on_drain = std::move(fn);
    }

    /// The bytes the session holds for the peer, not yet taken (0 when buffered, and for a HEAD response).
    [[nodiscard]] std::size_t
    pending() const noexcept {
        if (_framing == stream_framing::buffered || _head_only)
            return 0;
        if constexpr (streaming_session<SessionType>) {
            if (auto session = _session.lock())
                return session->stream_pending(*this);
        }
        return 0;
    }

    [[nodiscard]] bool
    cancelled() const noexcept {
        return _cancelled;
    }
    [[nodiscard]] bool
    ended() const noexcept {
        return _ended;
    }
    [[nodiscard]] bool
    aborted() const noexcept {
        return _aborted;
    }
    [[nodiscard]] stream_framing
    framing() const noexcept {
        return _framing;
    }
    /// The response answers a HEAD request: the head went out, the pieces are counted and discarded.
    [[nodiscard]] bool
    head_only() const noexcept {
        return _head_only;
    }
    /// The bytes of body taken so far, the preamble included (counted, not written, for a HEAD response).
    [[nodiscard]] std::size_t
    written() const noexcept {
        return _written;
    }
    /// The `Content-Length` the response declared (0 unless `framing() == content_length`).
    [[nodiscard]] std::size_t
    declared_length() const noexcept {
        return _declared;
    }
    /// The stream this response answers: the request's `stream_id` -- 0 on HTTP/1.1, the HTTP/2 stream, the QUIC stream.
    [[nodiscard]] std::uint64_t
    stream_id() const noexcept {
        return _stream_id;
    }
    /// The context this stream answers, while it lives (a session reads the response's trailers at the end there).
    [[nodiscard]] std::shared_ptr<context_type>
    context() const noexcept {
        return _ctx.lock();
    }
    [[nodiscard]] std::size_t
    high_watermark() const noexcept {
        return _high_watermark;
    }
    [[nodiscard]] std::size_t
    low_watermark() const noexcept {
        return _low_watermark;
    }
    /**
     * @brief The longest the stream may wait for the socket -- the peer, on HTTP/2 and HTTP/3 -- to accept a byte of
     *        what it holds (Huly QB-1212): an IDLE deadline between two acceptances, not a total one, counted only while
     *        bytes wait. Past it the stream is aborted: `abort()`'s outcome, the producer released with what it holds
     *        (a static file's descriptor), the stream reset on HTTP/2 and HTTP/3, the connection closed on HTTP/1.1.
     *        `qb::duration::zero()` disables it (the default here; the static files middleware sets 60 s, nginx's
     *        `send_timeout`). Settable at any time, per stream, as `set_watermarks()` is: a change takes effect at once,
     *        armed or not, and restarts the clock (the same value again changes nothing). Acceptance is what the
     *        session reports to the stream at its write passes (`notify_drain()`; on HTTP/2 what it keeps for THIS
     *        stream, the connection's output being shared): a watched stream pays a clock read per report and one
     *        timer, an unwatched one a flag test at each write and report. The watch runs while the stream is open:
     *        once `end()` was called, what still waits in the output -- a body of at most the high watermark leaves in
     *        one go -- is the session's inactivity timeout's, the producer released already.
     */
    void
    set_idle_deadline(qb::duration deadline) noexcept {
        const auto wanted = deadline > qb::duration::zero() ? deadline : qb::duration::zero();
        if (wanted == _idle_deadline && _watching)
            return; // the same deadline again: the clock runs on
        _idle_deadline = wanted;
        update_watch();
    }
    [[nodiscard]] qb::duration
    idle_deadline() const noexcept {
        return _idle_deadline;
    }

    /**
     * @brief A floor under the rate at which the socket accepts the stream's bytes, in bytes per second over a SLIDING
     *        window of `window` (Huly QB-1212): a peer that reads an octet a minute never idles for the deadline, and
     *        this is for the deployments that refuse it. Sampled every eighth of the window while bytes wait, judged
     *        once the samples span a whole window (the burst that fills the socket's buffers never counts against the
     *        peer); under the floor the stream is aborted as at the idle deadline. The floor is a download's: a
     *        producer that writes less than it itself, with bytes waiting at every sample, is cut as a slow peer is.
     *        0 disables it (the default, the static files middleware's too); `window` is at least 10 ms.
     */
    void
    set_min_rate(std::size_t bytes_per_second, qb::duration window = std::chrono::seconds(10)) noexcept {
        const auto wanted_window = std::max<qb::duration>(window, std::chrono::milliseconds(10));
        if (bytes_per_second == _min_rate && wanted_window == _rate_window && _watching)
            return; // the same floor again: the window runs on
        _min_rate    = bytes_per_second;
        _rate_window = wanted_window;
        if (_min_rate != 0 && !_rate) {
            try {
                _rate = std::make_unique<RateRing>();
            } catch (...) {
                _min_rate = 0; // no window: no floor, as if none had been asked
            }
        }
        if (_min_rate == 0)
            _rate.reset();
        update_watch();
    }
    [[nodiscard]] std::size_t
    min_rate() const noexcept {
        return _min_rate;
    }
    [[nodiscard]] qb::duration
    min_rate_window() const noexcept {
        return _rate_window;
    }
    /// The bytes the socket (the peer, on HTTP/2 and HTTP/3) accepted so far, as the session reported them to the
    /// stream; counted while a deadline or a rate floor is set, 0 otherwise.
    [[nodiscard]] std::uint64_t
    accepted() const noexcept {
        return _accepted;
    }

    /// Both marks at once (0 for `high` is the default, 1 MiB). The high one is clamped to half the session's hard
    /// output cap, the low one under the high one (half of it when `low` is not below it): a producer that waits for
    /// `drain()` then always has room for any piece `write()` does not call `too_large`.
    void
    set_watermarks(std::size_t high, std::size_t low) noexcept {
        _high_watermark = clamped_high(high);
        _low_watermark  = low < _high_watermark ? low : _high_watermark / 2;
    }

    /// The framing bytes a chunk of `size` payload bytes adds: its hexadecimal size, CRLF, then CRLF after the bytes
    /// (the last-chunk, of size 0, is `chunk_overhead(0)` bytes).
    [[nodiscard]] static constexpr std::size_t
    chunk_overhead(std::size_t size) noexcept {
        std::size_t digits = 1;
        while (size >>= 4)
            ++digits;
        return digits + 4;
    }

    // --- the session's side ----------------------------------------------------------------------------------

    /**
     * @brief The session reports how many bytes its output still holds (on `pending_write`, and 0 on `eos`): a
     *        producer waiting for room is resumed once that falls to `low_watermark()`.
     */
    void
    notify_drain(std::size_t remaining) noexcept {
        if (_ended || _cancelled)
            return;
        if (_watching) {
            const std::size_t waiting = waiting_for_watch(remaining);
            if (waiting < _last_pending) { // the socket, or the peer, took bytes of this stream since the last report
                _accepted += _last_pending - waiting;
                _progress_at = qb::mono_now();
            }
            _last_pending = waiting;
        }
        if (remaining <= _low_watermark)
            drop_waiters();
    }

    /// The peer is gone (the session disconnects): every wait ends, every later `write()` is refused.
    void
    cancel() noexcept {
        if (_cancelled)
            return;
        _cancelled = true;
        stop_watch();
        drop_waiters();
    }

    /**
     * @brief The context was cancelled while the stream was open (`Context::cancel()`): every wait ends, every later
     *        `write()` is refused, and a stream whose head is on the wire is aborted -- the message cannot be completed,
     *        so the exchange ends (the connection closes, or the stream is reset) rather than leave the peer waiting.
     */
    void
    context_cancelled() noexcept {
        if (_cancelled || _ended)
            return;
        _cancelled = true;
        stop_watch();
        if (_framing != stream_framing::buffered && !_head_only) {
            _aborted = true;
            if (auto session = _session.lock()) {
                if constexpr (streaming_session<SessionType>)
                    session->stream_abort(*this); // the context is already cancelling: its own cancel() returns at once
            }
        }
        drop_waiters();
    }

private:
    /// A high mark as the stream keeps it: 0 is the default, and no more than half the hard output cap.
    [[nodiscard]] std::size_t
    clamped_high(std::size_t high) const noexcept {
        std::size_t h = high ? high : default_stream_high_watermark;
        if (_write_cap != static_cast<std::size_t>(-1) && h > _write_cap / 2)
            h = _write_cap / 2;
        return h ? h : 1;
    }

    /// A piece of a buffered body: gathered in the response, under the bound every protocol's serializer applies.
    [[nodiscard]] write_result
    write_buffered(std::string_view bytes) {
        auto ctx = _ctx.lock();
        if (!ctx || ctx->is_completed() || ctx->is_cancelled()) {
            _cancelled = true;
            stop_watch(); // the response is over: what would gather now would never be sent
            drop_waiters();
            return write_result::closed;
        }
        auto             &body  = ctx->response().body();
        const std::size_t bound = qb::http::protocol_limits::MAX_BODY_SIZE;
        if (body.size() > bound || bytes.size() > bound - body.size())
            return write_result::too_large; // the serializer would refuse the whole body at end()
        body.raw().put(bytes.data(), bytes.size());
        _written += bytes.size();
        return write_result::taken;
    }

    /// Resume the parked producer and defer the one-shot callback, whichever is registered: nothing of the
    /// producer's runs inside the session's I/O handlers.
    void
    drop_waiters() noexcept {
        if (auto *w = std::exchange(_waiter, nullptr); w && w->handle)
            qb::io::async::schedule_via_current(std::exchange(w->handle, {}));
        if (_on_drain) {
            try {
                qb::io::async::defer(std::exchange(_on_drain, nullptr));
            } catch (...) {
                // defer() allocates its slot; out of memory here leaves the producer uninformed, and the session's
                // timeout ends the story. Nothing may throw out of a noexcept event path.
            }
        }
    }

    // --- the stall watch (Huly QB-1212) ---------------------------------------------------------------------

    /// The watch's timer: a `with_timeout` the stream owns, created at its first setting and destroyed when the watch
    /// stops -- `stop_watch()` cancels it at once, so an ended stream leaves no timer behind and the loop nothing to wait
    /// for. Its tick is the stream's (`on_watch_tick()`), which holds the stream for its length; the tick may end the
    /// watch, and this object with it, so nothing here touches `this` once the owner was told.
    struct Watch final : qb::io::async::with_timeout<Watch> {
        ResponseStream *owner;
        explicit Watch(ResponseStream *stream) // may throw: the loop registers the timer (update_watch() catches)
            : qb::io::async::with_timeout<Watch>(qb::duration::zero())
            , owner(stream) {}
        void
        on(qb::io::async::event::timer const &) {
            owner->on_watch_tick();
        }
    };

    /// The rate floor's sliding window: eight samples of (when, bytes accepted so far), one every eighth of the window
    /// while bytes wait, the rate read against the oldest once they span the window. Allocated by `set_min_rate()` alone.
    struct RateRing {
        std::array<std::pair<qb::mono_time, std::uint64_t>, 8> samples{};
        std::uint8_t                                           count = 0;
        std::uint8_t                                           head  = 0; ///< the next slot written: the oldest while full
        qb::mono_time                                          last_sample{};
    };

    /// What waits for the socket of THIS stream's bytes, for the watch: what the session keeps per stream where its
    /// output is shared (`stream_waiting()` -- HTTP/2: the pieces the windows hold back and the frames of this stream
    /// a FIFO output of its size can still hold, never another stream's traffic), else what it reports for the stream.
    [[nodiscard]] std::size_t
    waiting_now(SessionType &session, std::size_t reported) const noexcept {
        if constexpr (per_stream_waiting<SessionType>)
            return session.stream_waiting(*this);
        else
            return reported;
    }

    /// `waiting_now()` at a session's report, the session locked only where it keeps a count per stream.
    [[nodiscard]] std::size_t
    waiting_for_watch(std::size_t reported) const noexcept {
        if constexpr (per_stream_waiting<SessionType>) {
            if (auto session = _session.lock())
                return session->stream_waiting(*this);
        }
        return reported;
    }

    void
    stop_watch() noexcept {
        _watching = false;
        _watch.reset(); // the timer goes with it, at once
    }

    /// Start, re-arm or stop the watch as the settings say; a change made while armed is armed anew, so it takes effect
    /// now. Nothing is watched where nothing can wait: a buffered stream, a HEAD's, a session without the hooks.
    void
    update_watch() noexcept {
        if constexpr (!streaming_session<SessionType>) {
            return;
        } else {
            const bool wanted = (_idle_deadline > qb::duration::zero() || _min_rate != 0) && !_ended && !_cancelled && !_head_only
                                && _framing != stream_framing::buffered;
            if (!wanted) {
                stop_watch();
                return;
            }
            _progress_at  = qb::mono_now();
            _last_pending = 0;
            if (auto session = _session.lock())
                _last_pending = waiting_now(*session, session->stream_pending(*this));
            if (_rate)
                _rate->count = 0;
            if (!_watch) {
                try {
                    _watch = std::make_unique<Watch>(this);
                } catch (...) {
                    _watching = false; // no timer: the stream runs unwatched, as without a setting
                    return;
                }
            }
            _watching = true;
            _watch->setTimeout(next_tick());
        }
    }

    /// The next tick: the idle deadline's remainder, or the rate window's next sample, whichever comes first, 1 ms at least.
    [[nodiscard]] qb::duration
    next_tick() const noexcept {
        const auto now  = qb::mono_now();
        auto       tick = qb::duration::max();
        if (_idle_deadline > qb::duration::zero()) {
            const auto idle = now - _progress_at;
            tick            = idle < _idle_deadline ? _idle_deadline - idle : qb::duration::zero();
        }
        if (_min_rate != 0 && _rate) {
            // The next sample a step away: from the last one, or from now when the window is empty (nothing waited, or
            // the floor was just set) -- never sooner, so a stream with nothing waiting ticks once a step, not once a ms.
            const auto step  = _rate_window / 8;
            const auto since = _rate->count == 0 ? qb::duration::zero() : now - _rate->last_sample;
            tick             = std::min<qb::duration>(tick, since < step ? step - since : qb::duration::zero());
        }
        return std::max<qb::duration>(tick, std::chrono::milliseconds(1));
    }

    /// The timer's tick: the stream holds itself for its length (an abort may drop every other reference), looks at
    /// the stall, and re-arms unless the watch stopped under it.
    void
    on_watch_tick() noexcept {
        auto self = this->weak_from_this().lock();
        if (!self || !_watching)
            return;
        if (watch_tick() && _watching && _watch)
            _watch->setTimeout(next_tick());
    }

    /// One look at the stall: `false` once the stream was aborted for it. Nothing waiting is no stall: the clock and
    /// the rate window restart when bytes wait again.
    [[nodiscard]] bool
    watch_tick() noexcept {
        const auto now = qb::mono_now();
        if (_last_pending == 0) {
            _progress_at = now;
            if (_rate)
                _rate->count = 0;
            return true;
        }
        if (_idle_deadline > qb::duration::zero() && now - _progress_at >= _idle_deadline) {
            abort();
            return false;
        }
        if (_min_rate != 0 && _rate) {
            auto &ring = *_rate;
            // The verdict first, against the oldest sample once the eight span the window; then the sample, one every
            // eighth of the window (a tick may come sooner, for the deadline): the window is the window whatever the
            // deadline, and the burst that fills the socket's buffers at the start is never read against the peer.
            if (ring.count == ring.samples.size()) {
                const auto &oldest = ring.samples[ring.head];
                if (now - oldest.first >= _rate_window) {
                    const auto elapsed = std::chrono::duration<double>(now - oldest.first).count();
                    if (elapsed > 0 && static_cast<double>(_accepted - oldest.second) / elapsed < static_cast<double>(_min_rate)) {
                        abort();
                        return false;
                    }
                }
            }
            if (ring.count == 0 || now - ring.last_sample >= _rate_window / 8) {
                ring.samples[ring.head] = {now, _accepted};
                ring.last_sample        = now;
                ring.head               = static_cast<std::uint8_t>((ring.head + 1) % ring.samples.size());
                if (ring.count < ring.samples.size())
                    ++ring.count;
            }
        }
        return true;
    }

    std::weak_ptr<context_type> _ctx;
    std::weak_ptr<SessionType>  _session;
    stream_framing              _framing;
    std::size_t                 _declared;
    bool                        _head_only;
    std::size_t                 _write_cap;
    std::size_t                 _high_watermark;
    std::size_t                 _low_watermark;
    std::size_t                 _written{0};
    bool                        _ended{false};
    bool                        _cancelled{false};
    bool                        _aborted{false};
    drain_awaiter              *_waiter{nullptr};
    std::function<void()>       _on_drain;
    std::uint64_t               _stream_id{0};
    // The stall watch (Huly QB-1212): the settings, what waits and when it last fell, the timer, the rate's window.
    qb::duration              _idle_deadline{qb::duration::zero()};
    std::size_t               _min_rate{0};
    qb::duration              _rate_window{std::chrono::seconds(10)};
    std::uint64_t             _accepted{0};
    std::size_t               _last_pending{0};
    qb::mono_time             _progress_at{};
    bool                      _watching{false};
    std::unique_ptr<Watch>    _watch;
    std::unique_ptr<RateRing> _rate;
};

namespace sse {
/// An event stream over a ResponseStream (sse.h, Huly QB-86): declared here for `Context::begin_sse()`.
template <typename SessionType>
class Stream;
struct Options;
} // namespace sse

} // namespace qb::http

#endif // QB_MODULE_HTTP_ROUTING_RESPONSE_STREAM_H

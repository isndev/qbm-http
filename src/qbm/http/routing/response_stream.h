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
#include <qb/io/async/listener.h>            // qb::io::async::defer

#include "../1.1/protocol/base.h" // qb::http::protocol_limits::MAX_BODY_SIZE (a buffered body's bound)
#include "../chunk.h"
#include "../types.h" // qb::http::status
#include "./types.h"  // AsyncTaskResult

namespace qb::http {

template <typename SessionType>
class Context;
template <typename SessionType>
class ResponseStream;

/**
 * @brief How the body of a streamed response reaches the wire (Huly QB-86).
 */
enum class stream_framing : std::uint8_t {
    buffered,       ///< not streamed: the pieces gather in the body and leave whole at `end()`, through the ordinary completion
    content_length, ///< a `Content-Length` was declared: the pieces go as they are, counted against it
    chunked         ///< `Transfer-Encoding: chunked`: every piece a chunk, `end()` the last-chunk
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
 * @brief The hooks a session offers a `ResponseStream` (the HTTP/1.1 server session does; `Context::begin_stream()`
 *        probes them and gives a buffered stream on a session without them).
 *
 * - `stream_can_answer(ctx)`: whether the session can stream the response to `ctx` now -- it is the context the
 *   session answers, or the one being routed for it, and no stream is live on it. A query: nothing changes.
 * - `stream_request_is_head()`: the request being answered is a HEAD: the head goes out, the body never does.
 * - `stream_head(ctx, stream)`: writes the head of `ctx.response()` now -- adopting `ctx` when it is the context
 *   being routed for the session -- and keeps a WEAK reference to `stream` to notify it, except for a HEAD, whose
 *   exchange ends at its head; `false` when the head could not be written (the session then closes the connection).
 * - `stream_write(bytes)` / `stream_write(chunk)`: appends to the session's output.
 * - `stream_pending()`: the bytes queued in the session's output, not yet written to the socket.
 * - `stream_high_watermark()`: the bytes a producer may queue before it should wait for `drain()`.
 * - `stream_write_cap()`: the hard cap of the output (qb-io's write-buffer cap: `publish()` DISCONNECTS past it).
 * - `stream_end(chunked)`: the terminator when chunked, then what follows any response's last byte.
 * - `stream_abort()`: the message cannot be completed correctly any more: the connection closes.
 */
template <typename S>
concept streaming_session =
    requires(S &s, Context<S> &ctx, std::shared_ptr<ResponseStream<S>> stream, std::string_view bytes, Chunk const &chunk, bool chunked) {
        { s.stream_can_answer(ctx) } -> std::convertible_to<bool>;
        { s.stream_request_is_head() } -> std::convertible_to<bool>;
        { s.stream_head(ctx, stream) } -> std::convertible_to<bool>;
        s.stream_write(bytes);
        s.stream_write(chunk);
        { s.stream_pending() } -> std::convertible_to<std::size_t>;
        { s.stream_high_watermark() } -> std::convertible_to<std::size_t>;
        { s.stream_write_cap() } -> std::convertible_to<std::size_t>;
        s.stream_end(chunked);
        s.stream_abort();
    };

/**
 * @brief A response body written piece by piece, with backpressure (Huly QB-86).
 * @tparam SessionType The session type of the `Context` that began the stream.
 *
 * Obtained from `Context::begin_stream()`, never constructed by hand. THE PRODUCER OWNS IT: `begin_stream()`
 * hands out the only strong reference, the context and the session keep weak ones. A producer that drops its
 * handle without `end()` ends the message the only correct way left -- it is aborted: on the wire the connection is
 * closed, so a peer never waits for bytes that will not come and a pipelined request never queues behind a dead
 * stream; buffered, the context answers 500. Nothing cycles: producer -> stream (shared); stream -> context and
 * session (weak); context -> stream (weak); session -> context (shared, until the response is delivered).
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
 *    `Content-Length` ends the stream too, by closing the connection: a message cannot be lengthened). The framing
 *    bytes of a chunk count against the caps with its payload, and the last-chunk's room is kept for `end()`.
 * 2. Backpressure: when `needs_drain()` -- the session holds `high_watermark()` bytes or more that the socket has
 *    not taken yet -- the producer waits: `co_await drain()` in a coroutine, `on_drain(fn)` otherwise. Both resume
 *    once the session's output falls to `low_watermark()` (half the high one by default), or when the stream is
 *    cancelled or ended -- the coroutine form says which through its `bool`, the callback reads `cancelled()` /
 *    `ended()`. The callback always runs at the end of an event-loop turn (`qb::io::async::defer`), never inside the
 *    session's own I/O handlers and never recursively; a callback still registered when the stream dies is released
 *    without running (capture the stream weakly, or own it). ONE producer at a time: a second `drain()` while one
 *    is parked resumes the newcomer at once with `false`. The marks stay under the session's hard output cap: the
 *    high one at most half of it, the low one under the high one.
 * 3. `end()` closes the message -- the last-chunk when chunked; a declared length not reached closes the
 *    CONNECTION instead, since the message cannot be completed -- and completes the context.
 * 4. The peer may go away at any time: the session cancels the stream, a parked `drain()` resumes with `false`, the
 *    next `write()` returns `closed`, and the context is cancelled; the producer's only duty is to stop. A
 *    `ctx->cancel()` does the same from the application's side, and closes the connection under a streamed head.
 *
 * Framing (`framing()`) is decided by `begin_stream()` from the head as the `PRE_RESPONSE_SEND` hooks leave it: a
 * valid `Content-Length` is honoured and enforced; a `Transfer-Encoding` whose only coding is `chunked`, or none at
 * all, gives chunked framing (never to HTTP/1.0). A body already in `response()` when the stream begins is its first
 * piece, on every path. The response to a HEAD request streams its head alone: the pieces are counted and
 * discarded, never faulted against a length. A response that cannot be streamed gets a BUFFERED stream: same
 * interface, the body leaves whole at `end()` through the ordinary completion, `pending()` reads 0 and `drain()`
 * never waits. `PRE_RESPONSE_SEND` hooks run once: at `begin_stream()` when the response may stream -- they see the
 * head that leaves and an empty body, so a body-rewriting hook (compression) leaves a streamed body alone -- and at
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
    /// watermarks are clamped under it.
    ResponseStream(std::weak_ptr<context_type> ctx, std::weak_ptr<SessionType> session, stream_framing framing, std::size_t declared_length,
                   bool head_only, std::size_t high_watermark, std::size_t write_cap) noexcept
        : _ctx(std::move(ctx))
        , _session(std::move(session))
        , _framing(framing)
        , _declared(declared_length)
        , _head_only(head_only)
        , _write_cap(write_cap)
        , _high_watermark(clamped_high(high_watermark))
        , _low_watermark(_high_watermark / 2) {}

    ResponseStream(const ResponseStream &)            = delete;
    ResponseStream &operator=(const ResponseStream &) = delete;
    ResponseStream(ResponseStream &&)                 = delete;
    ResponseStream &operator=(ResponseStream &&)      = delete;

    /// The producer dropped its handle: a message still open cannot be completed, so it is aborted. A drain callback
    /// still registered is released without running: the stream it would report on is gone.
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
                if (session->stream_pending() > _write_cap - reserve - framed)
                    return write_result::wait; // publish() would disconnect the peer for the producer's haste
            }
            if (chunked)
                session->stream_write(Chunk{bytes.data(), bytes.size()});
            else
                session->stream_write(bytes);
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
     * @details Chunked: the last-chunk goes out. Declared length: reached, nothing more is needed; NOT reached, the
     *          connection is closed instead (`abort()`), since the peer would wait for bytes that never come.
     *          Buffered: the whole body leaves now through the ordinary completion. HEAD: nothing -- its response was
     *          complete at its head.
     */
    void
    end() {
        if (_ended)
            return;
        if (_cancelled || _head_only) {
            _ended = true;
            drop_waiters();
            return;
        }
        if (_framing == stream_framing::content_length && _written != _declared) {
            abort();
            return;
        }
        _ended = true;
        if (_framing != stream_framing::buffered) {
            if (auto session = _session.lock()) {
                if constexpr (streaming_session<SessionType>)
                    session->stream_end(_framing == stream_framing::chunked);
            }
        }
        drop_waiters();
        if (auto ctx = _ctx.lock())
            ctx->stream_finished_internal(_written);
    }

    /**
     * @brief The message cannot be completed correctly (a source that failed mid-body, a declared length that will
     *        not be reached, a producer gone): close the connection rather than deliver a message the peer would
     *        take for whole. Buffered: nothing has left, the context answers 500 -- an empty body, its framing and
     *        content-coding headers dropped -- unless it is already over (cancelled). HEAD: nothing to undo, its
     *        response was complete at its head. Idempotent.
     */
    void
    abort() {
        if (_ended)
            return;
        _ended   = true;
        _aborted = true;
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
                session->stream_abort(); // cancels the context, then disconnects
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

    /// The bytes the session holds for the socket, not yet written (0 when buffered, and for a HEAD response).
    [[nodiscard]] std::size_t
    pending() const noexcept {
        if (_framing == stream_framing::buffered || _head_only)
            return 0;
        if constexpr (streaming_session<SessionType>) {
            if (auto session = _session.lock())
                return session->stream_pending();
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
    [[nodiscard]] std::size_t
    high_watermark() const noexcept {
        return _high_watermark;
    }
    [[nodiscard]] std::size_t
    low_watermark() const noexcept {
        return _low_watermark;
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
        if (remaining <= _low_watermark)
            drop_waiters();
    }

    /// The peer is gone (the session disconnects): every wait ends, every later `write()` is refused.
    void
    cancel() noexcept {
        if (_cancelled)
            return;
        _cancelled = true;
        drop_waiters();
    }

    /**
     * @brief The context was cancelled while the stream was open (`Context::cancel()`): every wait ends, every later
     *        `write()` is refused, and a stream whose head is on the wire is aborted -- the message cannot be completed,
     *        so the connection closes rather than leave the peer waiting for the rest of it.
     */
    void
    context_cancelled() noexcept {
        if (_cancelled || _ended)
            return;
        _cancelled = true;
        if (_framing != stream_framing::buffered && !_head_only) {
            _aborted = true;
            if (auto session = _session.lock()) {
                if constexpr (streaming_session<SessionType>)
                    session->stream_abort(); // the context is already cancelling: its own cancel() returns at once
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
            _cancelled = true; // the response is over: what would gather now would never be sent
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
};

} // namespace qb::http

#endif // QB_MODULE_HTTP_ROUTING_RESPONSE_STREAM_H

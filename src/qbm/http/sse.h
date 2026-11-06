/**
 * @file qbm/http/src/qbm/http/sse.h
 * @brief Server-Sent Events (`text/event-stream`) over a response stream, on every protocol (Huly QB-86).
 *
 * `qb::http::sse::begin(ctx)` -- or `ctx->begin_sse()` -- sets the head of an event stream and begins the context's
 * `ResponseStream`; the `sse::Stream` it returns writes events (`event:`, `data:`, `id:`, `retry:` lines, a blank line
 * after each) and comments (the heartbeat form), with the verdicts and the backpressure of the stream beneath it:
 * chunked on HTTP/1.1, DATA frames on HTTP/2 and HTTP/3. The wire format is the WHATWG HTML Standard's
 * (section "Server-sent events"): one `data:` line per line of an event's data, nothing escaped, a field value never
 * holding a line break.
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

#ifndef QB_MODULE_HTTP_SSE_H
#define QB_MODULE_HTTP_SSE_H

#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <qb/io/async/coroutine.h> // qb::io::async::task
#include <qb/io/async/io.h>        // qb::io::async::callback (the heartbeat timer)
#include <qb/system/time.h>        // qb::duration

#include "./request.h"
#include "./routing/context.h"
#include "./routing/response_stream.h"
#include "./utility.h" // utility::iequals

namespace qb::http::sse {

/**
 * @brief One event, as the stream writes it.
 *
 * `name` goes on an `event:` line (none when empty: the client dispatches a `message`); `data` on one `data:` line
 * per line of it -- a LF, a CR or a CRLF ends a line, the client joins the lines back with LF and drops the last one,
 * so a data that ends with a line break arrives as it was sent -- at least one line, so an event with empty data is
 * still dispatched (a client dispatches nothing for an event without a `data:` line); `id` on an `id:` line (none
 * when empty), which the client sends back as `Last-Event-ID` when it reconnects; `retry` on a `retry:` line, the
 * reconnection time in milliseconds the client keeps from then on. Nothing is escaped; a CR or LF inside `name` or
 * `id` is dropped, since it would start another field (a value a client supplied could forge an event).
 */
struct Event {
    std::string                              name;
    std::string                              data;
    std::string                              id;
    std::optional<std::chrono::milliseconds> retry;
};

/// The wire form of `event`: its `event:`, `id:`, `retry:` and `data:` lines, then the blank line that ends it.
[[nodiscard]] std::string format(Event const &event);

/// A comment line, `: text`, then a blank line: ignored by every client, the heartbeat form (a line keeps a
/// connection, a proxy and the session's inactivity timeout alive). A CR or LF in `text` is dropped.
[[nodiscard]] std::string comment_line(std::string_view text);

/// The `retry:` line alone, then a blank line: the reconnection time a client keeps for the stream.
[[nodiscard]] std::string retry_line(std::chrono::milliseconds retry);

/// The `Last-Event-ID` a reconnecting client sends -- the `id` of the last event it received -- or empty.
[[nodiscard]] std::string const &last_event_id(Request const &request);

/// The content type of an event stream, as `begin()` sets it.
inline constexpr std::string_view content_type = "text/event-stream; charset=utf-8";

/**
 * @brief What `begin()` writes besides the head.
 */
struct Options {
    /// A `retry:` line written first: the reconnection time the client keeps (none by default: the client's own).
    std::optional<std::chrono::milliseconds> retry;
    /// A comment line every `heartbeat` while the stream lives (none by default): see `Stream::heartbeat()`. Under the
    /// session's inactivity timeout, HTTP/2's idle-stream sweep (30 s) and every proxy's idle timeout on the way.
    std::optional<qb::duration> heartbeat;
    /// `X-Accel-Buffering: no`: tells an nginx in front not to buffer the response (off by default).
    bool accel_buffering_off = false;
};

/**
 * @brief An event stream over a `ResponseStream` (Huly QB-86): the same protocol-agnostic handle, writing events.
 * @tparam SessionType The session type of the `Context` that began it.
 *
 * Obtained from `begin()`. THE PRODUCER OWNS IT, as it owns a `ResponseStream`: the `Stream` holds the response stream,
 * and dropping the last handle before `end()` aborts the response (the connection closes on HTTP/1.1, the stream is
 * reset on HTTP/2 and HTTP/3). The verdicts are the stream's: `send()` and `comment()` return
 * `ResponseStream::write_result` -- `taken`; `wait` (the output is at its hard cap: nothing was written, write it
 * again after `drain()`); `too_large`; `closed` (the client is gone, or the stream ended). Backpressure is the
 * stream's too: `needs_drain()` once the session holds its high watermark, `co_await drain()` / `on_drain(fn)` to
 * wait, `send_async()` for a coroutine that wants one call to do both. The client may go away at any time: the
 * session cancels the stream, `cancelled()` holds, every later write answers `closed`, and the producer stops.
 *
 * A stream that writes nothing for the session's inactivity timeout -- and, on HTTP/2, one whose stream sent no frame
 * for the connection's idle sweep (30 s, `RST_STREAM(CANCEL)`), whatever its window -- ends like a peer that left: `heartbeat()`
 * writes a comment line at an interval while the stream lives, on a `qb::io::async::callback` timer that holds the
 * stream weakly -- it stops by itself at its next tick once the stream is gone, ended or cancelled (a dropped
 * handle's timer fires once more, finds no stream and stops).
 */
template <typename SessionType>
class Stream : public std::enable_shared_from_this<Stream<SessionType>> {
public:
    using stream_type  = ResponseStream<SessionType>;
    using write_result = typename stream_type::write_result;

    /// Built by `begin()` only.
    explicit Stream(std::shared_ptr<stream_type> stream) noexcept
        : _stream(std::move(stream)) {}

    Stream(const Stream &)            = delete;
    Stream &operator=(const Stream &) = delete;

    /// Write an event. `taken`: on its way (counted by `events_sent()`); the other verdicts are the stream's.
    [[nodiscard]] write_result
    send(Event const &event) {
        const auto verdict = _stream->write(format(event));
        if (verdict == write_result::taken)
            ++_events;
        return verdict;
    }

    /// Write a comment line (`: text`): the heartbeat form, ignored by every client.
    [[nodiscard]] write_result
    comment(std::string_view text = {}) {
        return _stream->write(comment_line(text));
    }

    /// Write a `retry:` line: the reconnection time the client keeps from then on.
    [[nodiscard]] write_result
    retry(std::chrono::milliseconds reconnection) {
        return _stream->write(retry_line(reconnection));
    }

    /**
     * @brief Write an event from a coroutine, waiting as the stream asks: when the piece must wait for a drain it is
     *        written again after one, and when the stream wants a drain after it (`needs_drain()`) the drain is waited
     *        for before resuming. `true` once the event is on its way and the producer may go on; `false` when the
     *        stream is over -- cancelled by the client, ended -- or the event cannot fit (`too_large`).
     */
    [[nodiscard]] qb::io::async::task<bool>
    send_async(Event event) {
        // The frame owns the stream from its creation: a task is lazy, and a `shared_from_this()` taken at the first
        // resume would read a `this` the caller may have dropped between creating the task and awaiting it.
        return send_async_on(this->shared_from_this(), std::move(event));
    }

    /**
     * @brief Write a comment line every `interval` while the stream lives, starting one interval from now, on a
     *        `qb::io::async::callback` timer that holds this stream weakly: it stops by itself once the stream is
     *        gone, ended or cancelled. A tick whose comment the stream cannot take now (`wait`) is skipped: the
     *        client is behind already. A second call replaces the first (its next tick stops); an interval of zero or
     *        less stops it.
     */
    void
    heartbeat(qb::duration interval, std::string text = {}) {
        const auto generation = ++_heartbeat_generation;
        if (interval <= qb::duration::zero())
            return;
        arm_heartbeat(this->weak_from_this(), generation, interval, std::move(text));
    }

    /// Close the event stream and complete the context (`ResponseStream::end()`).
    void
    end() {
        _stream->end();
    }
    /// The stream cannot be completed correctly: end the exchange (`ResponseStream::abort()`).
    void
    abort() {
        _stream->abort();
    }

    [[nodiscard]] bool
    needs_drain() const noexcept {
        return _stream->needs_drain();
    }
    /// Wait (in a coroutine) until the output falls to the low watermark, or the stream is cancelled or ended.
    [[nodiscard]] auto
    drain() noexcept {
        return _stream->drain();
    }
    /// The same wait as a callback (`ResponseStream::on_drain()`).
    void
    on_drain(std::function<void()> fn) {
        _stream->on_drain(std::move(fn));
    }
    [[nodiscard]] bool
    cancelled() const noexcept {
        return _stream->cancelled();
    }
    [[nodiscard]] bool
    ended() const noexcept {
        return _stream->ended();
    }
    /// The events `send()` / `send_async()` wrote so far (comments and `retry:` lines are not events).
    [[nodiscard]] std::size_t
    events_sent() const noexcept {
        return _events;
    }
    /// The response stream beneath: its framing, its watermarks, its bytes.
    [[nodiscard]] std::shared_ptr<stream_type> const &
    stream() const noexcept {
        return _stream;
    }

private:
    /// send_async()'s body, on a frame that owns the stream (`self`) from the task's creation.
    static qb::io::async::task<bool>
    send_async_on(std::shared_ptr<Stream> self, Event event) {
        const std::string wire = format(event);
        for (;;) {
            const auto verdict = self->_stream->write(wire);
            if (verdict == write_result::taken) {
                ++self->_events;
                break;
            }
            if (verdict != write_result::wait)
                co_return false;
            if (!co_await self->_stream->drain())
                co_return false;
        }
        if (self->_stream->needs_drain() && !co_await self->_stream->drain())
            co_return false;
        co_return true;
    }

    static void
    arm_heartbeat(std::weak_ptr<Stream> weak, std::uint32_t generation, qb::duration interval, std::string text) {
        qb::io::async::callback(
            [weak = std::move(weak), generation, interval, text = std::move(text)]() mutable {
                auto self = weak.lock();
                if (!self || self->_heartbeat_generation != generation || self->cancelled() || self->ended())
                    return; // the stream is gone, over, or beats to a newer call: this timer stops here
                (void) self->comment(text);
                if (self->cancelled() || self->ended())
                    return;
                arm_heartbeat(std::move(weak), generation, interval, std::move(text));
            },
            interval);
    }

    std::shared_ptr<stream_type> _stream;
    std::size_t                  _events{0};
    std::uint32_t                _heartbeat_generation{0};
};

namespace detail {
/// Whether the session drains (HTTP/1.1's `http1_draining()`): its next answer closes the connection, so an event
/// stream says no `keep-alive` on it. A session without the hook never drains this way.
template <typename S>
[[nodiscard]] bool
session_draining(S const &session) noexcept {
    if constexpr (requires {
                      { session.http1_draining() } -> std::convertible_to<bool>;
                  }) {
        return session.http1_draining();
    } else {
        return false;
    }
}
} // namespace detail

/**
 * @brief Begin an event stream on `ctx` (Huly QB-86): the head of a `text/event-stream` response, then the
 *        context's `ResponseStream` (`Context::begin_stream()`), wrapped.
 *
 * The head: status 200 unless the handler set another, `Content-Type: text/event-stream; charset=utf-8`,
 * `Cache-Control: no-cache`, and `Connection: keep-alive` on HTTP/1.1 only -- a hop-by-hop field is forbidden on
 * HTTP/2 and HTTP/3 (`well_known::is_hop_by_hop`), whose sessions delimit their messages themselves -- and only when
 * the request keeps the connection (`Request::keep_alive`, the parser's verdict over every `Connection` token) and
 * the server is not draining the session, which would answer `close`; `X-Accel-Buffering: no`
 * when `options` ask for it. A `Content-Length` the handler set is removed: an event stream has no length. Then
 * `options.retry` is written, and `options.heartbeat` starts.
 *
 * An event stream is streamed or it is nothing: where `begin_stream()` can only buffer (an HTTP/1.0 request, the
 * HTTP/1.1 fallback of an HTTP/2 server, a session without the hooks) the events would gather until `end()` -- never
 * for a stream that does not end -- so `begin()` refuses: the request is answered 500 with an empty body (the
 * buffered stream aborted) and `nullptr` is returned. A handler that wants a buffered fallback writes it itself.
 *
 * A HEAD gets the head alone: the stream comes back ended (`send()` answers `closed`, `ended()` holds, no `retry:`
 * line and no heartbeat), so a producer that loops on `cancelled()` alone must read `ended()` too.
 *
 * @return The event stream, or `nullptr` when the response cannot be streamed, or when `begin_stream()` refuses one
 *         (the context is finalised, cancelled, or holding back a completion); either way the head set here is
 *         taken off again, so a response still to be sent says nothing of an event stream.
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<Stream<SessionType>>
begin(std::shared_ptr<Context<SessionType>> const &ctx, Options const &options = {}) {
    if (!ctx)
        return nullptr;
    // The head is set BEFORE begin_stream(): on HTTP/2 and HTTP/3 the head leaves inside it. A begin_stream() that
    // refuses, or that can only buffer, takes these fields off again (strip_head): the response then sent -- a
    // finalisation that was pending, the 500 of an aborted buffered stream -- is no event stream.
    auto &response        = ctx->response();
    bool  said_keep_alive = false;
    response.set_header("Content-Type", std::string(content_type));
    response.set_header("Cache-Control", "no-cache");
    response.remove_header("Content-Length");
    if (options.accel_buffering_off)
        response.set_header("X-Accel-Buffering", "no");
    if constexpr (streaming_session<SessionType>) {
        if (auto session = ctx->session(); session && !session->stream_delimits_messages()) {
            // HTTP/1.1: a persistent connection, said -- when the request keeps it (the parser's verdict, every token
            // of its `Connection` field read) and the server is not draining this session, which would answer `close`;
            // hop-by-hop, so never on HTTP/2 and HTTP/3.
            if (ctx->request().keep_alive && !detail::session_draining(*session)) {
                response.set_header("Connection", "keep-alive");
                said_keep_alive = true;
            }
        }
    }
    const auto strip_head = [&] {
        response.remove_header("Content-Type");
        response.remove_header("Cache-Control");
        if (said_keep_alive)
            response.remove_header("Connection");
        if (options.accel_buffering_off)
            response.remove_header("X-Accel-Buffering");
    };
    auto stream = ctx->begin_stream();
    if (!stream) {
        strip_head(); // a finalisation that was pending sends the response as it stands: not as an event stream
        return nullptr;
    }
    if (stream->framing() == stream_framing::buffered) {
        // An event stream that waits for its end is no event stream: the buffered stream is aborted (the context
        // answers 500, with none of the head set above) and the handler is told.
        strip_head();
        stream->abort();
        return nullptr;
    }
    if (stream->head_only())
        stream->end(); // a HEAD: the head left whole at begin_stream(); the producer reads an ended stream (`closed`)
    auto events = std::make_shared<Stream<SessionType>>(std::move(stream));
    if (!events->ended()) {
        if (options.retry)
            (void) events->retry(*options.retry);
        if (options.heartbeat)
            events->heartbeat(*options.heartbeat);
    }
    return events;
}

} // namespace qb::http::sse

namespace qb::http {

// Context::begin_sse(): declared in routing/context.h, defined here, where sse::Stream is complete (Huly QB-86).
template <typename SessionType>
std::shared_ptr<sse::Stream<SessionType>>
Context<SessionType>::begin_sse() {
    return sse::begin(this->shared_from_this());
}

template <typename SessionType>
std::shared_ptr<sse::Stream<SessionType>>
Context<SessionType>::begin_sse(sse::Options const &options) {
    return sse::begin(this->shared_from_this(), options);
}

} // namespace qb::http

#endif // QB_MODULE_HTTP_SSE_H

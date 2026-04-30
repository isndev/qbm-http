/**
 * @file http/ws/coro.h
 * @brief Coroutine-first client for the qb::http::ws module.
 *
 * This header is the WebSocket equivalent of `qbm/http/coro.h`:
 *   - A coroutine-friendly client (`coro_client` / `coro_client_secure`)
 *     that exposes `co_await`-able entry points for every operation
 *     (`connect`, `receive`, `send`, `ping`, `close`).
 *   - Thin re-exports of the existing `http_awaiter<T>` machinery so users
 *     don't have to reach into `qb::http::async`.
 *   - A `qb::http::ws::run_sync(...)` alias over `qb::io::async::run_sync`
 *     for tests and `main()` code.
 *
 * Design notes
 * ------------
 *
 *  * The coroutine client inherits from the existing CRTP
 *    `qb::http::ws::WebSocket<Self, Transport>` base so we keep using the
 *    battle-tested protocol state machine. On top of that we stash:
 *    - a queue of inbound frames (`IncomingFrame`) delivered to successive
 *      `co_await receive()` calls;
 *    - at most one pending completion handler per operation (connect,
 *      receive, close) — if callers overlap awaiters on the same client,
 *      we fail fast rather than silently dropping the previous one.
 *
 *  * Like every qb coroutine adapter, resumption is routed through
 *    `qb::io::async::coro_scheduler()` so the listener thread that owns
 *    the socket is the one that runs the continuation. The mono-thread
 *    model is preserved end-to-end.
 *
 *  * The existing callback client (`qb::http::ws::Client`) remains
 *    supported without modification. Use whichever style suits the call
 *    site — the protocol machinery is shared.
 *
 * Basic usage
 * -----------
 *
 * @code
 * #include <http/ws/coro.h>
 *
 * qb::io::async::task<void> talk_to_echo() {
 *     qb::http::ws::coro_client ws;
 *     auto connected = co_await ws.connect("ws://localhost:9001/");
 *     if (!connected.ok) co_return;
 *
 *     qb::http::ws::MessageText msg; msg << "hello";
 *     ws << msg;
 *
 *     auto frame = co_await ws.receive();
 *     // frame.kind == Kind::Message
 *     // frame.payload == "hello"
 *     co_await ws.close_async();
 * }
 *
 * int main() {
 *     qb::io::async::init();
 *     qb::http::ws::run_sync(talk_to_echo());
 * }
 * @endcode
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * @ingroup WebSocket
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include <qb/io/async/coroutine/scheduler.h>

#include "../coro.h"
#include "ws.h"

namespace qb::http::ws {

// -----------------------------------------------------------------------------
// Value types exchanged through the coroutine API
// -----------------------------------------------------------------------------

/**
 * @brief Outcome of `coro_client::connect`.
 *
 * `ok` is `true` iff both the TCP connection and the WebSocket handshake
 * succeeded. On failure, callers can inspect the transport log or bind
 * a `sending_http_request` callback before `connect()` to see the wire
 * data — the coroutine result stays intentionally small.
 */
struct ConnectResult {
    bool ok{false};
};

/**
 * @brief Variant-like value for any inbound event delivered through
 *        `coro_client::receive`.
 *
 * The lifetime of `payload` / `close_reason` is owned by the struct, so
 * callers can freely store it past the end of the `co_await` expression
 * — unlike the zero-copy pointers delivered to the classical CRTP
 * `on(message)` callbacks.
 */
struct IncomingFrame {
    enum class Kind : std::uint8_t {
        Message,      ///< Text or binary data frame.
        Ping,         ///< Incoming ping (pong is auto-sent by the protocol layer).
        Pong,         ///< Incoming pong (response to a locally-sent ping).
        Close,        ///< Peer requested connection close (payload is reason).
        Disconnected  ///< Transport went away before a frame arrived.
    };

    Kind          kind{Kind::Disconnected};
    std::string   payload{};       ///< Owning copy of the frame payload.
    bool          is_text{false};  ///< True when `kind == Message` and type is Text.
    std::uint16_t close_code{0};   ///< Parsed close code (only meaningful for `Close`).
    std::string   close_reason{};  ///< Human-readable close reason.
};

/**
 * @brief Outcome of `coro_client::close_async`.
 */
struct CloseResult {
    bool ok{true};
};

// -----------------------------------------------------------------------------
// Coroutine-first client
// -----------------------------------------------------------------------------

/**
 * @tparam Transport Either `qb::io::transport::tcp` (ws://) or
 *                   `qb::io::transport::stcp` (wss://).
 *
 * Internally uses `qb::http::ws::WebSocket<Self, Transport>` as the CRTP base
 * so all framing / RFC compliance logic is shared with the callback client.
 */
template <typename Transport = ::qb::io::transport::tcp>
class coro_client
    : public WebSocket<coro_client<Transport>, Transport> {
    using base = WebSocket<coro_client<Transport>, Transport>;

public:
    using typename base::connected;
    using typename base::disconnected;
    using typename base::error;
    using typename base::message;
    using typename base::ping;
    using typename base::pong;
    using typename base::closed;
    using typename base::timeout;

private:
    using connect_complete_fn = std::function<void(ConnectResult &&)>;
    using frame_complete_fn   = std::function<void(IncomingFrame &&)>;
    using close_complete_fn   = std::function<void(CloseResult &&)>;

    std::deque<IncomingFrame> _pending_frames;
    connect_complete_fn       _connect_complete;
    frame_complete_fn         _frame_complete;
    close_complete_fn         _close_complete;
    bool                      _disconnected{false};
    bool                      _close_sent{false};

    // Bound when the caller asks for a per-operation receive cap, so that
    // unread frames cannot grow without bound if the consumer is slow.
    std::size_t _pending_cap{1024};

    // ---------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------

    static IncomingFrame
    make_message_frame(message const &event) {
        IncomingFrame frame;
        frame.kind    = IncomingFrame::Kind::Message;
        frame.payload.assign(event.data, event.size);
        frame.is_text = ((event.ws.fin_rsv_opcode & 0x0F) == opcode::_Text);
        return frame;
    }

    static IncomingFrame
    make_control_frame(IncomingFrame::Kind kind,
                       std::size_t         size,
                       char const         *data) {
        IncomingFrame frame;
        frame.kind = kind;
        frame.payload.assign(data, size);
        return frame;
    }

    static IncomingFrame
    make_close_frame(std::size_t size, char const *data) {
        IncomingFrame frame;
        frame.kind = IncomingFrame::Kind::Close;
        if (size >= 2u) {
            const auto hi     = static_cast<std::uint8_t>(data[0]);
            const auto lo     = static_cast<std::uint8_t>(data[1]);
            frame.close_code  = static_cast<std::uint16_t>((hi << 8) | lo);
            frame.close_reason.assign(data + 2, size - 2);
        }
        return frame;
    }

    void
    deliver_frame(IncomingFrame &&frame) {
        if (_frame_complete) {
            auto cb = std::exchange(_frame_complete, {});
            cb(std::move(frame));
            return;
        }
        if (_pending_cap == 0u) {
            return; // Buffering explicitly disabled.
        }
        if (_pending_frames.size() >= _pending_cap) {
            // Drop the oldest frame rather than the newest — callers who
            // fall behind typically care more about the tail of the stream
            // (close frames, latest state update) than the head.
            _pending_frames.pop_front();
        }
        _pending_frames.push_back(std::move(frame));
    }

    template <typename Complete>
    void
    install_connect_complete(Complete &&cb) {
        if (_connect_complete) {
            // The previous awaiter was never resumed; tear it down with an
            // `ok=false` so the coroutine can unwind safely before we replace
            // it. This should never happen in normal code paths.
            auto prev = std::exchange(_connect_complete, {});
            prev(ConnectResult{false});
        }
        _connect_complete = std::forward<Complete>(cb);
    }

    template <typename Complete>
    void
    install_frame_complete(Complete &&cb) {
        if (_frame_complete) {
            throw std::logic_error(
                "qb::http::ws::coro_client::receive(): another awaiter is "
                "already waiting for a frame on this client");
        }
        _frame_complete = std::forward<Complete>(cb);
    }

public:
    coro_client()  = default;
    ~coro_client() = default;

    coro_client(coro_client const &)            = delete;
    coro_client &operator=(coro_client const &) = delete;
    coro_client(coro_client &&)                 = delete;
    coro_client &operator=(coro_client &&)      = delete;

    /**
     * @brief Override the maximum number of buffered inbound frames.
     *
     * Default is 1024. When the cap is hit, the oldest buffered frame is
     * dropped to make room for the new one. Setting the cap to 0 disables
     * buffering entirely — any frame received while no awaiter is parked
     * is then discarded.
     */
    void
    set_pending_cap(std::size_t cap) noexcept {
        _pending_cap = cap;
    }

    // ---------------------------------------------------------------------
    // CRTP callbacks (wired automatically by `WebSocket<Self, Transport>`)
    // ---------------------------------------------------------------------

    void
    on(connected &&) {
        if (_connect_complete) {
            auto cb = std::exchange(_connect_complete, {});
            cb(ConnectResult{true});
        }
    }

    void
    on(error &&) {
        _disconnected = true;
        if (_connect_complete) {
            auto cb = std::exchange(_connect_complete, {});
            cb(ConnectResult{false});
        }
        if (_frame_complete) {
            IncomingFrame frame;
            frame.kind = IncomingFrame::Kind::Disconnected;
            auto cb    = std::exchange(_frame_complete, {});
            cb(std::move(frame));
        }
        if (_close_complete) {
            auto cb = std::exchange(_close_complete, {});
            cb(CloseResult{false});
        }
    }

    void
    on(message &&event) {
        deliver_frame(make_message_frame(event));
    }

    void
    on(ping &&event) {
        deliver_frame(make_control_frame(IncomingFrame::Kind::Ping,
                                         event.size,
                                         event.data));
    }

    void
    on(pong &&event) {
        deliver_frame(make_control_frame(IncomingFrame::Kind::Pong,
                                         event.size,
                                         event.data));
    }

    void
    on(closed &&event) {
        if (!_close_sent) {
            ::qb::http::ws::Message echo = event.ws;
            _close_sent = true;
            *this << echo;
        }
        deliver_frame(make_close_frame(event.size, event.data));
        if (_close_complete) {
            auto cb = std::exchange(_close_complete, {});
            cb(CloseResult{true});
        }
    }

    void
    on(disconnected &&) {
        _disconnected = true;
        _close_sent = false;
        // Fire pending completions with a failure so coroutines don't hang
        // when the transport is yanked from under them. `coro_client` is a
        // leaf type: no further forwarding to the base's CRTP `on()` is
        // needed — doing so would recurse back into this override.
        if (_connect_complete) {
            auto cb = std::exchange(_connect_complete, {});
            cb(ConnectResult{false});
        }
        if (_frame_complete) {
            IncomingFrame frame;
            frame.kind = IncomingFrame::Kind::Disconnected;
            auto cb    = std::exchange(_frame_complete, {});
            cb(std::move(frame));
        }
        if (_close_complete) {
            auto cb = std::exchange(_close_complete, {});
            cb(CloseResult{true});
        }
    }

    // The `timeout` CRTP hook is already implemented by the base and sends
    // an automatic ping; nothing to do at this layer.

    // ---------------------------------------------------------------------
    // Coroutine entry points
    // ---------------------------------------------------------------------

    /**
     * @brief Suspend until the TCP connection + WebSocket handshake complete.
     *
     * @code
     * auto res = co_await ws.connect("ws://localhost:9001/");
     * if (!res.ok) { ... }
     * @endcode
     */
    [[nodiscard]] auto
    connect(::qb::io::uri const &remote,
            std::chrono::milliseconds timeout = std::chrono::milliseconds{0}) {
        return qb::http::async::make_awaiter<ConnectResult>(
            [this, remote, timeout](auto complete) {
                if (_frame_complete) {
                    IncomingFrame frame;
                    frame.kind = IncomingFrame::Kind::Disconnected;
                    auto cb = std::exchange(_frame_complete, {});
                    cb(std::move(frame));
                }
                if (_close_complete) {
                    auto cb = std::exchange(_close_complete, {});
                    cb(CloseResult{false});
                }
                _pending_frames.clear();
                _disconnected = false;
                _close_sent = false;
                install_connect_complete(std::move(complete));
                base::connect(remote, static_cast<int>(timeout.count()));
            });
    }

    /**
     * @brief Overload that accepts a stringish URI for terseness in tests.
     */
    [[nodiscard]] auto
    connect(std::string_view remote_uri,
            std::chrono::milliseconds timeout = std::chrono::milliseconds{0}) {
        return connect(::qb::io::uri(std::string(remote_uri)), timeout);
    }

    /**
     * @brief Suspend until the next inbound frame (message / ping / pong
     *        / close / disconnection) is available.
     *
     * Subsequent calls return successive frames in delivery order; if frames
     * arrive while no coroutine is parked on `receive()`, they are buffered
     * up to the cap configured via `set_pending_cap()`.
     *
     * @throws std::logic_error if another coroutine is already suspended on
     *         this client's `receive()` (one consumer at a time).
     */
    [[nodiscard]] auto
    receive() {
        return qb::http::async::make_awaiter<IncomingFrame>(
            [this](auto complete) {
                if (!_pending_frames.empty()) {
                    auto frame = std::move(_pending_frames.front());
                    _pending_frames.pop_front();
                    complete(std::move(frame));
                    return;
                }
                if (_disconnected) {
                    IncomingFrame frame;
                    frame.kind = IncomingFrame::Kind::Disconnected;
                    complete(std::move(frame));
                    return;
                }
                install_frame_complete(std::move(complete));
            });
    }

    /**
     * @brief Queue a Close frame and suspend until the close handshake
     *        completes (peer echo or transport drop).
     *
     * The underlying TCP disconnection is **not** forced here — callers that
     * want a hard tear-down after the close should invoke `disconnect()`.
     *
     * @throws std::invalid_argument if @p status is a reserved close code.
     */
    [[nodiscard]] auto
    close_async(CloseStatus      status = CloseStatus::Normal,
                std::string_view reason = "closed normally") {
        return qb::http::async::make_awaiter<CloseResult>(
            [this, status, reason = std::string(reason)](auto complete) {
                if (_close_complete) {
                    throw std::logic_error(
                        "qb::http::ws::coro_client::close_async(): another "
                        "close awaiter is already pending");
                }
                if (_disconnected) {
                    complete(CloseResult{true});
                    return;
                }
                _close_sent = true;
                _close_complete = std::move(complete);
                MessageClose msg(status, reason);
                *this << msg;
            });
    }
};

/// wss:// coroutine client — TLS by default.
using coro_client_secure = coro_client<::qb::io::transport::stcp>;

// -----------------------------------------------------------------------------
// `run_sync` re-export
// -----------------------------------------------------------------------------

/**
 * @brief Drive a WebSocket-related awaitable to completion on the current
 *        I/O thread.
 *
 * Identical semantics to `qb::http::run_sync` / `qb::io::async::run_sync`
 * — lives here so that code that has already included `<http/ws/coro.h>`
 * can call `qb::http::ws::run_sync(...)` without reaching into another
 * namespace.
 */
template <typename Awaitable>
auto
run_sync(Awaitable &&awaitable)
    -> decltype(qb::io::async::run_sync(std::forward<Awaitable>(awaitable))) {
    return qb::io::async::run_sync(std::forward<Awaitable>(awaitable));
}

// -----------------------------------------------------------------------------
// Server-side coroutine session (CRTP base)
// -----------------------------------------------------------------------------

/**
 * @brief CRTP base for server-side WebSocket sessions expressed as a
 *        coroutine.
 *
 * `coro_session<Self, Server>` is the server-side mirror of
 * `coro_client`: instead of driving the session with a collection of
 * CRTP `on(...)` callbacks, users write the whole conversation as a
 * single coroutine method:
 *
 * @code
 * class ChatSession
 *     : public qb::http::ws::coro_session<ChatSession, ChatServer> {
 * public:
 *     using qb::http::ws::coro_session<ChatSession, ChatServer>::coro_session;
 *
 *     qb::io::async::task<void> run() {
 *         while (true) {
 *             auto frame = co_await this->next_frame();
 *             if (frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected ||
 *                 frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
 *                 co_return;
 *             }
 *             if (frame.kind == qb::http::ws::IncomingFrame::Kind::Message) {
 *                 qb::http::ws::MessageText out;
 *                 out << frame.payload;
 *                 *this << out;
 *             }
 *         }
 *     }
 * };
 * @endcode
 *
 * Contract / safety:
 *   - The `Self` type **must** define `task<void> run()`; the base spawns
 *     it once, as soon as the HTTP upgrade succeeds.
 *   - The base keeps the session alive for the entire life of the
 *     coroutine by capturing its `shared_ptr` from the io_handler — so
 *     `*this` is always valid at every suspension point. Consequence:
 *     the coroutine **must** eventually return (typically on a
 *     `Disconnected`/`Close` frame) or the session will leak.
 *   - Incoming frames arrive through `next_frame()`; if the caller is
 *     slower than the peer, frames queue up to `set_pending_cap()` (1024
 *     by default). Beyond that, the oldest frame is dropped.
 *   - Closing is symmetric to `coro_client::close_async`:
 *     `co_await close_async(status, reason)` queues a Close frame and
 *     resumes once the peer has echoed (or the transport drops).
 *   - Subprotocol / handshake customisation is optional: call
 *     `set_handshake_hook(...)` **before** `start()` to mutate the
 *     response or reject the upgrade.
 *
 * @tparam Self   The concrete session type (CRTP).
 * @tparam Server The owning io_handler type (parent server).
 */
namespace detail {
template <typename Self, typename Server>
using coro_session_base_t =
    typename qb::io::use<Self>::tcp::template client<Server>;
} // namespace detail

template <typename Self, typename Server>
class coro_session : public detail::coro_session_base_t<Self, Server> {
    using base_client_t = detail::coro_session_base_t<Self, Server>;
    using Self_t        = coro_session<Self, Server>;

public:
    /// HTTP protocol (auto-installed at construction via the CRTP base).
    /// Resolved against `coro_session<Self, Server>` (not `Self`) so the
    /// alias can be instantiated while the user's derived type is still
    /// incomplete. The base's `has_server == true` routes requests to the
    /// server variant.
    using Protocol    = qb::http::protocol<Self_t>;
    /// WebSocket protocol (installed on successful upgrade).
    using WS_Protocol = qb::http::ws::protocol<Self_t>;

    /**
     * @brief Handshake customisation hook.
     *
     * Invoked once, before the upgrade is accepted. Mutate `response` to
     * negotiate a subprotocol (`Sec-WebSocket-Protocol`) or extra headers.
     * Return `false` to refuse the upgrade — in that case, set
     * `response.status()` to a non-success code and the base will send it
     * as-is before dropping the connection.
     */
    using HandshakeHook = std::function<bool(Self &             session,
                                             qb::http::Request  &request,
                                             qb::http::Response &response)>;

private:
    std::deque<IncomingFrame>            _pending_frames;
    std::function<void(IncomingFrame &&)> _frame_complete;
    std::function<void(CloseResult &&)>   _close_complete;
    std::size_t                           _pending_cap{1024};
    HandshakeHook                         _handshake_hook;
    bool                                  _upgraded{false};
    bool                                  _run_spawned{false};
    bool                                  _disconnected{false};
    bool                                  _close_sent{false};

    Self &
    self() noexcept {
        return *static_cast<Self *>(this);
    }

    void
    deliver_frame(IncomingFrame &&frame) {
        if (_frame_complete) {
            auto cb = std::exchange(_frame_complete, {});
            cb(std::move(frame));
            return;
        }
        if (_pending_cap == 0u) {
            return; // Buffering disabled: frames arriving with no awaiter
                    // parked are silently discarded.
        }
        if (_pending_frames.size() >= _pending_cap) {
            _pending_frames.pop_front();
        }
        _pending_frames.push_back(std::move(frame));
    }

    void
    spawn_run_loop() {
        if (_run_spawned)
            return;
        _run_spawned = true;

        // Capture a shared_ptr to `Self` so the session outlives every
        // suspension point inside `run()`. We intentionally look up the
        // session on the owning io_handler: the derived class is already
        // registered at this point (the base `client(_Server&)` constructor
        // has returned and `registerSession` stored the shared_ptr).
        std::shared_ptr<Self> self_sp = this->_server.session(this->id());
        if (!self_sp) {
            // Should never happen: the base client stores us in the
            // server's registry before the first event ever dispatches.
            // Fall through silently — the upgrade has already happened
            // and `on(disconnected)` will still fire when the TCP stream
            // ends.
            return;
        }

        qb::io::async::coro_scheduler().spawn(
            [self_sp]() mutable -> qb::io::async::task<void> {
                try {
                    co_await self_sp->run();
                } catch (const std::exception &) {
                    // Best-effort orderly shutdown on uncaught exceptions:
                    // notify the peer with a 1011 Close and drop the TCP
                    // stream. We swallow any secondary failure because the
                    // transport may already be gone.
                    try {
                        MessageClose msg(CloseStatus::UnexpectedReason,
                                         "internal server error");
                        *self_sp << msg;
                    } catch (...) {
                    }
                    self_sp->disconnect();
                } catch (...) {
                    try {
                        MessageClose msg(CloseStatus::UnexpectedReason,
                                         "internal server error");
                        *self_sp << msg;
                    } catch (...) {
                    }
                    self_sp->disconnect();
                }
                co_return;
            });
    }

public:
    using base_client_t::base_client_t;

    // --- Configuration ------------------------------------------------------

    /**
     * @brief Change the maximum number of inbound frames buffered between
     *        two `next_frame()` calls. Default is 1024; set to 0 to
     *        disable buffering (frames with no awaiter are dropped).
     */
    void
    set_pending_cap(std::size_t cap) noexcept {
        _pending_cap = cap;
    }

    /**
     * @brief Install a handshake customisation hook.
     *
     * The hook fires once, on the upgrade request, before the `101`
     * response is sent. Use it to negotiate a subprotocol (add
     * `Sec-WebSocket-Protocol` to the response) or to reject the upgrade
     * with a custom status code.
     */
    void
    set_handshake_hook(HandshakeHook hook) {
        _handshake_hook = std::move(hook);
    }

    // --- CRTP HTTP upgrade handler -----------------------------------------

    void
    on(typename Protocol::request &&event) {
        qb::http::Response response;
        (void) accept_upgrade(event, response);
    }

    /**
     * @brief Finalise the WebSocket handshake for an already-parsed HTTP
     *        upgrade request.
     *
     * Calling this method is the single integration point between an
     * external HTTP router (which has already parsed `request`) and the
     * coroutine-driven session: it applies the handshake hook, runs
     * `switch_protocol<WS_Protocol>`, sends the resulting response, and
     * spawns `run()`.
     *
     * @param request   The parsed HTTP upgrade request. Headers
     *                  (`Sec-WebSocket-Key`, `Connection`, `Upgrade`,
     *                  `Sec-WebSocket-Version`) must be set by the caller
     *                  — this helper performs no rewriting.
     * @param response  Scratch response object; will be populated either
     *                  by the hook (on reject) or by `switch_protocol`
     *                  (on accept). Safe to pass a freshly constructed
     *                  `qb::http::Response`.
     * @return `true` if the upgrade succeeded, `false` if the hook
     *         refused or if `switch_protocol` rejected the request — in
     *         both failure cases the transport is disconnected before
     *         this function returns.
     *
     * @note Intended to be called on the io_handler thread that owns the
     *       underlying transport (the same thread as `run()` / the
     *       event loop). Calling it from elsewhere violates the
     *       mono-thread invariant of `qb-io`.
     */
    bool
    accept_upgrade(qb::http::Request &request, qb::http::Response &response) {
        bool allowed = true;
        if (_handshake_hook) {
            try {
                allowed = _handshake_hook(self(), request, response);
            } catch (...) {
                allowed = false;
            }
        }
        if (!allowed) {
            if (static_cast<int>(response.status()) == 0) {
                response.status() = qb::http::status::BAD_REQUEST;
            }
            *this << response;
            this->close_after_deliver();
            return false;
        }

        if (!this->template switch_protocol<WS_Protocol>(self(), request,
                                                         response)) {
            // `switch_protocol` sets BAD_REQUEST on handshake failures; deliver
            // it before closing so clients get a concrete HTTP rejection.
            if (static_cast<int>(response.status()) == 0) {
                response.status() = qb::http::status::BAD_REQUEST;
            }
            *this << response;
            this->close_after_deliver();
            return false;
        }

        *this << response;
        _upgraded = true;
        spawn_run_loop();
        return true;
    }

    // --- CRTP WebSocket event handlers --------------------------------------

    void
    on(typename WS_Protocol::message &&event) {
        IncomingFrame frame;
        frame.kind = IncomingFrame::Kind::Message;
        frame.payload.assign(event.data, event.size);
        frame.is_text = ((event.ws.fin_rsv_opcode & 0x0Fu) == opcode::_Text);
        deliver_frame(std::move(frame));
    }

    void
    on(typename WS_Protocol::ping &&event) {
        // RFC 6455 §5.5.3 ("as soon as is practical") is already honoured
        // by the base framer: `ws_internal::base::processControlFrame`
        // unconditionally forwards a Pong with the same payload AFTER
        // dispatching this observer. Emitting another Pong here would
        // double-send. We merely surface the ping to any coroutine parked
        // on `next_frame()`.
        IncomingFrame frame;
        frame.kind = IncomingFrame::Kind::Ping;
        frame.payload.assign(event.data, event.size);
        deliver_frame(std::move(frame));
    }

    void
    on(typename WS_Protocol::pong &&event) {
        IncomingFrame frame;
        frame.kind = IncomingFrame::Kind::Pong;
        frame.payload.assign(event.data, event.size);
        deliver_frame(std::move(frame));
    }

    void
    on(typename WS_Protocol::close &&event) {
        // The base protocol stops parsing after this callback (`not_ok()`),
        // so we must echo the close frame ourselves to satisfy §5.5.1.
        IncomingFrame frame;
        frame.kind = IncomingFrame::Kind::Close;
        if (event.size >= 2u) {
            const auto hi = static_cast<std::uint8_t>(event.data[0]);
            const auto lo = static_cast<std::uint8_t>(event.data[1]);
            frame.close_code = static_cast<std::uint16_t>((hi << 8) | lo);
            frame.close_reason.assign(event.data + 2, event.size - 2);
        }

        // Echo only when the peer initiated the close. If we already sent a
        // close, this frame is the peer's echo and must not be echoed again.
        if (!_close_sent) {
            *this << event.ws;
            _close_sent = true;
        }

        deliver_frame(std::move(frame));

        if (_close_complete) {
            auto cb = std::exchange(_close_complete, {});
            cb(CloseResult{true});
        }
    }

    void
    on(qb::io::async::event::disconnected &&) {
        _disconnected = true;
        _close_sent = false;

        IncomingFrame frame;
        frame.kind = IncomingFrame::Kind::Disconnected;
        deliver_frame(std::move(frame));

        if (_close_complete) {
            auto cb = std::exchange(_close_complete, {});
            cb(CloseResult{true});
        }
    }

    // --- Coroutine entry points --------------------------------------------

    /**
     * @brief Suspend until the next inbound frame is available.
     *
     * Once the underlying transport has closed, every subsequent call
     * resolves synchronously with a `Disconnected` frame — the awaiter
     * never hangs on a dropped connection.
     *
     * @throws std::logic_error if another coroutine on the same session
     *         is already parked on `next_frame()`.
     */
    [[nodiscard]] auto
    next_frame() {
        return qb::http::async::make_awaiter<IncomingFrame>(
            [this](auto complete) {
                if (!_pending_frames.empty()) {
                    auto frame = std::move(_pending_frames.front());
                    _pending_frames.pop_front();
                    complete(std::move(frame));
                    return;
                }
                if (_disconnected) {
                    IncomingFrame frame;
                    frame.kind = IncomingFrame::Kind::Disconnected;
                    complete(std::move(frame));
                    return;
                }
                if (_frame_complete) {
                    throw std::logic_error(
                        "qb::http::ws::coro_session::next_frame(): another "
                        "awaiter is already suspended on this session");
                }
                _frame_complete = std::move(complete);
            });
    }

    /**
     * @brief Queue a Close frame and suspend until the peer echoes it
     *        (or the transport drops).
     *
     * @throws std::invalid_argument when @p status is a reserved code.
     */
    [[nodiscard]] auto
    close_async(CloseStatus      status = CloseStatus::Normal,
                std::string_view reason = "closed normally") {
        return qb::http::async::make_awaiter<CloseResult>(
            [this, status, reason = std::string(reason)](auto complete) {
                if (_close_complete) {
                    throw std::logic_error(
                        "qb::http::ws::coro_session::close_async(): another "
                        "close awaiter is already pending");
                }
                if (_disconnected) {
                    complete(CloseResult{true});
                    return;
                }
                _close_sent = true;
                _close_complete = std::move(complete);
                MessageClose msg(status, reason);
                *this << msg;
            });
    }
};

} // namespace qb::http::ws

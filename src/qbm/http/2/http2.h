/**
 * @file qbm/http/2/http2.h
 * @brief Main include file for the QB HTTP/2 client and server module.
 *
 * This header aggregates core components for HTTP/2 communication using SSL/TLS.
 * It defines classes for requests, responses, asynchronous client operations,
 * protocol handlers, and server-side logic, all within the qb::http2 namespace.
 *
 * ## Features:
 * - HTTP/2 client with multiplexing support
 * - HTTP/2 server with stream management
 * - SSL/TLS only (ALPN negotiation for "h2")
 * - Integration with qb I/O framework
 * - Asynchronous request/response handling
 *
 * ## Usage:
 * @code
 * // Server example
 * using MySession = qb::http2::use<MySession>::session<MyServer>;
 * using MyServer = qb::http2::use<MyServer>::server<MySession>;
 *
 * MyServer server;
 * server.router().GET("/hello", [](auto ctx) {
 *     ctx->response().body() = "Hello, HTTP/2!";
 *     ctx->send();
 * });
 * server.listen(443);
 * @endcode
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

// HTTP/2 here is TLS-only -- see the note in ./client.h, which this header pulls in. Guarding
// both, rather than only the one that names qb::io::transport::stcp, so that a direct
// #include of EITHER spelling self-diagnoses instead of failing inside a base-clause.
#ifndef QB_HAS_SSL
#error "HTTP/2 requires OpenSSL crypto library (qb::io::transport::stcp)"
#endif

#include <algorithm> // std::clamp, std::min: the sweep's period (Huly QB-1248)
#include <array>
#include <filesystem>
#include <limits>
#include <memory>   // the lifetime the session watches of a protocol it installs (Huly QB-1248)
#include <optional> // the sweep's timer (Huly QB-1248)
#include <qb/io/protocol/handshake.h>
#include <type_traits> // std::is_same_v: the inactivity timer's name (Huly QB-1248)
// Re-using HTTP/1.1 Request/Response structures as a base
#include "../1.1/http.h"
#include "../detail/drain.h"
// HTTP/2 protocol implementations
#include "./protocol/client.h"
#include "./protocol/server.h"
// HTTP/2 client implementation
#include "./client.h"

namespace qb::http2 {

// Constants for HTTP/2 session configuration
namespace constants {
constexpr uint32_t     HTTP11_STREAM_ID        = 0; ///< Stream ID used for HTTP/1.1 requests (not a valid HTTP/2 stream ID)
constexpr qb::duration DEFAULT_SESSION_TIMEOUT = std::chrono::seconds(60); ///< Default session timeout
constexpr uint32_t     MIN_VALID_STREAM_ID     = 1;                        ///< Minimum valid HTTP/2 stream ID (0 is reserved for HTTP/1.1)

// DDoS Protection constants
constexpr uint32_t DEFAULT_MAX_CONCURRENT_STREAMS = 50; ///< Default max concurrent streams per connection (reduced from 100 for security)
/// A response its peer has not taken -- DATA a window holds back, frames the socket has not taken -- is reset once
/// nothing of it left for this long.
constexpr qb::duration STREAM_IDLE_TIMEOUT = std::chrono::seconds(30);
/// A request not yet complete is reset once no octet of its body arrived for this long (the frames that bring none --
/// its header block's CONTINUATION frames, an empty DATA -- do not count).
constexpr qb::duration STREAM_INCOMPLETE_TIMEOUT = std::chrono::seconds(10);
/// The longest interval between two sweeps of a connection's streams, which the default bounds give; a session
/// timeout under them shortens it (session::stream_sweep_period()).
constexpr qb::duration CLEANUP_INTERVAL = std::chrono::seconds(5);
/// The shortest one: a session timeout of a few milliseconds does not make the sweep a timer that spins.
constexpr qb::duration STREAM_SWEEP_MIN_INTERVAL = std::chrono::milliseconds(50);
} // namespace constants

// Protocol type aliases for cleaner code
template <typename IO_Handler>
using client_protocol = qb::protocol::http2::ClientHttp2Protocol<IO_Handler>;

template <typename IO_Handler>
using server_protocol = qb::protocol::http2::ServerHttp2Protocol<IO_Handler>;

namespace internal {
// Forward declaration
template <typename Derived>
class Context;

/**
 * @brief HTTP/2 server session implementation
 *
 * Handles HTTP/2 connections with protocol negotiation, stream management,
 * and request routing. Supports both HTTP/1.1 and HTTP/2 via ALPN.
 *
 * @tparam Derived CRTP derived type
 * @tparam Handler Server handler type
 */
template <typename Derived, typename Handler>
class session
    : public qb::io::async::tcp::client<session<Derived, Handler>, qb::io::transport::stcp, Handler>
    , public qb::io::use<session<Derived, Handler>>::timeout
    , public std::enable_shared_from_this<Derived> {
public:
    using IoBase        = qb::io::async::tcp::client<session<Derived, Handler>, qb::io::transport::stcp, Handler>;
    using Http1Protocol = qb::protocol::http::server<session<Derived, Handler>>;
    using Http2Protocol = server_protocol<session<Derived, Handler>>;
    /// The session's inactivity timer (`setTimeout()`), named for qb-io: `io_handler::extractSession()` stops this one,
    /// so that a `use<S>::timeout` a session type keeps of its own is not taken for it -- that one was stopped, and this
    /// one left to time out a session held past its extraction (the fourteenth independent review of Huly QB-1248).
    using inactivity_timer_t = qb::io::async::with_timeout<session<Derived, Handler>>;

    /// Every frame the HTTP/2 protocol writes goes through here (`_io << frame`): the bytes the output ever took are
    /// counted, so that with `out().size()` the session knows what the socket has taken so far -- the mark a streamed
    /// response's DATA frame is measured against by its stall watch (Huly QB-1212). The HTTP/1.1 fallback's own writes
    /// name `io<session>::operator<<` and skip the count: ALPN fixes the protocol per connection, so a session that
    /// speaks HTTP/1.1 never runs the protocol the count is read for.
    template <typename T>
    session &
    operator<<(T &&data) {
        const auto before = this->out().size();
        IoBase::operator<<(std::forward<T>(data));
        if (const auto after = this->out().size(); after > before)
            _appended_total += after - before;
        return *this;
    }
    /// The bytes the output ever took, and the bytes the socket took of them.
    [[nodiscard]] std::uint64_t
    appended_total() const noexcept {
        return _appended_total;
    }
    [[nodiscard]] std::uint64_t
    drained_total() noexcept { // out() is not const in qb-io
        const auto queued = this->out().size();
        return _appended_total > queued ? _appended_total - queued : 0;
    }
    using ContextType = qb::http::Context<Derived>;
    using Router      = typename qb::http::Router<Derived>;

private:
    friend qb::io::async::io<session<Derived, Handler>>;
    friend struct has_method_on<session, void, qb::io::async::event::pending_write>;
    friend struct has_method_on<session, void, qb::io::async::event::eos>;
    friend struct has_method_on<session, void, qb::io::async::event::disconnected>;
    friend Http2Protocol;
    friend qb::io::async::with_timeout<session<Derived, Handler>>;

    qb::unordered_map<uint32_t, std::shared_ptr<ContextType>> _contexts; ///< Stream contexts
    /// The response streams begun on this connection (Huly QB-86), by stream id, weak: the producer owns each. A
    /// stream is told what its peer took (notify_drain) and when its stream or the connection ends (cancel).
    qb::unordered_map<uint32_t, std::weak_ptr<qb::http::ResponseStream<Derived>>> _streams;
    std::size_t _stream_high_watermark{qb::http::default_stream_high_watermark}; ///< stream_high_watermark()

    /// A protocol this session installs, with a lifetime the session can watch (Huly QB-1248): the weak half it keeps
    /// expires when the io destroys the object, so a protocol installed later at the same address -- by the application,
    /// once it cleared the session's -- is not taken for it. The session's pointers to its HTTP/1.1 and HTTP/2 protocols
    /// are never lowered, each also saying which protocol the connection negotiated; the TLS handshake's is, once the
    /// session replaced it.
    template <typename Protocol>
    struct watched final : Protocol {
        using Protocol::Protocol;
        std::shared_ptr<void> lifetime = std::make_shared<char>();
    };

    Http1Protocol *_http1_protocol;     ///< HTTP/1.1 protocol handler
    Http2Protocol *_http2_protocol;     ///< HTTP/2 protocol handler
    std::uint64_t  _appended_total = 0; ///< the bytes the output ever took (operator<<): the socket's drain mark (Huly QB-1212)

    /// The stream sweep's timer (Huly QB-1248): a `with_timeout` the session owns from its first HTTP/2 stream, armed
    /// while the connection has streams and left to lapse when it has none -- an idle connection has no tick. Its tick
    /// is the session's (on_stream_sweep_tick()); the object lives as long as the session, stopped by connection_left().
    struct StreamSweep final : qb::io::async::with_timeout<StreamSweep> {
        session *owner;
        explicit StreamSweep(session *session_) // may throw: the loop registers the timer (arm_stream_sweep() catches)
            : qb::io::async::with_timeout<StreamSweep>(qb::duration::zero())
            , owner(session_) {}
        void
        on(qb::io::async::event::timer const &) {
            owner->on_stream_sweep_tick();
        }
    };
    std::optional<StreamSweep> _stream_sweep;
    bool                       _stream_sweep_armed{false}; ///< A tick is due

    /// The bound of the drain's last delivery (http2_abort_drain(), Huly QB-91): a one-shot timer of its own, the kind
    /// the drain's deadline is, which nothing restarts. The session's inactivity timeout restarts at every write that
    /// leaves octets queued (on(pending_write)): set to the linger, as that delivery's bound was, it let a client whose
    /// reading made the server write within each linger keep the session, its contexts and its output for as long as
    /// it wished (the ninth independent review, Huly QB-1248). Alive from the drain's deadline; stopped by
    /// connection_left().
    std::unique_ptr<qb::http::detail::loop_timer> _drain_delivery;
    /// The connection ended, or left this session (connection_left()): its HTTP/2 protocol is no longer live to it.
    bool _connection_left{false};
    /// The lifetimes of the two protocols above (`watched`): expired once the object the pointer named is gone.
    std::weak_ptr<void> _http1_lifetime, _http2_lifetime;
    bool                _reclaiming_completed_contexts{false};
    /// The TLS handshake the session starts in: with HTTP/2 and the HTTP/1.1 fallback, the protocols an HTTP drain
    /// knows (http2_speaks_http()).
    qb::io::async::IProtocol const *_handshake_protocol{nullptr};
    bool                            _draining{false}; ///< The server drains (http2_begin_drain(), Huly QB-91)
    bool _client_goaway_logged{false};                ///< A NO_ERROR GOAWAY of the client was logged (on(Http2GoAwayEvent), Huly QB-1270)

    void
    reclaim_completed_stream_contexts() noexcept {
        if (_reclaiming_completed_contexts)
            return;
        _reclaiming_completed_contexts = true;
        struct ReclaimGuard {
            bool &active;
            ~ReclaimGuard() noexcept {
                active = false;
            }
        } guard{_reclaiming_completed_contexts};
        const auto pending_bytes = this->out().size();

        auto       remaining    = _contexts.size();
        const auto can_continue = [&]() noexcept {
            return live_http2_protocol() && this->is_connected() && this->out().size() == pending_bytes;
        };

        // IDs carry no ownership or iterators across callbacks. The stack
        // buffer is a batch size, not a limit on the context registry.
        std::array<uint32_t, 32> ids;
        while (remaining != 0) {
            if (!can_continue())
                break;
            std::size_t count = 0;
            {
                for (auto it = _contexts.begin(); it != _contexts.end(); ++it) {
                    if (it->second && it->second->is_completed() && _http2_protocol->is_stream_closed(it->first)) {
                        ids[count++] = it->first;
                        if (count == ids.size() || count == remaining)
                            break;
                    }
                }
            }
            if (count == 0)
                break;
            for (std::size_t index = 0; index != count && remaining != 0; ++index) {
                if (!can_continue())
                    return;
                std::shared_ptr<ContextType> context;
                {
                    auto it = _contexts.find(ids[index]);
                    if (it == _contexts.end() || !it->second || !it->second->is_completed() || !_http2_protocol->is_stream_closed(it->first))
                        continue;
                    context = std::move(it->second);
                    _contexts.erase(it);
                }
                --remaining;
                context->execute_hook(qb::http::HookPoint::POST_RESPONSE_SEND);
                // REQUEST_COMPLETE and member destructors can change other
                // entries too. Finish this release before the next ID.
                context.reset();
            }
            // Catch eligibility created without new output by any callback or
            // destructor. Only actual removals spend the initial entry budget.
        }
    }

    /// A response stream's peer is gone -- its stream reset or closed, the connection ended (Huly QB-86): its producer
    /// is told before its context is cancelled, as the HTTP/1.1 session tells one on disconnect, so the cancellation
    /// of the context resets nothing (the stream is cancelled already). The entry goes.
    void
    cancel_stream(uint32_t stream_id) noexcept {
        auto it = _streams.find(stream_id);
        if (it == _streams.end())
            return;
        if (auto stream = it->second.lock())
            stream->cancel();
        _streams.erase(it);
    }

    /// Every response stream of this connection is cancelled (disconnect, extraction, destruction).
    void
    cancel_all_streams() noexcept {
        for (auto &[stream_id, weak] : _streams) {
            if (auto stream = weak.lock())
                stream->cancel();
        }
        _streams.clear();
    }

    /// The socket took some of the output (`pending_write`, or `eos` with 0): every live response stream reads what
    /// its peer has not taken -- the socket's remainder and the pieces its windows hold back -- and a producer parked
    /// on `drain()` under the low mark is resumed, at the end of the turn; a stream gone with its producer is forgotten.
    /// The HTTP/2 protocol while the io still runs it, else null: a hook may clear the protocols under a drain (the
    /// drain's POST hook, as its test does) and the io's own disconnect clears them too, leaving `_http2_protocol` a
    /// freed object -- a later write pass or end of stream must not read it (ASan under QB-86's `notify_streams(0)`,
    /// found in QB-1212's lot).
    /// `_http2_protocol` is never lowered -- it also says the connection negotiated HTTP/2 --, so the object's own
    /// lifetime is read first: a protocol the application installs later at the address of the one it cleared is not it.
    /// Nor is the protocol live once the connection left the session: an extraction leaves it installed, and the
    /// session "connected" -- a reset, a response or a sweep then acted on streams whose connection another owner has,
    /// and wrote into an output nothing drains (the third and fourth independent reviews, Huly QB-1248).
    [[nodiscard]] Http2Protocol *
    live_http2_protocol() const noexcept {
        if (_connection_left || !_http2_protocol || _http2_lifetime.expired())
            return nullptr;
        return this->protocol() == _http2_protocol ? _http2_protocol : nullptr;
    }
    /// The same for the HTTP/1.1 fallback's.
    [[nodiscard]] Http1Protocol *
    live_http1_protocol() const noexcept {
        return _http1_protocol && !_http1_lifetime.expired() && this->protocol() == _http1_protocol ? _http1_protocol : nullptr;
    }

    void
    notify_streams(std::size_t socket_pending) noexcept {
        // The pieces the socket's write cap held back leave first -- before the map is consulted: stream_end() forgets
        // its stream before the flush that may stop for room, so the map can be empty while a tail still waits.
        if (auto *const waiting = live_http2_protocol(); waiting && waiting->streams_wait_for_socket())
            waiting->resume_streamed_responses();
        if (_streams.empty())
            return;
        // Read again: the resume can refuse a trailer section and reset its stream, whose observer cancels a context,
        // and a hook of that context may clear the protocols (the caller's pass keeps them alive, not current).
        auto *const protocol = live_http2_protocol();
        for (auto it = _streams.begin(); it != _streams.end();) {
            if (auto stream = it->second.lock()) {
                stream->notify_drain(socket_pending + (protocol ? protocol->streamed_body_pending(it->first) : 0));
                ++it;
            } else {
                it = _streams.erase(it);
            }
        }
    }

    /// How often the streams are swept: half the smallest of the sweep's three bounds -- so each is met within the
    /// smallest's length of its expiry --, `CLEANUP_INTERVAL` at most (what the default bounds give) and
    /// `STREAM_SWEEP_MIN_INTERVAL` at least (a bound under twice that floor is met within two floors). Read at every
    /// arming: a session timeout changed since is followed.
    [[nodiscard]] qb::duration
    stream_sweep_period() const noexcept {
        auto smallest = std::min<qb::duration>(constants::STREAM_IDLE_TIMEOUT, constants::STREAM_INCOMPLETE_TIMEOUT);
        if (const auto unanswered = this->getTimeout(); unanswered > qb::duration::zero())
            smallest = std::min<qb::duration>(smallest, unanswered);
        return std::clamp<qb::duration>(smallest / 2, constants::STREAM_SWEEP_MIN_INTERVAL, constants::CLEANUP_INTERVAL);
    }

    /// A stream opened: the sweep's tick is due, unless one already is. Without a timer -- the loop could not register
    /// it -- the streams are not swept, and the session's own timeout is the connection's only bound, as it was for a
    /// connection that never wrote.
    void
    arm_stream_sweep() noexcept {
        if (_stream_sweep_armed)
            return;
        if (!_stream_sweep) {
            try {
                _stream_sweep.emplace(this);
            } catch (...) {
                return;
            }
        }
        _stream_sweep_armed = true;
        _stream_sweep->setTimeout(stream_sweep_period());
    }

    /// The connection ended, or left this session (an extraction): its HTTP/2 protocol is no longer live to it
    /// (live_http2_protocol()) -- no reset, no response and no sweep goes through it, and the tick under which a hook
    /// extracted the session arms no other -- and no tick is due any more, the sweep's nor the bound of the drain's
    /// last delivery. The timer objects stay (a tick may be what runs this).
    void
    connection_left() noexcept {
        _connection_left    = true;
        _stream_sweep_armed = false;
        if (_stream_sweep)
            _stream_sweep->setTimeout(qb::duration::zero());
        if (_drain_delivery)
            _drain_delivery->stop();
    }

    /// Ends the session for @p reason -- unless something ended it first: it keeps the reason it ended with. qb-io's
    /// disconnect() updates the reason at each call; a session ended in a pass of the loop is released a dispatch
    /// later -- after the timers of that pass when the poll had made its watcher pending (output queued, or input
    /// arrived), before them otherwise -- and, held by a capture after its release, still takes the ticks of its
    /// timers: a later disconnection reported its reason over the cause (the eleventh to thirteenth independent
    /// reviews, Huly QB-1248). Every disconnection of the session's own goes through here.
    void
    end_session(qb::http::DisconnectedReason reason) noexcept {
        if (this->is_connected())
            this->disconnect(reason);
    }

    /// The drain's last delivery reached its bound (http2_abort_drain()). Delivered, the session is in qb-io's
    /// lingering close, which has its own bound and ends by itself: cutting it here would close a socket whose peer may
    /// not have read what was just delivered. Not delivered, it is aborted with what is left of its output.
    void
    on_drain_delivery_bound() noexcept {
        if (!this->lingering())
            end_session(qb::http::DisconnectedReason::ServerDraining);
    }

    /**
     * @brief The sweep's tick (Huly QB-1248): the streams are swept (http2_sweep_streams()), and the next tick is armed
     *        while streams remain. The session holds itself for the tick: a context the sweep's reset cancels may drop
     *        the server's reference.
     */
    void
    on_stream_sweep_tick() noexcept {
        _stream_sweep_armed  = false;
        const auto  self     = static_cast<Derived &>(*this).weak_from_this().lock();
        auto *const protocol = live_http2_protocol();
        if (!protocol)
            return;
        (void) http2_sweep_streams(std::chrono::steady_clock::now());
        if (live_http2_protocol() == protocol && protocol->has_streams() && this->is_connected())
            arm_stream_sweep();
    }

    // A neutral peer reset is a lifecycle notification, not a stream error.
    // The protocol opts in through this private hook without extending the
    // public error-event contract of custom IO handlers.
    void
    on_peer_stream_reset(uint32_t stream_id) noexcept {
        cancel_stream(stream_id); // a streamed response ends with its stream (Huly QB-86)
        auto it = _contexts.find(stream_id);
        if (it == _contexts.end())
            return;
        auto context = std::move(it->second);
        _contexts.erase(it);
        if (context)
            context->cancel("HTTP/2 reset");
    }

    /**
     * @brief Validate HTTP/2 stream ID
     * @param stream_id Stream ID to validate
     * @return true if stream_id is valid for HTTP/2 (not 0)
     */
    [[nodiscard]] static constexpr bool
    is_valid_http2_stream_id(uint32_t stream_id) noexcept {
        return stream_id != constants::HTTP11_STREAM_ID;
    }

    /**
     * @brief Validate response before sending
     * @param res Response to validate
     * @return true if response is valid
     */
    [[nodiscard]] bool
    validate_response(const qb::http::Response &res) const noexcept {
        // Basic validation - can be extended
        // Use code() method to get the integer status code
        const auto status_code = res.status().code();
        return status_code >= 100 && status_code < 600; // Valid HTTP status code range
    }

public:
    using handler_type = Handler;

    session() = delete;

    /**
     * @brief Construct server session
     * @param server_handler Server handler reference
     */
    explicit session(Handler &server_handler)
        : qb::io::async::tcp::client<session<Derived, Handler>, qb::io::transport::stcp, Handler>(server_handler)
        , _http1_protocol(nullptr)
        , _http2_protocol(nullptr) {
        // The name qb-io reads for the timer an extraction stops is this session's (inactivity_timer_t): a session type
        // that declared one of its own hid it, and the extraction stopped another timer (the fifteenth independent
        // review of Huly QB-1248).
        static_assert(std::is_same_v<typename Derived::inactivity_timer_t, inactivity_timer_t>,
                      "inactivity_timer_t is the HTTP session's name for its inactivity timer: a session type cannot declare "
                      "one of its own");
        LOG_HTTP_DEBUG_PA(this->id(), "HTTP/2 internal::session (server-side) created.");
        _handshake_protocol = this->template switch_protocol<qb::io::protocol::handshake<session<Derived, Handler>>>(*this);
        this->setTimeout(constants::DEFAULT_SESSION_TIMEOUT);
        // Both protocols this session runs bound their messages themselves -- HTTP/2 frames by the frame
        // size it advertises, the HTTP/1.1 fallback by its header limits and the server's body cap -- and
        // answer a breach; the transport's generic message cap (QB_MAX_MESSAGE_SIZE) would cut an HTTP/1.1
        // request the server accepts with no answer (Huly QB-168).
        this->set_max_message_size(std::numeric_limits<std::size_t>::max());
    }

    ~session() {
        cancel_all_streams(); // a server destroyed under a live stream releases its producer (Huly QB-86)
        LOG_HTTP_DEBUG_PA(this->id(), "HTTP/2 internal::session (server-side) destroyed.");
    }

    using qb::io::async::io<session<Derived, Handler>>::operator<<;

    [[nodiscard]] bool
    reset_stream(uint32_t stream_id, qb::protocol::http2::ErrorCode error_code = qb::protocol::http2::ErrorCode::CANCEL,
                 const std::string &reason = {}) {
        auto *const protocol = live_http2_protocol();
        if (!protocol || !is_valid_http2_stream_id(stream_id)) {
            return false;
        }
        {
            // The reset's observer cancels the stream's context, and a hook of it may clear the protocols: called from
            // outside the read dispatch -- a timer, a coroutine resumed later --, the protocol would be destroyed
            // under its own function (Huly QB-1248; qb's protocol_pass()).
            const auto pass = this->protocol_pass();
            protocol->send_rst_stream(stream_id, error_code, reason);
        }
        this->ready_to_write();
        this->updateTimeout();
        return true;
    }

    /**
     * @brief Sweep this connection's HTTP/2 streams at @p now (Huly QB-1248): the streams that made no progress for the
     *        bound of their turn are reset, `RST_STREAM(CANCEL)` -- a request not complete (`STREAM_INCOMPLETE_TIMEOUT`),
     *        a response its peer has not taken (`STREAM_IDLE_TIMEOUT`), a request its handler has not answered within
     *        this session's own inactivity timeout as it is now (none when the session has none): a timeout lowered
     *        at run time holds at the next sweep for the requests in progress, on each one's own clock. And a header
     *        block the server refused that its client leaves open ends the connection once it has stayed so for
     *        `STREAM_INCOMPLETE_TIMEOUT` past the sweep that first saw it: the protocol sends
     *        `GOAWAY(ENHANCE_YOUR_CALM)`, and the session is released at once, as for any error it ends a connection
     *        with -- from this timer, outside the read dispatch, the frame is dropped with it (on(Http2GoAwayEvent)).
     *
     * What the session's own timer runs, every half of the smallest bound while the connection has streams or such a
     * block (the protocol's `has_streams()`; `http2_refused_block_open()` arms it for a block) -- that timer goes on
     * whoever else calls this. Public for a test, which steps @p now, and for an application that wants
     * a sweep before the next tick. The io's `protocol_pass()` is held over the sweep: the reset's observer cancels a
     * context, and a hook of that context may clear the protocols, which under the pass are retired and end with it,
     * after the sweep has returned. Until 3.4 the sweep ran from `on(pending_write)` alone: a connection that only
     * read, or whose writes always drained, was never swept, and its stalled requests were bounded by nothing once
     * other streams kept the session's timeout restarting.
     *
     * @param now The time of the sweep: the steady clock's (`std::chrono::steady_clock::now()`), or a test's stepped
     *            from it, and never earlier than a previous call's -- the streams' clocks are stamped with it, so a
     *            time behind them resets what just progressed and a time ahead keeps what is overdue
     * @return The number of streams reset; 0 on a session that does not run HTTP/2, or whose connection ended or
     *         left it (a disconnection, an extraction)
     */
    std::uint32_t
    http2_sweep_streams(std::chrono::steady_clock::time_point now) noexcept {
        auto *const protocol = live_http2_protocol(); // none once the connection left: an extraction too
        if (!protocol || !this->is_connected())
            return 0;
        const auto pass       = this->protocol_pass();
        const auto unanswered = this->getTimeout(); // 0: the session has no timeout, a handler no bound
        // The RST_STREAM frames leave as every frame of the protocol does: the session's operator<< arms the write.
        return protocol->cleanup_idle_streams(now, constants::STREAM_IDLE_TIMEOUT, constants::STREAM_INCOMPLETE_TIMEOUT,
                                              unanswered > qb::duration::zero() ? unanswered : qb::duration::max());
    }

    /**
     * @brief Send HTTP response
     * @param res HTTP response to send
     * @return Output stream reference
     */
    auto &
    operator<<(qb::http::Response &res) {
        if (_http2_protocol) {
            // The connection speaks HTTP/2 (ALPN), and nothing else once its protocol was cleared: `_http2_protocol` is
            // never lowered, so it is read through the io (Huly QB-1248).
            auto *const protocol = live_http2_protocol();
            if (!protocol) {
                LOG_HTTP_WARN_PA(this->id(), "HTTP/2 response dropped: the session's HTTP/2 protocol was cleared, or its connection left");
                return this->out();
            }
            if (res.stream_id > std::numeric_limits<uint32_t>::max()) {
                LOG_HTTP_ERROR_PA(this->id(), "HTTP/2 response stream_id is too large: " << res.stream_id);
                return this->out();
            }
            const uint32_t stream_id = static_cast<uint32_t>(res.stream_id);
            if (!is_valid_http2_stream_id(stream_id)) {
                LOG_HTTP_ERROR_PA(this->id(),
                                  "HTTP/2 response with stream_id " << stream_id << " is invalid (stream_id 0 is reserved for HTTP/1.1)");
                return this->out();
            }
            if (!validate_response(res)) {
                LOG_HTTP_ERROR_PA(this->id(), "HTTP/2 response validation failed for stream "
                                                  << stream_id << " (invalid status code: " << res.status() << ")");
                return this->out();
            }
            if (!res.has_header("content-length") && !res.body().empty()) {
                res.set_header("content-length", std::to_string(res.body().size()));
            }
            bool sent = false;
            {
                // A response the protocol refuses resets its stream, and a closed stream lets a waiting pushed response
                // out: the observer of either reset may clear the protocols (protocol_pass(), as reset_stream()).
                const auto pass = this->protocol_pass();
                sent            = protocol->send_response(stream_id, res);
            }
            if (!sent) {
                LOG_HTTP_ERROR_PA(this->id(), "HTTP/2 response send failed for stream " << stream_id);
                return this->out();
            }
            // Keep stream context alive until the protocol lifecycle reports
            // stream closure through the write/cleanup path. This avoids firing
            // POST_RESPONSE_SEND immediately after enqueue, before bytes have
            // actually progressed through transport flow control.
            this->ready_to_write();
            this->updateTimeout();
        } else {
            // HTTP/1.1 fallback: one exchange per connection. The io closes once the response is delivered,
            // after the peer (qb-io close_after_deliver(), Huly QB-1089): on(eos) used to disconnect at once,
            // which a peer still sending turns into a reset that can destroy the response (Huly QB-168).
            qb::io::async::io<session<Derived, Handler>>::operator<<(res);
            this->close_after_deliver();
        }
        return this->out();
    }

    /**
     * @brief Protocol hook: the request limits, the server's `request_limits()` read live (Huly QB-168, QB-94).
     *
     * Read by both protocols this session can run: HTTP/2 when a request's header block ends and on every
     * DATA frame, the HTTP/1.1 fallback when a request begins. A server without the setting keeps the
     * defaults, `protocol_limits`' constants. Public because the protocols detect it through a
     * `requires`-expression, which would not see a private member.
     */
    [[nodiscard]] qb::http::request_limits const &
    http_request_limits() noexcept {
        if constexpr (requires(Handler &h) { h.request_limits(); }) {
            return this->server().request_limits();
        } else {
            static constexpr qb::http::request_limits defaults{};
            return defaults;
        }
    }

    /**
     * @brief Send the response of a finalised context (the router's callback): nothing for a response whose head
     *        left at `begin_stream()` and whose body went through its stream (Huly QB-86), the response itself
     *        otherwise (`operator<<`).
     */
    void
    send_response(ContextType &ctx) {
        if (ctx.is_streaming())
            return;
        *this << ctx.response();
    }

    // --- the streaming hooks of qb::http::ResponseStream (Huly QB-86; the streaming_session concept) ----------------
    //
    // One connection, many streams: each hook about a stream takes it and reads its stream id. The pieces go as DATA
    // frames as far as the stream's and the connection's send windows and the peer's frame size allow; the rest waits in
    // the protocol's stream until a WINDOW_UPDATE lets it go. The HTTP/1.1 fallback (ALPN http/1.1) buffers.

    /// Whether this session can stream the response to `ctx` now: it speaks HTTP/2, `ctx` answers a request stream of
    /// this connection -- stored, or being routed for it (a synchronous handler) -- that can take a streamed response
    /// (dispatched, open to a response, none sent), and no stream is live on it. A query: nothing changes.
    [[nodiscard]] bool
    stream_can_answer(ContextType &ctx) {
        if (!live_http2_protocol() || !this->is_connected())
            return false;
        const auto id = ctx.request().stream_id;
        if (id > std::numeric_limits<uint32_t>::max() || !is_valid_http2_stream_id(static_cast<uint32_t>(id)))
            return false;
        const auto stream_id = static_cast<uint32_t>(id);
        if (_streams.find(stream_id) != _streams.end())
            return false;
        if (auto it = _contexts.find(stream_id); it != _contexts.end())
            return it->second.get() == &ctx && _http2_protocol->can_begin_streamed_response(stream_id);
        return ctx.session().get() == static_cast<Derived *>(this) && _http2_protocol->can_begin_streamed_response(stream_id);
    }

    /// The request being answered is a HEAD: a streamed response sends its head alone (HEADERS with END_STREAM).
    [[nodiscard]] static bool
    stream_request_is_head(ContextType const &ctx) noexcept {
        return ctx.request().method() == qb::http::method::HEAD;
    }

    /// HTTP/2 ends a message by END_STREAM: a stream without a declared length is `end_of_stream` framing, no coding.
    [[nodiscard]] static constexpr bool
    stream_delimits_messages() noexcept {
        return true;
    }

    /// Write the head of `ctx.response()` now -- its HEADERS, without END_STREAM (with it for a HEAD, whose exchange
    /// ends there) -- adopting `ctx` when it is being routed for this session, and keep the stream to notify. `false`
    /// when the head could not be written: the stream can no longer take it, or the protocol refused the head (a field
    /// HTTP/2 forbids) and reset the stream, which cancels the context through on(Http2StreamErrorEvent).
    [[nodiscard]] bool
    stream_head(ContextType &ctx, std::shared_ptr<qb::http::ResponseStream<Derived>> const &stream) {
        if (!stream_can_answer(ctx))
            return false;
        const auto stream_id = static_cast<uint32_t>(ctx.request().stream_id);
        if (_contexts.find(stream_id) == _contexts.end())
            _contexts[stream_id] = ctx.shared_from_this(); // on(Request&&, stream_id)'s own assignment then stores the same object
        auto &response     = ctx.response();
        response.stream_id = stream_id;
        const bool head    = stream_request_is_head(ctx);
        bool       begun   = false;
        {
            const auto pass = this->protocol_pass(); // a refused head resets the stream (as reset_stream())
            begun           = _http2_protocol->begin_streamed_response(stream_id, response, head);
        }
        if (!begun) {
            this->ready_to_write(); // the refusal's RST_STREAM, if any
            return false;
        }
        if (!head)
            _streams[stream_id] = stream;
        this->ready_to_write();
        this->updateTimeout();
        return true;
    }

    /// Append a piece of a streamed body: DATA frames as far as the windows go, the rest waits in the stream. Each
    /// piece refreshes the inactivity timeout: a stream that writes is not an idle connection.
    void
    stream_write(qb::http::ResponseStream<Derived> const &stream, std::string_view bytes) {
        auto *const protocol = live_http2_protocol(); // no reset is reachable from a piece: no pass
        if (!protocol || !protocol->write_streamed_body(static_cast<uint32_t>(stream.stream_id()), bytes))
            return;
        this->ready_to_write();
        this->updateTimeout();
    }
    /// A chunk never reaches HTTP/2 (a stream here is `end_of_stream` or `content_length` framed): its payload is taken.
    void
    stream_write(qb::http::ResponseStream<Derived> const &stream, qb::http::Chunk const &chunk) {
        stream_write(stream, std::string_view{chunk.data(), chunk.size()});
    }

    /// What the peer has not taken of this stream's output: the socket's output buffer, shared by every stream of the
    /// connection, and the pieces this stream's windows hold back.
    [[nodiscard]] std::size_t
    stream_pending(qb::http::ResponseStream<Derived> const &stream) noexcept {
        auto *const protocol = live_http2_protocol();
        return this->out().size() + (protocol ? protocol->streamed_body_pending(static_cast<uint32_t>(stream.stream_id())) : 0);
    }

    /// What the peer has not taken of THIS stream's bytes alone, for the stream's stall watch (Huly QB-1212): the
    /// output is shared, so another stream's traffic leaving it must not count as this stream's acceptance -- the
    /// pieces its windows hold back, and its last DATA frame's distance from leaving the output (a FIFO bound).
    [[nodiscard]] std::size_t
    stream_waiting(qb::http::ResponseStream<Derived> const &stream) noexcept {
        auto *const protocol = live_http2_protocol();
        return protocol ? protocol->streamed_body_waiting(static_cast<uint32_t>(stream.stream_id()), drained_total()) : this->out().size();
    }

    /// The hard cap of the output: the session's write-buffer cap (`max_write_buffer_size()`, its transport's:
    /// `QB_MAX_WRITE_BUFFER_SIZE` unless `set_max_write_buffer_size()` changed it; Huly QB-86), which `publish()` enforces
    /// by disconnecting. A stream's own buffer is bounded by the producer's `drain()`: it waits at
    /// `stream_high_watermark()`. The cap is checked against this stream's pieces at `write()`; what every stream held back
    /// for a window flushes under it too, the protocol bounding each flush by the socket's room under the same cap
    /// (`resume_streamed_responses()` on the next write pass).
    [[nodiscard]] std::size_t
    stream_write_cap() const noexcept {
        return this->max_write_buffer_size();
    }

    /// The bytes a producer may leave queued before it should wait (1 MiB by default), per stream.
    [[nodiscard]] std::size_t
    stream_high_watermark() const noexcept {
        return _stream_high_watermark;
    }
    Derived &
    stream_high_watermark(std::size_t bytes) noexcept {
        _stream_high_watermark = bytes;
        return static_cast<Derived &>(*this);
    }

    /// The end of a streamed body: END_STREAM follows the pieces still waiting -- after the response's trailer section
    /// (its `trailers()` as they stand now, the fields its `trailer` header announces) when it has one.
    void
    stream_end(qb::http::ResponseStream<Derived> const &stream, bool) {
        const auto stream_id = static_cast<uint32_t>(stream.stream_id());
        _streams.erase(stream_id);
        auto *const protocol = live_http2_protocol();
        if (!protocol)
            return;
        const auto ctx = stream.context();
        {
            const auto pass = this->protocol_pass(); // a refused trailer section resets the stream (as reset_stream())
            protocol->end_streamed_response(stream_id, ctx ? &ctx->response() : nullptr);
        }
        this->ready_to_write();
        this->updateTimeout();
    }

    /// A streamed body cannot be completed correctly: the stream is reset (RST_STREAM INTERNAL_ERROR), which cancels its
    /// context; the connection serves on. Nothing is sent on a stream the peer ended first, nor once the connection is
    /// gone or extracted.
    void
    stream_abort(qb::http::ResponseStream<Derived> const &stream) noexcept {
        const auto stream_id = static_cast<uint32_t>(stream.stream_id());
        _streams.erase(stream_id);
        auto *const protocol = live_http2_protocol();
        if (!protocol || !this->is_connected())
            return;
        bool reset = false;
        {
            const auto pass = this->protocol_pass(); // the stall watch's timer comes here (as reset_stream())
            reset           = protocol->abandon_streamed_response(stream_id);
        }
        if (reset) {
            this->ready_to_write();
            this->updateTimeout();
        }
    }

    /**
     * @brief Server hook (Huly QB-91): whether the session still speaks HTTP -- its TLS handshake, HTTP/2 or the
     *        HTTP/1.1 fallback. A session switched to another protocol is out of an HTTP drain.
     */
    [[nodiscard]] bool
    http2_speaks_http() const noexcept {
        // The handshake's pointer is lowered once the session replaced it; the two others are read with their lifetime.
        return this->protocol() == _handshake_protocol || live_http2_protocol() != nullptr || live_http1_protocol() != nullptr;
    }

    /**
     * @brief Server hook (Huly QB-91): the server drains.
     *
     * - HTTP/2: the graceful shutdown of RFC 9113 section 6.8 begins -- the notice (GOAWAY naming the largest
     *   stream id, then a PING), and on the PING's ACK the final GOAWAY with the last stream the client opened;
     *   the connection closes when its last stream has ended.
     * - The HTTP/1.1 fallback, one exchange per connection: an exchange under way closes the connection after its
     *   answer, as always; a session that has received nothing closes now, gracefully (qb-io's lingering close).
     * - In the TLS handshake: it ends first. Then HTTP/2 is refused at once -- the final GOAWAY names stream 0:
     *   no stream of the client's is processed, and it may retry them elsewhere -- and HTTP/1.1 serves its one
     *   exchange.
     */
    void
    http2_begin_drain() noexcept {
        if (_draining)
            return;
        _draining = true;
        if (!http2_speaks_http() || this->lingering())
            return;
        if (auto *const protocol = live_http2_protocol()) {
            if (protocol->begin_graceful_shutdown())
                this->ready_to_write();
            return;
        }
        if (live_http1_protocol()) {
            if (!_contexts.empty() || this->in().size() != 0)
                return; // an exchange under way: its answer closes the connection
            this->close_after_deliver();
            this->ready_to_write(); // nothing to deliver: the write path closes at once, after the client
        }
    }

    /**
     * @brief Server hook (Huly QB-91): the drain's deadline came.
     *
     * An HTTP/2 connection is sent its final GOAWAY -- unless it was -- and closes once that is delivered: what
     * is still open is abandoned, and the client learns which of its streams were never processed. The delivery has
     * qb-io's linger bound (set_linger()), counted from here whatever the client takes meanwhile: one that does not
     * read, or reads a little at a time, is aborted at the bound with what is left of the output (`ServerDraining`).
     * Delivered, the connection closes after its peer (qb-io's lingering close, which has that bound again). With
     * no linger bound, or no timer for it, the session is aborted at once, as any other.
     *
     * The session's inactivity timeout is over: it restarts at every write that leaves octets queued, and bounded
     * nothing against a client whose reading made the server write within each (the ninth independent review, Huly
     * QB-1248).
     */
    void
    http2_abort_drain() noexcept {
        if (auto *const protocol = live_http2_protocol(); protocol && protocol->ok() && this->linger() > qb::duration::zero()) {
            try {
                _drain_delivery =
                    std::make_unique<qb::http::detail::loop_timer>(this->linger(), [this]() noexcept { on_drain_delivery_bound(); });
            } catch (...) {
                end_session(qb::http::DisconnectedReason::ServerDraining); // no bound, no delivery
                return;
            }
            protocol->complete_graceful_shutdown();
            this->close_after_deliver();
            this->setTimeout(qb::duration::zero());
            this->ready_to_write();
            return;
        }
        end_session(qb::http::DisconnectedReason::ServerDraining);
    }

    /**
     * @brief Protocol hook of the HTTP/1.1 fallback: a request was refused for a limit (414, 431 or 413, Huly QB-168, QB-94), a
     *        target, a Host or a framing (400, 501 for a coding before chunked; QB-1177, QB-1186, QB-1248) or its version (505).
     * @param status The status that answers it.
     *
     * Answered with the status, an empty body and `Connection: close`, and on(eos) closes the connection,
     * as after every HTTP/1.1 exchange of this session. A request still being answered goes first: its
     * response already ends the connection, and the refused one is not answered, as no request pipelined
     * behind another is on this path.
     */
    void
    http1_refuse_request(qb::http::Status status) noexcept {
        LOG_HTTP_WARN_PA(this->id(), "HTTP/1.1 request refused with " << status.code() << "; the connection closes after the answer.");
        if (auto it = _contexts.find(constants::HTTP11_STREAM_ID); it != _contexts.end() && it->second)
            return;
        try {
            qb::http::Response response{status};
            response.set_header("Connection", "close");
            qb::io::async::io<session<Derived, Handler>>::operator<<(response);
            this->close_after_deliver();
            this->updateTimeout();
        } catch (...) {
            end_session(qb::http::DisconnectedReason::ServerError);
        }
    }

    /**
     * @brief Handle SSL handshake completion
     * @param event Handshake event
     */
    void
    on([[maybe_unused]] qb::io::async::event::handshake &&event) {
        auto alpn_proto = this->transport().get_alpn_selected_protocol();
        LOG_HTTP_INFO_PA(this->id(), "Handshake complete. ALPN selected: " << (alpn_proto.empty() ? "none/http1.1" : alpn_proto));
        if (alpn_proto == "h2") {
            LOG_HTTP_DEBUG_PA(this->id(), "Switching to HTTP/2 protocol.");
            // The protocol counts the replies its peer solicited that are still queued in this session's output -- PONGs,
            // SETTINGS ACKs, resets -- on what its socket took, `bytes_written()`: without it they would be forgiven only
            // once the output is empty (Huly QB-1270).
            static_assert(qb::protocol::http2::counts_bytes_written<session>, "the HTTP/2 session counts the bytes its socket took");
            if (auto *const installed = this->template switch_protocol<watched<Http2Protocol>>(*this)) {
                _http2_protocol     = installed;
                _http2_lifetime     = installed->lifetime;
                _handshake_protocol = nullptr; // replaced: no later protocol at its address is the handshake
            }
            // The server drains: the connection serves nothing. Its final GOAWAY names stream 0, so the client
            // knows none of its streams was processed (Huly QB-91).
            if (_draining && _http2_protocol) {
                _http2_protocol->complete_graceful_shutdown();
                this->ready_to_write();
            }
        } else {
            LOG_HTTP_DEBUG_PA(this->id(), "Switching to HTTP/1.1 protocol.");
            if (auto *const installed = this->template switch_protocol<watched<Http1Protocol>>(*this)) {
                _http1_protocol     = installed;
                _http1_lifetime     = installed->lifetime;
                _handshake_protocol = nullptr; // as above
            }
        }
    }

    /**
     * @brief Handle HTTP/1.1 request
     * @param msg HTTP/1.1 request message
     */
    void
    on(qb::http::Request &&request) {
        LOG_HTTP_INFO_PA(this->id(), "Received HTTP/1.1 request: " << request.method() << " " << request.uri().source());
        // HTTP/1.1 uses stream_id 0 (not a valid HTTP/2 stream ID)
        request.stream_id = constants::HTTP11_STREAM_ID;
        // Check if context[0] already exists and cleanup if needed
        auto it = _contexts.find(constants::HTTP11_STREAM_ID);
        if (it != _contexts.end() && it->second) {
            it->second->cancel("New HTTP/1.1 request replacing previous context");
            _contexts.erase(it);
        }
        auto context = _contexts[constants::HTTP11_STREAM_ID] = router().route(this->shared_from_this(), std::move(request));
        if (!context) {
            LOG_HTTP_WARN_PA(this->id(), "HTTP/1.1 request not routed, disconnecting.");
            end_session(qb::http::DisconnectedReason::Undefined); // Consider a more specific reason like NoRouteFound
        }
    }

    /**
     * @brief Handle HTTP/2 request
     * @param req HTTP request
     * @param stream_id HTTP/2 stream identifier
     */
    void
    on(qb::http::Request &&request, uint32_t stream_id) {
        LOG_HTTP_INFO_PA(this->id(),
                         "Received HTTP/2 request on stream " << stream_id << ": " << request.method() << " " << request.uri().source());
        // Store stream_id directly in request (no string conversion needed)
        request.stream_id = stream_id;

        auto context = router().route(this->shared_from_this(), std::move(request));
        if (!context) {
            LOG_HTTP_WARN_PA(this->id(), "HTTP/2 request on stream " << stream_id << " not routed. Sending RST_STREAM.");
            // Explicitly send RST_STREAM when routing fails
            if (auto *const protocol = live_http2_protocol()) { // read again: the routing ran application code
                protocol->send_rst_stream(stream_id, qb::protocol::http2::ErrorCode::REFUSED_STREAM,
                                          "Request not routed - no matching route found");
            }
            // Don't store nullptr in _contexts - only store valid contexts
        } else {
            // Only store valid contexts
            _contexts[stream_id] = context;
        }
        this->updateTimeout();
    }

    /**
     * @brief Handle session timeout
     * @param event Timeout event
     *
     * Nothing for a session that has ended (end_session()): one ended earlier in this pass of the loop, released a
     * dispatch later, or held by a capture after its release, whose timer still ticks -- it keeps the reason it ended
     * with; the timeout disconnected it again, `ByTimeout` over that reason (the eleventh and twelfth independent
     * reviews, Huly QB-1248). Nor for one in qb-io's lingering close, delivered and waiting for its peer: the linger
     * has its own bound, and the timeout cut it, the socket closed under a peer that may not have read what was just
     * delivered (the thirteenth).
     */
    void
    on([[maybe_unused]] qb::io::async::event::timeout const &event) {
        if (!this->is_connected() || this->lingering())
            return;
        LOG_HTTP_WARN_PA(this->id(), "Session timed out.");
        end_session(qb::http::DisconnectedReason::ByTimeout);
    }

    /**
     * @brief Handle pending write event
     * @param event Pending write event
     */
    void
    on(qb::io::async::event::pending_write &&event) {
        LOG_HTTP_TRACE_PA(this->id(), "Pending write event, updating timeout.");
        this->updateTimeout();
        if (!_http2_protocol)
            return;
        // The resume of a streamed response can reset its stream, a reclaimed context runs its hooks: either may clear
        // the protocols, outside the read dispatch (protocol_pass(), Huly QB-1248). The streams are swept from the
        // session's own timer (on_stream_sweep_tick()), no longer from here.
        const auto pass = this->protocol_pass();
        notify_streams(event.bytes); // a producer parked on drain() may resume (Huly QB-86)
        reclaim_completed_stream_contexts();
    }

    /**
     * @brief Handle end of stream event
     * @param event EOS event
     */
    void
    on([[maybe_unused]] qb::io::async::event::eos &&event) {
        LOG_HTTP_DEBUG_PA(this->id(), "End of stream (eos) event.");
        if (_http1_protocol) {
            auto it = _contexts.find(constants::HTTP11_STREAM_ID);
            if (it != _contexts.end() && it->second) {
                it->second->execute_hook(qb::http::HookPoint::POST_RESPONSE_SEND);
                _contexts.clear();
            }
            // The io closes after this delivery: the response was published with close_after_deliver().
        } else if (_http2_protocol) {
            const auto pass = this->protocol_pass(); // as on(pending_write)
            notify_streams(0); // the socket took everything: what a stream's windows hold back is all that waits (Huly QB-86)
            reclaim_completed_stream_contexts();
        }
    }

    void
    on(qb::io::async::event::extracted &&) {
        LOG_HTTP_DEBUG_PA(this->id(), "HTTP/2 session extracted.");
        // Stop the libev watcher immediately so this event loop stops monitoring
        // the socket before it is moved to another io_handler.
        this->stop();
        connection_left();
        cancel_all_streams(); // the producers are told first: the cancellation of a context then resets nothing (Huly QB-86)
        for (auto &[stream_id, context] : _contexts) {
            context->cancel("Session extracted");
        }
        _contexts.clear();
    }

    /**
     * @brief Server hook (Huly QB-1182): the session is being extracted -- what its `on(event::extracted)` does: the
     *        watcher stops, every stream's context is cancelled and released. The server's extractSession() calls it
     *        when io_handler's probe cannot see that handler: a session class that declares an `on()` of its own
     *        hides the base's overloads from a probe on its type, public ones included (name hiding ignores access).
     */
    void
    http2_extracted() {
        on(qb::io::async::event::extracted{});
    }

    /**
     * @brief Handle disconnection event
     * @param e Disconnection event
     */
    void
    on(qb::io::async::event::disconnected &&e) {
        if (!e.reason) {
            LOG_HTTP_WARN_PA(this->id(), "Disconnected by peer.");
        } else {
            LOG_HTTP_INFO_PA(this->id(), "Disconnected. Reason code: " << e.reason);
        }
        connection_left();
        cancel_all_streams(); // the producers are told first (Huly QB-86)
        for (auto &context : _contexts) {
            context.second->cancel("Session disconnected");
        }
        _contexts.clear(); // Clear all stream contexts on disconnect
    }

    /**
     * @brief Handle HTTP/2 connection error
     * @param event Connection error details
     */
    void
    on(const qb::protocol::http2::Http2ConnectionErrorEvent &event) {
        LOG_HTTP_ERROR_PA(this->id(), "HTTP/2 Connection Error: " << event.message << ". Fatal: " << event.fatal);
        if (event.fatal) {
            end_session(qb::http::DisconnectedReason::ByProtocolError);
        }
    }

    /**
     * @brief Handle HTTP/2 stream error
     * @param event Stream error details
     */
    void
    on(const qb::protocol::http2::Http2StreamErrorEvent &event) {
        LOG_HTTP_WARN_PA(this->id(), "HTTP/2 Stream Error on stream " << event.stream_id << ". Code: " << static_cast<int>(event.error_code)
                                                                      << ", Msg: " << event.message);
        cancel_stream(event.stream_id); // a streamed response ends with its stream (Huly QB-86)
        // Context for this stream might need to be cleared or marked.
        auto it = _contexts.find(event.stream_id);
        if (it != _contexts.end() && it->second) {
            auto context = std::move(it->second);
            _contexts.erase(it);
            context->cancel("HTTP/2 stream error: " + event.message);
        }
    }

    /**
     * @brief Handle a GOAWAY: the client's, or the one this session's protocol sent with an error (`event.sent`)
     * @param event GOAWAY details
     */
    void
    on(const qb::protocol::http2::Http2GoAwayEvent &event) {
        // The server's own GOAWAY was logged as received from the client. A client's NO_ERROR GOAWAY after the first -- one it
        // lowers each time -- is logged by the protocol at each power of two of their count, not here each time (Huly
        // QB-1270).
        const bool graceful_again = !event.sent && event.error_code == qb::protocol::http2::ErrorCode::NO_ERROR && _client_goaway_logged;
        if (!graceful_again) {
            LOG_HTTP_WARN_PA(
                this->id(), (event.sent ? "Sent GOAWAY to client. Last Stream ID: " : "Received GOAWAY from client. Last Stream ID: ")
                                << event.last_stream_id << ", Code: " << static_cast<int>(event.error_code) << ", Debug: " << event.debug_data);
        }
        _client_goaway_logged = _client_goaway_logged || (!event.sent && event.error_code == qb::protocol::http2::ErrorCode::NO_ERROR);
        // Server may decide to stop accepting new requests on this connection.
        if (event.error_code != qb::protocol::http2::ErrorCode::NO_ERROR) {
            // A connection this server ended for a flood (every flood rule of the protocol, the no-progress bucket
            // included, sends ENHANCE_YOUR_CALM) is closed with the session: a linger of zero is qb-io's "close at
            // once", and the loop does not read on, for the bound, the peer it has just refused to read. Any other
            // error GOAWAY leaves with a disconnect(), as before: the session is released at the next dispatch, and
            // once the frame is written qb-io closes the descriptor after the peer, so that a client still sending
            // reads the GOAWAY instead of a reset. A GOAWAY still queued behind output the client has not taken is
            // dropped with the session: the bound on resources wins over delivery there (Huly QB-1270).
            // The GOAWAY the sweep sends -- a refused header block left open past its bound (Huly QB-1248) -- comes
            // from the sweep's timer, outside the read dispatch, where no write follows a disconnect(): it is dropped
            // with the session, and the client reads the end of its connection. Delivering it would keep a session
            // whose protocol has ended, with its contexts and its output, for as long as the client took to read:
            // the bound on resources wins there too (the eighth independent review).
            if (event.sent && event.error_code == qb::protocol::http2::ErrorCode::ENHANCE_YOUR_CALM)
                this->set_linger(qb::duration::zero());
            end_session(qb::http::DisconnectedReason::ResponseTransmitted);
        }
    }

    /// The server's router.
    Router &
    router() {
        return this->server().router();
    }

    /// Protocol hooks (Huly QB-1248): a read brought part of an HTTP/1.1 request of the ALPN fallback, or a frame of an HTTP/2
    /// request not yet complete (its first HEADERS, a DATA with octets): the timeout restarts. Public for the protocols' `requires`.
    void
    http1_request_progress() noexcept {
        this->updateTimeout();
    }
    void
    http2_request_progress() noexcept {
        this->updateTimeout();
        if (!_stream_sweep_armed) [[unlikely]]
            arm_stream_sweep(); // a stream opened on a connection that had none: its streams are swept from now
    }
    /// Protocol hook (Huly QB-1248): the client left a refused header block open, which has no stream. The sweep is what
    /// bounds it, so it is armed when no tick is due -- the connection's last stream had ended; the timeout does not
    /// restart: such a block is no progress of a request.
    void
    http2_refused_block_open() noexcept {
        if (!_stream_sweep_armed)
            arm_stream_sweep();
    }
};

/// HTTP/2 I/O handler with routing (Derived: the CRTP derived type; Session: the session type).
template <typename Derived, typename Session>
class io_handler : public qb::io::async::io_handler<Derived, Session> {
public:
    using Router = typename qb::http::Router<Session>;

private:
    Router                   _router; ///< HTTP router
    qb::http::request_limits _request_limits{};

public:
    io_handler() {}

    /// The router.
    Router &
    router() {
        return _router;
    }

    /**
     * @brief Set the limits this server applies to every request it reads, over both protocols it speaks (Huly QB-94); 0 in any
     *        of them means no limit of that kind.
     *
     * Same call on the HTTP/1.1, HTTP/3 and dual-stack servers. Read live: a request that begins after the call is judged under
     * the new limits. An HTTP/2 request over a limit is answered on its stream -- `414 URI Too Long` for its `:path`, `431
     * Request Header Fields Too Large` for a field name, a field value or the number of fields of its header or trailer section,
     * `413 Content Too Large` for a declared `content-length` (before a byte of the body is read) or for DATA that passes the
     * body limit -- then RST_STREAM(NO_ERROR) asks the client to stop sending the rest (RFC 9113 §8.1); the connection and its
     * other streams go on. Until 3.3 the body was reset with ENHANCE_YOUR_CALM against the HTTP/1.1 constant and the fields had
     * no limit but the 1 MiB HPACK header list, which stays. The HTTP/1.1 requests of this server's ALPN fallback get the
     * HTTP/1.1 answers. The defaults are `qb::http::protocol_limits`' constants.
     * @param limits The limits.
     */
    void
    set_request_limits(qb::http::request_limits const &limits) noexcept {
        _request_limits = limits;
    }

    /**
     * @brief The limits set_request_limits() set, as given (0 = none).
     */
    [[nodiscard]] qb::http::request_limits const &
    request_limits() const noexcept {
        return _request_limits;
    }

    /**
     * @brief Set the request body limit alone, in bytes; 0 means none (set_request_limits() for the rest).
     *
     * Same name and contract as the HTTP/1.1 and HTTP/3 servers' (Huly QB-168): a request over it is answered
     * `413 Content Too Large`, as set_request_limits() says. The default is
     * `qb::http::protocol_limits::MAX_BODY_SIZE` (100 MiB).
     * @param value The limit in bytes.
     */
    void
    set_max_body_size(std::size_t value) noexcept {
        _request_limits.max_body_size = value;
    }

    /**
     * @brief The request body limit; 0 when there is none.
     */
    [[nodiscard]] std::size_t
    max_body_size() const noexcept {
        return _request_limits.max_body_size;
    }
};

/**
 * @brief HTTP/2 server acceptor
 *
 * Listens for incoming SSL/TLS connections and creates sessions
 * with HTTP/2 or HTTP/1.1 protocol support via ALPN.
 *
 * @tparam Derived CRTP derived type
 * @tparam Session Session type
 */
template <typename Derived, typename Session>
class server
    : public qb::io::async::tcp::acceptor<server<Derived, Session>, qb::io::transport::saccept>
    , public io_handler<Derived, Session> {
    friend qb::io::async::tcp::acceptor<server<Derived, Session>, qb::io::transport::saccept>;
    friend io_handler<Derived, Session>;
    // The acceptor finds on(disconnected) through qb::has_own_on, which sees a private handler
    // only through this friend -- befriending the acceptor is not enough (Huly QB-252).
    friend struct has_method_on<server, void, qb::io::async::event::disconnected>;
    using acceptor_type = qb::io::async::tcp::acceptor<server<Derived, Session>, qb::io::transport::saccept>;

    /**
     * @brief Handle accepted connection
     * @param new_io New SSL socket
     */
    void
    on(typename acceptor_type::accepted_socket_type &&new_io) {
        this->registerSession(std::move(new_io));
    }

    /**
     * @brief Handle acceptor disconnection
     * @param event Disconnection event
     *
     * The listening socket is gone: no further connection will be accepted. Forwarded to the
     * derived server as `qb::http::event::disconnected` when it handles one -- as the HTTP/1.1
     * server does -- and always logged.
     */
    void
    on(qb::io::async::event::disconnected &&event) {
        if constexpr (qb::has_on<Derived, qb::http::event::disconnected>) {
            static_cast<Derived &>(*this).on(qb::http::event::disconnected{event.reason});
        }
        LOG_HTTP_WARN("HTTP/2 server disconnected. Reason: " << event.reason);
    }

    qb::http::detail::drain_state _drain; ///< drain() (Huly QB-91): begun once -- the listener closed -- reported once

    /// The sessions a drain waits for: those still speaking HTTP, lingering ones included (they are closing).
    [[nodiscard]] std::size_t
    http_sessions_left() noexcept {
        std::size_t left = 0;
        for (auto const &[id, session] : this->sessions()) {
            if (session && session->http2_speaks_http())
                ++left;
        }
        return left;
    }

    void
    drain_deadline_reached() noexcept {
        if (!_drain.pending())
            return;
        for (auto const &[id, session] : this->sessions()) {
            if (session && session->http2_speaks_http())
                session->http2_abort_drain();
        }
        LOG_HTTP_WARN("HTTP/2 drain deadline reached: the connections still open are closed.");
        _drain.report(qb::http::drain_outcome::deadline, "HTTP/2");
    }

public:
    /**
     * @brief Construct HTTP/2 server
     */
    server() = default;

    /**
     * @brief Drain the server (Huly QB-91): stop taking connections, end each one gracefully, and report when
     *        every HTTP session has closed or @p deadline came.
     *
     * - The listening socket is closed: a new connection is refused, and the port is free.
     * - An HTTP/2 connection shuts down in two phases (RFC 9113 section 6.8): a GOAWAY naming the largest stream
     *   id with NO_ERROR -- the client stops opening streams, and none it opened is lost -- and a PING; on the
     *   PING's ACK, a round trip later, the final GOAWAY names the last stream the client opened. The streams up
     *   to it are served, one above it is refused (REFUSED_STREAM, safe to retry elsewhere), and the connection
     *   closes when its last stream has ended.
     * - A connection still in its TLS handshake finishes it; then HTTP/2 is refused at once (the final GOAWAY
     *   names stream 0) and HTTP/1.1 serves its one exchange. An HTTP/1.1 connection of the ALPN fallback that has
     *   received nothing closes now; one at work closes after its answer, as always.
     * - @p on_drained runs once, on the server's loop: with `drain_outcome::drained` when the last HTTP session
     *   has closed -- a lingering one counts until it is gone -- or with `drain_outcome::deadline` when
     *   @p deadline came first. Then each HTTP/2 connection is sent its final GOAWAY, if the PING was never
     *   answered, and closes once it is delivered, abandoning what is open -- qb-io's linger bound from the
     *   deadline, whatever the client takes meanwhile: one that has not taken it by then is aborted --; any
     *   other session is aborted. The `deadline` report does not wait for those last deliveries: it comes right
     *   after the final GOAWAYs are queued, and each of those connections ends within two lingers of it -- one to
     *   deliver, one to close after its client; a server destroyed on the report cuts them. With no HTTP session
     *   open the report comes before drain() returns; a deadline of zero or less ends the drain at once.
     *
     * The contract of the HTTP/1.1 server's drain(), whose deadline delivers nothing: it aborts every session at
     * once. The server cannot listen again afterwards.
     * @param deadline   How long the connections have, from now.
     * @param on_drained Told how the drain ended; may be empty.
     * @return False when a drain is already under way: the call changes nothing.
     */
    bool
    drain(qb::duration deadline, std::function<void(qb::http::drain_outcome)> on_drained = {}) {
        if (!_drain.begin(std::move(on_drained)))
            return false;
        this->stop();              // the accept watcher
        this->transport().close(); // and the listening socket: a new connection is refused
        for (auto const &[id, session] : this->sessions()) {
            if (session)
                session->http2_begin_drain();
        }
        if (http_sessions_left() == 0) {
            _drain.report(qb::http::drain_outcome::drained, "HTTP/2");
            return true;
        }
        if (deadline <= qb::duration::zero()) {
            drain_deadline_reached();
            return true;
        }
        _drain.arm_deadline(deadline, [this]() noexcept { drain_deadline_reached(); });
        return true;
    }

    /**
     * @brief Whether drain() was called (the drain may be over: see its callback).
     */
    [[nodiscard]] bool
    draining() const noexcept {
        return _drain.started();
    }

    /**
     * @brief Session hook: a session of this server is gone. The base forgets it; a drain that waited for it may end.
     * @param ident The session's id.
     */
    void
    disconnected(qb::uuid ident) {
        qb::io::async::io_handler<Derived, Session>::disconnected(ident);
        if (_drain.pending() && http_sessions_left() == 0)
            _drain.report(qb::http::drain_outcome::drained, "HTTP/2");
    }

    /**
     * @brief Extract a session's transport, as io_handler::extractSession does. A drain that waited for that
     *        session may end: it is no longer this server's (Huly QB-91).
     * @param ident The session's id.
     * @return The transport and whether the session was found.
     */
    [[nodiscard]] std::pair<typename Session::transport_io_type, bool>
    extractSession(qb::uuid const &ident) {
        // io_handler runs the session's on(event::extracted) itself when its probe sees it. A session class that
        // declares an on() of its own hides that handler from the probe, public as it is (C++ name hiding ignores
        // access): it is run from here then, before the transport leaves, as the HTTP/1.1 server does (Huly QB-1182).
        if constexpr (!qb::has_on<Session, qb::io::async::event::extracted>) {
            const auto it = this->sessions().find(ident);
            if (it != this->sessions().end() && it->second) {
                const auto session = it->second; // its handler cancels contexts whose hooks may change the sessions
                session->http2_extracted();
            }
        }
        auto extracted = qb::io::async::io_handler<Derived, Session>::extractSession(ident);
        if (_drain.pending() && http_sessions_left() == 0)
            _drain.report(qb::http::drain_outcome::drained, "HTTP/2");
        return extracted;
    }

    /**
     * @brief Bind the listening socket **and start accepting**.
     *
     * @param uri The URI to listen on.
     * @param cert_file The path to the certificate file.
     * @param key_file The path to the key file.
     * @return True if the server is bound and accepting, false otherwise.
     *
     * @note **Same contract as the base, with the ALPN this protocol requires.** This
     *       shadows `qb::io::async::tcp::acceptor::listen()` only to pin `{"h2","http/1.1"}`
     *       as the advertised ALPN — the base takes the list as a parameter and would
     *       otherwise be called with none, leaving a server that cannot negotiate h2.
     *       Binding *and* starting is what the base's `listen()` means ("Auto-start"), so
     *       the pair here mirrors the pair there, and matches `qb::http3` — whose
     *       `listen()` forwards to `quic::endpoint::listen()` and has always done both.
     *
     *       Until 3.0 this override bound *without* starting, under the base's other name.
     *       Forgetting the second step failed silently and expensively: `listen()` returned
     *       `true`, the port was held so nothing else could take it, and no accept watcher
     *       was ever registered — every client `connect()` hung to its own timeout with
     *       nothing in any log naming the cause. `dual_stack_server::listen()` compensated
     *       by calling `_http2->start()` itself; it no longer needs to. Calling `start()`
     *       yourself afterwards remains correct: `ev_io_start` returns early on an already
     *       active watcher, so the redundant call is a no-op.
     * @see listen_no_start
     * @see qb::io::async::tcp::acceptor::listen
     */
    [[nodiscard]] bool
    listen(qb::io::uri uri, std::filesystem::path cert_file, std::filesystem::path key_file) {
        if (!listen_no_start(std::move(uri), std::move(cert_file), std::move(key_file)))
            return false;
        this->start();
        return true;
    }

    /**
     * @brief Bind the listening socket without registering the accept watcher.
     *
     * Identical to `listen()` but leaves the server idle until `start()` is called — for a
     * server that must finish wiring (routers, hooks, session limits) before the first
     * accept can fire. Mirrors `qb::io::async::tcp::acceptor::listen_no_start()`, and
     * shadows it for the same reason `listen()` does: to pin the h2 ALPN.
     * @see listen
     */
    [[nodiscard]] bool
    listen_no_start(qb::io::uri uri, std::filesystem::path cert_file, std::filesystem::path key_file) {
        if (!reload_certificates(std::move(cert_file), std::move(key_file)))
            return false;
        return !this->transport().listen(std::move(uri));
    }

    /**
     * @brief Install a fresh TLS configuration for future accepts, with h2 then http/1.1 ALPN.
     *
     * Owner-thread operation; an invalid context leaves the listener unchanged. Existing
     * connections, including accepted sockets awaiting their handshake, retain their old
     * context. No session is closed and the listening socket is not rebound.
     * Context copies share SSL_CTX: supply a fresh, configured, unpublished context. This
     * call changes its ALPN list. SNI callbacks are retained; their selected contexts must
     * already advertise h2/http/1.1 before publication. Rebuild the entire SNI table for a
     * rotation and capture its contexts by value. Session resumption across rotation is
     * not guaranteed: the new context has its own cache and ticket configuration.
     * TLS server and generic methods are supported, including fresh adopt/share contexts;
     * client-only and DTLS contexts are refused. Usability and role are checked, not every
     * handshake prerequisite: the caller provides identity, SNI and/or custom authentication.
     */
    [[nodiscard]] bool
    set_tls_context(qb::io::ssl::Context context) {
        return qb::http::detail::set_server_tls_context(this->transport(), std::move(context), true);
    }

    /**
     * @brief Load certificate/key with Context::server defaults and replace the entire TLS configuration.
     *
     * Synchronous cold operation; failure preserves the listener. Does not retain mTLS,
     * ciphers, callbacks or session cache. Use set_tls_context for a complete custom policy.
     */
    [[nodiscard]] bool
    reload_certificates(std::filesystem::path cert_file, std::filesystem::path key_file) {
        return set_tls_context(qb::io::ssl::Context::server(std::move(cert_file), std::move(key_file)));
    }

    /** @brief Install a fresh Context, bind and start accepting. See set_tls_context for ownership and SNI. */
    template <typename TLSContext>
    requires std::same_as<std::remove_cvref_t<TLSContext>, qb::io::ssl::Context>
    [[nodiscard]] bool
    listen(qb::io::uri uri, TLSContext &&context) {
        if (!listen_no_start(std::move(uri), std::forward<TLSContext>(context)))
            return false;
        this->start();
        return true;
    }

    /** @brief Install a fresh Context and bind, deferring accepts until start(). */
    template <typename TLSContext>
    requires std::same_as<std::remove_cvref_t<TLSContext>, qb::io::ssl::Context>
    [[nodiscard]] bool
    listen_no_start(qb::io::uri uri, TLSContext &&context) {
        return set_tls_context(std::forward<TLSContext>(context)) && !this->transport().listen(std::move(uri));
    }
};

} // namespace internal

/**
 * @brief HTTP/2 type definitions for CRTP pattern
 * @tparam Derived CRTP derived type
 */
template <typename Derived>
struct use {
    template <typename ServerHandler>
    using session = internal::session<Derived, ServerHandler>;

    template <typename SessionType>
    using io_handler = internal::io_handler<Derived, SessionType>;

    template <typename SessionType>
    using server = internal::server<Derived, SessionType>;
};

// Forward declaration for Server to be used in DefaultSession's definition
template <typename SessionType>
class Server;

/**
 * @brief Default session implementation for HTTP/2 servers.
 *
 * This session type is used by `qb::http2::Server` by default if no custom
 * session is specified. It derives from the internal HTTP/2 session machinery.
 * Users can create their own session classes by deriving from
 * `qb::http2::internal::session<MySession, qb::http2::Server<MySession>>`.
 */
class DefaultSession : public qb::http2::use<DefaultSession>::session<Server<DefaultSession>> {
public:
    using Base       = qb::http2::use<DefaultSession>::session<Server<DefaultSession>>;
    using ServerType = qb::http2::Server<DefaultSession>;

    /**
     * @brief Constructs a DefaultSession.
     * @param server_handler Reference to the server instance that owns this session.
     */
    explicit DefaultSession(qb::http2::Server<DefaultSession> &server_handler)
        : Base(server_handler) {}
};

// io_handler::extractSession() runs a session's extracted handler only when its probe sees it (Huly QB-1182).
static_assert(qb::has_on<DefaultSession, qb::io::async::event::extracted>, "the HTTP/2 session's extracted handler must be visible");

/**
 * @brief A general-purpose HTTP/2 server class.
 *
 * This class template provides a concrete HTTP/2 server implementation that can be
 * parameterized with a specific session type. By default, it uses `qb::http2::DefaultSession`.
 * It inherits from the internal server machinery and exposes a router for defining endpoints.
 *
 * @tparam SessionType The type of session to be used by this server. Must be constructible
 *                     with a reference to `Server<SessionType>`.
 */
template <typename SessionType = DefaultSession>
class Server : public qb::http2::internal::server<Server<SessionType>, SessionType> {
public:
    using Session = SessionType; ///< Alias for the session type used by this server.

    /**
     * @brief Default constructor.
     */
    Server() = default;
};

/**
 * @brief Creates a shared pointer to an HTTP/2 server instance.
 *
 * This factory function simplifies the creation of an HTTP/2 server.
 *
 * @tparam Session The session type to be used by the server. Defaults to `qb::http2::DefaultSession`.
 *                 If providing a custom session, it must be defined to be constructible with
 *                 a reference to `qb::http2::Server<YourCustomSession>`.
 * @return A `std::unique_ptr` to a newly created `qb::http2::Server<Session>` instance.
 *
 * Example with default session:
 * @code
 * auto server = qb::http2::make_server();
 * server->router().get("/hello", ...);
 * @endcode
 *
 * Example with custom session:
 * @code
 * class MyHttp2Session : public qb::http2::internal::session<MyHttp2Session, qb::http2::Server<MyHttp2Session>> {
 * public:
 *   MyHttp2Session(qb::http2::Server<MyHttp2Session>& handler)
 *     : qb::http2::internal::session<MyHttp2Session, qb::http2::Server<MyHttp2Session>>(handler) {}
 *   // ... custom session logic ...
 * };
 * auto server = qb::http2::make_server<MyHttp2Session>();
 * server->router().get(...);
 * @endcode
 */
template <typename Session = DefaultSession>
[[nodiscard]] std::unique_ptr<Server<Session>>
make_server() {
    return std::make_unique<Server<Session>>();
}

// Type alias for the default server type for easier use.
template <typename Session = DefaultSession>
using server = Server<Session>;

} // namespace qb::http2

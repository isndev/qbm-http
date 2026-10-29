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

#include <array>
#include <filesystem>
#include <limits>
#include <qb/io/protocol/handshake.h>
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
constexpr uint32_t     DEFAULT_MAX_CONCURRENT_STREAMS = 50; ///< Default max concurrent streams per connection (reduced from 100 for security)
constexpr qb::duration STREAM_IDLE_TIMEOUT            = std::chrono::seconds(30); ///< Timeout for idle streams
constexpr qb::duration STREAM_INCOMPLETE_TIMEOUT      = std::chrono::seconds(10); ///< Timeout for incomplete streams
constexpr qb::duration CLEANUP_INTERVAL               = std::chrono::seconds(5);  ///< Interval for periodic stream cleanup
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
    using Http1Protocol = qb::protocol::http::server<session<Derived, Handler>>;
    using Http2Protocol = server_protocol<session<Derived, Handler>>;
    using ContextType   = qb::http::Context<Derived>;
    using Router        = typename qb::http::Router<Derived>;

private:
    friend qb::io::async::io<session<Derived, Handler>>;
    friend struct has_method_on<session, void, qb::io::async::event::pending_write>;
    friend struct has_method_on<session, void, qb::io::async::event::eos>;
    friend struct has_method_on<session, void, qb::io::async::event::disconnected>;
    friend Http2Protocol;
    friend qb::io::async::with_timeout<session<Derived, Handler>>;

    qb::unordered_map<uint32_t, std::shared_ptr<ContextType>> _contexts; ///< Stream contexts

    Http1Protocol *_http1_protocol; ///< HTTP/1.1 protocol handler
    Http2Protocol *_http2_protocol; ///< HTTP/2 protocol handler

    std::chrono::steady_clock::time_point _last_stream_cleanup; ///< Last time we cleaned up idle streams
    bool                                  _reclaiming_completed_contexts{false};
    /// The TLS handshake the session starts in: with HTTP/2 and the HTTP/1.1 fallback, the protocols an HTTP drain
    /// knows (http2_speaks_http()).
    qb::io::async::IProtocol const *_handshake_protocol{nullptr};
    bool                            _draining{false}; ///< The server drains (http2_begin_drain(), Huly QB-91)

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
            return _http2_protocol && this->protocol() == _http2_protocol && this->is_connected() && this->out().size() == pending_bytes;
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

    // A neutral peer reset is a lifecycle notification, not a stream error.
    // The protocol opts in through this private hook without extending the
    // public error-event contract of custom IO handlers.
    void
    on_peer_stream_reset(uint32_t stream_id) noexcept {
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
        , _http2_protocol(nullptr)
        , _last_stream_cleanup(std::chrono::steady_clock::now()) {
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
        LOG_HTTP_DEBUG_PA(this->id(), "HTTP/2 internal::session (server-side) destroyed.");
    }

    using qb::io::async::io<session<Derived, Handler>>::operator<<;

    [[nodiscard]] bool
    reset_stream(uint32_t stream_id, qb::protocol::http2::ErrorCode error_code = qb::protocol::http2::ErrorCode::CANCEL,
                 const std::string &reason = {}) {
        if (!_http2_protocol || !is_valid_http2_stream_id(stream_id)) {
            return false;
        }
        _http2_protocol->send_rst_stream(stream_id, error_code, reason);
        this->ready_to_write();
        this->updateTimeout();
        return true;
    }

    /**
     * @brief Send HTTP response
     * @param res HTTP response to send
     * @return Output stream reference
     */
    auto &
    operator<<(qb::http::Response &res) {
        if (_http2_protocol) {
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
            if (!_http2_protocol->send_response(stream_id, res)) {
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
     * @brief Server hook (Huly QB-91): whether the session still speaks HTTP -- its TLS handshake, HTTP/2 or the
     *        HTTP/1.1 fallback. A session switched to another protocol is out of an HTTP drain.
     */
    [[nodiscard]] bool
    http2_speaks_http() const noexcept {
        auto const *current = this->protocol();
        return current == _handshake_protocol || current == _http2_protocol || current == _http1_protocol;
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
        if (_http2_protocol && this->protocol() == _http2_protocol) {
            if (_http2_protocol->begin_graceful_shutdown())
                this->ready_to_write();
            return;
        }
        if (_http1_protocol && this->protocol() == _http1_protocol) {
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
     * is still open is abandoned, and the client learns which of its streams were never processed. A peer that
     * does not read cannot hold it past qb-io's linger bound (set_linger()); with no linger bound it is aborted,
     * as any other session.
     */
    void
    http2_abort_drain() noexcept {
        if (_http2_protocol && this->protocol() == _http2_protocol && _http2_protocol->ok() && this->linger() > qb::duration::zero()) {
            _http2_protocol->complete_graceful_shutdown();
            this->close_after_deliver();
            this->setTimeout(this->linger());
            this->ready_to_write();
            return;
        }
        this->disconnect(qb::http::DisconnectedReason::ServerDraining);
    }

    /**
     * @brief Protocol hook of the HTTP/1.1 fallback: a request was refused for a limit (414, 431 or 413,
     *        Huly QB-168, QB-94).
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
            this->disconnect(qb::http::DisconnectedReason::ServerError);
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
            _http2_protocol = this->template switch_protocol<Http2Protocol>(*this);
            // The server drains: the connection serves nothing. Its final GOAWAY names stream 0, so the client
            // knows none of its streams was processed (Huly QB-91).
            if (_draining && _http2_protocol) {
                _http2_protocol->complete_graceful_shutdown();
                this->ready_to_write();
            }
        } else {
            LOG_HTTP_DEBUG_PA(this->id(), "Switching to HTTP/1.1 protocol.");
            _http1_protocol = this->template switch_protocol<Http1Protocol>(*this);
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
            this->disconnect(qb::http::DisconnectedReason::Undefined); // Consider a more specific reason like NoRouteFound
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
            if (_http2_protocol) {
                _http2_protocol->send_rst_stream(stream_id, qb::protocol::http2::ErrorCode::REFUSED_STREAM,
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
     */
    void
    on([[maybe_unused]] qb::io::async::event::timeout const &event) {
        LOG_HTTP_WARN_PA(this->id(), "Session timed out.");
        this->disconnect(qb::http::DisconnectedReason::ByTimeout);
    }

    /**
     * @brief Handle pending write event
     * @param event Pending write event
     */
    void
    on([[maybe_unused]] qb::io::async::event::pending_write &&event) {
        LOG_HTTP_TRACE_PA(this->id(), "Pending write event, updating timeout.");
        this->updateTimeout();
        // Periodic cleanup of idle streams for DDoS protection
        if (_http2_protocol) {
            reclaim_completed_stream_contexts();
            if (this->protocol() != _http2_protocol || !this->is_connected())
                return;
            auto now = std::chrono::steady_clock::now();
            if (now - _last_stream_cleanup >= constants::CLEANUP_INTERVAL) {
                _http2_protocol->cleanup_idle_streams(constants::STREAM_IDLE_TIMEOUT, constants::STREAM_INCOMPLETE_TIMEOUT);
                _last_stream_cleanup = now;
            }
        }
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
            reclaim_completed_stream_contexts();
        }
    }

    void
    on(qb::io::async::event::extracted &&) {
        LOG_HTTP_DEBUG_PA(this->id(), "HTTP/2 session extracted.");
        // Stop the libev watcher immediately so this event loop stops monitoring
        // the socket before it is moved to another io_handler.
        this->stop();
        for (auto &[stream_id, context] : _contexts) {
            context->cancel("Session extracted");
        }
        _contexts.clear();
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
            this->disconnect(qb::http::DisconnectedReason::ByProtocolError);
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
        // Context for this stream might need to be cleared or marked.
        auto it = _contexts.find(event.stream_id);
        if (it != _contexts.end() && it->second) {
            auto context = std::move(it->second);
            _contexts.erase(it);
            context->cancel("HTTP/2 stream error: " + event.message);
        }
    }

    /**
     * @brief Handle GOAWAY from client
     * @param event GOAWAY details
     */
    void
    on(const qb::protocol::http2::Http2GoAwayEvent &event) {
        LOG_HTTP_WARN_PA(this->id(), "Received GOAWAY from client. Last Stream ID: " << event.last_stream_id
                                                                                     << ", Code: " << static_cast<int>(event.error_code)
                                                                                     << ", Debug: " << event.debug_data);
        // Server may decide to stop accepting new requests on this connection.
        if (event.error_code != qb::protocol::http2::ErrorCode::NO_ERROR) {
            this->disconnect(qb::http::DisconnectedReason::ResponseTransmitted);
        }
    }

    /**
     * @brief Get router reference
     * @return Router reference
     */
    Router &
    router() {
        return this->server().router();
    }
};

/**
 * @brief HTTP/2 I/O handler with routing
 * @tparam Derived CRTP derived type
 * @tparam Session Session type
 */
template <typename Derived, typename Session>
class io_handler : public qb::io::async::io_handler<Derived, Session> {
public:
    using Router = typename qb::http::Router<Session>;

private:
    Router                   _router; ///< HTTP router
    qb::http::request_limits _request_limits{};

public:
    io_handler() {}

    /**
     * @brief Get router reference
     * @return Router reference
     */
    Router &
    router() {
        return _router;
    }

    /**
     * @brief Set the limits this server applies to every request it reads, over both protocols it speaks
     *        (Huly QB-94); 0 in any of them means no limit of that kind.
     *
     * Same call on the HTTP/1.1, HTTP/3 and dual-stack servers. Read live: a request that begins after the
     * call is judged under the new limits. An HTTP/2 request over a limit is answered on its stream -- `414
     * URI Too Long` for its `:path`, `431 Request Header Fields Too Large` for a field name, a field value or
     * the number of fields of its header or trailer section, `413 Content Too Large` for a declared
     * `content-length` (before a byte of the body is read) or for DATA that passes the body limit -- then
     * RST_STREAM(NO_ERROR) asks the client to stop sending the rest (RFC 9113 §8.1); the connection and its
     * other streams go on. Until 3.3 the body was reset with ENHANCE_YOUR_CALM against the HTTP/1.1 constant
     * and the fields had no limit but the 1 MiB HPACK header list, which stays. The HTTP/1.1 requests of this
     * server's ALPN fallback get the HTTP/1.1 answers. The defaults are `qb::http::protocol_limits`' constants.
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
     *   answered, and closes once it is delivered (within qb-io's linger bound), abandoning what is open; any
     *   other session is aborted. With no HTTP session open the report comes before drain() returns; a deadline
     *   of zero or less ends the drain at once.
     *
     * Same contract as the HTTP/1.1 server's drain(). The server cannot listen again afterwards.
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

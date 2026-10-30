/**
 * @file qbm/http/1.1/http.h
 * @brief HTTP/1.1 server and client implementation for qb-io framework
 *
 * This file provides a comprehensive HTTP/1.1 server and client implementation
 * built on top of the qb-io asynchronous framework. It includes:
 *
 * - Complete HTTP/1.1 protocol support with request/response handling
 * - Asynchronous and synchronous client implementations
 * - Full-featured HTTP server with routing capabilities
 * - Session management with timeout handling
 * - Content compression/decompression support (with zlib)
 * - SSL/TLS support for secure HTTPS connections
 * - Event-driven architecture for high performance
 * - Template-based extensibility for custom session types
 *
 * @code
 * // Example HTTP/1.1 server usage:
 * auto server = qb::http::make_server();
 * server->router().get("/api/data", [](auto ctx) {
 *     ctx->response().json({"message": "Hello HTTP/1.1!"});
 *     ctx->complete();
 * });
 * server->listen(qb::io::uri("http://localhost:8080"));
 * @endcode
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once
#ifdef QB_HAS_COMPRESSION
#include <qb/io/compression.h>
#endif
#include <cctype>
#include <concepts>
#include <deque>
#include <optional>
#include <string_view>
#include <type_traits>
#include <utility>
#include "../coro.h"
#include "../detail/drain.h"
#include "../detail/server_tls.h"
#include "../logger.h"
#include "../origin.h"
#include "../routing.h"
#include "./protocol/client.h"
#include "./protocol/server.h"

namespace qb::http {
/**
 * @brief Event types for HTTP session
 *
 * Contains event structures used in the HTTP event-driven architecture.
 * These events facilitate non-blocking I/O operations and session management.
 * The event system enables asynchronous handling of HTTP sessions, allowing
 * the server to process multiple connections simultaneously.
 */
namespace event {
/**
 * @brief End-of-stream event
 *
 * Triggered when all buffered data has been sent.
 * Usually indicates that a response has been fully transmitted.
 * This event allows the application to perform actions once transmission
 * is complete, such as cleaning up resources or initiating follow-up actions.
 */
struct eos {};

/**
 * @brief Disconnection event
 *
 * Triggered when a session is disconnected.
 * Contains the reason for disconnection from DisconnectedReason enum.
 * Applications can use this event to properly handle session termination,
 * such as logging, cleanup, or attempting reconnection when appropriate.
 */
struct disconnected {
    int reason; ///< Disconnection reason code
};

/**
 * @brief Request event
 *
 * Triggered when a complete HTTP request is received.
 * Indicates that the request is ready for processing.
 * This event allows the application to handle incoming requests
 * in an asynchronous manner, without blocking while waiting for requests.
 */
struct request {};

/**
 * @brief Timeout event
 *
 * Triggered when a session times out due to inactivity.
 * Used to clean up resources for idle connections.
 * Timeouts help prevent resource leaks when clients disconnect
 * without properly closing the connection.
 */
struct timeout {};
} // namespace event

namespace internal {
/**
 * @brief Base HTTP session implementation
 * @tparam Derived Derived class type (CRTP pattern)
 * @tparam Transport Transport layer type
 * @tparam TProtocol Protocol template type
 * @tparam Handler Handler type
 *
 * Implements core HTTP session functionality for both client and
 * server side. Handles request processing, timeouts, and transmission.
 */
template <typename Derived, typename Transport, template <typename T> typename TProtocol, typename Handler>
class session
    : public qb::io::async::tcp::client<session<Derived, Transport, TProtocol, Handler>, Transport, Handler>
    , public qb::io::use<session<Derived, Transport, TProtocol, Handler>>::timeout
    , public std::enable_shared_from_this<Derived> {
public:
    using Protocol    = TProtocol<session<Derived, Transport, TProtocol, Handler>>;
    using string_type = typename Protocol::string_type;

private:
    friend qb::io::async::io<session>;
    friend class qb::io::async::io_handler<Handler, Derived>;
    // The detector is befriended whole (Huly QB-1182). io<> probes this base for pending_write, eos and disconnected,
    // but io_handler::extractSession() probes the session it registered -- the concrete type deriving from this one --
    // for extracted: befriended for `session` alone, that handler was invisible there, and no extraction of an
    // HTTP/1.1 session ran it. Befriended whole, the detector sees every on() of this session from a probe on any
    // type, a session registered as a class deriving from the concrete one included.
    template <typename, typename, typename...>
    friend struct ::has_method_on;
    friend Protocol;
    friend qb::io::async::with_timeout<session>;

    using ContextType = Context<Derived>;

    std::shared_ptr<ContextType> _context{};
    std::deque<Request>          _pending_requests{};
    std::optional<Response>      _ready_response{};
    qb::http::method             _active_request_method{qb::http::method::GET};
    bool                         _active_should_keep_alive{false};
    bool                         _keep_alive{false}; ///< Application override for persistent connections
    std::size_t                  _max_pipelined_requests{128};
    int  _refusal_status{0}; ///< The answer owed to a request the parser refused (a limit, a target, Host) once the ones before it are answered
    bool _closing{false};    ///< The connection's last response is published: the io closes once it is delivered
    bool _draining{false};   ///< The server drains (http1_begin_drain()): the last request received is answered `close`
    bool _drain_cut{false};  ///< Closed by the drain while idle: it reports DisconnectedReason::ServerDraining
    /// The active context's incremental body while its head is out and its end() is not (Huly QB-86). Weak: the
    /// producer owns the stream; a stream dropped without end() aborts, which reaches stream_abort().
    std::weak_ptr<ResponseStream<Derived>> _stream{};
    std::size_t                            _stream_high_watermark{qb::http::default_stream_high_watermark};
    bool                                   _stream_live{false}; ///< a streamed head is out and its end() is not: eos does not end the response
    /// The original HTTP/1.1 protocol. An in-place WebSocket upgrade participates through its cold drain hook;
    /// a transport extracted to another owner is no longer this server's.
    qb::io::async::IProtocol const *_http_protocol{nullptr};

    /// The connection's last response is published: the io closes once it is delivered -- after the peer, at most the
    /// session's linger() later (qb-io close_after_deliver(), Huly QB-1089) -- so a peer still sending, a refused
    /// upload's included, reads it before the close; disconnect() at its eos closed at once, which a peer still
    /// sending turns into a reset that can destroy the response before it is read (Huly QB-168). What the peer
    /// sends meanwhile is not read.
    void
    close_after_response() noexcept {
        _closing = true;
        this->close_after_deliver();
    }

    /// A live stream ends with the connection: its producer is told (Huly QB-86).
    void
    cancel_live_stream() noexcept {
        if (!_stream_live)
            return;
        _stream_live = false;
        if (auto stream = _stream.lock())
            stream->cancel();
        _stream.reset();
    }

    [[nodiscard]] static bool
    has_connection_token(qb::http::Headers const &headers, std::string_view token) {
        auto it = headers.headers().find("Connection");
        if (it == headers.headers().end()) {
            return false;
        }
        for (const auto &value : it->second) {
            for (auto part : qb::http::utility::split_string<std::string>(value, ",")) {
                if (qb::http::utility::iequals(qb::http::utility::trim_http_whitespace(part), token)) {
                    return true;
                }
            }
        }
        return false;
    }

    /// Whether the input buffer holds a byte of a request after the one being answered: the protocol tells which bytes
    /// are that request's own while it hands it over (Protocol::dispatching_size()), none are afterwards.
    [[nodiscard]] bool
    another_request_buffered() noexcept {
        return this->in().size() > static_cast<Protocol const *>(_http_protocol)->dispatching_size();
    }

    void
    prepare_response_for_active_request(Response &response) {
        const bool response_closes = has_connection_token(response, "close");
        if (response_closes) {
            _active_should_keep_alive = false;
        }
        // The server drains (Huly QB-167): the answer to the last request received -- none queued behind it, no byte
        // of another one buffered -- closes the connection. A request still arriving keeps it open until it is
        // answered in turn, or the drain's deadline.
        if (_draining && _pending_requests.empty() && !another_request_buffered()) [[unlikely]] {
            _active_should_keep_alive = false;
        }

        if (_active_request_method == qb::http::method::HEAD) {
            // The response to HEAD describes the content a GET would carry (RFC 9110 §9.3.2): the
            // body's length becomes its Content-Length -- unless it already declares its framing,
            // a Transfer-Encoding included (the two never go together, RFC 9112 §6.2).
            if (!response.has_header("Content-Length") && !response.has_header("Transfer-Encoding") && !response.body().empty()) {
                response.set_header("Content-Length", std::to_string(response.body().size()));
            }
            response.body().clear();
        }

        if (!_active_should_keep_alive && !response.has_header("Connection")) {
            response.set_header("Connection", "close");
        } else if (_active_should_keep_alive && _context && _context->request().major_version == 1 && _context->request().minor_version == 0
                   && !response.has_header("Connection")) {
            response.set_header("Connection", "keep-alive");
        }
    }

    void
    drain_ready_response() {
        if (!_context || !_ready_response) {
            return;
        }
        // Serializing the response (*this << response) can throw (oversized
        // response, invalid header). This is reached synchronously from
        // start_request AND asynchronously from send_response (a coroutine/
        // callback completion) — both noexcept contexts. Contain a throw so
        // it cannot escape the noexcept boundary and call std::terminate.
        try {
            auto response = std::move(*_ready_response);
            _ready_response.reset();
            prepare_response_for_active_request(response);
            if (_active_request_method == qb::http::method::HEAD)
                *this << MessageHead{response}; // the header section only: no body, no last-chunk
            else
                *this << response;
            this->updateTimeout();
            if (!_active_should_keep_alive)
                close_after_response();
        } catch (const std::exception &e) {
            LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 response send threw: " << e.what());
            this->disconnect(DisconnectedReason::ServerError);
        } catch (...) {
            LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 response send threw an unknown exception");
            this->disconnect(DisconnectedReason::ServerError);
        }
    }

    void
    start_request(Request &&request) {
        // This runs synchronously from the protocol's noexcept onMessage
        // (and from the noexcept eos event). Routing builds a Context,
        // decodes path parameters, runs lifecycle hooks and the handler
        // chain, and serializes the response — any of which can throw.
        // Contain it here so a throw fails the connection instead of
        // escaping the noexcept boundary and calling std::terminate.
        try {
            _active_request_method    = request.method();
            _active_should_keep_alive = request.keep_alive || _keep_alive;
            _ready_response.reset();

            auto context = this->server().router().route(this->shared_from_this(), std::move(request));
            if (!context) {
                LOG_HTTP_WARN_PA(this->id(), "HTTP/1.1 request not routed, disconnecting.");
                this->disconnect(DisconnectedReason::Undefined);
                return;
            }

            _context = std::move(context);
            drain_ready_response();
        } catch (const std::exception &e) {
            LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 request handling threw: " << e.what());
            this->disconnect(DisconnectedReason::Undefined);
        } catch (...) {
            LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 request handling threw an unknown exception");
            this->disconnect(DisconnectedReason::Undefined);
        }
    }

    /// Answers the request the parser refused (http1_refuse_request()): its status, an empty body,
    /// `Connection: close`. on(eos) closes the connection once it is written.
    void
    send_refusal() {
        const qb::http::Status status{_refusal_status};
        _refusal_status = 0;
        try {
            Response response{status};
            response.set_header("Connection", "close");
            _active_request_method    = qb::http::method::GET; // the answer carries no body either way
            _active_should_keep_alive = false;
            _ready_response.reset();
            *this << response;
            this->updateTimeout();
            close_after_response();
        } catch (const std::exception &e) {
            LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 refusal send threw: " << e.what());
            this->disconnect(DisconnectedReason::ServerError);
        } catch (...) {
            LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 refusal send threw an unknown exception");
            this->disconnect(DisconnectedReason::ServerError);
        }
    }

    void
    start_next_request_if_possible() {
        if (_context) {
            return;
        }
        if (_pending_requests.empty()) {
            if (_refusal_status != 0) [[unlikely]]
                send_refusal(); // every request received before the refused one is answered
            return;
        }
        auto request = std::move(_pending_requests.front());
        _pending_requests.pop_front();
        start_request(std::move(request));
    }

    /**
     * @brief Handle incoming HTTP request
     * @param msg HTTP request message
     *
     * Routes the incoming HTTP request to the appropriate handler.
     * If the request is not routed, the session is disconnected.
     */
    void
    on(typename Protocol::request &&request) {
        LOG_HTTP_INFO_PA(this->id(), "Received HTTP/1.1 request: " << request.method() << " " << request.uri().source());

        if (_context) {
            if (_pending_requests.size() >= _max_pipelined_requests) {
                LOG_HTTP_WARN_PA(this->id(), "HTTP/1.1 pipelined request queue limit reached.");
                this->disconnect(DisconnectedReason::ByProtocolError);
                return;
            }
            _pending_requests.emplace_back(std::move(request));
            LOG_HTTP_DEBUG_PA(this->id(), "HTTP/1.1 request queued behind active response.");
            return;
        }
        start_request(std::move(request));
    }

    /**
     * @brief Handle session timeout
     * @param _ Timeout event information
     *
     * Called when the session timer expires without activity. This method
     * either:
     * 1. Calls the derived class's timeout handler if one exists
     * 2. Disconnects the session with a timeout reason code
     *
     * Timeouts are used to prevent idle connections from consuming
     * server resources indefinitely.
     */
    void
    on([[maybe_unused]] qb::io::async::event::timeout const &) { // handler-access: with_timeout (a friend) calls it
        LOG_HTTP_WARN_PA(this->id(), "HTTP/1.1 session timed out.");

        // disconnect session on timeout
        // add reason for timeout
        if constexpr (qb::has_on<Derived, event::timeout const &>) {
            // User timeout handler runs from a noexcept event dispatch;
            // contain a throw so it cannot call std::terminate.
            try {
                static_cast<Derived &>(*this).on(event::timeout{});
            } catch (const std::exception &e) {
                LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 user timeout handler threw: " << e.what());
                this->disconnect(DisconnectedReason::ByTimeout);
            } catch (...) {
                LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 user timeout handler threw an unknown exception");
                this->disconnect(DisconnectedReason::ByTimeout);
            }
        } else
            this->disconnect(DisconnectedReason::ByTimeout);
    }

    /**
     * @brief Handle pending write operation
     * @param _ Pending write event information
     *
     * Called when data is being written to the client socket. This
     * method updates the session timeout timer to prevent disconnection
     * during active data transfer operations.
     */
    void
    on(qb::io::async::event::pending_write &&pending) {
        LOG_HTTP_TRACE_PA(this->id(), "Pending write event, updating timeout.");
        this->updateTimeout();
        if (_stream_live) {
            if (auto stream = _stream.lock()) // a strong reference for the call (Huly QB-86)
                stream->notify_drain(pending.bytes);
        }
    }

    /**
     * @brief Handle end-of-stream event
     * @param _ End-of-stream event
     *
     * Called when all pending data has been written to the socket.
     * By default, disconnects the session with ResponseTransmitted reason.
     */
    void
    on([[maybe_unused]] qb::io::async::event::eos &&) {
        if (_stream_live) {
            // A streamed response: everything written so far is delivered, the producer may write on. The response
            // ends at the stream's end(), whose last write brings the eos that takes the path below (Huly QB-86).
            if (auto stream = _stream.lock())
                stream->notify_drain(0);
            return;
        }
        LOG_HTTP_DEBUG_PA(this->id(), "End of stream (eos) event - response fully transmitted.");

        // Reached from the noexcept eos event. The POST_RESPONSE_SEND
        // hooks run user code; contain a throw. start_next_request_if_-
        // possible() routes the next pipelined request and is already
        // protected inside start_request().
        try {
            if (_context) {
                _context->execute_hook(HookPoint::POST_RESPONSE_SEND);
                _context.reset();
            }
        } catch (const std::exception &e) {
            LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 POST_RESPONSE_SEND hook threw: " << e.what());
            _context.reset();
        } catch (...) {
            LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 POST_RESPONSE_SEND hook threw an unknown exception");
            _context.reset();
        }
        if (!_active_should_keep_alive) {
            // The io closes after this delivery (close_after_response()); a response that did not go through it
            // still closes here, at once, as before.
            if (!_closing)
                this->disconnect(DisconnectedReason::ResponseTransmitted);
            return;
        }
        start_next_request_if_possible();
    }

    void
    on(qb::io::async::event::extracted &&) {
        LOG_HTTP_DEBUG_PA(this->id(), "HTTP/1.1 session extracted.");
        // Stop the libev watcher immediately so this event loop stops monitoring
        // the socket before it is moved to another io_handler (e.g. a WebSocket
        // server on a different actor).  Without this, the watcher keeps the fd
        // registered in the current backend until the session destructor runs,
        // causing spurious read events to fire in the wrong handler.
        this->stop();
        cancel_live_stream();
        if (_context) {
            _context->cancel(); // no-op when suppress_response() was already called
            _context.reset();
        }
        _pending_requests.clear();
        _ready_response.reset();
        _refusal_status = 0;
    }

    /**
     * @brief Handle disconnection event
     * @param e Disconnection event
     *
     * Called when the session is disconnected. If the response was already
     * received, this should not generate a 410 Gone response.
     */
    void
    on(qb::io::async::event::disconnected &&e) {
        // The close that follows the last response (close_after_response()) ends without a reason of the io's own: it
        // is still the one it always reported.
        if (_closing && e.reason == 0)
            e.reason = _drain_cut ? DisconnectedReason::ServerDraining : DisconnectedReason::ResponseTransmitted;
        if constexpr (qb::has_on<Derived, event::disconnected>) {
            static_cast<Derived &>(*this).on(event::disconnected{e.reason});
        } else {
            static const auto reason = [](auto why) {
                switch (why) {
                    case DisconnectedReason::ByUser:
                        return "by user";
                    case DisconnectedReason::ByTimeout:
                        return "by timeout";
                    case DisconnectedReason::ResponseTransmitted:
                        return "response transmitted";
                    case DisconnectedReason::ServerError:
                        return "server error";
                    default:
                        return "unhandled reason";
                }
            };
            LOG_HTTP_INFO_PA(this->id(), "HTTP/1.1 session disconnected -> " << reason(e.reason));
        }
        if (_stream_live) {
            // The connection ended under a streamed response: the producer is told and the context ends, whatever the
            // reason -- the message can no longer be completed (Huly QB-86).
            cancel_live_stream();
            if (_context && !_context->is_completed())
                _context->cancel("the connection ended during a streamed response");
        }
        if (e.reason == DisconnectedReason::ByUser && _context && !_context->is_completed()) {
            LOG_HTTP_DEBUG_PA(this->id(), "Cancelling incomplete context due to user disconnection.");
            _context->cancel();
        }
        _pending_requests.clear();
        _ready_response.reset();
        _refusal_status = 0;
    }

public:
    using handler_type = Handler;

    /**
     * @brief Default constructor is deleted
     *
     * Sessions must be created with a server reference.
     * This enforces the requirement that each session belongs to a server,
     * ensuring proper lifecycle management and access to server resources.
     */
    session() = delete;

    /**
     * @brief Constructor with server handler
     * @param server Server handler reference
     *
     * Initializes the session with a reference to the server handler,
     * sets the default response, and configures a 60-second timeout.
     * The server handler provides access to shared resources like the router,
     * which is needed to process incoming requests.
     */
    explicit session(Handler &server)
        : qb::io::async::tcp::client<session<Derived, Transport, TProtocol, Handler>, Transport, Handler>(server) {
        LOG_HTTP_DEBUG_PA(this->id(), "HTTP/1.1 session created with 60s timeout.");
        this->setTimeout(std::chrono::seconds(60));
        // The HTTP/1.1 protocol bounds every request itself -- its header limits, the server's body cap --
        // and answers a breach. The transport's generic message cap (QB_MAX_MESSAGE_SIZE, 100 MiB) would
        // cut a request the server accepts with no answer at all: a body at the default cap plus its
        // header section is over it (Huly QB-168). The input-buffer cap (QB_MAX_READ_BUFFER_SIZE) stays.
        this->set_max_message_size(std::numeric_limits<std::size_t>::max());
        _http_protocol = this->protocol(); // the tcp::client base installed it
    }

    /**
     * @brief A session destroyed under a live stream tells its producer, as a disconnection would (Huly QB-86).
     *
     * The io_handler destroys its sessions with the server, without a disconnected event: nothing else would. A parked
     * `drain()` is resumed with `false`; an `on_drain()` callback is deferred, which runs it or releases it with the
     * event loop -- a callback that holds the stream would otherwise keep the stream, and itself, alive for good. The
     * context is not cancelled here: its hooks are user code, and this is a destructor.
     */
    ~session() {
        cancel_live_stream();
    }

    /**
     * @brief Server hook (Huly QB-1182): the session is being extracted -- what its `on(event::extracted)` does: the
     *        watcher stops, the context being answered is cancelled (a no-op after `suppress_response()`) and
     *        released, the queued requests are dropped. The server's extractSession() calls it when io_handler's
     *        probe cannot see that handler: a session class that declares an `on()` of its own -- the
     *        `on(qb::http::event::disconnected &&)` this session forwards to it, say -- hides the base's overloads.
     */
    void
    http1_extracted() {
        on(qb::io::async::event::extracted{});
    }

    /**
     * @brief Server hook (Huly QB-167): whether the session still speaks HTTP/1.1. A session switched to another
     *        protocol is handled by its own shutdown hook when it supports the server's drain.
     */
    [[nodiscard]] bool
    http1_speaks_http() const noexcept {
        return this->protocol() == _http_protocol;
    }

    /**
     * @brief Server hook (Huly QB-167): the server drains. An idle session -- no request being answered, none
     *        queued, no byte of one buffered -- closes now, gracefully: its sending side shut down, what the
     *        client still sends read and dropped until it closes (qb-io's lingering close), reporting
     *        DisconnectedReason::ServerDraining. Otherwise the answer to the last request received carries
     *        `Connection: close` and the connection closes after it. A session already closing, or one that no
     *        longer speaks HTTP/1.1, is left to its own protocol's drain hook.
     */
    void
    http1_begin_drain() noexcept {
        if (_draining)
            return;
        _draining = true;
        if (_closing || this->lingering() || !http1_speaks_http())
            return;
        if (_context || !_pending_requests.empty() || _refusal_status != 0 || this->in().size() != 0)
            return; // work in progress -- a request being handed over included: its last answer closes the connection
        _drain_cut                = true;
        _active_should_keep_alive = false;
        close_after_response();
        this->ready_to_write(); // nothing to deliver: the write path closes at once, after the client
    }

    /// Server hook (Huly QB-167): the drain's deadline came: the session is aborted.
    void
    http1_abort_drain() noexcept {
        this->disconnect(DisconnectedReason::ServerDraining);
    }

    /**
     * @brief Get the context for the session
     * @return Shared pointer to the context
     *
     * Returns a shared pointer to the context for the session.
     * The context contains information about the current request and response.
     */
    [[nodiscard]] std::shared_ptr<Context<Derived>>
    context() const {
        return _context;
    }

    /**
     * @brief Set the keep-alive flag
     * @param value Keep-alive flag value
     *
     * Sets the keep-alive flag for the session. If set to true,
     * the session will not disconnect after sending the response.
     */
    void
    keep_alive(bool value = true) {
        _keep_alive = value;
    }

    void
    max_pipelined_requests(std::size_t value) noexcept {
        _max_pipelined_requests = value;
    }

    /**
     * @brief Protocol hook: the limits of the next request, the server's `request_limits()` read live.
     *
     * The HTTP/1.1 protocol reads them when a request begins (Huly QB-168, QB-94); a server without
     * the setting keeps the defaults, `protocol_limits`' constants. Public because the protocol detects
     * it through a `requires`-expression, which would not see a private member.
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
     * @brief Protocol hook: a request was refused -- 414 for its target, 431 for its fields, 413 for its body or a chunk,
     *        400 for a target that names no resource or a bad Host field, 505 for a version not 1.x (refusal_status(), or llhttp's own).
     * @param status The status that answers it.
     *
     * The answer -- the status, an empty body, `Connection: close` -- goes out once every request
     * received before the refused one is answered, so responses keep their order; the connection
     * closes after it, and the protocol drops what the peer sends meanwhile (Huly QB-168). Public for
     * the same reason as http_request_limits().
     */
    void
    http1_refuse_request(qb::http::Status status) noexcept {
        LOG_HTTP_WARN_PA(this->id(), "HTTP/1.1 request refused with " << status.code() << "; the connection closes after the answer.");
        _refusal_status = status.code();
        if (!_context && _pending_requests.empty())
            send_refusal();
    }

    // --- the streaming hooks of qb::http::ResponseStream (Huly QB-86; the streaming_session concept) ----------------

    /// Whether this session can stream the response to `ctx` now: it answers `ctx`, or `ctx` is the context being
    /// routed for THIS session -- when the handler runs synchronously inside the routing (a middleware, a handler that
    /// does not suspend), start_request() has not stored it yet; stream_head() adopts it. A query: nothing changes,
    /// so a response that ends up buffered keeps the timing of any other.
    [[nodiscard]] bool
    stream_can_answer(ContextType &ctx) {
        if (_stream_live || _closing)
            return false;
        if (_context)
            return _context.get() == &ctx;
        return ctx.session().get() == static_cast<Derived *>(this);
    }

    /// The request being answered is a HEAD: a streamed response sends its head alone.
    [[nodiscard]] bool
    stream_request_is_head() const noexcept {
        return _active_request_method == qb::http::method::HEAD;
    }

    /// Write the head of `ctx.response()` now -- the keep-alive and HEAD rules of any response applied -- adopting
    /// `ctx` when it is the context being routed for this session, and keep the stream to notify. The answer to a
    /// HEAD request is whole at its head: its exchange ends there, as a buffered HEAD's does once written, and the
    /// next request is served when it is delivered; the stream is not kept. `false` when the head could not be
    /// written -- the session can no longer answer `ctx` (a PRE_RESPONSE_SEND hook changed it after
    /// stream_can_answer()), or the serializer refused it: the connection is then closed.
    [[nodiscard]] bool
    stream_head(ContextType &ctx, std::shared_ptr<ResponseStream<Derived>> const &stream) {
        if (!stream_can_answer(ctx)) {
            this->disconnect(DisconnectedReason::ServerError);
            return false;
        }
        if (!_context)
            _context = ctx.shared_from_this(); // start_request()'s own assignment then stores the same object
        try {
            auto &response = ctx.response();
            prepare_response_for_active_request(response);
            *this << MessageHead{response}; // the status line and the header section: the body follows
            this->updateTimeout();
            if (_active_request_method == qb::http::method::HEAD) {
                if (!_active_should_keep_alive)
                    close_after_response();
                return true;
            }
            _stream      = stream;
            _stream_live = true;
            return true;
        } catch (const std::exception &e) {
            LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 streamed response head threw: " << e.what());
        } catch (...) {
            LOG_HTTP_ERROR_PA(this->id(), "HTTP/1.1 streamed response head threw an unknown exception");
        }
        this->disconnect(DisconnectedReason::ServerError);
        return false;
    }

    /// Append a piece of a streamed body. Each piece refreshes the inactivity timeout.
    void
    stream_write(std::string_view bytes) {
        if (!_stream_live)
            return;
        *this << bytes;
        this->updateTimeout();
    }
    void
    stream_write(Chunk const &chunk) {
        if (!_stream_live)
            return;
        *this << chunk;
        this->updateTimeout();
    }

    /// The bytes queued for the socket, not yet written: the session's output buffer (what `pendingWrite()` reads --
    /// the transport is a private base of the tcp client, `out()` is the part of it a session sees).
    [[nodiscard]] std::size_t
    stream_pending() noexcept {
        return this->out().size();
    }

    /// The hard cap of the output: qb-io's write-buffer cap, which `publish()` enforces by disconnecting. A tcp
    /// session cannot change it (`set_max_write_buffer_size` belongs to its transport, a private base), so it is the
    /// transport's default, `QB_MAX_WRITE_BUFFER_SIZE`.
    [[nodiscard]] static constexpr std::size_t
    stream_write_cap() noexcept {
        return QB_MAX_WRITE_BUFFER_SIZE;
    }

    /// The bytes a producer may leave queued before it should wait (1 MiB by default).
    [[nodiscard]] std::size_t
    stream_high_watermark() const noexcept {
        return _stream_high_watermark;
    }
    Derived &
    stream_high_watermark(std::size_t bytes) noexcept {
        _stream_high_watermark = bytes;
        return static_cast<Derived &>(*this);
    }

    /// The end of a streamed body: the last-chunk when chunked, then what follows any response's last byte. The
    /// message may end with nothing left to write (a declared length already delivered): the eos that completes a
    /// response comes only from a write pass, so the write path is armed again -- with nothing queued it finds
    /// nothing to send and reports eos, on every transport (qb-io's stream::write() hands TLS no empty write, Huly
    /// QB-1176), the outcome http1_begin_drain()'s empty arm relies on too.
    void
    stream_end(bool chunked) {
        if (!_stream_live)
            return;
        if (chunked)
            *this << Chunk{};
        _stream_live = false;
        _stream.reset();
        this->updateTimeout();
        // The server drains (Huly QB-167): decided at the head for a request answered then, re-read here for one
        // whose drain began while it streamed. Closing a persistent connection after a complete response is legal.
        if (_draining && _pending_requests.empty() && !another_request_buffered())
            _active_should_keep_alive = false;
        if (!_active_should_keep_alive)
            close_after_response(); // not at the head: the io would have closed once the head drained
        this->ready_to_write();
    }

    /// A streamed body cannot be completed correctly: the context ends now and the connection is closed.
    void
    stream_abort() noexcept {
        if (!_stream_live)
            return;
        _stream_live = false;
        _stream.reset();
        if (_context && !_context->is_completed())
            _context->cancel("the streamed response was aborted");
        this->disconnect(DisconnectedReason::ServerError);
    }

    void
    send_response(ContextType &ctx) {
        if (ctx.is_streaming())
            return; // its head left at begin_stream() and its body through the stream (Huly QB-86)
        if (_context && _context.get() != &ctx) {
            LOG_HTTP_WARN_PA(this->id(), "HTTP/1.1 response completed for a non-active context; closing session.");
            this->disconnect(DisconnectedReason::ServerError);
            return;
        }
        _ready_response = ctx.response();
        drain_ready_response();
    }
};

/**
 * @brief IO handler for HTTP sessions
 * @tparam Derived Derived class type (CRTP pattern)
 * @tparam Session Session type
 *
 * Handles IO operations for HTTP sessions including routing
 * and event dispatching. Maintains the router instance and provides
 * access to it for configuring routes and handling requests.
 *
 * This class follows the Curiously Recurring Template Pattern (CRTP)
 * to allow specialized behavior in derived classes while maintaining
 * static polymorphism for better performance.
 */
template <typename Derived, typename Session>
class io_handler : public qb::io::async::io_handler<Derived, Session> {
public:
    using Router     = typename qb::http::Router<Session>;
    using Route      = typename qb::http::ICustomRoute<Session>;
    using RouteGroup = typename qb::http::RouteGroup<Session>;
    using Controller = typename qb::http::Controller<Session>;
    using Context    = typename qb::http::Context<Session>;

private:
    Router                   _router;
    qb::http::request_limits _request_limits{};

public:
    /**
     * @brief Default constructor
     *
     * Initializes the IO handler with an empty router.
     * The router will need to be configured with routes before
     * the server can handle requests.
     */
    io_handler() = default;

    /**
     * @brief Set the limits this server applies to every request it reads (Huly QB-94); 0 in any of them means
     *        no limit of that kind.
     *
     * Same call on the HTTP/2, HTTP/3 and dual-stack servers. Read live: the next request a session begins is
     * judged under the new limits, one half read keeps the ones it began with. A request over a limit is
     * answered with `Connection: close`, after every request the client sent before it, and the connection
     * closes after that answer: `414 URI Too Long` for its target, `431 Request Header Fields Too Large` for a
     * field name, a field value or the number of fields (trailer fields included), `413 Content Too Large` for
     * its body -- a declared `Content-Length` before a body byte is read, a chunked body when it passes the
     * limit -- or one chunk. Until 3.3 each closed the connection with no answer, against constants. The
     * defaults are `qb::http::protocol_limits`' constants. With a body limit of 0 the transport's input-buffer
     * cap (`QB_MAX_READ_BUFFER_SIZE`) is the only bound left on a body.
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
     * Same name and contract as the HTTP/3 server's (Huly QB-168): a request over it is answered `413 Content
     * Too Large`, as set_request_limits() says. The default is `qb::http::protocol_limits::MAX_BODY_SIZE`
     * (100 MiB).
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

    /**
     * @brief Access the router
     * @return Reference to the router
     *
     * Provides access to the HTTP router for configuring routes
     * and handling HTTP requests. Routes can be added to the router
     * to define how different URI paths should be handled.
     */
    Router &
    router() {
        return _router;
    }
};

/**
 * @brief HTTP server implementation
 * @tparam Derived Derived class type (CRTP pattern)
 * @tparam Session Session type
 * @tparam Transport Transport type for accepting connections
 *
 * Implements an HTTP server that accepts connections and
 * creates sessions to handle requests.
 */
template <typename Derived, typename Session, typename Transport>
class server
    : public qb::io::async::tcp::acceptor<server<Derived, Session, Transport>, Transport>
    , public io_handler<Derived, Session> {
    friend qb::io::async::tcp::acceptor<server<Derived, Session, Transport>, Transport>;
    friend io_handler<Derived, Session>;
    // The acceptor finds on(disconnected) through qb::has_own_on, which sees a private handler
    // only through this friend -- befriending the acceptor is not enough (Huly QB-252).
    friend struct has_method_on<server, void, qb::io::async::event::disconnected>;
    using acceptor_type = qb::io::async::tcp::acceptor<server<Derived, Session, Transport>, Transport>;

    /**
     * @brief Handle new client connection
     * @param new_io Socket IO object for the new connection
     *
     * Called when a new client connects to the server. Creates a new
     * session to handle the client's requests using the provided IO object.
     * The session is registered with the server and started immediately.
     */
    void
    on(typename acceptor_type::accepted_socket_type &&new_io) {
        LOG_HTTP_INFO("New HTTP/1.1 client connection accepted.");
        this->registerSession(std::forward<typename acceptor_type::accepted_socket_type>(new_io));
    }

    /**
     * @brief Handle server disconnection event
     * @param event Disconnection event information
     *
     * Called when the server is disconnected. If the derived class
     * implements a handler for disconnection events, it will be called.
     * Otherwise, a warning is logged.
     */
    void
    on(qb::io::async::event::disconnected &&event) {
        if constexpr (qb::has_on<Derived, event::disconnected>) {
            static_cast<Derived &>(*this).on(event::disconnected{event.reason});
        }
        LOG_HTTP_WARN("HTTP/1.1 server disconnected. Reason: " << event.reason);
    }

    qb::http::detail::drain_state _drain; ///< drain() (Huly QB-167): begun once -- the listener closed -- reported once

    /// Whether the session type has the drain's hooks (this module's session does; a bare qb-io session served by this
    /// server does not, and is waited for as it is, then aborted at the deadline).
    static constexpr bool drainable_sessions = requires(Session &s) {
        s.http1_begin_drain();
        s.http1_abort_drain();
        { s.http1_speaks_http() } -> std::convertible_to<bool>;
    };

    [[nodiscard]] static qb::http::detail::websocket_drain *
    upgraded_drain(Session &session) noexcept {
        if constexpr (requires { session.protocol(); })
            return dynamic_cast<qb::http::detail::websocket_drain *>(session.protocol());
        else
            return nullptr;
    }

    [[nodiscard]] static bool
    participates_in_drain(Session &session) noexcept {
        if constexpr (drainable_sessions)
            return session.http1_speaks_http() || upgraded_drain(session) != nullptr;
        else
            return true;
    }

    /// The drain waits for owned HTTP and upgraded WebSocket sessions, including a lingering close.
    [[nodiscard]] std::size_t
    http_sessions_left() noexcept {
        std::size_t left = 0;
        for (auto const &[id, session] : this->sessions()) {
            if (session && participates_in_drain(*session)) {
                ++left;
            }
        }
        return left;
    }

    void
    drain_deadline_reached() noexcept {
        if (!_drain.pending())
            return;
        for (auto const &[id, session] : this->sessions()) {
            if constexpr (drainable_sessions) {
                if (session && participates_in_drain(*session))
                    session->http1_abort_drain();
            } else if (session) {
                session->disconnect(qb::http::DisconnectedReason::ServerDraining);
            }
        }
        LOG_HTTP_WARN("HTTP/1.1 drain deadline reached: the sessions still open are aborted.");
        _drain.report(qb::http::drain_outcome::deadline, "HTTP/1.1");
    }

public:
    /**
     * @brief Default constructor
     *
     * Initializes the HTTP server with default configurations.
     * The server must be started separately by binding to a port
     * and calling the listen method.
     */
    server() = default;

    /**
     * @brief Drain the server (Huly QB-167): stop taking connections, close the ones that wait, answer the
     *        requests already received, and report when every HTTP session has closed or @p deadline came.
     *
     * - The listening socket is closed: a new connection is refused, and the port is free.
     * - An idle session -- no request being answered, none queued, no byte of one buffered -- closes now,
     *   gracefully: its sending side shut down, what its client still sends dropped until the client closes
     *   (qb-io's lingering close); it reports `DisconnectedReason::ServerDraining`.
     * - A session at work answers every request it has received; the answer to the last one carries
     *   `Connection: close`, and the connection closes after it. A request still arriving is answered in turn.
     * - @p on_drained runs once, on the server's loop: with `drain_outcome::drained` when the last HTTP session has
     *   closed -- a lingering session counts until it is gone -- or with `drain_outcome::deadline` when @p deadline
     *   came first, after aborting the sessions still open (`ServerDraining`). With no HTTP session open it runs
     *   before drain() returns. A deadline of zero or less aborts what is still open at once.
     * - An owned WebSocket upgraded in place receives Close `1001 Going Away` and is counted until it closes or
     *   the deadline aborts it (Huly QB-1097). A connection extracted to another owner remains outside this drain;
     *   its new owner is responsible for closing it.
     *
     * A server of bare qb-io sessions (no drain hooks) closes its listener and waits for them as they are, aborting
     * them at the deadline. The server cannot listen again afterwards. drain_outcome is the HTTP/2 and HTTP/3
     * servers' too.
     * @param deadline   How long the sessions have, from now.
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
            if (session) {
                if (auto *upgraded = upgraded_drain(*session))
                    upgraded->begin_server_drain();
                else if constexpr (drainable_sessions)
                    session->http1_begin_drain();
            }
        }
        if (http_sessions_left() == 0) {
            _drain.report(qb::http::drain_outcome::drained, "HTTP/1.1");
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
            _drain.report(qb::http::drain_outcome::drained, "HTTP/1.1");
    }

    /**
     * @brief Extract a session's transport, as io_handler::extractSession does -- a WebSocket upgrade handing its
     *        connection to another actor. A drain that waited for that session may end: it is no longer this
     *        server's (Huly QB-167).
     * @param ident The session's id.
     * @return The transport and whether the session was found.
     */
    [[nodiscard]] std::pair<typename Session::transport_io_type, bool>
    extractSession(qb::uuid const &ident) {
        // io_handler runs the session's on(event::extracted) itself when its probe sees it. A session class that
        // declares an on() of its own hides that handler from the probe (C++ name hiding): it is run from here
        // then, before the transport leaves, so every HTTP/1.1 session is extracted the same way (Huly QB-1182).
        if constexpr (!qb::has_on<Session, qb::io::async::event::extracted>) {
            const auto it = this->sessions().find(ident);
            if (it != this->sessions().end() && it->second) {
                const auto session = it->second; // its handler may cancel a context whose hooks change the sessions
                session->http1_extracted();
            }
        }
        auto extracted = qb::io::async::io_handler<Derived, Session>::extractSession(ident);
        if (_drain.pending() && http_sessions_left() == 0)
            _drain.report(qb::http::drain_outcome::drained, "HTTP/1.1");
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
     *       shadows `qb::io::async::tcp::acceptor::listen()` only to pin `http/1.1` as the
     *       advertised ALPN — the base takes the list as a parameter and would otherwise be
     *       called with none. Binding and starting is what the base's `listen()` means
     *       ("Auto-start"), so the pair here mirrors the pair there: `listen()` to serve,
     *       `listen_no_start()` when the accept watcher must be armed later.
     *
     *       Until 3.0 this override bound *without* starting, under the base's other name.
     *       Forgetting the second step failed silently and expensively: `listen()` returned
     *       `true`, the port was held so nothing else could take it, and no accept watcher
     *       was ever registered — every client `connect()` hung to its own timeout with
     *       nothing in any log naming the cause. Calling `start()` yourself afterwards is
     *       still correct and still supported: `ev_io_start` returns early on an already
     *       active watcher, so the redundant call is a no-op.
     * @see listen_no_start
     * @see qb::io::async::tcp::acceptor::listen
     */
    [[nodiscard]] bool
    listen(qb::io::uri uri, std::filesystem::path cert_file = {}, std::filesystem::path key_file = {}) {
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
     * shadows it for the same reason `listen()` does: to pin the `http/1.1` ALPN.
     * @see listen
     */
    [[nodiscard]] bool
    listen_no_start(qb::io::uri uri, std::filesystem::path cert_file = {}, std::filesystem::path key_file = {}) {
#ifdef QB_HAS_SSL
        // Declared inside the guard, not above it: the alias is only ever consumed by the
        // if constexpr below. Hoisted out, it is an unused local typedef in every SSL-off
        // translation unit that includes this header -- one declaration, 47 warnings.
        using tpt = std::decay_t<decltype(this->transport())>;
        if constexpr (tpt::is_secure()) {
            if (!reload_certificates(std::move(cert_file), std::move(key_file)))
                return false;
        }
#else
        static_cast<void>(cert_file);
        static_cast<void>(key_file);
#endif
        return !this->transport().listen(std::move(uri));
    }

#ifdef QB_HAS_SSL
    /**
     * @brief Install a fresh TLS configuration for future accepts, pinning ALPN to http/1.1.
     *
     * Call on the listener's owner thread. Invalid configurations return false and leave
     * the listener unchanged. Established and already accepted connections retain their
     * old context, including handshakes not yet begun; no socket is closed or rebound.
     * Context copies share SSL_CTX: supply a fresh, fully configured, unpublished context,
     * never a copy of one already serving connections. This call changes its ALPN list.
     * SNI callbacks are preserved; prepare every context they return with http/1.1 ALPN
     * before publication. Rotation replaces the full configuration and its session cache.
     * TLS server and generic methods are supported, including fresh adopt/share contexts;
     * client-only and DTLS contexts are refused. This checks usability and role, not every
     * handshake prerequisite: the caller provides identity, SNI and/or custom authentication.
     */
    [[nodiscard]] bool
    set_tls_context(qb::io::ssl::Context context)
    requires(Transport::is_secure())
    {
        return qb::http::detail::set_server_tls_context(this->transport(), std::move(context), false);
    }

    /**
     * @brief Load a new certificate/key with Context::server defaults, then install it.
     *
     * Synchronous cold operation; failure keeps the serving context. This replaces ALL
     * configuration: mTLS policy, cipher settings, callbacks and session cache are not
     * retained. For custom policy, build a fresh Context and use set_tls_context instead.
     */
    [[nodiscard]] bool
    reload_certificates(std::filesystem::path cert_file, std::filesystem::path key_file)
    requires(Transport::is_secure())
    {
        return set_tls_context(qb::io::ssl::Context::server(std::move(cert_file), std::move(key_file)));
    }

    /** @brief Install a fresh Context, bind and start accepting. See set_tls_context for ownership and SNI. */
    template <typename TLSContext>
    requires(Transport::is_secure() && std::same_as<std::remove_cvref_t<TLSContext>, qb::io::ssl::Context>)
    [[nodiscard]] bool
    listen(qb::io::uri uri, TLSContext &&context) {
        if (!listen_no_start(std::move(uri), std::forward<TLSContext>(context)))
            return false;
        this->start();
        return true;
    }

    /** @brief Install a fresh Context and bind, deferring accepts until start(). */
    template <typename TLSContext>
    requires(Transport::is_secure() && std::same_as<std::remove_cvref_t<TLSContext>, qb::io::ssl::Context>)
    [[nodiscard]] bool
    listen_no_start(qb::io::uri uri, TLSContext &&context) {
        return set_tls_context(std::forward<TLSContext>(context)) && !this->transport().listen(std::move(uri));
    }
#endif
};

template <typename IO_Handler, bool has_server = IO_Handler::has_server>
struct side {
    using protocol = qb::protocol::http::server<IO_Handler>;
};

/**
 * @brief Protocol selector specialization for client-side IO handlers
 * @tparam IO_Handler The IO handler type
 *
 * Selects client protocol implementations for client-side IO handlers.
 */
template <typename IO_Handler>
struct side<IO_Handler, false> {
    using protocol = qb::protocol::http::client<IO_Handler>;
};
} // namespace internal

/**
 * @brief Get the appropriate protocol type for an IO handler
 * @tparam IO_Handler The IO handler type
 */
template <typename IO_Handler>
using protocol = typename internal::side<IO_Handler>::protocol;

/**
 * @brief Asynchronous HTTP client implementation namespace
 *
 * Contains classes and functions for asynchronous HTTP client operations.
 * This namespace provides a complete asynchronous HTTP client implementation
 * using the QB Actor Framework's event-driven I/O system. Key features include:
 *
 * - Non-blocking HTTP request/response processing
 * - Support for both HTTP and HTTPS connections
 * - Automatic content compression/decompression
 * - Timeouts and connection management
 * - Callback-based response handling
 * - Exception safety and error handling
 * - Request/response pipeline management
 *
 * The implementation follows HTTP/1.1 standards and provides both high-level
 * convenience functions for common HTTP methods (GET, POST, etc.) and
 * low-level session management for advanced use cases.
 */
namespace async {
/**
 * @brief HTTP reply container
 *
 * Contains both the original request and the server's response.
 */
struct Reply {
    Request  request;
    Response response;
};

/**
 * @brief HTTP session implementation
 * @tparam Func Callback function type
 * @tparam Transport Transport layer type
 *
 * Handles an HTTP client session, including connection establishment,
 * request transmission, and response handling.
 *
 * The callback runs EXACTLY once: with the response, with 504 on a timeout, with 503 when
 * the connection cannot be made, with 400 when the request cannot be put on the wire, and
 * with 502 when the session is disposed before any of those -- a peer close before a
 * complete response, a protocol error, a read limit. A response delimited by the connection
 * close (no Content-Length, no Transfer-Encoding, RFC 9112 §6.3) is complete at EOF and is
 * delivered then (Huly QB-507).
 */
template <typename Func, typename Transport>
class session
    : public io::async::tcp::client<session<Func, Transport>, Transport>
    , public io::use<session<Func, Transport>>::timeout {
public:
    using http_protocol = http::protocol<session<Func, Transport>>;

private:
    Func           _func;
    Request        _request;
    http_protocol *_http_protocol = nullptr; ///< Typed handle, for the EOF delivery of a close-delimited response
    bool           _answered      = false;   ///< The callback ran; it never runs twice
    bool           _flushing_eof  = false;   ///< Inside the EOF delivery, which a disposal is already tearing down

    /// Run the callback, at most once.
    void
    answer(Response &&response) {
        if (_answered)
            return;
        _answered = true;
        _func(Reply{std::move(_request), std::move(response)});
    }

public:
    /**
     * @brief Constructor
     * @param func Callback function for the response
     * @param request HTTP request to send
     */
    session(Func &&func, Request &request)
        : _func(std::forward<Func>(func))
        , _request(std::move([](auto &req) -> auto & {
            if (!req.has_header("User-Agent"))
                req.headers()["User-Agent"] = {std::string(default_user_agent)};
            req.headers()["Accept-Encoding"] = {accept_encoding()};
            return req;
        }(request))) {
        LOG_HTTP_DEBUG("HTTP/1.1 client session created for " << _request.method() << " " << _request.uri().source());
        _http_protocol = this->template switch_protocol<http_protocol>(*this);
        this->setTimeout(qb::duration::zero());
    }

    ~session() = default;

    [[nodiscard]] bool
    http1_response_body_forbidden() const noexcept {
        return _request.method() == qb::http::Method::HEAD;
    }

    /**
     * @brief Connect to a remote server
     * @param remote URI to connect to
     * @param timeout Connection timeout
     */
    void
    connect(qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
        LOG_HTTP_INFO("HTTP/1.1 client connecting to " << _request.uri().source() << " with timeout " << qb::detail::to_ev_seconds(timeout)
                                                       << "s");

        qb::io::async::tcp::connect<typename Transport::transport_io_type>(
            _request.uri(),
            [this, timeout, remote_uri = _request.uri().source()](auto &&transport) {
                if (!transport.is_open()) {
                    LOG_HTTP_ERROR("HTTP/1.1 client connection failed to " << remote_uri);
                    Response response;
                    response.status() = qb::http::status::SERVICE_UNAVAILABLE;

                    answer(std::move(response));
                    delete this;
                } else {
                    LOG_HTTP_DEBUG("HTTP/1.1 client connection established to " << remote_uri);
                    this->transport() = std::forward<decltype(transport)>(transport);
                    this->start();
                    // Compressing and serializing can refuse the request (an unknown coding, a header or a
                    // request-target the serializer rejects). That is this request's answer, given here:
                    // the exception must not leave the connect completion.
                    try {
#ifdef QB_HAS_COMPRESSION
                        if (_request.has_header("Content-Encoding")) {
                            LOG_HTTP_DEBUG("Compressing request body with " << _request.header("Content-Encoding"));
                            _request.body().compress(_request.header("Content-Encoding"));
                        }
#else
                        _request.remove_header("Content-Encoding");
#endif
                        LOG_HTTP_DEBUG("Sending HTTP/1.1 request: " << _request.method() << " " << _request.uri().source());
                        *this << _request;
                    } catch (std::exception const &e) {
                        LOG_HTTP_ERROR("HTTP/1.1 client cannot send the request: " << e.what());
                        answer(Response{qb::http::status::BAD_REQUEST});
                        this->disconnect(1);
                        return;
                    }
                    this->setTimeout(timeout);
                }
            },
            timeout, verify_peer);
    }

    /**
     * @brief Handle response event
     * @param event Response event
     */
    void
    on(typename http_protocol::response response) {
        const auto status = response.status().code();
        if (status >= 100 && status < 200 && status != 101) [[unlikely]] {
            // Keep this session and its deadline alive until the final response (RFC 9110 section 15.2).
            return;
        }
        LOG_HTTP_INFO("HTTP/1.1 client received response. Status: " << response.status().code());

#ifdef QB_HAS_COMPRESSION
        try {
            if (response.has_header("Content-Encoding")) {
                LOG_HTTP_DEBUG("Decompressing response body with " << response.header("Content-Encoding"));
                response.body().uncompress(response.header("Content-Encoding"));
            }
        } catch (std::exception &e) {
            LOG_HTTP_WARN("Failed to decompress response: " << e.what());
            response.status() = qb::http::status::BAD_REQUEST;
        }
#endif
        answer(std::move(response));
        if (!_flushing_eof)
            this->disconnect(1);
    }

    /**
     * @brief Handle timeout event
     * @param event Timeout event
     */
    void
    on(qb::io::async::event::timeout const &) {
        LOG_HTTP_WARN("HTTP/1.1 client request timed out.");
        answer(Response{qb::http::status::GATEWAY_TIMEOUT});
        this->disconnect(2);
    }

    /**
     * @brief Handle disconnection event
     * @param event Disconnection event
     *
     * Every disposal passes here before on(dispose). A peer close (reason 0) first completes a
     * close-delimited response the protocol has buffered; flush_eof() never delivers a failed or
     * oversized message. A session still unanswered then -- whatever the reason -- answers 502.
     */
    void
    on(qb::io::async::event::disconnected const &event) {
        if (!_answered && !event.reason && _http_protocol) {
            _flushing_eof = true;
            _http_protocol->flush_eof(); // dispatches to on(response) when a close-delimited body is pending
            _flushing_eof = false;
        }
        if (!_answered) {
            LOG_HTTP_WARN("HTTP/1.1 client disconnected before a complete response. Reason: " << event.reason);
            answer(Response{qb::http::status::BAD_GATEWAY});
        } else {
            LOG_HTTP_DEBUG("HTTP/1.1 client disconnected. Reason: " << event.reason);
        }
    }

    /**
     * @brief Handle disposal event
     * @param event Disposal event
     */
    void
    on(qb::io::async::event::dispose const &) {
        LOG_HTTP_DEBUG("HTTP/1.1 client session disposed.");
        delete this;
    }
};

// These are the session types for HTTP and HTTPS connections.
// The _Func template parameter is the type of the callback function
// that will be invoked with an async::Reply.
template <typename Func>
using HTTP = session<Func, qb::io::transport::tcp>;

#if QB_HAS_SSL
template <typename Func>
using HTTPS = session<Func, qb::io::transport::stcp>;
#endif // QB_HAS_SSL

} // namespace async

/**
 * @brief Compute the value for the HTTP @c Host header derived from @p uri:
 *        qb::http::origin::authority, the authority every protocol writes (Huly QB-1064).
 *
 * The host is bracketed when it is an IPv6 literal, whose zone identifier is left out, and the
 * port is appended only when it is non-default for the URI scheme (http and ws 80, https and wss
 * 443 are omitted). The scheme is compared case-insensitively (ASCII).
 *
 * @param uri The source URI to derive the @c Host header value from.
 * @return The @c Host header value (host, optionally bracketed, with a
 *         non-default port appended).
 */
[[nodiscard]] std::string host_header_value(const qb::io::uri &uri);

namespace detail {
template <typename _Func>
void
_execute_async_request_internal(Request request, _Func &&func, qb::duration timeout, const char *method_name_for_log, bool verify_peer = true) {
    if (!request.has_header("host")) {
        request.set_header("host", host_header_value(request.uri()));
    }
    const auto scheme   = request.uri().scheme();
    const bool is_https = origin::scheme_eq(scheme, "https");
    if (!is_https && !origin::scheme_eq(scheme, "http")) {
        std::forward<_Func>(func)(async::Reply{std::move(request), Response{qb::http::status::BAD_REQUEST}});
        return;
    }
#if !QB_HAS_SSL
    if (is_https) {
        std::forward<_Func>(func)(async::Reply{std::move(request), Response{qb::http::status::SERVICE_UNAVAILABLE}});
        return;
    }
#endif
    LOG_HTTP_DEBUG("Executing HTTP/1.1 " << method_name_for_log << " request: " << request.method() << " " << request.uri().source());
#if QB_HAS_SSL
    if (is_https) {
        (new async::HTTPS<_Func>(std::forward<_Func>(func), request))->connect(timeout, verify_peer);
    } else {
        (new async::HTTP<_Func>(std::forward<_Func>(func), request))->connect(timeout, verify_peer);
    }
#else
    (new async::HTTP<_Func>(std::forward<_Func>(func), request))->connect(timeout, verify_peer);
#endif
}
} // namespace detail

// --- Asynchronous HTTP Client Functions ---

/**
 * @brief Sends a generic HTTP/1.1 request asynchronously.
 * The HTTP method should be pre-set on the Request object.
 * @tparam _Func Callable type for the response callback. Signature: void(qb::http::async::Reply&&)
 * @param request The HTTP request object.
 * @param func The callback function to handle the response.
 * @param timeout Connect and inactivity timeout (a `qb::duration`); zero, the default, disables it.
 */
template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply &&>, void>
REQUEST(Request request, _Func &&func, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "Generic", verify_peer);
}

/**
 * @brief Sends an HTTP GET request asynchronously.
 * @tparam _Func Callable type for the response callback.
 * @param request The HTTP request object. Its method will be set to GET.
 * @param func The callback function.
 * @param timeout Optional timeout.
 */
template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply &&>, void>
GET(Request request, _Func &&func, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    request.method() = qb::http::Method::GET;
    detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "GET", verify_peer);
}

/**
 * @brief Sends an HTTP POST request asynchronously.
 * @tparam _Func Callable type for the response callback.
 * @param request The HTTP request object. Its method will be set to POST.
 * @param func The callback function.
 * @param timeout Optional timeout.
 */
template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply &&>, void>
POST(Request request, _Func &&func, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    request.method() = qb::http::Method::POST;
    detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "POST", verify_peer);
}

/**
 * @brief Sends an HTTP PUT request asynchronously.
 * @tparam _Func Callable type for the response callback.
 * @param request The HTTP request object. Its method will be set to PUT.
 * @param func The callback function.
 * @param timeout Optional timeout.
 */
template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply &&>, void>
PUT(Request request, _Func &&func, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    request.method() = qb::http::Method::PUT;
    detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "PUT", verify_peer);
}

/**
 * @brief Sends an HTTP DELETE request asynchronously.
 * @tparam _Func Callable type for the response callback.
 * @param request The HTTP request object. Its method will be set to DELETE.
 * @param func The callback function.
 * @param timeout Optional timeout.
 */
template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply &&>, void>
DEL(Request request, _Func &&func, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    request.method() = qb::http::Method::DEL;
    detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "DELETE", verify_peer);
}

/**
 * @brief Sends an HTTP HEAD request asynchronously.
 * @tparam _Func Callable type for the response callback.
 * @param request The HTTP request object. Its method will be set to HEAD.
 * @param func The callback function.
 * @param timeout Optional timeout.
 */
template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply &&>, void>
HEAD(Request request, _Func &&func, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    request.method() = qb::http::Method::HEAD;
    detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "HEAD", verify_peer);
}

/**
 * @brief Sends an HTTP OPTIONS request asynchronously.
 * @tparam _Func Callable type for the response callback.
 * @param request The HTTP request object. Its method will be set to OPTIONS.
 * @param func The callback function.
 * @param timeout Optional timeout.
 */
template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply &&>, void>
OPTIONS(Request request, _Func &&func, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    request.method() = qb::http::Method::OPTIONS;
    detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "OPTIONS", verify_peer);
}

/**
 * @brief Sends an HTTP PATCH request asynchronously.
 * @tparam _Func Callable type for the response callback.
 * @param request The HTTP request object. Its method will be set to PATCH.
 * @param func The callback function.
 * @param timeout Optional timeout.
 */
template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply &&>, void>
PATCH(Request request, _Func &&func, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    request.method() = qb::http::Method::PATCH;
    detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "PATCH", verify_peer);
}

// --- Coroutine HTTP/1.1 Client Functions ----------------------------------
//
// These overloads replace the former synchronous blocking helpers
// (`Response qb::http::GET(Request, double)` &hellip;). They return an
// `async::awaiter<async::Reply>` that must be driven by a coroutine runtime:
//
//   - From a coroutine:  `auto reply = co_await qb::http::GET(request);`
//   - From a test/main:  `auto reply = qb::http::run_sync(qb::http::GET(request));`
//
// Overload resolution is unambiguous with the callback-based async API:
//     qb::http::GET(Request, _Func, double)    // 3-arg, callback-style
//     qb::http::GET(Request, double)           // 2-arg, coroutine-style
// --------------------------------------------------------------------------

namespace detail {
/// Bridge a callback-async `qb::http::async::*`-style function into an
/// `async::awaiter<async::Reply>`. Each of the eight overloads below
/// simply forwards to the appropriate method.
template <typename AsyncOp>
[[nodiscard]] inline async::awaiter<async::Reply>
_co_invoke(AsyncOp op, Request request, qb::duration timeout) {
    return async::make_awaiter<async::Reply>(
        [op = std::move(op), req = std::move(request), timeout](std::function<void(async::Reply &&)> complete) mutable {
            op(std::move(req), [complete = std::move(complete)](async::Reply &&reply) mutable { complete(std::move(reply)); }, timeout);
        });
}
} // namespace detail

/**
 * @brief Coroutine-style HTTP/1.1 request.
 *
 * The HTTP method must be pre-set on @p request.
 *
 * @param request  Fully-formed request (uri, method, headers, body).
 * @param timeout  Connect and inactivity timeout (a `qb::duration`); zero means "no timeout".
 * @return An awaitable that yields `async::Reply` (original request + response).
 */
[[nodiscard]] inline async::awaiter<async::Reply>
REQUEST(Request request, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    return detail::_co_invoke([verify_peer](Request r, auto cb, qb::duration t) { REQUEST(std::move(r), std::move(cb), t, verify_peer); },
                              std::move(request), timeout);
}

/// @brief Coroutine-style HTTP GET. See `REQUEST` for the contract.
[[nodiscard]] inline async::awaiter<async::Reply>
GET(Request request, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    return detail::_co_invoke([verify_peer](Request r, auto cb, qb::duration t) { GET(std::move(r), std::move(cb), t, verify_peer); },
                              std::move(request), timeout);
}

/// @brief Coroutine-style HTTP POST. See `REQUEST` for the contract.
[[nodiscard]] inline async::awaiter<async::Reply>
POST(Request request, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    return detail::_co_invoke([verify_peer](Request r, auto cb, qb::duration t) { POST(std::move(r), std::move(cb), t, verify_peer); },
                              std::move(request), timeout);
}

/// @brief Coroutine-style HTTP PUT. See `REQUEST` for the contract.
[[nodiscard]] inline async::awaiter<async::Reply>
PUT(Request request, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    return detail::_co_invoke([verify_peer](Request r, auto cb, qb::duration t) { PUT(std::move(r), std::move(cb), t, verify_peer); },
                              std::move(request), timeout);
}

/// @brief Coroutine-style HTTP DELETE. See `REQUEST` for the contract.
[[nodiscard]] inline async::awaiter<async::Reply>
DEL(Request request, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    return detail::_co_invoke([verify_peer](Request r, auto cb, qb::duration t) { DEL(std::move(r), std::move(cb), t, verify_peer); },
                              std::move(request), timeout);
}

/// @brief Coroutine-style HTTP HEAD. See `REQUEST` for the contract.
[[nodiscard]] inline async::awaiter<async::Reply>
HEAD(Request request, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    return detail::_co_invoke([verify_peer](Request r, auto cb, qb::duration t) { HEAD(std::move(r), std::move(cb), t, verify_peer); },
                              std::move(request), timeout);
}

/// @brief Coroutine-style HTTP OPTIONS. See `REQUEST` for the contract.
[[nodiscard]] inline async::awaiter<async::Reply>
OPTIONS(Request request, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    return detail::_co_invoke([verify_peer](Request r, auto cb, qb::duration t) { OPTIONS(std::move(r), std::move(cb), t, verify_peer); },
                              std::move(request), timeout);
}

/// @brief Coroutine-style HTTP PATCH. See `REQUEST` for the contract.
[[nodiscard]] inline async::awaiter<async::Reply>
PATCH(Request request, qb::duration timeout = qb::duration::zero(), bool verify_peer = true) {
    return detail::_co_invoke([verify_peer](Request r, auto cb, qb::duration t) { PATCH(std::move(r), std::move(cb), t, verify_peer); },
                              std::move(request), timeout);
}

} // namespace qb::http

namespace qb::http {
/**
 * @brief HTTP server/client session utility namespace
 *
 * This namespace provides template utilities for creating HTTP server and client
 * sessions with different transport options.
 *
 * @tparam T The type implementing the session
 */
template <typename Derived>
struct use {
    /**
     * @brief Standard TCP HTTP session type
     * @tparam Server Server handler type
     */
    template <typename Server>
    using session = internal::session<Derived, qb::io::transport::tcp, qb::protocol::http::server, Server>;

    /**
     * @brief Standard HTTP IO handler
     * @tparam Session Session type
     */
    template <typename Session>
    using io_handler = internal::io_handler<Derived, Session>;

    /**
     * @brief Standard HTTP server
     * @tparam Session Session type
     */
    template <typename Session>
    using server = internal::server<Derived, Session, qb::io::transport::accept>;

#if QB_HAS_SSL
    /**
     * @brief SSL/TLS transport types for secure HTTP
     */
    struct ssl {
        /**
         * @brief Secure HTTPS session type
         * @tparam Server Server handler type
         */
        template <typename Server>
        using session = internal::session<Derived, qb::io::transport::stcp, qb::protocol::http::server, Server>;

        /**
         * @brief Secure HTTPS IO handler
         * @tparam Session Session type
         */
        template <typename Session>
        using io_handler = internal::io_handler<Derived, Session>;

        /**
         * @brief Secure HTTPS server
         * @tparam Session Session type
         */
        template <typename Session>
        using server = internal::server<Derived, Session, qb::io::transport::saccept>;
    };
#endif // QB_HAS_SSL
};
} // namespace qb::http

// --- HTTP/1.1 Server Factory ---

// Forward declaration for Server to be used in DefaultSession's definition
namespace qb::http {

template <typename SessionType>
class Server;

/**
 * @brief Default session implementation for HTTP/1.1 servers.
 *
 * This session type is used by `qb::http::Server` by default for non-SSL connections.
 * It derives from the internal HTTP/1.1 session machinery.
 */
class DefaultSession : public qb::http::use<DefaultSession>::session<Server<DefaultSession>> {
public:
    using Base = qb::http::use<DefaultSession>::session<Server<DefaultSession>>;
    /**
     * @brief Constructs a DefaultSession.
     * @param server_handler Reference to the server instance that owns this session.
     */
    explicit DefaultSession(Server<DefaultSession> &server_handler)
        : Base(server_handler) {}
};

// io_handler::extractSession() runs a session's extracted handler only when its probe sees it: a session that stopped
// being seen would keep watching a socket it gave away and never cancel its context, silently (Huly QB-1182).
static_assert(qb::has_on<DefaultSession, qb::io::async::event::extracted>, "the HTTP/1.1 session's extracted handler must be visible");

/**
 * @brief Generic HTTP/1.1 application server.
 *
 * This class template serves as the base for HTTP/1.1 servers.
 * It uses CRTP with the SessionType.
 *
 * @tparam SessionType The type of session this server will manage (e.g., DefaultSession).
 */
template <typename SessionType = DefaultSession>
class Server : public qb::http::use<Server<SessionType>>::template server<SessionType> {
public:
    Server() = default;

    /**
     * @brief Provides access to the router.
     * @return A reference to the internal HTTP router.
     */
    qb::http::Router<SessionType> &
    router() {
        return qb::http::internal::io_handler<Server, SessionType>::router();
    }
};

/**
 * @brief Factory function to create an HTTP/1.1 server instance.
 *
 * @tparam Session The session type to use. Defaults to `qb::http::DefaultSession`.
 * @return A `std::unique_ptr` to the created server.
 */
template <typename Session = DefaultSession>
[[nodiscard]] std::unique_ptr<Server<Session>>
make_server() {
    return std::make_unique<Server<Session>>();
}

/**
 * @brief Alias for the HTTP/1.1 server type, allowing custom session.
 * @tparam Session The session type to use. Defaults to `qb::http::DefaultSession`.
 */
template <typename Session = DefaultSession>
using server = Server<Session>;

// The HTTP/1.1 session streams (Huly QB-86). A session that stopped satisfying the hooks would answer every
// begin_stream() with a buffered stream, silently: a compile error instead.
static_assert(streaming_session<DefaultSession>, "the HTTP/1.1 session must offer ResponseStream's hooks");

#if QB_HAS_SSL
namespace ssl {
template <typename SessionType>
class Server;
/**
 * @brief Default session implementation for secure HTTPS/1.1 servers.
 *
 * This session type is used by `qb::http::ssl::Server` by default for SSL connections.
 * It derives from the internal HTTP/1.1 session machinery, configured for secure transport.
 */
class DefaultSecureSession : public qb::http::use<DefaultSecureSession>::ssl::session<Server<DefaultSecureSession>> {
public:
    using Base = qb::http::use<DefaultSecureSession>::ssl::session<Server<DefaultSecureSession>>;
    /**
     * @brief Constructs a DefaultSecureSession.
     * @param server_handler Reference to the server instance that owns this session.
     */
    explicit DefaultSecureSession(Server<DefaultSecureSession> &server_handler)
        : Base(server_handler) {}
};

static_assert(qb::has_on<DefaultSecureSession, qb::io::async::event::extracted>,
              "the HTTPS/1.1 session's extracted handler must be visible (Huly QB-1182)");

/**
 * @brief Generic HTTP/1.1 application server.
 *
 * This class template serves as the base for HTTP/1.1 servers.
 * It uses CRTP with the SessionType.
 *
 * @tparam SessionType The type of session this server will manage (e.g., DefaultSession).
 */
template <typename SessionType = DefaultSecureSession>
class Server : public qb::http::use<Server<SessionType>>::ssl::template server<SessionType> {
public:
    Server() = default;

    /**
     * @brief Provides access to the router.
     * @return A reference to the internal HTTP router.
     */
    qb::http::Router<SessionType> &
    router() {
        return qb::http::internal::io_handler<Server, SessionType>::router();
    }

    /**
     * @brief Provides const access to the router.
     * @return A const reference to the internal HTTP router.
     */
    const qb::http::Router<SessionType> &
    router() const {
        return qb::http::internal::io_handler<Server, SessionType>::router();
    }
};
/**
 * @brief Factory function to create a secure HTTPS/1.1 server instance.
 *
 * @tparam Session The session type to use. Defaults to `qb::http::DefaultSecureSession`.
 * @return A `std::unique_ptr` to the created server.
 */
template <typename Session = DefaultSecureSession>
[[nodiscard]] std::unique_ptr<Server<Session>>
make_server() {
    return std::make_unique<Server<Session>>();
}

/**
 * @brief Alias for the HTTPS/1.1 server type, allowing custom session.
 * @tparam Session The session type to use. Defaults to `qb::http::DefaultSecureSession`.
 */
template <typename Session = DefaultSecureSession>
using server = Server<Session>;

static_assert(streaming_session<DefaultSecureSession>, "the HTTPS/1.1 session must offer ResponseStream's hooks");
} // namespace ssl
#endif // QB_HAS_SSL

} // namespace qb::http

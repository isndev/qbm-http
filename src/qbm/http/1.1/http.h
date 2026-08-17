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
#include <deque>
#include <optional>
#include <string_view>
#include "../coro.h"
#include "../logger.h"
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
    friend struct has_method_on<session, void, qb::io::async::event::pending_write>;
    friend struct has_method_on<session, void, qb::io::async::event::eos>;
    friend struct has_method_on<session, void, qb::io::async::event::extracted>;
    friend struct has_method_on<session, void, qb::io::async::event::disconnected>;
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

    void
    prepare_response_for_active_request(Response &response) {
        const bool response_closes = has_connection_token(response, "close");
        if (response_closes) {
            _active_should_keep_alive = false;
        }

        if (_active_request_method == qb::http::method::HEAD) {
            if (!response.has_header("Content-Length") && !response.body().empty()) {
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
            *this << response;
            this->updateTimeout();
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

    void
    start_next_request_if_possible() {
        if (_context || _pending_requests.empty()) {
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
    on([[maybe_unused]] qb::io::async::event::timeout const &) {
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
    on([[maybe_unused]] qb::io::async::event::pending_write &&) {
        LOG_HTTP_TRACE_PA(this->id(), "Pending write event, updating timeout.");
        this->updateTimeout();
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
        if (_context) {
            _context->cancel(); // no-op when suppress_response() was already called
            _context.reset();
        }
        _pending_requests.clear();
        _ready_response.reset();
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
        if (e.reason == DisconnectedReason::ByUser && _context && !_context->is_completed()) {
            LOG_HTTP_DEBUG_PA(this->id(), "Cancelling incomplete context due to user disconnection.");
            _context->cancel();
        }
        _pending_requests.clear();
        _ready_response.reset();
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

    void
    send_response(ContextType &ctx) {
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
    Router _router;

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
     *       still correct and still supported: `qev_io_start` returns early on an already
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
            this->transport().init(qb::io::ssl::Context::server(std::move(cert_file), std::move(key_file)).alpn({"http/1.1"}));
            if (!this->transport().context().ok()) {
                LOG_HTTP_ERROR("Failed to initialize SSL/TLS server context: " << this->transport().context().error());
                return false;
            }
        }
#else
        static_cast<void>(cert_file);
        static_cast<void>(key_file);
#endif
        return !this->transport().listen(std::move(uri));
    }
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
 */
template <typename Func, typename Transport>
class session
    : public io::async::tcp::client<session<Func, Transport>, Transport>
    , public io::use<session<Func, Transport>>::timeout {
    Func    _func;
    Request _request;

public:
    using http_protocol = http::protocol<session<Func, Transport>>;

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
        this->template switch_protocol<http_protocol>(*this);
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

                    _func(Reply{std::move(_request), std::move(response)});
                    delete this;
                } else {
                    LOG_HTTP_DEBUG("HTTP/1.1 client connection established to " << remote_uri);
                    this->transport() = std::forward<decltype(transport)>(transport);
                    this->start();
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
        _func(Reply{std::move(_request), std::move(response)});
        this->disconnect(1);
    }

    /**
     * @brief Handle timeout event
     * @param event Timeout event
     */
    void
    on(qb::io::async::event::timeout const &) {
        LOG_HTTP_WARN("HTTP/1.1 client request timed out.");
        _func(Reply{std::move(_request), Response{qb::http::status::GATEWAY_TIMEOUT}});
        this->disconnect(2);
    }

    /**
     * @brief Handle disconnection event
     * @param event Disconnection event
     */
    void
    on(qb::io::async::event::disconnected const &event) {
        if (!event.reason) {
            LOG_HTTP_WARN("HTTP/1.1 client disconnected unexpectedly by peer.");
            _func(Reply{std::move(_request), Response{qb::http::status::BAD_GATEWAY}});
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
 * @brief Compute the value for the HTTP @c Host header derived from @p uri.
 *
 * The host is bracketed when it is an unbracketed IPv6 literal, and the port is
 * appended only when it is non-default for the URI scheme (the @c http:80 and
 * @c https:443 default ports are omitted). The scheme is compared
 * case-insensitively (ASCII).
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
    LOG_HTTP_DEBUG("Executing HTTP/1.1 " << method_name_for_log << " request: " << request.method() << " " << request.uri().source());
#if QB_HAS_SSL
    if (request.uri().scheme() == "https") {
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
 * @param timeout Optional timeout in seconds for the request.
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
 * @param timeout  Socket timeout in seconds; 0 means "no timeout".
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

} // namespace ssl
#endif // QB_HAS_SSL

} // namespace qb::http

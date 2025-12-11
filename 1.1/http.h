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
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once
#ifdef QB_HAS_COMPRESSION
#include <qb/io/compression.h>
#endif
#include "../routing.h"
#include "./protocol/server.h"
#include "./protocol/client.h"
#include "../logger.h"

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
        struct eos {
        };

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
        struct request {
        };

        /**
         * @brief Timeout event
         *
         * Triggered when a session times out due to inactivity.
         * Used to clean up resources for idle connections.
         * Timeouts help prevent resource leaks when clients disconnect
         * without properly closing the connection.
         */
        struct timeout {
        };
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
        template<typename Derived, typename Transport,
            template <typename T> typename TProtocol,
            typename Handler>
        class session
                : public qb::io::async::tcp::client<session<Derived, Transport, TProtocol, Handler>, Transport, Handler>
                , public qb::io::use<session<Derived, Transport, TProtocol, Handler> >::timeout
                , public std::enable_shared_from_this<Derived>
        {
        public:
            using Protocol = TProtocol<session<Derived, Transport, TProtocol, Handler> >;
            using string_type = typename Protocol::string_type;

        private:
            friend qb::io::async::io<session>;
            friend class qb::io::async::io_handler<Handler, Derived>;
            friend class has_method_on<session, void, qb::io::async::event::pending_write>;
            friend class has_method_on<session, void, qb::io::async::event::eos>;
            friend class has_method_on<session, void, qb::io::async::event::extracted>;
            friend class has_method_on<session, void, qb::io::async::event::disconnected>;
            friend Protocol;
            friend qb::io::async::with_timeout<session>;

            std::shared_ptr<Context<Derived> > _context{};
            bool _keep_alive{false}; ///< Keep-alive flag for persistent connections

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

                _context = this->server().router().route(this->shared_from_this(), std::move(request));

                if (!_context) {
                    LOG_HTTP_WARN_PA(this->id(), "HTTP/1.1 request not routed, disconnecting.");
                    this->disconnect(DisconnectedReason::Undefined);
                } else {
                    LOG_HTTP_DEBUG_PA(this->id(), "HTTP/1.1 request successfully routed.");
                }
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
            on(qb::io::async::event::timeout const &) {
                LOG_HTTP_WARN_PA(this->id(), "HTTP/1.1 session timed out.");

                // disconnect session on timeout
                // add reason for timeout
                if constexpr (has_method_on<Derived, void, event::timeout const &>::value) {
                    static_cast<Derived &>(*this).on(event::timeout{});
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
            on(qb::io::async::event::pending_write &&) {
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
            on(qb::io::async::event::eos &&) {
                LOG_HTTP_DEBUG_PA(this->id(), "End of stream (eos) event - response fully transmitted.");

                if (_context) {
                    _context->execute_hook(HookPoint::POST_RESPONSE_SEND);
                    _context.reset();
                }
                if (!_keep_alive)
                    this->disconnect(DisconnectedReason::ResponseTransmitted);
            }

            void
            on(qb::io::async::event::extracted &&) {
                LOG_HTTP_DEBUG_PA(this->id(), "HTTP/1.1 session extracted.");
                if (_context) {
                    _context->cancel();
                    _context.reset();
                }
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
                if constexpr (has_method_on<Derived, void, event::disconnected>::value) {
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
                : qb::io::async::tcp::client<session<Derived, Transport, TProtocol, Handler>,
                    Transport, Handler>(server) {
                LOG_HTTP_DEBUG_PA(this->id(), "HTTP/1.1 session created with 60s timeout.");
                this->setTimeout(60);
            }

            /**
             * @brief Get the context for the session
             * @return Shared pointer to the context
             *
             * Returns a shared pointer to the context for the session.
             * The context contains information about the current request and response.
             */
            std::shared_ptr<Context<Derived> > context() const {
                return _context;
            }

            /**
             * @brief Set the keep-alive flag
             * @param value Keep-alive flag value
             *
             * Sets the keep-alive flag for the session. If set to true,
             * the session will not disconnect after sending the response.
             */
            void keep_alive(bool value = true) {
                _keep_alive = value;
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
        template<typename Derived, typename Session>
        class io_handler : public qb::io::async::io_handler<Derived, Session> {
        public:
            using Router = typename qb::http::Router<Session>;
            using Route = typename qb::http::ICustomRoute<Session>;
            using RouteGroup = typename qb::http::RouteGroup<Session>;
            using Controller = typename qb::http::Controller<Session>;
            using Context = typename qb::http::Context<Session>;

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
        template<typename Derived, typename Session, typename Transport>
        class server
                : public qb::io::async::tcp::acceptor<server<Derived, Session, Transport>, Transport>
                  , public io_handler<Derived, Session> {
            friend qb::io::async::tcp::acceptor<server<Derived, Session, Transport>, Transport>;
            friend io_handler<Derived, Session>;
            using acceptor_type =
            qb::io::async::tcp::acceptor<server<Derived, Session, Transport>, Transport>;

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
                this->registerSession(
                    std::forward<typename acceptor_type::accepted_socket_type>(new_io));
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
                if constexpr (has_method_on<Derived, void, event::disconnected>::value) {
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
             * @brief Listen for incoming connections on a given URI.
             * @param uri The URI to listen on.
             * @param cert_file The path to the certificate file.
             * @param key_file The path to the key file.
             * @return True if the server is listening, false otherwise.
             */
            bool listen(qb::io::uri uri, std::filesystem::path cert_file = {}, std::filesystem::path key_file = {}) {
                using tpt = std::decay_t<decltype(this->transport())>;
                if constexpr (tpt::is_secure()) {
                    this->transport().init(qb::io::ssl::create_server_context(TLS_server_method(), cert_file, key_file));
                    if (!this->transport().ssl_handle()) {
                        LOG_HTTP_ERROR("Failed to initialize SSL/TLS server context.");
                        return false;
                    }
                    this->transport().set_supported_alpn_protocols({"http/1.1"});
                }
                return !this->transport().listen(std::move(uri));
            }
        };

        template<typename IO_Handler, bool has_server = IO_Handler::has_server>
        struct side {
            using protocol = qb::protocol::http::server<IO_Handler>;
            using protocol_view = qb::protocol::http::server_view<IO_Handler>;
        };

        /**
         * @brief Protocol selector specialization for client-side IO handlers
         * @tparam IO_Handler The IO handler type
         *
         * Selects client protocol implementations for client-side IO handlers.
         */
        template<typename IO_Handler>
        struct side<IO_Handler, false> {
            using protocol = qb::protocol::http::client<IO_Handler>;
            using protocol_view = qb::protocol::http::client_view<IO_Handler>;
        };
    } // namespace internal

    /**
     * @brief Get the appropriate protocol type for an IO handler
     * @tparam IO_Handler The IO handler type
     */
    template<typename IO_Handler>
    using protocol = typename internal::side<IO_Handler>::protocol;

    /**
     * @brief Get the appropriate string_view-based protocol type for an IO handler
     * @tparam IO_Handler The IO handler type
     */
    template<typename IO_Handler>
    using protocol_view = typename internal::side<IO_Handler>::protocol_view;

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
            Request request;
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
        template<typename Func, typename Transport>
        class session : public io::async::tcp::client<session<Func, Transport>, Transport>
                        , public io::use<session<Func, Transport> >::timeout {
            Func _func;
            Request _request;

        public:
            using http_protocol = http::protocol<session<Func, Transport> >;

            /**
             * @brief Constructor
             * @param func Callback function for the response
             * @param request HTTP request to send
             */
            session(Func &&func, Request &request)
                : _func(std::forward<Func>(func))
                  , _request(std::move([](auto &req) -> auto & {
                      if (!req.has_header("User-Agent"))
                          req.headers()["User-Agent"] = {"qb/1.0.0"};
                      req.headers()["Accept-Encoding"] = {accept_encoding()};
                      return req;
                  }(request))) {
                LOG_HTTP_DEBUG("HTTP/1.1 client session created for " << _request.method() << " " << _request.uri().source());
                this->template switch_protocol<http_protocol>(*this);
                this->setTimeout(0);
            }

            ~session() = default;

            /**
             * @brief Connect to a remote server
             * @param remote URI to connect to
             * @param timeout Connection timeout
             */
            void
            connect(double timeout = 0) {
                LOG_HTTP_INFO("HTTP/1.1 client connecting to " << _request.uri().source() << " with timeout " << timeout << "s");

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
                    if (_request.header("Content-Encoding") != "chunked") {
                        _request.remove_header("Content-Encoding");
                    }
#endif
                            LOG_HTTP_DEBUG("Sending HTTP/1.1 request: " << _request.method() << " " << _request.uri().source());
                            *this << _request;
                            this->setTimeout(timeout);
                        }
                    },
                    timeout);
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

    namespace detail {
        template <typename _Func>
        void _execute_async_request_internal(Request request, _Func &&func, double timeout, const char* method_name_for_log) {
            request.headers()["host"].emplace_back(request.uri().host());
            LOG_HTTP_DEBUG("Executing HTTP/1.1 " << method_name_for_log << " request: " << request.method() << " " << request.uri().source());
#if QB_HAS_SSL
            if (request.uri().scheme() == "https") {
                (new async::HTTPS<_Func>(std::forward<_Func>(func), request))
                    ->connect(timeout);
            } else {
                (new async::HTTP<_Func>(std::forward<_Func>(func), request))
                    ->connect(timeout);
            }
#else
            (new async::HTTP<_Func>(std::forward<_Func>(func), request))
                ->connect(timeout);
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
    REQUEST(Request request, _Func &&func, double timeout = 0.) {
        detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "Generic");
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
    GET(Request request, _Func &&func, double timeout = 0.) {
        request.method() = qb::http::Method::GET;
        detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "GET");
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
    POST(Request request, _Func &&func, double timeout = 0.) {
        request.method() = qb::http::Method::POST;
        detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "POST");
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
    PUT(Request request, _Func &&func, double timeout = 0.) {
        request.method() = qb::http::Method::PUT;
        detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "PUT");
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
    DEL(Request request, _Func &&func, double timeout = 0.) {
        request.method() = qb::http::Method::DEL;
        detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "DELETE");
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
    HEAD(Request request, _Func &&func, double timeout = 0.) {
        request.method() = qb::http::Method::HEAD;
        detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "HEAD");
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
    OPTIONS(Request request, _Func &&func, double timeout = 0.) {
        request.method() = qb::http::Method::OPTIONS;
        detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "OPTIONS");
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
    PATCH(Request request, _Func &&func, double timeout = 0.) {
        request.method() = qb::http::Method::PATCH;
        detail::_execute_async_request_internal(std::move(request), std::forward<_Func>(func), timeout, "PATCH");
    }

    // --- Synchronous HTTP Client Function Declarations ---

    /**
     * @brief Sends a generic HTTP/1.1 request synchronously.
     * @param request The HTTP request object.
     * @param timeout Optional timeout in seconds. Default is 3 seconds.
     * @return The HTTP response.
     */
    Response REQUEST(Request request, double timeout = 3.);
    /**
     * @brief Sends an HTTP GET request synchronously.
     * @param request The HTTP request object. Its method will be set to GET.
     * @param timeout Optional timeout.
     * @return The HTTP response.
     */
    Response GET(Request request, double timeout = 3.);
    /**
     * @brief Sends an HTTP POST request synchronously.
     * @param request The HTTP request object. Its method will be set to POST.
     * @param timeout Optional timeout.
     * @return The HTTP response.
     */
    Response POST(Request request, double timeout = 3.);
    /**
     * @brief Sends an HTTP PUT request synchronously.
     * @param request The HTTP request object. Its method will be set to PUT.
     * @param timeout Optional timeout.
     * @return The HTTP response.
     */
    Response PUT(Request request, double timeout = 3.);
    /**
     * @brief Sends an HTTP DELETE request synchronously.
     * @param request The HTTP request object. Its method will be set to DELETE.
     * @param timeout Optional timeout.
     * @return The HTTP response.
     */
    Response DEL(Request request, double timeout = 3.); // For DELETE
    /**
     * @brief Sends an HTTP HEAD request synchronously.
     * @param request The HTTP request object. Its method will be set to HEAD.
     * @param timeout Optional timeout.
     * @return The HTTP response.
     */
    Response HEAD(Request request, double timeout = 3.);
    /**
     * @brief Sends an HTTP OPTIONS request synchronously.
     * @param request The HTTP request object. Its method will be set to OPTIONS.
     * @param timeout Optional timeout.
     * @return The HTTP response.
     */
    Response OPTIONS(Request request, double timeout = 3.);
    /**
     * @brief Sends an HTTP PATCH request synchronously.
     * @param request The HTTP request object. Its method will be set to PATCH.
     * @param timeout Optional timeout.
     * @return The HTTP response.
     */
    Response PATCH(Request request, double timeout = 3.);

}

namespace qb::http {
    /**
     * @brief HTTP server/client session utility namespace
     *
     * This namespace provides template utilities for creating HTTP server and client
     * sessions with different transport options.
     *
     * @tparam T The type implementing the session
     */
    template<typename Derived>
    struct use {
        /**
         * @brief Standard TCP HTTP session type
         * @tparam Server Server handler type
         */
        template<typename Server>
        using session = internal::session<Derived, qb::io::transport::tcp,
            qb::protocol::http::server, Server>;

        /**
         * @brief Standard TCP HTTP session type with string_view optimization
         * @tparam Server Server handler type
         */
        template<typename Server>
        using session_view = internal::session<Derived, qb::io::transport::tcp,
            qb::protocol::http::server_view, Server>;

        /**
         * @brief Standard HTTP IO handler
         * @tparam Session Session type
         */
        template<typename Session>
        using io_handler = internal::io_handler<Derived, Session>;

        /**
         * @brief Standard HTTP server
         * @tparam Session Session type
         */
        template<typename Session>
        using server = internal::server<Derived, Session, qb::io::transport::accept>;

        /**
         * @brief SSL/TLS transport types for secure HTTP
         */
        struct ssl {
            /**
             * @brief Secure HTTPS session type
             * @tparam Server Server handler type
             */
            template<typename Server>
            using session = internal::session<Derived, qb::io::transport::stcp,
                qb::protocol::http::server, Server>;

            /**
             * @brief Secure HTTPS session type with string_view optimization
             * @tparam Server Server handler type
             */
            template<typename Server>
            using session_view = internal::session<Derived, qb::io::transport::stcp,
                qb::protocol::http::server_view, Server>;

            /**
             * @brief Secure HTTPS IO handler
             * @tparam Session Session type
             */
            template<typename Session>
            using io_handler = internal::io_handler<Derived, Session>;

            /**
             * @brief Secure HTTPS server
             * @tparam Session Session type
             */
            template<typename Session>
            using server = internal::server<Derived, Session, qb::io::transport::saccept>;
        };
    };
} // namespace qb::http

// --- HTTP/1.1 Server Factory ---

// Forward declaration for Server to be used in DefaultSession's definition
namespace qb::http {

template<typename SessionType>
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
    explicit DefaultSession(Server<DefaultSession>& server_handler)
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
template<typename SessionType = DefaultSession>
class Server : public qb::http::use<Server<SessionType>>::template server<SessionType> {
public:
    Server() = default;

    /**
     * @brief Provides access to the router.
     * @return A reference to the internal HTTP router.
     */
    qb::http::Router<SessionType>& router() {
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
std::unique_ptr<Server<Session>> make_server() {
    return std::make_unique<Server<Session>>();
}

/**
 * @brief Alias for the HTTP/1.1 server type, allowing custom session.
 * @tparam Session The session type to use. Defaults to `qb::http::DefaultSession`.
 */
template<typename Session = DefaultSession>
using server = Server<Session>;

#if QB_HAS_SSL
namespace ssl {
    template<typename SessionType>
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
        explicit DefaultSecureSession(Server<DefaultSecureSession>& server_handler)
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
    template<typename SessionType = DefaultSecureSession>
    class Server : public qb::http::use<Server<SessionType>>::ssl::template server<SessionType> {
    public:
        Server() = default;

        /**
         * @brief Provides access to the router.
         * @return A reference to the internal HTTP router.
         */
        qb::http::Router<SessionType>& router() {
            return qb::http::internal::io_handler<Server, SessionType>::router();
        }

        /**
         * @brief Provides const access to the router.
         * @return A const reference to the internal HTTP router.
         */
        const qb::http::Router<SessionType>& router() const {
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
std::unique_ptr<Server<Session>> make_server() {
    return std::make_unique<Server<Session>>();
}

/**
 * @brief Alias for the HTTPS/1.1 server type, allowing custom session.
 * @tparam Session The session type to use. Defaults to `qb::http::DefaultSecureSession`.
 */
template<typename Session = DefaultSecureSession>
using server = Server<Session>;

} // namespace ssl
#endif // QB_HAS_SSL

} // namespace qb::http

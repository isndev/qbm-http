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
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http2
 */
#pragma once
#include <filesystem>
#include <qb/io/protocol/handshake.h>
// Re-using HTTP/1.1 Request/Response structures as a base
#include "../1.1/http.h"
// HTTP/2 protocol implementations
#include "./protocol/client.h"
#include "./protocol/server.h"
// HTTP/2 client implementation
#include "./client.h"


namespace qb::http2 {

    // Constants for HTTP/2 session configuration
    namespace constants {
        constexpr uint32_t HTTP11_STREAM_ID = 0;        ///< Stream ID used for HTTP/1.1 requests (not a valid HTTP/2 stream ID)
        constexpr uint32_t DEFAULT_SESSION_TIMEOUT = 60; ///< Default session timeout in seconds
        constexpr uint32_t MIN_VALID_STREAM_ID = 1;     ///< Minimum valid HTTP/2 stream ID (0 is reserved for HTTP/1.1)
        
        // DDoS Protection constants
        constexpr uint32_t DEFAULT_MAX_CONCURRENT_STREAMS = 50;  ///< Default max concurrent streams per connection (reduced from 100 for security)
        constexpr uint32_t STREAM_IDLE_TIMEOUT_SECONDS = 30;      ///< Timeout for idle streams (seconds)
        constexpr uint32_t STREAM_INCOMPLETE_TIMEOUT_SECONDS = 10; ///< Timeout for incomplete streams (seconds)
        constexpr uint32_t CLEANUP_INTERVAL_SECONDS = 5;          ///< Interval for periodic stream cleanup (seconds)
    }

    // Protocol type aliases for cleaner code
    template<typename IO_Handler> 
    using client_protocol = qb::protocol::http2::ClientHttp2Protocol<IO_Handler>;
    
    template<typename IO_Handler> 
    using server_protocol = qb::protocol::http2::ServerHttp2Protocol<IO_Handler>;

    namespace internal {
        // Forward declaration
        template<typename Derived> class Context;


        /**
         * @brief HTTP/2 server session implementation
         * 
         * Handles HTTP/2 connections with protocol negotiation, stream management,
         * and request routing. Supports both HTTP/1.1 and HTTP/2 via ALPN.
         * 
         * @tparam Derived CRTP derived type
         * @tparam Handler Server handler type
         */
        template<typename Derived, typename Handler>
        class session
                : public qb::io::async::tcp::client<session<Derived, Handler>, qb::io::transport::stcp, Handler>,
                  public qb::io::use<session<Derived, Handler>>::timeout,
                  public std::enable_shared_from_this<Derived> {
        public:
            using Http1Protocol = qb::protocol::http::server<session<Derived, Handler>>;
            using Http2Protocol = server_protocol<session<Derived, Handler>>;
            using ContextType = qb::http::Context<Derived>;
            using Router = typename qb::http::Router<Derived>;


        private:
            friend qb::io::async::io<session<Derived, Handler>>;
            friend class has_method_on<session, void, qb::io::async::event::pending_write>;
            friend class has_method_on<session, void, qb::io::async::event::eos>;
            friend class has_method_on<session, void, qb::io::async::event::disconnected>;
            friend Http2Protocol;
            friend qb::io::async::with_timeout<session<Derived, Handler>>;

            qb::unordered_map<uint32_t, std::shared_ptr<ContextType>> _contexts; ///< Stream contexts
            
            Http1Protocol *_http1_protocol; ///< HTTP/1.1 protocol handler
            Http2Protocol *_http2_protocol; ///< HTTP/2 protocol handler
            
            std::chrono::steady_clock::time_point _last_stream_cleanup; ///< Last time we cleaned up idle streams

            /**
             * @brief Validate HTTP/2 stream ID
             * @param stream_id Stream ID to validate
             * @return true if stream_id is valid for HTTP/2 (not 0)
             */
            static constexpr bool is_valid_http2_stream_id(uint32_t stream_id) noexcept {
                return stream_id != constants::HTTP11_STREAM_ID;
            }

            /**
             * @brief Validate response before sending
             * @param res Response to validate
             * @return true if response is valid
             */
            bool validate_response(const qb::http::Response &res) const noexcept {
                // Basic validation - can be extended
                // Status is an enum class, convert to underlying type for comparison
                const auto status_code = static_cast<int>(res.status());
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
                : qb::io::async::tcp::client<session<Derived, Handler>, qb::io::transport::stcp, Handler>(server_handler),
                  _http1_protocol(nullptr),
                  _http2_protocol(nullptr),
                  _last_stream_cleanup(std::chrono::steady_clock::now()) {
                LOG_HTTP_DEBUG_PA(this->id(), "HTTP/2 internal::session (server-side) created.");
                this->template switch_protocol<qb::io::protocol::handshake<session<Derived, Handler>>>(*this);
                this->setTimeout(constants::DEFAULT_SESSION_TIMEOUT);
            }

            ~session() {
                LOG_HTTP_DEBUG_PA(this->id(), "HTTP/2 internal::session (server-side) destroyed.");
            }

            using qb::io::async::io<session<Derived, Handler>>::operator<<;

            /**
             * @brief Send HTTP response
             * @param res HTTP response to send
             * @return Output stream reference
             */
            auto &operator<<(qb::http::Response &res) {
                if (_http2_protocol) {
                    const uint32_t stream_id = res.stream_id;
                    if (!is_valid_http2_stream_id(stream_id)) {
                        LOG_HTTP_ERROR_PA(this->id(), "HTTP/2 response with stream_id " << stream_id << " is invalid (stream_id 0 is reserved for HTTP/1.1)");
                        return this->out();
                    }
                    if (!validate_response(res)) {
                        LOG_HTTP_ERROR_PA(this->id(), "HTTP/2 response validation failed for stream " << stream_id << " (invalid status code: " << res.status() << ")");
                        return this->out();
                    }
                    if (!res.has_header("content-length") && !res.body().empty()) {
                       res.set_header("content-length", std::to_string(res.body().size()));
                    }
                    _http2_protocol->send_response(stream_id, res);
                    auto it = _contexts.find(stream_id);
                    if (it != _contexts.end() && it->second) {
                        it->second->execute_hook(qb::http::HookPoint::POST_RESPONSE_SEND);
                        _contexts.erase(it);
                    }
                    this->ready_to_write();
                    this->updateTimeout();
                } else {
                   qb::io::async::io<session<Derived, Handler>>::operator<<(res);
                }
                return this->out();
            }

            /**
             * @brief Handle SSL handshake completion
             * @param event Handshake event
             */
            void on(qb::io::async::event::handshake &&) {
                auto alpn_proto = this->transport().get_alpn_selected_protocol();
                LOG_HTTP_INFO_PA(this->id(), "Handshake complete. ALPN selected: " << (alpn_proto.empty() ? "none/http1.1" : alpn_proto));
                if (alpn_proto == "h2") {
                    LOG_HTTP_DEBUG_PA(this->id(), "Switching to HTTP/2 protocol.");
                    _http2_protocol = this->template switch_protocol<Http2Protocol>(*this);
                } else {
                    LOG_HTTP_DEBUG_PA(this->id(), "Switching to HTTP/1.1 protocol.");
                    _http1_protocol = this->template switch_protocol<Http1Protocol>(*this);
                }
            }

            /**
             * @brief Handle HTTP/1.1 request
             * @param msg HTTP/1.1 request message
             */
            void on(qb::http::Request &&request) {
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
            void on(qb::http::Request &&request, uint32_t stream_id) {
                LOG_HTTP_INFO_PA(this->id(), "Received HTTP/2 request on stream " << stream_id << ": " << request.method() << " " << request.uri().source());
                // Store stream_id directly in request (no string conversion needed)
                request.stream_id = stream_id;
                request.set_header("server", "qb/http2");
                
                auto context = router().route(this->shared_from_this(), std::move(request));
                if (!context) {
                    LOG_HTTP_WARN_PA(this->id(), "HTTP/2 request on stream " << stream_id << " not routed. Sending RST_STREAM.");
                    // Explicitly send RST_STREAM when routing fails
                    if (_http2_protocol) {
                        _http2_protocol->send_rst_stream(stream_id, qb::protocol::http2::ErrorCode::REFUSED_STREAM, "Request not routed - no matching route found");
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
            void on(qb::io::async::event::timeout const &) {
                LOG_HTTP_WARN_PA(this->id(), "Session timed out.");
                this->disconnect(qb::http::DisconnectedReason::ByTimeout);
            }

            /**
             * @brief Handle pending write event
             * @param event Pending write event
             */
            void on(qb::io::async::event::pending_write &&) {
                LOG_HTTP_TRACE_PA(this->id(), "Pending write event, updating timeout.");
                this->updateTimeout();
                // Periodic cleanup of idle streams for DDoS protection
                if (_http2_protocol) {
                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - _last_stream_cleanup).count();
                    if (elapsed >= constants::CLEANUP_INTERVAL_SECONDS) {
                        _http2_protocol->cleanup_idle_streams(
                            constants::STREAM_IDLE_TIMEOUT_SECONDS,
                            constants::STREAM_INCOMPLETE_TIMEOUT_SECONDS);
                        _last_stream_cleanup = now;
                    }
                }
            }

            /**
             * @brief Handle end of stream event
             * @param event EOS event
             */
            void on(qb::io::async::event::eos &&) {
                LOG_HTTP_DEBUG_PA(this->id(), "End of stream (eos) event.");
                if (_http1_protocol) {
                    auto it = _contexts.find(constants::HTTP11_STREAM_ID);
                    if (it != _contexts.end() && it->second) {
                        it->second->execute_hook(qb::http::HookPoint::POST_RESPONSE_SEND);
                        _contexts.clear();
                    }
                    this->disconnect(qb::http::DisconnectedReason::ResponseTransmitted);
                } // For HTTP/2, EOS is per-stream and handled by Http2Protocol stream lifecycle.
            }

            void
            on(qb::io::async::event::extracted &&) {
                LOG_HTTP_DEBUG_PA(this->id(), "HTTP/2 session extracted.");
                for (auto& [stream_id, context] : _contexts) {
                    context->cancel("Session extracted");
                }
                _contexts.clear();
            }

            /**
             * @brief Handle disconnection event
             * @param e Disconnection event
             */
            void on(qb::io::async::event::disconnected &&e) {
                if (!e.reason) { 
                    LOG_HTTP_WARN_PA(this->id(), "Disconnected by peer.");
                } else {
                    LOG_HTTP_INFO_PA(this->id(), "Disconnected. Reason code: " << e.reason);
                }
                for (auto& context : _contexts) {
                    context.second->cancel("Session disconnected");
                }
                _contexts.clear(); // Clear all stream contexts on disconnect
            }

            /**
             * @brief Handle HTTP/2 connection error
             * @param event Connection error details
             */
            void on(const qb::protocol::http2::Http2ConnectionErrorEvent& event) {
                LOG_HTTP_ERROR_PA(this->id(), "HTTP/2 Connection Error: " << event.message << ". Fatal: " << event.fatal);
                if (event.fatal) {
                    this->disconnect(qb::http::DisconnectedReason::ByProtocolError);
                }
            }

            /**
             * @brief Handle HTTP/2 stream error
             * @param event Stream error details
             */
            void on(const qb::protocol::http2::Http2StreamErrorEvent& event) {
                LOG_HTTP_WARN_PA(this->id(), "HTTP/2 Stream Error on stream " << event.stream_id << ". Code: " << static_cast<int>(event.error_code) << ", Msg: " << event.message);
                // Context for this stream might need to be cleared or marked.
                auto it = _contexts.find(event.stream_id);
                if (it != _contexts.end() && it->second) {
                    it->second->cancel("HTTP/2 stream error: " + event.message);
                    _contexts.erase(it);
                }
            }

            /**
             * @brief Handle GOAWAY from client
             * @param event GOAWAY details
             */
            void on(const qb::protocol::http2::Http2GoAwayEvent& event) {
                LOG_HTTP_WARN_PA(this->id(), "Received GOAWAY from client. Last Stream ID: " << event.last_stream_id << ", Code: " << static_cast<int>(event.error_code) << ", Debug: " << event.debug_data);
                // Server may decide to stop accepting new requests on this connection.
                if (event.error_code != qb::protocol::http2::ErrorCode::NO_ERROR) {
                    this->disconnect(qb::http::DisconnectedReason::ResponseTransmitted);
                }
            }

            /**
             * @brief Get router reference
             * @return Router reference
             */
            Router &router() {
                return this->server().router();
            }
        };

        /**
         * @brief HTTP/2 I/O handler with routing
         * @tparam Derived CRTP derived type
         * @tparam Session Session type
         */
        template<typename Derived, typename Session>
        class io_handler : public qb::io::async::io_handler<Derived, Session> {
        public:
            using Router = typename qb::http::Router<Session>;

        private:
            Router _router; ///< HTTP router

        public:
            io_handler() {
            }

            /**
             * @brief Get router reference
             * @return Router reference
             */
            Router &router() {
                return _router;
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
        template<typename Derived, typename Session>
        class server
                : public qb::io::async::tcp::acceptor<server<Derived, Session>, qb::io::transport::saccept>,
                  public io_handler<Derived, Session> {
            friend qb::io::async::tcp::acceptor<server<Derived, Session>, qb::io::transport::saccept>;
            friend io_handler<Derived, Session>;
            using acceptor_type = qb::io::async::tcp::acceptor<server<Derived, Session>, qb::io::transport::saccept>;

            /**
             * @brief Handle accepted connection
             * @param new_io New SSL socket
             */
            void on(typename acceptor_type::accepted_socket_type &&new_io) {
                this->registerSession(std::move(new_io));
            }

            /**
             * @brief Handle acceptor disconnection
             * @param event Disconnection event
             */
            void on(qb::io::async::event::disconnected &&event) {
                (void)event;
                // Acceptor disconnected
                // if constexpr(has_method_on<Derived, void, qb::http::event::disconnected>::value) {
                //     this->on({event.reason});
                // }
            }

        public:
            /**
             * @brief Construct HTTP/2 server
             */
            server() = default;

            /**
             * @brief Listen for incoming connections on a given URI.
             * @param uri The URI to listen on.
             * @param cert_file The path to the certificate file.
             * @param key_file The path to the key file.
             * @return True if the server is listening, false otherwise.
             */
            bool listen(qb::io::uri uri, std::filesystem::path cert_file, std::filesystem::path key_file) {
                this->transport().init(qb::io::ssl::create_server_context(TLS_server_method(), std::move(cert_file), std::move(key_file)));
                if (!this->transport().ssl_handle()) {
                    LOG_HTTP_ERROR("Failed to initialize SSL/TLS server context.");
                    return false;
                }
                this->transport().set_supported_alpn_protocols({"h2", "http/1.1"});
                return !this->transport().listen(std::move(uri));
            }
        };

    } // namespace internal


    /**
     * @brief HTTP/2 type definitions for CRTP pattern
     * @tparam Derived CRTP derived type
     */
    template<typename Derived>
    struct use {
        template<typename ServerHandler>
        using session = internal::session<Derived, ServerHandler>;

        template<typename SessionType>
        using io_handler = internal::io_handler<Derived, SessionType>;

        template<typename SessionType>
        using server = internal::server<Derived, SessionType>;
    };


// Forward declaration for Server to be used in DefaultSession's definition
template<typename SessionType>
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
    using Base = qb::http2::use<DefaultSession>::session<Server<DefaultSession>>;
    using ServerType = qb::http2::Server<DefaultSession>;

    /**
     * @brief Constructs a DefaultSession.
     * @param server_handler Reference to the server instance that owns this session.
     */
    explicit DefaultSession(qb::http2::Server<DefaultSession>& server_handler)
        : Base(server_handler) {}
};

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
template<typename SessionType = DefaultSession>
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
std::unique_ptr<Server<Session>> make_server() {
    return std::unique_ptr<Server<Session>>(new Server<Session>());
}

// Type alias for the default server type for easier use.
template <typename Session = DefaultSession>
using server = Server<DefaultSession>;

} // namespace qb::http2

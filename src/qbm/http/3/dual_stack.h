/**
 * @file qbm/http/3/dual_stack.h
 * @brief Convenience HTTP/2 + HTTP/3 dual-stack server wrapper.
 *
 * This file provides @ref qb::http::dual_stack_server, a thin convenience layer
 * that owns both an HTTP/2 (TCP/TLS) server and an HTTP/3 (QUIC) server and
 * exposes a single router facade that mirrors every registered route onto both
 * underlying stacks. It is intended for advertising the same application over
 * HTTP/2 and HTTP/3 simultaneously (e.g. alongside an `Alt-Svc` advertisement).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#ifndef QBM_HTTP_HAS_HTTP3
#error "HTTP/3 support is not enabled. Build qbm/http with QBM_HTTP_HAS_HTTP3."
#endif

#include <filesystem>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include "../2/http2.h"
#include "./http3.h"

namespace qb::http {

/**
 * @brief Convenience server owning both an HTTP/2 and an HTTP/3 stack.
 *
 * Owns one @ref qb::http2::Server (TCP/TLS) and one @ref qb::http3::Server
 * (QUIC), and exposes a unified @ref router_facade whose route registrations are
 * applied to both routers. This lets a single application be served over HTTP/2
 * and HTTP/3 with one set of handler registrations.
 *
 * @tparam Http2Session Session type for the HTTP/2 server (defaults to
 *         @ref qb::http2::DefaultSession).
 * @tparam Http3Session Session type for the HTTP/3 server (defaults to
 *         @ref qb::http3::DefaultSession).
 */
template <typename Http2Session = qb::http2::DefaultSession, typename Http3Session = qb::http3::DefaultSession>
class dual_stack_server {
public:
    using http2_server_type = qb::http2::Server<Http2Session>;
    using http3_server_type = qb::http3::Server<Http3Session>;

    /**
     * @brief Unified router that mirrors every registration onto both stacks.
     *
     * Each registration call adds the route to both the HTTP/2 and HTTP/3
     * routers of the owning @ref dual_stack_server. The handler is stored once
     * in a `shared_ptr` and shared between the two routers.
     */
    class router_facade {
        dual_stack_server *_owner = nullptr;

        /**
         * @brief Register @p handler on both underlying routers.
         *
         * The handler is decayed, stored once in a `shared_ptr`, and wrapped by
         * a forwarding lambda registered on each router so both stacks share a
         * single handler instance.
         *
         * @tparam Handler Invocable accepting the route context.
         * @param path    Route path (copied for the HTTP/2 router, moved into
         *                the HTTP/3 router).
         * @param verb    HTTP method to match.
         * @param handler Handler to register.
         * @return Reference to this facade for chaining.
         */
        template <typename Handler>
        router_facade &
        add_to_both(std::string path, qb::http::method verb, Handler &&handler) {
            using stored_handler = std::decay_t<Handler>;
            auto shared          = std::make_shared<stored_handler>(std::forward<Handler>(handler));
            _owner->_http2->router().add_route(path, verb, [shared](auto ctx) { (*shared)(std::move(ctx)); });
            _owner->_http3->router().add_route(std::move(path), verb, [shared](auto ctx) { (*shared)(std::move(ctx)); });
            return *this;
        }

    public:
        /**
         * @brief Construct a facade bound to @p owner.
         * @param owner Dual-stack server whose routers this facade drives.
         */
        explicit router_facade(dual_stack_server &owner) noexcept
            : _owner(&owner) {}

        /**
         * @brief Register a route for an arbitrary HTTP method on both stacks.
         * @tparam Handler Invocable accepting the route context.
         * @param path    Route path.
         * @param verb    HTTP method to match.
         * @param handler Handler to register.
         * @return Reference to this facade for chaining.
         */
        template <typename Handler>
        router_facade &
        add_route(std::string path, qb::http::method verb, Handler &&handler) {
            return add_to_both(std::move(path), verb, std::forward<Handler>(handler));
        }

        /**
         * @brief Register a `GET` route on both stacks.
         * @tparam Handler Invocable accepting the route context.
         * @param path    Route path.
         * @param handler Handler to register.
         * @return Reference to this facade for chaining.
         */
        template <typename Handler>
        router_facade &
        get(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::GET, std::forward<Handler>(handler));
        }

        /**
         * @brief Register a `POST` route on both stacks.
         * @tparam Handler Invocable accepting the route context.
         * @param path    Route path.
         * @param handler Handler to register.
         * @return Reference to this facade for chaining.
         */
        template <typename Handler>
        router_facade &
        post(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::POST, std::forward<Handler>(handler));
        }

        /**
         * @brief Register a `PUT` route on both stacks.
         * @tparam Handler Invocable accepting the route context.
         * @param path    Route path.
         * @param handler Handler to register.
         * @return Reference to this facade for chaining.
         */
        template <typename Handler>
        router_facade &
        put(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::PUT, std::forward<Handler>(handler));
        }

        /**
         * @brief Register a `DELETE` route on both stacks.
         * @tparam Handler Invocable accepting the route context.
         * @param path    Route path.
         * @param handler Handler to register.
         * @return Reference to this facade for chaining.
         */
        template <typename Handler>
        router_facade &
        del(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::DEL, std::forward<Handler>(handler));
        }

        /**
         * @brief Register a `PATCH` route on both stacks.
         * @tparam Handler Invocable accepting the route context.
         * @param path    Route path.
         * @param handler Handler to register.
         * @return Reference to this facade for chaining.
         */
        template <typename Handler>
        router_facade &
        patch(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::PATCH, std::forward<Handler>(handler));
        }

        /**
         * @brief Register an `OPTIONS` route on both stacks.
         * @tparam Handler Invocable accepting the route context.
         * @param path    Route path.
         * @param handler Handler to register.
         * @return Reference to this facade for chaining.
         */
        template <typename Handler>
        router_facade &
        options(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::OPTIONS, std::forward<Handler>(handler));
        }

        /**
         * @brief Register a `HEAD` route on both stacks.
         * @tparam Handler Invocable accepting the route context.
         * @param path    Route path.
         * @param handler Handler to register.
         * @return Reference to this facade for chaining.
         */
        template <typename Handler>
        router_facade &
        head(std::string path, Handler &&handler) {
            return add_to_both(std::move(path), qb::http::method::HEAD, std::forward<Handler>(handler));
        }

        /**
         * @brief Compile the routing tables of both underlying routers.
         *
         * Must be called once after all routes have been registered and before
         * the servers start handling requests.
         */
        void
        compile() {
            _owner->_http2->router().compile();
            _owner->_http3->router().compile();
        }
    };

private:
    std::unique_ptr<http2_server_type> _http2;
    std::unique_ptr<http3_server_type> _http3;
    router_facade                      _router;

public:
    /**
     * @brief Construct both servers and bind the router facade to them.
     */
    dual_stack_server()
        : _http2(qb::http2::make_server<Http2Session>())
        , _http3(qb::http3::make_server<Http3Session>())
        , _router(*this) {}

    /**
     * @brief Access the unified router facade.
     * @return Reference to the facade that mirrors routes onto both stacks.
     */
    [[nodiscard]] router_facade &
    router() noexcept {
        return _router;
    }
    /**
     * @brief Access the underlying HTTP/2 server.
     * @return Reference to the owned HTTP/2 server.
     */
    [[nodiscard]] http2_server_type &
    http2_server() noexcept {
        return *_http2;
    }
    /**
     * @brief Access the underlying HTTP/3 server.
     * @return Reference to the owned HTTP/3 server.
     */
    [[nodiscard]] http3_server_type &
    http3_server() noexcept {
        return *_http3;
    }

    /**
     * @brief Listen on both stacks.
     *
     * Binds the HTTP/2 server to @p tcp_tls_uri and the HTTP/3 server to @p quic_uri, both
     * using the same TLS certificate and key, and starts accepting on each.
     *
     * @param tcp_tls_uri URI for the HTTP/2 (TCP/TLS) listener.
     * @param quic_uri    URI for the HTTP/3 (QUIC) listener.
     * @param cert_file   Path to the TLS certificate file.
     * @param key_file    Path to the TLS private key file.
     * @return `true` only if both listeners were established successfully.
     *
     * @note Until 3.0 this method called `_http2->start()` itself, because the HTTP/2
     *       server's `listen()` bound without starting while the HTTP/3 one did both. That
     *       compensation is gone: both now honour the base contract, so this method only
     *       has to bind each side and roll back on a partial failure.
     */
    bool
    listen(qb::io::uri tcp_tls_uri, qb::io::uri quic_uri, std::filesystem::path const &cert_file, std::filesystem::path const &key_file) {
        const bool tcp_ok  = _http2->listen(std::move(tcp_tls_uri), cert_file, key_file);
        const bool quic_ok = _http3->listen(std::move(quic_uri), cert_file, key_file);
        if (tcp_ok && quic_ok) {
            return true;
        }
        // All-or-nothing: a half-bound pair (e.g. TCP came up but the QUIC UDP port is taken) must
        // not leave one stack silently listening/accepting while the caller sees listen() return
        // false. Roll back whichever side came up.
        if (tcp_ok) {
            close_http2();
        }
        if (quic_ok) {
            close_http3();
        }
        return false;
    }

    /**
     * @brief Listen on both stacks using string URIs.
     *
     * Convenience overload that parses @p tcp_tls_uri and @p quic_uri into
     * @ref qb::io::uri before delegating to the URI overload.
     *
     * @param tcp_tls_uri URI string for the HTTP/2 (TCP/TLS) listener.
     * @param quic_uri    URI string for the HTTP/3 (QUIC) listener.
     * @param cert_file   Path to the TLS certificate file.
     * @param key_file    Path to the TLS private key file.
     * @return `true` only if both listeners were established successfully.
     */
    bool
    listen(std::string const &tcp_tls_uri, std::string const &quic_uri, std::filesystem::path const &cert_file,
           std::filesystem::path const &key_file) {
        return listen(qb::io::uri(tcp_tls_uri), qb::io::uri(quic_uri), cert_file, key_file);
    }

    /**
     * @brief Stop and close the HTTP/2 server and its transport.
     */
    void
    close_http2() {
        _http2->stop();
        _http2->transport().close();
    }

    /**
     * @brief Close the HTTP/3 server.
     */
    void
    close_http3() {
        _http3->close();
    }

    /**
     * @brief Close both stacks (HTTP/3 first, then HTTP/2).
     */
    void
    close() {
        close_http3();
        close_http2();
    }
};

/**
 * @brief Create a heap-allocated @ref dual_stack_server.
 *
 * @tparam Http2Session Session type for the HTTP/2 server (defaults to
 *         @ref qb::http2::DefaultSession).
 * @tparam Http3Session Session type for the HTTP/3 server (defaults to
 *         @ref qb::http3::DefaultSession).
 * @return Owning pointer to a new dual-stack server.
 */
template <typename Http2Session = qb::http2::DefaultSession, typename Http3Session = qb::http3::DefaultSession>
[[nodiscard]] std::unique_ptr<dual_stack_server<Http2Session, Http3Session>>
make_dual_stack_server() {
    return std::make_unique<dual_stack_server<Http2Session, Http3Session>>();
}

} // namespace qb::http

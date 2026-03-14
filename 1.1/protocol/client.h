/**
 * @file qbm/http/1.1/protocol/client.h
 * @brief HTTP/1.1 client protocol implementation for qb-io framework
 *
 * This file provides HTTP/1.1 client-side protocol handling built on top of
 * the qb-io asynchronous framework. It includes:
 *
 * - HTTP/1.1 response parsing and processing
 * - Cookie parsing from Set-Cookie headers
 * - Support for both string and string_view semantics
 * - Asynchronous response handling through callbacks
 * - Integration with the base HTTP/1.1 protocol parser
 *
 * The implementation supports both owning (string-based) and non-owning
 * (string_view-based) response handling for optimal performance.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once
#include "../../response.h"
#include "../../logger.h"  // For LOG_HTTP_WARN - SECURITY FIX: Required for exception logging
#include "./base.h"

namespace qb::protocol::http {
    template<typename IO_Handler>
    class client : public base<IO_Handler, qb::http::Response> {
        using base_t = base<IO_Handler, qb::http::Response>;

    public:
        /**
         * @brief Default constructor is deleted
         *
         * HTTP client must be constructed with an IO handler.
         */
        client() = delete;

        /**
         * @brief Constructor with IO handler
         * @param io IO handler for network operations
         *
         * Creates an HTTP client protocol handler attached to the provided
         * IO handler, which manages the underlying socket connections.
         */
        explicit client(IO_Handler &io) noexcept
            : base_t(io) {
        }


        using response = qb::http::Response;

        /**
         * @brief Process an incoming HTTP response
         * @param size Size of the incoming message
         *
         * This method is called when a complete HTTP response is received from a server.
         * It parses the response data using the HTTP parser, then passes the
         * response to the client's callback handler.
         *
         * @security CRITICAL FIX: All cookie parsing exceptions are caught to prevent
         * std::terminate() in noexcept context. Malformed cookies are logged and ignored.
         */
        void
        onMessage(std::size_t) noexcept final {
            auto &response_obj = this->_http_obj.get_parsed_message();
            // Parse cookies from the Set-Cookie headers
            // SECURITY: Wrap in try/catch - parse_set_cookie_headers() can throw
            try {
                response_obj.parse_set_cookie_headers();
            } catch (const std::exception &e) {
                // Log error but continue processing response without cookies
                // This prevents std::terminate() in noexcept context
                LOG_HTTP_WARN("Failed to parse Set-Cookie headers: " << e.what());
            } catch (...) {
                LOG_HTTP_WARN("Failed to parse Set-Cookie headers: unknown exception");
            }
            this->_io.on(std::move(response_obj));
            this->_http_obj.reset();
        }
    };

    template<typename IO_Handler>
    class client_view : public base<IO_Handler, qb::http::ResponseView> {
        using base_t = base<IO_Handler, qb::http::ResponseView>;

    public:
        /**
         * @brief Default constructor is deleted
         *
         * HTTP client view must be constructed with an IO handler.
         */
        client_view() = delete;

        /**
         * @brief Constructor with IO handler
         * @param io IO handler for network operations
         *
         * Creates an HTTP client protocol handler with view semantics,
         * attached to the provided IO handler.
         */
        explicit client_view(IO_Handler &io) noexcept
            : base_t(io) {
        }

        using response = qb::http::ResponseView;

        /**
         * @brief Process an incoming HTTP response with view semantics
         * @param size Size of the incoming message
         *
         * This method is called when a complete HTTP response is received from a server.
         * It parses the response data using the HTTP parser with string_view semantics,
         * then passes the response to the client's callback handler.
         *
         * @security CRITICAL FIX: All cookie parsing exceptions are caught to prevent
         * std::terminate() in noexcept context. Malformed cookies are logged and ignored.
         */
        void
        onMessage(std::size_t) noexcept final {
            auto &response_obj = this->_http_obj.get_parsed_message();
            // Parse cookies from the Set-Cookie headers
            // SECURITY: Wrap in try/catch - parse_set_cookie_headers() can throw
            try {
                response_obj.parse_set_cookie_headers();
            } catch (const std::exception &e) {
                // Log error but continue processing response without cookies
                // This prevents std::terminate() in noexcept context
                LOG_HTTP_WARN("Failed to parse Set-Cookie headers: " << e.what());
            } catch (...) {
                LOG_HTTP_WARN("Failed to parse Set-Cookie headers: unknown exception");
            }
            this->_io.on(std::move(response_obj));
            this->_http_obj.reset();
        }
    };
}

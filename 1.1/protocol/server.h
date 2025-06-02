/**
 * @file qbm/http/1.1/protocol/server.h
 * @brief HTTP/1.1 server protocol implementation for qb-io framework
 *
 * This file provides HTTP/1.1 server-side protocol handling built on top of
 * the qb-io asynchronous framework. It includes:
 *
 * - HTTP/1.1 request parsing and processing
 * - Cookie parsing from Cookie headers
 * - Support for both string and string_view semantics
 * - Asynchronous request handling through callbacks
 * - Integration with the base HTTP/1.1 protocol parser
 * - Request routing and response generation
 *
 * The implementation supports both owning (string-based) and non-owning
 * (string_view-based) request handling for optimal performance.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once
#include "../../request.h"
#include "./base.h"

namespace qb::protocol::http {
    /**
     * @brief HTTP server protocol implementation
     * @tparam IO_Handler Handler type for I/O operations
     *
     * This class implements the HTTP protocol for server-side operations.
     * It handles HTTP request parsing and dispatches the parsed requests
     * to the IO handler for processing.
     *
     * This implementation uses std::string for storing request data,
     * which means the request objects can be modified and stored
     * independently of the input buffer.
     */
    template<typename IO_Handler>
    class server : public base<IO_Handler, qb::http::Request> {
        using base_t = base<IO_Handler, qb::http::Request>;

    public:
        server() = delete;

        /**
         * @brief Constructor with IO handler
         * @param io IO handler for network operations
         *
         * Creates an HTTP server protocol handler attached to the provided
         * IO handler, which manages the underlying socket connections.
         */
        explicit server(IO_Handler &io) noexcept
            : base_t(io) {
        }

        using request = qb::http::Request;

        /**
         * @brief Process an incoming HTTP request
         * @param size Size of the incoming message
         *
         * This method is called when a complete HTTP request is received.
         * It parses the request data using the HTTP parser, then routes it
         * to the appropriate handler based on the request path and method.
         * The response is automatically sent back to the client.
         */
        void
        onMessage(std::size_t size) noexcept final {
            auto &request_obj = this->_http_obj.get_parsed_message();
            // Parse cookies from the Cookie header
            request_obj.parse_cookie_header();
            this->_io.on(std::move(request_obj));
            // Reset the parser without consuming (pipe API might have changed)
            this->_http_obj.reset();
        }
    };

    /**
     * @brief HTTP server protocol implementation using string_view
     * @tparam IO_Handler Handler type for I/O operations
     *
     * Similar to server, but uses string_view instead of string
     * for better performance when the request data doesn't need to be
     * modified or stored independently of the input buffer.
     */
    template<typename IO_Handler>
    class server_view : public base<IO_Handler, qb::http::RequestView> {
        using base_t = base<IO_Handler, qb::http::RequestView>;

    public:
        server_view() = delete;

        /**
         * @brief Constructor with IO handler
         * @param io IO handler for network operations
         *
         * Creates an HTTP server protocol handler with view semantics,
         * attached to the provided IO handler.
         */
        explicit server_view(IO_Handler &io) noexcept
            : base_t(io) {
        }

        using request = qb::http::RequestView;

        /**
         * @brief Process an incoming HTTP request with view semantics
         * @param size Size of the incoming message
         *
         * This method is called when a complete HTTP request is received.
         * It parses the request data using the HTTP parser, then routes it
         * to the appropriate handler based on the request path and method.
         * The response is automatically sent back to the client.
         */
        void
        onMessage(std::size_t size) noexcept final {
            auto &request_obj = this->_http_obj.get_parsed_message();
            // Parse cookies from the Cookie header
            request_obj.parse_cookie_header();
            this->_io.on(std::move(request_obj));
            // Reset the parser without consuming (pipe API might have changed)
            this->_http_obj.reset();
        }
    };
}

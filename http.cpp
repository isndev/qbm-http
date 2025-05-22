/**
 * @file qbm/http/http.cpp
 * @brief Main include file for the QB HTTP client and server module.
 *
 * This header aggregates all core components of the qb-http module, providing a comprehensive
 * suite for HTTP/1.1 communication. It defines foundational classes for requests (`qb::http::Request`),
 * responses (`qb::http::Response`), message parsing (`qb::http::Parser`), asynchronous client
 * operations (`qb::http::async`), protocol handlers (`qb::protocol::http_server`, `qb::protocol::http_client`),
 * and server-side routing (`qb::http::Router`).
 *
 * The module is designed for high performance and integration with the qb-io asynchronous
 * I/O layer, leveraging libev for event handling. It supports features like content
 * compression, cookie management, multipart forms, and customizable routing.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include "http.h"
#include "multipart.h"

#if defined(_WIN32)
#undef DELETE // Windows :/
#endif

#include <sstream>
#include <iostream>

namespace qb::http {
    /**
     * @brief Macro to register synchronous HTTP functions
     * @param num HTTP method code
     * @param name HTTP method name
     * @param description HTTP method description
     *
     * Generates synchronous versions of HTTP method functions that wrap the asynchronous
     * API. These functions block until a response is received or timeout occurs, making them
     * easier to use when synchronous behavior is needed.
     *
     * Each generated function:
     * 1. Accepts a request and an optional timeout
     * 2. Creates an asynchronous request with a completion callback
     * 3. Runs the event loop until the response is received
     * 4. Returns the response object
     */
#define REGISTER_HTTP_SYNC_FUNCTION(num, name, description) \
    Response name(Request request, double timeout) {        \
        Response response;                                  \
        bool     wait = true;                               \
        name(                                               \
            request,                                        \
            [&response, &wait](async::Reply &&reply) {      \
                response = std::move(reply.response);       \
                wait     = false;                           \
            },                                              \
            timeout);                                       \
        qb::io::async::run_until(wait);                     \
        return response;                                    \
    }

    REGISTER_HTTP_SYNC_FUNCTION(-1, REQUEST, "User defined")
    HTTP_METHOD_MAP(REGISTER_HTTP_SYNC_FUNCTION)
} // namespace qb::http

namespace qb::allocator {
    /**
     * @brief Serialize an HTTP Request into a byte stream
     * @param r HTTP Request to serialize
     * @return Reference to this pipe
     *
     * Formats an HTTP request into a properly formatted request string
     * including request line, headers, and body.
     *
     * The format follows the HTTP/1.1 specification with:
     * - Request line: METHOD PATH HTTP/VERSION
     * - Headers: HEADER: VALUE
     * - Empty line separator
     * - Request body (if present)
     */
    template<>
    pipe<char> &
    pipe<char>::put<qb::http::Request>(const qb::http::Request &r) {
        // HTTP Status Line
        *this << ::http_method_name(r.method()) << qb::http::sep
                << r.uri().path();
        if (r.uri().encoded_queries().size())
            *this << "?" << r.uri().encoded_queries();
        if (r.uri().fragment().size())
            *this << "#" << r.uri().fragment();
        *this << qb::http::sep << "HTTP/" << r.major_version << "." << r.minor_version
                << qb::http::endl;
        // HTTP Headers
        for (const auto &it: r.headers()) {
            for (const auto &value: it.second)
                *this << it.first << ": " << value << qb::http::endl;
        }
        // Body
        const auto length = r.body().size();
        const auto is_chunked = r.header("Transfer-Encoding").find("chunked") != std::string::npos;
        if (length && !is_chunked) {
            if (!r.has_header("Content-Length")) {
                *this << "content-length: " << length << qb::http::endl;
            }
            *this << qb::http::endl
                    << r.body().raw();
        } else
            *this << qb::http::endl;
        return *this;
    }

    /**
     * @brief Serialize an HTTP Response into a byte stream
     * @param r HTTP Response to serialize
     * @return Reference to this pipe
     *
     * Formats an HTTP response into a properly formatted response string
     * including status line, headers, and body.
     *
     * The format follows the HTTP/1.1 specification with:
     * - Status line: HTTP/VERSION STATUS_CODE STATUS_TEXT
     * - Headers: HEADER: VALUE
     * - Empty line separator
     * - Response body (if present)
     *
     * This method also handles automatic compression of the body
     * if Content-Encoding header is present.
     */
    template<>
    pipe<char> &
    pipe<char>::put<qb::http::Response>(const qb::http::Response &r) {
        // HTTP Status Line
        *this << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::sep
                << r.status() << qb::http::sep
                << std::to_string(r.status())
                << qb::http::endl;
        // HTTP Headers
        for (const auto &it: r.headers()) {
            for (const auto &value: it.second)
                *this << it.first << ": " << value << qb::http::endl;
        }
        // Body
        const auto length = r.body().size();
        const auto is_chunked = r.header("Transfer-Encoding").find("chunked") != std::string::npos;
        if (length && !is_chunked) {
            if (!r.has_header("Content-Length")) {
                *this << "content-length: " << length << qb::http::endl;
            }
            *this << qb::http::endl
                    << r.body().raw();
        } else
            *this << qb::http::endl;
        return *this;
    }
} // namespace qb::allocator

// templates instantiation
// objects
template struct qb::http::TRequest<std::string>;
template struct qb::http::TRequest<std::string_view>;
template struct qb::http::TResponse<std::string>;
template struct qb::http::TResponse<std::string_view>;

/**
 * @file http.cpp
 * @brief Implementation of the HTTP client and server for the QB Actor Framework
 *
 * This file contains the implementation of the HTTP protocol features defined in http.h,
 * providing concrete implementations for:
 *
 * - HTTP request and response serialization and deserialization
 * - HTTP header parsing and cookie handling
 * - Content compression and decompression
 * - Multipart form data parsing and generation
 * - HTTP message body management
 * - Utility functions for HTTP protocol operations
 *
 * The implementation follows HTTP/1.1 standards (RFCs 7230-7235) and provides
 * efficient, high-performance processing of HTTP messages in both client and server
 * contexts.
 *
 * @see http.h for interface definitions and API documentation
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2021 isndev (www.qbaf.io)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "http.h"
#include "multipart.h"
#if defined(_WIN32)
#undef DELETE // Windows :/
#endif

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

namespace qb::http {

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
template <>
pipe<char> &
pipe<char>::put<qb::http::Request>(const qb::http::Request &r) {
    // HTTP Status Line
    *this << ::http_method_name(static_cast<http_method_t>(r.method)) << qb::http::sep
          << r.uri().path();
    if (r.uri().encoded_queries().size())
        *this << "?" << r.uri().encoded_queries();
    if (r.uri().fragment().size())
        *this << "#" << r.uri().fragment();
    *this << qb::http::sep << "HTTP/" << r.major_version << "." << r.minor_version
          << qb::http::endl;
    // HTTP Headers
    for (const auto &it : r.headers()) {
        for (const auto &value : it.second)
            *this << it.first << ": " << value << qb::http::endl;
    }
    // Body
    const auto length = r.body().size();
    if (length) {
        *this << "content-length: " << length << qb::http::endl << qb::http::endl;
        *this << r.body().raw();
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
template <>
pipe<char> &
pipe<char>::put<qb::http::Response>(const qb::http::Response &r) {
    // HTTP Status Line
    *this << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::sep
          << r.status_code << qb::http::sep
          << (r.status.empty()
                  ? ::http_status_name(static_cast<http_status>(r.status_code))
                  : r.status.c_str())
          << qb::http::endl;
    // HTTP Headers
    for (const auto &it : r.headers()) {
        for (const auto &value : it.second)
            *this << it.first << ": " << value << qb::http::endl;
    }
    // Body
    auto length = r.body().size();
    if (length) {
        if (r.has_header("Content-Encoding"))
            length = const_cast<qb::http::Response &>(r).body().compress(
                r.header("Content-Encoding"));

        *this << "content-length: " << length << qb::http::endl
              << qb::http::endl
              << r.body().raw();
    } else
        *this << qb::http::endl;
    return *this;
}

/**
 * @brief Serialize an HTTP Chunk into a byte stream
 * @param c HTTP Chunk to serialize
 * @return Reference to this pipe
 *
 * Formats an HTTP chunk according to the chunked transfer encoding
 * specification (RFC 7230).
 *
 * The format is:
 * - Chunk size in hexadecimal
 * - CRLF
 * - Chunk data
 * - CRLF
 *
 * A zero-length chunk (with size "0") represents the end of the
 * chunked data stream.
 */
template <>
pipe<char> &
pipe<char>::put<qb::http::Chunk>(const qb::http::Chunk &c) {
    constexpr static const std::size_t hex_len  = sizeof(std::size_t) << 1u;
    static const char                  digits[] = "0123456789ABCDEF";
    if (c.size()) {
        std::string rc(hex_len, '0');
        auto        f_pos = 0u;
        for (size_t i = 0u, j = (hex_len - 1u) * 4u; i < hex_len; ++i, j -= 4u) {
            const auto offset = (c.size() >> j) & 0x0fu;
            rc[i]             = digits[offset];
            if (!offset)
                ++f_pos;
        }
        std::string_view hex_view(rc.c_str() + f_pos, rc.size() - f_pos);
        *this << hex_view << qb::http::endl;
        put(c.data(), c.size());
    } else {
        *this << '0' << qb::http::endl;
    }

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
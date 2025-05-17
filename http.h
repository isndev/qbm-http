/**
 * @file http.h
 * @brief HTTP client and server implementation for the QB Actor Framework
 *
 * This file implements a comprehensive HTTP client and server stack integrated with the
 * QB Actor Framework. It provides a non-blocking, asynchronous interface for HTTP
 * operations including:
 *
 * - HTTP 1.1 client and server implementations
 * - Request and response handling with full header support
 * - Content negotiation and compression support
 * - Form data and multipart content handling
 * - Cookie management and parsing
 * - RESTful routing with parameter extraction
 * - High-performance message parsing using llhttp
 * - Support for both string and string_view based operations
 * - WebSocket upgrade support
 *
 * The implementation is designed to work with the actor model, allowing
 * network I/O operations to be performed without blocking actor threads.
 * The module fully implements the HTTP/1.1 protocol for efficient communication.
 *
 * Key features:
 * - Asynchronous I/O using the QB Actor Framework
 * - Support for both plain TCP and SSL/TLS connections
 * - Content compression (when built with zlib support)
 * - Flexible routing system for server implementations
 * - RESTful API support with path parameter extraction
 * - Streaming support through chunked transfer encoding
 * - Detailed error reporting and handling
 * - Performance optimized header and body processing
 *
 * @see qb::http::Request
 * @see qb::http::Response
 * @see qb::http::async
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 isndev (www.qbaf.io)
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

#ifndef QB_MODULE_HTTP_H_
#define QB_MODULE_HTTP_H_
#include <qb/io/async.h>
#include <qb/io/async/listener.h>
#include <qb/io/async/tcp/connector.h>
#include <qb/io/transport/file.h>
#include <qb/json.h>
#include <qb/system/allocator/pipe.h>
#include <qb/system/container/unordered_map.h>
#include <qb/system/timestamp.h>
#ifdef QB_IO_WITH_ZLIB
#include <qb/io/compression.h>
#endif
#include <random>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include "./types.h"
#include "./body.h"
#include "./cookie.h"
#include "./date.h"
#include "./headers.h"
#include "./message_base.h"
#include "./request.h"
#include "./response.h"
#include "./utility.h"
#include "./multipart.h"
#include "./routing.h"
#include "./auth.h"
#include "./validation.h"

#if defined(_WIN32)
#undef DELETE // Windows :/
#endif

/**
 * @brief HTTP module namespace for the QB C++ Actor Framework
 *
 * This namespace provides a comprehensive set of classes and functions for HTTP protocol
 * handling, including client and server implementations, request/response processing,
 * header management, content negotiation, and routing. The implementation follows
 * HTTP/1.1 standards and supports advanced features such as:
 *
 * - Complete HTTP request and response handling with headers and body processing
 * - Content compression and decompression (with zlib support)
 * - Cookie parsing and management (RFC 6265)
 * - Multipart form data handling (RFC 7578)
 * - Date handling for HTTP headers (RFC 7231)
 * - RESTful API routing with path parameter extraction
 * - Asynchronous client and server implementations
 * - Support for both string and string_view based operations for performance
 * optimization
 *
 * The HTTP module is built on top of the QB Actor Framework's asynchronous I/O system,
 * making it fully non-blocking and suitable for high-performance applications.
 */
namespace qb::http {

/**
 * @brief HTTP message parser
 * @tparam MessageType The message type to parse (Request or Response)
 *
 * Parser based on llhttp that handles HTTP messages. It processes
 * headers, body chunks, and status information according to the
 * HTTP protocol specification. Key features include:
 *
 * - High-performance message parsing using the llhttp library
 * - Event-driven callback architecture for efficient processing
 * - Support for chunked transfer encoding
 * - Header field and value parsing with case-insensitive handling
 * - Content-Length detection and body allocation optimization
 * - Support for both request and response parsing
 * - Proper HTTP version detection
 * - Upgrade protocol handling (e.g., for WebSockets)
 *
 * The parser implements the HTTP/1.1 specification and correctly handles
 * all standard HTTP message elements, providing a robust foundation for
 * both client and server implementations.
 */
template <typename MessageType>
struct Parser : public http_t {
    using String = typename MessageType::string_type;

    /**
     * @brief Default callback for HTTP data
     * 
     * This is a placeholder callback that does nothing with the data.
     * It's used as a default for callbacks that aren't explicitly implemented.
     * 
     * @param parser Parser instance
     * @param at Pointer to data
     * @param length Length of data
     * @return Always returns 0 (success)
     */
    static int
    default_http_data_cb(http_t *, const char *, size_t) {
        return 0;
    }

    /**
     * @brief Default callback for HTTP events
     * 
     * This is a placeholder callback for HTTP events that don't need
     * special handling in this implementation.
     * 
     * @param parser Parser instance
     * @return Always returns 0 (success)
     */
    static int
    default_http_cb(http_t *) {
        return 0;
    }

    /**
     * @brief URL parsing callback
     * @param parser Parser instance
     * @param at Pointer to URL data
     * @param length Length of URL data
     * @return Result code (0 for success)
     *
     * Called when the URL portion of a request is parsed.
     * Extracts and stores the URL for further processing.
     * This is only used for request messages; for response
     * messages, this callback does nothing.
     */
    static int
    on_url(http_t *parser, const char *at, size_t length) {
        if constexpr (MessageType::type == HTTP_REQUEST) {
            auto &msg  = static_cast<Parser *>(parser->data)->msg;
            msg.method = static_cast<http_method>(parser->method);
            msg._uri   = std::string{at, length};
        } else {
            (void) at;
            (void) length;
        }
        return 0;
    }

    /**
     * @brief Status message parsing callback
     * @param parser Parser instance
     * @param at Pointer to status message data
     * @param length Length of status message data
     * @return Result code (0 for success)
     *
     * Called when the status message portion of a response is parsed.
     * Extracts and stores the status message for the response.
     * This is only used for response messages; for request
     * messages, this callback does nothing.
     */
    static int
    on_status(http_t *parser, const char *at, size_t length) {
        if constexpr (MessageType::type == HTTP_RESPONSE) {
            auto &msg       = static_cast<Parser *>(parser->data)->msg;
            msg.status_code = static_cast<http_status>(parser->status_code);
            msg.status      = String(at, length);
        }
        return 0;
    }

    /**
     * @brief Header field name parsing callback
     * @param parser Parser instance
     * @param at Pointer to header field name data
     * @param length Length of header field name data
     * @return Result code (0 for success)
     *
     * Called when a header field name is parsed.
     * Stores the header field name for association with its value.
     * Header field names are case-insensitive as per HTTP specification.
     */
    static int
    on_header_field(http_t *parser, const char *at, size_t length) {
        static_cast<Parser *>(parser->data)->_last_header_key = String(at, length);
        return 0;
    }

    /**
     * @brief Header value parsing callback
     * @param parser Parser instance
     * @param at Pointer to header value data
     * @param length Length of header value data
     * @return Result code (0 for success)
     *
     * Called when a header value is parsed.
     * Associates the value with the previously parsed header field name.
     * Multiple values for the same header are stored as a vector.
     */
    static int
    on_header_value(http_t *parser, const char *at, size_t length) {
        auto &msg = static_cast<Parser *>(parser->data)->msg;
        msg.headers()[String{static_cast<Parser *>(parser->data)->_last_header_key}]
            .push_back(String(at, length));
        return 0;
    }

    /**
     * @brief Headers complete callback
     * @param parser Parser instance
     * @return HPE_PAUSED to pause the parser after headers
     *
     * Called when all headers have been parsed.
     * Finalizes header processing and prepares for body parsing.
     * This callback:
     * 1. Sets the HTTP version
     * 2. Reserves memory for the body based on Content-Length if available
     * 3. Sets the upgrade flag if applicable
     * 4. Marks headers as completed and pauses the parser
     * 
     * The parser is paused to allow the application to process headers
     * before continuing with the body.
     */
    static int
    on_headers_complete(http_t *parser) {
        auto &msg         = static_cast<Parser *>(parser->data)->msg;
        msg.major_version = parser->http_major;
        msg.minor_version = parser->http_major;
        if (parser->content_length != ULLONG_MAX) {
            msg.body().raw().reserve(parser->content_length);
        }
        msg.upgrade = static_cast<bool>(parser->upgrade);
        static_cast<Parser *>(parser->data)->_headers_completed = true;
        return HPE_PAUSED;
    }

    /**
     * @brief Message body parsing callback
     * @param parser Parser instance
     * @param at Pointer to body data
     * @param length Length of body data
     * @return Result code (0 for success)
     *
     * Called when a portion of the message body is parsed.
     * Accumulates the body data in the chunked buffer.
     * This is efficient for handling large bodies or
     * chunked transfer encoding.
     */
    static int
    on_body(http_t *parser, const char *at, size_t length) {
        auto &chunked = static_cast<Parser *>(parser->data)->_chunked;
        std::copy_n(at, length, chunked.allocate_back(length));
        return 0;
    }

    /**
     * @brief Message complete callback
     * @param parser Parser instance
     * @return 1 to signal message completion
     *
     * Called when the entire HTTP message has been parsed.
     * Finalizes message processing by:
     * 1. Setting the content type from the Content-Type header
     * 2. Moving the accumulated body data to the message body
     * 3. Returning 1 to signal message completion
     */
    static int
    on_message_complete(http_t *parser) {
        auto p = static_cast<Parser *>(parser->data);
        p->msg.set_content_type(p->msg.header("Content-Type"));
        p->msg.body().raw() = std::move(p->_chunked);
        return 1;
    }

protected:
    MessageType msg;  ///< The message being constructed (Request or Response)

private:
    /**
     * @brief HTTP parser settings with callback functions
     * 
     * This static configuration defines all the callbacks used by the
     * llhttp parser. Most callbacks are set to default no-op functions,
     * while the essential ones are set to the specific handlers defined
     * in this class.
     */
    static const http_settings_s inline settings{
        &Parser::default_http_cb,      // on message begin
        &Parser::default_http_data_cb, // on protocol
        &Parser::on_url,               // on url
        &Parser::on_status,            // on status
        &Parser::default_http_data_cb, // on method
        &Parser::default_http_data_cb, // on version
        &Parser::on_header_field,      // on header field
        &Parser::on_header_value,      // on header value
        &Parser::default_http_data_cb, // on chunk extention name
        &Parser::default_http_data_cb, // on chunk extension value
        &Parser::on_headers_complete,  // on headers complete
        &Parser::on_body,              // on body
        &Parser::on_message_complete,  // on message complete
        &Parser::default_http_cb,      // on protocol complete
        &Parser::default_http_cb,      // on url complete
        &Parser::default_http_cb,      // on status complete
        &Parser::default_http_cb,      // on method complete
        &Parser::default_http_cb,      // on version complete
        &Parser::default_http_cb,      // on header field complete
        &Parser::default_http_cb,      // on header value complete
        &Parser::default_http_cb,      // on chunk extention name complete
        &Parser::default_http_cb,      // on chunk extension value complete
        &Parser::default_http_cb,      // on chunk header
        &Parser::default_http_cb,      // on chunk complete
        &Parser::default_http_cb       // on reset
    };
    String                    _last_header_key;   ///< Storage for the current header field name
    bool                      _headers_completed = false; ///< Flag indicating if headers have been fully parsed
    qb::allocator::pipe<char> _chunked;          ///< Buffer for body content

public:
    /**
     * @brief Constructor
     * 
     * Initializes the parser and immediately calls reset() to prepare
     * it for parsing a new message.
     */
    Parser() noexcept
        : http__internal_s() {
        reset();
    };

    /**
     * @brief Parse an HTTP message
     * @param buffer Buffer containing the message data
     * @param size Size of the buffer
     * @return HTTP parser error code or HPE_OK on success
     *
     * Parses HTTP message data according to HTTP/1.1 specification.
     * This method can handle both full messages and partial messages.
     * For partial messages, it can be called multiple times with
     * subsequent chunks of data until a complete message is parsed.
     *
     * When a parsing error occurs, the error_pos field is set to point
     * to the position in the buffer where the error occurred, which
     * can be useful for debugging.
     */
    http_errno_t
    parse(const char *buffer, std::size_t const size) {
        return http_execute(static_cast<http_t *>(this), buffer, size);
    }

    /**
     * @brief Reset the parser state
     *
     * Clears all parser state and prepares it for parsing a new message.
     * This includes:
     * 1. Reinitializing the parser with the appropriate message type
     * 2. Setting the data pointer to this instance for callbacks
     * 3. Resetting the message object
     * 4. Clearing the headers_completed flag
     * 5. Clearing any accumulated body data
     *
     * This method should be called before reusing the parser for a new
     * message or after an error occurs to restore the parser to a clean state.
     */
    void
    reset() noexcept {
        http_init(static_cast<http_t *>(this), MessageType::type, &settings);
        this->data = this;
        msg.reset();
        _headers_completed = false;
        _chunked.clear();
    }

    /**
     * @brief Resume parsing after headers are completed
     *
     * Transitions the parser from header parsing mode to body parsing mode.
     * This is typically called after headers_completed() returns true and
     * the application has processed the headers but wants to continue
     * parsing the message body.
     *
     * This is particularly useful for handling chunked transfer encoding
     * or when processing a message in multiple stages, such as:
     * 1. Parse headers
     * 2. Examine Content-Type, Content-Length, etc.
     * 3. Decide how to handle the body
     * 4. Resume parsing to process the body
     */
    void
    resume() noexcept {
        http_resume(static_cast<http_t *>(this));
    }

    /**
     * @brief Get the parsed message
     * @return Reference to the parsed message
     *
     * Provides access to the message object (Request or Response) that has
     * been constructed from the parsed HTTP data. After successful parsing,
     * this message contains all headers, body content, and metadata such as
     * status code or HTTP method.
     *
     * This method is typically used after parsing is complete to retrieve
     * the resulting HTTP message for further processing or response generation.
     */
    [[nodiscard]] MessageType &
    get_parsed_message() noexcept {
        return msg;
    }

    /**
     * @brief Check if headers have been completely parsed
     * @return true if headers are fully parsed
     *
     * Indicates whether the parser has finished parsing the headers
     * section of the HTTP message. This is useful for determining
     * when header information is available for processing but before
     * the full message (including body) has been parsed.
     * 
     * Common uses include:
     * - Early rejection of requests with invalid headers
     * - Content negotiation before processing the body
     * - Determining if a request should be upgraded (e.g., to WebSockets)
     */
    [[nodiscard]] bool
    headers_completed() const noexcept {
        return _headers_completed;
    }
};

namespace route {
#define REGISTER_ROUTE_FUNCTION(num, name, description) \
    /**                                                 \
     * @brief HTTP route handler for description        \
     * @tparam _Func Function type for handling routes  \
     *                                                  \
     * Stores a path and a function to handle requests  \
     * with the HTTP method described by description.   \
     */                                                 \
    template <typename _Func>                           \
    struct name {                                       \
        std::string   _path;                            \
        mutable _Func _func;                            \
        const int     _num = num;                       \
        /**                                             \
         * @brief Constructor                           \
         * @param path URL path pattern                 \
         * @param func Function to handle the route     \
         *                                              \
         * Creates a route handler for a specific path  \
         * and HTTP method.                             \
         */                                             \
        name(std::string path, _Func &&func)            \
            : _path(std::move(path))                    \
            , _func(std::move(func)) {}                 \
    };

HTTP_METHOD_MAP(REGISTER_ROUTE_FUNCTION)

#undef REGISTER_ROUTE_FUNCTION
} // namespace route

} // namespace qb::http

namespace qb::protocol {
namespace http_internal {

/**
 * @brief Base protocol implementation for HTTP
 * @tparam IO_Handler Handler type for I/O operations
 * @tparam Trait Message trait type (Request or Response)
 *
 * This class implements the core HTTP protocol handling functionality.
 * It parses incoming HTTP messages and extracts headers and body content
 * according to the HTTP/1.1 specification. It handles:
 *
 * - Message header parsing
 * - Content length detection
 * - Chunked transfer encoding
 * - Message completion detection
 * - Buffer management for partial messages
 *
 * The class is used as a base for both client-side (response parsing)
 * and server-side (request parsing) protocol handlers.
 */
template <typename IO_Handler, typename Trait>
class base : public qb::io::async::AProtocol<IO_Handler> {
    using String = typename qb::http::Parser<std::remove_const_t<Trait>>::String;
    std::size_t body_offset = 0; ///< Current offset for body parsing

protected:
    qb::http::Parser<std::remove_const_t<Trait>> _http_obj; ///< HTTP parser

public:
    typedef String string_type;                      ///< String type used for storage

    /**
     * @brief Default constructor is deleted
     *
     * A base protocol must be constructed with an IO handler.
     */
    base() = delete;

    /**
     * @brief Construct a protocol handler with an IO handler
     * @param io IO handler to use for I/O operations
     *
     * Creates a protocol handler that uses the given IO handler
     * for reading and writing data.
     */
    explicit base(IO_Handler &io) noexcept
        : qb::io::async::AProtocol<IO_Handler>(io) {}

    /**
     * @brief Calculate the size of a complete HTTP message
     * @return Size of the complete message if available, 0 otherwise
     *
     * This method implements the AProtocol interface by parsing the
     * input buffer to determine if a complete HTTP message is available.
     *
     * For HTTP, this involves:
     * 1. Parsing headers if not already parsed
     * 2. Determining the body length from Content-Length or Transfer-Encoding
     * 3. Checking if the entire message (headers + body) is available
     *
     * If a complete message is available, returns its size. Otherwise,
     * returns 0 to indicate more data is needed.
     */
    std::size_t
    getMessageSize() noexcept final {
        if (!_http_obj.headers_completed()) {
            // parse headers
            const auto ret =
                _http_obj.parse(this->_io.in().begin(), this->_io.in().size());
            if (ret == HPE_OK) {
                // restart parsing for next time;
                _http_obj.reset();
                return 0;
            }

            if (!_http_obj.headers_completed()) {
                this->not_ok();
                return 0;
            }

            body_offset = _http_obj.error_pos - this->_io.in().begin();
        }

        auto &msg = _http_obj.get_parsed_message();

        if (msg.has_header("Transfer-Encoding")) {
            _http_obj.resume();
            const auto ret = _http_obj.parse(this->_io.in().begin() + body_offset,
                                             this->_io.in().size() - body_offset);

            if (ret == HPE_CB_MESSAGE_COMPLETE) {
                body_offset = 0;
                return _http_obj.error_pos - this->_io.in().begin();
            } else if (ret == HPE_OK) {
                if constexpr (std::is_same_v<std::string_view, String>) {
                    _http_obj.reset();
                    body_offset = 0;
                } else
                    body_offset = this->_io.in().size();
            } else
                this->not_ok();
            return 0;
        }

        const auto full_size = body_offset + _http_obj.content_length;
        if (this->_io.in().size() < full_size) {
            // if is protocol view reset parser for next read
            if constexpr (std::is_same_v<std::string_view, String>) {
                _http_obj.reset();
                body_offset = 0;
            }
            return 0; // incomplete body
        }

        if (_http_obj.content_length)
            msg.body() = std::string_view(
                this->_io.in().cbegin() + body_offset, _http_obj.content_length);

        body_offset = 0;

        return full_size;
    }

    /**
     * @brief Reset the protocol handler
     *
     * Resets the internal state of the protocol handler, clearing
     * any partially parsed message data and preparing for a new message.
     * This is called when a message is completed or when an error occurs.
     */
    void
    reset() noexcept final {
        body_offset = 0;
        _http_obj.reset();
    }
};

} // namespace http_internal

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
template <typename IO_Handler>
class http_server : public http_internal::base<IO_Handler, qb::http::Request> {
    using base_t = http_internal::base<IO_Handler, qb::http::Request>;

public:
    http_server() = delete;
    /**
     * @brief Constructor with IO handler
     * @param io IO handler for network operations
     *
     * Creates an HTTP server protocol handler attached to the provided
     * IO handler, which manages the underlying socket connections.
     */
    explicit http_server(IO_Handler &io) noexcept
        : base_t(io) {}

    /**
     * @brief Container for HTTP request data
     *
     * Stores information about a received HTTP request including
     * the raw data pointer, message size, and parsed HTTP request.
     */
    struct request {
        const std::size_t size{}; ///< Size of the request data
        const char       *data{}; ///< Pointer to raw request data
        qb::http::Request http;   ///< Parsed HTTP request object
    };

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
        auto& request_obj = this->_http_obj.get_parsed_message();
        // Parse cookies from the Cookie header
        request_obj.parse_cookie_header();
        this->_io.on(request{size, this->_io.in().begin(),
                             std::move(request_obj)});
        // Reset the parser without consuming (pipe API might have changed)
        this->_http_obj.reset();
    }
};

/**
 * @brief HTTP server protocol implementation using string_view
 * @tparam IO_Handler Handler type for I/O operations
 *
 * Similar to http_server, but uses string_view instead of string
 * for better performance when the request data doesn't need to be
 * modified or stored independently of the input buffer.
 */
template <typename IO_Handler>
class http_server_view : public http_internal::base<IO_Handler, qb::http::RequestView> {
    using base_t = http_internal::base<IO_Handler, qb::http::RequestView>;

public:
    http_server_view() = delete;
    /**
     * @brief Constructor with IO handler
     * @param io IO handler for network operations
     *
     * Creates an HTTP server protocol handler with view semantics,
     * attached to the provided IO handler.
     */
    explicit http_server_view(IO_Handler &io) noexcept
        : base_t(io) {}

    /**
     * @brief Container for HTTP request data using views
     *
     * Stores information about a received HTTP request including
     * the raw data pointer, message size, and parsed HTTP request
     * using string_view for better performance.
     */
    struct request {
        const std::size_t     size{}; ///< Size of the request data
        const char           *data{}; ///< Pointer to raw request data
        qb::http::RequestView http;   ///< Parsed HTTP request object with views
    };

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
        auto& request_obj = this->_http_obj.get_parsed_message();
        // Parse cookies from the Cookie header
        request_obj.parse_cookie_header();
        this->_io.on(request{size, this->_io.in().begin(),
                             std::move(request_obj)});
        // Reset the parser without consuming (pipe API might have changed)
        this->_http_obj.reset();
    }
};

template <typename IO_Handler>
class http_client : public http_internal::base<IO_Handler, qb::http::Response> {
    using base_t = http_internal::base<IO_Handler, qb::http::Response>;

public:
    /**
     * @brief Default constructor is deleted
     *
     * HTTP client must be constructed with an IO handler.
     */
    http_client() = delete;

    /**
     * @brief Constructor with IO handler
     * @param io IO handler for network operations
     *
     * Creates an HTTP client protocol handler attached to the provided
     * IO handler, which manages the underlying socket connections.
     */
    explicit http_client(IO_Handler &io) noexcept
        : base_t(io) {}

    /**
     * @brief Container for HTTP response data
     *
     * Stores information about a received HTTP response including
     * the raw data pointer, message size, and parsed HTTP response.
     */
    struct response {
        const std::size_t  size{}; ///< Size of the response data
        const char        *data{}; ///< Pointer to raw response data
        qb::http::Response http;   ///< Parsed HTTP response object
    };

    /**
     * @brief Process an incoming HTTP response
     * @param size Size of the incoming message
     *
     * This method is called when a complete HTTP response is received from a server.
     * It parses the response data using the HTTP parser, then passes the
     * response to the client's callback handler.
     */
    void
    onMessage(std::size_t size) noexcept final {
        auto& response_obj = this->_http_obj.get_parsed_message();
        // Parse cookies from the Set-Cookie headers
        response_obj.parse_set_cookie_headers();
        this->_io.on(response{size, this->_io.in().begin(),
                              std::move(response_obj)});
        this->_http_obj.reset();
    }
};

template <typename IO_Handler>
class http_client_view : public http_internal::base<IO_Handler, qb::http::ResponseView> {
    using base_t = http_internal::base<IO_Handler, qb::http::ResponseView>;

public:
    /**
     * @brief Default constructor is deleted
     *
     * HTTP client view must be constructed with an IO handler.
     */
    http_client_view() = delete;

    /**
     * @brief Constructor with IO handler
     * @param io IO handler for network operations
     *
     * Creates an HTTP client protocol handler with view semantics,
     * attached to the provided IO handler.
     */
    explicit http_client_view(IO_Handler &io) noexcept
        : base_t(io) {}

    /**
     * @brief Container for HTTP response data using views
     *
     * Stores information about a received HTTP response including
     * the raw data pointer, message size, and parsed HTTP response
     * using string_view for better performance.
     */
    struct response {
        const std::size_t      size{}; ///< Size of the response data
        const char            *data{}; ///< Pointer to raw response data
        qb::http::ResponseView http;   ///< Parsed HTTP response object with views
    };

    /**
     * @brief Process an incoming HTTP response with view semantics
     * @param size Size of the incoming message
     *
     * This method is called when a complete HTTP response is received from a server.
     * It parses the response data using the HTTP parser with string_view semantics,
     * then passes the response to the client's callback handler.
     */
    void
    onMessage(std::size_t size) noexcept final {
        auto& response_obj = this->_http_obj.get_parsed_message();
        // Parse cookies from the Set-Cookie headers
        response_obj.parse_set_cookie_headers();
        this->_io.on(response{size, this->_io.in().begin(),
                              std::move(response_obj)});
        this->_http_obj.reset();
    }
};

} // namespace qb::protocol
namespace qb::http {

namespace internal {

template <typename IO_Handler, bool has_server = IO_Handler::has_server>
struct side {
    using protocol      = qb::protocol::http_server<IO_Handler>;
    using protocol_view = qb::protocol::http_server_view<IO_Handler>;
};

/**
 * @brief Protocol selector specialization for client-side IO handlers
 * @tparam IO_Handler The IO handler type
 *
 * Selects client protocol implementations for client-side IO handlers.
 */
template <typename IO_Handler>
struct side<IO_Handler, false> {
    using protocol      = qb::protocol::http_client<IO_Handler>;
    using protocol_view = qb::protocol::http_client_view<IO_Handler>;
};

} // namespace internal

/**
 * @brief Get the appropriate protocol type for an IO handler
 * @tparam IO_Handler The IO handler type
 */
template <typename IO_Handler>
using protocol = typename internal::side<IO_Handler>::protocol;

/**
 * @brief Get the appropriate string_view-based protocol type for an IO handler
 * @tparam IO_Handler The IO handler type
 */
template <typename IO_Handler>
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
class session : public io::async::tcp::client<session<Func, Transport>, Transport> {
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
                req.headers()["User-Agent"] = {"qb/1.0.0"};
            req.headers()["Accept-Encoding"] = {accept_encoding()};
            return req;
        }(request))) {
        this->template switch_protocol<http_protocol>(*this);
    }
    ~session() = default;

    /**
     * @brief Connect to a remote server
     * @param remote URI to connect to
     * @param timeout Connection timeout
     */
    void
    connect(qb::io::uri const &remote, double timeout = 0) {
        qb::io::async::tcp::connect<typename Transport::transport_io_type>(
            remote,
            [this](auto &&transport) {
                if (!transport.is_open()) {
                    Response response;
                    response.status_code = HTTP_STATUS_SERVICE_UNAVAILABLE;

                    _func(Reply{std::move(_request), std::move(response)});
                    delete this;
                } else {
                    this->transport() = std::forward<decltype(transport)>(transport);
                    this->start();
#ifdef QB_IO_WITH_ZLIB
                    if (_request.has_header("Content-Encoding")) {
                        _request.body().compress(_request.header("Content-Encoding"));
                    }
#else
                    if (_request.header("Content-Encoding") != "chunked") {
                        _request.remove_header("Content-Encoding");
                    }
#endif
                    *this << _request;
                }
            },
            timeout);
    }

    /**
     * @brief Handle response event
     * @param event Response event
     */
    void
    on(typename http_protocol::response event) {
        auto &response = event.http;
#ifdef QB_IO_WITH_ZLIB
        try {
            if (response.has_header("Content-Encoding")) {
                response.body().uncompress(response.header("Content-Encoding"));
            }
        } catch (std::exception &e) {
            LOG_WARN("[http] failed to decompress: " << e.what());
            response.status_code = HTTP_STATUS_BAD_REQUEST;
        }
#endif
        _func(Reply{std::move(_request), std::move(event.http)});
        this->disconnect(1);
    }

    /**
     * @brief Handle disconnection event
     * @param event Disconnection event
     */
    void
    on(qb::io::async::event::disconnected const &event) {
        if (!event.reason) {
            Response response;
            response.status_code = HTTP_STATUS_GONE;
            _func(Reply{std::move(_request), std::move(response)});
        }
    }

    /**
     * @brief Handle disposal event
     * @param event Disposal event
     */
    void
    on(qb::io::async::event::dispose const &) {
        delete this;
    }
};

/**
 * @brief HTTP client using TCP transport
 * @tparam Func Callback function type
 */
template <typename Func>
using HTTP = session<Func, qb::io::transport::tcp>;

#ifdef QB_IO_WITH_SSL
/**
 * @brief HTTPS client using SSL/TLS transport
 * @tparam Func Callback function type
 */
template <typename Func>
using HTTPS = session<Func, qb::io::transport::stcp>;

} // namespace async

#define EXEC_REQUEST()                                                \
    if (request.uri().scheme() == "https")                            \
        (new async::HTTPS<_Func>(std::forward<_Func>(func), request)) \
            ->connect(request.uri(), timeout);                        \
    else                                                              \
        (new async::HTTP<_Func>(std::forward<_Func>(func), request))  \
            ->connect(request.uri(), timeout);

#else
#define EXEC_REQUEST() \
    (new HTTP<_Func>(std::forward<_Func>(func), request))->connect(remote, timeout);
#endif

/**
 * @brief Macro for registering asynchronous HTTP API functions
 *
 * This macro defines template functions for each HTTP method that accept:
 * - A request object
 * - A callback function to handle the response
 * - An optional timeout parameter
 *
 * The macro creates functions like GET(), POST(), etc. that execute
 * the request asynchronously and call the provided callback when done.
 *
 * @param num HTTP method code (from http_method enum)
 * @param name Function name (e.g., GET, POST, etc.)
 * @param description HTTP method description
 */
#define REGISTER_HTTP_ASYNC_FUNCTION(num, name, description)                  \
    template <typename _Func>                                                 \
    std::enable_if_t<std::is_invocable_v<_Func, async::Reply &&>, void> name( \
        Request request, _Func &&func, double timeout = 0.) {                 \
        if constexpr ((num) >= 0)                                             \
            request.method = static_cast<http_method>(num);                   \
                                                                              \
        request.headers()["host"].emplace_back(request.uri().host());         \
        EXEC_REQUEST()                                                        \
    }

/**
 * @brief Macro for declaring synchronous HTTP API functions
 *
 * This macro declares template functions for each HTTP method that accept:
 * - A request object
 * - An optional timeout parameter
 *
 * The declared functions will be implemented elsewhere and provide
 * a synchronous interface for HTTP operations, returning a Response
 * object directly instead of using callbacks.
 *
 * @param num HTTP method code (from http_method enum)
 * @param name Function name (e.g., GET, POST, etc.)
 * @param description HTTP method description
 */
#define REGISTER_HTTP_SYNC_FUNCTION_P(num, name, description) \
    Response name(Request request, double timeout = 3.);

REGISTER_HTTP_ASYNC_FUNCTION(-1, REQUEST, USER_DEFINED)

HTTP_METHOD_MAP(REGISTER_HTTP_ASYNC_FUNCTION)

REGISTER_HTTP_SYNC_FUNCTION_P(-1, REQUEST, USER_DEFINED)

HTTP_METHOD_MAP(REGISTER_HTTP_SYNC_FUNCTION_P)

#undef REGISTER_HTTP_ASYNC_FUNCTION
#undef REGISTER_HTTP_SYNC_FUNCTION_P
#undef EXEC_REQUEST

} // namespace qb::http

namespace qb::allocator {

/**
 * @brief HTTP Request serialization specialization
 *
 * Formats the HTTP request according to the HTTP/1.1 specification,
 * including method, URI, headers, and body. Used to serialize requests
 * for transmission over the network.
 *
 * The implementation handles all aspects of HTTP request formatting:
 * - Request line with method, URI, query parameters, and HTTP version
 * - Header fields with proper formatting
 * - Content-Length header for the body
 * - Body content if present
 *
 * @param r HTTP request to serialize
 * @return Reference to the pipe for method chaining
 */
template <>
pipe<char> &pipe<char>::put<qb::http::Request>(const qb::http::Request &r);

/**
 * @brief HTTP Response serialization specialization
 *
 * Formats the HTTP response according to the HTTP/1.1 specification,
 * including status line, headers, and body. Used to serialize responses
 * for transmission over the network.
 *
 * The implementation handles all aspects of HTTP response formatting:
 * - Status line with HTTP version, status code, and reason phrase
 * - Header fields with proper formatting
 * - Content compression if requested in Content-Encoding header
 * - Content-Length header for the body
 * - Body content if present
 *
 * @param r HTTP response to serialize
 * @return Reference to the pipe for method chaining
 */
template <>
pipe<char> &pipe<char>::put<qb::http::Response>(const qb::http::Response &r);

/**
 * @brief HTTP Chunk serialization specialization
 *
 * Specialization of the pipe<char>::put template for HTTP chunks.
 * This function formats an HTTP chunk according to the chunked transfer encoding
 * specification in HTTP/1.1.
 *
 * This is used for implementing chunked transfer encoding in HTTP/1.1, allowing
 * the server to send data in chunks without knowing the total size in advance.
 * A zero-size chunk (0\r\n\r\n) indicates the end of the chunked data.
 *
 * @param c HTTP chunk to serialize
 * @return Reference to the pipe for method chaining
 */
template <>
pipe<char> &pipe<char>::put<qb::http::Chunk>(const qb::http::Chunk &c);

} // namespace qb::allocator

namespace qb::http {
/**
 * @brief HTTP disconnection reason codes
 *
 * Defines possible reasons for disconnection of HTTP sessions.
 * These codes help with debugging and proper handling of session termination.
 * Used to provide context when a disconnection event is triggered, allowing
 * the application to react appropriately based on the reason.
 */
enum DisconnectedReason : int {
    ByUser = 0,          ///< Disconnected by user request
    ByTimeout,           ///< Disconnected due to timeout
    ResponseTransmitted, ///< Disconnected after response was transmitted
    ServerError,         ///< Disconnected due to server error
    Undefined            ///< Undefined reason (should never happen)
};

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
template <typename Derived, typename Transport, template <typename T> typename TProtocol,
          typename Handler>
class session
    : public qb::io::async::tcp::client<session<Derived, Transport, TProtocol, Handler>,
                                        Transport, Handler>
    , public qb::io::use<session<Derived, Transport, TProtocol, Handler>>::timeout {
public:
    using Protocol    = TProtocol<session<Derived, Transport, TProtocol, Handler>>;
    using string_type = typename Protocol::string_type;

private:
    friend qb::io::async::io<session>;
    friend class has_method_on<session, void, qb::io::async::event::pending_write>;
    friend class has_method_on<session, void, qb::io::async::event::eos>;
    friend class has_method_on<session, void, qb::io::async::event::disconnected>;
    friend Protocol;
    friend qb::io::async::with_timeout<session>;

    std::shared_ptr<Context<Derived>> _context{};

    /**
     * @brief Handle incoming HTTP request
     * @param msg HTTP request message
     *
     * Routes the incoming HTTP request to the appropriate handler.
     * If the request is not routed, the session is disconnected.
     */
    void
    on(typename Protocol::request &&msg) {
        _context = this->server().router().route(this->shared(), std::move(msg.http));

        if (!_context) {
            this->disconnect(DisconnectedReason::Undefined);
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
        if (_context) {
            _context->execute_hook(HookPoint::POST_RESPONSE_SEND);
            _context.reset();
        }

        if constexpr (has_method_on<Derived, void, event::eos>::value) {
            static_cast<Derived &>(*this).on(event::eos{});
        } else
            this->disconnect(DisconnectedReason::ResponseTransmitted);
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
            LOG_DEBUG("HttpSession(" << this->id() << ") disconnected -> " << reason(e.reason));
        }
        if (e.reason == DisconnectedReason::ByUser && _context && !_context->is_completed()) {
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
                                     Transport, Handler>(server)
    {
        this->setTimeout(60);
    }

    /**
     * @brief Get the context for the session
     * @return Shared pointer to the context
     *
     * Returns a shared pointer to the context for the session.
     * The context contains information about the current request and response.
     */
    std::shared_ptr<Context<Derived>> context() const {
        return _context;
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
template <typename Derived, typename Session, typename Transport>
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
        LOG_WARN("HttpServer disconnected");
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
};
} // namespace internal

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
    using session = internal::session<Derived, qb::io::transport::tcp,
                                      qb::protocol::http_server, Server>;

    /**
     * @brief Standard TCP HTTP session type with string_view optimization
     * @tparam Server Server handler type
     */
    template <typename Server>
    using session_view = internal::session<Derived, qb::io::transport::tcp,
                                           qb::protocol::http_server_view, Server>;

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

    /**
     * @brief SSL/TLS transport types for secure HTTP
     */
    struct ssl {
        /**
         * @brief Secure HTTPS session type
         * @tparam Server Server handler type
         */
        template <typename Server>
        using session = internal::session<Derived, qb::io::transport::stcp,
                                          qb::protocol::http_server, Server>;

        /**
         * @brief Secure HTTPS session type with string_view optimization
         * @tparam Server Server handler type
         */
        template <typename Server>
        using session_view = internal::session<Derived, qb::io::transport::stcp,
                                               qb::protocol::http_server_view, Server>;

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
};

} // namespace qb::http

#if defined(_WIN32)
#define DELETE (0x00010000L)
#endif

#endif // QB_MODULE_HTTP_H_

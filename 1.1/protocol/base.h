/**
 * @file qbm/http/1.1/protocol/base.h
 * @brief HTTP/1.1 protocol base implementation for qb-io framework
 *
 * This file provides the foundational HTTP/1.1 protocol parsing and handling
 * infrastructure built on top of the qb-io asynchronous framework. It includes:
 *
 * - Complete HTTP/1.1 message parsing using llhttp
 * - Event-driven callback architecture for efficient processing
 * - Support for chunked transfer encoding
 * - Header field and value parsing with case-insensitive handling
 * - Content-Length detection and body allocation optimization
 * - Support for both request and response parsing
 * - Proper HTTP version detection and upgrade protocol handling
 *
 * The parser implements the HTTP/1.1 specification (RFC 7230-7235) and provides
 * a robust foundation for both client and server implementations.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once
#include <qb/io/async.h>
#include <qb/system/allocator/pipe.h>
#include "../../types.h"

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
    template<typename MessageType>
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
                auto &msg = static_cast<Parser *>(parser->data)->msg;
                msg.method() = static_cast<http_method>(parser->method);
                msg.uri() = std::string{at, length};
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
                auto &msg = static_cast<Parser *>(parser->data)->msg;
                msg.status() = static_cast<http_status>(parser->status_code);
                // msg.status      = String(at, length);
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
            auto &msg = static_cast<Parser *>(parser->data)->msg;
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
        MessageType msg; ///< The message being constructed (Request or Response)

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
            &Parser::default_http_cb, // on message begin
            &Parser::default_http_data_cb, // on protocol
            &Parser::on_url, // on url
            &Parser::on_status, // on status
            &Parser::default_http_data_cb, // on method
            &Parser::default_http_data_cb, // on version
            &Parser::on_header_field, // on header field
            &Parser::on_header_value, // on header value
            &Parser::default_http_data_cb, // on chunk extention name
            &Parser::default_http_data_cb, // on chunk extension value
            &Parser::on_headers_complete, // on headers complete
            &Parser::on_body, // on body
            &Parser::on_message_complete, // on message complete
            &Parser::default_http_cb, // on protocol complete
            &Parser::default_http_cb, // on url complete
            &Parser::default_http_cb, // on status complete
            &Parser::default_http_cb, // on method complete
            &Parser::default_http_cb, // on version complete
            &Parser::default_http_cb, // on header field complete
            &Parser::default_http_cb, // on header value complete
            &Parser::default_http_cb, // on chunk extention name complete
            &Parser::default_http_cb, // on chunk extension value complete
            &Parser::default_http_cb, // on chunk header
            &Parser::default_http_cb, // on chunk complete
            &Parser::default_http_cb // on reset
        };
        String _last_header_key; ///< Storage for the current header field name
        bool _headers_completed = false; ///< Flag indicating if headers have been fully parsed
        qb::allocator::pipe<char> _chunked; ///< Buffer for body content

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
} // namespace qb::http

namespace qb::protocol::http {
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
    template<typename IO_Handler, typename Trait>
    class base : public qb::io::async::AProtocol<IO_Handler> {
        using String = typename qb::http::Parser<std::remove_const_t<Trait> >::String;
        std::size_t body_offset = 0; ///< Current offset for body parsing

    protected:
        qb::http::Parser<std::remove_const_t<Trait> > _http_obj; ///< HTTP parser

    public:
        typedef String string_type; ///< String type used for storage

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
            : qb::io::async::AProtocol<IO_Handler>(io) {
        }

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
}

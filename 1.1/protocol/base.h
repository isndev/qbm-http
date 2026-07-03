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
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <algorithm>
#include <climits>
#include <string>
#include <vector>

/**
 * @brief Security limits for HTTP/1.1 protocol handling
 *
 * These limits help prevent various DoS attacks and ensure stable operation.
 * Values are chosen based on RFC recommendations and common server configurations.
 *
 * @note These limits are designed to be:
 * - **RFC Compliant**: Based on HTTP/1.1 specifications (RFC 7230-7235)
 * - **DoS Resistant**: Prevent resource exhaustion attacks
 * - **Production Ready**: Used by major web servers (nginx, Apache)
 * - **Configurable**: Can be adjusted at compile time if needed
 */
namespace qb::http::protocol_limits {
/** @brief Maximum URL length (8KB) - per RFC 7230 guidance for URI length */
constexpr std::size_t MAX_URL_LENGTH = 8192;

/** @brief Maximum header name length (1KB) - prevents memory exhaustion */
constexpr std::size_t MAX_HEADER_NAME_LENGTH = 1024;

/** @brief Maximum header value length (8KB) - prevents memory exhaustion */
constexpr std::size_t MAX_HEADER_VALUE_LENGTH = 8192;

/** @brief Maximum number of headers per message (100) - RFC recommendation */
constexpr std::size_t MAX_HEADERS_COUNT = 100;

/** @brief Maximum chunk size for chunked encoding (16MB) - prevents OOM */
constexpr std::size_t MAX_CHUNK_SIZE = 16 * 1024 * 1024;

/** @brief Maximum total body size (100MB) - default upload limit */
constexpr std::size_t MAX_BODY_SIZE = 100 * 1024 * 1024;
} // namespace qb::http::protocol_limits
#include <qb/io/async.h>
#include <qb/system/allocator/pipe.h>
#include "../../types.h"
#include "../../utility.h"

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
    using String = std::string;

private:
    static int
    fail_with_reason(http_t *parser, const char *reason) noexcept {
        http_set_error_reason(parser, reason);
        return HPE_USER;
    }

    static bool
    is_supported_transfer_encoding(MessageType const &msg) {
        auto it = msg.headers().find("Transfer-Encoding");
        if (it == msg.headers().end()) {
            return true;
        }

        std::vector<std::string> tokens;
        for (const auto &value : it->second) {
            for (auto token : utility::split_string<std::string>(value, ",")) {
                token = std::string(utility::trim_http_whitespace(token));
                if (!token.empty()) {
                    tokens.emplace_back(std::move(token));
                }
            }
        }

        return tokens.size() == 1 && utility::iequals(tokens.front(), "chunked");
    }

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
            auto      *self          = static_cast<Parser *>(parser->data);
            const auto next_url_size = self->_url_bytes_seen + length;
            if (next_url_size > protocol_limits::MAX_URL_LENGTH) {
                return fail_with_reason(parser, "HTTP URL exceeds configured size limit");
            }
            auto &msg    = self->msg;
            msg.method() = static_cast<http_method>(parser->method);
            if (self->_url_bytes_seen == 0) {
                self->_url_buffer.clear();
                self->_url_buffer.reserve(std::min(next_url_size, protocol_limits::MAX_URL_LENGTH));
            }
            self->_url_buffer.append(at, length);
            self->_url_bytes_seen = next_url_size;
            msg.uri()             = self->_url_buffer;
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
    on_status(http_t *parser, const char *, size_t) {
        if constexpr (MessageType::type == HTTP_RESPONSE) {
            auto &msg    = static_cast<Parser *>(parser->data)->msg;
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
        auto *self = static_cast<Parser *>(parser->data);
        if (self->_last_header_token == HeaderToken::VALUE && !self->_last_header_key.empty()) {
            if (self->_last_header_value.size() > protocol_limits::MAX_HEADER_VALUE_LENGTH) {
                return fail_with_reason(parser, "HTTP header value exceeds configured size limit");
            }
            self->msg.headers()[self->_last_header_key].push_back(self->_last_header_value);
            self->_last_header_key.clear();
            self->_last_header_value.clear();
        }

        if (self->_last_header_token != HeaderToken::FIELD) {
            if (++self->_header_pairs_seen > protocol_limits::MAX_HEADERS_COUNT) {
                return fail_with_reason(parser, "HTTP header count exceeds configured limit");
            }
            self->_last_header_key.clear();
        }

        self->_last_header_key.append(at, length);
        if (self->_last_header_key.size() > protocol_limits::MAX_HEADER_NAME_LENGTH) {
            return fail_with_reason(parser, "HTTP header name exceeds configured size limit");
        }
        self->_last_header_token = HeaderToken::FIELD;
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
        auto *self = static_cast<Parser *>(parser->data);
        if (self->_last_header_token != HeaderToken::VALUE) {
            self->_last_header_value.clear();
        }
        self->_last_header_value.append(at, length);
        if (self->_last_header_value.size() > protocol_limits::MAX_HEADER_VALUE_LENGTH) {
            return fail_with_reason(parser, "HTTP header value exceeds configured size limit");
        }
        self->_last_header_token = HeaderToken::VALUE;
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
        auto *self = static_cast<Parser *>(parser->data);
        auto &msg  = self->msg;
        if (self->_last_header_token == HeaderToken::VALUE && !self->_last_header_key.empty()) {
            if (self->_last_header_value.size() > protocol_limits::MAX_HEADER_VALUE_LENGTH) {
                return fail_with_reason(parser, "HTTP header value exceeds configured size limit");
            }
            msg.headers()[self->_last_header_key].push_back(self->_last_header_value);
            self->_last_header_key.clear();
            self->_last_header_value.clear();
        }
        self->_last_header_token = HeaderToken::NONE;
        msg.major_version        = parser->http_major;
        msg.minor_version        = parser->http_minor;
        if (msg.has_header("Transfer-Encoding")) {
            if (msg.has_header("Content-Length")) {
                return fail_with_reason(parser, "HTTP Transfer-Encoding with Content-Length is forbidden");
            }
            if (!is_supported_transfer_encoding(msg)) {
                return fail_with_reason(parser, "Unsupported HTTP Transfer-Encoding");
            }
        }
        if constexpr (MessageType::type == HTTP_REQUEST) {
            // llhttp uses ULLONG_MAX as "unknown length". For HTTP requests,
            // absence of both Content-Length and Transfer-Encoding means an
            // empty body by default (RFC 9112 framing). Normalize this here
            // so downstream framing code never treats header-only requests as
            // waiting for an impossible body length.
            if (parser->content_length == ULLONG_MAX && !msg.has_header("Transfer-Encoding")) {
                parser->content_length = 0;
            }
        } else if constexpr (MessageType::type == HTTP_RESPONSE) {
            const auto status = parser->status_code;
            if ((status >= 100 && status < 200) || status == 204 || status == 304) {
                parser->content_length = 0;
            }
        }
        if (parser->content_length != ULLONG_MAX) {
            if (parser->content_length > protocol_limits::MAX_BODY_SIZE) {
                return fail_with_reason(parser, "HTTP Content-Length exceeds configured body size limit");
            }
            msg.body().raw().reserve(parser->content_length);
        }
        msg.upgrade              = static_cast<bool>(parser->upgrade);
        msg.keep_alive           = static_cast<bool>(http_should_keep_alive(parser));
        self->_headers_completed = true;
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
        auto *self = static_cast<Parser *>(parser->data);
        if (length > protocol_limits::MAX_CHUNK_SIZE) {
            return fail_with_reason(parser, "HTTP chunk exceeds configured chunk size limit");
        }
        const auto next_total = self->_body_bytes_seen + length;
        if (next_total > protocol_limits::MAX_BODY_SIZE) {
            return fail_with_reason(parser, "HTTP body exceeds configured size limit");
        }
        auto &chunked = self->_chunked;
        std::copy_n(at, length, chunked.allocate_back(length));
        self->_body_bytes_seen = next_total;
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
    enum class HeaderToken { NONE, FIELD, VALUE };
    String                    _last_header_key;   ///< Storage for the current header field name
    String                    _last_header_value; ///< Storage for the current header field value
    String                    _url_buffer;        ///< Storage for request-target when URL callback is fragmented
    HeaderToken               _last_header_token = HeaderToken::NONE;
    bool                      _headers_completed = false; ///< Flag indicating if headers have been fully parsed
    qb::allocator::pipe<char> _chunked;                   ///< Buffer for body content
    std::size_t               _header_pairs_seen = 0;     ///< Number of parsed header fields in the current message
    std::size_t               _body_bytes_seen   = 0;     ///< Total parsed body bytes for the current message
    std::size_t               _url_bytes_seen    = 0;     ///< Total URL bytes seen across fragmented on_url callbacks

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
        // Explicitly destroy and reconstruct msg instead of calling msg.reset().
        // server::onMessage() moves msg out (via std::move) before calling reset(),
        // leaving msg in a moved-from state.  Calling assignment operators on a
        // moved-from std::string crashes in MSVC debug mode due to iterator-proxy
        // corruption in _Orphan_all.  Placement-new avoids all assignment operators
        // on the moved-from object entirely, guaranteeing a clean initial state.
        msg.~MessageType();
        ::new (static_cast<void *>(&msg)) MessageType{};
        _headers_completed = false;
        _chunked.clear();
        _header_pairs_seen = 0;
        _body_bytes_seen   = 0;
        _last_header_key.clear();
        _last_header_value.clear();
        _url_buffer.clear();
        _last_header_token = HeaderToken::NONE;
        _url_bytes_seen    = 0;
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
template <typename IO_Handler, typename Trait>
class base : public qb::io::async::AProtocol<IO_Handler> {
    using String            = typename qb::http::Parser<std::remove_const_t<Trait>>::String;
    std::size_t body_offset = 0; ///< Current offset for body parsing

    /// True while accumulating a close-delimited response body (no Content-Length, no
    /// Transfer-Encoding, body-bearing status — RFC 9112 §6.3). getMessageSize cannot know
    /// the length until the connection closes, so it returns 0 (keep buffering) and flush_eof()
    /// delivers the accumulated body on disconnect.
    bool _close_delimited = false;

protected:
    qb::http::Parser<std::remove_const_t<Trait>> _http_obj; ///< HTTP parser

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
        //
        // Buffer semantics (important, see qb::allocator::pipe):
        //
        //   * `_io.in().begin()` is always the first **unconsumed**
        //     byte of the buffer. `allocate_back()` (called when new
        //     bytes arrive between two `getMessageSize()` invocations)
        //     may `memmove` the content down (reorder) or reallocate
        //     the storage entirely. In both cases the *logical*
        //     position of each unread byte relative to `begin()` is
        //     preserved — but the raw pointer may move.
        //
        //   * llhttp can invoke `on_header_field` / `on_header_value`
        //     multiple times per logical header when a field spans
        //     two `http_execute` calls (see llhttp docs: "may be
        //     called with a partial value"). Our callbacks copy into
        //     owning `std::string` by assignment / push_back, which
        //     overwrites rather than appends — so we must guarantee
        //     that each header is parsed in a single `http_execute`
        //     call. The simplest correct strategy is to reset the
        //     parser whenever the header block is incomplete and
        //     re-feed it the full current buffer on the next call.
        //     Once headers are complete the body is parsed
        //     incrementally (chunked branch / Content-Length check),
        //     where the callback contract allows partial calls
        //     because `on_body` already appends.
        //
        if (!_http_obj.headers_completed()) {
            const auto ret = _http_obj.parse(this->_io.in().begin(), this->_io.in().size());
            if (ret == HPE_OK) {
                // Headers still incomplete — reset to guarantee the
                // next pass sees every header in one shot.
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

        if constexpr (std::remove_const_t<Trait>::type == HTTP_RESPONSE) {
            if constexpr (requires(IO_Handler &io) { io.http1_response_body_forbidden(); }) {
                if (this->_io.http1_response_body_forbidden()) {
                    const auto header_size = body_offset;
                    body_offset            = 0;
                    return header_size;
                }
            }
        }

        if (msg.has_header("Transfer-Encoding")) {
            _http_obj.resume();
            const auto ret = _http_obj.parse(this->_io.in().begin() + body_offset, this->_io.in().size() - body_offset);

            if (ret == HPE_CB_MESSAGE_COMPLETE) {
                body_offset = 0;
                return _http_obj.error_pos - this->_io.in().begin();
            }
            if (ret == HPE_OK) {
                body_offset = this->_io.in().size();
            } else {
                this->not_ok();
            }
            return 0;
        }

        if constexpr (std::remove_const_t<Trait>::type == HTTP_RESPONSE) {
            // Close-delimited response body (RFC 9112 §6.3): no Content-Length AND no
            // Transfer-Encoding on a body-bearing status → the body runs until the server closes
            // the connection. llhttp flags exactly this via http_message_needs_eof (0 for
            // Content-Length / chunked / bodyless-status responses, so the normal paths below are
            // untouched). We can't frame by size, so keep buffering and let flush_eof() deliver
            // the body on disconnect. Bound the accumulation so a server cannot stream forever.
            if (http_message_needs_eof(&_http_obj)) {
                if (this->_io.in().size() - body_offset > ::qb::http::protocol_limits::MAX_BODY_SIZE) {
                    // Oversize: fail the message. Clear _close_delimited so flush_eof does NOT
                    // deliver the truncated buffer as a successful response — the caller must see
                    // a failed request, not a silently cut body. (The flag may already be set from
                    // an earlier under-cap read of this same body.)
                    _close_delimited = false;
                    this->not_ok();
                    return 0;
                }
                _close_delimited = true;
                return 0;
            }
        }

        const auto full_size = body_offset + _http_obj.content_length;
        if (this->_io.in().size() < full_size) {
            return 0; // incomplete body, keep accumulating
        }

        if (_http_obj.content_length)
            msg.body() = std::string_view(this->_io.in().cbegin() + body_offset, _http_obj.content_length);

        body_offset = 0;

        return full_size;
    }

    /**
     * @brief Deliver a close-delimited response body on connection EOF.
     *
     * A response with no Content-Length and no Transfer-Encoding (RFC 9112 §6.3) has its body
     * delimited by the connection close; getMessageSize() buffered it (returning 0) rather than
     * framing an empty body. The client calls this on disconnect to hand the accumulated body to
     * the message handler exactly once. No-op unless such a body is pending.
     */
    void
    flush_eof() noexcept {
        // this->ok() guards the oversize/error path: getMessageSize calls not_ok() (and clears
        // _close_delimited) when the accumulated body exceeds MAX_BODY_SIZE, so a failed message
        // is never delivered as a truncated success.
        if (!_close_delimited || !_http_obj.headers_completed() || !this->ok()) {
            return;
        }
        _close_delimited = false; // deliver exactly once
        auto      &msg   = _http_obj.get_parsed_message();
        const auto total = this->_io.in().size();
        if (total > body_offset) {
            // OWNING copy: the input buffer is discarded once the socket closes, and the async
            // pipeline requires the body to outlive the read that produced it.
            msg.body() = std::string(this->_io.in().cbegin() + body_offset, this->_io.in().cbegin() + total);
        }
        body_offset = 0;
        this->onMessage(total); // derived onMessage: parse cookies, dispatch to handler, reset()
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
        body_offset      = 0;
        _close_delimited = false;
        _http_obj.reset();
    }
};
} // namespace qb::protocol::http

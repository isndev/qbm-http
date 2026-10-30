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
#include <limits>
#include <new>
#include <string>
#include <string_view>
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
 * - **Configurable**: they are the defaults of `qb::http::request_limits`, which a server takes at run time
 *   (`set_request_limits`, Huly QB-94); a client reads its responses under these values
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

/**
 * @brief Upper bound (64KB) on how much body buffer a declared `Content-Length` may pre-reserve.
 * @details `Content-Length` is attacker-controlled all the way up to `MAX_BODY_SIZE`, and it is
 *          known at headers-complete — i.e. before a single body byte has arrived. Honouring it
 *          verbatim lets a ~40-byte request that then sends nothing pin `MAX_BODY_SIZE` of heap
 *          per connection until the idle timeout: ~2.6 million times amplification, and trivially
 *          multiplied by the connection count.
 *
 *          Capping the hint keeps the optimisation that matters — the overwhelming majority of
 *          real bodies fit in one allocation and never regrow — while making the pre-body
 *          commitment independent of what the peer claims. Anything larger simply grows
 *          geometrically as bytes actually arrive, so memory tracks delivered traffic.
 */
constexpr std::size_t MAX_BODY_RESERVE_HINT = 64 * 1024;
} // namespace qb::http::protocol_limits

namespace qb::http {
/**
 * @brief The limits a server applies to every request it reads, on HTTP/1.1, HTTP/2 and HTTP/3 alike (Huly QB-94).
 * @details A value type: a server keeps one (`set_request_limits` / `request_limits()` on the HTTP/1.1, HTTP/2,
 *          HTTP/3 and dual-stack servers) and reads it as each request arrives, so a change applies to the
 *          requests that follow, never to one half read. 0 means no limit of that kind. A request over a limit is
 *          answered, never dropped, once it is known well-formed -- a malformed request stays the error it is,
 *          whatever limit it also passes (Huly QB-1195, QB-1197): `414 URI Too Long` for the target, `431 Request
 *          Header Fields Too Large` for a
 *          field name, a field value or the number of regular fields of a section (the header section, the
 *          trailer section), `413 Content Too Large` for the body or -- HTTP/1.1 only -- a chunk. HTTP/1.1 then
 *          closes the connection after that answer, HTTP/2 resets the stream with NO_ERROR, HTTP/3 sends
 *          STOP_SENDING with H3_NO_ERROR. The defaults are `protocol_limits`' constants; the HTTP/3 server's
 *          body default is its own 64 MiB. Clients read responses under the defaults. HTTP/2 keeps its 1 MiB
 *          HPACK header-list cap (`qb::http2::protocol_limits::MAX_HEADER_LIST_SIZE`) under these, HTTP/3 the 64 KiB
 *          field section it advertises, a section past it answered 431 (Huly QB-1196).
 */
struct request_limits {
    std::size_t max_url_length          = protocol_limits::MAX_URL_LENGTH;          ///< the request target, in bytes (414)
    std::size_t max_header_name_length  = protocol_limits::MAX_HEADER_NAME_LENGTH;  ///< one field name, in bytes (431)
    std::size_t max_header_value_length = protocol_limits::MAX_HEADER_VALUE_LENGTH; ///< one field value, in bytes (431)
    std::size_t max_headers_count       = protocol_limits::MAX_HEADERS_COUNT;       ///< regular fields per section (431)
    std::size_t max_chunk_size          = protocol_limits::MAX_CHUNK_SIZE;          ///< one chunk, HTTP/1.1 (413)
    std::size_t max_body_size           = protocol_limits::MAX_BODY_SIZE;           ///< the whole body, in bytes (413)

    /// The same limits with every 0 ("none") read as the largest size, so each check stays one comparison.
    [[nodiscard]] constexpr request_limits
    normalized() const noexcept {
        constexpr auto none = [](std::size_t v) noexcept {
            return v == 0 ? std::numeric_limits<std::size_t>::max() : v;
        };
        return {none(max_url_length),    none(max_header_name_length), none(max_header_value_length),
                none(max_headers_count), none(max_chunk_size),         none(max_body_size)};
    }
};
} // namespace qb::http

#include <qb/io/async.h>
#include <qb/system/allocator/pipe.h>
#include <qb/utility/branch_hints.h> // QB_MSVC_FORCEINLINE (the Host check's helpers, Huly QB-1186)
#include "../../headers.h"           // detail::is_forbidden_trailer_field (trailer sections, Huly QB-1067)
#include "../../message_base.h"      // detail::store_received_trailer (trailers(), Huly QB-1073)
#include "../../origin.h"            // origin::request_target_uri (Huly QB-1177), is_request_authority (QB-1186)
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
 *
 * A Parser holds no pointer to itself, so its implicit copy and move are complete at
 * every phase (request line, header block, body): the copy continues the parse into its
 * own message and leaves the source alone.
 *
 * Every callback llhttp calls is noexcept, and one that fails to allocate refuses the message --
 * 503 (refuse_for_exception()) -- so no exception unwinds through llhttp's C frames.
 */
template <typename MessageType>
struct Parser : public http_t {
    using String = std::string;

private:
    /// The Parser an llhttp callback runs for. llhttp hands each callback the state it is
    /// executing, which IS this object's `http_t` base — whatever the Parser was copied or moved
    /// from. Nothing is read through `http_t::data`: a self-pointer stored there was copied
    /// verbatim by the implicit copy and move, so a copy parsed into its source (Huly QB-510).
    [[nodiscard]] static Parser *
    self_of(http_t *parser) noexcept {
        return static_cast<Parser *>(parser);
    }

    static int
    fail_with_reason(http_t *parser, const char *reason) noexcept {
        http_set_error_reason(parser, reason);
        return HPE_USER;
    }

    /// Fails the message for a size limit, a target that names no resource, a Host field that names no authority or
    /// a major version other than 1, and records the status it answers (refusal_status()): the server's session answers it,
    /// then closes, instead of closing on silence (Huly QB-168, QB-1186).
    static int
    refuse_with_status(http_t *parser, const char *reason, http_status status) noexcept {
        self_of(parser)->_refusal_status = status;
        return fail_with_reason(parser, reason);
    }

    /// Refuses the message for the exception a callback caught. llhttp is C and calls every callback from its own
    /// frames, which no exception may unwind: each callback is noexcept, and each that allocates -- the target, a field
    /// line, the Host value it rewrites, a chunk, a trailer field -- ends in a handler that calls this. The exception
    /// used to unwind through llhttp up to the protocol's noexcept getMessageSize(), which terminated (review r1 N2,
    /// Huly QB-1186). An allocation failure is 503: the server cannot take the request now, which a client may send
    /// again (RFC 9110 §15.6.4), not a request it judged; any other exception 500, a condition it did not expect
    /// (§15.6.1). The session answers it as any refusal, and closes the connection if it cannot build the answer.
    static int
    refuse_for_exception(http_t *parser) noexcept {
        try {
            throw;
        } catch (std::bad_alloc const &) {
            return refuse_with_status(parser, "HTTP parser could not allocate", HTTP_STATUS_SERVICE_UNAVAILABLE);
        } catch (...) {
            return refuse_with_status(parser, "HTTP parser callback threw", HTTP_STATUS_INTERNAL_SERVER_ERROR);
        }
    }

    /// Ends @p value at its last octet that is no whitespace: the OWS around a field line value is not part of it (RFC
    /// 9112 §5), and llhttp drops only the run before it -- `Host: a ` was the value `a `, no host (Huly QB-1186).
    /// Forced inline on MSVC, as note_host_field() and check_host_field() are: left out of line there -- three calls
    /// on the header-complete path of every request, where g++ inlines them -- the Host check cost a 2-line GET 38 ns
    /// (+12 %) a parse on MSVC 19.51 against the 7..10 ns of the check itself on g++ 14 (Huly QB-1186).
    static QB_MSVC_FORCEINLINE String &
    without_trailing_whitespace(String &value) noexcept {
        if (!value.empty() && (value.back() == ' ' || value.back() == '\t')) [[unlikely]]
            value.erase(value.find_last_not_of(" \t") + 1); // npos + 1 is 0 (llhttp hands no value of whitespace alone)
        return value;
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
    default_http_data_cb(http_t *, const char *, size_t) noexcept {
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
    default_http_cb(http_t *) noexcept {
        return 0;
    }

    /**
     * @brief URL parsing callback
     * @param parser Parser instance
     * @param at Pointer to URL data
     * @param length Length of URL data
     * @return Result code (0 for success)
     *
     * Called when the URL portion of a request is parsed, possibly in several pieces: each is appended to
     * the target, which on_url_complete() reads once it has ended. This is only used for request messages;
     * for response messages, this callback does nothing.
     */
    static int
    on_url(http_t *parser, const char *at, size_t length) noexcept try {
        if constexpr (MessageType::type == HTTP_REQUEST) {
            auto      *self          = self_of(parser);
            const auto next_url_size = self->_url_bytes_seen + length;
            if (next_url_size > self->_limits.max_url_length) {
                return refuse_with_status(parser, "HTTP URL exceeds configured size limit", HTTP_STATUS_URI_TOO_LONG);
            }
            self->msg.method() = static_cast<http_method>(parser->method);
            if (self->_url_bytes_seen == 0) {
                self->_url_buffer.clear();
                self->_url_buffer.reserve(std::min(next_url_size, protocol_limits::MAX_URL_LENGTH)); // a hint, not the limit
            }
            self->_url_buffer.append(at, length);
            self->_url_bytes_seen = next_url_size;
        } else {
            (void) at;
            (void) length;
        }
        return 0;
    } catch (...) {
        return refuse_for_exception(parser);
    }

    /**
     * @brief Builds the request's URI once its target has ended
     * @param parser Parser instance
     * @return 0, or the refusal of the request: 400
     *
     * The target's form decides what is an authority (RFC 9112 §3.2), and origin::request_target_uri()
     * reads it: an origin-form target (`/path?query`) by qb::io::uri::origin_form(), so `//a/b` is the
     * path `//a/b` and the authority is the Host field's, never the `a` a URI reference names (Huly
     * QB-1177); an absolute-form one as a URI with an authority and no userinfo; the authority-form of a
     * CONNECT request as a host and a port; the asterisk-form of an OPTIONS request as `*`. A path may hold
     * `[`, `]` and `|`, which a browser sends unencoded (QB-1187). Any other target names no resource and
     * is answered 400 (one with a byte the URI parser refuses reached the route of the empty path, a
     * fragment the route of its path, a GET `*` a 404). The target is read into the request's own uri, in
     * place: a uri built apart and moved in cost 830 instructions a request.
     */
    static int
    on_url_complete(http_t *parser) noexcept try {
        if constexpr (MessageType::type == HTTP_REQUEST) {
            auto *self = self_of(parser);
            if (!qb::http::origin::request_target_uri(self->msg.uri(), self->_url_buffer, parser->method == HTTP_CONNECT,
                                                      parser->method == HTTP_OPTIONS))
                return refuse_with_status(parser, "HTTP request target names no resource", HTTP_STATUS_BAD_REQUEST);
        }
        return 0;
    } catch (...) {
        return refuse_for_exception(parser);
    }

    /// Counts and checks a request's Host field line as the header section stores it, so that check_host_field() looks
    /// nothing up on the path of every request: a name of four octets is compared, any other costs one comparison.
    /// Forced inline on MSVC, which kept it out of line (without_trailing_whitespace()).
    static QB_MSVC_FORCEINLINE void
    note_host_field(Parser *self, String const &name, String const &value) noexcept {
        if constexpr (MessageType::type == HTTP_REQUEST) {
            if (name.size() == 4 && utility::iequals(name, "host")) {
                ++self->_host_fields;
                self->_host_malformed |= !value.empty() && !qb::http::origin::is_request_authority(value);
            }
        }
    }

    /**
     * @brief Checks a request's Host field once its header section has ended
     * @param parser Parser instance
     * @param msg The request
     * @return 0, or the refusal of the request: 400
     *
     * The Host field names the request's authority (RFC 9112 §3.2): an HTTP/1.1 request carries one (HTTP/1.0 may
     * send none), no request carries two field lines of it, and its value is empty -- a target URI with no
     * authority -- or a host and an optional port, as origin::is_request_authority() reads one. An origin-form
     * target's authority IS that field (§3.3): with two lines, `header("Host")` read the first while a proxy before
     * the server may have routed by the other (Huly QB-1186). A target that names its authority itself -- the
     * absolute-form (§3.2.2), or a CONNECT request's authority-form (§3.3) -- overrides the field, which is still
     * required and checked: the field then reads the target's authority as the client wrote it, so no reader of it
     * takes the host it named instead (an HTTP/1.0 request that sends none has none: the URI names it).
     *
     * Forced inline on MSVC, which kept it out of line (without_trailing_whitespace()).
     */
    static QB_MSVC_FORCEINLINE int
    check_host_field(http_t *parser, MessageType &msg) {
        auto const *self = self_of(parser);
        if (self->_host_fields == 0) {
            if (parser->http_major > 1 || (parser->http_major == 1 && parser->http_minor >= 1))
                return refuse_with_status(parser, "HTTP/1.1 request has no Host field", HTTP_STATUS_BAD_REQUEST);
            return 0;
        }
        if (self->_host_fields != 1)
            return refuse_with_status(parser, "HTTP request has more than one Host field", HTTP_STATUS_BAD_REQUEST);
        if (self->_host_malformed)
            return refuse_with_status(parser, "HTTP Host field is not a host and an optional port", HTTP_STATUS_BAD_REQUEST);
        if (!msg.uri().host().empty()) { // the target's authority, as the client wrote it (§3.3)
            std::string_view const target = msg.uri().source();
            auto const             scheme = target.find("://");
            auto const             begin  = scheme == std::string_view::npos ? 0 : scheme + 3;
            msg.headers().find("host")->second.front().assign(target.substr(begin, target.find_first_of("/?", begin) - begin));
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
    on_status(http_t *parser, const char *, size_t) noexcept {
        if constexpr (MessageType::type == HTTP_RESPONSE) {
            auto &msg    = self_of(parser)->msg;
            msg.status() = static_cast<http_status>(parser->status_code);
            // msg.status      = String(at, length);
        }
        return 0;
    }

    /**
     * @brief Stores the trailer field the parser holds, if any, into the message's trailer section.
     * @param parser Parser instance
     * @return 0, or the refusal of the message
     *
     * A header-section field is stored when the next one begins or when the section ends (inline
     * in on_header_field / on_headers_complete); a trailer-section field when its value ends, here
     * through on_value_end: the last one is followed by neither, and it was dropped (Huly QB-1067).
     * A trailer field goes to the message's `trailers()` -- and to its header fields too, for 3.x
     * compatibility -- as HTTP/2 and HTTP/3 store theirs (detail::store_received_trailer, Huly
     * QB-1073); one a trailer section must not carry (framing, connection, routing, proxy
     * authentication: detail::is_forbidden_trailer_field) refuses the message, as they refuse
     * their stream -- merged, a trailer `Content-Length` would sit beside the chunked framing.
     */
    static int
    store_trailer_field(http_t *parser) {
        auto *self = self_of(parser);
        if (self->_last_header_token != HeaderToken::VALUE || self->_last_header_key.empty()) {
            return 0;
        }
        if (self->_last_header_value.size() > self->_limits.max_header_value_length) {
            return refuse_with_status(parser, "HTTP header value exceeds configured size limit", HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
        if (qb::http::detail::is_forbidden_trailer_field(self->_last_header_key)) {
            return fail_with_reason(parser, "HTTP trailer section carries a field it must not (framing, connection, routing)");
        }
        qb::http::detail::store_received_trailer(self->msg, self->_last_header_key, without_trailing_whitespace(self->_last_header_value));
        self->_last_header_key.clear();
        self->_last_header_value.clear();
        return 0;
    }

    /**
     * @brief Header value complete callback (llhttp's on_header_value_complete) of a trailer section:
     *        stores the field as soon as its value ends, so the last one is not lost and a refusal is
     *        the parser's error (a refusal returned from on_message_complete would read as the
     *        completion llhttp signals there). Installed only after the header section of a chunked
     *        message (trailer_settings, by on_headers_complete): a header-section field keeps its lazy
     *        store, inline in on_header_field / on_headers_complete, at no cost per field.
     * @param parser Parser instance
     * @return 0, or the refusal of the message
     */
    static int
    on_value_end(http_t *parser) noexcept try {
        return store_trailer_field(parser);
    } catch (...) {
        return refuse_for_exception(parser);
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
    on_header_field(http_t *parser, const char *at, size_t length) noexcept try {
        auto *self = self_of(parser);
        if (self->_last_header_token == HeaderToken::VALUE && !self->_last_header_key.empty()) {
            if (self->_last_header_value.size() > self->_limits.max_header_value_length) {
                return refuse_with_status(parser, "HTTP header value exceeds configured size limit",
                                          HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE);
            }
            note_host_field(self, self->_last_header_key, without_trailing_whitespace(self->_last_header_value));
            self->msg.headers()[self->_last_header_key].push_back(self->_last_header_value);
            self->_last_header_key.clear();
            self->_last_header_value.clear();
        }

        if (self->_last_header_token != HeaderToken::FIELD) {
            if (++self->_header_pairs_seen > self->_limits.max_headers_count) {
                return refuse_with_status(parser, "HTTP header count exceeds configured limit", HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE);
            }
            self->_last_header_key.clear();
        }

        self->_last_header_key.append(at, length);
        if (self->_last_header_key.size() > self->_limits.max_header_name_length) {
            return refuse_with_status(parser, "HTTP header name exceeds configured size limit", HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
        self->_last_header_token = HeaderToken::FIELD;
        return 0;
    } catch (...) {
        return refuse_for_exception(parser);
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
    on_header_value(http_t *parser, const char *at, size_t length) noexcept try {
        auto *self = self_of(parser);
        if (self->_last_header_token != HeaderToken::VALUE) {
            self->_last_header_value.clear();
        }
        self->_last_header_value.append(at, length);
        if (self->_last_header_value.size() > self->_limits.max_header_value_length) {
            return refuse_with_status(parser, "HTTP header value exceeds configured size limit", HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE);
        }
        self->_last_header_token = HeaderToken::VALUE;
        return 0;
    } catch (...) {
        return refuse_for_exception(parser);
    }

    /**
     * @brief Headers complete callback
     * @param parser Parser instance
     * @return HPE_PAUSED to pause the parser after headers
     *
     * Called when all headers have been parsed.
     * Finalizes header processing and prepares for body parsing.
     * This callback:
     * 1. Sets the HTTP version, and refuses a request whose major version is not 1: 505
     * 2. Checks a request's Host field (check_host_field()) and reserves memory for the body based on
     *    Content-Length if available
     * 3. Sets the upgrade flag if applicable
     * 4. Marks headers as completed and pauses the parser
     *
     * The parser is paused to allow the application to process headers
     * before continuing with the body. The message's typed Content-Type is set neither here
     * nor anywhere else in the parser: `content_type()` derives it from the raw header on its
     * first read (Huly QB-506), on every framing path -- the protocol frames Content-Length,
     * empty, HEAD and close-delimited bodies itself and never reaches on_message_complete --
     * and a message nobody asks never parses it.
     */
    static int
    on_headers_complete(http_t *parser) noexcept try {
        auto *self = self_of(parser);
        auto &msg  = self->msg;
        if (self->_last_header_token == HeaderToken::VALUE && !self->_last_header_key.empty()) {
            if (self->_last_header_value.size() > self->_limits.max_header_value_length) {
                return refuse_with_status(parser, "HTTP header value exceeds configured size limit",
                                          HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE);
            }
            note_host_field(self, self->_last_header_key, without_trailing_whitespace(self->_last_header_value));
            msg.headers()[self->_last_header_key].push_back(self->_last_header_value);
            self->_last_header_key.clear();
            self->_last_header_value.clear();
        }
        self->_last_header_token = HeaderToken::NONE;
        self->_header_pairs_seen = 0; // a trailer section counts its fields on its own, as HTTP/2 and HTTP/3 do (Huly QB-94)
        msg.major_version        = parser->http_major;
        msg.minor_version        = parser->http_minor;
        if constexpr (MessageType::type == HTTP_REQUEST) {
            // A major version other than 1 is one the server does not support: 505 (RFC 9110 §15.6.6). llhttp reads two,
            // HTTP/0.9 -- a request line with no version, read with the field lines after it, or 0.9 written out -- and
            // HTTP/2.0, which is no text protocol; both were served as HTTP/1.x (review r1 N3 and its follow-up).
            if (parser->http_major != 1) [[unlikely]]
                return refuse_with_status(parser, "HTTP request version is not 1.x", HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED);
        }
        if (msg.has_header("Transfer-Encoding")) {
            if (msg.has_header("Content-Length")) {
                return fail_with_reason(parser, "HTTP Transfer-Encoding with Content-Length is forbidden");
            }
            if (!is_supported_transfer_encoding(msg)) {
                return fail_with_reason(parser, "Unsupported HTTP Transfer-Encoding");
            }
            // A chunked body may end with a trailer section: its fields are stored as their values end
            // (trailer_settings, Huly QB-1067). Installed here, so no other message pays for it.
            parser->settings = const_cast<http_settings_s *>(&trailer_settings);
        }
        if constexpr (MessageType::type == HTTP_REQUEST) {
            if (int const refused = check_host_field(parser, msg); refused != 0) {
                return refused;
            }
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
            if (parser->content_length > self->_limits.max_body_size) {
                return refuse_with_status(parser, "HTTP Content-Length exceeds configured body size limit", HTTP_STATUS_PAYLOAD_TOO_LARGE);
            }
            // Reserve on `_chunked` — the buffer that actually receives the body. `msg.body().raw()`
            // is MOVE-ASSIGNED from `_chunked` in on_message_complete, which deallocates whatever
            // was reserved here, so reserving on it was both dangerous and pure waste.
            //
            // And cap the hint: see MAX_BODY_RESERVE_HINT. `content_length` is peer-supplied and is
            // known before any body byte arrives, so an unbounded reserve turns a ~40-byte request
            // into a 100 MB allocation held for the connection's lifetime.
            self->_chunked.reserve(
                std::min<std::size_t>(static_cast<std::size_t>(parser->content_length), protocol_limits::MAX_BODY_RESERVE_HINT));
        }
        msg.upgrade              = static_cast<bool>(parser->upgrade);
        msg.keep_alive           = static_cast<bool>(http_should_keep_alive(parser));
        self->_headers_completed = true;
        return HPE_PAUSED;
    } catch (...) {
        return refuse_for_exception(parser);
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
    on_body(http_t *parser, const char *at, size_t length) noexcept try {
        auto *self = self_of(parser);
        if (length > self->_limits.max_chunk_size) {
            return refuse_with_status(parser, "HTTP chunk exceeds configured chunk size limit", HTTP_STATUS_PAYLOAD_TOO_LARGE);
        }
        const auto next_total = self->_body_bytes_seen + length;
        if (next_total > self->_limits.max_body_size) {
            return refuse_with_status(parser, "HTTP body exceeds configured size limit", HTTP_STATUS_PAYLOAD_TOO_LARGE);
        }
        auto &chunked = self->_chunked;
        std::copy_n(at, length, chunked.allocate_back(length));
        self->_body_bytes_seen = next_total;
        return 0;
    } catch (...) {
        return refuse_for_exception(parser);
    }

    /**
     * @brief Message complete callback
     * @param parser Parser instance
     * @return 1 to signal message completion
     *
     * Called when the entire HTTP message has been parsed.
     * Finalizes message processing by:
     * 1. Moving the accumulated body data to the message body
     * 2. Returning 1 to signal message completion
     *
     * The typed Content-Type is derived from the raw header when first read; nothing is
     * re-written here, so a message without a Content-Type does not gain an empty one.
     */
    static int
    on_message_complete(http_t *parser) noexcept {
        auto p              = self_of(parser);
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
        &Parser::on_url_complete,      // on url complete: builds the request's URI
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

    /**
     * @brief The settings of a chunked message's body and trailer section: settings, with on_value_end
     *        storing each trailer field when its value ends. on_headers_complete installs them for a
     *        chunked message; reset() restores settings (Huly QB-1067).
     */
    static const http_settings_s inline trailer_settings{
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
        &Parser::on_url_complete,      // on url complete: builds the request's URI
        &Parser::default_http_cb,      // on status complete
        &Parser::default_http_cb,      // on method complete
        &Parser::default_http_cb,      // on version complete
        &Parser::default_http_cb,      // on header field complete
        &Parser::on_value_end,         // on header value complete: stores the trailer field
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
    /// The limits of the next message: set_request_limits(), normalized (a 0 "none" stored as the largest size, so
    /// each check stays one comparison). Configuration, kept across reset().
    qb::http::request_limits _limits         = qb::http::request_limits{}.normalized();
    int                      _refusal_status = 0;     ///< The status a refusal of the current message answers (refusal_status())
    std::size_t              _host_fields    = 0;     ///< Host field lines of the current request's header section (check_host_field())
    bool                     _host_malformed = false; ///< One of them names no authority (note_host_field())

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
     * 2. Resetting the message object
     * 3. Clearing the headers_completed flag
     * 4. Clearing any accumulated body data
     *
     * `http_t::data` is left as http_init() sets it: the callbacks find this object through
     * the state llhttp executes, never through a stored self-pointer (Huly QB-510).
     *
     * This method should be called before reusing the parser for a new
     * message or after an error occurs to restore the parser to a clean state.
     */
    void
    reset() noexcept {
        http_init(static_cast<http_t *>(this), MessageType::type, &settings);
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
        _refusal_status    = 0;
        _host_fields       = 0;
        _host_malformed    = false;
    }

    /**
     * @brief Set the limits of the messages parsed from now on (Huly QB-94).
     * @param limits The limits; a 0 in any of them means no limit of that kind.
     *
     * A breach fails the message and records the status that answers it as the refusal_status():
     * 414 for the request target, 431 for a field name, a field value or the field count (trailer
     * fields included), 413 for a chunk or the body -- a declared `Content-Length` above the body
     * limit at the end of the header section, before a body byte is read; a chunked body when the
     * bytes it delivered pass it. The defaults are `protocol_limits`' constants. A server installs
     * its own before each request (`set_request_limits`); reset() keeps them.
     */
    void
    set_request_limits(qb::http::request_limits const &limits) noexcept {
        _limits = limits.normalized();
    }

    /**
     * @brief The limits set_request_limits() installed, each "none" read as the largest size.
     */
    [[nodiscard]] qb::http::request_limits const &
    request_limits() const noexcept {
        return _limits;
    }

    /**
     * @brief Set the body limit alone (set_request_limits() for the rest); 0 means none (Huly QB-168).
     */
    void
    set_max_body_size(std::size_t value) noexcept {
        _limits.max_body_size = value == 0 ? std::numeric_limits<std::size_t>::max() : value;
    }

    /**
     * @brief The body limit installed; the largest size when there is none.
     */
    [[nodiscard]] std::size_t
    max_body_size() const noexcept {
        return _limits.max_body_size;
    }

    /**
     * @brief The HTTP status a refusal of the current message answers, or 0.
     *
     * Set when the parse failed on a limit the peer can be told about (set_request_limits()): 414,
     * 431 or 413; on a target origin::request_target_uri() refuses: 400 (on_url_complete()); on a Host field
     * that names no authority: 400 (check_host_field()); or on a major version other than 1: 505 (on_headers_complete()). 0 for any
     * other failure, which the protocol's fail_message() answers only for a request line llhttp refuses
     * at its target (400) -- any other malformed message is not answered. reset() clears it.
     */
    [[nodiscard]] int
    refusal_status() const noexcept {
        return _refusal_status;
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

    /// How many bytes of the *current* header block have already been handed to llhttp.
    /// The header block is parsed INCREMENTALLY: each call feeds only the bytes that arrived
    /// since the last one. Re-feeding the whole buffer every time is quadratic in the header
    /// size — see getMessageSize().
    std::size_t header_parsed = 0;

    /// True while accumulating a close-delimited response body (no Content-Length, no
    /// Transfer-Encoding, body-bearing status — RFC 9112 §6.3). getMessageSize cannot know
    /// the length until the connection closes, so it returns 0 (keep buffering) and flush_eof()
    /// delivers the accumulated body on disconnect.
    bool _close_delimited = false;

    /// True once a request was refused, for a limit, its target, its version or Host (fail_message()): the stream lost
    /// its framing -- the refused body is not read -- so every byte that follows is dropped until the connection ends.
    bool _refused = false;

    /// The message failed. A request refused for a limit, its target, its version or Host the server can answer (the
    /// parser's refusal_status(), the io's `http1_refuse_request`) is handed to the io, which answers it and ends the
    /// connection; what the peer sends next is dropped. A request line llhttp refuses at or just after its
    /// target (HPE_INVALID_URL) names no resource either, and is answered 400 the same way (RFC 9112 §3,
    /// Huly QB-1177). Anything else -- a malformed
    /// message, an io that cannot answer -- invalidates the protocol, which closes the connection.
    std::size_t
    fail_message() noexcept {
        if constexpr (requires(IO_Handler &io) { io.http1_refuse_request(qb::http::Status{}); }) {
            int status = _http_obj.refusal_status();
            if (status == 0 && http_get_errno(static_cast<http_t *>(&_http_obj)) == HPE_INVALID_URL)
                status = HTTP_STATUS_BAD_REQUEST;
            if (status != 0) {
                _refused      = true;
                body_offset   = 0;
                header_parsed = 0;
                _http_obj.reset(); // the refused request: its header section, the body bytes it held
                this->_io.in().reset();
                this->_io.http1_refuse_request(qb::http::Status(status));
                return 0;
            }
        }
        this->not_ok();
        return 0;
    }

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
        //     called with a partial value"). Our callbacks handle
        //     that: `on_header_field` / `on_header_value` APPEND to
        //     `_last_header_key` / `_last_header_value` and clear
        //     only on a field<->value transition (committing the
        //     completed pair into `msg.headers()` exactly once), and
        //     `on_url` accumulates through `_url_buffer`. So the
        //     header block can be — and is — fed incrementally.
        //
        //     This used to `reset()` the parser and re-feed the WHOLE
        //     buffer on every arrival while the header block was
        //     incomplete. That is O(n^2) in the header size, and the
        //     peer controls the segmentation: a well-formed 793 KB
        //     header block (99 headers, all inside the configured
        //     limits) delivered in 64-byte segments cost 1.5 SECONDS
        //     of parsing for a single request, ~95 s extrapolated to
        //     byte-at-a-time. A `VirtualCore` is single-threaded, so
        //     that stalls every actor on the core — a remote CPU
        //     denial of service out of one legal request per
        //     connection. Feeding only the new bytes makes the cost
        //     linear and keeps llhttp's incremental state, which is
        //     what it is designed for.
        //
        if (_refused) [[unlikely]] {
            this->_io.in().reset(); // a refused request ends the connection: nothing after it is read
            return 0;
        }
        if (!_http_obj.headers_completed()) {
            const auto *const buf   = this->_io.in().begin();
            const auto        total = this->_io.in().size();
            // Nothing new since the last call (the buffer may be memmoved/reallocated between
            // calls, but the logical position of every unread byte relative to begin() is stable).
            if (total <= header_parsed) {
                return 0;
            }
            if constexpr (requires(IO_Handler &io) { io.http_request_limits(); }) {
                // The limits are read when a message begins, from the server's current value: a change
                // applies to the next request, never to one half read (Huly QB-168, QB-94).
                if (header_parsed == 0)
                    _http_obj.set_request_limits(this->_io.http_request_limits());
            }
            const auto ret = _http_obj.parse(buf + header_parsed, total - header_parsed);
            if (ret == HPE_OK) {
                // Header block still incomplete — remember how far llhttp has consumed so the
                // next arrival feeds only what is new.
                header_parsed = total;
                return 0;
            }
            if (!_http_obj.headers_completed()) {
                return fail_message();
            }
            // `error_pos` is an absolute pointer into the same buffer, so it stays correct
            // regardless of where this pass started.
            body_offset   = static_cast<std::size_t>(_http_obj.error_pos - buf);
            header_parsed = 0;
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
                return 0;
            }
            return fail_message();
        }

        if constexpr (std::remove_const_t<Trait>::type == HTTP_RESPONSE) {
            // Close-delimited response body (RFC 9112 §6.3): no Content-Length AND no
            // Transfer-Encoding on a body-bearing status → the body runs until the server closes
            // the connection. llhttp flags exactly this via http_message_needs_eof (0 for
            // Content-Length / chunked / bodyless-status responses, so the normal paths below are
            // untouched). We can't frame by size, so keep buffering and let flush_eof() deliver
            // the body on disconnect. Bound the accumulation so a server cannot stream forever.
            if (http_message_needs_eof(&_http_obj)) {
                if (this->_io.in().size() - body_offset > _http_obj.max_body_size()) {
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
        header_parsed    = 0;
        _close_delimited = false;
        _refused         = false;
        _http_obj.reset();
    }
};
} // namespace qb::protocol::http

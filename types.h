/**
 * @file qbm/http/types.h
 * @brief Core HTTP type definitions and utilities
 *
 * This file defines fundamental types, constants, and utility functions
 * for the HTTP module, including HTTP methods, status codes, and
 * related helper functions.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <llhttp.h>      // For http_method, http_status, http_method_name, http_status_name
#include <functional>    // For std::hash
#include <string>        // For std::string, std::to_string
#include <string_view>   // For std::string_view
#include <ostream>       // For std::ostream
#include <qb/system/container/unordered_map.h> // For qb::icase_unordered_map
#include "./logger.h"

namespace qb::http {
    /**
     * @brief HTTP method type alias for the underlying enum `http_method_t`.
     *
     * Represents standard HTTP methods like GET, POST, PUT, DELETE, etc., as defined in
     * RFC 7231.
     * The underlying type `http_method` is an alias for `http_method_t` from the `llhttp` library.
     */
    class Method {
    public:
        /**
         * @brief Enum representing supported HTTP methods.
         * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
         */
        enum class Value : int {
            UNINITIALIZED = ::HTTP_UNINITIALIZED, ///< Uninitialized method.
            DEL = ::HTTP_DELETE, ///< DELETE method. "DEL" is used as "DELETE" is a C++ reserved keyword.
            GET = ::HTTP_GET, ///< GET method.
            HEAD = ::HTTP_HEAD, ///< HEAD method.
            POST = ::HTTP_POST, ///< POST method.
            PUT = ::HTTP_PUT, ///< PUT method.
            CONNECT = ::HTTP_CONNECT, ///< CONNECT method.
            OPTIONS = ::HTTP_OPTIONS, ///< OPTIONS method.
            TRACE = ::HTTP_TRACE, ///< TRACE method.
            COPY = ::HTTP_COPY, ///< COPY method (WebDAV).
            LOCK = ::HTTP_LOCK, ///< LOCK method (WebDAV).
            MKCOL = ::HTTP_MKCOL, ///< MKCOL method (WebDAV).
            MOVE = ::HTTP_MOVE, ///< MOVE method (WebDAV).
            PROPFIND = ::HTTP_PROPFIND, ///< PROPFIND method (WebDAV).
            PROPPATCH = ::HTTP_PROPPATCH, ///< PROPPATCH method (WebDAV).
            SEARCH = ::HTTP_SEARCH, ///< SEARCH method.
            UNLOCK = ::HTTP_UNLOCK, ///< UNLOCK method (WebDAV).
            BIND = ::HTTP_BIND, ///< BIND method.
            REBIND = ::HTTP_REBIND, ///< REBIND method.
            UNBIND = ::HTTP_UNBIND, ///< UNBIND method.
            ACL = ::HTTP_ACL, ///< ACL method.
            REPORT = ::HTTP_REPORT, ///< REPORT method.
            MKACTIVITY = ::HTTP_MKACTIVITY, ///< MKACTIVITY method.
            CHECKOUT = ::HTTP_CHECKOUT, ///< CHECKOUT method.
            MERGE = ::HTTP_MERGE, ///< MERGE method.
            MSEARCH = ::HTTP_MSEARCH, ///< M-SEARCH method (UPnP).
            NOTIFY = ::HTTP_NOTIFY, ///< NOTIFY method.
            SUBSCRIBE = ::HTTP_SUBSCRIBE, ///< SUBSCRIBE method.
            UNSUBSCRIBE = ::HTTP_UNSUBSCRIBE, ///< UNSUBSCRIBE method.
            PATCH = ::HTTP_PATCH, ///< PATCH method (RFC 5789).
            PURGE = ::HTTP_PURGE, ///< PURGE method.
            MKCALENDAR = ::HTTP_MKCALENDAR, ///< MKCALENDAR method (CalDAV).
            LINK = ::HTTP_LINK, ///< LINK method.
            UNLINK = ::HTTP_UNLINK, ///< UNLINK method.
            SOURCE = ::HTTP_SOURCE, ///< SOURCE method.
            // The following are from llhttp but might be less common or specific
            PRI = ::HTTP_PRI,
            DESCRIBE = ::HTTP_DESCRIBE,
            ANNOUNCE = ::HTTP_ANNOUNCE,
            SETUP = ::HTTP_SETUP,
            PLAY = ::HTTP_PLAY,
            PAUSE = ::HTTP_PAUSE,
            TEARDOWN = ::HTTP_TEARDOWN,
            GET_PARAMETER = ::HTTP_GET_PARAMETER,
            SET_PARAMETER = ::HTTP_SET_PARAMETER,
            REDIRECT = ::HTTP_REDIRECT,
            RECORD = ::HTTP_RECORD,
            FLUSH = ::HTTP_FLUSH,
            QUERY = ::HTTP_QUERY
        };

        /// Default constructor, initializes to UNINITIALIZED.
        constexpr Method() : _value(Value::UNINITIALIZED) {
        }

        /// Construct from qb::http::Method::Value enum.
        constexpr Method(Value v) : _value(v) {
        }

        /// Construct from raw ::http_method (from llhttp).
        constexpr Method(::http_method m) : _value(static_cast<Value>(m)) {
        }

        /// Construct from std::string_view (case-insensitive).
        Method(std::string_view sv) : _value(Value::UNINITIALIZED) {
            const auto& map = get_string_to_method_map();
            auto it = map.find(std::string(sv)); // Convert to string for icase_unordered_map lookup
            if (it != map.end()) {
                _value = it->second;
            }
        }

        /// Assign from qb::http::Method::Value enum.
        constexpr Method &operator=(Value v) {
            _value = v;
            return *this;
        }

        /// Assign from raw ::http_method.
        constexpr Method &operator=(::http_method m) {
            _value = static_cast<Value>(m);
            return *this;
        }

        /// Equality comparison with another Method object.
        constexpr bool operator==(Method other) const {
            return _value == other._value;
        }

        /// Inequality comparison with another Method object.
        constexpr bool operator!=(Method other) const {
            return !(*this == other);
        }

        /// Less-than comparison (for sorting, maps, sets, etc.).
        constexpr bool operator<(const Method &other) const {
            return static_cast<int>(_value) < static_cast<int>(other._value);
        }

        /// Equality comparison with qb::http::Method::Value enum.
        constexpr bool operator==(Value v) const {
            return _value == v;
        }

        /// Inequality comparison with qb::http::Method::Value enum.
        constexpr bool operator!=(Value v) const {
            return !(*this == v);
        }

        /// Equality comparison with raw ::http_method.
        constexpr bool operator==(::http_method m) const {
            return static_cast<::http_method>(*this) == m;
        }

        /// Inequality comparison with raw ::http_method.
        constexpr bool operator!=(::http_method m) const {
            return !(*this == m);
        }

        /// Convert to raw ::http_method (from llhttp).
        constexpr operator ::http_method() const {
            return static_cast<::http_method>(_value);
        }

        /// Convert to qb::http::Method::Value enum.
        constexpr operator Value() const {
            return _value;
        }

        /// Convert to std::string (e.g., "GET", "POST").
        operator std::string() const {
            return ::http_method_name(static_cast<::http_method>(_value));
        }

        /// Convert to std::string_view (e.g., "GET", "POST").
        operator std::string_view() const {
            return ::http_method_name(static_cast<::http_method>(_value));
        }

        /// Output stream operator (writes method name).
        friend std::ostream &operator<<(std::ostream &os, const Method &m) {
            return os << std::string_view(m);
        }

        // Static accessors for convenient use of enum values (e.g., Method::POST).
        static constexpr Value UNINITIALIZED = Value::UNINITIALIZED; ///< @see Value::UNINITIALIZED
        static constexpr Value DEL = Value::DEL; ///< @see Value::DEL
        static constexpr Value GET = Value::GET; ///< @see Value::GET
        static constexpr Value HEAD = Value::HEAD; ///< @see Value::HEAD
        static constexpr Value POST = Value::POST; ///< @see Value::POST
        static constexpr Value PUT = Value::PUT; ///< @see Value::PUT
        static constexpr Value CONNECT = Value::CONNECT; ///< @see Value::CONNECT
        static constexpr Value OPTIONS = Value::OPTIONS; ///< @see Value::OPTIONS
        static constexpr Value TRACE = Value::TRACE; ///< @see Value::TRACE
        static constexpr Value COPY = Value::COPY; ///< @see Value::COPY
        static constexpr Value LOCK = Value::LOCK; ///< @see Value::LOCK
        static constexpr Value MKCOL = Value::MKCOL; ///< @see Value::MKCOL
        static constexpr Value MOVE = Value::MOVE; ///< @see Value::MOVE
        static constexpr Value PROPFIND = Value::PROPFIND; ///< @see Value::PROPFIND
        static constexpr Value PROPPATCH = Value::PROPPATCH; ///< @see Value::PROPPATCH
        static constexpr Value SEARCH = Value::SEARCH; ///< @see Value::SEARCH
        static constexpr Value UNLOCK = Value::UNLOCK; ///< @see Value::UNLOCK
        static constexpr Value BIND = Value::BIND; ///< @see Value::BIND
        static constexpr Value REBIND = Value::REBIND; ///< @see Value::REBIND
        static constexpr Value UNBIND = Value::UNBIND; ///< @see Value::UNBIND
        static constexpr Value ACL = Value::ACL; ///< @see Value::ACL
        static constexpr Value REPORT = Value::REPORT; ///< @see Value::REPORT
        static constexpr Value MKACTIVITY = Value::MKACTIVITY; ///< @see Value::MKACTIVITY
        static constexpr Value CHECKOUT = Value::CHECKOUT; ///< @see Value::CHECKOUT
        static constexpr Value MERGE = Value::MERGE; ///< @see Value::MERGE
        static constexpr Value MSEARCH = Value::MSEARCH; ///< @see Value::MSEARCH
        static constexpr Value NOTIFY = Value::NOTIFY; ///< @see Value::NOTIFY
        static constexpr Value SUBSCRIBE = Value::SUBSCRIBE; ///< @see Value::SUBSCRIBE
        static constexpr Value UNSUBSCRIBE = Value::UNSUBSCRIBE; ///< @see Value::UNSUBSCRIBE
        static constexpr Value PATCH = Value::PATCH; ///< @see Value::PATCH
        static constexpr Value PURGE = Value::PURGE; ///< @see Value::PURGE
        static constexpr Value MKCALENDAR = Value::MKCALENDAR; ///< @see Value::MKCALENDAR
        static constexpr Value LINK = Value::LINK; ///< @see Value::LINK
        static constexpr Value UNLINK = Value::UNLINK; ///< @see Value::UNLINK
        static constexpr Value SOURCE = Value::SOURCE; ///< @see Value::SOURCE
        static constexpr Value PRI = Value::PRI; ///< @see Value::PRI
        static constexpr Value DESCRIBE = Value::DESCRIBE; ///< @see Value::DESCRIBE
        static constexpr Value ANNOUNCE = Value::ANNOUNCE; ///< @see Value::ANNOUNCE
        static constexpr Value SETUP = Value::SETUP; ///< @see Value::SETUP
        static constexpr Value PLAY = Value::PLAY; ///< @see Value::PLAY
        static constexpr Value PAUSE = Value::PAUSE; ///< @see Value::PAUSE
        static constexpr Value TEARDOWN = Value::TEARDOWN; ///< @see Value::TEARDOWN
        static constexpr Value GET_PARAMETER = Value::GET_PARAMETER; ///< @see Value::GET_PARAMETER
        static constexpr Value SET_PARAMETER = Value::SET_PARAMETER; ///< @see Value::SET_PARAMETER
        static constexpr Value REDIRECT = Value::REDIRECT; ///< @see Value::REDIRECT
        static constexpr Value RECORD = Value::RECORD; ///< @see Value::RECORD
        static constexpr Value FLUSH = Value::FLUSH; ///< @see Value::FLUSH
        static constexpr Value QUERY = Value::QUERY; ///< @see Value::QUERY

    private:
        Value _value;

        // Static map for string to Method::Value conversion
        static const qb::icase_unordered_map<Value>& get_string_to_method_map() {
            static qb::icase_unordered_map<Value> string_to_method_map = {
                {"DELETE", Value::DEL},
                {"GET", Value::GET},
                {"HEAD", Value::HEAD},
                {"POST", Value::POST},
                {"PUT", Value::PUT},
                {"CONNECT", Value::CONNECT},
                {"OPTIONS", Value::OPTIONS},
                {"TRACE", Value::TRACE},
                {"COPY", Value::COPY},
                {"LOCK", Value::LOCK},
                {"MKCOL", Value::MKCOL},
                {"MOVE", Value::MOVE},
                {"PROPFIND", Value::PROPFIND},
                {"PROPPATCH", Value::PROPPATCH},
                {"SEARCH", Value::SEARCH},
                {"UNLOCK", Value::UNLOCK},
                {"BIND", Value::BIND},
                {"REBIND", Value::REBIND},
                {"UNBIND", Value::UNBIND},
                {"ACL", Value::ACL},
                {"REPORT", Value::REPORT},
                {"MKACTIVITY", Value::MKACTIVITY},
                {"CHECKOUT", Value::CHECKOUT},
                {"MERGE", Value::MERGE},
                {"M-SEARCH", Value::MSEARCH},
                {"NOTIFY", Value::NOTIFY},
                {"SUBSCRIBE", Value::SUBSCRIBE},
                {"UNSUBSCRIBE", Value::UNSUBSCRIBE},
                {"PATCH", Value::PATCH},
                {"PURGE", Value::PURGE},
                {"MKCALENDAR", Value::MKCALENDAR},
                {"LINK", Value::LINK},
                {"UNLINK", Value::UNLINK},
                {"SOURCE", Value::SOURCE},
                {"PRI", Value::PRI},
                {"DESCRIBE", Value::DESCRIBE},
                {"ANNOUNCE", Value::ANNOUNCE},
                {"SETUP", Value::SETUP},
                {"PLAY", Value::PLAY},
                {"PAUSE", Value::PAUSE},
                {"TEARDOWN", Value::TEARDOWN},
                {"GET_PARAMETER", Value::GET_PARAMETER},
                {"SET_PARAMETER", Value::SET_PARAMETER},
                {"REDIRECT", Value::REDIRECT},
                {"RECORD", Value::RECORD},
                {"FLUSH", Value::FLUSH},
                {"QUERY", Value::QUERY}
            };
            return string_to_method_map;
        }
    };

    using method = Method;

    /**
     * @brief HTTP status code type alias for the underlying enum `http_status_t`.
     *
     * Represents standard HTTP status codes like 200 OK, 404 Not Found, etc.,
     * as defined in RFC 7231 and other relevant RFCs.
     * The underlying type `http_status` is an alias for `http_status_t` from the `llhttp` library.
     */
    class Status {
    public:
        /**
         * @brief Enum representing supported HTTP status codes.
         * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
         */
        enum class Value : int {
            // Informational 1xx
            CONTINUE = ::HTTP_STATUS_CONTINUE, ///< 100 Continue
            SWITCHING_PROTOCOLS = ::HTTP_STATUS_SWITCHING_PROTOCOLS, ///< 101 Switching Protocols
            PROCESSING = ::HTTP_STATUS_PROCESSING, ///< 102 Processing (WebDAV)
            EARLY_HINTS = ::HTTP_STATUS_EARLY_HINTS, ///< 103 Early Hints

            // Successful 2xx
            OK = ::HTTP_STATUS_OK, ///< 200 OK
            CREATED = ::HTTP_STATUS_CREATED, ///< 201 Created
            ACCEPTED = ::HTTP_STATUS_ACCEPTED, ///< 202 Accepted
            NON_AUTHORITATIVE_INFORMATION = ::HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION,
            ///< 203 Non-Authoritative Information
            NO_CONTENT = ::HTTP_STATUS_NO_CONTENT, ///< 204 No Content
            RESET_CONTENT = ::HTTP_STATUS_RESET_CONTENT, ///< 205 Reset Content
            PARTIAL_CONTENT = ::HTTP_STATUS_PARTIAL_CONTENT, ///< 206 Partial Content
            MULTI_STATUS = ::HTTP_STATUS_MULTI_STATUS, ///< 207 Multi-Status (WebDAV)
            ALREADY_REPORTED = ::HTTP_STATUS_ALREADY_REPORTED, ///< 208 Already Reported (WebDAV)
            IM_USED = ::HTTP_STATUS_IM_USED, ///< 226 IM Used (HTTP Delta encoding)

            // Redirection 3xx
            MULTIPLE_CHOICES = ::HTTP_STATUS_MULTIPLE_CHOICES, ///< 300 Multiple Choices
            MOVED_PERMANENTLY = ::HTTP_STATUS_MOVED_PERMANENTLY, ///< 301 Moved Permanently
            FOUND = ::HTTP_STATUS_FOUND, ///< 302 Found (Previously "Moved temporarily")
            SEE_OTHER = ::HTTP_STATUS_SEE_OTHER, ///< 303 See Other
            NOT_MODIFIED = ::HTTP_STATUS_NOT_MODIFIED, ///< 304 Not Modified
            USE_PROXY = ::HTTP_STATUS_USE_PROXY, ///< 305 Use Proxy (deprecated)
            TEMPORARY_REDIRECT = ::HTTP_STATUS_TEMPORARY_REDIRECT, ///< 307 Temporary Redirect
            PERMANENT_REDIRECT = ::HTTP_STATUS_PERMANENT_REDIRECT, ///< 308 Permanent Redirect

            // Client Error 4xx
            BAD_REQUEST = ::HTTP_STATUS_BAD_REQUEST, ///< 400 Bad Request
            UNAUTHORIZED = ::HTTP_STATUS_UNAUTHORIZED, ///< 401 Unauthorized
            PAYMENT_REQUIRED = ::HTTP_STATUS_PAYMENT_REQUIRED, ///< 402 Payment Required
            FORBIDDEN = ::HTTP_STATUS_FORBIDDEN, ///< 403 Forbidden
            NOT_FOUND = ::HTTP_STATUS_NOT_FOUND, ///< 404 Not Found
            METHOD_NOT_ALLOWED = ::HTTP_STATUS_METHOD_NOT_ALLOWED, ///< 405 Method Not Allowed
            NOT_ACCEPTABLE = ::HTTP_STATUS_NOT_ACCEPTABLE, ///< 406 Not Acceptable
            PROXY_AUTHENTICATION_REQUIRED = ::HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED,
            ///< 407 Proxy Authentication Required
            REQUEST_TIMEOUT = ::HTTP_STATUS_REQUEST_TIMEOUT, ///< 408 Request Timeout
            CONFLICT = ::HTTP_STATUS_CONFLICT, ///< 409 Conflict
            GONE = ::HTTP_STATUS_GONE, ///< 410 Gone
            LENGTH_REQUIRED = ::HTTP_STATUS_LENGTH_REQUIRED, ///< 411 Length Required
            PRECONDITION_FAILED = ::HTTP_STATUS_PRECONDITION_FAILED, ///< 412 Precondition Failed
            PAYLOAD_TOO_LARGE = ::HTTP_STATUS_PAYLOAD_TOO_LARGE, ///< 413 Payload Too Large
            URI_TOO_LONG = ::HTTP_STATUS_URI_TOO_LONG, ///< 414 URI Too Long
            UNSUPPORTED_MEDIA_TYPE = ::HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE, ///< 415 Unsupported Media Type
            RANGE_NOT_SATISFIABLE = ::HTTP_STATUS_RANGE_NOT_SATISFIABLE, ///< 416 Range Not Satisfiable
            EXPECTATION_FAILED = ::HTTP_STATUS_EXPECTATION_FAILED, ///< 417 Expectation Failed
            IM_A_TEAPOT = ::HTTP_STATUS_IM_A_TEAPOT, ///< 418 I'm a teapot (RFC 2324)
            MISDIRECTED_REQUEST = ::HTTP_STATUS_MISDIRECTED_REQUEST, ///< 421 Misdirected Request
            UNPROCESSABLE_ENTITY = ::HTTP_STATUS_UNPROCESSABLE_ENTITY, ///< 422 Unprocessable Entity (WebDAV)
            LOCKED = ::HTTP_STATUS_LOCKED, ///< 423 Locked (WebDAV)
            FAILED_DEPENDENCY = ::HTTP_STATUS_FAILED_DEPENDENCY, ///< 424 Failed Dependency (WebDAV)
            TOO_EARLY = ::HTTP_STATUS_TOO_EARLY, ///< 425 Too Early (RFC 8470)
            UPGRADE_REQUIRED = ::HTTP_STATUS_UPGRADE_REQUIRED, ///< 426 Upgrade Required
            PRECONDITION_REQUIRED = ::HTTP_STATUS_PRECONDITION_REQUIRED, ///< 428 Precondition Required (RFC 6585)
            TOO_MANY_REQUESTS = ::HTTP_STATUS_TOO_MANY_REQUESTS, ///< 429 Too Many Requests (RFC 6585)
            REQUEST_HEADER_FIELDS_TOO_LARGE = ::HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE,
            ///< 431 Request Header Fields Too Large (RFC 6585)
            UNAVAILABLE_FOR_LEGAL_REASONS = ::HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS,
            ///< 451 Unavailable For Legal Reasons (RFC 7725)

            // Server Error 5xx
            INTERNAL_SERVER_ERROR = ::HTTP_STATUS_INTERNAL_SERVER_ERROR, ///< 500 Internal Server Error
            NOT_IMPLEMENTED = ::HTTP_STATUS_NOT_IMPLEMENTED, ///< 501 Not Implemented
            BAD_GATEWAY = ::HTTP_STATUS_BAD_GATEWAY, ///< 502 Bad Gateway
            SERVICE_UNAVAILABLE = ::HTTP_STATUS_SERVICE_UNAVAILABLE, ///< 503 Service Unavailable
            GATEWAY_TIMEOUT = ::HTTP_STATUS_GATEWAY_TIMEOUT, ///< 504 Gateway Timeout
            HTTP_VERSION_NOT_SUPPORTED = ::HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED, ///< 505 HTTP Version Not Supported
            VARIANT_ALSO_NEGOTIATES = ::HTTP_STATUS_VARIANT_ALSO_NEGOTIATES, ///< 506 Variant Also Negotiates (RFC 2295)
            INSUFFICIENT_STORAGE = ::HTTP_STATUS_INSUFFICIENT_STORAGE, ///< 507 Insufficient Storage (WebDAV)
            LOOP_DETECTED = ::HTTP_STATUS_LOOP_DETECTED, ///< 508 Loop Detected (WebDAV)
            NOT_EXTENDED = ::HTTP_STATUS_NOT_EXTENDED, ///< 510 Not Extended (RFC 2774)
            NETWORK_AUTHENTICATION_REQUIRED = ::HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED,
            ///< 511 Network Authentication Required (RFC 6585)

            // llhttp specific or less common status codes (may not be standard or universally recognized)
            RESPONSE_IS_STALE = ::HTTP_STATUS_RESPONSE_IS_STALE, ///< (llhttp specific) Response is stale.
            REVALIDATION_FAILED = ::HTTP_STATUS_REVALIDATION_FAILED, ///< (llhttp specific) Revalidation failed.
            DISCONNECTED_OPERATION = ::HTTP_STATUS_DISCONNECTED_OPERATION,
            ///< (llhttp specific) Disconnected operation.
            HEURISTIC_EXPIRATION = ::HTTP_STATUS_HEURISTIC_EXPIRATION, ///< (llhttp specific) Heuristic expiration.
            MISCELLANEOUS_WARNING = ::HTTP_STATUS_MISCELLANEOUS_WARNING, ///< (llhttp specific) Miscellaneous warning.
            TRANSFORMATION_APPLIED = ::HTTP_STATUS_TRANSFORMATION_APPLIED,
            ///< (llhttp specific) Transformation applied.
            MISCELLANEOUS_PERSISTENT_WARNING = ::HTTP_STATUS_MISCELLANEOUS_PERSISTENT_WARNING,
            ///< (llhttp specific) Miscellaneous persistent warning.
            SWITCH_PROXY = ::HTTP_STATUS_SWITCH_PROXY,
            ///< (llhttp specific, possibly related to 306 Switch Proxy, which is unused)
            PAGE_EXPIRED = ::HTTP_STATUS_PAGE_EXPIRED, ///< (llhttp specific) Page expired.
            ENHANCE_YOUR_CALM = ::HTTP_STATUS_ENHANCE_YOUR_CALM, ///< (llhttp specific, Twitter API) Enhance Your Calm.
            REQUEST_HEADER_FIELDS_TOO_LARGE_UNOFFICIAL = ::HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE_UNOFFICIAL,
            ///< (llhttp specific, unofficial) Request header fields too large.
            LOGIN_TIMEOUT = ::HTTP_STATUS_LOGIN_TIMEOUT, ///< (llhttp specific) Login timeout.
            NO_RESPONSE = ::HTTP_STATUS_NO_RESPONSE, ///< (llhttp specific) No response.
            RETRY_WITH = ::HTTP_STATUS_RETRY_WITH, ///< (llhttp specific, Microsoft) Retry With.
            BLOCKED_BY_PARENTAL_CONTROL = ::HTTP_STATUS_BLOCKED_BY_PARENTAL_CONTROL,
            ///< (llhttp specific, Microsoft) Blocked by Windows Parental Controls.
            CLIENT_CLOSED_LOAD_BALANCED_REQUEST = ::HTTP_STATUS_CLIENT_CLOSED_LOAD_BALANCED_REQUEST,
            ///< (llhttp specific) Client closed load balanced request.
            INVALID_X_FORWARDED_FOR = ::HTTP_STATUS_INVALID_X_FORWARDED_FOR,
            ///< (llhttp specific) Invalid X-Forwarded-For.
            REQUEST_HEADER_TOO_LARGE = ::HTTP_STATUS_REQUEST_HEADER_TOO_LARGE,
            ///< (llhttp specific) Request header too large (potentially distinct from 431).
            SSL_CERTIFICATE_ERROR = ::HTTP_STATUS_SSL_CERTIFICATE_ERROR, ///< (llhttp specific) SSL certificate error.
            SSL_CERTIFICATE_REQUIRED = ::HTTP_STATUS_SSL_CERTIFICATE_REQUIRED,
            ///< (llhttp specific) SSL certificate required.
            HTTP_REQUEST_SENT_TO_HTTPS_PORT = ::HTTP_STATUS_HTTP_REQUEST_SENT_TO_HTTPS_PORT,
            ///< (llhttp specific) HTTP request sent to HTTPS port.
            INVALID_TOKEN = ::HTTP_STATUS_INVALID_TOKEN, ///< (llhttp specific) Invalid token.
            CLIENT_CLOSED_REQUEST = ::HTTP_STATUS_CLIENT_CLOSED_REQUEST, ///< (llhttp specific) Client closed request.
            BANDWIDTH_LIMIT_EXCEEDED = ::HTTP_STATUS_BANDWIDTH_LIMIT_EXCEEDED,
            ///< (llhttp specific) Bandwidth limit exceeded.
            WEB_SERVER_UNKNOWN_ERROR = ::HTTP_STATUS_WEB_SERVER_UNKNOWN_ERROR,
            ///< (llhttp specific) Web server unknown error.
            WEB_SERVER_IS_DOWN = ::HTTP_STATUS_WEB_SERVER_IS_DOWN, ///< (llhttp specific) Web server is down.
            CONNECTION_TIMEOUT = ::HTTP_STATUS_CONNECTION_TIMEOUT, ///< (llhttp specific) Connection timeout.
            ORIGIN_IS_UNREACHABLE = ::HTTP_STATUS_ORIGIN_IS_UNREACHABLE, ///< (llhttp specific) Origin is unreachable.
            TIMEOUT_OCCURED = ::HTTP_STATUS_TIMEOUT_OCCURED, ///< (llhttp specific) Timeout occurred.
            SSL_HANDSHAKE_FAILED = ::HTTP_STATUS_SSL_HANDSHAKE_FAILED, ///< (llhttp specific) SSL handshake failed.
            INVALID_SSL_CERTIFICATE = ::HTTP_STATUS_INVALID_SSL_CERTIFICATE,
            ///< (llhttp specific) Invalid SSL certificate.
            RAILGUN_ERROR = ::HTTP_STATUS_RAILGUN_ERROR, ///< (llhttp specific) Railgun error.
            SITE_IS_OVERLOADED = ::HTTP_STATUS_SITE_IS_OVERLOADED, ///< (llhttp specific) Site is overloaded.
            SITE_IS_FROZEN = ::HTTP_STATUS_SITE_IS_FROZEN, ///< (llhttp specific) Site is frozen.
            IDENTITY_PROVIDER_AUTHENTICATION_ERROR = ::HTTP_STATUS_IDENTITY_PROVIDER_AUTHENTICATION_ERROR,
            ///< (llhttp specific) Identity provider authentication error.
            NETWORK_READ_TIMEOUT = ::HTTP_STATUS_NETWORK_READ_TIMEOUT, ///< (llhttp specific) Network read timeout.
            NETWORK_CONNECT_TIMEOUT = ::HTTP_STATUS_NETWORK_CONNECT_TIMEOUT
            ///< (llhttp specific) Network connect timeout.
        };

        /// Default constructor, initializes to 200 OK.
        constexpr Status() : _value(Value::OK) {
        }

        /// Construct from qb::http::Status::Value enum.
        constexpr Status(Value v) : _value(v) {
        }

        /// Construct from raw ::http_status (from llhttp).
        constexpr Status(::http_status s) : _value(static_cast<Value>(s)) {
        }

        /// Construct from an integer status code.
        constexpr Status(int i) : _value(static_cast<Value>(i)) {
        }

        /// Assign from qb::http::Status::Value enum.
        constexpr Status &operator=(Value v) {
            _value = v;
            return *this;
        }

        /// Assign from raw ::http_status.
        constexpr Status &operator=(::http_status s) {
            _value = static_cast<Value>(s);
            return *this;
        }

        /// Assign from an integer status code.
        constexpr Status &operator=(int i) {
            _value = static_cast<Value>(i);
            return *this;
        }

        /// Equality comparison with another Status object.
        constexpr bool operator==(Status other) const { return _value == other._value; }
        /// Inequality comparison with another Status object.
        constexpr bool operator!=(Status other) const { return !(*this == other); }

        /// Less-than comparison (for sorting, maps, sets, etc.).
        constexpr bool operator<(const Status &other) const {
            return static_cast<int>(_value) < static_cast<int>(other._value);
        }

        /// Equality comparison with qb::http::Status::Value enum.
        constexpr bool operator==(Value v) const { return _value == v; }
        /// Inequality comparison with qb::http::Status::Value enum.
        constexpr bool operator!=(Value v) const { return !(*this == v); }

        /// Less-than comparison with qb::http::Status::Value enum.
        constexpr bool operator<(Value v) const { return static_cast<int>(_value) < static_cast<int>(v); }

        /// Equality comparison with raw ::http_status.
        constexpr bool operator==(::http_status s) const { return static_cast<::http_status>(*this) == s; }
        /// Inequality comparison with raw ::http_status.
        constexpr bool operator!=(::http_status s) const { return !(*this == s); }

        /// Equality comparison with an integer status code.
        constexpr bool operator==(int i) const { return static_cast<int>(_value) == i; }
        /// Inequality comparison with an integer status code.
        constexpr bool operator!=(int i) const { return !(*this == i); }


        /// Convert to raw ::http_status (from llhttp).
        constexpr operator ::http_status() const { return static_cast<::http_status>(_value); }
        /// Convert to qb::http::Status::Value enum.
        constexpr operator Value() const { return _value; }

        /// Convert to std::string (e.g., "OK", "Not Found").
        operator std::string() const {
            const char *name = ::http_status_name(static_cast<::http_status>(_value));
            return name ? name : "Unknown Status";
        }

        /// Convert to std::string_view (e.g., "OK", "Not Found").
        operator std::string_view() const {
            const char *name = ::http_status_name(static_cast<::http_status>(_value));
            return name ? name : "Unknown Status";
        }

        /// Convert to int (e.g., 200, 404).
        constexpr int code() const { return static_cast<int>(_value); }
        /// Convert to std::string_view (e.g., "OK", "Not Found").
        constexpr std::string_view str() const { return std::string_view(*this); }

        /// Output stream operator (writes status code and name).
        friend std::ostream &operator<<(std::ostream &os, const Status &s) {
            return os << std::string_view(s); // Outputs status code string e.g. "OK", "Not Found"
        }

        // Static accessors for convenient use of enum values (e.g., Status::OK).
        // Informational 1xx
        static constexpr Value CONTINUE = Value::CONTINUE; ///< @see Value::CONTINUE
        static constexpr Value SWITCHING_PROTOCOLS = Value::SWITCHING_PROTOCOLS; ///< @see Value::SWITCHING_PROTOCOLS
        static constexpr Value PROCESSING = Value::PROCESSING; ///< @see Value::PROCESSING
        static constexpr Value EARLY_HINTS = Value::EARLY_HINTS; ///< @see Value::EARLY_HINTS
        // Successful 2xx
        static constexpr Value OK = Value::OK; ///< @see Value::OK
        static constexpr Value CREATED = Value::CREATED; ///< @see Value::CREATED
        static constexpr Value ACCEPTED = Value::ACCEPTED; ///< @see Value::ACCEPTED
        static constexpr Value NON_AUTHORITATIVE_INFORMATION = Value::NON_AUTHORITATIVE_INFORMATION;
        ///< @see Value::NON_AUTHORITATIVE_INFORMATION
        static constexpr Value NO_CONTENT = Value::NO_CONTENT; ///< @see Value::NO_CONTENT
        static constexpr Value RESET_CONTENT = Value::RESET_CONTENT; ///< @see Value::RESET_CONTENT
        static constexpr Value PARTIAL_CONTENT = Value::PARTIAL_CONTENT; ///< @see Value::PARTIAL_CONTENT
        static constexpr Value MULTI_STATUS = Value::MULTI_STATUS; ///< @see Value::MULTI_STATUS
        static constexpr Value ALREADY_REPORTED = Value::ALREADY_REPORTED; ///< @see Value::ALREADY_REPORTED
        static constexpr Value IM_USED = Value::IM_USED; ///< @see Value::IM_USED
        // Redirection 3xx
        static constexpr Value MULTIPLE_CHOICES = Value::MULTIPLE_CHOICES; ///< @see Value::MULTIPLE_CHOICES
        static constexpr Value MOVED_PERMANENTLY = Value::MOVED_PERMANENTLY; ///< @see Value::MOVED_PERMANENTLY
        static constexpr Value FOUND = Value::FOUND; ///< @see Value::FOUND
        static constexpr Value SEE_OTHER = Value::SEE_OTHER; ///< @see Value::SEE_OTHER
        static constexpr Value NOT_MODIFIED = Value::NOT_MODIFIED; ///< @see Value::NOT_MODIFIED
        static constexpr Value USE_PROXY = Value::USE_PROXY; ///< @see Value::USE_PROXY
        static constexpr Value TEMPORARY_REDIRECT = Value::TEMPORARY_REDIRECT; ///< @see Value::TEMPORARY_REDIRECT
        static constexpr Value PERMANENT_REDIRECT = Value::PERMANENT_REDIRECT; ///< @see Value::PERMANENT_REDIRECT
        // Client Error 4xx
        static constexpr Value BAD_REQUEST = Value::BAD_REQUEST; ///< @see Value::BAD_REQUEST
        static constexpr Value UNAUTHORIZED = Value::UNAUTHORIZED; ///< @see Value::UNAUTHORIZED
        static constexpr Value PAYMENT_REQUIRED = Value::PAYMENT_REQUIRED; ///< @see Value::PAYMENT_REQUIRED
        static constexpr Value FORBIDDEN = Value::FORBIDDEN; ///< @see Value::FORBIDDEN
        static constexpr Value NOT_FOUND = Value::NOT_FOUND; ///< @see Value::NOT_FOUND
        static constexpr Value METHOD_NOT_ALLOWED = Value::METHOD_NOT_ALLOWED; ///< @see Value::METHOD_NOT_ALLOWED
        static constexpr Value NOT_ACCEPTABLE = Value::NOT_ACCEPTABLE; ///< @see Value::NOT_ACCEPTABLE
        static constexpr Value PROXY_AUTHENTICATION_REQUIRED = Value::PROXY_AUTHENTICATION_REQUIRED;
        ///< @see Value::PROXY_AUTHENTICATION_REQUIRED
        static constexpr Value REQUEST_TIMEOUT = Value::REQUEST_TIMEOUT; ///< @see Value::REQUEST_TIMEOUT
        static constexpr Value CONFLICT = Value::CONFLICT; ///< @see Value::CONFLICT
        static constexpr Value GONE = Value::GONE; ///< @see Value::GONE
        static constexpr Value LENGTH_REQUIRED = Value::LENGTH_REQUIRED; ///< @see Value::LENGTH_REQUIRED
        static constexpr Value PRECONDITION_FAILED = Value::PRECONDITION_FAILED; ///< @see Value::PRECONDITION_FAILED
        static constexpr Value PAYLOAD_TOO_LARGE = Value::PAYLOAD_TOO_LARGE; ///< @see Value::PAYLOAD_TOO_LARGE
        static constexpr Value URI_TOO_LONG = Value::URI_TOO_LONG; ///< @see Value::URI_TOO_LONG
        static constexpr Value UNSUPPORTED_MEDIA_TYPE = Value::UNSUPPORTED_MEDIA_TYPE;
        ///< @see Value::UNSUPPORTED_MEDIA_TYPE
        static constexpr Value RANGE_NOT_SATISFIABLE = Value::RANGE_NOT_SATISFIABLE;
        ///< @see Value::RANGE_NOT_SATISFIABLE
        static constexpr Value EXPECTATION_FAILED = Value::EXPECTATION_FAILED; ///< @see Value::EXPECTATION_FAILED
        static constexpr Value IM_A_TEAPOT = Value::IM_A_TEAPOT; ///< @see Value::IM_A_TEAPOT
        static constexpr Value MISDIRECTED_REQUEST = Value::MISDIRECTED_REQUEST; ///< @see Value::MISDIRECTED_REQUEST
        static constexpr Value UNPROCESSABLE_ENTITY = Value::UNPROCESSABLE_ENTITY; ///< @see Value::UNPROCESSABLE_ENTITY
        static constexpr Value LOCKED = Value::LOCKED; ///< @see Value::LOCKED
        static constexpr Value FAILED_DEPENDENCY = Value::FAILED_DEPENDENCY; ///< @see Value::FAILED_DEPENDENCY
        static constexpr Value TOO_EARLY = Value::TOO_EARLY; ///< @see Value::TOO_EARLY
        static constexpr Value UPGRADE_REQUIRED = Value::UPGRADE_REQUIRED; ///< @see Value::UPGRADE_REQUIRED
        static constexpr Value PRECONDITION_REQUIRED = Value::PRECONDITION_REQUIRED;
        ///< @see Value::PRECONDITION_REQUIRED
        static constexpr Value TOO_MANY_REQUESTS = Value::TOO_MANY_REQUESTS; ///< @see Value::TOO_MANY_REQUESTS
        static constexpr Value REQUEST_HEADER_FIELDS_TOO_LARGE = Value::REQUEST_HEADER_FIELDS_TOO_LARGE;
        ///< @see Value::REQUEST_HEADER_FIELDS_TOO_LARGE
        static constexpr Value UNAVAILABLE_FOR_LEGAL_REASONS = Value::UNAVAILABLE_FOR_LEGAL_REASONS;
        ///< @see Value::UNAVAILABLE_FOR_LEGAL_REASONS
        // Server Error 5xx
        static constexpr Value INTERNAL_SERVER_ERROR = Value::INTERNAL_SERVER_ERROR;
        ///< @see Value::INTERNAL_SERVER_ERROR
        static constexpr Value NOT_IMPLEMENTED = Value::NOT_IMPLEMENTED; ///< @see Value::NOT_IMPLEMENTED
        static constexpr Value BAD_GATEWAY = Value::BAD_GATEWAY; ///< @see Value::BAD_GATEWAY
        static constexpr Value SERVICE_UNAVAILABLE = Value::SERVICE_UNAVAILABLE; ///< @see Value::SERVICE_UNAVAILABLE
        static constexpr Value GATEWAY_TIMEOUT = Value::GATEWAY_TIMEOUT; ///< @see Value::GATEWAY_TIMEOUT
        static constexpr Value HTTP_VERSION_NOT_SUPPORTED = Value::HTTP_VERSION_NOT_SUPPORTED;
        ///< @see Value::HTTP_VERSION_NOT_SUPPORTED
        static constexpr Value VARIANT_ALSO_NEGOTIATES = Value::VARIANT_ALSO_NEGOTIATES;
        ///< @see Value::VARIANT_ALSO_NEGOTIATES
        static constexpr Value INSUFFICIENT_STORAGE = Value::INSUFFICIENT_STORAGE; ///< @see Value::INSUFFICIENT_STORAGE
        static constexpr Value LOOP_DETECTED = Value::LOOP_DETECTED; ///< @see Value::LOOP_DETECTED
        static constexpr Value NOT_EXTENDED = Value::NOT_EXTENDED; ///< @see Value::NOT_EXTENDED
        static constexpr Value NETWORK_AUTHENTICATION_REQUIRED = Value::NETWORK_AUTHENTICATION_REQUIRED;
        ///< @see Value::NETWORK_AUTHENTICATION_REQUIRED

        // --- Less common / llhttp specific static accessors ---
        // (These match the enum but are not part of the primary HTTP status code sets)
        static constexpr Value RESPONSE_IS_STALE = Value::RESPONSE_IS_STALE;
        static constexpr Value REVALIDATION_FAILED = Value::REVALIDATION_FAILED;
        static constexpr Value DISCONNECTED_OPERATION = Value::DISCONNECTED_OPERATION;
        static constexpr Value HEURISTIC_EXPIRATION = Value::HEURISTIC_EXPIRATION;
        static constexpr Value MISCELLANEOUS_WARNING = Value::MISCELLANEOUS_WARNING;
        static constexpr Value TRANSFORMATION_APPLIED = Value::TRANSFORMATION_APPLIED;
        static constexpr Value MISCELLANEOUS_PERSISTENT_WARNING = Value::MISCELLANEOUS_PERSISTENT_WARNING;
        static constexpr Value SWITCH_PROXY = Value::SWITCH_PROXY;
        static constexpr Value PAGE_EXPIRED = Value::PAGE_EXPIRED;
        static constexpr Value ENHANCE_YOUR_CALM = Value::ENHANCE_YOUR_CALM;
        static constexpr Value REQUEST_HEADER_FIELDS_TOO_LARGE_UNOFFICIAL =
                Value::REQUEST_HEADER_FIELDS_TOO_LARGE_UNOFFICIAL;
        static constexpr Value LOGIN_TIMEOUT = Value::LOGIN_TIMEOUT;
        static constexpr Value NO_RESPONSE = Value::NO_RESPONSE;
        static constexpr Value RETRY_WITH = Value::RETRY_WITH;
        static constexpr Value BLOCKED_BY_PARENTAL_CONTROL = Value::BLOCKED_BY_PARENTAL_CONTROL;
        static constexpr Value CLIENT_CLOSED_LOAD_BALANCED_REQUEST = Value::CLIENT_CLOSED_LOAD_BALANCED_REQUEST;
        static constexpr Value INVALID_X_FORWARDED_FOR = Value::INVALID_X_FORWARDED_FOR;
        // Note: REQUEST_HEADER_TOO_LARGE is intentionally omitted if REQUEST_HEADER_FIELDS_TOO_LARGE is preferred.
        // If both needed, add: static constexpr Value REQUEST_HEADER_TOO_LARGE = Value::REQUEST_HEADER_TOO_LARGE;
        static constexpr Value SSL_CERTIFICATE_ERROR = Value::SSL_CERTIFICATE_ERROR;
        static constexpr Value SSL_CERTIFICATE_REQUIRED = Value::SSL_CERTIFICATE_REQUIRED;
        static constexpr Value HTTP_REQUEST_SENT_TO_HTTPS_PORT = Value::HTTP_REQUEST_SENT_TO_HTTPS_PORT;
        static constexpr Value INVALID_TOKEN = Value::INVALID_TOKEN;
        static constexpr Value CLIENT_CLOSED_REQUEST = Value::CLIENT_CLOSED_REQUEST;
        static constexpr Value BANDWIDTH_LIMIT_EXCEEDED = Value::BANDWIDTH_LIMIT_EXCEEDED;
        static constexpr Value WEB_SERVER_UNKNOWN_ERROR = Value::WEB_SERVER_UNKNOWN_ERROR;
        static constexpr Value WEB_SERVER_IS_DOWN = Value::WEB_SERVER_IS_DOWN;
        static constexpr Value CONNECTION_TIMEOUT = Value::CONNECTION_TIMEOUT;
        static constexpr Value ORIGIN_IS_UNREACHABLE = Value::ORIGIN_IS_UNREACHABLE;
        static constexpr Value TIMEOUT_OCCURED = Value::TIMEOUT_OCCURED;
        static constexpr Value SSL_HANDSHAKE_FAILED = Value::SSL_HANDSHAKE_FAILED;
        static constexpr Value INVALID_SSL_CERTIFICATE = Value::INVALID_SSL_CERTIFICATE;
        static constexpr Value RAILGUN_ERROR = Value::RAILGUN_ERROR;
        static constexpr Value SITE_IS_OVERLOADED = Value::SITE_IS_OVERLOADED;
        static constexpr Value SITE_IS_FROZEN = Value::SITE_IS_FROZEN;
        static constexpr Value IDENTITY_PROVIDER_AUTHENTICATION_ERROR = Value::IDENTITY_PROVIDER_AUTHENTICATION_ERROR;
        static constexpr Value NETWORK_READ_TIMEOUT = Value::NETWORK_READ_TIMEOUT;
        static constexpr Value NETWORK_CONNECT_TIMEOUT = Value::NETWORK_CONNECT_TIMEOUT;

    private:
        Value _value;
    };

    using status = Status;

    /**
     * @brief HTTP line ending sequence (CRLF).
     *
     * As defined in the HTTP specification (RFC 7230, Section 3.5), lines must end with CR+LF.
     */
    constexpr char endl[] = "\r\n";

    /**
     * @brief HTTP separator character (space).
     *
     * Used between parts of the request/status line in HTTP messages
     * (e.g., "GET / HTTP/1.1").
     */
    constexpr char sep = ' ';

    /**
     * @brief HTTP disconnection reason codes
     *
     * Defines possible reasons for disconnection of HTTP sessions.
     * These codes help with debugging and proper handling of session termination.
     * Used to provide context when a disconnection event is triggered, allowing
     * the application to react appropriately based on the reason.
     */
    enum DisconnectedReason : int {
        ByUser = 0, ///< Disconnected by user request
        ByTimeout, ///< Disconnected due to timeout
        ResponseTransmitted, ///< Disconnected after response was transmitted
        ServerError, ///< Disconnected due to server error
        ByProtocolError, ///< Disconnected due to protocol error
        Undefined ///< Undefined reason (should never happen)
    };
} // namespace qb::http

/**
 * @def HTTP_SERVER_METHOD_MAP(XX)
 * @brief Macro to generate mappings for HTTP server methods.
 *
 * This macro is typically used by the `llhttp` library or similar parsers
 * to iterate over supported HTTP methods. The `XX` parameter is a macro
 * that takes three arguments: an index, a lowercase name, and an uppercase name.
 *
 * Example usage:
 * @code
 * #define PRINT_METHOD(index, lower, upper) \
 *     std::cout << #index << ": " << #lower << " (" << #upper << ")" << std::endl;
 * HTTP_SERVER_METHOD_MAP(PRINT_METHOD)
 * @endcode
 */
#define HTTP_SERVER_METHOD_MAP(XX) \
  XX(0, del, DELETE)               \
  XX(1, get, GET)                 \
  XX(2, head, HEAD)               \
  XX(3, post, POST)               \
  XX(4, put, PUT)                 \
  /* pathological */                \
  XX(5, connect, CONNECT)         \
  XX(6, options, OPTIONS)         \
  XX(7, trace, TRACE)             \
  /* WebDAV */                      \
  /* RFC-5789 */                    \
  XX(28, patch, PATCH)

namespace std {
    /**
     * @brief Specialization of `std::hash` for `qb::http::method`.
     *
     * Allows `qb::http::method` to be used as a key in unordered STL containers.
     */
    template<>
    struct hash<qb::http::method> {
        /**
         * @brief Computes the hash value for a given HTTP method.
         * @param m The HTTP method.
         * @return The hash value.
         */
        [[nodiscard]] size_t operator()(qb::http::method const &m) const noexcept {
            return static_cast<size_t>(m);
        }
    };

    /**
     * @brief Specialization of `std::hash` for `qb::http::status`.
     *
     * Allows `qb::http::status` to be used as a key in unordered STL containers.
     */
    template<>
    struct hash<qb::http::status> {
        /**
         * @brief Computes the hash value for a given HTTP status code.
         * @param s The HTTP status code.
         * @return The hash value.
         */
        [[nodiscard]] size_t operator()(qb::http::status const &s) const noexcept {
            return static_cast<size_t>(s);
        }
    };

    /**
     * @brief Converts a `qb::http::method` enum to its string representation.
     * @param m The HTTP method.
     * @return A string representing the HTTP method (e.g., "GET", "POST").
     * @see http_method_name from `llhttp.h`
     */
    [[nodiscard]] inline std::string to_string(qb::http::method m) noexcept {
        return std::string(m);
    }

    /**
     * @brief Converts a `qb::http::status` enum to its string representation.
     * @param s The HTTP status code.
     * @return A string representing the HTTP status code (e.g., "OK", "Not Found").
     * @see http_status_name from `llhttp.h`
     */
    [[nodiscard]] inline std::string to_string(qb::http::status s) noexcept {
        // llhttp_status_name can return nullptr if the status is unknown
        // however, our status type is an enum, so it should always be valid.
        // Still, it's good practice to handle potential nullptrs from C libraries.
        const char *name = ::http_status_name(s);
        return name ? name : "Unknown Status";
    }
} // namespace std

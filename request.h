/**
 * @file qbm/http/request.h
 * @brief Defines the HTTP Request message class.
 *
 * This file contains the `Request` class, which represents an HTTP request.
 * It inherits from `internal::MessageBase` to include common HTTP message
 * properties like version, headers, and body, and adds request-specific
 * details such as the HTTP method, URI, and parsed cookies.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <string>
#include <vector>
#include <utility>

#include "./message_base.h"
#include "./cookie.h"
#include <qb/io/uri.h>
#include "./types.h"

namespace qb::http {
    template<typename Session>
    class Router;

    /**
     * @brief Represents an HTTP request message (owning `std::string` headers / body).
     *
     * Provides access to method, URI, headers, body and cookies. Inherits
     * common message properties from `internal::MessageBase`.
     */
    class Request : public internal::MessageBase {
    public:
        /** @brief Indicates that this message type is an HTTP request, used by parsers. */
        constexpr static http_type type = HTTP_REQUEST;

    private:
        /** @brief The HTTP method of the request (e.g., GET, POST). */
        Method _method;
        /** @brief The URI associated with the request. */
        qb::io::uri _uri;
        /** @brief A collection of cookies parsed from the `Cookie` header of the request. */
        CookieJar _cookies;

    public:
        /**
         * @brief Default constructor.
         *
         * Creates an empty HTTP request. The method defaults to `HTTP_GET`.
         * The URI, headers, body, and cookies are default-initialized (empty).
         * HTTP version defaults to 1.1 via `MessageBase`.
         */
        Request() noexcept
            : internal::MessageBase()
              , _method(Method::UNINITIALIZED)
              , _uri()
              , _cookies()
        {
            this->internal::MessageBase::reset();
        }

        /**
         * @brief Constructs an HTTP request with specified method, URI, headers, and body.
         * @param m The HTTP method for the request.
         * @param u The URI for the request (moved).
         * @param h A map of headers for the request (moved). Defaults to an empty map.
         * @param b The body content for the request (moved). Defaults to an empty body.
         */
        Request(qb::http::method m, qb::io::uri u,
                qb::icase_unordered_map<std::vector<std::string> > h = {},
                Body b = {})
            : internal::MessageBase(std::move(h), std::move(b))
              , _method(m)
              , _uri(std::move(u)) {
        }

        /**
         * @brief Constructs an HTTP GET request with specified URI, headers, and body.
         * @param u The URI for the request (moved).
         * @param h A map of headers for the request (moved). Defaults to an empty map.
         * @param b The body content for the request (moved). Defaults to an empty body.
         */
        explicit Request(qb::io::uri u,
                         qb::icase_unordered_map<std::vector<std::string> > h = {},
                         Body b = {})
            : internal::MessageBase(std::move(h), std::move(b))
              , _method(Method::GET)
              , _uri(std::move(u)) {
        }

        Request(const Request &) = default;

        Request(Request &&) noexcept = default;

        Request &operator=(const Request &) = default;

        Request &operator=(Request &&) noexcept = default;

        [[nodiscard]] const Method &method() const noexcept { return _method; }
        Method &method() noexcept { return _method; }

        /**
         * @brief Gets a constant reference to the request's URI.
         * @return `const qb::io::uri&` representing the URI.
         */
        [[nodiscard]] const qb::io::uri &
        uri() const noexcept {
            return _uri;
        }

        /**
         * @brief Gets a mutable reference to the request's URI.
         * @return `qb::io::uri&` allowing modification of the URI.
         */
        [[nodiscard]] qb::io::uri &
        uri() noexcept {
            return _uri;
        }

        /**
         * @brief Retrieves a specific query parameter value from the request's URI.
         *
         * If the query parameter has multiple values, `index` specifies which one to retrieve.
         * @tparam QueryNameType The type of the query parameter name (e.g., `const char*`, `std::string_view`).
         * @param name The name of the query parameter.
         * @param index The 0-based index for multi-value parameters. Defaults to 0.
         * @param not_found_value The string to return if the parameter is not found or index is out of bounds.
         * @return A constant reference to the query parameter's value if found; otherwise, `not_found_value`.
         */
        template<typename QueryNameType>
        [[nodiscard]] const std::string &
        query(QueryNameType &&name, std::size_t index = 0,
              const std::string &not_found_value = "") const noexcept {
            // Assumes _uri.query() is noexcept or handles exceptions appropriately to fit this noexcept.
            return _uri.query(std::forward<QueryNameType>(name), index, not_found_value);
        }

        /**
         * @brief Gets a mutable reference to the map of all query parameters in the URI.
         * @return A reference to the `qb::io::uri`'s internal query map.
         *         The exact type is `qb::icase_unordered_map<std::vector<std::string>>&`.
         */
        [[nodiscard]] auto &
        queries() noexcept {
            return _uri.queries();
        }

        /**
         * @brief Gets a constant reference to the map of all query parameters in the URI.
         * @return A constant reference to the `qb::io::uri`'s internal query map.
         */
        [[nodiscard]] const auto &
        queries() const noexcept {
            return _uri.queries();
        }

        /**
         * @brief Parses the `Cookie` header from the request and populates the internal `CookieJar`.
         *
         * This method should be called after headers are available (e.g., by a server
         * processing an incoming request). It clears any existing cookies in the jar
         * before parsing.
         * If the `Cookie` header is not present or empty, the cookie jar remains empty.
         * @throws std::runtime_error if `parse_cookies` encounters a parsing error.
         */
        void parse_cookie_header() {
            _cookies.clear();
            const std::string &cookie_header_value = this->header("Cookie", 0);
            if (cookie_header_value.empty()) {
                return;
            }
            auto cookies_map = parse_cookies(std::string_view(cookie_header_value), false);
            for (const auto &[name, value] : cookies_map) {
                _cookies.add(name, value);
            }
        }

        /**
         * @brief Retrieves a cookie by its name from the parsed request cookies.
         * @param name The name of the cookie (case-insensitive lookup).
         * @return A `const Cookie*` pointing to the cookie if found, otherwise `nullptr`.
         */
        [[nodiscard]] const Cookie *cookie(const std::string &name) const noexcept {
            return _cookies.get(name);
        }

        /**
         * @brief Retrieves the value of a cookie by its name.
         * @param name The name of the cookie (case-insensitive lookup).
         * @param default_value The value to return if the cookie is not found.
         * @return The cookie's value if found, otherwise `default_value`.
         */
        [[nodiscard]] std::string cookie_value(const std::string &name,
                                               const std::string &default_value = "") const noexcept {
            const Cookie *c = _cookies.get(name);
            return c ? c->value() : default_value;
        }

        /**
         * @brief Checks if a cookie with the given name exists in the request.
         * @param name The name of the cookie (case-insensitive lookup).
         * @return `true` if the cookie exists, `false` otherwise.
         */
        [[nodiscard]] bool has_cookie(const std::string &name) const noexcept {
            return _cookies.has(name);
        }

        /**
         * @brief Gets a constant reference to the `CookieJar` containing all parsed request cookies.
         * @return `const CookieJar&`.
         */
        [[nodiscard]] const CookieJar &cookies() const noexcept {
            return _cookies;
        }

        /**
         * @brief Gets a mutable reference to the `CookieJar` associated with this request.
         * Allows direct manipulation of the cookie collection.
         * @return `CookieJar&`.
         */
        [[nodiscard]] CookieJar &cookies() noexcept {
            return _cookies;
        }

        /**
         * @brief Resets the request object to a default state.
         *
         * - Sets the HTTP method to `GET`.
         * - Clears the URI (to an empty/default state).
         * - Clears all parsed cookies from the internal `CookieJar`.
         * - Calls the `reset()` method of the `MessageBase` base class, which
         *   clears all headers and resets the Content-Type to its default.
         * The body content is not cleared by `MessageBase::reset()` itself but would be
         * by `Body::clear()` if called directly on the body.
         * The HTTP version and upgrade flag in `MessageBase` are not modified by this reset.
         */
        void
        reset() noexcept {
            _method = Method::GET;
            _uri = qb::io::uri{};
            _cookies.clear();
            this->internal::MessageBase::reset();
        }

        /**
         * @brief Sets the HTTP method for the request.
         * @param m The HTTP method to set.
         * @return A reference to the request object.
         *
         * @note Only `with_method` is truly non-throwing; the other
         * `with_*` setters allocate (URI / headers / cookies / body) and
         * therefore cannot be `noexcept` without risking
         * `std::terminate` on allocation failure.
         */
        Request &with_method(Method m) noexcept {
            _method = m;
            return *this;
        }

        /**
         * @brief Sets the URI for the request.
         * @param u The URI to set.
         * @return A reference to the request object.
         */
        Request &with_uri(qb::io::uri u) {
            _uri = std::move(u);
            return *this;
        }

        /**
         * @brief Adds a header to the request.
         * @param name The name of the header.
         * @param value The value of the header.
         * @return A reference to the request object.
         */
        Request &with_header(std::string name, std::string value) {
            this->add_header(std::move(name), std::move(value));
            return *this;
        }

        /**
         * @brief Sets the headers for the request.
         * @param h The headers to set.
         * @return A reference to the request object.
         */
        Request &with_headers(qb::icase_unordered_map<std::vector<std::string> > h) {
            this->headers() = std::move(h);
            return *this;
        }

        /**
         * @brief Adds a cookie to the request.
         * @param c The cookie to add.
         * @return A reference to the request object.
         */
        Request &with_cookie(const Cookie &c) {
            _cookies.add(c);
            return *this;
        }

        /**
         * @brief Sets the cookies for the request.
         * @param cookies The cookies to set.
         * @return A reference to the request object.
         */
        Request &with_cookies(const CookieJar &cookies) {
            _cookies = cookies;
            return *this;
        }

        /**
         * @brief Sets the body for the request.
         * @param b The body to set.
         * @return A reference to the request object.
         */
        template<typename BodyType>
        Request &with_body(BodyType &&b) {
            this->body() = std::forward<BodyType>(b);
            return *this;
        }

        /**
         * @brief Using-declaration for `qb::http::Router` template.
         *
         * This declaration makes the `qb::http::Router<Session>` template accessible
         * as `Request::Router<Session>` within contexts where `Request` is known.
         * It does not define a nested Router class but rather aliases the external one.
         */
        template<typename Session>
        using Router = qb::http::Router<Session>;
    };

    /** @brief Shorthand alias for `Request`. */
    using request = Request;
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
     * @throws std::length_error if the message exceeds qb::http::protocol_limits.
     */
    template<>
    pipe<char> &pipe<char>::put<qb::http::Request>(const qb::http::Request &r);
} // namespace qb::allocator

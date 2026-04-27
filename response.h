/**
 * @file qbm/http/response.h
 * @brief Defines the HTTP Response message class.
 *
 * This file contains the `Response` class, representing an HTTP response.
 * It inherits from `internal::MessageBase` for common message properties
 * and adds response-specific details like status code, reason phrase, and
 * methods for managing `Set-Cookie` headers via an internal `CookieJar`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <algorithm>
#include <utility>

#include "./message_base.h"
#include "./cookie.h"
#include "./types.h"

namespace qb::http {
    /**
     * @brief Represents an HTTP response message (owning `std::string` headers / body).
     *
     * Provides access to status, headers, body and a `CookieJar` whose
     * entries are serialised to `Set-Cookie` headers. Inherits common
     * message properties from `internal::MessageBase`.
     */
    class Response : public internal::MessageBase {
    public:
        /** @brief Indicates that this message type is an HTTP response, used by parsers. */
        constexpr static http_type type = HTTP_RESPONSE;
    private:
        /** @brief The HTTP status code of the response (e.g., 200, 404). */
        Status _status;
        /** @brief A collection of cookies to be sent with this response via `Set-Cookie` headers. */
        CookieJar _cookies;

    public:
        /**
         * @brief Default constructor.
         *
         * Initializes an HTTP response with a status code of `200 OK`.
         * The reason phrase (`status`) is initially empty (it will typically be set by
         * the server or inferred from `status_code` during serialization).
         * The cookie jar is empty. HTTP version defaults to 1.1 via `MessageBase`.
         */
        Response() noexcept
            : internal::MessageBase()
              , _status(Status::OK)
              , _cookies()
        {
            this->internal::MessageBase::reset();
        }

        Response(Status s,
                 qb::icase_unordered_map<std::vector<std::string> > h = {},
                 Body b = {})
            : internal::MessageBase(std::move(h), std::move(b))
            , _status(s)
        {}

        Response(const Response &) = default;

        Response(Response &&) noexcept = default;
        Response &operator=(const Response &) = default;

        Response &operator=(Response &&) noexcept = default;

        [[nodiscard]] const Status &status() const noexcept { return _status; }
        Status &status() noexcept { return _status; }

        /**
         * @brief Resets the response to a default state.
         *
         * - Sets the `status_code` to `200 OK`.
         * - Clears the `status` (reason phrase) string.
         * - Clears all cookies from the internal `CookieJar`.
         * - Calls `MessageBase::reset()`, which clears all headers and resets Content-Type.
         * The HTTP version and upgrade flag in `MessageBase` are not modified.
         */
        void
        reset() noexcept {
            _status = Status::OK;
            _cookies.clear();
            this->internal::MessageBase::reset();
        }

        /**
         * @brief Parses `Set-Cookie` headers present in `this->_headers` and populates the internal `CookieJar`.
         *
         * This method is useful if a `Response` object is populated from an existing set of raw headers
         * that might already contain `Set-Cookie` directives (e.g., when proxying or modifying a response).
         * It clears the internal `_cookies` jar before parsing.
         * @note This can throw if `parse_set_cookie` or `CookieJar::add` throws.
         */
        void parse_set_cookie_headers() {
            _cookies.clear();
            const auto &set_cookie_iter = this->_headers.find("Set-Cookie");
            if (set_cookie_iter == this->_headers.end()) {
                return;
            }
            for (const std::string &header_value_str : set_cookie_iter->second) {
                if (auto cookie_opt = parse_set_cookie(std::string_view(header_value_str))) {
                    _cookies.add(std::move(*cookie_opt));
                }
            }
        }

        /**
         * @brief Adds a cookie to be sent with the response.
         *
         * This method adds the cookie to the internal `CookieJar` and also appends a corresponding
         * `Set-Cookie` header string to `this->_headers`.
         * @param cookie The `Cookie` object to add (copied).
         */
        void add_cookie(const Cookie &cookie) {
            _cookies.add(cookie); // Adds or replaces in jar
            // Add the serialized cookie to the actual headers
            this->add_header("Set-Cookie", cookie.to_header());
        }

        /**
         * @brief Adds a cookie to be sent with the response using move semantics.
         * @param cookie The `Cookie` object to add (moved).
         */
        void add_cookie(Cookie &&cookie) {
            std::string header_value = cookie.to_header(); // Generate header before moving name/value from cookie
            _cookies.add(std::move(cookie)); // Add to jar
            this->add_header("Set-Cookie", std::move(header_value)); // Add to headers
        }

        /**
         * @brief Creates a new cookie with the given name and value, and adds it to the response.
         * @param name The name of the cookie. Copied.
         * @param value The value of the cookie. Copied.
         * @return A mutable reference to the newly created `Cookie` object within the `CookieJar`,
         *         allowing further modification of its attributes (e.g., path, domain, expires).
         *         Remember to call `update_cookie_header()` or `update_cookie_headers()` if you modify it further.
         */
        Cookie &add_cookie(const std::string &name, const std::string &value) {
            // Add to jar first to get a stable reference to the Cookie object
            Cookie &new_cookie_in_jar = _cookies.add(name, value);
            this->add_header("Set-Cookie", new_cookie_in_jar.to_header());
            return new_cookie_in_jar;
        }

        /**
         * @brief Instructs the client to remove a cookie by its name.
         *
         * This is achieved by sending a `Set-Cookie` header for the given `name`
         * with an expiration date in the past and Max-Age of 0.
         * @param name The name of the cookie to remove.
         */
        /** Offset used by `remove_cookie()` to force immediate expiry. */
        static constexpr int EXPIRED_COOKIE_OFFSET_SECONDS = -86400; // one day in the past
        /** `Max-Age` value used by `remove_cookie()`. */
        static constexpr int EXPIRED_COOKIE_MAX_AGE = 0;

        void remove_cookie(const std::string &name) {
            Cookie removal_cookie(name, "");
            removal_cookie.expires_in(EXPIRED_COOKIE_OFFSET_SECONDS);
            removal_cookie.max_age(EXPIRED_COOKIE_MAX_AGE);
            add_cookie(std::move(removal_cookie));
        }

        /**
         * @brief Instructs the client to remove a cookie by name, considering its domain and path.
         * To effectively remove a cookie, the `Domain` and `Path` attributes in the `Set-Cookie`
         * header must match those of the cookie to be removed.
         * @param name The name of the cookie.
         * @param domain The domain of the cookie to remove.
         * @param path The path of the cookie to remove. Defaults to "/".
         */
        void remove_cookie(const std::string &name, const std::string &domain, const std::string &path = "/") {
            Cookie removal_cookie(name, "");
            removal_cookie.expires_in(EXPIRED_COOKIE_OFFSET_SECONDS);
            removal_cookie.max_age(EXPIRED_COOKIE_MAX_AGE);
            removal_cookie.domain(domain);
            removal_cookie.path(path);
            add_cookie(std::move(removal_cookie));
        }

        /**
         * @brief Retrieves a constant pointer to a cookie intended to be set by this response.
         * @param name The name of the cookie (case-insensitive lookup in the internal `CookieJar`).
         * @return A `const Cookie*` if a cookie with that name is scheduled to be set, otherwise `nullptr`.
         */
        [[nodiscard]] const Cookie *cookie(const std::string &name) const noexcept {
            return _cookies.get(name);
        }

        /**
         * @brief Retrieves a mutable pointer to a cookie intended to be set by this response.
         *
         * Allows modification of a cookie's attributes after it has been added.
         * @param name The name of the cookie (case-insensitive lookup).
         * @return A `Cookie*` if found, otherwise `nullptr`.
         * @warning If you modify the `Cookie` object obtained via this pointer, you **must** call
         *          `update_cookie_header(name)` or `update_cookie_headers()` afterwards to ensure
         *          the `Set-Cookie` headers in the response are updated to reflect the changes.
         */
        [[nodiscard]] Cookie *cookie(const std::string &name) noexcept {
            return _cookies.get(name);
        }

        /**
         * @brief Updates the `Set-Cookie` header for a specific cookie after it has been modified.
         *
         * If a cookie was retrieved using the non-const `cookie(name)` method and then modified,
         * this function should be called with the cookie's name to regenerate its corresponding
         * `Set-Cookie` header string in `this->_headers`. It removes old header entries for this
         * cookie name and adds the new one.
         * @param name The name of the cookie whose `Set-Cookie` header needs to be updated.
         */
        void update_cookie_header(const std::string &name) {
            Cookie *modified_cookie = _cookies.get(name);
            if (!modified_cookie) {
                return;
            }
            auto &set_cookie_headers = this->_headers["Set-Cookie"];
            const std::string prefix_to_find = name + "=";
            set_cookie_headers.erase(
                std::remove_if(set_cookie_headers.begin(), set_cookie_headers.end(),
                               [&](const std::string &header_val) {
                                   return std::string_view(header_val).starts_with(prefix_to_find);
                               }),
                set_cookie_headers.end()
            );
            this->add_header("Set-Cookie", modified_cookie->to_header());
        }

        /**
         * @brief Checks if a cookie with the given name is scheduled to be set by this response.
         * @param name The name of the cookie (case-insensitive lookup).
         * @return `true` if the cookie exists in the internal `CookieJar`, `false` otherwise.
         */
        [[nodiscard]] bool has_cookie(const std::string &name) const noexcept {
            return _cookies.has(name);
        }

        /**
         * @brief Gets a constant reference to the `CookieJar` containing all cookies to be set.
         * @return `const CookieJar&`.
         */
        [[nodiscard]] const CookieJar &cookies() const noexcept {
            return _cookies;
        }

        /**
         * @brief Gets a mutable reference to the `CookieJar` associated with this response.
         *
         * Allows direct manipulation of the cookies to be set.
         * @return `CookieJar&`.
         * @warning If you modify the `CookieJar` directly (e.g., adding/removing cookies),
         *          you **must** call `update_cookie_headers()` afterwards to synchronize these
         *          changes with the actual `Set-Cookie` headers in the response.
         */
        [[nodiscard]] CookieJar &cookies() noexcept {
            return _cookies;
        }

        /**
         * @brief Rebuilds all `Set-Cookie` headers from the current state of the internal `CookieJar`.
         *
         * This method should be called if cookies were added, removed, or modified directly
         * through the `CookieJar` reference obtained from `cookies()` (non-const version),
         * to ensure the raw `Set-Cookie` headers in `this->_headers` are synchronized.
         * It clears all existing `Set-Cookie` headers and re-adds them based on the jar.
         */
        void update_cookie_headers() {
            this->_headers.erase("Set-Cookie"); // Remove all current Set-Cookie headers
            for (const auto &pair: _cookies.all()) {
                this->add_header("Set-Cookie", pair.second.to_header());
            }
        }

        /**
         * @brief Sets the HTTP status for the response.
         * @param s The HTTP status to set.
         * @return A reference to the response object.
         *
         * @note Only `with_status` is genuinely non-throwing; the other
         * `with_*` methods previously claimed `noexcept` although their
         * bodies performed allocations (`add_header`, `CookieJar::add`,
         * body assignment). `std::bad_alloc` would therefore have
         * triggered `std::terminate`. `noexcept` is now reserved for
         * operations that are actually non-throwing.
         */
        Response &with_status(Status s) noexcept {
            _status = s;
            return *this;
        }

        /**
         * @brief Adds a cookie to the response (same wire semantics as add_cookie()).
         * @param c The cookie to add.
         * @return A reference to the response object.
         */
        Response &with_cookie(const Cookie &c) {
            add_cookie(c);
            return *this;
        }

        /**
         * @brief Replaces the response cookie jar and synchronises all Set-Cookie headers.
         * @param cookies The cookies to set.
         * @return A reference to the response object.
         */
        Response &with_cookies(const CookieJar &cookies) {
            _cookies = cookies;
            update_cookie_headers();
            return *this;
        }

        /**
         * @brief Adds a header to the response.
         * @param name The name of the header.
         * @param value The value of the header.
         * @return A reference to the response object.
         */
        Response &with_header(std::string name, std::string value) {
            this->add_header(std::move(name), std::move(value));
            return *this;
        }

        /**
         * @brief Sets the headers for the response.
         * @param h The headers to set.
         * @return A reference to the response object.
         */
        Response &with_headers(qb::icase_unordered_map<std::vector<std::string> > h) {
            this->headers() = std::move(h);
            return *this;
        }

        /**
         * @brief Sets the body for the response.
         * @param b The body to set.
         * @return A reference to the response object.
         */
        template<typename BodyType>
        Response &with_body(BodyType &&b) {
            this->body() = std::forward<BodyType>(b);
            return *this;
        }
    };

    /** @brief Shorthand alias for `Response`. */
    using response = Response;
} // namespace qb::http

namespace qb::allocator {
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
     * @throws std::length_error if the message exceeds qb::http::protocol_limits
     *         (oversized body, headers, or estimated wire size).
     */
    template<>
    pipe<char> &pipe<char>::put<qb::http::Response>(const qb::http::Response &r);
} // namespace qb::allocator
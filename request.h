/**
 * @file qbm/http/request.h
 * @brief Defines the HTTP Request message class.
 *
 * This file contains the `TRequest` template class, which represents an HTTP request.
 * It inherits from `MessageBase` to include common HTTP message properties like
 * version, headers, and body, and adds request-specific details such as the
 * HTTP method, URI, and parsed cookies.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <string>       // For std::string (used in TRequest members if String is std::string)
#include <vector>       // For std::vector (used in TRequest members if String is std::string)
#include <utility>      // For std::move, std::forward

#include "./message_base.h" // For internal::MessageBase
#include "./cookie.h"       // For CookieJar, parse_cookies
#include <qb/io/uri.h>      // For qb::io::uri
#include "./types.h"        // For qb::http::method, HTTP_REQUEST (via llhttp.h)

namespace qb::http {

// Forward declaration for the Router class, if it were to be a friend or closely related.
// However, the `using Router = Router<Session>` below is a using-declaration for a template.
// If `qb::http::Router` is a distinct class template, this forward declaration is fine.
// If `TRequest::Router` is meant to be a nested class, it would be defined inside TRequest.
// Based on context of routing.h, Router is likely a standalone class template.
template <typename Session> class Router;

/**
 * @brief Represents an HTTP request message.
 *
 * This class template models an HTTP request, providing access to its method, URI,
 * headers, body, and cookies. It inherits common message properties from `MessageBase`.
 * The `String` template parameter allows flexibility in the underlying string type used for headers.
 *
 * @tparam String The string type used for headers (e.g., `std::string`, `std::string_view`).
 */
template <typename String>
struct TRequest : public internal::MessageBase<String> {
    /** @brief Indicates that this message type is an HTTP request, used by parsers. */
    constexpr static http_type type = HTTP_REQUEST;
    /** @brief The HTTP method of the request (e.g., GET, POST). */
    Method _method;
    /** @brief The URI associated with the request. */
    qb::io::uri _uri;
    /** @brief A collection of cookies parsed from the `Cookie` header of the request. */
    CookieJar   _cookies;

public:
    /**
     * @brief Default constructor.
     *
     * Creates an empty HTTP request. The method defaults to `HTTP_GET`.
     * The URI, headers, body, and cookies are default-initialized (empty).
     * HTTP version defaults to 1.1 via `MessageBase`.
     */
    TRequest() noexcept
        : internal::MessageBase<String>() // Ensure MessageBase default constructor is called
        , _method(Method::UNINITIALIZED)
        , _uri() // Default construct URI
        , _cookies() // Default construct CookieJar
    {
        this->internal::MessageBase<String>::reset(); // Resets headers and content_type in MessageBase
    }

    /**
     * @brief Constructs an HTTP request with specified method, URI, headers, and body.
     * @param m The HTTP method for the request.
     * @param u The URI for the request (moved).
     * @param h A map of headers for the request (moved). Defaults to an empty map.
     * @param b The body content for the request (moved). Defaults to an empty body.
     */
    TRequest(qb::http::method m, qb::io::uri u,
             qb::icase_unordered_map<std::vector<String>> h = {},
             Body b = {})
        : internal::MessageBase<String>(std::move(h), std::move(b))
        , _method(m)
        , _uri(std::move(u)) {
        // Cookies would be parsed separately if this constructor is used for incoming requests.
    }

    /**
     * @brief Constructs an HTTP GET request with specified URI, headers, and body.
     * @param u The URI for the request (moved).
     * @param h A map of headers for the request (moved). Defaults to an empty map.
     * @param b The body content for the request (moved). Defaults to an empty body.
     */
    explicit TRequest(qb::io::uri u,
                      qb::icase_unordered_map<std::vector<String>> h = {},
                      Body b = {})
        : internal::MessageBase<String>(std::move(h), std::move(b))
        , _method(Method::GET)
        , _uri(std::move(u)) {}

    // Defaulted copy/move constructors and assignment operators
    TRequest(const TRequest&) = default;
    TRequest(TRequest&&) noexcept = default;
    TRequest& operator=(const TRequest&) = default;
    TRequest& operator=(TRequest&&) noexcept = default;

    const Method &method() const noexcept { return _method; }
    Method &method() noexcept { return _method; }

    /**
     * @brief Gets a constant reference to the request's URI.
     * @return `const qb::io::uri&` representing the URI.
     */
    [[nodiscard]] const qb::io::uri&
    uri() const noexcept {
        return _uri;
    }

    /**
     * @brief Gets a mutable reference to the request's URI.
     * @return `qb::io::uri&` allowing modification of the URI.
     */
    [[nodiscard]] qb::io::uri&
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
    template <typename QueryNameType>
    [[nodiscard]] const std::string&
    query(QueryNameType&& name, std::size_t index = 0,
          const std::string& not_found_value = "") const noexcept {
        // Assumes _uri.query() is noexcept or handles exceptions appropriately to fit this noexcept.
        return _uri.query(std::forward<QueryNameType>(name), index, not_found_value);
    }

    /**
     * @brief Gets a mutable reference to the map of all query parameters in the URI.
     * @return A reference to the `qb::io::uri`'s internal query map.
     *         The exact type is `qb::icase_unordered_map<std::vector<std::string>>&`.
     */
    [[nodiscard]] auto&
    queries() noexcept {
        return _uri.queries();
    }

    /**
     * @brief Gets a constant reference to the map of all query parameters in the URI.
     * @return A constant reference to the `qb::io::uri`'s internal query map.
     */
    [[nodiscard]] const auto&
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
        // Use this->header to access headers from MessageBase/THeaders
        const String& cookie_header_value = this->header("Cookie", 0, String{});
        
        if (!cookie_header_value.empty()) {
            // parse_cookies expects std::string_view or const char*, String might need conversion.
            std::string_view cookie_header_sv;
            if constexpr (std::is_convertible_v<const String&, std::string_view>) {
                cookie_header_sv = cookie_header_value;
            } else {
                // If String is not convertible (e.g. custom string type), this path needs handling.
                // Assuming String is std::string or std::string_view for now.
                // This part might need adjustment if String is more complex.
                static_assert(std::is_same_v<String, std::string> || std::is_same_v<String, std::string_view>,
                              "TRequest::parse_cookie_header expects String to be std::string or std::string_view or convertible for parse_cookies.");
                // If it's std::string, it's convertible. If it's string_view, it's direct.
                cookie_header_sv = std::string_view(cookie_header_value.data(), cookie_header_value.length());
            }

            if (!cookie_header_sv.empty()) {
                auto cookies_map = parse_cookies(cookie_header_sv, false); // false for parsing "Cookie" header
                for (const auto& [name, value] : cookies_map) {
                    _cookies.add(name, value); // CookieJar::add handles name case-insensitivity
                }
            }
        }
    }

    /**
     * @brief Retrieves a cookie by its name from the parsed request cookies.
     * @param name The name of the cookie (case-insensitive lookup).
     * @return A `const Cookie*` pointing to the cookie if found, otherwise `nullptr`.
     */
    [[nodiscard]] const Cookie* cookie(const std::string& name) const noexcept {
        return _cookies.get(name);
    }

    /**
     * @brief Retrieves the value of a cookie by its name.
     * @param name The name of the cookie (case-insensitive lookup).
     * @param default_value The value to return if the cookie is not found.
     * @return The cookie's value if found, otherwise `default_value`.
     */
    [[nodiscard]] std::string cookie_value(const std::string& name,
                                           const std::string& default_value = "") const noexcept {
        const Cookie* c = _cookies.get(name);
        return c ? c->value() : default_value;
    }

    /**
     * @brief Checks if a cookie with the given name exists in the request.
     * @param name The name of the cookie (case-insensitive lookup).
     * @return `true` if the cookie exists, `false` otherwise.
     */
    [[nodiscard]] bool has_cookie(const std::string& name) const noexcept {
        return _cookies.has(name);
    }

    /**
     * @brief Gets a constant reference to the `CookieJar` containing all parsed request cookies.
     * @return `const CookieJar&`.
     */
    [[nodiscard]] const CookieJar& cookies() const noexcept {
        return _cookies;
    }

    /**
     * @brief Gets a mutable reference to the `CookieJar` associated with this request.
     * Allows direct manipulation of the cookie collection.
     * @return `CookieJar&`.
     */
    [[nodiscard]] CookieJar& cookies() noexcept {
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
        _uri   = qb::io::uri{}; // Reset URI to default
        _cookies.clear();       // Clear all cookies
        this->internal::MessageBase<String>::reset(); // Reset headers and Content-Type in base
    }

    /**
     * @brief Sets the HTTP method for the request.
     * @param m The HTTP method to set.
     * @return A reference to the request object.
     */
    TRequest &with_method(Method m) noexcept {
        _method = m;
        return *this;
    }

    /**
     * @brief Sets the URI for the request.
     * @param u The URI to set.
     * @return A reference to the request object.
     */
    TRequest &with_uri(qb::io::uri u) noexcept {
        _uri = std::move(u);
        return *this;
    }

    /**
     * @brief Adds a header to the request.
     * @param name The name of the header.
     * @param value The value of the header.
     * @return A reference to the request object.
     */
    TRequest &with_header(std::string name, std::string value) noexcept {
        this->add_header(std::move(name), std::move(value));
        return *this;
    }

    /**
     * @brief Sets the headers for the request.
     * @param h The headers to set.
     * @return A reference to the request object.
     */
    TRequest &with_headers(qb::icase_unordered_map<std::vector<String>> h) noexcept {
        this->headers() = std::move(h);
        return *this;
    }

    /**
     * @brief Adds a cookie to the request.
     * @param c The cookie to add.
     * @return A reference to the request object.
     */
    TRequest &with_cookie(const Cookie &c) noexcept {
        _cookies.add(c);
        return *this;
    }

    /**
     * @brief Sets the cookies for the request.
     * @param cookies The cookies to set.
     * @return A reference to the request object.
     */
    TRequest &with_cookies(const CookieJar &cookies) noexcept {
        _cookies = cookies;
        return *this;
    }

    /**
     * @brief Sets the body for the request.
     * @param b The body to set.
     * @return A reference to the request object.
     */
    template <typename BodyType>
    TRequest &with_body(BodyType &&b) noexcept {
        this->body()= std::forward<BodyType>(b);
        return *this;
    }

    /**
     * @brief Using-declaration for `qb::http::Router` template.
     *
     * This declaration makes the `qb::http::Router<Session>` template accessible
     * as `TRequest::Router<Session>` within contexts where `TRequest` is known.
     * It does not define a nested Router class but rather aliases the external one.
     */
    template <typename Session>
    using Router = qb::http::Router<Session>;
};

/** @brief Convenience alias for `TRequest<std::string>`, representing a request with mutable string headers. */
using Request      = TRequest<std::string>;
/** @brief Shorthand alias for `Request`. */
using request      = Request;
/** @brief Convenience alias for `TRequest<std::string_view>`, representing a request with immutable string_view headers. */
using RequestView  = TRequest<std::string_view>;
/** @brief Shorthand alias for `RequestView`. */
using request_view = RequestView;

} // namespace qb::http
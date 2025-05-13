#pragma once

#include "./message_base.h"
#include "./cookie.h"

namespace qb::http {
/**
 * @brief HTTP response message template
 * @tparam String String type used for storage (std::string or std::string_view)
 *
 * Represents an HTTP response message with status code, reason phrase, headers, and
 * body. This template class can use either std::string or std::string_view as the
 * underlying storage type, allowing for efficient memory management depending
 * on the use case:
 *
 * - std::string for mutable responses that may be modified
 * - std::string_view for immutable responses that are processed once
 *
 * The class provides comprehensive functionality for HTTP response handling:
 * - Status code and reason phrase management
 * - Header manipulation with case-insensitive keys
 * - Protocol version control
 * - Content type handling with charset management
 * - Flexible body content manipulation
 *
 * It also implements a Router system for status code-based response handling,
 * allowing for customized responses to different HTTP status codes.
 */
template <typename String>
struct TResponse : public internal::MessageBase<String> {
    constexpr static const http_type_t type = HTTP_RESPONSE;
    http_status                        status_code;
    String                             status;
    CookieJar                          _cookies;

    TResponse() noexcept
        : status_code(HTTP_STATUS_OK) {}
    TResponse(TResponse const &) = default;
    TResponse(TResponse &&)      = default;
    TResponse &operator=(TResponse const &) = default;
    TResponse &operator=(TResponse &&)      = default;

    void
    reset() {
        status_code = HTTP_STATUS_OK;
        status      = {};
        _cookies.clear();
        static_cast<internal::MessageBase<String> &>(*this).reset();
    }

    /**
     * @brief Parse cookies from Set-Cookie headers
     * 
     * Extracts cookies from Set-Cookie headers and makes them
     * available through the cookie management functions.
     * This is automatically called when a response is received.
     */
    void parse_set_cookie_headers() {
        _cookies.clear();
        const auto& set_cookie_it = this->_headers.find("Set-Cookie");
        if (set_cookie_it != this->_headers.end()) {
            for (const auto& header_value : set_cookie_it->second) {
                auto cookie = parse_set_cookie(header_value);
                if (cookie) {
                    _cookies.add(std::move(*cookie));
                }
            }
        }
    }

    /**
     * @brief Add a cookie to the response
     * @param cookie Cookie to add
     * 
     * Adds a cookie to the response, which will be included in
     * the Set-Cookie headers when the response is sent.
     */
    void add_cookie(const Cookie& cookie) {
        _cookies.add(cookie);
        this->add_header("Set-Cookie", cookie.to_header());
    }

    /**
     * @brief Add a cookie to the response
     * @param cookie Cookie to add
     * 
     * Move version of add_cookie that takes ownership of the cookie.
     */
    void add_cookie(Cookie&& cookie) {
        std::string header_value = cookie.to_header();
        _cookies.add(std::move(cookie));
        this->add_header("Set-Cookie", std::move(header_value));
    }

    /**
     * @brief Create and add a new cookie
     * @param name Cookie name
     * @param value Cookie value
     * @return Reference to the created cookie
     * 
     * Creates a new cookie with the given name and value, adds it
     * to the response, and returns a reference to it for further
     * configuration.
     */
    Cookie& add_cookie(std::string name, std::string value) {
        Cookie& cookie = _cookies.add(name, value);
        this->add_header("Set-Cookie", cookie.to_header());
        return cookie;
    }

    /**
     * @brief Remove a cookie
     * @param name Cookie name
     * 
     * Creates an empty, expired cookie with the same name, effectively
     * instructing the client to remove the cookie.
     */
    void remove_cookie(const std::string& name) {
        Cookie cookie(name, "");
        cookie.expires_in(-1); // Expire immediately
        cookie.max_age(0);     // Alternative expiration method
        add_cookie(cookie);
    }

    /**
     * @brief Remove a cookie with specific domain and path
     * @param name Cookie name
     * @param domain Cookie domain
     * @param path Cookie path
     * 
     * Creates an empty, expired cookie with the same name, domain, and path,
     * effectively instructing the client to remove the specific cookie.
     */
    void remove_cookie(const std::string& name, const std::string& domain, const std::string& path = "/") {
        Cookie cookie(name, "");
        cookie.expires_in(-1); // Expire immediately
        cookie.max_age(0);     // Alternative expiration method
        cookie.domain(domain);
        cookie.path(path);
        add_cookie(cookie);
    }

    /**
     * @brief Get a cookie from the response
     * @param name Cookie name
     * @return Pointer to the cookie, or nullptr if not found
     */
    [[nodiscard]] const Cookie* cookie(const std::string& name) const {
        return _cookies.get(name);
    }

    /**
     * @brief Get a cookie from the response (mutable)
     * @param name Cookie name
     * @return Pointer to the cookie, or nullptr if not found
     * 
     * Returns a mutable pointer to a cookie, allowing modification.
     * Note: After modifying a cookie, you must call update_cookie_header
     * to reflect those changes in the response headers.
     */
    [[nodiscard]] Cookie* cookie(const std::string& name) {
        return _cookies.get(name);
    }

    /**
     * @brief Update a cookie's header after modification
     * @param name Cookie name
     * 
     * After manually modifying a cookie using a non-const cookie pointer,
     * call this method to update the corresponding Set-Cookie header.
     */
    void update_cookie_header(const std::string& name) {
        Cookie* cookie = _cookies.get(name);
        if (cookie) {
            // Remove existing header with this cookie name (if any)
            // This is an expensive operation, could be optimized with direct header access
            auto& headers = this->_headers["Set-Cookie"];
            auto it = std::remove_if(headers.begin(), headers.end(), 
                [&name](const String& header) {
                    return header.find(name + "=") == 0;
                });
            if (it != headers.end()) {
                headers.erase(it, headers.end());
            }
            
            // Add the updated header
            this->add_header("Set-Cookie", cookie->to_header());
        }
    }

    /**
     * @brief Check if a cookie exists
     * @param name Cookie name
     * @return true if the cookie exists
     */
    [[nodiscard]] bool has_cookie(const std::string& name) const {
        return _cookies.has(name);
    }

    /**
     * @brief Get all cookies
     * @return Reference to the cookie jar
     */
    [[nodiscard]] const CookieJar& cookies() const {
        return _cookies;
    }

    /**
     * @brief Get the cookie jar (mutable)
     * @return Mutable reference to the cookie jar
     * 
     * Note: After modifying cookies through this reference,
     * you should call update_cookie_headers to ensure the
     * changes are reflected in the response headers.
     */
    CookieJar& cookies() {
        return _cookies;
    }

    /**
     * @brief Update all cookie headers
     * 
     * Updates all Set-Cookie headers to match the cookies in the cookie jar.
     * Use this after making bulk changes to cookies through the cookie jar.
     */
    void update_cookie_headers() {
        // Remove all existing Set-Cookie headers
        this->_headers.erase("Set-Cookie");
        
        // Add headers for each cookie
        for (const auto& pair : _cookies.all()) {
            this->add_header("Set-Cookie", pair.second.to_header());
        }
    }
};

using Response      = TResponse<std::string>;
using response      = TResponse<std::string>;
using ResponseView  = TResponse<std::string_view>;
using response_view = TResponse<std::string_view>;

} // namespace qb::http
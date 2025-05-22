/**
 * @file qbm/http/cookie.h
 * @brief Defines classes and functions for HTTP cookie management.
 *
 * This file provides the `Cookie` class to represent individual HTTP cookies with their
 * attributes (name, value, domain, path, expires, etc.), the `CookieJar` class for
 * managing collections of cookies, and utility functions for parsing `Cookie` and
 * `Set-Cookie` headers according to RFC 6265.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <qb/system/container/unordered_map.h>
#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include "./utility.h"

namespace qb::http {

/**
 * @brief Maximum length for cookie names in bytes
 *
 * Defines the maximum allowed length for cookie names to prevent
 * buffer overflow attacks and ensure efficient memory usage.
 */
constexpr const uint32_t COOKIE_NAME_MAX = 1024; // 1 KB

/**
 * @brief Maximum length for cookie values in bytes
 *
 * Defines the maximum allowed length for cookie values to prevent
 * buffer overflow attacks and ensure efficient memory usage.
 */
constexpr const uint32_t COOKIE_VALUE_MAX = 1024 * 1024; // 1 MB

/**
 * @brief Cookie SameSite policy enum
 * 
 * Defines the possible values for the SameSite attribute of a cookie
 * according to RFC 6265bis.
 */
enum class SameSite {
    None,
    Lax,
    Strict,
    NOT_SET
};

/**
 * @brief Individual HTTP cookie with attributes
 *
 * Represents a single HTTP cookie with name, value, and all standard attributes
 * including expiration, path, domain, security flags, and SameSite policy.
 * Fully compliant with RFC 6265bis.
 */
class Cookie {
private:
    std::string _name;
    std::string _value;
    std::optional<std::chrono::system_clock::time_point> _expires;
    std::optional<int> _max_age;
    std::string _domain;
    std::string _path;
    bool _secure = false;
    bool _http_only = false;
    std::optional<SameSite> _same_site;

public:
    /**
     * @brief Default constructor. Creates an empty Cookie object.
     * Path defaults to "/", secure and http_only to false, SameSite is not set.
     */
    Cookie() noexcept : _path("/"), _secure(false), _http_only(false), _same_site(std::nullopt) {}

    /**
     * @brief Constructs a Cookie with a name and value.
     * Other attributes default as per the default constructor (e.g., path="/", secure=false).
     * @param name The name of the cookie. Copied.
     * @param value The value of the cookie. Copied.
     * @note Definition is in `cookie.cpp`.
     */
    Cookie(const std::string& name, const std::string& value);

    /**
     * @brief Constructs a Cookie with a name and value using move semantics.
     * @param name The name of the cookie. Moved.
     * @param value The value of the cookie. Moved.
     */
    Cookie(std::string&& name, std::string&& value) noexcept;

    // Defaulted copy/move constructors and assignment operators
    Cookie(const Cookie&) = default;
    Cookie(Cookie&&) noexcept = default;
    Cookie& operator=(const Cookie&) = default;
    Cookie& operator=(Cookie&&) noexcept = default;

    /**
     * @brief Get the cookie name
     */
    [[nodiscard]] const std::string& name() const noexcept { return _name; }

    /**
     * @brief Get the cookie value
     */
    [[nodiscard]] const std::string& value() const noexcept { return _value; }

    /**
     * @brief Set the cookie value
     */
    Cookie& value(std::string value) {
        _value = std::move(value);
        return *this;
    }

    /**
     * @brief Get the expires attribute
     */
    [[nodiscard]] const std::optional<std::chrono::system_clock::time_point>& expires() const noexcept { 
        return _expires; 
    }

    /**
     * @brief Set the expires attribute
     * @param time_point Expiration time point
     */
    Cookie& expires(const std::chrono::system_clock::time_point& time_point) {
        _expires = time_point;
        return *this;
    }

    /**
     * @brief Set the expires attribute from a delta in seconds
     * @param seconds Seconds from now
     */
    Cookie& expires_in(int seconds) {
        _expires = std::chrono::system_clock::now() + std::chrono::seconds(seconds);
        return *this;
    }

    /**
     * @brief Get the max-age attribute
     */
    [[nodiscard]] const std::optional<int>& max_age() const noexcept { 
        return _max_age; 
    }

    /**
     * @brief Set the max-age attribute
     * @param seconds Max age in seconds
     */
    Cookie& max_age(int seconds) {
        _max_age = seconds;
        return *this;
    }

    /**
     * @brief Get the domain attribute
     */
    [[nodiscard]] const std::string& domain() const noexcept { return _domain; }

    /**
     * @brief Set the domain attribute
     * @param domain Domain value
     */
    Cookie& domain(std::string domain) {
        _domain = std::move(domain);
        return *this;
    }

    /**
     * @brief Get the path attribute
     */
    [[nodiscard]] const std::string& path() const noexcept { return _path; }

    /**
     * @brief Set the path attribute
     * @param path Path value
     */
    Cookie& path(std::string path) {
        _path = std::move(path);
        return *this;
    }

    /**
     * @brief Check if secure flag is set
     */
    [[nodiscard]] bool secure() const noexcept { return _secure; }

    /**
     * @brief Set the secure flag
     * @param secure Secure flag value
     */
    Cookie& secure(bool secure) {
        _secure = secure;
        return *this;
    }

    /**
     * @brief Check if http_only flag is set
     */
    [[nodiscard]] bool http_only() const noexcept { return _http_only; }

    /**
     * @brief Set the http_only flag
     * @param http_only HTTP only flag value
     */
    Cookie& http_only(bool http_only) {
        _http_only = http_only;
        return *this;
    }

    /**
     * @brief Get the SameSite policy
     */
    [[nodiscard]] const std::optional<SameSite>& same_site() const noexcept { 
        return _same_site; 
    }

    /**
     * @brief Set the SameSite policy
     * @param same_site SameSite policy
     */
    Cookie& same_site(SameSite same_site) {
        if (same_site == SameSite::NOT_SET) {
            _same_site.reset();
        } else {
            _same_site = same_site;
        }
        return *this;
    }

    /**
     * @brief Convert cookie to Set-Cookie header value
     */
    [[nodiscard]] std::string to_header() const;

    /**
     * @brief Serialize the cookie to a string (name=value format)
     */
    [[nodiscard]] std::string serialize() const;
};

/**
 * @brief Container for managing multiple cookies
 * 
 * Provides a convenient interface for storing and accessing multiple cookies,
 * with case-insensitive cookie name lookup.
 */
class CookieJar {
private:
    qb::icase_unordered_map<Cookie> _cookies;

public:
    /**
     * @brief Default constructor
     */
    CookieJar() = default;

    /**
     * @brief Add or replace a cookie
     * @param cookie Cookie to add
     */
    void add(const Cookie& cookie) {
        _cookies[cookie.name()] = cookie;
    }

    /**
     * @brief Add or replace a cookie
     * @param cookie Cookie to add
     */
    void add(Cookie&& cookie) {
        _cookies[cookie.name()] = std::move(cookie);
    }

    /**
     * @brief Create and add a new cookie
     * @param name Cookie name
     * @param value Cookie value
     * @return Reference to the created cookie
     */
    Cookie& add(std::string name, std::string value) {
        return _cookies.emplace(std::move(name), Cookie(name, std::move(value))).first->second;
    }

    /**
     * @brief Remove a cookie
     * @param name Cookie name
     * @return true if cookie was found and removed
     */
    bool remove(const std::string& name) {
        return _cookies.erase(name) > 0;
    }

    /**
     * @brief Clear all cookies
     */
    void clear() {
        _cookies.clear();
    }

    /**
     * @brief Get a cookie by name
     * @param name Cookie name
     * @return Pointer to cookie or nullptr if not found
     */
    [[nodiscard]] const Cookie* get(const std::string& name) const {
        auto it = _cookies.find(name);
        if (it != _cookies.end()) {
            return &it->second;
        }
        return nullptr;
    }

    /**
     * @brief Get a cookie by name
     * @param name Cookie name
     * @return Pointer to cookie or nullptr if not found
     */
    [[nodiscard]] Cookie* get(const std::string& name) {
        auto it = _cookies.find(name);
        if (it != _cookies.end()) {
            return &it->second;
        }
        return nullptr;
    }

    /**
     * @brief Check if cookie exists
     * @param name Cookie name
     * @return true if cookie exists
     */
    [[nodiscard]] bool has(const std::string& name) const {
        return _cookies.find(name) != _cookies.end();
    }

    /**
     * @brief Get all cookies
     * @return Map of all cookies
     */
    [[nodiscard]] const qb::icase_unordered_map<Cookie>& all() const {
        return _cookies;
    }

    /**
     * @brief Get number of cookies
     */
    [[nodiscard]] size_t size() const {
        return _cookies.size();
    }

    /**
     * @brief Check if jar is empty
     */
    [[nodiscard]] bool empty() const {
        return _cookies.empty();
    }
};

/**
 * @brief Parse cookies from a header
 * @param ptr Header data pointer
 * @param len Header data length
 * @param set_cookie_header true if parsing Set-Cookie header
 * @return Map of cookie names to values
 *
 * Parses HTTP Cookie or Set-Cookie headers according to RFC 6265,
 * extracting cookie names and values while handling quoted values
 * and special characters.
 *
 * For Cookie headers, it parses formats like:
 * "name1=value1; name2=value2"
 *
 * For Set-Cookie headers, it handles formats like:
 * "name=value; Path=/; Domain=example.com; Expires=Wed, 21 Oct 2015 07:28:00 GMT"
 *
 * Cookie attributes (Path, Domain, etc.) are not included in the returned map.
 */
[[nodiscard]] qb::icase_unordered_map<std::string>
parse_cookies(const char *ptr, size_t len, bool set_cookie_header);

/**
 * @brief Parse cookies from a string_view header
 * @param header Header string_view
 * @param set_cookie_header true if parsing Set-Cookie header
 * @return Map of cookie names to values
 *
 * String_view overload of the parse_cookies function, providing a more
 * efficient way to parse cookies without copying the header data.
 */
[[nodiscard]] qb::icase_unordered_map<std::string>
parse_cookies(std::string_view header, bool set_cookie_header);

/**
 * @brief Parse a Set-Cookie header into a Cookie object
 * @param header Set-Cookie header value
 * @return Cookie object with parsed attributes
 */
[[nodiscard]] std::optional<Cookie> parse_set_cookie(std::string_view header);

} // namespace qb::http
/**
 * @file qbm/http/cookie.cpp
 * @brief Implements HTTP cookie parsing and serialization utilities.
 *
 * This file provides the definitions for functions and methods declared in
 * `cookie.h`, including parsing `Cookie` and `Set-Cookie` headers, and
 * serializing `Cookie` objects to header strings.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include "./cookie.h"
#include "./date.h"      // For qb::http::date::parse_http_date, format_http_date
#include "./utility.h"   // For qb::http::utility::iequals, is_control

#include <algorithm>   // For std::find_if_not, std::transform
#include <sstream>     // For std::ostringstream
#include <stdexcept>   // For std::runtime_error, std::stoi related exceptions
// #include <qb/system/timestamp.h> // Not directly used here, date.h handles conversions
// <chrono>, <string>, <vector> are included via cookie.h or other headers above

namespace qb::http {

/**
 * @brief (Internal) Checks if a given name string corresponds to a known cookie attribute name.
 *
 * This helper function is used during cookie parsing to differentiate between
 * actual cookie name-value pairs and reserved attribute names like "Path", "Domain",
 * "Expires", etc., as defined in RFC 6265. It also considers legacy "$" prefixed
 * attributes from older RFCs (like RFC 2109), though these are obsolete.
 *
 * @param name The attribute name to check (case-insensitive comparison is used for known attributes).
 * @param set_cookie_header `true` if parsing a `Set-Cookie` header (where attributes are common),
 *                          `false` if parsing a `Cookie` header (where attributes are not expected).
 * @return `true` if `name` is a recognized cookie attribute, `false` otherwise.
 */
inline bool
is_cookie_attribute(std::string_view name, bool set_cookie_header) noexcept {
    if (name.empty() || name[0] == '$') { // Legacy RFC 2109 attributes or empty string
        return true;
    }
    if (set_cookie_header) {
        // RFC 6265 attributes. Comparison should be case-insensitive.
        static const char* known_attributes[] = {
            "Comment", "Domain", "Max-Age", "Path", "Secure",
            "Version", "Expires", "HttpOnly", "SameSite"
        };
        for (const char* attr : known_attributes) {
            if (utility::iequals(name, attr)) {
                return true;
            }
        }
    }
    return false;
}

/**
 * @brief Parse HTTP cookies from raw data
 * @param ptr Pointer to cookie data
 * @param len Length of cookie data
 * @param set_cookie_header Whether parsing a Set-Cookie header (true) or Cookie header
 * (false)
 * @return Map of cookie names to values
 *
 * Parses raw cookie data according to RFC 6265 and returns a case-insensitive map
 * of cookie names to values. Handles both Cookie and Set-Cookie headers based on
 * the set_cookie_header parameter.
 *
 * For Cookie headers (set_cookie_header=false), parses "name1=value1; name2=value2"
 * For Set-Cookie headers (set_cookie_header=true), parses individual cookies while
 * ignoring cookie attributes like Path, Domain, Expires, etc.
 *
 * Supports both quoted and unquoted values, and properly handles special characters.
 *
 * @throws std::runtime_error If parsing fails due to malformed data
 */
qb::icase_unordered_map<std::string>
parse_cookies(const char* ptr, const size_t len, bool set_cookie_header) {
    qb::icase_unordered_map<std::string> dict;
    if (!ptr || len == 0) {
        return dict;
    }

    enum class CookieParseState {
        COOKIE_PARSE_NAME,
        COOKIE_PARSE_VALUE,
        COOKIE_PARSE_IGNORE // After a quoted value, ignore until next separator
    } parse_state = CookieParseState::COOKIE_PARSE_NAME;

    const char* const end = ptr + len;
    std::string cookie_name;
    std::string cookie_value;
    char value_quote_character = '\0'; // '\'' or '"' if parsing a quoted value, else '\0'

    while (ptr < end) {
        const char current_char = *ptr;
        switch (parse_state) {
            case CookieParseState::COOKIE_PARSE_NAME:
                if (current_char == '=') {
                    // End of name found. Value might be empty.
                    // Name itself can be empty if previous was like ";=", handled by is_cookie_attribute.
                    value_quote_character = '\0'; // Reset for new value
                    cookie_value.clear();
                    parse_state = CookieParseState::COOKIE_PARSE_VALUE;
                } else if (current_char == ';' || current_char == ',') {
                    // Separator found before '=', means empty value for previous name (if any).
                    if (!cookie_name.empty()) { // If a name was parsed
                        if (!is_cookie_attribute(cookie_name, set_cookie_header)) {
                            dict.emplace(cookie_name, ""); // Empty value
                        }
                        cookie_name.clear();
                        // cookie_value is already empty or irrelevant here
                    }
                    // Stay in COOKIE_PARSE_NAME for the next potential cookie
                } else if (!utility::is_http_whitespace(current_char)) { // Ignore whitespace
                    if (utility::is_control(current_char) || cookie_name.length() >= COOKIE_NAME_MAX) {
                        throw std::runtime_error("Invalid character or max length exceeded for cookie name.");
                    }
                    cookie_name.push_back(current_char);
                }
                break;

            case CookieParseState::COOKIE_PARSE_VALUE:
                if (value_quote_character == '\0') { // Value is not (yet) quoted
                    if (current_char == ';' || current_char == ',') {
                        // End of value (unquoted)
                        if (!is_cookie_attribute(cookie_name, set_cookie_header)) {
                            dict.emplace(cookie_name, cookie_value); // Value might be empty
                        }
                        cookie_name.clear();
                        cookie_value.clear();
                        parse_state = CookieParseState::COOKIE_PARSE_NAME;
                    } else if ((current_char == '\'' || current_char == '"') && cookie_value.empty()) {
                        // Start of a quoted value, only if value is currently empty
                        value_quote_character = current_char;
                    } else if (!utility::is_http_whitespace(current_char) || !cookie_value.empty()) {
                        // Non-whitespace, or non-leading whitespace for unquoted value
                        if (utility::is_control(current_char) || cookie_value.length() >= COOKIE_VALUE_MAX) {
                            throw std::runtime_error("Invalid character or max length exceeded for cookie value.");
                        }
                        cookie_value.push_back(current_char);
                    }
                } else { // Value is quoted
                    if (current_char == value_quote_character) {
                        // End of quoted value
                        if (!is_cookie_attribute(cookie_name, set_cookie_header)) {
                            dict.emplace(cookie_name, cookie_value);
                        }
                        cookie_name.clear();
                        cookie_value.clear();
                        value_quote_character = '\0'; // Reset quote char
                        parse_state = CookieParseState::COOKIE_PARSE_IGNORE; // Ignore until next separator
                    } else {
                        if (cookie_value.length() >= COOKIE_VALUE_MAX) { // Max length check within quoted value
                            throw std::runtime_error("Max length exceeded for quoted cookie value.");
                        }
                        // Allow CTLs within quoted strings as per RFC 6265 (though some older RFCs restricted)
                        // For simplicity and modern behavior, not checking is_control here.
                        cookie_value.push_back(current_char);
                    }
                }
                break;

            case CookieParseState::COOKIE_PARSE_IGNORE:
                // Ignore everything until a separator is found, then switch to parsing next name.
                if (current_char == ';' || current_char == ',') {
                    parse_state = CookieParseState::COOKIE_PARSE_NAME;
                }
                break;
        }
        ++ptr;
    }

    // Handle the last cookie in the string (if any name was parsed)
    if (!cookie_name.empty()) {
        if (!is_cookie_attribute(cookie_name, set_cookie_header)) {
            dict.emplace(std::move(cookie_name), std::move(cookie_value));
        }
    }

    return dict;
}

/**
 * @brief Parse HTTP cookies from a string_view
 * @param header Cookie header string_view
 * @param set_cookie_header Whether parsing a Set-Cookie header (true) or Cookie header
 * (false)
 * @return Map of cookie names to values
 *
 * String_view overload that converts to raw pointer and length for processing.
 * More efficient than the string version as it avoids copying.
 *
 * @see parse_cookies(const char*, size_t, bool)
 */
qb::icase_unordered_map<std::string>
parse_cookies(std::string_view header, bool set_cookie_header) {
    return parse_cookies(header.data(), header.size(), set_cookie_header);
}

/**
 * @brief Parse a Set-Cookie header into a Cookie object
 * @param header Set-Cookie header value
 * @return Cookie object with parsed attributes
 */
std::optional<Cookie> parse_set_cookie(std::string_view header) {
    if (header.empty()) {
        return std::nullopt;
    }

    std::string_view original_header = header;
    std::string_view cookie_pair_sv;
    std::string_view attributes_sv;

    size_t first_semi = header.find(';');
    if (first_semi == std::string_view::npos) {
        cookie_pair_sv = header;
        // attributes_sv remains empty
    } else {
        cookie_pair_sv = header.substr(0, first_semi);
        attributes_sv = header.substr(first_semi + 1);
    }

    cookie_pair_sv = utility::trim_http_whitespace(cookie_pair_sv);
    size_t eq_pos = cookie_pair_sv.find('=');

    if (eq_pos == std::string_view::npos || eq_pos == 0) { // No '=' or starts with '=' (empty name)
        return std::nullopt; // Invalid cookie-pair
    }

    std::string cookie_name(cookie_pair_sv.substr(0, eq_pos));
    std::string cookie_value(cookie_pair_sv.substr(eq_pos + 1));

    // Basic unquoting of value if present (simple quotes, not full RFC spec)
    if (cookie_value.length() >= 2 && cookie_value.front() == '"' && cookie_value.back() == '"' ) {
        cookie_value = cookie_value.substr(1, cookie_value.length() - 2);
    }

    Cookie result_cookie(std::move(cookie_name), std::move(cookie_value));

    // Parse attributes
    std::string_view remaining_attrs = attributes_sv;
    while (!remaining_attrs.empty()) {
        size_t next_attr_semi = remaining_attrs.find(';');
        std::string_view current_attr_pair = utility::trim_http_whitespace(
            remaining_attrs.substr(0, next_attr_semi)
        );

        if (!current_attr_pair.empty()) {
            std::string_view attr_name_sv;
            std::string_view attr_value_sv;
            size_t attr_eq_pos = current_attr_pair.find('=');

            if (attr_eq_pos == std::string_view::npos) { // Flag attribute (e.g., Secure, HttpOnly)
                attr_name_sv = current_attr_pair;
            } else {
                attr_name_sv = utility::trim_http_whitespace(current_attr_pair.substr(0, attr_eq_pos));
                attr_value_sv = utility::trim_http_whitespace(current_attr_pair.substr(attr_eq_pos + 1));
                // Simple unquoting for attribute values
                if (attr_value_sv.length() >= 2 && attr_value_sv.front() == '\"' && attr_value_sv.back() == '\"') {
                    attr_value_sv = attr_value_sv.substr(1, attr_value_sv.length() - 2);
                }
            }

            if (utility::iequals(attr_name_sv, "Expires")) {
                if (auto tp = date::parse_http_date(std::string(attr_value_sv))) {
                    result_cookie.expires(*tp);
                }
            } else if (utility::iequals(attr_name_sv, "Max-Age")) {
                try {
                    // Ensure attr_value_sv is null-terminated for std::stoi, or use std::from_chars
                    std::string temp_max_age(attr_value_sv);
                    if (!temp_max_age.empty()){
                        result_cookie.max_age(std::stoi(temp_max_age));
                    }
                } catch (const std::invalid_argument&) { /* ignore */ }
                  catch (const std::out_of_range&)   { /* ignore */ }
            } else if (utility::iequals(attr_name_sv, "Domain")) {
                result_cookie.domain(std::string(attr_value_sv));
            } else if (utility::iequals(attr_name_sv, "Path")) {
                result_cookie.path(std::string(attr_value_sv));
            } else if (utility::iequals(attr_name_sv, "Secure")) {
                result_cookie.secure(true);
            } else if (utility::iequals(attr_name_sv, "HttpOnly")) {
                result_cookie.http_only(true);
            } else if (utility::iequals(attr_name_sv, "SameSite")) {
                if (utility::iequals(attr_value_sv, "Strict")) {
                    result_cookie.same_site(SameSite::Strict);
                } else if (utility::iequals(attr_value_sv, "Lax")) {
                    result_cookie.same_site(SameSite::Lax);
                } else if (utility::iequals(attr_value_sv, "None")) {
                    result_cookie.same_site(SameSite::None);
                }
            } // Other attributes like Comment, Version are ignored as per RFC 6265 focus
        }

        if (next_attr_semi == std::string_view::npos) {
            break;
        }
        remaining_attrs = remaining_attrs.substr(next_attr_semi + 1);
    }
    return result_cookie;
}

/**
 * @brief Convert a Cookie to a Set-Cookie header value
 * @return Formatted header value according to RFC 6265
 */
std::string Cookie::to_header() const {
    std::ostringstream ss;
    ss << _name << "=" << _value; // Name and value are assumed to not need special encoding here
                                  // as per Set-Cookie syntax (they are tokens or quoted-strings).
                                  // If they could contain delimiters, they must be quoted by the caller or setter.

    if (_expires) {
        ss << "; Expires=" << date::format_http_date(*_expires);
    }
    if (_max_age) {
        ss << "; Max-Age=" << *_max_age;
    }
    if (!_domain.empty()) {
        ss << "; Domain=" << _domain;
    }
    // Path defaults to "/" in constructor, so it's usually present.
    // RFC 6265 says if Path is not specified, it defaults to the path of the request URI.
    // However, when sending Set-Cookie, servers often explicitly set Path=/ for wide applicability.
    if (!_path.empty()) { // Ensure path is not empty before adding, though default is "/"
        ss << "; Path=" << _path;
    }
    if (_secure) {
        ss << "; Secure";
    }
    if (_http_only) {
        ss << "; HttpOnly";
    }
    if (_same_site) {
        ss << "; SameSite=";
        switch (*_same_site) {
            case SameSite::Strict: ss << "Strict"; break;
            case SameSite::Lax:    ss << "Lax";    break;
            case SameSite::None:   ss << "None";   break;
            case SameSite::NOT_SET: break; // Should not happen if _same_site is std::optional and NOT_SET clears it
        }
    }
    return ss.str();
}

std::string Cookie::serialize() const {
    // Simply name=value, for Cookie header. No attributes.
    // Assumes name and value are already suitable for Cookie header (e.g., no restricted chars unless quoted by original source).
    return _name + "=" + _value;
}

// Constructor definition
Cookie::Cookie(const std::string& name, const std::string& value)
    : _name(name) // Copy from const lvalue ref
    , _value(value) // Copy from const lvalue ref
    , _path("/") // Default path
    , _secure(false)
    , _http_only(false)
    , _same_site(std::nullopt) // Default: SameSite attribute not set
{
    // _expires and _max_age default to std::nullopt by their type.
    // _domain defaults to empty string.
}

Cookie::Cookie(std::string&& name, std::string&& value) noexcept
    : _name(std::move(name))
    , _value(std::move(value))
    , _path("/")
    , _secure(false)
    , _http_only(false)
    , _same_site(std::nullopt)
{}

} // namespace qb::http
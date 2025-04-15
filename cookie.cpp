#include <algorithm>
#include <sstream>

#include "./cookie.h"
#include "./date.h"
#include "./utility.h"

#include <qb/system/timestamp.h>
#include <chrono>
#include <string>
#include <vector>

namespace qb::http {

/**
 * @brief Check if a name is a cookie attribute
 * @param name Name to check
 * @param set_cookie_header Whether parsing a Set-Cookie header (true) or Cookie header
 * (false)
 * @return true if name is a cookie attribute, false otherwise
 *
 * Determines if a name-value pair in a cookie string is an attribute rather than a
 * cookie. Cookie attributes include $-prefixed attributes and standard attributes like
 * Path, Domain, etc.
 *
 * According to RFC 6265, everything after the first semicolon in a Set-Cookie header
 * is considered an attribute, but this function provides more precise detection by
 * checking against a list of known attributes.
 */
inline bool
is_cookie_attribute(const std::string &name, bool set_cookie_header) {
    return (
        name.empty() || name[0] == '$' ||
        (set_cookie_header &&
         (
             // This is needed because of a very lenient determination in
             // parse_cookie_header() of what qualifies as a cookie-pair in a Set-Cookie
             // header. According to RFC 6265, everything after the first semicolon is a
             // cookie attribute, but RFC 2109, which is obsolete, allowed multiple comma
             // separated cookies. parse_cookie_header() is very conservatively assuming
             // that any <n>=<value> pair in a Set-Cookie header is a cookie-pair unless
             // <n> is a known cookie attribute.
             utility::iequals(name, "Comment") || utility::iequals(name, "Domain") ||
             utility::iequals(name, "Max-Age") || utility::iequals(name, "Path") ||
             utility::iequals(name, "Secure") || utility::iequals(name, "Version") ||
             utility::iequals(name, "Expires") || utility::iequals(name, "HttpOnly") ||
             utility::iequals(name, "SameSite"))));
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
parse_cookies(const char *ptr, const size_t len, bool set_cookie_header) {
    qb::icase_unordered_map<std::string> dict;
    // BASED ON RFC 2109
    // http://www.ietf.org/rfc/rfc2109.txt
    //
    // The current implementation ignores cookie attributes which begin with '$'
    // (i.e. $Path=/, $Domain=, etc.)

    // used to track what we are parsing
    enum CookieParseState {
        COOKIE_PARSE_NAME,
        COOKIE_PARSE_VALUE,
        COOKIE_PARSE_IGNORE
    } parse_state = COOKIE_PARSE_NAME;

    // misc other variables used for parsing
    const char *const end = ptr + len;
    std::string       cookie_name;
    std::string       cookie_value;
    char              value_quote_character = '\0';

    // iterate through each character
    while (ptr < end) {
        switch (parse_state) {
            case COOKIE_PARSE_NAME:
                // parsing cookie name
                if (*ptr == '=') {
                    // end of name found (OK if empty)
                    value_quote_character = '\0';
                    parse_state           = COOKIE_PARSE_VALUE;
                } else if (*ptr == ';' || *ptr == ',') {
                    // ignore empty cookie names since this may occur naturally
                    // when quoted values are encountered
                    if (!cookie_name.empty()) {
                        // value is empty (OK)
                        if (!is_cookie_attribute(cookie_name, set_cookie_header))
                            dict.emplace(cookie_name, cookie_value);
                        cookie_name.erase();
                    }
                } else if (*ptr != ' ') { // ignore whitespace
                    // check if control character detected, or max sized exceeded
                    if (qb::http::utility::is_control(*ptr) ||
                        cookie_name.size() >= COOKIE_NAME_MAX)
                        throw std::runtime_error(
                            "ctrl in name found or max cookie name length");
                    // character is part of the name
                    cookie_name.push_back(*ptr);
                }
                break;

            case COOKIE_PARSE_VALUE:
                // parsing cookie value
                if (value_quote_character == '\0') {
                    // value is not (yet) quoted
                    if (*ptr == ';' || *ptr == ',') {
                        // end of value found (OK if empty)
                        if (!is_cookie_attribute(cookie_name, set_cookie_header))
                            dict.emplace(cookie_name, cookie_value);
                        cookie_name.erase();
                        cookie_value.erase();
                        parse_state = COOKIE_PARSE_NAME;
                    } else if (*ptr == '\'' || *ptr == '"') {
                        if (cookie_value.empty()) {
                            // begin quoted value
                            value_quote_character = *ptr;
                        } else if (cookie_value.size() >= COOKIE_VALUE_MAX) {
                            // max size exceeded
                            throw std::runtime_error("cookie ");
                        } else {
                            // assume character is part of the (unquoted) value
                            cookie_value.push_back(*ptr);
                        }
                    } else if (*ptr != ' ' ||
                               !cookie_value
                                    .empty()) { // ignore leading unquoted whitespace
                        // check if control character detected, or max sized exceeded
                        if (qb::http::utility::is_control(*ptr) ||
                            cookie_value.size() >= COOKIE_VALUE_MAX)
                            throw std::runtime_error(
                                "ctrl in value found or max cookie value length");
                        // character is part of the (unquoted) value
                        cookie_value.push_back(*ptr);
                    }
                } else {
                    // value is quoted
                    if (*ptr == value_quote_character) {
                        // end of value found (OK if empty)
                        if (!is_cookie_attribute(cookie_name, set_cookie_header))
                            dict.emplace(cookie_name, cookie_value);
                        cookie_name.erase();
                        cookie_value.erase();
                        parse_state = COOKIE_PARSE_IGNORE;
                    } else if (cookie_value.size() >= COOKIE_VALUE_MAX) {
                        // max size exceeded
                        throw std::runtime_error("max cookie value length");
                    } else {
                        // character is part of the (quoted) value
                        cookie_value.push_back(*ptr);
                    }
                }
                break;

            case COOKIE_PARSE_IGNORE:
                // ignore everything until we reach a comma "," or semicolon ";"
                if (*ptr == ';' || *ptr == ',')
                    parse_state = COOKIE_PARSE_NAME;
                break;
        }

        ++ptr;
    }

    // handle last cookie in string
    if (!is_cookie_attribute(cookie_name, set_cookie_header))
        dict.emplace(cookie_name, cookie_value);

    return dict;
}

/**
 * @brief Parse HTTP cookies from a string
 * @param header Cookie header string
 * @param set_cookie_header Whether parsing a Set-Cookie header (true) or Cookie header
 * (false)
 * @return Map of cookie names to values
 *
 * String overload that converts to raw pointer and length for processing.
 *
 * @see parse_cookies(const char*, size_t, bool)
 */
qb::icase_unordered_map<std::string>
parse_cookies(std::string const &header, bool set_cookie_header) {
    return parse_cookies(header.c_str(), header.size(), set_cookie_header);
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
parse_cookies(std::string_view const &header, bool set_cookie_header) {
    return parse_cookies(header.data(), header.size(), set_cookie_header);
}

/**
 * @brief Parse a Set-Cookie header into a Cookie object
 * @param header Set-Cookie header value
 * @return Cookie object with parsed attributes
 */
std::optional<Cookie> parse_set_cookie(std::string_view header) {
    // First, parse the basic cookie data to get name/value
    auto cookies = parse_cookies(header.data(), header.size(), true);
    if (cookies.empty()) {
        return std::nullopt;
    }
    
    // Use the first entry for the cookie name/value
    auto it = cookies.begin();
    Cookie cookie(it->first, it->second);
    
    // Now parse all the attributes
    std::string_view remaining = header;
    
    // Find the position after the first name=value pair
    size_t pos = remaining.find(';');
    if (pos != std::string_view::npos) {
        remaining = remaining.substr(pos + 1);
        
        // Parse each attribute
        while (!remaining.empty()) {
            // Remove leading whitespace
            while (!remaining.empty() && (remaining.front() == ' ' || remaining.front() == '\t')) {
                remaining = remaining.substr(1);
            }
            
            if (remaining.empty()) {
                break;
            }
            
            // Find attribute name
            pos = remaining.find('=');
            size_t end = remaining.find(';');
            if (end == std::string_view::npos) {
                end = remaining.size();
            }
            
            if (pos != std::string_view::npos && pos < end) {
                // Name=Value attribute
                std::string_view name = remaining.substr(0, pos);
                std::string_view value = remaining.substr(pos + 1, end - pos - 1);
                
                // Trim whitespace
                while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) {
                    name = name.substr(0, name.size() - 1);
                }
                
                while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
                    value = value.substr(1);
                }
                
                // Remove quotes from value if present
                if (!value.empty() && (value.front() == '"' || value.front() == '\'')) {
                    if (value.size() > 1 && value.back() == value.front()) {
                        value = value.substr(1, value.size() - 2);
                    }
                }
                
                // Process attribute
                if (qb::http::utility::iequals(std::string(name), "Path")) {
                    cookie.path(std::string(value));
                } else if (qb::http::utility::iequals(std::string(name), "Domain")) {
                    cookie.domain(std::string(value));
                } else if (qb::http::utility::iequals(std::string(name), "Expires")) {
                    try {
                        auto tp = qb::http::date::parse_http_date(std::string(value));
                        if (tp) {
                            cookie.expires(tp.value());
                        }
                    } catch (...) {
                        // Invalid date, ignore
                    }
                } else if (qb::http::utility::iequals(std::string(name), "Max-Age")) {
                    try {
                        int seconds = std::stoi(std::string(value));
                        cookie.max_age(seconds);
                    } catch (...) {
                        // Invalid integer, ignore
                    }
                } else if (qb::http::utility::iequals(std::string(name), "SameSite")) {
                    if (qb::http::utility::iequals(std::string(value), "Strict")) {
                        cookie.same_site(SameSite::Strict);
                    } else if (qb::http::utility::iequals(std::string(value), "Lax")) {
                        cookie.same_site(SameSite::Lax);
                    } else if (qb::http::utility::iequals(std::string(value), "None")) {
                        cookie.same_site(SameSite::None);
                    }
                }
            } else {
                // Flag attribute (no value)
                std::string_view flag = remaining.substr(0, end);
                
                // Trim whitespace
                while (!flag.empty() && (flag.back() == ' ' || flag.back() == '\t')) {
                    flag = flag.substr(0, flag.size() - 1);
                }
                
                if (qb::http::utility::iequals(std::string(flag), "Secure")) {
                    cookie.secure(true);
                } else if (qb::http::utility::iequals(std::string(flag), "HttpOnly")) {
                    cookie.http_only(true);
                }
            }
            
            // Move to next attribute
            if (end < remaining.size()) {
                remaining = remaining.substr(end + 1);
            } else {
                break;
            }
        }
    }
    
    return cookie;
}

/**
 * @brief Convert a Cookie to a Set-Cookie header value
 * @return Formatted header value according to RFC 6265
 */
std::string Cookie::to_header() const {
    std::ostringstream ss;
    
    // Cookie name and value (required)
    ss << _name << "=" << _value;
    
    // Expires attribute (optional)
    if (_expires) {
        ss << "; Expires=" << qb::http::date::format_http_date(*_expires);
    }
    
    // Max-Age attribute (optional)
    if (_max_age) {
        ss << "; Max-Age=" << *_max_age;
    }
    
    // Domain attribute (optional)
    if (!_domain.empty()) {
        ss << "; Domain=" << _domain;
    }
    
    // Path attribute (optional, but defaults to "/" so it's always present)
    ss << "; Path=" << _path;
    
    // Secure flag (optional)
    if (_secure) {
        ss << "; Secure";
    }
    
    // HttpOnly flag (optional)
    if (_http_only) {
        ss << "; HttpOnly";
    }
    
    // SameSite attribute (optional)
    if (_same_site) {
        ss << "; SameSite=";
        switch (*_same_site) {
            case qb::http::SameSite::Strict:
                ss << "Strict";
                break;
            case qb::http::SameSite::Lax:
                ss << "Lax";
                break;
            case qb::http::SameSite::None:
                ss << "None";
                break;
            case qb::http::SameSite::NOT_SET:
                // This case should never be reached since we're using empty optionals now
                break;
        }
    }
    
    return ss.str();
}

std::string Cookie::serialize() const {
    return _name + "=" + _value;
}

Cookie::Cookie(std::string name, std::string value)
    : _name(std::move(name)), _value(std::move(value)), _path("/"),
      _secure(false), _http_only(false), _same_site() {}

} // namespace qb::http
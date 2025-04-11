
#include "./cookie.h"

namespace qb::http {

/**
 * @brief Check if a name is a cookie attribute
 * @param name Name to check
 * @param set_cookie_header Whether parsing a Set-Cookie header (true) or Cookie header (false)
 * @return true if name is a cookie attribute, false otherwise
 * 
 * Determines if a name-value pair in a cookie string is an attribute rather than a cookie.
 * Cookie attributes include $-prefixed attributes and standard attributes like Path, Domain, etc.
 * 
 * According to RFC 6265, everything after the first semicolon in a Set-Cookie header
 * is considered an attribute, but this function provides more precise detection by
 * checking against a list of known attributes.
 */
inline bool is_cookie_attribute(const std::string& name, bool set_cookie_header)
{
    return (name.empty() || name[0] == '$' || (set_cookie_header &&
                                               (
                                                   // This is needed because of a very lenient determination in parse_cookie_header() of what
                                                   // qualifies as a cookie-pair in a Set-Cookie header.
                                                   // According to RFC 6265, everything after the first semicolon is a cookie attribute, but RFC 2109,
                                                   // which is obsolete, allowed multiple comma separated cookies.
                                                   // parse_cookie_header() is very conservatively assuming that any <n>=<value> pair in a
                                                   // Set-Cookie header is a cookie-pair unless <n> is a known cookie attribute.
                                                   utility::iequals(name, "Comment")
                                                   || utility::iequals(name, "Domain")
                                                   || utility::iequals(name, "Max-Age")
                                                   || utility::iequals(name, "Path")
                                                   || utility::iequals(name, "Secure")
                                                   || utility::iequals(name, "Version")
                                                   || utility::iequals(name, "Expires")
                                                   || utility::iequals(name, "HttpOnly")
                                                       )
                                                   ));
}

/**
 * @brief Parse HTTP cookies from raw data
 * @param ptr Pointer to cookie data
 * @param len Length of cookie data
 * @param set_cookie_header Whether parsing a Set-Cookie header (true) or Cookie header (false)
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
parse_cookies(const char *ptr, const size_t len,
              bool set_cookie_header) {
    qb::icase_unordered_map<std::string> dict;
    // BASED ON RFC 2109
    // http://www.ietf.org/rfc/rfc2109.txt
    //
    // The current implementation ignores cookie attributes which begin with '$'
    // (i.e. $Path=/, $Domain=, etc.)

    // used to track what we are parsing
    enum CookieParseState {
        COOKIE_PARSE_NAME, COOKIE_PARSE_VALUE, COOKIE_PARSE_IGNORE
    } parse_state = COOKIE_PARSE_NAME;

    // misc other variables used for parsing
    const char * const end = ptr + len;
    std::string cookie_name;
    std::string cookie_value;
    char value_quote_character = '\0';

    // iterate through each character
    while (ptr < end) {
        switch (parse_state) {

        case COOKIE_PARSE_NAME:
            // parsing cookie name
            if (*ptr == '=') {
                // end of name found (OK if empty)
                value_quote_character = '\0';
                parse_state = COOKIE_PARSE_VALUE;
            } else if (*ptr == ';' || *ptr == ',') {
                // ignore empty cookie names since this may occur naturally
                // when quoted values are encountered
                if (! cookie_name.empty()) {
                    // value is empty (OK)
                    if (! is_cookie_attribute(cookie_name, set_cookie_header))
                        dict.emplace(cookie_name, cookie_value);
                    cookie_name.erase();
                }
            } else if (*ptr != ' ') {   // ignore whitespace
                // check if control character detected, or max sized exceeded
                if (utility::is_control(*ptr) || cookie_name.size() >= COOKIE_NAME_MAX)
                    throw std::runtime_error("ctrl in name found or max cookie name length");
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
                    if (! is_cookie_attribute(cookie_name, set_cookie_header))
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
                } else if (*ptr != ' ' || !cookie_value.empty()) {  // ignore leading unquoted whitespace
                    // check if control character detected, or max sized exceeded
                    if (utility::is_control(*ptr) || cookie_value.size() >= COOKIE_VALUE_MAX)
                        throw std::runtime_error("ctrl in value found or max cookie value length");
                    // character is part of the (unquoted) value
                    cookie_value.push_back(*ptr);
                }
            } else {
                // value is quoted
                if (*ptr == value_quote_character) {
                    // end of value found (OK if empty)
                    if (! is_cookie_attribute(cookie_name, set_cookie_header))
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
    if (! is_cookie_attribute(cookie_name, set_cookie_header))
        dict.emplace(cookie_name, cookie_value);

    return dict;
}

/**
 * @brief Parse HTTP cookies from a string
 * @param header Cookie header string
 * @param set_cookie_header Whether parsing a Set-Cookie header (true) or Cookie header (false)
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
 * @param set_cookie_header Whether parsing a Set-Cookie header (true) or Cookie header (false)
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

}
#pragma once

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace qb::http {

/**
 * @brief Utility functions for HTTP protocol handling
 *
 * Contains helper functions for character validation, string manipulation,
 * and HTTP-specific operations to support the HTTP implementation.
 * These utilities follow RFC specifications for HTTP protocol elements.
 */
namespace utility {
/**
 * @brief Check if a character is a valid HTTP character
 * @param c Character to check
 * @return true if the character is valid for HTTP
 *
 * Checks if a character is a valid HTTP character according to
 * RFC 7230. Valid HTTP characters are those with ASCII codes between
 * 0 and 127 inclusive.
 */
inline bool
is_char(int c) {
    return c >= 0 && c <= 127;
}

/**
 * @brief Check if a character is a control character
 * @param c Character to check
 * @return true if the character is a control character
 *
 * Checks if a character is a control character according to
 * RFC 7230. Control characters are those with ASCII codes
 * between 0 and 31, or 127 (DEL).
 */
inline bool
is_control(int c) {
    return (c >= 0 && c <= 31) || (c == 127);
}

/**
 * @brief Check if a character is a special HTTP character
 * @param c Character to check
 * @return true if the character is a special HTTP character
 *
 * Checks if a character is one of the special characters used in
 * HTTP syntax as defined in RFC 7230. These include characters
 * used as delimiters or separators in HTTP headers and request line.
 */
inline bool
is_special(int c) {
    switch (c) {
        case '(':
        case ')':
        case '<':
        case '>':
        case '@':
        case ',':
        case ';':
        case ':':
        case '\\':
        case '"':
        case '/':
        case '[':
        case ']':
        case '?':
        case '=':
        case '{':
        case '}':
        case ' ':
        case '\t':
            return true;
        default:
            return false;
    }
}

/**
 * @brief Check if a character is a digit
 * @param c Character to check
 * @return true if the character is a digit (0-9)
 *
 * Checks if a character is a decimal digit (0-9).
 * This is used for parsing numeric values in HTTP headers.
 */
inline bool
is_digit(int c) {
    return c >= '0' && c <= '9';
}

/**
 * @brief Check if a character is a hexadecimal digit
 * @param c Character to check
 * @return true if the character is a hex digit (0-9, A-F, a-f)
 *
 * Checks if a character is a valid hexadecimal digit.
 * This includes the decimal digits 0-9 and the letters
 * A-F and a-f (case-insensitive). Used for parsing hexadecimal
 * values in HTTP, such as chunk sizes in chunked encoding.
 */
inline bool
is_hex_digit(int c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/**
 * @brief Case-insensitive string comparison
 * @param a First string
 * @param b Second string
 * @return true if strings are equal ignoring case
 *
 * Performs character by character case-insensitive comparison of two strings.
 * This is useful for HTTP header names which are case-insensitive according to RFC 7230.
 */
inline bool
iequals(const std::string &a, const std::string &b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end(),
                      [](char a, char b) { return tolower(a) == tolower(b); });
}

/**
 * @brief Check if a character is HTTP whitespace
 * @param ch Character to check
 * @return true if character is a space or horizontal tab
 *
 * According to RFC 7230 section 3.2.3, HTTP whitespace is defined as
 * space (SP) or horizontal tab (HTAB).
 */
inline bool
is_http_whitespace(const char ch) {
    return ch == ' ' || ch == '\t';
}

/**
 * @brief Split a string by delimiters
 * @tparam String String type for result
 * @param str String to split
 * @param delimiters Delimiter characters
 * @param reserve Number of elements to reserve in the result vector
 * @return Vector of substrings
 *
 * Splits the input string into a vector of substrings based on
 * any of the specified delimiter characters. Empty segments are
 * skipped, and the result vector is pre-allocated for efficiency
 * if a reserve size is specified.
 *
 * Example:
 * ```
 * auto parts = split_string("header; param=value", "; =");
 * // results in {"header", "param", "value"}
 * ```
 */
template <typename String>
std::vector<String>
split_string(std::string_view str, std::string_view delimiters,
             std::size_t reserve = 0) {
    std::vector<String> result;
    if (reserve)
        result.reserve(reserve);

    auto first = str.begin();
    while (first != str.end()) {
        const auto second = std::find_first_of(
            first, std::cend(str), std::cbegin(delimiters), std::cend(delimiters));
        if (first != second)
            result.emplace_back(first, std::distance(first, second));
        if (second == str.end())
            break;
        first = std::next(second);
    }
    return result;
}

/**
 * @brief Split a string with custom function
 * @tparam String String type for result
 * @tparam Pred Predicate function type
 * @param str String to split
 * @param pred Predicate function to determine split points
 * @param reserve Number of elements to reserve in the result vector
 * @return Vector of substrings
 *
 * Splits the input string into a vector of substrings based on
 * a custom predicate function. The predicate should return true
 * for characters that should be treated as delimiters.
 *
 * This version allows for more complex splitting logic than
 * the delimiter-based version.
 */
template <typename String, typename Pred>
std::enable_if_t<std::is_invocable_v<Pred, char>, std::vector<String>>
split_string(std::string_view str, Pred pred, std::size_t reserve = 0) {
    std::vector<String> result;
    if (reserve)
        result.reserve(reserve);

    auto first = str.begin();
    while (first != str.end()) {
        const auto second = std::find_if(first, std::cend(str), pred);
        if (first != second)
            result.emplace_back(first, std::distance(first, second));
        if (second == str.end())
            break;
        first = std::next(second);
    }
    return result;
}

/**
 * @brief Split a string by boundary string
 * @param str String to split
 * @param boundary Boundary string
 * @param reserve Number of elements to reserve in the result vector
 * @return Vector of substrings
 */
template <typename String>
std::vector<String>
split_string_by(String const &str, std::string const &boundary,
                std::size_t reserve = 5) {
    std::vector<String> ret;
    auto                begin      = str.begin();
    auto                end        = str.end();
    bool                flag_delim = true;

    ret.reserve(reserve);
    while (begin != str.end()) {
        if (flag_delim) {
            auto p = std::mismatch(begin, str.end(), boundary.begin(), boundary.end());
            if (static_cast<std::size_t>(p.first - begin) == boundary.size())
                begin = p.first;
            flag_delim = false;
        } else {
            const auto pos = str.find(boundary, begin - str.begin());
            if (pos != std::string::npos)
                end = str.begin() + pos;
            else
                end = str.end();
            ret.push_back({&(*begin), static_cast<std::size_t>(end - begin)});
            begin      = end;
            flag_delim = true;
        }
    }

    return ret;
}

/**
 * @brief Join strings with a delimiter
 * @param strings Vector of strings to join
 * @param delimiter Delimiter to use between strings
 * @return Joined string
 */
template <typename T>
std::string
join(const std::vector<T> &strings, const std::string &delimiter) {
    std::string result;
    for (size_t i = 0; i < strings.size(); ++i) {
        if (i > 0) {
            result += delimiter;
        }
        result += strings[i];
    }
    return result;
}

} // namespace utility
} // namespace qb::http

/**
 * @file qbm/http/utility.h
 * @brief HTTP protocol utility functions
 *
 * This file provides a collection of utility functions for string manipulation,
 * character validation, and encoding/decoding tasks relevant to the HTTP protocol.
 * These helpers are designed to be efficient and conform to relevant RFC specifications.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <algorithm>     // For std::equal, std::find_first_of, std::find_if, std::mismatch, std::next, std::distance
#include <cctype>        // For std::tolower, std::isalnum
#include <string>        // For std::string
#include <string_view>   // For std::string_view
#include <vector>        // For std::vector
#include <iomanip>       // For std::setw, std::uppercase, std::nouppercase
#include <sstream>       // For std::ostringstream
#include <type_traits>   // For std::enable_if_t, std::is_invocable_v

namespace qb::http {
    // Forward declarations if any helper structs/classes were here.

    /**
     * @brief Utility functions for HTTP protocol handling.
     *
     * Contains helper functions for character validation, string manipulation,
     * and HTTP-specific operations to support the HTTP implementation.
     * These utilities generally follow RFC specifications for HTTP protocol elements.
     */
    namespace utility {
        /**
         * @brief Checks if a character is a valid HTTP character (octet).
         * @param c Character to check.
         * @return `true` if the character's ASCII value is between 0 and 127 (inclusive), `false` otherwise.
         * @note Conforms to the definition of an octet in RFC 7230, Section 3.
         */
        [[nodiscard]] inline bool
        is_char(int c) noexcept {
            return c >= 0 && c <= 127;
        }

        /**
         * @brief Checks if a character is a control character (CTL).
         * @param c Character to check.
         * @return `true` if the character is an ASCII control character (0-31 or 127), `false` otherwise.
         * @note Conforms to RFC 7230, Appendix B (imported from RFC 5234).
         *       CTL = %x00-1F / %x7F
         */
        [[nodiscard]] inline bool
        is_control(int c) noexcept {
            return (c >= 0 && c <= 31) || (c == 127);
        }

        /**
         * @brief Checks if a character is a special "tspecial" character in HTTP.
         * @param c Character to check.
         * @return `true` if the character is one of "()<>@,;:\"/[]?={} \t", `false` otherwise.
         * @note Conforms to the `tspecials` definition in RFC 7230, Section 3.2.6.
         *       tspecials = "(" / ")" / "<" / ">" / "@" /
         *                   "," / ";" / ":" / "\\" / "\"" /
         *                   "/" / "[" / "]" / "?" / "=" /
         *                   "{" / "}" / SP / HT
         */
        [[nodiscard]] inline bool
        is_special(int c) noexcept {
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
         * @brief Checks if a character is a digit ('0'-'9').
         * @param c Character to check.
         * @return `true` if the character is a decimal digit, `false` otherwise.
         * @note Conforms to DIGIT definition in RFC 5234, Appendix B.1.
         */
        [[nodiscard]] inline bool
        is_digit(int c) noexcept {
            return c >= '0' && c <= '9';
        }

        /**
         * @brief Checks if a character is a hexadecimal digit.
         * @param c Character to check.
         * @return `true` if the character is a hex digit (0-9, A-F, a-f), `false` otherwise.
         * @note Conforms to HEXDIG definition in RFC 5234, Appendix B.1.
         */
        [[nodiscard]] inline bool
        is_hex_digit(int c) noexcept {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        }

        /**
         * @brief Performs a case-insensitive comparison of two string views.
         * @param a First string view.
         * @param b Second string view.
         * @return `true` if strings are equal ignoring case, `false` otherwise.
         * @note Useful for HTTP header names which are case-insensitive (RFC 7230, Section 3.2).
         */
        [[nodiscard]] inline bool
        iequals(std::string_view a, std::string_view b) noexcept {
            return std::equal(a.begin(), a.end(), b.begin(), b.end(),
                              [](char c1, char c2) {
                                  return std::tolower(static_cast<unsigned char>(c1)) ==
                                         std::tolower(static_cast<unsigned char>(c2));
                              });
        }

        /**
         * @brief Checks if a character is HTTP whitespace (Space or Horizontal Tab).
         * @param ch Character to check.
         * @return `true` if character is a space or horizontal tab, `false` otherwise.
         * @note According to RFC 7230, Section 3.2.3, OWS (optional whitespace)
         *       is SP / HTAB. This function checks for one such character.
         */
        [[nodiscard]] inline bool
        is_http_whitespace(char ch) noexcept {
            return ch == ' ' || ch == '\t';
        }

        /**
         * @brief Trims leading and trailing HTTP whitespace (SP or HTAB) from a string_view.
         * @param sv The string_view to trim.
         * @return A string_view with whitespace removed from both ends.
         *         Returns an empty view if the input is all whitespace.
         */
        [[nodiscard]] inline std::string_view
        trim_http_whitespace(std::string_view sv) noexcept {
            const auto *start = sv.data();
            const auto *end = sv.data() + sv.size();

            while (start < end && is_http_whitespace(*start)) {
                ++start;
            }
            while (end > start && is_http_whitespace(*(end - 1))) {
                --end;
            }
            return std::string_view(start, static_cast<size_t>(end - start));
        }

        /**
         * @brief Splits a header value string by a delimiter and trims HTTP whitespace from each part.
         *
         * This function is typically used for parsing list-based header fields,
         * such as `Accept` or `Cache-Control`, where values are comma-separated.
         * Empty parts resulting from trimming are omitted from the result.
         *
         * @param header_value The string_view of the header value to split.
         * @param delimiter The character to split by (e.g., ',').
         * @return A vector of strings, where each string is a trimmed part of the header value.
         *         Empty parts (after trimming) are not included.
         */
        [[nodiscard]] inline std::vector<std::string>
        split_and_trim_header_list(std::string_view header_value, char delimiter) {
            std::vector<std::string> result;
            std::string_view remaining = header_value;
            size_t pos;
            while ((pos = remaining.find(delimiter)) != std::string_view::npos) {
                std::string_view token_sv = remaining.substr(0, pos);
                std::string_view trimmed_token = trim_http_whitespace(token_sv);
                if (!trimmed_token.empty()) {
                    result.emplace_back(trimmed_token);
                }
                remaining = remaining.substr(pos + 1);
            }
            // Add the last token
            std::string_view trimmed_last_token = trim_http_whitespace(remaining);
            if (!trimmed_last_token.empty()) {
                result.emplace_back(trimmed_last_token);
            }
            return result;
        }

        /**
         * @brief Splits a string_view into a vector of substrings based on a set of delimiter characters.
         *
         * Empty substrings that would result from adjacent delimiters or delimiters at
         * the start/end of the string are not included in the result.
         *
         * @tparam String The type of string to store in the result vector (e.g., `std::string`, `std::string_view`).
         * @param str The input string_view to split.
         * @param delimiters A string_view containing all characters to be treated as delimiters.
         * @param reserve Optional: The number of elements to reserve in the result vector for efficiency.
         * @return A vector of `String` objects, each containing a substring.
         *
         * Example:
         * @code
         * auto parts = split_string<std::string>("key=value;other=val", ";=");
         * // parts will contain {"key", "value", "other", "val"}
         * @endcode
         */
        template<typename String>
        [[nodiscard]] std::vector<String>
        split_string(std::string_view str, std::string_view delimiters,
                     std::size_t reserve = 0) {
            std::vector<String> result;
            if (reserve > 0) {
                // Ensure reserve is only called if reserve > 0
                result.reserve(reserve);
            }

            auto first = str.begin();
            while (first != str.end()) {
                const auto second = std::find_first_of(
                    first, str.end(), delimiters.begin(), delimiters.end());
                if (first != second) {
                    // Ensure non-empty token
                    result.emplace_back(String{&*first, static_cast<size_t>(std::distance(first, second))});
                }
                if (second == str.end()) {
                    break;
                }
                first = std::next(second); // Move past the delimiter
            }
            return result;
        }

        /**
         * @brief Splits a string_view into a vector of substrings based on a custom predicate.
         *
         * Empty substrings that would result from characters satisfying the predicate
         * at the start/end of the string or adjacently are not included.
         *
         * @tparam String The type of string to store in the result vector (e.g., `std::string`, `std::string_view`).
         * @tparam Pred A callable type (function pointer, lambda, functor) that takes a `char`
         *              and returns `true` if the character is a delimiter, `false` otherwise.
         * @param str The input string_view to split.
         * @param pred The predicate function to determine split points.
         * @param reserve Optional: The number of elements to reserve in the result vector.
         * @return A vector of `String` objects, each containing a substring.
         *
         * Example:
         * @code
         * auto parts = split_string<std::string_view>("a,b c;d", [](char c){ return c == ',' || c == ' ' || c == ';'; });
         * // parts will contain {"a", "b", "c", "d"}
         * @endcode
         */
        template<typename String, typename Pred>
        [[nodiscard]] std::enable_if_t<std::is_invocable_r_v<bool, Pred, char>, std::vector<String> >
        split_string(std::string_view str, Pred pred, std::size_t reserve = 0) {
            std::vector<String> result;
            if (reserve > 0) {
                // Ensure reserve is only called if reserve > 0
                result.reserve(reserve);
            }

            auto first = str.begin();
            while (first != str.end()) {
                const auto second = std::find_if(first, str.end(), pred);
                if (first != second) {
                    // Ensure non-empty token
                    // Construct String from iterators or pointer/length if supported
                    result.emplace_back(&*first, static_cast<size_t>(std::distance(first, second)));
                }
                if (second == str.end()) {
                    break;
                }
                first = std::next(second); // Move past the delimiter
            }
            return result;
        }


        /**
         * @brief Splits a string-like object by a specified boundary string.
         *
         * This function divides the input string `str` into parts based on occurrences
         * of the `boundary` string. The boundary itself is not included in the resulting parts.
         *
         * @tparam StringType The type of the input string and the elements in the output vector.
         *                 This type must be constructible from `(const char*, size_t)`.
         *                 Typically `std::string` or `std::string_view`.
         * @param str The input string to be split.
         * @param boundary The string marking the boundaries between parts.
         * @param reserve An initial capacity hint for the result vector.
         * @return A vector of `StringType` containing the parts of the original string.
         *         If `str` is empty, or `boundary` is empty or not found, behavior
         *         depends on the exact conditions (e.g., might return a single part with `str`).
         *         Empty parts between consecutive boundaries are typically included.
         *
         * Example:
         * @code
         * std::string data = "part1--boundary--part2--boundary--part3";
         * auto parts = split_string_by<std::string>(data, "--boundary--");
         * // parts would contain {"part1", "part2", "part3"}
         * @endcode
         */
        template<typename StringType>
        [[nodiscard]] std::vector<StringType>
        split_string_by(std::string_view str, std::string_view boundary,
                        std::size_t reserve = 5) {
            std::vector<StringType> result;
            if (reserve > 0) {
                result.reserve(reserve);
            }

            if (boundary.empty()) {
                if (!str.empty()) {
                    result.emplace_back(str.data(), str.length());
                }
                return result;
            }

            std::string_view::size_type current_pos = 0;
            while (current_pos <= str.length()) {
                // Use <= to handle trailing empty part if str ends with boundary
                std::string_view::size_type next_boundary_pos = str.find(boundary, current_pos);

                if (next_boundary_pos == std::string_view::npos) {
                    // No more boundaries, take the rest of the string
                    result.emplace_back(str.data() + current_pos, str.length() - current_pos);
                    break;
                }

                // Found a boundary, take the part before it
                result.emplace_back(str.data() + current_pos, next_boundary_pos - current_pos);
                current_pos = next_boundary_pos + boundary.length();

                // If the string ends with the boundary, an empty part after it is often expected.
                // This loop condition (current_pos <= str.length()) and the check after loop
                // handle this. The current logic adds the part and then breaks if no more boundary.
                // If `str.find` returns `npos` and `current_pos` is at `str.length()`, it means
                // the string ended exactly on a boundary. The part before it has been added.
                // The next iteration will start at `str.length() + boundary.length()`,
                // which is > str.length(), so the loop terminates.
                // If str = "a--b", boundary = "--".
                // 1. current_pos = 0. next_boundary_pos = 1. Add "a" (str.data(), 1). current_pos = 1 + 2 = 3.
                // 2. current_pos = 3. str.find(boundary, 3) is npos. Add "b" (str.data()+3, 1). break.
                // Result: {"a", "b"} - Correct.

                // If str = "a--", boundary = "--"
                // 1. current_pos = 0. next_boundary_pos = 1. Add "a". current_pos = 3.
                // 2. current_pos = 3. str.find(boundary, 3) is npos. Add "" (str.data()+3, 0). break.
                // Result: {"a", ""} - Correct.

                // If str = "--a", boundary = "--"
                // 1. current_pos = 0. next_boundary_pos = 0. Add "" (str.data(), 0). current_pos = 0 + 2 = 2.
                // 2. current_pos = 2. str.find(boundary, 2) is npos. Add "a" (str.data()+2, 1). break.
                // Result: {"", "a"} - Correct.
            }
            return result;
        }


        /**
         * @brief Joins a collection of string-like objects into a single string, separated by a delimiter.
         * @tparam T The type of elements in the input collection (e.g., `std::string`, `std::string_view`, `const char*`).
         *           Must be convertible to `std::string` or appendable to `std::string`.
         * @param strings A `std::vector<T>` containing the strings to join.
         * @param delimiter The string to insert between each element.
         * @return A single `std::string` representing the joined elements.
         *         If `strings` is empty, returns an empty string.
         *         If `strings` has one element, returns that element as a string without the delimiter.
         */
        template<typename T>
        [[nodiscard]] std::string
        join(const std::vector<T> &strings, std::string_view delimiter) {
            if (strings.empty()) {
                return "";
            }
            std::string result;
            // Estimate capacity
            size_t total_len = 0;
            if (!strings.empty()) {
                total_len += (strings.size() - 1) * delimiter.length();
                for (const auto &s: strings) {
                    if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, std::string_view>) {
                        total_len += s.length();
                    } else if constexpr (std::is_convertible_v<T, std::string_view>) {
                        total_len += std::string_view(s).length();
                    }
                    // For other types, it's harder to estimate without conversion.
                    // A rough estimate or no reserve might be okay.
                }
                if (total_len > 0) {
                    // Avoid reserving 0
                    result.reserve(total_len);
                }
            }


            result.append(std::string(strings[0])); // Ensure first element is converted if needed
            for (size_t i = 1; i < strings.size(); ++i) {
                result.append(delimiter);
                result.append(std::string(strings[i])); // Ensure subsequent elements are converted
            }
            return result;
        }

        /**
         * @brief Escapes characters in a string_view to produce a basic HTML-safe string.
         *
         * Replaces `&` with `&amp;`, `"` with `&quot;`, `'` with `&#39;` (more compatible than `&apos;`),
         * `<` with `&lt;`, and `>` with `&gt;`.
         *
         * @param text The input string_view to escape.
         * @return A `std::string` with HTML special characters escaped.
         */
        [[nodiscard]] inline std::string
        escape_html(std::string_view text) {
            std::string result;
            result.reserve(text.length()); // Reserve at least the original length
            for (char c: text) {
                switch (c) {
                    case '&': result.append("&amp;");
                        break;
                    case '\"': result.append("&quot;");
                        break;
                    case '\'': result.append("&#39;");
                        break; // &apos; is not universally supported
                    case '<': result.append("&lt;");
                        break;
                    case '>': result.append("&gt;");
                        break;
                    default: result.push_back(c);
                        break;
                }
            }
            return result;
        }

        /**
         * @brief Encodes a string_view component for use in a URI.
         *
         * This function performs percent-encoding on characters that are not
         * "unreserved" according to RFC 3986 (i.e., alphanumeric, '-', '_', '.', '~').
         * All other characters are replaced by a '%' followed by two hexadecimal digits.
         *
         * @param component The string_view representing a URI component to be encoded
         *                  (e.g., a query parameter value, a path segment).
         * @return A `std::string` with the component percent-encoded.
         */
        [[nodiscard]] inline std::string
        uri_encode_component(std::string_view component) {
            std::ostringstream escaped;
            escaped.fill('0'); // Ensures leading zeros for hex values if setw is used (e.g. %0A for newline)
            escaped << std::hex << std::uppercase; // Output hex in uppercase

            for (char c_signed: component) {
                unsigned char c = static_cast<unsigned char>(c_signed);
                // Keep alphanumeric and other unreserved characters as defined in RFC 3986, Section 2.3
                if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                    escaped << c;
                } else {
                    // Any other characters are percent-encoded
                    escaped << '%' << std::setw(2) << static_cast<int>(c);
                }
            }
            // No need for std::nouppercase here as std::hex settings are local to ostringstream state changes
            return escaped.str();
        }
    } // namespace utility
} // namespace qb::http

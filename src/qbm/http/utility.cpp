/**
 * @file qbm/http/utility.cpp
 * @brief Out-of-line definitions for the HTTP protocol utility functions.
 *
 * Hosts the non-template, non-trivial helper bodies declared in
 * @ref qbm/http/utility.h (percent-decoding, header-list splitting, HTML
 * escaping and URI component encoding). The trivial character-classification
 * predicates and all template/`constexpr` helpers remain defined inline in the
 * header.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./utility.h"

namespace qb::http {
namespace utility {

std::string
decode_path_component(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        const char c = input[i];
        if (c == '%' && i + 2 < input.size() && is_hex_digit(static_cast<unsigned char>(input[i + 1]))
            && is_hex_digit(static_cast<unsigned char>(input[i + 2]))) {
            const unsigned char high = hex_value(input[i + 1]);
            const unsigned char low  = hex_value(input[i + 2]);
            result.push_back(static_cast<char>((high << 4) | low));
            i += 2;
        } else {
            result.push_back(c);
        }
    }
    return result;
}

std::vector<std::string>
split_and_trim_header_list(std::string_view header_value, char delimiter) {
    std::vector<std::string> result;
    std::string_view         remaining = header_value;
    size_t                   pos;
    while ((pos = remaining.find(delimiter)) != std::string_view::npos) {
        std::string_view token_sv      = remaining.substr(0, pos);
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

std::string
escape_html(std::string_view text) {
    std::string result;
    result.reserve(text.length()); // Reserve at least the original length
    for (char c : text) {
        switch (c) {
            case '&':
                result.append("&amp;");
                break;
            case '\"':
                result.append("&quot;");
                break;
            case '\'':
                result.append("&#39;");
                break; // &apos; is not universally supported
            case '<':
                result.append("&lt;");
                break;
            case '>':
                result.append("&gt;");
                break;
            default:
                result.push_back(c);
                break;
        }
    }
    return result;
}

std::string
uri_encode_component(std::string_view component) {
    std::string result;
    result.reserve(component.size() * 3); // Worst case: all chars encoded as %XX

    for (unsigned char c : component) {
        // Keep alphanumeric and other unreserved characters as defined in RFC 3986, Section 2.3
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            result += static_cast<char>(c);
        } else {
            // Any other characters are percent-encoded
            static constexpr char hex_digits[] = "0123456789ABCDEF";
            result += '%';
            result += hex_digits[c >> 4];
            result += hex_digits[c & 0xF];
        }
    }
    return result;
}

} // namespace utility
} // namespace qb::http

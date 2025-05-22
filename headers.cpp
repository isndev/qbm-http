/**
 * @file qbm/http/headers.cpp
 * @brief Implements utility functions for HTTP header parsing and generation.
 *
 * This file provides the definitions for functions declared in `headers.h`,
 * including `parse_header_attributes` for breaking down complex header values
 * (like Content-Type parameters), `accept_encoding` for generating an appropriate
 * Accept-Encoding header value based on server capabilities, and `content_encoding`
 * for selecting a suitable Content-Encoding from a client's Accept-Encoding header.
 * It also contains explicit template instantiations for `THeaders<std::string>`
 * and `THeaders<std::string_view>`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include "./headers.h" // Includes utility, types, icase_unordered_map, string, string_view, etc.
#include <stdexcept>    // For std::runtime_error (thrown by parse_header_attributes)
#include <charconv>     // For std::to_chars (used in accept_encoding)

#ifdef QB_IO_WITH_ZLIB
#include <qb/io/compression.h> // For qb::compression::builtin factories
#endif

namespace qb::http {

/**
 * @brief Parses attributes from a raw HTTP header value string.
 *
 * This function implements a state machine to parse header attributes from a character buffer.
 * It handles formats like `name1=value1; name2="quoted value2"; name3=value3, name4=value4`.
 * Delimiters can be semicolons (`;`) or commas (`,`). Attribute names are treated case-insensitively
 * due to the `qb::icase_unordered_map` return type for keys, while values are stored as `std::string`.
 *
 * The parser expects attribute names and values to adhere to length limits defined by
 * `ATTRIBUTE_NAME_MAX` and `ATTRIBUTE_VALUE_MAX` from `headers.h`.
 * It also disallows control characters within names and unquoted values.
 * Leading/trailing whitespace around names and unquoted values is trimmed.
 *
 * @param ptr Pointer to the start of the header attribute data.
 * @param len Length of the data in bytes.
 * @return A `qb::icase_unordered_map<std::string>` where keys are attribute names
 *         and values are the corresponding attribute values.
 * @throws std::runtime_error If parsing fails due to malformed data (e.g., control characters found,
 *                            max attribute name/value length exceeded, unterminated quoted value).
 */
qb::icase_unordered_map<std::string>
parse_header_attributes(const char *ptr, const size_t len) {
    qb::icase_unordered_map<std::string> dict;

    enum class AttributeParseState { // Using enum class for better type safety
        NAME,  
        VALUE, 
        IGNORE 
    } parse_state = AttributeParseState::NAME;

    const char *const end_ptr = ptr + len;
    std::string current_attribute_name;
    std::string current_attribute_value;
    char value_quote_char = '\0'; // '\0' indicates not currently parsing a quoted value

    while (ptr < end_ptr) {
        const char c = *ptr;
        switch (parse_state) {
            case AttributeParseState::NAME:
                if (c == '=') {
                    value_quote_char = '\0'; // Reset for the new value
                    current_attribute_value.clear();
                    parse_state = AttributeParseState::VALUE;
                } else if (c == ';' || c == ',') {
                    // Attribute without a value, or separator after a previous valueless attribute
                    if (!current_attribute_name.empty()) {
                        dict.emplace(std::string(utility::trim_http_whitespace(current_attribute_name)), "");
                        current_attribute_name.clear();
                    }
                    // Stay in NAME state for the next attribute.
                } else if (!std::isspace(static_cast<unsigned char>(c))) { // Ignore whitespace
                    if (utility::is_control(c) || current_attribute_name.size() >= ATTRIBUTE_NAME_MAX) {
                        throw std::runtime_error("Control character in attribute name or max name length exceeded.");
                    }
                    current_attribute_name.push_back(c);
                }
                break;

            case AttributeParseState::VALUE:
                if (value_quote_char == '\0') { // Value is not (yet) inside quotes
                    if (c == ';' || c == ',') { // Delimiter ends an unquoted value
                        dict.emplace(std::string(utility::trim_http_whitespace(current_attribute_name)), 
                                     std::string(utility::trim_http_whitespace(current_attribute_value)));
                        current_attribute_name.clear();
                        current_attribute_value.clear();
                        parse_state = AttributeParseState::NAME;
                    } else if (current_attribute_value.empty() && (c == '\'' || c == '"')) {
                        // Start of a new quoted value
                        value_quote_char = c;
                    } else if (c == ' ' || c == '\t') { // Handle whitespace for unquoted values
                        if (!current_attribute_value.empty()) { // If value has started, space is part of it (until trimmed)
                             current_attribute_value.push_back(c);
                        } // else, leading whitespace is ignored for unquoted value, do nothing
                    } else { // Non-delimiter, non-quote, non-space character
                        if (utility::is_control(c) || current_attribute_value.size() >= ATTRIBUTE_VALUE_MAX) {
                            throw std::runtime_error("Control character in attribute value or max value length exceeded.");
                        }
                        current_attribute_value.push_back(c);
                    }
                } else { // Value is currently inside quotes
                    if (c == value_quote_char) { // End of quoted value
                        dict.emplace(std::string(utility::trim_http_whitespace(current_attribute_name)), current_attribute_value); // Quoted value is not trimmed here
                        current_attribute_name.clear();
                        current_attribute_value.clear();
                        value_quote_char = '\0';
                        parse_state = AttributeParseState::IGNORE; // Ignore chars until next delimiter
                    } else if (current_attribute_value.size() >= ATTRIBUTE_VALUE_MAX) {
                        throw std::runtime_error("Max attribute value length exceeded (quoted).");
                    } else {
                        // Note: HTTP quoted-string can have quoted-pair escapes (e.g., \\"). This parser doesn't handle them.
                        current_attribute_value.push_back(c);
                    }
                }
                break;

            case AttributeParseState::IGNORE:
                // After a quoted value, ignore characters until a delimiter is found
                if (c == ';' || c == ',') {
                    parse_state = AttributeParseState::NAME;
                }
                break;
        }
        ++ptr;
    }

    // After the loop, handle any remaining attribute that was being parsed
    if (!current_attribute_name.empty()) {
        if (parse_state == AttributeParseState::VALUE && value_quote_char != '\0') {
            throw std::runtime_error("Unterminated quoted attribute value at end of header string.");
        }
        // If ended in IGNORE state, value was quoted and already emplaced. Name/Value buffers are clear.
        // If ended in NAME state, it's an attribute without a value.
        // If ended in VALUE state (unquoted), emplace it.
        if (parse_state == AttributeParseState::NAME || parse_state == AttributeParseState::VALUE) {
             dict.emplace(std::string(utility::trim_http_whitespace(current_attribute_name)), 
                         std::string(utility::trim_http_whitespace(current_attribute_value)));
        }
    } else if (parse_state == AttributeParseState::VALUE && !current_attribute_value.empty()){
        // This means we have a value but no preceding name (e.g., an initial "=value"). This is malformed.
        // Depending on strictness, could throw or ignore. Silently ignoring for now.
    }

    return dict;
}

/**
 * @brief Parses attributes from an HTTP header value `std::string`.
 * This is an overload that delegates to the `const char*` version for actual parsing.
 * @param header The header value string.
 * @return A `qb::icase_unordered_map<std::string>` of attribute names to values.
 * @see parse_header_attributes(const char*, size_t)
 */
qb::icase_unordered_map<std::string>
parse_header_attributes(const std::string& header) {
    return parse_header_attributes(header.data(), header.length());
}

/**
 * @brief Parses attributes from an HTTP header value `std::string_view`.
 * This overload delegates to the `const char*` version. It is more efficient for `std::string_view` inputs
 * as it avoids creating an intermediate `std::string` if the view is already contiguous.
 * @param header The header value `std::string_view`.
 * @return A `qb::icase_unordered_map<std::string>` of attribute names to values.
 * @see parse_header_attributes(const char*, size_t)
 */
qb::icase_unordered_map<std::string>
parse_header_attributes(std::string_view header) {
    return parse_header_attributes(header.data(), header.size());
}

/**
 * @brief Generates an `Accept-Encoding` HTTP header value string based on server capabilities.
 *
 * This string lists compression algorithms supported by the server (if `QB_IO_WITH_ZLIB` is defined),
 * typically with quality values (q-values) indicating preference. For example: "gzip;q=1.0, deflate;q=0.9".
 * The string "chunked" is always appended; while `chunked` is a Transfer-Encoding, its presence in
 * `Accept-Encoding` has historical context or might be used by some clients.
 *
 * @return A string suitable for use as an `Accept-Encoding` header value, typically sent by a client.
 */
[[nodiscard]] std::string
accept_encoding() {
    std::string algorithms_str;
#ifdef QB_IO_WITH_ZLIB
    algorithms_str.reserve(64); // Pre-allocate for common cases
    const auto& decompress_factories = qb::compression::builtin::get_decompress_factories();
    bool first_algorithm = true;
    for (const auto& factory : decompress_factories) {
        if (!factory || factory->algorithm().empty()) continue;
        if (!first_algorithm) {
            algorithms_str += ", ";
        }
        algorithms_str += factory->algorithm();
        
        // q-values are between 0 and 1, up to 3 decimal places.
        // weight is an integer, e.g., 1000 for q=1.0, 900 for q=0.9, 50 for q=0.05
        if (factory->weight() < 1000) { // Don't add q=1.0, as it's the default
            algorithms_str += ";q=";
            double q_val = static_cast<double>(factory->weight()) / 1000.0;
            char buf[10]; // Buffer for "0.XXX"
            // std::to_chars for floating point with fixed precision is C++17
            auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf) -1 , q_val, std::chars_format::fixed, 3); 
            if (ec == std::errc()) {
                *ptr = '\0'; // Null-terminate
                std::string_view q_str(buf);
                // Trim trailing zeros after decimal point, but keep at least one digit (e.g. 0.5, not 0.)
                size_t dot_pos = q_str.find('.');
                if (dot_pos != std::string_view::npos) {
                    size_t last_digit_to_keep = q_str.find_last_not_of('0');
                    if (last_digit_to_keep == dot_pos) { // e.g., "0." from "0.000"
                        q_str = q_str.substr(0, dot_pos + 2); // Keep one zero like "0.0"
                    } else if (last_digit_to_keep > dot_pos) {
                        q_str = q_str.substr(0, last_digit_to_keep + 1);
                    }
                }
                algorithms_str += q_str;
            } else {
                // Fallback if std::to_chars had an issue (should be rare for double)
                algorithms_str += std::to_string(q_val); // This might have more precision than needed
            }
        }
        first_algorithm = false;
    }
    if (!algorithms_str.empty()) {
        algorithms_str += ", ";
    }
#endif
    algorithms_str += "chunked"; // "chunked" is a Transfer-Encoding, also often accepted.
    return algorithms_str;
}

/**
 * @brief Selects a suitable `Content-Encoding` based on the client's `Accept-Encoding` header.
 *
 * This function parses the `accept_encoding_header` string (e.g., "gzip, deflate, br") from the client.
 * It then iterates through the server's available compression algorithms (if `QB_IO_WITH_ZLIB` is defined)
 * and returns the name of the first algorithm found in the client's accepted list that is also supported
 * by the server. The order of encodings in the client's `Accept-Encoding` header is generally respected.
 * Quality values (q-values) are not used for weighting in this simple implementation; first match wins.
 *
 * @param accept_encoding_header The `Accept-Encoding` header value received from the client.
 * @return The name of the selected encoding (e.g., `"gzip"`, `"deflate"`), or an empty string
 *         if no suitable common encoding is found or if server-side compression is disabled.
 */
[[nodiscard]] std::string
content_encoding(std::string_view accept_encoding_header) {
#ifdef QB_IO_WITH_ZLIB
    // Split client's Accept-Encoding header into individual tokens (encodings).
    // Delimiters include comma and semicolon (q-values are attached to tokens before this split).
    std::vector<std::string> client_accepted_tokens = utility::split_string<std::string>(accept_encoding_header, ",");
    
    const auto& server_compress_factories = qb::compression::builtin::get_compress_factories();

    for (const auto& client_token_full : client_accepted_tokens) {
        std::string_view client_encoding_name = utility::trim_http_whitespace(client_token_full);
        // Remove q-value part if present, e.g., "gzip;q=0.8" -> "gzip"
        auto q_param_pos = client_encoding_name.find(';');
        if (q_param_pos != std::string_view::npos) {
            client_encoding_name = client_encoding_name.substr(0, q_param_pos);
            client_encoding_name = utility::trim_http_whitespace(client_encoding_name); // Trim again after substr
        }

        if (client_encoding_name.empty() || client_encoding_name == "*") {
            // Wildcard '*' could mean any encoding not explicitly mentioned. Server can pick its best.
            // For simplicity, if '*' is present and we have factories, pick the first available one.
            // A more advanced implementation might use server preferences or q-values.
            if (client_encoding_name == "*" && !server_compress_factories.empty() && server_compress_factories.front()){
                return server_compress_factories.front()->algorithm();
            }
            continue; 
        }

        for (const auto& server_factory : server_compress_factories) {
            if (server_factory && utility::iequals(server_factory->algorithm(), client_encoding_name)) {
                return server_factory->algorithm(); // Found a directly supported match
            }
        }
    }
#else
    // Suppress unused parameter warning if ZLIB support is not compiled in.
    (void)accept_encoding_header; 
#endif
    return ""; // No suitable encoding found or compression disabled
}

// Explicit template instantiations for THeaders defined in headers.h
// This ensures that the compiler generates code for these common types, which can
// speed up link times for users of this library.
template class THeaders<std::string>;
template class THeaders<std::string_view>;

} // namespace qb::http

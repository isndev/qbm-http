/**
 * @file qbm/http/headers.cpp
 * @brief Implements utility functions for HTTP header parsing and generation.
 *
 * This file provides the definitions for functions declared in `headers.h`,
 * including `parse_header_attributes` for breaking down complex header values
 * (like Content-Type parameters), `accept_encoding` for generating an appropriate
 * Accept-Encoding header value based on server capabilities, and `content_encoding`
 * for selecting a suitable Content-Encoding from a client's Accept-Encoding header.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./headers.h" // Includes utility, types, icase_unordered_map, string, string_view, etc.
#include <charconv>    // For std::to_chars (used in accept_encoding)
#include <optional>
#include <stdexcept> // For std::runtime_error (thrown by parse_header_attributes)
#include <vector>

#ifdef QB_HAS_COMPRESSION
#include <qb/io/compression.h> // For qb::compression::builtin factories
#endif

namespace qb::http {
namespace {
#ifdef QB_HAS_COMPRESSION // these qvalue parsers feed Accept-Encoding negotiation only
// Parse RFC 9110 qvalue into milli-units [0..1000].
// Accepts:
// - "1" / "1.0" / "1.00" / "1.000"
// - "0" / "0.123" (up to 3 fractional digits)
[[nodiscard]] std::optional<int>
parse_qvalue_milli(std::string_view raw_q) noexcept {
    const std::string_view q = utility::trim_http_whitespace(raw_q);
    if (q.empty()) {
        return std::nullopt;
    }
    if (q == "1" || q == "1.0" || q == "1.00" || q == "1.000") {
        return 1000;
    }
    if (q[0] != '0') {
        return std::nullopt;
    }
    if (q.size() == 1) {
        return 0;
    }
    if (q.size() < 3 || q[1] != '.') {
        return std::nullopt;
    }

    int milli = 0;
    int place = 100;
    for (std::size_t i = 2; i < q.size(); ++i) {
        const char c = q[i];
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        if (place > 0) {
            milli += (c - '0') * place;
            place /= 10;
        } else {
            // More than 3 fractional digits is invalid for qvalue.
            return std::nullopt;
        }
    }
    return milli;
}

// Extract q from a single Accept-Encoding token.
// If no q parameter is present, defaults to 1000.
[[nodiscard]] int
parse_accept_encoding_q(std::string_view token_full) noexcept {
    auto semicolon_pos = token_full.find(';');
    if (semicolon_pos == std::string_view::npos) {
        return 1000;
    }

    std::string_view params = token_full.substr(semicolon_pos + 1);
    while (!params.empty()) {
        const auto             next  = params.find(';');
        const std::string_view param = utility::trim_http_whitespace(next == std::string_view::npos ? params : params.substr(0, next));

        if (!param.empty()) {
            const auto eq_pos = param.find('=');
            if (eq_pos != std::string_view::npos) {
                const std::string_view key   = utility::trim_http_whitespace(param.substr(0, eq_pos));
                const std::string_view value = utility::trim_http_whitespace(param.substr(eq_pos + 1));
                if (utility::iequals(key, "q")) {
                    const auto q = parse_qvalue_milli(value);
                    return q.value_or(0);
                }
            }
        }

        if (next == std::string_view::npos) {
            break;
        }
        params.remove_prefix(next + 1);
    }

    return 1000;
}
#endif // QB_HAS_COMPRESSION
} // namespace

namespace {
/**
 * @brief The attribute state machine behind parse_header_attributes(): it reports each attribute to
 *        @p emit as it completes -- `emit(std::string_view name, std::string &&value)`, the name trimmed --
 *        instead of collecting them, so a caller that needs one attribute builds no map. Same grammar,
 *        same limits, same exceptions.
 */
template <typename Emit>
void
for_each_header_attribute(const char *ptr, const size_t len, Emit &&emit) {
    // Security: Limit maximum input size to prevent DoS attacks via excessive memory allocation
    constexpr size_t MAX_HEADER_ATTRIBUTES_SIZE = 64 * 1024; // 64KB limit as per security best practices
    if (len > MAX_HEADER_ATTRIBUTES_SIZE) {
        throw std::runtime_error("Header attributes exceed maximum allowed size of 64KB");
    }
    if (ptr == nullptr && len > 0) {
        throw std::runtime_error("Invalid null pointer with non-zero length");
    }

    enum class AttributeParseState {
        // Using enum class for better type safety
        NAME,
        VALUE,
        AFTER_QUOTED_VALUE
    } parse_state = AttributeParseState::NAME;

    const char *const end_ptr = ptr + len;
    std::string       current_attribute_name;
    std::string       current_attribute_value;
    char              value_quote_char = '\0'; // '\0' indicates not currently parsing a quoted value
    bool              value_escape     = false;

    while (ptr < end_ptr) {
        const char c = *ptr;
        switch (parse_state) {
            case AttributeParseState::NAME:
                if (c == '=') {
                    if (utility::trim_http_whitespace(current_attribute_name).empty()) {
                        throw std::runtime_error("Attribute value is missing a name.");
                    }
                    value_quote_char = '\0'; // Reset for the new value
                    current_attribute_value.clear();
                    parse_state = AttributeParseState::VALUE;
                } else if (c == ';' || c == ',') {
                    // Attribute without a value, or separator after a previous valueless attribute
                    if (!current_attribute_name.empty()) {
                        emit(utility::trim_http_whitespace(current_attribute_name), std::string());
                        current_attribute_name.clear();
                    }
                    // Stay in NAME state for the next attribute.
                } else if (!utility::is_http_whitespace(c)) {
                    // Ignore whitespace
                    if (utility::is_control(c) || current_attribute_name.size() >= ATTRIBUTE_NAME_MAX) {
                        throw std::runtime_error("Control character in attribute name or attribute name size exceeds maximum allowed length.");
                    }
                    current_attribute_name.push_back(c);
                }
                break;

            case AttributeParseState::VALUE:
                if (value_quote_char == '\0') {
                    // Value is not (yet) inside quotes
                    if (c == ';' || c == ',') {
                        // Delimiter ends an unquoted value
                        emit(utility::trim_http_whitespace(current_attribute_name),
                             std::string(utility::trim_http_whitespace(current_attribute_value)));
                        current_attribute_name.clear();
                        current_attribute_value.clear();
                        parse_state = AttributeParseState::NAME;
                    } else if (current_attribute_value.empty() && (c == '\'' || c == '"')) {
                        // Start of a new quoted value
                        value_quote_char = c;
                    } else if (c == ' ' || c == '\t') {
                        // Handle whitespace for unquoted values
                        if (!current_attribute_value.empty()) {
                            // If value has started, space is part of it (until trimmed)
                            current_attribute_value.push_back(c);
                        } // else, leading whitespace is ignored for unquoted value, do nothing
                    } else {
                        // Non-delimiter, non-quote, non-space character
                        if (utility::is_control(c) || current_attribute_value.size() >= ATTRIBUTE_VALUE_MAX) {
                            throw std::runtime_error(
                                "Control character in attribute value or attribute value size exceeds maximum allowed length.");
                        }
                        current_attribute_value.push_back(c);
                    }
                } else {
                    // Value is currently inside quotes
                    if (value_escape) {
                        // RFC 7230 quoted-pair: only HTAB / SP / VCHAR / obs-text
                        // may follow a backslash. Reject other control characters
                        // (NUL, CR, LF, ...) so they cannot be smuggled into the
                        // parsed attribute value.
                        if (utility::is_control(c) && c != '\t') {
                            throw std::runtime_error("Invalid escaped control character in quoted attribute value.");
                        }
                        if (current_attribute_value.size() >= ATTRIBUTE_VALUE_MAX) {
                            throw std::runtime_error("Quoted attribute value size exceeds maximum allowed length.");
                        }
                        current_attribute_value.push_back(c);
                        value_escape = false;
                    } else if (c == '\\') {
                        value_escape = true;
                    } else if (c == value_quote_char) {
                        // End of quoted value
                        emit(utility::trim_http_whitespace(current_attribute_name),
                             std::string(current_attribute_value)); // Quoted value is not trimmed here
                        current_attribute_name.clear();
                        current_attribute_value.clear();
                        value_quote_char = '\0';
                        parse_state      = AttributeParseState::AFTER_QUOTED_VALUE;
                    } else if (current_attribute_value.size() >= ATTRIBUTE_VALUE_MAX) {
                        throw std::runtime_error("Quoted attribute value size exceeds maximum allowed length.");
                    } else if (utility::is_control(c) && c != '\t') {
                        // RFC 7230 qdtext excludes control characters (except HTAB).
                        throw std::runtime_error("Control character in quoted attribute value.");
                    } else {
                        current_attribute_value.push_back(c);
                    }
                }
                break;

            case AttributeParseState::AFTER_QUOTED_VALUE:
                // After a quoted value, only optional whitespace may appear before the next delimiter.
                if (c == ';' || c == ',') {
                    parse_state = AttributeParseState::NAME;
                } else if (c != ' ' && c != '\t') {
                    throw std::runtime_error("Invalid character after quoted attribute value.");
                }
                break;
        }
        ++ptr;
    }

    // After the loop, handle any remaining attribute that was being parsed
    if (!current_attribute_name.empty()) {
        if (parse_state == AttributeParseState::VALUE && (value_quote_char != '\0' || value_escape)) {
            throw std::runtime_error("Unterminated quoted attribute value at end of header string.");
        }
        // If ended in AFTER_QUOTED_VALUE state, value was quoted and already emitted.
        // If ended in NAME state, it's an attribute without a value.
        // If ended in VALUE state (unquoted), emit it.
        if (parse_state == AttributeParseState::NAME || parse_state == AttributeParseState::VALUE) {
            emit(utility::trim_http_whitespace(current_attribute_name), std::string(utility::trim_http_whitespace(current_attribute_value)));
        }
    }
}
} // namespace

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
    // The first occurrence of a name wins: emplace() never replaces.
    for_each_header_attribute(ptr, len,
                              [&dict](std::string_view name, std::string &&value) { dict.emplace(std::string(name), std::move(value)); });
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
parse_header_attributes(const std::string &header) {
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
 * This string lists compression algorithms supported by the server (if `QB_HAS_COMPRESSION` is defined),
 * typically with quality values (q-values) indicating preference. For example: "gzip;q=1.0, deflate;q=0.9".
 * Transfer codings such as `chunked` are intentionally not advertised in `Accept-Encoding`.
 *
 * @return A string suitable for use as an `Accept-Encoding` header value, typically sent by a client.
 */
[[nodiscard]] std::string
accept_encoding() {
    std::string algorithms_str;
#ifdef QB_HAS_COMPRESSION
    algorithms_str.reserve(64); // Pre-allocate for common cases
    const auto &decompress_factories = qb::compression::builtin::get_decompress_factories();
    bool        first_algorithm      = true;
    for (const auto &factory : decompress_factories) {
        if (!factory || factory->algorithm().empty())
            continue;
        if (!first_algorithm) {
            algorithms_str += ", ";
        }
        algorithms_str += factory->algorithm();

        // q-values are between 0 and 1, up to 3 decimal places.
        // weight is an integer, e.g., 1000 for q=1.0, 900 for q=0.9, 50 for q=0.05
        if (factory->weight() < 1000) {
            // Don't add q=1.0, as it's the default
            algorithms_str += ";q=";
            double q_val = static_cast<double>(factory->weight()) / 1000.0;
            char   buf[10]; // Buffer for "0.XXX"
            // std::to_chars for floating point with fixed precision is C++17
            auto [ptr, ec] = std::to_chars(buf, buf + sizeof(buf) - 1, q_val, std::chars_format::fixed, 3);
            if (ec == std::errc()) {
                *ptr = '\0'; // Null-terminate
                std::string_view q_str(buf);
                // Trim trailing zeros after decimal point, but keep at least one digit (e.g. 0.5, not 0.)
                size_t dot_pos = q_str.find('.');
                if (dot_pos != std::string_view::npos) {
                    size_t last_digit_to_keep = q_str.find_last_not_of('0');
                    if (last_digit_to_keep == dot_pos) {
                        // e.g., "0." from "0.000"
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
#endif
    return algorithms_str;
}

/**
 * @brief Selects a suitable `Content-Encoding` based on the client's `Accept-Encoding` header.
 *
 * This function parses the `accept_encoding_header` string (e.g., "gzip, deflate, br") from the client.
 * It then iterates through the server's available compression algorithms (if `QB_HAS_COMPRESSION` is defined)
 * and returns the name of the first algorithm found in the client's accepted list that is also supported
 * by the server. The order of encodings in the client's `Accept-Encoding` header is respected: q-values
 * only decide acceptability (q=0 or a malformed q excludes a coding), never rank, so the first acceptable
 * match wins. A wildcard `*` stands for any coding the field does not exclude, wherever the exclusion is
 * listed (RFC 9110 §12.5.3), so the exclusions are collected before any token is matched.
 *
 * @param accept_encoding_header The `Accept-Encoding` header value received from the client.
 * @return The name of the selected encoding (e.g., `"gzip"`, `"deflate"`), or an empty string
 *         if no suitable common encoding is found or if server-side compression is disabled.
 */
[[nodiscard]] std::string
content_encoding(std::string_view accept_encoding_header) {
#ifdef QB_HAS_COMPRESSION
    // Split client's Accept-Encoding header into individual tokens (encodings).
    // Delimiters include comma and semicolon (q-values are attached to tokens before this split).
    const std::vector<std::string> client_accepted_tokens = utility::split_string<std::string>(accept_encoding_header, ",");

    struct accepted_coding {
        std::string_view name;    ///< The coding, parameters stripped (a view into client_accepted_tokens)
        int              q_milli; ///< Its qvalue in thousandths; <= 0 excludes it (q=0 or malformed)
    };
    std::vector<accepted_coding> codings;
    codings.reserve(client_accepted_tokens.size());
    for (const auto &client_token_full : client_accepted_tokens) {
        std::string_view client_encoding_name = utility::trim_http_whitespace(client_token_full);
        const int        q_milli              = parse_accept_encoding_q(client_encoding_name);

        // Remove q-value part if present, e.g., "gzip;q=0.8" -> "gzip"
        auto q_param_pos = client_encoding_name.find(';');
        if (q_param_pos != std::string_view::npos) {
            client_encoding_name = client_encoding_name.substr(0, q_param_pos);
            client_encoding_name = utility::trim_http_whitespace(client_encoding_name); // Trim again after substr
        }
        codings.push_back({client_encoding_name, q_milli});
    }

    // A coding the field excludes, wherever it is listed: a wildcard must not resurrect it, even when
    // the exclusion comes AFTER the wildcard (Huly QB-492).
    const auto excluded = [&codings](std::string_view algo) {
        return std::any_of(codings.begin(), codings.end(), [&](const accepted_coding &c) {
            return c.q_milli <= 0 && !c.name.empty() && c.name != "*" && utility::iequals(c.name, algo);
        });
    };

    const auto &server_compress_factories = qb::compression::builtin::get_compress_factories();
    for (const auto &coding : codings) {
        if (coding.q_milli <= 0 || coding.name.empty()) {
            continue; // Explicitly unacceptable (`q=0`), a malformed q-value, or an empty token.
        }

        if (coding.name == "*") {
            // The wildcard stands for any coding the field does not exclude; the server picks its first.
            for (const auto &server_factory : server_compress_factories) {
                if (server_factory && !excluded(server_factory->algorithm())) {
                    return server_factory->algorithm();
                }
            }
            continue;
        }

        for (const auto &server_factory : server_compress_factories) {
            if (server_factory && utility::iequals(server_factory->algorithm(), coding.name)) {
                return server_factory->algorithm(); // Found a directly supported match
            }
        }
    }
#else
    // Suppress unused parameter warning if ZLIB support is not compiled in.
    (void) accept_encoding_header;
#endif
    return ""; // No suitable encoding found or compression disabled
}

namespace {
/**
 * @brief The charset of a Content-Type parameter list in the PLAIN shape, read without the state
 *        machine's accumulators: `name=value` tokens separated by `;` or `,`, no quote, no backslash,
 *        no control byte (HTAB apart), no byte above 0x7E, at most 256 bytes -- the shape every
 *        `application/json; charset=utf-8` has.
 *
 * The verdict is for_each_header_attribute()'s, read from the same bytes: the FIRST `charset` decides,
 * an empty one included; a name is the segment before its `=`, trimmed. Returns false -- and leaves the
 * verdict to the machine, whose exceptions keep the default -- for any list outside that shape, and for
 * the two plain-looking lists the machine refuses or rewrites: a `=` with no name before it, and a name
 * with whitespace inside (the machine joins its pieces).
 */
bool
plain_charset(std::string_view params, std::string &out) noexcept {
    if (params.size() > 256) {
        return false;
    }
    for (const char c : params) {
        const auto uc = static_cast<unsigned char>(c);
        if ((uc < 0x20 && c != '\t') || uc > 0x7E || c == '"' || c == '\'' || c == '\\') {
            return false;
        }
    }
    bool seen = false;
    while (!params.empty()) {
        const auto             end     = params.find_first_of(";,");
        const std::string_view segment = params.substr(0, end);
        params.remove_prefix(end == std::string_view::npos ? params.size() : end + 1);
        const auto             eq   = segment.find('=');
        const std::string_view name = utility::trim_http_whitespace(segment.substr(0, eq));
        if (name.find_first_of(" \t") != std::string_view::npos) {
            return false;
        }
        if (eq != std::string_view::npos && name.empty()) {
            return false;
        }
        if (!seen && utility::iequals(name, "charset")) {
            seen = true;
            if (eq != std::string_view::npos) {
                out.assign(utility::trim_http_whitespace(segment.substr(eq + 1)));
            }
        }
    }
    return true;
}
} // namespace

void
Headers::ContentType::assign(std::string_view content_type_str) {
    _type.clear();
    _charset.clear();
    const auto semicolon_pos = content_type_str.find(';');
    const auto media_type =
        utility::trim_http_whitespace(semicolon_pos == std::string_view::npos ? content_type_str : content_type_str.substr(0, semicolon_pos));
    if (media_type.empty()) {
        return; // the defaults, reported from the shared strings
    }
    _type.assign(media_type);

    if (semicolon_pos != std::string_view::npos) {
        // The parameters' FIRST `charset` decides, and a malformed parameter list anywhere keeps the
        // default -- the rules of parse_header_attributes() and its map, read here without building the map:
        // this runs for every received message whose typed Content-Type is read (Huly QB-506).
        const auto params = content_type_str.substr(semicolon_pos + 1);
        if (plain_charset(params, _charset)) {
            return;
        }
        _charset.clear();
        try {
            bool seen = false;
            for_each_header_attribute(params.data(), params.size(), [&](std::string_view name, std::string &&value) {
                if (!seen && utility::iequals(name, "charset")) {
                    seen     = true;
                    _charset = std::move(value); // empty keeps the default
                }
            });
        } catch (...) {
            _charset.clear(); // keep the default charset
        }
    }
}

std::pair<std::string, std::string>
Headers::ContentType::parse(std::string_view content_type_str) {
    const ContentType parsed{content_type_str};
    return {parsed.type(), parsed.charset()};
}

void
Headers::derive_content_type() const noexcept {
    const auto it = _headers.find(content_type_name);
    if (it != _headers.cend() && !it->second.empty()) {
        _content_type.assign(it->second.front());
    } else {
        _content_type = ContentType{}; // absent: the defaults, nothing allocated
    }
    _content_type_derived = true;
}
} // namespace qb::http

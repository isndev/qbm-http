
#ifdef QB_IO_WITH_ZLIB
#include <qb/io/compression.h>
#endif
#include "./headers.h"

namespace qb::http {

/**
 * @brief Parse HTTP header attributes from raw data
 * @param ptr Pointer to header attribute data
 * @param len Length of header attribute data
 * @return Map of attribute names to values
 *
 * Parses header attributes in the format "name1=value1; name2=value2" and returns
 * a case-insensitive map of attribute names to values. This is commonly used for
 * parsing complex HTTP headers like Content-Type, Content-Disposition, etc.
 *
 * Example: "type=text/html; charset=utf-8" would parse to:
 * {"type": "text/html", "charset": "utf-8"}
 *
 * Supports both quoted and unquoted values, and properly handles special characters.
 *
 * @throws std::runtime_error If parsing fails due to malformed data
 */
qb::icase_unordered_map<std::string>
parse_header_attributes(const char *ptr, const size_t len) {
    qb::icase_unordered_map<std::string> dict;

    enum AttributeParseState {
        ATTRIBUTE_PARSE_NAME,
        ATTRIBUTE_PARSE_VALUE,
        ATTRIBUTE_PARSE_IGNORE
    } parse_state = ATTRIBUTE_PARSE_NAME;

    // misc other variables used for parsing
    const char *const end = ptr + len;
    std::string       attribute_name;
    std::string       attribute_value;
    char              value_quote_character = '\0';

    // iterate through each character
    while (ptr < end) {
        switch (parse_state) {
            case ATTRIBUTE_PARSE_NAME:
                // parsing attribute name
                if (*ptr == '=') {
                    // end of name found (OK if empty)
                    value_quote_character = '\0';
                    parse_state           = ATTRIBUTE_PARSE_VALUE;
                } else if (*ptr == ';' || *ptr == ',') {
                    // ignore empty attribute names since this may occur naturally
                    // when quoted values are encountered
                    if (!attribute_name.empty()) {
                        // value is empty (OK)
                        dict.emplace(attribute_name, attribute_value);
                        attribute_name.erase();
                    }
                } else if (*ptr != ' ') { // ignore whitespace
                    // check if control character detected, or max sized exceeded
                    if (utility::is_control(*ptr) ||
                        attribute_name.size() >= ATTRIBUTE_NAME_MAX)
                        throw std::runtime_error(
                            "ctrl in name found or max attribute name length");
                    // character is part of the name
                    attribute_name.push_back(*ptr);
                }
                break;

            case ATTRIBUTE_PARSE_VALUE:
                // parsing attribute value
                if (value_quote_character == '\0') {
                    // value is not (yet) quoted
                    if (*ptr == ';' || *ptr == ',') {
                        // end of value found (OK if empty)
                        dict.emplace(attribute_name, attribute_value);
                        attribute_name.erase();
                        attribute_value.erase();
                        parse_state = ATTRIBUTE_PARSE_NAME;
                    } else if (*ptr == '\'' || *ptr == '"') {
                        if (attribute_value.empty()) {
                            // begin quoted value
                            value_quote_character = *ptr;
                        } else if (attribute_value.size() >= ATTRIBUTE_VALUE_MAX) {
                            // max size exceeded
                            throw std::runtime_error("max attribute size");
                        } else {
                            // assume character is part of the (unquoted) value
                            attribute_value.push_back(*ptr);
                        }
                    } else if (*ptr != ' ' ||
                               !attribute_value
                                    .empty()) { // ignore leading unquoted whitespace
                        // check if control character detected, or max sized exceeded
                        if (utility::is_control(*ptr) ||
                            attribute_value.size() >= ATTRIBUTE_VALUE_MAX)
                            throw std::runtime_error(
                                "ctrl in value found or max attribute value length");
                        // character is part of the (unquoted) value
                        attribute_value.push_back(*ptr);
                    }
                } else {
                    // value is quoted
                    if (*ptr == value_quote_character) {
                        // end of value found (OK if empty)
                        dict.emplace(attribute_name, attribute_value);
                        attribute_name.erase();
                        attribute_value.erase();
                        parse_state = ATTRIBUTE_PARSE_IGNORE;
                    } else if (attribute_value.size() >= ATTRIBUTE_VALUE_MAX) {
                        // max size exceeded
                        throw std::runtime_error("max attribute value length");
                    } else {
                        // character is part of the (quoted) value
                        attribute_value.push_back(*ptr);
                    }
                }
                break;

            case ATTRIBUTE_PARSE_IGNORE:
                // ignore everything until we reach a comma "," or semicolon ";"
                if (*ptr == ';' || *ptr == ',')
                    parse_state = ATTRIBUTE_PARSE_NAME;
                break;
        }

        ++ptr;
    }

    // handle last attribute in string
    dict.emplace(attribute_name, attribute_value);

    return dict;
}

/**
 * @brief Parse HTTP header attributes from a string
 * @param header Header attribute string
 * @return Map of attribute names to values
 *
 * String overload that converts to raw pointer and length for processing.
 *
 * @see parse_header_attributes(const char*, size_t)
 */
qb::icase_unordered_map<std::string>
parse_header_attributes(std::string const &header) {
    return parse_header_attributes(header.c_str(), header.size());
}

/**
 * @brief Parse HTTP header attributes from a string_view
 * @param header Header attribute string_view
 * @return Map of attribute names to values
 *
 * String_view overload that converts to raw pointer and length for processing.
 * More efficient than the string version as it avoids copying.
 *
 * @see parse_header_attributes(const char*, size_t)
 */
qb::icase_unordered_map<std::string>
parse_header_attributes(std::string_view const &header) {
    return parse_header_attributes(header.data(), header.size());
}

/**
 * @brief Generate an Accept-Encoding HTTP header value
 * @return String containing supported encodings with quality values
 *
 * Builds a properly formatted Accept-Encoding header value based on available
 * decompression algorithms in the system. Each algorithm is listed with an
 * appropriate quality value (q-value) based on its weight.
 *
 * The header always includes "chunked" as the fallback encoding.
 *
 * Example: "gzip;q=1.0, deflate;q=0.9, chunked"
 */
[[nodiscard]] std::string
accept_encoding() {
    std::string algorithms;
#ifdef QB_IO_WITH_ZLIB
    algorithms.reserve(64);
    for (auto factory : qb::compression::builtin::get_decompress_factories()) {
        auto weight = factory->weight();
        algorithms += factory->algorithm();
        if (weight <= 1000) {
            algorithms += ";q=";
            algorithms += std::to_string(weight / 1000);
            algorithms += '.';
            algorithms += std::to_string(weight % 1000);
        }
        algorithms += ", ";
    }
#endif
    algorithms += "chunked";
    return algorithms;
}

/**
 * @brief Determine the best content encoding to use
 * @param accept_encoding Accept-Encoding header value from client
 * @return Selected encoding algorithm or empty string if none suitable
 *
 * Analyzes the Accept-Encoding header from a client request and selects
 * the best compression algorithm that both the client and server support.
 *
 * The function respects the order of encodings in the Accept-Encoding header,
 * which typically represents client preference.
 */
[[nodiscard]] std::string
content_encoding(std::string_view const &accept_encoding) {
#ifdef QB_IO_WITH_ZLIB
    auto tokens    = utility::split_string<std::string>(accept_encoding, ",; \t");
    auto factories = qb::compression::builtin::get_compress_factories();
    for (const auto &token : tokens) {
        for (const auto &factory : factories) {
            if (utility::iequals(factory->algorithm(), std::string(token)))
                return factory->algorithm();
        }
    }
#endif
    return "";
}

template struct qb::http::THeaders<std::string>;
template struct qb::http::THeaders<std::string_view>;

} // namespace qb::http

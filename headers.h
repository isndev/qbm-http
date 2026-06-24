/**
 * @file qbm/http/headers.h
 * @brief Defines HTTP header management classes, including `Headers` and `ContentType`,
 *        and utility functions for header attribute parsing and content encoding negotiation.
 *
 * This file provides the `Headers` class for managing collections of HTTP headers,
 * supporting case-insensitive header names and multi-value headers. It includes a nested
 * `ContentType` class for specialized parsing and handling of `Content-Type` headers.
 * Additionally, free functions are provided for parsing complex header attributes (like those
 * in `Content-Type` or `Content-Disposition`) and for assisting with content encoding selection
 * (generating `Accept-Encoding` strings and interpreting client preferences).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <string>      // For std::string
#include <string_view> // For std::string_view
#include <type_traits> // For std::is_constructible_v, std::is_same_v
#include <utility>     // For std::pair, std::move, std::forward
#include <vector>      // For std::vector (used to store multiple header values)

#include <qb/system/container/unordered_map.h> // For qb::icase_unordered_map

#include "./types.h"   // For common HTTP types (though not directly used in Headers API, often a peer include)
#include "./utility.h" // For utility::split_string, utility::iequals, utility::trim_http_whitespace

namespace qb::http {
/**
 * @brief Maximum allowed length for HTTP header attribute names in bytes (e.g., `charset` in `Content-Type`).
 * Helps prevent excessive memory usage or potential denial-of-service by overly long attribute names.
 */
constexpr uint32_t ATTRIBUTE_NAME_MAX = 1024; // 1 Kilobyte

/**
 * @brief Maximum allowed length for HTTP header attribute values in bytes (e.g., `utf-8` in `charset=utf-8`).
 * Large enough for filenames in Content-Disposition; small enough to bound memory on hostile inputs.
 */
constexpr uint32_t ATTRIBUTE_VALUE_MAX = 8192;

/**
 * @brief Type alias for a map storing HTTP headers.
 *
 * Uses a case-insensitive string key (for header names like "Content-Type", "Authorization")
 * and a `std::vector<std::string>` for header values, allowing for multiple headers with
 * the same name (e.g., multiple `Set-Cookie` headers).
 */
using headers_map = qb::icase_unordered_map<std::vector<std::string>>;

/**
 * @brief Parses attributes from an HTTP header value string (e.g., parameters from `Content-Type` or `Content-Disposition`).
 *
 * This function handles formats like: `"name1=value1; name2=value2; name3=\"quoted value\""`.
 * It supports both quoted and unquoted attribute values and correctly handles whitespace and delimiters (`;` or `,`).
 * Attribute names are treated as case-insensitive due to the return type `qb::icase_unordered_map`.
 *
 * @param ptr Pointer to the start of the header attribute data.
 * @param len Length of the header attribute data in bytes.
 * @return A `qb::icase_unordered_map<std::string>` where keys are attribute names (case-insensitive) and values are attribute values.
 * @throws std::runtime_error If parsing fails due to malformed data (e.g., control characters, excessive length of names/values, unterminated
 * quotes).
 */
[[nodiscard]] qb::icase_unordered_map<std::string> parse_header_attributes(const char *ptr, size_t len);

/**
 * @brief Parses attributes from an HTTP header value `std::string`.
 * Overload that delegates to the `const char*` version.
 * @param header The header value string to parse.
 * @return A map of attribute names to values.
 * @see parse_header_attributes(const char*, size_t)
 */
[[nodiscard]] qb::icase_unordered_map<std::string> parse_header_attributes(const std::string &header);

/**
 * @brief Parses attributes from an HTTP header value `std::string_view`.
 * Overload that delegates to the `const char*` version. This version is efficient as it avoids string copying for the input.
 * @param header The header value `std::string_view` to parse.
 * @return A map of attribute names to values.
 * @see parse_header_attributes(const char*, size_t)
 */
[[nodiscard]] qb::icase_unordered_map<std::string> parse_header_attributes(std::string_view header);

/**
 * @brief Generates an `Accept-Encoding` header value string based on server capabilities for decompression.
 *
 * This string lists compression algorithms supported by the server for decompressing request bodies
 * (if `QB_HAS_COMPRESSION` is defined), usually with quality values (q-values) indicating preference.
 * For example: `"gzip;q=1.0, deflate;q=0.9"`. Transfer codings such as `chunked` are intentionally not included.
 * This function is useful for a client to indicate to a server what encodings it can accept in a response.
 *
 * @return A string suitable for use as an `Accept-Encoding` header value.
 */
[[nodiscard]] std::string accept_encoding();

/**
 * @brief Selects a suitable `Content-Encoding` for a response based on the client's `Accept-Encoding` header.
 *
 * Compares the client's accepted encodings with the server's supported compression algorithms
 * (if `QB_HAS_COMPRESSION` is defined) and selects the best match. The selection logic typically respects
 * the client's preference order but does not currently parse q-values for complex weighting.
 *
 * @param accept_encoding_header The `Accept-Encoding` header value received from the client.
 * @return The name of the selected encoding (e.g., `"gzip"`, `"deflate"`), or an empty string
 *         if no suitable common encoding is found or if server-side compression is disabled.
 */
[[nodiscard]] std::string content_encoding(std::string_view accept_encoding_header);

/**
 * @brief Manages a collection of HTTP headers with owning `std::string`
 *        values and case-insensitive lookup.
 *
 * Features:
 * - Case-insensitive lookup for header names.
 * - Support for multiple values for a single header name
 *   (`Set-Cookie`, `Via`, etc.).
 * - Nested `ContentType` helper for `Content-Type`.
 *
 * @note Historically this class was templated on `StringType` to
 * support both `std::string` (owning) and `std::string_view`
 * (zero-copy) header values. The view mode has been retired: the qb
 * input pipe relocates buffer bytes between reads (reorder /
 * realloc), and the async request lifecycle (shared `Context`,
 * middleware chain, coroutine plan) makes it impossible to guarantee
 * that captured views outlive the socket read.
 */
class Headers {
public:
    /** @brief Default MIME type used if `Content-Type` is not specified or cannot be parsed. */
    static constexpr std::string_view default_content_type = "application/octet-stream";
    /** @brief Default charset used if not specified in `Content-Type` or if parsing fails. */
    static constexpr std::string_view default_charset = "utf-8";

    /** @brief Type alias for the underlying map storing headers. Keys are case-insensitive header names. */
    using headers_map_type = qb::icase_unordered_map<std::vector<std::string>>;

    /**
     * @brief Represents and parses the HTTP `Content-Type` header.
     *
     * This class provides convenient access to the main MIME type (e.g., `"text/html"`)
     * and the charset parameter (e.g., `"utf-8"`) from a `Content-Type` header string.
     */
    class ContentType {
    public:
        /**
         * @brief Parses a `Content-Type` header string into its MIME type and charset components.
         *
         * If parsing fails or components are missing, defaults are used:
         * - MIME type defaults to `Headers::default_content_type` (`application/octet-stream`).
         * - Charset defaults to `Headers::default_charset` (`utf-8`).
         * The parsing logic handles formats like `type/subtype` and `type/subtype; charset=value`,
         * including optional whitespace, case-insensitive parameter names, quoted values and quoted-pair escapes.
         *
         * @param content_type_str The full `Content-Type` header string, as a `std::string_view`.
         * @return A `std::pair` containing the MIME type (as `std::string`) as the first element
         *         and the charset (as `std::string`) as the second.
         */
        [[nodiscard]] static std::pair<std::string, std::string>
        parse(std::string_view content_type_str) {
            std::pair<std::string, std::string> ret{std::string(default_content_type), std::string(default_charset)};

            const auto semicolon_pos = content_type_str.find(';');
            const auto media_type    = utility::trim_http_whitespace(
                semicolon_pos == std::string_view::npos ? content_type_str : content_type_str.substr(0, semicolon_pos));
            if (media_type.empty()) {
                return ret;
            }
            ret.first = std::string(media_type);

            if (semicolon_pos != std::string_view::npos) {
                try {
                    auto attrs      = parse_header_attributes(content_type_str.substr(semicolon_pos + 1));
                    auto charset_it = attrs.find("charset");
                    if (charset_it != attrs.end() && !charset_it->second.empty()) {
                        ret.second = charset_it->second;
                    }
                } catch (...) {
                    ret.second = std::string(default_charset);
                }
            }

            return ret;
        }

    private:
        /** @brief Pair storing the MIME type (`.first`) and charset (`.second`). */
        std::pair<std::string, std::string> _type_charset;

    public:
        /**
         * @brief Constructs a `ContentType` object by parsing the given header string.
         * If `content_type_str` is empty, defaults are used.
         * @param content_type_str The `Content-Type` header string (as `std::string_view`).
         */
        explicit ContentType(std::string_view content_type_str = "")
            : _type_charset(parse(content_type_str)) {}

        ContentType(const ContentType &) = default;

        ContentType(ContentType &&) noexcept = default;

        ContentType &operator=(const ContentType &) = default;

        ContentType &operator=(ContentType &&) noexcept = default;

        /**
         * @brief Gets the MIME type component of the Content-Type.
         * @return A constant reference to the MIME type string (e.g., `"text/html"`).
         */
        [[nodiscard]] const std::string &
        type() const noexcept {
            return _type_charset.first;
        }

        /**
         * @brief Gets the charset component of the Content-Type.
         * @return A constant reference to the charset string (e.g., `"utf-8"`).
         */
        [[nodiscard]] const std::string &
        charset() const noexcept {
            return _type_charset.second;
        }
    };

protected:
    /** @brief The map storing all headers. Keys are case-insensitive header names. Values are vectors of `std::string`. */
    headers_map_type _headers;
    /** @brief Parsed `Content-Type` header object, providing easy access to MIME type and charset. */
    ContentType _content_type;

    template <typename HeaderNameType>
    [[nodiscard]] static bool
    is_content_type_header(const HeaderNameType &name) noexcept {
        if constexpr (std::is_convertible_v<HeaderNameType, std::string_view>) {
            return utility::iequals(std::string_view{name}, "Content-Type");
        } else {
            return false;
        }
    }

public:
    /** @brief Default constructor. Initializes an empty set of headers and a default `ContentType`. */
    Headers() noexcept
        : _content_type(default_content_type) {}

    /**
     * @brief Constructs `Headers` with an initial map of headers.
     * The `Content-Type` member is initialized by parsing the "Content-Type" header from `initial_headers`,
     * or defaults if not present.
     * @param initial_headers A map of headers to initialize with. The map is moved.
     */
    explicit Headers(headers_map_type initial_headers)
        : _headers(std::move(initial_headers))
        , _content_type(default_content_type) {
        refresh_content_type();
    }

    Headers(const Headers &) = default;

    Headers(Headers &&) noexcept        = default; // Assuming headers_map_type and ContentType are noexcept-movable
    Headers &operator=(const Headers &) = default;

    Headers &operator=(Headers &&) noexcept = default;

    // Assuming headers_map_type and ContentType are noexcept-move-assignable

    /**
     * @brief Provides mutable access to the underlying map of headers.
     * @return A reference to the `headers_map_type`.
     */
    [[nodiscard]] headers_map_type &
    headers() noexcept {
        return _headers;
    }

    /**
     * @brief Provides constant access to the underlying map of headers.
     * @return A constant reference to the `headers_map_type`.
     */
    [[nodiscard]] const headers_map_type &
    headers() const noexcept {
        return _headers;
    }

    /**
     * @brief Re-parses the cached Content-Type helper from the raw header map.
     *
     * Call this after direct mutation through `headers()`. The typed mutators
     * (`set_content_type`, `set_header`, `add_header`, `remove_header`) keep it
     * synchronized automatically.
     */
    void
    refresh_content_type() noexcept {
        const auto it = _headers.find("Content-Type");
        if (it != _headers.end() && !it->second.empty()) {
            _content_type = ContentType{it->second.front()};
        } else {
            _content_type = ContentType{default_content_type};
        }
    }

    /**
     * @brief Retrieves the value of a specific header.
     *
     * If multiple headers with the same name exist (e.g., `Set-Cookie`), `index` specifies which one to retrieve (0-based).
     * Header names are looked up case-insensitively.
     *
     * @tparam HeaderNameType The type of the header name (e.g., `const char*`, `std::string`, `std::string_view`).
     * @param name The name of the header to retrieve.
     * @param index The 0-based index for headers with multiple values. Defaults to 0 (the first value).
     * @return A constant reference to the header value if present, otherwise to a process-wide static
     *         empty string. The reference is always safe to keep for the message's lifetime — it is
     *         never a reference to a temporary. For a custom fallback, use `header_or()`.
     */
    template <typename HeaderNameType>
    [[nodiscard]] const std::string &
    header(HeaderNameType &&name, std::size_t index = 0) const {
        const auto it = _headers.find(std::forward<HeaderNameType>(name));
        if (it != _headers.cend() && index < it->second.size()) {
            return it->second[index];
        }
        return detail::empty_string_value;
    }

    /**
     * @brief Retrieves a header value, or `fallback` if the header is absent / `index` is out of bounds.
     *
     * Returns BY VALUE, so the fallback (literal, temporary, or lvalue) is always safe — no lifetime
     * caveat. A present header (even with an empty value) yields the header's value, not the fallback.
     *
     * @tparam HeaderNameType The type of the header name.
     * @param name The name of the header to retrieve.
     * @param fallback Returned when the header is absent (taken by value, moved out on a miss).
     * @param index The 0-based index for headers with multiple values. Defaults to 0.
     */
    template <typename HeaderNameType>
    [[nodiscard]] std::string
    header_or(HeaderNameType &&name, std::string fallback, std::size_t index = 0) const {
        const auto it = _headers.find(std::forward<HeaderNameType>(name));
        if (it != _headers.cend() && index < it->second.size()) {
            return it->second[index];
        }
        return fallback;
    }

    /**
     * @brief Retrieves and parses attributes of a specific header value using `parse_header_attributes`.
     *
     * @tparam HeaderNameType The type of the header name.
     * @param name The name of the header whose value's attributes are to be parsed.
     * @param index The 0-based index if the header has multiple values. Defaults to 0.
     * @param default_to_parse A `std::string_view` to parse instead when the header is absent or empty.
     *                         Defaults to empty (→ an empty attribute map).
     * @return A `qb::icase_unordered_map<std::string>` of attribute names to values.
     */
    template <typename HeaderNameType>
    [[nodiscard]] qb::icase_unordered_map<std::string>
    attributes(HeaderNameType &&name, std::size_t index = 0, std::string_view default_to_parse = "") const {
        // `header()` returns a stable reference (the stored value, or the static empty on a miss);
        // `default_to_parse` is a view valid for this call. Both are safe to hand to the parser.
        const std::string &value = header(std::forward<HeaderNameType>(name), index);
        return parse_header_attributes(!value.empty() ? std::string_view(value) : default_to_parse);
    }

    /**
     * @brief Checks if a header with the given name exists.
     * Header names are checked case-insensitively.
     * @tparam HeaderNameType The type of the header name.
     * @param name The name of the header to check.
     * @return `true` if at least one header with the given name exists, `false` otherwise.
     */
    template <typename HeaderNameType>
    [[nodiscard]] bool
    has_header(HeaderNameType &&name) const noexcept {
        return _headers.has(std::forward<HeaderNameType>(name));
    }

    /**
     * @brief Sets the `Content-Type` header value and updates the internal parsed `_content_type`.
     * Any existing `Content-Type` headers are replaced with this single value.
     * @param value The full `Content-Type` header value string (e.g., "text/html; charset=utf-8").
     *              This `std::string_view` is used to parse the `ContentType` and to set the header.
     */
    void
    set_content_type(std::string_view value) {
        _content_type = ContentType{value};
        set_header("Content-Type", std::string(value));
    }

    /**
     * @brief Gets the parsed `ContentType` object, allowing easy access to MIME type and charset.
     * @return A constant reference to the internal `ContentType` object.
     */
    [[nodiscard]] constexpr const ContentType &
    content_type() const noexcept {
        return _content_type;
    }

    /**
     * @brief Adds a header name-value pair. If a header with the same name already exists,
     * this new value is appended to its list of values (supporting multi-value headers).
     * @tparam HeaderNameType Type of the header name (string-like).
     * @tparam HeaderValueType Type of the header value (convertible to `std::string`).
     * @param name The name of the header. Forwarded to map key construction.
     * @param value The value for the header. Forwarded to `std::string` construction and pushed into vector.
     */
    template <typename HeaderNameType, typename HeaderValueType>
    void
    add_header(HeaderNameType &&name, HeaderValueType &&value) {
        const bool is_content_type = is_content_type_header(name);
        // Map/vector operations can allocate
        auto &values_vec = _headers[std::forward<HeaderNameType>(name)];
        values_vec.emplace_back(std::forward<HeaderValueType>(value));
        if (is_content_type && values_vec.size() == 1) {
            _content_type = ContentType{values_vec.front()};
        }
    }

    /**
     * @brief Removes all occurrences of a header by its name (case-insensitive).
     * @tparam HeaderNameType The type of the header name.
     * @param name The name of the header to remove.
     */
    template <typename HeaderNameType>
    void
    remove_header(HeaderNameType &&name) noexcept {
        const bool is_content_type = is_content_type_header(name);
        // Assuming icase_unordered_map::erase(key) is noexcept
        _headers.erase(std::forward<HeaderNameType>(name));
        if (is_content_type) {
            _content_type = ContentType{default_content_type};
        }
    }

    /**
     * @brief Sets a header name-value pair, replacing any existing header(s) with the same name.
     * If a header with the same name exists, all its current values are cleared, and the new
     * `value` becomes its only value.
     * @tparam HeaderNameType Type of the header name.
     * @tparam HeaderValueType Type of the header value (convertible to `std::string`).
     * @param name The name of the header. Forwarded to map key construction.
     * @param value The value to set for the header. Forwarded to `std::string` construction.
     */
    template <typename HeaderNameType, typename HeaderValueType>
    void
    set_header(HeaderNameType &&name, HeaderValueType &&value) {
        const bool is_content_type = is_content_type_header(name);
        // Map/vector operations can allocate
        auto &values_vec = _headers[std::forward<HeaderNameType>(name)];
        values_vec.clear();
        values_vec.emplace_back(std::forward<HeaderValueType>(value));
        if (is_content_type) {
            _content_type = ContentType{values_vec.front()};
        }
    }

    /**
     * @brief Returns the total number of unique header names.
     * @return The count of distinct header names in the container.
     * @note This counts unique header names, not total values. For multi-value headers,
     *       each name is counted once regardless of how many values it has.
     */
    [[nodiscard]] std::size_t
    header_count() const noexcept {
        return _headers.size();
    }

    /**
     * @brief Checks if the number of headers exceeds a security limit.
     * @param max_headers Maximum allowed number of unique header names.
     * @return `true` if the header count exceeds the limit, `false` otherwise.
     * @note This is useful for DoS protection. Typical limit is 100 headers (RFC recommendation).
     * @see qb::http::protocol_limits::MAX_HEADERS_COUNT for the default recommended limit.
     */
    [[nodiscard]] bool
    exceeds_header_limit(std::size_t max_headers = 100) const noexcept {
        return _headers.size() > max_headers;
    }
};

/** @brief Shorthand alias for `Headers`, often used for brevity. */
using headers = Headers;
} // namespace qb::http

/**
 * @file qbm/http/headers.h
 * @brief Defines HTTP header management classes, including `THeaders` and `ContentType`,
 *        and utility functions for header attribute parsing and content encoding negotiation.
 *
 * This file provides the `THeaders` template class for managing collections of HTTP headers,
 * supporting case-insensitive header names and multi-value headers. It includes a nested
 * `ContentType` class for specialized parsing and handling of `Content-Type` headers.
 * Additionally, free functions are provided for parsing complex header attributes (like those
 * in `Content-Type` or `Content-Disposition`) and for assisting with content encoding selection
 * (generating `Accept-Encoding` strings and interpreting client preferences).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <string>       // For std::string
#include <string_view>  // For std::string_view
#include <vector>       // For std::vector (used to store multiple header values)
#include <utility>      // For std::pair, std::move, std::forward
#include <type_traits>  // For std::is_constructible_v, std::is_same_v

#include <qb/system/container/unordered_map.h> // For qb::icase_unordered_map

#include "./types.h"    // For common HTTP types (though not directly used in THeaders API, often a peer include)
#include "./utility.h"  // For utility::split_string, utility::iequals, utility::trim_http_whitespace

namespace qb::http {
    /**
     * @brief Maximum allowed length for HTTP header attribute names in bytes (e.g., `charset` in `Content-Type`).
     * Helps prevent excessive memory usage or potential denial-of-service by overly long attribute names.
     */
    constexpr uint32_t ATTRIBUTE_NAME_MAX = 1024; // 1 Kilobyte

    /**
     * @brief Maximum allowed length for HTTP header attribute values in bytes (e.g., `utf-8` in `charset=utf-8`).
     * Helps prevent excessive memory usage or potential denial-of-service by overly long attribute values.
     */
    constexpr uint32_t ATTRIBUTE_VALUE_MAX = 1024 * 1024; // 1 Megabyte

    /**
     * @brief Type alias for a map storing HTTP headers.
     *
     * Uses a case-insensitive string key (for header names like "Content-Type", "Authorization")
     * and a `std::vector<std::string>` for header values, allowing for multiple headers with
     * the same name (e.g., multiple `Set-Cookie` headers).
     * @note This specific alias uses `std::string` for values. `THeaders` is templated to allow `std::string_view` as well.
     */
    using headers_map = qb::icase_unordered_map<std::vector<std::string> >;

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
     * @throws std::runtime_error If parsing fails due to malformed data (e.g., control characters, excessive length of names/values, unterminated quotes).
     */
    [[nodiscard]] qb::icase_unordered_map<std::string>
    parse_header_attributes(const char *ptr, size_t len);

    /**
     * @brief Parses attributes from an HTTP header value `std::string`.
     * Overload that delegates to the `const char*` version.
     * @param header The header value string to parse.
     * @return A map of attribute names to values.
     * @see parse_header_attributes(const char*, size_t)
     */
    [[nodiscard]] qb::icase_unordered_map<std::string>
    parse_header_attributes(const std::string &header);

    /**
     * @brief Parses attributes from an HTTP header value `std::string_view`.
     * Overload that delegates to the `const char*` version. This version is efficient as it avoids string copying for the input.
     * @param header The header value `std::string_view` to parse.
     * @return A map of attribute names to values.
     * @see parse_header_attributes(const char*, size_t)
     */
    [[nodiscard]] qb::icase_unordered_map<std::string>
    parse_header_attributes(std::string_view header);

    /**
     * @brief Generates an `Accept-Encoding` header value string based on server capabilities for decompression.
     *
     * This string lists compression algorithms supported by the server for decompressing request bodies
     * (if `QB_IO_WITH_ZLIB` is defined), usually with quality values (q-values) indicating preference.
     * For example: `"gzip;q=1.0, deflate;q=0.9"`. The string "chunked" (a transfer encoding) is also typically appended.
     * This function is useful for a client to indicate to a server what encodings it can accept in a response.
     *
     * @return A string suitable for use as an `Accept-Encoding` header value.
     */
    [[nodiscard]] std::string accept_encoding();

    /**
     * @brief Selects a suitable `Content-Encoding` for a response based on the client's `Accept-Encoding` header.
     *
     * Compares the client's accepted encodings with the server's supported compression algorithms
     * (if `QB_IO_WITH_ZLIB` is defined) and selects the best match. The selection logic typically respects
     * the client's preference order but does not currently parse q-values for complex weighting.
     *
     * @param accept_encoding_header The `Accept-Encoding` header value received from the client.
     * @return The name of the selected encoding (e.g., `"gzip"`, `"deflate"`), or an empty string
     *         if no suitable common encoding is found or if server-side compression is disabled.
     */
    [[nodiscard]] std::string content_encoding(std::string_view accept_encoding_header);

    /**
     * @brief Template class for managing a collection of HTTP headers.
     *
     * This class provides a common interface and storage mechanism for HTTP headers, used by both
     * `Request` and `Response` objects. It features:
     * - Case-insensitive lookup for header names.
     * - Support for multiple values for a single header name (e.g., `Set-Cookie`).
     * - A nested `ContentType` class for specialized handling of `Content-Type` headers.
     * - Methods for adding, setting, retrieving, and removing headers.
     *
     * @tparam StringType The string type used for storing header names and values.
     *                  Typically `std::string` for mutable headers or `std::string_view`
     *                  for immutable, efficient read-only access (e.g., in `RequestView`).
     */
    template<typename StringType>
    class THeaders {
    public:
        /** @brief Default MIME type used if `Content-Type` is not specified or cannot be parsed. */
        static constexpr std::string_view default_content_type = "application/octet-stream";
        /** @brief Default charset used if not specified in `Content-Type` or if parsing fails. */
        static constexpr std::string_view default_charset = "utf-8";

        /** @brief Type alias for the underlying map storing headers. Keys are case-insensitive header names. */
        using headers_map_type = qb::icase_unordered_map<std::vector<StringType> >;

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
             * - MIME type defaults to `THeaders::default_content_type` (`application/octet-stream`).
             * - Charset defaults to `THeaders::default_charset` (`utf-8`).
             * The parsing logic attempts to handle formats like `type/subtype` and `type/subtype; charset=value`,
             * including trimming whitespace and handling quoted charset values (though full unquoting of quoted-pairs is not implemented here).
             *
             * @param content_type_str The full `Content-Type` header string, as a `std::string_view`.
             * @return A `std::pair` containing the MIME type (as `StringType`) as the first element
             *         and the charset (as `StringType`) as the second.
             */
            [[nodiscard]] static std::pair<StringType, StringType>
            parse(std::string_view content_type_str) {
                std::pair<StringType, StringType> ret{StringType(default_content_type), StringType(default_charset)};

                auto words = utility::split_string<StringType>(content_type_str, " \t;=");
                if (!words.size())
                    return ret;
                ret.first = std::move(words.front());
                if (words.size() == 3 && words[1] == "charset") {
                    auto &charset = words[2];
                    ret.second = charset.substr(charset.front() == '"' ? 1 : 0,
                                                charset.back() == '"'
                                                    ? charset.size() - 2
                                                    : std::string::npos);
                }
                return ret;
            }

        private:
            /** @brief Pair storing the MIME type (`.first`) and charset (`.second`). */
            std::pair<StringType, StringType> _type_charset;

        public:
            /**
             * @brief Constructs a `ContentType` object by parsing the given header string.
             * If `content_type_str` is empty, defaults are used.
             * @param content_type_str The `Content-Type` header string (as `std::string_view`).
             */
            explicit ContentType(std::string_view content_type_str = "")
                : _type_charset(parse(content_type_str)) {
            }

            ContentType(const ContentType &) = default;

            ContentType(ContentType &&) noexcept = default;

            ContentType &operator=(const ContentType &) = default;

            ContentType &operator=(ContentType &&) noexcept = default;

            /**
             * @brief Gets the MIME type component of the Content-Type.
             * @return A constant reference to the MIME type string (e.g., `"text/html"`).
             */
            [[nodiscard]] const StringType &type() const noexcept {
                return _type_charset.first;
            }

            /**
             * @brief Gets the charset component of the Content-Type.
             * @return A constant reference to the charset string (e.g., `"utf-8"`).
             */
            [[nodiscard]] const StringType &charset() const noexcept {
                return _type_charset.second;
            }
        };

    protected:
        /** @brief The map storing all headers. Keys are case-insensitive header names. Values are vectors of `StringType`. */
        headers_map_type _headers;
        /** @brief Parsed `Content-Type` header object, providing easy access to MIME type and charset. */
        ContentType _content_type;

    public:
        /** @brief Default constructor. Initializes an empty set of headers and a default `ContentType`. */
        THeaders() noexcept : _content_type(default_content_type) {
        }

        /**
         * @brief Constructs `THeaders` with an initial map of headers.
         * The `Content-Type` member is initialized by parsing the "Content-Type" header from `initial_headers`,
         * or defaults if not present.
         * @param initial_headers A map of headers to initialize with. The map is moved.
         */
        explicit THeaders(headers_map_type initial_headers)
            : _headers(std::move(initial_headers))
              , _content_type(header("Content-Type", 0, StringType(default_content_type))) {
        }

        THeaders(const THeaders &) = default;

        THeaders(THeaders &&) noexcept = default; // Assuming headers_map_type and ContentType are noexcept-movable
        THeaders &operator=(const THeaders &) = default;

        THeaders &operator=(THeaders &&) noexcept = default;

        // Assuming headers_map_type and ContentType are noexcept-move-assignable

        /**
         * @brief Provides mutable access to the underlying map of headers.
         * @return A reference to the `headers_map_type`.
         */
        [[nodiscard]] headers_map_type &headers() noexcept {
            return _headers;
        }

        /**
         * @brief Provides constant access to the underlying map of headers.
         * @return A constant reference to the `headers_map_type`.
         */
        [[nodiscard]] const headers_map_type &headers() const noexcept {
            return _headers;
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
         * @param not_found_value The value to return (as a `StringType` reference) if the header is not found or the index is out of bounds.
         *                        Defaults to a static empty `StringType`.
         * @return A constant reference to the header value string if found. If not found or index is invalid,
         *         returns a reference to `not_found_value` (or a static empty `StringType` if `not_found_value` was the default empty string).
         */
        template<typename HeaderNameType>
        [[nodiscard]] const StringType &
        header(HeaderNameType &&name, std::size_t index = 0, const StringType &not_found_value = StringType{}) const {
            // Use a static empty string to return a reference to for the default case,
            // especially important if StringType is std::string to avoid dangling references.
            static const StringType static_empty_string_value{};

            const auto it = _headers.find(std::forward<HeaderNameType>(name));
            if (it != _headers.cend() && index < it->second.size()) {
                return it->second[index];
            }
            // If the provided not_found_value is the default-constructed one, return our static empty one.
            // This comparison is safe for std::string and std::string_view (empty views compare equal).
            if (not_found_value == StringType{}) {
                return static_empty_string_value;
            }
            return not_found_value;
        }

        /**
         * @brief Retrieves and parses attributes of a specific header value using `parse_header_attributes`.
         *
         * @tparam HeaderNameType The type of the header name.
         * @param name The name of the header whose value's attributes are to be parsed.
         * @param index The 0-based index if the header has multiple values. Defaults to 0.
         * @param default_value_for_parsing A `std::string_view` to parse if the header itself is not found.
         *                                   Defaults to an empty string_view, resulting in an empty attribute map.
         * @return A `qb::icase_unordered_map<std::string>` of attribute names to values.
         *         Returns an empty map if the header is not found and `default_value_for_parsing` is empty.
         */
        template<typename HeaderNameType>
        [[nodiscard]] qb::icase_unordered_map<std::string>
        attributes(HeaderNameType &&name, std::size_t index = 0,
                   std::string_view default_value_for_parsing = "") const {
            // Get the header value. If StringType is std::string_view, this is efficient.
            // If StringType is std::string, header() returns const std::string&.
            // parse_header_attributes takes std::string_view, so conversion is fine.
            const StringType &header_value = header(std::forward<HeaderNameType>(name), index,
                                                    StringType(default_value_for_parsing));
            return parse_header_attributes(std::string_view(header_value.data(), header_value.length()));
        }

        /**
         * @brief Checks if a header with the given name exists.
         * Header names are checked case-insensitively.
         * @tparam HeaderNameType The type of the header name.
         * @param name The name of the header to check.
         * @return `true` if at least one header with the given name exists, `false` otherwise.
         */
        template<typename HeaderNameType>
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
            // StringType construction and map operations can allocate
            _content_type = ContentType{value};
            // Construct StringType from string_view for setting header
            if constexpr (std::is_constructible_v<StringType, std::string_view>) {
                set_header("Content-Type", StringType(value));
            } else {
                // Fallback if StringType not directly constructible from string_view (e.g., needs explicit std::string conversion)
                set_header("Content-Type", StringType(std::string(value)));
            }
        }

        /**
         * @brief Gets the parsed `ContentType` object, allowing easy access to MIME type and charset.
         * @return A constant reference to the internal `ContentType` object.
         */
        [[nodiscard]] const ContentType &
        content_type() const noexcept {
            return _content_type;
        }

        /**
         * @brief Adds a header name-value pair. If a header with the same name already exists,
         * this new value is appended to its list of values (supporting multi-value headers).
         * @tparam HeaderNameType Type of the header name (string-like).
         * @tparam HeaderValueType Type of the header value (convertible to `StringType`).
         * @param name The name of the header. Forwarded to map key construction.
         * @param value The value for the header. Forwarded to `StringType` construction and pushed into vector.
         */
        template<typename HeaderNameType, typename HeaderValueType>
        void
        add_header(HeaderNameType &&name, HeaderValueType &&value) {
            // Map/vector operations can allocate
            _headers[std::forward<HeaderNameType>(name)].emplace_back(std::forward<HeaderValueType>(value));
        }

        /**
         * @brief Removes all occurrences of a header by its name (case-insensitive).
         * @tparam HeaderNameType The type of the header name.
         * @param name The name of the header to remove.
         */
        template<typename HeaderNameType>
        void
        remove_header(HeaderNameType &&name) noexcept {
            // Assuming icase_unordered_map::erase(key) is noexcept
            _headers.erase(std::forward<HeaderNameType>(name));
        }

        /**
         * @brief Sets a header name-value pair, replacing any existing header(s) with the same name.
         * If a header with the same name exists, all its current values are cleared, and the new
         * `value` becomes its only value.
         * @tparam HeaderNameType Type of the header name.
         * @tparam HeaderValueType Type of the header value (convertible to `StringType`).
         * @param name The name of the header. Forwarded to map key construction.
         * @param value The value to set for the header. Forwarded to `StringType` construction.
         */
        template<typename HeaderNameType, typename HeaderValueType>
        void
        set_header(HeaderNameType &&name, HeaderValueType &&value) {
            // Map/vector operations can allocate
            auto &values_vec = _headers[std::forward<HeaderNameType>(name)];
            values_vec.clear();
            values_vec.emplace_back(std::forward<HeaderValueType>(value));
        }
    };

    /** @brief Convenience alias for `THeaders<std::string>`, representing mutable HTTP headers where values are owned `std::string`s. */
    using Headers = THeaders<std::string>;
    /** @brief Shorthand alias for `Headers`, often used for brevity. */
    using headers = Headers;
    /** @brief Convenience alias for `THeaders<std::string_view>`, representing potentially immutable HTTP header views (values are `std::string_view`s). */
    using HeadersView = THeaders<std::string_view>;
    /** @brief Shorthand alias for `HeadersView`. */
    using headers_view = HeadersView;
} // namespace qb::http

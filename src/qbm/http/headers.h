/**
 * @file qbm/http/headers.h
 * @brief Defines HTTP header management classes, including `Headers` and `ContentType`,
 *
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
#include <qb/utility/branch_hints.h>           // QB_COLD (the long-name lookups, Huly QB-1068)

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

// QB_VERSION is published by qb's CMake as a PUBLIC compile definition (see
// qb/cmake/qbConfig.cmake), so it reaches every consumer of the qb targets through both the
// BUILD_INTERFACE and the INSTALL_INTERFACE. Failing the build here is deliberate: the value
// below used to be a hand-written "qb/2.6.0" literal in two places, which silently became a lie
// the moment the framework version moved. A hard error is what stops that from happening again.
#if !defined(QB_VERSION)
#error \
    "qbm-http requires QB_VERSION. Link the qb targets (qb::io / qb::core) so their usage requirements apply, rather than adding qbm's include directories by hand."
#endif

/**
 * @brief The `User-Agent` value the built-in HTTP clients send when the caller sets none.
 *
 * Derived at compile time from the framework version, so it cannot drift from the version
 * actually shipped. Callers that set their own `User-Agent` are never overridden.
 *
 * @return `"qb/"` followed by `QB_VERSION` (e.g. `qb/3.0.0`). Deliberately not restated as a
 *         literal here: a doc comment naming a version is the same drift this constant removes.
 */
inline constexpr std::string_view default_user_agent = "qb/" QB_VERSION;

namespace detail {
/// `Headers::default_content_type`, as the `std::string` a typed `ContentType` returns by reference
/// for a message that carries no type: one process-wide object, never built per message.
inline const std::string default_content_type_string{"application/octet-stream"};
/// `Headers::default_charset`, likewise.
inline const std::string default_charset_string{"utf-8"};
} // namespace detail

/**
 * @brief Selects a suitable `Content-Encoding` for a response based on the client's `Accept-Encoding` header.
 *
 * Compares the client's accepted encodings with the server's supported compression algorithms
 * (if `QB_HAS_COMPRESSION` is defined). q=0 or a malformed q excludes a coding; among the acceptable
 * ones the FIRST in the header's order wins, not the highest q (`CompressionMiddleware` ranks by q).
 * A `*` stands for any coding the field does not exclude, wherever that exclusion is listed — after
 * the wildcard as well as before it (RFC 9110 §12.5.3).
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
     *
     * The defaults are not stored: a default-constructed `ContentType`, or one parsed from a
     * value without a type (or without a usable charset), holds empty strings and reports
     * `Headers::default_content_type` / `Headers::default_charset` from one process-wide object
     * each. Building one for a message that carries no `Content-Type` allocates nothing.
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
        [[nodiscard]] static std::pair<std::string, std::string> parse(std::string_view content_type_str);

    private:
        /** @brief The MIME type; empty stands for `Headers::default_content_type`. */
        std::string _type;
        /** @brief The charset; empty stands for `Headers::default_charset`. */
        std::string _charset;

    public:
        /** @brief The defaults (`application/octet-stream`, `utf-8`): nothing parsed, nothing allocated. */
        ContentType() noexcept = default;

        /**
         * @brief Constructs a `ContentType` object by parsing the given header string.
         * If `content_type_str` is empty, defaults are used.
         * @param content_type_str The `Content-Type` header string (as `std::string_view`).
         */
        explicit ContentType(std::string_view content_type_str) {
            assign(content_type_str);
        }

        ContentType(const ContentType &) = default;

        ContentType(ContentType &&) noexcept = default;

        ContentType &operator=(const ContentType &) = default;

        ContentType &operator=(ContentType &&) noexcept = default;

        /**
         * @brief Re-parses this object from a `Content-Type` header value, reusing its storage.
         * The grammar and the defaults are `parse()`'s.
         * @param content_type_str The `Content-Type` header value; empty yields the defaults.
         */
        void assign(std::string_view content_type_str);

        /**
         * @brief Gets the MIME type component of the Content-Type.
         * @return A constant reference to the MIME type string (e.g., `"text/html"`).
         */
        [[nodiscard]] const std::string &
        type() const noexcept {
            return _type.empty() ? detail::default_content_type_string : _type;
        }

        /**
         * @brief Gets the charset component of the Content-Type.
         * @return A constant reference to the charset string (e.g., `"utf-8"`).
         */
        [[nodiscard]] const std::string &
        charset() const noexcept {
            return _charset.empty() ? detail::default_charset_string : _charset;
        }
    };

protected:
    /** @brief The map storing all headers. Keys are case-insensitive header names. Values are vectors of `std::string`. */
    headers_map_type _headers;
    /**
     * @brief The typed `Content-Type`, derived from the raw map on the first `content_type()` read
     *        after a change (`_content_type_derived` says whether it is current). `mutable`: the
     *        derivation is a read's side effect, and a message, like every qb object, is used by one
     *        thread at a time.
     */
    mutable ContentType _content_type;
    /** @brief Whether `_content_type` was derived from the current contents of `_headers`. */
    mutable bool _content_type_derived = false;

    /** @brief The header name the typed cache follows. */
    static constexpr std::string_view content_type_name = "Content-Type";

    /// Whether `name` is `Content-Type`, in any case: a literal of another length is decided at compile time.
    template <std::size_t N>
    [[nodiscard]] static constexpr bool
    is_content_type_header(const char (&name)[N]) noexcept {
        if constexpr (N - 1 != content_type_name.size()) {
            return false;
        } else {
            return utility::iequals(std::string_view{name, N - 1}, content_type_name);
        }
    }
    template <typename HeaderNameType>
    requires(!std::is_array_v<std::remove_cvref_t<HeaderNameType>>)
    [[nodiscard]] static bool
    is_content_type_header(const HeaderNameType &name) noexcept {
        if constexpr (std::is_convertible_v<const HeaderNameType &, std::string_view>) {
            return utility::iequals(std::string_view{name}, content_type_name);
        } else {
            return false;
        }
    }

    /// Derives the typed `Content-Type` from the raw map: the first value of the header, or the defaults.
    void derive_content_type() const noexcept;

    /**
     * @brief Whether a field is named `name` (any case) when `name` is longer than the map folds on
     *        the stack (`lookup_fold_capacity`): the map would convert it into a `std::string`, so it is
     *        matched against each stored, already-lowercase name instead -- nothing allocated. Out of
     *        line: no field in common use is that long (Huly QB-1068).
     */
    [[nodiscard]] QB_COLD bool has_long_name(std::string_view name) const noexcept;

    /// Erases the field named `name` (any case), `name` being longer than the map folds on the stack,
    /// without allocating: see has_long_name (Huly QB-1068).
    QB_COLD void erase_long_name(std::string_view name) noexcept;

public:
    /** @brief Default constructor. Initializes an empty set of headers and a default `ContentType`. */
    Headers() noexcept = default;

    /**
     * @brief Constructs `Headers` with an initial map of headers.
     * The typed `Content-Type` follows the "Content-Type" header of `initial_headers`, or the
     * defaults if it is absent, when first read.
     * @param initial_headers A map of headers to initialize with. The map is moved.
     */
    explicit Headers(headers_map_type initial_headers)
        : _headers(std::move(initial_headers)) {}

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
     * @brief Marks the typed Content-Type helper as out of date: the next `content_type()` read
     *        re-derives it from the raw header map.
     *
     * Call this after direct mutation through `headers()`. The typed mutators
     * (`set_content_type`, `set_header`, `add_header`, `remove_header`) do it themselves, and a
     * freshly constructed or parsed message derives on its first read, so the raw map is the
     * source of truth and nothing is parsed for a message whose typed Content-Type nobody reads.
     */
    void
    refresh_content_type() noexcept {
        _content_type_derived = false;
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
     * Header names are checked case-insensitively. Allocates nothing, whatever the name's length
     * (Huly QB-1068): it cannot throw.
     * @tparam HeaderNameType The type of the header name.
     * @param name The name of the header to check.
     * @return `true` if at least one header with the given name exists, `false` otherwise.
     */
    template <typename HeaderNameType>
    requires std::is_convertible_v<const HeaderNameType &, std::string_view>
    [[nodiscard]] bool
    has_header(HeaderNameType &&name) const noexcept {
        // A name the map folds on the stack allocates nothing; a longer one would (Huly QB-1068). A
        // string literal's length is known here, so its check costs nothing.
        if constexpr (std::is_array_v<std::remove_reference_t<HeaderNameType>>) {
            if constexpr (std::extent_v<std::remove_reference_t<HeaderNameType>> <= headers_map_type::lookup_fold_capacity + 1) {
                return _headers.has(std::forward<HeaderNameType>(name));
            } else {
                return has_long_name(std::string_view(name));
            }
        } else {
            if (std::string_view(name).size() <= headers_map_type::lookup_fold_capacity) [[likely]] {
                return _headers.has(std::forward<HeaderNameType>(name));
            }
            return has_long_name(std::string_view(name));
        }
    }

    /**
     * @brief Sets the `Content-Type` header value; the typed `content_type()` follows it when next read.
     * Any existing `Content-Type` headers are replaced with this single value.
     * @param value The full `Content-Type` header value string (e.g., "text/html; charset=utf-8").
     *              It may be a view of the value this header already holds.
     */
    void
    set_content_type(std::string_view value) {
        set_header("Content-Type", std::string(value));
    }

    /**
     * @brief Gets the parsed `ContentType` object, allowing easy access to MIME type and charset.
     *
     * Derived from the raw `Content-Type` header (its first value, or the defaults when it is
     * absent) on the first read after the message was built, parsed or had that header changed
     * through a typed mutator or `refresh_content_type()`; later reads return the cached object.
     * A message whose typed Content-Type is never read never parses it. That first read may
     * allocate (a type or charset longer than the small-string capacity); as a `noexcept` read, an
     * allocation failure there terminates the program, as one in qb's `push` does (Huly QB-1068).
     *
     * @return A constant reference to the internal `ContentType` object.
     */
    [[nodiscard]] const ContentType &
    content_type() const noexcept {
        if (!_content_type_derived) [[unlikely]] {
            derive_content_type();
        }
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
        if (is_content_type) {
            _content_type_derived = false;
        }
    }

    /**
     * @brief Removes all occurrences of a header by its name (case-insensitive). Allocates nothing,
     *        whatever the name's length (Huly QB-1068): it cannot throw.
     * @tparam HeaderNameType The type of the header name.
     * @param name The name of the header to remove.
     */
    template <typename HeaderNameType>
    requires std::is_convertible_v<const HeaderNameType &, std::string_view>
    void
    remove_header(HeaderNameType &&name) noexcept {
        const bool is_content_type = is_content_type_header(name);
        // Nothing allocated, so nothing thrown, whatever the name's length (Huly QB-1068): the map
        // folds a name of up to lookup_fold_capacity bytes on the stack, and a longer one -- no field
        // in common use is -- is matched against each stored name and erased by position.
        if constexpr (std::is_array_v<std::remove_reference_t<HeaderNameType>>) {
            if constexpr (std::extent_v<std::remove_reference_t<HeaderNameType>> <= headers_map_type::lookup_fold_capacity + 1) {
                _headers.erase(std::forward<HeaderNameType>(name));
            } else {
                erase_long_name(std::string_view(name));
            }
        } else if (std::string_view(name).size() <= headers_map_type::lookup_fold_capacity) [[likely]] {
            _headers.erase(std::forward<HeaderNameType>(name));
        } else {
            erase_long_name(std::string_view(name));
        }
        if (is_content_type) {
            _content_type_derived = false;
        }
    }

    /**
     * @brief Sets a header name-value pair, replacing any existing header(s) with the same name.
     * If a header with the same name exists, all its current values are cleared, and the new
     * `value` becomes its only value.
     * @tparam HeaderNameType Type of the header name.
     * @tparam HeaderValueType Type of the header value (convertible to `std::string`).
     * @param name The name of the header. Forwarded to map key construction.
     * @param value The value to set for the header. Forwarded to `std::string` construction. It
     *        may alias a value this header holds (a view of it, or the reference `header()`
     *        returns): the new value is built before the old ones are destroyed.
     */
    template <typename HeaderNameType, typename HeaderValueType>
    void
    set_header(HeaderNameType &&name, HeaderValueType &&value) {
        const bool is_content_type = is_content_type_header(name);
        // Build the new value FIRST: clear() destroys the storage `value` may point into (Huly QB-490).
        std::string new_value(std::forward<HeaderValueType>(value));
        // Map/vector operations can allocate
        auto &values_vec = _headers[std::forward<HeaderNameType>(name)];
        values_vec.clear();
        values_vec.emplace_back(std::move(new_value));
        if (is_content_type) {
            _content_type_derived = false;
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

namespace detail {
/**
 * @brief Whether a field must stay out of a trailer section: it frames the message, manages the
 *        connection, routes the request or authenticates to a proxy (RFC 9110 §6.5.1).
 *
 * ONE list for HTTP/1.1, HTTP/2 and HTTP/3, received and sent (Huly QB-1073): `content-length`,
 * `transfer-encoding`, `trailer`, `host`, `connection`, `keep-alive`, `proxy-connection`, `te`,
 * `upgrade`, `http2-settings`, `proxy-authenticate`, `proxy-authorization`. A received trailer
 * section that carries one refuses its message (HTTP/1.1) or its stream (HTTP/2, HTTP/3); a field
 * the `Trailer` header announces that is one stays in the header section; one in `trailers()`
 * refuses the message to send.
 *
 * @param name A field name, in any case.
 */
[[nodiscard]] bool is_forbidden_trailer_field(std::string_view name) noexcept;

/**
 * @brief The fields a message's `Trailer` header announces that may travel in a trailer section:
 *        lowercased, in the order announced, each once; empty when the message has no `Trailer`
 *        header. A forbidden field (is_forbidden_trailer_field) or a pseudo-header is left out -- it
 *        stays in the header section.
 * @param message The message whose `Trailer` header is read.
 */
[[nodiscard]] std::vector<std::string> trailer_section_fields(const Headers &message);

/**
 * @brief The trailer section a message sends, built the same way by HTTP/1.1 (a chunked message),
 *        HTTP/2 and HTTP/3 (Huly QB-1073).
 *
 * Its fields, names lowercase, in order: the header-section fields the `Trailer` header announces
 * that a trailer section may carry (trailer_section_fields, the 3.x way of sending trailers: they
 * leave the header section), then every field of the message's `trailers()`. The views point into
 * the message: valid while it is neither changed nor destroyed.
 */
struct outgoing_trailers {
    /// The header-section fields that leave for the trailer section (trailer_section_fields).
    std::vector<std::string> moved;
    /// The trailer section, in sending order: one entry per value.
    std::vector<std::pair<std::string_view, std::string_view>> fields;
    /// The `trailer` value the header section gains -- the names `trailers()` carries, each once --
    /// when the message announces nothing itself (RFC 9110 §6.6.2); empty otherwise.
    std::string announcement;
    /// A field of `trailers()` a trailer section must not carry (is_forbidden_trailer_field): the
    /// message is refused. Empty when there is none.
    std::string_view forbidden;
};

/**
 * @brief Builds a message's outgoing trailer section (outgoing_trailers).
 * @param message The message's header section.
 * @param trailers The message's `trailers()`, or nullptr when it carries none.
 */
[[nodiscard]] outgoing_trailers plan_outgoing_trailers(const Headers &message, const Headers *trailers);
} // namespace detail
} // namespace qb::http

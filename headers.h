
#pragma once

#include <qb/system/container/unordered_map.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "./types.h"
#include "./utility.h"

namespace qb::http {
/**
 * @brief Maximum length for header attribute names in bytes
 *
 * Defines the maximum allowed length for attribute names to prevent
 * buffer overflow attacks and ensure efficient memory usage.
 */
constexpr const uint32_t ATTRIBUTE_NAME_MAX = 1024; // 1 KB

/**
 * @brief Maximum length for header attribute values in bytes
 *
 * Defines the maximum allowed length for attribute values to prevent
 * buffer overflow attacks and ensure efficient memory usage.
 */
constexpr const uint32_t ATTRIBUTE_VALUE_MAX = 1024 * 1024; // 1 MB

/**
 * @brief Case-insensitive map type for HTTP headers
 *
 * Stores HTTP headers with case-insensitive keys and multiple values per key.
 * This allows proper handling of headers like "Set-Cookie" that can appear multiple
 * times.
 */
using headers_map = qb::icase_unordered_map<std::vector<std::string>>;

/**
 * @brief Parse header attributes from a header
 * @param ptr Header data pointer
 * @param len Header data length
 * @return Map of attribute names to values
 *
 * Parses HTTP header attributes in the format:
 * "name1=value1; name2=value2; name3="quoted value""
 *
 * Handles quoted values, whitespace, and special characters according
 * to HTTP specifications. Used for parsing complex headers with
 * multiple attributes like Content-Disposition, Content-Type with
 * parameters, etc.
 */
[[nodiscard]] qb::icase_unordered_map<std::string>
parse_header_attributes(const char *ptr, size_t len);

/**
 * @brief Parse header attributes from a string header
 * @param header Header string
 * @return Map of attribute names to values
 *
 * String overload of the parse_header_attributes function, converting
 * the string to a raw pointer and length for processing.
 */
[[nodiscard]] qb::icase_unordered_map<std::string>
parse_header_attributes(std::string const &header);

/**
 * @brief Parse header attributes from a string_view header
 * @param header Header string_view
 * @return Map of attribute names to values
 *
 * String_view overload of the parse_header_attributes function, providing
 * a more efficient way to parse attributes without copying the header data.
 */
[[nodiscard]] qb::icase_unordered_map<std::string>
parse_header_attributes(std::string_view const &header);

/**
 * @brief Get the Accept-Encoding header for the client
 * @return Accept-Encoding header value
 *
 * Generates an Accept-Encoding header based on available compression
 * algorithms supported by the client. Each algorithm is listed with
 * its weight (q-value) to indicate preference.
 *
 * The generated header follows the format:
 * "gzip;q=1.0, deflate;q=0.9, chunked"
 *
 * When compression support is not available, only "chunked" is returned.
 */
[[nodiscard]] std::string accept_encoding();

/**
 * @brief Get the Content-Encoding value based on Accept-Encoding
 * @param accept_encoding Accept-Encoding header value
 * @return Content-Encoding header value
 *
 * Selects the most appropriate content encoding algorithm based on
 * the client's Accept-Encoding header and the server's supported
 * compression algorithms.
 *
 * Returns the selected encoding name (e.g., "gzip", "deflate") or
 * an empty string if no matching encoding is found or if compression
 * is not supported.
 */
[[nodiscard]] std::string content_encoding(std::string_view const &accept_encoding);

/**
 * @brief Template class for HTTP headers
 * @tparam String String type (std::string or std::string_view)
 *
 * This class provides a comprehensive implementation for HTTP header management
 * following the HTTP/1.1 specification. It offers:
 *
 * - Case-insensitive header name handling as required by the HTTP spec
 * - Support for multiple values per header (e.g., for Set-Cookie)
 * - ContentType header class with MIME type and charset handling
 * - Efficient access to header values with fallback for missing headers
 * - Header attribute parsing for complex headers
 * - Special handling for common headers like Content-Type
 *
 * The template parameter allows for using either std::string for mutable
 * headers or std::string_view for read-only efficient header access.
 */
template <typename String>
class THeaders {
public:
    constexpr static const char default_content_type[] = "application/octet-stream";
    constexpr static const char default_charset[]      = "utf8";
    using headers_map_type = qb::icase_unordered_map<std::vector<String>>;

    /**
     * @brief Class for handling Content-Type header
     */
    class ContentType {
    public:
        /**
         * @brief Parse a Content-Type header value
         * @param content_type Content-Type header value
         * @return Pair of mime type and charset
         */
        static std::pair<String, String>
        parse(String const &content_type) {
            std::pair<String, String> ret{default_content_type, default_charset};

            auto words = utility::split_string<String>(content_type, " \t;=");
            if (!words.size())
                return ret;
            ret.first = std::move(words.front());
            if (words.size() == 3 && words[1] == "charset") {
                auto &charset = words[2];
                ret.second    = charset.substr(charset.front() == '"' ? 1 : 0,
                                            charset.back() == '"' ? charset.size() - 2
                                                                     : std::string::npos);
            }
            return ret;
        }

    private:
        std::pair<String, String> type_charset;

    public:
        /**
         * @brief Constructor
         * @param content_type Content-Type header value
         */
        explicit ContentType(String const &content_type = "")
            : type_charset{parse(content_type)} {}

        ContentType(ContentType const &rhs)     = default;
        ContentType(ContentType &&rhs) noexcept = default;

        ContentType &operator=(ContentType const &rhs)     = default;
        ContentType &operator=(ContentType &&rhs) noexcept = default;

        /**
         * @brief Get the mime type
         * @return Mime type
         */
        [[nodiscard]] String const &
        type() const {
            return type_charset.first;
        }

        /**
         * @brief Get the charset
         * @return Charset
         */
        [[nodiscard]] String const &
        charset() const {
            return type_charset.second;
        }
    };

protected:
    headers_map_type _headers;
    ContentType      _content_type;

public:
    THeaders() = default;
    /**
     * @brief Constructor with headers
     * @param headers Headers map
     */
    THeaders(qb::icase_unordered_map<std::vector<String>> headers)
        : _headers(std::move(headers))
        , _content_type(header("Content-Type", 0, default_content_type)) {}
    THeaders(THeaders const &)                = default;
    THeaders(THeaders &&) noexcept            = default;
    THeaders &operator=(THeaders const &)     = default;
    THeaders &operator=(THeaders &&) noexcept = default;

    /**
     * @brief Get the headers map
     * @return Headers map
     */
    [[nodiscard]] headers_map_type &
    headers() noexcept {
        return _headers;
    }

    /**
     * @brief Get the headers map (const)
     * @return Headers map
     */
    [[nodiscard]] headers_map_type const &
    headers() const noexcept {
        return _headers;
    }

    /**
     * @brief Get a header value
     * @param name Header name
     * @param index Index for multiple values
     * @param not_found Value to return if not found
     * @return Header value
     */
    template <typename T>
    [[nodiscard]] const auto &
    header(T &&name, std::size_t const index = 0, String const &not_found = "") const {
        const auto &it = this->_headers.find(std::forward<T>(name));
        if (it != this->_headers.cend() && index < it->second.size())
            return it->second[index];
        return not_found;
    }

    /**
     * @brief Get a header's attributes
     * @param name Header name
     * @param index Index for multiple values
     * @param not_found Value to return if not found
     * @return Map of attributes
     */
    template <typename T>
    [[nodiscard]] auto
    attributes(T &&name, std::size_t const index = 0,
               String const &not_found = "") const {
        return parse_header_attributes(header(std::forward<T>(name), index, not_found));
    }

    /**
     * @brief Check if a header exists
     * @param key Header name
     * @return true if header exists
     */
    template <typename T>
    [[nodiscard]] inline bool
    has_header(T &&key) const noexcept {
        return this->_headers.has(std::forward<T>(key));
    }

    /**
     * @brief Set the Content-Type header
     * @param value Content-Type value
     */
    void
    set_content_type(String const &value) {
        _content_type = ContentType{value};
    }

    /**
     * @brief Get the Content-Type object
     * @return Content-Type object
     */
    [[nodiscard]] ContentType const &
    content_type() const noexcept {
        return _content_type;
    }

    /**
     * @brief Add a header with a value
     * @param name Header name
     * @param value Header value
     */
    template <typename T, typename U>
    void
    add_header(T &&name, U &&value) {
        this->_headers[std::forward<T>(name)].push_back(std::forward<U>(value));
    }

    /**
     * @brief Set a header with a value, replacing any existing values
     * @param name Header name
     * @param value Header value
     */
    template <typename T, typename U>
    void
    set_header(T &&name, U &&value) {
        auto &values = this->_headers[std::forward<T>(name)];
        values.clear();
        values.push_back(std::forward<U>(value));
    }
};

using Headers      = THeaders<std::string>;
using headers      = Headers;
using HeadersView  = THeaders<std::string_view>;
using headers_view = HeadersView;

} // namespace qb::http
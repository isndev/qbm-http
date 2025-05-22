/**
 * @file qbm/http/body.h
 * @brief HTTP message body class
 *
 * This file contains the definition of the `Body` class, which represents
 * the body of an HTTP message. It provides methods for manipulating and
 * accessing the body data.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <type_traits>

#include <qb/json.h>
#include <qb/system/allocator/pipe.h>
#include <qb/utility/build_macros.h>
#ifdef QB_IO_WITH_ZLIB
#include <qb/io/compression.h>
#endif

#include "./chunk.h"
#include "./form.h"
#include "./multipart.h"

namespace qb::http {

/**
 * @brief HTTP message body class
 *
 * This class represents the body of an HTTP message, providing methods
 * for manipulating and accessing the body data. It serves as a central
 * component for both requests and responses in the HTTP protocol.
 *
 * Key features:
 * - Efficient storage using a pipe allocator for memory management
 * - Support for various content types including text and binary data
 * - Compression/decompression capabilities (with zlib support)
 * - Conversions between different formats (string, string_view, vectors)
 * - Support for multipart content handling
 * - Streaming capabilities for efficient I/O operations
 *
 * The Body class allows for efficient manipulation of HTTP message content
 * with minimal copying, using move semantics where appropriate for performance.
 */
class Body {
    qb::allocator::pipe<char> _data;

public:
    Body()                    = default;
    ~Body()                   = default;
    Body(Body &&rhs) noexcept = default;
    Body(Body const &rhs);

    Body &operator=(Body &&rhs) noexcept = default;
    Body &operator=(Body const &rhs);

    /**
     * @brief Constructor with variadic arguments
     * @param args Arguments to add to the body
     */
    template <typename... Args,
              typename = std::enable_if_t<
                  !(std::conjunction_v<std::is_same<std::decay_t<Args>, Body>...> && (sizeof...(Args) == 1))
              >>
    Body(Args &&...args) {
        (_data << ... << std::forward<Args>(args));
    }

    /**
     * @brief Append data to the body
     * @param args Data to append
     * @return Reference to this body
     */
    template <typename... Args,
              typename = std::enable_if_t<
                  !(std::conjunction_v<std::is_same<std::decay_t<Args>, Body>...> && (sizeof...(Args) == 1))
              >>
    Body &
    operator<<(Args &&...args) {
        (_data << ... << std::forward<Args>(args));
        return *this;
    }

    /**
     * @brief Assign data to the body
     * @param rhs Data to assign
     * @return Reference to this body
     */
    template <typename T>
    inline Body &
    operator=(T &rhs) {
        return operator=(static_cast<T const &>(rhs));
    }

    /**
     * @brief Assign data to the body (const reference version)
     * @tparam T Type of data to assign
     * @param rhs Data to assign
     * @return Reference to this body
     *
     * Copies the content of the provided data into the body.
     * This generic template handles any type that can be stored in the body.
     */
    template <typename T>
    Body &operator=(T const &);

    /**
     * @brief Assign data to the body (rvalue reference version)
     * @tparam T Type of data to assign
     * @param rhs Data to move
     * @return Reference to this body
     *
     * Moves the content of the provided data into the body.
     * This version is more efficient for temporary values as it
     * avoids unnecessary copying when possible.
     */
    template <typename T>
    Body &operator=(T &&) noexcept;

    /**
     * @brief Assign a C string to the body
     * @param str C string to assign
     * @return Reference to this body
     */
    template <std::size_t N>
    Body &
    operator=(const char (&str)[N]) noexcept {
        _data.clear();
        _data << str;
        return *this;
    }

#ifdef QB_IO_WITH_ZLIB
    /**
     * @brief Get a compressor for the given encoding
     * @param encoding Compression encoding name (e.g., "gzip", "deflate")
     * @return Unique pointer to a compression provider
     *
     * Creates a compressor based on the specified encoding type.
     * Supported encodings include "gzip" and "deflate".
     * Returns nullptr for unsupported or unknown encodings.
     *
     * This method is only available when the library is compiled
     * with zlib support (when QB_IO_WITH_ZLIB is defined).
     */
    static std::unique_ptr<qb::compression::compress_provider>
    get_compressor_from_header(const std::string &encoding);

    /**
     * @brief Compress the body
     * @param encoding Encoding type
     * @return Compressed size
     *
     * Compresses the body content using the specified encoding algorithm.
     * If the body is empty or encoding is empty, returns the original size.
     *
     * The compression process works as follows:
     * 1. A compressor is created for the specified encoding
     * 2. The original content is compressed into a temporary buffer
     * 3. The original data is replaced with the compressed data
     * 4. The size of the compressed data is returned
     *
     * This method is typically called automatically when sending a response
     * with a Content-Encoding header.
     */
    std::size_t compress(std::string const &encoding);

    /**
     * @brief Get a decompressor for the given encoding
     * @param encoding Encoding type
     * @return Decompressor provider
     *
     * Creates a decompression provider based on the specified encoding type.
     * Supported encodings include "gzip", "deflate", and others depending
     * on the build configuration.
     *
     * This method is used internally by the uncompress() method to handle
     * Content-Encoding requirements from incoming requests or responses.
     *
     * @throws std::runtime_error if an unsupported encoding is specified
     * @throws std::runtime_error if multiple compression algorithms are specified
     */
    static std::unique_ptr<qb::compression::decompress_provider>
    get_decompressor_from_header(const std::string &encoding);

    /**
     * @brief Decompress the body
     * @param encoding Encoding type
     * @return Decompressed size
     *
     * Decompresses the body content that was compressed with the specified
     * encoding algorithm. If the body is empty or encoding is empty,
     * returns the original size.
     *
     * The decompression process works as follows:
     * 1. A decompressor is created for the specified encoding
     * 2. The compressed content is decompressed into a temporary buffer
     * 3. The compressed data is replaced with the decompressed data
     * 4. The size of the decompressed data is returned
     *
     * This method is typically called automatically when receiving a request
     * or response with a Content-Encoding header.
     *
     * @throws std::runtime_error if decompression fails or the encoding is unsupported
     */
    std::size_t uncompress(const std::string &encoding);
#endif

    /**
     * @brief Get the raw data buffer
     * @return Raw data buffer
     */
    [[nodiscard]] inline qb::allocator::pipe<char> const &
    raw() const noexcept {
        return _data;
    }

    /**
     * @brief Get the raw data buffer (non-const)
     * @return Raw data buffer
     */
    [[nodiscard]] inline qb::allocator::pipe<char> &
    raw() noexcept {
        return _data;
    }

    /**
     * @brief Get iterator to the beginning of the body
     * @return Begin iterator
     */
    [[nodiscard]] inline auto
    begin() const {
        return _data.begin();
    }

    /**
     * @brief Get iterator to the end of the body
     * @return End iterator
     */
    [[nodiscard]] inline auto
    end() const {
        return _data.end();
    }

    /**
     * @brief Get the size of the body
     * @return Body size
     */
    [[nodiscard]] inline std::size_t
    size() const {
        return _data.size();
    }

    /**
     * @brief Check if the body is empty
     * @return true if body is empty
     */
    [[nodiscard]] inline bool
    empty() const {
        return _data.empty();
    }

    /**
     * @brief Convert the body to a specific type
     * @tparam T Type to convert to
     * @return Converted value
     */
    template <typename T>
    [[nodiscard]] T
    as() const {
        static_assert("cannot convert http body to a not implemented type");
        return {};
    }

    /**
     * @brief Clear the body
     */
    inline void clear() noexcept {
        _data.clear();
    }
};
using body = Body;

// Specializations of templates for Body
template <>
Body &Body::operator= <std::string>(std::string &&str) noexcept;
template <>
Body &Body::operator= <std::string_view>(std::string_view &&str) noexcept;
template <>
Body &Body::operator= <std::string>(std::string const &str);
template <>
Body &Body::operator= <std::vector<char>>(std::vector<char> const &str);
template <>
Body &Body::operator= <std::vector<char>>(std::vector<char> &&str) noexcept;
template <>
Body &Body::operator= <qb::json>(qb::json const &json);
template <>
Body &Body::operator= <qb::json>(qb::json &&json) noexcept;
template <>
Body &Body::operator= <Multipart>(Multipart const &mp);
template <>
Body &Body::operator= <Form>(Form const &form);
template <>
Body &Body::operator= <Form>(Form &&form) noexcept;
template <>
Body &Body::operator= <std::string_view>(std::string_view const &str);
template <>
Body &Body::operator= <const char*>(char const * const &str);
template <>
Body &Body::operator= <MultipartView>(MultipartView const &mpv);
template <>
Body &Body::operator= <MultipartView>(MultipartView &&mpv) noexcept;

template <>
std::string_view Body::as<std::string_view>() const;
template <>
std::string Body::as<std::string>() const;
template <>
qb::json Body::as<qb::json>() const;
template <>
Multipart Body::as<Multipart>() const;
template <>
MultipartView Body::as<MultipartView>() const;
template <>
Form Body::as<Form>() const;

} // namespace qb::http

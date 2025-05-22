/**
 * @file qbm/http/chunk.h
 * @brief Defines the HTTP Chunk class for chunked transfer encoding.
 *
 * This file contains the definition of the `Chunk` class, which represents a single
 * chunk of data in an HTTP message using chunked transfer encoding (RFC 7230, Section 4.1).
 * It is a lightweight, non-owning view of a data segment.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <cstddef> // For std::size_t

namespace qb::http {
    /**
     * @brief Represents a single chunk in HTTP chunked transfer encoding.
     *
     * This class provides a lightweight, non-owning view of a segment of data that
     * constitutes a chunk in an HTTP message body transmitted with chunked encoding.
     * It stores a pointer to the data and its size, but does not manage the lifetime
     * of the underlying data buffer. This makes it efficient for streaming scenarios
     * where chunks are processed sequentially.
     *
     * Chunked transfer encoding allows a sender to begin transmitting a dynamically
     * generated message body before knowing its total size.
     */
    class Chunk {
        const char *_data; ///< Pointer to the beginning of the chunk data. This class does not own the data.
        std::size_t _size; ///< Size of the chunk data in bytes.

    public:
        /**
         * @brief Default constructor.
         *
         * Creates an empty chunk, with its data pointer initialized to `nullptr`
         * and size initialized to `0`.
         */
        Chunk() noexcept
            : _data(nullptr)
              , _size(0) {
        }

        /**
         * @brief Constructs a chunk with a pointer to data and its size.
         *
         * Creates a chunk that refers to an existing block of memory.
         * The caller is responsible for ensuring that the memory pointed to by `data`
         * remains valid for the lifetime of this `Chunk` object or for as long as
         * the chunk data is accessed.
         *
         * @param data Pointer to the start of the chunk data. Must not be null if size > 0.
         * @param size The size of the chunk data in bytes.
         */
        Chunk(const char *data, std::size_t size) noexcept
            : _data(data)
              , _size(size) {
        }

        /**
         * @brief Gets a pointer to the chunk data.
         * @return A `const char*` pointing to the start of the chunk data.
         *         Returns `nullptr` if the chunk is empty and was default constructed.
         */
        [[nodiscard]] const char *
        data() const noexcept {
            return _data;
        }

        /**
         * @brief Gets the size of the chunk data.
         * @return The size of the chunk in bytes.
         */
        [[nodiscard]] std::size_t
        size() const noexcept {
            return _size;
        }
    };

    /**
     * @brief Alias for `qb::http::Chunk`.
     *
     * Provides a convenient shorthand for the `Chunk` class.
     */
    using chunk = Chunk;
} // namespace qb::http 

#pragma once

#include <cstddef> // For std::size_t

namespace qb::http {

/**
 * @brief HTTP chunk for use with chunked transfer encoding
 *
 * Represents a single chunk in HTTP chunked transfer encoding.
 * This lightweight class stores a reference to chunk data without
 * owning the memory, making it efficient for handling streaming data.
 *
 * Chunks are used with chunked transfer encoding, where the body of a
 * message is transferred as a series of chunks, each with its own size.
 * This allows for streaming data without knowing the total size in advance.
 */
class Chunk {
    const char *_data; ///< Pointer to chunk data (not owned)
    std::size_t _size; ///< Size of the chunk in bytes

public:
    /**
     * @brief Default constructor
     *
     * Creates an empty chunk with null data and zero size.
     */
    Chunk()
        : _data(nullptr)
        , _size(0) {}

    /**
     * @brief Construct a chunk with data pointer and size
     * @param data Pointer to chunk data (not owned)
     * @param size Size of the chunk in bytes
     *
     * Creates a chunk referencing the provided data.
     * The chunk does not take ownership of the data,
     * so the caller must ensure the data remains valid.
     */
    Chunk(const char *data, std::size_t size)
        : _data(data)
        , _size(size) {}

    /**
     * @brief Get the chunk data
     * @return Pointer to the chunk data
     */
    [[nodiscard]] const char *
    data() const {
        return _data;
    }

    /**
     * @brief Get the chunk size
     * @return Size of the chunk in bytes
     */
    [[nodiscard]] std::size_t
    size() const {
        return _size;
    }
};
using chunk = Chunk;

} // namespace qb::http 
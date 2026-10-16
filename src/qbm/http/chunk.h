/**
 * @file qbm/http/chunk.h
 * @brief Defines the HTTP Chunk class for chunked transfer encoding.
 *
 * This file contains the definition of the `Chunk` class, which represents a single
 * chunk of data in an HTTP message using chunked transfer encoding (RFC 7230, Section 4.1).
 * It is a lightweight, non-owning view of a data segment.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <cstddef>                    // For std::size_t
#include <qb/system/allocator/pipe.h> // qb::allocator::pipe<char> — specialised below

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
        , _size(0) {}

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
        , _size(size) {}

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

namespace qb::allocator {
/**
 * @brief HTTP Chunk serialization specialization
 *
 * Specialization of the pipe<char>::put template for HTTP chunks.
 * This function formats an HTTP chunk according to the chunked transfer encoding
 * specification in HTTP/1.1.
 *
 * This is used for implementing chunked transfer encoding in HTTP/1.1, allowing
 * the server to send data in chunks without knowing the total size in advance.
 * A zero-size chunk (0\r\n\r\n) indicates the end of the chunked data.
 *
 * @param c HTTP chunk to serialize
 * @return Reference to the pipe for method chaining
 */
template <>
pipe<char> &pipe<char>::put<qb::http::Chunk>(const qb::http::Chunk &c);
} // namespace qb::allocator

namespace qb::http {
namespace internal {
struct MessageBase;
} // namespace internal

namespace detail {
/**
 * @brief Whether a complete chunked message writes a trailer section: it announces fields (a `Trailer`
 *        header) or carries some (`trailers()`). The question the HTTP/1.1 serializers ask before they
 *        write a byte, once they have validated the header section (Huly QB-1067, QB-1073).
 *
 * A field of `trailers()` that cannot travel -- one a trailer section must not carry
 * (is_forbidden_trailer_field), or that no header field could be (not a token name, a value with CR,
 * LF or another control byte, over the protocol_limits lengths) -- throws `std::length_error` here,
 * so a refused message leaves the pipe as the serializer found it. Out of line and cold, the `Trailer`
 * lookup included: few messages have trailers. The serializers write the start line themselves, in
 * both cases -- a second writer of it in their translation unit made MSVC stop inlining the status
 * code's `pipe<char>::operator<<` into them, 6 to 18 ns a message.
 *
 * @param message The message.
 * @param serializer The refusal's prefix, e.g. "qb::http::Response serialization".
 * @return true when the message writes a trailer section (write_trailed_chunked_message); false when
 *         it neither announces nor carries a trailer field.
 */
[[nodiscard]] bool writes_trailer_section(const internal::MessageBase &message, const char *serializer);

/**
 * @brief Writes, after the start line the serializer wrote, the rest of a complete chunked message
 *        that has a trailer section (writes_trailer_section): its header section, its chunked body,
 *        its trailer section (detail::plan_outgoing_trailers) -- the fields its `Trailer` header
 *        announces that a trailer section may carry leave the header section (Huly QB-1067), every
 *        field of its `trailers()` follows them, announced by a `Trailer` field when the message
 *        carries none (Huly QB-1073): the trailer section HTTP/2 and HTTP/3 send.
 *
 * Refuses nothing: writes_trailer_section did, before the start line. Out of line and cold.
 *
 * @param out Where the bytes go, the start line already in it.
 * @param message The message whose fields are written.
 * @param body The message's body bytes.
 * @param length How many of them form the body (one chunk; none for an empty body).
 */
void write_trailed_chunked_message(qb::allocator::pipe<char> &out, const internal::MessageBase &message, const qb::allocator::pipe<char> &body,
                                   std::size_t length);
} // namespace detail
} // namespace qb::http

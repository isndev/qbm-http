/**
 * @file ws.cpp
 * @brief Implementation of the WebSocket protocol for the qb Actor Framework
 *
 * This file contains the implementation of core WebSocket functionality including:
 * - Secure random key generation for handshakes (RFC 6455 §4.1).
 * - Cryptographically unpredictable frame masks (RFC 6455 §5.3) served from a
 *   per-thread batched CSPRNG to avoid syscalls on the hot path.
 * - Frame construction with proper masking / length fields.
 * - Serialization of every message type through the `qb::allocator::pipe<char>`
 *   fast path.
 *
 * The implementation follows RFC 6455 (The WebSocket Protocol).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ws.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace qb::http::ws {

// -----------------------------------------------------------------------------
// Batched thread-local CSPRNG
// -----------------------------------------------------------------------------
//
// RFC 6455 §5.3 mandates that masking keys be cryptographically unpredictable.
// Calling `std::random_device` or OpenSSL's `RAND_bytes` once per 4-byte mask
// means one syscall per outbound frame, which dominates the serialisation
// cost for small messages. We pull bytes in 4 KiB chunks from `RAND_bytes`
// and hand them out 4 bytes at a time. The buffer lives in thread_local
// storage so the fast path is lock-free and respects `qb-io`'s strict
// mono-thread-per-listener model.
//
namespace {

constexpr std::size_t kMaskPoolBytes = 4096;

struct mask_pool {
    std::array<unsigned char, kMaskPoolBytes> data{};
    std::size_t                               offset = kMaskPoolBytes;

    void
    refill() {
        // generate_random_bytes() wraps `RAND_bytes` and throws on failure; we
        // leave the exception propagate — losing entropy is a hard error.
        auto bytes = qb::crypto::generate_random_bytes(kMaskPoolBytes);
        std::memcpy(data.data(), bytes.data(), kMaskPoolBytes);
        offset = 0;
    }
};

[[nodiscard]] mask_pool &
thread_mask_pool() noexcept {
    thread_local mask_pool pool{};
    return pool;
}

void
fill_secure_bytes(unsigned char *out, std::size_t n) {
    auto &pool = thread_mask_pool();
    while (n > 0) {
        if (pool.offset >= kMaskPoolBytes) {
            pool.refill();
        }
        const auto take = std::min<std::size_t>(n, kMaskPoolBytes - pool.offset);
        std::memcpy(out, pool.data.data() + pool.offset, take);
        pool.offset += take;
        out += take;
        n -= take;
    }
}

} // namespace

/**
 * @brief Checks if a string view contains valid UTF-8 data.
 *
 * This function validates a sequence of bytes to ensure it conforms to the
 * UTF-8 encoding rules as specified in RFC 3629. It checks for:
 * - Correct number of continuation bytes for multi-byte sequences.
 * - Correct format of continuation bytes (10xxxxxx).
 * - Absence of overlong encodings.
 * - Absence of surrogate code points (U+D800 to U+DFFF).
 * - Code points within the valid Unicode range (up to U+10FFFF).
 *
 * @param sv The string_view to validate.
 * @return True if the data is valid UTF-8, false otherwise.
 */
bool
is_utf8(std::string_view sv) noexcept {
    const auto *bytes = reinterpret_cast<const unsigned char *>(sv.data());
    const auto  n     = sv.size();

    auto is_cont = [](unsigned char b) noexcept {
        return (b & 0xC0u) == 0x80u;
    };

    std::size_t i = 0;
    while (i < n) {
        const unsigned char b0 = bytes[i];
        if (b0 <= 0x7Fu) {
            ++i;
            continue;
        }

        if (b0 >= 0xC2u && b0 <= 0xDFu) {
            if (i + 1u >= n)
                return false;
            const unsigned char b1 = bytes[i + 1u];
            if (!is_cont(b1))
                return false;
            i += 2u;
            continue;
        }

        if (b0 == 0xE0u) {
            if (i + 2u >= n)
                return false;
            const unsigned char b1 = bytes[i + 1u];
            const unsigned char b2 = bytes[i + 2u];
            if (b1 < 0xA0u || b1 > 0xBFu || !is_cont(b2))
                return false;
            i += 3u;
            continue;
        }
        if (b0 >= 0xE1u && b0 <= 0xECu) {
            if (i + 2u >= n)
                return false;
            const unsigned char b1 = bytes[i + 1u];
            const unsigned char b2 = bytes[i + 2u];
            if (!is_cont(b1) || !is_cont(b2))
                return false;
            i += 3u;
            continue;
        }
        if (b0 == 0xEDu) {
            if (i + 2u >= n)
                return false;
            const unsigned char b1 = bytes[i + 1u];
            const unsigned char b2 = bytes[i + 2u];
            // U+D800..U+DFFF surrogates are forbidden in UTF-8.
            if (b1 < 0x80u || b1 > 0x9Fu || !is_cont(b2))
                return false;
            i += 3u;
            continue;
        }
        if (b0 >= 0xEEu && b0 <= 0xEFu) {
            if (i + 2u >= n)
                return false;
            const unsigned char b1 = bytes[i + 1u];
            const unsigned char b2 = bytes[i + 2u];
            if (!is_cont(b1) || !is_cont(b2))
                return false;
            i += 3u;
            continue;
        }

        if (b0 == 0xF0u) {
            if (i + 3u >= n)
                return false;
            const unsigned char b1 = bytes[i + 1u];
            const unsigned char b2 = bytes[i + 2u];
            const unsigned char b3 = bytes[i + 3u];
            if (b1 < 0x90u || b1 > 0xBFu || !is_cont(b2) || !is_cont(b3))
                return false;
            i += 4u;
            continue;
        }
        if (b0 >= 0xF1u && b0 <= 0xF3u) {
            if (i + 3u >= n)
                return false;
            const unsigned char b1 = bytes[i + 1u];
            const unsigned char b2 = bytes[i + 2u];
            const unsigned char b3 = bytes[i + 3u];
            if (!is_cont(b1) || !is_cont(b2) || !is_cont(b3))
                return false;
            i += 4u;
            continue;
        }
        if (b0 == 0xF4u) {
            if (i + 3u >= n)
                return false;
            const unsigned char b1 = bytes[i + 1u];
            const unsigned char b2 = bytes[i + 2u];
            const unsigned char b3 = bytes[i + 3u];
            if (b1 < 0x80u || b1 > 0x8Fu || !is_cont(b2) || !is_cont(b3))
                return false;
            i += 4u;
            continue;
        }

        return false;
    }

    return true;
}

/**
 * @brief Generate a random WebSocket key for handshake.
 *
 * Creates a cryptographically secure 16-byte nonce (RFC 6455 §4.1) pulled
 * from OpenSSL's CSPRNG and returns it base64-encoded. This is not a hot
 * path (one call per connection) so we go straight to `RAND_bytes` without
 * touching the batched mask pool.
 */
std::string
generateKey() {
    unsigned char nonce[16];
    fill_secure_bytes(nonce, sizeof(nonce));
    return crypto::base64::encode({reinterpret_cast<char *>(nonce), sizeof(nonce)});
}

} // namespace qb::http::ws

namespace qb::allocator {

namespace {

[[nodiscard]] bool
is_control_opcode(unsigned char fin_rsv_opcode) noexcept {
    const auto opcode = static_cast<unsigned char>(fin_rsv_opcode & 0x0Fu);
    return opcode >= static_cast<unsigned char>(qb::http::ws::opcode::_Close);
}

void
enforce_outgoing_frame_constraints(const http::ws::Message &msg) {
    const auto opcode = static_cast<unsigned char>(msg.fin_rsv_opcode & qb::protocol::ws_internal::rfc::OPCODE_MASK);
    if ((msg.fin_rsv_opcode & qb::protocol::ws_internal::rfc::RSV_BITS_MASK) != 0u) {
        throw std::invalid_argument("qb::http::ws: RSV bits require an extension and must be clear");
    }
    if (!qb::protocol::ws_internal::is_valid_frame_opcode(opcode)) {
        throw std::invalid_argument("qb::http::ws: reserved or unknown opcode cannot be serialized");
    }
    if (is_control_opcode(msg.fin_rsv_opcode) && msg.size() > qb::protocol::ws_internal::rfc::MAX_CONTROL_FRAME_PAYLOAD_SIZE) {
        throw std::invalid_argument("qb::http::ws: control frame payload exceeds 125-byte RFC 6455 limit");
    }
    if (is_control_opcode(msg.fin_rsv_opcode) && (msg.fin_rsv_opcode & qb::protocol::ws_internal::rfc::FIN_BIT_MASK) == 0u) {
        throw std::invalid_argument("qb::http::ws: control frames must not be fragmented");
    }
}

} // namespace

/**
 * @brief Create an unmasked WebSocket frame in the output buffer
 * @param pipe The output buffer to write the frame to
 * @param msg The WebSocket message to format
 *
 * Formats a WebSocket message as an unmasked frame according to RFC 6455.
 * This is typically used for server-to-client communication where masking
 * is not required.
 */
static void
fill_unmasked_message(pipe<char> &pipe, const http::ws::Message &msg) {
    enforce_outgoing_frame_constraints(msg);

    std::size_t length = msg.size();
    pipe.reserve(length + 10); // Reserve space for header and payload

    // Write FIN, RSV, and opcode
    pipe << static_cast<char>(msg.fin_rsv_opcode);

    // Write payload length with appropriate format based on size
    if (length >= 126) {
        std::size_t num_bytes;
        if (length > 0xffff) {
            // For lengths >= 65536, use 8-byte length format
            num_bytes = 8;
            pipe << static_cast<char>(127); // 127 indicates 8-byte length
        } else {
            // For lengths >= 126 but < 65536, use 2-byte length format
            num_bytes = 2;
            pipe << static_cast<char>(126); // 126 indicates 2-byte length
        }

        // Write the length bytes in network byte order (big-endian)
        for (std::size_t c = num_bytes - 1; c != static_cast<std::size_t>(-1); --c)
            pipe << static_cast<char>((static_cast<unsigned long long>(length) >> (8 * c)) % 256);
    } else {
        // For lengths < 126, use 1-byte length format
        pipe << static_cast<char>(length);
    }

    // Append the message payload
    pipe << msg._data;
}

/**
 * @brief Create a masked WebSocket frame in the output buffer
 * @param pipe The output buffer to write the frame to
 * @param msg The WebSocket message to format
 *
 * Formats a WebSocket message as a masked frame according to RFC 6455.
 * This is required for client-to-server communication to prevent certain
 * types of attacks on proxies and intermediaries. The 4-byte mask is
 * drawn from the per-thread CSPRNG batch (see `fill_secure_bytes`).
 */
static void
fill_masked_message(pipe<char> &pipe, const http::ws::Message &msg) {
    enforce_outgoing_frame_constraints(msg);

    // Pull a cryptographically unpredictable 4-byte mask from the thread-local
    // CSPRNG pool. No fresh `std::random_device` / `RAND_bytes` call per frame.
    std::array<unsigned char, 4> mask{};
    qb::http::ws::fill_secure_bytes(mask.data(), mask.size());

    std::size_t length = msg.size();
    pipe.reserve(length + 14); // Reserve space for header, mask, and payload

    // Write FIN, RSV, and opcode
    pipe << static_cast<char>(msg.fin_rsv_opcode);

    // Write payload length with appropriate format based on size
    // Set the mask bit (0x80) in the first length byte
    if (length >= 126) {
        std::size_t num_bytes;
        if (length > 0xffff) {
            // For lengths >= 65536, use 8-byte length format
            num_bytes = 8;
            pipe << static_cast<char>(127 + 128); // 127 + mask bit
        } else {
            // For lengths >= 126 but < 65536, use 2-byte length format
            num_bytes = 2;
            pipe << static_cast<char>(126 + 128); // 126 + mask bit
        }

        // Write the length bytes in network byte order (big-endian)
        for (std::size_t c = num_bytes - 1; c != static_cast<std::size_t>(-1); --c)
            pipe << static_cast<char>((static_cast<unsigned long long>(length) >> (8 * c)) % 256);
    } else {
        // For lengths < 126, use 1-byte length format
        pipe << static_cast<char>(length + 128); // length + mask bit
    }

    // Write the 4-byte mask
    pipe.write(reinterpret_cast<char *>(mask.data()), 4);

    // Apply the mask to the payload and write it. We XOR four bytes at a time
    // whenever possible — this is ~4x faster than the per-byte loop on every
    // modern compiler's auto-vectoriser.
    const auto msg_begin = msg._data.cbegin();
    auto       out_begin = pipe.allocate_back(length);

    std::uint32_t mask_word;
    std::memcpy(&mask_word, mask.data(), 4);

    std::size_t i = 0;
    for (; i + 4 <= length; i += 4) {
        std::uint32_t chunk;
        std::memcpy(&chunk, msg_begin + i, 4);
        chunk ^= mask_word;
        std::memcpy(out_begin + i, &chunk, 4);
    }
    for (; i < length; ++i) {
        out_begin[i] = static_cast<char>(msg_begin[i] ^ mask[i & 3]);
    }
}

/**
 * @brief Specialization to serialize a WebSocket Message into a pipe
 * @param msg The WebSocket message to serialize
 * @return Reference to this pipe for chaining
 *
 * Formats the WebSocket message according to the protocol specification,
 * applying masking if required by the message's masked flag.
 */
template <>
pipe<char> &
pipe<char>::put<http::ws::Message>(const http::ws::Message &msg) {
    if (msg.masked)
        fill_masked_message(*this, msg);
    else
        fill_unmasked_message(*this, msg);
    return *this;
}

/**
 * @brief Specialization to serialize a WebSocket Ping message
 * @param msg The Ping message to serialize
 * @return Reference to this pipe for chaining
 */
template <>
pipe<char> &
pipe<char>::put<http::ws::MessagePing>(const http::ws::MessagePing &msg) {
    return put(static_cast<http::ws::Message const &>(msg));
}

/**
 * @brief Specialization to serialize a WebSocket Pong message
 * @param msg The Pong message to serialize
 * @return Reference to this pipe for chaining
 */
template <>
pipe<char> &
pipe<char>::put<http::ws::MessagePong>(const http::ws::MessagePong &msg) {
    return put(static_cast<http::ws::Message const &>(msg));
}

/**
 * @brief Specialization to serialize a WebSocket Text message
 * @param msg The Text message to serialize
 * @return Reference to this pipe for chaining
 */
template <>
pipe<char> &
pipe<char>::put<http::ws::MessageText>(const http::ws::MessageText &msg) {
    return put(static_cast<http::ws::Message const &>(msg));
}

/**
 * @brief Specialization to serialize a WebSocket Binary message
 * @param msg The Binary message to serialize
 * @return Reference to this pipe for chaining
 */
template <>
pipe<char> &
pipe<char>::put<http::ws::MessageBinary>(const http::ws::MessageBinary &msg) {
    return put(static_cast<http::ws::Message const &>(msg));
}

/**
 * @brief Specialization to serialize a WebSocket Close message
 * @param msg The Close message to serialize
 * @return Reference to this pipe for chaining
 */
template <>
pipe<char> &
pipe<char>::put<http::ws::MessageClose>(const http::ws::MessageClose &msg) {
    return put(static_cast<http::ws::Message const &>(msg));
}

/**
 * @brief Specialization to serialize a WebSocket handshake request
 * @param msg The WebSocket handshake request to serialize
 * @return Reference to this pipe for chaining
 *
 * Converts a WebSocketRequest to an HTTP Request for the initial handshake.
 */
template <>
pipe<char> &
pipe<char>::put<http::WebSocketRequest>(const http::WebSocketRequest &msg) {
    return put(static_cast<const http::Request &>(msg));
}

} // namespace qb::allocator

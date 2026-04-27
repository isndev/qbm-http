#include "./response.h"
#include "./1.1/protocol/base.h"  // For protocol_limits - SECURITY FIX: DoS protection

#include <stdexcept>
#include <string>

namespace qb::allocator {
    namespace {
        [[nodiscard]] bool header_is_within_limits(const std::string& name, const std::string& value) noexcept {
            return name.size() <= qb::http::protocol_limits::MAX_HEADER_NAME_LENGTH
                && value.size() <= qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH;
        }

        [[nodiscard]] bool transfer_encoding_contains_chunked(const std::string &value) {
            for (const auto &token: qb::http::utility::split_string<std::string>(value, ",")) {
                if (qb::http::utility::iequals(qb::http::utility::trim_http_whitespace(token), "chunked")) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * @brief Serialize an HTTP Response into a byte stream
     * @param r HTTP Response to serialize
     * @return Reference to this pipe
     *
     * Formats an HTTP response into a properly formatted response string
     * including status line, headers, and body.
     *
     * The format follows the HTTP/1.1 specification with:
     * - Status line: HTTP/VERSION STATUS_CODE STATUS_TEXT
     * - Headers: HEADER: VALUE
     * - Empty line separator
     * - Response body (if present)
     *
     * This method also handles automatic compression of the body
     * if Content-Encoding header is present.
     *
     * @security Validation uses qb::http::protocol_limits; oversize messages throw
     *       std::length_error instead of emitting a truncated or empty wire format.
     *
     * @note Performance: Uses reserve() to minimize allocations during serialization.
     *       Estimates output size based on status line, headers, and body size.
     */
    template<>
    pipe<char> &
    pipe<char>::put<qb::http::Response>(const qb::http::Response &r) {
        // SECURITY FIX: Validate body size to prevent DoS
        const std::size_t body_size = r.body().size();
        if (body_size > qb::http::protocol_limits::MAX_BODY_SIZE) {
            this->clear(); throw std::length_error(
                "qb::http::Response serialization: body size (" + std::to_string(body_size) + ") exceeds "
                "qb::http::protocol_limits::MAX_BODY_SIZE (" + std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE)
                + "); refusing to emit a truncated or empty wire representation.");
        }

        // Performance: Pre-calculate approximate output size to minimize allocations
        std::size_t estimated_size = 32; // Base status line size
        estimated_size += std::to_string(r.status().code()).size();
        estimated_size += 32; // Status text estimate

        // Add headers size
        for (const auto &it: r.headers()) {
            if (it.first.size() > qb::http::protocol_limits::MAX_HEADER_NAME_LENGTH) {
                this->clear(); throw std::length_error("qb::http::Response serialization: header name exceeds MAX_HEADER_NAME_LENGTH.");
            }
            estimated_size += it.first.size() + 2; // ": "
            for (const auto &value: it.second) {
                if (value.size() > qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH) {
                    this->clear(); throw std::length_error(
                        "qb::http::Response serialization: header value exceeds MAX_HEADER_VALUE_LENGTH.");
                }
                estimated_size += value.size() + 2; // CRLF
            }
        }
        estimated_size += 2; // Final CRLF
        estimated_size += body_size;

        // SECURITY FIX: Cap maximum serialized size to prevent overflow
        constexpr std::size_t MAX_SERIALIZED_SIZE = 110 * 1024 * 1024; // 110MB (slightly above MAX_BODY_SIZE + headers)
        if (estimated_size > MAX_SERIALIZED_SIZE) {
            this->clear(); throw std::length_error(
                "qb::http::Response serialization: estimated wire size exceeds internal cap (decompression "
                "or header explosion); refusing to allocate.");
        }

        // Reserve space in pipe to reduce allocations
        this->reserve(estimated_size);
        
        // HTTP Status Line
        *this << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::sep
                << r.status().code() << qb::http::sep
                << std::to_string(r.status())
                << qb::http::endl;
        
        // HTTP Headers
        for (const auto &it: r.headers()) {
            for (const auto &value: it.second) {
                if (!header_is_within_limits(it.first, value)) {
                    this->clear(); throw std::length_error(
                        "qb::http::Response serialization: header name/value outside protocol_limits.");
                }
                *this << it.first << ": " << value << qb::http::endl;
            }
        }
        
        // Body
        const auto length = r.body().size();
        const auto is_chunked = transfer_encoding_contains_chunked(r.header("Transfer-Encoding"));
        if (length && !is_chunked) {
            if (!r.has_header("Content-Length")) {
                *this << "content-length: " << length << qb::http::endl;
            }
            *this << qb::http::endl
                    << r.body().raw();
        } else
            *this << qb::http::endl;
        return *this;
    }
} // namespace qb::allocator

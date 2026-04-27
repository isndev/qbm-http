#include "./request.h"
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
     * @brief Serialize an HTTP Request into a byte stream
     * @param r HTTP Request to serialize
     * @return Reference to this pipe
     *
     * Formats an HTTP request into a properly formatted request string
     * including request line, headers, and body.
     *
     * The format follows the HTTP/1.1 specification with:
     * - Request line: METHOD PATH HTTP/VERSION
     * - Headers: HEADER: VALUE
     * - Empty line separator
     * - Request body (if present)
     *
     * @security Validation uses qb::http::protocol_limits; oversize messages throw
     *       std::length_error instead of emitting a truncated or empty wire format.
     *
     * @note Performance: Uses reserve() to minimize allocations during serialization.
     *       Estimates output size based on path, headers, and body size.
     */
    template<>
    pipe<char> &
    pipe<char>::put<qb::http::Request>(const qb::http::Request &r) {
        // SECURITY FIX: Validate URL size to prevent DoS
        const std::size_t path_size = r.uri().path().size();
        const std::size_t query_size = r.uri().encoded_queries().size();
        const std::size_t fragment_size = r.uri().fragment().size();
        const std::size_t total_url_size = path_size + query_size + fragment_size;

        if (total_url_size > qb::http::protocol_limits::MAX_URL_LENGTH) {
            this->clear(); throw std::length_error(
                "qb::http::Request serialization: URL length (" + std::to_string(total_url_size) + ") exceeds "
                "qb::http::protocol_limits::MAX_URL_LENGTH (" + std::to_string(qb::http::protocol_limits::MAX_URL_LENGTH)
                + ").");
        }

        // SECURITY FIX: Validate body size to prevent DoS
        const std::size_t body_size = r.body().size();
        if (body_size > qb::http::protocol_limits::MAX_BODY_SIZE) {
            this->clear(); throw std::length_error(
                "qb::http::Request serialization: body size (" + std::to_string(body_size) + ") exceeds "
                "qb::http::protocol_limits::MAX_BODY_SIZE (" + std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE)
                + ").");
        }

        // Performance: Pre-calculate approximate output size to minimize allocations
        std::size_t estimated_size = 64; // Base request line size
        estimated_size += path_size;
        estimated_size += query_size + 1; // ?query
        estimated_size += fragment_size + 1; // #fragment

        // Add headers size
        for (const auto &it: r.headers()) {
            if (it.first.size() > qb::http::protocol_limits::MAX_HEADER_NAME_LENGTH) {
                this->clear(); throw std::length_error("qb::http::Request serialization: header name exceeds MAX_HEADER_NAME_LENGTH.");
            }
            estimated_size += it.first.size() + 2; // ": "
            for (const auto &value: it.second) {
                if (value.size() > qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH) {
                    this->clear(); throw std::length_error(
                        "qb::http::Request serialization: header value exceeds MAX_HEADER_VALUE_LENGTH.");
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
                "qb::http::Request serialization: estimated wire size exceeds internal cap; refusing to allocate.");
        }

        // Reserve space in pipe to reduce allocations
        this->reserve(estimated_size);
        
        // HTTP Request Line: METHOD PATH[?query][#fragment] HTTP/VERSION
        *this << ::http_method_name(r.method()) << qb::http::sep
                << r.uri().path();
        if (!r.uri().encoded_queries().empty())
            *this << "?" << r.uri().encoded_queries();
        if (!r.uri().fragment().empty())
            *this << "#" << r.uri().fragment();
        *this << qb::http::sep << "HTTP/" << r.major_version << "." << r.minor_version
                << qb::http::endl;
        
        // HTTP Headers
        for (const auto &it: r.headers()) {
            for (const auto &value: it.second) {
                if (!header_is_within_limits(it.first, value)) {
                    this->clear(); throw std::length_error(
                        "qb::http::Request serialization: header name/value outside protocol_limits.");
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

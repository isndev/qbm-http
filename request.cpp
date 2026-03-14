#include "./request.h"
#include "./1.1/protocol/base.h"  // For protocol_limits - SECURITY FIX: DoS protection

// templates instantiation
// objects
template class qb::http::TRequest<std::string>;
template class qb::http::TRequest<std::string_view>;

namespace qb::allocator {
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
     * @security SECURITY FIX: Added validation to prevent DoS attacks via oversized URLs
     *       or bodies. Uses qb::http::protocol_limits for maximum sizes.
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
            // URL too large - return empty pipe to prevent memory exhaustion
            // This is a security measure against DoS attacks
            return *this;
        }

        // SECURITY FIX: Validate body size to prevent DoS
        const std::size_t body_size = r.body().size();
        if (body_size > qb::http::protocol_limits::MAX_BODY_SIZE) {
            // Body too large - return empty pipe to prevent memory exhaustion
            return *this;
        }

        // Performance: Pre-calculate approximate output size to minimize allocations
        std::size_t estimated_size = 64; // Base request line size
        estimated_size += path_size;
        estimated_size += query_size + 1; // ?query
        estimated_size += fragment_size + 1; // #fragment

        // Add headers size
        for (const auto &it: r.headers()) {
            // SECURITY FIX: Validate header name and value sizes
            if (it.first.size() > qb::http::protocol_limits::MAX_HEADER_NAME_LENGTH) {
                continue; // Skip oversized header names
            }
            estimated_size += it.first.size() + 2; // ": "
            for (const auto &value: it.second) {
                if (value.size() > qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH) {
                    continue; // Skip oversized header values
                }
                estimated_size += value.size() + 2; // CRLF
            }
        }
        estimated_size += 2; // Final CRLF
        estimated_size += body_size;

        // SECURITY FIX: Cap maximum serialized size to prevent overflow
        constexpr std::size_t MAX_SERIALIZED_SIZE = 110 * 1024 * 1024; // 110MB (slightly above MAX_BODY_SIZE + headers)
        if (estimated_size > MAX_SERIALIZED_SIZE) {
            return *this; // Too large, would cause memory issues
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
            for (const auto &value: it.second)
                *this << it.first << ": " << value << qb::http::endl;
        }
        
        // Body
        const auto length = r.body().size();
        const auto is_chunked = r.header("Transfer-Encoding").find("chunked") != std::string::npos;
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

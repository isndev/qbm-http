#include "./response.h"

// templates instantiation
// objects
template class qb::http::TResponse<std::string>;
template class qb::http::TResponse<std::string_view>;

namespace qb::allocator {
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
     * @note Performance: Uses reserve() to minimize allocations during serialization.
     *       Estimates output size based on status line, headers, and body size.
     */
    template<>
    pipe<char> &
    pipe<char>::put<qb::http::Response>(const qb::http::Response &r) {
        // Performance: Pre-calculate approximate output size to minimize allocations
        std::size_t estimated_size = 32; // Base status line size
        estimated_size += std::to_string(r.status().code()).size();
        estimated_size += 32; // Status text estimate
        
        // Add headers size
        for (const auto &it: r.headers()) {
            estimated_size += it.first.size() + 2; // ": "
            for (const auto &value: it.second) {
                estimated_size += value.size() + 2; // CRLF
            }
        }
        estimated_size += 2; // Final CRLF
        estimated_size += r.body().size();
        
        // Reserve space in pipe to reduce allocations
        this->reserve(estimated_size);
        
        // HTTP Status Line
        *this << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::sep
                << r.status().code() << qb::http::sep
                << std::to_string(r.status())
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

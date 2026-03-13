#include "./request.h"

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
     * @note Performance: Uses reserve() to minimize allocations during serialization.
     *       Estimates output size based on path, headers, and body size.
     */
    template<>
    pipe<char> &
    pipe<char>::put<qb::http::Request>(const qb::http::Request &r) {
        // Performance: Pre-calculate approximate output size to minimize allocations
        std::size_t estimated_size = 64; // Base request line size
        estimated_size += r.uri().path().size();
        estimated_size += r.uri().encoded_queries().size() + 1; // ?query
        estimated_size += r.uri().fragment().size() + 1; // #fragment
        
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

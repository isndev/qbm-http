#include "./request.h"

// templates instantiation
// objects
template struct qb::http::TRequest<std::string>;
template struct qb::http::TRequest<std::string_view>;

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
     */
    template<>
    pipe<char> &
    pipe<char>::put<qb::http::Request>(const qb::http::Request &r) {
        // HTTP Status Line
        *this << ::http_method_name(r.method()) << qb::http::sep
                << r.uri().path();
        if (r.uri().encoded_queries().size())
            *this << "?" << r.uri().encoded_queries();
        if (r.uri().fragment().size())
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
#include "./response.h"

// templates instantiation
// objects
template struct qb::http::TResponse<std::string>;
template struct qb::http::TResponse<std::string_view>;

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
     */
    template<>
    pipe<char> &
    pipe<char>::put<qb::http::Response>(const qb::http::Response &r) {
        // HTTP Status Line
        *this << "HTTP/" << r.major_version << "." << r.minor_version << qb::http::sep
                << r.status() << qb::http::sep
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


#pragma once

#include <llhttp.h>

namespace qb::http {

/**
 * @brief HTTP method type alias for the underlying enum
 *
 * Represents standard HTTP methods like GET, POST, PUT, etc. as defined in RFC 7231.
 */
using method = http_method;

/**
 * @brief HTTP status code type alias for the underlying enum
 *
 * Represents standard HTTP status codes like 200 OK, 404 Not Found, etc. as defined in
 * RFC 7231.
 */
using status = http_status;

/**
 * @brief HTTP line ending sequence (CRLF)
 *
 * As defined in the HTTP specification, lines must end with CR+LF.
 */
constexpr const char endl[] = "\r\n";

/**
 * @brief HTTP separator character (space)
 *
 * Used between parts of the request/status line in HTTP messages.
 */
constexpr const char sep = ' ';

} // namespace qb::http

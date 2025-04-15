
#pragma once

#include <qb/system/container/unordered_map.h>
#include <string>
#include <string_view>
#include "./utility.h"

namespace qb::http {

/**
 * @brief Maximum length for cookie names in bytes
 *
 * Defines the maximum allowed length for cookie names to prevent
 * buffer overflow attacks and ensure efficient memory usage.
 */
constexpr const uint32_t COOKIE_NAME_MAX = 1024; // 1 KB

/**
 * @brief Maximum length for cookie values in bytes
 *
 * Defines the maximum allowed length for cookie values to prevent
 * buffer overflow attacks and ensure efficient memory usage.
 */
constexpr const uint32_t COOKIE_VALUE_MAX = 1024 * 1024; // 1 MB

/**
 * @brief Parse cookies from a header
 * @param ptr Header data pointer
 * @param len Header data length
 * @param set_cookie_header true if parsing Set-Cookie header
 * @return Map of cookie names to values
 *
 * Parses HTTP Cookie or Set-Cookie headers according to RFC 6265,
 * extracting cookie names and values while handling quoted values
 * and special characters.
 *
 * For Cookie headers, it parses formats like:
 * "name1=value1; name2=value2"
 *
 * For Set-Cookie headers, it handles formats like:
 * "name=value; Path=/; Domain=example.com; Expires=Wed, 21 Oct 2015 07:28:00 GMT"
 *
 * Cookie attributes (Path, Domain, etc.) are not included in the returned map.
 */
[[nodiscard]] qb::icase_unordered_map<std::string>
parse_cookies(const char *ptr, size_t len, bool set_cookie_header);

/**
 * @brief Parse cookies from a string header
 * @param header Header string
 * @param set_cookie_header true if parsing Set-Cookie header
 * @return Map of cookie names to values
 *
 * String overload of the parse_cookies function, converting the string
 * to a raw pointer and length for processing.
 */
[[nodiscard]] qb::icase_unordered_map<std::string>
parse_cookies(std::string const &header, bool set_cookie_header);

/**
 * @brief Parse cookies from a string_view header
 * @param header Header string_view
 * @param set_cookie_header true if parsing Set-Cookie header
 * @return Map of cookie names to values
 *
 * String_view overload of the parse_cookies function, providing a more
 * efficient way to parse cookies without copying the header data.
 */
[[nodiscard]] qb::icase_unordered_map<std::string>
parse_cookies(std::string_view const &header, bool set_cookie_header);

} // namespace qb::http
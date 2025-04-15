#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <qb/system/timestamp.h>

namespace qb::http {

/**
 * @brief Date utilities for HTTP date formatting and parsing
 *
 * This namespace provides functions for formatting and parsing HTTP dates
 * according to RFC 7231 and RFC 6265 (Cookie dates).
 *
 * HTTP dates can appear in multiple formats:
 * - RFC 1123 format: "Sun, 06 Nov 1994 08:49:37 GMT" (preferred format)
 * - RFC 850 format: "Sunday, 06-Nov-94 08:49:37 GMT" (obsolete format)
 * - ANSI C's asctime() format: "Sun Nov  6 08:49:37 1994" (obsolete format)
 *
 * All HTTP date/time stamps MUST be represented in Greenwich Mean Time (GMT).
 */
namespace date {

/**
 * @brief Format a timestamp as an HTTP date string
 * @param ts Timestamp to format
 * @return Formatted date string conforming to RFC 7231
 *
 * Formats a timestamp in the preferred HTTP date format (RFC 1123):
 * "Sun, 06 Nov 1994 08:49:37 GMT"
 *
 * All HTTP date/time stamps are represented in Greenwich Mean Time (GMT).
 */
std::string format_http_date(qb::Timestamp const ts) noexcept;

/**
 * @brief Format a time point as an HTTP date string
 * @param tp Time point to format
 * @return Formatted date string conforming to RFC 7231
 *
 * Formats a time point in the preferred HTTP date format (RFC 1123):
 * "Sun, 06 Nov 1994 08:49:37 GMT"
 *
 * All HTTP date/time stamps are represented in Greenwich Mean Time (GMT).
 */
std::string format_http_date(std::chrono::system_clock::time_point const tp) noexcept;

/**
 * @brief Format a time point as a cookie expiration date string
 * @param tp Time point to format
 * @return Formatted date string conforming to RFC 6265
 *
 * Formats a time point for cookie expiration (RFC 6265 section 5.2.1):
 * "Sun, 06 Nov 1994 08:49:37 GMT"
 *
 * This is functionally equivalent to format_http_date but provided
 * for semantic clarity in cookie-related code.
 */
std::string format_cookie_date(std::chrono::system_clock::time_point const tp) noexcept;

/**
 * @brief Parse an HTTP date string into a time point
 * @param str HTTP date string to parse
 * @return Optional time point, empty if parsing failed
 *
 * Parses an HTTP date string in any of the three allowed formats:
 * - RFC 1123: "Sun, 06 Nov 1994 08:49:37 GMT"
 * - RFC 850: "Sunday, 06-Nov-94 08:49:37 GMT"
 * - ANSI C asctime(): "Sun Nov  6 08:49:37 1994"
 *
 * Returns an empty optional if parsing fails.
 */
std::optional<std::chrono::system_clock::time_point>
parse_http_date(std::string_view const str) noexcept;

/**
 * @brief Parse an HTTP date string into a time point
 * @param str HTTP date string to parse
 * @return Optional time point, empty if parsing failed
 *
 * String overload of parse_http_date.
 *
 * @see parse_http_date(std::string_view const)
 */
std::optional<std::chrono::system_clock::time_point>
parse_http_date(std::string const &str) noexcept;

/**
 * @brief Parse a cookie date string into a time point
 * @param str Cookie date string to parse
 * @return Optional time point, empty if parsing failed
 *
 * Parses a cookie date string according to RFC 6265 section 5.1.1.
 * Cookie dates are more lenient than general HTTP dates, allowing
 * various non-standard formats.
 *
 * Returns an empty optional if parsing fails.
 */
std::optional<std::chrono::system_clock::time_point>
parse_cookie_date(std::string_view const str) noexcept;

/**
 * @brief Parse a cookie date string into a time point
 * @param str Cookie date string to parse
 * @return Optional time point, empty if parsing failed
 *
 * String overload of parse_cookie_date.
 *
 * @see parse_cookie_date(std::string_view const)
 */
std::optional<std::chrono::system_clock::time_point>
parse_cookie_date(std::string const &str) noexcept;

/**
 * @brief Get current time as an HTTP date string
 * @return Current time formatted as an HTTP date
 *
 * Returns the current system time formatted as an HTTP date.
 * This is useful for generating Date headers in HTTP responses.
 */
std::string now() noexcept;

/**
 * @brief Convert a Timestamp to a system_clock::time_point
 * @param ts Timestamp to convert
 * @return Equivalent system_clock::time_point
 */
std::chrono::system_clock::time_point to_time_point(qb::Timestamp const ts) noexcept;

/**
 * @brief Convert a system_clock::time_point to a Timestamp
 * @param tp Time point to convert
 * @return Equivalent Timestamp
 */
qb::Timestamp to_timestamp(std::chrono::system_clock::time_point const tp) noexcept;

inline std::string
to_string(qb::Timestamp const ts) noexcept {
    return date::format_http_date(ts);
}

inline std::string
to_string(std::chrono::system_clock::time_point const tp) noexcept {
    return date::format_http_date(tp);
}

inline qb::Timestamp
parse(std::string_view const str) noexcept {
    auto tp = date::parse_http_date(str);
    return tp ? date::to_timestamp(*tp) : qb::Timestamp{};
}

inline qb::Timestamp
parse(std::string const &str) noexcept {
    auto tp = date::parse_http_date(str);
    return tp ? date::to_timestamp(*tp) : qb::Timestamp{};
}

std::string
format_timestamp(const std::chrono::system_clock::time_point &tp);

} // namespace date

} // namespace qb::http

#pragma once

#include <chrono>
#include <string>
#include <string_view>
#include <utility>

#include <qb/system/timestamp.h>

namespace qb::http {

/**
 * @brief Date class for formatting timestamps as HTTP dates
 *
 * This class provides a static method to format timestamps into
 * HTTP date strings according to RFC 7231.
 *
 * All HTTP date/time stamps MUST be represented in Greenwich Mean Time (GMT).
 */
class Date {
public:
    /**
     * @brief Format a timestamp as an HTTP date string
     * @param ts Timestamp to format
     * @return Formatted date string conforming to RFC 7231
     *
     * Formats a timestamp in the standard HTTP date format:
     * "Day, DD Mon YYYY HH:MM:SS GMT"
     *
     * All HTTP date/time stamps MUST be represented in Greenwich Mean Time (GMT).
     */
    static std::string to_string(qb::Timestamp const ts) noexcept;

    /**
     * @brief Format a timestamp as an HTTP date string
     * @param tp Timestamp to format
     * @return Formatted date string conforming to RFC 7231
     *
     * Formats a timestamp in the standard HTTP date format:
     * "Day, DD Mon YYYY HH:MM:SS GMT"
     */
    static std::string
    to_string(std::chrono::system_clock::time_point const tp) noexcept;

    /**
     * @brief Parse an HTTP date string into a timestamp
     * @param str HTTP date string to parse
     * @return Parsed timestamp
     *
     * Parses an HTTP date string into a timestamp according to RFC 7231.
     */
    static qb::Timestamp parse(std::string_view const str) noexcept;

    /**
     * @brief Parse an HTTP date string into a timestamp
     * @param str HTTP date string to parse
     * @return Parsed timestamp
     *
     * Parses an HTTP date string into a timestamp according to RFC 7231.
     */
    static qb::Timestamp parse(std::string const &str) noexcept;
};

using date = Date;

} // namespace qb::http
/**
 * @file qbm/http/date.h
 * @brief HTTP-compliant date and time formatting and parsing utilities.
 *
 * This file provides functions within the `qb::http::date` namespace for converting
 * between various time representations (like `qb::wall_time`, `std::chrono::system_clock::time_point`)
 * and HTTP-formatted date strings (RFC 7231, RFC 6265). It supports parsing multiple
 * standard date formats found in HTTP headers.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./date.h"
#include <array>
#include <charconv>  // For std::from_chars - faster than std::stoi, no exceptions
#include <cctype>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string_view>
#include <vector>

namespace qb::http::date {
    // Month name arrays for parsing different date formats
    constexpr std::array<const char *, 12> MONTH_NAMES = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };

    constexpr std::array<const char *, 12> MONTH_NAMES_LONG = {
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    };

    constexpr std::array<const char *, 7> DAY_NAMES = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };

    //constexpr std::array<const char*, 7> DAY_NAMES_LONG = {
    //    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
    //};

    /**
     * @brief Convert a string month name to its numeric value (0-11)
     * @param month Month name to convert
     * @return Month number (0-11) or -1 if invalid
     */
    int month_to_num(std::string_view month) {
        for (size_t i = 0; i < MONTH_NAMES.size(); ++i) {
            if (month == MONTH_NAMES[i]) {
                return static_cast<int>(i);
            }
        }

        // Try long month names
        for (size_t i = 0; i < MONTH_NAMES_LONG.size(); ++i) {
            if (month == MONTH_NAMES_LONG[i]) {
                return static_cast<int>(i);
            }
        }

        return -1;
    }

    /**
     * @brief Convert number to two digit string with leading zero
     * @param num Number to convert
     * @return Two digit string
     */
    std::string two_digits(int num) {
        return (num < 10 ? "0" : "") + std::to_string(num);
    }

    std::optional<std::chrono::system_clock::time_point>
    make_time_point_utc(int year, int month, int day, int hour, int minute, int second) noexcept {
        if (month < 0 || month > 11 || day < 1 || day > 31 ||
            hour < 0 || hour > 23 || minute < 0 || minute > 59 ||
            second < 0 || second > 59) {
            return std::nullopt;
        }

        const int expected_year = year - 1900;
        const int expected_month = month;
        const int expected_day = day;
        const int expected_hour = hour;
        const int expected_minute = minute;
        const int expected_second = second;

        tm tm_value{};
        tm_value.tm_year = expected_year;
        tm_value.tm_mon = expected_month;
        tm_value.tm_mday = expected_day;
        tm_value.tm_hour = expected_hour;
        tm_value.tm_min = expected_minute;
        tm_value.tm_sec = expected_second;

#if defined(_MSC_VER) || defined(__MINGW32__)
        time_t time_value = _mkgmtime(&tm_value);
#else
        time_t time_value = timegm(&tm_value);
#endif
        if (time_value == static_cast<time_t>(-1)) {
            return std::nullopt;
        }

        tm normalized{};
#if defined(_MSC_VER) || defined(__MINGW32__)
        if (gmtime_s(&normalized, &time_value) != 0) {
            return std::nullopt;
        }
#else
        if (gmtime_r(&time_value, &normalized) == nullptr) {
            return std::nullopt;
        }
#endif

        if (normalized.tm_year != expected_year ||
            normalized.tm_mon != expected_month ||
            normalized.tm_mday != expected_day ||
            normalized.tm_hour != expected_hour ||
            normalized.tm_min != expected_minute ||
            normalized.tm_sec != expected_second) {
            return std::nullopt;
        }

        return std::chrono::system_clock::from_time_t(time_value);
    }

    /**
     * @brief Format a time point as an HTTP date string
     * @param tp Time point to format
     * @return Formatted date string conforming to RFC 7231
     */
    std::string format_http_date(std::chrono::system_clock::time_point const tp) noexcept {
        const auto time_t_value = std::chrono::system_clock::to_time_t(tp);
        tm tm_value{};

#if defined(_MSC_VER) || defined(__MINGW32__)
    if (gmtime_s(&tm_value, &time_t_value) != 0)
        return {};
#else
        if (gmtime_r(&time_t_value, &tm_value) == nullptr)
            return {};
#endif

        std::ostringstream oss;
        oss << DAY_NAMES[tm_value.tm_wday] << ", "
                << (tm_value.tm_mday < 10 ? "0" : "") << tm_value.tm_mday << " "
                << MONTH_NAMES[tm_value.tm_mon] << " "
                << (tm_value.tm_year + 1900) << " "
                << (tm_value.tm_hour < 10 ? "0" : "") << tm_value.tm_hour << ":"
                << (tm_value.tm_min < 10 ? "0" : "") << tm_value.tm_min << ":"
                << (tm_value.tm_sec < 10 ? "0" : "") << tm_value.tm_sec << " "
                << "GMT";

        return oss.str();
    }

    /**
     * @brief Format a time point as a cookie expiration date string
     * @param tp Time point to format
     * @return Formatted date string conforming to RFC 6265
     */
    std::string format_cookie_date(std::chrono::system_clock::time_point const tp) noexcept {
        // Cookie dates use the same format as HTTP dates
        return format_http_date(tp);
    }

    /**
     * @brief Parse an HTTP date string in RFC 1123 format
     * @param str Date string in format "Sun, 06 Nov 1994 08:49:37 GMT"
     * @return Optional time point
     */
    std::optional<std::chrono::system_clock::time_point> parse_rfc1123_date(std::string_view str) {
        // Format: "Sun, 06 Nov 1994 08:49:37 GMT"
        if (str.size() != 29) return std::nullopt;

        // Skip weekday and comma
        auto pos = str.find(',');
        if (pos != 3 || pos + 1 >= str.size() || str[pos + 1] != ' ') return std::nullopt;

        // Move past the comma and space
        pos += 2;
        if (pos >= str.size()) return std::nullopt;

        // Extract day (2 digits) - Using from_chars for better performance (no exceptions, no allocations)
        if (pos + 2 > str.size()) return std::nullopt;
        int day = 0;
        if (std::from_chars(str.data() + pos, str.data() + pos + 2, day).ec != std::errc{}) return std::nullopt;
        if (pos + 2 >= str.size() || str[pos + 2] != ' ') return std::nullopt;
        pos += 3; // Move past day and space

        // Extract month (3 chars)
        if (pos + 3 > str.size()) return std::nullopt;
        std::string_view month_str = str.substr(pos, 3);
        int month = month_to_num(month_str);
        if (month < 0) return std::nullopt;
        if (pos + 3 >= str.size() || str[pos + 3] != ' ') return std::nullopt;
        pos += 4; // Move past month and space

        // Extract year (4 digits) - Using from_chars for better performance
        if (pos + 4 > str.size()) return std::nullopt;
        int year = 0;
        if (std::from_chars(str.data() + pos, str.data() + pos + 4, year).ec != std::errc{}) return std::nullopt;
        if (pos + 4 >= str.size() || str[pos + 4] != ' ') return std::nullopt;
        pos += 5; // Move past year and space

        // Extract time - Using from_chars for better performance
        if (pos + 8 > str.size()) return std::nullopt;
        int hour = 0, minute = 0, second = 0;
        if (std::from_chars(str.data() + pos, str.data() + pos + 2, hour).ec != std::errc{}) return std::nullopt;
        if (str[pos + 2] != ':') return std::nullopt;
        if (std::from_chars(str.data() + pos + 3, str.data() + pos + 5, minute).ec != std::errc{}) return std::nullopt;
        if (str[pos + 5] != ':') return std::nullopt;
        if (std::from_chars(str.data() + pos + 6, str.data() + pos + 8, second).ec != std::errc{}) return std::nullopt;

        pos += 8;
        if (pos + 4 != str.size() || str.substr(pos, 4) != " GMT") return std::nullopt;

        return make_time_point_utc(year, month, day, hour, minute, second);
    }

    /**
     * @brief Parse an HTTP date string in RFC 850 format
     * @param str Date string in format "Sunday, 06-Nov-94 08:49:37 GMT"
     * @return Optional time point
     */
    std::optional<std::chrono::system_clock::time_point> parse_rfc850_date(std::string_view str) {
        // Format: "Sunday, 06-Nov-94 08:49:37 GMT"
        auto pos = str.find(',');
        if (pos == std::string_view::npos || pos + 1 >= str.size() || str[pos + 1] != ' ') return std::nullopt;

        // Move past the comma and space
        pos += 2;
        if (pos >= str.size()) return std::nullopt;

        // Extract day (2 digits) - Using from_chars for better performance
        if (pos + 2 > str.size()) return std::nullopt;
        int day = 0;
        if (std::from_chars(str.data() + pos, str.data() + pos + 2, day).ec != std::errc{}) return std::nullopt;
        if (pos + 2 >= str.size() || str[pos + 2] != '-') return std::nullopt;
        pos += 3; // Move past day and hyphen

        // Extract month (3 chars)
        if (pos + 3 > str.size()) return std::nullopt;
        std::string_view month_str = str.substr(pos, 3);
        int month = month_to_num(month_str);
        if (month < 0) return std::nullopt;
        if (pos + 3 >= str.size() || str[pos + 3] != '-') return std::nullopt;
        pos += 4; // Move past month and hyphen

        // Extract year (2 digits) - Using from_chars for better performance
        if (pos + 2 > str.size()) return std::nullopt;
        int year = 0;
        if (std::from_chars(str.data() + pos, str.data() + pos + 2, year).ec != std::errc{}) return std::nullopt;
        if (year < 70) {
            year += 2000; // Y2K pivot for 2-digit years
        } else {
            year += 1900;
        }
        if (pos + 2 >= str.size() || str[pos + 2] != ' ') return std::nullopt;
        pos += 3; // Move past year and space

        // Extract time - Using from_chars for better performance
        if (pos + 8 > str.size()) return std::nullopt;
        int hour = 0, minute = 0, second = 0;
        if (std::from_chars(str.data() + pos, str.data() + pos + 2, hour).ec != std::errc{}) return std::nullopt;
        if (str[pos + 2] != ':') return std::nullopt;
        if (std::from_chars(str.data() + pos + 3, str.data() + pos + 5, minute).ec != std::errc{}) return std::nullopt;
        if (str[pos + 5] != ':') return std::nullopt;
        if (std::from_chars(str.data() + pos + 6, str.data() + pos + 8, second).ec != std::errc{}) return std::nullopt;

        pos += 8;
        if (pos + 4 != str.size() || str.substr(pos, 4) != " GMT") return std::nullopt;

        return make_time_point_utc(year, month, day, hour, minute, second);
    }

    /**
     * @brief Parse an HTTP date string in ANSI C asctime() format
     * @param str Date string in format "Sun Nov  6 08:49:37 1994"
     * @return Optional time point
     */
    std::optional<std::chrono::system_clock::time_point> parse_asctime_date(std::string_view str) {
        // Format: "Sun Nov  6 08:49:37 1994"
        if (str.size() != 24 || str[3] != ' ' || str[7] != ' ') return std::nullopt;

        // Skip weekday
        size_t pos = 4;

        // Extract month (3 chars)
        if (pos + 3 > str.size()) return std::nullopt;
        std::string_view month_str = str.substr(pos, 3);
        int month = month_to_num(month_str);
        if (month < 0) return std::nullopt;
        pos += 4; // Move past month and space

        // Extract day (1-2 digits)
        // Skip leading space if present
        if (str[pos] == ' ') pos++;

        size_t day_len = 0;
        while (pos + day_len < str.size() &&
               std::isdigit(static_cast<unsigned char>(str[pos + day_len]))) {
            day_len++;
        }
        if (day_len == 0 || day_len > 2) return std::nullopt;

        // Extract day (1-2 digits) - Using from_chars for better performance
        int day = 0;
        if (std::from_chars(str.data() + pos, str.data() + pos + day_len, day).ec != std::errc{}) return std::nullopt;
        if (pos + day_len >= str.size() || str[pos + day_len] != ' ') return std::nullopt;
        pos += day_len + 1; // Move past day and space

        // Extract time - Using from_chars for better performance
        if (pos + 8 > str.size()) return std::nullopt;
        int hour = 0, minute = 0, second = 0;
        if (std::from_chars(str.data() + pos, str.data() + pos + 2, hour).ec != std::errc{}) return std::nullopt;
        if (str[pos + 2] != ':') return std::nullopt;
        if (std::from_chars(str.data() + pos + 3, str.data() + pos + 5, minute).ec != std::errc{}) return std::nullopt;
        if (str[pos + 5] != ':') return std::nullopt;
        if (std::from_chars(str.data() + pos + 6, str.data() + pos + 8, second).ec != std::errc{}) return std::nullopt;

        pos += 9; // Move past time and space

        // Extract year (4 digits) - Using from_chars for better performance
        if (pos + 4 != str.size()) return std::nullopt;
        int year = 0;
        if (std::from_chars(str.data() + pos, str.data() + pos + 4, year).ec != std::errc{}) return std::nullopt;

        return make_time_point_utc(year, month, day, hour, minute, second);
    }

    /**
     * @brief Parse an HTTP date string into a time point
     * @param str HTTP date string to parse
     * @return Optional time point, empty if parsing failed
     */
    std::optional<std::chrono::system_clock::time_point> parse_http_date(std::string_view const str) noexcept {
        try {
            // Try RFC 1123 format (preferred)
            if (str.find(',') != std::string_view::npos && str.find('-') == std::string_view::npos) {
                auto result = parse_rfc1123_date(str);
                if (result) return result;
            }

            // Try RFC 850 format
            if (str.find('-') != std::string_view::npos) {
                auto result = parse_rfc850_date(str);
                if (result) return result;
            }

            // Try ANSI C asctime() format
            auto result = parse_asctime_date(str);
            if (result) return result;

            // All formats failed
            return std::nullopt;
        } catch (...) {
            // Any exception during parsing
            return std::nullopt;
        }
    }

    /**
     * @brief Parse an HTTP date string into a time point
     * @param str HTTP date string to parse
     * @return Optional time point, empty if parsing failed
     */
    std::optional<std::chrono::system_clock::time_point> parse_http_date(std::string const &str) noexcept {
        return parse_http_date(std::string_view(str.data(), str.size()));
    }

    /**
     * @brief Parse a cookie date string into a time point
     * @param str Cookie date string to parse
     * @return Optional time point, empty if parsing failed
     */
    std::optional<std::chrono::system_clock::time_point> parse_cookie_date(std::string_view const str) noexcept {
        // For now, cookie date parsing is the same as HTTP date parsing
        // In a production system, we would implement the more lenient
        // RFC 6265 cookie date parsing algorithm
        return parse_http_date(str);
    }

    /**
     * @brief Parse a cookie date string into a time point
     * @param str Cookie date string to parse
     * @return Optional time point, empty if parsing failed
     */
    std::optional<std::chrono::system_clock::time_point> parse_cookie_date(std::string const &str) noexcept {
        return parse_cookie_date(std::string_view(str.data(), str.size()));
    }

    /**
     * @brief Get current time as an HTTP date string
     * @return Current time formatted as an HTTP date
     */
    std::string now() noexcept {
        return format_http_date(std::chrono::system_clock::now());
    }

    std::string
    format_timestamp(const std::chrono::system_clock::time_point &tp) {
        auto time = std::chrono::system_clock::to_time_t(tp);
        char buf[100];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&time));
        return std::string(buf);
    }
} // namespace qb::http::date

// Implement the Date class methods for backward compatibility
namespace qb::http {
    class Date {
    public:
        static std::string to_string(std::chrono::system_clock::time_point const tp) noexcept {
            return date::format_http_date(tp);
        }

        static qb::wall_time parse(std::string_view const str) noexcept {
            return date::parse_http_date(str).value_or(qb::wall_time{});
        }

        static qb::wall_time parse(std::string const &str) noexcept {
            return date::parse_http_date(str).value_or(qb::wall_time{});
        }
    };
} // namespace qb::http

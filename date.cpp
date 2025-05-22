/**
 * @file qbm/http/date.h
 * @brief HTTP-compliant date and time formatting and parsing utilities.
 *
 * This file provides functions within the `qb::http::date` namespace for converting
 * between various time representations (like `qb::Timestamp`, `std::chrono::system_clock::time_point`)
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

    /**
     * @brief Format a timestamp as an HTTP date string
     * @param ts Timestamp to format
     * @return Formatted date string conforming to RFC 7231
     */
    std::string format_http_date(qb::Timestamp const ts) noexcept {
        std::string result;
        result.reserve(29); // "Sun, 06 Nov 1994 08:49:37 GMT" = 29 chars

        const auto time = static_cast<int64_t>(ts.seconds());
        tm tm{};
#if defined(_MSC_VER) || defined(__MINGW32__)
    if (gmtime_s(&tm, &time) != 0)
        return {};
    auto gmtime = &tm;
#else
        const auto crt_time = static_cast<time_t>(time);
        const auto gmtime = gmtime_r(&crt_time, &tm);
        if (!gmtime)
            return {};
#endif

        // Day of week
        result += DAY_NAMES[gmtime->tm_wday];
        result += ", ";

        // Day of month (2 digits)
        result += gmtime->tm_mday < 10 ? '0' : static_cast<char>(gmtime->tm_mday / 10 + 48);
        result += static_cast<char>(gmtime->tm_mday % 10 + 48);
        result += ' ';

        // Month name
        result += MONTH_NAMES[gmtime->tm_mon];
        result += ' ';

        // Year (4 digits)
        const auto year = gmtime->tm_year + 1900;
        result += static_cast<char>(year / 1000 + 48);
        result += static_cast<char>((year / 100) % 10 + 48);
        result += static_cast<char>((year / 10) % 10 + 48);
        result += static_cast<char>(year % 10 + 48);
        result += ' ';

        // Hour (2 digits)
        result += gmtime->tm_hour < 10 ? '0' : static_cast<char>(gmtime->tm_hour / 10 + 48);
        result += static_cast<char>(gmtime->tm_hour % 10 + 48);
        result += ':';

        // Minute (2 digits)
        result += gmtime->tm_min < 10 ? '0' : static_cast<char>(gmtime->tm_min / 10 + 48);
        result += static_cast<char>(gmtime->tm_min % 10 + 48);
        result += ':';

        // Second (2 digits)
        result += gmtime->tm_sec < 10 ? '0' : static_cast<char>(gmtime->tm_sec / 10 + 48);
        result += static_cast<char>(gmtime->tm_sec % 10 + 48);

        result += " GMT";

        return result;
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
        if (str.size() < 29) return std::nullopt;

        // Skip weekday and comma
        auto pos = str.find(',');
        if (pos == std::string_view::npos) return std::nullopt;

        // Move past the comma and space
        pos += 2;
        if (pos >= str.size()) return std::nullopt;

        // Extract day (2 digits)
        if (pos + 2 > str.size()) return std::nullopt;
        std::string_view day_str = str.substr(pos, 2);
        int day = std::stoi(std::string(day_str.data(), day_str.size()));
        pos += 3; // Move past day and space

        // Extract month (3 chars)
        if (pos + 3 > str.size()) return std::nullopt;
        std::string_view month_str = str.substr(pos, 3);
        int month = month_to_num(month_str);
        if (month < 0) return std::nullopt;
        pos += 4; // Move past month and space

        // Extract year (4 digits)
        if (pos + 4 > str.size()) return std::nullopt;
        std::string_view year_str = str.substr(pos, 4);
        int year = std::stoi(std::string(year_str.data(), year_str.size()));
        pos += 5; // Move past year and space

        // Extract time
        if (pos + 8 > str.size()) return std::nullopt;
        std::string_view time_str = str.substr(pos, 8);
        int hour = std::stoi(std::string(time_str.substr(0, 2).data(), 2));
        int minute = std::stoi(std::string(time_str.substr(3, 2).data(), 2));
        int second = std::stoi(std::string(time_str.substr(6, 2).data(), 2));

        // Validate time components
        if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) {
            return std::nullopt;
        }

        // Create a tm structure and convert to time_point
        tm tm_value{};
        tm_value.tm_year = year - 1900;
        tm_value.tm_mon = month;
        tm_value.tm_mday = day;
        tm_value.tm_hour = hour;
        tm_value.tm_min = minute;
        tm_value.tm_sec = second;

        // Convert to time_t (seconds since epoch)
#if defined(_MSC_VER) || defined(__MINGW32__)
    time_t time_value = _mkgmtime(&tm_value);
#else
        time_t time_value = timegm(&tm_value);
#endif

        if (time_value == -1) return std::nullopt;

        return std::chrono::system_clock::from_time_t(time_value);
    }

    /**
     * @brief Parse an HTTP date string in RFC 850 format
     * @param str Date string in format "Sunday, 06-Nov-94 08:49:37 GMT"
     * @return Optional time point
     */
    std::optional<std::chrono::system_clock::time_point> parse_rfc850_date(std::string_view str) {
        // Format: "Sunday, 06-Nov-94 08:49:37 GMT"
        auto pos = str.find(',');
        if (pos == std::string_view::npos) return std::nullopt;

        // Move past the comma and space
        pos += 2;
        if (pos >= str.size()) return std::nullopt;

        // Extract day (2 digits)
        if (pos + 2 > str.size()) return std::nullopt;
        std::string_view day_str = str.substr(pos, 2);
        int day = std::stoi(std::string(day_str.data(), day_str.size()));
        pos += 3; // Move past day and hyphen

        // Extract month (3 chars)
        if (pos + 3 > str.size()) return std::nullopt;
        std::string_view month_str = str.substr(pos, 3);
        int month = month_to_num(month_str);
        if (month < 0) return std::nullopt;
        pos += 4; // Move past month and hyphen

        // Extract year (2 digits)
        if (pos + 2 > str.size()) return std::nullopt;
        std::string_view year_str = str.substr(pos, 2);
        int year = std::stoi(std::string(year_str.data(), year_str.size()));
        if (year < 70) {
            year += 2000; // Y2K pivot for 2-digit years
        } else {
            year += 1900;
        }
        pos += 3; // Move past year and space

        // Extract time
        if (pos + 8 > str.size()) return std::nullopt;
        std::string_view time_str = str.substr(pos, 8);
        int hour = std::stoi(std::string(time_str.substr(0, 2).data(), 2));
        int minute = std::stoi(std::string(time_str.substr(3, 2).data(), 2));
        int second = std::stoi(std::string(time_str.substr(6, 2).data(), 2));

        // Validate time components
        if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) {
            return std::nullopt;
        }

        // Create a tm structure and convert to time_point
        tm tm_value{};
        tm_value.tm_year = year - 1900;
        tm_value.tm_mon = month;
        tm_value.tm_mday = day;
        tm_value.tm_hour = hour;
        tm_value.tm_min = minute;
        tm_value.tm_sec = second;

        // Convert to time_t (seconds since epoch)
#if defined(_MSC_VER) || defined(__MINGW32__)
    time_t time_value = _mkgmtime(&tm_value);
#else
        time_t time_value = timegm(&tm_value);
#endif

        if (time_value == -1) return std::nullopt;

        return std::chrono::system_clock::from_time_t(time_value);
    }

    /**
     * @brief Parse an HTTP date string in ANSI C asctime() format
     * @param str Date string in format "Sun Nov  6 08:49:37 1994"
     * @return Optional time point
     */
    std::optional<std::chrono::system_clock::time_point> parse_asctime_date(std::string_view str) {
        // Format: "Sun Nov  6 08:49:37 1994"
        if (str.size() < 24) return std::nullopt;

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
        while (pos + day_len < str.size() && std::isdigit(str[pos + day_len])) {
            day_len++;
        }
        if (day_len == 0) return std::nullopt;

        std::string_view day_str = str.substr(pos, day_len);
        int day = std::stoi(std::string(day_str.data(), day_str.size()));
        pos += day_len + 1; // Move past day and space

        // Extract time
        if (pos + 8 > str.size()) return std::nullopt;
        std::string_view time_str = str.substr(pos, 8);
        int hour = std::stoi(std::string(time_str.substr(0, 2).data(), 2));
        int minute = std::stoi(std::string(time_str.substr(3, 2).data(), 2));
        int second = std::stoi(std::string(time_str.substr(6, 2).data(), 2));

        // Validate time components
        if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) {
            return std::nullopt;
        }
        pos += 9; // Move past time and space

        // Extract year (4 digits)
        if (pos + 4 > str.size()) return std::nullopt;
        std::string_view year_str = str.substr(pos, 4);
        int year = std::stoi(std::string(year_str.data(), year_str.size()));

        // Create a tm structure and convert to time_point
        tm tm_value{};
        tm_value.tm_year = year - 1900;
        tm_value.tm_mon = month;
        tm_value.tm_mday = day;
        tm_value.tm_hour = hour;
        tm_value.tm_min = minute;
        tm_value.tm_sec = second;

        // Convert to time_t (seconds since epoch)
#if defined(_MSC_VER) || defined(__MINGW32__)
    time_t time_value = _mkgmtime(&tm_value);
#else
        time_t time_value = timegm(&tm_value);
#endif

        if (time_value == -1) return std::nullopt;

        return std::chrono::system_clock::from_time_t(time_value);
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

    /**
     * @brief Convert a Timestamp to a system_clock::time_point
     * @param ts Timestamp to convert
     * @return Equivalent system_clock::time_point
     */
    std::chrono::system_clock::time_point to_time_point(qb::Timestamp const ts) noexcept {
        return std::chrono::system_clock::from_time_t(static_cast<time_t>(ts.seconds()));
    }

    /**
     * @brief Convert a system_clock::time_point to a Timestamp
     * @param tp Time point to convert
     * @return Equivalent Timestamp
     */
    qb::Timestamp to_timestamp(std::chrono::system_clock::time_point const tp) noexcept {
        auto time_since_epoch = tp.time_since_epoch();
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(time_since_epoch);
        return qb::Timestamp(static_cast<double>(seconds.count()));
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
        static std::string to_string(qb::Timestamp const ts) noexcept {
            return date::format_http_date(ts);
        }

        static std::string to_string(std::chrono::system_clock::time_point const tp) noexcept {
            return date::format_http_date(tp);
        }

        static qb::Timestamp parse(std::string_view const str) noexcept {
            auto tp = date::parse_http_date(str);
            return tp ? date::to_timestamp(*tp) : qb::Timestamp{};
        }

        static qb::Timestamp parse(std::string const &str) noexcept {
            auto tp = date::parse_http_date(str);
            return tp ? date::to_timestamp(*tp) : qb::Timestamp{};
        }
    };
} // namespace qb::http

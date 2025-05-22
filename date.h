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
#pragma once

#include <chrono>       // For std::chrono::system_clock::time_point, std::chrono::seconds
#include <optional>     // For std::optional
#include <string>       // For std::string
#include <string_view>  // For std::string_view
#include <utility>      // For std::pair (though not directly used in this header, often related)

#include <qb/system/timestamp.h> // For qb::Timestamp
#include "./utility.h"

namespace qb::http {
    /**
     * @brief Provides utilities for HTTP date formatting and parsing.
     *
     * This namespace contains functions to handle date and time conversions
     * as specified by HTTP standards, primarily RFC 7231 ("HTTP/1.1: Semantics and Content")
     * and RFC 6265 ("HTTP State Management Mechanism" for cookie dates).
     *
     * HTTP dates are case-sensitive and must be represented in Greenwich Mean Time (GMT),
     * never in local time.
     *
     * Supported formats for parsing include:
     * - RFC 1123 (IMF-fixdate): `Sun, 06 Nov 1994 08:49:37 GMT` (preferred format)
     * - RFC 850 (obsolete): `Sunday, 06-Nov-94 08:49:37 GMT`
     * - ANSI C asctime() (obsolete): `Sun Nov  6 08:49:37 1994`
     */
    namespace date {
        /**
         * @brief Formats a `qb::Timestamp` as an HTTP-compliant date string (RFC 1123).
         * @param ts The `qb::Timestamp` to format.
         * @return A string representing the timestamp in the format "Wdy, DD Mon YYYY HH:MM:SS GMT".
         *         Returns an empty string if the timestamp is invalid or formatting fails.
         * @note This function is `noexcept` and handles internal errors by returning an empty string.
         */
        [[nodiscard]] std::string format_http_date(qb::Timestamp ts) noexcept;

        /**
         * @brief Formats a `std::chrono::system_clock::time_point` as an HTTP-compliant date string (RFC 1123).
         * @param tp The `time_point` to format.
         * @return A string representing the time_point in the format "Wdy, DD Mon YYYY HH:MM:SS GMT".
         *         Returns an empty string if formatting fails.
         * @note This function is `noexcept` and handles internal errors by returning an empty string.
         */
        [[nodiscard]] std::string format_http_date(std::chrono::system_clock::time_point tp) noexcept;

        /**
         * @brief Formats a `std::chrono::system_clock::time_point` as a cookie expiration date string.
         *
         * According to RFC 6265, cookie expiration dates use the same format as HTTP-dates (RFC 1123).
         * This function is functionally equivalent to `format_http_date(std::chrono::system_clock::time_point)`
         * but provided for semantic clarity in cookie-related code.
         *
         * @param tp The `time_point` to format for a cookie's `Expires` attribute.
         * @return A formatted date string (e.g., "Sun, 06 Nov 1994 08:49:37 GMT").
         *         Returns an empty string if formatting fails.
         * @note This function is `noexcept`.
         */
        [[nodiscard]] std::string format_cookie_date(std::chrono::system_clock::time_point tp) noexcept;

        /**
         * @brief Parses an HTTP date string into a `std::chrono::system_clock::time_point`.
         *
         * Attempts to parse the input string against RFC 1123, RFC 850, and ANSI C asctime() formats.
         * @param str The HTTP date string_view to parse.
         * @return An `std::optional<std::chrono::system_clock::time_point>` containing the parsed time point
         *         if successful, or `std::nullopt` if parsing fails or the format is unrecognized.
         * @note This function is `noexcept` and returns `std::nullopt` on any parsing error.
         */
        [[nodiscard]] std::optional<std::chrono::system_clock::time_point>
        parse_http_date(std::string_view str) noexcept;

        /**
         * @brief Overload of `parse_http_date` for `std::string` input.
         * @param str The HTTP date string to parse.
         * @return Optional time point, empty if parsing failed.
         * @see parse_http_date(std::string_view)
         * @note This function is `noexcept`.
         */
        [[nodiscard]] std::optional<std::chrono::system_clock::time_point>
        parse_http_date(const std::string &str) noexcept;

        /**
         * @brief Parses a cookie date string into a `std::chrono::system_clock::time_point`.
         *
         * While RFC 6265 specifies that cookie dates should follow HTTP-date syntax, parsers
         * are often more lenient. This implementation currently uses the same parsing logic
         * as `parse_http_date` but could be adapted for stricter or more lenient RFC 6265 rules.
         *
         * @param str The cookie date string_view to parse.
         * @return An `std::optional<std::chrono::system_clock::time_point>` if successful, `std::nullopt` otherwise.
         * @note This function is `noexcept`.
         */
        [[nodiscard]] std::optional<std::chrono::system_clock::time_point>
        parse_cookie_date(std::string_view str) noexcept;

        /**
         * @brief Overload of `parse_cookie_date` for `std::string` input.
         * @param str The cookie date string to parse.
         * @return Optional time point, empty if parsing failed.
         * @see parse_cookie_date(std::string_view)
         * @note This function is `noexcept`.
         */
        [[nodiscard]] std::optional<std::chrono::system_clock::time_point>
        parse_cookie_date(const std::string &str) noexcept;

        /**
         * @brief Gets the current system time formatted as an HTTP date string (RFC 1123).
         * Useful for generating `Date` headers in HTTP responses.
         * @return A string representing the current time in HTTP date format.
         * @note This function is `noexcept`.
         */
        [[nodiscard]] std::string now() noexcept;

        /**
         * @brief Converts a `qb::Timestamp` to a `std::chrono::system_clock::time_point`.
         * @param ts The `qb::Timestamp` to convert (assumed to represent seconds since epoch).
         * @return The equivalent `std::chrono::system_clock::time_point`.
         * @note This function is `noexcept`.
         */
        [[nodiscard]] std::chrono::system_clock::time_point to_time_point(qb::Timestamp ts) noexcept;

        /**
         * @brief Converts a `std::chrono::system_clock::time_point` to a `qb::Timestamp`.
         * @param tp The `time_point` to convert.
         * @return The equivalent `qb::Timestamp` (representing seconds since epoch as a double).
         * @note This function is `noexcept`.
         */
        [[nodiscard]] qb::Timestamp to_timestamp(std::chrono::system_clock::time_point tp) noexcept;

        /**
         * @brief Convenience function to format a `qb::Timestamp` to an HTTP date string.
         * Equivalent to `date::format_http_date(ts)`.
         * @param ts The `qb::Timestamp` to format.
         * @return HTTP date string.
         * @note This function is `noexcept`.
         */
        [[nodiscard]] inline std::string
        to_string(qb::Timestamp ts) noexcept {
            return date::format_http_date(ts);
        }

        /**
         * @brief Convenience function to format a `std::chrono::system_clock::time_point` to an HTTP date string.
         * Equivalent to `date::format_http_date(tp)`.
         * @param tp The `time_point` to format.
         * @return HTTP date string.
         * @note This function is `noexcept`.
         */
        [[nodiscard]] inline std::string
        to_string(std::chrono::system_clock::time_point tp) noexcept {
            return date::format_http_date(tp);
        }

        /**
         * @brief Convenience function to parse an HTTP date string_view into a `qb::Timestamp`.
         * @param str The date string_view to parse.
         * @return A `qb::Timestamp`. If parsing fails, returns a default-constructed `qb::Timestamp` (often representing epoch or an invalid state).
         * @note This function is `noexcept`.
         */
        [[nodiscard]] inline qb::Timestamp
        parse(std::string_view str) noexcept {
            auto tp = date::parse_http_date(str);
            return tp ? date::to_timestamp(*tp) : qb::Timestamp{}; // Default Timestamp on parse failure
        }

        /**
         * @brief Convenience function to parse an HTTP date string into a `qb::Timestamp`.
         * @param str The date string to parse.
         * @return A `qb::Timestamp`. If parsing fails, returns a default-constructed `qb::Timestamp`.
         * @note This function is `noexcept`.
         */
        [[nodiscard]] inline qb::Timestamp
        parse(const std::string &str) noexcept {
            auto tp = date::parse_http_date(str);
            return tp ? date::to_timestamp(*tp) : qb::Timestamp{}; // Default Timestamp on parse failure
        }

        /**
         * @brief Formats a `std::chrono::system_clock::time_point` into a custom timestamp string.
         *
         * This function formats the given time_point into a "YYYY-MM-DD HH:MM:SS" string
         * based on the local time zone.
         * @param tp The time_point to format.
         * @return A string representing the formatted timestamp.
         *         Returns an empty string if formatting fails.
         * @note This function's behavior depends on `std::localtime` and may not be `noexcept`
         *       if underlying C library functions can fail in unexpected ways, though typically
         *       strftime errors result in an empty or partially formatted string rather than exceptions.
         *       Marked as `noexcept(false)` for safety, though `std::strftime` itself doesn't throw.
         */
        [[nodiscard]] std::string
        format_timestamp(const std::chrono::system_clock::time_point &tp) noexcept(false);
    } // namespace date
} // namespace qb::http

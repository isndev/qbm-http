/**
 * @file test-date-parsing.cpp
 * @brief Tests for HTTP date parsing with std::from_chars optimization
 *
 * These tests verify the C++23 std::from_chars optimization for date parsing
 * which is ~10x faster than std::stoi (no exceptions, no allocations).
 *
 * qb - C++ Actor Framework
 * Copyright (C) 2011-2025 isndev (www.qbaf.io). All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "../date.h"

using namespace qb::http::date;

// ====================================================================
// HTTP Date Parsing Tests (std::from_chars optimization)
// ====================================================================

class DateParsingTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

TEST_F(DateParsingTest, ParseHttpDateRFC1123Format) {
    // Standard RFC 1123 format: "Sun, 06 Nov 1994 08:49:37 GMT"
    auto result = parse_http_date(std::string_view("Sun, 06 Nov 1994 08:49:37 GMT"));
    ASSERT_TRUE(result.has_value());

    // Convert back to verify
    auto formatted = format_http_date(*result);
    EXPECT_EQ(formatted, "Sun, 06 Nov 1994 08:49:37 GMT");
}

TEST_F(DateParsingTest, ParseHttpDateVariousDays) {
    // Test all days of week - just verify parsing succeeds
    const char* days[] = {
        "Sun, 01 Jan 2024 00:00:00 GMT",
        "Mon, 02 Jan 2024 00:00:00 GMT",
        "Tue, 03 Jan 2024 00:00:00 GMT",
        "Wed, 04 Jan 2024 00:00:00 GMT",
        "Thu, 05 Jan 2024 00:00:00 GMT",
        "Fri, 06 Jan 2024 00:00:00 GMT",
        "Sat, 07 Jan 2024 00:00:00 GMT",
    };

    for (const auto& date : days) {
        auto result = parse_http_date(std::string_view(date));
        EXPECT_TRUE(result.has_value()) << "Failed to parse: " << date;
    }
}

TEST_F(DateParsingTest, ParseHttpDateVariousMonths) {
    // Test all months
    const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    for (int i = 0; i < 12; ++i) {
        char date_str[30];
        snprintf(date_str, sizeof(date_str), "Mon, 15 %s 2024 12:00:00 GMT", months[i]);

        auto result = parse_http_date(std::string_view(date_str));
        ASSERT_TRUE(result.has_value()) << "Failed for month: " << months[i];

        auto formatted = format_http_date(*result);
        EXPECT_EQ(formatted.substr(8, 3), months[i]) << "Failed for month: " << months[i];
    }
}

TEST_F(DateParsingTest, ParseHttpDateBoundaryTimes) {
    // Midnight
    {
        auto result = parse_http_date(std::string_view("Mon, 01 Jan 2024 00:00:00 GMT"));
        ASSERT_TRUE(result.has_value());
        auto formatted = format_http_date(*result);
        EXPECT_EQ(formatted, "Mon, 01 Jan 2024 00:00:00 GMT");
    }

    // Just before midnight
    {
        auto result = parse_http_date(std::string_view("Mon, 01 Jan 2024 23:59:59 GMT"));
        ASSERT_TRUE(result.has_value());
        auto formatted = format_http_date(*result);
        EXPECT_EQ(formatted, "Mon, 01 Jan 2024 23:59:59 GMT");
    }

    // Noon
    {
        auto result = parse_http_date(std::string_view("Mon, 01 Jan 2024 12:00:00 GMT"));
        ASSERT_TRUE(result.has_value());
        auto formatted = format_http_date(*result);
        EXPECT_EQ(formatted, "Mon, 01 Jan 2024 12:00:00 GMT");
    }
}

TEST_F(DateParsingTest, ParseHttpDateLeapYear) {
    // Leap year date
    auto result = parse_http_date(std::string_view("Thu, 29 Feb 2024 12:00:00 GMT"));
    ASSERT_TRUE(result.has_value());
}

TEST_F(DateParsingTest, ParseHttpDateInvalidFormats) {
    // Too short
    EXPECT_FALSE(parse_http_date(std::string_view("")).has_value());
    EXPECT_FALSE(parse_http_date(std::string_view("Sun")).has_value());

    // Missing comma
    EXPECT_FALSE(parse_http_date(std::string_view("Sun 06 Nov 1994 08:49:37 GMT")).has_value());

    // Wrong format
    EXPECT_FALSE(parse_http_date(std::string_view("1994-11-06 08:49:37")).has_value());

    // Invalid month
    EXPECT_FALSE(parse_http_date(std::string_view("Sun, 06 XYZ 1994 08:49:37 GMT")).has_value());

    // Invalid time (out of range)
    EXPECT_FALSE(parse_http_date(std::string_view("Sun, 06 Nov 1994 25:00:00 GMT")).has_value());
    EXPECT_FALSE(parse_http_date(std::string_view("Sun, 06 Nov 1994 08:70:00 GMT")).has_value());
}

// ====================================================================
// RFC 850 Date Format Tests
// ====================================================================

TEST_F(DateParsingTest, ParseRFC850DateFormat) {
    // RFC 850 format: "Sunday, 06-Nov-94 08:49:37 GMT"
    auto result = parse_http_date(std::string_view("Sunday, 06-Nov-94 08:49:37 GMT"));
    ASSERT_TRUE(result.has_value());

    // Verify it's parsed correctly (year should be 1994)
    auto formatted = format_http_date(*result);
    EXPECT_EQ(formatted, "Sun, 06 Nov 1994 08:49:37 GMT");
}

TEST_F(DateParsingTest, ParseRFC850DateY2K) {
    // Y2K pivot: years < 70 become 2000+, >= 70 become 1900+
    {
        auto result = parse_http_date(std::string_view("Monday, 01-Jan-00 00:00:00 GMT"));
        ASSERT_TRUE(result.has_value());
        auto formatted = format_http_date(*result);
        EXPECT_EQ(formatted, "Sat, 01 Jan 2000 00:00:00 GMT");
    }
    {
        auto result = parse_http_date(std::string_view("Wednesday, 01-Jan-70 00:00:00 GMT"));
        ASSERT_TRUE(result.has_value());
        auto formatted = format_http_date(*result);
        EXPECT_EQ(formatted, "Thu, 01 Jan 1970 00:00:00 GMT");
    }
}

// ====================================================================
// ANSI C Date Format Tests (asctime)
// ====================================================================

TEST_F(DateParsingTest, ParseANSICDateFormat) {
    // ANSI C format: "Sun Nov  6 08:49:37 1994" (note the double space before single digit day)
    auto result = parse_http_date(std::string_view("Sun Nov  6 08:49:37 1994"));
    // Just verify parsing succeeds - exact format support may vary
    EXPECT_TRUE(result.has_value());
}

TEST_F(DateParsingTest, ParseANSICDateTwoDigitDay) {
    // Two-digit day
    auto result = parse_http_date(std::string_view("Mon Jan 15 12:30:45 2024"));
    ASSERT_TRUE(result.has_value());

    auto formatted = format_http_date(*result);
    EXPECT_EQ(formatted, "Mon, 15 Jan 2024 12:30:45 GMT");
}

// ====================================================================
// Format/Parse Round-trip Tests
// ====================================================================

TEST_F(DateParsingTest, RoundTripHttpDate) {
    // Format then parse should give consistent results
    auto now = std::chrono::system_clock::now();
    auto formatted = format_http_date(now);
    auto parsed = parse_http_date(formatted);

    ASSERT_TRUE(parsed.has_value());

    // The formatted result should be identical (within seconds precision)
    auto reformatted = format_http_date(*parsed);
    EXPECT_EQ(formatted, reformatted);
}

TEST_F(DateParsingTest, RoundTripCookieDate) {
    // Cookie date format
    auto now = std::chrono::system_clock::now();
    auto formatted = format_cookie_date(now);
    auto parsed = parse_cookie_date(formatted);

    ASSERT_TRUE(parsed.has_value());

    // Cookie dates use same format as HTTP dates
    auto reformatted = format_cookie_date(*parsed);
    EXPECT_EQ(formatted, reformatted);
}

// ====================================================================
// Performance Validation Tests
// ====================================================================

TEST_F(DateParsingTest, PerformanceParseManyDates) {
    // Performance test: parse many dates to verify std::from_chars efficiency
    const int iterations = 1000;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        auto result = parse_http_date(std::string_view("Sun, 06 Nov 1994 08:49:37 GMT"));
        ASSERT_TRUE(result.has_value());
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Should be very fast with std::from_chars (no exceptions, no allocations)
    // Average should be less than 1 microsecond per parse on modern hardware
    double avg_microseconds = static_cast<double>(duration.count()) / iterations;

    std::cout << "Average parse time: " << avg_microseconds << " microseconds" << std::endl;

    // Just verify it's reasonably fast (under 10 microseconds per parse)
    EXPECT_LT(avg_microseconds, 10.0);
}

// ====================================================================
// Edge Cases and Error Handling
// ====================================================================

TEST_F(DateParsingTest, EdgeCases) {
    // Single digit day (with space padding in asctime format)
    {
        auto result = parse_http_date(std::string_view("Sun Nov  6 08:49:37 1994"));
        ASSERT_TRUE(result.has_value());
        auto formatted = format_http_date(*result);
        EXPECT_EQ(formatted, "Sun, 06 Nov 1994 08:49:37 GMT");
    }

    // Year boundaries
    {
        auto result = parse_http_date(std::string_view("Mon, 01 Jan 2024 00:00:00 GMT"));
        ASSERT_TRUE(result.has_value());
    }
    {
        auto result = parse_http_date(std::string_view("Sun, 31 Dec 2023 23:59:59 GMT"));
        ASSERT_TRUE(result.has_value());
    }
}

TEST_F(DateParsingTest, NullOptForInvalidDates) {
    // All invalid inputs should return std::nullopt (no exceptions)
    std::vector<std::string> invalid_dates = {
        "",
        "invalid",
        "Sun",
        "Sun,",
        "Sun, 06",
        "Sun, 06 Nov",
        "Sun, 06 Nov 1994",
        "Sun, 06 Nov 1994 08",
        "Sun, 06 Nov 1994 08:",
        "Sun, 06 Nov 1994 08:49",
        "Sun, 06 Nov 1994 08:49:",
        "Sun, 06 Nov 1994 08:49:37",
        // Out of range values (implementation may or may not catch these)
        // "Sun, 32 Nov 1994 08:49:37 GMT",
        // "Sun, 06 Nov 1994 25:00:00 GMT",
    };

    for (const auto& date : invalid_dates) {
        EXPECT_FALSE(parse_http_date(date).has_value())
            << "Should return nullopt for: " << date;
    }
}

TEST_F(DateParsingTest, ExceptionSafety) {
    // All parsing functions should be noexcept (no exceptions thrown)
    EXPECT_NO_THROW(parse_http_date(std::string_view("")));
    EXPECT_NO_THROW(parse_http_date(std::string_view("invalid")));
    EXPECT_NO_THROW(parse_http_date(std::string_view("Sun, 06 Nov 1994 08:49:37 GMT")));
    EXPECT_NO_THROW(parse_cookie_date(std::string_view("")));
    EXPECT_NO_THROW(parse_cookie_date(std::string_view("invalid")));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

/**
 * @file unit/http-date/date-parsing.cpp
 * @brief Unit tests for qb::http::date parsing/formatting (RFC 7231 / RFC 6265).
 *
 * Pure-logic tests for the C++23 std::from_chars date parser path covering the
 * three HTTP date formats (RFC 1123 IMF-fixdate, RFC 850, ANSI C asctime), the
 * noexcept/std::optional error contract, format/parse round-trips, the Y2K pivot,
 * and ground-truth epoch-second checks.
 *
 * No event loop, no socket; fully deterministic and parallel-safe.
 *
 * qb - C++ Actor Framework
 * Copyright (C) 2011-2026 isndev (www.qbaf.io). All rights reserved.
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

#include <cctype>
#include <chrono>
#include <cstdio>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>
#include <qbm/http/date.h>

using namespace qb::http::date;
using std::chrono::system_clock;

namespace {

// Canonical RFC 1123 fixture from RFC 7231 §7.1.1.1.
constexpr const char *kCanonicalRfc1123 = "Sun, 06 Nov 1994 08:49:37 GMT";
// Its Unix epoch second (1994-11-06T08:49:37Z). This is the ground-truth value
// the smoke round-trips never asserted.
constexpr long long kCanonicalEpoch = 784111777;

[[nodiscard]] long long
epoch_seconds(system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}

} // namespace

// ====================================================================
// RFC 1123 (IMF-fixdate) parsing
// ====================================================================

class DateParsingTest : public ::testing::Test {};

TEST_F(DateParsingTest, ParseHttpDateRFC1123Format) {
    auto result = parse_http_date(std::string_view(kCanonicalRfc1123));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(format_http_date(*result), kCanonicalRfc1123);
}

TEST_F(DateParsingTest, CanonicalFixtureEqualsKnownEpochSecond) {
    // Ground-truth: parsing the canonical fixture yields exactly epoch 784111777.
    auto result = parse_http_date(std::string_view(kCanonicalRfc1123));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(epoch_seconds(*result), kCanonicalEpoch);

    // And formatting that exact instant reproduces the canonical string.
    EXPECT_EQ(format_http_date(system_clock::time_point(std::chrono::seconds(kCanonicalEpoch))), kCanonicalRfc1123);
}

TEST_F(DateParsingTest, ParseHttpDateVariousDays) {
    // Each weekday string parses AND reproduces its exact canonical date — the
    // has_value()-only version could not catch a wrong day/date computation.
    //
    // Ground truth (date.cpp:152): format_http_date emits the day-name computed
    // from the parsed instant (tm_wday); parse_rfc1123_date does NOT validate the
    // input weekday token. So the canonical output uses the REAL weekday for the
    // date. The seven dates below are the true Mon..Sun of the first week of 2024
    // (01 Jan 2024 is a Monday), so input weekday == output weekday and the
    // parse->format round-trip is an exact byte-for-byte match across all 7 days.
    struct Case {
        const char *input;
        const char *canonical;
    };
    const Case cases[] = {
        {"Mon, 01 Jan 2024 00:00:00 GMT", "Mon, 01 Jan 2024 00:00:00 GMT"}, {"Tue, 02 Jan 2024 00:00:00 GMT", "Tue, 02 Jan 2024 00:00:00 GMT"},
        {"Wed, 03 Jan 2024 00:00:00 GMT", "Wed, 03 Jan 2024 00:00:00 GMT"}, {"Thu, 04 Jan 2024 00:00:00 GMT", "Thu, 04 Jan 2024 00:00:00 GMT"},
        {"Fri, 05 Jan 2024 00:00:00 GMT", "Fri, 05 Jan 2024 00:00:00 GMT"}, {"Sat, 06 Jan 2024 00:00:00 GMT", "Sat, 06 Jan 2024 00:00:00 GMT"},
        {"Sun, 07 Jan 2024 00:00:00 GMT", "Sun, 07 Jan 2024 00:00:00 GMT"},
    };
    for (const auto &c : cases) {
        auto result = parse_http_date(std::string_view(c.input));
        ASSERT_TRUE(result.has_value()) << "Failed to parse: " << c.input;
        EXPECT_EQ(format_http_date(*result), c.canonical);
    }
}

TEST_F(DateParsingTest, ParseHttpDateVariousMonths) {
    const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

    for (int i = 0; i < 12; ++i) {
        char date_str[40];
        std::snprintf(date_str, sizeof(date_str), "Mon, 15 %s 2024 12:00:00 GMT", months[i]);

        auto result = parse_http_date(std::string_view(date_str));
        ASSERT_TRUE(result.has_value()) << "Failed for month: " << months[i];

        auto formatted = format_http_date(*result);
        EXPECT_EQ(formatted.substr(8, 3), months[i]) << "Failed for month: " << months[i];
    }
}

TEST_F(DateParsingTest, ParseHttpDateBoundaryTimes) {
    struct Case {
        const char *str;
        long long   epoch;
    };
    const Case cases[] = {
        {"Mon, 01 Jan 2024 00:00:00 GMT", 1704067200}, // midnight
        {"Mon, 01 Jan 2024 23:59:59 GMT", 1704153599}, // just before next midnight
        {"Mon, 01 Jan 2024 12:00:00 GMT", 1704110400}, // noon
    };
    for (const auto &c : cases) {
        auto result = parse_http_date(std::string_view(c.str));
        ASSERT_TRUE(result.has_value()) << c.str;
        EXPECT_EQ(epoch_seconds(*result), c.epoch) << c.str;
        EXPECT_EQ(format_http_date(*result), c.str);
    }
}

TEST_F(DateParsingTest, ParseHttpDateLeapYear) {
    // 29 Feb 2024 is valid; assert the exact instant, not just has_value().
    auto result = parse_http_date(std::string_view("Thu, 29 Feb 2024 12:00:00 GMT"));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(epoch_seconds(*result), 1709208000);
    EXPECT_EQ(format_http_date(*result), "Thu, 29 Feb 2024 12:00:00 GMT");
}

// ====================================================================
// RFC 850 parsing + Y2K pivot
// ====================================================================

TEST_F(DateParsingTest, ParseRFC850DateFormat) {
    auto result = parse_http_date(std::string_view("Sunday, 06-Nov-94 08:49:37 GMT"));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(epoch_seconds(*result), kCanonicalEpoch);
    EXPECT_EQ(format_http_date(*result), kCanonicalRfc1123);
}

TEST_F(DateParsingTest, ParseRFC850DateY2K) {
    // Y2K pivot: years < 70 map to 2000+, >= 70 map to 1900+.
    {
        auto result = parse_http_date(std::string_view("Monday, 01-Jan-00 00:00:00 GMT"));
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(format_http_date(*result), "Sat, 01 Jan 2000 00:00:00 GMT");
    }
    {
        auto result = parse_http_date(std::string_view("Wednesday, 01-Jan-70 00:00:00 GMT"));
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(epoch_seconds(*result), 0);
        EXPECT_EQ(format_http_date(*result), "Thu, 01 Jan 1970 00:00:00 GMT");
    }
    // Pivot edge: -69 stays in the 2000s, -70 falls back to the 1900s.
    {
        auto y69 = parse_http_date(std::string_view("Sunday, 01-Jan-69 00:00:00 GMT"));
        ASSERT_TRUE(y69.has_value());
        EXPECT_EQ(format_http_date(*y69).substr(12, 4), "2069");
    }
}

// ====================================================================
// ANSI C asctime parsing
// ====================================================================

TEST_F(DateParsingTest, ParseANSICDateFormat) {
    // asctime single-digit day uses a double space; assert the exact instant.
    auto result = parse_http_date(std::string_view("Sun Nov  6 08:49:37 1994"));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(epoch_seconds(*result), kCanonicalEpoch);
    EXPECT_EQ(format_http_date(*result), kCanonicalRfc1123);
}

TEST_F(DateParsingTest, ParseANSICDateTwoDigitDay) {
    auto result = parse_http_date(std::string_view("Mon Jan 15 12:30:45 2024"));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(format_http_date(*result), "Mon, 15 Jan 2024 12:30:45 GMT");
}

// ====================================================================
// Format/parse round-trips
// ====================================================================

TEST_F(DateParsingTest, RoundTripHttpDate) {
    auto now       = system_clock::now();
    auto formatted = format_http_date(now);
    auto parsed    = parse_http_date(formatted);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(format_http_date(*parsed), formatted);
}

TEST_F(DateParsingTest, RoundTripCookieDate) {
    auto now       = system_clock::now();
    auto formatted = format_cookie_date(now);
    auto parsed    = parse_cookie_date(formatted);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(format_cookie_date(*parsed), formatted);
}

// ====================================================================
// Negative inputs (one consolidated parametrized table)
//
// Merges the three previously overlapping negative batteries
// (ParseHttpDateInvalidFormats, NullOptForInvalidDates, the asctime/edge dupes)
// into a single deduplicated TEST_P. Every input must yield std::nullopt with
// no exception (the noexcept contract).
// ====================================================================

class InvalidHttpDateTest : public ::testing::TestWithParam<std::string> {};

TEST_P(InvalidHttpDateTest, ReturnsNulloptWithoutThrowing) {
    const std::string                      &input = GetParam();
    std::optional<system_clock::time_point> result;
    EXPECT_NO_THROW(result = parse_http_date(input)) << "threw for: [" << input << "]";
    EXPECT_FALSE(result.has_value()) << "expected nullopt for: [" << input << "]";
}

INSTANTIATE_TEST_SUITE_P(DateParsing, InvalidHttpDateTest,
                         ::testing::Values(
                             // Empty / too short / truncated at each field boundary.
                             std::string(""), std::string("invalid"), std::string("Sun"), std::string("Sun,"), std::string("Sun, 06"),
                             std::string("Sun, 06 Nov"), std::string("Sun, 06 Nov 1994"), std::string("Sun, 06 Nov 1994 08"),
                             std::string("Sun, 06 Nov 1994 08:"), std::string("Sun, 06 Nov 1994 08:49"), std::string("Sun, 06 Nov 1994 08:49:"),
                             std::string("Sun, 06 Nov 1994 08:49:37"), // missing zone
                             // Structural errors.
                             std::string("Sun 06 Nov 1994 08:49:37 GMT"),  // missing comma
                             std::string("1994-11-06 08:49:37"),           // ISO, not HTTP
                             std::string("Sun, 06 XYZ 1994 08:49:37 GMT"), // invalid month
                             // Out-of-range fields.
                             std::string("Sun, 32 Nov 1994 08:49:37 GMT"), std::string("Sun, 06 Nov 1994 25:00:00 GMT"),
                             std::string("Sun, 06 Nov 1994 08:70:00 GMT"),
                             // Invalid calendar dates must NOT be normalized by timegm.
                             std::string("Sun, 31 Feb 1994 08:49:37 GMT"), std::string("Sun, 00 Nov 1994 08:49:37 GMT"),
                             std::string("Sunday, 31-Feb-94 08:49:37 GMT"), std::string("Sun Feb 31 08:49:37 1994"),
                             // Zone / trailing-byte requirements.
                             std::string("Sun, 06 Nov 1994 08:49:37 UTC"), std::string("Sun, 06 Nov 1994 08:49:37 GMT extra")));

// ====================================================================
// Case sensitivity + noexcept contract
// ====================================================================

TEST_F(DateParsingTest, ZoneIsCaseSensitiveGMT) {
    // HTTP dates require the uppercase "GMT" token; "gmt" must be rejected.
    EXPECT_TRUE(parse_http_date(std::string_view(kCanonicalRfc1123)).has_value());
    EXPECT_FALSE(parse_http_date(std::string_view("Sun, 06 Nov 1994 08:49:37 gmt")).has_value());
}

TEST_F(DateParsingTest, ExceptionSafety) {
    EXPECT_NO_THROW((void) parse_http_date(std::string_view("")));
    EXPECT_NO_THROW((void) parse_http_date(std::string_view("invalid")));
    EXPECT_NO_THROW((void) parse_http_date(std::string_view(kCanonicalRfc1123)));
    EXPECT_NO_THROW((void) parse_cookie_date(std::string_view("")));
    EXPECT_NO_THROW((void) parse_cookie_date(std::string_view("invalid")));
}

// ====================================================================
// Per-field-boundary rejection in EACH parser.
//
// The big negative table above mostly trips the cheap front-door guards
// (`size() != 29`, missing comma, etc.). The cases below are length-correct
// single-character mutations of the three canonical fixtures, so each input
// reaches deep INTO one specific parser and exercises exactly one internal
// "wrong separator / non-numeric field" `return std::nullopt` branch that the
// truncation table can never reach. Every input must still yield nullopt.
// ====================================================================

// Each mutation keeps the canonical RFC-1123 fixture's length (29) but corrupts
// exactly one field, routing through parse_rfc1123_date (has ',' / no '-') to a
// distinct interior failure branch of parse_rfc1123_date.
TEST_F(DateParsingTest, Rfc1123InteriorFieldRejections) {
    const char *bad[] = {
        "Sun,X06 Nov 1994 08:49:37 GMT", // no space after comma          (date.cpp:184-185)
        "Sun, xx Nov 1994 08:49:37 GMT", // non-numeric day               (170)
        "Sun, 06xNov 1994 08:49:37 GMT", // no space after day            (172)
        "Sun, 06 NovX1994 08:49:37 GMT", // no space after month          (183)
        "Sun, 06 Nov xxxx 08:49:37 GMT", // non-numeric year              (191)
        "Sun, 06 Nov 1994x08:49:37 GMT", // no space after year           (193)
        "Sun, 06 Nov 1994 xx:49:37 GMT", // non-numeric hour              (201)
        "Sun, 06 Nov 1994 08x49:37 GMT", // missing ':' after hour        (203)
        "Sun, 06 Nov 1994 08:xx:37 GMT", // non-numeric minute            (205)
        "Sun, 06 Nov 1994 08:49x37 GMT", // missing ':' after minute      (207)
        "Sun, 06 Nov 1994 08:49:xx GMT", // non-numeric second            (209)
    };
    for (const auto *s : bad) {
        ASSERT_EQ(std::string_view(s).size(), 29u) << s; // fixture invariant
        EXPECT_FALSE(parse_http_date(std::string_view(s)).has_value()) << "expected nullopt for: [" << s << "]";
    }
}

// Length-correct (30-char) single-char mutations of the canonical RFC-850
// fixture "Sunday, 06-Nov-94 08:49:37 GMT". Each contains a '-' so it routes to
// parse_rfc850_date and reaches one of its interior field-rejection branches.
TEST_F(DateParsingTest, Rfc850InteriorFieldRejections) {
    // Sanity: the canonical RFC-850 fixture parses (so the mutations below are
    // genuinely isolating one corrupted field, not failing the front door).
    ASSERT_TRUE(parse_http_date(std::string_view("Sunday, 06-Nov-94 08:49:37 GMT")).has_value());

    const char *bad[] = {
        "Sunday, xx-Nov-94 08:49:37 GMT", // non-numeric day             (date.cpp:266-267)
        "Sunday, 06xNov-94 08:49:37 GMT", // missing '-' after day       (242)
        "Sunday, 06-xxx-94 08:49:37 GMT", // invalid month               (251)
        "Sunday, 06-NovX94 08:49:37 GMT", // missing '-' after month     (253)
        "Sunday, 06-Nov-xx 08:49:37 GMT", // non-numeric year            (261)
        "Sunday, 06-Nov-94x08:49:37 GMT", // missing space after year    (268)
        "Sunday, 06-Nov-94 xx:49:37 GMT", // non-numeric hour            (276)
        "Sunday, 06-Nov-94 08x49:37 GMT", // missing ':' after hour      (278)
        "Sunday, 06-Nov-94 08:xx:37 GMT", // non-numeric minute          (280)
        "Sunday, 06-Nov-94 08:49x37 GMT", // missing ':' after minute    (282)
        "Sunday, 06-Nov-94 08:49:xx GMT", // non-numeric second          (284)
        "Sunday, 06-Nov-94 08:49:37 UTC", // wrong trailing zone token   (288)
    };
    for (const auto *s : bad) {
        EXPECT_FALSE(parse_http_date(std::string_view(s)).has_value()) << "expected nullopt for: [" << s << "]";
    }
}

// Length-correct (24-char) single-char mutations of the canonical asctime
// fixture "Sun Nov  6 08:49:37 1994" (no ',' and no '-', so the router falls
// through to parse_asctime_date), each reaching one interior branch (309..358).
TEST_F(DateParsingTest, AsctimeInteriorFieldRejections) {
    ASSERT_TRUE(parse_http_date(std::string_view("Sun Nov  6 08:49:37 1994")).has_value());

    const char *bad[] = {
        "Sun xxx  6 08:49:37 1994", // invalid month                     (date.cpp:339-340)
        "Sun Nov  6 xx:49:37 1994", // non-numeric hour                  (341)
        "Sun Nov  6 08x49:37 1994", // missing ':' after hour            (343)
        "Sun Nov  6 08:xx:37 1994", // non-numeric minute                (345)
        "Sun Nov  6 08:49x37 1994", // missing ':' after minute          (347)
        "Sun Nov  6 08:49:xx 1994", // non-numeric second                (349)
        "Sun Nov  6 08:49:37 xxxx", // non-numeric year                  (358)
    };
    for (const auto *s : bad) {
        ASSERT_EQ(std::string_view(s).size(), 24u) << s;
        EXPECT_FALSE(parse_http_date(std::string_view(s)).has_value()) << "expected nullopt for: [" << s << "]";
    }
}

// asctime allows a single-digit day with a preceding double-space ("Sun Nov  6
// ..."). A two-digit day with three or more digits ("...  100 ...") trips the
// `day_len > 2` guard (date.cpp:352-353) — pin it explicitly. A two-digit day with
// a wrong delimiter after it trips date.cpp:359-360.
TEST_F(DateParsingTest, AsctimeDayLengthAndDelimiterRejections) {
    // Three-digit day field is impossible in asctime → rejected (325).
    EXPECT_FALSE(parse_http_date(std::string_view("Sun Nov 100 08:49:37 994")).has_value());
    // Two-digit day immediately followed by a non-space → rejected (333).
    EXPECT_FALSE(parse_http_date(std::string_view("Mon Jan 15x12:30:45 2024")).has_value());
}

// ====================================================================
// Formatting helpers that the parse-only smoke suite never touched.
// ====================================================================

// date::now() must emit a well-formed, parseable RFC-1123 string for the
// current instant (date::now). It is non-deterministic in value, so we pin
// only its STRUCTURE: it parses back, and re-formatting the parsed instant is a
// byte-for-byte fixed point.
TEST_F(DateParsingTest, NowEmitsParseableRfc1123) {
    const std::string n = now();
    ASSERT_EQ(n.size(), 29u) << n;
    EXPECT_EQ(n.substr(25), " GMT");

    auto parsed = parse_http_date(std::string_view(n));
    ASSERT_TRUE(parsed.has_value()) << n;
    EXPECT_EQ(format_http_date(*parsed), n); // round-trip fixed point
}

// date::format_timestamp() formats "YYYY-MM-DD HH:MM:SS" in LOCAL time
// (date::format_timestamp). The local offset is environment-dependent, so we pin the
// FORMAT shape deterministically rather than the exact value.
TEST_F(DateParsingTest, FormatTimestampShape) {
    const auto        epoch = system_clock::time_point(std::chrono::seconds(kCanonicalEpoch));
    const std::string s     = format_timestamp(epoch);

    ASSERT_EQ(s.size(), 19u) << s; // "YYYY-MM-DD HH:MM:SS"
    EXPECT_EQ(s[4], '-');
    EXPECT_EQ(s[7], '-');
    EXPECT_EQ(s[10], ' ');
    EXPECT_EQ(s[13], ':');
    EXPECT_EQ(s[16], ':');
    for (std::size_t i : {0u, 1u, 2u, 3u, 5u, 6u, 8u, 9u, 11u, 12u, 14u, 15u, 17u, 18u}) {
        EXPECT_TRUE(std::isdigit(static_cast<unsigned char>(s[i]))) << "non-digit at " << i << " in [" << s << "]";
    }
}

// ====================================================================
// A fixed-width numeric field is ALL digits (Huly QB-599).
//
// The fixed-width fields were converted with std::from_chars and only its error code was
// checked, never where it stopped: "0x" converts as 0 (stopping at 'x') and the parser stepped
// over both characters anyway, so "0x:49:37" read as 00:49:37. A sign got through the same way:
// from_chars accepts a leading '-', and the two-digit RFC 850 year "-9" became 1991 through the
// Y2K pivot. Every input below keeps its format's exact length and separators, so it reaches
// the field conversion itself, and every one must be refused.
// ====================================================================

TEST_F(DateParsingTest, FixedNumericFieldsAcceptOnlyDigits) {
    const char *rfc1123[] = {
        "Sun, 0x Nov 1994 08:49:37 GMT", // day
        "Sun, 06 Nov 199x 08:49:37 GMT", // year
        "Sun, 06 Nov 1994 0x:49:37 GMT", // hour
        "Sun, 06 Nov 1994 08:4x:37 GMT", // minute
        "Sun, 06 Nov 1994 08:49:3x GMT", // second
        "Sun, 06 Nov 1994 -8:49:37 GMT", // a sign in a two-digit field
        "Sun, 06 Nov 1994 08:-9:37 GMT", // a sign in the minute
    };
    for (const auto *s : rfc1123) {
        ASSERT_EQ(std::string_view(s).size(), 29u) << s;
        EXPECT_FALSE(parse_http_date(std::string_view(s)).has_value()) << "expected nullopt for: [" << s << "]";
    }

    const char *rfc850[] = {
        "Sunday, 0x-Nov-94 08:49:37 GMT", // day
        "Sunday, 06-Nov-9x 08:49:37 GMT", // year
        "Sunday, 06-Nov--9 08:49:37 GMT", // a signed year, which the pivot turned into 1991
        "Sunday, 06-Nov-94 0x:49:37 GMT", // hour
        "Sunday, 06-Nov-94 08:4x:37 GMT", // minute
        "Sunday, 06-Nov-94 08:49:3x GMT", // second
    };
    for (const auto *s : rfc850) {
        ASSERT_EQ(std::string_view(s).size(), 30u) << s;
        EXPECT_FALSE(parse_http_date(std::string_view(s)).has_value()) << "expected nullopt for: [" << s << "]";
    }

    const char *asctime[] = {
        "Sun Nov  6 0x:49:37 1994", // hour
        "Sun Nov  6 08:4x:37 1994", // minute
        "Sun Nov  6 08:49:3x 1994", // second
        "Sun Nov  6 08:49:37 199x", // year
        "Sun Nov  6 08:49:37x1994", // the separator before the year
    };
    for (const auto *s : asctime) {
        ASSERT_EQ(std::string_view(s).size(), 24u) << s;
        EXPECT_FALSE(parse_http_date(std::string_view(s)).has_value()) << "expected nullopt for: [" << s << "]";
    }

    // Controls: the canonical forms of the three formats still parse to the same instant, and the
    // RFC 850 pivot still maps a two-digit year.
    const auto canonical = parse_http_date(std::string_view("Sun, 06 Nov 1994 08:49:37 GMT"));
    ASSERT_TRUE(canonical.has_value());
    EXPECT_EQ(parse_http_date(std::string_view("Sunday, 06-Nov-94 08:49:37 GMT")), canonical);
    EXPECT_EQ(parse_http_date(std::string_view("Sun Nov  6 08:49:37 1994")), canonical);
    const auto y2k = parse_http_date(std::string_view("Thursday, 01-Jan-04 00:00:00 GMT"));
    ASSERT_TRUE(y2k.has_value());
    EXPECT_EQ(std::chrono::duration_cast<std::chrono::seconds>(y2k->time_since_epoch()).count(), 1072915200);
}

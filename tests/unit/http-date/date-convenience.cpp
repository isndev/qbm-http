/**
 * @file qbm/http/tests/unit/http-date/date-convenience.cpp
 * @brief Unit tests for the inline convenience wrappers in date.h that
 *        date-parsing.cpp never calls.
 *
 * date-parsing.cpp drives the out-of-line parser/formatter in date.cpp through
 * the `string_view` overloads of `parse_http_date` / `format_http_date` and the
 * helpers `now()` / `format_timestamp()`. It never touches the thin inline
 * convenience layer declared in date.h itself, which therefore sits uncovered:
 *
 *   - `to_string(tp)`            — alias for `format_http_date(tp)`.
 *   - `parse(string_view)`       — `parse_http_date(...).value_or(wall_time{})`.
 *   - `parse(const std::string&) — same, std::string overload.
 *   - `parse_http_date(const std::string&)`  — the std::string forwarder.
 *   - `parse_cookie_date(const std::string&)` — the std::string forwarder.
 *
 * The wrappers' contract is asserted against the canonical RFC 7231 fixture and
 * its known epoch second, including the documented failure semantics of `parse()`
 * (returns the epoch `wall_time{}`, NOT nullopt, on a bad string).
 *
 * No event loop, no socket; fully deterministic and parallel-safe.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <string_view>

#include <qbm/http/date.h>

using namespace qb::http::date;
using std::chrono::system_clock;

namespace {

constexpr const char *kCanonicalRfc1123 = "Sun, 06 Nov 1994 08:49:37 GMT";
constexpr long long   kCanonicalEpoch   = 784111777; // 1994-11-06T08:49:37Z

[[nodiscard]] long long
epoch_seconds(system_clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}

} // namespace

// ---------------------------------------------------------------------------
// to_string(tp) — alias for format_http_date(tp).
// ---------------------------------------------------------------------------

TEST(DateConvenience, ToStringMatchesFormatHttpDate) {
    const auto tp = system_clock::time_point(std::chrono::seconds(kCanonicalEpoch));
    EXPECT_EQ(to_string(tp), kCanonicalRfc1123);
    EXPECT_EQ(to_string(tp), format_http_date(tp)); // exact alias contract
}

// ---------------------------------------------------------------------------
// parse(...) → qb::wall_time, value_or(epoch) on failure.
// ---------------------------------------------------------------------------

TEST(DateConvenience, ParseStringViewYieldsWallTime) {
    qb::wall_time wt = parse(std::string_view(kCanonicalRfc1123));
    EXPECT_EQ(epoch_seconds(wt), kCanonicalEpoch);
}

TEST(DateConvenience, ParseStdStringYieldsWallTime) {
    qb::wall_time wt = parse(std::string(kCanonicalRfc1123));
    EXPECT_EQ(epoch_seconds(wt), kCanonicalEpoch);
}

TEST(DateConvenience, ParseInvalidReturnsEpochWallTimeNotNullopt) {
    // Documented behaviour: parse() collapses a failure to qb::wall_time{} (epoch),
    // unlike parse_http_date() which returns std::nullopt.
    EXPECT_EQ(epoch_seconds(parse(std::string_view("not a date"))), 0);
    EXPECT_EQ(epoch_seconds(parse(std::string(""))), 0);
    EXPECT_EQ(parse(std::string_view("garbage")), qb::wall_time{});
}

// ---------------------------------------------------------------------------
// std::string overloads of parse_http_date / parse_cookie_date.
// ---------------------------------------------------------------------------

TEST(DateConvenience, ParseHttpDateStdStringOverload) {
    auto ok = parse_http_date(std::string(kCanonicalRfc1123));
    ASSERT_TRUE(ok.has_value());
    EXPECT_EQ(epoch_seconds(*ok), kCanonicalEpoch);

    auto bad = parse_http_date(std::string("nope"));
    EXPECT_FALSE(bad.has_value());
}

TEST(DateConvenience, ParseCookieDateStdStringOverload) {
    auto ok = parse_cookie_date(std::string(kCanonicalRfc1123));
    ASSERT_TRUE(ok.has_value());
    EXPECT_EQ(epoch_seconds(*ok), kCanonicalEpoch);

    auto bad = parse_cookie_date(std::string("nope"));
    EXPECT_FALSE(bad.has_value());
}

// to_string + parse round-trip through the convenience layer only.
TEST(DateConvenience, ConvenienceRoundTrip) {
    const auto        tp = system_clock::time_point(std::chrono::seconds(kCanonicalEpoch));
    const std::string s  = to_string(tp);
    qb::wall_time     wt = parse(s);
    EXPECT_EQ(epoch_seconds(wt), kCanonicalEpoch);
    EXPECT_EQ(to_string(wt), s);
}

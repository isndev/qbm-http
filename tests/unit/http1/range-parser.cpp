/**
 * @file qbm/http/tests/unit/http1/range-parser.cpp
 * @brief White-box unit tests for qb::http::internal::parse_byte_range.
 *
 * Split out of middleware-static-files.cpp: `parse_byte_range` is a free helper
 * (RFC 7233 single byte-range parsing) independent of the StaticFilesMiddleware,
 * the router, the filesystem, or any session. It returns
 * `{start_offset, length_to_read}` on success and `std::nullopt` for malformed,
 * multi-range, or unsatisfiable input.
 *
 * The end-to-end HTTP-status Range cases (206 / 416 / Content-Range arithmetic)
 * stay in middleware-static-files.cpp; this file pins the parser contract
 * directly, including the boundary and rejection rules the integration cases
 * can only observe indirectly.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <optional>
#include <utility>

#include <qbm/http/http.h>
#include <qbm/http/middleware/static_files.h>

namespace {

using qb::http::internal::parse_byte_range;

// Convenience: assert a parse succeeds with the expected {offset, length}.
void
expect_range(std::string_view header, long long total, long long expected_offset, long long expected_length) {
    const auto r = parse_byte_range(header, total);
    ASSERT_TRUE(r.has_value()) << "expected a valid range for: " << header;
    EXPECT_EQ(r->first, expected_offset) << "offset for: " << header;
    EXPECT_EQ(r->second, expected_length) << "length for: " << header;
}

// --- Valid forms -----------------------------------------------------------

TEST(RangeParserTest, ExplicitStartEnd) {
    // bytes=0-99 over 1000 -> offset 0, length 100 (end is inclusive).
    expect_range("bytes=0-99", 1000, 0, 100);
}

TEST(RangeParserTest, OpenEndedStartServesRemainder) {
    // bytes=500- over 1000 -> from 500 to EOF -> length 500.
    expect_range("bytes=500-", 1000, 500, 500);
}

TEST(RangeParserTest, SuffixLength) {
    // bytes=-200 over 1000 -> last 200 bytes -> offset 800, length 200.
    expect_range("bytes=-200", 1000, 800, 200);
}

TEST(RangeParserTest, SuffixLargerThanFileClampsToWholeRepresentation) {
    // bytes=-2000 over 1000 -> clamped to the whole file -> offset 0, length 1000.
    expect_range("bytes=-2000", 1000, 0, 1000);
}

TEST(RangeParserTest, SingleByteAtStart) {
    expect_range("bytes=0-0", 1000, 0, 1);
}

TEST(RangeParserTest, LastByteExplicit) {
    expect_range("bytes=999-999", 1000, 999, 1);
}

TEST(RangeParserTest, EndBeyondEofClampsToEof) {
    // bytes=995-2000 over 1000 -> clamp end to last byte (999) -> offset 995, length 5.
    expect_range("bytes=995-2000", 1000, 995, 5);
}

TEST(RangeParserTest, WholeFileExplicit) {
    expect_range("bytes=0-999", 1000, 0, 1000);
}

// --- Unsatisfiable (in-range syntax, out-of-bounds semantics) --------------

TEST(RangeParserTest, StartAtOrBeyondEofIsUnsatisfiable) {
    EXPECT_FALSE(parse_byte_range("bytes=1000-1001", 1000).has_value());
    EXPECT_FALSE(parse_byte_range("bytes=5000-", 1000).has_value());
}

TEST(RangeParserTest, StartGreaterThanEndIsRejected) {
    EXPECT_FALSE(parse_byte_range("bytes=10-5", 1000).has_value());
}

TEST(RangeParserTest, ZeroLengthSuffixIsRejected) {
    // bytes=-0 requests zero trailing bytes -> not satisfiable.
    EXPECT_FALSE(parse_byte_range("bytes=-0", 1000).has_value());
}

// --- Malformed / unsupported syntax (must be nullopt) ----------------------

TEST(RangeParserTest, MissingBytesUnitIsRejected) {
    EXPECT_FALSE(parse_byte_range("0-99", 1000).has_value());
    EXPECT_FALSE(parse_byte_range("items=0-99", 1000).has_value());
}

TEST(RangeParserTest, EmptySpecIsRejected) {
    EXPECT_FALSE(parse_byte_range("bytes=", 1000).has_value());
    EXPECT_FALSE(parse_byte_range("bytes=-", 1000).has_value());
}

TEST(RangeParserTest, NonDigitTokensAreRejected) {
    EXPECT_FALSE(parse_byte_range("bytes=abc-def", 1000).has_value());
    EXPECT_FALSE(parse_byte_range("bytes=0-xyz", 1000).has_value());
}

TEST(RangeParserTest, SignedAndWhitespaceTokensAreRejected) {
    // RFC 7233: a byte-range numeric token is solely ASCII digits.
    EXPECT_FALSE(parse_byte_range("bytes=-5-10", 1000).has_value()); // negative start
    EXPECT_FALSE(parse_byte_range("bytes=+5-10", 1000).has_value()); // leading '+'
    EXPECT_FALSE(parse_byte_range("bytes= 5-10", 1000).has_value()); // embedded space
    EXPECT_FALSE(parse_byte_range("bytes=5 -10", 1000).has_value()); // trailing space in start
}

TEST(RangeParserTest, MultiRangeSpecIsRejected) {
    // Only single ranges are served; comma lists must be refused wholesale.
    EXPECT_FALSE(parse_byte_range("bytes=0-5,10-15", 1000).has_value());
    EXPECT_FALSE(parse_byte_range("bytes=0-5, 10-15", 1000).has_value());
}

TEST(RangeParserTest, MissingDashIsRejected) {
    EXPECT_FALSE(parse_byte_range("bytes=100", 1000).has_value());
}

// --- Degenerate totals -----------------------------------------------------

TEST(RangeParserTest, AnyRangeOnEmptyFileIsUnsatisfiable) {
    EXPECT_FALSE(parse_byte_range("bytes=0-0", 0).has_value());
    EXPECT_FALSE(parse_byte_range("bytes=0-", 0).has_value());
    EXPECT_FALSE(parse_byte_range("bytes=-1", 0).has_value());
}

} // namespace

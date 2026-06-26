/**
 * @file test-multipart-security.cpp
 * @brief Security tests for multipart form-data parsing
 *
 * These tests verify the DoS protection mechanisms for multipart parsing:
 * - Boundary length limit (RFC 2046 max 70 characters)
 * - Header attributes size limit (64KB)
 * - Memory safety with RAII std::vector (replaces raw pointer)
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

#include <gtest/gtest.h>
#include <qb/system/allocator/pipe.h>
#include "../body.h"
#include "../headers.h"
#include "../multipart.h"

using namespace qb::http;

// ====================================================================
// Multipart Boundary DoS Protection Tests
// ====================================================================

class MultipartSecurityTest : public ::testing::Test {
protected:
    void
    SetUp() override {}
};

TEST_F(MultipartSecurityTest, ValidBoundaryParsing) {
    // Standard boundary parsing should work
    std::string content_type = "multipart/form-data; boundary=abc123";
    std::string boundary     = parse_boundary(content_type);
    EXPECT_EQ(boundary, "abc123");
}

TEST_F(MultipartSecurityTest, ValidBoundaryWithQuotes) {
    // RFC 2046 allows quoted boundaries
    std::string content_type = "multipart/form-data; boundary=\"boundary-with-dashes\"";
    std::string boundary     = parse_boundary(content_type);
    EXPECT_EQ(boundary, "boundary-with-dashes");
}

TEST_F(MultipartSecurityTest, BoundaryParsingHandlesCaseAndAdditionalParameters) {
    EXPECT_EQ(parse_boundary("Multipart/Form-Data; charset=utf-8; boundary=abc123"), "abc123");
    EXPECT_EQ(parse_boundary("multipart/form-data; boundary=abc123; charset=utf-8"), "abc123");
}

TEST_F(MultipartSecurityTest, BoundaryAtMaxLength) {
    // A boundary of exactly MAX_BOUNDARY_LENGTH is the inclusive upper bound
    // (multipart.cpp is_valid_boundary uses `size() <= MAX_BOUNDARY_LENGTH`),
    // so it parses and is returned verbatim. Pin the deterministic outcome.
    const std::string long_boundary(multipart_limits::MAX_BOUNDARY_LENGTH, 'a');
    const std::string content_type = "multipart/form-data; boundary=" + long_boundary;
    EXPECT_EQ(parse_boundary(content_type), long_boundary);
}

TEST_F(MultipartSecurityTest, BodyParsingAcceptsBoundaryAtMaxLength) {
    const std::string boundary(multipart_limits::MAX_BOUNDARY_LENGTH, 'a');
    const std::string raw = "--" + boundary
                            + "\r\n"
                              "Content-Disposition: form-data; name=\"field\"\r\n"
                              "\r\n"
                              "value\r\n"
                              "--"
                            + boundary + "--";

    Body body;
    body = raw;

    Multipart parsed;
    ASSERT_NO_THROW(parsed = body.as<Multipart>());
    ASSERT_EQ(parsed.parts().size(), 1u);
    EXPECT_EQ(parsed.parts().front().body, "value");
}

TEST_F(MultipartSecurityTest, BoundaryOverMaxLengthIsRejected) {
    // Boundary exceeding 70 characters should be rejected
    std::string oversized_boundary(71, 'b');
    std::string content_type = "multipart/form-data; boundary=" + oversized_boundary;

    // Should throw due to security limit
    EXPECT_THROW({ (void) parse_boundary(content_type); }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, ExcessivePartCountIsRejected) {
    // A body with more than MAX_PARTS_COUNT parts must be rejected so a peer
    // cannot exhaust memory with millions of tiny parts.
    const std::string boundary = "bnd";
    std::string       raw;
    for (std::size_t i = 0; i <= multipart_limits::MAX_PARTS_COUNT; ++i) {
        raw += "--" + boundary
               + "\r\n"
                 "Content-Disposition: form-data; name=\"f\"\r\n"
                 "\r\n"
                 "v\r\n";
    }
    raw += "--" + boundary + "--";

    Body body;
    body = raw;
    EXPECT_THROW({ (void) body.as<Multipart>(); }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, ParseSideRejectsControlCharacterInPartHeaderName) {
    // On the parse path a part header field name may only contain RFC token
    // characters; an embedded control byte (here a NUL) trips the parser's
    // "Malformed header name" and Body::as<Multipart>() surfaces it as a throw
    // (the wire complement of the serialize-side injection defenses below).
    const std::string boundary = "bnd";
    std::string       raw       = "--" + boundary + "\r\n";
    raw += "Bad";
    raw.push_back('\0'); // control char inside the header field name
    raw += "Name: form-data; name=\"f\"\r\n\r\nvalue\r\n";
    raw += "--" + boundary + "--";

    Body body;
    body = raw;
    EXPECT_THROW({ (void) body.as<Multipart>(); }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, ParseSideRejectsOversizedPartHeaderValue) {
    // Per-part header value size is capped on the parse path at
    // multipart_limits::MAX_HEADER_VALUE_LENGTH (body.cpp:196); a single part
    // whose header value exceeds it is rejected before accumulating unbounded.
    const std::string boundary  = "bnd";
    const std::string huge_value(multipart_limits::MAX_HEADER_VALUE_LENGTH + 1, 'V');
    std::string       raw = "--" + boundary
                            + "\r\n"
                              "X-Big: "
                            + huge_value
                            + "\r\n"
                              "\r\n"
                              "value\r\n";
    raw += "--" + boundary + "--";

    Body body;
    body = raw;
    EXPECT_THROW({ (void) body.as<Multipart>(); }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, BoundaryWithControlCharactersIsRejected) {
    EXPECT_THROW({ (void) parse_boundary("multipart/form-data; boundary=\"safe\r\nInjected\""); }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, BoundaryWithTrailingSpaceIsRejected) {
    EXPECT_THROW({ (void) parse_boundary("multipart/form-data; boundary=\"abc \""); }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, BoundaryMuchOverMaxLength) {
    // Very large boundary (potential DoS attack)
    std::string huge_boundary(10000, 'x');
    std::string content_type = "multipart/form-data; boundary=" + huge_boundary;

    // Should throw immediately without allocating huge memory
    EXPECT_THROW({ (void) parse_boundary(content_type); }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, EmptyBoundary) {
    // Empty boundary should return empty string
    std::string content_type = "multipart/form-data; boundary=";
    std::string boundary     = parse_boundary(content_type);
    EXPECT_TRUE(boundary.empty());
}

TEST_F(MultipartSecurityTest, NoBoundaryParameter) {
    // Missing boundary parameter
    std::string content_type = "multipart/form-data";
    std::string boundary     = parse_boundary(content_type);
    EXPECT_TRUE(boundary.empty());
}

TEST_F(MultipartSecurityTest, NonMultipartContentType) {
    // Non-multipart content type
    std::string content_type = "application/json";
    std::string boundary     = parse_boundary(content_type);
    EXPECT_TRUE(boundary.empty());
}

TEST_F(MultipartSecurityTest, WhitespaceInContentType) {
    // Various whitespace patterns
    {
        std::string ct1 = "multipart/form-data;boundary=test";
        EXPECT_EQ(parse_boundary(ct1), "test");
    }
    {
        std::string ct2 = "multipart/form-data; boundary=test";
        EXPECT_EQ(parse_boundary(ct2), "test");
    }
    {
        std::string ct3 = "multipart/form-data;  boundary=test";
        EXPECT_EQ(parse_boundary(ct3), "test");
    }
}

// ====================================================================
// Header Attributes DoS Protection Tests
// ====================================================================

TEST_F(MultipartSecurityTest, ValidHeaderAttributesParsing) {
    // Normal header attributes parsing
    std::string attrs  = "name=\"file\"; filename=\"document.pdf\"";
    auto        result = parse_header_attributes(attrs.data(), attrs.size());

    EXPECT_TRUE(result.find("name") != result.end());
    EXPECT_EQ(result["name"], "file");
    EXPECT_TRUE(result.find("filename") != result.end());
    EXPECT_EQ(result["filename"], "document.pdf");
}

TEST_F(MultipartSecurityTest, HeaderAttributeValueAtLimitSucceeds) {
    // The per-value cap is ATTRIBUTE_VALUE_MAX (8192). A value of exactly
    // ATTRIBUTE_VALUE_MAX - 1 bytes is the largest accepted (the check rejects on
    // reaching the cap), so this is deterministic success — not accept-either.
    const std::string at_limit_value(ATTRIBUTE_VALUE_MAX - 1, 'x');
    const std::string attrs  = "data=" + at_limit_value;
    auto              result = parse_header_attributes(attrs.data(), attrs.size());
    ASSERT_TRUE(result.find("data") != result.end());
    EXPECT_EQ(result["data"].size(), static_cast<std::size_t>(ATTRIBUTE_VALUE_MAX - 1));
    EXPECT_EQ(result["data"], at_limit_value);
}

TEST_F(MultipartSecurityTest, HeaderAttributeValueExactlyAtLimitIsAccepted) {
    // Ground truth (headers.cpp:199): the guard is `size() >= ATTRIBUTE_VALUE_MAX`
    // checked BEFORE pushing, so the longest accepted value is exactly
    // ATTRIBUTE_VALUE_MAX bytes. A value of exactly ATTRIBUTE_VALUE_MAX is
    // therefore ACCEPTED verbatim, not rejected — the constant is the max stored
    // length, and rejection only triggers when a further char would exceed it.
    const std::string at_max_value(ATTRIBUTE_VALUE_MAX, 'x');
    const std::string attrs  = "data=" + at_max_value;
    auto              result = parse_header_attributes(attrs.data(), attrs.size());
    ASSERT_TRUE(result.find("data") != result.end());
    EXPECT_EQ(result["data"].size(), static_cast<std::size_t>(ATTRIBUTE_VALUE_MAX));
    EXPECT_EQ(result["data"], at_max_value);
}

TEST_F(MultipartSecurityTest, HeaderAttributeValueOverLimitIsRejected) {
    // The FIRST rejected length is ATTRIBUTE_VALUE_MAX + 1: on the (MAX+1)-th value
    // char the guard `size() >= ATTRIBUTE_VALUE_MAX` (headers.cpp:199) trips and
    // throws, even though the whole input stays well under the 64KB total cap.
    const std::string over_value(ATTRIBUTE_VALUE_MAX + 1, 'x');
    const std::string attrs = "data=" + over_value;
    EXPECT_THROW({ (void) parse_header_attributes(attrs.data(), attrs.size()); }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, HeaderAttributesTotalInputOverLimitIsRejected) {
    // The whole-input guard (len > 64KB) trips before any per-value parsing,
    // so a >64KB blob is rejected even split across many small attributes.
    constexpr std::size_t over_total = 64u * 1024u + 1u;
    const std::string     attrs(over_total, 'y');
    EXPECT_THROW({ (void) parse_header_attributes(attrs.data(), attrs.size()); }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, EmptyHeaderAttributes) {
    // Empty attributes should return empty map
    std::string attrs  = "";
    auto        result = parse_header_attributes(attrs.data(), attrs.size());
    EXPECT_TRUE(result.empty());
}

TEST_F(MultipartSecurityTest, HeaderAttributesWithQuotes) {
    // Quoted values
    std::string attrs  = "name=\"file name with spaces\"; type=\"application/pdf\"";
    auto        result = parse_header_attributes(attrs.data(), attrs.size());

    EXPECT_TRUE(result.find("name") != result.end());
    EXPECT_TRUE(result.find("type") != result.end());
}

TEST_F(MultipartSecurityTest, HeaderAttributesFlagStyle) {
    // Flag-style attributes (no '=') must be present AND map to an empty value,
    // matching the documented behavior (not merely "key exists").
    std::string attrs  = "required; secure; httponly";
    auto        result = parse_header_attributes(attrs.data(), attrs.size());

    ASSERT_TRUE(result.find("required") != result.end());
    ASSERT_TRUE(result.find("secure") != result.end());
    ASSERT_TRUE(result.find("httponly") != result.end());
    EXPECT_EQ(result["required"], "");
    EXPECT_EQ(result["secure"], "");
    EXPECT_EQ(result["httponly"], "");
}

// ====================================================================
// Multipart Limits Constants Tests
// ====================================================================

TEST_F(MultipartSecurityTest, BoundaryMaxLengthIs70) {
    // Verify RFC 2046 boundary limit constant
    EXPECT_EQ(multipart_limits::MAX_BOUNDARY_LENGTH, 70);
}

// ====================================================================
// Edge Cases
// ====================================================================

TEST_F(MultipartSecurityTest, MalformedContentTypes) {
    // Malformed content types should not crash
    {
        std::string ct1 = "";
        EXPECT_NO_THROW((void) parse_boundary(ct1));
    }
    {
        std::string ct2 = "boundary=test";
        EXPECT_NO_THROW((void) parse_boundary(ct2));
    }
    {
        std::string ct3 = "multipart/form-data; boundary=";
        EXPECT_NO_THROW((void) parse_boundary(ct3));
    }
    {
        std::string ct4 = "multipart/form-data boundary=test"; // Missing semicolon
        EXPECT_NO_THROW((void) parse_boundary(ct4));
    }
}

TEST_F(MultipartSecurityTest, SpecialCharactersInBoundary) {
    // Boundaries with special characters
    std::vector<std::string> test_boundaries = {"boundary-123", "boundary_123", "boundary.123", "boundary:123", "boundary=123"};

    for (const auto &b : test_boundaries) {
        std::string ct = "multipart/form-data; boundary=" + b;
        EXPECT_NO_THROW({ (void) parse_boundary(ct); });
    }
}

TEST_F(MultipartSecurityTest, SerializationRejectsPartHeaderNameInjection) {
    Multipart mp;
    auto     &part = mp.create_part();
    part.set_header("Content-Disposition\r\nInjected", "form-data; name=\"field\"");
    part.body = "payload";

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out.put(mp), std::length_error);
    EXPECT_TRUE(out.empty());
}

TEST_F(MultipartSecurityTest, SerializationRejectsPartHeaderValueInjection) {
    Multipart mp;
    auto     &part = mp.create_part();
    part.set_header("Content-Disposition", "form-data; name=\"field\"\r\nInjected: bad");
    part.body = "payload";

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out.put(mp), std::length_error);
    EXPECT_TRUE(out.empty());
}

TEST_F(MultipartSecurityTest, SerializationRejectsOversizedPartHeaderValue) {
    Multipart mp;
    auto     &part = mp.create_part();
    part.set_header("X-Large", std::string(multipart_limits::MAX_HEADER_VALUE_LENGTH + 1, 'x'));
    part.body = "payload";

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out.put(mp), std::length_error);
    EXPECT_TRUE(out.empty());
}

TEST_F(MultipartSecurityTest, SerializationRejectsBoundaryInjection) {
    Multipart mp("safe\r\nInjected: bad");
    auto     &part = mp.create_part();
    part.set_header("Content-Disposition", "form-data; name=\"field\"");
    part.body = "payload";

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out.put(mp), std::length_error);
    EXPECT_TRUE(out.empty());
}

// ====================================================================
// MultipartParser::setBoundary — direct error-path coverage.
//
// parse_boundary() guards the *header* form, but the low-level parser has its
// own setBoundary() guards (multipart.cpp:245-256) reached when a parser is
// driven directly (e.g. by a streaming consumer). These pin the two rejection
// reasons and the resulting ERROR state, plus the accept path.
// ====================================================================

TEST_F(MultipartSecurityTest, ParserSetBoundaryRejectsEmpty) {
    MultipartParser parser;
    parser.setBoundary("");
    EXPECT_TRUE(parser.hasError());
    EXPECT_STREQ(parser.getErrorMessage(), "Boundary exceeds maximum allowed length");
}

TEST_F(MultipartSecurityTest, ParserSetBoundaryRejectsOverLength) {
    MultipartParser parser;
    parser.setBoundary(std::string(multipart_limits::MAX_BOUNDARY_LENGTH + 1, 'a'));
    EXPECT_TRUE(parser.hasError());
    EXPECT_STREQ(parser.getErrorMessage(), "Boundary exceeds maximum allowed length");
    // feed() on an errored parser is a no-op returning 0 (multipart.cpp:273).
    const char buf[] = "anything";
    EXPECT_EQ(parser.feed(buf, sizeof(buf) - 1), 0u);
}

TEST_F(MultipartSecurityTest, ParserSetBoundaryRejectsControlCharacter) {
    MultipartParser parser;
    parser.setBoundary(std::string("ab\x01" "cd")); // 0x01 < 0x20 control byte
    EXPECT_TRUE(parser.hasError());
    EXPECT_STREQ(parser.getErrorMessage(), "Boundary contains invalid control character");
}

TEST_F(MultipartSecurityTest, ParserSetBoundaryRejectsDelByte) {
    MultipartParser parser;
    parser.setBoundary(std::string("ab\x7f""cd")); // DEL (0x7f) is rejected too
    EXPECT_TRUE(parser.hasError());
    EXPECT_STREQ(parser.getErrorMessage(), "Boundary contains invalid control character");
}

TEST_F(MultipartSecurityTest, ParserSetBoundaryAcceptsValid) {
    MultipartParser parser;
    parser.setBoundary("validBoundary123");
    EXPECT_FALSE(parser.hasError());
    EXPECT_FALSE(parser.stopped());
    EXPECT_STREQ(parser.getErrorMessage(), "No error.");
}

// ====================================================================
// find_boundary — the free helper (multipart.cpp:42).
// ====================================================================

TEST_F(MultipartSecurityTest, FindBoundaryLocatesAndMisses) {
    const std::string boundary = "--XYZ";

    // Present: iterator points at the first byte of the match.
    {
        const std::string hay = "prefix--XYZsuffix";
        auto              it  = find_boundary(hay, boundary);
        ASSERT_NE(it, hay.end());
        EXPECT_EQ(std::string(it, it + boundary.size()), boundary);
        EXPECT_EQ(static_cast<std::size_t>(it - hay.begin()), hay.find(boundary));
    }
    // Absent: returns end().
    {
        const std::string hay = "no marker present here";
        EXPECT_EQ(find_boundary(hay, boundary), hay.end());
    }
    // A near-miss prefix that does not complete still misses (drives the
    // std::mismatch advance loop, multipart.cpp:44-49).
    {
        const std::string hay = "--XY--XY"; // boundary "--XYZ" never completes
        EXPECT_EQ(find_boundary(hay, boundary), hay.end());
    }
}

// ====================================================================
// Boyer-Moore non-boundary skip + reassembly across a parser feed.
//
// A part body packed with bytes that are NOT in the boundary alphabet forces
// the inner `i += boundarySize` skip loop (multipart.cpp:129-135) — the fast
// path the small body-codec fixtures never stress — while still reassembling
// the exact payload. Driving the parser directly (not via Body) lets us assert
// succeeded() and the captured payload through a raw callback.
// ====================================================================

namespace {
struct CaptureCtx {
    std::string data;
    bool        ended = false;
};
void
capture_part_data(const char *buf, size_t start, size_t end, void *user) {
    auto *ctx = static_cast<CaptureCtx *>(user);
    if (start != static_cast<size_t>(-1) && end >= start) {
        ctx->data.append(buf + start, end - start);
    }
}
void
capture_end(const char *, size_t, size_t, void *user) {
    static_cast<CaptureCtx *>(user)->ended = true;
}
} // namespace

TEST_F(MultipartSecurityTest, ParserFeedReassemblesBodyThroughBoyerMooreSkip) {
    const std::string boundary = "bnd";
    // Payload contains only digits/letters absent from "\r\n--bnd", so the
    // Boyer-Moore skip advances boundarySize at a time across the body.
    const std::string payload(64, '7');
    const std::string raw = "--" + boundary
                            + "\r\n"
                              "Content-Disposition: form-data; name=\"f\"\r\n"
                              "\r\n"
                            + payload + "\r\n--" + boundary + "--";

    MultipartParser parser(boundary);
    ASSERT_FALSE(parser.hasError());

    CaptureCtx ctx;
    parser.userData   = &ctx;
    parser.onPartData = &capture_part_data;
    parser.onEnd      = &capture_end;

    const size_t consumed = parser.feed(raw.data(), raw.size());
    EXPECT_EQ(consumed, raw.size());
    EXPECT_TRUE(parser.succeeded());
    EXPECT_TRUE(ctx.ended);
    EXPECT_EQ(ctx.data, payload);
}

TEST_F(MultipartSecurityTest, ParserFeedReportsMalformedFirstBoundary) {
    // A buffer that does not begin with the expected boundary trips
    // START_BOUNDARY's "different boundary data" guard (multipart.cpp:312) and
    // stops the parser with an error before any part is emitted.
    MultipartParser parser("bnd");
    ASSERT_FALSE(parser.hasError());

    const std::string raw = "--XXX\r\n\r\nbody\r\n--bnd--";
    const size_t      consumed = parser.feed(raw.data(), raw.size());
    EXPECT_LT(consumed, raw.size());
    EXPECT_TRUE(parser.hasError());
    EXPECT_FALSE(parser.succeeded());
}

TEST_F(MultipartSecurityTest, SerializationRejectsInvalidBoundaryLength) {
    Multipart mp(std::string(multipart_limits::MAX_BOUNDARY_LENGTH + 1, 'x'));
    auto     &part = mp.create_part();
    part.set_header("Content-Disposition", "form-data; name=\"field\"");
    part.body = "payload";

    qb::allocator::pipe<char> out;
    EXPECT_THROW(out.put(mp), std::length_error);
    EXPECT_TRUE(out.empty());
}

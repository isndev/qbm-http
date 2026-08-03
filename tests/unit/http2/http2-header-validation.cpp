/**
 * @file qbm/http/tests/unit/http2/http2-header-validation.cpp
 * @brief Unit tests for the HTTP/2 header / settings validators and strict
 *        field-value parsers.
 *
 * Pure-logic half split out of the legacy test-http2-header-validator.cpp (spec
 * §3 D7): every test is a direct call into a static helper of
 * qb::protocol::http2::HeaderValidator / SettingsHelper / detail — no socket, no
 * event loop, no protocol instance. The framer / state-machine half lives in
 * http2-protocol-state.cpp.
 *
 * Covers: request/response/trailer pseudo-header validation, forbidden
 * connection-specific headers, the TE-trailers special case, ENABLE_CONNECT_PROTOCOL
 * boolean validation, header field-name/value format rules (lowercase, control
 * bytes, CRLF, embedded NUL), and the strict :status / content-length parsers
 * (RFC 9113 §8.1.1 / §8.1.2).
 *
 * Pure logic, deterministic, parallel-safe (tier:unit; un-gated from SSL).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include <qbm/http/2/protocol/base.h>
#include <qbm/http/2/protocol/client.h> // detail::parse_status_code lives here

namespace h2 = qb::protocol::http2;

// ===========================================================================
// Request / response / trailer pseudo-header validation.
// ===========================================================================
TEST(HTTP2HeaderValidator, RejectsUnknownRequestPseudoHeaders) {
    std::vector<qb::protocol::hpack::HeaderField> headers{
        {":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/"}, {":protocol", "websocket"}
    };

    const auto result = h2::HeaderValidator::validate_request_pseudo_headers(headers);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2HeaderValidator, RequiresAuthorityPseudoHeaderInRequests) {
    std::vector<qb::protocol::hpack::HeaderField> headers{{":method", "GET"}, {":scheme", "https"}, {":path", "/"}};

    const auto result = h2::HeaderValidator::validate_request_pseudo_headers(headers);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2HeaderValidator, AcceptsCompleteRequestPseudoHeaderSet) {
    std::vector<qb::protocol::hpack::HeaderField> headers{
        {":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/"}
    };

    const auto result = h2::HeaderValidator::validate_request_pseudo_headers(headers);
    EXPECT_TRUE(result.is_valid);
}

TEST(HTTP2HeaderValidator, RejectsConnectionSpecificRequestHeaders) {
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_header("connection"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_header("host"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_header("transfer-encoding"));
}

TEST(HTTP2HeaderValidator, AllowsTeToBeValidatedByValue) {
    EXPECT_FALSE(h2::HeaderValidator::is_forbidden_header("te"));
}

TEST(HTTP2HeaderValidator, ForbidsTeInResponses) {
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_response_header("te"));
}

TEST(HTTP2HeaderValidator, ForbidsTeAndTrailerInTrailers) {
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_trailer_header("te"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_trailer_header("trailer"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_trailer_header("content-length"));
}

TEST(HTTP2HeaderValidator, TeRequestValueValidationAcceptsTrailersWithOws) {
    EXPECT_TRUE(h2::HeaderValidator::is_valid_request_te_value("trailers"));
    EXPECT_TRUE(h2::HeaderValidator::is_valid_request_te_value(" trailers "));
    EXPECT_TRUE(h2::HeaderValidator::is_valid_request_te_value("trailers, trailers"));
}

TEST(HTTP2HeaderValidator, TeRequestValueValidationRejectsOtherTokens) {
    EXPECT_FALSE(h2::HeaderValidator::is_valid_request_te_value(""));
    EXPECT_FALSE(h2::HeaderValidator::is_valid_request_te_value("gzip"));
    EXPECT_FALSE(h2::HeaderValidator::is_valid_request_te_value("trailers, gzip"));
}

TEST(HTTP2HeaderValidator, AllowsContentLengthInResponseHeaders) {
    EXPECT_FALSE(h2::HeaderValidator::is_forbidden_response_header("content-length"));
}

TEST(HTTP2HeaderValidator, RejectsUnknownResponsePseudoHeaders) {
    std::vector<qb::protocol::hpack::HeaderField> headers{{":status", "200"}, {":path", "/illegal-in-response"}};

    const auto result = h2::HeaderValidator::validate_response_pseudo_headers(headers);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2HeaderValidator, RequiresStatusPseudoHeaderInResponse) {
    std::vector<qb::protocol::hpack::HeaderField> headers{{"content-type", "text/plain"}};

    const auto result = h2::HeaderValidator::validate_response_pseudo_headers(headers);
    EXPECT_FALSE(result.is_valid);
    EXPECT_EQ(result.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2HeaderValidator, AcceptsStatusOnlyResponsePseudoHeaderSet) {
    std::vector<qb::protocol::hpack::HeaderField> headers{{":status", "204"}};

    const auto result = h2::HeaderValidator::validate_response_pseudo_headers(headers);
    EXPECT_TRUE(result.is_valid);
}

// ===========================================================================
// SETTINGS value validation.
// ===========================================================================
TEST(HTTP2SettingsValidator, EnableConnectProtocolIsBoolean) {
    using h2::Http2SettingIdentifier;
    using h2::SettingsHelper;

    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL, 0, true).is_valid);
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL, 1, true).is_valid);

    const auto invalid = SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL, 2, true);
    EXPECT_FALSE(invalid.is_valid);
    EXPECT_EQ(invalid.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2SettingsValidator, EnablePushIsBoolean) {
    using h2::Http2SettingIdentifier;
    using h2::SettingsHelper;

    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 0, true).is_valid);
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 1, true).is_valid);

    const auto invalid = SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 2, true);
    EXPECT_FALSE(invalid.is_valid);
    EXPECT_EQ(invalid.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2SettingsValidator, InitialWindowSizeOverMaxIsFlowControlError) {
    using h2::Http2SettingIdentifier;
    using h2::SettingsHelper;

    // 2^31 (one past the 2^31-1 maximum) must be rejected as FLOW_CONTROL_ERROR.
    const auto invalid = SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 0x80000000u, true);
    EXPECT_FALSE(invalid.is_valid);
    EXPECT_EQ(invalid.error_code, h2::ErrorCode::FLOW_CONTROL_ERROR);

    // 2^31-1 (the maximum) is accepted.
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 0x7FFFFFFFu, true).is_valid);
}

TEST(HTTP2SettingsValidator, MaxFrameSizeOutOfRangeIsProtocolError) {
    using h2::Http2SettingIdentifier;
    using h2::SettingsHelper;

    // Below the 2^14 floor.
    const auto too_small = SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 16383, true);
    EXPECT_FALSE(too_small.is_valid);
    EXPECT_EQ(too_small.error_code, h2::ErrorCode::PROTOCOL_ERROR);

    // Above the 2^24-1 ceiling.
    const auto too_big = SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 16777216, true);
    EXPECT_FALSE(too_big.is_valid);
    EXPECT_EQ(too_big.error_code, h2::ErrorCode::PROTOCOL_ERROR);

    // Both endpoints of the legal range are accepted.
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 16384, true).is_valid);
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 16777215, true).is_valid);
}

// ===========================================================================
// Header field name / value format rules.
// ===========================================================================
TEST(HTTP2HeaderValidator, ValidHeaderFieldFormatAcceptsLowercaseToken) {
    EXPECT_TRUE(h2::HeaderValidator::is_valid_header_field("content-type", "text/plain"));
}

TEST(HTTP2HeaderValidator, HeaderValueFormatRejectsControlBytes) {
    EXPECT_TRUE(h2::HeaderValidator::is_valid_header_value("/safe/path"));
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_value("/bad\rpath"));
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_value("/bad\npath"));
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_value(std::string_view{"bad\0path", 8}));
}

TEST(HTTP2HeaderValidator, RejectsUppercaseHeaderName) {
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("Content-Type", "text/plain"));
}

TEST(HTTP2HeaderValidator, RejectsHeaderValueWithCRLF) {
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("x-test", "line1\r\nline2"));
}

TEST(HTTP2HeaderValidator, RejectsEmptyHeaderName) {
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("", "value"));
}

// ===========================================================================
// Strict :status parsing (RFC 9113 §8.3.2 — exactly three ASCII digits).
// ===========================================================================
TEST(HTTP2HeaderValidator, StrictStatusParsingAcceptsValidThreeDigits) {
    const auto parsed = h2::detail::parse_status_code("200");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, 200);
}

TEST(HTTP2HeaderValidator, StrictStatusParsingAcceptsBoundaryCodes) {
    auto p100 = h2::detail::parse_status_code("100");
    ASSERT_TRUE(p100.has_value());
    EXPECT_EQ(*p100, 100);

    auto p599 = h2::detail::parse_status_code("599");
    ASSERT_TRUE(p599.has_value());
    EXPECT_EQ(*p599, 599);
}

TEST(HTTP2HeaderValidator, StrictStatusParsingRejectsNonThreeDigitsOrDecoratedForms) {
    EXPECT_FALSE(h2::detail::parse_status_code("99").has_value());
    EXPECT_FALSE(h2::detail::parse_status_code("1000").has_value());
    EXPECT_FALSE(h2::detail::parse_status_code("+200").has_value());
    EXPECT_FALSE(h2::detail::parse_status_code("200 ").has_value());
    EXPECT_FALSE(h2::detail::parse_status_code("2O0").has_value());
    EXPECT_FALSE(h2::detail::parse_status_code("").has_value());
}

// ===========================================================================
// Strict content-length parsing (digits + OWS, no sign, no overflow).
// ===========================================================================
TEST(HTTP2HeaderValidator, StrictContentLengthParsingAcceptsDigitsWithOws) {
    const auto parsed = h2::HeaderValidator::parse_content_length(" 00123\t");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, 123u);
}

TEST(HTTP2HeaderValidator, StrictContentLengthParsingAcceptsZero) {
    const auto parsed = h2::HeaderValidator::parse_content_length("0");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, 0u);
}

TEST(HTTP2HeaderValidator, StrictContentLengthParsingAcceptsUint64Max) {
    const auto parsed = h2::HeaderValidator::parse_content_length("18446744073709551615");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, 18446744073709551615ull);
}

TEST(HTTP2HeaderValidator, StrictContentLengthParsingRejectsInvalidForms) {
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("").has_value());
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("-1").has_value());
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("+1").has_value());
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("1.0").has_value());
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("1, 1").has_value());
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("18446744073709551616").has_value()); // 2^64
}

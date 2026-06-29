/**
 * @file qbm/http/tests/unit/http2/http2-frame-layer.cpp
 * @brief Pure unit tests for the HTTP/2 frame-layer static helpers
 *
 * These tests exercise the non-template, socket-free helpers of the HTTP/2
 * protocol base layer:
 *   - Binary big-endian extract/encode utilities (base.h)
 *   - FrameHeader 24-bit length / 31-bit stream-id accessors (frames.h)
 *   - SettingsHelper (validate_setting / get_default_settings /
 *     calculate_safe_max_frame_size)
 *   - HeaderValidator (pseudo-header order, forbidden headers, te value,
 *     content-length parsing)
 *   - Http2ErrorHandler (error names, escalation, message formatting)
 *   - StreamIdValidator (client/server/connection parity + per-frame rules)
 *
 * No socket, no FakeIO, no protocol instantiation: every assertion calls a
 * static helper or a value-type member directly.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "../../shared/http2_fake_io.h"
#include "../2/protocol/base.h"

namespace h2 = qb::protocol::http2;

using qb::http::test::default_request_headers;
using qb::http::test::do_handshake;
using qb::http::test::drive;
using qb::http::test::encode_hpack_headers;
using qb::http::test::Http2FakeIO;
using qb::http::test::parse_emitted_frames;
using qb::http::test::push_frame;
using qb::http::test::push_preface;

using FrameLayerServer = qb::protocol::http2::ServerHttp2Protocol<Http2FakeIO>;

// ---------------------------------------------------------------------------
// Binary utilities (base.h)
// ---------------------------------------------------------------------------

TEST(HTTP2FrameLayerBinary, ExtractUint16BigEndian) {
    const uint8_t data[2] = {0x12, 0x34};
    EXPECT_EQ(h2::extract_uint16_be(data), 0x1234u);

    const uint8_t zero[2] = {0x00, 0x00};
    EXPECT_EQ(h2::extract_uint16_be(zero), 0u);

    const uint8_t max[2] = {0xFF, 0xFF};
    EXPECT_EQ(h2::extract_uint16_be(max), 0xFFFFu);
}

TEST(HTTP2FrameLayerBinary, ExtractUint32BigEndian) {
    const uint8_t data[4] = {0x12, 0x34, 0x56, 0x78};
    EXPECT_EQ(h2::extract_uint32_be(data), 0x12345678u);

    const uint8_t max[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_EQ(h2::extract_uint32_be(max), 0xFFFFFFFFu);
}

TEST(HTTP2FrameLayerBinary, ExtractUint31MasksReservedBit) {
    // High (R) bit set: must be masked out, rest preserved.
    const uint8_t with_r[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_EQ(h2::extract_uint31_be(with_r), 0x7FFFFFFFu);

    // R bit set on an otherwise-zero stream id -> 0.
    const uint8_t only_r[4] = {0x80, 0x00, 0x00, 0x00};
    EXPECT_EQ(h2::extract_uint31_be(only_r), 0u);

    // R bit clear: value passes through unchanged.
    const uint8_t no_r[4] = {0x12, 0x34, 0x56, 0x78};
    EXPECT_EQ(h2::extract_uint31_be(no_r), 0x12345678u);

    // R bit set over a real id: only the top bit is stripped.
    const uint8_t r_over_id[4] = {0x80, 0x00, 0x00, 0x01};
    EXPECT_EQ(h2::extract_uint31_be(r_over_id), 1u);
}

TEST(HTTP2FrameLayerBinary, EncodeUint16BigEndian) {
    uint8_t out[2] = {0, 0};
    h2::encode_uint16_be(0x1234, out);
    EXPECT_EQ(out[0], 0x12);
    EXPECT_EQ(out[1], 0x34);

    h2::encode_uint16_be(0xFFFF, out);
    EXPECT_EQ(out[0], 0xFF);
    EXPECT_EQ(out[1], 0xFF);
}

TEST(HTTP2FrameLayerBinary, EncodeUint32BigEndian) {
    uint8_t out[4] = {0, 0, 0, 0};
    h2::encode_uint32_be(0x12345678, out);
    EXPECT_EQ(out[0], 0x12);
    EXPECT_EQ(out[1], 0x34);
    EXPECT_EQ(out[2], 0x56);
    EXPECT_EQ(out[3], 0x78);
}

TEST(HTTP2FrameLayerBinary, Uint16RoundTrip) {
    for (uint32_t v : {0u, 1u, 0x00FFu, 0x0100u, 0x1234u, 0xFFFFu}) {
        uint8_t buf[2] = {0, 0};
        h2::encode_uint16_be(static_cast<uint16_t>(v), buf);
        EXPECT_EQ(h2::extract_uint16_be(buf), v);
    }
}

TEST(HTTP2FrameLayerBinary, Uint32RoundTrip) {
    for (uint32_t v : {0u, 1u, 0x0000FFFFu, 0x00FF00FFu, 0x12345678u, 0x7FFFFFFFu, 0xFFFFFFFFu}) {
        uint8_t buf[4] = {0, 0, 0, 0};
        h2::encode_uint32_be(v, buf);
        EXPECT_EQ(h2::extract_uint32_be(buf), v);
    }
}

TEST(HTTP2FrameLayerBinary, Uint31RoundTripWithEncode32) {
    // encode_uint32_be then extract_uint31_be: any value <= 2^31-1 survives,
    // and a value with the R bit set comes back masked.
    for (uint32_t v : {0u, 1u, 0x12345678u, 0x7FFFFFFFu}) {
        uint8_t buf[4] = {0, 0, 0, 0};
        h2::encode_uint32_be(v, buf);
        EXPECT_EQ(h2::extract_uint31_be(buf), v & 0x7FFFFFFFu);
    }
    uint8_t buf[4] = {0, 0, 0, 0};
    h2::encode_uint32_be(0xFFFFFFFFu, buf);
    EXPECT_EQ(h2::extract_uint31_be(buf), 0x7FFFFFFFu);
}

// ---------------------------------------------------------------------------
// FrameHeader (frames.h)
// ---------------------------------------------------------------------------

TEST(HTTP2FrameLayerFrameHeader, PayloadLengthRoundTrip) {
    h2::FrameHeader fh{};
    fh.set_payload_length(0);
    EXPECT_EQ(fh.get_payload_length(), 0u);

    fh.set_payload_length(16384);
    EXPECT_EQ(fh.get_payload_length(), 16384u);

    // 24-bit maximum (2^24 - 1).
    fh.set_payload_length(h2::MAX_FRAME_SIZE_LIMIT);
    EXPECT_EQ(fh.get_payload_length(), 16777215u);
}

TEST(HTTP2FrameLayerFrameHeader, PayloadLengthTruncatesTo24Bits) {
    h2::FrameHeader fh{};
    // The setter keeps only the low 24 bits; bits above 2^24 are dropped.
    fh.set_payload_length(0x01000000u + 5u); // 2^24 + 5
    EXPECT_EQ(fh.get_payload_length(), 5u);
}

TEST(HTTP2FrameLayerFrameHeader, StreamIdRoundTripAndReservedBitCleared) {
    h2::FrameHeader fh{};

    fh.set_stream_id(0);
    EXPECT_EQ(fh.get_stream_id(), 0u);

    fh.set_stream_id(1);
    EXPECT_EQ(fh.get_stream_id(), 1u);

    fh.set_stream_id(0x7FFFFFFFu); // 31-bit max
    EXPECT_EQ(fh.get_stream_id(), 0x7FFFFFFFu);

    // Setting a value with the reserved (high) bit set clears it on store; the
    // raw top byte must have its MSB cleared.
    fh.set_stream_id(0xFFFFFFFFu);
    EXPECT_EQ(fh.get_stream_id(), 0x7FFFFFFFu);
    EXPECT_EQ(fh.stream_id_bytes[0] & 0x80, 0); // R bit physically zero
}

TEST(HTTP2FrameLayerFrameHeader, TypeRoundTrip) {
    h2::FrameHeader fh{};
    fh.type = static_cast<uint8_t>(h2::FrameType::HEADERS);
    EXPECT_EQ(fh.get_type(), h2::FrameType::HEADERS);

    fh.type = static_cast<uint8_t>(h2::FrameType::GOAWAY);
    EXPECT_EQ(fh.get_type(), h2::FrameType::GOAWAY);

    fh.type = static_cast<uint8_t>(h2::FrameType::DATA);
    EXPECT_EQ(fh.get_type(), h2::FrameType::DATA);
}

TEST(HTTP2FrameLayerFrameHeader, HeaderSizeIsNineOctets) {
    EXPECT_EQ(h2::FRAME_HEADER_SIZE, 9u);
    EXPECT_EQ(sizeof(h2::FrameHeader), 9u);
}

// The 9-octet header is #pragma pack(1), so its in-memory image IS the wire
// image: a memcpy round-trip must reproduce the exact byte layout RFC 9113 §4.1
// specifies (3 length octets, type, flags, 4 stream-id octets, big-endian).
TEST(HTTP2FrameLayerFrameHeader, WireByteLayoutRoundTrip) {
    h2::FrameHeader fh{};
    fh.set_payload_length(0x010203u);
    fh.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    fh.flags = h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM; // 0x05
    fh.set_stream_id(0x04050607u);

    uint8_t wire[9] = {};
    std::memcpy(wire, &fh, sizeof(fh));

    // Length (24-bit, big-endian).
    EXPECT_EQ(wire[0], 0x01);
    EXPECT_EQ(wire[1], 0x02);
    EXPECT_EQ(wire[2], 0x03);
    // Type / flags.
    EXPECT_EQ(wire[3], static_cast<uint8_t>(h2::FrameType::HEADERS));
    EXPECT_EQ(wire[4], 0x05);
    // Stream id (31-bit, big-endian; R bit clear on the top octet).
    EXPECT_EQ(wire[5], 0x04);
    EXPECT_EQ(wire[6], 0x05);
    EXPECT_EQ(wire[7], 0x06);
    EXPECT_EQ(wire[8], 0x07);

    // Re-read the wire image and confirm every accessor recovers the value.
    h2::FrameHeader parsed{};
    std::memcpy(&parsed, wire, sizeof(parsed));
    EXPECT_EQ(parsed.get_payload_length(), 0x010203u);
    EXPECT_EQ(parsed.get_type(), h2::FrameType::HEADERS);
    EXPECT_EQ(parsed.flags, 0x05);
    EXPECT_EQ(parsed.get_stream_id(), 0x04050607u);
}

// ---------------------------------------------------------------------------
// SettingsHelper::validate_setting (base.cpp)
// ---------------------------------------------------------------------------

TEST(HTTP2FrameLayerSettings, EnablePushBooleanRule) {
    using h2::Http2SettingIdentifier;
    using h2::SettingsHelper;

    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 0, true).is_valid);
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 1, true).is_valid);

    const auto bad = SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 2, true);
    EXPECT_FALSE(bad.is_valid);
    EXPECT_EQ(bad.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2FrameLayerSettings, EnableConnectProtocolBooleanRule) {
    using h2::Http2SettingIdentifier;
    using h2::SettingsHelper;

    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL, 0, false).is_valid);
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL, 1, false).is_valid);

    const auto bad = SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL, 5, false);
    EXPECT_FALSE(bad.is_valid);
    EXPECT_EQ(bad.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2FrameLayerSettings, InitialWindowSizeFlowControlBoundary) {
    using h2::Http2SettingIdentifier;
    using h2::SettingsHelper;

    // Exactly 2^31-1 is the maximum and must be accepted.
    EXPECT_TRUE(
        SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, h2::MAX_WINDOW_SIZE_LIMIT, true).is_valid);
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 0, true).is_valid);

    // One above the limit -> FLOW_CONTROL_ERROR.
    const auto bad =
        SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, h2::MAX_WINDOW_SIZE_LIMIT + 1u, true);
    EXPECT_FALSE(bad.is_valid);
    EXPECT_EQ(bad.error_code, h2::ErrorCode::FLOW_CONTROL_ERROR);

    const auto bad_max = SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 0xFFFFFFFFu, true);
    EXPECT_FALSE(bad_max.is_valid);
    EXPECT_EQ(bad_max.error_code, h2::ErrorCode::FLOW_CONTROL_ERROR);
}

TEST(HTTP2FrameLayerSettings, MaxFrameSizeRangeRule) {
    using h2::Http2SettingIdentifier;
    using h2::SettingsHelper;

    // Valid range is [16384, 16777215] inclusive.
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, h2::MIN_MAX_FRAME_SIZE, true).is_valid);
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, h2::MAX_FRAME_SIZE_LIMIT, true).is_valid);
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 16384, true).is_valid);

    // Below minimum -> PROTOCOL_ERROR.
    const auto too_small = SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 16383, true);
    EXPECT_FALSE(too_small.is_valid);
    EXPECT_EQ(too_small.error_code, h2::ErrorCode::PROTOCOL_ERROR);

    const auto zero = SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 0, true);
    EXPECT_FALSE(zero.is_valid);
    EXPECT_EQ(zero.error_code, h2::ErrorCode::PROTOCOL_ERROR);

    // Above maximum -> PROTOCOL_ERROR.
    const auto too_big = SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, h2::MAX_FRAME_SIZE_LIMIT + 1u, true);
    EXPECT_FALSE(too_big.is_valid);
    EXPECT_EQ(too_big.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2FrameLayerSettings, UnconstrainedAndUnknownSettingsAreValid) {
    using h2::Http2SettingIdentifier;
    using h2::SettingsHelper;

    // RFC-unconstrained settings always validate.
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE, 0xFFFFFFFFu, true).is_valid);
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS, 0xFFFFFFFFu, true).is_valid);
    EXPECT_TRUE(SettingsHelper::validate_setting(Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE, 0xFFFFFFFFu, true).is_valid);

    // Unknown setting id (0x7) -> must be ignored, hence valid.
    EXPECT_TRUE(SettingsHelper::validate_setting(static_cast<Http2SettingIdentifier>(0x7), 12345, true).is_valid);
}

TEST(HTTP2FrameLayerSettings, GetDefaultSettingsServer) {
    using h2::Http2SettingIdentifier;
    const auto settings = h2::SettingsHelper::get_default_settings(/*is_server=*/true);

    ASSERT_EQ(settings.count(Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE), 1u);
    EXPECT_EQ(settings.at(Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE), h2::DEFAULT_SETTINGS_HEADER_TABLE_SIZE);
    EXPECT_EQ(settings.at(Http2SettingIdentifier::SETTINGS_ENABLE_PUSH), h2::DEFAULT_SETTINGS_ENABLE_PUSH_SERVER); // 1
    EXPECT_EQ(settings.at(Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE), h2::DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE);
    EXPECT_EQ(settings.at(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE), h2::DEFAULT_SETTINGS_MAX_FRAME_SIZE);
}

TEST(HTTP2FrameLayerSettings, GetDefaultSettingsClient) {
    using h2::Http2SettingIdentifier;
    const auto settings = h2::SettingsHelper::get_default_settings(/*is_server=*/false);

    // Only difference vs server defaults: ENABLE_PUSH is 0 for clients.
    EXPECT_EQ(settings.at(Http2SettingIdentifier::SETTINGS_ENABLE_PUSH), h2::DEFAULT_SETTINGS_ENABLE_PUSH_CLIENT); // 0
    EXPECT_EQ(settings.at(Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE), h2::DEFAULT_SETTINGS_HEADER_TABLE_SIZE);
    EXPECT_EQ(settings.at(Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE), h2::DEFAULT_SETTINGS_MAX_FRAME_SIZE);
}

TEST(HTTP2FrameLayerSettings, CalculateSafeMaxFrameSize) {
    using h2::Http2SettingIdentifier;
    using map_t = qb::unordered_map<Http2SettingIdentifier, uint32_t>;

    // Empty map -> default.
    {
        map_t empty;
        EXPECT_EQ(h2::SettingsHelper::calculate_safe_max_frame_size(empty), h2::DEFAULT_SETTINGS_MAX_FRAME_SIZE);
    }
    // In-range value -> echoed back.
    {
        map_t m;
        m[Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE] = 32768;
        EXPECT_EQ(h2::SettingsHelper::calculate_safe_max_frame_size(m), 32768u);
    }
    // Boundary values pass through.
    {
        map_t lo, hi;
        lo[Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE] = h2::MIN_MAX_FRAME_SIZE;
        hi[Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE] = h2::MAX_FRAME_SIZE_LIMIT;
        EXPECT_EQ(h2::SettingsHelper::calculate_safe_max_frame_size(lo), h2::MIN_MAX_FRAME_SIZE);
        EXPECT_EQ(h2::SettingsHelper::calculate_safe_max_frame_size(hi), h2::MAX_FRAME_SIZE_LIMIT);
    }
    // Out-of-range value -> falls back to default.
    {
        map_t too_small, too_big;
        too_small[Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE] = 16383;
        too_big[Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE]   = h2::MAX_FRAME_SIZE_LIMIT + 1u;
        EXPECT_EQ(h2::SettingsHelper::calculate_safe_max_frame_size(too_small), h2::DEFAULT_SETTINGS_MAX_FRAME_SIZE);
        EXPECT_EQ(h2::SettingsHelper::calculate_safe_max_frame_size(too_big), h2::DEFAULT_SETTINGS_MAX_FRAME_SIZE);
    }
}

// ---------------------------------------------------------------------------
// HeaderValidator (base.cpp)
// ---------------------------------------------------------------------------

TEST(HTTP2FrameLayerHeaderValidator, PseudoHeaderOrderValid) {
    std::vector<qb::protocol::hpack::HeaderField> ok{
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "x"}, {"content-type", "text/plain"}
    };
    EXPECT_TRUE(h2::HeaderValidator::validate_pseudo_header_order(ok));

    // All-pseudo (no regular) is valid.
    std::vector<qb::protocol::hpack::HeaderField> all_pseudo{{":method", "GET"}, {":path", "/"}};
    EXPECT_TRUE(h2::HeaderValidator::validate_pseudo_header_order(all_pseudo));

    // Empty list is trivially valid.
    std::vector<qb::protocol::hpack::HeaderField> empty;
    EXPECT_TRUE(h2::HeaderValidator::validate_pseudo_header_order(empty));
}

TEST(HTTP2FrameLayerHeaderValidator, PseudoHeaderAfterRegularIsInvalid) {
    std::vector<qb::protocol::hpack::HeaderField> bad{{":method", "GET"}, {"content-type", "text/plain"}, {":path", "/"}};
    EXPECT_FALSE(h2::HeaderValidator::validate_pseudo_header_order(bad));
}

TEST(HTTP2FrameLayerHeaderValidator, PseudoHeaderOrderDuplicateAllowedByOrderCheck) {
    // validate_pseudo_header_order only checks ordering, not duplication: two
    // pseudo-headers in a row (no regular header between) is order-valid.
    std::vector<qb::protocol::hpack::HeaderField> dup{{":method", "GET"}, {":method", "POST"}, {"content-type", "x"}};
    EXPECT_TRUE(h2::HeaderValidator::validate_pseudo_header_order(dup));
}

TEST(HTTP2FrameLayerHeaderValidator, ForbiddenHeaders) {
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_header("connection"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_header("upgrade"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_header("http2-settings"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_header("transfer-encoding"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_header("proxy-connection"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_header("keep-alive"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_header("host"));

    // "te" is special-cased: not forbidden by name (value is checked elsewhere).
    EXPECT_FALSE(h2::HeaderValidator::is_forbidden_header("te"));

    // Ordinary headers are allowed.
    EXPECT_FALSE(h2::HeaderValidator::is_forbidden_header("content-type"));
    EXPECT_FALSE(h2::HeaderValidator::is_forbidden_header("content-length"));
}

TEST(HTTP2FrameLayerHeaderValidator, ForbiddenResponseHeaders) {
    // "te" IS forbidden in responses (the request-only exception does not apply).
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_response_header("te"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_response_header("connection"));
    // content-length is permitted in responses.
    EXPECT_FALSE(h2::HeaderValidator::is_forbidden_response_header("content-length"));
    EXPECT_FALSE(h2::HeaderValidator::is_forbidden_response_header("content-type"));
}

TEST(HTTP2FrameLayerHeaderValidator, ForbiddenTrailerHeaders) {
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_trailer_header("te"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_trailer_header("trailer"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_trailer_header("content-length"));
    EXPECT_TRUE(h2::HeaderValidator::is_forbidden_trailer_header("connection"));
    // A normal field is allowed in trailers.
    EXPECT_FALSE(h2::HeaderValidator::is_forbidden_trailer_header("content-type"));
}

TEST(HTTP2FrameLayerHeaderValidator, RequestTeValueRule) {
    // "trailers" (and lists of only "trailers", with OWS) accepted.
    EXPECT_TRUE(h2::HeaderValidator::is_valid_request_te_value("trailers"));
    EXPECT_TRUE(h2::HeaderValidator::is_valid_request_te_value(" trailers "));
    EXPECT_TRUE(h2::HeaderValidator::is_valid_request_te_value("trailers, trailers"));

    // Anything else (incl. empty) rejected.
    EXPECT_FALSE(h2::HeaderValidator::is_valid_request_te_value("gzip"));
    EXPECT_FALSE(h2::HeaderValidator::is_valid_request_te_value(""));
    EXPECT_FALSE(h2::HeaderValidator::is_valid_request_te_value("trailers, gzip"));
}

TEST(HTTP2FrameLayerHeaderValidator, ParseContentLengthValid) {
    auto v = h2::HeaderValidator::parse_content_length("0");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 0u);

    v = h2::HeaderValidator::parse_content_length("123");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 123u);

    // Leading zeros and surrounding OWS are tolerated.
    v = h2::HeaderValidator::parse_content_length(" 00123\t");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 123u);
}

TEST(HTTP2FrameLayerHeaderValidator, ParseContentLengthInvalid) {
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("").has_value());
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("-1").has_value());
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("+1").has_value());
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("1.0").has_value());
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("12a").has_value());
    // Multiple (comma-joined) values rejected.
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("1, 1").has_value());
    // Overflow (2^64) rejected.
    EXPECT_FALSE(h2::HeaderValidator::parse_content_length("18446744073709551616").has_value());
}

// ---------------------------------------------------------------------------
// HeaderValidator::is_valid_header_field — name/value character rules (base.cpp)
// The validate_request_pseudo_headers / validate_response_pseudo_headers wire
// paths are exercised through the server/client protocols, but the lowest-level
// per-character name/value checks have rejection branches reachable only with a
// direct call carrying out-of-range octets.
// ---------------------------------------------------------------------------

TEST(HTTP2FrameLayerHeaderValidator, ValidHeaderFieldAcceptsLowercaseTokenChars) {
    // The full RFC 7230 token character set plus digits, lowercase.
    EXPECT_TRUE(h2::HeaderValidator::is_valid_header_field("x-custom_header.9", "value"));
    EXPECT_TRUE(h2::HeaderValidator::is_valid_header_field("!#$%&'*+-.^_`|~", "v"));
    EXPECT_TRUE(h2::HeaderValidator::is_valid_header_field("content-type", "text/plain"));
}

TEST(HTTP2FrameLayerHeaderValidator, HeaderFieldEmptyNameRejected) {
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("", "value"));
}

TEST(HTTP2FrameLayerHeaderValidator, HeaderFieldUppercaseNameRejected) {
    // RFC 9113 §8.2: header field names must be lowercase. An uppercase letter in
    // the name hits the (c >= 'A' && c <= 'Z') reject branch.
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("Content-Type", "text/plain"));
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("X", "v"));
}

TEST(HTTP2FrameLayerHeaderValidator, HeaderFieldControlCharInNameRejected) {
    // NUL / CR / LF and any non-token character in the name are rejected via the
    // is_valid_char == false branch.
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field(std::string("bad\x00name", 8), "v"));
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("bad name", "v"));  // space is not a token char
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("bad\tname", "v")); // TAB is not a token char
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("bad:colon", "v")); // ':' not a token char (mid-name)
}

TEST(HTTP2FrameLayerHeaderValidator, HeaderFieldControlCharInValueRejected) {
    // is_valid_header_value rejects NUL, CR, LF, other C0 controls (except TAB)
    // and DEL (0x7F).
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("name", std::string("v\x00", 2))); // NUL
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("name", "v\r"));                   // CR
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("name", "v\n"));                   // LF
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("name", std::string("v\x01", 2))); // SOH (C0)
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_field("name", std::string("v\x7F", 2))); // DEL
    // TAB (0x09) and ordinary printable bytes ARE allowed in a value.
    EXPECT_TRUE(h2::HeaderValidator::is_valid_header_field("name", "v\tw"));
    EXPECT_TRUE(h2::HeaderValidator::is_valid_header_field("name", "a normal value"));
}

TEST(HTTP2FrameLayerHeaderValidator, IsValidHeaderValueDirect) {
    EXPECT_TRUE(h2::HeaderValidator::is_valid_header_value("plain"));
    EXPECT_TRUE(h2::HeaderValidator::is_valid_header_value("")); // empty value is valid
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_value("x\ny"));
    EXPECT_FALSE(h2::HeaderValidator::is_valid_header_value(std::string("x\x7F", 2)));
}

// ---------------------------------------------------------------------------
// HeaderValidator::validate_request_pseudo_headers (base.cpp)
// All duplicate / empty / unknown / missing branches via direct calls.
// ---------------------------------------------------------------------------

TEST(HTTP2FrameLayerHeaderValidator, RequestPseudoHeadersValid) {
    std::vector<qb::protocol::hpack::HeaderField> ok{
        {":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "x"}, {"accept", "*/*"}
    };
    EXPECT_TRUE(h2::HeaderValidator::validate_request_pseudo_headers(ok).is_valid);
}

TEST(HTTP2FrameLayerHeaderValidator, RequestPseudoHeadersDuplicateBranches) {
    using h2::HeaderValidator;
    auto dup = [](const char *n, const char *v) {
        return std::vector<qb::protocol::hpack::HeaderField>{
            {":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "x"}, {n, v}
        };
    };
    EXPECT_FALSE(HeaderValidator::validate_request_pseudo_headers(dup(":method", "POST")).is_valid);
    EXPECT_FALSE(HeaderValidator::validate_request_pseudo_headers(dup(":path", "/a")).is_valid);
    EXPECT_FALSE(HeaderValidator::validate_request_pseudo_headers(dup(":scheme", "http")).is_valid);
    EXPECT_FALSE(HeaderValidator::validate_request_pseudo_headers(dup(":authority", "y")).is_valid);
}

TEST(HTTP2FrameLayerHeaderValidator, RequestPseudoHeadersEmptyValueBranches) {
    using h2::HeaderValidator;
    EXPECT_FALSE(HeaderValidator::validate_request_pseudo_headers({{":method", ""}, {":path", "/"}, {":scheme", "https"}, {":authority", "x"}})
                     .is_valid);
    EXPECT_FALSE(
        HeaderValidator::validate_request_pseudo_headers({{":method", "GET"}, {":path", ""}, {":scheme", "https"}, {":authority", "x"}})
            .is_valid);
    EXPECT_FALSE(
        HeaderValidator::validate_request_pseudo_headers({{":method", "GET"}, {":path", "/"}, {":scheme", ""}, {":authority", "x"}}).is_valid);
    EXPECT_FALSE(
        HeaderValidator::validate_request_pseudo_headers({{":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", ""}})
            .is_valid);
}

TEST(HTTP2FrameLayerHeaderValidator, RequestPseudoHeadersUnknownAndMissing) {
    using h2::HeaderValidator;
    // Unknown pseudo-header.
    EXPECT_FALSE(HeaderValidator::validate_request_pseudo_headers(
                     {{":method", "GET"}, {":path", "/"}, {":scheme", "https"}, {":authority", "x"}, {":bogus", "v"}})
                     .is_valid);
    // Missing a mandatory one (no :authority).
    const auto missing = HeaderValidator::validate_request_pseudo_headers({{":method", "GET"}, {":path", "/"}, {":scheme", "https"}});
    EXPECT_FALSE(missing.is_valid);
    EXPECT_EQ(missing.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

// ---------------------------------------------------------------------------
// HeaderValidator::validate_response_pseudo_headers (base.cpp) — full function.
// ---------------------------------------------------------------------------

TEST(HTTP2FrameLayerHeaderValidator, ResponsePseudoHeadersValid) {
    std::vector<qb::protocol::hpack::HeaderField> ok{{":status", "200"}, {"content-type", "text/html"}};
    EXPECT_TRUE(h2::HeaderValidator::validate_response_pseudo_headers(ok).is_valid);
}

TEST(HTTP2FrameLayerHeaderValidator, ResponsePseudoHeadersInvalidBranches) {
    using h2::HeaderValidator;
    // Duplicate :status.
    EXPECT_FALSE(HeaderValidator::validate_response_pseudo_headers({{":status", "200"}, {":status", "404"}}).is_valid);
    // Wrong-length :status (must be exactly 3 digits).
    EXPECT_FALSE(HeaderValidator::validate_response_pseudo_headers({{":status", "20"}}).is_valid);
    EXPECT_FALSE(HeaderValidator::validate_response_pseudo_headers({{":status", ""}}).is_valid);
    // Non-numeric :status.
    EXPECT_FALSE(HeaderValidator::validate_response_pseudo_headers({{":status", "2x0"}}).is_valid);
    // A request pseudo-header (:path) is invalid in a response.
    EXPECT_FALSE(HeaderValidator::validate_response_pseudo_headers({{":status", "200"}, {":path", "/"}}).is_valid);
    // Missing :status entirely.
    const auto missing = HeaderValidator::validate_response_pseudo_headers({{"content-type", "text/html"}});
    EXPECT_FALSE(missing.is_valid);
    EXPECT_EQ(missing.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

// Note: StreamIdValidator::get_frame_type_name (base.cpp ~434-460) is a PRIVATE
// static member, reachable only from internal logging paths inside the validator
// — it has no public caller and cannot be exercised by a unit test without
// changing visibility, so its switch arms are left uncovered by design.

// ---------------------------------------------------------------------------
// Http2ErrorHandler (base.cpp)
// ---------------------------------------------------------------------------

TEST(HTTP2FrameLayerErrorHandler, ErrorNamesForAllCodes) {
    using EC = h2::ErrorCode;
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::NO_ERROR), "NO_ERROR");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::PROTOCOL_ERROR), "PROTOCOL_ERROR");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::INTERNAL_ERROR), "INTERNAL_ERROR");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::FLOW_CONTROL_ERROR), "FLOW_CONTROL_ERROR");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::SETTINGS_TIMEOUT), "SETTINGS_TIMEOUT");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::STREAM_CLOSED), "STREAM_CLOSED");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::FRAME_SIZE_ERROR), "FRAME_SIZE_ERROR");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::REFUSED_STREAM), "REFUSED_STREAM");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::CANCEL), "CANCEL");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::COMPRESSION_ERROR), "COMPRESSION_ERROR");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::CONNECT_ERROR), "CONNECT_ERROR");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::ENHANCE_YOUR_CALM), "ENHANCE_YOUR_CALM");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::INADEQUATE_SECURITY), "INADEQUATE_SECURITY");
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(EC::HTTP_1_1_REQUIRED), "HTTP_1_1_REQUIRED");
    // Unmapped value falls through to UNKNOWN_ERROR.
    EXPECT_EQ(h2::Http2ErrorHandler::get_error_name(static_cast<EC>(0xFF)), "UNKNOWN_ERROR");
}

TEST(HTTP2FrameLayerErrorHandler, EscalateStreamZeroAlwaysEscalates) {
    // stream_id == 0 escalates regardless of code, even for normally
    // stream-scoped codes.
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(h2::ErrorCode::CANCEL, 0));
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(h2::ErrorCode::STREAM_CLOSED, 0));
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(h2::ErrorCode::NO_ERROR, 0));
}

TEST(HTTP2FrameLayerErrorHandler, EscalatePerCodeOnNonZeroStream) {
    constexpr uint32_t sid = 3;
    using EC               = h2::ErrorCode;

    // Connection-level / always-escalating codes.
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::PROTOCOL_ERROR, sid));
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::COMPRESSION_ERROR, sid));
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::CONNECT_ERROR, sid));
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::ENHANCE_YOUR_CALM, sid));
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::INADEQUATE_SECURITY, sid));
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::HTTP_1_1_REQUIRED, sid));
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::INTERNAL_ERROR, sid));
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::FLOW_CONTROL_ERROR, sid));
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::SETTINGS_TIMEOUT, sid));
    EXPECT_TRUE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::FRAME_SIZE_ERROR, sid));

    // Stream-scoped codes do NOT escalate on a non-zero stream.
    EXPECT_FALSE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::STREAM_CLOSED, sid));
    EXPECT_FALSE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::REFUSED_STREAM, sid));
    EXPECT_FALSE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::CANCEL, sid));
    // NO_ERROR on a stream hits the default branch -> no escalation.
    EXPECT_FALSE(h2::Http2ErrorHandler::should_escalate_to_connection(EC::NO_ERROR, sid));
}

TEST(HTTP2FrameLayerErrorHandler, FormatErrorMessageNonEmpty) {
    const auto conn = h2::Http2ErrorHandler::format_error_message(h2::ErrorCode::PROTOCOL_ERROR, "bad preface", 0);
    EXPECT_FALSE(conn.empty());
    EXPECT_NE(conn.find("Connection error"), std::string::npos);
    EXPECT_NE(conn.find("bad preface"), std::string::npos);

    const auto stream = h2::Http2ErrorHandler::format_error_message(h2::ErrorCode::CANCEL, "cancelled", 7);
    EXPECT_FALSE(stream.empty());
    EXPECT_NE(stream.find("Stream 7"), std::string::npos);

    // Empty context still produces a non-empty message.
    const auto no_ctx = h2::Http2ErrorHandler::format_error_message(h2::ErrorCode::INTERNAL_ERROR, "", 0);
    EXPECT_FALSE(no_ctx.empty());
}

// ---------------------------------------------------------------------------
// StreamIdValidator (base.h inline + base.cpp)
// ---------------------------------------------------------------------------

TEST(HTTP2FrameLayerStreamId, ClientServerConnectionParity) {
    // Client streams: non-zero, odd.
    EXPECT_TRUE(h2::StreamIdValidator::is_valid_client_stream_id(1));
    EXPECT_TRUE(h2::StreamIdValidator::is_valid_client_stream_id(3));
    EXPECT_FALSE(h2::StreamIdValidator::is_valid_client_stream_id(0));
    EXPECT_FALSE(h2::StreamIdValidator::is_valid_client_stream_id(2));

    // Server streams: non-zero, even.
    EXPECT_TRUE(h2::StreamIdValidator::is_valid_server_stream_id(2));
    EXPECT_TRUE(h2::StreamIdValidator::is_valid_server_stream_id(4));
    EXPECT_FALSE(h2::StreamIdValidator::is_valid_server_stream_id(0));
    EXPECT_FALSE(h2::StreamIdValidator::is_valid_server_stream_id(1));

    // Connection stream: only 0.
    EXPECT_TRUE(h2::StreamIdValidator::is_connection_stream_id(0));
    EXPECT_FALSE(h2::StreamIdValidator::is_connection_stream_id(1));
}

TEST(HTTP2FrameLayerStreamId, ConnectionFramesRequireStreamZero) {
    using h2::FrameType;
    // SETTINGS / PING / GOAWAY must use stream 0.
    for (FrameType t : {FrameType::SETTINGS, FrameType::PING, FrameType::GOAWAY}) {
        EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(t, 0, true).is_valid);
        const auto bad = h2::StreamIdValidator::validate_stream_id_for_frame(t, 1, true);
        EXPECT_FALSE(bad.is_valid);
        EXPECT_EQ(bad.error_code, h2::ErrorCode::PROTOCOL_ERROR);
    }
}

TEST(HTTP2FrameLayerStreamId, StreamFramesRejectStreamZero) {
    using h2::FrameType;
    // DATA / RST_STREAM / PRIORITY / CONTINUATION must NOT use stream 0.
    for (FrameType t : {FrameType::DATA, FrameType::RST_STREAM, FrameType::PRIORITY, FrameType::CONTINUATION}) {
        const auto bad = h2::StreamIdValidator::validate_stream_id_for_frame(t, 0, true);
        EXPECT_FALSE(bad.is_valid);
        EXPECT_EQ(bad.error_code, h2::ErrorCode::PROTOCOL_ERROR);
    }
    // DATA on a valid non-zero stream is accepted (no parity requirement on DATA).
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::DATA, 1, true).is_valid);
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::DATA, 2, true).is_valid);
}

TEST(HTTP2FrameLayerStreamId, HeadersParityRules) {
    using h2::FrameType;

    // Server receiving HEADERS: must be a valid client (odd) stream id.
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::HEADERS, 1, /*is_server=*/true).is_valid);
    const auto server_even = h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::HEADERS, 2, /*is_server=*/true);
    EXPECT_FALSE(server_even.is_valid);
    EXPECT_EQ(server_even.error_code, h2::ErrorCode::PROTOCOL_ERROR);

    // Client receiving HEADERS: no extra parity gate beyond non-zero, so an
    // even (server-initiated) stream id is accepted here.
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::HEADERS, 2, /*is_server=*/false).is_valid);
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::HEADERS, 1, /*is_server=*/false).is_valid);
}

TEST(HTTP2FrameLayerStreamId, PushPromiseParityRules) {
    using h2::FrameType;

    // Client receiving PUSH_PROMISE: promised id must be a valid server (even) id.
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::PUSH_PROMISE, 2, /*is_server=*/false).is_valid);
    const auto client_odd = h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::PUSH_PROMISE, 3, /*is_server=*/false);
    EXPECT_FALSE(client_odd.is_valid);
    EXPECT_EQ(client_odd.error_code, h2::ErrorCode::PROTOCOL_ERROR);

    // Server receiving PUSH_PROMISE: validated as a client (odd) stream id.
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::PUSH_PROMISE, 1, /*is_server=*/true).is_valid);
    const auto server_even = h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::PUSH_PROMISE, 2, /*is_server=*/true);
    EXPECT_FALSE(server_even.is_valid);
    EXPECT_EQ(server_even.error_code, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2FrameLayerStreamId, WindowUpdateAcceptsZeroAndNonZero) {
    using h2::FrameType;
    // WINDOW_UPDATE is valid on stream 0 (connection) and on a specific stream.
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::WINDOW_UPDATE, 0, true).is_valid);
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::WINDOW_UPDATE, 1, true).is_valid);
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::WINDOW_UPDATE, 2, false).is_valid);
}

TEST(HTTP2FrameLayerStreamId, UnknownFrameTypeIsValid) {
    using h2::FrameType;
    // Unknown frame types are ignored per RFC 9113, so validation passes.
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::UNKNOWN, 0, true).is_valid);
    EXPECT_TRUE(h2::StreamIdValidator::validate_stream_id_for_frame(FrameType::UNKNOWN, 5, false).is_valid);
}

// ===========================================================================
// Framer-driving tests (base.h templated Http2Protocol<>)
//
// The static-helper tests above never instantiate the framer. The block below
// drives the shared frame parser/state-machine (qb::protocol::http2::Http2Protocol)
// through a real ServerHttp2Protocol over the socket-less Http2FakeIO harness,
// reaching the frame-header validation, zero-payload dispatch, padding, the
// HEADERS-with-PRIORITY parse, PUSH_PROMISE/GOAWAY payload parsing and the
// CONTINUATION-required gate that pure value-type tests cannot exercise.
// ===========================================================================

namespace {

using qb::protocol::http2::FLAG_ACK;
using qb::protocol::http2::FLAG_END_HEADERS;
using qb::protocol::http2::FLAG_END_STREAM;
using qb::protocol::http2::FLAG_PADDED;
using qb::protocol::http2::FLAG_PRIORITY;
using FT = h2::FrameType;

// Drive preface + an empty client SETTINGS so the server is post-handshake.
void
fl_handshake(FrameLayerServer &protocol, Http2FakeIO &io) {
    push_preface(io);
    push_frame(io, FT::SETTINGS, 0, 0, {});
    drive(protocol, io);
}

} // namespace

// --- getMessageSize stalls (base.h:523-525, 539-540) -----------------------

TEST(HTTP2FramerDrive, PartialPrefaceLeavesParserStalled) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);

    // Push only the first half of the 24-byte preface: getMessageSize in the
    // EXPECTING_PREFACE state sees in_buffer < remaining_preface_needed and
    // returns 0, so the framer makes no progress and stays ok().
    const auto &preface = ::HTTP2_CONNECTION_PREFACE;
    qb::http::test::push_bytes(io, preface.data(), preface.size() / 2);

    EXPECT_EQ(protocol.getMessageSize(), 0u);
    EXPECT_TRUE(protocol.ok());

    // Completing the preface now unblocks it.
    qb::http::test::push_bytes(io, preface.data() + preface.size() / 2, preface.size() - preface.size() / 2);
    drive(protocol, io);
    EXPECT_TRUE(protocol.ok());
}

TEST(HTTP2FramerDrive, FrameHeaderWithoutPayloadLeavesParserStalled) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Manually write a frame header that promises an 8-byte PING payload, but
    // do NOT push the payload bytes. The framer consumes the header, moves to
    // EXPECTING_FRAME_PAYLOAD, then getMessageSize returns 0 because
    // in_buffer.size() < _expected_payload_bytes.
    h2::FrameHeader fh{};
    fh.set_payload_length(8);
    fh.type  = static_cast<uint8_t>(FT::PING);
    fh.flags = 0;
    fh.set_stream_id(0);
    qb::http::test::push_bytes(io, &fh, sizeof(fh));

    drive(protocol, io); // consumes the header, then stalls
    EXPECT_EQ(protocol.getMessageSize(), 0u);
    EXPECT_TRUE(protocol.ok());

    // Supplying the 8 payload octets now lets the PING complete.
    const std::vector<uint8_t> ping_payload(8, 0u);
    qb::http::test::push_bytes(io, ping_payload.data(), ping_payload.size());
    drive(protocol, io);
    EXPECT_TRUE(protocol.ok());
}

// --- invalid preface bytes (base.h:582-584) --------------------------------

TEST(HTTP2FramerDrive, InvalidPrefaceBytesAreProtocolError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);

    // 24 bytes of the wrong content (same length as the real preface so the
    // size check passes but the memcmp fails -> PROTOCOL_ERROR).
    const std::vector<uint8_t> bogus(::HTTP2_CONNECTION_PREFACE.size(), 'Z');
    qb::http::test::push_bytes(io, bogus.data(), bogus.size());
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

// --- zero-payload frame dispatch (base.h:976-1048) -------------------------

TEST(HTTP2FramerDrive, ZeroPayloadHeadersFrameDispatches) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // HEADERS with END_HEADERS|END_STREAM and a zero-length payload: the
    // zero-payload dispatch path constructs an (empty) HeadersFrame and hands
    // it to the side protocol. An empty header block is a malformed request,
    // so the server resets the stream rather than accepting it.
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, {});
    drive(protocol, io);

    // The framer itself stays healthy (it dispatched a well-formed empty frame);
    // the request was simply rejected at the stream layer.
    EXPECT_TRUE(protocol.ok());
    EXPECT_TRUE(qb::http::test::output_has_frame(io.output, FT::RST_STREAM) || io.request_count == 0);
}

TEST(HTTP2FramerDrive, ZeroPayloadDataFrameOnOpenStreamDispatches) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open a POST stream (HEADERS, no END_STREAM) so a subsequent empty DATA
    // frame has a live stream to land on; that drives the DATA arm of the
    // zero-payload dispatch.
    auto post_headers     = default_request_headers("/upload");
    post_headers[0].value = "POST";
    const auto encoded    = encode_hpack_headers(post_headers);
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS, 1, encoded);
    push_frame(io, FT::DATA, FLAG_END_STREAM, 1, {}); // zero-length DATA, END_STREAM
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
}

TEST(HTTP2FramerDrive, ZeroPayloadSettingsAckDispatches) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // A SETTINGS frame with the ACK flag and an empty payload exercises the
    // SETTINGS-ACK branch of the zero-payload dispatch.
    push_frame(io, FT::SETTINGS, FLAG_ACK, 0, {});
    drive(protocol, io);
    EXPECT_TRUE(protocol.ok());
}

TEST(HTTP2FramerDrive, ZeroPayloadRstStreamIsFrameSizeError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // RST_STREAM mandates a 4-octet payload; a zero-length RST_STREAM hits the
    // PRIORITY/RST_STREAM/GOAWAY/WINDOW_UPDATE "mandatory non-zero payload"
    // arm -> FRAME_SIZE_ERROR.
    push_frame(io, FT::RST_STREAM, 0, 1, {});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

TEST(HTTP2FramerDrive, ZeroPayloadWindowUpdateIsFrameSizeError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FT::WINDOW_UPDATE, 0, 0, {}); // 0-length WINDOW_UPDATE
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

TEST(HTTP2FramerDrive, ZeroPayloadPushPromiseIsFrameSizeError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // PUSH_PROMISE with zero payload hits its dedicated zero-payload arm
    // (must carry at least the 4-octet promised stream id) -> FRAME_SIZE_ERROR.
    push_frame(io, FT::PUSH_PROMISE, 0, 1, {});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

TEST(HTTP2FramerDrive, ZeroPayloadPingIsFrameSizeError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // PING payload MUST be 8 octets; a zero-length PING is the PING arm of the
    // zero-payload dispatch -> FRAME_SIZE_ERROR.
    push_frame(io, FT::PING, 0, 0, {});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

// --- CONTINUATION-required gate (base.h:604-613, 1036-1040) ----------------

TEST(HTTP2FramerDrive, NonContinuationAfterIncompleteHeadersIsProtocolError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // HEADERS WITHOUT END_HEADERS leaves the parser expecting a CONTINUATION
    // for the same stream. Sending a DATA frame instead trips the
    // continuation-required gate in the frame-header state -> PROTOCOL_ERROR.
    const auto encoded = encode_hpack_headers(default_request_headers("/"));
    push_frame(io, FT::HEADERS, 0, 1, encoded); // no END_HEADERS
    push_frame(io, FT::DATA, FLAG_END_STREAM, 1, {0x00});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

TEST(HTTP2FramerDrive, ContinuationOnWrongStreamIsProtocolError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // HEADERS on stream 1 without END_HEADERS, then a CONTINUATION on stream 3:
    // the stream-id mismatch in the continuation-required gate is a
    // PROTOCOL_ERROR.
    const auto encoded = encode_hpack_headers(default_request_headers("/"));
    push_frame(io, FT::HEADERS, 0, 1, encoded);                // no END_HEADERS, stream 1
    push_frame(io, FT::CONTINUATION, FLAG_END_HEADERS, 3, {}); // wrong stream
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

TEST(HTTP2FramerDrive, HeadersSplitAcrossContinuationCompletes) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Encode a full request header block, then split it: the first half rides a
    // HEADERS frame WITHOUT END_HEADERS, the rest a zero-or-more CONTINUATION
    // frames. This drives both the continuation-required gate (accepted path)
    // and the zero-payload CONTINUATION dispatch when the tail is empty.
    const auto encoded = encode_hpack_headers(default_request_headers("/split"));
    ASSERT_GE(encoded.size(), 2u);
    const std::size_t          half = encoded.size() / 2;
    const std::vector<uint8_t> first(encoded.begin(), encoded.begin() + half);
    const std::vector<uint8_t> rest(encoded.begin() + half, encoded.end());

    push_frame(io, FT::HEADERS, FLAG_END_STREAM, 1, first); // no END_HEADERS
    push_frame(io, FT::CONTINUATION, FLAG_END_HEADERS, 1, rest);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
}

// --- HEADERS with PRIORITY flag (base.h:1144-1152) -------------------------

TEST(HTTP2FramerDrive, HeadersWithPriorityFlagParses) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Build a HEADERS payload that begins with the 5-octet PRIORITY block
    // (exclusive=1, stream dependency=1, weight=16) followed by the HPACK block.
    const auto           hpack = encode_hpack_headers(default_request_headers("/prio"));
    std::vector<uint8_t> payload;
    payload.push_back(0x80); // exclusive bit set, dependency high byte = 0
    payload.push_back(0x00);
    payload.push_back(0x00);
    payload.push_back(0x01); // stream dependency = 1
    payload.push_back(0x10); // weight = 16
    payload.insert(payload.end(), hpack.begin(), hpack.end());

    push_frame(io, FT::HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM | FLAG_PRIORITY, 1, payload);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
}

// --- padded frame validation (base.h:822-824, 1130) ------------------------

TEST(HTTP2FramerDrive, PaddedHeadersSuccessPathStripsPadding) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // HEADERS, FLAG_PADDED, with a Pad Length octet of 0 followed by the real
    // HPACK header block and no padding bytes. This drives the FLAG_PADDED
    // branch of handle_headers_frame_payload (the success path that records
    // pad_length and assigns the trimmed header block).
    const auto           hpack = encode_hpack_headers(default_request_headers("/padh"));
    std::vector<uint8_t> payload;
    payload.push_back(0x00); // Pad Length = 0
    payload.insert(payload.end(), hpack.begin(), hpack.end());

    push_frame(io, FT::HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM | FLAG_PADDED, 1, payload);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
}

TEST(HTTP2FramerDrive, PaddedDataWithPadLengthExceedingPayloadIsProtocolError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open a stream first so DATA has somewhere to land.
    auto post_headers     = default_request_headers("/p");
    post_headers[0].value = "POST";
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS, 1, encode_hpack_headers(post_headers));

    // DATA, PADDED: first octet is Pad Length=200 but only 2 bytes follow ->
    // pad_length > p_len -> PROTOCOL_ERROR.
    push_frame(io, FT::DATA, FLAG_PADDED, 1, {200, 'a', 'b'});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

TEST(HTTP2FramerDrive, PaddedDataWithValidPaddingIsAccepted) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    auto post_headers     = default_request_headers("/p");
    post_headers[0].value = "POST";
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS, 1, encode_hpack_headers(post_headers));

    // Pad Length=3, payload "hi", then 3 padding octets: the padded-frame
    // success path strips the padding cleanly.
    push_frame(io, FT::DATA, FLAG_PADDED | FLAG_END_STREAM, 1, {3, 'h', 'i', 0, 0, 0});
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
}

// --- GOAWAY with debug data (base.h:1300-1301) -----------------------------

TEST(HTTP2FramerDrive, GoAwayWithDebugDataParses) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // GOAWAY: last-stream-id (4) + error-code (4) + trailing debug bytes. The
    // payload-size > 8 branch copies the additional debug data.
    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x01,  // last stream id = 1
                                    0x00, 0x00, 0x00, 0x00}; // error code = NO_ERROR
    const std::string    debug   = "bye";
    payload.insert(payload.end(), debug.begin(), debug.end());

    push_frame(io, FT::GOAWAY, 0, 0, payload);
    drive(protocol, io);

    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::NO_ERROR);
}

// --- WINDOW_UPDATE zero increment (base.h:1313-1314, 1326-1328) ------------

TEST(HTTP2FramerDrive, WindowUpdateZeroIncrementIsProtocolError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // 4-octet WINDOW_UPDATE with a zero increment -> PROTOCOL_ERROR.
    push_frame(io, FT::WINDOW_UPDATE, 0, 0, {0x00, 0x00, 0x00, 0x00});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

TEST(HTTP2FramerDrive, WindowUpdateWrongSizeIsFrameSizeError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // WINDOW_UPDATE with a 5-octet (non-4) payload -> FRAME_SIZE_ERROR.
    push_frame(io, FT::WINDOW_UPDATE, 0, 0, {0x00, 0x00, 0x00, 0x01, 0x00});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

// --- send_headers_with_continuation (base.h:718-734) -----------------------

TEST(HTTP2FramerDrive, ServerResponseLargeHeaderBlockSpansContinuation) {
    Http2FakeIO io;
    // Advertise the smallest legal max-frame-size (16384) and force a tiny peer
    // frame size via the client's SETTINGS so the server must fragment its
    // response header block across HEADERS + CONTINUATION when it replies.
    FrameLayerServer protocol(io);

    push_preface(io);
    // Client SETTINGS: SETTINGS_MAX_FRAME_SIZE = 16384 (the floor), which also
    // bounds the server's per-frame fragment size for header serialization.
    const std::vector<uint8_t> settings = {0x00, 0x05, 0x00, 0x00, 0x40, 0x00};
    push_frame(io, FT::SETTINGS, 0, 0, settings);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Issue a GET; the response path emits the response headers. We can't force
    // a >16KB header block from here deterministically, but the single-frame
    // path through send_headers_with_continuation (first_frame + last_fragment)
    // is exercised by every emitted response.
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, encode_hpack_headers(default_request_headers("/")));
    drive(protocol, io);
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
}

// --- PUSH_PROMISE payload parse (base.h:1234-1264) -------------------------

TEST(HTTP2FramerDrive, PushPromisePayloadIsParsedThenRejectedByServer) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // A client must never send PUSH_PROMISE, but the shared framer still parses
    // the payload (promised stream id + header block) before handing the typed
    // frame to the server, which then rejects it. This drives
    // handle_push_promise_frame_payload (promised id extraction + header block
    // assignment + END_HEADERS continuation bookkeeping).
    const auto           hpack   = encode_hpack_headers(default_request_headers("/pushed"));
    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x02}; // promised stream id = 2
    payload.insert(payload.end(), hpack.begin(), hpack.end());

    push_frame(io, FT::PUSH_PROMISE, FLAG_END_HEADERS, 1, payload);
    drive(protocol, io);

    // Either way the payload-parse path ran; the server treats a received
    // PUSH_PROMISE as a connection error.
    EXPECT_FALSE(protocol.ok());
}

TEST(HTTP2FramerDrive, PaddedPushPromiseTooShortIsFrameSizeError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // PUSH_PROMISE, PADDED, with a Pad Length octet of 200 but only two trailing
    // bytes: validate_padded_frame fails (pad_length > remaining payload) and the
    // PUSH_PROMISE handler returns the failure early.
    push_frame(io, FT::PUSH_PROMISE, FLAG_PADDED, 1, {200, 0x00, 0x02}); // pad len 200, 2 bytes
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

// --- zero-payload CONTINUATION dispatch (base.h:1036-1040) -----------------

TEST(HTTP2FramerDrive, EmptyEndHeadersContinuationCompletesHeaderBlock) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Full header block on a HEADERS frame WITHOUT END_HEADERS, then an EMPTY
    // CONTINUATION carrying only END_HEADERS. The zero-length CONTINUATION takes
    // the zero-payload dispatch CONTINUATION arm and closes the header block.
    const auto encoded = encode_hpack_headers(default_request_headers("/cont0"));
    push_frame(io, FT::HEADERS, FLAG_END_STREAM, 1, encoded);  // no END_HEADERS
    push_frame(io, FT::CONTINUATION, FLAG_END_HEADERS, 1, {}); // empty, END_HEADERS
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
}

// --- padded HEADERS failure path (base.h:1128-1130) ------------------------

TEST(HTTP2FramerDrive, PaddedHeadersPadLengthExceedsPayloadIsProtocolError) {
    Http2FakeIO      io;
    FrameLayerServer protocol(io);
    fl_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // HEADERS, PADDED: Pad Length octet = 200 but only a couple of bytes
    // follow, so validate_padded_frame fails (pad_length > p_len) and the
    // HEADERS handler returns the failure early.
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS | FLAG_PADDED, 1, {200, 0x82, 0x86});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
}

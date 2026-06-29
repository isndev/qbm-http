/**
 * @file qbm/http/tests/unit/http2/http2-server-coverage-deep.cpp
 * @brief Deep server-side HTTP/2 protocol coverage: branches the existing
 *        server/state/coverage/roundtrip files leave unexercised.
 *
 * The existing http2 server units (`http2-server-protocol.cpp`,
 * `http2-protocol-state.cpp`, `http2-protocol-coverage.cpp`) are thorough on the
 * happy path and most rejects, and `http2-protocol-roundtrip.cpp` drives the
 * connected client<->server dispatch. This file targets the REACHABLE
 * `ServerHttp2Protocol` branches still missing from that set, each asserting a
 * concrete protocol outcome (emitted frame, dispatched event, ErrorCode, ok()):
 *
 *   - SETTINGS value-validation -> GOAWAY (the whole SettingsHelper::validate_setting
 *     matrix on the server side was untested): ENABLE_PUSH > 1, INITIAL_WINDOW_SIZE
 *     over 2^31-1, MAX_FRAME_SIZE below/above the legal range, ENABLE_CONNECT_PROTOCOL
 *     > 1. Each maps to a specific GOAWAY ErrorCode.
 *   - request `te` header value-discrimination: `te: trailers` accepted (dispatched),
 *     any other `te` token -> PROTOCOL_ERROR stream error.
 *   - request `content-length` DECLARED above MAX_BODY_SIZE -> ENHANCE_YOUR_CALM
 *     (validates the header value, not the bytes, so it is cheap to reach).
 *   - trailers whose content-length contradicts the delivered body -> PROTOCOL_ERROR.
 *   - send_response on a RESERVED_LOCAL (server-pushed) stream -> PROTOCOL_ERROR
 *     stream error (the RESERVED_LOCAL arm of the send-state guard).
 *   - send_response with a control byte in a response header VALUE -> PROTOCOL_ERROR
 *     (the is_valid_header_field send-path arm; the value is set via Response::set_header,
 *     which stores verbatim, so it reaches the validator before any HPACK encode).
 *   - GOAWAY received: the dispatched Http2GoAwayEvent carries the peer's
 *     last_stream_id and debug_data (the canonical harness sink drops both; a
 *     local rich sink captures them), and a second GOAWAY arriving while already
 *     shutting down returns early without re-dispatching.
 *
 * Pure logic: socket-less, deterministic, parallel-safe, no engine / TLS / clock.
 * The harness lives in tests/shared/http2_fake_io.h. Contains no main().
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "../../shared/http2_fake_io.h"

using namespace qb::http::test;

using qb::protocol::http2::ErrorCode;
using qb::protocol::http2::FrameType;
using qb::protocol::http2::Http2SettingIdentifier;

namespace {

namespace h2 = qb::protocol::http2;

using ServerProtocol = h2::ServerHttp2Protocol<Http2FakeIO>;

// Encode a SETTINGS payload from (typed-identifier, value) pairs, mirroring the
// helper in http2-server-protocol.cpp.
[[nodiscard]] std::vector<uint8_t>
encode_settings_payload(const std::vector<std::pair<Http2SettingIdentifier, uint32_t>> &settings) {
    std::vector<std::pair<uint16_t, uint32_t>> raw;
    raw.reserve(settings.size());
    for (const auto &[id, val] : settings) {
        raw.emplace_back(static_cast<uint16_t>(id), val);
    }
    return make_settings_payload(raw);
}

// Drive preface + a client SETTINGS frame carrying the given entries, then drive
// the framer. Used to deliver a single value-validation-failing setting.
void
handshake_with_settings(ServerProtocol &protocol, Http2FakeIO &io, const std::vector<std::pair<Http2SettingIdentifier, uint32_t>> &settings) {
    push_preface(io);
    push_frame(io, FrameType::SETTINGS, 0, 0, encode_settings_payload(settings));
    drive(protocol, io);
}

// Plain preface + empty SETTINGS handshake (server stays healthy, push enabled
// by default).
void
handshake_default(ServerProtocol &protocol, Http2FakeIO &io) {
    do_handshake(protocol, io);
}

// Open a client GET stream (END_HEADERS + END_STREAM) carrying the given header
// list, driving the framer. Leaves the stream HALF_CLOSED_REMOTE / dispatched.
void
push_request_headers(ServerProtocol &protocol, Http2FakeIO &io, uint32_t stream_id,
                     const std::vector<qb::protocol::hpack::HeaderField> &headers) {
    const auto encoded = encode_hpack_headers(headers);
    push_frame(io, FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, stream_id, encoded);
    drive(protocol, io);
}

// A request header set with valid pseudo-headers plus the supplied extra regular
// fields, so a test can exercise a single regular-header validation arm.
[[nodiscard]] std::vector<qb::protocol::hpack::HeaderField>
request_with(const std::vector<qb::protocol::hpack::HeaderField> &extra) {
    std::vector<qb::protocol::hpack::HeaderField> hdrs = {
        {":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/"}
    };
    for (const auto &h : extra) {
        hdrs.push_back(h);
    }
    return hdrs;
}

// A server-facing rich sink that captures the FULL GOAWAY event (the canonical
// Http2FakeIO drops last_stream_id and debug_data). Otherwise mirrors the
// server IO contract.
struct RichServerIO {
    using base_io_t = RichServerIO;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;

    int         request_count       = 0;
    int         stream_error_count  = 0;
    int         goaway_count        = 0;
    ErrorCode   last_goaway_error   = ErrorCode::NO_ERROR;
    uint32_t    last_goaway_last_id = 0;
    std::string last_goaway_debug;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    qb::allocator::pipe<char> &
    out() noexcept {
        return output;
    }

    template <typename Frame>
    RichServerIO &
    operator<<(const Frame &frame) {
        output.put(frame);
        return *this;
    }

    void
    on(qb::http::Request &&, uint32_t) {
        ++request_count;
    }
    void
    on(const h2::Http2StreamErrorEvent &) {
        ++stream_error_count;
    }
    void
    on(const h2::Http2GoAwayEvent &event) {
        ++goaway_count;
        last_goaway_error   = event.error_code;
        last_goaway_last_id = event.last_stream_id;
        last_goaway_debug   = event.debug_data;
    }
    void
    on(const h2::Http2PushPromiseEvent &) {}
};

using RichServerProtocol = h2::ServerHttp2Protocol<RichServerIO>;

} // namespace

// ===========================================================================
// SETTINGS value-validation -> GOAWAY (server SettingsHelper::validate_setting).
// The framer parses each SETTINGS entry from raw bytes and dispatches it; the
// server validates the VALUE and answers a bad one with GOAWAY of a specific
// ErrorCode. None of these value-validation arms was exercised server-side.
// ===========================================================================

TEST(HTTP2ServerCoverageDeep, SettingsEnablePushAboveOneIsProtocolErrorGoaway) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    handshake_with_settings(server, io, {{Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 2}});

    EXPECT_FALSE(server.ok());
    ASSERT_TRUE(server.get_last_error_code().has_value());
    EXPECT_EQ(*server.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, ErrorCode::PROTOCOL_ERROR);
    EXPECT_TRUE(output_has_frame(io.output, FrameType::GOAWAY));
}

TEST(HTTP2ServerCoverageDeep, SettingsInitialWindowSizeOverLimitIsFlowControlGoaway) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    // 0x80000000 == 2^31, one past MAX_WINDOW_SIZE_LIMIT (2^31 - 1). The SETTINGS
    // value field is a full 32-bit field (unlike the 31-bit-masked WINDOW_UPDATE),
    // so this over-limit value is deliverable on the wire.
    handshake_with_settings(server, io, {{Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 0x80000000u}});

    EXPECT_FALSE(server.ok());
    ASSERT_TRUE(server.get_last_error_code().has_value());
    EXPECT_EQ(*server.get_last_error_code(), ErrorCode::FLOW_CONTROL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, ErrorCode::FLOW_CONTROL_ERROR);
    EXPECT_TRUE(output_has_frame(io.output, FrameType::GOAWAY));
}

TEST(HTTP2ServerCoverageDeep, SettingsMaxFrameSizeBelowMinimumIsProtocolErrorGoaway) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    // 100 < MIN_MAX_FRAME_SIZE (16384) -> out-of-range PROTOCOL_ERROR.
    handshake_with_settings(server, io, {{Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 100}});

    EXPECT_FALSE(server.ok());
    ASSERT_TRUE(server.get_last_error_code().has_value());
    EXPECT_EQ(*server.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_TRUE(output_has_frame(io.output, FrameType::GOAWAY));
}

TEST(HTTP2ServerCoverageDeep, SettingsMaxFrameSizeAboveMaximumIsProtocolErrorGoaway) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    // 0x01000000 == 2^24, one past MAX_FRAME_SIZE_LIMIT (2^24 - 1) -> PROTOCOL_ERROR.
    handshake_with_settings(server, io, {{Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 0x01000000u}});

    EXPECT_FALSE(server.ok());
    ASSERT_TRUE(server.get_last_error_code().has_value());
    EXPECT_EQ(*server.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_TRUE(output_has_frame(io.output, FrameType::GOAWAY));
}

TEST(HTTP2ServerCoverageDeep, SettingsEnableConnectProtocolAboveOneIsProtocolErrorGoaway) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    handshake_with_settings(server, io, {{Http2SettingIdentifier::SETTINGS_ENABLE_CONNECT_PROTOCOL, 5}});

    EXPECT_FALSE(server.ok());
    ASSERT_TRUE(server.get_last_error_code().has_value());
    EXPECT_EQ(*server.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_TRUE(output_has_frame(io.output, FrameType::GOAWAY));
}

// A SETTINGS frame that carries SETTINGS_MAX_HEADER_LIST_SIZE (no RFC-mandated
// bound) is accepted: the server validates it as valid and answers a plain ACK,
// staying healthy. Confirms the "valid setting -> ACK" arm for a setting whose
// validator has no constraint.
TEST(HTTP2ServerCoverageDeep, SettingsMaxHeaderListSizeIsAcceptedAndAcked) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    handshake_with_settings(server, io, {{Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE, 8192}});

    EXPECT_TRUE(server.ok());
    // The server answered the client SETTINGS with exactly one ACK (flags & ACK).
    std::size_t acks = 0;
    for (const auto &f : parse_emitted_frames(io.output)) {
        if (f.type == FrameType::SETTINGS && (f.flags & h2::FLAG_ACK)) {
            ++acks;
        }
    }
    EXPECT_EQ(acks, 1u);
    EXPECT_FALSE(output_has_frame(io.output, FrameType::GOAWAY));
}

// ===========================================================================
// Request `te` header value discrimination (RFC 9113 §8.2.2): only `trailers`.
// ===========================================================================

// `te: trailers` is the one allowed value -> the request is accepted/dispatched.
TEST(HTTP2ServerCoverageDeep, RequestTeTrailersIsAcceptedAndDispatched) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    handshake_default(server, io);

    push_request_headers(server, io, 1, request_with({{"te", "trailers"}}));

    EXPECT_TRUE(server.ok());
    EXPECT_EQ(io.request_count, 1);
    EXPECT_EQ(io.stream_error_count, 0);
}

// Any other `te` token (here `gzip`) is a forbidden connection-specific value ->
// PROTOCOL_ERROR stream error, request NOT dispatched, connection stays up.
TEST(HTTP2ServerCoverageDeep, RequestTeNonTrailersIsStreamProtocolError) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    handshake_default(server, io);

    const std::size_t before = io.output.size();
    push_request_headers(server, io, 1, request_with({{"te", "gzip"}}));

    EXPECT_TRUE(server.ok()); // stream-level error, connection survives
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
    EXPECT_NE(find_frame_offset(io.output, FrameType::RST_STREAM, before), SIZE_MAX);
}

// ===========================================================================
// Request content-length DECLARED above MAX_BODY_SIZE -> ENHANCE_YOUR_CALM.
// This validates the declared header value (a decimal string), not the actual
// body bytes, so it is reachable without a multi-MB allocation. ENHANCE_YOUR_CALM
// on the request path is not asserted anywhere else.
// ===========================================================================

TEST(HTTP2ServerCoverageDeep, RequestContentLengthOverMaxBodySizeIsEnhanceYourCalm) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    handshake_default(server, io);

    // 999999999999 (~1 TB) vastly exceeds MAX_BODY_SIZE (100 MiB). Open a POST so
    // the content-length is meaningful; END_HEADERS without END_STREAM keeps the
    // stream awaiting the (never-sent) body, but the declared-length guard fires
    // during header processing regardless.
    const auto encoded = encode_hpack_headers(
        {{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/upload"}, {"content-length", "999999999999"}});
    const std::size_t before = io.output.size();
    push_frame(io, FrameType::HEADERS, h2::FLAG_END_HEADERS, 1, encoded);
    drive(server, io);

    EXPECT_TRUE(server.ok()); // stream-level error
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::ENHANCE_YOUR_CALM);
    EXPECT_NE(find_frame_offset(io.output, FrameType::RST_STREAM, before), SIZE_MAX);
}

// ===========================================================================
// Trailers whose content-length contradicts the actually-delivered body ->
// PROTOCOL_ERROR. (The trailer-block content-length-mismatch arm.)
// ===========================================================================

TEST(HTTP2ServerCoverageDeep, TrailersContentLengthMismatchIsProtocolError) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    handshake_default(server, io);

    // POST declaring content-length 10, headers do NOT end the stream (trailers
    // announced so the request is not dispatched on the header block).
    const auto headers = encode_hpack_headers(
        {{":method", "POST"},
         {":scheme", "https"},
         {":authority", "example.test"},
         {":path", "/upload"},
         {"content-length", "10"},
         {"trailer", "x-done"}});
    push_frame(io, FrameType::HEADERS, h2::FLAG_END_HEADERS, 1, headers);
    drive(server, io);
    ASSERT_TRUE(server.ok());
    EXPECT_EQ(io.request_count, 0);

    // Only 3 body bytes (no END_STREAM) -> body (3) will not match declared (10).
    push_frame(io, FrameType::DATA, 0, 1, {'a', 'b', 'c'});
    drive(server, io);
    ASSERT_TRUE(server.ok());

    // Trailer HEADERS block carrying END_STREAM completes the stream; at trailer
    // processing the body length (3) != declared content-length (10).
    const auto        trailers = encode_hpack_headers({{"x-done", "yes"}});
    const std::size_t before   = io.output.size();
    push_frame(io, FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, 1, trailers);
    drive(server, io);

    EXPECT_TRUE(server.ok()); // stream-level error, connection survives
    EXPECT_EQ(io.request_count, 0) << "mismatched request must not dispatch";
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
    EXPECT_NE(find_frame_offset(io.output, FrameType::RST_STREAM, before), SIZE_MAX);
}

// ===========================================================================
// send_response invalid-state guard: RESERVED_LOCAL (a server-pushed stream that
// has not yet sent its response headers). Distinct from the unknown-stream and
// closed/half-closed-local arms covered elsewhere.
// ===========================================================================

TEST(HTTP2ServerCoverageDeep, SendResponseOnReservedLocalPushStreamIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    // Enable push so send_push_promise can create a RESERVED_LOCAL stream.
    push_preface(io);
    push_frame(io, FrameType::SETTINGS, 0, 0, encode_settings_payload({{Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 1}}));
    drive(server, io);
    ASSERT_TRUE(server.ok());

    // Open a client request stream that stays OPEN (POST, no END_STREAM) so it is
    // a valid associated stream for a PUSH_PROMISE.
    const auto parent = encode_hpack_headers({{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/parent"}});
    push_frame(io, FrameType::HEADERS, h2::FLAG_END_HEADERS, 1, parent);
    drive(server, io);
    ASSERT_TRUE(server.ok());

    // Promise stream 2 (even). It is created in RESERVED_LOCAL state.
    qb::http::Request promised{qb::io::uri{"https://example.test/asset.css"}};
    promised.method()  = qb::http::method::GET;
    const auto failure = server.send_push_promise(1, 2, std::move(promised));
    ASSERT_FALSE(failure.has_value()) << "PUSH_PROMISE should succeed when peer allows push";

    // Attempt to send a response on the RESERVED_LOCAL promised stream BEFORE its
    // headers were sent -> the IDLE/RESERVED_LOCAL guard rejects with PROTOCOL_ERROR.
    const std::size_t  before = io.output.size();
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    EXPECT_FALSE(server.send_response(2, response));
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
    // The stream-error path emits an RST_STREAM on the offending stream.
    EXPECT_NE(find_frame_offset(io.output, FrameType::RST_STREAM, before), SIZE_MAX);
}

// ===========================================================================
// send_response with a control byte in a response header VALUE -> PROTOCOL_ERROR.
// Response::set_header stores the value verbatim (no validation), so the byte
// survives to send_response's is_valid_header_field check, which runs BEFORE any
// HPACK encoding (the inbound HEADERS path can't reach this because the HPACK
// ENCODER would reject the control byte first).
// ===========================================================================

TEST(HTTP2ServerCoverageDeep, SendResponseWithControlByteInHeaderValueIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol server(io);
    handshake_default(server, io);

    // Open + dispatch a GET request so the stream is HALF_CLOSED_REMOTE (valid for
    // send_response).
    push_request_headers(server, io, 1, request_with({}));
    ASSERT_EQ(io.request_count, 1);
    const uint32_t sid = io.last_request_stream_id;

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    // 0x01 is a C0 control byte (< 0x20, not TAB) -> is_valid_header_value rejects.
    response.set_header("x-custom", std::string("bad\x01value"));

    const std::size_t before = io.output.size();
    EXPECT_FALSE(server.send_response(sid, response));
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
    EXPECT_NE(find_frame_offset(io.output, FrameType::RST_STREAM, before), SIZE_MAX);
}

// ===========================================================================
// GOAWAY received: the dispatched event carries the peer's last_stream_id and
// debug_data verbatim (fields the canonical harness sink drops). A local rich
// sink captures them.
// ===========================================================================

TEST(HTTP2ServerCoverageDeep, ReceivedGoawayEventCarriesLastStreamIdAndDebugData) {
    RichServerIO       io;
    RichServerProtocol server(io);
    do_handshake(server, io);
    ASSERT_TRUE(server.ok());

    // Build a GOAWAY payload: 4-byte last_stream_id (7), 4-byte error code
    // (ENHANCE_YOUR_CALM == 11), then the debug bytes.
    const std::string    debug   = "bye-now";
    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x07,  // last_stream_id = 7
                                    0x00, 0x00, 0x00, 0x0B}; // error_code = ENHANCE_YOUR_CALM (11)
    payload.insert(payload.end(), debug.begin(), debug.end());
    push_frame(io, FrameType::GOAWAY, 0, 0, payload);
    drive(server, io);

    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, ErrorCode::ENHANCE_YOUR_CALM);
    EXPECT_EQ(io.last_goaway_last_id, 7u);
    EXPECT_EQ(io.last_goaway_debug, debug);
}

// A second GOAWAY arriving once the server has already begun shutdown (it is
// !ok() after a connection error and graceful_shutdown was flagged by the first
// GOAWAY) is ignored: the event is NOT dispatched a second time.
TEST(HTTP2ServerCoverageDeep, SecondGoawayWhileShuttingDownIsIgnored) {
    RichServerIO       io;
    RichServerProtocol server(io);
    do_handshake(server, io);
    ASSERT_TRUE(server.ok());

    // First GOAWAY (graceful, NO_ERROR) flags graceful shutdown and dispatches once.
    h2::Http2FrameData<h2::GoAwayFrame> first;
    first.header.type = static_cast<uint8_t>(FrameType::GOAWAY);
    first.header.set_stream_id(0);
    first.payload.last_stream_id = 0;
    first.payload.error_code     = ErrorCode::NO_ERROR;
    server.on(std::move(first));
    EXPECT_EQ(io.goaway_count, 1);

    // Force the protocol into a not-ok state so the early-return guard
    // (!ok() && graceful_shutdown_initiated) is satisfied.
    push_frame(io, FrameType::DATA, 0, 0, {'x'}); // DATA on stream 0 -> connection error
    drive(server, io);
    EXPECT_FALSE(server.ok());
    const int goaways_after_error = io.goaway_count;

    // A second received GOAWAY now hits the early-return guard and is NOT
    // dispatched again.
    h2::Http2FrameData<h2::GoAwayFrame> second;
    second.header.type = static_cast<uint8_t>(FrameType::GOAWAY);
    second.header.set_stream_id(0);
    second.payload.last_stream_id = 0;
    second.payload.error_code     = ErrorCode::NO_ERROR;
    server.on(std::move(second));
    EXPECT_EQ(io.goaway_count, goaways_after_error) << "GOAWAY while shutting down must not re-dispatch";
}

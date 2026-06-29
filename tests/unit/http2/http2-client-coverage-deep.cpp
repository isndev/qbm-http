/**
 * @file qbm/http/tests/unit/http2/http2-client-coverage-deep.cpp
 * @brief Deep client-side HTTP/2 protocol coverage: branches the existing
 *        client-protocol / client-validation / roundtrip files leave unexercised.
 *
 * `http2-client-protocol.cpp` and `http2-client-validation.cpp` are extensive on
 * inbound-frame handling and request emission; `http2-protocol-roundtrip.cpp`
 * drives the connected client<->server cycle. This file targets the REACHABLE
 * `ClientHttp2Protocol` branches still missing, each asserting a concrete
 * outcome (RST_STREAM / GOAWAY / dispatched event / ErrorCode / send_request
 * acceptance):
 *
 *   - response :status validation arms NOT yet hit (validate_response_pseudo_headers,
 *     which runs before the per-field loop): duplicate :status, :status whose
 *     length != 3, non-digit :status, and a non-:status pseudo-header in a
 *     response -> all PROTOCOL_ERROR RST.
 *   - a second main HEADERS block on an OPEN stream that is NOT trailers ->
 *     PROTOCOL_ERROR RST ("Multiple HEADERS frames not as trailers").
 *   - a DATA frame on a stream that is HALF_CLOSED_REMOTE (response already
 *     received with END_STREAM, but the client has not finished its request, so
 *     the stream is still resident) -> STREAM_CLOSED RST ("DATA in invalid state").
 *   - an incoming PING that ALREADY carries the ACK flag is consumed silently:
 *     the client does NOT answer it (only PING requests get a PONG).
 *   - SETTINGS_MAX_CONCURRENT_STREAMS lowered by the server is enforced: once the
 *     active-stream budget is reached, the next send_request is rejected.
 *   - a graceful GOAWAY (NO_ERROR) that names a still-open stream keeps the client
 *     ok() with shutdown pending, and the dispatched Http2GoAwayEvent carries the
 *     peer's last_stream_id and debug_data (the canonical sink drops both; a local
 *     rich sink captures them).
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
#include <vector>

#include "../../shared/http2_fake_io.h"

using namespace qb::http::test;

using qb::protocol::http2::ErrorCode;
using qb::protocol::http2::FrameType;
using qb::protocol::http2::Http2SettingIdentifier;

namespace {

namespace h2 = qb::protocol::http2;

using ClientProtocol = h2::ClientHttp2Protocol<Http2ClientFakeIO>;

// Open client stream 1 by issuing a GET; the request emits HEADERS+END_STREAM so
// the stream becomes HALF_CLOSED_LOCAL and is ready to receive a response.
void
open_get_stream(ClientProtocol &protocol, uint64_t app_id, const char *path) {
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri(std::string("https://example.test") + path);
    ASSERT_TRUE(protocol.send_request(std::move(req), app_id));
}

// A server-SETTINGS Http2FrameData (not an ACK) with the given entries.
[[nodiscard]] h2::Http2FrameData<h2::SettingsFrame>
make_server_settings(std::initializer_list<std::pair<Http2SettingIdentifier, uint32_t>> entries) {
    h2::Http2FrameData<h2::SettingsFrame> frame;
    frame.header.type  = static_cast<uint8_t>(FrameType::SETTINGS);
    frame.header.flags = 0;
    frame.header.set_stream_id(0);
    for (const auto &e : entries) {
        frame.payload.entries.push_back({e.first, e.second});
    }
    return frame;
}

// A client-facing rich sink that captures the FULL GOAWAY event (the canonical
// Http2ClientFakeIO drops last_stream_id and debug_data). Mirrors the client IO
// contract otherwise.
struct RichClientIO {
    using base_io_t = RichClientIO;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;

    int         response_count      = 0;
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
    RichClientIO &
    operator<<(const Frame &frame) {
        output.put(frame);
        return *this;
    }

    void
    on(qb::http::Response &&, uint64_t) {
        ++response_count;
    }
    void
    on(qb::http::Response &&, uint64_t, ErrorCode) {
        ++response_count;
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

using RichClientProtocol = h2::ClientHttp2Protocol<RichClientIO>;

} // namespace

// ===========================================================================
// Response :status validation arms (HeaderValidator::validate_response_pseudo_headers
// runs before the per-field loop). Each is a distinct PROTOCOL_ERROR RST.
// ===========================================================================

TEST(HTTP2ClientCoverageDeep, DuplicateStatusPseudoHeaderRstsStream) {
    Http2ClientFakeIO io;
    ClientProtocol    protocol(io);
    open_get_stream(protocol, 11, "/dup");

    const std::size_t before = io.output.size();
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {":status", "204"}}));

    EXPECT_TRUE(protocol.ok()); // stream-level error
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
    EXPECT_NE(find_frame_offset(io.output, FrameType::RST_STREAM, before), SIZE_MAX);
}

TEST(HTTP2ClientCoverageDeep, StatusWithWrongLengthRstsStream) {
    Http2ClientFakeIO io;
    ClientProtocol    protocol(io);
    open_get_stream(protocol, 12, "/len");

    const std::size_t before = io.output.size();
    // ":status" must be exactly 3 octets; "20" (length 2) is rejected.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "20"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
    EXPECT_NE(find_frame_offset(io.output, FrameType::RST_STREAM, before), SIZE_MAX);
}

TEST(HTTP2ClientCoverageDeep, NonDigitStatusRstsStream) {
    Http2ClientFakeIO io;
    ClientProtocol    protocol(io);
    open_get_stream(protocol, 13, "/digit");

    const std::size_t before = io.output.size();
    // 3 octets but not all digits.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "2x0"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
    EXPECT_NE(find_frame_offset(io.output, FrameType::RST_STREAM, before), SIZE_MAX);
}

TEST(HTTP2ClientCoverageDeep, NonStatusPseudoHeaderInResponseRstsStream) {
    Http2ClientFakeIO io;
    ClientProtocol    protocol(io);
    open_get_stream(protocol, 14, "/badpseudo");

    const std::size_t before = io.output.size();
    // A request pseudo-header (:method) is invalid in a response section.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {":method", "GET"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
    EXPECT_NE(find_frame_offset(io.output, FrameType::RST_STREAM, before), SIZE_MAX);
}

// ===========================================================================
// A second main HEADERS block on an OPEN stream that is NOT a trailer block
// (no trailers announced, first block had no END_STREAM) -> PROTOCOL_ERROR RST.
// ===========================================================================

TEST(HTTP2ClientCoverageDeep, SecondMainHeadersNotAsTrailersRstsStream) {
    Http2ClientFakeIO io;
    ClientProtocol    protocol(io);
    open_get_stream(protocol, 21, "/twice");

    // First response HEADERS block: status 200, NO END_STREAM, no trailer
    // announce -> headers_received_main = true, stream stays OPEN.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    ASSERT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0) << "response is not complete without END_STREAM";

    // A SECOND main HEADERS block (still no END_STREAM) is neither informational
    // nor trailers -> "Multiple HEADERS frames not as trailers".
    const std::size_t before = io.output.size();
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
    EXPECT_NE(find_frame_offset(io.output, FrameType::RST_STREAM, before), SIZE_MAX);
}

// ===========================================================================
// DATA on a HALF_CLOSED_REMOTE (but still-resident) stream -> STREAM_CLOSED RST.
// To keep the stream resident after the response END_STREAM, the client request
// must NOT have sent END_STREAM yet (so the stream is not erased on response
// completion). A request that ANNOUNCES trailers defers END_STREAM, leaving the
// stream OPEN; the response HEADERS+END_STREAM then moves it to HALF_CLOSED_REMOTE.
// ===========================================================================

TEST(HTTP2ClientCoverageDeep, DataOnHalfClosedRemoteResidentStreamIsStreamClosedRst) {
    Http2ClientFakeIO io;
    ClientProtocol    protocol(io);

    // POST announcing trailers via the `trailer` header: the client sends HEADERS
    // (+ optional DATA) WITHOUT END_STREAM, leaving stream 1 OPEN awaiting the
    // trailer block the application would send later.
    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/upload");
    req.body()   = "payload";
    req.set_header("trailer", "x-checksum");
    ASSERT_TRUE(protocol.send_request(std::move(req), /*app_id=*/31));

    // Server response completes the response half: HEADERS + END_STREAM. The
    // client's stream was OPEN (no END_STREAM sent) -> it transitions to
    // HALF_CLOSED_REMOTE and, because the client side is not closed, stays resident.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "200"}}));
    ASSERT_TRUE(protocol.ok());

    // A follow-up DATA frame on that HALF_CLOSED_REMOTE stream is invalid (the
    // peer already ended the stream) -> STREAM_CLOSED RST.
    const std::size_t before = io.output.size();
    protocol.on(make_data_frame(1, 0, "late-bytes"));

    EXPECT_TRUE(protocol.ok()); // stream-level, connection survives
    EXPECT_NE(find_frame_offset(io.output, FrameType::RST_STREAM, before), SIZE_MAX);
}

// ===========================================================================
// An incoming PING that already carries the ACK flag is consumed silently: the
// client only answers PING *requests* (ACK clear). Complements the covered
// PingRequestIsAnsweredWithAck case.
// ===========================================================================

TEST(HTTP2ClientCoverageDeep, IncomingPingAckIsNotAnswered) {
    Http2ClientFakeIO io;
    ClientProtocol    protocol(io);

    const std::size_t before = io.output.size();
    // PING with the ACK flag set and an 8-octet opaque payload.
    const std::vector<uint8_t> opaque = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    push_frame(io, FrameType::PING, h2::FLAG_ACK, 0, opaque);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    // No PING frame (PONG) was emitted in response to a PING ACK.
    EXPECT_EQ(find_frame_offset(io.output, FrameType::PING, before), SIZE_MAX) << "client must not answer an incoming PING ACK";
}

// ===========================================================================
// SETTINGS_MAX_CONCURRENT_STREAMS lowered by the server is enforced by
// send_request: once the active-stream budget is reached the next request is
// rejected (returns false) without emitting a new HEADERS frame.
// ===========================================================================

TEST(HTTP2ClientCoverageDeep, MaxConcurrentStreamsLimitRejectsOverflowRequest) {
    Http2ClientFakeIO io;
    ClientProtocol    protocol(io);

    // Server lowers the client's concurrent-stream budget to 1.
    protocol.on(make_server_settings({{Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS, 1}}));
    ASSERT_TRUE(protocol.ok());

    // First request consumes the single allowed concurrent stream.
    qb::http::Request first;
    first.method() = qb::http::method::GET;
    first.uri()    = qb::io::uri("https://example.test/a");
    EXPECT_TRUE(protocol.send_request(std::move(first), 1));

    const std::size_t after_first = io.output.size();

    // Second request would exceed MAX_CONCURRENT_STREAMS (1) -> rejected.
    qb::http::Request second;
    second.method() = qb::http::method::GET;
    second.uri()    = qb::io::uri("https://example.test/b");
    EXPECT_FALSE(protocol.send_request(std::move(second), 2)) << "request past MAX_CONCURRENT_STREAMS must be rejected";

    // No additional HEADERS frame was emitted for the rejected request.
    EXPECT_EQ(find_frame_offset(io.output, FrameType::HEADERS, after_first), SIZE_MAX);
}

// ===========================================================================
// Graceful GOAWAY (NO_ERROR) naming a still-open stream: the client stays ok()
// with shutdown pending, and the dispatched event carries the peer's
// last_stream_id and debug_data verbatim (captured by a rich sink).
// ===========================================================================

TEST(HTTP2ClientCoverageDeep, GracefulGoawayWithOpenStreamStaysOkAndCarriesFields) {
    RichClientIO       io;
    RichClientProtocol protocol(io);

    // Open a stream that stays in-flight (no response yet) so it is "relevant".
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/inflight");
    ASSERT_TRUE(protocol.send_request(std::move(req), /*app_id=*/41));

    // Graceful GOAWAY(NO_ERROR) whose last_stream_id (1) covers the open stream,
    // with debug data. Because a relevant stream is still open, the client marks
    // shutdown pending but does NOT go not-ok.
    h2::Http2FrameData<h2::GoAwayFrame> goaway;
    goaway.header.type = static_cast<uint8_t>(FrameType::GOAWAY);
    goaway.header.set_stream_id(0);
    goaway.payload.last_stream_id = 1;
    goaway.payload.error_code     = ErrorCode::NO_ERROR;
    const std::string debug       = "draining";
    goaway.payload.additional_debug_data.assign(debug.begin(), debug.end());
    protocol.on(std::move(goaway));

    EXPECT_TRUE(protocol.ok()) << "graceful GOAWAY with an open relevant stream keeps the connection ok";
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, ErrorCode::NO_ERROR);
    EXPECT_EQ(io.last_goaway_last_id, 1u);
    EXPECT_EQ(io.last_goaway_debug, debug);
}

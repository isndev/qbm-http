/**
 * @file qbm/http/tests/unit/http2/http2-protocol-state.cpp
 * @brief Unit tests for the HTTP/2 server & client protocol state machine and
 *        the underlying framer error paths.
 *
 * Framer / state-machine half split out of the legacy
 * test-http2-header-validator.cpp (spec §3 D7). Drives real
 * ServerHttp2Protocol / ClientHttp2Protocol instances over the shared socket-less
 * FakeIO harness (qb::http::test::Http2FakeIO / Http2ClientFakeIO). Covers:
 *   - idle-stream rejections (DATA / RST_STREAM / WINDOW_UPDATE on a never-opened
 *     stream are connection PROTOCOL_ERRORs),
 *   - request/response content-length mismatch handling,
 *   - missing/empty :authority stream resets,
 *   - PUSH_PROMISE validation failures,
 *   - graceful GOAWAY keeping accepted streams alive,
 *   - the padded+priority HEADERS length-underflow FRAME_SIZE_ERROR regression
 *     (driven over the wire), and
 *   - the throwing-request-handler containment regression — now asserting that a
 *     RST_STREAM(INTERNAL_ERROR) is emitted and the connection survives.
 *
 * Pure logic, deterministic, parallel-safe (tier:unit; un-gated from SSL).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

#include "../../shared/http2_fake_io.h"

using qb::http::test::Http2ClientFakeIO;
using qb::http::test::Http2FakeIO;
using qb::http::test::drive;
using qb::http::test::encode_hpack_headers;
using qb::http::test::find_frame_offset;
using qb::http::test::peek_frame_header;
using qb::http::test::push_bytes;
using qb::http::test::push_preface;

namespace h2 = qb::protocol::http2;

// ===========================================================================
// Server: frames on an IDLE (never-opened) stream are connection errors.
// ===========================================================================
TEST(HTTP2ServerProtocol, RejectsDataOnIdleStreamAsConnectionError) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    h2::Http2FrameData<h2::DataFrame> data;
    data.header.type  = static_cast<uint8_t>(h2::FrameType::DATA);
    data.header.flags = h2::FLAG_END_STREAM;
    data.header.set_stream_id(1);
    data.payload.data_payload = {'x'};

    protocol.on(std::move(data));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, RejectsRstStreamOnIdleStreamAsConnectionError) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(1);
    rst.payload.error_code = h2::ErrorCode::CANCEL;

    protocol.on(std::move(rst));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, RejectsWindowUpdateOnIdleStreamAsConnectionError) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    h2::Http2FrameData<h2::WindowUpdateFrame> window_update;
    window_update.header.type = static_cast<uint8_t>(h2::FrameType::WINDOW_UPDATE);
    window_update.header.set_stream_id(1);
    window_update.payload.window_size_increment = 1;

    protocol.on(std::move(window_update));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// Server: a request body shorter than its declared content-length resets the
// stream (PROTOCOL_ERROR) but keeps the connection.
// ===========================================================================
TEST(HTTP2ServerProtocol, RejectsRequestBodyShorterThanContentLengthOnDataEndStream) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    h2::Http2FrameData<h2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    headers.header.flags = h2::FLAG_END_HEADERS;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers(
        {{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/mismatch"}, {"content-length", "5"}});

    protocol.on(std::move(headers));
    ASSERT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);

    h2::Http2FrameData<h2::DataFrame> data;
    data.header.type  = static_cast<uint8_t>(h2::FrameType::DATA);
    data.header.flags = h2::FLAG_END_STREAM;
    data.header.set_stream_id(1);
    data.payload.data_payload = {'a', 'b', 'c'};

    protocol.on(std::move(data));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// Server: a padded DATA frame counts the Pad Length octet + Padding against flow
// control (RFC 9113 §6.1), not just the de-padded application bytes. A frame whose
// FULL payload exceeds the connection receive window is a FLOW_CONTROL_ERROR even
// when its de-padded data alone would fit. (Regression: the accounting previously
// used only data_payload.size(), under-debiting by 1 + pad_length per frame — a
// ~256x flow-control amplification that defeats receive-side backpressure.)
// ===========================================================================
TEST(HTTP2ServerProtocol, PaddedDataFrameCountsPaddingAgainstFlowControl) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    h2::Http2FrameData<h2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    headers.header.flags = h2::FLAG_END_HEADERS;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers(
        {{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/padded"}});
    protocol.on(std::move(headers));
    ASSERT_TRUE(protocol.ok());

    // Tiny application data, but the padding pushes the full frame payload past the
    // 65535-byte initial connection receive window.
    h2::Http2FrameData<h2::DataFrame> data;
    data.header.type = static_cast<uint8_t>(h2::FrameType::DATA);
    data.header.set_stream_id(1);
    data.payload.data_payload = {'a', 'b', 'c'};
    data.payload.padding_size = 70000; // 3 + 70000 > 65535 -> connection flow-control error
    protocol.on(std::move(data));

    EXPECT_FALSE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::FLOW_CONTROL_ERROR);
}

// ===========================================================================
// Server: an outgoing response whose body length disagrees with its declared
// content-length is rejected with a stream error.
// ===========================================================================
TEST(HTTP2ServerProtocol, RejectsOutgoingResponseContentLengthMismatch) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    h2::Http2FrameData<h2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    headers.header.flags = h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment =
        encode_hpack_headers({{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/mismatch"}});

    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "abc";
    response.set_header("content-length", "5");

    EXPECT_FALSE(protocol.send_response(1, response));
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// Server: a HEAD response may carry content-length metadata with an empty body.
// ===========================================================================
TEST(HTTP2ServerProtocol, AllowsHeadResponseContentLengthMetadata) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    h2::Http2FrameData<h2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    headers.header.flags = h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment =
        encode_hpack_headers({{":method", "HEAD"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/head"}});

    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("content-length", "123");

    EXPECT_TRUE(protocol.send_response(1, response));
    EXPECT_EQ(io.stream_error_count, 0);
}

// ===========================================================================
// Server: a request missing or with an empty :authority resets the stream.
// ===========================================================================
TEST(HTTP2ServerProtocol, RejectsRequestMissingAuthorityPseudoHeader) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    h2::Http2FrameData<h2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    headers.header.flags = h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers({{":method", "GET"}, {":scheme", "https"}, {":path", "/missing-authority"}});

    protocol.on(std::move(headers));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, RejectsRequestEmptyAuthorityPseudoHeader) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    h2::Http2FrameData<h2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    headers.header.flags = h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment =
        encode_hpack_headers({{":method", "GET"}, {":scheme", "https"}, {":authority", ""}, {":path", "/empty-authority"}});

    protocol.on(std::move(headers));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// Server PUSH_PROMISE validation: an odd (invalid) promised stream id and a
// promised request missing :authority are both rejected up-front.
// ===========================================================================
TEST(HTTP2ServerProtocol, PushPromiseRejectsInvalidPromisedStreamId) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    h2::Http2FrameData<h2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    headers.header.flags = h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment =
        encode_hpack_headers({{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/parent"}});
    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    qb::http::Request promised{qb::io::uri{"https://example.test/asset"}};
    promised.method() = qb::http::method::GET;

    auto failure = protocol.send_push_promise(1, 3, std::move(promised));
    ASSERT_TRUE(failure.has_value());
    EXPECT_EQ(*failure, h2::PushPromiseFailureReason::INVALID_PROMISED_STREAM);
}

TEST(HTTP2ServerProtocol, PushPromiseRejectsMissingPromisedAuthority) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    h2::Http2FrameData<h2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    headers.header.flags = h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment =
        encode_hpack_headers({{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/parent"}});
    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    qb::http::Request promised{qb::io::uri{"/asset"}};
    promised.method() = qb::http::method::GET;

    auto failure = protocol.send_push_promise(1, 2, std::move(promised));
    ASSERT_TRUE(failure.has_value());
    EXPECT_EQ(*failure, h2::PushPromiseFailureReason::INVALID_PROMISED_REQUEST);
}

// ===========================================================================
// Client: a graceful GOAWAY keeps already-accepted streams alive (no response
// is forced and the connection stays ok).
// ===========================================================================
TEST(HTTP2ClientProtocol, GracefulGoawayKeepsAcceptedStreamsAlive) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request first;
    first.method() = qb::http::method::GET;
    first.uri()    = qb::io::uri("https://example.test/first");

    qb::http::Request second;
    second.method() = qb::http::method::GET;
    second.uri()    = qb::io::uri("https://example.test/second");

    ASSERT_TRUE(protocol.send_request(std::move(first), 1));
    ASSERT_TRUE(protocol.send_request(std::move(second), 2));
    ASSERT_EQ(protocol.last_initiated_stream_id(), 3u);

    h2::Http2FrameData<h2::GoAwayFrame> goaway;
    goaway.header.type = static_cast<uint8_t>(h2::FrameType::GOAWAY);
    goaway.header.set_stream_id(0);
    goaway.payload.last_stream_id = 1;
    goaway.payload.error_code     = h2::ErrorCode::NO_ERROR;

    protocol.on(std::move(goaway));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::NO_ERROR);
    EXPECT_EQ(io.response_count, 0);
}

// ===========================================================================
// Client: frames on an IDLE (never-initiated) client stream are connection
// errors.
// ===========================================================================
TEST(HTTP2ClientProtocol, RejectsRstStreamOnIdleClientStreamAsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(1);
    rst.payload.error_code = h2::ErrorCode::CANCEL;

    protocol.on(std::move(rst));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ClientProtocol, RejectsHeadersOnIdleClientStreamAsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    h2::Http2FrameData<h2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    headers.header.flags = h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers({{":status", "200"}});

    protocol.on(std::move(headers));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ClientProtocol, RejectsWindowUpdateOnIdleClientStreamAsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    h2::Http2FrameData<h2::WindowUpdateFrame> window_update;
    window_update.header.type = static_cast<uint8_t>(h2::FrameType::WINDOW_UPDATE);
    window_update.header.set_stream_id(1);
    window_update.payload.window_size_increment = 1;

    protocol.on(std::move(window_update));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// REGRESSION (framer): a HEADERS frame with FLAG_PADDED|FLAG_PRIORITY whose
// declared length is exactly the prefix size (1 pad-length + 5 priority bytes)
// made the header-block size (p_len - pad_length) underflow to SIZE_MAX and drive
// an out-of-bounds read in assign(). The framer must reject it as a
// FRAME_SIZE_ERROR. Driven over the wire because the bug lives in
// handle_headers_frame_payload, not in on(HeadersFrame).
// ===========================================================================
TEST(HTTP2ServerProtocol, PaddedPriorityHeadersLengthUnderflowIsRejected) {
    Http2FakeIO                          io;
    h2::ServerHttp2Protocol<Http2FakeIO> protocol(io);

    push_preface(io);

    h2::FrameHeader fh{};
    fh.set_payload_length(6);
    fh.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    fh.flags = h2::FLAG_PADDED | h2::FLAG_PRIORITY;
    fh.set_stream_id(1);
    push_bytes(io, &fh, sizeof(fh));

    // pad_length = 1, then the 5 priority bytes; nothing left for the declared
    // padding byte or any header block — the malformed part.
    const std::uint8_t payload[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    push_bytes(io, payload, sizeof(payload));

    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::FRAME_SIZE_ERROR);
    EXPECT_EQ(io.request_count, 0);
}

namespace {

// Server harness whose request sink throws, to exercise the dispatch-boundary
// try/catch. Satisfies the full server IO contract (request + event sinks).
struct ThrowingRequestHarness {
    using base_io_t = ThrowingRequestHarness;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;
    bool                      handler_invoked    = false;
    int                       stream_error_count = 0;
    int                       goaway_count       = 0;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    qb::allocator::pipe<char> &
    out() noexcept {
        return output;
    }

    template <typename Frame>
    ThrowingRequestHarness &
    operator<<(const Frame &frame) {
        output.put(frame);
        return *this;
    }

    void
    on(qb::http::Request &&, uint32_t) {
        handler_invoked = true;
        throw std::runtime_error("request handler boom");
    }
    void
    on(const h2::Http2StreamErrorEvent &) {
        ++stream_error_count;
    }
    void
    on(const h2::Http2GoAwayEvent &) {
        ++goaway_count;
    }
    void
    on(const h2::Http2PushPromiseEvent &) {}
};

} // namespace

// ===========================================================================
// REGRESSION: an HTTP/2 request handler runs synchronously from the noexcept
// frame-dispatch chain (on(HeadersFrame) -> dispatch_complete_request ->
// _io.on(request)). A throwing handler used to escape that noexcept boundary and
// call std::terminate. The protocol must instead reset the offending stream with
// RST_STREAM(INTERNAL_ERROR) and keep the connection alive.
// ===========================================================================
TEST(HTTP2ServerProtocol, ThrowingRequestHandlerEmitsRstStreamAndSurvives) {
    ThrowingRequestHarness                          io;
    h2::ServerHttp2Protocol<ThrowingRequestHarness> protocol(io);

    qb::http::test::push_preface(io);

    const auto encoded = encode_hpack_headers({
        {":method", "GET"},
        {":path", "/"},
        {":scheme", "https"},
        {":authority", "example.com"},
    });

    h2::FrameHeader fh{};
    fh.set_payload_length(static_cast<uint32_t>(encoded.size()));
    fh.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    fh.flags = h2::FLAG_END_STREAM | h2::FLAG_END_HEADERS;
    fh.set_stream_id(1);
    push_bytes(io, &fh, sizeof(fh));
    push_bytes(io, encoded.data(), encoded.size());

    drive(protocol, io);

    // The handler was reached and threw; the dispatch-boundary catch reset the
    // stream instead of terminating, and the connection is still alive.
    EXPECT_TRUE(io.handler_invoked);
    EXPECT_TRUE(protocol.ok());

    // A RST_STREAM(INTERNAL_ERROR) for stream 1 must have been emitted.
    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, 0);
    ASSERT_NE(rst_off, SIZE_MAX) << "no RST_STREAM emitted for the thrown handler";
    const auto rst_fh = peek_frame_header(io.output, rst_off);
    EXPECT_EQ(rst_fh.get_stream_id(), 1u);
    const auto *p = reinterpret_cast<const uint8_t *>(io.output.cbegin() + rst_off + h2::FRAME_HEADER_SIZE);
    const uint32_t err = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | p[3];
    EXPECT_EQ(static_cast<h2::ErrorCode>(err), h2::ErrorCode::INTERNAL_ERROR);
    EXPECT_EQ(io.goaway_count, 0); // Connection survives; no GOAWAY.
}

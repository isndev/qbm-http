/**
 * @file qbm/http/tests/test-http2-server-protocol.cpp
 * @brief Unit tests driving ServerHttp2Protocol over a fake (socket-less) IO.
 *
 * These tests exercise the HTTP/2 server framer (qbm/http/2/protocol/base.h)
 * and the server protocol state machine (qbm/http/2/protocol/server.h) by
 * feeding raw wire bytes (preface + frames) into the parser and/or invoking
 * the typed on(Http2FrameData<T>) handlers directly. No real socket is used:
 * a FakeIO harness owns two pipes (input/output) and counts the application
 * callbacks. Emitted frames are inspected by parsing the 9-byte FrameHeader
 * sequence the serializers write into io.output.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

#include "../2/protocol/base.h"
#include "../2/protocol/server.h"

namespace {

// ---------------------------------------------------------------------------
// FakeIO harness: a socket-less IO_Handler. Mirrors the harness used by
// test-http2-header-validator.cpp but adds an Http2PushPromiseEvent sink to
// satisfy the full IO contract requested for the server.
// ---------------------------------------------------------------------------
struct Http2ServerHarness {
    using base_io_t = Http2ServerHarness;

    qb::allocator::pipe<char>      input;
    qb::allocator::pipe<char>      output;
    int                            request_count      = 0;
    int                            stream_error_count = 0;
    int                            goaway_count       = 0;
    int                            push_promise_count = 0;
    qb::protocol::http2::ErrorCode last_stream_error  = qb::protocol::http2::ErrorCode::NO_ERROR;
    qb::protocol::http2::ErrorCode last_goaway_error  = qb::protocol::http2::ErrorCode::NO_ERROR;

    // Last request seen by on(Request&&, stream_id). Captured so individual
    // tests can assert parsed fields without re-deriving them.
    std::optional<qb::http::Request> last_request;
    uint32_t                         last_request_stream_id = 0;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    qb::allocator::pipe<char> &
    out() noexcept {
        return output;
    }

    template <typename Frame>
    Http2ServerHarness &
    operator<<(const Frame &frame) {
        output.put(frame);
        return *this;
    }

    void
    on(qb::http::Request &&request, uint32_t stream_id) {
        ++request_count;
        last_request_stream_id = stream_id;
        last_request           = std::move(request);
    }

    void
    on(const qb::protocol::http2::Http2StreamErrorEvent &event) {
        ++stream_error_count;
        last_stream_error = event.error_code;
    }

    void
    on(const qb::protocol::http2::Http2GoAwayEvent &event) {
        ++goaway_count;
        last_goaway_error = event.error_code;
    }

    void
    on(const qb::protocol::http2::Http2PushPromiseEvent & /*event*/) {
        ++push_promise_count;
    }
};

using qb::protocol::http2::ErrorCode;
using qb::protocol::http2::FrameHeader;
using qb::protocol::http2::FrameType;
using ServerProtocol = qb::protocol::http2::ServerHttp2Protocol<Http2ServerHarness>;

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

[[nodiscard]] std::vector<uint8_t>
encode_hpack_headers(const std::vector<qb::protocol::hpack::HeaderField> &headers) {
    qb::protocol::hpack::Encoder encoder;
    std::vector<uint8_t>         encoded;
    EXPECT_TRUE(encoder.encode(headers, encoded));
    return encoded;
}

// Append raw bytes to the protocol's input pipe.
void
push_bytes(Http2ServerHarness &io, const void *p, std::size_t n) {
    std::memcpy(io.input.allocate_back(n), p, n);
}

void
push_preface(Http2ServerHarness &io) {
    push_bytes(io, HTTP2_CONNECTION_PREFACE.data(), HTTP2_CONNECTION_PREFACE.size());
}

// Append a full frame (9-byte header with given length/type/flags/stream + payload).
void
push_frame(Http2ServerHarness &io, FrameType type, uint8_t flags, uint32_t stream_id, const std::vector<uint8_t> &payload) {
    FrameHeader fh{};
    fh.set_payload_length(static_cast<uint32_t>(payload.size()));
    fh.type  = static_cast<uint8_t>(type);
    fh.flags = flags;
    fh.set_stream_id(stream_id);
    push_bytes(io, &fh, sizeof(fh));
    if (!payload.empty()) {
        push_bytes(io, payload.data(), payload.size());
    }
}

// Drive the framer until it cannot consume more (the exact idiom used by the
// existing header-validator regression tests).
void
drive(ServerProtocol &protocol, Http2ServerHarness &io) {
    std::size_t sz = 0;
    while ((sz = protocol.getMessageSize()) > 0) {
        protocol.onMessage(sz);
        io.input.free_front(sz);
        if (!protocol.ok()) {
            break;
        }
    }
}

// A parsed view of an emitted frame from io.output.
struct EmittedFrame {
    FrameType type;
    uint8_t   flags;
    uint32_t  stream_id;
    uint32_t  payload_length;
};

// Walk io.output as a sequence of [FrameHeader][payload]. Every server frame
// serializer writes a 9-byte FrameHeader with the recomputed payload length,
// so the output is self-describing.
[[nodiscard]] std::vector<EmittedFrame>
parse_emitted_frames(const qb::allocator::pipe<char> &output) {
    std::vector<EmittedFrame> frames;
    const char               *data = output.cbegin();
    const std::size_t         size = output.size();
    std::size_t               off  = 0;
    while (off + qb::protocol::http2::FRAME_HEADER_SIZE <= size) {
        FrameHeader fh{};
        std::memcpy(&fh, data + off, qb::protocol::http2::FRAME_HEADER_SIZE);
        const uint32_t plen = fh.get_payload_length();
        frames.push_back({fh.get_type(), fh.flags, fh.get_stream_id(), plen});
        off += qb::protocol::http2::FRAME_HEADER_SIZE + plen;
    }
    return frames;
}

[[nodiscard]] bool
output_has_frame(const qb::allocator::pipe<char> &output, FrameType type) {
    for (const auto &f : parse_emitted_frames(output)) {
        if (f.type == type) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] std::size_t
count_output_frames(const qb::allocator::pipe<char> &output, FrameType type) {
    std::size_t n = 0;
    for (const auto &f : parse_emitted_frames(output)) {
        if (f.type == type) {
            ++n;
        }
    }
    return n;
}

// Standard valid request pseudo-header set.
std::vector<qb::protocol::hpack::HeaderField>
default_request_headers(const std::string &path = "/") {
    return {{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", path}};
}

// Drive preface + an empty client SETTINGS so the server is in a normal,
// post-handshake state with a valid open request. Returns nothing; assertions
// live in each test.
void
do_handshake(ServerProtocol &protocol, Http2ServerHarness &io) {
    push_preface(io);
    push_frame(io, FrameType::SETTINGS, 0, 0, {});
    drive(protocol, io);
}

} // namespace

// ===========================================================================
// Preface + SETTINGS handshake
// ===========================================================================

TEST(HTTP2ServerProtocol, PrefaceTriggersServerSettingsAndAck) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);

    push_preface(io);
    push_frame(io, FrameType::SETTINGS, 0, 0, {}); // empty client SETTINGS (not ACK)
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    // PrefaceCompleteEvent makes the server emit its own SETTINGS; processing
    // the client SETTINGS makes it emit a SETTINGS ACK. Both are SETTINGS
    // frames on stream 0 -> at least two SETTINGS frames, one of them an ACK.
    const auto  frames         = parse_emitted_frames(io.output);
    std::size_t settings_total = 0;
    std::size_t settings_ack   = 0;
    for (const auto &f : frames) {
        if (f.type == FrameType::SETTINGS) {
            ++settings_total;
            if (f.flags & qb::protocol::http2::FLAG_ACK) {
                ++settings_ack;
            }
            EXPECT_EQ(f.stream_id, 0u);
        }
    }
    EXPECT_GE(settings_total, 2u);
    EXPECT_EQ(settings_ack, 1u);
}

TEST(HTTP2ServerProtocol, ClientSettingsWithValuesAreAcknowledged) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);

    push_preface(io);
    // Build a SETTINGS payload with a few valid entries (6 bytes each).
    std::vector<uint8_t> payload;
    auto                 add = [&](uint16_t id, uint32_t val) {
        payload.push_back(static_cast<uint8_t>((id >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(id & 0xFF));
        payload.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
        payload.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
        payload.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(val & 0xFF));
    };
    add(static_cast<uint16_t>(qb::protocol::http2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE), 65535);
    add(static_cast<uint16_t>(qb::protocol::http2::Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE), 16384);
    push_frame(io, FrameType::SETTINGS, 0, 0, payload);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    // ACK must be emitted for the client's non-ACK SETTINGS.
    std::size_t settings_ack = 0;
    for (const auto &f : parse_emitted_frames(io.output)) {
        if (f.type == FrameType::SETTINGS && (f.flags & qb::protocol::http2::FLAG_ACK)) {
            ++settings_ack;
        }
    }
    EXPECT_EQ(settings_ack, 1u);
}

TEST(HTTP2ServerProtocol, SettingsPayloadNotMultipleOfSixIsFrameSizeError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);

    push_preface(io);
    // 5-byte SETTINGS payload (not a multiple of 6) -> FRAME_SIZE_ERROR.
    push_frame(io, FrameType::SETTINGS, 0, 0, {0x00, 0x01, 0x00, 0x00, 0x00});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, SettingsAckWithPayloadIsFrameSizeError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);

    push_preface(io);
    // SETTINGS ACK frames must be empty; a non-empty ACK is FRAME_SIZE_ERROR.
    push_frame(io, FrameType::SETTINGS, qb::protocol::http2::FLAG_ACK, 0, {0x00, 0x01, 0x00, 0x00, 0x00, 0x01});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, SettingsOnNonZeroStreamIsProtocolError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);

    push_preface(io);
    // base.h rejects SETTINGS on a non-zero stream at the header-parse stage.
    push_frame(io, FrameType::SETTINGS, 0, 1, {});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// Full request via wire bytes
// ===========================================================================

TEST(HTTP2ServerProtocol, FullRequestHeadersEndStreamDispatches) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const auto encoded = encode_hpack_headers(default_request_headers("/hello"));
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
    EXPECT_EQ(io.last_request_stream_id, 1u);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->method(), qb::http::method::GET);
    // URI was assembled from scheme://authority/path.
    EXPECT_EQ(std::string(io.last_request->uri().path()), "/hello");
}

TEST(HTTP2ServerProtocol, HeadersThenContinuationAccumulatesAndDispatches) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const auto encoded = encode_hpack_headers(default_request_headers("/split"));
    ASSERT_GE(encoded.size(), 2u);
    // Split the encoded block across a HEADERS (no END_HEADERS) + CONTINUATION.
    const std::size_t    half = encoded.size() / 2;
    std::vector<uint8_t> part1(encoded.begin(), encoded.begin() + half);
    std::vector<uint8_t> part2(encoded.begin() + half, encoded.end());

    // HEADERS with END_STREAM but NOT END_HEADERS -> framer expects CONTINUATION.
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_STREAM, 1, part1);
    push_frame(io, FrameType::CONTINUATION, qb::protocol::http2::FLAG_END_HEADERS, 1, part2);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(std::string(io.last_request->uri().path()), "/split");
}

// ===========================================================================
// DATA frame flow control
// ===========================================================================

TEST(HTTP2ServerProtocol, DataFrameDeliversBodyAndDispatchesOnEndStream) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // POST with content-length 3, headers do NOT end the stream.
    const auto encoded = encode_hpack_headers(
        {{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/upload"}, {"content-length", "3"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0); // not yet, body pending

    push_frame(io, FrameType::DATA, qb::protocol::http2::FLAG_END_STREAM, 1, {'a', 'b', 'c'});
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->body().raw().size(), 3u);
}

TEST(HTTP2ServerProtocol, ValidPaddedDataFrameIsAccepted) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const auto encoded = encode_hpack_headers(
        {{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/padded"}, {"content-length", "3"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Padded DATA: pad_length=2, 3 data bytes, 2 pad bytes. Total payload 6.
    std::vector<uint8_t> padded = {0x02, 'a', 'b', 'c', 0x00, 0x00};
    push_frame(io, FrameType::DATA, qb::protocol::http2::FLAG_END_STREAM | qb::protocol::http2::FLAG_PADDED, 1, padded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
    ASSERT_TRUE(io.last_request.has_value());
    EXPECT_EQ(io.last_request->body().raw().size(), 3u); // padding stripped
}

TEST(HTTP2ServerProtocol, PaddedDataFramePadExceedingLengthIsProtocolError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const auto encoded = encode_hpack_headers(default_request_headers("/padbad"));
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // pad_length (5) > remaining payload after the pad-length byte (1) ->
    // validate_padded_frame reports PROTOCOL_ERROR (and not_ok).
    std::vector<uint8_t> padded = {0x05, 'a'};
    push_frame(io, FrameType::DATA, qb::protocol::http2::FLAG_PADDED, 1, padded);
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, DataFrameOnStreamZeroIsProtocolError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::DATA, 0, 0, {'x'});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// WINDOW_UPDATE
// ===========================================================================

TEST(HTTP2ServerProtocol, WindowUpdateZeroIncrementOnStreamZeroIsProtocolError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // The framer (handle_window_update_frame_payload) rejects a zero increment
    // as PROTOCOL_ERROR before dispatch, regardless of stream id.
    push_frame(io, FrameType::WINDOW_UPDATE, 0, 0, {0x00, 0x00, 0x00, 0x00});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, WindowUpdateConnectionLevelIncrementIsAccepted) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Valid connection-level WINDOW_UPDATE (+1024) is accepted, no error.
    push_frame(io, FrameType::WINDOW_UPDATE, 0, 0, {0x00, 0x00, 0x04, 0x00});
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
}

// Note on "WINDOW_UPDATE > 0x7FFFFFFF -> FLOW_CONTROL_ERROR": the wire-level
// window_size_increment is a 31-bit field (extract_uint31_be masks the high
// bit), so a serialized increment can never exceed 0x7FFFFFFF. The
// FLOW_CONTROL_ERROR branch in handle_window_update_frame_payload is therefore
// unreachable from raw bytes; exercising it would require an out-of-band value.
// Instead we cover the reachable connection-overflow path: a WINDOW_UPDATE that
// pushes the connection send window past MAX_WINDOW_SIZE_LIMIT.
TEST(HTTP2ServerProtocol, ConnectionWindowOverflowIsFlowControlError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Connection send window starts at 65535. on(WindowUpdateFrame) on stream 0
    // errors when _connection_send_window > (MAX_WINDOW_SIZE_LIMIT - increment),
    // i.e. when 65535 + increment > 2^31-1. A maximal increment of 0x7FFFFFFF
    // passes the framer's "> 0x7FFFFFFF" guard but overflows the connection
    // window: 65535 > (0x7FFFFFFF - 0x7FFFFFFF) == 0 -> FLOW_CONTROL_ERROR.
    push_frame(io, FrameType::WINDOW_UPDATE, 0, 0, {0x7F, 0xFF, 0xFF, 0xFF});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FLOW_CONTROL_ERROR);
}

// ===========================================================================
// PING / RST_STREAM / GOAWAY / PRIORITY
// ===========================================================================

TEST(HTTP2ServerProtocol, PingIsAnsweredWithPongAck) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    std::vector<uint8_t> opaque = {1, 2, 3, 4, 5, 6, 7, 8};
    push_frame(io, FrameType::PING, 0, 0, opaque);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    // Server must reply with a PING that has the ACK flag set.
    bool pong_seen = false;
    for (const auto &f : parse_emitted_frames(io.output)) {
        if (f.type == FrameType::PING && (f.flags & qb::protocol::http2::FLAG_ACK)) {
            pong_seen = true;
            EXPECT_EQ(f.payload_length, 8u);
        }
    }
    EXPECT_TRUE(pong_seen);
}

TEST(HTTP2ServerProtocol, PingAckFromClientIsNotEchoed) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t    pings_before = count_output_frames(io.output, FrameType::PING);
    std::vector<uint8_t> opaque       = {8, 7, 6, 5, 4, 3, 2, 1};
    push_frame(io, FrameType::PING, qb::protocol::http2::FLAG_ACK, 0, opaque);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    // A PING ACK is consumed silently; no new PING frame is emitted.
    EXPECT_EQ(count_output_frames(io.output, FrameType::PING), pings_before);
}

TEST(HTTP2ServerProtocol, PingWrongPayloadSizeIsFrameSizeError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::PING, 0, 0, {1, 2, 3, 4}); // 4 != 8
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, PingZeroPayloadIsFrameSizeError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::PING, 0, 0, {}); // zero-payload PING -> FRAME_SIZE_ERROR
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, PingOnNonZeroStreamIsProtocolError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // base.h rejects PING on a non-zero stream at header-parse time.
    push_frame(io, FrameType::PING, 0, 1, {1, 2, 3, 4, 5, 6, 7, 8});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, RstStreamOnOpenStreamClosesAndNotifies) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open a stream (POST, no END_STREAM) so it has a live context.
    const auto encoded = encode_hpack_headers({{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/rst"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Client resets the open (not yet dispatched) stream.
    push_frame(io, FrameType::RST_STREAM, 0, 1, {0x00, 0x00, 0x00, static_cast<uint8_t>(ErrorCode::CANCEL)});
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    // RST on an open, undispatched stream notifies the application.
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::CANCEL);
}

TEST(HTTP2ServerProtocol, RstStreamWrongPayloadSizeIsFrameSizeError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::RST_STREAM, 0, 1, {0x00, 0x00, 0x08}); // 3 != 4
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, RstStreamOnStreamZeroIsProtocolError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::RST_STREAM, 0, 0, {0x00, 0x00, 0x00, 0x08});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, GoAwayFromClientWithErrorClosesConnection) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // GOAWAY: last_stream_id=0, error_code=PROTOCOL_ERROR(0x1), no debug data.
    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    push_frame(io, FrameType::GOAWAY, 0, 0, payload);
    drive(protocol, io);

    // A non-NO_ERROR GOAWAY makes the connection not ok and dispatches the event.
    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, GoAwayWrongPayloadSizeIsFrameSizeError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // GOAWAY needs at least 8 octets; 4 is too short -> FRAME_SIZE_ERROR.
    push_frame(io, FrameType::GOAWAY, 0, 0, {0x00, 0x00, 0x00, 0x00});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, PriorityFrameIsAccepted) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // PRIORITY payload: 4-byte stream dependency + 1-byte weight = 5 octets.
    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x00, 0x10};
    push_frame(io, FrameType::PRIORITY, 0, 1, payload);
    drive(protocol, io);

    // PRIORITY for an unknown stream is simply ignored; connection stays ok.
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
}

TEST(HTTP2ServerProtocol, PriorityWrongPayloadSizeIsFrameSizeError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::PRIORITY, 0, 1, {0x00, 0x00, 0x00, 0x00}); // 4 != 5
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, PriorityOnStreamZeroIsProtocolError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::PRIORITY, 0, 0, {0x00, 0x00, 0x00, 0x00, 0x10});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// Server received PUSH_PROMISE (illegal from client)
// ===========================================================================

TEST(HTTP2ServerProtocol, ServerReceivingPushPromiseIsProtocolError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // PUSH_PROMISE payload: 4-byte promised stream id + (empty) header block.
    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x02};
    push_frame(io, FrameType::PUSH_PROMISE, qb::protocol::http2::FLAG_END_HEADERS, 1, payload);
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// send_response / send_response_body (direct on(...) + send_response calls)
// ===========================================================================

TEST(HTTP2ServerProtocol, SendResponseNoBodyEmitsHeadersWithEndStream) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);

    // Establish an open stream via a direct GET HEADERS dispatch (no END_STREAM
    // is needed to reach a respondable state: END_STREAM here -> HALF_CLOSED_REMOTE,
    // which send_response accepts).
    qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(FrameType::HEADERS);
    headers.header.flags = qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers(default_request_headers("/resp"));
    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    const std::size_t headers_before = count_output_frames(io.output, FrameType::HEADERS);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    EXPECT_TRUE(protocol.send_response(1, response));

    // A response with no body emits a HEADERS frame carrying END_STREAM.
    const auto  frames          = parse_emitted_frames(io.output);
    std::size_t resp_headers    = 0;
    bool        end_stream_seen = false;
    for (const auto &f : frames) {
        if (f.type == FrameType::HEADERS && f.stream_id == 1) {
            ++resp_headers;
            if (f.flags & qb::protocol::http2::FLAG_END_STREAM) {
                end_stream_seen = true;
            }
        }
    }
    EXPECT_GT(resp_headers, headers_before);
    EXPECT_TRUE(end_stream_seen);
    EXPECT_FALSE(output_has_frame(io.output, FrameType::DATA));
    EXPECT_EQ(io.stream_error_count, 0);
}

TEST(HTTP2ServerProtocol, SendResponseWithBodyEmitsHeadersAndData) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(FrameType::HEADERS);
    headers.header.flags = qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers(default_request_headers("/body"));
    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "hello-body";
    response.set_header("content-length", "10");

    EXPECT_TRUE(protocol.send_response(1, response));
    EXPECT_EQ(io.stream_error_count, 0);

    // Both a HEADERS frame and at least one DATA frame must be emitted on s1.
    EXPECT_TRUE(output_has_frame(io.output, FrameType::HEADERS));
    ASSERT_TRUE(output_has_frame(io.output, FrameType::DATA));

    // Sum the DATA payload bytes -> must equal the body length.
    uint32_t data_bytes      = 0;
    bool     data_end_stream = false;
    for (const auto &f : parse_emitted_frames(io.output)) {
        if (f.type == FrameType::DATA && f.stream_id == 1) {
            data_bytes += f.payload_length;
            if (f.flags & qb::protocol::http2::FLAG_END_STREAM) {
                data_end_stream = true;
            }
        }
    }
    EXPECT_EQ(data_bytes, 10u);
    EXPECT_TRUE(data_end_stream);
}

TEST(HTTP2ServerProtocol, SendResponseOnUnknownStreamReturnsFalse) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    // No stream 7 exists -> send_response returns false, no error event.
    EXPECT_FALSE(protocol.send_response(7, response));
    EXPECT_EQ(io.stream_error_count, 0);
}

TEST(HTTP2ServerProtocol, SendResponseForbiddenHeaderIsStreamError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);

    qb::protocol::http2::Http2FrameData<qb::protocol::http2::HeadersFrame> headers;
    headers.header.type  = static_cast<uint8_t>(FrameType::HEADERS);
    headers.header.flags = qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM;
    headers.header.set_stream_id(1);
    headers.payload.header_block_fragment = encode_hpack_headers(default_request_headers("/forbidden"));
    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    // "connection" is a forbidden (hop-by-hop) response header in HTTP/2.
    response.set_header("connection", "close");

    EXPECT_FALSE(protocol.send_response(1, response));
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// send_push_promise success path
// ===========================================================================

TEST(HTTP2ServerProtocol, SendPushPromiseSucceedsWhenPeerAllowsPush) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    push_preface(io);
    // Client SETTINGS enabling push (SETTINGS_ENABLE_PUSH = 1).
    {
        std::vector<uint8_t> payload = {0x00, 0x02, 0x00, 0x00, 0x00, 0x01};
        push_frame(io, FrameType::SETTINGS, 0, 0, payload);
    }
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open a client request stream that stays OPEN (POST, no END_STREAM) so the
    // associated stream is in a valid state for PUSH_PROMISE.
    const auto encoded =
        encode_hpack_headers({{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/parent"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    qb::http::Request promised{qb::io::uri{"https://example.test/asset.css"}};
    promised.method() = qb::http::method::GET;

    auto failure = protocol.send_push_promise(1, 2, std::move(promised));
    EXPECT_FALSE(failure.has_value()); // std::nullopt == success
    EXPECT_TRUE(output_has_frame(io.output, FrameType::PUSH_PROMISE));
}

TEST(HTTP2ServerProtocol, SendPushPromiseRejectedWhenPeerDisablesPush) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    // Default handshake (empty SETTINGS) does NOT enable push; server default
    // _peer_allows_push is true initially, so explicitly disable via SETTINGS.
    push_preface(io);
    {
        std::vector<uint8_t> payload = {0x00, 0x02, 0x00, 0x00, 0x00, 0x00}; // ENABLE_PUSH=0
        push_frame(io, FrameType::SETTINGS, 0, 0, payload);
    }
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const auto encoded =
        encode_hpack_headers({{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/parent"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    qb::http::Request promised{qb::io::uri{"https://example.test/asset.css"}};
    promised.method() = qb::http::method::GET;

    auto failure = protocol.send_push_promise(1, 2, std::move(promised));
    ASSERT_TRUE(failure.has_value());
    EXPECT_EQ(*failure, qb::protocol::http2::PushPromiseFailureReason::PEER_PUSH_DISABLED);
}

// ===========================================================================
// Extended coverage: send-side flow control, lifecycle, error escalation.
//
// These tests target the previously-uncovered send path in server.h:
//   - send_response_body buffering when the peer window is exhausted
//   - try_send_pending_data_for_stream flush on stream/connection WINDOW_UPDATE
//   - send_window_update (stream + connection auto-emit)
//   - conditionally_send_connection_window_update
//   - update_initial_peer_window_size via SETTINGS_INITIAL_WINDOW_SIZE
//   - try_close_stream_context / are_all_relevant_streams_closed lifecycle
//   - on_connection_error / on_stream_error / send_goaway_and_close / handle_*
//   - send_rst_stream, chunked DATA, trailers
//
// They reuse the namespace-local harness/helpers above (push_*, drive,
// parse_emitted_frames, encode_hpack_headers, default_request_headers).
// ===========================================================================

namespace {

// Encode a SETTINGS payload from (id, value) pairs (6 octets each, big-endian).
[[nodiscard]] std::vector<uint8_t>
encode_settings_payload(const std::vector<std::pair<qb::protocol::http2::Http2SettingIdentifier, uint32_t>> &settings) {
    std::vector<uint8_t> payload;
    for (const auto &[id, val] : settings) {
        const auto id16 = static_cast<uint16_t>(id);
        payload.push_back(static_cast<uint8_t>((id16 >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(id16 & 0xFF));
        payload.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
        payload.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
        payload.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(val & 0xFF));
    }
    return payload;
}

// Drive preface + a client SETTINGS frame that advertises a custom
// SETTINGS_INITIAL_WINDOW_SIZE. This puts the server's _initial_peer_window_size
// (the per-stream send window applied to *new* streams) at the requested value,
// so a subsequently opened stream begins flow-control-limited.
void
handshake_with_initial_window(ServerProtocol &protocol, Http2ServerHarness &io, uint32_t initial_window) {
    push_preface(io);
    const auto payload = encode_settings_payload({{qb::protocol::http2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, initial_window}});
    push_frame(io, FrameType::SETTINGS, 0, 0, payload);
    drive(protocol, io);
}

// Open a client GET stream that ends the stream (END_STREAM + END_HEADERS) and
// dispatches the request. The stream is left in HALF_CLOSED_REMOTE, a valid
// state for send_response to write a response (and queue body under flow ctrl).
void
open_get_stream_end_stream(ServerProtocol &protocol, Http2ServerHarness &io, uint32_t stream_id, const std::string &path) {
    const auto encoded = encode_hpack_headers(default_request_headers(path));
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, stream_id, encoded);
    drive(protocol, io);
}

// Build a WINDOW_UPDATE payload (31-bit increment, big-endian).
[[nodiscard]] std::vector<uint8_t>
window_update_payload(uint32_t increment) {
    return {
        static_cast<uint8_t>((increment >> 24) & 0x7F), static_cast<uint8_t>((increment >> 16) & 0xFF),
        static_cast<uint8_t>((increment >> 8) & 0xFF), static_cast<uint8_t>(increment & 0xFF)
    };
}

// Sum DATA payload bytes emitted on a given stream id.
[[nodiscard]] uint32_t
sum_data_bytes(const qb::allocator::pipe<char> &output, uint32_t stream_id) {
    uint32_t total = 0;
    for (const auto &f : parse_emitted_frames(output)) {
        if (f.type == FrameType::DATA && f.stream_id == stream_id) {
            total += f.payload_length;
        }
    }
    return total;
}

// True if any DATA frame on the stream carried END_STREAM.
[[nodiscard]] bool
data_end_stream_seen(const qb::allocator::pipe<char> &output, uint32_t stream_id) {
    for (const auto &f : parse_emitted_frames(output)) {
        if (f.type == FrameType::DATA && f.stream_id == stream_id && (f.flags & qb::protocol::http2::FLAG_END_STREAM)) {
            return true;
        }
    }
    return false;
}

} // namespace

// ---------------------------------------------------------------------------
// Flow control: small peer window -> body queues -> WINDOW_UPDATE flushes
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, SmallInitialWindowQueuesBodyUntilStreamWindowUpdate) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    // Client advertises a tiny send window of 10 for streams the server sends on.
    handshake_with_initial_window(protocol, io, 10);
    ASSERT_TRUE(protocol.ok());

    // Open a GET stream (END_STREAM) -> dispatched, HALF_CLOSED_REMOTE.
    open_get_stream_end_stream(protocol, io, 1, "/queued");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    // Response body (30 bytes) > stream peer window (10) -> only the first 10
    // bytes are written as DATA; the rest is buffered (has_pending_data_to_send).
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = std::string(30, 'x');
    ASSERT_TRUE(protocol.send_response(1, response));
    EXPECT_EQ(io.stream_error_count, 0);

    // Exactly the windowed prefix is on the wire so far, and NO END_STREAM.
    EXPECT_EQ(sum_data_bytes(io.output, 1), 10u);
    EXPECT_FALSE(data_end_stream_seen(io.output, 1));
    EXPECT_TRUE(protocol.ok());

    // Client opens the stream window (+1000) -> try_send_pending_data_for_stream
    // flushes the remaining 20 bytes and sets END_STREAM.
    push_frame(io, FrameType::WINDOW_UPDATE, 0, 1, window_update_payload(1000));
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(sum_data_bytes(io.output, 1), 30u); // full body now flushed
    EXPECT_TRUE(data_end_stream_seen(io.output, 1));
}

TEST(HTTP2ServerProtocol, ConnectionWindowExhaustionQueuesBodyUntilConnectionWindowUpdate) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io); // default windows (65535)
    ASSERT_TRUE(protocol.ok());

    open_get_stream_end_stream(protocol, io, 1, "/connwin");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    // First response consumes the entire 65535 connection send window with a
    // body sized exactly to it. _connection_send_window -> 0 after this send.
    const std::size_t  conn_window = 65535;
    qb::http::Response first;
    first.status() = qb::http::status::OK;
    first.body()   = std::string(conn_window, 'a');
    ASSERT_TRUE(protocol.send_response(1, first));
    EXPECT_EQ(sum_data_bytes(io.output, 1), static_cast<uint32_t>(conn_window));
    EXPECT_TRUE(data_end_stream_seen(io.output, 1));

    // Open a second stream that stays OPEN (POST, no END_STREAM from client) so
    // its body cannot be sent because the *connection* send window is now 0 even
    // though the stream window is full. Keeping it OPEN (not END_STREAM) means
    // the flush below does not drive it to CLOSED, so the server's stream-0
    // WINDOW_UPDATE loop does not erase it mid-iteration.
    {
        const auto encoded =
            encode_hpack_headers({{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/connwin2"}});
        push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 3, encoded);
        drive(protocol, io);
    }
    ASSERT_TRUE(protocol.ok());

    qb::http::Response second;
    second.status() = qb::http::status::OK;
    second.body()   = std::string(50, 'b');
    ASSERT_TRUE(protocol.send_response(3, second));
    // Connection window is 0 -> body queues, nothing on the wire for stream 3.
    EXPECT_EQ(sum_data_bytes(io.output, 3), 0u);
    EXPECT_FALSE(data_end_stream_seen(io.output, 3));

    // A connection-level WINDOW_UPDATE (stream 0) releases the window and the
    // on(WindowUpdateFrame) handler drains pending data for all streams. The
    // body (and its END_STREAM) is flushed; the stream goes HALF_CLOSED_LOCAL
    // (client never sent END_STREAM) and is not erased during the loop.
    push_frame(io, FrameType::WINDOW_UPDATE, 0, 0, window_update_payload(10000));
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(sum_data_bytes(io.output, 3), 50u);
    EXPECT_TRUE(data_end_stream_seen(io.output, 3));
}

// Regression: a connection-level WINDOW_UPDATE must not erase streams from
// _server_streams while iterating it. Several client streams are left in
// HALF_CLOSED_REMOTE (GET + END_STREAM) with response bodies queued behind a
// zero connection send window. The single stream-0 WINDOW_UPDATE below flushes
// each body + END_STREAM, driving every stream straight to CLOSED, which calls
// try_close_stream_context -> _server_streams.erase mid-iteration. Before the
// snapshot-then-refind fix this invalidated the loop iterator (heap UAF /
// non-deterministic SIGSEGV). Unlike the test above, these streams DO reach
// CLOSED during the loop, exercising the erase-during-iteration path directly.
TEST(HTTP2ServerProtocol, ConnectionWindowUpdateFlushClosesStreamsMidLoopNoUAF) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io); // default windows (65535)
    ASSERT_TRUE(protocol.ok());

    // Stream 1: GET + END_STREAM, body sized to drain the entire connection send
    // window (65535). It flushes fully and closes immediately, leaving the
    // connection send window at 0 for the streams that follow.
    open_get_stream_end_stream(protocol, io, 1, "/drain");
    ASSERT_TRUE(protocol.ok());
    qb::http::Response drain;
    drain.status() = qb::http::status::OK;
    drain.body()   = std::string(65535, 'a');
    ASSERT_TRUE(protocol.send_response(1, drain));
    EXPECT_EQ(sum_data_bytes(io.output, 1), 65535u);
    EXPECT_TRUE(data_end_stream_seen(io.output, 1));

    // Open several more HALF_CLOSED_REMOTE streams, each with a small queued body.
    // Connection window is 0, so nothing flushes yet; each stream keeps pending
    // data and will go CLOSED the moment its body + END_STREAM are written.
    const std::vector<uint32_t> ids = {3, 5, 7, 9, 11};
    for (uint32_t sid : ids) {
        open_get_stream_end_stream(protocol, io, sid, "/q");
        ASSERT_TRUE(protocol.ok());
        qb::http::Response resp;
        resp.status() = qb::http::status::OK;
        resp.body()   = std::string(10, 'b');
        ASSERT_TRUE(protocol.send_response(sid, resp));
        EXPECT_EQ(sum_data_bytes(io.output, sid), 0u); // queued, conn window 0
        EXPECT_FALSE(data_end_stream_seen(io.output, sid));
    }

    // One connection-level WINDOW_UPDATE flushes every queued body; each stream
    // reaches CLOSED and is erased during the stream-0 loop.
    push_frame(io, FrameType::WINDOW_UPDATE, 0, 0, window_update_payload(1000000));
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    for (uint32_t sid : ids) {
        EXPECT_EQ(sum_data_bytes(io.output, sid), 10u);
        EXPECT_TRUE(data_end_stream_seen(io.output, sid));
    }
}

// ---------------------------------------------------------------------------
// Auto WINDOW_UPDATE: heavy inbound DATA forces the server to advertise more
// window (stream-level via send_window_update and connection-level via
// conditionally_send_connection_window_update).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, LargeInboundDataTriggersServerWindowUpdates) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // POST without END_STREAM so the body arrives in a DATA frame.
    const auto encoded =
        encode_hpack_headers({{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/upload"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t window_updates_before = count_output_frames(io.output, FrameType::WINDOW_UPDATE);

    // Send the body as several DATA frames. Each frame must stay under the
    // server's advertised MAX_FRAME_SIZE (16384), so use 12000-byte chunks.
    // Cumulative inbound (48000) stays below the stream local window (65535) and
    // connection receive window (65535), but crosses both WINDOW_UPDATE
    // thresholds (32767), so the server emits WINDOW_UPDATE(s):
    //   - stream-level via send_window_update(stream_id, increment)
    //   - connection-level via conditionally_send_connection_window_update
    const std::vector<uint8_t> chunk(12000, 0x7A);
    push_frame(io, FrameType::DATA, 0, 1, chunk);
    push_frame(io, FrameType::DATA, 0, 1, chunk);
    push_frame(io, FrameType::DATA, 0, 1, chunk);
    push_frame(io, FrameType::DATA, qb::protocol::http2::FLAG_END_STREAM, 1, chunk);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);

    const auto frames    = parse_emitted_frames(io.output);
    bool       stream_wu = false;
    bool       conn_wu   = false;
    for (const auto &f : frames) {
        if (f.type == FrameType::WINDOW_UPDATE) {
            if (f.stream_id == 1) {
                stream_wu = true;
            } else if (f.stream_id == 0) {
                conn_wu = true;
            }
        }
    }
    EXPECT_GT(count_output_frames(io.output, FrameType::WINDOW_UPDATE), window_updates_before);
    EXPECT_TRUE(stream_wu);
    EXPECT_TRUE(conn_wu);
}

// ---------------------------------------------------------------------------
// SETTINGS_INITIAL_WINDOW_SIZE change retroactively unblocks a pending stream
// (update_initial_peer_window_size delta path + pending flush).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, InitialWindowSizeIncreaseFlushesPendingStream) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    // Start with a window of 0 so the server can send nothing on a new stream.
    handshake_with_initial_window(protocol, io, 0);
    ASSERT_TRUE(protocol.ok());

    // Open a POST stream that stays OPEN (no END_STREAM). update_initial_peer_
    // window_size only adjusts streams in OPEN / HALF_CLOSED_LOCAL / RESERVED_
    // LOCAL state, so the stream must be OPEN for the delta-driven flush.
    {
        const auto encoded =
            encode_hpack_headers({{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/grow"}});
        push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
        drive(protocol, io);
    }
    ASSERT_TRUE(protocol.ok());
    // POST without END_STREAM is not dispatched (awaits body), but the stream is
    // OPEN, which is all send_response needs.

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = std::string(20, 'z');
    ASSERT_TRUE(protocol.send_response(1, response));
    // peer window is 0 -> nothing sent, body fully queued.
    EXPECT_EQ(sum_data_bytes(io.output, 1), 0u);
    EXPECT_FALSE(data_end_stream_seen(io.output, 1));

    // Raise SETTINGS_INITIAL_WINDOW_SIZE to 1000. update_initial_peer_window_size
    // applies the +1000 delta to the open stream's peer_window_size (was 0) and,
    // because it crossed from <=0 to >0 with pending data, flushes it.
    const auto payload = encode_settings_payload({{qb::protocol::http2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 1000}});
    push_frame(io, FrameType::SETTINGS, 0, 0, payload);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(sum_data_bytes(io.output, 1), 20u);
    EXPECT_TRUE(data_end_stream_seen(io.output, 1));
}

// ---------------------------------------------------------------------------
// Chunked DATA: a body larger than max_frame_size is split into >1 DATA frames.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, LargeBodyIsChunkedAcrossMultipleDataFrames) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    // Generous windows so flow control never blocks: advertise a large initial
    // window and a large connection window so the only limit is max_frame_size.
    handshake_with_initial_window(protocol, io, qb::protocol::http2::MAX_WINDOW_SIZE_LIMIT);
    ASSERT_TRUE(protocol.ok());
    // Lift the connection send window well above the body size.
    push_frame(io, FrameType::WINDOW_UPDATE, 0, 0, window_update_payload(1000000));
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_get_stream_end_stream(protocol, io, 1, "/big");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    // Body of ~2.5 * default max_frame_size (16384) -> at least 3 DATA frames,
    // each capped at 16384 octets.
    const std::size_t  body_size = qb::protocol::http2::DEFAULT_SETTINGS_MAX_FRAME_SIZE * 2 + 5000;
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = std::string(body_size, 'q');
    ASSERT_TRUE(protocol.send_response(1, response));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 0);
    EXPECT_GE(count_output_frames(io.output, FrameType::DATA), 3u);
    EXPECT_EQ(sum_data_bytes(io.output, 1), static_cast<uint32_t>(body_size));
    EXPECT_TRUE(data_end_stream_seen(io.output, 1));
    for (const auto &f : parse_emitted_frames(io.output)) {
        if (f.type == FrameType::DATA) {
            EXPECT_LE(f.payload_length, qb::protocol::http2::DEFAULT_SETTINGS_MAX_FRAME_SIZE);
        }
    }
}

// ---------------------------------------------------------------------------
// Trailers: a response carrying a "Trailer" header sends body DATA (no
// END_STREAM) followed by a trailers HEADERS frame that ends the stream.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, ResponseWithTrailersSendsHeadersDataThenTrailers) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_get_stream_end_stream(protocol, io, 1, "/trailers");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "payload";
    // "Trailer" header signals send_response_body to defer END_STREAM to a
    // trailers HEADERS frame. Add an actual trailer field too.
    response.set_header("Trailer", "x-checksum");
    response.set_header("x-checksum", "abc123");

    ASSERT_TRUE(protocol.send_response(1, response));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 0);

    const auto frames = parse_emitted_frames(io.output);
    // Two HEADERS frames on stream 1: the initial response headers (no
    // END_STREAM, since a body follows) and the trailers (END_STREAM).
    std::size_t headers_s1          = 0;
    bool        trailers_end_stream = false;
    bool        data_seen           = false;
    bool        data_carried_es     = false;
    for (const auto &f : frames) {
        if (f.stream_id != 1) {
            continue;
        }
        if (f.type == FrameType::HEADERS) {
            ++headers_s1;
            if (f.flags & qb::protocol::http2::FLAG_END_STREAM) {
                trailers_end_stream = true;
            }
        } else if (f.type == FrameType::DATA) {
            data_seen = true;
            if (f.flags & qb::protocol::http2::FLAG_END_STREAM) {
                data_carried_es = true;
            }
        }
    }
    EXPECT_GE(headers_s1, 2u);        // response headers + trailers
    EXPECT_TRUE(data_seen);           // body delivered
    EXPECT_FALSE(data_carried_es);    // DATA must NOT end the stream (trailers do)
    EXPECT_TRUE(trailers_end_stream); // trailers HEADERS carries END_STREAM
    EXPECT_EQ(sum_data_bytes(io.output, 1), 7u);
}

// ---------------------------------------------------------------------------
// Explicit content-length response is accepted and sized correctly.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, ResponseWithMatchingContentLengthSendsBody) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_get_stream_end_stream(protocol, io, 1, "/clen");
    ASSERT_TRUE(protocol.ok());

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "exactly-thirteen"; // 16 bytes
    response.set_header("content-length", "16");

    ASSERT_TRUE(protocol.send_response(1, response));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 0);
    EXPECT_EQ(sum_data_bytes(io.output, 1), 16u);
    EXPECT_TRUE(data_end_stream_seen(io.output, 1));
}

TEST(HTTP2ServerProtocol, ResponseWithMismatchedContentLengthIsStreamError) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_get_stream_end_stream(protocol, io, 1, "/clenbad");
    ASSERT_TRUE(protocol.ok());

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "short"; // 5 bytes
    response.set_header("content-length", "999");

    // body size (5) != declared content-length (999) -> on_stream_error.
    EXPECT_FALSE(protocol.send_response(1, response));
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

// ---------------------------------------------------------------------------
// Lifecycle: a no-body response on a HALF_CLOSED_REMOTE stream closes it
// (try_close_stream_context erases the context).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, NoBodyResponseClosesStreamContext) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_get_stream_end_stream(protocol, io, 1, "/close");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);
    EXPECT_FALSE(protocol.is_stream_closed(1)); // still open before response

    qb::http::Response response;
    response.status() = qb::http::status::NO_CONTENT; // 204, no body
    ASSERT_TRUE(protocol.send_response(1, response));

    // After send (END_STREAM on HEADERS, and END_STREAM already received), the
    // stream reaches CLOSED and try_close_stream_context erases the context, so
    // is_stream_closed (which treats unknown streams as closed) is true.
    EXPECT_TRUE(protocol.is_stream_closed(1));
    // A second send_response on the now-gone stream returns false (no crash).
    EXPECT_FALSE(protocol.send_response(1, response));
}

TEST(HTTP2ServerProtocol, MultipleConcurrentStreamsRespondIndependently) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_get_stream_end_stream(protocol, io, 1, "/a");
    open_get_stream_end_stream(protocol, io, 3, "/b");
    open_get_stream_end_stream(protocol, io, 5, "/c");
    ASSERT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 3);

    // All three are live (HALF_CLOSED_REMOTE) until we respond.
    EXPECT_FALSE(protocol.is_stream_closed(1));
    EXPECT_FALSE(protocol.is_stream_closed(3));
    EXPECT_FALSE(protocol.is_stream_closed(5));

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "ok";
    response.set_header("content-length", "2");

    ASSERT_TRUE(protocol.send_response(3, response)); // respond out of order
    ASSERT_TRUE(protocol.send_response(1, response));
    ASSERT_TRUE(protocol.send_response(5, response));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 0);
    // Each stream got its own 2-byte body ending the stream, and is now closed.
    EXPECT_EQ(sum_data_bytes(io.output, 1), 2u);
    EXPECT_EQ(sum_data_bytes(io.output, 3), 2u);
    EXPECT_EQ(sum_data_bytes(io.output, 5), 2u);
    EXPECT_TRUE(protocol.is_stream_closed(1));
    EXPECT_TRUE(protocol.is_stream_closed(3));
    EXPECT_TRUE(protocol.is_stream_closed(5));
}

// ---------------------------------------------------------------------------
// Explicit send_rst_stream: the public API emits RST_STREAM, marks the stream
// closed, and notifies the application (stream not fully responded).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, ExplicitSendRstStreamEmitsFrameAndNotifies) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open a POST stream that stays OPEN (no END_STREAM) and is not dispatched.
    const auto encoded = encode_hpack_headers({{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/abort"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t rst_before = count_output_frames(io.output, FrameType::RST_STREAM);
    protocol.send_rst_stream(1, ErrorCode::INTERNAL_ERROR, "explicit abort");

    EXPECT_TRUE(protocol.ok()); // RST_STREAM is a stream-level action; connection stays ok
    EXPECT_GT(count_output_frames(io.output, FrameType::RST_STREAM), rst_before);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::INTERNAL_ERROR);
    EXPECT_TRUE(protocol.is_stream_closed(1)); // context erased / closed
}

// ---------------------------------------------------------------------------
// Error escalation: connection-level protocol violation -> on_connection_error
// -> send_goaway_and_close (GOAWAY emitted, protocol not ok).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, ConnectionLevelErrorEmitsGoawayAndCloses) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t goaway_before = count_output_frames(io.output, FrameType::GOAWAY);

    // A WINDOW_UPDATE with a zero increment on stream 0 is a connection-level
    // PROTOCOL_ERROR: on(WindowUpdateFrame) calls on_connection_error ->
    // send_goaway_and_close. (Server's own handler path, not the framer's.)
    push_frame(io, FrameType::WINDOW_UPDATE, 0, 0, window_update_payload(0));
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_GT(count_output_frames(io.output, FrameType::GOAWAY), goaway_before);
    EXPECT_EQ(io.goaway_count, 1); // server's send_goaway_and_close dispatches the event
    EXPECT_EQ(io.last_goaway_error, ErrorCode::PROTOCOL_ERROR);
}

// ---------------------------------------------------------------------------
// Error escalation: stream-level violation -> send_rst_stream (RST_STREAM
// emitted), connection stays ok.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, StreamLevelErrorEmitsRstStreamKeepsConnection) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Finish a GET request (END_STREAM) -> stream becomes HALF_CLOSED_REMOTE and
    // end_stream_received is set, but stays in the map (no response yet).
    open_get_stream_end_stream(protocol, io, 1, "/streamerr");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    const std::size_t rst_before = count_output_frames(io.output, FrameType::RST_STREAM);

    // A DATA frame after END_STREAM is a stream-level error: on(DataFrame) calls
    // send_rst_stream(STREAM_CLOSED) but does NOT tear down the connection.
    push_frame(io, FrameType::DATA, 0, 1, {'x', 'y'});
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok()); // connection survives a stream-level reset
    EXPECT_GT(count_output_frames(io.output, FrameType::RST_STREAM), rst_before);
    EXPECT_TRUE(output_has_frame(io.output, FrameType::RST_STREAM));
}

// ---------------------------------------------------------------------------
// Graceful shutdown: client GOAWAY(NO_ERROR) with all relevant streams already
// closed completes the shutdown (are_all_relevant_streams_closed -> connection
// becomes not ok with NO_ERROR).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, GoawayNoErrorWithClosedStreamsCompletesGracefulShutdown) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open and fully complete a stream (GET + no-body 204 response) so it is
    // closed/erased before the GOAWAY arrives.
    open_get_stream_end_stream(protocol, io, 1, "/done");
    ASSERT_TRUE(protocol.ok());
    qb::http::Response response;
    response.status() = qb::http::status::NO_CONTENT;
    ASSERT_TRUE(protocol.send_response(1, response));
    ASSERT_TRUE(protocol.is_stream_closed(1));

    // Client sends GOAWAY(NO_ERROR), last_stream_id=1. With no active relevant
    // streams remaining, are_all_relevant_streams_closed(1) is true and the
    // server completes the graceful shutdown: connection becomes not ok with
    // NO_ERROR.
    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}; // last_stream_id=1, error=NO_ERROR
    push_frame(io, FrameType::GOAWAY, 0, 0, payload);
    drive(protocol, io);

    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, ErrorCode::NO_ERROR);
    EXPECT_FALSE(protocol.ok()); // shutdown complete -> not ok
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::NO_ERROR);
}

TEST(HTTP2ServerProtocol, GoawayNoErrorDefersShutdownUntilActiveStreamCompletes) {
    Http2ServerHarness io;
    ServerProtocol     protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open a stream and leave it active (GET END_STREAM -> HALF_CLOSED_REMOTE,
    // awaiting our response).
    open_get_stream_end_stream(protocol, io, 1, "/inflight");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);
    ASSERT_FALSE(protocol.is_stream_closed(1));

    // Client GOAWAY(NO_ERROR, last_stream_id=1). Stream 1 is still active and is
    // <= last_stream_id, so are_all_relevant_streams_closed(1) returns false and
    // the connection must NOT close yet (still ok, event dispatched).
    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    push_frame(io, FrameType::GOAWAY, 0, 0, payload);
    drive(protocol, io);

    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, ErrorCode::NO_ERROR);
    EXPECT_TRUE(protocol.ok()); // shutdown deferred: an active stream remains

    // Complete the in-flight stream with a no-body 204. send_response emits the
    // HEADERS (END_STREAM), the stream reaches CLOSED, and try_close_stream_
    // context re-checks are_all_relevant_streams_closed during graceful
    // shutdown: with the last relevant stream now closed, the shutdown completes
    // and the connection transitions to not ok (NO_ERROR) *during* the call.
    // send_response returns this->ok(), which is therefore false by the time it
    // returns -- the response was still emitted and the stream is closed.
    qb::http::Response response;
    response.status() = qb::http::status::NO_CONTENT;
    EXPECT_FALSE(protocol.send_response(1, response));

    EXPECT_TRUE(protocol.is_stream_closed(1)); // stream finalized
    EXPECT_FALSE(protocol.ok());               // graceful shutdown completed
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::NO_ERROR);
}

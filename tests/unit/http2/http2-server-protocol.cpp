/**
 * @file qbm/http/tests/unit/http2/http2-server-protocol.cpp
 * @brief Unit tests driving ServerHttp2Protocol over a fake (socket-less) IO.
 *
 * These tests exercise the HTTP/2 server framer (qbm/http/2/protocol/base.h)
 * and the server protocol state machine (qbm/http/2/protocol/server.h) by
 * feeding raw wire bytes (preface + frames) into the parser and/or invoking
 * the typed on(Http2FrameData<T>) handlers directly. No real socket is used:
 * the shared @ref qb::http::test::Http2FakeIO harness owns two pipes
 * (input/output) and counts the application callbacks. Emitted frames are
 * inspected by parsing the 9-byte FrameHeader sequence the serializers write
 * into io.output (shared @ref parse_emitted_frames / @ref count_frames /
 * @ref find_frame_offset).
 *
 * Pure logic: deterministic, parallel-safe, no engine, no TLS, no wall clock.
 * The harness and wire helpers are factored into tests/shared/http2_fake_io.h
 * so the server/client/validator unit files share one canonical fake IO.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "../../shared/http2_fake_io.h"

using namespace qb::http::test;

using qb::protocol::http2::ErrorCode;
using qb::protocol::http2::FrameHeader;
using qb::protocol::http2::FrameType;
using qb::protocol::http2::Http2SettingIdentifier;
using ServerProtocol = qb::protocol::http2::ServerHttp2Protocol<Http2FakeIO>;

namespace {

// ---------------------------------------------------------------------------
// File-local helpers built on top of the shared wire primitives. These express
// server-test-specific intent (settings keyed by the typed identifier enum,
// opening a request stream, summing emitted DATA bytes) without duplicating the
// generic push_frame / parse_emitted_frames / encode_hpack_headers machinery.
// ---------------------------------------------------------------------------

// Encode a SETTINGS payload from (typed-identifier, value) pairs.
[[nodiscard]] std::vector<uint8_t>
encode_settings_payload(const std::vector<std::pair<Http2SettingIdentifier, uint32_t>> &settings) {
    std::vector<std::pair<uint16_t, uint32_t>> raw;
    raw.reserve(settings.size());
    for (const auto &[id, val] : settings) {
        raw.emplace_back(static_cast<uint16_t>(id), val);
    }
    return make_settings_payload(raw);
}

// Drive preface + a client SETTINGS frame that advertises a custom
// SETTINGS_INITIAL_WINDOW_SIZE, so a subsequently opened stream begins
// flow-control-limited at that value.
void
handshake_with_initial_window(ServerProtocol &protocol, Http2FakeIO &io, uint32_t initial_window) {
    push_preface(io);
    const auto payload = encode_settings_payload({{Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, initial_window}});
    push_frame(io, FrameType::SETTINGS, 0, 0, payload);
    drive(protocol, io);
}

// Open a client GET stream that ends the stream (END_STREAM + END_HEADERS) and
// dispatches the request, leaving it HALF_CLOSED_REMOTE (a valid state for
// send_response).
void
open_get_stream_end_stream(ServerProtocol &protocol, Http2FakeIO &io, uint32_t stream_id, const std::string &path) {
    const auto encoded = encode_hpack_headers(default_request_headers(path));
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, stream_id, encoded);
    drive(protocol, io);
}

// Open a client POST stream that stays OPEN (END_HEADERS, no END_STREAM); the
// request is not dispatched (awaits body) but the stream is in OPEN state.
void
open_post_stream_open(ServerProtocol &protocol, Http2FakeIO &io, uint32_t stream_id, const std::string &path) {
    const auto encoded =
        encode_hpack_headers({{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", path}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, stream_id, encoded);
    drive(protocol, io);
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

// Parse the first emitted frame of the given type AT OR AFTER `from_offset` and
// return its decoded view, or std::nullopt if none. Used to pin the *exact*
// next emitted frame (type+stream+flags) rather than a relative count delta.
[[nodiscard]] std::optional<EmittedFrame>
first_frame_at_or_after(const qb::allocator::pipe<char> &output, FrameType type, std::size_t from_offset) {
    const std::size_t off = find_frame_offset(output, type, from_offset);
    if (off == SIZE_MAX) {
        return std::nullopt;
    }
    const auto fh = peek_frame_header(output, off);
    return EmittedFrame{fh.get_type(), fh.flags, fh.get_stream_id(), fh.get_payload_length()};
}

} // namespace

// ===========================================================================
// Preface + SETTINGS handshake
// ===========================================================================

TEST(HTTP2ServerProtocol, PrefaceTriggersServerSettingsAndAck) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);

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

    // Pin the FIRST emitted frame exactly: the server's own (non-ACK) SETTINGS
    // on stream 0, emitted in response to PrefaceCompleteEvent before the ACK.
    const auto first = first_frame_at_or_after(io.output, FrameType::SETTINGS, 0);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->stream_id, 0u);
    EXPECT_EQ(first->flags & qb::protocol::http2::FLAG_ACK, 0); // server settings, not the ACK
}

TEST(HTTP2ServerProtocol, ClientSettingsWithValuesAreAcknowledged) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);

    push_preface(io);
    const auto payload = encode_settings_payload(
        {{Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 65535}, {Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 16384}});
    push_frame(io, FrameType::SETTINGS, 0, 0, payload);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    // Exactly one ACK is emitted for the client's non-ACK SETTINGS, and the ACK
    // is an empty SETTINGS frame on stream 0.
    std::size_t settings_ack = 0;
    for (const auto &f : parse_emitted_frames(io.output)) {
        if (f.type == FrameType::SETTINGS && (f.flags & qb::protocol::http2::FLAG_ACK)) {
            ++settings_ack;
            EXPECT_EQ(f.stream_id, 0u);
            EXPECT_EQ(f.payload_length, 0u); // an ACK carries no entries
        }
    }
    EXPECT_EQ(settings_ack, 1u);
}

TEST(HTTP2ServerProtocol, SettingsPayloadNotMultipleOfSixIsFrameSizeError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);

    push_preface(io);
    // 5-byte SETTINGS payload (not a multiple of 6) -> FRAME_SIZE_ERROR.
    push_frame(io, FrameType::SETTINGS, 0, 0, {0x00, 0x01, 0x00, 0x00, 0x00});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, SettingsAckWithPayloadIsFrameSizeError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);

    push_preface(io);
    // SETTINGS ACK frames must be empty; a non-empty ACK is FRAME_SIZE_ERROR.
    push_frame(io, FrameType::SETTINGS, qb::protocol::http2::FLAG_ACK, 0, {0x00, 0x01, 0x00, 0x00, 0x00, 0x01});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, SettingsOnNonZeroStreamIsProtocolError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);

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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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

// ---------------------------------------------------------------------------
// Stream-id rules: HEADERS must arrive on a non-zero, odd (client-initiated),
// strictly-increasing stream id (RFC 9113 §5.1.1).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, HeadersOnEvenStreamIdIsConnectionProtocolError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t goaway_before = count_frames(io.output, FrameType::GOAWAY);

    // Stream id 2 is even -> server-initiated parity; a client HEADERS there is
    // a connection-level PROTOCOL_ERROR: send_goaway_and_close.
    const auto encoded = encode_hpack_headers(default_request_headers("/even"));
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 2, encoded);
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_GT(count_frames(io.output, FrameType::GOAWAY), goaway_before);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.request_count, 0); // never dispatched
}

TEST(HTTP2ServerProtocol, HeadersOnDecreasingStreamIdIsStreamClosedRst) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open stream 3 first -> _last_client_initiated_stream_id becomes 3.
    open_get_stream_end_stream(protocol, io, 3, "/three");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    const std::size_t rst_before = count_frames(io.output, FrameType::RST_STREAM);

    // A *new* HEADERS on the lower id 1 (<= last initiated 3, not in the map) is
    // an idle/old stream id: the server refuses it with RST_STREAM(STREAM_CLOSED)
    // but the connection survives (RFC §5.1.1 monotonicity is stream-scoped here).
    const auto encoded = encode_hpack_headers(default_request_headers("/one"));
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());      // connection stays up
    EXPECT_EQ(io.request_count, 1);  // the stale stream is NOT dispatched
    ASSERT_GT(count_frames(io.output, FrameType::RST_STREAM), rst_before);
    // The RST_STREAM targets the offending old stream id 1.
    bool rst_on_1 = false;
    for (const auto &f : parse_emitted_frames(io.output)) {
        if (f.type == FrameType::RST_STREAM && f.stream_id == 1) {
            rst_on_1 = true;
        }
    }
    EXPECT_TRUE(rst_on_1);
}

// ---------------------------------------------------------------------------
// CONTINUATION arriving without a preceding (incomplete) HEADERS is a
// connection-level PROTOCOL_ERROR (RFC 9113 §6.10).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, ContinuationWithoutHeadersIsConnectionProtocolError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t goaway_before = count_frames(io.output, FrameType::GOAWAY);

    // No HEADERS block is in progress (_continuation_required == false), so this
    // CONTINUATION dispatches to on(ContinuationFrame) with _current_header_
    // stream_id == 0 -> send_goaway_and_close(PROTOCOL_ERROR).
    const auto encoded = encode_hpack_headers(default_request_headers("/orphan"));
    push_frame(io, FrameType::CONTINUATION, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_GT(count_frames(io.output, FrameType::GOAWAY), goaway_before);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, ErrorCode::PROTOCOL_ERROR);
}

// ---------------------------------------------------------------------------
// A malformed HPACK header block (indexed field referencing index 0) makes the
// decoder fail -> stream-level COMPRESSION_ERROR (RST_STREAM), connection ok.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, MalformedHpackBlockIsCompressionStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t rst_before = count_frames(io.output, FrameType::RST_STREAM);

    // 0x80 == Indexed Header Field with index 0, which is illegal per RFC 7541
    // §6.1 -> _hpack_decoder.decode returns false -> on_stream_error(
    // COMPRESSION_ERROR) -> RST_STREAM. The connection is NOT torn down.
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, {0x80});
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok()); // stream-level, connection survives
    EXPECT_EQ(io.request_count, 0); // never dispatched
    EXPECT_GT(count_frames(io.output, FrameType::RST_STREAM), rst_before);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::COMPRESSION_ERROR);
}

// ===========================================================================
// DATA frame flow control
// ===========================================================================

TEST(HTTP2ServerProtocol, DataFrameDeliversBodyAndDispatchesOnEndStream) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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

// A frame whose declared payload length exceeds our advertised MAX_FRAME_SIZE
// (default 16384) is rejected at header-parse time -> FRAME_SIZE_ERROR
// (RFC 9113 §4.2).
TEST(HTTP2ServerProtocol, DataFrameExceedingMaxFrameSizeIsFrameSizeError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_post_stream_open(protocol, io, 1, "/toobig");
    ASSERT_TRUE(protocol.ok());

    // 16385 > DEFAULT_SETTINGS_MAX_FRAME_SIZE (16384).
    std::vector<uint8_t> oversized(qb::protocol::http2::DEFAULT_SETTINGS_MAX_FRAME_SIZE + 1u, 0x5A);
    push_frame(io, FrameType::DATA, qb::protocol::http2::FLAG_END_STREAM, 1, oversized);
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

// An unknown / extension frame type must be ignored (RFC 9113 §4.1) and leave
// the connection healthy.
TEST(HTTP2ServerProtocol, UnknownFrameTypeIsIgnored) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t goaway_before = count_frames(io.output, FrameType::GOAWAY);

    // Type 0x1F is unassigned; the framer discards it without error.
    push_frame(io, static_cast<FrameType>(0x1F), 0, 0, {0xDE, 0xAD, 0xBE, 0xEF});
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(count_frames(io.output, FrameType::GOAWAY), goaway_before);

    // A normal request still works afterward, proving the parser stayed in sync
    // (the unknown frame's payload was fully consumed).
    open_get_stream_end_stream(protocol, io, 1, "/after-unknown");
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
}

// ===========================================================================
// WINDOW_UPDATE
// ===========================================================================

TEST(HTTP2ServerProtocol, WindowUpdateZeroIncrementOnStreamZeroIsProtocolError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t    before = io.output.size();
    std::vector<uint8_t> opaque = {1, 2, 3, 4, 5, 6, 7, 8};
    push_frame(io, FrameType::PING, 0, 0, opaque);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    // The exact next PING frame emitted after the request is a PONG: PING + ACK
    // on stream 0 with an 8-octet payload.
    const auto pong = first_frame_at_or_after(io.output, FrameType::PING, before);
    ASSERT_TRUE(pong.has_value());
    EXPECT_NE(pong->flags & qb::protocol::http2::FLAG_ACK, 0);
    EXPECT_EQ(pong->stream_id, 0u);
    EXPECT_EQ(pong->payload_length, 8u);
}

TEST(HTTP2ServerProtocol, PingAckFromClientIsNotEchoed) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t    pings_before = count_frames(io.output, FrameType::PING);
    std::vector<uint8_t> opaque       = {8, 7, 6, 5, 4, 3, 2, 1};
    push_frame(io, FrameType::PING, qb::protocol::http2::FLAG_ACK, 0, opaque);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    // A PING ACK is consumed silently; no new PING frame is emitted.
    EXPECT_EQ(count_frames(io.output, FrameType::PING), pings_before);
}

TEST(HTTP2ServerProtocol, PingWrongPayloadSizeIsFrameSizeError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::PING, 0, 0, {1, 2, 3, 4}); // 4 != 8
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, PingZeroPayloadIsFrameSizeError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::PING, 0, 0, {}); // zero-payload PING -> FRAME_SIZE_ERROR
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, PingOnNonZeroStreamIsProtocolError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open a stream (POST, no END_STREAM) so it has a live context.
    open_post_stream_open(protocol, io, 1, "/rst");
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::RST_STREAM, 0, 1, {0x00, 0x00, 0x08}); // 3 != 4
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, RstStreamOnStreamZeroIsProtocolError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::RST_STREAM, 0, 0, {0x00, 0x00, 0x00, 0x08});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, GoAwayFromClientWithErrorClosesConnection) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FrameType::PRIORITY, 0, 1, {0x00, 0x00, 0x00, 0x00}); // 4 != 5
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::FRAME_SIZE_ERROR);
}

TEST(HTTP2ServerProtocol, PriorityOnStreamZeroIsProtocolError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);

    // Establish an open stream via a direct GET HEADERS dispatch. END_STREAM here
    // -> HALF_CLOSED_REMOTE, which send_response accepts.
    auto headers = make_headers_frame(1, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM,
                                      default_request_headers("/resp"));
    protocol.on(std::move(headers));
    ASSERT_EQ(io.request_count, 1);

    const std::size_t before = io.output.size();

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    EXPECT_TRUE(protocol.send_response(1, response));

    // The exact next HEADERS frame emitted is the response: stream 1, carrying
    // both END_HEADERS and END_STREAM (no body).
    const auto resp_headers = first_frame_at_or_after(io.output, FrameType::HEADERS, before);
    ASSERT_TRUE(resp_headers.has_value());
    EXPECT_EQ(resp_headers->stream_id, 1u);
    EXPECT_NE(resp_headers->flags & qb::protocol::http2::FLAG_END_STREAM, 0);
    EXPECT_NE(resp_headers->flags & qb::protocol::http2::FLAG_END_HEADERS, 0);
    EXPECT_FALSE(output_has_frame(io.output, FrameType::DATA));
    EXPECT_EQ(io.stream_error_count, 0);
}

TEST(HTTP2ServerProtocol, SendResponseWithBodyEmitsHeadersAndData) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);

    auto headers = make_headers_frame(1, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM,
                                      default_request_headers("/body"));
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
    EXPECT_EQ(sum_data_bytes(io.output, 1), 10u);
    EXPECT_TRUE(data_end_stream_seen(io.output, 1));
}

TEST(HTTP2ServerProtocol, SendResponseOnUnknownStreamReturnsFalse) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    // No stream 7 exists -> send_response returns false, no error event.
    EXPECT_FALSE(protocol.send_response(7, response));
    EXPECT_EQ(io.stream_error_count, 0);
}

TEST(HTTP2ServerProtocol, SendResponseForbiddenHeaderIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);

    auto headers = make_headers_frame(1, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM,
                                      default_request_headers("/forbidden"));
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    push_preface(io);
    // Client SETTINGS enabling push (SETTINGS_ENABLE_PUSH = 1).
    push_frame(io, FrameType::SETTINGS, 0, 0, encode_settings_payload({{Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 1}}));
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open a client request stream that stays OPEN (POST, no END_STREAM) so the
    // associated stream is in a valid state for PUSH_PROMISE.
    open_post_stream_open(protocol, io, 1, "/parent");
    ASSERT_TRUE(protocol.ok());

    qb::http::Request promised{qb::io::uri{"https://example.test/asset.css"}};
    promised.method() = qb::http::method::GET;

    const std::size_t before  = io.output.size();
    auto              failure = protocol.send_push_promise(1, 2, std::move(promised));
    EXPECT_FALSE(failure.has_value()); // std::nullopt == success

    // The exact next emitted frame of interest is a PUSH_PROMISE associated with
    // stream 1 (the promised stream id lives in the payload, not the header).
    const auto pp = first_frame_at_or_after(io.output, FrameType::PUSH_PROMISE, before);
    ASSERT_TRUE(pp.has_value());
    EXPECT_EQ(pp->stream_id, 1u);
}

TEST(HTTP2ServerProtocol, SendPushPromiseRejectedWhenPeerDisablesPush) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    // Default handshake (empty SETTINGS) does NOT enable push; server default
    // _peer_allows_push is true initially, so explicitly disable via SETTINGS.
    push_preface(io);
    push_frame(io, FrameType::SETTINGS, 0, 0, encode_settings_payload({{Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 0}}));
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_post_stream_open(protocol, io, 1, "/parent");
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
// These tests target the send path in server.h:
//   - send_response_body buffering when the peer window is exhausted
//   - try_send_pending_data_for_stream flush on stream/connection WINDOW_UPDATE
//   - send_window_update (stream + connection auto-emit)
//   - conditionally_send_connection_window_update
//   - update_initial_peer_window_size via SETTINGS_INITIAL_WINDOW_SIZE
//   - try_close_stream_context / are_all_relevant_streams_closed lifecycle
//   - on_connection_error / on_stream_error / send_goaway_and_close
//   - send_rst_stream, chunked DATA, trailers
// ===========================================================================

// ---------------------------------------------------------------------------
// Flow control: small peer window -> body queues -> WINDOW_UPDATE flushes
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, SmallInitialWindowQueuesBodyUntilStreamWindowUpdate) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    // Client advertises a tiny send window of 10 for streams the server sends on.
    handshake_with_initial_window(protocol, io, 10);
    ASSERT_TRUE(protocol.ok());

    // Open a GET stream (END_STREAM) -> dispatched, HALF_CLOSED_REMOTE.
    open_get_stream_end_stream(protocol, io, 1, "/queued");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    // Response body (30 bytes) > stream peer window (10) -> only the first 10
    // bytes are written as DATA; the rest is buffered.
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
    make_window_update_frame(io, 1, 1000);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(sum_data_bytes(io.output, 1), 30u); // full body now flushed
    EXPECT_TRUE(data_end_stream_seen(io.output, 1));
}

TEST(HTTP2ServerProtocol, ConnectionWindowExhaustionQueuesBodyUntilConnectionWindowUpdate) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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

    // Open a second stream that stays OPEN so its body cannot be sent because the
    // *connection* send window is now 0 even though the stream window is full.
    open_post_stream_open(protocol, io, 3, "/connwin2");
    ASSERT_TRUE(protocol.ok());

    qb::http::Response second;
    second.status() = qb::http::status::OK;
    second.body()   = std::string(50, 'b');
    ASSERT_TRUE(protocol.send_response(3, second));
    // Connection window is 0 -> body queues, nothing on the wire for stream 3.
    EXPECT_EQ(sum_data_bytes(io.output, 3), 0u);
    EXPECT_FALSE(data_end_stream_seen(io.output, 3));

    // A connection-level WINDOW_UPDATE (stream 0) releases the window and the
    // on(WindowUpdateFrame) handler drains pending data for all streams.
    make_window_update_frame(io, 0, 10000);
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
// non-deterministic SIGSEGV).
TEST(HTTP2ServerProtocol, ConnectionWindowUpdateFlushClosesStreamsMidLoopNoUAF) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    make_window_update_frame(io, 0, 1000000);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_post_stream_open(protocol, io, 1, "/upload");
    ASSERT_TRUE(protocol.ok());

    const std::size_t window_updates_before = count_frames(io.output, FrameType::WINDOW_UPDATE);

    // Send the body as several DATA frames. Each frame stays under the server's
    // advertised MAX_FRAME_SIZE (16384), so use 12000-byte chunks. Cumulative
    // inbound (48000) stays below the windows but crosses both WINDOW_UPDATE
    // thresholds, so the server emits stream-level + connection-level updates.
    const std::vector<uint8_t> chunk(12000, 0x7A);
    push_frame(io, FrameType::DATA, 0, 1, chunk);
    push_frame(io, FrameType::DATA, 0, 1, chunk);
    push_frame(io, FrameType::DATA, 0, 1, chunk);
    push_frame(io, FrameType::DATA, qb::protocol::http2::FLAG_END_STREAM, 1, chunk);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);

    // Pin both a stream-level (stream 1) and a connection-level (stream 0)
    // WINDOW_UPDATE, each advertising a POSITIVE increment (decoded from the
    // 4-octet big-endian payload that follows the 9-byte frame header).
    bool     stream_wu = false, conn_wu = false;
    uint32_t stream_inc = 0, conn_inc = 0;
    {
        const char       *data   = io.output.cbegin();
        const std::size_t total  = io.output.size();
        std::size_t       offset = 0;
        while (offset + h2::FRAME_HEADER_SIZE <= total) {
            const auto fh   = peek_frame_header(io.output, offset);
            const auto plen = fh.get_payload_length();
            if (fh.get_type() == FrameType::WINDOW_UPDATE && plen == 4u
                && offset + h2::FRAME_HEADER_SIZE + 4u <= total) {
                const uint8_t *p = reinterpret_cast<const uint8_t *>(data + offset + h2::FRAME_HEADER_SIZE);
                const uint32_t inc =
                    (static_cast<uint32_t>(p[0] & 0x7F) << 24) | (static_cast<uint32_t>(p[1]) << 16)
                    | (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
                if (fh.get_stream_id() == 1) {
                    stream_wu  = true;
                    stream_inc = std::max(stream_inc, inc);
                } else if (fh.get_stream_id() == 0) {
                    conn_wu  = true;
                    conn_inc = std::max(conn_inc, inc);
                }
            }
            offset += h2::FRAME_HEADER_SIZE + plen;
        }
    }
    EXPECT_GT(count_frames(io.output, FrameType::WINDOW_UPDATE), window_updates_before);
    EXPECT_TRUE(stream_wu);
    EXPECT_TRUE(conn_wu);
    EXPECT_GT(stream_inc, 0u); // a real, positive advertised increment
    EXPECT_GT(conn_inc, 0u);
}

// ---------------------------------------------------------------------------
// SETTINGS_INITIAL_WINDOW_SIZE change retroactively unblocks a pending stream
// (update_initial_peer_window_size delta path + pending flush).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, InitialWindowSizeIncreaseFlushesPendingStream) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    // Start with a window of 0 so the server can send nothing on a new stream.
    handshake_with_initial_window(protocol, io, 0);
    ASSERT_TRUE(protocol.ok());

    // Open a POST stream that stays OPEN (no END_STREAM). update_initial_peer_
    // window_size only adjusts OPEN / HALF_CLOSED_LOCAL / RESERVED_LOCAL streams.
    open_post_stream_open(protocol, io, 1, "/grow");
    ASSERT_TRUE(protocol.ok());

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = std::string(20, 'z');
    ASSERT_TRUE(protocol.send_response(1, response));
    // peer window is 0 -> nothing sent, body fully queued.
    EXPECT_EQ(sum_data_bytes(io.output, 1), 0u);
    EXPECT_FALSE(data_end_stream_seen(io.output, 1));

    // Raise SETTINGS_INITIAL_WINDOW_SIZE to 1000. update_initial_peer_window_size
    // applies the +1000 delta to the open stream's peer_window_size (was 0) and
    // flushes it.
    push_frame(io, FrameType::SETTINGS, 0, 0,
               encode_settings_payload({{Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 1000}}));
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(sum_data_bytes(io.output, 1), 20u);
    EXPECT_TRUE(data_end_stream_seen(io.output, 1));
}

// ---------------------------------------------------------------------------
// Chunked DATA: a body larger than max_frame_size is split into >1 DATA frames.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, LargeBodyIsChunkedAcrossMultipleDataFrames) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    // Generous windows so flow control never blocks.
    handshake_with_initial_window(protocol, io, qb::protocol::http2::MAX_WINDOW_SIZE_LIMIT);
    ASSERT_TRUE(protocol.ok());
    // Lift the connection send window well above the body size.
    make_window_update_frame(io, 0, 1000000);
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
    EXPECT_GE(count_frames(io.output, FrameType::DATA), 3u);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_get_stream_end_stream(protocol, io, 1, "/trailers");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "payload";
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_get_stream_end_stream(protocol, io, 1, "/close");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);
    EXPECT_FALSE(protocol.is_stream_closed(1)); // still open before response

    qb::http::Response response;
    response.status() = qb::http::status::NO_CONTENT; // 204, no body
    ASSERT_TRUE(protocol.send_response(1, response));

    // After send the stream reaches CLOSED and try_close_stream_context erases
    // the context, so is_stream_closed (unknown streams treated as closed) is true.
    EXPECT_TRUE(protocol.is_stream_closed(1));
    // A second send_response on the now-gone stream returns false (no crash).
    EXPECT_FALSE(protocol.send_response(1, response));
}

TEST(HTTP2ServerProtocol, MultipleConcurrentStreamsRespondIndependently) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    open_post_stream_open(protocol, io, 1, "/abort");
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();
    protocol.send_rst_stream(1, ErrorCode::INTERNAL_ERROR, "explicit abort");

    EXPECT_TRUE(protocol.ok()); // RST_STREAM is a stream-level action; connection stays ok
    // The exact next RST_STREAM targets stream 1.
    const auto rst = first_frame_at_or_after(io.output, FrameType::RST_STREAM, before);
    ASSERT_TRUE(rst.has_value());
    EXPECT_EQ(rst->stream_id, 1u);
    EXPECT_EQ(rst->payload_length, 4u); // RST_STREAM carries a 4-octet error code
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::INTERNAL_ERROR);
    EXPECT_TRUE(protocol.is_stream_closed(1)); // context erased / closed
}

// ---------------------------------------------------------------------------
// Error escalation: connection-level protocol violation -> on_connection_error
// -> send_goaway_and_close (GOAWAY emitted, protocol not ok).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, ConnectionLevelErrorEmitsGoawayAndCloses) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();

    // A WINDOW_UPDATE with a zero increment on stream 0 is a connection-level
    // PROTOCOL_ERROR: on(WindowUpdateFrame) calls on_connection_error ->
    // send_goaway_and_close.
    push_frame(io, FrameType::WINDOW_UPDATE, 0, 0, make_window_update_payload(0));
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    // The exact next emitted frame is a GOAWAY on stream 0.
    const auto goaway = first_frame_at_or_after(io.output, FrameType::GOAWAY, before);
    ASSERT_TRUE(goaway.has_value());
    EXPECT_EQ(goaway->stream_id, 0u);
    EXPECT_EQ(io.goaway_count, 1); // server's send_goaway_and_close dispatches the event
    EXPECT_EQ(io.last_goaway_error, ErrorCode::PROTOCOL_ERROR);
}

// ---------------------------------------------------------------------------
// Error escalation: stream-level violation -> send_rst_stream (RST_STREAM
// emitted), connection stays ok.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, StreamLevelErrorEmitsRstStreamKeepsConnection) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Finish a GET request (END_STREAM) -> stream becomes HALF_CLOSED_REMOTE and
    // end_stream_received is set, but stays in the map (no response yet).
    open_get_stream_end_stream(protocol, io, 1, "/streamerr");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    const std::size_t before = io.output.size();

    // A DATA frame after END_STREAM is a stream-level error: on(DataFrame) calls
    // send_rst_stream(STREAM_CLOSED) but does NOT tear down the connection.
    push_frame(io, FrameType::DATA, 0, 1, {'x', 'y'});
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok()); // connection survives a stream-level reset
    const auto rst = first_frame_at_or_after(io.output, FrameType::RST_STREAM, before);
    ASSERT_TRUE(rst.has_value());
    EXPECT_EQ(rst->stream_id, 1u);
}

// ---------------------------------------------------------------------------
// Graceful shutdown: client GOAWAY(NO_ERROR) with all relevant streams already
// closed completes the shutdown (are_all_relevant_streams_closed -> connection
// becomes not ok with NO_ERROR).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, GoawayNoErrorWithClosedStreamsCompletesGracefulShutdown) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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
    // streams remaining, the server completes the graceful shutdown.
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
    Http2FakeIO    io;
    ServerProtocol protocol(io);
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

    // Complete the in-flight stream with a no-body 204. The graceful shutdown
    // completes *during* send_response once the last relevant stream closes, so
    // send_response returns this->ok() == false; the response was still emitted.
    qb::http::Response response;
    response.status() = qb::http::status::NO_CONTENT;
    EXPECT_FALSE(protocol.send_response(1, response));

    EXPECT_TRUE(protocol.is_stream_closed(1)); // stream finalized
    EXPECT_FALSE(protocol.ok());               // graceful shutdown completed
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::NO_ERROR);
}

// ===========================================================================
// Extended coverage wave 2: request-header validation, DATA/HEADERS/CONTINUATION
// edge branches, stream-level WINDOW_UPDATE, concurrency cap, GOAWAY stream
// cleanup. All driven through the same socket-less fake IO. These target the
// reachable error branches in server.h's frame handlers and
// process_complete_header_block that were previously uncovered.
// ===========================================================================

namespace {

// Open a POST stream (END_HEADERS, no END_STREAM) declaring content-length so a
// subsequent DATA frame is body-bearing and the stream stays OPEN.
void
open_post_stream_with_clen(ServerProtocol &protocol, Http2FakeIO &io, uint32_t stream_id, const std::string &path,
                           const std::string &clen) {
    const auto encoded = encode_hpack_headers(
        {{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", path}, {"content-length", clen}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, stream_id, encoded);
    drive(protocol, io);
}

} // namespace

// ---------------------------------------------------------------------------
// Request header validation -> stream-level errors (RST_STREAM, connection ok).
// Each crafts a header block that process_complete_header_block must reject.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, DuplicateMethodPseudoHeaderIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Two ":method" pseudo-headers -> COMPRESSION-safe HPACK but PROTOCOL_ERROR
    // at the pseudo-header validation stage.
    const auto encoded = encode_hpack_headers(
        {{":method", "GET"}, {":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/dup"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok()); // stream-level: connection survives
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, PseudoHeaderAfterRegularHeaderIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // A regular header ("x-early") precedes the ":path" pseudo-header -> the
    // pseudo-after-regular guard fires (pseudo_headers_finished == true).
    const auto encoded = encode_hpack_headers(
        {{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {"x-early", "1"}, {":path", "/late"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, UnknownPseudoHeaderIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // ":bogus" is not a recognized request pseudo-header.
    const auto encoded = encode_hpack_headers(
        {{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/x"}, {":bogus", "v"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, MissingMandatoryPseudoHeaderIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // No ":path" -> missing-mandatory-pseudo-header path.
    const auto encoded = encode_hpack_headers({{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, EmptyPathPseudoHeaderIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // ":path" present but empty -> the empty-path guard fires.
    const auto encoded =
        encode_hpack_headers({{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", ""}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, MissingAuthorityPseudoHeaderIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // No ":authority" (and no Host) -> missing-or-empty-authority guard.
    const auto encoded = encode_hpack_headers({{":method", "GET"}, {":scheme", "https"}, {":path", "/noauth"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, ForbiddenConnectionHeaderInRequestIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // "connection" is a forbidden hop-by-hop header in an HTTP/2 request.
    const auto encoded = encode_hpack_headers(
        {{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/conn"}, {"connection", "keep-alive"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, InvalidContentLengthHeaderIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Non-numeric content-length -> parse_content_length fails.
    const auto encoded = encode_hpack_headers({{":method", "POST"},
                                               {":scheme", "https"},
                                               {":authority", "example.test"},
                                               {":path", "/badclen"},
                                               {"content-length", "not-a-number"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, ConflictingContentLengthHeadersIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Two differing content-length values -> conflicting-content-length guard.
    const auto encoded = encode_hpack_headers({{":method", "POST"},
                                               {":scheme", "https"},
                                               {":authority", "example.test"},
                                               {":path", "/conflict"},
                                               {"content-length", "5"},
                                               {"content-length", "9"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ServerProtocol, RequestContentLengthBodyMismatchOnEndStreamIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // content-length 10 but END_STREAM arrives with an empty body (0 bytes) on
    // the headers frame itself -> process_complete_header_block mismatch guard.
    const auto encoded = encode_hpack_headers({{":method", "POST"},
                                               {":scheme", "https"},
                                               {":authority", "example.test"},
                                               {":path", "/clenmismatch"},
                                               {"content-length", "10"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

// ---------------------------------------------------------------------------
// DATA-frame edge branches in on(DataFrame).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, DataBeyondDeclaredContentLengthIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open a POST stream declaring content-length 2.
    open_post_stream_with_clen(protocol, io, 1, "/overflow", "2");
    ASSERT_TRUE(protocol.ok());

    const std::size_t rst_before = count_frames(io.output, FrameType::RST_STREAM);

    // 5 bytes of DATA (no END_STREAM) exceeds the declared content-length (2) ->
    // body_pipe.size() > *expected_content_length -> RST_STREAM(PROTOCOL_ERROR).
    push_frame(io, FrameType::DATA, 0, 1, {'a', 'b', 'c', 'd', 'e'});
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok()); // stream-level
    EXPECT_EQ(io.request_count, 0);
    EXPECT_GT(count_frames(io.output, FrameType::RST_STREAM), rst_before);
}

TEST(HTTP2ServerProtocol, DataOnFullyClosedAndErasedStreamIsRstStreamClosed) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Complete a stream so its context is erased but its id is recorded as a
    // past client-initiated id (1 <= _last_client_initiated_stream_id).
    open_get_stream_end_stream(protocol, io, 1, "/gone");
    ASSERT_TRUE(protocol.ok());
    qb::http::Response response;
    response.status() = qb::http::status::NO_CONTENT;
    ASSERT_TRUE(protocol.send_response(1, response));
    ASSERT_TRUE(protocol.is_stream_closed(1));

    const std::size_t rst_before = count_frames(io.output, FrameType::RST_STREAM);

    // DATA for the erased-but-known stream id 1 -> the "not in map but
    // <= last_client_initiated" branch RSTs with STREAM_CLOSED, connection ok.
    push_frame(io, FrameType::DATA, 0, 1, {'z'});
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_GT(count_frames(io.output, FrameType::RST_STREAM), rst_before);
    EXPECT_EQ(io.goaway_count, 0);
}

// ---------------------------------------------------------------------------
// HEADERS-frame edge branches.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, UnexpectedHeadersAfterEndStreamNoTrailersIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Finish a GET request (END_STREAM) -> HALF_CLOSED_REMOTE, no trailers
    // expected (no "Trailer" was advertised, no body pending).
    open_get_stream_end_stream(protocol, io, 1, "/done");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    const std::size_t rst_before = count_frames(io.output, FrameType::RST_STREAM);

    // A second HEADERS on the now half-closed-remote stream with no trailers
    // expected -> RST_STREAM(PROTOCOL_ERROR), connection survives.
    const auto encoded = encode_hpack_headers(default_request_headers("/again"));
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_GT(count_frames(io.output, FrameType::RST_STREAM), rst_before);
}

TEST(HTTP2ServerProtocol, NonContinuationFrameWhileHeaderBlockOpenIsConnectionError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t rst_before = count_frames(io.output, FrameType::RST_STREAM);

    // Begin an incomplete header block on stream 1 (no END_HEADERS). The base
    // framer now requires the very next frame to be a CONTINUATION for stream 1.
    const auto encoded1 = encode_hpack_headers(default_request_headers("/s1"));
    ASSERT_GE(encoded1.size(), 2u);
    const std::size_t    half = encoded1.size() / 2;
    std::vector<uint8_t> part1(encoded1.begin(), encoded1.begin() + half);
    push_frame(io, FrameType::HEADERS, 0 /* no END_HEADERS */, 1, part1);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // A HEADERS frame for a *different* stream id (3) while stream 1's block is
    // open is NOT a CONTINUATION -> the framer's _continuation_required gate
    // fires. handle_framer_detected_error routes the error to the open stream
    // (stream 1, non-zero context) as an RST_STREAM and marks the connection
    // not-ok with PROTOCOL_ERROR.
    const auto encoded3 = encode_hpack_headers(default_request_headers("/s3"));
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 3, encoded3);
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_GT(count_frames(io.output, FrameType::RST_STREAM), rst_before);
}

TEST(HTTP2ServerProtocol, MaxConcurrentStreamsExceededRefusesNewStream) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // The server advertises SETTINGS_MAX_CONCURRENT_STREAMS = 50. Open 50 OPEN
    // (POST, no END_STREAM) client streams so they all stay active.
    uint32_t sid = 1;
    for (int i = 0; i < 50; ++i, sid += 2) {
        open_post_stream_open(protocol, io, sid, "/c");
        ASSERT_TRUE(protocol.ok());
    }

    const std::size_t rst_before = count_frames(io.output, FrameType::RST_STREAM);

    // The 51st new stream must be refused with RST_STREAM(REFUSED_STREAM); the
    // connection stays healthy.
    const auto encoded = encode_hpack_headers(default_request_headers("/overflow"));
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, sid, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    ASSERT_GT(count_frames(io.output, FrameType::RST_STREAM), rst_before);
    bool refused_on_new = false;
    for (const auto &f : parse_emitted_frames(io.output)) {
        if (f.type == FrameType::RST_STREAM && f.stream_id == sid) {
            refused_on_new = true;
        }
    }
    EXPECT_TRUE(refused_on_new);
}

// ---------------------------------------------------------------------------
// CONTINUATION on an unknown stream id (matches _current_header_stream_id but
// the stream was erased) -> connection PROTOCOL_ERROR. Reach it by opening a
// partial header block on a stream, then nothing else can erase it, so instead
// drive the simpler "expecting_continuation == false after END_HEADERS" guard:
// a CONTINUATION after a completed HEADERS block.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, ContinuationAfterCompletedHeadersIsConnectionError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // A complete HEADERS block (END_HEADERS) clears _current_header_stream_id to
    // 0. A following CONTINUATION then fails the stream_id == _current_header_
    // stream_id (0) guard -> send_goaway_and_close(PROTOCOL_ERROR).
    const auto encoded = encode_hpack_headers(default_request_headers("/cont"));
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS, 1, encoded);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t goaway_before = count_frames(io.output, FrameType::GOAWAY);

    const auto extra = encode_hpack_headers({{"x-trailer", "v"}});
    push_frame(io, FrameType::CONTINUATION, qb::protocol::http2::FLAG_END_HEADERS, 1, extra);
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_GT(count_frames(io.output, FrameType::GOAWAY), goaway_before);
}

// ---------------------------------------------------------------------------
// Stream-level WINDOW_UPDATE on an idle / unknown stream.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, WindowUpdateOnIdleHigherStreamIsConnectionError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t goaway_before = count_frames(io.output, FrameType::GOAWAY);

    // WINDOW_UPDATE for stream 7 which is > _last_client_initiated_stream_id (0)
    // and not in the map -> "WINDOW_UPDATE on idle stream" GOAWAY.
    make_window_update_frame(io, 7, 1024);
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_GT(count_frames(io.output, FrameType::GOAWAY), goaway_before);
}

// Note: a zero-increment WINDOW_UPDATE on a *non-zero* stream cannot reach
// on(WindowUpdateFrame)'s stream-level send_rst_stream branch: the base framer
// (handle_window_update_frame_payload) rejects a zero increment as a connection
// PROTOCOL_ERROR before dispatch, regardless of stream id. That stream-level
// zero-increment arm in server.h is therefore unreachable from raw bytes.

// ---------------------------------------------------------------------------
// RST_STREAM on an idle (never-opened) higher stream id -> connection error.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, RstStreamOnIdleHigherStreamIsConnectionError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t goaway_before = count_frames(io.output, FrameType::GOAWAY);

    // RST_STREAM for stream 9 which is > _last_client_initiated_stream_id (0)
    // and not in the map -> "RST_STREAM frame received on idle stream" GOAWAY.
    push_frame(io, FrameType::RST_STREAM, 0, 9, {0x00, 0x00, 0x00, static_cast<uint8_t>(ErrorCode::CANCEL)});
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    EXPECT_GT(count_frames(io.output, FrameType::GOAWAY), goaway_before);
}

// ---------------------------------------------------------------------------
// New HEADERS arriving during graceful shutdown is refused.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, NewStreamDuringGracefulShutdownIsRefused) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Leave an in-flight stream so a NO_ERROR GOAWAY defers (does not close).
    open_get_stream_end_stream(protocol, io, 1, "/inflight");
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    // Client GOAWAY(NO_ERROR, last_stream_id=1) -> _graceful_shutdown_initiated,
    // connection still ok because stream 1 is active.
    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    push_frame(io, FrameType::GOAWAY, 0, 0, payload);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());

    const std::size_t rst_before = count_frames(io.output, FrameType::RST_STREAM);

    // A brand-new stream (id 3) after graceful shutdown started -> RST_STREAM(
    // REFUSED_STREAM), connection survives.
    const auto encoded = encode_hpack_headers(default_request_headers("/new"));
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 3, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    ASSERT_GT(count_frames(io.output, FrameType::RST_STREAM), rst_before);
    bool refused_on_3 = false;
    for (const auto &f : parse_emitted_frames(io.output)) {
        if (f.type == FrameType::RST_STREAM && f.stream_id == 3) {
            refused_on_3 = true;
        }
    }
    EXPECT_TRUE(refused_on_3);
    EXPECT_EQ(io.request_count, 1); // new stream never dispatched
}

// ---------------------------------------------------------------------------
// GOAWAY(error) implicitly closes active client streams above last_stream_id
// and notifies the application per stream (client-stream cleanup loop).
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, GoAwayErrorImplicitlyClosesHigherClientStreams) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open three live client streams (1, 3, 5).
    open_post_stream_open(protocol, io, 1, "/a");
    open_post_stream_open(protocol, io, 3, "/b");
    open_post_stream_open(protocol, io, 5, "/c");
    ASSERT_TRUE(protocol.ok());

    // GOAWAY with an error code (INTERNAL_ERROR=0x2) and last_stream_id=1.
    // Streams 3 and 5 are > last_stream_id and active -> each is implicitly
    // closed and reported via Http2StreamErrorEvent.
    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, static_cast<uint8_t>(ErrorCode::INTERNAL_ERROR)};
    push_frame(io, FrameType::GOAWAY, 0, 0, payload);
    drive(protocol, io);

    // The error GOAWAY tears down the connection.
    EXPECT_FALSE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, ErrorCode::INTERNAL_ERROR);
    // At least the two streams above last_stream_id (3, 5) were reported closed.
    EXPECT_GE(io.stream_error_count, 2);
}

// ---------------------------------------------------------------------------
// Client SETTINGS that change server-relevant peer parameters are applied.
// HEADER_TABLE_SIZE + MAX_CONCURRENT_STREAMS + MAX_HEADER_LIST_SIZE branches.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, ClientSettingsApplyMultipleParametersAndAck) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    push_preface(io);

    // A SETTINGS frame exercising the HEADER_TABLE_SIZE, MAX_CONCURRENT_STREAMS,
    // MAX_FRAME_SIZE and MAX_HEADER_LIST_SIZE apply-switch arms in one go.
    const auto payload = encode_settings_payload({
        {Http2SettingIdentifier::SETTINGS_HEADER_TABLE_SIZE, 8192},
        {Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS, 7},
        {Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 32768},
        {Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE, 16384},
    });
    push_frame(io, FrameType::SETTINGS, 0, 0, payload);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    // Exactly one ACK for the non-ACK client SETTINGS.
    std::size_t settings_ack = 0;
    for (const auto &f : parse_emitted_frames(io.output)) {
        if (f.type == FrameType::SETTINGS && (f.flags & qb::protocol::http2::FLAG_ACK)) {
            ++settings_ack;
        }
    }
    EXPECT_EQ(settings_ack, 1u);

    // A normal request still works after the settings exchange, proving the
    // peer-max-frame-size update kept the parser in sync.
    open_get_stream_end_stream(protocol, io, 1, "/after-settings");
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1);
}

// ---------------------------------------------------------------------------
// A request whose ":method" decodes to an unknown verb is rejected.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, InvalidMethodValueIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // ":method" = "BOGUSVERB" parses to Method::Value::UNINITIALIZED ->
    // send_rst_stream(PROTOCOL_ERROR). All other pseudo-headers are valid so the
    // failure is specifically the method-validity guard.
    const auto encoded = encode_hpack_headers(
        {{":method", "BOGUSVERB"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/m"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, encoded);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 0);
    EXPECT_GT(count_frames(io.output, FrameType::RST_STREAM), 0u);
}

// ---------------------------------------------------------------------------
// Trailers carrying a pseudo-header (illegal) are rejected.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PRIORITY for a *known* (live) stream stores priority info (the existing-stream
// arm of on(PriorityFrame)); connection stays healthy.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, PriorityForExistingStreamIsStored) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open a live stream so the PRIORITY frame targets an existing context.
    open_post_stream_open(protocol, io, 1, "/prio");
    ASSERT_TRUE(protocol.ok());

    const std::size_t goaway_before = count_frames(io.output, FrameType::GOAWAY);

    // PRIORITY payload: 4-byte stream dependency + 1-byte weight.
    std::vector<uint8_t> payload = {0x00, 0x00, 0x00, 0x00, 0x20};
    push_frame(io, FrameType::PRIORITY, 0, 1, payload);
    drive(protocol, io);

    // The priority info is stored on the existing stream; no error, no GOAWAY.
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(count_frames(io.output, FrameType::GOAWAY), goaway_before);
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_FALSE(protocol.is_stream_closed(1)); // stream stays live after PRIORITY
}

// ---------------------------------------------------------------------------
// A stream-level WINDOW_UPDATE that would push the stream send window past the
// 2^31-1 maximum is a stream-level FLOW_CONTROL_ERROR (RST_STREAM); connection
// survives.
// ---------------------------------------------------------------------------

TEST(HTTP2ServerProtocol, StreamWindowUpdateOverflowIsFlowControlStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    // Open the stream's send (peer) window to its maximum so any positive
    // increment overflows. Advertise SETTINGS_INITIAL_WINDOW_SIZE = MAX so the
    // new stream starts with peer_window_size == 2^31-1.
    handshake_with_initial_window(protocol, io, qb::protocol::http2::MAX_WINDOW_SIZE_LIMIT);
    ASSERT_TRUE(protocol.ok());

    // Open a live OPEN stream; its peer_window_size is now MAX_WINDOW_SIZE_LIMIT.
    open_post_stream_open(protocol, io, 1, "/wuoverflow");
    ASSERT_TRUE(protocol.ok());

    const std::size_t rst_before = count_frames(io.output, FrameType::RST_STREAM);

    // Any positive increment now makes peer_window_size exceed the maximum ->
    // stream WINDOW_UPDATE overflow guard -> RST_STREAM(FLOW_CONTROL_ERROR).
    make_window_update_frame(io, 1, 1);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok()); // stream-level; connection survives
    ASSERT_GT(count_frames(io.output, FrameType::RST_STREAM), rst_before);
    bool rst_on_1 = false;
    for (const auto &f : parse_emitted_frames(io.output)) {
        if (f.type == FrameType::RST_STREAM && f.stream_id == 1) {
            rst_on_1 = true;
        }
    }
    EXPECT_TRUE(rst_on_1);
}

TEST(HTTP2ServerProtocol, TrailersWithPseudoHeaderIsStreamError) {
    Http2FakeIO    io;
    ServerProtocol protocol(io);
    do_handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Main headers for a POST that stays OPEN (no END_STREAM) so a trailers
    // HEADERS block is the next thing the server processes for this stream.
    open_post_stream_open(protocol, io, 1, "/trailpseudo");
    ASSERT_TRUE(protocol.ok());

    const std::size_t rst_before = count_frames(io.output, FrameType::RST_STREAM);

    // A trailers HEADERS block (END_STREAM) containing a pseudo-header ":x" ->
    // the trailers-block guard rejects pseudo-headers -> RST_STREAM.
    const auto trailers = encode_hpack_headers({{":x", "illegal"}});
    push_frame(io, FrameType::HEADERS, qb::protocol::http2::FLAG_END_HEADERS | qb::protocol::http2::FLAG_END_STREAM, 1, trailers);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_GT(count_frames(io.output, FrameType::RST_STREAM), rst_before);
    EXPECT_EQ(io.last_stream_error, ErrorCode::PROTOCOL_ERROR);
}

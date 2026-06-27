/**
 * @file qbm/http/tests/unit/http2/http2-protocol-coverage.cpp
 * @brief Additional protocol-branch coverage for the HTTP/2 server & client state machines.
 *
 * The existing http2-server-protocol / http2-client-protocol suites are broad,
 * but a handful of meaningful RFC 9113 branches are still unexercised. This TU
 * drives those specific paths through the shared socket-less FakeIO harness:
 *
 * Server (qb::protocol::http2::ServerHttp2Protocol):
 *   - RST_STREAM(NO_ERROR): the stream closes but NO Http2StreamErrorEvent is
 *     dispatched (the `error_code != NO_ERROR` guard, server.h ~702).
 *   - Request trailers happy path: HEADERS(no END_STREAM) -> DATA -> trailer
 *     HEADERS(END_STREAM) assembles and dispatches the request with the trailer
 *     field present (server.h trailers block ~1616-1653).
 *   - Trailers with a forbidden field / a pseudo-header -> stream error.
 *   - Trailers HEADERS block that does not end the stream -> RST PROTOCOL_ERROR.
 *   - DATA arriving after the client already set END_STREAM -> RST STREAM_CLOSED.
 *   - is_valid_header_field static helper (server.h ~142) direct call.
 *   - reset() clears stream state and re-arms the parser for a fresh preface.
 *
 * Client (qb::protocol::http2::ClientHttp2Protocol):
 *   - send_request refused after a graceful GOAWAY was received (the
 *     `_received_goaway` arm of the guard at client.h ~1003), distinct from the
 *     not-ok arm.
 *   - send_request refused at the peer's MAX_CONCURRENT_STREAMS limit
 *     (client.h ~1009), driven via a server SETTINGS frame.
 *   - PING with the ACK flag set is silently ignored (no echo) — the false arm
 *     of `if (!(flags & 0x01))` (client.h ping handler).
 *
 * Pure logic: no socket, no qb::Main, no event loop, no SSL. Deterministic.
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

namespace h2 = qb::protocol::http2;

using qb::http::test::default_request_headers;
using qb::http::test::do_handshake;
using qb::http::test::drive;
using qb::http::test::encode_hpack_headers;
using qb::http::test::Http2ClientFakeIO;
using qb::http::test::Http2FakeIO;
using qb::http::test::output_has_frame;
using qb::http::test::parse_emitted_frames;
using qb::http::test::push_frame;
using qb::http::test::push_preface;

using FT     = h2::FrameType;
using Server = h2::ServerHttp2Protocol<Http2FakeIO>;
using Client = h2::ClientHttp2Protocol<Http2ClientFakeIO>;

using h2::FLAG_END_HEADERS;
using h2::FLAG_END_STREAM;

namespace {

// Standard server handshake: preface + empty client SETTINGS, leaving the
// server post-handshake and ok().
void
handshake(Server &protocol, Http2FakeIO &io) {
    push_preface(io);
    push_frame(io, FT::SETTINGS, 0, 0, {});
    drive(protocol, io);
}

// Open a request stream that is NOT yet ended: HEADERS(END_HEADERS, no
// END_STREAM) carrying a valid POST pseudo-header set so the stream is OPEN and
// the server is willing to receive a body + trailers.
void
open_post_stream(Server &protocol, Http2FakeIO &io, uint32_t stream_id, const char *path = "/upload") {
    auto headers     = default_request_headers(path);
    headers[0].value = "POST"; // :method
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS, stream_id, encode_hpack_headers(headers));
    drive(protocol, io);
}

// Build a RST_STREAM payload (4-octet big-endian error code).
[[nodiscard]] std::vector<uint8_t>
rst_payload(h2::ErrorCode ec) {
    const uint32_t code = static_cast<uint32_t>(ec);
    return {static_cast<uint8_t>((code >> 24) & 0xFF), static_cast<uint8_t>((code >> 16) & 0xFF),
            static_cast<uint8_t>((code >> 8) & 0xFF), static_cast<uint8_t>(code & 0xFF)};
}

} // namespace

// ===========================================================================
// Server: RST_STREAM(NO_ERROR) closes the stream WITHOUT a stream-error event
// ===========================================================================

TEST(HTTP2ProtocolCoverage, ServerRstStreamNoErrorClosesWithoutErrorEvent) {
    Http2FakeIO io;
    Server      protocol(io);
    handshake(protocol, io);
    ASSERT_TRUE(protocol.ok());

    // Open a stream (POST, not ended) so it is live and undispatched.
    open_post_stream(protocol, io, 1);
    ASSERT_TRUE(protocol.ok());
    ASSERT_FALSE(protocol.is_stream_closed(1)) << "stream should be open before RST";
    const int errors_before = io.stream_error_count;

    // RST_STREAM with NO_ERROR (0x0): the stream closes, but because the code is
    // NO_ERROR the server must NOT raise an Http2StreamErrorEvent to the app.
    push_frame(io, FT::RST_STREAM, 0, 1, rst_payload(h2::ErrorCode::NO_ERROR));
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok()) << "RST_STREAM is a stream-level action, connection survives";
    EXPECT_TRUE(protocol.is_stream_closed(1));
    EXPECT_EQ(io.stream_error_count, errors_before) << "NO_ERROR RST must not fire a stream-error event";
}

// Contrast: a RST_STREAM with a real error code DOES dispatch the event (this
// pins the difference and proves the NO_ERROR test above is a real branch split).
TEST(HTTP2ProtocolCoverage, ServerRstStreamWithErrorDispatchesEvent) {
    Http2FakeIO io;
    Server      protocol(io);
    handshake(protocol, io);
    open_post_stream(protocol, io, 1);
    ASSERT_TRUE(protocol.ok());

    push_frame(io, FT::RST_STREAM, 0, 1, rst_payload(h2::ErrorCode::CANCEL));
    drive(protocol, io);

    EXPECT_TRUE(protocol.is_stream_closed(1));
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::CANCEL);
}

// ===========================================================================
// Server: request trailers (HEADERS + DATA + trailer HEADERS with END_STREAM)
// ===========================================================================

TEST(HTTP2ProtocolCoverage, ServerRequestTrailersAreAcceptedAndRequestDispatched) {
    Http2FakeIO io;
    Server      protocol(io);
    handshake(protocol, io);

    // Main headers (no END_STREAM): opens the stream for body + trailers.
    open_post_stream(protocol, io, 1);
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 0) << "request not dispatched until END_STREAM";

    // A body DATA frame, still not ending the stream.
    const std::string body = "payload";
    push_frame(io, FT::DATA, 0, 1, std::vector<uint8_t>(body.begin(), body.end()));
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 0);

    // Trailer HEADERS block (a regular field, END_HEADERS + END_STREAM): this
    // closes the stream and dispatches the assembled request.
    const std::vector<qb::protocol::hpack::HeaderField> trailers = {{"x-checksum", "abc123"}};
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, encode_hpack_headers(trailers));
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.request_count, 1) << "trailers with END_STREAM dispatch the request";
    EXPECT_EQ(io.stream_error_count, 0);
    ASSERT_TRUE(io.last_request.has_value());
    // The trailer field is folded into the request's header set.
    EXPECT_EQ(io.last_request->header("x-checksum"), "abc123");
    EXPECT_EQ(io.last_request->body().as<std::string>(), body);
}

TEST(HTTP2ProtocolCoverage, ServerForbiddenTrailerHeaderIsStreamError) {
    Http2FakeIO io;
    Server      protocol(io);
    handshake(protocol, io);
    open_post_stream(protocol, io, 1);
    ASSERT_TRUE(protocol.ok());

    // "transfer-encoding" is forbidden in a trailer section (RFC 9113 §8.1).
    const std::vector<qb::protocol::hpack::HeaderField> trailers = {{"transfer-encoding", "chunked"}};
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, encode_hpack_headers(trailers));
    drive(protocol, io);

    // Stream-level rejection: a RST_STREAM is emitted and the request is NOT dispatched.
    EXPECT_TRUE(output_has_frame(io.output, FT::RST_STREAM));
    EXPECT_EQ(io.request_count, 0);
}

TEST(HTTP2ProtocolCoverage, ServerPseudoHeaderInTrailersIsStreamError) {
    Http2FakeIO io;
    Server      protocol(io);
    handshake(protocol, io);
    open_post_stream(protocol, io, 1);
    ASSERT_TRUE(protocol.ok());

    // A pseudo-header is never legal in a trailer section.
    const std::vector<qb::protocol::hpack::HeaderField> trailers = {{":method", "GET"}};
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, encode_hpack_headers(trailers));
    drive(protocol, io);

    EXPECT_TRUE(output_has_frame(io.output, FT::RST_STREAM));
    EXPECT_EQ(io.request_count, 0);
}

TEST(HTTP2ProtocolCoverage, ServerTrailersWithoutEndStreamIsRstStream) {
    Http2FakeIO io;
    Server      protocol(io);
    handshake(protocol, io);
    open_post_stream(protocol, io, 1);
    ASSERT_TRUE(protocol.ok());

    // A trailer block (after main headers were received) that carries END_HEADERS
    // but NOT END_STREAM violates RFC 9113 — the trailer section must end the
    // stream. The server resets the stream.
    const std::vector<qb::protocol::hpack::HeaderField> trailers = {{"x-trailer", "v"}};
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS, 1, encode_hpack_headers(trailers));
    drive(protocol, io);

    EXPECT_TRUE(output_has_frame(io.output, FT::RST_STREAM));
    EXPECT_EQ(io.request_count, 0);
}

// ===========================================================================
// Server: DATA after the client already sent END_STREAM -> RST STREAM_CLOSED
// ===========================================================================

TEST(HTTP2ProtocolCoverage, ServerDataAfterClientEndStreamIsStreamClosedRst) {
    Http2FakeIO io;
    Server      protocol(io);
    handshake(protocol, io);

    // POST request fully ended at the HEADERS frame (END_STREAM set). After this
    // the stream's end_stream_received is true; the request is dispatched.
    auto headers     = default_request_headers("/done");
    headers[0].value = "POST";
    push_frame(io, FT::HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, encode_hpack_headers(headers));
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.request_count, 1);

    // A trailing DATA frame on the same stream after END_STREAM was received is a
    // STREAM_CLOSED error -> the server emits RST_STREAM and the connection survives.
    const std::string extra = "late";
    push_frame(io, FT::DATA, 0, 1, std::vector<uint8_t>(extra.begin(), extra.end()));
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_TRUE(output_has_frame(io.output, FT::RST_STREAM));
}

// ===========================================================================
// Server: is_valid_header_field static helper (server.h forwarding wrapper)
// ===========================================================================

TEST(HTTP2ProtocolCoverage, ServerIsValidHeaderFieldStaticHelper) {
    // Lowercase token name + clean value -> valid.
    EXPECT_TRUE(Server::is_valid_header_field("content-type", "text/plain"));
    EXPECT_TRUE(Server::is_valid_header_field("x-custom", ""));
    // Uppercase name -> invalid (RFC 9113 §8.2 requires lowercase).
    EXPECT_FALSE(Server::is_valid_header_field("Content-Type", "text/plain"));
    // Empty name -> invalid.
    EXPECT_FALSE(Server::is_valid_header_field("", "v"));
    // Control byte in value -> invalid.
    EXPECT_FALSE(Server::is_valid_header_field("name", "bad\nvalue"));
}

// ===========================================================================
// Server: reset() clears streams and re-arms the parser for a fresh connection
// ===========================================================================

TEST(HTTP2ProtocolCoverage, ServerResetClearsStreamsAndReArmsParser) {
    Http2FakeIO io;
    Server      protocol(io);
    handshake(protocol, io);
    open_post_stream(protocol, io, 1);
    ASSERT_TRUE(protocol.ok());
    ASSERT_FALSE(protocol.is_stream_closed(1));

    // reset() returns the parser to EXPECTING_PREFACE and drops all stream state.
    protocol.reset();
    EXPECT_TRUE(protocol.ok());

    // The previously-open stream is gone (treated as closed/unknown now).
    EXPECT_TRUE(protocol.is_stream_closed(1));

    // After reset the parser again requires a preface: a fresh handshake works.
    io.output.reset();
    handshake(protocol, io);
    EXPECT_TRUE(protocol.ok());
    EXPECT_TRUE(output_has_frame(io.output, FT::SETTINGS)) << "server re-emits its SETTINGS after the new preface";
}

// ===========================================================================
// Client: send_request refused after a graceful GOAWAY was received
// ===========================================================================

TEST(HTTP2ProtocolCoverage, ClientSendRequestRefusedAfterGracefulGoaway) {
    Http2ClientFakeIO io;
    Client            client(io);

    // First request creates an active stream (stream 1, HALF_CLOSED_LOCAL).
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/first");
    ASSERT_TRUE(client.send_request(std::move(req), 1));

    // Feed a graceful GOAWAY (NO_ERROR) whose last_stream_id == 1, so stream 1 is
    // still "relevant" and active. Because not all relevant streams are closed,
    // the protocol stays ok() but records _received_goaway = true.
    h2::Http2FrameData<h2::GoAwayFrame> goaway;
    goaway.header.type = static_cast<uint8_t>(FT::GOAWAY);
    goaway.header.set_stream_id(0);
    goaway.payload.last_stream_id = 1;
    goaway.payload.error_code     = h2::ErrorCode::NO_ERROR;
    client.on(std::move(goaway));

    ASSERT_TRUE(client.ok()) << "graceful GOAWAY with an active relevant stream keeps the connection ok";

    // A subsequent request must be refused via the _received_goaway guard.
    qb::http::Request req2;
    req2.method() = qb::http::method::GET;
    req2.uri()    = qb::io::uri("https://example.test/second");
    EXPECT_FALSE(client.send_request(std::move(req2), 2));
}

// ===========================================================================
// Client: send_request refused at the peer MAX_CONCURRENT_STREAMS limit
// ===========================================================================

TEST(HTTP2ProtocolCoverage, ClientSendRequestRefusedAtConcurrencyLimit) {
    Http2ClientFakeIO io;
    Client            client(io);

    // Server SETTINGS restricting the client to a single concurrent stream.
    h2::Http2FrameData<h2::SettingsFrame> settings;
    settings.header.type = static_cast<uint8_t>(FT::SETTINGS);
    settings.header.set_stream_id(0);
    settings.payload.entries.push_back({h2::Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS, 1});
    client.on(std::move(settings));
    ASSERT_TRUE(client.ok());

    // First request consumes the single allowed stream (it stays active as
    // HALF_CLOSED_LOCAL for a body-less GET).
    qb::http::Request req1;
    req1.method() = qb::http::method::GET;
    req1.uri()    = qb::io::uri("https://example.test/a");
    ASSERT_TRUE(client.send_request(std::move(req1), 1));

    // Second request would exceed the limit -> refused.
    qb::http::Request req2;
    req2.method() = qb::http::method::GET;
    req2.uri()    = qb::io::uri("https://example.test/b");
    EXPECT_FALSE(client.send_request(std::move(req2), 2));
}

// ===========================================================================
// Client: a PING carrying the ACK flag is silently ignored (no echo)
// ===========================================================================

TEST(HTTP2ProtocolCoverage, ClientPingAckIsNotEchoed) {
    Http2ClientFakeIO io;
    Client            client(io);

    // Snapshot the output size after construction (preface + client SETTINGS).
    const std::size_t baseline = io.output.size();

    // Feed (via the wire, the way the framer dispatches PING) a PING that carries
    // the ACK flag — a response to one of OUR pings. The client must NOT echo it
    // back. This is the false arm of `if (!(flags & ACK))` in the PING handler;
    // the request-answered-with-ACK arm is already covered elsewhere.
    push_frame(io, FT::PING, 0x01 /*ACK*/, 0, std::vector<uint8_t>(8, 0xAB));
    drive(client, io);

    EXPECT_TRUE(client.ok());
    EXPECT_EQ(io.output.size(), baseline) << "PING ACK must not produce any output frame";
}

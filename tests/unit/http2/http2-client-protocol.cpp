/**
 * @file qbm/http/tests/test-http2-client-protocol.cpp
 * @brief Unit tests for the HTTP/2 client protocol state machine.
 *
 * Drives qb::protocol::http2::ClientHttp2Protocol over a FakeIO harness (no
 * socket). Exercises the request-serialization path (preface + SETTINGS on
 * construction, HEADERS / DATA emission, odd stream-id assignment) and the
 * frame-ingest path (response assembly, trailers, GOAWAY, RST_STREAM,
 * WINDOW_UPDATE, SETTINGS window deltas, PUSH_PROMISE accept/reject, malformed
 * frames). Where practical, the client's emitted frames are round-tripped into
 * a peer ServerHttp2Protocol for additional confidence.
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
#include <string>

#include "../2/protocol/base.h"
#include "../2/protocol/client.h"
#include "../2/protocol/server.h"

namespace {

namespace h2 = qb::protocol::http2;

// ---------------------------------------------------------------------------
// FakeIO harness for the client protocol. Mirrors the Http2ProtocolHarness used
// in test-http2-header-validator.cpp, but supplies the client-facing handler
// overloads: on(Response&&, uint64_t) and on(Response&&, uint64_t, ErrorCode),
// plus the GOAWAY / PUSH_PROMISE event sinks.
// ---------------------------------------------------------------------------
struct ClientHarness {
    using base_io_t = ClientHarness;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;

    int           response_count      = 0;
    int           stream_error_count  = 0;
    int           goaway_count        = 0;
    int           push_promise_count  = 0;
    uint64_t      last_app_id         = 0;
    h2::ErrorCode last_response_error = h2::ErrorCode::NO_ERROR;
    h2::ErrorCode last_stream_error   = h2::ErrorCode::NO_ERROR;
    h2::ErrorCode last_goaway_error   = h2::ErrorCode::NO_ERROR;

    std::optional<int>         last_status;
    std::optional<std::string> last_body;
    std::optional<bool>        last_response_had_protocol_header;

    // Captured PUSH_PROMISE details.
    uint32_t last_promised_stream_id   = 0;
    uint32_t last_associated_stream_id = 0;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    qb::allocator::pipe<char> &
    out() noexcept {
        return output;
    }

    template <typename Frame>
    ClientHarness &
    operator<<(const Frame &frame) {
        output.put(frame);
        return *this;
    }

    void
    capture(qb::http::Response &&response) {
        ++response_count;
        last_status = response.status().code();
        last_body   = response.body().template as<std::string>();
    }

    void
    on(qb::http::Response &&response, uint64_t app_id) {
        last_app_id         = app_id;
        last_response_error = h2::ErrorCode::NO_ERROR;
        capture(std::move(response));
    }

    void
    on(qb::http::Response &&response, uint64_t app_id, h2::ErrorCode ec) {
        last_app_id         = app_id;
        last_response_error = ec;
        capture(std::move(response));
    }

    void
    on(const h2::Http2StreamErrorEvent &event) {
        ++stream_error_count;
        last_stream_error = event.error_code;
    }

    void
    on(const h2::Http2GoAwayEvent &event) {
        ++goaway_count;
        last_goaway_error = event.error_code;
    }

    void
    on(const h2::Http2PushPromiseEvent &event) {
        ++push_promise_count;
        last_associated_stream_id = event.associated_stream_id;
        last_promised_stream_id   = event.promised_stream_id;
    }
};

// Peer server harness for round-trip tests. Captures the request the server
// receives so we can assert the client serialized it faithfully.
struct ServerPeerHarness {
    using base_io_t = ServerPeerHarness;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;

    int                        request_count = 0;
    std::optional<std::string> last_method;
    std::optional<std::string> last_path;
    std::optional<std::string> last_body;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    qb::allocator::pipe<char> &
    out() noexcept {
        return output;
    }

    template <typename Frame>
    ServerPeerHarness &
    operator<<(const Frame &frame) {
        output.put(frame);
        return *this;
    }

    void
    on(qb::http::Request &&request, uint32_t) {
        ++request_count;
        last_method = std::string(request.method());
        last_path   = std::string(request.uri().path());
        last_body   = request.body().template as<std::string>();
    }

    void
    on(const h2::Http2StreamErrorEvent &) {}
    void
    on(const h2::Http2GoAwayEvent &) {}
};

[[nodiscard]] std::vector<uint8_t>
encode_hpack_headers(const std::vector<qb::protocol::hpack::HeaderField> &headers) {
    qb::protocol::hpack::Encoder encoder;
    std::vector<uint8_t>         encoded;
    EXPECT_TRUE(encoder.encode(headers, encoded));
    return encoded;
}

// Build a HEADERS Http2FrameData ready to feed to protocol.on(...).
[[nodiscard]] h2::Http2FrameData<h2::HeadersFrame>
make_headers_frame(uint32_t stream_id, uint8_t flags, const std::vector<qb::protocol::hpack::HeaderField> &headers) {
    h2::Http2FrameData<h2::HeadersFrame> frame;
    frame.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    frame.header.flags = flags;
    frame.header.set_stream_id(stream_id);
    frame.payload.header_block_fragment = encode_hpack_headers(headers);
    return frame;
}

[[nodiscard]] h2::Http2FrameData<h2::DataFrame>
make_data_frame(uint32_t stream_id, uint8_t flags, const std::string &body) {
    h2::Http2FrameData<h2::DataFrame> frame;
    frame.header.type  = static_cast<uint8_t>(h2::FrameType::DATA);
    frame.header.flags = flags;
    frame.header.set_stream_id(stream_id);
    frame.payload.data_payload.assign(body.begin(), body.end());
    return frame;
}

// Copy whatever is currently in `from` into `to`'s input pipe (raw bytes) and
// drive the parser loop until it stalls. `from` is consumed.
template <typename Protocol, typename ToHarness, typename FromHarness>
void
pump(Protocol &protocol, ToHarness &to, FromHarness &from) {
    const std::size_t n = from.output.size();
    if (n > 0) {
        std::memcpy(to.input.allocate_back(n), from.output.cbegin(), n);
        from.output.reset();
    }
    std::size_t sz = 0;
    while ((sz = protocol.getMessageSize()) > 0) {
        protocol.onMessage(sz);
        to.input.free_front(sz);
        if (!protocol.ok()) {
            break;
        }
    }
}

// Parse the first frame header sitting in a pipe (the client's output).
[[nodiscard]] h2::FrameHeader
peek_frame_header(const qb::allocator::pipe<char> &pipe, std::size_t offset) {
    h2::FrameHeader fh{};
    std::memcpy(&fh, pipe.cbegin() + offset, h2::FRAME_HEADER_SIZE);
    return fh;
}

// Locate the byte offset of the first frame of `type` in a pipe that begins with
// the client preface + SETTINGS. Returns SIZE_MAX if not found.
[[nodiscard]] std::size_t
find_frame_offset(const qb::allocator::pipe<char> &pipe, h2::FrameType type, std::size_t start) {
    std::size_t       offset = start;
    const std::size_t total  = pipe.size();
    while (offset + h2::FRAME_HEADER_SIZE <= total) {
        const auto fh      = peek_frame_header(pipe, offset);
        const auto payload = fh.get_payload_length();
        if (fh.get_type() == type) {
            return offset;
        }
        offset += h2::FRAME_HEADER_SIZE + payload;
    }
    return SIZE_MAX;
}

} // namespace

// ===========================================================================
// Construction: client preface + initial SETTINGS frame.
// ===========================================================================
TEST(HTTP2ClientProtocol, ConstructionEmitsPrefaceThenSettings) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    ASSERT_GE(io.output.size(), HTTP2_CONNECTION_PREFACE.size() + h2::FRAME_HEADER_SIZE);

    // Output must begin with the literal HTTP/2 connection preface magic.
    EXPECT_EQ(0, std::memcmp(io.output.cbegin(), HTTP2_CONNECTION_PREFACE.data(), HTTP2_CONNECTION_PREFACE.size()));

    // Immediately followed by a SETTINGS frame on stream 0 (not an ACK).
    const auto settings_fh = peek_frame_header(io.output, HTTP2_CONNECTION_PREFACE.size());
    EXPECT_EQ(settings_fh.get_type(), h2::FrameType::SETTINGS);
    EXPECT_EQ(settings_fh.get_stream_id(), 0u);
    EXPECT_EQ(settings_fh.flags & h2::FLAG_ACK, 0);
    EXPECT_GT(settings_fh.get_payload_length(), 0u); // We advertise several settings.
    EXPECT_TRUE(protocol.ok());
}

// ===========================================================================
// send_request(GET): a single HEADERS frame with END_HEADERS|END_STREAM, odd
// stream id, and next request gets the next odd id.
// ===========================================================================
TEST(HTTP2ClientProtocol, SendGetEmitsHeadersWithEndStreamAndOddStreamId) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    const std::size_t after_preface = HTTP2_CONNECTION_PREFACE.size();

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/get");

    ASSERT_TRUE(protocol.send_request(std::move(req), 42));
    EXPECT_EQ(protocol.last_initiated_stream_id(), 1u);

    // Find the HEADERS frame after the SETTINGS frame.
    const auto headers_off = find_frame_offset(io.output, h2::FrameType::HEADERS, after_preface);
    ASSERT_NE(headers_off, SIZE_MAX);
    const auto fh = peek_frame_header(io.output, headers_off);
    EXPECT_EQ(fh.get_type(), h2::FrameType::HEADERS);
    EXPECT_EQ(fh.get_stream_id(), 1u); // First client stream is odd id 1.
    EXPECT_TRUE(fh.flags & h2::FLAG_END_HEADERS);
    EXPECT_TRUE(fh.flags & h2::FLAG_END_STREAM); // No body -> END_STREAM on HEADERS.

    // Second request -> next odd stream id 3.
    qb::http::Request req2;
    req2.method() = qb::http::method::GET;
    req2.uri()    = qb::io::uri("https://example.test/get2");
    ASSERT_TRUE(protocol.send_request(std::move(req2), 43));
    EXPECT_EQ(protocol.last_initiated_stream_id(), 3u);
}

// ===========================================================================
// send_request with a body: HEADERS (no END_STREAM) followed by a DATA frame
// carrying the body with END_STREAM.
// ===========================================================================
TEST(HTTP2ClientProtocol, SendPostWithBodyEmitsHeadersThenData) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    const std::size_t after_preface = HTTP2_CONNECTION_PREFACE.size();

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/post");
    req.body()   = "hello-body";

    ASSERT_TRUE(protocol.send_request(std::move(req), 7));

    const auto headers_off = find_frame_offset(io.output, h2::FrameType::HEADERS, after_preface);
    ASSERT_NE(headers_off, SIZE_MAX);
    const auto headers_fh = peek_frame_header(io.output, headers_off);
    EXPECT_TRUE(headers_fh.flags & h2::FLAG_END_HEADERS);
    EXPECT_FALSE(headers_fh.flags & h2::FLAG_END_STREAM); // Body follows -> no END_STREAM on HEADERS.

    const auto data_off = find_frame_offset(io.output, h2::FrameType::DATA, headers_off);
    ASSERT_NE(data_off, SIZE_MAX);
    const auto data_fh = peek_frame_header(io.output, data_off);
    EXPECT_EQ(data_fh.get_stream_id(), 1u);
    EXPECT_EQ(data_fh.get_payload_length(), std::string("hello-body").size());
    EXPECT_TRUE(data_fh.flags & h2::FLAG_END_STREAM); // Final DATA frame closes the stream locally.
}

// ===========================================================================
// Round-trip: client GET is parsed by a peer server, and the server's response
// is fed back to the client which assembles and dispatches it.
// ===========================================================================
TEST(HTTP2ClientProtocol, RoundTripGetRequestThroughPeerServer) {
    ClientHarness                          client_io;
    h2::ClientHttp2Protocol<ClientHarness> client(client_io);

    ServerPeerHarness                          server_io;
    h2::ServerHttp2Protocol<ServerPeerHarness> server(server_io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/round");
    ASSERT_TRUE(client.send_request(std::move(req), 99));

    // Feed everything the client emitted (preface + SETTINGS + HEADERS) into the
    // server and drive it.
    pump(server, server_io, client_io);

    ASSERT_TRUE(server.ok());
    EXPECT_EQ(server_io.request_count, 1);
    ASSERT_TRUE(server_io.last_method.has_value());
    EXPECT_EQ(*server_io.last_method, "GET");
    EXPECT_EQ(*server_io.last_path, "/round");

    // Server replies 200 with a body via the real serialization path.
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "round-trip-ok";
    ASSERT_TRUE(server.send_response(1, response));

    // Feed the server's frames back into the client.
    pump(client, client_io, server_io);

    EXPECT_TRUE(client.ok());
    EXPECT_EQ(client_io.response_count, 1);
    ASSERT_TRUE(client_io.last_status.has_value());
    EXPECT_EQ(*client_io.last_status, 200);
    ASSERT_TRUE(client_io.last_body.has_value());
    EXPECT_EQ(*client_io.last_body, "round-trip-ok");
    EXPECT_EQ(client_io.last_app_id, 99u);
}

// ===========================================================================
// Hand-built response delivery: HEADERS(:status 200) + DATA(END_STREAM) fed via
// protocol.on(...) directly.
// ===========================================================================
TEST(HTTP2ClientProtocol, AssemblesResponseFromHeadersAndData) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/r");
    ASSERT_TRUE(protocol.send_request(std::move(req), 5));

    // HEADERS with :status 200, no END_STREAM (body follows).
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"content-type", "text/plain"}}));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0); // Not yet complete; awaiting END_STREAM.

    // DATA with END_STREAM completes the response.
    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "payload-bytes"));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_status.has_value());
    EXPECT_EQ(*io.last_status, 200);
    EXPECT_EQ(*io.last_body, "payload-bytes");
    EXPECT_EQ(io.last_app_id, 5u);
}

// ===========================================================================
// Response with trailers: HEADERS (main) -> DATA -> HEADERS (trailers,
// END_STREAM). The trailer-announcing "trailer" header on the main response
// makes the client wait for the trailer block before dispatching.
// ===========================================================================
TEST(HTTP2ClientProtocol, AssemblesResponseWithTrailers) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/trailers");
    ASSERT_TRUE(protocol.send_request(std::move(req), 11));

    // Main headers announce trailers; no END_STREAM.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"trailer", "x-checksum"}}));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);

    // Body, no END_STREAM (trailers will end the stream).
    protocol.on(make_data_frame(1, 0, "body-with-trailers"));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0); // Still waiting on trailers.

    // Trailer HEADERS block with END_STREAM.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{"x-checksum", "abc123"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_status.has_value());
    EXPECT_EQ(*io.last_status, 200);
    EXPECT_EQ(*io.last_body, "body-with-trailers");
}

// ===========================================================================
// GOAWAY (graceful, NO_ERROR): dispatches a GOAWAY event, protocol stays ok,
// and accepted streams below last_stream_id are kept.
// ===========================================================================
TEST(HTTP2ClientProtocol, GracefulGoawayDispatchesEventAndStaysOk) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/g");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    h2::Http2FrameData<h2::GoAwayFrame> goaway;
    goaway.header.type = static_cast<uint8_t>(h2::FrameType::GOAWAY);
    goaway.header.set_stream_id(0);
    goaway.payload.last_stream_id = 1;
    goaway.payload.error_code     = h2::ErrorCode::NO_ERROR;
    protocol.on(std::move(goaway));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::NO_ERROR);
}

// ===========================================================================
// GOAWAY (error): dispatches a GOAWAY event and forces the protocol not-ok with
// the carried error code.
// ===========================================================================
TEST(HTTP2ClientProtocol, ErrorGoawayMarksConnectionNotOk) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    h2::Http2FrameData<h2::GoAwayFrame> goaway;
    goaway.header.type = static_cast<uint8_t>(h2::FrameType::GOAWAY);
    goaway.header.set_stream_id(0);
    goaway.payload.last_stream_id = 0;
    goaway.payload.error_code     = h2::ErrorCode::PROTOCOL_ERROR;
    protocol.on(std::move(goaway));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::PROTOCOL_ERROR);

    // After a GOAWAY, no new requests may be initiated.
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/late");
    EXPECT_FALSE(protocol.send_request(std::move(req), 0));
}

// ===========================================================================
// RST_STREAM for an open stream: dispatches a stream error and removes the
// stream; the connection survives.
// ===========================================================================
TEST(HTTP2ClientProtocol, RstStreamOnOpenStreamDispatchesStreamError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/rst");
    ASSERT_TRUE(protocol.send_request(std::move(req), 3));

    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(1);
    rst.payload.error_code = h2::ErrorCode::CANCEL;
    protocol.on(std::move(rst));

    EXPECT_TRUE(protocol.ok()); // RST on a known open stream is not a connection error.
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::CANCEL);
    EXPECT_EQ(io.response_count, 0);
}

// ===========================================================================
// WINDOW_UPDATE with zero increment on stream 0 is a connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, ZeroIncrementConnectionWindowUpdateIsConnectionError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    h2::Http2FrameData<h2::WindowUpdateFrame> wu;
    wu.header.type = static_cast<uint8_t>(h2::FrameType::WINDOW_UPDATE);
    wu.header.set_stream_id(0);
    wu.payload.window_size_increment = 0;
    protocol.on(std::move(wu));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// A valid connection-level WINDOW_UPDATE is accepted (connection stays ok).
// ===========================================================================
TEST(HTTP2ClientProtocol, ValidConnectionWindowUpdateIsAccepted) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    h2::Http2FrameData<h2::WindowUpdateFrame> wu;
    wu.header.type = static_cast<uint8_t>(h2::FrameType::WINDOW_UPDATE);
    wu.header.set_stream_id(0);
    wu.payload.window_size_increment = 65535;
    protocol.on(std::move(wu));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
}

// ===========================================================================
// Stream-level WINDOW_UPDATE on an open stream is accepted; the request can
// then still complete via a hand-fed response.
// ===========================================================================
TEST(HTTP2ClientProtocol, StreamWindowUpdateOnOpenStreamIsAccepted) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    // Send a body-bearing request so the stream stays OPEN (not half-closed).
    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/wu");
    req.body()   = "x";
    ASSERT_TRUE(protocol.send_request(std::move(req), 4));

    h2::Http2FrameData<h2::WindowUpdateFrame> wu;
    wu.header.type = static_cast<uint8_t>(h2::FrameType::WINDOW_UPDATE);
    wu.header.set_stream_id(1);
    wu.payload.window_size_increment = 1000;
    protocol.on(std::move(wu));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(io.stream_error_count, 0);
}

// ===========================================================================
// SETTINGS frame from server with INITIAL_WINDOW_SIZE applies a delta to
// existing client streams' peer windows and the client ACKs.
// ===========================================================================
TEST(HTTP2ClientProtocol, ServerSettingsInitialWindowSizeAppliesAndAcks) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    // Open a stream first so the delta has something to apply to.
    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/s");
    req.body()   = "y";
    ASSERT_TRUE(protocol.send_request(std::move(req), 2));

    const std::size_t output_before = io.output.size();

    h2::Http2FrameData<h2::SettingsFrame> settings;
    settings.header.type  = static_cast<uint8_t>(h2::FrameType::SETTINGS);
    settings.header.flags = 0;
    settings.header.set_stream_id(0);
    settings.payload.entries.push_back({h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 131070});
    settings.payload.entries.push_back({h2::Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 32768});
    protocol.on(std::move(settings));

    EXPECT_TRUE(protocol.ok());

    // A SETTINGS ACK must have been emitted after the settings were applied.
    const auto ack_off = find_frame_offset(io.output, h2::FrameType::SETTINGS, output_before);
    ASSERT_NE(ack_off, SIZE_MAX);
    const auto ack_fh = peek_frame_header(io.output, ack_off);
    EXPECT_EQ(ack_fh.get_type(), h2::FrameType::SETTINGS);
    EXPECT_TRUE(ack_fh.flags & h2::FLAG_ACK);
    EXPECT_EQ(ack_fh.get_payload_length(), 0u);
}

// ===========================================================================
// SETTINGS ACK with a non-empty payload is a FRAME_SIZE_ERROR connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, SettingsAckWithPayloadIsFrameSizeError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    h2::Http2FrameData<h2::SettingsFrame> ack;
    ack.header.type  = static_cast<uint8_t>(h2::FrameType::SETTINGS);
    ack.header.flags = h2::FLAG_ACK;
    ack.header.set_stream_id(0);
    ack.payload.entries.push_back({h2::Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 16384});
    protocol.on(std::move(ack));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::FRAME_SIZE_ERROR);
}

// ===========================================================================
// PUSH_PROMISE accept path: the client has ENABLE_PUSH=0 by default, so a
// PUSH_PROMISE is refused with RST_STREAM(REFUSED_STREAM) without dispatching a
// push event. (Default _our_settings sets SETTINGS_ENABLE_PUSH = 0.)
// ===========================================================================
TEST(HTTP2ClientProtocol, PushPromiseRefusedWhenPushDisabledByDefault) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/parent");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    // Drive the parent stream to OPEN by feeding response headers (no END_STREAM)
    // so PUSH_PROMISE association is valid.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t output_before = io.output.size();

    h2::Http2FrameData<h2::PushPromiseFrame> pp;
    pp.header.type  = static_cast<uint8_t>(h2::FrameType::PUSH_PROMISE);
    pp.header.flags = h2::FLAG_END_HEADERS;
    pp.header.set_stream_id(1);
    pp.payload.promised_stream_id = 2;
    pp.payload.header_block_fragment =
        encode_hpack_headers({{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/pushed"}});
    protocol.on(std::move(pp));

    EXPECT_TRUE(protocol.ok());
    // ENABLE_PUSH=0 -> client refuses before dispatching any push event.
    EXPECT_EQ(io.push_promise_count, 0);

    // An RST_STREAM(REFUSED_STREAM) for stream 2 must have been emitted.
    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, output_before);
    ASSERT_NE(rst_off, SIZE_MAX);
    const auto rst_fh = peek_frame_header(io.output, rst_off);
    EXPECT_EQ(rst_fh.get_stream_id(), 2u);
}

// ===========================================================================
// PUSH_PROMISE with an odd (invalid) promised stream id is a connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, PushPromiseWithOddPromisedStreamIdIsConnectionError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/parent");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    ASSERT_TRUE(protocol.ok());

    h2::Http2FrameData<h2::PushPromiseFrame> pp;
    pp.header.type  = static_cast<uint8_t>(h2::FrameType::PUSH_PROMISE);
    pp.header.flags = h2::FLAG_END_HEADERS;
    pp.header.set_stream_id(1);
    pp.payload.promised_stream_id    = 3; // odd -> invalid
    pp.payload.header_block_fragment = encode_hpack_headers({{":method", "GET"}, {":path", "/x"}});
    protocol.on(std::move(pp));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// Malformed response headers: HEADERS without a :status pseudo-header. The
// client RST_STREAMs the offending stream (stream-level error) but the
// connection survives.
// ===========================================================================
TEST(HTTP2ClientProtocol, ResponseHeadersMissingStatusResetsStream) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/nostatus");
    ASSERT_TRUE(protocol.send_request(std::move(req), 8));

    const std::size_t output_before = io.output.size();

    // No :status pseudo-header -> invalid response header block.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{"content-type", "text/plain"}}));

    EXPECT_TRUE(protocol.ok()); // Stream-level error, connection stays alive.
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, output_before);
    ASSERT_NE(rst_off, SIZE_MAX);
    const auto rst_fh = peek_frame_header(io.output, rst_off);
    EXPECT_EQ(rst_fh.get_stream_id(), 1u);
}

// ===========================================================================
// Malformed frame on the wire: a RST_STREAM frame with a 3-byte payload (must
// be exactly 4) is a FRAME_SIZE_ERROR. Drives raw bytes through the framer.
// ===========================================================================
TEST(HTTP2ClientProtocol, WrongSizedRstStreamPayloadIsFrameSizeError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    auto push = [&](const void *p, std::size_t n) {
        std::memcpy(io.input.allocate_back(n), p, n);
    };

    // RST_STREAM declared length = 3 (invalid; must be 4), stream 1.
    h2::FrameHeader fh{};
    fh.set_payload_length(3);
    fh.type  = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    fh.flags = 0;
    fh.set_stream_id(1);
    push(&fh, sizeof(fh));

    const std::uint8_t payload[3] = {0x00, 0x00, 0x00};
    push(payload, sizeof(payload));

    std::size_t sz = 0;
    while ((sz = protocol.getMessageSize()) > 0) {
        protocol.onMessage(sz);
        io.input.free_front(sz);
        if (!protocol.ok()) {
            break;
        }
    }

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::FRAME_SIZE_ERROR);
}

// ===========================================================================
// Oversized frame on the wire: a frame whose declared length exceeds our
// advertised max frame size (16384) is rejected with FRAME_SIZE_ERROR before
// the payload is even read.
// ===========================================================================
TEST(HTTP2ClientProtocol, OversizedFrameLengthIsFrameSizeError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    auto push = [&](const void *p, std::size_t n) {
        std::memcpy(io.input.allocate_back(n), p, n);
    };

    // DATA frame claiming a payload of 16385 octets (> our 16384 limit).
    h2::FrameHeader fh{};
    fh.set_payload_length(16385);
    fh.type  = static_cast<uint8_t>(h2::FrameType::DATA);
    fh.flags = 0;
    fh.set_stream_id(1);
    push(&fh, sizeof(fh));

    std::size_t sz = 0;
    while ((sz = protocol.getMessageSize()) > 0) {
        protocol.onMessage(sz);
        io.input.free_front(sz);
        if (!protocol.ok()) {
            break;
        }
    }

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::FRAME_SIZE_ERROR);
}

// ===========================================================================
// PING request from server is answered with a PING ACK echoing the opaque data.
// Driven over the wire (raw bytes) because on(Http2FrameData<PingFrame>) is a
// private handler reached only through the framer's dispatch.
// ===========================================================================
TEST(HTTP2ClientProtocol, PingRequestIsAnsweredWithAck) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    const std::size_t output_before = io.output.size();

    auto push = [&](const void *p, std::size_t n) {
        std::memcpy(io.input.allocate_back(n), p, n);
    };

    h2::FrameHeader fh{};
    fh.set_payload_length(8);
    fh.type  = static_cast<uint8_t>(h2::FrameType::PING);
    fh.flags = 0; // request (no ACK)
    fh.set_stream_id(0);
    push(&fh, sizeof(fh));
    const std::uint8_t opaque[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    push(opaque, sizeof(opaque));

    std::size_t sz = 0;
    while ((sz = protocol.getMessageSize()) > 0) {
        protocol.onMessage(sz);
        io.input.free_front(sz);
        if (!protocol.ok()) {
            break;
        }
    }

    EXPECT_TRUE(protocol.ok());
    const auto ping_off = find_frame_offset(io.output, h2::FrameType::PING, output_before);
    ASSERT_NE(ping_off, SIZE_MAX);
    const auto ping_fh = peek_frame_header(io.output, ping_off);
    EXPECT_TRUE(ping_fh.flags & h2::FLAG_ACK);
    EXPECT_EQ(ping_fh.get_payload_length(), 8u);
}

// ===========================================================================
// RST_STREAM on an idle (never-initiated) client stream is a connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, RstStreamOnIdleClientStreamIsConnectionError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(1); // never initiated
    rst.payload.error_code = h2::ErrorCode::CANCEL;
    protocol.on(std::move(rst));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// Extended coverage suite (appended): flow control queueing & WINDOW_UPDATE
// flush, auto connection/stream WINDOW_UPDATE emission on large server bodies,
// DATA for closed/unknown streams, rich request-header preparation, application
// push accept/reject, multi-stream lifecycle, SETTINGS-derived window sizing,
// and connection-error GOAWAY paths.
// ===========================================================================
namespace {

// Build a WINDOW_UPDATE Http2FrameData ready to feed to protocol.on(...).
[[nodiscard]] h2::Http2FrameData<h2::WindowUpdateFrame>
make_window_update_frame(uint32_t stream_id, uint32_t increment) {
    h2::Http2FrameData<h2::WindowUpdateFrame> frame;
    frame.header.type = static_cast<uint8_t>(h2::FrameType::WINDOW_UPDATE);
    frame.header.set_stream_id(stream_id);
    frame.payload.window_size_increment = increment;
    return frame;
}

// Build a server-SETTINGS Http2FrameData (not an ACK) with the given entries.
[[nodiscard]] h2::Http2FrameData<h2::SettingsFrame>
make_settings_frame(std::initializer_list<std::pair<h2::Http2SettingIdentifier, uint32_t>> entries) {
    h2::Http2FrameData<h2::SettingsFrame> frame;
    frame.header.type  = static_cast<uint8_t>(h2::FrameType::SETTINGS);
    frame.header.flags = 0;
    frame.header.set_stream_id(0);
    for (const auto &e : entries) {
        frame.payload.entries.push_back({e.first, e.second});
    }
    return frame;
}

// Count how many frames of `type` occur in a pipe, starting from `start`.
[[nodiscard]] std::size_t
count_frames(const qb::allocator::pipe<char> &pipe, h2::FrameType type, std::size_t start) {
    std::size_t       offset = start;
    std::size_t       hits   = 0;
    const std::size_t total  = pipe.size();
    while (offset + h2::FRAME_HEADER_SIZE <= total) {
        const auto fh      = peek_frame_header(pipe, offset);
        const auto payload = fh.get_payload_length();
        if (fh.get_type() == type) {
            ++hits;
        }
        offset += h2::FRAME_HEADER_SIZE + payload;
    }
    return hits;
}

// Sum the DATA-frame payload bytes emitted for `stream_id` from `start` onward.
[[nodiscard]] std::size_t
sum_data_payload_for_stream(const qb::allocator::pipe<char> &pipe, uint32_t stream_id, std::size_t start) {
    std::size_t       offset = start;
    std::size_t       bytes  = 0;
    const std::size_t total  = pipe.size();
    while (offset + h2::FRAME_HEADER_SIZE <= total) {
        const auto fh      = peek_frame_header(pipe, offset);
        const auto payload = fh.get_payload_length();
        if (fh.get_type() == h2::FrameType::DATA && fh.get_stream_id() == stream_id) {
            bytes += payload;
        }
        offset += h2::FRAME_HEADER_SIZE + payload;
    }
    return bytes;
}

// True if any WINDOW_UPDATE frame for `stream_id` appears from `start` onward.
[[nodiscard]] bool
has_window_update_for_stream(const qb::allocator::pipe<char> &pipe, uint32_t stream_id, std::size_t start) {
    std::size_t       offset = start;
    const std::size_t total  = pipe.size();
    while (offset + h2::FRAME_HEADER_SIZE <= total) {
        const auto fh = peek_frame_header(pipe, offset);
        if (fh.get_type() == h2::FrameType::WINDOW_UPDATE && fh.get_stream_id() == stream_id) {
            return true;
        }
        offset += h2::FRAME_HEADER_SIZE + fh.get_payload_length();
    }
    return false;
}

} // namespace

// ===========================================================================
// FLOW CONTROL — stream window queueing then flush:
// The server advertises a tiny SETTINGS_INITIAL_WINDOW_SIZE *before* the client
// opens a stream, so the new stream's peer (send) window is small. A POST whose
// body exceeds that window cannot be fully sent: the surplus stays queued
// (has_pending_data_to_send). A subsequent stream WINDOW_UPDATE must flush the
// remainder via try_send_pending_data_for_stream, and the full body lands on the
// wire with END_STREAM on the final DATA frame.
// ===========================================================================
TEST(HTTP2ClientProtocol, SmallStreamWindowQueuesBodyThenWindowUpdateFlushesIt) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    // Server caps the per-stream initial window at 10 bytes (applies to streams
    // opened *after* this SETTINGS is processed).
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 10}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/upload");
    req.body()   = std::string(30, 'A'); // 30-byte body, only 10 fit initially.
    ASSERT_TRUE(protocol.send_request(std::move(req), 77));

    // Only the first 10 bytes are flushed; no END_STREAM yet (body still pending).
    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 10u);
    {
        const auto data_off = find_frame_offset(io.output, h2::FrameType::DATA, before);
        ASSERT_NE(data_off, SIZE_MAX);
        const auto data_fh = peek_frame_header(io.output, data_off);
        EXPECT_FALSE(data_fh.flags & h2::FLAG_END_STREAM);
    }

    const std::size_t after_first = io.output.size();

    // Grant 100 more bytes on the stream -> remaining 20 bytes flush now.
    protocol.on(make_window_update_frame(1, 100));
    EXPECT_TRUE(protocol.ok());

    // All 30 bytes are now on the wire across the DATA frames.
    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 30u);

    // The newly-emitted DATA carries END_STREAM (final chunk closes locally).
    const auto last_data_off = find_frame_offset(io.output, h2::FrameType::DATA, after_first);
    ASSERT_NE(last_data_off, SIZE_MAX);
    const auto last_data_fh = peek_frame_header(io.output, last_data_off);
    EXPECT_TRUE(last_data_fh.flags & h2::FLAG_END_STREAM);
}

// ===========================================================================
// FLOW CONTROL — connection window blocks then a connection WINDOW_UPDATE
// flushes pending data on a stream. We exhaust most of the connection send
// window with one request, then a second request's body is throttled by the
// connection window; a connection-level (stream 0) WINDOW_UPDATE drives
// try_send_pending_data_for_stream across all streams.
// ===========================================================================
TEST(HTTP2ClientProtocol, ConnectionWindowBlocksBodyThenConnectionWindowUpdateFlushes) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    // Keep the per-stream window generous so the *connection* window is the only
    // limiter. Connection send window starts at our 65535 default.
    const std::size_t before = io.output.size();

    // First request: 60000-byte body. Stream window default 65535 is fine, so the
    // connection window (65535) is the binding limit; ~60000 bytes go out.
    qb::http::Request req1;
    req1.method() = qb::http::method::POST;
    req1.uri()    = qb::io::uri("https://example.test/a");
    req1.body()   = std::string(60000, 'a');
    ASSERT_TRUE(protocol.send_request(std::move(req1), 1));

    // Second request: another 20000-byte body. Connection window now nearly
    // drained (~5535 left), so only part of this body can flush; rest queues.
    qb::http::Request req2;
    req2.method() = qb::http::method::POST;
    req2.uri()    = qb::io::uri("https://example.test/b");
    req2.body()   = std::string(20000, 'b');
    ASSERT_TRUE(protocol.send_request(std::move(req2), 2));

    const std::size_t stream1_sent = sum_data_payload_for_stream(io.output, 1, before);
    const std::size_t stream3_sent = sum_data_payload_for_stream(io.output, 3, before);
    // Combined emitted DATA cannot exceed the initial 65535 connection window.
    EXPECT_LE(stream1_sent + stream3_sent, 65535u);
    EXPECT_LT(stream3_sent, 20000u); // stream 3 body is throttled.

    const std::size_t after_block = io.output.size();

    // Grant a big connection-level window increment -> queued data on all streams
    // flushes.
    protocol.on(make_window_update_frame(0, 200000));
    EXPECT_TRUE(protocol.ok());

    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 60000u);
    EXPECT_EQ(sum_data_payload_for_stream(io.output, 3, before), 20000u);
    EXPECT_GT(io.output.size(), after_block); // More DATA was emitted on flush.
}

// ===========================================================================
// AUTO STREAM WINDOW_UPDATE — when the server delivers enough DATA to cross the
// per-stream window-update threshold (initial window 65535 / 2), the client
// auto-emits a stream-level WINDOW_UPDATE so the peer may keep sending.
// ===========================================================================
TEST(HTTP2ClientProtocol, LargeServerBodyTriggersStreamWindowUpdate) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/big");
    ASSERT_TRUE(protocol.send_request(std::move(req), 9));

    // Response headers, no END_STREAM (large body follows).
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();

    // 40000 bytes > threshold (65535/2 = 32767) -> client must emit a stream
    // WINDOW_UPDATE for stream 1 (and possibly a connection-level one too).
    protocol.on(make_data_frame(1, 0, std::string(40000, 'Z')));
    EXPECT_TRUE(protocol.ok());

    EXPECT_TRUE(has_window_update_for_stream(io.output, 1, before));
}

// ===========================================================================
// AUTO CONNECTION WINDOW_UPDATE — server DATA crosses the connection-level
// threshold (DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE / 2), driving
// conditionally_send_connection_window_update() to emit a stream-0
// WINDOW_UPDATE.
// ===========================================================================
TEST(HTTP2ClientProtocol, LargeServerBodyTriggersConnectionWindowUpdate) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/c");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();

    // 40000 bytes of server DATA: > connection threshold (65535/2) -> a stream-0
    // WINDOW_UPDATE must appear.
    protocol.on(make_data_frame(1, 0, std::string(40000, 'Q')));
    EXPECT_TRUE(protocol.ok());

    EXPECT_TRUE(has_window_update_for_stream(io.output, 0, before));
}

// ===========================================================================
// DATA for an UNKNOWN client (odd) stream is a connection error: the client
// never opened stream 5, so DATA on it triggers handle_data_for_unknown_stream
// -> send_goaway_and_close(PROTOCOL_ERROR).
// ===========================================================================
TEST(HTTP2ClientProtocol, DataForUnknownClientStreamIsConnectionError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    protocol.on(make_data_frame(5, h2::FLAG_END_STREAM, "orphan"));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// DATA for an UNKNOWN pushed (even) stream that was never promised is a
// stream-level error: handle_data_for_unknown_stream RST_STREAMs the even id
// (STREAM_CLOSED) without tearing down the connection.
// ===========================================================================
TEST(HTTP2ClientProtocol, DataForUnknownPushedStreamResetsStreamOnly) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    const std::size_t before = io.output.size();
    protocol.on(make_data_frame(2, 0, "never-promised"));

    EXPECT_TRUE(protocol.ok()); // Even-id DATA -> stream-level RST, not GOAWAY.
    EXPECT_EQ(io.goaway_count, 0);

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, before);
    ASSERT_NE(rst_off, SIZE_MAX);
    const auto rst_fh = peek_frame_header(io.output, rst_off);
    EXPECT_EQ(rst_fh.get_stream_id(), 2u);
}

// ===========================================================================
// DATA for a CLOSED stream: complete the response (stream closes), then feed
// another DATA frame for the same id. handle_data_for_closed/unknown escalates
// to a connection error because the id was initiated.
// ===========================================================================
TEST(HTTP2ClientProtocol, DataAfterStreamClosedIsConnectionError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/closed");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    // Complete the response: HEADERS + DATA(END_STREAM) -> stream fully closed.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "done"));
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.response_count, 1);

    // Extra DATA after the stream is gone -> the id (1) was initiated, so this is
    // a connection error.
    protocol.on(make_data_frame(1, 0, "late"));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// prepare_request_headers — rich headers: custom headers are forwarded, a Host
// header becomes :authority, connection-specific/forbidden headers (Connection,
// Transfer-Encoding, Keep-Alive, Upgrade) are filtered out, and the request
// round-trips through a peer server which reconstructs method/path/body.
// ===========================================================================
TEST(HTTP2ClientProtocol, RichRequestHeadersAreFilteredAndRoundTrip) {
    ClientHarness                          client_io;
    h2::ClientHttp2Protocol<ClientHarness> client(client_io);

    ServerPeerHarness                          server_io;
    h2::ServerHttp2Protocol<ServerPeerHarness> server(server_io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/submit?x=1");
    req.body()   = "payload";
    // Custom (kept) headers.
    req.set_header("x-custom-one", "value-one");
    req.set_header("accept", "application/json");
    // Forbidden / connection-specific headers (must be stripped by the client).
    req.set_header("connection", "keep-alive");
    req.set_header("transfer-encoding", "chunked");
    req.set_header("keep-alive", "timeout=5");
    req.set_header("upgrade", "websocket");
    // Host header -> converted to :authority (and dropped as a regular header).
    req.set_header("host", "from-host-header.test");

    ASSERT_TRUE(client.send_request(std::move(req), 55));

    // The peer server must parse the request without a connection error.
    pump(server, server_io, client_io);
    ASSERT_TRUE(server.ok());
    ASSERT_EQ(server_io.request_count, 1);
    ASSERT_TRUE(server_io.last_method.has_value());
    EXPECT_EQ(*server_io.last_method, "POST");
    EXPECT_EQ(*server_io.last_path, "/submit");
    ASSERT_TRUE(server_io.last_body.has_value());
    EXPECT_EQ(*server_io.last_body, "payload");
    EXPECT_TRUE(client.ok());
}

// ===========================================================================
// prepare_request_headers — a "trailer" header announces trailers: the client
// emits HEADERS without END_STREAM, then send_request_trailers() emits a trailer
// HEADERS block with END_STREAM. Exercises the announced-trailer path and
// send_request_trailers success.
// ===========================================================================
TEST(HTTP2ClientProtocol, AnnouncedTrailersAreSentViaSendRequestTrailers) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    const std::size_t before = io.output.size();

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/with-trailers");
    req.body()   = "body";
    req.set_header("trailer", "x-checksum");
    ASSERT_TRUE(protocol.send_request(std::move(req), 21));

    // HEADERS emitted; because trailers are announced, the body DATA must NOT
    // carry END_STREAM (the trailer block will).
    const auto data_off = find_frame_offset(io.output, h2::FrameType::DATA, before);
    if (data_off != SIZE_MAX) {
        const auto data_fh = peek_frame_header(io.output, data_off);
        EXPECT_FALSE(data_fh.flags & h2::FLAG_END_STREAM);
    }

    const std::size_t before_trailers = io.output.size();

    qb::http::headers trailers;
    trailers.add_header("x-checksum", "deadbeef");
    ASSERT_TRUE(protocol.send_request_trailers(1, trailers));
    EXPECT_TRUE(protocol.ok());

    // A trailer HEADERS frame with END_STREAM must follow.
    const auto trailer_off = find_frame_offset(io.output, h2::FrameType::HEADERS, before_trailers);
    ASSERT_NE(trailer_off, SIZE_MAX);
    const auto trailer_fh = peek_frame_header(io.output, trailer_off);
    EXPECT_EQ(trailer_fh.get_stream_id(), 1u);
    EXPECT_TRUE(trailer_fh.flags & h2::FLAG_END_STREAM);
    EXPECT_TRUE(trailer_fh.flags & h2::FLAG_END_HEADERS);
}

// ===========================================================================
// send_request_trailers without an announced "trailer" header is rejected with
// RST_STREAM(PROTOCOL_ERROR) and returns false. To reach the
// "trailers-not-announced" branch the stream must still be open (END_STREAM not
// yet sent): we advertise a tiny peer window so the body stays flow-control
// blocked, leaving the stream OPEN with end_stream_sent == false.
// ===========================================================================
TEST(HTTP2ClientProtocol, SendTrailersWithoutAnnouncementRstsStream) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    // Tiny per-stream send window so the body cannot fully flush (END_STREAM is
    // therefore never set, keeping the stream OPEN for the trailers call).
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 1}}));
    ASSERT_TRUE(protocol.ok());

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/no-announce");
    req.body()   = "bb"; // 2-byte body, only 1 byte fits -> stays pending/open.
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    const std::size_t before = io.output.size();

    // No "trailer" header was announced -> send_request_trailers must refuse.
    qb::http::headers trailers;
    trailers.add_header("x-foo", "bar");
    EXPECT_FALSE(protocol.send_request_trailers(1, trailers));

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, before);
    ASSERT_NE(rst_off, SIZE_MAX);
    const auto rst_fh = peek_frame_header(io.output, rst_off);
    EXPECT_EQ(rst_fh.get_stream_id(), 1u);
}

// ===========================================================================
// application_reject_push for an id that was never promised is a documented
// no-op: no frame emitted, connection healthy. (The production default refuses
// pushes up-front because our SETTINGS_ENABLE_PUSH = 0, so a RESERVED_REMOTE
// stream is not reachable through the public API here; the no-op contract is
// what is observable.)
// ===========================================================================
TEST(HTTP2ClientProtocol, ApplicationRejectPushUnknownIdIsSafeNoop) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/p");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();
    // Rejecting an id that was never promised is a documented no-op.
    protocol.application_reject_push(4);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.output.size(), before); // No frame emitted.
}

// ===========================================================================
// PUSH_PROMISE with promised_stream_id == 0 (invalid) is a connection error
// (PROTOCOL_ERROR). This first-line validity check fires before the
// push-disabled refusal gate, so it is reachable with the default settings.
// ===========================================================================
TEST(HTTP2ClientProtocol, PushPromiseWithZeroPromisedStreamIdIsConnectionError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    h2::Http2FrameData<h2::PushPromiseFrame> pp;
    pp.header.type  = static_cast<uint8_t>(h2::FrameType::PUSH_PROMISE);
    pp.header.flags = h2::FLAG_END_HEADERS;
    pp.header.set_stream_id(1);
    pp.payload.promised_stream_id    = 0; // invalid (must be even and non-zero)
    pp.payload.header_block_fragment = encode_hpack_headers({{":method", "GET"}, {":path", "/x"}});
    protocol.on(std::move(pp));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// PUSH_PROMISE while push is disabled (our default SETTINGS_ENABLE_PUSH = 0)
// for an unknown associated stream: the push-disabled gate refuses the promised
// stream with RST_STREAM(REFUSED_STREAM) *before* the associated-stream check is
// reached, so the connection survives. Complements the existing
// PushPromiseRefusedWhenPushDisabledByDefault test with a non-existent
// association as input.
// ===========================================================================
TEST(HTTP2ClientProtocol, PushPromiseRefusedBeforeAssociatedStreamCheck) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    const std::size_t before = io.output.size();

    h2::Http2FrameData<h2::PushPromiseFrame> pp;
    pp.header.type  = static_cast<uint8_t>(h2::FrameType::PUSH_PROMISE);
    pp.header.flags = h2::FLAG_END_HEADERS;
    pp.header.set_stream_id(3); // associated stream never opened
    pp.payload.promised_stream_id    = 2;
    pp.payload.header_block_fragment = encode_hpack_headers({{":method", "GET"}, {":path", "/x"}});
    protocol.on(std::move(pp));

    EXPECT_TRUE(protocol.ok()); // Refused at the push-disabled gate, not GOAWAY.
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(io.push_promise_count, 0);

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, before);
    ASSERT_NE(rst_off, SIZE_MAX);
    const auto rst_fh = peek_frame_header(io.output, rst_off);
    EXPECT_EQ(rst_fh.get_stream_id(), 2u);
}

// ===========================================================================
// LIFECYCLE — multiple concurrent requests (stream ids 1, 3, 5) with interleaved
// responses. Each completes independently and dispatches its own app id; after
// all three, no streams remain blocking and the connection is healthy.
// ===========================================================================
TEST(HTTP2ClientProtocol, MultipleConcurrentRequestsInterleavedResponses) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    for (int i = 0; i < 3; ++i) {
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/n");
        ASSERT_TRUE(protocol.send_request(std::move(req), 100 + i));
    }
    EXPECT_EQ(protocol.last_initiated_stream_id(), 5u);

    // Interleave: headers for 1, headers for 3, data(END) for 3, headers+data for
    // 5, then data(END) for 1.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    protocol.on(make_headers_frame(3, h2::FLAG_END_HEADERS, {{":status", "201"}}));
    protocol.on(make_data_frame(3, h2::FLAG_END_STREAM, "three"));
    EXPECT_EQ(io.response_count, 1);
    EXPECT_EQ(io.last_app_id, 101u);

    protocol.on(make_headers_frame(5, h2::FLAG_END_HEADERS, {{":status", "404"}}));
    protocol.on(make_data_frame(5, h2::FLAG_END_STREAM, "five"));
    EXPECT_EQ(io.response_count, 2);
    EXPECT_EQ(io.last_app_id, 102u);

    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "one"));
    EXPECT_EQ(io.response_count, 3);
    EXPECT_EQ(io.last_app_id, 100u);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(io.stream_error_count, 0);
}

// ===========================================================================
// LIFECYCLE — graceful GOAWAY after all relevant streams are already closed:
// once the only client stream has completed, a graceful GOAWAY whose
// last_stream_id covers it makes are_all_relevant_streams_closed() true and the
// client signals a clean shutdown (protocol becomes not-ok with NO_ERROR).
// ===========================================================================
TEST(HTTP2ClientProtocol, GracefulGoawayAfterStreamsClosedSignalsCleanShutdown) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/done");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    // Complete and close stream 1.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "204"}}));
    ASSERT_EQ(io.response_count, 1);

    // Graceful GOAWAY (NO_ERROR), last_stream_id = 1: all relevant streams closed.
    h2::Http2FrameData<h2::GoAwayFrame> goaway;
    goaway.header.type = static_cast<uint8_t>(h2::FrameType::GOAWAY);
    goaway.header.set_stream_id(0);
    goaway.payload.last_stream_id = 1;
    goaway.payload.error_code     = h2::ErrorCode::NO_ERROR;
    protocol.on(std::move(goaway));

    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::NO_ERROR);
    // Clean shutdown was signalled to the transport.
    EXPECT_FALSE(protocol.ok());
}

// ===========================================================================
// GOAWAY implicitly closes streams above last_stream_id. We open streams 1 and 3
// then receive a graceful GOAWAY(last_stream_id=1): stream 3 (> 1) is implicitly
// closed and removed, while stream 1 (<= 1) survives and can still complete.
//
// REGRESSION: stream 3 is given main response HEADERS (FLAG_END_HEADERS, no
// END_STREAM) so it has a DISPATCHABLE response at GOAWAY time. This used to
// crash: the implicit-close loop in client.h marked the stream CLOSED+rst, then
// process_complete_response_if_ready() dispatched AND erased the stream context,
// after which the loop's own `it = _client_streams.erase(it)` operated on the
// now-invalidated iterator -> use-after-free. The loop now collects IDs first
// and only erases entries still present, so stream 3 dispatches on implicit
// close without a crash. Run under ASan to exercise the regression.
// ===========================================================================
TEST(HTTP2ClientProtocol, GoawayImplicitlyClosesStreamsAboveLastStreamId) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req1;
    req1.method() = qb::http::method::GET;
    req1.uri()    = qb::io::uri("https://example.test/1");
    ASSERT_TRUE(protocol.send_request(std::move(req1), 1));

    qb::http::Request req3;
    req3.method() = qb::http::method::GET;
    req3.uri()    = qb::io::uri("https://example.test/3");
    ASSERT_TRUE(protocol.send_request(std::move(req3), 3));
    ASSERT_TRUE(protocol.ok());

    // Give stream 3 main response headers (no END_STREAM): it now has a
    // dispatchable response but is still open. Not dispatched yet (awaiting
    // body/END_STREAM).
    protocol.on(make_headers_frame(3, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    EXPECT_EQ(io.response_count, 0);

    // Graceful GOAWAY, last_stream_id = 1: stream 3 (> 1) is implicitly closed.
    // Because it has main headers, the implicit close dispatches its (error)
    // response and erases the context -- the loop must not double-erase.
    h2::Http2FrameData<h2::GoAwayFrame> goaway;
    goaway.header.type = static_cast<uint8_t>(h2::FrameType::GOAWAY);
    goaway.header.set_stream_id(0);
    goaway.payload.last_stream_id = 1;
    goaway.payload.error_code     = h2::ErrorCode::NO_ERROR;
    protocol.on(std::move(goaway));

    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::NO_ERROR);
    // Stream 3 was dispatched on implicit close (no crash, no UAF).
    EXPECT_EQ(io.response_count, 1);
    EXPECT_EQ(io.last_app_id, 3u);

    // Stream 1 survived the GOAWAY and can still receive and complete its
    // response (the graceful GOAWAY did not force the connection not-ok because a
    // relevant stream <= last_stream_id was still open).
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "200"}}));
    EXPECT_EQ(io.response_count, 2);
    EXPECT_EQ(io.last_app_id, 1u);
}

// ===========================================================================
// ERROR — WINDOW_UPDATE with a zero increment on a *stream* is a stream error:
// the client RST_STREAMs that stream but keeps the connection alive.
// ===========================================================================
TEST(HTTP2ClientProtocol, ZeroIncrementStreamWindowUpdateRstsStream) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/z");
    req.body()   = "x";
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    const std::size_t before = io.output.size();
    protocol.on(make_window_update_frame(1, 0));

    EXPECT_TRUE(protocol.ok()); // Stream-level, not a connection error.
    EXPECT_EQ(io.goaway_count, 0);

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, before);
    ASSERT_NE(rst_off, SIZE_MAX);
    const auto rst_fh = peek_frame_header(io.output, rst_off);
    EXPECT_EQ(rst_fh.get_stream_id(), 1u);
}

// ===========================================================================
// ERROR — WINDOW_UPDATE that overflows a stream's send window beyond
// MAX_WINDOW_SIZE_LIMIT (2^31-1) is a FLOW_CONTROL_ERROR connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, StreamWindowUpdateOverflowIsFlowControlError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/ovf");
    req.body()   = "x";
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    // Stream peer window starts at 65535; adding 0x7FFFFFFF overflows the limit.
    protocol.on(make_window_update_frame(1, 0x7FFFFFFF));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::FLOW_CONTROL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// ERROR — PRIORITY frame on stream 0 is a connection error (PROTOCOL_ERROR).
// ===========================================================================
TEST(HTTP2ClientProtocol, PriorityFrameOnStreamZeroIsConnectionError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    h2::Http2FrameData<h2::PriorityFrame> prio;
    prio.header.type = static_cast<uint8_t>(h2::FrameType::PRIORITY);
    prio.header.set_stream_id(0);
    protocol.on(std::move(prio));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// PRIORITY frame on a known stream is accepted (stored) and is not an error.
// ===========================================================================
TEST(HTTP2ClientProtocol, PriorityFrameOnKnownStreamIsAccepted) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/prio");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    h2::Http2FrameData<h2::PriorityFrame> prio;
    prio.header.type = static_cast<uint8_t>(h2::FrameType::PRIORITY);
    prio.header.set_stream_id(1);
    protocol.on(std::move(prio));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
}

// ===========================================================================
// SETTINGS exchange — server advertises a larger MAX_FRAME_SIZE; the client
// applies it to outgoing-DATA chunking. A 20000-byte body that would be split
// in two at the 16384 default fits in a single DATA frame once the peer raised
// the limit to 32768.
// ===========================================================================
TEST(HTTP2ClientProtocol, ServerSettingsRaiseMaxFrameSizeAffectsChunking) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    // Raise peer max frame size to 32768 and window to a generous value.
    protocol.on(make_settings_frame(
        {{h2::Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 32768}, {h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 100000}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/chunk");
    req.body()   = std::string(20000, 'c');
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    EXPECT_EQ(count_frames(io.output, h2::FrameType::DATA, before), 1u);
    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 20000u);
}

// ===========================================================================
// SETTINGS exchange — an invalid SETTINGS_ENABLE_PUSH value (2) from the server
// is a connection error (PROTOCOL_ERROR) per the settings validator.
// ===========================================================================
TEST(HTTP2ClientProtocol, ServerSettingsInvalidEnablePushIsConnectionError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 2}}));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// SETTINGS on a non-zero stream id is a connection error (PROTOCOL_ERROR).
// ===========================================================================
TEST(HTTP2ClientProtocol, SettingsOnNonZeroStreamIsConnectionError) {
    ClientHarness                          io;
    h2::ClientHttp2Protocol<ClientHarness> protocol(io);

    h2::Http2FrameData<h2::SettingsFrame> settings;
    settings.header.type  = static_cast<uint8_t>(h2::FrameType::SETTINGS);
    settings.header.flags = 0;
    settings.header.set_stream_id(1); // illegal
    settings.payload.entries.push_back({h2::Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 16384});
    protocol.on(std::move(settings));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// Full round-trip with a body: client POST -> peer server parses request body
// -> server replies with a body -> client assembles the response. Confirms the
// _send_request_body_data_internal + response-assembly paths end to end.
// ===========================================================================
TEST(HTTP2ClientProtocol, RoundTripPostWithBodyThroughPeerServer) {
    ClientHarness                          client_io;
    h2::ClientHttp2Protocol<ClientHarness> client(client_io);

    ServerPeerHarness                          server_io;
    h2::ServerHttp2Protocol<ServerPeerHarness> server(server_io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/echo");
    req.body()   = "request-body-data";
    ASSERT_TRUE(client.send_request(std::move(req), 31));

    pump(server, server_io, client_io);
    ASSERT_TRUE(server.ok());
    ASSERT_EQ(server_io.request_count, 1);
    ASSERT_TRUE(server_io.last_body.has_value());
    EXPECT_EQ(*server_io.last_body, "request-body-data");

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "server-response-body";
    ASSERT_TRUE(server.send_response(1, response));

    pump(client, client_io, server_io);
    EXPECT_TRUE(client.ok());
    ASSERT_EQ(client_io.response_count, 1);
    ASSERT_TRUE(client_io.last_status.has_value());
    EXPECT_EQ(*client_io.last_status, 200);
    ASSERT_TRUE(client_io.last_body.has_value());
    EXPECT_EQ(*client_io.last_body, "server-response-body");
    EXPECT_EQ(client_io.last_app_id, 31u);
}

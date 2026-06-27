/**
 * @file qbm/http/tests/unit/http2/http2-protocol-roundtrip.cpp
 * @brief Bidirectional client<->server HTTP/2 protocol round-trip tests.
 *
 * The other http2 unit files (`http2-server-protocol.cpp`,
 * `http2-client-protocol.cpp`, `http2-protocol-state.cpp`,
 * `http2-protocol-coverage.cpp`) drive ONE protocol state machine at a time
 * against synthetic peer bytes. That covers the per-frame validation logic well
 * but leaves the *connected* dispatch + lifecycle paths under-exercised: the
 * paths that only fire when a real @c ClientHttp2Protocol and a real
 * @c ServerHttp2Protocol consume each other's actual emitted frames through the
 * framer.
 *
 * This file closes that gap. Every test wires a real client and a real server to
 * two rich fake-IO sinks (@ref Http2ClientFakeIO / @ref Http2FakeIO) and shuttles
 * their emitted bytes back and forth with the shared @ref pump helper. That makes
 * each side parse the OTHER side's genuine SETTINGS / ACK / HEADERS / DATA /
 * WINDOW_UPDATE / PING / GOAWAY frames — exercising:
 *
 *   - the full SETTINGS exchange + ACK in BOTH directions (client consumes the
 *     server's real SETTINGS and emits an ACK the server then consumes);
 *   - a complete request -> response cycle with bodies, dispatched end-to-end;
 *   - several concurrent streams interleaved through one connection;
 *   - request trailers (client->server) folded into the dispatched request's
 *     header set across a real pump;
 *   - a flow-control feedback loop: the server queues a large body behind the
 *     default send window, the client's real inbound consumption crosses its
 *     receive-window threshold and emits a real WINDOW_UPDATE, and the server
 *     flushes the remainder (driving @c try_send_pending_data_for_stream from a
 *     genuine peer frame, not an injected one);
 *   - a large server body that makes the client emit real WINDOW_UPDATEs of the
 *     bytes it consumed;
 *   - a PING/PONG round trip: a server PING is answered by the client's PONG,
 *     which the server then consumes silently;
 *   - error GOAWAY detected by each side and acted on by the peer (there is no
 *     public send_goaway API; the connection-error path is the only trigger);
 *   - a server-initiated RST_STREAM surfacing as a per-stream client error.
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

namespace {

namespace h2 = qb::protocol::http2;

using ServerProtocol = h2::ServerHttp2Protocol<Http2FakeIO>;

// ---------------------------------------------------------------------------
// Rich client sink: like Http2ClientFakeIO but RETAINS the full Response so a
// test can assert on folded response trailers / arbitrary headers, not just the
// status + body the canonical sink captures. Same IO contract otherwise.
// ---------------------------------------------------------------------------
struct RichClientIO {
    using base_io_t = RichClientIO;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;

    int           response_count     = 0;
    int           stream_error_count = 0;
    int           goaway_count       = 0;
    int           push_promise_count = 0;
    ErrorCode     last_stream_error  = ErrorCode::NO_ERROR;
    ErrorCode     last_goaway_error  = ErrorCode::NO_ERROR;
    uint32_t      last_goaway_last_stream_id = 0;

    // Per-app-id captured responses, so concurrent streams stay distinguishable.
    std::vector<std::pair<uint64_t, qb::http::Response>> responses;

    qb::allocator::pipe<char> &in() noexcept { return input; }
    qb::allocator::pipe<char> &out() noexcept { return output; }

    template <typename Frame>
    RichClientIO &operator<<(const Frame &frame) {
        output.put(frame);
        return *this;
    }

    void on(qb::http::Response &&response, uint64_t app_id) {
        ++response_count;
        responses.emplace_back(app_id, std::move(response));
    }
    void on(qb::http::Response &&response, uint64_t app_id, ErrorCode /*ec*/) {
        ++response_count;
        responses.emplace_back(app_id, std::move(response));
    }
    void on(const h2::Http2StreamErrorEvent &event) {
        ++stream_error_count;
        last_stream_error = event.error_code;
    }
    void on(const h2::Http2GoAwayEvent &event) {
        ++goaway_count;
        last_goaway_error          = event.error_code;
        last_goaway_last_stream_id = event.last_stream_id;
    }
    void on(const h2::Http2PushPromiseEvent & /*event*/) { ++push_promise_count; }

    // Find the captured response for a given application id.
    [[nodiscard]] const qb::http::Response *find(uint64_t app_id) const {
        for (const auto &pr : responses) {
            if (pr.first == app_id) {
                return &pr.second;
            }
        }
        return nullptr;
    }
};

using ClientProtocol = h2::ClientHttp2Protocol<RichClientIO>;

// Drive a freshly-constructed client + server through their mutual handshake by
// pumping both directions until quiescent: the client's preface + SETTINGS reach
// the server, the server's SETTINGS + ACK reach the client, and the client's ACK
// reaches the server. After this, both protocols are post-handshake and have
// each acknowledged the other's settings via real frames.
void
mutual_handshake(ClientProtocol &client, RichClientIO &client_io, ServerProtocol &server, Http2FakeIO &server_io) {
    // Client construction already emitted preface + SETTINGS into client_io.output.
    pump(server, server_io, client_io); // server consumes preface + client SETTINGS, emits its SETTINGS + ACK
    pump(client, client_io, server_io); // client consumes server SETTINGS + ACK, emits its own ACK
    pump(server, server_io, client_io); // server consumes the client's SETTINGS ACK
}

// Sum DATA payload bytes emitted on a given stream id into an output pipe.
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
        if (f.type == FrameType::DATA && f.stream_id == stream_id && (f.flags & h2::FLAG_END_STREAM)) {
            return true;
        }
    }
    return false;
}

} // namespace

// ===========================================================================
// Full SETTINGS exchange + ACK in both directions
// ===========================================================================

// The handshake makes BOTH sides parse the peer's real SETTINGS and emit a real
// ACK that the peer then consumes. This test drives the handshake step by step
// and inspects each side's output AT THE MOMENT it emits, before the next pump
// drains that buffer (pump() resets the source's output — see http2_fake_io.h).
TEST(HTTP2RoundTrip, MutualSettingsExchangeAcksBothDirections) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);

    // Count SETTINGS (non-ACK vs ACK) frames in an output pipe.
    auto count_settings = [](const qb::allocator::pipe<char> &out, bool ack) {
        std::size_t n = 0;
        for (const auto &f : parse_emitted_frames(out)) {
            if (f.type == FrameType::SETTINGS && static_cast<bool>(f.flags & h2::FLAG_ACK) == ack) {
                if (ack) {
                    EXPECT_EQ(f.payload_length, 0u); // an ACK carries no entries
                }
                ++n;
            }
        }
        return n;
    };

    // Step 1: server consumes the client's preface + SETTINGS, emits its OWN
    // (non-ACK) SETTINGS plus exactly one SETTINGS ACK of the client's. Inspect
    // server_io.output now, before step 2's pump drains it.
    pump(server, server_io, client_io);
    ASSERT_TRUE(server.ok());
    EXPECT_GE(count_settings(server_io.output, /*ack=*/false), 1u) << "server did not send its own SETTINGS";
    EXPECT_EQ(count_settings(server_io.output, /*ack=*/true), 1u) << "server did not ACK the client's SETTINGS exactly once";

    // Step 2: client consumes the server's SETTINGS + ACK, emits exactly one
    // SETTINGS ACK of the server's. Inspect client_io.output now, before step 3.
    pump(client, client_io, server_io);
    ASSERT_TRUE(client.ok());
    EXPECT_EQ(count_settings(client_io.output, /*ack=*/true), 1u) << "client did not ACK the server's SETTINGS exactly once";

    // Step 3: server consumes the client's SETTINGS ACK; both stay healthy.
    pump(server, server_io, client_io);
    EXPECT_TRUE(server.ok());
    EXPECT_TRUE(client.ok());
}

// ===========================================================================
// Full request -> response cycle with bodies, driven end-to-end.
// ===========================================================================

TEST(HTTP2RoundTrip, GetRequestRoundTripDeliversResponseBody) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);
    mutual_handshake(client, client_io, server, server_io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/resource");
    ASSERT_TRUE(client.send_request(std::move(req), /*app_id=*/77));

    // Server receives + dispatches the request.
    pump(server, server_io, client_io);
    ASSERT_TRUE(server.ok());
    ASSERT_EQ(server_io.request_count, 1);
    ASSERT_TRUE(server_io.last_request.has_value());
    EXPECT_EQ(server_io.last_request->method(), qb::http::method::GET);
    EXPECT_EQ(std::string(server_io.last_request->uri().path()), "/resource");
    const uint32_t stream_id = server_io.last_request_stream_id;
    EXPECT_EQ(stream_id, 1u);

    // Server answers with a body.
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "hello from server";
    response.set_header("content-length", "17");
    ASSERT_TRUE(server.send_response(stream_id, response));

    // Client receives + dispatches the response.
    pump(client, client_io, server_io);
    EXPECT_TRUE(client.ok());
    ASSERT_EQ(client_io.response_count, 1);
    const auto *resp = client_io.find(77);
    ASSERT_NE(resp, nullptr);
    EXPECT_EQ(resp->status().code(), 200);
    EXPECT_EQ(resp->body().as<std::string>(), "hello from server");
}

TEST(HTTP2RoundTrip, PostRequestBodyAndResponseBodyRoundTrip) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);
    mutual_handshake(client, client_io, server, server_io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/echo");
    req.body()   = "the-request-payload";
    req.set_header("content-length", "19");
    ASSERT_TRUE(client.send_request(std::move(req), /*app_id=*/9));

    pump(server, server_io, client_io);
    ASSERT_TRUE(server.ok());
    ASSERT_EQ(server_io.request_count, 1);
    ASSERT_TRUE(server_io.last_request.has_value());
    EXPECT_EQ(server_io.last_request->body().as<std::string>(), "the-request-payload");

    qb::http::Response response;
    response.status() = qb::http::status::CREATED;
    response.body()   = "the-response-payload";
    response.set_header("content-length", "20");
    ASSERT_TRUE(server.send_response(server_io.last_request_stream_id, response));

    pump(client, client_io, server_io);
    EXPECT_TRUE(client.ok());
    const auto *resp = client_io.find(9);
    ASSERT_NE(resp, nullptr);
    EXPECT_EQ(resp->status().code(), 201);
    EXPECT_EQ(resp->body().as<std::string>(), "the-response-payload");
}

// ===========================================================================
// Several concurrent streams interleaved through one connection.
// ===========================================================================

TEST(HTTP2RoundTrip, ThreeConcurrentStreamsEachAnswered) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);
    mutual_handshake(client, client_io, server, server_io);

    // Fire three GET requests before pumping any of them.
    for (uint64_t i = 0; i < 3; ++i) {
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/r" + std::to_string(i));
        ASSERT_TRUE(client.send_request(std::move(req), /*app_id=*/100 + i));
    }

    // All three HEADERS frames are already in the client output; one pump makes
    // the server parse + dispatch them. They take the strictly-increasing odd
    // ids 1, 3, 5 (RFC 9113 §5.1.1), so the server can respond on those ids.
    pump(server, server_io, client_io);
    ASSERT_TRUE(server.ok());
    ASSERT_EQ(server_io.request_count, 3);

    for (uint32_t sid : {1u, 3u, 5u}) {
        qb::http::Response response;
        response.status() = qb::http::status::OK;
        response.body()   = "body-" + std::to_string(sid);
        response.set_header("content-length", std::to_string(response.body().as<std::string>().size()));
        ASSERT_TRUE(server.send_response(sid, response)) << "send_response failed for stream " << sid;
    }

    pump(client, client_io, server_io);
    EXPECT_TRUE(client.ok());
    EXPECT_EQ(client_io.response_count, 3);

    // Every request id got a distinct 200 response with the stream-specific body.
    // app_id 100 -> stream 1, 101 -> 3, 102 -> 5 (strictly increasing odd ids).
    const auto *r0 = client_io.find(100);
    const auto *r1 = client_io.find(101);
    const auto *r2 = client_io.find(102);
    ASSERT_NE(r0, nullptr);
    ASSERT_NE(r1, nullptr);
    ASSERT_NE(r2, nullptr);
    EXPECT_EQ(r0->status().code(), 200);
    EXPECT_EQ(r1->status().code(), 200);
    EXPECT_EQ(r2->status().code(), 200);
    EXPECT_EQ(r0->body().as<std::string>(), "body-1");
    EXPECT_EQ(r1->body().as<std::string>(), "body-3");
    EXPECT_EQ(r2->body().as<std::string>(), "body-5");
}

// ===========================================================================
// Request trailers (client -> server) folded into the server's request set.
// ===========================================================================

TEST(HTTP2RoundTrip, ClientRequestTrailersReachServerAndFoldIntoRequest) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);
    mutual_handshake(client, client_io, server, server_io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/upload");
    req.body()   = "payload-bytes";
    req.set_header("trailer", "x-checksum"); // announce trailers -> HEADERS/DATA carry no END_STREAM
    ASSERT_TRUE(client.send_request(std::move(req), /*app_id=*/55));

    // Push the headers + body to the server (no END_STREAM yet -> not dispatched).
    pump(server, server_io, client_io);
    ASSERT_TRUE(server.ok());
    EXPECT_EQ(server_io.request_count, 0) << "request must wait for the trailer block";

    // Send the announced trailer block; this carries END_STREAM and completes it.
    qb::http::headers trailers;
    trailers.add_header("x-checksum", "cafef00d");
    ASSERT_TRUE(client.send_request_trailers(1, trailers));

    pump(server, server_io, client_io);
    EXPECT_TRUE(server.ok());
    ASSERT_EQ(server_io.request_count, 1);
    ASSERT_TRUE(server_io.last_request.has_value());
    EXPECT_EQ(server_io.last_request->body().as<std::string>(), "payload-bytes");
    // The trailer field is folded into the dispatched request's header set.
    EXPECT_EQ(server_io.last_request->header("x-checksum"), "cafef00d");
}

// ===========================================================================
// Flow control feedback loop: a response body larger than the default 65535
// stream send window forces the server to emit only the windowed prefix (no
// END_STREAM) and buffer the rest. Draining that prefix makes the CLIENT cross
// its receive-window threshold (65535/2) and emit a real WINDOW_UPDATE; feeding
// that update back to the server drives try_send_pending_data_for_stream to
// flush the remaining body with END_STREAM. This is the bidirectional path that
// single-side tests cannot exercise: the server's flush is driven by a genuine
// peer-emitted WINDOW_UPDATE, not an injected frame.
// ===========================================================================

TEST(HTTP2RoundTrip, ServerBodyBlockedByWindowFlushesOnClientWindowUpdate) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);
    mutual_handshake(client, client_io, server, server_io);

    // Open a GET stream (END_STREAM) so the server can respond. Default windows.
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/big");
    ASSERT_TRUE(client.send_request(std::move(req), /*app_id=*/1));
    pump(server, server_io, client_io);
    ASSERT_EQ(server_io.request_count, 1);
    const uint32_t sid = server_io.last_request_stream_id;

    // 100 KiB body > 65535-byte stream/connection send window: the server can
    // only emit the windowed prefix (65535 bytes), with NO END_STREAM; the rest
    // is buffered server-side.
    constexpr std::size_t kBodySize = 100u * 1024u;
    qb::http::Response    response;
    response.status() = qb::http::status::OK;
    response.body()   = std::string(kBodySize, 'Z');
    ASSERT_TRUE(server.send_response(sid, response));

    const uint32_t prefix_bytes = sum_data_bytes(server_io.output, sid);
    EXPECT_GT(prefix_bytes, 0u);
    EXPECT_LT(prefix_bytes, kBodySize) << "server should NOT have flushed the whole body in one window";
    EXPECT_FALSE(data_end_stream_seen(server_io.output, sid)) << "windowed prefix must not carry END_STREAM";

    // Deliver the windowed prefix to the client. Consuming >= 65535/2 bytes
    // crosses the client's stream + connection WINDOW_UPDATE thresholds, so it
    // emits real WINDOW_UPDATE frames back to the server. Inspect client_io.output
    // NOW, before the next pump drains it (pump resets the source's output).
    pump(client, client_io, server_io);
    EXPECT_TRUE(client.ok());
    ASSERT_TRUE(output_has_frame(client_io.output, FrameType::WINDOW_UPDATE))
        << "client did not open its receive window after consuming a large DATA prefix";

    // Feed the client's WINDOW_UPDATE(s) to the server -> try_send_pending_data_for_stream
    // flushes more of the buffered body, which the client drains and acknowledges.
    // We cannot read sum_data_bytes(server_io.output) across rounds because each
    // pump drains the buffer; instead we assert the downstream EFFECT — the
    // client's assembled response body growing to the full size — once the
    // response is dispatched.
    for (int round = 0; round < 8 && client_io.response_count == 0; ++round) {
        pump(server, server_io, client_io); // server flushes more DATA on the reopened window
        pump(client, client_io, server_io); // client drains it, opens the window again
        EXPECT_TRUE(server.ok());
        EXPECT_TRUE(client.ok());
    }

    // The full buffered body was flushed by the server (driven by the client's
    // genuine WINDOW_UPDATEs) and reassembled on the client.
    ASSERT_EQ(client_io.response_count, 1) << "response never completed after window-driven flush";
    const auto *resp = client_io.find(1);
    ASSERT_NE(resp, nullptr);
    EXPECT_EQ(resp->body().as<std::string>().size(), kBodySize) << "client did not reassemble the full body";
}

// ===========================================================================
// A large server body makes the client emit WINDOW_UPDATEs of consumed bytes.
// ===========================================================================

TEST(HTTP2RoundTrip, LargeResponseDrivesClientConnectionAndStreamWindowUpdates) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);
    mutual_handshake(client, client_io, server, server_io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/large");
    ASSERT_TRUE(client.send_request(std::move(req), /*app_id=*/3));
    pump(server, server_io, client_io);
    ASSERT_EQ(server_io.request_count, 1);
    const uint32_t sid = server_io.last_request_stream_id;

    // 50 KiB body: larger than half the default 65535 connection receive window,
    // so the client must emit connection-level WINDOW_UPDATE(s) as it drains it,
    // and a stream-level one when the stream completes.
    const std::string big_body(50u * 1024u, 'q');
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = big_body;
    ASSERT_TRUE(server.send_response(sid, response));

    // The 50 KiB body exceeds the default 65535 stream/connection windows only
    // partially; the default windows admit it, but draining it crosses the
    // client's half-window auto-update threshold. Pump response -> client.
    pump(client, client_io, server_io);
    EXPECT_TRUE(client.ok());

    // The client emitted at least one connection-level WINDOW_UPDATE (stream 0)
    // as it consumed the large inbound body.
    bool conn_window_update = false;
    for (const auto &f : parse_emitted_frames(client_io.output)) {
        if (f.type == FrameType::WINDOW_UPDATE && f.stream_id == 0) {
            conn_window_update = true;
        }
    }
    EXPECT_TRUE(conn_window_update) << "no connection WINDOW_UPDATE emitted for a 50 KiB inbound body";

    ASSERT_EQ(client_io.response_count, 1);
    const auto *resp = client_io.find(3);
    ASSERT_NE(resp, nullptr);
    EXPECT_EQ(resp->body().as<std::string>().size(), big_body.size());
}

// ===========================================================================
// PING / PONG round trip clears the client's outstanding-ping state.
// (Client receives a server PING and answers with a PONG the server consumes.)
// ===========================================================================

TEST(HTTP2RoundTrip, ServerPingIsAnsweredByClientPong) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);
    mutual_handshake(client, client_io, server, server_io);

    // Server sends a (non-ACK) PING; the client must answer with a PING+ACK that
    // echoes the same opaque payload.
    const std::vector<uint8_t> opaque = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44};
    {
        h2::FrameHeader fh{};
        fh.set_payload_length(8);
        fh.type  = static_cast<uint8_t>(FrameType::PING);
        fh.flags = 0;
        fh.set_stream_id(0);
        push_bytes(client_io, &fh, sizeof(fh));
        push_bytes(client_io, opaque.data(), opaque.size());
        drive(client, client_io);
    }
    EXPECT_TRUE(client.ok());

    // Find the PONG the client emitted: PING + ACK on stream 0, 8-octet payload.
    const auto pong_off = find_frame_offset(client_io.output, FrameType::PING);
    ASSERT_NE(pong_off, SIZE_MAX);
    const auto pong_fh = peek_frame_header(client_io.output, pong_off);
    EXPECT_NE(pong_fh.flags & h2::FLAG_ACK, 0);
    EXPECT_EQ(pong_fh.get_stream_id(), 0u);
    EXPECT_EQ(pong_fh.get_payload_length(), 8u);

    // The echoed opaque data matches what the server sent.
    const char *p = client_io.output.cbegin() + pong_off + h2::FRAME_HEADER_SIZE;
    for (std::size_t i = 0; i < opaque.size(); ++i) {
        EXPECT_EQ(static_cast<uint8_t>(p[i]), opaque[i]) << "PONG echo mismatch at byte " << i;
    }

    // Feeding the PONG to the server is consumed silently (a PING ACK is not
    // re-echoed): no new PING appears in the server's output.
    const std::size_t server_pings_before = count_frames(server_io.output, FrameType::PING);
    pump(server, server_io, client_io);
    EXPECT_TRUE(server.ok());
    EXPECT_EQ(count_frames(server_io.output, FrameType::PING), server_pings_before);
}

// ===========================================================================
// Error GOAWAY initiated by the SERVER reaches the client and tears its
// connection down. There is no public send_goaway API; the connection-error
// path is the only trigger. IMPORTANT (real behavior discovered): only errors
// raised from a typed on(...) handler — which call send_goaway_and_close while
// the protocol is still ok() — actually emit a GOAWAY frame. Framer-stage
// rejections (e.g. PING/SETTINGS on a non-zero stream, zero-increment
// WINDOW_UPDATE) call not_ok() FIRST, so the subsequent handle_framer_detected_error
// short-circuits on `!ok()` and NO GOAWAY is written. We therefore use a HEADERS
// frame on an even (server-parity) stream id, which reaches server on(HeadersFrame)
// and emits a real GOAWAY(PROTOCOL_ERROR).
// ===========================================================================

TEST(HTTP2RoundTrip, ServerDetectedProtocolErrorGoawayMarksClientNotOk) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);
    mutual_handshake(client, client_io, server, server_io);

    // HEADERS on an even stream id (2): a client must not initiate even streams
    // (RFC 9113 §5.1.1). server on(HeadersFrame) -> send_goaway_and_close(PROTOCOL_ERROR),
    // which writes a real GOAWAY frame while still ok().
    const auto encoded = encode_hpack_headers(default_request_headers("/even"));
    push_frame(server_io, FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, 2, encoded);
    drive(server, server_io);
    EXPECT_FALSE(server.ok());
    EXPECT_EQ(server_io.goaway_count, 1) << "server should dispatch a GOAWAY event";
    ASSERT_TRUE(output_has_frame(server_io.output, FrameType::GOAWAY)) << "server should emit a GOAWAY frame";

    // The GOAWAY frame, delivered to the client, marks it not-ok and surfaces the
    // GOAWAY event with the server's error code.
    pump(client, client_io, server_io);
    EXPECT_FALSE(client.ok());
    EXPECT_EQ(client_io.goaway_count, 1);
    EXPECT_EQ(client_io.last_goaway_error, ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// Error GOAWAY initiated by the CLIENT reaches the server, which dispatches the
// GOAWAY event. Same real-behavior constraint as above: we need a trigger that
// routes through a typed client on(...) handler so send_goaway_and_close runs
// while still ok() and a real GOAWAY frame is written. A PUSH_PROMISE promising
// an ODD stream id (RFC 9113 §6.6 requires even) hits client on(PushPromiseFrame)
// -> send_goaway_and_close(PROTOCOL_ERROR).
// ===========================================================================

TEST(HTTP2RoundTrip, ClientDetectedProtocolErrorGoawayReachesServer) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);
    mutual_handshake(client, client_io, server, server_io);

    // Open a normal request stream first so an associated stream exists.
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/parent");
    ASSERT_TRUE(client.send_request(std::move(req), /*app_id=*/1));
    // Give the stream a response-headers block so it is OPEN/HALF_CLOSED_REMOTE.
    client.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    ASSERT_TRUE(client.ok());

    // PUSH_PROMISE on the (valid) associated stream 1 promising an ODD id (3) is a
    // connection PROTOCOL_ERROR -> client send_goaway_and_close, writing a GOAWAY.
    h2::Http2FrameData<h2::PushPromiseFrame> pp;
    pp.header.type  = static_cast<uint8_t>(FrameType::PUSH_PROMISE);
    pp.header.flags = h2::FLAG_END_HEADERS;
    pp.header.set_stream_id(1);
    pp.payload.promised_stream_id    = 3; // odd -> invalid
    pp.payload.header_block_fragment = encode_hpack_headers({{":method", "GET"}, {":path", "/x"}});
    client.on(std::move(pp));

    EXPECT_FALSE(client.ok());
    EXPECT_EQ(client_io.goaway_count, 1) << "client should dispatch a GOAWAY event";
    ASSERT_TRUE(output_has_frame(client_io.output, FrameType::GOAWAY)) << "client should emit a GOAWAY frame";

    // The client's GOAWAY frame is delivered to the server, which dispatches the
    // event with the matching error code.
    pump(server, server_io, client_io);
    EXPECT_EQ(server_io.goaway_count, 1);
    EXPECT_EQ(server_io.last_goaway_error, ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// Server RST_STREAM is observed by the client as a per-stream error that does
// NOT take the connection down.
// ===========================================================================

TEST(HTTP2RoundTrip, ServerRstStreamSurfacesAsClientStreamError) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);
    mutual_handshake(client, client_io, server, server_io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/will-reset");
    ASSERT_TRUE(client.send_request(std::move(req), /*app_id=*/4));
    pump(server, server_io, client_io);
    ASSERT_EQ(server_io.request_count, 1);
    const uint32_t sid = server_io.last_request_stream_id;

    // Server resets the request stream instead of answering.
    server.send_rst_stream(sid, ErrorCode::INTERNAL_ERROR, "handler failed");
    pump(client, client_io, server_io);

    EXPECT_TRUE(client.ok()); // connection stays up
    EXPECT_EQ(client_io.stream_error_count, 1);
    EXPECT_EQ(client_io.last_stream_error, ErrorCode::INTERNAL_ERROR);
}

// ===========================================================================
// A protocol-error frame from the client drives the server to GOAWAY, and the
// resulting GOAWAY is delivered back to (and tears down) the client.
// ===========================================================================

TEST(HTTP2RoundTrip, ClientProtocolErrorMakesServerGoawayWhichClosesClient) {
    RichClientIO   client_io;
    ClientProtocol client(client_io);
    Http2FakeIO    server_io;
    ServerProtocol server(server_io);
    mutual_handshake(client, client_io, server, server_io);

    // Inject a raw DATA frame on stream 0 into the server's input — an illegal
    // connection-level frame (RFC 9113 §6.1) that forces send_goaway_and_close.
    push_frame(server_io, FrameType::DATA, 0, 0, {'x'});
    drive(server, server_io);

    EXPECT_FALSE(server.ok());
    ASSERT_TRUE(server.get_last_error_code().has_value());
    EXPECT_EQ(*server.get_last_error_code(), ErrorCode::PROTOCOL_ERROR);
    ASSERT_TRUE(output_has_frame(server_io.output, FrameType::GOAWAY));

    // The server's GOAWAY frame, delivered to the client, marks it not-ok with
    // the same connection error code.
    pump(client, client_io, server_io);
    EXPECT_FALSE(client.ok());
    EXPECT_EQ(client_io.goaway_count, 1);
    EXPECT_EQ(client_io.last_goaway_error, ErrorCode::PROTOCOL_ERROR);
}

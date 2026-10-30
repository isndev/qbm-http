/**
 * @file qbm/http/tests/unit/http2/http2-client-protocol.cpp
 * @brief Unit tests for the HTTP/2 client protocol state machine.
 *
 * Drives qb::protocol::http2::ClientHttp2Protocol over the shared socket-less
 * FakeIO harness (qb::http::test::Http2ClientFakeIO). Exercises the
 * request-serialization path (preface + SETTINGS on construction, HEADERS / DATA
 * emission, odd stream-id assignment, body chunking, request trailers) and the
 * frame-ingest path (response assembly, trailers, GOAWAY, RST_STREAM,
 * WINDOW_UPDATE, SETTINGS window deltas, PUSH_PROMISE accept/reject, PING, 1xx
 * informational responses, CONTINUATION-split header blocks, malformed frames).
 * Where practical, the client's emitted frames are round-tripped into a peer
 * ServerHttp2Protocol to ground-truth the serialization.
 *
 * Pure logic: no socket, no qb::Main, no event loop, no SSL. Deterministic and
 * parallel-safe (tier:unit).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <gtest/gtest.h>

#include "../../shared/http2_fake_io.h"

using qb::http::test::default_request_headers;
using qb::http::test::encode_hpack_headers;
using qb::http::test::find_frame_offset;
using qb::http::test::Http2ClientFakeIO;
using qb::http::test::Http2FakeIO;
using qb::http::test::Http2PeerFakeIO;
using qb::http::test::make_data_frame;
using qb::http::test::make_headers_frame;
using qb::http::test::peek_frame_header;
using qb::http::test::pump;
using qb::http::test::push_bytes;
using qb::http::test::push_frame;

namespace h2 = qb::protocol::http2;

namespace {

// ---------------------------------------------------------------------------
// Client-specific decode helpers (not in the shared harness because they are
// per-stream wire accounting needed only here).
// ---------------------------------------------------------------------------

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

// Count frames of `type` in a pipe from `start` onward. The shared count_frames
// walks from offset 0, which is unsafe on a *client* output pipe because that
// begins with the 24-byte connection preface (not a frame header); callers must
// start past the preface/SETTINGS via an explicit offset.
[[nodiscard]] std::size_t
count_frames_from(const qb::allocator::pipe<char> &pipe, h2::FrameType type, std::size_t start) {
    std::size_t       offset = start;
    std::size_t       hits   = 0;
    const std::size_t total  = pipe.size();
    while (offset + h2::FRAME_HEADER_SIZE <= total) {
        const auto fh = peek_frame_header(pipe, offset);
        if (fh.get_type() == type) {
            ++hits;
        }
        offset += h2::FRAME_HEADER_SIZE + fh.get_payload_length();
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

// Decode the window_size_increment carried by the first WINDOW_UPDATE frame for
// `stream_id` at or after `start`. The 4-byte big-endian increment lives in the
// payload immediately after the 9-byte frame header. Returns nullopt if none.
// The R (reserved) high bit is masked, matching the framer's extract_uint31_be.
[[nodiscard]] std::optional<uint32_t>
window_update_increment_for_stream(const qb::allocator::pipe<char> &pipe, uint32_t stream_id, std::size_t start) {
    std::size_t       offset = start;
    const std::size_t total  = pipe.size();
    while (offset + h2::FRAME_HEADER_SIZE <= total) {
        const auto fh      = peek_frame_header(pipe, offset);
        const auto payload = fh.get_payload_length();
        if (fh.get_type() == h2::FrameType::WINDOW_UPDATE && fh.get_stream_id() == stream_id) {
            const auto    *p = reinterpret_cast<const uint8_t *>(pipe.cbegin() + offset + h2::FRAME_HEADER_SIZE);
            const uint32_t raw =
                (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | p[3];
            return raw & 0x7FFFFFFFu;
        }
        offset += h2::FRAME_HEADER_SIZE + payload;
    }
    return std::nullopt;
}

// Sum every WINDOW_UPDATE increment emitted for `stream_id` from `start` onward
// (the client may auto-emit more than one as repeated DATA crosses the
// threshold). Returns 0 if none were emitted.
[[nodiscard]] uint64_t
total_window_update_increment_for_stream(const qb::allocator::pipe<char> &pipe, uint32_t stream_id, std::size_t start) {
    std::size_t       offset    = start;
    uint64_t          total_inc = 0;
    const std::size_t total     = pipe.size();
    while (offset + h2::FRAME_HEADER_SIZE <= total) {
        const auto fh      = peek_frame_header(pipe, offset);
        const auto payload = fh.get_payload_length();
        if (fh.get_type() == h2::FrameType::WINDOW_UPDATE && fh.get_stream_id() == stream_id) {
            const auto    *p = reinterpret_cast<const uint8_t *>(pipe.cbegin() + offset + h2::FRAME_HEADER_SIZE);
            const uint32_t raw =
                (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | p[3];
            total_inc += (raw & 0x7FFFFFFFu);
        }
        offset += h2::FRAME_HEADER_SIZE + payload;
    }
    return total_inc;
}

// Append a raw HEADERS or CONTINUATION frame carrying `fragment` to a harness
// input pipe. Used to split a single header block across HEADERS + CONTINUATION.
template <typename FakeIO>
void
push_raw_header_carrier(FakeIO &io, h2::FrameType type, uint8_t flags, uint32_t stream_id, const std::vector<uint8_t> &fragment) {
    h2::FrameHeader fh{};
    fh.set_payload_length(static_cast<uint32_t>(fragment.size()));
    fh.type  = static_cast<uint8_t>(type);
    fh.flags = flags;
    fh.set_stream_id(stream_id);
    push_bytes(io, &fh, sizeof(fh));
    if (!fragment.empty()) {
        push_bytes(io, fragment.data(), fragment.size());
    }
}

// One header block the client emitted on a stream: its HEADERS flags and its decoded fields.
struct SentHeaderBlock {
    uint8_t                                       flags = 0;
    std::vector<qb::protocol::hpack::HeaderField> fields;

    [[nodiscard]] std::size_t
    count(std::string_view name) const {
        return static_cast<std::size_t>(std::count_if(fields.begin(), fields.end(), [&](const auto &f) { return f.name == name; }));
    }
    [[nodiscard]] std::string
    value(std::string_view name) const {
        for (const auto &f : fields) {
            if (f.name == name) {
                return f.value;
            }
        }
        return {};
    }
};

// The header blocks emitted on `stream_id` from `from` on, decoded in order with one decoder (they
// share the client's HPACK state). Every block fits one frame here.
[[nodiscard]] std::vector<SentHeaderBlock>
sent_header_blocks(const qb::allocator::pipe<char> &output, uint32_t stream_id, std::size_t from) {
    qb::protocol::hpack::Decoder decoder;
    std::vector<SentHeaderBlock> blocks;
    for (std::size_t off = from; off + h2::FRAME_HEADER_SIZE <= output.size();) {
        const auto fh = peek_frame_header(output, off);
        if (fh.get_type() == h2::FrameType::HEADERS && fh.get_stream_id() == stream_id) {
            const auto          *first = reinterpret_cast<const uint8_t *>(output.cbegin() + off + h2::FRAME_HEADER_SIZE);
            std::vector<uint8_t> payload(first, first + fh.get_payload_length());
            SentHeaderBlock      block;
            block.flags     = fh.flags;
            bool incomplete = false;
            EXPECT_TRUE(decoder.decode(payload, block.fields, incomplete));
            blocks.push_back(std::move(block));
        }
        off += h2::FRAME_HEADER_SIZE + fh.get_payload_length();
    }
    return blocks;
}

} // namespace

// The framer drive loop is the shared harness helper.
using qb::http::test::drive;

// Test seam (declared by the protocol): jump the client stream-id counter to the 31-bit bound
// instead of sending 2^30 requests.
template <>
struct qb::protocol::http2::ProtocolTestPeer<qb::protocol::http2::ClientHttp2Protocol<Http2ClientFakeIO>> {
    static void
    set_next_stream_id(qb::protocol::http2::ClientHttp2Protocol<Http2ClientFakeIO> &protocol, uint32_t id) {
        protocol._next_client_stream_id = id;
    }

    static void
    reserve_pushed_stream(qb::protocol::http2::ClientHttp2Protocol<Http2ClientFakeIO> &protocol, uint32_t id) {
        auto [it, inserted] = protocol._client_streams.emplace(
            id, h2::Http2ClientStream(id, h2::DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE, h2::DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE));
        ASSERT_TRUE(inserted);
        it->second.state = h2::Http2StreamConcreteState::RESERVED_REMOTE;
    }
};

// ===========================================================================
// Construction: client preface + initial SETTINGS frame.
// ===========================================================================
TEST(HTTP2ClientProtocol, ReservedPushRejectionRetiresStreamOnce) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    // Public settings disable push. Seed only the dormant reserved-state teardown
    // branch; this test does not advertise or claim supported server push.
    h2::ProtocolTestPeer<h2::ClientHttp2Protocol<Http2ClientFakeIO>>::reserve_pushed_stream(protocol, 2);
    const auto before = io.output.size();
    protocol.application_reject_push(2);
    protocol.application_reject_push(2);
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::REFUSED_STREAM);
    EXPECT_EQ(count_frames_from(io.output, h2::FrameType::RST_STREAM, before), 1u);
}

TEST(HTTP2ClientProtocol, ConstructionEmitsPrefaceThenSettings) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

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
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    const std::size_t after_preface = HTTP2_CONNECTION_PREFACE.size();

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/get");

    ASSERT_TRUE(protocol.send_request(std::move(req), 42));
    EXPECT_EQ(protocol.last_initiated_stream_id(), 1u);

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
// Stream identifiers are 31-bit (RFC 9113 §5.1.1): 2^31-1 is the last odd id a
// client may open. The next request is REFUSED on this connection -- a client
// opens a new connection for new streams -- instead of taking 2^31+1, which the
// frame header masked to stream 1 on the wire while the stream map kept the
// unmasked key (Huly QB-525). A reset protocol counts from 1 again.
// ===========================================================================
TEST(HTTP2ClientProtocol, StreamIdsStopAtTheThirtyOneBitBound) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    h2::ProtocolTestPeer<h2::ClientHttp2Protocol<Http2ClientFakeIO>>::set_next_stream_id(protocol, 0x7FFFFFFFu);

    auto get = [] {
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/id");
        return req;
    };
    const std::size_t before = io.output.size();
    ASSERT_TRUE(protocol.send_request(get(), 1));
    EXPECT_EQ(protocol.last_initiated_stream_id(), 0x7FFFFFFFu);
    const auto headers_off = find_frame_offset(io.output, h2::FrameType::HEADERS, before);
    ASSERT_NE(headers_off, SIZE_MAX);
    EXPECT_EQ(peek_frame_header(io.output, headers_off).get_stream_id(), 0x7FFFFFFFu);

    const std::size_t after_last = io.output.size();
    EXPECT_FALSE(protocol.send_request(get(), 2)) << "no 32-bit stream id, no masked id 1";
    EXPECT_EQ(io.output.size(), after_last) << "nothing was sent";
    EXPECT_EQ(protocol.last_initiated_stream_id(), 0x7FFFFFFFu);
    EXPECT_TRUE(protocol.ok()) << "the connection itself is fine: the request waits for a new one";
}

// ===========================================================================
// Stream-id monotonicity: a run of requests must claim strictly increasing odd
// ids 1, 3, 5, 7, ... with no gaps and no even ids.
// ===========================================================================
TEST(HTTP2ClientProtocol, StreamIdsAreStrictlyIncreasingOddNumbers) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    uint32_t expected = 1;
    for (int i = 0; i < 5; ++i) {
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/seq");
        ASSERT_TRUE(protocol.send_request(std::move(req), 1000 + i));
        EXPECT_EQ(protocol.last_initiated_stream_id(), expected);
        EXPECT_EQ(protocol.last_initiated_stream_id() % 2u, 1u); // odd
        expected += 2;
    }
    // last_initiated_stream_id() reports the *most recently* assigned odd id; the
    // five requests claimed 1, 3, 5, 7, 9.
    EXPECT_EQ(protocol.last_initiated_stream_id(), 9u);
}

// ===========================================================================
// send_request with a body: HEADERS (no END_STREAM) followed by a DATA frame
// carrying the body with END_STREAM.
// ===========================================================================
TEST(HTTP2ClientProtocol, SendPostWithBodyEmitsHeadersThenData) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

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
    Http2ClientFakeIO                          client_io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);

    Http2PeerFakeIO                          server_io;
    h2::ServerHttp2Protocol<Http2PeerFakeIO> server(server_io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/round");
    ASSERT_TRUE(client.send_request(std::move(req), 99));

    pump(server, server_io, client_io);

    ASSERT_TRUE(server.ok());
    EXPECT_EQ(server_io.request_count, 1);
    ASSERT_TRUE(server_io.last_method.has_value());
    EXPECT_EQ(*server_io.last_method, "GET");
    EXPECT_EQ(*server_io.last_path, "/round");

    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.body()   = "round-trip-ok";
    ASSERT_TRUE(server.send_response(1, response));

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
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/r");
    ASSERT_TRUE(protocol.send_request(std::move(req), 5));

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"content-type", "text/plain"}}));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0); // Not yet complete; awaiting END_STREAM.

    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "payload-bytes"));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_status.has_value());
    EXPECT_EQ(*io.last_status, 200);
    EXPECT_EQ(*io.last_body, "payload-bytes");
    EXPECT_EQ(io.last_app_id, 5u);
}

// ===========================================================================
// Reentrancy controls for process_complete_response_if_ready. Insertion during
// dispatch proves the map can grow while user code runs; the second case erases
// the current node through an inbound RST_STREAM, the lifetime hazard that
// requires the completion path to snapshot every value used after dispatch.
// ===========================================================================
namespace {
struct ReentrantSendClientFakeIO : Http2ClientFakeIO {
    using Http2ClientFakeIO::on; // keep all base on(...) overloads visible (name-hiding guard)

    h2::ClientHttp2Protocol<ReentrantSendClientFakeIO> *proto     = nullptr;
    bool                                                reentered = false;

    void
    on(qb::http::Response &&response, uint64_t app_id, h2::ErrorCode ec) {
        Http2ClientFakeIO::on(std::move(response), app_id, ec);
        // Open many streams during dispatch to exercise map growth separately
        // from the current-node erase case below.
        if (proto && !reentered) {
            reentered = true;
            for (int i = 0; i < 256; ++i) {
                qb::http::Request r;
                r.method() = qb::http::method::GET;
                r.uri()    = qb::io::uri("https://example.test/x");
                (void) proto->send_request(std::move(r), 2000 + static_cast<uint64_t>(i));
            }
        }
    }
};

struct ReentrantEraseClientFakeIO : Http2ClientFakeIO {
    using Http2ClientFakeIO::on;

    h2::ClientHttp2Protocol<ReentrantEraseClientFakeIO> *proto     = nullptr;
    bool                                                 reentered = false;

    void
    on(qb::http::Response &&response, uint64_t app_id, h2::ErrorCode ec) {
        Http2ClientFakeIO::on(std::move(response), app_id, ec);
        if (!proto || reentered) {
            return;
        }
        reentered = true;
        h2::Http2FrameData<h2::RstStreamFrame> rst;
        rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
        rst.header.set_stream_id(1);
        rst.payload.error_code = h2::ErrorCode::CANCEL;
        proto->on(std::move(rst));
    }
};

struct ReentrantStreamErrorClientFakeIO : Http2ClientFakeIO {
    using Http2ClientFakeIO::on;
    h2::ClientHttp2Protocol<ReentrantStreamErrorClientFakeIO> *proto         = nullptr;
    bool                                                       reentered     = false;
    bool                                                       next_accepted = false;

    void
    on(const h2::Http2StreamErrorEvent &event) {
        Http2ClientFakeIO::on(event);
        if (reentered) {
            return;
        }
        reentered = true;
        // A peer cancellation dispatched synchronously by a user's error handler must
        // neither re-notify this request nor leave the outer RST holding an erased node.
        h2::Http2FrameData<h2::RstStreamFrame> rst;
        rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
        rst.header.set_stream_id(event.stream_id);
        rst.payload.error_code = h2::ErrorCode::CANCEL;
        proto->on(rst);
        qb::http::Request next{qb::http::method::GET, qb::io::uri("https://example.test/next")};
        next_accepted = proto->send_request(std::move(next), 97);
    }
};
} // namespace

TEST(HTTP2ClientProtocol, StreamErrorReentrantlyResettingSameStreamNotifiesOnce) {
    for (int path = 0; path != 3; ++path) {
        SCOPED_TRACE(path);
        ReentrantStreamErrorClientFakeIO                          io;
        h2::ClientHttp2Protocol<ReentrantStreamErrorClientFakeIO> protocol(io);
        io.proto = &protocol;
        qb::http::Request req{qb::http::method::GET, qb::io::uri("https://example.test/error")};
        ASSERT_TRUE(protocol.send_request(std::move(req), 96));
        if (path == 0) {
            // Existing error path: proves the lifetime defect independently of 1xx handling.
            protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "bad"}}));
        } else if (path == 1) {
            protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "103"}}));
        } else {
            protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "103"}}));
            protocol.on(make_data_frame(1, 0, std::string(40000, 'x')));
        }
        EXPECT_TRUE(protocol.ok());
        EXPECT_TRUE(io.reentered);
        EXPECT_EQ(io.stream_error_count, 1);
        EXPECT_EQ(io.response_count, 0);
        ASSERT_TRUE(io.next_accepted);
        protocol.on(make_headers_frame(3, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "204"}}));
        EXPECT_EQ(io.response_count, 1);
        EXPECT_EQ(io.last_app_id, 97u);
    }
}

TEST(HTTP2ClientProtocol, ResponseHandlerReenteringSendRequestKeepsResponseAndConnectionIntact) {
    ReentrantSendClientFakeIO                          io;
    h2::ClientHttp2Protocol<ReentrantSendClientFakeIO> protocol(io);
    io.proto = &protocol;

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/r");
    ASSERT_TRUE(protocol.send_request(std::move(req), 5)); // stream 1, app id 5

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "103"}}));
    EXPECT_EQ(io.response_count, 0);
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    // END_STREAM completes stream 1 → process_complete_response_if_ready dispatches; the handler
    // re-enters send_request 256× (relocating _client_streams) while the stream ref is live.
    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "body-1"));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_status.has_value());
    EXPECT_EQ(*io.last_status, 200);
    ASSERT_TRUE(io.last_body.has_value());
    EXPECT_EQ(*io.last_body, "body-1");
    EXPECT_EQ(io.last_app_id, 5u);

    // The connection is not wedged/corrupted: a response for one of the re-entrant streams
    // (stream 3, the first opened during the callback) still round-trips.
    protocol.on(make_headers_frame(3, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "204"}}));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 2);
}

TEST(HTTP2ClientProtocol, ResponseHandlerReentrantlyErasingCurrentStreamKeepsConnectionIntact) {
    ReentrantEraseClientFakeIO                          io;
    h2::ClientHttp2Protocol<ReentrantEraseClientFakeIO> protocol(io);
    io.proto = &protocol;
    // A one-stream peer cap makes the next request a public witness that the
    // completed stream no longer counts after reentrant RST cleanup.
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_MAX_CONCURRENT_STREAMS, 1}}));
    ASSERT_TRUE(protocol.ok());

    qb::http::Request first;
    first.method() = qb::http::method::GET;
    first.uri()    = qb::io::uri("https://example.test/erase-current");
    ASSERT_TRUE(protocol.send_request(std::move(first), 5));

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "100"}}));
    EXPECT_EQ(io.response_count, 0);
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "body-1"));

    EXPECT_TRUE(io.reentered);
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 1);
    EXPECT_EQ(io.last_app_id, 5u);

    // The by-id cleanup after user dispatch must tolerate that stream 1 is
    // already gone. The cap rejects a second request if stream 1 remained active.
    qb::http::Request second;
    second.method() = qb::http::method::GET;
    second.uri()    = qb::io::uri("https://example.test/after-erase");
    ASSERT_TRUE(protocol.send_request(std::move(second), 6));
    protocol.on(make_headers_frame(3, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "204"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 2);
    EXPECT_EQ(io.last_app_id, 6u);
}

// ===========================================================================
// CONTINUATION split: a header block delivered as HEADERS (no END_HEADERS) +
// CONTINUATION (END_HEADERS) must be reassembled and the response dispatched.
// The HPACK-encoded :status/content-type block is split byte-wise across the two
// frames, exercising the framer's _continuation_required / _continuation_stream_id
// path and the client's on(ContinuationFrame) reassembly.
// ===========================================================================
TEST(HTTP2ClientProtocol, ContinuationFrameSplitHeaderBlockIsReassembled) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/split");
    ASSERT_TRUE(protocol.send_request(std::move(req), 17));

    // Encode a realistic response header block, then split it across two frames.
    const auto block = encode_hpack_headers({{":status", "200"}, {"content-type", "application/json"}, {"x-trace", "split-header-block"}});
    ASSERT_GE(block.size(), 4u);
    const std::size_t cut = block.size() / 2;

    std::vector<uint8_t> first(block.begin(), block.begin() + cut);
    std::vector<uint8_t> rest(block.begin() + cut, block.end());

    // HEADERS without END_HEADERS (and without END_STREAM): more header frames
    // are required, so the framer enters CONTINUATION-required state.
    push_raw_header_carrier(io, h2::FrameType::HEADERS, 0, 1, first);
    // CONTINUATION with END_HEADERS completes the block.
    push_raw_header_carrier(io, h2::FrameType::CONTINUATION, h2::FLAG_END_HEADERS, 1, rest);
    // DATA(END_STREAM) completes the response.
    {
        h2::FrameHeader   fh{};
        const std::string body = "reassembled";
        fh.set_payload_length(static_cast<uint32_t>(body.size()));
        fh.type  = static_cast<uint8_t>(h2::FrameType::DATA);
        fh.flags = h2::FLAG_END_STREAM;
        fh.set_stream_id(1);
        push_bytes(io, &fh, sizeof(fh));
        push_bytes(io, body.data(), body.size());
    }

    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(io.stream_error_count, 0);
    ASSERT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_status.has_value());
    EXPECT_EQ(*io.last_status, 200);
    EXPECT_EQ(*io.last_body, "reassembled");
    EXPECT_EQ(io.last_app_id, 17u);
}

// ===========================================================================
// CONTINUATION flood (CVE-2024-27316 class, hostile server): a peer opens a
// header block then sends many tiny CONTINUATION frames that each stay under the
// header-block BYTE cap but exhaust CPU/memory reassembling one block. Past
// MAX_CONTINUATION_FRAMES the client must GOAWAY(ENHANCE_YOUR_CALM).
// ===========================================================================
TEST(HTTP2ClientProtocol, ContinuationFloodFromServerTriggersGoaway) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/flood");
    ASSERT_TRUE(protocol.send_request(std::move(req), 17)); // opens stream 1

    // HEADERS without END_HEADERS opens a response header block for stream 1.
    push_raw_header_carrier(io, h2::FrameType::HEADERS, 0 /*no END_HEADERS*/, 1, encode_hpack_headers({{":status", "200"}}));
    drive(protocol, io);
    ASSERT_EQ(io.goaway_count, 0) << "opening the header block must not itself trip the guard";

    // Flood tiny CONTINUATION frames (no END_HEADERS): each is well under the byte cap, so only the
    // per-block frame-count guard (MAX_CONTINUATION_FRAMES=512) can stop it. 700 > 512 must trip it.
    const std::vector<uint8_t> tiny(1, 0x00);
    for (int i = 0; i < 700 && io.goaway_count == 0; ++i) {
        push_raw_header_carrier(io, h2::FrameType::CONTINUATION, 0 /*no END_HEADERS*/, 1, tiny);
        drive(protocol, io);
    }
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
}

// ===========================================================================
// CONTINUATION for the wrong stream id (interleaved with the open header block)
// is a connection PROTOCOL_ERROR: the framer enforces that the CONTINUATION must
// be on the same stream as the unterminated HEADERS block.
// ===========================================================================
TEST(HTTP2ClientProtocol, ContinuationForWrongStreamIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/badcont");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    const auto block = encode_hpack_headers({{":status", "200"}, {"x-trace", "interleaved"}});
    ASSERT_GE(block.size(), 2u);
    const std::size_t    cut = block.size() / 2;
    std::vector<uint8_t> first(block.begin(), block.begin() + cut);
    std::vector<uint8_t> rest(block.begin() + cut, block.end());

    // HEADERS for stream 1 without END_HEADERS, then a CONTINUATION for stream 3.
    push_raw_header_carrier(io, h2::FrameType::HEADERS, 0, 1, first);
    push_raw_header_carrier(io, h2::FrameType::CONTINUATION, h2::FLAG_END_HEADERS, 3, rest);

    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.response_count, 0);
}

// ===========================================================================
// RFC 9113 section 8.1: any number of informational header blocks precede the
// final response. None completes a request or becomes part of its final fields.
// ===========================================================================
TEST(HTTP2ClientProtocol, InformationalHeadersWaitForFinalWithoutLeakingFields) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/continue");
    req.body()   = "expect-100";
    ASSERT_TRUE(protocol.send_request(std::move(req), 88));

    // Interim 100 Continue: no END_STREAM. Accepted, nothing dispatched, no error.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "100"}}));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "103"}, {"link", "</first>"}, {"trailer", "x-interim"}}));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "103"}, {"link", "</second>"}}));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 0);
    EXPECT_EQ(io.goaway_count, 0);

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"content-length", "4"}, {"x-final", "yes"}}));
    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "body"));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 1);
    EXPECT_EQ(io.stream_error_count, 0);
    ASSERT_TRUE(io.last_response);
    EXPECT_EQ(io.last_response->status(), 200);
    EXPECT_EQ(io.last_response->body().as<std::string>(), "body");
    EXPECT_EQ(io.last_response->header("x-final"), "yes");
    EXPECT_FALSE(io.last_response->has_header("link"));
    EXPECT_FALSE(io.last_response->has_header("trailer"));
    EXPECT_EQ(io.last_app_id, 88u);
}

// ===========================================================================
// An informational response cannot terminate the exchange before a final status.
// ===========================================================================
TEST(HTTP2ClientProtocol, InformationalHeadersWithEndStreamResetOnlyTheirStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/interim");
    ASSERT_TRUE(protocol.send_request(std::move(req), 5));

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "100"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ClientProtocol, InformationalSplitHeadersThenFinalAndTrailersCompleteOnce) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    qb::http::Request                          req{qb::http::method::GET, qb::io::uri("https://example.test/hints")};
    ASSERT_TRUE(protocol.send_request(std::move(req), 91));
    const auto block = encode_hpack_headers({{":status", "103"}, {"link", "</hint>"}});
    const auto cut   = block.size() / 2;
    push_raw_header_carrier(io, h2::FrameType::HEADERS, 0, 1, {block.begin(), block.begin() + cut});
    push_raw_header_carrier(io, h2::FrameType::CONTINUATION, h2::FLAG_END_HEADERS, 1, {block.begin() + cut, block.end()});
    drive(protocol, io);
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 0);
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"trailer", "x-sum"}}));
    protocol.on(make_data_frame(1, 0, "result"));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{"x-sum", "6"}}));
    EXPECT_TRUE(protocol.ok());
    ASSERT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_response);
    EXPECT_EQ(io.last_response->status(), 200);
    EXPECT_EQ(io.last_response->body().as<std::string>(), "result");
    EXPECT_EQ(io.last_response->trailers().header("x-sum"), "6");
    EXPECT_FALSE(io.last_response->has_header("link"));
}

TEST(HTTP2ClientProtocol, InformationalSplitHeadersWithEndStreamResetOnlyTheirStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    qb::http::Request                          req{qb::http::method::GET, qb::io::uri("https://example.test/hints")};
    ASSERT_TRUE(protocol.send_request(std::move(req), 92));
    const auto block = encode_hpack_headers({{":status", "103"}, {"link", "</hint>"}});
    const auto cut   = block.size() / 2;
    push_raw_header_carrier(io, h2::FrameType::HEADERS, h2::FLAG_END_STREAM, 1, {block.begin(), block.begin() + cut});
    push_raw_header_carrier(io, h2::FrameType::CONTINUATION, h2::FLAG_END_HEADERS, 1, {block.begin() + cut, block.end()});
    drive(protocol, io);
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ClientProtocol, InformationalSwitchingProtocolsIsRejectedInHttp2) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    qb::http::Request                          req{qb::http::method::GET, qb::io::uri("https://example.test/switch")};
    ASSERT_TRUE(protocol.send_request(std::move(req), 93));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "101"}}));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ClientProtocol, InformationalResponsesDoNotAllowDataBeforeFinalHeaders) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    qb::http::Request                          req{qb::http::method::GET, qb::io::uri("https://example.test/hints")};
    ASSERT_TRUE(protocol.send_request(std::move(req), 94));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "103"}}));
    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "not-final"));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
}

TEST(HTTP2ClientProtocol, InformationalResponsesKeepHpackStateAndIndependentStreams) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    qb::protocol::hpack::Encoder               encoder;
    qb::http::Request                          first{qb::http::method::GET, qb::io::uri("https://example.test/first")};
    qb::http::Request                          second{qb::http::method::GET, qb::io::uri("https://example.test/second")};
    ASSERT_TRUE(protocol.send_request(std::move(first), 10));
    ASSERT_TRUE(protocol.send_request(std::move(second), 20));
    auto headers = [&](uint32_t stream, uint8_t flags, std::vector<qb::protocol::hpack::HeaderField> fields) {
        std::vector<uint8_t> encoded;
        ASSERT_TRUE(encoder.encode(fields, encoded));
        push_raw_header_carrier(io, h2::FrameType::HEADERS, flags | h2::FLAG_END_HEADERS, stream, encoded);
        drive(protocol, io);
    };
    headers(1, 0, {{":status", "103"}, {"link", "</shared>"}});
    EXPECT_EQ(io.response_count, 0);
    // The second response refers to a dynamic-table entry learned from the first stream's 103.
    headers(3, h2::FLAG_END_STREAM, {{":status", "204"}, {"link", "</shared>"}});
    ASSERT_EQ(io.response_count, 1);
    EXPECT_EQ(io.last_app_id, 20u);
    ASSERT_TRUE(io.last_response);
    EXPECT_EQ(io.last_response->header("link"), "</shared>");
    headers(1, 0, {{":status", "103"}, {"link", "</shared>"}});
    EXPECT_EQ(io.response_count, 1);
    headers(1, h2::FLAG_END_STREAM, {{":status", "204"}});
    EXPECT_TRUE(protocol.ok());
    ASSERT_EQ(io.response_count, 2);
    EXPECT_EQ(io.last_app_id, 10u);
    EXPECT_EQ(io.stream_error_count, 0);
    ASSERT_TRUE(io.last_response);
    EXPECT_FALSE(io.last_response->has_header("link"));
}

TEST(HTTP2ClientProtocol, InformationalResponseThenPeerResetCompletesOnlyAsStreamError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    qb::http::Request                          req{qb::http::method::GET, qb::io::uri("https://example.test/cancel")};
    ASSERT_TRUE(protocol.send_request(std::move(req), 95));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "103"}}));
    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(1);
    rst.payload.error_code = h2::ErrorCode::CANCEL;
    protocol.on(rst);
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::CANCEL);
}

// ===========================================================================
// Response with trailers: HEADERS (main) -> DATA -> HEADERS (trailers,
// END_STREAM). The trailer-announcing "trailer" header on the main response
// makes the client wait for the trailer block before dispatching.
// ===========================================================================
TEST(HTTP2ClientProtocol, AssemblesResponseWithTrailers) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/trailers");
    ASSERT_TRUE(protocol.send_request(std::move(req), 11));

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"trailer", "x-checksum"}}));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);

    protocol.on(make_data_frame(1, 0, "body-with-trailers"));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0); // Still waiting on trailers.

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{"x-checksum", "abc123"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_status.has_value());
    EXPECT_EQ(*io.last_status, 200);
    EXPECT_EQ(*io.last_body, "body-with-trailers");
    // The trailer field is the response's trailers(), apart from its header section (Huly QB-1073),
    // and -- 3.x source compatibility -- one of its header fields too.
    ASSERT_TRUE(io.last_response.has_value());
    EXPECT_EQ(io.last_response->trailers().header("x-checksum"), "abc123");
    EXPECT_EQ(io.last_response->trailers().header_count(), 1u) << "the `trailer` announcement is a header field";
    EXPECT_EQ(io.last_response->header("x-checksum"), "abc123");
    EXPECT_TRUE(io.last_response->has_header("trailer"));
}

// ===========================================================================
// A response may announce trailers and send none: the `Trailer` header is a
// hint, and END_STREAM on the last DATA frame ends the message -- nothing can
// follow it (RFC 9110 §6.6.2, RFC 9113 §8.1). The response completes, with no
// trailer fields, once. The client used to wait for a trailer block that could
// never come: the request never completed (Huly QB-1061).
// ===========================================================================
TEST(HTTP2ClientProtocol, ResponseAnnouncingTrailersButEndingOnDataCompletes) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/announced");
    ASSERT_TRUE(protocol.send_request(std::move(req), 12));

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"trailer", "x-checksum"}}));
    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "body-without-trailers"));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 1) << "the response never completed";
    EXPECT_EQ(io.last_app_id, 12u);
    EXPECT_EQ(io.last_response_error, h2::ErrorCode::NO_ERROR);
    EXPECT_EQ(io.stream_error_count, 0);
    ASSERT_TRUE(io.last_status.has_value());
    EXPECT_EQ(*io.last_status, 200);
    EXPECT_EQ(*io.last_body, "body-without-trailers");
}

// ===========================================================================
// A response trailer section carrying a field the shared list forbids
// (qb::http::detail::is_forbidden_trailer_field) resets the stream, as the
// server does for a request's: the client checked only the connection-specific
// fields there, and accepted -- and merged into the response's headers -- a
// trailer `content-length`, `trailer` or proxy-authentication field (Huly
// QB-1073, RFC 9110 §6.5.1).
// ===========================================================================
TEST(HTTP2ClientProtocol, ResponseTrailerFieldThatFramesOrRoutesIsRefused) {
    const std::vector<std::pair<std::string, std::string>> forbidden = {
        {"content-length", "4"},
        {"trailer", "x-a"},
        {"proxy-authenticate", "Basic"},
        {"proxy-authorization", "Basic eA=="},
        {"host", "example.test"},
        {"te", "trailers"},
        {"connection", "close"},
        {"keep-alive", "timeout=5"},
        {"transfer-encoding", "chunked"},
        {"proxy-connection", "close"},
        {"upgrade", "h2c"},
        {"http2-settings", "AAMAAABk"}
    };
    for (const auto &[name, value] : forbidden) {
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/forbidden-trailer");
        ASSERT_TRUE(protocol.send_request(std::move(req), 21));

        protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"trailer", "x-a"}}));
        protocol.on(make_data_frame(1, 0, "body"));
        protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{name, value}}));

        EXPECT_TRUE(protocol.ok()) << name << ": a stream error, not a connection one";
        EXPECT_EQ(io.response_count, 0) << name << ": the response must not be delivered";
        EXPECT_EQ(io.stream_error_count, 1) << name;
        EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR) << name;
    }
}

// ===========================================================================
// A trailer section the response did not announce completes it: the `trailer`
// header is a SHOULD (RFC 9110 §6.6.2), and RFC 9113 §8.1 lets one HEADERS
// block that ends the stream follow the DATA frames. The client reset such a
// stream ("Multiple HEADERS frames not as trailers") -- what a server sending
// an unannounced trailer section gets (Huly QB-1073). Split over CONTINUATION
// frames alike, the response completes once its block does. A second header
// block that does NOT end the stream is still refused
// (SecondMainHeadersNotAsTrailersRstsStream).
// ===========================================================================
TEST(HTTP2ClientProtocol, ResponseTrailersWithoutAnnouncementComplete) {
    {
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        qb::http::Request                          req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/unannounced");
        ASSERT_TRUE(protocol.send_request(std::move(req), 22));

        protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
        protocol.on(make_data_frame(1, 0, "body"));
        EXPECT_EQ(io.response_count, 0);
        protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{"x-checksum", "abc123"}}));

        EXPECT_TRUE(protocol.ok());
        EXPECT_EQ(io.stream_error_count, 0);
        ASSERT_EQ(io.response_count, 1);
        EXPECT_EQ(*io.last_body, "body");
        ASSERT_TRUE(io.last_response.has_value());
        EXPECT_EQ(io.last_response->header("x-checksum"), "abc123");
    }
    {
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        qb::http::Request                          req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/unannounced-continuation");
        ASSERT_TRUE(protocol.send_request(std::move(req), 23));

        protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
        protocol.on(make_data_frame(1, 0, "body"));
        const auto block = encode_hpack_headers({{"x-checksum", "abc123"}});
        ASSERT_GE(block.size(), 2u);
        const std::size_t    cut = block.size() / 2;
        std::vector<uint8_t> first(block.begin(), block.begin() + cut);
        std::vector<uint8_t> rest(block.begin() + cut, block.end());
        push_raw_header_carrier(io, h2::FrameType::HEADERS, h2::FLAG_END_STREAM, 1, first);
        drive(protocol, io);
        EXPECT_EQ(io.response_count, 0) << "the trailer block is not complete yet";
        push_raw_header_carrier(io, h2::FrameType::CONTINUATION, h2::FLAG_END_HEADERS, 1, rest);
        drive(protocol, io);

        EXPECT_TRUE(protocol.ok());
        EXPECT_EQ(io.goaway_count, 0);
        EXPECT_EQ(io.stream_error_count, 0);
        ASSERT_EQ(io.response_count, 1);
        ASSERT_TRUE(io.last_response.has_value());
        EXPECT_EQ(io.last_response->header("x-checksum"), "abc123");
    }
}

// ===========================================================================
// GOAWAY (graceful, NO_ERROR): dispatches a GOAWAY event, protocol stays ok.
// ===========================================================================
TEST(HTTP2ClientProtocol, GracefulGoawayDispatchesEventAndStaysOk) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

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
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

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
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/rst");
    ASSERT_TRUE(protocol.send_request(std::move(req), 3));

    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(1);
    rst.payload.error_code = h2::ErrorCode::CANCEL;
    protocol.on(std::move(rst));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::CANCEL);
    EXPECT_EQ(io.response_count, 0);
}

// ===========================================================================
// WINDOW_UPDATE with zero increment on stream 0 is a connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, ZeroIncrementConnectionWindowUpdateIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    protocol.on(make_window_update_frame(0, 0));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// A valid connection-level WINDOW_UPDATE is accepted (connection stays ok).
// ===========================================================================
TEST(HTTP2ClientProtocol, ValidConnectionWindowUpdateIsAccepted) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    protocol.on(make_window_update_frame(0, 65535));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
}

// ===========================================================================
// Stream-level WINDOW_UPDATE on an open stream is accepted (connection healthy,
// no goaway, no stream error).
// ===========================================================================
TEST(HTTP2ClientProtocol, StreamWindowUpdateOnOpenStreamIsAccepted) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/wu");
    req.body()   = "x";
    ASSERT_TRUE(protocol.send_request(std::move(req), 4));

    protocol.on(make_window_update_frame(1, 1000));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(io.stream_error_count, 0);
}

// ===========================================================================
// SETTINGS frame from server with INITIAL_WINDOW_SIZE applies a delta to
// existing client streams' peer windows and the client ACKs.
// ===========================================================================
TEST(HTTP2ClientProtocol, ServerSettingsInitialWindowSizeAppliesAndAcks) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/s");
    req.body()   = "y";
    ASSERT_TRUE(protocol.send_request(std::move(req), 2));

    const std::size_t output_before = io.output.size();

    protocol.on(make_settings_frame(
        {{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 131070}, {h2::Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 32768}}));

    EXPECT_TRUE(protocol.ok());

    const auto ack_off = find_frame_offset(io.output, h2::FrameType::SETTINGS, output_before);
    ASSERT_NE(ack_off, SIZE_MAX);
    const auto ack_fh = peek_frame_header(io.output, ack_off);
    EXPECT_EQ(ack_fh.get_type(), h2::FrameType::SETTINGS);
    EXPECT_TRUE(ack_fh.flags & h2::FLAG_ACK);
    EXPECT_EQ(ack_fh.get_payload_length(), 0u);
}

// ===========================================================================
// SETTINGS_INITIAL_WINDOW_SIZE raised mid-connection adjusts the live stream by the
// delta and flushes a body that a smaller initial window had stalled. Exercises the
// deferred-flush path of on(SettingsFrame)'s per-stream window adjustment (loop 1829):
// that flush can close+erase a stream, so it runs over a snapshotted id list, not a
// live map iterator. Guards the refactor's flush semantics (both bytes eventually sent).
// ===========================================================================
TEST(HTTP2ClientProtocol, RaisingInitialWindowSizeFlushesStalledStreamBody) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    // Server starts with a tiny per-stream initial window so the request body stalls.
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 10}}));

    const std::size_t before = io.output.size();

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/stalled");
    req.body()   = std::string(100, 'z');
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    // Only the first 10 bytes fit the stream window; the remaining 90 stay pending.
    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 10u);

    // Raising the initial window size adjusts the live stream by the delta and flushes it.
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 100000}}));
    EXPECT_TRUE(protocol.ok());

    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 100u);
}

// ===========================================================================
// A lowered SETTINGS_INITIAL_WINDOW_SIZE can leave a stream window negative: a
// debt, never an error (RFC 9113 §6.9.2). Nothing is sent until WINDOW_UPDATE
// credit repays it; a change that pushes a window past 2^31-1 is a connection
// FLOW_CONTROL_ERROR. The client applies the shared Http2StreamBase rule, the
// server's too (Huly QB-1058).
// ===========================================================================
TEST(HTTP2ClientProtocol, LoweringInitialWindowSizeLeavesTheStreamInDebtUntilCreditArrives) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 10}}));

    const std::size_t before = io.output.size();
    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/debt");
    req.body()   = std::string(100, 'd');
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));
    ASSERT_EQ(sum_data_payload_for_stream(io.output, 1, before), 10u); // window 10 -> 0

    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 4}})); // 0 -> -6
    EXPECT_TRUE(protocol.ok()) << "a negative window is legal";
    protocol.on(make_window_update_frame(1, 6)); // -6 -> 0: the debt is repaid, nothing to send yet
    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 10u);
    protocol.on(make_window_update_frame(1, 20)); // 0 -> 20
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 30u);
}

TEST(HTTP2ClientProtocol, InitialWindowSizeChangePushingAWindowPastTheMaximumIsFlowControlError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/max");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));
    protocol.on(make_window_update_frame(1, 0x7FFFFFFFu - 65535u)); // the stream window is now exactly 2^31-1
    ASSERT_TRUE(protocol.ok());

    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 65536}})); // +1
    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::FLOW_CONTROL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// SETTINGS ACK with a non-empty payload is a FRAME_SIZE_ERROR connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, SettingsAckWithPayloadIsFrameSizeError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

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
// PUSH_PROMISE while push is disabled (ENABLE_PUSH=0, the client default) is a
// connection error of type PROTOCOL_ERROR — RFC 9113 §8.4, matching the server's
// mirror on(PushPromiseFrame). GOAWAY-and-close, no push event dispatched.
// Regression guard: the old behavior was a lenient RST-and-continue, which diverged
// from the RFC and the server and let a hostile server flood pushes for an unbounded
// (flow-control-exempt) RST_STREAM reply stream.
// ===========================================================================
TEST(HTTP2ClientProtocol, PushPromiseWhenPushDisabledIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

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
    pp.payload.promised_stream_id = 2;
    pp.payload.header_block_fragment =
        encode_hpack_headers({{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/pushed"}});
    protocol.on(std::move(pp));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.push_promise_count, 0);
}

// ===========================================================================
// PUSH_PROMISE with an odd (invalid) promised stream id is a connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, PushPromiseWithOddPromisedStreamIdIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

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
// Malformed response headers: HEADERS without a :status pseudo-header resets the
// stream; the connection survives.
// ===========================================================================
TEST(HTTP2ClientProtocol, ResponseHeadersMissingStatusResetsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/nostatus");
    ASSERT_TRUE(protocol.send_request(std::move(req), 8));

    const std::size_t output_before = io.output.size();

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{"content-type", "text/plain"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, output_before);
    ASSERT_NE(rst_off, SIZE_MAX);
    EXPECT_EQ(peek_frame_header(io.output, rst_off).get_stream_id(), 1u);
}

// ===========================================================================
// Malformed frame on the wire: a RST_STREAM frame with a 3-byte payload (must
// be exactly 4) is a FRAME_SIZE_ERROR. Drives raw bytes through the framer.
// ===========================================================================
TEST(HTTP2ClientProtocol, WrongSizedRstStreamPayloadIsFrameSizeError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    h2::FrameHeader fh{};
    fh.set_payload_length(3);
    fh.type  = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    fh.flags = 0;
    fh.set_stream_id(1);
    push_bytes(io, &fh, sizeof(fh));
    const std::uint8_t payload[3] = {0x00, 0x00, 0x00};
    push_bytes(io, payload, sizeof(payload));

    drive(protocol, io);

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
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    h2::FrameHeader fh{};
    fh.set_payload_length(16385);
    fh.type  = static_cast<uint8_t>(h2::FrameType::DATA);
    fh.flags = 0;
    fh.set_stream_id(1);
    push_bytes(io, &fh, sizeof(fh));

    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::FRAME_SIZE_ERROR);
}

// ===========================================================================
// PING request from server is answered with a PING ACK echoing the opaque data.
// ===========================================================================
TEST(HTTP2ClientProtocol, PingRequestIsAnsweredWithAck) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    const std::size_t output_before = io.output.size();

    h2::FrameHeader fh{};
    fh.set_payload_length(8);
    fh.type  = static_cast<uint8_t>(h2::FrameType::PING);
    fh.flags = 0; // request (no ACK)
    fh.set_stream_id(0);
    push_bytes(io, &fh, sizeof(fh));
    const std::uint8_t opaque[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    push_bytes(io, opaque, sizeof(opaque));

    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    const auto ping_off = find_frame_offset(io.output, h2::FrameType::PING, output_before);
    ASSERT_NE(ping_off, SIZE_MAX);
    const auto ping_fh = peek_frame_header(io.output, ping_off);
    EXPECT_TRUE(ping_fh.flags & h2::FLAG_ACK);
    EXPECT_EQ(ping_fh.get_payload_length(), 8u);
    // The PING ACK must echo the 8 opaque bytes verbatim.
    const auto *echoed = reinterpret_cast<const uint8_t *>(io.output.cbegin() + ping_off + h2::FRAME_HEADER_SIZE);
    EXPECT_EQ(0, std::memcmp(echoed, opaque, sizeof(opaque)));
}

// ===========================================================================
// RST_STREAM on an idle (never-initiated) client stream is a connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, RstStreamOnIdleClientStreamIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

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
// FLOW CONTROL — stream window queueing then flush. A tiny per-stream initial
// window leaves the body partly queued; a stream WINDOW_UPDATE flushes the rest.
// ===========================================================================
TEST(HTTP2ClientProtocol, SmallStreamWindowQueuesBodyThenWindowUpdateFlushesIt) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 10}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/upload");
    req.body()   = std::string(30, 'A');
    ASSERT_TRUE(protocol.send_request(std::move(req), 77));

    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 10u);
    {
        const auto data_off = find_frame_offset(io.output, h2::FrameType::DATA, before);
        ASSERT_NE(data_off, SIZE_MAX);
        EXPECT_FALSE(peek_frame_header(io.output, data_off).flags & h2::FLAG_END_STREAM);
    }

    const std::size_t after_first = io.output.size();

    protocol.on(make_window_update_frame(1, 100));
    EXPECT_TRUE(protocol.ok());

    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 30u);

    const auto last_data_off = find_frame_offset(io.output, h2::FrameType::DATA, after_first);
    ASSERT_NE(last_data_off, SIZE_MAX);
    EXPECT_TRUE(peek_frame_header(io.output, last_data_off).flags & h2::FLAG_END_STREAM);
}

// ===========================================================================
// FLOW CONTROL — connection window blocks then a connection WINDOW_UPDATE
// flushes pending data across streams.
// ===========================================================================
TEST(HTTP2ClientProtocol, ConnectionWindowBlocksBodyThenConnectionWindowUpdateFlushes) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    const std::size_t before = io.output.size();

    qb::http::Request req1;
    req1.method() = qb::http::method::POST;
    req1.uri()    = qb::io::uri("https://example.test/a");
    req1.body()   = std::string(60000, 'a');
    ASSERT_TRUE(protocol.send_request(std::move(req1), 1));

    qb::http::Request req2;
    req2.method() = qb::http::method::POST;
    req2.uri()    = qb::io::uri("https://example.test/b");
    req2.body()   = std::string(20000, 'b');
    ASSERT_TRUE(protocol.send_request(std::move(req2), 2));

    const std::size_t stream1_sent = sum_data_payload_for_stream(io.output, 1, before);
    const std::size_t stream3_sent = sum_data_payload_for_stream(io.output, 3, before);
    EXPECT_LE(stream1_sent + stream3_sent, 65535u);
    EXPECT_LT(stream3_sent, 20000u);

    const std::size_t after_block = io.output.size();

    protocol.on(make_window_update_frame(0, 200000));
    EXPECT_TRUE(protocol.ok());

    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 60000u);
    EXPECT_EQ(sum_data_payload_for_stream(io.output, 3, before), 20000u);
    EXPECT_GT(io.output.size(), after_block);
}

// ===========================================================================
// AUTO STREAM WINDOW_UPDATE — server DATA crossing the per-stream threshold makes
// the client auto-emit a stream WINDOW_UPDATE whose increment reclaims exactly
// the bytes consumed (40000), not merely *a* WINDOW_UPDATE of any magnitude.
// ===========================================================================
TEST(HTTP2ClientProtocol, LargeServerBodyTriggersStreamWindowUpdateOfConsumedBytes) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/big");
    ASSERT_TRUE(protocol.send_request(std::move(req), 9));

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();

    constexpr std::size_t consumed = 40000; // > 65535/2 threshold.
    protocol.on(make_data_frame(1, 0, std::string(consumed, 'Z')));
    EXPECT_TRUE(protocol.ok());

    // A stream-1 WINDOW_UPDATE was emitted, and its increment(s) total exactly the
    // consumed byte count so the peer's view of our receive window is restored.
    const auto first_inc = window_update_increment_for_stream(io.output, 1, before);
    ASSERT_TRUE(first_inc.has_value()) << "no stream-1 WINDOW_UPDATE emitted";
    EXPECT_EQ(total_window_update_increment_for_stream(io.output, 1, before), consumed);
}

// ===========================================================================
// AUTO CONNECTION WINDOW_UPDATE — server DATA crossing the connection-level
// threshold makes the client emit a stream-0 WINDOW_UPDATE whose increment
// totals exactly the consumed byte count.
// ===========================================================================
TEST(HTTP2ClientProtocol, LargeServerBodyTriggersConnectionWindowUpdateOfConsumedBytes) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/c");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();

    constexpr std::size_t consumed = 40000; // > connection threshold (65535/2).
    protocol.on(make_data_frame(1, 0, std::string(consumed, 'Q')));
    EXPECT_TRUE(protocol.ok());

    const auto conn_inc = window_update_increment_for_stream(io.output, 0, before);
    ASSERT_TRUE(conn_inc.has_value()) << "no connection (stream 0) WINDOW_UPDATE emitted";
    EXPECT_EQ(total_window_update_increment_for_stream(io.output, 0, before), consumed);
}

// ===========================================================================
// DATA for an UNKNOWN client (odd) stream is a connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, DataForUnknownClientStreamIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    protocol.on(make_data_frame(5, h2::FLAG_END_STREAM, "orphan"));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// DATA for an UNKNOWN pushed (even) stream that was never promised is a
// stream-level error: RST on the even id, connection survives.
// ===========================================================================
TEST(HTTP2ClientProtocol, DataForUnknownPushedStreamResetsStreamOnly) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    const std::size_t before = io.output.size();
    protocol.on(make_data_frame(2, 0, "never-promised"));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, before);
    ASSERT_NE(rst_off, SIZE_MAX);
    EXPECT_EQ(peek_frame_header(io.output, rst_off).get_stream_id(), 2u);
}

// ===========================================================================
// DATA for an UNKNOWN (already-completed-then-erased) initiated id is a
// connection error. After GET -> 200 -> END_STREAM the stream is ERASED, so the
// trailing DATA frame is not found by id and falls into
// handle_data_for_unknown_stream(), which raises GOAWAY(PROTOCOL_ERROR) — this
// is the unknown-id path, NOT the per-stream STREAM_CLOSED RST path (that only
// fires while a closed-but-still-resident stream context exists).
// ===========================================================================
TEST(HTTP2ClientProtocol, DataOnUnknownStreamIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/closed");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "done"));
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.response_count, 1);

    protocol.on(make_data_frame(1, 0, "late"));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// prepare_request_headers — rich headers: custom headers forwarded, Host ->
// :authority, connection-specific/forbidden headers stripped; round-trips through
// a peer server which reconstructs method/path/body.
// ===========================================================================
TEST(HTTP2ClientProtocol, RichRequestHeadersAreFilteredAndRoundTrip) {
    Http2ClientFakeIO                          client_io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);

    Http2PeerFakeIO                          server_io;
    h2::ServerHttp2Protocol<Http2PeerFakeIO> server(server_io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/submit?x=1");
    req.body()   = "payload";
    req.set_header("x-custom-one", "value-one");
    req.set_header("accept", "application/json");
    req.set_header("connection", "keep-alive");
    req.set_header("transfer-encoding", "chunked");
    req.set_header("keep-alive", "timeout=5");
    req.set_header("upgrade", "websocket");
    req.set_header("host", "from-host-header.test");

    ASSERT_TRUE(client.send_request(std::move(req), 55));

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
// prepare_request_headers — announced trailers: the body DATA must NOT carry
// END_STREAM (the trailer block will), then send_request_trailers emits the
// trailer HEADERS with END_STREAM. The body-DATA presence is asserted hard
// (was a silent if-guard that could no-op the END_STREAM-absence check).
// ===========================================================================
TEST(HTTP2ClientProtocol, AnnouncedTrailersAreSentViaSendRequestTrailers) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    const std::size_t before = io.output.size();

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/with-trailers");
    req.body()   = "body";
    req.set_header("trailer", "x-checksum");
    ASSERT_TRUE(protocol.send_request(std::move(req), 21));

    // The body DATA frame MUST exist and MUST NOT carry END_STREAM.
    const auto data_off = find_frame_offset(io.output, h2::FrameType::DATA, before);
    ASSERT_NE(data_off, SIZE_MAX) << "body DATA frame missing — trailers announced but body never emitted";
    EXPECT_FALSE(peek_frame_header(io.output, data_off).flags & h2::FLAG_END_STREAM);

    const std::size_t before_trailers = io.output.size();

    qb::http::headers trailers;
    trailers.add_header("x-checksum", "deadbeef");
    ASSERT_TRUE(protocol.send_request_trailers(1, trailers));
    EXPECT_TRUE(protocol.ok());

    const auto trailer_off = find_frame_offset(io.output, h2::FrameType::HEADERS, before_trailers);
    ASSERT_NE(trailer_off, SIZE_MAX);
    const auto trailer_fh = peek_frame_header(io.output, trailer_off);
    EXPECT_EQ(trailer_fh.get_stream_id(), 1u);
    EXPECT_TRUE(trailer_fh.flags & h2::FLAG_END_STREAM);
    EXPECT_TRUE(trailer_fh.flags & h2::FLAG_END_HEADERS);
}

// ===========================================================================
// Announced trailers handed over while the body still waits for flow-control
// credit leave AFTER its last DATA frame, carrying the stream's single
// END_STREAM (Huly QB-521). They used to go out at once with END_STREAM, and
// the window update then sent the rest of the body behind the end of the
// stream: the server dispatched a request truncated to the first window.
// ===========================================================================
TEST(HTTP2ClientProtocol, AnnouncedTrailersWaitForTheBlockedBodyAndEndTheStreamOnce) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    Http2FakeIO                                server_io;
    h2::ServerHttp2Protocol<Http2FakeIO>       server(server_io);

    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 4}}));
    ASSERT_TRUE(protocol.ok());
    const std::size_t before = io.output.size();

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/upload");
    req.body()   = "0123456789"; // only 4 octets fit the stream window
    req.set_header("trailer", "x-checksum");
    ASSERT_TRUE(protocol.send_request(std::move(req), 21));

    qb::http::headers trailers;
    trailers.add_header("x-checksum", "cafe");
    ASSERT_TRUE(protocol.send_request_trailers(1, trailers)) << "accepted, kept behind the blocked body";
    EXPECT_EQ(count_frames_from(io.output, h2::FrameType::HEADERS, before), 1u) << "only the request HEADERS so far";
    EXPECT_FALSE(protocol.send_request_trailers(1, trailers)) << "one trailer section per request";

    protocol.on(make_window_update_frame(1, 100));
    ASSERT_TRUE(protocol.ok());
    EXPECT_FALSE(protocol.send_request_trailers(1, trailers)) << "the stream has ended";

    // Exact order on the wire: request HEADERS, DATA(4), DATA(6), trailer HEADERS + END_STREAM.
    std::vector<std::pair<h2::FrameType, uint8_t>> frames;
    std::vector<uint32_t>                          lengths;
    for (std::size_t off = before; off + h2::FRAME_HEADER_SIZE <= io.output.size();) {
        const auto fh = peek_frame_header(io.output, off);
        if (fh.get_stream_id() == 1) {
            frames.emplace_back(fh.get_type(), fh.flags);
            lengths.push_back(fh.get_payload_length());
        }
        off += h2::FRAME_HEADER_SIZE + fh.get_payload_length();
    }
    ASSERT_EQ(frames.size(), 4u);
    EXPECT_EQ(frames[0].first, h2::FrameType::HEADERS);
    EXPECT_EQ(frames[1].first, h2::FrameType::DATA);
    EXPECT_EQ(lengths[1], 4u);
    EXPECT_EQ(frames[2].first, h2::FrameType::DATA);
    EXPECT_EQ(lengths[2], 6u);
    EXPECT_EQ(frames[3].first, h2::FrameType::HEADERS);
    for (std::size_t i = 0; i < 3; ++i) {
        EXPECT_FALSE(frames[i].second & h2::FLAG_END_STREAM) << "END_STREAM before the last frame, at " << i;
    }
    EXPECT_TRUE(frames[3].second & h2::FLAG_END_STREAM);
    EXPECT_TRUE(frames[3].second & h2::FLAG_END_HEADERS);

    // A real server reassembles the whole body and the trailer.
    pump(server, server_io, io);
    EXPECT_TRUE(server.ok());
    ASSERT_EQ(server_io.request_count, 1);
    EXPECT_EQ(server_io.last_request->body().as<std::string>(), "0123456789");
    EXPECT_EQ(server_io.last_request->header("x-checksum"), "cafe");
}

// ===========================================================================
// A request trailer block larger than the peer's SETTINGS_MAX_FRAME_SIZE (16384)
// is split over CONTINUATION frames like any header block (Huly QB-522); it used
// to go out as ONE HEADERS frame, which the peer refuses with FRAME_SIZE_ERROR.
// Exact threshold: {"x-a": V octets of '{'} encodes as a literal without
// indexing of V + 8 octets ('{' has a 15-bit Huffman code, so the value stays
// raw; "x-a" too) -> V = 16376 fills one frame exactly, V = 16377 needs two.
// ===========================================================================
namespace {
/// A server io with no request limits: the case pins the CLIENT's framing of a 16 KiB trailer value, which the
/// default limits (an 8 KiB field value, Huly QB-94) would answer 431 on the receiving side.
struct UnlimitedHttp2FakeIO : Http2FakeIO {
    [[nodiscard]] qb::http::request_limits const &
    http_request_limits() const noexcept {
        static constexpr qb::http::request_limits none{0, 0, 0, 0, 0, 0};
        return none;
    }
};
} // namespace

TEST(HTTP2ClientProtocol, RequestTrailerBlockIsSplitAtThePeerMaxFrameSize) {
    for (const std::size_t value_size : {std::size_t{16376}, std::size_t{16377}}) {
        Http2ClientFakeIO                             io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO>    protocol(io);
        UnlimitedHttp2FakeIO                          server_io;
        h2::ServerHttp2Protocol<UnlimitedHttp2FakeIO> server(server_io);

        qb::http::Request req;
        req.method() = qb::http::method::POST;
        req.uri()    = qb::io::uri("https://example.test/big-trailer");
        req.body()   = "b";
        req.set_header("trailer", "x-a");
        ASSERT_TRUE(protocol.send_request(std::move(req), 5));
        const std::size_t before = io.output.size();

        const std::string value(value_size, '{');
        qb::http::headers trailers;
        trailers.add_header("x-a", value);
        ASSERT_TRUE(protocol.send_request_trailers(1, trailers));
        ASSERT_TRUE(protocol.ok());

        std::vector<h2::FrameHeader> block;
        for (std::size_t off = before; off + h2::FRAME_HEADER_SIZE <= io.output.size();) {
            const auto fh = peek_frame_header(io.output, off);
            block.push_back(fh);
            off += h2::FRAME_HEADER_SIZE + fh.get_payload_length();
        }
        const std::size_t expected_frames = value_size == 16376 ? 1u : 2u;
        ASSERT_EQ(block.size(), expected_frames) << "value " << value_size;
        EXPECT_EQ(block[0].get_type(), h2::FrameType::HEADERS);
        EXPECT_EQ(block[0].get_payload_length(), 16384u);
        EXPECT_TRUE(block[0].flags & h2::FLAG_END_STREAM);
        EXPECT_EQ(static_cast<bool>(block[0].flags & h2::FLAG_END_HEADERS), expected_frames == 1);
        if (expected_frames == 2) {
            EXPECT_EQ(block[1].get_type(), h2::FrameType::CONTINUATION);
            EXPECT_EQ(block[1].get_payload_length(), 1u);
            EXPECT_TRUE(block[1].flags & h2::FLAG_END_HEADERS);
            EXPECT_FALSE(block[1].flags & h2::FLAG_END_STREAM);
        }

        pump(server, server_io, io);
        EXPECT_TRUE(server.ok()) << "value " << value_size;
        ASSERT_EQ(server_io.request_count, 1) << "value " << value_size;
        EXPECT_EQ(server_io.last_request->header("x-a"), value);
    }
}

// ===========================================================================
// The fields a request's `Trailer` header announces travel in the trailer
// block, and only there; the other fields stay in the leading HEADERS -- the
// contract the server follows for responses (Huly QB-1058) and HTTP/3 for both.
// The client used to send them twice: in the leading HEADERS, then again in the
// trailer block (Huly QB-1061).
// ===========================================================================
TEST(HTTP2ClientProtocol, AnnouncedRequestTrailerFieldsLeaveOnlyInTheTrailerBlock) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    const std::size_t                          before = io.output.size(); // past the preface and SETTINGS

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/announces");
    req.body()   = "ab";
    req.set_header("trailer", "X-Checksum");
    req.set_header("x-checksum", "cafe");
    req.set_header("x-other", "1");
    ASSERT_TRUE(protocol.send_request(std::move(req), 9));
    ASSERT_TRUE(protocol.ok());

    // Decode every header block of stream 1, in order, with one decoder (they share the client's
    // HPACK state).
    qb::protocol::hpack::Decoder                               decoder;
    std::vector<std::vector<qb::protocol::hpack::HeaderField>> blocks;
    for (std::size_t off = before; off + h2::FRAME_HEADER_SIZE <= io.output.size();) {
        const auto fh = peek_frame_header(io.output, off);
        if (fh.get_type() == h2::FrameType::HEADERS && fh.get_stream_id() == 1) {
            const auto          *first = reinterpret_cast<const uint8_t *>(io.output.cbegin() + off + h2::FRAME_HEADER_SIZE);
            std::vector<uint8_t> payload(first, first + fh.get_payload_length());
            std::vector<qb::protocol::hpack::HeaderField> fields;
            bool                                          incomplete = false;
            ASSERT_TRUE(decoder.decode(payload, fields, incomplete));
            blocks.push_back(std::move(fields));
        }
        off += h2::FRAME_HEADER_SIZE + fh.get_payload_length();
    }
    ASSERT_EQ(blocks.size(), 2u) << "leading HEADERS, then the trailer block";
    auto count = [](const std::vector<qb::protocol::hpack::HeaderField> &fields, std::string_view name) {
        return std::count_if(fields.begin(), fields.end(), [&](const auto &f) { return f.name == name; });
    };
    EXPECT_EQ(count(blocks[0], "trailer"), 1) << "the announcement leads";
    EXPECT_EQ(count(blocks[0], "x-other"), 1);
    EXPECT_EQ(count(blocks[0], "x-checksum"), 0) << "an announced trailer field is not sent in the leading HEADERS";
    ASSERT_EQ(blocks[1].size(), 1u);
    EXPECT_EQ(blocks[1][0].name, "x-checksum");
    EXPECT_EQ(blocks[1][0].value, "cafe");
}

// ===========================================================================
// :authority is the authority every protocol sends (qb::http::origin::authority,
// Huly QB-1064): the scheme's default port left out -- qb::io::uri fills it in,
// and HTTP/2 sent "example.test:443" where HTTP/1.1 sent `Host: example.test` --
// and an IPv6 zone identifier, which has local significance only, never sent
// (RFC 9844 §6).
// ===========================================================================
TEST(HTTP2ClientProtocol, RequestAuthorityIsWhatEveryProtocolSends) {
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"https://example.test/a", "example.test"},
        {"https://example.test:443/a", "example.test"},
        {"https://example.test:8443/a", "example.test:8443"},
        {"https://[2001:db8::1]:8443/a", "[2001:db8::1]:8443"},
        {"https://[fe80::1%25eth0]:8443/a", "[fe80::1]:8443"},
    };
    for (const auto &[uri, authority] : cases) {
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        const std::size_t                          before = io.output.size();

        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri(uri);
        ASSERT_TRUE(protocol.send_request(std::move(req), 1)) << uri;
        const auto blocks = sent_header_blocks(io.output, 1, before);
        ASSERT_EQ(blocks.size(), 1u) << uri;
        EXPECT_EQ(blocks[0].value(":authority"), authority) << uri;
    }
}

// A request's `Host` header never leaves as a `host` field, so the client cannot send one that differs from
// :authority (RFC 9113 section 8.3.1, which the server enforces since Huly QB-1189): :authority is the URI's
// authority when the URI has a host -- the header is then dropped --, the header's value otherwise.
TEST(HTTP2ClientProtocol, ARequestHostHeaderNeverLeavesAsAHostField) {
    const std::vector<std::tuple<std::string, std::string, std::string>> cases = {
        {"https://example.test/a", "example.test", "example.test"},
        {"https://example.test/a", "Other.test", "example.test"},
        {"/a", "from-host.test:8443", "from-host.test:8443"},
    };
    for (const auto &[uri, host, authority] : cases) {
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        const std::size_t                          before = io.output.size();

        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri(uri);
        req.set_header("Host", host);
        ASSERT_TRUE(protocol.send_request(std::move(req), 1)) << uri << " " << host;
        const auto blocks = sent_header_blocks(io.output, 1, before);
        ASSERT_EQ(blocks.size(), 1u) << uri << " " << host;
        EXPECT_EQ(blocks[0].value(":authority"), authority) << uri << " " << host;
        EXPECT_EQ(blocks[0].count(":authority"), 1u) << uri << " " << host;
        EXPECT_EQ(blocks[0].count("host"), 0u) << uri << " " << host;
    }
}

// The regular fields a request sends are those the server accepts on receipt (append_sent_request_fields, Huly
// QB-1191): a connection-specific field RFC 9113 section 8.2.2 names -- `http2-settings` left, and a qbm-http server
// resets the stream that carries it --, a `te` other than the one value `trailers` (a list is what a sender must not
// write, and nghttp2 refuses it), a `content-length` the client did not write from the body, a pseudo-header name, a
// value HTTP/2 cannot carry are left out, whatever their case; the fields kept leave lowercase (section 8.2.1). Each
// request then crosses a qbm-http server and is served.
TEST(HTTP2ClientProtocol, ARequestSendsOnlyTheFieldsTheServerAccepts) {
    const std::vector<std::pair<std::string, std::string>> left_out = {
        {"HTTP2-Settings", "AAMAAABkAAQAAP__"},
        {"http2-settings", "AAMAAABkAAQAAP__"},
        {"Connection", "keep-alive"},
        {"Proxy-Connection", "keep-alive"},
        {"Keep-Alive", "timeout=5"},
        {"Transfer-Encoding", "chunked"},
        {"Upgrade", "h2c"},
        {"TE", "gzip"},
        {"TE", "trailers, trailers"},
        {"TE", "trailers,"},
        {"TE", " trailers"},
        {"Content-Length", "99"},
        {":protocol", "websocket"},
        {"x-bad", "a\rb"},
    };
    for (const auto &[name, value] : left_out) {
        Http2ClientFakeIO                          client_io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);
        Http2PeerFakeIO                            server_io;
        h2::ServerHttp2Protocol<Http2PeerFakeIO>   server(server_io);
        const std::size_t                          before = client_io.output.size();

        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/r");
        req.set_header(name, value);
        req.set_header("X-Kept", "1");
        ASSERT_TRUE(client.send_request(std::move(req), 1)) << name;

        const auto blocks = sent_header_blocks(client_io.output, 1, before);
        ASSERT_EQ(blocks.size(), 1u) << name;
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](char c) { return qb::http::utility::ascii_to_lower(c); });
        EXPECT_EQ(blocks[0].count(lower), 0u) << name << " left the client";
        EXPECT_EQ(blocks[0].value("x-kept"), "1") << "a field the server accepts leaves lowercase";
        EXPECT_EQ(blocks[0].count("X-Kept"), 0u);

        pump(server, server_io, client_io);
        EXPECT_TRUE(server.ok()) << name;
        EXPECT_EQ(server_io.request_count, 1) << name << ": the server refused the request";
    }

    // A field the `connection` header names is connection-specific with it (RFC 9110 section 7.6.1): left out, whatever
    // its case -- `te` excepted, which HTTP/1.1 names there and HTTP/2 judges by its value.
    {
        Http2ClientFakeIO                          client_io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);
        Http2PeerFakeIO                            server_io;
        h2::ServerHttp2Protocol<Http2PeerFakeIO>   server(server_io);
        const std::size_t                          before = client_io.output.size();
        qb::http::Request                          req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/r");
        req.add_header("Connection", "X-Hop, te");
        req.add_header("Connection", " x-other ,");
        req.set_header("X-Hop", "1");
        req.set_header("X-Other", "2");
        req.set_header("TE", "trailers");
        req.set_header("X-Kept", "3");
        ASSERT_TRUE(client.send_request(std::move(req), 1));
        const auto blocks = sent_header_blocks(client_io.output, 1, before);
        ASSERT_EQ(blocks.size(), 1u);
        EXPECT_EQ(blocks[0].count("x-hop"), 0u);
        EXPECT_EQ(blocks[0].count("x-other"), 0u);
        EXPECT_EQ(blocks[0].count("connection"), 0u);
        EXPECT_EQ(blocks[0].value("te"), "trailers");
        EXPECT_EQ(blocks[0].value("x-kept"), "3");
        pump(server, server_io, client_io);
        EXPECT_EQ(server_io.request_count, 1);
    }

    // `te: trailers` is the one `te` a request carries; a second value it does not allow is left out alone.
    Http2ClientFakeIO                          client_io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);
    Http2PeerFakeIO                            server_io;
    h2::ServerHttp2Protocol<Http2PeerFakeIO>   server(server_io);
    const std::size_t                          before = client_io.output.size();
    qb::http::Request                          req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/r");
    req.add_header("TE", "trailers");
    req.add_header("TE", "gzip");
    ASSERT_TRUE(client.send_request(std::move(req), 1));
    const auto blocks = sent_header_blocks(client_io.output, 1, before);
    ASSERT_EQ(blocks.size(), 1u);
    EXPECT_EQ(blocks[0].count("te"), 1u);
    EXPECT_EQ(blocks[0].value("te"), "trailers");
    pump(server, server_io, client_io);
    EXPECT_EQ(server_io.request_count, 1);
}

// ===========================================================================
// A request's trailers() leave in its trailer section once the body is out --
// without send_request_trailers(), on a protocol that otherwise waits for it --
// announced by a `trailer` field the leading HEADERS gain (RFC 9110 §6.6.2).
// An empty body alike: the leading HEADERS then do not end the stream (Huly
// QB-1073).
// ===========================================================================
TEST(HTTP2ClientProtocol, RequestTrailersContainerLeavesAfterTheBody) {
    for (const bool with_body : {true, false}) {
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        ASSERT_TRUE(protocol.explicit_request_trailers()) << "the protocol's default: it would wait for send_request_trailers()";
        const std::size_t before = io.output.size();

        qb::http::Request req;
        req.method() = qb::http::method::POST;
        req.uri()    = qb::io::uri("https://example.test/container");
        if (with_body) {
            req.body() = "ab";
        }
        req.trailers().set_header("x-checksum", "cafe");
        ASSERT_TRUE(protocol.send_request(std::move(req), 10));
        ASSERT_TRUE(protocol.ok());

        const auto blocks = sent_header_blocks(io.output, 1, before);
        ASSERT_EQ(blocks.size(), 2u) << "leading HEADERS, then the trailer block (body " << with_body << ")";
        EXPECT_FALSE(blocks[0].flags & h2::FLAG_END_STREAM);
        EXPECT_EQ(blocks[0].value("trailer"), "x-checksum") << "the announcement the request did not write";
        EXPECT_EQ(blocks[0].count("x-checksum"), 0u);
        EXPECT_TRUE(blocks[1].flags & h2::FLAG_END_STREAM);
        ASSERT_EQ(blocks[1].fields.size(), 1u);
        EXPECT_EQ(blocks[1].value("x-checksum"), "cafe");
    }
}

// ===========================================================================
// A field of a request's trailers() a trailer section must not carry refuses the
// request before anything is sent: send_request() returns false and no HEADERS
// leave (Huly QB-1073).
// ===========================================================================
TEST(HTTP2ClientProtocol, RequestWithAForbiddenTrailerFieldIsRefusedBeforeAnythingIsSent) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    const std::size_t                          before = io.output.size();

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/forbidden");
    req.body()   = "ab";
    req.trailers().set_header("content-length", "2");
    EXPECT_FALSE(protocol.send_request(std::move(req), 11));
    EXPECT_TRUE(protocol.ok()) << "the connection is untouched";
    EXPECT_EQ(io.output.size(), before) << "nothing was sent";

    // The next request is sent normally.
    qb::http::Request next;
    next.method() = qb::http::method::GET;
    next.uri()    = qb::io::uri("https://example.test/next");
    EXPECT_TRUE(protocol.send_request(std::move(next), 12));
    EXPECT_GT(io.output.size(), before);
}

// ===========================================================================
// A request that announces trailer fields it does not set keeps its stream open
// for send_request_trailers() -- the protocol's contract -- unless the caller
// never hands trailers over (set_explicit_request_trailers(false), what
// qb::http2::Client does): the stream then ends once the body is out, with an
// empty trailer block (Huly QB-1061).
// ===========================================================================
TEST(HTTP2ClientProtocol, UnsetAnnouncedTrailersWaitForTheCallerUnlessExplicitTrailersAreOff) {
    for (const bool explicit_trailers : {true, false}) {
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        EXPECT_TRUE(protocol.explicit_request_trailers()) << "the protocol's default";
        protocol.set_explicit_request_trailers(explicit_trailers);
        const std::size_t before = io.output.size();

        qb::http::Request req;
        req.method() = qb::http::method::POST;
        req.uri()    = qb::io::uri("https://example.test/unset");
        req.body()   = "ab";
        req.set_header("trailer", "x-checksum"); // announced, never set
        ASSERT_TRUE(protocol.send_request(std::move(req), 4));
        ASSERT_TRUE(protocol.ok());

        std::vector<h2::FrameHeader> headers_frames;
        bool                         data_ended = false;
        for (std::size_t off = before; off + h2::FRAME_HEADER_SIZE <= io.output.size();) {
            const auto fh = peek_frame_header(io.output, off);
            if (fh.get_stream_id() == 1 && fh.get_type() == h2::FrameType::HEADERS) {
                headers_frames.push_back(fh);
            }
            data_ended = data_ended || (fh.get_type() == h2::FrameType::DATA && (fh.flags & h2::FLAG_END_STREAM));
            off += h2::FRAME_HEADER_SIZE + fh.get_payload_length();
        }
        EXPECT_FALSE(data_ended) << "a trailer section was announced: the last DATA does not end the stream";
        if (explicit_trailers) {
            EXPECT_EQ(headers_frames.size(), 1u) << "the stream waits for send_request_trailers()";
        } else {
            ASSERT_EQ(headers_frames.size(), 2u) << "leading HEADERS, then the empty trailer block";
            EXPECT_TRUE(headers_frames[1].flags & h2::FLAG_END_STREAM);
            EXPECT_EQ(headers_frames[1].get_payload_length(), 0u);
        }
    }
}

// ===========================================================================
// Automatic trailers: a body that waited for flow-control credit is followed by
// the request headers the "Trailer" header names. Those names come from the
// header's VALUE, as written ("X-Checksum"), and HTTP/2 field names must be
// lowercase (RFC 9113 §8.2.1): sent as written, the server refused the trailer
// block and the request was never dispatched.
// ===========================================================================
TEST(HTTP2ClientProtocol, AutomaticTrailerNamesAreSentLowercase) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    Http2FakeIO                                server_io;
    h2::ServerHttp2Protocol<Http2FakeIO>       server(server_io);

    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 1}}));
    ASSERT_TRUE(protocol.ok());

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/auto-trailers");
    req.body()   = "ab"; // one octet fits, one waits
    req.set_header("trailer", "X-Checksum");
    req.set_header("x-checksum", "cafe");
    ASSERT_TRUE(protocol.send_request(std::move(req), 8));
    protocol.on(make_window_update_frame(1, 10)); // the rest of the body, then the trailers
    ASSERT_TRUE(protocol.ok());

    pump(server, server_io, io);
    EXPECT_TRUE(server.ok());
    ASSERT_EQ(server_io.request_count, 1) << "the trailer block was refused";
    EXPECT_EQ(server_io.last_request->body().as<std::string>(), "ab");
}

// ===========================================================================
// A header block arriving on a stream the client already reset -- here the
// server's trailers, in flight when the client refused the response's headers
// -- is still decoded: the server's encoder indexed its fields in the shared
// dynamic table and its next block references them (RFC 9113 §4.3). The client
// used to answer RST_STREAM without decoding, and the next response was read
// against a table out of step (Huly QB-534, client side).
// ===========================================================================
TEST(HTTP2ClientProtocol, HeaderBlockOnAResetStreamStillFeedsTheHpackTable) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    qb::protocol::hpack::Encoder               server_encoder; // one encoder: the server's

    for (uint64_t app_id : {1u, 2u}) {
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/r" + std::to_string(app_id));
        ASSERT_TRUE(protocol.send_request(std::move(req), app_id)); // streams 1 and 3
    }

    auto block = [&](const std::vector<qb::protocol::hpack::HeaderField> &h) {
        std::vector<uint8_t> out;
        EXPECT_TRUE(server_encoder.encode(h, out));
        return out;
    };
    // Stream 1: a forbidden response header makes the client reset the stream.
    push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS, 1, block({{":status", "200"}, {"connection", "close"}}));
    // Stream 1 again: the server's trailers, already on the wire; they index "x-t: 1".
    push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, 1, block({{"x-t", "1"}}));
    // Stream 3: a response that references that entry.
    push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, 3, block({{":status", "204"}, {"x-t", "1"}}));
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(io.last_app_id, 2u);
    ASSERT_TRUE(io.last_status.has_value());
    EXPECT_EQ(*io.last_status, 204);
}

// ===========================================================================
// send_request_trailers without an announced "trailer" header is rejected with
// RST_STREAM(PROTOCOL_ERROR) and returns false.
// ===========================================================================
TEST(HTTP2ClientProtocol, SendTrailersWithoutAnnouncementRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 1}}));
    ASSERT_TRUE(protocol.ok());

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/no-announce");
    req.body()   = "bb"; // 2-byte body, only 1 byte fits -> stays pending/open.
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    const std::size_t before = io.output.size();

    qb::http::headers trailers;
    trailers.add_header("x-foo", "bar");
    EXPECT_FALSE(protocol.send_request_trailers(1, trailers));

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, before);
    ASSERT_NE(rst_off, SIZE_MAX);
    EXPECT_EQ(peek_frame_header(io.output, rst_off).get_stream_id(), 1u);
}

// ===========================================================================
// application_reject_push for an id that was never promised is a documented
// no-op: no frame emitted, connection healthy.
// ===========================================================================
TEST(HTTP2ClientProtocol, ApplicationRejectPushUnknownIdIsSafeNoop) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/p");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();
    protocol.application_reject_push(4);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.output.size(), before); // No frame emitted.
}

// ===========================================================================
// PUSH_PROMISE with promised_stream_id == 0 (invalid) is a connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, PushPromiseWithZeroPromisedStreamIdIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    h2::Http2FrameData<h2::PushPromiseFrame> pp;
    pp.header.type  = static_cast<uint8_t>(h2::FrameType::PUSH_PROMISE);
    pp.header.flags = h2::FLAG_END_HEADERS;
    pp.header.set_stream_id(1);
    pp.payload.promised_stream_id    = 0;
    pp.payload.header_block_fragment = encode_hpack_headers({{":method", "GET"}, {":path", "/x"}});
    protocol.on(std::move(pp));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// PUSH_PROMISE while push is disabled, with an association that was never opened:
// the push-disabled gate (RFC 9113 §8.4) fires first, so this is a clean PROTOCOL_ERROR
// connection error — the handler must not fall through to dereference the missing parent.
// ===========================================================================
TEST(HTTP2ClientProtocol, PushPromiseWhenPushDisabledWithUnknownAssociationIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    h2::Http2FrameData<h2::PushPromiseFrame> pp;
    pp.header.type  = static_cast<uint8_t>(h2::FrameType::PUSH_PROMISE);
    pp.header.flags = h2::FLAG_END_HEADERS;
    pp.header.set_stream_id(3); // associated stream never opened
    pp.payload.promised_stream_id    = 2;
    pp.payload.header_block_fragment = encode_hpack_headers({{":method", "GET"}, {":path", "/x"}});
    protocol.on(std::move(pp));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.push_promise_count, 0);
}

// ===========================================================================
// LIFECYCLE — multiple concurrent requests (1, 3, 5) with interleaved responses.
// ===========================================================================
TEST(HTTP2ClientProtocol, MultipleConcurrentRequestsInterleavedResponses) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    for (int i = 0; i < 3; ++i) {
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/n");
        ASSERT_TRUE(protocol.send_request(std::move(req), 100 + i));
    }
    EXPECT_EQ(protocol.last_initiated_stream_id(), 5u);

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
// LIFECYCLE — graceful GOAWAY after all relevant streams are already closed
// signals a clean shutdown (not-ok with NO_ERROR).
// ===========================================================================
TEST(HTTP2ClientProtocol, GracefulGoawayAfterStreamsClosedSignalsCleanShutdown) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/done");
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "204"}}));
    ASSERT_EQ(io.response_count, 1);

    h2::Http2FrameData<h2::GoAwayFrame> goaway;
    goaway.header.type = static_cast<uint8_t>(h2::FrameType::GOAWAY);
    goaway.header.set_stream_id(0);
    goaway.payload.last_stream_id = 1;
    goaway.payload.error_code     = h2::ErrorCode::NO_ERROR;
    protocol.on(std::move(goaway));

    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::NO_ERROR);
    EXPECT_FALSE(protocol.ok());
}

// ===========================================================================
// GOAWAY implicitly closes streams above last_stream_id.
//
// REGRESSION (ASan): stream 3 has a DISPATCHABLE response at GOAWAY time. The
// implicit-close loop used to mark CLOSED+rst, then
// process_complete_response_if_ready() dispatched AND erased the stream context,
// after which the loop's own erase() operated on an invalidated iterator ->
// use-after-free. The loop now collects ids first and only erases entries still
// present. Run under ASan to exercise the regression.
// ===========================================================================
TEST(HTTP2ClientProtocol, GoawayImplicitlyClosesStreamsAboveLastStreamId) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req1;
    req1.method() = qb::http::method::GET;
    req1.uri()    = qb::io::uri("https://example.test/1");
    ASSERT_TRUE(protocol.send_request(std::move(req1), 1));

    qb::http::Request req3;
    req3.method() = qb::http::method::GET;
    req3.uri()    = qb::io::uri("https://example.test/3");
    ASSERT_TRUE(protocol.send_request(std::move(req3), 3));
    ASSERT_TRUE(protocol.ok());

    protocol.on(make_headers_frame(3, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    EXPECT_EQ(io.response_count, 0);

    h2::Http2FrameData<h2::GoAwayFrame> goaway;
    goaway.header.type = static_cast<uint8_t>(h2::FrameType::GOAWAY);
    goaway.header.set_stream_id(0);
    goaway.payload.last_stream_id = 1;
    goaway.payload.error_code     = h2::ErrorCode::NO_ERROR;
    protocol.on(std::move(goaway));

    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::NO_ERROR);
    EXPECT_EQ(io.response_count, 1);
    EXPECT_EQ(io.last_app_id, 3u);

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "200"}}));
    EXPECT_EQ(io.response_count, 2);
    EXPECT_EQ(io.last_app_id, 1u);
}

// ===========================================================================
// ERROR — WINDOW_UPDATE with a zero increment on a *stream* RSTs that stream.
// ===========================================================================
TEST(HTTP2ClientProtocol, ZeroIncrementStreamWindowUpdateRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/z");
    req.body()   = "x";
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    const std::size_t before = io.output.size();
    protocol.on(make_window_update_frame(1, 0));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, before);
    ASSERT_NE(rst_off, SIZE_MAX);
    EXPECT_EQ(peek_frame_header(io.output, rst_off).get_stream_id(), 1u);
}

// ===========================================================================
// ERROR — WINDOW_UPDATE overflowing a stream's send window beyond 2^31-1 is a
// FLOW_CONTROL_ERROR connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, StreamWindowUpdateOverflowIsFlowControlError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/ovf");
    req.body()   = "x";
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

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
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    h2::Http2FrameData<h2::PriorityFrame> prio;
    prio.header.type = static_cast<uint8_t>(h2::FrameType::PRIORITY);
    prio.header.set_stream_id(0);
    protocol.on(std::move(prio));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
}

// ===========================================================================
// PRIORITY frame on a known stream is accepted and is not an error.
// ===========================================================================
TEST(HTTP2ClientProtocol, PriorityFrameOnKnownStreamIsAccepted) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

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
// SETTINGS — server raises MAX_FRAME_SIZE; a 20000-byte body that would split at
// the 16384 default fits in a single DATA frame once the peer raised it to 32768.
// ===========================================================================
TEST(HTTP2ClientProtocol, ServerSettingsRaiseMaxFrameSizeAffectsChunking) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    protocol.on(make_settings_frame(
        {{h2::Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 32768}, {h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 100000}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/chunk");
    req.body()   = std::string(20000, 'c');
    ASSERT_TRUE(protocol.send_request(std::move(req), 1));

    EXPECT_EQ(count_frames_from(io.output, h2::FrameType::DATA, before), 1u);
    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 20000u);
}

// ===========================================================================
// SETTINGS — a server may send SETTINGS_ENABLE_PUSH only as 0 (RFC 9113 §6.5.2):
// 1 is a connection PROTOCOL_ERROR like the out-of-range 2 (Huly QB-567); 0 is
// accepted and acknowledged.
// ===========================================================================
TEST(HTTP2ClientProtocol, ServerSettingsEnablePushOtherThanZeroIsConnectionError) {
    for (const uint32_t value : {2u, 1u}) {
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

        protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, value}}));

        EXPECT_FALSE(protocol.ok()) << "ENABLE_PUSH=" << value;
        ASSERT_TRUE(protocol.get_last_error_code().has_value());
        EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
        EXPECT_EQ(io.goaway_count, 1);
    }

    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    io.output.reset();
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_ENABLE_PUSH, 0}}));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_NE(find_frame_offset(io.output, h2::FrameType::SETTINGS), SIZE_MAX) << "SETTINGS ACK sent";
}

// ===========================================================================
// SETTINGS on a non-zero stream id is a connection error.
// ===========================================================================
TEST(HTTP2ClientProtocol, SettingsOnNonZeroStreamIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

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
// Full round-trip with a body: client POST -> peer parses body -> server replies
// with a body -> client assembles the response.
// ===========================================================================
TEST(HTTP2ClientProtocol, RoundTripPostWithBodyThroughPeerServer) {
    Http2ClientFakeIO                          client_io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);

    Http2PeerFakeIO                          server_io;
    h2::ServerHttp2Protocol<Http2PeerFakeIO> server(server_io);

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

// ===========================================================================
// HPACK dynamic-table eviction across multiple header sets on one shared codec
// pair (the same machinery the client uses across requests on a connection). As
// custom headers accumulate they are inserted into the dynamic table; lowering
// the table size limit forces eviction, yet every header set still round-trips
// byte-exactly through a matching Decoder. Concrete eviction assertion replaces
// the dossier's flagged cout-only / tautology HPACK checks.
// ===========================================================================
TEST(HTTP2ClientProtocol, HpackDynamicTableEvictsButStillRoundTrips) {
    qb::protocol::hpack::Encoder encoder;
    qb::protocol::hpack::Decoder decoder;

    // Header field large enough that only a couple fit in a small dynamic table.
    auto make_field = [](int i) {
        return qb::protocol::hpack::HeaderField{"x-custom-header-" + std::to_string(i), std::string(60, static_cast<char>('a' + (i % 26)))};
    };

    // Constrain both sides' dynamic table to a small budget so insertion of new
    // entries necessarily evicts older ones.
    constexpr uint32_t kSmallTable = 128;
    encoder.set_peer_max_dynamic_table_size(kSmallTable);
    decoder.set_max_dynamic_table_size(kSmallTable);

    std::size_t max_entries_seen = 0;
    for (int i = 0; i < 20; ++i) {
        const std::vector<qb::protocol::hpack::HeaderField> headers{make_field(i)};

        std::vector<uint8_t> encoded;
        ASSERT_TRUE(encoder.encode(headers, encoded));

        std::vector<qb::protocol::hpack::HeaderField> decoded;
        bool                                          incomplete = true;
        ASSERT_TRUE(decoder.decode(encoded, decoded, incomplete));
        EXPECT_FALSE(incomplete);

        // Byte-exact round-trip despite the churning dynamic table.
        ASSERT_EQ(decoded.size(), 1u);
        EXPECT_EQ(decoded[0].name, headers[0].name);
        EXPECT_EQ(decoded[0].value, headers[0].value);

        max_entries_seen = std::max(max_entries_seen, encoder.get_dynamic_table_entry_count());
    }

    // The encoder's dynamic table never exceeds its byte budget...
    EXPECT_LE(encoder.get_dynamic_table_size(), kSmallTable);
    // ...and with 20 distinct ~80-byte entries against a 128-byte table, eviction
    // must have happened: far fewer than 20 entries are retained at any time.
    EXPECT_LT(max_entries_seen, 20u);
    // The decoder's table likewise stays within budget.
    EXPECT_LE(decoder.get_dynamic_table_size(), kSmallTable);
}

// ===========================================================================
// FLOW CONTROL — a connection-level WINDOW_UPDATE whose increment would push the
// connection send window past 2^31-1 is a connection error (FLOW_CONTROL_ERROR ->
// GOAWAY). The default connection send window is 65535, so an increment of
// 0x7FFFFFFF (the max legal single increment) overflows it: 65535 > (MAX - inc).
// Mirrors StreamWindowUpdateOverflowIsFlowControlError but for stream 0.
// ===========================================================================
TEST(HTTP2ClientProtocol, ConnectionWindowUpdateOverflowIsFlowControlError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    protocol.on(make_window_update_frame(0, 0x7FFFFFFF));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::FLOW_CONTROL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// ===========================================================================
// CONTENT-LENGTH (under-run) — a response that advertises content-length: 50 but
// terminates the stream (END_STREAM) with only 5 body bytes is a content-length
// mismatch: the client RST_STREAMs the stream (PROTOCOL_ERROR), dispatches no
// response, and stays connection-OK. Hits the
// `body().raw().size() != *expected_content_length` mismatch branch in
// process_complete_response_if_ready / on(DataFrame, END_STREAM).
// ===========================================================================
TEST(HTTP2ClientProtocol, ResponseBodyShorterThanContentLengthIsMismatchRst) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/short");
    ASSERT_TRUE(protocol.send_request(std::move(req), 21));

    const std::size_t output_before = io.output.size();

    // HEADERS announce a 50-byte body but do NOT end the stream.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"content-length", "50"}}));
    EXPECT_EQ(io.response_count, 0);

    // Only 5 bytes arrive, then END_STREAM: 5 != 50 -> content-length mismatch.
    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "short"));

    EXPECT_TRUE(protocol.ok()); // stream-level RST, connection survives
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, output_before);
    ASSERT_NE(rst_off, SIZE_MAX);
    EXPECT_EQ(peek_frame_header(io.output, rst_off).get_stream_id(), 1u);
}

// ===========================================================================
// CONTENT-LENGTH (over-run) — a single DATA frame carrying MORE bytes than the
// advertised content-length is rejected immediately with RST_STREAM
// (PROTOCOL_ERROR, "body exceeds content-length") on the DATA-frame path, before
// END_STREAM. Hits the `body_size > *expected_content_length` branch.
// ===========================================================================
TEST(HTTP2ClientProtocol, ResponseBodyLongerThanContentLengthIsRst) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/long");
    ASSERT_TRUE(protocol.send_request(std::move(req), 23));

    const std::size_t output_before = io.output.size();

    // Announce a 2-byte body, then deliver 10 bytes (no END_STREAM needed: the
    // overflow is detected as soon as accumulated body exceeds the bound).
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"content-length", "2"}}));
    protocol.on(make_data_frame(1, 0, "0123456789"));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, output_before);
    ASSERT_NE(rst_off, SIZE_MAX);
    EXPECT_EQ(peek_frame_header(io.output, rst_off).get_stream_id(), 1u);
}

// ===========================================================================
// Wave-2 coverage: error/edge branches in ClientHttp2Protocol that are only
// reachable by dispatching typed frames straight to the protocol's `on(...)`
// overloads (bypassing the base framer's own pre-dispatch validation) or by
// exercising the public trailer/CONTINUATION surface with adversarial input.
// All socket-less and deterministic. See coverage cluster `h2-client`.
// ===========================================================================

namespace {

// Build a CONTINUATION Http2FrameData ready to hand to protocol.on(...). Used to
// drive the client's own on(ContinuationFrame) guard branches, which the base
// framer would otherwise reject before they are reached.
[[nodiscard]] h2::Http2FrameData<h2::ContinuationFrame>
make_continuation_frame(uint32_t stream_id, uint8_t flags, const std::vector<uint8_t> &fragment) {
    h2::Http2FrameData<h2::ContinuationFrame> frame;
    frame.header.type  = static_cast<uint8_t>(h2::FrameType::CONTINUATION);
    frame.header.flags = flags;
    frame.header.set_stream_id(stream_id);
    frame.payload.header_block_fragment = fragment;
    return frame;
}

} // namespace

// ---------------------------------------------------------------------------
// CONTINUATION dispatched while no header block is open (i.e.
// `_active_header_block_stream_id == 0`) is a connection PROTOCOL_ERROR. The
// base framer normally rejects a stray CONTINUATION before dispatch, so this
// drives the protocol's own guard (client.h on(ContinuationFrame), first branch)
// directly.
// ---------------------------------------------------------------------------
TEST(HTTP2ClientProtocol, ContinuationWithNoOpenHeaderBlockIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    const std::size_t before = io.output.size();
    protocol.on(make_continuation_frame(1, h2::FLAG_END_HEADERS, {0x00}));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_NE(find_frame_offset(io.output, h2::FrameType::GOAWAY, before), SIZE_MAX);
}

// ---------------------------------------------------------------------------
// HEADERS for an even (server-initiated) stream id that was never promised and
// is not pending-pushed is treated as HEADERS on an unknown/closed stream:
// the client RST_STREAMs that id (STREAM_CLOSED) and the connection survives.
// Drives client.h on(HeadersFrame) unknown-stream RST branch (the even id skips
// the "idle client stream" GOAWAY branch reserved for odd ids).
// ---------------------------------------------------------------------------
TEST(HTTP2ClientProtocol, HeadersForUnknownEvenStreamRstsStreamOnly) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    const std::size_t before = io.output.size();
    // Even id 4 was never promised via PUSH_PROMISE and is not a known stream.
    protocol.on(make_headers_frame(4, h2::FLAG_END_HEADERS, {{":status", "200"}}));

    EXPECT_TRUE(protocol.ok()); // stream-level only, connection healthy
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(io.response_count, 0);

    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, before);
    ASSERT_NE(rst_off, SIZE_MAX);
    EXPECT_EQ(peek_frame_header(io.output, rst_off).get_stream_id(), 4u);
    EXPECT_FALSE(io.last_status.has_value());
}

// ---------------------------------------------------------------------------
// send_request_trailers — trailer validation rejects: a trailer carrying a
// PSEUDO-header name (leading ':') is a stream PROTOCOL_ERROR (RST_STREAM) and
// the call returns false. Hits client.h send_request_trailers pseudo-header
// branch. The stream must first have announced trailers (request "trailer"
// header) and stay open (body not fully flushed) so the trailer path is taken.
// ---------------------------------------------------------------------------
TEST(HTTP2ClientProtocol, SendTrailersWithPseudoHeaderNameRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    // Tiny stream window so the body DATA cannot fully flush -> stream stays OPEN
    // and end_stream_sent stays false, keeping the trailer path live.
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 1}}));

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/trailers-pseudo");
    req.body()   = "bb";
    req.set_header("trailer", "x-checksum");
    ASSERT_TRUE(protocol.send_request(std::move(req), 31));

    const std::size_t before = io.output.size();

    qb::http::headers trailers;
    trailers.add_header(":status", "200"); // pseudo-header is forbidden in trailers
    EXPECT_FALSE(protocol.send_request_trailers(1, trailers));

    EXPECT_TRUE(protocol.ok());
    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, before);
    ASSERT_NE(rst_off, SIZE_MAX);
    EXPECT_EQ(peek_frame_header(io.output, rst_off).get_stream_id(), 1u);
}

// ---------------------------------------------------------------------------
// send_request_trailers — a FORBIDDEN trailer header (`content-length`, which
// is_forbidden_trailer_header rejects) is a stream PROTOCOL_ERROR and returns
// false. Hits client.h send_request_trailers forbidden-header branch.
// ---------------------------------------------------------------------------
TEST(HTTP2ClientProtocol, SendTrailersWithForbiddenHeaderRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 1}}));

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/trailers-forbidden");
    req.body()   = "bb";
    req.set_header("trailer", "content-length");
    ASSERT_TRUE(protocol.send_request(std::move(req), 33));

    const std::size_t before = io.output.size();

    qb::http::headers trailers;
    trailers.add_header("content-length", "5"); // forbidden in the trailer section
    EXPECT_FALSE(protocol.send_request_trailers(1, trailers));

    EXPECT_TRUE(protocol.ok());
    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, before);
    ASSERT_NE(rst_off, SIZE_MAX);
    EXPECT_EQ(peek_frame_header(io.output, rst_off).get_stream_id(), 1u);
}

// ---------------------------------------------------------------------------
// send_request_trailers — a trailer whose VALUE contains a control byte (CR)
// fails is_valid_header_field and is a stream PROTOCOL_ERROR returning false.
// Hits client.h send_request_trailers invalid-value branch.
// ---------------------------------------------------------------------------
TEST(HTTP2ClientProtocol, SendTrailersWithInvalidValueRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 1}}));

    qb::http::Request req;
    req.method() = qb::http::method::POST;
    req.uri()    = qb::io::uri("https://example.test/trailers-badvalue");
    req.body()   = "bb";
    req.set_header("trailer", "x-checksum");
    ASSERT_TRUE(protocol.send_request(std::move(req), 35));

    const std::size_t before = io.output.size();

    qb::http::headers trailers;
    trailers.add_header("x-checksum", std::string("dead\r\nbeef")); // CRLF -> invalid value
    EXPECT_FALSE(protocol.send_request_trailers(1, trailers));

    EXPECT_TRUE(protocol.ok());
    const auto rst_off = find_frame_offset(io.output, h2::FrameType::RST_STREAM, before);
    ASSERT_NE(rst_off, SIZE_MAX);
    EXPECT_EQ(peek_frame_header(io.output, rst_off).get_stream_id(), 1u);
}

// ===========================================================================
// Wave-2 coverage: response HEADERS validation rejects in
// parse_and_validate_headers_into_response. Each case sends a single request to
// open stream 1, then dispatches a response HEADERS block that is malformed in
// exactly one way; the client RST_STREAMs the stream (PROTOCOL_ERROR or
// ENHANCE_YOUR_CALM), dispatches no response, and the connection stays OK.
// ===========================================================================

namespace {

// Open client stream 1 by sending a GET, returns the protocol ready for a
// response HEADERS frame on stream 1.
void
open_stream_one(h2::ClientHttp2Protocol<Http2ClientFakeIO> &protocol, uint64_t app_id, const char *path) {
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri(std::string("https://example.test") + path);
    ASSERT_TRUE(protocol.send_request(std::move(req), app_id));
}

} // namespace

// A regular header appearing BEFORE the :status pseudo-header violates pseudo-
// header ordering (validate_pseudo_header_order) -> PROTOCOL_ERROR RST.
TEST(HTTP2ClientProtocol, ResponsePseudoHeaderAfterRegularHeaderRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 41, "/order");

    const std::size_t before = io.output.size();
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{"x-early", "1"}, {":status", "200"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
    ASSERT_NE(find_frame_offset(io.output, h2::FrameType::RST_STREAM, before), SIZE_MAX);
}

// A regular header whose NAME contains an uppercase letter fails
// is_valid_header_field (HTTP/2 header names must be lowercase) ->
// PROTOCOL_ERROR RST. (An uppercase name survives the HPACK round-trip, unlike a
// control-byte value which the encoder may sanitize before it reaches the
// validator.)
TEST(HTTP2ClientProtocol, ResponseInvalidRegularHeaderValueRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 43, "/badhdr");

    const std::size_t before = io.output.size();
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"X-Bad-Upper", "v"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
    ASSERT_NE(find_frame_offset(io.output, h2::FrameType::RST_STREAM, before), SIZE_MAX);
}

// A connection-specific response field (RFC 9113 section 8.2.2), `te` whatever its value, or `http2-settings`
// -> PROTOCOL_ERROR RST (is_forbidden_response_header branch).
TEST(HTTP2ClientProtocol, ResponseForbiddenConnectionHeaderRstsStream) {
    for (const auto &[name, value] : std::vector<std::pair<std::string, std::string>>{
             {"connection", "keep-alive"},
             {"proxy-connection", "keep-alive"},
             {"keep-alive", "timeout=5"},
             {"transfer-encoding", "chunked"},
             {"upgrade", "h2c"},
             {"te", "trailers"},
             {"http2-settings", "AAMAAABk"}
         }) {
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        open_stream_one(protocol, 45, "/forbidden");

        const std::size_t before = io.output.size();
        protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {name, value}}));

        EXPECT_TRUE(protocol.ok()) << name;
        EXPECT_EQ(io.response_count, 0) << name;
        EXPECT_EQ(io.stream_error_count, 1) << name;
        EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR) << name;
        ASSERT_NE(find_frame_offset(io.output, h2::FrameType::RST_STREAM, before), SIZE_MAX) << name;
    }
}

// `host` is no connection-specific field (RFC 9113 section 8.2.2): a response carrying one is delivered with it,
// as the HTTP/1.1 and HTTP/3 clients deliver it. The stream was reset (Huly QB-1189).
TEST(HTTP2ClientProtocol, ResponseWithAHostFieldIsDelivered) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 46, "/host");

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "200"}, {"host", "example.test"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 0);
    ASSERT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_response.has_value());
    EXPECT_EQ(io.last_response->header("Host"), "example.test");
}

// A non-numeric content-length value fails parse_content_length ->
// PROTOCOL_ERROR RST.
TEST(HTTP2ClientProtocol, ResponseInvalidContentLengthRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 47, "/badcl");

    const std::size_t before = io.output.size();
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"content-length", "not-a-number"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
    ASSERT_NE(find_frame_offset(io.output, h2::FrameType::RST_STREAM, before), SIZE_MAX);
}

// Two DIFFERENT content-length values on the same response are conflicting ->
// PROTOCOL_ERROR RST (second value mismatches the stored expected length).
TEST(HTTP2ClientProtocol, ResponseConflictingContentLengthRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 49, "/conflict");

    const std::size_t before = io.output.size();
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"content-length", "5"}, {"content-length", "7"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
    ASSERT_NE(find_frame_offset(io.output, h2::FrameType::RST_STREAM, before), SIZE_MAX);
}

// A content-length larger than the configured MAX_BODY_SIZE is refused with
// ENHANCE_YOUR_CALM RST before any body arrives.
TEST(HTTP2ClientProtocol, ResponseContentLengthExceedsLimitRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 51, "/huge");

    const std::size_t before = io.output.size();
    // Far beyond MAX_BODY_SIZE; parse_content_length accepts it, the limit check rejects.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"content-length", "99999999999999"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
    ASSERT_NE(find_frame_offset(io.output, h2::FrameType::RST_STREAM, before), SIZE_MAX);
}

// A :status that is three digits and numeric (so it passes the pseudo-header
// validator) but is below 100 ("000") is rejected by parse_status_code ->
// PROTOCOL_ERROR RST. Drives the post-loop status-parse branch.
TEST(HTTP2ClientProtocol, ResponseStatusBelowOneHundredRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 53, "/status000");

    const std::size_t before = io.output.size();
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "000"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
    ASSERT_NE(find_frame_offset(io.output, h2::FrameType::RST_STREAM, before), SIZE_MAX);
}

// A pseudo-header appearing in a TRAILERS block (which skips the response-pseudo
// validator) is rejected with PROTOCOL_ERROR RST. The main response is assembled
// first (HEADERS + DATA without END_STREAM is not needed: HEADERS-only with a
// "trailer" announce, then a trailers HEADERS carrying a pseudo-header).
TEST(HTTP2ClientProtocol, ResponsePseudoHeaderInTrailersRstsStream) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 55, "/trailer-pseudo");

    // Main response headers announce trailers and do NOT end the stream.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"trailer", "x-sig"}}));
    ASSERT_TRUE(protocol.ok());

    const std::size_t before = io.output.size();
    // Trailers block (END_STREAM) carrying a pseudo-header -> rejected.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "204"}}));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR);
    ASSERT_NE(find_frame_offset(io.output, h2::FrameType::RST_STREAM, before), SIZE_MAX);
}

// ===========================================================================
// Coverage-fill: protocol-internal error / state branches reachable only by
// hand-feeding typed frames (the FakeIO harness lets us bypass the wire-level
// framer that would otherwise reject these before dispatch).
//
// These extend the happy-path suite above to drive: the preface-complete
// guards (not-ok / already-sent / single-request auto-send), the DATA
// flow-control violation arms, END_STREAM window-update emission, the
// CONTINUATION trailers reassembly path, the SETTINGS not-ok + unknown-id
// arms, the RST_STREAM stream-0 + not-ok guards, the PRIORITY not-ok guard,
// and the PUSH_PROMISE not-ok guard.
// ===========================================================================

namespace {

// Locate the first frame of `type` from offset 0; safe here because every test
// that uses it has already consumed past the preface (the protocol's output
// pipe begins with the 24-byte preface, so callers pass start past it where the
// preface might still be present). This walks from the FIRST real frame header.
[[nodiscard]] bool
output_has_frame_after(const qb::allocator::pipe<char> &pipe, h2::FrameType type) {
    // The preface is exactly 24 bytes; frames start at offset 24.
    return find_frame_offset(pipe, type, 24) != SIZE_MAX;
}

// Drive the protocol into a !ok() state via a RST_STREAM on stream 0 (a
// connection PROTOCOL_ERROR). Returns with protocol.ok() == false so the next
// frame ingest exercises the leading not-ok guard of each handler.
void
force_connection_not_ok(h2::ClientHttp2Protocol<Http2ClientFakeIO> &protocol) {
    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(0);
    rst.payload.error_code = h2::ErrorCode::CANCEL;
    protocol.on(std::move(rst));
    ASSERT_FALSE(protocol.ok());
}

} // namespace

// --- Preface-complete guards -------------------------------------------------

// PrefaceCompleteEvent received while the protocol is already not-ok: the
// handler's leading guard returns early without emitting another SETTINGS frame.
TEST(HTTP2ClientProtocol, PrefaceCompleteWhileNotOkIsIgnored) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    force_connection_not_ok(protocol);
    const std::size_t before = io.output.size();

    protocol.on(h2::PrefaceCompleteEvent{});

    // No further bytes emitted (guard returned before the SETTINGS send).
    EXPECT_EQ(io.output.size(), before);
}

// A second PrefaceCompleteEvent after the first already sent the initial
// SETTINGS hits the `_initial_settings_sent` else-branch (no duplicate SETTINGS).
TEST(HTTP2ClientProtocol, SecondPrefaceCompleteDoesNotResendSettings) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    protocol.on(h2::PrefaceCompleteEvent{}); // sends initial SETTINGS
    const std::size_t after_first = io.output.size();

    protocol.on(h2::PrefaceCompleteEvent{}); // _initial_settings_sent already true

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.output.size(), after_first); // nothing more emitted
}

// Single-request mode: when constructed with a request pointer, preface-complete
// auto-sends that request (emitting a HEADERS frame) without an explicit
// send_request call. Drives the `_single_request_mode` auto-send arm.
TEST(HTTP2ClientProtocol, SingleRequestModeAutoSendsOnPrefaceComplete) {
    Http2ClientFakeIO io;

    qb::http::Request single;
    single.method() = qb::http::method::GET;
    single.uri()    = qb::io::uri("https://example.test/single");

    // The request must outlive the protocol (it stores a raw pointer).
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io, &single);

    const std::size_t before = io.output.size();
    protocol.on(h2::PrefaceCompleteEvent{});

    EXPECT_TRUE(protocol.ok());
    // A HEADERS frame for the auto-sent stream 1 must have been emitted.
    EXPECT_NE(find_frame_offset(io.output, h2::FrameType::HEADERS, before), SIZE_MAX);
}

// --- DATA frame flow-control / not-ok arms ----------------------------------

// A DATA frame delivered while the protocol is not-ok is dropped by the leading
// FramerBase::ok() guard (no crash, no response).
TEST(HTTP2ClientProtocol, DataFrameWhileNotOkIsIgnored) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/data-notok");
    force_connection_not_ok(protocol);

    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, "ignored"));

    EXPECT_FALSE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
}

// A single server DATA frame whose payload exceeds the stream's local receive
// window (default 65535) is a stream FLOW_CONTROL_ERROR that also escalates to a
// connection GOAWAY(FLOW_CONTROL_ERROR).
TEST(HTTP2ClientProtocol, ServerDataExceedingStreamWindowIsFlowControlError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/overflow");

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));

    // 70000 bytes > 65535 stream window -> stream FC violation + GOAWAY.
    protocol.on(make_data_frame(1, 0, std::string(70000, 'x')));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::FLOW_CONTROL_ERROR);
    EXPECT_TRUE(output_has_frame_after(io.output, h2::FrameType::RST_STREAM));
}

// A DATA frame that fits the stream window but exhausts the shared connection
// receive window is a connection FLOW_CONTROL_ERROR. Stream A first consumes
// most of the shared connection window; a fresh stream B then receives a DATA
// frame within its own (full) stream window but over the remaining connection
// window, driving the connection-level violation arm.
TEST(HTTP2ClientProtocol, ServerDataExceedingConnectionWindowIsFlowControlError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    qb::http::Request a;
    a.method() = qb::http::method::GET;
    a.uri()    = qb::io::uri("https://example.test/a");
    ASSERT_TRUE(protocol.send_request(std::move(a), 1)); // stream 1
    qb::http::Request b;
    b.method() = qb::http::method::GET;
    b.uri()    = qb::io::uri("https://example.test/b");
    ASSERT_TRUE(protocol.send_request(std::move(b), 2)); // stream 3

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    protocol.on(make_headers_frame(3, h2::FLAG_END_HEADERS, {{":status", "200"}}));

    // Stream 1 consumes 32000 of the 65535 connection window. This stays just
    // under the connection auto-WINDOW_UPDATE threshold (65535/2 = 32767), so the
    // shared connection receive window is NOT replenished and is left at ~33535.
    protocol.on(make_data_frame(1, 0, std::string(32000, 'a')));
    EXPECT_TRUE(protocol.ok());

    // Stream 3 (fresh 65535 stream window) receives 40000: passes the per-stream
    // check (65535 >= 40000) but the remaining connection window (33535) is now
    // too small -> connection FLOW_CONTROL_ERROR.
    protocol.on(make_data_frame(3, 0, std::string(40000, 'b')));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::FLOW_CONTROL_ERROR);
}

// A large but in-window response body delivered as several DATA frames crosses
// the per-stream window-update threshold; on END_STREAM the client emits a
// WINDOW_UPDATE for the consumed bytes (the END_STREAM threshold-flush arm).
TEST(HTTP2ClientProtocol, EndStreamFlushesPendingStreamWindowUpdate) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/winflush");

    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}}));

    const std::size_t before = io.output.size();
    // First DATA stays below the per-stream window-update threshold (65535/2 =
    // 32767), so no mid-stream flush fires. The second DATA carries END_STREAM
    // and pushes the accumulated processed bytes (40000) past the threshold, so
    // the flush happens on the END_STREAM path specifically.
    protocol.on(make_data_frame(1, 0, std::string(20000, 'p')));
    protocol.on(make_data_frame(1, h2::FLAG_END_STREAM, std::string(20000, 'q')));

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 1);
    // A stream-level WINDOW_UPDATE (stream id 1) must have been emitted.
    EXPECT_GT(total_window_update_increment_for_stream(io.output, 1, before), 0u);
}

// --- HEADERS on an idle stream ----------------------------------------------

// A HEADERS frame for an odd stream id ABOVE the last client-initiated id refers
// to an idle client stream the server must not open -> connection PROTOCOL_ERROR.
TEST(HTTP2ClientProtocol, HeadersForIdleHighOddStreamIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/hdr-idle"); // last initiated = 1

    // Stream 9 is odd and > 1: idle client stream -> connection error.
    protocol.on(make_headers_frame(9, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "200"}}));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
}

// --- WINDOW_UPDATE on unknown / idle streams --------------------------------

// A stream-level WINDOW_UPDATE for an odd stream id ABOVE the last client-
// initiated stream id targets a never-opened (idle) client stream, which is a
// connection PROTOCOL_ERROR.
TEST(HTTP2ClientProtocol, WindowUpdateForIdleHighOddStreamIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/wu-idle"); // last initiated = 1

    // Stream 7 is odd and > 1: never initiated -> idle -> connection error.
    protocol.on(make_window_update_frame(7, 100));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
}

// A stream-level WINDOW_UPDATE for an EVEN (server-push) stream id we never saw
// is tolerated and ignored per RFC 9113 6.9 (frames may cross paths with a
// closed stream): no error, connection stays ok.
TEST(HTTP2ClientProtocol, WindowUpdateForUnknownEvenStreamIsIgnored) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/wu-even");

    protocol.on(make_window_update_frame(4, 100)); // even, unknown -> ignored

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 0);
    EXPECT_EQ(io.goaway_count, 0);
}

// --- CONTINUATION error + trailers reassembly -------------------------------

// A CONTINUATION frame arriving when no header block is open for that stream is
// a connection PROTOCOL_ERROR (the active-header-block stream id is 0, so the
// "unexpected stream" guard fires). Driven via direct typed dispatch.
TEST(HTTP2ClientProtocol, ContinuationWithNoActiveBlockTypedIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/lonecont");

    h2::Http2FrameData<h2::ContinuationFrame> cont;
    cont.header.type  = static_cast<uint8_t>(h2::FrameType::CONTINUATION);
    cont.header.flags = h2::FLAG_END_HEADERS;
    cont.header.set_stream_id(1);
    cont.payload.header_block_fragment = encode_hpack_headers({{":status", "200"}});
    protocol.on(std::move(cont));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
}

// Trailers delivered as a HEADERS(no END_HEADERS) + CONTINUATION(END_HEADERS)
// block after the main response: the CONTINUATION reassembly path detects the
// trailers block (stream.headers_received_main is set) and dispatches the
// completed response. Drives the is_trailers_block success branch of
// on(ContinuationFrame).
TEST(HTTP2ClientProtocol, TrailersViaContinuationAreReassembledAndDispatched) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 71, "/cont-trailers");

    // Main response announces a trailer and does NOT end the stream.
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"trailer", "x-checksum"}}));
    ASSERT_TRUE(protocol.ok());
    // Body without END_STREAM (the END_STREAM rides the trailers HEADERS block).
    protocol.on(make_data_frame(1, 0, "body"));
    ASSERT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0); // awaiting trailers

    // Trailers as a split HEADERS(END_STREAM) + CONTINUATION(END_HEADERS) block
    // (no pseudo-headers). END_STREAM rides the opening HEADERS frame.
    const auto block = encode_hpack_headers({{"x-checksum", "abc123"}});
    ASSERT_GE(block.size(), 2u);
    const std::size_t    cut = block.size() / 2;
    std::vector<uint8_t> first(block.begin(), block.begin() + cut);
    std::vector<uint8_t> rest(block.begin() + cut, block.end());

    push_raw_header_carrier(io, h2::FrameType::HEADERS, h2::FLAG_END_STREAM, 1, first);
    push_raw_header_carrier(io, h2::FrameType::CONTINUATION, h2::FLAG_END_HEADERS, 1, rest);
    drive(protocol, io);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 0);
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(io.response_count, 1);
    ASSERT_TRUE(io.last_status.has_value());
    EXPECT_EQ(*io.last_status, 200);
    EXPECT_EQ(*io.last_body, "body");
}

// A CONTINUATION carrying a corrupt HPACK fragment after a valid open HEADERS
// block fails to decode -> COMPRESSION_ERROR (RST + GOAWAY). Drives the
// on(ContinuationFrame) HPACK-decode-failure arm.
TEST(HTTP2ClientProtocol, ContinuationWithCorruptHpackIsCompressionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 73, "/cont-bad-hpack");

    const auto block = encode_hpack_headers({{":status", "200"}, {"x-trace", "cont"}});
    ASSERT_GE(block.size(), 2u);
    const std::size_t    cut = block.size() / 2;
    std::vector<uint8_t> first(block.begin(), block.begin() + cut);

    // HEADERS (no END_HEADERS) opens the block on stream 1.
    push_raw_header_carrier(io, h2::FrameType::HEADERS, 0, 1, first);
    // CONTINUATION (END_HEADERS) with a literal-name-reference to the reserved
    // index 0 -> HPACK decode failure on reassembly.
    const std::vector<uint8_t> corrupt = {0x10, 0x00};
    push_raw_header_carrier(io, h2::FrameType::CONTINUATION, h2::FLAG_END_HEADERS, 1, corrupt);
    drive(protocol, io);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::COMPRESSION_ERROR);
}

// --- SETTINGS guards ---------------------------------------------------------

// A SETTINGS frame arriving while the protocol is not-ok is dropped by the
// leading not-ok / inactive guard.
TEST(HTTP2ClientProtocol, SettingsFrameWhileNotOkIsIgnored) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    force_connection_not_ok(protocol);

    const std::size_t before = io.output.size();
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_MAX_FRAME_SIZE, 32768}}));

    EXPECT_FALSE(protocol.ok());
    EXPECT_EQ(io.output.size(), before); // no ACK emitted
}

// A SETTINGS frame carrying an UNKNOWN setting identifier must be accepted: the
// unknown id is ignored (default switch arm) and the frame is still ACKed.
TEST(HTTP2ClientProtocol, SettingsFrameWithUnknownIdIsIgnoredAndAcked) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    const std::size_t                     before = io.output.size();
    h2::Http2FrameData<h2::SettingsFrame> frame;
    frame.header.type  = static_cast<uint8_t>(h2::FrameType::SETTINGS);
    frame.header.flags = 0;
    frame.header.set_stream_id(0);
    // 0x99 is not a defined SETTINGS id -> validated valid, hits default arm.
    frame.payload.entries.push_back({static_cast<h2::Http2SettingIdentifier>(0x0099), 12345});
    protocol.on(std::move(frame));

    EXPECT_TRUE(protocol.ok());
    const auto ack_off = find_frame_offset(io.output, h2::FrameType::SETTINGS, before);
    ASSERT_NE(ack_off, SIZE_MAX);
    EXPECT_TRUE(peek_frame_header(io.output, ack_off).flags & h2::FLAG_ACK);
}

// --- RST_STREAM / PRIORITY / PUSH_PROMISE guards ----------------------------

// A RST_STREAM on stream 0 is a connection PROTOCOL_ERROR.
TEST(HTTP2ClientProtocol, RstStreamOnStreamZeroIsConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(0);
    rst.payload.error_code = h2::ErrorCode::CANCEL;
    protocol.on(std::move(rst));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
}

// A RST_STREAM arriving while the protocol is not-ok is dropped by the leading
// not-ok guard.
TEST(HTTP2ClientProtocol, RstStreamWhileNotOkIsIgnored) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/rst-notok");
    force_connection_not_ok(protocol);

    const int                              errs_before = io.stream_error_count;
    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(1);
    rst.payload.error_code = h2::ErrorCode::CANCEL;
    protocol.on(std::move(rst));

    EXPECT_FALSE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, errs_before); // guard returned early
}

// A PRIORITY frame arriving while the protocol is not-ok is dropped by the
// leading not-ok guard.
TEST(HTTP2ClientProtocol, PriorityFrameWhileNotOkIsIgnored) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    force_connection_not_ok(protocol);

    const std::size_t                     before = io.output.size();
    h2::Http2FrameData<h2::PriorityFrame> prio;
    prio.header.type = static_cast<uint8_t>(h2::FrameType::PRIORITY);
    prio.header.set_stream_id(1);
    protocol.on(std::move(prio));

    EXPECT_FALSE(protocol.ok());
    EXPECT_EQ(io.output.size(), before); // no GOAWAY emitted by the handler
}

// A PUSH_PROMISE arriving while the protocol is not-ok is dropped by the leading
// not-ok guard (before any promised-id validation).
TEST(HTTP2ClientProtocol, PushPromiseWhileNotOkIsIgnored) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/pp-notok");
    force_connection_not_ok(protocol);

    const std::size_t                        before = io.output.size();
    h2::Http2FrameData<h2::PushPromiseFrame> pp;
    pp.header.type = static_cast<uint8_t>(h2::FrameType::PUSH_PROMISE);
    pp.header.set_stream_id(1);
    pp.payload.promised_stream_id    = 2;
    pp.payload.header_block_fragment = encode_hpack_headers(default_request_headers("/pushed"));
    protocol.on(std::move(pp));

    EXPECT_FALSE(protocol.ok());
    EXPECT_EQ(io.output.size(), before);
    EXPECT_EQ(io.push_promise_count, 0);
}

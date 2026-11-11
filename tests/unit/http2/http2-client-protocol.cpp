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
#include <functional>
#include <numeric>
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

    /// As if the server had promised every even stream up to @p id: push is disabled, so nothing else moves this.
    static void
    set_last_promised_stream_id(qb::protocol::http2::ClientHttp2Protocol<Http2ClientFakeIO> &protocol, uint32_t id) {
        protocol._last_promised_stream_id = id;
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

// A response field value with SP or HTAB at an end makes the response malformed (RFC 9113 section 8.2.1), which a
// client must not accept (section 8.1.1): its stream is reset, in a header section and in a trailer section, the
// connection kept. It was delivered (Huly QB-1191). Whitespace inside a value is part of it.
TEST(HTTP2ClientProtocol, AResponseFieldValueWithWhitespaceAtAnEndIsRefused) {
    for (const bool trailer : {false, true}) {
        for (const char *value : {" a", "a\t"}) {
            Http2ClientFakeIO                          io;
            h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

            qb::http::Request req;
            req.method() = qb::http::method::GET;
            req.uri()    = qb::io::uri("https://example.test/edge");
            ASSERT_TRUE(protocol.send_request(std::move(req), 21));

            if (trailer) {
                protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS, {{":status", "200"}, {"trailer", "x-sum"}}));
                protocol.on(make_data_frame(1, 0, "body"));
                protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{"x-sum", value}}));
            } else {
                protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "200"}, {"x-edge", value}}));
            }

            EXPECT_TRUE(protocol.ok()) << value << ": a stream error, not a connection one";
            EXPECT_EQ(io.response_count, 0) << value << ": the response must not be delivered";
            EXPECT_EQ(io.stream_error_count, 1) << value;
            EXPECT_EQ(io.last_stream_error, h2::ErrorCode::PROTOCOL_ERROR) << value;
        }
    }
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    qb::http::Request                          req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/inner");
    ASSERT_TRUE(protocol.send_request(std::move(req), 21));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "200"}, {"x-inner", "a \t b"}}));
    ASSERT_EQ(io.response_count, 1);
    EXPECT_EQ(io.last_response->header("x-inner"), "a \t b");
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
// DATA for an even stream id the server never promised: the stream is idle, where only HEADERS and PRIORITY are frames
// at all -- a connection error, PROTOCOL_ERROR (RFC 9113 §5.1). The client disables push, so the server can promise no
// stream (§6.6) and every even id is idle. It was reset (STREAM_CLOSED) and the connection survived: a 13-octet reply
// for each such DATA, without a bound (Huly QB-1270; re-derived from DataForUnknownPushedStreamResetsStreamOnly: the
// same frame, the verdict RFC 9113 asks for).
// ===========================================================================
TEST(HTTP2ClientProtocol, DataOnAnIdleEvenStreamIsAConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    const std::size_t before = io.output.size();
    protocol.on(make_data_frame(2, 0, "never-promised"));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(find_frame_offset(io.output, h2::FrameType::RST_STREAM, before), SIZE_MAX) << "an idle stream was reset";
    EXPECT_NE(find_frame_offset(io.output, h2::FrameType::GOAWAY, before), SIZE_MAX);
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
        // A value with SP or HTAB at an end (RFC 9113 section 8.2.1; Huly QB-1191: it was sent).
        {"x-edge", " a"},
        {"x-edge", "a\t"},
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
// HEADERS for an even (server-initiated) stream id that was never promised: the stream is idle, and a server opens no
// stream with HEADERS -- a connection error, PROTOCOL_ERROR (RFC 9113 §5.1.1). The client disables push, so the server
// can promise no stream (§6.6) and every even id is idle. It was read as a HEADERS on a closed stream: reset
// (STREAM_CLOSED), the connection kept, a 13-octet reply for each such HEADERS and no bound on them (Huly QB-1270;
// re-derived from HeadersForUnknownEvenStreamRstsStreamOnly: the same frame, the verdict RFC 9113 asks for).
// ---------------------------------------------------------------------------
TEST(HTTP2ClientProtocol, HeadersOnAnIdleEvenStreamIsAConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);

    const std::size_t before = io.output.size();
    // Even id 4 was never promised via PUSH_PROMISE and is not a known stream.
    protocol.on(make_headers_frame(4, h2::FLAG_END_HEADERS, {{":status", "200"}}));

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(find_frame_offset(io.output, h2::FrameType::RST_STREAM, before), SIZE_MAX) << "an idle stream was reset (RFC 9113 §6.4)";
    EXPECT_NE(find_frame_offset(io.output, h2::FrameType::GOAWAY, before), SIZE_MAX);
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

// A stream-level WINDOW_UPDATE for an EVEN stream id the server never promised targets an idle stream, as one for an
// odd id past the last request does: a connection PROTOCOL_ERROR (RFC 9113 §5.1). It was ignored, as a frame crossing
// a stream that has closed is (§6.9) -- but no even stream can have closed: the client disables push, so the server
// can promise none (Huly QB-1270; re-derived from WindowUpdateForUnknownEvenStreamIsIgnored: the same frame, the
// verdict the odd ids already had).
TEST(HTTP2ClientProtocol, WindowUpdateOnAnIdleEvenStreamIsAConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/wu-even");

    protocol.on(make_window_update_frame(4, 100)); // even, never promised -> idle

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.stream_error_count, 0);
    EXPECT_EQ(io.goaway_count, 1);
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

// ===========================================================================
// A field the request's `connection` header names never leaves in its trailer section either (Huly QB-1202). RFC 9110
// section 7.6.1: intermediaries "remove any header or trailer field(s) from the message with the same name as the
// connection-option"; RFC 9113 section 8.2.2: "An intermediary transforming an HTTP/1.x message to HTTP/2 MUST remove
// connection-specific header fields as discussed in Section 7.6.1 of [HTTP]". QB-1191 dropped them from the header
// section only. Whether the request sets its trailer fields is read from the section it plans -- never from what is left
// once they are dropped: a section whose every field is nominated still ends the stream, with an empty block, where a
// first attempt waited for send_request_trailers() for ever (review R3 of QB-1191). The announcement the client composes
// for trailers() leaves them out too. Each request then crosses a qbm-http server and is served.
// ===========================================================================
TEST(HTTP2ClientProtocol, AFieldTheConnectionHeaderNamesNeverLeavesInTheTrailerSection) {
    struct Case {
        const char *what;
        bool        announced_header; ///< the fields are header fields the `trailer` header announces, else trailers()
        bool        only_nominated;   ///< every trailer field is nominated
        uint32_t    window;           ///< the server's initial stream window: 1 blocks the body, the trailers then follow it
    };
    const std::vector<Case> cases = {
        {"announced header fields", true, false, 65535},
        {"announced header fields, body blocked", true, false, 1},
        {"trailers()", false, false, 65535},
        {"trailers(), body blocked", false, false, 1},
        {"announced header fields, all nominated", true, true, 65535},
        {"announced header fields, all nominated, body blocked", true, true, 1},
        {"trailers(), all nominated", false, true, 65535},
        {"trailers(), all nominated, body blocked", false, true, 1},
    };
    for (const auto &c : cases) {
        Http2ClientFakeIO                          client_io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);
        ASSERT_TRUE(client.explicit_request_trailers()) << "the protocol's default: an unset announced section waits";
        Http2FakeIO                          server_io;
        h2::ServerHttp2Protocol<Http2FakeIO> server(server_io);
        if (c.window != 65535) {
            client.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, c.window}}));
            ASSERT_TRUE(client.ok()) << c.what;
        }
        const std::size_t before = client_io.output.size();

        qb::http::Request req;
        req.method() = qb::http::method::POST;
        req.uri()    = qb::io::uri("https://example.test/nominated");
        req.body()   = "ab";
        req.add_header("Connection", "X-Hop");
        if (c.announced_header) {
            req.set_header("trailer", c.only_nominated ? "x-hop" : "x-hop, x-sum");
            req.set_header("x-hop", "1");
            if (!c.only_nominated) {
                req.set_header("x-sum", "2");
            }
        } else {
            req.trailers().set_header("x-hop", "1");
            if (!c.only_nominated) {
                req.trailers().set_header("x-sum", "2");
            }
        }
        ASSERT_TRUE(client.send_request(std::move(req), 1)) << c.what;
        if (c.window != 65535) {
            client.on(make_window_update_frame(1, 100));
            client.on(make_window_update_frame(0, 100));
        }
        ASSERT_TRUE(client.ok()) << c.what;

        const auto blocks = sent_header_blocks(client_io.output, 1, before);
        ASSERT_EQ(blocks.size(), 2u) << c.what << ": the leading HEADERS, then the trailer block -- the stream ends";
        EXPECT_EQ(blocks[0].count("x-hop"), 0u) << c.what;
        EXPECT_EQ(blocks[0].count("connection"), 0u) << c.what;
        if (!c.announced_header) {
            EXPECT_EQ(blocks[0].value("trailer"), c.only_nominated ? "" : "x-sum") << c.what << ": the composed announcement";
        }
        EXPECT_TRUE(blocks[1].flags & h2::FLAG_END_STREAM) << c.what;
        EXPECT_EQ(blocks[1].count("x-hop"), 0u) << c.what << ": a nominated field in the trailer section";
        EXPECT_EQ(blocks[1].fields.size(), c.only_nominated ? 0u : 1u) << c.what;
        if (!c.only_nominated) {
            EXPECT_EQ(blocks[1].value("x-sum"), "2") << c.what;
        }

        pump(server, server_io, client_io);
        EXPECT_TRUE(server.ok()) << c.what;
        ASSERT_EQ(server_io.request_count, 1) << c.what;
        EXPECT_FALSE(server_io.last_request->has_header("x-hop")) << c.what;
        EXPECT_EQ(server_io.last_request->body().as<std::string>(), "ab") << c.what;
    }
}

// The trailers handed to send_request_trailers() go by the same rule (Huly QB-1202): a field the request's `connection`
// header names is dropped, the others sent, the stream ended -- with an empty block when nothing is left. Behind a
// blocked body as at once.
TEST(HTTP2ClientProtocol, SendRequestTrailersDropsAFieldTheConnectionHeaderNames) {
    for (const bool body_blocked : {false, true}) {
        for (const bool only_nominated : {false, true}) {
            const std::string what = std::string(body_blocked ? "blocked body" : "body out") + (only_nominated ? ", all nominated" : "");
            Http2ClientFakeIO client_io;
            h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);
            Http2FakeIO                                server_io;
            h2::ServerHttp2Protocol<Http2FakeIO>       server(server_io);
            if (body_blocked) {
                client.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 1}}));
            }
            const std::size_t before = client_io.output.size();

            qb::http::Request req;
            req.method() = qb::http::method::POST;
            req.uri()    = qb::io::uri("https://example.test/explicit");
            req.body()   = "ab";
            req.add_header("connection", "x-hop");
            req.set_header("trailer", "x-hop, x-sum"); // announced, handed over below
            ASSERT_TRUE(client.send_request(std::move(req), 1)) << what;

            qb::http::headers trailers;
            trailers.add_header("X-Hop", "1");
            if (!only_nominated) {
                trailers.add_header("x-sum", "2");
            }
            ASSERT_TRUE(client.send_request_trailers(1, trailers)) << what;
            if (body_blocked) {
                client.on(make_window_update_frame(1, 100));
                client.on(make_window_update_frame(0, 100));
            }
            ASSERT_TRUE(client.ok()) << what;

            const auto blocks = sent_header_blocks(client_io.output, 1, before);
            ASSERT_EQ(blocks.size(), 2u) << what;
            EXPECT_TRUE(blocks[1].flags & h2::FLAG_END_STREAM) << what;
            EXPECT_EQ(blocks[1].count("x-hop"), 0u) << what << ": a nominated field in the trailer section";
            EXPECT_EQ(blocks[1].fields.size(), only_nominated ? 0u : 1u) << what;

            pump(server, server_io, client_io);
            EXPECT_TRUE(server.ok()) << what;
            ASSERT_EQ(server_io.request_count, 1) << what;
            EXPECT_FALSE(server_io.last_request->has_header("x-hop")) << what;
        }
    }
}

// A request that announces trailer fields it does not set waits for send_request_trailers() once its body is out
// (explicit request trailers, the protocol's default), and a body that waited for flow-control credit changes nothing:
// it used to end the stream with an empty trailer block as soon as the credit came, and the trailers handed over next
// were refused (Huly QB-1202, the plan read in both paths). With explicit trailers off the stream ends there.
TEST(HTTP2ClientProtocol, UnsetAnnouncedTrailersWaitForTheCallerBehindABlockedBodyToo) {
    for (const bool explicit_trailers : {true, false}) {
        Http2ClientFakeIO                          client_io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);
        client.set_explicit_request_trailers(explicit_trailers);
        Http2FakeIO                          server_io;
        h2::ServerHttp2Protocol<Http2FakeIO> server(server_io);
        client.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 4}}));
        const std::size_t before = client_io.output.size();

        qb::http::Request req;
        req.method() = qb::http::method::POST;
        req.uri()    = qb::io::uri("https://example.test/later");
        req.body()   = "0123456789"; // four octets fit, six wait
        req.set_header("trailer", "x-checksum");
        ASSERT_TRUE(client.send_request(std::move(req), 1));
        client.on(make_window_update_frame(1, 100));
        ASSERT_TRUE(client.ok());
        EXPECT_EQ(sum_data_payload_for_stream(client_io.output, 1, before), 10u) << "the whole body is out";

        const auto blocks = sent_header_blocks(client_io.output, 1, before);
        if (!explicit_trailers) {
            ASSERT_EQ(blocks.size(), 2u) << "the stream ends after the body, with an empty trailer block";
            EXPECT_TRUE(blocks[1].flags & h2::FLAG_END_STREAM);
            EXPECT_TRUE(blocks[1].fields.empty());
            continue;
        }
        EXPECT_EQ(blocks.size(), 1u) << "the stream waits for send_request_trailers()";
        qb::http::headers trailers;
        trailers.add_header("x-checksum", "cafe");
        ASSERT_TRUE(client.send_request_trailers(1, trailers)) << "the trailers the caller hands over are sent";
        const auto after = sent_header_blocks(client_io.output, 1, before);
        ASSERT_EQ(after.size(), 2u);
        EXPECT_TRUE(after[1].flags & h2::FLAG_END_STREAM);
        EXPECT_EQ(after[1].value("x-checksum"), "cafe");

        pump(server, server_io, client_io);
        EXPECT_TRUE(server.ok());
        ASSERT_EQ(server_io.request_count, 1);
        EXPECT_EQ(server_io.last_request->body().as<std::string>(), "0123456789");
        EXPECT_EQ(server_io.last_request->header("x-checksum"), "cafe");
    }
}

// ===========================================================================
// The client's twin of the bound the server advertises (Huly QB-1211, QB-1196 on the server). RFC 9113 section 6.5.2:
// SETTINGS_MAX_HEADER_LIST_SIZE "informs a peer of the maximum field section size that the sender is prepared to
// accept ... The value is based on the uncompressed size of field lines, including the length of the name and value in
// units of octets plus an overhead of 32 octets for each field line"; section 10.5.1: "A client can discard responses
// that it cannot process. The field block MUST be processed to ensure a consistent connection state". The client's
// decoder stops at 1 MiB of decoded list, but it advertised nothing, and a response past it failed the decode:
// COMPRESSION_ERROR, GOAWAY, every request multiplexed on the connection with it.
// ===========================================================================
namespace qb1211_test {

constexpr std::size_t header_list_bound = qb::http2::protocol_limits::MAX_HEADER_LIST_SIZE;

/// A response field list of exactly @p total octets as RFC 9113 section 6.5.2 counts them: :status 200, fields of
/// 8000 octets, then one that makes up the rest.
std::vector<qb::protocol::hpack::HeaderField>
response_list_of_size(std::size_t total) {
    std::vector<qb::protocol::hpack::HeaderField> fields{{":status", "200"}};
    std::size_t                                   size = fields.front().hpack_size();
    for (int i = 0; total - size > 8000 + 2 * 64; ++i) {
        fields.emplace_back("x-f" + std::to_string(i), std::string(8000, 'a'));
        size += fields.back().hpack_size();
    }
    fields.emplace_back("x-pad", std::string(total - size - (5 + qb::protocol::hpack::HPACK_ENTRY_OVERHEAD), 'a'));
    return fields;
}

/// A response HEADERS frame on @p stream_id carrying @p block, ending the stream.
h2::Http2FrameData<h2::HeadersFrame>
response_headers(uint32_t stream_id, std::vector<uint8_t> block) {
    h2::Http2FrameData<h2::HeadersFrame> frame;
    frame.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
    frame.header.flags = h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM;
    frame.header.set_stream_id(stream_id);
    frame.payload.header_block_fragment = std::move(block);
    return frame;
}

/// An HPACK integer (RFC 7541 section 5.1) after @p prefix_bits, in an @p n -bit prefix.
void
append_hpack_integer(std::vector<uint8_t> &block, uint8_t prefix_bits, uint8_t n, std::size_t value) {
    const std::size_t max_prefix = (std::size_t{1} << n) - 1;
    if (value < max_prefix) {
        block.push_back(static_cast<uint8_t>(prefix_bits | value));
        return;
    }
    block.push_back(static_cast<uint8_t>(prefix_bits | max_prefix));
    value -= max_prefix;
    while (value >= 128) {
        block.push_back(static_cast<uint8_t>((value % 128) | 0x80));
        value /= 128;
    }
    block.push_back(static_cast<uint8_t>(value));
}

/// A literal field with incremental indexing and a new name (RFC 7541 section 6.2.1), its strings raw.
void
append_indexed_literal(std::vector<uint8_t> &block, const std::string &name, const std::string &value) {
    block.push_back(0x40);
    append_hpack_integer(block, 0x00, 7, name.size());
    block.insert(block.end(), name.begin(), name.end());
    append_hpack_integer(block, 0x00, 7, value.size());
    block.insert(block.end(), value.begin(), value.end());
}

/// The RST_STREAM error code the client last sent on @p stream_id, if any.
std::optional<h2::ErrorCode>
last_rst_stream_error(const qb::allocator::pipe<char> &output, uint32_t stream_id) {
    std::optional<h2::ErrorCode> code;
    for (std::size_t off = 24; off + h2::FRAME_HEADER_SIZE <= output.size();) { // past the client preface
        const auto fh = peek_frame_header(output, off);
        if (fh.get_type() == h2::FrameType::RST_STREAM && fh.get_stream_id() == stream_id && fh.get_payload_length() == 4) {
            const auto *p = reinterpret_cast<const uint8_t *>(output.cbegin() + off + h2::FRAME_HEADER_SIZE);
            code          = static_cast<h2::ErrorCode>((static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16)
                                                       | (static_cast<uint32_t>(p[2]) << 8) | p[3]);
        }
        off += h2::FRAME_HEADER_SIZE + fh.get_payload_length();
    }
    return code;
}

void
open_streams(h2::ClientHttp2Protocol<Http2ClientFakeIO> &protocol, int count) {
    for (int i = 0; i < count; ++i) {
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/r" + std::to_string(i));
        ASSERT_TRUE(protocol.send_request(std::move(req), 100 + i));
    }
}

} // namespace qb1211_test

TEST(HTTP2ClientProtocol, TheClientAdvertisesTheHeaderListBoundItEnforces) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    std::optional<uint32_t>                    advertised;
    for (std::size_t off = 24; off + h2::FRAME_HEADER_SIZE <= io.output.size();) { // past the connection preface
        const auto fh = peek_frame_header(io.output, off);
        if (fh.get_type() == h2::FrameType::SETTINGS && !(fh.flags & h2::FLAG_ACK)) {
            const auto *p = reinterpret_cast<const uint8_t *>(io.output.cbegin() + off + h2::FRAME_HEADER_SIZE);
            for (std::size_t i = 0; i + 6 <= fh.get_payload_length(); i += 6) {
                if (((p[i] << 8) | p[i + 1]) == static_cast<int>(h2::Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE)) {
                    advertised = (static_cast<uint32_t>(p[i + 2]) << 24) | (static_cast<uint32_t>(p[i + 3]) << 16)
                                 | (static_cast<uint32_t>(p[i + 4]) << 8) | p[i + 5];
                }
            }
        }
        off += h2::FRAME_HEADER_SIZE + fh.get_payload_length();
    }
    ASSERT_TRUE(advertised.has_value()) << "SETTINGS_MAX_HEADER_LIST_SIZE is advertised";
    EXPECT_EQ(*advertised, qb1211_test::header_list_bound);
}

// Exactly at the bound a response is delivered; past it, its stream is reset -- ENHANCE_YOUR_CALM, the code of the
// client's other refusals of a response too large -- and its request fails, the connection serving the next one, whose
// block references an entry the refused block indexed past the bound: the table stayed in step with the server's.
TEST(HTTP2ClientProtocol, AResponseHeaderListPastTheBoundFailsItsStreamNotTheConnection) {
    using namespace qb1211_test;
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_streams(protocol, 3);
    qb::protocol::hpack::Encoder encoder; // the server's: one compression context for the connection
    const auto                   block_of = [&](const std::vector<qb::protocol::hpack::HeaderField> &fields) {
        std::vector<uint8_t> block;
        EXPECT_TRUE(encoder.encode(fields, block));
        EXPECT_LE(block.size(), qb::http2::protocol_limits::MAX_HEADER_BLOCK_SIZE) << "within the encoded block cap";
        return block;
    };

    protocol.on(response_headers(1, block_of(response_list_of_size(header_list_bound))));
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.response_count, 1) << "a list of exactly the bound is delivered";
    EXPECT_EQ(io.last_status, 200);

    auto past = response_list_of_size(header_list_bound);
    past.emplace_back("x-after", "1"); // indexed by the server's encoder, past the bound
    protocol.on(response_headers(3, block_of(past)));
    EXPECT_TRUE(protocol.ok()) << "the stream is refused, not the connection";
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(io.response_count, 1) << "a response past the bound is never delivered";
    EXPECT_EQ(io.stream_error_count, 1) << "its request fails";
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
    EXPECT_EQ(qb1211_test::last_rst_stream_error(io.output, 3), h2::ErrorCode::ENHANCE_YOUR_CALM);

    protocol.on(response_headers(5, block_of({{":status", "200"}, {"x-after", "1"}})));
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.response_count, 2) << "the next request is served";
    EXPECT_EQ(io.last_response->header("x-after"), "1") << "the entry indexed past the bound is in the table";
}

// One 4 KiB dynamic-table entry referenced 300 times: 4.3 KB of block, 1.2 MiB of list -- refused on its stream, the
// table kept in step (an entry the block indexed after the bound is referenced by the next response). 5000 references,
// 20 MiB, past 16 times the bound: the decompression bomb the bound exists for closes the connection, as on the server.
TEST(HTTP2ClientProtocol, AReferencedEntryPastTheBoundIsRefusedOnItsStreamAndABombClosesTheConnection) {
    using namespace qb1211_test;
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_streams(protocol, 3);

    std::vector<uint8_t> block{0x88};                               // :status 200, static
    append_indexed_literal(block, "x-big", std::string(4000, 'v')); // dynamic index 62
    block.insert(block.end(), 300, 0xBE);                           // 300 references to it
    append_indexed_literal(block, "x-after", "1");                  // indexed past the bound: x-big becomes 63
    ASSERT_LT(block.size(), 4500u);
    protocol.on(response_headers(1, block));
    EXPECT_TRUE(protocol.ok()) << "the stream is refused, not the connection";
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::ENHANCE_YOUR_CALM);

    protocol.on(response_headers(3, {0x88, 0xBE, 0xBF})); // x-after, x-big
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.response_count, 1);
    EXPECT_EQ(io.last_response->header("x-after"), "1") << "the entry indexed past the bound is in the table";
    EXPECT_EQ(io.last_response->header("x-big").size(), 4000u);

    std::vector<uint8_t> bomb{0x88};
    bomb.insert(bomb.end(), 5000, 0xBF);
    protocol.on(response_headers(5, bomb));
    EXPECT_FALSE(protocol.ok()) << "a block that expands 16 times past the bound closes the connection";
    EXPECT_EQ(io.response_count, 1);
}

// The bound holds on the two other ways a response header block reaches the decoder (Huly QB-1211): a block split over
// CONTINUATION frames, and a block on a stream the client already reset -- decoded only to keep the table in step, never
// delivered (RFC 9113 section 4.3) -- which a list past the bound closed the connection with.
TEST(HTTP2ClientProtocol, AResponseHeaderListPastTheBoundIsDiscardedAcrossContinuationAndOnAResetStream) {
    using namespace qb1211_test;
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_streams(protocol, 3);
    qb::protocol::hpack::Encoder encoder;
    const auto                   block_of = [&](const std::vector<qb::protocol::hpack::HeaderField> &fields) {
        std::vector<uint8_t> block;
        EXPECT_TRUE(encoder.encode(fields, block));
        return block;
    };

    auto past = response_list_of_size(header_list_bound);
    past.emplace_back("x-after", "1");
    const auto                 whole = block_of(past);
    const std::vector<uint8_t> head(whole.begin(), whole.begin() + static_cast<std::ptrdiff_t>(whole.size() / 2));
    const std::vector<uint8_t> tail(whole.begin() + static_cast<std::ptrdiff_t>(whole.size() / 2), whole.end());
    auto                       first = response_headers(1, head);
    first.header.flags               = h2::FLAG_END_STREAM; // the block goes on in a CONTINUATION frame
    protocol.on(std::move(first));
    protocol.on(make_continuation_frame(1, h2::FLAG_END_HEADERS, tail));
    EXPECT_TRUE(protocol.ok()) << "a block past the bound over CONTINUATION refuses the stream, not the connection";
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(io.stream_error_count, 1);
    EXPECT_EQ(qb1211_test::last_rst_stream_error(io.output, 1), h2::ErrorCode::ENHANCE_YOUR_CALM);

    // Stream 3: a connection-specific field resets it; its trailer section, past the bound, arrives on the reset stream.
    auto refused         = response_headers(3, block_of({{":status", "200"}, {"connection", "close"}}));
    refused.header.flags = h2::FLAG_END_HEADERS;
    protocol.on(std::move(refused));
    ASSERT_EQ(qb1211_test::last_rst_stream_error(io.output, 3), h2::ErrorCode::PROTOCOL_ERROR);
    auto late    = response_list_of_size(header_list_bound);
    late.front() = qb::protocol::hpack::HeaderField{"x-status", "20"}; // a trailer section: no :status, the same octets
    late.emplace_back("x-later", "2");                                 // past the bound
    ASSERT_GT(std::accumulate(late.begin(), late.end(), std::size_t{0},
                              [](std::size_t n, const qb::protocol::hpack::HeaderField &f) { return n + f.hpack_size(); }),
              header_list_bound);
    protocol.on(response_headers(3, block_of(late)));
    EXPECT_TRUE(protocol.ok()) << "a refused block past the bound is decoded and dropped, the connection kept";
    EXPECT_EQ(io.goaway_count, 0);

    protocol.on(response_headers(5, block_of({{":status", "200"}, {"x-after", "1"}, {"x-later", "2"}})));
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.response_count, 1) << "the next request is served";
    EXPECT_EQ(io.last_response->header("x-after"), "1") << "the table kept in step through the CONTINUATION frame";
    EXPECT_EQ(io.last_response->header("x-later"), "2") << "the table kept in step through the reset stream";
}

// The bound holds on every section a response carries (Huly QB-1211): a trailer section past it, and an informational
// response past it, reset the stream -- ENHANCE_YOUR_CALM -- and fail the request, the connection kept and its table in
// step with the server's.
TEST(HTTP2ClientProtocol, ATrailerOrInformationalSectionPastTheBoundFailsItsStream) {
    using namespace qb1211_test;
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_streams(protocol, 3);
    qb::protocol::hpack::Encoder encoder;
    const auto                   block_of = [&](const std::vector<qb::protocol::hpack::HeaderField> &fields) {
        std::vector<uint8_t> block;
        EXPECT_TRUE(encoder.encode(fields, block));
        return block;
    };

    // Stream 1: the header section, then a trailer section past the bound -- x-status 20 counts as :status 200 does.
    auto head         = response_headers(1, block_of({{":status", "200"}}));
    head.header.flags = h2::FLAG_END_HEADERS;
    protocol.on(std::move(head));
    auto trailers    = response_list_of_size(header_list_bound);
    trailers.front() = qb::protocol::hpack::HeaderField{"x-status", "20"};
    trailers.emplace_back("x-after", "1");
    protocol.on(response_headers(1, block_of(trailers)));
    EXPECT_TRUE(protocol.ok()) << "the stream is refused, not the connection";
    EXPECT_EQ(io.response_count, 0) << "a response whose trailer section passed the bound was delivered";
    EXPECT_EQ(qb1211_test::last_rst_stream_error(io.output, 1), h2::ErrorCode::ENHANCE_YOUR_CALM);

    // Stream 3: a 103 past the bound.
    auto early          = response_list_of_size(header_list_bound);
    early.front().value = "103";
    early.emplace_back("x-early", "1");
    auto informational         = response_headers(3, block_of(early));
    informational.header.flags = h2::FLAG_END_HEADERS;
    protocol.on(std::move(informational));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(qb1211_test::last_rst_stream_error(io.output, 3), h2::ErrorCode::ENHANCE_YOUR_CALM);
    EXPECT_EQ(io.stream_error_count, 2) << "both requests fail";
    EXPECT_EQ(io.goaway_count, 0);

    protocol.on(response_headers(5, block_of({{":status", "200"}, {"x-after", "1"}, {"x-early", "1"}})));
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.response_count, 1) << "the next request is served";
    EXPECT_EQ(io.last_response->header("x-after"), "1");
    EXPECT_EQ(io.last_response->header("x-early"), "1");
}

// A block past the bound is refused for its size only once the fields kept say it is well-formed (Huly QB-1211): a
// malformed one -- a connection-specific field among the fields kept -- stays the PROTOCOL_ERROR it is, as within the
// bound.
TEST(HTTP2ClientProtocol, AMalformedResponsePastTheBoundStaysAProtocolError) {
    using namespace qb1211_test;
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_streams(protocol, 1);
    qb::protocol::hpack::Encoder encoder;
    auto                         past = response_list_of_size(header_list_bound);
    past.insert(past.begin() + 1, qb::protocol::hpack::HeaderField{"connection", "close"}); // kept: before the bound
    std::vector<uint8_t> block;
    ASSERT_TRUE(encoder.encode(past, block));
    protocol.on(response_headers(1, block));
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.response_count, 0);
    EXPECT_EQ(qb1211_test::last_rst_stream_error(io.output, 1), h2::ErrorCode::PROTOCOL_ERROR) << "malformed, whatever its size";
}

// ===========================================================================
// A response whose body contradicts its `content-length`, and one whose header list passes the client's
// SETTINGS_MAX_HEADER_LIST_SIZE (Huly QB-1235), are reset with INTERNAL_ERROR, read by the client off the wire (Huly
// QB-1265): the request was well-formed, and the server met "an unexpected internal error" (RFC 9113 §7) -- the first
// was reset with PROTOCOL_ERROR. Nothing is sent before the reset, and the same connection serves the next request.
// The other refusals of an invalid response use it too since Huly QB-1273 (HTTP/3 resets every one of them with
// H3_REQUEST_CANCELLED, Huly QB-1241).
// ===========================================================================
TEST(HTTP2ClientProtocol, AContradictedContentLengthOrAListPastTheClientBoundIsResetWithInternalError) {
    qb::http::Response contradicted;
    contradicted.status() = qb::http::status::OK;
    contradicted.add_header("content-length", "100");
    contradicted.body() = std::string("short");
    qb::http::Response past_list;
    past_list.status() = qb::http::status::OK;
    for (int i = 0; i < 140; ++i) {
        past_list.add_header("x-" + std::to_string(i), std::string(8000, 'v'));
    }
    const std::vector<std::pair<std::string, qb::http::Response const *>> shapes{
        {"content-length the body contradicts", &contradicted},
        {"header list past the client's MAX_HEADER_LIST_SIZE", &past_list},
    };
    for (auto const &[label, response] : shapes) {
        SCOPED_TRACE(label);
        Http2ClientFakeIO                          client_io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);
        Http2PeerFakeIO                            server_io;
        h2::ServerHttp2Protocol<Http2PeerFakeIO>   server(server_io);

        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/refused");
        ASSERT_TRUE(client.send_request(std::move(req), 7));
        pump(server, server_io, client_io);
        ASSERT_EQ(server_io.request_count, 1);

        EXPECT_FALSE(server.send_response(1, *response)) << "refused";
        EXPECT_TRUE(server.ok()) << "a stream error, the connection kept";
        EXPECT_EQ(find_frame_offset(server_io.output, h2::FrameType::HEADERS), SIZE_MAX) << "nothing sent before the reset";
        pump(client, client_io, server_io);
        EXPECT_TRUE(client.ok());
        EXPECT_EQ(client_io.stream_error_count, 1) << "the stream was reset";
        EXPECT_EQ(client_io.last_stream_error, h2::ErrorCode::INTERNAL_ERROR) << "the code on the wire";
        EXPECT_EQ(client_io.goaway_count, 0);

        // The same connection serves the next request.
        qb::http::Request next;
        next.method() = qb::http::method::GET;
        next.uri()    = qb::io::uri("https://example.test/next");
        ASSERT_TRUE(client.send_request(std::move(next), 8));
        pump(server, server_io, client_io);
        ASSERT_EQ(server_io.request_count, 2);
        qb::http::Response accepted;
        accepted.status() = qb::http::status::OK;
        accepted.body()   = "accepted";
        ASSERT_TRUE(server.send_response(3, accepted));
        pump(client, client_io, server_io);
        EXPECT_EQ(client_io.response_count, 1);
        EXPECT_EQ(client_io.last_status, 200);
        EXPECT_EQ(client_io.last_body, std::string("accepted"));
        EXPECT_EQ(client_io.last_app_id, 8u);
    }

    // The control: the same fields, fewer of them, the list under the client's 1 MiB -- sent and delivered.
    Http2ClientFakeIO                          client_io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);
    Http2PeerFakeIO                            server_io;
    h2::ServerHttp2Protocol<Http2PeerFakeIO>   server(server_io);
    qb::http::Request                          req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/under");
    ASSERT_TRUE(client.send_request(std::move(req), 9));
    pump(server, server_io, client_io);
    qb::http::Response under_list;
    under_list.status() = qb::http::status::OK;
    for (int i = 0; i < 120; ++i) {
        under_list.add_header("x-" + std::to_string(i), std::string(8000, 'v'));
    }
    ASSERT_TRUE(server.send_response(1, under_list)) << "120 fields of 8000 bytes, some 0.96 MB, within the bound";
    pump(client, client_io, server_io);
    EXPECT_EQ(client_io.stream_error_count, 0);
    EXPECT_EQ(client_io.response_count, 1);
}

// ===========================================================================
// Every response the server refuses itself in send_response() is reset with INTERNAL_ERROR, read by the client off the
// wire (Huly QB-1273, the reasoning of QB-1241 and QB-1265): the request was well-formed, and the server met "an
// unexpected internal error" in the application's response (RFC 9113 §7). A forbidden field, an invalid field, an invalid
// or conflicting `content-length`, a refused trailer section were reset with PROTOCOL_ERROR -- which says the CLIENT
// violated the protocol -- and a body past MAX_BODY_SIZE with ENHANCE_YOUR_CALM -- which says it generates excessive load.
// Nothing is sent before the reset, and the same connection serves the next request.
// ===========================================================================
TEST(HTTP2ClientProtocol, EveryInvalidResponseTheServerRefusesIsResetWithInternalError) {
    const auto shaped = [](const std::function<void(qb::http::Response &)> &shape) {
        qb::http::Response response;
        response.status() = qb::http::status::OK;
        shape(response);
        return response;
    };
    const std::vector<std::pair<std::string, qb::http::Response>> refused{
        {"a forbidden field", shaped([](qb::http::Response &r) { r.set_header("connection", "close"); })},
        {"an invalid field", shaped([](qb::http::Response &r) { r.set_header("x-bad", "a\rb"); })},
        {"an invalid content-length", shaped([](qb::http::Response &r) { r.set_header("content-length", "abc"); })},
        {"conflicting content-lengths", shaped([](qb::http::Response &r) {
             r.add_header("content-length", "5");
             r.add_header("content-length", "6");
             r.body() = std::string("12345");
         })},
        {"a refused trailer section", shaped([](qb::http::Response &r) { r.trailers().set_header("content-length", "7"); })},
        {"a body past MAX_BODY_SIZE",
         shaped([](qb::http::Response &r) { r.body() = std::string(qb::http::protocol_limits::MAX_BODY_SIZE + 1, 'x'); })},
    };
    for (auto const &[label, response] : refused) {
        SCOPED_TRACE(label);
        Http2ClientFakeIO                          client_io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> client(client_io);
        Http2PeerFakeIO                            server_io;
        h2::ServerHttp2Protocol<Http2PeerFakeIO>   server(server_io);

        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/refused");
        ASSERT_TRUE(client.send_request(std::move(req), 7));
        pump(server, server_io, client_io);
        ASSERT_EQ(server_io.request_count, 1);

        EXPECT_FALSE(server.send_response(1, response)) << "refused";
        EXPECT_TRUE(server.ok()) << "a stream error, the connection kept";
        EXPECT_EQ(find_frame_offset(server_io.output, h2::FrameType::HEADERS), SIZE_MAX) << "nothing sent before the reset";
        pump(client, client_io, server_io);
        EXPECT_TRUE(client.ok());
        EXPECT_EQ(client_io.stream_error_count, 1) << "the stream was reset";
        EXPECT_EQ(client_io.last_stream_error, h2::ErrorCode::INTERNAL_ERROR) << "the code on the wire";
        EXPECT_EQ(client_io.goaway_count, 0);

        qb::http::Request next;
        next.method() = qb::http::method::GET;
        next.uri()    = qb::io::uri("https://example.test/next");
        ASSERT_TRUE(client.send_request(std::move(next), 8));
        pump(server, server_io, client_io);
        ASSERT_EQ(server_io.request_count, 2);
        qb::http::Response accepted;
        accepted.status() = qb::http::status::OK;
        accepted.body()   = "accepted";
        ASSERT_TRUE(server.send_response(3, accepted));
        pump(client, client_io, server_io);
        EXPECT_EQ(client_io.response_count, 1) << "the same connection serves the next request";
        EXPECT_EQ(client_io.last_body, std::string("accepted"));
    }
}

// ===========================================================================
// RFC 9113 section 6.5.2: SETTINGS_MAX_HEADER_LIST_SIZE announces "the maximum size of field section that the sender is
// prepared to accept". The client stored the server's and never read it: a request, or its trailer section, left past it,
// and a server held to its own bound answered 431 or reset the stream (Huly QB-1274). The client judges both now as the
// server judges a response (Huly QB-1240): the leading block and the trailer section the request plans before anything
// is sent -- send_request() returns false, zero bytes on the socket, the stream id given back -- and a trailer section
// when it is handed over and again when it leaves, by the bound then in force: past it the stream is reset
// (INTERNAL_ERROR), the section never encoded. The first three cases then send a block that must decode as the server
// decodes the connection: a section encoded and dropped would have left its fields in the HPACK table, and the next block
// would name them by index.
// ===========================================================================
namespace qb1274_test {

/// A request of @p method on /big with an `x-k: v` field -- small enough for the HPACK table, so a block encoded and
/// then dropped would leave it there -- an `x-pad` field of @p octets octets, and @p body.
[[nodiscard]] qb::http::Request
padded(std::size_t octets, qb::http::Method method = qb::http::method::GET, std::string body = {}) {
    qb::http::Request request;
    request.method() = method;
    request.uri()    = qb::io::uri("https://example.test/big");
    request.set_header("x-k", "v");
    request.set_header("x-pad", std::string(octets, 'p'));
    request.body() = std::move(body);
    return request;
}

/// The size RFC 9113 section 6.5.2 counts of a header block the client sent.
[[nodiscard]] std::size_t
list_size(const SentHeaderBlock &block) {
    std::size_t size = 0;
    for (const auto &f : block.fields) {
        size += f.hpack_size();
    }
    return size;
}

/// The leading block the client sends for @p request, read off the wire of a client with no bound: its size less the
/// `x-pad` field's, the fixed part a bound is measured against.
[[nodiscard]] std::size_t
fixed_part(qb::http::Request request) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    const std::size_t                          before = io.output.size();
    const std::size_t                          pad    = request.header("x-pad").size();
    EXPECT_TRUE(protocol.send_request(std::move(request), 1));
    const auto blocks = sent_header_blocks(io.output, 1, before);
    EXPECT_FALSE(blocks.empty());
    return blocks.empty() ? 0 : list_size(blocks.front()) - (5 + pad + 32);
}

/// Every header block the client sent from @p from on, whatever its stream, decoded in order by ONE decoder: the
/// server's view of the connection's HPACK state. A block the client encoded and never sent leaves the ones after it
/// naming entries this decoder never saw.
[[nodiscard]] std::vector<SentHeaderBlock>
connection_blocks(const qb::allocator::pipe<char> &output, std::size_t from) {
    qb::protocol::hpack::Decoder decoder;
    std::vector<SentHeaderBlock> blocks;
    for (std::size_t off = from; off + h2::FRAME_HEADER_SIZE <= output.size();) {
        const auto fh = peek_frame_header(output, off);
        if (fh.get_type() == h2::FrameType::HEADERS) {
            const auto          *first = reinterpret_cast<const uint8_t *>(output.cbegin() + off + h2::FRAME_HEADER_SIZE);
            std::vector<uint8_t> payload(first, first + fh.get_payload_length());
            SentHeaderBlock      block;
            block.flags     = fh.flags;
            bool incomplete = false;
            EXPECT_TRUE(decoder.decode(payload, block.fields, incomplete)) << "a block names an entry the server never saw";
            blocks.push_back(std::move(block));
        }
        off += h2::FRAME_HEADER_SIZE + fh.get_payload_length();
    }
    return blocks;
}

/// Lift the server's bound out of the way, then send a request carrying @p name = @p value: the field a refused section
/// held, which an HPACK table run ahead of the server's would name by index.
void
send_after(h2::ClientHttp2Protocol<Http2ClientFakeIO> &protocol, const std::string &name, const std::string &value) {
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE, 65536}}));
    auto request = padded(0);
    request.set_header(name, value);
    EXPECT_TRUE(protocol.send_request(std::move(request), 99));
}

/// The payload size of every HEADERS frame the client sent from @p from on, in order.
[[nodiscard]] std::vector<std::size_t>
header_payload_sizes(const qb::allocator::pipe<char> &output, std::size_t from) {
    std::vector<std::size_t> sizes;
    for (std::size_t off = from; off + h2::FRAME_HEADER_SIZE <= output.size();) {
        const auto fh = peek_frame_header(output, off);
        if (fh.get_type() == h2::FrameType::HEADERS) {
            sizes.push_back(fh.get_payload_length());
        }
        off += h2::FRAME_HEADER_SIZE + fh.get_payload_length();
    }
    return sizes;
}

} // namespace qb1274_test

// The leading block: exactly the server's bound leaves, a byte more is refused with nothing written and its stream id
// given back, and the client's HPACK table stays in step -- the request that follows decodes from a fresh decoder. The
// bound is 2 KiB, under the 4 KiB HPACK table, so a refused block encoded and dropped would have left its fields there.
TEST(HTTP2ClientProtocol, ARequestPastTheServersHeaderListBoundIsRefusedWithNothingSent) {
    constexpr std::size_t                      bound = 2048;
    const std::size_t                          pad   = bound - qb1274_test::fixed_part(qb1274_test::padded(0)) - (5 + 32);
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE, static_cast<uint32_t>(bound)}}));
    const std::size_t before = io.output.size();
    EXPECT_FALSE(protocol.send_request(qb1274_test::padded(pad + 1), 1)) << "a byte past the server's bound left";
    EXPECT_EQ(io.output.size(), before) << "zero bytes on the socket";
    EXPECT_EQ(protocol.last_initiated_stream_id(), 0u) << "the refused request kept a stream id it never sent";
    EXPECT_TRUE(protocol.ok());
    ASSERT_TRUE(protocol.send_request(qb1274_test::padded(pad), 2)) << "exactly the bound";
    EXPECT_EQ(protocol.last_initiated_stream_id(), 1u) << "the next request takes the id given back";
    const auto blocks = sent_header_blocks(io.output, 1, before);
    ASSERT_EQ(blocks.size(), 1u);
    EXPECT_EQ(qb1274_test::list_size(blocks.front()), bound);
    EXPECT_EQ(blocks.front().value("x-pad").size(), pad);
    EXPECT_EQ(blocks.front().value("x-k"), "v");
}

// The trailer section the request plans is judged with its leading block, before anything is sent: past the bound the
// request is refused, nothing written; at the bound it leaves after the body and ends the stream, its blocks decoded
// from a fresh decoder.
TEST(HTTP2ClientProtocol, ARequestsTrailerSectionPastTheServersBoundIsRefusedWithNothingSent) {
    constexpr uint32_t bound   = 1000;
    const auto         trailed = [](std::size_t octets) {
        auto request = qb1274_test::padded(0, qb::http::method::POST, "abc");
        request.trailers().set_header("x-c", std::string(octets, 'c')); // 3 + octets + 32
        return request;
    };
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE, bound}}));
    const std::size_t before = io.output.size();
    EXPECT_FALSE(protocol.send_request(trailed(bound - 35 + 1), 1)) << "a trailer section a byte past the bound";
    EXPECT_EQ(io.output.size(), before) << "zero bytes on the socket";
    ASSERT_TRUE(protocol.send_request(trailed(bound - 35), 2)) << "exactly the bound";
    const auto blocks = sent_header_blocks(io.output, 1, before);
    ASSERT_EQ(blocks.size(), 2u) << "the leading block, then the trailer section";
    EXPECT_EQ(qb1274_test::list_size(blocks[1]), bound);
    EXPECT_EQ(blocks[1].value("x-c"), std::string(bound - 35, 'c'));
    EXPECT_TRUE(blocks[1].flags & h2::FLAG_END_STREAM);
}

// A trailer section handed over later -- send_request_trailers() -- or one whose body waited for credit while the server
// lowered its bound is judged when it leaves, by the bound then in force: the stream is reset with INTERNAL_ERROR, the
// section never sent and never encoded -- the next block, carrying its field, decodes as the server decodes.
TEST(HTTP2ClientProtocol, ATrailerSectionIsJudgedByTheServersBoundInForceWhenItLeaves) {
    {
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE, 1000}}));
        const std::size_t start   = io.output.size();
        auto              request = qb1274_test::padded(0, qb::http::method::POST, "body");
        request.set_header("trailer", "x-checksum");
        ASSERT_TRUE(protocol.send_request(std::move(request), 1)) << "announced, not set: handed over later";
        const std::size_t before = io.output.size();
        qb::http::headers trailers;
        trailers.add_header("x-checksum", std::string(1000, 'd'));
        EXPECT_FALSE(protocol.send_request_trailers(1, trailers)) << "past the bound";
        EXPECT_EQ(qb1211_test::last_rst_stream_error(io.output, 1), h2::ErrorCode::INTERNAL_ERROR);
        EXPECT_EQ(find_frame_offset(io.output, h2::FrameType::HEADERS, before), SIZE_MAX) << "the section was sent";
        EXPECT_TRUE(protocol.ok());
        qb1274_test::send_after(protocol, "x-checksum", std::string(1000, 'd'));
        const auto blocks = qb1274_test::connection_blocks(io.output, start);
        ASSERT_EQ(blocks.size(), 2u) << "the request's leading block and the next one's";
        EXPECT_EQ(blocks[1].value("x-checksum"), std::string(1000, 'd')) << "the HPACK table ran ahead of the server's";
        // The positive control: the encoder indexes such a field once it is sent, so a section encoded and dropped
        // would have indexed it too -- the same request again names it in a few octets, where its literal takes at
        // least the 625 its value Huffman-codes to (a 5-bit code per `d`).
        qb1274_test::send_after(protocol, "x-checksum", std::string(1000, 'd'));
        const auto sizes = qb1274_test::header_payload_sizes(io.output, start);
        ASSERT_EQ(sizes.size(), 3u);
        EXPECT_LT(sizes[2] + 500, sizes[1]) << "the field was not indexed: the check above proves nothing";
    }
    {
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 0}}));
        const std::size_t start   = io.output.size();
        auto              request = qb1274_test::padded(0, qb::http::method::POST, "abc");
        request.trailers().set_header("x-c", std::string(50, 'c')); // 3 + 50 + 32 = 85
        ASSERT_TRUE(protocol.send_request(std::move(request), 1)) << "no bound yet; the body waits for credit";
        const std::size_t before = io.output.size();
        protocol.on(make_settings_frame(
            {{h2::Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE, 84},
             {h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 100}}));
        EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 3u) << "the body left";
        EXPECT_EQ(qb1211_test::last_rst_stream_error(io.output, 1), h2::ErrorCode::INTERNAL_ERROR) << "judged by the bound in force";
        EXPECT_EQ(find_frame_offset(io.output, h2::FrameType::HEADERS, before), SIZE_MAX) << "the section was sent";
        qb1274_test::send_after(protocol, "x-c", std::string(50, 'c'));
        const auto blocks = qb1274_test::connection_blocks(io.output, start);
        ASSERT_EQ(blocks.size(), 2u) << "the request's leading block and the next one's";
        EXPECT_EQ(blocks[1].value("x-c"), std::string(50, 'c')) << "the HPACK table ran ahead of the server's";
    }
}

// A trailer section handed to send_request_trailers() while the body still waits for credit is judged then, not only once
// the body is out: past the bound the call returns false and the stream is reset at once (INTERNAL_ERROR), nothing kept.
// It returned true, and the reset came only after the body.
TEST(HTTP2ClientProtocol, ATrailerSectionHandedOverBehindTheBodyIsJudgedThen) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    protocol.on(make_settings_frame(
        {{h2::Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE, 1000}, {h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 0}}));
    auto request = qb1274_test::padded(0, qb::http::method::POST, "body");
    request.set_header("trailer", "x-checksum");
    ASSERT_TRUE(protocol.send_request(std::move(request), 1)) << "the body waits for credit";
    const std::size_t before = io.output.size();
    qb::http::headers trailers;
    trailers.add_header("x-checksum", std::string(1000, 'd'));
    EXPECT_FALSE(protocol.send_request_trailers(1, trailers)) << "past the bound, behind the body";
    EXPECT_EQ(qb1211_test::last_rst_stream_error(io.output, 1), h2::ErrorCode::INTERNAL_ERROR) << "reset when handed over";
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_INITIAL_WINDOW_SIZE, 100}}));
    EXPECT_EQ(sum_data_payload_for_stream(io.output, 1, before), 0u) << "the reset stream sent its body";
    EXPECT_EQ(find_frame_offset(io.output, h2::FrameType::HEADERS, before), SIZE_MAX) << "the section was sent";
    EXPECT_TRUE(protocol.ok());
}

// The id a refused request gives back is the one it took, whatever came before: after stream 1 is answered and closed, a
// request refused at id 3 leaves stream 1 the last initiated -- a late RST_STREAM on it is one on a closed stream,
// tolerated -- and id 3 idle: a frame the server sends on it before the next request is a connection error (RFC 9113
// §5.1), as on any id the client never used. It was read as one on a closed stream.
TEST(HTTP2ClientProtocol, ARefusedRequestGivesBackTheIdItTookAfterEarlierStreams) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    protocol.on(make_settings_frame({{h2::Http2SettingIdentifier::SETTINGS_MAX_HEADER_LIST_SIZE, 1000}}));
    ASSERT_TRUE(protocol.send_request(qb1274_test::padded(0), 1));
    protocol.on(make_headers_frame(1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, {{":status", "204"}}));
    ASSERT_EQ(io.response_count, 1);
    EXPECT_FALSE(protocol.send_request(qb1274_test::padded(1000), 2)) << "past the bound";
    EXPECT_EQ(protocol.last_initiated_stream_id(), 1u) << "the refused request kept id 3";
    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(1);
    rst.payload.error_code = h2::ErrorCode::CANCEL;
    protocol.on(rst);
    EXPECT_TRUE(protocol.ok()) << "a late RST_STREAM on closed stream 1 closed the connection";
    const std::size_t before = io.output.size();
    protocol.on(make_window_update_frame(3, 100));
    EXPECT_FALSE(protocol.ok()) << "a frame on id 3, never sent, was read as one on a closed stream";
    EXPECT_NE(find_frame_offset(io.output, h2::FrameType::GOAWAY, before), SIZE_MAX);
}

// ===========================================================================
// The client's PING/SETTINGS guard counts the replies QUEUED in its output, as the server's does (Huly QB-1270, the
// maintainer's decision of 2026-11-11): a PONG or a SETTINGS ACK the server solicited counts from the moment it is
// written until the socket has taken its last byte, and the 1001st one queued closes the connection. Nothing the server
// sends forgives a reply -- only the output draining does.
// ===========================================================================
namespace qb1270_queue_test {

namespace fake = qb::http::test;
using fake::solicited_reply;

constexpr int control_budget = static_cast<int>(qb::http2::protocol_limits::MAX_QUEUED_CONTROL_REPLIES);

[[nodiscard]] qb::http::Request
get(const char *path) {
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri(std::string("https://example.test") + path);
    return req;
}

} // namespace qb1270_queue_test

// The attack: a server that never reads solicits 999 replies, then sends what the guard took for progress between two
// units of it -- an octet of a response body, a response completed -- five times over; each unit forgave the budget,
// 4995 PONGs or ACKs queued and no GOAWAY, and so on up to qb-io's write cap. So did nothing at all once, and an empty
// DATA until QB-1270's first cut. A thousand queued close the connection now, whatever the server sends between them,
// and the 1001st reply is not written (re-derived from AnEmptyDataDoesNotForgiveTheControlReplyBudget, whose octet of
// the body was what forgave).
TEST(HTTP2ClientProtocol, AServerThatNeverReadsIsCutOnceAThousandRepliesAreQueued) {
    namespace fake = qb::http::test;
    enum class between { nothing, an_empty_data, an_octet_of_the_body, a_response_completed };
    for (const auto what : fake::all_solicited_replies) {
        for (const auto unit : {between::nothing, between::an_empty_data, between::an_octet_of_the_body, between::a_response_completed}) {
            SCOPED_TRACE(std::string(what == fake::solicited_reply::pong ? "PING" : "SETTINGS") + ", between the rounds: "
                         + (unit == between::nothing                ? "nothing"
                            : unit == between::an_empty_data        ? "an empty DATA"
                            : unit == between::an_octet_of_the_body ? "an octet of the body"
                                                                    : "a response completed"));
            Http2ClientFakeIO                          io;
            h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
            ASSERT_TRUE(protocol.send_request(qb1270_queue_test::get("/flood"), 17)); // opens stream 1
            push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS, 1, encode_hpack_headers({{":status", "200"}}));
            drive(protocol, io);
            ASSERT_EQ(io.goaway_count, 0);
            fake::socket_takes_everything(io); // the preface and the request left; from here the server reads nothing
            io.wire.reset();
            uint32_t sid = 3;
            for (int round = 0; round < 5 && io.goaway_count == 0; ++round) {
                fake::solicit_replies(io, what, qb1270_queue_test::control_budget - 1);
                if (unit == between::an_empty_data) {
                    push_frame(io, h2::FrameType::DATA, 0, 1, {});
                } else if (unit == between::an_octet_of_the_body) {
                    push_frame(io, h2::FrameType::DATA, 0, 1, {'x'});
                } else if (unit == between::a_response_completed) {
                    ASSERT_TRUE(protocol.send_request(qb1270_queue_test::get("/answered"), 100u + static_cast<uint64_t>(round)));
                    push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, sid,
                               encode_hpack_headers({{":status", "204"}}));
                    sid += 2;
                }
                drive(protocol, io);
            }
            EXPECT_EQ(io.goaway_count, 1) << "the replies to a server that never reads queued without a bound";
            EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
            EXPECT_FALSE(protocol.ok());
            EXPECT_EQ(fake::solicited_reply_ends(io.output).size(), static_cast<std::size_t>(qb1270_queue_test::control_budget))
                << "a thousand replies queued is the bound: the 1001st is not written";
            const auto frames = fake::parse_emitted_frames(io.output);
            ASSERT_FALSE(frames.empty());
            EXPECT_EQ(frames.back().type, h2::FrameType::GOAWAY) << "the GOAWAY is the last frame written";
        }
    }
}

// The legitimate case the old budget cut: a server that pings to keep an idle connection alive, or to measure it, while
// the client has no request in flight -- no response progress ever forgave its PONGs, and the client closed the
// connection at the 1001st. Each PONG leaves before the next PING comes: nothing is queued, 5000 are answered and the
// connection stays open. The same for SETTINGS.
TEST(HTTP2ClientProtocol, AServerThatReadsMaySolicitRepliesForEverWithNoRequestInFlight) {
    namespace fake = qb::http::test;
    for (const auto what : fake::all_solicited_replies) {
        SCOPED_TRACE(what == fake::solicited_reply::pong ? "PING" : "SETTINGS");
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        fake::socket_takes_everything(io);
        io.wire.reset();
        for (int i = 0; i < 5000 && io.goaway_count == 0; ++i) {
            fake::solicit_replies(io, what);
            drive(protocol, io);
            fake::socket_takes_everything(io); // the server reads its reply before it asks again
        }
        EXPECT_EQ(io.goaway_count, 0) << "a connection its server only pings was closed";
        EXPECT_TRUE(protocol.ok());
        EXPECT_EQ(fake::solicited_reply_ends(io.wire).size(), 5000u) << "a reply is missing";
        EXPECT_EQ(io.wire.size(), 5000u * fake::solicited_reply_size(what)) << "something other than the replies was written";
    }
}

// A busy server that reads is never cut either: 999 PINGs in one read, then nothing, an octet of a response's body or
// a response completed, the client's output drained before the next round, five times over -- every PING answered, no
// GOAWAY. What the server sends between the rounds plays no part: with nothing between them the 1001st PING closed the
// connection (re-derived from the progress model's witness, where the octet was what forgave; Huly QB-1270).
TEST(HTTP2ClientProtocol, ABusyServerThatReadsIsNeverCut) {
    namespace fake = qb::http::test;
    enum class between { nothing, an_octet_of_the_body, a_response_completed };
    for (const auto unit : {between::nothing, between::an_octet_of_the_body, between::a_response_completed}) {
        SCOPED_TRACE(unit == between::nothing                ? "nothing"
                     : unit == between::an_octet_of_the_body ? "an octet of the body"
                                                             : "a response completed");
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        ASSERT_TRUE(protocol.send_request(qb1270_queue_test::get("/busy"), 17)); // opens stream 1
        push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS, 1, encode_hpack_headers({{":status", "200"}}));
        drive(protocol, io);
        fake::socket_takes_everything(io);
        io.wire.reset();
        uint32_t sid       = 3;
        int      completed = 0;
        for (int round = 0; round < 5; ++round) {
            fake::solicit_replies(io, fake::solicited_reply::pong, qb1270_queue_test::control_budget - 1);
            if (unit == between::an_octet_of_the_body) {
                push_frame(io, h2::FrameType::DATA, 0, 1, {'x'});
            } else if (unit == between::a_response_completed) {
                ASSERT_TRUE(protocol.send_request(qb1270_queue_test::get("/answered"), 100u + static_cast<uint64_t>(round)));
                push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, sid,
                           encode_hpack_headers({{":status", "204"}}));
                sid += 2;
                ++completed;
            }
            drive(protocol, io);
            fake::socket_takes_everything(io);
        }
        EXPECT_EQ(io.goaway_count, 0) << "a server that reads was cut";
        EXPECT_TRUE(protocol.ok());
        EXPECT_EQ(fake::solicited_reply_ends(io.wire).size(), static_cast<std::size_t>(5 * (qb1270_queue_test::control_budget - 1)));
        EXPECT_EQ(io.response_count, completed);
    }
}

// A slow reader is counted for what it has not read, never for what it has: a thousand replies queued, then one leaves
// and one is solicited, 3000 times -- always a thousand queued, never the 1001st, no GOAWAY, with no response progress
// in 4000 PINGs. Then one more with nothing read: the 1001st, and the connection is closed.
TEST(HTTP2ClientProtocol, ASlowReaderIsNotCutWhileFewerThanAThousandRepliesAreQueued) {
    namespace fake = qb::http::test;
    for (const auto what : fake::all_solicited_replies) {
        SCOPED_TRACE(what == fake::solicited_reply::pong ? "PING" : "SETTINGS");
        const std::size_t                          reply = fake::solicited_reply_size(what);
        Http2ClientFakeIO                          io;
        h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
        fake::socket_takes_everything(io);
        io.wire.reset();
        fake::solicit_replies(io, what, qb1270_queue_test::control_budget);
        drive(protocol, io);
        ASSERT_EQ(io.goaway_count, 0) << "a thousand replies queued are within the bound";
        ASSERT_EQ(io.output.size(), 1000u * reply);
        for (int i = 0; i < 3000 && io.goaway_count == 0; ++i) {
            fake::socket_takes(io, reply); // one reply leaves: 999 queued
            fake::solicit_replies(io, what);
            drive(protocol, io); // a thousand again
        }
        EXPECT_EQ(io.goaway_count, 0) << "a slow reader was cut with fewer than a thousand replies queued";
        EXPECT_TRUE(protocol.ok());
        EXPECT_EQ(io.output.size(), 1000u * reply);
        EXPECT_EQ(io.wire.size(), 3000u * reply);
        fake::solicit_replies(io, what); // nothing left since: this one would be the 1001st queued
        drive(protocol, io);
        EXPECT_EQ(io.goaway_count, 1) << "the 1001st queued reply did not close the connection";
        EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
        EXPECT_EQ(fake::solicited_reply_ends(fake::written_and_queued(io)).size(), 4000u) << "the 1001st queued reply was written";
    }
}

namespace qb1270_queue_test {

/// The offsets at which the replies queued end, oldest first: what a row of the partial-write table reads.
using ends_t = const std::vector<std::size_t> &;

/// A thousand replies queued behind and around two requests -- a request sent, 400 replies, a request sent, 600
/// replies -- on a connection whose io has already counted @p already_written bytes; then the socket takes the first
/// bytes of the output, as many as @p take says of the ends of the replies queued. What is asserted: the client queues
/// as many further replies as have wholly left -- their last byte taken -- and closes the connection at the next.
void
expect_replies_forgiven_as_their_last_byte_leaves(solicited_reply what, std::size_t already_written,
                                                  const std::function<std::size_t(ends_t)> &take) {
    Http2ClientFakeIO io;
    io.written = already_written;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    fake::socket_takes_everything(io); // the preface and the client's SETTINGS
    io.wire.reset();
    ASSERT_TRUE(protocol.send_request(get("/first"), 1));
    fake::solicit_replies(io, what, 400);
    drive(protocol, io);
    ASSERT_TRUE(protocol.send_request(get("/second"), 2));
    fake::solicit_replies(io, what, 600);
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok()) << "a thousand replies queued are within the bound";
    const auto ends = fake::solicited_reply_ends(io.output);
    ASSERT_EQ(ends.size(), 1000u);
    ASSERT_GT(ends.front(), fake::solicited_reply_size(what)) << "the first request is queued before the first reply";
    ASSERT_GT(ends[400] - ends[399], fake::solicited_reply_size(what)) << "the second request is queued between two replies";
    ASSERT_EQ(ends.back(), io.output.size());

    const std::size_t taken = take(ends);
    fake::socket_takes(io, taken);
    const int left = static_cast<int>(std::count_if(ends.begin(), ends.end(), [taken](std::size_t end) { return end <= taken; }));
    EXPECT_EQ(fake::replies_admitted_before_the_cut(protocol, io, what, 1100), left)
        << "the socket took " << taken << " bytes of " << ends.back() << ": " << left << " replies have wholly left";
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
}

} // namespace qb1270_queue_test

// The partial write, as on the server: a reply is forgiven when its LAST byte has left the output, no sooner -- the
// bytes queued before it, or all of it but one octet, forgive nothing -- and no later; every frame the client writes
// moves the output, a request's HEADERS as much as a reply; one write forgives the replies it carried away, not the
// count. Read at each edge of the first reply, of the second, around the request queued between the 400th and the
// 401st, and at the end of the output; and again on an io whose count of bytes written wraps in the middle of the queue.
TEST(HTTP2ClientProtocol, AReplySplitAcrossAPartialWriteIsForgivenWhenItsLastByteHasLeft) {
    namespace fake = qb::http::test;
    using qb1270_queue_test::ends_t;

    const std::vector<std::pair<const char *, std::function<std::size_t(ends_t)>>> takes = {
        {"nothing", [](ends_t) -> std::size_t { return 0; }},
        {"one octet", [](ends_t) -> std::size_t { return 1; }},
        {"all that is queued before the first reply but one octet", [](ends_t e) { return e[0] - (e[1] - e[0]) - 1; }},
        {"all that is queued before the first reply", [](ends_t e) { return e[0] - (e[1] - e[0]); }},
        {"the first octet of the first reply", [](ends_t e) { return e[0] - (e[1] - e[0]) + 1; }},
        {"the first reply but its last octet", [](ends_t e) { return e[0] - 1; }},
        {"the first reply", [](ends_t e) { return e[0]; }},
        {"the first reply and an octet of the second", [](ends_t e) { return e[0] + 1; }},
        {"the second reply but its last octet", [](ends_t e) { return e[1] - 1; }},
        {"the second reply", [](ends_t e) { return e[1]; }},
        {"the 400th reply", [](ends_t e) { return e[399]; }},
        {"the request queued behind the 400th reply", [](ends_t e) { return e[400] - (e[1] - e[0]); }},
        {"the 401st reply but its last octet", [](ends_t e) { return e[400] - 1; }},
        {"the 401st reply", [](ends_t e) { return e[400]; }},
        {"everything but the last octet", [](ends_t e) { return e[999] - 1; }},
        {"everything", [](ends_t e) { return e[999]; }},
    };
    for (const auto what : fake::all_solicited_replies) {
        for (const std::size_t already_written : {std::size_t{0}, std::size_t{123456}, static_cast<std::size_t>(-1) - 9000u}) {
            for (const auto &[name, take] : takes) {
                SCOPED_TRACE(std::string(what == fake::solicited_reply::pong ? "PING" : "SETTINGS") + ", the io had written "
                             + std::to_string(already_written) + " bytes, the socket takes " + name);
                qb1270_queue_test::expect_replies_forgiven_as_their_last_byte_leaves(what, already_written, take);
            }
        }
    }
}

// A DATA the stream is reset for -- its body past the response's content-length -- forgives nothing either: it
// forgave the queued control replies before the client found the overrun, so a hostile server answering each request
// with one held the guard at zero across rounds of 999 PINGs. No frame the server sends forgives them since the guard
// counts what the output holds, and this server reads nothing: the 1001st reply queued closes the connection (Huly
// QB-1270; the reset this DATA draws is the reset of a request in flight: written between the PONGs, it is not a reply
// the server drew for nothing and is not counted with them -- TheResetOfARequestInFlightIsNotAReplyTheServerSolicits).
TEST(HTTP2ClientProtocol, ADataTheStreamIsResetForDoesNotForgiveTheControlReplyBudget) {
    const int                                  budget = static_cast<int>(qb::http2::protocol_limits::MAX_QUEUED_CONTROL_REPLIES);
    const std::vector<uint8_t>                 ping_payload(8, 0x00);
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    uint32_t                                   sid = 1;
    for (int round = 0; round < 3 && io.goaway_count == 0; ++round, sid += 2) {
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("https://example.test/overrun");
        ASSERT_TRUE(protocol.send_request(std::move(req), 17 + round));
        push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS, sid, encode_hpack_headers({{":status", "200"}, {"content-length", "1"}}));
        for (int i = 0; i < budget - 1; ++i) {
            push_frame(io, h2::FrameType::PING, 0, 0, ping_payload);
        }
        push_frame(io, h2::FrameType::DATA, 0, sid, {'a', 'b'}); // past the content-length: the stream is reset
        drive(protocol, io);
    }
    EXPECT_EQ(io.goaway_count, 1) << "a DATA the stream was reset for forgave the budget";
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
}

// ===========================================================================
// The resets a server solicits from the client count with its PONGs and SETTINGS ACKs while the output holds them (Huly
// QB-1270, the maintainer's « Oui, dans QB-1270 » of 2026-11-11). The reset of a request in flight retires it: the
// server draws one for each request the client opened. Any other -- a HEADERS on a stream that is closed -- is a reply
// it draws for nothing, and those had no bound at all: a server that read nothing queued one for each frame it sent,
// up to qb-io's write cap. A frame on an IDLE stream is not such a reply: it is a connection error (RFC 9113 §5.1).
// ===========================================================================
namespace qb1270_reset_test {

namespace fake = qb::http::test;
using qb1270_queue_test::control_budget;
using qb1270_queue_test::get;
using client_protocol = h2::ClientHttp2Protocol<Http2ClientFakeIO>;

/// The octets of a RST_STREAM frame.
constexpr std::size_t reset_size = h2::FRAME_HEADER_SIZE + 4;

/// What closed the stream the server then sends HEADERS on.
enum class closed_by { a_response_completed, a_reset_of_the_server, a_reset_of_the_client };
constexpr std::array<closed_by, 3> all_closed_by{
    closed_by::a_response_completed, closed_by::a_reset_of_the_server, closed_by::a_reset_of_the_client
};

[[nodiscard]] const char *
name_of(closed_by how) {
    return how == closed_by::a_response_completed    ? "stream 1 closed by a completed response"
           : how == closed_by::a_reset_of_the_server ? "stream 1 closed by the server's reset"
                                                     : "stream 1 closed by the client's reset";
}

/// The client opens stream 1 and the stream is closed @p how -- the client's own reset, of a response with no :status,
/// is the reset of a request in flight, which is not counted. The socket then takes everything: the server has read the
/// request, and from here whatever the test lets it read.
void
close_stream_one(client_protocol &protocol, Http2ClientFakeIO &io, closed_by how) {
    ASSERT_TRUE(protocol.send_request(get("/closed"), 1));
    switch (how) {
        case closed_by::a_response_completed:
            push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, 1, encode_hpack_headers({{":status", "204"}}));
            break;
        case closed_by::a_reset_of_the_server:
            push_frame(io, h2::FrameType::RST_STREAM, 0, 1, {0x00, 0x00, 0x00, 0x08}); // CANCEL
            break;
        case closed_by::a_reset_of_the_client:
            push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS, 1, encode_hpack_headers({{"x-no-status", "1"}}));
            break;
    }
    drive(protocol, io);
    ASSERT_TRUE(protocol.ok());
    ASSERT_EQ(io.goaway_count, 0);
    fake::socket_takes_everything(io);
    io.wire.reset();
}

/// @p n HEADERS frames on closed stream 1, a whole block each: each one draws a RST_STREAM(STREAM_CLOSED).
void
headers_on_closed_stream_one(Http2ClientFakeIO &io, int n = 1) {
    static const std::vector<uint8_t> block = encode_hpack_headers({{":status", "200"}});
    for (int i = 0; i < n; ++i) {
        push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS, 1, block);
    }
}

/// The RST_STREAM frames in @p bytes.
[[nodiscard]] std::size_t
resets_in(const qb::allocator::pipe<char> &bytes) {
    std::size_t n = 0;
    for (const auto &f : fake::parse_emitted_frames(bytes)) {
        n += f.type == h2::FrameType::RST_STREAM ? 1u : 0u;
    }
    return n;
}

} // namespace qb1270_reset_test

// The attack: a server that never reads sends 5000 HEADERS on a stream that is closed -- by a completed response, by
// its own reset, by the client's. Each drew a RST_STREAM(STREAM_CLOSED), 13 octets exempt from flow control, and
// nothing counted them: 5000 queued, no GOAWAY, and so on up to qb-io's write cap (CVE-2019-9514 from the client's
// side). A thousand queued close the connection now, and the 1001st reset is not written.
TEST(HTTP2ClientProtocol, AServerThatNeverReadsIsCutOnceAThousandResetsAreQueued) {
    using namespace qb1270_reset_test;
    for (const auto how : all_closed_by) {
        SCOPED_TRACE(name_of(how));
        Http2ClientFakeIO io;
        client_protocol   protocol(io);
        close_stream_one(protocol, io, how);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
        headers_on_closed_stream_one(io, 5000);
        drive(protocol, io);
        EXPECT_EQ(io.goaway_count, 1) << "the resets a server that never reads solicited queued without a bound";
        EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
        EXPECT_FALSE(protocol.ok());
        EXPECT_EQ(resets_in(io.output), static_cast<std::size_t>(control_budget))
            << "a thousand resets queued is the bound: the 1001st is not written";
        const auto frames = fake::parse_emitted_frames(io.output);
        ASSERT_FALSE(frames.empty());
        EXPECT_EQ(frames.back().type, h2::FrameType::GOAWAY) << "the GOAWAY is the last frame written";
    }
}

// One count for every reply the server draws for nothing: 333 PONGs, 333 SETTINGS ACKs and 333 resets queued by a
// server that reads nothing, then one more reply of any kind -- a thousand queued, within the bound; the next one, of
// that kind, closes the connection and is not written. The resets were in no count, so a thousand replies queued, a
// third of them resets, closed nothing.
TEST(HTTP2ClientProtocol, PongsSettingsAcksAndTheResetsAServerSolicitsShareTheQueuedCount) {
    using namespace qb1270_reset_test;
    struct kind {
        const char                              *name;
        std::function<void(Http2ClientFakeIO &)> solicit; // one more reply of this kind
    };
    const std::vector<kind> kinds = {
        {"a PING", [](Http2ClientFakeIO &io) { fake::solicit_replies(io, fake::solicited_reply::pong); }},
        {"a SETTINGS", [](Http2ClientFakeIO &io) { fake::solicit_replies(io, fake::solicited_reply::settings_ack); }},
        {"a HEADERS on a closed stream", [](Http2ClientFakeIO &io) { headers_on_closed_stream_one(io); }},
    };
    const auto replies_in = [](const qb::allocator::pipe<char> &bytes) {
        return fake::solicited_reply_ends(bytes).size() + resets_in(bytes);
    };
    for (const auto &[name, one_more] : kinds) {
        SCOPED_TRACE(name);
        Http2ClientFakeIO io;
        client_protocol   protocol(io);
        close_stream_one(protocol, io, closed_by::a_response_completed);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
        for (int i = 0; i < 333; ++i) {
            fake::solicit_replies(io, fake::solicited_reply::pong);
            fake::solicit_replies(io, fake::solicited_reply::settings_ack);
            headers_on_closed_stream_one(io);
        }
        drive(protocol, io);
        ASSERT_TRUE(protocol.ok());
        ASSERT_EQ(replies_in(io.output), 999u);
        one_more(io);
        drive(protocol, io);
        EXPECT_TRUE(protocol.ok()) << "a thousand replies queued are within the bound";
        EXPECT_EQ(replies_in(io.output), 1000u);
        const std::size_t queued = io.output.size();
        one_more(io);
        drive(protocol, io);
        EXPECT_EQ(io.goaway_count, 1) << "the 1001st reply queued closed nothing";
        EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
        EXPECT_EQ(replies_in(io.output), 1000u) << "the 1001st reply was written";
        const auto frames = fake::parse_emitted_frames(io.output);
        ASSERT_FALSE(frames.empty());
        EXPECT_EQ(frames.back().type, h2::FrameType::GOAWAY);
        EXPECT_EQ(frames.back().payload_offset - h2::FRAME_HEADER_SIZE, queued) << "something was written before the GOAWAY";
    }
}

// A busy, legitimate server is never cut by this count, however many HEADERS fall on streams that have closed, because
// it reads: 5000 HEADERS on a closed stream each read before the next; 999 in one read, the client's output drained,
// five times; and what a client meets when the response it resets a request for has more frames in flight -- a
// request, a response with no :status (the client resets its request: not counted), the trailers that were behind it
// (on a stream now closed: a reset, counted), 3000 times. Every reset is written, none is refused, no GOAWAY.
TEST(HTTP2ClientProtocol, ABusyServerWhoseFramesFallOnClosedStreamsIsNeverCut) {
    using namespace qb1270_reset_test;
    {
        SCOPED_TRACE("each reset read before the next HEADERS");
        Http2ClientFakeIO io;
        client_protocol   protocol(io);
        close_stream_one(protocol, io, closed_by::a_response_completed);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
        for (int i = 0; i < 5000 && io.goaway_count == 0; ++i) {
            headers_on_closed_stream_one(io);
            drive(protocol, io);
            fake::socket_takes_everything(io);
        }
        EXPECT_EQ(io.goaway_count, 0) << "a server that reads was cut";
        EXPECT_TRUE(protocol.ok());
        EXPECT_EQ(io.wire.size(), 5000u * reset_size) << "a reset is missing, or something else was written";
    }
    {
        SCOPED_TRACE("999 HEADERS in one read, five times");
        Http2ClientFakeIO io;
        client_protocol   protocol(io);
        close_stream_one(protocol, io, closed_by::a_reset_of_the_server);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
        for (int round = 0; round < 5; ++round) {
            headers_on_closed_stream_one(io, control_budget - 1);
            drive(protocol, io);
            fake::socket_takes_everything(io);
        }
        EXPECT_EQ(io.goaway_count, 0) << "a server that reads was cut";
        EXPECT_TRUE(protocol.ok());
        EXPECT_EQ(io.wire.size(), 5u * static_cast<std::size_t>(control_budget - 1) * reset_size);
    }
    {
        SCOPED_TRACE("3000 requests reset for their response, each with trailers in flight behind it");
        Http2ClientFakeIO io;
        client_protocol   protocol(io);
        fake::socket_takes_everything(io);
        io.wire.reset();
        uint32_t sid = 1;
        for (int i = 0; i < 3000 && io.goaway_count == 0; ++i, sid += 2) {
            ASSERT_TRUE(protocol.send_request(get("/reset-for-its-response"), 1u + static_cast<uint64_t>(i)));
            push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS, sid, encode_hpack_headers({{"x-no-status", "1"}}));
            push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, sid, encode_hpack_headers({{"x-trailer", "1"}}));
            drive(protocol, io);
            fake::socket_takes_everything(io);
        }
        EXPECT_EQ(io.goaway_count, 0) << "a server that reads was cut";
        EXPECT_TRUE(protocol.ok());
        EXPECT_EQ(io.stream_error_count, 3000);
        EXPECT_EQ(resets_in(io.wire), 6000u) << "one reset of each request, one for the trailers behind it";
    }
}

// A slow server is counted for what it has not read, never for what it has: a thousand resets queued, then one leaves
// and one is solicited, 3000 times -- always a thousand queued, never the 1001st, no GOAWAY. Then one more with
// nothing read: the 1001st, and the connection is closed.
TEST(HTTP2ClientProtocol, ASlowServerIsNotCutWhileFewerThanAThousandResetsAreQueued) {
    using namespace qb1270_reset_test;
    Http2ClientFakeIO io;
    client_protocol   protocol(io);
    close_stream_one(protocol, io, closed_by::a_response_completed);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    headers_on_closed_stream_one(io, control_budget);
    drive(protocol, io);
    ASSERT_EQ(io.goaway_count, 0) << "a thousand resets queued are within the bound";
    ASSERT_EQ(io.output.size(), 1000u * reset_size);
    for (int i = 0; i < 3000 && io.goaway_count == 0; ++i) {
        fake::socket_takes(io, reset_size); // one reset leaves: 999 queued
        headers_on_closed_stream_one(io);
        drive(protocol, io); // a thousand again
    }
    EXPECT_EQ(io.goaway_count, 0) << "a slow server was cut with fewer than a thousand resets queued";
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.output.size(), 1000u * reset_size);
    EXPECT_EQ(io.wire.size(), 3000u * reset_size);
    headers_on_closed_stream_one(io); // nothing left since: this one would be the 1001st queued
    drive(protocol, io);
    EXPECT_EQ(io.goaway_count, 1) << "the 1001st queued reset did not close the connection";
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
    EXPECT_EQ(resets_in(fake::written_and_queued(io)), 4000u) << "the 1001st queued reset was written";
}

// The partial write of a reset: it is queued until the socket has taken its LAST byte, as a PONG is. A reset written
// first in an empty output, or behind a request the client queued; the socket takes it but for its last byte, or
// whole, and the server pings until the connection is closed. While that byte has not left, the reset is one of the
// thousand: 999 PONGs are admitted behind it. Once it has left, a thousand are. (It was in no count: a thousand PONGs
// were admitted either way.)
TEST(HTTP2ClientProtocol, AClientResetIsForgivenWhenItsLastByteHasLeft) {
    using namespace qb1270_reset_test;
    for (const auto how : all_closed_by) {
        for (const bool behind_a_request : {false, true}) {
            for (const bool last_byte_left : {false, true}) {
                SCOPED_TRACE(std::string(name_of(how))
                             + (behind_a_request ? ", the reset behind a request queued" : ", the reset first in the output")
                             + (last_byte_left ? ", taken whole" : ", taken but for its last byte"));
                Http2ClientFakeIO io;
                client_protocol   protocol(io);
                close_stream_one(protocol, io, how);
                ASSERT_FALSE(::testing::Test::HasFatalFailure());
                if (behind_a_request) {
                    ASSERT_TRUE(protocol.send_request(get("/queued"), 2));
                    ASSERT_GT(io.output.size(), 0u);
                }
                const std::size_t before = io.output.size();
                headers_on_closed_stream_one(io);
                drive(protocol, io);
                ASSERT_TRUE(protocol.ok());
                ASSERT_EQ(io.output.size(), before + reset_size) << "one reset, and nothing else, was written";
                fake::socket_takes(io, last_byte_left ? before + reset_size : before + reset_size - 1);
                EXPECT_EQ(fake::replies_admitted_before_the_cut(protocol, io, fake::solicited_reply::pong, 1100),
                          control_budget - (last_byte_left ? 0 : 1))
                    << (last_byte_left ? "a reset the socket took whole was still counted"
                                       : "a reset whose last byte had not left was forgiven");
                EXPECT_EQ(io.goaway_count, 1);
                EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
            }
        }
    }
}

// What is NOT such a reply: the reset of a request in flight. It retires the request, so the server draws one for each
// request the client opened and no more; it is written with what the client itself sends. 1500 requests, each answered
// with a response the client resets it for, nothing read: 1500 resets queued and no GOAWAY -- and they take no place
// in the count: a thousand PONGs are still admitted behind them, the 1001st closes the connection.
TEST(HTTP2ClientProtocol, TheResetOfARequestInFlightIsNotAReplyTheServerSolicits) {
    using namespace qb1270_reset_test;
    Http2ClientFakeIO io;
    client_protocol   protocol(io);
    fake::socket_takes_everything(io);
    io.wire.reset();
    uint32_t sid = 1;
    for (int i = 0; i < 1500; ++i, sid += 2) {
        ASSERT_TRUE(protocol.send_request(get("/no-status"), 1u + static_cast<uint64_t>(i)));
        push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS, sid, encode_hpack_headers({{"x-no-status", "1"}}));
        drive(protocol, io);
        ASSERT_EQ(io.goaway_count, 0) << "the reset of request " << i << " closed the connection";
    }
    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.stream_error_count, 1500);
    EXPECT_EQ(resets_in(io.output), 1500u);
    EXPECT_EQ(fake::replies_admitted_before_the_cut(protocol, io, fake::solicited_reply::pong, 1100), control_budget)
        << "the resets of requests in flight were counted with the replies the server solicits";
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
}

// A stream the SERVER opened is never a request in flight: the reset of a pushed stream is a reply it solicits, counted
// like the others. Push is disabled and no PUSH_PROMISE reaches this code; the test seam reserves the streams, as
// ReservedPushRejectionRetiresStreamOnce does, and the application refuses each. A thousand refusals queued, the
// 1001st closes the connection and is not written.
TEST(HTTP2ClientProtocol, ARefusedPushIsAReplyTheServerSolicits) {
    using namespace qb1270_reset_test;
    using peer = h2::ProtocolTestPeer<client_protocol>;
    Http2ClientFakeIO io;
    client_protocol   protocol(io);
    fake::socket_takes_everything(io);
    io.wire.reset();
    int refused = 0;
    for (uint32_t id = 2; refused < 1100 && io.goaway_count == 0; id += 2) {
        peer::reserve_pushed_stream(protocol, id);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
        protocol.application_reject_push(id);
        refused += io.goaway_count == 0 ? 1 : 0;
    }
    EXPECT_EQ(refused, control_budget) << "the resets of pushed streams queued without a bound";
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(io.last_goaway_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
    EXPECT_EQ(resets_in(io.output), static_cast<std::size_t>(control_budget));
}

// --- a frame on an idle stream of either parity (RFC 9113 §5.1, §5.1.1, §6.4) --------------------------------------------

// RST_STREAM names no idle stream (RFC 9113 §6.4): one for an even id the server never promised is a connection
// PROTOCOL_ERROR, as one for an odd id past the last request already was. It was ignored.
TEST(HTTP2ClientProtocol, RstStreamOnAnIdleEvenStreamIsAConnectionError) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/rst-even");

    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(4);
    rst.payload.error_code = h2::ErrorCode::CANCEL;
    protocol.on(rst);

    EXPECT_FALSE(protocol.ok());
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
}

// PRIORITY is the frame an idle stream may receive (RFC 9113 §5.1): on an even id never promised it is read and
// changes nothing, before and after.
TEST(HTTP2ClientProtocol, PriorityOnAnIdleEvenStreamIsTolerated) {
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/priority-even");
    const std::size_t before = io.output.size();

    h2::Http2FrameData<h2::PriorityFrame> priority;
    priority.header.type = static_cast<uint8_t>(h2::FrameType::PRIORITY);
    priority.header.set_stream_id(4);
    protocol.on(priority);

    EXPECT_TRUE(protocol.ok());
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(io.stream_error_count, 0);
    EXPECT_EQ(io.output.size(), before) << "a PRIORITY on an idle stream was answered";
}

// Idle is "past the last stream promised", not "even": had the server promised streams 2 and 4 (the test seam says so;
// push is disabled and nothing else can), a frame on them once they have closed is a frame on a closed stream -- a
// HEADERS or a DATA is reset (STREAM_CLOSED, a reply counted while queued), a WINDOW_UPDATE or a RST_STREAM crossing
// the close is ignored (RFC 9113 §6.9, §5.1) -- and the connection lives on. Stream 6 is the first idle one: a HEADERS
// on it is the connection error.
TEST(HTTP2ClientProtocol, AFrameOnAClosedEvenStreamIsNotOneOnAnIdleStream) {
    using peer = h2::ProtocolTestPeer<h2::ClientHttp2Protocol<Http2ClientFakeIO>>;
    Http2ClientFakeIO                          io;
    h2::ClientHttp2Protocol<Http2ClientFakeIO> protocol(io);
    open_stream_one(protocol, 1, "/closed-even");
    peer::set_last_promised_stream_id(protocol, 4);
    const std::size_t before = io.output.size();

    protocol.on(make_headers_frame(4, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    protocol.on(make_data_frame(2, 0, "late"));
    protocol.on(make_window_update_frame(4, 100));
    h2::Http2FrameData<h2::RstStreamFrame> rst;
    rst.header.type = static_cast<uint8_t>(h2::FrameType::RST_STREAM);
    rst.header.set_stream_id(2);
    rst.payload.error_code = h2::ErrorCode::CANCEL;
    protocol.on(rst);
    EXPECT_TRUE(protocol.ok()) << "a frame on a closed even stream was read as one on an idle stream";
    EXPECT_EQ(io.goaway_count, 0);
    EXPECT_EQ(count_frames_from(io.output, h2::FrameType::RST_STREAM, before), 2u) << "the HEADERS and the DATA each draw a reset";

    protocol.on(make_headers_frame(6, h2::FLAG_END_HEADERS, {{":status", "200"}}));
    EXPECT_FALSE(protocol.ok()) << "stream 6, past the last promised, was not read as idle";
    ASSERT_TRUE(protocol.get_last_error_code().has_value());
    EXPECT_EQ(*protocol.get_last_error_code(), h2::ErrorCode::PROTOCOL_ERROR);
    EXPECT_EQ(io.goaway_count, 1);
    EXPECT_EQ(count_frames_from(io.output, h2::FrameType::RST_STREAM, before), 2u) << "the idle stream was reset";
}

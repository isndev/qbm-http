/**
 * @file qbm/http/tests/unit/http2/http2-server-stream.cpp
 * @brief `ServerHttp2Protocol`'s streamed response (Huly QB-86), frame by frame over the socket-less harness.
 *
 * The session's hooks (2/http2.h) sit on five protocol calls: `begin_streamed_response()` sends the HEADERS without
 * END_STREAM, `write_streamed_body()` sends what the windows allow as DATA frames of at most the peer's frame size and
 * keeps the rest, `end_streamed_response()` sends END_STREAM -- on the last DATA frame, an empty one, or the trailer
 * section's HEADERS -- once the last byte left, `abandon_streamed_response()` resets the stream, and
 * `streamed_body_pending()` is what the windows hold back. Each decision has its witness here, on the bytes the
 * protocol emits, with the client's SETTINGS and WINDOW_UPDATEs chosen by the test; the wire over a real TLS
 * connection is `system/http2/http2-response-stream.cpp`'s.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <cstdint>
#include <algorithm>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "../../shared/http2_fake_io.h"

using namespace qb::http::test;
using qb::protocol::http2::ErrorCode;
using qb::protocol::http2::FrameType;
using ServerProtocol = qb::protocol::http2::ServerHttp2Protocol<Http2FakeIO>;

using namespace std::chrono_literals;

namespace http2_server_stream_test {

constexpr uint8_t  END_STREAM                    = qb::protocol::http2::FLAG_END_STREAM;
constexpr uint8_t  END_HEADERS                   = qb::protocol::http2::FLAG_END_HEADERS;
constexpr uint16_t SETTINGS_INITIAL_WINDOW_SIZE  = 0x4;
constexpr uint16_t SETTINGS_MAX_HEADER_LIST_SIZE = 0x6;

/// A server protocol past its handshake, the client's SETTINGS as the test wants them, its output cleared.
struct Harness {
    Http2FakeIO    io;
    ServerProtocol protocol{io};
    uint32_t       next_stream_id = 1;

    explicit Harness(std::vector<std::pair<uint16_t, uint32_t>> const &settings = {}) {
        push_preface(io);
        push_frame(io, FrameType::SETTINGS, 0, 0, make_settings_payload(settings));
        drive(protocol, io);
        EXPECT_TRUE(protocol.ok());
        io.output.reset();
    }

    /// A request on a fresh stream: HEADERS with END_STREAM; the protocol dispatches it to the io.
    uint32_t
    open(std::string const &path = "/", std::string const &method = "GET") {
        const uint32_t stream_id = next_stream_id;
        next_stream_id += 2;
        std::vector<qb::protocol::hpack::HeaderField> fields = {
            {":method", method}, {":scheme", "https"}, {":authority", "example.test"}, {":path", path}
        };
        push_frame(io, FrameType::HEADERS, END_HEADERS | END_STREAM, stream_id, encode_hpack_headers(fields));
        drive(protocol, io);
        return stream_id;
    }

    [[nodiscard]] std::vector<EmittedFrame>
    frames() const {
        return parse_emitted_frames(io.output);
    }
    [[nodiscard]] std::string
    payload(EmittedFrame const &frame) const {
        const auto bytes = emitted_payload(io.output, frame);
        return std::string(bytes.begin(), bytes.end());
    }
    [[nodiscard]] std::vector<qb::protocol::hpack::HeaderField>
    decode(EmittedFrame const &frame) {
        std::vector<qb::protocol::hpack::HeaderField> fields;
        bool                                          incomplete = false;
        EXPECT_TRUE(_decoder.decode(emitted_payload(io.output, frame), fields, incomplete));
        return fields;
    }
    void
    clear() {
        io.output.reset();
    }
    void
    window_update(uint32_t stream_id, uint32_t increment) {
        push_frame(io, FrameType::WINDOW_UPDATE, 0, stream_id, make_window_update_payload(increment));
        drive(protocol, io);
    }

private:
    qb::protocol::hpack::Decoder _decoder;
};

qb::http::Response
ok_response() {
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("content-type", "text/plain");
    return response;
}

[[nodiscard]] std::string
field(std::vector<qb::protocol::hpack::HeaderField> const &fields, std::string const &name) {
    for (auto const &f : fields)
        if (f.name == name)
            return f.value;
    return {};
}

TEST(Http2ServerStream, TheHeadLeavesAtOnceWithoutEndStream) {
    Harness    h;
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.can_begin_streamed_response(id));
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), /*head_only=*/false));
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::HEADERS);
    EXPECT_EQ(frames[0].stream_id, id);
    EXPECT_EQ(frames[0].flags, END_HEADERS) << "no END_STREAM: the body follows";
    const auto fields = h.decode(frames[0]);
    EXPECT_EQ(field(fields, ":status"), "200");
    EXPECT_EQ(field(fields, "content-type"), "text/plain");
    EXPECT_TRUE(h.protocol.is_streaming_response(id));
    EXPECT_FALSE(h.protocol.can_begin_streamed_response(id)) << "one streamed response per stream";
    EXPECT_FALSE(h.protocol.begin_streamed_response(id, ok_response(), false));
    EXPECT_FALSE(h.protocol.is_stream_closed(id)) << "a streamed stream is open until its END_STREAM";
}

TEST(Http2ServerStream, APieceGoesAsDataFramesOfAtMostThePeerFrameSize) {
    Harness    h;
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    h.clear();
    const std::string piece(40000, 'x'); // under the 65535 windows, over two 16384 frames
    ASSERT_TRUE(h.protocol.write_streamed_body(id, piece));
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 3u) << "16384 + 16384 + 7232: split at the peer's frame size, never refused";
    EXPECT_EQ(frames[0].payload_length, 16384u);
    EXPECT_EQ(frames[1].payload_length, 16384u);
    EXPECT_EQ(frames[2].payload_length, 7232u);
    for (auto const &f : frames) {
        EXPECT_EQ(f.type, FrameType::DATA);
        EXPECT_EQ(f.flags, 0) << "no END_STREAM before end_streamed_response()";
    }
    EXPECT_EQ(h.protocol.streamed_body_pending(id), 0u);
    EXPECT_EQ(h.payload(frames[2]), std::string(7232, 'x'));
}

TEST(Http2ServerStream, TheStreamWindowHoldsThePiecesBackAndAWindowUpdateLetsThemGo) {
    Harness    h({{SETTINGS_INITIAL_WINDOW_SIZE, 1000}});
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    h.clear();
    ASSERT_TRUE(h.protocol.write_streamed_body(id, std::string(2500, 'a')));
    auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].payload_length, 1000u) << "the stream window: 1000 of 2500";
    EXPECT_EQ(h.protocol.streamed_body_pending(id), 1500u);
    h.clear();
    h.window_update(id, 1000);
    frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].payload_length, 1000u) << "a WINDOW_UPDATE sends what it allows, by itself";
    EXPECT_EQ(h.protocol.streamed_body_pending(id), 500u);
    h.clear();
    ASSERT_TRUE(h.protocol.end_streamed_response(id, nullptr));
    EXPECT_TRUE(h.frames().empty()) << "END_STREAM waits behind the 500 bytes the window still holds";
    EXPECT_TRUE(h.protocol.is_streaming_response(id));
    h.window_update(id, 1000);
    frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].payload_length, 500u);
    EXPECT_EQ(frames[0].flags, END_STREAM) << "the last piece carries END_STREAM";
    EXPECT_EQ(h.protocol.streamed_body_pending(id), 0u);
    EXPECT_TRUE(h.protocol.is_stream_closed(id)) << "the client's END_STREAM came with its HEADERS: the stream is closed";
    EXPECT_FALSE(h.protocol.write_streamed_body(id, "late")) << "nothing after the end";
}

TEST(Http2ServerStream, NothingIsTakenBetweenEndAndTheEndStreamTheWindowHoldsBack) {
    // end() ran while the window still holds pieces: the END_STREAM waits with them, and a write that comes in that
    // gap is refused -- the stream is ended for its producer, whatever the peer has read so far.
    Harness    h({{SETTINGS_INITIAL_WINDOW_SIZE, 100}});
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    ASSERT_TRUE(h.protocol.write_streamed_body(id, std::string(300, 'e')));
    EXPECT_EQ(h.protocol.streamed_body_pending(id), 200u);
    ASSERT_TRUE(h.protocol.end_streamed_response(id, nullptr));
    EXPECT_TRUE(h.protocol.is_streaming_response(id)) << "ended, not over: 200 bytes and the END_STREAM wait for the window";
    EXPECT_FALSE(h.protocol.write_streamed_body(id, "late")) << "nothing after end(), even while the window holds the tail";
    EXPECT_EQ(h.protocol.streamed_body_pending(id), 200u) << "the refused piece left the held bytes as they were";
    h.clear();
    h.window_update(id, 1000);
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].payload_length, 200u);
    EXPECT_EQ(frames[0].flags, END_STREAM) << "the tail and the end, nothing of the late piece";
    EXPECT_FALSE(h.protocol.is_streaming_response(id));
}

TEST(Http2ServerStream, TheConnectionWindowHoldsEveryStreamBack) {
    Harness    h;
    const auto first  = h.open("/a");
    const auto second = h.open("/b");
    ASSERT_TRUE(h.protocol.begin_streamed_response(first, ok_response(), false));
    ASSERT_TRUE(h.protocol.begin_streamed_response(second, ok_response(), false));
    h.clear();
    ASSERT_TRUE(h.protocol.write_streamed_body(first, std::string(65535, 'a'))); // the whole connection window
    ASSERT_TRUE(h.protocol.write_streamed_body(second, std::string(10, 'b')));
    EXPECT_EQ(h.protocol.streamed_body_pending(first), 0u);
    EXPECT_EQ(h.protocol.streamed_body_pending(second), 10u) << "the connection window is spent: the second stream waits";
    h.clear();
    h.window_update(0, 10); // the connection's window
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].stream_id, second);
    EXPECT_EQ(frames[0].payload_length, 10u);
    EXPECT_EQ(h.protocol.streamed_body_pending(second), 0u);
}

TEST(Http2ServerStream, TheSocketsWriteCapBoundsWhatEveryStreamFlushesTogether) {
    // Two streams hold pieces back for their windows; one WINDOW_UPDATE opens both. Each write() was admitted against
    // the cap with its own stream's pieces alone: flushed together they would pass it, and publish() disconnects past
    // it. The flush stops at the socket's room and the next write pass (resume_streamed_responses) sends the rest.
    Harness h;
    h.io.write_cap             = 200000; // the gate keeps a headroom free under it: 64 KiB, or a quarter of a small cap
    const std::size_t headroom = std::min(ServerProtocol::streamed_socket_headroom, h.io.write_cap / 4);
    const auto        first    = h.open("/a");
    const auto        second   = h.open("/b");
    ASSERT_TRUE(h.protocol.begin_streamed_response(first, ok_response(), false));
    ASSERT_TRUE(h.protocol.begin_streamed_response(second, ok_response(), false));
    h.clear();
    ASSERT_TRUE(h.protocol.write_streamed_body(first, std::string(65535, 'a'))); // the connection window, and the stream's
    const auto queued_by_first = h.io.output.size();
    EXPECT_EQ(h.protocol.streamed_body_pending(first), 0u);
    ASSERT_TRUE(h.protocol.write_streamed_body(second, std::string(50000, 'b'))); // held: the connection window is spent
    ASSERT_TRUE(h.protocol.write_streamed_body(first, std::string(50000, 'c')));  // held: the stream's window is spent
    EXPECT_EQ(h.protocol.streamed_body_pending(second), 50000u);
    EXPECT_EQ(h.protocol.streamed_body_pending(first), 50000u);
    EXPECT_FALSE(h.protocol.streams_wait_for_socket()) << "held for the windows, not the socket";
    h.window_update(first, 50000);
    h.window_update(second, 50000);
    h.window_update(0, 100000); // the connection's window opens for both
    EXPECT_LE(h.io.output.size(), 200000u - headroom) << "the flush stopped under the cap, the headroom kept";
    EXPECT_GT(h.io.output.size(), queued_by_first) << "and it did flush what fitted";
    const auto held = h.protocol.streamed_body_pending(first) + h.protocol.streamed_body_pending(second);
    EXPECT_GT(held, 0u) << "the rest waits for the socket";
    EXPECT_TRUE(h.protocol.streams_wait_for_socket());
    std::size_t left_before = 0;
    for (auto const &f : h.frames())
        if (f.type == FrameType::DATA)
            left_before += f.payload_length;
    EXPECT_EQ(left_before + held, 65535u + 100000u) << "every byte is either on the socket or held";
    h.clear();                              // the socket drained
    h.protocol.resume_streamed_responses(); // the session's write pass
    EXPECT_FALSE(h.protocol.streams_wait_for_socket());
    std::size_t left_after = 0;
    for (auto const &f : h.frames())
        if (f.type == FrameType::DATA)
            left_after += f.payload_length;
    EXPECT_EQ(left_after, held) << "the pieces the cap held back left on the next pass";
    EXPECT_EQ(h.protocol.streamed_body_pending(first), 0u);
    EXPECT_EQ(h.protocol.streamed_body_pending(second), 0u);
    const auto frames_after_resume = h.frames().size();
    h.protocol.resume_streamed_responses();
    EXPECT_EQ(h.frames().size(), frames_after_resume) << "a second pass with nothing waiting sends nothing";
}

TEST(Http2ServerStream, TrailersWaitForTheSocketsRoomUnencodedAndLeaveWholeOnTheNextPass) {
    // The trailer section is HPACK-encoded only when it leaves: an encoding advances the encoder's dynamic table, so a
    // block encoded and held back would leave the peer's table behind on the retry. The harness decodes with a peer's
    // table of its own: a second encoding of the same fields would come out as indices it never received.
    Harness    h;
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    h.clear();
    h.io.write_cap = 100; // a quarter kept: 75 of room -- a 17-byte piece and its header fit, the section's bound (55) then does not
    ASSERT_TRUE(h.protocol.write_streamed_body(id, std::string(17, 'p')));
    EXPECT_EQ(h.protocol.streamed_body_pending(id), 0u);
    auto final_response = ok_response();
    final_response.trailers().set_header("x-checksum", "beef");
    ASSERT_TRUE(h.protocol.end_streamed_response(id, &final_response));
    auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u) << "the piece left; the section waits";
    EXPECT_EQ(frames[0].type, FrameType::DATA);
    EXPECT_EQ(frames[0].flags, 0u) << "no END_STREAM on the last piece: the trailers end the stream";
    EXPECT_TRUE(h.protocol.streams_wait_for_socket());
    EXPECT_TRUE(h.protocol.is_streaming_response(id)) << "not over: the section has not left";
    h.clear(); // the socket drained
    h.io.write_cap = static_cast<std::size_t>(-1);
    h.protocol.resume_streamed_responses(); // the session's write pass
    frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::HEADERS);
    EXPECT_EQ(frames[0].flags & END_STREAM, END_STREAM);
    const auto fields = h.decode(frames[0]);
    EXPECT_EQ(field(fields, "x-checksum"), "beef") << "decoded against a table that saw exactly one encoding";
    EXPECT_FALSE(h.protocol.is_streaming_response(id));
    EXPECT_FALSE(h.protocol.streams_wait_for_socket());
}

TEST(Http2ServerStream, TheIdleSweepResetsAStreamThatSentNothingAndSparesOneThatDid) {
    // The connection's idle sweep (cleanup_idle_streams, 30 s in the session) counts a stream's frames, not its window:
    // a streamed response that writes nothing is reset CANCEL like any idle stream -- the heartbeat's reason.
    Harness    h;
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    h.clear();
    std::this_thread::sleep_for(5ms);
    ASSERT_TRUE(h.protocol.write_streamed_body(id, "beat"));
    EXPECT_EQ(h.protocol.cleanup_idle_streams(1ms, 1s), 0u) << "a frame left since the last sweep: spared";
    EXPECT_TRUE(h.protocol.is_streaming_response(id));
    h.clear();
    std::this_thread::sleep_for(5ms);
    EXPECT_EQ(h.protocol.cleanup_idle_streams(1ms, 1s), 1u) << "nothing left for longer than the idle bound: reset";
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::RST_STREAM);
    EXPECT_EQ(h.io.last_stream_error, ErrorCode::CANCEL);
    EXPECT_FALSE(h.protocol.is_streaming_response(id));
    EXPECT_FALSE(h.protocol.write_streamed_body(id, "late"));
}

TEST(Http2ServerStream, EndWithNothingLeftSendsAnEmptyDataFrameWithEndStream) {
    Harness    h;
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    ASSERT_TRUE(h.protocol.write_streamed_body(id, "all of it"));
    h.clear();
    ASSERT_TRUE(h.protocol.end_streamed_response(id, nullptr));
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::DATA);
    EXPECT_EQ(frames[0].payload_length, 0u);
    EXPECT_EQ(frames[0].flags, END_STREAM);
    EXPECT_FALSE(h.protocol.is_streaming_response(id));
    EXPECT_FALSE(h.protocol.end_streamed_response(id, nullptr)) << "ended once";
}

TEST(Http2ServerStream, TrailersSetAtTheEndLeaveAsAHeadersFrameWithEndStream) {
    Harness    h;
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    ASSERT_TRUE(h.protocol.write_streamed_body(id, "body"));
    h.clear();
    auto final_response = ok_response();
    final_response.trailers().set_header("x-checksum", "cafe"); // set by the producer after the head left
    ASSERT_TRUE(h.protocol.end_streamed_response(id, &final_response));
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u) << "no empty DATA frame: the trailer section ends the stream";
    EXPECT_EQ(frames[0].type, FrameType::HEADERS);
    EXPECT_EQ(frames[0].flags, END_HEADERS | END_STREAM);
    const auto fields = h.decode(frames[0]);
    EXPECT_EQ(field(fields, "x-checksum"), "cafe");
    EXPECT_TRUE(h.protocol.is_stream_closed(id));
}

TEST(Http2ServerStream, TrailersWaitBehindThePiecesTheWindowHoldsBack) {
    Harness    h({{SETTINGS_INITIAL_WINDOW_SIZE, 4}});
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    ASSERT_TRUE(h.protocol.write_streamed_body(id, "12345678"));
    h.clear();
    auto final_response = ok_response();
    final_response.trailers().set_header("x-sum", "36");
    ASSERT_TRUE(h.protocol.end_streamed_response(id, &final_response));
    EXPECT_TRUE(h.frames().empty()) << "four bytes still wait for the window: no trailers yet";
    h.window_update(id, 4);
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 2u);
    EXPECT_EQ(frames[0].type, FrameType::DATA);
    EXPECT_EQ(frames[0].flags, 0) << "the last DATA frame does not end the stream when trailers follow";
    EXPECT_EQ(frames[1].type, FrameType::HEADERS);
    EXPECT_EQ(frames[1].flags, END_HEADERS | END_STREAM);
}

TEST(Http2ServerStream, AForbiddenTrailerFieldAtTheEndResetsTheStream) {
    Harness    h;
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    h.clear();
    auto final_response = ok_response();
    final_response.trailers().set_header("content-length", "4"); // a framing field: never in a trailer section
    EXPECT_FALSE(h.protocol.end_streamed_response(id, &final_response));
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::RST_STREAM);
    EXPECT_EQ(h.io.stream_error_count, 1);
    EXPECT_EQ(h.io.last_stream_error, ErrorCode::INTERNAL_ERROR);
    EXPECT_TRUE(h.protocol.is_stream_closed(id));
}

TEST(Http2ServerStream, AHeadRequestGetsItsHeadersWithEndStreamAndNoStream) {
    Harness    h;
    const auto id = h.open("/stream", "HEAD");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), /*head_only=*/true));
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::HEADERS);
    EXPECT_EQ(frames[0].flags, END_HEADERS | END_STREAM) << "a HEAD's response is whole at its head";
    EXPECT_FALSE(h.protocol.is_streaming_response(id));
    EXPECT_FALSE(h.protocol.write_streamed_body(id, "never")) << "no body on a HEAD's stream";
    EXPECT_TRUE(h.protocol.is_stream_closed(id));
}

TEST(Http2ServerStream, AbandonResetsTheStreamAndDropsThePiecesItHeld) {
    Harness    h({{SETTINGS_INITIAL_WINDOW_SIZE, 100}});
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    ASSERT_TRUE(h.protocol.write_streamed_body(id, std::string(300, 'q')));
    EXPECT_EQ(h.protocol.streamed_body_pending(id), 200u);
    h.clear();
    EXPECT_TRUE(h.protocol.abandon_streamed_response(id));
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::RST_STREAM);
    EXPECT_EQ(h.io.last_stream_error, ErrorCode::INTERNAL_ERROR);
    EXPECT_EQ(h.protocol.streamed_body_pending(id), 0u);
    EXPECT_TRUE(h.protocol.is_stream_closed(id));
    h.clear();
    h.window_update(id, 1000);
    // The RST_STREAM reclaims the stream and its pieces with it: a later WINDOW_UPDATE finds no stream to flush.
    EXPECT_TRUE(h.frames().empty()) << "nothing of the dropped pieces leaves on a later WINDOW_UPDATE";
    EXPECT_FALSE(h.protocol.is_streaming_response(id)) << "the stream is gone, not merely emptied";
    EXPECT_FALSE(h.protocol.abandon_streamed_response(id)) << "once";
}

TEST(Http2ServerStream, APeerResetEndsTheStreamAndRefusesTheNextPiece) {
    Harness    h;
    const auto id = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    ASSERT_TRUE(h.protocol.write_streamed_body(id, "first"));
    h.clear();
    push_frame(h.io, FrameType::RST_STREAM, 0, id, {0, 0, 0, 8}); // CANCEL
    drive(h.protocol, h.io);
    EXPECT_FALSE(h.protocol.write_streamed_body(id, "second"));
    EXPECT_FALSE(h.protocol.end_streamed_response(id, nullptr));
    EXPECT_EQ(h.protocol.streamed_body_pending(id), 0u);
    EXPECT_TRUE(h.frames().empty()) << "nothing is sent on a stream the peer reset";
    EXPECT_FALSE(h.protocol.abandon_streamed_response(id)) << "no RST_STREAM back at the peer's";
}

TEST(Http2ServerStream, ADeclaredContentLengthIsComparedToNoBody) {
    Harness    h;
    const auto id       = h.open("/stream");
    auto       response = ok_response();
    response.set_header("content-length", "10");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, response, false)) << "the stream counts the pieces; the head is not refused";
    const auto fields = h.decode(h.frames()[0]);
    EXPECT_EQ(field(fields, "content-length"), "10");
}

TEST(Http2ServerStream, AForbiddenHeaderRefusesTheHeadAndResetsTheStream) {
    Harness    h;
    const auto id       = h.open("/stream");
    auto       response = ok_response();
    response.set_header("transfer-encoding", "chunked"); // hop-by-hop: never on HTTP/2
    EXPECT_FALSE(h.protocol.begin_streamed_response(id, response, false));
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::RST_STREAM);
    EXPECT_EQ(h.io.last_stream_error, ErrorCode::INTERNAL_ERROR);
    EXPECT_FALSE(h.protocol.is_streaming_response(id));
}

TEST(Http2ServerStream, AStreamedStreamHoldsItsConcurrencySlotUntilItsEndStream) {
    Harness h;
    // The server allows 50 concurrent streams: 49 requests left unanswered and one streamed response fill them.
    std::vector<uint32_t> held;
    for (int i = 0; i < 49; ++i)
        held.push_back(h.open("/held"));
    const auto streamed = h.open("/stream");
    ASSERT_TRUE(h.protocol.begin_streamed_response(streamed, ok_response(), false));
    ASSERT_TRUE(h.protocol.write_streamed_body(streamed, "piece"));
    h.clear();
    const auto refused = h.open("/one-too-many");
    auto       frames  = h.frames();
    ASSERT_EQ(frames.size(), 1u) << "the 51st stream is refused while the streamed one is open";
    EXPECT_EQ(frames[0].type, FrameType::RST_STREAM);
    EXPECT_EQ(frames[0].stream_id, refused);
    const auto code = emitted_payload(h.io.output, frames[0]);
    ASSERT_EQ(code.size(), 4u);
    EXPECT_EQ(code[3], static_cast<uint8_t>(ErrorCode::REFUSED_STREAM))
        << "REFUSED_STREAM, on the frame: a stream never opened raises no event";
    h.clear();
    ASSERT_TRUE(h.protocol.end_streamed_response(streamed, nullptr)); // END_STREAM: the slot is free
    h.clear();
    const auto served = h.open("/room-again");
    EXPECT_TRUE(h.frames().empty()) << "accepted: no RST_STREAM for the stream opened after the streamed one ended";
    EXPECT_EQ(h.io.last_request_stream_id, served) << "and dispatched";
}

TEST(Http2ServerStream, TheWholeResponsePathIsUnchangedBesideAStreamedOne) {
    Harness    h;
    const auto streamed = h.open("/stream");
    const auto whole    = h.open("/whole");
    ASSERT_TRUE(h.protocol.begin_streamed_response(streamed, ok_response(), false));
    h.clear();
    auto response   = ok_response();
    response.body() = "whole body";
    ASSERT_TRUE(h.protocol.send_response(whole, response));
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 2u);
    EXPECT_EQ(frames[0].type, FrameType::HEADERS);
    EXPECT_EQ(frames[1].type, FrameType::DATA);
    EXPECT_EQ(frames[1].flags, END_STREAM);
    EXPECT_EQ(h.payload(frames[1]), "whole body");
    EXPECT_TRUE(h.protocol.is_stream_closed(whole));
    EXPECT_TRUE(h.protocol.is_streaming_response(streamed)) << "the other stream is untouched";
}

// A streamed response's trailer section is held to the client's SETTINGS_MAX_HEADER_LIST_SIZE as a buffered one's is
// (Huly QB-1240): at the end, by the bound in force -- past it the stream is reset, nothing encoded, so the HPACK table
// stays in step -- and at the bound exactly the section leaves whole.
TEST(Http2ServerStream, ATrailerSectionPastTheClientsBoundAtTheEndResetsTheStreamAndEncodesNothing) {
    Harness    h({{SETTINGS_MAX_HEADER_LIST_SIZE, 100}});
    const auto past = h.open("/past");
    ASSERT_TRUE(h.protocol.begin_streamed_response(past, ok_response(), false)); // :status (42) and content-type (54): 96 of 100
    h.clear();
    auto final_response = ok_response();
    final_response.trailers().set_header("x-c", std::string(66, 'c')); // 3 + 66 + 32 = 101: a byte past the bound
    EXPECT_FALSE(h.protocol.end_streamed_response(past, &final_response));
    auto frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::RST_STREAM);
    EXPECT_EQ(h.io.stream_error_count, 1);
    EXPECT_EQ(h.io.last_stream_error, ErrorCode::INTERNAL_ERROR);
    EXPECT_TRUE(h.protocol.is_stream_closed(past));

    const auto at = h.open("/at");
    ASSERT_TRUE(h.protocol.begin_streamed_response(at, ok_response(), false));
    h.clear();
    final_response.trailers().set_header("x-c", std::string(65, 'c')); // exactly the bound
    EXPECT_TRUE(h.protocol.end_streamed_response(at, &final_response));
    frames = h.frames();
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].type, FrameType::HEADERS);
    EXPECT_TRUE(frames[0].flags & END_STREAM);
    EXPECT_EQ(field(h.decode(frames[0]), "x-c"), std::string(65, 'c')) << "the first section was never encoded: this one decodes";
    EXPECT_TRUE(h.protocol.is_stream_closed(at));
    EXPECT_TRUE(h.protocol.ok());
}

// The section is judged again when it leaves, by the bound then in force (Huly QB-1240): pieces the window holds back
// keep the section waiting, and a bound the client lowers meanwhile refuses it -- the stream reset after the DATA, no
// HEADERS encoded.
TEST(Http2ServerStream, AStreamedTrailerSectionIsJudgedByTheBoundInForceWhenItLeaves) {
    Harness    h({{SETTINGS_INITIAL_WINDOW_SIZE, 0}});
    const auto id = h.open("/waits");
    ASSERT_TRUE(h.protocol.begin_streamed_response(id, ok_response(), false));
    ASSERT_TRUE(h.protocol.write_streamed_body(id, "abc"));
    auto final_response = ok_response();
    final_response.trailers().set_header("x-c", std::string(20, 'c')); // 3 + 20 + 32 = 55
    ASSERT_TRUE(h.protocol.end_streamed_response(id, &final_response));
    EXPECT_EQ(h.protocol.streamed_body_pending(id), 3u) << "the body waits for credit, the section behind it";
    h.clear();
    push_frame(h.io, FrameType::SETTINGS, 0, 0, make_settings_payload({{SETTINGS_MAX_HEADER_LIST_SIZE, 50}}));
    drive(h.protocol, h.io);
    h.clear();
    h.window_update(id, 100);
    const auto frames = h.frames();
    ASSERT_EQ(frames.size(), 2u);
    EXPECT_EQ(frames[0].type, FrameType::DATA);
    EXPECT_EQ(h.payload(frames[0]), "abc");
    EXPECT_FALSE(frames[0].flags & END_STREAM);
    EXPECT_EQ(frames[1].type, FrameType::RST_STREAM);
    EXPECT_EQ(h.io.last_stream_error, ErrorCode::INTERNAL_ERROR);
    EXPECT_TRUE(h.protocol.is_stream_closed(id));
}

} // namespace http2_server_stream_test

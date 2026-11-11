/**
 * @file qbm/http/tests/unit/http2/http2-client-huge-body.cpp
 * @brief The HTTP/2 client's reset of a response body past MAX_BODY_SIZE, and what crosses it (Huly QB-1270): 100 MiB
 *        through the socket-less harness, so a binary of its own, labelled huge-body (`ctest -LE huge-body` drops it).
 *
 * A server streams a body past MAX_BODY_SIZE on stream 1 while the client's request on stream 3 waits. The frame that
 * passes the limit is also the one that reaches the connection's WINDOW_UPDATE threshold: the client gives the window
 * back with its reset (it waited for the next DATA read). The DATA the server sent behind it closed the connection, the
 * request on stream 3 with it: it is discarded, counted against the connection window and given back (RFC 9113 §5.1,
 * §6.9), and stream 3 is answered. The other ways of being reset are cases of http2-client-protocol.cpp.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <cstddef>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "../../shared/http2_fake_io.h"

namespace http2_client_huge_body_test {

namespace h2          = qb::protocol::http2;
namespace fake        = qb::http::test;
using client_protocol = h2::ClientHttp2Protocol<fake::Http2ClientFakeIO>;

constexpr std::size_t max_frame = 16384;

void
data(client_protocol &protocol, fake::Http2ClientFakeIO &io, uint32_t sid, std::size_t octets, uint8_t flags = 0) {
    fake::push_frame(io, h2::FrameType::DATA, flags, sid, std::vector<uint8_t>(octets, static_cast<uint8_t>('d')));
    fake::drive(protocol, io);
}

/// The sum of the connection WINDOW_UPDATE increments the client wrote, the socket having taken them or not.
[[nodiscard]] uint64_t
connection_window_given_back(const fake::Http2ClientFakeIO &io) {
    const auto bytes = fake::written_and_queued(io);
    uint64_t   total = 0;
    for (const auto &f : fake::parse_emitted_frames(bytes)) {
        if (f.type == h2::FrameType::WINDOW_UPDATE && f.stream_id == 0) {
            const auto p = fake::emitted_payload(bytes, f);
            total += ((uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | p[3]) & 0x7FFFFFFFu;
        }
    }
    return total;
}

[[nodiscard]] std::size_t
resets_written(const fake::Http2ClientFakeIO &io) {
    std::size_t n = 0;
    for (const auto &f : fake::parse_emitted_frames(fake::written_and_queued(io))) {
        n += f.type == h2::FrameType::RST_STREAM ? 1u : 0u;
    }
    return n;
}

TEST(HTTP2ClientHugeBody, ADataCrossingTheResetOfABodyPastTheLimitIsDiscardedAndTheConnectionServesOn) {
    fake::Http2ClientFakeIO io;
    client_protocol         protocol(io);
    fake::socket_takes_everything(io);
    io.wire.reset();
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("https://example.test/large");
    ASSERT_TRUE(protocol.send_request(req, 1)); // stream 1
    req.uri() = qb::io::uri("https://example.test/other");
    ASSERT_TRUE(protocol.send_request(req, 2)); // stream 3
    fake::push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS, 1, fake::encode_hpack_headers({{":status", "200"}}));
    fake::drive(protocol, io);

    // 1 + 6400 x 16384 = MAX_BODY_SIZE + 1 octets; the first frame of one octet puts the connection's threshold (32767)
    // on every second frame after it, the 6400th of 16384 -- the one that passes the limit -- among them.
    static_assert(qb::http::protocol_limits::MAX_BODY_SIZE == 6400u * max_frame);
    data(protocol, io, 1, 1);
    uint64_t                   received = 1;
    const std::vector<uint8_t> frame(max_frame, static_cast<uint8_t>('b'));
    for (int i = 0; i < 6400 && io.stream_error_count == 0; ++i) {
        fake::push_frame(io, h2::FrameType::DATA, 0, 1, frame);
        fake::drive(protocol, io);
        received += max_frame;
    }
    ASSERT_EQ(io.stream_error_count, 1) << "the body past MAX_BODY_SIZE did not reset its stream";
    ASSERT_EQ(received, qb::http::protocol_limits::MAX_BODY_SIZE + 1);
    EXPECT_EQ(io.last_stream_error, h2::ErrorCode::ENHANCE_YOUR_CALM);
    EXPECT_EQ(connection_window_given_back(io), received)
        << "the octets of the frame the stream was reset for wait for a DATA that may never come";

    // What the server had sent behind it, before it read the reset: the rest of the body, its end.
    data(protocol, io, 1, max_frame / 2);
    data(protocol, io, 1, max_frame / 2, h2::FLAG_END_STREAM);
    received += max_frame;
    EXPECT_TRUE(protocol.ok()) << "a DATA the server sent before it read the reset closed the connection";
    EXPECT_EQ(io.goaway_count, 0);

    fake::push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS, 3, fake::encode_hpack_headers({{":status", "200"}}));
    fake::drive(protocol, io);
    data(protocol, io, 3, max_frame, h2::FLAG_END_STREAM);
    received += max_frame;
    EXPECT_TRUE(protocol.ok());
    ASSERT_EQ(io.response_count, 1) << "the other request of the connection was not answered";
    EXPECT_EQ(io.last_app_id, 2u);
    EXPECT_EQ(resets_written(io), 1u) << "the DATA crossing the reset was answered";
    EXPECT_EQ(connection_window_given_back(io), received) << "an octet the client discarded was lost to the connection window";
}

} // namespace http2_client_huge_body_test

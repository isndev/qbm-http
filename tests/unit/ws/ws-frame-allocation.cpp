/**
 * @file qbm/http/tests/unit/ws/ws-frame-allocation.cpp
 * @brief The WebSocket frame decoder allocates nothing per frame, and the frame buffer it reuses carries nothing
 *        from one frame to the next (Huly QB-1247).
 *
 * `onMessage()` built a local `ws::Message` for every frame, whose pipe allocated 4 KiB at construction and freed
 * it at the end of the frame -- one allocation and one free for a 16-byte text frame or an empty Ping. The frame's
 * payload lands in a buffer the protocol keeps now, reset between frames. The count is read with the replaced
 * global `operator new` of tests/shared/allocation_counter.h, never a timing; the second test checks what a
 * reused buffer could leak and runs under every preset.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include <qbm/http/ws.h>

#include "../../shared/allocation_counter.h" // AllocScope::count(), allocation_counter_is_live(): the replaced operator new

namespace ws_frame_allocation_test {

/// One masked client-to-server frame, FIN set, of @p opcode carrying @p payload (at most 125 octets here).
[[nodiscard]] std::vector<std::uint8_t>
masked_frame(std::uint8_t opcode, std::string_view payload) {
    const std::array<std::uint8_t, 4> mask{{0xAA, 0x55, 0x01, 0xFE}};
    std::vector<std::uint8_t>         out{static_cast<std::uint8_t>(0x80u | opcode), static_cast<std::uint8_t>(0x80u | payload.size())};
    out.insert(out.end(), mask.begin(), mask.end());
    for (std::size_t i = 0; i < payload.size(); ++i) {
        out.push_back(static_cast<std::uint8_t>(static_cast<std::uint8_t>(payload[i]) ^ mask[i & 3u]));
    }
    return out;
}

/// A socket-less server IO: the frames go into `input`, the Pongs come out of `output`, each message is kept.
struct ServerIO {
    using base_io_t                  = ServerIO;
    static constexpr bool has_server = true;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;
    std::size_t               messages = 0;
    std::string               last; ///< the last message's payload, copied only when `keep` is set
    bool                      keep = false;

    struct error {};

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    qb::allocator::pipe<char> &
    out() noexcept {
        return output;
    }
    template <typename T>
    ServerIO &
    operator<<(const T &msg) {
        output.put(msg);
        return *this;
    }
    void
    on(qb::protocol::ws_internal::event_message &&event) {
        ++messages;
        if (keep) {
            last.assign(event.data, event.size);
        }
    }
    void
    on(error &&) {}
};

using ServerProtocol = qb::protocol::ws_server<ServerIO>;

[[nodiscard]] qb::http::Request
upgrade_request() {
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("/");
    req.upgrade  = true;
    req.set_header("Upgrade", "websocket");
    req.set_header("Connection", "Upgrade");
    req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    req.set_header("Sec-WebSocket-Version", "13");
    return req;
}

/// Put @p frame in the input and decode every complete frame there.
void
feed(ServerProtocol &protocol, ServerIO &io, const std::vector<std::uint8_t> &frame) {
    std::memcpy(io.input.allocate_back(frame.size()), frame.data(), frame.size());
    std::size_t n;
    while ((n = protocol.getMessageSize()) > 0) {
        protocol.onMessage(n);
        io.input.free_front(n);
        if (!protocol.ok()) {
            break;
        }
    }
}

/// The allocations decoding @p frame costs, @p rounds times, once the buffers it reaches have grown: only the
/// decode is counted, never the copy into the input nor the reset of the output.
[[nodiscard]] std::size_t
allocations_per_round(ServerProtocol &protocol, ServerIO &io, const std::vector<std::uint8_t> &frame, int rounds) {
    for (int i = 0; i < 4; ++i) { // warm: the reassembly buffer, the output's Pong, the input
        feed(protocol, io, frame);
        io.output.reset();
    }
    std::size_t total = 0;
    for (int i = 0; i < rounds; ++i) {
        std::memcpy(io.input.allocate_back(frame.size()), frame.data(), frame.size());
        {
            AllocScope  scope;
            std::size_t n;
            while ((n = protocol.getMessageSize()) > 0) {
                protocol.onMessage(n);
                io.input.free_front(n);
            }
            total += AllocScope::count();
        }
        io.output.reset();
    }
    return total;
}

} // namespace ws_frame_allocation_test

// A 16-byte masked text frame, an empty Ping answered by a Pong, a full 125-octet Ping, an empty text frame: each
// cost one allocation (the local Message's 4 KiB pipe) and its free. None is made now, frame after frame.
TEST(WsFrameAllocation, ADecodedFrameAllocatesNothing) {
    if (!allocation_counter_is_live()) {
        GTEST_SKIP() << "the replaced operator new is not live under this sanitizer runtime";
    }
    using namespace ws_frame_allocation_test;
    const std::vector<std::pair<std::string, std::vector<std::uint8_t>>> frames{
        {"16-byte masked text", masked_frame(0x1u, "0123456789abcdef")},
        {"empty Ping, auto-Pong", masked_frame(0x9u, "")},
        {"125-octet Ping, auto-Pong", masked_frame(0x9u, std::string(125, 'p'))},
        {"empty text", masked_frame(0x1u, "")},
    };
    for (const auto &[label, frame] : frames) {
        SCOPED_TRACE(label);
        ServerIO       io;
        ServerProtocol protocol(io, upgrade_request());
        ASSERT_TRUE(protocol.ok());
        EXPECT_EQ(allocations_per_round(protocol, io, frame, 64), 0u) << "allocations in 64 decoded frames";
        EXPECT_TRUE(protocol.ok());
    }
}

// The reused buffer keeps the bytes of a longer frame past the end of a shorter one; none of them is read: each
// frame's payload, each Pong's, is exactly its own -- a 32-octet text, then a 16-octet one, an empty Ping, a 4-octet
// one, then an empty text.
TEST(WsFrameAllocation, TheReusedFrameBufferCarriesNothingFromOneFrameToTheNext) {
    using namespace ws_frame_allocation_test;
    ServerIO       io;
    ServerProtocol protocol(io, upgrade_request());
    ASSERT_TRUE(protocol.ok());
    io.keep = true;
    io.output.reset();

    feed(protocol, io, masked_frame(0x1u, std::string(32, 'L')));
    ASSERT_EQ(io.messages, 1u);
    EXPECT_EQ(io.last, std::string(32, 'L'));
    feed(protocol, io, masked_frame(0x1u, "short-frame-16oc"));
    ASSERT_EQ(io.messages, 2u);
    EXPECT_EQ(io.last, "short-frame-16oc");

    const auto pong_of = [&](std::string_view ping) {
        io.output.reset();
        feed(protocol, io, masked_frame(0x9u, ping));
        return std::string(io.output.cbegin(), io.output.size());
    };
    EXPECT_EQ(pong_of(""), std::string("\x8a\x00", 2)) << "an empty Ping's Pong carried bytes";
    EXPECT_EQ(pong_of("ping"), std::string("\x8a\x04ping", 6));

    feed(protocol, io, masked_frame(0x1u, ""));
    ASSERT_EQ(io.messages, 3u);
    EXPECT_EQ(io.last, "") << "an empty text frame read the last frame's bytes";
    EXPECT_TRUE(protocol.ok());
}

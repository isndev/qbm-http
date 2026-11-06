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
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <qbm/http/ws.h>

#include "../../shared/allocation_counter.h" // AllocScope::count(), allocation_counter_is_live(): the replaced operator new

namespace ws_frame_allocation_test {

/// One frame, FIN set, of @p opcode carrying @p payload: masked (client to server) or not (server to client), its
/// length in 7, 16 or 64 bits as RFC 6455 section 5.2 requires.
[[nodiscard]] std::vector<std::uint8_t>
frame_of(std::uint8_t opcode, std::string_view payload, bool masked) {
    const std::array<std::uint8_t, 4> mask{{0xAA, 0x55, 0x01, 0xFE}};
    const std::uint8_t                mask_bit = masked ? 0x80u : 0x00u;
    std::vector<std::uint8_t>         out{static_cast<std::uint8_t>(0x80u | opcode)};
    if (payload.size() < 126u) {
        out.push_back(static_cast<std::uint8_t>(mask_bit | payload.size()));
    } else if (payload.size() <= 0xFFFFu) {
        out.push_back(static_cast<std::uint8_t>(mask_bit | 126u));
        for (int shift = 8; shift >= 0; shift -= 8) {
            out.push_back(static_cast<std::uint8_t>((payload.size() >> shift) & 0xFFu));
        }
    } else {
        out.push_back(static_cast<std::uint8_t>(mask_bit | 127u));
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.push_back(static_cast<std::uint8_t>((static_cast<std::uint64_t>(payload.size()) >> shift) & 0xFFu));
        }
    }
    if (masked) {
        out.insert(out.end(), mask.begin(), mask.end());
    }
    for (std::size_t i = 0; i < payload.size(); ++i) {
        out.push_back(static_cast<std::uint8_t>(static_cast<std::uint8_t>(payload[i]) ^ (masked ? mask[i & 3u] : 0u)));
    }
    return out;
}

/// One masked client-to-server frame.
[[nodiscard]] std::vector<std::uint8_t>
masked_frame(std::uint8_t opcode, std::string_view payload) {
    return frame_of(opcode, payload, true);
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
/// decode is counted, never the copy into the input nor the reset of the output. Each round must decode its frame
/// and answer a Ping with its Pong, or a zero would prove nothing.
[[nodiscard]] std::size_t
allocations_per_round(ServerProtocol &protocol, ServerIO &io, const std::vector<std::uint8_t> &frame, int rounds) {
    const bool ping = (frame[0] & 0x0Fu) == 0x9u;
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
        EXPECT_TRUE(io.input.empty()) << "round " << i << ": the frame was not decoded";
        if (ping) {
            EXPECT_EQ(io.output.size(), frame.size() - 4u) << "round " << i << ": no Pong (an unmasked copy of the Ping)";
        }
        io.output.reset();
    }
    return total;
}

/// The allocations decoding @p frame costs once.
[[nodiscard]] std::size_t
allocations_of(ServerProtocol &protocol, ServerIO &io, const std::vector<std::uint8_t> &frame) {
    std::memcpy(io.input.allocate_back(frame.size()), frame.data(), frame.size());
    AllocScope  scope;
    std::size_t n;
    while ((n = protocol.getMessageSize()) > 0) {
        protocol.onMessage(n);
        io.input.free_front(n);
    }
    return AllocScope::count();
}

/// A socket-less client IO: the server's frames go into `input`, the client's Pongs come out of `output`. `steal`
/// makes the Ping handler move the frame's payload buffer out, as an application may.
struct ClientIO {
    using base_io_t                  = ClientIO;
    static constexpr bool has_server = false;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;
    std::vector<std::string>  messages;
    bool                      steal = false;

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
    ClientIO &
    operator<<(const T &msg) {
        output.put(msg);
        return *this;
    }
    void
    on(qb::protocol::ws_internal::event_message &&event) {
        messages.emplace_back(event.data, event.size);
    }
    void
    on(qb::protocol::ws_internal::event_ping &&event) {
        if (steal) {
            auto taken = std::move(event.ws._data);
            (void) taken;
        }
    }
    void
    on(error &&) {}
};

using ClientProtocol = qb::protocol::ws_client<ClientIO>;

/// The server's 101 to the request of upgrade_request() (RFC 6455 section 1.3's example key).
[[nodiscard]] qb::http::Response
upgrade_response() {
    qb::http::Response res;
    res.status() = qb::http::status::SWITCHING_PROTOCOLS;
    res.upgrade  = true;
    res.set_header("Upgrade", "websocket");
    res.set_header("Connection", "Upgrade");
    res.set_header("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    return res;
}

/// Put @p frame in a client's input and decode every complete frame there.
void
feed_client(ClientProtocol &protocol, ClientIO &io, const std::vector<std::uint8_t> &frame) {
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

// The kept buffer is bounded: a frame that grew it past 64 KiB frees it at its end, so a connection does not hold a
// second copy of its largest message between frames -- the next frame allocates once, the one after nothing. A frame
// within 64 KiB keeps it.
TEST(WsFrameAllocation, AFramePast64KiBLeavesNoBufferBehind) {
    if (!allocation_counter_is_live()) {
        GTEST_SKIP() << "the replaced operator new is not live under this sanitizer runtime";
    }
    using namespace ws_frame_allocation_test;
    const auto small = masked_frame(0x1u, "0123456789abcdef");
    for (const auto &[size, kept] : std::vector<std::pair<std::size_t, bool>>{{60000, true}, {100000, false}}) {
        SCOPED_TRACE(size);
        ServerIO       io;
        ServerProtocol protocol(io, upgrade_request());
        ASSERT_TRUE(protocol.ok());
        (void) allocations_per_round(protocol, io, small, 1);
        const auto large = masked_frame(0x2u, std::string(size, 'b'));
        (void) allocations_of(protocol, io, large);
        (void) allocations_of(protocol, io, large); // the reassembly buffer has grown to it too
        EXPECT_EQ(allocations_of(protocol, io, small), kept ? 0u : 1u) << "the frame after a frame of " << size << " octets";
        EXPECT_EQ(allocations_of(protocol, io, small), 0u) << "and the one after it";
        EXPECT_EQ(io.messages, 9u) << "4 warming, 1 counted, 2 large, 2 after";
        EXPECT_TRUE(protocol.ok());
    }
}

// The client side: the server's frames are unmasked, and the buffer that carried a Ping is the one its masked Pong
// is sent from -- the next frame is decoded unmasked all the same. An application that moves a Ping's payload out
// leaves the buffer null: an empty frame then copies nothing (memcpy(nullptr, src, 0) was undefined) and a frame
// with a payload decodes as any other.
TEST(WsFrameAllocation, TheClientDecodesUnmaskedFramesAfterAPingAndAfterItsBufferIsTaken) {
    using namespace ws_frame_allocation_test;
    ClientIO       io;
    ClientProtocol protocol(io, upgrade_response(), "dGhlIHNhbXBsZSBub25jZQ==");
    ASSERT_TRUE(protocol.ok());

    feed_client(protocol, io, frame_of(0x9u, "ab", false));
    ASSERT_EQ(io.output.size(), 8u) << "a masked Pong of two octets: 2 + 4 + 2";
    const auto *pong = reinterpret_cast<const std::uint8_t *>(io.output.cbegin());
    EXPECT_EQ(pong[0], 0x8Au);
    EXPECT_EQ(pong[1], 0x82u) << "the Pong is masked";
    EXPECT_EQ(static_cast<char>(pong[6] ^ pong[2]), 'a');
    EXPECT_EQ(static_cast<char>(pong[7] ^ pong[3]), 'b');
    feed_client(protocol, io, frame_of(0x1u, "hello", false));
    ASSERT_EQ(io.messages.size(), 1u);
    EXPECT_EQ(io.messages[0], "hello") << "decoded with the Pong's mask flag";

    io.steal = true;
    feed_client(protocol, io, frame_of(0x9u, "xy", false));
    io.steal = false;
    feed_client(protocol, io, frame_of(0x1u, "", false));
    feed_client(protocol, io, frame_of(0x1u, "after", false));
    ASSERT_EQ(io.messages.size(), 3u);
    EXPECT_EQ(io.messages[1], "");
    EXPECT_EQ(io.messages[2], "after");
    EXPECT_TRUE(protocol.ok());
}

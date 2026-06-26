/**
 * @file qbm/http/tests/system/ws/ws-framing-edge.cpp
 * @brief RFC 6455 §5 framing edge cases not covered by the happy-path tests.
 *
 * Every case here drives a real loopback `tcp::server` on a background event
 * loop and talks to it over an actual socket — either a raw `qb::io::tcp::socket`
 * (so the test controls the exact bytes on the wire and can violate the framing
 * rules deliberately) or a real `coro_client`. This is a SYSTEM-tier test; it
 * runs plaintext `ws://` and needs OpenSSL only as a crypto *link* dependency
 * (`generateKey` / `Sec-WebSocket-Accept` use `qb::io::crypto` SHA-1/base64), not
 * as a TLS transport.
 *
 * Coverage map:
 *   - Aggregate / per-message payload caps  (1009 MessageTooBig)
 *   - Interleaved control frames inside a fragmented data message (auto-Pong)
 *   - Zero-length text / ping handling
 *   - Non-minimal length encodings, RSV bits, fragmented control frames,
 *     stray continuation, mid-fragment new data frame, 64-bit MSB set
 *     (1002 ProtocolError)
 *   - Invalid UTF-8 in a text frame (1007 DataNotConsistent)
 *   - Unmasked client frame                (1002 ProtocolError)
 *   - Close frame with an out-of-range close code (1002 ProtocolError)
 *   - >125-byte single (non-fragmented) payload over the ext16 length path
 *     (happy-path echo)
 *   - Throwing message handler must not terminate (noexcept backstop)
 *
 * The server harness, `perform_upgrade()`, `make_client_frame()`, `read_some()`
 * and `extract_close_code()` all come from the shared loopback header so the
 * inline copies that used to live here are gone. Ports are ephemeral (assigned
 * by the OS) so cases never collide and can run in parallel.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "../../shared/loopback_server.h"
#include "../../shared/ws_loopback.h"
#include "../ws/coro.h"

namespace {

using namespace std::chrono_literals;
using qb::http::test::ephemeral_port;
using qb::http::test::extract_close_code;
using qb::http::test::make_client_frame;
using qb::http::test::perform_upgrade;
using qb::http::test::read_some;
using qb::http::test::WsServerThread;

// ---------------------------------------------------------------------------
// Test sessions/servers
// ---------------------------------------------------------------------------

// A coro session that installs a 64-byte payload cap before its receive loop.
class BoundedServer;

class BoundedSession : public qb::http::ws::coro_session<BoundedSession, BoundedServer> {
public:
    using base = qb::http::ws::coro_session<BoundedSession, BoundedServer>;
    using base::base;

    qb::io::async::task<void>
    run() {
        // The WebSocket protocol is installed by switch_protocol<WS_Protocol>
        // before spawn_run_loop(), so this static_cast is safe.
        if (auto *p = static_cast<qb::protocol::ws_server<BoundedSession> *>(this->protocol())) {
            p->set_max_payload_size(64);
        }
        while (true) {
            auto frame = co_await this->next_frame();
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected ||
                frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
                co_return;
            }
        }
    }
};

class BoundedServer : public qb::io::use<BoundedServer>::tcp::server<BoundedSession> {
public:
    void
    on(IOSession &) {}
};

// A coro echo session: relies on the base framer to reassemble fragmented
// messages, auto-Pong pings, and validate UTF-8 transparently.
class EchoServer;

class EchoSession : public qb::http::ws::coro_session<EchoSession, EchoServer> {
public:
    using base = qb::http::ws::coro_session<EchoSession, EchoServer>;
    using base::base;

    qb::io::async::task<void>
    run() {
        while (true) {
            auto frame = co_await this->next_frame();
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected ||
                frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
                co_return;
            }
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Message) {
                qb::http::ws::MessageText reply;
                reply << frame.payload;
                *this << reply;
            }
        }
    }
};

class EchoServer : public qb::io::use<EchoServer>::tcp::server<EchoSession> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Shared assertion: connect, upgrade, send frames, expect an exact close code.
// ---------------------------------------------------------------------------

template <typename ServerT>
void
expect_close_code_after_frames(WsServerThread<ServerT>                    &server,
                               std::vector<std::vector<std::uint8_t>> const &frames,
                               qb::http::ws::CloseStatus                     expected) {
    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(
        qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    for (auto const &frame : frames) {
        sock.write(reinterpret_cast<const char *>(frame.data()),
                   static_cast<int>(frame.size()));
    }

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value())
        << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(expected));

    sock.close();
}

// ===========================================================================
// 1. Aggregate / per-message payload caps
// ===========================================================================

TEST(WsFramingEdge, MaxPayloadSizeEnforced) {
    WsServerThread<BoundedServer> server{ephemeral_port()};

    auto scenario = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        const std::string         url = "ws://localhost:" + std::to_string(server.port) + "/";
        auto                      c   = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok) {
            co_return qb::http::ws::IncomingFrame{};
        }
        qb::http::ws::MessageText msg;
        msg << std::string(128, 'A'); // 128 > 64-byte cap
        ws << msg;
        co_return co_await ws.receive();
    };

    const auto frame = qb::http::ws::run_sync(scenario());
    EXPECT_TRUE(frame.kind == qb::http::ws::IncomingFrame::Kind::Close ||
                frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected)
        << "Got unexpected kind " << static_cast<int>(frame.kind);
    if (frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
        EXPECT_EQ(frame.close_code,
                  static_cast<std::uint16_t>(qb::http::ws::CloseStatus::MessageTooBig))
            << "reason='" << frame.close_reason << "'";
    }
}

TEST(WsFramingEdge, FragmentedPayloadLimitIsEnforcedOnAggregateMessageSize) {
    WsServerThread<BoundedServer> server{ephemeral_port()};
    // 40 + 40: each frame is under 64 but the reassembled message is not.
    expect_close_code_after_frames(
        server,
        {make_client_frame(0x01, std::string(40, 'A')),
         make_client_frame(0x80, std::string(40, 'B'))},
        qb::http::ws::CloseStatus::MessageTooBig);
}

// ===========================================================================
// 2. Interleaved Ping inside a fragmented text message
// ===========================================================================

TEST(WsFramingEdge, InterleavedPingDuringFragmented) {
    WsServerThread<EchoServer> server{ephemeral_port()};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(
        qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // Frame A: Text, FIN=0, "Hel". Frame B: Ping, FIN=1, "P" (injected mid
    // fragment, RFC 6455 §5.4). Frame C: Continuation, FIN=1, "lo".
    auto frame_a = make_client_frame(0x01, "Hel");
    auto frame_b = make_client_frame(0x89, "P");
    auto frame_c = make_client_frame(0x80, "lo");
    sock.write(reinterpret_cast<const char *>(frame_a.data()), static_cast<int>(frame_a.size()));
    sock.write(reinterpret_cast<const char *>(frame_b.data()), static_cast<int>(frame_b.size()));
    sock.write(reinterpret_cast<const char *>(frame_c.data()), static_cast<int>(frame_c.size()));

    // Expect, in order: Pong 0x8A 0x01 'P' (3 bytes), then text echo
    // 0x81 0x05 "Hello" (7 bytes).
    const std::string got = read_some(sock, 10);
    ASSERT_GE(got.size(), 10u) << "only got " << got.size() << " bytes back: '" << got << "'";

    EXPECT_EQ(static_cast<std::uint8_t>(got[0]), 0x8Au) << "frame#1 fin+opcode";
    EXPECT_EQ(static_cast<std::uint8_t>(got[1]), 0x01u) << "frame#1 len7";
    EXPECT_EQ(got[2], 'P') << "frame#1 payload";

    EXPECT_EQ(static_cast<std::uint8_t>(got[3]), 0x81u) << "frame#2 fin+opcode";
    EXPECT_EQ(static_cast<std::uint8_t>(got[4]), 0x05u) << "frame#2 len7";
    EXPECT_EQ(got.substr(5, 5), "Hello") << "fragmented text was not reassembled";

    sock.close();
}

// ===========================================================================
// 3. Zero-length data / control frames
// ===========================================================================

TEST(WsFramingEdge, ZeroLengthTextFrameIsDeliveredAndEchoed) {
    WsServerThread<EchoServer> server{ephemeral_port()};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(
        qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    auto frame = make_client_frame(0x81, ""); // FIN + text, empty payload
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    const std::string got = read_some(sock, 2);
    ASSERT_EQ(got.size(), 2u) << "empty text echo should be a 2-byte zero-length frame";
    EXPECT_EQ(static_cast<std::uint8_t>(got[0]), 0x81u);
    EXPECT_EQ(static_cast<std::uint8_t>(got[1]), 0x00u);

    sock.close();
}

TEST(WsFramingEdge, ZeroLengthPingGetsZeroLengthPong) {
    WsServerThread<EchoServer> server{ephemeral_port()};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(
        qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    auto frame = make_client_frame(0x89, ""); // FIN + ping, empty payload
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    const std::string got = read_some(sock, 2);
    ASSERT_EQ(got.size(), 2u) << "empty ping should receive a 2-byte empty pong";
    EXPECT_EQ(static_cast<std::uint8_t>(got[0]), 0x8Au);
    EXPECT_EQ(static_cast<std::uint8_t>(got[1]), 0x00u);

    sock.close();
}

// ===========================================================================
// 4. Protocol-error negatives (1002)
// ===========================================================================

TEST(WsFramingEdge, NonMinimalPayloadLengthEncodingIsRejected) {
    WsServerThread<EchoServer> server{ephemeral_port()};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(
        qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // Text frame whose length is encoded as 126 + ext16(1): a 1-byte payload
    // that should have used the 7-bit form. Non-minimal => 1002.
    std::vector<std::uint8_t>       bad{0x81u, static_cast<std::uint8_t>(0x80u | 126u), 0x00u, 0x01u};
    constexpr std::array<std::uint8_t, 4> mask{{0x12, 0x34, 0x56, 0x78}};
    for (auto m : mask) {
        bad.push_back(m);
    }
    bad.push_back(static_cast<std::uint8_t>('X') ^ mask[0]);
    sock.write(reinterpret_cast<const char *>(bad.data()), static_cast<int>(bad.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value())
        << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));

    sock.close();
}

TEST(WsFramingEdge, RsvBitsAreRejected) {
    WsServerThread<EchoServer> server{ephemeral_port()};
    expect_close_code_after_frames(server, {make_client_frame(0xC1, "x")}, // FIN + RSV1 + text
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST(WsFramingEdge, FragmentedControlFrameIsRejected) {
    WsServerThread<EchoServer> server{ephemeral_port()};
    expect_close_code_after_frames(server, {make_client_frame(0x09, "p")}, // Ping with FIN=0
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST(WsFramingEdge, ContinuationWithoutInitialDataFrameIsRejected) {
    WsServerThread<EchoServer> server{ephemeral_port()};
    expect_close_code_after_frames(server, {make_client_frame(0x80, "x")}, // FIN + continuation, no prior data
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST(WsFramingEdge, NewDataFrameBeforeFinalContinuationIsRejected) {
    WsServerThread<EchoServer> server{ephemeral_port()};
    expect_close_code_after_frames(server,
                                   {make_client_frame(0x01, "hel"), // Text, FIN=0
                                    make_client_frame(0x82, "bin")}, // Binary, FIN=1 mid-fragment
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST(WsFramingEdge, PayloadLength64MostSignificantBitIsRejected) {
    WsServerThread<EchoServer> server{ephemeral_port()};
    std::vector<std::uint8_t> bad;
    bad.reserve(2 + 8 + 4);
    bad.push_back(0x81u);        // FIN + text
    bad.push_back(0x80u | 127u); // masked + extended64
    bad.push_back(0x80u);        // invalid MSB set
    for (int i = 0; i < 7; ++i) {
        bad.push_back(0x00u);
    }
    bad.insert(bad.end(), {0x12u, 0x34u, 0x56u, 0x78u});
    expect_close_code_after_frames(server, {bad}, qb::http::ws::CloseStatus::ProtocolError);
}

// NEW: an unmasked client text frame must be rejected (RFC 6455 §5.1).
TEST(WsFramingEdge, UnmaskedClientFrameIsRejected) {
    WsServerThread<EchoServer> server{ephemeral_port()};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(
        qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // Hand-build a text frame with the MASK bit clear (make_client_frame always
    // masks, so we cannot use it here).
    const std::string         payload = "unmasked payload";
    std::vector<std::uint8_t> frame;
    frame.push_back(0x81u);                                          // FIN + text
    frame.push_back(static_cast<std::uint8_t>(payload.size()));      // MASK=0, len7
    for (char ch : payload) {
        frame.push_back(static_cast<std::uint8_t>(ch));
    }
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value())
        << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));

    sock.close();
}

// NEW: a Close frame carrying an out-of-range status code must be rejected
// with 1002 (ws.h:500 "Invalid close status code").
TEST(WsFramingEdge, OutOfRangeCloseCodeIsRejected) {
    WsServerThread<EchoServer> server{ephemeral_port()};

    // Close payload = status 999 (below the lowest valid 1000) + no reason.
    std::string close_payload;
    close_payload.push_back(static_cast<char>((999u >> 8) & 0xFFu));
    close_payload.push_back(static_cast<char>(999u & 0xFFu));

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(
        qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    auto frame = make_client_frame(0x88, close_payload); // FIN + Close
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value())
        << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));

    sock.close();
}

// A Close frame whose payload is exactly ONE byte is malformed: a close code is
// two bytes, so a lone byte can never be a valid status (ws.h:492 → 1002).
TEST(WsFramingEdge, OneByteCloseFramePayloadIsRejected) {
    WsServerThread<EchoServer> server{ephemeral_port()};
    // Close (0x88) with a single payload byte.
    expect_close_code_after_frames(server, {make_client_frame(0x88, std::string(1, '\x03'))},
                                   qb::http::ws::CloseStatus::ProtocolError);
}

// A Close frame with a VALID status code but a reason that is not valid UTF-8
// must be failed with 1007 DataNotConsistent (ws.h:504). This is distinct from
// the out-of-range-code path (1002) already covered above.
TEST(WsFramingEdge, CloseFrameWithInvalidUtf8ReasonIsRejectedWith1007) {
    WsServerThread<EchoServer> server{ephemeral_port()};

    // Payload = status 1000 (Normal, valid) + invalid UTF-8 reason (lone 0x80
    // continuation byte → not a valid scalar).
    std::string close_payload;
    close_payload.push_back(static_cast<char>((1000u >> 8) & 0xFFu));
    close_payload.push_back(static_cast<char>(1000u & 0xFFu));
    close_payload.push_back(static_cast<char>(0x80)); // invalid UTF-8

    expect_close_code_after_frames(server, {make_client_frame(0x88, close_payload)},
                                   qb::http::ws::CloseStatus::DataNotConsistent);
}

// A control (Ping) frame announcing a length indicator of 126 exceeds the 125
// byte control-frame payload cap and is rejected from the indicator alone
// (ws.h:674 → 1002): 126 is read as a length value > 125 before the ext16 path
// is taken. make_client_frame only emits the 7-bit form, so build it by hand.
TEST(WsFramingEdge, ControlFrameAnnouncingOversizeLengthIsRejected) {
    WsServerThread<EchoServer> server{ephemeral_port()};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(
        qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // Ping (0x89) + MASK + len-indicator 126 — over the control-frame cap.
    std::vector<std::uint8_t> bad{0x89u, static_cast<std::uint8_t>(0x80u | 126u), 0x00u, 0x01u};
    constexpr std::array<std::uint8_t, 4> mask{{0x12, 0x34, 0x56, 0x78}};
    for (auto m : mask) {
        bad.push_back(m);
    }
    bad.push_back(static_cast<std::uint8_t>('Z') ^ mask[0]);
    sock.write(reinterpret_cast<const char *>(bad.data()), static_cast<int>(bad.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value())
        << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));

    sock.close();
}

// ===========================================================================
// 5. UTF-8 validation (1007)
// ===========================================================================

TEST(WsFramingEdge, InvalidUtf8TextFrameIsRejectedWith1007) {
    WsServerThread<EchoServer> server{ephemeral_port()};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(
        qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // U+D800 surrogate encoded as ED A0 80 is invalid UTF-8.
    const std::string invalid_utf8("\xED\xA0\x80", 3);
    auto              frame = make_client_frame(0x81, invalid_utf8);
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value())
        << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code,
              static_cast<std::uint16_t>(qb::http::ws::CloseStatus::DataNotConsistent));

    sock.close();
}

// ===========================================================================
// 6. >125-byte single payload over the ext16 length path (happy echo)
// ===========================================================================

TEST(WsFramingEdge, LargeSingleFramePayloadUsesExt16LengthPath) {
    WsServerThread<EchoServer> server{ephemeral_port()};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(
        qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // 200-byte payload: forces the 126 + ext16 client length form. make_client_frame
    // only emits the 7-bit form, so build the masked frame by hand here.
    const std::string                     payload(200, 'Z');
    const std::array<std::uint8_t, 4>     mask{{0xAA, 0x55, 0x01, 0xFE}};
    std::vector<std::uint8_t>             frame;
    frame.reserve(4 + 4 + payload.size());
    frame.push_back(0x81u);                                                 // FIN + text
    frame.push_back(static_cast<std::uint8_t>(0x80u | 126u));               // MASK + ext16
    frame.push_back(static_cast<std::uint8_t>((payload.size() >> 8) & 0xFFu));
    frame.push_back(static_cast<std::uint8_t>(payload.size() & 0xFFu));
    for (auto b : mask) {
        frame.push_back(b);
    }
    for (std::size_t i = 0; i < payload.size(); ++i) {
        frame.push_back(static_cast<std::uint8_t>(
            static_cast<std::uint8_t>(payload[i]) ^ mask[i & 3u]));
    }
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    // Server echoes unmasked: 0x81, 126, ext16(200), then 200 payload bytes = 204.
    const std::string got = read_some(sock, 4 + payload.size());
    ASSERT_GE(got.size(), 4u + payload.size())
        << "only got " << got.size() << " bytes; expected the full ext16 echo";
    EXPECT_EQ(static_cast<std::uint8_t>(got[0]), 0x81u) << "echo fin+opcode";
    EXPECT_EQ(static_cast<std::uint8_t>(got[1]), 126u) << "echo must use ext16 length form";
    const std::size_t echoed_len =
        (static_cast<std::size_t>(static_cast<std::uint8_t>(got[2])) << 8u) |
        static_cast<std::size_t>(static_cast<std::uint8_t>(got[3]));
    EXPECT_EQ(echoed_len, payload.size());
    EXPECT_EQ(got.substr(4, payload.size()), payload) << "echoed bytes must equal sent bytes";

    sock.close();
}

// ===========================================================================
// 7. Throwing message handler must not terminate (noexcept onMessage backstop)
// ===========================================================================

class ThrowServer;

class ThrowSession : public qb::io::use<ThrowSession>::tcp::client<ThrowServer> {
public:
    using Protocol    = qb::http::protocol<ThrowSession>;
    using WS_Protocol = qb::http::ws::protocol<ThrowSession>;

    explicit ThrowSession(IOServer &server)
        : client(server) {}

    void
    on(Protocol::request &&request) {
        if (!this->switch_protocol<WS_Protocol>(*this, request)) {
            disconnect();
        }
    }

    void
    on(WS_Protocol::message &&) {
        throw std::runtime_error("ws message handler boom");
    }
};

class ThrowServer : public qb::io::use<ThrowServer>::tcp::server<ThrowSession> {
public:
    void
    on(IOSession &) {}
};

TEST(WsFramingEdge, ThrowingMessageHandlerDoesNotTerminate) {
    WsServerThread<ThrowServer> server{ephemeral_port()};

    auto scenario = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        const std::string         url = "ws://localhost:" + std::to_string(server.port) + "/";
        auto                      c   = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok) {
            co_return qb::http::ws::IncomingFrame{};
        }
        qb::http::ws::MessageText msg;
        msg << std::string("hello");
        ws << msg;
        co_return co_await ws.receive();
    };

    const auto frame = qb::http::ws::run_sync(scenario());
    EXPECT_TRUE(frame.kind == qb::http::ws::IncomingFrame::Kind::Close ||
                frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected)
        << "unexpected frame kind " << static_cast<int>(frame.kind);
}

} // namespace

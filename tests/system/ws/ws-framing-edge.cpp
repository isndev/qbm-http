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
 * inline copies that used to live here are gone. Each case's server binds :0
 * ITSELF and publishes the port the kernel assigned it (see @ref EphemeralWsServer),
 * so cases never collide — not with each other and not with another test process
 * under `ctest -j`.
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
#include <qbm/http/ws/coro.h>

namespace {

using namespace std::chrono_literals;
using qb::http::test::extract_close_code;
using qb::http::test::make_client_frame;
using qb::http::test::perform_upgrade;
using qb::http::test::read_some;
using qb::http::test::WsServerThread;

// ---------------------------------------------------------------------------
// Server fixture: the SERVING socket takes the ephemeral port itself
// ---------------------------------------------------------------------------

/**
 * @brief A @ref WsServerThread whose own listener is bound to :0.
 *
 * Passing port 0 makes the harness `listen_v4(0)` and publish the kernel-assigned port
 * under its readiness lock before signalling ready (shared/ws_loopback.h), so `port` is
 * the real, bound port by the time this constructor returns.
 *
 * This replaces `WsServerThread<T>{ephemeral_port()}`. `ephemeral_port()` probed a free
 * port on a THROWAWAY listener and had to close it before the server could bind: in that
 * window another test PROCESS can take the port, which under `ctest -j` is a measured
 * flake (2 failures in 12 full-suite runs across the qbm-http system suites). Binding :0
 * on the socket that actually serves leaves no window at all — the kernel hands out a port
 * and this socket keeps it.
 */
template <typename ServerT>
struct EphemeralWsServer : WsServerThread<ServerT> {
    EphemeralWsServer()
        : WsServerThread<ServerT>(0) {
        EXPECT_NE(this->port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    }
};

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
        // The WebSocket protocol is installed by switch_protocol<WS_Protocol> before
        // spawn_run_loop(). The live protocol's type is base::WS_Protocol —
        // ws_server<coro_session<BoundedSession, BoundedServer>>, NOT ws_server<BoundedSession>
        // (a sibling instantiation); casting to the latter is an invalid downcast (UB).
        // The WS protocol is installed (switch_protocol) before run(), so protocol() is it (never null).
        static_cast<base::WS_Protocol *>(this->protocol())->set_max_payload_size(64);
        while (true) {
            auto frame = co_await this->next_frame();
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected || frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
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
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected || frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
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
expect_close_code_after_frames(WsServerThread<ServerT> &server, std::vector<std::vector<std::uint8_t>> const &frames,
                               qb::http::ws::CloseStatus expected) {
    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    for (auto const &frame : frames) {
        sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));
    }

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value()) << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(expected));

    sock.close();
}

// ===========================================================================
// 1. Aggregate / per-message payload caps
// ===========================================================================

TEST(WsFramingEdge, MaxPayloadSizeEnforced) {
    EphemeralWsServer<BoundedServer> server;

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
    EXPECT_TRUE(frame.kind == qb::http::ws::IncomingFrame::Kind::Close || frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected)
        << "Got unexpected kind " << static_cast<int>(frame.kind);
    if (frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
        EXPECT_EQ(frame.close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::MessageTooBig))
            << "reason='" << frame.close_reason << "'";
    }
}

TEST(WsFramingEdge, FragmentedPayloadLimitIsEnforcedOnAggregateMessageSize) {
    EphemeralWsServer<BoundedServer> server;
    // 40 + 40: each frame is under 64 but the reassembled message is not.
    expect_close_code_after_frames(server, {make_client_frame(0x01, std::string(40, 'A')), make_client_frame(0x80, std::string(40, 'B'))},
                                   qb::http::ws::CloseStatus::MessageTooBig);
}

// ===========================================================================
// 2. Interleaved Ping inside a fragmented text message
// ===========================================================================

TEST(WsFramingEdge, InterleavedPingDuringFragmented) {
    EphemeralWsServer<EchoServer> server;

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
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
    EphemeralWsServer<EchoServer> server;

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
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
    EphemeralWsServer<EchoServer> server;

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
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
    EphemeralWsServer<EchoServer> server;

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // Text frame whose length is encoded as 126 + ext16(1): a 1-byte payload
    // that should have used the 7-bit form. Non-minimal => 1002.
    std::vector<std::uint8_t>             bad{0x81u, static_cast<std::uint8_t>(0x80u | 126u), 0x00u, 0x01u};
    constexpr std::array<std::uint8_t, 4> mask{{0x12, 0x34, 0x56, 0x78}};
    for (auto m : mask) {
        bad.push_back(m);
    }
    bad.push_back(static_cast<std::uint8_t>('X') ^ mask[0]);
    sock.write(reinterpret_cast<const char *>(bad.data()), static_cast<int>(bad.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value()) << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));

    sock.close();
}

TEST(WsFramingEdge, RsvBitsAreRejected) {
    EphemeralWsServer<EchoServer> server;
    expect_close_code_after_frames(server, {make_client_frame(0xC1, "x")}, // FIN + RSV1 + text
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST(WsFramingEdge, FragmentedControlFrameIsRejected) {
    EphemeralWsServer<EchoServer> server;
    expect_close_code_after_frames(server, {make_client_frame(0x09, "p")}, // Ping with FIN=0
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST(WsFramingEdge, ContinuationWithoutInitialDataFrameIsRejected) {
    EphemeralWsServer<EchoServer> server;
    expect_close_code_after_frames(server, {make_client_frame(0x80, "x")}, // FIN + continuation, no prior data
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST(WsFramingEdge, NewDataFrameBeforeFinalContinuationIsRejected) {
    EphemeralWsServer<EchoServer> server;
    expect_close_code_after_frames(server,
                                   {make_client_frame(0x01, "hel"),  // Text, FIN=0
                                    make_client_frame(0x82, "bin")}, // Binary, FIN=1 mid-fragment
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST(WsFramingEdge, PayloadLength64MostSignificantBitIsRejected) {
    EphemeralWsServer<EchoServer> server;
    std::vector<std::uint8_t>  bad;
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
    EphemeralWsServer<EchoServer> server;

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // Hand-build a text frame with the MASK bit clear (make_client_frame always
    // masks, so we cannot use it here).
    const std::string         payload = "unmasked payload";
    std::vector<std::uint8_t> frame;
    frame.push_back(0x81u);                                     // FIN + text
    frame.push_back(static_cast<std::uint8_t>(payload.size())); // MASK=0, len7
    for (char ch : payload) {
        frame.push_back(static_cast<std::uint8_t>(ch));
    }
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value()) << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));

    sock.close();
}

// NEW: a Close frame carrying an out-of-range status code must be rejected
// with 1002 (ws.h:500 "Invalid close status code").
TEST(WsFramingEdge, OutOfRangeCloseCodeIsRejected) {
    EphemeralWsServer<EchoServer> server;

    // Close payload = status 999 (below the lowest valid 1000) + no reason.
    std::string close_payload;
    close_payload.push_back(static_cast<char>((999u >> 8) & 0xFFu));
    close_payload.push_back(static_cast<char>(999u & 0xFFu));

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    auto frame = make_client_frame(0x88, close_payload); // FIN + Close
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value()) << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));

    sock.close();
}

// A Close frame whose payload is exactly ONE byte is malformed: a close code is
// two bytes, so a lone byte can never be a valid status (ws.h:492 → 1002).
TEST(WsFramingEdge, OneByteCloseFramePayloadIsRejected) {
    EphemeralWsServer<EchoServer> server;
    // Close (0x88) with a single payload byte.
    expect_close_code_after_frames(server, {make_client_frame(0x88, std::string(1, '\x03'))}, qb::http::ws::CloseStatus::ProtocolError);
}

// A Close frame with a VALID status code but a reason that is not valid UTF-8
// must be failed with 1007 DataNotConsistent (ws.h:504). This is distinct from
// the out-of-range-code path (1002) already covered above.
TEST(WsFramingEdge, CloseFrameWithInvalidUtf8ReasonIsRejectedWith1007) {
    EphemeralWsServer<EchoServer> server;

    // Payload = status 1000 (Normal, valid) + invalid UTF-8 reason (lone 0x80
    // continuation byte → not a valid scalar).
    std::string close_payload;
    close_payload.push_back(static_cast<char>((1000u >> 8) & 0xFFu));
    close_payload.push_back(static_cast<char>(1000u & 0xFFu));
    close_payload.push_back(static_cast<char>(0x80)); // invalid UTF-8

    expect_close_code_after_frames(server, {make_client_frame(0x88, close_payload)}, qb::http::ws::CloseStatus::DataNotConsistent);
}

// A control (Ping) frame announcing a length indicator of 126 exceeds the 125
// byte control-frame payload cap and is rejected from the indicator alone
// (ws.h:674 → 1002): 126 is read as a length value > 125 before the ext16 path
// is taken. make_client_frame only emits the 7-bit form, so build it by hand.
TEST(WsFramingEdge, ControlFrameAnnouncingOversizeLengthIsRejected) {
    EphemeralWsServer<EchoServer> server;

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // Ping (0x89) + MASK + len-indicator 126 — over the control-frame cap.
    std::vector<std::uint8_t>             bad{0x89u, static_cast<std::uint8_t>(0x80u | 126u), 0x00u, 0x01u};
    constexpr std::array<std::uint8_t, 4> mask{{0x12, 0x34, 0x56, 0x78}};
    for (auto m : mask) {
        bad.push_back(m);
    }
    bad.push_back(static_cast<std::uint8_t>('Z') ^ mask[0]);
    sock.write(reinterpret_cast<const char *>(bad.data()), static_cast<int>(bad.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value()) << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));

    sock.close();
}

// ===========================================================================
// 5. UTF-8 validation (1007)
// ===========================================================================

TEST(WsFramingEdge, InvalidUtf8TextFrameIsRejectedWith1007) {
    EphemeralWsServer<EchoServer> server;

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // U+D800 surrogate encoded as ED A0 80 is invalid UTF-8.
    const std::string invalid_utf8("\xED\xA0\x80", 3);
    auto              frame = make_client_frame(0x81, invalid_utf8);
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value()) << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::DataNotConsistent));

    sock.close();
}

// ===========================================================================
// 6. >125-byte single payload over the ext16 length path (happy echo)
// ===========================================================================

TEST(WsFramingEdge, LargeSingleFramePayloadUsesExt16LengthPath) {
    EphemeralWsServer<EchoServer> server;

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // 200-byte payload: forces the 126 + ext16 client length form. make_client_frame
    // only emits the 7-bit form, so build the masked frame by hand here.
    const std::string                 payload(200, 'Z');
    const std::array<std::uint8_t, 4> mask{{0xAA, 0x55, 0x01, 0xFE}};
    std::vector<std::uint8_t>         frame;
    frame.reserve(4 + 4 + payload.size());
    frame.push_back(0x81u);                                   // FIN + text
    frame.push_back(static_cast<std::uint8_t>(0x80u | 126u)); // MASK + ext16
    frame.push_back(static_cast<std::uint8_t>((payload.size() >> 8) & 0xFFu));
    frame.push_back(static_cast<std::uint8_t>(payload.size() & 0xFFu));
    for (auto b : mask) {
        frame.push_back(b);
    }
    for (std::size_t i = 0; i < payload.size(); ++i) {
        frame.push_back(static_cast<std::uint8_t>(static_cast<std::uint8_t>(payload[i]) ^ mask[i & 3u]));
    }
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    // Server echoes unmasked: 0x81, 126, ext16(200), then 200 payload bytes = 204.
    const std::string got = read_some(sock, 4 + payload.size());
    ASSERT_GE(got.size(), 4u + payload.size()) << "only got " << got.size() << " bytes; expected the full ext16 echo";
    EXPECT_EQ(static_cast<std::uint8_t>(got[0]), 0x81u) << "echo fin+opcode";
    EXPECT_EQ(static_cast<std::uint8_t>(got[1]), 126u) << "echo must use ext16 length form";
    const std::size_t echoed_len =
        (static_cast<std::size_t>(static_cast<std::uint8_t>(got[2])) << 8u) | static_cast<std::size_t>(static_cast<std::uint8_t>(got[3]));
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
    EphemeralWsServer<ThrowServer> server;

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
    EXPECT_TRUE(frame.kind == qb::http::ws::IncomingFrame::Kind::Close || frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected)
        << "unexpected frame kind " << static_cast<int>(frame.kind);
}

// ===========================================================================
// 8. Valid multi-byte UTF-8 acceptance (drives every accepting branch of
//    qb::http::ws::is_utf8 in ws.cpp). The existing UTF-8 cases only send
//    INVALID bytes (surrogate / lone continuation), so the 2/3/4-byte
//    accept paths and their `continue` arms were never executed end-to-end.
//    A text frame whose reassembled payload is valid UTF-8 is echoed back
//    intact, which proves is_utf8() returned true through each multi-byte form.
// ===========================================================================

// One byte from every accepting UTF-8 length class. Kept ≤125 bytes so the
// shared 7-bit make_client_frame builder can mask it.
//   - 2-byte  C2..DF : "é"  = C3 A9
//   - E0      lead    : "à"  = C3 A0? no -> use U+0800 "ࠀ" = E0 A0 80
//   - E1..EC  lead    : "€"  = E2 82 AC
//   - ED valid (<A0)  : U+D000 "퐀"? U+D000 = ED 80 80
//   - EE..EF lead     : U+F000 "" = EF 80 80
//   - F0     lead     : U+10000 "𐀀" = F0 90 80 80
//   - F1..F3 lead     : U+40000      = F1 80 80 80
//   - F4     lead     : U+100000     = F4 80 80 80
static const std::string kAllUtf8Forms = []() {
    std::string s;
    s += "A";                                // ASCII (<=0x7F)
    s += std::string("\xC3\xA9", 2);         // 2-byte
    s += std::string("\xE0\xA0\x80", 3);     // E0 lead (b1 in A0..BF)
    s += std::string("\xE2\x82\xAC", 3);     // E1..EC lead (euro)
    s += std::string("\xED\x80\x80", 3);     // ED valid (b1 in 80..9F)
    s += std::string("\xEF\x80\x80", 3);     // EE..EF lead
    s += std::string("\xF0\x90\x80\x80", 4); // F0 lead (b1 in 90..BF)
    s += std::string("\xF1\x80\x80\x80", 4); // F1..F3 lead
    s += std::string("\xF4\x80\x80\x80", 4); // F4 lead (b1 in 80..8F)
    return s;
}();

TEST(WsFramingEdge, ValidMultiByteUtf8TextIsAcceptedAndEchoed) {
    EphemeralWsServer<EchoServer> server;

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    ASSERT_LE(kAllUtf8Forms.size(), 125u);
    auto frame = make_client_frame(0x81, kAllUtf8Forms); // FIN + text, valid UTF-8
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    // Valid UTF-8 -> message delivered -> echoed back unmasked. 7-bit length form.
    const std::size_t expected = 2u + kAllUtf8Forms.size();
    const std::string got      = read_some(sock, expected);
    ASSERT_GE(got.size(), expected) << "valid UTF-8 text was not echoed back intact";
    EXPECT_EQ(static_cast<std::uint8_t>(got[0]), 0x81u) << "echo fin+opcode";
    EXPECT_EQ(static_cast<std::uint8_t>(got[1]), kAllUtf8Forms.size()) << "echo must use 7-bit length form";
    EXPECT_EQ(got.substr(2, kAllUtf8Forms.size()), kAllUtf8Forms) << "echoed bytes must equal the sent UTF-8 payload";

    sock.close();
}

// A multi-byte code point split ACROSS a fragment boundary must reassemble and
// validate as one scalar (ws.h:572 final-fragment UTF-8 check on the joined
// buffer). The euro sign (E2 82 AC) is split 1+2 between two frames.
TEST(WsFramingEdge, MultiByteUtf8SplitAcrossFragmentsReassemblesAndValidates) {
    EphemeralWsServer<EchoServer> server;

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // Frame A: Text FIN=0 "A\xE2" (the lead + first byte of the euro sign).
    // Frame B: Continuation FIN=1 "\x82\xAC" (the two trailing bytes).
    // Reassembled = "A€" which is valid UTF-8 only as a whole.
    auto frame_a = make_client_frame(0x01, std::string("A\xE2", 2));
    auto frame_b = make_client_frame(0x80, std::string("\x82\xAC", 2));
    sock.write(reinterpret_cast<const char *>(frame_a.data()), static_cast<int>(frame_a.size()));
    sock.write(reinterpret_cast<const char *>(frame_b.data()), static_cast<int>(frame_b.size()));

    const std::string expected_payload("A\xE2\x82\xAC", 4);
    const std::size_t expected = 2u + expected_payload.size();
    const std::string got      = read_some(sock, expected);
    ASSERT_GE(got.size(), expected) << "split multi-byte UTF-8 not reassembled+echoed";
    EXPECT_EQ(static_cast<std::uint8_t>(got[0]), 0x81u);
    EXPECT_EQ(static_cast<std::uint8_t>(got[1]), expected_payload.size());
    EXPECT_EQ(got.substr(2, expected_payload.size()), expected_payload);

    sock.close();
}

// A valid UTF-8 (multi-byte) close reason must pass is_utf8() on both the close
// path in ws.h (processControlFrame line 504 accept branch) and round-trip back
// in the echoed close frame.
TEST(WsFramingEdge, CloseFrameWithValidMultiByteUtf8ReasonIsEchoed) {
    EphemeralWsServer<EchoServer> server;

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(server.port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, server.port, "/edge");

    // status 1000 (Normal) + valid UTF-8 reason "ok€" (euro is 3 bytes).
    std::string close_payload;
    close_payload.push_back(static_cast<char>((1000u >> 8) & 0xFFu));
    close_payload.push_back(static_cast<char>(1000u & 0xFFu));
    close_payload += std::string("ok\xE2\x82\xAC", 5);

    auto frame = make_client_frame(0x88, close_payload);
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value()) << "server did not echo a parseable close frame: size=" << got.size();
    // Valid reason => server echoes a Normal-closure close (not a protocol error).
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::Normal));

    sock.close();
}

// Drive the specific REJECTING sub-branches of is_utf8 that the existing
// surrogate/lone-continuation cases miss: a truncated 2-byte lead at the very
// end of the buffer (i+1 >= n), an E0 lead with an out-of-range second byte
// (b1 < 0xA0), and an F0 lead with an out-of-range second byte (b1 < 0x90).
// Each is sent as a standalone text frame and must close with 1007.
TEST(WsFramingEdge, Utf8TruncatedTwoByteLeadAtEndIsRejected) {
    EphemeralWsServer<EchoServer> server;
    // "A" + lone 2-byte lead 0xC3 with no continuation byte. is_utf8: i+1>=n.
    expect_close_code_after_frames(server, {make_client_frame(0x81, std::string("A\xC3", 2))}, qb::http::ws::CloseStatus::DataNotConsistent);
}

TEST(WsFramingEdge, Utf8E0OverlongSecondByteIsRejected) {
    EphemeralWsServer<EchoServer> server;
    // E0 80 80 is an overlong encoding (b1 must be >= 0xA0). is_utf8 rejects it.
    expect_close_code_after_frames(server, {make_client_frame(0x81, std::string("\xE0\x80\x80", 3))},
                                   qb::http::ws::CloseStatus::DataNotConsistent);
}

TEST(WsFramingEdge, Utf8F0OverlongSecondByteIsRejected) {
    EphemeralWsServer<EchoServer> server;
    // F0 80 80 80 is an overlong 4-byte encoding (b1 must be >= 0x90).
    expect_close_code_after_frames(server, {make_client_frame(0x81, std::string("\xF0\x80\x80\x80", 4))},
                                   qb::http::ws::CloseStatus::DataNotConsistent);
}

TEST(WsFramingEdge, Utf8F4OutOfRangeSecondByteIsRejected) {
    EphemeralWsServer<EchoServer> server;
    // F4 90 80 80 would encode > U+10FFFF (b1 must be <= 0x8F). Rejected.
    expect_close_code_after_frames(server, {make_client_frame(0x81, std::string("\xF4\x90\x80\x80", 4))},
                                   qb::http::ws::CloseStatus::DataNotConsistent);
}

// ===========================================================================
// 9. MessageClose construction guards (ws.cpp:210-234). The wire tests above
//    exercise the RECEIVE side; these drive the SEND-side constructor, which a
//    real client invokes to build a Close frame. Reserved/out-of-range codes
//    throw; an over-long reason is clipped to 123 bytes on a UTF-8 boundary.
// ===========================================================================

TEST(WsFramingEdge, MessageCloseRejectsReservedAndOutOfRangeCodes) {
    using qb::http::ws::MessageClose;
    // 1005 ("no status received") and 1006 ("abnormal") MUST NOT appear on the
    // wire; 1004 is reserved; codes below 1000 / above 4999 are out of range.
    EXPECT_THROW(MessageClose(std::uint16_t{1004}, "x"), std::invalid_argument);
    EXPECT_THROW(MessageClose(std::uint16_t{1005}, "x"), std::invalid_argument);
    EXPECT_THROW(MessageClose(std::uint16_t{1006}, "x"), std::invalid_argument);
    EXPECT_THROW(MessageClose(std::uint16_t{1015}, "x"), std::invalid_argument);
    EXPECT_THROW(MessageClose(std::uint16_t{999}, "x"), std::invalid_argument);
    EXPECT_THROW(MessageClose(std::uint16_t{5000}, "x"), std::invalid_argument);
    // A valid application code in [3000,4999] with a short reason is fine.
    EXPECT_NO_THROW(MessageClose(std::uint16_t{3000}, "ok"));
}

TEST(WsFramingEdge, MessageCloseRejectsInvalidUtf8Reason) {
    using qb::http::ws::MessageClose;
    // A short reason carrying an invalid byte (lone continuation 0x80) must be
    // rejected outright (it is <123 bytes, so it bypasses the clip path and hits
    // the trailing is_utf8 guard).
    EXPECT_THROW(MessageClose(std::uint16_t{1000}, std::string("bad\x80", 4)), std::invalid_argument);
}

TEST(WsFramingEdge, MessageCloseClipsOverLongReasonOnUtf8Boundary) {
    using qb::http::ws::MessageClose;
    // Build a >123-byte reason that ends with a multi-byte euro sign straddling
    // the 123-byte cut so the UTF-8-clean loop must walk back past the partial
    // sequence. 121 ASCII 'a' + euro(3 bytes) = 124 bytes; the cut at 123 leaves
    // a truncated euro (a + a*120 + E2 82) which is invalid, so the clip loop
    // removes bytes until valid.
    std::string reason(121, 'a');
    reason += std::string("\xE2\x82\xAC", 3); // total 124 bytes
    ASSERT_GT(reason.size(), 123u);

    MessageClose msg(std::uint16_t{1000}, reason);
    // 2-byte status + clipped reason; the whole payload is a valid control frame
    // (<=125 bytes) and the reason portion is valid UTF-8 (no dangling bytes).
    ASSERT_GE(msg.size(), 2u);
    EXPECT_LE(msg.size(), 125u) << "clip must keep the close frame within the control cap";
    const std::string reason_bytes(msg._data.cbegin() + 2, msg.size() - 2);
    EXPECT_TRUE(qb::http::ws::is_utf8(reason_bytes)) << "clipped reason must remain valid UTF-8";
    // The trailing partial euro must have been dropped: last byte is an 'a'.
    ASSERT_FALSE(reason_bytes.empty());
    EXPECT_EQ(reason_bytes.back(), 'a') << "partial multi-byte tail must be clipped away";
}

TEST(WsFramingEdge, MessageCloseClipsOverLongAsciiReasonTo123) {
    using qb::http::ws::MessageClose;
    // A long pure-ASCII reason is simply truncated to 123 bytes (no UTF-8 walk-back).
    const std::string reason(200, 'Z');
    MessageClose      msg(std::uint16_t{1000}, reason);
    EXPECT_EQ(msg.size(), 2u + 123u) << "ASCII reason clipped to exactly 123 bytes";
}

// ===========================================================================
// 10. Outgoing-frame serialization guard rails (ws.cpp
//     enforce_outgoing_frame_constraints, invoked from
//     qb::allocator::pipe<char>::put<ws::Message>). Building a frame that
//     violates RFC 6455 must throw at serialization time rather than emit a
//     malformed frame on the wire. This drives the same `pipe << msg` path the
//     server/client transport uses, just exercised directly so the test owns
//     the (deliberately invalid) message.
// ===========================================================================

TEST(WsFramingEdge, SerializingFrameWithRsvBitsThrows) {
    qb::http::ws::Message msg;
    msg.fin_rsv_opcode = static_cast<unsigned char>(0x40u | 0x01u); // RSV1 + text
    msg << std::string("x");
    qb::allocator::pipe<char> out;
    EXPECT_THROW(out << msg, std::invalid_argument);
}

TEST(WsFramingEdge, SerializingFrameWithReservedOpcodeThrows) {
    qb::http::ws::Message msg;
    msg.fin_rsv_opcode = static_cast<unsigned char>(0x80u | 0x03u); // FIN + reserved opcode 0x3
    msg << std::string("x");
    qb::allocator::pipe<char> out;
    EXPECT_THROW(out << msg, std::invalid_argument);
}

TEST(WsFramingEdge, SerializingOversizeControlFrameThrows) {
    qb::http::ws::Message msg;
    // FIN + Close, but a 130-byte payload exceeds the 125-byte control cap.
    msg.fin_rsv_opcode = static_cast<unsigned char>(0x80u | 0x08u);
    msg << std::string(130, 'x');
    qb::allocator::pipe<char> out;
    EXPECT_THROW(out << msg, std::invalid_argument);
}

TEST(WsFramingEdge, SerializingFragmentedControlFrameThrows) {
    qb::http::ws::Message msg;
    // Ping (0x09) with FIN=0 is an illegal fragmented control frame.
    msg.fin_rsv_opcode = static_cast<unsigned char>(0x09u); // no FIN bit
    msg << std::string("x");
    qb::allocator::pipe<char> out;
    EXPECT_THROW(out << msg, std::invalid_argument);
}

TEST(WsFramingEdge, SerializingValidFrameSucceeds) {
    qb::http::ws::Message msg;
    msg.fin_rsv_opcode = static_cast<unsigned char>(0x80u | 0x01u); // FIN + text
    msg << std::string("ok");
    qb::allocator::pipe<char> out;
    EXPECT_NO_THROW(out << msg);
    // 2-byte header (FIN+text, len=2) + 2-byte payload for an unmasked frame.
    EXPECT_EQ(out.size(), 4u);
}

} // namespace

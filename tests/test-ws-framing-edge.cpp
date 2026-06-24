/**
 * @file qbm/http/tests/test-framing-edge.cpp
 * @brief Framing-level edge cases required by RFC 6455 §5 that are not
 *        exercised by the happy-path coroutine tests.
 *
 * Two scenarios:
 *
 *   - `MaxPayloadSizeEnforced`          — a session configures the
 *                                         protocol with a 64-byte payload
 *                                         cap (`set_max_payload_size(64)`)
 *                                         and receives a 128-byte message.
 *                                         The server MUST abort the
 *                                         connection with a `1009
 *                                         MessageTooBig` Close (§5.4 +
 *                                         §7.4.1).
 *   - `InterleavedPingDuringFragmented` — a client sends a fragmented
 *                                         text message (`FIN=0` / `FIN=0`
 *                                         continuation / Ping control
 *                                         frame / `FIN=1` continuation).
 *                                         The server MUST (1) auto-Pong
 *                                         the ping without corrupting the
 *                                         in-progress fragmented assembly
 *                                         (§5.4 + §5.5.3), and (2)
 *                                         deliver the fully reassembled
 *                                         text message to the application.
 *
 * Both tests use the coroutine server (`coro_session`) to get a clean,
 * assertive `run()` body and a raw TCP socket on the client side to
 * bypass the framing protection we're testing.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0
 */

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "../ws/coro.h"

namespace ws_framing_edge_test {

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// Shared server harness (same idiom as test-coro-server.cpp).
// ---------------------------------------------------------------------------

template <typename ServerT>
struct ServerThread {
    std::thread       thread;
    std::atomic<bool> ready{false};
    std::atomic<bool> running{true};
    int               port{0};

    ServerThread(int port_, std::function<void(ServerT &)> config = {})
        : port(port_) {
        thread = std::thread([this, config = std::move(config)] {
            qb::io::async::init();
            ServerT server;
            if (config)
                config(server);
            server.transport().listen_v4(port);
            server.start();
            ready.store(true, std::memory_order_release);
            while (running.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(5ms);
                }
            }
        });
        while (!ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(5ms);
        }
        std::this_thread::sleep_for(30ms);
    }

    ~ServerThread() {
        running.store(false, std::memory_order_release);
        if (thread.joinable())
            thread.join();
    }
};

class FramingEdgeTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        qb::io::async::init();
    }
};

// ===========================================================================
// 1. Max payload size enforcement
// ===========================================================================

class BoundedServer;

class BoundedSession : public qb::http::ws::coro_session<BoundedSession, BoundedServer> {
public:
    using base = qb::http::ws::coro_session<BoundedSession, BoundedServer>;
    using base::base;

    qb::io::async::task<void>
    run() {
        // The WebSocket protocol is now installed: apply the cap. The
        // cast is safe because `switch_protocol<WS_Protocol>` ran before
        // `spawn_run_loop()`.
        if (auto *p = static_cast<qb::protocol::ws_server<BoundedSession> *>(this->protocol())) {
            p->set_max_payload_size(64);
        }

        while (true) {
            auto frame = co_await this->next_frame();
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected || frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
                co_return;
            }
            // Any Message larger than 64 bytes is rejected at the framer
            // layer: `fail_connection` fires and we never see it here.
        }
    }
};

class BoundedServer : public qb::io::use<BoundedServer>::tcp::server<BoundedSession> {
public:
    void
    on(IOSession &) {}
};

TEST_F(FramingEdgeTest, MaxPayloadSizeEnforced) {
    ServerThread<BoundedServer> server{19971};

    auto scenario = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect("ws://localhost:19971/");
        EXPECT_TRUE(c.ok);
        if (!c.ok) {
            co_return qb::http::ws::IncomingFrame{};
        }

        // 128 bytes > 64-byte cap — server must MessageTooBig-close.
        qb::http::ws::MessageText msg;
        msg << std::string(128, 'A');
        ws << msg;

        auto frame = co_await ws.receive();
        co_return frame;
    };

    const auto frame = qb::http::ws::run_sync(scenario());
    EXPECT_TRUE(frame.kind == qb::http::ws::IncomingFrame::Kind::Close || frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected)
        << "Got unexpected kind " << static_cast<int>(frame.kind);
    if (frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
        EXPECT_EQ(frame.close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::MessageTooBig))
            << "reason='" << frame.close_reason << "'";
    }
}

// ===========================================================================
// 2. Interleaved Ping inside a fragmented text message
// ===========================================================================

// We reuse the echo session defined locally: it relies on the base
// framer to reassemble multi-frame text messages transparently.
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

namespace {

// Build a single WebSocket frame for client-to-server delivery (masked).
// Header layout: [FIN|RSV|opcode][MASK|len7][len16/len64?][mask4][payload].
std::vector<std::uint8_t>
make_client_frame(std::uint8_t opcode_with_flags, std::string_view payload) {
    std::vector<std::uint8_t> out;
    out.reserve(payload.size() + 14);
    out.push_back(opcode_with_flags);

    // Payloads over 125 bytes need extended length encoding; the caller
    // keeps everything small on purpose.
    EXPECT_LE(payload.size(), 125u);
    out.push_back(static_cast<std::uint8_t>(0x80u | payload.size()));

    // A predictable mask keeps the test fully deterministic.
    const std::array<std::uint8_t, 4> mask{{0xAA, 0x55, 0x01, 0xFE}};
    for (auto b : mask)
        out.push_back(b);

    for (std::size_t i = 0; i < payload.size(); ++i) {
        out.push_back(static_cast<std::uint8_t>(static_cast<std::uint8_t>(payload[i]) ^ mask[i & 3u]));
    }
    return out;
}

std::optional<std::uint16_t>
extract_close_code(std::string const &frame_bytes) {
    if (frame_bytes.size() < 2u) {
        return std::nullopt;
    }
    const auto b0 = static_cast<std::uint8_t>(frame_bytes[0]);
    const auto b1 = static_cast<std::uint8_t>(frame_bytes[1]);
    if ((b0 & 0x0Fu) != 0x08u) {
        return std::nullopt;
    }
    if ((b1 & 0x80u) != 0u) {
        return std::nullopt; // server->client close must be unmasked
    }

    std::size_t payload_len = static_cast<std::size_t>(b1 & 0x7Fu);
    std::size_t header_len  = 2u;
    if (payload_len == 126u) {
        if (frame_bytes.size() < 4u) {
            return std::nullopt;
        }
        payload_len = (static_cast<std::size_t>(static_cast<std::uint8_t>(frame_bytes[2])) << 8u)
                      | static_cast<std::size_t>(static_cast<std::uint8_t>(frame_bytes[3]));
        header_len  = 4u;
    } else if (payload_len == 127u) {
        return std::nullopt; // unexpected for close in these tests
    }

    if (frame_bytes.size() < header_len + payload_len || payload_len < 2u) {
        return std::nullopt;
    }
    const auto hi = static_cast<std::uint8_t>(frame_bytes[header_len]);
    const auto lo = static_cast<std::uint8_t>(frame_bytes[header_len + 1u]);
    return static_cast<std::uint16_t>((hi << 8u) | lo);
}

// Read at most @p max bytes, polling the socket a few times to tolerate
// the event loop cadence. Returns whatever arrived when `dead` fires.
std::string
read_some(qb::io::tcp::socket &sock, std::size_t max, std::chrono::milliseconds dead = 1500ms) {
    std::string out;
    const auto  start = std::chrono::steady_clock::now();
    char        buf[256];
    while (out.size() < max && std::chrono::steady_clock::now() - start < dead) {
        int n = sock.read(buf, sizeof(buf));
        if (n > 0) {
            out.append(buf, static_cast<std::size_t>(n));
        } else if (n == 0) {
            break;
        } else {
            std::this_thread::sleep_for(5ms);
        }
    }
    return out;
}

void
perform_upgrade(qb::io::tcp::socket &sock, int port) {
    const std::string port_s  = std::to_string(port);
    const std::string upgrade = "GET /edge HTTP/1.1\r\n"
                                "Host: localhost:"
                                + port_s
                                + "\r\n"
                                  "Upgrade: websocket\r\n"
                                  "Connection: Upgrade\r\n"
                                  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                  "Sec-WebSocket-Version: 13\r\n"
                                  "\r\n";
    sock.write(upgrade.data(), static_cast<int>(upgrade.size()));

    std::string response;
    for (int i = 0; i < 500; ++i) {
        char buf[512];
        int  n = sock.read(buf, sizeof(buf));
        if (n > 0)
            response.append(buf, static_cast<std::size_t>(n));
        if (response.find("\r\n\r\n") != std::string::npos)
            break;
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_NE(response.find("101"), std::string::npos) << "handshake failed:\n" << response;
}

void
expect_close_code_after_frames(int port, std::vector<std::vector<std::uint8_t>> const &frames, qb::http::ws::CloseStatus expected_status) {
    ServerThread<EchoServer> server{port};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(port)});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, port);

    for (auto const &frame : frames) {
        sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));
    }

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value()) << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(expected_status));

    sock.close();
}

} // namespace

TEST_F(FramingEdgeTest, InterleavedPingDuringFragmented) {
    ServerThread<EchoServer> server{19972};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{"tcp://localhost:19972"});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);

    // --- 1. Run the HTTP upgrade by hand so we stay on a raw socket -----
    const std::string upgrade = "GET /edge HTTP/1.1\r\n"
                                "Host: localhost:19972\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                "Sec-WebSocket-Version: 13\r\n"
                                "\r\n";
    sock.write(upgrade.data(), static_cast<int>(upgrade.size()));

    // Drain the 101 response header block (ends with CRLFCRLF).
    std::string response;
    for (int i = 0; i < 500; ++i) {
        char buf[512];
        int  n = sock.read(buf, sizeof(buf));
        if (n > 0)
            response.append(buf, static_cast<std::size_t>(n));
        if (response.find("\r\n\r\n") != std::string::npos)
            break;
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_NE(response.find("101"), std::string::npos) << "handshake failed:\n" << response;

    // --- 2. Send interleaved frames ------------------------------------
    // Frame A: Text, FIN=0, "Hel"
    auto frame_a = make_client_frame(0x01, "Hel");
    sock.write(reinterpret_cast<const char *>(frame_a.data()), static_cast<int>(frame_a.size()));

    // Frame B: Ping control frame, FIN=1, payload "P" (1 byte).
    // Per RFC 6455 §5.4 control frames MAY be injected in the middle of
    // a fragmented data message — the server must service them without
    // disturbing the reassembly buffer.
    auto frame_b = make_client_frame(0x89, "P");
    sock.write(reinterpret_cast<const char *>(frame_b.data()), static_cast<int>(frame_b.size()));

    // Frame C: Continuation, FIN=1, "lo"
    auto frame_c = make_client_frame(0x80, "lo");
    sock.write(reinterpret_cast<const char *>(frame_c.data()), static_cast<int>(frame_c.size()));

    // --- 3. Receive server response ------------------------------------
    // Expected from the server (in order):
    //   - Pong frame: 0x8A 0x01 'P'                    (3 bytes)
    //   - Text echo : 0x81 0x05 'H' 'e' 'l' 'l' 'o'    (7 bytes)
    const std::string got = read_some(sock, 10);
    ASSERT_GE(got.size(), 10u) << "only got " << got.size() << " bytes back: '" << got << "'";

    // Parse frame #1 (pong).
    EXPECT_EQ(static_cast<std::uint8_t>(got[0]), 0x8Au) << "frame#1 fin+opcode";
    EXPECT_EQ(static_cast<std::uint8_t>(got[1]), 0x01u) << "frame#1 len7";
    EXPECT_EQ(got[2], 'P') << "frame#1 payload";

    // Parse frame #2 (text echo).
    EXPECT_EQ(static_cast<std::uint8_t>(got[3]), 0x81u) << "frame#2 fin+opcode";
    EXPECT_EQ(static_cast<std::uint8_t>(got[4]), 0x05u) << "frame#2 len7";
    EXPECT_EQ(got.substr(5, 5), "Hello") << "server did not reassemble the fragmented text message";

    sock.close();
}

TEST_F(FramingEdgeTest, ZeroLengthTextFrameIsDeliveredAndEchoed) {
    ServerThread<EchoServer> server{19981};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{"tcp://localhost:19981"});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, 19981);

    auto frame = make_client_frame(0x81, ""); // FIN + text, empty payload
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    const std::string got = read_some(sock, 2);
    ASSERT_EQ(got.size(), 2u) << "empty text echo should be a 2-byte zero-length frame";
    EXPECT_EQ(static_cast<std::uint8_t>(got[0]), 0x81u);
    EXPECT_EQ(static_cast<std::uint8_t>(got[1]), 0x00u);

    sock.close();
}

TEST_F(FramingEdgeTest, ZeroLengthPingGetsZeroLengthPong) {
    ServerThread<EchoServer> server{19982};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{"tcp://localhost:19982"});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, 19982);

    auto frame = make_client_frame(0x89, ""); // FIN + ping, empty payload
    sock.write(reinterpret_cast<const char *>(frame.data()), static_cast<int>(frame.size()));

    const std::string got = read_some(sock, 2);
    ASSERT_EQ(got.size(), 2u) << "empty ping should receive a 2-byte empty pong";
    EXPECT_EQ(static_cast<std::uint8_t>(got[0]), 0x8Au);
    EXPECT_EQ(static_cast<std::uint8_t>(got[1]), 0x00u);

    sock.close();
}

TEST_F(FramingEdgeTest, FragmentedPayloadLimitIsEnforcedOnAggregateMessageSize) {
    ServerThread<BoundedServer> server{19973};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{"tcp://localhost:19973"});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);

    const std::string upgrade = "GET /edge HTTP/1.1\r\n"
                                "Host: localhost:19973\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                "Sec-WebSocket-Version: 13\r\n"
                                "\r\n";
    sock.write(upgrade.data(), static_cast<int>(upgrade.size()));

    std::string response;
    for (int i = 0; i < 500; ++i) {
        char buf[512];
        int  n = sock.read(buf, sizeof(buf));
        if (n > 0)
            response.append(buf, static_cast<std::size_t>(n));
        if (response.find("\r\n\r\n") != std::string::npos)
            break;
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_NE(response.find("101"), std::string::npos) << "handshake failed:\n" << response;

    // 40 + 40 bytes: each frame is under the 64-byte limit, but aggregate
    // fragmented message exceeds it and must be rejected with 1009.
    auto frame_a = make_client_frame(0x01, std::string(40, 'A'));
    auto frame_b = make_client_frame(0x80, std::string(40, 'B'));
    sock.write(reinterpret_cast<const char *>(frame_a.data()), static_cast<int>(frame_a.size()));
    sock.write(reinterpret_cast<const char *>(frame_b.data()), static_cast<int>(frame_b.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value()) << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::MessageTooBig));

    sock.close();
}

TEST_F(FramingEdgeTest, NonMinimalPayloadLengthEncodingIsRejected) {
    ServerThread<EchoServer> server{19974};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{"tcp://localhost:19974"});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);

    const std::string upgrade = "GET /edge HTTP/1.1\r\n"
                                "Host: localhost:19974\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                "Sec-WebSocket-Version: 13\r\n"
                                "\r\n";
    sock.write(upgrade.data(), static_cast<int>(upgrade.size()));

    std::string response;
    for (int i = 0; i < 500; ++i) {
        char buf[512];
        int  n = sock.read(buf, sizeof(buf));
        if (n > 0)
            response.append(buf, static_cast<std::size_t>(n));
        if (response.find("\r\n\r\n") != std::string::npos)
            break;
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_NE(response.find("101"), std::string::npos) << "handshake failed:\n" << response;

    // Build a text frame with payload length encoded as 126 + ext16(1), which
    // is non-minimal and must be rejected with 1002.
    std::vector<std::uint8_t> bad;
    bad.reserve(2 + 2 + 4 + 1);
    bad.push_back(0x81u);        // FIN + text
    bad.push_back(0x80u | 126u); // masked + extended16
    bad.push_back(0x00u);
    bad.push_back(0x01u); // actual payload length = 1 (invalid encoding form)
    constexpr std::array<std::uint8_t, 4> mask{{0x12, 0x34, 0x56, 0x78}};
    for (auto m : mask)
        bad.push_back(m);
    bad.push_back(static_cast<std::uint8_t>('X') ^ mask[0]);

    sock.write(reinterpret_cast<const char *>(bad.data()), static_cast<int>(bad.size()));

    const std::string got        = read_some(sock, 128);
    const auto        close_code = extract_close_code(got);
    ASSERT_TRUE(close_code.has_value()) << "server did not send a parseable close frame: size=" << got.size();
    EXPECT_EQ(*close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));

    sock.close();
}

TEST_F(FramingEdgeTest, RsvBitsAreRejected) {
    expect_close_code_after_frames(19976, {make_client_frame(0xC1, "x")}, // FIN + RSV1 + text
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST_F(FramingEdgeTest, FragmentedControlFrameIsRejected) {
    expect_close_code_after_frames(19977, {make_client_frame(0x09, "p")}, // Ping with FIN=0
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST_F(FramingEdgeTest, ContinuationWithoutInitialDataFrameIsRejected) {
    expect_close_code_after_frames(19978, {make_client_frame(0x80, "x")}, // FIN + continuation, no prior data frame
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST_F(FramingEdgeTest, NewDataFrameBeforeFinalContinuationIsRejected) {
    expect_close_code_after_frames(19979,
                                   {
                                       make_client_frame(0x01, "hel"), // Text, FIN=0
                                       make_client_frame(0x82, "bin")  // Binary, FIN=1 before continuation
                                   },
                                   qb::http::ws::CloseStatus::ProtocolError);
}

TEST_F(FramingEdgeTest, PayloadLength64MostSignificantBitIsRejected) {
    std::vector<std::uint8_t> bad;
    bad.reserve(2 + 8 + 4);
    bad.push_back(0x81u);        // FIN + text
    bad.push_back(0x80u | 127u); // masked + extended64
    bad.push_back(0x80u);        // invalid MSB set
    for (int i = 0; i < 7; ++i) {
        bad.push_back(0x00u);
    }
    bad.insert(bad.end(), {0x12u, 0x34u, 0x56u, 0x78u});

    expect_close_code_after_frames(19980, {bad}, qb::http::ws::CloseStatus::ProtocolError);
}

TEST_F(FramingEdgeTest, InvalidUtf8TextFrameIsRejectedWith1007) {
    ServerThread<EchoServer> server{19975};

    qb::io::tcp::socket sock;
    const auto          rc = sock.connect(qb::io::uri{"tcp://localhost:19975"});
    ASSERT_EQ(rc, 0);
    (void) sock.set_nonblocking(true);

    const std::string upgrade = "GET /edge HTTP/1.1\r\n"
                                "Host: localhost:19975\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                "Sec-WebSocket-Version: 13\r\n"
                                "\r\n";
    sock.write(upgrade.data(), static_cast<int>(upgrade.size()));

    std::string response;
    for (int i = 0; i < 500; ++i) {
        char buf[512];
        int  n = sock.read(buf, sizeof(buf));
        if (n > 0)
            response.append(buf, static_cast<std::size_t>(n));
        if (response.find("\r\n\r\n") != std::string::npos)
            break;
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_NE(response.find("101"), std::string::npos) << "handshake failed:\n" << response;

    // UTF-8 surrogate sequence U+D800 encoded as ED A0 80 is invalid.
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
//  Throwing frame handler must not terminate (noexcept onMessage backstop)
// ===========================================================================

class ThrowServer;

// Callback-style session: on(WS_Protocol::message&&) runs synchronously from
// the protocol's noexcept onMessage dispatch, so a throw here exercises exactly
// the boundary the backstop protects.
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

TEST_F(FramingEdgeTest, ThrowingMessageHandlerDoesNotTerminate) {
    ServerThread<ThrowServer> server{19984};

    auto scenario = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect("ws://localhost:19984/");
        EXPECT_TRUE(c.ok);
        if (!c.ok) {
            co_return qb::http::ws::IncomingFrame{};
        }

        qb::http::ws::MessageText msg;
        msg << std::string("hello");
        ws << msg;

        // The server handler throws; the onMessage backstop must fail the
        // connection rather than terminate, so the client observes a
        // close/disconnect and — crucially — the process is still alive.
        auto frame = co_await ws.receive();
        co_return frame;
    };

    const auto frame = qb::http::ws::run_sync(scenario());
    EXPECT_TRUE(frame.kind == qb::http::ws::IncomingFrame::Kind::Close || frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected)
        << "unexpected frame kind " << static_cast<int>(frame.kind);
}

} // namespace ws_framing_edge_test

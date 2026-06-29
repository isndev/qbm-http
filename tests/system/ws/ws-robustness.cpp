/**
 * @file qbm/http/tests/system/ws/ws-robustness.cpp
 * @brief WebSocket robustness over real loopback sockets: large frames,
 *        ping/pong content fidelity, fragmentation, and Close code/reason.
 *
 * De-flaked rewrite of the former `test-ws-robustness.cpp`. The original carried
 * a dead `DebugServer`/`DebugClient`, an empty `on(disconnected)`, `cout`/`cerr`
 * debug spam, a per-file `main()`, soft-failures (`cerr` + `return` instead of an
 * assertion), cross-thread `EXPECT`s, and fixed magic ports. This version:
 *
 *   - `LargeTextEchoExact`     — a 16 KiB text message round-trips and the echo
 *                                is compared byte-for-byte (content, not size).
 *   - `LargeBinaryEchoExact`   — a 16 KiB binary message (full byte range)
 *                                round-trips intact and arrives as binary.
 *   - `PingPongPayloadFidelity`— a client Ping with a payload yields a Pong
 *                                carrying the EXACT same bytes (RFC 6455 §5.5.3).
 *   - `FragmentedTextReassembled` — a raw client sends a text message split into
 *                                three continuation frames; the server reassembles
 *                                it and echoes the whole payload (§5.4).
 *   - `ServerClosePropagatesCodeAndReason` — the server initiates a Close with a
 *                                specific status code and reason; a raw client
 *                                reads the unmasked Close frame and decodes the
 *                                EXACT code and reason text (§5.5.1 / §7.4).
 *
 * Each test owns an ephemeral port (`ephemeral_port()`) and a server on a worker
 * thread (`WsServerThread`). The CRTP-client tests are driven on the main thread
 * with `pump_until(pred, budget)` (FAILS LOUD on timeout). The framing-sensitive
 * tests use a raw loopback socket via the shared `perform_upgrade` /
 * `make_client_frame` / `read_some` / `extract_close_code` helpers so the test
 * controls the exact bytes on the wire. All assertions run on the main thread.
 *
 * `ws/ws.h` `#error`s without `QB_HAS_SSL` (crypto-link only); these tests run
 * plaintext `ws://`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <atomic>
#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

#include <qb/io/async.h>

#include "../../shared/loopback_server.h"
#include "../../shared/ws_loopback.h"
#include "../ws/ws.h"

namespace ws_robustness_test {

using namespace std::chrono_literals;
using qb::http::test::ephemeral_port;
using qb::http::test::extract_close_code;
using qb::http::test::make_client_frame;
using qb::http::test::perform_upgrade;
using qb::http::test::read_some;
using qb::http::test::WsServerThread;

constexpr std::size_t kLargeSize = 16u * 1024u;

template <typename Pred>
bool
pump_until(Pred &&pred, std::chrono::milliseconds budget = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!pred()) {
        qb::io::async::run(EVRUN_NOWAIT);
        if (std::chrono::steady_clock::now() >= deadline) {
            return pred();
        }
        std::this_thread::sleep_for(1ms);
    }
    return true;
}

std::string
make_payload(std::size_t size) {
    std::string s;
    s.reserve(size);
    for (std::size_t i = 0; i < size; ++i) {
        s.push_back(static_cast<char>('A' + (i % 26)));
    }
    return s;
}

std::string
make_binary(std::size_t size) {
    std::string s;
    s.reserve(size);
    for (std::size_t i = 0; i < size; ++i) {
        s.push_back(static_cast<char>(i % 256));
    }
    return s;
}

// ===========================================================================
// Echo server (text + binary, auto-pong) for the CRTP-driven tests.
// ===========================================================================

class EchoServer;

class EchoServerClient : public qb::io::use<EchoServerClient>::tcp::client<EchoServer> {
public:
    using Protocol    = qb::http::protocol<EchoServerClient>;
    using WS_Protocol = qb::http::ws::protocol<EchoServerClient>;

    explicit EchoServerClient(IOServer &server)
        : client(server) {}

    void
    on(Protocol::request &&request) {
        if (!this->switch_protocol<WS_Protocol>(*this, request)) {
            disconnect();
        }
    }

    void
    on(WS_Protocol::message &&event) {
        *this << event.ws; // echo text/binary back, unmasked
    }

    void
    on(WS_Protocol::ping &&) {
        // Observation hook only. The WebSocket protocol auto-replies to an
        // inbound Ping with a Pong carrying the same payload (RFC 6455 §5.5.2/3),
        // so this handler MUST NOT send its own Pong — doing so would put a
        // duplicate Pong on the wire and break the "exactly one Pong" assertion.
    }

    void
    on(WS_Protocol::close &&) {
        disconnect();
    }
};

class EchoServer : public qb::io::use<EchoServer>::tcp::server<EchoServerClient> {
public:
    void
    on(IOSession &) {}
};

// ===========================================================================
// CRTP client for large-frame + ping/pong tests.
// ===========================================================================

class RobustClient : public qb::io::use<RobustClient>::tcp::client<> {
    const std::string _ws_key;
    int               _port;

public:
    using Protocol    = qb::http::protocol<RobustClient>;
    using WS_Protocol = qb::http::ws::protocol<RobustClient>;

    std::atomic<bool>        connected{false};
    std::atomic<std::size_t> text_received{0};
    std::atomic<std::size_t> binary_received{0};
    std::atomic<std::size_t> pongs{0};
    std::string              last_text;
    std::string              last_binary;
    std::string              last_pong;

    explicit RobustClient(int port)
        : _ws_key(qb::http::ws::generateKey())
        , _port(port) {}

    void
    send_handshake() {
        qb::http::WebSocketRequest r(_ws_key);
        r.uri() = "ws://localhost:" + std::to_string(_port) + "/";
        r.headers()["Host"].emplace_back("localhost:" + std::to_string(_port));
        *this << r;
    }

    void
    send_text(const std::string &text) {
        qb::http::ws::MessageText msg;
        msg.masked = true;
        msg << text;
        *this << msg;
    }

    void
    send_binary(const std::string &bytes) {
        qb::http::ws::MessageBinary msg;
        msg.masked = true;
        msg << bytes;
        *this << msg;
    }

    void
    send_ping(const std::string &payload) {
        qb::http::ws::MessagePing msg;
        msg.masked = true;
        msg << payload;
        *this << msg;
    }

    void
    on(Protocol::response &&response) {
        if (!this->switch_protocol<WS_Protocol>(*this, response, _ws_key)) {
            disconnect();
            return;
        }
        connected.store(true, std::memory_order_release);
    }

    void
    on(WS_Protocol::message &&event) {
        const std::string payload(event.data, event.size);
        if ((event.ws.fin_rsv_opcode & 0x0f) == 0x01) {
            last_text = payload;
            ++text_received;
        } else if ((event.ws.fin_rsv_opcode & 0x0f) == 0x02) {
            last_binary = payload;
            ++binary_received;
        }
    }

    void
    on(WS_Protocol::pong &&event) {
        last_pong = std::string(event.data, event.size);
        ++pongs;
    }

    void
    on(qb::io::async::event::disconnected &&) {
        connected.store(false, std::memory_order_release);
    }
};

// ===========================================================================
// Tests — large frames + ping/pong (CRTP)
// ===========================================================================

TEST(WsRobustness, LargeTextEchoExact) {
    const int                  port = ephemeral_port();
    WsServerThread<EchoServer> server{port};

    const std::string payload = make_payload(kLargeSize);

    RobustClient client{port};
    ASSERT_EQ(qb::io::SocketStatus::Done, client.transport().connect_v4("127.0.0.1", port));
    client.start();
    client.send_handshake();
    ASSERT_TRUE(pump_until([&] { return client.connected.load(); }));

    client.send_text(payload);
    ASSERT_TRUE(pump_until([&] { return client.text_received.load() == 1u; })) << "large text frame was not echoed";

    EXPECT_EQ(client.last_text.size(), payload.size());
    EXPECT_EQ(client.last_text, payload) << "large text payload must round-trip byte-for-byte";
}

TEST(WsRobustness, LargeBinaryEchoExact) {
    const int                  port = ephemeral_port();
    WsServerThread<EchoServer> server{port};

    const std::string payload = make_binary(kLargeSize);

    RobustClient client{port};
    ASSERT_EQ(qb::io::SocketStatus::Done, client.transport().connect_v4("127.0.0.1", port));
    client.start();
    client.send_handshake();
    ASSERT_TRUE(pump_until([&] { return client.connected.load(); }));

    client.send_binary(payload);
    ASSERT_TRUE(pump_until([&] { return client.binary_received.load() == 1u; })) << "large binary frame was not echoed";

    EXPECT_EQ(client.binary_received.load(), 1u);
    EXPECT_EQ(client.text_received.load(), 0u) << "binary frame must not arrive as text";
    EXPECT_EQ(client.last_binary.size(), payload.size());
    EXPECT_EQ(client.last_binary, payload) << "large binary payload must round-trip byte-for-byte";
}

TEST(WsRobustness, PingPongPayloadFidelity) {
    const int                  port = ephemeral_port();
    WsServerThread<EchoServer> server{port};

    RobustClient client{port};
    ASSERT_EQ(qb::io::SocketStatus::Done, client.transport().connect_v4("127.0.0.1", port));
    client.start();
    client.send_handshake();
    ASSERT_TRUE(pump_until([&] { return client.connected.load(); }));

    const std::string ping_payload = "ROBUSTNESS-PING-PAYLOAD";
    client.send_ping(ping_payload);

    ASSERT_TRUE(pump_until([&] { return client.pongs.load() == 1u; })) << "no Pong received for the Ping";

    EXPECT_EQ(client.pongs.load(), 1u);
    EXPECT_EQ(client.last_pong, ping_payload) << "Pong payload must equal the Ping payload (RFC 6455 §5.5.3)";
}

// ===========================================================================
// Framing-sensitive tests — raw socket (the wire bytes are controlled directly).
// ===========================================================================

// A raw client sends a text message split into three frames:
//   [FIN=0, text "Frag-"] [FIN=0, continuation "ment-"] [FIN=1, continuation "end"]
// The server must reassemble and echo the full "Frag-ment-end" payload (§5.4).
TEST(WsRobustness, FragmentedTextReassembled) {
    const int                  port = ephemeral_port();
    WsServerThread<EchoServer> server{port};

    qb::io::tcp::socket sock;
    ASSERT_EQ(sock.connect(qb::io::uri{"tcp://127.0.0.1:" + std::to_string(port)}), 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, port, "/");

    // opcode bytes: 0x01 = text/FIN0, 0x00 = continuation/FIN0, 0x80 = continuation/FIN1.
    const auto f1 = make_client_frame(0x01, "Frag-"); // text, not final
    const auto f2 = make_client_frame(0x00, "ment-"); // continuation, not final
    const auto f3 = make_client_frame(0x80, "end");   // continuation, final
    sock.write(reinterpret_cast<const char *>(f1.data()), static_cast<int>(f1.size()));
    sock.write(reinterpret_cast<const char *>(f2.data()), static_cast<int>(f2.size()));
    sock.write(reinterpret_cast<const char *>(f3.data()), static_cast<int>(f3.size()));

    // Server echoes the reassembled message back as a single unmasked text frame:
    // 2-byte header + 13-byte payload "Frag-ment-end".
    const std::string echoed = read_some(sock, 2u + 13u);
    ASSERT_GE(echoed.size(), 2u + 13u) << "server did not echo the reassembled message";

    const auto opcode = static_cast<std::uint8_t>(echoed[0]) & 0x0fu;
    EXPECT_EQ(opcode, 0x01u) << "echo must be a text frame";
    const auto len = static_cast<std::uint8_t>(echoed[1]) & 0x7fu;
    EXPECT_EQ(len, 13u) << "echo payload length must be the reassembled length";
    EXPECT_EQ(echoed.substr(2u, 13u), "Frag-ment-end") << "fragments must reassemble in order";

    sock.close();
}

// A server-side session that closes with a specific code + reason after the
// first message; a raw client decodes the unmasked Close frame and asserts the
// EXACT code (1001 GoingAway) and reason text (§5.5.1 / §7.4).
class CloseServer;

class CloseServerClient : public qb::io::use<CloseServerClient>::tcp::client<CloseServer> {
public:
    using Protocol    = qb::http::protocol<CloseServerClient>;
    using WS_Protocol = qb::http::ws::protocol<CloseServerClient>;

    explicit CloseServerClient(IOServer &server)
        : client(server) {}

    void
    on(Protocol::request &&request) {
        if (!this->switch_protocol<WS_Protocol>(*this, request)) {
            disconnect();
        }
    }

    void
    on(WS_Protocol::message &&) {
        qb::http::ws::MessageClose close(qb::http::ws::CloseStatus::GoingAway, "server-going-away");
        *this << close;
    }
};

class CloseServer : public qb::io::use<CloseServer>::tcp::server<CloseServerClient> {
public:
    void
    on(IOSession &) {}
};

TEST(WsRobustness, ServerClosePropagatesCodeAndReason) {
    const int                   port = ephemeral_port();
    WsServerThread<CloseServer> server{port};

    qb::io::tcp::socket sock;
    ASSERT_EQ(sock.connect(qb::io::uri{"tcp://127.0.0.1:" + std::to_string(port)}), 0);
    (void) sock.set_nonblocking(true);
    perform_upgrade(sock, port, "/");

    const auto trigger = make_client_frame(0x81, "trigger-close"); // text, final
    sock.write(reinterpret_cast<const char *>(trigger.data()), static_cast<int>(trigger.size()));

    // Read enough for the Close frame: 2-byte header + 2-byte code + reason.
    const std::string reason = "server-going-away";
    const std::string frame  = read_some(sock, 2u + 2u + reason.size());

    const auto code = extract_close_code(frame);
    ASSERT_TRUE(code.has_value()) << "server did not send a well-formed Close frame";
    EXPECT_EQ(*code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::GoingAway));

    // Decode the reason text following the 2-byte code (7-bit length form for this
    // short reason: header is 2 bytes, code starts at offset 2, reason at offset 4).
    ASSERT_GE(frame.size(), 2u + 2u + reason.size());
    EXPECT_EQ(frame.substr(4u, reason.size()), reason) << "Close reason text must match";

    sock.close();
}

} // namespace ws_robustness_test

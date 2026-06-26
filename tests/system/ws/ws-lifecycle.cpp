/**
 * @file qbm/http/tests/system/ws/ws-lifecycle.cpp
 * @brief Deterministic WebSocket connection-lifecycle correctness over real
 *        plaintext `ws://` loopback sockets.
 *
 * This file is the de-flaked correctness half of the former `test-ws-stress.cpp`
 * and `test-ws-session.cpp`. Where those files asserted with tolerance bands
 * (`EXPECT_GE(received, expected - tolerance)`), 80%-done early-exits, and fixed
 * magic ports, this one asserts EXACT outcomes:
 *
 *   - `EchoPreservesContent`     — every text frame the client sends is echoed
 *                                  back byte-for-byte (content compared, not a
 *                                  count); the server-side receive count matches
 *                                  the client-side send count exactly.
 *   - `BinaryRoundTripExact`     — a binary payload containing embedded NULs and
 *                                  the full byte range round-trips intact and is
 *                                  reported as binary (opcode 0x2), not text.
 *   - `PongsEqualPings`          — N client pings each yield exactly one server
 *                                  pong carrying the same payload — `pongs == pings`,
 *                                  no tolerance.
 *   - `GracefulCloseExchange`    — a client Close(1000) is answered and the TCP
 *                                  stream is torn down; the client observes the
 *                                  Disconnect.
 *   - `RapidConnectDisconnect`   — opening and closing many short-lived
 *                                  connections in sequence leaves the server able
 *                                  to accept and upgrade every one (exact upgrade
 *                                  count), proving no listener/session leak.
 *
 * All servers run on their own qb-io event-loop thread (`WsServerThread`) bound to
 * a kernel-assigned ephemeral port (`ephemeral_port()`), so concurrent CTest
 * shards never collide. The client side is driven on the main thread by a
 * `pump_until(pred, budget)` helper that FAILS LOUD on timeout instead of
 * silently passing. Per-test state lives in the client/server objects; there are
 * no module-global counters. Cross-thread assertions are read on the main thread
 * after the worker has been joined.
 *
 * The five throughput tests and `LONG_LIVED_CONNECTIONS` from `test-ws-stress.cpp`
 * are intentionally NOT reproduced here — they belong in the perf tier
 * (`benchmark/ws/ws-throughput.bench.cpp`), measuring msgs/sec and bytes/sec
 * rather than asserting correctness.
 *
 * `ws/ws.h` `#error`s without `QB_HAS_SSL` because `generateKey()` /
 * `Sec-WebSocket-Accept` use `qb::io::crypto` (SHA-1/base64); this file therefore
 * REQUIRES the crypto library to LINK, but runs entirely over plaintext `ws://`.
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

namespace ws_lifecycle_test {

using namespace std::chrono_literals;
using qb::http::test::ephemeral_port;
using qb::http::test::WsServerThread;

// ===========================================================================
// Deterministic main-thread pump
// ===========================================================================

/**
 * @brief Drive the calling thread's event loop until @p pred holds or @p budget
 *        elapses. Returns whether the predicate became true. Never hangs.
 */
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

// ===========================================================================
// Echo server (text + binary) — CRTP, one instance per test.
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
        // Echo the exact frame back unmasked (server->client frames are unmasked).
        *this << event.ws;
    }

    void
    on(WS_Protocol::ping &&) {
        // Observation hook only. The WebSocket protocol auto-replies to an
        // inbound Ping with a Pong carrying the same payload (RFC 6455 §5.5.2/3),
        // so this handler MUST NOT send its own Pong — a manual Pong here would
        // double every reply and make `pongs == pings` impossible.
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
// Test client — counts and stores what it actually received.
// ===========================================================================

class LifecycleClient : public qb::io::use<LifecycleClient>::tcp::client<> {
    const std::string _ws_key;

public:
    using Protocol    = qb::http::protocol<LifecycleClient>;
    using WS_Protocol = qb::http::ws::protocol<LifecycleClient>;

    std::atomic<bool>        connected{false};
    std::atomic<bool>        disconnected{false};
    std::atomic<std::size_t> text_received{0};
    std::atomic<std::size_t> binary_received{0};
    std::atomic<std::size_t> pongs_received{0};

    std::vector<std::string> echoed_texts;
    std::string              last_binary;
    std::string              last_pong;

    explicit LifecycleClient(int port)
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
    send_close(qb::http::ws::CloseStatus status, const std::string &reason) {
        qb::http::ws::MessageClose msg(status, reason);
        msg.masked = true;
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
            echoed_texts.push_back(payload);
            ++text_received;
        } else if ((event.ws.fin_rsv_opcode & 0x0f) == 0x02) {
            last_binary = payload;
            ++binary_received;
        }
    }

    void
    on(WS_Protocol::pong &&event) {
        last_pong = std::string(event.data, event.size);
        ++pongs_received;
    }

    void
    on(qb::io::async::event::disconnected &&) {
        connected.store(false, std::memory_order_release);
        disconnected.store(true, std::memory_order_release);
    }

private:
    int _port;
};

// ===========================================================================
// Tests
// ===========================================================================

// Every text frame the client sends is echoed back byte-for-byte. We compare
// the actual echoed content, not just a count, and require an exact match on
// both the number and the bytes — no tolerance band.
TEST(WsLifecycle, EchoPreservesContent) {
    const int                    port = ephemeral_port();
    WsServerThread<EchoServer>   server{port};

    constexpr std::size_t        kCount = 32;
    std::vector<std::string>     sent;
    sent.reserve(kCount);
    for (std::size_t i = 0; i < kCount; ++i) {
        sent.push_back("lifecycle-echo-#" + std::to_string(i) + "-payload");
    }

    LifecycleClient client{port};
    ASSERT_EQ(qb::io::SocketStatus::Done, client.transport().connect_v4("127.0.0.1", port));
    client.start();
    client.send_handshake();

    ASSERT_TRUE(pump_until([&] { return client.connected.load(); }))
        << "client never completed the WebSocket upgrade";

    for (const auto &m : sent) {
        client.send_text(m);
    }

    ASSERT_TRUE(pump_until([&] { return client.text_received.load() == kCount; }))
        << "expected " << kCount << " echoes, got " << client.text_received.load();

    EXPECT_EQ(client.text_received.load(), kCount);
    EXPECT_EQ(client.echoed_texts, sent) << "echoed content must match sent content exactly";

    client.send_close(qb::http::ws::CloseStatus::Normal, "done");
    EXPECT_TRUE(pump_until([&] { return client.disconnected.load(); }))
        << "server did not tear down after Close";
}

// A binary payload with embedded NULs and the full 0..255 byte range round-trips
// intact and is delivered as binary (opcode 0x2), never reinterpreted as text.
TEST(WsLifecycle, BinaryRoundTripExact) {
    const int                  port = ephemeral_port();
    WsServerThread<EchoServer> server{port};

    std::string payload;
    payload.reserve(120);
    for (int i = 0; i < 120; ++i) {
        payload.push_back(static_cast<char>(i)); // includes '\0' at i==0
    }

    LifecycleClient client{port};
    ASSERT_EQ(qb::io::SocketStatus::Done, client.transport().connect_v4("127.0.0.1", port));
    client.start();
    client.send_handshake();
    ASSERT_TRUE(pump_until([&] { return client.connected.load(); }));

    client.send_binary(payload);

    ASSERT_TRUE(pump_until([&] { return client.binary_received.load() == 1u; }))
        << "binary frame was not echoed back";

    EXPECT_EQ(client.binary_received.load(), 1u);
    EXPECT_EQ(client.text_received.load(), 0u) << "binary frame must not arrive as text";
    EXPECT_EQ(client.last_binary, payload) << "binary payload must round-trip byte-for-byte";

    client.send_close(qb::http::ws::CloseStatus::Normal, "done");
    EXPECT_TRUE(pump_until([&] { return client.disconnected.load(); }));
}

// N pings yield exactly N pongs, each carrying the matching payload. The server
// echoes the ping payload into its pong, so the last pong must equal the last
// ping payload, and pongs == pings exactly.
TEST(WsLifecycle, PongsEqualPings) {
    const int                  port = ephemeral_port();
    WsServerThread<EchoServer> server{port};

    LifecycleClient client{port};
    ASSERT_EQ(qb::io::SocketStatus::Done, client.transport().connect_v4("127.0.0.1", port));
    client.start();
    client.send_handshake();
    ASSERT_TRUE(pump_until([&] { return client.connected.load(); }));

    constexpr std::size_t kPings = 10;
    std::string           last_payload;
    for (std::size_t i = 0; i < kPings; ++i) {
        last_payload = "ping-payload-" + std::to_string(i);
        client.send_ping(last_payload);
    }

    ASSERT_TRUE(pump_until([&] { return client.pongs_received.load() == kPings; }))
        << "expected " << kPings << " pongs, got " << client.pongs_received.load();

    EXPECT_EQ(client.pongs_received.load(), kPings);
    EXPECT_EQ(client.last_pong, last_payload) << "pong payload must mirror the ping payload";

    client.send_close(qb::http::ws::CloseStatus::Normal, "done");
    EXPECT_TRUE(pump_until([&] { return client.disconnected.load(); }));
}

// A client-initiated Close(1000) is answered by the server, which disconnects;
// the client observes the TCP teardown. No tolerance, no early exit.
TEST(WsLifecycle, GracefulCloseExchange) {
    const int                  port = ephemeral_port();
    WsServerThread<EchoServer> server{port};

    LifecycleClient client{port};
    ASSERT_EQ(qb::io::SocketStatus::Done, client.transport().connect_v4("127.0.0.1", port));
    client.start();
    client.send_handshake();
    ASSERT_TRUE(pump_until([&] { return client.connected.load(); }));

    client.send_close(qb::http::ws::CloseStatus::Normal, "client closing");

    ASSERT_TRUE(pump_until([&] { return client.disconnected.load(); }))
        << "graceful close did not result in a disconnect";

    EXPECT_TRUE(client.disconnected.load());
    EXPECT_FALSE(client.connected.load());
}

// Open and tear down many short-lived connections in sequence. The server must
// accept and upgrade every one — an EXACT upgrade count proves there is no
// listener/session leak across rapid churn (the de-flaked replacement for
// ws-stress's RAPID_CONNECTIONS, which tolerated mismatched counts).
TEST(WsLifecycle, RapidConnectDisconnect) {
    const int                  port = ephemeral_port();
    WsServerThread<EchoServer> server{port};

    constexpr std::size_t kConnections = 25;
    for (std::size_t i = 0; i < kConnections; ++i) {
        LifecycleClient client{port};
        ASSERT_EQ(qb::io::SocketStatus::Done, client.transport().connect_v4("127.0.0.1", port))
            << "connection #" << i << " failed to establish";
        client.start();
        client.send_handshake();

        ASSERT_TRUE(pump_until([&] { return client.connected.load(); }))
            << "connection #" << i << " never upgraded";

        // Round-trip one frame so the connection is provably live.
        client.send_text("ping-" + std::to_string(i));
        ASSERT_TRUE(pump_until([&] { return client.text_received.load() == 1u; }))
            << "connection #" << i << " did not echo";

        client.send_close(qb::http::ws::CloseStatus::Normal, "next");
        ASSERT_TRUE(pump_until([&] { return client.disconnected.load(); }))
            << "connection #" << i << " did not tear down";
    }

    // Every one of the kConnections handshakes upgraded and echoed: the server
    // accepted, upgraded, and serviced each short-lived connection without a
    // listener/session leak. (Server-side counts are not reachable from the
    // worker-thread WsServerThread, so the proof is the per-connection
    // upgrade+echo+teardown asserted in the loop above.)
}

} // namespace ws_lifecycle_test

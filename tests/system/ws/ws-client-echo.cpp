/**
 * @file qbm/http/tests/system/ws/ws-client-echo.cpp
 * @brief Client-facing WebSocket echo lifecycle over real loopback sockets —
 *        the CRTP client, the callback `ws::client`, and the TLS handshake.
 *
 * Refined from the former `test-ws-client.cpp` (and absorbing the one unique
 * TLS-handshake assertion from the deleted `test-ws-session.cpp`). The original
 * asserted with vacuous predicates (`EXPECT_GE(pings_received, 0)`) and counted
 * messages without checking content. This version asserts EXACT content:
 *
 *   - `CrtpClientEchoesContent`     — the CRTP `tcp::client` performs the
 *                                     handshake, sends N distinct text frames,
 *                                     and verifies every echo matches the sent
 *                                     payload byte-for-byte (content, not count).
 *   - `CallbackClientEchoesContent` — the high-level callback `ws::client`
 *                                     (`on_connected` / `on_message` / ...) does
 *                                     the same round-trip; the `on_connected`
 *                                     callback fires exactly once and the echoed
 *                                     content matches.
 *   - `TlsHandshakeUpgrades`        — (QB_HAS_SSL) a secure `wss://` client
 *                                     completes the upgrade against a TLS server
 *                                     and round-trips one frame, proving the
 *                                     handshake path works over an encrypted
 *                                     transport. This is the single distinct
 *                                     assertion preserved from `ws-session`'s
 *                                     `WEBSOCKET_OVER_SECURE_TCP`.
 *
 * Each test uses its own server on a worker-thread event loop (`WsServerThread`)
 * bound to `:0` — the port is the kernel-assigned one read back from the serving
 * listener, not one probed and re-bound a moment later — and per-test client
 * state, no module-global counters. The main thread is pumped with
 * `pump_until(pred, budget)` which FAILS LOUD on timeout. There is no per-file
 * `main()`; the shared gtest_main drives the suite.
 *
 * `ws/ws.h` `#error`s without `QB_HAS_SSL` (crypto-link for `generateKey()` /
 * `Sec-WebSocket-Accept`); the plaintext tests still run over `ws://`, while the
 * TLS test additionally exercises the encrypted transport.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

#include <qb/io/async.h>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"
#include "../../shared/ws_loopback.h"
#include <qbm/http/ws/ws.h>

namespace ws_client_echo_test {

using namespace std::chrono_literals;
using qb::http::test::WsServerThread;

/**
 * @brief Port argument that makes @ref WsServerThread bind `:0` and publish what the kernel gave.
 *
 * NOT `ephemeral_port()`. That helper probes a free port with a throwaway listener and must close
 * it before the caller can bind, so between the probe closing and the server binding, another test
 * PROCESS can take the port — a real flake under `ctest -j` (measured at 2 failures in 12
 * full-suite runs in the http1 suites, and documented in `ephemeral_port()`'s own @warning).
 * Binding `:0` on the socket that actually serves leaves no window: `WsServerThread` reads the
 * assigned port back from the bound listener and publishes it in `server.port` before signalling
 * readiness, so the ctor returning means `server.port` is the live port.
 */
constexpr int kBindEphemeral = 0;

// ===========================================================================
// Deterministic main-thread pump
// ===========================================================================

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
// Plaintext echo server (CRTP).
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
        *this << event.ws;
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
// CRTP echo client.
// ===========================================================================

class CrtpEchoClient : public qb::io::use<CrtpEchoClient>::tcp::client<> {
    const std::string _ws_key;
    int               _port;

public:
    using Protocol    = qb::http::protocol<CrtpEchoClient>;
    using WS_Protocol = qb::http::ws::protocol<CrtpEchoClient>;

    std::atomic<bool>        connected{false};
    std::atomic<std::size_t> received{0};
    std::vector<std::string> echoed;

    explicit CrtpEchoClient(int port)
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
    send_close() {
        qb::http::ws::MessageClose msg(qb::http::ws::CloseStatus::Normal, "done");
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
        echoed.emplace_back(event.data, event.size);
        ++received;
    }

    void
    on(qb::io::async::event::disconnected &&) {
        connected.store(false, std::memory_order_release);
    }
};

// ===========================================================================
// Tests — plaintext
// ===========================================================================

// The CRTP client sends N distinct text frames; every echo must match the sent
// payload exactly (content compared, not just a received count).
TEST(WsClientEcho, CrtpClientEchoesContent) {
    WsServerThread<EchoServer> server{kBindEphemeral};
    ASSERT_NE(server.port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    const int port = server.port;

    constexpr std::size_t    kCount = 24;
    std::vector<std::string> sent;
    sent.reserve(kCount);
    for (std::size_t i = 0; i < kCount; ++i) {
        sent.push_back("crtp-msg-#" + std::to_string(i));
    }

    CrtpEchoClient client{port};
    ASSERT_EQ(qb::io::SocketStatus::Done, client.transport().connect_v4("127.0.0.1", port));
    client.start();
    client.send_handshake();
    ASSERT_TRUE(pump_until([&] { return client.connected.load(); })) << "CRTP client never upgraded";

    for (const auto &m : sent) {
        client.send_text(m);
    }
    ASSERT_TRUE(pump_until([&] { return client.received.load() == kCount; }))
        << "expected " << kCount << " echoes, got " << client.received.load();

    EXPECT_EQ(client.received.load(), kCount);
    EXPECT_EQ(client.echoed, sent) << "echoed content must match sent content exactly";

    client.send_close();
    EXPECT_TRUE(pump_until([&] { return !client.connected.load(); }));
}

// The high-level callback `ws::client` round-trips the same content. on_connected
// must fire exactly once; the collected echoes must match the sent payloads.
TEST(WsClientEcho, CallbackClientEchoesContent) {
    WsServerThread<EchoServer> server{kBindEphemeral};
    ASSERT_NE(server.port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    const int port = server.port;

    constexpr std::size_t    kCount = 16;
    std::vector<std::string> sent;
    sent.reserve(kCount);
    for (std::size_t i = 0; i < kCount; ++i) {
        sent.push_back("cb-msg-#" + std::to_string(i));
    }

    std::atomic<std::size_t> connected_calls{0};
    std::atomic<std::size_t> received{0};
    std::vector<std::string> echoed;

    qb::http::ws::client ws_client;
    ws_client.on_connected([&](auto &) { ++connected_calls; }).on_message([&](auto &event) {
        echoed.emplace_back(event.data, event.size);
        ++received;
    });

    qb::io::uri uri("ws://localhost:" + std::to_string(port) + "/");
    ws_client.connect(uri);

    ASSERT_TRUE(pump_until([&] { return connected_calls.load() >= 1; })) << "callback client never connected";

    for (const auto &m : sent) {
        qb::http::ws::MessageText msg;
        msg << m;
        ws_client << msg;
    }

    ASSERT_TRUE(pump_until([&] { return received.load() == kCount; })) << "expected " << kCount << " echoes, got " << received.load();

    EXPECT_EQ(connected_calls.load(), 1u) << "on_connected must fire exactly once";
    EXPECT_EQ(received.load(), kCount);
    EXPECT_EQ(echoed, sent) << "callback echoes must match sent content exactly";

    qb::http::ws::MessageClose close(qb::http::ws::CloseStatus::Normal, "done");
    ws_client << close;
    pump_until([] { return false; }, 100ms); // brief drain for the close frame
}

#ifdef QB_HAS_SSL

// ===========================================================================
// Secure (wss://) echo server + client — the one distinct assertion preserved
// from the deleted ws-session WEBSOCKET_OVER_SECURE_TCP: the WebSocket upgrade
// works over an encrypted transport and a frame round-trips.
// ===========================================================================

class SecureEchoServer;

class SecureEchoServerClient : public qb::io::use<SecureEchoServerClient>::tcp::ssl::client<SecureEchoServer> {
public:
    using Protocol    = qb::http::protocol<SecureEchoServerClient>;
    using WS_Protocol = qb::http::ws::protocol<SecureEchoServerClient>;

    explicit SecureEchoServerClient(IOServer &server)
        : client(server) {}

    void
    on(Protocol::request &&request) {
        if (!this->switch_protocol<WS_Protocol>(*this, request)) {
            disconnect();
        }
    }

    void
    on(WS_Protocol::message &&event) {
        *this << event.ws;
    }

    void
    on(WS_Protocol::close &&) {
        disconnect();
    }
};

class SecureEchoServer : public qb::io::use<SecureEchoServer>::tcp::ssl::server<SecureEchoServerClient> {
public:
    void
    on(IOSession &) {}
};

class SecureEchoClient : public qb::io::use<SecureEchoClient>::tcp::ssl::client<> {
    const std::string _ws_key;
    int               _port;

public:
    using Protocol    = qb::http::protocol<SecureEchoClient>;
    using WS_Protocol = qb::http::ws::protocol<SecureEchoClient>;

    std::atomic<bool> connected{false};
    std::atomic<bool> echoed_ok{false};

    explicit SecureEchoClient(int port)
        : _ws_key(qb::http::ws::generateKey())
        , _port(port) {}

    void
    send_handshake() {
        qb::http::WebSocketRequest r(_ws_key);
        r.uri() = "wss://localhost:" + std::to_string(_port) + "/";
        r.headers()["Host"].emplace_back("localhost:" + std::to_string(_port));
        *this << r;
    }

    void
    on(Protocol::response &&response) {
        if (!this->switch_protocol<WS_Protocol>(*this, response, _ws_key)) {
            disconnect();
            return;
        }
        connected.store(true, std::memory_order_release);
        qb::http::ws::MessageText msg;
        msg.masked = true;
        msg << "secure-echo";
        *this << msg;
    }

    void
    on(WS_Protocol::message &&event) {
        echoed_ok.store(std::string(event.data, event.size) == "secure-echo", std::memory_order_release);
    }

    void
    on(qb::io::async::event::disconnected &&) {
        connected.store(false, std::memory_order_release);
    }
};

TEST(WsClientEcho, TlsHandshakeUpgrades) {
    ASSERT_TRUE(qb::http::test::certs_available()) << "TLS test certificate/key not found; secure WS coverage cannot run";

    // The TLS server is configured on its own worker thread before it listens; the config callback
    // runs BEFORE listen_v4, so binding `:0` and reading the port back works exactly as it does for
    // the plaintext servers above.
    WsServerThread<SecureEchoServer> server{kBindEphemeral, [](SecureEchoServer &s) {
                                                s.transport().init(qb::io::ssl::Context::server(qb::http::test::ssl_cert_path(),
                                                                                                qb::http::test::ssl_key_path()));
                                            }};
    ASSERT_NE(server.port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    const int port = server.port;

    SecureEchoClient client{port};
    // Self-signed test certificate: opt out of qb-io's secure-by-default peer
    // verification for this local fixture (mirrors ws-session's set_insecure()).
    client.transport().set_insecure();
    ASSERT_EQ(qb::io::SocketStatus::Done, client.transport().connect_v4("127.0.0.1", port));
    client.start();
    client.send_handshake();

    ASSERT_TRUE(pump_until([&] { return client.connected.load(); })) << "secure WebSocket upgrade failed";
    ASSERT_TRUE(pump_until([&] { return client.echoed_ok.load(); })) << "secure echo frame did not round-trip";

    EXPECT_TRUE(client.connected.load());
    EXPECT_TRUE(client.echoed_ok.load());
}

#endif // QB_HAS_SSL

} // namespace ws_client_echo_test

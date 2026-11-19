/**
 * @file qbm/http/tests/system/ws/ws-client-hardening.cpp
 * @brief System-tier hardening tests: a `qb::http::ws::client` rejecting a hostile server.
 *
 * Each test spins up a deliberately misbehaving WebSocket server on its own
 * loopback event loop (via @ref qb::http::test::WsServerThread) and drives a real
 * callback `qb::http::ws::client` against it over plaintext `ws://`. The focus is
 * the *client* parser's RFC-6455 enforcement: a malformed server frame must make
 * the client `fail_connection()` — which (1) fires the client `error` event and
 * (2) emits a *masked* Close frame carrying a precise protocol close code
 * (1002 ProtocolError / 1007 DataNotConsistent / 1009 MessageTooBig). The
 * adversarial server reads that Close back off the wire and records the exact
 * code, so the assertions pin the protocol outcome rather than a vague
 * "errored || disconnected" disjunction.
 *
 * These tests run plaintext `ws://` over real loopback sockets — a SYSTEM tier —
 * but the WS module hard-`#error`s without `QB_HAS_SSL` because `generateKey()` /
 * `Sec-WebSocket-Accept` use `qb::io::crypto` (SHA-1/base64). The dependency is a
 * crypto-library *link* requirement, NOT a TLS transport; tag `ws`, REQUIRES ssl.
 *
 * Ports are ephemeral and come from the listener that ACTUALLY SERVES — every
 * @ref qb::http::test::WsServerThread here is constructed with port 0 and publishes
 * the kernel-assigned port (see @ref bound_port), so the suite is parallel-safe
 * across processes as well as within one; the loopback loops are driven by a
 * fail-loud @ref pump_until rather than fixed-iter sleeps; no module globals —
 * every test owns its server-side result struct.
 *
 * Split out of the former `tests/test-ws-api-hardening.cpp` (the 9 adversarial
 * loopback cases). The 7 pure serializer / token-validation cases moved to
 * `tests/unit/ws/ws-frame-encode-validation.cpp`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <qb/io/async.h>
#include <qb/io/stream.h>
#include <qb/io/tcp/socket.h>

#include "../../shared/loopback_server.h" // shared system-tier fixtures
#include "../../shared/ws_loopback.h"     // WsServerThread
#include <qbm/http/ws.h>

using namespace std::chrono_literals;

namespace ws_connect_lifetime_test {

// Keep the real connector and its deferred-failure dispatch, but remove kernel
// refusal timing and the closed-port TOCTOU from these lifetime witnesses.
class RefusingSocket : public qb::io::tcp::socket {
public:
    inline static unsigned connect_calls = 0;

    int
    n_connect(qb::io::endpoint const &) noexcept {
        ++connect_calls;
        qb::io::socket::set_last_errno(ECONNREFUSED);
        return -1;
    }

    int
    n_connect(qb::io::uri const &) noexcept {
        ++connect_calls;
        qb::io::socket::set_last_errno(ECONNREFUSED);
        return -1;
    }
};

struct RefusingTransport : qb::io::stream<RefusingSocket> {
    static constexpr bool
    is_secure() noexcept {
        return false;
    }
};

using RefusingClient = qb::http::ws::Client<RefusingTransport>;

struct OwnerState {
    bool entered   = false;
    int  destroyed = 0;
    int  resumed   = 0;
    bool connected = false;
};

class OwnedCoroClient : public qb::http::ws::coro_client<RefusingTransport> {
    OwnerState &_state;

public:
    explicit OwnedCoroClient(OwnerState &state)
        : _state(state) {}

    ~OwnedCoroClient() {
        ++_state.destroyed;
    }
};

qb::io::async::task<void>
connect_in_owned_frame(qb::io::uri remote, OwnerState &state) {
    // The task's pooled frame is not ASan-poisoned when freed. A heap-owned
    // client gives the late connector's raw-this access a real ASan witness.
    auto client       = std::make_unique<OwnedCoroClient>(state);
    state.entered     = true;
    const auto result = co_await client->connect(remote);
    ++state.resumed;
    state.connected = result.ok;
}

} // namespace ws_connect_lifetime_test

namespace {

static_assert(requires(qb::http::ws::client &client) {
    client.disconnect();
    client.disconnect(73);
    client.disconnect(qb::io::async::event::disconnect_reason::protocol_error);
});
static_assert(requires(qb::http::ws::client_secure &client) {
    client.disconnect(73);
    client.disconnect(qb::io::async::event::disconnect_reason::protocol_error);
});

// ---------------------------------------------------------------------------
// Ephemeral port: bind :0 on the socket that actually serves.
// ---------------------------------------------------------------------------

/**
 * @brief Port a started @ref qb::http::test::WsServerThread is really listening on.
 *
 * Every adversarial server in this file is constructed with port **0**: the kernel
 * assigns the port at `bind()` time and `WsServerThread` publishes it under its
 * readiness barrier, so by the time its ctor returns `server.port` is the real one.
 *
 * This is deliberately NOT `ephemeral_port()`. That helper documents the hole in its
 * own `@warning`: its probe listener must CLOSE before the caller can bind, so under
 * `ctest -j` another test PROCESS can take the port in that window — measured at 2
 * failures in 12 full-suite runs elsewhere in this suite. No workaround closes it
 * (holding the probe open stops the caller binding; SO_REUSEADDR does not make a
 * listening port shareable). Binding :0 on the socket that actually serves and reading
 * the assigned port back leaves no window at all.
 *
 * @return The kernel-assigned port, or 0 when the fixture is not listening — its ctor has already
 *         reported why (Huly QB-1125). Every caller ASSERTs on it, so the scenario stops there
 *         instead of driving its client at port 0 until its pump budget runs out.
 */
template <typename ServerT>
[[nodiscard]] int
bound_port(const qb::http::test::WsServerThread<ServerT> &server) {
    return server.listening() ? server.port : 0;
}

// ---------------------------------------------------------------------------
// Fail-loud loop pump for the client side (runs on the main thread's listener).
// ---------------------------------------------------------------------------

/**
 * @brief Pump the calling thread's async loop until @p pred holds or @p budget
 *        elapses. Returns true if the predicate became true; on timeout it
 *        ADD_FAILUREs (loud) and returns false — it never hangs the suite.
 */
template <typename Pred>
bool
pump_until(Pred &&pred, std::chrono::milliseconds budget = 3000ms) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_NOWAIT);
        if (pred()) {
            return true;
        }
        std::this_thread::sleep_for(1ms);
    }
    ADD_FAILURE() << "pump_until: predicate did not hold within budget";
    return false;
}

/// Decode an unmasked Close status code from a 2+ byte payload.
[[nodiscard]] std::uint16_t
decode_close_code(const char *data, std::size_t size) {
    if (size < 2u) {
        return 0u;
    }
    const auto hi = static_cast<std::uint8_t>(data[0]);
    const auto lo = static_cast<std::uint8_t>(data[1]);
    return static_cast<std::uint16_t>((hi << 8u) | lo);
}

// ---------------------------------------------------------------------------
// Shared per-test server result struct (NO module globals).
// ---------------------------------------------------------------------------

/**
 * @brief Records what the adversarial server observed from the client, so the
 *        main thread can assert it after the worker thread is joined.
 *
 * Cross-thread visibility is via atomics; the test pumps until `client_closed`
 * flips, then reads `client_close_code`.
 */
struct ServerProbeResult {
    std::atomic<bool>          client_closed{false};  ///< client emitted a Close frame
    std::atomic<std::uint16_t> client_close_code{0u}; ///< decoded code from that Close
    std::atomic<std::size_t>   client_pings{0u};      ///< client→server pings observed
};

// ===========================================================================
// 1. Control frames: client PING must be masked & accepted by the server parser
// ===========================================================================

class ControlProbeServer;

class ControlProbeSession : public qb::io::use<ControlProbeSession>::tcp::client<ControlProbeServer> {
public:
    using Protocol    = qb::http::protocol<ControlProbeSession>;
    using WS_Protocol = qb::http::ws::protocol<ControlProbeSession>;

    explicit ControlProbeSession(IOServer &server)
        : client(server) {}

    void
    on(Protocol::request &&request) {
        if (!this->switch_protocol<WS_Protocol>(*this, request)) {
            disconnect();
        }
    }

    void on(WS_Protocol::ping &&);

    void
    on(WS_Protocol::message &&) {}
    void
    on(WS_Protocol::pong &&) {}
    void
    on(WS_Protocol::close &&) {}
};

class ControlProbeServer : public qb::io::use<ControlProbeServer>::tcp::server<ControlProbeSession> {
public:
    ServerProbeResult *results = nullptr;

    void
    on(IOSession &) {}
};

void
ControlProbeSession::on(WS_Protocol::ping &&) {
    if (auto *r = this->server().results) {
        r->client_pings.fetch_add(1u);
    }
    this->disconnect();
}

TEST(WebSocketClientHardening, ClientControlFramesAreMaskedAndAcceptedByServer) {
    qb::io::async::init();

    ServerProbeResult                                  result;
    qb::http::test::WsServerThread<ControlProbeServer> server(0, [&](ControlProbeServer &s) { s.results = &result; });
    const int                                          port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    bool connected = false;

    qb::http::ws::client client;
    client.on_connected([&](auto &) {
        connected = true;
        qb::http::ws::MessagePing ping; // Must be masked by the client operator<<.
        client << ping;
    });
    client.connect(qb::io::uri("ws://localhost:" + std::to_string(port) + "/path"), 1000ms);

    ASSERT_TRUE(pump_until([&] { return result.client_pings.load() > 0u; }));

    EXPECT_TRUE(connected);
    EXPECT_EQ(result.client_pings.load(), 1u);
}

// ===========================================================================
// 2/3. Server handshake validation: malformed / non-base64 Sec-WebSocket-Key
// ===========================================================================

class HandshakeValidationServer;

class HandshakeValidationSession : public qb::io::use<HandshakeValidationSession>::tcp::client<HandshakeValidationServer> {
public:
    using Protocol    = qb::http::protocol<HandshakeValidationSession>;
    using WS_Protocol = qb::http::ws::protocol<HandshakeValidationSession>;

    explicit HandshakeValidationSession(IOServer &server)
        : client(server) {}

    void
    on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            if (static_cast<int>(response.status()) == 0) {
                response.status() = qb::http::status::BAD_REQUEST;
            }
            *this << response;
            this->disconnect();
            return;
        }
        *this << response;
        this->disconnect();
    }

    void
    on(WS_Protocol::message &&) {}
    void
    on(WS_Protocol::ping &&) {}
    void
    on(WS_Protocol::pong &&) {}
    void
    on(WS_Protocol::close &&) {}
};

class HandshakeValidationServer : public qb::io::use<HandshakeValidationServer>::tcp::server<HandshakeValidationSession> {
public:
    void
    on(IOSession &) {}
};

// Raw-socket helper: send a custom upgrade with a chosen key and return the
// server's HTTP response (status line + headers).
[[nodiscard]] std::string
drive_bad_key_handshake(int port, std::string_view key) {
    qb::io::tcp::socket sock;
    EXPECT_EQ(sock.connect(qb::io::uri{"tcp://localhost:" + std::to_string(port)}), 0);
    (void) sock.set_nonblocking(true);

    std::string request = "GET /path HTTP/1.1\r\n"
                          "Host: localhost:";
    request += std::to_string(port);
    request += "\r\n"
               "Upgrade: websocket\r\n"
               "Connection: Upgrade\r\n"
               "Sec-WebSocket-Key: ";
    request += key;
    request += "\r\n"
               "Sec-WebSocket-Version: 13\r\n"
               "\r\n";
    sock.write(request.data(), static_cast<int>(request.size()));
    return qb::http::test::read_http_response(sock);
}

TEST(WebSocketClientHardening, ServerRejectsMalformedSecWebSocketKey) {
    qb::io::async::init();

    qb::http::test::WsServerThread<HandshakeValidationServer> server(0);
    const int                                                 port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    // 24 'a' chars: valid base64 length but not a 16-byte nonce decode.
    const std::string response = drive_bad_key_handshake(port, "aaaaaaaaaaaaaaaaaaaaaaaa");

    EXPECT_EQ(response.find("101 Switching Protocols"), std::string::npos) << "Server must reject malformed Sec-WebSocket-Key";
    EXPECT_NE(response.find("400"), std::string::npos) << "Expected a BAD_REQUEST response, got:\n" << response;
}

TEST(WebSocketClientHardening, ServerRejectsNonBase64SecWebSocketKey) {
    qb::io::async::init();

    qb::http::test::WsServerThread<HandshakeValidationServer> server(0);
    const int                                                 port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    const std::string response = drive_bad_key_handshake(port, "!!!!!!!!!!!!!!!!!!!!!!!!");

    EXPECT_EQ(response.find("101 Switching Protocols"), std::string::npos) << "Server must reject non-base64 Sec-WebSocket-Key";
    EXPECT_NE(response.find("400"), std::string::npos) << "Expected a BAD_REQUEST response, got:\n" << response;
}

// ===========================================================================
// 4. Client rejects a server-offered subprotocol it never advertised.
// ===========================================================================

class BadSubprotocolServer;

class BadSubprotocolSession : public qb::io::use<BadSubprotocolSession>::tcp::client<BadSubprotocolServer> {
public:
    using Protocol    = qb::http::protocol<BadSubprotocolSession>;
    using WS_Protocol = qb::http::ws::protocol<BadSubprotocolSession>;

    explicit BadSubprotocolSession(IOServer &server)
        : client(server) {}

    void
    on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            disconnect();
            return;
        }
        response.headers()["Sec-WebSocket-Protocol"].clear();
        response.headers()["Sec-WebSocket-Protocol"].emplace_back(std::string("server-only.proto"));
        *this << response;
    }

    void
    on(WS_Protocol::message &&) {}
    void
    on(WS_Protocol::ping &&) {}
    void
    on(WS_Protocol::pong &&) {}
    void
    on(WS_Protocol::close &&) {}
};

class BadSubprotocolServer : public qb::io::use<BadSubprotocolServer>::tcp::server<BadSubprotocolSession> {
public:
    void
    on(IOSession &) {}
};

TEST(WebSocketClientHardening, ClientRejectsServerSubprotocolNotOffered) {
    qb::io::async::init();

    qb::http::test::WsServerThread<BadSubprotocolServer> server(0);
    const int                                            port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    bool connected = false;
    bool errored   = false;

    qb::http::ws::client client;
    client.add_subprotocol("chat.v1");
    client.on_connected([&](auto &) { connected = true; });
    client.on_error([&](auto &) { errored = true; });
    client.connect(qb::io::uri("ws://localhost:" + std::to_string(port) + "/path"), 1000ms);

    ASSERT_TRUE(pump_until([&] { return errored || connected; }));

    EXPECT_TRUE(errored);
    EXPECT_FALSE(connected);
}

// A valid 101 is accepted, but the same response must be rejected when the
// server selects an extension that the client never offered.
class ExtensionResponseServer;

class ExtensionResponseSession : public qb::io::use<ExtensionResponseSession>::tcp::client<ExtensionResponseServer> {
public:
    using Protocol    = qb::http::protocol<ExtensionResponseSession>;
    using WS_Protocol = qb::http::ws::protocol<ExtensionResponseSession>;

    explicit ExtensionResponseSession(IOServer &server)
        : client(server) {}

    void on(Protocol::request &&request);
    void on(qb::io::async::event::disconnected &&);
    void on(WS_Protocol::message &&);
    void
    on(WS_Protocol::ping &&) {}
    void
    on(WS_Protocol::pong &&) {}
    void
    on(WS_Protocol::close &&) {}
};

class ExtensionResponseServer : public qb::io::use<ExtensionResponseServer>::tcp::server<ExtensionResponseSession> {
public:
    bool               select_unoffered_extension        = false;
    bool               send_message_after_upgrade        = false;
    bool               send_second_message_after_upgrade = false;
    bool               disconnect_on_message             = false; ///< hang up, no Close frame: the client reads EOF
    bool               reply_to_message                  = false; ///< answer a client message with the text "reply"
    bool               answer_with_a_reserved_opcode     = false; ///< answer a client message with a frame no client accepts
    std::string        select_subprotocol;                        ///< the subprotocol the 101 names, when not empty
    std::atomic<int>  *requests                 = nullptr;
    std::atomic<int>  *closed                   = nullptr;
    std::atomic<bool> *client_offered_extension = nullptr;

    void
    on(IOSession &) {}
};

void
ExtensionResponseSession::on(Protocol::request &&request) {
    auto &probe = this->server();
    if (probe.client_offered_extension) {
        probe.client_offered_extension->store(request.has_header("Sec-WebSocket-Extensions"));
    }
    qb::http::Response response;
    if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
        disconnect();
        return;
    }
    if (probe.select_unoffered_extension) {
        response.headers()["Sec-WebSocket-Extensions"].emplace_back(std::string("permessage-deflate"));
    }
    if (!probe.select_subprotocol.empty()) {
        response.headers()["Sec-WebSocket-Protocol"].clear();
        response.headers()["Sec-WebSocket-Protocol"].emplace_back(probe.select_subprotocol);
    }
    *this << response;
    if (probe.send_message_after_upgrade) {
        qb::http::ws::MessageText message;
        message << "switch";
        *this << message;
        if (probe.send_second_message_after_upgrade) {
            qb::http::ws::MessageText second;
            second << "retired";
            *this << second;
        }
    }
    if (probe.requests) {
        probe.requests->fetch_add(1);
    }
}

void
ExtensionResponseSession::on(WS_Protocol::message &&) {
    if (this->server().answer_with_a_reserved_opcode) {
        // FIN + opcode 0xB, no payload: a control opcode RFC 6455 reserves -- a protocol error for whoever reads it.
        const std::string frame{static_cast<char>(0x8Bu), static_cast<char>(0x00)};
        std::memcpy(this->out().allocate_back(frame.size()), frame.data(), frame.size());
        this->ready_to_write();
        return;
    }
    if (this->server().reply_to_message) {
        qb::http::ws::MessageText reply;
        reply << "reply";
        *this << reply;
    }
    if (this->server().disconnect_on_message)
        this->disconnect();
}

void
ExtensionResponseSession::on(qb::io::async::event::disconnected &&) {
    if (auto *closed = this->server().closed)
        closed->fetch_add(1, std::memory_order_release);
}

void
run_extension_response_case(bool select_unoffered_extension) {
    qb::io::async::init();

    std::atomic<int>                                        requests{0};
    std::atomic<bool>                                       client_offered_extension{false};
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [&](ExtensionResponseServer &s) {
        s.select_unoffered_extension = select_unoffered_extension;
        s.requests                   = &requests;
        s.client_offered_extension   = &client_offered_extension;
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    int                  connected = 0;
    int                  errors    = 0;
    qb::http::ws::client client;
    client.on_connected([&](auto &) { ++connected; });
    client.on_error([&](auto &) { ++errors; });
    client.connect(qb::io::uri("ws://localhost:" + std::to_string(port) + "/path"), 1000ms);

    ASSERT_TRUE(pump_until([&] { return connected + errors > 0; }));
    EXPECT_EQ(requests.load(), 1);
    EXPECT_FALSE(client_offered_extension.load());
    EXPECT_EQ(connected + errors, 1);
    EXPECT_EQ(connected, select_unoffered_extension ? 0 : 1);
    EXPECT_EQ(errors, select_unoffered_extension ? 1 : 0);
    client.disconnect();
}

TEST(WebSocketClientHardening, ClientAcceptsValidResponseWithoutExtension) {
    run_extension_response_case(false);
}

TEST(WebSocketClientHardening, ClientRejectsServerExtensionNotOffered) {
    run_extension_response_case(true);
}

TEST(WebSocketClientHardening, ConnectedCallbackMayDestroyClient) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) { s.send_message_after_upgrade = true; });
    int                                                     callbacks = 0;
    int                                                     messages  = 0;
    auto                                                    client    = std::make_unique<qb::http::ws::client>();
    client->on_connected([&](auto &) {
        ++callbacks;
        client.reset();
    });
    client->on_message([&](auto &) { ++messages; });
    const int port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";
    client->connect(qb::io::uri("ws://localhost:" + std::to_string(port) + "/path"), 1s);
    ASSERT_TRUE(pump_until([&] { return callbacks == 1; }));
    EXPECT_FALSE(client);
    EXPECT_EQ(messages, 0);
}

TEST(WebSocketClientHardening, HandshakeErrorCallbackMayDestroyClient) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) { s.select_unoffered_extension = true; });
    int                                                     callbacks = 0;
    auto                                                    client    = std::make_unique<qb::http::ws::client>();
    client->on_error([&](auto &) {
        ++callbacks;
        client.reset();
    });
    const int port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";
    client->connect(qb::io::uri("ws://localhost:" + std::to_string(port) + "/path"), 1s);
    ASSERT_TRUE(pump_until([&] { return callbacks == 1; }));
    EXPECT_FALSE(client);
}

TEST(WebSocketClientHardening, HandshakeErrorCallbackCanReconnect) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> rejected(0,
                                                                     [](ExtensionResponseServer &s) { s.select_unoffered_extension = true; });
    qb::http::test::WsServerThread<ExtensionResponseServer> accepting(0);
    const qb::io::uri                                       first("ws://localhost:" + std::to_string(bound_port(rejected)) + "/path");
    const qb::io::uri                                       second("ws://localhost:" + std::to_string(bound_port(accepting)) + "/path");
    int                                                     errors    = 0;
    int                                                     connected = 0;
    qb::http::ws::client                                    client;
    client.on_error([&](auto &) {
        if (++errors == 1)
            client.connect(second, 2s);
    });
    client.on_connected([&](auto &) { ++connected; });
    client.connect(first, 1s);
    ASSERT_TRUE(pump_until([&] { return connected == 1 || errors > 1; }, 4000ms));
    EXPECT_EQ(errors, 1);
    EXPECT_EQ(connected, 1);
    client.disconnect();
}

TEST(WebSocketClientHardening, RequestHookDisconnectStopsUpgradeSend) {
    qb::io::async::init();
    std::atomic<int>                                        requests{0};
    std::atomic<int>                                        closed{0};
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [&](ExtensionResponseServer &s) {
        s.requests = &requests;
        s.closed   = &closed;
    });
    int                                                     errors = 0;
    std::string                                             host;
    {
        qb::http::ws::client client;
        client.on_sending_http_request([&](auto &event) {
            host = event.request.header("host");
            client.disconnect();
        });
        client.on_error([&](auto &) { ++errors; });
        client.connect(qb::io::uri("ws://localhost:" + std::to_string(bound_port(server)) + "/path"), 1s);
        ASSERT_TRUE(pump_until([&] { return errors == 1; }));
        EXPECT_EQ(client.out().size(), 0u);
    }
    ASSERT_TRUE(pump_until([&] { return closed.load(std::memory_order_acquire) == 1; }));
    EXPECT_EQ(requests.load(), 0);
    // The handshake's Host is the authority every protocol writes (qb::http::origin::authority, Huly
    // QB-1064): the non-default port kept.
    EXPECT_EQ(host, "localhost:" + std::to_string(bound_port(server)));
}

TEST(WebSocketClientHardening, RequestHookMayDestroyClient) {
    qb::io::async::init();
    std::atomic<int>                                        requests{0};
    std::atomic<int>                                        closed{0};
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [&](ExtensionResponseServer &s) {
        s.requests = &requests;
        s.closed   = &closed;
    });
    int                                                     hooks  = 0;
    auto                                                    client = std::make_unique<qb::http::ws::client>();
    client->on_sending_http_request([&](auto &) {
        ++hooks;
        client.reset();
    });
    client->connect(qb::io::uri("ws://localhost:" + std::to_string(bound_port(server)) + "/path"), 1s);
    ASSERT_TRUE(pump_until([&] { return hooks == 1; }));
    EXPECT_FALSE(client);
    ASSERT_TRUE(pump_until([&] { return closed.load(std::memory_order_acquire) == 1; }));
    EXPECT_EQ(requests.load(), 0);
}

TEST(WebSocketClientHardening, RequestHookDisconnectErrorMayDestroyClient) {
    qb::io::async::init();
    std::atomic<int>                                        requests{0};
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [&](ExtensionResponseServer &s) { s.requests = &requests; });
    int                                                     errors = 0;
    auto                                                    client = std::make_unique<qb::http::ws::client>();
    client->on_error([&](auto &) {
        ++errors;
        client.reset();
    });
    client->on_sending_http_request([&](auto &) { client->disconnect(); });
    client->connect(qb::io::uri("ws://localhost:" + std::to_string(bound_port(server)) + "/path"), 1s);
    ASSERT_TRUE(pump_until([&] { return errors == 1; }));
    EXPECT_FALSE(client);
    EXPECT_EQ(requests.load(), 0);
}

TEST(WebSocketClientHardening, ReconnectDropsFramePipelinedWithFirstUpgrade) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> first_server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade        = true;
        s.send_second_message_after_upgrade = true;
    });
    qb::http::test::WsServerThread<ExtensionResponseServer> second_server(0);
    const qb::io::uri                                       first("ws://localhost:" + std::to_string(bound_port(first_server)) + "/path");
    const qb::io::uri                                       second("ws://localhost:" + std::to_string(bound_port(second_server)) + "/path");
    int                                                     connected = 0;
    int                                                     messages  = 0;
    qb::http::ws::client                                    client;
    client.on_connected([&](auto &) {
        if (++connected == 1)
            client.connect(second, 2s);
    });
    client.on_message([&](auto &) { ++messages; });
    client.connect(first, 1s);
    ASSERT_TRUE(pump_until([&] { return connected == 2; }, 4000ms));
    EXPECT_EQ(messages, 0);
    client.disconnect();
}

TEST(WebSocketClientHardening, RequestHookReconnectSkipsRetiredUpgrade) {
    qb::io::async::init();
    std::atomic<int>                                        first_requests{0};
    std::atomic<int>                                        second_requests{0};
    qb::http::test::WsServerThread<ExtensionResponseServer> first_server(0, [&](ExtensionResponseServer &s) { s.requests = &first_requests; });
    qb::http::test::WsServerThread<ExtensionResponseServer> second_server(0,
                                                                          [&](ExtensionResponseServer &s) { s.requests = &second_requests; });
    const qb::io::uri                                       first("ws://localhost:" + std::to_string(bound_port(first_server)) + "/path");
    const qb::io::uri                                       second("ws://localhost:" + std::to_string(bound_port(second_server)) + "/path");
    int                                                     hooks     = 0;
    int                                                     connected = 0;
    qb::http::ws::client                                    client;
    client.on_sending_http_request([&](auto &) {
        if (++hooks == 1)
            client.connect(second, 2s);
    });
    client.on_connected([&](auto &) { ++connected; });
    client.connect(first, 1s);
    ASSERT_TRUE(pump_until([&] { return connected == 1; }, 4000ms));
    EXPECT_EQ(hooks, 2);
    EXPECT_EQ(first_requests.load(), 0);
    EXPECT_EQ(second_requests.load(), 1);
    client.disconnect();
}

TEST(WebSocketClientHardening, ReconnectDropsRetiredOutputBytes) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> first_server(0);
    qb::http::test::WsServerThread<ExtensionResponseServer> second_server(0);
    const qb::io::uri                                       first("ws://localhost:" + std::to_string(bound_port(first_server)) + "/path");
    const qb::io::uri                                       second("ws://localhost:" + std::to_string(bound_port(second_server)) + "/path");
    int                                                     connected = 0;
    qb::http::ws::client                                    client;
    client.on_connected([&](auto &) { ++connected; });
    client.connect(first, 1s);
    ASSERT_TRUE(pump_until([&] { return connected == 1; }));
    client.disconnect();
    client.out() << "STALE";
    client.connect(second, 2s);
    ASSERT_TRUE(pump_until([&] { return connected == 2; }, 4000ms));
    client.disconnect();
}

TEST(WebSocketClientHardening, EstablishedMessageCallbackCanReconnect) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> first_server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade        = true;
        s.send_second_message_after_upgrade = true;
    });
    qb::http::test::WsServerThread<ExtensionResponseServer> second_server(0);
    const qb::io::uri                                       first("ws://localhost:" + std::to_string(bound_port(first_server)) + "/path");
    const qb::io::uri                                       second("ws://localhost:" + std::to_string(bound_port(second_server)) + "/path");
    int                                                     connected = 0;
    int                                                     messages  = 0;
    std::string                                             order;
    qb::http::ws::client                                    client;
    client.on_connected([&](auto &) {
        ++connected;
        order.push_back('C');
    });
    client.on_message([&](auto &) {
        order.push_back('M');
        if (++messages == 1)
            client.connect(second, 2s);
    });
    client.connect(first, 1s);
    ASSERT_TRUE(pump_until([&] { return connected == 2; }, 4000ms));
    EXPECT_EQ(messages, 1);
    EXPECT_EQ(order, "CMC");
    client.disconnect();
}

// Counts the connector's connect attempts, and connects for real: whether a reconnect has started is
// read off the socket the connector opens for it.
class CountingSocket : public qb::io::tcp::socket {
public:
    inline static unsigned connect_calls = 0;

    int
    n_connect(qb::io::endpoint const &ep) noexcept {
        ++connect_calls;
        return qb::io::tcp::socket::n_connect(ep);
    }

    int
    n_connect(qb::io::uri const &u) noexcept {
        ++connect_calls;
        return qb::io::tcp::socket::n_connect(u);
    }
};

struct CountingTransport : qb::io::stream<CountingSocket> {
    static constexpr bool
    is_secure() noexcept {
        return false;
    }
};

// After the peer's EOF, qb-io's dispose() closes the client's transport itself (Huly QB-1060), so the
// cleanup the client deferred for it finds nothing to close. It must still clear the retirement it
// stood for: a connect() from the disconnect callback, which runs after it in the same drain, then
// starts at once. It used to find the old connection still marked retiring and wait one more loop
// pass for a launch that had nothing left to retire (Huly QB-1069).
TEST(WebSocketClientHardening, ReconnectAfterPeerEofStartsInTheSamePass) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> first_server(0, [](ExtensionResponseServer &s) { s.disconnect_on_message = true; });
    qb::http::test::WsServerThread<ExtensionResponseServer> second_server(0);
    const qb::io::uri                                       first("ws://127.0.0.1:" + std::to_string(bound_port(first_server)) + "/path");
    const qb::io::uri                                       second("ws://127.0.0.1:" + std::to_string(bound_port(second_server)) + "/path");
    CountingSocket::connect_calls                        = 0;
    int                                     connected    = 0;
    int                                     disconnected = 0;
    int                                     errors       = 0;
    unsigned                                before       = 0;
    unsigned                                after        = 0;
    qb::http::ws::Client<CountingTransport> client;
    client.on_connected([&](auto &) {
        if (++connected == 1) {
            qb::http::ws::MessageText hang_up;
            hang_up << "hang up";
            client << hang_up;
        }
    });
    client.on_error([&](auto &) { ++errors; });
    client.on_disconnected([&](auto &) {
        if (++disconnected == 1) {
            before = CountingSocket::connect_calls;
            client.connect(second, 2s);
            after = CountingSocket::connect_calls;
        }
    });
    client.connect(first, 2s);
    ASSERT_TRUE(pump_until([&] { return connected == 2 || errors > 0; }, 4000ms));
    EXPECT_EQ(errors, 0);
    EXPECT_EQ(disconnected, 1);
    EXPECT_GT(after, before) << "the reconnect requested after the peer's EOF did not start in the callback's pass";
    client.disconnect();
}

// What reaches a client is delivered in the order it happened, whatever its "connected" callback does. A frame the
// server sends with its 101 arrives before the client has been told it is connected: it waits for that. When the
// callback then PUMPS the loop -- it sends, and waits for the answer -- what the pump brings must come after the frame
// that was waiting, never before it:
//  - a second message was delivered at once, ahead of the first, which was held until the callback returned;
//  - the end of the connection was notified inside the pump, ahead of that first message -- since qb's loop drains
//    deferred callbacks under a nested turn (Huly QB-1246); before, the notification could not run there at all.
// Both pumps are bounded: against the client as it was these cases fail, they do not hang.
namespace ws_connected_pumps_test {

/// Loop turns until `done()`, or two seconds on a host too busy to answer: a callback's own wait.
template <typename Done>
void
pump_inside_the_callback(Done done) {
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!done() && std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(1ms);
    }
}

} // namespace ws_connected_pumps_test

TEST(WebSocketClientHardening, AMessageThatArrivesWhileConnectedPumpsComesAfterTheOneThatWasWaiting) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade = true; // "switch", sent with the 101
        s.reply_to_message           = true; // "reply", once the client has spoken
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::vector<std::string> events;
    qb::http::ws::client     client;
    client.on_connected([&](auto &) {
        events.emplace_back("connected");
        qb::http::ws::MessageText hello;
        hello << "hello";
        client << hello;
        ws_connected_pumps_test::pump_inside_the_callback([&] { return std::count(events.begin(), events.end(), "reply") != 0; });
        events.emplace_back("connected returns");
    });
    client.on_message([&](auto &event) { events.emplace_back(event.data, event.size); });
    client.connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return events.size() >= 4; }));
    EXPECT_EQ(events, (std::vector<std::string>{"connected", "switch", "reply", "connected returns"}))
        << "the message that arrived during the callback's pump was not delivered behind the one that was waiting";
    client.disconnect();
}

TEST(WebSocketClientHardening, TheEndOfTheConnectionWhileConnectedPumpsComesAfterTheMessageThatWasWaiting) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade = true; // "switch", sent with the 101
        s.disconnect_on_message      = true; // hangs up once the client has spoken
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::vector<std::string> events;
    qb::http::ws::client     client;
    client.on_connected([&](auto &) {
        events.emplace_back("connected");
        qb::http::ws::MessageText hello;
        hello << "hello";
        client << hello;
        ws_connected_pumps_test::pump_inside_the_callback([&] { return std::count(events.begin(), events.end(), "disconnected") != 0; });
        events.emplace_back("connected returns");
    });
    client.on_message([&](auto &event) { events.emplace_back(event.data, event.size); });
    client.on_disconnected([&](auto &) { events.emplace_back("disconnected"); });
    client.connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return events.size() >= 4; }));
    EXPECT_EQ(events, (std::vector<std::string>{"connected", "switch", "disconnected", "connected returns"}))
        << "the end of the connection was notified ahead of a message received before it";
    client.disconnect();
}

// The handler of an event that waited is the user's: it may destroy the client, or begin another connection. Either
// ends the delivery there -- nothing of the client is read again, and the connection it left is not said ended.
TEST(WebSocketClientHardening, AHandlerOfAMessageThatWaitedMayDestroyTheClient) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade        = true; // two frames with the 101: both wait for "connected"
        s.send_second_message_after_upgrade = true;
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    int  connected = 0;
    int  messages  = 0;
    auto client    = std::make_unique<qb::http::ws::client>();
    client->on_connected([&](auto &) { ++connected; });
    client->on_message([&](auto &) {
        ++messages;
        client.reset(); // under the first of the two
    });
    client->connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return messages >= 1; }));
    for (int turn = 0; turn < 50; ++turn) { // the second frame has nobody to reach
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(connected, 1);
    EXPECT_EQ(messages, 1) << "a frame that waited was delivered to a client its own handler had destroyed";
    EXPECT_FALSE(client);
}

TEST(WebSocketClientHardening, AConnectionReplacedByAHandlerOfAMessageThatWaitedIsNotSaidEnded) {
    // "connected" pumps; the first server hangs up; its end, before it is said, delivers the frame that waited -- and
    // that frame's handler connects elsewhere. The connection it replaced is the past: no "disconnected" for it.
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> first_server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade = true;
        s.disconnect_on_message      = true;
    });
    qb::http::test::WsServerThread<ExtensionResponseServer> second_server(0);
    const qb::io::uri                                       first("ws://127.0.0.1:" + std::to_string(bound_port(first_server)) + "/path");
    const qb::io::uri                                       second("ws://127.0.0.1:" + std::to_string(bound_port(second_server)) + "/path");

    std::vector<std::string> events;
    int                      connected = 0;
    qb::http::ws::client     client;
    client.on_connected([&](auto &) {
        events.emplace_back("connected");
        if (++connected == 1) {
            qb::http::ws::MessageText hello;
            hello << "hello";
            client << hello;
            ws_connected_pumps_test::pump_inside_the_callback([&] { return connected == 2; });
            events.emplace_back("connected returns");
        }
    });
    client.on_message([&](auto &event) {
        events.emplace_back(event.data, event.size);
        client.connect(second, 2s);
    });
    client.on_disconnected([&](auto &) { events.emplace_back("disconnected"); });
    client.connect(first, 2s);
    ASSERT_TRUE(pump_until([&] { return connected == 2; }, 5000ms));
    EXPECT_EQ(std::count(events.begin(), events.end(), "disconnected"), 0) << "the connection a handler had just replaced was said ended";
    ASSERT_GE(events.size(), 2u);
    EXPECT_EQ(events[0], "connected");
    EXPECT_EQ(events[1], "switch");
    client.disconnect();
}

TEST(WebSocketClientHardening, AConnectionBegunByAHandlerOfAMessageThatWaitedIsSaidConnectedBeforeItsOwnFrames) {
    // The delivery of what waited for "connected" is ONE connection's. The handler of the message it delivers begins
    // another connection and waits, inside the handler, until that one's 101 has been read -- its first frame with it,
    // which waits for a "connected" of its own. The end of that wait runs the loop's watchers and no deferred callback
    // (`loop().run()`, the loop's own call): when the handler returns, the second "connected" is still queued. Back in
    // the delivery it was called from, the frame now in the queue is not the next one to deliver: it is the other
    // connection's, and it goes behind that connection's "connected".
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> first_server(
        0, [](ExtensionResponseServer &s) { s.send_message_after_upgrade = true; });
    qb::http::test::WsServerThread<ExtensionResponseServer> second_server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade = true;
        s.select_subprotocol         = "chat.v1"; // what tells the handler below that the second 101 has been read
    });
    const qb::io::uri                                       first("ws://127.0.0.1:" + std::to_string(bound_port(first_server)) + "/path");
    const qb::io::uri                                       second("ws://127.0.0.1:" + std::to_string(bound_port(second_server)) + "/path");

    std::vector<std::string> events;
    int                      connected     = 0;
    int                      upgrades      = 0;
    bool                     replaced      = false;
    bool                     second_101_in = false;
    qb::http::ws::client     client;
    client.add_subprotocol("chat.v1");
    client.on_sending_http_request([&](auto &) { ++upgrades; });
    client.on_connected([&](auto &) { events.emplace_back("connected " + std::to_string(++connected)); });
    client.on_message([&](auto &event) {
        events.emplace_back(std::string(event.data, event.size) + " after connected " + std::to_string(connected));
        if (std::exchange(replaced, true))
            return;
        client.connect(second, 2s);
        // Until the second upgrade request leaves: loop turns, deferred callbacks included -- the connection needs them.
        ws_connected_pumps_test::pump_inside_the_callback([&] { return upgrades == 2; });
        // Then the loop alone until the 101 is in: its watchers run, no deferred callback does.
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (client.negotiated_subprotocol().empty() && std::chrono::steady_clock::now() < deadline) {
            qb::io::async::listener::current.loop().run(EVRUN_NOWAIT);
            std::this_thread::sleep_for(1ms);
        }
        second_101_in = !client.negotiated_subprotocol().empty() && connected == 1;
    });
    client.connect(first, 2s);
    ASSERT_TRUE(pump_until([&] { return events.size() >= 4; }, 5000ms));
    EXPECT_TRUE(second_101_in) << "the handler did not come back with the second 101 read and its \"connected\" still to run";
    EXPECT_EQ(events, (std::vector<std::string>{"connected 1", "switch after connected 1", "connected 2", "switch after connected 2"}))
        << "the first frame of a connection begun by a handler of a message that waited was delivered before its \"connected\"";
    client.disconnect();
}

TEST(WebSocketClientHardening, ADeliveryItsHandlerEndedLeavesTheNextConnectionsEventsWaiting) {
    // The same, with the other connection's 101 ALONE: its first frame arrives after the handler has returned. The
    // delivery that handler was called from finds nothing left in the queue, and must still leave the other
    // connection's events waiting for its "connected" -- a test of the connection made before each delivery only
    // would end the loop here and let events through. (The first server hangs up on what "connected" sends: the end
    // of that connection delivers the frame that waited, and a connection begun there, the old transport gone,
    // starts at once -- the loop alone can bring its 101.)
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> first_server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade = true;
        s.disconnect_on_message      = true;
    });
    qb::http::test::WsServerThread<ExtensionResponseServer> second_server(0, [](ExtensionResponseServer &s) {
        s.select_subprotocol = "chat.v1"; // the 101 alone; it tells the handler below that the 101 has been read
        s.reply_to_message   = true;      // "reply", once the client has spoken
    });
    const qb::io::uri                                       first("ws://127.0.0.1:" + std::to_string(bound_port(first_server)) + "/path");
    const qb::io::uri                                       second("ws://127.0.0.1:" + std::to_string(bound_port(second_server)) + "/path");

    std::vector<std::string> events;
    int                      connected = 0;
    bool                     replaced  = false;
    qb::http::ws::client     client;
    client.add_subprotocol("chat.v1");
    client.on_connected([&](auto &) {
        events.emplace_back("connected " + std::to_string(++connected));
        if (connected == 1) {
            qb::http::ws::MessageText hello;
            hello << "hello";
            client << hello;
            ws_connected_pumps_test::pump_inside_the_callback([&] { return connected == 2; });
        }
    });
    client.on_message([&](auto &event) {
        events.emplace_back(std::string(event.data, event.size) + " after connected " + std::to_string(connected));
        if (std::exchange(replaced, true))
            return;
        client.connect(second, 2s);
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (client.negotiated_subprotocol().empty() && std::chrono::steady_clock::now() < deadline)
            qb::io::async::listener::current.loop().run(EVRUN_NOWAIT);
        qb::http::ws::MessageText hi;
        hi << "hi";
        client << hi;
        // The write goes out at the pass that finds the socket writable -- the first: a connected socket is. Then
        // the answer lands in the socket while nothing reads it, and the handler returns.
        qb::io::async::listener::current.loop().run(EVRUN_NOWAIT);
        qb::io::async::listener::current.loop().run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(50ms);
    });
    client.on_disconnected([&](auto &) { events.emplace_back("disconnected"); });
    client.connect(first, 2s);
    ASSERT_TRUE(pump_until([&] { return connected == 2 && events.size() >= 4; }, 5000ms));
    for (int turn = 0; turn < 20; ++turn) { // nothing else follows
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(events, (std::vector<std::string>{"connected 1", "switch after connected 1", "connected 2", "reply after connected 2"}))
        << "the delivery its handler ended let through an event of the connection that handler began, before its \"connected\"";
    client.disconnect();
}

TEST(WebSocketClientHardening, AHandlerOfAMessageThatWaitedMayDestroyTheClientWhileConnectedPumps) {
    // "connected" pumps; the answer to what it sent arrives, and the frame that was waiting is delivered then. Its
    // handler destroys the client: it runs from the loop's deferred queue as it always did, never from under the
    // read of the frame that arrived -- the protocol and qb-io, which go on after that read, would be gone.
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade = true; // "switch", sent with the 101
        s.reply_to_message           = true; // "reply", once the client has spoken
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::vector<std::string> events;
    bool                     destroyed            = false;
    bool                     pumping              = false;
    bool                     destroyed_under_pump = false;
    auto                     client               = std::make_unique<qb::http::ws::client>();
    client->on_connected([&](auto &) {
        events.emplace_back("connected");
        qb::http::ws::MessageText hello;
        hello << "hello";
        *client << hello;
        // What this closure captured goes with the client: only locals from here.
        bool const *const gone     = &destroyed;
        bool *const       in_pump  = &pumping;
        const auto        deadline = std::chrono::steady_clock::now() + 2s;
        *in_pump                   = true;
        while (!*gone && std::chrono::steady_clock::now() < deadline) {
            qb::io::async::run(EVRUN_NOWAIT);
            std::this_thread::sleep_for(1ms);
        }
        *in_pump = false;
    });
    client->on_message([&](auto &event) {
        events.emplace_back(event.data, event.size);
        if (events.back() == "switch") {
            destroyed_under_pump = pumping;
            destroyed            = true;
            client.reset();
        }
    });
    client->connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return destroyed; }));
    for (int turn = 0; turn < 50; ++turn) { // "reply" has nobody to reach
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(events, (std::vector<std::string>{"connected", "switch"}));
    EXPECT_TRUE(destroyed_under_pump) << "the frame that waited was not delivered while \"connected\" pumped: the case proved nothing";
    EXPECT_FALSE(client);
}

TEST(WebSocketClientHardening, AHandlerOfAMessageThatWaitedMayDestroyTheClientOnceThePeerHasEnded) {
    // "connected" pumps; the server hangs up; the end, before it is said, delivers the frame that waited, and that
    // frame's handler destroys the client: the end is said to nobody, and nothing of the client is read again.
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade = true; // "switch", sent with the 101
        s.disconnect_on_message      = true; // hangs up once the client has spoken
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::vector<std::string> events;
    bool                     destroyed            = false;
    bool                     pumping              = false;
    bool                     destroyed_under_pump = false;
    auto                     client               = std::make_unique<qb::http::ws::client>();
    client->on_connected([&](auto &) {
        events.emplace_back("connected");
        qb::http::ws::MessageText hello;
        hello << "hello";
        *client << hello;
        // What this closure captured goes with the client: only locals from here.
        bool const *const gone     = &destroyed;
        bool *const       in_pump  = &pumping;
        const auto        deadline = std::chrono::steady_clock::now() + 2s;
        *in_pump                   = true;
        while (!*gone && std::chrono::steady_clock::now() < deadline) {
            qb::io::async::run(EVRUN_NOWAIT);
            std::this_thread::sleep_for(1ms);
        }
        *in_pump = false;
    });
    client->on_message([&](auto &event) {
        events.emplace_back(event.data, event.size);
        destroyed_under_pump = pumping;
        destroyed            = true;
        client.reset();
    });
    client->on_disconnected([&](auto &) { events.emplace_back("disconnected"); });
    client->connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return destroyed; }));
    for (int turn = 0; turn < 50; ++turn) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(events, (std::vector<std::string>{"connected", "switch"}));
    EXPECT_TRUE(destroyed_under_pump) << "the frame that waited was not delivered while \"connected\" pumped: the case proved nothing";
    EXPECT_FALSE(client);
}

TEST(WebSocketClientHardening, AHandlerOfAMessageThatWaitedPumpsForTheNextFrame) {
    // A delivery inside a delivery: "connected" pumps, and the answer to what it sent has the frame that waited
    // delivered -- whose handler sends in turn, and pumps for ITS answer. That second answer waits behind the first,
    // and is delivered inside the handler's pump: each event once, in the order they arrived.
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade = true; // "switch", sent with the 101
        s.reply_to_message           = true; // "reply", to every message of the client
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::vector<std::string> events;
    const auto               count = [&](char const *e) {
        return std::count(events.begin(), events.end(), e);
    };
    bool                 second_seen_inside = false;
    qb::http::ws::client client;
    client.on_connected([&](auto &) {
        events.emplace_back("connected");
        qb::http::ws::MessageText hello;
        hello << "hello";
        client << hello;
        ws_connected_pumps_test::pump_inside_the_callback([&] { return count("switch") != 0; });
        events.emplace_back("connected returns");
    });
    client.on_message([&](auto &event) {
        events.emplace_back(event.data, event.size);
        if (events.back() == "switch") {
            qb::http::ws::MessageText again;
            again << "again";
            client << again;
            ws_connected_pumps_test::pump_inside_the_callback([&] { return count("reply") == 2; });
            second_seen_inside = count("reply") == 2;
            events.emplace_back("switch returns");
        }
    });
    client.connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return count("connected returns") != 0 && count("switch returns") != 0; }, 6000ms));
    EXPECT_TRUE(second_seen_inside) << "the frame that waited behind another was not delivered inside the pump of a handler";
    EXPECT_EQ(events, (std::vector<std::string>{"connected", "switch", "reply", "reply", "switch returns", "connected returns"}));
    client.disconnect();
}

TEST(WebSocketClientHardening, AProtocolErrorWhileConnectedPumpsComesAfterTheMessageThatWasWaiting) {
    // The server answers what "connected" sent with a frame of a reserved opcode: a protocol error, notified from the
    // loop's deferred queue -- inside the pump. The message received before it is delivered before it.
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade    = true; // "switch", sent with the 101
        s.answer_with_a_reserved_opcode = true;
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::vector<std::string> events;
    const auto               has = [&](char const *e) {
        return std::count(events.begin(), events.end(), e) != 0;
    };
    const auto pos = [&](char const *e) {
        return std::find(events.begin(), events.end(), e) - events.begin();
    };
    qb::http::ws::client client;
    client.on_connected([&](auto &) {
        events.emplace_back("connected");
        qb::http::ws::MessageText hello;
        hello << "hello";
        client << hello;
        ws_connected_pumps_test::pump_inside_the_callback([&] { return has("error"); });
        events.emplace_back("connected returns");
    });
    client.on_message([&](auto &event) { events.emplace_back(event.data, event.size); });
    client.on_error([&](auto &) { events.emplace_back("error"); });
    client.on_disconnected([&](auto &) { events.emplace_back("disconnected"); });
    client.connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return has("connected returns") && has("switch") && has("error"); }, 6000ms));
    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events.front(), "connected");
    EXPECT_LT(pos("error"), pos("connected returns")) << "the error was not notified inside the pump: the case proved nothing";
    EXPECT_LT(pos("switch"), pos("error")) << "a protocol error was notified ahead of a message received before it";
    client.disconnect();
}

TEST(WebSocketClientHardening, AHandlerOfAMessageThatWaitedMayDestroyTheClientWhenAnErrorFollowsIt) {
    // The protocol error, before it is notified, delivers the frame that waited -- and that frame's handler destroys
    // the client: the error is notified to nobody, and nothing of the client is read again.
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade    = true; // "switch", sent with the 101
        s.answer_with_a_reserved_opcode = true;
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::vector<std::string> events;
    bool                     destroyed            = false;
    bool                     pumping              = false;
    bool                     destroyed_under_pump = false;
    auto                     client               = std::make_unique<qb::http::ws::client>();
    client->on_connected([&](auto &) {
        events.emplace_back("connected");
        qb::http::ws::MessageText hello;
        hello << "hello";
        *client << hello;
        // What this closure captured goes with the client: only locals from here.
        bool const *const gone     = &destroyed;
        bool *const       in_pump  = &pumping;
        const auto        deadline = std::chrono::steady_clock::now() + 2s;
        *in_pump                   = true;
        while (!*gone && std::chrono::steady_clock::now() < deadline) {
            qb::io::async::run(EVRUN_NOWAIT);
            std::this_thread::sleep_for(1ms);
        }
        *in_pump = false;
    });
    client->on_message([&](auto &event) {
        events.emplace_back(event.data, event.size);
        destroyed_under_pump = pumping;
        destroyed            = true;
        client.reset();
    });
    client->on_error([&](auto &) { events.emplace_back("error"); });
    client->connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return destroyed; }, 6000ms));
    for (int turn = 0; turn < 50; ++turn) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(events, (std::vector<std::string>{"connected", "switch"}));
    EXPECT_TRUE(destroyed_under_pump) << "the frame that waited was not delivered while \"connected\" pumped: the case proved nothing";
    EXPECT_FALSE(client);
}

TEST(WebSocketClientHardening, ADisconnectFromAMessageThatWaitedSilencesTheErrorThatFollowedIt) {
    // The same error, the same delivery before it -- and the handler disconnects: an error of a connection its user
    // has ended is not notified, as it was not when the user disconnected before the notification ran.
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade    = true; // "switch", sent with the 101
        s.answer_with_a_reserved_opcode = true;
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::vector<std::string> events;
    const auto               has = [&](char const *e) {
        return std::count(events.begin(), events.end(), e) != 0;
    };
    qb::http::ws::client client;
    client.on_connected([&](auto &) {
        events.emplace_back("connected");
        qb::http::ws::MessageText hello;
        hello << "hello";
        client << hello;
        ws_connected_pumps_test::pump_inside_the_callback([&] { return has("disconnected"); });
        events.emplace_back("connected returns");
    });
    client.on_message([&](auto &event) {
        events.emplace_back(event.data, event.size);
        client.disconnect();
    });
    client.on_error([&](auto &) { events.emplace_back("error"); });
    client.on_disconnected([&](auto &) { events.emplace_back("disconnected"); });
    client.connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return has("connected returns") && has("disconnected"); }, 6000ms));
    for (int turn = 0; turn < 50; ++turn) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(events, (std::vector<std::string>{"connected", "switch", "disconnected", "connected returns"}));
}

// The client's own disconnect() ends what was waiting with the connection, as it ends the frames still in the read
// buffer: nothing is delivered behind it but "disconnected".
TEST(WebSocketClientHardening, ADisconnectFromConnectedDeliversNoFrameThatWasWaiting) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade        = true; // "switch"
        s.send_second_message_after_upgrade = true; // "retired"
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::vector<std::string> events;
    qb::http::ws::client     client;
    client.on_connected([&](auto &) {
        events.emplace_back("connected");
        client.disconnect();
    });
    client.on_message([&](auto &event) { events.emplace_back(event.data, event.size); });
    client.on_disconnected([&](auto &) { events.emplace_back("disconnected"); });
    client.connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return std::count(events.begin(), events.end(), "disconnected") != 0; }));
    for (int turn = 0; turn < 50; ++turn) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(events, (std::vector<std::string>{"connected", "disconnected"}))
        << "a frame that was waiting was delivered after the client's own disconnect()";
}

TEST(WebSocketClientHardening, ADisconnectFromAMessageThatWaitedDeliversNoneOfThoseBehindIt) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade        = true;
        s.send_second_message_after_upgrade = true;
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::vector<std::string> events;
    qb::http::ws::client     client;
    client.on_connected([&](auto &) { events.emplace_back("connected"); });
    client.on_message([&](auto &event) {
        events.emplace_back(event.data, event.size);
        if (events.size() == 2)
            client.disconnect(); // from the first of the two that waited
    });
    client.on_disconnected([&](auto &) { events.emplace_back("disconnected"); });
    client.connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return std::count(events.begin(), events.end(), "disconnected") != 0; }));
    for (int turn = 0; turn < 50; ++turn) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(events, (std::vector<std::string>{"connected", "switch", "disconnected"}))
        << "a frame that was waiting was delivered after the client's own disconnect()";
}

TEST(WebSocketClientHardening, ADisconnectFromAMessageThatWaitedOnAConnectionThePeerEndedIsStillToldItEnded) {
    // "connected" pumps; the server hangs up; the end, before it is said, delivers the frame that waited -- and that
    // frame's handler disconnects. The connection had ended already: its user is told so, once.
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0, [](ExtensionResponseServer &s) {
        s.send_message_after_upgrade = true; // "switch", sent with the 101
        s.disconnect_on_message      = true; // hangs up once the client has spoken
    });
    const int                                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::vector<std::string> events;
    qb::http::ws::client     client;
    client.on_connected([&](auto &) {
        events.emplace_back("connected");
        qb::http::ws::MessageText hello;
        hello << "hello";
        client << hello;
        ws_connected_pumps_test::pump_inside_the_callback([&] { return std::count(events.begin(), events.end(), "disconnected") != 0; });
        events.emplace_back("connected returns");
    });
    client.on_message([&](auto &event) {
        events.emplace_back(event.data, event.size);
        client.disconnect();
    });
    client.on_disconnected([&](auto &) { events.emplace_back("disconnected"); });
    client.connect(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return events.size() >= 4; }));
    for (int turn = 0; turn < 50; ++turn) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(events, (std::vector<std::string>{"connected", "switch", "disconnected", "connected returns"}));
}

// TCP establishment is only the first phase of connect(timeout). Hold the
// upgrade response indefinitely after receiving a valid request, and require
// the client's requested deadline to finish the operation exactly once.
class WithheldUpgradeServer;

class WithheldUpgradeSession : public qb::io::use<WithheldUpgradeSession>::tcp::client<WithheldUpgradeServer> {
public:
    using Protocol = qb::http::protocol<WithheldUpgradeSession>;

    explicit WithheldUpgradeSession(IOServer &server)
        : client(server) {}

    void on(Protocol::request &&);
    void on(qb::io::async::event::disconnected &&);
};

class WithheldUpgradeServer : public qb::io::use<WithheldUpgradeServer>::tcp::server<WithheldUpgradeSession> {
public:
    bool                                        disconnect_on_request = false;
    std::atomic<int>                           *requests              = nullptr;
    std::atomic<int>                           *closed                = nullptr;
    std::atomic<std::chrono::nanoseconds::rep> *request_time_ns       = nullptr;

    void
    on(IOSession &) {}
};

void
WithheldUpgradeSession::on(Protocol::request &&) {
    auto &probe = this->server();
    if (probe.request_time_ns) {
        probe.request_time_ns->store(
            std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(),
            std::memory_order_relaxed);
    }
    if (auto *requests = probe.requests) {
        requests->fetch_add(1, std::memory_order_release);
    }
    if (probe.disconnect_on_request)
        this->disconnect();
}

void
WithheldUpgradeSession::on(qb::io::async::event::disconnected &&) {
    if (auto *closed = this->server().closed)
        closed->fetch_add(1, std::memory_order_release);
}

TEST(WebSocketClientHardening, DestroyedClientsIgnorePendingConnectorCallbacks) {
    qb::io::async::init();

    std::atomic<int>                                      requests{0};
    std::atomic<int>                                      closed{0};
    qb::http::test::WsServerThread<WithheldUpgradeServer> server(0, [&](WithheldUpgradeServer &s) {
        s.requests = &requests;
        s.closed   = &closed;
    });
    const int                                             port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";
    const qb::io::uri remote("ws://localhost:" + std::to_string(port) + "/path");

    {
        qb::http::ws::client client;
        client.connect(remote, 1s);
    }
    {
        auto client = std::make_unique<qb::http::ws::client>();
        client->connect(remote, 1s);
    }

    // The server sees both transports close only after the connector has
    // delivered them. Neither expired client may send an Upgrade request.
    ASSERT_TRUE(pump_until([&] { return closed.load(std::memory_order_acquire) == 2; }, 2500ms));
    EXPECT_EQ(requests.load(std::memory_order_acquire), 0);
}

TEST(WebSocketClientHardening, DestroyedClientIgnoresDeferredConnectorFailure) {
    qb::io::async::init();
    using ws_connect_lifetime_test::RefusingClient;
    const qb::io::uri remote("ws://127.0.0.1:1/path");
    int               expired_errors = 0;
    auto              client         = std::make_unique<RefusingClient>();
    client->on_error([&](auto &) { ++expired_errors; });
    ws_connect_lifetime_test::RefusingSocket::connect_calls = 0;
    client->connect(remote);
    ASSERT_GT(ws_connect_lifetime_test::RefusingSocket::connect_calls, 0u);
    ASSERT_TRUE(qb::io::async::listener::current.has_deferred());
    EXPECT_EQ(expired_errors, 0) << "the connector failure must not run inline";
    client.reset();

    bool drained = false;
    qb::io::async::defer([&] { drained = true; });
    qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(drained) << "barrier follows the already queued connector failure";
    // A failure also queues the WebSocket error at the tail. Two passes
    // cover both snapshot drains, whether libev ran the defer wake or not.
    qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_EQ(expired_errors, 0);

    // Positive control: the same connector still reports one failure to an
    // owner that remains alive. No timer or network completion is involved.
    int            live_errors = 0;
    RefusingClient live;
    live.on_error([&](auto &) { ++live_errors; });
    ws_connect_lifetime_test::RefusingSocket::connect_calls = 0;
    live.connect(remote);
    ASSERT_GT(ws_connect_lifetime_test::RefusingSocket::connect_calls, 0u);
    EXPECT_EQ(live_errors, 0);
    drained = false;
    qb::io::async::defer([&] { drained = true; });
    qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(drained);
    qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_EQ(live_errors, 1);
}

TEST(WebSocketClientHardening, DestroyedCoroutineOwnerIgnoresDeferredConnectorFailure) {
    qb::io::async::init();
    using ws_connect_lifetime_test::connect_in_owned_frame;
    using ws_connect_lifetime_test::OwnerState;
    const qb::io::uri remote("ws://127.0.0.1:1/path");
    OwnerState        expired;
    {
        ws_connect_lifetime_test::RefusingSocket::connect_calls = 0;
        auto owner                                              = connect_in_owned_frame(remote, expired);
        owner.handle().resume();
        ASSERT_GT(ws_connect_lifetime_test::RefusingSocket::connect_calls, 0u);
        ASSERT_TRUE(expired.entered);
        ASSERT_FALSE(owner.handle().done()) << "owner must be parked on connect";
        ASSERT_TRUE(qb::io::async::listener::current.has_deferred());
        EXPECT_EQ(expired.resumed, 0);
        EXPECT_EQ(expired.destroyed, 0);
    }
    ASSERT_EQ(expired.destroyed, 1) << "destroying the frame must also destroy its client";
    bool drained = false;
    qb::io::async::defer([&] { drained = true; });
    qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(drained);
    qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_EQ(expired.resumed, 0);
    EXPECT_EQ(expired.destroyed, 1);

    OwnerState live;
    ws_connect_lifetime_test::RefusingSocket::connect_calls = 0;
    auto owner                                              = connect_in_owned_frame(remote, live);
    owner.handle().resume();
    ASSERT_GT(ws_connect_lifetime_test::RefusingSocket::connect_calls, 0u);
    ASSERT_TRUE(live.entered);
    ASSERT_FALSE(owner.handle().done());
    drained = false;
    qb::io::async::defer([&] { drained = true; });
    qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(drained);
    qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(owner.handle().done()) << "live owner must resume through the real awaiter/scheduler";
    EXPECT_NO_THROW(owner.await_resume());
    EXPECT_EQ(live.resumed, 1);
    EXPECT_FALSE(live.connected);
    EXPECT_EQ(live.destroyed, 1);
}

TEST(WebSocketClientHardening, RemoteCloseBeforeUpgradeFailsPendingConnect) {
    qb::io::async::init();
    qb::http::test::WsServerThread<WithheldUpgradeServer> server(0, [](WithheldUpgradeServer &s) { s.disconnect_on_request = true; });
    int                                                   errors    = 0;
    int                                                   connected = 0;
    qb::http::ws::client                                  client;
    client.on_error([&](auto &) { ++errors; });
    client.on_connected([&](auto &) { ++connected; });
    client.connect(qb::io::uri("ws://localhost:" + std::to_string(bound_port(server)) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return errors > 0 || connected > 0; }));
    EXPECT_EQ(errors, 1);
    EXPECT_EQ(connected, 0);
}

TEST(WebSocketClientHardening, PendingDisconnectForwardsTypedReason) {
    qb::io::async::init();
    std::atomic<int>                                      requests{0};
    qb::http::test::WsServerThread<WithheldUpgradeServer> server(0, [&](WithheldUpgradeServer &s) { s.requests = &requests; });
    int                                                   errors       = 0;
    int                                                   disconnected = 0;
    int                                                   reason       = 0;
    qb::http::ws::client                                  client;
    client.on_error([&](auto &) { ++errors; });
    client.on_disconnected([&](auto &event) {
        ++disconnected;
        reason = event.reason;
    });
    client.connect(qb::io::uri("ws://localhost:" + std::to_string(bound_port(server)) + "/path"), 2s);
    ASSERT_TRUE(pump_until([&] { return requests.load(std::memory_order_acquire) == 1; }));
    client.disconnect(qb::io::async::event::disconnect_reason::protocol_error);
    ASSERT_TRUE(pump_until([&] { return disconnected == 1; }));
    EXPECT_EQ(errors, 1);
    EXPECT_EQ(reason, static_cast<int>(qb::io::async::event::disconnect_reason::protocol_error));
}

TEST(WebSocketClientHardening, EstablishedDisconnectForwardsIntegerReason) {
    qb::io::async::init();
    qb::http::test::WsServerThread<ExtensionResponseServer> server(0);
    int                                                     connected    = 0;
    int                                                     disconnected = 0;
    int                                                     reason       = 0;
    qb::http::ws::client                                    client;
    client.on_connected([&](auto &) { ++connected; });
    client.on_disconnected([&](auto &event) {
        ++disconnected;
        reason = event.reason;
    });
    client.connect(qb::io::uri("ws://localhost:" + std::to_string(bound_port(server)) + "/path"), 1s);
    ASSERT_TRUE(pump_until([&] { return connected == 1; }));
    client.disconnect(73);
    ASSERT_TRUE(pump_until([&] { return disconnected == 1; }));
    EXPECT_EQ(connected, 1);
    EXPECT_EQ(reason, 73);
}

TEST(WebSocketClientHardening, ClientDeadlineIncludesUpgradeResponse) {
    qb::io::async::init();

    constexpr auto                             requested_timeout = 3s;
    std::atomic<int>                           requests{0};
    std::atomic<std::chrono::nanoseconds::rep> request_time_ns{0};
    int                                        connected = 0;
    int                                        errors    = 0;
    qb::http::ws::client                       client;
    client.on_connected([&](auto &) { ++connected; });
    client.on_error([&](auto &) { ++errors; });

    {
        qb::http::test::WsServerThread<WithheldUpgradeServer> server(0, [&](WithheldUpgradeServer &s) {
            s.requests        = &requests;
            s.request_time_ns = &request_time_ns;
        });
        const int                                             port    = bound_port(server);
        const auto                                            started = std::chrono::steady_clock::now();
        const auto started_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(started.time_since_epoch()).count();
        client.connect(qb::io::uri("ws://localhost:" + std::to_string(port) + "/path"), requested_timeout);

        // The server records receipt on its own loop. This distinguishes a
        // missing upgrade timeout from an overloaded TCP connect that expired
        // before the request was even delivered.
        const bool request_seen = pump_until([&] { return requests.load(std::memory_order_acquire) == 1; }, 2000ms);
        if (request_seen) {
            const auto request_delay_ns = request_time_ns.load(std::memory_order_relaxed) - started_ns;
            EXPECT_GE(request_delay_ns, 0);
            EXPECT_LT(request_delay_ns, std::chrono::duration_cast<std::chrono::nanoseconds>(requested_timeout).count());
            EXPECT_EQ(connected + errors, 0);
        }

        const bool completed = pump_until([&] { return connected + errors > 0; }, 5000ms);
        EXPECT_TRUE(completed);
        if (completed) {
            EXPECT_LE(std::chrono::steady_clock::now() - started, requested_timeout + 1500ms);
        }

        // Allow a second callback scheduled on the deadline to surface before
        // tearing down the peer. The time bound only drains work; callback
        // counts below are the oracle.
        const auto deadline_drain = started + requested_timeout + 500ms;
        while (std::chrono::steady_clock::now() < deadline_drain) {
            qb::io::async::run(EVRUN_NOWAIT);
            std::this_thread::yield();
        }
    }

    // Server teardown closes the held transport. Deliver that notification,
    // then drain any callback queued by local disconnect before counting.
    qb::io::async::run(EVRUN_NOWAIT);
    client.disconnect();
    const auto teardown_drain = std::chrono::steady_clock::now() + 250ms;
    while (std::chrono::steady_clock::now() < teardown_drain) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::yield();
    }
    EXPECT_EQ(requests.load(std::memory_order_acquire), 1);
    EXPECT_EQ(connected + errors, 1);
    EXPECT_EQ(connected, 0);
    EXPECT_EQ(errors, 1);
}

TEST(WebSocketClientHardening, CoroutineClientDeadlineIncludesUpgradeResponse) {
    qb::io::async::init();

    std::atomic<int>                                      requests{0};
    qb::http::test::WsServerThread<WithheldUpgradeServer> server(0, [&](WithheldUpgradeServer &s) { s.requests = &requests; });
    const qb::io::uri                                     remote("ws://localhost:" + std::to_string(bound_port(server)) + "/path");

    auto scenario = [remote]() -> qb::io::async::task<bool> {
        qb::http::ws::coro_client<> client;
        const auto                  connected = co_await client.connect(remote, 1s);
        co_return connected.ok;
    };

    const auto started = std::chrono::steady_clock::now();
    EXPECT_FALSE(qb::http::ws::run_sync(scenario()));
    EXPECT_EQ(requests.load(std::memory_order_acquire), 1);
    EXPECT_LE(std::chrono::steady_clock::now() - started, 2500ms);
}

TEST(WebSocketClientHardening, TimeoutCallbackCanStartAnotherAttempt) {
    qb::io::async::init();

    std::atomic<int>                                        withheld_requests{0};
    qb::http::test::WsServerThread<WithheldUpgradeServer>   withheld(0, [&](WithheldUpgradeServer &s) { s.requests = &withheld_requests; });
    qb::http::test::WsServerThread<ExtensionResponseServer> accepting(0);
    const qb::io::uri                                       first("ws://localhost:" + std::to_string(bound_port(withheld)) + "/path");
    const qb::io::uri                                       second("ws://localhost:" + std::to_string(bound_port(accepting)) + "/path");

    int                  errors    = 0;
    int                  connected = 0;
    qb::http::ws::client client;
    client.on_error([&](auto &) {
        if (++errors == 1)
            client.connect(second, 2s);
    });
    client.on_connected([&](auto &) { ++connected; });
    client.connect(first, 1s);

    ASSERT_TRUE(pump_until([&] { return connected == 1 || errors > 1; }, 4500ms));
    EXPECT_EQ(withheld_requests.load(std::memory_order_acquire), 1);
    EXPECT_EQ(errors, 1);
    EXPECT_EQ(connected, 1);
    client.disconnect();
}

// ===========================================================================
// 5. Client rejects a handshake response with a malformed Connection token.
// ===========================================================================

class BadConnectionTokenServer;

class BadConnectionTokenSession : public qb::io::use<BadConnectionTokenSession>::tcp::client<BadConnectionTokenServer> {
public:
    using Protocol    = qb::http::protocol<BadConnectionTokenSession>;
    using WS_Protocol = qb::http::ws::protocol<BadConnectionTokenSession>;

    explicit BadConnectionTokenSession(IOServer &server)
        : client(server) {}

    void
    on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            disconnect();
            return;
        }
        // Deliberately malformed token list: "upgraded", not "Upgrade".
        response.headers()["Connection"].clear();
        response.headers()["Connection"].emplace_back(std::string("keep-alive, upgraded"));
        *this << response;
    }

    void
    on(WS_Protocol::message &&) {}
    void
    on(WS_Protocol::ping &&) {}
    void
    on(WS_Protocol::pong &&) {}
    void
    on(WS_Protocol::close &&) {}
};

class BadConnectionTokenServer : public qb::io::use<BadConnectionTokenServer>::tcp::server<BadConnectionTokenSession> {
public:
    void
    on(IOSession &) {}
};

TEST(WebSocketClientHardening, ClientRejectsMalformedConnectionTokenInResponse) {
    qb::io::async::init();

    qb::http::test::WsServerThread<BadConnectionTokenServer> server(0);
    const int                                                port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    bool connected = false;
    bool errored   = false;

    qb::http::ws::client client;
    client.on_connected([&](auto &) { connected = true; });
    client.on_error([&](auto &) { errored = true; });
    client.connect(qb::io::uri("ws://localhost:" + std::to_string(port) + "/path"), 1000ms);

    ASSERT_TRUE(pump_until([&] { return errored || connected; }));

    EXPECT_TRUE(errored);
    EXPECT_FALSE(connected);
}

// ===========================================================================
// 6/7/8/9. Client rejects RFC-6455-illegal server frames, emitting a precise
// protocol Close code (1002 ProtocolError / 1007 DataNotConsistent). The
// adversarial server completes the handshake, sends ONE bad frame, then reads
// the client's masked Close back and records the exact code.
// ===========================================================================

// Raw bad frames, one per scenario. Each is a complete server→client frame the
// client parser must reject with a precise protocol Close code.
namespace bad_frame {

// FIN+text, MASK bit set (illegal for server→client), 4-byte mask + masked "evil".
[[nodiscard]] inline std::string
masked_server_frame() {
    const std::string                      payload = "evil";
    constexpr std::array<unsigned char, 4> mask{{0x11, 0x22, 0x33, 0x44}};
    std::string                            frame;
    frame.push_back(static_cast<char>(0x81));
    frame.push_back(static_cast<char>(0x80u | payload.size()));
    for (unsigned char b : mask) {
        frame.push_back(static_cast<char>(b));
    }
    for (std::size_t i = 0; i < payload.size(); ++i) {
        frame.push_back(static_cast<char>(static_cast<unsigned char>(payload[i]) ^ mask[i % 4]));
    }
    return frame;
}

// FIN + reserved control opcode 0xB (invalid per RFC 6455).
[[nodiscard]] inline std::string
reserved_opcode() {
    return std::string{static_cast<char>(0x8Bu), static_cast<char>(0x00)};
}

// Close with payload length 1 — invalid per RFC 6455 §5.5.1.
[[nodiscard]] inline std::string
invalid_close_length_one() {
    return std::string{static_cast<char>(0x88u), static_cast<char>(0x01), static_cast<char>(0x00)};
}

// Close code 1000 + invalid UTF-8 reason ED A0 80 (surrogate).
[[nodiscard]] inline std::string
invalid_close_reason_utf8() {
    return std::string{static_cast<char>(0x88u), static_cast<char>(0x05), static_cast<char>(0x03), static_cast<char>(0xE8),
                       static_cast<char>(0xED),  static_cast<char>(0xA0), static_cast<char>(0x80)};
}

} // namespace bad_frame

/// Record a client→server Close into a probe result (shared by every server's on(close)).
inline void
capture_client_close(ServerProbeResult *r, const char *data, std::size_t size) {
    if (r) {
        r->client_close_code.store(decode_close_code(data, size));
        r->client_closed.store(true);
    }
}

// Each adversarial scenario gets its own concrete session/server pair: qb-io
// binds events by concrete type and the protocol/io-handler machinery looks
// member traits up on the *most-derived* session, so a CRTP intermediate is not
// viable here. The session/server bodies are generated by this macro to keep the
// four pairs in lockstep without copy-paste drift; the close handler (which
// touches the now-complete server) is defined out-of-line after both classes.
#define DEFINE_BAD_FRAME_SERVER(SessionName, ServerName, FRAME_EXPR)                          \
    class ServerName;                                                                         \
    class SessionName : public qb::io::use<SessionName>::tcp::client<ServerName> {            \
    public:                                                                                   \
        using Protocol    = qb::http::protocol<SessionName>;                                  \
        using WS_Protocol = qb::http::ws::protocol<SessionName>;                              \
        explicit SessionName(IOServer &server)                                                \
            : client(server) {}                                                               \
        void                                                                                  \
        on(Protocol::request &&request) {                                                     \
            qb::http::Response response;                                                      \
            if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {              \
                disconnect();                                                                 \
                return;                                                                       \
            }                                                                                 \
            *this << response;                                                                \
            const std::string frame = (FRAME_EXPR);                                           \
            std::memcpy(this->out().allocate_back(frame.size()), frame.data(), frame.size()); \
            this->ready_to_write();                                                           \
        }                                                                                     \
        void on(WS_Protocol::close &&event);                                                  \
        void                                                                                  \
        on(WS_Protocol::message &&) {}                                                        \
        void                                                                                  \
        on(WS_Protocol::ping &&) {}                                                           \
        void                                                                                  \
        on(WS_Protocol::pong &&) {}                                                           \
    };                                                                                        \
    class ServerName : public qb::io::use<ServerName>::tcp::server<SessionName> {             \
    public:                                                                                   \
        ServerProbeResult *results = nullptr;                                                 \
        void                                                                                  \
        on(IOSession &) {}                                                                    \
    };                                                                                        \
    inline void SessionName::on(WS_Protocol::close &&event) {                                 \
        capture_client_close(this->server().results, event.data, event.size);                 \
        this->disconnect();                                                                   \
    }                                                                                         \
    static_assert(true, "require trailing semicolon")

DEFINE_BAD_FRAME_SERVER(MaskedFrameSession, MaskedFrameServer, bad_frame::masked_server_frame());
DEFINE_BAD_FRAME_SERVER(ReservedOpcodeSession, ReservedOpcodeServer, bad_frame::reserved_opcode());
DEFINE_BAD_FRAME_SERVER(InvalidCloseLenSession, InvalidCloseLenServer, bad_frame::invalid_close_length_one());
DEFINE_BAD_FRAME_SERVER(InvalidCloseUtf8Session, InvalidCloseUtf8Server, bad_frame::invalid_close_reason_utf8());

#undef DEFINE_BAD_FRAME_SERVER

// Drive a bad-frame scenario and assert the precise Close code the client emitted.
template <typename ServerT>
void
run_bad_frame_scenario(std::uint16_t expected_close_code) {
    qb::io::async::init();

    ServerProbeResult                       result;
    qb::http::test::WsServerThread<ServerT> server(0, [&](ServerT &s) { s.results = &result; });
    const int                               port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    bool        errored  = false;
    std::size_t messages = 0;
    std::size_t closes   = 0;

    qb::http::ws::client client;
    client.on_error([&](auto &) { errored = true; });
    client.on_message([&](auto &) { ++messages; });
    client.on_closed([&](auto &) { ++closes; });
    client.connect(qb::io::uri("ws://localhost:" + std::to_string(port) + "/path"), 1000ms);

    ASSERT_TRUE(pump_until([&] { return result.client_closed.load(); }));

    // The bad frame must never have been surfaced as a valid message/close.
    EXPECT_EQ(messages, 0u);
    EXPECT_EQ(closes, 0u);
    // The client fail_connection() always raises the error event...
    EXPECT_TRUE(errored);
    // ...and emits a Close carrying the precise protocol code.
    EXPECT_EQ(result.client_close_code.load(), expected_close_code);
}

TEST(WebSocketClientHardening, ClientRejectsMaskedServerFrameWithProtocolError) {
    run_bad_frame_scenario<MaskedFrameServer>(static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));
}

TEST(WebSocketClientHardening, ClientRejectsReservedOpcodeWithProtocolError) {
    run_bad_frame_scenario<ReservedOpcodeServer>(static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));
}

TEST(WebSocketClientHardening, ClientRejectsInvalidCloseLengthOneWithProtocolError) {
    run_bad_frame_scenario<InvalidCloseLenServer>(static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));
}

TEST(WebSocketClientHardening, ClientRejectsInvalidUtf8CloseReasonWithDataNotConsistent) {
    run_bad_frame_scenario<InvalidCloseUtf8Server>(static_cast<std::uint16_t>(qb::http::ws::CloseStatus::DataNotConsistent));
}

// ===========================================================================
// 10. Peer-initiated close: the client echoes the Close frame back exactly once,
// carrying the same code, per RFC 6455 §5.5.1.
//
// The callback client surfaces an incoming Close via `on_closed` (it does NOT
// auto-echo, since defining the handler suppresses the default echo). The test
// drives the echo explicitly from `on_closed`, and the server records the
// client's Close so the assertion is deterministic (`== 1`, not the former
// always-passing `<= 1`).
// ===========================================================================

class CloseEchoProbeServer;

class CloseEchoProbeSession : public qb::io::use<CloseEchoProbeSession>::tcp::client<CloseEchoProbeServer> {
public:
    using Protocol    = qb::http::protocol<CloseEchoProbeSession>;
    using WS_Protocol = qb::http::ws::protocol<CloseEchoProbeSession>;

    explicit CloseEchoProbeSession(IOServer &server)
        : client(server) {}

    void
    on(Protocol::request &&request) {
        qb::http::Response response;
        if (!this->switch_protocol<WS_Protocol>(*this, request, response)) {
            disconnect();
            return;
        }
        *this << response;
        // Server initiates the close; the transport stays up so the client can echo.
        qb::http::ws::MessageClose close_msg(qb::http::ws::CloseStatus::GoingAway, "server-closing");
        *this << close_msg;
    }

    void on(WS_Protocol::close &&event);

    void
    on(WS_Protocol::message &&) {}
    void
    on(WS_Protocol::ping &&) {}
    void
    on(WS_Protocol::pong &&) {}
};

class CloseEchoProbeServer : public qb::io::use<CloseEchoProbeServer>::tcp::server<CloseEchoProbeSession> {
public:
    ServerProbeResult *results = nullptr;

    void
    on(IOSession &) {}
};

void
CloseEchoProbeSession::on(WS_Protocol::close &&event) {
    capture_client_close(this->server().results, event.data, event.size);
    this->disconnect();
}

TEST(WebSocketClientHardening, ClientEchoesPeerCloseFrameExactlyOnce) {
    qb::io::async::init();

    ServerProbeResult                                    result;
    qb::http::test::WsServerThread<CloseEchoProbeServer> server(0, [&](CloseEchoProbeServer &s) { s.results = &result; });
    const int                                            port = bound_port(server);
    ASSERT_NE(port, 0) << "the adversarial server is not listening";

    std::size_t closes_seen = 0;
    std::string order;

    qb::http::ws::client client;
    client.on_connected([&](auto &) { order.push_back('C'); });
    client.on_closed([&](auto &) {
        ++closes_seen;
        order.push_back('L');
        // Echo the peer's Close exactly once.
        client.close(qb::http::ws::CloseStatus::GoingAway, "client-echo");
    });
    client.on_disconnected([&](auto &) { order.push_back('D'); });
    client.connect(qb::io::uri("ws://localhost:" + std::to_string(port) + "/path"), 1000ms);

    ASSERT_TRUE(pump_until([&] { return result.client_closed.load() && order.find('D') != std::string::npos; }));

    // The client observed the peer Close exactly once and echoed it back with
    // the same code — no tolerance, no always-passing `<= 1`.
    EXPECT_EQ(closes_seen, 1u);
    EXPECT_EQ(order, "CLD");
    EXPECT_EQ(result.client_close_code.load(), static_cast<std::uint16_t>(qb::http::ws::CloseStatus::GoingAway));
}

TEST(WebSocketClientHardening, ExplicitDisconnectFromConnectedStillNotifiesOnce) {
    qb::io::async::init();
    qb::http::test::WsServerThread<CloseEchoProbeServer> server(0);
    int                                                  connected    = 0;
    int                                                  disconnected = 0;
    qb::http::ws::client                                 client;
    client.on_connected([&](auto &) {
        ++connected;
        client.disconnect();
    });
    client.on_disconnected([&](auto &) { ++disconnected; });
    client.connect(qb::io::uri("ws://localhost:" + std::to_string(bound_port(server)) + "/path"), 1s);
    ASSERT_TRUE(pump_until([&] { return disconnected == 1; }));
    EXPECT_EQ(connected, 1);
    EXPECT_EQ(disconnected, 1);
}

} // namespace

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
 * Ports are ephemeral (kernel-assigned) so the suite is parallel-safe; the
 * loopback loops are driven by a fail-loud @ref pump_until rather than fixed-iter
 * sleeps; no module globals — every test owns its server-side result struct.
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

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

#include <qb/io/async.h>

#include "../../shared/loopback_server.h" // ephemeral_port
#include "../../shared/ws_loopback.h"     // WsServerThread
#include "../ws.h"

using namespace std::chrono_literals;

namespace {

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
    const int                                          port = static_cast<int>(qb::http::test::ephemeral_port());
    qb::http::test::WsServerThread<ControlProbeServer> server(port, [&](ControlProbeServer &s) { s.results = &result; });

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

    const int                                                 port = static_cast<int>(qb::http::test::ephemeral_port());
    qb::http::test::WsServerThread<HandshakeValidationServer> server(port);

    // 24 'a' chars: valid base64 length but not a 16-byte nonce decode.
    const std::string response = drive_bad_key_handshake(port, "aaaaaaaaaaaaaaaaaaaaaaaa");

    EXPECT_EQ(response.find("101 Switching Protocols"), std::string::npos) << "Server must reject malformed Sec-WebSocket-Key";
    EXPECT_NE(response.find("400"), std::string::npos) << "Expected a BAD_REQUEST response, got:\n" << response;
}

TEST(WebSocketClientHardening, ServerRejectsNonBase64SecWebSocketKey) {
    qb::io::async::init();

    const int                                                 port = static_cast<int>(qb::http::test::ephemeral_port());
    qb::http::test::WsServerThread<HandshakeValidationServer> server(port);

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

    const int                                            port = static_cast<int>(qb::http::test::ephemeral_port());
    qb::http::test::WsServerThread<BadSubprotocolServer> server(port);

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

    const int                                                port = static_cast<int>(qb::http::test::ephemeral_port());
    qb::http::test::WsServerThread<BadConnectionTokenServer> server(port);

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
    const int                               port = static_cast<int>(qb::http::test::ephemeral_port());
    qb::http::test::WsServerThread<ServerT> server(port, [&](ServerT &s) { s.results = &result; });

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
    const int                                            port = static_cast<int>(qb::http::test::ephemeral_port());
    qb::http::test::WsServerThread<CloseEchoProbeServer> server(port, [&](CloseEchoProbeServer &s) { s.results = &result; });

    std::size_t closes_seen = 0;

    qb::http::ws::client client;
    client.on_closed([&](auto &) {
        ++closes_seen;
        // Echo the peer's Close exactly once.
        client.close(qb::http::ws::CloseStatus::GoingAway, "client-echo");
    });
    client.connect(qb::io::uri("ws://localhost:" + std::to_string(port) + "/path"), 1000ms);

    ASSERT_TRUE(pump_until([&] { return result.client_closed.load(); }));

    // The client observed the peer Close exactly once and echoed it back with
    // the same code — no tolerance, no always-passing `<= 1`.
    EXPECT_EQ(closes_seen, 1u);
    EXPECT_EQ(result.client_close_code.load(), static_cast<std::uint16_t>(qb::http::ws::CloseStatus::GoingAway));
}

} // namespace

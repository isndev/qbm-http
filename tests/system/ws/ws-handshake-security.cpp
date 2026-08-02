/**
 * @file qbm/http/tests/system/ws/ws-handshake-security.cpp
 * @brief Server-side WebSocket handshake + wire-compliance security (RFC 6455).
 *
 * Five raw-socket cases drive a real loopback WebSocket server and assert the
 * server enforces the handshake and framing rules a hostile client might break:
 *
 *   - VALID_HANDSHAKE     — well-formed upgrade yields 101 + Sec-WebSocket-Accept.
 *   - INVALID_KEY         — missing Sec-WebSocket-Key  → 400, no connection.
 *   - INVALID_VERSION     — Sec-WebSocket-Version != 13 → 400, no connection.
 *   - INVALID_METHOD      — non-GET upgrade → 400, no connection.
 *   - UNMASKED_FRAMES     — an unmasked client text frame → Close(1002).
 *
 * This is a SYSTEM-tier test: in-process loopback server on a background event
 * loop, plaintext `ws://`, no external daemon. It needs OpenSSL only as a crypto
 * *link* dependency (`generateKey` / accept-key derivation), not TLS transport.
 *
 * Compared with the monolith it replaces (`test-ws-security.cpp`), every shared
 * piece of machinery — server thread, `perform_upgrade`-style raw socket — now
 * comes from `shared/ws_loopback.h`, ports are kernel-assigned by binding `:0` on
 * the serving listener itself and reading it back (no fixed `20160`, and no
 * probe-then-bind window another process can steal), the dead
 * `condition_variable` scaffolding is gone, the custom `main()` is gone, and
 * connection/rejection counts are owned per-server (no module globals).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

#include <qb/io/async.h>

#include "../../shared/loopback_server.h"
#include "../../shared/ws_loopback.h"
#include "../ws/ws.h"

namespace {

using namespace std::chrono_literals;
using qb::http::test::read_http_response;
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

// ---------------------------------------------------------------------------
// Security server: per-instance counters (NO module globals).
// ---------------------------------------------------------------------------

class SecurityServer;

class SecurityServerClient : public qb::io::use<SecurityServerClient>::tcp::client<SecurityServer> {
private:
    bool _validated = false;

public:
    using Protocol    = qb::http::protocol<SecurityServerClient>;
    using WS_Protocol = qb::http::ws::protocol<SecurityServerClient>;

    explicit SecurityServerClient(IOServer &server)
        : qb::io::use<SecurityServerClient>::tcp::client<SecurityServer>(server) {}

    void on(typename Protocol::request &&request);

    void
    on(typename WS_Protocol::message &&event) {
        // Echo only after validation; an unmasked client frame never reaches
        // here (the framer fails the connection first), so this just lets the
        // valid path round-trip.
        if (_validated) {
            event.ws.masked = false;
            *this << event.ws;
        } else {
            disconnect();
        }
    }

    void
    on(typename WS_Protocol::close &&) {
        disconnect();
    }
};

class SecurityServer : public qb::io::use<SecurityServer>::tcp::server<SecurityServerClient> {
public:
    std::atomic<std::size_t> connections{0};
    std::atomic<std::size_t> rejections{0};

    void
    on(IOSession &) {}
};

inline void
SecurityServerClient::on(typename Protocol::request &&request) {
    bool valid = true;
    if (request.header("Sec-WebSocket-Version") != "13") {
        valid = false;
    }
    if (request.header("Sec-WebSocket-Key").empty()) {
        valid = false;
    }
    if (!request.upgrade || request.header("Upgrade") != "websocket" || request.header("Connection").find("Upgrade") == std::string::npos) {
        valid = false;
    }

    if (valid) {
        _validated = true;
        if (!this->switch_protocol<WS_Protocol>(*this, request)) {
            ++server().rejections;
            disconnect();
        } else {
            ++server().connections;
        }
    } else {
        qb::http::Response res;
        res.status() = qb::http::status::BAD_REQUEST;
        res.body()   = "Invalid WebSocket request";
        *this << res;
        ++server().rejections;
        disconnect();
    }
}

// ---------------------------------------------------------------------------
// Raw handshake request builder.
// ---------------------------------------------------------------------------

std::string
raw_handshake_request(int port, std::string_view key, std::string_view version = "13", std::string_view method = "GET") {
    std::string request;
    request += method;
    request += " / HTTP/1.1\r\n";
    request += "Host: localhost:";
    request += std::to_string(port);
    request += "\r\n";
    request += "Upgrade: websocket\r\n";
    request += "Connection: Upgrade\r\n";
    if (!key.empty()) {
        request += "Sec-WebSocket-Key: ";
        request += key;
        request += "\r\n";
    }
    request += "Sec-WebSocket-Version: ";
    request += version;
    request += "\r\n\r\n";
    return request;
}

// Connect a raw, non-blocking loopback socket to the server's port.
qb::io::tcp::socket
connect_raw(int port) {
    qb::io::tcp::socket sock;
    EXPECT_EQ(sock.connect(qb::io::uri{std::string("tcp://localhost:") + std::to_string(port)}), 0);
    (void) sock.set_nonblocking(true);
    return sock;
}

void
write_all(qb::io::tcp::socket &sock, std::string_view bytes) {
    sock.write(bytes.data(), static_cast<int>(bytes.size()));
}

} // namespace

// ===========================================================================
// Handshake acceptance / rejection
// ===========================================================================

TEST(WsHandshakeSecurity, ValidHandshake) {
    WsServerThread<SecurityServer> server{kBindEphemeral};
    ASSERT_NE(server.port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    auto sock = connect_raw(server.port);

    const auto key = qb::http::ws::generateKey();
    write_all(sock, raw_handshake_request(server.port, key));

    const auto response = read_http_response(sock);
    EXPECT_NE(response.find("101"), std::string::npos) << response;
    EXPECT_NE(response.find("sec-websocket-accept"), std::string::npos) << response;
    sock.close();
}

TEST(WsHandshakeSecurity, MissingKeyIsRejected) {
    WsServerThread<SecurityServer> server{kBindEphemeral};
    ASSERT_NE(server.port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    auto sock = connect_raw(server.port);

    write_all(sock, raw_handshake_request(server.port, ""));

    const auto response = read_http_response(sock);
    EXPECT_NE(response.find("400"), std::string::npos) << response;
    sock.close();
}

TEST(WsHandshakeSecurity, InvalidVersionIsRejected) {
    WsServerThread<SecurityServer> server{kBindEphemeral};
    ASSERT_NE(server.port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    auto sock = connect_raw(server.port);

    write_all(sock, raw_handshake_request(server.port, qb::http::ws::generateKey(), "12"));

    const auto response = read_http_response(sock);
    EXPECT_NE(response.find("400"), std::string::npos) << response;
    sock.close();
}

TEST(WsHandshakeSecurity, NonGetMethodIsRejected) {
    WsServerThread<SecurityServer> server{kBindEphemeral};
    ASSERT_NE(server.port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    auto sock = connect_raw(server.port);

    write_all(sock, raw_handshake_request(server.port, qb::http::ws::generateKey(), "13", "POST"));

    const auto response = read_http_response(sock);
    EXPECT_NE(response.find("400"), std::string::npos) << response;
    sock.close();
}

// ---------------------------------------------------------------------------
// Sec-WebSocket-Key value validation inside populate_handshake_response.
//
// The session's own pre-check only requires the key to be *present*; the strict
// RFC 6455 §4.2.1 validation (24-char base64 of 16 bytes) lives in
// ws_server::populate_handshake_response (ws.h:913..926). A key that is present
// but malformed therefore passes the session gate, is handed to switch_protocol,
// and the ws_server constructor rejects it → 400 + not_ok (ws.h:964). Each case
// below isolates one rejection branch and asserts the 400.
// ---------------------------------------------------------------------------

TEST(WsHandshakeSecurity, WrongLengthKeyIsRejected) {
    WsServerThread<SecurityServer> server{kBindEphemeral};
    ASSERT_NE(server.port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    auto sock = connect_raw(server.port);

    // 8-char key: non-empty (passes session gate) but != 24 chars (ws.h:915).
    write_all(sock, raw_handshake_request(server.port, "shortkey"));

    const auto response = read_http_response(sock);
    EXPECT_NE(response.find("400"), std::string::npos) << response;
    sock.close();
}

TEST(WsHandshakeSecurity, NonBase64KeyOfCorrectLengthIsRejected) {
    WsServerThread<SecurityServer> server{kBindEphemeral};
    ASSERT_NE(server.port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    auto sock = connect_raw(server.port);

    // Exactly 24 chars but contains characters illegal in base64 ('*','!','@'),
    // so base64::decode either throws or yields the wrong byte count
    // (ws.h:919-926). Either way → 400.
    write_all(sock, raw_handshake_request(server.port, "************************"));

    const auto response = read_http_response(sock);
    EXPECT_NE(response.find("400"), std::string::npos) << response;
    sock.close();
}

TEST(WsHandshakeSecurity, WellFormedButWrongDecodedSizeKeyIsRejected) {
    WsServerThread<SecurityServer> server{kBindEphemeral};
    ASSERT_NE(server.port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    auto sock = connect_raw(server.port);

    // 24 valid base64 chars decoding to 18 bytes (not 16). "AAAAAAAAAAAAAAAAAAAAAAAA"
    // is 24 'A's = 18 zero bytes when base64-decoded, so the size check at
    // ws.h:923 (decoded_key.size() != 16) fires → 400.
    write_all(sock, raw_handshake_request(server.port, "AAAAAAAAAAAAAAAAAAAAAAAA"));

    const auto response = read_http_response(sock);
    EXPECT_NE(response.find("400"), std::string::npos) << response;
    sock.close();
}

// ===========================================================================
// Wire compliance: client→server frames must be masked.
// ===========================================================================

TEST(WsHandshakeSecurity, UnmaskedClientFrameIsClosed) {
    WsServerThread<SecurityServer> server{kBindEphemeral};
    ASSERT_NE(server.port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    auto sock = connect_raw(server.port);

    write_all(sock, raw_handshake_request(server.port, qb::http::ws::generateKey()));
    const auto response = read_http_response(sock);
    ASSERT_NE(response.find("101"), std::string::npos) << response;

    // Unmasked text frame (MASK bit clear) — RFC 6455 §5.1 violation.
    const std::string payload = "unmasked payload";
    std::string       frame;
    frame.push_back(static_cast<char>(0x81));           // FIN + text
    frame.push_back(static_cast<char>(payload.size())); // MASK=0, len7
    frame += payload;
    write_all(sock, frame);

    const auto close_frame = qb::http::test::read_some(sock, 128);
    ASSERT_GE(close_frame.size(), 4u) << "expected a Close frame from the server";
    EXPECT_EQ(static_cast<unsigned char>(close_frame[0]), 0x88u) << "must be a Close frame";
    EXPECT_LE(static_cast<unsigned char>(close_frame[1]), 125u) << "Close payload must fit 7-bit length";
    const auto code =
        static_cast<std::uint16_t>((static_cast<unsigned char>(close_frame[2]) << 8) | static_cast<unsigned char>(close_frame[3]));
    EXPECT_EQ(code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::ProtocolError));
    sock.close();
}

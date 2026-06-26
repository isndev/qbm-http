/**
 * @file qbm/http/tests/unit/ws/ws-frame-encode-validation.cpp
 * @brief Unit-tier validation of the outgoing-frame serializer and subprotocol guards.
 *
 * Pure-logic checks of the WebSocket *encode* path — no event loop, no socket.
 * They instantiate nothing but a `qb::allocator::pipe<char>` (the outbound
 * buffer) and a `qb::http::ws::client` (for token validation) and assert the
 * `operator<<` / `add_subprotocol` / `set_subprotocols` contracts reject
 * RFC-6455-illegal frames and tokens by throwing `std::invalid_argument`:
 *
 *   - control frames (Ping/Pong) larger than 125 bytes,
 *   - reserved/unknown opcodes,
 *   - any RSV bit set,
 *   - fragmented (non-FIN) control frames,
 *   - malformed subprotocol tokens.
 *
 * These need OpenSSL only to *link* (`ws/ws.h` hard-`#error`s without
 * `QB_HAS_SSL` because the handshake uses `qb::io::crypto` SHA-1/base64); they
 * run zero crypto and open zero sockets. Tier `unit`, tag `ws`, REQUIRES ssl
 * (crypto link).
 *
 * Split out of the former `tests/test-ws-api-hardening.cpp` (the serializer /
 * token-validation half). The adversarial loopback cases moved to
 * `tests/system/ws/ws-client-hardening.cpp`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include <qb/system/allocator/pipe.h>

#include "../ws.h"

// ---------------------------------------------------------------------------
// Control-frame size guard (RFC 6455 §5.5: control frames ≤ 125 bytes).
// ---------------------------------------------------------------------------

TEST(WebSocketFrameEncodeValidation, RejectsOversizedOutgoingPingFrame) {
    qb::allocator::pipe<char> out;
    qb::http::ws::MessagePing ping;
    ping << std::string(126, 'x');

    EXPECT_THROW(out << ping, std::invalid_argument);
}

TEST(WebSocketFrameEncodeValidation, RejectsOversizedOutgoingPongFrame) {
    qb::allocator::pipe<char> out;
    qb::http::ws::MessagePong pong;
    pong << std::string(126, 'x');

    EXPECT_THROW(out << pong, std::invalid_argument);
}

// ---------------------------------------------------------------------------
// Opcode / RSV guards (RFC 6455 §5.2).
// ---------------------------------------------------------------------------

TEST(WebSocketFrameEncodeValidation, RejectsOutgoingReservedOpcode) {
    qb::allocator::pipe<char> out;

    qb::http::ws::Message reserved_opcode;
    reserved_opcode.fin_rsv_opcode = 0x8Bu; // FIN + reserved control opcode 0xB.
    EXPECT_THROW(out << reserved_opcode, std::invalid_argument);
}

TEST(WebSocketFrameEncodeValidation, RejectsOutgoingRsvBits) {
    qb::allocator::pipe<char> out;

    qb::http::ws::Message rsv_text;
    rsv_text.fin_rsv_opcode = 0xC1u; // FIN + RSV1 + RSV2 + text.
    EXPECT_THROW(out << rsv_text, std::invalid_argument);
}

TEST(WebSocketFrameEncodeValidation, RejectsOutgoingFragmentedControlFrame) {
    qb::allocator::pipe<char> out;

    qb::http::ws::Message fragmented_ping;
    fragmented_ping.fin_rsv_opcode = qb::http::ws::opcode::_Ping; // ping opcode without the FIN bit.
    EXPECT_THROW(out << fragmented_ping, std::invalid_argument);
}

// ---------------------------------------------------------------------------
// Subprotocol token guards (RFC 6455 §1.9 / §4.1 — RFC 7230 token grammar).
// ---------------------------------------------------------------------------

TEST(WebSocketFrameEncodeValidation, RejectsInvalidAddSubprotocolTokens) {
    qb::http::ws::client client;

    EXPECT_THROW(client.add_subprotocol(""), std::invalid_argument);
    EXPECT_THROW(client.add_subprotocol("chat v1"), std::invalid_argument);
    EXPECT_THROW(client.add_subprotocol("chat,v1"), std::invalid_argument);
    EXPECT_THROW(client.add_subprotocol(std::string("bad\nproto", 9)), std::invalid_argument);
}

TEST(WebSocketFrameEncodeValidation, SetSubprotocolsRejectsBadAndAcceptsGoodTokens) {
    qb::http::ws::client client;

    EXPECT_THROW(client.set_subprotocols({"chat.v1", "bad proto"}), std::invalid_argument);
    EXPECT_NO_THROW(client.set_subprotocols({"chat.v1", "superchat-v2"}));
}

// ---------------------------------------------------------------------------
// Handshake header-parsing primitives (qb::protocol::detail).
//
// These pure inline helpers back BOTH the server `populate_handshake_response`
// and the client `validate_handshake_response`. The over-the-wire system tests
// only exercise their happy path; the cases below pin the case-folding,
// token-grammar, comma-list, OWS-trim and constant-time-equality branches
// directly (ws.h:807..880) with no socket.
// ---------------------------------------------------------------------------

TEST(WsHandshakeDetail, IequalAsciiFoldsCaseAndRejectsMismatches) {
    using qb::protocol::detail::iequal_ascii;

    EXPECT_TRUE(iequal_ascii("websocket", "WebSocket"));
    EXPECT_TRUE(iequal_ascii("UPGRADE", "upgrade"));
    EXPECT_TRUE(iequal_ascii("", ""));
    EXPECT_FALSE(iequal_ascii("websocket", "websockets")); // length mismatch
    EXPECT_FALSE(iequal_ascii("websocket", "websscket"));  // single-byte differ
}

TEST(WsHandshakeDetail, IsTokenCharAndIsValidToken) {
    using qb::protocol::detail::is_token_char;
    using qb::protocol::detail::is_valid_token;

    // RFC 7230 token chars: alphanumerics + a fixed punctuation set.
    EXPECT_TRUE(is_token_char('a'));
    EXPECT_TRUE(is_token_char('Z'));
    EXPECT_TRUE(is_token_char('0'));
    EXPECT_TRUE(is_token_char('!'));
    EXPECT_TRUE(is_token_char('~'));
    // Non-token separators / controls.
    EXPECT_FALSE(is_token_char(' '));
    EXPECT_FALSE(is_token_char(','));
    EXPECT_FALSE(is_token_char('\n'));
    EXPECT_FALSE(is_token_char('('));

    EXPECT_TRUE(is_valid_token("chat.v1"));
    EXPECT_TRUE(is_valid_token("superchat-v2"));
    EXPECT_FALSE(is_valid_token(""));          // empty rejected
    EXPECT_FALSE(is_valid_token("chat v1"));   // space
    EXPECT_FALSE(is_valid_token("chat,v1"));   // comma
}

TEST(WsHandshakeDetail, HasTokenCiHandlesListsCaseAndWhitespace) {
    using qb::protocol::detail::has_token_ci;

    // Single token, exact and case-folded.
    EXPECT_TRUE(has_token_ci("Upgrade", "upgrade"));
    EXPECT_TRUE(has_token_ci("upgrade", "Upgrade"));
    // Multi-token Connection list with OWS around each element.
    EXPECT_TRUE(has_token_ci("keep-alive, Upgrade", "upgrade"));
    EXPECT_TRUE(has_token_ci("  Upgrade  ,  keep-alive  ", "upgrade"));
    EXPECT_TRUE(has_token_ci("a,b,c,Upgrade", "upgrade"));
    // Absent token in a list.
    EXPECT_FALSE(has_token_ci("keep-alive, close", "upgrade"));
    // Empty header value and an all-whitespace element (find_first_not_of npos
    // branch) must not match.
    EXPECT_FALSE(has_token_ci("", "upgrade"));
    EXPECT_FALSE(has_token_ci("  ,  ", "upgrade"));
}

TEST(WsHandshakeDetail, TrimOwsStripsSurroundingSpacesAndTabs) {
    using qb::protocol::detail::trim_ows;

    EXPECT_EQ(trim_ows("  value  "), "value");
    EXPECT_EQ(trim_ows("\tvalue\t"), "value");
    EXPECT_EQ(trim_ows("value"), "value");
    EXPECT_EQ(trim_ows("   "), std::string_view{}); // all-OWS → empty (npos branch)
    EXPECT_EQ(trim_ows(""), std::string_view{});
}

TEST(WsHandshakeDetail, ConstantTimeEqualMatchesAndDiffers) {
    using qb::protocol::detail::constant_time_equal;

    EXPECT_TRUE(constant_time_equal("abc123", "abc123"));
    EXPECT_TRUE(constant_time_equal("", ""));
    EXPECT_FALSE(constant_time_equal("abc123", "abc124")); // last byte differs
    EXPECT_FALSE(constant_time_equal("abc", "abcd"));       // length differs
}

// ---------------------------------------------------------------------------
// MessageClose typed-status constructor (ws.h:289 delegating ctor).
//
// The encode/validation TU never builds a Close via the CloseStatus overload;
// the close-frame-negative TU does, but coverage is per-binary. Pin the typed
// overload here so this binary records the delegating constructor and its
// status-byte layout.
// ---------------------------------------------------------------------------

TEST(WebSocketFrameEncodeValidation, MessageCloseTypedStatusOverloadEncodesStatusBytes) {
    using qb::http::ws::CloseStatus;
    using qb::http::ws::MessageClose;

    MessageClose msg{CloseStatus::GoingAway, "bye"};
    ASSERT_GE(msg.size(), 2u + 3u);

    const auto         status = static_cast<std::uint16_t>(CloseStatus::GoingAway);
    const char        *bytes  = msg._data.begin();
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[0]), static_cast<std::uint8_t>((status >> 8) & 0xFFu));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[1]), static_cast<std::uint8_t>(status & 0xFFu));
    EXPECT_EQ(std::string_view(bytes + 2, msg.size() - 2), "bye");

    // The default-status overload uses Normal (1000) with the default reason.
    MessageClose def{CloseStatus::Normal};
    ASSERT_GE(def.size(), 2u);
    const auto   normal = static_cast<std::uint16_t>(CloseStatus::Normal);
    const char  *db     = def._data.begin();
    EXPECT_EQ(static_cast<std::uint8_t>(db[0]), static_cast<std::uint8_t>((normal >> 8) & 0xFFu));
    EXPECT_EQ(static_cast<std::uint8_t>(db[1]), static_cast<std::uint8_t>(normal & 0xFFu));
}

// ===========================================================================
// Coverage Wave-2: handshake-validator reject branches via a socket-less IO.
//
// ws_server::populate_handshake_response and ws_client::validate_handshake_response
// are private static template methods, reachable only through the protocol
// constructors. The over-the-wire system tests cannot hit several reject arms
// because the test session gates the request (it requires Upgrade/Connection
// before calling switch_protocol). Driving the constructors directly with a
// hand-built Request/Response pins those false-return branches. The 3-arg
// ws_server ctor (io, request, response) and the ws_client ctor only call the
// validator + not_ok(); they touch no buffers, so a near-empty fake IO suffices.
// ===========================================================================

namespace {

// The WS protocol base<IO_> instantiates every member (getMessageSize,
// onMessage, fail_connection, processControlFrame, ...) when the class template
// is instantiated, so even a constructor-only use needs the full IO concept:
// base_io_t, has_server, in()/out() pipes, an operator<< sink, and on()
// overloads for the wire events + error.
template <bool HasServer>
struct WsFakeIOBase {
    using base_io_t                  = WsFakeIOBase<HasServer>;
    static constexpr bool has_server = HasServer;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;
    struct error {};

    qb::allocator::pipe<char> &in() noexcept { return input; }
    qb::allocator::pipe<char> &out() noexcept { return output; }

    template <typename T>
    WsFakeIOBase &operator<<(const T &msg) {
        output.put(msg);
        return *this;
    }
    void on(qb::protocol::ws_internal::event_message &&) {}
    void on(qb::protocol::ws_internal::event_close &&) {}
    void on(qb::protocol::ws_internal::event_ping &&) {}
    void on(qb::protocol::ws_internal::event_pong &&) {}
    void on(error &&) {}
};

using HsServerFakeIO = WsFakeIOBase<true>;
using HsClientFakeIO = WsFakeIOBase<false>;

// Build a valid base upgrade request, then let the caller mutate one field.
qb::http::Request valid_upgrade_request() {
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

} // namespace

TEST(WsHandshakeValidator, ServerAcceptsWellFormedUpgrade) {
    HsServerFakeIO    io;
    qb::http::Request req = valid_upgrade_request();
    qb::http::Response resp;
    qb::protocol::ws_server<HsServerFakeIO> proto(io, req, resp);
    EXPECT_TRUE(proto.ok());
    EXPECT_EQ(resp.status(), qb::http::status::SWITCHING_PROTOCOLS);
}

TEST(WsHandshakeValidator, ServerRejectsNonGetMethod) {
    HsServerFakeIO    io;
    qb::http::Request req = valid_upgrade_request();
    req.method()          = qb::http::method::POST;
    qb::http::Response resp;
    qb::protocol::ws_server<HsServerFakeIO> proto(io, req, resp);
    EXPECT_FALSE(proto.ok());
    EXPECT_EQ(resp.status(), qb::http::status::BAD_REQUEST);
}

TEST(WsHandshakeValidator, ServerRejectsMissingUpgradeFlag) {
    HsServerFakeIO    io;
    qb::http::Request req = valid_upgrade_request();
    req.upgrade           = false; // ws.h:903-904 branch
    qb::http::Response resp;
    qb::protocol::ws_server<HsServerFakeIO> proto(io, req, resp);
    EXPECT_FALSE(proto.ok());
}

TEST(WsHandshakeValidator, ServerRejectsWrongUpgradeHeaderValue) {
    HsServerFakeIO    io;
    qb::http::Request req = valid_upgrade_request();
    req.set_header("Upgrade", "h2c"); // not "websocket" => ws.h:905-906
    qb::http::Response resp;
    qb::protocol::ws_server<HsServerFakeIO> proto(io, req, resp);
    EXPECT_FALSE(proto.ok());
}

TEST(WsHandshakeValidator, ServerRejectsConnectionWithoutUpgradeToken) {
    HsServerFakeIO    io;
    qb::http::Request req = valid_upgrade_request();
    req.set_header("Connection", "keep-alive"); // no Upgrade token => ws.h:907-908
    qb::http::Response resp;
    qb::protocol::ws_server<HsServerFakeIO> proto(io, req, resp);
    EXPECT_FALSE(proto.ok());
}

TEST(WsHandshakeValidator, ServerRejectsWrongKeyLength) {
    HsServerFakeIO    io;
    qb::http::Request req = valid_upgrade_request();
    req.set_header("Sec-WebSocket-Key", "short"); // != 24 chars => ws.h:915-916
    qb::http::Response resp;
    qb::protocol::ws_server<HsServerFakeIO> proto(io, req, resp);
    EXPECT_FALSE(proto.ok());
}

TEST(WsHandshakeValidator, ServerRejectsNonBase64KeyOfCorrectLength) {
    HsServerFakeIO    io;
    qb::http::Request req = valid_upgrade_request();
    // 24 chars containing base64-illegal bytes => decode throws (ws.h:919-922)
    // or yields a wrong size / non-canonical re-encode (ws.h:923-926).
    req.set_header("Sec-WebSocket-Key", "************************");
    qb::http::Response resp;
    qb::protocol::ws_server<HsServerFakeIO> proto(io, req, resp);
    EXPECT_FALSE(proto.ok());
}

TEST(WsHandshakeValidator, ServerRejectsNonCanonicalBase64Key) {
    HsServerFakeIO    io;
    qb::http::Request req = valid_upgrade_request();
    // 24 chars that DO decode to exactly 16 bytes, but with non-zero trailing
    // bits in the final sextet — so re-encoding canonicalises them and the
    // round-trip differs from the input, tripping the canonical-form check
    // (ws.h:925-926). The decoder is noexcept, so this is the only way to fail
    // *after* a successful 16-byte decode.
    req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZR==");
    qb::http::Response resp;
    qb::protocol::ws_server<HsServerFakeIO> proto(io, req, resp);
    EXPECT_FALSE(proto.ok());
}

TEST(WsHandshakeValidator, ServerRejectsWrongVersion) {
    HsServerFakeIO    io;
    qb::http::Request req = valid_upgrade_request();
    req.set_header("Sec-WebSocket-Version", "8"); // != 13 => ws.h:929-930
    qb::http::Response resp;
    qb::protocol::ws_server<HsServerFakeIO> proto(io, req, resp);
    EXPECT_FALSE(proto.ok());
}

// --- client side: validate_handshake_response ------------------------------

namespace {
// Compute the accept value the client expects for a given key.
std::string accept_for(const std::string &key) {
    return qb::protocol::detail::compute_accept_key(key);
}

qb::http::Response valid_handshake_response(const std::string &key) {
    qb::http::Response resp;
    resp.upgrade  = true;
    resp.status() = qb::http::status::SWITCHING_PROTOCOLS;
    resp.set_header("Upgrade", "websocket");
    resp.set_header("Connection", "Upgrade");
    resp.set_header("Sec-WebSocket-Accept", accept_for(key));
    return resp;
}
} // namespace

TEST(WsHandshakeValidator, ClientAcceptsMatchingAccept) {
    HsClientFakeIO     io;
    const std::string  key  = "dGhlIHNhbXBsZSBub25jZQ==";
    qb::http::Response resp = valid_handshake_response(key);
    qb::protocol::ws_client<HsClientFakeIO> proto(io, resp, key);
    EXPECT_TRUE(proto.ok());
}

TEST(WsHandshakeValidator, ClientRejectsMissingUpgradeFlag) {
    HsClientFakeIO     io;
    const std::string  key  = "dGhlIHNhbXBsZSBub25jZQ==";
    qb::http::Response resp = valid_handshake_response(key);
    resp.upgrade            = false; // ws.h:1002-1003
    qb::protocol::ws_client<HsClientFakeIO> proto(io, resp, key);
    EXPECT_FALSE(proto.ok());
}

TEST(WsHandshakeValidator, ClientRejectsWrongStatus) {
    HsClientFakeIO     io;
    const std::string  key  = "dGhlIHNhbXBsZSBub25jZQ==";
    qb::http::Response resp = valid_handshake_response(key);
    resp.status()           = qb::http::status::OK; // not 101 => ws.h:1004-1005
    qb::protocol::ws_client<HsClientFakeIO> proto(io, resp, key);
    EXPECT_FALSE(proto.ok());
}

TEST(WsHandshakeValidator, ClientRejectsWrongUpgradeHeader) {
    HsClientFakeIO     io;
    const std::string  key  = "dGhlIHNhbXBsZSBub25jZQ==";
    qb::http::Response resp = valid_handshake_response(key);
    resp.set_header("Upgrade", "h2c"); // ws.h:1006-1007
    qb::protocol::ws_client<HsClientFakeIO> proto(io, resp, key);
    EXPECT_FALSE(proto.ok());
}

TEST(WsHandshakeValidator, ClientRejectsConnectionWithoutUpgradeToken) {
    HsClientFakeIO     io;
    const std::string  key  = "dGhlIHNhbXBsZSBub25jZQ==";
    qb::http::Response resp = valid_handshake_response(key);
    resp.set_header("Connection", "close"); // ws.h:1008-1009
    qb::protocol::ws_client<HsClientFakeIO> proto(io, resp, key);
    EXPECT_FALSE(proto.ok());
}

TEST(WsHandshakeValidator, ClientRejectsEmptyAccept) {
    HsClientFakeIO     io;
    const std::string  key  = "dGhlIHNhbXBsZSBub25jZQ==";
    qb::http::Response resp = valid_handshake_response(key);
    resp.set_header("Sec-WebSocket-Accept", ""); // ws.h:1012-1013
    qb::protocol::ws_client<HsClientFakeIO> proto(io, resp, key);
    EXPECT_FALSE(proto.ok());
}

TEST(WsHandshakeValidator, ClientRejectsMismatchedAccept) {
    HsClientFakeIO     io;
    const std::string  key  = "dGhlIHNhbXBsZSBub25jZQ==";
    qb::http::Response resp = valid_handshake_response(key);
    // Accept computed for a *different* key fails the constant-time compare.
    resp.set_header("Sec-WebSocket-Accept", accept_for("AAAAAAAAAAAAAAAAAAAAAA=="));
    qb::protocol::ws_client<HsClientFakeIO> proto(io, resp, key);
    EXPECT_FALSE(proto.ok());
}

// ===========================================================================
// Coverage Wave-2: callback-based ws::Client event dispatch (ws.h:1548-1685).
//
// The callback `Client` is default-constructible with no socket (the encode
// tests already prove this). Registering each callback and dispatching the
// matching event directly through `client.on(Event{})` drives both the setter
// forwarders and the `if (_on_X) _on_X(event)` true branch of every handler;
// a parallel "no callback registered" pass drives the false branch.
// ===========================================================================

TEST(WsClientCallbacks, RegisteredCallbacksAreInvokedOnDispatch) {
    qb::http::ws::client client;

    bool got_connected = false, got_error = false, got_closed = false;
    bool got_ping = false, got_pong = false, got_message = false, got_disconnected = false;
    bool got_sending = false;

    client.on_sending_http_request([&](auto &) { got_sending = true; })
          .on_connected([&](auto &) { got_connected = true; })
          .on_error([&](auto &) { got_error = true; })
          .on_closed([&](auto &) { got_closed = true; })
          .on_ping([&](auto &) { got_ping = true; })
          .on_pong([&](auto &) { got_pong = true; })
          .on_message([&](auto &) { got_message = true; })
          .on_disconnected([&](auto &) { got_disconnected = true; });

    using C = qb::http::ws::client;

    // Trivial events.
    client.on(C::connected{});
    client.on(C::error{});
    client.on(qb::io::async::event::disconnected{});

    // Message-family events carry a Message reference.
    qb::http::ws::Message msg;
    client.on(C::closed{msg.size(), msg._data.cbegin(), msg});
    client.on(C::ping{msg.size(), msg._data.cbegin(), msg});
    client.on(C::pong{msg.size(), msg._data.cbegin(), msg});
    client.on(C::message{msg.size(), msg._data.cbegin(), msg});

    // sending_http_request carries a WebSocketRequest reference.
    qb::http::WebSocketRequest req(qb::http::ws::generateKey());
    client.on(C::sending_http_request{req});

    EXPECT_TRUE(got_connected);
    EXPECT_TRUE(got_error);
    EXPECT_TRUE(got_closed);
    EXPECT_TRUE(got_ping);
    EXPECT_TRUE(got_pong);
    EXPECT_TRUE(got_message);
    EXPECT_TRUE(got_disconnected);
    EXPECT_TRUE(got_sending);
}

TEST(WsClientCallbacks, UnsetCallbacksAreSafeNoOps) {
    // No callbacks registered => every handler takes the `if (_on_X)` false
    // branch and must not crash.
    qb::http::ws::client client;

    using C = qb::http::ws::client;
    client.on(C::connected{});
    client.on(C::error{});
    client.on(qb::io::async::event::disconnected{});

    qb::http::ws::Message msg;
    client.on(C::closed{msg.size(), msg._data.cbegin(), msg});
    client.on(C::ping{msg.size(), msg._data.cbegin(), msg});
    client.on(C::pong{msg.size(), msg._data.cbegin(), msg});
    client.on(C::message{msg.size(), msg._data.cbegin(), msg});

    qb::http::WebSocketRequest req(qb::http::ws::generateKey());
    client.on(C::sending_http_request{req});

    SUCCEED();
}

// ===========================================================================
// Coverage Wave-2: socket-less server-side frame parser (getMessageSize /
// onMessage / reset). Drives the framing-error arms the over-the-wire framing
// test cannot easily reach. A masked client->server frame is fed into the
// fake IO's input pipe and the parse loop is run until no further complete
// message is available.
// ===========================================================================

namespace {

struct WsFramerFakeIO {
    using base_io_t                  = WsFramerFakeIO;
    static constexpr bool has_server = true;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;
    std::size_t               message_count = 0;
    struct error {};

    qb::allocator::pipe<char> &in() noexcept { return input; }
    qb::allocator::pipe<char> &out() noexcept { return output; }

    template <typename T>
    WsFramerFakeIO &operator<<(const T &msg) {
        output.put(msg);
        return *this;
    }
    void on(qb::protocol::ws_internal::event_message &&) { ++message_count; }
    void on(qb::protocol::ws_internal::event_close &&) {}
    void on(qb::protocol::ws_internal::event_ping &&) {}
    void on(qb::protocol::ws_internal::event_pong &&) {}
    void on(error &&) {}
};

using WsFramer = qb::protocol::ws_server<WsFramerFakeIO>;

// Append a masked client->server frame to the pipe. first_byte = FIN/RSV/opcode.
// The extended-length form is selected automatically from payload size, but
// `force_len_indicator` lets a test emit a *non-minimal* length encoding (e.g.
// a 16-bit length field for a tiny payload) to drive the minimal-encoding guard.
void push_masked_frame(qb::allocator::pipe<char> &pipe, std::uint8_t first_byte, std::string_view payload,
                       int force_len_indicator = -1) {
    const std::array<std::uint8_t, 4> mask{{0xAA, 0x55, 0x01, 0xFE}};
    std::vector<std::uint8_t>         out;
    out.push_back(first_byte);

    const std::size_t len = payload.size();
    int               indicator;
    if (force_len_indicator >= 0) {
        indicator = force_len_indicator;
    } else if (len < 126) {
        indicator = static_cast<int>(len);
    } else if (len <= 0xFFFF) {
        indicator = 126;
    } else {
        indicator = 127;
    }

    out.push_back(static_cast<std::uint8_t>(0x80u | static_cast<std::uint8_t>(indicator))); // MASK bit + len7
    if (indicator == 126) {
        out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFF));
        out.push_back(static_cast<std::uint8_t>(len & 0xFF));
    } else if (indicator == 127) {
        for (int s = 7; s >= 0; --s)
            out.push_back(static_cast<std::uint8_t>((static_cast<std::uint64_t>(len) >> (8 * s)) & 0xFF));
    }
    for (auto b : mask)
        out.push_back(b);
    for (std::size_t i = 0; i < len; ++i)
        out.push_back(static_cast<std::uint8_t>(static_cast<std::uint8_t>(payload[i]) ^ mask[i & 3u]));

    pipe.put(reinterpret_cast<const char *>(out.data()), out.size());
}

// Run the framer until it can no longer extract a complete message or it fails.
void run_framer(WsFramer &proto, WsFramerFakeIO &io) {
    std::size_t n;
    while (proto.ok() && (n = proto.getMessageSize()) > 0) {
        proto.onMessage(n);
        io.input.free_front(n);
    }
}

} // namespace

TEST(WsFramerErrors, FinalContinuationWithNoInitialDataFrameFails) {
    WsFramerFakeIO io;
    WsFramer       proto(io, valid_upgrade_request());
    ASSERT_TRUE(proto.ok());

    // A FIN continuation frame (opcode 0x0 + FIN) with no preceding data frame:
    // _data_opcode is still 0 => ws.h:565-567 ProtocolError.
    push_masked_frame(io.input, 0x80u /*FIN + Continuation*/, "x");
    run_framer(proto, io);
    EXPECT_FALSE(proto.ok());
}

TEST(WsFramerErrors, ControlFrameWithExtendedLengthFails) {
    WsFramerFakeIO io;
    WsFramer       proto(io, valid_upgrade_request());
    ASSERT_TRUE(proto.ok());

    // A close frame (control) whose length field uses the 16-bit extended form
    // (indicator 126) => ws.h:686-689 "Control frame cannot have extended
    // payload length". Payload kept tiny; the indicator is forced.
    push_masked_frame(io.input, qb::http::ws::opcode::Close, "ab", /*force=*/126);
    run_framer(proto, io);
    EXPECT_FALSE(proto.ok());
}

TEST(WsFramerErrors, NonMinimal16BitLengthFails) {
    WsFramerFakeIO io;
    WsFramer       proto(io, valid_upgrade_request());
    ASSERT_TRUE(proto.ok());

    // A text frame that uses the 16-bit length form (indicator 126) for a tiny
    // payload (< 126) => ws.h:704-706 "Non-minimal payload length encoding".
    push_masked_frame(io.input, qb::http::ws::opcode::Text, "hi", /*force=*/126);
    run_framer(proto, io);
    EXPECT_FALSE(proto.ok());
}

TEST(WsFramerErrors, NonMinimal64BitLengthFails) {
    WsFramerFakeIO io;
    WsFramer       proto(io, valid_upgrade_request());
    ASSERT_TRUE(proto.ok());

    // A text frame using the 64-bit length form (indicator 127) for a value that
    // fits in 16 bits => ws.h:707-709 "Non-minimal payload length encoding".
    push_masked_frame(io.input, qb::http::ws::opcode::Text, "hi", /*force=*/127);
    run_framer(proto, io);
    EXPECT_FALSE(proto.ok());
}

TEST(WsFramerErrors, GetMessageSizeReturnsZeroAfterFailure) {
    WsFramerFakeIO io;
    WsFramer       proto(io, valid_upgrade_request());
    ASSERT_TRUE(proto.ok());

    // Fail the parser with a reserved opcode, then assert getMessageSize()
    // short-circuits to 0 on the next call (ws.h:624-625 !this->ok()).
    push_masked_frame(io.input, 0x83u /*FIN + reserved opcode 0x3*/, "x");
    run_framer(proto, io);
    ASSERT_FALSE(proto.ok());
    EXPECT_EQ(proto.getMessageSize(), 0u);
}

TEST(WsFramerErrors, ResetClearsPerFrameState) {
    WsFramerFakeIO io;
    WsFramer       proto(io, valid_upgrade_request());
    ASSERT_TRUE(proto.ok());

    // Feed a complete masked text frame, then call reset() (ws.h:775-780) — the
    // framer must accept a fresh frame afterwards and dispatch it.
    push_masked_frame(io.input, qb::http::ws::opcode::Text, "first");
    run_framer(proto, io);
    EXPECT_EQ(io.message_count, 1u);

    proto.reset();

    push_masked_frame(io.input, qb::http::ws::opcode::Text, "second");
    run_framer(proto, io);
    EXPECT_EQ(io.message_count, 2u);
    EXPECT_TRUE(proto.ok());
}

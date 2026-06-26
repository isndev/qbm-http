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

#include <stdexcept>
#include <string>

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

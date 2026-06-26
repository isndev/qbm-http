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

/**
 * @file qbm/http/tests/unit/ws/ws-key-crypto.cpp
 * @brief WebSocket handshake crypto primitives (RFC 6455 §1.3 / §4.2.2).
 *
 * Pure, deterministic UNIT cases — no socket, no event loop, no server:
 *
 *   - KeyUniqueness        — `generateKey()` produces a fresh, well-formed
 *                            16-byte nonce each call: keys never collide, decode
 *                            back to exactly 16 bytes, and base64-round-trip
 *                            (re-encoding the decoded bytes reproduces the key).
 *   - AcceptKeyComputation — the Sec-WebSocket-Accept value for the RFC's
 *                            published example key matches the published result,
 *                            i.e. `base64(sha1(key + GUID)) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="`.
 *
 * These need OpenSSL only as a *link* dependency: `generateKey` draws from the
 * OpenSSL CSPRNG and the accept-key derivation uses `qb::crypto` SHA-1/base64.
 * There is no network and no TLS here — REQUIRES ssl (crypto link), tier:unit.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <set>
#include <string>

#include <gtest/gtest.h>

#include <qb/io/crypto.h>

#include "../ws/ws.h"

namespace {

// RFC 6455 §1.3 GUID appended to the client key before SHA-1.
constexpr const char *kWsAcceptGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

} // namespace

// ===========================================================================
// generateKey() entropy / well-formedness
// ===========================================================================

TEST(WsKeyCrypto, KeyUniqueness) {
    constexpr int         kNumKeys = 100;
    std::set<std::string> keys;

    for (int i = 0; i < kNumKeys; ++i) {
        const std::string key = qb::http::ws::generateKey();

        // No collisions across the sample.
        EXPECT_TRUE(keys.insert(key).second) << "key collision detected: " << key;

        // RFC 6455 §4.1: the key is base64 of a fresh 16-byte nonce.
        const std::string decoded = qb::crypto::base64::decode(key);
        EXPECT_EQ(decoded.size(), 16u) << "decoded key must be exactly 16 bytes: " << key;

        // Base64 validity: re-encoding the decoded bytes must reproduce the key.
        EXPECT_EQ(qb::crypto::base64::encode(decoded), key) << "key is not a valid canonical base64 string: " << key;
    }

    EXPECT_EQ(keys.size(), static_cast<std::size_t>(kNumKeys)) << "keys should all be unique";
}

// ===========================================================================
// Sec-WebSocket-Accept derivation against the RFC's published example
// ===========================================================================

TEST(WsKeyCrypto, AcceptKeyComputation) {
    const std::string key             = "dGhlIHNhbXBsZSBub25jZQ==";
    const std::string expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    const std::string computed_accept = qb::crypto::base64::encode(qb::crypto::sha1(key + kWsAcceptGuid));

    EXPECT_EQ(computed_accept, expected_accept) << "accept-key computation is incorrect";
}

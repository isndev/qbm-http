/**
 * @file qbm/http/tests/unit/ws/ws-close-frame-negative.cpp
 * @brief Pure-logic negative tests for the WebSocket Close-frame surface.
 *
 * These cases pin down the in-process hardening of `qb::http::ws` against the
 * well-known footguns of RFC 6455 §5.5.1 / §7.4 — entirely without a socket or
 * event loop. They are the UNIT half of the old `test-ws-coro-negative.cpp`
 * monolith (the two handshake-over-the-wire cases moved to
 * `system/ws/ws-coro-handshake-negative.cpp`).
 *
 *   - `ReservedCloseCodeIsRefused`        — `MessageClose` throws for reserved /
 *                                           out-of-range status codes.
 *   - `CoroClientCloseAsyncRefusesReservedCode` — `coro_client::close_async`
 *                                           re-dispatches through the same
 *                                           constructor; the throw surfaces at
 *                                           the `co_await` boundary on a client
 *                                           that never touched a socket.
 *   - `OversizedCloseReasonIsTruncated`   — reasons over the 123-byte budget are
 *                                           clipped, not overflowed.
 *   - `OversizedUtf8CloseReasonKeepsValidBoundary` — truncation never cuts a
 *                                           multi-byte UTF-8 sequence in half.
 *   - `InvalidUtf8CloseReasonIsRejected`  — non-UTF-8 reasons are refused.
 *   - `IsUtf8AcceptsAndRejects`           — the `is_utf8` validator directly.
 *   - `CoroClientPendingCapZeroDropsFrame` — with the cap at 0 and no awaiter
 *                                           parked, an inbound frame is dropped
 *                                           and the subsequent `receive()` does
 *                                           NOT observe it (asserted post-state).
 *
 * This TU REQUIRES the SSL/crypto library to LINK (`ws/ws.h` `#error`s without
 * `QB_HAS_SSL` because the handshake uses `qb::io::crypto` SHA-1/base64), but it
 * never opens a TLS — or any — connection. It is a `tier:unit` test.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

#include <qbm/http/ws.h>

namespace {

// ---------------------------------------------------------------------------
// 1. MessageClose constructor — reserved / out-of-range status codes.
// ---------------------------------------------------------------------------

TEST(WsCloseFrameNegative, ReservedCloseCodeIsRefused) {
    using qb::http::ws::MessageClose;

    // RFC 6455 §7.4.1 — the following codes MUST NOT appear on the wire.
    for (std::uint16_t code : {1004u, 1005u, 1006u, 1015u}) {
        EXPECT_THROW(MessageClose(static_cast<std::uint16_t>(code), "should not build"), std::invalid_argument) << "code=" << code;
    }

    // Out-of-range codes must be refused too.
    EXPECT_THROW(MessageClose(static_cast<std::uint16_t>(999u), ""), std::invalid_argument);
    EXPECT_THROW(MessageClose(static_cast<std::uint16_t>(5000u), ""), std::invalid_argument);

    // Boundary codes that ARE sendable must build without throwing.
    EXPECT_NO_THROW(MessageClose(static_cast<std::uint16_t>(1000u), "ok"));
    EXPECT_NO_THROW(MessageClose(static_cast<std::uint16_t>(4999u), "private"));
}

// `coro_client::close_async(CloseStatus)` re-dispatches through the same
// `MessageClose(code, reason)` constructor, so the throw must surface inside the
// coroutine. The client is never connected — this is pure constructor logic that
// happens to be reached through the awaiter, so it stays in the unit tier.
TEST(WsCloseFrameNegative, CoroClientCloseAsyncRefusesReservedCode) {
    qb::io::async::init();

    auto scenario = [&]() -> qb::io::async::task<bool> {
        qb::http::ws::coro_client ws;
        try {
            // 1005 ("no status received") is reserved: forge it via a cast.
            (void) co_await ws.close_async(static_cast<qb::http::ws::CloseStatus>(1005u));
            co_return false;
        } catch (std::invalid_argument const &) {
            co_return true;
        } catch (...) {
            co_return false;
        }
    };

    EXPECT_TRUE(qb::http::ws::run_sync(scenario()));
}

// ---------------------------------------------------------------------------
// 2. Oversized / non-UTF-8 close reasons — RFC 6455 §5.5.1 caps the control
//    frame payload at 125 bytes, leaving 123 for the reason after the 2-byte
//    status code.
// ---------------------------------------------------------------------------

TEST(WsCloseFrameNegative, OversizedCloseReasonIsTruncated) {
    using qb::http::ws::CloseStatus;
    using qb::http::ws::MessageClose;

    const std::string reason(200, 'x');
    MessageClose      msg{CloseStatus::Normal, reason};

    // Payload is [status_hi, status_lo, reason...]; only 123 reason bytes fit.
    ASSERT_GE(msg.size(), 2u);
    EXPECT_LE(msg.size(), 125u);
    EXPECT_EQ(msg.size(), 2u + 123u);

    const char *bytes = msg._data.begin();
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[0]), static_cast<std::uint8_t>((static_cast<std::uint16_t>(CloseStatus::Normal) >> 8) & 0xFFu));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[1]), static_cast<std::uint8_t>(static_cast<std::uint16_t>(CloseStatus::Normal) & 0xFFu));

    for (std::size_t i = 2; i < msg.size(); ++i) {
        EXPECT_EQ(bytes[i], 'x') << "idx=" << i;
    }
}

TEST(WsCloseFrameNegative, OversizedUtf8CloseReasonKeepsValidBoundary) {
    using qb::http::ws::CloseStatus;
    using qb::http::ws::MessageClose;

    // 121 ASCII bytes + '€' (3 bytes) = 124 bytes. A naive 123-byte cut would
    // split the multi-byte sequence; the constructor must back off to 121.
    const std::string reason = std::string(121, 'a') + std::string("\xE2\x82\xAC");
    MessageClose      msg{CloseStatus::Normal, reason};

    ASSERT_GE(msg.size(), 2u);
    const std::string_view wire_reason{msg._data.cbegin() + 2, msg.size() - 2};
    EXPECT_TRUE(qb::http::ws::is_utf8(wire_reason));
    EXPECT_EQ(wire_reason, std::string_view(std::string(121, 'a')));
}

TEST(WsCloseFrameNegative, InvalidUtf8CloseReasonIsRejected) {
    using qb::http::ws::CloseStatus;
    using qb::http::ws::MessageClose;

    // UTF-16 high-surrogate encoded as UTF-8 — illegal as a scalar value.
    const std::string invalid_utf8{static_cast<char>(0xED), static_cast<char>(0xA0), static_cast<char>(0x80)};

    EXPECT_THROW((MessageClose(CloseStatus::Normal, invalid_utf8)), std::invalid_argument);
}

// ---------------------------------------------------------------------------
// 3. `is_utf8` validator — exercised directly so the clamp tests above rest on
//    a proven primitive.
// ---------------------------------------------------------------------------

TEST(WsCloseFrameNegative, IsUtf8AcceptsAndRejects) {
    using qb::http::ws::is_utf8;

    EXPECT_TRUE(is_utf8(std::string_view{""}));
    EXPECT_TRUE(is_utf8(std::string_view{"plain ascii"}));
    EXPECT_TRUE(is_utf8(std::string_view{"\xE2\x82\xAC"}));     // €
    EXPECT_TRUE(is_utf8(std::string_view{"\xF0\x9F\x98\x80"})); // 😀

    // Lone continuation byte, truncated 3-byte sequence, and a surrogate.
    EXPECT_FALSE(is_utf8(std::string_view{"\x80"}));
    EXPECT_FALSE(is_utf8(std::string_view{"\xE2\x82"}));
    EXPECT_FALSE(is_utf8(std::string_view{"\xED\xA0\x80"}));
    EXPECT_FALSE(is_utf8(std::string_view{"\xC0\x80"})); // overlong NUL
}

// Exhaustive per-class coverage of is_utf8 (ws.cpp:108-199): every leading-byte
// range gets a valid sequence (continue branch), a continuation/range error,
// and a truncation (i+k >= n) error. Drives every range arm and the final
// `return false` for invalid lead bytes.
TEST(WsCloseFrameNegative, IsUtf8AllByteClasses) {
    using qb::http::ws::is_utf8;

    // --- 2-byte: 0xC2..0xDF ---
    EXPECT_TRUE(is_utf8(std::string_view{"\xC2\xA9"}));  // © valid
    EXPECT_TRUE(is_utf8(std::string_view{"\xDF\xBF"}));  // upper bound valid
    EXPECT_FALSE(is_utf8(std::string_view{"\xC2", 1}));  // truncated (i+1>=n)
    EXPECT_FALSE(is_utf8(std::string_view{"\xC2\x20"})); // 2nd byte not continuation

    // --- 3-byte 0xE0: 2nd byte must be 0xA0..0xBF (no overlong) ---
    EXPECT_TRUE(is_utf8(std::string_view{"\xE0\xA4\xB9"}));  // valid (U+0939)
    EXPECT_FALSE(is_utf8(std::string_view{"\xE0\xA4", 2}));  // truncated (i+2>=n)
    EXPECT_FALSE(is_utf8(std::string_view{"\xE0\x80\x80"})); // overlong: b1 < 0xA0
    EXPECT_FALSE(is_utf8(std::string_view{"\xE0\xA4\x20"})); // 3rd byte not continuation

    // --- 3-byte 0xE1..0xEC: both trailing must be continuation ---
    EXPECT_TRUE(is_utf8(std::string_view{"\xE1\x80\x80"}));  // valid
    EXPECT_FALSE(is_utf8(std::string_view{"\xE1\x80", 2}));  // truncated
    EXPECT_FALSE(is_utf8(std::string_view{"\xE1\x20\x80"})); // b1 not continuation

    // --- 3-byte 0xED: 2nd byte 0x80..0x9F (surrogates excluded) ---
    EXPECT_TRUE(is_utf8(std::string_view{"\xED\x9F\xBF"}));  // U+D7FF valid
    EXPECT_FALSE(is_utf8(std::string_view{"\xED\x9F", 2}));  // truncated
    EXPECT_FALSE(is_utf8(std::string_view{"\xED\x80\x20"})); // 3rd byte not continuation

    // --- 3-byte 0xEE..0xEF ---
    EXPECT_TRUE(is_utf8(std::string_view{"\xEE\x80\x80"}));  // valid
    EXPECT_TRUE(is_utf8(std::string_view{"\xEF\xBF\xBD"}));  // U+FFFD replacement char
    EXPECT_FALSE(is_utf8(std::string_view{"\xEE\x80", 2}));  // truncated
    EXPECT_FALSE(is_utf8(std::string_view{"\xEE\x20\x80"})); // b1 not continuation

    // --- 4-byte 0xF0: 2nd byte 0x90..0xBF (no overlong) ---
    EXPECT_TRUE(is_utf8(std::string_view{"\xF0\x90\x80\x80"}));  // U+10000 valid
    EXPECT_FALSE(is_utf8(std::string_view{"\xF0\x90\x80", 3}));  // truncated (i+3>=n)
    EXPECT_FALSE(is_utf8(std::string_view{"\xF0\x80\x80\x80"})); // overlong: b1 < 0x90
    EXPECT_FALSE(is_utf8(std::string_view{"\xF0\x90\x80\x20"})); // 4th byte not continuation

    // --- 4-byte 0xF1..0xF3 ---
    EXPECT_TRUE(is_utf8(std::string_view{"\xF1\x80\x80\x80"}));  // valid
    EXPECT_FALSE(is_utf8(std::string_view{"\xF3\x80\x80", 3}));  // truncated
    EXPECT_FALSE(is_utf8(std::string_view{"\xF1\x20\x80\x80"})); // b1 not continuation

    // --- 4-byte 0xF4: 2nd byte 0x80..0x8F (cap at U+10FFFF) ---
    EXPECT_TRUE(is_utf8(std::string_view{"\xF4\x8F\xBF\xBF"}));  // U+10FFFF valid
    EXPECT_FALSE(is_utf8(std::string_view{"\xF4\x80\x80", 3}));  // truncated
    EXPECT_FALSE(is_utf8(std::string_view{"\xF4\x90\x80\x80"})); // b1 > 0x8F (out of range)
    EXPECT_FALSE(is_utf8(std::string_view{"\xF4\x80\x80\x20"})); // 4th byte not continuation

    // --- invalid lead bytes that fall through to the final return false ---
    EXPECT_FALSE(is_utf8(std::string_view{"\xC1\x80"}));         // 0xC1 (< 0xC2)
    EXPECT_FALSE(is_utf8(std::string_view{"\xF5\x80\x80\x80"})); // 0xF5 (> 0xF4)
    EXPECT_FALSE(is_utf8(std::string_view{"\xFF"}));             // 0xFF never valid
}

// ---------------------------------------------------------------------------
// 4. pending-cap == 0 frame-drop — pure delivery-path logic with no socket.
//    Prior to the fix this could `pop_front()` an empty deque; the guard must
//    drop the frame silently AND leave no buffered frame behind.
// ---------------------------------------------------------------------------

TEST(WsCloseFrameNegative, CoroClientPendingCapZeroDropsFrame) {
    qb::io::async::init();

    qb::http::ws::coro_client ws;
    ws.set_pending_cap(0);

    using MessageEvent = qb::http::ws::coro_client<>::message;

    qb::http::ws::MessageText dropped;
    dropped << "dropped";
    MessageEvent drop_event{dropped.size(), dropped.data().cbegin(), dropped};

    // No awaiter is parked and the cap is 0 → the frame must be discarded with
    // no crash. Prior to the fix this could pop_front() an empty deque.
    ws.on(std::move(drop_event));

    // Post-state assertion (stronger than the old bare SUCCEED()): re-enable
    // buffering, deliver a SECOND frame, and prove the very next receive()
    // resolves synchronously with the second frame — never the dropped one.
    // If the dropped frame had leaked into the buffer, "dropped" would arrive
    // first and this would fail.
    ws.set_pending_cap(8);

    qb::http::ws::MessageText kept;
    kept << "kept";
    MessageEvent keep_event{kept.size(), kept.data().cbegin(), kept};
    ws.on(std::move(keep_event));

    auto probe = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        co_return co_await ws.receive();
    };

    const auto frame = qb::http::ws::run_sync(probe());
    EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Message);
    EXPECT_EQ(frame.payload, "kept") << "the cap-0 frame must have been dropped, not buffered";
}

} // namespace

/**
 * @file qbm/http/tests/test-coro-negative.cpp
 * @brief Negative tests for the coroutine-first WebSocket API.
 *
 * These tests pin down the safety net around well-known footguns of the
 * WebSocket protocol (RFC 6455) and make sure the coroutine surface
 * surfaces the failures cleanly instead of silently producing invalid
 * wire frames:
 *
 *   - `ReservedCloseCodeIsRefused`     — `MessageClose` refuses to build a
 *                                        Close frame for reserved/out-of-range
 *                                        status codes (1004/1005/1006/1015,
 *                                        < 1000, > 4999).
 *   - `CoroClientCloseAsyncPropagatesClampedCode` — `coro_client::close_async`
 *                                        rejects reserved typed codes at the
 *                                        `co_await` boundary.
 *   - `CoroSessionCloseAsyncPropagatesClampedCode` — same for the
 *                                        server-side `coro_session`.
 *   - `ClientRefusesHandshakeWithoutVersion` — a server that does NOT send
 *                                        `Sec-WebSocket-Version` (simulated
 *                                        here by responding with a 400)
 *                                        makes the client's `connect()`
 *                                        awaiter resolve with `ok == false`.
 *   - `ServerRefusesHandshakeWithoutVersion` — the stock
 *                                        `populate_handshake_response`
 *                                        refuses an upgrade request whose
 *                                        `Sec-WebSocket-Version` header is
 *                                        missing.
 *   - `OversizedCloseReasonIsTruncated` — `MessageClose` silently clips
 *                                        the reason to the 123-byte control
 *                                        frame budget instead of emitting an
 *                                        overflowing frame.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0
 */

#include <atomic>
#include <chrono>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "../ws/coro.h"

namespace {

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// Server that accepts a TCP connection but replies with a plain HTTP 400,
// *without* the `Sec-WebSocket-Version: 13` negotiation. Used to assert the
// coro client correctly reports `ok == false`.
// ---------------------------------------------------------------------------

class NoVersionServer;

class NoVersionSession
    : public qb::io::use<NoVersionSession>::tcp::client<NoVersionServer> {
public:
    using Protocol = qb::http::protocol<NoVersionSession>;

    explicit NoVersionSession(NoVersionServer &s)
        : client(s) {}

    void
    on(Protocol::request &&) {
        // Respond with a raw, non-upgrade 400 Bad Request so the client's
        // handshake validator rejects the response.
        qb::http::Response response;
        response.status() = qb::http::status::BAD_REQUEST;
        response.body()   = "missing upgrade";
        *this << response;
        this->disconnect();
    }
};

class NoVersionServer
    : public qb::io::use<NoVersionServer>::tcp::server<NoVersionSession> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Test harness: identical idiom to test-coro-server.cpp — dedicated
// listener thread for each test.
// ---------------------------------------------------------------------------

template <typename ServerT>
struct ServerThread {
    std::thread        thread;
    std::atomic<bool>  ready{false};
    std::atomic<bool>  running{true};
    int                port{0};

    ServerThread(int port_)
        : port(port_) {
        thread = std::thread([this] {
            qb::io::async::init();
            ServerT server;
            server.transport().listen_v4(port);
            server.start();
            ready.store(true, std::memory_order_release);
            while (running.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(5ms);
                }
            }
        });
        while (!ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(5ms);
        }
        std::this_thread::sleep_for(30ms);
    }

    ~ServerThread() {
        running.store(false, std::memory_order_release);
        if (thread.joinable()) thread.join();
    }
};

class CoroNegativeTest : public ::testing::Test {
protected:
    void SetUp() override { qb::io::async::init(); }
};

// ---------------------------------------------------------------------------
// 1. `MessageClose` constructor hardening — reserved / out-of-range codes.
// ---------------------------------------------------------------------------

TEST_F(CoroNegativeTest, ReservedCloseCodeIsRefused) {
    using qb::http::ws::MessageClose;

    // RFC 6455 §7.4.1 — the following codes MUST NOT appear on the wire:
    for (std::uint16_t code : {1004u, 1005u, 1006u, 1015u}) {
        EXPECT_THROW(MessageClose(static_cast<std::uint16_t>(code),
                                   "should not build"),
                     std::invalid_argument)
            << "code=" << code;
    }

    // Out-of-range codes must be refused too.
    EXPECT_THROW(MessageClose(static_cast<std::uint16_t>(999u), ""),
                 std::invalid_argument);
    EXPECT_THROW(MessageClose(static_cast<std::uint16_t>(5000u), ""),
                 std::invalid_argument);
}

// `coro_client::close_async(CloseStatus)` only accepts the enum form, so
// the awaiter re-dispatches through the same `MessageClose(code, reason)`
// constructor — that throw must surface inside the coroutine.
TEST_F(CoroNegativeTest, CoroClientCloseAsyncPropagatesReserved) {
    auto scenario = [&]() -> qb::io::async::task<bool> {
        qb::http::ws::coro_client ws;
        try {
            // Force-cast a known-reserved code through the enum: the enum
            // members don't include 1005 by default, so we forge the value
            // via `static_cast`.
            (void) co_await ws.close_async(
                static_cast<qb::http::ws::CloseStatus>(1005u));
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
// 2. `Sec-WebSocket-Version` enforcement — client side.
// ---------------------------------------------------------------------------

TEST_F(CoroNegativeTest, ClientRefusesHandshakeWithoutVersion) {
    ServerThread<NoVersionServer> server{19961};

    auto scenario = [&]() -> qb::io::async::task<bool> {
        qb::http::ws::coro_client ws;
        auto res = co_await ws.connect("ws://localhost:19961/");
        co_return res.ok;
    };

    EXPECT_FALSE(qb::http::ws::run_sync(scenario()));
}

// ---------------------------------------------------------------------------
// 3. `Sec-WebSocket-Version` enforcement — server side.
//    Drives a real `coro_session`-based server with a manually crafted
//    upgrade request that omits `Sec-WebSocket-Version`: the server must
//    close the connection without ever sending a `101 Switching Protocols`.
// ---------------------------------------------------------------------------

class ProbeServer;
class ProbeSession
    : public qb::http::ws::coro_session<ProbeSession, ProbeServer> {
public:
    using base = qb::http::ws::coro_session<ProbeSession, ProbeServer>;
    using base::base;
    qb::io::async::task<void>
    run() {
        co_return;
    }
};
class ProbeServer
    : public qb::io::use<ProbeServer>::tcp::server<ProbeSession> {
public:
    void
    on(IOSession &) {}
};

TEST_F(CoroNegativeTest, ServerRefusesHandshakeWithoutVersion) {
    ServerThread<ProbeServer> server{19962};

    // Hand-crafted upgrade request: missing `Sec-WebSocket-Version`.
    const std::string request =
        "GET /ws HTTP/1.1\r\n"
        "Host: localhost:19962\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "\r\n";

    qb::io::tcp::socket sock;
    const auto         rc =
        sock.connect(qb::io::uri{"tcp://localhost:19962"});
    ASSERT_EQ(rc, 0) << "failed to connect to ProbeServer";

    sock.write(request.data(), static_cast<int>(request.size()));

    // Drain whatever the server is willing to send us until it closes.
    // A compliant implementation closes the socket without sending a
    // `HTTP/1.1 101` line; we assert on the NUL / 101 absence.
    std::string response;
    char        buf[512];
    for (int i = 0; i < 200; ++i) {
        int n = sock.read(buf, sizeof(buf));
        if (n > 0) {
            response.append(buf, static_cast<std::size_t>(n));
        } else if (n == 0) {
            // Peer closed.
            break;
        } else {
            std::this_thread::sleep_for(5ms);
        }
    }
    sock.close();

    EXPECT_EQ(response.find("101"), std::string::npos)
        << "server should NOT send a 101 Switching Protocols on an "
           "upgrade without Sec-WebSocket-Version; got:\n"
        << response;
    EXPECT_NE(response.find("400"), std::string::npos)
        << "server should deliver a BAD_REQUEST response before closing; got:\n"
        << response;
}

// ---------------------------------------------------------------------------
// 4. Oversized close reason — RFC 6455 §5.5.1 caps control frame payload
//    at 125 bytes. `MessageClose` absorbs oversized reasons by truncating
//    to 123 bytes (2 bytes are reserved for the status code).
// ---------------------------------------------------------------------------

TEST_F(CoroNegativeTest, OversizedCloseReasonIsTruncated) {
    using qb::http::ws::MessageClose;
    using qb::http::ws::CloseStatus;

    const std::string reason(200, 'x');
    MessageClose msg{CloseStatus::Normal, reason};
    // The Close frame payload is [status_hi, status_lo, reason...].
    // Only 123 bytes of reason may remain.
    ASSERT_GE(msg.size(), 2u);
    EXPECT_LE(msg.size(), 125u);
    EXPECT_EQ(msg.size(), 2u + 123u);

    const char *bytes = msg._data.begin();
    // Status code is still the one we asked for.
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[0]),
              static_cast<std::uint8_t>(
                  (static_cast<std::uint16_t>(CloseStatus::Normal) >> 8) &
                  0xFFu));
    EXPECT_EQ(static_cast<std::uint8_t>(bytes[1]),
              static_cast<std::uint8_t>(
                  static_cast<std::uint16_t>(CloseStatus::Normal) & 0xFFu));

    // Reason bytes are a prefix of the original string (all 'x').
    for (std::size_t i = 2; i < msg.size(); ++i) {
        EXPECT_EQ(bytes[i], 'x') << "idx=" << i;
    }
}

TEST_F(CoroNegativeTest, OversizedUtf8CloseReasonKeepsValidBoundary) {
    using qb::http::ws::MessageClose;
    using qb::http::ws::CloseStatus;

    // 121 ASCII bytes + '€' (3 bytes) = 124 bytes.
    // A naive 123-byte truncation would cut inside the multi-byte sequence.
    const std::string reason =
        std::string(121, 'a') + std::string("\xE2\x82\xAC");
    MessageClose msg{CloseStatus::Normal, reason};

    ASSERT_GE(msg.size(), 2u);
    const std::string_view wire_reason{msg._data.cbegin() + 2, msg.size() - 2};
    EXPECT_TRUE(qb::http::ws::is_utf8(wire_reason));
    EXPECT_EQ(wire_reason, std::string_view(std::string(121, 'a')));
}

TEST_F(CoroNegativeTest, InvalidUtf8CloseReasonIsRejected) {
    using qb::http::ws::MessageClose;
    using qb::http::ws::CloseStatus;

    const std::string invalid_utf8{
        static_cast<char>(0xED),
        static_cast<char>(0xA0),
        static_cast<char>(0x80)}; // UTF-16 surrogate encoded in UTF-8

    EXPECT_THROW((MessageClose(CloseStatus::Normal, invalid_utf8)),
                 std::invalid_argument);
}

TEST_F(CoroNegativeTest, CoroClientPendingCapZeroDropsWithoutCrash) {
    qb::http::ws::coro_client ws;
    ws.set_pending_cap(0);

    qb::http::ws::MessageText payload;
    payload << "x";

    using MessageEvent = qb::http::ws::coro_client<>::message;
    MessageEvent event{payload.size(), payload.data().cbegin(), payload};

    // Prior to the fix, this path could call pop_front() on an empty deque
    // when pending_cap == 0 and no awaiter was parked.
    ws.on(std::move(event));
    SUCCEED();
}

} // namespace

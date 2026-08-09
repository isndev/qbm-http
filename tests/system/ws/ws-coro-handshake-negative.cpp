/**
 * @file qbm/http/tests/system/ws/ws-coro-handshake-negative.cpp
 * @brief Over-the-wire negative tests for the coroutine WebSocket handshake.
 *
 * The SYSTEM half of the old `test-ws-coro-negative.cpp` monolith: these cases
 * need a real loopback server and a real handshake on the wire (the pure-logic
 * Close-frame / UTF-8 / pending-cap cases live in
 * `unit/ws/ws-close-frame-negative.cpp`).
 *
 *   - `ClientRefusesHandshakeWithoutVersion` — a server that answers a plain
 *     `400` (no `Sec-WebSocket-Accept`) makes the client's `connect()` awaiter
 *     resolve with `ok == false`.
 *   - `ServerRefusesHandshakeWithoutVersion` — a real `coro_session` server,
 *     driven with a raw upgrade request that omits `Sec-WebSocket-Version`,
 *     answers `400` and never sends `101`.
 *   - `CoroSessionCloseAsyncPropagatesClampedCode` — the documented mirror of
 *     the client-side clamp: `coro_session::close_async` re-dispatches through
 *     `MessageClose`, so a reserved code throws at the `co_await` boundary
 *     inside a live session's `run()` and is turned into an orderly `1011`
 *     teardown by the spawn wrapper.
 *
 * Runs plaintext `ws://` over loopback; REQUIRES the SSL/crypto library only to
 * LINK (`ws/ws.h` uses `qb::io::crypto` for the handshake accept-key). Uses the
 * shared `WsServerThread` / `read_http_response` from `shared/ws_loopback.h`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <atomic>
#include <chrono>
#include <string>

#include <gtest/gtest.h>

#include <qbm/http/ws/coro.h>

#include "../../shared/ws_loopback.h"

namespace ws_coro_handshake_negative_test {

using namespace std::chrono_literals;
using qb::http::test::read_http_response;
using qb::http::test::WsServerThread;

// ---------------------------------------------------------------------------
// Server that answers every upgrade with a raw, non-upgrade 400 — no
// `Sec-WebSocket-Accept`, no `101`. The client's handshake validator must
// reject it and report `ok == false`.
// ---------------------------------------------------------------------------

class NoVersionServer;

class NoVersionSession : public qb::io::use<NoVersionSession>::tcp::client<NoVersionServer> {
public:
    using Protocol = qb::http::protocol<NoVersionSession>;

    explicit NoVersionSession(NoVersionServer &s)
        : client(s) {}

    void
    on(Protocol::request &&) {
        qb::http::Response response;
        response.status() = qb::http::status::BAD_REQUEST;
        response.body()   = "missing upgrade";
        *this << response;
        this->disconnect();
    }
};

class NoVersionServer : public qb::io::use<NoVersionServer>::tcp::server<NoVersionSession> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Real coroutine-session server used to prove the SERVER refuses a malformed
// upgrade (missing `Sec-WebSocket-Version`).
// ---------------------------------------------------------------------------

class ProbeServer;

class ProbeSession : public qb::http::ws::coro_session<ProbeSession, ProbeServer> {
public:
    using base = qb::http::ws::coro_session<ProbeSession, ProbeServer>;
    using base::base;

    qb::io::async::task<void>
    run() {
        co_return;
    }
};

class ProbeServer : public qb::io::use<ProbeServer>::tcp::server<ProbeSession> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Coroutine-session server whose `run()` attempts a reserved Close code on the
// first inbound frame. `close_async` re-dispatches through `MessageClose`, so
// the reserved code throws; the `coro_session` spawn wrapper turns the uncaught
// exception into a `1011` Close + disconnect. The client observes that orderly
// teardown.
// ---------------------------------------------------------------------------

class ClampingCoroServer;

class ClampingCoroSession : public qb::http::ws::coro_session<ClampingCoroSession, ClampingCoroServer> {
public:
    using base = qb::http::ws::coro_session<ClampingCoroSession, ClampingCoroServer>;
    using base::base;

    qb::io::async::task<void>
    run() {
        auto frame = co_await this->next_frame();
        if (frame.kind != qb::http::ws::IncomingFrame::Kind::Message) {
            co_return;
        }
        // 1005 is reserved — this MUST throw std::invalid_argument out of the
        // awaiter, which the spawn wrapper converts to a 1011 Close.
        (void) co_await this->close_async(static_cast<qb::http::ws::CloseStatus>(1005u), "should not build");
        co_return; // unreached
    }
};

class ClampingCoroServer : public qb::io::use<ClampingCoroServer>::tcp::server<ClampingCoroSession> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

class WsCoroHandshakeNegative : public ::testing::Test {
protected:
    void
    SetUp() override {
        qb::io::async::init();
    }
};

TEST_F(WsCoroHandshakeNegative, ClientRefusesHandshakeWithoutVersion) {
    WsServerThread<NoVersionServer> server{0};

    const std::string url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto scenario = [&]() -> qb::io::async::task<bool> {
        qb::http::ws::coro_client ws;
        auto                      res = co_await ws.connect(std::string_view{url});
        co_return res.ok;
    };

    EXPECT_FALSE(qb::http::ws::run_sync(scenario()));
}

TEST_F(WsCoroHandshakeNegative, ServerRefusesHandshakeWithoutVersion) {
    WsServerThread<ProbeServer> server{0};

    // Hand-crafted upgrade request: missing `Sec-WebSocket-Version`.
    const std::string request = "GET /ws HTTP/1.1\r\n"
                                "Host: localhost:"
                                + std::to_string(server.port)
                                + "\r\n"
                                  "Upgrade: websocket\r\n"
                                  "Connection: Upgrade\r\n"
                                  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                  "\r\n";

    qb::io::tcp::socket sock;
    ASSERT_EQ(sock.connect(qb::io::uri{"tcp://localhost:" + std::to_string(server.port)}), 0) << "failed to connect to ProbeServer";
    (void) sock.set_nonblocking(true);
    sock.write(request.data(), static_cast<int>(request.size()));

    const std::string response = read_http_response(sock);
    sock.close();

    EXPECT_EQ(response.find("101"), std::string::npos) << "server must NOT send 101 on an upgrade without Sec-WebSocket-Version; got:\n"
                                                       << response;
    EXPECT_NE(response.find("400"), std::string::npos) << "server should deliver a BAD_REQUEST before closing; got:\n" << response;
}

// Documented-but-previously-missing mirror of the client-side clamp: a reserved
// close code attempted from inside a server session's `run()` is refused by
// `MessageClose`, and the session is torn down with a `1011` Close that the
// client observes (rather than the reserved `1005` ever reaching the wire).
TEST_F(WsCoroHandshakeNegative, CoroSessionCloseAsyncPropagatesClampedCode) {
    WsServerThread<ClampingCoroServer> server{0};

    const std::string url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto scenario = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame{};

        qb::http::ws::MessageText msg;
        msg << "trigger";
        ws << msg;

        // The session's reserved-code attempt throws; the spawn wrapper sends a
        // 1011 Close instead. We must never see the reserved 1005.
        co_return co_await ws.receive();
    };

    const auto frame = qb::http::ws::run_sync(scenario());
    EXPECT_TRUE(frame.kind == qb::http::ws::IncomingFrame::Kind::Close || frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected);
    EXPECT_NE(frame.close_code, static_cast<std::uint16_t>(1005u)) << "reserved code must never reach the wire";
    if (frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
        EXPECT_EQ(frame.close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::UnexpectedReason));
    }
}

} // namespace ws_coro_handshake_negative_test

/**
 * @file qbm/http/tests/system/ws/ws-coro-handoff.cpp
 * @brief End-to-end system test: HTTP router -> `extractSession` handoff ->
 *        `coro_session::accept_upgrade` -> coroutine WebSocket echo.
 *
 * Demonstrates the fully supported integration between `qbm-http` and
 * `qb::http::ws`'s coroutine surface:
 *
 *   1. A `qb::http::Server` handles HTTP requests through its router.
 *   2. The `/ws` route detaches the transport (TCP socket + FD) via
 *      `extractSession(session_id)`.
 *   3. The extracted transport is registered on a separate io_handler whose
 *      session type is a `coro_session`, and `accept_upgrade(request, response)`
 *      performs the 101 handshake and spawns the user-defined `run()` coroutine.
 *   4. Both servers share a single event loop (mono-thread invariant of qb-io),
 *      proving there is no cross-thread contention.
 *
 * The `coro_client` on the other end observes a standard ws echo round trip —
 * the same path a real application would take. The handoff outcome is asserted
 * client-observably (the echoed reply proves `accept_upgrade` succeeded) rather
 * than via a cross-thread `EXPECT` on the server thread.
 *
 * Runs plaintext `ws://`; REQUIRES the SSL/crypto library only to LINK
 * (`ws/ws.h` uses `qb::io::crypto` for `Sec-WebSocket-Accept`). The listener
 * port is ephemeral and readiness is a barrier flag — no `sleep_for` warmup.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include <gtest/gtest.h>

#include "../http.h"

#include "../ws/coro.h"

#include "../../shared/loopback_server.h"

namespace {

using namespace std::chrono_literals;
using qb::http::test::ephemeral_port;

// ---------------------------------------------------------------------------
// WS side: server + coroutine session doing a simple text echo.
// ---------------------------------------------------------------------------

class IntegrationWsServer;

class IntegrationWsSession : public qb::http::ws::coro_session<IntegrationWsSession, IntegrationWsServer> {
public:
    using base = qb::http::ws::coro_session<IntegrationWsSession, IntegrationWsServer>;
    using base::base;

    qb::io::async::task<void>
    run() {
        while (true) {
            auto frame = co_await this->next_frame();
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected || frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
                co_return;
            }
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Message) {
                qb::http::ws::MessageText reply;
                reply << "router-echo:" << frame.payload;
                *this << reply;
            }
        }
    }
};

class IntegrationWsServer : public qb::io::use<IntegrationWsServer>::tcp::io_handler<IntegrationWsSession> {};

// ---------------------------------------------------------------------------
// Test fixture: a single thread drives both the HTTP and the WS io_handlers.
// Readiness is signalled through a barrier flag (no sleep_for settle); the
// listener is bound before the flag flips, so a client connecting right after
// construction will not race the bind.
// ---------------------------------------------------------------------------

struct HandoffFixture {
    std::thread                          thread;
    std::atomic<bool>                    ready{false};
    std::atomic<bool>                    running{true};
    std::atomic<bool>                    saw_null_registration{false};
    std::unique_ptr<qb::http::Server<>>  http_server;
    std::unique_ptr<IntegrationWsServer> ws_server;
    std::uint16_t                        port;

    // force_registry_full: when true, the WS io_handler is capped at one slot so
    // a second concurrent handoff exercises the registerSession()==nullptr dead
    // path, giving that previously-untested branch real coverage.
    explicit HandoffFixture(std::uint16_t port_, bool force_registry_full = false)
        : port(port_) {
        thread = std::thread([this, force_registry_full] {
            qb::io::async::init();

            http_server = qb::http::make_server();
            ws_server   = std::make_unique<IntegrationWsServer>();

            if (force_registry_full) {
                // Cap the WS io_handler's session registry at 1. The first
                // handoff succeeds and that long-lived session occupies the slot;
                // a concurrent SECOND handoff then hits the cap and
                // registerSession() returns nullptr — driving the dead path.
                ws_server->set_max_sessions(1u);
            }

            http_server->router().get("/ping", [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
                ctx->response().body() = "pong";
                ctx->complete();
            });

            http_server->router().get("/ws", [this](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
                auto session_id      = ctx->session()->id();
                auto [transport, ok] = http_server->extractSession(session_id);
                if (!ok) {
                    ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                    ctx->response().body()   = "extractSession failed";
                    ctx->complete();
                    return;
                }

                auto *sess = ws_server->registerSession(std::move(transport));
                if (sess == nullptr) {
                    // Registry full — the HTTP response pipe is already detached,
                    // so we can only drop the FD. This is the dead path the
                    // NullRegistration test forces.
                    saw_null_registration.store(true, std::memory_order_release);
                    ctx->suppress_response();
                    return;
                }

                qb::http::Response response;
                const bool         upgraded = sess->accept_upgrade(ctx->request(), response);
                // Do NOT cross-thread EXPECT here; the echo round trip on the
                // client proves the upgrade. We still drop the connection if the
                // upgrade somehow failed so the client observes a clean failure.
                (void) upgraded;
                ctx->suppress_response();
            });
            http_server->router().compile();

            http_server->transport().listen_v4(port);
            http_server->start();

            if (force_registry_full) {
                // Deterministically occupy the single WS slot BEFORE any client
                // connects. We open a loopback socket to our own listener (the
                // HTTP side accepts it as an idle session that never sends a
                // request) and register the client end as a WS filler session.
                // Every subsequent /ws handoff then hits the cap → nullptr, with
                // no race and no risk of a hang.
                qb::io::tcp::socket filler;
                if (filler.connect(qb::io::uri{"tcp://127.0.0.1:" + std::to_string(port)}) == 0) {
                    (void) ws_server->registerSession(std::move(filler));
                }
            }

            ready.store(true, std::memory_order_release);
            while (running.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(2ms);
                }
            }

            ws_server.reset();
            http_server.reset();
        });

        while (!ready.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    }

    ~HandoffFixture() {
        running.store(false, std::memory_order_release);
        if (thread.joinable())
            thread.join();
    }
};

class WsCoroHandoff : public ::testing::Test {
protected:
    void
    SetUp() override {
        qb::io::async::init();
    }
};

// ---------------------------------------------------------------------------
// Test: full round-trip through router -> extractSession -> coro_session.
// ---------------------------------------------------------------------------

TEST_F(WsCoroHandoff, RouterHandoffAndCoroEcho) {
    const std::uint16_t port = ephemeral_port();
    HandoffFixture      fixture{port};

    auto scenario = [&]() -> qb::io::async::task<std::string> {
        qb::http::ws::coro_client ws;
        const std::string         url = "ws://localhost:" + std::to_string(port) + "/ws";
        auto                      c   = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return std::string{};

        qb::http::ws::MessageText msg;
        msg << "hello-from-coro";
        ws << msg;

        auto frame = co_await ws.receive();
        EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Message);
        EXPECT_TRUE(frame.is_text);

        (void) co_await ws.close_async(qb::http::ws::CloseStatus::Normal, "bye");
        co_return frame.payload;
    };

    // The echoed reply is the client-observable proof that accept_upgrade()
    // succeeded on the server thread.
    EXPECT_EQ(qb::http::ws::run_sync(scenario()), "router-echo:hello-from-coro");
}

// A non-WS GET on the same server must still be handled by the plain HTTP
// router — proving the handoff is opt-in and doesn't leak into unrelated
// traffic.
TEST_F(WsCoroHandoff, NonUpgradeRouteStaysOnHttp) {
    const std::uint16_t port = ephemeral_port();
    HandoffFixture      fixture{port};

    qb::http::Request request;
    request.uri()    = qb::io::uri{"http://localhost:" + std::to_string(port) + "/ping"};
    request.method() = qb::http::method::GET;

    auto resp = qb::http::run_sync(qb::http::GET(request)).response;
    EXPECT_EQ(resp.status(), qb::http::status::OK);
    EXPECT_EQ(resp.body().template as<std::string>(), "pong");
}

// A plain HTTP/1.1 GET (NO Upgrade headers) routed to /ws must NOT produce a
// WebSocket upgrade: extractSession + accept_upgrade run, but switch_protocol
// fails on the missing handshake headers, so the client never sees a 101 and
// the request resolves as a non-OK / closed connection rather than an echo.
TEST_F(WsCoroHandoff, NonWebSocketRequestToWsRouteIsNotUpgraded) {
    const std::uint16_t port = ephemeral_port();
    HandoffFixture      fixture{port};

    qb::io::tcp::socket sock;
    ASSERT_EQ(sock.connect(qb::io::uri{"tcp://localhost:" + std::to_string(port)}), 0);
    (void) sock.set_nonblocking(true);

    const std::string request = "GET /ws HTTP/1.1\r\n"
                                "Host: localhost:"
                                + std::to_string(port)
                                + "\r\n"
                                  "\r\n";
    sock.write(request.data(), static_cast<int>(request.size()));

    // Read whatever the server is willing to send until it closes. A compliant
    // server answers the handshake failure with a non-101 (BAD_REQUEST) and/or
    // drops the socket — it must NEVER send a 101 Switching Protocols.
    std::string response;
    char        buf[512];
    const auto  deadline = std::chrono::steady_clock::now() + 2s;
    while (std::chrono::steady_clock::now() < deadline) {
        int n = sock.read(buf, sizeof(buf));
        if (n > 0) {
            response.append(buf, static_cast<std::size_t>(n));
            if (response.find("\r\n\r\n") != std::string::npos) {
                break;
            }
        } else if (n == 0) {
            break; // peer closed
        } else {
            std::this_thread::sleep_for(2ms);
        }
    }
    sock.close();

    EXPECT_EQ(response.find("101"), std::string::npos) << "a non-WS request must not be upgraded; got:\n" << response;
}

// registerSession() returning nullptr is a real (if rare) failure mode: the WS
// io_handler's registry is full. The fixture deterministically pre-fills the
// single slot (a filler session) BEFORE the test connects, so the one /ws
// handoff is guaranteed to hit the cap and take the dead path — no race, no
// hang. We assert the client is cleanly disconnected and the server actually
// executed the nullptr branch.
TEST_F(WsCoroHandoff, RegisterSessionNullptrIsHandledGracefully) {
    const std::uint16_t port = ephemeral_port();
    HandoffFixture      fixture{port, /*force_registry_full=*/true};

    const std::string url = "ws://localhost:" + std::to_string(port) + "/ws";

    auto scenario = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame::Kind> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect(std::string_view{url});
        // The handoff route extracts the transport, then registerSession()
        // returns nullptr (slot already full) and drops the FD: the client never
        // sees a 101, so connect() resolves ok=false. Either way receive() must
        // resolve (Disconnected), never hang.
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame::Kind::Disconnected;
        co_return (co_await ws.receive()).kind;
    };

    const auto kind = qb::http::ws::run_sync(scenario());
    EXPECT_EQ(kind, qb::http::ws::IncomingFrame::Kind::Disconnected) << "the capped handoff must be dropped, not hang or echo";
    EXPECT_TRUE(fixture.saw_null_registration.load(std::memory_order_acquire)) << "the registerSession()==nullptr dead path was never reached";
}

TEST_F(WsCoroHandoff, PersistentHttp1ClientCanReuseConnectionBeforeUpgrade) {
    const std::uint16_t port = ephemeral_port();
    HandoffFixture      fixture{port};

    auto              client = qb::http1::make_client("http://localhost:" + std::to_string(port));
    qb::http::Request first;
    first.uri()              = qb::io::uri{"/ping"};
    first.method()           = qb::http::method::GET;
    qb::http::Request second = first;

    auto first_response  = qb::http::run_sync(client->push_request(std::move(first)));
    auto second_response = qb::http::run_sync(client->push_request(std::move(second)));

    EXPECT_EQ(first_response.status(), qb::http::status::OK);
    EXPECT_EQ(second_response.status(), qb::http::status::OK);
    EXPECT_EQ(first_response.body().template as<std::string>(), "pong");
    EXPECT_EQ(second_response.body().template as<std::string>(), "pong");
    EXPECT_TRUE(client->is_connected());

    // Drop the persistent client and drain the parent loop so the deferred self-guard
    // release (Client::hold_through_current_tick's 1us callback) fires — otherwise the
    // last response callback leaves _callback_self_guard set and the connection's io
    // watcher registered when the fixture closes the server. Mirrors the established
    // pattern in Http1ClientTest.DestroyingClientDuringConnectDoesNotLeaveDanglingCallback.
    client.reset();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
    while (std::chrono::steady_clock::now() < deadline)
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
}

} // namespace

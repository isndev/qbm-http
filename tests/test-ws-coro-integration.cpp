/**
 * @file qbm/http/tests/test-coro-integration.cpp
 * @brief End-to-end test: HTTP router -> `extractSession` handoff ->
 *        `coro_session::accept_upgrade` -> coroutine WebSocket echo.
 *
 * Demonstrates the fully supported integration between `qbm-http` and
 * `qb::http::ws`'s coroutine surface:
 *
 *   1. A `qb::http::Server` handles HTTP requests through its router.
 *   2. The `/ws` route detaches the transport (TCP socket + FD) via
 *      `extractSession(session_id)`.
 *   3. The extracted transport is registered on a separate io_handler
 *      whose session type is a `coro_session`, and
 *      `accept_upgrade(request, response)` performs the 101 handshake
 *      and spawns the user-defined `run()` coroutine.
 *   4. Both servers share a single event loop (mono-thread invariant of
 *      `qb-io`), proving there is no cross-thread contention.
 *
 * The `coro_client` on the other end observes a standard ws echo round
 * trip — same path a real application would take.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0
 */

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>

#include "../http.h"

#include "../ws/coro.h"

namespace ws_coro_integration_test {

using namespace std::chrono_literals;

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
// ---------------------------------------------------------------------------

constexpr int kPort = 19951;

struct IntegrationFixture {
    std::thread                          thread;
    std::atomic<bool>                    ready{false};
    std::atomic<bool>                    running{true};
    std::unique_ptr<qb::http::Server<>>  http_server;
    std::unique_ptr<IntegrationWsServer> ws_server;

    IntegrationFixture() {
        thread = std::thread([this] {
            qb::io::async::init();

            http_server = qb::http::make_server();
            ws_server   = std::make_unique<IntegrationWsServer>();

            http_server->router().get("/ping", [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
                ctx->response().body() = "pong";
                ctx->complete();
            });

            http_server->router().get("/ws", [this](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
                // 1. Detach the TCP transport from the HTTP server.
                auto session_id      = ctx->session()->id();
                auto [transport, ok] = http_server->extractSession(session_id);
                if (!ok) {
                    ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                    ctx->response().body()   = "extractSession failed";
                    ctx->complete();
                    return;
                }

                // 2. Register the transport as a WS session on the
                //    dedicated io_handler.
                auto *sess = ws_server->registerSession(std::move(transport));
                if (sess == nullptr) {
                    // registry full — the HTTP response pipe is already
                    // detached, so we can only drop the FD.
                    ctx->suppress_response();
                    return;
                }

                // 3. Run the coroutine-driven upgrade (handshake hook,
                //    switch_protocol, spawn run()).
                qb::http::Response response;
                const bool         upgraded = sess->accept_upgrade(ctx->request(), response);
                EXPECT_TRUE(upgraded);

                // 4. The HTTP context no longer owns the transport;
                //    make sure its destructor doesn't try to send a
                //    stale response on a moved-away socket.
                ctx->suppress_response();
            });
            http_server->router().compile();

            http_server->transport().listen_v4(kPort);
            http_server->start();

            ready.store(true, std::memory_order_release);
            while (running.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(5ms);
                }
            }

            ws_server.reset();
            http_server.reset();
        });

        while (!ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(5ms);
        }
        std::this_thread::sleep_for(30ms);
    }

    ~IntegrationFixture() {
        running.store(false, std::memory_order_release);
        if (thread.joinable())
            thread.join();
    }
};

class CoroIntegrationTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        qb::io::async::init();
    }
};

// ---------------------------------------------------------------------------
// Test: full round-trip through router -> extractSession -> coro_session.
// ---------------------------------------------------------------------------

TEST_F(CoroIntegrationTest, RouterHandoffAndCoroEcho) {
    IntegrationFixture fixture;

    auto scenario = [&]() -> qb::io::async::task<std::string> {
        qb::http::ws::coro_client ws;
        const std::string         url = "ws://localhost:" + std::to_string(kPort) + "/ws";
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

    EXPECT_EQ(qb::http::ws::run_sync(scenario()), "router-echo:hello-from-coro");
}

// A non-WS GET on the same server must still be handled by the plain HTTP
// router — proving the handoff is opt-in and doesn't leak into unrelated
// traffic.
TEST_F(CoroIntegrationTest, NonUpgradeRouteStaysOnHttp) {
    IntegrationFixture fixture;

    qb::http::Request request;
    request.uri()    = qb::io::uri{"http://localhost:" + std::to_string(kPort) + "/ping"};
    request.method() = qb::http::method::GET;

    auto resp = qb::http::run_sync(qb::http::GET(request)).response;
    EXPECT_EQ(resp.status(), qb::http::status::OK);
    EXPECT_EQ(resp.body().template as<std::string>(), "pong");
}

TEST_F(CoroIntegrationTest, PersistentHttp1ClientCanReuseConnectionBeforeUpgrade) {
    IntegrationFixture fixture;

    auto              client = qb::http1::make_client("http://localhost:" + std::to_string(kPort));
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
}

} // namespace ws_coro_integration_test

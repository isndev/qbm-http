/**
 * @file qbm/http/tests/test-coro-integration.cpp
 * @brief End-to-end coroutine integration across two real HTTP servers.
 *
 * This suite covers the realistic pattern showcased by
 * `examples/qbm/http/13_coroutine_handlers.cpp`: a *gateway* HTTP/1.1
 * server whose route handlers are written as coroutines and delegate to
 * an *upstream* HTTP/1.1 server via `co_await qb::http::GET(...)` /
 * `qb::http::POST(...)`. The goal is to validate the full loop:
 *
 *  1. The gateway's `qb::http::coro_handler` runs on its listener's
 *     coroutine scheduler.
 *  2. Inside that handler, an outbound HTTP/1.1 awaiter suspends the
 *     coroutine, drives a real client request, resumes with the upstream
 *     response.
 *  3. The gateway composes the result and the framework auto-completes
 *     the response &mdash; no manual CPS wiring, no leaked callbacks, no
 *     blocking calls in a listener thread.
 *
 * The tests exercise three representative scenarios:
 *
 *   * `ProxyingRoute` &mdash; straight pass-through: gateway forwards the
 *     path, reads the upstream body, returns it with an added header.
 *   * `AggregatingRoute` &mdash; fan-out / fan-in: the handler suspends on
 *     two upstream calls and stitches their bodies into one response.
 *   * `UpstreamErrorFallback` &mdash; the upstream returns 500; the
 *     gateway catches the status in-flight and degrades gracefully to a
 *     503.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0
 */

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "../http.h"
#include "../coro.h"

namespace {

// ---------------------------------------------------------------------------
// Upstream service: pure coroutine handlers, tiny surface.
// ---------------------------------------------------------------------------

class UpstreamSession;
class UpstreamServer;

class UpstreamSession
    : public qb::http::use<UpstreamSession>::session<UpstreamServer> {
public:
    explicit UpstreamSession(UpstreamServer& server) : session(server) {}
};

class UpstreamServer
    : public qb::http::use<UpstreamServer>::server<UpstreamSession> {
public:
    UpstreamServer() {
        using Session = UpstreamSession;
        using namespace std::chrono_literals;

        router().get("/profile/:id",
            qb::http::coro_handler<Session>(
                [](auto ctx) -> qb::io::async::task<void> {
                    co_await qb::io::async::sleep(1ms);
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().set_header("X-Source", "upstream");
                    ctx->response().body() =
                        "profile:" + std::string{ctx->path_param("id")};
                    co_return;
                }));

        router().get("/stats/:id",
            qb::http::coro_handler<Session>(
                [](auto ctx) -> qb::io::async::task<void> {
                    co_await qb::io::async::sleep(1ms);
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body() =
                        "stats:" + std::string{ctx->path_param("id")};
                    co_return;
                }));

        router().get("/broken",
            qb::http::coro_handler<Session>(
                [](auto ctx) -> qb::io::async::task<void> {
                    ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                    ctx->response().body()   = "upstream-on-fire";
                    co_return;
                }));

        router().compile();
    }
};

// ---------------------------------------------------------------------------
// Gateway service: coroutine handlers that `co_await` the upstream over
// real HTTP/1.1 sockets, composing the final response.
// ---------------------------------------------------------------------------

class GatewaySession;
class GatewayServer;

class GatewaySession
    : public qb::http::use<GatewaySession>::session<GatewayServer> {
public:
    explicit GatewaySession(GatewayServer& server) : session(server) {}
};

class GatewayServer
    : public qb::http::use<GatewayServer>::server<GatewaySession> {
public:
    explicit GatewayServer(std::string upstream_base)
        : _upstream_base(std::move(upstream_base)) {
        using Session = GatewaySession;

        // ---- /proxy/:id -> upstream /profile/:id ----
        router().get("/proxy/:id",
            qb::http::coro_handler<Session>(
                [base = _upstream_base]
                (auto ctx) -> qb::io::async::task<void> {
                    const auto target = base + "/profile/"
                                      + std::string{ctx->path_param("id")};
                    auto reply = co_await qb::http::GET(qb::http::Request{{target}});

                    ctx->response().status() = reply.response.status();
                    ctx->response().set_header("X-Gateway", "coro");
                    ctx->response().set_header(
                        "X-Upstream-Source",
                        std::string{reply.response.header("X-Source")});
                    ctx->response().body() = reply.response.body().template as<std::string>();
                    co_return;
                }));

        // ---- /aggregate/:id -> upstream /profile/:id + /stats/:id ----
        router().get("/aggregate/:id",
            qb::http::coro_handler<Session>(
                [base = _upstream_base]
                (auto ctx) -> qb::io::async::task<void> {
                    const auto id       = std::string{ctx->path_param("id")};
                    const auto prof_url = base + "/profile/" + id;
                    const auto stat_url = base + "/stats/"   + id;

                    // Sequential awaits keep the example simple; both still
                    // happen off the listener thread of the *caller* because
                    // each `co_await` suspends the coroutine frame.
                    auto prof = co_await qb::http::GET(qb::http::Request{{prof_url}});
                    auto stat = co_await qb::http::GET(qb::http::Request{{stat_url}});

                    if (prof.response.status() != qb::http::status::OK ||
                        stat.response.status() != qb::http::status::OK) {
                        ctx->response().status() = qb::http::status::BAD_GATEWAY;
                        ctx->response().body()   = "aggregate-failed";
                        co_return;
                    }

                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   =
                        prof.response.body().template as<std::string>()
                        + "|" + stat.response.body().template as<std::string>();
                    co_return;
                }));

        // ---- /fallback -> upstream is broken, degrade to 503 ----
        router().get("/fallback",
            qb::http::coro_handler<Session>(
                [base = _upstream_base]
                (auto ctx) -> qb::io::async::task<void> {
                    auto reply = co_await qb::http::GET(
                        qb::http::Request{{base + "/broken"}});

                    if (reply.response.status() != qb::http::status::OK) {
                        ctx->response().status() = qb::http::status::SERVICE_UNAVAILABLE;
                        ctx->response().body()   = "degraded";
                        co_return;
                    }

                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   = reply.response.body().template as<std::string>();
                    co_return;
                }));

        router().compile();
    }

private:
    std::string _upstream_base;
};

// ---------------------------------------------------------------------------
// Fixture: runs *two* servers on distinct listener threads and joins them
// cleanly on tear-down. Both loops follow the same pattern as
// `test-coro-server.cpp` so behaviour stays consistent across the suite.
// ---------------------------------------------------------------------------

class CoroIntegrationTest : public ::testing::Test {
protected:
    static constexpr int kUpstreamPort = 19901;
    static constexpr int kGatewayPort  = 19902;

    std::thread _upstream_thread;
    std::thread _gateway_thread;

    std::atomic<bool> _upstream_ready{false};
    std::atomic<bool> _gateway_ready{false};
    std::atomic<bool> _keep_running{true};

    void SetUp() override {
        qb::io::async::init();

        _upstream_thread = std::thread([this] {
            qb::io::async::init();
            UpstreamServer server;
            server.transport().listen_v4(kUpstreamPort);
            server.start();
            _upstream_ready.store(true, std::memory_order_release);
            while (_keep_running.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            }
        });

        _gateway_thread = std::thread([this] {
            qb::io::async::init();
            GatewayServer server{upstream_base()};
            server.transport().listen_v4(kGatewayPort);
            server.start();
            _gateway_ready.store(true, std::memory_order_release);
            while (_keep_running.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            }
        });

        while (!_upstream_ready.load(std::memory_order_acquire) ||
               !_gateway_ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
    }

    void TearDown() override {
        _keep_running.store(false, std::memory_order_release);
        if (_upstream_thread.joinable()) _upstream_thread.join();
        if (_gateway_thread.joinable())  _gateway_thread.join();
    }

    [[nodiscard]] static std::string upstream_base() {
        return "http://localhost:" + std::to_string(kUpstreamPort);
    }
    [[nodiscard]] static std::string gateway_url(const std::string& path) {
        return "http://localhost:" + std::to_string(kGatewayPort) + path;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Gateway proxies a single path through to the upstream. Validates that
// the listener-to-listener suspension / resumption correctly preserves
// headers, status and body across the network round-trip.
TEST_F(CoroIntegrationTest, ProxyingRoute) {
    auto reply = qb::http::run_sync(
        qb::http::GET(qb::http::Request{{gateway_url("/proxy/42")}}));

    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "profile:42");
    EXPECT_EQ(std::string{reply.response.header("X-Gateway")}, "coro");
    EXPECT_EQ(std::string{reply.response.header("X-Upstream-Source")}, "upstream");
}

// Gateway aggregates two upstream calls inside a single coroutine
// handler. Verifies that sequential `co_await`s work and that path
// parameters survive all the way to the composition step.
TEST_F(CoroIntegrationTest, AggregatingRoute) {
    auto reply = qb::http::run_sync(
        qb::http::GET(qb::http::Request{{gateway_url("/aggregate/7")}}));

    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "profile:7|stats:7");
}

// Upstream intentionally returns 500. The gateway handler inspects the
// status in-flight and degrades to a 503 with a fallback body; the
// framework must not hijack the outcome with an auto-COMPLETE that
// overwrites the explicit body.
TEST_F(CoroIntegrationTest, UpstreamErrorFallback) {
    auto reply = qb::http::run_sync(
        qb::http::GET(qb::http::Request{{gateway_url("/fallback")}}));

    EXPECT_EQ(reply.response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "degraded");
}

} // namespace

/**
 * @file qbm/http/tests/system/coro/coro-gateway-e2e.cpp
 * @brief System tier: end-to-end coroutine gateway across two real HTTP/1.1 servers.
 *
 * Covers the realistic pattern from `examples/06-modules/http/09-coroutine-handlers.cpp`:
 * a *gateway* HTTP/1.1 server whose route handlers are coroutines and delegate
 * to an *upstream* HTTP/1.1 server via `co_await qb::http::GET(...)`. The full
 * loop is validated end to end over real loopback sockets:
 *
 *   1. the gateway's coro route handler runs on its listener's coroutine scheduler;
 *   2. an outbound HTTP/1.1 awaiter suspends the coroutine, drives a real client
 *      request, and resumes with the upstream response;
 *   3. the gateway composes the result and the framework auto-completes — no
 *      manual CPS wiring, no leaked callbacks, no blocking in a listener thread.
 *
 * Scenarios:
 *   - `ProxyingRoute`            — straight pass-through (status/headers/body survive).
 *   - `AggregatingRoute`         — two SEQUENTIAL awaits stitched (path params survive).
 *   - `ParallelAggregatingRoute` — two awaits via `when_all` running CONCURRENTLY
 *                                  on the gateway's scheduler (real fan-out).
 *   - `UpstreamErrorFallback`    — upstream returns 500; gateway degrades to 503.
 *   - `UpstreamRefusedFallback`  — upstream socket is refused/unreachable; the
 *                                  gateway's awaiter resolves non-OK (502/503/504)
 *                                  and the handler degrades to 503 deterministically.
 *
 * Topology: TWO servers, each on its own worker thread via the shared
 * `ServerThread<>` RAII harness (condition-variable readiness barriers — NO
 * sleep_for warmup, NO magic ports; both ports are ephemeral). A dead ephemeral
 * port (reserved then released) provides the "refused upstream" target.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <gtest/gtest.h>

#include <qb/io/async/coroutine/combinators.h> // when_all

#include "../../shared/loopback_server.h"

#include <qbm/http/coro.h>
#include <qbm/http/http.h>

using namespace std::chrono_literals;

namespace {

/// Bounded timeout for every outbound awaiter so failures resolve, never hang.
constexpr auto kUpstreamTimeout = 5s;

// ---------------------------------------------------------------------------
// Upstream service.
// ---------------------------------------------------------------------------

class UpstreamServer;

class UpstreamSession : public qb::http::use<UpstreamSession>::session<UpstreamServer> {
public:
    explicit UpstreamSession(UpstreamServer &server)
        : session(server) {}
};

class UpstreamServer : public qb::http::use<UpstreamServer>::server<UpstreamSession> {
public:
    UpstreamServer() {
        router().get("/profile/:id", [](auto ctx) -> qb::io::async::task<void> {
            co_await qb::io::async::sleep(1ms);
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("X-Source", "upstream");
            ctx->response().body() = "profile:" + std::string{ctx->path_param("id")};
            co_return;
        });

        router().get("/stats/:id", [](auto ctx) -> qb::io::async::task<void> {
            co_await qb::io::async::sleep(1ms);
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "stats:" + std::string{ctx->path_param("id")};
            co_return;
        });

        router().get("/broken", [](auto ctx) -> qb::io::async::task<void> {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->response().body()   = "upstream-on-fire";
            co_return;
        });

        router().compile();
    }
};

// ---------------------------------------------------------------------------
// Gateway service: coro handlers that co_await the upstream over real sockets.
// ---------------------------------------------------------------------------

class GatewayServer;

class GatewaySession : public qb::http::use<GatewaySession>::session<GatewayServer> {
public:
    explicit GatewaySession(GatewayServer &server)
        : session(server) {}
};

class GatewayServer : public qb::http::use<GatewayServer>::server<GatewaySession> {
public:
    GatewayServer(std::string upstream_base, std::string dead_base)
        : _upstream_base(std::move(upstream_base))
        , _dead_base(std::move(dead_base)) {
        // ---- /proxy/:id -> upstream /profile/:id ----
        router().get("/proxy/:id", [base = _upstream_base](auto ctx) -> qb::io::async::task<void> {
            const auto target = base + "/profile/" + std::string{ctx->path_param("id")};
            auto       reply  = co_await qb::http::GET(qb::http::Request{{target}}, kUpstreamTimeout);

            ctx->response().status() = reply.response.status();
            ctx->response().set_header("X-Gateway", "coro");
            ctx->response().set_header("X-Upstream-Source", std::string{reply.response.header("X-Source")});
            ctx->response().body() = reply.response.body().template as<std::string>();
            co_return;
        });

        // ---- /aggregate/:id -> SEQUENTIAL upstream /profile + /stats ----
        router().get("/aggregate/:id", [base = _upstream_base](auto ctx) -> qb::io::async::task<void> {
            const auto id       = std::string{ctx->path_param("id")};
            const auto prof_url = base + "/profile/" + id;
            const auto stat_url = base + "/stats/" + id;

            auto prof = co_await qb::http::GET(qb::http::Request{{prof_url}}, kUpstreamTimeout);
            auto stat = co_await qb::http::GET(qb::http::Request{{stat_url}}, kUpstreamTimeout);

            if (prof.response.status() != qb::http::status::OK || stat.response.status() != qb::http::status::OK) {
                ctx->response().status() = qb::http::status::BAD_GATEWAY;
                ctx->response().body()   = "aggregate-failed";
                co_return;
            }

            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = prof.response.body().template as<std::string>() + "|" + stat.response.body().template as<std::string>();
            co_return;
        });

        // ---- /parallel/:id -> CONCURRENT upstream /profile + /stats via when_all ----
        router().get("/parallel/:id", [base = _upstream_base](auto ctx) -> qb::io::async::task<void> {
            const auto id       = std::string{ctx->path_param("id")};
            const auto prof_url = base + "/profile/" + id;
            const auto stat_url = base + "/stats/" + id;

            // Each upstream call is wrapped in its own task<Reply> so
            // when_all can drive both concurrently on this scheduler.
            auto fetch = [](std::string u) -> qb::io::async::task<qb::http::async::Reply> {
                co_return co_await qb::http::GET(qb::http::Request{{u}}, kUpstreamTimeout);
            };

            auto [prof, stat] = co_await qb::io::async::when_all(fetch(prof_url), fetch(stat_url));

            if (prof.response.status() != qb::http::status::OK || stat.response.status() != qb::http::status::OK) {
                ctx->response().status() = qb::http::status::BAD_GATEWAY;
                ctx->response().body()   = "parallel-failed";
                co_return;
            }

            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = prof.response.body().template as<std::string>() + "|" + stat.response.body().template as<std::string>();
            co_return;
        });

        // ---- /fallback -> upstream returns 500, degrade to 503 ----
        router().get("/fallback", [base = _upstream_base](auto ctx) -> qb::io::async::task<void> {
            auto reply = co_await qb::http::GET(qb::http::Request{{base + "/broken"}}, kUpstreamTimeout);

            if (reply.response.status() != qb::http::status::OK) {
                ctx->response().status() = qb::http::status::SERVICE_UNAVAILABLE;
                ctx->response().body()   = "degraded";
                co_return;
            }

            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = reply.response.body().template as<std::string>();
            co_return;
        });

        // ---- /fallback-refused -> upstream socket unreachable, degrade to 503 ----
        router().get("/fallback-refused", [dead = _dead_base](auto ctx) -> qb::io::async::task<void> {
            // Bounded timeout so a refused/unreachable upstream resolves
            // (the awaiter yields BAD_GATEWAY / GATEWAY_TIMEOUT), never hangs.
            auto reply = co_await qb::http::GET(qb::http::Request{{dead + "/profile/1"}}, 500ms);

            if (reply.response.status() != qb::http::status::OK) {
                ctx->response().status() = qb::http::status::SERVICE_UNAVAILABLE;
                ctx->response().set_header("X-Upstream-Status", std::to_string(reply.response.status().code()));
                ctx->response().body() = "upstream-unreachable";
                co_return;
            }

            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = reply.response.body().template as<std::string>();
            co_return;
        });

        router().compile();
    }

private:
    std::string _upstream_base;
    std::string _dead_base;
};

using UpstreamThread = qb::http::test::ServerThread<UpstreamServer>;

// ---------------------------------------------------------------------------
// Fixture: upstream + gateway, each on its own worker thread (ephemeral ports).
// The gateway needs the upstream base at construction, so it is wrapped in a
// thin RAII type rather than the plain ServerThread<> default-construct path.
// ---------------------------------------------------------------------------

class CoroGatewayTest : public ::testing::Test {
protected:
    std::uint16_t                   _upstream_port{0};
    std::uint16_t                   _gateway_port{0};
    std::uint16_t                   _dead_port{0};
    std::unique_ptr<UpstreamThread> _upstream;

    void
    SetUp() override {
        qb::io::async::init();

        // The two LIVE servers bind :0 on the socket that actually serves and read the port back,
        // rather than probing for a free port and binding it a moment later. `ephemeral_port()`
        // documents the hole that closes: its probe must be shut before the caller can bind, so
        // under `ctest -j` another test PROCESS can take the port in that window (measured: 2
        // failures in 12 full-suite runs).
        _upstream = std::make_unique<UpstreamThread>([](UpstreamServer &srv) -> bool {
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
                return false;
            }
            srv.start();
            return true;
        });
        ASSERT_TRUE(_upstream->ready()) << "upstream loopback server failed to start";
        // The UpstreamThread ctor already blocked on the readiness barrier, so the transport is
        // bound and its assigned port is visible to this thread.
        _upstream_port = _upstream->server().transport().local_endpoint().port();
        ASSERT_NE(_upstream_port, 0) << "listen_v4(0) did not yield a kernel-assigned port";

        // _dead_port is the ONE port here that must never be bound — `UpstreamRefusedFallback`
        // needs a connect to it to be REFUSED — so it cannot use the bind-and-read-back pattern:
        // there is no serving socket to read a port off. It keeps the probe-and-release draw, and
        // is drawn AFTER the upstream is listening so the kernel cannot hand out that port.
        _dead_port = qb::http::test::ephemeral_port(); // reserved + released = refused target
        ASSERT_NE(_dead_port, _upstream_port);

        const std::string upstream_base = "http://localhost:" + std::to_string(_upstream_port);
        const std::string dead_base     = "http://localhost:" + std::to_string(_dead_port);

        // GatewayServer needs ctor args (upstream + dead bases), which the
        // generic ServerThread<> default-construct path does not support, so the
        // gateway runs on a manually-managed worker thread below. It still uses
        // an observable condition-variable readiness barrier (no sleep_for warmup).
        start_gateway(upstream_base, dead_base);
        ASSERT_NE(_gateway_port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
        // The gateway's :0 bind happened after _dead_port's probe was released, so the kernel
        // could in principle re-hand that number. UpstreamRefusedFallback only proves anything if
        // the dead target really is distinct from both live servers — pin it rather than let the
        // test pass for the wrong reason.
        ASSERT_NE(_gateway_port, _dead_port);
        ASSERT_NE(_gateway_port, _upstream_port);
    }

    // Run the gateway on a worker thread with a condition-variable readiness
    // barrier (mirrors ServerThread<>'s contract for the ctor-arg case).
    // Publishes the kernel-assigned port into _gateway_port under _gateway_mtx.
    void
    start_gateway(std::string upstream_base, std::string dead_base) {
        _gateway_running.store(true, std::memory_order_release);
        _gateway_thread = std::thread([this, upstream_base, dead_base] {
            qb::io::async::init();
            GatewayServer server{upstream_base, dead_base};
            const bool    listening = server.transport().listen_v4(0, "127.0.0.1") == 0;
            if (listening) {
                server.start();
            }
            {
                std::lock_guard<std::mutex> lock(_gateway_mtx);
                // Published under the same lock as the readiness flag the ctor waits on, so the
                // test thread's read below is ordered after this write.
                _gateway_port   = listening ? server.transport().local_endpoint().port() : 0;
                _gateway_ready  = listening;
                _gateway_failed = !listening;
            }
            _gateway_cv.notify_all();
            if (!listening) {
                return;
            }
            while (_gateway_running.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        });

        std::unique_lock<std::mutex> lock(_gateway_mtx);
        const bool signalled = _gateway_cv.wait_for(lock, std::chrono::seconds(5), [this] { return _gateway_ready || _gateway_failed; });
        ASSERT_TRUE(signalled) << "gateway server did not become ready in time";
        ASSERT_TRUE(_gateway_ready) << "gateway server failed to listen on an ephemeral port";
    }

    void
    TearDown() override {
        _gateway_running.store(false, std::memory_order_release);
        if (_gateway_thread.joinable()) {
            _gateway_thread.join();
        }
        _upstream.reset();
    }

    [[nodiscard]] qb::http::Response
    gateway_get(const std::string &path) const {
        return qb::http::run_sync(
                   qb::http::GET(qb::http::Request{{"http://localhost:" + std::to_string(_gateway_port) + path}}, kUpstreamTimeout))
            .response;
    }

private:
    std::thread             _gateway_thread;
    std::atomic<bool>       _gateway_running{false};
    bool                    _gateway_ready{false};
    bool                    _gateway_failed{false};
    std::mutex              _gateway_mtx;
    std::condition_variable _gateway_cv;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_F(CoroGatewayTest, ProxyingRoute) {
    auto response = gateway_get("/proxy/42");

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "profile:42");
    EXPECT_EQ(std::string{response.header("X-Gateway")}, "coro");
    EXPECT_EQ(std::string{response.header("X-Upstream-Source")}, "upstream");
}

TEST_F(CoroGatewayTest, AggregatingRoute) {
    auto response = gateway_get("/aggregate/7");

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "profile:7|stats:7");
}

TEST_F(CoroGatewayTest, ParallelAggregatingRoute) {
    // Same composed result as the sequential route, but the two upstream calls
    // are driven concurrently via when_all on the gateway's coroutine scheduler.
    auto response = gateway_get("/parallel/9");

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "profile:9|stats:9");
}

TEST_F(CoroGatewayTest, UpstreamErrorFallback) {
    auto response = gateway_get("/fallback");

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(response.body().template as<std::string>(), "degraded");
}

TEST_F(CoroGatewayTest, UpstreamRefusedFallback) {
    // The dead upstream port has no listener: the gateway's outbound awaiter
    // resolves with a non-OK status (connection refused -> BAD_GATEWAY, or the
    // bounded timeout -> GATEWAY_TIMEOUT). Either way the handler degrades to
    // a deterministic 503 instead of hanging.
    auto response = gateway_get("/fallback-refused");

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(response.body().template as<std::string>(), "upstream-unreachable");
}

} // namespace

/**
 * @file qbm/http/tests/test-coro-server.cpp
 * @brief Coroutine server-side handler / middleware adapters.
 *
 * Exercises `qb::http::coro_handler` and `qb::http::coro_middleware`
 * helpers declared in `qbm/http/routing/coro_task.h`. The tests run against
 * a real HTTP/1.1 server so the full routing chain is observed:
 *
 *   - Registering a coroutine handler executes on the server's thread-local
 *     coroutine scheduler and the framework auto-completes the request.
 *   - A coroutine middleware observes / mutates the context and continues
 *     the chain without an explicit `next()` call.
 *   - Exceptions thrown from the coroutine body translate to
 *     `500 Internal Server Error`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>

#include "../http.h"
#include "../coro.h"

namespace {

class CoroServerSession;
class CoroServer;

class CoroServerSession
    : public qb::http::use<CoroServerSession>::session<CoroServer> {
public:
    explicit CoroServerSession(CoroServer& server) : session(server) {}
};

class CoroServer : public qb::http::use<CoroServer>::server<CoroServerSession> {
public:
    CoroServer() {
        using Session = CoroServerSession;

        using namespace std::chrono_literals;

        router().use(qb::http::coro_middleware<Session>(
            [](auto ctx) -> qb::io::async::task<void> {
                // Small async pause to prove we actually suspend.
                co_await qb::io::async::sleep(1ms);
                ctx->request().set_header("X-Seen-By-Coro-MW", "yes");
                co_return;
            }));

        router().get("/coro/hello",
            qb::http::coro_handler<Session>(
                [](auto ctx) -> qb::io::async::task<void> {
                    co_await qb::io::async::sleep(1ms);
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   =
                        std::string{"hi:"} + ctx->request().header("X-Seen-By-Coro-MW");
                    co_return;
                }));

        router().get("/coro/explicit",
            qb::http::coro_handler<Session>(
                [](auto ctx) -> qb::io::async::task<void> {
                    ctx->response().status() = qb::http::status::ACCEPTED;
                    ctx->response().body()   = "explicit-ok";
                    // Short-circuit: the wrapper must NOT overwrite the outcome.
                    ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
                    co_return;
                }));

        router().get("/coro/boom",
            qb::http::coro_handler<Session>(
                [](auto /*ctx*/) -> qb::io::async::task<void> {
                    co_await qb::io::async::sleep(1ms);
                    throw std::runtime_error("coro handler failed on purpose");
                    co_return;
                }));

        // Dedicated group to test middleware chaining + short-circuit
        // without impacting the other tests.
        auto group = router().group("/coro/mw");

        group->use(qb::http::coro_middleware<Session>(
            [](auto ctx) -> qb::io::async::task<void> {
                co_await qb::io::async::sleep(1ms);
                ctx->request().set_header("X-Step", "A");
                co_return;
            }));
        group->use(qb::http::coro_middleware<Session>(
            [](auto ctx) -> qb::io::async::task<void> {
                co_await qb::io::async::sleep(1ms);
                auto current = std::string{ctx->request().header("X-Step")};
                ctx->request().set_header("X-Step", current + "->B");
                co_return;
            }));
        group->get("/chain",
            qb::http::coro_handler<Session>(
                [](auto ctx) -> qb::io::async::task<void> {
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   = std::string{ctx->request().header("X-Step")};
                    co_return;
                }));

        // Short-circuit middleware: responds directly and declares COMPLETE.
        group->use(qb::http::coro_middleware<Session>(
            [](auto ctx) -> qb::io::async::task<void> {
                if (ctx->request().uri().path() == "/coro/mw/gate") {
                    ctx->response().status() = qb::http::status::FORBIDDEN;
                    ctx->response().body()   = "blocked-by-coro-mw";
                    ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
                }
                co_return;
            }));
        group->get("/gate",
            qb::http::coro_handler<Session>(
                [](auto ctx) -> qb::io::async::task<void> {
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   = "should-not-be-reached";
                    co_return;
                }));

        // Manual CONTINUE path: MW1 explicitly continues early, then resumes later.
        // The wrapper must not emit a second implicit CONTINUE when MW1 returns.
        group->use(qb::http::coro_middleware<Session>(
            [](auto ctx) -> qb::io::async::task<void> {
                if (ctx->request().uri().path() == "/coro/mw/manual-continue") {
                    ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
                    co_await qb::io::async::sleep(1ms);
                }
                co_return;
            }));
        group->use(qb::http::coro_middleware<Session>(
            [](auto ctx) -> qb::io::async::task<void> {
                if (ctx->request().uri().path() == "/coro/mw/manual-continue") {
                    co_await qb::io::async::sleep(10ms);
                    ctx->request().set_header("X-MW2", "yes");
                }
                co_return;
            }));
        group->get("/manual-continue",
            qb::http::coro_handler<Session>(
                [](auto ctx) -> qb::io::async::task<void> {
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   = std::string{ctx->request().header("X-MW2")};
                    co_return;
                }));

        router().compile();
    }
};

class CoroServerTest : public ::testing::Test {
protected:
    static constexpr int kPort = 19897;

    std::thread        _server_thread;
    std::atomic<bool>  _server_ready{false};
    std::atomic<bool>  _keep_server_alive{true};

    void SetUp() override {
        qb::io::async::init();
        _server_thread = std::thread([this] {
            qb::io::async::init();
            CoroServer server;
            server.transport().listen_v4(kPort);
            server.start();
            _server_ready.store(true, std::memory_order_release);
            while (_keep_server_alive.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            }
        });
        while (!_server_ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
    }

    void TearDown() override {
        _keep_server_alive.store(false, std::memory_order_release);
        if (_server_thread.joinable()) {
            _server_thread.join();
        }
    }

    [[nodiscard]] static std::string url(const std::string& path) {
        return "http://localhost:" + std::to_string(kPort) + path;
    }
};

TEST_F(CoroServerTest, CoroHandlerAndMiddlewareCooperate) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/coro/hello")}}));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "hi:yes");
}

TEST_F(CoroServerTest, CoroHandlerExplicitCompleteIsPreserved) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/coro/explicit")}}));
    EXPECT_EQ(reply.response.status(), qb::http::status::ACCEPTED);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "explicit-ok");
}

TEST_F(CoroServerTest, CoroHandlerExceptionTranslatesTo500) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/coro/boom")}}));
    EXPECT_EQ(reply.response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
}

TEST_F(CoroServerTest, CoroMiddlewaresChainInOrder) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/coro/mw/chain")}}));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    // Root-level coro MW + group-level coro MWs all execute in order:
    //   (root MW: X-Seen-By-Coro-MW=yes does not touch X-Step)
    //   A -> A->B then handler reflects X-Step.
    EXPECT_EQ(reply.response.body().template as<std::string>(), "A->B");
}

TEST_F(CoroServerTest, CoroMiddlewareCanShortCircuitChain) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/coro/mw/gate")}}));
    EXPECT_EQ(reply.response.status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "blocked-by-coro-mw");
}

TEST_F(CoroServerTest, CoroMiddlewareManualContinueDoesNotDoubleAdvanceChain) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/coro/mw/manual-continue")}}));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "yes");
}

} // namespace

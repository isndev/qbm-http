/**
 * @file qbm/http/tests/system/coro/coro-server-http1.cpp
 * @brief System tier: coroutine server-side handler / middleware adapters (HTTP/1.1).
 *
 * Exercises the router's unified coroutine handler and middleware support
 * (auto-detected via the `CoroRouteHandler` / `CoroMiddlewareHandler` concepts
 * in `qbm/http/routing/coro_task.h`) against a REAL loopback HTTP/1.1 server, so
 * the full routing chain is observed on the wire:
 *
 *   - a `task<void>(ctx)` handler passed directly to a verb method runs on the
 *     server's coroutine scheduler and the framework auto-completes the request;
 *   - a `task<void>(ctx)` passed to `use()` mutates the context and continues the
 *     chain without an explicit `next()`;
 *   - an explicit `complete(COMPLETE)` inside a coro handler is preserved (the
 *     wrapper must not overwrite the outcome);
 *   - exceptions thrown from a coro HANDLER body translate to 500;
 *   - exceptions thrown from a coro MIDDLEWARE body ALSO translate to 500;
 *   - coro middlewares chain in order and may short-circuit the chain;
 *   - a manual CONTINUE in a coro middleware does not double-advance the chain.
 *
 * Topology: the server runs on its own worker thread via the shared
 * `ServerThread<>` RAII harness (condition-variable readiness barrier — NO
 * sleep_for warmup, NO magic port). The client side is driven from the test body
 * with a BOUNDED client timeout so a hung coroutine fails fast instead of
 * hanging the whole suite.
 *
 * De-flake notes (vs the pre-restructure `test-coro-server.cpp`):
 *   - magic port 19897 + `sleep_for(40ms)` warmup -> `ephemeral_port()` + the
 *     readiness barrier inside `ServerThread`.
 *   - `run_sync(GET(...))` with no deadline -> every client GET carries an
 *     explicit timeout (`kClientTimeout`); a stuck coroutine yields 504, never a
 *     hang.
 *   - manual-continue ordering is asserted DIRECTLY: the handler echoes the
 *     mutation MW2 made AND a marker proving the handler observed it, so a
 *     double-advance regression is unambiguous.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <chrono>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "../../shared/loopback_server.h"

#include "../coro.h"
#include "../http.h"

using namespace std::chrono_literals;

namespace {

/// Bounded client timeout: a hung coroutine surfaces as 504, never a hang.
constexpr auto kClientTimeout = 5s;

class CoroServer;

class CoroServerSession : public qb::http::use<CoroServerSession>::session<CoroServer> {
public:
    explicit CoroServerSession(CoroServer &server)
        : session(server) {}
};

class CoroServer : public qb::http::use<CoroServer>::server<CoroServerSession> {
public:
    CoroServer() {
        router().use([](auto ctx) -> qb::io::async::task<void> {
            // Small async pause to prove we actually suspend.
            co_await qb::io::async::sleep(1ms);
            ctx->request().set_header("X-Seen-By-Coro-MW", "yes");
            co_return;
        });

        router().get("/coro/hello", [](auto ctx) -> qb::io::async::task<void> {
            co_await qb::io::async::sleep(1ms);
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() =
                std::string{"hi:"} + std::string(ctx->request().header("X-Seen-By-Coro-MW"));
            co_return;
        });

        router().get("/coro/explicit", [](auto ctx) -> qb::io::async::task<void> {
            ctx->response().status() = qb::http::status::ACCEPTED;
            ctx->response().body()   = "explicit-ok";
            // Short-circuit: the wrapper must NOT overwrite the outcome.
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
            co_return;
        });

        router().get("/coro/boom", [](auto /*ctx*/) -> qb::io::async::task<void> {
            co_await qb::io::async::sleep(1ms);
            throw std::runtime_error("coro handler failed on purpose");
            co_return;
        });

        // ---- Coro MIDDLEWARE that throws: must also translate to 500 ----
        {
            auto throwing = router().group("/coro/mw-throws");
            throwing->use([](auto /*ctx*/) -> qb::io::async::task<void> {
                co_await qb::io::async::sleep(1ms);
                throw std::runtime_error("coro middleware failed on purpose");
                co_return;
            });
            throwing->get("/route", [](auto ctx) -> qb::io::async::task<void> {
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body()   = "should-not-be-reached";
                co_return;
            });
        }

        // ---- Chained coro middlewares (ordering + short-circuit) ----
        auto group = router().group("/coro/mw");

        group->use([](auto ctx) -> qb::io::async::task<void> {
            co_await qb::io::async::sleep(1ms);
            ctx->request().set_header("X-Step", "A");
            co_return;
        });
        group->use([](auto ctx) -> qb::io::async::task<void> {
            co_await qb::io::async::sleep(1ms);
            auto current = std::string{ctx->request().header("X-Step")};
            ctx->request().set_header("X-Step", current + "->B");
            co_return;
        });
        group->get("/chain", [](auto ctx) -> qb::io::async::task<void> {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::string{ctx->request().header("X-Step")};
            co_return;
        });

        // Short-circuit middleware: responds directly and declares COMPLETE.
        group->use([](auto ctx) -> qb::io::async::task<void> {
            if (ctx->request().uri().path() == "/coro/mw/gate") {
                ctx->response().status() = qb::http::status::FORBIDDEN;
                ctx->response().body()   = "blocked-by-coro-mw";
                ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
            }
            co_return;
        });
        group->get("/gate", [](auto ctx) -> qb::io::async::task<void> {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "should-not-be-reached";
            co_return;
        });

        // Manual CONTINUE path: MW1 explicitly continues early, then resumes
        // (suspending) afterwards. MW2 sets X-MW2 only after a suspension that
        // outlasts MW1's early CONTINUE. The wrapper must NOT emit a second
        // implicit CONTINUE when MW1's coroutine returns.
        group->use([](auto ctx) -> qb::io::async::task<void> {
            if (ctx->request().uri().path() == "/coro/mw/manual-continue") {
                ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
                co_await qb::io::async::sleep(1ms);
            }
            co_return;
        });
        group->use([](auto ctx) -> qb::io::async::task<void> {
            if (ctx->request().uri().path() == "/coro/mw/manual-continue") {
                co_await qb::io::async::sleep(10ms);
                ctx->request().set_header("X-MW2", "yes");
            }
            co_return;
        });
        group->get("/manual-continue", [](auto ctx) -> qb::io::async::task<void> {
            // The handler reports BOTH the value MW2 wrote AND an explicit
            // "observed" marker. If the chain double-advanced (running the
            // handler before MW2 resumed), `seen` would be empty -> body
            // "observed:" and the assertion below fails unambiguously.
            const auto seen          = std::string{ctx->request().header("X-MW2")};
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "observed:" + seen;
            co_return;
        });

        router().compile();
    }
};

using ServerThread = qb::http::test::ServerThread<CoroServer>;

class CoroServerTest : public ::testing::Test {
protected:
    std::uint16_t                 _port{0};
    std::unique_ptr<ServerThread> _server;

    void
    SetUp() override {
        qb::io::async::init();
        _port = qb::http::test::ephemeral_port();

        const std::uint16_t port = _port;
        _server                  = std::make_unique<ServerThread>([port](CoroServer &srv) -> bool {
            if (srv.transport().listen_v4(port) != 0) {
                return false;
            }
            srv.start();
            return true;
        });
        ASSERT_TRUE(_server->ready())
            << "coro HTTP/1.1 server failed to start on port " << _port;
    }

    void
    TearDown() override {
        _server.reset();
    }

    [[nodiscard]] qb::http::Response
    get(const std::string &path) const {
        return qb::http::run_sync(
                   qb::http::GET(qb::http::Request{{"http://localhost:" + std::to_string(_port) +
                                                    path}},
                                 kClientTimeout))
            .response;
    }
};

TEST_F(CoroServerTest, CoroHandlerAndMiddlewareCooperate) {
    auto response = get("/coro/hello");
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "hi:yes");
}

TEST_F(CoroServerTest, CoroHandlerExplicitCompleteIsPreserved) {
    auto response = get("/coro/explicit");
    EXPECT_EQ(response.status(), qb::http::status::ACCEPTED);
    EXPECT_EQ(response.body().template as<std::string>(), "explicit-ok");
}

TEST_F(CoroServerTest, CoroHandlerExceptionTranslatesTo500) {
    auto response = get("/coro/boom");
    EXPECT_EQ(response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
}

TEST_F(CoroServerTest, CoroMiddlewareExceptionTranslatesTo500) {
    // The thrown exception originates in a coro MIDDLEWARE, not a handler; the
    // route handler must never run, and the failure still maps to 500.
    auto response = get("/coro/mw-throws/route");
    EXPECT_EQ(response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_NE(response.body().template as<std::string>(), "should-not-be-reached");
}

TEST_F(CoroServerTest, CoroMiddlewaresChainInOrder) {
    auto response = get("/coro/mw/chain");
    EXPECT_EQ(response.status(), qb::http::status::OK);
    // Group-level coro MWs execute in order: A -> A->B, then handler reflects
    // X-Step. (The root coro MW sets X-Seen-By-Coro-MW, not X-Step.)
    EXPECT_EQ(response.body().template as<std::string>(), "A->B");
}

TEST_F(CoroServerTest, CoroMiddlewareCanShortCircuitChain) {
    auto response = get("/coro/mw/gate");
    EXPECT_EQ(response.status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(response.body().template as<std::string>(), "blocked-by-coro-mw");
}

TEST_F(CoroServerTest, CoroMiddlewareManualContinueDoesNotDoubleAdvanceChain) {
    auto response = get("/coro/mw/manual-continue");
    EXPECT_EQ(response.status(), qb::http::status::OK);
    // The handler ran AFTER MW2 resumed and wrote X-MW2: it observed "yes".
    // A double-advance would have run the handler early -> "observed:".
    EXPECT_EQ(response.body().template as<std::string>(), "observed:yes");
}

} // namespace

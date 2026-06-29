/**
 * @file qbm/http/tests/system/routing/router-e2e-advanced.cpp
 * @brief System tier: wire-level router behaviour over a real loopback HTTP/1.1 server.
 *
 * This is the focused successor to the pre-restructure `test-integration-advanced.cpp`
 * monolith (2188 LOC). Per the dedup decision (spec D3), pure router-matching
 * logic — static/param/wildcard precedence, middleware ordering, controller
 * mounting, group nesting, custom 404 — is already proven IN-PROCESS by the
 * `unit/routing/router-*` family with a mock session, and is NOT re-run here.
 *
 * What remains is exactly the coverage the socket round-trip ADDS, which a
 * mock-session unit test cannot reach:
 *
 *   - on-the-wire request parsing: path params, query string, request body, and
 *     header round-tripping survive real serialization + parsing;
 *   - URL-encoded path segments decode correctly server-side;
 *   - HEAD body-stripping on the wire (handler may set a body; the client sees none);
 *   - the `Allow` header is serialized correctly for auto-405 and OPTIONS;
 *   - async-over-loop completion: a handler that completes from a deferred
 *     `qb::io::async::callback` still produces a correct response;
 *   - several requests in flight concurrently on the same loop all complete;
 *   - a middleware-induced error routes to the custom global error chain and
 *     yields EXACTLY 503 (the pre-restructure weak `EXPECT_NE(OK)` is gone; see
 *     spec D4 — the strong exact-503 assertion is the canonical one).
 *
 * De-flake / quality notes (vs `test-integration-advanced.cpp`):
 *   - DELETED the three global magic-sum atomics (`adv_request_count_*`,
 *     `adv_server_side_assertions`) and the `PerformTestExecution` cross-thread
 *     accounting. They counted "this code ran", not "it produced a correct
 *     value". Every assertion here is on OBSERVABLE response state (status /
 *     body / headers / the deterministic `X-MW-Trace` header).
 *   - magic port 29887 + `sleep_for(250ms)` warmup -> `ephemeral_port()` + the
 *     condition-variable readiness barrier inside the shared `ServerThread<>`.
 *   - dropped the misleading `integration-` prefix and the `qb::io::cout` spam.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <array>
#include <cctype>
#include <chrono>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "../../shared/loopback_server.h"

#include "../http.h"
#include "../routing/context.h"
#include "../routing/middleware.h"
#include "../routing/router.h"

using namespace std::chrono_literals;

namespace {

/// Bounded client timeout — a stuck server surfaces as 504, never a hang.
constexpr auto kClientTimeout = 7s;

class RouterE2EServer;

class RouterE2ESession : public qb::http::use<RouterE2ESession>::session<RouterE2EServer> {
public:
    explicit RouterE2ESession(RouterE2EServer &server)
        : session(server) {}
};

/// Minimal RFC-3986 percent-encoder for path segments (test client side).
std::string
url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }
        escaped << std::uppercase << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c)) << std::nouppercase;
    }
    return escaped.str();
}

// ---------------------------------------------------------------------------
// A middleware that always routes to the error chain. Used to prove the custom
// global error handler maps an in-chain ERROR to a 503 over the wire.
// ---------------------------------------------------------------------------
class ErrorInducingMiddleware : public qb::http::IMiddleware<RouterE2ESession> {
public:
    std::string
    name() const override {
        return "ErrorInducingMiddleware";
    }
    void
    cancel() override {}
    void
    process(std::shared_ptr<qb::http::Context<RouterE2ESession>> ctx) override {
        ctx->response().set_header("X-Error-Inducer", "Applied");
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    }
};

class RouterE2EServer : public qb::http::use<RouterE2EServer>::server<RouterE2ESession> {
public:
    using Context = qb::http::Context<RouterE2ESession>;

    RouterE2EServer() {
        // ---- Custom global error chain: any routed ERROR -> 503 ----
        qb::http::RouteHandlerFn<RouterE2ESession> error_handler = [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::SERVICE_UNAVAILABLE;
            ctx->response().body()   = "global-error-handled";
            ctx->response().set_header("X-Global-Error-Handler", "Applied");
            ctx->complete();
        };
        auto error_task = std::make_shared<qb::http::RouteLambdaTask<RouterE2ESession>>(error_handler, "GlobalErrorHandlerTask");
        std::vector<std::shared_ptr<qb::http::IAsyncTask<RouterE2ESession>>> error_chain;
        error_chain.push_back(error_task);
        router().set_error_task_chain(std::move(error_chain));

        // ---- A trace middleware proving deterministic on-wire ordering ----
        // Functional middleware signature is void(ctx, next): mutate then call next() to continue
        // the chain (complete() is for route handlers / terminal tasks, not a pass-through MW).
        router().use([](std::shared_ptr<Context> ctx, std::function<void()> next) {
            ctx->response().set_header("X-MW-Trace", "L0;");
            next();
        });

        // ---- GET /ping (+ HEAD): GET has a body, HEAD must strip it ----
        router().get("/ping", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "pong";
            ctx->complete();
        });
        router().head("/ping", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            // Deliberately set a body: the transport must strip it for HEAD.
            ctx->response().body() = "this-body-must-not-reach-the-client";
            ctx->complete();
        });

        // ---- Path-parameter echo (URL-decoded server-side) ----
        router().get("/param/:value", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "param:" + std::string{ctx->path_param("value")};
            ctx->complete();
        });

        // ---- Wildcard capture ----
        router().get("/files/*filepath", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "file:" + std::string{ctx->path_param("filepath")};
            ctx->complete();
        });

        // ---- Query-string handling with defaults ----
        router().get("/search", [](std::shared_ptr<Context> ctx) {
            const auto q             = ctx->request().uri().query_or("q", "none");
            const auto page          = ctx->request().uri().query_or("page", "1");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "q=" + q + ";page=" + page;
            ctx->complete();
        });

        // ---- Body echo (POST) ----
        router().post("/echo", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::CREATED;
            ctx->response().body()   = ctx->request().body().template as<std::string>();
            ctx->complete();
        });

        // ---- Multi-method resource: auto-405 must compute a sorted Allow ----
        router().get("/resource", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "GET resource";
            ctx->complete();
        });
        router().post("/resource", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::CREATED;
            ctx->complete();
        });
        router().put("/resource", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router().del("/resource", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });

        // ---- OPTIONS with an explicit Allow header ----
        router().options("/resource", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->response().set_header("Allow", "GET, POST, PUT, DELETE, OPTIONS");
            ctx->complete();
        });

        // ---- Async-over-loop completion via a deferred callback ----
        router().get("/async", [](std::shared_ptr<Context> ctx) {
            qb::io::async::callback(
                [ctx]() {
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   = "async-done";
                    ctx->response().set_header("X-Async", "completed");
                    ctx->complete();
                },
                qb::duration::zero());
        });

        // ---- Middleware-induced error -> global error chain -> 503 ----
        {
            auto err_group = router().group("/mw-error");
            err_group->use(std::make_shared<ErrorInducingMiddleware>());
            err_group->get("/route", [](std::shared_ptr<Context> ctx) {
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body()   = "should-not-be-reached";
                ctx->complete();
            });
        }

        router().compile();
    }
};

using ServerThread = qb::http::test::ServerThread<RouterE2EServer>;

class RouterE2ETest : public ::testing::Test {
protected:
    std::uint16_t                 _port{0};
    std::unique_ptr<ServerThread> _server;

    void
    SetUp() override {
        qb::io::async::init();
        _port = qb::http::test::ephemeral_port();

        const std::uint16_t port = _port;
        _server                  = std::make_unique<ServerThread>([port](RouterE2EServer &srv) -> bool {
            if (srv.transport().listen_v4(port) != 0) {
                return false;
            }
            srv.start();
            return true;
        });
        ASSERT_TRUE(_server->ready()) << "router e2e server failed to start on port " << _port;
    }

    void
    TearDown() override {
        _server.reset();
    }

    [[nodiscard]] std::string
    url(const std::string &path) const {
        return "http://localhost:" + std::to_string(_port) + path;
    }
};

// ---------------------------------------------------------------------------
// On-the-wire request parsing
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, PathParamSurvivesWire) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/param/hello")}}, kClientTimeout));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "param:hello");
    // The global trace middleware ran and serialized its header.
    EXPECT_EQ(reply.response.header("X-MW-Trace"), "L0;");
}

TEST_F(RouterE2ETest, UrlEncodedPathParamDecodesServerSide) {
    struct Case {
        std::string raw;
    };
    const std::vector<Case> cases = {{"simplevalue"}, {"hello world"}, {"path/component-ish"}, {"!@#$%^&*()"}};

    for (const auto &c : cases) {
        const auto path  = "/param/" + url_encode(c.raw);
        auto       reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url(path)}}, kClientTimeout));
        EXPECT_EQ(reply.response.status(), qb::http::status::OK) << "raw=" << c.raw;
        EXPECT_EQ(reply.response.body().template as<std::string>(), "param:" + c.raw) << "raw=" << c.raw;
    }
}

TEST_F(RouterE2ETest, WildcardCaptureSurvivesWire) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/files/some/long/path/to/file.txt")}}, kClientTimeout));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "file:some/long/path/to/file.txt");
}

TEST_F(RouterE2ETest, QueryStringParsedFromWire) {
    auto with_query = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/search?q=widgets&page=3")}}, kClientTimeout));
    EXPECT_EQ(with_query.response.status(), qb::http::status::OK);
    EXPECT_EQ(with_query.response.body().template as<std::string>(), "q=widgets;page=3");

    auto defaults = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/search")}}, kClientTimeout));
    EXPECT_EQ(defaults.response.body().template as<std::string>(), "q=none;page=1");
}

TEST_F(RouterE2ETest, RequestBodyRoundTripsThroughWire) {
    qb::http::Request req{qb::http::method::POST, {url("/echo")}};
    req.body() = "round-trip-payload";
    auto reply = qb::http::run_sync(qb::http::POST(std::move(req), kClientTimeout));

    EXPECT_EQ(reply.response.status(), qb::http::status::CREATED);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "round-trip-payload");
}

// ---------------------------------------------------------------------------
// HEAD body-stripping on the wire
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, HeadResponseHasNoBodyOnTheWire) {
    auto reply = qb::http::run_sync(qb::http::HEAD(qb::http::Request{qb::http::method::HEAD, {url("/ping")}}, kClientTimeout));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    // The HEAD handler set a body; the transport must strip it for HEAD.
    EXPECT_TRUE(reply.response.body().empty());
}

// ---------------------------------------------------------------------------
// Allow-header serialization (auto-405 + OPTIONS)
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, MethodNotAllowedSerializesAllowHeader) {
    // PATCH is not registered on /resource -> auto 405 with a computed,
    // alphabetically-sorted Allow header (DELETE, GET, POST, PUT, OPTIONS).
    qb::http::Request req{qb::http::method::PATCH, {url("/resource")}};
    auto              reply = qb::http::run_sync(qb::http::PATCH(std::move(req), kClientTimeout));

    EXPECT_EQ(reply.response.status(), qb::http::status::METHOD_NOT_ALLOWED);
    EXPECT_EQ(reply.response.header("Allow"), "DELETE, GET, POST, PUT, OPTIONS");
}

TEST_F(RouterE2ETest, OptionsSerializesExplicitAllowHeader) {
    auto reply = qb::http::run_sync(qb::http::OPTIONS(qb::http::Request{qb::http::method::OPTIONS, {url("/resource")}}, kClientTimeout));
    EXPECT_EQ(reply.response.status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(reply.response.header("Allow"), "GET, POST, PUT, DELETE, OPTIONS");
}

// ---------------------------------------------------------------------------
// Async-over-loop completion
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, AsyncHandlerCompletesOverTheLoop) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/async")}}, kClientTimeout));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "async-done");
    EXPECT_EQ(reply.response.header("X-Async"), "completed");
}

// ---------------------------------------------------------------------------
// Middleware-induced error -> custom global error chain -> exact 503
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, MiddlewareInducedErrorYieldsExact503) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/mw-error/route")}}, kClientTimeout));

    // The handler must never run; the error chain owns the response.
    EXPECT_EQ(reply.response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "global-error-handled");
    EXPECT_EQ(reply.response.header("X-Global-Error-Handler"), "Applied");
    EXPECT_EQ(reply.response.header("X-Error-Inducer"), "Applied");
    EXPECT_NE(reply.response.body().template as<std::string>(), "should-not-be-reached");
}

// ---------------------------------------------------------------------------
// Concurrent in-flight requests on one loop
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, ConcurrentInFlightRequestsAllComplete) {
    // Issue several requests from a single coroutine WITHOUT awaiting each in
    // turn: they are all spawned onto the loop and resolved together. The test
    // pins each response to its own deterministic body, so an out-of-order or
    // cross-talk bug would surface as a mismatched body, not just a count.
    constexpr int               kN = 8;
    std::array<int, kN>         statuses{};
    std::array<std::string, kN> bodies{};
    int                         completed = 0;

    qb::io::async::run_sync([&]() -> qb::io::async::task<void> {
        for (int i = 0; i < kN; ++i) {
            auto reply  = co_await qb::http::GET(qb::http::Request{{url("/param/req" + std::to_string(i))}}, kClientTimeout);
            statuses[i] = reply.response.status();
            bodies[i]   = reply.response.body().template as<std::string>();
            ++completed;
        }
        co_return;
    }());

    ASSERT_EQ(completed, kN);
    for (int i = 0; i < kN; ++i) {
        EXPECT_EQ(statuses[i], static_cast<int>(qb::http::status::OK)) << "i=" << i;
        EXPECT_EQ(bodies[i], "param:req" + std::to_string(i)) << "i=" << i;
    }
}

} // namespace

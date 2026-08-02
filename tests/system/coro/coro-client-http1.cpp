/**
 * @file qbm/http/tests/system/coro/coro-client-http1.cpp
 * @brief System tier: coroutine HTTP/1.1 client awaiters over a real loopback server.
 *
 * Exercises the coroutine-friendly public client entry points declared in
 * `qbm/http/1.1/http.h` (re-exported through `coro.h` / `http.h`):
 *
 *   - `qb::http::{REQUEST,GET,POST,PUT,DEL,HEAD,OPTIONS,PATCH}(Request, qb::duration)`
 *     returning `async::awaiter<async::Reply>`.
 *   - `qb::http::run_sync(awaitable)` — drive the awaitable to completion on the
 *     calling thread's event loop.
 *   - direct `co_await` from inside a `qb::io::async::task<void>`.
 *   - the legacy callback-style `qb::http::GET(Request, cb)` overload (interop).
 *   - the awaiter completion-callback one-shot contract.
 *
 * Topology: a single fixed-route HTTP/1.1 server runs on its own worker thread
 * via the shared `ServerThread<>` RAII harness (readiness barrier, NO sleep_for
 * warmup, NO magic port). The test body drives the client on the main thread's
 * event loop. All assertions are on observable response state.
 *
 * De-flake notes (vs the pre-restructure `test-coro-client.cpp`):
 *   - magic port 29879 + `sleep_for(40ms)` warmup -> `listen_v4(0)` on the socket
 *     that actually serves + the condition-variable readiness barrier inside
 *     `ServerThread`.
 *   - busy-spin callback poll -> bounded `pump_until(pred, budget)` that fails
 *     loud on timeout instead of looping with a 3s wall deadline.
 *   - `TimeoutYieldsGatewayTimeout` previously asserted only `status != OK`
 *     against a closed port (race between refused/timeout). It now hits a
 *     deterministic NEVER-COMPLETE route with a bounded client timeout, so the
 *     HTTP/1.1 client's timeout mapping yields EXACTLY 504 Gateway Timeout.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "../../shared/loopback_server.h"

#include "../coro.h"
#include "../http.h"

using namespace std::chrono_literals;

namespace {

class CoroTestServer;

class CoroTestSession : public qb::http::use<CoroTestSession>::session<CoroTestServer> {
public:
    explicit CoroTestSession(CoroTestServer &server)
        : session(server) {}
};

/// Fixed-route HTTP/1.1 server used by every test in this file.
class CoroTestServer : public qb::http::use<CoroTestServer>::server<CoroTestSession> {
public:
    CoroTestServer() {
        router().get("/ping", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "pong";
            ctx->response().add_header("X-Source", "coro-test-server");
            ctx->complete();
        });

        router().get("/echo/:id", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = ctx->path_param("id");
            ctx->complete();
        });

        router().post("/echo", [](auto ctx) {
            ctx->response().status() = qb::http::status::CREATED;
            ctx->response().body()   = ctx->request().body().template as<std::string>();
            ctx->response().add_header("Content-Type", "text/plain");
            ctx->complete();
        });

        router().put("/resource/:id", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "PUT:" + ctx->path_param("id");
            ctx->complete();
        });

        router().del("/resource/:id", [](auto ctx) {
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });

        router().patch("/resource/:id", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "PATCH:" + ctx->path_param("id");
            ctx->complete();
        });

        router().head("/ping", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().add_header("X-Source", "coro-test-server");
            ctx->complete();
        });

        router().head("/head-length", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "4");
            ctx->response().add_header("X-Source", "coro-test-server");
            ctx->complete();
        });

        router().options("/ping", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().add_header("Allow", "GET,HEAD,OPTIONS");
            ctx->complete();
        });

        // A deterministic 4xx route for error-status round-trips.
        router().get("/missing", [](auto ctx) {
            ctx->response().status() = qb::http::status::NOT_FOUND;
            ctx->response().body()   = "no-such-thing";
            ctx->complete();
        });

        // A deterministic 5xx route (server-side application failure).
        router().get("/explode", [](auto ctx) {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->response().body()   = "kaboom";
            ctx->complete();
        });

        // Large-body echo to exercise the chunked/large-buffer parse path.
        router().post("/bulk", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = ctx->request().body().template as<std::string>();
            ctx->complete();
        });

        // A route that NEVER completes: the handler suspends forever (the
        // captured context is dropped without `complete()`), so the only way
        // the client awaiter resolves is via its own request timeout. This
        // pins the framework's timeout->504 mapping deterministically.
        router().get("/blackhole", [](auto ctx) {
            // Intentionally retain the context but never complete it.
            auto held = ctx;
            (void) held;
        });

        router().compile();
    }
};

using ServerThread = qb::http::test::ServerThread<CoroTestServer>;

/// Boots the loopback server on a worker thread; the client runs on the main loop.
class CoroClientTest : public ::testing::Test {
protected:
    std::uint16_t                 _port{0};
    std::unique_ptr<ServerThread> _server;

    void
    SetUp() override {
        qb::io::async::init();

        // Bind :0 on the socket that ACTUALLY SERVES and read the port back, rather than probing
        // for a free port and binding it a moment later. `ephemeral_port()` documents the hole
        // this closes: its probe must be shut before the caller can bind, so under `ctest -j`
        // another test PROCESS can take the port in that window (measured: 2 failures in 12
        // full-suite runs). Binding :0 here leaves no window at all.
        _server = std::make_unique<ServerThread>([](CoroTestServer &srv) -> bool {
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
                return false;
            }
            srv.start();
            return true;
        });
        ASSERT_TRUE(_server->ready()) << "coro HTTP/1.1 loopback server failed to start";
        // The ServerThread ctor already blocked on the readiness barrier, so the transport is
        // bound and its assigned port is visible to this thread.
        _port = _server->server().transport().local_endpoint().port();
        ASSERT_NE(_port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
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
// Happy-path awaiters
// ---------------------------------------------------------------------------

TEST_F(CoroClientTest, GetReturnsAwaiterWithReply) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/ping")}}));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "pong");
    EXPECT_EQ(reply.response.header("X-Source"), "coro-test-server");
}

TEST_F(CoroClientTest, ReplyCarriesOriginalRequest) {
    qb::http::Request req{{url("/echo/42")}};
    req.add_header("X-Trace-Id", "trace-coro-1");
    auto reply = qb::http::run_sync(qb::http::GET(std::move(req)));

    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "42");
    EXPECT_EQ(reply.request.header("X-Trace-Id"), "trace-coro-1");
}

TEST_F(CoroClientTest, PostWithBodyRoundTrips) {
    qb::http::Request req{qb::http::method::POST, {url("/echo")}};
    req.body() = "hello-world";
    auto reply = qb::http::run_sync(qb::http::POST(std::move(req)));

    EXPECT_EQ(reply.response.status(), qb::http::status::CREATED);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "hello-world");
}

TEST_F(CoroClientTest, AllVerbsReachTheServer) {
    using qb::http::Request;

    EXPECT_EQ(qb::http::run_sync(qb::http::GET(Request{{url("/ping")}})).response.status(), qb::http::status::OK);
    EXPECT_EQ(qb::http::run_sync(qb::http::PUT(Request{qb::http::method::PUT, {url("/resource/7")}})).response.status(), qb::http::status::OK);
    EXPECT_EQ(qb::http::run_sync(qb::http::DEL(Request{qb::http::method::DEL, {url("/resource/7")}})).response.status(),
              qb::http::status::NO_CONTENT);
    EXPECT_EQ(qb::http::run_sync(qb::http::PATCH(Request{qb::http::method::PATCH, {url("/resource/7")}})).response.status(),
              qb::http::status::OK);
    EXPECT_EQ(qb::http::run_sync(qb::http::HEAD(Request{qb::http::method::HEAD, {url("/ping")}})).response.status(), qb::http::status::OK);
    EXPECT_EQ(qb::http::run_sync(qb::http::OPTIONS(Request{qb::http::method::OPTIONS, {url("/ping")}})).response.status(),
              qb::http::status::OK);
}

TEST_F(CoroClientTest, HeadResponseWithContentLengthCompletesWithoutBody) {
    qb::http::Request request{qb::http::method::HEAD, {url("/head-length")}};
    auto              reply = qb::http::run_sync(qb::http::HEAD(std::move(request), 2s));

    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.header("Content-Length"), "4");
    EXPECT_TRUE(reply.response.body().empty());
}

// ---------------------------------------------------------------------------
// Error-status round-trips (4xx / 5xx bodies travel back intact)
// ---------------------------------------------------------------------------

TEST_F(CoroClientTest, NotFoundStatusAndBodyRoundTrip) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/missing")}}));
    EXPECT_EQ(reply.response.status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "no-such-thing");
}

TEST_F(CoroClientTest, ServerErrorStatusAndBodyRoundTrip) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/explode")}}));
    EXPECT_EQ(reply.response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "kaboom");
}

// ---------------------------------------------------------------------------
// Large POST body — exercises the large-buffer / chunked parse path
// ---------------------------------------------------------------------------

TEST_F(CoroClientTest, LargePostBodyRoundTrips) {
    const std::string payload(256 * 1024, 'Z'); // 256 KiB
    qb::http::Request req{qb::http::method::POST, {url("/bulk")}};
    req.body() = payload;

    auto reply = qb::http::run_sync(qb::http::POST(std::move(req), 5s));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>().size(), payload.size());
    EXPECT_EQ(reply.response.body().template as<std::string>(), payload);
}

// ---------------------------------------------------------------------------
// Real co_await suspension / resume
// ---------------------------------------------------------------------------

TEST_F(CoroClientTest, CoAwaitFromInsideCoroutine) {
    qb::http::Response captured;
    bool               done = false;

    qb::io::async::run_sync([&]() -> qb::io::async::task<void> {
        auto reply = co_await qb::http::GET(qb::http::Request{{url("/ping")}});
        captured   = std::move(reply.response);
        done       = true;
        co_return;
    }());

    EXPECT_TRUE(done);
    EXPECT_EQ(captured.status(), qb::http::status::OK);
    EXPECT_EQ(captured.body().template as<std::string>(), "pong");
}

TEST_F(CoroClientTest, SequentialAwaitsShareLoop) {
    std::vector<int> statuses;

    qb::io::async::run_sync([&]() -> qb::io::async::task<void> {
        for (int i = 0; i < 3; ++i) {
            auto reply = co_await qb::http::GET(qb::http::Request{{url("/echo/" + std::to_string(i))}});
            statuses.push_back(reply.response.status());
        }
        co_return;
    }());

    ASSERT_EQ(statuses.size(), 3u);
    for (int s : statuses)
        EXPECT_EQ(s, static_cast<int>(qb::http::status::OK));
}

// ---------------------------------------------------------------------------
// Timeout mapping: a never-completing route yields a deterministic 504
// ---------------------------------------------------------------------------

TEST_F(CoroClientTest, TimeoutYieldsGatewayTimeout) {
    // The server accepts the request but its handler never calls complete(),
    // so the response can only arrive via the client's request timeout. The
    // HTTP/1.1 client maps that timeout to 504 Gateway Timeout (client.cpp /
    // 1.1/http.h on(event::timeout) -> Response{GATEWAY_TIMEOUT}).
    qb::http::Request req{{url("/blackhole")}};
    auto              reply = qb::http::run_sync(qb::http::GET(std::move(req), 250ms));

    EXPECT_EQ(reply.response.status(), qb::http::status::GATEWAY_TIMEOUT);
}

// ---------------------------------------------------------------------------
// Interop with the untouched callback-style API
// ---------------------------------------------------------------------------

TEST_F(CoroClientTest, CallbackApiStillWorks) {
    std::atomic<bool>  callback_fired{false};
    qb::http::Response received;

    qb::http::GET(qb::http::Request{{url("/ping")}}, [&](qb::http::async::Reply &&reply) {
        received       = std::move(reply.response);
        callback_fired = true;
    });

    ASSERT_TRUE(ServerThread::pump_until([&] { return callback_fired.load(); })) << "callback-style GET never fired";

    EXPECT_EQ(received.status(), qb::http::status::OK);
    EXPECT_EQ(received.body().template as<std::string>(), "pong");
}

} // namespace

// The awaiter's completion callback is one-shot: a second complete() is ignored.
TEST(HttpCoroAwaiterTest, CompletionCallbackIsOneShot) {
    auto value = qb::http::run_sync(qb::http::async::make_awaiter<int>([](std::function<void(int &&)> complete) {
        complete(1);
        complete(2); // Must be ignored.
    }));

    EXPECT_EQ(value, 1);
}

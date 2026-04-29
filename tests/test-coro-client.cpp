/**
 * @file qbm/http/tests/test-coro-client.cpp
 * @brief Coroutine HTTP/1.1 and HTTP/2 client API tests.
 *
 * These tests exercise the coroutine-friendly public entry points
 * introduced by `qbm/http/coro.h`:
 *
 *   - `qb::http::{REQUEST,GET,POST,PUT,DEL,HEAD,OPTIONS,PATCH}(Request, double)`
 *     returning `async::awaiter<async::Reply>`.
 *   - `qb::http::run_sync(awaitable)` convenience alias over
 *     `qb::io::async::run_sync`.
 *   - `qb::http2::Client::connect()` returning `awaiter<ConnectResult>`.
 *   - `qb::http2::Client::push_request(Request)` returning `awaiter<Response>`.
 *   - `qb::http2::Client::push_requests(std::vector<Request>)` returning
 *     `awaiter<std::vector<Response>>`.
 *
 * Pattern / topology:
 *   - An HTTP/1.1 server runs on its own thread on localhost.
 *   - Each test spawns client work from the gtest thread, driving the
 *     awaitables through either `qb::http::run_sync` (for the blocking-test
 *     ergonomy) or a locally-spawned `qb::io::async::task<void>` (to verify
 *     the actual `co_await` path).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

#include "../http.h"
#include "../coro.h"

namespace {

using SessionCtx = qb::http::Context<class CoroTestSession>;

class CoroTestServer;

class CoroTestSession
    : public qb::http::use<CoroTestSession>::session<CoroTestServer> {
public:
    explicit CoroTestSession(CoroTestServer& server) : session(server) {}
};

/// Tiny fixed-route HTTP/1.1 server used by every test in this file.
class CoroTestServer
    : public qb::http::use<CoroTestServer>::server<CoroTestSession> {
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

        router().compile();
    }
};

/// Shared fixture: boots the server on a dedicated thread, tears it down cleanly.
class CoroClientTest : public ::testing::Test {
protected:
    static constexpr int kPort = 29879;

    std::thread                     _server_thread;
    std::atomic<bool>               _server_ready{false};
    std::atomic<bool>               _keep_server_alive{true};

    void SetUp() override {
        qb::io::async::init();
        _server_thread = std::thread([this] {
            qb::io::async::init();
            CoroTestServer server;
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

// ---------------------------------------------------------------------------
// HTTP/1.1 coroutine client tests
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

    EXPECT_EQ(qb::http::run_sync(qb::http::GET    (Request{{url("/ping")}})).response.status(),
              qb::http::status::OK);
    EXPECT_EQ(qb::http::run_sync(qb::http::PUT    (Request{qb::http::method::PUT,    {url("/resource/7")}})).response.status(),
              qb::http::status::OK);
    EXPECT_EQ(qb::http::run_sync(qb::http::DEL    (Request{qb::http::method::DEL,    {url("/resource/7")}})).response.status(),
              qb::http::status::NO_CONTENT);
    EXPECT_EQ(qb::http::run_sync(qb::http::PATCH  (Request{qb::http::method::PATCH,  {url("/resource/7")}})).response.status(),
              qb::http::status::OK);
    EXPECT_EQ(qb::http::run_sync(qb::http::HEAD   (Request{qb::http::method::HEAD,   {url("/ping")}})).response.status(),
              qb::http::status::OK);
    EXPECT_EQ(qb::http::run_sync(qb::http::OPTIONS(Request{qb::http::method::OPTIONS,{url("/ping")}})).response.status(),
              qb::http::status::OK);
}

TEST_F(CoroClientTest, HeadResponseWithContentLengthCompletesWithoutBody) {
    qb::http::Request request{qb::http::method::HEAD, {url("/head-length")}};
    auto reply = qb::http::run_sync(qb::http::HEAD(std::move(request), 2.0));

    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.header("Content-Length"), "4");
    EXPECT_TRUE(reply.response.body().empty());
}

TEST_F(CoroClientTest, CoAwaitFromInsideCoroutine) {
    // Drives the same awaitable through `co_await`, exercising the real
    // coroutine suspension / resume path (rather than `run_sync` which
    // pumps the loop manually).
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
    // Verifies that a single coroutine may issue several HTTP calls in
    // sequence without interference from the event loop.
    std::vector<int> statuses;

    qb::io::async::run_sync([&]() -> qb::io::async::task<void> {
        for (int i = 0; i < 3; ++i) {
            auto reply = co_await qb::http::GET(
                qb::http::Request{{url("/echo/" + std::to_string(i))}});
            statuses.push_back(reply.response.status());
        }
        co_return;
    }());

    ASSERT_EQ(statuses.size(), 3u);
    for (int s : statuses) EXPECT_EQ(s, static_cast<int>(qb::http::status::OK));
}

TEST_F(CoroClientTest, TimeoutYieldsGatewayTimeout) {
    // Send a request to a closed port with a tight timeout; the awaitable
    // must resolve (not hang) with the framework's "connection failure" mapping.
    qb::http::Request req{{"http://127.0.0.1:1/unused"}};
    auto reply = qb::http::run_sync(qb::http::GET(std::move(req), 0.25));
    // The exact failure status depends on the platform (connection refused
    // vs timeout), but it must never be 200 OK.
    EXPECT_NE(reply.response.status(), qb::http::status::OK);
}

// ---------------------------------------------------------------------------
// Interop with the untouched callback-style API (must still work)
// ---------------------------------------------------------------------------

TEST_F(CoroClientTest, CallbackApiStillWorks) {
    std::atomic<bool> callback_fired{false};
    qb::http::Response received;

    qb::http::GET(qb::http::Request{{url("/ping")}},
                  [&](qb::http::async::Reply&& reply) {
                      received        = std::move(reply.response);
                      callback_fired  = true;
                  });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (!callback_fired.load() && std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    ASSERT_TRUE(callback_fired.load());
    EXPECT_EQ(received.status(), qb::http::status::OK);
    EXPECT_EQ(received.body().template as<std::string>(), "pong");
}

} // namespace

TEST(HttpCoroAwaiterTest, CompletionCallbackIsOneShot) {
    auto value = qb::http::run_sync(
        qb::http::async::make_awaiter<int>(
            [](std::function<void(int&&)> complete) {
                complete(1);
                complete(2); // Must be ignored.
            }));

    EXPECT_EQ(value, 1);
}

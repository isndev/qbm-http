/**
 * @file qbm/http/tests/test-coro-http2-client.cpp
 * @brief Coroutine HTTP/2 client API tests.
 *
 * Covers the three coroutine entry points added to `qb::http2::Client`:
 *
 *   - `awaiter<ConnectResult> connect()`
 *   - `awaiter<Response>      push_request(Request)`
 *   - `awaiter<std::vector<Response>> push_requests(std::vector<Request>)`
 *
 * The topology mirrors `test-integration-http2-client.cpp`: a tiny HTTP/2
 * server runs on its own thread with self-signed TLS, and the test body
 * exercises the coroutine API from the gtest thread. If the SSL fixture
 * files are missing, the test is skipped (same convention as the existing
 * HTTP/2 integration test).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

#include <atomic>
#include <chrono>
#include <fstream>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

#include "../2/client.h"
#include "../2/http2.h"
#include "../coro.h"

namespace {

class CoroH2Server;

class CoroH2Session : public qb::http2::use<CoroH2Session>::session<CoroH2Server> {
public:
    explicit CoroH2Session(CoroH2Server& server) : session(server) {}
};

class CoroH2Server : public qb::http2::use<CoroH2Server>::server<CoroH2Session> {
public:
    CoroH2Server() {
        router().get("/ping", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "pong-h2";
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        router().get("/echo/:id", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = ctx->path_param("id");
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        router().post("/data", [](auto ctx) {
            ctx->response().status() = qb::http::status::CREATED;
            ctx->response().body()   = ctx->request().body().template as<std::string>();
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        router().compile();
    }
};

class CoroH2ClientTest : public ::testing::Test {
protected:
    static constexpr int kPort   = 19877;
    const char*          kCert   = "cert.pem";
    const char*          kKey    = "key.pem";

    std::unique_ptr<CoroH2Server> _server;
    std::thread                   _server_thread;
    std::atomic<bool>             _server_ready{false};
    std::atomic<bool>             _keep_alive{true};

    bool ssl_fixtures_available() const {
        std::ifstream c(kCert), k(kKey);
        return c.good() && k.good();
    }

    void SetUp() override {
        if (!ssl_fixtures_available()) {
            GTEST_SKIP() << "Test SSL certificates missing; skipping HTTP/2 coro tests.";
        }

        qb::io::async::init();
        _server = std::make_unique<CoroH2Server>();

        _server_thread = std::thread([this] {
            qb::io::async::init();
            _server->transport().init(
                qb::io::ssl::create_server_context(SSLv23_server_method(), "cert.pem", "key.pem"));
            _server->transport().set_supported_alpn_protocols({"h2", "http/1.1"});
            _server->transport().listen_v4(kPort);
            _server->start();
            _server_ready.store(true, std::memory_order_release);
            while (_keep_alive.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            }
        });

        while (!_server_ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    void TearDown() override {
        if (IsSkipped()) return;
        _keep_alive.store(false, std::memory_order_release);
        if (_server_thread.joinable()) _server_thread.join();
    }

    [[nodiscard]] std::string url() const {
        return "https://localhost:" + std::to_string(kPort);
    }
};

TEST_F(CoroH2ClientTest, ConnectAwaiterYieldsConnectResult) {
    if (IsSkipped()) return;
    auto client = qb::http2::make_client(url());
    client->set_connect_timeout(5.0);

    auto result = qb::http::run_sync(client->connect());
    ASSERT_TRUE(result) << "expected successful connect, got: " << result.error_message;
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(client->is_connected());
}

TEST_F(CoroH2ClientTest, PushRequestAwaiterYieldsResponse) {
    if (IsSkipped()) return;
    auto client = qb::http2::make_client(url());
    client->set_connect_timeout(5.0);

    // push_request triggers an implicit connect if needed.
    qb::http::Request req;
    req.method() = qb::http::Method::GET;
    req.uri()    = qb::io::uri("/ping");

    auto response = qb::http::run_sync(client->push_request(std::move(req)));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "pong-h2");
    EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
}

TEST_F(CoroH2ClientTest, CoAwaitPushRequestInsideCoroutine) {
    if (IsSkipped()) return;
    auto client = qb::http2::make_client(url());
    client->set_connect_timeout(5.0);

    qb::http::Response captured;
    bool               connected = false;
    qb::io::async::run_sync([&]() -> qb::io::async::task<void> {
        auto cr = co_await client->connect();
        connected = cr.ok;
        if (!connected) co_return;

        qb::http::Request req;
        req.method() = qb::http::Method::POST;
        req.uri()    = qb::io::uri("/data");
        req.add_header("Content-Type", "text/plain");
        req.body()   = "payload-42";
        captured = co_await client->push_request(std::move(req));
        co_return;
    }());

    ASSERT_TRUE(connected);
    EXPECT_EQ(captured.status(), qb::http::status::CREATED);
    EXPECT_EQ(captured.body().template as<std::string>(), "payload-42");
}

TEST_F(CoroH2ClientTest, PushRequestsBatchAwaiter) {
    if (IsSkipped()) return;
    auto client = qb::http2::make_client(url());
    client->set_connect_timeout(5.0);

    std::vector<qb::http::Request> reqs;
    for (int i = 0; i < 4; ++i) {
        qb::http::Request r;
        r.method() = qb::http::Method::GET;
        r.uri()    = qb::io::uri("/echo/" + std::to_string(i));
        reqs.push_back(std::move(r));
    }

    auto responses = qb::http::run_sync(client->push_requests(std::move(reqs)));
    ASSERT_EQ(responses.size(), 4u);
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(responses[i].status(), qb::http::status::OK);
        EXPECT_EQ(responses[i].body().template as<std::string>(), std::to_string(i));
    }
}

TEST_F(CoroH2ClientTest, InteropWithCallbackApiUnchanged) {
    if (IsSkipped()) return;
    auto client = qb::http2::make_client(url());
    client->set_connect_timeout(5.0);

    std::atomic<bool>   done{false};
    qb::http::Response  response;

    qb::http::Request req;
    req.method() = qb::http::Method::GET;
    req.uri()    = qb::io::uri("/ping");

    client->push_request(std::move(req), [&](qb::http::Response r) {
        response = std::move(r);
        done.store(true, std::memory_order_release);
    });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!done.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    ASSERT_TRUE(done.load(std::memory_order_acquire));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "pong-h2");
}

} // namespace

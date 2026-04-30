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
#include <stdexcept>
#include <thread>
#include <vector>

#include "../2/client.h"
#include "../2/http2.h"
#include "../coro.h"
#include "../origin.h"

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

        router().get("/echo-header", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::string(ctx->request().header("x-custom-header"));
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        router().get("/never-complete", [](auto) {
            // Intentionally keep the context unresolved so the client request
            // timeout is the only completion path.
        });

        router().compile();
    }
};

TEST(Http2ClientConfigTest, RejectsPlainHttpBaseUri) {
    EXPECT_THROW(
        {
            auto client = qb::http2::make_client("http://localhost:29881");
            (void)client;
        },
        std::invalid_argument);
}

TEST(HttpClientOriginTest, ComparesHostCaseInsensitivelyAndDefaultPorts) {
    EXPECT_TRUE(qb::http::origin::same(qb::io::uri("https://LOCALHOST/resource"),
                                       qb::io::uri("https://localhost:443/")));
    EXPECT_TRUE(qb::http::origin::same(qb::io::uri("https://localhost:0443/resource"),
                                       qb::io::uri("https://localhost:443/")));
    EXPECT_TRUE(qb::http::origin::same(qb::io::uri("http://Example.com:80/path"),
                                       qb::io::uri("http://example.COM/")));
    EXPECT_TRUE(qb::http::origin::same(qb::io::uri("http://example.com:00080/path"),
                                       qb::io::uri("http://EXAMPLE.com/")));
    EXPECT_FALSE(qb::http::origin::same(qb::io::uri("https://localhost:444/path"),
                                        qb::io::uri("https://localhost/")));
    EXPECT_FALSE(qb::http::origin::same(qb::io::uri("https://localhost:65536/path"),
                                        qb::io::uri("https://localhost:443/")));
    EXPECT_FALSE(qb::http::origin::same(qb::io::uri("http://localhost/path"),
                                        qb::io::uri("https://localhost/")));
}

TEST(Http2ClientConfigTest, RejectsPlainHttpAbsoluteRequestWithoutConnecting) {
    auto client = qb::http2::make_client("https://localhost:1");
    client->set_connect_timeout(0.01);

    bool done = false;
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("http://localhost:1/plain")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    EXPECT_TRUE(done);
    EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(response.body().template as<std::string>(), "HTTP/2 request URI must use https");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);
}

TEST(Http2ClientConfigTest, RejectsCrossOriginAbsoluteRequestWithoutConnecting) {
    auto client = qb::http2::make_client("https://localhost:443");

    bool done = false;
    qb::http::Response response;
    qb::http::Request request{qb::io::uri("https://example.com:443/other")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done = true;
    }));

    EXPECT_TRUE(done);
    EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(response.body().template as<std::string>(),
              "HTTP/2 persistent client only accepts same-origin requests");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());
}

TEST(Http2ClientConfigTest, BatchRejectsInvalidSchemesWithoutConnecting) {
    auto client = qb::http2::make_client("https://localhost:1");
    client->set_connect_timeout(0.01);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("http://localhost:1/plain"));
    requests.emplace_back(qb::io::uri("ws://localhost:1/ws"));

    bool done = false;
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done = true;
    }));

    ASSERT_TRUE(done);
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[0].body().template as<std::string>(), "HTTP/2 request URI must use https");
    EXPECT_EQ(responses[1].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[1].body().template as<std::string>(), "HTTP/2 request URI must use https");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 2u);
}

TEST(Http2ClientConfigTest, BatchRejectsCrossOriginRequestsAndPreservesOrder) {
    auto client = qb::http2::make_client("https://localhost:443");

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("https://example.com/first"));
    requests.emplace_back(qb::io::uri("http://localhost/plain"));
    requests.emplace_back(qb::io::uri("https://localhost:444/wrong-port"));

    bool done = false;
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done = true;
    }));

    ASSERT_TRUE(done);
    ASSERT_EQ(responses.size(), 3u);
    EXPECT_EQ(responses[0].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[0].body().template as<std::string>(),
              "HTTP/2 persistent client only accepts same-origin requests");
    EXPECT_EQ(responses[1].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[1].body().template as<std::string>(), "HTTP/2 request URI must use https");
    EXPECT_EQ(responses[2].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[2].body().template as<std::string>(),
              "HTTP/2 persistent client only accepts same-origin requests");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());
}

TEST(Http2ClientConfigTest, CoroPushRequestRejectsCrossOriginWithoutConnecting) {
    auto response = qb::http::run_sync([]() -> qb::io::async::task<qb::http::Response> {
        auto client = qb::http2::make_client("https://localhost:443");
        qb::http::Request request{qb::io::uri("https://example.com:443/coro")};
        co_return co_await client->push_request(std::move(request));
    }());

    EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(response.body().template as<std::string>(),
              "HTTP/2 persistent client only accepts same-origin requests");
}

TEST(Http2ClientReentrancyTest, BatchCallbackMayQueueAnotherBatchAcrossFailurePasses) {
    auto client = qb::http2::make_client("https://localhost:1");
    client->set_auto_reconnect(false);

    auto make_get_request = [](const std::string &path) {
        qb::http::Request req;
        req.method() = qb::http::Method::GET;
        req.uri() = qb::io::uri(path);
        return req;
    };

    bool first_batch_callback_called = false;
    bool second_batch_callback_called = false;
    std::size_t second_batch_response_count = 0;

    ASSERT_TRUE(client->push_requests(
        {make_get_request("/first")},
        [&](std::vector<qb::http::Response> responses) {
            first_batch_callback_called = true;
            EXPECT_EQ(responses.size(), 1u);
            ASSERT_TRUE(client->push_requests(
                {make_get_request("/second")},
                [&](std::vector<qb::http::Response> second_responses) {
                    second_batch_callback_called = true;
                    second_batch_response_count = second_responses.size();
                }));
        }));

    client->on(qb::io::async::event::disconnected{1});
    EXPECT_TRUE(first_batch_callback_called);
    EXPECT_FALSE(second_batch_callback_called);

    // The second batch is queued by the first callback; a new failure pass must
    // still observe and complete it.
    client->on(qb::io::async::event::disconnected{1});
    EXPECT_TRUE(second_batch_callback_called);
    EXPECT_EQ(second_batch_response_count, 1u);
}

TEST(Http2ClientLifetimeTest, ConnectAwaiterReturnsErrorWhenClientExpiresBeforeAwait) {
    auto connect_result = qb::io::async::run_sync([]() -> qb::io::async::task<qb::http2::ConnectResult> {
        auto client = qb::http2::make_client("https://localhost:1");
        auto awaiter = client->connect();
        client.reset();
        auto result = co_await awaiter;
        co_return result;
    }());

    EXPECT_FALSE(connect_result.ok);
    EXPECT_FALSE(connect_result.error_message.empty());
}

class CoroH2ClientTest : public ::testing::Test {
protected:
    const char*          kCert   = "cert.pem";
    const char*          kKey    = "key.pem";

    int                            _port{0};
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
        static std::atomic<int> next_port{29910};
        _port = next_port.fetch_add(1, std::memory_order_relaxed);
        _server = std::make_unique<CoroH2Server>();

        _server_thread = std::thread([this] {
            qb::io::async::init();
            _server->transport().init(
                qb::io::ssl::create_server_context(SSLv23_server_method(), "cert.pem", "key.pem"));
            _server->transport().set_supported_alpn_protocols({"h2", "http/1.1"});
            _server->transport().listen_v4(_port);
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
        return "https://localhost:" + std::to_string(_port);
    }
};

TEST_F(CoroH2ClientTest, ActiveRequestTimeoutCompletesCallbackOnce) {
    if (IsSkipped()) return;
    auto client = qb::http2::make_client(url());
    client->set_connect_timeout(5.0);
    client->set_request_timeout(0.05);

    std::atomic<int> callbacks{0};
    qb::http::Response response;

    qb::http::Request req;
    req.method() = qb::http::Method::GET;
    req.uri() = qb::io::uri("/never-complete");

    ASSERT_TRUE(client->push_request(std::move(req), [&](qb::http::Response r) {
        response = std::move(r);
        callbacks.fetch_add(1, std::memory_order_acq_rel);
    }));

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (callbacks.load(std::memory_order_acquire) == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_ONCE);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    ASSERT_EQ(callbacks.load(std::memory_order_acquire), 1)
        << "connected=" << client->is_connected()
        << " active=" << client->get_active_request_count();
    EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_EQ(response.body().template as<std::string>(), "Request timeout");

    const auto quiet_until = std::chrono::steady_clock::now() + std::chrono::milliseconds(150);
    while (std::chrono::steady_clock::now() < quiet_until) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    EXPECT_EQ(callbacks.load(std::memory_order_acquire), 1);
    client->disconnect();
}

TEST_F(CoroH2ClientTest, MultipleActiveRequestTimeoutsUseTransportStreamIds) {
    if (IsSkipped()) return;
    auto client = qb::http2::make_client(url());
    client->set_connect_timeout(5.0);
    client->set_request_timeout(0.05);

    std::atomic<int> callbacks{0};
    std::vector<qb::http::Response> responses(2);

    for (std::size_t i = 0; i < responses.size(); ++i) {
        qb::http::Request req;
        req.method() = qb::http::Method::GET;
        req.uri() = qb::io::uri("/never-complete");

        ASSERT_TRUE(client->push_request(std::move(req), [&, i](qb::http::Response r) {
            responses[i] = std::move(r);
            callbacks.fetch_add(1, std::memory_order_acq_rel);
        }));
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (callbacks.load(std::memory_order_acquire) != 2 &&
           std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_ONCE);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    ASSERT_EQ(callbacks.load(std::memory_order_acquire), 2)
        << "connected=" << client->is_connected()
        << " active=" << client->get_active_request_count();
    for (auto const& response : responses) {
        EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT);
        EXPECT_EQ(response.body().template as<std::string>(), "Request timeout");
    }
    EXPECT_EQ(client->get_active_request_count(), 0u);
    client->disconnect();
}

TEST_F(CoroH2ClientTest, ConnectAwaiterYieldsConnectResult) {
    if (IsSkipped()) return;
    auto client = qb::http2::make_client(url());
    client->set_connect_timeout(5.0);

    auto result = qb::http::run_sync(client->connect());
    ASSERT_TRUE(result) << "expected successful connect, got: " << result.error_message;
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(client->is_connected());
}

TEST_F(CoroH2ClientTest, MultipleConnectCallbacksShareOneHandshake) {
    if (IsSkipped()) return;
    auto client = qb::http2::make_client(url());
    client->set_connect_timeout(5.0);

    std::atomic<int> callbacks{0};
    std::atomic<int> successes{0};
    std::vector<std::string> errors(2);

    ASSERT_TRUE(client->connect([&](bool ok, const std::string& error) {
        ++callbacks;
        if (ok) ++successes;
        errors[0] = error;
    }));
    ASSERT_TRUE(client->connect([&](bool ok, const std::string& error) {
        ++callbacks;
        if (ok) ++successes;
        errors[1] = error;
    }));

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (callbacks.load(std::memory_order_acquire) != 2 &&
           std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    EXPECT_EQ(callbacks.load(), 2);
    EXPECT_EQ(successes.load(), 2);
    EXPECT_TRUE(errors[0].empty());
    EXPECT_TRUE(errors[1].empty());
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

TEST_F(CoroH2ClientTest, PushRequestNormalizesCustomHeaderNamesToHttp2Lowercase) {
    if (IsSkipped()) return;
    auto client = qb::http2::make_client(url());
    client->set_connect_timeout(5.0);

    qb::http::Request req;
    req.method() = qb::http::Method::GET;
    req.uri()    = qb::io::uri("/echo-header");
    req.set_header("X-CUSTOM-HEADER", "UPPERCASE-KEY");

    auto response = qb::http::run_sync(client->push_request(std::move(req)));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "UPPERCASE-KEY");
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

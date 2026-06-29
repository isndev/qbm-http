/**
 * @file qbm/http/tests/system/http2/http2-client-coro.cpp
 * @brief Live loopback+TLS tests for the coroutine HTTP/2 client API.
 *
 * The system half of the former `test-coro-http2-client.cpp`. These cases
 * exercise the three coroutine entry points on `qb::http2::Client` against a
 * REAL in-process HTTP/2-over-TLS server:
 *
 *   - `awaiter<ConnectResult>            connect()`
 *   - `awaiter<Response>                 push_request(Request)`
 *   - `awaiter<std::vector<Response>>    push_requests(std::vector<Request>)`
 *
 * plus the active-request timeout path and callback/coroutine interop.
 *
 * Differences from the legacy file (per the restructure spec):
 *   - The cert-missing `GTEST_SKIP` is replaced by a HARD resource prerequisite:
 *     `certs_available()` (from shared/ssl_test_resource.h) is asserted in
 *     SetUp, so a secure build that lost its certificates FAILS loudly instead
 *     of silently green-skipping the whole TLS suite.
 *   - The server fixture is the shared `ServerThread<>` (loopback_server.h):
 *     readiness via condition variable, an ephemeral port (no fixed magic port
 *     that flakes under parallel CTest), and a worker-thread run loop — no
 *     `sleep_for` warmup.
 *   - Client-side completion is awaited with the shared bounded `pump_until`
 *     (fails loud on timeout) instead of ad-hoc deadline/`sleep_for` spins.
 *
 * REQUIRES: ssl + live. This TU stays inside the `if(QB_HAS_SSL)` block.
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

#include "../2/client.h"
#include "../2/http2.h"
#include "../coro.h"

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

using namespace std::chrono_literals;

namespace {

class CoroH2Server;

class CoroH2Session : public qb::http2::use<CoroH2Session>::session<CoroH2Server> {
public:
    explicit CoroH2Session(CoroH2Server &server)
        : session(server) {}
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
            // Intentionally leave the context unresolved so the client request
            // timeout is the only completion path.
        });

        router().compile();
    }
};

using ServerThread = qb::http::test::ServerThread<CoroH2Server>;

/**
 * @brief Coro HTTP/2 client fixture over a real loopback TLS server.
 *
 * The server runs on its own worker thread (via the shared ServerThread RAII),
 * the test body drives the client on the main thread's event loop. The TLS
 * certificate pair is a HARD prerequisite — a missing pair fails the fixture
 * rather than skipping coverage.
 */
class CoroH2ClientTest : public ::testing::Test {
protected:
    std::uint16_t                 _port{0};
    std::unique_ptr<ServerThread> _server;

    void
    SetUp() override {
        // Hard prerequisite: secure system tests must not silently skip.
        ASSERT_TRUE(qb::http::test::certs_available())
            << "Missing TLS test certificates (looked for " << qb::http::test::ssl_cert_path() << " and " << qb::http::test::ssl_key_path()
            << "). The HTTP/2 coro system suite REQUIRES them.";

        qb::io::async::init();
        _port = qb::http::test::ephemeral_port();

        const std::string   cert = qb::http::test::ssl_cert_path().string();
        const std::string   key  = qb::http::test::ssl_key_path().string();
        const std::uint16_t port = _port;

        _server = std::make_unique<ServerThread>([cert, key, port](CoroH2Server &srv) -> bool {
            srv.transport().init(qb::io::ssl::create_server_context(SSLv23_server_method(), cert.c_str(), key.c_str()));
            srv.transport().set_supported_alpn_protocols({"h2", "http/1.1"});
            if (srv.transport().listen_v4(port) != 0) {
                return false;
            }
            srv.start();
            return true;
        });
        ASSERT_TRUE(_server->ready()) << "HTTP/2 loopback server failed to start on port " << _port;
    }

    void
    TearDown() override {
        _server.reset();
    }

    [[nodiscard]] std::string
    url() const {
        return "https://localhost:" + std::to_string(_port);
    }

    [[nodiscard]] std::shared_ptr<qb::http2::Client>
    make_test_client() const {
        auto client = qb::http2::make_client(url());
        client->set_verify_peer(false); // self-signed test cert
        client->set_connect_timeout(5s);
        return client;
    }
};

// ---------------------------------------------------------------------------
// connect() awaiter
// ---------------------------------------------------------------------------

TEST_F(CoroH2ClientTest, ConnectAwaiterYieldsConnectResult) {
    auto client = make_test_client();

    auto result = qb::http::run_sync(client->connect());
    ASSERT_TRUE(result) << "expected successful connect, got: " << result.error_message;
    EXPECT_TRUE(result.ok);
    EXPECT_TRUE(result.error_message.empty());
    EXPECT_TRUE(client->is_connected());
}

TEST_F(CoroH2ClientTest, MultipleConnectCallbacksShareOneHandshake) {
    auto client = make_test_client();

    std::atomic<int>         callbacks{0};
    std::atomic<int>         successes{0};
    std::vector<std::string> errors(2);

    ASSERT_TRUE(client->connect([&](bool ok, const std::string &error) {
        ++callbacks;
        if (ok)
            ++successes;
        errors[0] = error;
    }));
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &error) {
        ++callbacks;
        if (ok)
            ++successes;
        errors[1] = error;
    }));

    ASSERT_TRUE(ServerThread::pump_until([&] { return callbacks.load() == 2; }));

    EXPECT_EQ(callbacks.load(), 2);
    EXPECT_EQ(successes.load(), 2);
    EXPECT_TRUE(errors[0].empty());
    EXPECT_TRUE(errors[1].empty());
    EXPECT_TRUE(client->is_connected());
}

// ---------------------------------------------------------------------------
// push_request() awaiter
// ---------------------------------------------------------------------------

TEST_F(CoroH2ClientTest, PushRequestAwaiterYieldsResponse) {
    auto client = make_test_client();

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
    auto client = make_test_client();

    qb::http::Request req;
    req.method() = qb::http::Method::GET;
    req.uri()    = qb::io::uri("/echo-header");
    req.set_header("X-CUSTOM-HEADER", "UPPERCASE-KEY");

    auto response = qb::http::run_sync(client->push_request(std::move(req)));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "UPPERCASE-KEY");
}

TEST_F(CoroH2ClientTest, CoAwaitConnectThenPushRequestInsideCoroutine) {
    auto client = make_test_client();

    qb::http::Response captured;
    bool               connected = false;
    qb::io::async::run_sync([&]() -> qb::io::async::task<void> {
        auto cr   = co_await client->connect();
        connected = cr.ok;
        if (!connected)
            co_return;

        qb::http::Request req;
        req.method() = qb::http::Method::POST;
        req.uri()    = qb::io::uri("/data");
        req.add_header("Content-Type", "text/plain");
        req.body() = "payload-42";
        captured   = co_await client->push_request(std::move(req));
        co_return;
    }());

    ASSERT_TRUE(connected);
    EXPECT_EQ(captured.status(), qb::http::status::CREATED);
    EXPECT_EQ(captured.body().template as<std::string>(), "payload-42");
}

// ---------------------------------------------------------------------------
// push_requests() batch awaiter
// ---------------------------------------------------------------------------

TEST_F(CoroH2ClientTest, PushRequestsBatchAwaiterYieldsOrderedResponses) {
    auto client = make_test_client();

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

// ---------------------------------------------------------------------------
// Active-request timeout (the only completion path for /never-complete)
// ---------------------------------------------------------------------------

TEST_F(CoroH2ClientTest, ActiveRequestTimeoutCompletesCallbackExactlyOnce) {
    auto client = make_test_client();
    client->set_request_timeout(50ms);

    std::atomic<int>   callbacks{0};
    qb::http::Response response;

    qb::http::Request req;
    req.method() = qb::http::Method::GET;
    req.uri()    = qb::io::uri("/never-complete");

    ASSERT_TRUE(client->push_request(std::move(req), [&](qb::http::Response r) {
        response = std::move(r);
        callbacks.fetch_add(1, std::memory_order_acq_rel);
    }));

    ASSERT_TRUE(ServerThread::pump_until([&] { return callbacks.load(std::memory_order_acquire) >= 1; }))
        << "connected=" << client->is_connected() << " active=" << client->get_active_request_count();

    ASSERT_EQ(callbacks.load(std::memory_order_acquire), 1);
    EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_EQ(response.body().template as<std::string>(), "Request timeout");

    // A quiet window must not produce a second (duplicate) callback.
    const auto quiet_until = std::chrono::steady_clock::now() + 150ms;
    while (std::chrono::steady_clock::now() < quiet_until) {
        qb::io::async::run(EVRUN_NOWAIT);
    }
    EXPECT_EQ(callbacks.load(std::memory_order_acquire), 1);
    EXPECT_EQ(client->get_active_request_count(), 0u);
    client->disconnect();
}

TEST_F(CoroH2ClientTest, MultipleActiveRequestTimeoutsEachCompleteOnce) {
    auto client = make_test_client();
    client->set_request_timeout(50ms);

    std::atomic<int>                callbacks{0};
    std::vector<qb::http::Response> responses(2);

    for (std::size_t i = 0; i < responses.size(); ++i) {
        qb::http::Request req;
        req.method() = qb::http::Method::GET;
        req.uri()    = qb::io::uri("/never-complete");

        ASSERT_TRUE(client->push_request(std::move(req), [&, i](qb::http::Response r) {
            responses[i] = std::move(r);
            callbacks.fetch_add(1, std::memory_order_acq_rel);
        }));
    }

    ASSERT_TRUE(ServerThread::pump_until([&] { return callbacks.load(std::memory_order_acquire) >= 2; }))
        << "connected=" << client->is_connected() << " active=" << client->get_active_request_count();

    ASSERT_EQ(callbacks.load(std::memory_order_acquire), 2);
    for (auto const &response : responses) {
        EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT);
        EXPECT_EQ(response.body().template as<std::string>(), "Request timeout");
    }
    EXPECT_EQ(client->get_active_request_count(), 0u);
    client->disconnect();
}

// ---------------------------------------------------------------------------
// Callback API interop (the coroutine surface must not regress the callback one)
// ---------------------------------------------------------------------------

TEST_F(CoroH2ClientTest, InteropWithCallbackApiUnchanged) {
    auto client = make_test_client();

    std::atomic<bool>  done{false};
    qb::http::Response response;

    qb::http::Request req;
    req.method() = qb::http::Method::GET;
    req.uri()    = qb::io::uri("/ping");

    client->push_request(std::move(req), [&](qb::http::Response r) {
        response = std::move(r);
        done.store(true, std::memory_order_release);
    });

    ASSERT_TRUE(ServerThread::pump_until([&] { return done.load(std::memory_order_acquire); }));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "pong-h2");
    EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
    client->disconnect();
}

} // namespace

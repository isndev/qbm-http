/**
 * @file qbm/http/tests/system/server/make-server-factory.cpp
 * @brief Live loopback tests for the qbm-http server factory functions.
 *
 * The system-tier successor to `test-integration-make-server.cpp`. It verifies
 * the three factory entry points produce a server that actually serves over the
 * loopback interface:
 *
 *   - `qb::http::make_server()`        -> plaintext HTTP/1.1   (UN-GATED)
 *   - `qb::http::ssl::make_server()`   -> HTTPS                (REQUIRES ssl)
 *   - `qb::http2::make_server()`       -> HTTP/2 over TLS+ALPN (REQUIRES ssl)
 *
 * Differences from the legacy file (per the restructure spec, §2/§7):
 *   - DROP the misleading `integration-` prefix (loopback, not daemon).
 *   - UN-GATE the plaintext HTTP/1.1 fixture: it has no SSL dependency and must
 *     build/run on `QB_HAS_SSL=OFF`. Only the https/h2 fixtures stay behind
 *     `#if QB_HAS_SSL`.
 *   - The hand-rolled server threads (fixed magic ports 29878/29880/29882,
 *     `server_ready` busy flags, 200ms/100ms `sleep_for` settles) are replaced
 *     by the shared `ServerThread<>` RAII (loopback_server.h): readiness via
 *     condition variable, ephemeral ports, worker-thread run loops.
 *   - The self-incremented client/server smoke counters are dropped; tests
 *     assert OBSERVABLE response state. The server-side request counter that
 *     still carries signal (proving the handler ran exactly once) is an atomic
 *     owned by the test and asserted in the test body after completion.
 *   - The cert-missing `GTEST_SKIP` + `check_test_certs_exist()` helper is
 *     replaced by the shared `certs_available()` HARD prerequisite.
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

#include <qb/io/async.h>
#include <qb/io/uri.h>

#include <qbm/http/2/client.h>
#include <qbm/http/2/http2.h>
#include <qbm/http/http.h>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

using namespace std::chrono_literals;

namespace {

// ===========================================================================
// Plaintext HTTP/1.1 factory (UN-GATED — no SSL dependency)
// ===========================================================================

using PlainServer       = qb::http::Server<>;
using PlainServerThread = qb::http::test::ServerThread<PlainServer>;

// Server-side request count: the one counter that still carries signal (it
// proves the factory-built handler actually ran). It is an atomic so the test
// thread can read it after the request round-trips.
std::atomic<int> g_plain_server_requests{0};

class HttpMakeServerTest : public ::testing::Test {
protected:
    std::uint16_t                      _port{0};
    std::unique_ptr<PlainServerThread> _server;

    void
    SetUp() override {
        qb::io::async::init();
        g_plain_server_requests = 0;

        // Bind :0 on the socket that ACTUALLY SERVES and read the port back, rather than probing
        // for a free port and binding it a moment later. `ephemeral_port()` documents the hole
        // this closes: its probe must be shut before the caller can bind, so under `ctest -j`
        // another test PROCESS can take the port in that window (measured: 2 failures in 12
        // full-suite runs). Binding :0 here leaves no window at all.
        _server = std::make_unique<PlainServerThread>([](PlainServer &srv) -> bool {
            srv.router().get("/ping", [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
                ++g_plain_server_requests;
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body()   = "pong_http_default";
                ctx->complete();
            });
            srv.router().compile();
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
                return false;
            }
            srv.start();
            return true;
        });
        ASSERT_TRUE(_server->ready()) << "plaintext HTTP/1.1 loopback server failed to start";
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
    base_url() const {
        return "http://localhost:" + std::to_string(_port);
    }
};

TEST_F(HttpMakeServerTest, PingDefaultSessionHttpServer) {
    qb::http::Request request{{base_url() + "/ping"}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("pong_http_default", response.body().as<std::string>());
    EXPECT_EQ(1, g_plain_server_requests.load());
}

#if QB_HAS_SSL

// ===========================================================================
// HTTPS factory (REQUIRES ssl)
// ===========================================================================

using SecureServer       = qb::http::ssl::Server<>;
using SecureServerThread = qb::http::test::ServerThread<SecureServer>;

std::atomic<int> g_https_server_requests{0};

class HttpsMakeServerTest : public ::testing::Test {
protected:
    std::uint16_t                       _port{0};
    std::unique_ptr<SecureServerThread> _server;

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available())
            << "Missing TLS test certificates (looked for " << qb::http::test::ssl_cert_path() << " and " << qb::http::test::ssl_key_path()
            << "). The HTTPS factory system suite REQUIRES them.";

        qb::io::async::init();
        g_https_server_requests = 0;

        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();

        // Bind :0 on the socket that ACTUALLY SERVES and read the port back (see the plaintext
        // fixture above for why): the probe-then-bind window is a cross-process race under
        // `ctest -j`, and binding :0 on the serving socket removes it entirely.
        _server = std::make_unique<SecureServerThread>([cert, key](SecureServer &srv) -> bool {
            auto tls = qb::io::ssl::Context::server(cert, key);
            if (!tls.ok()) {
                return false;
            }
            srv.transport().init(std::move(tls));
            srv.router().get("/ping_ssl", [](std::shared_ptr<qb::http::Context<qb::http::ssl::DefaultSecureSession>> ctx) {
                ++g_https_server_requests;
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body()   = "pong_https_default";
                ctx->complete();
            });
            srv.router().compile();
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
                return false;
            }
            srv.start();
            return true;
        });
        ASSERT_TRUE(_server->ready()) << "HTTPS loopback server failed to start";
        _port = _server->server().transport().local_endpoint().port();
        ASSERT_NE(_port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    }

    void
    TearDown() override {
        _server.reset();
    }

    [[nodiscard]] std::string
    base_url() const {
        return "https://localhost:" + std::to_string(_port);
    }
};

TEST_F(HttpsMakeServerTest, PingDefaultSessionHttpsServer) {
    qb::http::Request request{{base_url() + "/ping_ssl"}};
    // Self-signed test certificate: opt out of secure-by-default verification.
    auto response = qb::http::run_sync(qb::http::GET(request, qb::duration::zero(), /*verify_peer=*/false)).response;

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("pong_https_default", response.body().as<std::string>());
    EXPECT_EQ(1, g_https_server_requests.load());
}

// ===========================================================================
// HTTP/2 factory (REQUIRES ssl)
// ===========================================================================

using Http2FactoryServer       = qb::http2::Server<>;
using Http2FactoryServerThread = qb::http::test::ServerThread<Http2FactoryServer>;

std::atomic<int> g_http2_server_requests{0};

class Http2MakeServerTest : public ::testing::Test {
protected:
    std::uint16_t                             _port{0};
    std::unique_ptr<Http2FactoryServerThread> _server;

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available())
            << "Missing TLS test certificates (looked for " << qb::http::test::ssl_cert_path() << " and " << qb::http::test::ssl_key_path()
            << "). The HTTP/2 factory system suite REQUIRES them.";

        qb::io::async::init();
        g_http2_server_requests = 0;

        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();

        // Bind :0 on the socket that ACTUALLY SERVES and read the port back (see the plaintext
        // fixture above for why): the probe-then-bind window is a cross-process race under
        // `ctest -j`, and binding :0 on the serving socket removes it entirely.
        _server = std::make_unique<Http2FactoryServerThread>([cert, key](Http2FactoryServer &srv) -> bool {
            auto tls = qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"});
            if (!tls.ok()) {
                return false;
            }
            srv.transport().init(std::move(tls));
            srv.router().get("/ping_http2", [](std::shared_ptr<qb::http::Context<qb::http2::DefaultSession>> ctx) {
                ++g_http2_server_requests;
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body()   = "pong_http2_default";
                ctx->complete();
            });
            // A response larger than the default per-stream send window forces
            // the factory-built server through its flow-control / pending-DATA
            // path over a real socket.
            srv.router().get("/big_http2", [](std::shared_ptr<qb::http::Context<qb::http2::DefaultSession>> ctx) {
                std::string body;
                body.reserve(300 * 1024);
                body += "BIG-START;";
                while (body.size() < 300 * 1024) {
                    body += static_cast<char>('a' + (body.size() % 26));
                }
                body += ";BIG-END";
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body()   = std::move(body);
                ctx->complete();
            });
            srv.router().compile();
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
                return false;
            }
            srv.start();
            return true;
        });
        ASSERT_TRUE(_server->ready()) << "HTTP/2 loopback server failed to start";
        _port = _server->server().transport().local_endpoint().port();
        ASSERT_NE(_port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    }

    void
    TearDown() override {
        _server.reset();
    }

    [[nodiscard]] std::string
    base_url() const {
        return "https://localhost:" + std::to_string(_port);
    }
};

TEST_F(Http2MakeServerTest, PingHttp2Server) {
    auto client = std::make_shared<qb::http2::Client>(base_url());
    client->set_verify_peer(false); // self-signed test cert
    client->set_connect_timeout(5s);

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

    qb::http::Request request{{base_url() + "/ping_http2"}};
    request.method() = qb::http::Method::GET;

    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(Http2FactoryServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("pong_http2_default", response.body().as<std::string>());
    EXPECT_EQ(1, g_http2_server_requests.load());

    client->disconnect();
}

// A >256KiB response from the factory-built HTTP/2 server: the per-stream send
// window cannot hold it, so the server's flow-control machinery (pending-DATA
// queue + client WINDOW_UPDATE accounting in 2/protocol/server.h) carries the
// body to completion. Asserting the reassembled sentinels proves end-to-end
// integrity across many flow-controlled DATA frames.
TEST_F(Http2MakeServerTest, FactoryServerStreamsLargeFlowControlledResponse) {
    auto client = std::make_shared<qb::http2::Client>(base_url());
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

    qb::http::Request request{{base_url() + "/big_http2"}};
    request.method() = qb::http::Method::GET;

    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(Http2FactoryServerThread::pump_until([&] { return response_received.load(); }, 15s));

    EXPECT_EQ(qb::http::status::OK, response.status());
    const std::string body = response.body().as<std::string>();
    EXPECT_GT(body.size(), 300u * 1024u);
    EXPECT_EQ(body.compare(0, 10, "BIG-START;"), 0);
    EXPECT_NE(body.find(";BIG-END"), std::string::npos);

    client->disconnect();
}

// Two concurrent streams on one factory-built HTTP/2 connection are each
// answered, and the per-handler request counter advances exactly twice —
// exercising the server session's multiplexed request dispatch + per-stream
// response/cleanup across a real socket.
TEST_F(Http2MakeServerTest, FactoryServerMultiplexesConcurrentStreams) {
    auto client = std::make_shared<qb::http2::Client>(base_url());
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);

    std::atomic<int>                responses_received{0};
    std::vector<qb::http::Response> responses(2);

    for (int i = 0; i < 2; ++i) {
        qb::http::Request request{{base_url() + "/ping_http2"}};
        request.method() = qb::http::Method::GET;
        ASSERT_TRUE(client->push_request(std::move(request), [&, i](qb::http::Response r) {
            responses[i] = std::move(r);
            ++responses_received;
        }));
    }
    client->connect(nullptr);

    ASSERT_TRUE(Http2FactoryServerThread::pump_until([&] { return responses_received.load() == 2; }));

    for (const auto &r : responses) {
        EXPECT_EQ(qb::http::status::OK, r.status());
        EXPECT_EQ("pong_http2_default", r.body().as<std::string>());
    }
    EXPECT_EQ(2, g_http2_server_requests.load());

    client->disconnect();
}

// The factory HTTP/2 server advertises {h2, http/1.1}. A plain HTTPS/1.1 client
// (run_sync) negotiates http/1.1 over ALPN and is served by the SAME handler
// through the session's HTTP/1.1 protocol branch — proving the factory server
// transparently supports the ALPN fallback.
TEST_F(Http2MakeServerTest, FactoryServerServesHttp1FallbackOverAlpn) {
    qb::http::Request request{{base_url() + "/ping_http2"}};
    auto              response = qb::http::run_sync(qb::http::GET(request, qb::duration::zero(), /*verify_peer=*/false)).response;

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("pong_http2_default", response.body().as<std::string>());
    EXPECT_EQ(1, g_http2_server_requests.load());
}

#endif // QB_HAS_SSL

} // namespace

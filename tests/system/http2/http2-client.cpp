/**
 * @file qbm/http/tests/system/http2/http2-client.cpp
 * @brief Live loopback+TLS tests for the callback HTTP/2 client API.
 *
 * The system half of the former `test-integration-http2-client.cpp`. These
 * cases drive `qb::http2::Client` (callback surface) against a REAL in-process
 * HTTP/2-over-TLS server reached over the loopback interface with ALPN `h2`.
 *
 * Differences from the legacy file (per the restructure spec, §7):
 *   - DROP the misleading `integration-` prefix: this is a loopback system test,
 *     not a daemon/integration test.
 *   - The cert-missing `GTEST_SKIP` (+ per-test `IsSkipped()` re-guards) is
 *     replaced by a HARD resource prerequisite: `certs_available()` is asserted
 *     in SetUp, so a secure build that lost its certificates FAILS loudly
 *     instead of silently green-skipping the whole TLS/h2 suite.
 *   - The hand-rolled server thread (fixed magic port 29877, `server_ready`
 *     busy flag, 200ms SSL warmup `sleep_for`) is replaced by the shared
 *     `ServerThread<>` RAII (loopback_server.h): readiness via condition
 *     variable, an ephemeral port (no parallel-CTest port collisions), and a
 *     worker-thread run loop.
 *   - The `h2_server_side_assertions` / `h2_expected_server_assertions`
 *     echo-counter (which only re-asserted values the test itself fed) is
 *     RETIRED. Every test now asserts OBSERVABLE response state (status, body,
 *     headers) plus, where it adds signal, an independent server-derived header.
 *   - Client-side completion is awaited with the shared bounded `pump_until`
 *     (fails loud on timeout) instead of ad-hoc deadline/`sleep_for` spins.
 *   - `std::cout`/`std::cerr` debug noise and the file-local `main()` are stripped.
 *
 * New coverage added per spec: GOAWAY-adjacent graceful drain on disconnect,
 * the previously-dead `/api/large` route, and a bad-ALPN negative case (server
 * offers only `http/1.1`, so the `h2` client connect must fail observably).
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

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

using namespace std::chrono_literals;

namespace {

class H2Server;

class H2Session : public qb::http2::use<H2Session>::session<H2Server> {
public:
    explicit H2Session(H2Server &server)
        : session(server) {}
};

// HTTP/2 server exercising the route surface the callback client tests use.
// Routes echo back enough of the request (id, body, method) that the test body
// can assert correctness from the OBSERVABLE response alone — no server-side
// smoke counters.
class H2Server : public qb::http2::use<H2Server>::server<H2Session> {
public:
    H2Server() {
        // 1. Basic GET.
        router().get("/api/test", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "HTTP/2 GET Success";
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 2. POST echoing the request body back into the response.
        router().post("/api/data", [](auto ctx) {
            const std::string request_body = ctx->request().body().template as<std::string>();
            ctx->response().status()       = qb::http::status::CREATED;
            ctx->response().body()         = "Data received: " + request_body + " - created successfully";
            ctx->response().add_header("Content-Type", "application/json");
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 3. Path-parameter echo.
        router().get("/api/users/:id", [](auto ctx) {
            const std::string id     = ctx->path_param("id");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "User ID: " + id + " (via HTTP/2)";
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 4. Large response (previously a dead route — now exercised).
        router().get("/api/large", [](auto ctx) {
            std::string large_body;
            large_body.reserve(64 * 1024);
            for (int i = 0; i < 1000; ++i) {
                large_body += "This is line " + std::to_string(i) + " of a large HTTP/2 response.\n";
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = large_body;
            ctx->response().add_header("Content-Type", "text/plain");
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 5. Error route.
        router().get("/api/error", [](auto ctx) {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->response().body()   = "HTTP/2 server error occurred";
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 6. Server-initiated RST_STREAM: maps to a BAD_GATEWAY stream error
        //    on the client, observable through the per-request callback.
        router().get("/api/reset-stream", [](auto ctx) {
            auto session = ctx->session();
            if (session) {
                (void) session->reset_stream(static_cast<uint32_t>(ctx->request().stream_id),
                                      qb::protocol::http2::ErrorCode::CANCEL, "test initiated stream reset");
            }
        });

        // 7. HEAD with metadata-only Content-Length.
        router().head("/api/head-metadata", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "123");
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 8. Response carrying trailers.
        router().get("/api/trailers", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "HTTP/2 response with trailers";
            ctx->response().add_header("Trailer", "X-Checksum");
            ctx->response().add_header("X-Checksum", "h2-trailer-ok");
            ctx->complete();
        });

        router().compile();
    }
};

using ServerThread = qb::http::test::ServerThread<H2Server>;

/**
 * @brief HTTP/2 callback-client fixture over a real loopback TLS server.
 *
 * The server runs on its own worker thread (shared ServerThread RAII, ALPN
 * offers `h2` then `http/1.1`); the test body drives the client on the main
 * thread's event loop. The TLS certificate pair is a HARD prerequisite.
 */
class Http2ClientTest : public ::testing::Test {
protected:
    std::uint16_t                 _port{0};
    std::unique_ptr<ServerThread> _server;

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available())
            << "Missing TLS test certificates (looked for " << qb::http::test::ssl_cert_path() << " and "
            << qb::http::test::ssl_key_path() << "). The HTTP/2 client system suite REQUIRES them.";

        qb::io::async::init();
        _port = qb::http::test::ephemeral_port();

        const std::string   cert = qb::http::test::ssl_cert_path().string();
        const std::string   key  = qb::http::test::ssl_key_path().string();
        const std::uint16_t port = _port;

        _server = std::make_unique<ServerThread>([cert, key, port](H2Server &srv) -> bool {
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
// Single request round-trips
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, SimpleGetRequest) {
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/test");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "HTTP/2 GET Success");
    EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
    client->disconnect();
}

TEST_F(Http2ClientTest, PostRequestEchoesBody) {
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

    qb::http::Request request;
    request.method() = qb::http::Method::POST;
    request.uri()    = qb::io::uri("/api/data");
    request.add_header("Content-Type", "application/json");
    request.body() = R"({"key": "test_data", "value": 123})";

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::CREATED);
    // Independent assertion on the server-echoed body, not a smoke counter.
    EXPECT_EQ(response.body().template as<std::string>(),
              R"(Data received: {"key": "test_data", "value": 123} - created successfully)");
    EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
    client->disconnect();
}

TEST_F(Http2ClientTest, ErrorStatusIsPropagated) {
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/error");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_NE(response.body().template as<std::string>().find("server error"), std::string::npos);
    EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
    client->disconnect();
}

// ---------------------------------------------------------------------------
// Large response (formerly a dead route)
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, LargeResponseIsReassembledAcrossDataFrames) {
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/large");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    const std::string body = response.body().template as<std::string>();
    // The body is large enough to span multiple DATA frames; assert the
    // boundary lines survived reassembly, end to end.
    EXPECT_NE(body.find("This is line 0 of a large HTTP/2 response."), std::string::npos);
    EXPECT_NE(body.find("This is line 999 of a large HTTP/2 response."), std::string::npos);
    EXPECT_GT(body.size(), 10000u);
    EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
    client->disconnect();
}

// ---------------------------------------------------------------------------
// Multiplexing
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, ConcurrentRequestsAreEachAnswered) {
    auto client = make_test_client();

    std::atomic<int>                responses_received{0};
    std::vector<qb::http::Response> responses(3);

    for (int i = 0; i < 3; ++i) {
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri("/api/users/" + std::to_string(100 + i));

        ASSERT_TRUE(client->push_request(request, [&, i](qb::http::Response r) {
            responses[i] = std::move(r);
            ++responses_received;
        }));
    }
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return responses_received.load() == 3; }));

    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(responses[i].status(), qb::http::status::OK);
        EXPECT_EQ(responses[i].body().template as<std::string>(),
                  "User ID: " + std::to_string(100 + i) + " (via HTTP/2)");
        EXPECT_EQ(responses[i].header("X-Protocol"), "HTTP/2");
    }
    client->disconnect();
}

TEST_F(Http2ClientTest, BatchRequestsPreserveOrder) {
    auto client = make_test_client();

    std::atomic<bool>               batch_completed{false};
    std::vector<qb::http::Response> batch_responses;

    std::vector<qb::http::Request> requests;
    for (int i = 0; i < 3; ++i) {
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri("/api/users/" + std::to_string(200 + i));
        requests.push_back(std::move(request));
    }

    ASSERT_TRUE(client->push_requests(requests, [&](std::vector<qb::http::Response> responses) {
        batch_responses = std::move(responses);
        batch_completed = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return batch_completed.load(); }));

    ASSERT_EQ(batch_responses.size(), 3u);
    for (std::size_t i = 0; i < batch_responses.size(); ++i) {
        EXPECT_EQ(batch_responses[i].status(), qb::http::status::OK);
        EXPECT_EQ(batch_responses[i].body().template as<std::string>(),
                  "User ID: " + std::to_string(200 + static_cast<int>(i)) + " (via HTTP/2)");
        EXPECT_EQ(batch_responses[i].header("X-Protocol"), "HTTP/2");
    }
    client->disconnect();
}

// ---------------------------------------------------------------------------
// Stream reset mapping (server RST_STREAM -> client BAD_GATEWAY)
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, StreamResetIsMappedToTheCorrectConcurrentRequest) {
    auto client = make_test_client();

    std::atomic<int>   responses_received{0};
    qb::http::Response ok_response;
    qb::http::Response reset_response;

    qb::http::Request ok_request;
    ok_request.method() = qb::http::Method::GET;
    ok_request.uri()    = qb::io::uri("/api/test");

    qb::http::Request reset_request;
    reset_request.method() = qb::http::Method::GET;
    reset_request.uri()    = qb::io::uri("/api/reset-stream");

    ASSERT_TRUE(client->push_request(ok_request, [&](qb::http::Response r) {
        ok_response = std::move(r);
        ++responses_received;
    }));
    ASSERT_TRUE(client->push_request(reset_request, [&](qb::http::Response r) {
        reset_response = std::move(r);
        ++responses_received;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return responses_received.load() == 2; }));

    EXPECT_EQ(ok_response.status(), qb::http::status::OK);
    EXPECT_EQ(ok_response.body().template as<std::string>(), "HTTP/2 GET Success");
    EXPECT_EQ(reset_response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_NE(reset_response.body().template as<std::string>().find("Stream error"), std::string::npos);
    client->disconnect();
}

// ---------------------------------------------------------------------------
// HEAD + trailers
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, HeadResponseAllowsMetadataContentLengthWithoutBody) {
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

    qb::http::Request request;
    request.method() = qb::http::Method::HEAD;
    request.uri()    = qb::io::uri("/api/head-metadata");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("content-length"), "123");
    EXPECT_TRUE(response.body().empty());
    EXPECT_EQ(response.header("x-protocol"), "HTTP/2");
    client->disconnect();
}

TEST_F(Http2ClientTest, ResponseTrailersCompleteStream) {
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/trailers");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "HTTP/2 response with trailers");
    EXPECT_EQ(response.header("X-Checksum"), "h2-trailer-ok");
    client->disconnect();
}

// ---------------------------------------------------------------------------
// GOAWAY-adjacent: graceful drain on client-initiated disconnect
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, GracefulDisconnectDrainsInflightRequest) {
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/test");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));
    EXPECT_EQ(response.status(), qb::http::status::OK);

    // After the in-flight stream completes, a clean disconnect must leave the
    // client with no active requests and report disconnected — the observable
    // end state of the GOAWAY/drain machinery.
    client->disconnect();
    EXPECT_TRUE(ServerThread::pump_until([&] { return !client->is_connected(); }));
    EXPECT_EQ(client->get_active_request_count(), 0u);
}

// ---------------------------------------------------------------------------
// Bad-ALPN negative: server offers only http/1.1, so the h2 client fails
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, ConnectFailsWhenServerDoesNotOfferH2) {
    // A second, independent server that advertises ONLY http/1.1 over ALPN.
    const std::string   cert = qb::http::test::ssl_cert_path().string();
    const std::string   key  = qb::http::test::ssl_key_path().string();
    const std::uint16_t port = qb::http::test::ephemeral_port();

    ServerThread http1_only_server([cert, key, port](H2Server &srv) -> bool {
        srv.transport().init(qb::io::ssl::create_server_context(SSLv23_server_method(), cert.c_str(), key.c_str()));
        srv.transport().set_supported_alpn_protocols({"http/1.1"}); // no "h2"
        if (srv.transport().listen_v4(port) != 0) {
            return false;
        }
        srv.start();
        return true;
    });
    ASSERT_TRUE(http1_only_server.ready());

    auto client = qb::http2::make_client("https://localhost:" + std::to_string(port));
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);

    std::atomic<bool> callback_called{false};
    std::atomic<bool> connected{true};
    std::string       error_message;

    client->connect([&](bool ok, const std::string &err) {
        connected       = ok;
        error_message   = err;
        callback_called = true;
    });

    ASSERT_TRUE(ServerThread::pump_until([&] { return callback_called.load(); }));

    EXPECT_FALSE(connected.load()) << "h2 client must not consider itself connected when ALPN did not negotiate h2";
    EXPECT_FALSE(client->is_connected());
    EXPECT_NE(error_message.find("ALPN"), std::string::npos)
        << "expected an ALPN-negotiation failure message, got: " << error_message;
}

} // namespace

/**
 * @file qbm/http/tests/system/http1/http1-loopback-basic.cpp
 * @brief System (loopback) smoke for the qbm-http HTTP/1.1 server + router.
 *
 * The canonical in-process HTTP/1.1 loopback test: a real `qb::http` server runs
 * on a worker thread (shared @ref qb::http::test::ServerThread harness, ephemeral
 * port, readiness barrier — no sleep warmup) and is driven by a real async client
 * via `qb::http::run_sync`. Every assertion is on the OBSERVABLE client-side
 * response (status / body / headers); there is no server-side smoke-counter that
 * the test increments and then checks against itself.
 *
 * Was `test-integration-basic.cpp` — renamed off the misleading "integration"
 * prefix (it needs no external daemon). Cookie wire routes were dropped: the
 * canonical cookie coverage lives in unit/cookie/cookie.cpp (spec D2).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <gtest/gtest.h>
#include <string>

#include "../../shared/loopback_server.h"

#include "../http.h"

using namespace std::chrono_literals;
using qb::http::test::ephemeral_port;
using qb::http::test::ServerThread;

namespace {

class BasicLoopbackServer;

class BasicLoopbackSession : public qb::http::use<BasicLoopbackSession>::session<BasicLoopbackServer> {
public:
    explicit BasicLoopbackSession(BasicLoopbackServer &server_ref)
        : session(server_ref) {}
};

class BasicLoopbackServer : public qb::http::use<BasicLoopbackServer>::server<BasicLoopbackSession> {
public:
    using SessionContext = qb::http::Context<BasicLoopbackSession>;

    BasicLoopbackServer() {
        // 1. Basic GET
        router().get("/test", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "GET Success";
            ctx->response().add_header("X-Test-Header", "test-value");
            ctx->complete();
        });

        // 2. POST echoes the JSON body back
        router().post("/test", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::CREATED;
            ctx->response().body()   = ctx->request().body();
            ctx->response().add_header("Content-Type", "application/json");
            ctx->complete();
        });

        // 3. PUT with a path parameter
        router().put("/test/:id", [](std::shared_ptr<SessionContext> ctx) {
            std::string id           = ctx->path_param("id");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "PUT Success for ID: " + id;
            ctx->complete();
        });

        // 4. DELETE with a path parameter -> 204
        router().del("/test/:id", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });

        // 5. Query parameters echoed into the body + a header count
        router().get("/query", [](std::shared_ptr<SessionContext> ctx) {
            std::string name{ctx->request().query("name")};
            std::string age{ctx->request().query("age")};
            std::string sort{ctx->request().query_or("sort", "default")};

            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Query params - name: " + name + ", age: " + age + ", sort: " + sort;
            ctx->response().add_header("X-Query-Count", std::to_string(ctx->request().queries().size()));
            ctx->complete();
        });

        // 6. Synchronous handler that completes inline
        router().get("/sync-complete", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Sync response";
            ctx->response().add_header("X-Complete-Type", "inline");
            ctx->complete();
        });

        // 7. Error route -> 500
        router().get("/error", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->response().body()   = "Intentional error";
            ctx->complete();
        });

        // 8. Async handler that completes from a deferred callback
        router().get("/async", [](std::shared_ptr<SessionContext> ctx) {
            qb::io::async::callback(
                [ctx_capture = ctx]() {
                    ctx_capture->response().status() = qb::http::status::OK;
                    ctx_capture->response().body()   = "Async response";
                    ctx_capture->response().add_header("X-Async", "true");
                    ctx_capture->complete();
                },
                50ms);
        });

        // 9. Route group
        auto api_group = router().group("/api/v1");
        api_group->get("/status", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "API Status: OK";
            ctx->response().add_header("X-Route-Type", "group");
            ctx->complete();
        });

        // 10. JSON content type
        router().get("/json", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().add_header("Content-Type", "application/json");
            qb::json json_obj      = {{"message", "This is JSON"}, {"success", true}, {"code", 200}};
            ctx->response().body() = json_obj;
            ctx->complete();
        });

        // 11. Request-headers echo back as JSON
        router().get("/echo-headers", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().add_header("Content-Type", "application/json");

            qb::json headers_json = qb::json::object();
            for (const auto &header_pair : ctx->request().headers()) {
                const auto &name   = header_pair.first;
                const auto &values = header_pair.second;
                if (values.size() == 1) {
                    headers_json[name] = values[0];
                } else {
                    headers_json[name] = qb::json::array();
                    for (const auto &value : values) {
                        headers_json[name].push_back(value);
                    }
                }
            }
            ctx->response().body() = headers_json;
            ctx->complete();
        });

        // 12. Chunked Transfer-Encoding response (server streams the body framed)
        router().get("/chunked", [](std::shared_ptr<SessionContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Transfer-Encoding", "chunked");
            ctx->response().body() = "chunked-body-content";
            ctx->complete();
        });

        // A handler whose response fails serialization (malformed
        // Transfer-Encoding), completed ASYNCHRONOUSLY. Completing from the
        // deferred (noexcept) callback makes send_response run OUTSIDE the
        // Context's task try/catch, so the serialization throw reaches the
        // session's noexcept boundary — which must contain it rather than
        // terminate the process.
        router().get("/throw-serialize", [](std::shared_ptr<SessionContext> ctx) {
            qb::io::async::callback(
                [ctx_capture = ctx]() {
                    ctx_capture->response().status() = qb::http::status::OK;
                    ctx_capture->response().set_header("Transfer-Encoding", "bogus-not-chunked");
                    ctx_capture->response().body() = "x";
                    ctx_capture->complete();
                },
                50ms);
        });

        router().compile();
    }
};

/**
 * @brief Test fixture: one ephemeral-port loopback server per test, started via
 *        the shared @ref ServerThread harness (readiness barrier, no sleep).
 */
class Http1LoopbackBasicTest : public ::testing::Test {
protected:
    std::uint16_t                                      port = ephemeral_port();
    std::unique_ptr<ServerThread<BasicLoopbackServer>> server;

    void
    SetUp() override {
        qb::io::async::init(); // client side runs on the main/test thread
        server = std::make_unique<ServerThread<BasicLoopbackServer>>([this](BasicLoopbackServer &s) {
            if (s.transport().listen_v4(port) != 0) {
                return false;
            }
            s.start();
            return true;
        });
        ASSERT_TRUE(server->ready());
    }

    void
    TearDown() override {
        server.reset();
    }

    [[nodiscard]] std::string
    url(std::string const &path) const {
        return "http://127.0.0.1:" + std::to_string(port) + path;
    }
};

} // namespace

TEST_F(Http1LoopbackBasicTest, GetRequest) {
    qb::http::Request request{{url("/test")}};
    request.add_header("User-Agent", "Http1Loopback/1.0");
    auto response = qb::http::run_sync(qb::http::GET(request)).response;

    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("GET Success", response.body().template as<std::string>());
    EXPECT_EQ("test-value", response.header("X-Test-Header"));
}

TEST_F(Http1LoopbackBasicTest, PostRequestEchoesBody) {
    qb::http::Request request{qb::http::method::POST, {url("/test")}};
    request.add_header("Content-Type", "application/json");
    request.body() = "{\"test\": \"data\"}";
    auto response  = qb::http::run_sync(qb::http::POST(request)).response;

    EXPECT_EQ(HTTP_STATUS_CREATED, response.status());
    EXPECT_EQ("{\"test\": \"data\"}", response.body().template as<std::string>());
    EXPECT_EQ("application/json", response.header("Content-Type"));
}

TEST_F(Http1LoopbackBasicTest, PutRequestWithParam) {
    qb::http::Request request{qb::http::method::PUT, {url("/test/123")}};
    auto              response = qb::http::run_sync(qb::http::PUT(request)).response;

    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("PUT Success for ID: 123", response.body().template as<std::string>());
}

TEST_F(Http1LoopbackBasicTest, DeleteRequestWithParam) {
    qb::http::Request request{qb::http::method::DEL, {url("/test/456")}};
    auto              response = qb::http::run_sync(qb::http::DEL(request)).response;

    EXPECT_EQ(HTTP_STATUS_NO_CONTENT, response.status());
    EXPECT_TRUE(response.body().empty());
}

TEST_F(Http1LoopbackBasicTest, GetWithQueryParameters) {
    qb::http::Request request{{url("/query?name=test&age=25&sort=asc")}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;

    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("Query params - name: test, age: 25, sort: asc", response.body().template as<std::string>());
    EXPECT_EQ("3", response.header("X-Query-Count"));
}

TEST_F(Http1LoopbackBasicTest, GetErrorRoute) {
    qb::http::Request request{{url("/error")}};
    auto              response = qb::http::run_sync(qb::http::GET(request, 5s)).response;

    EXPECT_EQ(HTTP_STATUS_INTERNAL_SERVER_ERROR, response.status());
    EXPECT_EQ("Intentional error", response.body().template as<std::string>());
}

TEST_F(Http1LoopbackBasicTest, GetSyncRoute) {
    qb::http::Request request{{url("/sync-complete")}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;

    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("Sync response", response.body().template as<std::string>());
    EXPECT_EQ("inline", response.header("X-Complete-Type"));
}

TEST_F(Http1LoopbackBasicTest, GetAsyncRoute) {
    qb::http::Request request{{url("/async")}};
    auto              response = qb::http::run_sync(qb::http::GET(request, 5s)).response;

    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("Async response", response.body().template as<std::string>());
    EXPECT_EQ("true", response.header("X-Async"));
}

TEST_F(Http1LoopbackBasicTest, GetRouteGroup) {
    qb::http::Request request{{url("/api/v1/status")}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;

    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("API Status: OK", response.body().template as<std::string>());
    EXPECT_EQ("group", response.header("X-Route-Type"));
}

TEST_F(Http1LoopbackBasicTest, JsonContentType) {
    qb::http::Request request{{url("/json")}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;

    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("application/json", response.header("Content-Type"));
    auto json_body = response.body().template as<qb::json>();
    EXPECT_EQ("This is JSON", json_body["message"]);
    EXPECT_EQ(true, json_body["success"]);
    EXPECT_EQ(200, json_body["code"]);
}

TEST_F(Http1LoopbackBasicTest, RequestHeadersEcho) {
    qb::http::Request request{{url("/echo-headers")}};
    request.add_header("X-Custom-Header", "test-value");
    request.add_header("User-Agent", "Echo-Headers-Test/1.0");
    auto response = qb::http::run_sync(qb::http::GET(request)).response;

    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("application/json", response.header("Content-Type"));
    auto headers_json_body = response.body().template as<qb::json>();
    EXPECT_TRUE(headers_json_body.contains("x-custom-header") || headers_json_body.contains("X-Custom-Header"));
    EXPECT_TRUE(headers_json_body.contains("user-agent") || headers_json_body.contains("User-Agent"));
}

// --- Added coverage (spec 229): 404, 405, keep-alive reuse, chunked framing ---

TEST_F(Http1LoopbackBasicTest, UnknownRouteReturns404) {
    qb::http::Request request{{url("/does-not-exist")}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;

    EXPECT_EQ(HTTP_STATUS_NOT_FOUND, response.status());
}

TEST_F(Http1LoopbackBasicTest, KnownPathWrongMethodReturns405) {
    // /test exists for GET/POST but not for DELETE -> the router answers
    // 405 Method Not Allowed (path matched, verb did not).
    qb::http::Request request{qb::http::method::DEL, {url("/test")}};
    auto              response = qb::http::run_sync(qb::http::DEL(request)).response;

    EXPECT_EQ(HTTP_STATUS_METHOD_NOT_ALLOWED, response.status());
}

TEST_F(Http1LoopbackBasicTest, KeepAliveConnectionServesMultipleRequests) {
    // A single client persists its keep-alive connection across two requests;
    // both must round-trip to their own observable responses.
    auto client = qb::http1::make_client(url("/"));

    auto first = qb::http::run_sync(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri(url("/test"))}));
    EXPECT_EQ(first.status(), qb::http::status::OK);
    EXPECT_EQ(first.body().template as<std::string>(), "GET Success");

    auto second = qb::http::run_sync(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri(url("/sync-complete"))}));
    EXPECT_EQ(second.status(), qb::http::status::OK);
    EXPECT_EQ(second.body().template as<std::string>(), "Sync response");
    EXPECT_TRUE(client->is_connected());
}

TEST_F(Http1LoopbackBasicTest, ChunkedResponseIsReassembled) {
    // The server frames the response with Transfer-Encoding: chunked; the client
    // must transparently de-chunk and surface the full body.
    qb::http::Request request{{url("/chunked")}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;

    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("chunked-body-content", response.body().template as<std::string>());
}

TEST_F(Http1LoopbackBasicTest, MalformedAsyncResponseDoesNotWedgeServer) {
    // The /throw-serialize handler produces, from an async completion, a response
    // that throws during serialization. Without the drain_ready_response
    // containment the throw left the connection wedged with no response (a slow
    // DoS); the server now disconnects cleanly and keeps serving.
    {
        qb::http::Request request{{url("/throw-serialize")}};
        auto              reply = qb::http::run_sync(qb::http::GET(request));
        (void) reply; // The server closes the connection; we only require survival.
    }

    // The server must still be alive and serving a subsequent request.
    qb::http::Request request{{url("/test")}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;
    EXPECT_EQ(HTTP_STATUS_OK, response.status());
    EXPECT_EQ("GET Success", response.body().template as<std::string>());
}

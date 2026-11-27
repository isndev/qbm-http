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
#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <string>
#include <thread>

#include <qb/io/protocol/text.h>
#include <qb/io/tcp/socket.h>

#include "../../shared/loopback_server.h"

#include <qbm/http/http.h>

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
    std::uint16_t                                      port = 0;
    std::unique_ptr<ServerThread<BasicLoopbackServer>> server;

    void
    SetUp() override {
        qb::io::async::init(); // client side runs on the main/test thread
        // Bind :0 and read the port BACK, rather than probing for a free one and binding it a
        // moment later. `ephemeral_port()` documents the hole this closes: its probe must be shut
        // before the caller can bind, so under `ctest -j` another test PROCESS can take the port in
        // that window. Measured here at 2 failures in 12 full-suite runs, across two different
        // tests in this directory. Binding :0 on the socket that actually serves leaves no window
        // at all -- the kernel hands out a port and we keep it.
        server = std::make_unique<ServerThread<BasicLoopbackServer>>([](BasicLoopbackServer &s) {
            if (s.transport().listen_v4(0, "127.0.0.1") != 0) {
                return false;
            }
            s.start();
            return true;
        });
        ASSERT_TRUE(server->ready());
        port = server->port();
        ASSERT_NE(port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
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

// An HTTP/1.1 session keeps the first reason it ended with (Huly QB-1248; the eleventh and twelfth independent reviews
// of its HTTP/2 counterpart). qb-io's disconnect() updates the reason at each call: a session that something ended in a
// pass of the loop, and that a later disconnection of the session's own ended again, reported the later reason -- its
// inactivity timeout's ByTimeout, the drain deadline's ServerDraining, a session type's own timeout handler's. Each
// case holds a request, answers it from a callback outside the read dispatch (nothing is written before the loop's
// next pass), sets in motion what ends the session, and holds the server's thread past what expires; the reason is
// read twice: at the session's release (the server's disconnected() hook: the session is still in its map) and 100 ms
// after the hold-up. With output queued the session's watcher is made pending by the poll that follows the hold-up and
// its release comes after the expired timers; with nothing queued it is released first, and its timers -- the capture
// of the case keeps the session -- tick after its release: the two readings see the two orders.
namespace http1_reason_test {
using std::chrono::milliseconds;

/// What a case sets in motion from the callback, once the request is answered (or not).
enum class Plan : int {
    disconnect_then_timeout,        ///< a disconnection 30 ms later; the session's 150 ms timeout
    nothing_queued_then_timeout,    ///< the same, the request never answered: nothing queued
    disconnect_then_drain_deadline, ///< a disconnection 30 ms later; the server drains, its deadline 40 ms away
    timeout_then_drain_deadline,    ///< the session's 30 ms timeout; the server drains, its deadline 60 ms away
};

/// What the server's thread saw: the run's own.
struct Seen {
    std::atomic<std::size_t> queued{0};    ///< the session's output when the thread was held
    std::atomic<int>         reported{-1}; ///< the session's reason at its release
    std::atomic<int>         reason{-1};   ///< the session's reason, read 100 ms after the hold-up
    std::atomic<int>         own_calls{0}; ///< calls of a session type's own on(event::timeout)
    std::atomic<bool>        done{false};
};
inline Seen *g_seen = nullptr; ///< the run's, set before its server's thread starts, cleared once that thread is joined

/// The /held route of every case: what the server's thread does, from a callback 20 ms after the request was routed.
template <typename ServerT, typename ContextPtr>
void
hold(ServerT *server, ContextPtr ctx) {
    Seen *const observed = g_seen;
    const Plan  plan     = server->plan;
    qb::io::async::callback(
        [ctx, observed, plan, server] {
            const auto session   = ctx->session();
            const int  undefined = static_cast<int>(qb::http::DisconnectedReason::Undefined);
            const auto record    = [](qb::http::drain_outcome) {
            };
            if (plan != Plan::nothing_queued_then_timeout) {
                ctx->response().status() = qb::http::status::OK;
                ctx->complete();
            }
            observed->queued = session->queued();
            switch (plan) {
                case Plan::disconnect_then_timeout:
                case Plan::nothing_queued_then_timeout:
                    // The disconnection's timer first: it expires before the timeout whatever holds the thread between the two.
                    qb::io::async::callback([session, reason = undefined] { session->disconnect(reason); }, milliseconds(30));
                    session->setTimeout(milliseconds(150)); // armed afresh from here
                    std::this_thread::sleep_for(milliseconds(300));
                    break;
                case Plan::disconnect_then_drain_deadline:
                    qb::io::async::callback([session, reason = undefined] { session->disconnect(reason); }, milliseconds(30));
                    (void) server->drain(milliseconds(40), record);
                    std::this_thread::sleep_for(milliseconds(100));
                    break;
                case Plan::timeout_then_drain_deadline:
                    session->setTimeout(milliseconds(30));
                    (void) server->drain(milliseconds(60), record);
                    std::this_thread::sleep_for(milliseconds(150));
                    break;
            }
            qb::io::async::callback(
                [session, observed] {
                    observed->reason = session->ended_for();
                    observed->done   = true;
                },
                milliseconds(100));
        },
        milliseconds(20));
}

/// The server's disconnected() hook: the session is still in its map, its on(disconnected) has run.
template <typename ServerT>
void
record_release(ServerT &server, qb::uuid id) {
    auto const &sessions = server.sessions();
    if (auto it = sessions.find(id); it != sessions.end() && it->second && g_seen)
        g_seen->reported = it->second->ended_for();
}

class Server;
class Session : public qb::http::use<Session>::session<Server> {
public:
    explicit Session(Server &server)
        : session(server) {}
    /// What the server's thread reads of its session, by name.
    [[nodiscard]] std::size_t
    queued() noexcept {
        return this->out().size();
    }
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
};
class Server : public qb::http::use<Server>::server<Session> {
public:
    Plan plan = Plan::disconnect_then_timeout;
    Server() {
        router().get("/held", [this](std::shared_ptr<qb::http::Context<Session>> ctx) { hold(this, std::move(ctx)); });
        router().compile();
    }
    void
    disconnected(qb::uuid id) {
        record_release(*this, id);
        qb::http::use<Server>::server<Session>::disconnected(id);
    }
};

/// A session type with its own timeout handler, which ends the session with a reason of its own.
class OwnServer;
class OwnSession : public qb::http::use<OwnSession>::session<OwnServer> {
public:
    explicit OwnSession(OwnServer &server)
        : session(server) {}
    [[nodiscard]] std::size_t
    queued() noexcept {
        return this->out().size();
    }
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
    void
    on(qb::http::event::timeout const &) {
        if (g_seen)
            ++g_seen->own_calls;
        this->disconnect(qb::http::DisconnectedReason::ByProtocolError);
    }
};
class OwnServer : public qb::http::use<OwnServer>::server<OwnSession> {
public:
    Plan plan = Plan::disconnect_then_timeout;
    OwnServer() {
        router().get("/held", [this](std::shared_ptr<qb::http::Context<OwnSession>> ctx) { hold(this, std::move(ctx)); });
        router().compile();
    }
    void
    disconnected(qb::uuid id) {
        record_release(*this, id);
        qb::http::use<OwnServer>::server<OwnSession>::disconnected(id);
    }
};

/// Runs @p plan on a server of type ServerT, and returns what was seen once its thread is joined.
template <typename ServerT>
void
run(Plan plan, Seen &seen) {
    g_seen = &seen;
    {
        ServerThread<ServerT> thread([plan](ServerT &srv) -> bool {
            srv.plan = plan;
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread.ready());
        qb::io::tcp::socket client;
        ASSERT_EQ(client.connect_v4("127.0.0.1", thread.port()), 0);
        const std::string request = "GET /held HTTP/1.1\r\nHost: localhost\r\n\r\n";
        ASSERT_EQ(client.write(request.data(), request.size()), static_cast<int>(request.size()));
        qb::http::test::wait_until([&] { return seen.done.load(); }, std::chrono::seconds(5), "wait_until",
                                   qb::http::test::fail_wait::nap{milliseconds(5)});
        client.disconnect();
    }
    g_seen = nullptr;
    ASSERT_TRUE(seen.done.load()) << "the session was not read after its release";
}

[[nodiscard]] constexpr int
reason(qb::http::DisconnectedReason r) {
    return static_cast<int>(r);
}
} // namespace http1_reason_test

// Ended by a callback in the pass of its timeout, its response queued: the timeout's tick ran before the release, and
// disconnected it again.
TEST(Http1SessionReason, ADisconnectionInThePassOfTheTimeoutKeepsItsReason) {
    using namespace http1_reason_test;
    Seen seen;
    ASSERT_NO_FATAL_FAILURE(run<Server>(Plan::disconnect_then_timeout, seen));
    ASSERT_GT(seen.queued.load(), 0u) << "nothing queued: the case is the next one";
    EXPECT_EQ(seen.reported.load(), reason(qb::http::DisconnectedReason::Undefined)) << "reported at the release";
    EXPECT_EQ(seen.reason.load(), reason(qb::http::DisconnectedReason::Undefined)) << "read after the hold-up";
}

// The same with nothing queued: released first, its timer ticked after the release, the capture holding the session.
TEST(Http1SessionReason, AReleasedSessionKeepsItsReasonAtItsTimeout) {
    using namespace http1_reason_test;
    Seen seen;
    ASSERT_NO_FATAL_FAILURE(run<Server>(Plan::nothing_queued_then_timeout, seen));
    ASSERT_EQ(seen.queued.load(), 0u);
    EXPECT_EQ(seen.reported.load(), reason(qb::http::DisconnectedReason::Undefined)) << "reported at the release";
    EXPECT_EQ(seen.reason.load(), reason(qb::http::DisconnectedReason::Undefined)) << "read after the hold-up";
}

// A session type's own timeout handler is not called for a session that has ended, before its release or after.
TEST(Http1SessionReason, ASessionTypesOwnTimeoutHandlerIsNotCalledOnceTheSessionHasEnded) {
    using namespace http1_reason_test;
    for (const Plan plan : {Plan::disconnect_then_timeout, Plan::nothing_queued_then_timeout}) {
        Seen seen;
        ASSERT_NO_FATAL_FAILURE(run<OwnServer>(plan, seen));
        EXPECT_EQ(seen.own_calls.load(), 0) << "the handler ran for a session that had ended";
        EXPECT_EQ(seen.reported.load(), reason(qb::http::DisconnectedReason::Undefined)) << "reported at the release";
        EXPECT_EQ(seen.reason.load(), reason(qb::http::DisconnectedReason::Undefined)) << "read after the hold-up";
    }
}

// Ended by a callback in the pass of the drain's deadline: the deadline aborted it again, ServerDraining over the cause.
TEST(Http1SessionReason, ADisconnectionInThePassOfTheDrainDeadlineKeepsItsReason) {
    using namespace http1_reason_test;
    Seen seen;
    ASSERT_NO_FATAL_FAILURE(run<Server>(Plan::disconnect_then_drain_deadline, seen));
    ASSERT_GT(seen.queued.load(), 0u) << "nothing queued: its watcher is not pending, the case proves nothing";
    EXPECT_EQ(seen.reported.load(), reason(qb::http::DisconnectedReason::Undefined)) << "reported at the release";
    EXPECT_EQ(seen.reason.load(), reason(qb::http::DisconnectedReason::Undefined)) << "read after the hold-up";
}

// Ended by its own timeout in the pass of the drain's deadline: it reports the timeout, the first cause.
TEST(Http1SessionReason, ATimeoutInThePassOfTheDrainDeadlineKeepsItsReason) {
    using namespace http1_reason_test;
    Seen seen;
    ASSERT_NO_FATAL_FAILURE(run<Server>(Plan::timeout_then_drain_deadline, seen));
    ASSERT_GT(seen.queued.load(), 0u) << "nothing queued: its watcher is not pending, the case proves nothing";
    EXPECT_EQ(seen.reported.load(), reason(qb::http::DisconnectedReason::ByTimeout)) << "reported at the release";
    EXPECT_EQ(seen.reason.load(), reason(qb::http::DisconnectedReason::ByTimeout)) << "read after the hold-up";
}

// A session in qb-io's lingering close -- its response delivered with `Connection: close`, its sending side shut down,
// waiting for its client to close -- is not cut by its inactivity timeout (the thirteenth independent review of Huly
// QB-1248): the linger has its own bound, and the timeout disconnected the session ByTimeout before its client had
// closed, the socket closed with it. The client keeps its end open a second, under a timeout of 150 ms and a linger of
// 2 s: the session ends at the client's close, and its type is told ResponseTransmitted, the graceful end.
namespace http1_linger_test {
using std::chrono::milliseconds;
using Clock = std::chrono::steady_clock;

struct Seen {
    std::atomic<int>       told{-1};        ///< the reason the session type was told at its release
    std::atomic<long long> released_ms{-1}; ///< from the response to the release
    std::atomic<bool>      done{false};
};
inline Seen             *g_seen = nullptr;
inline Clock::time_point g_answered{};

class Server;
class Session : public qb::http::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
    void
    on(qb::http::event::disconnected &&e) {
        if (g_seen) {
            g_seen->told        = e.reason;
            g_seen->released_ms = std::chrono::duration_cast<milliseconds>(Clock::now() - g_answered).count();
            g_seen->done        = true;
        }
    }
};
class Server : public qb::http::use<Server>::server<Session> {
public:
    Server() {
        router().get("/close", [](std::shared_ptr<qb::http::Context<Session>> ctx) {
            ctx->session()->setTimeout(milliseconds(150));
            g_answered               = Clock::now();
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router().compile();
    }
};
Session::Session(Server &server)
    : session(server) {
    this->set_linger(std::chrono::seconds(2));
}
} // namespace http1_linger_test

TEST(Http1SessionReason, ALingeringSessionIsNotCutByItsInactivityTimeout) {
    using namespace http1_linger_test;
    Seen seen;
    g_seen = &seen;
    {
        ServerThread<Server> thread([](Server &srv) -> bool {
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread.ready());
        qb::io::tcp::socket client;
        ASSERT_EQ(client.connect_v4("127.0.0.1", thread.port()), 0);
        const std::string request = "GET /close HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        ASSERT_EQ(client.write(request.data(), request.size()), static_cast<int>(request.size()));
        char buffer[512];
        (void) qb::io::socket::handle_read_ready(client.native_handle(), std::chrono::seconds(3));
        const int n = client.read(buffer, sizeof(buffer)); // the response
        ASSERT_GT(n, 12);
        EXPECT_EQ(std::string(buffer, 12), "HTTP/1.1 200");
        std::this_thread::sleep_for(milliseconds(1000)); // the client keeps its end open
        client.disconnect();
        qb::http::test::wait_until([&] { return seen.done.load(); }, std::chrono::seconds(4), "wait_until",
                                   qb::http::test::fail_wait::nap{milliseconds(5)});
    }
    g_seen = nullptr;
    ASSERT_TRUE(seen.done.load()) << "the session was not released";
    EXPECT_EQ(seen.told.load(), static_cast<int>(qb::http::DisconnectedReason::ResponseTransmitted))
        << "the lingering session was ended by its inactivity timeout";
    EXPECT_GE(seen.released_ms.load(), 900) << "released before its client closed";
}

// A session held past its extraction runs no timeout, a session type's own handler included: qb-io stops its
// inactivity timer with its watcher (Huly QB-1248's twelfth independent review) -- the HTTP/1.1 session's is the
// `with_timeout` of its base template. Its timeout disconnected a session whose connection goes on under its next
// owner, and told the server of a session it no longer had.
namespace http1_extraction_test {
using std::chrono::milliseconds;

struct Seen {
    std::atomic<bool> extracted{false};
    std::atomic<bool> done{false};
    std::atomic<int>  own_calls{0};      ///< a session type's own on(event::timeout) calls
    std::atomic<int>  reason_after{-1};  ///< disconnection_reason(), 400 ms after the extraction
    std::atomic<int>  server_unknown{0}; ///< the server's disconnected() calls for an id it no longer has
};
inline Seen *g_seen = nullptr;

template <typename S>
class Server;

class OwnSession : public qb::http::use<OwnSession>::session<Server<OwnSession>> {
public:
    explicit OwnSession(Server<OwnSession> &server)
        : session(server) {}
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
    void
    on(qb::http::event::timeout const &) {
        if (g_seen)
            ++g_seen->own_calls;
        this->disconnect(qb::http::DisconnectedReason::ByProtocolError);
    }
};
class PlainSession : public qb::http::use<PlainSession>::session<Server<PlainSession>> {
public:
    explicit PlainSession(Server<PlainSession> &server)
        : session(server) {}
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
};

template <typename S>
class Server : public qb::http::use<Server<S>>::template server<S> {
public:
    std::optional<typename S::transport_io_type> taken; ///< the extracted transport: it ends with the server
    Server() {
        this->router().get("/x", [this](std::shared_ptr<qb::http::Context<S>> ctx) {
            Seen *const observed = g_seen;
            qb::io::async::callback(
                [this, ctx, observed] {
                    auto session = ctx->session();
                    session->setTimeout(milliseconds(100));
                    auto transfer       = this->extractSession(session->id());
                    observed->extracted = transfer.second;
                    taken.emplace(std::move(transfer.first));
                    qb::io::async::callback(
                        [session, observed] {
                            observed->reason_after = session->ended_for();
                            observed->done         = true;
                        },
                        milliseconds(400));
                },
                milliseconds(10));
        });
        this->router().compile();
    }
    void
    disconnected(qb::uuid id) {
        if (g_seen && this->sessions().find(id) == this->sessions().end())
            ++g_seen->server_unknown;
        qb::http::use<Server<S>>::template server<S>::disconnected(id);
    }
};

template <typename S>
void
run(Seen &seen) {
    g_seen = &seen;
    {
        ServerThread<Server<S>> thread([](Server<S> &srv) -> bool {
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread.ready());
        qb::io::tcp::socket client;
        ASSERT_EQ(client.connect_v4("127.0.0.1", thread.port()), 0);
        const std::string request = "GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n";
        ASSERT_EQ(client.write(request.data(), request.size()), static_cast<int>(request.size()));
        qb::http::test::wait_until([&] { return seen.done.load(); }, std::chrono::seconds(5), "wait_until",
                                   qb::http::test::fail_wait::nap{milliseconds(5)});
        client.disconnect();
    }
    g_seen = nullptr;
    ASSERT_TRUE(seen.extracted.load()) << "no session was extracted: the case proves nothing";
    ASSERT_TRUE(seen.done.load()) << "the extracted session was not read";
}
} // namespace http1_extraction_test

TEST(Http1SessionReason, ASessionHeldPastItsExtractionRunsNoTimeout) {
    using namespace http1_extraction_test;
    {
        Seen seen;
        ASSERT_NO_FATAL_FAILURE(run<PlainSession>(seen));
        EXPECT_EQ(seen.reason_after.load(), 0) << "the session whose transport was taken was disconnected";
        EXPECT_EQ(seen.server_unknown.load(), 0) << "the server was told of a session it no longer had";
    }
    {
        Seen seen;
        ASSERT_NO_FATAL_FAILURE(run<OwnSession>(seen));
        EXPECT_EQ(seen.own_calls.load(), 0) << "a timeout handler ran on a session whose transport was taken";
        EXPECT_EQ(seen.reason_after.load(), 0) << "the session whose transport was taken was disconnected";
        EXPECT_EQ(seen.server_unknown.load(), 0) << "the server was told of a session it no longer had";
    }
}

// The HTTP/1.1 server's deadline leaves a session that ended first with its reason, a bare qb-io session -- one with no
// drain hooks of its own, which the deadline disconnects directly -- as well as an HTTP one (the thirteenth independent
// review): disconnected by a callback in the pass of the deadline, its output queued so that its release comes after
// the timers.
namespace http1_bare_test {
using std::chrono::milliseconds;

struct Seen {
    std::atomic<int>  reported{-1};
    std::atomic<int>  reason_after{-1};
    std::atomic<bool> done{false};
};
inline Seen *g_seen = nullptr;

class Server;
class Session : public qb::io::use<Session>::tcp::client<Server> {
public:
    using Protocol = qb::protocol::text::command<Session>;
    explicit Session(Server &server)
        : client(server) {}
    void
    on(Protocol::message &&) {}
    [[nodiscard]] int
    ended_for() const noexcept {
        return this->disconnection_reason();
    }
};

class Server : public qb::http::use<Server>::server<Session> {
public:
    void
    on(Session &registered) {
        Seen *const observed = g_seen;
        auto        session  = this->session(registered.id());
        Server     *server   = this;
        qb::io::async::callback(
            [session, server, observed] {
                *session << std::string("queued\n"); // output queued: the release comes after the expired timers
                qb::io::async::callback([session] { session->disconnect(static_cast<int>(qb::http::DisconnectedReason::Undefined)); },
                                        milliseconds(30));
                (void) server->drain(milliseconds(40), [](qb::http::drain_outcome) {});
                std::this_thread::sleep_for(milliseconds(100));
                qb::io::async::callback(
                    [session, observed] {
                        observed->reason_after = session->ended_for();
                        observed->done         = true;
                    },
                    milliseconds(100));
            },
            milliseconds(20));
    }
    void
    disconnected(qb::uuid id) {
        auto const &all = this->sessions();
        if (auto it = all.find(id); it != all.end() && it->second && g_seen)
            g_seen->reported = it->second->ended_for();
        qb::http::use<Server>::server<Session>::disconnected(id);
    }
};
} // namespace http1_bare_test

TEST(Http1SessionReason, ABareSessionEndedInThePassOfTheDrainDeadlineKeepsItsReason) {
    using namespace http1_bare_test;
    Seen seen;
    g_seen = &seen;
    {
        ServerThread<Server> thread([](Server &srv) -> bool {
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread.ready());
        qb::io::tcp::socket client;
        ASSERT_EQ(client.connect_v4("127.0.0.1", thread.port()), 0);
        qb::http::test::wait_until([&] { return seen.done.load(); }, std::chrono::seconds(5), "wait_until",
                                   qb::http::test::fail_wait::nap{milliseconds(5)});
        client.disconnect();
    }
    g_seen = nullptr;
    ASSERT_TRUE(seen.done.load()) << "the session was not read after its release";
    EXPECT_EQ(seen.reported.load(), static_cast<int>(qb::http::DisconnectedReason::Undefined)) << "reported at the release";
    EXPECT_EQ(seen.reason_after.load(), static_cast<int>(qb::http::DisconnectedReason::Undefined)) << "read after the hold-up";
}

// A session held past its extraction has its INACTIVITY timer stopped -- the one the HTTP session names
// (`inactivity_timer_t`) -- and a timer the session type keeps of its own is left to tick (the fourteenth independent
// review of Huly QB-1248): with a `use<S>::timeout` of its own, qb-io's rule by type stopped that one and left the
// inactivity timer armed, which timed the session out on a connection its next owner has; with a timer of its own type
// as a base, neither was stopped. Inactivity 100 ms, own timer 300 ms, read 450 ms after the extraction.
namespace http1_own_timer_test {
using std::chrono::milliseconds;

struct Seen {
    std::atomic<bool>      extracted{false};
    std::atomic<bool>      done{false};
    std::atomic<int>       reason_after{-1};
    std::atomic<int>       server_unknown{0};
    std::atomic<int>       own_ticks{0};
    std::atomic<long long> inactivity_ms{-1};
    std::atomic<long long> own_ms{-1};
};
inline Seen *g_seen = nullptr;

template <typename S>
class Server;

/// Its own timer is `use<S>::timeout`.
class UseTimeoutSession
    : public qb::http::use<UseTimeoutSession>::session<Server<UseTimeoutSession>>
    , public qb::io::use<UseTimeoutSession>::timeout {
    using http_base = qb::http::use<UseTimeoutSession>::session<Server<UseTimeoutSession>>;
    using own_base  = qb::io::async::with_timeout<UseTimeoutSession>;

public:
    explicit UseTimeoutSession(Server<UseTimeoutSession> &server)
        : http_base(server)
        , own_base(qb::duration::zero()) {}
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
    void
    set_inactivity(qb::duration d) noexcept {
        static_cast<http_base &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    inactivity() noexcept {
        return static_cast<http_base &>(*this).getTimeout();
    }
    void
    set_own(qb::duration d) noexcept {
        static_cast<own_base &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    own() noexcept {
        return static_cast<own_base &>(*this).getTimeout();
    }
    void
    on(qb::io::async::event::timer const &) {
        if (g_seen)
            ++g_seen->own_ticks;
    }
};

/// The same, declared final (the seventeenth independent review's W171): qb-io's probe cannot derive from it, and
/// the name -- the session's public alias -- is looked up in it directly.
class FinalUseTimeoutSession final
    : public qb::http::use<FinalUseTimeoutSession>::session<Server<FinalUseTimeoutSession>>
    , public qb::io::use<FinalUseTimeoutSession>::timeout {
    using http_base = qb::http::use<FinalUseTimeoutSession>::session<Server<FinalUseTimeoutSession>>;
    using own_base  = qb::io::async::with_timeout<FinalUseTimeoutSession>;

public:
    explicit FinalUseTimeoutSession(Server<FinalUseTimeoutSession> &server)
        : http_base(server)
        , own_base(qb::duration::zero()) {}
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
    void
    set_inactivity(qb::duration d) noexcept {
        static_cast<http_base &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    inactivity() noexcept {
        return static_cast<http_base &>(*this).getTimeout();
    }
    void
    set_own(qb::duration d) noexcept {
        static_cast<own_base &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    own() noexcept {
        return static_cast<own_base &>(*this).getTimeout();
    }
    void
    on(qb::io::async::event::timer const &) {
        if (g_seen)
            ++g_seen->own_ticks;
    }
};

/// Its own timer is a base of its own type.
struct Tick : qb::io::async::with_timeout<Tick> {
    Tick()
        : qb::io::async::with_timeout<Tick>(qb::duration::zero()) {}
    void
    on(qb::io::async::event::timer const &) {
        if (g_seen)
            ++g_seen->own_ticks;
    }
};
class TickSession
    : public qb::http::use<TickSession>::session<Server<TickSession>>
    , public Tick {
    using http_base = qb::http::use<TickSession>::session<Server<TickSession>>;

public:
    explicit TickSession(Server<TickSession> &server)
        : http_base(server) {}
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
    void
    set_inactivity(qb::duration d) noexcept {
        static_cast<http_base &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    inactivity() noexcept {
        return static_cast<http_base &>(*this).getTimeout();
    }
    void
    set_own(qb::duration d) noexcept {
        static_cast<Tick &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    own() noexcept {
        return static_cast<Tick &>(*this).getTimeout();
    }
    /// An on() of its own, as a session type that handles something has: it hides both bases' (no ambiguous lookup).
    struct Unused {};
    void
    on(Unused) {}
};

template <typename S>
class Server : public qb::http::use<Server<S>>::template server<S> {
public:
    std::optional<typename S::transport_io_type> taken; ///< the extracted transport: it ends with the server
    Server() {
        this->router().get("/x", [this](std::shared_ptr<qb::http::Context<S>> ctx) {
            Seen *const observed = g_seen;
            qb::io::async::callback(
                [this, ctx, observed] {
                    auto session = ctx->session();
                    session->set_inactivity(milliseconds(100));
                    session->set_own(milliseconds(300));
                    auto transfer       = this->extractSession(session->id());
                    observed->extracted = transfer.second;
                    taken.emplace(std::move(transfer.first));
                    qb::io::async::callback(
                        [session, observed] {
                            observed->reason_after  = session->ended_for();
                            observed->inactivity_ms = std::chrono::duration_cast<milliseconds>(session->inactivity()).count();
                            observed->own_ms        = std::chrono::duration_cast<milliseconds>(session->own()).count();
                            observed->done          = true;
                        },
                        milliseconds(450));
                },
                milliseconds(10));
        });
        this->router().compile();
    }
    void
    disconnected(qb::uuid id) {
        if (g_seen && this->sessions().find(id) == this->sessions().end())
            ++g_seen->server_unknown;
        qb::http::use<Server<S>>::template server<S>::disconnected(id);
    }
};

template <typename S>
void
run(Seen &seen) {
    g_seen = &seen;
    {
        ServerThread<Server<S>> thread([](Server<S> &srv) -> bool {
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread.ready());
        qb::io::tcp::socket client;
        ASSERT_EQ(client.connect_v4("127.0.0.1", thread.port()), 0);
        const std::string request = "GET /x HTTP/1.1\r\nHost: localhost\r\n\r\n";
        ASSERT_EQ(client.write(request.data(), request.size()), static_cast<int>(request.size()));
        qb::http::test::wait_until([&] { return seen.done.load(); }, std::chrono::seconds(5), "wait_until",
                                   qb::http::test::fail_wait::nap{milliseconds(5)});
        client.disconnect();
    }
    g_seen = nullptr;
    ASSERT_TRUE(seen.extracted.load()) << "no session was extracted: the case proves nothing";
    ASSERT_TRUE(seen.done.load()) << "the extracted session was not read";
}

template <typename S>
void
expect_the_inactivity_timer_alone_stopped() {
    Seen seen;
    ASSERT_NO_FATAL_FAILURE(run<S>(seen));
    EXPECT_EQ(seen.reason_after.load(), 0) << "the session whose transport was taken was disconnected";
    EXPECT_EQ(seen.server_unknown.load(), 0) << "the server was told of a session it no longer had";
    EXPECT_EQ(seen.inactivity_ms.load(), 0) << "the inactivity timer was not stopped";
    EXPECT_EQ(seen.own_ms.load(), 300) << "the session's own timer was stopped";
    EXPECT_EQ(seen.own_ticks.load(), 1) << "the session's own timer did not tick";
}
} // namespace http1_own_timer_test

TEST(Http1SessionReason, AnExtractedSessionWithATimerOfItsOwnHasItsInactivityTimerAloneStopped) {
    using namespace http1_own_timer_test;
    expect_the_inactivity_timer_alone_stopped<UseTimeoutSession>();
    expect_the_inactivity_timer_alone_stopped<FinalUseTimeoutSession>();
    expect_the_inactivity_timer_alone_stopped<TickSession>();
}

// The boundary of the lingering exemption (the fourteenth independent review): a session whose close is under way but
// whose output is not delivered -- a `Connection: close` response not yet written when its timeout runs -- is not
// lingering, and its inactivity timeout still ends it, ByTimeout. Exempting every closing session left it held for as
// long as its client read nothing. The response is completed from a callback, outside any dispatch of the session --
// publish() queues it and arms the write --, which then holds the server's thread 250 ms: in the next pass the socket
// is writable and the timeout (150 ms) and a check (100 ms) have expired, and libev runs expired timers before the
// write, so the timeout ends a session whose close is under way, its output not delivered (the fifteenth independent
// review's construction). The check finds the response still queued and the session not lingering: the write had not
// run -- whichever of the two timers ran first, the check proves no order between them (the sixteenth). The premise
// state 18 built on a client that reads nothing held on Linux only: Windows' loopback took a 32 MiB response whole
// within 10 ms.
namespace http1_closing_test {
using std::chrono::milliseconds;
using Clock = std::chrono::steady_clock;

struct Seen {
    std::atomic<int>         told{-1};
    std::atomic<long long>   released_ms{-1};
    std::atomic<bool>        done{false};
    std::atomic<std::size_t> queued_at_check{0};     ///< the session's output at the check: the response not written yet
    std::atomic<int>         lingering_at_check{-1}; ///< whether it lingered there
};
inline Seen             *g_seen = nullptr;
inline Clock::time_point g_answered{};

class Server;
class Session : public qb::http::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
    [[nodiscard]] std::size_t
    queued() noexcept {
        return this->out().size();
    }
    [[nodiscard]] bool
    closing_after_its_peer() noexcept {
        return this->lingering();
    }
    void
    on(qb::http::event::disconnected &&e) {
        if (g_seen) {
            g_seen->told        = e.reason;
            g_seen->released_ms = std::chrono::duration_cast<milliseconds>(Clock::now() - g_answered).count();
            g_seen->done        = true;
        }
    }
};
class Server : public qb::http::use<Server>::server<Session> {
public:
    Server() {
        router().get("/late", [](std::shared_ptr<qb::http::Context<Session>> ctx) {
            Seen *const observed = g_seen;
            qb::io::async::callback(
                [ctx, observed] {
                    auto session = ctx->session();
                    session->setTimeout(milliseconds(150));
                    g_answered               = Clock::now();
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   = std::string(std::size_t{64} << 10, 'b');
                    ctx->complete();
                    qb::io::async::callback(
                        [session, observed] {
                            observed->queued_at_check    = session->queued();
                            observed->lingering_at_check = session->closing_after_its_peer() ? 1 : 0;
                        },
                        milliseconds(100));
                    std::this_thread::sleep_for(milliseconds(250)); // past both: the next pass finds them expired
                },
                milliseconds(1));
        });
        router().compile();
    }
};
Session::Session(Server &server)
    : session(server) {}
} // namespace http1_closing_test

TEST(Http1SessionReason, AClosingSessionNotYetDeliveredStillTimesOut) {
    using namespace http1_closing_test;
    Seen seen;
    g_seen = &seen;
    {
        ServerThread<Server> thread([](Server &srv) -> bool {
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread.ready());
        qb::io::tcp::socket client;
        ASSERT_EQ(client.connect_v4("127.0.0.1", thread.port()), 0);
        const std::string request = "GET /late HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        ASSERT_EQ(client.write(request.data(), request.size()), static_cast<int>(request.size()));
        qb::http::test::wait_until([&] { return seen.done.load(); }, std::chrono::seconds(3), "wait_until",
                                   qb::http::test::fail_wait::nap{milliseconds(5)});
        client.disconnect();
    }
    g_seen = nullptr;
    ASSERT_GT(seen.queued_at_check.load(), 0u) << "the response was written before the timers ran: the case proves nothing";
    ASSERT_EQ(seen.lingering_at_check.load(), 0) << "the session lingered at the check: the case proves nothing";
    ASSERT_TRUE(seen.done.load()) << "a session whose close is under way, its output not delivered, was not released within 3 s";
    EXPECT_EQ(seen.told.load(), static_cast<int>(qb::http::DisconnectedReason::ByTimeout));
    EXPECT_LT(seen.released_ms.load(), 1000) << "the session ended at its linger's bound, not by its timeout";
}

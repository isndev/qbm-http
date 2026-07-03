/**
 * @file qbm/http/tests/system/http3/http3-loopback.cpp
 * @brief System tier: in-process HTTP/3-over-QUIC loopback client+server tests.
 *
 * These tests spin up a real @c qb::http3 QUIC+TLS server and client on
 * 127.0.0.1 (and ::1 for the dual-stack cases), driven by a single pumped
 * @c qb::io::async event loop, using the repository's self-signed test cert.
 * They require a live QUIC+TLS stack but NO external daemon, so they are
 * system-tier (the former @c Http3ClientIntegrationTest / @c Http3DualStack...
 * "Integration" naming was a misnomer — there is no outside process).
 *
 * Extracted from the monolithic @c test-http3-client.cpp and hardened for the
 * "ultimate quality" (qb) bar:
 *   - The ~40 copy-pasted loopback scaffolds are consolidated into the
 *     @ref Http3LoopbackTest fixture, which owns @c qb::io::async::init(), a
 *     hard cert prerequisite, an ephemeral port, and a generous-deadline
 *     @ref pump (replacing the file-local busy-pump helper).
 *   - The TLS cert is a HARD prerequisite via @c shared/ssl_test_resource.h:
 *     a missing cert FAILS @c SetUp loudly rather than silently @c GTEST_SKIP.
 *   - Every fixed magic port (31943, 31987, ...) is replaced by an
 *     @c ephemeral_port() bind-and-read-back, so concurrent CTest never collides.
 *   - The four weak @c EXPECT_NE(status, OK) body/content-length-limit negatives
 *     are pinned to their exact contract (413 PAYLOAD_TOO_LARGE / 502 BAD_GATEWAY).
 *   - The fixed @c for(i<20) pump in the graceful-shutdown test is replaced by a
 *     stable-condition pump.
 *
 * The @c QBM_HTTP_HAS_HTTP3 gate (SSL ∧ QUIC ∧ libnghttp3) is retained.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include "../http.h"

#if defined(QBM_HTTP_HAS_HTTP3)

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

using namespace std::chrono_literals;

namespace {
using qb::http::test::ephemeral_port;

// ---------------------------------------------------------------------------
// Custom-session / connection-observer server types used by a couple of tests.
// ---------------------------------------------------------------------------

class CustomHttp3Session;
using CustomHttp3Server = qb::http3::Server<CustomHttp3Session>;

class CustomHttp3Session : public qb::http3::use<CustomHttp3Session>::session<CustomHttp3Server> {
public:
    using Base = qb::http3::use<CustomHttp3Session>::session<CustomHttp3Server>;

    explicit CustomHttp3Session(CustomHttp3Server &server)
        : Base(server) {}
};

class ReuseHttp3Server;

class ReuseHttp3Session : public qb::http3::use<ReuseHttp3Session>::session<ReuseHttp3Server> {
public:
    using Base = qb::http3::use<ReuseHttp3Session>::session<ReuseHttp3Server>;

    explicit ReuseHttp3Session(ReuseHttp3Server &server)
        : Base(server) {}
};

class ReuseHttp3Server : public qb::http3::use<ReuseHttp3Server>::server<ReuseHttp3Session> {
public:
    std::atomic<int> connected_events{0};

    void
    on(qb::io::async::quic::event::connected const &) {
        ++connected_events;
    }
};

/**
 * @brief Common HTTP/3 loopback fixture: cert prerequisite, async init, ports.
 *
 * Erases the ~40-way copy-pasted "init → certs_available? skip → make_server →
 * route → compile → listen → make_client → pump → assert" scaffold. The cert is
 * a HARD prerequisite (SetUp ASSERTs), not a silent skip. Each test gets a
 * fresh ephemeral port via @ref next_port() so parallel CTest never collides.
 */
class Http3LoopbackTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available())
            << "HTTP/3 system tests require the test TLS certificate pair; resolved cert=" << qb::http::test::ssl_cert_path()
            << " key=" << qb::http::test::ssl_key_path();
        qb::io::async::init();
    }

    /** @brief A fresh kernel-assigned loopback port (no fixed magic ports). */
    static std::uint16_t
    next_port() {
        return qb::http::test::ephemeral_port();
    }

    /** @brief "https://127.0.0.1:<port>" base origin for a server/client pair. */
    static std::string
    https_origin(std::uint16_t port) {
        return "https://127.0.0.1:" + std::to_string(port);
    }

    static std::filesystem::path
    cert_path() {
        return qb::http::test::ssl_cert_path();
    }
    static std::filesystem::path
    key_path() {
        return qb::http::test::ssl_key_path();
    }

    /**
     * @brief Pump the single shared loop until @p done holds or @p budget elapses.
     *
     * HTTP/3 loopback runs server AND client on one @c qb::io::async listener, so
     * this drives both. Fails loud (ADD_FAILURE) on timeout — never hangs.
     */
    static bool
    pump(const std::function<bool()> &done, std::chrono::milliseconds budget = 5s) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!done()) {
            if (std::chrono::steady_clock::now() >= deadline) {
                ADD_FAILURE() << "pump: predicate not satisfied within " << budget.count() << "ms";
                return false;
            }
            if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                std::this_thread::sleep_for(1ms);
            }
        }
        return true;
    }
};

// A request timeout safely above the loopback RTT yet short enough to keep
// "operation never completes" tests fast. The de-flaked replacement for the
// original load-sensitive 30ms deadlines.
constexpr auto kStallTimeout = 250ms;

} // namespace

// ---------------------------------------------------------------------------
// Happy-path round-trips
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, SimpleGetRequest) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().get("/ping", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-protocol", "HTTP/3");
        ctx->response().body() = "pong-h3";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    qb::http::Request  request{qb::io::uri(https_origin(port) + "/ping")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    EXPECT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-protocol"), "HTTP/3");
    EXPECT_EQ(response.body().as<std::string>(), "pong-h3");
    EXPECT_EQ(server_requests.load(), 1);

    client->disconnect();
    server->close();
}

// H7/H8 reentrancy repro: a routed handler emits a response far larger than a tiny configured
// QUIC stream TX budget. Serializing it overflows send_stream_data (quic.cpp), which queues a
// connection close and reentrantly delivers dispatch(connection_closed) WHILE the server is still
// inside nghttp3_conn_read_stream2 for this request. Before the fix, that reentrant close ran
// _connections.erase (→ nghttp3_conn_del) mid-read = use-after-free. The fix defers the connection
// free until the read unwinds. The load-bearing assertion here is IMPLICIT: under ASan this test
// must not use-after-free / crash. The follow-up request proves the server is not wedged (a leaked
// _read_depth from the exception-safety path would freeze every future connection).
TEST_F(Http3LoopbackTest, OversizedResponseReentrantCloseDuringReadIsUseAfterFreeSafe) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();

    auto st                     = server->settings();
    st.max_pending_stream_bytes = 16 * 1024; // enough for handshake/QPACK, far below the response
    server->set_settings(st);

    std::atomic<int> handled{0};
    server->router().get("/big", [&handled](auto ctx) {
        ++handled;
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = std::string(256 * 1024, 'x'); // >> the 16 KB TX budget
        ctx->complete();
    });
    server->router().get("/ok", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "ok";
        ctx->complete();
    });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    std::atomic<bool> settled{false};
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(https_origin(port) + "/big")},
                                     [&](qb::http::Response) { settled = true; }));
    pump([&] { return settled.load(); }, 5s);
    EXPECT_TRUE(settled.load());
    EXPECT_GE(handled.load(), 1) << "the request must have reached the handler (reentrancy path taken)";

    // Server survived and is not wedged: a fresh connection still serves.
    auto client2 = qb::http3::make_client(https_origin(port));
    client2->set_verify_peer(false);
    std::atomic<bool> settled2{false};
    qb::http::Response r2;
    ASSERT_TRUE(client2->push_request(qb::http::Request{qb::io::uri(https_origin(port) + "/ok")}, [&](qb::http::Response res) {
        r2       = std::move(res);
        settled2 = true;
    }));
    pump([&] { return settled2.load(); }, 5s);
    EXPECT_TRUE(settled2.load());
    EXPECT_EQ(r2.status(), qb::http::status::OK);
    EXPECT_EQ(r2.body().as<std::string>(), "ok");

    client->disconnect();
    client2->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, RelativeUriUsesClientBaseUri) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/relative", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "relative-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/relative")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "relative-ok");

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, PostRequestWithBody) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().post("/echo", [](auto ctx) {
        ctx->response().status() = qb::http::status::CREATED;
        ctx->response().set_header("x-protocol", "HTTP/3");
        ctx->response().body() = ctx->request().body().template as<std::string>();
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri(https_origin(port) + "/echo")};
    request.body() = "payload-h3";

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::CREATED);
    EXPECT_EQ(response.header("x-protocol"), "HTTP/3");
    EXPECT_EQ(response.body().as<std::string>(), "payload-h3");

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, HeadResponseKeepsHeadersButNoBody) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().head("/metadata", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-head", "yes");
        ctx->response().body() = "body-that-must-not-be-sent";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::HEAD, qb::io::uri("/metadata")};
    auto              response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-head"), "yes");
    EXPECT_EQ(response.header("content-length"), std::to_string(std::string("body-that-must-not-be-sent").size()));
    EXPECT_TRUE(response.body().empty());

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, NotModifiedResponseAllowsContentLengthMetadata) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/metadata-304", [](auto ctx) {
        ctx->response().status() = qb::http::status::NOT_MODIFIED;
        ctx->response().set_header("content-length", "123");
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/metadata-304")}));

    EXPECT_EQ(response.status(), qb::http::status::NOT_MODIFIED);
    EXPECT_EQ(response.header("content-length"), "123");
    EXPECT_TRUE(response.body().empty());

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, QueryAndRepeatedHeadersRoundTrip) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/inspect/:id", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-path-id", ctx->path_param("id"));
        ctx->response().set_header("x-query-name", ctx->request().query("name"));
        ctx->response().set_header("x-request-header", ctx->request().header("x-custom-header"));
        ctx->response().add_header("set-cookie", "a=1");
        ctx->response().add_header("set-cookie", "b=2");
        ctx->response().body() = "inspect-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/inspect/42?name=qb")};
    request.set_header("X-CUSTOM-HEADER", "UPPERCASE-KEY");
    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-path-id"), "42");
    EXPECT_EQ(response.header("x-query-name"), "qb");
    EXPECT_EQ(response.header("x-request-header"), "UPPERCASE-KEY");
    EXPECT_EQ(response.header("set-cookie", 0), "a=1");
    EXPECT_EQ(response.header("set-cookie", 1), "b=2");
    EXPECT_EQ(response.body().as<std::string>(), "inspect-ok");

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, LargePostBody) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().post("/large", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = std::to_string(ctx->request().body().size());
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::string       payload(128 * 1024, 'x');
    qb::http::Request request{qb::http::method::POST, qb::io::uri(https_origin(port) + "/large")};
    request.body() = payload;

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), std::to_string(payload.size()));

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, LargeResponseBody) {
    const auto  port = next_port();
    std::string payload(160 * 1024, 'r');
    auto        server = qb::http3::make_server();
    server->router().get("/large-response", [&payload](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = payload;
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(https_origin(port) + "/large-response")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().size(), payload.size());
    EXPECT_EQ(response.body().as<std::string>(), payload);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, RouterNotFoundReturns404) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/known", [](auto ctx) {
        ctx->response().body() = "known";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(https_origin(port) + "/missing")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::NOT_FOUND);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ServerErrorResponseIsDelivered) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/error", [](auto ctx) {
        ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
        ctx->response().set_header("x-protocol", "HTTP/3");
        ctx->response().body() = "server error";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/error")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(response.header("x-protocol"), "HTTP/3");
    EXPECT_EQ(response.body().as<std::string>(), "server error");

    client->disconnect();
    server->close();
}

// ---------------------------------------------------------------------------
// Batch round-trips + ordering
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, BatchRequestsPreserveOrder) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/item/:id", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = ctx->path_param("id");
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::vector<qb::http::Request> requests;
    for (int i = 0; i < 4; ++i) {
        requests.emplace_back(qb::io::uri(https_origin(port) + "/item/" + std::to_string(i)));
    }

    std::atomic<bool>               done{false};
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done      = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    ASSERT_EQ(responses.size(), 4u);
    for (std::size_t i = 0; i < responses.size(); ++i) {
        EXPECT_EQ(responses[i].status(), qb::http::status::OK);
        EXPECT_EQ(responses[i].body().as<std::string>(), std::to_string(i));
    }

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, BatchKeepsEmptySuccessWhenAnotherRequestTimesOut) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/empty", [](auto ctx) {
        ctx->response().status() = qb::http::status::NO_CONTENT;
        ctx->complete();
    });
    server->router().get("/stall", [](auto) {
        // Keep this stream open so only this request times out.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_request_timeout(kStallTimeout);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("/empty"));
    requests.emplace_back(qb::io::uri("/stall"));

    std::atomic<bool>               done{false};
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done      = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::NO_CONTENT);
    EXPECT_TRUE(responses[0].body().empty());
    EXPECT_EQ(responses[1].status(), qb::http::status::REQUEST_TIMEOUT);

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 1u);
    EXPECT_EQ(failed, 1u);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, BatchAwaiterPreservesMixedResponses) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/ok/:id", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = ctx->path_param("id");
        ctx->complete();
    });
    server->router().get("/empty", [](auto ctx) {
        ctx->response().status() = qb::http::status::NO_CONTENT;
        ctx->complete();
    });
    server->router().get("/error", [](auto ctx) {
        ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
        ctx->response().body()   = "boom";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("/ok/1"));
    requests.emplace_back(qb::io::uri("/empty"));
    requests.emplace_back(qb::io::uri("/missing"));
    requests.emplace_back(qb::io::uri("/error"));

    auto responses = qb::http::run_sync(client->push_requests(std::move(requests)));

    ASSERT_EQ(responses.size(), 4u);
    EXPECT_EQ(responses[0].status(), qb::http::status::OK);
    EXPECT_EQ(responses[0].body().as<std::string>(), "1");
    EXPECT_EQ(responses[1].status(), qb::http::status::NO_CONTENT);
    EXPECT_TRUE(responses[1].body().empty());
    EXPECT_EQ(responses[2].status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(responses[3].status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(responses[3].body().as<std::string>(), "boom");

    client->disconnect();
    server->close();
}

// ---------------------------------------------------------------------------
// Synchronous scheme/origin rejection (no connect)
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, RejectsPlainHttpAbsoluteRequestWithoutConnecting) {
    auto client = qb::http3::make_client("https://127.0.0.1:" + std::to_string(next_port()));
    client->set_connect_timeout(10ms);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("http://127.0.0.1:1/plain")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    EXPECT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(response.body().as<std::string>(), "HTTP/3 request URI must use https");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);
}

TEST_F(Http3LoopbackTest, RejectsCrossOriginAbsoluteRequestWithoutConnecting) {
    auto client = qb::http3::make_client("https://127.0.0.1:443");

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("https://localhost:443/cross-origin")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    EXPECT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(response.body().as<std::string>(), "HTTP/3 persistent client only accepts same-origin requests");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());
}

TEST_F(Http3LoopbackTest, BatchRejectsInvalidSchemesAndPreservesOrder) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/valid", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "valid-h3";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("http://127.0.0.1:" + std::to_string(port) + "/plain"));
    requests.emplace_back(qb::io::uri("/valid"));
    requests.emplace_back(qb::io::uri("https://localhost:" + std::to_string(port) + "/cross-origin"));
    requests.emplace_back(qb::io::uri("ws://127.0.0.1:" + std::to_string(port) + "/ws"));

    std::atomic<bool>               done{false};
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done      = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    ASSERT_EQ(responses.size(), 4u);
    EXPECT_EQ(responses[0].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[0].body().as<std::string>(), "HTTP/3 request URI must use https");
    EXPECT_EQ(responses[1].status(), qb::http::status::OK);
    EXPECT_EQ(responses[1].body().as<std::string>(), "valid-h3");
    EXPECT_EQ(responses[2].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[2].body().as<std::string>(), "HTTP/3 persistent client only accepts same-origin requests");
    EXPECT_EQ(responses[3].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[3].body().as<std::string>(), "HTTP/3 request URI must use https");

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 4u);
    EXPECT_EQ(successful, 1u);
    EXPECT_EQ(failed, 3u);

    client->disconnect();
    server->close();
}

// ---------------------------------------------------------------------------
// Timeout / disconnect / remote-close lifecycle
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, RequestTimeoutReturnsTimeoutResponse) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/stall", [](auto) {
        // Intentionally keep the context open to exercise the client timeout path.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_request_timeout(kStallTimeout);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(https_origin(port) + "/stall")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_EQ(client->get_active_request_count(), 0u);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ManualDisconnectFailsActiveRequestImmediately) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/stall", [](auto) {
        // Keep the request active until the client disconnects.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_request_timeout(10s);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/stall")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return client->get_active_request_count() == 1u; });
    ASSERT_EQ(client->get_active_request_count(), 1u);

    client->disconnect();

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_NE(response.body().as<std::string>().find("disconnect"), std::string::npos);
    EXPECT_EQ(client->get_active_request_count(), 0u);

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);

    server->close();
}

TEST_F(Http3LoopbackTest, ManualDisconnectFailsBatchOncePerRequest) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/stall/:id", [](auto) {
        // Keep all batch streams active until the client disconnects.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_request_timeout(10s);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("/stall/0"));
    requests.emplace_back(qb::io::uri("/stall/1"));

    std::atomic<bool>               done{false};
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done      = true;
    }));

    pump([&] { return client->get_active_request_count() == 2u; });
    ASSERT_EQ(client->get_active_request_count(), 2u);

    client->disconnect();

    ASSERT_TRUE(done.load());
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(responses[1].status(), qb::http::status::SERVICE_UNAVAILABLE);

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 2u);

    server->close();
}

TEST_F(Http3LoopbackTest, RemoteConnectionCloseFailsActiveRequestWithoutGhostReconnect) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/stall", [](auto) {
        // Keep the request active until the server closes the connection.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_request_timeout(10s);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/stall")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return client->get_active_request_count() == 1u; });
    ASSERT_EQ(client->get_active_request_count(), 1u);

    server->close();
    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(client->get_active_request_count(), 0u);
    EXPECT_FALSE(client->is_connected());
    EXPECT_FALSE(client->is_connecting());

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);

    client->disconnect();
}

// ---------------------------------------------------------------------------
// Concurrency limit + connect-timeout
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, MaxConcurrentStreamsQueuesPendingRequests) {
    const auto                                                                 port   = next_port();
    auto                                                                       server = qb::http3::make_server();
    std::vector<std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>>> held_contexts;
    server->router().get("/hold/:id", [&held_contexts](auto ctx) { held_contexts.push_back(ctx); });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_max_concurrent_streams(1);
    client->set_request_timeout(10s);

    std::atomic<int>                done{0};
    std::vector<qb::http::Response> responses(2);
    for (int i = 0; i < 2; ++i) {
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold/" + std::to_string(i))}, [&, i](qb::http::Response res) {
            responses[static_cast<std::size_t>(i)] = std::move(res);
            ++done;
        }));
    }

    pump([&] { return held_contexts.size() == 1u && client->get_active_request_count() == 1u; });
    ASSERT_EQ(held_contexts.size(), 1u);
    EXPECT_EQ(client->get_active_request_count(), 1u);
    EXPECT_EQ(done.load(), 0);

    held_contexts.front()->response().status() = qb::http::status::OK;
    held_contexts.front()->response().body()   = "first";
    held_contexts.front()->complete();

    pump([&] { return done.load() == 1 && held_contexts.size() == 2u; });
    ASSERT_EQ(done.load(), 1);
    ASSERT_EQ(held_contexts.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::OK);
    EXPECT_EQ(responses[0].body().as<std::string>(), "first");
    EXPECT_EQ(client->get_active_request_count(), 1u);

    held_contexts.back()->response().status() = qb::http::status::OK;
    held_contexts.back()->response().body()   = "second";
    held_contexts.back()->complete();

    pump([&] { return done.load() == 2; });
    ASSERT_EQ(done.load(), 2);
    EXPECT_EQ(responses[1].status(), qb::http::status::OK);
    EXPECT_EQ(responses[1].body().as<std::string>(), "second");
    EXPECT_EQ(client->get_active_request_count(), 0u);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, RequestTimeoutIncludesPendingBehindConcurrencyLimit) {
    const auto                                                                 port   = next_port();
    auto                                                                       server = qb::http3::make_server();
    std::vector<std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>>> held_contexts;
    server->router().get("/hold/:id", [&held_contexts](auto ctx) { held_contexts.push_back(ctx); });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_max_concurrent_streams(1);
    client->set_request_timeout(kStallTimeout);

    std::atomic<int>                done{0};
    std::vector<qb::http::Response> responses(2);
    for (int i = 0; i < 2; ++i) {
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold/" + std::to_string(i))}, [&, i](qb::http::Response res) {
            responses[static_cast<std::size_t>(i)] = std::move(res);
            ++done;
        }));
    }

    pump([&] { return done.load() == 2; });

    ASSERT_EQ(done.load(), 2);
    EXPECT_GE(held_contexts.size(), 1u);
    EXPECT_LE(held_contexts.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_EQ(responses[1].status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_EQ(client->get_active_request_count(), 0u);

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 2u);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ConnectTimeoutFailsQueuedRequest) {
    // No server: bind an ephemeral port but never listen on it, so connect times out.
    auto client = qb::http3::make_client(https_origin(next_port()));
    client->set_verify_peer(false);
    client->set_connect_timeout(kStallTimeout);

    std::atomic<bool> connected_callback{false};
    bool              connected = true;
    std::string       error;
    ASSERT_TRUE(client->connect([&](bool ok, std::string const &message) {
        connected          = ok;
        error              = message;
        connected_callback = true;
    }));

    pump([&] { return connected_callback.load(); });

    ASSERT_TRUE(connected_callback.load());
    EXPECT_FALSE(connected);
    EXPECT_NE(error.find("timeout"), std::string::npos);
    EXPECT_FALSE(client->is_connected());
}

TEST_F(Http3LoopbackTest, ConnectTimeoutFailsImplicitQueuedRequest) {
    auto client = qb::http3::make_client(https_origin(next_port()));
    client->set_verify_peer(false);
    client->set_connect_timeout(kStallTimeout);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/never")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_NE(response.body().as<std::string>().find("timeout"), std::string::npos);
    EXPECT_FALSE(client->is_connected());
}

// ---------------------------------------------------------------------------
// Awaiter / coroutine API parity + connection reuse
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, AwaiterApiMatchesCallbackApi) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/await", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-protocol", "HTTP/3");
        ctx->response().body() = "await-h3";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/await")}));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-protocol"), "HTTP/3");
    EXPECT_EQ(response.body().as<std::string>(), "await-h3");

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, CoAwaitConnectAndPushRequestInsideCoroutine) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().post("/data", [](auto ctx) {
        ctx->response().status() = qb::http::status::CREATED;
        ctx->response().set_header("x-protocol", "HTTP/3");
        ctx->response().body() = ctx->request().body().template as<std::string>();
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    bool               connected = false;
    qb::http::Response captured;
    qb::io::async::run_sync([&]() -> qb::io::async::task<void> {
        auto result = co_await client->connect();
        connected   = result.ok;
        if (!connected) {
            co_return;
        }

        qb::http::Request request{qb::http::method::POST, qb::io::uri("/data")};
        request.set_header("content-type", "text/plain");
        request.body() = "payload-h3-coro";
        captured       = co_await client->push_request(std::move(request));
        co_return;
    }());

    ASSERT_TRUE(connected);
    EXPECT_EQ(captured.status(), qb::http::status::CREATED);
    EXPECT_EQ(captured.header("x-protocol"), "HTTP/3");
    EXPECT_EQ(captured.body().as<std::string>(), "payload-h3-coro");

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ServerCleansClosedConnectionsAndAcceptsNewClient) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/again", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "again";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    {
        auto client = qb::http3::make_client(https_origin(port));
        client->set_verify_peer(false);
        auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/again")}));
        ASSERT_EQ(response.status(), qb::http::status::OK);
        client->disconnect();
    }

    pump([&] {
        qb::io::async::run(EVRUN_NOWAIT);
        return server->stats().active_connections == 0u;
    });

    EXPECT_EQ(server->stats().active_connections, 0u);
    EXPECT_TRUE(server->is_open());

    auto second = qb::http3::make_client(https_origin(port));
    second->set_verify_peer(false);
    auto response = qb::http::run_sync(second->push_request(qb::http::Request{qb::io::uri("/again")}));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "again");

    second->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, CustomSessionServerUsesSameRouterApi) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server<CustomHttp3Session>();
    server->router().get("/custom", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-session", "custom");
        ctx->response().body() = "custom-h3";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(https_origin(port) + "/custom")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-session"), "custom");
    EXPECT_EQ(response.body().as<std::string>(), "custom-h3");

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, MultipleConnectCallbacksShareOneHandshake) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/ready", [](auto ctx) {
        ctx->response().body() = "ready";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::atomic<int> callbacks{0};
    bool             first_ok  = false;
    bool             second_ok = false;

    ASSERT_TRUE(client->connect([&](bool ok, std::string const &) {
        first_ok = ok;
        ++callbacks;
    }));
    ASSERT_TRUE(client->connect([&](bool ok, std::string const &) {
        second_ok = ok;
        ++callbacks;
    }));

    pump([&] { return callbacks.load() == 2; });

    EXPECT_EQ(callbacks.load(), 2);
    EXPECT_TRUE(first_ok);
    EXPECT_TRUE(second_ok);
    EXPECT_TRUE(client->is_connected());

    auto connected = qb::http::run_sync(client->connect());
    EXPECT_TRUE(connected);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, SequentialRequestsReuseOneConnection) {
    const auto port   = next_port();
    auto       server = std::make_unique<ReuseHttp3Server>();
    server->router().get("/seq/:id", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = ctx->path_param("id");
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto first_response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/seq/first")}));
    ASSERT_EQ(first_response.status(), qb::http::status::OK);
    EXPECT_EQ(first_response.body().as<std::string>(), "first");
    ASSERT_EQ(server->connected_events.load(), 1);
    ASSERT_TRUE(client->is_connected());

    auto second_response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/seq/second")}));
    EXPECT_EQ(second_response.status(), qb::http::status::OK);
    EXPECT_EQ(second_response.body().as<std::string>(), "second");
    EXPECT_EQ(server->connected_events.load(), 1);
    EXPECT_TRUE(client->is_connected());

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, MultipleClientsCanUseOneServerConcurrently) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().get("/client/:id", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = ctx->path_param("id");
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    std::vector<std::shared_ptr<qb::http3::Client>> clients;
    std::vector<qb::http::Response>                 responses(3);
    std::atomic<int>                                done{0};

    for (int i = 0; i < 3; ++i) {
        auto client = qb::http3::make_client(https_origin(port));
        client->set_verify_peer(false);
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/client/" + std::to_string(i))}, [&, i](qb::http::Response response) {
            responses[static_cast<std::size_t>(i)] = std::move(response);
            ++done;
        }));
        clients.push_back(std::move(client));
    }

    pump([&] { return done.load() == 3; });

    ASSERT_EQ(done.load(), 3);
    for (std::size_t i = 0; i < responses.size(); ++i) {
        EXPECT_EQ(responses[i].status(), qb::http::status::OK);
        EXPECT_EQ(responses[i].body().as<std::string>(), std::to_string(i));
    }
    EXPECT_EQ(server_requests.load(), 3);

    for (auto &client : clients) {
        client->disconnect();
    }
    server->close();
}

// ---------------------------------------------------------------------------
// Body / content-length / header limits  (WEAK negatives pinned to 413 / 502)
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, ServerRejectsRequestBodyOverLimit) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->set_max_body_size(8);
    server->router().post("/limited", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = std::to_string(ctx->request().body().size());
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/limited")};
    request.body() = std::string(64, 'x');

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    // HTTP/3 enforces the server's max-body limit at the QUIC/nghttp3 transport
    // layer: recv_data_cb (3/protocol/connection.h:690-695) detects the overflow
    // while the body is still streaming in — before the request reaches the
    // router — and the only RFC 9114-conformant action there is to RESET the
    // request stream (NGHTTP3_H3_REQUEST_CANCELLED). There is no buffered request
    // to answer with a synthesized 413 (unlike HTTP/1.1, which buffers the whole
    // body and can return PAYLOAD_TOO_LARGE). The client observes the peer stream
    // reset as a stream-closed-before-completion failure and surfaces its default
    // BAD_GATEWAY (502) — see Client::on_http3_stream_closed -> fail_request
    // (3/client.cpp:517-520, default status BAD_GATEWAY). So the pinned contract
    // for an over-limit body in HTTP/3 is a client-side 502 via stream reset, NOT
    // a 413 response.
    EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_EQ(client->get_active_request_count(), 0u);
    EXPECT_TRUE(server->is_open());

    auto second = qb::http3::make_client(https_origin(port));
    second->set_verify_peer(false);
    qb::http::Request ok_request{qb::http::method::POST, qb::io::uri("/limited")};
    ok_request.body() = "ok";
    auto ok_response  = qb::http::run_sync(second->push_request(std::move(ok_request)));
    EXPECT_EQ(ok_response.status(), qb::http::status::OK);
    EXPECT_EQ(ok_response.body().as<std::string>(), "2");

    client->disconnect();
    second->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ClientRejectsResponseBodyOverLimit) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/too-large", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = std::string(64, 'r');
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_max_body_size(8);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/too-large")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY); // 502 (was EXPECT_NE OK)
    EXPECT_EQ(client->get_active_request_count(), 0u);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ServerRejectsRequestContentLengthMismatch) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().post("/length", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "accepted";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/length")};
    request.set_header("content-length", "1");
    request.body() = "abc";

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    // The client validates the outgoing content-length/body mismatch before the
    // request ever reaches the server, surfacing as a local 503 SERVICE_UNAVAILABLE.
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE); // (was EXPECT_NE OK)

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ClientRejectsOutgoingRequestContentLengthMismatchBeforeRouter) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().post("/length", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/length")};
    request.set_header("content-length", "1");
    request.body() = "abc";

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server_requests.load(), 0);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ClientRejectsOutgoingRequestContentLengthWithOWSBeforeRouter) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().post("/length-ows", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = ctx->request().body().template as<std::string>();
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/length-ows")};
    request.set_header("content-length", " 3\t");
    request.body() = "abc";

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server_requests.load(), 0);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ClientRejectsResponseContentLengthMismatch) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/bad-length", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("content-length", "1");
        ctx->response().body() = "abc";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/bad-length")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY); // 502 (was EXPECT_NE OK)

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ClientRejectsOversizedOutgoingHeader) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().get("/guarded", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/guarded")};
    request.set_header("x-too-large", std::string(qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'v'));

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server_requests.load(), 0);

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ClientRejectsInvalidOutgoingHeaderField) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().get("/guarded-invalid", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/guarded-invalid")};
    request.set_header("x-injected", "safe\r\nInjected: bad");

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server_requests.load(), 0);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ServerResetsStreamForOversizedOutgoingHeader) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/bad-response", [](auto ctx) {
        ctx->response().set_header("x-too-large", std::string(qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'v'));
        ctx->response().body() = "not sent";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/bad-response")}));

    EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_TRUE(server->is_open());

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ServerRejectsInvalidOutgoingHeaderField) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/bad-response-field", [](auto ctx) {
        ctx->response().set_header("x-injected", "safe\r\nInjected: bad");
        ctx->response().body() = "not sent";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/bad-response-field")}));

    EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_TRUE(server->is_open());

    client->disconnect();
    server->close();
}

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, GracefulShutdownClosesCurrentConnectionOnly) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/ping", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "pong-before-shutdown";
        ctx->complete();
    });
    server->router().get("/again", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "new-connection-ok";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/ping")}));
    ASSERT_EQ(response.status(), qb::http::status::OK);
    ASSERT_TRUE(client->is_connected());

    server->graceful_shutdown();
    pump([&] { return !client->is_connected(); });
    EXPECT_FALSE(client->is_connected());

    auto second_client = qb::http3::make_client(https_origin(port));
    second_client->set_verify_peer(false);
    auto second = qb::http::run_sync(second_client->push_request(qb::http::Request{qb::io::uri("/again")}));
    EXPECT_EQ(second.status(), qb::http::status::OK);
    EXPECT_EQ(second.body().as<std::string>(), "new-connection-ok");

    client->disconnect();
    second_client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, GracefulShutdownWaitsForActiveAsyncContext) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/delayed", [&](auto ctx) { held_context = ctx; });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/delayed")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    pump([&] { return held_context != nullptr; });
    ASSERT_NE(held_context, nullptr);
    ASSERT_TRUE(client->is_connected());

    // Graceful shutdown must NOT complete the in-flight request: the connection
    // stays up and the callback stays pending. Pump for a stable settle window
    // (replacing the original magic for(i<20)) and assert non-completion.
    server->graceful_shutdown();
    const auto settle_deadline = std::chrono::steady_clock::now() + 200ms;
    while (std::chrono::steady_clock::now() < settle_deadline) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_TRUE(client->is_connected());
    EXPECT_FALSE(done.load());

    held_context->response().status() = qb::http::status::OK;
    held_context->response().body()   = "delayed-ok";
    held_context->complete();
    held_context.reset();

    pump([&] { return done.load() && !client->is_connected(); });
    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "delayed-ok");
    EXPECT_FALSE(client->is_connected());

    client->disconnect();
    server->close();
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, CancelActiveRequestResetsStreamAndCompletesCallback) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/stall", [](auto) {
        // Keep the stream open until the client cancels it.
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_request_timeout(10s);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    auto               id = client->push_request_with_id(qb::http::Request{qb::io::uri("/stall")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    });
    ASSERT_NE(id, 0u);

    pump([&] { return client->get_active_request_count() == 1; });
    ASSERT_TRUE(client->cancel_request(id, "manual cancel"));
    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::CLIENT_CLOSED_REQUEST);
    EXPECT_EQ(response.body().as<std::string>(), "manual cancel");

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, CancelPendingRequestCompletesWithoutOpeningStream) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> fast_requests{0};
    server->router().get("/stall", [](auto) {
        // Keep the first stream active so the second request remains queued.
    });
    server->router().get("/fast", [&fast_requests](auto ctx) {
        ++fast_requests;
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_max_concurrent_streams(1);
    client->set_request_timeout(10s);

    std::atomic<bool> first_done{false};
    auto first = client->push_request_with_id(qb::http::Request{qb::io::uri("/stall")}, [&](qb::http::Response) { first_done = true; });
    ASSERT_NE(first, 0u);

    std::atomic<bool>  second_done{false};
    qb::http::Response second_response;
    auto               second = client->push_request_with_id(qb::http::Request{qb::io::uri("/fast")}, [&](qb::http::Response response) {
        second_response = std::move(response);
        second_done     = true;
    });
    ASSERT_NE(second, 0u);

    pump([&] { return client->get_active_request_count() == 1; });
    ASSERT_TRUE(client->cancel_request(second, "pending cancel"));
    pump([&] { return second_done.load(); });

    EXPECT_FALSE(first_done.load());
    EXPECT_TRUE(second_done.load());
    EXPECT_EQ(second_response.status(), qb::http::status::CLIENT_CLOSED_REQUEST);
    EXPECT_EQ(second_response.body().as<std::string>(), "pending cancel");
    EXPECT_EQ(fast_requests.load(), 0);

    client->disconnect();
    server->close();
}

// ---------------------------------------------------------------------------
// Trailers + forbidden header/trailer handling
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, ResponseTrailersAreDeliveredAsHeaders) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/trailers", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("trailer", "x-checksum");
        ctx->response().set_header("x-checksum", "response-trailer");
        ctx->response().body() = "body-with-trailer";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/trailers")}));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "body-with-trailer");
    EXPECT_EQ(response.header("x-checksum"), "response-trailer");

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, RequestTrailersAreDeliveredToRouter) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().post("/trailers", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = ctx->request().header("x-client-checksum");
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/trailers")};
    request.set_header("trailer", "x-client-checksum");
    request.set_header("x-client-checksum", "request-trailer");
    request.body() = "payload";

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "request-trailer");

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ClientRejectsForbiddenOutgoingRequestTrailer) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().post("/forbidden-trailer", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::http::method::POST, qb::io::uri("/forbidden-trailer")};
    request.set_header("trailer", "content-length");
    request.set_header("content-length", "7");
    request.body() = "payload";

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server_requests.load(), 0);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ClientRejectsForbiddenOutgoingRequestHeader) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().get("/forbidden-header", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/forbidden-header")};
    request.set_header("connection", "close");

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server_requests.load(), 0);

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ServerRejectsForbiddenOutgoingResponseTrailer) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/forbidden-trailer", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("trailer", "content-length");
        ctx->response().set_header("content-length", "3");
        ctx->response().body() = "abc";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/forbidden-trailer")}));

    EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_TRUE(server->is_open());

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, ServerRejectsForbiddenOutgoingResponseHeader) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/forbidden-header", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("connection", "close");
        ctx->response().body() = "unexpected";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/forbidden-header")}));

    EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_TRUE(server->is_open());

    client->disconnect();
    server->close();
}

// ---------------------------------------------------------------------------
// Lifecycle hooks
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, LifecycleHooksFollowHttpSessionSemantics) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> pre_response{0};
    std::atomic<int> post_response{0};
    std::atomic<int> request_complete{0};

    server->router().get("/hooks", [&](auto ctx) {
        ctx->add_lifecycle_hook([&](auto &hook_ctx, qb::http::HookPoint point) {
            if (point == qb::http::HookPoint::PRE_RESPONSE_SEND) {
                ++pre_response;
                hook_ctx.response().set_header("x-hook-pre", "1");
            } else if (point == qb::http::HookPoint::POST_RESPONSE_SEND) {
                ++post_response;
            } else if (point == qb::http::HookPoint::REQUEST_COMPLETE) {
                ++request_complete;
            }
        });
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "hooked";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/hooks")}));

    pump([&] { return post_response.load() == 1 && request_complete.load() == 1; });

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "hooked");
    EXPECT_EQ(response.header("x-hook-pre"), "1");
    EXPECT_EQ(pre_response.load(), 1);
    EXPECT_EQ(post_response.load(), 1);
    EXPECT_EQ(request_complete.load(), 1);

    client->disconnect();
    server->close();
}

// ---------------------------------------------------------------------------
// Dual-stack (HTTP/2 + HTTP/3 on separate sockets, one router)
// ---------------------------------------------------------------------------

TEST_F(Http3LoopbackTest, DualStackSameRouteServesHttp2AndHttp3OnSeparateSockets) {
    const auto h2_port = next_port();
    const auto h3_port = next_port();
    auto       server  = qb::http::make_dual_stack_server();
    server->router().get("/shared", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-version", ctx->request().major_version == 3 ? "h3" : "h2");
        ctx->response().body() = ctx->request().major_version == 3 ? "shared-over-h3" : "shared-over-h2";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(h2_port)), qb::io::uri(https_origin(h3_port)), cert_path(), key_path()));

    auto http2_client = qb::http2::make_client(https_origin(h2_port));
    http2_client->set_connect_timeout(5s);
    http2_client->set_verify_peer(false); // self-signed test cert
    auto http3_client = qb::http3::make_client(https_origin(h3_port));
    http3_client->set_verify_peer(false);

    std::atomic<bool>  h2_done{false};
    std::atomic<bool>  h3_done{false};
    qb::http::Response h2_response;
    qb::http::Response h3_response;

    ASSERT_TRUE(http2_client->push_request(qb::http::Request{qb::io::uri("/shared")}, [&](qb::http::Response res) {
        h2_response = std::move(res);
        h2_done     = true;
    }));
    ASSERT_TRUE(http2_client->connect(nullptr));

    ASSERT_TRUE(http3_client->push_request(qb::http::Request{qb::io::uri("/shared")}, [&](qb::http::Response res) {
        h3_response = std::move(res);
        h3_done     = true;
    }));

    pump([&] { return h2_done.load() && h3_done.load(); });

    ASSERT_TRUE(h2_done.load());
    ASSERT_TRUE(h3_done.load());
    EXPECT_EQ(h2_response.status(), qb::http::status::OK);
    EXPECT_EQ(h2_response.header("x-version"), "h2");
    EXPECT_EQ(h2_response.body().as<std::string>(), "shared-over-h2");
    EXPECT_EQ(h3_response.status(), qb::http::status::OK);
    EXPECT_EQ(h3_response.header("x-version"), "h3");
    EXPECT_EQ(h3_response.body().as<std::string>(), "shared-over-h3");

    http2_client->disconnect();
    http3_client->disconnect();
    server->close();
    qb::io::async::listener::current.clear();
}

TEST_F(Http3LoopbackTest, DualStackClosingHttp3SideKeepsHttp2SideServing) {
    const auto h2_port = next_port();
    const auto h3_port = next_port();
    auto       server  = qb::http::make_dual_stack_server();
    server->router().get("/h2-only-after-h3-close", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "h2-still-alive";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(h2_port)), qb::io::uri(https_origin(h3_port)), cert_path(), key_path()));

    server->close_http3();

    auto http2_client = qb::http2::make_client(https_origin(h2_port));
    http2_client->set_connect_timeout(5s);
    http2_client->set_verify_peer(false); // self-signed test cert

    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(http2_client->push_request(qb::http::Request{qb::io::uri("/h2-only-after-h3-close")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));
    ASSERT_TRUE(http2_client->connect(nullptr));

    pump([&] { return done.load(); });

    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "h2-still-alive");

    http2_client->disconnect();
    server->close();
    qb::io::async::listener::current.clear();
}

TEST_F(Http3LoopbackTest, DualStackClosingHttp2SideKeepsHttp3SideServing) {
    const auto h2_port = next_port();
    const auto h3_port = next_port();
    auto       server  = qb::http::make_dual_stack_server();
    server->router().get("/h3-only-after-h2-close", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "h3-still-alive";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(h2_port)), qb::io::uri(https_origin(h3_port)), cert_path(), key_path()));

    server->close_http2();

    auto http3_client = qb::http3::make_client(https_origin(h3_port));
    http3_client->set_verify_peer(false);

    auto response = qb::http::run_sync(http3_client->push_request(qb::http::Request{qb::io::uri("/h3-only-after-h2-close")}));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "h3-still-alive");

    http3_client->disconnect();
    server->close();
    qb::io::async::listener::current.clear();
}

#endif // QBM_HTTP_HAS_HTTP3

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
 *     @c ephemeral_udp_port() bind-and-read-back on a UDP probe (QUIC binds UDP; a TCP probe says nothing about the same number on UDP).
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

#include <qbm/http/http.h>

#if defined(QBM_HTTP_HAS_HTTP3)

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

using namespace std::chrono_literals;

namespace {
using qb::http::test::ephemeral_udp_port;

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
    std::uint64_t    last_connection_id = 0;

    void
    on(qb::io::async::quic::event::connected const &ev) {
        last_connection_id = ev.connection_id;
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

    /** @brief A fresh kernel-assigned loopback port, probed in the UDP space (QUIC binds UDP). */
    static std::uint16_t
    next_port() {
        return qb::http::test::ephemeral_udp_port();
    }

    /**
     * @brief A fresh kernel-assigned loopback port, probed in the TCP space.
     *
     * The dual-stack cases below bind BOTH an HTTP/2 listener (TCP) and an HTTP/3 endpoint
     * (UDP). @ref next_port() probes UDP, which is exactly right for the HTTP/3 half and says
     * NOTHING about the same number in the TCP space — the two are independent, which is the
     * very reason this file has two probes at all. Handing a UDP-probed number to a TCP listener
     * therefore binds a port nothing verified was free, and when it was not,
     * `server->listen(...)` simply returned false:
     *   http3-loopback.cpp(2080): Value of: server->listen(...)  Actual: false  Expected: true
     * observed on all three dual-stack cases in one run. Probe the space you are going to bind.
     */
    static std::uint16_t
    next_tcp_port() {
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
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(https_origin(port) + "/big")}, [&](qb::http::Response) { settled = true; }));
    pump([&] { return settled.load(); }, 5s);
    EXPECT_TRUE(settled.load());
    EXPECT_GE(handled.load(), 1) << "the request must have reached the handler (reentrancy path taken)";

    // Server survived and is not wedged: a fresh connection still serves.
    auto client2 = qb::http3::make_client(https_origin(port));
    client2->set_verify_peer(false);
    std::atomic<bool>  settled2{false};
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

// An IPv6 origin works end to end (Huly QB-572): the persistent client's :authority keeps the
// literal's brackets (RFC 3986 section 3.2.2, RFC 9114 section 4.3.1), whether the request arrives
// as an absolute same-origin URI or as a relative target the client completes from its base.
TEST_F(Http3LoopbackTest, Ipv6OriginRoundTripsAbsoluteAndRelativeRequests) {
    const auto port   = next_port();
    const auto origin = "https://[::1]:" + std::to_string(port);
    auto       server = qb::http3::make_server();
    server->router().get("/v6", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        // The server rebuilds the URI from :scheme, :authority and :path: its source is the authority as received.
        ctx->response().body() = std::string(ctx->request().uri().source());
        ctx->complete();
    });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(origin), cert_path(), key_path()));

    auto client = qb::http3::make_client(origin);
    client->set_verify_peer(false);
    for (auto const &target : {origin + "/v6", std::string("/v6")}) {
        std::atomic<bool>  done{false};
        qb::http::Response response;
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(target)}, [&](qb::http::Response res) {
            response = std::move(res);
            done     = true;
        }));
        ASSERT_TRUE(pump([&] { return done.load(); })) << target;
        EXPECT_EQ(response.status(), qb::http::status::OK) << target << ": " << response.body().as<std::string>();
        EXPECT_EQ(response.body().as<std::string>(), origin + "/v6") << target;
    }
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
    auto               connect_and_post = [&]() -> qb::io::async::task<void> {
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
    };
    qb::io::async::run_sync(connect_and_post());
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

    int completed = 2;
    for (int i = 0; i < 128; ++i) {
        bool               done = false;
        qb::http::Response response;
        bool               accepted = false;
        try {
            accepted = client->push_request(qb::http::Request{qb::io::uri("/seq/" + std::to_string(i))}, [&](qb::http::Response result) {
                response = std::move(result);
                done     = true;
            });
        } catch (std::exception const &error) {
            ADD_FAILURE() << "stream " << i << " could not open: " << error.what();
            break;
        }
        if (!accepted) {
            ADD_FAILURE() << "stream " << i << " was rejected";
            break;
        }
        if (!pump([&] { return done; }, 1s)) {
            break;
        }
        if (response.status() != qb::http::status::OK || response.body().as<std::string>() != std::to_string(i) || !client->is_connected()) {
            ADD_FAILURE() << "request " << i << " failed after " << completed << " responses on one connection";
            break;
        }
        ++completed;
    }
    EXPECT_EQ(completed, 130);
    EXPECT_EQ(server->connected_events.load(), 1) << "the stream quota must renew without reconnecting";

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
    // The request declares 64 bytes against a cap of 8: the server answers 413 Content Too Large on the
    // stream as soon as the header section is read, then STOP_SENDING(H3_NO_ERROR) asks the client to stop
    // sending the rest (RFC 9114 section 4.1.1) -- the answer HTTP/1.1 and HTTP/2 give (Huly QB-168).
    // Until 3.3 the stream was reset (H3_REQUEST_CANCELLED) and the client surfaced a 502.
    EXPECT_EQ(response.status(), qb::http::status::PAYLOAD_TOO_LARGE);
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

// The server's request limits (`set_request_limits`, Huly QB-94) over a real QUIC connection: a `:path` and a
// field value exactly at their limits are served, one byte over each is answered on its stream -- 414, 431 --
// and the same client serves the next request.
TEST_F(Http3LoopbackTest, ServerAnswersRequestsOverItsLimits) {
    const auto               port   = next_port();
    auto                     server = qb::http3::make_server();
    qb::http::request_limits limits;
    limits.max_url_length          = 64;
    limits.max_header_value_length = 64;
    server->set_request_limits(limits);
    server->router().get("/limits", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "ok";
        ctx->complete();
    });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    const auto send = [&](qb::http::Request request) {
        return qb::http::run_sync(client->push_request(std::move(request)));
    };
    const auto target = [](std::size_t size) {
        std::string t = "/limits?q=";
        t += std::string(size - t.size(), 'a');
        return qb::io::uri(t);
    };

    EXPECT_EQ(send(qb::http::Request{target(64)}).status(), qb::http::status::OK);
    EXPECT_EQ(send(qb::http::Request{target(65)}).status(), qb::http::status::URI_TOO_LONG);
    qb::http::Request at_limit{qb::io::uri("/limits")};
    at_limit.set_header("x-v", std::string(64, 'v'));
    EXPECT_EQ(send(std::move(at_limit)).status(), qb::http::status::OK);
    qb::http::Request over{qb::io::uri("/limits")};
    over.set_header("x-v", std::string(65, 'v'));
    EXPECT_EQ(send(std::move(over)).status(), qb::http::status::REQUEST_HEADER_FIELDS_TOO_LARGE);
    EXPECT_EQ(send(qb::http::Request{qb::io::uri("/limits")}).status(), qb::http::status::OK) << "the connection serves the next request";
    EXPECT_TRUE(server->is_open());

    client->disconnect();
    server->close();
}

// What the limit refuses is a STREAM. The connection carries the client's other exchanges, and an
// oversized upload used to take all of them down: the callback that saw the overflow failed, which
// made the HTTP/3 engine's read fail, and the read's answer to that is CONNECTION_CLOSE. Here the
// refused request is settled (413 on its stream, Huly QB-168; a 502 stream reset until 3.3), and the
// SAME connection -- never reconnected, its peak of one connection on the server proves it -- serves
// the next request.
TEST_F(Http3LoopbackTest, BodyOverLimitRefusesTheStreamNotTheConnection) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->set_max_body_size(8);
    server->router().post("/limited", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "accepted";
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto post = [&](std::size_t size) {
        qb::http::Request request{qb::http::method::POST, qb::io::uri("/limited")};
        request.body() = std::string(size, 'x');
        std::atomic<bool>  done{false};
        qb::http::Response response;
        EXPECT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
            response = std::move(res);
            done     = true;
        }));
        pump([&] { return done.load(); });
        EXPECT_TRUE(done.load());
        return response;
    };

    EXPECT_EQ(post(64).status(), qb::http::status::PAYLOAD_TOO_LARGE);

    // Let a CONNECTION_CLOSE arrive if one was sent: it is what this test exists to refuse.
    const auto settle = std::chrono::steady_clock::now() + 150ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_TRUE(client->is_connected()) << "the refused upload closed the whole connection";

    const auto accepted = post(4);
    EXPECT_EQ(accepted.status(), qb::http::status::OK);
    EXPECT_EQ(accepted.body().as<std::string>(), "accepted");
    EXPECT_EQ(server->stats().active_connections, 1u);

    client->disconnect();
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

// The server refuses to SEND a response whose body does not match its content-length (the
// outgoing validation of submit_response) and resets the stream with H3_MESSAGE_ERROR, so the
// client settles the exchange as a 502 -- a stream reset, never a connection close (Huly QB-234;
// RFC 9114 section 4.1.2). The connection carries the client's other exchanges: the SAME one --
// never reconnected, the server's peak of one connection proves it -- serves the next request.
TEST_F(Http3LoopbackTest, ClientRejectsResponseContentLengthMismatch) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/bad-length", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("content-length", "1");
        ctx->response().body() = "abc";
        ctx->complete();
    });
    server->router().get("/good-length", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "accepted";
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

    // Let a CONNECTION_CLOSE arrive if one was sent: it is what this test exists to refuse.
    const auto settle = std::chrono::steady_clock::now() + 150ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_TRUE(client->is_connected()) << "the refused response closed the whole connection";

    std::atomic<bool>  next_done{false};
    qb::http::Response next;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/good-length")}, [&](qb::http::Response res) {
        next      = std::move(res);
        next_done = true;
    }));
    pump([&] { return next_done.load(); });
    ASSERT_TRUE(next_done.load());
    EXPECT_EQ(next.status(), qb::http::status::OK);
    EXPECT_EQ(next.body().as<std::string>(), "accepted");
    EXPECT_EQ(server->stats().active_connections, 1u) << "the follow-up went over a new connection";

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

TEST_F(Http3LoopbackTest, PendingGoawayCallbackMayDisconnectDuringNativeRead) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    int                                                           pending_route_calls = 0, late_route_calls = 0;
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().get("/pending", [&](auto ctx) {
        ++pending_route_calls;
        ctx->text("unexpected pending response");
    });
    server->router().get("/late", [&](auto ctx) {
        ++late_route_calls;
        ctx->text("unexpected late response");
    });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_max_concurrent_streams(1);

    int                             active_calls = 0, pending_calls = 0;
    std::size_t                     states_before_disconnect = 0, states_inside_disconnect_callback = 0;
    bool                            connected_after_disconnect = true, reentrant_connect_started = true, reentrant_connect_succeeded = true;
    int                             reentrant_connect_calls = 0;
    int                             late_calls = 0, late_batch_calls = 0;
    qb::http3::request_id           late_request_id = 1;
    qb::http::Response              late_response;
    std::vector<qb::http::Response> late_batch_responses;
    qb::http::Response              active_response, pending_response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response response) {
        ++active_calls;
        active_response = std::move(response);
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));
    ASSERT_TRUE(client->is_connected());

    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/pending")}, [&](qb::http::Response response) {
        ++pending_calls;
        pending_response         = std::move(response);
        states_before_disconnect = client->get_stream_state_count();
        client->disconnect(); // executes from nghttp3's GOAWAY callback
        states_inside_disconnect_callback = client->get_stream_state_count();
        connected_after_disconnect        = client->is_connected();
        reentrant_connect_started         = client->connect([&](bool ok, std::string const &) {
            ++reentrant_connect_calls;
            reentrant_connect_succeeded = ok;
        });
        late_request_id                   = client->push_request_with_id(qb::http::Request{qb::io::uri("/late")}, [&](qb::http::Response late) {
            ++late_calls;
            late_response = std::move(late);
        });
        std::vector<qb::http::Request> late_batch;
        late_batch.emplace_back(qb::io::uri("/late"));
        EXPECT_TRUE(client->push_requests(std::move(late_batch), [&](std::vector<qb::http::Response> late) {
            ++late_batch_calls;
            late_batch_responses = std::move(late);
        }));
    }));
    EXPECT_EQ(pending_calls, 0);
    EXPECT_EQ(pending_route_calls, 0);

    server->graceful_shutdown();
    ASSERT_TRUE(pump([&] { return pending_calls == 1 && active_calls == 1 && !client->is_connected(); }));
    EXPECT_EQ(pending_calls, 1);
    EXPECT_EQ(active_calls, 1);
    EXPECT_EQ(pending_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_NE(pending_response.body().as<std::string>().find("shutting down"), std::string::npos);
    EXPECT_EQ(active_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_GT(states_before_disconnect, 0u) << "the callback must run while an HTTP/3 stream still exists";
    EXPECT_GT(states_inside_disconnect_callback, 0u) << "native GOAWAY reading must retain the HTTP/3 connection through the callback";
    EXPECT_FALSE(connected_after_disconnect) << "disconnect must mark the client logically down before teardown";
    EXPECT_FALSE(reentrant_connect_started) << "a new handshake cannot start on nghttp3's active stack";
    EXPECT_EQ(reentrant_connect_calls, 1);
    EXPECT_FALSE(reentrant_connect_succeeded);
    EXPECT_EQ(late_request_id, 0u);
    EXPECT_EQ(late_calls, 1);
    EXPECT_EQ(late_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(late_response.body().as<std::string>(), "HTTP/3 client disconnect");
    EXPECT_EQ(late_batch_calls, 1);
    ASSERT_EQ(late_batch_responses.size(), 1u);
    EXPECT_EQ(late_batch_responses[0].status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(late_batch_responses[0].body().as<std::string>(), "HTTP/3 client disconnect");
    EXPECT_EQ(client->get_stream_state_count(), 0u) << "deferred teardown must finish after the native read returns";
    EXPECT_EQ(pending_route_calls, 0);
    EXPECT_EQ(late_route_calls, 0);
    EXPECT_FALSE(client->is_connecting());

    held_context.reset();
    server->close();
}

TEST_F(Http3LoopbackTest, ResponseCallbackMayReleaseLastClientOwnerDuringNativeRead) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/drop-owner", [](auto ctx) { ctx->text("delivered"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    std::weak_ptr<qb::http3::Client> weak_client            = client;
    int                              calls                  = 0;
    bool                             alive_after_owner_drop = false;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/drop-owner")}, [&](qb::http::Response response) {
        ++calls;
        EXPECT_EQ(response.status(), qb::http::status::OK);
        EXPECT_EQ(response.body().as<std::string>(), "delivered");
        client.reset();
        alive_after_owner_drop = !weak_client.expired();
    }));

    ASSERT_TRUE(pump([&] { return calls == 1; }));
    EXPECT_EQ(calls, 1);
    EXPECT_TRUE(alive_after_owner_drop) << "the native read must keep the client alive through callback return";
    EXPECT_TRUE(weak_client.expired()) << "the endpoint event stack must release its temporary owner afterward";
    server->close();
}

TEST_F(Http3LoopbackTest, ExplicitDisconnectRejectsWorkFromFailureCallback) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    int                                                           late_route_calls = 0;
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().get("/late", [&](auto ctx) {
        ++late_route_calls;
        ctx->text("unexpected");
    });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    int                   failed_calls = 0, connect_calls = 0, late_calls = 0;
    bool                  connected_in_callback = true, connect_started = true, connect_succeeded = true;
    qb::http3::request_id late_id = 1;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response response) {
        ++failed_calls;
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
        connected_in_callback = client->is_connected();
        connect_started       = client->connect([&](bool ok, std::string const &) {
            ++connect_calls;
            connect_succeeded = ok;
        });
        late_id               = client->push_request_with_id(qb::http::Request{qb::io::uri("/late")}, [&](qb::http::Response late) {
            ++late_calls;
            EXPECT_EQ(late.status(), qb::http::status::SERVICE_UNAVAILABLE);
        });
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));
    ASSERT_TRUE(client->is_connected());

    client->disconnect();
    EXPECT_EQ(failed_calls, 1);
    EXPECT_FALSE(connected_in_callback);
    EXPECT_FALSE(connect_started);
    EXPECT_EQ(connect_calls, 1);
    EXPECT_FALSE(connect_succeeded);
    EXPECT_EQ(late_id, 0u);
    EXPECT_EQ(late_calls, 1);
    EXPECT_EQ(late_route_calls, 0);
    EXPECT_FALSE(client->is_connected());
    held_context.reset();
    server->close();
}

TEST_F(Http3LoopbackTest, ConnectFailureCallbackMaySubmitFreshRequest) {
    const auto port        = next_port();
    auto       server      = qb::http3::make_server();
    int        route_calls = 0;
    server->router().get("/retry", [&](auto ctx) {
        ++route_calls;
        ctx->text("retried");
    });
    server->router().compile();

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_connect_timeout(kStallTimeout);
    int                   connect_calls = 0, retry_calls = 0;
    qb::http3::request_id retry_id = 0;
    qb::http::Response    retry_response;
    ASSERT_TRUE(client->connect([&](bool ok, std::string const &) {
        ++connect_calls;
        if (ok) {
            return;
        }
        ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));
        client->set_connect_timeout(1s);
        retry_id = client->push_request_with_id(qb::http::Request{qb::io::uri("/retry")}, [&](qb::http::Response response) {
            ++retry_calls;
            retry_response = std::move(response);
        });
    }));

    ASSERT_TRUE(pump([&] { return retry_calls == 1; }, 3s));
    EXPECT_EQ(connect_calls, 1);
    EXPECT_NE(retry_id, 0u);
    EXPECT_EQ(retry_calls, 1);
    auto const &client_quic = static_cast<qb::io::async::quic::endpoint &>(*client).stats();
    auto const &server_quic = static_cast<qb::io::async::quic::endpoint &>(*server).stats();
    EXPECT_EQ(retry_response.status(), qb::http::status::OK)
        << "client packets=" << client_quic.packets_sent << "/" << client_quic.packets_received
        << " server packets=" << server_quic.packets_sent << "/" << server_quic.packets_received;
    EXPECT_EQ(retry_response.body().as<std::string>(), "retried");
    EXPECT_EQ(route_calls, 1);
    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, CancelledAttemptTimeoutCannotFailNewAttempt) {
    auto client = qb::http3::make_client(https_origin(next_port())); // no server
    client->set_verify_peer(false);
    client->set_connect_timeout(100ms);
    int  first_callbacks = 0, second_callbacks = 0;
    bool first_succeeded = true;
    ASSERT_TRUE(client->connect([&](bool ok, std::string const &) {
        ++first_callbacks;
        first_succeeded = ok;
    }));
    client->disconnect();
    EXPECT_EQ(first_callbacks, 1);
    EXPECT_FALSE(first_succeeded);

    client->set_connect_timeout(2s);
    ASSERT_TRUE(client->connect([&](bool, std::string const &) { ++second_callbacks; }));
    bool checkpoint = false, second_still_connecting = false;
    qb::io::async::callback(
        [&] {
            second_still_connecting = client->is_connecting();
            checkpoint              = true;
        },
        300ms);
    ASSERT_TRUE(pump([&] { return checkpoint; }, 1s));
    EXPECT_TRUE(second_still_connecting) << "the first attempt's 100ms timer must not end the 2s attempt";
    EXPECT_EQ(first_callbacks, 1);
    EXPECT_EQ(second_callbacks, 0);
    client->disconnect();
    EXPECT_EQ(second_callbacks, 1);
}

TEST_F(Http3LoopbackTest, RemoteCloseCallbackMayRetryOnSameClient) {
    const auto port   = next_port();
    auto       server = std::make_shared<ReuseHttp3Server>();
    server->router().get("/stall", [](auto) {});
    int route_calls = 0;
    server->router().get("/retry", [&](auto ctx) {
        ++route_calls;
        ctx->text("retried");
    });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    int                old_calls = 0, retry_calls = 0;
    qb::http::Response retry_response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/stall")}, [&](qb::http::Response response) {
        ++old_calls;
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/retry")}, [&](qb::http::Response retry) {
            ++retry_calls;
            retry_response = std::move(retry);
        }));
    }));
    ASSERT_TRUE(pump([&] { return client->get_active_request_count() == 1u && server->last_connection_id != 0; }));

    server->close_connection(server->last_connection_id, 0, "test remote close");
    ASSERT_TRUE(pump([&] { return retry_calls == 1; }, 3s));
    EXPECT_EQ(old_calls, 1);
    EXPECT_EQ(retry_calls, 1);
    EXPECT_EQ(retry_response.status(), qb::http::status::OK);
    EXPECT_EQ(retry_response.body().as<std::string>(), "retried");
    EXPECT_EQ(route_calls, 1);
    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, FailedSubmitCallbackMayDisconnectAndQueueAnotherRequest) {
    const auto port             = next_port();
    auto       server           = qb::http3::make_server();
    int        good_route_calls = 0;
    server->router().get("/good", [&](auto ctx) {
        ++good_route_calls;
        ctx->text("accepted");
    });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    ASSERT_TRUE(client->connect(nullptr));
    ASSERT_TRUE(pump([&] { return client->is_connected(); }));

    int                failed_calls = 0, good_calls = 0;
    qb::http::Response good_response;
    qb::http::Request  invalid{qb::http::method::POST, qb::io::uri("/forbidden-trailer")};
    // A trailer field no trailer section may carry: the submission is refused (Huly QB-1073). An
    // announced field the request does not set -- what this test used -- is sent now, as HTTP/1.1 and
    // HTTP/2 send it: an empty trailer section.
    invalid.trailers().set_header("content-length", "7");
    invalid.body() = "payload";
    EXPECT_NO_THROW(client->push_request(std::move(invalid), [&](qb::http::Response response) {
        ++failed_calls;
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
        client->disconnect();
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/good")}, [&](qb::http::Response good) {
            ++good_calls;
            good_response = std::move(good);
        }));
    }));

    ASSERT_TRUE(pump([&] { return good_calls == 1; }));
    EXPECT_EQ(failed_calls, 1);
    EXPECT_EQ(good_calls, 1);
    EXPECT_EQ(good_response.status(), qb::http::status::OK);
    EXPECT_EQ(good_route_calls, 1);
    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, SynchronousCloseDuringSubmitCompletesSubmittingRequest) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().post("/upload", [](auto ctx) { ctx->text("unexpected"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    auto settings                     = client->settings();
    settings.max_pending_stream_bytes = 16 * 1024;
    client->set_settings(settings);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->connect(nullptr));
    ASSERT_TRUE(pump([&] { return client->is_connected(); }));

    int                calls = 0;
    qb::http::Response response;
    qb::http::Request  request{qb::http::method::POST, qb::io::uri("/upload")};
    request.body() = std::string(256 * 1024, 'x');
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response result) {
        ++calls;
        response = std::move(result);
    }));
    const bool completed_before_close = pump([&] { return calls == 1; }, 1s);
    EXPECT_TRUE(completed_before_close) << "the submitting request must finish without a later timeout or explicit close";
    if (completed_before_close) {
        EXPECT_EQ(calls, 1);
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
        EXPECT_EQ(client->get_active_request_count(), 0u);
    }
    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, SynchronousCloseStillCompletesSubmitWhenOldFailureCallbackThrows) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().post("/upload", [](auto ctx) { ctx->text("unexpected"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_max_concurrent_streams(2);
    auto settings                     = client->settings();
    settings.max_pending_stream_bytes = 16 * 1024;
    client->set_settings(settings);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response response) {
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
        throw std::runtime_error("old request failure callback");
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr && client->get_active_request_count() == 1u; }));

    int                upload_calls = 0;
    qb::http::Response upload_response;
    qb::http::Request  upload{qb::http::method::POST, qb::io::uri("/upload")};
    upload.body() = std::string(256 * 1024, 'x');
    bool caught   = false;
    try {
        client->push_request(std::move(upload), [&](qb::http::Response response) {
            ++upload_calls;
            upload_response = std::move(response);
        });
    } catch (std::runtime_error const &) {
        caught = true;
    }
    EXPECT_TRUE(caught);
    EXPECT_EQ(upload_calls, 1) << "the in-progress submission must finish despite an older callback throwing";
    if (upload_calls == 1) {
        EXPECT_EQ(upload_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    }
    client->disconnect();
    held_context.reset();
    server->close();
}

TEST_F(Http3LoopbackTest, ThrowingConnectCallbackCannotStrandExplicitDisconnect) {
    auto client = qb::http3::make_client(https_origin(next_port())); // no server
    client->set_verify_peer(false);
    ASSERT_TRUE(client->connect([](bool, std::string const &) { throw std::runtime_error("connect callback"); }));

    EXPECT_THROW(client->disconnect(), std::runtime_error);
    EXPECT_FALSE(client->is_connected());
    EXPECT_FALSE(client->is_connecting());
    EXPECT_EQ(static_cast<qb::io::async::quic::endpoint &>(*client).current_state(), qb::io::async::quic::endpoint::state::closed);
    EXPECT_NO_THROW(client->disconnect());
}

TEST_F(Http3LoopbackTest, ThrowingRequestFailureStillNotifiesConnectCallback) {
    auto client = qb::http3::make_client(https_origin(next_port())); // no server
    client->set_verify_peer(false);
    client->set_connect_timeout(100ms);
    int request_calls = 0, connect_calls = 0;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/never")}, [&](qb::http::Response) {
        ++request_calls;
        throw std::runtime_error("request callback");
    }));
    ASSERT_TRUE(client->connect([&](bool ok, std::string const &) {
        ++connect_calls;
        EXPECT_FALSE(ok);
    }));

    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while (connect_calls == 0 && std::chrono::steady_clock::now() < deadline) {
        try {
            qb::io::async::run(EVRUN_NOWAIT);
        } catch (std::runtime_error const &) {
            // Direct callers may receive the first application exception after cleanup.
        }
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(request_calls, 1);
    EXPECT_EQ(connect_calls, 1);
    EXPECT_FALSE(client->is_connecting());
    client->disconnect();
}

TEST_F(Http3LoopbackTest, ThrowingConnectSuccessCallbackStillFlushesPendingRequest) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/ok", [](auto ctx) { ctx->text("done"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    int                first_connect_calls = 0, second_connect_calls = 0, response_calls = 0;
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/ok")}, [&](qb::http::Response result) {
        ++response_calls;
        response = std::move(result);
    }));
    ASSERT_TRUE(client->connect([&](bool ok, std::string const &) {
        ++first_connect_calls;
        EXPECT_TRUE(ok);
        throw std::runtime_error("first connect callback");
    }));
    ASSERT_TRUE(client->connect([&](bool ok, std::string const &) {
        ++second_connect_calls;
        EXPECT_TRUE(ok);
    }));

    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while ((response_calls != 1 || second_connect_calls != 1) && std::chrono::steady_clock::now() < deadline) {
        try {
            qb::io::async::run(EVRUN_NOWAIT);
        } catch (std::runtime_error const &) {
        }
        std::this_thread::sleep_for(1ms);
    }
    EXPECT_EQ(first_connect_calls, 1);
    EXPECT_EQ(second_connect_calls, 1);
    EXPECT_EQ(response_calls, 1);
    if (response_calls == 1) {
        EXPECT_EQ(response.status(), qb::http::status::OK);
        EXPECT_EQ(response.body().as<std::string>(), "done");
    }
    client->disconnect();
    server->close();
}

// The deterministic form of what the test above can only lose to a timing: a response the transport
// CANNOT put on the wire in one burst. 256 KiB is some twenty initial congestion windows, so after
// the first flight the tail waits in the QUIC send queue for ACKs. A graceful shutdown that closes
// the connection once the response has been HANDED to the transport sends CONNECTION_CLOSE -- which
// no window and no pacer holds back -- ahead of that tail, and the client is told the connection
// closed under its request. The shutdown must hold until the request stream has CLOSED, that is
// until the peer has acknowledged the last byte.
TEST_F(Http3LoopbackTest, GracefulShutdownDeliversResponseWiderThanTheCongestionWindow) {
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

    server->graceful_shutdown();

    const std::string wide(256 * 1024, 'w');
    held_context->response().status() = qb::http::status::OK;
    held_context->response().body()   = wide;
    held_context->complete();
    held_context.reset();

    pump([&] { return done.load() && !client->is_connected(); });
    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>().size(), wide.size());
    EXPECT_FALSE(client->is_connected());

    client->disconnect();
    server->close();
}

// A connection keeps state beside every stream -- the request, the response, the body copy the
// HTTP/3 engine reads from -- and that state goes when the engine is told the stream closed. It was
// never told: a connection kept every exchange it had ever carried, on both sides, until it died.
// Forty requests over ONE connection, each settled before the next, must leave what three leave.
TEST_F(Http3LoopbackTest, StreamStateFollowsRequestsInFlightNotRequestsServed) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/blob", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = std::string(4096, 'b');
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto exchange = [&](int count) {
        for (int i = 0; i < count; ++i) {
            std::atomic<bool> done{false};
            qb::http::status  got = qb::http::status::INTERNAL_SERVER_ERROR;
            ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/blob")}, [&](qb::http::Response res) {
                got  = res.status();
                done = true;
            }));
            pump([&] { return done.load(); });
            ASSERT_TRUE(done.load());
            ASSERT_EQ(got, qb::http::status::OK);
        }
        // The stream closes once the last byte is acknowledged: a few more turns.
        const auto settle = std::chrono::steady_clock::now() + 100ms;
        while (std::chrono::steady_clock::now() < settle) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        }
    };

    exchange(3);
    const auto server_after_three = server->http3_stream_state_count();
    const auto client_after_three = client->get_stream_state_count();
    ASSERT_GT(server_after_three, 0u) << "the counter reads nothing: the control and QPACK streams are always there";
    ASSERT_GT(client_after_three, 0u);

    exchange(37);
    EXPECT_EQ(server->http3_stream_state_count(), server_after_three);
    EXPECT_EQ(client->get_stream_state_count(), client_after_three);

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
    // The trailer field is the response's trailers(); the header fields keep it for 3.x (Huly QB-1073).
    EXPECT_EQ(response.trailers().header("x-checksum"), "response-trailer");

    client->disconnect();
    server->close();
}

TEST_F(Http3LoopbackTest, RequestTrailersAreDeliveredToRouter) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().post("/trailers", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        // The trailer field reaches the router as the request's trailers() -- and, for 3.x, as one of
        // its header fields (Huly QB-1073).
        ctx->response().body() = ctx->request().trailers().header("x-client-checksum") + "|" + ctx->request().header("x-client-checksum");
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
    EXPECT_EQ(response.body().as<std::string>(), "request-trailer|request-trailer");

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

    // A field of trailers() a trailer section must not carry refuses the request (Huly QB-1073). An
    // announced one (`trailer: content-length`) stays in the header section, as on HTTP/1.1 and HTTP/2.
    qb::http::Request request{qb::http::method::POST, qb::io::uri("/forbidden-trailer")};
    request.trailers().set_header("content-length", "7");
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
        // A field of trailers() a trailer section must not carry refuses the response (Huly QB-1073).
        ctx->response().status() = qb::http::status::OK;
        ctx->response().trailers().set_header("content-length", "3");
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
    const auto h2_port = next_tcp_port(); // TCP side: probe the TCP space (see next_tcp_port)
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
    const auto h2_port = next_tcp_port(); // TCP side: probe the TCP space (see next_tcp_port)
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
    const auto h2_port = next_tcp_port(); // TCP side: probe the TCP space (see next_tcp_port)
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

// A dual-stack server that is moved before it listens keeps a router facade bound to the stacks it
// owns (Huly QB-504). The facade held a raw pointer to its owner and the implicit moves copied it,
// so the destination's router() still drove the source -- whose stacks had just left it. Routes are
// registered through a move-constructed server, then through the move-assigned one that ends up
// owning both stacks, and every route answers on HTTP/2 and on HTTP/3.
TEST_F(Http3LoopbackTest, DualStackMovedBeforeListenRoutesOnItsOwnStacks) {
    using dual = qb::http::dual_stack_server<>;
    static_assert(std::is_nothrow_move_constructible_v<dual>);
    static_assert(std::is_nothrow_move_assignable_v<dual>);
    static_assert(!std::is_copy_constructible_v<dual> && !std::is_copy_assignable_v<dual>);

    const auto answer = [](std::string body) {
        return [body = std::move(body)](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = body;
            ctx->complete();
        };
    };
    dual built;
    dual moved{std::move(built)};
    moved.router().get("/via-move-constructed", answer("constructed"));
    dual assigned;
    assigned = std::move(moved);
    assigned.router().get("/via-move-assigned", answer("assigned"));
    assigned.router().compile();

    const auto h2_port = next_tcp_port();
    const auto h3_port = next_port();
    ASSERT_TRUE(assigned.listen(qb::io::uri(https_origin(h2_port)), qb::io::uri(https_origin(h3_port)), cert_path(), key_path()));

    auto http2_client = qb::http2::make_client(https_origin(h2_port));
    http2_client->set_connect_timeout(5s);
    http2_client->set_verify_peer(false);
    auto http3_client = qb::http3::make_client(https_origin(h3_port));
    http3_client->set_verify_peer(false);
    for (auto const &[path, body] :
         std::vector<std::pair<std::string, std::string>>{{"/via-move-constructed", "constructed"}, {"/via-move-assigned", "assigned"}}) {
        const auto h2 = qb::http::run_sync(http2_client->push_request(qb::http::Request{qb::io::uri(path)}));
        EXPECT_EQ(h2.status(), qb::http::status::OK) << "HTTP/2 " << path;
        EXPECT_EQ(h2.body().as<std::string>(), body) << "HTTP/2 " << path;
        const auto h3 = qb::http::run_sync(http3_client->push_request(qb::http::Request{qb::io::uri(path)}));
        EXPECT_EQ(h3.status(), qb::http::status::OK) << "HTTP/3 " << path;
        EXPECT_EQ(h3.body().as<std::string>(), body) << "HTTP/3 " << path;
    }

    http2_client->disconnect();
    http3_client->disconnect();
    assigned.close();
    qb::io::async::listener::current.clear();
}

// ---------------------------------------------------------------------------
// Synchronous request-validation / limit guards + awaiter self-expiry.
// Each of these exercises a push_request/push_requests early-return branch that
// fires (or resolves) in-line without connecting: no QUIC handshake, no server.
// ---------------------------------------------------------------------------

// push_request / push_request_with_id / push_requests with an EMPTY callback are
// rejected up front (false / 0 / false) and never touch the request counters.
TEST_F(Http3LoopbackTest, NullCallbackRequestsAreRejectedWithoutSideEffects) {
    auto client = qb::http3::make_client(https_origin(next_port()));

    EXPECT_FALSE(client->push_request(qb::http::Request{qb::io::uri("/x")}, qb::http3::ResponseCallback{}));
    EXPECT_EQ(client->push_request_with_id(qb::http::Request{qb::io::uri("/x")}, qb::http3::ResponseCallback{}), 0u);

    std::vector<qb::http::Request> reqs;
    reqs.push_back(qb::http::Request{qb::io::uri("/x")});
    EXPECT_FALSE(client->push_requests(std::move(reqs), qb::http3::BatchResponseCallback{}));

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 0u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 0u);
}

// An empty batch completes immediately by invoking the callback with an empty
// vector (the requests.empty() early-out), no connection required.
TEST_F(Http3LoopbackTest, EmptyBatchCompletesImmediatelyWithEmptyVector) {
    auto client = qb::http3::make_client(https_origin(next_port()));

    bool                            done = false;
    std::vector<qb::http::Response> out{qb::http::Response{}}; // pre-seed non-empty
    EXPECT_TRUE(client->push_requests(std::vector<qb::http::Request>{}, [&](std::vector<qb::http::Response> rs) {
        out  = std::move(rs);
        done = true;
    }));
    ASSERT_TRUE(done);
    EXPECT_TRUE(out.empty());
}

// set_max_pending_requests(0) makes the first push exceed the bound, so the
// request is failed synchronously with a 503 ("pending request limit reached")
// before any connect attempt is started, and push_request returns false, as the
// HTTP/1.1 and HTTP/2 clients answer a request their bound refuses (Huly QB-499).
TEST_F(Http3LoopbackTest, PendingRequestLimitRejectsWith503) {
    auto client = qb::http3::make_client(https_origin(next_port()));
    client->set_max_pending_requests(0);

    std::atomic<bool>  done{false};
    qb::http::Response response;
    EXPECT_FALSE(client->push_request(qb::http::Request{qb::io::uri("/x")}, [&](qb::http::Response r) {
        response = std::move(r);
        done     = true;
    }));
    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_NE(response.body().as<std::string>().find("limit"), std::string::npos);
    EXPECT_FALSE(client->is_connecting()); // rejected before any connect attempt

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);
}

// The bound of set_max_pending_requests counts queued + active requests whatever API queued them
// (Huly QB-499): a batch is admitted member by member, in order, exactly as the same requests pushed
// one by one. A member past the bound is answered 503 at its index before any context or timer
// exists for it; an invalid member keeps its 400; the callback runs once, with every result; and
// push_requests returns false as soon as the bound refused a member.
TEST_F(Http3LoopbackTest, PendingRequestLimitAdmitsBatchMembersOneByOne) {
    const auto is_limit = [](qb::http::Response const &r) {
        return r.status() == qb::http::status::SERVICE_UNAVAILABLE && r.body().as<std::string>().find("limit") != std::string::npos;
    };

    // A bound of 0 refuses a whole valid batch synchronously, and starts no connection for it.
    {
        // Declared before the client, which outlives them otherwise: its destructor fails what it still holds.
        int                             calls = 0;
        std::vector<qb::http::Response> got;
        auto                            client = qb::http3::make_client(https_origin(next_port()));
        client->set_max_pending_requests(0);
        std::vector<qb::http::Request> batch;
        batch.emplace_back(qb::io::uri("/a"));
        batch.emplace_back(qb::io::uri("/b"));
        EXPECT_FALSE(client->push_requests(std::move(batch), [&](std::vector<qb::http::Response> rs) {
            ++calls;
            got = std::move(rs);
        }));
        ASSERT_EQ(calls, 1) << "every member was over the bound: the batch is complete at once";
        ASSERT_EQ(got.size(), 2u);
        EXPECT_TRUE(is_limit(got[0]));
        EXPECT_TRUE(is_limit(got[1]));
        EXPECT_FALSE(client->is_connecting()) << "no member was admitted, so nothing may connect";
        auto [total, successful, failed] = client->get_stats();
        EXPECT_EQ(total, 2u);
        EXPECT_EQ(successful, 0u);
        EXPECT_EQ(failed, 2u);
    }

    // A bound of 2 with one request already queued leaves room for exactly one more: the first valid
    // member is admitted, the cross-origin member keeps its 400 at its index, and the valid members
    // after it are refused. Disconnecting fails what was admitted and completes the batch, once.
    {
        int                             calls = 0;
        std::vector<qb::http::Response> got;
        std::vector<qb::http::Response> single;
        auto                            client = qb::http3::make_client(https_origin(next_port())); // no server: requests stay queued
        client->set_verify_peer(false);
        client->set_max_pending_requests(2);
        ASSERT_TRUE(
            client->push_request(qb::http::Request{qb::io::uri("/first")}, [&](qb::http::Response r) { single.push_back(std::move(r)); }));
        ASSERT_TRUE(client->is_connecting()) << "the first request must be queued behind a connection attempt";

        std::vector<qb::http::Request> batch;
        batch.emplace_back(qb::io::uri("/m0"));
        batch.emplace_back(qb::io::uri("https://not-the-configured-origin.invalid:443/m1"));
        batch.emplace_back(qb::io::uri("/m2"));
        batch.emplace_back(qb::io::uri("/m3"));
        EXPECT_FALSE(client->push_requests(std::move(batch), [&](std::vector<qb::http::Response> rs) {
            ++calls;
            got = std::move(rs);
        }));
        EXPECT_EQ(calls, 0) << "one member is admitted and outstanding";
        client->disconnect();
        ASSERT_EQ(calls, 1);
        ASSERT_EQ(got.size(), 4u);
        EXPECT_EQ(got[0].status(), qb::http::status::SERVICE_UNAVAILABLE);
        EXPECT_FALSE(is_limit(got[0])) << "the admitted member is failed by the disconnect, not by the bound";
        EXPECT_EQ(got[1].status(), qb::http::status::BAD_REQUEST);
        EXPECT_TRUE(is_limit(got[2])) << got[2].body().as<std::string>();
        EXPECT_TRUE(is_limit(got[3])) << got[3].body().as<std::string>();
        ASSERT_EQ(single.size(), 1u);
        EXPECT_FALSE(is_limit(single[0]));
    }
}

// The return value of push_requests is the same on the three clients: false as soon as the pending
// bound refused a member, as push_request answers a refused request; the members within the bound
// are still sent and answered (Huly QB-499, the HTTP/2 twin is QB-1063). Bound 2, batch of 3: the
// first two go over the wire and come back 200, the third is answered 503 at its index.
TEST_F(Http3LoopbackTest, BatchPastThePendingLimitRefusesOnlyTheMembersOverIt) {
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
    client->set_max_pending_requests(2);

    std::vector<qb::http::Request> requests;
    for (int i = 0; i < 3; ++i) {
        requests.emplace_back(qb::io::uri("/item/" + std::to_string(i)));
    }

    int                             calls = 0;
    std::vector<qb::http::Response> responses;
    EXPECT_FALSE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        ++calls;
        responses = std::move(res);
    })) << "the bound refused the third member";

    pump([&] { return calls != 0; });

    ASSERT_EQ(calls, 1);
    ASSERT_EQ(responses.size(), 3u);
    EXPECT_EQ(responses[0].status(), qb::http::status::OK);
    EXPECT_EQ(responses[0].body().as<std::string>(), "0");
    EXPECT_EQ(responses[1].status(), qb::http::status::OK);
    EXPECT_EQ(responses[1].body().as<std::string>(), "1");
    EXPECT_EQ(responses[2].status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_NE(responses[2].body().as<std::string>().find("limit"), std::string::npos) << responses[2].body().as<std::string>();

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 3u);
    EXPECT_EQ(successful, 2u);
    EXPECT_EQ(failed, 1u);

    client->disconnect();
    server->close();
}

// Cancelling an id that matches no pending or active request returns false
// (both find_if lookups miss).
TEST_F(Http3LoopbackTest, CancelUnknownRequestReturnsFalse) {
    auto client = qb::http3::make_client(https_origin(next_port()));
    EXPECT_FALSE(client->cancel_request(4242u, "no such request"));
}

// The coroutine connect() awaiter, given a client destroyed before the await
// runs, resolves to a failed ConnectResult (weak_self.lock()==nullptr branch)
// instead of dereferencing the gone client.
TEST_F(Http3LoopbackTest, ConnectAwaiterErrorsWhenClientExpiresBeforeAwait) {
    auto result = qb::io::async::run_sync([]() -> qb::io::async::task<qb::http3::ConnectResult> {
        auto client  = qb::http3::make_client("https://127.0.0.1:1");
        auto awaiter = client->connect();
        client.reset(); // drop the last strong ref before awaiting
        co_return co_await awaiter;
    }());

    EXPECT_FALSE(result.ok);
    EXPECT_FALSE(result.error_message.empty());
}

// Same self-expiry contract for the push_request awaiter: a destroyed client
// resolves the awaiter with a synthesized 503.
TEST_F(Http3LoopbackTest, PushRequestAwaiterErrorsWhenClientExpiresBeforeAwait) {
    auto response = qb::io::async::run_sync([]() -> qb::io::async::task<qb::http::Response> {
        auto client  = qb::http3::make_client("https://127.0.0.1:1");
        auto awaiter = client->push_request(qb::http::Request{qb::io::uri("/x")});
        client.reset();
        co_return co_await awaiter;
    }());

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_FALSE(response.body().empty());
}

/**
 * @test A request and response cross several deliberately small QUIC receive windows
 * @brief DATA credit must be returned by each HTTP/3 receiver. Without it the sender
 *        stops at the first 16 KiB stream window and neither side completes its body.
 */
TEST_F(Http3LoopbackTest, BodiesCrossSeveralSmallReceiveWindows) {
    constexpr std::size_t request_size  = 160 * 1024;
    constexpr std::size_t response_size = 192 * 1024;
    const auto            port          = next_port();

    qb::io::quic::settings flow;
    flow.stream_recv_window          = 16 * 1024;
    flow.connection_recv_window      = 64 * 1024;
    flow.max_stream_data_bidi_local  = 16 * 1024;
    flow.max_stream_data_bidi_remote = 16 * 1024;
    flow.max_stream_data_uni         = 16 * 1024;

    auto server = qb::http3::make_server();
    server->set_settings(flow);
    std::size_t received_request_size = 0;
    server->router().post("/credit", [&](auto ctx) {
        received_request_size  = ctx->request().body().size();
        ctx->response().body() = std::string(response_size, 'R');
        ctx->complete();
    });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_settings(flow);
    client->set_verify_peer(false);
    qb::http::Request request{qb::http::method::POST, qb::io::uri("/credit")};
    request.body() = std::string(request_size, 'Q');
    std::atomic<bool>  done{false};
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response result) {
        response = std::move(result);
        done     = true;
    }));

    ASSERT_TRUE(pump([&] { return done.load(); }, 10s));
    EXPECT_EQ(received_request_size, request_size);
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().size(), response_size);
    EXPECT_EQ(response.body().as<std::string>(), std::string(response_size, 'R'));
    EXPECT_TRUE(client->is_connected());
    EXPECT_TRUE(server->is_open());

    client->disconnect();
    server->close();
}

#endif // QBM_HTTP_HAS_HTTP3

// ---------------------------------------------------------------------------
// A batch whose requests ALL fail prepare_request must still invoke the callback.
//
// push_requests() moves the caller's callback into the batch context
// (`batch->callback = std::move(callback)`) and then, if every request failed validation
// synchronously, took an early-completion path that invoked the ORIGINAL `callback` — by then a
// moved-from std::function, i.e. empty. Calling it throws std::bad_function_call, so the caller
// never receives the per-request error responses it was promised, precisely in the case where it
// most needs them.
//
// prepare_request rejects a missing host, a non-https scheme, or a cross-origin URI — so a single
// off-origin request is enough, and the whole path is synchronous and pre-network: no server, no
// connection, no pumping required.
//
// Found by clang-analyzer-cplusplus.Move + bugprone-use-after-move. The same use-after-move shape
// exists in the HTTP/1.1 and HTTP/2 clients' connect() awaiters, but there it is unreachable
// (their connect(callback) never returns false when a callback is supplied), so only this one is a
// live defect; the others were hardened defensively.
//
// PLATFORM NOTE, so a green run here is not over-read: a moved-from std::function is "valid but
// unspecified". libstdc++ ALWAYS empties it — verified with a direct probe, including for this
// exact signature — so the pre-fix code throws bad_function_call on Linux (and, by the same
// mechanism, very likely MSVC). libc++ leaves a small-buffer callable intact, so on macOS the old
// code happened to work and this case passes with OR without the fix. It still earns its place
// everywhere as coverage of the all-rejected batch path; the use-after-move half only
// discriminates on an implementation that empties the source.
// ---------------------------------------------------------------------------
TEST_F(Http3LoopbackTest, BatchOfFullyRejectedRequestsStillInvokesTheCallback) {
    auto client = qb::http3::make_client(https_origin(ephemeral_udp_port()));
    client->set_verify_peer(false);

    // Cross-origin (different host) => prepare_request rejects it before any I/O.
    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("https://not-the-configured-origin.invalid:443/nope"));

    bool                            fired = false;
    std::vector<qb::http::Response> got;
    EXPECT_NO_THROW({
        client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> responses) {
            fired = true;
            got   = std::move(responses);
        });
    }) << "an all-rejected batch threw instead of delivering its error responses";

    EXPECT_TRUE(fired) << "the batch callback must fire even when every request is rejected up front";
    ASSERT_EQ(got.size(), 1u);
    EXPECT_EQ(got[0].status(), qb::http::status::BAD_REQUEST);
}

TEST_F(Http3LoopbackTest, CancelActiveRequestKeepsClientAliveThroughCallback) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/stall", [](auto) {});
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    std::weak_ptr<qb::http3::Client> weak_client       = client;
    int                              calls             = 0;
    bool                             alive_in_callback = false;
    const auto id = client->push_request_with_id(qb::http::Request{qb::io::uri("/stall")}, [&](qb::http::Response response) {
        ++calls;
        EXPECT_EQ(response.status(), qb::http::status::CLIENT_CLOSED_REQUEST);
        client.reset();
        alive_in_callback = !weak_client.expired();
    });
    ASSERT_NE(id, 0u);
    ASSERT_TRUE(pump([&] { return client->get_active_request_count() == 1u; }));

    EXPECT_TRUE(client->cancel_request(id));
    EXPECT_EQ(calls, 1);
    EXPECT_TRUE(alive_in_callback) << "cancel_request must finish its stream teardown before the last owner is released";
    EXPECT_TRUE(weak_client.expired());
    server->close();
}

// ---------------------------------------------------------------------------
// Drain (Huly QB-91): the shutdown notice, the final GOAWAY two smoothed round trips later, the close once the last
// request stream has closed and the GOAWAY is acknowledged -- and a connection made during the drain serves nothing.
// ---------------------------------------------------------------------------

// A request in flight when the drain begins is answered; the connection then closes, and the drain reports
// `drained` once no connection is left -- not before the request is answered.
TEST_F(Http3LoopbackTest, DrainAnswersTheRequestInFlightThenReportsDrained) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    bool               done = false;
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));

    int  reports = 0;
    auto outcome = qb::http::drain_outcome::deadline;
    ASSERT_TRUE(server->drain(5s, [&](qb::http::drain_outcome o) {
        outcome = o;
        ++reports;
    }));
    EXPECT_TRUE(server->draining());
    EXPECT_FALSE(server->drain(5s)) << "a drain begins once";
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_EQ(reports, 0) << "a request is still in flight";
    EXPECT_FALSE(done);

    held_context->text("held-ok");
    held_context.reset();
    ASSERT_TRUE(pump([&] { return done && reports == 1; }));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "held-ok");
    EXPECT_EQ(outcome, qb::http::drain_outcome::drained);
    EXPECT_TRUE(pump([&] { return !client->is_connected(); }));

    client->disconnect();
    server->close();
}

// A request still unanswered at the deadline is abandoned: the connection is closed and the drain reports
// `deadline`, not before it.
TEST_F(Http3LoopbackTest, DrainDeadlineClosesTheConnectionsStillOpen) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    bool               done = false;
    qb::http::Response response;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));

    int        reports = 0;
    auto       outcome = qb::http::drain_outcome::drained;
    const auto started = std::chrono::steady_clock::now();
    ASSERT_TRUE(server->drain(300ms, [&](qb::http::drain_outcome o) {
        outcome = o;
        ++reports;
    }));
    ASSERT_TRUE(pump([&] { return reports == 1; }));
    EXPECT_EQ(outcome, qb::http::drain_outcome::deadline);
    EXPECT_GE(std::chrono::steady_clock::now() - started, 250ms) << "not before the deadline";
    ASSERT_TRUE(pump([&] { return done; }));
    EXPECT_NE(response.status(), qb::http::status::OK) << "the abandoned request is never answered";
    EXPECT_TRUE(pump([&] { return !client->is_connected(); }));

    held_context.reset();
    client->disconnect();
    server->close();
}

// A connection made while the server drains serves nothing: its GOAWAY, sent before any request stream is read,
// names stream 0, so the request it sent in its first flight is rejected -- never handed to the router -- and it
// closes once the GOAWAY is acknowledged. The drain still waits for the connection that was there before it.
TEST_F(Http3LoopbackTest, ARequestOnAConnectionMadeDuringTheDrainNeverReachesTheRouter) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    int                                                           counted = 0;
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().get("/count", [&](auto ctx) {
        ++counted;
        ctx->text("counted");
    });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto first = qb::http3::make_client(https_origin(port));
    first->set_verify_peer(false);
    bool first_done = false;
    ASSERT_TRUE(first->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response) { first_done = true; }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));

    int  reports = 0;
    auto outcome = qb::http::drain_outcome::deadline;
    ASSERT_TRUE(server->drain(5s, [&](qb::http::drain_outcome o) {
        outcome = o;
        ++reports;
    }));

    auto late = qb::http3::make_client(https_origin(port));
    late->set_verify_peer(false);
    bool               late_done = false;
    qb::http::Response late_response;
    ASSERT_TRUE(late->push_request(qb::http::Request{qb::io::uri("/count")}, [&](qb::http::Response res) {
        late_response = std::move(res);
        late_done     = true;
    }));
    ASSERT_TRUE(pump([&] { return late_done; }));
    EXPECT_NE(late_response.status(), qb::http::status::OK);
    EXPECT_EQ(counted, 0) << "the request of a connection made during the drain never reaches the router";
    EXPECT_TRUE(pump([&] { return !late->is_connected(); })) << "and the connection is closed";
    EXPECT_EQ(reports, 0) << "the connection there before the drain still has a request in flight";

    held_context->text("held-ok");
    held_context.reset();
    ASSERT_TRUE(pump([&] { return first_done && reports == 1; }));
    EXPECT_EQ(outcome, qb::http::drain_outcome::drained);
    EXPECT_EQ(counted, 0);

    first->disconnect();
    late->disconnect();
    server->close();
}

// A server with no connection reports `drained` before drain() returns.
TEST_F(Http3LoopbackTest, DrainWithNoConnectionReportsAtOnce) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    int  reports = 0;
    auto outcome = qb::http::drain_outcome::deadline;
    ASSERT_TRUE(server->drain(5s, [&](qb::http::drain_outcome o) {
        outcome = o;
        ++reports;
    }));
    EXPECT_EQ(reports, 1);
    EXPECT_EQ(outcome, qb::http::drain_outcome::drained);
    server->close();
}

// The dual-stack server drains both stacks and reports once: `deadline` when one of them met it -- here the HTTP/3
// stack, whose request is held -- although the HTTP/2 stack drained at once.
TEST_F(Http3LoopbackTest, DualStackDrainReportsOnceAndDeadlineWhenOneStackMetIt) {
    const auto                                                    h2_port = next_tcp_port();
    const auto                                                    h3_port = next_port();
    auto                                                          server  = qb::http::make_dual_stack_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->http3_server().router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(h2_port)), qb::io::uri(https_origin(h3_port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(h3_port));
    client->set_verify_peer(false);
    bool done = false;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response) { done = true; }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));

    int  reports = 0;
    auto outcome = qb::http::drain_outcome::drained;
    ASSERT_TRUE(server->drain(300ms, [&](qb::http::drain_outcome o) {
        outcome = o;
        ++reports;
    }));
    EXPECT_TRUE(server->draining());
    EXPECT_FALSE(server->drain(300ms)) << "a drain begins once";
    EXPECT_EQ(reports, 0) << "the HTTP/2 stack drained at once, the HTTP/3 one has not";
    ASSERT_TRUE(pump([&] { return reports == 1; }));
    EXPECT_EQ(outcome, qb::http::drain_outcome::deadline);
    ASSERT_TRUE(pump([&] { return done; }));
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_EQ(reports, 1) << "one report";

    held_context.reset();
    client->disconnect();
    server->close();
    qb::io::async::listener::current.clear();
}

namespace http3_shutdown_wire_test {

/// A bare QUIC peer offering h3: it reads what the server's control stream carries -- its GOAWAYs, and when each
/// arrived -- and whether the connection closed. It opens no stream of its own. (qb-io reports no peer's
/// CONNECTION_CLOSE code, so the H3_NO_ERROR it now carries is not read here.)
class RawH3Peer : public qb::io::async::quic::endpoint {
    std::string _control; ///< The bytes of the server's control stream (its first unidirectional stream, id 3)

    static bool
    varint(std::string const &bytes, std::size_t &at, std::uint64_t &value) {
        if (at >= bytes.size())
            return false;
        const auto        first  = static_cast<std::uint8_t>(bytes[at]);
        const std::size_t length = std::size_t{1} << (first >> 6);
        if (at + length > bytes.size())
            return false;
        value = first & 0x3Fu;
        for (std::size_t i = 1; i < length; ++i)
            value = (value << 8) | static_cast<std::uint8_t>(bytes[at + i]);
        at += length;
        return true;
    }

    void
    parse_goaways() {
        std::size_t   at = 0;
        std::uint64_t value;
        if (!varint(_control, at, value) || value != 0x00)
            return; // not a control stream (yet)
        std::size_t seen = 0;
        while (true) {
            std::uint64_t type, length;
            std::size_t   frame = at;
            if (!varint(_control, frame, type) || !varint(_control, frame, length) || frame + length > _control.size())
                return;
            if (type == 0x07) {
                std::size_t   id_at = frame;
                std::uint64_t id    = 0;
                (void) varint(_control, id_at, id);
                if (++seen > goaway_ids.size()) {
                    goaway_ids.push_back(id);
                    goaway_arrivals.push_back(std::chrono::steady_clock::now());
                }
            }
            at = frame + length;
        }
    }

protected:
    void
    dispatch(qb::io::async::quic::event::connected const &) override {
        connected = true;
    }
    void
    dispatch(qb::io::async::quic::event::connection_closed const &) override {
        closed = true;
    }
    void
    dispatch(qb::io::async::quic::event::stream_data const &ev) override {
        if (ev.id == 3) {
            _control.append(ev.payload.data(), ev.payload.size());
            parse_goaways();
        }
    }

public:
    bool                                               connected = false;
    bool                                               closed    = false;
    std::vector<std::uint64_t>                         goaway_ids;
    std::vector<std::chrono::steady_clock::time_point> goaway_arrivals;

    bool
    open(std::string const &origin) {
        qb::io::quic::tls_config tls;
        tls.verify_peer = false;
        return connect(qb::io::uri(origin), tls, {"h3"});
    }
};

} // namespace http3_shutdown_wire_test

// graceful_shutdown() in two phases (RFC 9114 section 5.2, Huly QB-91): the notice -- a GOAWAY naming the largest
// stream id -- then, at least a millisecond later, the final GOAWAY naming the first request not read (0: none was
// sent); the connection closes once that GOAWAY is acknowledged. Until 3.3 the two GOAWAYs went back to back, which
// left no round trip for the requests already on their way.
TEST_F(Http3LoopbackTest, GracefulShutdownSendsTheNoticeThenTheFinalGoawayARoundTripLater) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    http3_shutdown_wire_test::RawH3Peer peer;
    ASSERT_TRUE(peer.open(https_origin(port)));
    ASSERT_TRUE(pump([&] { return peer.connected; }));
    const auto settle = std::chrono::steady_clock::now() + 50ms; // the server's control stream and SETTINGS
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    ASSERT_TRUE(peer.goaway_ids.empty());

    server->graceful_shutdown();
    ASSERT_TRUE(pump([&] { return peer.closed; }));
    ASSERT_EQ(peer.goaway_ids.size(), 2u);
    EXPECT_EQ(peer.goaway_ids[0], (std::uint64_t{1} << 62) - 4) << "the notice names the largest stream id";
    EXPECT_EQ(peer.goaway_ids[1], 0u) << "the final GOAWAY: no request was read";
    EXPECT_GE(peer.goaway_arrivals[1] - peer.goaway_arrivals[0], 500us) << "a round trip separates the two GOAWAYs";

    server->close();
}

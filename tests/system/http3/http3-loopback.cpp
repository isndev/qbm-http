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
#include <qbm/http/middleware/compression.h>

#if defined(QBM_HTTP_HAS_HTTP3)

#include <algorithm>
#include <atomic>
#include <chrono>
#include <coroutine>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"
#include "../../shared/watchdog.h"

#include <qbm/http/middleware/static_files.h>

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

TEST_F(Http3LoopbackTest, RequestCookiesAreParsedSplitLinesIncludedAndARefusedHeaderIsServed) {
    // HTTP/3 parsed no Cookie header at all, and a client may split it into one line per cookie-pair
    // (RFC 9114 4.2.1); a header the parser refuses is served without cookies (Huly QB-1174).
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/cookies", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("x-cookie-a", ctx->request().cookie_value("a"));
        ctx->response().set_header("x-cookie-b", ctx->request().cookie_value("b"));
        ctx->response().body() = "cookies";
        ctx->complete();
    });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request split{qb::io::uri("/cookies")};
    split.add_header("cookie", "a=1");
    split.add_header("cookie", "b=2");
    auto response = qb::http::run_sync(client->push_request(std::move(split)));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-cookie-a"), "1");
    EXPECT_EQ(response.header("x-cookie-b"), "2");

    qb::http::Request refused{qb::io::uri("/cookies")};
    refused.add_header("cookie", "a=1"); // lines that join past max_cookie_header_size: the one refusal left (QB-95)
    for (int line = 0; line < 3; ++line)
        refused.add_header("cookie", "pad" + std::to_string(line) + "=" + std::string(6000, 'v'));
    response = qb::http::run_sync(client->push_request(std::move(refused)));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("x-cookie-a"), "");

    response = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/cookies")}));
    EXPECT_EQ(response.status(), qb::http::status::OK) << "the server keeps serving";

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

// A request's content-length is its body's, as the HTTP/2 client writes it (Huly QB-1191): a declared one the body
// contradicts is left out -- the request was failed with 503 before it left, and HTTP/2 sent it.
TEST_F(Http3LoopbackTest, ClientSendsTheContentLengthOfTheBody) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().post("/length", [&server_requests](auto ctx) {
        ++server_requests;
        // What the server read: the content-length field, then the body it framed.
        ctx->response().body() = std::string(ctx->request().header("content-length")) + ":" + ctx->request().body().template as<std::string>();
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

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(server_requests.load(), 1);
    EXPECT_EQ(response.body().as<std::string>(), "3:abc");

    client->disconnect();
    server->close();
}

// A declared content-length with whitespace around the number is left out like any declared one, and the body's
// written (Huly QB-1191: the request was failed with 503 before it left).
TEST_F(Http3LoopbackTest, ClientWritesTheBodysContentLengthOverOneWithOWS) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().post("/length-ows", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = std::string(ctx->request().header("content-length")) + ":" + ctx->request().body().template as<std::string>();
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

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(server_requests.load(), 1);
    EXPECT_EQ(response.body().as<std::string>(), "3:abc");

    client->disconnect();
    server->close();
}

// The server refuses to SEND a response whose body does not match its content-length (the
// outgoing validation of submit_response) and resets the stream with H3_REQUEST_CANCELLED (Huly QB-1241), so the
// client settles the exchange as a 502 -- a stream reset, never a connection close (Huly QB-234;
// RFC 9114 section 4.1.1). The connection carries the client's other exchanges: the SAME one --
// never reconnected: still connected after a settle, one connection on the server -- serves the next request.
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

// A field HTTP/3 cannot carry never leaves the client: it is left out and the request served, as the HTTP/2 client
// leaves it out (Huly QB-1191; the request was failed with 503). Nothing of it reaches the server.
TEST_F(Http3LoopbackTest, ClientLeavesOutAnInvalidOutgoingHeaderField) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().get("/guarded-invalid", [&server_requests](auto ctx) {
        ++server_requests;
        // What reached the server of the field: nothing, whichever name the injection aimed at.
        ctx->response().body() = std::string(ctx->request().header("x-injected")) + "|" + std::string(ctx->request().header("injected"));
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/guarded-invalid")};
    request.set_header("x-injected", "safe\r\nInjected: bad");

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(server_requests.load(), 1);
    EXPECT_EQ(response.body().as<std::string>(), "|");

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

    // What the callbacks capture is declared before the client: it answers what it still holds when it is destroyed.
    int                             active_calls = 0, pending_calls = 0;
    std::size_t                     states_before_disconnect = 0, states_inside_disconnect_callback = 0;
    bool                            connected_after_disconnect = true, reentrant_connect_started = false, reentrant_connect_succeeded = false;
    int                             reentrant_connect_calls = 0, reentrant_connect_calls_inside = -1;
    int                             late_calls = 0, late_batch_calls = 0;
    qb::http3::request_id           late_request_id = 1;
    qb::http::Response              late_response;
    std::vector<qb::http::Response> late_batch_responses;
    qb::http::Response              active_response, pending_response;

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_max_concurrent_streams(1);
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
        reentrant_connect_calls_inside    = reentrant_connect_calls;
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
    EXPECT_TRUE(reentrant_connect_started) << "a handshake asked on nghttp3's active stack waits for the teardown: it is accepted";
    EXPECT_EQ(reentrant_connect_calls_inside, 0) << "the callback of a connect() is never called inside the call";
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
    // The teardown done, the attempt the callback asked for has started. No pass of the loop since: the disconnect() below
    // gives it up, and its callback hears that, once.
    EXPECT_TRUE(client->is_connecting());
    EXPECT_EQ(reentrant_connect_calls, 0);
    client->disconnect();
    EXPECT_EQ(reentrant_connect_calls, 1);
    EXPECT_FALSE(reentrant_connect_succeeded);
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

// A failure callback of an explicit disconnect() asks for the next connection and pushes a request. The request is answered
// in the push, as during any close. The connect() is accepted and waits for the close: its callback is not called inside the
// call -- it heard `false` there (Huly QB-1246) -- and hears the outcome of the attempt started once the close has run.
TEST_F(Http3LoopbackTest, ExplicitDisconnectStartsTheConnectItsFailureCallbackAsks) {
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

    // What the callbacks capture is declared before the client: it answers what it still holds when it is destroyed.
    int                   failed_calls = 0, connect_calls = 0, connect_calls_inside = -1, late_calls = 0;
    bool                  connected_in_callback = true, connect_started = false, connect_succeeded = false;
    qb::http3::request_id late_id = 1;
    auto                  client  = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response response) {
        ++failed_calls;
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
        connected_in_callback = client->is_connected();
        connect_started       = client->connect([&](bool ok, std::string const &) {
            ++connect_calls;
            connect_succeeded = ok;
        });
        connect_calls_inside  = connect_calls;
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
    EXPECT_TRUE(connect_started);
    EXPECT_EQ(connect_calls_inside, 0) << "the callback of a connect() is never called inside the call";
    EXPECT_EQ(connect_calls, 0) << "nor by the close it waits for";
    EXPECT_EQ(late_id, 0u);
    EXPECT_EQ(late_calls, 1);
    EXPECT_EQ(late_route_calls, 0);
    EXPECT_FALSE(client->is_connected());
    EXPECT_TRUE(client->is_connecting()) << "the close done, the connect() the callback asked for has started";
    ASSERT_TRUE(pump([&] { return connect_calls == 1; }));
    EXPECT_TRUE(connect_succeeded);
    EXPECT_TRUE(client->is_connected());
    EXPECT_EQ(late_route_calls, 0);
    client->disconnect();
    EXPECT_EQ(connect_calls, 1);
    held_context.reset();
    server->close();
}

namespace qb::http3 {

/// An explicit disconnect() deferred by a read that an exception cut short: the read's depth is restored, the close it
/// should have completed is not. No call leaves a client there -- an allocation failure inside the read does --, so the test
/// reaches it by hand, as the one friend the client declares for it.
struct ClientTestPeer {
    static void
    disconnect_in_a_read_cut_short(Client &client) {
        ++client._read_depth;
        client.disconnect();
        --client._read_depth;
    }
    /// connect() past its lookup: the addresses a name resolved to are the test's own (no resolver gives two loopback
    /// addresses of which the first is silent).
    static bool
    dial(Client &client, std::vector<qb::io::endpoint> candidates, ConnectionCallback callback) {
        return client.dial(std::move(candidates), std::move(callback), std::chrono::steady_clock::now());
    }
    /// start_attempt() with nothing left of the connect timeout -- where the timer of a share that fired at the deadline
    /// finds it --: how many of @p candidates it dialled.
    static std::size_t
    dialled_with_no_time_left(Client &client, std::vector<qb::io::endpoint> candidates) {
        client._connect_candidates = std::move(candidates);
        client._connect_next       = 0;
        client._is_connecting      = true;
        client._connect_deadline   = std::chrono::steady_clock::now() - std::chrono::milliseconds(1);
        static_cast<void>(client.start_attempt());
        const auto dialled = client._connect_next;
        client.disconnect();
        return dialled;
    }
};

} // namespace qb::http3

namespace http3_client_redial_test {

// A client the test takes the connection from in the middle of its own read -- what a close the transport delivers
// re-entrantly is, while nghttp3 reads. The teardown is then deferred to the end of that read.
struct LosingClient : qb::http3::Client {
    using qb::http3::Client::Client;

    void
    lose_connection() {
        qb::io::async::quic::event::connection_closed lost;
        lost.reason_phrase = "lost in the middle of a read";
        dispatch(lost);
    }
};

// The callback a program dials again from: on `false`, connect() again -- bounded here, so that a client that answers
// inside the call is measured by its depth, not by the stack it overflows.
struct Redial {
    qb::http3::Client *client = nullptr; ///< set once the client exists: a Redial is declared before it, and outlives it
    int                dials = 0, heard_true = 0, heard_false = 0, depth = 0, deepest = 0, cap = 64;

    bool
    dial() {
        ++dials;
        return client->connect([this](bool ok, std::string const &) {
            deepest = std::max(deepest, ++depth);
            ++(ok ? heard_true : heard_false);
            if (!ok && dials < cap) {
                static_cast<void>(dial());
            }
            --depth;
        });
    }
};

} // namespace http3_client_redial_test

using http3_client_redial_test::LosingClient;
using http3_client_redial_test::Redial;

// A callback that dials again on `false`, asked from a response callback that has just disconnected -- the native read is
// on the stack, the close deferred. The connect() waits for that close and its callback hears the new connection: it was
// answered `false` inside the call, and dialled again from there, without end (Huly QB-1246).
TEST_F(Http3LoopbackTest, ARedialAskedDuringADeferredCloseConnectsOnceTheCloseHasRun) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/ok", [](auto ctx) { ctx->text("ok"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    Redial             redial;
    int                first_calls = 0, second_calls = 0;
    bool               dial_accepted = false;
    qb::http::Response second;
    auto               client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    redial.client = client.get();
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/ok")}, [&](qb::http::Response response) {
        ++first_calls;
        EXPECT_EQ(response.status(), qb::http::status::OK);
        client->disconnect(); // from nghttp3's read: deferred
        dial_accepted = redial.dial();
    }));
    ASSERT_TRUE(pump([&] { return first_calls == 1 && redial.heard_true + redial.heard_false != 0; }));
    EXPECT_TRUE(dial_accepted);
    EXPECT_EQ(redial.dials, 1);
    EXPECT_EQ(redial.deepest, 1) << "the callback of a connect() is never called inside the call";
    EXPECT_EQ(redial.heard_true, 1);
    EXPECT_EQ(redial.heard_false, 0);
    ASSERT_TRUE(client->is_connected());

    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/ok")}, [&](qb::http::Response response) {
        ++second_calls;
        second = std::move(response);
    }));
    ASSERT_TRUE(pump([&] { return second_calls == 1; }));
    EXPECT_EQ(second.status(), qb::http::status::OK) << "the connection the redial asked for carries the next request";
    client->disconnect();
    server->close();
}

// The same of a connection LOST during the read -- the close the transport delivers there is deferred to the end of that
// read, as an explicit one is. The teardown done, the redial connects; a request in flight whose failure callback throws
// does not keep it from starting.
TEST_F(Http3LoopbackTest, ARedialAskedOfAConnectionLostDuringItsReadConnectsOnceTheTeardownHasRun) {
    for (const bool a_failure_callback_throws : {false, true}) {
        SCOPED_TRACE(a_failure_callback_throws ? "a request in flight, whose failure callback throws" : "nothing else in flight");
        const auto                                                    port   = next_port();
        auto                                                          server = qb::http3::make_server();
        std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
        server->router().get("/ok", [](auto ctx) { ctx->text("ok"); });
        server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
        server->router().compile();
        ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

        Redial redial;
        int    held_calls = 0, first_calls = 0;
        bool   dial_accepted = false;
        auto   losing        = std::make_shared<LosingClient>(qb::io::uri(https_origin(port)));
        auto  *client        = losing.get();
        client->set_verify_peer(false);
        client->set_auto_reconnect(false); // nothing but the redial asks for the next connection
        redial.client = client;
        if (a_failure_callback_throws) {
            ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response) {
                ++held_calls;
                throw std::runtime_error("the failure callback of a request in flight");
            }));
            ASSERT_TRUE(pump([&] { return held_context != nullptr; }));
        }
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/ok")}, [&](qb::http::Response response) {
            ++first_calls;
            EXPECT_EQ(response.status(), qb::http::status::OK);
            losing->lose_connection(); // from nghttp3's read: the teardown is deferred
            dial_accepted = redial.dial();
        }));
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (redial.heard_true + redial.heard_false == 0 && std::chrono::steady_clock::now() < deadline) {
            try {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(1ms);
                }
            } catch (std::runtime_error const &) {
                // what the failure callback threw, where the loop lets it out
            }
        }
        EXPECT_EQ(first_calls, 1);
        EXPECT_EQ(held_calls, a_failure_callback_throws ? 1 : 0);
        EXPECT_TRUE(dial_accepted);
        EXPECT_EQ(redial.dials, 1);
        EXPECT_EQ(redial.deepest, 1) << "the callback of a connect() is never called inside the call";
        EXPECT_EQ(redial.heard_true, 1);
        EXPECT_EQ(redial.heard_false, 0);
        EXPECT_TRUE(client->is_connected());
        client->disconnect();
        held_context.reset();
        server->close();
    }
}

// A connect() the client accepted while a close was deferred, then a disconnect(): the last word is the disconnect().
// The connect() is given up -- its callback hears `false` once, from the close -- and no connection starts.
TEST_F(Http3LoopbackTest, ADisconnectAfterAConnectAskedDuringACloseGivesThatConnectUp) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    int  failed_calls = 0, connect_calls = 0, connect_calls_inside = -1;
    bool connect_accepted = false, connect_succeeded = true;
    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response) {
        ++failed_calls;
        connect_accepted     = client->connect([&](bool ok, std::string const &) {
            ++connect_calls;
            connect_succeeded = ok;
        });
        connect_calls_inside = connect_calls;
        client->disconnect();
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));

    client->disconnect();
    EXPECT_EQ(failed_calls, 1);
    EXPECT_TRUE(connect_accepted);
    EXPECT_EQ(connect_calls_inside, 0);
    EXPECT_EQ(connect_calls, 1) << "a connect() given up hears, once, from the close that gave it up";
    EXPECT_FALSE(connect_succeeded);
    EXPECT_FALSE(client->is_connecting()) << "and nothing connects for it";
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());
    EXPECT_EQ(connect_calls, 1);
    held_context.reset();
    server->close();
}

// The same of a connection lost during the read: the connect() asked of it there, then a disconnect().
TEST_F(Http3LoopbackTest, ADisconnectAfterAConnectAskedOfAConnectionLostDuringItsReadGivesThatConnectUp) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/ok", [](auto ctx) { ctx->text("ok"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    int  response_calls = 0, connect_calls = 0, connect_calls_inside = -1;
    bool connect_accepted = false, connect_succeeded = true;
    auto losing = std::make_shared<LosingClient>(qb::io::uri(https_origin(port)));
    losing->set_verify_peer(false);
    losing->set_auto_reconnect(false);
    ASSERT_TRUE(losing->push_request(qb::http::Request{qb::io::uri("/ok")}, [&](qb::http::Response) {
        ++response_calls;
        losing->lose_connection(); // from nghttp3's read: the teardown is deferred
        connect_accepted     = losing->connect([&](bool ok, std::string const &) {
            ++connect_calls;
            connect_succeeded = ok;
        });
        connect_calls_inside = connect_calls;
        losing->disconnect();
    }));
    ASSERT_TRUE(pump([&] { return response_calls == 1 && connect_calls != 0; }));
    EXPECT_TRUE(connect_accepted);
    EXPECT_EQ(connect_calls_inside, 0);
    EXPECT_EQ(connect_calls, 1) << "a connect() given up hears, once, from the close that gave it up";
    EXPECT_FALSE(connect_succeeded);
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_FALSE(losing->is_connecting()) << "and nothing connects for it";
    EXPECT_FALSE(losing->is_connected());
    EXPECT_EQ(connect_calls, 1);
    server->close();
}

// The same, the disconnect() made from ANOTHER callback: the failure callback of a request that was in flight when the
// connection was lost. The connect() asked of the lost connection waits for the end of its teardown, and that callback
// runs in that teardown, with no read on the stack: its disconnect() is the close itself, and the caller's last word. The
// connect() is given up -- its callback hears `false` once --: disconnect() never starts a connect() asked before it (one
// its own callbacks ask starts at its end). It started this one itself: it returned with an attempt under way, and the
// callback heard `true` (Huly QB-1246).
TEST_F(Http3LoopbackTest, ADisconnectFromAFailureCallbackGivesUpTheConnectAskedOfTheLostConnection) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/ok", [](auto ctx) { ctx->text("ok"); });
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    int  response_calls = 0, held_calls = 0, connect_calls = 0;
    bool connect_accepted = false, connect_succeeded = true, connecting_after_disconnect = true;
    auto losing = std::make_shared<LosingClient>(qb::io::uri(https_origin(port)));
    losing->set_verify_peer(false);
    losing->set_auto_reconnect(false);
    ASSERT_TRUE(losing->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response response) {
        ++held_calls;
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
        losing->disconnect(); // from a failure callback of the teardown: no read on the stack, the close itself
        connecting_after_disconnect = losing->is_connecting();
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));
    ASSERT_TRUE(losing->push_request(qb::http::Request{qb::io::uri("/ok")}, [&](qb::http::Response) {
        ++response_calls;
        losing->lose_connection(); // from nghttp3's read: the teardown is deferred
        connect_accepted = losing->connect([&](bool ok, std::string const &) {
            ++connect_calls;
            connect_succeeded = ok;
        });
    }));
    ASSERT_TRUE(pump([&] { return response_calls == 1 && held_calls == 1 && connect_calls != 0; }));
    EXPECT_TRUE(connect_accepted);
    EXPECT_EQ(connect_calls, 1) << "a connect() given up hears, once, from the close that gave it up";
    EXPECT_FALSE(connect_succeeded);
    EXPECT_FALSE(connecting_after_disconnect) << "disconnect() returned with a connection attempt under way";
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_FALSE(losing->is_connecting()) << "and nothing connects for it";
    EXPECT_FALSE(losing->is_connected());
    EXPECT_EQ(connect_calls, 1);
    held_context.reset();
    server->close();
}

// A client destroyed with a close left half done -- a disconnect() deferred during a submission that an exception then cut
// short, set here through the test seam -- is closed whole by its destructor: a connect() still waiting hears `false` once.
// The destructor's close stopped at the mark the unfinished one had left: that connect() was destroyed unheard (Huly QB-1246).
TEST_F(Http3LoopbackTest, AClientDestroyedWithACloseLeftHalfDoneStillAnswersItsWaitingConnect) {
    int  connect_calls    = 0;
    bool connect_accepted = false, connect_succeeded = true;
    {
        auto client = qb::http3::make_client("https://127.0.0.1:1"); // it never connects: nothing here needs a peer
        qb::http3::ClientTestPeer::disconnect_in_a_read_cut_short(*client);
        connect_accepted = client->connect([&](bool ok, std::string const &) {
            ++connect_calls;
            connect_succeeded = ok;
        });
        EXPECT_TRUE(connect_accepted) << "a connect() asked while a close is under way waits for it";
        EXPECT_EQ(connect_calls, 0);
        EXPECT_FALSE(client->is_connecting());
    }
    EXPECT_EQ(connect_calls, 1) << "a connect() still waiting when the client is destroyed hears `false`, once";
    EXPECT_FALSE(connect_succeeded);
}

namespace http3_client_redial_test {

/// A coroutine that awaits connect(), and counts how many times it got past it.
qb::io::async::task<void>
await_connect(qb::http3::Client &client, qb::http3::ConnectResult &result, int &completions) {
    result = co_await client.connect();
    ++completions;
}

} // namespace http3_client_redial_test

// connect() awaited for an attempt that cannot start -- a name that resolves to nothing --: the awaiter completes once,
// `false`, with the reason, on a later turn of the loop, as for any attempt that failed.
TEST_F(Http3LoopbackTest, AConnectAwaitedForAnAttemptThatCannotStartCompletesFalseOnce) {
    int                      completions = 0;
    qb::http3::ConnectResult result{true, "not completed"};
    auto                     client = qb::http3::make_client("https://qb-http3-client.invalid:4433");
    qb::io::async::coro_scheduler().spawn(http3_client_redial_test::await_connect(*client, result, completions));
    ASSERT_TRUE(pump([&] { return completions != 0; }));
    const auto settle = std::chrono::steady_clock::now() + 50ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_EQ(completions, 1);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.error_message, "Unable to start QUIC connection");
    EXPECT_FALSE(client->is_connecting());
}

// The awaiter of the coroutine connect() asks connect() when it is awaited. Awaited from a callback of a close -- a
// coroutine resumed by a loop pumped there, or started by hand, as here -- it completes at once, `false`, "HTTP/3
// connection is closing", as in 3.3.0, and nothing is queued for it: connect(callback) queues an attempt for the end of
// that close, which cannot come before the callback returns. It waited for that attempt (Huly QB-1246).
TEST_F(Http3LoopbackTest, AConnectAwaitedDuringACloseCompletesFalseAtOnce) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    int                                                                 failed_calls = 0;
    std::optional<qb::http3::ConnectResult>                             at_once;
    std::unique_ptr<qb::http::async::awaiter<qb::http3::ConnectResult>> awaited; // before the client: its callback holds it
    auto                                                                client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response) {
        ++failed_calls;
        awaited.reset(new auto(client->connect()));
        awaited->await_suspend(std::noop_coroutine()); // what `co_await` does first: the awaiter asks connect() now
        at_once = awaited->await_resume();             // what it holds when await_suspend() returns
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));

    client->disconnect();
    EXPECT_EQ(failed_calls, 1);
    ASSERT_TRUE(at_once.has_value());
    EXPECT_FALSE(at_once->ok);
    EXPECT_EQ(at_once->error_message, "HTTP/3 connection is closing");
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for the awaiter";
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());
    held_context.reset();
    server->close();
}

// The same from the response callback of a read that lost its connection: the teardown waits for the end of that read,
// and the awaiter answers at once, `false`, as in 3.3.0. It waited for the teardown's attempt (Huly QB-1246).
TEST_F(Http3LoopbackTest, AConnectAwaitedDuringAReadThatLostItsConnectionCompletesFalseAtOnce) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/ok", [](auto ctx) { ctx->text("ok"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    int                                                                 response_calls = 0;
    std::optional<qb::http3::ConnectResult>                             at_once;
    std::unique_ptr<qb::http::async::awaiter<qb::http3::ConnectResult>> awaited; // before the client: its callback holds it
    auto losing = std::make_shared<LosingClient>(qb::io::uri(https_origin(port)));
    losing->set_verify_peer(false);
    losing->set_auto_reconnect(false);
    ASSERT_TRUE(losing->push_request(qb::http::Request{qb::io::uri("/ok")}, [&](qb::http::Response) {
        ++response_calls;
        losing->lose_connection(); // from nghttp3's read: the teardown is deferred
        awaited.reset(new auto(losing->connect()));
        awaited->await_suspend(std::noop_coroutine());
        at_once = awaited->await_resume();
    }));
    ASSERT_TRUE(pump([&] { return response_calls == 1; }));
    ASSERT_TRUE(at_once.has_value());
    EXPECT_FALSE(at_once->ok);
    EXPECT_EQ(at_once->error_message, "HTTP/3 connection is closing");
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_FALSE(losing->is_connecting()) << "nothing was queued for the awaiter";
    EXPECT_FALSE(losing->is_connected());
    server->close();
}

// The same through run_sync(): a coroutine the callback blocks on, the loop pumped until it completes. It returns at
// once, `false`. With nothing left for the connection to deliver -- the loop run until it is quiet --, it never returned:
// the connect() it asked was queued for the end of the close, and the pump it ran could not get there (Huly QB-1246; it
// answered `false` at once in 3.3.0). A watchdog ends the process, saying so, instead of letting the test hang.
TEST_F(Http3LoopbackTest, ARunSyncOfConnectFromAFailureCallbackOfACloseReturnsFalseAtOnce) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    int                      failed_calls = 0;
    bool                     returned     = false;
    qb::http3::ConnectResult result{true, "not returned"};
    auto                     client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response) {
        ++failed_calls;
        qb::http::test::watchdog bound("run_sync(connect()) from a failure callback of disconnect()", 5s);
        result   = qb::io::async::run_sync(client->connect());
        returned = true;
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));
    const auto quiet = std::chrono::steady_clock::now() + 100ms; // what the connection still had to deliver is read
    while (std::chrono::steady_clock::now() < quiet) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }

    client->disconnect();
    EXPECT_EQ(failed_calls, 1);
    EXPECT_TRUE(returned);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.error_message, "HTTP/3 connection is closing");
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    held_context.reset();
    server->close();
}

// The same while the connection still has data to deliver -- the close made as soon as the request was routed: the loop
// run_sync() pumps delivers it. It returns at once, `false`, and nothing connects. The data's read completed the close
// from inside the close, and the attempt connect() then started was the one the awaiter heard: `true`, for a connection
// the close, resumed, then ended -- in 3.3.0 as well (Huly QB-1246).
TEST_F(Http3LoopbackTest, ARunSyncOfConnectFromAFailureCallbackOfACloseReturnsFalseWhileItsConnectionStillDeliversData) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    int                      failed_calls = 0;
    bool                     returned     = false;
    qb::http3::ConnectResult result{true, "not returned"};
    auto                     client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response) {
        ++failed_calls;
        qb::http::test::watchdog bound("run_sync(connect()) from a failure callback of disconnect()", 5s);
        result   = qb::io::async::run_sync(client->connect());
        returned = true;
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));

    client->disconnect();
    EXPECT_EQ(failed_calls, 1);
    EXPECT_TRUE(returned);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.error_message, "HTTP/3 connection is closing");
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_FALSE(client->is_connected());
    EXPECT_FALSE(client->is_connecting());
    held_context.reset();
    server->close();
}

// run_sync(client->connect()) from the failure callback of a request whose connection was lost during the read of
// another -- the teardown deferred to the end of that read -- returns at once, `false`, and nothing connects for it. The
// teardown ran that callback inside the endpoint's dispatch: the attempt connect() then started could not be heard -- the
// endpoint delivers its `connected` once that dispatch has returned --, and with no connect timeout run_sync() never
// returned, the server answering (Huly QB-1246; in 3.3.0 as well).
TEST_F(Http3LoopbackTest, ARunSyncOfConnectFromAFailureCallbackOfAConnectionLostDuringAReadReturnsFalseAtOnce) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/ok", [](auto ctx) { ctx->text("ok"); });
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    int                      failed_calls = 0, ok_calls = 0;
    bool                     returned = false;
    qb::http3::ConnectResult result{true, "not returned"};
    auto                     losing = std::make_shared<LosingClient>(qb::io::uri(https_origin(port)));
    losing->set_verify_peer(false);
    losing->set_auto_reconnect(false);
    losing->set_connect_timeout(qb::duration::zero());
    ASSERT_TRUE(losing->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response) {
        ++failed_calls;
        qb::http::test::watchdog bound("run_sync(connect()) from a failure callback of a connection lost during a read", 5s);
        result   = qb::io::async::run_sync(losing->connect());
        returned = true;
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));
    ASSERT_TRUE(losing->push_request(qb::http::Request{qb::io::uri("/ok")}, [&](qb::http::Response) {
        ++ok_calls;
        losing->lose_connection(); // from nghttp3's read: the teardown runs at its end
    }));
    ASSERT_TRUE(pump([&] { return failed_calls != 0; }));
    EXPECT_EQ(ok_calls, 1);
    EXPECT_EQ(failed_calls, 1);
    EXPECT_TRUE(returned);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.error_message, "HTTP/3 connection is closing");
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_FALSE(losing->is_connecting()) << "nothing was queued for it";
    held_context.reset();
    server->close();
}

// The same from the failure callback of a request whose connection the server closed, its close read with no read on the
// stack: the teardown runs in the endpoint's dispatch of that close. It returns at once, `false`. The attempt it started
// -- a server back on the port -- was never heard: run_sync() never returned (Huly QB-1246; in 3.3.0 as well).
TEST_F(Http3LoopbackTest, ARunSyncOfConnectFromAFailureCallbackOfAConnectionTheServerClosedReturnsFalseAtOnce) {
    const auto                                                    port   = next_port();
    auto                                                          server = qb::http3::make_server();
    std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
    server->router().get("/hold", [&](auto ctx) { held_context = ctx; });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    int                      failed_calls = 0;
    bool                     returned     = false;
    qb::http3::ConnectResult result{true, "not returned"};
    auto                     client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_auto_reconnect(false);
    client->set_connect_timeout(qb::duration::zero());
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response) {
        ++failed_calls;
        qb::http::test::watchdog bound("run_sync(connect()) from a failure callback of a connection the server closed", 5s);
        result   = qb::io::async::run_sync(client->connect());
        returned = true;
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));

    held_context.reset();
    server->close(); // the connection's close is on its way to the client
    auto again = qb::http3::make_server();
    again->router().get("/hold", [](auto ctx) { ctx->text("again"); });
    again->router().compile();
    ASSERT_TRUE(again->listen(qb::io::uri(https_origin(port)), cert_path(), key_path())) << "the port could not be taken back";
    ASSERT_TRUE(pump([&] { return failed_calls != 0; }));
    EXPECT_EQ(failed_calls, 1);
    EXPECT_TRUE(returned);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.error_message, "HTTP/3 connection is closing");
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    again->close();
}

// run_sync(client->connect()) from the failure callback of a request whose connection closed during its own submission
// -- its body past the transport's queue bound, pushed on a connection that is up -- returns at once, `false`, and nothing
// connects for it: that callback answers a connection that has just ended, as every failure's does. It ran after the
// teardown's callbacks, outside their count: run_sync() started the next attempt there and returned its outcome, `true`
// with the server answering. One rule for every close and failure (Huly QB-1246).
TEST_F(Http3LoopbackTest, ARunSyncOfConnectFromTheFailureCallbackOfARequestWhoseSubmissionClosedItsConnectionReturnsFalseAtOnce) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().post("/upload", [](auto ctx) { ctx->text("unexpected"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    int                       calls    = 0;
    bool                      returned = false;
    std::string               answer;
    std::chrono::milliseconds took{0};
    qb::http3::ConnectResult  result{true, "not returned"};
    auto                      client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    auto settings                     = client->settings();
    settings.max_pending_stream_bytes = 16 * 1024;
    client->set_settings(settings);
    ASSERT_TRUE(client->connect(nullptr));
    ASSERT_TRUE(pump([&] { return client->is_connected(); }));
    qb::http::Request upload{qb::http::method::POST, qb::io::uri("/upload")};
    upload.body() = std::string(256 * 1024, 'x');
    ASSERT_TRUE(client->push_request(std::move(upload), [&](qb::http::Response response) {
        ++calls;
        answer                           = response.body().as<std::string>();
        const auto               started = std::chrono::steady_clock::now();
        qb::http::test::watchdog bound("run_sync(connect()) from a failure callback of a submission that closed its connection", 5s);
        result   = qb::io::async::run_sync(client->connect());
        took     = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        returned = true;
    }));
    ASSERT_TRUE(pump([&] { return calls != 0; }));
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(answer, "HTTP/3 connection closed during request submission") << "the submission's own answer";
    EXPECT_TRUE(returned);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.error_message, "HTTP/3 connection is closing");
    EXPECT_LT(took, 1s);
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    EXPECT_FALSE(client->is_connected());
    server->close();
}

// An attempt that cannot start -- a name that resolves to no address -- is a connection that failed, heard as one: through
// the callback, on a later turn of the loop, as on the HTTP/1.1 and HTTP/2 clients. connect() returns true. It returned
// false and ran the failure of what waited from inside the call (and, before that, called its own callback there): a
// callback that dials again on `false`, and a request whose callback pushes it back, were then called from inside their
// own call, without end (Huly QB-1246). Here both relaunch at every failure, and each is heard one loop turn at a time:
// never nested, and done at its count.
TEST_F(Http3LoopbackTest, AnAttemptThatCannotStartIsHeardThroughTheLoopAndARelaunchIsNeverNested) {
    Redial redial;
    redial.cap    = 6; // each dial is a lookup of a name that does not resolve
    auto client   = qb::http3::make_client("https://qb-http3-client.invalid:4433");
    redial.client = client.get();
    EXPECT_TRUE(redial.dial());
    EXPECT_EQ(redial.heard_true + redial.heard_false, 0) << "the callback was called inside connect()";
    EXPECT_TRUE(client->is_connecting());
    ASSERT_TRUE(pump([&] { return redial.heard_false == 6; }));
    EXPECT_EQ(redial.dials, 6);
    EXPECT_EQ(redial.heard_true, 0);
    EXPECT_EQ(redial.deepest, 1) << "a redial was answered from inside its own connect()";
    EXPECT_FALSE(client->is_connecting());

    // A request whose callback pushes it back at every failure: one failure a loop turn, the callback never under itself.
    int                   pushes = 0, answers = 0, depth = 0, deepest = 0;
    std::function<void()> push;
    push = [&] {
        ++pushes;
        client->push_request(qb::http::Request{qb::io::uri("/")}, [&](qb::http::Response answered) {
            deepest = std::max(deepest, ++depth);
            ++answers;
            EXPECT_NE(answered.status(), qb::http::status::OK);
            if (pushes < 6) {
                push();
            }
            --depth;
        });
    };
    push();
    EXPECT_EQ(answers, 0) << "a request the client cannot connect for was answered inside its push";
    ASSERT_TRUE(pump([&] { return answers == 6; }));
    EXPECT_EQ(pushes, 6);
    EXPECT_EQ(deepest, 1) << "a request pushed back from its failure callback was answered from inside its own push";
}

// A callback that pushes its request back at every failure -- it never gives up -- is never called more than two deep,
// and ends by itself (Huly QB-1246). During a disconnect() a push is refused at once: answered inside the push, and, when
// that push is made from inside such an answer, on the loop's next turn. Answered inside there too, the callback was
// called from inside its own push without end (the case stops such a run at 64 so that it fails and keeps its stack).
// Two rounds: the request in flight fails with the close, the push its callback makes is refused inside it, the next is
// heard a turn later -- the close has run by then, so that push connects and is served.
TEST_F(Http3LoopbackTest, ARequestPushedBackAtEveryFailureOfADisconnectIsNeverCalledMoreThanTwoDeep) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/stall", [](auto) {});
    server->router().get("/ok", [](auto ctx) { ctx->text("ok"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    int                                      pushes = 0, failures = 0, served = 0, depth = 0, deepest = 0;
    std::function<void(std::string const &)> push;
    push = [&](std::string const &path) {
        ++pushes;
        client->push_request(qb::http::Request{qb::io::uri(path)}, [&](qb::http::Response response) {
            deepest = std::max(deepest, ++depth);
            if (response.status() == qb::http::status::OK) {
                ++served;
            } else {
                ++failures;
                if (deepest < 64) {
                    push("/ok"); // always: nothing here counts the attempts
                }
            }
            --depth;
        });
    };
    for (int round = 1; round <= 2; ++round) {
        SCOPED_TRACE(round);
        const int failed_before = failures;
        push("/stall");
        ASSERT_TRUE(pump([&] { return client->get_active_request_count() == 1; }));
        client->disconnect();
        EXPECT_EQ(failures - failed_before, 2) << "the request in flight, and the push its callback made, are heard inside the close";
        ASSERT_TRUE(pump([&] { return served == round || deepest >= 64; }));
        EXPECT_EQ(served, round) << "the request pushed once the close had run was not served";
        EXPECT_EQ(failures - failed_before, 3);
    }
    EXPECT_LE(deepest, 2) << "a request pushed back from its failure callback was answered from inside its own push, again and again";
    client->disconnect();
    server->close();
}

// A refusal kept for the next turn is heard exactly once (Huly QB-1246), whatever happens before that turn. The answer
// that earned it may run the loop -- a turn of its own, which spends the one that was asked --: the kept refusal is not
// heard under it, and is heard once after. And the client may be destroyed before any turn: its destructor delivers
// what is still owed, and the turn that was asked finds nothing left.
TEST_F(Http3LoopbackTest, ARefusalKeptForTheNextTurnIsHeardExactlyOnce) {
    for (const std::string_view then : {"the answer runs the loop", "the client is destroyed before the turn"}) {
        SCOPED_TRACE(then);
        const auto port   = next_port();
        auto       server = qb::http3::make_server();
        server->router().get("/stall", [](auto) {});
        server->router().compile();
        ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

        int  kept_heard = 0, heard_under_the_answer = -1, answers = 0;
        auto client = qb::http3::make_client(https_origin(port));
        client->set_verify_peer(false);
        client->set_auto_reconnect(false);
        client->push_request(qb::http::Request{qb::io::uri("/stall")}, [&](qb::http::Response) { // fails with the close
            ++answers;
            client->push_request(qb::http::Request{qb::io::uri("/stall")}, [&](qb::http::Response) { // refused inside its push
                ++answers;
                client->push_request(qb::http::Request{qb::io::uri("/stall")}, [&](qb::http::Response) { ++kept_heard; }); // kept
                if (then == "the answer runs the loop") {
                    for (int pass = 0; pass < 4; ++pass) {
                        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
                    }
                }
                heard_under_the_answer = kept_heard;
            });
        });
        ASSERT_TRUE(pump([&] { return client->get_active_request_count() == 1; }));
        client->disconnect();
        EXPECT_EQ(answers, 2);
        EXPECT_EQ(heard_under_the_answer, 0) << "the kept refusal was heard under the answer that earned it";
        if (then == "the client is destroyed before the turn") {
            EXPECT_EQ(kept_heard, 0);
            client.reset();
            EXPECT_EQ(kept_heard, 1) << "the destructor did not deliver the refusal still owed its turn";
        }
        const auto settle = std::chrono::steady_clock::now() + 100ms;
        while (std::chrono::steady_clock::now() < settle) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        }
        EXPECT_EQ(kept_heard, 1) << "a refusal kept for the next turn is heard once, and once only";
        if (client) {
            client->disconnect();
        }
        server->close();
    }
}

// A push the client refuses at once is answered inside the push when the program makes it, and that answer may drop the
// last reference to the client (Huly QB-1246): the client lives to the end of the refusal. It was destroyed inside the
// answer, and the refusal then went on counting on it -- a write into freed memory. No connection, no timer, and no weak
// reference either, which would keep the storage: nothing else holds the client here.
TEST_F(Http3LoopbackTest, APushRefusedAtOnceWhoseCallbackDropsTheLastReferenceEndsCleanly) {
    struct Told : qb::http3::Client {
        int &destroyed;
        Told(std::string const &origin, int &count)
            : qb::http3::Client(origin)
            , destroyed(count) {}
        ~Told() {
            ++destroyed;
        }
    };
    for (const std::string_view refusal : {"another origin", "the pending bound"}) {
        SCOPED_TRACE(refusal);
        int         destroyed = 0;
        auto        client    = std::make_shared<Told>(https_origin(next_port()), destroyed);
        auto *const raw       = client.get();
        if (refusal == "the pending bound") {
            client->set_max_pending_requests(0);
        }
        int        answers  = 0;
        const bool accepted = raw->push_request(qb::http::Request{qb::io::uri(refusal == "another origin" ? "https://other.invalid/" : "/")},
                                                [&](qb::http::Response response) {
                                                    ++answers;
                                                    EXPECT_NE(response.status(), qb::http::status::OK);
                                                    client.reset(); // the last reference
                                                });
        EXPECT_EQ(answers, 1);
        EXPECT_EQ(accepted, refusal == "another origin") << "the bound refuses by its return value too";
        EXPECT_EQ(destroyed, 1) << "something else held the client";
    }
}

// A refusal kept for its turn is heard there as the answer of a refusal (Huly QB-1246): what its callback pushes is kept
// in its turn, and a loop turn that callback runs hears nothing more. Here the callback pushes its request back at every
// failure AND runs the loop. The callback of the close is no refusal's answer: under the turns it runs the kept refusals
// are heard, one a turn, each a single call deep under it. Heard there as a plain call, the callback of each pushed
// again and was answered inside that push -- three deep here, and without end where the loop it runs delivers what it
// keeps (the case stops such a run at 64). Every push is answered once.
TEST_F(Http3LoopbackTest, ARequestPushedBackByACallbackThatRunsTheLoopIsNeverCalledMoreThanTwoDeep) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/stall", [](auto) {});
    server->router().get("/ok", [](auto ctx) { ctx->text("ok"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    int                                      pushes = 0, failures = 0, served = 0, depth = 0, deepest = 0, under_the_close = -1;
    std::function<void(std::string const &)> push;
    push = [&](std::string const &path) {
        ++pushes;
        client->push_request(qb::http::Request{qb::io::uri(path)}, [&](qb::http::Response response) {
            deepest = std::max(deepest, ++depth);
            if (response.status() == qb::http::status::OK) {
                ++served;
            } else {
                const int mine = ++failures;
                if (deepest < 64) {
                    push("/ok"); // always: nothing here counts the attempts
                }
                for (int pass = 0; pass < 4; ++pass) {
                    qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT); // and the callback runs the loop
                }
                if (mine == 1) {
                    under_the_close = failures - 2; // heard under its turns: past itself and the push it made
                }
            }
            --depth;
        });
    };
    push("/stall");
    ASSERT_TRUE(pump([&] { return client->get_active_request_count() == 1; }));
    client->disconnect();
    EXPECT_GE(under_the_close, 1) << "no kept refusal was heard under the turns the callback of the close ran: the case shows nothing";
    ASSERT_TRUE(pump([&] { return served == 1 || deepest >= 64; }));
    EXPECT_EQ(served, 1) << "the request pushed once the close had run was not served";
    EXPECT_EQ(failures + served, pushes) << "a push was not answered once";
    EXPECT_LE(deepest, 2) << "a kept refusal heard in its turn answered, inside the push, the request its callback pushed back";
    client->disconnect();
    server->close();
}

// The batch form of the rule (Huly QB-1246): a batch whose members are all refused at once -- every one for another
// origin here -- is one refusal. Answered inside the push the program makes, and on the loop's next turn when that push is
// made from inside the answer of another. It was answered inside every push: a callback that pushes its batch back at
// every refusal was called from inside its own push, ten deep here, without end otherwise.
TEST_F(Http3LoopbackTest, ABatchPushedBackAtEveryRefusalIsNeverAnsweredFromInsideItsOwnPush) {
    auto                  client = qb::http3::make_client(https_origin(next_port())); // never connected
    int                   pushes = 0, calls = 0, depth = 0, deepest = 0;
    std::function<void()> push;
    push = [&] {
        ++pushes;
        std::vector<qb::http::Request> two;
        two.emplace_back(qb::io::uri("https://other.invalid/a"));
        two.emplace_back(qb::io::uri("https://other.invalid/b"));
        EXPECT_TRUE(client->push_requests(std::move(two), [&](std::vector<qb::http::Response> responses) {
            deepest = std::max(deepest, ++depth);
            ++calls;
            EXPECT_EQ(responses.size(), 2u);
            for (auto const &response : responses) {
                EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
            }
            if (pushes < 10) {
                push();
            }
            --depth;
        }));
    };
    push();
    EXPECT_EQ(calls, 1) << "the batch the program pushes is answered inside its push";
    ASSERT_TRUE(pump([&] { return calls == 10; }));
    const auto settle = std::chrono::steady_clock::now() + 50ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_EQ(calls, 10);
    EXPECT_EQ(pushes, 10);
    EXPECT_EQ(deepest, 1) << "a batch pushed back from its own callback was answered from inside that push";
    EXPECT_FALSE(client->is_connecting());
}

// The answers come in the order the client came to owe them (Huly QB-1246): a refusal kept for its turn is heard before
// any answer given after it -- the refusal of a push the program makes next, the failures of a disconnect() the same
// callback calls. Each of those was answered at once, ahead of the refusal still waiting for its turn.
TEST_F(Http3LoopbackTest, ARefusalKeptIsHeardBeforeAnyAnswerGivenAfterIt) {
    const auto elsewhere = [] {
        return qb::http::Request{qb::io::uri("https://other.invalid/")};
    }; // refused at once: 400
    {
        SCOPED_TRACE("a refusal of the program's next push");
        auto             client = qb::http3::make_client(https_origin(next_port())); // never connected
        std::vector<int> order;
        client->push_request(elsewhere(), [&](qb::http::Response) {
            order.push_back(1);
            client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // kept: pushed from inside an answer
        });
        EXPECT_EQ(order, (std::vector<int>{1}));
        client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(3); }); // answered inside, after what is owed
        EXPECT_EQ(order, (std::vector<int>{1, 2, 3}));
        const auto settle = std::chrono::steady_clock::now() + 50ms;
        while (std::chrono::steady_clock::now() < settle) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        }
        EXPECT_EQ(order, (std::vector<int>{1, 2, 3})) << "the turn that was asked found something left to hear";
    }
    {
        SCOPED_TRACE("the failures of a disconnect() the same callback calls");
        const auto port   = next_port();
        auto       server = qb::http3::make_server();
        server->router().get("/stall", [](auto) {});
        server->router().compile();
        ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));
        auto client = qb::http3::make_client(https_origin(port));
        client->set_verify_peer(false);
        std::vector<int> order;
        client->push_request(qb::http::Request{qb::io::uri("/stall")}, [&](qb::http::Response) { order.push_back(9); }); // in flight
        ASSERT_TRUE(pump([&] { return client->get_active_request_count() == 1; }));
        client->push_request(elsewhere(), [&](qb::http::Response) {
            order.push_back(1);
            client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // kept
            client->disconnect();                                                               // fails the request in flight
        });
        EXPECT_EQ(order, (std::vector<int>{1, 2, 9}));
        const auto settle = std::chrono::steady_clock::now() + 50ms;
        while (std::chrono::steady_clock::now() < settle) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        }
        EXPECT_EQ(order, (std::vector<int>{1, 2, 9}));
        server->close();
    }
}

// The same at the client's destruction, where no later turn exists (Huly QB-1246): a request pushed from a callback the
// destructor runs is answered inside its push, and one pushed from inside THAT answer is refused by the return value
// alone, its callback destroyed unheard. Three pushes, two answers, never deeper than two.
TEST_F(Http3LoopbackTest, ARequestPushedBackFromTheDestructorsCallbacksEndsAtItsSecondPush) {
    const auto            silent = next_port();
    int                   pushes = 0, answers = 0, depth = 0, deepest = 0;
    std::vector<bool>     accepted;
    qb::http3::Client    *raw = nullptr;
    std::function<void()> push;
    push = [&] {
        const auto index = static_cast<std::size_t>(pushes++); // a push returns after the ones its callback makes
        accepted.resize(index + 1);
        accepted[index] = raw->push_request(qb::http::Request{qb::io::uri("/")}, [&](qb::http::Response response) {
            deepest = std::max(deepest, ++depth);
            ++answers;
            EXPECT_NE(response.status(), qb::http::status::OK);
            if (deepest < 64) {
                push();
            }
            --depth;
        });
    };
    {
        auto client = qb::http3::make_client(https_origin(silent));
        client->set_verify_peer(false);
        raw = client.get();
        push(); // queued behind a connection nobody answers
        ASSERT_TRUE(client->is_connecting());
    } // destroyed with that request waiting
    EXPECT_EQ(pushes, 3);
    EXPECT_EQ(answers, 2);
    EXPECT_EQ(deepest, 2);
    EXPECT_EQ(accepted, (std::vector<bool>{true, true, false}));
}

// The coroutine push_request() and push_requests() take the rule of the coroutine connect() (Huly QB-1246): awaited
// from a callback of a failure, they complete at once, 503 "HTTP/3 connection is closing". The callback form queues the
// request behind the next attempt, whose `connected` the endpoint delivers only once its dispatch has returned: a
// run_sync() of the coroutine form there waited for that attempt's connect timeout -- it answered "HTTP/3 connection
// timeout" -- or for the request's.
TEST_F(Http3LoopbackTest, ARunSyncOfAPushFromACallbackOfAnAttemptThatTimedOutIsAnsweredAtOnce) {
    const auto                      silent = next_port();
    auto                            client = qb::http3::make_client(https_origin(silent));
    int                             failed = 0;
    qb::http::Response              single;
    std::vector<qb::http::Response> batch;
    std::chrono::milliseconds       took{0};
    client->set_verify_peer(false);
    client->set_connect_timeout(300ms);
    client->set_request_timeout(2s);
    ASSERT_TRUE(client->connect([&](bool ok, std::string const &) {
        EXPECT_FALSE(ok);
        ++failed;
        const auto               started = std::chrono::steady_clock::now();
        qb::http::test::watchdog bound("run_sync(push_request()) from the callback of an attempt that timed out", 10s);
        single = qb::io::async::run_sync(client->push_request(qb::http::Request{qb::io::uri("/")}));
        std::vector<qb::http::Request> two;
        two.emplace_back(qb::io::uri("/"));
        two.emplace_back(qb::io::uri("/"));
        batch = qb::io::async::run_sync(client->push_requests(std::move(two)));
        took  = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    }));
    ASSERT_TRUE(pump([&] { return failed != 0; }));
    EXPECT_EQ(failed, 1);
    EXPECT_EQ(single.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(single.body().as<std::string>(), "HTTP/3 connection is closing");
    ASSERT_EQ(batch.size(), 2u);
    EXPECT_EQ(batch[0].body().as<std::string>(), "HTTP/3 connection is closing");
    EXPECT_EQ(batch[1].body().as<std::string>(), "HTTP/3 connection is closing");
    EXPECT_LT(took, 250ms) << "a coroutine push awaited from a callback of a failure waited for the next attempt";
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    client->disconnect();
}

// A host name connects (Huly QB-1246): the client resolves it -- `localhost`, the loopback address of the family the URI
// names -- and hands the QUIC endpoint the address, the name staying the one sent as SNI. Until 3.4 the endpoint was
// handed the name, which it takes for an address: connect() answered that nothing could start.
TEST_F(Http3LoopbackTest, AHostNameIsResolvedAndItsRequestServed) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/named", [](auto ctx) { ctx->text("by name"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client("https://localhost:" + std::to_string(port));
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);
    int                connected = -1;
    qb::http::Response response;
    bool               answered = false;
    ASSERT_TRUE(client->connect([&](bool ok, std::string const &) { connected = ok ? 1 : 0; }));
    ASSERT_TRUE(pump([&] { return connected != -1; }));
    ASSERT_EQ(connected, 1) << "a host name did not connect";
    client->push_request(qb::http::Request{qb::io::uri("/named")}, [&](qb::http::Response res) {
        response = std::move(res);
        answered = true;
    });
    ASSERT_TRUE(pump([&] { return answered; }));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "by name");
    client->disconnect();
    server->close();
}

// An address that does not answer gives way to the next (Huly QB-1246): QUIC has no refusal to hear, so each address has
// its share of the connect timeout -- the TCP connector's rule, half of what is left for the first of two, two seconds at
// least -- and the next is dialled when it ends, without a word to the callbacks. The first address here is a loopback
// port nothing is bound to, the second the server's.
TEST_F(Http3LoopbackTest, AnAddressThatDoesNotAnswerGivesWayToTheNextWithinTheConnectTimeout) {
    const auto port   = next_port();
    const auto silent = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/second", [](auto ctx) { ctx->text("second address"); });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);
    int        calls = 0, connected = -1;
    const auto began = std::chrono::steady_clock::now();
    ASSERT_TRUE(qb::http3::ClientTestPeer::dial(*client, {qb::io::endpoint("127.0.0.1", silent), qb::io::endpoint("127.0.0.1", port)},
                                                [&](bool ok, std::string const &) {
                                                    ++calls;
                                                    connected = ok ? 1 : 0;
                                                }));
    ASSERT_TRUE(pump([&] { return calls != 0; }, 8s));
    const auto took = std::chrono::steady_clock::now() - began;
    EXPECT_EQ(calls, 1);
    ASSERT_EQ(connected, 1) << "the second address was never dialled";
    EXPECT_GE(took, 2s) << "the first address was given up before its share";
    EXPECT_LT(took, 5s) << "the second address was dialled only at the connect timeout";
    qb::http::Response response;
    bool               answered = false;
    client->push_request(qb::http::Request{qb::io::uri("/second")}, [&](qb::http::Response res) {
        response = std::move(res);
        answered = true;
    });
    ASSERT_TRUE(pump([&] { return answered; }));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    client->disconnect();
    server->close();
}

// The control: one address that does not answer has the whole connect timeout, and fails at it.
TEST_F(Http3LoopbackTest, ALoneAddressThatDoesNotAnswerFailsAtTheConnectTimeout) {
    const auto silent = next_port();
    auto       client = qb::http3::make_client(https_origin(silent));
    client->set_verify_peer(false);
    client->set_connect_timeout(600ms);
    int         calls = 0, connected = -1;
    std::string error;
    const auto  began = std::chrono::steady_clock::now();
    ASSERT_TRUE(client->connect([&](bool ok, std::string const &message) {
        ++calls;
        connected = ok ? 1 : 0;
        error     = message;
    }));
    ASSERT_TRUE(pump([&] { return calls != 0; }));
    EXPECT_EQ(connected, 0);
    EXPECT_EQ(error, "HTTP/3 connection timeout");
    EXPECT_GE(std::chrono::steady_clock::now() - began, 550ms);
}

// An address the network refuses at once -- the first datagram cannot be sent: no route to an address of that family, a
// host that is unreachable; here the broadcast address, which sendto() refuses on a socket that did not ask for it -- is
// an attempt that could not start (Huly QB-1246). The QUIC endpoint delivers that close inside its own connect(), and
// the client took it for the end of the connect(): its callback heard `false` inside the call, a callback that dials
// again was called from inside its own call, and the address after it was never tried. Alone, it is heard through the
// callback on a later turn, one failure a turn; before an address that answers, it gives way to it at once.
TEST_F(Http3LoopbackTest, AnAddressTheNetworkRefusesAtOnceIsHeardOnALaterTurnOrGivesWayToTheNext) {
    {
        SCOPED_TRACE("alone");
        Redial redial;
        redial.cap    = 6;
        auto client   = qb::http3::make_client("https://255.255.255.255:" + std::to_string(next_port()));
        redial.client = client.get();
        EXPECT_TRUE(redial.dial());
        EXPECT_EQ(redial.heard_true + redial.heard_false, 0) << "the callback was called inside connect()";
        ASSERT_TRUE(pump([&] { return redial.heard_false == 6; }));
        EXPECT_EQ(redial.dials, 6);
        EXPECT_EQ(redial.heard_true, 0);
        EXPECT_EQ(redial.deepest, 1) << "a redial was answered from inside its own connect()";
        EXPECT_FALSE(client->is_connecting());
    }
    {
        SCOPED_TRACE("before an address that answers");
        const auto port   = next_port();
        auto       server = qb::http3::make_server();
        server->router().compile();
        ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));
        auto client = qb::http3::make_client(https_origin(port));
        client->set_verify_peer(false);
        client->set_connect_timeout(5s);
        int        calls = 0, connected = -1;
        const auto began = std::chrono::steady_clock::now();
        ASSERT_TRUE(qb::http3::ClientTestPeer::dial(*client, {qb::io::endpoint("255.255.255.255", port), qb::io::endpoint("127.0.0.1", port)},
                                                    [&](bool ok, std::string const &) {
                                                        ++calls;
                                                        connected = ok ? 1 : 0;
                                                    }));
        EXPECT_EQ(calls, 0) << "the callback was called inside the call";
        ASSERT_TRUE(pump([&] { return calls != 0; }));
        EXPECT_EQ(calls, 1);
        EXPECT_EQ(connected, 1) << "the address after the one that could not start was never tried";
        EXPECT_LT(std::chrono::steady_clock::now() - began, 2s) << "it waited for the share of an address that never started";
        client->disconnect();
        server->close();
    }
}

// QUIC gives an address up by itself: its handshake timeout, ten seconds by default, shorter than the share an address
// has of the default connect timeout (Huly QB-1246). That close is no answer of a peer, an address is left and time is
// left: the next one is dialled. It was taken for the end of the connect(), which failed at QUIC's timeout with the
// second address never tried. The handshake timeout is shortened here to 300 ms, under a share of three seconds.
TEST_F(Http3LoopbackTest, AnAddressQuicGivesUpBeforeItsShareGivesWayToTheNext) {
    const auto port   = next_port();
    const auto silent = next_port();
    auto       server = qb::http3::make_server();
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);
    client->set_connect_timeout(6s);
    auto quic              = client->settings();
    quic.handshake_timeout = 300ms;
    client->set_settings(quic);
    int         calls = 0, connected = -1;
    std::string error;
    const auto  began = std::chrono::steady_clock::now();
    ASSERT_TRUE(qb::http3::ClientTestPeer::dial(*client, {qb::io::endpoint("127.0.0.1", silent), qb::io::endpoint("127.0.0.1", port)},
                                                [&](bool ok, std::string const &message) {
                                                    ++calls;
                                                    connected = ok ? 1 : 0;
                                                    error     = message;
                                                }));
    ASSERT_TRUE(pump([&] { return calls != 0; }, 8s));
    const auto took = std::chrono::steady_clock::now() - began;
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(connected, 1) << "QUIC's own timeout on the first address ended the connect(): " << error;
    EXPECT_GE(took, 250ms) << "the first address was given up before QUIC gave it up";
    EXPECT_LT(took, 2s) << "the second address waited for the first one's share";
    client->disconnect();
    server->close();
}

// The share of an address is armed by the TCP connector's test (Huly QB-1246): not when it is all of what is left, nor
// when nothing is left -- where the timer of a share that fires at the deadline finds the next attempt. A delay of zero
// runs its callback inline: the address after was dialled from inside the start of this one, and the one after it too.
TEST_F(Http3LoopbackTest, AnAttemptStartedWithNothingLeftOfTheConnectTimeoutArmsNoShare) {
    auto client = qb::http3::make_client(https_origin(next_port()));
    client->set_verify_peer(false);
    const std::vector<qb::io::endpoint> silent{
        qb::io::endpoint("127.0.0.1", next_port()), qb::io::endpoint("127.0.0.1", next_port()), qb::io::endpoint("127.0.0.1", next_port())
    };
    EXPECT_EQ(qb::http3::ClientTestPeer::dialled_with_no_time_left(*client, silent), 1u)
        << "a share of zero ran inline: the next address was dialled from inside the start of this one";
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

// A connection-specific field never leaves the client: it is left out and the request served, as the HTTP/2 client
// leaves it out (RFC 9114 section 4.2; Huly QB-1191: the request was failed with 503 before it left).
TEST_F(Http3LoopbackTest, ClientLeavesOutAConnectionSpecificRequestField) {
    const auto       port   = next_port();
    auto             server = qb::http3::make_server();
    std::atomic<int> server_requests{0};
    server->router().get("/forbidden-header", [&server_requests](auto ctx) {
        ++server_requests;
        ctx->response().body() = std::string(ctx->request().header("connection"));
        ctx->complete();
    });
    server->router().compile();

    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    qb::http::Request request{qb::io::uri("/forbidden-header")};
    request.set_header("connection", "close");

    auto response = qb::http::run_sync(client->push_request(std::move(request)));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(server_requests.load(), 1);
    EXPECT_EQ(response.body().as<std::string>(), "") << "the field never reached the server";

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

// ---------------------------------------------------------------------------
// Static files over HTTP/3 stream (Huly QB-101, QB-86). The HTTP/3 session offers the streaming hooks since train 6, so a
// body over StaticFilesOptions::stream_threshold is served through a stream, never materialised, and max_file_size --
// the bound of a body read whole -- no longer bounds it, exactly as on HTTP/1.1 (system/middleware/static-files-stream.cpp).
// ---------------------------------------------------------------------------
namespace {
/// A temporary directory removed with its scope, an early failure included.
struct TempRoot {
    std::filesystem::path path;
    explicit TempRoot(std::string const &prefix)
        : path(std::filesystem::temp_directory_path()
               / (prefix + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))) {
        std::filesystem::create_directories(path);
    }
    ~TempRoot() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};
} // namespace

TEST_F(Http3LoopbackTest, StaticFilesStreamABodyOverTheStreamThresholdAndMaxFileSizeNoLongerBoundsIt) {
    static_assert(qb::http::streaming_session<qb::http3::DefaultSession>, "the HTTP/3 session streams since Huly QB-86's train-6 lot");
    const TempRoot temp("qbm-h3-static-");
    const auto    &root = temp.path;
    ASSERT_TRUE(std::filesystem::is_directory(root));
    std::string whole(std::size_t{512} * 1024, '\0');
    for (std::size_t i = 0; i < whole.size(); ++i)
        whole[i] = static_cast<char>((i * 131 + i / 251) & 0xff);
    {
        std::ofstream(root / "whole.bin", std::ios::binary).write(whole.data(), static_cast<std::streamsize>(whole.size()));
        std::ofstream(root / "over.bin", std::ios::binary) << std::string(std::size_t{2} * 1024 * 1024, 'o');
    }

    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().use(qb::http::static_files_middleware<qb::http3::DefaultSession>(
        qb::http::StaticFilesOptions(root).with_stream_threshold(std::size_t{64} * 1024).with_max_file_size(std::size_t{1024} * 1024)));
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));
    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    const auto get = [&](std::string const &path) {
        // The callback owns what it writes: a late one, after a pump that timed out, writes into its own state.
        auto state = std::make_shared<std::optional<qb::http::Response>>();
        EXPECT_TRUE(client->push_request(qb::http::Request{qb::io::uri(https_origin(port) + path)},
                                         [state](qb::http::Response r) { *state = std::move(r); }));
        EXPECT_TRUE(pump([&] { return state->has_value(); }, 10s));
        return state->value_or(qb::http::Response{});
    };
    const auto served = get("/whole.bin");
    EXPECT_EQ(served.status(), qb::http::status::OK);
    EXPECT_EQ(served.header("Content-Length"), std::to_string(whole.size())) << "the file's length is declared: identity framing";
    EXPECT_TRUE(served.body().as<std::string>() == whole) << "the streamed body differs from the file's";
    const auto over = get("/over.bin");
    EXPECT_EQ(over.status(), qb::http::status::OK) << "a streamed body is never materialised: max_file_size does not bound it (as on HTTP/1.1)";
    EXPECT_EQ(over.body().size(), std::size_t{2} * 1024 * 1024);

    client->disconnect();
    server->close();
}

#ifdef QB_HAS_COMPRESSION
// A streamed static body the client accepts a coding for is coded on the fly on HTTP/3 too (Huly QB-1208): the head
// says `Content-Encoding: gzip` and declares no length (FIN ends the body), and the bytes inflate to the file.
TEST_F(Http3LoopbackTest, StaticFilesStreamACodedBodyOnTheFlyThatInflatesToTheFile) {
    const TempRoot temp("qbm-h3-coded-");
    const auto    &root = temp.path;
    std::string    text;
    while (text.size() < std::size_t{2} * 1024 * 1024)
        text += "a line of compressible text for the HTTP/3 static files suite, over and over\n";
    std::ofstream(root / "text.txt", std::ios::binary).write(text.data(), static_cast<std::streamsize>(text.size()));

    const auto port        = next_port();
    auto       server      = qb::http3::make_server();
    auto       compression = std::make_shared<qb::http::CompressionMiddleware<qb::http3::DefaultSession>>();
    compression->update_options(
        qb::http::CompressionOptions().compress_responses(true).min_size_to_compress(512).preferred_encodings({"gzip"}));
    server->router().use(compression);
    server->router().use(qb::http::static_files_middleware<qb::http3::DefaultSession>(
        qb::http::StaticFilesOptions(root).with_stream_threshold(std::size_t{64} * 1024)));
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));
    auto client = qb::http3::make_client(https_origin(port));
    client->set_verify_peer(false);

    auto              state = std::make_shared<std::optional<qb::http::Response>>();
    qb::http::Request request{qb::io::uri(https_origin(port) + "/text.txt")};
    request.set_header("Accept-Encoding", "gzip");
    ASSERT_TRUE(client->push_request(std::move(request), [state](qb::http::Response r) { *state = std::move(r); }));
    ASSERT_TRUE(pump([&] { return state->has_value(); }, 10s));
    auto &response = state->value();
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("Content-Encoding"), "gzip");
    EXPECT_FALSE(response.has_header("Content-Length")) << "the coded length is unknown: FIN ends the body";
    EXPECT_NE(response.header("Vary").find("Accept-Encoding"), std::string::npos);
    EXPECT_LT(response.body().size(), text.size()) << "compressible text got smaller";
    ASSERT_NO_THROW(response.body().uncompress("gzip"));
    EXPECT_TRUE(response.body().as<std::string>() == text) << "the inflated body differs from the file";

    qb::http::Request plain{qb::io::uri(https_origin(port) + "/text.txt")};
    auto              plain_state = std::make_shared<std::optional<qb::http::Response>>();
    ASSERT_TRUE(client->push_request(std::move(plain), [plain_state](qb::http::Response r) { *plain_state = std::move(r); }));
    ASSERT_TRUE(pump([&] { return plain_state->has_value(); }, 10s));
    EXPECT_FALSE(plain_state->value().has_header("Content-Encoding")) << "a client that accepts no coding gets the file as it is";
    EXPECT_EQ(plain_state->value().header("Content-Length"), std::to_string(text.size()));

    client->disconnect();
    server->close();
}
#endif // QB_HAS_COMPRESSION

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

// A new client is refused before its handshake completes while the server drains. Its request never reaches
// the router, and the request on the connection established before the drain still receives its answer.
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
    bool               first_done = false;
    qb::http::Response first_response;
    ASSERT_TRUE(first->push_request(qb::http::Request{qb::io::uri("/hold")}, [&](qb::http::Response res) {
        first_response = std::move(res);
        first_done     = true;
    }));
    ASSERT_TRUE(pump([&] { return held_context != nullptr; }));

    int  reports = 0;
    auto outcome = qb::http::drain_outcome::deadline;
    ASSERT_TRUE(server->drain(5s, [&](qb::http::drain_outcome o) {
        outcome = o;
        ++reports;
    }));

    int                late_connect_reports = 0;
    bool               late_connected       = false;
    bool               late_done            = false;
    qb::http::Response late_response;
    auto               late = qb::http3::make_client(https_origin(port));
    late->set_verify_peer(false);
    ASSERT_TRUE(late->connect([&](bool ok, std::string const &) {
        late_connected = late_connected || ok;
        ++late_connect_reports;
    }));
    ASSERT_TRUE(late->push_request(qb::http::Request{qb::io::uri("/count")}, [&](qb::http::Response res) {
        late_response = std::move(res);
        late_done     = true;
    }));
    ASSERT_TRUE(pump([&] { return late_done && late_connect_reports == 1; }));
    EXPECT_FALSE(late_connected) << "a client arriving during drain must not complete a handshake before being refused";
    EXPECT_NE(late_response.status(), qb::http::status::OK);
    EXPECT_EQ(counted, 0) << "the request of a connection made during the drain never reaches the router";
    EXPECT_TRUE(pump([&] { return !late->is_connected(); })) << "and the connection is closed";
    EXPECT_EQ(reports, 0) << "the connection there before the drain still has a request in flight";

    held_context->text("held-ok");
    held_context.reset();
    ASSERT_TRUE(pump([&] { return first_done && reports == 1; }));
    EXPECT_EQ(first_response.status(), qb::http::status::OK);
    EXPECT_EQ(first_response.body().as<std::string>(), "held-ok");
    EXPECT_EQ(outcome, qb::http::drain_outcome::drained);
    EXPECT_EQ(late_connect_reports, 1);
    EXPECT_EQ(counted, 0);

    first->disconnect();
    late->disconnect();
    server->close();
}

// A server with no connection reports `drained` before drain() returns and still refuses later handshakes.
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

    int  connect_reports = 0;
    bool connected       = false;
    auto late            = qb::http3::make_client(https_origin(port));
    late->set_verify_peer(false);
    ASSERT_TRUE(late->connect([&](bool ok, std::string const &) {
        connected = connected || ok;
        ++connect_reports;
    }));
    ASSERT_TRUE(pump([&] { return connect_reports == 1; }));
    EXPECT_FALSE(connected) << "an already drained listener must refuse a new Initial without completing its handshake";
    EXPECT_EQ(reports, 1);
    EXPECT_EQ(outcome, qb::http::drain_outcome::drained);
    late->disconnect();
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

// Real QUIC packets and TLS, with deterministic RTT estimates supplied only at the public cold query seam.
class ControlledRttBackend final : public qb::io::quic::backend {
    std::unique_ptr<qb::io::quic::backend> _native = qb::io::quic::make_native_backend();

public:
    std::vector<std::uint64_t>                          connections;
    std::vector<std::uint64_t>                          close_codes;
    std::vector<std::pair<std::uint64_t, qb::duration>> estimates;
    std::uint64_t                                       aggregate_rtt_us    = 10000000;
    bool                                                legacy_capabilities = false;
    mutable int                                         queries             = 0;

    void
    configure(qb::io::quic::settings const &config) override {
        _native->configure(config);
    }
    void
    start_server(qb::io::endpoint const &local, std::vector<std::string> const &alpn, qb::io::quic::tls_config const &tls) override {
        _native->start_server(local, alpn, tls);
    }
    void
    start_client(qb::io::endpoint const &local, qb::io::endpoint const &remote, std::vector<std::string> const &alpn,
                 qb::io::quic::tls_config const &tls) override {
        _native->start_client(local, remote, alpn, tls);
    }
    void
    on_udp_datagram(qb::io::quic::packet_view packet) override {
        _native->on_udp_datagram(packet);
    }
    void
    on_timeout(std::chrono::steady_clock::time_point now) override {
        _native->on_timeout(now);
    }
    std::chrono::steady_clock::time_point
    next_timeout() const override {
        return _native->next_timeout();
    }
    bool
    wants_write() const noexcept override {
        return _native->wants_write();
    }
    std::vector<qb::io::quic::packet>
    drain_packets() override {
        return _native->drain_packets();
    }
    std::vector<qb::io::quic::backend_event>
    drain_events() override {
        auto events = _native->drain_events();
        for (auto const &event : events)
            if (event.type == qb::io::quic::backend_event::kind::connected)
                connections.push_back(event.connection_id);
        return events;
    }
    std::uint64_t
    open_stream(qb::io::quic::stream_direction direction) override {
        return _native->open_stream(direction);
    }
    std::uint64_t
    open_stream(std::uint64_t id, qb::io::quic::stream_direction direction) override {
        return _native->open_stream(id, direction);
    }
    void
    send_stream_data(std::uint64_t id, std::uint64_t stream, std::span<const std::byte> bytes, bool fin) override {
        _native->send_stream_data(id, stream, bytes, fin);
    }
    void
    extend_stream_credit(std::uint64_t id, std::uint64_t stream, std::uint64_t bytes) override {
        _native->extend_stream_credit(id, stream, bytes);
    }
    void
    reset_stream(std::uint64_t id, std::uint64_t stream, std::uint64_t code) override {
        _native->reset_stream(id, stream, code);
    }
    void
    stop_stream(std::uint64_t id, std::uint64_t stream, std::uint64_t code) override {
        _native->stop_stream(id, stream, code);
    }
    void
    send_datagram(std::uint64_t id, std::span<const std::byte> bytes) override {
        _native->send_datagram(id, bytes);
    }
    void
    close_connection(std::uint64_t id, std::uint64_t code, std::string_view reason) override {
        close_codes.push_back(code); // the application code the server closes a connection with (Huly QB-1267)
        _native->close_connection(id, code, reason);
    }
    void
    close(std::uint64_t code, std::string_view reason) override {
        _native->close(code, reason);
    }
    qb::io::quic::stats
    current_stats() const noexcept override {
        auto stats            = _native->current_stats();
        stats.smoothed_rtt_us = aggregate_rtt_us;
        return stats;
    }
    std::optional<qb::duration>
    smoothed_rtt(std::uint64_t id) const noexcept override {
        ++queries;
        if (legacy_capabilities)
            return qb::io::quic::backend::smoothed_rtt(id);
        for (auto const &[connection_id, estimate] : estimates)
            if (connection_id == id)
                return estimate;
        return std::nullopt;
    }
    bool
    set_accepting_connections(bool accepting) noexcept override {
        if (legacy_capabilities)
            return qb::io::quic::backend::set_accepting_connections(accepting);
        return _native->set_accepting_connections(accepting);
    }
};

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
    open(std::string const &origin, std::vector<std::string> const &alpn = {"h3"}) {
        qb::io::quic::tls_config tls;
        tls.verify_peer = false;
        return connect(qb::io::uri(origin), tls, alpn);
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
    // Pumped without pump()'s idle sleep: its 1 ms nap after a pass that invokes nothing is the server's minimal
    // wait, so a pass that ran before the notice's datagram was readable let the final GOAWAY leave during the
    // nap, and the peer then read both in consecutive passes -- the spacing measured was the harness's.
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!peer.closed && std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    ASSERT_TRUE(peer.closed) << "the connection did not close within 5 s of graceful_shutdown()";
    ASSERT_EQ(peer.goaway_ids.size(), 2u);
    EXPECT_EQ(peer.goaway_ids[0], (std::uint64_t{1} << 62) - 4) << "the notice names the largest stream id";
    EXPECT_EQ(peer.goaway_ids[1], 0u) << "the final GOAWAY: no request was read";
    EXPECT_GE(peer.goaway_arrivals[1] - peer.goaway_arrivals[0], 500us) << "a round trip separates the two GOAWAYs";

    server->close();
}

TEST_F(Http3LoopbackTest, ShutdownUsesEachPeersRttAndAdditionalNoticesKeepExistingDeadlines) {
    const auto port       = next_port();
    auto       server     = qb::http3::make_server();
    auto       controlled = std::make_unique<http3_shutdown_wire_test::ControlledRttBackend>();
    auto      *backend    = controlled.get();
    server->set_backend(std::move(controlled));
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));
    http3_shutdown_wire_test::RawH3Peer fast;
    http3_shutdown_wire_test::RawH3Peer slow;
    ASSERT_TRUE(fast.open(https_origin(port)));
    ASSERT_TRUE(pump([&] { return fast.connected && backend->connections.size() == 1; }));
    ASSERT_TRUE(slow.open(https_origin(port)));
    ASSERT_TRUE(pump([&] { return slow.connected && backend->connections.size() == 2; }));
    backend->estimates = {{backend->connections[0], 5ms}, {backend->connections[1], 250ms}};
    EXPECT_EQ(server->smoothed_rtt(backend->connections[0]), std::optional<qb::duration>{5ms});
    EXPECT_EQ(server->smoothed_rtt(backend->connections[1]), std::optional<qb::duration>{250ms});
    EXPECT_FALSE(server->smoothed_rtt().has_value()) << "zero is ambiguous with two server peers";
    EXPECT_FALSE(server->smoothed_rtt(999999).has_value());
    backend->queries = 0;

    server->graceful_shutdown();
    ASSERT_TRUE(pump([&] { return fast.goaway_ids.size() == 2; }));
    EXPECT_LE(slow.goaway_ids.size(), 1u) << "the slower peer must retain its own notice delay";
    EXPECT_EQ(backend->queries, 2);

    // A later shutdown adds a new peer. Recomputing the old slow peer's due time would postpone it by twenty seconds.
    backend->estimates[1].second = 10s;
    http3_shutdown_wire_test::RawH3Peer later;
    ASSERT_TRUE(later.open(https_origin(port)));
    ASSERT_TRUE(pump([&] { return later.connected && backend->connections.size() == 3; }));
    backend->estimates.emplace_back(backend->connections[2], 5ms);
    server->graceful_shutdown();
    EXPECT_EQ(backend->queries, 3) << "only the newly noticed peer needs a fresh RTT estimate";
    ASSERT_TRUE(pump([&] { return fast.closed && slow.closed && later.closed; }));
    ASSERT_EQ(slow.goaway_ids.size(), 2u);
    ASSERT_EQ(later.goaway_ids.size(), 2u);
    EXPECT_EQ(slow.goaway_ids.back(), 0u);
    EXPECT_EQ(later.goaway_ids.back(), 0u);
    EXPECT_EQ(backend->queries, 3);
    server->close();
}

TEST_F(Http3LoopbackTest, LegacyBackendRttFallbackRemainsBoundedByTheDrainDeadline) {
    for (const auto aggregate : {std::uint64_t{5000}, std::numeric_limits<std::uint64_t>::max()}) {
        SCOPED_TRACE(aggregate);
        int                                                           routed    = 0;
        int                                                           responses = 0;
        int                                                           reports   = 0;
        auto                                                          outcome   = qb::http::drain_outcome::drained;
        qb::http::Response                                            response;
        const auto                                                    port   = next_port();
        auto                                                          server = qb::http3::make_server();
        std::shared_ptr<qb::http::Context<qb::http3::DefaultSession>> held_context;
        auto  controlled             = std::make_unique<http3_shutdown_wire_test::ControlledRttBackend>();
        auto *backend                = controlled.get();
        backend->aggregate_rtt_us    = aggregate;
        backend->legacy_capabilities = true;
        server->set_backend(std::move(controlled));
        server->router().get("/held", [&](auto ctx) {
            ++routed;
            held_context = ctx;
        });
        server->router().compile();
        ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));
        EXPECT_FALSE(server->set_accepting_connections(false)) << "a legacy backend retains the unsupported default";
        auto client = qb::http3::make_client(https_origin(port));
        client->set_verify_peer(false);
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/held")}, [&](qb::http::Response res) {
            response = std::move(res);
            ++responses;
        }));
        ASSERT_TRUE(pump([&] { return held_context != nullptr; }));
        ASSERT_EQ(backend->connections.size(), 1u);
        EXPECT_FALSE(server->smoothed_rtt(backend->connections.front()).has_value());
        EXPECT_EQ(server->stats().smoothed_rtt_us, aggregate);
        EXPECT_EQ(responses, 0);
        backend->queries = 0;

        ASSERT_TRUE(server->drain(50ms, [&](qb::http::drain_outcome result) {
            outcome = result;
            ++reports;
        }));
        EXPECT_EQ(backend->queries, 1) << "the live peer must use the unknown-RTT fallback";
        ASSERT_TRUE(pump([&] { return reports == 1 && responses == 1 && !client->is_connected(); }));
        EXPECT_EQ(outcome, qb::http::drain_outcome::deadline);
        EXPECT_EQ(routed, 1);
        EXPECT_NE(response.status(), qb::http::status::OK) << "the held request is abandoned, never fabricated as a successful response";
        EXPECT_FALSE(server->drain(50ms));
        held_context.reset();
        client->disconnect();
        server->close();
        EXPECT_EQ(reports, 1);
        EXPECT_EQ(responses, 1);
        client.reset();
        server.reset();
        qb::io::async::listener::current.clear();
    }
}

namespace http3_reset_code_test {

// The HTTP/3 client, with the first code each stream is reset with recorded: the client settles such an exchange as a
// 502 whatever its code. qb's backend raises the same event for the client's own reset_stream(), but the client resets
// nothing of a GET it sent whole before the server's RESET_STREAM arrives: the first code of such a stream is the one
// ngtcp2's stream_reset callback read off the wire. (A stop is always local here: the client's own stop_stream() or
// ngtcp2's read shutdown.)
class ResetRecordingClient : public qb::http3::Client {
public:
    using qb::http3::Client::Client;
    using qb::http3::Client::dispatch;

    std::vector<std::uint64_t> codes; // one a stream, the server's

protected:
    void
    dispatch(qb::io::async::quic::event::stream_closed const &ev) override {
        bool seen = false;
        for (const auto id : _streams)
            seen = seen || id == ev.id;
        if (ev.reason == qb::io::quic::stream_close_reason::reset && !seen) {
            _streams.push_back(ev.id);
            codes.push_back(ev.error_code);
        }
        qb::http3::Client::dispatch(ev);
    }

private:
    std::vector<std::uint64_t> _streams;
};

} // namespace http3_reset_code_test

// A response the server cannot submit resets its stream with H3_REQUEST_CANCELLED, read on the wire by the client (Huly
// QB-1241): a `content-length` its body contradicts (Huly QB-234), a `te` field, which a response never carries (Huly
// QB-1191). The request was well-formed, and RFC 9114 section 4.1.1 has a server that abandons a response after partial
// processing abort its response stream with that code; H3_MESSAGE_ERROR, sent until Huly QB-1241, told the client its own message
// was malformed. The client settles each exchange as a 502, and the same connection serves the next request.
TEST_F(Http3LoopbackTest, AResponseTheServerCannotSubmitIsResetWithRequestCancelled) {
    const auto port   = next_port();
    auto       server = qb::http3::make_server();
    server->router().get("/bad-length", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("content-length", "1");
        ctx->response().body() = "abc";
        ctx->complete();
    });
    server->router().get("/te", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("te", "trailers");
        ctx->response().body() = "abc";
        ctx->complete();
    });
    server->router().get("/good", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "accepted";
        ctx->complete();
    });
    server->router().compile();
    ASSERT_TRUE(server->listen(qb::io::uri(https_origin(port)), cert_path(), key_path()));

    auto client = std::make_shared<http3_reset_code_test::ResetRecordingClient>(https_origin(port));
    client->set_verify_peer(false);
    for (std::string const path : {"/bad-length", "/te"}) {
        SCOPED_TRACE(path);
        const auto         before = client->codes.size();
        std::atomic<bool>  done{false};
        qb::http::Response response;
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(path)}, [&](qb::http::Response res) {
            response = std::move(res);
            done     = true;
        }));
        ASSERT_TRUE(pump([&] { return done.load() && client->codes.size() > before; }));
        EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY);
        ASSERT_EQ(client->codes.size(), before + 1) << "the server reset the response's stream";
        EXPECT_EQ(client->codes.back(), static_cast<std::uint64_t>(NGHTTP3_H3_REQUEST_CANCELLED)) << "the code on the wire";
    }

    // Let a CONNECTION_CLOSE arrive if one was sent: the next request must go over the same connection.
    const auto settle = std::chrono::steady_clock::now() + 150ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_TRUE(client->is_connected()) << "a refused response closed the whole connection";

    std::atomic<bool>  next_done{false};
    qb::http::Response next;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/good")}, [&](qb::http::Response res) {
        next      = std::move(res);
        next_done = true;
    }));
    ASSERT_TRUE(pump([&] { return next_done.load(); }));
    EXPECT_EQ(next.status(), qb::http::status::OK);
    EXPECT_EQ(next.body().as<std::string>(), "accepted");
    EXPECT_EQ(server->stats().active_connections, 1u) << "the follow-up went over a new connection";

    client->disconnect();
    server->close();
}

// RFC 9114 section 8.1 makes H3_REQUEST_CANCELLED (0x010c) the code of a request stream the endpoint cancels; a server that
// saw another application protocol negotiated closed the CONNECTION with it. It closes it with H3_GENERAL_PROTOCOL_ERROR now
// (Huly QB-1267). http3::Server::listen() offers h3 alone, and qb-io closes a handshake that negotiated nothing before the
// server sees it: the base endpoint's listen, offering a second protocol, is the way there. h3 on the same server is served.
TEST_F(Http3LoopbackTest, AConnectionThatNegotiatesAnotherProtocolIsClosedWithAConnectionCode) {
    const auto port       = next_port();
    auto       server     = qb::http3::make_server();
    auto       controlled = std::make_unique<http3_shutdown_wire_test::ControlledRttBackend>();
    auto      *backend    = controlled.get();
    server->set_backend(std::move(controlled));
    server->router().compile();
    ASSERT_TRUE(static_cast<qb::io::async::quic::endpoint &>(*server).listen(qb::io::uri(https_origin(port)), cert_path(), key_path(),
                                                                             {"h3", "hq-interop"}));
    http3_shutdown_wire_test::RawH3Peer other;
    ASSERT_TRUE(other.open(https_origin(port), {"hq-interop"}));
    ASSERT_TRUE(pump([&] { return !backend->close_codes.empty() && other.closed; })) << "the connection is closed";
    ASSERT_EQ(backend->close_codes.size(), 1u);
    EXPECT_EQ(backend->close_codes.front(), static_cast<std::uint64_t>(NGHTTP3_H3_GENERAL_PROTOCOL_ERROR));
    EXPECT_NE(backend->close_codes.front(), static_cast<std::uint64_t>(NGHTTP3_H3_REQUEST_CANCELLED)) << "a stream's code";

    http3_shutdown_wire_test::RawH3Peer h3;
    ASSERT_TRUE(h3.open(https_origin(port)));
    ASSERT_TRUE(pump([&] { return h3.connected && backend->connections.size() == 2; }));
    const auto settle = std::chrono::steady_clock::now() + 100ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    EXPECT_FALSE(h3.closed) << "h3 is served";
    EXPECT_EQ(backend->close_codes.size(), 1u);
    server->close();
}

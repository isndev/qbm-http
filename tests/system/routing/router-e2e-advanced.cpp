/**
 * @file qbm/http/tests/system/routing/router-e2e-advanced.cpp
 * @brief System tier: wire-level router behaviour over a real loopback HTTP/1.1 server.
 *
 * This is the focused successor to the pre-restructure `test-integration-advanced.cpp`
 * monolith (2188 LOC). Per the dedup decision (spec D3), pure router-matching
 * logic — static/param/wildcard precedence, middleware ordering, controller
 * mounting, group nesting, custom 404 — is already proven IN-PROCESS by the
 * `unit/routing/router-*` family with a mock session, and is NOT re-run here.
 *
 * What remains is exactly the coverage the socket round-trip ADDS, which a
 * mock-session unit test cannot reach:
 *
 *   - on-the-wire request parsing: path params, query string, request body, and
 *     header round-tripping survive real serialization + parsing;
 *   - URL-encoded path segments decode correctly server-side;
 *   - HEAD body-stripping on the wire (handler may set a body; the client sees none);
 *   - the `Allow` header is serialized correctly for auto-405 and OPTIONS;
 *   - deferred completion: a handler that RETURNS before its response is
 *     complete -- a positive-delay `qb::io::async::callback` completes it on a
 *     later loop dispatch -- still produces a correct response, and says so in
 *     two phase headers; the zero-delay callback, which completes the response
 *     inline before the handler returns, is kept as the control (Huly QB-300);
 *   - several requests in flight concurrently on the same loop all complete;
 *   - a middleware-induced error routes to the custom global error chain and
 *     yields EXACTLY 503 (the pre-restructure weak `EXPECT_NE(OK)` is gone; see
 *     spec D4 — the strong exact-503 assertion is the canonical one).
 *
 * De-flake / quality notes (vs `test-integration-advanced.cpp`):
 *   - DELETED the three global magic-sum atomics (`adv_request_count_*`,
 *     `adv_server_side_assertions`) and the `PerformTestExecution` cross-thread
 *     accounting. They counted "this code ran", not "it produced a correct
 *     value". Every assertion here is on OBSERVABLE response state (status /
 *     body / headers / the deterministic `X-MW-Trace` header).
 *   - magic port 29887 + `sleep_for(250ms)` warmup -> `listen_v4(0)` on the socket
 *     that actually serves + the condition-variable readiness barrier inside the
 *     shared `ServerThread<>`.
 *   - dropped the misleading `integration-` prefix and the `qb::io::cout` spam.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <cctype>
#include <chrono>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "../../shared/loopback_server.h"

#include <qb/io/async/coroutine.h>
#include <qbm/http/http.h>
#include <qbm/http/routing/context.h>
#include <qbm/http/routing/middleware.h>
#include <qbm/http/routing/router.h>

using namespace std::chrono_literals;

namespace {

/// Bounded client timeout — a stuck server surfaces as 504, never a hang.
constexpr auto kClientTimeout = 7s;

qb::io::async::task<qb::http::async::Reply>
fetch_one(std::string target) {
    qb::http::Request request{{std::move(target)}};
    co_return co_await qb::http::GET(std::move(request), kClientTimeout);
}

qb::io::async::task<std::vector<qb::http::async::Reply>>
fetch_all(std::vector<std::string> targets) {
    std::vector<qb::io::async::task<qb::http::async::Reply>> tasks;
    tasks.reserve(targets.size());
    for (auto &target : targets) {
        tasks.emplace_back(fetch_one(std::move(target)));
    }
    co_return co_await qb::io::async::when_all(std::move(tasks));
}

class RouterE2EServer;

class RouterE2ESession : public qb::http::use<RouterE2ESession>::session<RouterE2EServer> {
public:
    explicit RouterE2ESession(RouterE2EServer &server)
        : session(server) {}
};

/// Minimal RFC-3986 percent-encoder for path segments (test client side).
std::string
url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;
    for (char c : value) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }
        escaped << std::uppercase << '%' << std::setw(2) << static_cast<int>(static_cast<unsigned char>(c)) << std::nouppercase;
    }
    return escaped.str();
}

bool
write_all(qb::io::tcp::socket &socket, std::string_view bytes) {
    std::size_t sent     = 0;
    const auto  deadline = std::chrono::steady_clock::now() + kClientTimeout;
    while (sent < bytes.size() && std::chrono::steady_clock::now() < deadline) {
        const int n = socket.write(bytes.data() + sent, static_cast<int>(bytes.size() - sent));
        if (n > 0) {
            sent += static_cast<std::size_t>(n);
        } else {
            std::this_thread::sleep_for(1ms);
        }
    }
    return sent == bytes.size();
}

std::string
read_wire_response(qb::io::tcp::socket &socket) {
    std::string response;
    const auto  deadline  = std::chrono::steady_clock::now() + kClientTimeout;
    auto        last_byte = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() < deadline) {
        char      buffer[1024];
        const int n = socket.read(buffer, sizeof(buffer));
        if (n > 0) {
            response.append(buffer, static_cast<std::size_t>(n));
            last_byte = std::chrono::steady_clock::now();
        } else if (n == 0) {
            break;
        } else {
            if (response.find("\r\n\r\n") != std::string::npos && std::chrono::steady_clock::now() - last_byte >= 200ms) {
                break;
            }
            std::this_thread::sleep_for(1ms);
        }
    }
    return response;
}

// ---------------------------------------------------------------------------
// Complete `ctx` from `qb::io::async::callback(..., delay)` and record the phase
// the completion ran in, as two response headers:
//   - `X-Handler-Returned`: whether the route handler that armed the callback
//     had returned first ("yes") or was still on the stack ("no");
//   - `X-Dispatches-Between`: how many loop dispatches the server's listener
//     completed between arming and completion. `total_events_processed()`
//     counts a dispatch once it has returned, so the dispatch that delivered
//     the request counts only after it unwound: 0 means the same dispatch.
// A positive delay arms a timer the loop fires on a later pass; a zero (or
// negative) one calls the lambda inline, before `callback` returns
// (`qb/io/async/io.h`) -- the control.
// ---------------------------------------------------------------------------
template <typename Ctx>
void
complete_from_callback(std::shared_ptr<Ctx> ctx, qb::duration delay, const char *body) {
    auto       returned = std::make_shared<bool>(false);
    const auto armed_at = qb::io::async::listener::current.total_events_processed();
    qb::io::async::callback(
        [ctx, returned, armed_at, body]() {
            const auto between       = qb::io::async::listener::current.total_events_processed() - armed_at;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = body;
            ctx->response().set_header("X-Async", "completed");
            ctx->response().set_header("X-Handler-Returned", *returned ? "yes" : "no");
            ctx->response().set_header("X-Dispatches-Between", std::to_string(between));
            ctx->complete();
        },
        delay);
    *returned = true; // the route handler returns right after this call
}

// ---------------------------------------------------------------------------
// A middleware that always routes to the error chain. Used to prove the custom
// global error handler maps an in-chain ERROR to a 503 over the wire.
// ---------------------------------------------------------------------------
class ErrorInducingMiddleware : public qb::http::IMiddleware<RouterE2ESession> {
public:
    std::string
    name() const override {
        return "ErrorInducingMiddleware";
    }
    void
    cancel() override {}
    void
    process(std::shared_ptr<qb::http::Context<RouterE2ESession>> ctx) override {
        ctx->response().set_header("X-Error-Inducer", "Applied");
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    }
};

class RouterE2EServer : public qb::http::use<RouterE2EServer>::server<RouterE2ESession> {
public:
    using Context                                    = qb::http::Context<RouterE2ESession>;
    static constexpr std::size_t kConcurrentRequests = 8;

private:
    std::vector<std::shared_ptr<Context>> _concurrent_requests;

public:
    RouterE2EServer() {
        // ---- Custom global error chain: any routed ERROR -> 503 ----
        qb::http::RouteHandlerFn<RouterE2ESession> error_handler = [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::SERVICE_UNAVAILABLE;
            ctx->response().body()   = "global-error-handled";
            ctx->response().set_header("X-Global-Error-Handler", "Applied");
            ctx->complete();
        };
        auto error_task = std::make_shared<qb::http::RouteLambdaTask<RouterE2ESession>>(error_handler, "GlobalErrorHandlerTask");
        std::vector<std::shared_ptr<qb::http::IAsyncTask<RouterE2ESession>>> error_chain;
        error_chain.push_back(error_task);
        router().set_error_task_chain(std::move(error_chain));

        // ---- A trace middleware proving deterministic on-wire ordering ----
        // Functional middleware signature is void(ctx, next): mutate then call next() to continue
        // the chain (complete() is for route handlers / terminal tasks, not a pass-through MW).
        router().use([](std::shared_ptr<Context> ctx, std::function<void()> next) {
            ctx->response().set_header("X-MW-Trace", "L0;");
            next();
        });

        // ---- GET /ping (+ HEAD): GET has a body, HEAD must strip it ----
        router().get("/ping", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "pong";
            ctx->complete();
        });
        router().head("/ping", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            // Deliberately set a body: the transport must strip it for HEAD.
            ctx->response().body() = "this-body-must-not-reach-the-client";
            ctx->complete();
        });

        // ---- Path-parameter echo (URL-decoded server-side) ----
        router().get("/param/:value", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "param:" + std::string{ctx->path_param("value")};
            ctx->complete();
        });

        // ---- Wildcard capture ----
        router().get("/files/*filepath", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "file:" + std::string{ctx->path_param("filepath")};
            ctx->complete();
        });

        // ---- Query-string handling with defaults ----
        router().get("/search", [](std::shared_ptr<Context> ctx) {
            const auto q             = ctx->request().uri().query_or("q", "none");
            const auto page          = ctx->request().uri().query_or("page", "1");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "q=" + q + ";page=" + page;
            ctx->complete();
        });

        // ---- Body echo (POST) ----
        router().post("/echo", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::CREATED;
            ctx->response().body()   = ctx->request().body().template as<std::string>();
            ctx->complete();
        });

        // Hold every request until all peers are simultaneously active. A
        // sequential client deadlocks here and times out, so the corresponding
        // test cannot pass without real overlap.
        router().get("/concurrent/:value", [this](std::shared_ptr<Context> ctx) {
            _concurrent_requests.push_back(ctx);
            if (_concurrent_requests.size() != kConcurrentRequests) {
                return;
            }
            auto ready = std::move(_concurrent_requests);
            _concurrent_requests.clear();
            for (auto &pending : ready) {
                pending->response().status() = qb::http::status::OK;
                pending->response().body()   = "concurrent:" + std::string{pending->path_param("value")};
                pending->complete();
            }
        });

        // ---- Multi-method resource: auto-405 must compute a sorted Allow ----
        router().get("/resource", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "GET resource";
            ctx->complete();
        });
        router().post("/resource", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::CREATED;
            ctx->complete();
        });
        router().put("/resource", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router().del("/resource", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });

        // ---- OPTIONS with an explicit Allow header ----
        router().options("/resource", [](std::shared_ptr<Context> ctx) {
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->response().set_header("Allow", "GET, POST, PUT, DELETE, OPTIONS");
            ctx->complete();
        });

        // ---- Deferred completion: the handler returns, a later loop dispatch completes ----
        router().get("/async", [](std::shared_ptr<Context> ctx) { complete_from_callback(ctx, 1ms, "async-done"); });
        // ---- The control: a zero delay completes inline, before the handler returns ----
        router().get("/async-inline", [](std::shared_ptr<Context> ctx) { complete_from_callback(ctx, qb::duration::zero(), "inline-done"); });

        // ---- What the request target named: the route, and the URI the server built from it ----
        // Three routes a target can land on, each echoing the request's URI and its Host field.
        const auto target_echo = [](std::string tag) {
            return [tag = std::move(tag)](std::shared_ptr<Context> ctx) {
                auto const &uri          = ctx->request().uri();
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body()   = "route=" + tag + ";path=" + std::string{uri.path()} + ";host=" + std::string{uri.host()}
                                           + ";userinfo=" + std::string{uri.user_info()} + ";Host=" + ctx->request().header("Host");
                ctx->complete();
            };
        };
        router().get("/", target_echo("root"));
        router().get("/where/*rest", target_echo("plain"));
        router().get("/a/where/*rest", target_echo("a"));

        // ---- Middleware-induced error -> global error chain -> 503 ----
        {
            auto err_group = router().group("/mw-error");
            err_group->use(std::make_shared<ErrorInducingMiddleware>());
            err_group->get("/route", [](std::shared_ptr<Context> ctx) {
                ctx->response().status() = qb::http::status::OK;
                ctx->response().body()   = "should-not-be-reached";
                ctx->complete();
            });
        }

        router().compile();
    }
};

using ServerThread = qb::http::test::ServerThread<RouterE2EServer>;

class RouterE2ETest : public ::testing::Test {
protected:
    std::uint16_t                 _port{0};
    std::unique_ptr<ServerThread> _server;

    void
    SetUp() override {
        qb::io::async::init();

        // Bind :0 on the socket that ACTUALLY SERVES and read the port back, rather than probing
        // for a free port and binding it a moment later. `ephemeral_port()` documents the hole
        // this closes: its probe must be shut before the caller can bind, so under `ctest -j`
        // another test PROCESS can take the port in that window (measured: 2 failures in 12
        // full-suite runs). Binding :0 here leaves no window at all.
        _server = std::make_unique<ServerThread>([](RouterE2EServer &srv) -> bool {
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
                return false;
            }
            srv.start();
            return true;
        });
        ASSERT_TRUE(_server->ready()) << "router e2e server failed to start";
        // The ServerThread ctor already blocked on the readiness barrier, so the transport is
        // bound and its assigned port is visible to this thread.
        _port = _server->port();
        ASSERT_NE(_port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    }

    void
    TearDown() override {
        _server.reset();
    }

    [[nodiscard]] std::string
    url(const std::string &path) const {
        return "http://localhost:" + std::to_string(_port) + path;
    }

    /// One request line on a connection of its own, with `Host: localhost`: the status line and the body.
    [[nodiscard]] std::pair<std::string, std::string>
    exchange(const std::string &method, const std::string &target) const {
        return exchange_raw(method + " " + target + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    }

    /// @p request, its bytes as given, on a connection of its own: the status line and the body.
    [[nodiscard]] std::pair<std::string, std::string>
    exchange_raw(const std::string &request) const {
        qb::io::tcp::socket socket;
        if (socket.connect_v4("127.0.0.1", _port) != qb::io::SocketStatus::Done)
            return {"no connection", {}};
        if (!write_all(socket, request))
            return {"not sent", {}};
        const std::string wire = read_wire_response(socket);
        socket.disconnect();
        const auto line  = wire.find("\r\n");
        const auto split = wire.find("\r\n\r\n");
        if (line == std::string::npos || split == std::string::npos)
            return {wire, {}};
        return {wire.substr(0, line), wire.substr(split + 4)};
    }
};

// ---------------------------------------------------------------------------
// On-the-wire request parsing
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, PathParamSurvivesWire) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/param/hello")}}, kClientTimeout));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "param:hello");
    // The global trace middleware ran and serialized its header.
    EXPECT_EQ(reply.response.header("X-MW-Trace"), "L0;");
}

TEST_F(RouterE2ETest, UrlEncodedPathParamDecodesServerSide) {
    struct Case {
        std::string raw;
    };
    const std::vector<Case> cases = {{"simplevalue"}, {"hello world"}, {"path/component-ish"}, {"!@#$%^&*()"}};

    for (const auto &c : cases) {
        const auto path  = "/param/" + url_encode(c.raw);
        auto       reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url(path)}}, kClientTimeout));
        EXPECT_EQ(reply.response.status(), qb::http::status::OK) << "raw=" << c.raw;
        EXPECT_EQ(reply.response.body().template as<std::string>(), "param:" + c.raw) << "raw=" << c.raw;
    }
}

TEST_F(RouterE2ETest, WildcardCaptureSurvivesWire) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/files/some/long/path/to/file.txt")}}, kClientTimeout));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "file:some/long/path/to/file.txt");
}

TEST_F(RouterE2ETest, QueryStringParsedFromWire) {
    auto with_query = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/search?q=widgets&page=3")}}, kClientTimeout));
    EXPECT_EQ(with_query.response.status(), qb::http::status::OK);
    EXPECT_EQ(with_query.response.body().template as<std::string>(), "q=widgets;page=3");

    auto defaults = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/search")}}, kClientTimeout));
    EXPECT_EQ(defaults.response.body().template as<std::string>(), "q=none;page=1");
}

TEST_F(RouterE2ETest, RequestBodyRoundTripsThroughWire) {
    qb::http::Request req{qb::http::method::POST, {url("/echo")}};
    req.body() = "round-trip-payload";
    auto reply = qb::http::run_sync(qb::http::POST(std::move(req), kClientTimeout));

    EXPECT_EQ(reply.response.status(), qb::http::status::CREATED);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "round-trip-payload");
}

// ---------------------------------------------------------------------------
// HEAD body-stripping on the wire
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, HeadResponseHasNoBodyOnTheWire) {
    qb::io::tcp::socket socket;
    ASSERT_EQ(socket.connect_v4("127.0.0.1", _port), qb::io::SocketStatus::Done);
    const std::string request = "HEAD /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    ASSERT_TRUE(write_all(socket, request));

    const std::string wire  = read_wire_response(socket);
    const auto        split = wire.find("\r\n\r\n");
    ASSERT_NE(split, std::string::npos) << wire;
    EXPECT_NE(wire.substr(0, split).find("HTTP/1.1 200"), std::string::npos) << wire;
    EXPECT_TRUE(wire.substr(split + 4).empty()) << "HEAD emitted body bytes on the wire";
    socket.disconnect();
}

// ---------------------------------------------------------------------------
// Allow-header serialization (auto-405 + OPTIONS)
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, MethodNotAllowedSerializesAllowHeader) {
    // PATCH is not registered on /resource -> auto 405 with a computed,
    // alphabetically-sorted Allow header (DELETE, GET, POST, PUT, OPTIONS).
    qb::http::Request req{qb::http::method::PATCH, {url("/resource")}};
    auto              reply = qb::http::run_sync(qb::http::PATCH(std::move(req), kClientTimeout));

    EXPECT_EQ(reply.response.status(), qb::http::status::METHOD_NOT_ALLOWED);
    EXPECT_EQ(reply.response.header("Allow"), "DELETE, GET, POST, PUT, OPTIONS");
}

TEST_F(RouterE2ETest, OptionsSerializesExplicitAllowHeader) {
    auto reply = qb::http::run_sync(qb::http::OPTIONS(qb::http::Request{qb::http::method::OPTIONS, {url("/resource")}}, kClientTimeout));
    EXPECT_EQ(reply.response.status(), qb::http::status::NO_CONTENT);
    EXPECT_EQ(reply.response.header("Allow"), "GET, POST, PUT, DELETE, OPTIONS");
}

// ---------------------------------------------------------------------------
// Deferred completion over the loop, and its inline control
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, AsyncHandlerCompletesOverTheLoop) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/async")}}, kClientTimeout));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "async-done");
    EXPECT_EQ(reply.response.header("X-Async"), "completed");
    // The phase: the handler had returned, and the loop completed at least one dispatch -- the
    // one that delivered the request -- before the timer's completed the response.
    EXPECT_EQ(reply.response.header("X-Handler-Returned"), "yes") << "the response was completed before the handler returned";
    const auto &between = reply.response.header("X-Dispatches-Between");
    ASSERT_FALSE(between.empty());
    EXPECT_GT(std::stoull(between), 0u) << "the completion ran inside the dispatch that armed it";
}

TEST_F(RouterE2ETest, ZeroDelayCallbackCompletesInlineBeforeTheHandlerReturns) {
    // The control of the case above: `callback(fn, 0)` calls `fn` inline, so the same headers must
    // read the other phase -- or they would distinguish nothing.
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/async-inline")}}, kClientTimeout));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "inline-done");
    EXPECT_EQ(reply.response.header("X-Handler-Returned"), "no");
    EXPECT_EQ(reply.response.header("X-Dispatches-Between"), "0");
}

// ---------------------------------------------------------------------------
// Middleware-induced error -> custom global error chain -> exact 503
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, MiddlewareInducedErrorYieldsExact503) {
    auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{url("/mw-error/route")}}, kClientTimeout));

    // The handler must never run; the error chain owns the response.
    EXPECT_EQ(reply.response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(reply.response.body().template as<std::string>(), "global-error-handled");
    EXPECT_EQ(reply.response.header("X-Global-Error-Handler"), "Applied");
    EXPECT_EQ(reply.response.header("X-Error-Inducer"), "Applied");
    EXPECT_NE(reply.response.body().template as<std::string>(), "should-not-be-reached");
}

// ---------------------------------------------------------------------------
// Concurrent in-flight requests on one loop
// ---------------------------------------------------------------------------

TEST_F(RouterE2ETest, ConcurrentInFlightRequestsAllComplete) {
    std::vector<std::string> targets;
    targets.reserve(RouterE2EServer::kConcurrentRequests);
    for (std::size_t i = 0; i < RouterE2EServer::kConcurrentRequests; ++i) {
        targets.push_back(url("/concurrent/req" + std::to_string(i)));
    }

    const auto replies = qb::io::async::run_sync(fetch_all(std::move(targets)));
    ASSERT_EQ(replies.size(), RouterE2EServer::kConcurrentRequests);
    for (std::size_t i = 0; i < replies.size(); ++i) {
        EXPECT_EQ(replies[i].response.status(), qb::http::status::OK) << "i=" << i;
        EXPECT_EQ(replies[i].response.body().template as<std::string>(), "concurrent:req" + std::to_string(i)) << "i=" << i;
    }
}

// ---------------------------------------------------------------------------
// The request target's form decides what is an authority (Huly QB-1177)
// ---------------------------------------------------------------------------

// An origin-form target is an absolute path (RFC 9112 §3.2.1), and `absolute-path = 1*( "/" segment )` admits an
// empty first segment: `//a/where/x` is the path `//a/where/x`, not the host `a` and the path `/where/x` a URI
// reference parser makes of it. The route served is the one the path's segments name; the authority is Host's.
TEST_F(RouterE2ETest, AnOriginFormDoubleSlashIsAPathNotAnAuthority) {
    using Wire = std::pair<std::string, std::string>;
    EXPECT_EQ(exchange("GET", "//a/where/x"), (Wire{"HTTP/1.1 200 OK", "route=a;path=//a/where/x;host=;userinfo=;Host=localhost"}));
    EXPECT_EQ(exchange("GET", "///where/x"), (Wire{"HTTP/1.1 200 OK", "route=plain;path=///where/x;host=;userinfo=;Host=localhost"}));
    EXPECT_EQ(exchange("GET", "//u@a/where/x").first, "HTTP/1.1 404 Not Found") << "its first segment is `u@a`: no route, no userinfo";
    EXPECT_EQ(exchange("GET", "/where/x"), (Wire{"HTTP/1.1 200 OK", "route=plain;path=/where/x;host=;userinfo=;Host=localhost"}));
    // The control: an absolute-form target is a URI, and the request's authority is its own (RFC 9112 §3.2.2) -- the
    // Host field's value too (QB-1186).
    EXPECT_EQ(exchange("GET", url("/where/x")),
              (Wire{"HTTP/1.1 200 OK", "route=plain;path=/where/x;host=localhost;userinfo=;Host=localhost:" + std::to_string(_port)}));
}

// A target that is none of the four forms (RFC 9112 §3.2), one the URI parser refuses or one llhttp refuses itself
// (`?x`) names no resource: it is answered 400 -- not served at the path a refused parse leaves empty, the route of
// `/`, nor closed on silence.
TEST_F(RouterE2ETest, ATargetThatNamesNoResourceIsABadRequest) {
    for (std::string const target :
         {"/where/a|b", "/where/a{b}", "*", "/where/x#f", "http://u@localhost/where/x", "http:///where/x", "http://[127.0.0.1]/where/x", "?x"})
        EXPECT_EQ(exchange("GET", target).first, "HTTP/1.1 400 Bad Request") << target;
    EXPECT_EQ(exchange("GET", "/where/a%7Cb").first, "HTTP/1.1 200 OK") << "the same byte, percent-encoded";
    EXPECT_EQ(exchange("OPTIONS", "*").first, "HTTP/1.1 404 Not Found") << "the asterisk-form of OPTIONS reaches the router";
}

// Pipelined on one connection: the request before a refused target is answered, then the 400, then the connection
// closes -- what follows the refused target is never read as a request.
TEST_F(RouterE2ETest, ARefusedTargetIsAnsweredAfterThePipelinedRequestBeforeIt) {
    qb::io::tcp::socket socket;
    ASSERT_EQ(socket.connect_v4("127.0.0.1", _port), qb::io::SocketStatus::Done);
    ASSERT_TRUE(write_all(socket, "GET /where/first HTTP/1.1\r\nHost: localhost\r\n\r\n"
                                  "GET /where/a|b HTTP/1.1\r\nHost: localhost\r\n\r\n"
                                  "GET /where/third HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    const std::string wire = read_wire_response(socket);
    socket.disconnect();
    const auto first   = wire.find("HTTP/1.1 200 OK");
    const auto refused = wire.find("HTTP/1.1 400 Bad Request");
    ASSERT_NE(first, std::string::npos) << wire;
    ASSERT_NE(refused, std::string::npos) << wire;
    EXPECT_LT(first, refused) << wire;
    EXPECT_NE(wire.find("path=/where/first"), std::string::npos) << wire;
    EXPECT_EQ(wire.find("path=/where/third"), std::string::npos) << "a request after the refused target was served: " << wire;
}

// ---------------------------------------------------------------------------
// The Host field names the authority once, and well (Huly QB-1186)
// ---------------------------------------------------------------------------

// An HTTP/1.1 request carries one Host field, `uri-host [ ":" port ]` (RFC 9112 §3.2); one without it, with two field
// lines or with a value that is no host and port is answered 400. An origin-form target's authority IS that field
// (QB-1177): with two, `header("Host")` read the first and a proxy before the server may route by the other.
TEST_F(RouterE2ETest, AnHttp11RequestNamesItsHostInOneWellFormedField) {
    using Wire     = std::pair<std::string, std::string>;
    auto const get = [this](std::string const &version, std::string const &fields) {
        return exchange_raw("GET /where/x " + version + "\r\n" + fields + "Connection: close\r\n\r\n");
    };
    for (std::string const fields :
         {"", "Host: a\r\nHost: b\r\n", "Host: a\r\nhost: a\r\n", "Host: a b\r\n", "Host: u@a\r\n", "Host: a/b\r\n", "Host: a:99999\r\n",
          "Host: a:b\r\n", "Host: :80\r\n", "Host: [127.0.0.1]\r\n"})
        EXPECT_EQ(get("HTTP/1.1", fields).first, "HTTP/1.1 400 Bad Request") << fields;
    EXPECT_EQ(get("HTTP/1.1", "Host: localhost:8080\r\n"),
              (Wire{"HTTP/1.1 200 OK", "route=plain;path=/where/x;host=;userinfo=;Host=localhost:8080"}));
    EXPECT_EQ(get("HTTP/1.1", "Host: \t localhost:8080 \t \r\n"),
              (Wire{"HTTP/1.1 200 OK", "route=plain;path=/where/x;host=;userinfo=;Host=localhost:8080"}))
        << "the whitespace around a field value is not part of it (RFC 9110 §5.5)";
    EXPECT_EQ(get("HTTP/1.1", "hOsT: [::1]:8080\r\n"), (Wire{"HTTP/1.1 200 OK", "route=plain;path=/where/x;host=;userinfo=;Host=[::1]:8080"}));
    EXPECT_EQ(get("HTTP/1.1", "Host:\r\n"), (Wire{"HTTP/1.1 200 OK", "route=plain;path=/where/x;host=;userinfo=;Host="}))
        << "an empty Host is the grammar's: a target URI with no authority (RFC 9112 §3.2)";
    // HTTP/1.0 may send none; two, or a malformed one, are refused on any request.
    EXPECT_EQ(get("HTTP/1.0", "").first, "HTTP/1.1 200 OK");
    EXPECT_EQ(get("HTTP/1.0", "Host: a\r\nHost: b\r\n").first, "HTTP/1.1 400 Bad Request");
    EXPECT_EQ(get("HTTP/1.0", "Host: a b\r\n").first, "HTTP/1.1 400 Bad Request");
}

// An absolute-form target names the authority and the Host field is ignored (RFC 9112 §3.2.2) -- but still required on
// HTTP/1.1 and still checked: the request's Host field then reads the target's authority, so a reader of
// `header("Host")` builds no link to the host the field named instead.
TEST_F(RouterE2ETest, AnAbsoluteFormTargetsAuthorityIsTheHostFieldsValue) {
    using Wire              = std::pair<std::string, std::string>;
    std::string const local = "localhost:" + std::to_string(_port);
    auto const        get   = [&](std::string const &fields) {
        return exchange_raw("GET http://" + local + "/where/x HTTP/1.1\r\n" + fields + "Connection: close\r\n\r\n");
    };
    EXPECT_EQ(get("Host: evil.test\r\n"), (Wire{"HTTP/1.1 200 OK", "route=plain;path=/where/x;host=localhost;userinfo=;Host=" + local}));
    EXPECT_EQ(get("Host: " + local + "\r\n"), (Wire{"HTTP/1.1 200 OK", "route=plain;path=/where/x;host=localhost;userinfo=;Host=" + local}));
    for (std::string const fields : {"", "Host: a\r\nHost: b\r\n", "Host: a b\r\n"})
        EXPECT_EQ(get(fields).first, "HTTP/1.1 400 Bad Request") << fields;
}

// Pipelined on one connection: a request without Host is refused as a target is -- the one before it answered, the
// one after it never read.
TEST_F(RouterE2ETest, ARequestWithoutHostIsAnsweredAfterThePipelinedRequestBeforeIt) {
    qb::io::tcp::socket socket;
    ASSERT_EQ(socket.connect_v4("127.0.0.1", _port), qb::io::SocketStatus::Done);
    ASSERT_TRUE(write_all(socket, "GET /where/first HTTP/1.1\r\nHost: localhost\r\n\r\n"
                                  "GET /where/second HTTP/1.1\r\n\r\n"
                                  "GET /where/third HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    const std::string wire = read_wire_response(socket);
    socket.disconnect();
    const auto first   = wire.find("HTTP/1.1 200 OK");
    const auto refused = wire.find("HTTP/1.1 400 Bad Request");
    ASSERT_NE(first, std::string::npos) << wire;
    ASSERT_NE(refused, std::string::npos) << wire;
    EXPECT_LT(first, refused) << wire;
    EXPECT_EQ(wire.find("path=/where/second"), std::string::npos) << wire;
    EXPECT_EQ(wire.find("path=/where/third"), std::string::npos) << "a request after the refused one was served: " << wire;
}

} // namespace

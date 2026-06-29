/**
 * @file qbm/http/tests/system/middleware/middleware-pipeline-system.cpp
 * @brief Live loopback (plaintext HTTP/1.1) tests for the middleware pipeline.
 *
 * The un-gated half of the former `test-integration-middleware.cpp`. Every case
 * here drives a REAL qbm-http server over the loopback interface and exercises
 * one middleware end-to-end through the router pipeline. The JWT/Auth cases
 * (which need OpenSSL crypto) live in the sibling `middleware-auth-jwt-system.cpp`.
 *
 * Differences from the legacy monolith (per the restructure spec, §7):
 *   - DROP the misleading `integration-` prefix (loopback, not daemon).
 *   - RETIRE the `mid_server_side_assertions` / `mid_expected_server_assertions`
 *     magic-sum invariant (a TearDown count that only re-asserted the test's own
 *     increments). Each test now asserts OBSERVABLE response state: status, body,
 *     and response headers the middleware actually set.
 *   - The hand-rolled server thread (fixed magic port 29888, `server_ready` busy
 *     flag, 100ms post-ready `sleep_for`) is replaced by the shared
 *     `ServerThread<>` RAII (loopback_server.h): readiness via condition variable,
 *     ephemeral ports, worker-thread run loop. Each test configures its own
 *     routes/middleware in the worker-thread `configure` lambda.
 *   - SecurityHeaders is RE-ENABLED as a plain-HTTP variant: HSTS is correctly
 *     suppressed for non-`https` schemes by the middleware, so the test asserts
 *     the scheme-independent headers (nonce CSP, nosniff, frame-options, ...) and
 *     explicitly asserts HSTS is ABSENT over plain HTTP. No more `DISABLED_`.
 *   - Compression is verified by ACTUALLY gzip-inflating the response body
 *     (`Body::uncompress`) and comparing to the original, not just header sniffing.
 *   - The rate-limit `sleep_for(3s)` window wait is replaced by a deterministic
 *     `reset_all_clients()` on the middleware instance — no wall-clock dependency.
 *   - `std::cout`/`std::cerr` debug noise and the file-local `main()` are stripped.
 *
 * REQUIRES: live. No SSL dependency — this TU builds and runs on QB_HAS_SSL=OFF.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "../http.h"
#include "../middleware/all.h"

#include "../../shared/loopback_server.h"

#include <qb/json.h>
#include <qb/system/parse.h>

using namespace std::chrono_literals;

namespace {

class PipelineServer;

class PipelineSession : public qb::http::use<PipelineSession>::session<PipelineServer> {
public:
    explicit PipelineSession(PipelineServer &server)
        : session(server) {}
};

using PipelineCtx = qb::http::Context<PipelineSession>;

// A loopback server whose routes/middleware are installed by a caller-supplied
// builder. The builder runs on the worker thread (inside the ServerThread
// configure lambda), so every middleware lives on the thread that pumps it.
class PipelineServer : public qb::http::use<PipelineServer>::server<PipelineSession> {
public:
    PipelineServer() {
        router().set_not_found_handler([](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::NOT_FOUND;
            ctx->response().body()   = "Not found";
            ctx->complete();
        });
    }
};

using ServerThread = qb::http::test::ServerThread<PipelineServer>;

/**
 * @brief Build a loopback ServerThread that installs @p build_routes then listens.
 *
 * @p build_routes runs on the worker thread and receives the live server; it
 * registers middleware + routes and must NOT compile (this helper compiles).
 */
template <typename BuildFn>
std::unique_ptr<ServerThread>
start_pipeline_server(std::uint16_t port, BuildFn build_routes) {
    return std::make_unique<ServerThread>([port, build_routes](PipelineServer &srv) -> bool {
        build_routes(srv);
        srv.router().compile();
        if (srv.transport().listen_v4(port) != 0) {
            return false;
        }
        srv.start();
        return true;
    });
}

// Common fixture: just an ephemeral port + async init. Each test starts its own
// server with the middleware under test.
class MiddlewarePipelineTest : public ::testing::Test {
protected:
    std::uint16_t _port{0};

    void
    SetUp() override {
        qb::io::async::init();
        _port = qb::http::test::ephemeral_port();
    }

    [[nodiscard]] std::string
    base_url() const {
        return "http://localhost:" + std::to_string(_port);
    }
};

// Thread-safe capture for middleware that report through a callback (Logging,
// Timing). Reads happen on the test thread after the response round-trips.
struct LogCapture {
    std::mutex                                              mtx;
    std::vector<std::pair<qb::http::LogLevel, std::string>> messages;

    void
    log(qb::http::LogLevel level, const std::string &message) {
        std::lock_guard<std::mutex> guard(mtx);
        messages.emplace_back(level, message);
    }

    std::vector<std::pair<qb::http::LogLevel, std::string>>
    snapshot() {
        std::lock_guard<std::mutex> guard(mtx);
        return messages;
    }
};

// ---------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------

TEST_F(MiddlewarePipelineTest, PingRoundTrip) {
    auto server = start_pipeline_server(_port, [](PipelineServer &srv) {
        srv.router().get("/ping", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "pong";
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    qb::http::Request request{{base_url() + "/ping"}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;
    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("pong", response.body().as<std::string>());
}

// ---------------------------------------------------------------------------
// LoggingMiddleware
// ---------------------------------------------------------------------------

TEST_F(MiddlewarePipelineTest, LoggingMiddlewareEmitsRequestAndResponseLines) {
    auto capture = std::make_shared<LogCapture>();

    auto server = start_pipeline_server(_port, [capture](PipelineServer &srv) {
        srv.router().use<qb::http::LoggingMiddleware<PipelineSession>>(
            [capture](qb::http::LogLevel level, const std::string &message) { capture->log(level, message); }, qb::http::LogLevel::Info,
            qb::http::LogLevel::Debug);
        srv.router().get("/logged_route", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Logged route content";
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    qb::http::Request request{{base_url() + "/logged_route"}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;
    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("Logged route content", response.body().as<std::string>());

    // The middleware logs on the worker thread; wait for both lines to land.
    ASSERT_TRUE(ServerThread::pump_until([&] { return capture->snapshot().size() >= 2; }));

    bool request_log_found  = false;
    bool response_log_found = false;
    for (const auto &entry : capture->snapshot()) {
        if (entry.first == qb::http::LogLevel::Info && entry.second.find("Request: GET /logged_route") != std::string::npos) {
            request_log_found = true;
        }
        if (entry.first == qb::http::LogLevel::Debug && entry.second.find("Response: 200") != std::string::npos) {
            response_log_found = true;
        }
    }
    EXPECT_TRUE(request_log_found) << "request log line missing";
    EXPECT_TRUE(response_log_found) << "response log line missing";
}

// ---------------------------------------------------------------------------
// TimingMiddleware
// ---------------------------------------------------------------------------

TEST_F(MiddlewarePipelineTest, TimingMiddlewareSetsResponseTimeHeader) {
    auto server = start_pipeline_server(_port, [](PipelineServer &srv) {
        srv.router().use<qb::http::TimingMiddleware<PipelineSession>>(
            [](const std::chrono::milliseconds &) { /* callback presence exercised; header is the assertion */ });
        srv.router().get("/timed_route", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Timed route content";
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    qb::http::Request request{{base_url() + "/timed_route"}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;
    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("Timed route content", response.body().as<std::string>());

    // Observable, non-flaky: the header must be present and numerically parseable.
    const std::string header{response.header("X-Response-Time")};
    EXPECT_FALSE(header.empty()) << "X-Response-Time header not set";
    if (!header.empty()) {
        // X-Response-Time is "<seconds>ms" (a numeric value with a trailing unit), so parse the
        // leading numeric prefix and tolerate the "ms" suffix, like the original std::stod did.
        const auto value = qb::to_number_prefix<double>(header);
        ASSERT_TRUE(value.has_value()) << "X-Response-Time header is not numerically parseable";
        EXPECT_GE(*value, 0.0);
    }
}

// ---------------------------------------------------------------------------
// SecurityHeadersMiddleware (plain-HTTP variant, formerly DISABLED_)
// ---------------------------------------------------------------------------

TEST_F(MiddlewarePipelineTest, SecurityHeadersMiddlewarePlainHttp) {
    // The literal CSP the user installs. When the nonce feature is enabled with a
    // *user-provided* CSP, the middleware's contract (pinned by the unit test
    // SecurityHeadersMiddlewareTest.CSPNonceWithUserProvidedCSP) is that the
    // user's CSP WINS verbatim: the framework does NOT substitute any placeholder
    // into it. The per-request nonce is exposed separately on the context under
    // the "csp_nonce" key so the application can embed it itself. So {NONCE} here
    // stays literal in the rendered header; we assert that exact contract below.
    const std::string user_csp = "default-src 'self'; script-src 'self' 'nonce-{NONCE}'; object-src 'none';";

    auto server = start_pipeline_server(_port, [user_csp](PipelineServer &srv) {
        qb::http::SecurityHeadersOptions options;
        options.with_hsts("max-age=63072000; includeSubDomains; preload")
            .with_x_content_type_options_nosniff()
            .with_x_frame_options("DENY")
            .with_content_security_policy(user_csp)
            .with_referrer_policy("no-referrer")
            .with_permissions_policy("microphone=(), geolocation=()");
#ifdef QB_HAS_SSL
        // CSP-nonce generation is backed by the OpenSSL CSPRNG; with_csp_nonce(true)
        // throws std::logic_error at construction when QB_HAS_SSL is off, so the
        // nonce feature is only enabled on SSL-capable builds.
        options.with_csp_nonce(true);
#endif
        srv.router().use<qb::http::SecurityHeadersMiddleware<PipelineSession>>(options);

        srv.router().get("/secure_route", [](std::shared_ptr<PipelineCtx> ctx) {
            // The nonce is injected into context by the middleware; surface it so
            // the test can assert it independently of the header rendering.
            auto nonce = ctx->template get<std::string>("csp_nonce");
            ctx->response().set_header("X-Observed-Nonce", nonce.value_or(""));
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Secure route response";
            ctx->response().set_header("Content-Type", "text/html");
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    qb::http::Request request{{base_url() + "/secure_route"}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("Secure route response", response.body().as<std::string>());

    // Scheme-independent headers: present over plain HTTP.
    EXPECT_EQ("nosniff", response.header("X-Content-Type-Options"));
    EXPECT_EQ("DENY", response.header("X-Frame-Options"));
    EXPECT_EQ("no-referrer", response.header("Referrer-Policy"));
    EXPECT_EQ("microphone=(), geolocation=()", response.header("Permissions-Policy"));

    // HSTS is correctly suppressed for non-https schemes.
    EXPECT_TRUE(std::string(response.header("Strict-Transport-Security")).empty()) << "HSTS must not be emitted over plain HTTP";

    // The user-provided CSP is emitted verbatim regardless of the nonce feature.
    const std::string csp{response.header("Content-Security-Policy")};
    EXPECT_EQ(csp, user_csp) << "user-provided CSP must be emitted verbatim";

#ifdef QB_HAS_SSL
    // With the nonce feature on, the middleware still exposes a fresh per-request
    // nonce on the context (surfaced here as X-Observed-Nonce) even though it does
    // NOT splice it into the user's CSP — the application owns that substitution.
    const std::string observed_nonce{response.header("X-Observed-Nonce")};
    EXPECT_FALSE(observed_nonce.empty()) << "CSP nonce was not injected into context";
    // The user-provided CSP keeps the literal {NONCE} the user wrote: the framework
    // does not touch it (contract: user-provided CSP wins verbatim).
    EXPECT_NE(csp.find("{NONCE}"), std::string::npos) << "framework must not rewrite a user-provided CSP";
    EXPECT_EQ(csp.find("'nonce-" + observed_nonce + "'"), std::string::npos)
        << "framework must not splice the generated nonce into a user-provided CSP";
#else
    // No crypto: the nonce feature is off, so no nonce is exposed on the context.
    EXPECT_TRUE(std::string(response.header("X-Observed-Nonce")).empty()) << "no CSP nonce should be produced without QB_HAS_SSL";
#endif
}

// ---------------------------------------------------------------------------
// CompressionMiddleware (actually inflates the response body)
// ---------------------------------------------------------------------------

TEST_F(MiddlewarePipelineTest, CompressionMiddlewareGzipsAndInflatesRoundTrip) {
    const std::string original = "This is a sufficiently long string that should be compressed. Repeating to make it longer. "
                                 "This is a sufficiently long string that should be compressed. Repeating to make it longer. "
                                 "This is a sufficiently long string that should be compressed. Repeating to make it longer.";

    auto server = start_pipeline_server(_port, [original](PipelineServer &srv) {
        qb::http::CompressionOptions comp_options;
        comp_options.compress_responses(true).decompress_requests(true).min_size_to_compress(100).preferred_encodings({"gzip", "deflate"});
        srv.router().use<qb::http::CompressionMiddleware<PipelineSession>>(comp_options);

        srv.router().get("/compressible_route", [original](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = original;
            ctx->response().set_header("Content-Type", "text/plain");
            ctx->complete();
        });

        srv.router().post("/decompress_test_route", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Received body: " + ctx->request().body().template as<std::string>();
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    // Response compression: ask for gzip; the server middleware compresses the
    // body and sets Content-Encoding: gzip, and the qb HTTP/1.1 client then
    // TRANSPARENTLY inflates the body in its response handler (http.h
    // async::session::on -> response.body().uncompress(Content-Encoding)) before
    // the awaiter resolves. The client leaves the Content-Encoding header in
    // place, so the observable contract through this high-level client is:
    //   - Content-Encoding: gzip is present (proves the server compressed), and
    //   - response.body() is ALREADY the inflated original (the client decoded it).
    // We therefore assert that round-trip directly and must NOT inflate again
    // (a second uncompress on already-plaintext bytes throws Z_DATA_ERROR). The
    // raw smaller-than-original wire size is not observable here because the
    // client never surfaces the compressed bytes.
    {
        qb::http::Request request{{base_url() + "/compressible_route"}};
        request.add_header("Accept-Encoding", "gzip, deflate");
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::OK, response.status());

#ifdef QB_HAS_COMPRESSION
        EXPECT_EQ("gzip", response.header("Content-Encoding")) << "response should be gzip-encoded on the wire";
        EXPECT_EQ(original, response.body().template as<std::string>())
            << "client should transparently inflate the gzip body back to the original";
#else
        EXPECT_TRUE(std::string(response.header("Content-Encoding")).empty());
        EXPECT_EQ(original, response.body().as<std::string>());
#endif
    }

    // Request decompression: the server must see the decompressed body. The qb
    // HTTP/1.1 client TRANSPARENTLY compresses the request body when a
    // Content-Encoding header is set (http.h async::session::connect ->
    // _request.body().compress(Content-Encoding)), so we set the PLAINTEXT body
    // plus Content-Encoding: gzip and let the client gzip it exactly once on the
    // wire. The server's CompressionMiddleware then inflates it once and the
    // handler sees the original plaintext. (Manually pre-compressing here would
    // double-gzip: the client would compress the already-gzipped bytes a second
    // time, the middleware would inflate only one layer, and the handler would
    // echo raw gzip — which is exactly the bug this assertion guards against.)
    {
        qb::http::Request request{qb::http::method::POST, {base_url() + "/decompress_test_route"}};
        const std::string payload = "decompress-me-please";
#ifdef QB_HAS_COMPRESSION
        request.body() = payload;
        request.add_header("Content-Encoding", "gzip"); // client compresses transparently
        request.add_header("Content-Type", "text/plain");
        auto response = qb::http::run_sync(qb::http::POST(request)).response;
        EXPECT_EQ(qb::http::status::OK, response.status());
        EXPECT_EQ("Received body: " + payload, response.body().as<std::string>()) << "server did not see the decompressed request body";
#else
        request.body() = payload;
        request.add_header("Content-Type", "text/plain");
        auto response = qb::http::run_sync(qb::http::POST(request)).response;
        EXPECT_EQ(qb::http::status::OK, response.status());
        EXPECT_EQ("Received body: " + payload, response.body().as<std::string>());
#endif
    }
}

// ---------------------------------------------------------------------------
// CorsMiddleware
// ---------------------------------------------------------------------------

TEST_F(MiddlewarePipelineTest, CorsMiddlewareHandlesSimplePreflightAndCredentials) {
    auto server = start_pipeline_server(_port, [](PipelineServer &srv) {
        qb::http::CorsOptions cors_opts;
        cors_opts.origins({"http://allowed.example.com", "http://another.example.com"})
            .methods({"GET", "POST", "OPTIONS"})
            .headers({"X-Custom-Header", "Content-Type"})
            .expose_headers({"X-Response-Info"})
            .credentials(qb::http::CorsOptions::AllowCredentials::Yes)
            .max_age(std::chrono::seconds(3600));
        srv.router().use<qb::http::CorsMiddleware<PipelineSession>>(cors_opts);

        srv.router().get("/cors_test_route", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "CORS test route content";
            ctx->response().set_header("X-Response-Info", "Some info");
            ctx->complete();
        });
        srv.router().get("/cors_test_route_credentials", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "CORS credentials route content";
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    // 1. Simple GET from an allowed origin.
    {
        qb::http::Request request{{base_url() + "/cors_test_route"}};
        request.add_header("Origin", "http://allowed.example.com");
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::OK, response.status());
        EXPECT_EQ("CORS test route content", response.body().as<std::string>());
        EXPECT_EQ("http://allowed.example.com", response.header("Access-Control-Allow-Origin"));
        EXPECT_NE(std::string(response.header("Access-Control-Expose-Headers")).find("X-Response-Info"), std::string::npos);
    }

    // 2. Simple GET from a disallowed origin: handler still runs, no ACAO.
    {
        qb::http::Request request{{base_url() + "/cors_test_route"}};
        request.add_header("Origin", "http://disallowed.example.com");
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::OK, response.status());
        EXPECT_EQ("CORS test route content", response.body().as<std::string>());
        EXPECT_TRUE(std::string(response.header("Access-Control-Allow-Origin")).empty());
    }

    // 3. Preflight OPTIONS: short-circuited by the middleware.
    {
        qb::http::Request request{qb::http::method::OPTIONS, {base_url() + "/cors_test_route"}};
        request.add_header("Origin", "http://allowed.example.com");
        request.add_header("Access-Control-Request-Method", "POST");
        request.add_header("Access-Control-Request-Headers", "X-Custom-Header, Content-Type");
        auto response = qb::http::run_sync(qb::http::OPTIONS(request)).response;
        EXPECT_EQ(qb::http::status::NO_CONTENT, response.status());
        EXPECT_EQ("http://allowed.example.com", response.header("Access-Control-Allow-Origin"));
        EXPECT_NE(std::string(response.header("Access-Control-Allow-Methods")).find("POST"), std::string::npos);
        const std::string allow_headers{response.header("Access-Control-Allow-Headers")};
        EXPECT_NE(allow_headers.find("X-Custom-Header"), std::string::npos);
        EXPECT_NE(allow_headers.find("Content-Type"), std::string::npos);
        EXPECT_EQ("true", response.header("Access-Control-Allow-Credentials"));
        EXPECT_EQ("3600", response.header("Access-Control-Max-Age"));
    }

    // 4. GET with credentials from an allowed origin.
    {
        qb::http::Request request{{base_url() + "/cors_test_route_credentials"}};
        request.add_header("Origin", "http://allowed.example.com");
        request.add_header("Cookie", "sessionid=12345");
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::OK, response.status());
        EXPECT_EQ("CORS credentials route content", response.body().as<std::string>());
        EXPECT_EQ("http://allowed.example.com", response.header("Access-Control-Allow-Origin"));
        EXPECT_EQ("true", response.header("Access-Control-Allow-Credentials"));
        EXPECT_NE(std::string(response.header("Vary")).find("Origin"), std::string::npos);
    }
}

// ---------------------------------------------------------------------------
// RateLimitMiddleware (deterministic reset, no sleep_for(3s))
// ---------------------------------------------------------------------------

TEST_F(MiddlewarePipelineTest, RateLimitMiddlewareLimitsThenResets) {
    // Hold the middleware instance so the test can reset its window
    // deterministically instead of waiting out a wall-clock window.
    auto rl_mw = qb::http::rate_limit_middleware<PipelineSession>(qb::http::RateLimitOptions()
                                                                      .max_requests(3)
                                                                      .window(std::chrono::seconds(60))
                                                                      .status_code(qb::http::status::TOO_MANY_REQUESTS)
                                                                      .message("Custom: Too many requests!"));

    auto server = start_pipeline_server(_port, [rl_mw](PipelineServer &srv) {
        srv.router().use(rl_mw);
        srv.router().get("/rate_limited_route", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Rate limit test content";
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    auto make_request = [&] {
        qb::http::Request request{{base_url() + "/rate_limited_route"}};
        request.add_header("X-Forwarded-For", "127.0.0.1"); // stable client id
        return qb::http::run_sync(qb::http::GET(request)).response;
    };

    // First 3 succeed and report a decreasing remaining count.
    for (int i = 0; i < 3; ++i) {
        auto response = make_request();
        EXPECT_EQ(qb::http::status::OK, response.status()) << "request " << (i + 1) << " should succeed";
        EXPECT_EQ("Rate limit test content", response.body().as<std::string>());
        EXPECT_EQ("3", response.header("X-RateLimit-Limit"));
        EXPECT_EQ(std::to_string(3 - (i + 1)), response.header("X-RateLimit-Remaining"));
    }

    // 4th is rate-limited.
    {
        auto response = make_request();
        EXPECT_EQ(qb::http::status::TOO_MANY_REQUESTS, response.status());
        EXPECT_EQ("Custom: Too many requests!", response.body().as<std::string>());
        EXPECT_EQ("0", response.header("X-RateLimit-Remaining"));
    }

    // Deterministic window reset (no sleep): the next request succeeds again.
    rl_mw->reset_all_clients();
    {
        auto response = make_request();
        EXPECT_EQ(qb::http::status::OK, response.status());
        EXPECT_EQ("2", response.header("X-RateLimit-Remaining"));
    }
}

// ---------------------------------------------------------------------------
// ErrorHandlingMiddleware
// ---------------------------------------------------------------------------

TEST_F(MiddlewarePipelineTest, ErrorHandlingMiddlewareMapsStatusesAndRanges) {
    auto server = start_pipeline_server(_port, [](PipelineServer &srv) {
        auto error_mw = qb::http::error_handling_middleware<PipelineSession>();

        error_mw->on_status(qb::http::status::FORBIDDEN, [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::FORBIDDEN;
            ctx->response().body()   = "Custom Forbidden Error Page";
            ctx->response().set_header("X-Error-Handler", "Specific-403");
        });
        error_mw->on_status_range(qb::http::status::INTERNAL_SERVER_ERROR, qb::http::status::BAD_GATEWAY, [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::SERVICE_UNAVAILABLE;
            ctx->response().body()   = "Custom 50x Error Page (became 503)";
            ctx->response().set_header("X-Error-Handler", "Range-50x-to-503");
        });
        error_mw->on_any_error([](std::shared_ptr<PipelineCtx> ctx, const std::string &error_message) {
            if (ctx->response().status() < qb::http::status::BAD_REQUEST
                || ctx->response().status() >= qb::http::status::NETWORK_AUTHENTICATION_REQUIRED) {
                ctx->response().status() = qb::http::status::IM_A_TEAPOT;
            }
            ctx->response().body() = "Generic Error: " + error_message;
            ctx->response().set_header("X-Error-Handler", "Generic");
        });

        std::vector<std::shared_ptr<qb::http::IAsyncTask<PipelineSession>>> error_chain;
        error_chain.push_back(std::make_shared<qb::http::MiddlewareTask<PipelineSession>>(error_mw, "ErrorHandlingMiddlewareTask"));
        srv.router().set_error_task_chain(std::move(error_chain));

        srv.router().get("/generic_error", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->set("__error_message", std::string("Something bad happened generically"));
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
        srv.router().get("/specific_error", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::FORBIDDEN;
            ctx->set("__error_message", std::string("Access specifically denied"));
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
        srv.router().get("/range_error", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->set("__error_message", std::string("Triggering a 500 error for range test."));
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    });
    ASSERT_TRUE(server->ready());

    {
        qb::http::Request request{{base_url() + "/generic_error"}};
        auto              response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::IM_A_TEAPOT, response.status());
        EXPECT_EQ("Generic Error: Something bad happened generically", response.body().as<std::string>());
        EXPECT_EQ("Generic", response.header("X-Error-Handler"));
    }
    {
        qb::http::Request request{{base_url() + "/specific_error"}};
        auto              response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::FORBIDDEN, response.status());
        EXPECT_EQ("Custom Forbidden Error Page", response.body().as<std::string>());
        EXPECT_EQ("Specific-403", response.header("X-Error-Handler"));
    }
    {
        qb::http::Request request{{base_url() + "/range_error"}};
        auto              response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::SERVICE_UNAVAILABLE, response.status());
        EXPECT_EQ("Custom 50x Error Page (became 503)", response.body().as<std::string>());
        EXPECT_EQ("Range-50x-to-503", response.header("X-Error-Handler"));
    }
}

// ---------------------------------------------------------------------------
// ConditionalMiddleware
// ---------------------------------------------------------------------------

// Minimal middleware that stamps a header (and optionally short-circuits).
class HeaderStampMiddleware : public qb::http::IMiddleware<PipelineSession> {
public:
    HeaderStampMiddleware(std::string id, std::string header_name, std::string header_value)
        : _id(std::move(id))
        , _header_name(std::move(header_name))
        , _header_value(std::move(header_value)) {}

    void
    process(std::shared_ptr<PipelineCtx> ctx) override {
        ctx->response().set_header(_header_name, _header_value);
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }

    std::string
    name() const override {
        return _id;
    }

    void
    cancel() override {}

private:
    std::string _id;
    std::string _header_name;
    std::string _header_value;
};

TEST_F(MiddlewarePipelineTest, ConditionalMiddlewarePredicateFalseSkipsIf) {
    auto server = start_pipeline_server(_port, [](PipelineServer &srv) {
        auto predicate = [](const auto &) -> bool {
            return false;
        };
        auto if_mw = std::make_shared<HeaderStampMiddleware>("If", "X-If-Ran", "true");
        srv.router().use(qb::http::conditional_middleware<PipelineSession>(predicate, if_mw));
        srv.router().get("/cond", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().set_header("X-Main-Ran", "true");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Main Handler";
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    qb::http::Request request{{base_url() + "/cond"}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;
    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("Main Handler", response.body().as<std::string>());
    EXPECT_EQ("true", response.header("X-Main-Ran"));
    EXPECT_TRUE(std::string(response.header("X-If-Ran")).empty());
}

TEST_F(MiddlewarePipelineTest, ConditionalMiddlewarePredicateTrueRunsIf) {
    auto server = start_pipeline_server(_port, [](PipelineServer &srv) {
        auto predicate = [](const auto &ctx) -> bool {
            return ctx->request().uri().query("exec_if") == "1";
        };
        auto if_mw = std::make_shared<HeaderStampMiddleware>("If", "X-If-Ran", "true");
        srv.router().use(qb::http::conditional_middleware<PipelineSession>(predicate, if_mw));
        srv.router().get("/cond", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().set_header("X-Main-Ran", "true");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Main Handler";
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    qb::http::Request request{{base_url() + "/cond?exec_if=1"}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;
    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("Main Handler", response.body().as<std::string>());
    EXPECT_EQ("true", response.header("X-Main-Ran"));
    EXPECT_EQ("true", response.header("X-If-Ran"));
}

// ---------------------------------------------------------------------------
// StaticFilesMiddleware
// ---------------------------------------------------------------------------

class StaticFilesPipelineTest : public MiddlewarePipelineTest {
protected:
    std::filesystem::path _root;

    void
    SetUp() override {
        MiddlewarePipelineTest::SetUp();
        std::error_code ec;
        _root = std::filesystem::temp_directory_path(ec) / ("static_files_system_" + std::to_string(_port));
        std::filesystem::remove_all(_root, ec);
        ASSERT_TRUE(std::filesystem::create_directories(_root, ec)) << ec.message();

        auto write_file = [&](const std::string &rel, const std::string &content) {
            const auto full = _root / rel;
            std::filesystem::create_directories(full.parent_path(), ec);
            std::ofstream out(full);
            ASSERT_TRUE(out.is_open()) << "cannot write " << full;
            out << content;
        };
        write_file("file1.txt", "Contents of file1.txt");
        write_file("index.html", "Root Index HTML");
    }

    void
    TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(_root, ec);
    }
};

TEST_F(StaticFilesPipelineTest, ServesFileNotFoundIndexAndRange) {
    const std::string root_str = _root.string();
    auto              server   = start_pipeline_server(_port, [root_str](PipelineServer &srv) {
        qb::http::StaticFilesOptions options(root_str);
        options.with_range_requests(true);
        srv.router().use(qb::http::static_files_middleware<PipelineSession>(options));
    });
    ASSERT_TRUE(server->ready());

    // 1. Serve a text file.
    {
        qb::http::Request request{{base_url() + "/file1.txt"}};
        auto              response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::OK, response.status());
        EXPECT_EQ("Contents of file1.txt", response.body().as<std::string>());
        EXPECT_EQ("text/plain; charset=utf-8", response.header("Content-Type"));
    }
    // 2. Not found.
    {
        qb::http::Request request{{base_url() + "/nonexistent.txt"}};
        auto              response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::NOT_FOUND, response.status());
        EXPECT_EQ("File not found", response.body().as<std::string>());
    }
    // 3. Root index.
    {
        qb::http::Request request{{base_url() + "/"}};
        auto              response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::OK, response.status());
        EXPECT_EQ("Root Index HTML", response.body().as<std::string>());
        EXPECT_EQ("text/html; charset=utf-8", response.header("Content-Type"));
    }
    // 4. Range request.
    {
        const std::string file_content = "Contents of file1.txt";
        qb::http::Request request{{base_url() + "/file1.txt"}};
        request.add_header("Range", "bytes=9-14");
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::PARTIAL_CONTENT, response.status());
        EXPECT_EQ(file_content.substr(9, 6), response.body().as<std::string>());
        EXPECT_EQ("bytes 9-14/" + std::to_string(file_content.length()), response.header("Content-Range"));
        EXPECT_EQ("bytes", response.header("Accept-Ranges"));
    }
}

// ---------------------------------------------------------------------------
// TransformMiddleware
// ---------------------------------------------------------------------------

TEST_F(MiddlewarePipelineTest, TransformMiddlewareRewritesRequestBodyAndHeader) {
    auto server = start_pipeline_server(_port, [](PipelineServer &srv) {
        qb::http::TransformMiddleware<PipelineSession>::RequestTransformer transformer = [](qb::http::Request &req) {
            req.set_header("X-Request-Transformed", "true");
            req.body() = "TransformedBody:" + req.body().as<std::string>();
        };
        srv.router().use(qb::http::transform_middleware<PipelineSession>(transformer, "RequestTransformMW"));
        srv.router().post("/transformed_route", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "handled";
            ctx->response().set_header("X-Handler-Saw-Header", ctx->request().header("X-Request-Transformed"));
            ctx->response().set_header("X-Handler-Saw-Body", ctx->request().body().as<std::string>());
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    qb::http::Request request{qb::http::method::POST, {base_url() + "/transformed_route"}};
    request.body() = "OriginalData";
    auto response  = qb::http::run_sync(qb::http::POST(request)).response;

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("handled", response.body().as<std::string>());
    EXPECT_EQ("true", response.header("X-Handler-Saw-Header"));
    EXPECT_EQ("TransformedBody:OriginalData", response.header("X-Handler-Saw-Body"));
}

TEST_F(MiddlewarePipelineTest, TransformMiddlewareChangesRequestMethod) {
    auto server = start_pipeline_server(_port, [](PipelineServer &srv) {
        qb::http::TransformMiddleware<PipelineSession>::RequestTransformer changer = [](qb::http::Request &req) {
            req.method() = qb::http::method::PUT;
            req.set_header("X-Method-Altered", "true");
        };
        srv.router().use(qb::http::transform_middleware<PipelineSession>(changer, "MethodChangerMW"));
        srv.router().post("/method_change", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "handled";
            ctx->response().set_header("X-Handler-Method", std::to_string(ctx->request().method()));
            ctx->response().set_header("X-Method-Altered", ctx->request().header("X-Method-Altered"));
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    qb::http::Request request{qb::http::method::POST, {base_url() + "/method_change"}};
    request.body() = "data";
    auto response  = qb::http::run_sync(qb::http::POST(request)).response;

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ(std::to_string(qb::http::method::PUT), response.header("X-Handler-Method"));
    EXPECT_EQ("true", response.header("X-Method-Altered"));
}

// ---------------------------------------------------------------------------
// ValidationMiddleware
// ---------------------------------------------------------------------------

TEST_F(MiddlewarePipelineTest, ValidationMiddlewareAcceptsValidBody) {
    auto server = start_pipeline_server(_port, [](PipelineServer &srv) {
        auto     validator   = std::make_shared<qb::http::validation::RequestValidator>();
        qb::json body_schema = {{"type", "object"}, {"properties", {{"name", {{"type", "string"}}}}}, {"required", {"name"}}};
        validator->for_body(body_schema);
        srv.router().use(qb::http::validation_middleware<PipelineSession>(validator));
        srv.router().post("/val_body", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Valid body processed";
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    qb::http::Request request{qb::http::method::POST, {base_url() + "/val_body"}};
    request.body() = qb::json{{"name", "Test User"}}.dump();
    request.set_header("Content-Type", "application/json");
    auto response = qb::http::run_sync(qb::http::POST(request)).response;

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("Valid body processed", response.body().as<std::string>());
}

TEST_F(MiddlewarePipelineTest, ValidationMiddlewareRejectsInvalidBody) {
    auto server = start_pipeline_server(_port, [](PipelineServer &srv) {
        auto     validator   = std::make_shared<qb::http::validation::RequestValidator>();
        qb::json body_schema = {
            {"type", "object"},
            {"properties", {{"email", {{"type", "string"}, {"pattern", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"}}}}},
            {"required", {"email"}}
        };
        validator->for_body(body_schema);
        srv.router().use(qb::http::validation_middleware<PipelineSession>(validator));
        srv.router().post("/val_body_invalid", [](std::shared_ptr<PipelineCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Handler reached unexpectedly";
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    qb::http::Request request{qb::http::method::POST, {base_url() + "/val_body_invalid"}};
    request.body() = qb::json{{"email", "not-an-email"}}.dump();
    request.set_header("Content-Type", "application/json");
    auto response = qb::http::run_sync(qb::http::POST(request)).response;

    EXPECT_EQ(qb::http::status::BAD_REQUEST, response.status());
    EXPECT_EQ("application/json; charset=utf-8", response.header("Content-Type"));
    qb::json error_response = qb::json::parse(response.body().as<std::string_view>());
    EXPECT_EQ("Validation failed.", error_response["message"].get<std::string>());
    ASSERT_TRUE(error_response["errors"].is_array() && !error_response["errors"].empty());
    bool email_pattern_error_found = false;
    for (const auto &err : error_response["errors"]) {
        if (err["field"].get<std::string>() == "email" && err["rule"].get<std::string>() == "pattern") {
            email_pattern_error_found = true;
            break;
        }
    }
    EXPECT_TRUE(email_pattern_error_found) << "email pattern error not found in: " << error_response.dump(2);
}

} // namespace

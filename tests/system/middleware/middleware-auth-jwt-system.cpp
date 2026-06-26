/**
 * @file qbm/http/tests/system/middleware/middleware-auth-jwt-system.cpp
 * @brief Live loopback tests for the JWT + Auth middleware (crypto-gated half).
 *
 * The crypto half of the former `test-integration-middleware.cpp`. These cases
 * drive `qb::http::JwtMiddleware` and the JWT-backed `AuthMiddleware` end-to-end
 * through a REAL qbm-http loopback server, forging signed tokens with the shared
 * auth helpers. The plain-pipeline middleware (logging, cors, compression, ...)
 * lives in the sibling `middleware-pipeline-system.cpp`.
 *
 * Why this half is `REQUIRES ssl`: JWT verification (HMAC-SHA256) links against
 * OpenSSL through qb-io's crypto layer, so the TU only builds when QB_HAS_SSL is
 * on. The transport itself is plain HTTP loopback — the assertion surface is the
 * verifier's accept/reject decision, observable in the response status/body.
 *
 * Differences from the legacy monolith (per the restructure spec, §7):
 *   - DROP the misleading `integration-` prefix (loopback, not daemon).
 *   - RETIRE the `mid_server_side_assertions` / `mid_expected_server_assertions`
 *     magic-sum invariant; the handler instead stamps what it observed (subject,
 *     role) into response headers so the test can assert it OBSERVABLY.
 *   - The hand-rolled server thread (fixed magic port 29888, busy `server_ready`
 *     flag, 100ms post-ready `sleep_for`) is replaced by the shared
 *     `ServerThread<>` RAII: condition-variable readiness, ephemeral port.
 *   - The file-local JWT-generation helper is replaced by the shared
 *     `forge_claims_token` helper (auth_test_helpers.h).
 *   - `std::cout`/`std::cerr` debug noise and the file-local `main()` are stripped.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <map>
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "../http.h"
#include "../middleware/all.h"

#include "../../shared/auth_test_helpers.h"
#include "../../shared/loopback_server.h"

#include <qb/io/crypto_jwt.h>
#include <qb/json.h>

#if QB_HAS_SSL

using namespace std::chrono_literals;

namespace {

constexpr char kJwtSecret[]    = "another_secret_for_jwt_testing_09876_XYZ";
constexpr char kJwtAlgorithm[] = "HS256";

class AuthServer;

class AuthSession : public qb::http::use<AuthSession>::session<AuthServer> {
public:
    explicit AuthSession(AuthServer &server)
        : session(server) {}
};

using AuthCtx = qb::http::Context<AuthSession>;

class AuthServer : public qb::http::use<AuthServer>::server<AuthSession> {
public:
    AuthServer() = default;
};

using ServerThread = qb::http::test::ServerThread<AuthServer>;

template <typename BuildFn>
std::unique_ptr<ServerThread>
start_auth_server(std::uint16_t port, BuildFn build_routes) {
    return std::make_unique<ServerThread>([port, build_routes](AuthServer &srv) -> bool {
        build_routes(srv);
        srv.router().compile();
        if (srv.transport().listen_v4(port) != 0) {
            return false;
        }
        srv.start();
        return true;
    });
}

// Forge a signed JWT carrying sub/iat/nbf/exp plus extra string claims, matching
// the wire shape the verifier expects. Deltas are relative to "now".
std::string
make_token(const std::string &subject, const std::map<std::string, std::string> &extra_claims = {},
           long long exp_delta_seconds = 3600, long long nbf_delta_seconds = 0) {
    const auto                         now = qb::http::test::now_epoch();
    std::map<std::string, std::string> claims;
    claims["sub"] = subject;
    claims["iat"] = std::to_string(now);
    if (exp_delta_seconds != 0) {
        claims["exp"] = std::to_string(static_cast<long long>(now) + exp_delta_seconds);
    }
    claims["nbf"] = std::to_string(static_cast<long long>(now) + nbf_delta_seconds);
    for (const auto &[k, v] : extra_claims) {
        claims[k] = v;
    }
    return qb::http::test::forge_claims_token(claims, kJwtSecret, qb::jwt::Algorithm::HS256);
}

class MiddlewareAuthJwtTest : public ::testing::Test {
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

// ---------------------------------------------------------------------------
// JwtMiddleware
// ---------------------------------------------------------------------------

TEST_F(MiddlewareAuthJwtTest, JwtMiddlewareEnforcesSignatureExpiryNbfAndRequiredClaims) {
    auto server = start_auth_server(_port, [](AuthServer &srv) {
        qb::http::JwtOptions jwt_options;
        jwt_options.secret         = kJwtSecret;
        jwt_options.algorithm      = kJwtAlgorithm;
        jwt_options.verify_exp     = true;
        jwt_options.verify_nbf     = true;
        jwt_options.leeway         = std::chrono::seconds(2);
        jwt_options.token_location = qb::http::JwtTokenLocation::HEADER;
        jwt_options.token_name     = "Authorization";
        jwt_options.auth_scheme    = "Bearer";

        auto jwt_mw = qb::http::jwt_middleware_with_options<AuthSession>(jwt_options);
        jwt_mw->require_claims({"custom_claim"});
        srv.router().use(jwt_mw);

        srv.router().get("/jwt_route", [](std::shared_ptr<AuthCtx> ctx) {
            auto payload = ctx->template get<qb::json>("jwt_payload");
            // Surface what the verifier produced so the test asserts it observably.
            if (payload.has_value() && payload->contains("sub") && (*payload)["sub"].is_string()) {
                ctx->response().set_header("X-Jwt-Subject", (*payload)["sub"].get<std::string>());
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "JWT Auth OK";
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    // 1. No token.
    {
        qb::http::Request request{{base_url() + "/jwt_route"}};
        auto              response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::UNAUTHORIZED, response.status());
    }
    // 2. Garbage token.
    {
        qb::http::Request request{{base_url() + "/jwt_route"}};
        request.add_header("Authorization", "Bearer garbage");
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::UNAUTHORIZED, response.status());
    }
    // 3. Expired token.
    {
        auto              token = make_token("simple_user", {{"custom_claim", "value"}}, -10);
        qb::http::Request request{{base_url() + "/jwt_route"}};
        request.add_header("Authorization", "Bearer " + token);
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::UNAUTHORIZED, response.status());
    }
    // 4. Not-yet-valid token (nbf in the future).
    {
        auto              token = make_token("simple_user", {{"custom_claim", "value"}}, 3600, 60);
        qb::http::Request request{{base_url() + "/jwt_route"}};
        request.add_header("Authorization", "Bearer " + token);
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::UNAUTHORIZED, response.status());
    }
    // 5. Valid signature but missing required claim.
    {
        auto              token = make_token("simple_user"); // no custom_claim
        qb::http::Request request{{base_url() + "/jwt_route"}};
        request.add_header("Authorization", "Bearer " + token);
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::UNAUTHORIZED, response.status());
        EXPECT_NE(response.body().as<std::string>().find("Required claim 'custom_claim' is missing"),
                  std::string::npos);
    }
    // 6. Fully valid token.
    {
        auto              token = make_token("simple_user", {{"custom_claim", "value"}}, 3600, -5);
        qb::http::Request request{{base_url() + "/jwt_route"}};
        request.add_header("Authorization", "Bearer " + token);
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::OK, response.status());
        EXPECT_EQ("JWT Auth OK", response.body().as<std::string>());
        EXPECT_EQ("simple_user", response.header("X-Jwt-Subject"));
    }
}

// ---------------------------------------------------------------------------
// AuthMiddleware (JWT-backed, role-gated)
// ---------------------------------------------------------------------------

TEST_F(MiddlewareAuthJwtTest, AuthMiddlewareEnforcesAuthenticationAndRole) {
    auto server = start_auth_server(_port, [](AuthServer &srv) {
        auto auth_mw = qb::http::jwt_auth_middleware<AuthSession>(kJwtSecret, kJwtAlgorithm, "AuthMiddlewareInstance");
        auth_mw->with_roles({"editor"}, true); // require "editor"
        srv.router().use(auth_mw);

        srv.router().get("/auth_route", [](std::shared_ptr<AuthCtx> ctx) {
            auto user = ctx->template get<qb::http::auth::User>("user");
            if (user.has_value()) {
                ctx->response().set_header("X-Auth-User", user->id);
                ctx->response().set_header("X-Auth-Has-Editor", user->has_role("editor") ? "yes" : "no");
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Auth Route OK - JWT Verified";
            ctx->complete();
        });
    });
    ASSERT_TRUE(server->ready());

    // 1. No Authorization header.
    {
        qb::http::Request request{{base_url() + "/auth_route"}};
        auto              response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::UNAUTHORIZED, response.status());
        EXPECT_NE(response.body().as<std::string>().find("Authentication required"), std::string::npos);
    }
    // 2. Malformed token.
    {
        qb::http::Request request{{base_url() + "/auth_route"}};
        request.add_header("Authorization", "Bearer aninvalidtokenstring");
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::UNAUTHORIZED, response.status());
        EXPECT_NE(response.body().as<std::string>().find("Invalid or expired token"), std::string::npos);
    }
    // 3. Valid token, wrong role.
    {
        auto token = make_token("user123", {{"roles", qb::json::array({"viewer"}).dump()}});
        qb::http::Request request{{base_url() + "/auth_route"}};
        request.add_header("Authorization", "Bearer " + token);
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::FORBIDDEN, response.status());
        EXPECT_NE(response.body().as<std::string>().find("Insufficient permissions"), std::string::npos);
    }
    // 4. Valid token, correct role.
    {
        auto token = make_token("user123", {{"roles", qb::json::array({"editor", "another_role"}).dump()}});
        qb::http::Request request{{base_url() + "/auth_route"}};
        request.add_header("Authorization", "Bearer " + token);
        auto response = qb::http::run_sync(qb::http::GET(request)).response;
        EXPECT_EQ(qb::http::status::OK, response.status());
        EXPECT_EQ("Auth Route OK - JWT Verified", response.body().as<std::string>());
        EXPECT_EQ("user123", response.header("X-Auth-User"));
        EXPECT_EQ("yes", response.header("X-Auth-Has-Editor"));
    }
}

} // namespace

#endif // QB_HAS_SSL

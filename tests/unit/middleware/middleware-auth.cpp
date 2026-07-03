/**
 * @file qbm/http/tests/unit/middleware/middleware-auth.cpp
 * @brief Unit tests for qb::http::AuthMiddleware<Session> and its factories.
 *
 * Drives the auth middleware through a real `qb::http::Router<AuthSession>` with a
 * capturing mock session — token extraction/verification (HMAC-SHA256/384/512,
 * RSA-SHA256, ECDSA-SHA256/ES256), role-based authorization (any / all), the
 * pre-authenticated context-user and `jwt_payload` ingress paths, optional auth,
 * custom user-context keys, custom auth scheme/header, clock-skew tolerance,
 * issuer/audience verification, header/scheme case-insensitivity, whitespace
 * tolerance, and an algorithm-confusion attack surface.
 *
 * Tier: **unit** with an `ssl` build dependency — JWT HMAC/RSA/EC signing &
 * verification go through `qb/io/crypto_jwt.h` (OpenSSL). No engine, socket, or
 * event loop: `Router::route` runs synchronously against the mock session.
 *
 * Restructured from the prior monolith:
 *   - Adopts the shared `MiddlewareTestFixture` / token helpers (auth_test_helpers.h).
 *   - The 8-scenario `IssuerAudienceFlexibility`, 4-scenario `ClockSkewTolerance`,
 *     4-scenario `RequireAllRoles` and the case-insensitivity packs are SPLIT into
 *     one `TEST_F` per scenario for failure localization.
 *   - Clock cases freeze `now` once per test (`now_epoch()`), then build BOTH the
 *     token's time claims and the verifier's reference window from that single
 *     captured instant with comfortable (load-immune) margins — no real sleeps.
 *   - The embedded RSA PEM pair is kept (deterministic, fast); an EC keypair is
 *     generated at setup for the ES256 case.
 *   - ADDS ES256 round-trip + algorithm-confusion negatives (HMAC token vs EC
 *     config, EC token vs HMAC config, RSA token vs HMAC config).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <qb/io/crypto.h>     // qb::crypto::generate_ec_keypair
#include <qb/io/crypto_jwt.h> // qb::jwt::{create, CreateOptions, Algorithm}
#include <qb/json.h>          // qb::json

#include "../../shared/auth_test_helpers.h"       // now_epoch
#include "../../shared/middleware_test_fixture.h" // MiddlewareTestFixture, MockMiddlewareSession
#include "../http.h"                              // Router, Context, FunctionalMiddleware, status, method
#include "../middleware/auth.h"                   // AuthMiddleware + factories

namespace {

using qb::http::auth::Manager;
using qb::http::auth::Options;
using qb::http::auth::User;
using qb::http::test::now_epoch;

constexpr char kSecret[] = "test_secret_key_for_auth_middleware_123";

// ---------------------------------------------------------------------------
// RSA test key pair (deterministic, embedded for speed). EC keys are generated
// per-process in the fixture (see SetUp).
// ---------------------------------------------------------------------------
const char *kRsaPrivateKeyPem = "-----BEGIN PRIVATE KEY-----\n"
                                "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC9XQ6VOHmUCz/d\n"
                                "b5jFqL/5ogkA7Zz6Kt2SR0eWa3lOLMimTcHGMNrkkeXt0vvHBKDiB5Rh8Jg40mar\n"
                                "CJudCO2ngIxh90toXSiZmtQzZwWHgxH3oqQFYw7kVKssVHuXusC+HC40V333kijR\n"
                                "l2xHX+ckFrzMCJu5zeBOTs+D+2w0EfaEmXTF1XRjsaxjXHA4VMzRjymo+XO73Csi\n"
                                "TSfqPfg2z+P3hz9owqamBc9SuJk5Ke1bv0Rzgauy1Po4B8bWJU0rk3KT2XUuAfJl\n"
                                "bumWwHWjM7G5ubhHyIADU7onHAYCucsZkoSqaKMe6K1ZCXTBYQYB9jcSVfhG/eFe\n"
                                "d0fKRA1/AgMBAAECggEAWHDMXUwdmFOytcinuPVKCByyCNFxRfPcPTP2Tt4OL0FC\n"
                                "S024qUhrC2LK2Qr3lalnPHnexulYJv25frsL9slTOa6TojOd7/XGfwstfX5pujMw\n"
                                "opA++9cafvC+a3tfp+tMlt3RhJeyWPzV/KG0rBcx/Ix0C/UfSiXJ07kCOXmlPSGy\n"
                                "H5AJNax1v/RMT1aP4fDUj8VhN9y58GoM+kkKuvrl/hMVdXSpIXtrGR9jDHBQXVjb\n"
                                "MybxAH5FvR1SY0d8rC6cq6Z7kuX9T/mqZYDxqxhxxyj9+tw0lrFyQtUcZ1mAdWKL\n"
                                "VjCAh0W28BCaEM/OmsTxjxfg+OZ5g+aa5Wc26sGw+QKBgQDwoBUHs4/zz93SInp6\n"
                                "S8EBp/T8qDoeUomxvgOPfi9cjOdUpMGm0z8JSca1Y4gIfjPXAjEwR+xK6ok0F7hL\n"
                                "i+XQUSfTJ91itPirRcILQijxahSkvt2BjbD2F+aRqzyRg+3hjLbUEySYNG/WkZNs\n"
                                "HqLFSQ4bC8TPUOH2OvjcOb9nZwKBgQDJdnu2hyTvR6vsDe6gJ4syGhnDk5sbpGlm\n"
                                "ZAyILw4vmMD9r6IGR++xnNf0ZTcOpgRJ2FFtntZIU/K8/gICV19XkNCA8g3X3mRN\n"
                                "CiTvqOBBrkTsrBbk04rYWy3NHGO8nciy5D05r6ox6uo7mIVbUYoqSmKdtwIEIxeX\n"
                                "jUbfzabSKQKBgC3ugNUtg4cI4NDh3/tERp1oUC2Cd0Wef8Y7/TYA4k2KYAYaRRTx\n"
                                "MhE10gaB70+ft4mNU5JhyEsspfAZrwZMuBuhwjZeX7Yd0XHwKPA5OtOKalJgVKwM\n"
                                "PgFb4plf1Hn6cwgg8i1dUhjzuX194GQ9HNkH7vdesbzZNajo7OQs6cp1AoGAFzDE\n"
                                "XOaBoemmKK4R4e2rYEEQ5ip/mFb8qwSpTKPeBiyXSpyFEiQFu3RKh59/DvidVcLI\n"
                                "3M2D7R98ubSjlpFoMDRDTBSQ82BuO1AHoG7YIbdlx7inif+v4+fbBdlWwceH6s/L\n"
                                "HHDULprUC7gq4bApL2UQpQcD/GXtuUxR9EFACsECgYBufXuFy2L7KP5Wh8wk9Ref\n"
                                "M9b9wQF7Lo9gySj6sBSuBOmMLOli0uLnhoiZ1U3dIkOC3tFwMOIhC5sQiB75nnCJ\n"
                                "/SzObI1PFJ0pUYKeHi0rVltHvZQ4tKvJd0l10qI5C/ND+QJoXs74RHElwUM3UdgT\n"
                                "Wr7IeElg/Hj/Xu9vfiTVnw==\n"
                                "-----END PRIVATE KEY-----";

const char *kRsaPublicKeyPem = "-----BEGIN PUBLIC KEY-----\n"
                               "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvV0OlTh5lAs/3W+Yxai/\n"
                               "+aIJAO2c+irdkkdHlmt5TizIpk3BxjDa5JHl7dL7xwSg4geUYfCYONJmqwibnQjt\n"
                               "p4CMYfdLaF0omZrUM2cFh4MR96KkBWMO5FSrLFR7l7rAvhwuNFd995Io0ZdsR1/n\n"
                               "JBa8zAibuc3gTk7Pg/tsNBH2hJl0xdV0Y7GsY1xwOFTM0Y8pqPlzu9wrIk0n6j34\n"
                               "Ns/j94c/aMKmpgXPUriZOSntW79Ec4GrstT6OAfG1iVNK5Nyk9l1LgHyZW7plsB1\n"
                               "ozOxubm4R8iAA1O6JxwGArnLGZKEqmijHuitWQl0wWEGAfY3ElX4Rv3hXndHykQN\n"
                               "fwIDAQAB\n"
                               "-----END PUBLIC KEY-----";

/// Capturing session for the auth middleware: records the typed User slot.
struct AuthSession : qb::http::test::MockMiddlewareSession {
    std::optional<User> _user_in_context;

    void
    reset() {
        qb::http::test::MockMiddlewareSession::reset();
        _user_in_context.reset();
    }
};

/// Fixture sharing the canonical middleware harness, with auth-specific helpers.
class AuthMiddlewareTest : public qb::http::test::MiddlewareTestFixture<AuthSession> {
protected:
    Options                                                _auth_options; ///< Base HMAC options (secret pre-loaded).
    std::shared_ptr<qb::http::AuthMiddleware<AuthSession>> _auth_mw;      ///< Default HMAC middleware.
    std::string                                            _ec_private;   ///< ES256 private PEM (per-process).
    std::string                                            _ec_public;    ///< ES256 public PEM (per-process).

    void
    SetUp() override {
        qb::http::test::MiddlewareTestFixture<AuthSession>::SetUp();
        _auth_options.secret_key(kSecret);
        _auth_mw = qb::http::auth_middleware<AuthSession>(_auth_options);

        auto ec     = qb::crypto::generate_ec_keypair("prime256v1"); // {private, public}
        _ec_private = ec.first;
        _ec_public  = ec.second;
    }

    /// Handler that records the authenticated User (default "user" slot) and replies 200.
    qb::http::RouteHandlerFn<AuthSession>
    user_capturing_handler(const std::string &context_key = "user") {
        return [this, context_key](std::shared_ptr<qb::http::Context<AuthSession>> ctx) {
            _session->_final_handler_called = true;
            if (ctx->has(context_key)) {
                _session->_user_in_context = ctx->template get<User>(context_key);
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Access Granted";
            ctx->complete();
        };
    }

    /// Wire @p mw ahead of a user-capturing handler on @p path and route one request.
    void
    run(std::shared_ptr<qb::http::AuthMiddleware<AuthSession>> mw, qb::http::Request request, const std::string &context_key = "user",
        const std::string &path = "/test") {
        _router = std::make_unique<qb::http::Router<AuthSession>>();
        _router->use(std::move(mw));
        _router->get(path, user_capturing_handler(context_key));
        _router->compile();
        _session->reset();
        _router->route(_session, std::move(request));
    }

    qb::http::Request
    authed_request(const std::string &header_value, const std::string &header_name = "Authorization", const std::string &path = "/test") {
        auto r = create_request(qb::http::method::GET, path);
        r.set_header(header_name, header_value);
        return r;
    }

    /// Token from the fixture HMAC secret (or an override secret).
    std::string
    hmac_token(const User &user, const std::string &secret_override = "") {
        Manager mgr(secret_override.empty() ? _auth_options : Options().secret_key(secret_override));
        return mgr.generate_token(user);
    }

    /**
     * @brief Sign a token directly via qb::jwt with explicit time claims.
     *
     * Builds the claim map (roles serialized as a JSON-array string, exactly as
     * the Manager does) and stamps iat/exp/nbf/iss/aud as provided. All times are
     * derived from a single captured `now` so a test's create-side and verify-side
     * reference the same instant (no intra-test clock drift across the window).
     */
    std::string
    sign_jwt(qb::jwt::Algorithm alg, const std::string &key, const User &user, std::optional<std::int64_t> exp = std::nullopt,
             std::optional<std::int64_t> nbf = std::nullopt, std::optional<std::int64_t> iat = std::nullopt,
             std::optional<std::string> iss = std::nullopt, std::optional<std::string> aud = std::nullopt) {
        std::map<std::string, std::string> claims;
        claims["sub"]      = user.id;
        claims["username"] = user.username;
        claims["roles"]    = qb::json(user.roles).dump();
        if (iat)
            claims["iat"] = std::to_string(*iat);
        if (exp)
            claims["exp"] = std::to_string(*exp);
        if (nbf)
            claims["nbf"] = std::to_string(*nbf);
        if (iss)
            claims["iss"] = *iss;
        if (aud)
            claims["aud"] = *aud;
        qb::jwt::CreateOptions opts;
        opts.algorithm = alg;
        opts.key       = key;
        return qb::jwt::create(claims, opts);
    }

    [[nodiscard]] std::string
    body() const {
        return _session->_response.body().template as<std::string>();
    }
    [[nodiscard]] qb::http::status
    status() const {
        return _session->_response.status();
    }
};

// ===========================================================================
// Core authentication (HMAC happy path + missing/invalid token)
// ===========================================================================

TEST_F(AuthMiddlewareTest, ValidTokenAuthentication) {
    const std::string token = hmac_token(User{"user123", "testuser", {"user"}});
    run(_auth_mw, authed_request("Bearer " + token));

    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_EQ(body(), "Access Granted");
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user123");
}

TEST_F(AuthMiddlewareTest, JwtFactoryRejectsUnknownAlgorithmInsteadOfSilentHsFallback) {
    // An unrecognised algorithm string used to silently fall back to HMAC_SHA256, routing the
    // `secret` argument into the HMAC secret slot. If the caller intended an asymmetric
    // algorithm and passed a PEM PUBLIC key, that public key became the HMAC secret and the
    // server would accept attacker-forged HS256 tokens (classic RS→HS key confusion). The
    // factory must now fail loudly at construction instead.
    EXPECT_THROW((void) qb::http::jwt_auth_middleware<AuthSession>("public-key-or-secret", "RS256_TYPO"), std::invalid_argument);
    EXPECT_THROW((void) qb::http::jwt_auth_middleware<AuthSession>("public-key-or-secret", ""), std::invalid_argument);
    // A valid, case-insensitive algorithm still constructs fine (unchanged behavior).
    EXPECT_NO_THROW((void) qb::http::jwt_auth_middleware<AuthSession>("secret", "hs256"));
}

TEST_F(AuthMiddlewareTest, MissingToken) {
    _auth_mw->with_auth_required(true);
    run(_auth_mw, create_request(qb::http::method::GET, "/test"));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Authentication required: Missing token or authorization header.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, InvalidToken) {
    _auth_mw->with_auth_required(true);
    run(_auth_mw, authed_request("Bearer an_invalid_token_string"));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid or expired token; user authentication failed.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, TokenWithoutSubjectOrUsernameIsRejected) {
    _auth_mw->with_auth_required(true);

    // Signature-valid token carrying neither sub nor username.
    qb::jwt::CreateOptions opts;
    opts.algorithm = qb::jwt::Algorithm::HS256;
    opts.key       = kSecret;
    std::map<std::string, std::string> payload{
        {"roles", qb::json::array({"user"}).dump()},
        {"iat", std::to_string(now_epoch())},
        {"exp", std::to_string(now_epoch() + 3600)},
    };
    run(_auth_mw, authed_request("Bearer " + qb::jwt::create(payload, opts)));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

// ===========================================================================
// Signature-verification-disabled path still enforces claim checks
// ===========================================================================

TEST_F(AuthMiddlewareTest, SignatureDisabledStillAcceptsValidClaims) {
    Options relaxed = _auth_options;
    relaxed.require_signature_verification(false);
    _auth_mw->with_options(relaxed).with_auth_required(true);

    run(_auth_mw, authed_request("Bearer " + hmac_token(User{"user_sigless", "sigless", {"user"}})));
    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user_sigless");
}

TEST_F(AuthMiddlewareTest, SignatureDisabledStillRejectsExpired) {
    Options relaxed = _auth_options;
    relaxed.require_signature_verification(false);
    relaxed.token_expiration(std::chrono::seconds(-1));
    _auth_mw->with_options(relaxed).with_auth_required(true);

    Manager     mgr(relaxed);
    std::string expired = mgr.generate_token(User{"user_sigless", "sigless", {"user"}});
    run(_auth_mw, authed_request("Bearer " + expired));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, SignatureDisabledInvalidExpClaimIsRejectedWithoutThrowing) {
    Options relaxed = _auth_options;
    relaxed.require_signature_verification(false);
    relaxed.verify_expiration(true);
    _auth_mw->with_options(relaxed).with_auth_required(true);

    qb::jwt::CreateOptions opts;
    opts.algorithm = qb::jwt::Algorithm::HS256;
    opts.key       = kSecret;
    std::map<std::string, std::string> payload{
        {"sub", "user_invalid_exp"},          {"username", "invalidexp"}, {"roles", qb::json::array({"user"}).dump()},
        {"iat", std::to_string(now_epoch())}, {"exp", "not-a-number"},
    };
    auto req = authed_request("Bearer " + qb::jwt::create(payload, opts));

    EXPECT_NO_THROW(run(_auth_mw, std::move(req)));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

// ===========================================================================
// Role-based authorization (single role / pre-set context / jwt_payload)
// ===========================================================================

TEST_F(AuthMiddlewareTest, ValidRoleAuthorization) {
    _auth_mw->with_auth_required(true).with_roles({"admin"});
    run(_auth_mw, authed_request("Bearer " + hmac_token(User{"admin1", "adminuser", {"admin", "user"}})));

    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->username, "adminuser");
}

TEST_F(AuthMiddlewareTest, InvalidRoleAuthorization) {
    _auth_mw->with_auth_required(true).with_roles({"admin"});
    run(_auth_mw, authed_request("Bearer " + hmac_token(User{"user001", "reguser", {"user"}})));

    EXPECT_EQ(status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Insufficient permissions based on user roles.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, RoleMiddlewareUsesPreAuthenticatedContextUser) {
    auto role_mw = qb::http::role_auth_middleware<AuthSession>({"admin"});

    _router = std::make_unique<qb::http::Router<AuthSession>>();
    _router->use(std::make_shared<qb::http::FunctionalMiddleware<AuthSession>>(
        [](auto ctx, auto next_fn) {
            ctx->template set<User>("user", User{"ctx-user", "contextuser", {"admin"}});
            next_fn();
        },
        "PreAuthenticatedUserSetter"));
    _router->use(role_mw);
    _router->get("/role-from-context", user_capturing_handler());
    _router->compile();

    _session->reset();
    _router->route(_session, create_request(qb::http::method::GET, "/role-from-context"));

    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "ctx-user");
}

TEST_F(AuthMiddlewareTest, JwtPayloadStringRolesAuthorizeRoleChecks) {
    _auth_mw->with_auth_required(true).with_roles({"admin"});

    _router = std::make_unique<qb::http::Router<AuthSession>>();
    _router->use(std::make_shared<qb::http::FunctionalMiddleware<AuthSession>>(
        [](auto ctx, auto next_fn) {
            qb::json payload;
            payload["sub"]      = "jwt-context-user";
            payload["username"] = "jwtcontext";
            payload["roles"]    = qb::json::array({"admin", "user"}).dump();
            ctx->template set<qb::json>("jwt_payload", std::move(payload));
            next_fn();
        },
        "JwtPayloadSetter"));
    _router->use(_auth_mw);
    _router->get("/role-from-jwt-payload", user_capturing_handler());
    _router->compile();

    _session->reset();
    _router->route(_session, create_request(qb::http::method::GET, "/role-from-jwt-payload"));

    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "jwt-context-user");
    EXPECT_TRUE(_session->_user_in_context->has_role("admin"));
}

// ===========================================================================
// require_all roles (split from the old 4-scenario megatest)
// ===========================================================================

TEST_F(AuthMiddlewareTest, RequireAllRolesUserHasAll) {
    _auth_mw->with_auth_required(true).with_roles({"editor", "viewer"}, true);
    run(_auth_mw, authed_request("Bearer " + hmac_token(User{"user_all_roles", "allroler", {"editor", "viewer", "commenter"}})));

    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user_all_roles");
}

TEST_F(AuthMiddlewareTest, RequireAllRolesMissingOne) {
    _auth_mw->with_auth_required(true).with_roles({"editor", "admin"}, true); // user lacks "admin"
    run(_auth_mw, authed_request("Bearer " + hmac_token(User{"user_all_roles", "allroler", {"editor", "viewer", "commenter"}})));

    EXPECT_EQ(status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Insufficient permissions based on user roles.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, RequireAllRolesMissingAll) {
    _auth_mw->with_auth_required(true).with_roles({"publisher", "auditor"}, true);
    run(_auth_mw, authed_request("Bearer " + hmac_token(User{"user_all_roles", "allroler", {"editor", "viewer", "commenter"}})));

    EXPECT_EQ(status(), qb::http::status::FORBIDDEN);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, RequireAllRolesEmptyListPasses) {
    _auth_mw->with_auth_required(true).with_roles({}, true); // empty required list -> no role gate
    run(_auth_mw, authed_request("Bearer " + hmac_token(User{"user_all_roles", "allroler", {"editor", "viewer", "commenter"}})));

    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
}

// ===========================================================================
// Optional authentication
// ===========================================================================

TEST_F(AuthMiddlewareTest, OptionalAuthNoTokenIsAllowedWithoutUser) {
    auto mw = qb::http::optional_auth_middleware<AuthSession>(_auth_options);
    run(mw, create_request(qb::http::method::GET, "/test"));

    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_EQ(body(), "Access Granted");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_FALSE(_session->_user_in_context.has_value());
}

TEST_F(AuthMiddlewareTest, OptionalAuthValidTokenPopulatesUser) {
    auto mw = qb::http::optional_auth_middleware<AuthSession>(_auth_options);
    run(mw, authed_request("Bearer " + hmac_token(User{"user789", "optional_test", {"viewer"}})));

    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user789");
}

TEST_F(AuthMiddlewareTest, OptionalAuthRejectsProvidedMalformedToken) {
    auto mw = qb::http::optional_auth_middleware<AuthSession>(_auth_options);
    run(mw, authed_request("Bearer this_is_not_a_valid_jwt"));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_FALSE(_session->_user_in_context.has_value());
}

TEST_F(AuthMiddlewareTest, OptionalAuthRejectsProvidedExpiredToken) {
    auto mw = qb::http::optional_auth_middleware<AuthSession>(_auth_options);

    Options expiring = _auth_options;
    expiring.token_expiration(std::chrono::seconds(-3600));
    std::string expired = Manager(expiring).generate_token(User{"user_exp_opt", "expopter", {"user"}});
    run(mw, authed_request("Bearer " + expired));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_FALSE(_session->_user_in_context.has_value());
}

TEST_F(AuthMiddlewareTest, OptionalAuthRejectsProvidedWrongSignatureToken) {
    auto        mw        = qb::http::optional_auth_middleware<AuthSession>(_auth_options);
    std::string wrong_sig = hmac_token(User{"user_sig_opt", "sigopter", {"user"}}, "a_completely_different_secret_key_!@#");
    run(mw, authed_request("Bearer " + wrong_sig));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_FALSE(_session->_user_in_context.has_value());
}

// ===========================================================================
// Time claims: expiry / not-before / clock-skew (frozen-now, no real sleeps)
// ===========================================================================

TEST_F(AuthMiddlewareTest, ExpiredTokenIsRejected) {
    const std::int64_t now = static_cast<std::int64_t>(now_epoch());
    _auth_mw->with_options(_auth_options).with_auth_required(true);

    // exp one hour in the past; default leeway 0.
    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"exp_user", "expired", {"user"}},
                                 /*exp=*/now - 3600, /*nbf=*/now - 7200, /*iat=*/now - 7200);
    run(_auth_mw, authed_request("Bearer " + token));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid or expired token; user authentication failed.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, NotYetValidTokenIsRejected) {
    const std::int64_t now      = static_cast<std::int64_t>(now_epoch());
    Options            nbf_opts = _auth_options;
    nbf_opts.verify_not_before(true);
    _auth_mw->with_options(nbf_opts).with_auth_required(true);

    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_nbf", "nbf_tester", {"user"}},
                                 /*exp=*/now + 7200, /*nbf=*/now + 3600, /*iat=*/now);
    run(_auth_mw, authed_request("Bearer " + token));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, ClockSkewExpWithinTolerance) {
    const std::int64_t now  = static_cast<std::int64_t>(now_epoch());
    Options            skew = _auth_options;
    skew.clock_skew_tolerance(std::chrono::seconds(20));
    _auth_mw->with_options(skew).with_auth_required(true);

    // Expired 10s ago, within 20s tolerance -> accepted.
    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_skew", "skew_tester", {"user"}},
                                 /*exp=*/now - 10, /*nbf=*/now - 7200, /*iat=*/now - 7200);
    run(_auth_mw, authed_request("Bearer " + token));

    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user_skew");
}

TEST_F(AuthMiddlewareTest, ClockSkewExpBeyondTolerance) {
    const std::int64_t now  = static_cast<std::int64_t>(now_epoch());
    Options            skew = _auth_options;
    skew.clock_skew_tolerance(std::chrono::seconds(20));
    _auth_mw->with_options(skew).with_auth_required(true);

    // Expired 60s ago, well beyond 20s tolerance -> rejected (60s margin from boundary).
    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_skew", "skew_tester", {"user"}},
                                 /*exp=*/now - 60, /*nbf=*/now - 7200, /*iat=*/now - 7200);
    run(_auth_mw, authed_request("Bearer " + token));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, ClockSkewNbfWithinTolerance) {
    const std::int64_t now  = static_cast<std::int64_t>(now_epoch());
    Options            skew = _auth_options;
    skew.clock_skew_tolerance(std::chrono::seconds(20));
    skew.verify_not_before(true);
    _auth_mw->with_options(skew).with_auth_required(true);

    // nbf 10s in the future, within 20s tolerance -> accepted.
    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_skew", "skew_tester", {"user"}},
                                 /*exp=*/now + 7200, /*nbf=*/now + 10, /*iat=*/now);
    run(_auth_mw, authed_request("Bearer " + token));

    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, ClockSkewNbfBeyondTolerance) {
    const std::int64_t now  = static_cast<std::int64_t>(now_epoch());
    Options            skew = _auth_options;
    skew.clock_skew_tolerance(std::chrono::seconds(20));
    skew.verify_not_before(true);
    _auth_mw->with_options(skew).with_auth_required(true);

    // nbf 60s in the future, beyond 20s tolerance -> rejected.
    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_skew", "skew_tester", {"user"}},
                                 /*exp=*/now + 7200, /*nbf=*/now + 60, /*iat=*/now);
    run(_auth_mw, authed_request("Bearer " + token));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

// ===========================================================================
// Issuer / audience verification (split from the old 8-scenario megatest)
// ===========================================================================

TEST_F(AuthMiddlewareTest, IssuerCorrectAccepted) {
    const std::int64_t now  = static_cast<std::int64_t>(now_epoch());
    Options            opts = _auth_options;
    opts.token_issuer("my_app");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_iss_aud", "iss_aud_tester", {"user"}}, now + 3600, std::nullopt,
                                 now, /*iss=*/"my_app");
    run(_auth_mw, authed_request("Bearer " + token));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, IssuerIncorrectRejected) {
    const std::int64_t now  = static_cast<std::int64_t>(now_epoch());
    Options            opts = _auth_options;
    opts.token_issuer("my_app");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_iss_aud", "iss_aud_tester", {"user"}}, now + 3600, std::nullopt,
                                 now, /*iss=*/"other_app");
    run(_auth_mw, authed_request("Bearer " + token));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, IssuerMissingRejected) {
    const std::int64_t now  = static_cast<std::int64_t>(now_epoch());
    Options            opts = _auth_options;
    opts.token_issuer("my_app");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token =
        sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_iss_aud", "iss_aud_tester", {"user"}}, now + 3600, std::nullopt, now); // no iss
    run(_auth_mw, authed_request("Bearer " + token));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, IssuerPresentButVerificationOff) {
    const std::int64_t now = static_cast<std::int64_t>(now_epoch());
    // token_issuer("") leaves verify_issuer disabled -> iss claim ignored.
    _auth_mw->with_options(_auth_options).with_auth_required(true);

    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_iss_aud", "iss_aud_tester", {"user"}}, now + 3600, std::nullopt,
                                 now, /*iss=*/"any_app_iss");
    run(_auth_mw, authed_request("Bearer " + token));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, AudienceCorrectAccepted) {
    const std::int64_t now  = static_cast<std::int64_t>(now_epoch());
    Options            opts = _auth_options;
    opts.token_audience("my_client");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_iss_aud", "iss_aud_tester", {"user"}}, now + 3600, std::nullopt,
                                 now, std::nullopt, /*aud=*/"my_client");
    run(_auth_mw, authed_request("Bearer " + token));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, AudienceIncorrectRejected) {
    const std::int64_t now  = static_cast<std::int64_t>(now_epoch());
    Options            opts = _auth_options;
    opts.token_audience("my_client");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_iss_aud", "iss_aud_tester", {"user"}}, now + 3600, std::nullopt,
                                 now, std::nullopt, /*aud=*/"other_client");
    run(_auth_mw, authed_request("Bearer " + token));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, AudienceMissingRejected) {
    const std::int64_t now  = static_cast<std::int64_t>(now_epoch());
    Options            opts = _auth_options;
    opts.token_audience("my_client");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token =
        sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_iss_aud", "iss_aud_tester", {"user"}}, now + 3600, std::nullopt, now); // no aud
    run(_auth_mw, authed_request("Bearer " + token));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, AudiencePresentButVerificationOff) {
    const std::int64_t now = static_cast<std::int64_t>(now_epoch());
    _auth_mw->with_options(_auth_options).with_auth_required(true); // verify_audience off

    std::string token = sign_jwt(qb::jwt::Algorithm::HS256, kSecret, User{"user_iss_aud", "iss_aud_tester", {"user"}}, now + 3600, std::nullopt,
                                 now, std::nullopt, /*aud=*/"any_client_aud");
    run(_auth_mw, authed_request("Bearer " + token));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
}

// ===========================================================================
// Asymmetric algorithms: RSA + ES256 round-trips and algorithm confusion
// ===========================================================================

TEST_F(AuthMiddlewareTest, RsaSha256RoundTrip) {
    Options sign_opts;
    sign_opts.algorithm(Options::Algorithm::RSA_SHA256).private_key(kRsaPrivateKeyPem).secret_key("");
    std::string rsa_token = Manager(sign_opts).generate_token(User{"user_rsa", "rsatester", {"user"}});
    ASSERT_FALSE(rsa_token.empty());

    Options verify_opts;
    verify_opts.algorithm(Options::Algorithm::RSA_SHA256).public_key(kRsaPublicKeyPem).secret_key("");
    _auth_mw->with_options(verify_opts).with_auth_required(true);

    run(_auth_mw, authed_request("Bearer " + rsa_token));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user_rsa");
}

TEST_F(AuthMiddlewareTest, Es256RoundTrip) {
    Options sign_opts;
    sign_opts.algorithm(Options::Algorithm::ECDSA_SHA256).private_key(_ec_private).secret_key("");
    std::string ec_token = Manager(sign_opts).generate_token(User{"user_ec", "ectester", {"user"}});
    ASSERT_FALSE(ec_token.empty());

    Options verify_opts;
    verify_opts.algorithm(Options::Algorithm::ECDSA_SHA256).public_key(_ec_public).secret_key("");
    _auth_mw->with_options(verify_opts).with_auth_required(true);

    run(_auth_mw, authed_request("Bearer " + ec_token));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user_ec");
}

// Algorithm-confusion: an RSA-signed token must NOT validate against an HMAC
// (HS256) verifier configuration. The header alg (RS256) does not match the
// configured HS256, so verification fails closed -> 401.
TEST_F(AuthMiddlewareTest, RsaTokenRejectedByHmacConfig) {
    Options sign_opts;
    sign_opts.algorithm(Options::Algorithm::RSA_SHA256).private_key(kRsaPrivateKeyPem).secret_key("");
    std::string rsa_token = Manager(sign_opts).generate_token(User{"user_rsa", "rsatester", {"user"}});

    _auth_mw->with_options(_auth_options).with_auth_required(true); // fixture default = HMAC HS256
    run(_auth_mw, authed_request("Bearer " + rsa_token));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED) << "RSA token must not validate with HMAC config.";
    EXPECT_FALSE(_session->_final_handler_called);
}

// Algorithm-confusion: an HMAC-signed token must NOT validate against an EC
// (ES256) verifier configuration. A classic attack is presenting an HS256 token
// to a service that expects ES256 (hoping the public key gets used as an HMAC
// secret). The alg mismatch is rejected before any key confusion can occur.
TEST_F(AuthMiddlewareTest, HmacTokenRejectedByEcConfig) {
    std::string hs_token = hmac_token(User{"attacker", "attacker", {"admin"}});

    Options ec_verify;
    ec_verify.algorithm(Options::Algorithm::ECDSA_SHA256).public_key(_ec_public).secret_key("");
    _auth_mw->with_options(ec_verify).with_auth_required(true);

    run(_auth_mw, authed_request("Bearer " + hs_token));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED) << "HS256 token must not validate with ES256 config.";
    EXPECT_FALSE(_session->_final_handler_called);
}

// Algorithm-confusion: an EC-signed token must NOT validate against an HMAC
// verifier configuration either (the mirror of the RSA case for ECDSA).
TEST_F(AuthMiddlewareTest, EcTokenRejectedByHmacConfig) {
    Options sign_opts;
    sign_opts.algorithm(Options::Algorithm::ECDSA_SHA256).private_key(_ec_private).secret_key("");
    std::string ec_token = Manager(sign_opts).generate_token(User{"user_ec", "ectester", {"user"}});

    _auth_mw->with_options(_auth_options).with_auth_required(true); // HMAC HS256
    run(_auth_mw, authed_request("Bearer " + ec_token));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED) << "EC token must not validate with HMAC config.";
    EXPECT_FALSE(_session->_final_handler_called);
}

// ===========================================================================
// Context-key isolation, custom scheme/header, whitespace
// ===========================================================================

TEST_F(AuthMiddlewareTest, CustomUserContextKeyIsolation) {
    const std::string custom_key = "test_custom_user_key";
    _auth_mw->with_user_context_key(custom_key).with_auth_required(true);

    bool found_default = false;
    _router            = std::make_unique<qb::http::Router<AuthSession>>();
    _router->use(_auth_mw);
    _router->get("/test_custom_key", [&](std::shared_ptr<qb::http::Context<AuthSession>> ctx) {
        _session->_final_handler_called = true;
        if (ctx->has(custom_key)) {
            _session->_user_in_context = ctx->template get<User>(custom_key);
        }
        if (ctx->has("user")) {
            found_default = true;
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    std::string token = hmac_token(User{"user_ctx_key_test", "customkeyuser", {"user"}});
    auto        req   = create_request(qb::http::method::GET, "/test_custom_key");
    req.set_header("Authorization", "Bearer " + token);
    _session->reset();
    _router->route(_session, std::move(req));

    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value()) << "User absent at custom key " << custom_key;
    EXPECT_EQ(_session->_user_in_context->id, "user_ctx_key_test");
    EXPECT_FALSE(found_default) << "User unexpectedly present at default key 'user'.";
}

TEST_F(AuthMiddlewareTest, CustomAuthSchemeAccepted) {
    Options opts = _auth_options;
    opts.auth_scheme("MyAppToken");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token = _auth_mw->generate_token(User{"user_scheme", "schemetester", {"user"}});
    run(_auth_mw, authed_request("MyAppToken " + token));

    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user_scheme");
}

TEST_F(AuthMiddlewareTest, CustomAuthSchemeRejectsDefaultScheme) {
    Options opts = _auth_options;
    opts.auth_scheme("MyAppToken");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token = _auth_mw->generate_token(User{"user_scheme", "schemetester", {"user"}});
    run(_auth_mw, authed_request("Bearer " + token)); // wrong scheme

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid authentication format in header.");
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_FALSE(_session->_user_in_context.has_value());
}

TEST_F(AuthMiddlewareTest, CaseInsensitiveAuthHeaderNameExactCase) {
    Options opts = _auth_options;
    opts.auth_header_name("X-MyApp-AuthToken");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token = _auth_mw->generate_token(User{"user_header_case", "headercaser", {"user"}});
    run(_auth_mw, authed_request("Bearer " + token, "X-MyApp-AuthToken"));
    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, CaseInsensitiveAuthHeaderNameLowercase) {
    Options opts = _auth_options;
    opts.auth_header_name("X-MyApp-AuthToken");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token = _auth_mw->generate_token(User{"user_header_case", "headercaser", {"user"}});
    run(_auth_mw, authed_request("Bearer " + token, "x-myapp-authtoken"));
    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, CaseInsensitiveAuthHeaderNameWrongNameRejected) {
    Options opts = _auth_options;
    opts.auth_header_name("X-MyApp-AuthToken");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token = _auth_mw->generate_token(User{"user_header_case", "headercaser", {"user"}});
    run(_auth_mw, authed_request("Bearer " + token, "Authorization")); // wrong header name
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, CaseInsensitiveSchemeLowercase) {
    _auth_mw->with_auth_required(true);
    std::string token = hmac_token(User{"user_scheme_case", "bearercaser", {"user"}});
    run(_auth_mw, authed_request("bearer " + token));
    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user_scheme_case");
}

TEST_F(AuthMiddlewareTest, CaseInsensitiveSchemeMixedCase) {
    _auth_mw->with_auth_required(true);
    std::string token = hmac_token(User{"user_scheme_case", "bearercaser", {"user"}});
    run(_auth_mw, authed_request("BeArEr " + token));
    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, CaseInsensitiveCustomSchemeWrongSchemeRejected) {
    Options opts = _auth_options;
    opts.auth_scheme("MyAppAuth");
    _auth_mw->with_options(opts).with_auth_required(true);

    std::string token = _auth_mw->generate_token(User{"user_custom_scheme_case", "customcaser", {"admin"}});
    run(_auth_mw, authed_request("Bearer " + token)); // default Bearer, but custom expected
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, WhitespaceToleranceExtraSpacesBetweenSchemeAndToken) {
    _auth_mw->with_auth_required(true);
    std::string token = hmac_token(User{"user_ws", "whitespacer", {"user"}});
    run(_auth_mw, authed_request("Bearer   " + token)); // 3 spaces
    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user_ws");
}

TEST_F(AuthMiddlewareTest, WhitespaceToleranceNoSpaceIsRejected) {
    _auth_mw->with_auth_required(true);
    std::string token = hmac_token(User{"user_ws", "whitespacer", {"user"}});
    run(_auth_mw, authed_request("Bearer" + token)); // no space
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

} // namespace

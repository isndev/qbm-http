/**
 * @file qbm/http/tests/unit/middleware/middleware-jwt.cpp
 * @brief Unit tests for qb::http::JwtMiddleware<Session>.
 *
 * Drives the JWT middleware through a real `qb::http::Router<MockMiddlewareSession>`
 * with a capturing mock session — token extraction (header / cookie / query),
 * HS256 signature verification, standard-claim validation (exp/nbf/iat/iss/aud/sub),
 * leeway, custom validators, custom error/success handlers, required claims, and
 * the alg-confusion / "none"-algorithm attack surface.
 *
 * Tier: **unit** with an `ssl` build dependency — HS256 verification goes through
 * `qb/io/crypto_jwt.h` (OpenSSL HMAC). No engine, socket, or event loop is
 * involved; `Router::route` runs synchronously against the mock session.
 *
 * Token construction:
 *   - `make_token(...)` produces a signed HS256 token from a claim map, auto-filling
 *     exp/nbf with comfortable (deterministic, non-boundary) windows.
 *   - `sign_hs256_native(...)` hand-signs a token whose payload is a NATIVE qb::json
 *     value (e.g. an array `aud`), which `qb::jwt::create`'s string-map API cannot
 *     express. This is what lets the array-audience and alg-confusion cases reach
 *     the verifier with a structurally faithful payload.
 *
 * The file shares the canonical `MiddlewareTestFixture` / `MockMiddlewareSession`
 * (shared/middleware_test_fixture.h), extended here with a JWT-aware session that
 * also captures the decoded `jwt_payload` slot.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <qb/io/crypto.h>     // qb::crypto::{hmac, base64url_encode}
#include <qb/io/crypto_jwt.h> // qb::jwt::{create, CreateOptions, Algorithm}
#include <qb/json.h>          // qb::json

#include "../../shared/middleware_test_fixture.h" // MiddlewareTestFixture, MockMiddlewareSession
#include "../http.h"                              // Router, Context, status, method
#include "../middleware/jwt.h"                    // qb::http::JwtMiddleware + factories

namespace {

using qb::http::JwtError;
using qb::http::JwtErrorInfo;
using qb::http::JwtMiddleware;
using qb::http::JwtOptions;
using qb::http::JwtTokenLocation;

constexpr char kSecret[] = "very_secure_secret_for_jwt_tests!@#$%^";

/// Whole-second epoch `now`, captured at call time.
std::int64_t
epoch_now() {
    return static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

/**
 * @brief Sign an HS256 token from a string claim map (the qb::jwt wire form).
 *
 * exp/nbf are auto-filled (unless already present) with a comfortable window
 * around `now` so the happy path is deterministic regardless of CI load:
 *   - exp = now + @p exp_off (default +1h)
 *   - nbf = now + @p nbf_off (default -60s, i.e. already active)
 */
std::string
make_token(std::map<std::string, std::string> claims, const std::string &secret = kSecret, std::int64_t exp_off = 3600,
           std::int64_t nbf_off = -60) {
    if (!claims.count("exp")) {
        claims["exp"] = std::to_string(epoch_now() + exp_off);
    }
    if (!claims.count("nbf")) {
        claims["nbf"] = std::to_string(epoch_now() + nbf_off);
    }
    qb::jwt::CreateOptions opts;
    opts.algorithm = qb::jwt::Algorithm::HS256;
    opts.key       = secret;
    return qb::jwt::create(claims, opts);
}

/**
 * @brief Hand-sign an HS256 token whose payload is a NATIVE qb::json value.
 *
 * Unlike `qb::jwt::create` (which only takes std::map<string,string> and therefore
 * stringifies every non-string claim), this builds the payload segment from the
 * raw JSON so an array `aud`, numeric `exp`, etc. reach the verifier as native
 * types. The signature is a genuine HMAC-SHA256 over `header.payload`, so the
 * resulting token passes real signature verification.
 *
 * @param payload   The exact JSON payload object to encode.
 * @param secret    HMAC signing secret.
 * @param alg_header The literal `alg` value to stamp in the JOSE header (defaults
 *                  to "HS256"; override to forge an alg-confusion / "none" header
 *                  while still HMAC-signing the bytes).
 */
std::string
sign_hs256_native(const qb::json &payload, const std::string &secret = kSecret, const std::string &alg_header = "HS256") {
    const auto b64url = [](const std::string &s) {
        return qb::crypto::base64url_encode(std::vector<unsigned char>(s.begin(), s.end()));
    };
    qb::json          header        = {{"alg", alg_header}, {"typ", "JWT"}};
    const std::string header_b64    = b64url(header.dump());
    const std::string payload_b64   = b64url(payload.dump());
    const std::string signing_input = header_b64 + "." + payload_b64;

    const std::vector<unsigned char> data(signing_input.begin(), signing_input.end());
    const std::vector<unsigned char> key(secret.begin(), secret.end());
    const auto                       sig     = qb::crypto::hmac(data, key, qb::crypto::DigestAlgorithm::SHA256);
    const std::string                sig_b64 = qb::crypto::base64url_encode(sig);

    return signing_input + "." + sig_b64;
}

/// JWT-aware capturing session: also records the decoded `jwt_payload` slot.
struct MockJwtSession : qb::http::test::MockMiddlewareSession {
    std::optional<qb::json> _jwt_payload_in_context;

    void
    reset() {
        qb::http::test::MockMiddlewareSession::reset();
        _jwt_payload_in_context.reset();
    }
};

/// Fixture: owns a default HS256 JwtMiddleware and a payload-capturing handler.
class JwtMiddlewareTest : public qb::http::test::MiddlewareTestFixture<MockJwtSession> {
protected:
    JwtOptions                                     _jwt_options;
    std::shared_ptr<JwtMiddleware<MockJwtSession>> _jwt_mw;
    const std::string                              _scheme = "Bearer";
    const std::string                              _hdr    = "Authorization";

    void
    SetUp() override {
        qb::http::test::MiddlewareTestFixture<MockJwtSession>::SetUp();
        _jwt_options.secret     = kSecret;
        _jwt_options.algorithm  = "HS256";
        _jwt_options.verify_exp = true;
        _jwt_options.verify_nbf = true;
        _jwt_options.verify_iat = false;
        _jwt_mw                 = qb::http::jwt_middleware_with_options<MockJwtSession>(_jwt_options);
    }

    /// Terminal handler that captures the jwt_payload slot and replies 200.
    qb::http::RouteHandlerFn<MockJwtSession>
    payload_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockJwtSession>> ctx) {
            _session->_final_handler_called = true;
            if (ctx->has("jwt_payload")) {
                _session->_jwt_payload_in_context = ctx->template get<qb::json>("jwt_payload");
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Authenticated Access Granted";
            ctx->complete();
        };
    }

    /// Wire the given JWT middleware ahead of payload_handler and route one request.
    void
    run(std::shared_ptr<JwtMiddleware<MockJwtSession>> mw, qb::http::Request request, const std::string &path = "/protected") {
        _router = std::make_unique<qb::http::Router<MockJwtSession>>();
        _router->use(std::move(mw));
        _router->get(path, payload_handler());
        _router->compile();
        _session->reset();
        _router->route(_session, std::move(request));
    }

    qb::http::Request
    req_with_header(const std::string &value) {
        auto r = create_request(qb::http::method::GET, "/protected");
        r.set_header(_hdr, value);
        return r;
    }

    qb::http::Request
    bearer(const std::string &token) {
        return req_with_header(_scheme + " " + token);
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

// ---------------------------------------------------------------------------
// Happy path + extraction locations
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, ValidTokenAuthentication) {
    const std::string token = make_token({{"sub", "user123"}, {"name", "Test User"}});
    run(_jwt_mw, bearer(token));

    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    EXPECT_EQ(_session->_jwt_payload_in_context->at("sub").get<std::string>(), "user123");
}

TEST_F(JwtMiddlewareTest, TokenFromCookie) {
    _jwt_options.token_location = JwtTokenLocation::COOKIE;
    _jwt_options.token_name     = "my_jwt_cookie";
    _jwt_mw->with_options(_jwt_options);

    const std::string token = make_token({{"sub", "cookie_user"}});
    auto              req   = create_request(qb::http::method::GET, "/protected");
    req.cookies().add("my_jwt_cookie", token);
    run(_jwt_mw, std::move(req));

    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    EXPECT_EQ(_session->_jwt_payload_in_context->at("sub").get<std::string>(), "cookie_user");
}

TEST_F(JwtMiddlewareTest, TokenFromQuery) {
    _jwt_options.token_location = JwtTokenLocation::QUERY;
    _jwt_options.token_name     = "access_token";
    _jwt_mw->with_options(_jwt_options);

    const std::string token = make_token({{"sub", "query_user"}});
    auto              req   = create_request(qb::http::method::GET, "/protected", "access_token=" + token);
    run(_jwt_mw, std::move(req));

    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    EXPECT_EQ(_session->_jwt_payload_in_context->at("sub").get<std::string>(), "query_user");
}

// ---------------------------------------------------------------------------
// Missing / malformed token (exact error messages, no OR-tolerance)
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, MissingToken) {
    run(_jwt_mw, create_request(qb::http::method::GET, "/protected"));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "JWT token is missing.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, WhitespaceOnlyAuthorizationHeaderIsMissingToken) {
    EXPECT_NO_THROW(run(_jwt_mw, req_with_header("    \t   ")));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "JWT token is missing.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, InvalidTokenFormat) {
    run(_jwt_mw, bearer("not.a.valid.jwt.token"));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid token format.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, TokenWithNoSchemeWhenSchemeExpected) {
    run(_jwt_mw, req_with_header(make_token({{"sub", "no_scheme_user"}})));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "JWT token is missing.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, TokenWithWrongSchemeWhenSchemeExpected) {
    run(_jwt_mw, req_with_header("Basic " + make_token({{"sub", "wrong_scheme_user"}})));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "JWT token is missing.");
    EXPECT_FALSE(_session->_final_handler_called);
}

// ---------------------------------------------------------------------------
// Crypto integrity (wrong secret, tampering)
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, WrongSecret) {
    run(_jwt_mw, bearer(make_token({{"sub", "secret_user"}}, "another_secret_entirely")));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED) << "Body: " << body();
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid token signature.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, TokenTampering) {
    std::string token = make_token({{"sub", "tamper_user"}});
    const auto  d2    = token.rfind('.');
    ASSERT_NE(d2, std::string::npos);
    ASSERT_LT(d2 + 1, token.size());
    // Flip a byte inside the SIGNATURE segment: header/payload still decode and
    // parse cleanly, so the verifier deterministically reaches the signature
    // check and reports a signature failure (never a format error).
    token[d2 + 1] = (token[d2 + 1] == 'A' ? 'B' : 'A');

    run(_jwt_mw, bearer(token));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid token signature.") << "Body: " << body();
    EXPECT_FALSE(_session->_final_handler_called);
}

// ---------------------------------------------------------------------------
// Algorithm confusion / "none" attack (security-relevant)
// ---------------------------------------------------------------------------

// A token whose JOSE header claims alg "none" (unsigned-JWT attack) must be
// rejected: qb::jwt resolves the header alg, finds it does not match the
// configured HS256, and fails as a signature error -> 401. The handler never runs.
TEST_F(JwtMiddlewareTest, AlgNoneHeaderIsRejected) {
    qb::json payload = {{"sub", "attacker"}, {"exp", epoch_now() + 3600}, {"nbf", epoch_now() - 60}};
    // alg "none" header, but we still place a (now-irrelevant) HMAC sig segment.
    const std::string token = sign_hs256_native(payload, kSecret, "none");

    run(_jwt_mw, bearer(token));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid token signature.") << "Body: " << body();
    EXPECT_FALSE(_session->_final_handler_called);
}

// Header alg differs from the configured algorithm (e.g. token says HS512 while
// the middleware verifies HS256). The header/option mismatch is caught before any
// signature math and rejected as a signature error.
TEST_F(JwtMiddlewareTest, MismatchedHeaderAlgorithmIsRejected) {
    qb::json          payload = {{"sub", "confused"}, {"exp", epoch_now() + 3600}, {"nbf", epoch_now() - 60}};
    const std::string token   = sign_hs256_native(payload, kSecret, "HS512"); // header lies about alg

    run(_jwt_mw, bearer(token));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid token signature.") << "Body: " << body();
    EXPECT_FALSE(_session->_final_handler_called);
}

// Configuring the middleware itself with an unsupported algorithm string is a
// distinct, deterministic failure: algorithm_from_string returns nullopt and the
// middleware reports an algorithm-mismatch error before touching the token bytes.
TEST_F(JwtMiddlewareTest, UnsupportedConfiguredAlgorithmIsRejected) {
    _jwt_options.algorithm = "none";
    _jwt_mw->with_options(_jwt_options);

    run(_jwt_mw, bearer(make_token({{"sub", "x"}})));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(body().find("is not supported"), std::string::npos) << "Body: " << body();
    EXPECT_FALSE(_session->_final_handler_called);
}

// ---------------------------------------------------------------------------
// Time claims: exp / nbf / iat + leeway edge
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, ExpiredToken) {
    run(_jwt_mw, bearer(make_token({{"sub", "exp_user"}}, kSecret, /*exp_off=*/-3600)));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Token has expired.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, TokenNotYetValid) {
    // nbf one hour in the future, no leeway.
    run(_jwt_mw, bearer(make_token({{"sub", "nbf_user"}}, kSecret, /*exp_off=*/3600, /*nbf_off=*/3600)));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Token is not yet active.");
    EXPECT_FALSE(_session->_final_handler_called);
}

// Leeway edge: with leeway==0, a token whose exp is a few seconds in the PAST is
// rejected, and one a few seconds in the FUTURE is accepted. The +/-5s margins
// are far enough from the boundary to be load-immune while still exercising the
// zero-leeway exp comparison directly.
TEST_F(JwtMiddlewareTest, ZeroLeewayExpBoundary) {
    _jwt_options.leeway = std::chrono::seconds(0);
    _jwt_mw->with_options(_jwt_options);

    run(_jwt_mw, bearer(make_token({{"sub", "edge"}}, kSecret, /*exp_off=*/-5)));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED) << "Body: " << body();
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Token has expired.");

    run(_jwt_mw, bearer(make_token({{"sub", "edge"}}, kSecret, /*exp_off=*/5)));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, ClockSkewTolerance) {
    _jwt_options.leeway = std::chrono::seconds(60);
    _jwt_mw->with_options(_jwt_options);

    // exp 30s in the past -> within 60s leeway -> accepted.
    run(_jwt_mw, bearer(make_token({{"sub", "skew"}}, kSecret, /*exp_off=*/-30)));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);

    // exp 90s in the past -> beyond leeway -> rejected.
    run(_jwt_mw, bearer(make_token({{"sub", "skew"}}, kSecret, /*exp_off=*/-90)));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Token has expired.");

    // nbf 30s in the future -> within leeway -> accepted.
    run(_jwt_mw, bearer(make_token({{"sub", "skew"}}, kSecret, /*exp_off=*/3600, /*nbf_off=*/30)));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);

    // nbf 90s in the future -> beyond leeway -> rejected.
    run(_jwt_mw, bearer(make_token({{"sub", "skew"}}, kSecret, /*exp_off=*/3600, /*nbf_off=*/90)));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Token is not yet active.");
}

TEST_F(JwtMiddlewareTest, VerifyIatRejectsFutureIssuedAtClaim) {
    _jwt_options.verify_iat = true;
    _jwt_mw->with_options(_jwt_options);

    const std::string token = make_token({{"sub", "future_iat_user"}, {"iat", std::to_string(epoch_now() + 3600)}});
    run(_jwt_mw, bearer(token));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Token issued in the future (invalid 'iat').");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, VerifyIatCanBeDisabled) {
    _jwt_options.verify_iat = false;
    _jwt_mw->with_options(_jwt_options);

    const std::string token = make_token({{"sub", "future_iat_ignored"}, {"iat", std::to_string(epoch_now() + 3600)}});
    run(_jwt_mw, bearer(token));
    EXPECT_EQ(status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
}

// ---------------------------------------------------------------------------
// iss / aud / sub verification (correct / wrong / missing)
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, IssuerVerification) {
    _jwt_options.verify_iss = true;
    _jwt_options.issuer     = "my-app-issuer";
    _jwt_mw->with_options(_jwt_options);

    run(_jwt_mw, bearer(make_token({{"sub", "u"}, {"iss", "my-app-issuer"}})));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);

    run(_jwt_mw, bearer(make_token({{"sub", "u"}, {"iss", "wrong-issuer"}})));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid issuer.");

    run(_jwt_mw, bearer(make_token({{"sub", "u"}}))); // iss claim absent
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid issuer.");
}

TEST_F(JwtMiddlewareTest, AudienceValidationStringClaim) {
    _jwt_options.verify_aud = true;
    _jwt_options.audience   = "my-app-audience";
    _jwt_mw->with_options(_jwt_options);

    run(_jwt_mw, bearer(make_token({{"sub", "u"}, {"aud", "my-app-audience"}})));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);

    run(_jwt_mw, bearer(make_token({{"sub", "u"}, {"aud", "wrong-audience"}})));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid audience.");

    run(_jwt_mw, bearer(make_token({{"sub", "u"}}))); // aud claim absent
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid audience.");
}

// ADDED (spec): the `aud` claim as a JSON ARRAY. RFC 7519 permits aud to be an
// array; qb::jwt matches if any element equals the expected audience. The string
// claim-map API can't produce a native array, so the token is hand-signed with a
// native-JSON payload. A matching element passes; a disjoint array is rejected.
TEST_F(JwtMiddlewareTest, AudienceValidationArrayClaim) {
    _jwt_options.verify_aud = true;
    _jwt_options.audience   = "svc-b";
    _jwt_mw->with_options(_jwt_options);

    qb::json match = {
        {"sub", "u"}, {"exp", epoch_now() + 3600}, {"nbf", epoch_now() - 60}, {"aud", qb::json::array({"svc-a", "svc-b", "svc-c"})}
    };
    run(_jwt_mw, bearer(sign_hs256_native(match)));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);

    qb::json no_match = {{"sub", "u"}, {"exp", epoch_now() + 3600}, {"nbf", epoch_now() - 60}, {"aud", qb::json::array({"svc-x", "svc-y"})}};
    run(_jwt_mw, bearer(sign_hs256_native(no_match)));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid audience.");
}

TEST_F(JwtMiddlewareTest, SubjectVerification) {
    _jwt_options.verify_sub = true;
    _jwt_options.subject    = "expected-subject";
    _jwt_mw->with_options(_jwt_options);

    run(_jwt_mw, bearer(make_token({{"sub", "expected-subject"}})));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);

    run(_jwt_mw, bearer(make_token({{"sub", "wrong-subject"}})));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid subject.");

    run(_jwt_mw, bearer(make_token({{"name", "no-sub-claim"}}))); // sub claim absent
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Invalid subject.");
}

// ---------------------------------------------------------------------------
// Required claims + custom validator
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, RequiredClaimMissing) {
    _jwt_mw->require_claims({"user_id", "scope"});
    run(_jwt_mw, bearer(make_token({{"sub", "user123"}, {"user_id", "some_id"}})));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Required claim 'scope' is missing.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, CustomValidatorAcceptsAndRejects) {
    _jwt_mw->with_validator([](const qb::json &payload, JwtErrorInfo &error_info) {
        if (!payload.contains("custom_claim")) {
            error_info = {JwtError::INVALID_CLAIM, "Custom claim 'custom_claim' is missing."};
            return false;
        }
        if (payload.at("custom_claim").get<std::string>() != "valid") {
            error_info = {JwtError::INVALID_CLAIM, "Custom claim 'custom_claim' has invalid value."};
            return false;
        }
        return true;
    });

    run(_jwt_mw, bearer(make_token({{"sub", "v"}, {"custom_claim", "valid"}})));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);

    run(_jwt_mw, bearer(make_token({{"sub", "v"}, {"custom_claim", "invalid"}})));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Custom claim 'custom_claim' has invalid value.");
    EXPECT_FALSE(_session->_final_handler_called);

    run(_jwt_mw, bearer(make_token({{"sub", "v"}})));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "Custom claim 'custom_claim' is missing.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, ThrowingValidatorIsConvertedToUnauthorized) {
    _jwt_mw->with_validator([](const qb::json &, JwtErrorInfo &) -> bool { throw std::runtime_error("validator crash"); });

    EXPECT_NO_THROW(run(_jwt_mw, bearer(make_token({{"sub", "vt"}}))));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(body().find("Custom JWT validator threw exception"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

// ---------------------------------------------------------------------------
// Custom error / success handlers
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, CustomErrorHandler) {
    bool called = false;
    _jwt_mw->with_error_handler([&called](std::shared_ptr<qb::http::Context<MockJwtSession>> ctx, const JwtErrorInfo &err) {
        called                   = true;
        ctx->response().status() = qb::http::status::IM_A_TEAPOT;
        ctx->response().body()   = "Custom JWT Error: " + err.message;
        ctx->complete();
    });

    run(_jwt_mw, create_request(qb::http::method::GET, "/protected"));
    EXPECT_TRUE(called);
    EXPECT_EQ(status(), qb::http::status::IM_A_TEAPOT);
    EXPECT_EQ(body(), "Custom JWT Error: JWT token is missing.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, ThrowingErrorHandlerFallsBackToDefaultUnauthorized) {
    _jwt_mw->with_error_handler(
        [](std::shared_ptr<qb::http::Context<MockJwtSession>>, const JwtErrorInfo &) { throw std::runtime_error("error handler crash"); });

    EXPECT_NO_THROW(run(_jwt_mw, create_request(qb::http::method::GET, "/protected")));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "JWT token is missing.");
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, SuccessHandlerCanAccessPayload) {
    bool success_ran = false;
    _jwt_mw->with_success_handler([&success_ran](std::shared_ptr<qb::http::Context<MockJwtSession>> ctx, const qb::json &payload) {
        success_ran = true;
        EXPECT_EQ(payload.at("sub").get<std::string>(), "payload_access_user");
        EXPECT_EQ(payload.at("data").get<std::string>(), "secret_info");
        ctx->response().set_header("X-Success", "1");
    });

    run(_jwt_mw, bearer(make_token({{"sub", "payload_access_user"}, {"data", "secret_info"}})));
    EXPECT_TRUE(success_ran);
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.header(std::string("X-Success")), "1");
}

TEST_F(JwtMiddlewareTest, ThrowingSuccessHandlerReturnsInternalServerError) {
    _jwt_mw->with_success_handler(
        [](std::shared_ptr<qb::http::Context<MockJwtSession>>, const qb::json &) { throw std::runtime_error("success handler crash"); });

    EXPECT_NO_THROW(run(_jwt_mw, bearer(make_token({{"sub", "st"}}))));
    EXPECT_EQ(status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_NE(body().find("Error in JWT success handler"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

// ---------------------------------------------------------------------------
// Factories + scheme/whitespace parsing
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, FactoryFunctionsWorkAsExpected) {
    auto mw1 = qb::http::jwt_middleware<MockJwtSession>(kSecret, "HS256");
    run(mw1, bearer(make_token({{"sub", "factory_user1"}})));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    EXPECT_EQ(_session->_jwt_payload_in_context->at("sub").get<std::string>(), "factory_user1");

    run(mw1, create_request(qb::http::method::GET, "/protected"));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "JWT token is missing.");

    JwtOptions cookie_opts;
    cookie_opts.secret         = "another_factory_secret";
    cookie_opts.algorithm      = "HS256";
    cookie_opts.token_location = JwtTokenLocation::COOKIE;
    cookie_opts.token_name     = "factory_cookie_token";
    cookie_opts.auth_scheme    = "";
    auto mw2                   = qb::http::jwt_middleware_with_options<MockJwtSession>(cookie_opts);

    auto req = create_request(qb::http::method::GET, "/protected");
    req.cookies().add("factory_cookie_token", make_token({{"sub", "factory_user2"}}, "another_factory_secret"));
    run(mw2, std::move(req));
    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    EXPECT_EQ(_session->_jwt_payload_in_context->at("sub").get<std::string>(), "factory_user2");
}

TEST_F(JwtMiddlewareTest, CaseInsensitiveAuthSchemeInHeader) {
    const std::string token = make_token({{"sub", "case_scheme_user"}});

    run(_jwt_mw, req_with_header("bearer " + token));
    EXPECT_EQ(status(), qb::http::status::OK) << "Lowercase scheme. Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);

    run(_jwt_mw, req_with_header("BeArEr " + token));
    EXPECT_EQ(status(), qb::http::status::OK) << "Mixed case scheme. Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, WhitespaceToleranceInAuthHeader) {
    const std::string token = make_token({{"sub", "whitespace_user"}});

    run(_jwt_mw, req_with_header(_scheme + "   " + token));
    EXPECT_EQ(status(), qb::http::status::OK) << "Extra spaces after scheme. Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);

    run(_jwt_mw, req_with_header("  " + _scheme + " " + token));
    EXPECT_EQ(status(), qb::http::status::OK) << "Leading spaces before scheme. Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);

    // No space between scheme and token -> not a valid Bearer token.
    run(_jwt_mw, req_with_header(_scheme + token));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED) << "No space. Body: " << body();
    EXPECT_EQ(qb::json::parse(body()).at("error").get<std::string>(), "JWT token is missing.");
    EXPECT_FALSE(_session->_final_handler_called);
}

// ---------------------------------------------------------------------------
// Empty auth_scheme on a HEADER token: the raw header value IS the token.
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, EmptyAuthSchemeHeaderUsesRawHeaderValueAsToken) {
    JwtOptions opts;
    opts.secret         = kSecret;
    opts.algorithm      = "HS256";
    opts.token_location = JwtTokenLocation::HEADER;
    opts.token_name     = "X-Token";
    opts.auth_scheme    = ""; // no scheme → whole (trimmed) header value is the token
    auto mw             = qb::http::jwt_middleware_with_options<MockJwtSession>(opts);

    auto req = create_request(qb::http::method::GET, "/protected");
    req.set_header("X-Token", "  " + make_token({{"sub", "raw_header_user"}}) + "  "); // surrounding WS trimmed
    run(mw, std::move(req));

    EXPECT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, EmptyAuthSchemeHeaderWhitespaceOnlyIsMissingToken) {
    JwtOptions opts;
    opts.secret         = kSecret;
    opts.algorithm      = "HS256";
    opts.token_location = JwtTokenLocation::HEADER;
    opts.token_name     = "X-Token";
    opts.auth_scheme    = "";
    auto mw             = qb::http::jwt_middleware_with_options<MockJwtSession>(opts);

    auto req = create_request(qb::http::method::GET, "/protected");
    req.set_header("X-Token", "    "); // all whitespace → first_non_ws == npos
    run(mw, std::move(req));

    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, BearerSchemeWithOnlyWhitespaceAfterIsMissingToken) {
    // Scheme present + only whitespace after it → token_sv first_non_ws == npos.
    run(_jwt_mw, req_with_header(_scheme + "    "));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

// ---------------------------------------------------------------------------
// Non-std (non-exception) throw from a custom validator → 401, not crash.
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, NonStdThrowingValidatorIsConvertedToUnauthorized) {
    _jwt_mw->with_validator([](const qb::json &, JwtErrorInfo &) -> bool { throw 1234; });

    EXPECT_NO_THROW(run(_jwt_mw, bearer(make_token({{"sub", "x"}}))));
    EXPECT_EQ(status(), qb::http::status::UNAUTHORIZED);
    EXPECT_FALSE(_session->_final_handler_called);
}

// ---------------------------------------------------------------------------
// Claim value coercion: "true"/"false" -> bool, decimal -> double.
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, BooleanAndDecimalClaimsAreCoercedToNativeJsonTypes) {
    // qb::jwt stringifies claims; the middleware re-coerces "true"/"false" back
    // to JSON booleans and JSON-number-shaped decimals back to doubles.
    const std::string token = make_token({{"sub", "coerce"}, {"is_admin", "true"}, {"is_guest", "false"}, {"ratio", "3.14"}});
    run(_jwt_mw, bearer(token));

    ASSERT_EQ(status(), qb::http::status::OK) << "Body: " << body();
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    const auto &payload = *_session->_jwt_payload_in_context;
    ASSERT_TRUE(payload.at("is_admin").is_boolean());
    EXPECT_TRUE(payload.at("is_admin").get<bool>());
    ASSERT_TRUE(payload.at("is_guest").is_boolean());
    EXPECT_FALSE(payload.at("is_guest").get<bool>());
    ASSERT_TRUE(payload.at("ratio").is_number_float());
    EXPECT_DOUBLE_EQ(payload.at("ratio").get<double>(), 3.14);
}

// ---------------------------------------------------------------------------
// cancel() is a no-op on this synchronous middleware.
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, CancelIsNoop) {
    EXPECT_NO_THROW(_jwt_mw->cancel());
}

// ---------------------------------------------------------------------------
// Error handler that sets a response but does NOT complete → middleware
// completes the context for it (the handle_error fallback completion).
// ---------------------------------------------------------------------------

TEST_F(JwtMiddlewareTest, ErrorHandlerThatDoesNotCompleteIsCompletedByMiddleware) {
    _jwt_mw->with_error_handler([](std::shared_ptr<qb::http::Context<MockJwtSession>> ctx, const JwtErrorInfo &) {
        ctx->response().status() = qb::http::status::FORBIDDEN;
        ctx->response().body()   = "denied (no explicit complete)";
        // Intentionally NOT calling ctx->complete() — middleware must finalise.
    });

    run(_jwt_mw, create_request(qb::http::method::GET, "/protected"));
    EXPECT_EQ(status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(body(), "denied (no explicit complete)");
    EXPECT_FALSE(_session->_final_handler_called);
}

} // namespace

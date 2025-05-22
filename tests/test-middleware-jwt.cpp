#include <gtest/gtest.h>
#include "../http.h"
// Explicitly include core http types that the linter might be missing
#include "../request.h"
#include "../response.h"
#include "../routing/router.h"
#include "../routing/context.h"
#include "../routing/types.h" // For RouteHandlerFn and other routing types

#include "../middleware/jwt.h" // The adapted JwtMiddleware
#include "../auth.h"      // For qb::http::auth::User, qb::http::auth::Options (used by JwtOptions indirectly)
#include <qb/io/crypto_jwt.h>  // For generating test tokens if needed, or use AuthManager
#include <qb/json.h>           // Added for qb::json

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sstream> // For ostringstream in session mock

// --- Mock Session for JwtMiddleware Tests ---
struct MockJwtSession {
    qb::http::Response _response;
    std::string _session_id_str = "jwt_test_session";
    std::optional<qb::json> _jwt_payload_in_context; // To check what middleware stores
    bool _final_handler_called = false;
    std::string _trace; // Minimal trace if needed

    qb::http::Response &get_response_ref() { return _response; }

    MockJwtSession &operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _jwt_payload_in_context.reset();
        _final_handler_called = false;
        _trace.clear();
    }

    void trace(const std::string &point) {
        if (!_trace.empty()) _trace += ";";
        _trace += point;
    }
};

// --- Test Fixture for JwtMiddleware --- 
class JwtMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockJwtSession> _session;
    std::unique_ptr<qb::http::Router<MockJwtSession> > _router;
    qb::http::JwtOptions _jwt_options; // Use the struct from jwt.h
    std::shared_ptr<qb::http::JwtMiddleware<MockJwtSession> > _jwt_mw;

    const std::string _test_secret = "very_secure_secret_for_jwt_tests!@#$%^";
    const std::string _test_algorithm = "HS256";

    void SetUp() override {
        _session = std::make_shared<MockJwtSession>();
        _router = std::make_unique<qb::http::Router<MockJwtSession> >();

        _jwt_options.secret = _test_secret;
        _jwt_options.algorithm = _test_algorithm;
        _jwt_options.token_location = qb::http::JwtTokenLocation::HEADER;
        _jwt_options.token_name = "Authorization";
        _jwt_options.auth_scheme = "Bearer";
        _jwt_options.verify_exp = true;
        _jwt_options.verify_nbf = true;
        _jwt_options.verify_iat = false;

        _jwt_mw = qb::http::jwt_middleware_with_options<MockJwtSession>(_jwt_options);
    }

    qb::http::Request create_request(const std::string &target_path = "/protected") {
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "URI parse failure: " << target_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        return req;
    }

    qb::http::RouteHandlerFn<MockJwtSession> success_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockJwtSession> > ctx) {
            if (_session) {
                _session->_final_handler_called = true;
                if (ctx->has("jwt_payload")) {
                    _session->_jwt_payload_in_context = ctx->template get<qb::json>("jwt_payload");
                }
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Authenticated Access Granted";
            ctx->complete();
        };
    }

    void configure_router_and_run(std::shared_ptr<qb::http::JwtMiddleware<MockJwtSession> > jwt_mw_to_use,
                                  qb::http::Request request) {
        _router = std::make_unique<qb::http::Router<MockJwtSession> >(); // Re-initialize router for a clean state
        _router->use(jwt_mw_to_use);
        _router->get("/protected", success_handler());
        _router->get("/optional_route", success_handler()); // For optional auth tests
        _router->compile();

        _session->reset();
        _router->route(_session, std::move(request));
    }

    // Helper to generate a token using qb::jwt::create
    std::string generate_token(const qb::json &payload_json,
                               const std::string &secret_override = "",
                               std::chrono::seconds expiry_offset = std::chrono::hours(1),
                               std::optional<std::chrono::seconds> nbf_offset_from_now = std::nullopt) {
        qb::jwt::CreateOptions jwt_create_options;
        auto alg = qb::jwt::algorithm_from_string(_test_algorithm);
        if (!alg) throw std::runtime_error("Invalid algorithm for token generation in test: " + _test_algorithm);
        jwt_create_options.algorithm = *alg;
        jwt_create_options.key = secret_override.empty() ? _test_secret : secret_override;

        std::map<std::string, std::string> full_payload_map;

        // Convert input qb::json payload to string map
        if (payload_json.is_object()) {
            for (auto &[key, value]: payload_json.items()) {
                if (value.is_string()) {
                    full_payload_map[key] = value.get<std::string>();
                } else if (value.is_boolean()) {
                    full_payload_map[key] = value.get<bool>() ? "true" : "false";
                } else if (value.is_number_integer()) {
                    full_payload_map[key] = std::to_string(value.get<long long>());
                } else if (value.is_number_float()) {
                    full_payload_map[key] = std::to_string(value.get<double>());
                } else {
                    // For arrays or nested objects, serialize to string or skip
                    // For simplicity here, we'll use dump(), but this might not be ideal for all JWT claims.
                    full_payload_map[key] = value.dump();
                }
            }
        }

        // Add/override standard claims based on _jwt_options and test parameters
        // Priority: 1. Explicitly in payload_json, 2. From _jwt_options if verify_X and X is set, 3. Default logic (exp, nbf, iat)

        // Expiry (exp)
        if (!full_payload_map.count("exp") && _jwt_options.verify_exp) {
            full_payload_map["exp"] = std::to_string(
                std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + expiry_offset));
        }

        // Not Before (nbf)
        if (!full_payload_map.count("nbf") && _jwt_options.verify_nbf) {
            if (nbf_offset_from_now.has_value()) {
                full_payload_map["nbf"] = std::to_string(
                    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + *nbf_offset_from_now));
            } else {
                full_payload_map["nbf"] = std::to_string(
                    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() - std::chrono::minutes(1)));
            }
        }

        // Issued At (iat)
        if (!full_payload_map.count("iat")) {
            // If not in input payload_json
            if (_jwt_options.verify_iat) {
                // Only add if verify_iat is true
                full_payload_map["iat"] = std::to_string(
                    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
            }
        } // If payload_json already contains 'iat', its stringified version is already in full_payload_map

        // Issuer (iss)
        if (!full_payload_map.count("iss")) {
            // If not in input payload_json
            if (_jwt_options.verify_iss && !_jwt_options.issuer.empty()) {
                full_payload_map["iss"] = _jwt_options.issuer;
            }
        } // If payload_json already contains 'iss', its stringified version is already in full_payload_map

        // Audience (aud)
        if (!full_payload_map.count("aud")) {
            // If not in input payload_json
            if (_jwt_options.verify_aud && !_jwt_options.audience.empty()) {
                full_payload_map["aud"] = _jwt_options.audience;
            }
        }

        // Subject (sub)
        if (!full_payload_map.count("sub")) {
            // If not in input payload_json
            if (_jwt_options.verify_sub && !_jwt_options.subject.empty()) {
                full_payload_map["sub"] = _jwt_options.subject;
            }
        }

        return qb::jwt::create(full_payload_map, jwt_create_options);
    }
};

// --- Test Cases ---

TEST_F(JwtMiddlewareTest, ValidTokenAuthentication) {
    qb::json payload = {{"sub", "user123"}, {"name", "Test User"}, {"admin", true}};
    std::string token = generate_token(payload);

    auto req = create_request();
    req.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token);
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK)
        << "Response body: " << _session->_response.body().as<std::string>();
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    EXPECT_EQ(_session->_jwt_payload_in_context->at("sub").get<std::string>(), "user123");
}

TEST_F(JwtMiddlewareTest, MissingToken) {
    configure_router_and_run(_jwt_mw, create_request());

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().as<std::string>().find("JWT token is missing"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, InvalidTokenFormat) {
    auto req = create_request();
    req.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " not.a.valid.jwt.token");
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().as<std::string>().find("Invalid token format"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, ExpiredToken) {
    qb::json payload = {{"sub", "exp_user"}};
    std::string expired_token = generate_token(payload, "", std::chrono::seconds(-3600));

    auto req = create_request();
    req.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + expired_token);
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().as<std::string>().find("Token has expired"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, TokenNotYetValid) {
    _jwt_options.verify_nbf = true;
    _jwt_mw->with_options(_jwt_options);

    qb::json payload_json = {{"sub", "nbf_user"}};
    std::string nbf_token = generate_token(payload_json, "", std::chrono::hours(1), std::chrono::hours(1));

    auto req = create_request();
    req.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + nbf_token);
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().as<std::string>().find("Token is not yet active"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, RequiredClaimMissing) {
    _jwt_mw->require_claims({"user_id", "scope"});

    qb::json payload = {{"sub", "user123"}, {"user_id", "some_id"}};
    std::string token_missing_claim = generate_token(payload);

    auto req = create_request();
    req.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_missing_claim);
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().as<std::string>().find("Required claim 'scope' is missing"),
              std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, TokenFromCookie) {
    _jwt_options.token_location = qb::http::JwtTokenLocation::COOKIE;
    _jwt_options.token_name = "my_jwt_cookie";
    _jwt_mw->with_options(_jwt_options);

    qb::json payload = {{"sub", "cookie_user"}};
    std::string token = generate_token(payload);

    auto req = create_request();
    req.cookies().add(_jwt_options.token_name, token);
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    EXPECT_EQ(_session->_jwt_payload_in_context->at("sub").get<std::string>(), "cookie_user");
}

TEST_F(JwtMiddlewareTest, TokenFromQuery) {
    _jwt_options.token_location = qb::http::JwtTokenLocation::QUERY;
    _jwt_options.token_name = "access_token";
    _jwt_mw->with_options(_jwt_options);

    qb::json payload = {{"sub", "query_user"}};
    std::string token = generate_token(payload);

    auto req = create_request("/protected?access_token=" + token);
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    EXPECT_EQ(_session->_jwt_payload_in_context->at("sub").get<std::string>(), "query_user");
}

TEST_F(JwtMiddlewareTest, WrongAlgorithm) {
    qb::json payload = {{"sub", "algo_user"}};
    std::string token_wrong_key_implies_sig_fail =
            generate_token(payload, "a_completely_different_secret_for_alg_test");

    auto req = create_request();
    req.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_wrong_key_implies_sig_fail);
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED)
        << "Response body for WrongAlgorithm: " << _session->_response.body().as<std::string>();
    EXPECT_NE(_session->_response.body().as<std::string>().find("Invalid token signature."), std::string::npos)
        << "Response body for WrongAlgorithm: " << _session->_response.body().as<std::string>();
    EXPECT_FALSE(_session->_final_handler_called);
}


TEST_F(JwtMiddlewareTest, CustomValidator) {
    _jwt_mw->with_validator([](const qb::json &payload, qb::http::JwtErrorInfo &error_info) {
        if (!payload.contains("custom_claim")) {
            error_info = {qb::http::JwtError::INVALID_CLAIM, "Custom claim 'custom_claim' is missing."};
            return false;
        }
        if (payload.at("custom_claim").get<std::string>() != "valid") {
            error_info = {qb::http::JwtError::INVALID_CLAIM, "Custom claim 'custom_claim' has invalid value."};
            return false;
        }
        return true;
    });

    // Test Case 1: Validator returns true
    qb::json payload_valid = {{"sub", "validator_user"}, {"custom_claim", "valid"}};
    std::string token_valid = generate_token(payload_valid);
    auto req_valid = create_request();
    req_valid.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_valid);
    configure_router_and_run(_jwt_mw, std::move(req_valid));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);

    // Test Case 2: Validator returns false (invalid value)
    _session->reset();
    qb::json payload_invalid = {{"sub", "validator_user"}, {"custom_claim", "invalid"}};
    std::string token_invalid = generate_token(payload_invalid);
    auto req_invalid = create_request();
    req_invalid.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_invalid);
    configure_router_and_run(_jwt_mw, std::move(req_invalid));

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    std::string body_str_invalid = _session->_response.body().as<std::string>();
    EXPECT_TRUE(body_str_invalid.find("Custom claim 'custom_claim' has invalid value.") != std::string::npos ||
        body_str_invalid.find("Custom JWT validation failed") != std::string::npos)
                << "Body: " << body_str_invalid;
    EXPECT_FALSE(_session->_final_handler_called);

    // Test Case 3: Validator returns false (missing claim)
    _session->reset();
    qb::json payload_missing = {{"sub", "validator_user"}};
    std::string token_missing = generate_token(payload_missing);
    auto req_missing = create_request();
    req_missing.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_missing);
    configure_router_and_run(_jwt_mw, std::move(req_missing));

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    std::string body_str_missing = _session->_response.body().as<std::string>();
    EXPECT_TRUE(body_str_missing.find("Custom claim 'custom_claim' is missing.") != std::string::npos ||
        body_str_missing.find("Custom JWT validation failed") != std::string::npos)
                 << "Body: " << body_str_missing;
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, TokenTampering) {
    qb::json payload = {{"sub", "tamper_user"}};
    std::string token = generate_token(payload);

    size_t first_dot = token.find('.');
    ASSERT_NE(first_dot, std::string::npos);
    size_t second_dot = token.find('.', first_dot + 1);
    ASSERT_NE(second_dot, std::string::npos);

    std::string tampered_token = token;
    if (second_dot > first_dot + 1) {
        tampered_token[first_dot + 1] = (tampered_token[first_dot + 1] == 'A' ? 'B' : 'A');
    } else {
        tampered_token += "X";
    }

    auto req = create_request();
    req.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + tampered_token);
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    std::string body_str = _session->_response.body().as<std::string>();
    bool correct_error = body_str.find("Token signature verification failed") != std::string::npos ||
                         body_str.find("Invalid token format") != std::string::npos;
    EXPECT_TRUE(correct_error) << "Unexpected error message: " << body_str;
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, IssuerVerification) {
    _jwt_options.verify_iss = true;
    _jwt_options.issuer = "my-app-issuer";
    _jwt_mw->with_options(_jwt_options);

    // Case 1: Correct issuer
    qb::json payload_correct_iss_json;
    std::string token_correct_iss = generate_token(payload_correct_iss_json);
    auto req_correct_iss = create_request();
    req_correct_iss.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_correct_iss);
    configure_router_and_run(_jwt_mw, std::move(req_correct_iss));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);

    // Case 2: Wrong issuer
    _session->reset();
    qb::json payload_wrong_iss_json = {{"iss", "wrong-issuer"}};
    std::string token_wrong_iss = generate_token(payload_wrong_iss_json);
    auto req_wrong_iss = create_request();
    req_wrong_iss.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_wrong_iss);
    configure_router_and_run(_jwt_mw, std::move(req_wrong_iss));
    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED)
        << "Response body for IssuerVerification (Wrong Issuer): " << _session->_response.body().as<std::string>();
    EXPECT_NE(_session->_response.body().as<std::string>().find("\"error\":\"Invalid issuer.\""), std::string::npos)
        << "Response body for IssuerVerification (Wrong Issuer): " << _session->_response.body().as<std::string>();
    EXPECT_FALSE(_session->_final_handler_called);

    // Case 3: Missing issuer claim
    _session->reset();
    std::string token_missing_iss; {
        qb::jwt::CreateOptions custom_create_opts;
        auto alg_direct = qb::jwt::algorithm_from_string(_test_algorithm);
        ASSERT_TRUE(alg_direct.has_value());
        custom_create_opts.algorithm = *alg_direct;
        custom_create_opts.key = _test_secret;
        std::map<std::string, std::string> payload_map_no_iss = {
            {"sub", "missing_iss_user"},
            {
                "exp",
                std::to_string(
                    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::hours(1)))
            },
            {
                "nbf",
                std::to_string(
                    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() - std::chrono::minutes(1)))
            }
        };
        token_missing_iss = qb::jwt::create(payload_map_no_iss, custom_create_opts);
    }

    auto req_missing_iss = create_request();
    req_missing_iss.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_missing_iss);
    configure_router_and_run(_jwt_mw, std::move(req_missing_iss));
    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED)
        << "Response body for IssuerVerification (Missing Issuer): " << _session->_response.body().as<std::string>();
    EXPECT_NE(_session->_response.body().as<std::string>().find("\"error\":\"Invalid issuer.\""), std::string::npos)
        << "Response body for IssuerVerification (Missing Issuer): " << _session->_response.body().as<std::string>();
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, WrongSecret) {
    qb::json payload = {{"sub", "secret_user"}};
    std::string token_wrong_secret = generate_token(payload, "another_secret_entirely");

    auto req = create_request();
    req.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_wrong_secret);
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED)
        << "Response body for WrongSecret: " << _session->_response.body().as<std::string>();
    EXPECT_NE(_session->_response.body().as<std::string>().find("Invalid token signature."), std::string::npos)
        << "Response body for WrongSecret: " << _session->_response.body().as<std::string>();
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, AudienceValidation) {
    _jwt_options.verify_aud = true;
    _jwt_options.audience = "my-app-audience";
    _jwt_mw->with_options(_jwt_options);

    // Case 1: Correct audience
    qb::json payload_correct_aud_json;
    std::string token_correct_aud = generate_token(payload_correct_aud_json);
    auto req_correct_aud = create_request();
    req_correct_aud.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_correct_aud);
    configure_router_and_run(_jwt_mw, std::move(req_correct_aud));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);

    // Case 2: Wrong audience
    _session->reset();
    qb::json payload_wrong_aud_json = {{"aud", "wrong-audience"}};
    std::string token_wrong_aud = generate_token(payload_wrong_aud_json);
    auto req_wrong_aud = create_request();
    req_wrong_aud.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_wrong_aud);
    configure_router_and_run(_jwt_mw, std::move(req_wrong_aud));
    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED)
        << "Response body for AudienceValidation (Wrong Audience): " << _session->_response.body().as<std::string>();
    EXPECT_NE(_session->_response.body().as<std::string>().find("\"error\":\"Invalid audience.\""), std::string::npos)
        << "Response body for AudienceValidation (Wrong Audience): " << _session->_response.body().as<std::string>();
    EXPECT_FALSE(_session->_final_handler_called);

    // Case 3: Missing audience claim
    _session->reset();
    std::string token_missing_aud; {
        qb::jwt::CreateOptions custom_create_opts;
        auto alg_direct = qb::jwt::algorithm_from_string(_test_algorithm);
        ASSERT_TRUE(alg_direct.has_value());
        custom_create_opts.algorithm = *alg_direct;
        custom_create_opts.key = _test_secret;
        std::map<std::string, std::string> payload_map_no_aud = {
            {"sub", "missing_aud_user"},
            {
                "exp",
                std::to_string(
                    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::hours(1)))
            },
            {
                "nbf",
                std::to_string(
                    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() - std::chrono::minutes(1)))
            }
        };
        token_missing_aud = qb::jwt::create(payload_map_no_aud, custom_create_opts);
    }

    auto req_missing_aud = create_request();
    req_missing_aud.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_missing_aud);
    configure_router_and_run(_jwt_mw, std::move(req_missing_aud));
    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED)
        << "Response body for AudienceValidation (Missing Audience): " << _session->_response.body().as<std::string>();
    EXPECT_NE(_session->_response.body().as<std::string>().find("\"error\":\"Invalid audience.\""), std::string::npos)
        << "Response body for AudienceValidation (Missing Audience): " << _session->_response.body().as<std::string>();
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, SubjectVerification) {
    _jwt_options.verify_sub = true;
    _jwt_options.subject = "expected-subject";
    _jwt_mw->with_options(_jwt_options);

    // Case 1: Correct subject
    qb::json payload_correct_sub_json = {{"sub", "expected-subject"}};
    std::string token_correct_sub = generate_token(payload_correct_sub_json);
    auto req_correct_sub = create_request();
    req_correct_sub.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_correct_sub);
    configure_router_and_run(_jwt_mw, std::move(req_correct_sub));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);

    // Case 2: Wrong subject
    _session->reset();
    qb::json payload_wrong_sub_json = {{"sub", "wrong-subject"}};
    std::string token_wrong_sub = generate_token(payload_wrong_sub_json);
    auto req_wrong_sub = create_request();
    req_wrong_sub.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_wrong_sub);
    configure_router_and_run(_jwt_mw, std::move(req_wrong_sub));
    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED)
        << "Response body for SubjectVerification (Wrong Subject): " << _session->_response.body().as<std::string>();
    EXPECT_NE(_session->_response.body().as<std::string>().find("Invalid subject"), std::string::npos)
        << "Response body for SubjectVerification (Wrong Subject): " << _session->_response.body().as<std::string>();
    EXPECT_FALSE(_session->_final_handler_called);

    // Case 3: Missing subject claim
    _session->reset();
    std::string token_missing_sub_alt; {
        qb::jwt::CreateOptions custom_create_opts;
        auto alg_direct = qb::jwt::algorithm_from_string(_test_algorithm);
        ASSERT_TRUE(alg_direct.has_value());
        custom_create_opts.algorithm = *alg_direct;
        custom_create_opts.key = _test_secret;
        std::map<std::string, std::string> payload_map_no_sub = {
            {"user_id", "user_without_sub_claim"},
            {
                "exp",
                std::to_string(
                    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::hours(1)))
            },
            {
                "nbf",
                std::to_string(
                    std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() - std::chrono::minutes(1)))
            }
        };
        token_missing_sub_alt = qb::jwt::create(payload_map_no_sub, custom_create_opts);
    }

    auto req_missing_sub = create_request();
    req_missing_sub.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_missing_sub_alt);
    configure_router_and_run(_jwt_mw, std::move(req_missing_sub));
    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED)
        << "Response body for SubjectVerification (Missing Subject): " << _session->_response.body().as<std::string>();
    EXPECT_NE(_session->_response.body().as<std::string>().find("\"error\":\"Invalid subject.\""), std::string::npos)
        << "Response body for SubjectVerification (Missing Subject): " << _session->_response.body().as<std::string>();
    EXPECT_FALSE(_session->_final_handler_called);
}


TEST_F(JwtMiddlewareTest, ClockSkewTolerance) {
    _jwt_options.leeway_seconds = 60;
    _jwt_mw->with_options(_jwt_options);
    qb::json payload = {{"sub", "skew_user"}};

    // Test 1: Token expired by 30s (within leeway)
    _session->reset();
    std::string token_exp_within_leeway = generate_token(payload, "", std::chrono::seconds(-30));
    auto req_exp_leeway = create_request();
    req_exp_leeway.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_exp_within_leeway);
    configure_router_and_run(_jwt_mw, std::move(req_exp_leeway));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK) << "Expired within leeway failed. Body: " << _session
->_response.body().as<std::string>();
    EXPECT_TRUE(_session->_final_handler_called);

    // Test 2: Token expired by 90s (outside leeway)
    _session->reset();
    std::string token_exp_outside_leeway = generate_token(payload, "", std::chrono::seconds(-90));
    auto req_exp_no_leeway = create_request();
    req_exp_no_leeway.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_exp_outside_leeway);
    configure_router_and_run(_jwt_mw, std::move(req_exp_no_leeway));
    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().as<std::string>().find("Token has expired"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);

    // Test 3: Token NBF is 30s in future (within leeway)
    _session->reset();
    std::string token_nbf_within_leeway = generate_token(payload, "", std::chrono::hours(1), std::chrono::seconds(30));
    auto req_nbf_leeway = create_request();
    req_nbf_leeway.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_nbf_within_leeway);
    configure_router_and_run(_jwt_mw, std::move(req_nbf_leeway));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK) << "NBF within leeway failed. Body: " << _session->
_response.body().as<std::string>();
    EXPECT_TRUE(_session->_final_handler_called);

    // Test 4: Token NBF is 90s in future (outside leeway)
    _session->reset();
    std::string token_nbf_outside_leeway = generate_token(payload, "", std::chrono::hours(1), std::chrono::seconds(90));
    auto req_nbf_no_leeway = create_request();
    req_nbf_no_leeway.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token_nbf_outside_leeway);
    configure_router_and_run(_jwt_mw, std::move(req_nbf_no_leeway));
    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().as<std::string>().find("Token is not yet active"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, CustomErrorHandler) {
    bool custom_handler_called = false;
    _jwt_mw->with_error_handler(
        [&custom_handler_called](std::shared_ptr<qb::http::Context<MockJwtSession> > ctx,
                                 const qb::http::JwtErrorInfo &error_info) {
            custom_handler_called = true;
            ctx->response().status() = qb::http::status::IM_A_TEAPOT;
            ctx->response().body() = "Custom JWT Error: " + error_info.message;
            ctx->complete();
        });

    configure_router_and_run(_jwt_mw, create_request());

    EXPECT_TRUE(custom_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::IM_A_TEAPOT);
    EXPECT_NE(_session->_response.body().as<std::string>().find("Custom JWT Error: JWT token is missing"),
              std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, SuccessHandlerCanAccessPayload) {
    _router = std::make_unique<qb::http::Router<MockJwtSession> >();

    qb::http::RouteHandlerFn<MockJwtSession> custom_success_handler =
            [this](std::shared_ptr<qb::http::Context<MockJwtSession> > ctx) {
        if (_session) {
            _session->_final_handler_called = true;
            EXPECT_TRUE(ctx->has("jwt_payload"));
            if (ctx->has("jwt_payload")) {
                _session->_jwt_payload_in_context = ctx->template get<qb::json>("jwt_payload");
            }
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Authenticated Access Granted, payload checked";
        ctx->complete();
    };

    _router->use(_jwt_mw);
    _router->get("/protected", custom_success_handler);
    _router->compile();

    qb::json payload = {{"sub", "payload_access_user"}, {"data", "secret_info"}};
    std::string token = generate_token(payload);

    auto req = create_request();
    req.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + " " + token);

    _session->reset();
    _router->route(_session, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    EXPECT_EQ(_session->_jwt_payload_in_context->at("sub").get<std::string>(), "payload_access_user");
    EXPECT_EQ(_session->_jwt_payload_in_context->at("data").get<std::string>(), "secret_info");
}


TEST_F(JwtMiddlewareTest, FactoryFunctionsWorkAsExpected) {
    // Test 1: jwt_middleware(secret, algorithm)
    auto factory_mw1 = qb::http::jwt_middleware<MockJwtSession>(_test_secret, _test_algorithm);

    qb::json payload1 = {{"sub", "factory_user1"}};
    std::string token1 = generate_token(payload1);

    auto req1 = create_request();
    req1.set_header("Authorization", "Bearer " + token1);
    configure_router_and_run(factory_mw1, std::move(req1));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK) << "Factory MW1 Failed. Body: " << _session->_response
.body().as<std::string>();
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    EXPECT_EQ(_session->_jwt_payload_in_context->at("sub").get<std::string>(), "factory_user1");

    // Test 1.1: Missing token with factory_mw1
    _session->reset();
    configure_router_and_run(factory_mw1, create_request());
    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().as<std::string>().find("JWT token is missing"), std::string::npos);

    // Test 2: jwt_middleware_with_options(options)
    _session->reset();
    qb::http::JwtOptions custom_options;
    custom_options.secret = "another_factory_secret";
    custom_options.algorithm = _test_algorithm;
    custom_options.token_location = qb::http::JwtTokenLocation::COOKIE;
    custom_options.token_name = "factory_cookie_token";
    custom_options.auth_scheme = "";

    auto factory_mw2 = qb::http::jwt_middleware_with_options<MockJwtSession>(custom_options);

    qb::json payload2 = {{"sub", "factory_user2"}};
    std::string token2 = generate_token(payload2, custom_options.secret);

    auto req2 = create_request();
    req2.cookies().add(custom_options.token_name, token2);
    configure_router_and_run(factory_mw2, std::move(req2));

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK)
        << "Factory MW2 Failed. Body: " << _session->_response.body().as<std::string>();
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_jwt_payload_in_context.has_value());
    EXPECT_EQ(_session->_jwt_payload_in_context->at("sub").get<std::string>(), "factory_user2");
}

TEST_F(JwtMiddlewareTest, TokenWithNoSchemeWhenSchemeExpected) {
    qb::json payload = {{"sub", "no_scheme_user"}};
    std::string token = generate_token(payload);

    auto req = create_request();
    req.set_header(_jwt_options.token_name, token);
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().as<std::string>().find("\"error\":\"JWT token is missing.\""),
              std::string::npos)
        << "Response body: " << _session->_response.body().as<std::string>();
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, TokenWithWrongSchemeWhenSchemeExpected) {
    qb::json payload = {{"sub", "wrong_scheme_user"}};
    std::string token = generate_token(payload);

    auto req = create_request();
    req.set_header(_jwt_options.token_name, "Basic " + token);
    configure_router_and_run(_jwt_mw, std::move(req));

    EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().as<std::string>().find("\"error\":\"JWT token is missing.\""),
              std::string::npos)
        << "Response body: " << _session->_response.body().as<std::string>();
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, CaseInsensitiveAuthSchemeInHeader) {
    qb::json payload = {{"sub", "case_scheme_user"}};
    std::string token = generate_token(payload);
    auto req = create_request();

    _session->reset();
    req.set_header(_jwt_options.token_name, "bearer " + token);
    configure_router_and_run(_jwt_mw, std::move(req));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK)
        << "Lowercase scheme failed. Body: " << _session->_response.body().as<std::string>();
    EXPECT_TRUE(_session->_final_handler_called);

    _session->reset();
    req = create_request();
    req.set_header(_jwt_options.token_name, "BeArEr " + token);
    configure_router_and_run(_jwt_mw, std::move(req));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK)
        << "Mixed case scheme failed. Body: " << _session->_response.body().as<std::string>();
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(JwtMiddlewareTest, WhitespaceToleranceInAuthHeader) {
    qb::json payload = {{"sub", "whitespace_user"}};
    std::string token = generate_token(payload);
    auto req = create_request();

    _session->reset();
    req.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + "   " + token);
    configure_router_and_run(_jwt_mw, std::move(req));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK)
        << "Extra spaces after scheme. Body: " << _session->_response.body().as<std::string>();
    EXPECT_TRUE(_session->_final_handler_called);

    _session->reset();
    req = create_request();
    req.set_header(_jwt_options.token_name, "  " + _jwt_options.auth_scheme + " " + token);
    configure_router_and_run(_jwt_mw, std::move(req));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK)
        << "Leading spaces before scheme. Body: " << _session->_response.body().as<std::string>();
    EXPECT_TRUE(_session->_final_handler_called);

    if (!_jwt_options.auth_scheme.empty()) {
        _session->reset();
        req = create_request();
        req.set_header(_jwt_options.token_name, _jwt_options.auth_scheme + token);
        configure_router_and_run(_jwt_mw, std::move(req));
        EXPECT_EQ(_session->_response.status(), qb::http::status::UNAUTHORIZED)
            << "No space between scheme and token. Body: " << _session->_response.body().as<std::string>();
        EXPECT_NE(_session->_response.body().as<std::string>().find("\"error\":\"JWT token is missing.\""),
                  std::string::npos)
             << "Response body: " << _session->_response.body().as<std::string>();
        EXPECT_FALSE(_session->_final_handler_called);
    }
}

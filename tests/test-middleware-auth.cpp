#include <gtest/gtest.h>
#include "../http.h" // Should provide Router, Request, Response, Context, IMiddleware, MiddlewareTask, etc.
#include "../middleware/auth.h" // The adapted AuthMiddleware
#include "../auth.h"       // For qb::http::auth::User, qb::http::auth::Options

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sstream> // For ostringstream in session mock
#include <chrono>  // For time-based tests
#include <qb/io/crypto_jwt.h> // For qb::jwt::create and options
#include <qb/json.h>          // For qb::json
#include <algorithm> // For std::transform
#include <stdexcept> // For std::runtime_error
#include <optional> // For std::optional

// --- Mock Session for AuthMiddleware Tests ---
struct MockAuthSession {
    qb::http::Response _response;
    std::string _session_id_str = "auth_test_session";
    std::ostringstream _trace;
    std::optional<qb::http::auth::User> _user_in_context;
    bool _final_handler_called = false;

    qb::http::Response& get_response_ref() { return _response; }

    MockAuthSession& operator<<(const qb::http::Response& resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _trace.str("");
        _trace.clear();
        _user_in_context.reset();
        _final_handler_called = false;
    }

    void trace(const std::string& point) {
        if (!_trace.str().empty()) _trace << ";";
        _trace << point;
    }
    std::string get_trace() const { return _trace.str(); }
};

// Helper to get current epoch time
static uint64_t current_epoch_time() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
               .count());
}

// --- Test Fixture for AuthMiddleware --- 
class AuthMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockAuthSession> _session;
    std::unique_ptr<qb::http::Router<MockAuthSession>> _router;
    qb::http::auth::Options _auth_options;
    std::shared_ptr<qb::http::AuthMiddleware<MockAuthSession>> _auth_mw;

    // Default secret key for tests
    const std::string _test_secret = "test_secret_key_for_auth_middleware_123";

    void SetUp() override {
        _session = std::make_shared<MockAuthSession>();
        _router = std::make_unique<qb::http::Router<MockAuthSession>>();
        _auth_options.secret_key(_test_secret);
        // Default auth middleware instance, can be replaced in tests
        _auth_mw = qb::http::create_auth_middleware<MockAuthSession>(_auth_options);
    }

    qb::http::Request create_request(qb::http::method method_val = qb::http::method::HTTP_GET, const std::string& target_path = "/test") {
        qb::http::Request req;
        req.method = method_val;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception& e) {
            ADD_FAILURE() << "URI parse failure in create_request: " << target_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        return req;
    }

    // Handler that runs if authentication passes
    qb::http::RouteHandlerFn<MockAuthSession> success_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockAuthSession>> ctx) {
            _session->trace("SuccessHandlerCalled");
            _session->_final_handler_called = true;
            if (ctx->has("user")) {
                _session->_user_in_context = ctx->template get<qb::http::auth::User>("user");
            }
            ctx->response().status_code = qb::http::status::HTTP_STATUS_OK;
            ctx->response().body() = "Access Granted";
            ctx->complete();
        };
    }

    void configure_router_with_auth_mw(std::shared_ptr<qb::http::AuthMiddleware<MockAuthSession>> auth_mw_to_use) {
        _router->use(auth_mw_to_use); // Router will wrap this in a MiddlewareTask
        _router->get("/test", success_handler());
        _router->compile();
    }

    void make_request(qb::http::Request request) {
        _session->reset();
        _router->route(_session, std::move(request));
        // Assuming AuthMiddleware is synchronous and doesn't use TaskExecutor for JWT verification itself
    }

    std::string generate_test_token(const qb::http::auth::User& user, const std::string& secret_override = "") {
        qb::http::auth::Manager temp_manager(secret_override.empty() ? _auth_options : qb::http::auth::Options().secret_key(secret_override));
        return temp_manager.generate_token(user);
    }
};

// --- Test Cases --- 

TEST_F(AuthMiddlewareTest, ValidTokenAuthentication) {
    qb::http::auth::User test_user{"user123", "testuser", {"user"}};
    std::string token = generate_test_token(test_user);

    configure_router_with_auth_mw(_auth_mw); // Use default auth_mw
    
    auto req = create_request();
    req.set_header(_auth_options.get_auth_header_name(), _auth_options.get_auth_scheme() + " " + token);
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK);
    EXPECT_EQ(_session->_response.body().template as<std::string>(), "Access Granted");
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user123");
}

TEST_F(AuthMiddlewareTest, MissingToken) {
    _auth_mw->with_auth_required(true); // Ensure auth is required
    configure_router_with_auth_mw(_auth_mw);

    make_request(create_request()); // No token header

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().template as<std::string>().find("Authentication required"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, InvalidToken) {
    _auth_mw->with_auth_required(true);
    configure_router_with_auth_mw(_auth_mw);

    auto req = create_request();
    req.set_header(_auth_options.get_auth_header_name(), _auth_options.get_auth_scheme() + " an_invalid_token_string");
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED);
    // The exact message depends on qb::jwt::verify or AuthManager's verify_token
    EXPECT_NE(_session->_response.body().template as<std::string>().find("Invalid or expired token"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, ValidRoleAuthorization) {
    _auth_mw->with_auth_required(true).with_roles({"admin"});
    configure_router_with_auth_mw(_auth_mw);

    qb::http::auth::User admin_user{"admin1", "adminuser", {"admin", "user"}};
    std::string token = generate_test_token(admin_user);

    auto req = create_request();
    req.set_header(_auth_options.get_auth_header_name(), _auth_options.get_auth_scheme() + " " + token);
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->username, "adminuser");
}

TEST_F(AuthMiddlewareTest, InvalidRoleAuthorization) {
    _auth_mw->with_auth_required(true).with_roles({"admin"});
    configure_router_with_auth_mw(_auth_mw);

    qb::http::auth::User regular_user{"user001", "reguser", {"user"}};
    std::string token = generate_test_token(regular_user);

    auto req = create_request();
    req.set_header(_auth_options.get_auth_header_name(), _auth_options.get_auth_scheme() + " " + token);
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_FORBIDDEN);
    EXPECT_NE(_session->_response.body().template as<std::string>().find("Insufficient permissions"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, OptionalAuthentication) {
    // Create a new AuthMiddleware instance configured for optional auth
    auto optional_auth_mw = qb::http::create_optional_auth_middleware<MockAuthSession>(_auth_options);
    configure_router_with_auth_mw(optional_auth_mw);

    // Scenario 1: No token provided, should still allow access
    make_request(create_request());
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK);
    EXPECT_EQ(_session->_response.body().template as<std::string>(), "Access Granted");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_FALSE(_session->_user_in_context.has_value()); // No user in context

    _session->reset(); // Reset for next scenario

    // Scenario 2: Valid token provided, user should be in context
    qb::http::auth::User test_user{"user789", "optional_test", {"viewer"}};
    std::string token = generate_test_token(test_user);
    auto req_with_token = create_request();
    req_with_token.set_header(_auth_options.get_auth_header_name(), _auth_options.get_auth_scheme() + " " + token);
    make_request(std::move(req_with_token));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user789");
}

TEST_F(AuthMiddlewareTest, ExpiredTokenMiddleware) {
    // Create options for a token that expires quickly
    qb::http::auth::Options expiring_options = _auth_options; // Start with fixture defaults
    expiring_options.token_expiration(std::chrono::seconds(-3600)); // Expired one hour ago
    expiring_options.verify_expiration(true); // Ensure expiration is checked

    _auth_mw->with_options(expiring_options); // Apply to the middleware's manager
    _auth_mw->with_auth_required(true);
    configure_router_with_auth_mw(_auth_mw);

    qb::http::auth::User test_user{"exp_user", "expired", {"user"}};
    // Generate token with the expiring options (via the auth_mw's manager, which now has expiring_options)
    std::string expired_token = _auth_mw->generate_token(test_user);

    auto req = create_request();
    req.set_header(_auth_options.get_auth_header_name(), // Use original _auth_options for header name/scheme consistency if needed, or expiring_options
                   expiring_options.get_auth_scheme() + " " + expired_token);
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().template as<std::string>().find("Invalid or expired token"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, NotYetValidTokenMiddleware) {
    qb::http::auth::Options nbf_options = _auth_options; // Start with fixture defaults
    nbf_options.verify_not_before(true); // Ensure NBF is checked by the verifier
    // Clock skew defaults to 0, so NBF has to be exact or in the past

    _auth_mw->with_options(nbf_options);
    _auth_mw->with_auth_required(true);
    configure_router_with_auth_mw(_auth_mw);

    qb::http::auth::User test_user{"user_nbf", "nbf_tester", {"user"}};

    qb::json payload_json;
    payload_json["sub"] = test_user.id;
    payload_json["username"] = test_user.username;
    payload_json["roles"] = test_user.roles; // qb::json handles vector<string> to json array
    payload_json["iat"] = current_epoch_time();
    payload_json["nbf"] = current_epoch_time() + 3600; // Valid in 1 hour

    std::map<std::string, std::string> jwt_payload_map;
    for (auto& [key, value_json] : payload_json.items()) {
        if (value_json.is_string()) {
            jwt_payload_map[key] = value_json.get<std::string>();
        } else {
            jwt_payload_map[key] = value_json.dump(); // roles will be a JSON array string e.g. "[\"user\"]"
        }
    }
    
    qb::jwt::CreateOptions jwt_create_opts;
    const auto& current_auth_opts = _auth_mw->auth_manager().get_options();
    
    switch (current_auth_opts.get_algorithm()) {
        case qb::http::auth::Options::Algorithm::HMAC_SHA256:
            jwt_create_opts.algorithm = qb::jwt::Algorithm::HS256; break;
        case qb::http::auth::Options::Algorithm::HMAC_SHA384:
            jwt_create_opts.algorithm = qb::jwt::Algorithm::HS384; break;
        case qb::http::auth::Options::Algorithm::HMAC_SHA512:
            jwt_create_opts.algorithm = qb::jwt::Algorithm::HS512; break;
        // Add other algo mappings if necessary for tests, e.g. RSA
        default:
            FAIL() << "Unsupported algorithm for test token creation";
            return; // Or throw
    }

    const auto& secret_vec = current_auth_opts.get_secret_key();
    if (secret_vec.empty() && 
        (jwt_create_opts.algorithm == qb::jwt::Algorithm::HS256 || 
         jwt_create_opts.algorithm == qb::jwt::Algorithm::HS384 ||
         jwt_create_opts.algorithm == qb::jwt::Algorithm::HS512)) {
        FAIL() << "Secret key is empty for HMAC algorithm in test.";
        return;
    }
    jwt_create_opts.key = std::string(secret_vec.begin(), secret_vec.end());

    std::string token_not_yet_valid = qb::jwt::create(jwt_payload_map, jwt_create_opts);

    auto req = create_request();
    // Use header name/scheme from the options active in the middleware
    req.set_header(current_auth_opts.get_auth_header_name(), 
                   current_auth_opts.get_auth_scheme() + " " + token_not_yet_valid);
    make_request(std::move(req));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED);
    // This message is generic, qb::jwt might throw specific exception that AuthMiddleware standardizes
    EXPECT_NE(_session->_response.body().template as<std::string>().find("Invalid or expired token"), std::string::npos); 
    EXPECT_FALSE(_session->_final_handler_called);
}

// In a real scenario, these would be proper PEM-formatted keys.
const char* TEST_RSA_PRIVATE_KEY_PEM = 
    "-----BEGIN PRIVATE KEY-----\n"
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

const char* TEST_RSA_PUBLIC_KEY_PEM = 
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvV0OlTh5lAs/3W+Yxai/\n"
    "+aIJAO2c+irdkkdHlmt5TizIpk3BxjDa5JHl7dL7xwSg4geUYfCYONJmqwibnQjt\n"
    "p4CMYfdLaF0omZrUM2cFh4MR96KkBWMO5FSrLFR7l7rAvhwuNFd995Io0ZdsR1/n\n"
    "JBa8zAibuc3gTk7Pg/tsNBH2hJl0xdV0Y7GsY1xwOFTM0Y8pqPlzu9wrIk0n6j34\n"
    "Ns/j94c/aMKmpgXPUriZOSntW79Ec4GrstT6OAfG1iVNK5Nyk9l1LgHyZW7plsB1\n"
    "ozOxubm4R8iAA1O6JxwGArnLGZKEqmijHuitWQl0wWEGAfY3ElX4Rv3hXndHykQN\n"
    "fwIDAQAB\n"
    "-----END PUBLIC KEY-----";

TEST_F(AuthMiddlewareTest, RSAAlgorithmTokenVerification) {
    qb::http::auth::User test_user{"user_rsa", "rsatester", {"user"}};

    // 1. Configure AuthManager for RSA token CREATION (using private key)
    qb::http::auth::Options rsa_sign_options;
    rsa_sign_options.algorithm(qb::http::auth::Options::Algorithm::RSA_SHA256)
                    .private_key(TEST_RSA_PRIVATE_KEY_PEM)
                    .secret_key(""); // Clear HMAC secret key just in case

    qb::http::auth::Manager rsa_token_generator(rsa_sign_options);
    std::string rsa_token;
    try {
        rsa_token = rsa_token_generator.generate_token(test_user);
    } catch (const std::exception& e) {
        FAIL() << "RSA Token generation failed: " << e.what();
        return;
    }
    ASSERT_FALSE(rsa_token.empty());

    // 2. Configure AuthMiddleware for RSA token VERIFICATION (using public key)
    qb::http::auth::Options rsa_verify_options;
    rsa_verify_options.algorithm(qb::http::auth::Options::Algorithm::RSA_SHA256)
                      .public_key(TEST_RSA_PUBLIC_KEY_PEM)
                      .secret_key(""); // Clear HMAC secret key
    
    _auth_mw->with_options(rsa_verify_options);
    _auth_mw->with_auth_required(true);
    configure_router_with_auth_mw(_auth_mw); // Uses default success_handler

    // 3. Make request with RSA token
    _session->reset();
    auto req = create_request();
    // Use scheme/header from the verification options active in middleware
    req.set_header(rsa_verify_options.get_auth_header_name(), 
                   rsa_verify_options.get_auth_scheme() + " " + rsa_token);
    make_request(std::move(req));

    // 4. Assert success
    if (_session->_response.status_code != qb::http::status::HTTP_STATUS_OK) {
        FAIL() << "RSA Token verification failed. Status: " << _session->_response.status_code
               << ", Body: " << _session->_response.body().template as<std::string>();
    }
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user_rsa");

    // Optional Negative Test: Try to verify RSA token with HMAC config
    _session->reset();
    qb::http::auth::Options hmac_options_for_rsa_token = _auth_options; // Fixture default (HMAC)
     _auth_mw->with_options(hmac_options_for_rsa_token);
    // Router reconfig with new _auth_mw options (implicitly via configure_router_with_auth_mw)
    configure_router_with_auth_mw(_auth_mw); 

    auto req_hmac_verify = create_request();
    req_hmac_verify.set_header(hmac_options_for_rsa_token.get_auth_header_name(), 
                               hmac_options_for_rsa_token.get_auth_scheme() + " " + rsa_token);
    make_request(std::move(req_hmac_verify));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED)
        << "RSA token should not validate with HMAC configuration.";
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, CustomUserContextKey) {
    const std::string custom_key = "test_custom_user_key";
    _auth_mw->with_user_context_key(custom_key);
    _auth_mw->with_auth_required(true);
    // No need to call _auth_mw->with_options if default _auth_options is fine

    // Reconfigure router with the modified auth_mw and a custom handler for this test
    _router = std::make_unique<qb::http::Router<MockAuthSession>>(); 
    _router->use(_auth_mw);

    bool user_found_at_custom_key = false;
    bool user_found_at_default_key = false;
    std::optional<qb::http::auth::User> retrieved_user_opt;
    std::string original_user_id = "user_ctx_key_test";

    auto custom_key_check_handler = 
        [&](std::shared_ptr<qb::http::Context<MockAuthSession>> ctx) {
        _session->trace("CustomKeyCheckHandlerCalled");
        _session->_final_handler_called = true;
        if (ctx->has(custom_key)) {
            user_found_at_custom_key = true;
            retrieved_user_opt = ctx->template get<qb::http::auth::User>(custom_key);
        }
        if (ctx->has("user")) { // Check for default key "user"
            user_found_at_default_key = true;
        }
        ctx->response().status_code = qb::http::status::HTTP_STATUS_OK;
        ctx->response().body() = "Custom Key Handler Executed";
        ctx->complete();
    };

    _router->get("/test_custom_key", custom_key_check_handler);
    _router->compile();

    qb::http::auth::User test_user{original_user_id, "customkeyuser", {"user"}};
    std::string token = generate_test_token(test_user); // Uses _auth_options from fixture

    auto req = create_request(qb::http::method::HTTP_GET, "/test_custom_key");
    req.set_header(_auth_options.get_auth_header_name(), _auth_options.get_auth_scheme() + " " + token);
    
    _session->reset(); // Reset session before making the call via router
    _router->route(_session, std::move(req));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_TRUE(user_found_at_custom_key) << "User not found with custom key: " << custom_key;
    EXPECT_FALSE(user_found_at_default_key) << "User unexpectedly found with default key 'user'.";
    ASSERT_TRUE(retrieved_user_opt.has_value());
    EXPECT_EQ(retrieved_user_opt->id, original_user_id);
    EXPECT_EQ(retrieved_user_opt->username, "customkeyuser");
}

TEST_F(AuthMiddlewareTest, CustomAuthScheme) {
    const std::string custom_scheme = "MyAppToken";
    qb::http::auth::Options custom_scheme_options = _auth_options; // Base on fixture options
    custom_scheme_options.auth_scheme(custom_scheme);
    // Ensure other settings like secret_key are inherited from _auth_options

    _auth_mw->with_options(custom_scheme_options);
    _auth_mw->with_auth_required(true);
    configure_router_with_auth_mw(_auth_mw); // Uses the default success_handler

    qb::http::auth::User test_user{"user_scheme", "schemetester", {"user"}};
    // Token generation itself is scheme-agnostic; it uses the secret from custom_scheme_options via _auth_mw
    std::string token = _auth_mw->generate_token(test_user);

    // Scenario 1: Valid token with custom scheme
    _session->reset();
    auto req_custom_scheme = create_request();
    // Use the header name defined in custom_scheme_options (likely still "Authorization")
    req_custom_scheme.set_header(custom_scheme_options.get_auth_header_name(), 
                               custom_scheme + " " + token);
    make_request(std::move(req_custom_scheme));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user_scheme");

    // Scenario 2: Valid token but with default/wrong scheme (should fail)
    _session->reset();
    _session->_final_handler_called = false;

    auto req_default_scheme = create_request();
    req_default_scheme.set_header(custom_scheme_options.get_auth_header_name(), 
                                  _auth_options.get_auth_scheme() + " " + token); // Using default "Bearer"
    make_request(std::move(req_default_scheme));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED);
    EXPECT_NE(_session->_response.body().template as<std::string>().find("Invalid authentication format"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_FALSE(_session->_user_in_context.has_value());
}

TEST_F(AuthMiddlewareTest, RequireAllRoles) {
    _auth_mw->with_auth_required(true);
    // scena_options will be reused by reconfiguring _auth_mw

    qb::http::auth::User test_user{"user_all_roles", "allroler", {"editor", "viewer", "commenter"}};
    std::string token = generate_test_token(test_user); // Uses default _auth_options initially for token
                                                        // but auth_mw will use its configured options for verification.

    // Scenario 1: User has all required roles
    _session->reset();
    _auth_mw->with_roles({"editor", "viewer"}, true);
    configure_router_with_auth_mw(_auth_mw);
    
    auto req1 = create_request();
    req1.set_header(_auth_options.get_auth_header_name(), _auth_options.get_auth_scheme() + " " + token);
    make_request(std::move(req1));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK);
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, "user_all_roles");

    // Scenario 2: User is missing one of the required roles
    _session->reset();
    _auth_mw->with_roles({"editor", "admin"}, true); // Requires "admin", user doesn't have it
    // Router recompilation not strictly needed if only auth_mw config changes and not routes,
    // but configure_router_with_auth_mw does it, which is safer.
    configure_router_with_auth_mw(_auth_mw); 

    auto req2 = create_request();
    req2.set_header(_auth_options.get_auth_header_name(), _auth_options.get_auth_scheme() + " " + token);
    make_request(std::move(req2));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_FORBIDDEN);
    EXPECT_NE(_session->_response.body().template as<std::string>().find("Insufficient permissions"), std::string::npos);
    EXPECT_FALSE(_session->_final_handler_called);

    // Scenario 3: User is missing all of the (different) required roles
    _session->reset();
    _auth_mw->with_roles({"publisher", "auditor"}, true);
    configure_router_with_auth_mw(_auth_mw); 

    auto req3 = create_request();
    req3.set_header(_auth_options.get_auth_header_name(), _auth_options.get_auth_scheme() + " " + token);
    make_request(std::move(req3));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_FORBIDDEN);
    EXPECT_FALSE(_session->_final_handler_called);

    // Scenario 4: Required roles list is empty, require_all = true (should pass)
    _session->reset();
    _auth_mw->with_roles({}, true); // Empty list of required roles
    configure_router_with_auth_mw(_auth_mw);

    auto req4 = create_request();
    req4.set_header(_auth_options.get_auth_header_name(), _auth_options.get_auth_scheme() + " " + token);
    make_request(std::move(req4));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK)
        << "Access should be granted if require_all_roles is true and required list is empty.";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
}

TEST_F(AuthMiddlewareTest, ClockSkewTolerance) {
    qb::http::auth::User test_user{"user_skew", "skew_tester", {"user"}};
    const std::chrono::seconds tolerance(20);
    const std::chrono::seconds small_offset(10); // smaller than tolerance
    const std::chrono::seconds large_offset(30); // larger than tolerance

    qb::http::auth::Options skew_options = _auth_options;
    skew_options.clock_skew_tolerance(tolerance);
    skew_options.verify_expiration(true);
    skew_options.verify_not_before(true);

    _auth_mw->with_options(skew_options);
    _auth_mw->with_auth_required(true);
    configure_router_with_auth_mw(_auth_mw);
    
    const auto& current_auth_opts_for_creation = _auth_mw->auth_manager().get_options();
    qb::jwt::CreateOptions jwt_create_opts;
    switch (current_auth_opts_for_creation.get_algorithm()) {
        case qb::http::auth::Options::Algorithm::HMAC_SHA256:
            jwt_create_opts.algorithm = qb::jwt::Algorithm::HS256; break;
        // Add other necessary algorithm mappings here if tests use them
        default:
            FAIL() << "Unsupported algorithm for test token creation in ClockSkewTolerance";
            return;
    }
    const auto& secret_vec = current_auth_opts_for_creation.get_secret_key();
    if (secret_vec.empty()) {
        FAIL() << "Secret key is empty for HMAC algorithm in ClockSkewTolerance.";
        return;
    }
    jwt_create_opts.key = std::string(secret_vec.begin(), secret_vec.end());

    // --- Scenario 1: Clock skew with 'exp' (token expired but within tolerance) ---
    _session->reset();
    qb::json payload_exp_within_tolerance;
    payload_exp_within_tolerance["sub"] = test_user.id;
    payload_exp_within_tolerance["username"] = test_user.username;
    payload_exp_within_tolerance["roles"] = test_user.roles;
    payload_exp_within_tolerance["iat"] = current_epoch_time() - 7200; // Issued 2 hours ago
    payload_exp_within_tolerance["exp"] = current_epoch_time() - small_offset.count(); // Expired 10s ago

    std::map<std::string, std::string> map_exp_within_tolerance;
    for (auto& [k, v] : payload_exp_within_tolerance.items()) { map_exp_within_tolerance[k] = v.is_string() ? v.get<std::string>() : v.dump(); }
    
    std::string token_exp_within_tolerance = qb::jwt::create(map_exp_within_tolerance, jwt_create_opts);

    auto req1 = create_request();
    req1.set_header(current_auth_opts_for_creation.get_auth_header_name(), 
                    current_auth_opts_for_creation.get_auth_scheme() + " " + token_exp_within_tolerance);
    make_request(std::move(req1));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK)
        << "Token expired 10s ago, but should be OK due to 20s tolerance.";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, test_user.id);

    // --- Scenario 2: Clock skew with 'exp' (token expired beyond tolerance) ---
    _session->reset();
    qb::json payload_exp_beyond_tolerance;
    payload_exp_beyond_tolerance["sub"] = test_user.id;
    payload_exp_beyond_tolerance["username"] = test_user.username;
    payload_exp_beyond_tolerance["roles"] = test_user.roles;
    payload_exp_beyond_tolerance["iat"] = current_epoch_time() - 7200;
    payload_exp_beyond_tolerance["exp"] = current_epoch_time() - large_offset.count(); // Expired 30s ago

    std::map<std::string, std::string> map_exp_beyond_tolerance;
    for (auto& [k, v] : payload_exp_beyond_tolerance.items()) { map_exp_beyond_tolerance[k] = v.is_string() ? v.get<std::string>() : v.dump(); }

    std::string token_exp_beyond_tolerance = qb::jwt::create(map_exp_beyond_tolerance, jwt_create_opts);

    auto req2 = create_request();
    req2.set_header(current_auth_opts_for_creation.get_auth_header_name(), 
                    current_auth_opts_for_creation.get_auth_scheme() + " " + token_exp_beyond_tolerance);
    make_request(std::move(req2));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED)
        << "Token expired 30s ago, should be UNAUTHORIZED with 20s tolerance.";
    EXPECT_FALSE(_session->_final_handler_called);

    // --- Scenario 3: Clock skew with 'nbf' (token not yet valid but within tolerance) ---
    _session->reset();
    qb::json payload_nbf_within_tolerance;
    payload_nbf_within_tolerance["sub"] = test_user.id;
    payload_nbf_within_tolerance["username"] = test_user.username;
    payload_nbf_within_tolerance["roles"] = test_user.roles;
    payload_nbf_within_tolerance["iat"] = current_epoch_time();
    payload_nbf_within_tolerance["nbf"] = current_epoch_time() + small_offset.count(); // NBF in 10s
    
    std::map<std::string, std::string> map_nbf_within_tolerance;
    for (auto& [k, v] : payload_nbf_within_tolerance.items()) { map_nbf_within_tolerance[k] = v.is_string() ? v.get<std::string>() : v.dump(); }

    std::string token_nbf_within_tolerance = qb::jwt::create(map_nbf_within_tolerance, jwt_create_opts);

    auto req3 = create_request();
    req3.set_header(current_auth_opts_for_creation.get_auth_header_name(), 
                    current_auth_opts_for_creation.get_auth_scheme() + " " + token_nbf_within_tolerance);
    make_request(std::move(req3));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK)
        << "Token NBF in 10s, but should be OK due to 20s tolerance.";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, test_user.id);

    // --- Scenario 4: Clock skew with 'nbf' (token not yet valid beyond tolerance) ---
    _session->reset();
    qb::json payload_nbf_beyond_tolerance;
    payload_nbf_beyond_tolerance["sub"] = test_user.id;
    payload_nbf_beyond_tolerance["username"] = test_user.username;
    payload_nbf_beyond_tolerance["roles"] = test_user.roles;
    payload_nbf_beyond_tolerance["iat"] = current_epoch_time();
    payload_nbf_beyond_tolerance["nbf"] = current_epoch_time() + large_offset.count(); // NBF in 30s

    std::map<std::string, std::string> map_nbf_beyond_tolerance;
    for (auto& [k, v] : payload_nbf_beyond_tolerance.items()) { map_nbf_beyond_tolerance[k] = v.is_string() ? v.get<std::string>() : v.dump(); }

    std::string token_nbf_beyond_tolerance = qb::jwt::create(map_nbf_beyond_tolerance, jwt_create_opts);
    
    auto req4 = create_request();
    req4.set_header(current_auth_opts_for_creation.get_auth_header_name(), 
                    current_auth_opts_for_creation.get_auth_scheme() + " " + token_nbf_beyond_tolerance);
    make_request(std::move(req4));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED)
        << "Token NBF in 30s, should be UNAUTHORIZED with 20s tolerance.";
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, IssuerAudienceFlexibility) {
    qb::http::auth::User test_user{"user_iss_aud", "iss_aud_tester", {"user"}};
    
    // Helper to create token with specific iss/aud
    auto create_custom_token = [&](const qb::http::auth::User& user,
                                   const qb::http::auth::Options& creation_opts,
                                   const std::optional<std::string>& issuer,
                                   const std::optional<std::string>& audience) -> std::optional<std::string> {
        qb::json payload_json;
        payload_json["sub"] = user.id;
        payload_json["username"] = user.username;
        payload_json["roles"] = user.roles;
        payload_json["iat"] = current_epoch_time();
        payload_json["exp"] = current_epoch_time() + 3600; // Valid for 1 hour

        if (issuer) payload_json["iss"] = *issuer;
        if (audience) payload_json["aud"] = *audience;

        std::map<std::string, std::string> jwt_payload_map;
        for (auto& [key, value_json] : payload_json.items()) {
            jwt_payload_map[key] = value_json.is_string() ? value_json.get<std::string>() : value_json.dump();
        }
        
        qb::jwt::CreateOptions jwt_create_opts;
        switch (creation_opts.get_algorithm()) {
            case qb::http::auth::Options::Algorithm::HMAC_SHA256: {
                jwt_create_opts.algorithm = qb::jwt::Algorithm::HS256; break;
            }
            default: {
                // Instead of FAIL() here, indicate error via return type
                // The caller (test body) will use FAIL()
                return std::nullopt; 
            }
        }
        const auto& secret_vec = creation_opts.get_secret_key();
        if (secret_vec.empty()) { 
            // Instead of FAIL() here, indicate error via return type
            return std::nullopt;
        }
        jwt_create_opts.key = std::string(secret_vec.begin(), secret_vec.end());
        
        // It's possible qb::jwt::create itself throws an exception on error.
        // If so, the lambda doesn't need to handle it explicitly if the test body 
        // is not meant to catch it (i.e., an exception means test failure).
        // For now, assume it returns a string or we are interested in specific pre-checks.
        try {
            return qb::jwt::create(jwt_payload_map, jwt_create_opts);
        } catch (const std::exception& e) {
            // Log or handle if necessary, then return nullopt to signal failure to caller
            // For test purposes, usually letting it propagate or returning nullopt is fine.
            // std::cerr << "qb::jwt::create failed: " << e.what() << std::endl;
            return std::nullopt;
        }
    };

    // --- Part 1: Issuer Tests ---
    qb::http::auth::Options issuer_verify_opts = _auth_options;
    issuer_verify_opts.token_issuer("my_app"); // This also sets verify_issuer = true

    // Scenario 1.1: Correct Issuer
    _session->reset();
    _auth_mw->with_options(issuer_verify_opts).with_auth_required(true);
    configure_router_with_auth_mw(_auth_mw);
    std::optional<std::string> token_correct_iss_opt = create_custom_token(test_user, issuer_verify_opts, "my_app", std::nullopt);
    if (!token_correct_iss_opt) { FAIL() << "S1.1 Token creation failed (correct issuer)."; return; }
    std::string token_correct_iss = *token_correct_iss_opt;
    auto req1_1 = create_request();
    req1_1.set_header(issuer_verify_opts.get_auth_header_name(), issuer_verify_opts.get_auth_scheme() + " " + token_correct_iss);
    make_request(std::move(req1_1));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "S1.1 Correct Issuer";
    EXPECT_TRUE(_session->_final_handler_called);

    // Scenario 1.2: Incorrect Issuer
    _session->reset();
    std::optional<std::string> token_incorrect_iss_opt = create_custom_token(test_user, issuer_verify_opts, "other_app", std::nullopt);
    if (!token_incorrect_iss_opt) { FAIL() << "S1.2 Token creation failed (incorrect issuer)."; return; }
    std::string token_incorrect_iss = *token_incorrect_iss_opt;
    auto req1_2 = create_request();
    req1_2.set_header(issuer_verify_opts.get_auth_header_name(), issuer_verify_opts.get_auth_scheme() + " " + token_incorrect_iss);
    make_request(std::move(req1_2));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED) << "S1.2 Incorrect Issuer";
    EXPECT_FALSE(_session->_final_handler_called);

    // Scenario 1.3: Missing Issuer in Token, Verification On
    _session->reset();
    std::optional<std::string> token_no_iss_opt = create_custom_token(test_user, issuer_verify_opts, std::nullopt, std::nullopt);
    if (!token_no_iss_opt) { FAIL() << "S1.3 Token creation failed (no issuer)."; return; }
    std::string token_no_iss = *token_no_iss_opt;
    auto req1_3 = create_request();
    req1_3.set_header(issuer_verify_opts.get_auth_header_name(), issuer_verify_opts.get_auth_scheme() + " " + token_no_iss);
    make_request(std::move(req1_3));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED) << "S1.3 Missing Issuer";
    EXPECT_FALSE(_session->_final_handler_called);

    // Scenario 1.4: Issuer in Token, Verification Off
    _session->reset();
    qb::http::auth::Options issuer_no_verify_opts = _auth_options;
    issuer_no_verify_opts.token_issuer(""); 
    _auth_mw->with_options(issuer_no_verify_opts);
    configure_router_with_auth_mw(_auth_mw);
    std::optional<std::string> token_with_iss_verify_off_opt = create_custom_token(test_user, issuer_no_verify_opts, "any_app_iss", std::nullopt);
    if (!token_with_iss_verify_off_opt) { FAIL() << "S1.4 Token creation failed (issuer present, verify off)."; return; }
    std::string token_with_iss_verify_off = *token_with_iss_verify_off_opt;
    auto req1_4 = create_request();
    req1_4.set_header(issuer_no_verify_opts.get_auth_header_name(), issuer_no_verify_opts.get_auth_scheme() + " " + token_with_iss_verify_off);
    make_request(std::move(req1_4));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "S1.4 Issuer Present, Verification Off";
    EXPECT_TRUE(_session->_final_handler_called);

    // --- Part 2: Audience Tests ---
    qb::http::auth::Options audience_verify_opts = _auth_options;
    audience_verify_opts.token_audience("my_client"); 

    // Scenario 2.1: Correct Audience
    _session->reset();
    _auth_mw->with_options(audience_verify_opts);
    configure_router_with_auth_mw(_auth_mw);
    std::optional<std::string> token_correct_aud_opt = create_custom_token(test_user, audience_verify_opts, std::nullopt, "my_client");
    if (!token_correct_aud_opt) { FAIL() << "S2.1 Token creation failed (correct audience)."; return; }
    std::string token_correct_aud = *token_correct_aud_opt;
    auto req2_1 = create_request();
    req2_1.set_header(audience_verify_opts.get_auth_header_name(), audience_verify_opts.get_auth_scheme() + " " + token_correct_aud);
    make_request(std::move(req2_1));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "S2.1 Correct Audience";
    EXPECT_TRUE(_session->_final_handler_called);

    // Scenario 2.2: Incorrect Audience
    _session->reset();
    std::optional<std::string> token_incorrect_aud_opt = create_custom_token(test_user, audience_verify_opts, std::nullopt, "other_client");
    if (!token_incorrect_aud_opt) { FAIL() << "S2.2 Token creation failed (incorrect audience)."; return; }
    std::string token_incorrect_aud = *token_incorrect_aud_opt;
    auto req2_2 = create_request();
    req2_2.set_header(audience_verify_opts.get_auth_header_name(), audience_verify_opts.get_auth_scheme() + " " + token_incorrect_aud);
    make_request(std::move(req2_2));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED) << "S2.2 Incorrect Audience";
    EXPECT_FALSE(_session->_final_handler_called);

    // Scenario 2.3: Missing Audience in Token, Verification On
    _session->reset();
    std::optional<std::string> token_no_aud_opt = create_custom_token(test_user, audience_verify_opts, std::nullopt, std::nullopt);
    if (!token_no_aud_opt) { FAIL() << "S2.3 Token creation failed (no audience)."; return; }
    std::string token_no_aud = *token_no_aud_opt;
    auto req2_3 = create_request();
    req2_3.set_header(audience_verify_opts.get_auth_header_name(), audience_verify_opts.get_auth_scheme() + " " + token_no_aud);
    make_request(std::move(req2_3));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED) << "S2.3 Missing Audience";
    EXPECT_FALSE(_session->_final_handler_called);

    // Scenario 2.4: Audience in Token, Verification Off
    _session->reset();
    qb::http::auth::Options audience_no_verify_opts = _auth_options;
    audience_no_verify_opts.token_audience(""); 
    _auth_mw->with_options(audience_no_verify_opts);
    configure_router_with_auth_mw(_auth_mw);
    std::optional<std::string> token_with_aud_verify_off_opt = create_custom_token(test_user, audience_no_verify_opts, std::nullopt, "any_client_aud");
    if (!token_with_aud_verify_off_opt) { FAIL() << "S2.4 Token creation failed (audience present, verify off)."; return; }
    std::string token_with_aud_verify_off = *token_with_aud_verify_off_opt;
    auto req2_4 = create_request();
    req2_4.set_header(audience_no_verify_opts.get_auth_header_name(), audience_no_verify_opts.get_auth_scheme() + " " + token_with_aud_verify_off);
    make_request(std::move(req2_4));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "S2.4 Audience Present, Verification Off";
    EXPECT_TRUE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, CaseInsensitiveAuthHeaderName) {
    const std::string custom_header_name_config = "X-MyApp-AuthToken";
    qb::http::auth::Options custom_header_options = _auth_options;
    custom_header_options.auth_header_name(custom_header_name_config);
    // Scheme remains default "Bearer" or what _auth_options has.

    _auth_mw->with_options(custom_header_options);
    _auth_mw->with_auth_required(true);
    configure_router_with_auth_mw(_auth_mw);

    qb::http::auth::User test_user{"user_header_case", "headercaser", {"user"}};
    std::string token = _auth_mw->generate_token(test_user); // Token uses middleware's current options
    std::string token_header_value = custom_header_options.get_auth_scheme() + " " + token;

    // Scenario 1: Exact case match
    _session->reset();
    auto req_exact = create_request();
    req_exact.set_header(custom_header_name_config, token_header_value);
    make_request(std::move(req_exact));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "Exact case";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());

    // Scenario 2: Lowercase header name in request
    _session->reset();
    auto req_lower = create_request();
    std::string lower_case_header = custom_header_name_config;
    std::transform(lower_case_header.begin(), lower_case_header.end(), lower_case_header.begin(), ::tolower);
    req_lower.set_header(lower_case_header, token_header_value);
    make_request(std::move(req_lower));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "Lowercase header";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());

    // Scenario 3: Mixed/Upper case header name in request
    _session->reset();
    auto req_upper = create_request();
    std::string upper_case_header = custom_header_name_config;
    std::transform(upper_case_header.begin(), upper_case_header.end(), upper_case_header.begin(), ::toupper);
    req_upper.set_header(upper_case_header, token_header_value);
    make_request(std::move(req_upper));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "Uppercase header";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());

    // Scenario 4: Wrong header name (using default "Authorization" when custom is set)
    _session->reset();
    auto req_wrong_name = create_request();
    req_wrong_name.set_header("Authorization", token_header_value); // Default, but should fail
    make_request(std::move(req_wrong_name));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED) << "Wrong header name";
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, CaseInsensitiveAuthScheme) {
    // --- Scenario 1: Default "Bearer" scheme --- 
    _auth_mw->with_auth_required(true);
    // No need to call _auth_mw->with_options if default _auth_options (HMAC, Bearer) is fine
    configure_router_with_auth_mw(_auth_mw); // Uses default success_handler

    qb::http::auth::User test_user_bearer{"user_scheme_case", "bearercaser", {"user"}};
    std::string token_bearer = generate_test_token(test_user_bearer);

    const std::string header_name_bearer = _auth_options.get_auth_header_name();

    // 1.1: "bearer" (lowercase)
    _session->reset();
    auto req_lower_bearer = create_request();
    req_lower_bearer.set_header(header_name_bearer, "bearer " + token_bearer);
    make_request(std::move(req_lower_bearer));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "Lowercase Bearer";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, test_user_bearer.id);

    // 1.2: "BEARER" (uppercase)
    _session->reset();
    auto req_upper_bearer = create_request();
    req_upper_bearer.set_header(header_name_bearer, "BEARER " + token_bearer);
    make_request(std::move(req_upper_bearer));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "Uppercase Bearer";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());

    // 1.3: "BeArEr" (mixed case)
    _session->reset();
    auto req_mixed_bearer = create_request();
    req_mixed_bearer.set_header(header_name_bearer, "BeArEr " + token_bearer);
    make_request(std::move(req_mixed_bearer));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "Mixed case Bearer";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());

    // --- Scenario 2: Custom scheme --- 
    const std::string custom_scheme_val = "MyAppAuth";
    qb::http::auth::Options custom_scheme_opts = _auth_options;
    custom_scheme_opts.auth_scheme(custom_scheme_val);

    _auth_mw->with_options(custom_scheme_opts);
    // Router is reconfigured by configure_router_with_auth_mw below
    configure_router_with_auth_mw(_auth_mw);

    qb::http::auth::User test_user_custom{"user_custom_scheme_case", "customcaser", {"admin"}};
    // Token generation uses the options currently in _auth_mw
    std::string token_custom = _auth_mw->generate_token(test_user_custom); 
    const std::string header_name_custom = custom_scheme_opts.get_auth_header_name();

    // 2.1: "myappauth" (lowercase custom)
    _session->reset();
    auto req_lower_custom = create_request();
    std::string lower_custom_scheme = custom_scheme_val;
    std::transform(lower_custom_scheme.begin(), lower_custom_scheme.end(), lower_custom_scheme.begin(), ::tolower);
    req_lower_custom.set_header(header_name_custom, lower_custom_scheme + " " + token_custom);
    make_request(std::move(req_lower_custom));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "Lowercase Custom Scheme";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, test_user_custom.id);

    // 2.2: "MYAPPAUTH" (uppercase custom)
    _session->reset();
    auto req_upper_custom = create_request();
    std::string upper_custom_scheme = custom_scheme_val;
    std::transform(upper_custom_scheme.begin(), upper_custom_scheme.end(), upper_custom_scheme.begin(), ::toupper);
    req_upper_custom.set_header(header_name_custom, upper_custom_scheme + " " + token_custom);
    make_request(std::move(req_upper_custom));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "Uppercase Custom Scheme";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());

    // 2.3: Wrong scheme (should fail, ensuring case insensitivity is not overly permissive)
    _session->reset();
    auto req_wrong_scheme = create_request();
    req_wrong_scheme.set_header(header_name_custom, "Bearer " + token_custom); // Using default Bearer
    make_request(std::move(req_wrong_scheme));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED) << "Wrong scheme for custom token";
    EXPECT_FALSE(_session->_final_handler_called);
}

TEST_F(AuthMiddlewareTest, OptionalAuthWithInvalidToken) {
    // Configure middleware for optional authentication
    auto optional_auth_mw = qb::http::create_optional_auth_middleware<MockAuthSession>(_auth_options);
    // Use default roles (none specified), default user context key ("user")
    configure_router_with_auth_mw(optional_auth_mw);

    // Scenario 1: Malformed token
    _session->reset();
    auto req_malformed = create_request();
    req_malformed.set_header(_auth_options.get_auth_header_name(), _auth_options.get_auth_scheme() + " this_is_not_a_valid_jwt");
    make_request(std::move(req_malformed));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "Malformed token with optional auth";
    EXPECT_TRUE(_session->_final_handler_called) << "Handler should be called with malformed token and optional auth";
    EXPECT_FALSE(_session->_user_in_context.has_value()) << "User should not be in context with malformed token";

    // Scenario 2: Expired token (but auth is optional)
    _session->reset();
    qb::http::auth::Options expiring_opts = _auth_options;
    expiring_opts.token_expiration(std::chrono::seconds(-3600)); // Expired 1 hour ago
    expiring_opts.verify_expiration(true); // Make sure exp is checked by generator/verifier logic
    
    // Temporarily use a manager with these options to create an expired token.
    // The optional_auth_mw itself uses the default _auth_options for verification, 
    // so it will see the token as expired if verify_expiration is on (which it is by default in Options).
    qb::http::auth::Manager temp_manager_for_expired_token(expiring_opts);
    qb::http::auth::User test_user_exp{"user_exp_opt", "expopter", {"user"}};
    std::string expired_token = temp_manager_for_expired_token.generate_token(test_user_exp);

    auto req_expired = create_request();
    req_expired.set_header(_auth_options.get_auth_header_name(), 
                           _auth_options.get_auth_scheme() + " " + expired_token);
    make_request(std::move(req_expired));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "Expired token with optional auth";
    EXPECT_TRUE(_session->_final_handler_called) << "Handler should be called with expired token and optional auth";
    EXPECT_FALSE(_session->_user_in_context.has_value()) << "User should not be in context with expired token";

    // Scenario 3: Token with wrong signature (but auth is optional)
    _session->reset();
    qb::http::auth::User test_user_sig{"user_sig_opt", "sigopter", {"user"}};
    // Generate with default secret, but middleware (optional_auth_mw) will verify with a different one if we changed its options.
    // For this test, we assume optional_auth_mw uses _auth_options which has _test_secret.
    // So, to make the signature wrong, we generate a token with a *different* secret.
    std::string token_wrong_sig = generate_test_token(test_user_sig, "a_completely_different_secret_key_!@#");

    auto req_wrong_sig = create_request();
    req_wrong_sig.set_header(_auth_options.get_auth_header_name(), 
                             _auth_options.get_auth_scheme() + " " + token_wrong_sig);
    make_request(std::move(req_wrong_sig));

    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) << "Wrong signature token with optional auth";
    EXPECT_TRUE(_session->_final_handler_called) << "Handler should be called with wrong signature and optional auth";
    EXPECT_FALSE(_session->_user_in_context.has_value()) << "User should not be in context with wrong signature token";
}

TEST_F(AuthMiddlewareTest, TokenAndSchemeWhitespaceTolerance) {
    _auth_mw->with_auth_required(true);
    // Using default "Bearer" scheme from _auth_options
    configure_router_with_auth_mw(_auth_mw);

    qb::http::auth::User test_user{"user_ws", "whitespacer", {"user"}};
    std::string token = generate_test_token(test_user);
    const std::string header_name = _auth_options.get_auth_header_name();
    const std::string scheme = _auth_options.get_auth_scheme(); // Should be "Bearer"

    // Scenario 1: Extra space(s) between scheme and token
    _session->reset();
    auto req_extra_space_after = create_request();
    req_extra_space_after.set_header(header_name, scheme + "   " + token); // 3 spaces
    make_request(std::move(req_extra_space_after));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) 
        << "Extra spaces between scheme and token should be accepted.";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());
    EXPECT_EQ(_session->_user_in_context->id, test_user.id);

    // Scenario 2: Leading whitespace before the scheme (Authorization header value starts with spaces)
    // Note: HTTP header parsing by underlying libraries might trim this before it even reaches the middleware.
    // If this fails, it might be due to the HTTP parser, not necessarily the auth middleware's logic.
    _session->reset();
    auto req_leading_space = create_request();
    req_leading_space.set_header(header_name, "  " + scheme + " " + token); // 2 leading spaces
    make_request(std::move(req_leading_space));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) 
        << "Leading spaces before scheme should ideally be accepted or trimmed by HTTP parser.";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());

    // Scenario 3: Trailing whitespace after token
    // Similar to leading whitespace, this might be handled by general HTTP header trimming.
    _session->reset();
    auto req_trailing_space = create_request();
    req_trailing_space.set_header(header_name, scheme + " " + token + "  "); // 2 trailing spaces
    make_request(std::move(req_trailing_space));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_OK) 
        << "Trailing spaces after token should ideally be accepted or trimmed.";
    EXPECT_TRUE(_session->_final_handler_called);
    ASSERT_TRUE(_session->_user_in_context.has_value());

    // Scenario 4: No space between scheme and token (SHOULD FAIL - invalid format)
    _session->reset();
    auto req_no_space = create_request();
    req_no_space.set_header(header_name, scheme + token); // No space
    make_request(std::move(req_no_space));
    EXPECT_EQ(_session->_response.status_code, qb::http::status::HTTP_STATUS_UNAUTHORIZED) 
        << "No space between scheme and token should be rejected.";
    EXPECT_FALSE(_session->_final_handler_called);
}

//  (CustomErrorHandler might be tricky as the old API differs from new error chain) 
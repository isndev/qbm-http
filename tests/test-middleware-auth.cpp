#include <gtest/gtest.h>
#include <thread>
#include <filesystem>
#include <fstream>
#include "../auth/auth.h"
#include "../middleware/auth.h"
#include "../routing/router.h"
#include "../routing/router.tpp"

// Forward declarations for helper functions 
std::string readFileContents(const std::string &filename);
void writeFileContents(const std::string &filename, const std::string &content);
void generateTestKeys(const std::string &keys_path);

// Mock session for testing
class MockSession {
public:
    bool is_closed = false;
    qb::http::Response last_response;

    MockSession() = default;

    bool is_connected() const {
        return !is_closed;
    }

    void close() {
        is_closed = true;
    }

    MockSession& operator<<(qb::http::Response res) {
        last_response = std::move(res);
        return *this;
    }
};

// Test fixture for auth middleware tests
class AuthMiddlewareTest : public ::testing::Test {
protected:
    std::string keys_path;
    qb::http::auth::Options auth_options;
    qb::http::auth::User test_user;
    std::string token;
    bool done_callbacks_executed = false;

    void SetUp() override {
        // Setup test keys
        keys_path = "/tmp/qb_auth_test_keys";
        generateTestKeys(keys_path);

        // Setup auth options with HMAC algorithm for simplicity
        auth_options.algorithm(qb::http::auth::Options::Algorithm::HMAC_SHA256);
        auth_options.secret_key("test-secret-key");

        // Create auth manager to generate tokens for testing
        qb::http::auth::Manager auth_manager(auth_options);

        // Create test user
        test_user.id = "user123";
        test_user.username = "testuser";
        test_user.roles = {"user", "editor"};
        test_user.metadata["email"] = "testuser@example.com";

        // Generate token
        token = auth_manager.generate_token(test_user);
    }

    void TearDown() override {
        // Optional: Clean up test keys
        // std::filesystem::remove_all(keys_path);
    }

    // Helper to create a context with authentication headers
    qb::http::RouterContext<MockSession> createContext(const std::string& auth_header = "") {
        auto session = std::make_shared<MockSession>();
        qb::http::Request req;
        
        if (!auth_header.empty()) {
            req.headers()["Authorization"].push_back(auth_header);
        }
        
        qb::http::Router<MockSession> router;
        return qb::http::RouterContext<MockSession>(session, std::move(req), &router);
    }
    
    // Helper to execute done callbacks
    void execute_done_callbacks(qb::http::RouterContext<MockSession>& ctx) {
        done_callbacks_executed = true;
        ctx.execute_after_callbacks();
    }
};

// Test authentication middleware with valid token
TEST_F(AuthMiddlewareTest, ValidTokenAuthentication) {
    // Create middleware with auth options
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    
    // Create context with valid token
    auto ctx = createContext("Bearer " + token);
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_continue());
    EXPECT_FALSE(result.should_stop());
    EXPECT_TRUE(ctx.has("user"));
    
    // Verify that user data was properly set in context
    const auto& user = ctx.get<qb::http::auth::User>("user");
    EXPECT_EQ(user.id, test_user.id);
    EXPECT_EQ(user.username, test_user.username);
    EXPECT_EQ(user.roles.size(), test_user.roles.size());
}

// Test authentication middleware with missing token
TEST_F(AuthMiddlewareTest, MissingToken) {
    // Create middleware with auth options
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    
    // Create context without authorization header
    auto ctx = createContext();
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_stop());
    EXPECT_FALSE(result.should_continue());
    EXPECT_EQ(ctx.response.status_code, HTTP_STATUS_UNAUTHORIZED);
    EXPECT_FALSE(ctx.has("user"));
}

// Test authentication middleware with invalid token
TEST_F(AuthMiddlewareTest, InvalidToken) {
    // Create middleware with auth options
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    
    // Create context with invalid token
    auto ctx = createContext("Bearer invalid.token.here");
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_stop());
    EXPECT_FALSE(result.should_continue());
    EXPECT_EQ(ctx.response.status_code, HTTP_STATUS_UNAUTHORIZED);
    EXPECT_FALSE(ctx.has("user"));
}

// Test authorization middleware with valid roles
TEST_F(AuthMiddlewareTest, ValidRoleAuthorization) {
    // Create middleware with auth options and required role
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    middleware.with_roles({"editor"});
    
    // Create context with valid token
    auto ctx = createContext("Bearer " + token);
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_continue());
    EXPECT_FALSE(result.should_stop());
    EXPECT_TRUE(ctx.has("user"));
    EXPECT_NE(ctx.response.status_code, HTTP_STATUS_FORBIDDEN);
}

// Test authorization middleware with invalid roles
TEST_F(AuthMiddlewareTest, InvalidRoleAuthorization) {
    // Create middleware with auth options and required role
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    middleware.with_roles({"admin"});
    
    // Create context with valid token but insufficient roles
    auto ctx = createContext("Bearer " + token);
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_stop());
    EXPECT_FALSE(result.should_continue());
    EXPECT_EQ(ctx.response.status_code, HTTP_STATUS_FORBIDDEN);
}

// Test authorization middleware requiring all roles
TEST_F(AuthMiddlewareTest, RequireAllRoles) {
    // Test when user has all required roles
    {
        auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
        middleware.with_roles({"user", "editor"}, true); // require_all = true
        
        auto ctx = createContext("Bearer " + token);
        auto result = middleware.process(ctx);
        
        EXPECT_TRUE(result.should_continue());
        EXPECT_FALSE(result.should_stop());
        EXPECT_TRUE(ctx.has("user"));
    }
    
    // Test when user doesn't have all required roles
    {
        auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
        middleware.with_roles({"user", "admin"}, true); // require_all = true
        
        auto ctx = createContext("Bearer " + token);
        auto result = middleware.process(ctx);
        
        EXPECT_TRUE(result.should_stop());
        EXPECT_FALSE(result.should_continue());
        EXPECT_EQ(ctx.response.status_code, HTTP_STATUS_FORBIDDEN);
    }
}

// Test custom user context key
TEST_F(AuthMiddlewareTest, CustomUserContextKey) {
    // Create middleware with custom user context key
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    middleware.with_user_context_key("custom_user");
    
    // Create context with valid token
    auto ctx = createContext("Bearer " + token);
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_continue());
    EXPECT_FALSE(result.should_stop());
    EXPECT_FALSE(ctx.has("user")); // Default key not used
    EXPECT_TRUE(ctx.has("custom_user")); // Custom key used instead
    
    const auto& user = ctx.get<qb::http::auth::User>("custom_user");
    EXPECT_EQ(user.id, test_user.id);
}

// Test token expiration within middleware
TEST_F(AuthMiddlewareTest, ExpiredTokenMiddleware) {
    // Create options with short expiration
    qb::http::auth::Options options_expired = auth_options;
    options_expired.token_expiration(std::chrono::seconds(1));
    
    // Create auth manager with short expiration options
    qb::http::auth::Manager expired_manager(options_expired);
    std::string expired_token = expired_manager.generate_token(test_user);
    
    // Wait for the token to expire
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Create middleware with original auth options
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    
    // Create context with expired token
    auto ctx = createContext("Bearer " + expired_token);
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_stop());
    EXPECT_FALSE(result.should_continue());
    EXPECT_EQ(ctx.response.status_code, HTTP_STATUS_UNAUTHORIZED);
    EXPECT_FALSE(ctx.has("user"));
}

// Test token not yet valid (nbf claim) within middleware
TEST_F(AuthMiddlewareTest, NotYetValidTokenMiddleware) {
    // Create options and generate a token with nbf in the future
    qb::json payload = {
        {"sub", test_user.id},
        {"username", test_user.username},
        {"roles", test_user.roles},
        {"iat", std::time(nullptr)},
        {"nbf", std::time(nullptr) + 3600} // Not valid for 1 hour
    };
    
    qb::jwt::CreateOptions jwt_options;
    jwt_options.algorithm = qb::jwt::Algorithm::HS256;
    jwt_options.key = "test-secret-key";
    
    std::map<std::string, std::string> claims_map;
    for (auto it = payload.begin(); it != payload.end(); ++it) {
        if (it.value().is_string()) {
            claims_map[it.key()] = it.value().get<std::string>();
        } else {
            claims_map[it.key()] = it.value().dump();
        }
    }
    
    std::string nbf_token = qb::jwt::create(claims_map, jwt_options);
    
    // Create middleware with auth options
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    
    // Create context with future token
    auto ctx = createContext("Bearer " + nbf_token);
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_stop());
    EXPECT_FALSE(result.should_continue());
    EXPECT_EQ(ctx.response.status_code, HTTP_STATUS_UNAUTHORIZED);
    EXPECT_FALSE(ctx.has("user"));
}

// Test with RSA Algorithm
TEST_F(AuthMiddlewareTest, DISABLED_RSAAlgorithm) {
    std::string rsa_private_key, rsa_public_key;
    try {
        rsa_private_key = readFileContents(keys_path + "/rsa_private.pem");
        rsa_public_key = readFileContents(keys_path + "/rsa_public.pem");
    } catch (const std::exception& e) {
        GTEST_SKIP() << "Skipping RSA test due to missing key files: " << e.what();
    }

    // Create RSA auth options
    qb::http::auth::Options rsa_options;
    rsa_options.algorithm(qb::http::auth::Options::Algorithm::RSA_SHA256);
    rsa_options.private_key(rsa_private_key);
    rsa_options.public_key(rsa_public_key);
    
    // Create auth manager with RSA options
    qb::http::auth::Manager rsa_manager(rsa_options);
    std::string rsa_token = rsa_manager.generate_token(test_user);
    
    // Create middleware with RSA options
    auto middleware = qb::http::AuthMiddleware<MockSession>(rsa_options);
    
    // Create context with RSA token
    auto ctx = createContext("Bearer " + rsa_token);
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_continue());
    EXPECT_FALSE(result.should_stop());
    EXPECT_TRUE(ctx.has("user"));
    
    const auto& user = ctx.get<qb::http::auth::User>("user");
    EXPECT_EQ(user.id, test_user.id);
    
    // Test verification failure with wrong public key
    qb::http::auth::Options wrong_key_options = rsa_options;
    wrong_key_options.public_key("-----BEGIN PUBLIC KEY-----\n...invalid key...\n-----END PUBLIC KEY-----");
    
    auto wrong_key_middleware = qb::http::AuthMiddleware<MockSession>(wrong_key_options);
    auto ctx_fail = createContext("Bearer " + rsa_token);
    auto result_fail = wrong_key_middleware.process(ctx_fail);
    
    EXPECT_TRUE(result_fail.should_stop());
    EXPECT_FALSE(result_fail.should_continue());
    EXPECT_EQ(ctx_fail.response.status_code, HTTP_STATUS_UNAUTHORIZED);
}

// Test Custom Authentication Scheme
TEST_F(AuthMiddlewareTest, CustomAuthScheme) {
    // Create options with custom auth scheme
    qb::http::auth::Options custom_scheme_options = auth_options;
    custom_scheme_options.auth_scheme("JWT"); // Use JWT instead of Bearer
    
    // Create auth manager with custom scheme
    qb::http::auth::Manager custom_manager(custom_scheme_options);
    std::string custom_token = custom_manager.generate_token(test_user);
    
    // Create middleware with custom scheme options
    auto middleware = qb::http::AuthMiddleware<MockSession>(custom_scheme_options);

    // Test with correct custom scheme
    auto ctx_correct = createContext("JWT " + custom_token); // Note: JWT scheme used
    auto result_correct = middleware.process(ctx_correct);
    
    EXPECT_TRUE(result_correct.should_continue());
    EXPECT_FALSE(result_correct.should_stop());
    EXPECT_TRUE(ctx_correct.has("user"));

    // Test with default Bearer scheme (should fail)
    auto ctx_wrong_scheme = createContext("Bearer " + custom_token);
    auto result_wrong_scheme = middleware.process(ctx_wrong_scheme);
    
    EXPECT_TRUE(result_wrong_scheme.should_stop());
    EXPECT_FALSE(result_wrong_scheme.should_continue());
    EXPECT_EQ(ctx_wrong_scheme.response.status_code, HTTP_STATUS_UNAUTHORIZED);
}

// Test Authorization with Empty Roles
TEST_F(AuthMiddlewareTest, AuthorizationEmptyRoles) {
    // Create a user with no roles
    qb::http::auth::User user_no_roles;
    user_no_roles.id = "user_no_roles";
    user_no_roles.username = "norolesuser";
    
    // Generate token for user with no roles
    qb::http::auth::Manager auth_manager(auth_options);
    std::string token_no_roles = auth_manager.generate_token(user_no_roles);
    
    // Test with empty required roles (should succeed)
    {
        auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
        // No roles specified (empty by default)
        
        auto ctx = createContext("Bearer " + token_no_roles);
        auto result = middleware.process(ctx);
        
        EXPECT_TRUE(result.should_continue());
        EXPECT_FALSE(result.should_stop());
        EXPECT_TRUE(ctx.has("user"));
    }
    
    // Test with non-empty required roles (should fail)
    {
        auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
        middleware.with_roles({"admin"});
        
        auto ctx = createContext("Bearer " + token_no_roles);
        auto result = middleware.process(ctx);
        
        EXPECT_TRUE(result.should_stop());
        EXPECT_FALSE(result.should_continue());
        EXPECT_EQ(ctx.response.status_code, HTTP_STATUS_FORBIDDEN);
    }
    
    // Test with user WITH roles against an empty required list (should succeed)
    {
        auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
        // No roles specified (empty by default)
        
        auto ctx = createContext("Bearer " + token); // Use original user with roles
        auto result = middleware.process(ctx);
        
        EXPECT_TRUE(result.should_continue());
        EXPECT_FALSE(result.should_stop());
        EXPECT_TRUE(ctx.has("user"));
    }
}

// Test Clock Skew Tolerance
TEST_F(AuthMiddlewareTest, ClockSkewTolerance) {
    // 1. Test expiration with positive skew
    {
        // Token expired 10 seconds ago
        qb::json payload_exp = {
            {"sub", test_user.id},
            {"iat", std::time(nullptr) - 60},
            {"exp", std::time(nullptr) - 10} 
        };
        
        qb::jwt::CreateOptions jwt_options_exp;
        jwt_options_exp.algorithm = qb::jwt::Algorithm::HS256;
        jwt_options_exp.key = "test-secret-key";
        
        std::map<std::string, std::string> claims_map_exp;
        for (auto it = payload_exp.begin(); it != payload_exp.end(); ++it) {
             claims_map_exp[it.key()] = it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
        }
        
        std::string expired_token = qb::jwt::create(claims_map_exp, jwt_options_exp);

        // Configure middleware with 30 seconds tolerance
        qb::http::auth::Options options_skew = auth_options;
        options_skew.clock_skew_tolerance(std::chrono::seconds(30));
        
        auto middleware_skew = qb::http::AuthMiddleware<MockSession>(options_skew);
        auto ctx_skew = createContext("Bearer " + expired_token);
        auto result_skew = middleware_skew.process(ctx_skew);
        
        EXPECT_TRUE(result_skew.should_continue()) << "Token expired recently should be accepted with tolerance";
        EXPECT_FALSE(result_skew.should_stop());
        EXPECT_TRUE(ctx_skew.has("user"));
    }
    
    // 2. Test not-before (nbf) with positive skew
    {
        // Token not valid for another 10 seconds
        qb::json payload_nbf = {
            {"sub", test_user.id},
            {"iat", std::time(nullptr)},
            {"nbf", std::time(nullptr) + 10} 
        };
        
        qb::jwt::CreateOptions jwt_options_nbf;
        jwt_options_nbf.algorithm = qb::jwt::Algorithm::HS256;
        jwt_options_nbf.key = "test-secret-key";
        
        std::map<std::string, std::string> claims_map_nbf;
        for (auto it = payload_nbf.begin(); it != payload_nbf.end(); ++it) {
             claims_map_nbf[it.key()] = it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
        }
        
        std::string nbf_token = qb::jwt::create(claims_map_nbf, jwt_options_nbf);

        // Configure middleware with 30 seconds tolerance
        qb::http::auth::Options options_skew = auth_options;
        options_skew.clock_skew_tolerance(std::chrono::seconds(30));
        
        auto middleware_skew = qb::http::AuthMiddleware<MockSession>(options_skew);
        auto ctx_skew_nbf = createContext("Bearer " + nbf_token);
        auto result_skew_nbf = middleware_skew.process(ctx_skew_nbf);
        
        EXPECT_TRUE(result_skew_nbf.should_continue()) << "Token not yet valid should be accepted with tolerance";
        EXPECT_FALSE(result_skew_nbf.should_stop());
        EXPECT_TRUE(ctx_skew_nbf.has("user"));
    }
}

// Test Issuer/Audience Verification Flexibility
TEST_F(AuthMiddlewareTest, IssuerAudienceFlexibility) {
    // Case 1: Token has iss/aud, middleware doesn't verify
    {
        qb::json payload_with = {
            {"sub", test_user.id},
            {"iss", "my-issuer"},
            {"aud", "my-audience"}
        };
        
        qb::jwt::CreateOptions jwt_options_with;
        jwt_options_with.algorithm = qb::jwt::Algorithm::HS256;
        jwt_options_with.key = "test-secret-key";
        
        std::map<std::string, std::string> claims_map_with;
        for (auto it = payload_with.begin(); it != payload_with.end(); ++it) {
             claims_map_with[it.key()] = it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
        }
        
        std::string token_with = qb::jwt::create(claims_map_with, jwt_options_with);

        // Middleware with default options (no verification)
        auto middleware_no_verify = qb::http::AuthMiddleware<MockSession>(auth_options);
        auto ctx_no_verify = createContext("Bearer " + token_with);
        auto result_no_verify = middleware_no_verify.process(ctx_no_verify);
        
        EXPECT_TRUE(result_no_verify.should_continue()) << "Should pass when iss/aud present but not verified";
        EXPECT_FALSE(result_no_verify.should_stop());
        EXPECT_TRUE(ctx_no_verify.has("user"));
    }

    // Case 2: Middleware verifies iss/aud, token doesn't have them
    {
        qb::json payload_without = { {"sub", test_user.id} };
        
        qb::jwt::CreateOptions jwt_options_without;
        jwt_options_without.algorithm = qb::jwt::Algorithm::HS256;
        jwt_options_without.key = "test-secret-key";
        
        std::map<std::string, std::string> claims_map_without;
         for (auto it = payload_without.begin(); it != payload_without.end(); ++it) {
             claims_map_without[it.key()] = it.value().is_string() ? it.value().get<std::string>() : it.value().dump();
        }
        
        std::string token_without = qb::jwt::create(claims_map_without, jwt_options_without);

        // Middleware configured to verify
        qb::http::auth::Options options_verify = auth_options;
        options_verify.token_issuer("my-issuer"); // Enables issuer verification
        options_verify.token_audience("my-audience"); // Enables audience verification
        
        auto middleware_verify = qb::http::AuthMiddleware<MockSession>(options_verify);
        auto ctx_verify = createContext("Bearer " + token_without);
        auto result_verify = middleware_verify.process(ctx_verify);
        
        EXPECT_TRUE(result_verify.should_stop()) << "Should fail when iss/aud missing but verification enabled";
        EXPECT_FALSE(result_verify.should_continue());
        EXPECT_EQ(ctx_verify.response.status_code, HTTP_STATUS_UNAUTHORIZED);
        EXPECT_FALSE(ctx_verify.has("user"));
    }
}

// Test Authorization with require_all=false (explicitly)
TEST_F(AuthMiddlewareTest, AuthorizeRequireAnyRole) {
    // Create middleware with roles (at least one required)
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    middleware.with_roles({"editor", "admin"}, false); // require_all = false
    
    // Create context with valid token (user has "editor" role)
    auto ctx = createContext("Bearer " + token);
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_continue()) << "User should be authorized having one of the required roles";
    EXPECT_FALSE(result.should_stop());
    EXPECT_TRUE(ctx.has("user"));
    EXPECT_NE(ctx.response.status_code, HTTP_STATUS_FORBIDDEN);

    // Try with roles the user doesn't have
    auto middleware_fail = qb::http::AuthMiddleware<MockSession>(auth_options);
    middleware_fail.with_roles({"manager", "admin"}, false);
    
    auto ctx_fail = createContext("Bearer " + token);
    auto result_fail = middleware_fail.process(ctx_fail);
    
    EXPECT_TRUE(result_fail.should_stop()) << "User should not be authorized without any required roles";
    EXPECT_FALSE(result_fail.should_continue());
    EXPECT_EQ(ctx_fail.response.status_code, HTTP_STATUS_FORBIDDEN);
}

// Test Case-Insensitive Header Name
TEST_F(AuthMiddlewareTest, CaseInsensitiveHeader) {
    // Create middleware with auth options
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    
    // Create context with lowercase header name
    auto session_ci = std::make_shared<MockSession>();
    qb::http::Request req_ci;
    req_ci.headers()["authorization"].push_back("Bearer " + token); // Lowercase header
    qb::http::Router<MockSession> router_ci;
    auto ctx_ci = qb::http::RouterContext<MockSession>(session_ci, std::move(req_ci), &router_ci);
    
    // Process request through middleware
    auto result = middleware.process(ctx_ci);
    
    // The test should pass if the middleware handles case-insensitivity correctly
    EXPECT_TRUE(result.should_continue()) << "Authentication should succeed if header lookup is case-insensitive";
    EXPECT_FALSE(result.should_stop());
    EXPECT_TRUE(ctx_ci.has("user"));
}

// Test Multiple Authorization Headers
TEST_F(AuthMiddlewareTest, MultipleAuthHeaders) {
    // Create middleware with auth options
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    
    // Create context with multiple auth headers
    auto session_multi = std::make_shared<MockSession>();
    qb::http::Request req_multi;
    
    // Add the valid header first
    req_multi.headers()["Authorization"].push_back("Bearer " + token);
    // Add another invalid/dummy header with the same key
    req_multi.headers()["Authorization"].push_back("Bearer invalid-token"); 
    
    qb::http::Router<MockSession> router_multi;
    auto ctx_multi = qb::http::RouterContext<MockSession>(session_multi, std::move(req_multi), &router_multi);
    
    // Process request through middleware
    auto result = middleware.process(ctx_multi);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_continue()) << "Middleware should use the first valid Authorization header found";
    EXPECT_FALSE(result.should_stop());
    EXPECT_TRUE(ctx_multi.has("user"));
    
    const auto& user = ctx_multi.get<qb::http::auth::User>("user");
    EXPECT_EQ(user.id, test_user.id);
}

// Test Empty Secret Key Handling
TEST_F(AuthMiddlewareTest, EmptySecretKey) {
    // Create options with empty secret key
    qb::http::auth::Options empty_secret_options;
    empty_secret_options.algorithm(qb::http::auth::Options::Algorithm::HMAC_SHA256);
    empty_secret_options.secret_key(""); // Empty secret

    // Create middleware with empty secret
    auto middleware = qb::http::AuthMiddleware<MockSession>(empty_secret_options);
    
    // Create context with dummy token
    auto ctx = createContext("Bearer some-token"); 
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_stop()) << "Authenticate should fail when configured with an empty secret for HMAC";
    EXPECT_FALSE(result.should_continue());
    EXPECT_EQ(ctx.response.status_code, HTTP_STATUS_UNAUTHORIZED);
    EXPECT_FALSE(ctx.has("user"));
}

// Test Custom Error Handler
TEST_F(AuthMiddlewareTest, CustomErrorHandler) {
    // Create middleware with custom error handler
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    middleware.with_error_handler([](auto& ctx, int status_code, const std::string& message) {
        // Custom error response
        ctx.response.status_code = HTTP_STATUS_PAYMENT_REQUIRED; // Different status code
        ctx.response.add_header("Content-Type", "application/json");
        ctx.response.body() = "{\"custom_error\":\"" + message + "\"}";
        return qb::http::MiddlewareResult::Stop();
    });
    
    // Create context without auth header
    auto ctx = createContext();
    
    // Process request through middleware
    auto result = middleware.process(ctx);
    
    // Check middleware result and context state
    EXPECT_TRUE(result.should_stop());
    EXPECT_FALSE(result.should_continue());
    EXPECT_EQ(ctx.response.status_code, HTTP_STATUS_PAYMENT_REQUIRED); // Custom status code
    EXPECT_EQ(ctx.response.header("Content-Type"), "application/json");
    EXPECT_FALSE(ctx.has("user"));
}

// Test Optional Authentication
TEST_F(AuthMiddlewareTest, OptionalAuthentication) {
    // Create middleware with optional authentication
    auto middleware = qb::http::AuthMiddleware<MockSession>(auth_options);
    middleware.with_auth_required(false);
    
    // Test with no token (should pass)
    {
        auto ctx = createContext(); // No auth header
        auto result = middleware.process(ctx);
        
        EXPECT_TRUE(result.should_continue()) << "Should continue when auth is optional and no token provided";
        EXPECT_FALSE(result.should_stop());
        EXPECT_FALSE(ctx.has("user"));
    }
    
    // Test with valid token (should pass and set user)
    {
        auto ctx = createContext("Bearer " + token);
        auto result = middleware.process(ctx);
        
        EXPECT_TRUE(result.should_continue()) << "Should continue when auth is optional and valid token provided";
        EXPECT_FALSE(result.should_stop());
        EXPECT_TRUE(ctx.has("user"));
    }
    
    // Test with invalid token (should pass but not set user)
    {
        auto ctx = createContext("Bearer invalid-token");
        auto result = middleware.process(ctx);
        
        EXPECT_TRUE(result.should_continue()) << "Should continue when auth is optional and invalid token provided";
        EXPECT_FALSE(result.should_stop());
        EXPECT_FALSE(ctx.has("user"));
    }
}

// Helper function to read file contents
std::string readFileContents(const std::string &filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filename);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Helper function to write file contents
void writeFileContents(const std::string &filename, const std::string &content) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file for writing: " + filename);
    }
    file << content;
}

// Helper function to generate test keys
void generateTestKeys(const std::string &keys_path) {
    namespace fs = std::filesystem;
    
    // Create directory if it doesn't exist
    fs::create_directories(keys_path);
    
    // Sample RSA keys (for testing only, not for production use)
    std::string rsa_private_key = 
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n"
        "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n"
        "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n"
        "agucPD/rGxUhxhpQpj2tRIBN1r6K/4Rw6h22BfAKSlCxdpQs8AkzYX/7BDgtN3Bd\n"
        "E+FzYpSgKYpoa4tWvMhVe1+iAPHv/unvlNzxJBhLuPzopUyOU8lmFuYJkXpvC8T/\n"
        "3FHe+Vsm5kwGYfDYpPgW8sHON5aktYmyABEXZkdE5jAFVJMeGvNrBdmRvP3XJG/j\n"
        "b2PQdB+vAgMBAAECggEACB/kRV5eXZm3imDQBZQxOxkGBL7ME2cvQ/JGtMQDB9W4\n"
        "CjmhdqA1BxL9crTrBBbDMHRbGqEa216UfNGTXZpS2eZ8zRxdKCXn+f2y+q7hznXs\n"
        "eE9qqBh+AZYbY3rnn9JxYdZ7vXfuQn/NUi/3NAFZkp7CyvwNxvFJGbHXBeNzUiFq\n"
        "Ag84CWlhP8j3HwAykJELEL8TZULHW9OVblChs32JVQEee5h4+6jW4k5hPgEWAYB7\n"
        "qPGfT8wJPyQYXYjxZ5vY0wISGz/aj5c7dFYHqwn0aKHeBGhzR/iO4SvLy7YYkAG4\n"
        "WeBHG1MGLm9z2s2oCL8yX2//BxZrGt3RdvZ4hZD7YQKBgQDeRbWkQ6wM1owO3Cn0\n"
        "6Lfq825xwA6ScyAJ2U7sLWQ+yzZXUBB8HbpTBLvQJVhUBuS5GbPIZGwGzK8ZGzPC\n"
        "jYQEwbJxNwIfz3gYwD4UNFjbLTKpl8Egw/bNHUlCUDw8++LTcsFxvOoEew0sdTcu\n"
        "i+6ZWXVCXf6R7FG3REFsBPQ9JQKBgQDYZlNuTnDPODuLjnXh2yCCmw7B0IgVQdnK\n"
        "iRaDxjX9vGKFkO7Q9i4DxQQo9yByfTP5U7D7hVr9i7285sB5QPvrVs4K3a/w06Ye\n"
        "paIjLz1CuHwfLLfg2jxHnPpOkx3AQttiBMcS3K+oAEBMZjk7qUjEZJwUNs0/KCVC\n"
        "zsIVELUJ0wKBgQCXTlPGABE9MJCh5g0kEkWzMQHY5BrjgrdNY0qBQiC2r9Qd7xGg\n"
        "1ZBCj0qAqRYwXBXGDGjB+WqkizOBJVxs3Sbp3e7YZwcw/xH9r5wXJFYmhuVB/JcI\n"
        "zPIJaSCuaZajKe5FfQWTvZ/mXKQUGCnAL6YBCAY9Av9yv0LP0Zn8f9IBuQKBgAMr\n"
        "A4WQH/cV/s7DNbjFRVK4SnvuiDrfECVq4JLq9c8499ickGCJMOb6ymgVGY5Za2oC\n"
        "qIdy2ZJA2f0XpkU5yrFDYTUvHRZd+X99Y68bKQCwqNmF8UfzR28cRmP6J1rHYYq3\n"
        "vEezfJ1ZLGNmGKRwpqRExkCRQkUEgFHOJR0OW5/NAoGAO3ReOIoaCqB8u11Vt+6T\n"
        "dpR9MJG+5KVicXsDATNPiuMSmGcP0QgIKFKJviMo3M1jQoB6UqXCgRLjCiMuKnKJ\n"
        "KEyKD36/Zb7sf4rj/wpkBNLpbYXRrwmtLVBBQk6I5YPkis4thWGCEHjbeBZcGIPD\n"
        "f2FoXNBU9vvYUZHzh+aXPfU=\n"
        "-----END PRIVATE KEY-----\n";

    std::string rsa_public_key = 
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo\n"
        "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n"
        "+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWWoLnDw/\n"
        "6xsVIcYaUKY9rUSATda+iv+EcOodtgXwCkpQsXaULPAJM2F/+wQ4LTdwXRPhc2KU\n"
        "oCmKaGuLVrzIVXtfogDx7/7p75Tc8SQYS7j86KVMjlPJZhbmCZF6bwvE/9xR3vlb\n"
        "JuZMBmHw2KT4FvLBzjeWpLWJsgARF2ZHROYwBVSTHhrzawXZkbz91yRv429j0HQf\n"
        "rwIDAQAB\n"
        "-----END PUBLIC KEY-----\n";
    
    // Write the keys to files
    writeFileContents(keys_path + "/rsa_private.pem", rsa_private_key);
    writeFileContents(keys_path + "/rsa_public.pem", rsa_public_key);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
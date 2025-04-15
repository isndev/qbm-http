
#include <fstream>
#include <gtest/gtest.h>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "../auth.h"

using namespace qb::http;

// Helper functions for base64 encoding/decoding
std::string
base64_decode_str(const std::string &input) {
    auto decoded = qb::crypto::base64_decode(input);
    return {decoded.begin(), decoded.end()};
}

std::string
base64_encode_str(const std::string &input) {
    std::vector<unsigned char> data(input.begin(), input.end());
    return qb::crypto::base64_encode(data.data(), data.size());
}

// Helper function for base64url encoding/decoding
std::string
base64url_decode(const std::string &input) {
    // Convert from base64url to base64
    std::string base64 = input;
    std::replace(base64.begin(), base64.end(), '-', '+');
    std::replace(base64.begin(), base64.end(), '_', '/');

    // Add padding if needed
    while (base64.length() % 4 != 0) {
        base64 += '=';
    }

    return base64_decode_str(base64);
}

std::string
base64url_encode(const std::string &input) {
    // Encode to base64
    std::string base64 = base64_encode_str(input);

    // Convert to base64url
    std::replace(base64.begin(), base64.end(), '+', '-');
    std::replace(base64.begin(), base64.end(), '/', '_');

    // Remove padding
    base64.erase(std::remove(base64.begin(), base64.end(), '='), base64.end());

    return base64;
}

// Helper function to split a string
std::vector<std::string>
split_string(const std::string &str, char delimiter) {
    std::vector<std::string> result;
    std::istringstream       stream(str);
    std::string              token;

    while (std::getline(stream, token, delimiter)) {
        result.push_back(token);
    }

    return result;
}

// Helper function to read file contents
std::string
readFileContents(const std::string &filename) {
    std::ifstream     file(filename);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Helper function to generate random strings
std::string
generateRandomString(size_t length) {
    static const char charset[] = "0123456789"
                                  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                  "abcdefghijklmnopqrstuvwxyz";

    std::random_device              rd;
    std::mt19937                    gen(rd());
    std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

    std::string result;
    result.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        result += charset[dist(gen)];
    }

    return result;
}

// Tests for AuthManager basic functionality
TEST(AuthManagerTest, BasicTokenFunctionality) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");
    options.token_expiration(std::chrono::seconds(3600)); // 1 hour

    AuthManager auth_manager(options);

    // Create test user
    AuthUser test_user;
    test_user.id                = "12345";
    test_user.username          = "test_user";
    test_user.roles             = {"user", "editor"};
    test_user.metadata["email"] = "test@example.com";

    // Generate token
    auto token = auth_manager.generate_token(test_user);

    // Verify token is not empty and contains a period (.)
    ASSERT_FALSE(token.empty());
    ASSERT_NE(token.find('.'), std::string::npos);
    ASSERT_GT(token.length(), 20); // Tokens should be reasonably long

    // Verify token and extract user info
    auto verify_result = auth_manager.verify_token(token);
    ASSERT_TRUE(verify_result.has_value());

    const auto &user = verify_result.value();
    EXPECT_EQ(user.id, "12345");
    EXPECT_EQ(user.username, "test_user");
    ASSERT_EQ(user.roles.size(), 2);
    EXPECT_EQ(user.roles[0], "user");
    EXPECT_EQ(user.roles[1], "editor");
    ASSERT_EQ(user.metadata.size(), 1);
    EXPECT_EQ(user.metadata.at("email"), "test@example.com");
}

// Test token verification with different algorithms
TEST(AuthManagerTest, DifferentAlgorithms) {
    // Test keys path - adjust this for your local setup
    std::string keys_path = "/Users/mbelhadi/Repos/qb-auth-project/temp_keys/";

    // Read the keys
    std::string rsa_private_key = readFileContents(keys_path + "rsa_private.pem");
    std::string rsa_public_key  = readFileContents(keys_path + "rsa_public.pem");
    std::string ec_private_key  = readFileContents(keys_path + "ec_private.pem");
    std::string ec_public_key   = readFileContents(keys_path + "ec_public.pem");
    std::string ed25519_private_key =
        readFileContents(keys_path + "ed25519_private.pem");
    std::string ed25519_public_key = readFileContents(keys_path + "ed25519_public.pem");

    // Create test user
    AuthUser test_user;
    test_user.id                = "12345";
    test_user.username          = "test_user";
    test_user.roles             = {"user", "editor"};
    test_user.metadata["email"] = "test@example.com";

    // Test with HMAC_SHA256
    {
        AuthOptions options;
        options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
        options.secret_key("your-256-bit-secret");
        options.token_expiration(std::chrono::seconds(3600));

        AuthManager auth_manager(options);
        auto        token         = auth_manager.generate_token(test_user);
        auto        verify_result = auth_manager.verify_token(token);

        ASSERT_TRUE(verify_result.has_value());
        EXPECT_EQ(verify_result.value().id, "12345");
    }

    // Test with RSA_SHA256
    {
        AuthOptions options;
        options.algorithm(AuthOptions::Algorithm::RSA_SHA256);
        options.private_key(rsa_private_key);
        options.public_key(rsa_public_key);
        options.token_expiration(std::chrono::seconds(3600));

        AuthManager auth_manager(options);
        auto        token         = auth_manager.generate_token(test_user);
        auto        verify_result = auth_manager.verify_token(token);

        ASSERT_TRUE(verify_result.has_value());
        EXPECT_EQ(verify_result.value().id, "12345");
    }

    // Test with ECDSA_SHA256
    {
        AuthOptions options;
        options.algorithm(AuthOptions::Algorithm::ECDSA_SHA256);
        options.private_key(ec_private_key);
        options.public_key(ec_public_key);
        options.token_expiration(std::chrono::seconds(3600));

        AuthManager auth_manager(options);
        auto        token         = auth_manager.generate_token(test_user);
        auto        verify_result = auth_manager.verify_token(token);

        ASSERT_TRUE(verify_result.has_value());
        EXPECT_EQ(verify_result.value().id, "12345");
    }

    // Test with ED25519
    {
        AuthOptions options;
        options.algorithm(AuthOptions::Algorithm::ED25519);
        options.private_key(ed25519_private_key);
        options.public_key(ed25519_public_key);
        options.token_expiration(std::chrono::seconds(3600));

        AuthManager auth_manager(options);
        auto        token         = auth_manager.generate_token(test_user);
        auto        verify_result = auth_manager.verify_token(token);

        ASSERT_TRUE(verify_result.has_value());
        EXPECT_EQ(verify_result.value().id, "12345");
    }
}

// Test token expiration
TEST(AuthManagerTest, TokenExpiration) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");
    options.token_expiration(std::chrono::seconds(1)); // Expires in 1 second

    AuthManager auth_manager(options);

    AuthUser test_user;
    test_user.id = "12345";

    auto token = auth_manager.generate_token(test_user);

    // Verify immediately - should succeed
    {
        auto verify_result = auth_manager.verify_token(token);
        EXPECT_TRUE(verify_result.has_value());
    }

    // Wait for token to expire
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Verify again - should fail
    {
        auto verify_result = auth_manager.verify_token(token);
        EXPECT_FALSE(verify_result.has_value());
    }
}

// Test verification options
TEST(AuthManagerTest, VerificationOptions) {
    // Test issuer verification
    {
        AuthOptions options;
        options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
        options.secret_key("your-256-bit-secret");
        options.token_issuer("test-issuer");

        AuthManager auth_manager(options);

        AuthUser test_user;
        test_user.id = "12345";

        // Generate and verify with correct issuer
        auto token         = auth_manager.generate_token(test_user);
        auto verify_result = auth_manager.verify_token(token);
        EXPECT_TRUE(verify_result.has_value());

        // Create a new auth manager with different issuer
        AuthOptions wrong_options;
        wrong_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
        wrong_options.secret_key("your-256-bit-secret");
        wrong_options.token_issuer("wrong-issuer");

        AuthManager wrong_auth_manager(wrong_options);
        auto        wrong_verify_result = wrong_auth_manager.verify_token(token);
        EXPECT_FALSE(wrong_verify_result.has_value());
    }

    // Test audience verification
    {
        AuthOptions options;
        options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
        options.secret_key("your-256-bit-secret");
        options.token_audience("test-audience");

        AuthManager auth_manager(options);

        AuthUser test_user;
        test_user.id = "12345";

        // Generate and verify with correct audience
        auto token         = auth_manager.generate_token(test_user);
        auto verify_result = auth_manager.verify_token(token);
        EXPECT_TRUE(verify_result.has_value());

        // Create a new auth manager with different audience
        AuthOptions wrong_options;
        wrong_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
        wrong_options.secret_key("your-256-bit-secret");
        wrong_options.token_audience("wrong-audience");

        AuthManager wrong_auth_manager(wrong_options);
        auto        wrong_verify_result = wrong_auth_manager.verify_token(token);
        EXPECT_FALSE(wrong_verify_result.has_value());
    }
}

// Test user role functions
TEST(AuthManagerTest, UserRoleFunctions) {
    AuthUser user;
    user.id    = "12345";
    user.roles = {"user", "editor", "viewer"};

    // Test single role
    EXPECT_TRUE(user.has_role("user"));
    EXPECT_TRUE(user.has_role("editor"));
    EXPECT_FALSE(user.has_role("admin"));

    // Test any role
    EXPECT_TRUE(user.has_any_role({"admin", "editor"}));
    EXPECT_FALSE(user.has_any_role({"admin", "moderator"}));

    // Test all roles
    EXPECT_TRUE(user.has_all_roles({"user", "editor"}));
    EXPECT_FALSE(user.has_all_roles({"user", "admin"}));
}

// Test invalid token rejection
TEST(AuthManagerTest, InvalidTokenRejection) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");

    AuthManager auth_manager(options);

    // Empty token
    auto empty_result = auth_manager.verify_token("");
    EXPECT_FALSE(empty_result.has_value());

    // Invalid format (no dot)
    auto invalid_format = auth_manager.verify_token("invalidtokenformat");
    EXPECT_FALSE(invalid_format.has_value());

    // Invalid signature
    AuthUser test_user;
    test_user.id = "12345";

    auto valid_token    = auth_manager.generate_token(test_user);
    auto tampered_token = valid_token + "tampered";

    auto tampered_result = auth_manager.verify_token(tampered_token);
    EXPECT_FALSE(tampered_result.has_value());
}

// Test tokens with custom claims
TEST(AuthManagerTest, CustomClaims) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");

    AuthManager auth_manager(options);

    AuthUser test_user;
    test_user.id                           = "12345";
    test_user.metadata["custom_claim"]     = "custom_value";
    test_user.metadata["permission_level"] = "high";

    auto token         = auth_manager.generate_token(test_user);
    auto verify_result = auth_manager.verify_token(token);

    ASSERT_TRUE(verify_result.has_value());
    const auto &user = verify_result.value();

    EXPECT_EQ(user.metadata.at("custom_claim"), "custom_value");
    EXPECT_EQ(user.metadata.at("permission_level"), "high");
}

// Test malformed tokens
TEST(AuthManagerTest, MalformedTokens) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");

    AuthManager auth_manager(options);

    // Test with tokens that have invalid structure
    std::vector<std::string> malformed_tokens = {
        "onlyone.part", "too.many.parts.here", "bad-base64.value!",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.bad-payload", // Valid header, invalid
                                                            // payload
        "bad-header.eyJzdWIiOiIxMjM0NTY3ODkwIn0" // Invalid header, valid payload
    };

    for (const auto &token : malformed_tokens) {
        auto result = auth_manager.verify_token(token);
        EXPECT_FALSE(result.has_value()) << "Token should be rejected: " << token;
    }
}

// Test algorithm mismatch
TEST(AuthManagerTest, AlgorithmMismatch) {
    std::string keys_path = "/Users/mbelhadi/Repos/qb-auth-project/temp_keys/";

    std::string rsa_private_key = readFileContents(keys_path + "rsa_private.pem");
    std::string rsa_public_key  = readFileContents(keys_path + "rsa_public.pem");

    // Create a token with RSA_SHA256 algorithm
    AuthOptions rsa_options;
    rsa_options.algorithm(AuthOptions::Algorithm::RSA_SHA256);
    rsa_options.private_key(rsa_private_key);
    rsa_options.public_key(rsa_public_key);

    AuthManager rsa_manager(rsa_options);

    AuthUser test_user;
    test_user.id = "12345";

    auto rsa_token = rsa_manager.generate_token(test_user);

    // Try to verify it with HMAC_SHA256
    AuthOptions hmac_options;
    hmac_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    hmac_options.secret_key("your-256-bit-secret");

    AuthManager hmac_manager(hmac_options);

    auto result = hmac_manager.verify_token(rsa_token);
    EXPECT_FALSE(result.has_value())
        << "Token signed with RSA should not be verifiable with HMAC";
}

// Test key strength implications
TEST(AuthManagerTest, KeyStrengthTest) {
    // Test with weak keys (too short)
    {
        AuthOptions options;
        options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
        options.secret_key("weak");

        AuthManager auth_manager(options);

        AuthUser test_user;
        test_user.id = "12345";

        // Token generation should work, but it's cryptographically weak
        auto token = auth_manager.generate_token(test_user);
        ASSERT_FALSE(token.empty());

        // Verification should still work for the correct key
        auto verify_result = auth_manager.verify_token(token);
        ASSERT_TRUE(verify_result.has_value());
    }

    // Test with strong keys
    {
        std::string strong_key = generateRandomString(64);

        AuthOptions options;
        options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
        options.secret_key(strong_key);

        AuthManager auth_manager(options);

        AuthUser test_user;
        test_user.id = "12345";

        auto token = auth_manager.generate_token(test_user);
        ASSERT_FALSE(token.empty());

        auto verify_result = auth_manager.verify_token(token);
        ASSERT_TRUE(verify_result.has_value());
    }
}

// Test auth scheme and header configuration
TEST(AuthManagerTest, AuthSchemeConfiguration) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");
    options.auth_header_name("X-Custom-Auth");
    options.auth_scheme("CustomScheme");

    AuthManager auth_manager(options);

    // Check that options were correctly applied
    EXPECT_EQ(auth_manager.get_options().get_auth_header_name(), "X-Custom-Auth");
    EXPECT_EQ(auth_manager.get_options().get_auth_scheme(), "CustomScheme");
}

// Test with edge cases - large user data
TEST(AuthManagerTest, LargeUserData) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");

    AuthManager auth_manager(options);

    // Create user with large metadata
    AuthUser test_user;
    test_user.id       = "12345";
    test_user.username = generateRandomString(1000); // Very long username

    // Generate lots of roles
    for (int i = 0; i < 100; ++i) {
        test_user.roles.push_back("role_" + std::to_string(i));
    }

    // Add large metadata
    test_user.metadata["large_field"] = generateRandomString(2000);

    // Generate token
    auto token = auth_manager.generate_token(test_user);
    ASSERT_FALSE(token.empty());

    // Verify token
    auto verify_result = auth_manager.verify_token(token);
    ASSERT_TRUE(verify_result.has_value());

    // Check that all data was preserved
    const auto &user = verify_result.value();
    EXPECT_EQ(user.id, "12345");
    EXPECT_EQ(user.username, test_user.username);
    EXPECT_EQ(user.roles.size(), test_user.roles.size());
    EXPECT_EQ(user.metadata.at("large_field"), test_user.metadata.at("large_field"));
}

// Test special edge cases
TEST(AuthManagerTest, EdgeCases) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");

    AuthManager auth_manager(options);

    // User with empty ID
    {
        AuthUser test_user;
        test_user.id = "";

        auto token         = auth_manager.generate_token(test_user);
        auto verify_result = auth_manager.verify_token(token);

        ASSERT_TRUE(verify_result.has_value());
        EXPECT_TRUE(verify_result.value().id.empty());
    }

    // User with empty roles array
    {
        AuthUser test_user;
        test_user.id = "12345";
        test_user.roles.clear();

        auto token         = auth_manager.generate_token(test_user);
        auto verify_result = auth_manager.verify_token(token);

        ASSERT_TRUE(verify_result.has_value());
        EXPECT_TRUE(verify_result.value().roles.empty());

        // Empty roles array should handle role checks appropriately
        EXPECT_FALSE(verify_result.value().has_role("any_role"));
        EXPECT_FALSE(verify_result.value().has_any_role({"role1", "role2"}));
        EXPECT_TRUE(
            verify_result.value().has_all_roles({})); // Empty requirement is always true
    }

    // User with special characters in metadata
    {
        AuthUser test_user;
        test_user.id                        = "12345";
        test_user.metadata["special_chars"] = "!@#$%^&*(){}[]<>?/\\|\"'`~";

        auto token         = auth_manager.generate_token(test_user);
        auto verify_result = auth_manager.verify_token(token);

        ASSERT_TRUE(verify_result.has_value());
        EXPECT_EQ(verify_result.value().metadata.at("special_chars"),
                  test_user.metadata.at("special_chars"));
    }
}

// Test complex JSON structures in metadata
TEST(AuthManagerTest, ComplexJsonMetadata) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");

    AuthManager auth_manager(options);

    AuthUser test_user;
    test_user.id = "12345";

    // Add JSON structures as strings in metadata
    test_user.metadata["json_array"] = "[1, 2, 3, 4, 5]";
    test_user.metadata["json_object"] =
        R"({"name":"John","age":30,"city":"New York"})";
    test_user.metadata["nested_json"] = "{\"employees\":[{\"name\":\"Alice\",\"dept\":"
                                        "\"IT\"},{\"name\":\"Bob\",\"dept\":\"HR\"}]}";

    auto token         = auth_manager.generate_token(test_user);
    auto verify_result = auth_manager.verify_token(token);

    ASSERT_TRUE(verify_result.has_value());
    const auto &user = verify_result.value();

    EXPECT_EQ(user.metadata.at("json_array"), test_user.metadata.at("json_array"));
    EXPECT_EQ(user.metadata.at("json_object"), test_user.metadata.at("json_object"));
    EXPECT_EQ(user.metadata.at("nested_json"), test_user.metadata.at("nested_json"));
}

// Test token performance
TEST(AuthManagerTest, TokenPerformance) {
    const int NUM_TOKENS = 100; // Number of tokens to generate/verify

    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");

    AuthManager auth_manager(options);

    AuthUser test_user;
    test_user.id       = "12345";
    test_user.username = "test_user";
    test_user.roles    = {"user", "editor"};

    // Measure token generation time
    auto start_gen = std::chrono::high_resolution_clock::now();

    std::vector<std::string> tokens;
    tokens.reserve(NUM_TOKENS);

    for (int i = 0; i < NUM_TOKENS; ++i) {
        tokens.push_back(auth_manager.generate_token(test_user));
    }

    auto end_gen = std::chrono::high_resolution_clock::now();
    auto gen_duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end_gen - start_gen)
            .count();

    std::cout << "Generated " << NUM_TOKENS << " tokens in " << gen_duration
              << "ms (avg: " << static_cast<double>(gen_duration) / NUM_TOKENS
              << "ms per token)" << std::endl;

    // Measure token verification time
    auto start_verify = std::chrono::high_resolution_clock::now();

    int successful = 0;
    for (const auto &token : tokens) {
        auto result = auth_manager.verify_token(token);
        if (result.has_value()) {
            successful++;
        }
    }

    auto end_verify = std::chrono::high_resolution_clock::now();
    auto verify_duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(end_verify - start_verify)
            .count();

    std::cout << "Verified " << NUM_TOKENS << " tokens in " << verify_duration
              << "ms (avg: " << static_cast<double>(verify_duration) / NUM_TOKENS
              << "ms per token)" << std::endl;

    EXPECT_EQ(successful, NUM_TOKENS) << "All tokens should be successfully verified";
}

// Test token refresh functionality
TEST(AuthManagerTest, TokenRefresh) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");
    options.token_expiration(std::chrono::seconds(3600)); // 1 hour for regular tokens

    AuthManager auth_manager(options);

    // Create original user
    AuthUser original_user;
    original_user.id                        = "12345";
    original_user.username                  = "test_user";
    original_user.roles                     = {"user"};
    original_user.metadata["refresh_count"] = "0";

    // Generate original token
    auto original_token = auth_manager.generate_token(original_user);

    // Verify original token
    auto verify_result = auth_manager.verify_token(original_token);
    ASSERT_TRUE(verify_result.has_value());

    // Create a refreshed user by incrementing refresh count
    AuthUser refreshed_user = verify_result.value();
    int      refresh_count  = std::stoi(refreshed_user.metadata.at("refresh_count"));
    refreshed_user.metadata["refresh_count"] = std::to_string(refresh_count + 1);

    // Add some new metadata for the refreshed token
    refreshed_user.metadata["refreshed_at"] = std::to_string(std::time(nullptr));

    // Generate refreshed token
    auto refreshed_token = auth_manager.generate_token(refreshed_user);
    EXPECT_NE(refreshed_token, original_token);

    // Verify refreshed token
    auto refreshed_verify_result = auth_manager.verify_token(refreshed_token);
    ASSERT_TRUE(refreshed_verify_result.has_value());

    const auto &refreshed_user_verified = refreshed_verify_result.value();
    EXPECT_EQ(refreshed_user_verified.id, "12345");
    EXPECT_EQ(refreshed_user_verified.username, "test_user");
    EXPECT_EQ(refreshed_user_verified.metadata.at("refresh_count"), "1");
    EXPECT_TRUE(refreshed_user_verified.metadata.find("refreshed_at") !=
                refreshed_user_verified.metadata.end());

    // Multiple refresh cycles
    for (int i = 0; i < 5; i++) {
        // Refresh the token again
        AuthUser next_refresh = refreshed_verify_result.value();
        int      next_count   = std::stoi(next_refresh.metadata.at("refresh_count"));
        next_refresh.metadata["refresh_count"] = std::to_string(next_count + 1);
        next_refresh.metadata["refreshed_at"]  = std::to_string(std::time(nullptr));

        auto next_token         = auth_manager.generate_token(next_refresh);
        refreshed_verify_result = auth_manager.verify_token(next_token);
        ASSERT_TRUE(refreshed_verify_result.has_value());
    }

    // Final refresh count should be 6
    EXPECT_EQ(refreshed_verify_result.value().metadata.at("refresh_count"), "6");
}

// Test handling of clock skew between token generation and verification
TEST(AuthManagerTest, ClockSkewHandling) {
    // Create user
    AuthUser test_user;
    test_user.id       = "12345";
    test_user.username = "test_user";

    // Test with exact expiration (no tolerance)
    {
        AuthOptions strict_options;
        strict_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
        strict_options.secret_key("your-256-bit-secret");
        strict_options.token_expiration(std::chrono::seconds(3)); // 3 second expiration

        AuthManager strict_auth(strict_options);
        auto        token = strict_auth.generate_token(test_user);

        // Wait just under the expiration time
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // Should still be valid
        auto verify_result = strict_auth.verify_token(token);
        EXPECT_TRUE(verify_result.has_value());

        // Wait until just past expiration
        std::this_thread::sleep_for(std::chrono::seconds(2));

        // Should be expired
        verify_result = strict_auth.verify_token(token);
        EXPECT_FALSE(verify_result.has_value());
    }

    // Test with clock skew tolerance
    {
        AuthOptions skew_options;
        skew_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
        skew_options.secret_key("your-256-bit-secret");
        skew_options.token_expiration(std::chrono::seconds(2)); // 2 second expiration
        skew_options.clock_skew_tolerance(std::chrono::seconds(3)); // 3 second tolerance

        AuthManager skew_auth(skew_options);
        auto        token = skew_auth.generate_token(test_user);

        // Wait past nominal expiration but within tolerance
        std::this_thread::sleep_for(std::chrono::seconds(3));

        // Should still be valid due to clock skew tolerance
        auto verify_result = skew_auth.verify_token(token);
        EXPECT_TRUE(verify_result.has_value());

        // Wait past tolerance
        std::this_thread::sleep_for(std::chrono::seconds(3));

        // Now should be invalid
        verify_result = skew_auth.verify_token(token);
        EXPECT_FALSE(verify_result.has_value());
    }
}

// Test authorization flow with different token types
TEST(AuthManagerTest, AuthorizationFlow) {
    // Standard access token options
    AuthOptions access_options;
    access_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    access_options.secret_key("access-token-secret-key");
    access_options.token_expiration(
        std::chrono::minutes(15)); // Short-lived access token
    access_options.token_issuer("auth-service");
    access_options.token_audience("resource-server");

    // Refresh token options (longer expiration)
    AuthOptions refresh_options;
    refresh_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    refresh_options.secret_key("refresh-token-secret");
    refresh_options.token_expiration(std::chrono::hours(168)); // 7 days (168 hours)
    refresh_options.token_issuer("auth-service");
    refresh_options.token_audience("auth-server");

    AuthManager access_manager(access_options);
    AuthManager refresh_manager(refresh_options);

    // Create a user
    AuthUser user;
    user.id       = "user-12345";
    user.username = "test_user";
    user.roles    = {"user"};

    // 1. Initial authentication and token issuance
    auto access_token = access_manager.generate_token(user);

    // Set special claims for refresh token
    user.metadata["token_type"] = "refresh";
    user.metadata["client_id"]  = "client-12345";
    auto refresh_token          = refresh_manager.generate_token(user);

    // 2. Validate the access token
    auto access_validation = access_manager.verify_token(access_token);
    ASSERT_TRUE(access_validation.has_value());
    EXPECT_EQ(access_validation.value().id, "user-12345");

    // 3. Create a minimal token expiration test
    // Create a new options with zero expiration time
    AuthOptions zero_expiration = access_options;
    zero_expiration.token_expiration(std::chrono::seconds(2)); // Increase to 2 seconds
    AuthManager zero_manager(zero_expiration);

    // Create a token that will expire immediately
    auto expired_token = zero_manager.generate_token(user);

    // Wait a short time to ensure it's expired
    std::this_thread::sleep_for(std::chrono::seconds(5)); // Increase to 5 seconds

    // Check the token - it should be expired
    auto expired_validation = zero_manager.verify_token(expired_token);
    EXPECT_FALSE(expired_validation.has_value()) << "Token should have expired";

    // 4. Token refresh flow - validate refresh token
    auto refresh_validation = refresh_manager.verify_token(refresh_token);
    ASSERT_TRUE(refresh_validation.has_value());
    EXPECT_EQ(refresh_validation.value().metadata.at("token_type"), "refresh");
    EXPECT_EQ(refresh_validation.value().metadata.at("client_id"), "client-12345");

    // 5. Issue a new access token based on refresh token information
    AuthUser refreshed_user = refresh_validation.value();
    refreshed_user.metadata.erase("token_type"); // Clear refresh-specific metadata
    refreshed_user.metadata["renewed"] = "true";

    auto new_access_token = access_manager.generate_token(refreshed_user);

    // 6. Verify the new access token
    auto new_validation = access_manager.verify_token(new_access_token);
    ASSERT_TRUE(new_validation.has_value());
    EXPECT_EQ(new_validation.value().id, "user-12345");
    EXPECT_EQ(new_validation.value().metadata.at("renewed"), "true");
    EXPECT_FALSE(new_validation.value().metadata.find("token_type") !=
                 new_validation.value().metadata.end());

    // 7. Simulate token revocation (would typically be in a database)
    // Here we'll demonstrate by checking a hypothetical revocation check
    bool is_revoked = false; // In a real system, this would check against a store
    EXPECT_FALSE(is_revoked);
}

// Test password validation
TEST(AuthManagerTest, PasswordValidation) {
    // Setup simple password validation rules
    auto is_valid_password = [](const std::string &password) -> bool {
        // At least 8 chars, 1 uppercase, 1 lowercase, 1 digit
        bool has_min_length = password.length() >= 8;
        bool has_uppercase  = std::any_of(password.begin(), password.end(),
                                          [](char c) { return std::isupper(c); });
        bool has_lowercase  = std::any_of(password.begin(), password.end(),
                                          [](char c) { return std::islower(c); });
        bool has_digit      = std::any_of(password.begin(), password.end(),
                                          [](char c) { return std::isdigit(c); });

        return has_min_length && has_uppercase && has_lowercase && has_digit;
    };

    // Test various passwords
    EXPECT_TRUE(is_valid_password("Password123"));
    EXPECT_FALSE(is_valid_password("password"));    // no uppercase, no digit
    EXPECT_FALSE(is_valid_password("PASSWORD123")); // no lowercase
    EXPECT_FALSE(is_valid_password("Pass123"));     // too short
    EXPECT_FALSE(is_valid_password("Password"));    // no digit

    // Test password hashing
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");

    AuthManager auth_manager(options);

    AuthUser user;
    user.id       = "user-12345";
    user.username = "test_user";
    user.metadata["password_hash"] =
        "hashed_password_value"; // In a real system, this would be hashed

    auto token         = auth_manager.generate_token(user);
    auto verify_result = auth_manager.verify_token(token);

    ASSERT_TRUE(verify_result.has_value());
    EXPECT_EQ(verify_result.value().metadata.at("password_hash"),
              "hashed_password_value");

    // Test simulated password verification
    auto verify_password = [](const std::string &password,
                              const std::string &hash) -> bool {
        // In a real system, this would use a proper hashing function
        // This is just a simulation
        return hash == "hashed_" + password + "_value";
    };

    EXPECT_TRUE(verify_password("password", "hashed_password_value"));
    EXPECT_FALSE(verify_password("wrong_password", "hashed_password_value"));
}

// Test token refresh strategies
TEST(AuthManagerTest, TokenRefreshStrategies) {
    // Setup
    AuthOptions access_options;
    access_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    access_options.secret_key("access-token-secret");
    access_options.token_expiration(std::chrono::minutes(15));

    AuthOptions refresh_options;
    refresh_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    refresh_options.secret_key("refresh-token-secret");
    refresh_options.token_expiration(std::chrono::hours(168)); // 7 days (168 hours)

    AuthManager access_manager(access_options);
    AuthManager refresh_manager(refresh_options);

    // Create a user
    AuthUser user;
    user.id       = "user-12345";
    user.username = "test_user";
    user.roles    = {"user"};

    // Initial token issuance
    auto access_token = access_manager.generate_token(user);

    // Add refresh token specific data
    user.metadata["token_type"]            = "refresh";
    user.metadata["refresh_token_family"]  = "family-1";
    user.metadata["refresh_token_version"] = "1";
    auto refresh_token                     = refresh_manager.generate_token(user);

    // Test token rotation (single-use refresh tokens with family)
    // Simulate a refresh token repository
    std::unordered_map<std::string, std::unordered_set<std::string>> used_refresh_tokens;
    std::unordered_map<std::string, std::string> refresh_token_families;

    // Verify refresh token
    auto refresh_result = refresh_manager.verify_token(refresh_token);
    ASSERT_TRUE(refresh_result.has_value());

    // Extract token family and version
    std::string token_family =
        refresh_result.value().metadata.at("refresh_token_family");
    std::string token_version =
        refresh_result.value().metadata.at("refresh_token_version");

    // Check if token has been used before
    bool token_used = used_refresh_tokens[token_family].find(token_version) !=
                      used_refresh_tokens[token_family].end();
    EXPECT_FALSE(token_used);

    // Mark token as used
    used_refresh_tokens[token_family].insert(token_version);

    // Create a new refresh token (rotation)
    AuthUser refreshed_user                          = refresh_result.value();
    refreshed_user.metadata["refresh_token_version"] = "2"; // Increment version

    auto new_refresh_token = refresh_manager.generate_token(refreshed_user);

    // Verify the new token
    auto new_refresh_result = refresh_manager.verify_token(new_refresh_token);
    ASSERT_TRUE(new_refresh_result.has_value());
    EXPECT_EQ(new_refresh_result.value().metadata.at("refresh_token_version"), "2");

    // Issue a new access token
    refreshed_user.metadata.erase("token_type");
    auto new_access_token = access_manager.generate_token(refreshed_user);

    // Verify new access token
    auto access_result = access_manager.verify_token(new_access_token);
    ASSERT_TRUE(access_result.has_value());

    // Test reuse detection - try to use the old refresh token again
    bool reuse_detected = used_refresh_tokens[token_family].find(token_version) !=
                          used_refresh_tokens[token_family].end();
    EXPECT_TRUE(reuse_detected);

    // Test sliding window expiration for refresh tokens
    AuthOptions sliding_options = refresh_options;
    sliding_options.token_expiration(
        std::chrono::hours(1)); // Short expiration for testing
    AuthManager sliding_manager(sliding_options);

    // Create a token
    auto sliding_token = sliding_manager.generate_token(user);

    // Verify and "slide" expiration window
    auto sliding_result = sliding_manager.verify_token(sliding_token);
    ASSERT_TRUE(sliding_result.has_value());

    // Create a new token with extended expiration (simulating sliding window)
    auto extended_token = sliding_manager.generate_token(sliding_result.value());

    // Original token still valid
    auto original_still_valid = sliding_manager.verify_token(sliding_token);
    ASSERT_TRUE(original_still_valid.has_value());
}

// Test role-based access control
TEST(AuthManagerTest, RoleBasedAccessControl) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");

    AuthManager auth_manager(options);

    // Define a role hierarchy
    std::unordered_map<std::string, std::vector<std::string>> role_hierarchy = {
        {"admin", {"moderator", "user"}},
        {"moderator", {"user"}},
        {"editor", {"user"}},
        {"user", {}}};

    // Function to check if a role has permissions (including inherited ones)
    auto has_permission = [&role_hierarchy](const std::vector<std::string> &user_roles,
                                            const std::string &required_role) -> bool {
        // Direct role check
        if (std::find(user_roles.begin(), user_roles.end(), required_role) !=
            user_roles.end()) {
            return true;
        }

        // Check inherited roles
        for (const auto &role : user_roles) {
            // Build a queue for breadth-first search of inherited roles
            std::queue<std::string> queue;
            queue.push(role);

            while (!queue.empty()) {
                std::string current = queue.front();
                queue.pop();

                if (current == required_role) {
                    return true;
                }

                // Add inherited roles to the queue
                if (role_hierarchy.find(current) != role_hierarchy.end()) {
                    for (const auto &inherited : role_hierarchy.at(current)) {
                        queue.push(inherited);
                    }
                }
            }
        }

        return false;
    };

    // Test various role combinations
    AuthUser admin_user;
    admin_user.id       = "admin-123";
    admin_user.username = "admin";
    admin_user.roles    = {"admin"};

    AuthUser moderator_user;
    moderator_user.id       = "mod-123";
    moderator_user.username = "moderator";
    moderator_user.roles    = {"moderator"};

    AuthUser editor_user;
    editor_user.id       = "editor-123";
    editor_user.username = "editor";
    editor_user.roles    = {"editor"};

    AuthUser regular_user;
    regular_user.id       = "user-123";
    regular_user.username = "user";
    regular_user.roles    = {"user"};

    AuthUser multi_role_user;
    multi_role_user.id       = "multi-123";
    multi_role_user.username = "multi_role";
    multi_role_user.roles    = {"editor", "moderator"};

    // Admin can access everything
    EXPECT_TRUE(has_permission(admin_user.roles, "admin"));
    EXPECT_TRUE(has_permission(admin_user.roles, "moderator"));
    EXPECT_FALSE(has_permission(
        admin_user.roles, "editor")); // Admin doesn't have editor role in our hierarchy
    EXPECT_TRUE(has_permission(admin_user.roles, "user"));

    // Moderator can access moderator and user, but not admin or editor
    EXPECT_FALSE(has_permission(moderator_user.roles, "admin"));
    EXPECT_TRUE(has_permission(moderator_user.roles, "moderator"));
    EXPECT_FALSE(has_permission(moderator_user.roles, "editor"));
    EXPECT_TRUE(has_permission(moderator_user.roles, "user"));

    // Editor can access editor and user, but not admin or moderator
    EXPECT_FALSE(has_permission(editor_user.roles, "admin"));
    EXPECT_FALSE(has_permission(editor_user.roles, "moderator"));
    EXPECT_TRUE(has_permission(editor_user.roles, "editor"));
    EXPECT_TRUE(has_permission(editor_user.roles, "user"));

    // User can only access user
    EXPECT_FALSE(has_permission(regular_user.roles, "admin"));
    EXPECT_FALSE(has_permission(regular_user.roles, "moderator"));
    EXPECT_FALSE(has_permission(regular_user.roles, "editor"));
    EXPECT_TRUE(has_permission(regular_user.roles, "user"));

    // Multi-role user has combined permissions
    EXPECT_FALSE(has_permission(multi_role_user.roles, "admin"));
    EXPECT_TRUE(has_permission(multi_role_user.roles, "moderator"));
    EXPECT_TRUE(has_permission(multi_role_user.roles, "editor"));
    EXPECT_TRUE(has_permission(multi_role_user.roles, "user"));

    // Test route protection simulation
    auto protect_route = [&auth_manager,
                          &has_permission](const std::string &token,
                                           const std::string &required_role) -> bool {
        auto user = auth_manager.verify_token(token);
        if (!user) {
            return false;
        }

        return has_permission(user.value().roles, required_role);
    };

    // Generate tokens
    auto admin_token     = auth_manager.generate_token(admin_user);
    auto moderator_token = auth_manager.generate_token(moderator_user);
    auto editor_token    = auth_manager.generate_token(editor_user);
    auto user_token      = auth_manager.generate_token(regular_user);

    // Test route protection
    EXPECT_TRUE(protect_route(admin_token, "admin"));
    EXPECT_FALSE(protect_route(moderator_token, "admin"));
    EXPECT_TRUE(protect_route(admin_token, "user"));
    EXPECT_TRUE(protect_route(editor_token, "user"));
    EXPECT_FALSE(protect_route(user_token, "editor"));
}

// Test error handling
TEST(AuthManagerTest, ErrorHandling) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");
    options.token_expiration(std::chrono::seconds(3600));

    AuthManager auth_manager(options);

    // Test with empty token
    auto empty_result = auth_manager.verify_token("");
    EXPECT_FALSE(empty_result.has_value());

    // Test with malformed token
    auto malformed_result = auth_manager.verify_token("not.a.valid.token");
    EXPECT_FALSE(malformed_result.has_value());

    // Test with invalid signature
    AuthUser test_user;
    test_user.id       = "user-123";
    test_user.username = "test_user";

    auto valid_token = auth_manager.generate_token(test_user);

    // Tamper with the token (change the last character)
    std::string tampered_token  = valid_token.substr(0, valid_token.length() - 1) + "X";
    auto        tampered_result = auth_manager.verify_token(tampered_token);
    EXPECT_FALSE(tampered_result.has_value());

    // Test token with missing claims
    AuthOptions minimal_options;
    minimal_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    minimal_options.secret_key("minimal-secret-key");
    minimal_options.token_issuer("test-issuer");
    minimal_options.token_audience("test-audience");

    AuthManager minimal_manager(minimal_options);

    // Create a user with minimal data
    AuthUser minimal_user;
    minimal_user.id = "min-user";
    // No username, no roles, no metadata

    auto minimal_token  = minimal_manager.generate_token(minimal_user);
    auto minimal_result = minimal_manager.verify_token(minimal_token);

    ASSERT_TRUE(minimal_result.has_value());
    EXPECT_EQ(minimal_result.value().id, "min-user");
    EXPECT_TRUE(minimal_result.value().username.empty());
    EXPECT_TRUE(minimal_result.value().roles.empty());
    EXPECT_TRUE(minimal_result.value().metadata.empty());

    // Test rate limiting simulation
    std::unordered_map<std::string, int> failed_attempts;
    std::unordered_map<std::string, std::chrono::time_point<std::chrono::steady_clock>>
               lockout_until;
    const int  MAX_ATTEMPTS     = 3;
    const auto LOCKOUT_DURATION = std::chrono::seconds(300); // 5 minutes

    auto is_rate_limited = [&](const std::string &user_id) -> bool {
        auto now = std::chrono::steady_clock::now();

        // Check if user is locked out
        if (lockout_until.find(user_id) != lockout_until.end()) {
            if (now < lockout_until[user_id]) {
                return true; // Still in lockout period
            } else {
                // Lockout period expired, reset counter
                failed_attempts[user_id] = 0;
                lockout_until.erase(user_id);
            }
        }

        return false;
    };

    auto record_failed_attempt = [&](const std::string &user_id) {
        failed_attempts[user_id]++;
        if (failed_attempts[user_id] >= MAX_ATTEMPTS) {
            // Lock out the user
            lockout_until[user_id] = std::chrono::steady_clock::now() + LOCKOUT_DURATION;
        }
    };

    // Simulate failed login attempts
    std::string test_id = "user-456";

    // Not rate limited initially
    EXPECT_FALSE(is_rate_limited(test_id));

    // Record 3 failed attempts
    record_failed_attempt(test_id);
    EXPECT_FALSE(is_rate_limited(test_id));

    record_failed_attempt(test_id);
    EXPECT_FALSE(is_rate_limited(test_id));

    record_failed_attempt(test_id);
    EXPECT_TRUE(is_rate_limited(test_id)); // Now should be rate limited
}

// Test edge cases
TEST(AuthManagerTest, ExtendedEdgeCases) {
    AuthOptions options;
    options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    options.secret_key("your-256-bit-secret");
    options.token_expiration(std::chrono::seconds(5));

    AuthManager auth_manager(options);

    // Test very large tokens with extensive metadata
    AuthUser large_user;
    large_user.id       = "large-user-123";
    large_user.username = "large_username";
    large_user.roles    = {"user", "tester"};

    // Add a large amount of metadata
    for (int i = 0; i < 100; i++) {
        large_user.metadata["key_" + std::to_string(i)] =
            std::string(100, 'X'); // 100 character string
    }

    auto large_token = auth_manager.generate_token(large_user);
    EXPECT_GT(large_token.length(), 10000); // Ensure token is actually large

    auto large_result = auth_manager.verify_token(large_token);
    ASSERT_TRUE(large_result.has_value());
    EXPECT_EQ(large_result.value().id, "large-user-123");
    EXPECT_EQ(large_result.value().metadata.size(), 100);

    // Test token near expiration (boundary testing)
    AuthOptions short_options;
    short_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    short_options.secret_key("boundary-test-secret");
    short_options.token_expiration(std::chrono::seconds(2));

    AuthManager boundary_manager(short_options);

    AuthUser boundary_user;
    boundary_user.id = "boundary-user";

    auto boundary_token = boundary_manager.generate_token(boundary_user);

    // Token should be valid immediately
    auto immediate_result = boundary_manager.verify_token(boundary_token);
    EXPECT_TRUE(immediate_result.has_value());

    // Wait just under the expiration time
    std::this_thread::sleep_for(std::chrono::milliseconds(1900));

    // Token should still be valid
    auto near_expiry_result = boundary_manager.verify_token(boundary_token);
    EXPECT_TRUE(near_expiry_result.has_value());

    // Wait past the expiration time (ensure we're well beyond the 2 second limit)
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));

    // Token should now be expired
    auto expired_result = boundary_manager.verify_token(boundary_token);
    EXPECT_FALSE(expired_result.has_value());

    // Test token with empty claims
    AuthUser empty_user;
    // All fields are empty

    auto empty_token  = auth_manager.generate_token(empty_user);
    auto empty_result = auth_manager.verify_token(empty_token);

    ASSERT_TRUE(empty_result.has_value());
    EXPECT_TRUE(empty_result.value().id.empty());
    EXPECT_TRUE(empty_result.value().username.empty());
    EXPECT_TRUE(empty_result.value().roles.empty());
    EXPECT_TRUE(empty_result.value().metadata.empty());
}

// Test security features
TEST(AuthManagerTest, SecurityFeatures) {
    // Setup for algorithm verification
    AuthOptions hmac_options;
    hmac_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    hmac_options.secret_key("hmac-secret-key");

    // Use the same algorithm but with different keys for the second manager
    AuthOptions alternate_options;
    alternate_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    alternate_options.secret_key("different-secret-key");

    AuthManager hmac_manager(hmac_options);
    AuthManager alternate_manager(alternate_options);

    AuthUser test_user;
    test_user.id = "security-test-user";

    // Generate tokens with different keys
    auto hmac_token = hmac_manager.generate_token(test_user);
    auto alt_token  = alternate_manager.generate_token(test_user);

    // Test token verification between managers (should fail due to different keys)
    auto hmac_verify_alt = hmac_manager.verify_token(alt_token);
    EXPECT_FALSE(hmac_verify_alt.has_value());

    auto alt_verify_hmac = alternate_manager.verify_token(hmac_token);
    EXPECT_FALSE(alt_verify_hmac.has_value());

    // Test payload tampering detection
    AuthOptions secure_options;
    secure_options.algorithm(AuthOptions::Algorithm::HMAC_SHA256);
    secure_options.secret_key("tamper-detection-secret");

    AuthManager secure_manager(secure_options);

    AuthUser secure_user;
    secure_user.id    = "secure-user";
    secure_user.roles = {"user", "admin"};

    auto secure_token = secure_manager.generate_token(secure_user);

    // Original token should be valid
    auto validation_result = secure_manager.verify_token(secure_token);
    EXPECT_TRUE(validation_result.has_value());

    // Tamper with the token payload (modify the middle section which contains the
    // payload)
    auto token_parts = split_string(secure_token, '.');
    ASSERT_EQ(token_parts.size(), 3u); // Header, payload, signature

    // Decode the payload
    std::string decoded_payload = base64url_decode(token_parts[1]);

    // Modify the payload by changing the user ID
    decoded_payload = std::regex_replace(
        decoded_payload, std::regex(R"("sub":"secure-user")"), R"("sub":"hacker")");

    // Re-encode the payload
    token_parts[1] = base64url_encode(decoded_payload);

    // Reconstruct the token without regenerating the signature
    std::string tampered_token =
        token_parts[0] + "." + token_parts[1] + "." + token_parts[2];

    // Tampered token should fail validation
    auto tampered_result = secure_manager.verify_token(tampered_token);
    EXPECT_FALSE(tampered_result.has_value());
}

int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
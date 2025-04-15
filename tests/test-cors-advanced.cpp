#include <gtest/gtest.h>
#include "../routing.h"

// Mock session for testing - same as in test-cors.cpp
class MockSession {
public:
    qb::http::Response                 _response;
    bool                               _closed = false;
    std::vector<qb::http::Response>    _responses;
    qb::unordered_map<std::string, std::string> _cors_headers;
    std::string                        _captured_body;
    qb::uuid                           _id; // Add session ID member

    // Constructor to initialize the ID
    MockSession()
        : _id(qb::generate_random_uuid()) {}

    // Required by Router to send responses
    MockSession &
    operator<<(qb::http::Response resp) {
        std::cout << "MockSession received response" << std::endl;

        // Capture CORS headers before move
        if (resp.headers().find("Access-Control-Allow-Origin") != resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Origin"] =
                resp.header("Access-Control-Allow-Origin");
            std::cout << "Captured Access-Control-Allow-Origin: "
                      << _cors_headers["Access-Control-Allow-Origin"] << std::endl;
        }

        if (resp.headers().find("Access-Control-Allow-Methods") !=
            resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Methods"] =
                resp.header("Access-Control-Allow-Methods");
        }

        if (resp.headers().find("Access-Control-Allow-Headers") !=
            resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Headers"] =
                resp.header("Access-Control-Allow-Headers");
        }

        if (resp.headers().find("Access-Control-Allow-Credentials") !=
            resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Credentials"] =
                resp.header("Access-Control-Allow-Credentials");
        }

        if (resp.headers().find("Access-Control-Expose-Headers") !=
            resp.headers().end()) {
            _cors_headers["Access-Control-Expose-Headers"] =
                resp.header("Access-Control-Expose-Headers");
        }

        if (resp.headers().find("Access-Control-Max-Age") != resp.headers().end()) {
            _cors_headers["Access-Control-Max-Age"] =
                resp.header("Access-Control-Max-Age");
        }

        // Store Vary header
        if (resp.headers().find("Vary") != resp.headers().end()) {
            _cors_headers["Vary"] = resp.header("Vary");
            std::cout << "Captured Vary: " << _cors_headers["Vary"] << std::endl;
        }

        // Save status code
        _response.status_code = resp.status_code;

        try {
            if (!resp.body().empty()) {
                _captured_body   = resp.body().as<std::string>();
                _response.body() = _captured_body;
            }
        } catch (...) {
            // Ignore body errors
        }

        _responses.push_back(_response);
        return *this;
    }

    [[nodiscard]] bool
    is_connected() const {
        return !_closed;
    }

    void
    close() {
        _closed = true;
    }

    void
    reset() {
        _responses.clear();
        _response = qb::http::Response();
        _cors_headers.clear();
        _captured_body.clear();
        _closed = false;
    }

    [[nodiscard]] size_t
    responseCount() const {
        return _responses.size();
    }

    qb::http::Response &
    response() {
        return _response;
    }

    void
    printHeaders() const {
        std::cout << "Captured CORS headers:" << std::endl;
        for (const auto &[key, value] : _cors_headers) {
            std::cout << "  " << key << ": " << value << std::endl;
        }
        std::cout << "Captured body: " << _captured_body << std::endl;
    }

    // Helper to get CORS headers
    [[nodiscard]] std::string
    header(const std::string &name) const {
        auto it = _cors_headers.find(name);
        if (it != _cors_headers.end()) {
            return it->second;
        }
        return "";
    }

    // Helper to get body
    [[nodiscard]] std::string
    body() const {
        return _captured_body;
    }

    // Return the session ID
    [[nodiscard]] const qb::uuid& id() const { // Ensure const reference return type
        return _id;
    }

};

class CorsAdvancedTest : public ::testing::Test {
protected:
    using Router      = qb::http::TRequest<std::string>::Router<MockSession>;
    using Request     = qb::http::TRequest<std::string>;
    using CorsOptions = qb::http::CorsOptions;

    std::unique_ptr<Router> router;
    std::shared_ptr<MockSession> session; // Use shared_ptr for session

    void
    SetUp() override {
        router = std::make_unique<Router>();
        session = std::make_shared<MockSession>(); // Create session using make_shared
        session->reset();

        // Set up test routes
        router->GET("/api/users", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body()      = "List of users";
        });

        router->GET("/api/users/:id", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body()      = "User: " + ctx.param("id");
        });

        router->POST("/api/users", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_CREATED;
            ctx.response.body()      = "User created";
        });

        router->PUT("/api/users/:id", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body()      = "User updated: " + ctx.param("id");
        });

        router->DELETE("/api/users/:id", [](auto &ctx) {
            ctx.response.status_code = HTTP_STATUS_NO_CONTENT;
        });
    }

    void
    TearDown() override {
        router.reset();
    }

    Request
    createRequest(http_method method, const std::string &path,
                  const std::string &origin = "") {
        Request req;
        req.method = method;
        req._uri   = qb::io::uri(path);

        if (!origin.empty()) {
            req.add_header("Origin", origin);
        }

        return req;
    }

    Request
    createPreflightRequest(const std::string &path, const std::string &origin,
                           const std::string              &method,
                           const std::vector<std::string> &headers = {}) {
        Request req = createRequest(HTTP_OPTIONS, path, origin);
        req.add_header("Access-Control-Request-Method", method);

        if (!headers.empty()) {
            std::string header_str = headers[0];
            for (size_t i = 1; i < headers.size(); ++i) {
                header_str += ", " + headers[i];
            }
            req.add_header("Access-Control-Request-Headers", header_str);
        }

        return req;
    }
};

TEST_F(CorsAdvancedTest, RegexPatternMatching) {
    // Enable CORS with regex pattern matching
    router->enable_cors_with_patterns({
        R"(^https:\/\/([a-zA-Z0-9-]+)\.example\.com$)", // subdomains of example.com
        R"(^https:\/\/app\.example\.(com|org|net)$)"    // app.example.com/org/net
    });

    // Test with matching subdomain
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://api.example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://api.example.com");
    EXPECT_EQ(session->body(), "List of users");

    // Reset session
    session->reset();

    // Test with another matching subdomain
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://frontend.example.com");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://frontend.example.com");

    // Reset session
    session->reset();

    // Test with TLD variation
    auto req3 = createRequest(HTTP_GET, "/api/users", "https://app.example.org");
    router->route(session, req3);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app.example.org");

    // Reset session
    session->reset();

    // Test with non-matching origin
    auto req4 = createRequest(HTTP_GET, "/api/users", "https://example.com");
    router->route(session, req4);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
}

TEST_F(CorsAdvancedTest, PermissiveConfig) {
    // Use the permissive config for development
    router->enable_dev_cors();

    // Test with any origin
    auto req = createRequest(HTTP_GET, "/api/users", "https://localhost:3000");
    router->route(session, req);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://localhost:3000");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");

    // Reset session
    session->reset();

    // Test preflight
    auto preflight =
        createPreflightRequest("/api/users", "https://localhost:3000", "DELETE",
                               {"Content-Type", "Authorization", "X-Custom-Header"});
    router->route(session, preflight);

    // Check preflight response has all the permissive settings
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://localhost:3000");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");

    // Check that common methods are allowed
    std::string methods = session->header("Access-Control-Allow-Methods");
    EXPECT_TRUE(methods.find("GET") != std::string::npos);
    EXPECT_TRUE(methods.find("POST") != std::string::npos);
    EXPECT_TRUE(methods.find("PUT") != std::string::npos);
    EXPECT_TRUE(methods.find("DELETE") != std::string::npos);
    EXPECT_TRUE(methods.find("PATCH") != std::string::npos);
    EXPECT_TRUE(methods.find("HEAD") != std::string::npos);
    EXPECT_TRUE(methods.find("OPTIONS") != std::string::npos);

    // Check that headers are allowed
    std::string headers = session->header("Access-Control-Allow-Headers");
    EXPECT_TRUE(headers.find("Content-Type") != std::string::npos);
    EXPECT_TRUE(headers.find("Authorization") != std::string::npos);
    EXPECT_TRUE(headers.find("Accept") != std::string::npos);
    EXPECT_TRUE(headers.find("X-Auth-Token") != std::string::npos);
}

TEST_F(CorsAdvancedTest, SecureConfig) {
    // Use the secure config for production
    router->enable_cors(
        CorsOptions::secure({"https://app.example.com", "https://api.example.com"}));

    // Test with allowed origin
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://app.example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app.example.com");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");

    // Reset session
    session->reset();

    // Test with non-allowed origin
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://evil.com");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");

    // Reset session
    session->reset();

    // Test preflight
    auto preflight = createPreflightRequest("/api/users", "https://api.example.com",
                                            "POST", {"Content-Type", "Authorization"});
    router->route(session, preflight);

    // Check preflight response has secure settings
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://api.example.com");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");

    // Verify limited methods are allowed
    std::string methods = session->header("Access-Control-Allow-Methods");
    EXPECT_TRUE(methods.find("GET") != std::string::npos);
    EXPECT_TRUE(methods.find("POST") != std::string::npos);
    EXPECT_TRUE(methods.find("PUT") != std::string::npos);
    EXPECT_TRUE(methods.find("DELETE") != std::string::npos);
    EXPECT_FALSE(methods.find("PATCH") != std::string::npos);

    // Verify only secure headers are allowed
    std::string headers = session->header("Access-Control-Allow-Headers");
    EXPECT_TRUE(headers.find("Content-Type") != std::string::npos);
    EXPECT_TRUE(headers.find("Authorization") != std::string::npos);
    EXPECT_FALSE(headers.find("X-Custom-Header") != std::string::npos);
}

TEST_F(CorsAdvancedTest, CustomOriginMatcher) {
    // Create a custom origin matcher function
    std::function<bool(const std::string &)> matcher = [](const std::string &origin) {
        // Only allow origins from specific environments
        return origin == "https://app.example.com" ||
               origin.find("localhost") != std::string::npos ||
               origin.find("-dev.example.com") != std::string::npos ||
               origin.find("-staging.example.com") != std::string::npos;
    };

    // Enable CORS with the custom matcher
    router->enable_cors(CorsOptions()
                            .origin_matcher(matcher)
                            .methods({"GET", "POST", "PUT", "DELETE"})
                            .headers({"Content-Type", "Authorization"})
                            .credentials(CorsOptions::AllowCredentials::Yes));

    // Test with production origin
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://app.example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app.example.com");

    // Reset session
    session->reset();

    // Test with development origin
    auto req2 =
        createRequest(HTTP_GET, "/api/users", "https://feature123-dev.example.com");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://feature123-dev.example.com");

    // Reset session
    session->reset();

    // Test with localhost
    auto req3 = createRequest(HTTP_GET, "/api/users", "http://localhost:3000");
    router->route(session, req3);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "http://localhost:3000");

    // Reset session
    session->reset();

    // Test with non-allowed origin
    auto req4 = createRequest(HTTP_GET, "/api/users", "https://evil.com");
    router->route(session, req4);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
}

TEST_F(CorsAdvancedTest, VaryHeader) {
    // Enable CORS with default options
    router->enable_cors(CorsOptions());

    // Test with Origin header
    auto req = createRequest(HTTP_GET, "/api/users", "https://example.com");
    router->route(session, req);

    // Check that Vary header is set to Origin
    EXPECT_EQ(session->header("Vary"), "Origin");

    // Reset session
    session->reset();

    // Test preflight with additional headers
    auto preflight = createPreflightRequest("/api/users", "https://example.com", "POST",
                                            {"Content-Type", "Authorization"});
    router->route(session, preflight);

    // Check that Vary header includes both Origin and Access-Control-Request-Headers
    std::string vary = session->header("Vary");
    EXPECT_TRUE(vary.find("Origin") != std::string::npos);
    EXPECT_TRUE(vary.find("Access-Control-Request-Headers") != std::string::npos);
}

TEST_F(CorsAdvancedTest, WildcardOriginWithCredentials) {
    // Enable CORS with wildcard origin and credentials (should result in specific origin
    // being echoed)
    router->enable_cors(
        CorsOptions().origins({"*"}).credentials(CorsOptions::AllowCredentials::Yes));

    // Test with Origin header
    auto req = createRequest(HTTP_GET, "/api/users", "https://example.com");
    router->route(session, req);

    // Check that Origin is echoed back, not wildcard
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://example.com");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");
}

TEST_F(CorsAdvancedTest, ExposeHeadersTest) {
    // Enable CORS with specific headers to expose
    router->enable_cors(CorsOptions()
                            .origins({"https://app.example.com"})
                            .expose({"X-Custom-Header", "X-Rate-Limit", "X-Request-ID"})
                            .credentials(CorsOptions::AllowCredentials::Yes));

    // Test with regular request
    auto req = createRequest(HTTP_GET, "/api/users", "https://app.example.com");
    router->route(session, req);

    // Check that Access-Control-Expose-Headers is set correctly
    std::string expose_headers = session->header("Access-Control-Expose-Headers");
    EXPECT_TRUE(expose_headers.find("X-Custom-Header") != std::string::npos);
    EXPECT_TRUE(expose_headers.find("X-Rate-Limit") != std::string::npos);
    EXPECT_TRUE(expose_headers.find("X-Request-ID") != std::string::npos);

    // Also verify other standard headers are present
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app.example.com");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");
}

TEST_F(CorsAdvancedTest, DynamicSubdomainsTest) {
    // Create a more advanced regex for tenant-based subdomains
    router->enable_cors_with_patterns({
        R"(^https:\/\/([a-zA-Z0-9-]+)\.tenant\.example\.com$)" // tenant-specific
                                                               // subdomains
    });

    // Test with different tenant subdomains
    auto req1 =
        createRequest(HTTP_GET, "/api/users", "https://tenant1.tenant.example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://tenant1.tenant.example.com");

    // Reset session
    session->reset();

    // Test with another tenant
    auto req2 = createRequest(HTTP_GET, "/api/users",
                              "https://large-corp-15.tenant.example.com");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://large-corp-15.tenant.example.com");

    // Reset session
    session->reset();

    // Test with invalid subdomain format
    auto req3 =
        createRequest(HTTP_GET, "/api/users", "https://invalid@tenant.example.com");
    router->route(session, req3);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");

    // Reset session
    session->reset();

    // Test with invalid parent domain
    auto req4 =
        createRequest(HTTP_GET, "/api/users", "https://tenant1.tenant.example.org");
    router->route(session, req4);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
}

TEST_F(CorsAdvancedTest, MaxAgePreflightCacheTest) {
    // Test different Max-Age values
    std::vector<int> max_ages = {0, 60, 3600, 86400};

    for (int age : max_ages) {
        // Reset session and router
        session->reset();
        router = std::make_unique<Router>();
        SetUp(); // Recreate routes

        // Enable CORS with specific max-age
        router->enable_cors(CorsOptions()
                                .origins({"https://app.example.com"})
                                .all_methods()
                                .common_headers()
                                .age(age));

        // Test preflight request
        auto preflight =
            createPreflightRequest("/api/users", "https://app.example.com", "PUT",
                                   {"Content-Type", "Authorization"});
        router->route(session, preflight);

        // Check Max-Age is set correctly
        EXPECT_EQ(session->header("Access-Control-Max-Age"), std::to_string(age));
    }
}

TEST_F(CorsAdvancedTest, NonCorsRequestTest) {
    // Enable CORS with standard settings
    router->enable_cors(CorsOptions()
                            .origins({"https://app.example.com"})
                            .all_methods()
                            .common_headers());

    // Test with no Origin header (not a CORS request)
    auto req = createRequest(HTTP_GET, "/api/users");
    router->route(session, req);

    // Should get normal response with no CORS headers
    EXPECT_EQ(session->body(), "List of users");
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
    EXPECT_EQ(session->header("Access-Control-Allow-Methods"), "");

    // Check status code is correct
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
}

TEST_F(CorsAdvancedTest, MultipleMatchingStrategiesTest) {
    // Create a custom matcher that combines exact matching and regex patterns
    std::function<bool(const std::string &)> combined_matcher =
        [](const std::string &origin) {
            // Direct matches
            std::vector<std::string> exact_matches = {"https://app.example.com",
                                                      "https://mobile.example.com"};

            for (const auto &match : exact_matches) {
                if (origin == match) {
                    return true;
                }
            }

            // Regex patterns
            std::vector<std::regex> patterns = {
                std::regex(R"(^https:\/\/([a-zA-Z0-9-]+)\.dev\.example\.com$)"),
                std::regex(
                    R"(^https:\/\/dashboard\-([a-zA-Z0-9]+)\.example\.(com|org)$)")};

            for (const auto &pattern : patterns) {
                if (std::regex_match(origin, pattern)) {
                    return true;
                }
            }

            // Special case for localhost with any port
            if (origin.find("http://localhost:") == 0) {
                return true;
            }

            return false;
        };

    // Enable CORS with combined matcher
    router->enable_cors(
        CorsOptions().origin_matcher(combined_matcher).all_methods().common_headers());

    // Test with direct match
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://app.example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app.example.com");

    // Reset session
    session->reset();

    // Test with regex match (dev environment)
    auto req2 =
        createRequest(HTTP_GET, "/api/users", "https://feature123.dev.example.com");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://feature123.dev.example.com");

    // Reset session
    session->reset();

    // Test with another regex match (dashboard)
    auto req3 =
        createRequest(HTTP_GET, "/api/users", "https://dashboard-user1.example.org");
    router->route(session, req3);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"),
              "https://dashboard-user1.example.org");

    // Reset session
    session->reset();

    // Test with localhost special case
    auto req4 = createRequest(HTTP_GET, "/api/users", "http://localhost:3000");
    router->route(session, req4);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "http://localhost:3000");

    // Reset session
    session->reset();

    // Test with non-allowed origin
    auto req5 = createRequest(HTTP_GET, "/api/users", "https://malicious-site.com");
    router->route(session, req5);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
}

int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#include <gtest/gtest.h>
#include "../http.h"
#include "../cors/cors.h"
#include <memory>
#include <regex>

/**
 * @brief MockSession for CORS testing
 */
class MockSession {
public:
    qb::http::Response _response;
    bool _closed = false;
    std::vector<qb::http::Response> _responses;
    std::map<std::string, std::string> _cors_headers;
    std::string _captured_body;
    qb::uuid _id;

    // Constructor to initialize the ID
    MockSession() : _id(qb::generate_random_uuid()) {}

    // Required by Router to send responses
    MockSession& operator<<(qb::http::Response resp) {
        // Capture CORS headers before move
        if (resp.headers().find("Access-Control-Allow-Origin") != resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Origin"] = resp.header("Access-Control-Allow-Origin");
        }

        if (resp.headers().find("Access-Control-Allow-Methods") != resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Methods"] = resp.header("Access-Control-Allow-Methods");
        }

        if (resp.headers().find("Access-Control-Allow-Headers") != resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Headers"] = resp.header("Access-Control-Allow-Headers");
        }

        if (resp.headers().find("Access-Control-Allow-Credentials") != resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Credentials"] = resp.header("Access-Control-Allow-Credentials");
        }

        if (resp.headers().find("Access-Control-Expose-Headers") != resp.headers().end()) {
            _cors_headers["Access-Control-Expose-Headers"] = resp.header("Access-Control-Expose-Headers");
        }

        if (resp.headers().find("Access-Control-Max-Age") != resp.headers().end()) {
            _cors_headers["Access-Control-Max-Age"] = resp.header("Access-Control-Max-Age");
        }

        // Store Vary header
        if (resp.headers().find("Vary") != resp.headers().end()) {
            _cors_headers["Vary"] = resp.header("Vary");
        }

        // Save status code
        _response.status_code = resp.status_code;

        try {
            if (!resp.body().empty()) {
                _captured_body = resp.body().as<std::string>();
                _response.body() = _captured_body;
            }
        } catch (...) {
            // Ignore body errors
        }

        _responses.push_back(_response);
        return *this;
    }

    [[nodiscard]] bool is_connected() const {
        return !_closed;
    }

    void close() {
        _closed = true;
    }

    void reset() {
        _responses.clear();
        _response = qb::http::Response();
        _cors_headers.clear();
        _captured_body.clear();
        _closed = false;
    }

    [[nodiscard]] size_t responseCount() const {
        return _responses.size();
    }

    qb::http::Response& response() {
        return _response;
    }

    // Helper to get CORS headers
    [[nodiscard]] std::string header(const std::string& name) const {
        auto it = _cors_headers.find(name);
        if (it != _cors_headers.end()) {
            return it->second;
        }
        return "";
    }

    // Helper to get body
    [[nodiscard]] std::string body() const {
        return _captured_body;
    }

    // Return the session ID
    [[nodiscard]] const qb::uuid& id() const {
        return _id;
    }
};

/**
 * @brief Base test fixture for CORS tests
 */
class CorsTest : public ::testing::Test {
protected:
    using Router = qb::http::TRequest<std::string>::Router<MockSession>;
    using Request = qb::http::TRequest<std::string>;
    using Response = qb::http::TResponse<std::string>;
    using Context = qb::http::RouterContext<MockSession, std::string>;
    using Cors = qb::http::Cors<MockSession, std::string>;
    using CorsOptions = qb::http::CorsOptions;
    
    std::unique_ptr<Router> router;
    std::shared_ptr<MockSession> session;

    void SetUp() override {
        router = std::make_unique<Router>();
        session = std::make_shared<MockSession>();
        session->reset();

        // Set up test routes
        router->GET("/api/users", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "List of users";
        });

        router->GET("/api/users/:id", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "User: " + ctx.param("id");
        });

        router->POST("/api/users", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_CREATED;
            ctx.response.body() = "User created";
        });

        router->PUT("/api/users/:id", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "User updated: " + ctx.param("id");
        });

        router->DELETE("/api/users/:id", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_NO_CONTENT;
        });

        // Routes for testing authenticated content
        router->GET("/authenticated", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Authenticated content";
            ctx.response.add_header("Set-Cookie", "session=123456; Path=/; HttpOnly");
        });

        // Route for testing origin echo
        router->GET("/origin-echo", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Origin: " + ctx.request.header("Origin");
        });
    }

    void TearDown() override {
        router.reset();
    }

    Request createRequest(http_method method, const std::string& path, 
                         const std::string& origin = "") {
        Request req;
        req.method = method;
        req._uri = qb::io::uri(path);

        if (!origin.empty()) {
            req.add_header("Origin", origin);
        }

        return req;
    }

    Request createPreflightRequest(const std::string& path, const std::string& origin,
                                 const std::string& method,
                                 const std::vector<std::string>& headers = {}) {
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
    
    // Helper method to test a direct Cors instance without router
    void testDirectCors(const CorsOptions& options, const Request& req) {
        Context ctx(session, Request(req));
        Cors cors(options);
        
        // Apply CORS processing
        bool should_continue = cors.apply(ctx);
        
        // If it's a preflight request, we should handle it differently
        if (req.method == HTTP_OPTIONS && 
            !req.header("Access-Control-Request-Method").empty()) {
            EXPECT_FALSE(should_continue); // Should not continue processing
            // No need to check ctx.is_handled() as that's an implementation detail
            
            // Send the response directly
            *session << ctx.response;
        } else {
            EXPECT_TRUE(should_continue);
            // Send the response if we should continue
            *session << ctx.response;
        }
    }
};

//
// PART 1: Basic CORS Tests
//

TEST_F(CorsTest, DefaultCorsConfiguration) {
    // Use direct CORS instead of router->enable_cors
    auto cors = Cors(CorsOptions());
    router->use(cors.middleware());

    // Create a request with an origin
    auto req = createRequest(HTTP_GET, "/api/users", "https://example.com");

    // Route the request
    router->route(session, req);

    // Check that the CORS headers were added
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "*");
    EXPECT_EQ(session->body(), "List of users");
}

TEST_F(CorsTest, CustomOrigins) {
    // Use direct CORS instead of router->enable_cors
    auto cors = Cors(CorsOptions().origins({"https://example.com", "https://api.example.com"}));
    router->use(cors.middleware());

    // Test with allowed origin
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://example.com");

    // Reset session for next test
    session->reset();

    // Test with another allowed origin
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://api.example.com");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://api.example.com");

    // Reset session for next test
    session->reset();

    // Test with non-allowed origin
    auto req3 = createRequest(HTTP_GET, "/api/users", "https://attacker.com");
    router->route(session, req3);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
}

TEST_F(CorsTest, PreflightRequest) {
    // Use direct CORS instead of router->enable_cors
    auto cors = Cors(
        CorsOptions()
            .origins({"https://example.com"})
            .methods({"GET", "POST", "PUT", "DELETE"})
            .headers({"X-Custom-Header", "Content-Type", "Authorization"})
            .age(3600));
    router->use(cors.middleware());

    // Create a preflight (OPTIONS) request
    auto req = createPreflightRequest("/api/users", "https://example.com", "POST",
                                    {"X-Custom-Header", "Content-Type"});

    // Route the request
    router->route(session, req);

    // Check the preflight response
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://example.com");
    EXPECT_EQ(session->header("Access-Control-Allow-Methods"), "GET, POST, PUT, DELETE");
    EXPECT_EQ(session->header("Access-Control-Allow-Headers"),
            "X-Custom-Header, Content-Type, Authorization");
    EXPECT_EQ(session->header("Access-Control-Max-Age"), "3600");
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_NO_CONTENT);
}

TEST_F(CorsTest, Credentials) {
    // Use direct CORS instead of router->enable_cors
    auto cors = Cors(CorsOptions()
                   .origins({"https://example.com"})
                   .credentials(CorsOptions::AllowCredentials::Yes));
    router->use(cors.middleware());

    // Create a request with an origin
    auto req = createRequest(HTTP_GET, "/authenticated", "https://example.com");

    // Route the request
    router->route(session, req);

    // Check for credentials header
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://example.com");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");
    // Ensure we're not using wildcard with credentials
    EXPECT_NE(session->header("Access-Control-Allow-Origin"), "*");
}

//
// PART 2: Advanced CORS Tests
//

TEST_F(CorsTest, RegexPatternMatching) {
    // Use direct CORS with patterns instead of router->enable_cors_with_patterns
    auto cors = Cors({
        R"(^https:\/\/([a-zA-Z0-9-]+)\.example\.com$)", // subdomains of example.com
        R"(^https:\/\/app\.example\.(com|org|net)$)"    // app.example.com/org/net
    });
    router->use(cors.middleware());

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
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://frontend.example.com");

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

TEST_F(CorsTest, WildcardOriginWithCredentials) {
    // Use direct CORS instead of router->enable_cors
    auto cors = Cors(CorsOptions().credentials(CorsOptions::AllowCredentials::Yes));
    router->use(cors.middleware());

    // Create a request with an origin
    auto req = createRequest(HTTP_GET, "/api/users", "https://example.com");

    // Route the request
    router->route(session, req);

    // With credentials, even with wildcard origin, we should get the specific origin back
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://example.com");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");
}

TEST_F(CorsTest, ExposeHeadersTest) {
    // Use direct CORS instead of router->enable_cors
    auto cors = Cors(
        CorsOptions()
            .origins({"https://example.com"})
            .expose({"X-Custom-Header", "X-Powered-By", "X-Rate-Limit"}));
    router->use(cors.middleware());

    // Create a request with an origin
    auto req = createRequest(HTTP_GET, "/api/users", "https://example.com");

    // Route the request
    router->route(session, req);

    // Check for exposed headers
    EXPECT_EQ(session->header("Access-Control-Expose-Headers"),
            "X-Custom-Header, X-Powered-By, X-Rate-Limit");
}

TEST_F(CorsTest, VaryHeader) {
    // Use direct CORS instead of router->enable_cors
    auto cors = Cors(CorsOptions().origins({"https://app.example.com"}));
    router->use(cors.middleware());

    // Create a request with an origin
    auto req = createRequest(HTTP_GET, "/api/users", "https://app.example.com");

    // Route the request
    router->route(session, req);

    // Check that the Vary header was added
    EXPECT_EQ(session->header("Vary"), "Origin");

    // Reset session
    session->reset();

    // Create a preflight request with headers
    auto preflight = createPreflightRequest("/api/users", "https://app.example.com", "GET",
                                         {"Content-Type", "Authorization"});

    // Route the preflight request
    router->route(session, preflight);

    // Check that the Vary header includes Access-Control-Request-Headers
    EXPECT_EQ(session->header("Vary"), "Origin, Access-Control-Request-Headers");
}

//
// PART 3: Direct Cors Class Usage Tests
//

TEST_F(CorsTest, DirectCorsUsage) {
    // Create a CORS handler with specific allowed origins
    CorsOptions options;
    options.origins({"https://example.com", "https://api.example.com"});
    
    // Test with allowed origin
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://example.com");
    testDirectCors(options, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://example.com");
    
    // Reset session
    session->reset();
    
    // Test with non-allowed origin
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://attacker.com");
    testDirectCors(options, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
    
    // Reset session
    session->reset();
    
    // Test preflight request
    auto req3 = createPreflightRequest("/api/users", "https://example.com", "POST", {"Content-Type"});
    testDirectCors(options, req3);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://example.com");
}

TEST_F(CorsTest, CorsMiddlewareUsage) {
    // Create a CORS handler with specific allowed origins
    CorsOptions options;
    options.origins({"https://example.com"})
           .methods({"GET", "POST", "PUT", "DELETE"})
           .headers({"Content-Type", "Authorization"})
           .credentials(CorsOptions::AllowCredentials::Yes);
    
    // Get middleware function and add it to router
    auto cors = Cors(options);
    router->use(cors.middleware());
    
    // Test with allowed origin
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://example.com");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");
    
    // Reset session
    session->reset();
    
    // Test preflight request
    auto req2 = createPreflightRequest("/api/users", "https://example.com", "POST", {"Content-Type"});
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://example.com");
    EXPECT_EQ(session->header("Access-Control-Allow-Methods"), "GET, POST, PUT, DELETE");
}

TEST_F(CorsTest, CorsFactoryMethods) {
    // Test using the static factory methods
    
    // Dev CORS
    auto dev_cors = Cors::dev();
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://localhost:3000");
    
    Context ctx1(session, std::move(req1));
    dev_cors.apply(ctx1);
    *session << ctx1.response;
    
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://localhost:3000");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");
    
    // Reset session
    session->reset();
    
    // Secure CORS
    auto secure_cors = Cors::secure({"https://app.example.com"});
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://app.example.com");
    
    Context ctx2(session, std::move(req2));
    secure_cors.apply(ctx2);
    *session << ctx2.response;
    
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app.example.com");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");
    
    // Reset session
    session->reset();
    
    // Testing with non-allowed origin in secure mode
    auto req3 = createRequest(HTTP_GET, "/api/users", "https://evil.com");
    
    Context ctx3(session, std::move(req3));
    secure_cors.apply(ctx3);
    *session << ctx3.response;
    
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
}

//
// PART 4: Comprehensive CORS Tests
//

TEST_F(CorsTest, CustomOriginMatcher) {
    // Create a custom origin matcher function
    std::function<bool(const std::string&)> matcher = [](const std::string& origin) {
        // Only allow origins from specific environments
        return origin == "https://app.example.com" ||
               origin.find("localhost") != std::string::npos ||
               origin.find("-dev.example.com") != std::string::npos ||
               origin.find("-staging.example.com") != std::string::npos;
    };

    // Use direct CORS instead of router->enable_cors
    auto cors = Cors(CorsOptions()
                   .origin_matcher(matcher)
                   .methods({"GET", "POST", "PUT", "DELETE"})
                   .headers({"Content-Type", "Authorization"})
                   .credentials(CorsOptions::AllowCredentials::Yes));
    router->use(cors.middleware());

    // Test with production origin
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://app.example.com");
    router->route(session, req1);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app.example.com");

    // Reset session
    session->reset();

    // Test with development origin
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://feature123-dev.example.com");
    router->route(session, req2);
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://feature123-dev.example.com");

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

TEST_F(CorsTest, DynamicConfigurationTest) {
    // Initialize with one configuration
    CorsOptions initial_options;
    initial_options.origins({"https://app-v1.example.com"});
    
    Cors cors(initial_options);
    
    // Test initial configuration
    auto req1 = createRequest(HTTP_GET, "/api/users", "https://app-v1.example.com");
    Context ctx1(session, std::move(req1));
    cors.apply(ctx1);
    *session << ctx1.response;
    
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app-v1.example.com");
    
    // Reset session
    session->reset();
    
    // Update configuration dynamically
    CorsOptions new_options;
    new_options.origins({"https://app-v2.example.com"})
             .credentials(CorsOptions::AllowCredentials::Yes);
    
    cors.update_options(new_options);
    
    // Test new configuration
    auto req2 = createRequest(HTTP_GET, "/api/users", "https://app-v2.example.com");
    Context ctx2(session, std::move(req2));
    cors.apply(ctx2);
    *session << ctx2.response;
    
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "https://app-v2.example.com");
    EXPECT_EQ(session->header("Access-Control-Allow-Credentials"), "true");
    
    // Reset session
    session->reset();
    
    // Previous origin should no longer work
    auto req3 = createRequest(HTTP_GET, "/api/users", "https://app-v1.example.com");
    Context ctx3(session, std::move(req3));
    cors.apply(ctx3);
    *session << ctx3.response;
    
    EXPECT_EQ(session->header("Access-Control-Allow-Origin"), "");
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
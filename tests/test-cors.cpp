#include <gtest/gtest.h>
#include "../router.h"
#include <memory>
#include <string>
#include <iostream>
#include <map>
#include <regex>

// Mock session for testing
class MockSession {
public:
    qb::http::Response _response;
    bool _closed = false;
    std::vector<qb::http::Response> _responses;
    std::map<std::string, std::string> _cors_headers;
    std::string _captured_body;
    
    // Required by Router to send responses
    MockSession& operator<<(qb::http::Response resp) {
        std::cout << "MockSession received response" << std::endl;
        
        // Capture CORS headers before move
        if (resp.headers().find("Access-Control-Allow-Origin") != resp.headers().end()) {
            _cors_headers["Access-Control-Allow-Origin"] = resp.header("Access-Control-Allow-Origin");
            std::cout << "Captured Access-Control-Allow-Origin: " << _cors_headers["Access-Control-Allow-Origin"] << std::endl;
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
    
    bool is_connected() const {
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
    
    size_t responseCount() const {
        return _responses.size();
    }
    
    qb::http::Response& response() {
        return _response;
    }
    
    void printHeaders() const {
        std::cout << "Captured CORS headers:" << std::endl;
        for (const auto& [key, value] : _cors_headers) {
            std::cout << "  " << key << ": " << value << std::endl;
        }
        std::cout << "Captured body: " << _captured_body << std::endl;
    }
    
    // Helper to get CORS headers
    std::string header(const std::string& name) const {
        auto it = _cors_headers.find(name);
        if (it != _cors_headers.end()) {
            return it->second;
        }
        return "";
    }
    
    // Helper to get body
    std::string body() const {
        return _captured_body;
    }
};

class CorsTest : public ::testing::Test {
protected:
    using Router = qb::http::TRequest<std::string>::Router<MockSession>;
    using Request = qb::http::TRequest<std::string>;
    std::unique_ptr<Router> router;
    MockSession session;
    
    void SetUp() override {
        router = std::make_unique<Router>();
        session.reset();
        
        // Set up a basic GET route
        router->GET("/test", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Test successful";
        });

        // Add a route that returns different data based on Origin
        router->GET("/origin-echo", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Origin: " + ctx.request.header("Origin");
        });

        // Add a route that requires authentication (for CORS with credentials tests)
        router->GET("/authenticated", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Authenticated content";
            ctx.response.add_header("Set-Cookie", "session=123456; Path=/; HttpOnly");
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

    Request createPreflightRequest(const std::string& path,
                               const std::string& origin,
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
};

TEST_F(CorsTest, DefaultCorsConfiguration) {
    // Enable CORS with default options
    router->enable_cors(qb::http::CorsOptions());
    
    // Create a request with an origin
    auto req = createRequest(HTTP_GET, "/test", "https://example.com");
    
    // Route the request
    router->route(session, req);
    
    // Print headers for debugging
    std::cout << "DefaultCorsConfiguration test:" << std::endl;
    session.printHeaders();
    
    // Check that the CORS headers were added
    EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "*");
    EXPECT_EQ(session.body(), "Test successful");
}

TEST_F(CorsTest, CustomOrigins) {
    // Enable CORS with specific allowed origins
    router->enable_cors(qb::http::CorsOptions()
        .origins({"https://example.com", "https://api.example.com"}));
    
    // Test with allowed origin
    auto req1 = createRequest(HTTP_GET, "/test", "https://example.com");
    router->route(session, req1);
    EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "https://example.com");
    
    // Reset session for next test
    session.reset();
    
    // Test with another allowed origin
    auto req2 = createRequest(HTTP_GET, "/test", "https://api.example.com");
    router->route(session, req2);
    EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "https://api.example.com");
    
    // Reset session for next test
    session.reset();
    
    // Test with non-allowed origin
    auto req3 = createRequest(HTTP_GET, "/test", "https://attacker.com");
    router->route(session, req3);
    EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "");
}

TEST_F(CorsTest, PreflightRequest) {
    // Enable CORS with custom settings
    router->enable_cors(qb::http::CorsOptions()
        .origins({"https://example.com"})
        .methods({"GET", "POST", "PUT", "DELETE"})
        .headers({"X-Custom-Header", "Content-Type", "Authorization"})
        .age(3600));
    
    // Create a preflight (OPTIONS) request
    auto req = createPreflightRequest("/test", "https://example.com", "POST", 
                                 {"X-Custom-Header", "Content-Type"});
    
    // Route the request
    router->route(session, req);
    
    // Check the preflight response
    EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "https://example.com");
    EXPECT_EQ(session.header("Access-Control-Allow-Methods"), "GET, POST, PUT, DELETE");
    EXPECT_EQ(session.header("Access-Control-Allow-Headers"), "X-Custom-Header, Content-Type, Authorization");
    EXPECT_EQ(session.header("Access-Control-Max-Age"), "3600");
    EXPECT_EQ(session.response().status_code, HTTP_STATUS_NO_CONTENT);
}

TEST_F(CorsTest, Credentials) {
    // Enable CORS with credentials allowed
    router->enable_cors(qb::http::CorsOptions()
        .origins({"https://example.com"})
        .credentials(qb::http::CorsOptions::AllowCredentials::Yes));
    
    // Create a request with an origin
    auto req = createRequest(HTTP_GET, "/authenticated", "https://example.com");
    
    // Route the request
    router->route(session, req);
    
    // Check for credentials header
    EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "https://example.com");
    EXPECT_EQ(session.header("Access-Control-Allow-Credentials"), "true");
    // Ensure we're not using wildcard with credentials
    EXPECT_NE(session.header("Access-Control-Allow-Origin"), "*");
}

TEST_F(CorsTest, ExposedHeaders) {
    // Enable CORS with exposed headers
    router->enable_cors(qb::http::CorsOptions()
        .origins({"https://example.com"})
        .expose({"X-Custom-Header", "X-Powered-By", "X-Rate-Limit"}));
    
    // Create a request with an origin
    auto req = createRequest(HTTP_GET, "/test", "https://example.com");
    
    // Route the request
    router->route(session, req);
    
    // Check for exposed headers
    EXPECT_EQ(session.header("Access-Control-Expose-Headers"), "X-Custom-Header, X-Powered-By, X-Rate-Limit");
}

TEST_F(CorsTest, OptionsRouteWithoutOrigin) {
    // Enable CORS with default settings
    router->enable_cors(qb::http::CorsOptions());
    
    // Create an OPTIONS request without Origin header
    auto req = createRequest(HTTP_OPTIONS, "/test");
    
    // Route the request - should not be handled by CORS middleware
    router->route(session, req);
    
    // Check that no CORS headers were added
    EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "");
}

TEST_F(CorsTest, WildcardVsExplicitOrigin) {
    // Test with wildcard origin but requesting credentials (should narrow the origin)
    router->enable_cors(qb::http::CorsOptions()
        .credentials(qb::http::CorsOptions::AllowCredentials::Yes));
    
    // Create a request with an origin
    auto req = createRequest(HTTP_GET, "/test", "https://example.com");
    
    // Route the request
    router->route(session, req);
    
    // With credentials, even with wildcard origin, we should get the specific origin back
    EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "https://example.com");
    EXPECT_EQ(session.header("Access-Control-Allow-Credentials"), "true");
}

TEST_F(CorsTest, RegexOriginMatching) {
    // Enable CORS with a custom CorsOptions that supports regex pattern matching
    router = std::make_unique<Router>();
    session.reset();
    
    // Set up a basic GET route
    router->GET("/test", [](auto& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Test successful";
    });
    
    // Custom middleware to support regex pattern matching for origins
    router->use([](auto& ctx) {
        const auto& origin = ctx.request.header("Origin");
        
        if (!origin.empty()) {
            // Define regex patterns for allowed origins
            std::regex subdomain_pattern(R"(^https:\/\/([a-zA-Z0-9-]+)\.example\.com$)");
            
            if (std::regex_match(origin, subdomain_pattern)) {
                ctx.response.add_header("Access-Control-Allow-Origin", origin);
                ctx.response.add_header("Access-Control-Allow-Credentials", "true");
                
                if (ctx.request.method == HTTP_OPTIONS) {
                    const auto& request_method = ctx.request.header("Access-Control-Request-Method");
                    if (!request_method.empty()) {
                        ctx.response.add_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
                        ctx.response.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
                        ctx.response.add_header("Access-Control-Max-Age", "3600");
                        ctx.response.status_code = HTTP_STATUS_NO_CONTENT;
                        return false;
                    }
                }
            }
        }
        
        return true;
    });
    
    // Test with a matching subdomain
    auto req1 = createRequest(HTTP_GET, "/test", "https://api.example.com");
    router->route(session, req1);
    EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "https://api.example.com");
    EXPECT_EQ(session.header("Access-Control-Allow-Credentials"), "true");
    
    // Reset session
    session.reset();
    
    // Test with another matching subdomain
    auto req2 = createRequest(HTTP_GET, "/test", "https://user123.example.com");
    router->route(session, req2);
    EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "https://user123.example.com");
    
    // Reset session
    session.reset();
    
    // Test with non-matching origin
    auto req3 = createRequest(HTTP_GET, "/test", "https://example.org");
    router->route(session, req3);
    EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "");
}

TEST_F(CorsTest, DifferentRequestMethods) {
    // Enable CORS for all methods
    router->enable_cors(qb::http::CorsOptions()
        .origins({"https://example.com"})
        .methods({"GET", "POST", "PUT", "DELETE", "PATCH"}));
    
    // Add routes for different methods
    router->POST("/test", [](auto& ctx) {
        ctx.response.status_code = HTTP_STATUS_CREATED;
        ctx.response.body() = "Created successfully";
    });
    
    router->PUT("/test", [](auto& ctx) {
        ctx.response.status_code = HTTP_STATUS_OK;
        ctx.response.body() = "Updated successfully";
    });
    
    router->DELETE("/test", [](auto& ctx) {
        ctx.response.status_code = HTTP_STATUS_NO_CONTENT;
    });
    
    // Test each method
    for (auto method : {HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_DELETE}) {
        session.reset();
        auto req = createRequest(method, "/test", "https://example.com");
        router->route(session, req);
        EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "https://example.com");
    }
    
    // Test preflight for each method
    for (const auto& method_str : {"GET", "POST", "PUT", "DELETE", "PATCH"}) {
        session.reset();
        auto req = createPreflightRequest("/test", "https://example.com", method_str);
        router->route(session, req);
        EXPECT_EQ(session.header("Access-Control-Allow-Origin"), "https://example.com");
        EXPECT_EQ(session.header("Access-Control-Allow-Methods"), "GET, POST, PUT, DELETE, PATCH");
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
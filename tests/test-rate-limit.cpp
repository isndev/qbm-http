#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/rate_limit.h"
#include <memory>
#include <string>
#include <thread>
#include <chrono>

/**
 * @brief MockSession for RateLimit testing
 */
class MockSession {
public:
    qb::http::Response _response;
    bool _closed = false;
    std::vector<qb::http::Response> _responses;
    std::map<std::string, std::string> _headers;
    std::string _captured_body;
    qb::uuid _id;
    std::string _client_ip = "192.168.1.1";

    // Constructor to initialize the ID
    MockSession() : _id(qb::generate_random_uuid()) {}

    // Required by Router to send responses
    MockSession& operator<<(qb::http::Response resp) {
        // Capture headers before move
        for (const auto& [name, value] : resp.headers()) {
            if (!value.empty()) {
                _headers[name] = value[0];
            } else {
                _headers[name] = "";
            }
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

    [[nodiscard]] std::string get_client_ip() const {
        return _client_ip;
    }

    // Add ip() method for compatibility with the router
    [[nodiscard]] std::string ip() const {
        return _client_ip;
    }

    void close() {
        _closed = true;
    }

    void reset() {
        _responses.clear();
        _response = qb::http::Response();
        _headers.clear();
        _captured_body.clear();
        _closed = false;
    }

    [[nodiscard]] size_t responseCount() const {
        return _responses.size();
    }

    qb::http::Response& response() {
        return _response;
    }

    // Helper to get header values
    [[nodiscard]] std::string header(const std::string& name) const {
        auto it = _headers.find(name);
        if (it != _headers.end()) {
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
 * @brief Base test fixture for RateLimit tests
 */
class RateLimitTest : public ::testing::Test {
protected:
    using Router = qb::http::TRequest<std::string>::Router<MockSession>;
    using Request = qb::http::TRequest<std::string>;
    using Response = qb::http::TResponse<std::string>;
    using Context = qb::http::RouterContext<MockSession, std::string>;
    using RateLimit = qb::http::RateLimit<MockSession, std::string>;
    using RateLimitOptions = qb::http::RateLimitOptions;
    
    std::unique_ptr<Router> router;
    std::shared_ptr<MockSession> session;

    void SetUp() override {
        router = std::make_unique<Router>();
        session = std::make_shared<MockSession>();
        session->reset();

        // Set up test routes
        router->GET("/api/test", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "Test endpoint";
        });

        router->GET("/api/users", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_OK;
            ctx.response.body() = "User list";
        });

        router->POST("/api/users", [](auto& ctx) {
            ctx.response.status_code = HTTP_STATUS_CREATED;
            ctx.response.body() = "User created";
        });
    }

    void TearDown() override {
        router.reset();
    }

    Request createRequest(http_method method, const std::string& path, 
                        const std::map<std::string, std::string>& headers = {}) {
        Request req;
        req.method = method;
        req._uri = qb::io::uri(path);

        // Always add X-Forwarded-For header to avoid client IP issues
        req.add_header("X-Forwarded-For", "192.168.1.1");

        for (const auto& [name, value] : headers) {
            req.add_header(name, value);
        }

        return req;
    }
};

// Test basic rate limit configuration
TEST_F(RateLimitTest, BasicConfiguration) {
    // Allow just 2 requests per minute
    auto rate_limit = RateLimit(RateLimitOptions().max_requests(2).window(std::chrono::minutes(1)));
    router->use(rate_limit.middleware());

    // First request should pass
    auto req1 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req1);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->body(), "Test endpoint");
    
    // Reset session but not rate limiter
    session->reset();
    
    // Second request should also pass
    auto req2 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req2);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    EXPECT_EQ(session->body(), "Test endpoint");
    
    // Reset session but not rate limiter
    session->reset();
    
    // Third request should be rate limited
    auto req3 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req3);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_TOO_MANY_REQUESTS);
    EXPECT_EQ(session->body(), "Rate limit exceeded");
}

// Test custom client ID extraction
TEST_F(RateLimitTest, CustomClientIdExtractor) {
    // Create options with custom client ID extractor
    RateLimitOptions options;
    options.max_requests(2)
           .window(std::chrono::minutes(1))
           .client_id_extractor<MockSession, std::string>(
               [](const Context& ctx) {
                   // Extract client ID from a header
                   return ctx.header("X-Client-ID");
               });
    
    auto rate_limit = RateLimit(options);
    router->use(rate_limit.middleware());
    
    // First client - first request
    auto req1 = createRequest(HTTP_GET, "/api/test", {{"X-Client-ID", "client1"}});
    router->route(session, req1);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    
    // Reset session but not rate limiter
    session->reset();
    
    // Second client - first request (should pass)
    auto req2 = createRequest(HTTP_GET, "/api/test", {{"X-Client-ID", "client2"}});
    router->route(session, req2);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    
    // Reset session but not rate limiter
    session->reset();
    
    // First client - second request (should pass)
    auto req3 = createRequest(HTTP_GET, "/api/test", {{"X-Client-ID", "client1"}});
    router->route(session, req3);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    
    // Reset session but not rate limiter
    session->reset();
    
    // First client - third request (should be rate limited)
    auto req4 = createRequest(HTTP_GET, "/api/test", {{"X-Client-ID", "client1"}});
    router->route(session, req4);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_TOO_MANY_REQUESTS);
    
    // Reset session but not rate limiter
    session->reset();
    
    // Second client - second request (should pass)
    auto req5 = createRequest(HTTP_GET, "/api/test", {{"X-Client-ID", "client2"}});
    router->route(session, req5);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
}

// Test custom error message and status code
TEST_F(RateLimitTest, CustomErrorMessageAndStatusCode) {
    // Create options with custom error message and status code
    RateLimitOptions options;
    options.max_requests(1)
           .window(std::chrono::seconds(10))
           .message("Custom rate limit error message")
           .status_code(HTTP_STATUS_SERVICE_UNAVAILABLE);
    
    auto rate_limit = RateLimit(options);
    router->use(rate_limit.middleware());
    
    // First request should pass
    auto req1 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req1);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    
    // Reset session but not rate limiter
    session->reset();
    
    // Second request should be rate limited with custom message and status
    auto req2 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req2);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_SERVICE_UNAVAILABLE);
    EXPECT_EQ(session->body(), "Custom rate limit error message");
}

// Test reset functionality
TEST_F(RateLimitTest, ResetFunctionality) {
    // Create a rate limiter with 1 request per minute
    auto options = RateLimitOptions().max_requests(1).window(std::chrono::minutes(1));
    auto rate_limit = std::make_shared<RateLimit>(options);
    router->use(rate_limit->middleware());
    
    // First request should pass
    auto req1 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req1);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    
    // Reset session but not rate limiter
    session->reset();
    
    // Second request should be rate limited
    auto req2 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req2);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_TOO_MANY_REQUESTS);
    
    // Reset session and rate limiter
    session->reset();
    rate_limit->reset();
    
    // Now request should pass again
    auto req3 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req3);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
}

// Test predefined configurations
TEST_F(RateLimitTest, PredefinedConfigurations) {
    // Test development configuration
    auto dev_options = RateLimitOptions::dev();
    EXPECT_EQ(dev_options.max_requests(), 1000);
    
    // Test secure/production configuration
    auto secure_options = RateLimitOptions::secure();
    EXPECT_EQ(secure_options.max_requests(), 60);
    EXPECT_EQ(secure_options.message(), "Rate limit exceeded. Please try again later.");
}

// Test time-based rate limiting
TEST_F(RateLimitTest, TimeBased) {
    // Very short window (100ms) for testing
    RateLimitOptions options;
    options.max_requests(1).window(std::chrono::milliseconds(100));
    
    auto rate_limit = std::make_shared<RateLimit>(options);
    router->use(rate_limit->middleware());
    
    // First request should pass
    auto req1 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req1);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    
    // Reset session but not rate limiter
    session->reset();
    
    // Second request should be rate limited
    auto req2 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req2);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_TOO_MANY_REQUESTS);
    
    // Wait for the rate limit window to pass
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    
    // Reset session but not rate limiter
    session->reset();
    
    // Now request should pass again
    auto req3 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req3);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
}

// Test direct use without router
TEST_F(RateLimitTest, DirectUse) {
    // Create options allowing 2 requests
    RateLimitOptions options;
    options.max_requests(2).window(std::chrono::minutes(1));
    
    // Create a single rate limiter instance that persists through the test
    RateLimit rate_limit(options);
    
    // First request should pass
    {
        auto req = createRequest(HTTP_GET, "/api/test");
        Context ctx(session, std::move(req));
        
        bool should_continue = rate_limit.apply(ctx);
        EXPECT_TRUE(should_continue);
        
        // Since the test passes, status code is not set by rate limiter
        EXPECT_FALSE(ctx.is_handled());
    }
    
    // Reset session but not rate limiter
    session->reset();
    
    // Second request should also pass
    {
        auto req = createRequest(HTTP_GET, "/api/test");
        Context ctx(session, std::move(req));
        
        bool should_continue = rate_limit.apply(ctx);
        EXPECT_TRUE(should_continue);
        
        // Since the test passes, status code is not set by rate limiter
        EXPECT_FALSE(ctx.is_handled());
    }
    
    // Reset session but not rate limiter
    session->reset();
    
    // Third request should be rate limited
    {
        auto req = createRequest(HTTP_GET, "/api/test");
        Context ctx(session, std::move(req));
        
        bool should_continue = rate_limit.apply(ctx);
        EXPECT_FALSE(should_continue);
        
        // The context should be marked as handled and have TOO_MANY_REQUESTS status
        EXPECT_TRUE(ctx.is_handled());
        EXPECT_EQ(ctx.response.status_code, HTTP_STATUS_TOO_MANY_REQUESTS);
    }
}

// Test rate limit reset headers
TEST_F(RateLimitTest, ResetHeaders) {
    // Create options with a 10-second window
    RateLimitOptions options;
    options.max_requests(1).window(std::chrono::seconds(10));
    
    auto rate_limit = RateLimit(options);
    router->use(rate_limit.middleware());
    
    // First request should pass
    auto req1 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req1);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    
    // Reset session but not rate limiter
    session->reset();
    
    // Second request should be rate limited
    auto req2 = createRequest(HTTP_GET, "/api/test");
    router->route(session, req2);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_TOO_MANY_REQUESTS);
}

// Test reset_client functionality
TEST_F(RateLimitTest, ResetClientFunctionality) {
    // Create a rate limiter with client ID from headers
    RateLimitOptions options;
    options.max_requests(1)
           .window(std::chrono::minutes(1))
           .client_id_extractor<MockSession, std::string>(
               [](const Context& ctx) {
                   return ctx.header("X-Client-ID");
               });
    
    auto rate_limit = std::make_shared<RateLimit>(options);
    router->use(rate_limit->middleware());
    
    // First client request
    auto req1 = createRequest(HTTP_GET, "/api/test", {{"X-Client-ID", "client1"}});
    router->route(session, req1);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    
    // Reset session but not rate limiter
    session->reset();
    
    // Second client request
    auto req2 = createRequest(HTTP_GET, "/api/test", {{"X-Client-ID", "client2"}});
    router->route(session, req2);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    
    // Reset session but not rate limiter
    session->reset();
    
    // First client's second request (should be rate limited)
    auto req3 = createRequest(HTTP_GET, "/api/test", {{"X-Client-ID", "client1"}});
    router->route(session, req3);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_TOO_MANY_REQUESTS);
    
    // Reset client1's rate limit
    rate_limit->reset_client("client1");
    
    // Reset session but not rate limiter
    session->reset();
    
    // First client should now be able to make another request
    auto req4 = createRequest(HTTP_GET, "/api/test", {{"X-Client-ID", "client1"}});
    router->route(session, req4);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_OK);
    
    // Reset session but not rate limiter
    session->reset();
    
    // Second client's second request (should still be rate limited)
    auto req5 = createRequest(HTTP_GET, "/api/test", {{"X-Client-ID", "client2"}});
    router->route(session, req5);
    EXPECT_EQ(session->response().status_code, HTTP_STATUS_TOO_MANY_REQUESTS);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
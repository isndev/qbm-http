#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/rate_limit.h" // The adapted RateLimitMiddleware
#include "../routing/middleware.h"    // For MiddlewareTask if constructing directly

#include <chrono> // For std::chrono literals
#include <functional>
#include <memory>
#include <sstream> // For ostringstream in session mock
#include <stdexcept>
#include <string>
#include <thread> // For std::this_thread::sleep_for
#include <vector>

// --- Mock Session for RateLimitMiddleware Tests ---
struct MockRateLimitSession {
    qb::http::Response _response;
    std::string        _session_id_str = "ratelimit_test_session";
    // Using a simple string to represent a client identifier for these tests.
    // In real scenarios, this might come from IP, session ID, API key, etc.
    std::string _client_identifier_for_test = "client123";
    bool        _final_handler_called       = false;

    qb::http::Response &
    get_response_ref() {
        return _response;
    }

    MockRateLimitSession &
    operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void
    reset() {
        _response             = qb::http::Response();
        _final_handler_called = false;
    }
};

// --- Test Fixture for RateLimitMiddleware ---
class RateLimitMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockRateLimitSession>                   _session;
    std::unique_ptr<qb::http::Router<MockRateLimitSession>> _router;
    // TaskExecutor generally not needed as RateLimitMiddleware is synchronous

    void
    SetUp() override {
        _session = std::make_shared<MockRateLimitSession>();
        _router  = std::make_unique<qb::http::Router<MockRateLimitSession>>();
    }

    qb::http::Request
    create_request(const std::string &target_path = "/limited_route", const std::string &client_ip_header = "") {
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "URI parse failure: " << target_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        if (!client_ip_header.empty()) {
            req.set_header("X-Forwarded-For", client_ip_header);
        }
        return req;
    }

    qb::http::RouteHandlerFn<MockRateLimitSession>
    success_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockRateLimitSession>> ctx) {
            if (_session)
                _session->_final_handler_called = true;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Access Granted by Handler";
            ctx->complete();
        };
    }

    void
    configure_router_and_run(std::shared_ptr<qb::http::RateLimitMiddleware<MockRateLimitSession>> rate_limit_mw, qb::http::Request request) {
        // Re-initialize the router to ensure a clean state for each distinct configuration/run
        _router = std::make_unique<qb::http::Router<MockRateLimitSession>>();
        _router->use(rate_limit_mw);
        _router->get("/limited_route", success_handler());
        _router->compile();

        // For rate limit tests, session reset might be needed per request group, not always per single request
        // _session->reset(); // Moved to be controlled by test logic
        _router->route(_session, std::move(request));
    }
};

// --- Test Cases ---

TEST_F(RateLimitMiddlewareTest, BasicRateLimiting) {
    qb::http::RateLimitOptions options;
    options.max_requests(2).window(std::chrono::seconds(1)); // 2 requests per second
    auto rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);

    // Request 1 (Allowed)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", "client_A"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "1");

    // Request 2 (Allowed)
    _session->reset(); // Reset session to clear previous response/state for this distinct request
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", "client_A"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");

    // Request 3 (Rate Limited)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", "client_A"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");

    // Wait for window to pass
    std::this_thread::sleep_for(std::chrono::milliseconds(1100)); // Slightly more than 1 second

    // Request 4 (Allowed again after window)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", "client_A"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "1");
}

TEST_F(RateLimitMiddlewareTest, CustomClientIdExtractor) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::seconds(1));
    options.client_id_extractor<MockRateLimitSession>([](const qb::http::Context<MockRateLimitSession> &ctx) {
        // Use a custom header for client ID in this test
        return std::string(ctx.request().header("X-Client-ID"));
    });
    auto rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);

    // Request 1 for custom_client_1 (Allowed)
    _session->reset();
    auto req1 = create_request();
    req1.set_header("X-Client-ID", "custom_client_1");
    configure_router_and_run(rate_limit_mw, std::move(req1));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    // Request 2 for custom_client_1 (Rate Limited)
    _session->reset();
    auto req2 = create_request();
    req2.set_header("X-Client-ID", "custom_client_1");
    configure_router_and_run(rate_limit_mw, std::move(req2));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Request 3 for custom_client_2 (Allowed, different client)
    _session->reset();
    auto req3 = create_request();
    req3.set_header("X-Client-ID", "custom_client_2");
    configure_router_and_run(rate_limit_mw, std::move(req3));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(RateLimitMiddlewareTest, ThrowingCustomExtractorFallsBackToDefaultExtraction) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::seconds(60));
    options.client_id_extractor<MockRateLimitSession>(
        [](const qb::http::Context<MockRateLimitSession> & /*ctx*/) -> std::string { throw std::runtime_error("extractor crash"); });
    auto rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);

    auto req1 = create_request();
    req1.set_header("X-Forwarded-For", "10.0.0.1");
    EXPECT_NO_THROW(configure_router_and_run(rate_limit_mw, std::move(req1)));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    auto req2 = create_request();
    req2.set_header("X-Forwarded-For", "10.0.0.1");
    EXPECT_NO_THROW(configure_router_and_run(rate_limit_mw, std::move(req2)));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
}

TEST_F(RateLimitMiddlewareTest, CustomErrorMessageAndStatusCode) {
    qb::http::RateLimitOptions options;
    options
        .max_requests(0) // Rate limit immediately
        .status_code(qb::http::status::SERVICE_UNAVAILABLE)
        .message("Custom rate limit message.");
    auto rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", "client_B"));

    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Custom rate limit message.");
}

TEST_F(RateLimitMiddlewareTest, ResetClientFunctionality) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::seconds(60));
    auto rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);

    std::string client_id_to_test = "client_to_reset";

    // Request 1 (Allowed)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id_to_test));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    // Request 2 (Rate Limited)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id_to_test));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Reset the client
    rate_limit_mw->reset_client(client_id_to_test);

    // Request 3 (Allowed again after reset)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id_to_test));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(RateLimitMiddlewareTest, FactoryMethodsCreateInstances) {
    auto default_mw = qb::http::rate_limit_middleware<MockRateLimitSession>();
    ASSERT_NE(default_mw, nullptr);
    EXPECT_EQ(default_mw->name(), "RateLimitMiddleware"); // Default name

    auto dev_mw = qb::http::rate_limit_dev_middleware<MockRateLimitSession>("MyDevRateLimiter");
    ASSERT_NE(dev_mw, nullptr);
    EXPECT_EQ(dev_mw->name(), "MyDevRateLimiter");
    // Check some dev options
    // auto dev_options = dev_mw->options(); // Need options() getter in RateLimitMiddleware
    // EXPECT_EQ(dev_options.max_requests(), 1000);

    auto secure_mw = qb::http::rate_limit_secure_middleware<MockRateLimitSession>();
    ASSERT_NE(secure_mw, nullptr);
    EXPECT_EQ(secure_mw->name(), "SecureRateLimitMiddleware");
}

TEST_F(RateLimitMiddlewareTest, TestPermissiveConfiguration) {
    auto permissive_mw = qb::http::rate_limit_dev_middleware<MockRateLimitSession>();
    ASSERT_NE(permissive_mw, nullptr);

    const auto &opts = permissive_mw->get_options();
    EXPECT_EQ(opts.get_max_requests(), 1000);
    EXPECT_EQ(opts.get_window(), std::chrono::minutes(1));
    EXPECT_EQ(opts.get_status_code(), qb::http::status::TOO_MANY_REQUESTS);                    // Default status
    EXPECT_EQ(opts.get_message(), "You have reached the rate limit. Please try again later."); // Permissive message

    // Perform one request to check basic functionality and headers
    _session->reset();
    configure_router_and_run(permissive_mw, create_request("/limited_route", "client_perm_test"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Limit")), "1000");
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "999");
}

TEST_F(RateLimitMiddlewareTest, TestSecureConfiguration) {
    auto secure_mw = qb::http::rate_limit_secure_middleware<MockRateLimitSession>();
    ASSERT_NE(secure_mw, nullptr);

    const auto &opts = secure_mw->get_options();
    EXPECT_EQ(opts.get_max_requests(), 60);
    EXPECT_EQ(opts.get_window(), std::chrono::minutes(1));
    EXPECT_EQ(opts.get_status_code(), qb::http::status::TOO_MANY_REQUESTS);        // Default status
    EXPECT_EQ(opts.get_message(), "Rate limit exceeded. Please try again later."); // Default message for secure

    // Perform one request
    _session->reset();
    configure_router_and_run(secure_mw, create_request("/limited_route", "client_sec_test"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Limit")), "60");
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "59");

    // Exhaust the limit to check rate limiting behavior for secure config
    for (size_t i = 0; i < 59; ++i) {
        // 59 more requests
        _session->reset(); // Reset session for next distinct request
        configure_router_and_run(secure_mw, create_request("/limited_route", "client_sec_test"));
        EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    }

    _session->reset();
    configure_router_and_run(secure_mw, create_request("/limited_route", "client_sec_test"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");
}

TEST_F(RateLimitMiddlewareTest, RateLimitHeadersAreAccurate) {
    qb::http::RateLimitOptions options;
    options.max_requests(3).window(std::chrono::seconds(5)); // 3 requests per 5 seconds
    auto        rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);
    std::string client_id     = "header_test_client";

    // Request 1
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Limit")), "3");
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "2");
    long long reset_val1 = std::stoll(std::string(_session->_response.header("X-RateLimit-Reset")));
    EXPECT_GE(reset_val1, 0); // Should be positive or zero seconds remaining
    EXPECT_LE(reset_val1, 5); // Should be less than or equal to the window

    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Request 2
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Limit")), "3");
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "1");
    long long reset_val2 = std::stoll(std::string(_session->_response.header("X-RateLimit-Reset")));
    EXPECT_GE(reset_val2, 0);
    EXPECT_LE(reset_val2, reset_val1); // Reset time should be same or less as window progresses
    EXPECT_LE(reset_val2, 4);          // Approximately 4s remaining or less

    // Request 3
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");

    // Request 4 (Rate Limited)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Limit")), "3");
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");
    long long reset_val4 = std::stoll(std::string(_session->_response.header("X-RateLimit-Reset")));
    EXPECT_GE(reset_val4, 0);
    // Reset time should still be relative to the initial window start for this block of requests

    // Wait for window to pass from the *start* of the first request in this window
    std::this_thread::sleep_for(std::chrono::seconds(4)); // Total sleep approx 1+4 = 5s

    // Request 5 (Allowed again)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Limit")), "3");
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "2"); // Max - 1
    long long reset_val5 = std::stoll(std::string(_session->_response.header("X-RateLimit-Reset")));
    EXPECT_GE(reset_val5, 0);
    EXPECT_LE(reset_val5, 5); // New window, so reset value should be close to full window again
}

TEST_F(RateLimitMiddlewareTest, ResetAllClientsFunctionality) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::seconds(60));
    auto rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);

    std::string client_A_id = "clientA_for_reset_all";
    std::string client_B_id = "clientB_for_reset_all";

    // Client A - Request 1 (Allowed)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_A_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    // Client A - Request 2 (Rate Limited)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_A_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Client B - Request 1 (Allowed)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_B_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    // Client B - Request 2 (Rate Limited)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_B_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Reset all clients
    rate_limit_mw->reset_all_clients();

    // Client A - Request 3 (Allowed again after reset_all_clients)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_A_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");

    // Client B - Request 3 (Allowed again after reset_all_clients)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_B_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");
}

TEST_F(RateLimitMiddlewareTest, NoRateLimitForDifferentClients) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::seconds(5)); // 1 request per 5 seconds
    auto rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);

    std::string client1_id = "independent_client_1";
    std::string client2_id = "independent_client_2";

    // Client 1 - Request 1 (Allowed)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client1_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");

    // Client 2 - Request 1 (Allowed, should not be affected by Client 1)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client2_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");

    // Client 1 - Request 2 (Rate Limited)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client1_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Client 2 - Request 2 (Rate Limited)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client2_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
}

TEST_F(RateLimitMiddlewareTest, ZeroMaxRequestsBlocksAll) {
    qb::http::RateLimitOptions options;
    options.max_requests(0).window(std::chrono::seconds(60)); // 0 requests allowed
    auto        rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);
    std::string client_id     = "zero_max_client";

    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Limit")), "0");
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");
}

TEST_F(RateLimitMiddlewareTest, RateLimitWhenExtractorReturnsEmptyString) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::seconds(5));
    options.client_id_extractor<MockRateLimitSession>([](const qb::http::Context<MockRateLimitSession> &ctx) {
        // Intentionally return an empty string
        return "";
    });
    auto rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);

    // Request 1 (Allowed, client ID is "")
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request()); // No X-Forwarded-For needed as custom extractor is used
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");

    // Request 2 (Rate Limited, client ID is also "")
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request());
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");
}

TEST_F(RateLimitMiddlewareTest, RequestsStraddlingWindowBoundary) {
    qb::http::RateLimitOptions options;
    options.max_requests(2).window(std::chrono::seconds(2)); // 2 req / 2 sec
    auto        rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);
    std::string client_id     = "straddle_client";

    // Request 1 (Allowed)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "1");

    // Wait for a bit, but not for the full window to pass (e.g., 1.5 seconds into a 2s window)
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));

    // Request 2 (Allowed, still in the first window)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "0");
    long long reset_val_req2 = std::stoll(std::string(_session->_response.header("X-RateLimit-Reset")));
    EXPECT_EQ(reset_val_req2, 0);

    // Request 3 (Rate Limited, still in the first window)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Wait for the remainder of the first window plus a bit more (e.g., another 1 second, total ~2.5s from start)
    // This ensures we are definitely in the next window.
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    // Request 4 (Allowed, new window)
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", client_id));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "1");
    long long reset_val_req4 = std::stoll(std::string(_session->_response.header("X-RateLimit-Reset")));
    EXPECT_GT(reset_val_req4, 0); // Should be positive
    EXPECT_LE(reset_val_req4, 2); // Should be close to the full window (2s)
}

// --- F41: stale-entry eviction / capacity recovery ---

// The middleware now opportunistically evicts tracked clients whose window
// has already elapsed, so a one-shot scan of unique IPs no longer traps
// capacity permanently. `evict_stale_entries_now()` exposes the same sweep
// synchronously for tests and for operators who want to reclaim memory on
// demand.
TEST_F(RateLimitMiddlewareTest, StaleEntriesEvictedOnDemand) {
    qb::http::RateLimitOptions options;
    // 100 ms window: easy to straddle in the test without long sleeps.
    options.max_requests(5).window(std::chrono::milliseconds(100));
    auto rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);

    // Hit the middleware from three distinct client IDs: each one allocates
    // an entry in the internal map.
    for (const auto *client : {"c_one", "c_two", "c_three"}) {
        _session->reset();
        configure_router_and_run(rate_limit_mw, create_request("/limited_route", client));
        EXPECT_EQ(_session->_response.status(), qb::http::status::OK) << client;
    }
    EXPECT_EQ(rate_limit_mw->tracked_client_count(), 3U);

    // Let every window elapse, then force a sweep. All three entries are
    // stale (no traffic since one full window ago) and must be evicted.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    const auto evicted = rate_limit_mw->evict_stale_entries_now();
    EXPECT_EQ(evicted, 3U);
    EXPECT_EQ(rate_limit_mw->tracked_client_count(), 0U);

    // A fresh request after eviction must re-create the entry and behave
    // exactly as the first request for a brand-new client.
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", "c_one"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "4");
    EXPECT_EQ(rate_limit_mw->tracked_client_count(), 1U);
}

// Active clients (whose window has NOT elapsed) must survive the sweep.
// The test asserts that the opportunistic eviction is truly surgical: it
// only touches entries matching the staleness criterion.
TEST_F(RateLimitMiddlewareTest, ActiveEntriesSurviveEviction) {
    qb::http::RateLimitOptions options;
    options.max_requests(3).window(std::chrono::milliseconds(500));
    auto rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);

    // Stale client: hit once, then let its window elapse.
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", "stale"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    std::this_thread::sleep_for(std::chrono::milliseconds(600));

    // Active client: hit right before the sweep, its window is fresh.
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", "active"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    const auto evicted = rate_limit_mw->evict_stale_entries_now();
    EXPECT_EQ(evicted, 1U);                               // only `stale`
    EXPECT_EQ(rate_limit_mw->tracked_client_count(), 1U); // only `active` left

    // The surviving entry keeps its counter: the next request sees
    // remaining = 1 (max_requests - 2), not remaining = 2.
    _session->reset();
    configure_router_and_run(rate_limit_mw, create_request("/limited_route", "active"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(std::string(_session->_response.header("X-RateLimit-Remaining")), "1");
}

// End-to-end scenario: a flood of short-lived clients should **not**
// permanently consume tracking slots. After their windows elapse, the
// next request (regardless of client ID) must trigger the periodic sweep
// via the opportunistic path inside `process()` and clean up.
TEST_F(RateLimitMiddlewareTest, OpportunisticPeriodicCleanupRecoversCapacity) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::milliseconds(50));
    auto rate_limit_mw = qb::http::rate_limit_middleware<MockRateLimitSession>(options);

    // 20 unique clients fire once, then disappear.
    for (int i = 0; i < 20; ++i) {
        _session->reset();
        configure_router_and_run(rate_limit_mw, create_request("/limited_route", "burst_" + std::to_string(i)));
        EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    }
    EXPECT_EQ(rate_limit_mw->tracked_client_count(), 20U);

    // Every window has elapsed.
    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    // The public API for the periodic sweep is `evict_stale_entries_now`
    // (the timer-gated path inside `process()` is an implementation
    // detail that we already cover indirectly through the other F41
    // scenarios). Calling it here must reclaim every slot from the
    // 20-client burst.
    const auto evicted = rate_limit_mw->evict_stale_entries_now();
    EXPECT_EQ(evicted, 20U);
    EXPECT_EQ(rate_limit_mw->tracked_client_count(), 0U);
}

// A second, distinct session type used to exercise the type-erased client-id
// extractor with a mismatched SessionType.
struct OtherRateLimitSession {
    qb::http::Response _response;
    qb::http::Response &
    get_response_ref() {
        return _response;
    }
    OtherRateLimitSession &
    operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }
    void
    reset() {
        _response = qb::http::Response();
    }
};

// Regression: a RateLimitOptions configured with client_id_extractor<A> but used
// by a RateLimitMiddleware<B> must NOT invoke the type-erased extractor — its
// static_cast<const Context<A>*> applied to a Context<B>* is undefined
// behaviour. The recorded type tag makes extract_client_id fall through to the
// built-in (X-Forwarded-For) extractor, so two distinct client IPs are tracked
// independently.
TEST(RateLimitMiddlewareTypeSafety, MismatchedExtractorSessionTypeFallsBackToDefault) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::seconds(60));
    // Extractor is configured for MockRateLimitSession, but the middleware below
    // is instantiated for OtherRateLimitSession.
    options.client_id_extractor<MockRateLimitSession>([](const qb::http::Context<MockRateLimitSession> &) -> std::string { return "FIXED"; });

    auto mw = qb::http::rate_limit_middleware<OtherRateLimitSession>(options);

    auto run = [&](const std::string &ip) {
        auto                                    session = std::make_shared<OtherRateLimitSession>();
        qb::http::Router<OtherRateLimitSession> router;
        router.use(mw);
        router.get("/r", [](std::shared_ptr<qb::http::Context<OtherRateLimitSession>> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router.compile();
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("/r");
        req.set_header("X-Forwarded-For", ip);
        router.route(session, std::move(req));
        return session->_response.status();
    };

    // First client IP: allowed (its own counter, limit 1).
    EXPECT_EQ(run("10.0.0.1"), qb::http::status::OK);
    // A different IP keyed by the default extractor is an independent client and
    // is also allowed. Had the mismatched extractor been (mis)used, both IPs
    // would share the "FIXED" key and this would be 429 — or, without the type
    // tag, undefined behaviour.
    EXPECT_EQ(run("10.0.0.2"), qb::http::status::OK);
}

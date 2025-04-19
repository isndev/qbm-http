#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/timing.h"
#include "../middleware/middleware_interface.h"

// Mock Session class for testing
class MockSession {
public:
    void operator<<(const qb::http::Response& resp) {
        // Use move semantics since Response is not copyable
        last_response = std::move(const_cast<qb::http::Response&>(resp));
    }
    
    qb::http::Response last_response;
};

// Test fixture
class TimingTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a mock session
        session = std::make_shared<MockSession>();
        
        // Create a request
        request.method = HTTP_GET;
        request._uri = "/api/test";
        
        // Reset the captured duration value
        duration_ms = 0;
        callback_called = false;
    }
    
    void TearDown() override {
        // Clean up if needed
    }
    
    std::shared_ptr<MockSession> session;
    qb::http::Request request;
    int64_t duration_ms;
    bool callback_called;
    
    // Helper to create a context with a fresh copy of the request
    qb::http::RouterContext<MockSession> create_context() {
        // Create a deep copy of the request to prevent move issues
        qb::http::Request req_copy = request;
        return qb::http::RouterContext<MockSession>(session, std::move(req_copy));
    }
    
    // Helper function to capture timing
    std::function<void(const std::chrono::milliseconds&)> create_timing_callback() {
        return [this](const std::chrono::milliseconds& duration) {
            duration_ms = duration.count();
            callback_called = true;
        };
    }
};

// Test basic timing functionality
TEST_F(TimingTest, BasicTiming) {
    // Create the timing middleware
    auto middleware = std::make_shared<qb::http::TimingMiddleware<MockSession>>(
        create_timing_callback(), "TimingTest");
    
    // Process a request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Verify that processing continues
    EXPECT_TRUE(result.should_continue());
    
    // Execute the done callbacks (this should trigger the timing callback)
    ctx.execute_done_callbacks();
    
    // Verify that the callback was called
    EXPECT_TRUE(callback_called);
    
    // Since we didn't do any work, the duration should be very small
    EXPECT_GE(duration_ms, 0);
    
    // Check the middleware name
    EXPECT_EQ("TimingTest", middleware->name());
}

// Test timing with simulated delay
TEST_F(TimingTest, TimingWithDelay) {
    // Create the timing middleware
    auto middleware = std::make_shared<qb::http::TimingMiddleware<MockSession>>(
        create_timing_callback());
    
    // Process a request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Simulate some processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Execute the done callbacks
    ctx.execute_done_callbacks();
    
    // Verify that the callback was called
    EXPECT_TRUE(callback_called);
    
    // Verify that the duration is roughly what we expect
    // We allow some slack because sleep_for is not super precise
    EXPECT_GE(duration_ms, 50);  // Allow some variance
}

// Test custom naming functionality
TEST_F(TimingTest, CustomNaming) {
    // Create the timing middleware with a custom name
    auto middleware = std::make_shared<qb::http::TimingMiddleware<MockSession>>(
        create_timing_callback(), "CustomTimingName");
    
    // Check the middleware name
    EXPECT_EQ("CustomTimingName", middleware->name());
    
    // Process a request (to ensure it still works)
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    ctx.execute_done_callbacks();
    
    // Verify that the callback was called
    EXPECT_TRUE(callback_called);
}

// Test timing with multiple done callbacks
TEST_F(TimingTest, MultipleCallbacks) {
    // Create the timing middleware
    auto middleware = std::make_shared<qb::http::TimingMiddleware<MockSession>>(
        create_timing_callback());
    
    // Process a request
    auto ctx = create_context();
    
    // Add another done callback that will add delay
    ctx.on_done([](qb::http::RouterContext<MockSession>& ctx) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    });
    
    // Process the middleware (this adds another done callback)
    auto result = middleware->process(ctx);
    
    // Execute the done callbacks (both will be executed)
    ctx.execute_done_callbacks();
    
    // Verify that the timing callback was called
    EXPECT_TRUE(callback_called);
    
    // Verify that the duration includes the delay from the other callback
    EXPECT_GE(duration_ms, 30);  // Allow some variance
}

// Test timing with a completed request
TEST_F(TimingTest, CompletedRequest) {
    // Create the timing middleware
    auto middleware = std::make_shared<qb::http::TimingMiddleware<MockSession>>(
        create_timing_callback());
    
    // Process a request and mark it as handled
    auto ctx = create_context();
    ctx.mark_handled();
    ctx.response.status_code = HTTP_STATUS_OK;
    
    auto result = middleware->process(ctx);
    
    // Execute the done callbacks
    ctx.execute_done_callbacks();
    
    // Verify that the callback was called even for a completed request
    EXPECT_TRUE(callback_called);
}

// Test concurrent timing operations
TEST_F(TimingTest, ConcurrentTiming) {
    // Create multiple timing middleware instances with separate metrics
    int64_t first_duration = 0;
    bool first_called = false;
    
    int64_t second_duration = 0;
    bool second_called = false;
    
    auto first_callback = [&first_duration, &first_called](const std::chrono::milliseconds& duration) {
        first_duration = duration.count();
        first_called = true;
    };
    
    auto second_callback = [&second_duration, &second_called](const std::chrono::milliseconds& duration) {
        second_duration = duration.count();
        second_called = true;
    };
    
    auto first_middleware = std::make_shared<qb::http::TimingMiddleware<MockSession>>(first_callback, "First");
    auto second_middleware = std::make_shared<qb::http::TimingMiddleware<MockSession>>(second_callback, "Second");
    
    // Set up and process the first request
    auto ctx1 = create_context();
    first_middleware->process(ctx1);
    
    // Delay before processing the second request
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Set up and process the second request
    auto ctx2 = create_context();
    second_middleware->process(ctx2);
    
    // Execute callbacks in reverse order
    ctx2.execute_done_callbacks();
    
    // Another delay
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Execute first callbacks
    ctx1.execute_done_callbacks();
    
    // Verify that both callbacks were called
    EXPECT_TRUE(first_called);
    EXPECT_TRUE(second_called);
    
    // The first duration should be longer than the second
    EXPECT_GT(first_duration, second_duration);
}

// Test integrating with the complete method
TEST_F(TimingTest, IntegrationWithComplete) {
    // Create the timing middleware
    auto middleware = std::make_shared<qb::http::TimingMiddleware<MockSession>>(
        create_timing_callback(), "TimingTest");
    
    // Process a request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Simulate some processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Call complete method which should execute done callbacks
    ctx.complete();
    
    // Verify that the callback was called
    EXPECT_TRUE(callback_called);
    
    // Verify that the session received the response
    EXPECT_EQ(HTTP_STATUS_OK, session->last_response.status_code);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
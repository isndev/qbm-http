#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/error_handling.h"
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
class ErrorHandlingTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a mock session
        session = std::make_shared<MockSession>();
        
        // Create a request
        request.method = HTTP_GET;
        request._uri = "/api/test";
        
        // Reset error handling logs
        error_logs.clear();
        custom_responses.clear();

        // Reset done callbacks executed flag
        done_callbacks_executed = false;
        
        // Reset tracking variables
        execution_order.clear();
    }
    
    void TearDown() override {
        // Clean up if needed
    }
    
    std::shared_ptr<MockSession> session;
    qb::http::Request request;
    std::vector<std::string> error_logs;
    std::vector<std::string> custom_responses;
    bool done_callbacks_executed = false;
    std::vector<std::string> execution_order;
    
    // Helper to create a context with a fresh copy of the request
    qb::http::RouterContext<MockSession> create_context() {
        // Create a deep copy of the request to prevent move issues
        qb::http::Request req_copy = request;
        return qb::http::RouterContext<MockSession>(session, std::move(req_copy));
    }
    
    // Helper to execute done callbacks (since execute_after_callbacks might not be available)
    void execute_done_callbacks(qb::http::RouterContext<MockSession>& ctx) {
        ctx.execute_after_callbacks();
        done_callbacks_executed = true;
    }
    
    // Helper to create an error logger
    std::function<void(qb::http::RouterContext<MockSession>&, const std::string&)> create_error_logger() {
        return [this](qb::http::RouterContext<MockSession>& ctx, const std::string& error_message) {
            std::string log = "Error " + std::to_string(ctx.response.status_code) + ": " + error_message;
            error_logs.push_back(log);
        };
    }
    
    // Helper to create a custom error response handler for a specific status
    std::function<void(qb::http::RouterContext<MockSession>&)> create_response_customizer(const std::string& body_prefix) {
        return [this, body_prefix](qb::http::RouterContext<MockSession>& ctx) {
            std::string custom_message = body_prefix + " - Status: " + std::to_string(ctx.response.status_code);
            ctx.response.body() = custom_message;
            ctx.response.add_header("X-Error-Handled", "true");
            custom_responses.push_back(custom_message);
        };
    }
    
    // Helper to get body contents as string for comparison
    std::string body_str(const qb::http::Body& body) {
        return std::string(body.begin(), body.end());
    }
};

// Test handling of specific status codes
TEST_F(ErrorHandlingTest, SpecificStatusCode) {
    // Create the error handling middleware
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    
    // Register a handler for HTTP 404
    middleware->on_status(HTTP_STATUS_NOT_FOUND, create_response_customizer("Not Found"));
    
    // Process a request
    auto ctx = create_context();
    ctx.response.status_code = HTTP_STATUS_NOT_FOUND;
    
    auto result = middleware->process(ctx);
    
    // Verify that processing continues
    EXPECT_TRUE(result.should_continue());
    
    // Execute the after_handling callbacks (this should trigger the error handler)
    execute_done_callbacks(ctx);
    
    // Verify that the response was customized
    EXPECT_EQ(1, custom_responses.size());
    EXPECT_EQ("Not Found - Status: 404", body_str(ctx.response.body()));
    EXPECT_EQ("true", ctx.response.header("X-Error-Handled"));
}

// Test handling of status code ranges
TEST_F(ErrorHandlingTest, StatusCodeRange) {
    // Create the error handling middleware
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    
    // Register handlers for 4xx and 5xx ranges
    middleware->on_status_range(HTTP_STATUS_BAD_REQUEST, HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS, create_response_customizer("Client Error"));
    middleware->on_status_range(HTTP_STATUS_INTERNAL_SERVER_ERROR, HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED, create_response_customizer("Server Error"));
    
    // Test with a 400 Bad Request
    {
        auto ctx = create_context();
        ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
        
        middleware->process(ctx);
        execute_done_callbacks(ctx);
        
        EXPECT_EQ("Client Error - Status: 400", body_str(ctx.response.body()));
    }
    
    // Test with a 500 Internal Server Error
    {
        auto ctx = create_context();
        ctx.response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        
        middleware->process(ctx);
        execute_done_callbacks(ctx);
        
        EXPECT_EQ("Server Error - Status: 500", body_str(ctx.response.body()));
    }
    
    // Verify we handled two errors
    EXPECT_EQ(2, custom_responses.size());
}

// Test the error callback directly
TEST_F(ErrorHandlingTest, ExplicitErrorCallback) {
    // Create the error handling middleware with a generic error handler
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    middleware->on_any_error(create_error_logger());
    middleware->on_status(HTTP_STATUS_BAD_REQUEST, create_response_customizer("Bad Request"));
    
    // Process a request
    auto ctx = create_context();
    ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
    
    middleware->process(ctx);
    
    // Explicitly trigger the error callback
    ctx.execute_error_callbacks("Invalid input parameter");
    
    // Verify that the error was logged
    EXPECT_EQ(1, error_logs.size());
    EXPECT_EQ("Error 400: Invalid input parameter", error_logs[0]);
    
    // Verify that the response was customized
    EXPECT_EQ("Bad Request - Status: 400", body_str(ctx.response.body()));
}

// Test integration with the complete method
TEST_F(ErrorHandlingTest, IntegrationWithComplete) {
    // Create the error handling middleware
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    middleware->on_status_range(HTTP_STATUS_BAD_REQUEST, HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED, create_response_customizer("Error"));
    
    // Process a request
    auto ctx = create_context();
    ctx.response.status_code = HTTP_STATUS_FORBIDDEN;
    
    middleware->process(ctx);
    
    // Call complete method which should execute after_handling callbacks
    ctx.complete();
    
    // Verify that the error handler was called
    EXPECT_EQ(1, custom_responses.size());
    
    // Verify that the session received the customized response
    EXPECT_EQ("Error - Status: 403", body_str(session->last_response.body()));
    EXPECT_EQ("true", session->last_response.header("X-Error-Handled"));
}

// Test with multiple error handlers
TEST_F(ErrorHandlingTest, MultipleHandlers) {
    // Create error handling middleware with multiple specialized handlers
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    
    // Track which handlers were called
    bool not_found_handler_called = false;
    bool server_error_handler_called = false;
    bool generic_error_handler_called = false;
    
    // Specific error handlers
    middleware->on_status(HTTP_STATUS_NOT_FOUND, [&](qb::http::RouterContext<MockSession>& ctx) {
        not_found_handler_called = true;
        ctx.response.body() = "Custom 404 page";
    });
    
    middleware->on_status_range(HTTP_STATUS_INTERNAL_SERVER_ERROR, HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED, [&](qb::http::RouterContext<MockSession>& ctx) {
        server_error_handler_called = true;
        ctx.response.body() = "Server error occurred";
    });
    
    middleware->on_any_error([&](qb::http::RouterContext<MockSession>& ctx, const std::string& message) {
        generic_error_handler_called = true;
        ctx.response.add_header("X-Error-Message", message);
    });
    
    // Test with a 404 Not Found
    {
        auto ctx = create_context();
        ctx.response.status_code = HTTP_STATUS_NOT_FOUND;
        
        middleware->process(ctx);
        ctx.execute_error_callbacks("Resource not found");
        
        EXPECT_TRUE(not_found_handler_called);
        EXPECT_FALSE(server_error_handler_called);
        EXPECT_TRUE(generic_error_handler_called);
        EXPECT_EQ("Custom 404 page", body_str(ctx.response.body()));
        EXPECT_EQ("Resource not found", ctx.response.header("X-Error-Message"));
    }
}

// Test factory function
TEST_F(ErrorHandlingTest, FactoryFunction) {
    // Create middleware with the factory function
    auto error_middleware = qb::http::error_handling_middleware<MockSession>("CustomErrorHandler");
    
    // Process a request just to verify it works
    auto ctx = create_context();
    auto result = error_middleware->process(ctx);
    
    // Verify middleware name and that processing continues
    EXPECT_EQ("CustomErrorHandler", error_middleware->name());
    EXPECT_TRUE(result.should_continue());
}

// Test handler priority (range handlers vs specific handlers)
TEST_F(ErrorHandlingTest, HandlerPriority) {
    // Create the error handling middleware
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    
    // Register both specific and range handlers for 404
    bool specific_handler_called = false;
    bool range_handler_called = false;
    
    middleware->on_status(HTTP_STATUS_NOT_FOUND, [&](qb::http::RouterContext<MockSession>& ctx) {
        specific_handler_called = true;
        ctx.response.body() = "Specific handler";
    });
    
    middleware->on_status_range(HTTP_STATUS_BAD_REQUEST, HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS, 
        [&](qb::http::RouterContext<MockSession>& ctx) {
            range_handler_called = true;
            ctx.response.body() = "Range handler";
        });
    
    // Process a request with 404
    auto ctx = create_context();
    ctx.response.status_code = HTTP_STATUS_NOT_FOUND;
    
    middleware->process(ctx);
    execute_done_callbacks(ctx);
    
    // Based on the actual implementation, range handlers have priority over specific handlers
    EXPECT_FALSE(specific_handler_called);
    EXPECT_TRUE(range_handler_called);
    EXPECT_EQ("Range handler", body_str(ctx.response.body()));
}

// Test method chaining
TEST_F(ErrorHandlingTest, MethodChaining) {
    // Create the error handling middleware with method chaining
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    
    // Use method chaining to register handlers
    middleware->on_status(HTTP_STATUS_BAD_REQUEST, create_response_customizer("Bad Request"))
              .on_status(HTTP_STATUS_NOT_FOUND, create_response_customizer("Not Found"))
              .on_status_range(HTTP_STATUS_INTERNAL_SERVER_ERROR, HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED, 
                            create_response_customizer("Server Error"));
    
    // Test with a 400 Bad Request
    {
        auto ctx = create_context();
        ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
        
        middleware->process(ctx);
        execute_done_callbacks(ctx);
        
        EXPECT_EQ("Bad Request - Status: 400", body_str(ctx.response.body()));
    }
    
    // Test with a 404 Not Found
    {
        auto ctx = create_context();
        ctx.response.status_code = HTTP_STATUS_NOT_FOUND;
        
        middleware->process(ctx);
        execute_done_callbacks(ctx);
        
        EXPECT_EQ("Not Found - Status: 404", body_str(ctx.response.body()));
    }
    
    // Test with a 500 Internal Server Error
    {
        auto ctx = create_context();
        ctx.response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        
        middleware->process(ctx);
        execute_done_callbacks(ctx);
        
        EXPECT_EQ("Server Error - Status: 500", body_str(ctx.response.body()));
    }
    
    // Verify we handled three errors
    EXPECT_EQ(3, custom_responses.size());
}

// Test behavior when no handler is registered for a specific status
TEST_F(ErrorHandlingTest, NoHandlerForStatus) {
    // Create middleware with only 500 handler
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    
    middleware->on_status(HTTP_STATUS_INTERNAL_SERVER_ERROR, create_response_customizer("Server Error"));
    
    // Process a 404 request with no handler
    auto ctx = create_context();
    ctx.response.status_code = HTTP_STATUS_NOT_FOUND;
    ctx.response.body() = "Original response";
    
    middleware->process(ctx);
    execute_done_callbacks(ctx);
    
    // Verify the response wasn't modified
    EXPECT_EQ("Original response", body_str(ctx.response.body()));
    EXPECT_FALSE(ctx.response.has_header("X-Error-Handled"));
    EXPECT_EQ(0, custom_responses.size());
}

// Test callback execution order
TEST_F(ErrorHandlingTest, CallbackExecutionOrder) {
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    
    // Register handlers that track execution order
    middleware->on_any_error([this](qb::http::RouterContext<MockSession>& ctx, const std::string& message) {
        execution_order.push_back("generic");
    });
    
    middleware->on_status(HTTP_STATUS_BAD_REQUEST, [this](qb::http::RouterContext<MockSession>& ctx) {
        execution_order.push_back("specific");
    });
    
    // Process a 400 request
    auto ctx = create_context();
    ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
    
    middleware->process(ctx);
    ctx.execute_error_callbacks("Test error");
    
    // Verify execution order: generic handler is called first, then specific
    ASSERT_EQ(2, execution_order.size());
    EXPECT_EQ("generic", execution_order[0]);
    EXPECT_EQ("specific", execution_order[1]);
}

// Test handler replacement
TEST_F(ErrorHandlingTest, HandlerReplacement) {
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    
    // Register first handler
    middleware->on_status(HTTP_STATUS_BAD_REQUEST, [](qb::http::RouterContext<MockSession>& ctx) {
        ctx.response.body() = "First handler";
    });
    
    // Replace with second handler
    middleware->on_status(HTTP_STATUS_BAD_REQUEST, [](qb::http::RouterContext<MockSession>& ctx) {
        ctx.response.body() = "Second handler";
    });
    
    // Process a 400 request
    auto ctx = create_context();
    ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
    
    middleware->process(ctx);
    execute_done_callbacks(ctx);
    
    // Verify second handler was used
    EXPECT_EQ("Second handler", body_str(ctx.response.body()));
}

// Test fallback to generic status code handlers (400/500)
TEST_F(ErrorHandlingTest, FallbackToGenericHandlers) {
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    
    // Register handlers for general 4xx/5xx but not specific codes
    middleware->on_status(HTTP_STATUS_BAD_REQUEST, [](qb::http::RouterContext<MockSession>& ctx) {
        ctx.response.body() = "Generic 4xx handler";
    });
    
    middleware->on_status(HTTP_STATUS_INTERNAL_SERVER_ERROR, [](qb::http::RouterContext<MockSession>& ctx) {
        ctx.response.body() = "Generic 5xx handler";
    });
    
    // Test with 403 Forbidden (should use 400 handler)
    {
        auto ctx = create_context();
        ctx.response.status_code = HTTP_STATUS_FORBIDDEN;
        
        middleware->process(ctx);
        execute_done_callbacks(ctx);
        
        EXPECT_EQ("Generic 4xx handler", body_str(ctx.response.body()));
    }
    
    // Test with 503 Service Unavailable (should use 500 handler)
    {
        auto ctx = create_context();
        ctx.response.status_code = HTTP_STATUS_SERVICE_UNAVAILABLE;
        
        middleware->process(ctx);
        execute_done_callbacks(ctx);
        
        EXPECT_EQ("Generic 5xx handler", body_str(ctx.response.body()));
    }
}

// Test handling of custom HTTP status codes
TEST_F(ErrorHandlingTest, CustomStatusCodes) {
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    
    // Register handler for a custom status code
    const http_status CUSTOM_STATUS = static_cast<http_status>(499); // Example custom code
    
    middleware->on_status(CUSTOM_STATUS, [](qb::http::RouterContext<MockSession>& ctx) {
        ctx.response.body() = "Custom status handler";
    });
    
    // Process request with custom status
    auto ctx = create_context();
    ctx.response.status_code = CUSTOM_STATUS;
    
    middleware->process(ctx);
    execute_done_callbacks(ctx);
    
    // Verify handler was called
    EXPECT_EQ("Custom status handler", body_str(ctx.response.body()));
}

// Test handling of non-error status codes (shouldn't trigger handlers)
TEST_F(ErrorHandlingTest, IgnoreSuccessStatus) {
    auto middleware = std::make_shared<qb::http::ErrorHandlingMiddleware<MockSession>>();
    
    bool handler_called = false;
    
    middleware->on_status_range(HTTP_STATUS_BAD_REQUEST, HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED,
                              [&handler_called](qb::http::RouterContext<MockSession>& ctx) {
        handler_called = true;
        ctx.response.body() = "Error handler called";
    });
    
    // Process a 200 OK response
    auto ctx = create_context();
    ctx.response.status_code = HTTP_STATUS_OK;
    ctx.response.body() = "Success response";
    
    middleware->process(ctx);
    execute_done_callbacks(ctx);
    
    // Verify handler was not called for success status
    EXPECT_FALSE(handler_called);
    EXPECT_EQ("Success response", body_str(ctx.response.body()));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
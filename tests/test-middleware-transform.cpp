#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/transform.h"
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
class TransformTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a mock session
        session = std::make_shared<MockSession>();
        
        // Create a request
        request.method = HTTP_GET;
        request._uri = "/api/test";
        request.add_header("Content-Type", "application/json");
        
        // Reset done callback flags
        done_callbacks_executed = false;
        
        // Initialize the transformation log
        transform_log.clear();
    }
    
    void TearDown() override {
        // Clean up if needed
    }
    
    std::shared_ptr<MockSession> session;
    qb::http::Request request;
    bool done_callbacks_executed;
    std::vector<std::string> transform_log;
    
    // Helper to create a context with a fresh copy of the request
    qb::http::RouterContext<MockSession> create_context() {
        // Create a deep copy of the request to prevent move issues
        qb::http::Request req_copy = request;
        return qb::http::RouterContext<MockSession>(session, std::move(req_copy));
    }
    
    // Helper to execute done callbacks manually
    void execute_done_callbacks(qb::http::RouterContext<MockSession>& ctx) {
        done_callbacks_executed = true;
        ctx.execute_after_callbacks();
    }
    
    // Helper to get body contents as string for comparison
    std::string body_str(const qb::http::Body& body) {
        return std::string(body.begin(), body.end());
    }
};

// Test request transformation
TEST_F(TransformTest, RequestTransformation) {
    // Create a transformer that adds a header to the request
    auto request_transformer = [](qb::http::Request& req) {
        req.add_header("X-Custom-Header", "test-value");
    };
    
    // Create the middleware
    auto middleware = std::make_shared<qb::http::TransformMiddleware<MockSession>>(
        request_transformer, nullptr, "RequestTransformer");
    
    // Process a request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Verify that processing continues
    EXPECT_TRUE(result.should_continue());
    
    // Verify that the header was added
    EXPECT_EQ("test-value", ctx.request.header("X-Custom-Header"));
    
    // Check the middleware name
    EXPECT_EQ("RequestTransformer", middleware->name());
}

// Test response transformation
TEST_F(TransformTest, ResponseTransformation) {
    // Create a transformer that adds a header to the response
    auto response_transformer = [](qb::http::Response& resp) {
        resp.add_header("X-Response-Header", "response-value");
        resp.status_code = HTTP_STATUS_CREATED;
    };
    
    // Create the middleware
    auto middleware = std::make_shared<qb::http::TransformMiddleware<MockSession>>(
        nullptr, response_transformer, "ResponseTransformer");
    
    // Process a request
    auto ctx = create_context();
    ctx.response.status_code = HTTP_STATUS_OK;
    
    auto result = middleware->process(ctx);
    
    // Verify that processing continues
    EXPECT_TRUE(result.should_continue());
    
    // Execute the response transformers (simulating request completion)
    execute_done_callbacks(ctx);
    
    // Verify that the header was added and status code changed
    EXPECT_EQ("response-value", ctx.response.header("X-Response-Header"));
    EXPECT_EQ(HTTP_STATUS_CREATED, ctx.response.status_code);
}

// Test both request and response transformation
TEST_F(TransformTest, CombinedTransformation) {
    // Create a request transformer
    auto request_transformer = [](qb::http::Request& req) {
        req.add_header("X-Request-ID", "123456");
    };
    
    // Create a response transformer that uses the request header
    auto response_transformer = [](qb::http::Response& resp) {
        resp.add_header("X-Response-ID", "Response-123456");
    };
    
    // Create the middleware
    auto middleware = std::make_shared<qb::http::TransformMiddleware<MockSession>>(
        request_transformer, response_transformer, "CombinedTransformer");
    
    // Process a request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Verify request transformation
    EXPECT_EQ("123456", ctx.request.header("X-Request-ID"));
    
    // Execute response transformation
    execute_done_callbacks(ctx);
    
    // Verify response transformation
    EXPECT_EQ("Response-123456", ctx.response.header("X-Response-ID"));
}

// Test factory function
TEST_F(TransformTest, FactoryFunction) {
    // Use the factory function to create middleware
    auto transformer = qb::http::transform_middleware<MockSession>(
        [](qb::http::Request& req) { req.add_header("X-Factory", "factory-test"); },
        nullptr,
        "FactoryTransformer"
    );
    
    // Process a request
    auto ctx = create_context();
    auto result = transformer->process(ctx);
    
    // Verify that the factory-created middleware works
    EXPECT_TRUE(result.should_continue());
    EXPECT_EQ("factory-test", ctx.request.header("X-Factory"));
}

// Test null transformers
TEST_F(TransformTest, NullTransformers) {
    // Create middleware with null transformers
    auto middleware = std::make_shared<qb::http::TransformMiddleware<MockSession>>(
        nullptr, nullptr, "TransformMiddleware");
    
    // Process a request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Verify that processing continues even with null transformers
    EXPECT_TRUE(result.should_continue());
    
    // Execute done callbacks (should be safe even with null transformer)
    execute_done_callbacks(ctx);
    
    // Check default name
    EXPECT_EQ("TransformMiddleware", middleware->name());
}

// Test transformation of request body
TEST_F(TransformTest, RequestBodyTransformation) {
    // Create a request with a body
    request.body() = "original-body";
    
    // Create a transformer that modifies the request body
    auto request_transformer = [](qb::http::Request& req) {
        std::string original = std::string(req.body().begin(), req.body().end());
        req.body() = "transformed-" + original;
    };
    
    // Create the middleware
    auto middleware = std::make_shared<qb::http::TransformMiddleware<MockSession>>(
        request_transformer, nullptr, "BodyTransformer");
    
    // Process a request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Verify that the body was transformed
    EXPECT_EQ("transformed-original-body", body_str(ctx.request.body()));
}

// Test transformation of response body
TEST_F(TransformTest, ResponseBodyTransformation) {
    // Create a transformer that modifies the response body
    auto response_transformer = [](qb::http::Response& resp) {
        resp.body() = "transformed-response";
    };
    
    // Create the middleware
    auto middleware = std::make_shared<qb::http::TransformMiddleware<MockSession>>(
        nullptr, response_transformer);
    
    // Process a request
    auto ctx = create_context();
    ctx.response.body() = "original-response";
    
    middleware->process(ctx);
    execute_done_callbacks(ctx);
    
    // Verify the response body was transformed
    EXPECT_EQ("transformed-response", body_str(ctx.response.body()));
}

// Test conditional transformation based on request properties
TEST_F(TransformTest, ConditionalTransformation) {
    // Create transformers that only apply under certain conditions
    auto request_transformer = [](qb::http::Request& req) {
        // Only transform GET requests
        if (req.method == HTTP_GET) {
            req.add_header("X-Transformed", "get-request");
        }
    };
    
    auto response_transformer = [](qb::http::Response& resp) {
        // Only transform 200 OK responses
        if (resp.status_code == HTTP_STATUS_OK) {
            resp.add_header("X-Transformed", "ok-response");
        }
    };
    
    // Create the middleware
    auto middleware = std::make_shared<qb::http::TransformMiddleware<MockSession>>(
        request_transformer, response_transformer, "ConditionalTransformer");
    
    // Test with GET request and 200 OK response
    {
        request.method = HTTP_GET;
        auto ctx = create_context();
        ctx.response.status_code = HTTP_STATUS_OK;
        
        middleware->process(ctx);
        execute_done_callbacks(ctx);
        
        EXPECT_EQ("get-request", ctx.request.header("X-Transformed"));
        EXPECT_EQ("ok-response", ctx.response.header("X-Transformed"));
    }
    
    // Test with POST request and 201 Created response
    {
        request.method = HTTP_POST;
        auto ctx = create_context();
        ctx.response.status_code = HTTP_STATUS_CREATED;
        
        middleware->process(ctx);
        execute_done_callbacks(ctx);
        
        EXPECT_EQ("", ctx.request.header("X-Transformed")); // Should not be transformed
        EXPECT_EQ("", ctx.response.header("X-Transformed")); // Should not be transformed
    }
}

// Test multiple transformers with execution order tracking
TEST_F(TransformTest, TransformerExecutionOrder) {
    // Create a sequence of transformers
    auto first_transformer = qb::http::transform_middleware<MockSession>(
        [this](qb::http::Request& req) {
            transform_log.push_back("first-req");
            req.add_header("X-First", "first");
        },
        [this](qb::http::Response& resp) {
            transform_log.push_back("first-resp");
            resp.add_header("X-First-Resp", "first");
        }
    );
    
    auto second_transformer = qb::http::transform_middleware<MockSession>(
        [this](qb::http::Request& req) {
            transform_log.push_back("second-req");
            req.add_header("X-Second", "second");
        },
        [this](qb::http::Response& resp) {
            transform_log.push_back("second-resp");
            resp.add_header("X-Second-Resp", "second");
        }
    );
    
    // Process a request through both transformers
    auto ctx = create_context();
    
    first_transformer->process(ctx);
    second_transformer->process(ctx);
    
    // Verify request transformers executed in order
    EXPECT_EQ(2, transform_log.size());
    EXPECT_EQ("first-req", transform_log[0]);
    EXPECT_EQ("second-req", transform_log[1]);
    EXPECT_EQ("first", ctx.request.header("X-First"));
    EXPECT_EQ("second", ctx.request.header("X-Second"));
    
    // Execute response transformers - callbacks are executed in order of registration
    execute_done_callbacks(ctx);
    
    // Verify response transformers executed in registration order (not LIFO)
    EXPECT_EQ(4, transform_log.size());
    EXPECT_EQ("first-resp", transform_log[2]);
    EXPECT_EQ("second-resp", transform_log[3]);
    EXPECT_EQ("first", ctx.response.header("X-First-Resp"));
    EXPECT_EQ("second", ctx.response.header("X-Second-Resp"));
}

// Test transforming URI path and query parameters
TEST_F(TransformTest, URITransformation) {
    // Create a transformer that modifies the URI
    auto request_transformer = [](qb::http::Request& req) {
        // Note: In a real implementation, this would be more complex and would properly 
        // parse and modify the URI; this is just for the test
        std::string path_str(req._uri.path());
        req._uri = qb::io::uri(path_str + "?modified=true");
    };
    
    // Create the middleware
    auto middleware = std::make_shared<qb::http::TransformMiddleware<MockSession>>(
        request_transformer, nullptr);
    
    // Process a request
    auto ctx = create_context();
    middleware->process(ctx);
    
    // Convert URI to string for comparison - URI might not have a direct string conversion
    std::string uri_str(ctx.request._uri.path());
    const auto& queries = ctx.request._uri.encoded_queries();
    if (!queries.empty()) {
        uri_str += "?";
        uri_str += queries;
    }
    
    // Verify the URI was modified
    EXPECT_EQ("/api/test?modified=true", uri_str);
}

// Test transforming content type and handling JSON
TEST_F(TransformTest, ContentTypeTransformation) {
    // Create a transformer that changes content type
    auto response_transformer = [](qb::http::Response& resp) {
        // Need to set header not add_header to override existing value
        resp.set_header("Content-Type", "application/xml");
        resp.body() = "<root><message>Hello World</message></root>";
    };
    
    // Create the middleware
    auto middleware = std::make_shared<qb::http::TransformMiddleware<MockSession>>(
        nullptr, response_transformer);
    
    // Process a request
    auto ctx = create_context();
    ctx.response.add_header("Content-Type", "application/json");
    ctx.response.body() = "{\"message\": \"Hello World\"}";
    
    middleware->process(ctx);
    execute_done_callbacks(ctx);
    
    // Verify the content type and body were changed
    EXPECT_EQ("application/xml", ctx.response.header("Content-Type"));
    EXPECT_EQ("<root><message>Hello World</message></root>", body_str(ctx.response.body()));
}

// Test handling errors during transformation
TEST_F(TransformTest, ErrorHandlingDuringTransformation) {
    bool error_occurred = false;
    
    // Create a transformer that throws an exception
    auto request_transformer = [](qb::http::Request& req) {
        throw std::runtime_error("Transformation error");
    };
    
    // Create a middleware with try-catch
    auto middleware = std::make_shared<qb::http::TransformMiddleware<MockSession>>(
        [&error_occurred, request_transformer](qb::http::Request& req) {
            try {
                request_transformer(req);
            } catch (const std::exception& e) {
                error_occurred = true;
                req.add_header("X-Error", e.what());
            }
        }, nullptr);
    
    // Process a request
    auto ctx = create_context();
    middleware->process(ctx);
    
    // Verify error was handled
    EXPECT_TRUE(error_occurred);
    EXPECT_EQ("Transformation error", ctx.request.header("X-Error"));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
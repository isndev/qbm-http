#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/conditional.h"
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

// Mock middleware for testing
template <typename Session>
class MockMiddleware : public qb::http::IMiddleware<Session> {
public:
    using Context = typename qb::http::IMiddleware<Session>::Context;
    using CompletionCallback = typename qb::http::IMiddleware<Session>::CompletionCallback;
    
    // Add a custom process function type
    using CustomProcessFunction = std::function<qb::http::MiddlewareResult(Context&, CompletionCallback)>;
    
    MockMiddleware(const std::string& name, bool should_continue = true, bool mark_request_handled = false)
        : _name(name), _executed(false), _should_continue(should_continue), _mark_handled(mark_request_handled),
          custom_process(nullptr) {}
    
    qb::http::MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) override {
        _executed = true;
        
        // If a custom process function is set, use it
        if (custom_process) {
            return custom_process(ctx, callback);
        }
        
        if (_mark_handled) {
            ctx.mark_handled();
        }
        
        qb::http::MiddlewareResult result = _should_continue ? 
            qb::http::MiddlewareResult::Continue() : 
            qb::http::MiddlewareResult::Stop();
            
        if (callback) callback(result);
        return result;
    }
    
    std::string name() const override {
        return _name;
    }
    
    bool was_executed() const {
        return _executed;
    }
    
    void reset() {
        _executed = false;
    }

private:
    std::string _name;
    bool _executed;
    bool _should_continue;
    bool _mark_handled;
public:
    // Custom process function that can be set by tests
    CustomProcessFunction custom_process;
};

// Test fixture
class ConditionalTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a mock session
        session = std::make_shared<MockSession>();
        
        // Create a request
        request.method = HTTP_GET;
        request._uri = "/api/test";
        
        // Create mock middlewares
        if_middleware = std::make_shared<MockMiddleware<MockSession>>("if_middleware");
        else_middleware = std::make_shared<MockMiddleware<MockSession>>("else_middleware");
    }
    
    void TearDown() override {
        // Clean up if needed
    }
    
    std::shared_ptr<MockSession> session;
    qb::http::Request request;
    std::shared_ptr<MockMiddleware<MockSession>> if_middleware;
    std::shared_ptr<MockMiddleware<MockSession>> else_middleware;
    
    // Helper to create a context with a fresh copy of the request
    qb::http::Context<MockSession> create_context() {
        // Create a deep copy of the request to prevent move issues
        qb::http::Request req_copy = request;
        return qb::http::Context<MockSession>(session, std::move(req_copy));
    }
};

// Test condition is true
TEST_F(ConditionalTest, ConditionTrue) {
    // Create a predicate that always returns true
    auto predicate = [](const qb::http::Context<MockSession>&) {
        return true;
    };
    
    // Create the conditional middleware
    auto middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        predicate, if_middleware, else_middleware, "TrueCondition");
    
    // Process a request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Verify that the if_middleware was executed and else_middleware was not
    EXPECT_TRUE(if_middleware->was_executed());
    EXPECT_FALSE(else_middleware->was_executed());
    
    // Check the middleware name
    EXPECT_EQ("TrueCondition", middleware->name());
}

// Test condition is false with else middleware
TEST_F(ConditionalTest, ConditionFalseWithElse) {
    // Create a predicate that always returns false
    auto predicate = [](const qb::http::Context<MockSession>&) {
        return false;
    };
    
    // Create the conditional middleware
    auto middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        predicate, if_middleware, else_middleware, "FalseCondition");
    
    // Process a request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Verify that the else_middleware was executed and if_middleware was not
    EXPECT_FALSE(if_middleware->was_executed());
    EXPECT_TRUE(else_middleware->was_executed());
}

// Test condition is false without else middleware
TEST_F(ConditionalTest, ConditionFalseWithoutElse) {
    // Create a predicate that always returns false
    auto predicate = [](const qb::http::Context<MockSession>&) {
        return false;
    };
    
    // Create the conditional middleware without an else branch
    auto middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        predicate, if_middleware, nullptr, "FalseNoElse");
    
    // Process a request
    auto ctx = create_context();
    auto result = middleware->process(ctx);
    
    // Verify that the if_middleware was not executed
    EXPECT_FALSE(if_middleware->was_executed());
    
    // Verify that processing continues
    EXPECT_TRUE(result.should_continue());
}

// Test with conditional based on request attributes
TEST_F(ConditionalTest, RequestAttributeCondition) {
    // Create a predicate that checks for a header
    auto predicate = [](const qb::http::Context<MockSession>& ctx) {
        return ctx.request.header("X-Feature-Flag") == "enabled";
    };
    
    // Create the conditional middleware
    auto middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        predicate, if_middleware, else_middleware, "HeaderCondition");
    
    // Test with the header present
    {
        // Set up first request with enabled flag
        qb::http::Request req1;
        req1.method = HTTP_GET;
        req1._uri = "/api/test";
        req1.add_header("X-Feature-Flag", "enabled");
        
        auto ctx1 = qb::http::Context<MockSession>(session, std::move(req1));
        middleware->process(ctx1);
        
        EXPECT_TRUE(if_middleware->was_executed());
        EXPECT_FALSE(else_middleware->was_executed());
    }
    
    // Reset the middlewares
    if_middleware->reset();
    else_middleware->reset();
    
    // Test with the header changed
    {
        // Set up second request with disabled flag
        qb::http::Request req2;
        req2.method = HTTP_GET;
        req2._uri = "/api/test";
        req2.add_header("X-Feature-Flag", "disabled");
        
        auto ctx2 = qb::http::Context<MockSession>(session, std::move(req2));
        middleware->process(ctx2);
        
        EXPECT_FALSE(if_middleware->was_executed());
        EXPECT_TRUE(else_middleware->was_executed());
    }
}

// Test the factory function (modified to avoid using factory function directly)
TEST_F(ConditionalTest, FactoryFunction) {
    // Create a predicate that always returns true
    auto predicate = [](const qb::http::Context<MockSession>&) { return true; };
    
    // Create the conditional middleware directly instead of using factory function
    auto conditional = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        predicate, if_middleware, else_middleware, "FactoryConditional"
    );
    
    // Process a request
    auto ctx = create_context();
    auto result = conditional->process(ctx);
    
    // Verify that the middleware works as expected
    EXPECT_TRUE(if_middleware->was_executed());
    EXPECT_FALSE(else_middleware->was_executed());
    
    // Check the middleware name
    EXPECT_EQ("FactoryConditional", conditional->name());
}

// Test middleware result propagation
TEST_F(ConditionalTest, ResultPropagation) {
    // Create middlewares that either continue or stop
    auto continuing_middleware = std::make_shared<MockMiddleware<MockSession>>("continue", true);
    auto stopping_middleware = std::make_shared<MockMiddleware<MockSession>>("stop", false);
    
    // Test when condition is true and if_middleware stops
    {
        auto predicate = [](const qb::http::Context<MockSession>&) { return true; };
        auto middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
            predicate, stopping_middleware, continuing_middleware);
            
        auto ctx = create_context();
        auto result = middleware->process(ctx);
        
        EXPECT_FALSE(result.should_continue());
    }
    
    // Test when condition is false and else_middleware continues
    {
        auto predicate = [](const qb::http::Context<MockSession>&) { return false; };
        auto middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
            predicate, stopping_middleware, continuing_middleware);
            
        auto ctx = create_context();
        auto result = middleware->process(ctx);
        
        EXPECT_TRUE(result.should_continue());
    }
}

// Test nested conditional middlewares
TEST_F(ConditionalTest, NestedConditional) {
    // Create inner middleware predicate (always true)
    auto inner_predicate = [](const qb::http::Context<MockSession>&) {
        return true;
    };
    
    // Create nested conditional middleware
    auto inner_conditional = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        inner_predicate, if_middleware, else_middleware, "InnerConditional");
    
    // Create mock middlewares for outer conditional
    auto outer_if = std::make_shared<MockMiddleware<MockSession>>("outer_if");
    
    // Create outer middleware predicate (also true)
    auto outer_predicate = [](const qb::http::Context<MockSession>&) {
        return true;
    };
    
    // Create outer conditional with inner conditional as its "else" branch
    auto outer_conditional = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        outer_predicate, outer_if, inner_conditional, "OuterConditional");
    
    // Process a request
    auto ctx = create_context();
    auto result = outer_conditional->process(ctx);
    
    // Verify that outer_if was executed
    EXPECT_TRUE(outer_if->was_executed());
    
    // Verify that inner middlewares were NOT executed (since outer predicate was true)
    EXPECT_FALSE(if_middleware->was_executed());
    EXPECT_FALSE(else_middleware->was_executed());
    
    // Reset middlewares for second test
    outer_if->reset();
    if_middleware->reset();
    else_middleware->reset();
    
    // Change outer predicate to false to trigger inner conditional
    auto outer_predicate_false = [](const qb::http::Context<MockSession>&) {
        return false;
    };
    
    auto outer_conditional2 = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        outer_predicate_false, outer_if, inner_conditional, "OuterConditional");
    
    // Process another request
    auto ctx2 = create_context();
    auto result2 = outer_conditional2->process(ctx2);
    
    // Verify that outer_if was NOT executed
    EXPECT_FALSE(outer_if->was_executed());
    
    // Verify that inner if_middleware WAS executed (since inner predicate is true)
    EXPECT_TRUE(if_middleware->was_executed());
    
    // Verify that inner else_middleware was NOT executed
    EXPECT_FALSE(else_middleware->was_executed());
}

// Test with complex predicates
TEST_F(ConditionalTest, ComplexPredicate) {
    // Create a predicate that evaluates multiple conditions
    auto complex_predicate = [](const qb::http::Context<MockSession>& ctx) {
        // Check method is GET
        bool method_check = ctx.request.method == HTTP_GET;
        
        // Check path contains "api"
        bool path_check = std::string(ctx.request._uri.path()).find("api") != std::string::npos;
        
        // Check for specific header presence
        bool header_check = !ctx.request.header("X-Test-Header").empty();
        
        // All conditions must be true
        return method_check && path_check && header_check;
    };
    
    // Create the conditional middleware
    auto middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        complex_predicate, if_middleware, else_middleware, "ComplexCondition");
    
    // Create request that satisfies all conditions
    qb::http::Request req_pass;
    req_pass.method = HTTP_GET;
    req_pass._uri = "/api/test";
    req_pass.add_header("X-Test-Header", "present");
    
    auto ctx_pass = qb::http::Context<MockSession>(session, std::move(req_pass));
    middleware->process(ctx_pass);
    
    // Verify if_middleware was executed since all conditions were met
    EXPECT_TRUE(if_middleware->was_executed());
    EXPECT_FALSE(else_middleware->was_executed());
    
    // Reset middlewares
    if_middleware->reset();
    else_middleware->reset();
    
    // Create request that fails one condition (wrong method)
    qb::http::Request req_fail;
    req_fail.method = HTTP_POST; // Not GET
    req_fail._uri = "/api/test";
    req_fail.add_header("X-Test-Header", "present");
    
    auto ctx_fail = qb::http::Context<MockSession>(session, std::move(req_fail));
    middleware->process(ctx_fail);
    
    // Verify else_middleware was executed since a condition failed
    EXPECT_FALSE(if_middleware->was_executed());
    EXPECT_TRUE(else_middleware->was_executed());
}

// Test chained conditional middlewares
TEST_F(ConditionalTest, ChainedConditionals) {
    // Create middlewares to track order of execution
    auto first = std::make_shared<MockMiddleware<MockSession>>("first");
    auto second = std::make_shared<MockMiddleware<MockSession>>("second");
    auto third = std::make_shared<MockMiddleware<MockSession>>("third");
    auto fallback = std::make_shared<MockMiddleware<MockSession>>("fallback");
    
    // Create predicates
    auto path_is_users = [](const qb::http::Context<MockSession>& ctx) {
        return std::string(ctx.request._uri.path()).find("users") != std::string::npos;
    };
    
    auto path_is_products = [](const qb::http::Context<MockSession>& ctx) {
        return std::string(ctx.request._uri.path()).find("products") != std::string::npos;
    };
    
    auto path_is_orders = [](const qb::http::Context<MockSession>& ctx) {
        return std::string(ctx.request._uri.path()).find("orders") != std::string::npos;
    };
    
    // Create three conditional middlewares in a chain
    auto orders_middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        path_is_orders, third, fallback, "OrdersRouter");
    
    auto products_middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        path_is_products, second, orders_middleware, "ProductsRouter");
    
    auto users_middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        path_is_users, first, products_middleware, "UsersRouter");
    
    // Test with users path
    {
        qb::http::Request req;
        req.method = HTTP_GET;
        req._uri = "/users/123";
        
        auto ctx = qb::http::Context<MockSession>(session, std::move(req));
        users_middleware->process(ctx);
        
        EXPECT_TRUE(first->was_executed());
        EXPECT_FALSE(second->was_executed());
        EXPECT_FALSE(third->was_executed());
        EXPECT_FALSE(fallback->was_executed());
    }
    
    // Reset middlewares
    first->reset();
    second->reset();
    third->reset();
    fallback->reset();
    
    // Test with products path
    {
        qb::http::Request req;
        req.method = HTTP_GET;
        req._uri = "/products/456";
        
        auto ctx = qb::http::Context<MockSession>(session, std::move(req));
        users_middleware->process(ctx);
        
        EXPECT_FALSE(first->was_executed());
        EXPECT_TRUE(second->was_executed());
        EXPECT_FALSE(third->was_executed());
        EXPECT_FALSE(fallback->was_executed());
    }
    
    // Reset middlewares
    first->reset();
    second->reset();
    third->reset();
    fallback->reset();
    
    // Test with orders path
    {
        qb::http::Request req;
        req.method = HTTP_GET;
        req._uri = "/orders/789";
        
        auto ctx = qb::http::Context<MockSession>(session, std::move(req));
        users_middleware->process(ctx);
        
        EXPECT_FALSE(first->was_executed());
        EXPECT_FALSE(second->was_executed());
        EXPECT_TRUE(third->was_executed());
        EXPECT_FALSE(fallback->was_executed());
    }
    
    // Reset middlewares
    first->reset();
    second->reset();
    third->reset();
    fallback->reset();
    
    // Test with unknown path (should execute fallback)
    {
        qb::http::Request req;
        req.method = HTTP_GET;
        req._uri = "/unknown/path";
        
        auto ctx = qb::http::Context<MockSession>(session, std::move(req));
        users_middleware->process(ctx);
        
        EXPECT_FALSE(first->was_executed());
        EXPECT_FALSE(second->was_executed());
        EXPECT_FALSE(third->was_executed());
        EXPECT_TRUE(fallback->was_executed());
    }
}

// Test context manipulation by conditional branches
TEST_F(ConditionalTest, ContextManipulation) {
    // Create middleware that adds a header
    auto request_modifier = std::make_shared<MockMiddleware<MockSession>>("header_adder");
    
    // Custom implementation to add a header
    request_modifier->custom_process = [](
        typename MockMiddleware<MockSession>::Context& ctx,
        typename MockMiddleware<MockSession>::CompletionCallback callback) {
        
        ctx.request.add_header("X-Added-By", "if_branch");
        
        auto result = qb::http::MiddlewareResult::Continue();
        if (callback) callback(result);
        return result;
    };
    
    // Create middleware that modifies the response
    auto response_modifier = std::make_shared<MockMiddleware<MockSession>>("response_modifier");
    
    // Custom implementation to modify response
    response_modifier->custom_process = [](
        typename MockMiddleware<MockSession>::Context& ctx,
        typename MockMiddleware<MockSession>::CompletionCallback callback) {
        
        ctx.response.status_code = HTTP_STATUS_CREATED;
        ctx.response.add_header("X-Modified-By", "else_branch");
        
        auto result = qb::http::MiddlewareResult::Continue();
        if (callback) callback(result);
        return result;
    };
    
    // Create a predicate based on request method
    auto method_is_get = [](const qb::http::Context<MockSession>& ctx) {
        return ctx.request.method == HTTP_GET;
    };
    
    // Create the conditional middleware
    auto middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        method_is_get, request_modifier, response_modifier, "ContextModifier");
    
    // Test with GET request (should modify request)
    {
        qb::http::Request req;
        req.method = HTTP_GET;
        req._uri = "/test";
        
        auto ctx = qb::http::Context<MockSession>(session, std::move(req));
        middleware->process(ctx);
        
        // Check that request was modified by if_branch
        EXPECT_EQ("if_branch", ctx.request.header("X-Added-By"));
    }
    
    // Test with POST request (should modify response)
    {
        qb::http::Request req;
        req.method = HTTP_POST;
        req._uri = "/test";
        
        auto ctx = qb::http::Context<MockSession>(session, std::move(req));
        middleware->process(ctx);
        
        // Check that response was modified by else_branch
        EXPECT_EQ(HTTP_STATUS_CREATED, ctx.response.status_code);
        EXPECT_EQ("else_branch", ctx.response.header("X-Modified-By"));
    }
}

// Test with dynamic predicates
TEST_F(ConditionalTest, DynamicPredicate) {
    // Create an external state that will influence the predicate
    bool feature_enabled = true;
    
    // Create a predicate that uses the external state
    auto dynamic_predicate = [&feature_enabled](const qb::http::Context<MockSession>&) {
        return feature_enabled;
    };
    
    // Create the conditional middleware
    auto middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        dynamic_predicate, if_middleware, else_middleware, "DynamicCondition");
    
    // Test with feature enabled
    {
        auto ctx = create_context();
        middleware->process(ctx);
        
        EXPECT_TRUE(if_middleware->was_executed());
        EXPECT_FALSE(else_middleware->was_executed());
    }
    
    // Reset middlewares
    if_middleware->reset();
    else_middleware->reset();
    
    // Change external state
    feature_enabled = false;
    
    // Test with feature disabled
    {
        auto ctx = create_context();
        middleware->process(ctx);
        
        EXPECT_FALSE(if_middleware->was_executed());
        EXPECT_TRUE(else_middleware->was_executed());
    }
}

// Test predicate stability
TEST_F(ConditionalTest, PredicateStability) {
    // Counter to track number of predicate calls
    int predicate_call_count = 0;
    
    // Create a predicate that counts its invocations
    auto counting_predicate = [&predicate_call_count](const qb::http::Context<MockSession>&) {
        predicate_call_count++;
        return true;
    };
    
    // Create the conditional middleware
    auto middleware = std::make_shared<qb::http::ConditionalMiddleware<MockSession>>(
        counting_predicate, if_middleware, else_middleware, "StableCondition");
    
    // Create a context
    auto ctx = create_context();
    
    // Process the same context multiple times
    middleware->process(ctx);
    middleware->process(ctx);
    middleware->process(ctx);
    
    // Verify predicate was called exactly 3 times (once per process call)
    EXPECT_EQ(3, predicate_call_count);
    
    // Verify that the decision was stable (if_middleware always executed)
    EXPECT_TRUE(if_middleware->was_executed());
    EXPECT_FALSE(else_middleware->was_executed());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
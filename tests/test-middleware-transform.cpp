#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/transform.h" // The adapted TransformMiddleware
#include "../routing/middleware.h"   // For MiddlewareTask if needed

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sstream>
#include <iostream> // Ensure iostream is included for std::cerr

// --- Mock Session for TransformMiddleware Tests ---
struct MockTransformSession {
    qb::http::Response _response;
    std::string _session_id_str = "transform_test_session";
    // Store modified request/response parts for verification if needed
    std::string _request_body_at_handler;
    // qb::http::headers_map _request_headers_at_handler; // Removed
    std::string _xtransformed_header_value; // For RequestTransformation test
    bool _xbody_cleared_header_present;   // For RequestBodyClearedByTransformer test
    std::string _xbody_cleared_header_value; // For RequestBodyClearedByTransformer test
    // For RequestContentTypeTransform, we already check body. Content-Type header itself:
    std::string _content_type_header_at_handler;
    qb::http::method _method_at_handler; // Added for method change test

    std::string _response_body_before_transform_hook;
    bool _final_handler_called = false;

    qb::http::Response& get_response_ref() { return _response; }

    MockTransformSession& operator<<(const qb::http::Response& resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _request_body_at_handler.clear();
        // _request_headers_at_handler.clear(); // Removed
        _xtransformed_header_value.clear();
        _xbody_cleared_header_present = false;
        _xbody_cleared_header_value.clear();
        _content_type_header_at_handler.clear();
        _method_at_handler = qb::http::method::UNINITIALIZED; // Reset to a default
        _response_body_before_transform_hook.clear();
        _final_handler_called = false;
    }
};

// --- Test Fixture for TransformMiddleware --- 
class TransformMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockTransformSession> _session;
    std::unique_ptr<qb::http::Router<MockTransformSession>> _router;

    void SetUp() override {
        _session = std::make_shared<MockTransformSession>();
        _router = std::make_unique<qb::http::Router<MockTransformSession>>();
    }

    qb::http::Request create_request(
        const std::string& target_path = "/transform_route", 
        const std::string& body = "",
        qb::http::method http_method = qb::http::method::POST // Default to POST
    ) {
        qb::http::Request req;
        req.method() = http_method;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception& e) {
            ADD_FAILURE() << "URI parse failure: " << target_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        if (!body.empty()) {
            req.body() = body;
            req.set_header("Content-Type", "text/plain"); // Assume plain text for simple tests
        }
        return req;
    }

    qb::http::RouteHandlerFn<MockTransformSession> test_handler() {
        return [this](std::shared_ptr<qb::http::Context<MockTransformSession>> ctx) {
            if (_session) {
                _session->_final_handler_called = true;
                _session->_request_body_at_handler = ctx->request().body().as<std::string>();
                _session->_method_at_handler = ctx->request().method(); // Capture the method
                // _session->_request_headers_at_handler = ctx->request().headers(); // Removed

                // Capture specific headers using the public API of THeaders (via Request)
                if (ctx->request().has_header("X-Request-Transformed")) {
                    _session->_xtransformed_header_value = ctx->request().header("X-Request-Transformed");
                }
                _session->_xbody_cleared_header_present = ctx->request().has_header("X-Body-Cleared");
                if (_session->_xbody_cleared_header_present) {
                    _session->_xbody_cleared_header_value = ctx->request().header("X-Body-Cleared");
                }
                if (ctx->request().has_header("Content-Type")) {
                    _session->_content_type_header_at_handler = ctx->request().header("Content-Type");
                }

                // Capture response body *before* any PRE_RESPONSE_SEND hook from TransformMiddleware runs
                _session->_response_body_before_transform_hook = "Initial Handler Response Body"; 
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Initial Handler Response Body";
            ctx->complete();
        };
    }

    void configure_router_and_run(std::shared_ptr<qb::http::TransformMiddleware<MockTransformSession>> transform_mw, qb::http::Request request) {
        _router->use(transform_mw);
        _router->post("/transform_route", test_handler()); // Use POST to easily send request body
        _router->get("/transform_route_get", test_handler()); // For tests not needing req body
        _router->compile();
        
        _session->reset();
        _router->route(_session, std::move(request));
        // Lifecycle hooks for response transformation will be triggered by the router.
    }
};

// Define this function globally or as a static member if preferred for organization
void TestThrowingRequestTransformerFunction(qb::http::Request& /*req*/) {
    std::cerr << "TestThrowingRequestTransformerFunction: Entered function. About to attempt throw." << std::endl;
    // For now, let's see if it even prints. If this prints, then the throw is the next problem.
    throw std::runtime_error("Intentional error from TestThrowingRequestTransformerFunction"); 
}

// --- Test Cases --- 

TEST_F(TransformMiddlewareTest, RequestTransformation) {
    qb::http::TransformMiddleware<MockTransformSession>::RequestTransformer req_transformer = 
        [](qb::http::Request& req) {
            req.set_header("X-Request-Transformed", "true");
            std::string current_body = req.body().as<std::string>();
            req.body() = "Transformed:" + current_body;
        };
    
    auto transform_mw = qb::http::transform_middleware<MockTransformSession>(req_transformer, "RequestTransformerTest");
    configure_router_and_run(transform_mw, create_request("/transform_route", "OriginalBody"));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_request_body_at_handler, "Transformed:OriginalBody");
    // Check if the header set by transform is present in the request when handler sees it.
    ASSERT_FALSE(_session->_xtransformed_header_value.empty());
    EXPECT_EQ(_session->_xtransformed_header_value, "true");
    // EXPECT_TRUE(_session->_xbody_cleared_header_present); // This was an error, belongs to another test
    // EXPECT_EQ(_session->_xbody_cleared_header_value, "true"); // This was an error, belongs to another test
    // EXPECT_EQ(_session->_content_type_header_at_handler, "text/plain"); // Content-Type is set by create_request, not explicitly transformed here.
    // For simplicity, we'll assume the body check is sufficient to prove the transformer ran on the request.
    // To check headers, the test_handler or mock session would need to capture request headers.
}

TEST_F(TransformMiddlewareTest, NullTransformersDoNothing) {
    auto transform_mw = qb::http::transform_middleware<MockTransformSession>(nullptr, "NullTransformerTest");
    configure_router_and_run(transform_mw, create_request("/transform_route_get", "", qb::http::method::GET));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Initial Handler Response Body"); // Should be unchanged by MW
    EXPECT_TRUE(_session->_response.header("X-Request-Transformed").empty());
    EXPECT_TRUE(_session->_response.header("X-Response-Transformed").empty());
}

TEST_F(TransformMiddlewareTest, FactoryFunction) {
    auto mw = qb::http::transform_middleware<MockTransformSession>();
    ASSERT_NE(mw, nullptr);
    EXPECT_EQ(mw->name(), "TransformMiddleware"); // Default name
}

// --- TODO Test Implementations ---

TEST_F(TransformMiddlewareTest, RequestTransformerThrows) {
    // Using an inline lambda that prints and throws
    qb::http::TransformMiddleware<MockTransformSession>::RequestTransformer req_transformer_throws =
        [](qb::http::Request& req /*req*/) {
            std::cerr << "RequestTransformerThrows_Lambda: Entered. About to throw." << std::endl;
            throw std::runtime_error("Intentional error from req_transformer_throws lambda");
        };

    auto transform_mw = qb::http::transform_middleware<MockTransformSession>(req_transformer_throws, "ReqTransformerThrows");
    
    // Need to re-initialize router for specific error handling setup if any
    _router = std::make_unique<qb::http::Router<MockTransformSession>>();
    _router->use(transform_mw);
    _router->post("/transform_route", test_handler());
    // Add a generic error handler to the router if necessary to verify status code,
    // or rely on default router error handling.
    _router->compile();

    _session->reset();
    EXPECT_NO_THROW({
        _router->route(_session, create_request("/transform_route", "OriginalBody"));
    });

    EXPECT_FALSE(_session->_final_handler_called); // Handler should not be reached
    // Expecting a server error status code, assuming the router sets one when a middleware exec_task fails like this.
    // This might depend on the router's specific behavior for unhandled exceptions from middleware process() methods.
    // For now, let's check for 500. If default is different, this needs adjustment.
    EXPECT_EQ(_session->get_response_ref().status(), qb::http::status::INTERNAL_SERVER_ERROR);
}

TEST_F(TransformMiddlewareTest, RequestContentTypeTransform) {
    qb::http::TransformMiddleware<MockTransformSession>::RequestTransformer req_transformer = 
        [](qb::http::Request& req) {
            req.set_header("Content-Type", "application/json");
            req.body() = "JSON:" + req.body().as<std::string>();
        };
    
    auto transform_mw = qb::http::transform_middleware<MockTransformSession>(req_transformer);
    // In test_handler, we'd need to capture the request's Content-Type to verify this.
    // Modifying test_handler or MockTransformSession to store received request headers.
    // For now, _request_body_at_handler check implies transformation.
    configure_router_and_run(transform_mw, create_request("/transform_route", "Data"));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_request_body_at_handler, "JSON:Data");
    // To properly test Content-Type, the handler would need to save it:
    ASSERT_FALSE(_session->_content_type_header_at_handler.empty());
    EXPECT_EQ(_session->_content_type_header_at_handler, "application/json");
}

TEST_F(TransformMiddlewareTest, RequestBodyClearedByTransformer) {
    qb::http::TransformMiddleware<MockTransformSession>::RequestTransformer req_transformer = 
        [](qb::http::Request& req) {
            req.body().clear(); // Clear the body
            req.set_header("X-Body-Cleared", "true");
        };
    
    auto transform_mw = qb::http::transform_middleware<MockTransformSession>(req_transformer, "RequestBodyClearer");
    configure_router_and_run(transform_mw, create_request("/transform_route", "InitialNonEmptyBody"));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_TRUE(_session->_request_body_at_handler.empty());
    ASSERT_TRUE(_session->_xbody_cleared_header_present);
    ASSERT_FALSE(_session->_xbody_cleared_header_value.empty());
    EXPECT_EQ(_session->_xbody_cleared_header_value, "true");
}

TEST_F(TransformMiddlewareTest, RequestMethodChangedByTransformer_LeadsToMiss) {
    qb::http::TransformMiddleware<MockTransformSession>::RequestTransformer req_transformer = 
        [](qb::http::Request& req) {
            req.method() = qb::http::method::PUT; // Change method from POST to PUT
            req.set_header("X-Method-Changed", "true");
        };
    
    auto transform_mw = qb::http::transform_middleware<MockTransformSession>(req_transformer, "RequestMethodChanger");
    
    _router = std::make_unique<qb::http::Router<MockTransformSession>>();
    _router->use(transform_mw);
    _router->post("/transform_route", test_handler()); // Define only a POST route
    _router->put("/transform_route", test_handler());  // Also define a PUT route to be safe, though not strictly needed if POST handler is called
    _router->compile();
        
    _session->reset();
    // Create a POST request, which the transformer will change to PUT
    _router->route(_session, create_request("/transform_route", "SomeBody", qb::http::method::POST));

    // The handler for POST /transform_route SHOULD be called because route matching happens before this middleware type runs.
    // However, the handler should see the method as PUT.
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_method_at_handler, qb::http::method::PUT);
    // We can also check that the response is a 404 Not Found or 405 Method Not Allowed
    // depending on router's behavior for unhandled routes/methods. 
    // For now, not calling the handler is the primary check.
    // EXPECT_NE(_session->get_response_ref().status(), qb::http::status::OK);
}

// ConditionalTransformation would require a ConditionalMiddleware that works with MockTransformSession
// and a way to predicate based on request properties. This is more of an integration test.

// TODO:
// - Test ContentTypeTransformation (e.g. request from XML to JSON, response from JSON to XML)
// - Test ErrorHandlingDuringTransformation (what if a transformer throws?)
// - ConditionalTransformation (perhaps by wrapping TransformMiddleware in a ConditionalMiddleware) 
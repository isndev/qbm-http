#include <gtest/gtest.h>
#include "../http.h" // Main include for qb::http components
#include "../middleware/validation.h" // The middleware being tested
#include "../validation.h" // Main include for validation system - pulls in all qb::http::validation types
#include <qb/json.h>

// Use the new namespace for validation types
using namespace qb::http::validation;

// Mock Session for Middleware Tests
struct MockValidationSessionMid {
    qb::http::Response _response;
    std::string _handler_id_executed;
    bool _final_handler_reached = false;

    qb::http::Response& get_response_ref() { return _response; }

    MockValidationSessionMid& operator<<(const qb::http::Response& resp) {
        _response = resp;
        return *this;
    }

    void reset() {
        _response = qb::http::Response();
        _handler_id_executed.clear();
        _final_handler_reached = false;
    }
};

// Test Fixture for ValidationMiddleware
class ValidationMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockValidationSessionMid> _session;
    std::unique_ptr<qb::http::Router<MockValidationSessionMid>> _router;
    std::shared_ptr<qb::http::validation::RequestValidator> _request_validator; // Now namespaced

    void SetUp() override {
        _session = std::make_shared<MockValidationSessionMid>();
        _router = std::make_unique<qb::http::Router<MockValidationSessionMid>>();
        _request_validator = std::make_shared<qb::http::validation::RequestValidator>(); 
    }

    qb::http::Request create_request(const std::string& path, qb::http::method method = qb::http::method::POST, const std::string& body = "") {
        qb::http::Request req;
        req.method() = method;
        req.uri() = qb::io::uri(path);
        if (!body.empty()) {
            req.body() = body;
            // Assume JSON for body tests unless specified otherwise
            if (body.front() == '{' || body.front() == '[') {
                 req.set_header("Content-Type", "application/json");
            }
        }
        return req;
    }

    qb::http::RouteHandlerFn<MockValidationSessionMid> success_route_handler(const std::string& id = "SuccessHandler") {
        return [this, id](std::shared_ptr<qb::http::Context<MockValidationSessionMid>> ctx) {
            if (_session) {
                _session->_handler_id_executed = id;
                _session->_final_handler_reached = true;
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Handler reached: " + id;
            ctx->complete();
        };
    }

    void configure_and_run(qb::http::Request request) {
        // Create middleware instance with the current _request_validator
        auto val_mw = qb::http::validation_middleware<MockValidationSessionMid>(_request_validator);
        _router->use(val_mw);
        _router->post("/test_validation", success_route_handler());
        _router->get("/test_validation_get", success_route_handler()); // For GET requests
        _router->get("/users/:userId/info", success_route_handler("User Info Handler")); // For path param test
        _router->get("/orders/:orderId", success_route_handler("Order Handler")); // For path param test
        _router->post("/test_sanitization", success_route_handler("Sanitize Handler"));
        _router->compile();

        _session->reset();
        _router->route(_session, std::move(request));
        // Assuming validation middleware is synchronous, no TaskExecutor needed for it directly.
    }
};

// --- ValidationMiddleware Tests ---

TEST_F(ValidationMiddlewareTest, ValidRequestBodyPasses) {
    qb::json body_schema = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}}}
        }},
        {"required", {"name"}}
    };
    _request_validator->for_body(body_schema);

    qb::json valid_body_data = {{"name", "Test User"}};
    configure_and_run(create_request("/test_validation", qb::http::method::POST, valid_body_data.dump()));

    EXPECT_TRUE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ValidationMiddlewareTest, InvalidRequestBodyFails) {
    qb::json body_schema = {
        {"type", "object"},
        {"properties", {
            {"email", {{"type", "string"}, {"pattern", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"}}}
        }},
        {"required", {"email"}}
    };
    _request_validator->for_body(body_schema);

    qb::json invalid_body_data = {{"email", "not-an-email"}};
    configure_and_run(create_request("/test_validation", qb::http::method::POST, invalid_body_data.dump()));

    EXPECT_FALSE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    ASSERT_TRUE(_session->_response.has_header("Content-Type"));
    EXPECT_EQ(_session->_response.header("Content-Type"), "application/json; charset=utf-8");
    
    qb::json error_response = qb::json::parse(_session->_response.body().as<std::string_view>());
    EXPECT_EQ(error_response["message"], "Validation failed.");
    ASSERT_TRUE(error_response["errors"].is_array());
    ASSERT_FALSE(error_response["errors"].empty());
    // The field_path for body errors might be just "body" or more specific like "body.email"
    // Current SchemaValidator creates paths like "email" for root object properties.
    // RequestValidator might prefix this with "body."
    // Let's check if it contains "email" to be flexible
    bool found_email_error = false;
    for (const auto& err : error_response["errors"]){
        if (err["field"].get<std::string>().find("email") != std::string::npos && err["rule"] == "pattern"){
            found_email_error = true;
            break;
        }
    }
    EXPECT_TRUE(found_email_error) << "Email pattern error not found correctly.";
}

TEST_F(ValidationMiddlewareTest, ValidQueryParameterPasses) {
    _request_validator->for_query_param("id", ParameterRuleSet("id").set_type(DataType::INTEGER).set_required());
    configure_and_run(create_request("/test_validation_get?id=123", qb::http::method::GET));
    
    EXPECT_TRUE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ValidationMiddlewareTest, InvalidQueryParameterFails) {
    _request_validator->for_query_param("count", 
        ParameterRuleSet("count")
            .set_type(DataType::INTEGER)
            .add_rule(std::make_shared<MinimumRule>(10))
    );
    configure_and_run(create_request("/test_validation_get?count=5", qb::http::method::GET));

    EXPECT_FALSE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    qb::json error_response = qb::json::parse(_session->_response.body().as<std::string_view>());
    ASSERT_FALSE(error_response["errors"].empty());
    EXPECT_EQ(error_response["errors"][0]["field"], "query.count");
    EXPECT_EQ(error_response["errors"][0]["rule"], "minimum");
}

TEST_F(ValidationMiddlewareTest, ValidHeaderPasses) {
    _request_validator->for_header("X-API-Key", ParameterRuleSet("X-API-Key").set_required());
    qb::http::Request req = create_request("/test_validation_get", qb::http::method::GET);
    req.set_header("X-API-Key", "secrettoken");
    configure_and_run(std::move(req));
    
    EXPECT_TRUE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ValidationMiddlewareTest, InvalidHeaderFails) {
     _request_validator->for_header("Content-Length", 
        ParameterRuleSet("Content-Length")
            .set_type(DataType::INTEGER)
            .add_rule(std::make_shared<MinimumRule>(100))
    );
    qb::http::Request req = create_request("/test_validation_get", qb::http::method::GET);
    req.set_header("Content-Length", "50"); // Invalid according to rule
    configure_and_run(std::move(req));

    EXPECT_FALSE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    qb::json error_response = qb::json::parse(_session->_response.body().as<std::string_view>());
    ASSERT_FALSE(error_response["errors"].empty());
    EXPECT_EQ(error_response["errors"][0]["field"], "header.content-length");
    EXPECT_EQ(error_response["errors"][0]["rule"], "minimum");
}

TEST_F(ValidationMiddlewareTest, BodySanitizationByMiddleware) {
    _request_validator->add_body_sanitizer("description", PredefinedSanitizers::trim());
    _request_validator->for_body({ // Add a simple schema to ensure body is parsed as JSON
        {"type", "object"},
        {"properties", {{"description", {{"type", "string"}}}}}
    });

    // Test handler to check the sanitized body
    _router = std::make_unique<qb::http::Router<MockValidationSessionMid>>(); // Reset router for custom handler
    auto val_mw = qb::http::validation_middleware<MockValidationSessionMid>(_request_validator);
    _router->use(val_mw);
    _router->post("/test_sanitization", [this](auto ctx){
        if (_session) {
            _session->_final_handler_reached = true;
            // Check the body content as received by the handler
            qb::json received_body = qb::json::parse(ctx->request().body().template as<std::string_view>());
            EXPECT_EQ(received_body["description"].get<std::string>(), "Clean Description");
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    qb::json body_to_send = {{"description", "  Clean Description  "}};
    _session->reset();
    _router->route(_session, create_request("/test_sanitization", qb::http::method::POST, body_to_send.dump()));

    EXPECT_TRUE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ValidationMiddlewareTest, MultipleValidationFailures) {
    _request_validator->for_query_param("page", ParameterRuleSet("page").set_type(DataType::INTEGER).set_required());
    _request_validator->for_header("X-Client-Version", ParameterRuleSet("X-Client-Version").add_rule(std::make_shared<MinLengthRule>(3)));

    qb::http::Request req = create_request("/test_validation_get?page=one", qb::http::method::GET);
    req.set_header("X-Client-Version", "1"); // Too short
    configure_and_run(std::move(req));

    EXPECT_FALSE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    qb::json error_response = qb::json::parse(_session->_response.body().as<std::string_view>());
    ASSERT_TRUE(error_response["errors"].is_array());
    EXPECT_EQ(error_response["errors"].size(), 2);
    // Error order is not guaranteed, so check for presence of both
    bool found_page_error = false;
    bool found_header_error = false;
    for (const auto& err : error_response["errors"]) {
        if (err["field"] == "query.page" && err["rule"] == "type") found_page_error = true;
        if (err["field"] == "header.x-client-version" && err["rule"] == "minLength") found_header_error = true;
    }
    EXPECT_TRUE(found_page_error);
    EXPECT_TRUE(found_header_error);
}

// Path parameter validation requires router integration to provide PathParameters to RequestValidator::validate.
// This test simulates that.
TEST_F(ValidationMiddlewareTest, ValidPathParamPasses) {
    _request_validator->for_path_param("userId", ParameterRuleSet("userId").set_type(DataType::INTEGER));
    
    // Simulate path params being set by router before middleware
    _router = std::make_unique<qb::http::Router<MockValidationSessionMid>>();
    auto val_mw = qb::http::validation_middleware<MockValidationSessionMid>(_request_validator);
    _router->use(val_mw);
    _router->get("/users/:userId/info", [this](auto ctx){
        // This handler will be called if validation passes
        if(_session) _session->_final_handler_reached = true;
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();
    
    qb::http::Request req = create_request("/users/123/info", qb::http::method::GET);
    // In a real scenario, RouterCore would populate PathParameters in Context.
    // ValidationMiddleware then gets it from Context.
    // For this test, we need to simulate this. The middleware needs access to ctx->path_parameters().
    // The test infrastructure for `configure_and_run` implicitly handles this as the middleware
    // receives the context which should have path_parameters populated by the router's matching logic.
    _session->reset();
    _router->route(_session, std::move(req));

    EXPECT_TRUE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ValidationMiddlewareTest, InvalidPathParamFails) {
    _request_validator->for_path_param("orderId", ParameterRuleSet("orderId").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(100)));

    _router = std::make_unique<qb::http::Router<MockValidationSessionMid>>();
    auto val_mw = qb::http::validation_middleware<MockValidationSessionMid>(_request_validator);
    _router->use(val_mw);
    _router->get("/orders/:orderId", success_route_handler()); // Path variable name matches for_path_param
    _router->compile();

    qb::http::Request req = create_request("/orders/50", qb::http::method::GET);
    _session->reset();
    _router->route(_session, std::move(req));

    EXPECT_FALSE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    qb::json error_response = qb::json::parse(_session->_response.body().as<std::string_view>());
    ASSERT_FALSE(error_response["errors"].empty());
    EXPECT_EQ(error_response["errors"][0]["field"], "path.orderId");
    EXPECT_EQ(error_response["errors"][0]["rule"], "minimum");
}

TEST_F(ValidationMiddlewareTest, MultiValueQueryParamValidation) {
    _request_validator->for_query_param("ids", 
        ParameterRuleSet("ids")
            .set_type(DataType::INTEGER)
            .add_rule(std::make_shared<MinimumRule>(0)) // Each ID must be >= 0
    );
    // RequestValidator will iterate and validate each value of "ids"
    configure_and_run(create_request("/test_validation_get?ids=10&ids=20&ids=-5&ids=30", qb::http::method::GET));

    EXPECT_FALSE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    qb::json error_response = qb::json::parse(_session->_response.body().as<std::string_view>());
    ASSERT_EQ(error_response["errors"].size(), 1);
    EXPECT_EQ(error_response["errors"][0]["field"], "query.ids");
    EXPECT_EQ(error_response["errors"][0]["rule"], "minimum");
    EXPECT_EQ(error_response["errors"][0]["value"], -5);
}

TEST_F(ValidationMiddlewareTest, QueryParamSanitizationByMiddleware) {
    _request_validator->add_query_param_sanitizer("name", PredefinedSanitizers::trim());
    _request_validator->add_query_param_sanitizer("name", PredefinedSanitizers::to_upper_case());
    // Add a simple rule to ensure validation runs after sanitization
    _request_validator->for_query_param("name", ParameterRuleSet("name").set_type(DataType::STRING).add_rule(std::make_shared<MinLengthRule>(3)));

    _router = std::make_unique<qb::http::Router<MockValidationSessionMid>>();
    auto val_mw = qb::http::validation_middleware<MockValidationSessionMid>(_request_validator);
    _router->use(val_mw);
    _router->get("/test_query_sanitize", [this](auto ctx){
        if (_session) {
            _session->_final_handler_reached = true;
            // Request.uri().query() now returns the first value. 
            // If sanitizers modified the internal vector of strings, this check needs to be smarter
            // or Request::query() should return the sanitized version.
            // Assuming sanitizers modify the request in-place before rules are checked by the same validator instance.
            EXPECT_EQ(ctx->request().uri().query("name"), "TEST NAME");
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    _session->reset();
    _router->route(_session, create_request("/test_query_sanitize?name=  TeSt NaMe  ", qb::http::method::GET));

    EXPECT_TRUE(_session->_final_handler_reached);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
} 
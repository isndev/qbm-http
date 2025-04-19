#include <gtest/gtest.h>
#include "../http.h"
#include "../middleware/validator.h"
#include "../validation/validator.h"

/**
 * @brief MockSession for Validator testing
 */
class MockSession {
public:
    qb::http::Response _response;
    bool _closed = false;
    std::vector<qb::http::Response> _responses;
    std::map<std::string, std::string> _headers;
    std::string _captured_body;
    qb::uuid _id;

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
 * @brief Base test fixture for Validator tests
 */
class ValidatorTest : public ::testing::Test {
protected:
    using Request = qb::http::Request;
    using Response = qb::http::Response;
    using Context = qb::http::RouterContext<MockSession, std::string>;
    using Validator = qb::http::Validator<MockSession, std::string>;
    
    std::shared_ptr<MockSession> session;
    Request request;

    void SetUp() override {
        // Create a mock session
        session = std::make_shared<MockSession>();
        
        // Create a request
        request.method = HTTP_POST;
        request._uri = "/api/users";
        request.add_header("Content-Type", "application/json");
    }

    void TearDown() override {
        session.reset();
    }
    
    // Helper to create a context
    Context create_context() {
        return Context(session, std::move(request));
    }
};

// Test JSON Schema validation
TEST_F(ValidatorTest, JsonSchemaValidation) {
    // Define a schema
    qb::json schema = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}, {"minLength", 3}}},
            {"email", {{"type", "string"}, {"pattern", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"}}},
            {"age", {{"type", "integer"}, {"minimum", 18}}},
            {"tags", {{"type", "array"}, {"items", {{"type", "string"}}}}}
        }},
        {"required", {"name", "email"}}
    };
    
    // Create validator
    Validator validator(schema);
    
    // Test valid input
    {
        request.body() = R"({
            "name": "John Doe",
            "email": "john@example.com",
            "age": 25,
            "tags": ["user", "premium"]
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_TRUE(result);
        EXPECT_FALSE(ctx.is_handled());
    }
    
    // Test invalid input - missing required field
    {
        request.body() = R"({
            "name": "John Doe",
            "age": 25
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        EXPECT_EQ(HTTP_STATUS_BAD_REQUEST, ctx.response.status_code);
        
        auto response_json = qb::json::parse(ctx.response.body());
        EXPECT_EQ("error", response_json["status"]);
        EXPECT_TRUE(response_json["errors"].is_array());
        
        bool found_email_error = false;
        for (const auto& error : response_json["errors"]) {
            if (error["field"] == "email" && error["code"] == "required") {
                found_email_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_email_error);
    }
    
    // Test invalid input - wrong type
    {
        request.body() = R"({
            "name": "John Doe",
            "email": "john@example.com",
            "age": "twenty five"
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        
        auto response_json = qb::json::parse(ctx.response.body());
        bool found_age_error = false;
        for (const auto& error : response_json["errors"]) {
            if (error["field"] == "age" && error["code"] == "type") {
                found_age_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_age_error);
    }
    
    // Test invalid input - pattern validation
    {
        request.body() = R"({
            "name": "John Doe",
            "email": "not-an-email"
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        
        auto response_json = qb::json::parse(ctx.response.body());
        bool found_email_error = false;
        for (const auto& error : response_json["errors"]) {
            if (error["field"] == "email" && error["code"] == "pattern") {
                found_email_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_email_error);
    }
}

// Test query parameter validation
TEST_F(ValidatorTest, QueryParamValidation) {
    // Create validator
    Validator validator;
    
    // Add query parameter rules
    validator.with_query_param("page", qb::http::QueryParamRules().as_integer().min_value(static_cast<int64_t>(1)).default_value("1"));
    validator.with_query_param("limit", qb::http::QueryParamRules().as_integer().range(static_cast<int64_t>(10), static_cast<int64_t>(100)).default_value("10"));
    validator.with_query_param("sort", qb::http::QueryParamRules().one_of({"asc", "desc"}).default_value("asc"));
    validator.with_query_param("email", qb::http::QueryParamRules().email().optional());
    
    // Test valid input
    {
        request._uri = "/api/users?page=2&limit=20&sort=desc";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_TRUE(result);
        EXPECT_FALSE(ctx.is_handled());
    }
    
    // Test invalid input - below minimum
    {
        request._uri = "/api/users?page=0&limit=20";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        
        auto response_json = qb::json::parse(ctx.response.body());
        bool found_page_error = false;
        for (const auto& error : response_json["errors"]) {
            if (error["field"] == "page" && error["code"] == "min_value") {
                found_page_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_page_error);
    }
    
    // Test invalid input - not in enum
    {
        request._uri = "/api/users?page=1&limit=20&sort=invalid";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        
        auto response_json = qb::json::parse(ctx.response.body());
        bool found_sort_error = false;
        for (const auto& error : response_json["errors"]) {
            if (error["field"] == "sort" && error["code"] == "enum") {
                found_sort_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_sort_error);
    }
    
    // Test invalid input - email format
    {
        request._uri = "/api/users?page=1&limit=20&email=not-an-email";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        
        auto response_json = qb::json::parse(ctx.response.body());
        bool found_email_error = false;
        for (const auto& error : response_json["errors"]) {
            if (error["field"] == "email" && error["code"] == "pattern") {
                found_email_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_email_error);
    }
}

// Test sanitization
TEST_F(ValidatorTest, Sanitization) {
    // Define a schema with sanitization
    qb::json schema = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}}},
            {"email", {{"type", "string"}}},
            {"bio", {{"type", "string"}}}
        }}
    };
    
    // Create validator with sanitization rules
    Validator validator(schema);
    validator.with_sanitizer("/name", qb::http::CommonSanitizers::trim);
    validator.with_sanitizer("/email", qb::http::CommonSanitizers::to_lower);
    validator.with_sanitizer("/bio", qb::http::CommonSanitizers::strip_html);
    
    // Test sanitization
    {
        request.body() = R"({
            "name": "  John Doe  ",
            "email": "John@Example.COM",
            "bio": "<p>This is my <b>bio</b></p>"
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_TRUE(result);
        EXPECT_FALSE(ctx.is_handled());
        
        // Check that the request body was sanitized
        auto body_json = qb::json::parse(ctx.request.body());
        EXPECT_EQ("John Doe", body_json["name"]);
        EXPECT_EQ("john@example.com", body_json["email"]);
        EXPECT_EQ("This is my bio", body_json["bio"]);
    }
}

// Test custom validation rules
TEST_F(ValidatorTest, CustomValidation) {
    // Create validator
    Validator validator;
    
    // Add a custom validation rule
    validator.with_custom_rule("password_strength", [](qb::http::ValidationContext& ctx, const Request& req) {
        if (req.body().raw().empty()) {
            return true;
        }
        
        try {
            auto body = qb::json::parse(req.body().raw());
            if (!body.contains("password") || !body["password"].is_string()) {
                return true;
            }
            
            std::string password = body["password"];
            bool has_uppercase = false;
            bool has_lowercase = false;
            bool has_digit = false;
            bool has_special = false;
            
            for (char c : password) {
                if (std::isupper(c)) has_uppercase = true;
                else if (std::islower(c)) has_lowercase = true;
                else if (std::isdigit(c)) has_digit = true;
                else has_special = true;
            }
            
            if (password.length() < 8) {
                ctx.add_error("password", "min_length", "Password must be at least 8 characters long");
                return false;
            }
            
            if (!(has_uppercase && has_lowercase && has_digit && has_special)) {
                ctx.add_error("password", "complexity", 
                    "Password must contain uppercase, lowercase, digit, and special characters");
                return false;
            }
            
            return true;
        } catch (...) {
            return true;
        }
    });
    
    // Test valid password
    {
        request.body() = R"({"password": "Str0ng!P@ss"})";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_TRUE(result);
        EXPECT_FALSE(ctx.is_handled());
    }
    
    // Test weak password
    {
        request.body() = R"({"password": "weak"})";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        
        auto response_json = qb::json::parse(ctx.response.body());
        bool found_password_error = false;
        for (const auto& error : response_json["errors"]) {
            if (error["field"] == "password") {
                found_password_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_password_error);
    }
}

// Test validator middleware integration
TEST_F(ValidatorTest, MiddlewareIntegration) {
    // Define a schema
    qb::json schema = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}, {"minLength", 3}}},
            {"email", {{"type", "string"}}}
        }},
        {"required", {"name", "email"}}
    };
    
    // Create validator middleware directly
    auto middleware = std::make_shared<qb::http::ValidatorMiddleware<MockSession, std::string>>(schema);
    
    // Test valid input with middleware
    {
        request.body() = R"({
            "name": "John Doe",
            "email": "john@example.com"
        })";
        
        auto ctx = create_context();
        auto result = middleware->process(ctx);
        
        EXPECT_TRUE(result.should_continue());
        EXPECT_FALSE(ctx.is_handled());
    }
    
    // Test invalid input with middleware
    {
        request.body() = R"({
            "name": "Jo",
            "email": "john@example.com"
        })";
        
        auto ctx = create_context();
        auto result = middleware->process(ctx);
        
        EXPECT_TRUE(result.should_stop());
        EXPECT_TRUE(ctx.is_handled());
        EXPECT_EQ(HTTP_STATUS_BAD_REQUEST, ctx.response.status_code);
    }
}

// Test custom error handler
TEST_F(ValidatorTest, CustomErrorHandler) {
    // Define a schema
    qb::json schema = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}, {"minLength", 3}}}
        }},
        {"required", {"name"}}
    };
    
    // Create validator with custom error handler
    Validator validator(schema);
    validator.with_error_handler([](Context& ctx, const qb::http::ValidationErrors& errors) {
        // Create a custom error response
        qb::json response = {
            {"success", false},
            {"code", "VALIDATION_ERROR"},
            {"validationErrors", qb::json::array()}
        };
        
        for (const auto& [field, field_errors] : errors) {
            for (const auto& [code, message] : field_errors) {
                response["validationErrors"].push_back({
                    {"field", field},
                    {"errorType", code},
                    {"message", message}
                });
            }
        }
        
        ctx.response.status_code = HTTP_STATUS_UNPROCESSABLE_ENTITY;
        ctx.response.add_header("Content-Type", "application/json");
        ctx.response.body() = response.dump();
        ctx.mark_handled();
    });
    
    // Test invalid input with custom error handler
    {
        request.body() = R"({"name": "Jo"})";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        EXPECT_EQ(HTTP_STATUS_UNPROCESSABLE_ENTITY, ctx.response.status_code);
        
        auto response_json = qb::json::parse(ctx.response.body());
        EXPECT_FALSE(response_json["success"]);
        EXPECT_EQ("VALIDATION_ERROR", response_json["code"]);
        EXPECT_TRUE(response_json["validationErrors"].is_array());
        
        bool found_name_error = false;
        for (const auto& error : response_json["validationErrors"]) {
            if (error["field"] == "name" && error["errorType"] == "minLength") {
                found_name_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_name_error);
    }
}

// Test nested object validation
TEST_F(ValidatorTest, NestedObjectValidation) {
    // Define a schema with nested objects
    qb::json schema = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}}},
            {"address", {
                {"type", "object"},
                {"properties", {
                    {"street", {{"type", "string"}}},
                    {"city", {{"type", "string"}}},
                    {"zipCode", {{"type", "string"}, {"pattern", "^\\d{5}$"}}}
                }},
                {"required", {"street", "city"}}
            }}
        }},
        {"required", {"name", "address"}}
    };
    
    // Create validator
    Validator validator(schema);
    
    // Test valid input with nested object
    {
        request.body() = R"({
            "name": "John Doe",
            "address": {
                "street": "123 Main St",
                "city": "New York",
                "zipCode": "10001"
            }
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_TRUE(result);
        EXPECT_FALSE(ctx.is_handled());
    }
    
    // Test invalid nested object - missing required field
    {
        request.body() = R"({
            "name": "John Doe",
            "address": {
                "street": "123 Main St"
            }
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        
        auto response_json = qb::json::parse(ctx.response.body());
        bool found_city_error = false;
        for (const auto& error : response_json["errors"]) {
            if (error["field"] == "address.city" && error["code"] == "required") {
                found_city_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_city_error);
    }
    
    // Test invalid nested object - pattern validation
    {
        request.body() = R"({
            "name": "John Doe",
            "address": {
                "street": "123 Main St",
                "city": "New York",
                "zipCode": "ABC"
            }
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        
        auto response_json = qb::json::parse(ctx.response.body());
        bool found_zipcode_error = false;
        for (const auto& error : response_json["errors"]) {
            if ((error["field"] == "address.zipCode" || error["field"] == "address/zipCode") && 
                error["code"] == "pattern") {
                found_zipcode_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_zipcode_error);
    }
}

// Test array validation
TEST_F(ValidatorTest, ArrayValidation) {
    // Define a schema with array constraints
    qb::json schema = {
        {"type", "object"},
        {"properties", {
            {"name", {{"type", "string"}}},
            {"tags", {
                {"type", "array"},
                {"items", {{"type", "string"}}},
                {"minItems", 1},
                {"maxItems", 5},
                {"uniqueItems", true}
            }},
            {"scores", {
                {"type", "array"},
                {"items", {{"type", "integer"}, {"minimum", 0}, {"maximum", 100}}},
                {"minItems", 2}
            }}
        }},
        {"required", {"name", "tags", "scores"}}
    };
    
    // Create validator
    Validator validator(schema);
    
    // Test valid input with arrays
    {
        request.body() = R"({
            "name": "John Doe",
            "tags": ["developer", "frontend", "javascript"],
            "scores": [85, 92, 78]
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_TRUE(result);
        EXPECT_FALSE(ctx.is_handled());
    }
    
    // Test invalid array - too few items
    {
        request.body() = R"({
            "name": "John Doe",
            "tags": [],
            "scores": [85, 92]
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        
        auto response_json = qb::json::parse(ctx.response.body());
        bool found_tags_error = false;
        for (const auto& error : response_json["errors"]) {
            if (error["field"] == "tags" && error["code"] == "minItems") {
                found_tags_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_tags_error);
    }
    
    // Test invalid array - duplicate items
    {
        request.body() = R"({
            "name": "John Doe",
            "tags": ["developer", "developer", "javascript"],
            "scores": [85, 92]
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        
        auto response_json = qb::json::parse(ctx.response.body());
        bool found_unique_error = false;
        for (const auto& error : response_json["errors"]) {
            if (error["field"] == "tags" && error["code"] == "uniqueItems") {
                found_unique_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_unique_error);
    }
    
    // Test invalid array - item type validation
    {
        request.body() = R"({
            "name": "John Doe",
            "tags": ["developer", "frontend"],
            "scores": [85, "invalid", 78]
        })";
        
        auto ctx = create_context();
        bool result = validator.validate(ctx);
        
        EXPECT_FALSE(result);
        EXPECT_TRUE(ctx.is_handled());
        
        auto response_json = qb::json::parse(ctx.response.body());
        bool found_type_error = false;
        for (const auto& error : response_json["errors"]) {
            if ((error["field"] == "scores.1" || error["field"] == "scores/1") && 
                error["code"] == "type") {
                found_type_error = true;
                break;
            }
        }
        EXPECT_TRUE(found_type_error);
    }
} 
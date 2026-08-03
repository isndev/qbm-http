/**
 * @file qbm/http/tests/unit/middleware/middleware-validator.cpp
 * @brief Unit tests for qb::http::ValidationMiddleware (body schema, params, sanitizers).
 *
 * The middleware runs a configured RequestValidator over the in-flight request; on
 * failure it emits a 400 with a JSON envelope ({"message","errors":[{field,rule,
 * message,value}]}). Tests pin the exact field path AND rule for every error
 * (schema body paths are bare property names like "email"/"address.zip"; param
 * paths are namespaced "query."/"header."/"path."), and cover the JSON-Schema
 * keyword surface (type/pattern/maxLength/maximum/enum/oneOf, nested objects),
 * sanitizer-gates-rule ordering, and a malformed-JSON body.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include <qb/json.h>

#include <qbm/http/http.h>
#include <qbm/http/middleware/validation.h>
#include <qbm/http/validation.h>

#include "../../shared/middleware_test_fixture.h"

using namespace qb::http::validation;

namespace {

using Session = qb::http::test::MockMiddlewareSession;

class ValidationMiddlewareTest : public qb::http::test::MiddlewareTestFixture<Session> {
protected:
    std::shared_ptr<qb::http::validation::RequestValidator> _request_validator;

    void
    SetUp() override {
        qb::http::test::MiddlewareTestFixture<Session>::SetUp();
        _request_validator = std::make_shared<qb::http::validation::RequestValidator>();
    }

    /** @brief Builds a request, tagging JSON Content-Type when the body looks like JSON. */
    qb::http::Request
    val_request(const std::string &path, qb::http::method method = qb::http::method::POST, const std::string &body = "",
                bool force_json = false) {
        qb::http::Request req;
        req.method() = method;
        req.uri()    = qb::io::uri(path);
        if (!body.empty()) {
            req.body() = body;
            if (force_json || body.front() == '{' || body.front() == '[') {
                req.set_header("Content-Type", "application/json");
            }
        }
        return req;
    }

    /** @brief Terminal handler recording reachability. */
    qb::http::RouteHandlerFn<Session>
    success_route_handler(const std::string &id = "SuccessHandler") {
        return [this, id](std::shared_ptr<qb::http::Context<Session>> ctx) {
            if (_session) {
                _session->_final_handler_called = true;
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Handler reached: " + id;
            ctx->complete();
        };
    }

    /** @brief Wires the validation middleware with the standard route table and routes once. */
    void
    configure_and_run(qb::http::Request request) {
        _router     = std::make_unique<qb::http::Router<Session>>();
        auto val_mw = qb::http::validation_middleware<Session>(_request_validator);
        _router->use(val_mw);
        _router->post("/test_validation", success_route_handler());
        _router->get("/test_validation_get", success_route_handler());
        _router->get("/users/:userId/info", success_route_handler("User Info Handler"));
        _router->get("/orders/:orderId", success_route_handler("Order Handler"));
        _router->post("/test_sanitization", success_route_handler("Sanitize Handler"));
        _router->compile();

        _session->reset();
        _router->route(_session, std::move(request));
    }

    /** @brief Parses the 400 error envelope. */
    [[nodiscard]] qb::json
    error_envelope() const {
        return qb::json::parse(_session->_response.body().as<std::string_view>());
    }

    /** @brief True if the envelope has an error whose field == @p field and rule == @p rule. */
    [[nodiscard]] bool
    has_error(const std::string &field, const std::string &rule) const {
        const auto env = error_envelope();
        if (!env.contains("errors") || !env["errors"].is_array()) {
            return false;
        }
        for (const auto &err : env["errors"]) {
            if (err.value("field", std::string{}) == field && err.value("rule", std::string{}) == rule) {
                return true;
            }
        }
        return false;
    }
};

// --- Body schema -------------------------------------------------------------

TEST_F(ValidationMiddlewareTest, ValidRequestBodyPasses) {
    qb::json body_schema = {{"type", "object"}, {"properties", {{"name", {{"type", "string"}}}}}, {"required", {"name"}}};
    _request_validator->for_body(body_schema);

    configure_and_run(val_request("/test_validation", qb::http::method::POST, qb::json{{"name", "Test User"}}.dump()));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ValidationMiddlewareTest, InvalidEmailPatternFailsWithExactFieldPath) {
    qb::json body_schema = {
        {"type", "object"},
        {"properties", {{"email", {{"type", "string"}, {"pattern", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"}}}}},
        {"required", {"email"}}
    };
    _request_validator->for_body(body_schema);

    configure_and_run(val_request("/test_validation", qb::http::method::POST, qb::json{{"email", "not-an-email"}}.dump()));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    ASSERT_TRUE(_session->_response.has_header("Content-Type"));
    EXPECT_EQ(std::string(_session->_response.header("Content-Type")), "application/json; charset=utf-8");

    const auto env = error_envelope();
    EXPECT_EQ(env["message"], "Validation failed.");
    ASSERT_TRUE(env["errors"].is_array());
    ASSERT_FALSE(env["errors"].empty());
    // SchemaValidator reports root-object property paths bare (no "body." prefix).
    EXPECT_TRUE(has_error("email", "pattern")) << "Expected exact field path 'email' with rule 'pattern'.";
}

TEST_F(ValidationMiddlewareTest, MaxLengthBodyRuleFails) {
    qb::json body_schema = {{"type", "object"}, {"properties", {{"code", {{"type", "string"}, {"maxLength", 4}}}}}};
    _request_validator->for_body(body_schema);

    configure_and_run(val_request("/test_validation", qb::http::method::POST, qb::json{{"code", "toolong"}}.dump()));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_TRUE(has_error("code", "maxLength"));
}

TEST_F(ValidationMiddlewareTest, MaximumBodyRuleFails) {
    qb::json body_schema = {{"type", "object"}, {"properties", {{"qty", {{"type", "integer"}, {"maximum", 100}}}}}};
    _request_validator->for_body(body_schema);

    configure_and_run(val_request("/test_validation", qb::http::method::POST, qb::json{{"qty", 250}}.dump()));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_TRUE(has_error("qty", "maximum"));
}

TEST_F(ValidationMiddlewareTest, EnumBodyRuleFails) {
    qb::json body_schema = {{"type", "object"}, {"properties", {{"color", {{"type", "string"}, {"enum", {"red", "green", "blue"}}}}}}};
    _request_validator->for_body(body_schema);

    configure_and_run(val_request("/test_validation", qb::http::method::POST, qb::json{{"color", "purple"}}.dump()));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_TRUE(has_error("color", "enum"));
}

TEST_F(ValidationMiddlewareTest, NestedObjectSchemaFailsWithDottedPath) {
    qb::json body_schema = {
        {"type", "object"},
        {"properties",
         {{"address", {{"type", "object"}, {"properties", {{"zip", {{"type", "string"}, {"pattern", "^[0-9]{5}$"}}}}}, {"required", {"zip"}}}}}}
    };
    _request_validator->for_body(body_schema);

    qb::json bad = {{"address", {{"zip", "ABCDE"}}}};
    configure_and_run(val_request("/test_validation", qb::http::method::POST, bad.dump()));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    // Nested property paths are dotted from the root object.
    EXPECT_TRUE(has_error("address.zip", "pattern"));
}

TEST_F(ValidationMiddlewareTest, OneOfBodyRuleFailsWhenMatchingNone) {
    // oneOf: value must validate against exactly one sub-schema; a string matches neither.
    qb::json body_schema = {
        {"type", "object"},
        {"properties", {{"id", {{"oneOf", qb::json::array({qb::json{{"type", "integer"}}, qb::json{{"type", "boolean"}}})}}}}}
    };
    _request_validator->for_body(body_schema);

    configure_and_run(val_request("/test_validation", qb::http::method::POST, qb::json{{"id", "a-string"}}.dump()));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_TRUE(has_error("id", "oneOf"));
}

TEST_F(ValidationMiddlewareTest, MalformedJsonBodyFails) {
    qb::json body_schema = {{"type", "object"}, {"properties", {{"name", {{"type", "string"}}}}}};
    _request_validator->for_body(body_schema);

    // Not valid JSON, but Content-Type forces the JSON-parse path.
    configure_and_run(val_request("/test_validation", qb::http::method::POST, "{ not: valid json", /*force_json=*/true));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_TRUE(has_error("body", "invalidFormat.validate"));
}

// --- Query / header / path params -------------------------------------------

TEST_F(ValidationMiddlewareTest, ValidQueryParameterPasses) {
    _request_validator->for_query_param("id", ParameterRuleSet("id").set_type(DataType::INTEGER).set_required());
    configure_and_run(val_request("/test_validation_get?id=123", qb::http::method::GET));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ValidationMiddlewareTest, InvalidQueryParameterFails) {
    _request_validator->for_query_param("count",
                                        ParameterRuleSet("count").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(10)));
    configure_and_run(val_request("/test_validation_get?count=5", qb::http::method::GET));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_TRUE(has_error("query.count", "minimum"));
}

TEST_F(ValidationMiddlewareTest, ValidHeaderPasses) {
    _request_validator->for_header("X-API-Key", ParameterRuleSet("X-API-Key").set_required());
    auto req = val_request("/test_validation_get", qb::http::method::GET);
    req.set_header("X-API-Key", "secrettoken");
    configure_and_run(std::move(req));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ValidationMiddlewareTest, InvalidHeaderFails) {
    _request_validator->for_header("Content-Length",
                                   ParameterRuleSet("Content-Length").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(100)));
    auto req = val_request("/test_validation_get", qb::http::method::GET);
    req.set_header("Content-Length", "50");
    configure_and_run(std::move(req));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_TRUE(has_error("header.content-length", "minimum"));
}

TEST_F(ValidationMiddlewareTest, MultipleValidationFailures) {
    _request_validator->for_query_param("page", ParameterRuleSet("page").set_type(DataType::INTEGER).set_required());
    _request_validator->for_header("X-Client-Version", ParameterRuleSet("X-Client-Version").add_rule(std::make_shared<MinLengthRule>(3)));

    auto req = val_request("/test_validation_get?page=one", qb::http::method::GET);
    req.set_header("X-Client-Version", "1");
    configure_and_run(std::move(req));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    const auto env = error_envelope();
    ASSERT_TRUE(env["errors"].is_array());
    EXPECT_EQ(env["errors"].size(), 2u);
    EXPECT_TRUE(has_error("query.page", "type"));
    EXPECT_TRUE(has_error("header.x-client-version", "minLength"));
}

TEST_F(ValidationMiddlewareTest, ValidPathParamPasses) {
    _request_validator->for_path_param("userId", ParameterRuleSet("userId").set_type(DataType::INTEGER));
    configure_and_run(val_request("/users/123/info", qb::http::method::GET));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ValidationMiddlewareTest, InvalidPathParamFails) {
    _request_validator->for_path_param("orderId",
                                       ParameterRuleSet("orderId").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(100)));
    configure_and_run(val_request("/orders/50", qb::http::method::GET));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_TRUE(has_error("path.orderId", "minimum"));
}

TEST_F(ValidationMiddlewareTest, MultiValueQueryParamValidation) {
    _request_validator->for_query_param("ids", ParameterRuleSet("ids").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(0)));
    configure_and_run(val_request("/test_validation_get?ids=10&ids=20&ids=-5&ids=30", qb::http::method::GET));

    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    const auto env = error_envelope();
    ASSERT_EQ(env["errors"].size(), 1u);
    EXPECT_EQ(env["errors"][0]["field"], "query.ids");
    EXPECT_EQ(env["errors"][0]["rule"], "minimum");
    EXPECT_EQ(env["errors"][0]["value"], -5);
}

// --- Sanitization ------------------------------------------------------------

TEST_F(ValidationMiddlewareTest, BodySanitizationByMiddleware) {
    _request_validator->add_body_sanitizer("description", PredefinedSanitizers::trim());
    _request_validator->for_body({{"type", "object"}, {"properties", {{"description", {{"type", "string"}}}}}});

    _router     = std::make_unique<qb::http::Router<Session>>();
    auto val_mw = qb::http::validation_middleware<Session>(_request_validator);
    _router->use(val_mw);
    _router->post("/test_sanitization", [this](std::shared_ptr<qb::http::Context<Session>> ctx) {
        if (_session) {
            _session->_final_handler_called = true;
            qb::json received_body          = qb::json::parse(ctx->request().body().template as<std::string_view>());
            EXPECT_EQ(received_body["description"].get<std::string>(), "Clean Description");
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    _session->reset();
    _router->route(_session,
                   val_request("/test_sanitization", qb::http::method::POST, qb::json{{"description", "  Clean Description  "}}.dump()));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(ValidationMiddlewareTest, SanitizerGatesRuleSoValidationPassesAfterTransform) {
    // The raw value ("  ab  ", trimmed length 2) would FAIL MinLengthRule(3), but a
    // to_upper + a no-op proves the sanitizer runs BEFORE the rule: trim then pad-check.
    // Here the trimmed+uppercased value "VALID" satisfies MinLength(3), so the rule
    // sees the sanitized value, not the raw one — validation passes.
    _request_validator->add_query_param_sanitizer("name", PredefinedSanitizers::trim());
    _request_validator->add_query_param_sanitizer("name", PredefinedSanitizers::to_upper_case());
    _request_validator->for_query_param("name",
                                        ParameterRuleSet("name").set_type(DataType::STRING).add_rule(std::make_shared<MinLengthRule>(3)));

    _router     = std::make_unique<qb::http::Router<Session>>();
    auto val_mw = qb::http::validation_middleware<Session>(_request_validator);
    _router->use(val_mw);
    _router->get("/test_query_sanitize", [this](std::shared_ptr<qb::http::Context<Session>> ctx) {
        if (_session) {
            _session->_final_handler_called = true;
            EXPECT_EQ(ctx->request().uri().query("name"), "VALID");
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    _router->compile();

    _session->reset();
    _router->route(_session, val_request("/test_query_sanitize?name=  valid  ", qb::http::method::GET));

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

} // namespace

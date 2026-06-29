/**
 * @file qbm/http/tests/unit/validation/validation-request-params.cpp
 * @brief RequestValidator coverage for query/header/body parameter validation.
 *
 * Companion to validation-request.cpp (which owns body-schema empties, sanitizer
 * exceptions, and path-param context). This file drives the parameter-validation
 * arms of request_validator.cpp that were uncovered:
 *
 *   - Query parameters validated against a rule chain (pass + fail), and the
 *     multi-value query path where every occurrence of a repeated parameter is
 *     validated independently (one bad value among several fails the request).
 *   - A required query parameter that is absent → "required".
 *   - Headers validated against a rule chain (pass + fail). Header names round-trip
 *     through the case-insensitive map (reported lower-cased).
 *   - A valid JSON object body accepted by an object schema.
 *   - set_error_value_policy: preview-byte clamping to [16, 64 KiB] and propagation
 *     of the chosen policy into the caller's Result.
 *
 * Pure logic: hand-built qb::http::Request, no socket, no event loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <cstddef>
#include <memory>
#include <string>

#include <qb/json.h>

#include "../validation.h"

using namespace qb::http::validation;

namespace {

class RequestParamsTest : public ::testing::Test {};

// --------------------------------------------------------------------------
// Query parameter validation against a rule chain.
// --------------------------------------------------------------------------

TEST_F(RequestParamsTest, QueryParamTypedRulePasses) {
    RequestValidator validator;
    validator.for_query_param("age", ParameterRuleSet("age").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(18)));

    qb::http::Request req;
    req.uri() = qb::io::uri("/users?age=21");

    Result out;
    EXPECT_TRUE(validator.validate(req, out, nullptr));
    EXPECT_TRUE(out.success());
}

TEST_F(RequestParamsTest, QueryParamTypedRuleFails) {
    RequestValidator validator;
    validator.for_query_param("age", ParameterRuleSet("age").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(18)));

    qb::http::Request req;
    req.uri() = qb::io::uri("/users?age=15");

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1u);
    EXPECT_EQ(out.errors().front().field_path, "query.age");
    EXPECT_EQ(out.errors().front().rule_violated, "minimum");
}

TEST_F(RequestParamsTest, QueryParamWrongTypeReportsTypeError) {
    RequestValidator validator;
    validator.for_query_param("age", ParameterRuleSet("age").set_type(DataType::INTEGER));

    qb::http::Request req;
    req.uri() = qb::io::uri("/users?age=notanumber");

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1u);
    EXPECT_EQ(out.errors().front().field_path, "query.age");
    EXPECT_EQ(out.errors().front().rule_violated, "type");
}

// A required query parameter that is missing fails with "required".
TEST_F(RequestParamsTest, RequiredQueryParamAbsentFails) {
    RequestValidator validator;
    validator.for_query_param("token", ParameterRuleSet("token").set_required().set_type(DataType::STRING));

    qb::http::Request req;
    req.uri() = qb::io::uri("/secure"); // no token query

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1u);
    EXPECT_EQ(out.errors().front().field_path, "query.token");
    EXPECT_EQ(out.errors().front().rule_violated, "required");
}

// Multi-value query (?ids=10&ids=5&ids=20): each occurrence is validated; the
// single out-of-range value (5 < 10) fails the request.
TEST_F(RequestParamsTest, MultiValueQueryValidatesEachOccurrence) {
    RequestValidator validator;
    validator.for_query_param("ids", ParameterRuleSet("ids").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(10)));

    qb::http::Request req;
    req.uri()   = qb::io::uri("/items?ids=10&ids=5&ids=20");
    auto ids_it = req.queries().find("ids");
    ASSERT_NE(ids_it, req.queries().end());
    ASSERT_EQ(ids_it->second.size(), 3u); // confirm the URI parsed all three occurrences

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    // Exactly the offending occurrence (5) produces one minimum error.
    ASSERT_EQ(out.errors().size(), 1u);
    EXPECT_EQ(out.errors().front().field_path, "query.ids");
    EXPECT_EQ(out.errors().front().rule_violated, "minimum");
}

TEST_F(RequestParamsTest, MultiValueQueryAllValidPasses) {
    RequestValidator validator;
    validator.for_query_param("ids", ParameterRuleSet("ids").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(10)));

    qb::http::Request req;
    req.uri() = qb::io::uri("/items?ids=10&ids=15&ids=20");

    Result out;
    EXPECT_TRUE(validator.validate(req, out, nullptr));
    EXPECT_TRUE(out.success());
}

// --------------------------------------------------------------------------
// Header validation against a rule chain.
// --------------------------------------------------------------------------

TEST_F(RequestParamsTest, HeaderTypedRulePasses) {
    RequestValidator validator;
    validator.for_header("X-Count", ParameterRuleSet("X-Count").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(1)));

    qb::http::Request req;
    req.uri() = qb::io::uri("/x");
    req.set_header("X-Count", std::string("5"));

    Result out;
    EXPECT_TRUE(validator.validate(req, out, nullptr));
    EXPECT_TRUE(out.success());
}

TEST_F(RequestParamsTest, HeaderTypedRuleFails) {
    RequestValidator validator;
    validator.for_header("X-Count", ParameterRuleSet("X-Count").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(1)));

    qb::http::Request req;
    req.uri() = qb::io::uri("/x");
    req.set_header("X-Count", std::string("0"));

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1u);
    // Header names are stored / reported case-insensitively (lower-cased).
    EXPECT_EQ(out.errors().front().field_path, "header.x-count");
    EXPECT_EQ(out.errors().front().rule_violated, "minimum");
}

TEST_F(RequestParamsTest, RequiredHeaderAbsentFails) {
    RequestValidator validator;
    validator.for_header("X-Api-Key", ParameterRuleSet("X-Api-Key").set_required().set_type(DataType::STRING));

    qb::http::Request req;
    req.uri() = qb::io::uri("/x"); // no header

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1u);
    EXPECT_EQ(out.errors().front().field_path, "header.x-api-key");
    EXPECT_EQ(out.errors().front().rule_violated, "required");
}

// --------------------------------------------------------------------------
// Valid JSON body accepted by an object schema.
// --------------------------------------------------------------------------

TEST_F(RequestParamsTest, ValidObjectBodyPassesObjectSchema) {
    RequestValidator validator;
    validator.for_body(qb::json{{"type", "object"}, {"required", qb::json::array({"name"})}});

    qb::http::Request req;
    req.uri()  = qb::io::uri("/submit");
    req.body() = R"({"name":"alice"})";

    Result out;
    EXPECT_TRUE(validator.validate(req, out, nullptr));
    EXPECT_TRUE(out.success());
}

TEST_F(RequestParamsTest, ObjectBodyMissingRequiredPropertyFails) {
    RequestValidator validator;
    validator.for_body(qb::json{{"type", "object"}, {"required", qb::json::array({"name"})}});

    qb::http::Request req;
    req.uri()  = qb::io::uri("/submit");
    req.body() = R"({"other":"value"})";

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    EXPECT_FALSE(out.success());
    ASSERT_FALSE(out.errors().empty());
}

// --------------------------------------------------------------------------
// set_error_value_policy: clamping + propagation.
// --------------------------------------------------------------------------

TEST_F(RequestParamsTest, ErrorValuePolicyPreviewBytesClamped) {
    RequestValidator validator;

    validator.set_error_value_policy(Result::ErrorValuePolicy::Preview, 1); // below the 16-byte floor
    EXPECT_EQ(validator.error_value_policy(), Result::ErrorValuePolicy::Preview);
    EXPECT_EQ(validator.offending_value_preview_bytes(), static_cast<std::size_t>(16));

    validator.set_error_value_policy(Result::ErrorValuePolicy::Preview, 1024 * 1024); // above the 64 KiB ceiling
    EXPECT_EQ(validator.offending_value_preview_bytes(), static_cast<std::size_t>(64 * 1024));

    validator.set_error_value_policy(Result::ErrorValuePolicy::Preview, 128); // in range, untouched
    EXPECT_EQ(validator.offending_value_preview_bytes(), static_cast<std::size_t>(128));
}

// validate() forces its configured policy onto the caller's Result, so a "None"
// policy drops the offending value from the produced error.
TEST_F(RequestParamsTest, NonePolicyDropsOffendingValueOnError) {
    RequestValidator validator;
    validator.set_error_value_policy(Result::ErrorValuePolicy::None);
    validator.for_query_param("age", ParameterRuleSet("age").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(18)));

    qb::http::Request req;
    req.uri() = qb::io::uri("/users?age=10");

    Result out; // default policy is Full; validate() overrides it to None
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1u);
    EXPECT_EQ(out.errors().front().rule_violated, "minimum");
    EXPECT_FALSE(out.errors().front().offending_value.has_value());
    EXPECT_EQ(out.error_value_policy(), Result::ErrorValuePolicy::None);
}

} // namespace

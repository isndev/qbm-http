/**
 * @file qbm/http/tests/unit/validation/validation-request.cpp
 * @brief Unit tests for qb::http::validation::RequestValidator end-to-end wiring.
 *
 * Pure-logic coverage of validating a hand-built qb::http::Request: body-schema
 * validation (empty / object / malformed JSON), query/body/header sanitizers
 * (success and throwing), and path-parameter rules with and without a supplied
 * PathParameters context. No socket, no event loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>

#include <qb/json.h>

#include <qbm/http/validation.h> // pulls Request, PathParameters, io::uri transitively

using namespace qb::http::validation;

class ValidationRequestTest : public ::testing::Test {};

// --- Body schema -------------------------------------------------------------

// A scalar-typed schema validating an empty (null) body yields a synthetic
// "contentRequired" error rather than a raw type mismatch.
TEST_F(ValidationRequestTest, EmptyBodyYieldsContentRequired) {
    RequestValidator validator;
    validator.for_body(qb::json{{"type", "integer"}});

    qb::http::Request req;
    req.uri() = qb::io::uri("/submit");

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "body");
    EXPECT_EQ(out.errors().front().rule_violated, "contentRequired");
}

// An object-typed schema validating null produces a "type" error (whose message
// mentions "object") which the validator keeps as-is, reported at the root path.
TEST_F(ValidationRequestTest, EmptyBodyObjectSchemaReportsType) {
    RequestValidator validator;
    validator.for_body(qb::json{{"type", "object"}, {"required", qb::json::array({"name"})}});

    qb::http::Request req;
    req.uri() = qb::io::uri("/submit");

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "");
    EXPECT_EQ(out.errors().front().rule_violated, "type");
}

TEST_F(ValidationRequestTest, InvalidJsonBodyValidate) {
    RequestValidator validator;
    validator.for_body(qb::json{{"type", "object"}});

    qb::http::Request req;
    req.uri()  = qb::io::uri("/submit");
    req.body() = "{not valid json";

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "body");
    EXPECT_EQ(out.errors().front().rule_violated, "invalidFormat.validate");
}

// --- Sanitizers (success + throwing) -----------------------------------------

TEST_F(ValidationRequestTest, QuerySanitizerExceptionIsCaptured) {
    RequestValidator validator;
    validator.add_query_param_sanitizer("q", [](const std::string &) -> std::string { throw std::runtime_error("query sanitizer crash"); });

    qb::http::Request req;
    req.uri() = qb::io::uri("/search?q=test");

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "query.q");
    EXPECT_EQ(out.errors().front().rule_violated, "sanitizeException.query");
}

TEST_F(ValidationRequestTest, BodySanitizerExceptionIsCaptured) {
    RequestValidator validator;
    validator.add_body_sanitizer("name", [](const std::string &) -> std::string { throw std::runtime_error("body sanitizer crash"); });

    qb::http::Request req;
    req.uri()  = qb::io::uri("/submit");
    req.body() = R"({"name":"alice"})";

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "body");
    EXPECT_EQ(out.errors().front().rule_violated, "sanitizeException.body");
}

TEST_F(ValidationRequestTest, BodySanitizerInvalidJson) {
    RequestValidator validator;
    validator.add_body_sanitizer("name", [](const std::string &v) -> std::string { return v; });

    qb::http::Request req;
    req.uri()  = qb::io::uri("/submit");
    req.body() = "{not valid json";

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "body");
    EXPECT_EQ(out.errors().front().rule_violated, "invalidFormat.sanitize");
}

TEST_F(ValidationRequestTest, HeaderSanitizerSuccess) {
    RequestValidator validator;
    validator.add_header_sanitizer("X-Test", [](const std::string &v) -> std::string { return v + "-sanitized"; });

    qb::http::Request req;
    req.uri() = qb::io::uri("/submit");
    req.set_header("X-Test", std::string("raw"));

    Result out;
    EXPECT_TRUE(validator.validate(req, out, nullptr));
    EXPECT_TRUE(out.success());
    // The sanitizer mutated the header value in place.
    auto it = req.headers().find("X-Test");
    ASSERT_NE(it, req.headers().end());
    ASSERT_FALSE(it->second.empty());
    EXPECT_EQ(it->second.front(), "raw-sanitized");
}

TEST_F(ValidationRequestTest, HeaderSanitizerExceptionIsCaptured) {
    RequestValidator validator;
    validator.add_header_sanitizer("X-Test", [](const std::string &) -> std::string { throw std::runtime_error("header sanitizer crash"); });

    qb::http::Request req;
    req.uri() = qb::io::uri("/submit");
    req.set_header("X-Test", std::string("raw"));

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    // Header names are stored case-insensitively (lowercased) in the headers map.
    EXPECT_EQ(out.errors().front().field_path, "header.x-test");
    EXPECT_EQ(out.errors().front().rule_violated, "sanitizeException.header");
}

// A sanitizer that throws a non-std exception type (not derived from
// std::exception) must still be contained by the catch-all and reported, for the
// query, header and body sanitizer paths respectively.
TEST_F(ValidationRequestTest, QuerySanitizerNonStdExceptionIsCaptured) {
    RequestValidator validator;
    validator.add_query_param_sanitizer("q", [](const std::string &) -> std::string { throw 42; });

    qb::http::Request req;
    req.uri() = qb::io::uri("/search?q=test");

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "query.q");
    EXPECT_EQ(out.errors().front().rule_violated, "sanitizeException.query");
}

TEST_F(ValidationRequestTest, HeaderSanitizerNonStdExceptionIsCaptured) {
    RequestValidator validator;
    validator.add_header_sanitizer("X-Test", [](const std::string &) -> std::string { throw 42; });

    qb::http::Request req;
    req.uri() = qb::io::uri("/submit");
    req.set_header("X-Test", std::string("raw"));

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "header.x-test");
    EXPECT_EQ(out.errors().front().rule_violated, "sanitizeException.header");
}

TEST_F(ValidationRequestTest, BodySanitizerNonStdExceptionIsCaptured) {
    RequestValidator validator;
    validator.add_body_sanitizer("name", [](const std::string &) -> std::string { throw 42; });

    qb::http::Request req;
    req.uri()  = qb::io::uri("/submit");
    req.body() = R"({"name":"alice"})";

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "body");
    EXPECT_EQ(out.errors().front().rule_violated, "sanitizeException.body");
}

// --- Path parameters ---------------------------------------------------------

// Path-param rules require a PathParameters context; without one the parameter
// is treated as absent, so a typed path rule reports "required".
TEST_F(ValidationRequestTest, PathRulesRequirePathParameterContext) {
    RequestValidator validator;
    validator.for_path_param("userId", ParameterRuleSet("userId").set_type(DataType::INTEGER));

    qb::http::Request req;
    req.uri() = qb::io::uri("/users/123");

    Result out;
    EXPECT_FALSE(validator.validate(req, out, nullptr));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1);
    EXPECT_EQ(out.errors().front().field_path, "path.userId");
    EXPECT_EQ(out.errors().front().rule_violated, "required");
}

TEST_F(ValidationRequestTest, PathParamWithContext) {
    RequestValidator validator;
    validator.for_path_param("userId", ParameterRuleSet("userId").set_type(DataType::INTEGER));

    qb::http::Request req;
    req.uri() = qb::io::uri("/users/123");

    qb::http::PathParameters pp;
    pp.set("userId", "123");

    // Present and valid -> passes.
    Result out_ok;
    EXPECT_TRUE(validator.validate(req, out_ok, &pp));
    EXPECT_TRUE(out_ok.success());

    // Present but non-integer -> type error.
    qb::http::PathParameters pp_bad;
    pp_bad.set("userId", "abc");
    Result out_bad;
    EXPECT_FALSE(validator.validate(req, out_bad, &pp_bad));
    ASSERT_FALSE(out_bad.success());
    ASSERT_EQ(out_bad.errors().size(), 1);
    EXPECT_EQ(out_bad.errors().front().field_path, "path.userId");
    EXPECT_EQ(out_bad.errors().front().rule_violated, "type");
}

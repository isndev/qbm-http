/**
 * @file qbm/http/tests/unit/validation/validation-parameter-types.cpp
 * @brief Type-coercion + presence-policy coverage for ParameterValidator.
 *
 * Companion to validation-parameter.cpp. That file owns required/rule-chain/
 * custom-parser/strict-mode; this one drills the `parse_value` coercion switch
 * and the `validate_single` presence policy, which are the remaining uncovered
 * arms of parameter_validator.cpp:
 *
 *   - STRING passes through verbatim; ARRAY is treated as an opaque string at the
 *     parse stage (rules apply afterwards).
 *   - BOOLEAN accepts true/false/1/0 (case-insensitively) and rejects anything else.
 *   - NUMBER preserves integral doubles as JSON integers and keeps real fractions
 *     as doubles.
 *   - INTEGER rejects a partially-numeric input (trailing garbage / overflow).
 *   - OBJECT / NUL / ANY are unsupported as scalar parameter types → "type" error
 *     whose message names the rejected type.
 *   - Absent + optional + no default → no value, no error (the silent-skip arm).
 *   - Absent + required + default → the default is substituted and validated.
 *   - A custom parser that flags failure without adding its own error gets a
 *     generic "customParse" error synthesised for it.
 *
 * Pure logic: no socket, no loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <optional>
#include <string>

#include <qb/json.h>

#include "../validation.h"

using namespace qb::http::validation;

namespace {

class ParameterTypesTest : public ::testing::Test {
protected:
    ParameterValidator pv;
    Result             result;
};

// --------------------------------------------------------------------------
// STRING / ARRAY: opaque pass-through at the parse stage.
// --------------------------------------------------------------------------

TEST_F(ParameterTypesTest, StringPassesThroughVerbatim) {
    qb::json out =
        pv.validate_single("name", std::make_optional<std::string>("Hello World"), ParameterRuleSet("name").set_type(DataType::STRING),
                           result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(out.is_string());
    EXPECT_EQ(out.get<std::string>(), "Hello World");
}

TEST_F(ParameterTypesTest, ArrayTypeTreatedAsOpaqueString) {
    // DataType::ARRAY is intentionally not parsed into a JSON array here; the raw
    // comma-separated string is returned and any item rules apply afterwards.
    qb::json out =
        pv.validate_single("ids", std::make_optional<std::string>("1,2,3"), ParameterRuleSet("ids").set_type(DataType::ARRAY), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(out.is_string());
    EXPECT_EQ(out.get<std::string>(), "1,2,3");
}

// --------------------------------------------------------------------------
// BOOLEAN coercion.
// --------------------------------------------------------------------------

TEST_F(ParameterTypesTest, BooleanTrueForms) {
    for (const std::string &v : {std::string("true"), std::string("TRUE"), std::string("1")}) {
        Result   r;
        qb::json out = pv.validate_single("flag", std::make_optional(v), ParameterRuleSet("flag").set_type(DataType::BOOLEAN), r, "query");
        EXPECT_TRUE(r.success()) << "input: " << v;
        ASSERT_TRUE(out.is_boolean()) << "input: " << v;
        EXPECT_TRUE(out.get<bool>()) << "input: " << v;
    }
}

TEST_F(ParameterTypesTest, BooleanFalseForms) {
    for (const std::string &v : {std::string("false"), std::string("False"), std::string("0")}) {
        Result   r;
        qb::json out = pv.validate_single("flag", std::make_optional(v), ParameterRuleSet("flag").set_type(DataType::BOOLEAN), r, "query");
        EXPECT_TRUE(r.success()) << "input: " << v;
        ASSERT_TRUE(out.is_boolean()) << "input: " << v;
        EXPECT_FALSE(out.get<bool>()) << "input: " << v;
    }
}

TEST_F(ParameterTypesTest, BooleanInvalidRejected) {
    qb::json out =
        pv.validate_single("flag", std::make_optional<std::string>("maybe"), ParameterRuleSet("flag").set_type(DataType::BOOLEAN), result,
                           "query");
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(out.is_null());
    ASSERT_EQ(result.errors().size(), 1u);
    EXPECT_EQ(result.errors().front().field_path, "query.flag");
    EXPECT_EQ(result.errors().front().rule_violated, "type");
}

// --------------------------------------------------------------------------
// NUMBER: integral doubles preserved as integers, fractions kept as doubles.
// --------------------------------------------------------------------------

TEST_F(ParameterTypesTest, NumberIntegralIsStoredAsInteger) {
    qb::json out =
        pv.validate_single("v", std::make_optional<std::string>("42"), ParameterRuleSet("v").set_type(DataType::NUMBER), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(out.is_number_integer());
    EXPECT_EQ(out.get<long long>(), 42);
}

TEST_F(ParameterTypesTest, NumberFractionKeptAsDouble) {
    qb::json out =
        pv.validate_single("v", std::make_optional<std::string>("3.5"), ParameterRuleSet("v").set_type(DataType::NUMBER), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(out.is_number_float());
    EXPECT_DOUBLE_EQ(out.get<double>(), 3.5);
}

TEST_F(ParameterTypesTest, NumberRejectsTrailingGarbage) {
    qb::json out =
        pv.validate_single("v", std::make_optional<std::string>("3.5abc"), ParameterRuleSet("v").set_type(DataType::NUMBER), result, "query");
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(out.is_null());
    ASSERT_EQ(result.errors().size(), 1u);
    EXPECT_EQ(result.errors().front().rule_violated, "type");
}

// --------------------------------------------------------------------------
// INTEGER: must consume the whole input.
// --------------------------------------------------------------------------

TEST_F(ParameterTypesTest, IntegerRejectsPartialParse) {
    qb::json out =
        pv.validate_single("n", std::make_optional<std::string>("12x"), ParameterRuleSet("n").set_type(DataType::INTEGER), result, "query");
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(out.is_null());
    ASSERT_EQ(result.errors().size(), 1u);
    EXPECT_EQ(result.errors().front().field_path, "query.n");
    EXPECT_EQ(result.errors().front().rule_violated, "type");
}

TEST_F(ParameterTypesTest, IntegerNegativeAccepted) {
    qb::json out =
        pv.validate_single("n", std::make_optional<std::string>("-17"), ParameterRuleSet("n").set_type(DataType::INTEGER), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(out.is_number_integer());
    EXPECT_EQ(out.get<long long>(), -17);
}

// --------------------------------------------------------------------------
// Unsupported scalar types: OBJECT / NUL / ANY.
// --------------------------------------------------------------------------

TEST_F(ParameterTypesTest, ObjectTypeUnsupported) {
    qb::json out =
        pv.validate_single("o", std::make_optional<std::string>("{}"), ParameterRuleSet("o").set_type(DataType::OBJECT), result, "query");
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(out.is_null());
    ASSERT_EQ(result.errors().size(), 1u);
    EXPECT_EQ(result.errors().front().rule_violated, "type");
    // The message names the rejected type so the caller can see what was unsupported.
    EXPECT_NE(result.errors().front().message.find("object"), std::string::npos);
}

TEST_F(ParameterTypesTest, NullAndAnyTypesUnsupported) {
    {
        Result   r;
        qb::json out = pv.validate_single("v", std::make_optional<std::string>("x"), ParameterRuleSet("v").set_type(DataType::NUL), r, "query");
        EXPECT_FALSE(r.success());
        ASSERT_EQ(r.errors().size(), 1u);
        EXPECT_EQ(r.errors().front().rule_violated, "type");
        EXPECT_NE(r.errors().front().message.find("null"), std::string::npos);
    }
    {
        Result   r;
        qb::json out = pv.validate_single("v", std::make_optional<std::string>("x"), ParameterRuleSet("v").set_type(DataType::ANY), r, "query");
        EXPECT_FALSE(r.success());
        ASSERT_EQ(r.errors().size(), 1u);
        EXPECT_EQ(r.errors().front().rule_violated, "type");
        EXPECT_NE(r.errors().front().message.find("any"), std::string::npos);
    }
}

// --------------------------------------------------------------------------
// Presence policy in validate_single.
// --------------------------------------------------------------------------

// Absent + optional + no default: silently skipped — null result, no error.
TEST_F(ParameterTypesTest, AbsentOptionalNoDefaultIsSilentlySkipped) {
    qb::json out = pv.validate_single("opt", std::nullopt, ParameterRuleSet("opt").set_type(DataType::STRING), result, "query");
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(out.is_null());
    EXPECT_TRUE(result.errors().empty());
}

// Absent + required + default present: the default is substituted and validated.
TEST_F(ParameterTypesTest, AbsentRequiredWithDefaultUsesDefault) {
    qb::json out = pv.validate_single(
        "limit", std::nullopt, ParameterRuleSet("limit").set_required().set_type(DataType::INTEGER).set_default("25"), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(out.is_number_integer());
    EXPECT_EQ(out.get<long long>(), 25);
}

// Absent + required + no default: "required" error.
TEST_F(ParameterTypesTest, AbsentRequiredNoDefaultErrors) {
    qb::json out =
        pv.validate_single("token", std::nullopt, ParameterRuleSet("token").set_required().set_type(DataType::STRING), result, "query");
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(out.is_null());
    ASSERT_EQ(result.errors().size(), 1u);
    EXPECT_EQ(result.errors().front().field_path, "query.token");
    EXPECT_EQ(result.errors().front().rule_violated, "required");
}

// --------------------------------------------------------------------------
// Custom parser that flags failure WITHOUT adding its own error.
// --------------------------------------------------------------------------

TEST_F(ParameterTypesTest, SilentlyFailingCustomParserGetsGenericError) {
    auto silent_fail = [](const std::string &, bool &success) -> qb::json {
        success = false; // signals failure but adds no error of its own
        return nullptr;
    };

    qb::json out = pv.validate_single("p", std::make_optional<std::string>("anything"),
                                      ParameterRuleSet("p").set_custom_parser(silent_fail), result, "query");
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(out.is_null());
    ASSERT_EQ(result.errors().size(), 1u);
    EXPECT_EQ(result.errors().front().field_path, "query.p");
    EXPECT_EQ(result.errors().front().rule_violated, "customParse");
}

} // namespace

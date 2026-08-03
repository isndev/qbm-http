/**
 * @file qbm/http/tests/unit/validation/validation-parameter.cpp
 * @brief Unit tests for qb::http::validation::{ParameterValidator, ParameterRuleSet}.
 *
 * Pure-logic coverage of scalar parameter validation: required, type coercion
 * from string, rule chains, defaults, custom parsers, exception capture (parser
 * and rule), strict-mode unexpected-parameter rejection, multi-value handling,
 * and error-value-policy propagation into child results. No socket, no loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <algorithm>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <qb/json.h>

#include <qbm/http/validation.h>

using namespace qb::http::validation;

class ValidationParameterTest : public ::testing::Test {
protected:
    Result result;

    void
    SetUp() override {
        result.clear();
    }
};

TEST_F(ValidationParameterTest, Required) {
    ParameterValidator pv;
    pv.add_param(ParameterRuleSet("name").set_required());

    result.clear();
    qb::icase_unordered_map<std::string> params_ok = {{"name", "value"}};
    EXPECT_TRUE(pv.validate(params_ok, result, "query"));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::icase_unordered_map<std::string> params_missing = {};
    EXPECT_FALSE(pv.validate(params_missing, result, "query"));
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.name");
    EXPECT_EQ(result.errors()[0].rule_violated, "required");
}

TEST_F(ValidationParameterTest, TypeConversionAndRule) {
    ParameterValidator pv;
    pv.add_param(ParameterRuleSet("age").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(18)));

    result.clear();
    qb::icase_unordered_map<std::string> params_valid = {{"age", "20"}};
    EXPECT_TRUE(pv.validate(params_valid, result, "query"));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::icase_unordered_map<std::string> params_invalid_val = {{"age", "17"}};
    EXPECT_FALSE(pv.validate(params_invalid_val, result, "query"));
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.age");
    EXPECT_EQ(result.errors()[0].rule_violated, "minimum");

    result.clear();
    qb::icase_unordered_map<std::string> params_invalid_type = {{"age", "abc"}};
    EXPECT_FALSE(pv.validate(params_invalid_type, result, "query"));
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.age");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
}

TEST_F(ValidationParameterTest, NumberRejectsNaNAndInfinity) {
    ParameterValidator pv;
    pv.add_param(ParameterRuleSet("value").set_type(DataType::NUMBER));

    result.clear();
    qb::icase_unordered_map<std::string> params_nan = {{"value", "nan"}};
    EXPECT_FALSE(pv.validate(params_nan, result, "query"));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.value");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");

    result.clear();
    qb::icase_unordered_map<std::string> params_inf = {{"value", "inf"}};
    EXPECT_FALSE(pv.validate(params_inf, result, "query"));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.value");
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
}

TEST_F(ValidationParameterTest, DefaultValue) {
    ParameterValidator pv;

    // Absent value -> the default "10" is parsed and validated.
    result.clear();
    qb::json validated_json = pv.validate_single(
        "limit", std::nullopt,
        ParameterRuleSet("limit").set_type(DataType::INTEGER).set_default("10").add_rule(std::make_shared<MinimumRule>(1)), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(validated_json.is_number_integer());
    EXPECT_EQ(validated_json.get<long long>(), 10);

    // Present value overrides the default.
    result.clear();
    validated_json = pv.validate_single(
        "limit", std::make_optional<std::string>("5"),
        ParameterRuleSet("limit").set_type(DataType::INTEGER).set_default("10").add_rule(std::make_shared<MinimumRule>(1)), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(validated_json.is_number_integer());
    EXPECT_EQ(validated_json.get<long long>(), 5);

    // The default itself is validated against the rule chain: default "0" fails minimum:1.
    result.clear();
    validated_json = pv.validate_single(
        "limit", std::nullopt,
        ParameterRuleSet("limit").set_type(DataType::INTEGER).set_default("0").add_rule(std::make_shared<MinimumRule>(1)), result, "query");
    EXPECT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "minimum");
    EXPECT_TRUE(validated_json.is_null());
}

TEST_F(ValidationParameterTest, CustomParser) {
    ParameterValidator pv;
    auto               custom_bool_parser = [](const std::string &input, bool &success) -> qb::json {
        std::string lower_input = input;
        std::transform(lower_input.begin(), lower_input.end(), lower_input.begin(), ::tolower);
        if (lower_input == "yes" || lower_input == "on") {
            success = true;
            return true;
        }
        if (lower_input == "no" || lower_input == "off") {
            success = true;
            return false;
        }
        success = false;
        return nullptr;
    };

    pv.add_param(ParameterRuleSet("enabled").set_custom_parser(custom_bool_parser).set_type(DataType::BOOLEAN));

    result.clear();
    qb::icase_unordered_map<std::string> params_yes = {{"enabled", "YES"}};
    EXPECT_TRUE(pv.validate(params_yes, result, "query"));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::json parsed =
        pv.validate_single("enabled", std::make_optional<std::string>("YES"),
                           ParameterRuleSet("enabled").set_custom_parser(custom_bool_parser).set_type(DataType::BOOLEAN), result, "query");
    EXPECT_TRUE(result.success());
    ASSERT_TRUE(parsed.is_boolean());
    EXPECT_TRUE(parsed.get<bool>());

    result.clear();
    qb::icase_unordered_map<std::string> params_invalid = {{"enabled", "maybe"}};
    EXPECT_FALSE(pv.validate(params_invalid, result, "query"));
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "customParse");
}

TEST_F(ValidationParameterTest, CustomParserExceptionIsCaptured) {
    ParameterValidator pv;
    auto               throwing_parser = [](const std::string &, bool &) -> qb::json {
        throw std::runtime_error("parser blew up");
    };
    pv.add_param(ParameterRuleSet("enabled").set_custom_parser(throwing_parser));

    result.clear();
    qb::icase_unordered_map<std::string> params = {{"enabled", "yes"}};
    EXPECT_FALSE(pv.validate(params, result, "query"));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.enabled");
    EXPECT_EQ(result.errors()[0].rule_violated, "customParseException");
}

TEST_F(ValidationParameterTest, RuleExceptionIsCaptured) {
    ParameterValidator pv;
    auto               throwing_rule = std::make_shared<CustomRule>(
        [](const qb::json &, const std::string &, Result &) -> bool { throw std::runtime_error("rule blew up"); }, "throwing_rule");

    pv.add_param(ParameterRuleSet("name").set_type(DataType::STRING).add_rule(throwing_rule));

    result.clear();
    qb::icase_unordered_map<std::string> params = {{"name", "alice"}};
    EXPECT_FALSE(pv.validate(params, result, "query"));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.name");
    EXPECT_EQ(result.errors()[0].rule_violated, "ruleExecutionException");
}

TEST_F(ValidationParameterTest, StrictMode) {
    ParameterValidator pv_strict(true);
    pv_strict.add_param(ParameterRuleSet("id").set_type(DataType::INTEGER));
    pv_strict.add_param(ParameterRuleSet("name").set_type(DataType::STRING));

    result.clear();
    qb::icase_unordered_map<std::string> params_ok = {{"id", "123"}, {"name", "test"}};
    EXPECT_TRUE(pv_strict.validate(params_ok, result, "query"));
    EXPECT_TRUE(result.success());

    result.clear();
    qb::icase_unordered_map<std::string> params_extra_strict = {{"id", "123"}, {"name", "test"}, {"unexpected", "value"}};
    EXPECT_FALSE(pv_strict.validate(params_extra_strict, result, "query"));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.unexpected");
    EXPECT_EQ(result.errors()[0].rule_violated, "unexpectedParameter");

    // Non-strict validator ignores the extra parameter.
    ParameterValidator pv_non_strict;
    pv_non_strict.add_param(ParameterRuleSet("id").set_type(DataType::INTEGER));

    result.clear();
    qb::icase_unordered_map<std::string> params_extra_non_strict = {{"id", "123"}, {"name", "test"}, {"unexpected", "value"}};
    EXPECT_TRUE(pv_non_strict.validate(params_extra_non_strict, result, "query"));
    EXPECT_TRUE(result.success());
}

// Multiple values for a single parameter are validated independently via
// validate_single; a single out-of-range value surfaces one minimum error
// carrying the offending value.
TEST_F(ValidationParameterTest, MultiValueSupport) {
    ParameterValidator pv;
    auto               rules = ParameterRuleSet("ids").set_type(DataType::INTEGER).add_rule(std::make_shared<MinimumRule>(10));

    std::vector<std::string> valid_values   = {"10", "20", "30"};
    std::vector<std::string> invalid_values = {"15", "5", "25"};

    result.clear();
    bool all_valid_pass = true;
    for (const auto &val_str : valid_values) {
        Result item_result;
        pv.validate_single("ids", std::make_optional(val_str), rules, item_result, "query");
        if (!item_result.success()) {
            all_valid_pass = false;
            result.merge(item_result);
        }
    }
    EXPECT_TRUE(all_valid_pass);
    EXPECT_TRUE(result.success());

    result.clear();
    bool some_invalid_pass = true;
    for (const auto &val_str : invalid_values) {
        Result item_result;
        pv.validate_single("ids", std::make_optional(val_str), rules, item_result, "query");
        if (!item_result.success()) {
            some_invalid_pass = false;
            result.merge(item_result);
        }
    }
    EXPECT_FALSE(some_invalid_pass);
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "query.ids");
    EXPECT_EQ(result.errors()[0].rule_violated, "minimum");
    ASSERT_TRUE(result.errors()[0].offending_value.has_value());
    EXPECT_EQ(result.errors()[0].offending_value.value(), qb::json(5));
}

TEST_F(ValidationParameterTest, PropagatesErrorValuePolicyToChildResults) {
    ParameterValidator pv;
    pv.add_param(ParameterRuleSet("name").set_type(DataType::STRING).add_rule(std::make_shared<MinLengthRule>(3)));

    qb::icase_unordered_map<std::string> params;
    params["name"] = "ab";

    Result out;
    out.set_error_value_policy(Result::ErrorValuePolicy::None);

    EXPECT_FALSE(pv.validate(params, out, "query"));
    ASSERT_FALSE(out.success());
    ASSERT_EQ(out.errors().size(), 1u);
    EXPECT_EQ(out.errors().front().field_path, "query.name");
    EXPECT_EQ(out.errors().front().rule_violated, "minLength");
    EXPECT_FALSE(out.errors().front().offending_value.has_value());
}

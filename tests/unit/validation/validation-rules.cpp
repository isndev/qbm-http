/**
 * @file qbm/http/tests/unit/validation/validation-rules.cpp
 * @brief Unit tests for the concrete qb::http::validation::IRule implementations.
 *
 * Pure-logic coverage of each leaf rule (Type, MinLength, MaxLength, Pattern,
 * Minimum, Maximum, Enum, UniqueItems, MinItems, MaxItems, Custom) plus the
 * PatternRule ReDoS input-size guard. No socket, no event loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>
#include <memory>
#include <stdexcept>
#include <string>

#include <qb/json.h>

#include "../validation.h"

using namespace qb::http::validation;

class ValidationRulesTest : public ::testing::Test {
protected:
    Result result;

    void
    SetUp() override {
        result.clear();
    }
};

// --- TypeRule ----------------------------------------------------------------

TEST_F(ValidationRulesTest, TypeRuleValidation) {
    TypeRule string_rule(DataType::STRING);
    TypeRule int_rule(DataType::INTEGER);
    TypeRule num_rule(DataType::NUMBER);
    TypeRule bool_rule(DataType::BOOLEAN);
    TypeRule obj_rule(DataType::OBJECT);
    TypeRule arr_rule(DataType::ARRAY);
    TypeRule null_rule(DataType::NUL);
    TypeRule any_rule(DataType::ANY);

    result.clear();
    EXPECT_TRUE(string_rule.validate(qb::json("hello"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(string_rule.validate(qb::json(123), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "type");

    result.clear();
    EXPECT_TRUE(int_rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(int_rule.validate(qb::json(123.5), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "type");
    result.clear();
    EXPECT_FALSE(int_rule.validate(qb::json("123"), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(num_rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(num_rule.validate(qb::json(123.5), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(num_rule.validate(qb::json("123.5"), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(bool_rule.validate(qb::json(true), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(bool_rule.validate(qb::json(1), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(obj_rule.validate(qb::json::object(), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(obj_rule.validate(qb::json::array(), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(arr_rule.validate(qb::json::array(), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(arr_rule.validate(qb::json::object(), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(null_rule.validate(qb::json(nullptr), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(null_rule.validate(qb::json(0), "test", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(any_rule.validate(qb::json("any_value"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(any_rule.validate(qb::json(nullptr), "test", result));
    EXPECT_TRUE(result.success());
}

// --- MinLengthRule -----------------------------------------------------------

TEST_F(ValidationRulesTest, MinLengthRuleValidation) {
    MinLengthRule rule(3);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("abc"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("abcd"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json("ab"), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "minLength");

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2, 3}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1, 2}), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "minLength");

    // Rule does not apply to numbers -> passes through.
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
}

// --- MaxLengthRule -----------------------------------------------------------

TEST_F(ValidationRulesTest, MaxLengthRuleValidation) {
    MaxLengthRule rule(3);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("abc"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("ab"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json("abcd"), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "maxLength");

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2, 3}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1, 2, 3, 4}), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "maxLength");

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
}

// --- PatternRule -------------------------------------------------------------

TEST_F(ValidationRulesTest, PatternRuleValidation) {
    PatternRule rule("^[a-zA-Z]+$");
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("abcXYZ"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json("abc123"), "test", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json(""), "test", result));
    EXPECT_FALSE(result.success());
    // Non-string values are not constrained by a pattern rule.
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());

    EXPECT_EQ(rule.rule_name(), "pattern");

    // Invalid regex and over-long patterns are rejected at construction time.
    ASSERT_THROW(PatternRule("["), std::invalid_argument);
    ASSERT_THROW(PatternRule(std::string(1025, 'a')), std::invalid_argument);
}

// --- MinimumRule -------------------------------------------------------------

TEST_F(ValidationRulesTest, MinimumRuleValidation) {
    MinimumRule rule_incl(10.0);
    MinimumRule rule_excl(10.0, true);

    result.clear();
    EXPECT_TRUE(rule_incl.validate(qb::json(10.0), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule_incl.validate(qb::json(10.1), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule_incl.validate(qb::json(9.9), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "minimum");

    result.clear();
    EXPECT_FALSE(rule_excl.validate(qb::json(10.0), "test", result));
    EXPECT_FALSE(result.success());
    // Exclusive bound reports the "exclusiveMinimum" rule name (rule.h MinimumRule).
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "exclusiveMinimum");
    result.clear();
    EXPECT_TRUE(rule_excl.validate(qb::json(10.0001), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule_excl.validate(qb::json(9.9), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "exclusiveMinimum");

    // Rule only applies to numbers -> a string passes through.
    result.clear();
    EXPECT_TRUE(rule_incl.validate(qb::json("test"), "test", result));
    EXPECT_TRUE(result.success());
}

// --- MaximumRule -------------------------------------------------------------

TEST_F(ValidationRulesTest, MaximumRuleValidation) {
    MaximumRule rule_incl(20.0);
    MaximumRule rule_excl(20.0, true);

    result.clear();
    EXPECT_TRUE(rule_incl.validate(qb::json(20.0), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule_incl.validate(qb::json(19.9), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule_incl.validate(qb::json(20.1), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "maximum");

    result.clear();
    EXPECT_FALSE(rule_excl.validate(qb::json(20.0), "test", result));
    EXPECT_FALSE(result.success());
    // Exclusive bound reports the "exclusiveMaximum" rule name (rule.h MaximumRule).
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "exclusiveMaximum");
    result.clear();
    EXPECT_TRUE(rule_excl.validate(qb::json(19.9999), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule_excl.validate(qb::json(20.1), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "exclusiveMaximum");
}

// --- EnumRule ----------------------------------------------------------------

TEST_F(ValidationRulesTest, EnumRuleValidation) {
    EnumRule rule(qb::json::array({"red", "green", "blue", 10}));
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("green"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(10), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json("yellow"), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "enum");
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json(20), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "enum");

    ASSERT_THROW(EnumRule(qb::json(qb::json::value_t::object)), std::invalid_argument);
}

// --- UniqueItemsRule ---------------------------------------------------------

TEST_F(ValidationRulesTest, UniqueItemsRuleValidation) {
    UniqueItemsRule rule;
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2, 3, "a"}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1, 2, 3, 2}), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "uniqueItems");
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array(), "test", result));
    EXPECT_TRUE(result.success());
    // An object is not an array -> rule does not apply.
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json({{"a", 1}, {"b", 2}}), "test", result));
    EXPECT_TRUE(result.success());
    // Duplicate nested objects are detected by deep equality.
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({qb::json::object({{"a", 1}}), qb::json::object({{"a", 1}})}), "test", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
}

// --- MinItemsRule ------------------------------------------------------------

TEST_F(ValidationRulesTest, MinItemsRuleValidation) {
    MinItemsRule rule(2);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2, 3}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1}), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "minItems");
}

// --- MaxItemsRule ------------------------------------------------------------

TEST_F(ValidationRulesTest, MaxItemsRuleValidation) {
    MaxItemsRule rule(2);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1, 2, 3}), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "maxItems");
}

// --- CustomRule --------------------------------------------------------------

TEST_F(ValidationRulesTest, CustomRuleValidation) {
    bool custom_func_called = false;
    auto fn                 = [&](const qb::json &val, const std::string &path, Result &res) -> bool {
        custom_func_called = true;
        if (val.is_string() && val.get<std::string>() == "custom_valid") {
            return true;
        }
        res.add_error(path, "custom_lambda_error_name", "Value did not meet custom criteria.", std::make_optional(val));
        return false;
    };
    CustomRule rule(fn, "myCustomRuleNameRegisteredInValidator");

    custom_func_called = false;
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("custom_valid"), "field", result));
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(custom_func_called);

    custom_func_called = false;
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json("invalid"), "field", result));
    EXPECT_FALSE(result.success());
    EXPECT_TRUE(custom_func_called);
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "custom_lambda_error_name");
    EXPECT_EQ(rule.rule_name(), "myCustomRuleNameRegisteredInValidator");
}

// --- PatternRule ReDoS input-size guard --------------------------------------

// The PatternRule caps the input length at MAX_REGEX_INPUT_LENGTH (256 KiB) before
// running std::regex_match, since std::regex offers no execution timeout. Inputs at
// or below the cap match normally; an input above the cap is rejected deterministically
// with a `pattern` error (it never reaches the regex engine), which is what protects
// against ReDoS. This pins the exact 262144-byte boundary in both directions.
TEST_F(ValidationRulesTest, PatternRuleReDoSInputSizeGuard) {
    constexpr std::size_t kMaxInput = 256 * 1024; // 262144, mirrors rule.cpp

    PatternRule pattern_rule("^.*$"); // matches everything within the size budget

    // Normal input matches.
    result.clear();
    EXPECT_TRUE(pattern_rule.validate(qb::json("normal text"), "field", result));
    EXPECT_TRUE(result.success());

    // Exactly at the cap still goes through the regex and matches.
    result.clear();
    EXPECT_TRUE(pattern_rule.validate(qb::json(std::string(kMaxInput, 'a')), "field", result));
    EXPECT_TRUE(result.success());

    // One byte over the cap is rejected by the guard, before the regex runs.
    result.clear();
    EXPECT_FALSE(pattern_rule.validate(qb::json(std::string(kMaxInput + 1, 'b')), "field", result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "field");
    EXPECT_EQ(result.errors()[0].rule_violated, "pattern");
    EXPECT_NE(result.errors()[0].message.find("ReDoS"), std::string::npos);

    // The original 300k-char adversarial input (> cap) is rejected the same way.
    result.clear();
    EXPECT_FALSE(pattern_rule.validate(qb::json(std::string(300000, 'b')), "field", result));
    ASSERT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].rule_violated, "pattern");
}

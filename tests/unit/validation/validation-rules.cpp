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
#include <cmath>
#include <cstdint>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <qb/json.h>

#include <qbm/http/validation.h>

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

TEST_F(ValidationRulesTest, StringLengthCountsUnicodeCodePoints) {
    const qb::json one_code_point  = std::string("\xC3\xA9");  // U+00E9, two UTF-8 bytes
    const qb::json two_code_points = std::string("e\xCC\x81"); // e + U+0301, three UTF-8 bytes

    MaxLengthRule max_one(1);
    result.clear();
    EXPECT_TRUE(max_one.validate(one_code_point, "name", result));
    EXPECT_TRUE(result.success());

    MinLengthRule min_two(2);
    result.clear();
    EXPECT_FALSE(min_two.validate(one_code_point, "name", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(min_two.validate(two_code_points, "name", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(max_one.validate(two_code_points, "name", result));
    EXPECT_FALSE(result.success());
}

TEST_F(ValidationRulesTest, StringLengthRejectsMalformedUtf8WithoutCopyingItIntoError) {
    MaxLengthRule max_one(1);
    for (const std::string &malformed :
         {std::string("\x80"), std::string("\xC0\xAF"), std::string("\xED\xA0\x80"), std::string("\xF4\x90\x80\x80"),
          std::string("\xF0\x9F\x98"), std::string("\xC3\xA9\xC0\xAF\xC3\xA9\xC3\xA9")}) {
        result.clear();
        EXPECT_FALSE(max_one.validate(qb::json(malformed), "name", result));
        ASSERT_EQ(result.errors().size(), 1u);
        EXPECT_EQ(result.errors()[0].rule_violated, "maxLength");
        EXPECT_FALSE(result.errors()[0].offending_value.has_value());
    }

    result.clear();
    EXPECT_TRUE(max_one.validate(qb::json(std::string("\xF0\x9F\x98\x80")), "name", result)); // U+1F600
    EXPECT_TRUE(result.success());
}

TEST_F(ValidationRulesTest, UnicodeFastPathsPreserveBoundariesAndRejectBrokenPairs) {
    MaxLengthRule max_four(4);
    std::string   four_pairs;
    for (int i = 0; i < 4; ++i)
        four_pairs += "\xC3\xA9";
    result.clear();
    EXPECT_TRUE(max_four.validate(qb::json(four_pairs), "name", result));
    EXPECT_TRUE(result.success());

    for (std::size_t pair = 1; pair < 4; ++pair) {
        for (char invalid_lead : {'\xC0', '\xC1'}) {
            SCOPED_TRACE(pair);
            std::string malformed = four_pairs;
            malformed[pair * 2]   = invalid_lead;
            result.clear();
            EXPECT_FALSE(max_four.validate(qb::json(malformed), "name", result));
        }
        std::string malformed_tail   = four_pairs;
        malformed_tail[pair * 2 + 1] = 'x';
        result.clear();
        EXPECT_FALSE(max_four.validate(qb::json(malformed_tail), "name", result));
    }

    result.clear();
    EXPECT_FALSE(max_four.validate(qb::json(four_pairs + "\xF0\x9F"), "name", result));
    result.clear();
    EXPECT_FALSE(max_four.validate(qb::json(four_pairs + four_pairs + "\xC0\xAF"), "name", result));

    const std::string sixteen_pairs = four_pairs + four_pairs + four_pairs + four_pairs;
    MaxLengthRule     max_sixteen(16);
    result.clear();
    EXPECT_TRUE(max_sixteen.validate(qb::json(sixteen_pairs), "name", result));
    for (std::size_t pair : {4u, 7u, 8u, 15u}) {
        SCOPED_TRACE(pair);
        std::string malformed = sixteen_pairs;
        malformed[pair * 2]   = '\xC1';
        result.clear();
        EXPECT_FALSE(max_sixteen.validate(qb::json(malformed), "name", result));
    }

    for (std::size_t ascii_size : {7u, 8u, 9u, 31u, 32u, 33u}) {
        SCOPED_TRACE(ascii_size);
        MaxLengthRule max_length(ascii_size + 1);
        result.clear();
        EXPECT_TRUE(max_length.validate(qb::json(std::string(ascii_size, 'a') + "\xC3\xA9"), "name", result));
        EXPECT_TRUE(result.success());
    }
}

TEST_F(ValidationRulesTest, UnicodeFastPathsAgreeWithJsonUtf8SerializerAtEveryByte) {
    MaxLengthRule max_length(32);
    for (const std::size_t pairs : {4u, 16u}) {
        std::string base;
        for (std::size_t i = 0; i < pairs; ++i)
            base += "\xC3\xA9";
        for (std::size_t position = 0; position < base.size(); ++position) {
            for (unsigned byte = 0; byte <= 255; ++byte) {
                SCOPED_TRACE(pairs);
                SCOPED_TRACE(position);
                SCOPED_TRACE(byte);
                std::string mutated = base;
                mutated[position]   = static_cast<char>(byte);
                const qb::json value(mutated);
                bool           valid_utf8 = true;
                try {
                    (void) value.dump();
                } catch (const qb::json::type_error &) {
                    valid_utf8 = false;
                }
                result.clear();
                EXPECT_EQ(max_length.validate(value, "name", result), valid_utf8);
                EXPECT_EQ(result.success(), valid_utf8);
            }
        }
    }
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

    // Rule only applies to numbers -> a non-number passes through.
    result.clear();
    EXPECT_TRUE(rule_incl.validate(qb::json("test"), "test", result));
    EXPECT_TRUE(result.success());
}

TEST_F(ValidationRulesTest, NumericBoundsKeepIntegerPrecision) {
    constexpr std::uint64_t kTwoTo53 = std::uint64_t{1} << 53;

    MinimumRule exclusive_min(static_cast<double>(kTwoTo53), true);
    result.clear();
    EXPECT_TRUE(exclusive_min.validate(qb::json(kTwoTo53 + 1), "amount", result));
    EXPECT_TRUE(result.success());

    MinimumRule negative_exclusive_min(-static_cast<double>(kTwoTo53), true);
    result.clear();
    EXPECT_TRUE(negative_exclusive_min.validate(qb::json(-static_cast<std::int64_t>(kTwoTo53) + 1), "amount", result));
    EXPECT_TRUE(result.success());
}

TEST_F(ValidationRulesTest, NumericBoundsHandleMixedKindsAnd64BitEdges) {
    constexpr auto kMaxUnsigned = (std::numeric_limits<std::uint64_t>::max)();
    constexpr auto kMinSigned   = (std::numeric_limits<std::int64_t>::min)();

    MinimumRule unsigned_min(kMaxUnsigned);
    result.clear();
    EXPECT_TRUE(unsigned_min.validate(qb::json(kMaxUnsigned), "number", result));
    result.clear();
    EXPECT_FALSE(unsigned_min.validate(qb::json(kMaxUnsigned - 1), "number", result));
    result.clear();
    EXPECT_FALSE(unsigned_min.validate(qb::json(-1), "number", result));

    MaximumRule unsigned_max(kMaxUnsigned);
    result.clear();
    EXPECT_FALSE(unsigned_max.validate(qb::json(0x1p64), "number", result));
    result.clear();
    EXPECT_TRUE(unsigned_max.validate(qb::json(kMaxUnsigned), "number", result));

    MinimumRule signed_min(kMinSigned);
    result.clear();
    EXPECT_TRUE(signed_min.validate(qb::json(-0x1p63), "number", result));
    result.clear();
    EXPECT_FALSE(signed_min.validate(qb::json(std::nextafter(-0x1p63, -(std::numeric_limits<double>::infinity)())), "number", result));

    MinimumRule positive_fraction(0.5, true);
    result.clear();
    EXPECT_FALSE(positive_fraction.validate(qb::json(0), "number", result));
    result.clear();
    EXPECT_TRUE(positive_fraction.validate(qb::json(1), "number", result));
    MaximumRule negative_fraction(-0.5, true);
    result.clear();
    EXPECT_FALSE(negative_fraction.validate(qb::json(0), "number", result));
    result.clear();
    EXPECT_TRUE(negative_fraction.validate(qb::json(-1), "number", result));

    MinimumRule signed_boundary(qb::json(-1));
    result.clear();
    EXPECT_TRUE(signed_boundary.validate(qb::json(std::uint64_t{0}), "number", result));
    MaximumRule unsigned_boundary(qb::json(std::uint64_t{0}));
    result.clear();
    EXPECT_TRUE(unsigned_boundary.validate(qb::json(-1), "number", result));

    const auto nan = (std::numeric_limits<double>::quiet_NaN)();
    result.clear();
    EXPECT_FALSE(signed_boundary.validate(qb::json(nan), "number", result));
    EXPECT_FALSE(result.success());

    EXPECT_THROW(MinimumRule(qb::json("5")), std::invalid_argument);
    EXPECT_THROW(MaximumRule(qb::json("5")), std::invalid_argument);
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

TEST_F(ValidationRulesTest, EnumRuleUsesExactJsonNumberEquality) {
    constexpr std::uint64_t kTwoTo53 = std::uint64_t{1} << 53;
    EnumRule                rule(qb::json::array({static_cast<double>(kTwoTo53)}));

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(kTwoTo53), "choice", result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_FALSE(rule.validate(qb::json(kTwoTo53 + 1), "choice", result));
    EXPECT_FALSE(result.success());
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

TEST_F(ValidationRulesTest, UniqueItemsUsesJsonNumericEquality) {
    UniqueItemsRule rule;

    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({1, 1.0}), "items", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({qb::json::object({{"n", 1}}), qb::json::object({{"n", 1.0}})}), "items", result));
    EXPECT_FALSE(result.success());

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, true}), "items", result));
    EXPECT_TRUE(result.success());
}

TEST_F(ValidationRulesTest, UniqueItemsKeepsDistinctLargeNumbersAndIgnoresObjectInsertionOrder) {
    constexpr std::uint64_t kTwoTo53     = std::uint64_t{1} << 53;
    constexpr auto          kMaxUnsigned = (std::numeric_limits<std::uint64_t>::max)();
    constexpr auto          kMinSigned   = (std::numeric_limits<std::int64_t>::min)();
    UniqueItemsRule         rule;

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({kTwoTo53 + 1, static_cast<double>(kTwoTo53)}), "items", result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({kMaxUnsigned, -1, 0x1p64}), "items", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({kMinSigned, -0x1p63}), "items", result));
    EXPECT_FALSE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({0, -0.0}), "items", result));
    EXPECT_FALSE(result.success());
    result.clear();
    const auto nan = (std::numeric_limits<double>::quiet_NaN)();
    EXPECT_FALSE(rule.validate(qb::json::array({nan, nan}), "items", result));
    EXPECT_FALSE(result.success());

    qb::json first  = qb::json::object();
    first["a"]      = 1;
    first["b"]      = qb::json::array({2.0});
    qb::json second = qb::json::object();
    second["b"]     = qb::json::array({2});
    second["a"]     = 1.0;
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json::array({first, second}), "items", result));
    EXPECT_FALSE(result.success());
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

    // Rule only applies to arrays -> a non-array passes through.
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("not an array"), "test", result));
    EXPECT_TRUE(result.success());
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

    // Rule only applies to arrays -> a non-array passes through.
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(123), "test", result));
    EXPECT_TRUE(result.success());
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

// The PatternRule caps the input length at MAX_REGEX_INPUT_LENGTH (2 KiB) before running
// std::regex_match. The cap protects against BOTH catastrophic backtracking and, just as
// importantly, stack exhaustion: libstdc++'s std::regex executor recurses once per matched
// character, so even `^.*$` over a few KiB overflows the stack and crashes on Linux (macOS
// libc++ does not). Inputs at or below the cap match normally and — critically — must NOT
// crash; an input above the cap is rejected deterministically with a `pattern` error before
// the regex ever runs. This pins the 2048-byte boundary in both directions.
TEST_F(ValidationRulesTest, PatternRuleReDoSInputSizeGuard) {
    constexpr std::size_t kMaxInput = 2 * 1024; // 2048, mirrors rule.cpp

    PatternRule pattern_rule("^.*$"); // matches everything within the size budget

    // Normal input matches.
    result.clear();
    EXPECT_TRUE(pattern_rule.validate(qb::json("normal text"), "field", result));
    EXPECT_TRUE(result.success());

    // Exactly at the cap still goes through the regex and matches — without overflowing
    // the stack (the whole point of keeping the cap below libstdc++'s recursion limit).
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

// --- RequiredRule ------------------------------------------------------------

// RequiredRule is a presence marker: presence is enforced by the validator
// (SchemaValidator/ParameterValidator) before rules run, so the rule's own
// validate() is a no-op that passes whatever value reaches it.
TEST_F(ValidationRulesTest, RequiredRuleValidateAlwaysPasses) {
    RequiredRule rule;
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("present"), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json(nullptr), "test", result));
    EXPECT_TRUE(result.success());
    EXPECT_EQ(rule.rule_name(), "required");
}

// --- MinPropertiesRule -------------------------------------------------------

TEST_F(ValidationRulesTest, MinPropertiesRuleValidation) {
    MinPropertiesRule rule(2);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json({{"a", 1}, {"b", 2}}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json({{"a", 1}}), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "minProperties");
    // Rule only applies to objects -> a non-object passes through.
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2}), "test", result));
    EXPECT_TRUE(result.success());
}

// --- MaxPropertiesRule -------------------------------------------------------

TEST_F(ValidationRulesTest, MaxPropertiesRuleValidation) {
    MaxPropertiesRule rule(2);
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json({{"a", 1}, {"b", 2}}), "test", result));
    EXPECT_TRUE(result.success());
    result.clear();
    EXPECT_FALSE(rule.validate(qb::json({{"a", 1}, {"b", 2}, {"c", 3}}), "test", result));
    EXPECT_FALSE(result.success());
    ASSERT_FALSE(result.errors().empty());
    EXPECT_EQ(result.errors()[0].rule_violated, "maxProperties");
    // Rule only applies to objects -> a non-object passes through.
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("not an object"), "test", result));
    EXPECT_TRUE(result.success());
}

// --- PropertyNamesRule -------------------------------------------------------

// Validates every property NAME of an object against a sub-schema. Names that
// violate the schema produce errors; a non-object input is outside the rule's
// scope and passes through.
TEST_F(ValidationRulesTest, PropertyNamesRuleValidation) {
    // Each key must be a string of at most 4 characters.
    PropertyNamesRule rule(qb::json({{"type", "string"}, {"maxLength", 4}}));

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json({{"abcd", 1}, {"xy", 2}}), "test", result));
    EXPECT_TRUE(result.success());

    result.clear();
    EXPECT_FALSE(rule.validate(qb::json({{"toolong", 1}}), "test", result));
    EXPECT_FALSE(result.success());
    EXPECT_FALSE(result.errors().empty());

    // Rule only applies to objects -> a non-object passes through.
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2}), "test", result));
    EXPECT_TRUE(result.success());
}

// --- ItemsRule ---------------------------------------------------------------

// ItemsRule is a data carrier; the actual "items"/"additionalItems" logic lives
// in SchemaValidator, so the rule's own validate() is a placeholder that always
// passes. Exercise the constructor and that placeholder directly.
TEST_F(ValidationRulesTest, ItemsRulePlaceholderValidatePasses) {
    auto      item_schema = std::make_shared<SchemaValidator>(qb::json({{"type", "integer"}}));
    ItemsRule rule(ItemsRuleLogic{item_schema});

    result.clear();
    EXPECT_TRUE(rule.validate(qb::json::array({1, 2, 3}), "test", result));
    EXPECT_TRUE(result.success());
    // Even a type the real keyword logic would reject passes the placeholder.
    result.clear();
    EXPECT_TRUE(rule.validate(qb::json("not an array"), "test", result));
    EXPECT_TRUE(result.success());
    EXPECT_EQ(rule.rule_name(), "items");
}

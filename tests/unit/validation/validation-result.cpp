/**
 * @file qbm/http/tests/unit/validation/validation-result.cpp
 * @brief Unit tests for qb::http::validation::{Error, Result} accumulation and
 *        error-value policy (Full / Preview / None) shaping.
 *
 * Pure-logic coverage of the validation result container: error accumulation,
 * merge, clear, child-result inheritance, and the F48 error-value-policy that
 * controls whether (and how much of) an offending value is retained on each
 * recorded error. No socket, no event loop.
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

#include <qbm/http/validation.h>

using namespace qb::http::validation;

class ValidationResultTest : public ::testing::Test {
protected:
    Result result;

    void
    SetUp() override {
        result.clear();
    }
};

// --- Error & Result accumulation ---------------------------------------------

TEST_F(ValidationResultTest, ValidationResultBehavesCorrectly) {
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(result.errors().empty());

    result.add_error("field1", "required", "Field is missing");
    EXPECT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 1);
    EXPECT_EQ(result.errors()[0].field_path, "field1");
    EXPECT_EQ(result.errors()[0].rule_violated, "required");
    EXPECT_EQ(result.errors()[0].message, "Field is missing");

    Result other_result;
    other_result.add_error("field2", "type", "Must be a string", std::make_optional(qb::json(123)));
    result.merge(other_result);
    EXPECT_FALSE(result.success());
    ASSERT_EQ(result.errors().size(), 2);
    EXPECT_EQ(result.errors()[1].field_path, "field2");
    ASSERT_TRUE(result.errors()[1].offending_value.has_value());
    EXPECT_EQ(result.errors()[1].offending_value.value(), qb::json(123));

    result.clear();
    EXPECT_TRUE(result.success());
    EXPECT_TRUE(result.errors().empty());
}

// Every form a rule passes its offending value in compiles, under nlohmann 3.11 and 3.12 alike, and
// stores that value (Huly QB-1008). A `const qb::json &` -- what a CustomRule receives -- did not
// compile under 3.12: json's conversion operator to std::optional<json> competes with the optional's
// constructor. The qb::json overload takes json lvalues and rvalues only; std::nullopt, an omitted
// value, a std::optional and a value of another type (a string, a number, a literal: what qbm-http's
// own validators pass) keep the optional overload, and its behaviour -- a plain `const qb::json &`
// overload made those ambiguous.
TEST_F(ValidationResultTest, AddErrorTakesEveryOffendingValueForm) {
    const qb::json          received      = qb::json{{"k", 7}};
    qb::json                mutable_value = 8;
    std::optional<qb::json> maybe         = qb::json("o");
    const std::string       text          = "s";
    result.add_error("a", "rule", "const lvalue", received);
    result.add_error("b", "rule", "lvalue", mutable_value);
    result.add_error("c", "rule", "prvalue", qb::json(42));
    result.add_error("d", "rule", "nullopt", std::nullopt);
    result.add_error("e", "rule", "optional prvalue", std::optional<qb::json>(received));
    result.add_error("f", "rule", "optional lvalue", maybe);
    result.add_error("g", "rule", "omitted");
    result.add_error("h", "rule", "string", text);
    result.add_error("i", "rule", "number", 42);
    result.add_error("j", "rule", "literal", "lit");

    const auto &errors = result.errors();
    ASSERT_EQ(errors.size(), 10u);
    ASSERT_TRUE(errors[7].offending_value.has_value());
    EXPECT_EQ(*errors[7].offending_value, qb::json("s"));
    ASSERT_TRUE(errors[8].offending_value.has_value());
    EXPECT_EQ(*errors[8].offending_value, qb::json(42));
    ASSERT_TRUE(errors[9].offending_value.has_value());
    EXPECT_EQ(*errors[9].offending_value, qb::json("lit"));
    ASSERT_TRUE(errors[0].offending_value.has_value());
    EXPECT_EQ(*errors[0].offending_value, received);
    EXPECT_EQ(errors[0].field_path, "a");
    EXPECT_EQ(errors[0].message, "const lvalue");
    ASSERT_TRUE(errors[1].offending_value.has_value());
    EXPECT_EQ(*errors[1].offending_value, qb::json(8));
    ASSERT_TRUE(errors[2].offending_value.has_value());
    EXPECT_EQ(*errors[2].offending_value, qb::json(42));
    EXPECT_FALSE(errors[3].offending_value.has_value());
    ASSERT_TRUE(errors[4].offending_value.has_value());
    EXPECT_EQ(*errors[4].offending_value, received);
    ASSERT_TRUE(errors[5].offending_value.has_value());
    EXPECT_EQ(*errors[5].offending_value, qb::json("o"));
    EXPECT_FALSE(errors[6].offending_value.has_value());

    // The qb::json form is shaped by the policy as the optional form is.
    Result dropped;
    dropped.set_error_value_policy(Result::ErrorValuePolicy::None);
    dropped.add_error("a", "rule", "const lvalue", received);
    ASSERT_EQ(dropped.errors().size(), 1u);
    EXPECT_FALSE(dropped.errors().front().offending_value.has_value());
    Result previewed;
    previewed.set_error_value_policy(Result::ErrorValuePolicy::Preview, 16);
    const qb::json long_text = std::string(64, 'x');
    previewed.add_error("a", "rule", "const lvalue", long_text);
    ASSERT_EQ(previewed.errors().size(), 1u);
    ASSERT_TRUE(previewed.errors().front().offending_value.has_value());
    EXPECT_EQ(previewed.errors().front().offending_value->get<std::string>(), std::string(16, 'x'));
}

// --- F48: Error-value policy -------------------------------------------------

// Full (default) keeps the offending value verbatim.
TEST_F(ValidationResultTest, ErrorValuePolicyFullKeepsValue) {
    Result r;
    EXPECT_EQ(r.error_value_policy(), Result::ErrorValuePolicy::Full);
    qb::json big = qb::json::object();
    for (int i = 0; i < 100; ++i) {
        big["k" + std::to_string(i)] = std::string(64, 'x');
    }
    r.add_error("body", "type", "nope", big);
    ASSERT_EQ(r.errors().size(), 1);
    ASSERT_TRUE(r.errors().front().offending_value.has_value());
    EXPECT_EQ(r.errors().front().offending_value->size(), big.size());
}

// Preview: small values are passed through untouched; large values are truncated.
TEST_F(ValidationResultTest, ErrorValuePolicyPreviewTruncatesLargeValues) {
    Result r;
    r.set_error_value_policy(Result::ErrorValuePolicy::Preview, 64);

    // Small number stays untouched.
    r.add_error("a", "rule", "msg", qb::json(42));
    ASSERT_EQ(r.errors().size(), 1);
    ASSERT_TRUE(r.errors().front().offending_value.has_value());
    EXPECT_EQ(r.errors().front().offending_value.value(), qb::json(42));

    // Huge object is truncated and marked.
    qb::json big = qb::json::object();
    for (int i = 0; i < 50; ++i) {
        big["k" + std::to_string(i)] = std::string(32, 'x');
    }
    r.add_error("b", "rule", "msg", big);
    ASSERT_EQ(r.errors().size(), 2);
    ASSERT_TRUE(r.errors()[1].offending_value.has_value());
    const auto &preview = *r.errors()[1].offending_value;
    ASSERT_TRUE(preview.is_object());
    ASSERT_TRUE(preview.contains("_truncated"));
    EXPECT_TRUE(preview["_truncated"].get<bool>());
    ASSERT_TRUE(preview.contains("preview"));
    EXPECT_LE(preview["preview"].get<std::string>().size(), 64u);
    EXPECT_EQ(preview["original_kind"].get<std::string>(), std::string(big.type_name()));
}

// Preview: long strings are cut to exactly the budget.
TEST_F(ValidationResultTest, ErrorValuePolicyPreviewTruncatesLongStrings) {
    Result r;
    r.set_error_value_policy(Result::ErrorValuePolicy::Preview, 32);
    std::string huge(1024, 'a');
    r.add_error("s", "rule", "msg", qb::json(huge));
    ASSERT_EQ(r.errors().size(), 1);
    ASSERT_TRUE(r.errors().front().offending_value.has_value());
    EXPECT_EQ(r.errors().front().offending_value->get<std::string>().size(), 32u);
}

// Preview: a string already within budget is preserved byte-for-byte.
TEST_F(ValidationResultTest, ErrorValuePolicyPreviewKeepsShortStrings) {
    Result r;
    r.set_error_value_policy(Result::ErrorValuePolicy::Preview, 32);
    r.add_error("s", "rule", "msg", qb::json(std::string("short")));
    ASSERT_EQ(r.errors().size(), 1);
    ASSERT_TRUE(r.errors().front().offending_value.has_value());
    ASSERT_TRUE(r.errors().front().offending_value->is_string());
    EXPECT_EQ(r.errors().front().offending_value->get<std::string>(), "short");
}

TEST_F(ValidationResultTest, PreviewStopsAtUtf8BoundaryWithinByteBudget) {
    const std::string emoji{"\xF0\x9F\x98\x80", 4};
    const std::string two_bytes{"\xC3\xA9", 2};
    const std::string three_bytes{"\xE2\x82\xAC", 3};

    for (const auto &character : {emoji, two_bytes, three_bytes}) {
        for (std::size_t remaining = 1; remaining < character.size(); ++remaining) {
            const std::string prefix(16 - remaining, 'a');
            Result            r;
            r.set_error_value_policy(Result::ErrorValuePolicy::Preview, 16);
            r.add_error("field", "rule", "message", qb::json(prefix + character + "tail"));
            ASSERT_EQ(r.errors().size(), 1u);
            ASSERT_TRUE(r.errors()[0].offending_value.has_value());
            EXPECT_EQ(r.errors()[0].offending_value->get<std::string>(), prefix);
            EXPECT_NO_THROW((void) r.errors()[0].offending_value->dump());
        }
    }

    Result complete;
    complete.set_error_value_policy(Result::ErrorValuePolicy::Preview, 16);
    complete.add_error("field", "rule", "message", qb::json(std::string(12, 'a') + emoji + "tail"));
    EXPECT_EQ(*complete.errors()[0].offending_value, qb::json(std::string(12, 'a') + emoji));
}

TEST_F(ValidationResultTest, CompoundPreviewKeepsValidUtf8) {
    Result r;
    r.set_error_value_policy(Result::ErrorValuePolicy::Preview, 16);
    const std::string emoji{"\xF0\x9F\x98\x80", 4};
    r.add_error("body", "rule", "message", qb::json{{"a", std::string(9, 'a') + emoji + "tail"}});
    ASSERT_EQ(r.errors().size(), 1u);
    ASSERT_TRUE(r.errors()[0].offending_value.has_value());
    const qb::json &preview = *r.errors()[0].offending_value;
    ASSERT_TRUE(preview.is_object());
    EXPECT_EQ(preview["_truncated"], true);
    EXPECT_EQ(preview["preview"].get<std::string>(), "{\"a\":\"aaaaaaaaa");
    EXPECT_EQ(preview["original_kind"], "object");
    EXPECT_NO_THROW((void) preview.dump());
}

// None: offending_value is dropped entirely.
TEST_F(ValidationResultTest, ErrorValuePolicyNoneDropsValue) {
    Result r;
    r.set_error_value_policy(Result::ErrorValuePolicy::None);
    r.add_error("field", "rule", "msg", qb::json("whatever"));
    ASSERT_EQ(r.errors().size(), 1);
    EXPECT_FALSE(r.errors().front().offending_value.has_value());
}

// make_child inherits the parent's policy; merge folds shaped errors back unchanged.
TEST_F(ValidationResultTest, ErrorValuePolicyMergePreservesErrors) {
    Result parent;
    parent.set_error_value_policy(Result::ErrorValuePolicy::None);

    Result child = parent.make_child();
    EXPECT_EQ(child.error_value_policy(), Result::ErrorValuePolicy::None);
    child.add_error("x", "rule", "msg", qb::json("omitted"));
    parent.merge(child);

    ASSERT_EQ(parent.errors().size(), 1);
    EXPECT_FALSE(parent.errors().front().offending_value.has_value());
}

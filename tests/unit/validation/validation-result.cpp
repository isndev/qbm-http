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
#include <string>

#include <qb/json.h>

#include "../validation.h"

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

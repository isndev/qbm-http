/**
 * @file qbm/http/tests/unit/validation/validation-error-type.cpp
 * @brief Unit tests for the validation `Error` value type and the
 *        `Result::add_error(Error)` pre-shaped overload (validation/error.h).
 *
 * validation-result.cpp pins the policy-aware string overload
 * `add_error(path, rule, msg, value)` and the Full/Preview/None shaping. It never
 * constructs an `Error` directly, and never calls the SECOND `add_error` overload
 * that takes a fully-built `Error` and appends it *verbatim* (the documented
 * opt-out from the active capture policy). Both are uncovered:
 *
 *   - `Error(path, rule, msg, value = nullopt)` — the 4-field constructor:
 *     field/rule/message moved in, optional offending value defaulting to nullopt.
 *   - `Result::add_error(Error)` — pushes the supplied record untouched, even
 *     when the active policy is `None` (which WOULD have dropped the value had it
 *     gone through the string overload). This is the trust-the-caller path used
 *     for synthetic errors that must keep their full payload.
 *
 * Pure logic: no socket, no event loop.
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

using qb::http::validation::Error;
using qb::http::validation::Result;

namespace {

// ---------------------------------------------------------------------------
// Error: the 4-field constructor.
// ---------------------------------------------------------------------------

TEST(ValidationErrorType, ConstructsWithoutOffendingValue) {
    Error e("user.age", "minimum", "must be >= 18");
    EXPECT_EQ(e.field_path, "user.age");
    EXPECT_EQ(e.rule_violated, "minimum");
    EXPECT_EQ(e.message, "must be >= 18");
    EXPECT_FALSE(e.offending_value.has_value()); // defaults to nullopt
}

TEST(ValidationErrorType, ConstructsWithOffendingValue) {
    Error e("body", "type", "expected integer", std::make_optional(qb::json("not-an-int")));
    EXPECT_EQ(e.field_path, "body");
    EXPECT_EQ(e.rule_violated, "type");
    EXPECT_EQ(e.message, "expected integer");
    ASSERT_TRUE(e.offending_value.has_value());
    ASSERT_TRUE(e.offending_value->is_string());
    EXPECT_EQ(e.offending_value->get<std::string>(), "not-an-int");
}

// ---------------------------------------------------------------------------
// Result::add_error(Error): verbatim append, policy NOT applied.
// ---------------------------------------------------------------------------

TEST(ValidationErrorType, AddPreConstructedErrorAppendsVerbatim) {
    Result r;
    EXPECT_TRUE(r.success());

    Error e("f", "rule", "msg", std::make_optional(qb::json(123)));
    r.add_error(std::move(e));

    EXPECT_FALSE(r.success());
    ASSERT_EQ(r.errors().size(), 1u);
    EXPECT_EQ(r.errors().front().field_path, "f");
    EXPECT_EQ(r.errors().front().rule_violated, "rule");
    EXPECT_EQ(r.errors().front().message, "msg");
    ASSERT_TRUE(r.errors().front().offending_value.has_value());
    EXPECT_EQ(*r.errors().front().offending_value, qb::json(123));
}

TEST(ValidationErrorType, AddPreConstructedErrorIgnoresActivePolicy) {
    // The string overload under `None` would DROP the value; the Error overload
    // is the documented opt-out and keeps the caller-supplied payload intact.
    Result r;
    r.set_error_value_policy(Result::ErrorValuePolicy::None);

    qb::json big = qb::json::object();
    for (int i = 0; i < 20; ++i) {
        big["k" + std::to_string(i)] = std::string(64, 'x');
    }
    r.add_error(Error("root", "schema", "synthetic", std::make_optional(big)));

    ASSERT_EQ(r.errors().size(), 1u);
    ASSERT_TRUE(r.errors().front().offending_value.has_value());
    EXPECT_EQ(r.errors().front().offending_value->size(), big.size()); // untouched

    // Sanity contrast: the policy-aware overload on the SAME result drops it.
    r.add_error("other", "schema", "via-policy", std::make_optional(big));
    ASSERT_EQ(r.errors().size(), 2u);
    EXPECT_FALSE(r.errors().back().offending_value.has_value());
}

TEST(ValidationErrorType, AddPreConstructedErrorsAccumulateInOrder) {
    Result r;
    r.add_error(Error("a", "r1", "m1"));
    r.add_error(Error("b", "r2", "m2"));

    ASSERT_EQ(r.errors().size(), 2u);
    EXPECT_EQ(r.errors()[0].field_path, "a");
    EXPECT_EQ(r.errors()[1].field_path, "b");

    r.clear();
    EXPECT_TRUE(r.success());
    EXPECT_TRUE(r.errors().empty());
}

} // namespace

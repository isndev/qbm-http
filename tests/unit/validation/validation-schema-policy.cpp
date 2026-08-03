/**
 * @file qbm/http/tests/unit/validation/validation-schema-policy.cpp
 * @brief Unit tests for the SchemaValidator offending-value policy SURFACE
 *        (schema_validator.h) that validation-schema.cpp reaches only indirectly.
 *
 * validation-schema.cpp drives the JSON-Schema engine through `validate()` and so
 * exercises `set_error_value_policy()` and the policy's *effect* on produced
 * errors. It never touches three public entry points declared on the validator
 * itself, leaving them uncovered:
 *
 *   - `error_value_policy()`            — the inline getter (default + after set).
 *   - `offending_value_preview_bytes()` — the inline getter, incl. clamp readback.
 *   - `make_offending_value()`          — the standalone helper external rules use
 *                                         to shape a value under the active policy,
 *                                         independent of any `validate()` call.
 *
 * This file pins those directly: the getters' default/observed values, the
 * [16, 64K] clamp visible through the bytes getter, and `make_offending_value`'s
 * Full / Preview / None behaviour (pass-through, truncate-and-mark, drop).
 *
 * Pure logic: no socket, no event loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <cstddef>
#include <gtest/gtest.h>
#include <string>

#include <qb/json.h>

#include <qbm/http/validation.h>

using qb::http::validation::SchemaValidator;

namespace {

// A trivial-but-valid schema; the policy surface is orthogonal to schema content.
qb::json
trivial_schema() {
    return qb::json{{"type", "object"}};
}

// ---------------------------------------------------------------------------
// Inline getters: defaults + observed-after-set.
// ---------------------------------------------------------------------------

TEST(SchemaValidatorPolicy, DefaultsAreFullWith256Preview) {
    SchemaValidator v(trivial_schema());
    EXPECT_EQ(v.error_value_policy(), SchemaValidator::ErrorValuePolicy::Full);
    EXPECT_EQ(v.offending_value_preview_bytes(), static_cast<std::size_t>(256));
}

TEST(SchemaValidatorPolicy, GettersReflectConfiguredPolicy) {
    SchemaValidator v(trivial_schema());

    // set_error_value_policy returns *this for chaining; the getters observe it.
    SchemaValidator &ref = v.set_error_value_policy(SchemaValidator::ErrorValuePolicy::Preview, 128);
    EXPECT_EQ(&ref, &v);
    EXPECT_EQ(v.error_value_policy(), SchemaValidator::ErrorValuePolicy::Preview);
    EXPECT_EQ(v.offending_value_preview_bytes(), static_cast<std::size_t>(128));

    v.set_error_value_policy(SchemaValidator::ErrorValuePolicy::None);
    EXPECT_EQ(v.error_value_policy(), SchemaValidator::ErrorValuePolicy::None);
}

TEST(SchemaValidatorPolicy, PreviewBytesClampVisibleThroughGetter) {
    SchemaValidator v(trivial_schema());

    // Below the 16-byte floor → clamped UP to 16.
    v.set_error_value_policy(SchemaValidator::ErrorValuePolicy::Preview, 1);
    EXPECT_EQ(v.offending_value_preview_bytes(), static_cast<std::size_t>(16));

    // Above the 64 KiB ceiling → clamped DOWN to 65536.
    v.set_error_value_policy(SchemaValidator::ErrorValuePolicy::Preview, 1024u * 1024u);
    EXPECT_EQ(v.offending_value_preview_bytes(), static_cast<std::size_t>(64 * 1024));

    // In range → untouched.
    v.set_error_value_policy(SchemaValidator::ErrorValuePolicy::Preview, 512);
    EXPECT_EQ(v.offending_value_preview_bytes(), static_cast<std::size_t>(512));
}

// ---------------------------------------------------------------------------
// make_offending_value(): the standalone policy shaper.
// ---------------------------------------------------------------------------

TEST(SchemaValidatorPolicy, MakeOffendingValueFullReturnsVerbatim) {
    SchemaValidator v(trivial_schema()); // default policy = Full
    qb::json        big = qb::json::object();
    for (int i = 0; i < 50; ++i) {
        big["k" + std::to_string(i)] = std::string(32, 'x');
    }

    auto shaped = v.make_offending_value(big);
    ASSERT_TRUE(shaped.has_value());
    EXPECT_EQ(*shaped, big); // deep-copied verbatim
}

TEST(SchemaValidatorPolicy, MakeOffendingValueNoneDropsTheValue) {
    SchemaValidator v(trivial_schema());
    v.set_error_value_policy(SchemaValidator::ErrorValuePolicy::None);

    auto shaped = v.make_offending_value(qb::json("anything"));
    EXPECT_FALSE(shaped.has_value());
}

TEST(SchemaValidatorPolicy, MakeOffendingValuePreviewKeepsCheapKinds) {
    SchemaValidator v(trivial_schema());
    v.set_error_value_policy(SchemaValidator::ErrorValuePolicy::Preview, 16);

    // null / bool / number pass through untouched regardless of preview budget.
    EXPECT_EQ(*v.make_offending_value(qb::json(nullptr)), qb::json(nullptr));
    EXPECT_EQ(*v.make_offending_value(qb::json(true)), qb::json(true));
    EXPECT_EQ(*v.make_offending_value(qb::json(42)), qb::json(42));

    // A short string within budget survives byte-for-byte.
    auto short_s = v.make_offending_value(qb::json(std::string("short")));
    ASSERT_TRUE(short_s.has_value());
    ASSERT_TRUE(short_s->is_string());
    EXPECT_EQ(short_s->get<std::string>(), "short");
}

TEST(SchemaValidatorPolicy, MakeOffendingValuePreviewTruncatesLongString) {
    SchemaValidator v(trivial_schema());
    v.set_error_value_policy(SchemaValidator::ErrorValuePolicy::Preview, 32);

    auto shaped = v.make_offending_value(qb::json(std::string(1024, 'a')));
    ASSERT_TRUE(shaped.has_value());
    ASSERT_TRUE(shaped->is_string());
    EXPECT_EQ(shaped->get<std::string>().size(), static_cast<std::size_t>(32));
}

TEST(SchemaValidatorPolicy, MakeOffendingValuePreviewTruncatesAndMarksCompound) {
    SchemaValidator v(trivial_schema());
    v.set_error_value_policy(SchemaValidator::ErrorValuePolicy::Preview, 32);

    qb::json big = qb::json::object();
    for (int i = 0; i < 50; ++i) {
        big["k" + std::to_string(i)] = std::string(32, 'x');
    }

    auto shaped = v.make_offending_value(big);
    ASSERT_TRUE(shaped.has_value());
    ASSERT_TRUE(shaped->is_object());
    ASSERT_TRUE(shaped->contains("_truncated"));
    EXPECT_TRUE((*shaped)["_truncated"].get<bool>());
    ASSERT_TRUE(shaped->contains("preview"));
    EXPECT_LE((*shaped)["preview"].get<std::string>().size(), static_cast<std::size_t>(32));
    EXPECT_EQ((*shaped)["original_kind"].get<std::string>(), std::string(big.type_name()));
}

} // namespace

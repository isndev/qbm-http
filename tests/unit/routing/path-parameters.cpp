/**
 * @file qbm/http/tests/unit/routing/path-parameters.cpp
 * @brief Unit tests for qb::http::PathParameters (routing/path_parameters.h).
 *
 * The radix matcher exercises `PathParameters` indirectly (it only ever calls
 * `set()`), so the map-like accessor surface — `get`/`has`/`at`/`find`/`get_all`,
 * the iterator pair, `erase` in all three forms, `clear`/`size`/`empty`/`swap`/
 * `reserve`, and `insert_or_assign` overwrite semantics — was almost entirely
 * unverified. This file pins that surface directly: present vs. missing keys,
 * the `at()` throw, last-write-wins on a repeated key, and round-trip mutation.
 *
 * Pure value type: no router, no socket, no event loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <string_view>

#include "../routing/path_parameters.h"

using qb::http::PathParameters;

namespace {

// --------------------------------------------------------------------------
// Empty / default state.
// --------------------------------------------------------------------------

TEST(PathParametersTest, DefaultIsEmpty) {
    PathParameters pp;
    EXPECT_TRUE(pp.empty());
    EXPECT_EQ(pp.size(), 0u);
    EXPECT_FALSE(pp.has("id"));
    EXPECT_FALSE(pp.get("id").has_value());
    EXPECT_EQ(pp.begin(), pp.end());
    EXPECT_EQ(pp.cbegin(), pp.cend());
}

// --------------------------------------------------------------------------
// set() + get()/has()/size()/empty() — the common happy path.
// --------------------------------------------------------------------------

TEST(PathParametersTest, SetThenGet) {
    PathParameters pp;
    pp.set("id", "42");

    EXPECT_FALSE(pp.empty());
    EXPECT_EQ(pp.size(), 1u);
    EXPECT_TRUE(pp.has("id"));

    auto v = pp.get("id");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v.value(), "42");
}

TEST(PathParametersTest, MultipleDistinctKeys) {
    PathParameters pp;
    pp.set("category", "books");
    pp.set("id", "7");
    pp.set("slug", "the-trial");

    EXPECT_EQ(pp.size(), 3u);
    EXPECT_EQ(pp.get("category").value(), "books");
    EXPECT_EQ(pp.get("id").value(), "7");
    EXPECT_EQ(pp.get("slug").value(), "the-trial");
}

// set() is insert_or_assign: a repeated key overwrites, it does not duplicate.
TEST(PathParametersTest, SetOverwritesExistingKey) {
    PathParameters pp;
    pp.set("id", "first");
    pp.set("id", "second");

    EXPECT_EQ(pp.size(), 1u);
    EXPECT_EQ(pp.get("id").value(), "second");
}

// A captured value may legitimately be empty (e.g. a trailing wildcard that
// matched nothing): the key is still present, distinct from a missing key.
TEST(PathParametersTest, EmptyValueIsStillPresent) {
    PathParameters pp;
    pp.set("rest", "");

    EXPECT_TRUE(pp.has("rest"));
    auto v = pp.get("rest");
    ASSERT_TRUE(v.has_value());
    EXPECT_TRUE(v.value().empty());
    EXPECT_FALSE(pp.empty()); // the container is not empty even though the value is
}

// --------------------------------------------------------------------------
// Missing-key behaviour: get() yields nullopt, at() throws.
// --------------------------------------------------------------------------

TEST(PathParametersTest, GetMissingKeyReturnsNullopt) {
    PathParameters pp;
    pp.set("id", "1");
    EXPECT_FALSE(pp.get("missing").has_value());
    EXPECT_FALSE(pp.has("missing"));
}

TEST(PathParametersTest, AtPresentKeyReturnsReference) {
    PathParameters pp;
    pp.set("id", "abc");
    EXPECT_EQ(pp.at("id"), "abc");

    // at() returns a mutable reference; mutating through it is observable.
    pp.at("id") = "xyz";
    EXPECT_EQ(pp.get("id").value(), "xyz");
}

TEST(PathParametersTest, AtMissingKeyThrows) {
    PathParameters pp;
    pp.set("id", "1");
    EXPECT_THROW((void) pp.at("nope"), std::out_of_range);

    const PathParameters &cpp = pp;
    EXPECT_THROW((void) cpp.at("nope"), std::out_of_range);
}

// --------------------------------------------------------------------------
// find() — present and absent.
// --------------------------------------------------------------------------

TEST(PathParametersTest, FindPresentAndAbsent) {
    PathParameters pp;
    pp.set("a", "1");

    auto it = pp.find("a");
    ASSERT_NE(it, pp.end());
    EXPECT_EQ(it->second, "1");

    EXPECT_EQ(pp.find("b"), pp.end());

    const PathParameters &cpp = pp;
    auto                  cit = cpp.find("a");
    ASSERT_NE(cit, cpp.end());
    EXPECT_EQ(cit->second, "1");
    EXPECT_EQ(cpp.find("b"), cpp.end());
}

// --------------------------------------------------------------------------
// get_all() + iteration.
// --------------------------------------------------------------------------

TEST(PathParametersTest, GetAllExposesStorageAndIterates) {
    PathParameters pp;
    pp.set("x", "10");
    pp.set("y", "20");

    const auto &storage = pp.get_all();
    EXPECT_EQ(storage.size(), 2u);

    // Iteration order is unspecified for the hash map, so accumulate and compare.
    int x_seen = 0, y_seen = 0;
    for (const auto &[key, value] : pp) {
        if (key == "x") {
            ++x_seen;
            EXPECT_EQ(value, "10");
        } else if (key == "y") {
            ++y_seen;
            EXPECT_EQ(value, "20");
        }
    }
    EXPECT_EQ(x_seen, 1);
    EXPECT_EQ(y_seen, 1);
}

// --------------------------------------------------------------------------
// erase() — by key, by iterator, by range.
// --------------------------------------------------------------------------

TEST(PathParametersTest, EraseByKey) {
    PathParameters pp;
    pp.set("a", "1");
    pp.set("b", "2");

    EXPECT_EQ(pp.erase("a"), 1u); // one element removed
    EXPECT_FALSE(pp.has("a"));
    EXPECT_TRUE(pp.has("b"));
    EXPECT_EQ(pp.size(), 1u);

    EXPECT_EQ(pp.erase("missing"), 0u); // nothing to remove
    EXPECT_EQ(pp.size(), 1u);
}

TEST(PathParametersTest, EraseByIterator) {
    PathParameters pp;
    pp.set("only", "v");

    auto it = pp.find("only");
    ASSERT_NE(it, pp.end());
    pp.erase(it);
    EXPECT_TRUE(pp.empty());
}

TEST(PathParametersTest, EraseRangeClearsAll) {
    PathParameters pp;
    pp.set("a", "1");
    pp.set("b", "2");
    pp.set("c", "3");

    pp.erase(pp.cbegin(), pp.cend());
    EXPECT_TRUE(pp.empty());
    EXPECT_EQ(pp.size(), 0u);
}

// --------------------------------------------------------------------------
// clear() / reserve().
// --------------------------------------------------------------------------

TEST(PathParametersTest, ClearEmptiesContainer) {
    PathParameters pp;
    pp.set("a", "1");
    pp.set("b", "2");
    pp.clear();
    EXPECT_TRUE(pp.empty());
    EXPECT_EQ(pp.size(), 0u);
    EXPECT_FALSE(pp.get("a").has_value());
}

TEST(PathParametersTest, ReserveDoesNotChangeContents) {
    PathParameters pp;
    pp.set("a", "1");
    pp.reserve(64); // hint only; observable contents unchanged
    EXPECT_EQ(pp.size(), 1u);
    EXPECT_EQ(pp.get("a").value(), "1");
}

// --------------------------------------------------------------------------
// swap() — member and value semantics.
// --------------------------------------------------------------------------

TEST(PathParametersTest, SwapExchangesContents) {
    PathParameters lhs;
    lhs.set("l", "left");

    PathParameters rhs;
    rhs.set("r", "right");
    rhs.set("r2", "right2");

    lhs.swap(rhs);

    EXPECT_EQ(lhs.size(), 2u);
    EXPECT_TRUE(lhs.has("r"));
    EXPECT_TRUE(lhs.has("r2"));
    EXPECT_FALSE(lhs.has("l"));

    EXPECT_EQ(rhs.size(), 1u);
    EXPECT_TRUE(rhs.has("l"));
    EXPECT_FALSE(rhs.has("r"));
}

// --------------------------------------------------------------------------
// Copy / move value semantics.
// --------------------------------------------------------------------------

TEST(PathParametersTest, CopyIsIndependent) {
    PathParameters original;
    original.set("id", "1");

    PathParameters copy = original; // deep copy of owned std::string values
    copy.set("id", "2");
    copy.set("extra", "e");

    EXPECT_EQ(original.get("id").value(), "1");
    EXPECT_FALSE(original.has("extra"));
    EXPECT_EQ(copy.get("id").value(), "2");
    EXPECT_TRUE(copy.has("extra"));
}

TEST(PathParametersTest, MoveTransfersContents) {
    PathParameters source;
    source.set("id", "99");

    PathParameters moved = std::move(source);
    EXPECT_EQ(moved.get("id").value(), "99");
    EXPECT_EQ(moved.size(), 1u);
}

} // namespace

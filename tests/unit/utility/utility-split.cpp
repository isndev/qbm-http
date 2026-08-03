/**
 * @file unit/utility/utility-split.cpp
 * @brief Pure-function unit tests for the string-splitting / joining helpers in
 *        qb::http::utility: the lazy split_view range, the split_string /
 *        split_string_by templates, split_and_trim_header_list, and join.
 *
 * Split out of the former monolithic test-utility.cpp.
 *
 * qb - C++ Actor Framework
 * Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */
#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

#include <qbm/http/utility.h>

using namespace qb::http;

//////////////////////////////////////////////////
// split_and_trim_header_list
//////////////////////////////////////////////////

TEST(UtilitySplitAndTrim, TrimsAndDropsEmpty) {
    auto parts = utility::split_and_trim_header_list(" a , b ,, c ", ',');
    ASSERT_EQ(parts.size(), 3u);
    EXPECT_EQ(parts[0], "a");
    EXPECT_EQ(parts[1], "b");
    EXPECT_EQ(parts[2], "c");
}

TEST(UtilitySplitAndTrim, SingleAndEmpty) {
    auto single = utility::split_and_trim_header_list("  solo  ", ',');
    ASSERT_EQ(single.size(), 1u);
    EXPECT_EQ(single[0], "solo");

    // All-whitespace / all-delimiter input yields no tokens.
    EXPECT_TRUE(utility::split_and_trim_header_list("   ", ',').empty());
    EXPECT_TRUE(utility::split_and_trim_header_list(",,,", ',').empty());
    EXPECT_TRUE(utility::split_and_trim_header_list("", ',').empty());
}

//////////////////////////////////////////////////
// split_view lazy tokens including empties
//////////////////////////////////////////////////

static std::vector<std::string>
collect_split_view(std::string_view sv, char delim) {
    std::vector<std::string> out;
    for (auto tok : utility::split_view(sv, delim)) {
        out.emplace_back(tok);
    }
    return out;
}

TEST(UtilitySplitView, EmptyTokensPreserved) {
    auto out = collect_split_view("a,,b,", ',');
    ASSERT_EQ(out.size(), 4u);
    EXPECT_EQ(out[0], "a");
    EXPECT_EQ(out[1], "");
    EXPECT_EQ(out[2], "b");
    EXPECT_EQ(out[3], "");
}

TEST(UtilitySplitView, NoDelimiterSingleToken) {
    auto out = collect_split_view("abc", ',');
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], "abc");
}

TEST(UtilitySplitView, EmptyInputSingleEmptyToken) {
    auto out = collect_split_view("", ',');
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], "");
}

TEST(UtilitySplitView, PostfixIncrementAndSentinel) {
    utility::split_view view("x,y", ',');
    auto                it  = view.begin();
    auto                end = view.end();

    ASSERT_TRUE(it != end);
    // Postfix increment returns the pre-increment value.
    auto prev = it++;
    EXPECT_EQ(*prev, "x");
    EXPECT_EQ(*it, "y");

    auto last = it++;
    EXPECT_EQ(*last, "y");
    // After consuming the last token the iterator equals the sentinel.
    EXPECT_TRUE(it == end);
}

//////////////////////////////////////////////////
// split_string<String>(sv, delimiters)
//////////////////////////////////////////////////

TEST(UtilitySplitString, MultiDelimiterTokens) {
    auto parts = utility::split_string<std::string>("key=value;other=val", "=;");
    ASSERT_EQ(parts.size(), 4u);
    EXPECT_EQ(parts[0], "key");
    EXPECT_EQ(parts[1], "value");
    EXPECT_EQ(parts[2], "other");
    EXPECT_EQ(parts[3], "val");
}

TEST(UtilitySplitString, ExplicitReserveHint) {
    // The reserve hint is a capacity optimization; results are unchanged.
    auto parts = utility::split_string<std::string>("key=value;other=val", "=;", 4);
    ASSERT_EQ(parts.size(), 4u);
    EXPECT_EQ(parts[3], "val");
}

TEST(UtilitySplitString, EmptyInput) {
    auto parts = utility::split_string<std::string>("", "=;");
    EXPECT_TRUE(parts.empty());
}

TEST(UtilitySplitString, StringViewResultType) {
    // Same algorithm, string_view storage type.
    auto parts = utility::split_string<std::string_view>("a/b/c", "/");
    ASSERT_EQ(parts.size(), 3u);
    EXPECT_EQ(parts[0], "a");
    EXPECT_EQ(parts[1], "b");
    EXPECT_EQ(parts[2], "c");
}

TEST(UtilitySplitString, PredicateOverload) {
    auto parts = utility::split_string<std::string>("a,b c;d", [](char c) { return c == ',' || c == ' ' || c == ';'; });
    ASSERT_EQ(parts.size(), 4u);
    EXPECT_EQ(parts[0], "a");
    EXPECT_EQ(parts[1], "b");
    EXPECT_EQ(parts[2], "c");
    EXPECT_EQ(parts[3], "d");
}

//////////////////////////////////////////////////
// split_string_by<String>(sv, boundary)
//////////////////////////////////////////////////

TEST(UtilitySplitStringBy, MultiPartBoundary) {
    auto parts = utility::split_string_by<std::string>("p1--b--p2--b--p3", "--b--");
    ASSERT_EQ(parts.size(), 3u);
    EXPECT_EQ(parts[0], "p1");
    EXPECT_EQ(parts[1], "p2");
    EXPECT_EQ(parts[2], "p3");
}

TEST(UtilitySplitStringBy, TrailingBoundaryYieldsEmptyTail) {
    auto parts = utility::split_string_by<std::string>("a--", "--");
    ASSERT_EQ(parts.size(), 2u);
    EXPECT_EQ(parts[0], "a");
    EXPECT_EQ(parts[1], "");
}

TEST(UtilitySplitStringBy, LeadingBoundaryYieldsEmptyHead) {
    auto parts = utility::split_string_by<std::string>("--a", "--");
    ASSERT_EQ(parts.size(), 2u);
    EXPECT_EQ(parts[0], "");
    EXPECT_EQ(parts[1], "a");
}

TEST(UtilitySplitStringBy, EmptyBoundaryReturnsWholeString) {
    auto parts = utility::split_string_by<std::string>("abc", "");
    ASSERT_EQ(parts.size(), 1u);
    EXPECT_EQ(parts[0], "abc");
}

// Boundary strictly longer than the input can never occur -> the whole input is
// returned as a single part (str.find returns npos on the first probe).
TEST(UtilitySplitStringBy, BoundaryLongerThanInputYieldsWholeString) {
    auto parts = utility::split_string_by<std::string>("ab", "abcdef");
    ASSERT_EQ(parts.size(), 1u);
    EXPECT_EQ(parts[0], "ab");
}

// A boundary equal to the entire input splits into an empty head and empty tail.
TEST(UtilitySplitStringBy, BoundaryEqualToWholeInputYieldsTwoEmptyParts) {
    auto parts = utility::split_string_by<std::string>("--b--", "--b--");
    ASSERT_EQ(parts.size(), 2u);
    EXPECT_EQ(parts[0], "");
    EXPECT_EQ(parts[1], "");
}

// Empty input with a non-empty boundary yields a single empty part.
TEST(UtilitySplitStringBy, EmptyInputYieldsSingleEmptyPart) {
    auto parts = utility::split_string_by<std::string>("", "--");
    ASSERT_EQ(parts.size(), 1u);
    EXPECT_EQ(parts[0], "");
}

//////////////////////////////////////////////////
// join<T>
//////////////////////////////////////////////////

TEST(UtilityJoin, EmptySingleAndMultipleStrings) {
    std::vector<std::string> empty;
    EXPECT_EQ(utility::join(empty, ", "), "");

    std::vector<std::string> single{"a"};
    EXPECT_EQ(utility::join(single, ", "), "a");

    std::vector<std::string> multi{"a", "b", "c"};
    EXPECT_EQ(utility::join(multi, ", "), "a, b, c");
}

TEST(UtilityJoin, StringViewElements) {
    std::vector<std::string_view> empty;
    EXPECT_EQ(utility::join(empty, ", "), "");

    std::vector<std::string_view> single{"a"};
    EXPECT_EQ(utility::join(single, ", "), "a");

    std::vector<std::string_view> multi{"a", "b", "c"};
    EXPECT_EQ(utility::join(multi, ", "), "a, b, c");
}

/**
 * @file test-utility.cpp
 * @brief Pure-function unit tests for qb::http::utility.
 *
 * Covers the inline helpers declared in qbm/http/utility.h (character
 * classifiers, case-folding, iequals, trimming, the lazy split_view range,
 * and the split_string / split_string_by / join templates) as well as the
 * out-of-line definitions in qbm/http/utility.cpp (decode_path_component,
 * split_and_trim_header_list, escape_html, uri_encode_component).
 *
 * qb - C++ Actor Framework
 * Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */
#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

#include "../utility.h"

using namespace qb::http;

//////////////////////////////////////////////////
// 1. uri_encode_component
//////////////////////////////////////////////////

TEST(UtilityUriEncode, UnreservedCharactersPassThrough) {
    // Alphanumerics and the unreserved set (-_.~) are never encoded.
    EXPECT_EQ(utility::uri_encode_component("AZaz09"), "AZaz09");
    EXPECT_EQ(utility::uri_encode_component("-_.~"), "-_.~");
    EXPECT_EQ(utility::uri_encode_component("abcXYZ0123456789-_.~"), "abcXYZ0123456789-_.~");
}

TEST(UtilityUriEncode, ReservedCharactersAreEncodedUpperHex) {
    // Space -> %20, slash -> %2F, etc. Hex digits are UPPER-case (per impl).
    EXPECT_EQ(utility::uri_encode_component(" "), "%20");
    EXPECT_EQ(utility::uri_encode_component("/"), "%2F");
    EXPECT_EQ(utility::uri_encode_component("?"), "%3F");
    EXPECT_EQ(utility::uri_encode_component("&"), "%26");
    EXPECT_EQ(utility::uri_encode_component("="), "%3D");
    EXPECT_EQ(utility::uri_encode_component("a b/c"), "a%20b%2Fc");
}

TEST(UtilityUriEncode, HighByteEncodesUpperHex) {
    // 0xFF must become %FF (upper-case), not %ff.
    std::string in;
    in.push_back(static_cast<char>(0xFF));
    EXPECT_EQ(utility::uri_encode_component(in), "%FF");
}

TEST(UtilityUriEncode, EmptyInput) {
    EXPECT_EQ(utility::uri_encode_component(""), "");
}

//////////////////////////////////////////////////
// 2. escape_html
//////////////////////////////////////////////////

TEST(UtilityEscapeHtml, AllFiveEntities) {
    EXPECT_EQ(utility::escape_html("&"), "&amp;");
    EXPECT_EQ(utility::escape_html("<"), "&lt;");
    EXPECT_EQ(utility::escape_html(">"), "&gt;");
    EXPECT_EQ(utility::escape_html("\""), "&quot;");
    EXPECT_EQ(utility::escape_html("'"), "&#39;");
}

TEST(UtilityEscapeHtml, MixedAndPassthrough) {
    EXPECT_EQ(utility::escape_html("<a href=\"x\">a&b's</a>"), "&lt;a href=&quot;x&quot;&gt;a&amp;b&#39;s&lt;/a&gt;");
    // Ordinary text is untouched.
    EXPECT_EQ(utility::escape_html("plain text 123"), "plain text 123");
    EXPECT_EQ(utility::escape_html(""), "");
}

//////////////////////////////////////////////////
// 3. decode_path_component
//////////////////////////////////////////////////

TEST(UtilityDecodePath, ValidEscapeDecodes) {
    EXPECT_EQ(utility::decode_path_component("%2F"), "/");
    EXPECT_EQ(utility::decode_path_component("a%2Fb"), "a/b");
    // Lower-case hex digits are accepted too.
    EXPECT_EQ(utility::decode_path_component("%2f"), "/");
    EXPECT_EQ(utility::decode_path_component("%41"), "A");
}

TEST(UtilityDecodePath, TrailingPercentIsLiteral) {
    // A bare trailing '%' has no following hex digits -> kept literal.
    EXPECT_EQ(utility::decode_path_component("%"), "%");
    EXPECT_EQ(utility::decode_path_component("abc%"), "abc%");
}

TEST(UtilityDecodePath, IncompleteEscapeIsLiteral) {
    // "%4" has only one trailing char -> not decoded, kept literal.
    EXPECT_EQ(utility::decode_path_component("%4"), "%4");
}

TEST(UtilityDecodePath, PlusStaysLiteral) {
    // '+' is a valid path char and must NOT become a space.
    EXPECT_EQ(utility::decode_path_component("a+b"), "a+b");
    EXPECT_EQ(utility::decode_path_component("+"), "+");
}

TEST(UtilityDecodePath, NonHexEscapeIsLiteral) {
    // "%ZZ" is not a valid escape -> kept literal.
    EXPECT_EQ(utility::decode_path_component("%ZZ"), "%ZZ");
}

//////////////////////////////////////////////////
// 4. split_and_trim_header_list
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
// 5. split_view lazy tokens including empties
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

//////////////////////////////////////////////////
// 6. split_view::iterator postfix increment + sentinel compare
//////////////////////////////////////////////////

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
// 7. split_string<std::string>(sv, delimiters)
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

//////////////////////////////////////////////////
// 8. split_string predicate overload
//////////////////////////////////////////////////

TEST(UtilitySplitString, PredicateOverload) {
    auto parts = utility::split_string<std::string>("a,b c;d", [](char c) { return c == ',' || c == ' ' || c == ';'; });
    ASSERT_EQ(parts.size(), 4u);
    EXPECT_EQ(parts[0], "a");
    EXPECT_EQ(parts[1], "b");
    EXPECT_EQ(parts[2], "c");
    EXPECT_EQ(parts[3], "d");
}

//////////////////////////////////////////////////
// 9. split_string_by<std::string>(sv, boundary)
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

//////////////////////////////////////////////////
// 10. join<T>
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

//////////////////////////////////////////////////
// 11. iequals matrix
//////////////////////////////////////////////////

TEST(UtilityIequals, CaseInsensitiveMatrix) {
    EXPECT_TRUE(utility::iequals("ABC", "abc"));
    EXPECT_FALSE(utility::iequals("ab", "abc"));  // differing length
    EXPECT_TRUE(utility::iequals("a!", "a!"));    // non-letters compare exactly
    EXPECT_FALSE(utility::iequals("abc", "abd")); // differ not by case
    EXPECT_TRUE(utility::iequals("A", "a"));
    EXPECT_TRUE(utility::iequals("", "")); // both empty
    // Non-letter bytes that differ only by the 0x20 bit must NOT match.
    EXPECT_FALSE(utility::iequals("!", "\x01"));
}

//////////////////////////////////////////////////
// 12. char classifiers
//////////////////////////////////////////////////

TEST(UtilityClassifiers, HexValue) {
    EXPECT_EQ(utility::hex_value('9'), 9u);
    EXPECT_EQ(utility::hex_value('0'), 0u);
    EXPECT_EQ(utility::hex_value('f'), 15u);
    EXPECT_EQ(utility::hex_value('F'), 15u);
    EXPECT_EQ(utility::hex_value('a'), 10u);
    EXPECT_EQ(utility::hex_value('A'), 10u);
    // Non-hex digit returns 0.
    EXPECT_EQ(utility::hex_value('g'), 0u);
    EXPECT_EQ(utility::hex_value('!'), 0u);
}

TEST(UtilityClassifiers, IsSpecial) {
    // tspecials sample.
    EXPECT_TRUE(utility::is_special('('));
    EXPECT_TRUE(utility::is_special(';'));
    EXPECT_TRUE(utility::is_special('/'));
    EXPECT_TRUE(utility::is_special(' '));
    EXPECT_TRUE(utility::is_special('\t'));
    EXPECT_FALSE(utility::is_special('a'));
    EXPECT_FALSE(utility::is_special('5'));
}

TEST(UtilityClassifiers, IsHexDigit) {
    EXPECT_TRUE(utility::is_hex_digit('0'));
    EXPECT_TRUE(utility::is_hex_digit('9'));
    EXPECT_TRUE(utility::is_hex_digit('a'));
    EXPECT_TRUE(utility::is_hex_digit('f'));
    EXPECT_TRUE(utility::is_hex_digit('A'));
    EXPECT_TRUE(utility::is_hex_digit('F'));
    EXPECT_FALSE(utility::is_hex_digit('g'));
    EXPECT_FALSE(utility::is_hex_digit('G'));
    EXPECT_FALSE(utility::is_hex_digit(' '));
}

TEST(UtilityClassifiers, IsDigit) {
    EXPECT_TRUE(utility::is_digit('0'));
    EXPECT_TRUE(utility::is_digit('9'));
    EXPECT_FALSE(utility::is_digit('a'));
    EXPECT_FALSE(utility::is_digit('/')); // char just below '0'
    EXPECT_FALSE(utility::is_digit(':')); // char just above '9'
}

TEST(UtilityClassifiers, IsControl) {
    EXPECT_TRUE(utility::is_control(0));
    EXPECT_TRUE(utility::is_control(31));
    EXPECT_TRUE(utility::is_control(127));
    EXPECT_TRUE(utility::is_control('\t')); // 9
    EXPECT_FALSE(utility::is_control(32));  // space is not control
    EXPECT_FALSE(utility::is_control('A'));
}

TEST(UtilityClassifiers, IsChar) {
    EXPECT_TRUE(utility::is_char(0));
    EXPECT_TRUE(utility::is_char(127));
    EXPECT_TRUE(utility::is_char('A'));
    EXPECT_FALSE(utility::is_char(128));
    EXPECT_FALSE(utility::is_char(-1));
}

TEST(UtilityClassifiers, IsHttpWhitespace) {
    EXPECT_TRUE(utility::is_http_whitespace(' '));
    EXPECT_TRUE(utility::is_http_whitespace('\t'));
    EXPECT_FALSE(utility::is_http_whitespace('\n'));
    EXPECT_FALSE(utility::is_http_whitespace('a'));
}

TEST(UtilityClassifiers, AsciiToLower) {
    EXPECT_EQ(utility::ascii_to_lower('A'), 'a');
    EXPECT_EQ(utility::ascii_to_lower('Z'), 'z');
    EXPECT_EQ(utility::ascii_to_lower('a'), 'a'); // already lower
    EXPECT_EQ(utility::ascii_to_lower('5'), '5'); // non-letter untouched
    EXPECT_EQ(utility::ascii_to_lower('@'), '@'); // just below 'A'
    EXPECT_EQ(utility::ascii_to_lower('['), '['); // just above 'Z'
}

//////////////////////////////////////////////////
// 13. trim_http_whitespace
//////////////////////////////////////////////////

TEST(UtilityTrim, TrimsBothEnds) {
    EXPECT_EQ(utility::trim_http_whitespace("\t a \t"), "a");
    EXPECT_EQ(utility::trim_http_whitespace("  hello  "), "hello");
    EXPECT_EQ(utility::trim_http_whitespace("\tx"), "x");
}

TEST(UtilityTrim, AllWhitespaceYieldsEmpty) {
    EXPECT_EQ(utility::trim_http_whitespace("   "), "");
    EXPECT_EQ(utility::trim_http_whitespace("\t\t"), "");
    EXPECT_EQ(utility::trim_http_whitespace(""), "");
}

TEST(UtilityTrim, NoWhitespaceUnchanged) {
    EXPECT_EQ(utility::trim_http_whitespace("x"), "x");
    EXPECT_EQ(utility::trim_http_whitespace("abc"), "abc");
}

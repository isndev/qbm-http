/**
 * @file unit/utility/utility-chars.cpp
 * @brief Pure-function unit tests for the inline character classifiers,
 *        case-folding, iequals, and trim_http_whitespace helpers in
 *        qb::http::utility.
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

#include "../utility.h"

using namespace qb::http;

//////////////////////////////////////////////////
// iequals matrix
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

TEST(UtilityIequals, EmbeddedNulAndHighBytes) {
    // iequals operates over the full length (no NUL truncation): two views with
    // an embedded NUL match iff every byte folds equal.
    std::string a("a\0B", 3);
    std::string b("a\0b", 3);
    EXPECT_TRUE(utility::iequals(a, b)); // 'B' folds to 'b'; NUL matches NUL

    std::string c("a\0B", 3);
    std::string d("a\0c", 3);
    EXPECT_FALSE(utility::iequals(c, d)); // 'B' vs 'c' differ beyond case

    // High (non-ASCII) bytes are compared exactly — case-folding only applies to
    // ASCII A-Z, so 0xC0 and 0xE0 (which differ by 0x20) must NOT match.
    std::string hi1;
    hi1.push_back(static_cast<char>(0xC0));
    std::string hi2;
    hi2.push_back(static_cast<char>(0xE0));
    EXPECT_FALSE(utility::iequals(hi1, hi2));
    EXPECT_TRUE(utility::iequals(hi1, hi1));
}

//////////////////////////////////////////////////
// char classifiers
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
// trim_http_whitespace
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

// Only SP and HTAB are HTTP whitespace; CR/LF/VT/FF are NOT trimmed.
TEST(UtilityTrim, DoesNotTrimNonHttpWhitespace) {
    EXPECT_EQ(utility::trim_http_whitespace("\nabc\n"), "\nabc\n");
    EXPECT_EQ(utility::trim_http_whitespace("\r x \r"), "\r x \r");
    // Interior whitespace is preserved; only the ends are trimmed.
    EXPECT_EQ(utility::trim_http_whitespace("  a b  "), "a b");
}

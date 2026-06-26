/**
 * @file qbm/http/tests/unit/validation/validation-sanitizer.cpp
 * @brief Unit tests for qb::http::validation::{Sanitizer, PredefinedSanitizers}.
 *
 * Pure-logic coverage of the in-place JSON sanitizer: path targeting (nested,
 * array wildcard, array index), rule chaining order, and each predefined rule
 * (trim, lower-case, escape-html, normalize-whitespace, escape-sql-like, and
 * the state-machine strip_html_tags XSS guard). No socket, no event loop.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include <qb/json.h>

#include "../validation.h"

using namespace qb::http::validation;

class ValidationSanitizerTest : public ::testing::Test {};

// --- Path targeting & rule chaining ------------------------------------------

TEST_F(ValidationSanitizerTest, Trim) {
    Sanitizer s;
    s.add_rule("name", PredefinedSanitizers::trim());
    qb::json data = {{"name", "  test user  "}};
    s.sanitize(data);
    EXPECT_EQ(data["name"].get<std::string>(), "test user");
}

TEST_F(ValidationSanitizerTest, MultipleRulesOnField) {
    Sanitizer s;
    s.add_rule("comment", PredefinedSanitizers::trim());
    s.add_rule("comment", PredefinedSanitizers::to_lower_case());
    s.add_rule("comment", PredefinedSanitizers::escape_html());

    qb::json data = {{"comment", "  <Hello> World!  "}};
    s.sanitize(data);
    EXPECT_EQ(data["comment"].get<std::string>(), "&lt;hello&gt; world!");
}

TEST_F(ValidationSanitizerTest, NestedPath) {
    Sanitizer s;
    s.add_rule("user.profile.bio", PredefinedSanitizers::trim());
    qb::json data = {{"user", {{"profile", {{"bio", "  A long bio.  "}}}}}};
    s.sanitize(data);
    EXPECT_EQ(data["user"]["profile"]["bio"].get<std::string>(), "A long bio.");
}

TEST_F(ValidationSanitizerTest, ArrayWildcard) {
    Sanitizer s_combined;
    s_combined.add_rule("tags[*]", PredefinedSanitizers::trim());
    s_combined.add_rule("tags[*]", PredefinedSanitizers::to_lower_case());
    s_combined.add_rule("posts[*].title", PredefinedSanitizers::trim());

    qb::json data_for_combined = {
        {"tags", {"TAG_A", "  TagB  ", "  tAgC  "}},
        {"posts", {{{"title", "  First Post  "}, {"content", "..."}}, {{"title", "Second Post  "}, {"content", "..."}}}}
    };
    s_combined.sanitize(data_for_combined);
    ASSERT_TRUE(data_for_combined["tags"].is_array());
    EXPECT_EQ(data_for_combined["tags"][0].get<std::string>(), "tag_a");
    EXPECT_EQ(data_for_combined["tags"][1].get<std::string>(), "tagb");
    EXPECT_EQ(data_for_combined["tags"][2].get<std::string>(), "tagc");

    ASSERT_TRUE(data_for_combined["posts"].is_array());
    ASSERT_EQ(data_for_combined["posts"].size(), 2u);
    EXPECT_EQ(data_for_combined["posts"][0]["title"].get<std::string>(), "First Post");
    EXPECT_EQ(data_for_combined["posts"][1]["title"].get<std::string>(), "Second Post");
}

TEST_F(ValidationSanitizerTest, ArrayIndexSpecific) {
    Sanitizer s;
    s.add_rule("users[1].name", PredefinedSanitizers::trim());
    qb::json data = {{"users", {{{"name", "  Alice  "}}, {{"name", "   Bob   "}}, {{"name", "  Charlie  "}}}}};
    s.sanitize(data);
    EXPECT_EQ(data["users"][0]["name"].get<std::string>(), "  Alice  ");
    EXPECT_EQ(data["users"][1]["name"].get<std::string>(), "Bob");
    EXPECT_EQ(data["users"][2]["name"].get<std::string>(), "  Charlie  ");
}

// --- Predefined string rules -------------------------------------------------

TEST_F(ValidationSanitizerTest, NormalizeWhitespace) {
    Sanitizer s;
    s.add_rule("text", PredefinedSanitizers::normalize_whitespace());

    qb::json data1 = {{"text", "  hello    world  \t\n  next  "}};
    s.sanitize(data1);
    EXPECT_EQ(data1["text"].get<std::string>(), "hello world next");

    qb::json data2 = {{"text", "NoExtraSpaces"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["text"].get<std::string>(), "NoExtraSpaces");

    qb::json data3 = {{"text", "   "}};
    s.sanitize(data3);
    EXPECT_EQ(data3["text"].get<std::string>(), "");

    qb::json data4 = {{"text", " leading space"}};
    s.sanitize(data4);
    EXPECT_EQ(data4["text"].get<std::string>(), "leading space");
}

TEST_F(ValidationSanitizerTest, EscapeSqlLike) {
    Sanitizer s;
    s.add_rule("search", PredefinedSanitizers::escape_sql_like());

    qb::json data1 = {{"search", "user%name"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["search"].get<std::string>(), "user\\%name");

    qb::json data2 = {{"search", "customer_id"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["search"].get<std::string>(), "customer\\_id");

    qb::json data3 = {{"search", "O'Malley's"}};
    s.sanitize(data3);
    EXPECT_EQ(data3["search"].get<std::string>(), "O''Malley''s");

    Sanitizer s_combo;
    s_combo.add_rule("search", PredefinedSanitizers::trim());
    s_combo.add_rule("search", PredefinedSanitizers::escape_sql_like());
    qb::json data_combo = {{"search", "  test % _ '  "}};
    s_combo.sanitize(data_combo);
    EXPECT_EQ(data_combo["search"].get<std::string>(), "test \\% \\_ ''");
}

// --- strip_html_tags state machine -------------------------------------------

TEST_F(ValidationSanitizerTest, StripHtmlTagsBasic) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    qb::json data1 = {{"content", "<p>Hello World</p>"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["content"].get<std::string>(), "Hello World");

    qb::json data2 = {{"content", "<div><p>Nested <b>Bold</b> Text</p></div>"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["content"].get<std::string>(), "Nested Bold Text");

    qb::json data3 = {{"content", "Line 1<br/>Line 2<hr/>Line 3"}};
    s.sanitize(data3);
    EXPECT_EQ(data3["content"].get<std::string>(), "Line 1Line 2Line 3");
}

TEST_F(ValidationSanitizerTest, StripHtmlTagsWithAttributes) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    qb::json data1 = {{"content", "<a href=\"https://example.com\" target=\"_blank\">Link</a>"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["content"].get<std::string>(), "Link");

    qb::json data2 = {{"content", "<div class='container'>Content</div>"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["content"].get<std::string>(), "Content");

    qb::json data3 = {{"content", "<img src=\"image.jpg\" alt=\"Image\" width=\"100\" />"}};
    s.sanitize(data3);
    EXPECT_EQ(data3["content"].get<std::string>(), "");
}

TEST_F(ValidationSanitizerTest, StripHtmlTagsComments) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    qb::json data1 = {{"content", "<!-- This is a comment -->Visible text"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["content"].get<std::string>(), "Visible text");

    qb::json data2 = {{"content", "<!-- Start comment\nMiddle line\nEnd comment -->After comment"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["content"].get<std::string>(), "After comment");

    // Nested-looking comment: the state machine ends the comment at the FIRST "-->".
    // Everything before (including the inner "<!--") is consumed; the remaining
    // " outer -->Text" is plain text because there is no open tag/comment to close.
    // This pins the previously-punted "depends on implementation" case to one value.
    qb::json data3 = {{"content", "<!-- outer <!-- inner --> outer -->Text"}};
    s.sanitize(data3);
    EXPECT_EQ(data3["content"].get<std::string>(), " outer -->Text");
}

TEST_F(ValidationSanitizerTest, StripHtmlTagsScriptAndStyle) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // The tags are stripped; the inner text content is preserved.
    qb::json data1 = {{"content", "<script>alert('XSS')</script>Safe content"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["content"].get<std::string>(), "alert('XSS')Safe content");

    qb::json data2 = {{"content", "<style>body { color: red; }</style>Visible text"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["content"].get<std::string>(), "body { color: red; }Visible text");

    qb::json data3 = {{"content", "Before<script>var x = 1;</script>After"}};
    s.sanitize(data3);
    EXPECT_EQ(data3["content"].get<std::string>(), "Beforevar x = 1;After");
}

TEST_F(ValidationSanitizerTest, StripHtmlTagsEdgeCases) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // '>' inside a quoted attribute does not end the tag early.
    qb::json data1 = {{"content", "<div data-value=\">\">Content</div>"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["content"].get<std::string>(), "Content");

    // "<not a tag>" is a (malformed) tag closed by '>'; "</not>" is also stripped,
    // leaving only the text content. Pins the previously-punted "may vary" case.
    qb::json data2 = {{"content", "<not a tag>Text</not>"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["content"].get<std::string>(), "Text");

    qb::json data3 = {{"content", ""}};
    s.sanitize(data3);
    EXPECT_EQ(data3["content"].get<std::string>(), "");

    qb::json data4 = {{"content", "Plain text without HTML"}};
    s.sanitize(data4);
    EXPECT_EQ(data4["content"].get<std::string>(), "Plain text without HTML");
}

TEST_F(ValidationSanitizerTest, StripHtmlTagsPreservesUnclosedTagLikeText) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    qb::json trailing_lt = {{"content", "text<"}};
    s.sanitize(trailing_lt);
    EXPECT_EQ(trailing_lt["content"].get<std::string>(), "text<");

    qb::json unclosed_tag = {{"content", "prefix <div class=\"x\""}};
    s.sanitize(unclosed_tag);
    EXPECT_EQ(unclosed_tag["content"].get<std::string>(), "prefix <div class=\"x\"");
}

TEST_F(ValidationSanitizerTest, StripHtmlTagsSpecialChars) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    // HTML entities are plain text and survive unchanged.
    qb::json data1 = {{"content", "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>"}};
    s.sanitize(data1);
    EXPECT_EQ(data1["content"].get<std::string>(), "&lt;script&gt;alert(1)&lt;/script&gt;");

    qb::json data2 = {{"content", "<p>Café résumé naïve</p>"}};
    s.sanitize(data2);
    EXPECT_EQ(data2["content"].get<std::string>(), "Café résumé naïve");

    qb::json data3 = {{"content", "<div data-special=\"!@#$%^&*()\">Content</div>"}};
    s.sanitize(data3);
    EXPECT_EQ(data3["content"].get<std::string>(), "Content");
}

// XSS vectors: all tags (and therefore the dangerous attribute names that live
// inside them) are removed, leaving only inert text content.
TEST_F(ValidationSanitizerTest, StripHtmlTagsXSSProtection) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    std::vector<std::string> xss_attempts = {
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<object data=javascript:alert('XSS')>",
        "<embed src=javascript:alert('XSS')>",
        "<form onsubmit=alert('XSS')><button>Submit</button></form>"
    };

    for (const auto &xss : xss_attempts) {
        qb::json data = {{"content", xss}};
        s.sanitize(data);
        const std::string result = data["content"].get<std::string>();
        EXPECT_EQ(result.find('<'), std::string::npos) << "Failed for: " << xss;
        EXPECT_EQ(result.find('>'), std::string::npos) << "Failed for: " << xss;
        EXPECT_EQ(result.find("onerror"), std::string::npos) << "Failed for: " << xss;
        EXPECT_EQ(result.find("onload"), std::string::npos) << "Failed for: " << xss;
    }

    // The "Submit" button label survives once its surrounding tags are stripped.
    qb::json form = {{"content", "<form onsubmit=alert('XSS')><button>Submit</button></form>"}};
    s.sanitize(form);
    EXPECT_EQ(form["content"].get<std::string>(), "Submit");
}

// Chaining order is deterministic: trim -> lower-case -> strip tags.
TEST_F(ValidationSanitizerTest, ChainedRulesApplyInOrder) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::trim());
    s.add_rule("content", PredefinedSanitizers::to_lower_case());
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    qb::json data = {{"content", "  <DIV>HELLO WORLD</DIV>  "}};
    s.sanitize(data);
    EXPECT_EQ(data["content"].get<std::string>(), "hello world");
}

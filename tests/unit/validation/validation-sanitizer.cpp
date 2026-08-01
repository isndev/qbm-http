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

// CHANGED (security): this case used to assert that an unterminated tag is "tag-like TEXT" and is
// echoed back verbatim — `"prefix <div class=\"x\""` in, the same string out. It is not text: it is
// a tag start with a name and an attribute, and it was the ONLY strip_html_tags input that escaped
// the strip logic, because every other case in this file closes its tags.
//
// Sanitized output is interpolated into a page, so the surrounding document supplies the closing
// `>` the attacker omitted (a `</div>` is enough): the browser then builds the element and fires
// any `onerror` / `onload` it carries. A sanitizer may lose text; it may not emit markup.
//
// A trailing lone `<` is dropped too. An earlier revision kept it, reasoning that with no tag name
// seen it cannot start an element — but that reasoning ignores the interpolation the rest of this
// comment relies on. The HTML tokenizer opens a tag on `<` followed by an ASCII letter, `/`, `!` or
// `?`, and those are exactly the characters that begin the *template* text after the insertion
// point: sanitized `"text<"` dropped into `<p>VALUE div></p>` yields `<p>text< div></p>` — harmless
// — but into `<p>VALUEdiv></p>` it yields `text<div>`, an element the sanitizer never inspected.
TEST_F(ValidationSanitizerTest, StripHtmlTagsDropsUnterminatedTagIncludingBareLessThan) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    qb::json trailing_lt = {{"content", "text<"}};
    s.sanitize(trailing_lt);
    EXPECT_EQ(trailing_lt["content"].get<std::string>(), "text")
        << "a trailing '<' must not survive: the template text after the insertion point can complete it into a tag";

    qb::json unclosed_tag = {{"content", "prefix <div class=\"x\""}};
    s.sanitize(unclosed_tag);
    EXPECT_EQ(unclosed_tag["content"].get<std::string>(), "prefix ")
        << "an unterminated tag must be dropped, not echoed: the page around this value closes it";
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

// --- escape_html: ampersand / quote / apostrophe -----------------------------
// The existing MultipleRulesOnField test only exercises the `<`/`>` cases. These three entities
// (`&` → &amp;, `"` → &quot;, `'` → &#39;) are the uncovered branches of escape_html.
TEST_F(ValidationSanitizerTest, EscapeHtmlAmpersandQuoteApostrophe) {
    Sanitizer s;
    s.add_rule("c", PredefinedSanitizers::escape_html());
    qb::json data = {{"c", "Tom & \"Jerry\" 's"}};
    s.sanitize(data);
    EXPECT_EQ(data["c"].get<std::string>(), "Tom &amp; &quot;Jerry&quot; &#39;s");
}

// --- alphanumeric_only: strips every non-[A-Za-z0-9] character ----------------
// Whole sanitizer previously untested.
TEST_F(ValidationSanitizerTest, AlphanumericOnlyStripsNonAlnum) {
    Sanitizer s;
    s.add_rule("c", PredefinedSanitizers::alphanumeric_only());
    qb::json data = {{"c", "a1! b2 @c3#"}};
    s.sanitize(data);
    EXPECT_EQ(data["c"].get<std::string>(), "a1b2c3") << "only letters and digits survive";
}

// --- strip_html_tags: unterminated markup must be DROPPED, not echoed back ----
//
// Every case above feeds WELL-FORMED markup, so they only ever exercise the path where a tag is
// closed. The state machine used to end with "handle unclosed tags by preserving the original
// tail", which appended the raw remainder — so `strip_html_tags("<img src=x onerror=alert(1)")`
// returned that markup verbatim while the closed form was stripped correctly.
//
// That is exploitable, because sanitized output is interpolated into a page: the next `>` in the
// surrounding document (a `</div>`, say) terminates the attacker's tag for them, the browser builds
// the <img>, and onerror fires. Losing text is the correct failure mode for a sanitizer; emitting
// markup is not.

TEST_F(ValidationSanitizerTest, StripHtmlTagsDropsUnterminatedMarkup) {
    Sanitizer s;
    s.add_rule("content", PredefinedSanitizers::strip_html_tags());

    const auto strip = [&s](std::string in) {
        qb::json d = {{"content", std::move(in)}};
        s.sanitize(d);
        return d["content"].get<std::string>();
    };

    // The payload: identical to a case the suite already covers, minus the closing '>'.
    EXPECT_EQ(strip("hello <img src=x onerror=alert(1)>"), "hello ") << "precondition: the closed form is stripped";
    EXPECT_EQ(strip("hello <img src=x onerror=alert(1)"), "hello ")
        << "an unterminated tag was echoed back verbatim: the surrounding page supplies the closing "
           "'>' and the browser executes the handler";

    EXPECT_EQ(strip("safe <script"), "safe ") << "an unterminated tag name must not survive";
    EXPECT_EQ(strip("<!-- unterminated comment"), "") << "an unterminated comment must not survive";
    EXPECT_EQ(strip("text <div attr='unclosed"), "text ") << "an unterminated quoted attribute must not survive";

    // A '<' whose next character rules out a tag is resolved IN THE INPUT and stays: the scanner
    // sees the space, returns to TEXT and emits both characters. Nothing is guessed.
    EXPECT_EQ(strip("5 < 10"), "5 < 10") << "a lone '<' followed by a space is text, not markup";

    // A '<' at END of input is the opposite case: what follows it is not in the input at all, it is
    // whatever template text the caller interpolates this value into. `<` + a letter, '/', '!' or
    // '?' opens a tag, so the only safe reading of an unresolved trailing '<' is to drop it.
    EXPECT_EQ(strip("trailing <"), "trailing ") << "a trailing '<' is unresolved and must not be handed to the page";
}

#include <gtest/gtest.h>

#include "../headers.h"
#include "../request.h"
#include "../response.h"

TEST(HeadersUtility, AcceptEncodingDoesNotAdvertiseChunked) {
    const std::string advertised = qb::http::accept_encoding();
    EXPECT_EQ(advertised.find("chunked"), std::string::npos);
}

TEST(HeadersUtility, ContentEncodingRespectsQZero) {
    const std::string first_supported = qb::http::content_encoding("*");
    if (first_supported.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }

    const std::string header = first_supported + ";q=0";
    EXPECT_TRUE(qb::http::content_encoding(header).empty());
}

TEST(HeadersUtility, WildcardDoesNotReenableExplicitlyDisabledEncoding) {
    const std::string first_supported = qb::http::content_encoding("*");
    if (first_supported.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }

    const std::string header   = first_supported + ";q=0, *;q=1";
    const std::string selected = qb::http::content_encoding(header);

    EXPECT_TRUE(selected.empty() || selected != first_supported);
}

TEST(HeadersUtility, SetHeaderSynchronizesContentTypeHelper) {
    qb::http::Headers headers;

    headers.set_header("Content-Type", "text/html; charset=UTF-16");

    EXPECT_EQ(headers.content_type().type(), "text/html");
    EXPECT_EQ(headers.content_type().charset(), "UTF-16");

    headers.remove_header("content-type");

    EXPECT_EQ(headers.content_type().type(), qb::http::Headers::default_content_type);
    EXPECT_EQ(headers.content_type().charset(), qb::http::Headers::default_charset);
}

TEST(HeadersUtility, HeaderMissReturnsStableEmptyReference) {
    qb::http::Headers headers;

    // Default fallback: the returned reference is to a process-wide static empty string, so it is
    // safe to hold across statements (no dangling temporary).
    const std::string &missing = headers.header("X-Missing");
    EXPECT_TRUE(missing.empty());
    EXPECT_EQ(&missing, &qb::http::detail::empty_string_value);
}

TEST(HeadersUtility, HeaderOrReturnsFallbackByValue) {
    qb::http::Headers headers;

    // header_or() returns the fallback BY VALUE on a miss — always safe, no lifetime caveat.
    EXPECT_EQ(headers.header_or("X-Missing", "fallback-value"), "fallback-value");
}

TEST(HeadersUtility, AddHeaderSynchronizesContentTypeHelperWithFirstValue) {
    qb::http::Headers headers;

    headers.add_header("Content-Type", "application/json; charset=utf-8");
    headers.add_header("Content-Type", "text/plain; charset=iso-8859-1");

    EXPECT_EQ(headers.content_type().type(), "application/json");
    EXPECT_EQ(headers.content_type().charset(), "utf-8");
    EXPECT_EQ(headers.header("Content-Type", 1), "text/plain; charset=iso-8859-1");
}

TEST(HeadersUtility, ReplacingWholeHeaderMapRefreshesContentType) {
    qb::icase_unordered_map<std::vector<std::string>> raw_headers;
    raw_headers["Content-Type"] = {"application/problem+json; charset=utf-16"};

    qb::http::Request request;
    request.with_headers(raw_headers);
    EXPECT_EQ(request.content_type().type(), "application/problem+json");
    EXPECT_EQ(request.content_type().charset(), "utf-16");

    qb::http::Response response;
    response.with_headers(std::move(raw_headers));
    EXPECT_EQ(response.content_type().type(), "application/problem+json");
    EXPECT_EQ(response.content_type().charset(), "utf-16");
}

TEST(HeadersUtility, ContentTypeParsesCaseInsensitiveQuotedCharset) {
    qb::http::Headers headers;

    headers.set_header("Content-Type", " text/html ; Charset=\"UTF-16\"; boundary=abc");

    EXPECT_EQ(headers.content_type().type(), "text/html");
    EXPECT_EQ(headers.content_type().charset(), "UTF-16");
}

TEST(HeadersUtility, HeaderAttributesHandleQuotedPairs) {
    const std::string attrs = R"(name="file"; filename="a\"b\\c.txt")";

    auto parsed = qb::http::parse_header_attributes(attrs);

    ASSERT_NE(parsed.find("filename"), parsed.end());
    EXPECT_EQ(parsed["filename"], "a\"b\\c.txt");
}

TEST(HeadersUtility, HeaderAttributesRejectDanglingQuotedPair) {
    const std::string attrs = R"(filename="abc\)";

    EXPECT_THROW((void) qb::http::parse_header_attributes(attrs), std::runtime_error);
}

TEST(HeadersUtility, HeaderAttributesRejectJunkAfterQuotedValue) {
    const std::string attrs = R"(filename="document.pdf"junk; name=file)";

    EXPECT_THROW((void) qb::http::parse_header_attributes(attrs), std::runtime_error);
}

TEST(HeadersUtility, HeaderAttributesRejectMissingName) {
    const std::string attrs = R"(=document.pdf; name=file)";

    EXPECT_THROW((void) qb::http::parse_header_attributes(attrs), std::runtime_error);
}

TEST(HeadersUtility, HeaderAttributesAllowWhitespaceAfterQuotedValue) {
    const std::string attrs = R"(filename="document.pdf"  ; name=file)";

    const auto parsed = qb::http::parse_header_attributes(attrs);

    ASSERT_NE(parsed.find("filename"), parsed.end());
    EXPECT_EQ(parsed.at("filename"), "document.pdf");
    ASSERT_NE(parsed.find("name"), parsed.end());
    EXPECT_EQ(parsed.at("name"), "file");
}

// RFC 7230 quoted-pair forbids escaping a control character other than HTAB; a
// backslash-CR must not smuggle a CR into the parsed value.
TEST(HeadersUtility, HeaderAttributesRejectEscapedControlChar) {
    std::string attrs = "filename=\"a\\";
    attrs.push_back('\r');
    attrs += "b\"";

    EXPECT_THROW((void) qb::http::parse_header_attributes(attrs), std::runtime_error);
}

// RFC 7230 qdtext excludes control characters (except HTAB); a literal LF inside
// the quoted value must be rejected.
TEST(HeadersUtility, HeaderAttributesRejectLiteralControlCharInQuotes) {
    std::string attrs = "filename=\"a";
    attrs.push_back('\n');
    attrs += "b\"";

    EXPECT_THROW((void) qb::http::parse_header_attributes(attrs), std::runtime_error);
}

// HTAB is a valid quoted-pair character and must be preserved.
TEST(HeadersUtility, HeaderAttributesAllowEscapedTab) {
    std::string attrs = "filename=\"a\\";
    attrs.push_back('\t');
    attrs += "b\"";

    const auto parsed = qb::http::parse_header_attributes(attrs);

    ASSERT_NE(parsed.find("filename"), parsed.end());
    std::string expected = "a";
    expected.push_back('\t');
    expected += "b";
    EXPECT_EQ(parsed.at("filename"), expected);
}

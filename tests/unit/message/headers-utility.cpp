#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include <qbm/http/headers.h>
#include <qbm/http/request.h>
#include <qbm/http/response.h>
#include <qbm/http/utility.h>

namespace {
// Discover the encodings this build actually supports by parsing the codec
// names out of the server-advertised Accept-Encoding string (e.g.
// "gzip;q=1.0, deflate;q=0.9" -> {"gzip", "deflate"}). Returns empty when the
// build has no compression support.
std::vector<std::string>
supported_encodings() {
    std::vector<std::string> out;
    for (const auto &token : qb::http::utility::split_string<std::string>(qb::http::accept_encoding(), ",")) {
        std::string_view name = qb::http::utility::trim_http_whitespace(token);
        const auto       semi = name.find(';');
        if (semi != std::string_view::npos) {
            name = qb::http::utility::trim_http_whitespace(name.substr(0, semi));
        }
        if (!name.empty()) {
            out.emplace_back(name);
        }
    }
    return out;
}
} // namespace

TEST(HeadersUtility, AcceptEncodingDoesNotAdvertiseChunked) {
    const std::string advertised = qb::http::accept_encoding();
    EXPECT_EQ(advertised.find("chunked"), std::string::npos);
    // "identity" is a transfer/content coding the server never advertises as a
    // compression algorithm either.
    EXPECT_EQ(advertised.find("identity"), std::string::npos);
}

// ALWAYS-ON: holds regardless of which codecs (if any) are compiled in. The
// negotiation logic must select nothing for an empty header and for a header
// listing only encodings the server does not support. This guarantees the
// selection path is exercised even on a no-compression build, where the q=0
// branch below is skipped.
TEST(HeadersUtility, ContentEncodingSelectsNothingForUnknownOrEmpty) {
    EXPECT_TRUE(qb::http::content_encoding("").empty());
    EXPECT_TRUE(qb::http::content_encoding("x-no-such-codec").empty());
    EXPECT_TRUE(qb::http::content_encoding("x-no-such-codec, y-also-none;q=1.0").empty());
    // A wildcard with no server-supported encoding still selects nothing on a
    // no-compression build; on a compression build it picks a real codec — pin
    // the build-independent invariant that the result is never an unsupported name.
    const std::string wildcard = qb::http::content_encoding("*");
    if (!wildcard.empty()) {
        const auto sup = supported_encodings();
        EXPECT_NE(std::find(sup.begin(), sup.end(), wildcard), sup.end());
    }
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

// Multi-value negotiation: a positive-q encoding is selected while a q=0 sibling
// in the same list is excluded. Selection follows header order among the
// server-supported, positive-q tokens (the impl returns the FIRST acceptable
// match, NOT the highest q-value), so we pin that deterministic behavior.
TEST(HeadersUtility, ContentEncodingSelectsPositiveQAndSkipsZeroQ) {
    const auto sup = supported_encodings();
    if (sup.size() < 2) {
        GTEST_SKIP() << "Need at least two supported encodings to exercise multi-value ranking.";
    }
    const std::string &a = sup[0];
    const std::string &b = sup[1];

    // a disabled (q=0), b enabled -> b is selected even though a is the server's
    // first preference, because a is explicitly unacceptable.
    EXPECT_EQ(qb::http::content_encoding(a + ";q=0, " + b + ";q=0.9"), b);

    // Both acceptable -> the first in HEADER order wins (header-order priority,
    // not q-value magnitude): b is listed first here so b is chosen despite a's
    // higher q-value.
    EXPECT_EQ(qb::http::content_encoding(b + ";q=0.1, " + a + ";q=0.9"), b);
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

// A bare token (a name without an '=' value) is accepted and stored with an
// empty value — this is how flags like "form-data" in a Content-Disposition or
// "must-revalidate" in Cache-Control are represented.
TEST(HeadersUtility, HeaderAttributesBareTokenGetsEmptyValue) {
    const auto parsed = qb::http::parse_header_attributes(std::string("form-data; name=\"field\"; filename"));

    ASSERT_NE(parsed.find("form-data"), parsed.end());
    EXPECT_EQ(parsed.at("form-data"), "");
    ASSERT_NE(parsed.find("name"), parsed.end());
    EXPECT_EQ(parsed.at("name"), "field");
    // Trailing bare token at end-of-string is also captured with an empty value.
    ASSERT_NE(parsed.find("filename"), parsed.end());
    EXPECT_EQ(parsed.at("filename"), "");
}

// Duplicate attribute names are FIRST-WINS: the parser uses map emplace, which
// does not overwrite an existing key, so the first occurrence's value is kept.
TEST(HeadersUtility, HeaderAttributesDuplicateNameIsFirstWins) {
    const auto parsed = qb::http::parse_header_attributes(std::string("name=first; name=second; name=third"));

    ASSERT_NE(parsed.find("name"), parsed.end());
    EXPECT_EQ(parsed.at("name"), "first");
    // The duplicated key collapses to a single entry holding the first value.
    EXPECT_TRUE(parsed.has("name"));
    EXPECT_EQ(parsed.size(), 1u);
}

// Name matching is case-insensitive (icase map), so a differently-cased
// duplicate also collapses to first-wins.
TEST(HeadersUtility, HeaderAttributesDuplicateNameCaseInsensitiveFirstWins) {
    const auto parsed = qb::http::parse_header_attributes(std::string("Charset=utf-8; charset=utf-16"));

    ASSERT_NE(parsed.find("charset"), parsed.end());
    EXPECT_EQ(parsed.at("charset"), "utf-8");
    EXPECT_TRUE(parsed.has("CHARSET"));
    EXPECT_EQ(parsed.size(), 1u);
}

// A q-value that does not match the strict grammar ("1"/"1.0".."1.000", or
// "0" with up to three fractional digits) is rejected and treated as q=0, which
// makes the encoding unacceptable. Each input below exercises a distinct
// rejection branch of the q-value parser; since the named codec is the only
// candidate, the negotiated result must be empty in every case.
TEST(HeadersUtility, ContentEncodingMalformedQValueDisablesEncoding) {
    const std::string first = qb::http::content_encoding("*");
    if (first.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }

    for (const char *bad_q : {
             "",       // empty q value
             "2",      // leading digit is not '0' (and q > 1)
             "0x",     // two chars, second is not '.'
             "0.5x",   // trailing non-digit in the fraction
             "0.1234", // more than three fractional digits
         }) {
        const std::string header = first + ";q=" + bad_q;
        EXPECT_TRUE(qb::http::content_encoding(header).empty()) << "malformed q=\"" << bad_q << "\" should disable the encoding";
    }
}

// The q parameter need not be the first parameter on a token: the parser must
// skip preceding ';'-delimited parameters to find it, and default to q=1 when no
// q parameter is present at all. Both paths leave the codec acceptable, so it is
// selected.
TEST(HeadersUtility, ContentEncodingFindsQAfterOtherParameters) {
    const std::string first = qb::http::content_encoding("*");
    if (first.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }

    // q follows an unrelated parameter -> parser advances past "v=1" to read it.
    EXPECT_EQ(qb::http::content_encoding(first + ";v=1;q=0.5"), first);
    // Only a non-q parameter is present -> q defaults to 1 (acceptable).
    EXPECT_EQ(qb::http::content_encoding(first + ";level=best"), first);
}

// An empty token between commas has neither a wildcard nor a named codec; it must
// be skipped rather than treated as a match, and a following supported codec still
// wins.
TEST(HeadersUtility, ContentEncodingSkipsEmptyTokens) {
    const std::string first = qb::http::content_encoding("*");
    if (first.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }

    EXPECT_EQ(qb::http::content_encoding(" , " + first), first);
}

// When the attribute section of a Content-Type is malformed (parse_header_attributes
// throws), ContentType::parse must swallow the error and fall back to the default
// charset rather than propagate or leave the charset empty. The media type, parsed
// before the attributes, is still reported.
TEST(HeadersUtility, ContentTypeFallsBackToDefaultCharsetWhenAttributesThrow) {
    // Capture the build's default charset (no attributes -> default) instead of
    // hardcoding the constant.
    qb::http::Headers clean;
    clean.set_header("Content-Type", "text/html");
    const std::string default_charset = clean.content_type().charset();

    // A literal control character inside a quoted attribute value makes the
    // attribute parser throw.
    std::string ct = "text/html; charset=\"a";
    ct.push_back('\n');
    ct += "b\"";

    qb::http::Headers malformed;
    malformed.set_header("Content-Type", ct);

    EXPECT_EQ(malformed.content_type().type(), "text/html");
    EXPECT_EQ(malformed.content_type().charset(), default_charset);
}

// A control character in the attribute NAME (as opposed to the value) is rejected.
TEST(HeadersUtility, HeaderAttributesRejectControlCharInName) {
    std::string attrs;
    attrs.push_back('\x01');
    attrs += "name=value";

    EXPECT_THROW((void) qb::http::parse_header_attributes(attrs), std::runtime_error);
}

// Security/DoS guard: a quoted attribute value exceeding ATTRIBUTE_VALUE_MAX
// (8192) bytes is rejected rather than buffered without bound.
TEST(HeadersUtility, HeaderAttributesRejectOversizedQuotedValue) {
    std::string attrs = "x=\"";
    attrs.append(8193, 'a'); // one past the limit, still inside the open quote

    EXPECT_THROW((void) qb::http::parse_header_attributes(attrs), std::runtime_error);
}

// Same guard on the quoted-pair (escaped) path: the size check fires while
// consuming the escaped character once the value is already at the limit.
TEST(HeadersUtility, HeaderAttributesRejectOversizedEscapedQuotedValue) {
    std::string attrs = "x=\"";
    attrs.append(8192, 'a'); // value now exactly at the limit
    attrs += "\\b";          // escaped char pushes past it

    EXPECT_THROW((void) qb::http::parse_header_attributes(attrs), std::runtime_error);
}

// The raw (pointer,length) overload rejects a null buffer with a non-zero length
// instead of dereferencing it.
TEST(HeadersUtility, HeaderAttributesRejectNullPointerWithLength) {
    EXPECT_THROW((void) qb::http::parse_header_attributes(nullptr, 5), std::runtime_error);
}

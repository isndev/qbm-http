#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef QB_HAS_COMPRESSION
#include <qb/io/compression.h>
#endif
#include <qbm/http/headers.h>
#include <qbm/http/request.h>
#include <qbm/http/response.h>
#include <qbm/http/utility.h>

namespace {
// Discover codecs from the registered factories, independently of the
// content_encoding() selector under test.
std::vector<std::string>
supported_encodings() {
    std::vector<std::string> out;
#ifdef QB_HAS_COMPRESSION
    for (const auto &factory : qb::compression::builtin::get_compress_factories()) {
        if (factory) {
            out.push_back(factory->algorithm());
        }
    }
#endif
    return out;
}

template <typename Fn>
void
expect_runtime_error_containing(Fn &&fn, std::string_view expected) {
    try {
        std::forward<Fn>(fn)();
        FAIL() << "expected std::runtime_error containing: " << expected;
    } catch (const std::runtime_error &e) {
        EXPECT_NE(std::string_view{e.what()}.find(expected), std::string_view::npos) << e.what();
    } catch (...) {
        FAIL() << "expected std::runtime_error containing: " << expected;
    }
}
} // namespace

TEST(HeadersUtility, AcceptEncodingDoesNotAdvertiseChunked) {
    const std::string advertised = qb::http::accept_encoding();
#ifndef QB_HAS_COMPRESSION
    EXPECT_TRUE(advertised.empty());
#endif
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
    // no-compression build; on a compression build it picks the first registered
    // factory. Factory discovery cannot disappear with a selector regression.
    const auto        sup      = supported_encodings();
    const std::string wildcard = qb::http::content_encoding("*");
    EXPECT_EQ(wildcard, sup.empty() ? std::string{} : sup.front());
}

TEST(HeadersUtility, ContentEncodingRespectsQZero) {
    const auto supported = supported_encodings();
    if (supported.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }
    const std::string &first_supported = supported.front();

    const std::string header = first_supported + ";q=0";
    EXPECT_TRUE(qb::http::content_encoding(header).empty());
}

TEST(HeadersUtility, WildcardDoesNotReenableExplicitlyDisabledEncoding) {
    const auto supported = supported_encodings();
    if (supported.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }
    const std::string &first_supported = supported.front();

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

// The typed Content-Type is DERIVED from the raw map on first read: a message filled through the
// raw map -- the HTTP/1.1 parser, a decoder, a bulk edit -- reports the header it carries without
// anyone calling refresh_content_type(), a raw change AFTER a read waits for refresh_content_type()
// (the documented contract), a typed mutator re-derives by itself, and the derivation state travels
// with a copy (Huly QB-506 follow-up).
TEST(HeadersUtility, TypedContentTypeDerivesFromTheRawMapOnFirstRead) {
    qb::http::Headers headers;
    headers.headers()["Content-Type"].push_back("text/plain; charset=iso-8859-1");
    EXPECT_EQ(headers.content_type().type(), "text/plain") << "never refreshed, never read before: derived now";
    EXPECT_EQ(headers.content_type().charset(), "iso-8859-1");

    headers.headers()["Content-Type"].front() = "application/json";
    EXPECT_EQ(headers.content_type().type(), "text/plain") << "a raw change after a read is cached until refresh_content_type()";
    headers.refresh_content_type();
    EXPECT_EQ(headers.content_type().type(), "application/json");
    EXPECT_EQ(headers.content_type().charset(), qb::http::Headers::default_charset);

    headers.headers()["Content-Type"].front() = "image/png";
    const qb::http::Headers copy              = headers;
    EXPECT_EQ(copy.content_type().type(), "application/json") << "the copy's cache is exactly as current as the source's";

    headers.set_content_type("text/html; charset=utf-8");
    EXPECT_EQ(headers.header("Content-Type"), "text/html; charset=utf-8") << "set_content_type writes the raw header";
    EXPECT_EQ(headers.content_type().type(), "text/html") << "a typed mutator re-derives by itself";
    EXPECT_EQ(headers.content_type().charset(), "utf-8");
    headers.add_header("Content-Type", "text/plain");
    EXPECT_EQ(headers.content_type().type(), "text/html") << "the first value decides";
    headers.remove_header(std::string("CONTENT-TYPE"));
    EXPECT_EQ(headers.content_type().type(), qb::http::Headers::default_content_type);
}

// The defaults are not stored per message: a message without a Content-Type, a typeless value and
// a cleared ContentType all report `application/octet-stream` / `utf-8` from one process-wide
// std::string each, so constructing a message allocates nothing for them.
TEST(HeadersUtility, DefaultContentTypeIsOneProcessWideObject) {
    qb::http::Headers a, b;
    EXPECT_EQ(&a.content_type().type(), &b.content_type().type());
    EXPECT_EQ(&a.content_type().charset(), &b.content_type().charset());
    EXPECT_EQ(a.content_type().type(), qb::http::Headers::default_content_type);
    EXPECT_EQ(a.content_type().charset(), qb::http::Headers::default_charset);

    const qb::http::Headers::ContentType typeless{"; charset=utf-16"};
    EXPECT_EQ(&typeless.type(), &a.content_type().type()) << "no type: the default itself, not a copy";
    EXPECT_EQ(typeless.charset(), qb::http::Headers::default_charset) << "no type: the parameters are not read";

    qb::http::Headers::ContentType ct{"text/html; charset=UTF-16"};
    EXPECT_EQ(ct.type(), "text/html");
    EXPECT_EQ(ct.charset(), "UTF-16");
    ct.assign("");
    EXPECT_EQ(&ct.type(), &a.content_type().type());
    EXPECT_EQ(&ct.charset(), &a.content_type().charset());
    ct.assign("application/json; charset=");
    EXPECT_EQ(ct.type(), "application/json");
    EXPECT_EQ(&ct.charset(), &a.content_type().charset()) << "an empty charset keeps the default";

    const auto parsed = qb::http::Headers::ContentType::parse("");
    EXPECT_EQ(parsed.first, qb::http::Headers::default_content_type) << "parse() still returns the defaults by value";
    EXPECT_EQ(parsed.second, qb::http::Headers::default_charset);
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
    const auto supported = supported_encodings();
    if (supported.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }
    const std::string &first = supported.front();

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
    const auto supported = supported_encodings();
    if (supported.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }
    const std::string &first = supported.front();

    // q follows an unrelated parameter -> parser advances past "v=1" to read it.
    EXPECT_EQ(qb::http::content_encoding(first + ";v=1;q=0.5"), first);
    // Only a non-q parameter is present -> q defaults to 1 (acceptable).
    EXPECT_EQ(qb::http::content_encoding(first + ";level=best"), first);
}

// An empty token between commas has neither a wildcard nor a named codec; it must
// be skipped rather than treated as a match, and a following supported codec still
// wins.
TEST(HeadersUtility, ContentEncodingSkipsEmptyTokens) {
    const auto supported = supported_encodings();
    if (supported.empty()) {
        GTEST_SKIP() << "Compression support is not available in this build.";
    }
    const std::string &first = supported.front();

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
    attrs.append(qb::http::ATTRIBUTE_VALUE_MAX + 1u, 'a');
    attrs += '"';

    expect_runtime_error_containing([&] { (void) qb::http::parse_header_attributes(attrs); }, "Quoted attribute value size exceeds");
}

// Same guard on the quoted-pair (escaped) path: the size check fires while
// consuming the escaped character once the value is already at the limit.
TEST(HeadersUtility, HeaderAttributesRejectOversizedEscapedQuotedValue) {
    std::string attrs = "x=\"";
    attrs.append(qb::http::ATTRIBUTE_VALUE_MAX, 'a');
    attrs += "\\b"; // escaped char pushes past it
    attrs += '"';

    expect_runtime_error_containing([&] { (void) qb::http::parse_header_attributes(attrs); }, "Quoted attribute value size exceeds");
}

TEST(HeadersUtility, HeaderAttributesAcceptQuotedValueAtLimit) {
    const std::string value(qb::http::ATTRIBUTE_VALUE_MAX, 'a');
    const auto        parsed = qb::http::parse_header_attributes("x=\"" + value + "\"");
    ASSERT_NE(parsed.find("x"), parsed.end());
    EXPECT_EQ(parsed.at("x"), value);
}

TEST(HeadersUtility, HeaderAttributesRejectUnterminatedQuotedValueBelowLimit) {
    expect_runtime_error_containing([] { (void) qb::http::parse_header_attributes(std::string_view{"x=\"short"}); },
                                    "Unterminated quoted attribute value");
}

// The raw (pointer,length) overload rejects a null buffer with a non-zero length
// instead of dereferencing it.
TEST(HeadersUtility, HeaderAttributesRejectNullPointerWithLength) {
    EXPECT_THROW((void) qb::http::parse_header_attributes(nullptr, 5), std::runtime_error);
}

// RFC 9110 §12.5.3: "*" matches any coding NOT explicitly listed, so a q=0 entry
// excludes its coding from the wildcard wherever it sits in the field. The selector
// walked the tokens in order and collected exclusions only as it met them, so a q=0
// listed AFTER the wildcard came too late and the excluded coding was returned
// (Huly QB-492). Selection order stays the header's (QB-100): among acceptable
// codings the first one listed wins, not the highest q.
TEST(HeadersUtility, WildcardHonoursAnExclusionListedAfterIt) {
    const auto sup = supported_encodings();
    if (sup.empty()) {
        // No codec compiled in: nothing is ever selected, whatever the field says.
        EXPECT_TRUE(qb::http::content_encoding("*, gzip;q=0").empty());
        return;
    }
    // What the wildcard picks on its own: the first registered factory.
    const std::string &a = sup.front();
    ASSERT_EQ(qb::http::content_encoding("*"), a);
    const std::string next = sup.size() > 1 ? sup[1] : std::string{};

    EXPECT_EQ(qb::http::content_encoding("*, " + a + ";q=0"), next) << "q=0 after the wildcard";
    EXPECT_EQ(qb::http::content_encoding("*;q=1, " + a + "; q=0"), next) << "q=0 with OWS before the parameter";

    std::string upper = a;
    std::transform(upper.begin(), upper.end(), upper.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    EXPECT_EQ(qb::http::content_encoding("*, " + upper + ";Q=0"), next) << "the coding and the parameter name are case-insensitive";

    EXPECT_EQ(qb::http::content_encoding("*, " + a + ";q=abc"), next) << "a malformed q excludes, after the wildcard as before it";

    // Controls: the order the existing tests pin is unchanged.
    EXPECT_EQ(qb::http::content_encoding(a + ";q=0, *"), next) << "q=0 before the wildcard";
    EXPECT_EQ(qb::http::content_encoding("*;q=0.8, " + a + ";q=0.5"), a)
        << "a positive q is no exclusion: the wildcard, listed first, still wins";
    EXPECT_EQ(qb::http::content_encoding(a + ";q=0.1, *"), a) << "the explicit coding listed first wins";
}

// QB-279 at the Headers layer: remove_header() must fold the name whatever form it
// arrives in. A `const std::string` lvalue used to select the container's non-folding
// erase and leave the header — and its typed Content-Type cache — in place.
TEST(HeadersUtility, RemoveHeaderFoldsEveryNameForm) {
    const auto filled = [] {
        qb::http::Headers h;
        h.add_header("Content-Length", "5");
        h.add_header("Content-Type", "text/html; charset=utf-16");
        h.add_header("Set-Cookie", "a=1");
        h.add_header("Set-Cookie", "b=2");
        return h;
    };
    const auto expect_removed = [](qb::http::Headers const &h, const char *form) {
        EXPECT_FALSE(h.has_header("content-length")) << form;
        EXPECT_FALSE(h.has_header("CONTENT-TYPE")) << form;
        EXPECT_FALSE(h.has_header("set-cookie")) << form << ": every value of a multi-value header must go";
        EXPECT_EQ(h.header_count(), 0u) << form;
        EXPECT_EQ(h.content_type().type(), qb::http::Headers::default_content_type) << form << ": the typed cache kept a removed header";
        EXPECT_EQ(h.content_type().charset(), qb::http::Headers::default_charset) << form;
    };

    {
        auto              h  = filled();
        const std::string cl = "Content-Length", ct = "Content-Type", sc = "SET-COOKIE";
        h.remove_header(cl);
        h.remove_header(ct);
        h.remove_header(sc);
        expect_removed(h, "const std::string");
    }
    {
        auto        h  = filled();
        std::string cl = "Content-Length", ct = "Content-Type", sc = "SET-COOKIE";
        h.remove_header(cl);
        h.remove_header(ct);
        h.remove_header(sc);
        expect_removed(h, "std::string lvalue");
    }
    {
        auto h = filled();
        h.remove_header(std::string("Content-Length"));
        h.remove_header(std::string("Content-Type"));
        h.remove_header(std::string("SET-COOKIE"));
        expect_removed(h, "std::string rvalue");
    }
    {
        auto h = filled();
        h.remove_header(std::string_view("Content-Length"));
        h.remove_header(std::string_view("Content-Type"));
        h.remove_header(std::string_view("SET-COOKIE"));
        expect_removed(h, "std::string_view");
    }
    {
        auto h = filled();
        h.remove_header("Content-Length");
        h.remove_header("Content-Type");
        h.remove_header("SET-COOKIE");
        expect_removed(h, "string literal");
    }
}

// set_header() used to clear the stored values and only then build the new one from
// its argument, so an argument that aliases a stored value — a view of it, or the
// reference header() returns — was read after its storage was destroyed (Huly QB-490;
// AddressSanitizer reports the heap-use-after-free). The values are longer than any
// small-string buffer so the destroyed storage is a real heap block.
TEST(HeadersUtility, SetHeaderAcceptsAViewOfItsOwnValue) {
    const std::string content_type = "application/vnd.example+json; charset=utf-16; profile=" + std::string(48, 'p');
    const std::string long_value   = "head-" + std::string(40, 'm') + "-middle-" + std::string(40, 'n') + "-tail";

    {
        qb::http::Headers h;
        h.set_header("Content-Type", content_type);
        h.set_header("Content-Type", std::string_view(h.header("Content-Type")));
        EXPECT_EQ(h.header("Content-Type"), content_type) << "a full view of the current value";
        EXPECT_EQ(h.headers().at("content-type").size(), 1u);
        EXPECT_EQ(h.content_type().type(), "application/vnd.example+json");
        EXPECT_EQ(h.content_type().charset(), "utf-16");
    }
    {
        qb::http::Headers h;
        h.set_header("X-Long", long_value);
        h.set_header("X-Long", std::string_view(h.header("X-Long")).substr(5, 48));
        EXPECT_EQ(h.header("X-Long"), long_value.substr(5, 48)) << "a central sub-view of the current value";
        EXPECT_EQ(h.headers().at("x-long").size(), 1u);
    }
    {
        qb::http::Headers h;
        h.set_header("X-Long", long_value);
        h.set_header("X-Long", h.header("X-Long"));
        EXPECT_EQ(h.header("X-Long"), long_value) << "the const reference header() returns";
        EXPECT_EQ(h.headers().at("x-long").size(), 1u);
    }
    {
        qb::http::Headers h;
        h.add_header("X-Multi", long_value);
        h.add_header("X-Multi", content_type);
        h.set_header("X-Multi", h.header("X-Multi", 1));
        EXPECT_EQ(h.header("X-Multi"), content_type) << "a reference to the second of several values";
        EXPECT_EQ(h.headers().at("x-multi").size(), 1u);
    }
    {
        // Control: an independent source.
        qb::http::Headers h;
        h.set_header("Content-Type", "text/plain");
        const std::string independent = content_type;
        h.set_header("Content-Type", independent);
        EXPECT_EQ(h.header("Content-Type"), content_type);
        EXPECT_EQ(h.content_type().charset(), "utf-16");
    }
}

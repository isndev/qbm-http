/**
 * @file unit/utility/utility-codec.cpp
 * @brief Pure-function unit tests for the out-of-line URI/HTML codecs in
 *        qb::http::utility (uri_encode_component / escape_html /
 *        decode_path_component).
 *
 * Split out of the former monolithic test-utility.cpp. These three functions
 * form the percent-encoding / HTML-escaping concern cluster.
 *
 * qb - C++ Actor Framework
 * Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */
#include <gtest/gtest.h>

#include <string>
#include <string_view>

#include <qbm/http/utility.h>

using namespace qb::http;

//////////////////////////////////////////////////
// uri_encode_component
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

TEST(UtilityUriEncode, NulByteEncodesAsPercent00) {
    std::string in("a", 1);
    in.push_back('\0');
    in += "b";
    EXPECT_EQ(utility::uri_encode_component(in), "a%00b");
}

TEST(UtilityUriEncode, EmptyInput) {
    EXPECT_EQ(utility::uri_encode_component(""), "");
}

//////////////////////////////////////////////////
// escape_html
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

TEST(UtilityEscapeHtml, NulAndNonAsciiBytesPassThroughVerbatim) {
    // escape_html only rewrites the five HTML metacharacters; every other byte —
    // including an embedded NUL and high (non-ASCII) bytes — is copied verbatim
    // (length preserved, no truncation at NUL).
    std::string in("a", 1);
    in.push_back('\0');
    in += "<";
    in.push_back(static_cast<char>(0xC3));
    in.push_back(static_cast<char>(0xA9)); // UTF-8 'é'
    in += "&";

    std::string expected("a", 1);
    expected.push_back('\0');
    expected += "&lt;";
    expected.push_back(static_cast<char>(0xC3));
    expected.push_back(static_cast<char>(0xA9));
    expected += "&amp;";

    const std::string out = utility::escape_html(in);
    EXPECT_EQ(out.size(), expected.size());
    EXPECT_EQ(out, expected);
}

//////////////////////////////////////////////////
// decode_path_component
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

// Security-relevant: a percent-escape that decodes to a NUL or other control
// byte must round through verbatim (no truncation, no rejection) so callers can
// see and reject the embedded control rather than have it silently dropped.
TEST(UtilityDecodePath, ControlByteEscapesDecodeToRawBytes) {
    // %00 -> NUL (length preserved through the embedded NUL).
    const std::string nul_decoded = utility::decode_path_component("a%00b");
    ASSERT_EQ(nul_decoded.size(), 3u);
    EXPECT_EQ(nul_decoded[0], 'a');
    EXPECT_EQ(nul_decoded[1], '\0');
    EXPECT_EQ(nul_decoded[2], 'b');

    // %0A -> LF, %0D -> CR, %7F -> DEL.
    EXPECT_EQ(utility::decode_path_component("%0A"), std::string(1, '\n'));
    EXPECT_EQ(utility::decode_path_component("%0D"), std::string(1, '\r'));
    EXPECT_EQ(utility::decode_path_component("%7F"), std::string(1, '\x7F'));
}

//////////////////////////////////////////////////
// encode <-> decode identity over printable ASCII
//////////////////////////////////////////////////

// Property check: for every printable-ASCII byte, encoding then decoding the
// single character recovers it exactly. This cross-validates uri_encode_component
// and decode_path_component against each other (they were never linked before),
// while respecting the one documented asymmetry: '+' is NOT special to either
// function, so it survives identity (it is form-encoding, not path-encoding,
// that maps '+' <-> space).
TEST(UtilityCodec, EncodeThenDecodeIsIdentityOverPrintableAscii) {
    for (int ch = 0x20; ch <= 0x7E; ++ch) {
        const std::string original(1, static_cast<char>(ch));
        const std::string encoded = utility::uri_encode_component(original);
        const std::string decoded = utility::decode_path_component(encoded);
        EXPECT_EQ(decoded, original) << "identity failed for byte 0x" << std::hex << ch;
    }
}

TEST(UtilityCodec, EncodeThenDecodeIsIdentityOverMixedString) {
    const std::string original = "path/to file?a=b&c=d+e~end.";
    const std::string encoded  = utility::uri_encode_component(original);
    // Every reserved char is now percent-escaped; decoding recovers the source.
    EXPECT_EQ(utility::decode_path_component(encoded), original);
}

//////////////////////////////////////////////////
// decode_raw_path_octets (Huly QB-1187)
//////////////////////////////////////////////////

// Of the 256 escapes, in either case of hex digit, exactly those of `[`, `]` and `|` -- the octets a request path holds
// as themselves beyond RFC 3986 -- are decoded, wherever they stand; any other is kept as it was written.
TEST(UtilityDecodeRawPathOctets, DecodesTheEscapesOfTheOctetsABrowserSendsRawAndNoOther) {
    static constexpr char hex_upper[] = "0123456789ABCDEF";
    static constexpr char hex_lower[] = "0123456789abcdef";
    for (int c = 0; c < 256; ++c) {
        const bool raw_in_a_request = c == '[' || c == ']' || c == '|';
        for (const char *hex : {hex_upper, hex_lower}) {
            const std::string escape{'%', hex[c >> 4], hex[c & 0xF]};
            for (std::string const &path : {escape, "/a" + escape + "b", "/" + escape + escape}) {
                std::string out     = "untouched";
                const bool  decoded = utility::decode_raw_path_octets(path, out);
                EXPECT_EQ(decoded, raw_in_a_request) << path;
                if (decoded) {
                    std::string expected = path;
                    for (auto at = expected.find(escape); at != std::string::npos; at = expected.find(escape, at + 1))
                        expected.replace(at, 3, 1, static_cast<char>(c));
                    EXPECT_EQ(out, expected) << path;
                } else {
                    EXPECT_EQ(out, "untouched") << path;
                }
            }
        }
    }
}

// An escape is read as decode_path_component() reads one, left to right: `%25` is a percent sign, so `%257C` holds no
// `%7C`; a `%` without two hex digits after it is a byte, and the escape after it is read. Decoding the result gives
// what decoding the path gives, and the result splits on the same `/` -- `%2F` is kept.
TEST(UtilityDecodeRawPathOctets, ReadsEachEscapeAsThePathDecoderDoes) {
    struct Case {
        std::string_view path;
        bool             decoded;
        std::string_view out;
    };
    for (auto const &c :
         {Case{"/plain/path", false, ""}, Case{"", false, ""}, Case{"%", false, ""}, Case{"%7", false, ""}, Case{"/a%257Cb", false, ""},
          Case{"/a%2F%7Cb", true, "/a%2F|b"}, Case{"/a%%7Cb", true, "/a%|b"}, Case{"/a%7%7C", true, "/a%7|"}, Case{"%7C", true, "|"},
          Case{"/%5B%5d%7c/[x]|", true, "/[]|/[x]|"}, Case{"/a%7Cb%41%2f", true, "/a|b%41%2f"}, Case{"/a%7C%", true, "/a|%"},
          Case{"/%7Z%7C", true, "/%7Z|"}}) {
        std::string out;
        EXPECT_EQ(utility::decode_raw_path_octets(c.path, out), c.decoded) << c.path;
        if (c.decoded) {
            EXPECT_EQ(out, c.out) << c.path;
            EXPECT_EQ(utility::decode_path_component(out), utility::decode_path_component(c.path)) << c.path;
        }
    }
}

/**
 * @file unit/uri/uri-parse.cpp
 * @brief Pure unit tests for the qb::io::uri parser, encoder/decoder and
 *        validation helpers.
 *
 * Split out of the former monolithic tests/test-uri-only.cpp. The three
 * wall-clock `URI_Performance.*` cases were removed (relocated to a
 * google-benchmark harness, see manifest) and the `std::cout` query-dump
 * debug noise was stripped. `WhiteSpaceHandling` is now pinned to the
 * parser's concrete (reject) behavior instead of asserting only no-throw.
 *
 * NOTE (cross-module): `qb::io::uri` is a qb-io type, not qbm-http. This file
 * is parked here for now; the spec flags it for eventual relocation to the
 * qb-io test tree (§6 note in _spec-qbm-http.md). It is therefore included via
 * the absolute <qb/io/uri.h> header, NOT a module-relative "../" include.
 *
 * qb - C++ Actor Framework
 * Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */
#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <qb/io/uri.h>

// ====================================================================
// Basic URI Component Tests
// ====================================================================

TEST(UriComponents, BasicComponents) {
    qb::io::uri uri{"http://username:password@example.com:8080/path/to/resource?query=value&param2=value2#fragment"};

    EXPECT_TRUE(uri.is_valid());
    EXPECT_EQ(uri.scheme(), "http");
    EXPECT_EQ(uri.user_info(), "username:password");
    EXPECT_EQ(uri.host(), "example.com");
    EXPECT_EQ(uri.port(), "8080");
    EXPECT_EQ(uri.u_port(), 8080);
    EXPECT_EQ(uri.path(), "/path/to/resource");
    EXPECT_EQ(uri.encoded_queries(), "query=value&param2=value2");
    EXPECT_EQ(uri.fragment(), "fragment");
    EXPECT_EQ(uri.af(), AF_INET);
}

TEST(UriComponents, DefaultValues) {
    qb::io::uri uri{"http://example.com"};

    EXPECT_EQ(uri.scheme(), "http");
    EXPECT_EQ(uri.user_info(), "");
    EXPECT_EQ(uri.host(), "example.com");
    EXPECT_EQ(uri.port(), "80"); // Default HTTP port
    EXPECT_EQ(uri.u_port(), 80);
    EXPECT_EQ(uri.path(), "/"); // Default path
    EXPECT_EQ(uri.encoded_queries(), "");
    EXPECT_EQ(uri.fragment(), "");
}

TEST(UriComponents, SchemeSpecificDefaults) {
    const std::vector<std::pair<std::string, uint16_t>> scheme_ports = {{"http", 80},   {"https", 443}, {"ftp", 21},   {"ssh", 22},
                                                                        {"telnet", 23}, {"smtp", 25},   {"pop3", 110}, {"imap", 143},
                                                                        {"ws", 80},     {"wss", 443},   {"amqp", 5672}};

    for (const auto &[scheme, port] : scheme_ports) {
        qb::io::uri uri{scheme + "://example.com"};
        EXPECT_EQ(uri.scheme(), scheme);
        EXPECT_EQ(uri.u_port(), port) << "For scheme: " << scheme;
    }
}

// ====================================================================
// IPv4 and IPv6 Address Tests
// ====================================================================

TEST(UriIpAddresses, IPv4Address) {
    qb::io::uri uri{"http://192.168.1.1/path"};

    EXPECT_TRUE(uri.is_valid());
    EXPECT_EQ(uri.host(), "192.168.1.1");
    EXPECT_EQ(uri.af(), AF_INET);
}

TEST(UriIpAddresses, IPv4AddressWithPort) {
    qb::io::uri uri{"http://192.168.1.1:8080/path"};

    EXPECT_EQ(uri.host(), "192.168.1.1");
    EXPECT_EQ(uri.port(), "8080");
    EXPECT_EQ(uri.u_port(), 8080);
    EXPECT_EQ(uri.af(), AF_INET);
}

TEST(UriIpAddresses, IPv6Address) {
    qb::io::uri uri{"http://[2001:db8::1]/path"};

    EXPECT_TRUE(uri.is_valid());
    EXPECT_EQ(uri.host(), "2001:db8::1"); // brackets stripped for host()
    EXPECT_EQ(uri.af(), AF_INET6);
}

TEST(UriIpAddresses, IPv6AddressWithPort) {
    qb::io::uri uri{"http://[2001:db8::1]:8080/path"};

    EXPECT_TRUE(uri.is_valid());
    EXPECT_EQ(uri.host(), "2001:db8::1");
    EXPECT_EQ(uri.port(), "8080");
    EXPECT_EQ(uri.u_port(), 8080);
    EXPECT_EQ(uri.af(), AF_INET6);
}

TEST(UriIpAddresses, IPv6ScopedAddress) {
    // %25 is the URL-encoded '%' used to introduce a zone identifier (RFC 6874).
    qb::io::uri uri{"http://[fe80::1%25eth0]/path"};

    EXPECT_TRUE(uri.is_valid());
    EXPECT_EQ(uri.host(), "fe80::1%25eth0");
    EXPECT_EQ(uri.af(), AF_INET6);
}

// ADDED: a malformed IPv6 authority (unclosed bracket) must be rejected by the
// parser, not silently accepted. The .cpp sets _valid = false and returns.
TEST(UriIpAddresses, MalformedIPv6UnclosedBracketIsInvalid) {
    qb::io::uri uri{"http://[2001:db8::1/path"};

    EXPECT_FALSE(uri.is_valid());
}

// ADDED: a bracketed host followed by a non-digit "port" is rejected.
TEST(UriIpAddresses, MalformedIPv6NonNumericPortIsInvalid) {
    qb::io::uri uri{"http://[2001:db8::1]:80x/path"};

    EXPECT_FALSE(uri.is_valid());
}

TEST(UriIpAddresses, UnixDomainSocket) {
    qb::io::uri uri{"unix:///var/run/socket.sock"};

    EXPECT_EQ(uri.scheme(), "unix");
    EXPECT_EQ(uri.path(), "/var/run/socket.sock");
    EXPECT_EQ(uri.af(), AF_UNIX);
}

// ====================================================================
// Port parsing / overflow
// ====================================================================

// ADDED: u_port() rejects out-of-range ports rather than wrapping. "99999"
// would truncate to 34463 with a naive cast; the impl must return 0.
TEST(UriPort, PortOverflowReturnsZero) {
    qb::io::uri uri{"http://example.com:99999/path"};

    EXPECT_EQ(uri.port(), "99999"); // raw textual port is preserved
    EXPECT_EQ(uri.u_port(), 0u);    // numeric accessor rejects out-of-range
}

// ADDED: the maximum valid port survives; one above it is rejected.
TEST(UriPort, PortBoundaryValues) {
    qb::io::uri max_port{"http://example.com:65535/"};
    EXPECT_EQ(max_port.u_port(), 65535u);

    qb::io::uri over_max{"http://example.com:65536/"};
    EXPECT_EQ(over_max.u_port(), 0u);

    qb::io::uri zero_port{"http://example.com:0/"};
    EXPECT_EQ(zero_port.u_port(), 0u);
}

// ====================================================================
// Query Parameter Tests
// ====================================================================

TEST(UriQueries, BasicQueryParsing) {
    qb::io::uri uri1{"http://example.com/path?param1=value1&param2=value2"};
    EXPECT_EQ(uri1.query("param1"), "value1");
    EXPECT_EQ(uri1.query("param2"), "value2");

    qb::io::uri uri2{"http://example.com/path?empty=&novalue"};
    EXPECT_EQ(uri2.query("empty"), "");
    EXPECT_EQ(uri2.query("novalue"), "");

    qb::io::uri uri3{"http://example.com/path"};
    EXPECT_TRUE(uri3.queries().empty());
    EXPECT_EQ(uri3.query_or("missing", "default"), "default");
}

TEST(UriQueries, CaseInsensitiveAccess) {
    qb::io::uri uri{"http://example.com/path?ParamName=TestValue"};

    EXPECT_EQ(uri.query("ParamName"), "TestValue");
    EXPECT_EQ(uri.query("paramname"), "TestValue");
    EXPECT_EQ(uri.query("PARAMNAME"), "TestValue");
    EXPECT_EQ(uri.query("PaRaMnAmE"), "TestValue");
}

TEST(UriQueries, MultipleValues) {
    qb::io::uri uri{"http://example.com/path?param=value1&param=value2&param=value3"};

    EXPECT_EQ(uri.query("param", 0), "value1");
    EXPECT_EQ(uri.query("param", 1), "value2");
    EXPECT_EQ(uri.query("param", 2), "value3");

    // Out-of-bounds index falls back to the default.
    EXPECT_EQ(uri.query_or("param", "default", 3), "default");
    // query() (no fallback) returns the static empty string out of bounds.
    EXPECT_EQ(uri.query("param", 3), "");

    const auto &queries = uri.queries();
    const auto  it      = queries.find("param");
    ASSERT_NE(it, queries.cend());
    EXPECT_EQ(it->second.size(), 3u);
}

TEST(UriQueries, UrlEncodingDecoding) {
    qb::io::uri uri{"http://example.com/path?encoded=%20%21%40%23%24%25%5E%26%2A%28%29"};
    EXPECT_EQ(uri.query("encoded"), " !@#$%^&*()");

    qb::io::uri uri2{"http://example.com/path?q=space%20value&special=a+b+c&brackets=value%5B%5D"};
    EXPECT_EQ(uri2.query("q"), "space value");
    EXPECT_EQ(uri2.query("special"), "a b c"); // '+' in a query decodes to space
    EXPECT_EQ(uri2.query("brackets"), "value[]");
}

TEST(UriQueries, ComplexQueries) {
    qb::io::uri uri;
    uri = "http://example.com/path?q=search+term&filters[category]=books&filters[price]=10-50&page=1";

    EXPECT_EQ(uri.query("q"), "search term");
    EXPECT_EQ(uri.query("filters[category]"), "books");
    EXPECT_EQ(uri.query("filters[price]"), "10-50");
    EXPECT_EQ(uri.query("page"), "1");
}

TEST(UriQueries, ArrayStyleParameters) {
    qb::io::uri uri;
    uri = "http://example.com/path?ids[]=1&ids[]=2&ids[]=3";

    EXPECT_EQ(uri.query("ids[]", 0), "1");
    EXPECT_EQ(uri.query("ids[]", 1), "2");
    EXPECT_EQ(uri.query("ids[]", 2), "3");

    const auto &queries = uri.queries();
    const auto  it      = queries.find("ids[]");
    ASSERT_NE(it, queries.cend());
    EXPECT_EQ(it->second.size(), 3u);
}

TEST(UriQueries, EscapedDelimiters) {
    qb::io::uri uri{"http://example.com/path?key1=value%26with%3Dspecial&key2=normal"};

    EXPECT_EQ(uri.query("key1"), "value&with=special");
    EXPECT_EQ(uri.query("key2"), "normal");
}

TEST(UriQueries, WeirdEdgeCases) {
    qb::io::uri uri1{"http://example.com/path?=emptykey&=another&novalue="};
    EXPECT_EQ(uri1.query(""), "emptykey");
    EXPECT_EQ(uri1.query("novalue"), "");

    // Multiple '=' signs: the first one is the delimiter, the rest is value.
    qb::io::uri uri2{"http://example.com/path?key=value=with=equals"};
    EXPECT_EQ(uri2.query("key"), "value=with=equals");

    // Stray '&' separators with no key/value are ignored.
    qb::io::uri uri3{"http://example.com/path?&&&key=value&&&"};
    EXPECT_EQ(uri3.query("key"), "value");
}

// ====================================================================
// URI Encoding/Decoding Tests
// ====================================================================

TEST(UriEncoding, BasicEncodingRoundTrip) {
    const std::string original = "Hello World!@#$%^&*()";
    const std::string encoded  = qb::io::uri::encode(original);
    EXPECT_EQ(qb::io::uri::decode(encoded), original);
}

TEST(UriEncoding, SpecialCharactersRoundTrip) {
    const std::string original = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
                                 "abcdefghijklmnopqrstuvwxyz{|}~";
    const std::string encoded  = qb::io::uri::encode(original);
    EXPECT_EQ(qb::io::uri::decode(encoded), original);
}

TEST(UriEncoding, EncodedSequences) {
    EXPECT_EQ(qb::io::uri::decode("%20%3F%26%3D%23"), " ?&=#");
}

TEST(UriEncoding, InvalidSequencesPassThrough) {
    // The decoder must handle malformed % escapes gracefully (leave as-is).
    EXPECT_EQ(qb::io::uri::decode("%2"), "%2");   // incomplete escape
    EXPECT_EQ(qb::io::uri::decode("%XY"), "%XY"); // non-hex digits
}

TEST(UriEncoding, PlusSignDecodesToSpace) {
    EXPECT_EQ(qb::io::uri::decode("a+b+c"), "a b c");
}

// ====================================================================
// Validation helpers
// ====================================================================

TEST(UriValidation, SchemeValidation) {
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("http"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("https"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("ftp"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("file"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("data"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("custom+scheme"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("custom-scheme"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("custom.scheme"));

    EXPECT_FALSE(qb::io::uri::is_valid_scheme(""));
    EXPECT_FALSE(qb::io::uri::is_valid_scheme("0http")); // must start with a letter
    EXPECT_FALSE(qb::io::uri::is_valid_scheme("http:")); // colon not allowed
    EXPECT_FALSE(qb::io::uri::is_valid_scheme("http/")); // slash not allowed
    EXPECT_FALSE(qb::io::uri::is_valid_scheme("http#")); // hash not allowed
}

TEST(UriValidation, HostValidation) {
    EXPECT_TRUE(qb::io::uri::is_valid_host("example.com"));
    EXPECT_TRUE(qb::io::uri::is_valid_host("sub.example.com"));
    EXPECT_TRUE(qb::io::uri::is_valid_host("192.168.1.1"));
    EXPECT_TRUE(qb::io::uri::is_valid_host("[2001:db8::1]"));
    EXPECT_TRUE(qb::io::uri::is_valid_host("localhost"));

    EXPECT_FALSE(qb::io::uri::is_valid_host(""));
    EXPECT_FALSE(qb::io::uri::is_valid_host(" example.com")); // leading space
    EXPECT_FALSE(qb::io::uri::is_valid_host("example.com ")); // trailing space
}

// ====================================================================
// normalize_path: dot-segment resolution + traversal containment
// ====================================================================

TEST(UriNormalizePath, ResolvesDotSegments) {
    std::string path = "/a/b/../c/./d//e";
    EXPECT_TRUE(qb::io::uri::normalize_path(path));
    EXPECT_EQ(path, "/a/c/d/e");
}

TEST(UriNormalizePath, LeadingDotSegments) {
    std::string path = "/./a/../../b/c";
    EXPECT_TRUE(qb::io::uri::normalize_path(path));
    EXPECT_EQ(path, "/b/c");
}

TEST(UriNormalizePath, BackslashesBecomeForwardSlashes) {
    std::string path = "/a\\b\\c";
    EXPECT_TRUE(qb::io::uri::normalize_path(path));
    EXPECT_EQ(path, "/a/b/c");
}

TEST(UriNormalizePath, EmptyBecomesRoot) {
    std::string path;
    EXPECT_TRUE(qb::io::uri::normalize_path(path));
    EXPECT_EQ(path, "/");
}

// ADDED: a directory-traversal attempt on an ABSOLUTE path must be clamped at
// root — the leading ".." segments are discarded, never escaping above "/".
TEST(UriNormalizePath, AbsoluteTraversalClampedAtRoot) {
    std::string path = "/../../../etc/passwd";
    EXPECT_TRUE(qb::io::uri::normalize_path(path));
    EXPECT_EQ(path, "/etc/passwd"); // no leading "../" leaks out

    std::string deep = "/a/b/../../../../c";
    EXPECT_TRUE(qb::io::uri::normalize_path(deep));
    EXPECT_EQ(deep, "/c");

    std::string mixed = "/static/..\\..\\secret";
    EXPECT_TRUE(qb::io::uri::normalize_path(mixed));
    EXPECT_EQ(mixed, "/secret"); // backslash-traversal also contained
}

// ADDED: a RELATIVE path keeps leading ".." (it has no root to clamp against),
// which a caller must reject before using it as a filesystem path.
TEST(UriNormalizePath, RelativeTraversalKeepsLeadingDotDot) {
    std::string path = "a/../../b";
    EXPECT_TRUE(qb::io::uri::normalize_path(path));
    EXPECT_EQ(path, "../b");
}

// ====================================================================
// Edge Cases and Error Handling Tests
// ====================================================================

TEST(UriEdgeCases, EmptyURI) {
    qb::io::uri uri{""};

    EXPECT_EQ(uri.scheme(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.path(), "/");
}

TEST(UriEdgeCases, SchemeOnly) {
    qb::io::uri uri{"http:"};

    EXPECT_EQ(uri.scheme(), "http");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.path(), "/");
}

TEST(UriEdgeCases, AuthorityOnly) {
    qb::io::uri uri{"//example.com"};

    EXPECT_EQ(uri.scheme(), "");
    EXPECT_EQ(uri.host(), "example.com");
    EXPECT_EQ(uri.path(), "/");
}

TEST(UriEdgeCases, PathOnly) {
    qb::io::uri uri{"/path/to/resource"};

    EXPECT_EQ(uri.scheme(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.path(), "/path/to/resource");
}

TEST(UriEdgeCases, QueryOnly) {
    qb::io::uri uri{"?param=value"};

    EXPECT_EQ(uri.scheme(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.path(), "/");
    EXPECT_EQ(uri.query("param"), "value");
}

TEST(UriEdgeCases, FragmentOnly) {
    qb::io::uri uri{"#fragment"};

    EXPECT_EQ(uri.scheme(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.path(), "/");
    EXPECT_EQ(uri.fragment(), "fragment");
}

TEST(UriEdgeCases, CompleteCombinations) {
    qb::io::uri uri1{"http://example.com/path?query=value#fragment"};
    qb::io::uri uri2{"http://example.com/path#fragment"};
    qb::io::uri uri3{"http://example.com?query=value"};
    qb::io::uri uri4{"http://?query=value#fragment"};
    qb::io::uri uri5{"http://#fragment"};

    EXPECT_EQ(uri1.path(), "/path");
    EXPECT_EQ(uri1.query("query"), "value");
    EXPECT_EQ(uri1.fragment(), "fragment");

    EXPECT_EQ(uri2.path(), "/path");
    EXPECT_TRUE(uri2.queries().empty());
    EXPECT_EQ(uri2.fragment(), "fragment");

    EXPECT_EQ(uri3.path(), "/");
    EXPECT_EQ(uri3.query("query"), "value");
    EXPECT_EQ(uri3.fragment(), "");

    EXPECT_EQ(uri4.path(), "/");
    EXPECT_EQ(uri4.query("query"), "value");
    EXPECT_EQ(uri4.fragment(), "fragment");

    EXPECT_EQ(uri5.path(), "/");
    EXPECT_TRUE(uri5.queries().empty());
    EXPECT_EQ(uri5.fragment(), "fragment");
}

// PINNED: the original WhiteSpaceHandling only asserted "no throw" and dumped
// to std::cout. A leading space is not a legal scheme/path character, so the
// parser bails out early (an invalid path character) and marks the URI invalid.
// Pin the deterministic outcome: is_valid() is false, the scheme/host/port are
// left empty, and reading the accessors is still safe (no UB / no crash).
TEST(UriEdgeCases, WhiteSpaceHandlingIsRejected) {
    qb::io::uri uri{" http://example.com/path "};

    EXPECT_FALSE(uri.is_valid());
    EXPECT_EQ(uri.scheme(), ""); // no scheme parsed off the leading space
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.port(), "");

    // Accessors remain callable on a rejected URI (no UB).
    std::string_view scheme;
    std::string_view host;
    std::string_view path;
    EXPECT_NO_THROW({
        scheme = uri.scheme();
        host   = uri.host();
        path   = uri.path();
    });
    (void) scheme;
    (void) host;
    (void) path;
}

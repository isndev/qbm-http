/**
 * @file test-uri-only.cpp
 * @brief Comprehensive test suite for URI handling
 *
 * This file contains an extensive test suite for the URI class functionality:
 * - Parsing all components of URIs (scheme, authority, path, query, fragment)
 * - Support for IPv4 and IPv6 addresses
 * - Query parameter handling with multiple values
 * - URL encoding/decoding with special characters
 * - Edge cases and robustness tests
 * - Performance benchmarks
 *
 * qb - C++ Actor Framework
 * Copyright (C) 2011-2025 isndev (www.qbaf.io). All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <qb/io/uri.h>
#include <chrono>
#include <vector>
#include <algorithm>

// ====================================================================
// Basic URI Component Tests
// ====================================================================

TEST(URI_Components, BasicComponents) {
    // Standard HTTP URL
    qb::io::uri uri{"http://username:password@example.com:8080/path/to/resource?query=value&param2=value2#fragment"};

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

TEST(URI_Components, DefaultValues) {
    // URI with minimal components
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

TEST(URI_Components, SchemeSpecificDefaults) {
    // Test default ports for various schemes
    std::vector<std::pair<std::string, uint16_t> > scheme_ports = {
        {"http", 80},
        {"https", 443},
        {"ftp", 21},
        {"ssh", 22},
        {"telnet", 23},
        {"smtp", 25},
        {"pop3", 110},
        {"imap", 143},
        {"ws", 80},
        {"wss", 443},
        {"amqp", 5672}
    };

    for (const auto &[scheme, port]: scheme_ports) {
        std::string uri_str = scheme + "://example.com";
        qb::io::uri uri{uri_str};

        EXPECT_EQ(uri.scheme(), scheme);
        EXPECT_EQ(uri.u_port(), port) << "For scheme: " << scheme;
    }
}

// ====================================================================
// IPv4 and IPv6 Address Tests
// ====================================================================

TEST(URI_IPAddresses, IPv4Address) {
    qb::io::uri uri{"http://192.168.1.1/path"};

    EXPECT_EQ(uri.host(), "192.168.1.1");
    EXPECT_EQ(uri.af(), AF_INET);
}

TEST(URI_IPAddresses, IPv4AddressWithPort) {
    qb::io::uri uri{"http://192.168.1.1:8080/path"};

    EXPECT_EQ(uri.host(), "192.168.1.1");
    EXPECT_EQ(uri.port(), "8080");
    EXPECT_EQ(uri.u_port(), 8080);
    EXPECT_EQ(uri.af(), AF_INET);
}

TEST(URI_IPAddresses, IPv6Address) {
    qb::io::uri uri{"http://[2001:db8::1]/path"};

    EXPECT_EQ(uri.host(), "2001:db8::1");
    EXPECT_EQ(uri.af(), AF_INET6);
}

TEST(URI_IPAddresses, IPv6AddressWithPort) {
    qb::io::uri uri{"http://[2001:db8::1]:8080/path"};

    EXPECT_EQ(uri.host(), "2001:db8::1");
    EXPECT_EQ(uri.port(), "8080");
    EXPECT_EQ(uri.u_port(), 8080);
    EXPECT_EQ(uri.af(), AF_INET6);
}

TEST(URI_IPAddresses, IPv6ScopedAddress) {
    qb::io::uri uri{"http://[fe80::1%25eth0]/path"};

    // The %25 is the URL-encoded form of '%' which is used for zone identifiers
    EXPECT_EQ(uri.host(), "fe80::1%25eth0");
    EXPECT_EQ(uri.af(), AF_INET6);
}

TEST(URI_IPAddresses, UnixDomainSocket) {
    qb::io::uri uri{"unix:///var/run/socket.sock"};

    EXPECT_EQ(uri.scheme(), "unix");
    EXPECT_EQ(uri.path(), "/var/run/socket.sock");
    EXPECT_EQ(uri.af(), AF_UNIX);
}

// ====================================================================
// Query Parameter Tests
// ====================================================================

TEST(URI_Queries, BasicQueryParsing) {
    // Simple query with single parameters
    qb::io::uri uri1{"http://example.com/path?param1=value1&param2=value2"};
    EXPECT_EQ(uri1.query("param1"), "value1");
    EXPECT_EQ(uri1.query("param2"), "value2");

    // Query with empty parameter values
    qb::io::uri uri2{"http://example.com/path?empty=&novalue"};
    EXPECT_EQ(uri2.query("empty"), "");
    EXPECT_EQ(uri2.query("novalue"), "");

    // Query with no parameters
    qb::io::uri uri3{"http://example.com/path"};
    EXPECT_TRUE(uri3.queries().empty());
    EXPECT_EQ(uri3.query("missing", 0, "default"), "default");
}

TEST(URI_Queries, CaseInsensitiveAccess) {
    qb::io::uri uri{"http://example.com/path?ParamName=TestValue"};

    // Test different casings of the same parameter name
    EXPECT_EQ(uri.query("ParamName"), "TestValue");
    EXPECT_EQ(uri.query("paramname"), "TestValue");
    EXPECT_EQ(uri.query("PARAMNAME"), "TestValue");
    EXPECT_EQ(uri.query("PaRaMnAmE"), "TestValue");
}

TEST(URI_Queries, MultipleValues) {
    qb::io::uri uri{"http://example.com/path?param=value1&param=value2&param=value3"};

    // Verify we can access each value by index
    EXPECT_EQ(uri.query("param", 0), "value1");
    EXPECT_EQ(uri.query("param", 1), "value2");
    EXPECT_EQ(uri.query("param", 2), "value3");

    // Out of bounds index should return the default
    EXPECT_EQ(uri.query("param", 3, "default"), "default");

    // Verify that we have correct count of parameters
    const auto &queries = uri.queries();
    const auto &it = queries.find("param");
    ASSERT_NE(it, queries.cend());
    EXPECT_EQ(it->second.size(), 3);
}

TEST(URI_Queries, UrlEncodingDecoding) {
    // URI with encoded parameters
    qb::io::uri uri{"http://example.com/path?encoded=%20%21%40%23%24%25%5E%26%2A%28%29"};

    // The encoded value should be automatically decoded
    EXPECT_EQ(uri.query("encoded"), " !@#$%^&*()");

    // Test direct encoding and query parameter construction
    std::string param_str = "q=space value&special=a+b+c&brackets=value[]";
    std::string encoded_param_str = qb::io::uri::encode(param_str);

    // Manually construct URI with encoded parameters - should be properly decoded
    qb::io::uri uri2{"http://example.com/path?q=space%20value&special=a+b+c&brackets=value%5B%5D"};

    EXPECT_EQ(uri2.query("q"), "space value");
    EXPECT_EQ(uri2.query("special"), "a b c"); // '+' in URL query is decoded to space
    EXPECT_EQ(uri2.query("brackets"), "value[]");
}

TEST(URI_Queries, ComplexQueries) {
    // Test with complex query parameters - using operator= which is public
    qb::io::uri uri;
    uri = "http://example.com/path?q=search+term&filters[category]=books&filters[price]=10-50&page=1";

    // Print the source URI and the parsed components
    std::cout << "Parsed URI components:" << std::endl;
    std::cout << "  Source: '" << uri.source() << "'" << std::endl;
    std::cout << "  Scheme: '" << uri.scheme() << "'" << std::endl;
    std::cout << "  Host: '" << uri.host() << "'" << std::endl;
    std::cout << "  Path: '" << uri.path() << "'" << std::endl;
    std::cout << "  Raw query: '" << uri.encoded_queries() << "'" << std::endl;

    // Debug all the queries found
    std::cout << "Debug ComplexQueries - Parsed queries:" << std::endl;
    const auto &queries = uri.queries();
    for (const auto &[key, values]: queries) {
        std::cout << "Key: '" << key << "' has " << values.size() << " values: ";
        for (const auto &val: values) {
            std::cout << "'" << val << "', ";
        }
        std::cout << std::endl;
    }

    EXPECT_EQ(uri.query("q"), "search term");
    EXPECT_EQ(uri.query("filters[category]"), "books");
    EXPECT_EQ(uri.query("filters[price]"), "10-50");
    EXPECT_EQ(uri.query("page"), "1");

    // Test with array-style parameters
    qb::io::uri uri2;
    uri2 = "http://example.com/path?ids[]=1&ids[]=2&ids[]=3";

    std::cout << "Source2: '" << uri2.source() << "'" << std::endl;

    // Debug array parameters
    std::cout << "Debug Array Params - Raw: '" << uri2.encoded_queries() << "'" << std::endl;
    const auto &queries2 = uri2.queries();
    for (const auto &[key, values]: queries2) {
        std::cout << "Key: '" << key << "' has " << values.size() << " values: ";
        for (const auto &val: values) {
            std::cout << "'" << val << "', ";
        }
        std::cout << std::endl;
    }

    EXPECT_EQ(uri2.query("ids[]", 0), "1");
    EXPECT_EQ(uri2.query("ids[]", 1), "2");
    EXPECT_EQ(uri2.query("ids[]", 2), "3");
}

TEST(URI_Queries, EscapedDelimiters) {
    // Test handling of escaped delimiters in query parameters
    qb::io::uri uri{"http://example.com/path?key1=value%26with%3Dspecial&key2=normal"};

    EXPECT_EQ(uri.query("key1"), "value&with=special");
    EXPECT_EQ(uri.query("key2"), "normal");
}

TEST(URI_Queries, WeirdEdgeCases) {
    // Test some weird but valid query formats
    qb::io::uri uri1{"http://example.com/path?=emptykey&=another&novalue="};

    // Debug weird cases
    std::cout << "Debug WeirdEdgeCases - Raw: " << uri1.encoded_queries() << std::endl;
    const auto &queries = uri1.queries();
    for (const auto &[key, values]: queries) {
        std::cout << "Key: '" << key << "' has " << values.size() << " values: ";
        for (const auto &val: values) {
            std::cout << "'" << val << "', ";
        }
        std::cout << std::endl;
    }

    EXPECT_EQ(uri1.query(""), "emptykey");
    EXPECT_EQ(uri1.query("novalue"), "");

    // Multiple equal signs - typically the first one is the delimiter
    qb::io::uri uri2{"http://example.com/path?key=value=with=equals"};
    EXPECT_EQ(uri2.query("key"), "value=with=equals");

    // Sequence of & without values
    qb::io::uri uri3{"http://example.com/path?&&&key=value&&&"};
    EXPECT_EQ(uri3.query("key"), "value");
}

// ====================================================================
// URI Encoding/Decoding Tests
// ====================================================================

TEST(URI_Encoding, BasicEncoding) {
    std::string original = "Hello World!@#$%^&*()";
    std::string encoded = qb::io::uri::encode(original);
    std::string decoded = qb::io::uri::decode(encoded);

    EXPECT_EQ(decoded, original);
}

TEST(URI_Encoding, SpecialCharacters) {
    std::string original =
            " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    std::string encoded = qb::io::uri::encode(original);
    std::string decoded = qb::io::uri::decode(encoded);

    EXPECT_EQ(decoded, original);
}

TEST(URI_Encoding, EncodedSequences) {
    // Already encoded sequences should remain as-is
    std::string original = "%20%3F%26%3D%23";
    std::string decoded = qb::io::uri::decode(original);

    EXPECT_EQ(decoded, " ?&=#");
}

TEST(URI_Encoding, InvalidSequences) {
    // Test with invalid % sequences
    std::string invalid1 = "%2"; // Incomplete
    std::string invalid2 = "%XY"; // Not hex digits

    std::string decoded1 = qb::io::uri::decode(invalid1);
    std::string decoded2 = qb::io::uri::decode(invalid2);

    // The parser should handle these gracefully
    EXPECT_EQ(decoded1, "%2");
    EXPECT_EQ(decoded2, "%XY");
}

TEST(URI_Encoding, PlusSign) {
    // Test that + is decoded as a space in queries
    std::string encoded = "a+b+c";
    std::string decoded = qb::io::uri::decode(encoded);

    EXPECT_EQ(decoded, "a b c");
}

// ====================================================================
// URI Validation and Utility Method Tests
// ====================================================================

TEST(URI_Validation, SchemeValidation) {
    // Valid schemes
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("http"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("https"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("ftp"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("file"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("data"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("custom+scheme"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("custom-scheme"));
    EXPECT_TRUE(qb::io::uri::is_valid_scheme("custom.scheme"));

    // Invalid schemes
    EXPECT_FALSE(qb::io::uri::is_valid_scheme(""));
    EXPECT_FALSE(qb::io::uri::is_valid_scheme("0http")); // Must start with a letter
    EXPECT_FALSE(qb::io::uri::is_valid_scheme("http:")); // Cannot contain colon
    EXPECT_FALSE(qb::io::uri::is_valid_scheme("http/")); // Cannot contain slash
    EXPECT_FALSE(qb::io::uri::is_valid_scheme("http#")); // Cannot contain hash
}

TEST(URI_Validation, HostValidation) {
    // Valid hosts
    EXPECT_TRUE(qb::io::uri::is_valid_host("example.com"));
    EXPECT_TRUE(qb::io::uri::is_valid_host("sub.example.com"));
    EXPECT_TRUE(qb::io::uri::is_valid_host("192.168.1.1"));
    EXPECT_TRUE(qb::io::uri::is_valid_host("[2001:db8::1]"));
    EXPECT_TRUE(qb::io::uri::is_valid_host("localhost"));

    // Invalid hosts
    EXPECT_FALSE(qb::io::uri::is_valid_host(""));
    EXPECT_FALSE(qb::io::uri::is_valid_host(" example.com")); // Space not allowed
    EXPECT_FALSE(qb::io::uri::is_valid_host("example.com ")); // Space not allowed
}

TEST(URI_Validation, PathNormalization) {
    // Test path normalization
    std::string path1 = "/a/b/../c/./d//e";
    bool result1 = qb::io::uri::normalize_path(path1);
    EXPECT_TRUE(result1);
    EXPECT_EQ(path1, "/a/c/d/e");

    // Test with dots at the beginning
    std::string path2 = "/./a/../../b/c";
    bool result2 = qb::io::uri::normalize_path(path2);
    EXPECT_TRUE(result2);
    EXPECT_EQ(path2, "/b/c");

    // Test with backslashes
    std::string path3 = "/a\\b\\c";
    bool result3 = qb::io::uri::normalize_path(path3);
    EXPECT_TRUE(result3);
    EXPECT_EQ(path3, "/a/b/c");

    // Test with empty path
    std::string path4 = "";
    bool result4 = qb::io::uri::normalize_path(path4);
    EXPECT_TRUE(result4);
    EXPECT_EQ(path4, "/");
}

// ====================================================================
// Edge Cases and Error Handling Tests
// ====================================================================

TEST(URI_EdgeCases, EmptyURI) {
    qb::io::uri uri{""};

    // An empty URI should still be valid with default values
    EXPECT_EQ(uri.scheme(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.path(), "/");
}

TEST(URI_EdgeCases, SchemeOnly) {
    qb::io::uri uri{"http:"};

    EXPECT_EQ(uri.scheme(), "http");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.path(), "/");
}

TEST(URI_EdgeCases, AuthorityOnly) {
    qb::io::uri uri{"//example.com"};

    EXPECT_EQ(uri.scheme(), "");
    EXPECT_EQ(uri.host(), "example.com");
    EXPECT_EQ(uri.path(), "/");
}

TEST(URI_EdgeCases, PathOnly) {
    qb::io::uri uri{"/path/to/resource"};

    EXPECT_EQ(uri.scheme(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.path(), "/path/to/resource");
}

TEST(URI_EdgeCases, QueryOnly) {
    qb::io::uri uri{"?param=value"};

    EXPECT_EQ(uri.scheme(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.path(), "/");
    EXPECT_EQ(uri.query("param"), "value");
}

TEST(URI_EdgeCases, FragmentOnly) {
    qb::io::uri uri{"#fragment"};

    EXPECT_EQ(uri.scheme(), "");
    EXPECT_EQ(uri.host(), "");
    EXPECT_EQ(uri.path(), "/");
    EXPECT_EQ(uri.fragment(), "fragment");
}

TEST(URI_EdgeCases, CompleteCombinations) {
    // Test various combinations of URI components
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

TEST(URI_EdgeCases, WhiteSpaceHandling) {
    // URIs don't typically have whitespace, but our parser should handle it gracefully
    qb::io::uri uri{" http://example.com/path "};

    // Implementation-dependent - might trim or treat as part of the string
    // Instead of ignoring the return value, verify it doesn't throw and capture the result
    std::string_view scheme;
    std::string_view host;
    std::string_view path;

    EXPECT_NO_THROW({
        scheme = uri.scheme();
        host = uri.host();
        path = uri.path();
        });

    // Additional check that values are accessible, regardless of their exact content
    // Just verifying that we can access these values without crashing
    EXPECT_NO_FATAL_FAILURE({
        std::cout << "Scheme: " << scheme << std::endl;
        std::cout << "Host: " << host << std::endl;
        std::cout << "Path: " << path << std::endl;
        });
}

// ====================================================================
// Performance Benchmarks
// ====================================================================

TEST(URI_Performance, ParseSimpleURI) {
    const int iterations = 10000;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        qb::io::uri uri{"http://example.com/path?param=value#fragment"};
        // Just to make sure the compiler doesn't optimize it away
        EXPECT_FALSE(uri.scheme().empty());
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;

    std::cout << "Simple URI parsing: " << iterations << " iterations in "
            << elapsed.count() << " ms ("
            << (elapsed.count() / iterations) << " ms per parse)" << std::endl;
}

TEST(URI_Performance, ParseComplexURI) {
    const int iterations = 10000;
    std::string complex_uri = "https://username:password@example.com:8080/path/to/resource"
            "?param1=value1&param2=value2&param3=value3&param4=value4"
            "&param5=value5&param6=value6&param7=value7&param8=value8"
            "#section-identifier";

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        qb::io::uri uri{complex_uri};
        // Just to make sure the compiler doesn't optimize it away
        EXPECT_FALSE(uri.scheme().empty());
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;

    std::cout << "Complex URI parsing: " << iterations << " iterations in "
            << elapsed.count() << " ms ("
            << (elapsed.count() / iterations) << " ms per parse)" << std::endl;
}

TEST(URI_Performance, EncodeDecode) {
    const int iterations = 10000;
    std::string test_string = "This is a test string with special characters: !@#$%^&*()_+{}|:<>?~`-=[]\\;',./";

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        std::string encoded = qb::io::uri::encode(test_string);
        std::string decoded = qb::io::uri::decode(encoded);

        // Just to make sure the compiler doesn't optimize it away
        EXPECT_EQ(decoded, test_string);
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;

    std::cout << "Encode/Decode: " << iterations << " iterations in "
            << elapsed.count() << " ms ("
            << (elapsed.count() / iterations) << " ms per operation)" << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

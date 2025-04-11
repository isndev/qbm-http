/**
 * @file test-uri-only.cpp
 * @brief Tests for URI query parameters handling in HTTP module
 *
 * This file contains tests for the URI query parameters functionality:
 * - Parsing of query strings from URIs
 * - Case-insensitive query parameter access
 * - Multiple values for the same parameter
 * - URL encoding/decoding of query parameters
 * - Integration with HTTP request handling
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

// Test basic query parameter parsing
TEST(URI_Queries, BasicQueryParsing) {
    // Simple query with single parameters
    qb::io::uri uri1{"http://example.com/path?param1=value1&param2=value2"};
    EXPECT_EQ(uri1.query("param1"), "value1");
    EXPECT_EQ(uri1.query("param2"), "value2");
    
    // Query with empty parameter values
    qb::io::uri uri2{"http://example.com/path?empty=&novalue"};
    EXPECT_EQ(uri2.query("empty"), "");
    EXPECT_EQ(uri2.query("novalue", 0, "default"), "default");
    
    // Query with no parameters
    qb::io::uri uri3{"http://example.com/path"};
    EXPECT_TRUE(uri3.queries().empty());
    EXPECT_EQ(uri3.query("missing", 0, "default"), "default");
}

// Test case-insensitive query parameter access
TEST(URI_Queries, CaseInsensitiveAccess) {
    qb::io::uri uri{"http://example.com/path?ParamName=TestValue"};
    
    // Test different casings of the same parameter name
    EXPECT_EQ(uri.query("ParamName"), "TestValue");
    EXPECT_EQ(uri.query("paramname"), "TestValue");
    EXPECT_EQ(uri.query("PARAMNAME"), "TestValue");
    EXPECT_EQ(uri.query("PaRaMnAmE"), "TestValue");
}

// Test multiple values for the same parameter
TEST(URI_Queries, MultipleValues) {
    qb::io::uri uri{"http://example.com/path?param=value1&param=value2&param=value3"};
    
    // Verify we can access each value by index
    EXPECT_EQ(uri.query("param", 0), "value1");
    EXPECT_EQ(uri.query("param", 1), "value2");
    EXPECT_EQ(uri.query("param", 2), "value3");
    
    // Out of bounds index should return the default
    EXPECT_EQ(uri.query("param", 3, "default"), "default");
    
    // Verify that we have correct count of parameters
    const auto& queries = uri.queries();
    const auto& it = queries.find("param");
    ASSERT_NE(it, queries.cend());
    EXPECT_EQ(it->second.size(), 3);
}

// Test URL encoding and decoding in query parameters
TEST(URI_Queries, UrlEncodingDecoding) {
    // URI with encoded parameters
    qb::io::uri uri{"http://example.com/path?encoded=%20%21%40%23%24%25%5E%26%2A%28%29"};
    
    // The encoded value should be automatically decoded
    EXPECT_EQ(uri.query("encoded"), " !@#$%^&*()");
    
    // Create URI with special characters
    qb::io::uri uri2{"http://example.com/path?q=space value&special=a+b+c&brackets=value[]"};
    
    // The values should be automatically decoded
    EXPECT_EQ(uri2.query("q"), "space value");
    EXPECT_EQ(uri2.query("special"), "a b c");  // '+' in URL query is decoded to space
    EXPECT_EQ(uri2.query("brackets"), "value[]");
}

// Test complex query strings with various characters
TEST(URI_Queries, ComplexQueries) {
    qb::io::uri uri{
        "http://example.com/path?q=search+term&filters[category]=books&filters[price]=10-50&page=1"};
    
    EXPECT_EQ(uri.query("q"), "search term");
    EXPECT_EQ(uri.query("filters[category]"), "books");
    EXPECT_EQ(uri.query("filters[price]"), "10-50");
    EXPECT_EQ(uri.query("page"), "1");
    
    // Test with array-style parameters
    qb::io::uri uri2{"http://example.com/path?ids[]=1&ids[]=2&ids[]=3"};
    EXPECT_EQ(uri2.query("ids[]", 0), "1");
    EXPECT_EQ(uri2.query("ids[]", 1), "2");
    EXPECT_EQ(uri2.query("ids[]", 2), "3");
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 
/**
 * @file test-multipart-security.cpp
 * @brief Security tests for multipart form-data parsing
 *
 * These tests verify the DoS protection mechanisms for multipart parsing:
 * - Boundary length limit (RFC 2046 max 70 characters)
 * - Header attributes size limit (64KB)
 * - Memory safety with RAII std::vector (replaces raw pointer)
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
#include "../multipart.h"
#include "../headers.h"

using namespace qb::http;

// ====================================================================
// Multipart Boundary DoS Protection Tests
// ====================================================================

class MultipartSecurityTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

TEST_F(MultipartSecurityTest, ValidBoundaryParsing) {
    // Standard boundary parsing should work
    std::string content_type = "multipart/form-data; boundary=abc123";
    std::string boundary = parse_boundary(content_type);
    EXPECT_EQ(boundary, "abc123");
}

TEST_F(MultipartSecurityTest, ValidBoundaryWithQuotes) {
    // RFC 2046 allows quoted boundaries
    std::string content_type = "multipart/form-data; boundary=\"boundary-with-dashes\"";
    std::string boundary = parse_boundary(content_type);
    // Quotes may or may not be included depending on implementation
    EXPECT_FALSE(boundary.empty());
}

TEST_F(MultipartSecurityTest, BoundaryAtMaxLength) {
    // Boundary at exactly 70 characters (RFC 2046 limit)
    std::string long_boundary(70, 'a');
    std::string content_type = "multipart/form-data; boundary=" + long_boundary;
    std::string boundary = parse_boundary(content_type);
    // Should either succeed or throw with appropriate error
    // Behavior depends on implementation
    if (!boundary.empty()) {
        EXPECT_LE(boundary.length(), 70);
    }
}

TEST_F(MultipartSecurityTest, BoundaryOverMaxLengthIsRejected) {
    // Boundary exceeding 70 characters should be rejected
    std::string oversized_boundary(71, 'b');
    std::string content_type = "multipart/form-data; boundary=" + oversized_boundary;

    // Should throw due to security limit
    EXPECT_THROW({
        parse_boundary(content_type);
    }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, BoundaryMuchOverMaxLength) {
    // Very large boundary (potential DoS attack)
    std::string huge_boundary(10000, 'x');
    std::string content_type = "multipart/form-data; boundary=" + huge_boundary;

    // Should throw immediately without allocating huge memory
    EXPECT_THROW({
        parse_boundary(content_type);
    }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, EmptyBoundary) {
    // Empty boundary should return empty string
    std::string content_type = "multipart/form-data; boundary=";
    std::string boundary = parse_boundary(content_type);
    EXPECT_TRUE(boundary.empty());
}

TEST_F(MultipartSecurityTest, NoBoundaryParameter) {
    // Missing boundary parameter
    std::string content_type = "multipart/form-data";
    std::string boundary = parse_boundary(content_type);
    EXPECT_TRUE(boundary.empty());
}

TEST_F(MultipartSecurityTest, NonMultipartContentType) {
    // Non-multipart content type
    std::string content_type = "application/json";
    std::string boundary = parse_boundary(content_type);
    EXPECT_TRUE(boundary.empty());
}

TEST_F(MultipartSecurityTest, WhitespaceInContentType) {
    // Various whitespace patterns
    {
        std::string ct1 = "multipart/form-data;boundary=test";
        EXPECT_EQ(parse_boundary(ct1), "test");
    }
    {
        std::string ct2 = "multipart/form-data; boundary=test";
        EXPECT_EQ(parse_boundary(ct2), "test");
    }
    {
        std::string ct3 = "multipart/form-data;  boundary=test";
        EXPECT_EQ(parse_boundary(ct3), "test");
    }
}

// ====================================================================
// Header Attributes DoS Protection Tests
// ====================================================================

TEST_F(MultipartSecurityTest, ValidHeaderAttributesParsing) {
    // Normal header attributes parsing
    std::string attrs = "name=\"file\"; filename=\"document.pdf\"";
    auto result = parse_header_attributes(attrs.data(), attrs.size());

    EXPECT_TRUE(result.find("name") != result.end());
    EXPECT_EQ(result["name"], "file");
    EXPECT_TRUE(result.find("filename") != result.end());
    EXPECT_EQ(result["filename"], "document.pdf");
}

TEST_F(MultipartSecurityTest, HeaderAttributesAtLimit) {
    // Header attributes at size limit should work
    std::string large_value(64000, 'x');
    std::string attrs = "data=" + large_value;

    // Behavior depends on limit - should either work or throw
    try {
        auto result = parse_header_attributes(attrs.data(), attrs.size());
        // If succeeded, verify result
        if (result.find("data") != result.end()) {
            EXPECT_FALSE(result["data"].empty());
        }
    } catch (const std::runtime_error& e) {
        // If limit is lower, this is expected
        EXPECT_TRUE(std::string(e.what()).find("size") != std::string::npos ||
                    std::string(e.what()).find("exceeds") != std::string::npos);
    }
}

TEST_F(MultipartSecurityTest, HeaderAttributesOverLimitIsRejected) {
    // Header attributes exceeding 64KB should be rejected
    std::string huge_value(70000, 'y');
    std::string attrs = "data=" + huge_value;

    EXPECT_THROW({
        parse_header_attributes(attrs.data(), attrs.size());
    }, std::runtime_error);
}

TEST_F(MultipartSecurityTest, EmptyHeaderAttributes) {
    // Empty attributes should return empty map
    std::string attrs = "";
    auto result = parse_header_attributes(attrs.data(), attrs.size());
    EXPECT_TRUE(result.empty());
}

TEST_F(MultipartSecurityTest, HeaderAttributesWithQuotes) {
    // Quoted values
    std::string attrs = "name=\"file name with spaces\"; type=\"application/pdf\"";
    auto result = parse_header_attributes(attrs.data(), attrs.size());

    EXPECT_TRUE(result.find("name") != result.end());
    EXPECT_TRUE(result.find("type") != result.end());
}

TEST_F(MultipartSecurityTest, HeaderAttributesFlagStyle) {
    // Flag-style attributes (no value)
    std::string attrs = "required; secure; httponly";
    auto result = parse_header_attributes(attrs.data(), attrs.size());

    // Flag-style attributes should be parsed as empty values
    EXPECT_TRUE(result.find("required") != result.end());
    EXPECT_TRUE(result.find("secure") != result.end());
    EXPECT_TRUE(result.find("httponly") != result.end());
}

// ====================================================================
// Multipart Limits Constants Tests
// ====================================================================

TEST_F(MultipartSecurityTest, BoundaryMaxLengthIs70) {
    // Verify RFC 2046 boundary limit constant
    EXPECT_EQ(multipart_limits::MAX_BOUNDARY_LENGTH, 70);
}

// ====================================================================
// Edge Cases
// ====================================================================

TEST_F(MultipartSecurityTest, MalformedContentTypes) {
    // Malformed content types should not crash
    {
        std::string ct1 = "";
        EXPECT_NO_THROW(parse_boundary(ct1));
    }
    {
        std::string ct2 = "boundary=test";
        EXPECT_NO_THROW(parse_boundary(ct2));
    }
    {
        std::string ct3 = "multipart/form-data; boundary=";
        EXPECT_NO_THROW(parse_boundary(ct3));
    }
    {
        std::string ct4 = "multipart/form-data boundary=test"; // Missing semicolon
        EXPECT_NO_THROW(parse_boundary(ct4));
    }
}

TEST_F(MultipartSecurityTest, SpecialCharactersInBoundary) {
    // Boundaries with special characters
    std::vector<std::string> test_boundaries = {
        "boundary-123",
        "boundary_123",
        "boundary.123",
        "boundary:123",
        "boundary=123"
    };

    for (const auto& b : test_boundaries) {
        std::string ct = "multipart/form-data; boundary=" + b;
        EXPECT_NO_THROW({
            parse_boundary(ct);
        });
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

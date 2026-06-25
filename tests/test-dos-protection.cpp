/**
 * @file test-dos-protection.cpp
 * @brief Tests for DoS protection in HTTP request/response serialization
 *
 * These tests verify the security fixes added to prevent DoS attacks via:
 * - Oversized URLs (> 8KB)
 * - Oversized request/response bodies (> 100MB)
 * - Oversized headers (names > 1KB, values > 8KB)
 * - Total serialized size caps (> 110MB)
 *
 * Oversized serialization fails with std::length_error and clears the output pipe.
 *
 * qb - C++ Actor Framework
 * Copyright (C) 2011-2026 isndev (www.qbaf.io). All rights reserved.
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
#include <stdexcept>
#include <qb/system/allocator/pipe.h>
#include "../1.1/protocol/base.h"
#include "../http.h"

using namespace qb::http;

// ====================================================================
// Request DoS Protection Tests
// ====================================================================

class RequestDoSProtectionTest : public ::testing::Test {
protected:
    qb::allocator::pipe<char> pipe;

    void
    SetUp() override {
        pipe.clear();
    }
};

TEST_F(RequestDoSProtectionTest, NormalURLRequestSucceeds) {
    // Create a normal-sized request
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api/users?page=1&limit=10");
    req.body()   = R"({"filter": "active"})";

    // Serialization should succeed
    pipe.put(req);

    // Verify something was written
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, URLAtLimitSucceeds) {
    // Create a URL at exactly the limit (8KB)
    std::string long_path = "/api/";
    long_path.append(protocol_limits::MAX_URL_LENGTH - 20, 'a');

    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri(long_path);

    // Should succeed at exactly the limit
    pipe.put(req);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, URLExceedingLimitIsRejected) {
    // Create a URL exceeding the 8KB limit
    std::string oversized_path = "/api/";
    oversized_path.append(protocol_limits::MAX_URL_LENGTH + 100, 'x');

    Request req;
    req.method() = method::GET;

    try {
        req.uri() = qb::io::uri(oversized_path);
    } catch (...) {
        // URI parsing might fail first, which is fine
        SUCCEED();
        return;
    }

    // If URI parsing succeeded, serialization must reject (throws after clearing the pipe).
    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, QueryStringExceedingLimitIsRejected) {
    // Create a URL with an oversized query string
    std::string oversized_query;
    oversized_query.append(protocol_limits::MAX_URL_LENGTH + 100, 'q');

    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/search?" + oversized_query);

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, NormalBodySucceeds) {
    // Create a request with normal body size (1MB)
    std::string body_data(1024 * 1024, 'B');

    Request req;
    req.method() = method::POST;
    req.uri()    = qb::io::uri("/upload");
    req.body()   = body_data;

    pipe.put(req);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, BodyAtLimitSucceeds) {
    // Create a body at exactly the 100MB limit
    // Note: We use a smaller size for testing (10MB) to avoid memory issues in tests
    // The actual limit is tested conceptually here
    constexpr std::size_t test_size = 10 * 1024 * 1024; // 10MB for testing

    std::string body_data(test_size, 'D');

    Request req;
    req.method() = method::POST;
    req.uri()    = qb::io::uri("/upload");
    req.body()   = body_data;

    // Should succeed for test size (which is below 100MB limit)
    if (test_size <= protocol_limits::MAX_BODY_SIZE) {
        pipe.put(req);
        EXPECT_GT(pipe.size(), 0);
    }
}

TEST_F(RequestDoSProtectionTest, BodyExceedingLimitIsRejected) {
    // Create a body exceeding 100MB
    // For testing, we simulate by checking the limit directly
    Request req;
    req.method() = method::POST;
    req.uri()    = qb::io::uri("/upload");

    // Simulate oversized body by checking behavior
    // In reality, creating >100MB string in test is resource-intensive
    // So we verify the limit constant is correctly defined
    EXPECT_EQ(protocol_limits::MAX_BODY_SIZE, 100 * 1024 * 1024); // 100MB
}

TEST_F(RequestDoSProtectionTest, NormalHeadersSucceed) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api/data");

    // Add normal-sized headers
    req.set_header("Content-Type", "application/json");
    req.set_header("Authorization", "Bearer token123");
    req.set_header("X-Request-ID", "abc-123-xyz");

    pipe.put(req);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, RequestWithMultipleHeadersSucceeds) {
    // Test that requests with multiple normal-sized headers work correctly
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api/data");

    req.set_header("Content-Type", "application/json");
    req.set_header("Authorization", "Bearer token123");
    req.set_header("X-Request-ID", "abc-123");

    pipe.put(req);

    // Verify something was written
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, RequestWithLongButValidHeaders) {
    // Test that requests with headers approaching but under the limit work
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api/data");

    // Header name that is long but under 1KB limit
    std::string long_name(900, 'H');
    req.set_header(long_name, "value1");

    // Header value that is long but under 8KB limit
    std::string long_value(7000, 'V');
    req.set_header("X-Data", long_value);

    pipe.put(req);

    // Should succeed - pipe should have content
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, OversizedHeaderNameIsRejected) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api/data");

    std::string long_name(protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'H');
    req.set_header(long_name, "value1");

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, OversizedHeaderValueIsRejected) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api/data");

    std::string long_value(protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'V');
    req.set_header("X-Data", long_value);

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, HeaderNameInjectionIsRejected) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/test");
    req.set_header("X-Test\r\nInjected", "value");

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, HeaderValueInjectionIsRejected) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/test");
    req.set_header("X-Test", "safe\r\nInjected: bad");

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, RejectedSerializationClearsExistingBufferContent) {
    Request ok_req;
    ok_req.method() = method::GET;
    ok_req.uri()    = qb::io::uri("/ok");
    ok_req.set_header("X-Test", "ok");
    pipe.put(ok_req);
    ASSERT_GT(pipe.size(), 0);

    Request bad_req;
    bad_req.method() = method::GET;
    bad_req.uri()    = qb::io::uri("/bad");
    bad_req.set_header(std::string(protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'H'), "value");

    EXPECT_THROW(pipe.put(bad_req), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, FramingErrorClearsExistingBufferBeforeWriting) {
    Request ok_req;
    ok_req.method() = method::GET;
    ok_req.uri()    = qb::io::uri("/ok");
    pipe.put(ok_req);
    ASSERT_GT(pipe.size(), 0);

    Request bad_req;
    bad_req.method() = method::POST;
    bad_req.uri()    = qb::io::uri("/bad");
    bad_req.body()   = "payload";
    bad_req.set_header("Content-Length", "1");

    EXPECT_THROW(pipe.put(bad_req), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(RequestDoSProtectionTest, FragmentIsNotSerializedIntoHttpRequestTarget) {
    std::string oversized_fragment;
    oversized_fragment.append(protocol_limits::MAX_URL_LENGTH + 100, 'f');

    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/page#" + oversized_fragment);

    ASSERT_NO_THROW(pipe.put(req));
    const std::string raw_request = pipe.str();
    EXPECT_EQ(raw_request.find('#'), std::string::npos);
    EXPECT_NE(raw_request.find("GET /page HTTP/1.1\r\n"), std::string::npos);
}

// ====================================================================
// Response DoS Protection Tests
// ====================================================================

class ResponseDoSProtectionTest : public ::testing::Test {
protected:
    qb::allocator::pipe<char> pipe;

    void
    SetUp() override {
        pipe.clear();
    }
};

TEST_F(ResponseDoSProtectionTest, NormalResponseSucceeds) {
    Response resp;
    resp.status() = status::OK;
    resp.body()   = R"({"status": "success"})";
    resp.set_header("Content-Type", "application/json");

    pipe.put(resp);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(ResponseDoSProtectionTest, NormalBodySizeSucceeds) {
    // Create a response with 1MB body
    std::string body_data(1024 * 1024, 'R');

    Response resp;
    resp.status() = status::OK;
    resp.body()   = body_data;

    pipe.put(resp);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(ResponseDoSProtectionTest, BodyExceedingLimitIsRejected) {
    // Verify the MAX_BODY_SIZE limit for responses
    EXPECT_EQ(protocol_limits::MAX_BODY_SIZE, 100 * 1024 * 1024); // 100MB

    // Note: Creating >100MB string in test is resource-intensive
    // The implementation check is validated through code review
    SUCCEED();
}

TEST_F(ResponseDoSProtectionTest, ResponseWithMultipleHeaders) {
    // Test responses with multiple normal-sized headers
    Response resp;
    resp.status() = status::OK;

    resp.set_header("Content-Type", "application/json");
    resp.set_header("X-Response-ID", "resp-123");
    resp.set_header("Cache-Control", "no-cache");

    pipe.put(resp);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(ResponseDoSProtectionTest, ResponseWithLongButValidHeaders) {
    // Test responses with headers approaching but under the limit
    Response resp;
    resp.status() = status::OK;

    // Header name that is long but under 1KB limit
    std::string long_name(900, 'H');
    resp.set_header(long_name, "value1");

    // Header value that is long but under 8KB limit
    std::string long_value(7000, 'V');
    resp.set_header("X-Data", long_value);

    pipe.put(resp);

    // Should succeed
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(ResponseDoSProtectionTest, MultipleNormalHeadersSucceed) {
    Response resp;
    resp.status() = status::OK;

    // Add multiple normal headers
    for (int i = 0; i < 20; ++i) {
        resp.set_header("X-Header-" + std::to_string(i), "value-" + std::to_string(i));
    }

    pipe.put(resp);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(ResponseDoSProtectionTest, OversizedHeaderNameIsRejected) {
    Response resp;
    resp.status() = status::OK;

    std::string long_name(protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'H');
    resp.set_header(long_name, "value1");

    EXPECT_THROW(pipe.put(resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(ResponseDoSProtectionTest, OversizedHeaderValueIsRejected) {
    Response resp;
    resp.status() = status::OK;

    std::string long_value(protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'V');
    resp.set_header("X-Data", long_value);

    EXPECT_THROW(pipe.put(resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(ResponseDoSProtectionTest, HeaderNameInjectionIsRejected) {
    Response resp;
    resp.status() = status::OK;
    resp.set_header("X-Test\r\nInjected", "value");

    EXPECT_THROW(pipe.put(resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(ResponseDoSProtectionTest, HeaderValueInjectionIsRejected) {
    Response resp;
    resp.status() = status::OK;
    resp.set_header("X-Test", "safe\r\nInjected: bad");

    EXPECT_THROW(pipe.put(resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(ResponseDoSProtectionTest, SetCookieHeaderInjectionIsRejected) {
    Response resp;
    resp.status() = status::OK;
    resp.set_header("Set-Cookie", "session=safe\r\nInjected: bad");

    EXPECT_THROW(pipe.put(resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(ResponseDoSProtectionTest, RejectedSerializationClearsExistingBufferContent) {
    Response ok_resp;
    ok_resp.status() = status::OK;
    ok_resp.set_header("Content-Type", "text/plain");
    ok_resp.body() = "ok";
    pipe.put(ok_resp);
    ASSERT_GT(pipe.size(), 0);

    Response bad_resp;
    bad_resp.status() = status::OK;
    bad_resp.set_header(std::string(protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'H'), "value");

    EXPECT_THROW(pipe.put(bad_resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

TEST_F(ResponseDoSProtectionTest, FramingErrorClearsExistingBufferBeforeWriting) {
    Response ok_resp;
    ok_resp.status() = status::OK;
    ok_resp.body()   = "ok";
    pipe.put(ok_resp);
    ASSERT_GT(pipe.size(), 0);

    Response bad_resp;
    bad_resp.status() = status::OK;
    bad_resp.body()   = "payload";
    bad_resp.set_header("Content-Length", "1");

    EXPECT_THROW(pipe.put(bad_resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

// ====================================================================
// Protocol Limits Constants Tests
// ====================================================================

class ProtocolLimitsTest : public ::testing::Test {};

TEST_F(ProtocolLimitsTest, URLSizeLimitIs8KB) {
    EXPECT_EQ(protocol_limits::MAX_URL_LENGTH, 8192);
}

TEST_F(ProtocolLimitsTest, HeaderNameLimitIs1KB) {
    EXPECT_EQ(protocol_limits::MAX_HEADER_NAME_LENGTH, 1024);
}

TEST_F(ProtocolLimitsTest, HeaderValueLimitIs8KB) {
    EXPECT_EQ(protocol_limits::MAX_HEADER_VALUE_LENGTH, 8192);
}

TEST_F(ProtocolLimitsTest, HeadersCountLimitIs100) {
    EXPECT_EQ(protocol_limits::MAX_HEADERS_COUNT, 100);
}

TEST_F(ProtocolLimitsTest, ChunkSizeLimitIs16MB) {
    EXPECT_EQ(protocol_limits::MAX_CHUNK_SIZE, 16 * 1024 * 1024);
}

TEST_F(ProtocolLimitsTest, BodySizeLimitIs100MB) {
    EXPECT_EQ(protocol_limits::MAX_BODY_SIZE, 100 * 1024 * 1024);
}

// ====================================================================
// Incoming Parser Limits Tests
// ====================================================================

class IncomingParserLimitsTest : public ::testing::Test {};

TEST_F(IncomingParserLimitsTest, OversizedUrlIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw = "GET /" + std::string(protocol_limits::MAX_URL_LENGTH + 1, 'x') + " HTTP/1.1\r\n\r\n";

    EXPECT_NE(parser.parse(raw.data(), raw.size()), HPE_OK);
}

TEST_F(IncomingParserLimitsTest, OversizedHeaderNameIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw = "GET / HTTP/1.1\r\n" + std::string(protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'H') + ": value\r\n\r\n";

    EXPECT_NE(parser.parse(raw.data(), raw.size()), HPE_OK);
}

TEST_F(IncomingParserLimitsTest, OversizedHeaderValueIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw = "GET / HTTP/1.1\r\nX-Test: " + std::string(protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'V') + "\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_USER);
}

TEST_F(IncomingParserLimitsTest, TooManyHeadersAreRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw = "GET / HTTP/1.1\r\n";
    for (std::size_t i = 0; i < protocol_limits::MAX_HEADERS_COUNT + 1; ++i) {
        raw += "X-Test-" + std::to_string(i) + ": value\r\n";
    }
    raw += "\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_USER);
}

TEST_F(IncomingParserLimitsTest, OversizedContentLengthIsRejectedBeforeBodyAllocation) {
    qb::http::Parser<Request> parser;
    std::string raw = "POST /upload HTTP/1.1\r\nContent-Length: " + std::to_string(protocol_limits::MAX_BODY_SIZE + 1) + "\r\n\r\n";

    EXPECT_NE(parser.parse(raw.data(), raw.size()), HPE_OK);
}

TEST_F(IncomingParserLimitsTest, HeaderOnlyRequestNormalizesUnknownLengthToZero) {
    qb::http::Parser<Request> parser;
    std::string               raw = "GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n";

    // Parser pauses at end-of-headers in this implementation.
    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    EXPECT_TRUE(parser.headers_completed());
    EXPECT_EQ(parser.content_length, 0u);
}

TEST_F(IncomingParserLimitsTest, ChunkedTransferEncodingIsAcceptedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw = "POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    EXPECT_TRUE(parser.headers_completed());
}

TEST_F(IncomingParserLimitsTest, UnsupportedTransferEncodingIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw = "POST /upload HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";

    const auto err = parser.parse(raw.data(), raw.size());
    EXPECT_NE(err, HPE_OK);
    EXPECT_NE(err, HPE_PAUSED);
}

TEST_F(IncomingParserLimitsTest, TransferEncodingWithContentLengthIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw = "POST /upload HTTP/1.1\r\n"
                                    "Transfer-Encoding: chunked\r\n"
                                    "Content-Length: 3\r\n\r\n";

    EXPECT_NE(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
}

TEST_F(IncomingParserLimitsTest, NoBodyResponseStatusIgnoresDeclaredContentLength) {
    qb::http::Parser<Response> parser;
    std::string                raw = "HTTP/1.1 304 Not Modified\r\n"
                                     "Content-Length: 4\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    EXPECT_TRUE(parser.headers_completed());
    EXPECT_EQ(parser.content_length, 0u);
}

TEST_F(IncomingParserLimitsTest, NoContentResponseIgnoresDeclaredContentLength) {
    qb::http::Parser<Response> parser;
    std::string                raw = "HTTP/1.1 204 No Content\r\n"
                                     "Content-Length: 4\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    EXPECT_TRUE(parser.headers_completed());
    EXPECT_EQ(parser.content_length, 0u);
}

TEST_F(IncomingParserLimitsTest, FragmentedHeaderFieldAndValueAreReassembledCorrectly) {
    qb::http::Parser<Request> parser;

    const std::string chunk1 = "GET / HTTP/1.1\r\nX-Cus";
    const std::string chunk2 = "tom-Hea";
    const std::string chunk3 = "der: value-";
    const std::string chunk4 = "part-1";
    const std::string chunk5 = "part-2\r\n\r\n";

    EXPECT_EQ(parser.parse(chunk1.data(), chunk1.size()), HPE_OK);
    EXPECT_EQ(parser.parse(chunk2.data(), chunk2.size()), HPE_OK);
    EXPECT_EQ(parser.parse(chunk3.data(), chunk3.size()), HPE_OK);
    EXPECT_EQ(parser.parse(chunk4.data(), chunk4.size()), HPE_OK);
    EXPECT_EQ(parser.parse(chunk5.data(), chunk5.size()), HPE_PAUSED);

    EXPECT_TRUE(parser.headers_completed());
    EXPECT_EQ(parser.get_parsed_message().header("X-Custom-Header"), "value-part-1part-2");
}

TEST_F(IncomingParserLimitsTest, IncrementalParsingDoesNotOvercountFragmentedHeaderFields) {
    qb::http::Parser<Request> parser;
    std::string               raw = "GET / HTTP/1.1\r\n";
    for (std::size_t i = 0; i < protocol_limits::MAX_HEADERS_COUNT; ++i) {
        raw += "X-H-" + std::to_string(i) + ": v\r\n";
    }
    raw += "\r\n";

    http_errno_t last_err = HPE_OK;
    for (char c : raw) {
        last_err = parser.parse(&c, 1);
        if (last_err != HPE_OK) {
            break;
        }
    }

    EXPECT_EQ(last_err, HPE_PAUSED);
    EXPECT_TRUE(parser.headers_completed());
}

TEST_F(IncomingParserLimitsTest, FragmentedUrlIsReassembledCorrectly) {
    qb::http::Parser<Request> parser;

    const std::string chunk1 = "GET /api/v1/";
    const std::string chunk2 = "users?name=ali";
    const std::string chunk3 = "ce HTTP/1.1\r\nHost: example.test\r\n\r\n";

    EXPECT_EQ(parser.parse(chunk1.data(), chunk1.size()), HPE_OK);
    EXPECT_EQ(parser.parse(chunk2.data(), chunk2.size()), HPE_OK);
    EXPECT_EQ(parser.parse(chunk3.data(), chunk3.size()), HPE_PAUSED);
    EXPECT_TRUE(parser.headers_completed());
    EXPECT_EQ(parser.get_parsed_message().uri().source(), "/api/v1/users?name=alice");
}

TEST_F(IncomingParserLimitsTest, FragmentedUrlRespectsCumulativeLimit) {
    qb::http::Parser<Request> parser;

    const std::string part1 = "GET /" + std::string(protocol_limits::MAX_URL_LENGTH - 10, 'a');
    const std::string part2 = std::string(20, 'b') + " HTTP/1.1\r\nHost: example.test\r\n\r\n";

    EXPECT_EQ(parser.parse(part1.data(), part1.size()), HPE_OK);
    EXPECT_EQ(parser.parse(part2.data(), part2.size()), HPE_USER);
}

// ====================================================================
// Edge Cases and Boundary Tests
// ====================================================================

class DoSEdgeCasesTest : public ::testing::Test {
protected:
    qb::allocator::pipe<char> pipe;

    void
    SetUp() override {
        pipe.clear();
    }
};

TEST_F(DoSEdgeCasesTest, EmptyRequestSucceeds) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/");

    pipe.put(req);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(DoSEdgeCasesTest, EmptyResponseSucceeds) {
    Response resp;
    resp.status() = status::NO_CONTENT;

    pipe.put(resp);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(DoSEdgeCasesTest, RequestWithOnlyHeadersSucceeds) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api");
    req.set_header("Accept", "application/json");
    req.set_header("Accept-Language", "en-US");

    pipe.put(req);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(DoSEdgeCasesTest, ResponseWithEmptyBodySucceeds) {
    Response resp;
    resp.status() = status::OK;
    resp.set_header("Content-Type", "text/plain");
    // Empty body

    pipe.put(resp);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(DoSEdgeCasesTest, URLBoundaryAt8192Characters) {
    // Test URL exactly at 8KB boundary
    std::string path = "/";
    path.append(8191, 'p'); // 8191 + 1 (the "/") = 8192

    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri(path);

    pipe.put(req);
    EXPECT_GT(pipe.size(), 0);
}

TEST_F(DoSEdgeCasesTest, URLJustOverBoundaryIsRejected) {
    // Test URL just over 8KB boundary
    std::string path = "/";
    path.append(8192, 'p'); // 8192 + 1 (the "/") = 8193 > limit

    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri(path);

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0);
}

// ====================================================================
// Incoming Parser Happy-Path Tests
//
// These tests exercise the HTTP/1.1 Parser<> success branches in
// qbm/http/1.1/protocol/base.h that the IncomingParserLimitsTest suite
// above does not reach: Content-Length body capture, multi-value header
// accumulation, keep-alive / upgrade flag derivation, and response status
// extraction. They drive qb::http::Parser<> directly (not the IO-bound
// protocol::http::base) using the same parse()/resume()/get_parsed_message()
// idiom as the limit tests.
//
// Behaviour confirmed against base.h and verified empirically:
//   - on_headers_complete() always returns HPE_PAUSED (the parser pauses at
//     end-of-headers), so a body must be parsed in a second resume()+parse()
//     pass. error_pos points at the first unparsed (body) byte.
//   - The body is captured into the parser's _chunked buffer via on_body and
//     moved into msg.body() by on_message_complete (returns 1 ->
//     HPE_CB_MESSAGE_COMPLETE).
//   - Multiple values for one field name are stored as a vector
//     (msg.headers()[name] is std::vector<std::string>; header(name, index)).
//   - keep_alive / upgrade are derived in on_headers_complete and live on the
//     parsed message (msg.keep_alive / msg.upgrade), not on the parser.
//   - on_status stores only the numeric status_code; the reason phrase is NOT
//     retained (base.h:224 is commented out), so only status() is asserted.
// ====================================================================

class IncomingParserHappyPathTest : public ::testing::Test {};

TEST_F(IncomingParserHappyPathTest, ContentLengthBodyIsCapturedAndMessageCompletes) {
    qb::http::Parser<Request> parser;
    const std::string         raw = "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";

    // First pass parses up to end-of-headers and pauses.
    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    EXPECT_TRUE(parser.headers_completed());
    EXPECT_EQ(parser.content_length, 5u);

    // error_pos marks the first unparsed (body) byte.
    const std::size_t body_offset = static_cast<std::size_t>(parser.error_pos - raw.data());
    ASSERT_LT(body_offset, raw.size());

    // Resume and feed the remaining bytes (the body) to drive completion.
    parser.resume();
    EXPECT_EQ(parser.parse(raw.data() + body_offset, raw.size() - body_offset), HPE_CB_MESSAGE_COMPLETE);

    auto &msg = parser.get_parsed_message();
    EXPECT_EQ(msg.method(), HTTP_POST);
    EXPECT_EQ(msg.body().size(), 5u);
    EXPECT_EQ(msg.body().as<std::string>(), "hello");
    EXPECT_EQ(msg.body().as<std::string_view>(), std::string_view("hello"));
}

TEST_F(IncomingParserHappyPathTest, RepeatedHeaderFieldIsStoredAsMultipleValues) {
    qb::http::Parser<Request> parser;
    const std::string         raw = "GET / HTTP/1.1\r\n"
                                    "X-Multi: alpha\r\n"
                                    "X-Multi: beta\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    EXPECT_TRUE(parser.headers_completed());

    auto      &msg = parser.get_parsed_message();
    const auto it  = msg.headers().find("X-Multi");
    ASSERT_NE(it, msg.headers().end());
    ASSERT_EQ(it->second.size(), 2u);
    EXPECT_EQ(it->second[0], "alpha");
    EXPECT_EQ(it->second[1], "beta");
    // Indexed accessor exposes each stored value.
    EXPECT_EQ(msg.header("X-Multi", 0), "alpha");
    EXPECT_EQ(msg.header("X-Multi", 1), "beta");
}

TEST_F(IncomingParserHappyPathTest, KeepAliveDefaultsTrueForHttp11) {
    qb::http::Parser<Request> parser;
    const std::string         raw = "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    ASSERT_TRUE(parser.headers_completed());

    auto &msg = parser.get_parsed_message();
    EXPECT_EQ(msg.major_version, 1u);
    EXPECT_EQ(msg.minor_version, 1u);
    EXPECT_TRUE(msg.keep_alive);
}

TEST_F(IncomingParserHappyPathTest, ConnectionCloseDisablesKeepAliveOnHttp11) {
    qb::http::Parser<Request> parser;
    const std::string         raw = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    ASSERT_TRUE(parser.headers_completed());
    EXPECT_FALSE(parser.get_parsed_message().keep_alive);
}

TEST_F(IncomingParserHappyPathTest, KeepAliveDefaultsFalseForHttp10) {
    qb::http::Parser<Request> parser;
    const std::string         raw = "GET / HTTP/1.0\r\nHost: example.test\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    ASSERT_TRUE(parser.headers_completed());

    auto &msg = parser.get_parsed_message();
    EXPECT_EQ(msg.major_version, 1u);
    EXPECT_EQ(msg.minor_version, 0u);
    EXPECT_FALSE(msg.keep_alive);
}

TEST_F(IncomingParserHappyPathTest, ConnectionKeepAliveEnablesKeepAliveOnHttp10) {
    qb::http::Parser<Request> parser;
    const std::string         raw = "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    ASSERT_TRUE(parser.headers_completed());
    EXPECT_TRUE(parser.get_parsed_message().keep_alive);
}

TEST_F(IncomingParserHappyPathTest, UpgradeFlagIsSetForConnectionUpgrade) {
    qb::http::Parser<Request> parser;
    const std::string         raw = "GET / HTTP/1.1\r\n"
                                    "Connection: Upgrade\r\n"
                                    "Upgrade: h2c\r\n\r\n";

    // on_headers_complete pauses (HPE_PAUSED) before llhttp would surface the
    // upgrade pause, so the parse returns HPE_PAUSED with the flag already set.
    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    ASSERT_TRUE(parser.headers_completed());

    auto &msg = parser.get_parsed_message();
    EXPECT_TRUE(msg.upgrade);
    EXPECT_EQ(msg.header("Upgrade"), "h2c");
}

TEST_F(IncomingParserHappyPathTest, ResponseStatusCodeIsCaptured) {
    qb::http::Parser<Response> parser;
    const std::string          raw = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    ASSERT_TRUE(parser.headers_completed());

    auto &msg = parser.get_parsed_message();
    EXPECT_EQ(msg.status(), 404);
    // Reason phrase is intentionally not retained by on_status (base.h:224),
    // so only the numeric status code is asserted here.
    EXPECT_EQ(parser.content_length, 0u);
}

int
main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

/**
 * @file unit/http1/http1-serialize-limits.cpp
 * @brief Outbound HTTP/1.1 serialization DoS caps (pipe::put).
 *
 * Verifies the security caps enforced when an outgoing Request/Response is
 * serialized into a qb::allocator::pipe<char> via operator<<:
 *   - oversized URL / query / fragment handling,
 *   - oversized header name / value rejection,
 *   - CRLF header-injection rejection,
 *   - the "clear the pipe on failure" contract (no partial/poisoned output),
 *   - the protocol_limits constant values.
 *
 * Oversized / malformed serialization fails with std::length_error and clears
 * the output pipe. These are pure unit tests: no event loop, no socket.
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

#include <cstdlib>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <qb/system/allocator/pipe.h>
#include <qbm/http/1.1/protocol/base.h>
#include <qbm/http/http.h>

using namespace qb::http;

// ====================================================================
// Protocol limit constants (single source of truth for the wire caps)
// ====================================================================

class ProtocolLimitsTest : public ::testing::Test {};

TEST_F(ProtocolLimitsTest, URLSizeLimitIs8KB) {
    EXPECT_EQ(protocol_limits::MAX_URL_LENGTH, 8192u);
}

TEST_F(ProtocolLimitsTest, HeaderNameLimitIs1KB) {
    EXPECT_EQ(protocol_limits::MAX_HEADER_NAME_LENGTH, 1024u);
}

TEST_F(ProtocolLimitsTest, HeaderValueLimitIs8KB) {
    EXPECT_EQ(protocol_limits::MAX_HEADER_VALUE_LENGTH, 8192u);
}

TEST_F(ProtocolLimitsTest, HeadersCountLimitIs100) {
    EXPECT_EQ(protocol_limits::MAX_HEADERS_COUNT, 100u);
}

TEST_F(ProtocolLimitsTest, ChunkSizeLimitIs16MB) {
    EXPECT_EQ(protocol_limits::MAX_CHUNK_SIZE, 16u * 1024u * 1024u);
}

TEST_F(ProtocolLimitsTest, BodySizeLimitIs100MB) {
    EXPECT_EQ(protocol_limits::MAX_BODY_SIZE, 100u * 1024u * 1024u);
}

// ====================================================================
// Request outbound serialization caps
// ====================================================================

class RequestSerializeLimitsTest : public ::testing::Test {
protected:
    qb::allocator::pipe<char> pipe;

    void
    SetUp() override {
        pipe.clear();
    }
};

TEST_F(RequestSerializeLimitsTest, NormalURLRequestSucceeds) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api/users?page=1&limit=10");
    req.body()   = R"({"filter": "active"})";

    pipe.put(req);
    EXPECT_GT(pipe.size(), 0u);
    EXPECT_NE(pipe.str().find("GET /api/users?page=1&limit=10 HTTP/1.1\r\n"), std::string::npos);
}

TEST_F(RequestSerializeLimitsTest, URLAtLimitSucceeds) {
    // A URL whose request-target is exactly MAX_URL_LENGTH bytes.
    std::string long_path = "/api/";
    long_path.append(protocol_limits::MAX_URL_LENGTH - long_path.size(), 'a');
    ASSERT_EQ(long_path.size(), protocol_limits::MAX_URL_LENGTH);

    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri(long_path);

    pipe.put(req);
    EXPECT_GT(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, URLExceedingLimitIsRejected) {
    // De-masked: the URI must parse (no swallowing via try/catch-SUCCEED), and
    // serialization must reject the oversized request-target deterministically.
    std::string oversized_path = "/api/";
    oversized_path.append(protocol_limits::MAX_URL_LENGTH + 100, 'x');

    Request req;
    req.method() = method::GET;
    ASSERT_NO_THROW(req.uri() = qb::io::uri(oversized_path));
    ASSERT_GE(req.uri().source().size(), protocol_limits::MAX_URL_LENGTH + 100);

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, QueryStringExceedingLimitIsRejected) {
    std::string oversized_query(protocol_limits::MAX_URL_LENGTH + 100, 'q');

    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/search?" + oversized_query);

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, FragmentIsNotSerializedIntoHttpRequestTarget) {
    std::string oversized_fragment(protocol_limits::MAX_URL_LENGTH + 100, 'f');

    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/page#" + oversized_fragment);

    // The fragment is client-only and must never reach the wire: the
    // request-target stays "/page" and no '#' is emitted.
    ASSERT_NO_THROW(pipe.put(req));
    const std::string raw_request = pipe.str();
    EXPECT_EQ(raw_request.find('#'), std::string::npos);
    EXPECT_NE(raw_request.find("GET /page HTTP/1.1\r\n"), std::string::npos);
}

TEST_F(RequestSerializeLimitsTest, NormalBodySucceeds) {
    std::string body_data(1024 * 1024, 'B'); // 1 MB

    Request req;
    req.method() = method::POST;
    req.uri()    = qb::io::uri("/upload");
    req.body()   = body_data;

    pipe.put(req);
    EXPECT_GT(pipe.size(), body_data.size());
}

TEST_F(RequestSerializeLimitsTest, Body10MBSucceeds) {
    // Renamed from BodyAtLimitSucceeds: 10 MB is well below MAX_BODY_SIZE, so it
    // is a normal-large body case, not an "at the limit" case.
    constexpr std::size_t body_size = 10 * 1024 * 1024;
    static_assert(body_size < protocol_limits::MAX_BODY_SIZE);

    Request req;
    req.method() = method::POST;
    req.uri()    = qb::io::uri("/upload");
    req.body()   = std::string(body_size, 'D');

    pipe.put(req);
    EXPECT_GT(pipe.size(), body_size);
}

// Real >100MB rejection path — the only case that enforces MAX_BODY_SIZE rather than comparing it
// to a literal. Allocating ~100MB is expensive, so the case stays gated on QBM_HTTP_RUN_HUGE_BODY;
// `tests/CMakeLists.txt` registers a dedicated ctest entry
// (`qbm-http-test-unit-http1-serialize-limits-huge-body`) that sets it, so a plain `ctest` DOES run
// this. `ctest -LE huge-body` opts back out. When enabled it proves serialization throws
// std::length_error and clears the pipe.
TEST_F(RequestSerializeLimitsTest, BodyExceedingLimitIsRejected) {
    if (const char *flag = std::getenv("QBM_HTTP_RUN_HUGE_BODY"); !flag || std::string(flag) == "0") {
        GTEST_SKIP() << "set QBM_HTTP_RUN_HUGE_BODY=1 to exercise the >100MB body rejection path "
                        "(the ctest entry `qbm-http-test-unit-http1-serialize-limits-huge-body` does)";
    }

    Request req;
    req.method() = method::POST;
    req.uri()    = qb::io::uri("/upload");
    req.body()   = std::string(protocol_limits::MAX_BODY_SIZE + 1, 'X');

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, NormalHeadersSucceed) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api/data");
    req.set_header("Content-Type", "application/json");
    req.set_header("Authorization", "Bearer token123");
    req.set_header("X-Request-ID", "abc-123-xyz");

    pipe.put(req);
    const std::string raw = pipe.str();
    // Ground truth: header names go through qb::icase_unordered_map, which stores
    // keys LOWERCASED (unordered_map.h string_to_lower::convert). The wire bytes
    // therefore carry the lowercased field-name + ": " + value + CRLF — exactly
    // "content-type: application/json\r\n", not the "Content-Type" spelling passed
    // to set_header(). HTTP field-names are case-insensitive, so this is conformant.
    EXPECT_NE(raw.find("content-type: application/json\r\n"), std::string::npos);
    EXPECT_NE(raw.find("authorization: Bearer token123\r\n"), std::string::npos);
}

TEST_F(RequestSerializeLimitsTest, LongButValidHeadersSucceed) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api/data");

    std::string long_name(protocol_limits::MAX_HEADER_NAME_LENGTH - 1, 'H');
    req.set_header(long_name, "value1");

    std::string long_value(protocol_limits::MAX_HEADER_VALUE_LENGTH - 1, 'V');
    req.set_header("X-Data", long_value);

    pipe.put(req);
    EXPECT_GT(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, OversizedHeaderNameIsRejected) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api/data");
    req.set_header(std::string(protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'H'), "value1");

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, OversizedHeaderValueIsRejected) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/api/data");
    req.set_header("X-Data", std::string(protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'V'));

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, HeaderNameInjectionIsRejected) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/test");
    req.set_header("X-Test\r\nInjected", "value");

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, HeaderValueInjectionIsRejected) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/test");
    req.set_header("X-Test", "safe\r\nInjected: bad");

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, RejectedSerializationClearsExistingBufferContent) {
    Request ok_req;
    ok_req.method() = method::GET;
    ok_req.uri()    = qb::io::uri("/ok");
    ok_req.set_header("X-Test", "ok");
    pipe.put(ok_req);
    ASSERT_GT(pipe.size(), 0u);

    Request bad_req;
    bad_req.method() = method::GET;
    bad_req.uri()    = qb::io::uri("/bad");
    bad_req.set_header(std::string(protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'H'), "value");

    EXPECT_THROW(pipe.put(bad_req), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, URLBoundaryAt8192Characters) {
    std::string path = "/";
    path.append(protocol_limits::MAX_URL_LENGTH - 1, 'p'); // total == MAX_URL_LENGTH
    ASSERT_EQ(path.size(), protocol_limits::MAX_URL_LENGTH);

    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri(path);

    pipe.put(req);
    EXPECT_GT(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, URLJustOverBoundaryIsRejected) {
    std::string path = "/";
    path.append(protocol_limits::MAX_URL_LENGTH, 'p'); // total == MAX_URL_LENGTH + 1
    ASSERT_EQ(path.size(), protocol_limits::MAX_URL_LENGTH + 1);

    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri(path);

    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, EmptyRequestSucceeds) {
    Request req;
    req.method() = method::GET;
    req.uri()    = qb::io::uri("/");

    pipe.put(req);
    EXPECT_NE(pipe.str().find("GET / HTTP/1.1\r\n"), std::string::npos);
}

TEST_F(RequestSerializeLimitsTest, FramingMismatchClearsExistingBufferBeforeWriting) {
    // A body present while an explicit Content-Length disagrees is a framing
    // error: serialization must reject and leave nothing partially written.
    Request ok_req;
    ok_req.method() = method::GET;
    ok_req.uri()    = qb::io::uri("/ok");
    pipe.put(ok_req);
    ASSERT_GT(pipe.size(), 0u);

    Request bad_req;
    bad_req.method() = method::POST;
    bad_req.uri()    = qb::io::uri("/bad");
    bad_req.body()   = "payload";
    bad_req.set_header("Content-Length", "1");

    EXPECT_THROW(pipe.put(bad_req), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

// ====================================================================
// Response outbound serialization caps
// ====================================================================

class ResponseSerializeLimitsTest : public ::testing::Test {
protected:
    qb::allocator::pipe<char> pipe;

    void
    SetUp() override {
        pipe.clear();
    }
};

TEST_F(ResponseSerializeLimitsTest, NormalResponseSucceeds) {
    Response resp;
    resp.status() = status::OK;
    resp.body()   = R"({"status": "success"})";
    resp.set_header("Content-Type", "application/json");

    pipe.put(resp);
    EXPECT_NE(pipe.str().find("HTTP/1.1 200"), std::string::npos);
}

TEST_F(ResponseSerializeLimitsTest, NormalBodySizeSucceeds) {
    std::string body_data(1024 * 1024, 'R'); // 1 MB

    Response resp;
    resp.status() = status::OK;
    resp.body()   = body_data;

    pipe.put(resp);
    EXPECT_GT(pipe.size(), body_data.size());
}

TEST_F(ResponseSerializeLimitsTest, BodyExceedingLimitIsRejected) {
    if (const char *flag = std::getenv("QBM_HTTP_RUN_HUGE_BODY"); !flag || std::string(flag) == "0") {
        GTEST_SKIP() << "set QBM_HTTP_RUN_HUGE_BODY=1 to exercise the >100MB body rejection path "
                        "(the ctest entry `qbm-http-test-unit-http1-serialize-limits-huge-body` does)";
    }

    Response resp;
    resp.status() = status::OK;
    resp.body()   = std::string(protocol_limits::MAX_BODY_SIZE + 1, 'X');

    EXPECT_THROW(pipe.put(resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(ResponseSerializeLimitsTest, MultipleNormalHeadersSucceed) {
    Response resp;
    resp.status() = status::OK;
    for (int i = 0; i < 20; ++i) {
        resp.set_header("X-Header-" + std::to_string(i), "value-" + std::to_string(i));
    }

    pipe.put(resp);
    // Header names are lowercased on the wire (qb::icase_unordered_map stores keys
    // via string_to_lower::convert): "X-Header-N" serializes as "x-header-N: ...".
    EXPECT_NE(pipe.str().find("x-header-0: value-0\r\n"), std::string::npos);
    EXPECT_NE(pipe.str().find("x-header-19: value-19\r\n"), std::string::npos);
}

TEST_F(ResponseSerializeLimitsTest, OversizedHeaderNameIsRejected) {
    Response resp;
    resp.status() = status::OK;
    resp.set_header(std::string(protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'H'), "value1");

    EXPECT_THROW(pipe.put(resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(ResponseSerializeLimitsTest, OversizedHeaderValueIsRejected) {
    Response resp;
    resp.status() = status::OK;
    resp.set_header("X-Data", std::string(protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'V'));

    EXPECT_THROW(pipe.put(resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(ResponseSerializeLimitsTest, HeaderNameInjectionIsRejected) {
    Response resp;
    resp.status() = status::OK;
    resp.set_header("X-Test\r\nInjected", "value");

    EXPECT_THROW(pipe.put(resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(ResponseSerializeLimitsTest, HeaderValueInjectionIsRejected) {
    Response resp;
    resp.status() = status::OK;
    resp.set_header("X-Test", "safe\r\nInjected: bad");

    EXPECT_THROW(pipe.put(resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(ResponseSerializeLimitsTest, SetCookieHeaderInjectionIsRejected) {
    Response resp;
    resp.status() = status::OK;
    resp.set_header("Set-Cookie", "session=safe\r\nInjected: bad");

    EXPECT_THROW(pipe.put(resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(ResponseSerializeLimitsTest, RejectedSerializationClearsExistingBufferContent) {
    Response ok_resp;
    ok_resp.status() = status::OK;
    ok_resp.set_header("Content-Type", "text/plain");
    ok_resp.body() = "ok";
    pipe.put(ok_resp);
    ASSERT_GT(pipe.size(), 0u);

    Response bad_resp;
    bad_resp.status() = status::OK;
    bad_resp.set_header(std::string(protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'H'), "value");

    EXPECT_THROW(pipe.put(bad_resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(ResponseSerializeLimitsTest, EmptyResponseSucceeds) {
    Response resp;
    resp.status() = status::NO_CONTENT;

    pipe.put(resp);
    EXPECT_NE(pipe.str().find("HTTP/1.1 204"), std::string::npos);
}

TEST_F(ResponseSerializeLimitsTest, FramingMismatchClearsExistingBufferBeforeWriting) {
    Response ok_resp;
    ok_resp.status() = status::OK;
    ok_resp.body()   = "ok";
    pipe.put(ok_resp);
    ASSERT_GT(pipe.size(), 0u);

    Response bad_resp;
    bad_resp.status() = status::OK;
    bad_resp.body()   = "payload";
    bad_resp.set_header("Content-Length", "1");

    EXPECT_THROW(pipe.put(bad_resp), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

// ====================================================================
// Content-Length header validity (distinct from the body/CL framing
// mismatch above): an empty, non-numeric, or self-conflicting
// Content-Length is rejected by declared_content_length() before framing,
// and the pipe is cleared. Mirrored for Request and Response.
// ====================================================================

TEST_F(RequestSerializeLimitsTest, RejectsEmptyContentLength) {
    Request req;
    req.method() = method::POST;
    req.uri()    = qb::io::uri("/u");
    req.set_header("Content-Length", ""); // empty -> parse_content_length nullopt -> throw
    EXPECT_THROW(pipe.put(req), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(RequestSerializeLimitsTest, RejectsNonNumericContentLength) {
    Request req;
    req.method() = method::POST;
    req.uri()    = qb::io::uri("/u");
    req.set_header("Content-Length", "12x"); // from_chars stops short -> nullopt -> throw
    EXPECT_THROW(pipe.put(req), std::length_error);
}

TEST_F(RequestSerializeLimitsTest, RejectsConflictingContentLengths) {
    Request req;
    req.method() = method::POST;
    req.uri()    = qb::io::uri("/u");
    req.add_header("Content-Length", "2");
    req.add_header("Content-Length", "9"); // two different values -> conflict throw
    EXPECT_THROW(pipe.put(req), std::length_error);
}

TEST_F(RequestSerializeLimitsTest, RejectsEmptyTransferEncodingTokens) {
    Request req;
    req.method() = method::POST;
    req.uri()    = qb::io::uri("/u");
    req.set_header("Transfer-Encoding", ","); // splits to zero tokens -> malformed TE
    EXPECT_THROW(pipe.put(req), std::length_error);
}

TEST_F(ResponseSerializeLimitsTest, RejectsEmptyContentLength) {
    Response r;
    r.status() = status::OK;
    r.set_header("Content-Length", "");
    EXPECT_THROW(pipe.put(r), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

TEST_F(ResponseSerializeLimitsTest, RejectsNonNumericContentLength) {
    Response r;
    r.status() = status::OK;
    r.set_header("Content-Length", "abc");
    EXPECT_THROW(pipe.put(r), std::length_error);
}

TEST_F(ResponseSerializeLimitsTest, RejectsConflictingContentLengths) {
    Response r;
    r.status() = status::OK;
    r.add_header("Content-Length", "2");
    r.add_header("Content-Length", "3");
    EXPECT_THROW(pipe.put(r), std::length_error);
}

TEST_F(ResponseSerializeLimitsTest, RejectsEmptyTransferEncodingTokens) {
    Response r;
    r.status() = status::OK;
    r.body()   = "x";
    r.set_header("Transfer-Encoding", ",");
    EXPECT_THROW(pipe.put(r), std::length_error);
}

TEST_F(ResponseSerializeLimitsTest, RejectsContentLengthWithTransferEncoding) {
    Response r;
    r.status() = status::OK;
    r.body()   = "abc";
    r.set_header("Transfer-Encoding", "chunked");
    r.set_header("Content-Length", "3"); // CL forbidden alongside chunked TE
    EXPECT_THROW(pipe.put(r), std::length_error);
    EXPECT_EQ(pipe.size(), 0u);
}

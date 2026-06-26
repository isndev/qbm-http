/**
 * @file unit/http1/http1-parse-limits.cpp
 * @brief Inbound HTTP/1.1 Parser<> DoS limits, framing, and happy-path branches.
 *
 * Drives qb::http::Parser<Request>/Parser<Response> directly (no IO loop, no
 * socket) to verify:
 *   - inbound size caps (URL / header name / header value / header count /
 *     Content-Length / chunk size),
 *   - Transfer-Encoding vs Content-Length framing rules,
 *   - no-body status handling (204 / 304),
 *   - incremental / fragmented parsing correctness (URL + header reassembly,
 *     no double-counting of split header fields),
 *   - success branches: Content-Length body capture, repeated-header vectors,
 *     keep-alive / upgrade flag derivation, response status capture.
 *
 * Parser pause semantics confirmed against 1.1/protocol/base.h:
 *   - on_headers_complete() returns HPE_PAUSED (the parser pauses at
 *     end-of-headers); a body must be parsed in a second resume()+parse() pass.
 *   - error_pos points at the first unparsed (body) byte.
 *   - on_body accumulates into _chunked; on_message_complete moves it into
 *     msg.body() and returns 1 -> HPE_CB_MESSAGE_COMPLETE.
 *   - repeated field names are stored as a vector; header(name, index) indexes it.
 *   - keep_alive / upgrade are derived in on_headers_complete and live on the
 *     parsed message.
 *   - on_status keeps only the numeric status_code (reason phrase is not retained).
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
#include <cstddef>
#include <cstdio>
#include <string>
#include <string_view>
#include "../1.1/protocol/base.h"
#include "../http.h"

using namespace qb::http;

// ====================================================================
// Inbound parser limits
// ====================================================================

class IncomingParserLimitsTest : public ::testing::Test {};

TEST_F(IncomingParserLimitsTest, OversizedUrlIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string raw = "GET /" + std::string(protocol_limits::MAX_URL_LENGTH + 1, 'x') + " HTTP/1.1\r\n\r\n";

    EXPECT_NE(parser.parse(raw.data(), raw.size()), HPE_OK);
}

TEST_F(IncomingParserLimitsTest, OversizedHeaderNameIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string raw = "GET / HTTP/1.1\r\n" + std::string(protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'H') + ": value\r\n\r\n";

    EXPECT_NE(parser.parse(raw.data(), raw.size()), HPE_OK);
}

TEST_F(IncomingParserLimitsTest, OversizedHeaderValueIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string raw = "GET / HTTP/1.1\r\nX-Test: " + std::string(protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'V') + "\r\n\r\n";

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

// MAX_CHUNK_SIZE parse-path: a single chunked-transfer chunk larger than the
// configured limit is rejected by on_body before it can accumulate. Allocating
// >16MB once is acceptable for a unit run; the chunk is fed in one buffer so a
// single on_body call sees length > MAX_CHUNK_SIZE.
TEST_F(IncomingParserLimitsTest, OversizedChunkIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;

    const std::string headers = "POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    ASSERT_EQ(parser.parse(headers.data(), headers.size()), HPE_PAUSED);
    ASSERT_TRUE(parser.headers_completed());

    const std::size_t chunk_len = protocol_limits::MAX_CHUNK_SIZE + 1;
    std::string       chunk_size_line;
    {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%zx\r\n", chunk_len); // hex chunk-size
        chunk_size_line = buf;
    }
    std::string chunk = chunk_size_line + std::string(chunk_len, 'Z') + "\r\n0\r\n\r\n";

    parser.resume();
    EXPECT_NE(parser.parse(chunk.data(), chunk.size()), HPE_OK);
}

TEST_F(IncomingParserLimitsTest, HeaderOnlyRequestNormalizesUnknownLengthToZero) {
    qb::http::Parser<Request> parser;
    std::string               raw = "GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    EXPECT_TRUE(parser.headers_completed());
    EXPECT_EQ(parser.content_length, 0u);
}

// ====================================================================
// Transfer-Encoding / Content-Length framing
// ====================================================================

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

// ====================================================================
// Incremental / fragmented parsing
// ====================================================================

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
// Parser happy-path success branches
// ====================================================================

class IncomingParserHappyPathTest : public ::testing::Test {};

TEST_F(IncomingParserHappyPathTest, ContentLengthBodyIsCapturedAndMessageCompletes) {
    qb::http::Parser<Request> parser;
    const std::string         raw = "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    EXPECT_TRUE(parser.headers_completed());
    EXPECT_EQ(parser.content_length, 5u);

    const std::size_t body_offset = static_cast<std::size_t>(parser.error_pos - raw.data());
    ASSERT_LT(body_offset, raw.size());

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
    EXPECT_EQ(parser.content_length, 0u);
}

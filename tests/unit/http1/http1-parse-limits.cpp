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

#include <cstddef>
#include <cstdio>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <qbm/http/1.1/protocol/base.h>
#include <qbm/http/http.h>

using namespace qb::http;

// ====================================================================
// Inbound parser limits
// ====================================================================

class IncomingParserLimitsTest : public ::testing::Test {};

TEST_F(IncomingParserLimitsTest, OversizedUrlIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw = "GET /" + std::string(protocol_limits::MAX_URL_LENGTH + 1, 'x') + " HTTP/1.1\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_USER);
}

TEST_F(IncomingParserLimitsTest, OversizedHeaderNameIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw =
        "GET / HTTP/1.1\r\nHost: example.test\r\n" + std::string(protocol_limits::MAX_HEADER_NAME_LENGTH + 1, 'H') + ": value\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_USER);
}

TEST_F(IncomingParserLimitsTest, OversizedHeaderValueIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw =
        "GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: " + std::string(protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'V') + "\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_USER);
}

TEST_F(IncomingParserLimitsTest, TooManyHeadersAreRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw = "GET / HTTP/1.1\r\nHost: example.test\r\n"; // the Host field is one of the MAX_HEADERS_COUNT + 1
    for (std::size_t i = 0; i < protocol_limits::MAX_HEADERS_COUNT; ++i) {
        raw += "X-Test-" + std::to_string(i) + ": value\r\n";
    }
    raw += "\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_USER);
}

TEST_F(IncomingParserLimitsTest, OversizedContentLengthIsRejectedBeforeBodyAllocation) {
    qb::http::Parser<Request> at_limit;
    std::string               allowed =
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: " + std::to_string(protocol_limits::MAX_BODY_SIZE) + "\r\n\r\n";
    EXPECT_EQ(at_limit.parse(allowed.data(), allowed.size()), HPE_PAUSED);
    EXPECT_TRUE(at_limit.headers_completed());

    qb::http::Parser<Request> parser;
    std::string               raw =
        "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: " + std::to_string(protocol_limits::MAX_BODY_SIZE + 1) + "\r\n\r\n";

    const auto result = parser.parse(raw.data(), raw.size());
    // llhttp maps qb's on_headers_complete refusal to this callback code and
    // replaces the custom reason with "User callback error". The paired
    // boundary control proves the one-byte excess triggered this refusal.
    EXPECT_EQ(result, HPE_CB_HEADERS_COMPLETE);
}

// MAX_CHUNK_SIZE parse-path: a single chunked-transfer chunk larger than the
// configured limit is rejected by on_body before it can accumulate. Allocating
// >16MB once is acceptable for a unit run; the chunk is fed in one buffer so a
// single on_body call sees length > MAX_CHUNK_SIZE.
TEST_F(IncomingParserLimitsTest, OversizedChunkIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;

    const std::string headers = "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n";
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
    EXPECT_EQ(parser.parse(chunk.data(), chunk.size()), HPE_USER);
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
    std::string               raw = "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n";

    EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED);
    EXPECT_TRUE(parser.headers_completed());
}

TEST_F(IncomingParserLimitsTest, UnsupportedTransferEncodingIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw = "POST /upload HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";

    const auto err = parser.parse(raw.data(), raw.size());
    EXPECT_NE(err, HPE_OK);
    EXPECT_NE(err, HPE_PAUSED);
}

TEST_F(IncomingParserLimitsTest, TransferEncodingWithContentLengthIsRejectedWhileParsing) {
    qb::http::Parser<Request> parser;
    std::string               raw = "POST /upload HTTP/1.1\r\n"
                                    "Host: example.test\r\n"
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

    const std::string chunk1 = "GET / HTTP/1.1\r\nHost: example.test\r\nX-Cus";
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
    std::string               raw = "GET / HTTP/1.1\r\nHost: example.test\r\n"; // the Host field is one of the MAX_HEADERS_COUNT
    for (std::size_t i = 1; i < protocol_limits::MAX_HEADERS_COUNT; ++i) {
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

// The target is read by its form once it has ended, never piece by piece (Huly QB-1177): a `//` split over two
// pieces is still an origin-form path, and a refused byte in the second piece is the refusal 400.
TEST_F(IncomingParserLimitsTest, FragmentedTargetIsReadByItsFormOnceItHasEnded) {
    {
        qb::http::Parser<Request> parser;
        const std::string         chunk1 = "GET /";
        const std::string         chunk2 = "/evil.test/x?q=1 HTTP/1.1\r\nHost: example.test\r\n\r\n";
        EXPECT_EQ(parser.parse(chunk1.data(), chunk1.size()), HPE_OK);
        EXPECT_EQ(parser.parse(chunk2.data(), chunk2.size()), HPE_PAUSED);
        auto const &uri = parser.get_parsed_message().uri();
        EXPECT_TRUE(uri.host().empty());
        EXPECT_EQ(uri.path(), "//evil.test/x");
        EXPECT_EQ(uri.query("q"), "1");
    }
    {
        qb::http::Parser<Request> parser;
        const std::string         chunk1 = "GET /a";
        const std::string         chunk2 = "|b HTTP/1.1\r\nHost: example.test\r\n\r\n";
        EXPECT_EQ(parser.parse(chunk1.data(), chunk1.size()), HPE_OK);
        EXPECT_NE(parser.parse(chunk2.data(), chunk2.size()), HPE_PAUSED);
        EXPECT_EQ(parser.refusal_status(), HTTP_STATUS_BAD_REQUEST);
    }
}

// The Host field is checked once the header section has ended (RFC 9112 §3.2, Huly QB-1186): an HTTP/1.1 request
// carries one, no request two field lines, and its value is empty or a host and an optional port -- otherwise the
// refusal is 400. A target that names its authority itself (absolute-form, CONNECT's authority-form) overrides the
// field, which then reads the target's authority as the client wrote it -- no port added, none dropped.
TEST_F(IncomingParserLimitsTest, TheHostFieldIsCheckedOnceTheHeaderSectionEnds) {
    auto const outcome = [](std::string const &raw) {
        qb::http::Parser<Request> parser;
        auto const                err = parser.parse(raw.data(), raw.size());
        return std::pair<int, int>{err, parser.refusal_status()};
    };
    for (std::string const raw :
         {"GET / HTTP/1.1\r\n\r\n", "GET / HTTP/1.1\r\nHost: a\r\nhost: a\r\n\r\n", "GET / HTTP/1.0\r\nHost: a\r\nHost: b\r\n\r\n",
          "GET / HTTP/1.1\r\nHost: a b\r\n\r\n", "GET / HTTP/1.1\r\nHost: u@a\r\n\r\n", "GET / HTTP/1.1\r\nHost: a:65536\r\n\r\n",
          "GET / HTTP/1.1\r\nHost: [fe80::1%25eth0]\r\n\r\n", "GET http://example.test/ HTTP/1.1\r\n\r\n",
          "CONNECT example.test:443 HTTP/1.1\r\n\r\n", "OPTIONS * HTTP/1.1\r\n\r\n"})
        EXPECT_EQ(outcome(raw), (std::pair<int, int>{HPE_CB_HEADERS_COMPLETE, HTTP_STATUS_BAD_REQUEST})) << raw;
    for (std::string const raw :
         {"GET / HTTP/1.0\r\n\r\n", "GET / HTTP/1.1\r\nHost:\r\n\r\n", "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n",
          "GET / HTTP/1.1\r\nHost: a:0\r\n\r\n", "GET / HTTP/1.1\r\nHost: xn--bcher-kva.example:65535\r\n\r\n"})
        EXPECT_EQ(outcome(raw), (std::pair<int, int>{HPE_PAUSED, 0})) << raw;

    auto const host_field = [](std::string const &raw) -> std::string {
        qb::http::Parser<Request> parser;
        if (parser.parse(raw.data(), raw.size()) != HPE_PAUSED)
            return "refused";
        return parser.get_parsed_message().header("Host");
    };
    EXPECT_EQ(host_field("GET /x HTTP/1.1\r\nHost: Example.Test:8080\r\n\r\n"), "Example.Test:8080") << "origin-form: the field, as sent";
    EXPECT_EQ(host_field("GET http://example.test:8080/x HTTP/1.1\r\nHost: evil.test\r\n\r\n"), "example.test:8080");
    EXPECT_EQ(host_field("GET https://example.test:443/x HTTP/1.1\r\nHost: evil.test\r\n\r\n"), "example.test:443");
    EXPECT_EQ(host_field("GET ftp://example.test/x HTTP/1.1\r\nHost: evil.test\r\n\r\n"), "example.test")
        << "not the default port the URI parser knows for the scheme";
    EXPECT_EQ(host_field("GET http://example.test?q=1 HTTP/1.1\r\nHost: evil.test\r\n\r\n"), "example.test");
    EXPECT_EQ(host_field("CONNECT [::1]:443 HTTP/1.1\r\nHost: evil.test\r\n\r\n"), "[::1]:443");
    EXPECT_EQ(host_field("OPTIONS * HTTP/1.1\r\nHost: example.test\r\n\r\n"), "example.test") << "asterisk-form: the field";
}

// reset() starts the next request's Host count afresh: a parser that refused a malformed or a doubled Host field,
// and one that accepted a request, judges the next request's field on its own.
TEST_F(IncomingParserLimitsTest, AResetParserJudgesTheNextRequestsHostAlone) {
    qb::http::Parser<Request> parser;
    std::string const         next = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    for (std::string const &first :
         {std::string{"GET / HTTP/1.1\r\nHost: a b\r\n\r\n"}, std::string{"GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n"}, next}) {
        (void) parser.parse(first.data(), first.size());
        parser.reset();
        EXPECT_EQ(parser.parse(next.data(), next.size()), HPE_PAUSED) << "after " << first;
        EXPECT_EQ(parser.refusal_status(), 0) << "after " << first;
        parser.reset();
    }
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
    const std::string         raw = "POST /x HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello";

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
                                    "Host: example.test\r\n"
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
    const std::string         raw = "GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n";

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
                                    "Host: example.test\r\n"
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

// ====================================================================
// A copied or moved Parser parses into ITSELF (Huly QB-510)
//
// llhttp hands every callback the http_t* it is executing; the callbacks used to reach the
// C++ object through http_t::data, which reset() pointed at `this`. The implicit copy and
// move copied that pointer verbatim, so a copy kept writing into its SOURCE: what the copy
// parsed never reached its own message, and once the source was gone the callbacks wrote
// into a dead object. The callbacks now recover the Parser from the http_t* they are given,
// which is the object being executed — whatever it was copied or moved from. Parser<Response>
// keeps the URI semantics of a request (QB-351) out of the picture.
// ====================================================================

class ParserCopyMoveTest : public ::testing::Test {
protected:
    // Mid header block: X-First is parsed but not committed yet (a pair is committed on the next
    // field), so the continuation must commit it into the parser that executes it.
    const std::string head = "HTTP/1.1 200 OK\r\nX-First: 1\r\n";
    const std::string tail = "X-Second: 2\r\nContent-Length: 0\r\n\r\n";

    void
    expect_owns_its_parse(qb::http::Parser<Response> &parser, const char *what) {
        ASSERT_EQ(parser.parse(tail.data(), tail.size()), HPE_PAUSED) << what;
        EXPECT_TRUE(parser.headers_completed()) << what;
        auto &msg = parser.get_parsed_message();
        EXPECT_EQ(msg.status(), 200) << what;
        EXPECT_EQ(msg.header("X-First"), "1") << what << ": the pending pair was committed elsewhere";
        EXPECT_EQ(msg.header("X-Second"), "2") << what << ": the continuation was parsed into another object";
    }

    static void
    expect_untouched(qb::http::Parser<Response> &source, const char *what) {
        EXPECT_FALSE(source.headers_completed()) << what << ": the other parser's continuation completed THIS one";
        EXPECT_TRUE(source.get_parsed_message().headers().empty()) << what << ": the other parser's headers landed here";
    }
};

TEST_F(ParserCopyMoveTest, ACopyParsesIntoItselfAndLeavesItsSourceAlone) {
    qb::http::Parser<Response> source;
    ASSERT_EQ(source.parse(head.data(), head.size()), HPE_OK);

    qb::http::Parser<Response> copy(source);
    expect_owns_its_parse(copy, "copy-constructed");
    expect_untouched(source, "source of a copy");

    // The source still owns its own, different continuation.
    const std::string other = "X-Third: 3\r\nContent-Length: 0\r\n\r\n";
    ASSERT_EQ(source.parse(other.data(), other.size()), HPE_PAUSED);
    EXPECT_EQ(source.get_parsed_message().header("X-First"), "1");
    EXPECT_EQ(source.get_parsed_message().header("X-Third"), "3");
    EXPECT_FALSE(source.get_parsed_message().has_header("X-Second"));
    EXPECT_FALSE(copy.get_parsed_message().has_header("X-Third"));
}

TEST_F(ParserCopyMoveTest, AssignmentAndMoveTransferTheParse) {
    {
        qb::http::Parser<Response> source;
        ASSERT_EQ(source.parse(head.data(), head.size()), HPE_OK);
        qb::http::Parser<Response> target;
        target = source;
        expect_owns_its_parse(target, "copy-assigned");
        expect_untouched(source, "source of a copy assignment");
    }
    {
        qb::http::Parser<Response> source;
        ASSERT_EQ(source.parse(head.data(), head.size()), HPE_OK);
        qb::http::Parser<Response> moved(std::move(source));
        expect_owns_its_parse(moved, "move-constructed");
    }
    {
        qb::http::Parser<Response> source;
        ASSERT_EQ(source.parse(head.data(), head.size()), HPE_OK);
        qb::http::Parser<Response> target;
        target = std::move(source);
        expect_owns_its_parse(target, "move-assigned");
    }
}

// The lifetime half: the copy outlives its source. Under AddressSanitizer the old shape is a
// heap-use-after-free inside the header callback.
TEST_F(ParserCopyMoveTest, ACopyOutlivesItsSource) {
    auto source = std::make_unique<qb::http::Parser<Response>>();
    ASSERT_EQ(source->parse(head.data(), head.size()), HPE_OK);
    qb::http::Parser<Response> copy(*source);
    source.reset();
    expect_owns_its_parse(copy, "copy of a destroyed source");
}

// A copy taken inside a chunked body keeps the body bytes already seen and accumulates the
// rest into itself.
TEST_F(ParserCopyMoveTest, ACopyTakenMidBodyFinishesTheBodyItself) {
    qb::http::Parser<Response> source;
    const std::string          headers = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    ASSERT_EQ(source.parse(headers.data(), headers.size()), HPE_PAUSED);
    source.resume();
    const std::string first = "5\r\nhel";
    ASSERT_EQ(source.parse(first.data(), first.size()), HPE_OK);

    qb::http::Parser<Response> copy(source);
    const std::string          rest = "lo\r\n0\r\n\r\n";
    ASSERT_EQ(copy.parse(rest.data(), rest.size()), HPE_CB_MESSAGE_COMPLETE);
    EXPECT_EQ(copy.get_parsed_message().body().as<std::string>(), "hello");
    EXPECT_EQ(source.get_parsed_message().body().size(), 0u) << "the copy completed the SOURCE's message";
}

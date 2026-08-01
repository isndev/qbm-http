/**
 * @file unit/http1/http1-request-smuggling.cpp
 * @brief HTTP/1.1 request-smuggling vectors: every ambiguous framing must be REJECTED.
 *
 * Request smuggling is the defining attack class of HTTP/1.1, and it is never a memory bug — it
 * is a *disagreement*. Two parsers on the same byte stream (a front-end proxy and this server)
 * derive different message boundaries, so bytes the proxy thinks are a body become a second
 * request to the origin. The only safe posture for a server is to refuse anything ambiguous
 * rather than pick an interpretation.
 *
 * `http1-parse-limits.cpp` already pins the two headline rules (Transfer-Encoding together with
 * Content-Length is rejected; an unsupported Transfer-Encoding is rejected). This file covers the
 * framing-desync family that sits underneath them, because each one is a published bypass of a
 * naive implementation of those two rules:
 *
 *   - **CL.CL** — two `Content-Length` headers. A proxy taking the first and an origin taking the
 *     last (or vice versa) split the stream differently (RFC 9112 §6.3: reject).
 *   - **Non-canonical `Content-Length`** — `+5`, `0x5`, `5 x`. `strtoul`-style leniency accepts
 *     what a stricter peer rejects (RFC 9112 §6.2: 1*DIGIT only).
 *   - **`chunked` not final** — `Transfer-Encoding: chunked, gzip`. Mirrors the already-tested
 *     `gzip, chunked`, but the ordering is what RFC 9112 §6.1 actually constrains, and getting
 *     only one of the two right is the common mistake.
 *   - **Duplicate `Transfer-Encoding` headers**, whose values only combine to something legal when
 *     concatenated — a classic proxy/origin disagreement.
 *   - **Space before the colon** — `Content-Length : 5`. RFC 9112 §5.1 requires a rejection
 *     precisely because lenient peers strip the space and re-introduce the header.
 *   - **obs-fold** — a header value continued on the next line. Deprecated by RFC 9112 §5.2 for
 *     requests; a peer that unfolds while another does not disagrees on the header set.
 *
 * Note on scope: the parser is llhttp, which implements most of this itself, and qb enables no
 * `llhttp_set_lenient_*` flag. This file therefore asserts observable BEHAVIOUR rather than any
 * particular implementation, so it keeps its meaning if the parser is ever swapped or the vendored
 * llhttp is bumped — and it fails loudly if a lenient flag is ever switched on.
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
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include "../1.1/protocol/base.h"
#include "../http.h"

using namespace qb::http;

namespace {

/// The parser never signals success with `HPE_OK`: `on_headers_complete` returns **HPE_PAUSED**
/// and `on_message_complete` returns **HPE_CB_MESSAGE_COMPLETE**. Treating only `HPE_OK` as
/// success makes every vector look "rejected" and the whole file vacuous, so the predicate is
/// spelled out once here. Measured values on this build: OK=0, PAUSED=21, CB_MESSAGE_COMPLETE=18,
/// USER=24 (a qb-level rejection), INVALID_CHUNK_SIZE=12.
[[nodiscard]] constexpr bool
is_success(int rc) noexcept {
    return rc == HPE_OK || rc == HPE_PAUSED || rc == HPE_CB_MESSAGE_COMPLETE;
}

/// Feed one raw request to a fresh parser and report whether it was accepted.
[[nodiscard]] bool
accepted(std::string const &raw) {
    qb::http::Parser<Request> parser;
    return is_success(parser.parse(raw.data(), raw.size()));
}

struct Vector {
    const char *name;
    std::string raw;
};

/// Chunked bodies need a SECOND pass: `on_headers_complete` returns `HPE_PAUSED`, so the first
/// `parse()` stops at end-of-headers and has not yet looked at a single chunk byte. Feed the
/// headers, `resume()`, then feed the body — otherwise every malformed chunk trivially "passes".
[[nodiscard]] bool
chunked_body_accepted(std::string const &body) {
    qb::http::Parser<Request> parser;
    const std::string         headers = "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
    if (parser.parse(headers.data(), headers.size()) != HPE_PAUSED)
        return false; // headers themselves refused — not what these vectors are probing
    parser.resume();
    return is_success(parser.parse(body.data(), body.size()));
}

} // namespace

class RequestSmugglingTest : public ::testing::Test {};

// --- Content-Length ambiguity -----------------------------------------------------------------

TEST_F(RequestSmugglingTest, AmbiguousContentLengthFramingIsRejected) {
    const Vector vectors[] = {
        {"two Content-Length headers with different values",
         "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"},
        {"two Content-Length headers with the SAME value (still ambiguous to a strict peer)",
         "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"},
        {"Content-Length with a leading plus", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nhello"},
        {"Content-Length in hex notation", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0x5\r\n\r\nhello"},
        {"Content-Length with trailing garbage", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5 x\r\n\r\nhello"},
        {"Content-Length with an embedded space", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1 5\r\n\r\nhello"},
        {"negative Content-Length", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n"},
    };

    for (auto const &v : vectors)
        EXPECT_FALSE(accepted(v.raw)) << "accepted an ambiguous framing: " << v.name;
}

// --- Transfer-Encoding ambiguity --------------------------------------------------------------

TEST_F(RequestSmugglingTest, AmbiguousTransferEncodingFramingIsRejected) {
    const Vector vectors[] = {
        {"chunked is not the FINAL encoding", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n"},
        {"two Transfer-Encoding headers that only combine to something legal",
         "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"},
        {"unknown sole transfer coding", "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: banana\r\n\r\n"},
    };

    for (auto const &v : vectors)
        EXPECT_FALSE(accepted(v.raw)) << "accepted an ambiguous framing: " << v.name;
}

// --- Header syntax that lenient peers rewrite -------------------------------------------------

TEST_F(RequestSmugglingTest, HeaderSyntaxThatLenientPeersRewriteIsRejected) {
    const Vector vectors[] = {
        {"space before the colon", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\nhello"},
        {"tab before the colon", "POST / HTTP/1.1\r\nHost: x\r\nContent-Length\t: 5\r\n\r\nhello"},
        {"obs-fold continuation line", "POST / HTTP/1.1\r\nHost: x\r\nX-Fold: a\r\n b\r\nContent-Length: 5\r\n\r\nhello"},
        {"bare LF terminating the request line", "POST / HTTP/1.1\nHost: x\r\nContent-Length: 5\r\n\r\nhello"},
    };

    for (auto const &v : vectors)
        EXPECT_FALSE(accepted(v.raw)) << "accepted a header syntax a lenient peer would rewrite: " << v.name;
}

// --- Chunked framing --------------------------------------------------------------------------

TEST_F(RequestSmugglingTest, MalformedChunkFramingIsRejected) {
    const Vector vectors[] = {
        {"chunk size overflowing 64 bits", "FFFFFFFFFFFFFFFFF\r\n"},
        {"chunk size with a leading plus", "+5\r\nhello\r\n0\r\n\r\n"},
        {"non-hex chunk size", "zz\r\n"},
        {"chunk size with a leading space", " 5\r\nhello\r\n0\r\n\r\n"},
    };

    for (auto const &v : vectors)
        EXPECT_FALSE(chunked_body_accepted(v.raw)) << "accepted a malformed chunk framing: " << v.name;
}

// Control for the chunked path itself: the two-pass harness must accept a well-formed body,
// otherwise the rejections above would be vacuous.
TEST_F(RequestSmugglingTest, WellFormedChunkedBodyIsAccepted) {
    EXPECT_TRUE(chunked_body_accepted("5\r\nhello\r\n0\r\n\r\n"));
}

// --- Control: the legitimate shapes must still parse ------------------------------------------

TEST_F(RequestSmugglingTest, WellFormedFramingIsStillAccepted) {
    EXPECT_TRUE(accepted("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")) << "a single well-formed Content-Length must parse";
    EXPECT_TRUE(accepted("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")) << "plain chunked must parse";
    EXPECT_TRUE(accepted("GET / HTTP/1.1\r\nHost: x\r\n\r\n")) << "a header-only GET must parse";
}

// --- The outbound half of the same family: response splitting ---------------------------------
// A desync can also be created on the way OUT: if attacker-controlled data reaches a header value
// and the serializer emits it verbatim, the peer sees headers (or a whole second response) the
// application never wrote. `http1-serialize-limits.cpp` pins the CRLF pair; the variants below are
// the ones that slip past a naive `find("\r\n")` check — a lone LF is enough for a lenient peer, a
// lone CR is enough for some, and a NUL truncates any consumer that reaches for a C string.

TEST_F(RequestSmugglingTest, HeaderInjectionVariantsAreRejectedAtSerialization) {
    struct Case {
        const char *name;
        std::string field;
        std::string value;
    };
    const Case cases[] = {
        {"value with bare LF", "X-Test", "safe\nInjected: bad"},
        {"value with bare CR", "X-Test", "safe\rInjected: bad"},
        {"value with NUL", "X-Test", std::string("safe\0bad", 8)},
        {"value with DEL", "X-Test", "a\x7f" "b"},
        {"name with bare LF", "X-Test\nInjected", "v"},
        {"name with bare CR", "X-Test\rInjected", "v"},
        {"name with NUL", std::string("X-Test\0Inj", 10), "v"},
    };

    for (auto const &c : cases) {
        Response r;
        r.status() = qb::http::status::OK;
        r.set_header(c.field, c.value);
        qb::allocator::pipe<char> out;
        EXPECT_THROW(out.put(r), std::length_error) << "serialized a header a peer could read as a forged one: " << c.name;
        EXPECT_EQ(out.size(), 0u) << "the output pipe must be cleared on rejection, not left half-written: " << c.name;
    }
}

// --- Keep-alive reuse: no state may survive from one message to the next ----------------------
// A connection carries many messages through one parser, so anything `reset()` forgets to clear
// becomes a cross-request defect: leftover headers are a desync, and a leaked DoS counter rejects
// legitimate clients once the connection has been used enough times.

TEST_F(RequestSmugglingTest, ParserResetLeavesNoStateBetweenMessages) {
    qb::http::Parser<Request> parser;

    const std::string first = "POST /first HTTP/1.1\r\nHost: a\r\nX-Only-On-First: 1\r\nContent-Length: 5\r\n\r\nhello";
    ASSERT_EQ(parser.parse(first.data(), first.size()), HPE_PAUSED);
    const std::size_t body_offset = static_cast<std::size_t>(parser.error_pos - first.data());
    parser.resume();
    ASSERT_TRUE(is_success(parser.parse(first.data() + body_offset, first.size() - body_offset)));
    ASSERT_TRUE(parser.get_parsed_message().has_header("X-Only-On-First"));
    ASSERT_EQ(parser.get_parsed_message().body().size(), 5u);

    parser.reset();

    const std::string second = "GET /second HTTP/1.1\r\nHost: b\r\n\r\n";
    ASSERT_EQ(parser.parse(second.data(), second.size()), HPE_PAUSED);
    auto &msg2 = parser.get_parsed_message();
    EXPECT_FALSE(msg2.has_header("X-Only-On-First")) << "a header from the previous message survived reset() — every later request on this "
                                                       "connection would carry it";
    EXPECT_EQ(msg2.body().size(), 0u) << "the previous body survived reset()";
    EXPECT_EQ(parser.content_length, 0u);
}

TEST_F(RequestSmugglingTest, PerMessageDosCountersDoNotAccumulateAcrossAConnection) {
    qb::http::Parser<Request> parser;

    // Each message stays well under MAX_HEADERS_COUNT, but their sum is far over it. If the
    // counter were cumulative, a long-lived keep-alive connection would start rejecting valid
    // requests — a self-inflicted denial of service on well-behaved clients.
    const std::size_t per_message = protocol_limits::MAX_HEADERS_COUNT / 2;
    for (int round = 0; round < 5; ++round) {
        std::string raw = "GET /r HTTP/1.1\r\nHost: x\r\n";
        for (std::size_t i = 0; i < per_message; ++i)
            raw += "X-H-" + std::to_string(i) + ": v\r\n";
        raw += "\r\n";

        EXPECT_EQ(parser.parse(raw.data(), raw.size()), HPE_PAUSED) << "round " << round << " was rejected: a per-message limit is leaking across reset()";
        parser.reset();
    }
}

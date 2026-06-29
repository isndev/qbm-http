/**
 * @file qbm/http/tests/benchmark/http1/http1-parser.bench.cpp
 * @brief Benchmarks for the inbound HTTP/1.1 message parser `qb::http::Parser<Request>`.
 *
 * Measures the parser's hot path — `Parser<Request>::parse(buf, len)` — the byte
 * pump every inbound connection drives for request-line, headers, and body framing.
 * Three feed shapes reproduce the real transport conditions the parser tests pin:
 *   - WHOLE-buffer: the full request arrives in one read (the common fast path).
 *   - BYTE-AT-A-TIME: one byte per parse() call — the incremental-state stress the
 *     spec uses to prove no double-counting of fragmented header fields.
 *   - FRAGMENTED: a handful of arbitrary mid-token splits (URL + header reassembly),
 *     mirroring partial TCP segments.
 *
 * The parser pauses at end-of-headers (HPE_PAUSED) per 1.1/protocol/base.h; the
 * Content-Length body is parsed in a second resume()+parse() pass keyed off
 * `error_pos` — exactly the two-pass dance http1-parse-limits.cpp documents. Each
 * iteration constructs a FRESH parser (parser state is single-use per message); that
 * construction is hoisted out of the timed region with PauseTiming/ResumeTiming.
 *
 * Corpus is lifted from http1-parse-limits.cpp (happy-path branches): a header-only
 * GET, a multi-header GET with keep-alive/upgrade derivation, and a POST with a
 * Content-Length body captured + message-completed.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
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
 * @ingroup Http
 */

#include <benchmark/benchmark.h>
#include <cstddef>
#include <cstdint>
#include <string>

#include "../1.1/protocol/base.h" // qb::http::Parser, HPE_* codes
#include "../http.h"              // qb::http::Request

namespace {

using qb::http::Parser;
using qb::http::Request;

// ---------------------------------------------------------------------------
// Deterministic, byte-exact corpora (seeded from http1-parse-limits.cpp).
// ---------------------------------------------------------------------------

// Header-only GET (KeepAliveDefaultsTrueForHttp11): parses to HPE_PAUSED, no body.
std::string
corpus_header_only() {
    return "GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n";
}

// Multi-header GET exercising keep-alive + upgrade derivation in on_headers_complete
// (UpgradeFlagIsSetForConnectionUpgrade + a realistic browser-ish header set).
std::string
corpus_multi_header() {
    return "GET /api/v1/users?name=alice HTTP/1.1\r\n"
           "Host: example.test\r\n"
           "User-Agent: qb-bench/1.0\r\n"
           "Accept: application/json\r\n"
           "Accept-Encoding: gzip, deflate, br\r\n"
           "Connection: Upgrade\r\n"
           "Upgrade: h2c\r\n"
           "X-Multi: alpha\r\n"
           "X-Multi: beta\r\n\r\n";
}

// POST with a Content-Length body (ContentLengthBodyIsCapturedAndMessageCompletes).
std::string
corpus_post_with_body() {
    return "POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
}

// ---------------------------------------------------------------------------
// Parse drivers. All return the final errno of the message so callers can assert.
// ---------------------------------------------------------------------------

// Whole-buffer parse: headers in one call, then (if a Content-Length body remains)
// the two-pass resume()+parse() that http1-parse-limits.cpp pins.
http_errno_t
parse_whole(const std::string &raw) {
    Parser<Request> parser;
    auto            err = parser.parse(raw.data(), raw.size());
    if (err != HPE_PAUSED || !parser.headers_completed())
        return err;
    if (parser.content_length == 0u)
        return err; // header-only: PAUSED is terminal for this bench

    const std::size_t body_offset = static_cast<std::size_t>(parser.error_pos - raw.data());
    parser.resume();
    return parser.parse(raw.data() + body_offset, raw.size() - body_offset);
}

// Byte-at-a-time: feed one byte per parse() call. on_headers_complete pauses the
// parser mid-stream; resume() and keep feeding the remaining (body) bytes.
http_errno_t
parse_byte_at_a_time(const std::string &raw) {
    Parser<Request> parser;
    http_errno_t    err = HPE_OK;
    for (std::size_t i = 0; i < raw.size(); ++i) {
        err = parser.parse(raw.data() + i, 1);
        if (err == HPE_PAUSED) {
            // Headers done; resume so the remaining bytes feed the body.
            parser.resume();
            continue;
        }
        if (err != HPE_OK && err != HPE_CB_MESSAGE_COMPLETE)
            break;
    }
    return err;
}

// Fragmented: split at a few arbitrary mid-token offsets (URL + header + body), the
// realistic partial-segment shape FragmentedHeaderFieldAndValue / FragmentedUrl pin.
http_errno_t
parse_fragmented(const std::string &raw) {
    Parser<Request>   parser;
    const std::size_t n = raw.size();
    // 4 cut points spread across the buffer (never zero-length slices for n>=4).
    const std::size_t cuts[] = {n / 5, (2 * n) / 5, (3 * n) / 5, (4 * n) / 5};

    std::size_t  pos     = 0;
    bool         resumed = false;
    http_errno_t err     = HPE_OK;
    for (std::size_t c = 0; c <= 4; ++c) {
        const std::size_t end = (c < 4) ? cuts[c] : n;
        if (end <= pos)
            continue;
        err = parser.parse(raw.data() + pos, end - pos);
        pos = end;
        if (err == HPE_PAUSED && !resumed) {
            parser.resume(); // headers complete mid-stream; continue into the body
            resumed = true;
            continue;
        }
        if (err != HPE_OK && err != HPE_PAUSED && err != HPE_CB_MESSAGE_COMPLETE)
            break;
    }
    return err;
}

bool
ok_terminal(http_errno_t err) {
    return err == HPE_PAUSED || err == HPE_CB_MESSAGE_COMPLETE;
}

// ---------------------------------------------------------------------------
// Benchmark templates: state.range(0) selects the corpus (0/1/2).
// ---------------------------------------------------------------------------

const std::string &
select_corpus(std::int64_t which) {
    static const std::string header_only = corpus_header_only();
    static const std::string multi       = corpus_multi_header();
    static const std::string post_body   = corpus_post_with_body();
    switch (which) {
        case 0:
            return header_only;
        case 1:
            return multi;
        default:
            return post_body;
    }
}

void
BM_Http1Parse_WholeBuffer(benchmark::State &state) {
    const std::string &raw = select_corpus(state.range(0));

    if (!ok_terminal(parse_whole(raw))) {
        state.SkipWithError("whole-buffer parse did not reach a terminal state");
        return;
    }

    for (auto _ : state) {
        auto err = parse_whole(raw);
        benchmark::DoNotOptimize(err);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

void
BM_Http1Parse_ByteAtATime(benchmark::State &state) {
    const std::string &raw = select_corpus(state.range(0));

    if (!ok_terminal(parse_byte_at_a_time(raw))) {
        state.SkipWithError("byte-at-a-time parse did not reach a terminal state");
        return;
    }

    for (auto _ : state) {
        auto err = parse_byte_at_a_time(raw);
        benchmark::DoNotOptimize(err);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

void
BM_Http1Parse_Fragmented(benchmark::State &state) {
    const std::string &raw = select_corpus(state.range(0));

    if (!ok_terminal(parse_fragmented(raw))) {
        state.SkipWithError("fragmented parse did not reach a terminal state");
        return;
    }

    for (auto _ : state) {
        auto err = parse_fragmented(raw);
        benchmark::DoNotOptimize(err);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

} // namespace

// corpus: 0=header-only GET, 1=multi-header GET (keep-alive/upgrade), 2=POST+body.
BENCHMARK(BM_Http1Parse_WholeBuffer)->Arg(0)->Arg(1)->Arg(2)->ArgNames({"corpus"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http1Parse_ByteAtATime)->Arg(0)->Arg(1)->Arg(2)->ArgNames({"corpus"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http1Parse_Fragmented)->Arg(0)->Arg(1)->Arg(2)->ArgNames({"corpus"})->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();

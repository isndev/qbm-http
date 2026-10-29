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
 * construction and destruction are INCLUDED in the timed driver call. Only the
 * correctness probes run before the benchmark loop; no parser setup is moved out.
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
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <qbm/http/1.1/protocol/base.h> // qb::http::Parser, HPE_* codes
#include <qbm/http/http.h>              // qb::http::Request

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
    return "POST /x HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello";
}

// ---------------------------------------------------------------------------
// Parse drivers. All return the final errno of the message so callers can assert.
// ---------------------------------------------------------------------------

// Whole-buffer parse: headers in one call, then (if a Content-Length body remains)
// the two-pass resume()+parse() that http1-parse-limits.cpp pins.
http_errno_t
parse_whole(Parser<Request> &parser, const std::string &raw) {
    auto err = parser.parse(raw.data(), raw.size());
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
parse_byte_at_a_time(Parser<Request> &parser, const std::string &raw) {
    http_errno_t err = HPE_OK;
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

// The cut list names exclusive ends in the SAME raw buffer. A pause consumes only
// up to error_pos: the rest of that fragment must be replayed after resume().
// Check the fixed corpus and its cut/pause bounds in preflight, before using the
// same driver without those checks in the timed loop. No runtime mode branch.
template <bool Checked = false>
http_errno_t
parse_fragments(Parser<Request> &parser, const std::string &raw, std::span<const std::size_t> ends) {
    std::size_t  pos     = 0;
    bool         resumed = false;
    http_errno_t err     = HPE_OK;
    for (const auto end : ends) {
        if constexpr (Checked) {
            if (end < pos || end > raw.size())
                return HPE_USER;
        }
        while (pos < end) {
            err = parser.parse(raw.data() + pos, end - pos);
            if (err == HPE_PAUSED && !resumed && parser.headers_completed()) {
                const auto *resume_at = parser.error_pos;
                if constexpr (Checked) {
                    if (!resume_at || resume_at < raw.data() + pos || resume_at > raw.data() + end)
                        return HPE_USER;
                }
                pos                    = static_cast<std::size_t>(resume_at - raw.data());
                const bool header_only = parser.content_length == 0u;
                parser.resume(); // Preserve the original fragmented driver's resume, including heads.
                resumed = true;
                if (header_only)
                    return err; // This corpus deliberately measures header-only/upgrade heads.
                continue;       // Feed the unconsumed bytes of this fragment, if any.
            }
            if (err != HPE_OK)
                return err;
            pos = end;
        }
    }
    return err;
}

template <bool Checked = false>
http_errno_t
parse_fragmented(Parser<Request> &parser, const std::string &raw) {
    const std::size_t                n = raw.size();
    const std::array<std::size_t, 5> ends{n / 5, (2 * n) / 5, (3 * n) / 5, (4 * n) / 5, n};
    return parse_fragments<Checked>(parser, raw, ends);
}

// Preserve the timed workload: every public driver constructs and destroys its
// ordinary production Parser inside the call, with the original callback table.
http_errno_t
parse_whole(const std::string &raw) {
    Parser<Request> parser;
    return parse_whole(parser, raw);
}

http_errno_t
parse_byte_at_a_time(const std::string &raw) {
    Parser<Request> parser;
    return parse_byte_at_a_time(parser, raw);
}

http_errno_t
parse_fragmented(const std::string &raw) {
    Parser<Request> parser;
    return parse_fragmented(parser, raw);
}

// Probe-only callback observation. The production callbacks still build the message.
// Parser's callbacks recover their object from the http_t base, not its data member.
// These corpora have no Transfer-Encoding, so the header callback does not swap tables.
class CallbackProbe {
    http_t         &_wire;
    void           *_old_data;
    void           *_old_settings;
    http_settings_t _original;
    http_settings_t _observed;

public:
    std::size_t headers    = 0;
    std::size_t body_calls = 0;
    std::size_t completed  = 0;
    std::string body_bytes;

    explicit CallbackProbe(Parser<Request> &parser)
        : _wire(static_cast<http_t &>(parser))
        , _old_data(_wire.data)
        , _old_settings(_wire.settings)
        , _original(*static_cast<const http_settings_t *>(_wire.settings))
        , _observed(_original) {
        _observed.on_headers_complete = [](http_t *wire) {
            auto &probe = *static_cast<CallbackProbe *>(wire->data);
            ++probe.headers;
            return probe._original.on_headers_complete(wire);
        };
        _observed.on_body = [](http_t *wire, const char *data, std::size_t size) {
            auto &probe = *static_cast<CallbackProbe *>(wire->data);
            ++probe.body_calls;
            probe.body_bytes.append(data, size);
            return probe._original.on_body(wire, data, size);
        };
        _observed.on_message_complete = [](http_t *wire) {
            auto &probe = *static_cast<CallbackProbe *>(wire->data);
            ++probe.completed;
            return probe._original.on_message_complete(wire);
        };
        _wire.data     = this;
        _wire.settings = &_observed;
    }

    CallbackProbe(const CallbackProbe &)            = delete;
    CallbackProbe &operator=(const CallbackProbe &) = delete;

    ~CallbackProbe() {
        _wire.data     = _old_data;
        _wire.settings = _old_settings;
    }
};

struct ExpectedHeader {
    std::string_view              name;
    std::vector<std::string_view> values;
};

struct ExpectedMessage {
    http_method                 method;
    std::string_view            target;
    std::string_view            body;
    bool                        upgrade;
    std::vector<ExpectedHeader> headers;
};

const ExpectedMessage &
expected_message(std::int64_t corpus) {
    // Literal oracle, independently stated: no parser or serializer computes it.
    static const std::array<ExpectedMessage, 3> expected{
        {{HTTP_GET, "/health", "", false, {{"Host", {"example.test"}}}},
         {HTTP_GET,
          "/api/v1/users?name=alice",
          "",
          true,
          {{"Host", {"example.test"}},
           {"User-Agent", {"qb-bench/1.0"}},
           {"Accept", {"application/json"}},
           {"Accept-Encoding", {"gzip, deflate, br"}},
           {"Connection", {"Upgrade"}},
           {"Upgrade", {"h2c"}},
           {"X-Multi", {"alpha", "beta"}}}},
         {HTTP_POST, "/x", "hello", false, {{"Host", {"example.test"}}, {"Content-Length", {"5"}}}}}
    };
    return expected[static_cast<std::size_t>(corpus)];
}

bool
exact_message(Parser<Request> &parser, http_errno_t code, const std::string &raw, const ExpectedMessage &expected,
              const CallbackProbe *probe = nullptr) {
    auto      &message  = parser.get_parsed_message();
    const auto terminal = expected.body.empty() ? HPE_PAUSED : HPE_CB_MESSAGE_COMPLETE;
    if (code != terminal || !parser.headers_completed() || parser.error_pos != raw.data() + raw.size() || message.method() != expected.method
        || message.uri().source() != expected.target || message.major_version != 1 || message.minor_version != 1 || !message.keep_alive
        || message.upgrade != expected.upgrade || message.has_trailers() || message.body().as<std::string_view>() != expected.body
        || message.header_count() != expected.headers.size())
        return false;
    for (const auto &header : expected.headers) {
        const auto found = message.headers().find(std::string(header.name));
        if (found == message.headers().end() || found->second.size() != header.values.size())
            return false;
        for (std::size_t i = 0; i < header.values.size(); ++i)
            if (found->second[i] != header.values[i])
                return false;
    }
    if (probe
        && (probe->headers != 1 || probe->completed != static_cast<std::size_t>(!expected.body.empty()) || probe->body_bytes != expected.body
            || (probe->body_calls == 0) != expected.body.empty()))
        return false;
    return true;
}

template <typename Driver>
bool
preflight(const std::string &raw, std::int64_t corpus, Driver driver) {
    const auto &expected = expected_message(corpus);
    // First observe the actual timed callback table, then delegate through counters.
    // The observed parse is never used as the expected result of the ordinary one.
    Parser<Request> plain;
    if (!exact_message(plain, driver(plain), raw, expected))
        return false;
    Parser<Request> observed;
    CallbackProbe   callbacks(observed);
    return exact_message(observed, driver(observed), raw, expected, &callbacks);
}

bool
fragmented_preflight(const std::string &raw, std::int64_t corpus) {
    if (!preflight(raw, corpus, [&](auto &parser) { return parse_fragmented<true>(parser, raw); })
        || !preflight(raw, corpus, [&](auto &parser) { return parse_fragmented(parser, raw); }))
        return false;
    // Every single boundary covers splits in the request target, header tokens,
    // the CRLFCRLF pause, and each byte of "hello". The usual five-fragment shape
    // above is separately exercised; neither expectation is generated by parsing.
    for (std::size_t cut = 1; cut < raw.size(); ++cut) {
        const std::array<std::size_t, 2> ends{cut, raw.size()};
        if (!preflight(raw, corpus, [&](auto &parser) { return parse_fragments<true>(parser, raw, ends); }))
            return false;
    }
    return true;
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

    if (!preflight(raw, state.range(0), [&](auto &parser) { return parse_whole(parser, raw); })) {
        state.SkipWithError("whole-buffer preflight failed: exact message, callbacks or consumption");
        return;
    }

    for (auto _ : state) {
        auto err = parse_whole(raw);
        benchmark::DoNotOptimize(err);
    }

    state.SetLabel(state.range(0) == 2 ? "content-length-complete; driver-v2" : "headers-only; driver-v2");
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

void
BM_Http1Parse_ByteAtATime(benchmark::State &state) {
    const std::string &raw = select_corpus(state.range(0));

    if (!preflight(raw, state.range(0), [&](auto &parser) { return parse_byte_at_a_time(parser, raw); })) {
        state.SkipWithError("byte-at-a-time preflight failed: exact message, callbacks or consumption");
        return;
    }

    for (auto _ : state) {
        auto err = parse_byte_at_a_time(raw);
        benchmark::DoNotOptimize(err);
    }

    state.SetLabel(state.range(0) == 2 ? "content-length-complete; driver-v2" : "headers-only; driver-v2");
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

void
BM_Http1Parse_Fragmented(benchmark::State &state) {
    const std::string &raw = select_corpus(state.range(0));

    if (!fragmented_preflight(raw, state.range(0))) {
        state.SkipWithError("fragmented preflight failed: exact message, callbacks or consumption");
        return;
    }

    for (auto _ : state) {
        auto err = parse_fragmented(raw);
        benchmark::DoNotOptimize(err);
    }

    state.SetLabel(state.range(0) == 2 ? "content-length-complete; driver-v2" : "headers-only; driver-v2");
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

} // namespace

// corpus: 0=header-only GET, 1=multi-header GET (keep-alive/upgrade), 2=POST+body.
BENCHMARK(BM_Http1Parse_WholeBuffer)->Arg(0)->Arg(1)->Arg(2)->ArgNames({"corpus"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http1Parse_ByteAtATime)->Arg(0)->Arg(1)->Arg(2)->ArgNames({"corpus"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http1Parse_Fragmented)->Arg(0)->Arg(1)->Arg(2)->ArgNames({"corpus"})->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();

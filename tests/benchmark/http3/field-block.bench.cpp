/**
 * @file qbm/http/tests/benchmark/http3/field-block.bench.cpp
 * @brief google-benchmark harness for the HTTP/3 field-block assembly hot path.
 *
 * Every HTTP/3 request and response synthesises a field block (the QPACK
 * name/value array) through the @c qb::protocol::http3::detail helpers:
 * make_request_headers / make_response_headers / make_trailers run the
 * pseudo-header ordering, forbidden-header screening, content-length
 * reconciliation, and authority/target derivation once per message. These
 * benchmarks measure those pure, socket-free helpers plus the per-field
 * validators (is_valid_header_field / parse_content_length) they call.
 *
 * Seed (byte-exact fixtures reused so the benchmark measures the same code the
 * tests pin): tests/unit/http3/http3-validation.cpp —
 *   - MakeRequestHeadersOrdersPseudoHeadersAndDropsHost (GET https://example.test/path?q=1 + host + x-custom)
 *   - MakeRequestHeadersSynthesizesContentLengthForBody (POST .../echo, body "payload")
 *   - MakeResponseHeadersPutsStatusFirst (200 + x-extra)
 *   - MakeTrailersHonorsAnnouncedTrailers (trailer: x-checksum)
 *   - ParseContentLength* / IsValidHeaderFieldEnforcesRfc7230 corpora.
 *
 * The whole file is gated on QBM_HTTP_HAS_HTTP3 (the detail helpers are only
 * declared in an HTTP/3 build); when HTTP/3 is off it compiles to an empty
 * main so it still links.
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

#include <qbm/http/http.h>

#if defined(QBM_HTTP_HAS_HTTP3)

#include <benchmark/benchmark.h>

#include <optional>
#include <string>

namespace h3detail = qb::protocol::http3::detail;

// ===========================================================================
// make_request_headers — pseudo-header ordering + host folding (GET)
// ===========================================================================

// Seed: MakeRequestHeadersOrdersPseudoHeadersAndDropsHost. The request is
// rebuilt per iteration (it is the input the helper consumes); the build is
// paused out of the timed region so we measure only the field-block assembly.
void
BM_Http3_MakeRequestHeadersGet(benchmark::State &state) {
    {
        qb::http::Request req{qb::http::method::GET, qb::io::uri("https://example.test/path?q=1")};
        req.set_header("host", "should-be-dropped");
        req.set_header("x-custom", "v");
        auto probe = h3detail::make_request_headers(req);
        if (!probe.has_value() || probe->storage.size() < 4u) {
            state.SkipWithError("make_request_headers (GET) failed");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        qb::http::Request req{qb::http::method::GET, qb::io::uri("https://example.test/path?q=1")};
        req.set_header("host", "should-be-dropped");
        req.set_header("x-custom", "v");
        state.ResumeTiming();

        auto block = h3detail::make_request_headers(req);
        benchmark::DoNotOptimize(block);
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
}

// Seed: MakeRequestHeadersSynthesizesContentLengthForBody. POST with a body
// exercises the content-length synthesis + reconciliation path.
void
BM_Http3_MakeRequestHeadersPostBody(benchmark::State &state) {
    {
        qb::http::Request req{qb::http::method::POST, qb::io::uri("https://example.test/echo")};
        req.body() = "payload";
        auto probe = h3detail::make_request_headers(req);
        if (!probe.has_value()) {
            state.SkipWithError("make_request_headers (POST body) failed");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        qb::http::Request req{qb::http::method::POST, qb::io::uri("https://example.test/echo")};
        req.body() = "payload";
        state.ResumeTiming();

        auto block = h3detail::make_request_headers(req);
        benchmark::DoNotOptimize(block);
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
}

// ===========================================================================
// make_response_headers — :status first + forbidden-header screen
// ===========================================================================

// Seed: MakeResponseHeadersPutsStatusFirst + SynthesizesContentLengthForBody.
void
BM_Http3_MakeResponseHeaders(benchmark::State &state) {
    {
        qb::http::Response res;
        res.status() = qb::http::status::OK;
        res.set_header("x-extra", "v");
        res.body() = "hello";
        auto probe = h3detail::make_response_headers(res);
        if (!probe.has_value() || probe->storage.empty()) {
            state.SkipWithError("make_response_headers failed");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        qb::http::Response res;
        res.status() = qb::http::status::OK;
        res.set_header("x-extra", "v");
        res.body() = "hello";
        state.ResumeTiming();

        auto block = h3detail::make_response_headers(res);
        benchmark::DoNotOptimize(block);
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
}

// ===========================================================================
// make_trailers — announced-trailer derivation + screen
// ===========================================================================

// Seed: MakeTrailersHonorsAnnouncedTrailers (announced + present valid).
void
BM_Http3_MakeTrailers(benchmark::State &state) {
    {
        qb::http::Response res;
        res.status() = qb::http::status::OK;
        res.set_header("trailer", "x-checksum");
        res.set_header("x-checksum", "abc123");
        auto probe = h3detail::make_trailers(res);
        if (!probe.has_value() || probe->nva.empty()) {
            state.SkipWithError("make_trailers failed");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        qb::http::Response res;
        res.status() = qb::http::status::OK;
        res.set_header("trailer", "x-checksum");
        res.set_header("x-checksum", "abc123");
        state.ResumeTiming();

        auto block = h3detail::make_trailers(res);
        benchmark::DoNotOptimize(block);
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
}

// ===========================================================================
// parse_content_length — the strict decimal parser
// ===========================================================================

// Seed: ParseContentLengthAcceptsWellFormedDecimals / RejectsMalformedValues.
void
BM_Http3_ParseContentLength(benchmark::State &state) {
    static const std::string_view inputs[] = {
        "0", "12345", "18446744073709551615", "", "12a", " 12", "-1", "18446744073709551616",
    };

    {
        auto v = h3detail::parse_content_length("12345");
        if (!v.has_value() || *v != 12345u) {
            state.SkipWithError("parse_content_length mismatch");
            return;
        }
    }

    std::size_t i = 0;
    for (auto _ : state) {
        auto v = h3detail::parse_content_length(inputs[i]);
        benchmark::DoNotOptimize(v);
        i = (i + 1) % (sizeof(inputs) / sizeof(inputs[0]));
    }

    state.SetItemsProcessed(state.iterations());
}

// ===========================================================================
// is_valid_header_field — per-field RFC 7230 / RFC 9114 validation
// ===========================================================================

// Seed: IsValidHeaderFieldEnforcesRfc7230 corpus (valid + every reject class).
void
BM_Http3_IsValidHeaderField(benchmark::State &state) {
    struct Field {
        std::string_view name;
        std::string_view value;
    };
    static const Field fields[] = {
        {"x-test", "ok"},   {"content-type", "application/json; charset=utf-8"}, {"accept", "text/html,application/xhtml+xml"},
        {"", "ok"},         // empty name (reject)
        {"X-Test", "ok"},   // uppercase name (reject)
        {"x test", "ok"},   // space in name (reject)
        {"x-test", "a\tb"}, // TAB allowed (accept)
    };

    if (!h3detail::is_valid_header_field("x-test", "ok")) {
        state.SkipWithError("is_valid_header_field rejected a valid field");
        return;
    }

    std::size_t i = 0;
    for (auto _ : state) {
        bool ok = h3detail::is_valid_header_field(fields[i].name, fields[i].value);
        benchmark::DoNotOptimize(ok);
        i = (i + 1) % (sizeof(fields) / sizeof(fields[0]));
    }

    state.SetItemsProcessed(state.iterations());
}

BENCHMARK(BM_Http3_MakeRequestHeadersGet)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http3_MakeRequestHeadersPostBody)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http3_MakeResponseHeaders)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http3_MakeTrailers)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http3_ParseContentLength)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http3_IsValidHeaderField)->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();

#else // QBM_HTTP_HAS_HTTP3

int
main() {
    return 0;
}

#endif // QBM_HTTP_HAS_HTTP3

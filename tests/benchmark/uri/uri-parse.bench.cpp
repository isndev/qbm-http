/**
 * @file qbm/http/tests/benchmark/uri/uri-parse.bench.cpp
 * @brief google-benchmark harness for the qb::io::uri parser and percent codec.
 *
 * `qb::io::uri` is on the hot path of every routed HTTP request: each inbound
 * request-target is parsed once into scheme/authority/path/query, and outbound
 * client requests build a URI from a string. These benchmarks isolate that
 * parse cost plus the static `encode()`/`decode()` percent-codec, which the Form
 * and query machinery call per field.
 *
 * Fixtures are the byte-exact corpora pinned by the parser's unit suite
 * (tests/unit/uri/uri-parse.cpp): the full userinfo+port+path+query+fragment
 * URI from `UriComponents.BasicComponents`, the IPv6/scoped authorities, the
 * `ComplexQueries` / `ArrayStyleParameters` query strings, and the
 * round-trip codec strings from `UriEncoding.*`. Reusing them means the
 * benchmark measures the same code path the test pins.
 *
 * NOTE (cross-module): `qb::io::uri` is a qb-io type, so this harness includes
 * the absolute <qb/io/uri.h> header (not a module-relative "../" include),
 * mirroring the seed unit file.
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

#include <cstdint>
#include <string>

#include <benchmark/benchmark.h>

#include <qb/io/uri.h>

namespace {

// ---------------------------------------------------------------------------
// Byte-exact fixtures lifted from tests/unit/uri/uri-parse.cpp.
// ---------------------------------------------------------------------------

// UriComponents.BasicComponents — full userinfo + port + path + query + fragment.
constexpr char kComplexUri[] = "http://username:password@example.com:8080/path/to/resource"
                               "?query=value&param2=value2#fragment";

// UriEdgeCases.CompleteCombinations (uri1) — a leaner but complete request URI.
constexpr char kSimpleUri[] = "http://example.com/path?query=value#fragment";

// UriIpAddresses.IPv6AddressWithPort — bracketed IPv6 authority + port.
constexpr char kIpv6Uri[] = "http://[2001:db8::1]:8080/path";

// UriQueries.ComplexQueries — bracketed/array-ish keys, '+'-encoded space.
constexpr char kComplexQueryUri[] = "http://example.com/path?q=search+term&filters[category]=books"
                                    "&filters[price]=10-50&page=1";

// UriEncoding.SpecialCharactersRoundTrip — the full printable-ASCII span.
constexpr char kCodecRoundTrip[] = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
                                   "abcdefghijklmnopqrstuvwxyz{|}~";

// UriQueries.UrlEncodingDecoding — a percent-encoded query value to decode.
constexpr char kEncodedQueryValue[] = "%20%21%40%23%24%25%5E%26%2A%28%29";

// ---------------------------------------------------------------------------
// Parse a full URI (construct + internal parse()).
// ---------------------------------------------------------------------------
void
BM_Uri_ParseComplex(benchmark::State &state) {
    const std::string raw{kComplexUri};

    // Out-of-loop correctness gate: a broken parser must not report a number.
    {
        qb::io::uri probe{raw};
        if (!probe.is_valid() || probe.host() != "example.com" || probe.u_port() != 8080) {
            state.SkipWithError("uri parse mismatch on kComplexUri");
            return;
        }
    }

    for (auto _ : state) {
        qb::io::uri uri{raw};
        benchmark::DoNotOptimize(uri.host());
        benchmark::DoNotOptimize(uri.path());
        auto valid = uri.is_valid();
        benchmark::DoNotOptimize(valid);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

// ---------------------------------------------------------------------------
// Parse a lean request URI — the common per-request shape.
// ---------------------------------------------------------------------------
void
BM_Uri_ParseSimple(benchmark::State &state) {
    const std::string raw{kSimpleUri};

    {
        qb::io::uri probe{raw};
        if (!probe.is_valid() || probe.path() != "/path") {
            state.SkipWithError("uri parse mismatch on kSimpleUri");
            return;
        }
    }

    for (auto _ : state) {
        qb::io::uri uri{raw};
        benchmark::DoNotOptimize(uri.path());
        auto valid = uri.is_valid();
        benchmark::DoNotOptimize(valid);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

// ---------------------------------------------------------------------------
// Parse a bracketed IPv6 authority + port (the AF_INET6 path).
// ---------------------------------------------------------------------------
void
BM_Uri_ParseIpv6(benchmark::State &state) {
    const std::string raw{kIpv6Uri};

    {
        qb::io::uri probe{raw};
        if (!probe.is_valid() || probe.host() != "2001:db8::1" || probe.u_port() != 8080) {
            state.SkipWithError("uri parse mismatch on kIpv6Uri");
            return;
        }
    }

    for (auto _ : state) {
        qb::io::uri uri{raw};
        benchmark::DoNotOptimize(uri.host());
        auto port = uri.u_port();
        benchmark::DoNotOptimize(port);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

// ---------------------------------------------------------------------------
// Parse + materialise the query map (the array/bracket-key heavy case).
// ---------------------------------------------------------------------------
void
BM_Uri_ParseAndQueryLookup(benchmark::State &state) {
    const std::string raw{kComplexQueryUri};

    {
        qb::io::uri probe{raw};
        if (probe.query("q") != "search term" || probe.query("filters[category]") != "books") {
            state.SkipWithError("uri query decode mismatch on kComplexQueryUri");
            return;
        }
    }

    for (auto _ : state) {
        qb::io::uri uri{raw};
        // Touch the lazily-built query map so the parse + decode work is counted.
        auto q    = uri.query("q");
        auto cat  = uri.query("filters[category]");
        auto page = uri.query("page");
        benchmark::DoNotOptimize(q);
        benchmark::DoNotOptimize(cat);
        benchmark::DoNotOptimize(page);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

// ---------------------------------------------------------------------------
// Static percent-encoder over the full printable-ASCII span.
// ---------------------------------------------------------------------------
void
BM_Uri_Encode(benchmark::State &state) {
    const std::string raw{kCodecRoundTrip};

    {
        if (qb::io::uri::decode(qb::io::uri::encode(raw)) != raw) {
            state.SkipWithError("encode/decode is not a round-trip");
            return;
        }
    }

    for (auto _ : state) {
        std::string out = qb::io::uri::encode(raw);
        benchmark::DoNotOptimize(out.data());
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

// ---------------------------------------------------------------------------
// Static percent-decoder over a fully-escaped query value.
// ---------------------------------------------------------------------------
void
BM_Uri_Decode(benchmark::State &state) {
    const std::string raw{kEncodedQueryValue};

    {
        if (qb::io::uri::decode(raw) != " !@#$%^&*()") {
            state.SkipWithError("decode mismatch on kEncodedQueryValue");
            return;
        }
    }

    for (auto _ : state) {
        std::string out = qb::io::uri::decode(raw);
        benchmark::DoNotOptimize(out.data());
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(raw.size()));
    state.SetItemsProcessed(state.iterations());
}

} // namespace

BENCHMARK(BM_Uri_ParseComplex)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Uri_ParseSimple)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Uri_ParseIpv6)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Uri_ParseAndQueryLookup)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Uri_Encode)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Uri_Decode)->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();

/**
 * @file qbm/http/tests/benchmark/middleware/compression.bench.cpp
 * @brief Google-benchmark harness for qb::http compression (codec + middleware negotiation).
 *
 * Measures the two halves of the response-compression hot path with no socket
 * and no event loop:
 *
 *   - CODEC: `qb::http::Body::compress("gzip"|"deflate")` and the matching
 *     `uncompress()` round-trip — the raw zlib encode/decode that runs per
 *     message. Bytes/sec are reported against the ORIGINAL (uncompressed) size,
 *     and the in-loop assert decompresses back to confirm a lossless round-trip
 *     (the same guarantee every "compressed" assertion in
 *     tests/unit/middleware/middleware-compression.cpp enforces).
 *
 *   - MIDDLEWARE: `CompressionMiddleware::process(ctx)` followed by
 *     `ctx->execute_hook(PRE_RESPONSE_SEND)` — the full server path that parses
 *     the client `Accept-Encoding` header (q-values, wildcard, explicit `q=0`,
 *     malformed `q`), picks the server-preferred encoding, and compresses the
 *     body. This mirrors the Context-driven flow pinned by the seed's
 *     `ResponseHookSurvivesMiddlewareDestruction` case. Distinct Accept-Encoding
 *     shapes are benchmarked so the q-value parser cost is visible:
 *       * "gzip, deflate"        — straightforward two-token list
 *       * "gzip;q=0, deflate;q=1"— explicit refusal + selection (HonorsQValues…)
 *       * "*"                    — wildcard -> first server preference
 *       * "br"                   — no common encoding (gzip+deflate only) -> skip
 *
 * The round-trip corpus (highly-compressible repeated bytes at 256B..64KiB) is
 * seeded from the body shapes the unit test compresses (e.g. `std::string(512,
 * 'Z')`, `std::string(2048, 'A')`, `std::string(4096, 'B')`).
 *
 * Requires zlib: the codec lives behind `QB_HAS_COMPRESSION`. The integrator
 * gates this bench REQUIRES compression; the whole file is compiled only when
 * `QB_HAS_COMPRESSION` is defined (a BENCHMARK_MAIN with zero registrations is
 * emitted otherwise so the target still links).
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

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <benchmark/benchmark.h>

#include <qb/utility/build_macros.h>

#include "../http.h"
#include "../middleware/compression.h"
#include "../routing/middleware.h"

#ifdef QB_HAS_COMPRESSION

namespace {

/**
 * @brief Minimal capturing session satisfying the Context session concept.
 *
 * Mirrors tests/shared/MockMiddlewareSession's surface (operator<<,
 * get_response_ref, reset) without pulling the gtest-bearing fixture header
 * into this benchmark TU.
 */
struct BenchSession {
    qb::http::Response _response;

    [[nodiscard]] qb::http::Response &
    get_response_ref() {
        return _response;
    }

    BenchSession &
    operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void
    reset() {
        _response = qb::http::Response();
    }
};

using Session = BenchSession;

// Highly-compressible corpus: a repeating ASCII pattern (mirrors the unit
// test's `string(N, 'A')` / `string(N, 'Z')` bodies — predictable ratio).
std::string
make_corpus(std::size_t size) {
    std::string s(size, '\0');
    for (std::size_t i = 0; i < size; ++i) {
        s[i] = static_cast<char>('A' + (i % 8u)); // 8-symbol alphabet -> compresses well
    }
    return s;
}

// Build a GET Request carrying a given Accept-Encoding header.
qb::http::Request
make_request(const std::string &accept_encoding) {
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("/bench");
    req.major_version = 1;
    req.minor_version = 1;
    if (!accept_encoding.empty()) {
        req.set_header("Accept-Encoding", accept_encoding);
    }
    return req;
}

// ===========================================================================
// CODEC: Body::compress + uncompress round-trip.
// ===========================================================================
void
BM_Compress_BodyRoundTrip(benchmark::State &state, const std::string &encoding) {
    const auto        size     = static_cast<std::size_t>(state.range(0));
    const std::string original = make_corpus(size);

    // Out-of-loop correctness: round-trip must reproduce the original.
    {
        qb::http::Body b;
        b = original;
        b.compress(encoding);
        b.uncompress(encoding);
        std::string restored = b.as<std::string>();
        if (restored != original) {
            state.SkipWithError("compress/uncompress round-trip did not reproduce the original body");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        qb::http::Body b;
        b = original;
        state.ResumeTiming();

        b.compress(encoding);
        b.uncompress(encoding);
        auto restored_size = b.size();
        benchmark::DoNotOptimize(restored_size);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(size));
    state.SetItemsProcessed(state.iterations());
}

// Encode-only path (the per-response cost the middleware actually pays).
void
BM_Compress_BodyEncodeOnly(benchmark::State &state, const std::string &encoding) {
    const auto        size     = static_cast<std::size_t>(state.range(0));
    const std::string original = make_corpus(size);

    {
        qb::http::Body b;
        b = original;
        b.compress(encoding);
        if (b.size() >= original.size()) {
            state.SkipWithError("compressible corpus did not shrink under compression");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        qb::http::Body b;
        b = original;
        state.ResumeTiming();

        b.compress(encoding);
        auto compressed_size = b.size();
        benchmark::DoNotOptimize(compressed_size);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(size));
    state.SetItemsProcessed(state.iterations());
}

// ===========================================================================
// MIDDLEWARE: process() + PRE_RESPONSE_SEND hook (Accept-Encoding negotiation).
//
// `expect_encoded` is the Content-Encoding the negotiation should select for
// the given Accept-Encoding header ("" when no common encoding exists).
// ===========================================================================
void
BM_Compress_MiddlewareNegotiate(benchmark::State &state, const std::string &accept_encoding, const std::string &expect_encoded) {
    const auto        size     = static_cast<std::size_t>(state.range(0));
    const std::string original = make_corpus(size);

    qb::http::CompressionOptions opts;
    opts.compress_responses(true).min_size_to_compress(10).preferred_encodings({"gzip", "deflate"});

    auto session = std::make_shared<Session>();

    auto build_ctx = [&]() {
        auto ctx = std::make_shared<qb::http::Context<Session>>(
            make_request(accept_encoding), qb::http::Response{}, session, [](qb::http::Context<Session> &) {},
            std::weak_ptr<qb::http::RouterCore<Session>>{});
        ctx->response().set_header("Content-Type", "text/plain");
        ctx->response().body() = original;
        return ctx;
    };

    // Out-of-loop correctness: confirm the negotiated encoding matches expectation.
    {
        auto comp_mw = qb::http::compression_middleware<Session>(opts);
        auto ctx     = build_ctx();
        comp_mw->process(ctx);
        ctx->execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND);
        const std::string got = std::string(ctx->response().header("Content-Encoding"));
        if (got != expect_encoded) {
            state.SkipWithError("negotiated Content-Encoding did not match the expected value");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        auto comp_mw = qb::http::compression_middleware<Session>(opts);
        auto ctx     = build_ctx();
        state.ResumeTiming();

        comp_mw->process(ctx);
        ctx->execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND);
        auto body_size = ctx->response().body().size();
        benchmark::DoNotOptimize(body_size);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(size));
    state.SetItemsProcessed(state.iterations());
}

} // namespace

// --- CODEC round-trip + encode-only ----------------------------------------
BENCHMARK_CAPTURE(BM_Compress_BodyRoundTrip, gzip, std::string("gzip"))
    ->Arg(256)
    ->Arg(2048)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(BM_Compress_BodyRoundTrip, deflate, std::string("deflate"))
    ->Arg(256)
    ->Arg(2048)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(BM_Compress_BodyEncodeOnly, gzip, std::string("gzip"))
    ->Arg(2048)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(BM_Compress_BodyEncodeOnly, deflate, std::string("deflate"))
    ->Arg(2048)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kMicrosecond);

// --- MIDDLEWARE negotiation (q-value parse + select + compress) ------------
BENCHMARK_CAPTURE(BM_Compress_MiddlewareNegotiate, list_gzip, std::string("gzip, deflate"), std::string("gzip"))
    ->Arg(2048)
    ->Arg(16 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(BM_Compress_MiddlewareNegotiate, qvalue_gzip0, std::string("gzip;q=0, deflate;q=1"), std::string("deflate"))
    ->Arg(2048)
    ->Arg(16 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kMicrosecond);
BENCHMARK_CAPTURE(BM_Compress_MiddlewareNegotiate, wildcard, std::string("*"), std::string("gzip"))
    ->Arg(2048)
    ->Arg(16 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kMicrosecond);
// "br" only -> no common encoding -> body stays uncompressed (Content-Encoding empty).
BENCHMARK_CAPTURE(BM_Compress_MiddlewareNegotiate, br_unsupported, std::string("br"), std::string(""))
    ->Arg(2048)
    ->Arg(16 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();

#else // QB_HAS_COMPRESSION

// zlib not available: emit an empty main so the target still links/runs.
BENCHMARK_MAIN();

#endif // QB_HAS_COMPRESSION

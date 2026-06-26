/**
 * @file qbm/http/tests/benchmark/middleware/cors.bench.cpp
 * @brief Google-benchmark harness for qb::http CORS origin matching + process().
 *
 * Measures the CORS request hot path with no socket and no event loop, across
 * the four origin-match strategies the middleware supports:
 *
 *   - MATCHER: `CorsOptions::is_origin_allowed(origin)` called directly — the
 *     pure decision function, benchmarked per strategy so their relative cost is
 *     visible:
 *       * Exact     — linear scan of an allow-list (hit + miss).
 *       * Wildcard  — single "*" entry, always allowed.
 *       * Regex     — `std::regex_match` against the (length-guarded) patterns
 *         (`http://.*\.example\.com` style — mirrors the seed's
 *         RegexOriginMatching case), including the MAX_ORIGIN_LENGTH short-circuit
 *         on an over-length adversarial input (the ReDoSProtectionRegexTimeout
 *         shape).
 *       * Function  — a user predicate (the FunctionOriginMatching case).
 *
 *   - PROCESS: `CorsMiddleware::process(ctx)` over a Context — the full path that
 *     reads the `Origin` header, runs the matcher, writes the
 *     `Access-Control-Allow-Origin` / `Vary` headers, and (for OPTIONS preflight)
 *     negotiates methods + headers and short-circuits with 204. Two shapes:
 *       * a simple GET with an allowed Origin, and
 *       * an OPTIONS preflight (Access-Control-Request-Method/-Headers set),
 *         mirroring the seed's PreflightRequest case.
 *
 * Origin sets, regex patterns, the function matcher, the preflight header values,
 * and the over-length adversarial origin are all seeded from
 * tests/unit/middleware/middleware-cors.cpp so the benchmark exercises the same
 * code those tests pin. No TLS / zlib dependency — pure routing + std::regex.
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

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>

#include <benchmark/benchmark.h>

#include "../http.h"
#include "../middleware/cors.h"
#include "../routing/middleware.h"

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

// ===========================================================================
// MATCHER: CorsOptions::is_origin_allowed() per strategy.
// ===========================================================================

// Exact allow-list matching (hit near the end of the list + a guaranteed miss).
void
BM_Cors_MatchExact(benchmark::State &state) {
    qb::http::CorsOptions opts;
    opts.origins({"http://site1.com", "https://site2.org", "http://example.com", "https://app.example.com", "http://allowed.final.com"});

    const std::string hit  = "http://allowed.final.com";
    const std::string miss = "http://othersite.net";

    {
        if (!opts.is_origin_allowed(hit) || opts.is_origin_allowed(miss)) {
            state.SkipWithError("exact matcher decision did not match expectation");
            return;
        }
    }

    for (auto _ : state) {
        bool a = opts.is_origin_allowed(hit);
        bool b = opts.is_origin_allowed(miss);
        benchmark::DoNotOptimize(a);
        benchmark::DoNotOptimize(b);
    }
    state.SetItemsProcessed(state.iterations() * 2);
}

// Wildcard "*" — every origin is allowed.
void
BM_Cors_MatchWildcard(benchmark::State &state) {
    qb::http::CorsOptions opts;
    opts.origins({"*"});

    const std::string origin = "http://random.org";

    {
        if (!opts.is_origin_allowed(origin)) {
            state.SkipWithError("wildcard matcher should allow any origin");
            return;
        }
    }

    for (auto _ : state) {
        bool a = opts.is_origin_allowed(origin);
        benchmark::DoNotOptimize(a);
    }
    state.SetItemsProcessed(state.iterations());
}

// Regex matching (seed: RegexOriginMatching) — hit, miss, and the over-length
// adversarial input that the MAX_ORIGIN_LENGTH guard must short-circuit.
void
BM_Cors_MatchRegex(benchmark::State &state) {
    qb::http::CorsOptions opts;
    opts.origin_patterns({"http://.*\\.example\\.com", "http://example\\.com"});

    const std::string hit  = "http://sub.example.com";
    const std::string miss = "http://another.domain.com";

    {
        if (!opts.is_origin_allowed(hit) || opts.is_origin_allowed(miss)) {
            state.SkipWithError("regex matcher decision did not match expectation");
            return;
        }
    }

    for (auto _ : state) {
        bool a = opts.is_origin_allowed(hit);
        bool b = opts.is_origin_allowed(miss);
        benchmark::DoNotOptimize(a);
        benchmark::DoNotOptimize(b);
    }
    state.SetItemsProcessed(state.iterations() * 2);
}

// Over-length adversarial origin against a catastrophic-backtracking pattern:
// the length guard must reject it (return false) BEFORE std::regex runs, so this
// stays near-instant. Mirrors the seed's ReDoSProtectionRegexTimeout.
void
BM_Cors_MatchRegexOverlongGuard(benchmark::State &state) {
    qb::http::CorsOptions opts;
    opts.origin_patterns({"^(a+)+$"});

    std::string evil = std::string(qb::http::cors_security_limits::MAX_ORIGIN_LENGTH + 1, 'a');
    evil += "!";

    {
        if (opts.is_origin_allowed(evil)) {
            state.SkipWithError("over-length origin must be rejected by the length guard");
            return;
        }
    }

    for (auto _ : state) {
        bool a = opts.is_origin_allowed(evil);
        benchmark::DoNotOptimize(a);
    }
    state.SetItemsProcessed(state.iterations());
}

// Custom function predicate (seed: FunctionOriginMatching).
void
BM_Cors_MatchFunction(benchmark::State &state) {
    qb::http::CorsOptions opts;
    opts.origin_matcher([](const std::string &origin) -> bool {
        return origin == "http://allowed.by.function.com" || origin == "https://another.functional.match";
    });

    const std::string hit  = "http://allowed.by.function.com";
    const std::string miss = "http://denied.by.function.com";

    {
        if (!opts.is_origin_allowed(hit) || opts.is_origin_allowed(miss)) {
            state.SkipWithError("function matcher decision did not match expectation");
            return;
        }
    }

    for (auto _ : state) {
        bool a = opts.is_origin_allowed(hit);
        bool b = opts.is_origin_allowed(miss);
        benchmark::DoNotOptimize(a);
        benchmark::DoNotOptimize(b);
    }
    state.SetItemsProcessed(state.iterations() * 2);
}

// ===========================================================================
// PROCESS: full CorsMiddleware::process(ctx).
// ===========================================================================

qb::http::Request
make_request(qb::http::method method_val, const std::string &origin) {
    qb::http::Request req;
    req.method() = method_val;
    req.uri()    = qb::io::uri("/cors_test");
    req.major_version = 1;
    req.minor_version = 1;
    if (!origin.empty()) {
        req.set_header("Origin", origin);
    }
    return req;
}

// Simple (non-preflight) GET with an allowed origin: matcher + header writes.
void
BM_Cors_ProcessSimpleGet(benchmark::State &state) {
    auto cors_mw = qb::http::cors_middleware<Session>(qb::http::CorsOptions().origins({"http://example.com"}));
    auto session = std::make_shared<Session>();

    auto build_ctx = [&]() {
        return std::make_shared<qb::http::Context<Session>>(
            make_request(qb::http::method::GET, "http://example.com"), qb::http::Response{}, session,
            [](qb::http::Context<Session> &) {}, std::weak_ptr<qb::http::RouterCore<Session>>{});
    };

    {
        auto ctx = build_ctx();
        cors_mw->process(ctx);
        if (std::string(ctx->response().header("Access-Control-Allow-Origin")) != "http://example.com") {
            state.SkipWithError("simple GET did not reflect the allowed origin");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        auto ctx = build_ctx();
        state.ResumeTiming();

        cors_mw->process(ctx);
        auto allow = std::string(ctx->response().header("Access-Control-Allow-Origin"));
        benchmark::DoNotOptimize(allow);
    }
    state.SetItemsProcessed(state.iterations());
}

// OPTIONS preflight (seed: PreflightRequest): method + header negotiation,
// 204 short-circuit.
void
BM_Cors_ProcessPreflight(benchmark::State &state) {
    qb::http::CorsOptions opts;
    opts.origins({"http://localhost:3000"})
        .methods({"GET", "POST", "OPTIONS"})
        .headers({"Content-Type", "Authorization"})
        .max_age(std::chrono::seconds(3600));
    auto cors_mw = qb::http::cors_middleware<Session>(opts);
    auto session = std::make_shared<Session>();

    auto build_ctx = [&]() {
        auto req = make_request(qb::http::method::OPTIONS, "http://localhost:3000");
        req.set_header("Access-Control-Request-Method", "POST");
        req.set_header("Access-Control-Request-Headers", "Content-Type, Authorization");
        return std::make_shared<qb::http::Context<Session>>(std::move(req), qb::http::Response{}, session,
                                                            [](qb::http::Context<Session> &) {},
                                                            std::weak_ptr<qb::http::RouterCore<Session>>{});
    };

    {
        auto ctx = build_ctx();
        cors_mw->process(ctx);
        if (ctx->response().status() != qb::http::status::NO_CONTENT) {
            state.SkipWithError("preflight did not short-circuit with 204 No Content");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        auto ctx = build_ctx();
        state.ResumeTiming();

        cors_mw->process(ctx);
        auto code = ctx->response().status().code();
        benchmark::DoNotOptimize(code);
    }
    state.SetItemsProcessed(state.iterations());
}

} // namespace

BENCHMARK(BM_Cors_MatchExact)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Cors_MatchWildcard)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Cors_MatchRegex)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Cors_MatchRegexOverlongGuard)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Cors_MatchFunction)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Cors_ProcessSimpleGet)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Cors_ProcessPreflight)->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();

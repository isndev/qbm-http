/**
 * @file qbm/http/tests/benchmark/routing/route-match.bench.cpp
 * @brief Benchmarks for the qb-http radix-tree route matcher + middleware-chain dispatch.
 *
 * Measures the hot path `qb::http::Router<Session>::route()` end-to-end: split the
 * request target into segments, walk the compiled @ref qb::http::RadixTree, bind +
 * percent-decode path parameters, run the matched task chain (global middleware +
 * handler), and finalize the response into the session. This is the per-request CPU
 * cost a server pays for *dispatch* alone (no IO loop, no socket, no parser).
 *
 * The route tables and request shapes are lifted verbatim from the matcher's
 * canonical specs so the benchmark exercises exactly the code those tests pin:
 *   - static / parameter / wildcard precedence (static > param > wildcard) and the
 *     mixed param + wildcard-tail shape (`:user` then `*itemPath`)  ..  router-match.cpp
 *   - the global-middleware + per-request task-chain pump  ..  router-pipeline-integration.cpp
 *
 * Dimensions swept:
 *   - match KIND: static-hit / param-hit / wildcard-hit / miss(404).
 *   - route-table SIZE: how many sibling routes the radix tree carries.
 *   - middleware-chain DEPTH: how many global pass-through middlewares run before
 *     the matched handler.
 *
 * Per-iteration setup (building the Request, resetting the session) is hoisted out
 * of the timed region with PauseTiming/ResumeTiming so the reported number isolates
 * `route()`. One out-of-loop correctness assert guards against a bench that silently
 * stops matching and reports bogus throughput.
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
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "../http.h"     // qb::http::Request, Response, method, status
#include "../routing.h"  // qb::http::Router, Context

namespace {

// ---------------------------------------------------------------------------
// Minimal capturing session: the router writes the finalized Response through
// `session << response`. We keep only what dispatch needs (an id() + a status we
// can assert on) so the bench measures route(), not session bookkeeping.
// ---------------------------------------------------------------------------
struct BenchSession {
    qb::http::Response _response;
    qb::http::status   _last_status = qb::http::status::OK;
    bool               _handler_ran = false;

    BenchSession &
    operator<<(const qb::http::Response &response) {
        _response    = response;
        _last_status = response.status();
        return *this;
    }

    [[nodiscard]] int
    id() const noexcept {
        return 0;
    }

    void
    reset() {
        _response    = qb::http::Response();
        _last_status = qb::http::status::OK;
        _handler_ran = false;
    }
};

// A trivial handler that marks the session and finalizes 200 OK — the same shape as
// the seed tests' make_verifying_handler, minus the param snapshot we do not need.
auto
ok_handler() {
    return [](std::shared_ptr<qb::http::Context<BenchSession>> ctx) {
        if (auto s = ctx->session())
            s->_handler_ran = true;
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    };
}

// A pass-through global middleware: the cost the chain adds per hop is exactly one
// CONTINUE through the task pump (mirrors AllInOneMiddleware::Behavior::CONTINUE).
void
add_passthrough_middleware(qb::http::Router<BenchSession> &router, int depth) {
    for (int i = 0; i < depth; ++i) {
        router.use(
            [](std::shared_ptr<qb::http::Context<BenchSession>> /*ctx*/, std::function<void()> next) {
                next();
            },
            "PassThroughMw" + std::to_string(i));
    }
}

// Build a router carrying `extra_static` filler static routes at /pad/N plus the
// canonical static/param/wildcard/mixed routes the matcher spec pins, then compile.
std::unique_ptr<qb::http::Router<BenchSession>>
make_router(int extra_static, int mw_depth) {
    auto router = std::make_unique<qb::http::Router<BenchSession>>();

    add_passthrough_middleware(*router, mw_depth);

    // Filler static routes to grow the radix tree breadth (route-table size sweep).
    for (int i = 0; i < extra_static; ++i)
        router->get("/pad/route" + std::to_string(i), ok_handler());

    // Canonical shapes (verbatim from router-match.cpp precedence + mixed cases).
    router->get("/r/specific", ok_handler());                 // static hit target
    router->get("/users/:id", ok_handler());                  // param hit target
    router->get("/files/*filepath", ok_handler());            // wildcard hit target
    router->get("/data/:user/details/*itemPath", ok_handler()); // mixed param+wildcard

    router->compile();
    return router;
}

// Drive one request through the matcher with setup hoisted out of the timed region.
void
run_match(benchmark::State &state, int extra_static, int mw_depth, qb::http::method m, const std::string &path,
          qb::http::status expected) {
    auto router = make_router(extra_static, mw_depth);

    // One out-of-loop correctness assert: a broken matcher must not report numbers.
    {
        auto session = std::make_shared<BenchSession>();
        qb::http::Request probe;
        probe.method()      = m;
        probe.uri()         = qb::io::uri(path);
        probe.major_version = 1;
        probe.minor_version = 1;
        (void) router->route(session, probe);
        if (session->_last_status != expected) {
            state.SkipWithError("route() produced unexpected status for path: " + path);
            return;
        }
    }

    auto session = std::make_shared<BenchSession>();

    for (auto _ : state) {
        state.PauseTiming();
        session->reset();
        qb::http::Request request;
        request.method()      = m;
        request.uri()         = qb::io::uri(path);
        request.major_version = 1;
        request.minor_version = 1;
        state.ResumeTiming();

        auto ctx = router->route(session, request);
        benchmark::DoNotOptimize(ctx);
        benchmark::DoNotOptimize(session->_last_status);
    }

    state.SetItemsProcessed(state.iterations());
}

// --- Match-kind benchmarks (route-table size on the X axis) -----------------

void
BM_Route_StaticHit(benchmark::State &state) {
    run_match(state, static_cast<int>(state.range(0)), 0, qb::http::method::GET, "/r/specific", qb::http::status::OK);
}

void
BM_Route_ParamHit(benchmark::State &state) {
    run_match(state, static_cast<int>(state.range(0)), 0, qb::http::method::GET, "/users/12345", qb::http::status::OK);
}

void
BM_Route_WildcardHit(benchmark::State &state) {
    run_match(state, static_cast<int>(state.range(0)), 0, qb::http::method::GET, "/files/documents/reports/q4.pdf",
              qb::http::status::OK);
}

void
BM_Route_MixedParamWildcardHit(benchmark::State &state) {
    run_match(state, static_cast<int>(state.range(0)), 0, qb::http::method::GET,
              "/data/user123/details/path/to/item.json", qb::http::status::OK);
}

void
BM_Route_Miss404(benchmark::State &state) {
    run_match(state, static_cast<int>(state.range(0)), 0, qb::http::method::GET, "/this/path/does/not/exist",
              qb::http::status::NOT_FOUND);
}

// --- Middleware-chain depth benchmark (chain depth on the X axis) -----------
//
// A fixed, small route table; the variable is how many global pass-through
// middlewares the task pump runs before the matched handler.
void
BM_Route_StaticHitMiddlewareDepth(benchmark::State &state) {
    run_match(state, 0, static_cast<int>(state.range(0)), qb::http::method::GET, "/r/specific", qb::http::status::OK);
}

} // namespace

BENCHMARK(BM_Route_StaticHit)->Arg(0)->Arg(16)->Arg(256)->ArgNames({"routes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_ParamHit)->Arg(0)->Arg(16)->Arg(256)->ArgNames({"routes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_WildcardHit)->Arg(0)->Arg(16)->Arg(256)->ArgNames({"routes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_MixedParamWildcardHit)->Arg(0)->Arg(16)->Arg(256)->ArgNames({"routes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_Miss404)->Arg(0)->Arg(16)->Arg(256)->ArgNames({"routes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_StaticHitMiddlewareDepth)->Arg(0)->Arg(2)->Arg(8)->Arg(32)->ArgNames({"chain_depth"})->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();

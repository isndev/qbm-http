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
 *   - configured lifecycle hooks (0/1/8) and synchronous conditional selection.
 *
 * Per-iteration setup (building the Request, resetting the session) is hoisted out
 * of the timed region with PauseTiming/ResumeTiming so the reported number isolates
 * `route()`. Out-of-loop probes check the response, handler count, decoded path
 * parameters, hook phases and conditional branch before reporting a number.
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
#include <functional>
#include <initializer_list>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include <qbm/http/http.h> // qb::http::Request, Response, method, status
#include <qbm/http/middleware/conditional.h>
#include <qbm/http/routing.h> // qb::http::Router, Context

namespace {

// ---------------------------------------------------------------------------
// Minimal capturing session: the router writes the finalized Response through
// `session << response`. We keep only what dispatch needs (an id() + a status we
// can assert on) so the bench measures route(), not session bookkeeping.
// ---------------------------------------------------------------------------
struct BenchSession {
    qb::http::Response         _response;
    qb::http::status           _last_status     = qb::http::status::OK;
    std::size_t                _response_writes = 0;
    std::size_t                _handler_calls   = 0;
    std::size_t                _if_calls        = 0;
    std::size_t                _else_calls      = 0;
    std::array<std::size_t, 3> _hook_calls{};
    std::size_t                _hook_order_errors = 0;

    BenchSession &
    operator<<(const qb::http::Response &response) {
        _response    = response;
        _last_status = response.status();
        ++_response_writes;
        return *this;
    }

    [[nodiscard]] int
    id() const noexcept {
        return 0;
    }

    void
    reset() {
        _response          = qb::http::Response();
        _last_status       = qb::http::status::OK;
        _response_writes   = 0;
        _handler_calls     = 0;
        _if_calls          = 0;
        _else_calls        = 0;
        _hook_calls        = {};
        _hook_order_errors = 0;
    }
};

// A trivial handler that marks the session and finalizes 200 OK.
auto
ok_handler() {
    return [](std::shared_ptr<qb::http::Context<BenchSession>> ctx) {
        if (auto s = ctx->session())
            ++s->_handler_calls;
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    };
}

// A healthy synchronous conditional child: record selection and continue the
// same request. Both branches share this work; only the selected counter differs.
class SelectedChild final : public qb::http::IMiddleware<BenchSession> {
    bool _is_if;

public:
    explicit SelectedChild(bool is_if)
        : _is_if(is_if) {}

    void
    process(std::shared_ptr<qb::http::Context<BenchSession>> ctx) override {
        if (auto s = ctx->session()) {
            if (_is_if)
                ++s->_if_calls;
            else
                ++s->_else_calls;
        }
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }

    [[nodiscard]] std::string
    name() const override {
        return _is_if ? "SelectedIf" : "SelectedElse";
    }

    void
    cancel() override {}
};

// A pass-through global middleware: the cost the chain adds per hop is exactly one
// CONTINUE through the task pump (mirrors AllInOneMiddleware::Behavior::CONTINUE).
void
add_passthrough_middleware(qb::http::Router<BenchSession> &router, int depth) {
    for (int i = 0; i < depth; ++i) {
        router.use([](std::shared_ptr<qb::http::Context<BenchSession>> /*ctx*/, std::function<void()> next) { next(); },
                   "PassThroughMw" + std::to_string(i));
    }
}

// Build a router carrying `extra_static` filler static routes at /pad/N plus the
// canonical static/param/wildcard/mixed routes the matcher spec pins, then compile.
std::unique_ptr<qb::http::Router<BenchSession>>
make_router(int extra_static, int mw_depth, int hook_count, bool conditional) {
    auto router = std::make_unique<qb::http::Router<BenchSession>>();

    add_passthrough_middleware(*router, mw_depth);
    for (int i = 0; i < hook_count; ++i) {
        // The mutable cookie is copied into each Context by the router. It
        // verifies phase order without registering a hook during dispatch.
        router->add_lifecycle_hook([cookie = 0](auto &ctx, qb::http::HookPoint point) mutable {
            if (auto s = ctx.session()) {
                switch (point) {
                    case qb::http::HookPoint::PRE_ROUTING:
                        if (cookie != 0)
                            ++s->_hook_order_errors;
                        cookie = 1;
                        ++s->_hook_calls[0];
                        break;
                    case qb::http::HookPoint::PRE_HANDLER_EXECUTION:
                        if (cookie != 1)
                            ++s->_hook_order_errors;
                        cookie = 2;
                        ++s->_hook_calls[1];
                        break;
                    case qb::http::HookPoint::POST_HANDLER_EXECUTION:
                        if (cookie != 2)
                            ++s->_hook_order_errors;
                        cookie = 3;
                        ++s->_hook_calls[2];
                        break;
                    default:
                        break;
                }
            }
        });
    }
    if (conditional) {
        router->use(qb::http::conditional_middleware<BenchSession>([](const auto &ctx) { return ctx->request().header("X-Branch") == "if"; },
                                                                   std::make_shared<SelectedChild>(true),
                                                                   std::make_shared<SelectedChild>(false)));
    }

    // Filler static routes to grow the radix tree breadth (route-table size sweep).
    for (int i = 0; i < extra_static; ++i)
        router->get("/pad/route" + std::to_string(i), ok_handler());

    // Canonical shapes (verbatim from router-match.cpp precedence + mixed cases).
    router->get("/r/specific", ok_handler());                   // static hit target
    router->get("/users/:id", ok_handler());                    // param hit target
    router->get("/files/*filepath", ok_handler());              // wildcard hit target
    router->get("/data/:user/details/*itemPath", ok_handler()); // mixed param+wildcard

    router->compile();
    return router;
}

// Drive one request through the matcher with setup hoisted out of the timed region.
using ExpectedParams = std::initializer_list<std::pair<std::string_view, std::string_view>>;

void
run_match(benchmark::State &state, int extra_static, int mw_depth, qb::http::method m, const std::string &path, qb::http::status expected,
          ExpectedParams expected_params = {}, int hook_count = 0, int conditional_branch = -1) {
    auto router = make_router(extra_static, mw_depth, hook_count, conditional_branch >= 0);

    // One out-of-loop oracle covers the full result, not just the response status.
    {
        auto              session = std::make_shared<BenchSession>();
        qb::http::Request probe;
        probe.method() = m;
        probe.uri()    = qb::io::uri(path);
        if (conditional_branch >= 0)
            probe.set_header("X-Branch", conditional_branch == 1 ? "if" : "else");
        probe.major_version = 1;
        probe.minor_version = 1;
        auto ctx            = router->route(session, probe);
        if (!ctx || session->_last_status != expected || session->_response_writes != 1u
            || session->_handler_calls != (expected == qb::http::status::OK ? 1u : 0u)) {
            state.SkipWithError("route() did not produce one expected response/handler for path: " + path);
            return;
        }
        if (ctx->path_parameters().size() != expected_params.size()) {
            state.SkipWithError("route() produced unexpected parameter count for path: " + path);
            return;
        }
        for (const auto &[key, value] : expected_params) {
            if (ctx->path_parameters().get(key) != value) {
                state.SkipWithError("route() produced incorrect decoded parameter for path: " + path);
                return;
            }
        }
        if (session->_hook_order_errors != 0u
            || session->_hook_calls
                   != std::array<std::size_t, 3>{
                       static_cast<std::size_t>(hook_count), static_cast<std::size_t>(hook_count), static_cast<std::size_t>(hook_count)
                   }) {
            state.SkipWithError("route() did not invoke every configured lifecycle hook once per phase");
            return;
        }
        if (session->_if_calls != static_cast<std::size_t>(conditional_branch == 1)
            || session->_else_calls != static_cast<std::size_t>(conditional_branch == 0)) {
            state.SkipWithError("route() selected the wrong conditional middleware child");
            return;
        }
    }

    auto session = std::make_shared<BenchSession>();

    for (auto _ : state) {
        state.PauseTiming();
        session->reset();
        qb::http::Request request;
        request.method() = m;
        request.uri()    = qb::io::uri(path);
        if (conditional_branch >= 0)
            request.set_header("X-Branch", conditional_branch == 1 ? "if" : "else");
        request.major_version = 1;
        request.minor_version = 1;
        state.ResumeTiming();

        auto ctx = router->route(session, request);
        benchmark::DoNotOptimize(ctx);
        benchmark::DoNotOptimize(session->_last_status);
        benchmark::DoNotOptimize(session->_handler_calls);
        benchmark::DoNotOptimize(session->_hook_calls);
        benchmark::DoNotOptimize(session->_hook_order_errors);
        benchmark::DoNotOptimize(session->_if_calls);
        benchmark::DoNotOptimize(session->_else_calls);
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
    run_match(state, static_cast<int>(state.range(0)), 0, qb::http::method::GET, "/users/12345", qb::http::status::OK, {{"id", "12345"}});
}

void
BM_Route_WildcardHit(benchmark::State &state) {
    run_match(state, static_cast<int>(state.range(0)), 0, qb::http::method::GET, "/files/documents/reports/q4.pdf", qb::http::status::OK,
              {{"filepath", "documents/reports/q4.pdf"}});
}

void
BM_Route_MixedParamWildcardHit(benchmark::State &state) {
    run_match(state, static_cast<int>(state.range(0)), 0, qb::http::method::GET, "/data/user123/details/path/to/item.json",
              qb::http::status::OK, {{"user", "user123"}, {"itemPath", "path/to/item.json"}});
}

void
BM_Route_Miss404(benchmark::State &state) {
    run_match(state, static_cast<int>(state.range(0)), 0, qb::http::method::GET, "/this/path/does/not/exist", qb::http::status::NOT_FOUND);
}

// --- Middleware-chain depth benchmark (chain depth on the X axis) -----------
//
// A fixed, small route table; the variable is how many global pass-through
// middlewares the task pump runs before the matched handler.
void
BM_Route_StaticHitMiddlewareDepth(benchmark::State &state) {
    run_match(state, 0, static_cast<int>(state.range(0)), qb::http::method::GET, "/r/specific", qb::http::status::OK);
}

// Fixed table/depth cells isolate the per-context lifecycle cost from the
// existing route-size and middleware-depth sweeps.
void
BM_Route_StaticHitLifecycleHooks(benchmark::State &state) {
    run_match(state, 0, 0, qb::http::method::GET, "/r/specific", qb::http::status::OK, {}, static_cast<int>(state.range(0)));
}

void
BM_Route_ParamHitLifecycleHooks(benchmark::State &state) {
    run_match(state, 256, 0, qb::http::method::GET, "/users/user%20123", qb::http::status::OK, {{"id", "user 123"}},
              static_cast<int>(state.range(0)));
}

void
BM_Route_MixedParamWildcardHitLifecycleHooks(benchmark::State &state) {
    run_match(state, 256, 0, qb::http::method::GET, "/data/user%20123/details/path%20to/item.json", qb::http::status::OK,
              {{"user", "user 123"}, {"itemPath", "path to/item.json"}}, static_cast<int>(state.range(0)));
}

void
BM_Route_StaticHitMiddlewareDepth8LifecycleHooks(benchmark::State &state) {
    run_match(state, 0, 8, qb::http::method::GET, "/r/specific", qb::http::status::OK, {}, static_cast<int>(state.range(0)));
}

void
BM_Route_ConditionalSelectedIf(benchmark::State &state) {
    run_match(state, 0, 0, qb::http::method::GET, "/r/specific", qb::http::status::OK, {}, 0, 1);
}

void
BM_Route_ConditionalSelectedElse(benchmark::State &state) {
    run_match(state, 0, 0, qb::http::method::GET, "/r/specific", qb::http::status::OK, {}, 0, 0);
}

} // namespace

BENCHMARK(BM_Route_StaticHit)->Arg(0)->Arg(16)->Arg(256)->ArgNames({"routes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_ParamHit)->Arg(0)->Arg(16)->Arg(256)->ArgNames({"routes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_WildcardHit)->Arg(0)->Arg(16)->Arg(256)->ArgNames({"routes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_MixedParamWildcardHit)->Arg(0)->Arg(16)->Arg(256)->ArgNames({"routes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_Miss404)->Arg(0)->Arg(16)->Arg(256)->ArgNames({"routes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_StaticHitMiddlewareDepth)->Arg(0)->Arg(2)->Arg(8)->Arg(32)->ArgNames({"chain_depth"})->Unit(benchmark::kNanosecond);

BENCHMARK(BM_Route_StaticHitLifecycleHooks)->Arg(0)->Arg(1)->Arg(8)->ArgNames({"hooks"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_ParamHitLifecycleHooks)->Arg(0)->Arg(1)->Arg(8)->ArgNames({"hooks"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_MixedParamWildcardHitLifecycleHooks)->Arg(0)->Arg(1)->Arg(8)->ArgNames({"hooks"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_StaticHitMiddlewareDepth8LifecycleHooks)->Arg(0)->Arg(1)->Arg(8)->ArgNames({"hooks"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_ConditionalSelectedIf)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Route_ConditionalSelectedElse)->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();

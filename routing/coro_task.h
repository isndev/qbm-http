/**
 * @file qbm/http/routing/coro_task.h
 * @brief Wrapper helpers that adapt coroutine-returning lambdas into the
 *        classical `RouteHandlerFn` / `MiddlewareHandlerFn` signatures.
 *
 * These wrappers are the entry point for the coroutine server-side API:
 * users may register a handler (resp. middleware) as a function returning
 * `qb::io::async::task<void>`, and the wrappers transparently spawn the
 * coroutine, observe cancellation, and auto-complete the request context
 * when the coroutine body finishes &mdash; following the same conventions as
 * the rest of the routing layer (exceptions translate to `500`, ...).
 *
 * Policy:
 *   - A coroutine **route handler** defaults to
 *     `AsyncTaskResult::COMPLETE` when it returns normally without the
 *     user having explicitly called `ctx->complete(...)`. Rationale: the
 *     handler is the leaf of the processing chain and the natural end
 *     state is "response ready".
 *   - A coroutine **middleware** defaults to `AsyncTaskResult::CONTINUE`
 *     under the same conditions. Rationale: the natural role of a
 *     middleware is to let the next task run unless it decides otherwise.
 *   - In both cases, if the user already called `ctx->complete(...)` or
 *     `ctx->cancel()` before `co_return`, the wrapper **does not**
 *     override that decision &mdash; the existing outcome wins.
 *
 * Exceptions thrown from the coroutine body are caught, logged with route
 * context if available, and translated into a `500 Internal Server Error`
 * with `AsyncTaskResult::ERROR`, mirroring `RouteLambdaTask`.
 *
 * Safety:
 *   - The coroutine body receives a `std::shared_ptr<Context<Session>>`,
 *     so the context is guaranteed to outlive every suspension point the
 *     body may hit.
 *   - The spawn target is bound to the **current** coro scheduler
 *     (`qb::io::async::coro_scheduler()`), which is thread-local and the
 *     same scheduler used throughout `qb-io`. This preserves the strict
 *     mono-thread-per-listener contract of the framework.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include <concepts>
#include <functional>
#include <memory>
#include <type_traits>
#include <utility>

#include <qb/io/async/coroutine.h>

#include "../logger.h"
#include "../types.h" // For qb::http::status::INTERNAL_SERVER_ERROR
#include "./context.h"
#include "./types.h"

namespace qb::http {

/**
 * @brief Concept satisfied by callables usable as a coroutine route handler.
 *
 * Matches any callable whose invocation with a `std::shared_ptr<Context<Session>>`
 * yields a `qb::io::async::task<void>`.
 */
template <typename F, typename SessionType>
concept CoroRouteHandler = requires(F f, std::shared_ptr<Context<SessionType>> ctx) {
    { f(ctx) } -> std::same_as<qb::io::async::task<void>>;
};

/**
 * @brief Concept satisfied by callables usable as a coroutine middleware handler.
 *
 * Same shape as `CoroRouteHandler`: the middleware signature is `task<void>(ctx)`
 * (no explicit `next` parameter &mdash; the framework automatically proceeds to
 * the next task on normal coroutine completion unless the middleware called
 * `ctx->complete(...)` itself).
 */
template <typename F, typename SessionType>
concept CoroMiddlewareHandler = requires(F f, std::shared_ptr<Context<SessionType>> ctx) {
    { f(ctx) } -> std::same_as<qb::io::async::task<void>>;
};

namespace detail {

/// Policy selector: where to land when the coroutine body returns normally
/// without having called `ctx->complete(...)` or `ctx->cancel()`.
enum class DefaultCoroOutcome { COMPLETE_RESPONSE, CONTINUE_CHAIN };

template <typename SessionType, typename CoroFn>
[[nodiscard]] inline std::function<void(std::shared_ptr<Context<SessionType>>)>
make_coro_task_runner(CoroFn handler, DefaultCoroOutcome default_outcome, const char *kind) {
    return [handler = std::move(handler), default_outcome, kind](std::shared_ptr<Context<SessionType>> ctx) {
        if (!ctx) {
            LOG_HTTP_ERROR("Coro " << kind << ": null context; dropping");
            return;
        }

        auto spawn = [handler, default_outcome, kind, ctx]() mutable -> qb::io::async::task<void> {
            const auto completion_count_before = ctx->completion_count();
            try {
                co_await handler(ctx);
                // Auto-complete only if user code did not already signal an outcome.
                if (ctx->completion_count() == completion_count_before && !ctx->is_completed() && !ctx->is_cancelled()) {
                    ctx->complete(default_outcome == DefaultCoroOutcome::COMPLETE_RESPONSE ? AsyncTaskResult::COMPLETE
                                                                                           : AsyncTaskResult::CONTINUE);
                }
            } catch (const std::exception &e) {
                LOG_HTTP_ERROR("Coro " << kind << " exception: method=" << std::to_string(ctx->request().method())
                                       << " path=" << ctx->request().uri().path() << " what=" << e.what());
                if (!ctx->is_completed() && !ctx->is_cancelled()) {
                    ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                    ctx->response().body()   = "Internal server error in coroutine handler.";
                    ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                    ctx->complete(AsyncTaskResult::ERROR);
                }
            } catch (...) {
                LOG_HTTP_ERROR("Coro " << kind << " unknown exception: method=" << std::to_string(ctx->request().method())
                                       << " path=" << ctx->request().uri().path());
                if (!ctx->is_completed() && !ctx->is_cancelled()) {
                    ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                    ctx->response().body()   = "Unknown internal server error in coroutine handler.";
                    ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                    ctx->complete(AsyncTaskResult::ERROR);
                }
            }
            co_return;
        };

        qb::io::async::coro_scheduler().spawn(std::move(spawn));
    };
}

/// Wraps a coroutine route handler into a classical `RouteHandlerFn`.
/// Default outcome on normal return is `AsyncTaskResult::COMPLETE`.
template <typename SessionType, typename CoroFn>
[[nodiscard]] RouteHandlerFn<SessionType>
wrap_coro_route_handler(CoroFn &&handler) {
    return make_coro_task_runner<SessionType>(std::forward<CoroFn>(handler), DefaultCoroOutcome::COMPLETE_RESPONSE, "route");
}

/// Wraps a coroutine middleware into a classical `MiddlewareHandlerFn`.
/// Default outcome on normal return is `AsyncTaskResult::CONTINUE`.
///
/// Note: the resulting `MiddlewareHandlerFn` ignores the classical `next`
/// callback &mdash; the framework itself drives task chaining once the
/// coroutine completes, through `ctx->complete(...)`. Users who want to
/// short-circuit can write `ctx->complete(COMPLETE)` before `co_return`.
template <typename SessionType, typename CoroFn>
[[nodiscard]] MiddlewareHandlerFn<SessionType>
wrap_coro_middleware_handler(CoroFn &&handler) {
    auto runner = make_coro_task_runner<SessionType>(std::forward<CoroFn>(handler), DefaultCoroOutcome::CONTINUE_CHAIN, "middleware");
    return [runner = std::move(runner)](std::shared_ptr<Context<SessionType>> ctx, std::function<void()> /*next*/) {
        runner(std::move(ctx));
    };
}

} // namespace detail

/**
 * @brief Adapt a coroutine-returning lambda into a classical `RouteHandlerFn`.
 *
 * Expected signature of @p handler:
 * @code
 * qb::io::async::task<void> (std::shared_ptr<qb::http::Context<Session>>);
 * @endcode
 *
 * Usage:
 * @code
 * router.get("/search", qb::http::coro_handler<MySession>(
 *     [](auto ctx) -> qb::io::async::task<void> {
 *         auto reply = co_await qb::http::GET(build_upstream(ctx));
 *         ctx->response() = std::move(reply.response);
 *         co_return;
 *     }));
 * @endcode
 *
 * On normal coroutine return, the wrapper calls
 * `ctx->complete(AsyncTaskResult::COMPLETE)` unless the body already
 * completed or cancelled the context. Exceptions escape the body are
 * caught, logged, and translated into `500 Internal Server Error`.
 *
 * @tparam SessionType The session type of the router the handler targets.
 * @tparam CoroFn      Deduced type of the coroutine lambda.
 * @param  handler     The coroutine-returning callable to wrap.
 * @return A `RouteHandlerFn<SessionType>` suitable for `router.get(...)`,
 *         `router.post(...)`, etc.
 */
template <typename SessionType, typename CoroFn>
requires CoroRouteHandler<CoroFn, SessionType>
[[nodiscard]] inline RouteHandlerFn<SessionType>
coro_handler(CoroFn &&handler) {
    return detail::wrap_coro_route_handler<SessionType>(std::forward<CoroFn>(handler));
}

/**
 * @brief Adapt a coroutine-returning lambda into a classical `MiddlewareHandlerFn`.
 *
 * Expected signature of @p handler:
 * @code
 * qb::io::async::task<void> (std::shared_ptr<qb::http::Context<Session>>);
 * @endcode
 *
 * The coroutine body does **not** receive a `next` callback; the
 * framework proceeds to the next task when the coroutine completes
 * normally (default outcome: `AsyncTaskResult::CONTINUE`). To
 * short-circuit the chain, call `ctx->complete(AsyncTaskResult::COMPLETE)`
 * (or any other outcome) before `co_return`.
 *
 * Usage:
 * @code
 * router.use(qb::http::coro_middleware<MySession>(
 *     [](auto ctx) -> qb::io::async::task<void> {
 *         co_await qb::io::async::sleep(0.010); // e.g. rate-limit window
 *         ctx->request().set_header("X-Seen", "true");
 *         co_return;
 *     }));
 * @endcode
 *
 * @tparam SessionType The session type of the router the middleware targets.
 * @tparam CoroFn      Deduced type of the coroutine lambda.
 * @param  handler     The coroutine-returning callable to wrap.
 * @return A `MiddlewareHandlerFn<SessionType>` suitable for `router.use(...)`.
 */
template <typename SessionType, typename CoroFn>
requires CoroMiddlewareHandler<CoroFn, SessionType>
[[nodiscard]] inline MiddlewareHandlerFn<SessionType>
coro_middleware(CoroFn &&handler) {
    return detail::wrap_coro_middleware_handler<SessionType>(std::forward<CoroFn>(handler));
}

} // namespace qb::http

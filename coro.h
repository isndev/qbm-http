/**
 * @file qbm/http/coro.h
 * @brief Coroutine primitives for the qbm-http module.
 *
 * This header provides the single awaiter type and factory used by every
 * coroutine-friendly entry point exposed by `qbm/http`. It mirrors the
 * design already proven in `qbm/redis` and `qbm/pgsql`:
 *
 *   - A lightweight `http_awaiter<T, Operation>` that adapts any
 *     callback-based asynchronous operation into something you can
 *     `co_await` from a `qb::io::async::task<...>`.
 *   - A `make_awaiter<T>(op)` factory using a `std::function`-typed
 *     operation so return types stay simple in public headers.
 *   - A `qb::http::run_sync(awaitable)` convenience alias over
 *     `qb::io::async::run_sync` for "drive to completion on the current
 *     I/O thread" from synchronous code (tests, `main`, &hellip;).
 *
 * Ownership / safety contract &mdash; identical to the one in
 * `qbm/redis/redis.h` (`redis_awaiter`):
 *
 *   - An awaiter is single-shot, non-copyable, non-movable in practice
 *     (the caller constructs it as a prvalue returned by a factory, and
 *     `co_await`s it immediately).
 *   - Late callback invocations &mdash; where the underlying operation
 *     fires *after* the awaiter has been destroyed &mdash; are handled
 *     by a `shared_ptr<bool>` alive sentinel. If the awaiter goes away
 *     before the callback runs, the callback becomes a no-op.
 *   - Resumption happens through the per-listener
 *     `qb::io::async::coro_scheduler()`, guaranteeing that the caller's
 *     I/O thread runs the continuation (strict mono-thread model).
 *
 * Usage:
 *
 * @code
 * // Bridging a callback API into a coroutine:
 * qb::http::async::awaiter<qb::http::async::Reply>
 * get_async(qb::http::Request r, qb::duration timeout = qb::duration::zero()) {
 *     return qb::http::async::make_awaiter<qb::http::async::Reply>(
 *         [req = std::move(r), timeout](auto complete) mutable {
 *             qb::http::async::GET(std::move(req),
 *                 [complete](qb::http::async::Reply&& reply) {
 *                     complete(std::move(reply));
 *                 },
 *                 timeout);
 *         });
 * }
 *
 * // Blocking entry point (tests, main):
 * auto reply = qb::http::run_sync(get_async(Request{"http://api/x"}));
 * @endcode
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <atomic>
#include <coroutine>
#include <functional>
#include <memory>
#include <type_traits>
#include <utility>

#include <qb/io/async/coroutine.h>
#include <qb/io/async/coroutine/utils.h>

namespace qb::http::async {

    /**
     * @class http_awaiter
     * @brief Generic awaiter adapting a callback-based asynchronous operation.
     *
     * The operation is stored inside the awaiter and invoked once in
     * `await_suspend(h)`. The awaiter passes a completion handler to the
     * operation; whatever value that handler receives (of type `T`) becomes
     * the value of the `co_await` expression.
     *
     * The awaiter is reference-captured by `qb::io::async::run_sync` and may
     * outlive the enclosing expression, so we hold everything by value and
     * use a `shared_ptr<bool>` alive sentinel to guard against late
     * callbacks after the awaiter has been destroyed.
     *
     * @tparam T         Value type yielded by the operation (must be
     *                   default-constructible so that a spurious cancellation
     *                   can still satisfy `await_resume`).
     * @tparam Operation Callable taking a completion handler
     *                   `std::function<void(T&&)>` (or any invocable with
     *                   the same signature). Invoked exactly once on
     *                   suspension.
     */
    template<typename T, typename Operation>
    class http_awaiter {
        static_assert(std::is_default_constructible_v<T>,
                      "http_awaiter<T>: T must be default-constructible for cancellation safety");

        T                       _result{};
        std::coroutine_handle<> _handle{};
        std::shared_ptr<bool>   _alive{std::make_shared<bool>(true)};
        std::shared_ptr<std::atomic<bool>> _completed{
            std::make_shared<std::atomic<bool>>(false)
        };
        Operation               _op;

    public:
        using value_type = T;

        explicit http_awaiter(Operation op) noexcept(std::is_nothrow_move_constructible_v<Operation>)
            : _op(std::move(op)) {}

        http_awaiter(const http_awaiter&)            = delete;
        http_awaiter& operator=(const http_awaiter&) = delete;
        http_awaiter(http_awaiter&&)                 = delete;
        http_awaiter& operator=(http_awaiter&&)      = delete;

        ~http_awaiter() {
            if (_alive) *_alive = false;
        }

        [[nodiscard]] bool await_ready() const noexcept { return false; }

        void await_suspend(std::coroutine_handle<> h) {
            _handle = h;
            auto alive = _alive;
            auto completed = _completed;
            _op([this, alive, completed](T&& value) {
                if (!*alive) {
                    return;
                }
                bool expected = false;
                if (!completed->compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
                    return;
                }
                _result = std::move(value);
                if (_handle) {
                    qb::io::async::coro_scheduler().schedule_resume(_handle);
                }
            });
        }

        [[nodiscard]] T await_resume() noexcept(std::is_nothrow_move_constructible_v<T>) {
            return std::move(_result);
        }
    };

    /**
     * @brief Convenience alias over `http_awaiter` with a type-erased `std::function` operation.
     *
     * Using `std::function` here keeps the return type spellable in public
     * headers (e.g. as the return of `qb::http::GET(Request, double)`), at
     * the cost of one small-buffer-optimised allocation per call. Hot paths
     * can still use `http_awaiter<T, Lambda>` directly for zero-alloc.
     */
    template<typename T>
    using awaiter = http_awaiter<T, std::function<void(std::function<void(T&&)>)>>;

    /**
     * @brief Build an `awaiter<T>` from a callback-based asynchronous operation.
     *
     * The @p op is invoked exactly once inside `await_suspend` with a
     * completion callable that must be called at most once.
     *
     * @tparam T    Type yielded by the operation.
     * @tparam Func Operation type; deducible from the argument.
     * @param  op   The operation to drive.
     */
    template<typename T, typename Func>
    [[nodiscard]] auto make_awaiter(Func&& op) {
        return awaiter<T>(std::forward<Func>(op));
    }

} // namespace qb::http::async

namespace qb::http {

    /**
     * @brief Drive an HTTP awaiter to completion on the current I/O thread.
     *
     * Thin re-export of `qb::io::async::run_sync`. It exists only so that
     * code that has already `#include`d `qbm/http/coro.h` (or pulled in
     * `qbm/http/http.h` which transitively does) can call
     * `qb::http::run_sync(...)` without having to reach into the `qb::io`
     * namespace. Strictly equivalent to the `qb::io::async` alias.
     *
     * @code
     * // Typical test / main usage (the *only* supported way to block on
     * // an HTTP call &mdash; there is no `qb::http::GET(req) -> Response`
     * // anymore):
     * auto reply    = qb::http::run_sync(qb::http::GET(Request{"http://api/x"}));
     * auto& resp    = reply.response;
     * @endcode
     */
    template<typename Awaitable>
    auto run_sync(Awaitable&& awaitable)
        -> decltype(qb::io::async::run_sync(std::forward<Awaitable>(awaitable))) {
        return qb::io::async::run_sync(std::forward<Awaitable>(awaitable));
    }

} // namespace qb::http

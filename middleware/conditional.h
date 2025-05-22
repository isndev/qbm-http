/**
 * @file qbm/http/middleware/conditional.h
 * @brief Defines ConditionalMiddleware for routing logic.
 *
 * This file contains the `ConditionalMiddleware` class template, which allows
 * for the conditional execution of one of two child middleware instances based on
 * a predicate function evaluated against the request context. This enables dynamic
 * routing or processing paths within the middleware chain.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <memory>
#include <functional>
#include <string>
#include <stdexcept>
#include <utility>

#include "../routing/middleware.h"

namespace qb::http {

/**
 * @brief A middleware that conditionally executes one of two other child middlewares, or continues if no suitable child is run.
 *
 * This middleware evaluates a predicate function against the current request context.
 * - If the predicate returns `true`, the `if_middleware` is executed.
 * - If the predicate returns `false` and an `else_middleware` is provided, the `else_middleware` is executed.
 * - If the predicate returns `false` and no `else_middleware` is provided, this middleware simply calls `ctx->complete(AsyncTaskResult::CONTINUE)`
 *   to pass control to the next task in the main chain.
 *
 * The responsibility for calling `ctx->complete()` with an appropriate `AsyncTaskResult` is delegated
 * to the child middleware if one is executed. If no child middleware is executed (predicate is `false` and
 * no `else_middleware` exists), this `ConditionalMiddleware` itself ensures the chain continues.
 *
 * @tparam SessionType The type of the session object managed by the router, used by `Context`.
 */
template <typename SessionType>
class ConditionalMiddleware : public IMiddleware<SessionType> {
public:
    /** @brief Convenience alias for a shared pointer to the request context. */
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    /**
     * @brief Defines the function signature for the predicate.
     * The predicate takes a constant shared pointer to the context and returns `true` if the condition
     * for executing the `if_middleware` is met, `false` otherwise.
     */
    using Predicate = std::function<bool(const ContextPtr& context)>;
    /**
     * @brief Convenience alias for a shared pointer to an `IMiddleware` instance,
     * representing a child middleware to be conditionally executed.
     */
    using ChildMiddlewarePtr = std::shared_ptr<IMiddleware<SessionType>>;
    
    /**
     * @brief Constructs a `ConditionalMiddleware`.
     *
     * @param predicate The function to evaluate for conditional execution. Must not be null.
     * @param if_middleware The middleware to execute if the predicate returns `true`. Must not be null.
     * @param else_middleware Optional: The middleware to execute if the predicate returns `false`. Can be `nullptr`.
     * @param name An optional name for this middleware instance, useful for logging or debugging.
     * @throws std::invalid_argument if `predicate` or `if_middleware` is null.
     */
    ConditionalMiddleware(
        Predicate predicate,
        ChildMiddlewarePtr if_middleware,
        ChildMiddlewarePtr else_middleware = nullptr,
        std::string name = "ConditionalMiddleware"
    ) : _predicate(std::move(predicate)),
        _if_middleware(std::move(if_middleware)),
        _else_middleware(std::move(else_middleware)),
        _name(std::move(name)) {
        if (!_predicate) {
            throw std::invalid_argument("ConditionalMiddleware: predicate cannot be null.");
        }
        if (!_if_middleware) {
            throw std::invalid_argument("ConditionalMiddleware: if_middleware cannot be null.");
        }
    }
    
    /**
     * @brief Handles the incoming request by evaluating the predicate and either delegating
     * to a child middleware or directly continuing the middleware chain.
     * @param ctx The shared `Context` for the current request.
     */
    void process(ContextPtr ctx) override {
        if (_predicate(ctx)) {
            _if_middleware->process(ctx);
        } else if (_else_middleware) {
            _else_middleware->process(ctx);
        } else {
            ctx->complete(AsyncTaskResult::CONTINUE);
        }
    }
    
    /**
     * @brief Gets the configured name of this middleware instance.
     * @return The name of the middleware.
     */
    [[nodiscard]] std::string name() const noexcept override {
        return _name;
    }

    /**
     * @brief Handles a cancellation notification.
     * For this middleware, cancellation is typically propagated to the currently active child middleware (if any)
     * by the `Context` itself when `Context::cancel()` is called on it. This middleware itself does not
     * usually hold long-running asynchronous state that needs explicit cancellation here.
     */
    void cancel() noexcept override {
        // If child middleware were stateful and held by this class directly (not just via context execution),
        // one might call _if_middleware->cancel() or _else_middleware->cancel() here.
        // However, the current design implies context manages cancellation of the active task.
    }
    
private:
    Predicate _predicate; ///< The predicate function to evaluate.
    ChildMiddlewarePtr _if_middleware;   ///< Middleware to execute if predicate is true.
    ChildMiddlewarePtr _else_middleware; ///< Optional middleware if predicate is false.
    std::string _name;        ///< Name of this middleware instance.
};

/**
 * @brief Factory function to create a `std::shared_ptr` to a `ConditionalMiddleware` instance.
 *
 * @tparam SessionType The session type used by the HTTP context.
 * @param predicate The function to evaluate for conditional execution.
 * @param if_middleware The middleware to execute if the predicate returns `true`.
 * @param else_middleware Optional: The middleware to execute if the predicate returns `false`. Defaults to `nullptr`.
 * @param name An optional name for the middleware instance. Defaults to "ConditionalMiddleware".
 * @return A `std::shared_ptr<ConditionalMiddleware<SessionType>>`.
 * @throws std::invalid_argument if `predicate` or `if_middleware` is null (via `ConditionalMiddleware` constructor).
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<ConditionalMiddleware<SessionType>>
conditional_middleware(
    typename ConditionalMiddleware<SessionType>::Predicate predicate,
    std::shared_ptr<IMiddleware<SessionType>> if_middleware,
    std::shared_ptr<IMiddleware<SessionType>> else_middleware = nullptr,
    const std::string& name = "ConditionalMiddleware"
) {
    return std::make_shared<ConditionalMiddleware<SessionType>>(
        std::move(predicate),
        std::move(if_middleware),
        std::move(else_middleware),
        name
    );
}

} // namespace qb::http 
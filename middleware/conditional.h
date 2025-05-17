#pragma once

#include <memory>
#include <functional>
#include <string>
#include <stdexcept>

#include "../routing/middleware.h"

namespace qb::http {

/**
 * @brief A middleware that conditionally executes one of two other child middlewares, or continues if no suitable child is run.
 *
 * This middleware evaluates a predicate function against the current request context.
 * - If the predicate returns true, the `if_middleware` is executed.
 * - If the predicate returns false and an `else_middleware` is provided, the `else_middleware` is executed.
 * - If the predicate returns false and no `else_middleware` is provided, this middleware simply continues the chain.
 *
 * The responsibility for calling `ctx->complete()` is delegated to the executed child middleware.
 * If no child middleware is executed (predicate false and no else branch), this `ConditionalMiddleware` calls `ctx->complete(AsyncTaskResult::CONTINUE)`.
 *
 * @tparam SessionType The type of the session object managed by the router.
 */
template <typename SessionType>
class ConditionalMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    /**
     * @brief A function type that takes the request context and returns true if a condition is met, false otherwise.
     */
    using Predicate = std::function<bool(const ContextPtr&)>;
    /**
     * @brief A type alias for a shared pointer to an IMiddleware instance, representing a child middleware.
     */
    using ChildMiddlewarePtr = std::shared_ptr<IMiddleware<SessionType>>;
    
    /**
     * @brief Constructs a ConditionalMiddleware.
     *
     * @param predicate The function to evaluate for conditional execution. Must not be null.
     * @param if_middleware The middleware to execute if the predicate returns true. Must not be null.
     * @param else_middleware Optional middleware to execute if the predicate returns false. Can be nullptr.
     * @param name An optional name for this middleware instance (for logging/debugging).
     * @throws std::invalid_argument if predicate or if_middleware is null.
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
     * @brief Handles the incoming request by evaluating the predicate and delegating to a child middleware or continuing.
     * @param ctx The shared context for the current request.
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
     * @brief Gets the name of this middleware instance.
     * @return The name of the middleware.
     */
    std::string name() const override {
        return _name;
    }

    /**
     * @brief Handles cancellation. For this middleware, it's typically a no-op as it delegates quickly.
     * The child middleware, if engaged in an async operation, would be responsible for its own cancellation response.
     */
    void cancel() override {
        // No specific cancellation logic needed here; the active child middleware would be cancelled by the context.
    }
    
private:
    Predicate _predicate;
    ChildMiddlewarePtr _if_middleware;
    ChildMiddlewarePtr _else_middleware;
    std::string _name;
};

/**
 * @brief Factory function to create a ConditionalMiddleware instance.
 *
 * @tparam SessionType The session type.
 * @param predicate The function to evaluate for conditional execution.
 * @param if_middleware The middleware to execute if the predicate returns true.
 * @param else_middleware Optional middleware to execute if the predicate returns false.
 * @param name An optional name for the middleware.
 * @return A shared pointer to the created ConditionalMiddleware.
 */
template <typename SessionType>
std::shared_ptr<ConditionalMiddleware<SessionType>>
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
#pragma once

#include <memory>
#include <functional>
#include <string>
#include "./middleware_interface.h"

namespace qb::http {

/**
 * @brief Middleware that executes another middleware based on a condition
 */
template <typename Session, typename String = std::string>
class ConditionalMiddleware : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    using Predicate = std::function<bool(const Context&)>;
    
    /**
     * @brief Constructor
     * @param predicate Function that determines if the middleware should execute
     * @param if_middleware Middleware to execute if predicate returns true
     * @param else_middleware Middleware to execute if predicate returns false (optional)
     * @param name Middleware name
     */
    ConditionalMiddleware(
        Predicate predicate,
        MiddlewarePtr<Session, String> if_middleware,
        MiddlewarePtr<Session, String> else_middleware = nullptr,
        std::string name = "ConditionalMiddleware"
    ) : _predicate(std::move(predicate)),
        _if_middleware(std::move(if_middleware)),
        _else_middleware(std::move(else_middleware)),
        _name(std::move(name)) {}
    
    /**
     * @brief Process a request
     * @param ctx Request context
     * @param callback Callback to call when processing is complete
     * @return Middleware result
     */
    MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) override {
        // Evaluate the predicate
        if (_predicate(ctx)) {
            return _if_middleware->process(ctx, callback);
        } else if (_else_middleware) {
            return _else_middleware->process(ctx, callback);
        }
        
        // If no else_middleware, simply continue
        auto result = MiddlewareResult::Continue();
        if (callback) callback(result);
        return result;
    }
    
    /**
     * @brief Get the middleware name
     */
    std::string name() const override {
        return _name;
    }
    
private:
    Predicate _predicate;
    MiddlewarePtr<Session, String> _if_middleware;
    MiddlewarePtr<Session, String> _else_middleware;
    std::string _name;
};

/**
 * @brief Create a conditional middleware
 */
template <typename Session, typename String = std::string>
auto conditional_middleware(
    typename ConditionalMiddleware<Session, String>::Predicate predicate,
    MiddlewarePtr<Session, String> if_middleware,
    MiddlewarePtr<Session, String> else_middleware = nullptr,
    const std::string& name = "ConditionalMiddleware"
) {
    return std::make_shared<ConditionalMiddleware<Session, String>>(
        std::move(predicate),
        std::move(if_middleware),
        std::move(else_middleware),
        name
    );
}

} // namespace qb::http 
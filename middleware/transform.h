/**
 * @file qbm/http/middleware/transform.h
 * @brief Defines middleware for transforming HTTP requests.
 *
 * This file provides the `TransformMiddleware` class template, which allows for
 * the registration of a custom function to modify an incoming `qb::http::Request` object
 * before it is processed by downstream handlers in the middleware chain.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <memory>      // For std::shared_ptr, std::make_shared
#include <functional>  // For std::function
#include <string>      // For std::string
#include <utility>     // For std::move
// #include <iostream> // Removed: For std::cerr, not for production

#include "../routing/middleware.h" // For IMiddleware, Context, AsyncTaskResult
#include "../request.h"            // For qb::http::Request
#include "../response.h"           // For qb::http::Response (used by Context)
#include "../types.h"              // For qb::http::status enum (qb::http::status::INTERNAL_SERVER_ERROR)

namespace qb::http {

/**
 * @brief Middleware for applying custom transformations to HTTP requests.
 *
 * This middleware allows a user-provided `RequestTransformer` function to be executed,
 * which can modify the `qb::http::Request` object within the `Context`.
 * If the transformer function throws an exception, this middleware will catch it,
 * set a 500 Internal Server Error response, and complete the request processing with an error state.
 *
 * @tparam SessionType The type of the session object managed by the router, used by `Context`.
 */
template <typename SessionType>
class TransformMiddleware : public IMiddleware<SessionType> {
public:
    /** @brief Convenience alias for a shared pointer to the request `Context`. */
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    /** 
     * @brief Defines the signature for a function that can transform an HTTP request.
     * The function receives a mutable reference to the `qb::http::Request` object
     * from the current `Context` and can modify it in place.
     * @param request A mutable reference to the `qb::http::Request` to be transformed.
     */
    using RequestTransformer = std::function<void(Request& request)>; 
    
    /**
     * @brief Constructs a `TransformMiddleware` instance.
     *
     * @param request_transformer An optional `RequestTransformer` function. If `nullptr` (the default),
     *                            this middleware will effectively be a no-op for request transformation
     *                            but will still pass the request down the chain.
     * @param instance_name An optional name for this middleware instance, useful for logging or debugging.
     *                      Defaults to "TransformMiddleware".
     */
    explicit TransformMiddleware(
        RequestTransformer request_transformer = nullptr,
        std::string instance_name = "TransformMiddleware"
    ) noexcept(noexcept(std::function<void(Request& request)>(nullptr)) && noexcept(std::string(std::string())))
      // std::function move constructor is noexcept, std::string move constructor is noexcept.
        : _request_transformer(std::move(request_transformer)),
          _name(std::move(instance_name)) {}
    
    /**
     * @brief Processes the incoming request by applying the configured `RequestTransformer` if one exists.
     *
     * If a `_request_transformer` is set, it is invoked with `ctx->request()`.
     * - If the transformer executes successfully, `ctx->complete(AsyncTaskResult::CONTINUE)` is called.
     * - If the transformer throws any exception, a 500 Internal Server Error response is set on `ctx->response()`,
     *   and `ctx->complete(AsyncTaskResult::ERROR)` is called to halt normal processing and potentially trigger
     *   an error handling chain.
     * If no `_request_transformer` is set, it directly calls `ctx->complete(AsyncTaskResult::CONTINUE)`.
     * @param ctx The shared `Context` for the current request.
     */
    void process(ContextPtr ctx) override { // User transformer can throw
        if (_request_transformer) {
            try {
                _request_transformer(ctx->request());
            } catch (...) { // Catch any exception from the user-provided transformer
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->response().body() = "Error during request transformation."; 
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                ctx->complete(AsyncTaskResult::ERROR); 
                return; 
            }
        }
        
        ctx->complete(AsyncTaskResult::CONTINUE);
    }
    
    /** @brief Gets the configured name of this middleware instance. */
    [[nodiscard]] std::string name() const noexcept override {
        return _name;
    }

    /** 
     * @brief Handles a cancellation notification.
     * This middleware is synchronous in its `process` path with respect to transformation logic.
     * No specific asynchronous operations are initiated by this middleware itself that would need cancellation.
     */
    void cancel() noexcept override {
        // No specific cancellation logic needed.
    }
    
private:
    RequestTransformer _request_transformer; ///< The user-provided request transformation function.
    std::string _name;                       ///< Name of this middleware instance.
};

/**
 * @brief Factory function to create a `std::shared_ptr` to a `TransformMiddleware` instance.
 *
 * @tparam SessionType The session type used by the HTTP context.
 * @param request_transformer An optional `RequestTransformer` function to apply to requests.
 *                            If `nullptr`, the middleware will pass requests through without transformation.
 * @param name An optional name for the middleware instance. Defaults to "TransformMiddleware".
 * @return A `std::shared_ptr<TransformMiddleware<SessionType>>`.
 */
template <typename SessionType>
[[nodiscard]] std::shared_ptr<TransformMiddleware<SessionType>>
transform_middleware(
    typename TransformMiddleware<SessionType>::RequestTransformer request_transformer = nullptr,
    const std::string& name = "TransformMiddleware"
) {
    return std::make_shared<TransformMiddleware<SessionType>>(
        std::move(request_transformer),
        name
    );
}

} // namespace qb::http 
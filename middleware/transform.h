#pragma once

#include <memory>
#include <functional>
#include <string>
#include <iostream>

// New Includes for qb::http routing system
#include "../routing/middleware.h" // Includes IMiddleware, Context, AsyncTaskResult, HookPoint
#include "../request.h"            // For qb::http::Request
#include "../response.h"           // For qb::http::Response

namespace qb::http {

/**
 * @brief Middleware for transforming HTTP requests.
 *
 * This middleware allows registration of a transformer function that can modify
 * the request object before it reaches downstream handlers.
 * Request transformation happens directly in the `handle` method.
 *
 * @tparam SessionType The type of the session object managed by the router.
 */
template <typename SessionType>
class TransformMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    /** 
     * @brief Function signature for transforming a request.
     * The function receives a mutable reference to the `qb::http::Request` object.
     */
    using RequestTransformer = std::function<void(Request& request)>; 
    
    /**
     * @brief Constructs a TransformMiddleware instance.
     *
     * @param request_transformer An optional function to transform the request. Can be nullptr.
     * @param name An optional name for this middleware instance (for logging/debugging).
     */
    TransformMiddleware(
        RequestTransformer request_transformer = nullptr,
        std::string name = "TransformMiddleware"
    ) : _request_transformer(std::move(request_transformer)),
        _name(std::move(name)) {}
    
    /**
     * @brief Handles the incoming request, applying request transformation if configured.
     * @param ctx The shared context for the current request.
     */
    void process(ContextPtr ctx) override {
        if (_request_transformer) {
            std::cerr << "TransformMiddleware [" << _name << "]: _request_transformer is NOT NULL. Proceeding to try-catch." << std::endl;
            try {
                _request_transformer(ctx->request());
            } catch (...) { // Simplified to catch-all
                std::cerr << "TransformMiddleware [" << _name << "]: CAUGHT ANY EXCEPTION in request_transformer." << std::endl;
                std::cerr << "TransformMiddleware [" << _name << "]: Context state BEFORE complete(ERROR): is_completed=" 
                          << ctx->is_completed() << ", is_cancelled=" << ctx->is_cancelled() << std::endl;
                ctx->response().status_code = qb::http::status::HTTP_STATUS_INTERNAL_SERVER_ERROR;
                ctx->response().body() = "Error during request transformation (any exception)."; 
                ctx->complete(AsyncTaskResult::ERROR); 
                std::cerr << "TransformMiddleware [" << _name << "]: Context state AFTER complete(ERROR): is_completed=" 
                          << ctx->is_completed() << ", is_cancelled=" << ctx->is_cancelled() << std::endl;
                std::cerr << "TransformMiddleware [" << _name << "]: Returning early due to any exception." << std::endl;
                return; 
            }
        } else {
            std::cerr << "TransformMiddleware [" << _name << "]: _request_transformer IS NULL." << std::endl;
        }
        
        ctx->complete(AsyncTaskResult::CONTINUE);
    }
    
    /** @brief Gets the name of this middleware instance. */
    std::string name() const override {
        return _name;
    }

    /** @brief Handles cancellation; a no-op for this middleware. */
    void cancel() override {
        // No specific cancellation logic needed.
    }
    
private:
    RequestTransformer _request_transformer;
    std::string _name;
};

/**
 * @brief Factory function to create a TransformMiddleware instance.
 *
 * @tparam SessionType The session type.
 * @param request_transformer An optional function to transform requests.
 * @param name Optional name for the middleware instance.
 * @return A shared pointer to the created TransformMiddleware.
 */
template <typename SessionType>
std::shared_ptr<TransformMiddleware<SessionType>>
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
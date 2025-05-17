#pragma once

#include <memory>
#include <functional>
#include <string>
#include <vector>
#include <qb/system/container/unordered_map.h>

// New Includes for qb::http routing system
#include "../routing/middleware.h" // Includes IMiddleware, Context, AsyncTaskResult
#include "../types.h"              // For http_status
#include "../response.h"           // For qb::http::Response
#include "../request.h"            // For qb::http::Request (used by Context)

namespace qb::http {

/**
 * @brief Centralized error handling middleware designed to be part of the router's error chain.
 *
 * This middleware is invoked when a preceding task in the request processing chain calls
 * `ctx->complete(AsyncTaskResult::ERROR)`. It allows for custom responses based on HTTP status codes
 * or a generic error handler.
 *
 * The `handle` method inspects `ctx->response().status_code` (which might have been set by
 * the erroring task or defaulted by the router core) and dispatches to a registered handler.
 * After a custom handler potentially modifies the response, this middleware finalizes the
 * error response by calling `ctx->complete(AsyncTaskResult::COMPLETE)`.
 *
 * @tparam SessionType The type of the session object managed by the router.
 */
template <typename SessionType>
class ErrorHandlingMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    /** 
     * @brief Function signature for a generic error handler.
     * @param ctx The request context.
     * @param error_message A descriptive error message. Note: The propagation of this message
     *                      to this handler depends on conventions set by error-originating tasks.
     */
    using ErrorHandler = std::function<void(ContextPtr ctx, const std::string& error_message)>; 
    /** 
     * @brief Function signature for a status-code-specific error handler.
     * @param ctx The request context. The handler should modify `ctx->response()` as needed.
     */
    using StatusHandler = std::function<void(ContextPtr ctx)>;
    
    /**
     * @brief Constructs an ErrorHandlingMiddleware instance.
     * @param name An optional name for this middleware instance (for logging/debugging).
     */
    ErrorHandlingMiddleware(std::string name = "ErrorHandlingMiddleware")
        : _name(std::move(name)) {}
    
    /**
     * @brief Registers a handler for a specific HTTP status code.
     * @param status_code The HTTP status code to handle.
     * @param handler The function to execute when this status code is encountered in the error chain.
     * @return A reference to this ErrorHandlingMiddleware instance for chaining.
     */
    ErrorHandlingMiddleware& on_status(http_status status_code, StatusHandler handler) {
        if (handler) { // Ensure handler is not null
            _status_handlers[status_code] = std::move(handler);
        }
        return *this;
    }
    
    /**
     * @brief Registers a handler for a range of HTTP status codes.
     * The same handler will be used for all codes within the inclusive range [min_status, max_status].
     * @param min_status The minimum HTTP status code in the range.
     * @param max_status The maximum HTTP status code in the range.
     * @param handler The function to execute.
     * @return A reference to this ErrorHandlingMiddleware instance for chaining.
     */
    ErrorHandlingMiddleware& on_status_range(http_status min_status, http_status max_status, StatusHandler handler) {
        if (handler) {
            for (int code = static_cast<int>(min_status); code <= static_cast<int>(max_status); ++code) {
                if (code >= 100 && code < 600) { // Basic sanity check for HTTP status codes
                    // Only add if no handler already exists for this specific code
                    // This makes the first registered handler (specific or range) win.
                    _status_handlers.try_emplace(static_cast<http_status>(code), handler);
                }
            }
        }
        return *this;
    }
    
    /**
     * @brief Registers a generic error handler to be called if no specific status handler matches.
     * The usefulness of the `error_message` parameter depends on whether erroring tasks provide such details
     * in a standardized way (e.g., by setting a specific key in `ctx->set()`).
     * @param handler The generic error handler function.
     * @return A reference to this ErrorHandlingMiddleware instance for chaining.
     */
    ErrorHandlingMiddleware& on_any_error(ErrorHandler handler) {
        if (handler) { // Ensure handler is not null
            _generic_handler = std::move(handler);
        }
        return *this;
    }
    
    /**
     * @brief Handles the error context when this middleware is invoked in an error chain.
     * It attempts to find a registered handler for the current response status code, 
     * or falls back to a generic handler if one is set. After the handler (if any) modifies
     * the response, this method calls `ctx->complete(AsyncTaskResult::COMPLETE)` to finalize.
     * @param ctx The shared context for the current request, now in an error state.
     */
    void process(ContextPtr ctx) override {
        http_status current_status = ctx->response().status_code;
        auto it = _status_handlers.find(current_status);

        bool handled_by_specific_or_range = false;
        if (it != _status_handlers.end() && it->second) { 
            it->second(ctx); 
            handled_by_specific_or_range = true;
        } 

        if (!handled_by_specific_or_range && _generic_handler) {
            std::string error_message_from_context = "Error encountered: status " + std::to_string(static_cast<int>(current_status));
            
            try {
                // Attempt to get the error message from the context as std::string.
                if(auto err_msg_opt = ctx->template get<std::string>("__error_message")) {
                    if (err_msg_opt.has_value() && !err_msg_opt->empty()) { 
                        error_message_from_context = *err_msg_opt;
                    }
                } 
                // If get<std::string> returns an empty optional (key not found or type mismatch where get returns nullopt for type mismatch),
                // the default message remains.
            } catch (const std::bad_any_cast& e) {
                // This catch block would be relevant if ctx->get<T> threw std::bad_any_cast 
                // on type mismatch instead of returning an empty optional. 
                // Based on previous logs, it seems it might behave this way, or the issue was the set type.
                // QB_LOG_WARN("__error_message in context was not a std::string or key not found: " << e.what());
            }
             _generic_handler(ctx, error_message_from_context);
        }
        ctx->complete(AsyncTaskResult::COMPLETE);
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
    std::string _name;
    qb::unordered_map<http_status, StatusHandler> _status_handlers;
    ErrorHandler _generic_handler;
};

/**
 * @brief Factory function to create an ErrorHandlingMiddleware instance.
 * @tparam SessionType The session type.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created ErrorHandlingMiddleware.
 */
template <typename SessionType>
std::shared_ptr<ErrorHandlingMiddleware<SessionType>>
error_handling_middleware(const std::string& name = "ErrorHandlingMiddleware") {
    return std::make_shared<ErrorHandlingMiddleware<SessionType>>(name);
}

} // namespace qb::http 
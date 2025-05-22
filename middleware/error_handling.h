/**
 * @file qbm/http/middleware/error_handling.h
 * @brief Defines middleware for centralized HTTP error response generation.
 *
 * This file provides the `ErrorHandlingMiddleware` class template. This middleware is designed
 * to be a central point for generating user-friendly error responses. It is typically used
 * in a dedicated error handling chain within the router, invoked when a preceding task signals
 * an error. It allows registering custom handlers for specific HTTP status codes, ranges of codes,
 * or a generic fallback handler.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <memory>      // For std::shared_ptr, std::make_shared
#include <functional>  // For std::function
#include <string>      // For std::string, std::to_string
#include <vector>      // For std::vector (though not directly used in this class members)
#include <utility>     // For std::move

#include <qb/system/container/unordered_map.h> // For qb::unordered_map

#include "../routing/middleware.h" // For IMiddleware, Context, AsyncTaskResult
#include "../types.h"              // For qb::http::status enum
#include "../response.h"           // For qb::http::Response (used by Context)
#include "../request.h"            // For qb::http::Request (used by Context)

namespace qb::http {
    /**
     * @brief Centralized error handling middleware, typically used in a router's dedicated error chain.
     *
     * This middleware is invoked when a task in the main request processing chain calls
     * `ctx->complete(AsyncTaskResult::ERROR)`. It provides a flexible way to customize
     * error responses based on HTTP status codes.
     *
     * The `process` method inspects `ctx->response().status()` (which should have been set
     * appropriately by the task that signaled the error, or by the router core as a default like 500).
     * It then dispatches to a registered handler:
     * 1. A handler for the specific status code (registered via `on_status`).
     * 2. If no specific handler, a handler for a range covering the status code (registered via `on_status_range`).
     *    The first matching range handler registered will be used if multiple ranges overlap.
     * 3. If no status-specific or range handler matches, a generic error handler (registered via `on_any_error`) is called.
     * 4. If no handlers match, the response in the context (potentially a default 500 error) is used.
     *
     * After any custom handler modifies the response, this middleware calls `ctx->complete(AsyncTaskResult::COMPLETE)`
     * to signal that error processing is finished and the response can be sent.
     *
     * @tparam SessionType The type of the session object managed by the router, used by `Context`.
     */
    template<typename SessionType>
    class ErrorHandlingMiddleware : public IMiddleware<SessionType> {
    public:
        /** @brief Convenience alias for a shared pointer to the request `Context`. */
        using ContextPtr = std::shared_ptr<Context<SessionType> >;

        /**
         * @brief Function signature for a generic error handler.
         * @param ctx The request `Context`. The handler can modify `ctx->response()` to customize the error page.
         * @param error_message A descriptive error message. This message is typically constructed by this
         *                      middleware or can be sourced from `ctx->get<std::string>("__error_message")`
         *                      if set by a previous task.
         */
        using ErrorHandler = std::function<void(ContextPtr ctx, const std::string &error_message)>;

        /**
         * @brief Function signature for a status-code-specific error handler.
         * @param ctx The request `Context`. The handler should modify `ctx->response()` to customize
         *            the error page for the specific status code.
         */
        using StatusHandler = std::function<void(ContextPtr ctx)>;

        /**
         * @brief Constructs an `ErrorHandlingMiddleware` instance.
         * @param name An optional name for this middleware instance, useful for logging or debugging.
         *             Defaults to "ErrorHandlingMiddleware".
         */
        explicit ErrorHandlingMiddleware(std::string name = "ErrorHandlingMiddleware") noexcept
            : _name(std::move(name)) {
        }

        /**
         * @brief Registers a handler function for a specific HTTP status code.
         * If a handler for this exact `status_code` already exists, it will be overwritten.
         * @param status_code The `qb::http::status` enum value to handle.
         * @param handler The `StatusHandler` function to execute when this status code is encountered.
         *                The handler should not be null.
         * @return A reference to this `ErrorHandlingMiddleware` instance for chaining.
         */
        ErrorHandlingMiddleware &on_status(qb::http::status status_code, StatusHandler handler) {
            // Map assignment can throw
            if (handler) {
                _status_handlers[status_code] = std::move(handler);
            }
            return *this;
        }

        /**
         * @brief Registers a handler for a range of HTTP status codes (inclusive).
         * The same `handler` will be used for all status codes from `min_status` to `max_status`.
         * If a specific handler for a code within this range was already set by `on_status()`,
         * or by a previously registered overlapping range, `try_emplace` ensures the existing
         * more specific handler is not overwritten by this range handler for that specific code.
         * @param min_status The minimum `qb::http::status` in the range.
         * @param max_status The maximum `qb::http::status` in the range.
         * @param handler The `StatusHandler` function to execute for codes in this range.
         *                The handler should not be null.
         * @return A reference to this `ErrorHandlingMiddleware` instance for chaining.
         */
        ErrorHandlingMiddleware &on_status_range(qb::http::status min_status, qb::http::status max_status,
                                                 StatusHandler handler) {
            // Map emplace can throw
            if (handler) {
                for (int code_val = static_cast<int>(min_status); code_val <= static_cast<int>(max_status); ++
                     code_val) {
                    if (code_val >= 100 && code_val < 600) {
                        // Basic sanity check for HTTP status codes
                        _status_handlers.try_emplace(code_val, handler);
                    }
                }
            }
            return *this;
        }

        /**
         * @brief Registers a generic error handler.
         * This handler is called if no specific status code handler (from `on_status` or `on_status_range`)
         * matches the `ctx->response().status()` when an error occurs.
         * @param handler The generic `ErrorHandler` function. It receives the context and a default error message.
         *                The handler should not be null.
         * @return A reference to this `ErrorHandlingMiddleware` instance for chaining.
         */
        ErrorHandlingMiddleware &on_any_error(ErrorHandler handler) {
            // std::function assignment can throw
            if (handler) {
                _generic_handler = std::move(handler);
            }
            return *this;
        }

        /**
         * @brief Processes the error context by dispatching to an appropriate registered handler.
         *
         * This method is intended to be called by the router when the request context is in an error state.
         * It attempts to find a handler for `ctx->response().status()`. If found, it's executed.
         * Otherwise, if a generic error handler (`_generic_handler`) is registered, it's called.
         * Finally, it calls `ctx->complete(AsyncTaskResult::COMPLETE)` to signal the end of error processing.
         * @param ctx The shared `Context` for the current request, expected to be in an error processing phase.
         */
        void process(ContextPtr ctx) override {
            // User handlers can throw
            qb::http::status current_status = ctx->response().status();
            auto it = _status_handlers.find(current_status);

            bool handled = false;
            if (it != _status_handlers.end() && it->second) {
                // Check if handler is valid (not null)
                try {
                    it->second(ctx);
                } catch (...) {
                    // Log that a status-specific handler threw, then try generic or default.
                    // If logging isn't available: std::cerr << "Exception in status handler for " << current_status << std::endl;
                    // Fall through to generic handler or let response be as is.
                }
                handled = true;
            }

            if (!handled && _generic_handler) {
                std::string error_message_for_generic_handler = "Error encountered: status " + std::to_string(
                                                                    static_cast<int>(current_status));
                if (auto err_msg_from_ctx = ctx->template get<std::string>("__error_message");
                    err_msg_from_ctx && !err_msg_from_ctx->empty()) {
                    error_message_for_generic_handler = *err_msg_from_ctx;
                }
                try {
                    _generic_handler(ctx, error_message_for_generic_handler);
                } catch (...) {
                    // Log that generic handler threw. Response will be as is before this throw.
                    // std::cerr << "Exception in generic error handler for " << current_status << std::endl;
                }
                // handled = true; // Not strictly needed as this is the last resort before default response
            }

            // If no handler was found or successfully executed, the response in ctx remains as set by
            // the erroring task or router core (e.g., a simple 500).
            ctx->complete(AsyncTaskResult::COMPLETE);
        }

        /** @brief Gets the configured name of this middleware instance. */
        [[nodiscard]] std::string name() const noexcept override {
            return _name;
        }

        /** @brief Handles cancellation notification; currently a no-op for this middleware. */
        void cancel() noexcept override {
            // No specific asynchronous operations to cancel within this middleware itself.
        }

    private:
        std::string _name; ///< Name of this middleware instance.
        qb::unordered_map<qb::http::status, StatusHandler> _status_handlers;
        ///< Map of status codes to specific handlers.
        ErrorHandler _generic_handler; ///< Fallback handler for any error if no specific handler is found.
    };

    /**
     * @brief Factory function to create a `std::shared_ptr` to an `ErrorHandlingMiddleware` instance.
     * @tparam SessionType The session type used by the HTTP context.
     * @param name An optional name for the middleware instance. Defaults to "ErrorHandlingMiddleware".
     * @return A `std::shared_ptr<ErrorHandlingMiddleware<SessionType>>`.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<ErrorHandlingMiddleware<SessionType> >
    error_handling_middleware(const std::string &name = "ErrorHandlingMiddleware") {
        return std::make_shared<ErrorHandlingMiddleware<SessionType> >(name);
    }
} // namespace qb::http

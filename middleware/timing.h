/**
 * @file qbm/http/middleware/timing.h
 * @brief Defines middleware for measuring and reporting HTTP request processing time.
 *
 * This file provides the `TimingMiddleware` class template. This middleware captures
 * the start time when a request begins processing and the end time just before the
 * response is sent. It then calculates the duration, reports it via a user-provided
 * callback, and adds an `X-Response-Time` header to the outgoing response.
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
#include <chrono>      // For std::chrono::high_resolution_clock, duration_cast, milliseconds
#include <stdexcept>   // For std::invalid_argument
#include <utility>     // For std::move

#include "../routing/middleware.h" // For IMiddleware, Context, AsyncTaskResult, HookPoint
#include "../response.h"           // For qb::http::Response (used by Context in hook)
// Request.h is not directly needed as Context provides access to request if necessary

namespace qb::http {
    /**
     * @brief Middleware for measuring and reporting the execution time of HTTP requests.
     *
     * This middleware records a timestamp when it first encounters a request. It then
     * registers a lifecycle hook (`HookPoint::PRE_RESPONSE_SEND`) to capture an end timestamp
     * just before the response is sent. The difference is calculated and reported in two ways:
     * 1. Via a user-provided callback function, typically as `std::chrono::milliseconds`.
     * 2. By adding an `X-Response-Time` header to the response, usually in milliseconds (as a double).
     *
     * @tparam SessionType The type of the session object managed by the router, used by `Context`.
     */
    template<typename SessionType>
    class TimingMiddleware : public IMiddleware<SessionType> {
    public:
        /** @brief Convenience alias for a shared pointer to the request `Context`. */
        using ContextPtr = std::shared_ptr<Context<SessionType> >;
        /** @brief The clock type used for timing; `std::chrono::high_resolution_clock` is typically used for performance measurements. */
        using Clock = std::chrono::high_resolution_clock;
        /** @brief Represents a specific point in time captured by the `Clock`. */
        using TimePoint = typename Clock::time_point;
        /** @brief Represents the duration type reported to the user callback, typically `std::chrono::milliseconds`. */
        using Duration = std::chrono::milliseconds;

        /** 
         * @brief Defines the signature for the user-provided callback function that receives the calculated request duration.
         * @param duration The total processing time for the request, as a `std::chrono::milliseconds` value.
         */
        using TimingCallback = std::function<void(const Duration &duration)>;

        /**
         * @brief Constructs a `TimingMiddleware` instance.
         *
         * @param callback The function to be invoked with the measured request duration. This function must not be null.
         * @param instance_name An optional name for this middleware instance, primarily for generating a unique context key
         *                      to store the start time, and potentially for logging if combined with other systems.
         *                      Defaults to "TimingMiddleware".
         * @throws std::invalid_argument if the provided `callback` is null.
         */
        explicit TimingMiddleware(TimingCallback callback, std::string instance_name = "TimingMiddleware")
            : _callback(std::move(callback)), _name(std::move(instance_name)) {
            if (!_callback) {
                throw std::invalid_argument("TimingMiddleware: The provided TimingCallback function cannot be null.");
            }
        }

        /**
         * @brief Processes the incoming request by recording its start time in the context.
         * It then registers a lifecycle hook to be executed at `HookPoint::PRE_RESPONSE_SEND`.
         * This hook calculates the total request duration, invokes the user-provided callback with this duration,
         * and adds an `X-Response-Time` header to the outgoing response.
         * Finally, it calls `ctx->complete(AsyncTaskResult::CONTINUE)` to pass control to the next task.
         * @param ctx The shared `Context` for the current request.
         */
        void process(ContextPtr ctx) override {
            // Hook registration or context set might allocate.
            // Generate a unique context key using the middleware instance name to avoid collisions.
            const std::string start_time_context_key = "__TimingMiddleware_StartTime_" + _name;
            ctx->set(start_time_context_key, Clock::now());

            ctx->add_lifecycle_hook(
                [this, key = start_time_context_key](Context<SessionType> &ctx_ref, HookPoint point) {
                    if (point == HookPoint::PRE_RESPONSE_SEND) {
                        if (auto start_time_opt = ctx_ref.template get<TimePoint>(key)) {
                            TimePoint start_time = *start_time_opt;
                            TimePoint end_time = Clock::now();

                            auto duration_for_callback = std::chrono::duration_cast<Duration>(end_time - start_time);

                            // Format X-Response-Time header value as floating-point milliseconds.
                            auto duration_for_header = std::chrono::duration_cast<std::chrono::duration<double,
                                std::milli> >(end_time - start_time);
                            ctx_ref.response().set_header("X-Response-Time",
                                                          std::to_string(duration_for_header.count()) + "ms");

                            try {
                                _callback(duration_for_callback); // Invoke user callback.
                            } catch (...) {
                                // Suppress exceptions from user-provided callback to avoid disrupting response sending.
                                // Consider logging the callback exception here if a logging facility is available.
                            }
                            // Optionally remove the start time from the context, though usually not critical here.
                            // ctx_ref.remove(key);
                        } else {
                            // Start time not found in context - this indicates an issue with context propagation
                            // or an unexpected state. Log if possible.
                        }
                    }
                });

            ctx->complete(AsyncTaskResult::CONTINUE);
        }

        /** @brief Gets the configured name of this middleware instance. */
        [[nodiscard]] std::string name() const noexcept override {
            return _name;
        }

        /** 
         * @brief Handles a cancellation notification.
         * For this timing middleware, cancellation is a no-op as it does not manage long-running
         * asynchronous tasks that would need explicit interruption.
         */
        void cancel() noexcept override {
            // No specific cancellation logic needed for timing middleware.
        }

    private:
        TimingCallback _callback; ///< User-provided callback to report request duration.
        std::string _name; ///< Name of this middleware instance.
    };

    /**
     * @brief Factory function to create a `std::shared_ptr` to a `TimingMiddleware` instance.
     *
     * @tparam SessionType The session type used by the HTTP context.
     * @param callback The function to be called with the measured request duration (must not be null).
     * @param name An optional name for the middleware instance (defaults to "TimingMiddleware").
     * @return A `std::shared_ptr<TimingMiddleware<SessionType>>`.
     * @throws std::invalid_argument if `callback` is null (via `TimingMiddleware` constructor).
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<TimingMiddleware<SessionType> >
    timing_middleware(
        typename TimingMiddleware<SessionType>::TimingCallback callback,
        const std::string &name = "TimingMiddleware"
    ) {
        return std::make_shared<TimingMiddleware<SessionType> >(
            std::move(callback),
            name
        );
    }
} // namespace qb::http 

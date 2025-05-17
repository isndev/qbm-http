#pragma once

#include <memory>
#include <functional>
#include <string>
#include <chrono>
#include <stdexcept>

// New Includes for qb::http routing system
#include "../routing/middleware.h" // Includes IMiddleware, Context, AsyncTaskResult, HookPoint
// No direct need for Request/Response headers if only timing and using hooks.

namespace qb::http {

/**
 * @brief Middleware for measuring and reporting the execution time of requests.
 *
 * This middleware captures a timestamp when it first handles a request. It then registers
 * a lifecycle hook to capture another timestamp when the request processing is complete.
 * The duration between these two points is calculated and reported via a user-provided callback.
 *
 * @tparam SessionType The type of the session object managed by the router.
 */
template <typename SessionType>
class TimingMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    /** @brief The clock type used for timing, typically a high-resolution clock. */
    using Clock = std::chrono::high_resolution_clock;
    /** @brief Represents a point in time captured by the clock. */
    using TimePoint = typename Clock::time_point;
    /** @brief Represents the duration, typically in milliseconds, reported by the middleware. */
    using Duration = std::chrono::milliseconds;
    /** 
     * @brief Function signature for the callback that receives the execution duration.
     * @param duration The calculated execution time of the request.
     */
    using TimingCallback = std::function<void(const Duration& duration)>;
    
    /**
     * @brief Constructs a TimingMiddleware instance.
     *
     * @param callback The function to be called with the measured request duration. Must not be null.
     * @param name An optional name for this middleware instance (for logging/debugging).
     * @throws std::invalid_argument if the provided callback is null.
     */
    TimingMiddleware(TimingCallback callback, std::string name = "TimingMiddleware")
        : _callback(std::move(callback)), _name(std::move(name)) {
        if (!_callback) {
            throw std::invalid_argument("TimingMiddleware: The provided callback function cannot be null.");
        }
    }
    
    /**
     * @brief Handles the incoming request by recording the start time and setting up a lifecycle hook
     *        to calculate and report the duration upon request completion.
     * @param ctx The shared context for the current request.
     */
    void process(ContextPtr ctx) override {
        // Generate a unique key for storing the start time in the context, 
        // incorporating the middleware's name to avoid potential collisions if multiple TimingMiddleware instances are used.
        const std::string start_time_context_key = "__TimingMiddleware_StartTime_" + _name;
        ctx->set(start_time_context_key, Clock::now());
        
        // Add a lifecycle hook that will be executed when the request processing is fully complete.
        ctx->add_lifecycle_hook([this, key = start_time_context_key](Context<SessionType>& ctx_ref, HookPoint point) {
            if (point == HookPoint::PRE_RESPONSE_SEND) {
                if (auto start_time_opt = ctx_ref.template get<TimePoint>(key)) {
                    TimePoint start_time = *start_time_opt;
                    TimePoint end_time = Clock::now();
                    
                    // Calculate duration for the callback (std::chrono::milliseconds)
                    auto duration_ms = std::chrono::duration_cast<Duration>(end_time - start_time);
                    
                    // Calculate duration for the header (double, milliseconds)
                    auto duration_fp_ms = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(end_time - start_time);
                    ctx_ref.response().set_header("X-Response-Time", std::to_string(duration_fp_ms.count()));
                    
                    // Invoke the user-provided callback with the calculated duration.
                    // The null check for _callback was done in the constructor.
                    _callback(duration_ms);
                    
                    // Optionally remove the start time from the context, though it's not strictly necessary
                    // as the context will be destroyed shortly after this hook.
                    // ctx_ref.remove(key);
                } else {
                    // This case (start time not found in context) should ideally not happen if set correctly.
                    // Consider logging an error if such a situation is encountered.
                }
            }
        });
        
        // Continue processing the middleware chain.
        ctx->complete(AsyncTaskResult::CONTINUE);
    }
    
    /** @brief Gets the name of this middleware instance. */
    std::string name() const override {
        return _name;
    }

    /** @brief Handles cancellation; a no-op as timing is passive. */
    void cancel() override {
        // No specific cancellation logic needed for timing middleware.
    }
    
private:
    TimingCallback _callback;
    std::string _name;
};

/**
 * @brief Factory function to create a TimingMiddleware instance.
 *
 * @tparam SessionType The session type.
 * @param callback The function to be called with the measured request duration.
 * @param name Optional name for the middleware instance.
 * @return A shared pointer to the created TimingMiddleware.
 */
template <typename SessionType>
std::shared_ptr<TimingMiddleware<SessionType>>
timing_middleware(
    typename TimingMiddleware<SessionType>::TimingCallback callback,
    const std::string& name = "TimingMiddleware"
) {
    return std::make_shared<TimingMiddleware<SessionType>>(
        std::move(callback), 
        name
    );
}

} // namespace qb::http 
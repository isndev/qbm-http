#pragma once

#include "middleware_interface.h"
#include <memory>
#include <functional>
#include <string>
#include <chrono>

namespace qb::http {

/**
 * @brief Middleware for measuring request execution time
 */
template <typename Session, typename String = std::string>
class TimingMiddleware : public ISyncMiddleware<Session, String> {
public:
    using Context = typename ISyncMiddleware<Session, String>::Context;
    using Clock = std::chrono::high_resolution_clock;
    using Duration = std::chrono::milliseconds;
    using TimingCallback = std::function<void(const Duration&)>;
    
    /**
     * @brief Constructor
     * @param callback Function called with the execution duration
     * @param name Middleware name
     */
    TimingMiddleware(TimingCallback callback, std::string name = "TimingMiddleware")
        : _callback(std::move(callback)), _name(std::move(name)) {}
    
    /**
     * @brief Process a request
     * @param ctx Request context
     * @return Middleware result
     */
    MiddlewareResult process(Context& ctx) override {
        auto start = Clock::now();
        
        ctx.on_done([this, start](Context&) {
            auto end = Clock::now();
            auto duration = std::chrono::duration_cast<Duration>(end - start);
            _callback(duration);
        });
        
        return MiddlewareResult::Continue();
    }
    
    /**
     * @brief Get the middleware name
     */
    std::string name() const override {
        return _name;
    }
    
private:
    TimingCallback _callback;
    std::string _name;
};

/**
 * @brief Create a timing middleware
 */
template <typename Session, typename String = std::string>
auto timing_middleware(
    typename TimingMiddleware<Session, String>::TimingCallback callback,
    const std::string& name = "TimingMiddleware"
) {
    auto middleware = std::make_shared<TimingMiddleware<Session, String>>(
        std::move(callback), name
    );
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

} // namespace qb::http 
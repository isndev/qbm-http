#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <optional>
#include <type_traits>

#include "../routing/context.h"

namespace qb::http {

/**
 * @brief Result of a middleware indicating how the chain should proceed
 */
enum class MiddlewareAction {
    CONTINUE,   ///< Continue to the next middleware
    SKIP,       ///< Skip the rest of the middlewares and execute the final handler
    STOP,       ///< Stop processing (the response has been defined)
    ERROR       ///< Stop with an error
};

/**
 * @brief Execution result of a middleware with integrated asynchronous support
 */
class MiddlewareResult {
public:
    /**
     * @brief Constructor for a synchronous result
     * @param action Action to take for the rest of the processing
     * @param error_message Optional error message (if action is ERROR)
     */
    explicit MiddlewareResult(MiddlewareAction action, 
                      std::string error_message = {})
        : _action(action), 
          _is_async(false), 
          _error_message(std::move(error_message)) {}
    
    /**
     * @brief Constructor for an asynchronous result
     * @param is_async Indicates if the processing is asynchronous
     */
    explicit MiddlewareResult(bool is_async = true)
        : _action(MiddlewareAction::CONTINUE), 
          _is_async(is_async) {}
    
    // Factory methods to create the different types of results
    static MiddlewareResult Continue() { return MiddlewareResult(MiddlewareAction::CONTINUE); }
    static MiddlewareResult Skip() { return MiddlewareResult(MiddlewareAction::SKIP); }
    static MiddlewareResult Stop() { return MiddlewareResult(MiddlewareAction::STOP); }
    static MiddlewareResult Error(std::string message) { return MiddlewareResult(MiddlewareAction::ERROR, std::move(message)); }
    static MiddlewareResult Async() { return MiddlewareResult(true); }
    
    // Accessors
    bool is_async() const { return _is_async; }
    bool should_continue() const { return _action == MiddlewareAction::CONTINUE; }
    bool should_skip() const { return _action == MiddlewareAction::SKIP; }
    bool should_stop() const { return _action == MiddlewareAction::STOP || _action == MiddlewareAction::ERROR; }
    bool is_error() const { return _action == MiddlewareAction::ERROR; }
    MiddlewareAction action() const { return _action; }
    const std::string& error_message() const { return _error_message; }
    
private:
    MiddlewareAction _action;
    bool _is_async;
    std::string _error_message;
};

/**
 * @brief Interface for synchronous middlewares
 * 
 * This middleware processes synchronously and returns a result immediately.
 */
template <typename Session, typename String = std::string>
class ISyncMiddleware {
public:
    using Context = RouterContext<Session, String>;
    
    virtual ~ISyncMiddleware() = default;
    
    /**
     * @brief Processes a request through this middleware synchronously
     * @param ctx Request context
     * @return Middleware result
     */
    virtual MiddlewareResult process(Context& ctx) = 0;
    
    /**
     * @brief Gets the middleware name (for logging/debugging)
     */
    virtual std::string name() const = 0;
};

/**
 * @brief Interface for asynchronous middlewares
 * 
 * This middleware can delay its processing and call the callback
 * when it is finished.
 */
template <typename Session, typename String = std::string>
class IAsyncMiddleware {
public:
    using Context = RouterContext<Session, String>;
    using CompletionCallback = std::function<void(MiddlewareResult)>;
    
    virtual ~IAsyncMiddleware() = default;
    
    /**
     * @brief Processes a request through this middleware asynchronously
     * @param ctx Request context
     * @param callback Function to call when processing is complete
     */
    virtual void process_async(Context& ctx, CompletionCallback callback) = 0;
    
    /**
     * @brief Gets the middleware name (for logging/debugging)
     */
    virtual std::string name() const = 0;
};

/**
 * @brief Unified interface for middlewares
 * 
 * This interface combines synchronous and asynchronous behaviors.
 * Classes can implement one or both methods according to their needs.
 */
template <typename Session, typename String = std::string>
class IMiddleware {
public:
    using Context = RouterContext<Session, String>;
    using CompletionCallback = std::function<void(MiddlewareResult)>;
    
    virtual ~IMiddleware() = default;
    
    /**
     * @brief Processes a request synchronously or asynchronously depending on the middleware type
     * @param ctx Request context
     * @param callback Function to call if processing is asynchronous
     * @return Middleware result (ignored if asynchronous)
     * 
     * This method must be implemented by all derived classes.
     * For a synchronous middleware, it must return the result and ignore the callback.
     * For an asynchronous middleware, it must return MiddlewareResult::Async() and 
     * call the callback later.
     */
    virtual MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) = 0;
    
    /**
     * @brief Gets the middleware name (for logging/debugging)
     */
    virtual std::string name() const = 0;
};

// Type alias to simplify the creation of shared middlewares
template <typename Session, typename String = std::string>
using MiddlewarePtr = std::shared_ptr<IMiddleware<Session, String>>;

/**
 * @brief Adapter to convert a synchronous middleware into a unified middleware
 */
template <typename Session, typename String = std::string>
class SyncMiddlewareAdapter : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    
    explicit SyncMiddlewareAdapter(std::shared_ptr<ISyncMiddleware<Session, String>> middleware)
        : _middleware(std::move(middleware)) {}
    
    MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) override {
        auto result = _middleware->process(ctx);
        if (callback) callback(result);
        return result;
    }
    
    std::string name() const override {
        return _middleware->name();
    }
    
private:
    std::shared_ptr<ISyncMiddleware<Session, String>> _middleware;
};

/**
 * @brief Adapter to convert an asynchronous middleware into a unified middleware
 */
template <typename Session, typename String = std::string>
class AsyncMiddlewareAdapter : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    
    explicit AsyncMiddlewareAdapter(std::shared_ptr<IAsyncMiddleware<Session, String>> middleware)
        : _middleware(std::move(middleware)) {}
    
    MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) override {
        if (!callback) {
            throw std::runtime_error("Async middleware requires a callback");
        }
        
        _middleware->process_async(ctx, callback);
        return MiddlewareResult::Async();
    }
    
    std::string name() const override {
        return _middleware->name();
    }
    
private:
    std::shared_ptr<IAsyncMiddleware<Session, String>> _middleware;
};

/**
 * @brief Adapter to use a lambda function as a synchronous middleware
 */
template <typename Session, typename String = std::string>
class FunctionMiddleware : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    using SyncFunction = std::function<MiddlewareResult(Context&)>;
    using AsyncFunction = std::function<void(Context&, CompletionCallback)>;
    
    // Constructor for synchronous function
    explicit FunctionMiddleware(SyncFunction func, std::string name = "FunctionMiddleware")
        : _sync_func(std::move(func)), _name(std::move(name)) {}
    
    // Constructor for asynchronous function
    explicit FunctionMiddleware(AsyncFunction func, std::string name = "AsyncFunctionMiddleware")
        : _async_func(std::move(func)), _name(std::move(name)) {}
    
    MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) override {
        if (_sync_func) {
            auto result = _sync_func(ctx);
            if (callback) callback(result);
            return result;
        }
        
        if (_async_func) {
            if (!callback) {
                throw std::runtime_error("Async middleware requires a callback");
            }
            _async_func(ctx, callback);
            return MiddlewareResult::Async();
        }
        
        // No function defined
        auto error = MiddlewareResult::Error("No middleware function defined");
        if (callback) callback(error);
        return error;
    }
    
    std::string name() const override {
        return _name;
    }
    
private:
    SyncFunction _sync_func;
    AsyncFunction _async_func;
    std::string _name;
};

// Helper functions to create function-based middlewares
template <typename Session, typename String = std::string, typename Func>
std::shared_ptr<IMiddleware<Session, String>> make_middleware(Func&& func, const std::string& name = "Middleware") {
    return std::make_shared<FunctionMiddleware<Session, String>>(std::forward<Func>(func), name);
}

// Adapter for compatibility with the original middleware system
template <typename Session, typename String = std::string>
class LegacyMiddlewareAdapter : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    using LegacySyncMiddleware = std::function<bool(Context&)>;
    using LegacyAsyncMiddleware = std::function<void(Context&, std::function<void(bool)>)>;
    
    // Constructor for inherited synchronous middleware
    explicit LegacyMiddlewareAdapter(LegacySyncMiddleware func, std::string name = "LegacySyncMiddleware")
        : _sync_func(std::move(func)), _name(std::move(name)) {}
    
    // Constructor for inherited asynchronous middleware
    explicit LegacyMiddlewareAdapter(LegacyAsyncMiddleware func, std::string name = "LegacyAsyncMiddleware")
        : _async_func(std::move(func)), _name(std::move(name)) {}
    
    MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) override {
        if (_sync_func) {
            bool continue_processing = _sync_func(ctx);
            auto result = continue_processing ? MiddlewareResult::Continue() : MiddlewareResult::Stop();
            if (callback) callback(result);
            return result;
        }
        
        if (_async_func) {
            if (!callback) {
                throw std::runtime_error("Async middleware requires a callback");
            }
            
            _async_func(ctx, [callback](bool continue_processing) {
                auto result = continue_processing ? MiddlewareResult::Continue() : MiddlewareResult::Stop();
                callback(result);
            });
            
            return MiddlewareResult::Async();
        }
        
        // No function defined
        auto error = MiddlewareResult::Error("No middleware function defined");
        if (callback) callback(error);
        return error;
    }
    
    std::string name() const override {
        return _name;
    }
    
private:
    LegacySyncMiddleware _sync_func;
    LegacyAsyncMiddleware _async_func;
    std::string _name;
};

// Helper functions to create middlewares compatible with the old system
template <typename Session, typename String = std::string>
std::shared_ptr<IMiddleware<Session, String>> from_legacy_middleware(
    typename LegacyMiddlewareAdapter<Session, String>::LegacySyncMiddleware func, 
    const std::string& name = "LegacySyncMiddleware") {
    return std::make_shared<LegacyMiddlewareAdapter<Session, String>>(std::move(func), name);
}

template <typename Session, typename String = std::string>
std::shared_ptr<IMiddleware<Session, String>> from_legacy_middleware(
    typename LegacyMiddlewareAdapter<Session, String>::LegacyAsyncMiddleware func, 
    const std::string& name = "LegacyAsyncMiddleware") {
    return std::make_shared<LegacyMiddlewareAdapter<Session, String>>(std::move(func), name);
}

} // namespace qb::http 
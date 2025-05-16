#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <optional>
#include <type_traits>
#include <vector>

// #include "../routing/context.h" // Remove this direct include
#include "../routing/async_types.h" // For MiddlewareResultAction etc.

namespace qb::http {

// External declaration for middleware execution log (used for debugging and tests)
extern std::vector<std::string> adv_test_mw_middleware_execution_log;

// Forward declaration for RouterContext
template <typename Session, typename String>
struct RouterContext;

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
template <typename Session, typename String>
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
template <typename Session, typename String>
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
template <typename Session, typename String>
class IMiddleware {
public:
    using Context = RouterContext<Session, String>;
    using CompletionCallback = std::function<void(MiddlewareResult)>;
    
    virtual ~IMiddleware() = default;
    
    /**
     * @brief Get the name of this middleware.
     * @return The middleware name.
     */
    virtual std::string name() const = 0;

    /**
     * @brief Process a request with this middleware.
     *
     * This function is called for each request that passes through this middleware.
     * The middleware may process the request synchronously or asynchronously.
     *
     * @param ctx The request context.
     * @param callback Function to call when processing is complete.
     * @return MiddlewareResult indicating if the middleware chain should continue.
     */
    virtual MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) = 0;
    
    /**
     * @brief Safe wrapper for processing middleware
     *
     * This is a helper function that middleware implementations can use to ensure
     * safe async processing with proper error handling.
     *
     * @param ctx The request context.
     * @param callback The completion callback.
     * @param process_func The actual processing function.
     * @return MiddlewareResult from the processing function.
     */
    template <typename Func>
    MiddlewareResult safeProcess(Context& ctx, CompletionCallback callback, Func process_func) {
        try {
            // Create a shared_ptr copy of the context to ensure it remains valid during async operations
            auto ctx_ptr = std::shared_ptr<Context>(&ctx, [](Context*) {/* non-deleting */});
            
            // Create a safe callback wrapper that checks for nullptr before using the context
            auto safe_callback = [callback, ctx_ptr, middleware_name = this->name()](MiddlewareResult result) {
                try {
                    if (ctx_ptr && callback) {
                        callback(result);
                    } else if (callback) {
                        if (adv_test_mw_middleware_execution_log.size() < 2000) {
                            adv_test_mw_middleware_execution_log.push_back("[" + middleware_name + "::process] WARNING: Context is nullptr in callback");
                        }
                        callback(MiddlewareResult::Error("Context is null in middleware callback"));
                    }
                } catch (const std::exception& e) {
                    if (adv_test_mw_middleware_execution_log.size() < 2000) {
                        adv_test_mw_middleware_execution_log.push_back("[" + middleware_name + "::process] Exception in callback: " + std::string(e.what()));
                    }
                    if (callback) {
                        callback(MiddlewareResult::Error("Exception in middleware callback: " + std::string(e.what())));
                    }
                }
            };
            
            // Call the actual processing function with the safe context and callback
            return process_func(ctx, safe_callback);
        } catch (const std::exception& e) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[" + name() + "::process] Exception: " + std::string(e.what()));
            }
            if (callback) {
                callback(MiddlewareResult::Error("Exception in middleware: " + std::string(e.what())));
            }
            return MiddlewareResult::Error("Exception in middleware: " + std::string(e.what()));
        }
    }
};

// Type alias to simplify the creation of shared middlewares
template <typename Session, typename String>
using MiddlewarePtr = std::shared_ptr<IMiddleware<Session, String>>;

/**
 * @brief Adapter to convert a synchronous middleware into a unified middleware
 */
template <typename Session, typename String>
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
template <typename Session, typename String>
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
template <typename Session, typename String>
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
template <typename Session, typename String, typename Func>
std::shared_ptr<IMiddleware<Session, String>> make_middleware(Func&& func, const std::string& name = "Middleware") {
    return std::make_shared<FunctionMiddleware<Session, String>>(std::forward<Func>(func), name);
}

// Adapter for compatibility with the original middleware system
// This adapter converts legacy std::function-based middlewares into IMiddleware instances
// so they can be part of the unified MiddlewareChain.
template <typename Session, typename String>
class LegacyMiddlewareAdapter : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    using LegacySyncFunc = std::function<bool(Context&)>;
    using LegacyAsyncFunc = std::function<void(Context&, std::function<void(bool)>)>;
    
    // Constructor for legacy synchronous middleware function
    explicit LegacyMiddlewareAdapter(LegacySyncFunc func, std::string name = "LegacySyncMiddlewareAdapter")
        : _sync_func(std::move(func)), _name(std::move(name)), _is_async_legacy(false) {}
    
    // Constructor for legacy asynchronous middleware function
    explicit LegacyMiddlewareAdapter(LegacyAsyncFunc func, std::string name = "LegacyAsyncMiddlewareAdapter")
        : _async_func(std::move(func)), _name(std::move(name)), _is_async_legacy(true) {}
    
    MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) override {
        if (!_is_async_legacy && _sync_func) { // Wrapped a legacy sync function
            bool continue_processing = _sync_func(ctx);
            auto result = continue_processing ? MiddlewareResult::Continue() : MiddlewareResult::Stop();
            // If a completion_callback is provided (e.g., by MiddlewareChain), call it.
            if (callback) {
                callback(result);
            }
            return result; // Return result for synchronous execution path.
        }
        
        if (_is_async_legacy && _async_func) { // Wrapped a legacy async function
            if (!callback) {
                // This should ideally not happen if used within MiddlewareChain, which always provides a callback.
                // However, if called directly without a callback, it's an issue.
                return MiddlewareResult::Error("LegacyAsyncMiddlewareAdapter executed without a required CompletionCallback from the chain.");
            }
            
            _async_func(ctx, [callback_captured = callback](bool continue_processing_from_legacy) {
                auto result_for_typed_chain = continue_processing_from_legacy ? MiddlewareResult::Continue() : MiddlewareResult::Stop();
                callback_captured(result_for_typed_chain);
            });
            
            return MiddlewareResult::Async(); // Signal to the MiddlewareChain that this step is async.
        }
        
        // Should not reach here if constructors are used properly
        auto error_result = MiddlewareResult::Error("LegacyMiddlewareAdapter is not properly initialized with a sync or async function.");
        if (callback) {
            callback(error_result);
        }
        return error_result;
    }
    
    std::string name() const override {
        return _name;
    }
    
private:
    LegacySyncFunc _sync_func;
    LegacyAsyncFunc _async_func;
    std::string _name;
    bool _is_async_legacy; // To distinguish which function is valid
};

// Helper functions to create these adapters (optional, but can be convenient)
template <typename Session, typename String>
std::shared_ptr<IMiddleware<Session, String>> adapt_legacy_middleware(
    typename LegacyMiddlewareAdapter<Session, String>::LegacySyncFunc func, 
    const std::string& name = "AdaptedLegacySyncMiddleware") {
    return std::make_shared<LegacyMiddlewareAdapter<Session, String>>(std::move(func), name);
}

template <typename Session, typename String>
std::shared_ptr<IMiddleware<Session, String>> adapt_legacy_middleware(
    typename LegacyMiddlewareAdapter<Session, String>::LegacyAsyncFunc func, 
    const std::string& name = "AdaptedLegacyAsyncMiddleware") {
    return std::make_shared<LegacyMiddlewareAdapter<Session, String>>(std::move(func), name);
}

} // namespace qb::http 
; 
#pragma once

#include <vector>
#include <memory>
#include <functional>
#include <string>
#include <algorithm>

#include "./middleware_interface.h"

namespace qb::http {

/**
 * @brief Chain of synchronous and asynchronous middlewares
 * 
 * This class allows combining multiple middlewares into an execution sequence,
 * managing both synchronous and asynchronous middlewares.
 */
template <typename Session, typename String = std::string>
class MiddlewareChain : public IMiddleware<Session, String> {
public:
    using Context = typename IMiddleware<Session, String>::Context;
    using CompletionCallback = typename IMiddleware<Session, String>::CompletionCallback;
    
    /**
     * @brief Default constructor
     */
    MiddlewareChain() = default;
    
    /**
     * @brief Constructor with initial list of middlewares
     * @param middlewares List of middlewares to add
     */
    explicit MiddlewareChain(std::vector<MiddlewarePtr<Session, String>> middlewares)
        : _middlewares(std::move(middlewares)) {}
    
    /**
     * @brief Adds a middleware to the chain
     * @param middleware Middleware to add
     * @return Reference to this chain for chaining
     */
    MiddlewareChain& add(MiddlewarePtr<Session, String> middleware) {
        _middlewares.push_back(std::move(middleware));
        return *this;
    }
    
    /**
     * @brief Process a request through the middleware chain
     * @param ctx Request context
     * @param completion_callback Callback to call at the end of processing
     * @return Processing result
     */
    MiddlewareResult process(Context& ctx, CompletionCallback completion_callback = nullptr) override {
        if (_middlewares.empty()) {
            auto result = MiddlewareResult::Continue();
            if (completion_callback) completion_callback(result);
            return result;
        }
        
        // Create a processing context to track progress in the chain
        auto chain_context = std::make_shared<ChainExecutionContext>(
            ctx,
            _middlewares,
            0,
            completion_callback,
            _error_handler
        );
        
        // Start chain execution
        return process_next(*chain_context);
    }
    
    /**
     * @brief Defines an error handler for the chain
     * @param handler Function to call in case of error
     * @return Reference to this chain for chaining
     */
    MiddlewareChain& on_error(std::function<void(Context&, const std::string&)> handler) {
        _error_handler = std::move(handler);
        return *this;
    }
    
    /**
     * @brief Gets the chain name
     */
    std::string name() const override {
        return "MiddlewareChain";
    }
    
private:
    // List of middlewares
    std::vector<MiddlewarePtr<Session, String>> _middlewares;
    
    // Optional error handler
    std::function<void(Context&, const std::string&)> _error_handler;
    
    // Execution context to track chain state
    struct ChainExecutionContext {
        Context& ctx;
        const std::vector<MiddlewarePtr<Session, String>>& middlewares;
        size_t current_index;
        CompletionCallback final_callback;
        std::function<void(Context&, const std::string&)> error_handler;
        
        ChainExecutionContext(
            Context& c,
            const std::vector<MiddlewarePtr<Session, String>>& mw,
            size_t index,
            CompletionCallback callback,
            std::function<void(Context&, const std::string&)> eh
        ) : ctx(c), middlewares(mw), current_index(index), 
            final_callback(std::move(callback)), error_handler(std::move(eh)) {}
    };
    
    /**
     * @brief Processes the next middleware in the chain
     * @param chain_ctx Chain execution context
     * @return Processing result
     */
    MiddlewareResult process_next(ChainExecutionContext& chain_ctx) {
        // If all middlewares have been processed or if the context is already handled
        if (chain_ctx.current_index >= chain_ctx.middlewares.size() || chain_ctx.ctx.is_handled()) {
            auto result = MiddlewareResult::Continue();
            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(result);
            }
            return result;
        }
        
        // Get the current middleware
        auto& middleware = chain_ctx.middlewares[chain_ctx.current_index];
        
        // Prepare the callback for the next middleware
        auto next_callback = [chain_ctx_ptr = std::make_shared<ChainExecutionContext>(chain_ctx)](MiddlewareResult result) mutable {
            auto& chain_ctx = *chain_ctx_ptr;
            
            // Check the middleware result
            if (result.is_error()) {
                // Call the error handler if it exists
                if (chain_ctx.error_handler) {
                    chain_ctx.error_handler(chain_ctx.ctx, result.error_message());
                }
                
                // Pass the error to the final callback
                if (chain_ctx.final_callback) {
                    chain_ctx.final_callback(result);
                }
                return;
            }
            
            if (result.should_stop()) {
                // Middleware requested to stop processing
                if (chain_ctx.final_callback) {
                    chain_ctx.final_callback(result);
                }
                return;
            }
            
            if (result.should_skip()) {
                // Middleware requested to skip to the final handler
                chain_ctx.current_index = chain_ctx.middlewares.size();
            } else {
                // Move to the next middleware
                chain_ctx.current_index++;
            }
            
            // Recursively process the next middleware
            MiddlewareChain<Session, String>::process_next_static(chain_ctx);
        };
        
        // Execute the current middleware
        MiddlewareResult result = middleware->process(chain_ctx.ctx, next_callback);
        
        // If the middleware is asynchronous, simply return Async
        if (result.is_async()) {
            return MiddlewareResult::Async();
        }
        
        // For synchronous middlewares, check the result immediately
        if (result.is_error()) {
            if (chain_ctx.error_handler) {
                chain_ctx.error_handler(chain_ctx.ctx, result.error_message());
            }
            
            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(result);
            }
            return result;
        }
        
        if (result.should_stop()) {
            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(result);
            }
            return result;
        }
        
        if (result.should_skip()) {
            // Skip to the final handler
            auto final_result = MiddlewareResult::Skip();
            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(final_result);
            }
            return final_result;
        }
        
        // Move to the next middleware
        chain_ctx.current_index++;
        return process_next(chain_ctx);
    }
    
    // Static version to be called from lambdas capturing chain_ctx by value
    static void process_next_static(ChainExecutionContext& chain_ctx) {
        MiddlewareChain<Session, String> chain;
        chain.process_next(chain_ctx);
    }
};

/**
 * @brief Helper function to create a middleware chain
 */
template <typename Session, typename String = std::string>
auto make_middleware_chain(std::vector<MiddlewarePtr<Session, String>> middlewares = {}) {
    return std::make_shared<MiddlewareChain<Session, String>>(std::move(middlewares));
}

} // namespace qb::http 
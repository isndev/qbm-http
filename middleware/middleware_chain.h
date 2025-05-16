#pragma once

#include <vector>
#include <memory>
#include <functional>
#include <string>
#include <algorithm>
#include <optional>

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
        
        try {
            // Start chain execution
            return process_next(*chain_context);
        } catch (const std::exception& e) {
            std::string error_msg = "Exception in MiddlewareChain::process: " + std::string(e.what());
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process] EXCEPTION: " + error_msg);
            }
            
            if (completion_callback) {
                completion_callback(MiddlewareResult::Error(error_msg));
            }
            return MiddlewareResult::Error(error_msg);
        }
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
    
    /**
     * @brief Gets the number of middlewares in the chain
     * @return The number of middlewares
     */
    size_t get_middleware_count() const {
        return _middlewares.size();
    }
    
    /**
     * @brief Gets all the middlewares in the chain
     * @return Const reference to the middleware vector
     */
    const std::vector<MiddlewarePtr<Session, String>>& get_middleware() const {
        return _middlewares;
    }
    
    /**
     * @brief Clear all middlewares in the chain
     * @return Reference to this chain for chaining
     */
    MiddlewareChain& clear() {
        _middlewares.clear();
        return *this;
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
        std::optional<MiddlewareResult> last_result; // Store the result of the middleware that just completed
        
        ChainExecutionContext(
            Context& c,
            const std::vector<MiddlewarePtr<Session, String>>& mw,
            size_t index,
            CompletionCallback callback,
            std::function<void(Context&, const std::string&)> eh
        ) : ctx(c), middlewares(mw), current_index(index), 
            final_callback(std::move(callback)), error_handler(std::move(eh)), last_result(std::nullopt) {}
    };
    
    /**
     * @brief Processes the next middleware in the chain
     * @param chain_ctx Chain execution context
     * @return Processing result
     */
    MiddlewareResult process_next(ChainExecutionContext& chain_ctx) {
        // If all middlewares have been processed or if the context is already handled by a stopping middleware
        if (chain_ctx.current_index >= chain_ctx.middlewares.size() || 
            (chain_ctx.ctx.is_handled() && chain_ctx.last_result && chain_ctx.last_result->should_stop())) {
            
            MiddlewareResult final_chain_result = MiddlewareResult::Continue();
            if (chain_ctx.last_result && chain_ctx.last_result->should_stop()) {
                final_chain_result = *chain_ctx.last_result; // Propagate the Stop/Error result
            }

            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(final_chain_result);
            }
            return final_chain_result;
        }
        
        // Get current middleware and ensure it's valid
        if (chain_ctx.current_index >= chain_ctx.middlewares.size()) {
            std::string error_msg = "Invalid middleware index in chain";
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process_next] ERROR: " + error_msg);
            }
            
            auto error_result = MiddlewareResult::Error(error_msg);
            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(error_result);
            }
            return error_result;
        }
        
        auto& middleware = chain_ctx.middlewares[chain_ctx.current_index];
        if (!middleware) {
            std::string error_msg = "Null middleware pointer in chain at index " + std::to_string(chain_ctx.current_index);
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process_next] ERROR: " + error_msg);
            }
            
            auto error_result = MiddlewareResult::Error(error_msg);
            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(error_result);
            }
            return error_result;
        }
        
        // Important: create a shared copy of the chain context to avoid reference invalidation in the callback
        auto chain_ctx_shared = std::make_shared<ChainExecutionContext>(chain_ctx);
        
        // Create a safe callback for the next middleware
        auto next_middleware_callback = [this, chain_ctx_shared](MiddlewareResult result_from_current_mw) mutable {
            try {
                if (!chain_ctx_shared) {
                    if (adv_test_mw_middleware_execution_log.size() < 2000) {
                        adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::next_callback] ERROR: chain_ctx_shared is null");
                    }
                    return;
                }
                
                auto& current_chain_ctx = *chain_ctx_shared;
                current_chain_ctx.last_result = result_from_current_mw; // Store the result of the middleware that just ran

                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::next_callback] Received result: " + 
                        (result_from_current_mw.is_error() ? "ERROR: " + result_from_current_mw.error_message() : 
                        result_from_current_mw.should_stop() ? "STOP" : 
                        result_from_current_mw.is_async() ? "ASYNC" : "CONTINUE"));
                }

                if (result_from_current_mw.is_error()) {
                    if (current_chain_ctx.error_handler) {
                        try {
                            current_chain_ctx.error_handler(current_chain_ctx.ctx, result_from_current_mw.error_message());
                        } catch (const std::exception& e) {
                            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::next_callback] EXCEPTION in error_handler: " + std::string(e.what()));
                            }
                        }
                    }
                    if (current_chain_ctx.final_callback) {
                        try {
                            current_chain_ctx.final_callback(result_from_current_mw); // Propagate error
                        } catch (const std::exception& e) {
                            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::next_callback] EXCEPTION in final_callback on error: " + std::string(e.what()));
                            }
                        }
                    }
                    return; // Stop chain on error
                }
                
                if (result_from_current_mw.should_stop()) {
                    // Middleware requested to stop. If it handled the response, ctx.is_handled() should be true.
                    // The final_callback will be called by the top-level process_next check.
                    if (current_chain_ctx.final_callback) {
                        try {
                            current_chain_ctx.final_callback(result_from_current_mw); // Propagate Stop
                        } catch (const std::exception& e) {
                            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::next_callback] EXCEPTION in final_callback on stop: " + std::string(e.what()));
                            }
                        }
                    }
                    return; // Stop chain
                }
                
                // If Continue or Skip (Skip is handled like Continue for now, advancing index)
                current_chain_ctx.current_index++;
                
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::next_callback] Advancing to next middleware at index " + 
                        std::to_string(current_chain_ctx.current_index) + " of " + 
                        std::to_string(current_chain_ctx.middlewares.size()));
                }
                
                // Recursively process the next middleware using the static helper
                // to avoid issues if `this` MiddlewareChain instance is temporary.
                try {
                    MiddlewareChain<Session, String>::process_next_static(current_chain_ctx);
                } catch (const std::exception& e) {
                    std::string error_msg = "Exception in next middleware process: " + std::string(e.what());
                    if (adv_test_mw_middleware_execution_log.size() < 2000) {
                        adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::next_callback] ERROR: " + error_msg);
                    }
                    
                    if (current_chain_ctx.final_callback) {
                        try {
                            current_chain_ctx.final_callback(MiddlewareResult::Error(error_msg));
                        } catch (const std::exception& nested_e) {
                            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::next_callback] NESTED EXCEPTION in final_callback: " + std::string(nested_e.what()));
                            }
                        }
                    }
                }
            } catch (const std::exception& e) {
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::next_callback] EXCEPTION: " + std::string(e.what()));
                }
                
                if (chain_ctx_shared && chain_ctx_shared->final_callback) {
                    try {
                        chain_ctx_shared->final_callback(MiddlewareResult::Error(std::string(e.what())));
                    } catch (const std::exception& nested_e) {
                        if (adv_test_mw_middleware_execution_log.size() < 2000) {
                            adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::next_callback] NESTED EXCEPTION in error callback: " + std::string(nested_e.what()));
                        }
                    }
                }
            }
        };
        
        // Process the current middleware with the callback for the next one
        MiddlewareResult current_mw_processing_result;
        try {
            current_mw_processing_result = middleware->process(chain_ctx.ctx, next_middleware_callback);
        } catch (const std::exception& e) {
            std::string error_msg = "Exception in middleware " + middleware->name() + ": " + std::string(e.what());
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process_next] MIDDLEWARE ERROR: " + error_msg);
            }
            
            if (chain_ctx.final_callback) {
                chain_ctx.final_callback(MiddlewareResult::Error(error_msg));
            }
            return MiddlewareResult::Error(error_msg);
        }
        
        if (current_mw_processing_result.is_async()) {
            chain_ctx.ctx.mark_async(); // Ensure context is marked async here
            return MiddlewareResult::Async(); // Middleware is async, chain will continue via callback
        }
        
        // --- For Synchronous middleware in the chain --- 
        chain_ctx.last_result = current_mw_processing_result; // Store sync result

        if (current_mw_processing_result.is_error()) {
            if (chain_ctx.error_handler) {
                chain_ctx.error_handler(chain_ctx.ctx, current_mw_processing_result.error_message());
            }
            if (chain_ctx.final_callback) chain_ctx.final_callback(current_mw_processing_result);
            return current_mw_processing_result;
        }
        
        if (current_mw_processing_result.should_stop()) {
            if (chain_ctx.final_callback) chain_ctx.final_callback(current_mw_processing_result);
            return current_mw_processing_result;
        }
        
        // If Continue or Skip from sync middleware
        chain_ctx.current_index++;
        return process_next(chain_ctx); // Process next sync middleware
    }
    
    // Static version to be called from lambdas
    static void process_next_static(ChainExecutionContext& chain_ctx) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process_next_static] Called for index " + 
                std::to_string(chain_ctx.current_index) + " of " + std::to_string(chain_ctx.middlewares.size()) + " middlewares");
        }
        
        // Safety check: if we've reached the end of the chain, call the final callback if present
        if (chain_ctx.current_index >= chain_ctx.middlewares.size()) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process_next_static] Index beyond middleware count, completing chain");
            }
            
            if (chain_ctx.final_callback) {
                auto result = chain_ctx.last_result.value_or(MiddlewareResult::Continue());
                chain_ctx.final_callback(result);
            }
            return;
        }
        
        // Create a temporary chain instance to call the non-static process_next
        try {
            MiddlewareChain<Session, String> temp_chain_for_static_call;
            temp_chain_for_static_call._error_handler = chain_ctx.error_handler; // Pass error handler if needed
            
            auto chain_result = temp_chain_for_static_call.process_next(chain_ctx);
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process_next_static] process_next returned: " + 
                    (chain_result.is_error() ? "ERROR: " + chain_result.error_message() : 
                     chain_result.should_stop() ? "STOP" : 
                     chain_result.is_async() ? "ASYNC" : "CONTINUE"));
            }
        } catch (const std::exception& e) {
            std::string error_msg = "Exception in process_next_static: " + std::string(e.what());
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process_next_static] ERROR: " + error_msg);
            }
            
            if (chain_ctx.final_callback) {
                try {
                    chain_ctx.final_callback(MiddlewareResult::Error(error_msg));
                } catch (const std::exception& nested_e) {
                    if (adv_test_mw_middleware_execution_log.size() < 2000) {
                        adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process_next_static] NESTED EXCEPTION in callback: " + std::string(nested_e.what()));
                    }
                } catch (...) {
                    if (adv_test_mw_middleware_execution_log.size() < 2000) {
                        adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process_next_static] UNKNOWN NESTED EXCEPTION in callback");
                    }
                }
            }
        } catch (...) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process_next_static] UNKNOWN EXCEPTION");
            }
            
            if (chain_ctx.final_callback) {
                try {
                    chain_ctx.final_callback(MiddlewareResult::Error("Unknown exception in MiddlewareChain::process_next_static"));
                } catch (...) {
                    if (adv_test_mw_middleware_execution_log.size() < 2000) {
                        adv_test_mw_middleware_execution_log.push_back("[MiddlewareChain::process_next_static] EXCEPTION in error callback");
                    }
                }
            }
        }
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
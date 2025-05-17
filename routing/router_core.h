#pragma once

#include "./radix_tree.h"
#include "./context.h"
#include "./async_task.h"
#include "./handler_node.h"
#include "../request.h"   // Existing Request
#include "../response.h"  // Existing Response
#include "../types.h"     // For qb::http::HTTP_STATUS_NOT_FOUND etc.
#include "./route.h"      // For RouteHandlerTask and ICustomRoute
#include "./middleware.h"

#include <memory>
#include <string>
#include <list>
#include <functional>
#include <vector>         // For _top_level_nodes
#include <iostream> // For temporary logging
#include <algorithm> // For std::reverse

namespace qb::http {

/**
 * @brief Core logic for the router, including route registration and execution.
 *
 * This class is not meant to be used directly by users but is the engine
 * for the main Router class.
 */
template <typename Session>
class RouterCore : public std::enable_shared_from_this<RouterCore<Session>> {
private:
    RadixTree<Session> _radix_tree;
    std::vector<std::shared_ptr<IHandlerNode<Session>>> _top_level_nodes; // Groups, Controllers, direct Routes

    RouteHandlerFn<Session> _default_not_found_handler;
    std::list<std::shared_ptr<IAsyncTask<Session>>> _compiled_not_found_tasks;
    bool _custom_not_found_handler_set = false;
    // Cache for global middleware to be used by special handlers (404, error handlers etc.)
    std::list<std::shared_ptr<IAsyncTask<Session>>> _global_prefix_tasks_for_special_handlers;
    // Stores only the user-defined part of the error handling chain.
    std::list<std::shared_ptr<IAsyncTask<Session>>> _user_defined_error_chain;
    bool _user_error_chain_explicitly_set = false; // Tracks if user called set_error_task_chain

    std::function<void(Context<Session>&)> _on_request_finalized_callback; // For the server

    // Takes global_prefix_tasks to prepend to the actual 404 handler task
    void compile_default_not_found_handler(const std::list<std::shared_ptr<IAsyncTask<Session>>>& global_prefix_tasks) {
        if (!_default_not_found_handler || !_custom_not_found_handler_set) { 
            _default_not_found_handler = [](std::shared_ptr<Context<Session>> ctx) { 
                ctx->response().status_code = HTTP_STATUS_NOT_FOUND; 
                ctx->response().set_content_type("text/plain");
                ctx->response().body() = "404 Not Found (Default)";
                ctx->complete(); 
            };
        }
        _compiled_not_found_tasks.clear();
        // Prepend global prefix tasks
        for (const auto& task : global_prefix_tasks) {
            _compiled_not_found_tasks.push_back(task);
        }
        // Add the actual 404 handler task
        _compiled_not_found_tasks.push_back(
            std::make_shared<RouteLambdaTask<Session>>(_default_not_found_handler, "DefaultOrCustomNotFoundHandler") 
        );
    }

public:
    RouterCore(std::function<void(Context<Session>&)> on_request_finalized_cb) { 
        _on_request_finalized_callback = std::move(on_request_finalized_cb); 
        // Initial compilation of default 404 without global tasks; compile_all_routes will fix it.
        compile_default_not_found_handler({}); 
    }

    /**
     * @brief Registers a top-level handler node (Route, RouteGroup, Controller).
     */
    void add_handler_node(std::shared_ptr<IHandlerNode<Session>> node) {
        _top_level_nodes.push_back(node);
    }

    /**
     * @brief Compiles all registered routes.
     * This should be called after all routes, groups, and controllers are defined
     * and before the router starts accepting requests.
     */
    void compile_all_routes() {
        _radix_tree.clear(); 
        std::list<std::shared_ptr<IAsyncTask<Session>>> root_level_inherited_tasks; // Empty for top-most level nodes
        
        std::shared_ptr<RouteGroup<Session>> root_group_ptr = nullptr;

        for (const auto& node : _top_level_nodes) {
            // Attempt to find the main root group (created by Router) to get its middleware later
            if (!root_group_ptr && node->get_path_segment().empty()) {
                auto rg_candidate = std::dynamic_pointer_cast<RouteGroup<Session>>(node);
                if (rg_candidate) {
                    root_group_ptr = rg_candidate;
                    std::cerr << "RouterCore::compile_all_routes: Found root group." << std::endl;
                }
            }
            node->compile_tasks_and_register(*this, "", root_level_inherited_tasks);
        }

        // _global_prefix_tasks_for_special_handlers are specifically for the not-found handler.
        // The main error chain (user-defined) will be fetched directly.
        _global_prefix_tasks_for_special_handlers.clear(); // Ensure it's clean before populating
        if (root_group_ptr) {
            _global_prefix_tasks_for_special_handlers = root_group_ptr->combine_tasks({}); 
            std::cerr << "RouterCore::compile_all_routes: Populated _global_prefix_tasks_for_special_handlers with " 
                      << _global_prefix_tasks_for_special_handlers.size() << " tasks (for not-found handler)." << std::endl;
            for(const auto& task : _global_prefix_tasks_for_special_handlers) {
                if(task) std::cerr << "  - Global Prefix Task for 404: " << task->name() << std::endl;
            }
        } else {
            std::cerr << "RouterCore::compile_all_routes: root_group_ptr was NULL. _global_prefix_tasks_for_special_handlers will be empty." << std::endl;
        }

        compile_default_not_found_handler(_global_prefix_tasks_for_special_handlers); 
    }

    /**
     * @brief Called by IHandlerNode derivatives to register a fully compiled route task chain.
     */
    void register_compiled_route(const std::string& full_path, 
                                 qb::http::method method_val, 
                                 std::list<std::shared_ptr<IAsyncTask<Session>>> task_chain) { // Changed to list from vector
        _radix_tree.add_route(full_path, method_val, std::move(task_chain));
    }

    /**
     * @brief Sets a custom handler for 404 Not Found responses.
     */
    void set_not_found_handler(RouteHandlerFn<Session> handler_fn) { 
        _default_not_found_handler = std::move(handler_fn);
        _custom_not_found_handler_set = true;
        // Immediately recompile the 404 handler tasks using cached global prefix tasks.
        // This ensures that if set_not_found_handler is called after compile_all_routes,
        // it still picks up the correct global middleware.
        compile_default_not_found_handler(_global_prefix_tasks_for_special_handlers); 
    }

    /**
     * @brief Sets a dedicated task chain to be executed when an error occurs during normal request processing.
     * @param error_chain The list of tasks for handling errors.
     */
    void set_error_task_chain(std::list<std::shared_ptr<IAsyncTask<Session>>> error_chain) {
        _user_defined_error_chain = std::move(error_chain);
        _user_error_chain_explicitly_set = true; // Mark that the user has provided a chain (even if empty)
    }

    // Returns the user-defined error task chain.
    // Returns an empty list if no user-defined chain was set.
    std::list<std::shared_ptr<IAsyncTask<Session>>> get_compiled_error_tasks() const {
        std::cerr << "RouterCore::get_compiled_error_tasks called." << std::endl;
        if (!_user_error_chain_explicitly_set) { // Check if user explicitly set it
            std::cerr << "  User error chain not explicitly set. Returning empty chain (core will default to 500)." << std::endl;
            return {}; 
        }
        
        // The error chain now consists ONLY of what the user explicitly set.
        // If global middleware (e.g., for logging, auth) should run during error handling,
        // they must be explicitly added to the list of tasks passed to set_error_task_chain().
        // This prevents issues where a faulty global middleware could prevent the error chain itself from executing.
        std::list<std::shared_ptr<IAsyncTask<Session>>> full_error_chain = _user_defined_error_chain;
        
        std::cerr << "  Returning full error chain with " << full_error_chain.size() << " tasks." << std::endl;
        return full_error_chain;
    }

    bool is_error_chain_set() const {
        // An error chain is considered "set" and usable if the user has explicitly provided one.
        return _user_error_chain_explicitly_set;
    }

    /**
     * @brief Routes a request to the appropriate handler and executes its task chain.
     * @param session The client session.
     * @param request The incoming HTTP request.
     */
    std::shared_ptr<Context<Session>> route_request(std::shared_ptr<Session> session_ptr, qb::http::Request request_obj) { // Use shared_ptr for session
        auto ctx = std::make_shared<Context<Session>>(
            std::move(request_obj), 
            Response{}, 
            session_ptr, 
            _on_request_finalized_callback,
            this->weak_from_this() // Pass weak_ptr of RouterCore to Context
        );
        // Initial phase is INITIAL by default in Context constructor

        ctx->execute_hook(qb::http::HookPoint::PRE_ROUTING); 

        // Pass the raw path from the URI to the radix tree match function.
        // The RadixTree is expected to handle segmentation and decode parameter values itself.
        auto matched_info = _radix_tree.match(std::string(ctx->request().uri().path()), ctx->request().method);
        std::vector<std::shared_ptr<IAsyncTask<Session>>> tasks_to_execute_vec;

        if (matched_info && matched_info->route_tasks && matched_info->route_tasks.value()) { 
            // Decode path parameters before setting them in the context.
            for (auto& param_pair : matched_info->path_parameters) {
                param_pair.second = qb::io::uri::decode(param_pair.second);
            }
            // Restore the logic to populate tasks_to_execute_vec
            const auto& task_list_sptr = matched_info->route_tasks.value();
            if (task_list_sptr) { // Ensure the shared_ptr to the list is valid
                tasks_to_execute_vec = *task_list_sptr; // Copy tasks from the matched route's list
            }

            ctx->set_path_parameters(std::move(matched_info->path_parameters));
            ctx->set_processing_phase(Context<Session>::ProcessingPhase::NORMAL_CHAIN);
            std::cerr << "RouterCore: Matched normal route. Phase set to NORMAL_CHAIN." << std::endl;
        } else {
            std::copy(_compiled_not_found_tasks.begin(), _compiled_not_found_tasks.end(), std::back_inserter(tasks_to_execute_vec));
            ctx->set_processing_phase(Context<Session>::ProcessingPhase::NOT_FOUND_CHAIN);
            std::cerr << "RouterCore: No route matched. Using 'not found' chain. Phase set to NOT_FOUND_CHAIN." << std::endl;
        }

        if (tasks_to_execute_vec.empty()) { // This covers both empty matched route and empty not_found_tasks
            // This case should ideally not be reached if compile_default_not_found_handler works
            // and if all registered routes actually have tasks.
            std::cerr << "RouterCore: Critical error - no tasks for matched route or for 404." << std::endl;
            ctx->response().status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR; // NO NAMESPACE
            ctx->response().body() = "Router critical error: No task chain for 404.";
            const qb::http::AsyncTaskResult error_result = qb::http::AsyncTaskResult::ERROR;
            ctx->complete(error_result); // Scoped
            // If _on_request_finalized_callback exists and is appropriate here, call it.
            // Otherwise, the response is sent when ctx goes out of scope or is handled by a server wrapper.
            return ctx; // Return context even in error case
        }        
        // Log the task chain that is about to be executed.
        // The 0 indicates that the task at index 0 is the next to be executed by set_task_chain_and_start.
        Context<Session>::log_task_chain_snapshot(tasks_to_execute_vec, "Initial routing decision", 0);

        ctx->execute_hook(qb::http::HookPoint::PRE_HANDLER_EXECUTION);
        ctx->set_task_chain_and_start(std::move(tasks_to_execute_vec));
        return ctx;
    }

    /**
     * @brief Clears all registered routes, top-level nodes, and resets special handlers to their defaults.
     */
    void clear() {
        _radix_tree.clear();
        _top_level_nodes.clear();
        _custom_not_found_handler_set = false;
        _default_not_found_handler = nullptr; // Reset to trigger default creation
        _global_prefix_tasks_for_special_handlers.clear();
        _user_defined_error_chain.clear();
        _user_error_chain_explicitly_set = false;
        // Re-compile the default not-found handler with (now empty) global prefix tasks.
        compile_default_not_found_handler({}); 
        // Note: The root group of the main Router will be re-added by Router::clear()
    }

}; // End RouterCore

} // namespace qb::http 
/**
 * @file qbm/http/routing/router_core.h
 * @brief Defines the core engine for HTTP route registration, compilation, and execution.
 *
 * This file contains the `RouterCore` class template, which is the internal powerhouse
 * of the qb-http routing system. It manages a `RadixTree` for efficient route matching,
 * compiles route definitions (including middleware from `IHandlerNode`s) into executable
 * `IAsyncTask` chains, and dispatches incoming requests to the appropriate chains.
 * It is not intended for direct use by end-users but is leveraged by the main `Router` class.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include <memory>      // For std::shared_ptr, std::weak_ptr, std::enable_shared_from_this, std::make_shared
#include <string>      // For std::string
#include <vector>      // For std::vector (used for _top_level_nodes and task chains)
#include <functional>  // For std::function (used for _on_request_finalized_callback)
#include <optional>    // For std::optional (used in MatchedRouteInfo)
#include <algorithm>   // For std::copy, std::reverse (though reverse not used here currently)
#include <utility>     // For std::move

#include "./radix_tree.h"     // For RadixTree
#include "./context.h"        // For Context
#include "./async_task.h"     // For IAsyncTask
#include "./handler_node.h"   // For IHandlerNode
#include "./route.h"          // For RouteLambdaTask (used in default 404 handler)
#include "./middleware.h"     // For MiddlewareTask (potentially if global middleware were adapted differently)
#include "./route_group.h"    // For dynamic_pointer_cast to RouteGroup
#include "../request.h"       // For qb::http::Request
#include "../response.h"      // For qb::http::Response
#include "../types.h"         // For qb::http::method, http_status constants, HookPoint
#include "../logger.h"        // For LOG_HTTP_DEBUG, LOG_HTTP_ERROR, LOG_HTTP_TRACE
#include <qb/io/uri.h>        // For qb::io::uri::decode

namespace qb::http {
    /**
     * @brief Core engine for the HTTP routing system.
     *
     * `RouterCore` is responsible for:
     * - Storing and managing the hierarchy of route definitions (`IHandlerNode` objects).
     * - Compiling these definitions into a `RadixTree` for efficient path matching.
     * - During compilation, it resolves middleware chains for each route.
     * - Handling incoming requests by matching them against the `RadixTree`.
     * - Creating a `Context` for each request.
     * - Dispatching matched requests (or 404/error scenarios) to the appropriate compiled task chain.
     * - Managing default and custom handlers for "404 Not Found" and general errors.
     *
     * This class is not intended for direct instantiation by users; it serves as the internal logic
     * for the public-facing `Router` class.
     *
     * @tparam SessionType The session type used by the `Context` and `IAsyncTask` system.
     */
    template<typename SessionType>
    class RouterCore : public std::enable_shared_from_this<RouterCore<SessionType> > {
    private:
        RadixTree<SessionType> _radix_tree; ///< The radix tree used for efficient route matching.
        std::vector<std::shared_ptr<IHandlerNode<SessionType> > > _top_level_nodes;
        ///< Stores top-level groups, controllers, or direct routes added to the router.

        RouteHandlerFn<SessionType> _default_not_found_handler; ///< User-defined or default handler for 404 Not Found.
        std::vector<std::shared_ptr<IAsyncTask<SessionType> > > _compiled_not_found_tasks;
        ///< Compiled task chain for 404 responses.
        bool _custom_not_found_handler_set = false; ///< Flag indicating if a custom 404 handler was set.

        // Cache of global middleware tasks (from the root group) to prepend to special handlers like 404.
        std::vector<std::shared_ptr<IAsyncTask<SessionType> > > _global_prefix_tasks_for_special_handlers;

        // Stores the user-defined task chain for handling errors signaled by AsyncTaskResult::ERROR.
        std::vector<std::shared_ptr<IAsyncTask<SessionType> > > _user_defined_error_chain;
        bool _user_error_chain_explicitly_set = false; ///< True if `set_error_task_chain` was explicitly called.

        /** @brief Callback invoked by the `Context` when request processing is fully finalized (after response is sent or context cancelled). */
        std::function<void(Context<SessionType> &)> _on_request_finalized_callback;

        /**
         * @brief (Private) Compiles the task chain for the "404 Not Found" handler.
         * It prepends any specified `global_prefix_tasks` (typically global middleware)
         * to the actual 404 handler task (which is either user-defined or a default one).
         * @param global_prefix_tasks A vector of tasks (usually global middleware) to execute before the 404 handler.
         */
        void compile_default_not_found_handler(
            const std::vector<std::shared_ptr<IAsyncTask<SessionType> > > &global_prefix_tasks) {
            if (!_default_not_found_handler || !_custom_not_found_handler_set) {
                // Set a very basic default 404 handler if none was provided by the user.
                _default_not_found_handler = [](std::shared_ptr<Context<SessionType> > ctx) {
                    ctx->response().status() = qb::http::status::NOT_FOUND;
                    ctx->response().set_content_type("text/plain; charset=utf-8");
                    ctx->response().body() = "404 Not Found (Default)";
                    ctx->complete(AsyncTaskResult::COMPLETE); // Signal completion of this handler
                };
            }
            _compiled_not_found_tasks.clear();
            _compiled_not_found_tasks.reserve(global_prefix_tasks.size() + 1);
            _compiled_not_found_tasks.insert(_compiled_not_found_tasks.end(), global_prefix_tasks.begin(),
                                             global_prefix_tasks.end());
            _compiled_not_found_tasks.push_back(
                std::make_shared<RouteLambdaTask<SessionType> >(_default_not_found_handler,
                                                                "DefaultOrCustomNotFoundHandler")
            );
        }

    public:
        /**
         * @brief Constructs the `RouterCore`.
         * @param on_request_finalized_cb A callback function that the `Context` will invoke when its processing
         *                                is fully finalized (e.g., after the response is sent or it's cancelled).
         *                                This is typically used by the server to manage session lifecycle or send data.
         */
        explicit RouterCore(std::function<void(Context<SessionType> &)> on_request_finalized_cb)
            : _on_request_finalized_callback(std::move(on_request_finalized_cb)) {
            compile_default_not_found_handler({}); // Initial compilation with no global tasks yet.
        }

        /**
         * @brief Registers a top-level handler node (e.g., `RouteGroup`, `Controller`, or a direct `Route`)
         *        with this router core. These nodes form the root of the routing hierarchy.
         * @param node A `std::shared_ptr` to an `IHandlerNode`.
         */
        void add_handler_node(std::shared_ptr<IHandlerNode<SessionType> > node) {
            if (node) {
                // Avoid adding null nodes
                _top_level_nodes.push_back(std::move(node));
            }
        }

        /**
         * @brief Compiles all registered routes, groups, and controllers into the internal `RadixTree`.
         * This method must be called after all route definitions are complete and before the router
         * starts processing requests. It recursively traverses the handler node hierarchy, builds full
         * paths, combines middleware, and registers the final task chains for each endpoint.
         * It also determines global middleware (from the root group, if any) to apply to special handlers
         * like the 404 handler.
         */
        void compile_all_routes() {
            _radix_tree.clear();
            std::vector<std::shared_ptr<IAsyncTask<SessionType> > > root_level_inherited_tasks; // Initially empty

            std::shared_ptr<RouteGroup<SessionType> > root_group_ptr = nullptr;

            // Find the root group (typically path_segment "") to extract its middleware as global for special handlers.
            for (const auto &node: _top_level_nodes) {
                if (node && node->get_path_segment().empty()) {
                    // Check for null node
                    if (auto rg_candidate = std::dynamic_pointer_cast<RouteGroup<SessionType> >(node)) {
                        root_group_ptr = rg_candidate;
                        break; // Found the main root group
                    }
                }
            }

            _global_prefix_tasks_for_special_handlers.clear();
            if (root_group_ptr) {
                // Combine tasks from the root group itself (doesn't inherit any from above)
                _global_prefix_tasks_for_special_handlers = root_group_ptr->combine_tasks({});
            }

            // Compile all top-level nodes, they inherit nothing from above the router itself.
            for (const auto &node: _top_level_nodes) {
                if (node) {
                    // Check for null node
                    node->compile_tasks_and_register(*this, "", root_level_inherited_tasks);
                }
            }

            // Re-compile the default 404 handler with any global prefix tasks found.
            compile_default_not_found_handler(_global_prefix_tasks_for_special_handlers);
        }

        /**
         * @brief Registers a fully compiled route (path, method, and complete task chain) into the `RadixTree`.
         * This method is typically called by `IHandlerNode::compile_tasks_and_register` implementations.
         * @param full_path The complete, normalized URI path for the route.
         * @param method The HTTP method for the route.
         * @param task_chain_list The final, ordered vector of `IAsyncTask`s (middleware + handler) for this route.
         */
        void register_compiled_route(const std::string &full_path,
                                     qb::http::method method_val,
                                     std::vector<std::shared_ptr<IAsyncTask<SessionType> > > task_chain_list) {
            _radix_tree.add_route(full_path, method_val, std::move(task_chain_list));
        }

        /**
         * @brief Sets a custom handler function for "404 Not Found" responses.
         * If set, this handler will be used instead of the default 404 response logic.
         * Global middleware (from the root group) will still be prepended to this custom handler.
         * @param handler_fn A `RouteHandlerFn` that will process the 404 case.
         */
        void set_not_found_handler(RouteHandlerFn<SessionType> handler_fn) {
            _default_not_found_handler = std::move(handler_fn);
            _custom_not_found_handler_set = static_cast<bool>(_default_not_found_handler);
            // Recompile 404 handler with current global prefix tasks.
            compile_default_not_found_handler(_global_prefix_tasks_for_special_handlers);
        }

        /**
         * @brief Sets a user-defined task chain to be executed when an error occurs during normal request processing
         *        (i.e., when a task calls `ctx->complete(AsyncTaskResult::ERROR)`).
         * @param error_chain A vector of `IAsyncTask` shared pointers forming the error handling chain.
         *                    This chain will be executed in its entirety.
         * @note Global middleware is **not** automatically prepended to this user-defined error chain.
         *       If global behaviors (like error logging) are desired, they must be explicitly included in `error_chain`.
         */
        void set_error_task_chain(std::vector<std::shared_ptr<IAsyncTask<SessionType> > > error_chain) {
            _user_defined_error_chain = std::move(error_chain);
            _user_error_chain_explicitly_set = true;
        }

        /**
         * @brief Retrieves the compiled, user-defined error handling task chain.
         * @return A vector of `IAsyncTask` shared pointers. Returns an empty vector if no user-defined error chain was set.
         * @note This vector contains only the tasks explicitly set via `set_error_task_chain`.
         *       Global middleware is not automatically prepended here.
         */
        [[nodiscard]] std::vector<std::shared_ptr<IAsyncTask<SessionType> > > get_compiled_error_tasks() const {
            if (!_user_error_chain_explicitly_set) {
                return {};
            }
            return _user_defined_error_chain;
        }

        /**
         * @brief Checks if a user-defined error handling chain has been explicitly set.
         * @return `true` if `set_error_task_chain` was called (even with an empty list), `false` otherwise.
         */
        [[nodiscard]] bool is_error_chain_set() const noexcept {
            return _user_error_chain_explicitly_set;
        }

        /**
         * @brief Routes an incoming HTTP request to the appropriate handler chain.
         *
         * This is the main entry point for request processing by the `RouterCore`.
         * It performs the following steps:
         * 1. Creates a new `Context` for the request.
         * 2. Executes `PRE_ROUTING` lifecycle hooks on the context.
         * 3. Attempts to match the request's path and method against the `RadixTree`.
         * 4. If a match is found:
         *    a. Decodes extracted path parameters and sets them in the context.
         *    b. Sets the context's processing phase to `NORMAL_CHAIN`.
         *    c. Retrieves the compiled task chain for the matched route.
         * 5. If no match is found:
         *    a. Sets the context's processing phase to `NOT_FOUND_CHAIN`.
         *    b. Uses the compiled "404 Not Found" task chain.
         * 6. If the selected task chain is empty (which should be a critical error if defaults are working),
         *    it sets a 500 error and completes the context.
         * 7. Executes `PRE_HANDLER_EXECUTION` lifecycle hooks.
         * 8. Starts the execution of the selected task chain on the context.
         *
         * @param session_ptr A `std::shared_ptr` to the client session handling this request.
         * @param request_obj The incoming `qb::http::Request` object (moved into the context).
         * @return A `std::shared_ptr<Context<SessionType>>` for the processed request.
         *         The caller typically doesn't need to do much with this immediately, as the context
         *         manages its own lifecycle and will invoke `_on_request_finalized_callback` when done.
         */
        [[nodiscard]] std::shared_ptr<Context<SessionType> >
        route_request(std::shared_ptr<SessionType> session_ptr, qb::http::Request request_obj) {
            auto ctx = std::make_shared<Context<SessionType> >(
                std::move(request_obj),
                Response{}, // Default response prototype
                std::move(session_ptr),
                _on_request_finalized_callback,
                this->weak_from_this() // Pass weak_ptr of RouterCore to Context
            );

            ctx->execute_hook(qb::http::HookPoint::PRE_ROUTING);

            std::string request_path_str = std::string(ctx->request().uri().path());
            
            // Security: Limit path length to prevent DoS attacks
            // RFC 7230 recommends a practical limit of 8000 bytes for request-line, but we use a more conservative limit
            // for the path component alone. 4096 characters is a reasonable limit that prevents excessive allocations
            // while still allowing legitimate long paths (e.g., deep API hierarchies or encoded paths).
            constexpr size_t MAX_PATH_LENGTH = 4096;
            if (request_path_str.length() > MAX_PATH_LENGTH) {
                LOG_HTTP_WARN("Path length exceeds maximum (" << request_path_str.length() 
                    << " > " << MAX_PATH_LENGTH << "): " << request_path_str.substr(0, 100) << "...");
                ctx->response().status() = qb::http::status::BAD_REQUEST;
                ctx->response().body() = "Path too long";
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                ctx->complete(AsyncTaskResult::COMPLETE);
                return ctx;
            }
            
            qb::http::method request_method = ctx->request().method();
            
            LOG_HTTP_TRACE("Routing request: " << std::to_string(request_method) << " " << request_path_str);
            
            auto matched_info_opt = _radix_tree.match(request_path_str, request_method);

            std::vector<std::shared_ptr<IAsyncTask<SessionType> > > tasks_to_execute_vec;

            if (matched_info_opt && matched_info_opt->route_tasks && matched_info_opt->route_tasks.value()) {
                PathParameters decoded_params = std::move(matched_info_opt->path_parameters);
                // Decode URI-encoded path parameters.
                // RadixTree::match() stores raw (non-decoded) path segments in PathParameters.
                // We decode them here once to convert percent-encoded characters (e.g., %20 -> space).
                // Note: uri::decode() is idempotent, so calling it multiple times is safe but unnecessary.
                for (auto &param_pair: decoded_params) {
                    param_pair.second = qb::io::uri::decode(param_pair.second);
                }
                ctx->set_path_parameters(std::move(decoded_params));

                const auto &task_list_sptr = matched_info_opt->route_tasks.value();
                if (task_list_sptr) {
                    tasks_to_execute_vec = *task_list_sptr;
                }
                
                LOG_HTTP_DEBUG("Route matched: " << std::to_string(request_method) << " " << request_path_str);
                LOG_HTTP_TRACE("Route matched with " << decoded_params.size() << " path parameters");
                
                ctx->set_processing_phase(Context<SessionType>::ProcessingPhase::NORMAL_CHAIN);
            } else {
                // No route matched, use the compiled 404 tasks
                tasks_to_execute_vec = _compiled_not_found_tasks;
                
                LOG_HTTP_DEBUG("No route matched for: " << std::to_string(request_method) << " " << request_path_str << " (404)");
                
                ctx->set_processing_phase(Context<SessionType>::ProcessingPhase::NOT_FOUND_CHAIN);
            }

            if (tasks_to_execute_vec.empty()) {
                // This is a critical state: no tasks for a matched route or even for 404.
                // Should ideally not happen if compile_default_not_found_handler ensures a task.
                LOG_HTTP_ERROR("Router critical error: No task chain available for " 
                    << std::to_string(request_method) << " " << request_path_str);
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->response().body() = "Router critical error: No task chain available.";
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                ctx->complete(AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR); // Use FATAL to bypass normal error chain.
                return ctx;
            }

            // Context<SessionType>::log_task_chain_snapshot(tasks_to_execute_vec, "Initial routing decision", 0); // Removed debug log

            ctx->execute_hook(qb::http::HookPoint::PRE_HANDLER_EXECUTION);
            ctx->set_task_chain_and_start(std::move(tasks_to_execute_vec));
            return ctx;
        }

        /**
         * @brief Clears all registered routes and top-level handler nodes from the router.
         * Resets special handlers (404, error) to their system defaults.
         * The router must be recompiled (via `compile_all_routes()`) after clearing if it is to be used again.
         */
        void clear() noexcept {
            _radix_tree.clear();
            _top_level_nodes.clear();
            _custom_not_found_handler_set = false;
            _default_not_found_handler = nullptr; // Will cause re-creation of default handler
            _global_prefix_tasks_for_special_handlers.clear();
            _user_defined_error_chain.clear();
            _user_error_chain_explicitly_set = false;
            compile_default_not_found_handler({}); // Re-compile 404 with no global tasks for now.
        }
    }; // End RouterCore
} // namespace qb::http 

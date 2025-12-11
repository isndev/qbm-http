/**
 * @file qbm/http/routing/router.h
 * @brief Defines the main public HTTP Router class for defining and dispatching routes.
 *
 * This file contains the `Router` class template, which serves as the primary user interface
 * for defining HTTP routes, organizing them into groups or controllers, applying middleware,
 * and processing incoming HTTP requests. It internally uses a `RouterCore` for the actual
 * route matching and execution logic, and a root `RouteGroup` to facilitate a fluent API
 * for adding routes and global middleware directly to the router instance.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include <memory>       // For std::shared_ptr, std::make_shared, std::weak_ptr
#include <string>       // For std::string
#include <vector>       // For std::vector (used by some underlying components)
#include <type_traits>  // For std::enable_if_t, std::is_base_of_v
#include <functional>   // For std::function (used in RouteHandlerFn, MiddlewareHandlerFn)
#include <utility>      // For std::forward, std::move

#include "./router_core.h"  // Internal routing engine
#include "./route_group.h"  // For RouteGroup functionality
#include "./route.h"          // For Route class (used indirectly via RouteGroup)
#include "./controller.h"   // For Controller class
#include "./middleware.h"   // For IMiddleware interface
#include "./types.h"        // For RouteHandlerFn, MiddlewareHandlerFn, etc.
#include "../request.h"     // For qb::http::Request
#include "../types.h"       // For qb::http::method enum

namespace qb::http {
    /**
     * @brief Main HTTP Router class for defining and managing HTTP routes and middleware.
     *
     * The `Router` provides a fluent API to define how incoming HTTP requests are handled
     * based on their path and method. It supports:
     * - Defining routes for specific HTTP methods (GET, POST, etc.).
     * - Grouping routes under common path prefixes using `RouteGroup`.
     * - Organizing routes into class-based `Controller`s.
     * - Applying middleware at global, group, or controller levels.
     * - Customizing 404 (Not Found) and general error handling.
     *
     * Routes must be defined and then `compile()` must be called before the router can process requests.
     * Incoming requests are processed via the `route()` method.
     *
     * @tparam SessionType The type of the session object associated with the request `Context`.
     *                     This type is propagated throughout the routing system.
     */
    template<typename SessionType>
    class Router {
    private:
        std::shared_ptr<RouterCore<SessionType> > _router_core;
        ///< The core routing engine responsible for matching and execution.
        std::shared_ptr<RouteGroup<SessionType> > _root_group;
        ///< A default root group attached to the router for convenience.
                                                              ///< Routes and middleware added directly to the Router are attached to this group.
        bool _is_compiled = false; ///< Flag indicating if `compile()` has been called.

    public:
        /**
         * @brief Constructs a new `Router` instance.
         * Initializes the internal `RouterCore` and a root `RouteGroup`.
         * The `on_request_finalized_cb` passed to `RouterCore` is a placeholder here;
         * typically, a server implementation would provide a callback that uses the session
         * from the context to send the response.
         */
        Router();

        /** @brief Destructor. */
        ~Router();

        // --- Route Definition API (delegates to _root_group for convenience) --- 

        /** @brief Adds a route directly to the router (root level). @see RouteGroup::add_route */
        Router<SessionType> &add_route(std::string path, qb::http::method method,
                                       RouteHandlerFn<SessionType> handler_fn);

        /** @brief Adds a GET route directly to the router. @see RouteGroup::get */
        Router<SessionType> &get(std::string path, RouteHandlerFn<SessionType> handler_fn);

        /** @brief Adds a POST route directly to the router. @see RouteGroup::post */
        Router<SessionType> &post(std::string path, RouteHandlerFn<SessionType> handler_fn);

        /** @brief Adds a PUT route directly to the router. @see RouteGroup::put */
        Router<SessionType> &put(std::string path, RouteHandlerFn<SessionType> handler_fn);

        /** @brief Adds a DELETE route directly to the router. @see RouteGroup::del */
        Router<SessionType> &del(std::string path, RouteHandlerFn<SessionType> handler_fn);

        /** @brief Adds a PATCH route directly to the router. @see RouteGroup::patch */
        Router<SessionType> &patch(std::string path, RouteHandlerFn<SessionType> handler_fn);

        /** @brief Adds an OPTIONS route directly to the router. @see RouteGroup::options */
        Router<SessionType> &options(std::string path, RouteHandlerFn<SessionType> handler_fn);

        /** @brief Adds a HEAD route directly to the router. @see RouteGroup::head */
        Router<SessionType> &head(std::string path, RouteHandlerFn<SessionType> handler_fn);

        // --- Overloads for ICustomRoute shared_ptr at root level ---
        /** @brief Adds a GET route with an `ICustomRoute` handler directly to the router. @see RouteGroup::get */
        Router<SessionType> &get(std::string path, std::shared_ptr<ICustomRoute<SessionType> > custom_route);

        /** @brief Adds a POST route with an `ICustomRoute` handler directly to the router. @see RouteGroup::post */
        Router<SessionType> &post(std::string path, std::shared_ptr<ICustomRoute<SessionType> > custom_route);

        /** @brief Adds a PUT route with an `ICustomRoute` handler directly to the router. @see RouteGroup::put */
        Router<SessionType> &put(std::string path, std::shared_ptr<ICustomRoute<SessionType> > custom_route);

        /** @brief Adds a DELETE route with an `ICustomRoute` handler directly to the router. @see RouteGroup::del */
        Router<SessionType> &del(std::string path, std::shared_ptr<ICustomRoute<SessionType> > custom_route);

        /** @brief Adds a PATCH route with an `ICustomRoute` handler directly to the router. @see RouteGroup::patch */
        Router<SessionType> &patch(std::string path, std::shared_ptr<ICustomRoute<SessionType> > custom_route);

        /** @brief Adds an OPTIONS route with an `ICustomRoute` handler directly to the router. @see RouteGroup::options */
        Router<SessionType> &options(std::string path, std::shared_ptr<ICustomRoute<SessionType> > custom_route);

        /** @brief Adds a HEAD route with an `ICustomRoute` handler directly to the router. @see RouteGroup::head */
        Router<SessionType> &head(std::string path, std::shared_ptr<ICustomRoute<SessionType> > custom_route);

        // --- Typed ICustomRoute support at root level ---
        /**
         * @brief Adds a route with a custom handler type constructed in-place directly to the router.
         * @tparam CustomRouteType The concrete type of the custom route handler, must derive from `ICustomRoute<SessionType>`.
         * @tparam Args Variadic arguments for the `CustomRouteType` constructor.
         * @param path The path for this route.
         * @param method The HTTP method this route responds to.
         * @param ctor_args Constructor arguments for `CustomRouteType`.
         * @return Reference to this `Router` for chaining.
         */
        template<typename CustomRouteType, typename... Args,
            typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<SessionType>, CustomRouteType> > >
        Router<SessionType> &add_custom_route(std::string path, qb::http::method method, Args &&... ctor_args);

        /** @brief Adds a GET route with a typed `ICustomRoute` handler directly to the router. @see add_custom_route */
        template<typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<
            SessionType>, CustomRouteType> > >
        Router<SessionType> &get(std::string path, Args &&... ctor_args);

        /** @brief Adds a POST route with a typed `ICustomRoute` handler directly to the router. @see add_custom_route */
        template<typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<
            SessionType>, CustomRouteType> > >
        Router<SessionType> &post(std::string path, Args &&... ctor_args);

        // ... Other HTTP methods for typed custom routes ...
        template<typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<
            SessionType>, CustomRouteType> > >
        Router<SessionType> &put(std::string path, Args &&... ctor_args);

        template<typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<
            SessionType>, CustomRouteType> > >
        Router<SessionType> &del(std::string path, Args &&... ctor_args);

        template<typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<
            SessionType>, CustomRouteType> > >
        Router<SessionType> &patch(std::string path, Args &&... ctor_args);

        template<typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<
            SessionType>, CustomRouteType> > >
        Router<SessionType> &options(std::string path, Args &&... ctor_args);

        template<typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<
            SessionType>, CustomRouteType> > >
        Router<SessionType> &head(std::string path, Args &&... ctor_args);


        /**
         * @brief Creates a new top-level `RouteGroup` under this router.
         * @param path_prefix The prefix for all routes within this group (e.g., "/api").
         * @return A `std::shared_ptr` to the created `RouteGroup` for further configuration.
         */
        [[nodiscard]] std::shared_ptr<RouteGroup<SessionType> > group(std::string path_prefix);

        /**
         * @brief Mounts a `Controller` directly under this router with a given path prefix.
         * @tparam C The controller class type. Must be derived from `Controller<SessionType>`.
         * @tparam Args Variadic arguments for the controller's constructor.
         * @param path_prefix The base path for this controller (e.g., "/users").
         * @param args Constructor arguments to be forwarded to the controller `C`.
         * @return A `std::shared_ptr<C>` to the created and mounted controller instance.
         */
        template<typename C, typename... Args,
            typename = std::enable_if_t<std::is_base_of_v<Controller<SessionType>, C> > >
        std::shared_ptr<C> controller(std::string path_prefix, Args &&... args);

        // --- Middleware methods (apply to the root group, effectively global) --- 
        /**
         * @brief Adds global middleware using a `MiddlewareHandlerFn` (lambda/function pointer).
         * This middleware applies to all routes handled by this router.
         * @param mw_fn The middleware handler function.
         * @param name An optional name for this middleware instance. Defaults to "UnnamedGlobalFunctionalMiddleware".
         * @return Reference to this `Router` for chaining.
         */
        Router<SessionType> &use(MiddlewareHandlerFn<SessionType> mw_fn,
                                 std::string name = "UnnamedGlobalFunctionalMiddleware");

        /**
         * @brief Adds global middleware using a shared pointer to an `IMiddleware` object.
         * @param mw_ptr A `std::shared_ptr<IMiddleware<SessionType>>` instance.
         * @param name_override Optional: A name to use for this middleware task. If empty, derives from `mw_ptr`.
         * @return Reference to this `Router` for chaining.
         */
        Router<SessionType> &use(std::shared_ptr<IMiddleware<SessionType> > mw_ptr, std::string name_override = "");

        /**
         * @brief Adds global middleware by constructing an instance of `MiddlewareType` in-place.
         * @tparam MiddlewareType The concrete type of the middleware, must derive from `IMiddleware<SessionType>`.
         * @tparam Args Variadic arguments for the `MiddlewareType` constructor.
         * @param args Constructor arguments to be forwarded to `MiddlewareType`.
         * @return Reference to this `Router` for chaining.
         */
        template<typename MiddlewareType, typename... Args,
            typename = std::enable_if_t<std::is_base_of_v<IMiddleware<SessionType>, MiddlewareType> > >
        Router<SessionType> &use(Args &&... args);

        /**
         * @brief Sets a custom handler for "404 Not Found" responses for this router.
         * @param handler_fn The `RouteHandlerFn` to be invoked when no route matches.
         */
        void set_not_found_handler(RouteHandlerFn<SessionType> handler_fn);

        /**
         * @brief Sets the global error handling task chain for this router.
         * This chain is invoked when a task signals `AsyncTaskResult::ERROR`.
         * @param error_chain A vector of `IAsyncTask` shared pointers forming the error handling chain.
         */
        void set_error_task_chain(std::vector<std::shared_ptr<IAsyncTask<SessionType> > > error_chain);

        /**
         * @brief Finalizes all route definitions and compiles them into an efficient structure for matching.
         * This method **must** be called after all routes, groups, controllers, and middleware
         * have been defined and before the router is used to process any requests.
         * Calling `compile()` again will recompile all routes.
         */
        void compile();

        /**
         * @brief Processes an incoming HTTP request by matching it against the compiled routes
         *        and dispatching it to the appropriate handler chain.
         *
         * @param session A `std::shared_ptr` to the client session object associated with this request.
         *                This session is typically used by the underlying server infrastructure to send the response.
         * @param request The incoming `qb::http::Request` object to be processed (moved into the context).
         * @return A `std::shared_ptr<Context<SessionType>>` representing the context of this request processing.
         *         The context manages its own lifecycle and asynchronous task execution.
         */
        std::shared_ptr<Context<SessionType> > route(std::shared_ptr<SessionType> session, qb::http::Request request);

        /**
         * @brief (Advanced) Gets a weak pointer to the internal `RouterCore` instance.
         * This is typically used by components that need to interact deeply with the routing engine,
         * such as the `Context` for accessing error handlers.
         * @return A `std::weak_ptr<RouterCore<SessionType>>`.
         */
        [[nodiscard]] std::weak_ptr<RouterCore<SessionType> > get_router_core_weak_ptr() noexcept;

        /**
         * @brief Clears all defined routes, groups, controllers, middleware, and custom handlers.
         * Resets the router to its initial state. After clearing, `compile()` must be called again
         * if new routes are defined before the router can process requests.
         */
        void clear() noexcept;
    };
} // namespace qb::http

#include "./router.tpp" // Template implementations are in a .tpp file 

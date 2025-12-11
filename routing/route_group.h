/**
 * @file qbm/http/routing/route_group.h
 * @brief Defines the RouteGroup class for organizing HTTP routes hierarchically.
 *
 * This file contains the `RouteGroup` class template, which allows for the grouping
 * of HTTP routes, other route groups, and controllers under a common path prefix.
 * Middleware applied to a `RouteGroup` is inherited by all its children, enabling
 * shared functionality like authentication or logging for a section of the API.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include "./handler_node.h"
#include "./route.h"
#include "./middleware.h"
#include "./types.h" // For RouteHandlerFn, MiddlewareHandlerFn
#include "../types.h" // For qb::http::method

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <iostream>
#include <type_traits> // For std::enable_if_t, std::is_base_of_v

namespace qb::http {
    // Forward declarations
    template<typename Session>
    class RouterCore;

    template<typename Session>
    class Controller;

    /**
     * @brief Represents a group of routes that share a common path prefix and middleware stack.
     *
     * `RouteGroup` is a non-terminal node in the routing hierarchy. It allows for logical
     * organization of routes. Middleware added to a `RouteGroup` will be applied to all
     * routes, child groups, and controllers mounted under it. The path prefix of a group
     * is prepended to the path segments of all its children.
     *
     * @tparam SessionType The session type used by the `Context` and `IAsyncTask` system,
     *                     propagated to all child nodes.
     */
    template<typename Session>
    class RouteGroup : public IHandlerNode<Session> {
    private:
        /** @brief Child nodes of this group, which can be `Route`, `RouteGroup`, or `Controller` instances. */
        std::vector<std::shared_ptr<IHandlerNode<Session> > > _children;

        // --- Task Compilation ---
        /**
         * @brief Compiles tasks for this group and its children.
         * This method combines middleware inherited from its parent with its own middleware,
         * then recursively calls `compile_tasks_and_register` on all its child nodes,
         * passing down the augmented path and task list.
         * @param router_core Reference to the `RouterCore`.
         * @param current_built_path The full path accumulated up to this group's parent.
         * @param inherited_tasks Middleware tasks passed down from the parent.
         */
        void compile_tasks_and_register(
            RouterCore<Session> &router_core,
            const std::string &current_built_path,
            const std::vector<std::shared_ptr<IAsyncTask<Session> > > &inherited_tasks) override {
            std::string group_full_path = this->build_full_path(current_built_path);
            std::vector<std::shared_ptr<IAsyncTask<Session> > > tasks_for_children = this->combine_tasks(inherited_tasks);

            for (const auto &child: _children) {
                if (child) {
                    child->compile_tasks_and_register(router_core, group_full_path, tasks_for_children);
                }
            }
        }

    public:
        /**
         * @brief Constructs a `RouteGroup` with a specified path prefix.
         * @param path_prefix The common URL path prefix for all routes and sub-groups within this group.
         *                    For example, "/api/v1". This prefix is relative to the parent group or router.
         */
        explicit RouteGroup(std::string path_prefix)
            : IHandlerNode<Session>(std::move(path_prefix)) {
        }

        /**
         * @brief Gets a descriptive name for this route group node.
         * @return A string in the format "RouteGroup: [path_prefix]".
         */
        [[nodiscard]] std::string get_node_name() const noexcept override {
            return "RouteGroup: " + this->_path_segment;
        }

        // --- Fluent API for adding routes, groups, controllers, and middleware ---

        /**
         * @brief Adds a new route to this group using a `RouteHandlerFn` (lambda/function pointer).
         * @param path The path for this route, relative to the group's prefix.
         * @param method The HTTP method this route responds to.
         * @param handler_fn The function that will handle requests to this route.
         * @return Reference to this `RouteGroup` for chaining.
         */
        RouteGroup<Session> &add_route(std::string path, qb::http::method method, RouteHandlerFn<Session> handler_fn) {
            auto route_node = std::make_shared<Route<Session> >(std::move(path), method, std::move(handler_fn));
            add_child(route_node);
            return *this;
        }

        /** @brief Adds a GET route. @see add_route */
        RouteGroup<Session> &get(std::string path, RouteHandlerFn<Session> handler_fn) {
            return add_route(std::move(path), qb::http::method::GET, std::move(handler_fn));
        }

        /** @brief Adds a POST route. @see add_route */
        RouteGroup<Session> &post(std::string path, RouteHandlerFn<Session> handler_fn) {
            return add_route(std::move(path), qb::http::method::POST, std::move(handler_fn));
        }

        /** @brief Adds a PUT route. @see add_route */
        RouteGroup<Session> &put(std::string path, RouteHandlerFn<Session> handler_fn) {
            return add_route(std::move(path), qb::http::method::PUT, std::move(handler_fn));
        }

        /** @brief Adds a DELETE route. @see add_route */
        RouteGroup<Session> &del(std::string path, RouteHandlerFn<Session> handler_fn) {
            return add_route(std::move(path), qb::http::method::DEL, std::move(handler_fn));
        }

        /** @brief Adds a PATCH route. @see add_route */
        RouteGroup<Session> &patch(std::string path, RouteHandlerFn<Session> handler_fn) {
            return add_route(std::move(path), qb::http::method::PATCH, std::move(handler_fn));
        }

        /** @brief Adds an OPTIONS route. @see add_route */
        RouteGroup<Session> &options(std::string path, RouteHandlerFn<Session> handler_fn) {
            return add_route(std::move(path), qb::http::method::OPTIONS, std::move(handler_fn));
        }

        /** @brief Adds a HEAD route. @see add_route */
        RouteGroup<Session> &head(std::string path, RouteHandlerFn<Session> handler_fn) {
            return add_route(std::move(path), qb::http::method::HEAD, std::move(handler_fn));
        }

        /**
         * @brief Adds a new route to this group using a pre-created `ICustomRoute` object.
         * @param path The path for this route, relative to the group's prefix.
         * @param method The HTTP method this route responds to.
         * @param custom_route A `std::shared_ptr` to an object implementing `ICustomRoute`.
         * @return Reference to this `RouteGroup` for chaining.
         */
        RouteGroup<Session> &add_route(std::string path, qb::http::method method,
                                       std::shared_ptr<ICustomRoute<Session> > custom_route) {
            auto route_node = std::make_shared<Route<Session> >(std::move(path), method, std::move(custom_route));
            add_child(route_node);
            return *this;
        }

        /** @brief Adds a GET route with an `ICustomRoute` handler. @see add_route */
        RouteGroup<Session> &get(std::string path, std::shared_ptr<ICustomRoute<Session> > custom_route) {
            return add_route(std::move(path), qb::http::method::GET, std::move(custom_route));
        }

        /** @brief Adds a POST route with an `ICustomRoute` handler. @see add_route */
        RouteGroup<Session> &post(std::string path, std::shared_ptr<ICustomRoute<Session> > custom_route) {
            return add_route(std::move(path), qb::http::method::POST, std::move(custom_route));
        }

        /** @brief Adds a PUT route with an `ICustomRoute` handler. @see add_route */
        RouteGroup<Session> &put(std::string path, std::shared_ptr<ICustomRoute<Session> > custom_route) {
            return add_route(std::move(path), qb::http::method::PUT, std::move(custom_route));
        }

        /** @brief Adds a DELETE route with an `ICustomRoute` handler. @see add_route */
        RouteGroup<Session> &del(std::string path, std::shared_ptr<ICustomRoute<Session> > custom_route) {
            return add_route(std::move(path), qb::http::method::DEL, std::move(custom_route));
        }

        /** @brief Adds a PATCH route with an `ICustomRoute` handler. @see add_route */
        RouteGroup<Session> &patch(std::string path, std::shared_ptr<ICustomRoute<Session> > custom_route) {
            return add_route(std::move(path), qb::http::method::PATCH, std::move(custom_route));
        }

        /** @brief Adds an OPTIONS route with an `ICustomRoute` handler. @see add_route */
        RouteGroup<Session> &options(std::string path, std::shared_ptr<ICustomRoute<Session> > custom_route) {
            return add_route(std::move(path), qb::http::method::OPTIONS, std::move(custom_route));
        }

        /** @brief Adds a HEAD route with an `ICustomRoute` handler. @see add_route */
        RouteGroup<Session> &head(std::string path, std::shared_ptr<ICustomRoute<Session> > custom_route) {
            return add_route(std::move(path), qb::http::method::HEAD, std::move(custom_route));
        }

        /**
         * @brief Creates a new nested `RouteGroup` under this group.
         * @param path_prefix The path prefix for the new nested group, relative to this group's path.
         * @return A `std::shared_ptr` to the newly created `RouteGroup`, allowing further configuration on it.
         */
        [[nodiscard]] std::shared_ptr<RouteGroup<Session> > group(std::string path_prefix) {
            auto group_node = std::make_shared<RouteGroup<Session> >(std::move(path_prefix));
            add_child(group_node);
            return group_node;
        }

        /**
         * @brief Mounts a `Controller` under this group with a given path prefix.
         * The controller's routes will be relative to `this_group_path + path_prefix`.
         * @tparam C The controller class type. Must be derived from `Controller<Session>`.
         * @tparam Args Variadic arguments for the controller's constructor.
         * @param path_prefix The base path for this controller instance, relative to this group's path.
         * @param args Constructor arguments to be forwarded to the controller `C`.
         * @return A `std::shared_ptr<C>` to the created and mounted controller instance.
         */
        template<typename C, typename... Args,
            typename = std::enable_if_t<std::is_base_of_v<Controller<Session>, C> > >
        [[nodiscard]] std::shared_ptr<C> controller(std::string path_prefix, Args &&... args) {
            auto controller_node = std::make_shared<C>(std::forward<Args>(args)...);
            controller_node->set_base_path_segment(std::move(path_prefix));
            add_child(std::static_pointer_cast<IHandlerNode<Session> >(controller_node));
            return controller_node;
        }

        // --- Middleware methods ---

        /**
         * @brief Adds middleware to this group using a `MiddlewareHandlerFn` (lambda/function pointer).
         * The middleware will apply to all routes, child groups, and controllers within this group.
         * @param mw_fn The middleware handler function.
         * @param name An optional name for this middleware instance, useful for logging or debugging.
         * @return Reference to this `RouteGroup` for chaining.
         */
        RouteGroup<Session> &use(MiddlewareHandlerFn<Session> mw_fn,
                                 std::string name = "UnnamedFunctionalMiddleware") {
            auto functional_middleware = std::make_shared<FunctionalMiddleware<Session> >(std::move(mw_fn), name);
            auto middleware_task = std::make_shared<MiddlewareTask<Session> >(
                std::move(functional_middleware), std::move(name));
            this->add_middleware(std::move(middleware_task)); // From IHandlerNode
            return *this;
        }

        /**
         * @brief Adds middleware to this group using a shared pointer to an `IMiddleware` object.
         * @param mw_ptr A `std::shared_ptr<IMiddleware<Session>>` instance.
         * @param name_override Optional: A name to use for this middleware task. If empty,
         *                      it attempts to use `mw_ptr->name()`, then a type-derived name, then a default.
         * @return Reference to this `RouteGroup` for chaining.
         */
        RouteGroup<Session> &use(std::shared_ptr<IMiddleware<Session> > mw_ptr, std::string name_override = "") {
            if (!mw_ptr) return *this; // Do nothing if null middleware pointer is passed
            std::string task_name = name_override;
            if (task_name.empty()) {
                task_name = mw_ptr->name(); // Use middleware's own name if available
                if (task_name.empty()) {
                    // Fallback to typeid if name() returns empty
                    task_name = typeid(*mw_ptr).name();
                }
            }
            if (task_name.empty()) {
                // Ultimate fallback
                task_name = "UnnamedSharedPtrMiddleware";
            }
            auto middleware_task = std::make_shared<MiddlewareTask<Session> >(std::move(mw_ptr), std::move(task_name));
            this->add_middleware(std::move(middleware_task)); // From IHandlerNode
            return *this;
        }

        /**
         * @brief Adds middleware to this group by constructing an instance of `MiddlewareType` in-place.
         * @tparam MiddlewareType The concrete type of the middleware, must derive from `IMiddleware<Session>`.
         * @tparam Args Variadic arguments for the `MiddlewareType` constructor.
         * @param args Constructor arguments to be forwarded to `MiddlewareType`.
         * @return Reference to this `RouteGroup` for chaining.
         */
        template<typename MiddlewareType, typename... Args,
            typename = std::enable_if_t<std::is_base_of_v<IMiddleware<Session>, MiddlewareType> > >
        RouteGroup<Session> &use(Args &&... args) {
            auto mw_instance = std::make_shared<MiddlewareType>(std::forward<Args>(args)...);
            return use(std::move(mw_instance), ""); // Delegate to the shared_ptr overload for name derivation
        }

        /**
         * @brief (Protected-like, public for CRTP use by Router) Adds a child node to this group.
         * Sets this group as the parent of the child node.
         * @param child_node A `std::shared_ptr<IHandlerNode<Session>>` representing the child.
         */
        void add_child(std::shared_ptr<IHandlerNode<Session> > child_node) {
            if (child_node) {
                // Ensure not adding a null child
                child_node->set_parent(this->weak_from_this());
                _children.push_back(std::move(child_node));
            }
        }

        // --- Typed Route Support (Convenience for adding ICustomRoute derived types directly) ---
        /**
         * @brief Adds a route with a custom handler type constructed in-place.
         * @tparam CustomRouteType The concrete type of the custom route handler, must derive from `ICustomRoute<Session>`.
         * @tparam Args Variadic arguments for the `CustomRouteType` constructor.
         * @param path The path for this route, relative to the group's prefix.
         * @param method The HTTP method this route responds to.
         * @param ctor_args Constructor arguments for `CustomRouteType`.
         * @return Reference to this `RouteGroup` for chaining.
         */
        template<typename CustomRouteType, typename... Args,
            typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType> > >
        RouteGroup<Session> &add_custom_route(std::string path, qb::http::method method, Args &&... ctor_args) {
            auto custom_route_obj = std::make_shared<CustomRouteType>(std::forward<Args>(ctor_args)...);
            auto route_node = std::make_shared<Route<Session> >(std::move(path), method, std::move(custom_route_obj));
            add_child(route_node);
            return *this;
        }

        /** @brief Adds a GET route with a typed `ICustomRoute` handler. @see add_custom_route */
        template<typename CustomRouteType, typename... Args>
        RouteGroup<Session> &get(std::string path, Args &&... ctor_args) {
            return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::GET,
                                                     std::forward<Args>(ctor_args)...);
        }

        /** @brief Adds a POST route with a typed `ICustomRoute` handler. @see add_custom_route */
        template<typename CustomRouteType, typename... Args>
        RouteGroup<Session> &post(std::string path, Args &&... ctor_args) {
            return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::POST,
                                                     std::forward<Args>(ctor_args)...);
        }

        /** @brief Adds a PUT route with a typed `ICustomRoute` handler. @see add_custom_route */
        template<typename CustomRouteType, typename... Args>
        RouteGroup<Session> &put(std::string path, Args &&... ctor_args) {
            return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::PUT,
                                                     std::forward<Args>(ctor_args)...);
        }

        /** @brief Adds a DELETE route with a typed `ICustomRoute` handler. @see add_custom_route */
        template<typename CustomRouteType, typename... Args>
        RouteGroup<Session> &del(std::string path, Args &&... ctor_args) {
            return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::DEL,
                                                     std::forward<Args>(ctor_args)...);
        }

        /** @brief Adds a PATCH route with a typed `ICustomRoute` handler. @see add_custom_route */
        template<typename CustomRouteType, typename... Args>
        RouteGroup<Session> &patch(std::string path, Args &&... ctor_args) {
            return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::PATCH,
                                                     std::forward<Args>(ctor_args)...);
        }

        /** @brief Adds an OPTIONS route with a typed `ICustomRoute` handler. @see add_custom_route */
        template<typename CustomRouteType, typename... Args>
        RouteGroup<Session> &options(std::string path, Args &&... ctor_args) {
            return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::OPTIONS,
                                                     std::forward<Args>(ctor_args)...);
        }

        /** @brief Adds a HEAD route with a typed `ICustomRoute` handler. @see add_custom_route */
        template<typename CustomRouteType, typename... Args>
        RouteGroup<Session> &head(std::string path, Args &&... ctor_args) {
            return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HEAD,
                                                     std::forward<Args>(ctor_args)...);
        }
    }; // class RouteGroup
} // namespace qb::http

/**
 * @file qbm/http/routing/controller.h
 * @brief Defines the Controller base class for organizing HTTP routes within a class structure.
 *
 * This file contains the `Controller` template class, which serves as a base for user-defined
 * controllers. Controllers allow grouping of related route handlers under a common base path
 * and can manage their own stack of middleware that applies to all routes defined within them.
 * This promotes modularity and reusability in route definitions.
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
#include "./context.h"

#include <string>
#include <vector>
#include <memory>
#include <list>
#include <functional>
#include <typeinfo>
#include <type_traits> // For std::enable_if_t, std::is_base_of_v

namespace qb::http {

// Forward declaration
template <typename Session>
class RouterCore;

/**
 * @brief Base class for user-defined controllers in the HTTP routing system.
 *
 * Controllers provide a way to group related HTTP route handlers within a single class.
 * They are mounted onto a `Router` or `RouteGroup` at a specific base path, and all routes
 * defined within the controller are relative to this base path.
 * Controllers can also have their own middleware stack, which is applied to all their routes,
 * in addition to any middleware inherited from parent groups or the main router.
 *
 * Derived classes must implement the `initialize_routes()` pure virtual method to define
 * their routes using the provided fluent API (e.g., `get()`, `post()`, `use()`).
 *
 * @tparam SessionType The session type used by the `Context` and `IAsyncTask` system,
 *                     propagated throughout the routing system.
 */
template <typename Session>
class Controller : public IHandlerNode<Session> {
protected:
    // Routes defined within this controller. They are relative to the controller's base path.
    std::vector<std::shared_ptr<IHandlerNode<Session>>> _controller_routes;

    using ControllerMiddlewareFn = std::function<std::shared_ptr<IMiddleware<Session>>(void)>;

    // Helper methods for derived controllers to define routes
    // These can remain protected as they are implementation details for the public API below

    /**
     * @brief (Protected) Adds a route with a `RouteHandlerFn` (lambda/function) to this controller.
     * @param path Path relative to the controller's base path.
     * @param method The HTTP method for the route.
     * @param handler_fn The handler function.
     * @return Reference to this `Controller` for chaining.
     */
    Controller<Session>& add_controller_route(std::string path, qb::http::method method, RouteHandlerFn<Session> handler_fn) {
        auto route_node = std::make_shared<Route<Session>>(std::move(path), method, std::move(handler_fn));
        route_node->set_parent(this->weak_from_this()); // Route's parent is this controller instance
        _controller_routes.push_back(std::move(route_node));
        return *this;
    }

    /**
     * @brief (Protected) Adds a route with an `ICustomRoute` object to this controller.
     * @param path Path relative to the controller's base path.
     * @param method The HTTP method for the route.
     * @param custom_route_ptr Shared pointer to the `ICustomRoute` instance.
     * @return Reference to this `Controller` for chaining.
     */
    Controller<Session>& add_controller_route(std::string path, qb::http::method method, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        auto route_node = std::make_shared<Route<Session>>(std::move(path), method, std::move(custom_route_ptr));
        route_node->set_parent(this->weak_from_this());
        _controller_routes.push_back(std::move(route_node));
        return *this;
    }

    /**
     * @brief (Protected) Adds a route with a custom handler of `CustomRouteType` constructed in-place.
     * @tparam CustomRouteType The concrete type of the custom route handler (must derive from `ICustomRoute`).
     * @tparam Args Variadic arguments for the `CustomRouteType` constructor.
     * @param path Path relative to the controller's base path.
     * @param method The HTTP method for the route.
     * @param ctor_args Constructor arguments for `CustomRouteType`.
     * @return Reference to this `Controller` for chaining.
     */
    template <typename CustomRouteType, typename... Args,
              typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session>& add_controller_custom_route(std::string path, qb::http::method method, Args&&... ctor_args) {
        static_assert(std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>, "CustomRouteType must derive from ICustomRoute<Session>");
        auto custom_route_obj = std::make_shared<CustomRouteType>(std::forward<Args>(ctor_args)...);
        auto route_node = std::make_shared<Route<Session>>(std::move(path), method, custom_route_obj);
        route_node->set_parent(this->weak_from_this());
        _controller_routes.push_back(std::move(route_node));
        return *this;
    }

public:
    using SessionType = Session;
    using Context = Context<Session>;

    /**
     * @brief Default constructor.
     * Controllers are typically constructed with an empty base path segment (`""`).
     * Their actual mount path segment is set by the `Router` or `RouteGroup` via `set_base_path_segment()`.
     */
    Controller() : IHandlerNode<Session>("") {}
    /** @brief Virtual destructor. */
    virtual ~Controller() = default;

    /**
     * @brief Sets the base path segment for this controller instance.
     * This is usually called by the `Router` or `RouteGroup` when this controller is mounted,
     * establishing the controller's root path in the overall routing tree.
     * @param path_segment The path segment string (e.g., "/auth", "users").
     */
    void set_base_path_segment(std::string path_segment) noexcept {
        this->_path_segment = std::move(path_segment);
    }

    /**
     * @brief Gets a descriptive name for this controller node.
     * @return A string in the format "Controller: [base_path_segment]".
     */
    [[nodiscard]] std::string get_node_name() const override {
        return "Controller: " + this->_path_segment;
    }

    /**
     * @brief Pure virtual method that must be implemented by derived controllers to define their routes.
     *
     * Inside this method, derived controllers should use the provided public fluent API methods
     * (e.g., `get("/path", ...)`, `post("/items", ...)`, `use(...)`) to declare their routes
     * and controller-specific middleware.
     *
     * Example:
     * @code
     * class MyUserController : public qb::http::Controller<MySession> {
     * public:
     *     void initialize_routes() override {
     *         get("/:id", MEMBER_HANDLER(&MyUserController::getUserById));
     *         post("/", MEMBER_HANDLER(&MyUserController::createUser));
     *         use(std::make_shared<MyUserAuthMiddleware>());
     *     }
     *     // ... handler methods ...
     * };
     * @endcode
     */
    virtual void initialize_routes() = 0;

// --- Public Route Definition API for use within initialize_routes() ---

    // --- Lambda-based routes ---
    /** @brief Defines a GET route with a lambda handler. @see add_controller_route */
    Controller<Session>& get(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::GET, std::move(handler_fn));
    }
    /** @brief Defines a POST route with a lambda handler. @see add_controller_route */
    Controller<Session>& post(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::POST, std::move(handler_fn));
    }
    /** @brief Defines a PUT route with a lambda handler. @see add_controller_route */
    Controller<Session>& put(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::PUT, std::move(handler_fn));
    }
    /** @brief Defines a DELETE route with a lambda handler. @see add_controller_route */
    Controller<Session>& del(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::DEL, std::move(handler_fn));
    }
    /** @brief Defines a PATCH route with a lambda handler. @see add_controller_route */
    Controller<Session>& patch(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::PATCH, std::move(handler_fn));
    }
    /** @brief Defines an OPTIONS route with a lambda handler. @see add_controller_route */
    Controller<Session>& options(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::OPTIONS, std::move(handler_fn));
    }
    /** @brief Defines a HEAD route with a lambda handler. @see add_controller_route */
    Controller<Session>& head(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::HEAD, std::move(handler_fn));
    }

    // --- Typed ICustomRoute routes (constructs CustomRouteType in-place) ---
    /** @brief Defines a GET route with a typed `ICustomRoute` handler. @see add_controller_custom_route */
    template <typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session>& get(std::string path, Args&&... ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::GET, std::forward<Args>(ctor_args)...);
    }
    /** @brief Defines a POST route with a typed `ICustomRoute` handler. @see add_controller_custom_route */
    template <typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session>& post(std::string path, Args&&... ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::POST, std::forward<Args>(ctor_args)...);
    }
    // ... (similar overloads for PUT, DELETE, PATCH, OPTIONS, HEAD with CustomRouteType) ...
    template <typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session>& put(std::string path, Args&&... ctor_args) { return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::PUT, std::forward<Args>(ctor_args)...); }
    template <typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session>& del(std::string path, Args&&... ctor_args) { return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::DEL, std::forward<Args>(ctor_args)...); }
    template <typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session>& patch(std::string path, Args&&... ctor_args) { return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::PATCH, std::forward<Args>(ctor_args)...); }
    template <typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session>& options(std::string path, Args&&... ctor_args) { return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::OPTIONS, std::forward<Args>(ctor_args)...); }
    template <typename CustomRouteType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session>& head(std::string path, Args&&... ctor_args) { return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::HEAD, std::forward<Args>(ctor_args)...); }


    // --- std::shared_ptr<ICustomRoute<Session>> routes ---
    /** @brief Defines a GET route with a pre-created `ICustomRoute` handler. @see add_controller_route */
    Controller<Session>& get(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::GET, std::move(custom_route_ptr));
    }
    /** @brief Defines a POST route with a pre-created `ICustomRoute` handler. @see add_controller_route */
    Controller<Session>& post(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::POST, std::move(custom_route_ptr));
    }
    // ... (similar overloads for PUT, DELETE, PATCH, OPTIONS, HEAD with shared_ptr<ICustomRoute>) ...
    Controller<Session>& put(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) { return add_controller_route(std::move(path), qb::http::method::PUT, std::move(custom_route_ptr)); }
    Controller<Session>& del(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) { return add_controller_route(std::move(path), qb::http::method::DEL, std::move(custom_route_ptr)); }
    Controller<Session>& patch(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) { return add_controller_route(std::move(path), qb::http::method::PATCH, std::move(custom_route_ptr)); }
    Controller<Session>& options(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) { return add_controller_route(std::move(path), qb::http::method::OPTIONS, std::move(custom_route_ptr)); }
    Controller<Session>& head(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) { return add_controller_route(std::move(path), qb::http::method::HEAD, std::move(custom_route_ptr)); }


    /**
     * @def MEMBER_HANDLER(handler_ptr)
     * @brief A convenience macro for binding a controller's member function as a route handler.
     * Captures `this` pointer to call the member function.
     * Usage within `initialize_routes()`:
     * @code get("/path", MEMBER_HANDLER(&MyController::handler_method)); @endcode
     * where `handler_method` has a signature like `void handler_method(std::shared_ptr<Context<SessionType>> ctx);`.
     */
    #define MEMBER_HANDLER(handler_ptr) \
        [this](std::shared_ptr<Context> ctx_param) { (this->*handler_ptr)(ctx_param); }

public:
    // --- Middleware for this controller --- 

    /**
     * @brief Adds middleware to this controller using a factory function (`ControllerMiddlewareFn`).
     * The factory function is invoked to create an instance of the middleware.
     * @param mw_fn A function that returns `std::shared_ptr<IMiddleware<SessionType>>`.
     * @param name An optional name for this middleware task. If empty or default, tries to use middleware's own name.
     * @return Reference to this `Controller` for chaining.
     */
    Controller<Session>& use(ControllerMiddlewareFn mw_fn, std::string name = "ControllerMiddleware_Use") {
        if (!mw_fn) return *this;
        auto middleware_instance = mw_fn(); 
        if (!middleware_instance) {
            // Consider logging a warning if a logging facility is available.
            return *this;
        }
        std::string task_name = name;
        if (task_name == "ControllerMiddleware_Use" || task_name.empty()) {
            task_name = middleware_instance->name();
        }
        if (task_name.empty()) {
            task_name = "UnnamedControllerFactoryMiddleware_Use";
        }
        auto middleware_task = std::make_shared<MiddlewareTask<Session>>(std::move(middleware_instance), std::move(task_name));
        this->add_middleware(std::move(middleware_task)); // From IHandlerNode
        return *this;
    }

    /**
     * @brief Adds middleware to this controller using a pre-created `std::shared_ptr<IMiddleware<SessionType>>`.
     * @param mw_ptr Shared pointer to the middleware instance.
     * @param name_override Optional: A specific name for this middleware task. If empty, derives name from `mw_ptr`.
     * @return Reference to this `Controller` for chaining.
     */
    Controller<Session>& use(std::shared_ptr<IMiddleware<Session>> mw_ptr, std::string name_override = "") {
        if (!mw_ptr) return *this;
        std::string name = name_override;
        if (name.empty()) {
            std::string base_name = mw_ptr->name();
            if (base_name.empty()) {
                base_name = std::string(typeid(*mw_ptr).name()); 
            }
            name = base_name; 
        }
        if (name.empty()) { 
             name = "UnnamedControllerInstanceMiddleware_Use";
        }
        auto middleware_task = std::make_shared<MiddlewareTask<Session>>(std::move(mw_ptr), std::move(name));
        this->add_middleware(std::move(middleware_task)); // From IHandlerNode
        return *this;
    }

    /**
     * @brief Adds middleware to this controller by constructing an instance of `MiddlewareType` in-place.
     * @tparam MiddlewareType The concrete type of the middleware, must derive from `IMiddleware<SessionType>`.
     * @tparam Args Variadic arguments for the `MiddlewareType` constructor.
     * @param args Constructor arguments to be forwarded to `MiddlewareType`.
     * @return Reference to this `Controller` for chaining.
     */
    template<typename MiddlewareType, typename ...Args,
             typename = std::enable_if_t<std::is_base_of_v<IMiddleware<Session>, MiddlewareType>>>
    Controller<Session>& use(Args&&... args) {
        auto mw_instance = std::make_shared<MiddlewareType>(std::forward<Args>(args)...);
        return use(std::move(mw_instance), ""); // Delegate to shared_ptr overload for name derivation
    }

public:
    // --- Task Compilation --- 
    /**
     * @brief Compiles tasks for all routes defined within this controller.
     * This method first ensures `initialize_routes()` is called (once). It then calculates
     * the controller's full base path and combines inherited middleware with its own.
     * Finally, it iterates over all routes defined in `_controller_routes` and calls
     * `compile_tasks_and_register` on each, passing the combined context.
     * @param router_core Reference to the `RouterCore` for route registration.
     * @param current_built_path The full path from the router root to this controller's mount point.
     * @param inherited_tasks Middleware tasks inherited from parent groups or the main router.
     */
    void compile_tasks_and_register(
        RouterCore<Session>& router_core,
        const std::string& current_built_path, 
        const std::list<std::shared_ptr<IAsyncTask<Session>>>& inherited_tasks) override {
        
        // Ensure routes are defined by calling initialize_routes() once. 
        // This is a simple guard; a more robust one might use a std::once_flag or bool member.
        if (_controller_routes.empty()) { 
             initialize_routes();
        }

        std::string controller_base_path = this->build_full_path(current_built_path);
        std::list<std::shared_ptr<IAsyncTask<Session>>> tasks_for_controller_routes = this->combine_tasks(inherited_tasks);

        for (const auto& route_node : _controller_routes) {
            if (route_node) { // Ensure route_node is not null
                // route_node is a Route<SessionType> (or potentially another IHandlerNode if future allows)
                // Its path segment is relative to this controller.
                // It will use controller_base_path when it builds its own full path.
                route_node->compile_tasks_and_register(router_core, controller_base_path, tasks_for_controller_routes);
            }
        }
    }
};

} // namespace qb::http 
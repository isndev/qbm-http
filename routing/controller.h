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
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include "../types.h" // For qb::http::method
#include "./context.h"
#include "./coro_task.h" // Coroutine adapters + CoroRouteHandler / CoroMiddlewareHandler concepts
#include "./handler_node.h"
#include "./middleware.h"
#include "./route.h"
#include "./types.h" // For RouteHandlerFn, MiddlewareHandlerFn

#include <functional>
#include <memory>
#include <string>
#include <type_traits> // For std::enable_if_t, std::is_base_of_v
#include <typeinfo>
#include <vector>

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
    bool                                                _routes_initialized = false;

    // Helper methods for derived controllers to define routes
    // These can remain protected as they are implementation details for the public API below

    /**
     * @brief (Protected) Adds a route with a `RouteHandlerFn` (lambda/function) to this controller.
     * @param path Path relative to the controller's base path.
     * @param method The HTTP method for the route.
     * @param handler_fn The handler function.
     * @return Reference to this `Controller` for chaining.
     */
    Controller<Session> &
    add_controller_route(std::string path, qb::http::method method, RouteHandlerFn<Session> handler_fn) {
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
    Controller<Session> &
    add_controller_route(std::string path, qb::http::method method, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
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
    Controller<Session> &
    add_controller_custom_route(std::string path, qb::http::method method, Args &&...ctor_args) {
        static_assert(std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>, "CustomRouteType must derive from ICustomRoute<Session>");
        auto custom_route_obj = std::make_shared<CustomRouteType>(std::forward<Args>(ctor_args)...);
        auto route_node       = std::make_shared<Route<Session>>(std::move(path), method, custom_route_obj);
        route_node->set_parent(this->weak_from_this());
        _controller_routes.push_back(std::move(route_node));
        return *this;
    }

public:
    using SessionType = Session;
    using Context     = qb::http::Context<Session>;

    /**
     * @brief Default constructor.
     * Controllers are typically constructed with an empty base path segment (`""`).
     * Their actual mount path segment is set by the `Router` or `RouteGroup` via `set_base_path_segment()`.
     */
    Controller()
        : IHandlerNode<Session>("") {}

    /** @brief Virtual destructor. */
    virtual ~Controller() = default;

    /**
     * @brief Sets the base path segment for this controller instance.
     * This is usually called by the `Router` or `RouteGroup` when this controller is mounted,
     * establishing the controller's root path in the overall routing tree.
     * @param path_segment The path segment string (e.g., "/auth", "users").
     */
    void
    set_base_path_segment(std::string path_segment) noexcept {
        this->_path_segment = std::move(path_segment);
    }

    /**
     * @brief Gets a descriptive name for this controller node.
     * @return A string in the format "Controller: [base_path_segment]".
     */
    [[nodiscard]] std::string
    get_node_name() const override {
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
     *         get("/:id", this, &MyUserController::getUserById);
     *         post("/", this, &MyUserController::createUser);
     *         use(std::make_shared<MyUserAuthMiddleware>());
     *     }
     *     // ... handler methods ...
     * };
     * @endcode
     */
    virtual void initialize_routes() = 0;

    // --- Public Route Definition API for use within initialize_routes() ---
    //
    // Unified per-verb registration accepting a sync OR coroutine handler, or a member function:
    //   get("/:id", [](auto ctx) { ... });                                  // sync lambda
    //   get("/:id", [this](auto ctx) -> qb::io::async::task<void> { ... });  // coroutine lambda
    //   get("/:id", this, &MyController::get_user);                         // (sync or coro) member fn
    // One concept-gated overload (RouteHandlerLike) handles sync + coroutine (coroutine branch via
    // `if constexpr (CoroRouteHandler<...>)`). This is the single modern route-registration API.
#define QB_HTTP_CTRL_VERB(NAME, METHOD)                                                                  \
    template <typename H>                                                                                \
        requires RouteHandlerLike<std::remove_cvref_t<H>, Session>                                       \
    Controller<Session> &NAME(std::string path, H &&handler) {                                            \
        if constexpr (CoroRouteHandler<std::remove_cvref_t<H>, Session>) {                               \
            return add_controller_route(std::move(path), qb::http::method::METHOD,                        \
                                        detail::wrap_coro_route_handler<Session>(std::forward<H>(handler))); \
        } else {                                                                                          \
            return add_controller_route(std::move(path), qb::http::method::METHOD,                        \
                                        RouteHandlerFn<Session>(std::forward<H>(handler)));               \
        }                                                                                                 \
    }                                                                                                     \
    template <typename Obj, typename M>                                                                   \
        requires std::is_member_function_pointer_v<M>                                                     \
    Controller<Session> &NAME(std::string path, Obj *obj, M member) {                                     \
        return NAME(std::move(path), [obj, member](std::shared_ptr<qb::http::Context<Session>> ctx) {     \
            return (obj->*member)(std::move(ctx));                                                         \
        });                                                                                               \
    }
    QB_HTTP_CTRL_VERB(get, GET)
    QB_HTTP_CTRL_VERB(post, POST)
    QB_HTTP_CTRL_VERB(put, PUT)
    QB_HTTP_CTRL_VERB(del, DEL)
    QB_HTTP_CTRL_VERB(patch, PATCH)
    QB_HTTP_CTRL_VERB(options, OPTIONS)
    QB_HTTP_CTRL_VERB(head, HEAD)
#undef QB_HTTP_CTRL_VERB

    /** @brief Adds **coroutine** middleware to this controller (auto-wrapped). */
    template <typename H>
        requires CoroMiddlewareHandler<std::remove_cvref_t<H>, Session>
    Controller<Session> &
    use(H &&handler, std::string name = "UnnamedCoroMiddleware") {
        return use(detail::wrap_coro_middleware_handler<Session>(std::forward<H>(handler)), std::move(name));
    }

    // --- Typed ICustomRoute routes (constructs CustomRouteType in-place) ---
    /** @brief Defines a GET route with a typed `ICustomRoute` handler. @see add_controller_custom_route */
    template <typename CustomRouteType, typename... Args,
              typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session> &
    get(std::string path, Args &&...ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::GET, std::forward<Args>(ctor_args)...);
    }

    /** @brief Defines a POST route with a typed `ICustomRoute` handler. @see add_controller_custom_route */
    template <typename CustomRouteType, typename... Args,
              typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session> &
    post(std::string path, Args &&...ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::POST, std::forward<Args>(ctor_args)...);
    }

    // ... (similar overloads for PUT, DELETE, PATCH, OPTIONS, HEAD with CustomRouteType) ...
    template <typename CustomRouteType, typename... Args,
              typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session> &
    put(std::string path, Args &&...ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::PUT, std::forward<Args>(ctor_args)...);
    }

    template <typename CustomRouteType, typename... Args,
              typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session> &
    del(std::string path, Args &&...ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::DEL, std::forward<Args>(ctor_args)...);
    }

    template <typename CustomRouteType, typename... Args,
              typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session> &
    patch(std::string path, Args &&...ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::PATCH, std::forward<Args>(ctor_args)...);
    }

    template <typename CustomRouteType, typename... Args,
              typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session> &
    options(std::string path, Args &&...ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::OPTIONS, std::forward<Args>(ctor_args)...);
    }

    template <typename CustomRouteType, typename... Args,
              typename = std::enable_if_t<std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>>>
    Controller<Session> &
    head(std::string path, Args &&...ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::HEAD, std::forward<Args>(ctor_args)...);
    }

    // --- std::shared_ptr<ICustomRoute<Session>> routes ---
    /** @brief Defines a GET route with a pre-created `ICustomRoute` handler. @see add_controller_route */
    Controller<Session> &
    get(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::GET, std::move(custom_route_ptr));
    }

    /** @brief Defines a POST route with a pre-created `ICustomRoute` handler. @see add_controller_route */
    Controller<Session> &
    post(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::POST, std::move(custom_route_ptr));
    }

    // ... (similar overloads for PUT, DELETE, PATCH, OPTIONS, HEAD with shared_ptr<ICustomRoute>) ...
    Controller<Session> &
    put(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::PUT, std::move(custom_route_ptr));
    }

    Controller<Session> &
    del(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::DEL, std::move(custom_route_ptr));
    }

    Controller<Session> &
    patch(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::PATCH, std::move(custom_route_ptr));
    }

    Controller<Session> &
    options(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::OPTIONS, std::move(custom_route_ptr));
    }

    Controller<Session> &
    head(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::HEAD, std::move(custom_route_ptr));
    }

public:
    // --- Middleware for this controller ---

    /**
     * @brief Adds middleware to this controller using a `MiddlewareHandlerFn` (lambda/function pointer).
     * The middleware will apply to all routes defined within this controller.
     * @param mw_fn The middleware handler function.
     * @param name An optional name for this middleware instance, useful for logging or debugging.
     * @return Reference to this `Controller` for chaining.
     */
    template <typename H>
        requires SyncMiddleware<std::remove_cvref_t<H>, Session>
    Controller<Session> &
    use(H &&mw_fn, std::string name = "UnnamedFunctionalMiddleware") {
        auto functional_middleware =
            std::make_shared<FunctionalMiddleware<Session>>(MiddlewareHandlerFn<Session>(std::forward<H>(mw_fn)), name);
        auto middleware_task = std::make_shared<MiddlewareTask<Session>>(std::move(functional_middleware), std::move(name));
        this->add_middleware(std::move(middleware_task)); // From IHandlerNode
        return *this;
    }

    /**
     * @brief Adds middleware to this controller using a pre-created `std::shared_ptr<IMiddleware<Session>>`.
     * @param mw_ptr Shared pointer to the middleware instance.
     * @param name_override Optional: A specific name for this middleware task. If empty, derives name from `mw_ptr`.
     * @return Reference to this `Controller` for chaining.
     */
    Controller<Session> &
    use(std::shared_ptr<IMiddleware<Session>> mw_ptr, std::string name_override = "") {
        if (!mw_ptr)
            return *this;
        std::string name = name_override;
        if (name.empty()) {
            std::string base_name = mw_ptr->name();
            if (base_name.empty()) {
                base_name = std::string(typeid(*mw_ptr).name());
            }
            name = base_name;
        }
        if (name.empty()) {
            name = "UnnamedSharedPtrMiddleware";
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
    template <typename MiddlewareType, typename... Args, typename = std::enable_if_t<std::is_base_of_v<IMiddleware<Session>, MiddlewareType>>>
    Controller<Session> &
    use(Args &&...args) {
        auto mw_instance = std::make_shared<MiddlewareType>(std::forward<Args>(args)...);
        return use(std::move(mw_instance), ""); // Delegate to shared_ptr overload for name derivation
    }

private:
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
    void
    compile_tasks_and_register(RouterCore<Session> &router_core, const std::string &current_built_path,
                               const std::vector<std::shared_ptr<IAsyncTask<Session>>> &inherited_tasks) override {
        // Contract: routes/middleware are declared exclusively inside the overridden
        // initialize_routes(), which the router invokes exactly once at compile time.
        // (Do NOT add routes in the controller constructor — they would combine
        // unpredictably with initialize_routes(); the previous "_controller_routes.empty()"
        // guard silently DROPPED initialize_routes() routes whenever the ctor added any.)
        if (!_routes_initialized) {
            initialize_routes();
            _routes_initialized = true;
        }

        std::string                                       controller_base_path        = this->build_full_path(current_built_path);
        std::vector<std::shared_ptr<IAsyncTask<Session>>> tasks_for_controller_routes = this->combine_tasks(inherited_tasks);

        for (const auto &route_node : _controller_routes) {
            if (route_node) {
                // Ensure route_node is not null
                // route_node is a Route<SessionType> (or potentially another IHandlerNode if future allows)
                // Its path segment is relative to this controller.
                // It will use controller_base_path when it builds its own full path.
                route_node->compile_tasks_and_register(router_core, controller_base_path, tasks_for_controller_routes);
            }
        }
    }
};
} // namespace qb::http

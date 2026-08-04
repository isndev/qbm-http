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
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include <functional>  // For std::function (used in RouteHandlerFn, MiddlewareHandlerFn)
#include <memory>      // For std::shared_ptr, std::make_shared, std::weak_ptr
#include <string>      // For std::string
#include <type_traits> // For std::enable_if_t, std::is_base_of_v
#include <utility>     // For std::forward, std::move
#include <vector>      // For std::vector (used by some underlying components)

#include "../request.h"    // For qb::http::Request
#include "../types.h"      // For qb::http::method enum
#include "./controller.h"  // For Controller class
#include "./coro_task.h"   // Routing concepts (RouteHandlerLike / CoroRouteHandler / SyncMiddleware) + coro adapters
#include "./middleware.h"  // For IMiddleware interface
#include "./route.h"       // For Route class (used indirectly via RouteGroup)
#include "./route_group.h" // For RouteGroup functionality
#include "./router_core.h" // Internal routing engine
#include "./types.h"       // For RouteHandlerFn, MiddlewareHandlerFn, etc.

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
template <typename SessionType>
class Router {
private:
    std::shared_ptr<RouterCore<SessionType>> _router_core;
    ///< The core routing engine responsible for matching and execution.
    std::shared_ptr<RouteGroup<SessionType>> _root_group;
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
    Router<SessionType> &add_route(std::string path, qb::http::method method, RouteHandlerFn<SessionType> handler_fn);

    // Per-verb route registration (get/post/put/del/patch/options/head) is provided by the unified,
    // concept-gated overloads in the QB_HTTP_ROUTER_VERB macro block below: one template accepts a
    // synchronous OR coroutine handler (RouteHandlerLike) and a second binds a member function. The
    // separate `RouteHandlerFn` (std::function) verb overloads were removed — the macro overload
    // subsumes them (a sync lambda / function pointer / std::function all satisfy RouteHandlerLike).

    // --- Overloads for ICustomRoute shared_ptr at root level ---
    /** @brief Adds a GET route with an `ICustomRoute` handler directly to the router. @see RouteGroup::get */
    Router<SessionType> &get(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route);

    /** @brief Adds a POST route with an `ICustomRoute` handler directly to the router. @see RouteGroup::post */
    Router<SessionType> &post(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route);

    /** @brief Adds a PUT route with an `ICustomRoute` handler directly to the router. @see RouteGroup::put */
    Router<SessionType> &put(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route);

    /** @brief Adds a DELETE route with an `ICustomRoute` handler directly to the router. @see RouteGroup::del */
    Router<SessionType> &del(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route);

    /** @brief Adds a PATCH route with an `ICustomRoute` handler directly to the router. @see RouteGroup::patch */
    Router<SessionType> &patch(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route);

    /** @brief Adds an OPTIONS route with an `ICustomRoute` handler directly to the router. @see RouteGroup::options */
    Router<SessionType> &options(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route);

    /** @brief Adds a HEAD route with an `ICustomRoute` handler directly to the router. @see RouteGroup::head */
    Router<SessionType> &head(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route);

    // --- Unified per-verb route API (sync OR coroutine handler, or a member function) ----------
    //   router.get("/x", [](auto ctx) { ... });                                  // sync lambda
    //   router.get("/x", [](auto ctx) -> qb::io::async::task<void> { ... });     // coroutine lambda
    //   router.get("/x", this, &MyActor::handle_x);                              // (sync or coro) member fn
    // One concept-gated overload (RouteHandlerLike) accepts both flavours; the coroutine branch is
    // selected via `if constexpr (CoroRouteHandler<...>)`. No wrappers, no repeated session type.
#define QB_HTTP_ROUTER_VERB(NAME, METHOD)                                                                                           \
    template <typename H>                                                                                                           \
    requires RouteHandlerLike<std::remove_cvref_t<H>, SessionType>                                                                  \
    Router<SessionType> &NAME(std::string path, H &&handler) {                                                                      \
        if constexpr (CoroRouteHandler<std::remove_cvref_t<H>, SessionType>) {                                                      \
            return add_route(std::move(path), qb::http::method::METHOD,                                                             \
                             detail::wrap_coro_route_handler<SessionType>(std::forward<H>(handler)));                               \
        } else {                                                                                                                    \
            return add_route(std::move(path), qb::http::method::METHOD, RouteHandlerFn<SessionType>(std::forward<H>(handler)));     \
        }                                                                                                                           \
    }                                                                                                                               \
    template <typename Obj, typename M>                                                                                             \
    requires std::is_member_function_pointer_v<M>                                                                                   \
    Router<SessionType> &NAME(std::string path, Obj *obj, M member) {                                                               \
        return NAME(std::move(path),                                                                                                \
                    [obj, member](std::shared_ptr<qb::http::Context<SessionType>> ctx) { return (obj->*member)(std::move(ctx)); }); \
    }
    QB_HTTP_ROUTER_VERB(get, GET)
    QB_HTTP_ROUTER_VERB(post, POST)
    QB_HTTP_ROUTER_VERB(put, PUT)
    QB_HTTP_ROUTER_VERB(del, DEL)
    QB_HTTP_ROUTER_VERB(patch, PATCH)
    QB_HTTP_ROUTER_VERB(options, OPTIONS)
    QB_HTTP_ROUTER_VERB(head, HEAD)
#undef QB_HTTP_ROUTER_VERB

    /**
     * @brief Adds global **coroutine** middleware (pass the `task<void>(ctx)` lambda directly).
     *
     * Concept-gated on `CoroMiddlewareHandler`; the handler is wrapped into a synchronous
     * middleware via `detail::wrap_coro_middleware_handler` and then forwarded to the
     * `SyncMiddleware` `use()` overload, so it applies to all routes handled by this router.
     * @param handler The coroutine middleware handler (`qb::io::async::task<void>(ctx)`).
     * @param name An optional name for this middleware instance. Defaults to "UnnamedCoroMiddleware".
     * @return Reference to this `Router` for chaining.
     */
    template <typename H>
    requires CoroMiddlewareHandler<std::remove_cvref_t<H>, SessionType>
    Router<SessionType> &
    use(H &&handler, std::string name = "UnnamedCoroMiddleware") {
        return use(detail::wrap_coro_middleware_handler<SessionType>(std::forward<H>(handler)), std::move(name));
    }

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
    template <typename CustomRouteType, typename... Args>
    requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
    Router<SessionType> &add_custom_route(std::string path, qb::http::method method, Args &&...ctor_args);

    /** @brief Adds a GET route with a typed `ICustomRoute` handler directly to the router. @see add_custom_route */
    template <typename CustomRouteType, typename... Args>
    requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
    Router<SessionType> &get(std::string path, Args &&...ctor_args);

    /** @brief Adds a POST route with a typed `ICustomRoute` handler directly to the router. @see add_custom_route */
    template <typename CustomRouteType, typename... Args>
    requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
    Router<SessionType> &post(std::string path, Args &&...ctor_args);

    // ... Other HTTP methods for typed custom routes ...
    template <typename CustomRouteType, typename... Args>
    requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
    Router<SessionType> &put(std::string path, Args &&...ctor_args);

    template <typename CustomRouteType, typename... Args>
    requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
    Router<SessionType> &del(std::string path, Args &&...ctor_args);

    template <typename CustomRouteType, typename... Args>
    requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
    Router<SessionType> &patch(std::string path, Args &&...ctor_args);

    template <typename CustomRouteType, typename... Args>
    requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
    Router<SessionType> &options(std::string path, Args &&...ctor_args);

    template <typename CustomRouteType, typename... Args>
    requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
    Router<SessionType> &head(std::string path, Args &&...ctor_args);

    /**
     * @brief Creates a new top-level `RouteGroup` under this router.
     * @param path_prefix The prefix for all routes within this group (e.g., "/api").
     * @return A `std::shared_ptr` to the created `RouteGroup` for further configuration.
     */
    [[nodiscard]] std::shared_ptr<RouteGroup<SessionType>> group(std::string path_prefix);

    /**
     * @brief Mounts a `Controller` directly under this router with a given path prefix.
     * @tparam C The controller class type. Must be derived from `Controller<SessionType>`.
     * @tparam Args Variadic arguments for the controller's constructor.
     * @param path_prefix The base path for this controller (e.g., "/users").
     * @param args Constructor arguments to be forwarded to the controller `C`.
     * @return A `std::shared_ptr<C>` to the created and mounted controller instance.
     */
    template <typename C, typename... Args>
    requires DerivedFrom<C, Controller<SessionType>>
    [[nodiscard]] std::shared_ptr<C> controller(std::string path_prefix, Args &&...args);

    // --- Middleware methods (apply to the root group, effectively global) ---
    /**
     * @brief Adds global **synchronous** middleware (lambda / function pointer / `MiddlewareHandlerFn`).
     * Concept-gated on `SyncMiddleware` (callable with `(ctx, next)`), symmetric with the coroutine
     * `use()` overload above. Applies to all routes handled by this router.
     * @param mw_fn The middleware handler (`void(ctx, next)`).
     * @param name An optional name for this middleware instance. Defaults to "UnnamedGlobalFunctionalMiddleware".
     * @return Reference to this `Router` for chaining.
     */
    template <typename H>
    requires SyncMiddleware<std::remove_cvref_t<H>, SessionType>
    Router<SessionType> &
    use(H &&mw_fn, std::string name = "UnnamedGlobalFunctionalMiddleware") {
        if (_root_group) {
            _root_group->use(std::forward<H>(mw_fn), std::move(name));
        }
        _is_compiled = false;
        return *this;
    }

    /**
     * @brief Adds global middleware using a shared pointer to an `IMiddleware` object.
     * @param mw_ptr A `std::shared_ptr<IMiddleware<SessionType>>` instance.
     * @param name_override Optional: A name to use for this middleware task. If empty, derives from `mw_ptr`.
     * @return Reference to this `Router` for chaining.
     */
    Router<SessionType> &use(std::shared_ptr<IMiddleware<SessionType>> mw_ptr, std::string name_override = "");

    /**
     * @brief Adds global middleware by constructing an instance of `MiddlewareType` in-place.
     * @tparam MiddlewareType The concrete type of the middleware, must derive from `IMiddleware<SessionType>`.
     * @tparam Args Variadic arguments for the `MiddlewareType` constructor.
     * @param args Constructor arguments to be forwarded to `MiddlewareType`.
     * @return Reference to this `Router` for chaining.
     */
    template <typename MiddlewareType, typename... Args>
    requires DerivedFrom<MiddlewareType, IMiddleware<SessionType>>
    Router<SessionType> &use(Args &&...args);

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
    void set_error_task_chain(std::vector<std::shared_ptr<IAsyncTask<SessionType>>> error_chain);

    /**
     * @brief Registers a router-level lifecycle hook copied into every
     *        newly-created request context before PRE_ROUTING fires.
     *
     * Context-local hooks can only be added once middleware or handlers are
     * already running; this API is the intended place for cross-cutting
     * hooks that need to observe PRE_ROUTING.
     */
    Router<SessionType> &add_lifecycle_hook(typename Context<SessionType>::LifecycleHook hook_fn);

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
    std::shared_ptr<Context<SessionType>> route(std::shared_ptr<SessionType> session, qb::http::Request request);

    /**
     * @brief (Advanced) Gets a weak pointer to the internal `RouterCore` instance.
     * This is typically used by components that need to interact deeply with the routing engine,
     * such as the `Context` for accessing error handlers.
     * @return A `std::weak_ptr<RouterCore<SessionType>>`.
     */
    [[nodiscard]] std::weak_ptr<RouterCore<SessionType>> get_router_core_weak_ptr() noexcept;

    /**
     * @brief Clears all defined routes, groups, controllers, middleware, and custom handlers.
     * Resets the router to its initial state. After clearing, `compile()` must be called again
     * if new routes are defined before the router can process requests.
     */
    void clear(); // not noexcept: re-creates the root group / default handlers (allocates)
};
} // namespace qb::http

// ---------------------------------------------------------------------------
// Template definitions for qb::http::Router, merged here from the retired
// routing/router.tpp (3.0). Everything below stands exactly where the
// `#include "./router.tpp"` that used to occupy this line spliced it, so the
// preprocessed token stream of this header is byte-identical to 2.6 -- which is
// how the merge was verified, rather than by re-reading the bodies.
//
// The five includes below are therefore left here rather than hoisted into the
// block at the top of the file. Hoisting them does compile (measured: only
// ./context.h is new, and context.h does not include router.h, so there is no
// cycle) -- it was not done because it would forfeit that byte-identical proof
// for no functional gain. See dev/analysis/TEMPLATE-LINKAGE-AUDIT-3.0.md.
// ---------------------------------------------------------------------------

#include "./context.h"     // Required for Context definition
#include "./controller.h"  // Required for Controller definition
#include "./route_group.h" // Required for RouteGroup definition
#include "./router_core.h" // Required for RouterCore definition
#include "./types.h"       // For RouteHandlerFn, MiddlewareHandlerFn etc.

// Note: Other necessary headers like <memory>, <string>, <functional>
// are expected to be included in the block at the top of this file.

namespace qb::http {
template <typename SessionType>
Router<SessionType>::Router()
    : _router_core(std::make_shared<RouterCore<SessionType>>([](Context<SessionType> &ctx) {
        // This callback is invoked by RouterCore when a Context is finalized.
        // It's responsible for sending the response via the session associated with the context.
        if (auto session_ptr = ctx.session()) {
            // Ensure session is still valid
            ctx.execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND); // Allow final header mods
            if constexpr (requires(SessionType &session, Context<SessionType> &context) { session.send_response(context); }) {
                session_ptr->send_response(ctx);
            } else {
                (*session_ptr) << ctx.response();
            }
            // POST_RESPONSE_SEND hook would typically be called after this, by the session or IO layer upon write completion.
        } else {
            // Log warning if session is null: session might have disconnected before response could be sent.
            // This would typically be handled by a proper logging framework.
        }
    }))
    , _root_group(std::make_shared<RouteGroup<SessionType>>(""))
    , // Root group has an empty path prefix
    _is_compiled(false) {
    if (_router_core) {
        _router_core->add_handler_node(_root_group); // Add the root group to the core
    }
}

template <typename SessionType>
Router<SessionType>::~Router() = default; // Default destructor is sufficient

// --- Route Definition API (delegates to _root_group) ---

template <typename SessionType>
Router<SessionType> &
Router<SessionType>::add_route(std::string path, qb::http::method method, RouteHandlerFn<SessionType> handler_fn) {
    if (_root_group) {
        _root_group->add_route(std::move(path), method, std::move(handler_fn));
    }
    _is_compiled = false;
    return *this;
}

// NOTE: the synchronous per-verb methods (get/post/put/del/patch/options/head taking a
// RouteHandlerFn) were removed — they are now subsumed by the unified, concept-gated verb
// overloads defined inline in router.h (QB_HTTP_ROUTER_VERB), which accept any sync OR coroutine
// handler. `add_route()` above remains the shared primitive they all funnel through.

// --- Overloads for ICustomRoute shared_ptr at root level ---
template <typename SessionType>
Router<SessionType> &
Router<SessionType>::get(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->get(std::move(path), std::move(custom_route));
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType> &
Router<SessionType>::post(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->post(std::move(path), std::move(custom_route));
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType> &
Router<SessionType>::put(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->put(std::move(path), std::move(custom_route));
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType> &
Router<SessionType>::del(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->del(std::move(path), std::move(custom_route));
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType> &
Router<SessionType>::patch(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->patch(std::move(path), std::move(custom_route));
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType> &
Router<SessionType>::options(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->options(std::move(path), std::move(custom_route));
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType> &
Router<SessionType>::head(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->head(std::move(path), std::move(custom_route));
    }
    _is_compiled = false;
    return *this;
}

// --- Typed ICustomRoute support at root level ---
template <typename SessionType>
template <typename CustomRouteType, typename... Args>
requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
Router<SessionType> &
Router<SessionType>::add_custom_route(std::string path, qb::http::method method, Args &&...ctor_args) {
    if (_root_group) {
        _root_group->template add_custom_route<CustomRouteType>(std::move(path), method, std::forward<Args>(ctor_args)...);
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args>
requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
Router<SessionType> &
Router<SessionType>::get(std::string path, Args &&...ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::GET, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args>
requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
Router<SessionType> &
Router<SessionType>::post(std::string path, Args &&...ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::POST, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args>
requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
Router<SessionType> &
Router<SessionType>::put(std::string path, Args &&...ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::PUT, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args>
requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
Router<SessionType> &
Router<SessionType>::del(std::string path, Args &&...ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::DEL, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args>
requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
Router<SessionType> &
Router<SessionType>::patch(std::string path, Args &&...ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::PATCH, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args>
requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
Router<SessionType> &
Router<SessionType>::options(std::string path, Args &&...ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::OPTIONS, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args>
requires DerivedFrom<CustomRouteType, ICustomRoute<SessionType>>
Router<SessionType> &
Router<SessionType>::head(std::string path, Args &&...ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HEAD, std::forward<Args>(ctor_args)...);
}

// --- Group and Controller mounting ---
template <typename SessionType>
std::shared_ptr<RouteGroup<SessionType>>
Router<SessionType>::group(std::string path_prefix) {
    _is_compiled = false;
    return _root_group ? _root_group->group(std::move(path_prefix)) : nullptr;
}

template <typename SessionType>
template <typename C, typename... Args>
requires DerivedFrom<C, Controller<SessionType>>
std::shared_ptr<C>
Router<SessionType>::controller(std::string path_prefix, Args &&...args) {
    _is_compiled = false;
    return _root_group ? _root_group->template controller<C>(std::move(path_prefix), std::forward<Args>(args)...) : nullptr;
}

// --- Middleware methods (apply to _root_group) ---
// NOTE: the synchronous `use(MiddlewareHandlerFn, name)` overload is now an inline, concept-gated
// (`SyncMiddleware`) template in router.h. The shared_ptr<IMiddleware> overload remains here.
template <typename SessionType>
Router<SessionType> &
Router<SessionType>::use(std::shared_ptr<IMiddleware<SessionType>> mw_ptr, std::string name_override) {
    if (_root_group) {
        _root_group->use(std::move(mw_ptr), std::move(name_override));
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
template <typename MiddlewareType, typename... Args>
requires DerivedFrom<MiddlewareType, IMiddleware<SessionType>>
Router<SessionType> &
Router<SessionType>::use(Args &&...args) {
    if (_root_group) {
        _root_group->template use<MiddlewareType>(std::forward<Args>(args)...);
    }
    _is_compiled = false;
    return *this;
}

// --- Special Handlers (delegate to RouterCore) ---
template <typename SessionType>
void
Router<SessionType>::set_not_found_handler(RouteHandlerFn<SessionType> handler_fn) {
    if (_router_core) {
        _router_core->set_not_found_handler(std::move(handler_fn));
    }
}

template <typename SessionType>
void
Router<SessionType>::set_error_task_chain(std::vector<std::shared_ptr<IAsyncTask<SessionType>>> error_chain) {
    if (_router_core) {
        _router_core->set_error_task_chain(std::move(error_chain));
    }
}

template <typename SessionType>
Router<SessionType> &
Router<SessionType>::add_lifecycle_hook(typename Context<SessionType>::LifecycleHook hook_fn) {
    if (_router_core) {
        _router_core->add_lifecycle_hook(std::move(hook_fn));
    }
    return *this;
}

// --- Compilation and Routing ---
template <typename SessionType>
void
Router<SessionType>::compile() {
    if (_router_core) {
        _router_core->compile_all_routes();
    }
    _is_compiled = true;
}

template <typename SessionType>
std::shared_ptr<Context<SessionType>>
Router<SessionType>::route(std::shared_ptr<SessionType> session, qb::http::Request request) {
    if (!_is_compiled && _router_core) {
        // Auto-compile if not already compiled
        compile();
    }
    if (_router_core) {
        return _router_core->route_request(std::move(session), std::move(request));
    }
    // Should not happen if constructor succeeded, but return nullptr as a fallback.
    // Or, throw an exception indicating router is not properly initialized.
    // For now, returning nullptr if _router_core is somehow null.
    return nullptr;
}

// --- Other Methods ---
template <typename SessionType>
std::weak_ptr<RouterCore<SessionType>>
Router<SessionType>::get_router_core_weak_ptr() noexcept {
    return _router_core; // std::shared_ptr can implicitly convert to std::weak_ptr
}

template <typename SessionType>
void
Router<SessionType>::clear() {
    if (_router_core) {
        _router_core->clear();
    }
    // Re-initialize the root group for this router instance and add it to the core again.
    _root_group = std::make_shared<RouteGroup<SessionType>>("");
    if (_router_core) {
        _router_core->add_handler_node(_root_group);
    }
    _is_compiled = false;
}
} // namespace qb::http

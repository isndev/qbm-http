/**
 * @file qbm/http/routing/route.h
 * @brief Defines the Route class and task adapters for specific HTTP endpoints.
 *
 * This file contains the `Route` class, which represents a terminal node in the routing
 * tree, corresponding to a specific URI path and HTTP method. It also defines adapter
 * classes (`RouteLambdaTask`, `CustomRouteAdapterTask`) that wrap user-provided route
 * handlers (lambdas or `ICustomRoute` objects) to make them conform to the `IAsyncTask` interface
 * for execution within the request processing chain.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include "./handler_node.h"
#include "./async_task.h"
#include "./types.h" // Contains the corrected RouteHandlerFn using std::shared_ptr<Context<SessionType>>
#include "../types.h" // For qb::http::method
#include "./custom_route.h" // For ICustomRoute

#include <string>
#include <functional>
#include <memory>
#include <list>
#include <variant> // For std::variant
#include <stdexcept> // For std::invalid_argument
#include <iostream>  // For std::cerr in case of exceptions

namespace qb::http {

// Forward declaration
template <typename Session>
class RouterCore;

// RouteHandlerFn is now taken from ./types.h and should be the std::shared_ptr version
// template <typename SessionType>
// using RouteHandlerFn = std::function<void(std::shared_ptr<Context<SessionType>> ctx)>; // This line can be removed if types.h is correct

/**
 * @brief Adapts a lambda-based route handler (`RouteHandlerFn`) to the `IAsyncTask` interface.
 *
 * This task wrapper takes a `RouteHandlerFn` (typically a lambda) and executes it when its
 * `execute` method is called. It handles exceptions thrown by the lambda and ensures the
 * context is appropriately completed with an error status if necessary.
 *
 * @tparam SessionType The session type used by the `Context`.
 */
template <typename SessionType>
class RouteLambdaTask : public IAsyncTask<SessionType> {
private:
    RouteHandlerFn<SessionType> _handler_fn; ///< The stored lambda or function pointer.
    std::string _name;                       ///< A descriptive name for this task instance.

public:
    /**
     * @brief Constructs a `RouteLambdaTask`.
     * @param handler_fn The lambda or function conforming to `RouteHandlerFn` to be executed.
     * @param name A name for this task, primarily for logging/debugging. Defaults to "RouteLambdaHandler".
     * @throws std::invalid_argument if `handler_fn` is null.
     */
    explicit RouteLambdaTask(RouteHandlerFn<SessionType> handler_fn, std::string name = "RouteLambdaHandler")
        : _handler_fn(std::move(handler_fn)), _name(std::move(name)) {
        if (!_handler_fn) {
            throw std::invalid_argument("RouteLambdaTask: handler_fn cannot be null.");
        }
    }

    /**
     * @brief Executes the stored route handler lambda.
     * The lambda is responsible for calling `ctx->complete()`.
     * If the lambda throws, this method catches the exception, sets a 500 error on the response,
     * and calls `ctx->complete(AsyncTaskResult::ERROR)`.
     * @param ctx The shared context for the HTTP request.
     */
    void execute(std::shared_ptr<Context<SessionType>> ctx) override {
        try {
            _handler_fn(ctx);
        } catch (const std::exception& /*e*/) {
            // Log e.what() if logging is available
            if (ctx && !ctx->is_completed() && !ctx->is_cancelled()) {
                 ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                 ctx->response().body() = "Internal server error in route handler.";
                 ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                 ctx->complete(AsyncTaskResult::ERROR);
            }
        } catch (...) {
             if (ctx && !ctx->is_completed() && !ctx->is_cancelled()) {
                 ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                 ctx->response().body() = "Unknown internal server error in route handler.";
                 ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                 ctx->complete(AsyncTaskResult::ERROR);
            }
        }
    }

    /** @brief Cancellation handler for lambda tasks; typically a no-op as lambdas are often synchronous or manage their own async ops. */
    void cancel() noexcept override { /* No-op by default for simple lambda handlers */ }

    /** @brief Gets the name of this task instance. */
    [[nodiscard]] std::string name() const noexcept override {
        return _name;
    }
};

/**
 * @brief Adapts an `ICustomRoute` object to the `IAsyncTask` interface.
 *
 * This task wrapper takes a shared pointer to an `ICustomRoute` implementation.
 * When `execute` is called, it delegates to the `ICustomRoute::process` method.
 * It also delegates cancellation and naming to the underlying `ICustomRoute` object.
 *
 * @tparam SessionType The session type used by the `Context` and `ICustomRoute`.
 */
template <typename SessionType>
class CustomRouteAdapterTask : public IAsyncTask<SessionType> {
private:
    std::shared_ptr<ICustomRoute<SessionType>> _custom_route; ///< The stored custom route handler object.

public:
    /**
     * @brief Constructs a `CustomRouteAdapterTask`.
     * @param custom_route A `std::shared_ptr` to an object implementing `ICustomRoute<SessionType>`.
     * @throws std::invalid_argument if `custom_route` is null.
     */
    explicit CustomRouteAdapterTask(std::shared_ptr<ICustomRoute<SessionType>> custom_route)
        : _custom_route(std::move(custom_route)) {
        if (!_custom_route) {
            throw std::invalid_argument("CustomRouteAdapterTask: custom_route pointer cannot be null.");
        }
    }

    /**
     * @brief Executes the `process` method of the stored `ICustomRoute` object.
     * The custom route handler is responsible for calling `ctx->complete()`.
     * If `process()` throws, this method catches the exception, sets a 500 error on the response,
     * and calls `ctx->complete(AsyncTaskResult::ERROR)`.
     * @param ctx The shared context for the HTTP request.
     */
    void execute(std::shared_ptr<Context<SessionType>> ctx) override {
        try {
            _custom_route->process(ctx);
        } catch (const std::exception& /*e*/) {
            // Log e.what() if logging is available
            if (ctx && !ctx->is_completed() && !ctx->is_cancelled()) {
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->response().body() = "Internal server error in custom route handler.";
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                ctx->complete(AsyncTaskResult::ERROR);
            }
        } catch (...) {
             if (ctx && !ctx->is_completed() && !ctx->is_cancelled()) {
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->response().body() = "Unknown internal server error in custom route handler.";
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                ctx->complete(AsyncTaskResult::ERROR);
            }
        }
    }

    /** 
     * @brief Delegates cancellation to the `cancel` method of the underlying `ICustomRoute` object.
     * Catches any exceptions thrown by the custom route's cancel method.
     */
    void cancel() noexcept override {
        if (_custom_route) {
            try {
                _custom_route->cancel(); 
            } catch (...) { /* Suppress exceptions from custom route's cancel */ }
        }
    }

    /** 
     * @brief Gets the name of this task by delegating to the `name` method of the underlying `ICustomRoute` object.
     * Returns "InvalidCustomRouteAdapter" if the custom route pointer is null (should not happen due to constructor check).
     */
    [[nodiscard]] std::string name() const noexcept override {
        return _custom_route ? _custom_route->name() : "InvalidCustomRouteAdapter";
    }
};

/**
 * @brief Represents a specific routable endpoint (a leaf node in the routing tree).
 *
 * A `Route` object maps a specific HTTP method and a path segment (relative to its parent node)
 * to a handler. The handler can be either a `RouteHandlerFn` (lambda or function pointer)
 * or an `ICustomRoute` object for more complex logic.
 * It inherits from `IHandlerNode` to participate in the routing hierarchy and task compilation.
 *
 * @tparam SessionType The session type used by the `Context` and `IAsyncTask` system.
 */
template <typename SessionType>
class Route : public IHandlerNode<SessionType> {
private:
    qb::http::method _http_method; ///< The HTTP method this route responds to.
    
    /** @brief `std::variant` to store either a lambda handler or a shared_ptr to an ICustomRoute object. */
    using RouteLogicVariant = std::variant<
        RouteHandlerFn<SessionType>,
        std::shared_ptr<ICustomRoute<SessionType>>
    >;
    RouteLogicVariant _route_logic; ///< Holds the actual handler logic.
    std::string _route_name_for_log; ///< A descriptive name for this route, used for logging/debugging.

public:
    /**
     * @brief Constructs a `Route` with a lambda-based handler (`RouteHandlerFn`).
     * @param path_segment The path segment for this route (relative to its parent).
     * @param http_method The HTTP method this route matches.
     * @param handler_fn The `RouteHandlerFn` (e.g., a lambda) that will process requests for this route.
     * @throws std::invalid_argument if `handler_fn` is null.
     */
    Route(std::string path_segment, qb::http::method http_method, RouteHandlerFn<SessionType> handler_fn)
        : IHandlerNode<SessionType>(std::move(path_segment))
        , _http_method(http_method)
        , _route_logic(std::move(handler_fn)) {
        if (!std::get<RouteHandlerFn<SessionType>>(_route_logic)) {
            throw std::invalid_argument("Route constructor: handler_fn cannot be null.");
        }
        // Generate a default name for logging if ICustomRoute isn't providing one.
        _route_name_for_log = "Lambda@" + this->get_path_segment();
    }

    /**
     * @brief Constructs a `Route` with a class-based handler (`ICustomRoute`).
     * @param path_segment The path segment for this route.
     * @param http_method The HTTP method this route matches.
     * @param custom_route_ptr A `std::shared_ptr` to an object implementing `ICustomRoute<SessionType>`.
     * @throws std::invalid_argument if `custom_route_ptr` is null.
     */
    Route(std::string path_segment, qb::http::method http_method, std::shared_ptr<ICustomRoute<SessionType>> custom_route_ptr)
        : IHandlerNode<SessionType>(std::move(path_segment))
        , _http_method(http_method)
        , _route_logic(std::move(custom_route_ptr)) { 
        auto* logic_ptr = std::get_if<std::shared_ptr<ICustomRoute<SessionType>>>(&_route_logic);
        if (!logic_ptr || !(*logic_ptr)) { // Check if variant holds the ptr and ptr is not null
            throw std::invalid_argument("Route constructor: custom_route_ptr cannot be null.");
        }
        _route_name_for_log = (*logic_ptr)->name(); // Use name from ICustomRoute
    }

    /** @brief Gets the HTTP method associated with this route. */
    [[nodiscard]] qb::http::method get_http_method() const noexcept { return _http_method; }

    /**
     * @brief Gets a descriptive name for this route, combining method and its specific handler name.
     * Used for debugging or logging purposes.
     * @return A string like "Route: GET /path/to/resource (HandlerName)".
     */
    [[nodiscard]] std::string get_node_name() const noexcept override {
        return "Route: " + std::to_string(_http_method) + " (" + _route_name_for_log + ")";
    }

    /**
     * @brief Compiles the task chain for this route and registers it with the `RouterCore`.
     *
     * This implementation of the pure virtual method from `IHandlerNode` takes the
     * `inherited_tasks` (middleware from parent nodes), appends this route's own middleware
     * (if any, though `Route` nodes typically don't have their own `_middleware_tasks` list directly,
     * relying on `RouteGroup` or `Controller` for that), then appends the specific handler
     * for this route (adapted to `IAsyncTask` via `RouteLambdaTask` or `CustomRouteAdapterTask`).
     * The full path and the final, complete task chain are then registered with the `router_core`.
     *
     * @param router_core Reference to the `RouterCore` for registration.
     * @param current_built_path The full path accumulated up to this route's parent.
     * @param inherited_tasks Middleware tasks inherited from parent nodes.
     */
    void compile_tasks_and_register(
        RouterCore<SessionType>& router_core,
        const std::string& current_built_path,
        const std::list<std::shared_ptr<IAsyncTask<SessionType>>>& inherited_tasks) override {
        
        std::string full_route_path = this->build_full_path(current_built_path);
        std::list<std::shared_ptr<IAsyncTask<SessionType>>> final_tasks = this->combine_tasks(inherited_tasks);

        // Add the actual route handler task (lambda or custom route adapter)
        std::visit([&final_tasks, &full_route_path](auto&& arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, RouteHandlerFn<SessionType>>) {
                if (arg) { // arg is RouteHandlerFn<SessionType>
                    final_tasks.push_back(std::make_shared<RouteLambdaTask<SessionType>>(arg, "HandlerFor:" + full_route_path));
                }
            } else if constexpr (std::is_same_v<T, std::shared_ptr<ICustomRoute<SessionType>>>) {
                if (arg) { // arg is std::shared_ptr<ICustomRoute<SessionType>>
                    final_tasks.push_back(std::make_shared<CustomRouteAdapterTask<SessionType>>(arg));
                }
            }
        }, _route_logic);

        router_core.register_compiled_route(full_route_path, _http_method, final_tasks);
    }
};

} // namespace qb::http 
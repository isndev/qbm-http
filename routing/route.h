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

// --- Task adapter for RouteHandlerFn (lambda handlers) ---
template <typename SessionType>
class RouteLambdaTask : public IAsyncTask<SessionType> {
private:
    RouteHandlerFn<SessionType> _handler_fn; // Uses RouteHandlerFn from types.h
    std::string _name;

public:
    explicit RouteLambdaTask(RouteHandlerFn<SessionType> handler_fn, std::string name = "RouteLambdaHandler")
        : _handler_fn(std::move(handler_fn)), _name(std::move(name)) {
        if (!_handler_fn) {
            throw std::invalid_argument("RouteLambdaTask: handler_fn cannot be null.");
        }
    }

    void execute(std::shared_ptr<Context<SessionType>> ctx) override {
        try {
            _handler_fn(ctx); // Lambda is responsible for ctx->complete()
        } catch (const std::exception& e) {
            std::cerr << "RouteLambdaTask [" << name() << "]: Exception during handler_fn: " << e.what() << std::endl;
            if (!ctx->is_completed() && !ctx->is_cancelled()) {
                 ctx->response().status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR; // NO NAMESPACE
                 const qb::http::AsyncTaskResult error_result = qb::http::AsyncTaskResult::ERROR;
                 ctx->complete(error_result);
            }
        }
    }

    void cancel() override { /* No-op for typical lambdas */ }

    std::string name() const override {
        return _name;
    }
};

// --- Task adapter for ICustomRoute ---
template <typename SessionType>
class CustomRouteAdapterTask : public IAsyncTask<SessionType> {
private:
    std::shared_ptr<ICustomRoute<SessionType>> _custom_route;

public:
    explicit CustomRouteAdapterTask(std::shared_ptr<ICustomRoute<SessionType>> custom_route)
        : _custom_route(std::move(custom_route)) {
        if (!_custom_route) {
            throw std::invalid_argument("CustomRouteAdapterTask: custom_route pointer cannot be null.");
        }
    }

    void execute(std::shared_ptr<Context<SessionType>> ctx) override {
        try {
            _custom_route->process(ctx); // CustomRoute is responsible for ctx->complete()
        } catch (const std::exception& e) {
            std::cerr << "CustomRouteAdapterTask [" << name() << "]: Exception during process(): " << e.what() << std::endl;
            if (!ctx->is_completed() && !ctx->is_cancelled()) {
                ctx->response().status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR; // NO NAMESPACE
                const qb::http::AsyncTaskResult error_result = qb::http::AsyncTaskResult::ERROR;
                ctx->complete(error_result);
            }
        }
    }

    void cancel() override {
        if (_custom_route) {
            try {
                _custom_route->cancel();
            } catch (const std::exception& e) {
                 std::cerr << "CustomRouteAdapterTask [" << name() << "]: Exception during custom_route->cancel(): " << e.what() << std::endl;
            }
        }
    }

    std::string name() const override {
        return _custom_route ? _custom_route->name() : "InvalidCustomRouteAdapter";
    }
};

/**
 * @brief Represents a specific route (an endpoint) in the routing system.
 */
template <typename Session>
class Route : public IHandlerNode<Session> {
private:
    qb::http::method _http_method;
    
    using RouteLogic = std::variant<
        RouteHandlerFn<Session>,                     // Store raw lambda/function from types.h
        std::shared_ptr<ICustomRoute<Session>>       // Store shared_ptr to custom route object
    >;
    RouteLogic _route_logic;
    std::string _route_name_for_log; 

public:
    // Constructor for simple RouteHandlerFn
    Route(std::string path_segment, qb::http::method http_method, RouteHandlerFn<Session> handler_fn)
        : IHandlerNode<Session>(std::move(path_segment))
        , _http_method(http_method)
        , _route_logic(std::move(handler_fn)) { // Store the handler_fn (which is std::function<void(std::shared_ptr<Context<Session>>)>)
        _route_name_for_log = "Func:" + this->_path_segment;
    }

    // Constructor for ICustomRoute objects
    Route(std::string path_segment, qb::http::method http_method, std::shared_ptr<ICustomRoute<Session>> custom_route)
        : IHandlerNode<Session>(std::move(path_segment))
        , _http_method(http_method)
        , _route_logic(std::move(custom_route)) { 
        if (auto cr_ptr_variant = std::get_if<std::shared_ptr<ICustomRoute<Session>>>(&_route_logic)) {
            if (*cr_ptr_variant) {
                _route_name_for_log = (*cr_ptr_variant)->name(); // Assumes ICustomRoute has name()
            } else {
                _route_name_for_log = "InvalidCustomRoute:" + this->_path_segment;
            }
        } else { // This case implies it's a RouteHandlerFn, not an ICustomRoute
             _route_name_for_log = "Func:" + this->_path_segment; // Default name for lambda routes
        }
    }

    qb::http::method get_http_method() const { return _http_method; }

    std::string get_node_name() const override {
        // Use qb::http::http_method_to_string from types.h if available, otherwise provide a fallback or ensure it is included
        return "Route: " + qb::http::http_method_to_string(_http_method) + " " + _route_name_for_log;
    }

    void compile_tasks_and_register(
        RouterCore<Session>& router_core,
        const std::string& current_built_path,
        const std::list<std::shared_ptr<IAsyncTask<Session>>>& inherited_tasks) override {
        
        std::string full_route_path = this->build_full_path(current_built_path);
        std::list<std::shared_ptr<IAsyncTask<Session>>> final_tasks = this->combine_tasks(inherited_tasks);

        std::visit([&](auto&& arg) {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, RouteHandlerFn<Session>>) {
                if (arg) { // arg is RouteHandlerFn<Session>
                    final_tasks.push_back(std::make_shared<RouteLambdaTask<Session>>(arg, "Route:" + full_route_path));
                }
            } else if constexpr (std::is_same_v<T, std::shared_ptr<ICustomRoute<Session>>>) {
                if (arg) { // arg is std::shared_ptr<ICustomRoute<Session>>
                    final_tasks.push_back(std::make_shared<CustomRouteAdapterTask<Session>>(arg));
                }
            }
        }, _route_logic);

        router_core.register_compiled_route(full_route_path, _http_method, final_tasks);
    }
};

} // namespace qb::http 
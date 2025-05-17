#pragma once

#include "./handler_node.h"
#include "./route.h"
#include "./middleware.h"
#include "./types.h" // For RouteHandlerFn, MiddlewareHandlerFn
#include "../types.h" // For qb::http::method

#include <string>
#include <vector>
#include <memory>
#include <list>
#include <functional>
#include <iostream>
#include <type_traits> // For std::enable_if_t, std::is_base_of_v

namespace qb::http {

// Forward declarations
template <typename Session>
class RouterCore;

template <typename Session>
class Controller;

/**
 * @brief Represents a group of routes that share a common path prefix and middleware.
 */
template <typename Session>
class RouteGroup : public IHandlerNode<Session> {
private:
    // Children can be other RouteGroups, Routes, or Controllers
    std::vector<std::shared_ptr<IHandlerNode<Session>>> _children;

public:
    explicit RouteGroup(std::string path_prefix)
        : IHandlerNode<Session>(std::move(path_prefix)) {}

    std::string get_node_name() const override {
        return "RouteGroup: " + this->_path_segment;
    }

    // --- Fluent API for adding routes, groups, middleware --- 

    RouteGroup<Session>& add_route(std::string path, qb::http::method method, RouteHandlerFn<Session> handler_fn) {
        auto route_node = std::make_shared<Route<Session>>(std::move(path), method, std::move(handler_fn));
        add_child(route_node);
        return *this;
    }

    RouteGroup<Session>& get(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_route(std::move(path), qb::http::method::HTTP_GET, std::move(handler_fn));
    }

    RouteGroup<Session>& post(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_route(std::move(path), qb::http::method::HTTP_POST, std::move(handler_fn));
    }

    RouteGroup<Session>& put(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_route(std::move(path), qb::http::method::HTTP_PUT, std::move(handler_fn));
    }

    RouteGroup<Session>& del(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_route(std::move(path), qb::http::method::HTTP_DELETE, std::move(handler_fn));
    }

    RouteGroup<Session>& patch(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_route(std::move(path), qb::http::method::HTTP_PATCH, std::move(handler_fn));
    }

    RouteGroup<Session>& options(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_route(std::move(path), qb::http::method::HTTP_OPTIONS, std::move(handler_fn));
    }

    RouteGroup<Session>& head(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_route(std::move(path), qb::http::method::HTTP_HEAD, std::move(handler_fn));
    }

    // Overload for pre-created ICustomRoute shared_ptr
    RouteGroup<Session>& add_route(std::string path, qb::http::method method, std::shared_ptr<ICustomRoute<Session>> custom_route) {
        auto route_node = std::make_shared<Route<Session>>(std::move(path), method, std::move(custom_route));
        add_child(route_node);
        return *this;
    }

    RouteGroup<Session>& get(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
        return add_route(std::move(path), qb::http::method::HTTP_GET, std::move(custom_route));
    }
    RouteGroup<Session>& post(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
        return add_route(std::move(path), qb::http::method::HTTP_POST, std::move(custom_route));
    }
    RouteGroup<Session>& put(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
        return add_route(std::move(path), qb::http::method::HTTP_PUT, std::move(custom_route));
    }
    RouteGroup<Session>& del(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
        return add_route(std::move(path), qb::http::method::HTTP_DELETE, std::move(custom_route));
    }
    RouteGroup<Session>& patch(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
        return add_route(std::move(path), qb::http::method::HTTP_PATCH, std::move(custom_route));
    }
    RouteGroup<Session>& options(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
        return add_route(std::move(path), qb::http::method::HTTP_OPTIONS, std::move(custom_route));
    }
    RouteGroup<Session>& head(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
        return add_route(std::move(path), qb::http::method::HTTP_HEAD, std::move(custom_route));
    }

    std::shared_ptr<RouteGroup<Session>> group(std::string path_prefix) {
        auto group_node = std::make_shared<RouteGroup<Session>>(std::move(path_prefix));
        add_child(group_node);
        return group_node;
    }
    
    template <typename C, typename... Args>
    std::shared_ptr<C> controller(std::string path_prefix, Args&&... args) {
        static_assert(std::is_base_of_v<Controller<Session>, C>, "C must be derived from Controller<Session>");
        auto controller_node = std::make_shared<C>(std::forward<Args>(args)...);
        controller_node->set_base_path_segment(std::move(path_prefix)); 
        add_child(std::static_pointer_cast<IHandlerNode<Session>>(controller_node));
        return controller_node;
    }

    // --- Middleware methods --- 

    RouteGroup<Session>& use(MiddlewareHandlerFn<Session> mw_fn, std::string name = "UnnamedFunctionalMiddleware_Use") {
        auto functional_middleware = std::make_shared<FunctionalMiddleware<Session>>(std::move(mw_fn), name);
        auto middleware_task = std::make_shared<MiddlewareTask<Session>>(functional_middleware, name);
        this->add_middleware(middleware_task);
        return *this;
    }

    RouteGroup<Session>& use(std::shared_ptr<IMiddleware<Session>> mw_ptr, std::string name_override = "") {
        std::string task_name = name_override;
        if (task_name.empty() && mw_ptr) {
            task_name = mw_ptr->name();
        }
        if (task_name.empty()) {
             task_name = "UnnamedMiddlewareTask_Use";
        }
        auto middleware_task = std::make_shared<MiddlewareTask<Session>>(std::move(mw_ptr), task_name);
        this->add_middleware(middleware_task);
        return *this;
    }
    
    template<typename MiddlewareType, typename ...Args,
             typename = std::enable_if_t<std::is_base_of_v<IMiddleware<Session>, MiddlewareType>>>
    RouteGroup<Session>& use(Args&&... args) {
        auto mw_instance = std::make_shared<MiddlewareType>(std::forward<Args>(args)...);
        return use(mw_instance, "");
    }

    void add_child(std::shared_ptr<IHandlerNode<Session>> child_node) {
        child_node->set_parent(this->weak_from_this());
        _children.push_back(std::move(child_node));
    }

    // --- Task Compilation --- 
    void compile_tasks_and_register(
        RouterCore<Session>& router_core,
        const std::string& current_built_path,
        const std::list<std::shared_ptr<IAsyncTask<Session>>>& inherited_tasks) override {
        
        std::string group_full_path = this->build_full_path(current_built_path);
        std::list<std::shared_ptr<IAsyncTask<Session>>> tasks_for_children = this->combine_tasks(inherited_tasks);

        for (const auto& child : _children) {
            child->compile_tasks_and_register(router_core, group_full_path, tasks_for_children);
        }
    }

    std::list<std::shared_ptr<IAsyncTask<Session>>> combine_tasks(
        const std::list<std::shared_ptr<IAsyncTask<Session>>>& inherited_tasks) const override {
        return IHandlerNode<Session>::combine_tasks(inherited_tasks);
    }

    // --- Typed Route Support ---
    template <typename CustomRouteType, typename... Args>
    RouteGroup<Session>& add_custom_route(std::string path, qb::http::method method, Args&&... ctor_args) {
        static_assert(std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>, "CustomRouteType must derive from ICustomRoute<Session>");
        auto custom_route_obj = std::make_shared<CustomRouteType>(std::forward<Args>(ctor_args)...);
        auto route_node = std::make_shared<Route<Session>>(std::move(path), method, custom_route_obj);
        add_child(route_node);
        return *this;
    }

    template <typename CustomRouteType, typename... Args>
    RouteGroup<Session>& get(std::string path, Args&&... ctor_args) {
        return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_GET, std::forward<Args>(ctor_args)...);
    }

    template <typename CustomRouteType, typename... Args>
    RouteGroup<Session>& post(std::string path, Args&&... ctor_args) {
        return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_POST, std::forward<Args>(ctor_args)...);
    }

    template <typename CustomRouteType, typename... Args>
    RouteGroup<Session>& put(std::string path, Args&&... ctor_args) {
        return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_PUT, std::forward<Args>(ctor_args)...);
    }

    template <typename CustomRouteType, typename... Args>
    RouteGroup<Session>& del(std::string path, Args&&... ctor_args) {
        return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_DELETE, std::forward<Args>(ctor_args)...);
    }

    template <typename CustomRouteType, typename... Args>
    RouteGroup<Session>& patch(std::string path, Args&&... ctor_args) {
        return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_PATCH, std::forward<Args>(ctor_args)...);
    }

    template <typename CustomRouteType, typename... Args>
    RouteGroup<Session>& options(std::string path, Args&&... ctor_args) {
        return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_OPTIONS, std::forward<Args>(ctor_args)...);
    }

    template <typename CustomRouteType, typename... Args>
    RouteGroup<Session>& head(std::string path, Args&&... ctor_args) {
        return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_HEAD, std::forward<Args>(ctor_args)...);
    }

}; // class RouteGroup

} // namespace qb::http 
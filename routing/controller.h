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
#include <typeinfo>
#include <type_traits> // For std::enable_if_t, std::is_base_of_v

namespace qb::http {

// Forward declaration
template <typename Session>
class RouterCore;

/**
 * @brief Base class for user-defined controllers.
 *
 * Controllers group related route handlers within a class structure and under a common base path.
 * They also manage their own middleware stack, which applies to all routes within the controller.
 */
template <typename Session>
class Controller : public IHandlerNode<Session> {
protected:
    // Routes defined within this controller. They are relative to the controller's base path.
    std::vector<std::shared_ptr<IHandlerNode<Session>>> _controller_routes;

    using ControllerMiddlewareFn = std::function<std::shared_ptr<IMiddleware<Session>>(void)>;

    // Helper methods for derived controllers to define routes
    // These can remain protected as they are implementation details for the public API below

    Controller<Session>& add_controller_route(std::string path, qb::http::method method, RouteHandlerFn<Session> handler_fn) {
        auto route_node = std::make_shared<Route<Session>>(std::move(path), method, std::move(handler_fn));
        route_node->set_parent(this->weak_from_this()); // Route's parent is this controller instance
        _controller_routes.push_back(std::move(route_node));
        return *this;
    }

    Controller<Session>& add_controller_route(std::string path, qb::http::method method, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        auto route_node = std::make_shared<Route<Session>>(std::move(path), method, std::move(custom_route_ptr));
        route_node->set_parent(this->weak_from_this());
        _controller_routes.push_back(std::move(route_node));
        return *this;
    }

    template <typename CustomRouteType, typename... Args>
    Controller<Session>& add_controller_custom_route(std::string path, qb::http::method method, Args&&... ctor_args) {
        static_assert(std::is_base_of_v<ICustomRoute<Session>, CustomRouteType>, "CustomRouteType must derive from ICustomRoute<Session>");
        auto custom_route_obj = std::make_shared<CustomRouteType>(std::forward<Args>(ctor_args)...);
        auto route_node = std::make_shared<Route<Session>>(std::move(path), method, custom_route_obj);
        route_node->set_parent(this->weak_from_this());
        _controller_routes.push_back(std::move(route_node));
        return *this;
    }

public:
    /**
     * @brief Constructor.
     * Controllers are typically constructed with a base path segment of "" initially,
     * as their actual base path is set when they are mounted to a router or group.
     */
    Controller() : IHandlerNode<Session>("") {}
    virtual ~Controller() = default;

    /**
     * @brief Sets the base path segment for this controller. 
     * This is usually called by the Router or RouteGroup when mounting the controller.
     */
    void set_base_path_segment(std::string path_segment) {
        this->_path_segment = std::move(path_segment);
    }

    std::string get_node_name() const override {
        return "Controller: " + this->_path_segment;
    }

    /**
     * @brief This method should be implemented by derived controllers to define their routes.
     *
     * Example:
     * void initialize_routes() override {
     *     get("/items", [this](auto ctx){ this->get_items(ctx); }); // Using new public API
     *     post("/items", MEMBER_HANDLER(&MyController::create_item)); // MEMBER_HANDLER uses add_controller_route
     * }
     */
    virtual void initialize_routes() = 0;

// --- Public Route Definition API for Controllers ---

    // --- Lambda-based routes ---
    Controller<Session>& get(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_GET, std::move(handler_fn));
    }
    Controller<Session>& post(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_POST, std::move(handler_fn));
    }
    Controller<Session>& put(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_PUT, std::move(handler_fn));
    }
    Controller<Session>& del(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_DELETE, std::move(handler_fn));
    }
    Controller<Session>& patch(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_PATCH, std::move(handler_fn));
    }
    Controller<Session>& options(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_OPTIONS, std::move(handler_fn));
    }
    Controller<Session>& head(std::string path, RouteHandlerFn<Session> handler_fn) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_HEAD, std::move(handler_fn));
    }

    // --- Typed ICustomRoute routes (moved from protected to public) ---
    template <typename CustomRouteType, typename... Args>
    Controller<Session>& get(std::string path, Args&&... ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_GET, std::forward<Args>(ctor_args)...);
    }
    template <typename CustomRouteType, typename... Args>
    Controller<Session>& post(std::string path, Args&&... ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_POST, std::forward<Args>(ctor_args)...);
    }
    template <typename CustomRouteType, typename... Args>
    Controller<Session>& put(std::string path, Args&&... ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_PUT, std::forward<Args>(ctor_args)...);
    }
    template <typename CustomRouteType, typename... Args>
    Controller<Session>& del(std::string path, Args&&... ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_DELETE, std::forward<Args>(ctor_args)...);
    }
    template <typename CustomRouteType, typename... Args>
    Controller<Session>& patch(std::string path, Args&&... ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_PATCH, std::forward<Args>(ctor_args)...);
    }
    template <typename CustomRouteType, typename... Args>
    Controller<Session>& options(std::string path, Args&&... ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_OPTIONS, std::forward<Args>(ctor_args)...);
    }
    template <typename CustomRouteType, typename... Args>
    Controller<Session>& head(std::string path, Args&&... ctor_args) {
        return add_controller_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_HEAD, std::forward<Args>(ctor_args)...);
    }

    // --- std::shared_ptr<ICustomRoute<Session>> routes (moved from protected to public) ---
    Controller<Session>& get(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_GET, std::move(custom_route_ptr));
    }
    Controller<Session>& post(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_POST, std::move(custom_route_ptr));
    }
    Controller<Session>& put(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_PUT, std::move(custom_route_ptr));
    }
    Controller<Session>& del(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_DELETE, std::move(custom_route_ptr));
    }
    Controller<Session>& patch(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_PATCH, std::move(custom_route_ptr));
    }
    Controller<Session>& options(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_OPTIONS, std::move(custom_route_ptr));
    }
    Controller<Session>& head(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route_ptr) {
        return add_controller_route(std::move(path), qb::http::method::HTTP_HEAD, std::move(custom_route_ptr));
    }

    // Convenience macro for binding member functions as handlers
    // Usage: add_controller_route("/path", HTTP_GET, MEMBER_HANDLER(&MyController::handler_method));
    // Or with new public API: get("/path", MEMBER_HANDLER(&MyController::handler_method));
    #define MEMBER_HANDLER(handler_ptr) \
        [this](auto ctx_param) { (this->*handler_ptr)(ctx_param); }

public:
    // --- Middleware for this controller --- 
    Controller<Session>& use(ControllerMiddlewareFn mw_fn, std::string name = "ControllerMiddleware_Use") {
        if (!mw_fn) return *this;
        auto middleware_instance = mw_fn(); 
        if (!middleware_instance) {
            std::cerr << "Warning: Middleware factory for controller (use) with name '" << name << "' returned nullptr." << std::endl;
            return *this;
        }
        std::string task_name = name;
        if (task_name == "ControllerMiddleware_Use" || task_name.empty()) {
            task_name = middleware_instance->name();
        }
        if (task_name.empty()) {
            task_name = "UnnamedControllerFactoryMiddleware_Use";
        }
        auto middleware_task = std::make_shared<MiddlewareTask<Session>>(std::move(middleware_instance), task_name);
        this->add_middleware(middleware_task); // Calls IHandlerNode::add_middleware (prepends)
        return *this;
    }

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
        this->add_middleware(middleware_task); // Calls IHandlerNode::add_middleware (prepends)
        return *this;
    }

    template<typename MiddlewareType, typename ...Args,
             typename = std::enable_if_t<std::is_base_of_v<IMiddleware<Session>, MiddlewareType>>>
    Controller<Session>& use(Args&&... args) {
        auto mw_instance = std::make_shared<MiddlewareType>(std::forward<Args>(args)...);
        // Let the existing use overload handle name derivation
        return use(mw_instance, ""); 
    }

public:
    // --- Task Compilation --- 
    void compile_tasks_and_register(
        RouterCore<Session>& router_core,
        const std::string& current_built_path, // Path built up to the parent of this controller
        const std::list<std::shared_ptr<IAsyncTask<Session>>>& inherited_tasks) override {
        
        // Call initialize_routes only once, and effectively during compilation
        if (_controller_routes.empty()) { // Simple guard to ensure it's called once
             initialize_routes();
        }

        std::string controller_base_path = this->build_full_path(current_built_path);
        std::list<std::shared_ptr<IAsyncTask<Session>>> tasks_for_controller_routes = this->combine_tasks(inherited_tasks);

        for (const auto& route_node : _controller_routes) {
            // The route_node here is a Route<Session> added via add_controller_route
            // Its path segment is relative to the controller.
            // It will use controller_base_path as its parent's full path.
            route_node->compile_tasks_and_register(router_core, controller_base_path, tasks_for_controller_routes);
        }
    }
};

} // namespace qb::http 
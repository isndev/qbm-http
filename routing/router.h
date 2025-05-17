#pragma once

#include "./router_core.h"
#include "./route_group.h"
#include "./route.h"
#include "./controller.h"
#include "./middleware.h"
#include "./types.h" // For RouteHandlerFn etc.
#include "../request.h"  // Existing qb::http::Request
#include "../types.h"    // For qb::http::method

#include <memory>
#include <string>
#include <vector>
#include <list>
#include <type_traits> // For std::enable_if_t, std::is_base_of_v

namespace qb::http {

/**
 * @brief Main HTTP Router class templated on the Session type.
 *
 * Provides a fluent API for defining routes, groups, and controllers.
 * Manages the compilation of routes into efficient task chains and handles
 * incoming requests by dispatching them to the appropriate compiled chain.
 */
template <typename Session>
class Router {
private:
    std::shared_ptr<RouterCore<Session>> _core; // The engine that does the heavy lifting
    std::shared_ptr<RouteGroup<Session>> _root_group; // A root group to attach top-level items
    bool _is_compiled = false;

public:

    Router();
    ~Router();

    // --- Route Definition API (mirrors RouteGroup for convenience at top level) --- 

    Router<Session>& add_route(std::string path, qb::http::method method, RouteHandlerFn<Session> handler_fn);
    Router<Session>& get(std::string path, RouteHandlerFn<Session> handler_fn);
    Router<Session>& post(std::string path, RouteHandlerFn<Session> handler_fn);
    Router<Session>& put(std::string path, RouteHandlerFn<Session> handler_fn);
    Router<Session>& del(std::string path, RouteHandlerFn<Session> handler_fn); // 'delete' is a keyword
    Router<Session>& patch(std::string path, RouteHandlerFn<Session> handler_fn);
    Router<Session>& options(std::string path, RouteHandlerFn<Session> handler_fn);
    Router<Session>& head(std::string path, RouteHandlerFn<Session> handler_fn);

    // Overload for pre-created ICustomRoute shared_ptr
    Router<Session>& get(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route);
    Router<Session>& post(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route);
    Router<Session>& put(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route);
    Router<Session>& del(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route);
    Router<Session>& patch(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route);
    Router<Session>& options(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route);
    Router<Session>& head(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route);

    // Typed route support
    template <typename CustomRouteType, typename... Args>
    Router<Session>& add_custom_route(std::string path, qb::http::method method, Args&&... ctor_args);

    template <typename CustomRouteType, typename... Args>
    Router<Session>& get(std::string path, Args&&... ctor_args);

    template <typename CustomRouteType, typename... Args>
    Router<Session>& post(std::string path, Args&&... ctor_args);

    template <typename CustomRouteType, typename... Args>
    Router<Session>& put(std::string path, Args&&... ctor_args);

    template <typename CustomRouteType, typename... Args>
    Router<Session>& del(std::string path, Args&&... ctor_args);

    template <typename CustomRouteType, typename... Args>
    Router<Session>& patch(std::string path, Args&&... ctor_args);

    template <typename CustomRouteType, typename... Args>
    Router<Session>& options(std::string path, Args&&... ctor_args);

    template <typename CustomRouteType, typename... Args>
    Router<Session>& head(std::string path, Args&&... ctor_args);

    /**
     * @brief Creates a new route group under the router's root.
     * @param path_prefix The prefix for all routes within this group.
     * @return A shared pointer to the created RouteGroup.
     */
    std::shared_ptr<RouteGroup<Session>> group(std::string path_prefix);

    /**
     * @brief Mounts a controller under the router's root with a given path prefix.
     * @tparam C The controller class type (must derive from Controller<Session>).
     * @tparam Args Arguments for the controller's constructor.
     * @param path_prefix The base path for this controller.
     * @param args Constructor arguments for the controller.
     * @return A shared pointer to the created controller instance.
     */
    template <typename C, typename... Args>
    std::shared_ptr<C> controller(std::string path_prefix, Args&&... args);

    // --- Middleware methods --- 
    Router<Session>& use(MiddlewareHandlerFn<Session> mw_fn, std::string name = "UnnamedGlobalMiddleware_Use");
    Router<Session>& use(std::shared_ptr<IMiddleware<Session>> mw_ptr, std::string name_override = "");
    
    template<typename MiddlewareType, typename ...Args,
             typename = std::enable_if_t<std::is_base_of_v<IMiddleware<Session>, MiddlewareType>>>
    Router<Session>& use(Args&&... args) {
        if (_root_group) {
            _root_group->template use<MiddlewareType>(std::forward<Args>(args)...);
        }
        return *this;
    }

    /**
     * @brief Sets a custom handler for 404 Not Found responses.
     * @param handler_fn The function to handle 404 errors.
     */
    void set_not_found_handler(RouteHandlerFn<Session> handler_fn);

    /**
     * @brief Sets the global error handling task chain.
     * @param error_chain A list of IAsyncTask to be executed on unhandled errors.
     */
    void set_error_task_chain(std::list<std::shared_ptr<IAsyncTask<Session>>> error_chain);

    /**
     * @brief Compiles all defined routes, groups, and controllers.
     * This MUST be called after all route definitions and before processing requests.
     * Calling this multiple times will recompile (e.g., if routes are added dynamically).
     */
    void compile();

    /**
     * @brief Main entry point for routing an incoming request.
     *
     * The Session type must provide a way to send the qb::http::Response,
     * or the application must handle sending the response after this method processes it.
     * The RouterCore itself does not send the response; it prepares it in the Context.
     *
     * @param session A shared pointer to the client session.
     * @param request The incoming HTTP request (moved into the context).
     */
    std::shared_ptr<Context<Session>> route(std::shared_ptr<Session> session, qb::http::Request request);

    // Method to get a weak_ptr to the internal RouterCore
    std::weak_ptr<RouterCore<Session>> get_core_weak_ptr() {
        if (_core) {
            return _core->weak_from_this();
        }
        return {}; // Return an empty weak_ptr if _core is null
    }

    /**
     * @brief Clears all routes, middleware, and resets the router to its initial state.
     */
    void clear();
};

} // namespace qb::http

#include "./router.tpp" // Template implementations 
// This file is included by router.h and contains template implementations for qb::http::Router.

#include "./router_core.h"  // Required for RouterCore definition
#include "./route_group.h"  // Required for RouteGroup definition
#include "./controller.h"   // Required for Controller definition
#include "./context.h"      // Required for Context definition
#include "./types.h"        // For RouteHandlerFn, MiddlewareHandlerFn etc.

// Note: Other necessary headers like <memory>, <string>, <functional> 
// are expected to be included in router.h before this .tpp file.

namespace qb::http {

template <typename SessionType>
Router<SessionType>::Router()
    : _router_core(std::make_shared<RouterCore<SessionType>>([this](Context<SessionType>& ctx) {
        // This callback is invoked by RouterCore when a Context is finalized.
        // It's responsible for sending the response via the session associated with the context.
        if (auto session_ptr = ctx.session()) { // Ensure session is still valid
            ctx.execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND); // Allow final header mods
            (*session_ptr) << ctx.response(); // Assumes SessionType has send_response()
            // POST_RESPONSE_SEND hook would typically be called after this, by the session or IO layer upon write completion.
        } else {
            // Log warning if session is null: session might have disconnected before response could be sent.
            // This would typically be handled by a proper logging framework.
        }
    })),
      _root_group(std::make_shared<RouteGroup<SessionType>>("")), // Root group has an empty path prefix
      _is_compiled(false) {
    if (_router_core) {
        _router_core->add_handler_node(_root_group); // Add the root group to the core
    }
}

template <typename SessionType>
Router<SessionType>::~Router() = default; // Default destructor is sufficient

// --- Route Definition API (delegates to _root_group) ---

template <typename SessionType>
Router<SessionType>& Router<SessionType>::add_route(std::string path, qb::http::method method, RouteHandlerFn<SessionType> handler_fn) {
    if (_root_group) {
        _root_group->add_route(std::move(path), method, std::move(handler_fn));
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::get(std::string path, RouteHandlerFn<SessionType> handler_fn) {
    return add_route(std::move(path), qb::http::method::GET, std::move(handler_fn));
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::post(std::string path, RouteHandlerFn<SessionType> handler_fn) {
    return add_route(std::move(path), qb::http::method::POST, std::move(handler_fn));
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::put(std::string path, RouteHandlerFn<SessionType> handler_fn) {
    return add_route(std::move(path), qb::http::method::PUT, std::move(handler_fn));
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::del(std::string path, RouteHandlerFn<SessionType> handler_fn) {
    return add_route(std::move(path), qb::http::method::DEL, std::move(handler_fn));
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::patch(std::string path, RouteHandlerFn<SessionType> handler_fn) {
    return add_route(std::move(path), qb::http::method::PATCH, std::move(handler_fn));
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::options(std::string path, RouteHandlerFn<SessionType> handler_fn) {
    return add_route(std::move(path), qb::http::method::OPTIONS, std::move(handler_fn));
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::head(std::string path, RouteHandlerFn<SessionType> handler_fn) {
    return add_route(std::move(path), qb::http::method::HEAD, std::move(handler_fn));
}

// --- Overloads for ICustomRoute shared_ptr at root level ---
template <typename SessionType>
Router<SessionType>& Router<SessionType>::get(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->get(std::move(path), std::move(custom_route));
    }
     _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::post(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->post(std::move(path), std::move(custom_route));
    }
     _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::put(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->put(std::move(path), std::move(custom_route));
    }
     _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::del(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->del(std::move(path), std::move(custom_route));
    }
     _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::patch(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->patch(std::move(path), std::move(custom_route));
    }
     _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::options(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->options(std::move(path), std::move(custom_route));
    }
     _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::head(std::string path, std::shared_ptr<ICustomRoute<SessionType>> custom_route) {
    if (_root_group) {
        _root_group->head(std::move(path), std::move(custom_route));
    }
     _is_compiled = false;
    return *this;
}


// --- Typed ICustomRoute support at root level ---
template <typename SessionType>
template <typename CustomRouteType, typename... Args,
          typename /* = std::enable_if_t<std::is_base_of_v<ICustomRoute<SessionType>, CustomRouteType>> */>
Router<SessionType>& Router<SessionType>::add_custom_route(std::string path, qb::http::method method, Args&&... ctor_args) {
    if (_root_group) {
        _root_group->template add_custom_route<CustomRouteType>(std::move(path), method, std::forward<Args>(ctor_args)...);
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args,
          typename /* = std::enable_if_t<std::is_base_of_v<ICustomRoute<SessionType>, CustomRouteType>> */>
Router<SessionType>& Router<SessionType>::get(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::GET, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args,
          typename /* = std::enable_if_t<std::is_base_of_v<ICustomRoute<SessionType>, CustomRouteType>> */>
Router<SessionType>& Router<SessionType>::post(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::POST, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args,
          typename /* = std::enable_if_t<std::is_base_of_v<ICustomRoute<SessionType>, CustomRouteType>> */>
Router<SessionType>& Router<SessionType>::put(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::PUT, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args,
          typename /* = std::enable_if_t<std::is_base_of_v<ICustomRoute<SessionType>, CustomRouteType>> */>
Router<SessionType>& Router<SessionType>::del(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::DEL, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args,
          typename /* = std::enable_if_t<std::is_base_of_v<ICustomRoute<SessionType>, CustomRouteType>> */>
Router<SessionType>& Router<SessionType>::patch(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::PATCH, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args,
          typename /* = std::enable_if_t<std::is_base_of_v<ICustomRoute<SessionType>, CustomRouteType>> */>
Router<SessionType>& Router<SessionType>::options(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::OPTIONS, std::forward<Args>(ctor_args)...);
}

template <typename SessionType>
template <typename CustomRouteType, typename... Args,
          typename /* = std::enable_if_t<std::is_base_of_v<ICustomRoute<SessionType>, CustomRouteType>> */>
Router<SessionType>& Router<SessionType>::head(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HEAD, std::forward<Args>(ctor_args)...);
}

// --- Group and Controller mounting ---
template <typename SessionType>
std::shared_ptr<RouteGroup<SessionType>> Router<SessionType>::group(std::string path_prefix) {
    _is_compiled = false;
    return _root_group ? _root_group->group(std::move(path_prefix)) : nullptr;
}

template <typename SessionType>
template <typename C, typename... Args,
          typename /* = std::enable_if_t<std::is_base_of_v<IController<SessionType>, C> && std::is_constructible_v<C, Args...>> */ >
std::shared_ptr<C> Router<SessionType>::controller(std::string path_prefix, Args&&... args) {
    _is_compiled = false;
    return _root_group ? _root_group->template controller<C>(std::move(path_prefix), std::forward<Args>(args)...) : nullptr;
}

// --- Middleware methods (apply to _root_group) ---
template <typename SessionType>
Router<SessionType>& Router<SessionType>::use(MiddlewareHandlerFn<SessionType> mw_fn, std::string name) {
    if (_root_group) {
        _root_group->use(std::move(mw_fn), std::move(name));
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
Router<SessionType>& Router<SessionType>::use(std::shared_ptr<IMiddleware<SessionType>> mw_ptr, std::string name_override) {
    if (_root_group) {
        _root_group->use(std::move(mw_ptr), std::move(name_override));
    }
    _is_compiled = false;
    return *this;
}

template <typename SessionType>
template<typename MiddlewareType, typename ...Args,
         typename /* = std::enable_if_t<std::is_base_of_v<IMiddleware<SessionType>, MiddlewareType>> */>
Router<SessionType>& Router<SessionType>::use(Args&&... args) {
    if (_root_group) {
        _root_group->template use<MiddlewareType>(std::forward<Args>(args)...);
    }
    _is_compiled = false;
    return *this;
}

// --- Special Handlers (delegate to RouterCore) ---
template <typename SessionType>
void Router<SessionType>::set_not_found_handler(RouteHandlerFn<SessionType> handler_fn) {
    if (_router_core) {
        _router_core->set_not_found_handler(std::move(handler_fn));
    }
}

template <typename SessionType>
void Router<SessionType>::set_error_task_chain(std::list<std::shared_ptr<IAsyncTask<SessionType>>> error_chain) {
    if (_router_core) {
        _router_core->set_error_task_chain(std::move(error_chain));
    }
}

// --- Compilation and Routing ---
template <typename SessionType>
void Router<SessionType>::compile() {
    if (_router_core) {
        _router_core->compile_all_routes();
    }
    _is_compiled = true;
}

template <typename SessionType>
std::shared_ptr<Context<SessionType>> Router<SessionType>::route(std::shared_ptr<SessionType> session, qb::http::Request request) {
    if (!_is_compiled && _router_core) { // Auto-compile if not already compiled
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
std::weak_ptr<RouterCore<SessionType>> Router<SessionType>::get_router_core_weak_ptr() noexcept {
    return _router_core; // std::shared_ptr can implicitly convert to std::weak_ptr
}

template <typename SessionType>
void Router<SessionType>::clear() noexcept {
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
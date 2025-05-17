// This file should be included by router.h
// Contains template implementations for qb::http::Router

namespace qb::http {

template <typename Session>
Router<Session>::Router()
    : _is_compiled(false)
    , _root_group(std::make_shared<RouteGroup<Session>>("")) { 
    _core = std::make_shared<RouterCore<Session>>([this](qb::http::Context<Session>& ctx) {
        if (ctx.session()) {
            ctx.execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND);
             *(ctx.session()) << ctx.response();
        } else {
            std::cerr << "Router: Warning - on_request_finalized_callback called on a context with no session." << std::endl;
        }
    });
    _core->add_handler_node(_root_group); 
}

template <typename Session>
Router<Session>::~Router() {
}

template <typename Session>
Router<Session>& Router<Session>::add_route(std::string path, qb::http::method method, RouteHandlerFn<Session> handler_fn) {
    _root_group->add_route(std::move(path), method, std::move(handler_fn));
    _is_compiled = false;
    return *this;
}

template <typename Session>
Router<Session>& Router<Session>::get(std::string path, RouteHandlerFn<Session> handler_fn) {
    return add_route(std::move(path), qb::http::method::HTTP_GET, std::move(handler_fn));
}

template <typename Session>
Router<Session>& Router<Session>::post(std::string path, RouteHandlerFn<Session> handler_fn) {
    return add_route(std::move(path), qb::http::method::HTTP_POST, std::move(handler_fn));
}

template <typename Session>
Router<Session>& Router<Session>::put(std::string path, RouteHandlerFn<Session> handler_fn) {
    return add_route(std::move(path), qb::http::method::HTTP_PUT, std::move(handler_fn));
}

template <typename Session>
Router<Session>& Router<Session>::del(std::string path, RouteHandlerFn<Session> handler_fn) {
    return add_route(std::move(path), qb::http::method::HTTP_DELETE, std::move(handler_fn));
}

template <typename Session>
Router<Session>& Router<Session>::patch(std::string path, RouteHandlerFn<Session> handler_fn) {
    return add_route(std::move(path), qb::http::method::HTTP_PATCH, std::move(handler_fn));
}

template <typename Session>
Router<Session>& Router<Session>::options(std::string path, RouteHandlerFn<Session> handler_fn) {
    return add_route(std::move(path), qb::http::method::HTTP_OPTIONS, std::move(handler_fn));
}

template <typename Session>
Router<Session>& Router<Session>::head(std::string path, RouteHandlerFn<Session> handler_fn) {
    return add_route(std::move(path), qb::http::method::HTTP_HEAD, std::move(handler_fn));
}

template <typename Session>
std::shared_ptr<RouteGroup<Session>> Router<Session>::group(std::string path_prefix) {
    _is_compiled = false;
    return _root_group->group(std::move(path_prefix));
}

template <typename Session>
template <typename C, typename... Args>
std::shared_ptr<C> Router<Session>::controller(std::string path_prefix, Args&&... args) {
    _is_compiled = false;
    return _root_group->template controller<C>(std::move(path_prefix), std::forward<Args>(args)...);
}

template <typename Session>
Router<Session>& Router<Session>::use(MiddlewareHandlerFn<Session> mw_fn, std::string name) {
    _root_group->use(std::move(mw_fn), std::move(name));
    _is_compiled = false;
    return *this;
}

template <typename Session>
Router<Session>& Router<Session>::use(std::shared_ptr<IMiddleware<Session>> mw_ptr, std::string name_override) {
    _root_group->use(std::move(mw_ptr), std::move(name_override));
    _is_compiled = false;
    return *this;
}

template <typename Session>
void Router<Session>::set_not_found_handler(RouteHandlerFn<Session> handler_fn) {
    _core->set_not_found_handler(std::move(handler_fn));
}

template <typename Session>
void Router<Session>::set_error_task_chain(std::list<std::shared_ptr<IAsyncTask<Session>>> error_chain) {
    _core->set_error_task_chain(std::move(error_chain));
}

template <typename Session>
void Router<Session>::compile() {
    _core->compile_all_routes();
    _is_compiled = true;
}

template <typename Session>
std::shared_ptr<Context<Session>> Router<Session>::route(std::shared_ptr<Session> session, qb::http::Request request) {
    if (!_is_compiled) {
        compile();
    }
    if (_core) {
        return _core->route_request(std::move(session), std::move(request));
    }
    return nullptr; // Should not happen if _core is always initialized
}

template <typename Session>
template <typename CustomRouteType, typename... Args>
Router<Session>& Router<Session>::add_custom_route(std::string path, qb::http::method method, Args&&... ctor_args) {
    static_assert(std::is_base_of<ICustomRoute<Session>, CustomRouteType>::value, "CustomRouteType must derive from ICustomRoute<Session>");
    _root_group->template add_custom_route<CustomRouteType>(std::move(path), method, std::forward<Args>(ctor_args)...);
    _is_compiled = false;
    return *this;
}

template <typename Session>
template <typename CustomRouteType, typename... Args>
Router<Session>& Router<Session>::get(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_GET, std::forward<Args>(ctor_args)...);
}

template <typename Session>
template <typename CustomRouteType, typename... Args>
Router<Session>& Router<Session>::post(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_POST, std::forward<Args>(ctor_args)...);
}

template <typename Session>
template <typename CustomRouteType, typename... Args>
Router<Session>& Router<Session>::put(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_PUT, std::forward<Args>(ctor_args)...);
}

template <typename Session>
template <typename CustomRouteType, typename... Args>
Router<Session>& Router<Session>::del(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_DELETE, std::forward<Args>(ctor_args)...);
}

template <typename Session>
template <typename CustomRouteType, typename... Args>
Router<Session>& Router<Session>::patch(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_PATCH, std::forward<Args>(ctor_args)...);
}

template <typename Session>
template <typename CustomRouteType, typename... Args>
Router<Session>& Router<Session>::options(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_OPTIONS, std::forward<Args>(ctor_args)...);
}

template <typename Session>
template <typename CustomRouteType, typename... Args>
Router<Session>& Router<Session>::head(std::string path, Args&&... ctor_args) {
    return add_custom_route<CustomRouteType>(std::move(path), qb::http::method::HTTP_HEAD, std::forward<Args>(ctor_args)...);
}

template <typename Session>
Router<Session>& Router<Session>::get(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
    _root_group->add_route(std::move(path), qb::http::method::HTTP_GET, std::move(custom_route));
    _is_compiled = false;
    return *this;
}

template <typename Session>
Router<Session>& Router<Session>::post(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
    _root_group->add_route(std::move(path), qb::http::method::HTTP_POST, std::move(custom_route));
    _is_compiled = false;
    return *this;
}

template <typename Session>
Router<Session>& Router<Session>::put(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
    _root_group->add_route(std::move(path), qb::http::method::HTTP_PUT, std::move(custom_route));
    _is_compiled = false;
    return *this;
}

template <typename Session>
Router<Session>& Router<Session>::del(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
    _root_group->add_route(std::move(path), qb::http::method::HTTP_DELETE, std::move(custom_route));
    _is_compiled = false;
    return *this;
}

template <typename Session>
Router<Session>& Router<Session>::patch(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
    _root_group->add_route(std::move(path), qb::http::method::HTTP_PATCH, std::move(custom_route));
    _is_compiled = false;
    return *this;
}

template <typename Session>
Router<Session>& Router<Session>::options(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
    _root_group->add_route(std::move(path), qb::http::method::HTTP_OPTIONS, std::move(custom_route));
    _is_compiled = false;
    return *this;
}

template <typename Session>
Router<Session>& Router<Session>::head(std::string path, std::shared_ptr<ICustomRoute<Session>> custom_route) {
    _root_group->add_route(std::move(path), qb::http::method::HTTP_HEAD, std::move(custom_route));
    _is_compiled = false;
    return *this;
}

template <typename Session>
void Router<Session>::clear() {
    if (_core) {
        _core->clear();
    }
    // Re-initialize the root group for this router instance
    _root_group = std::make_shared<RouteGroup<Session>>(""); 
    if (_core) {
        _core->add_handler_node(_root_group); // Re-add the new root group to the core
    }
    _is_compiled = false;
}

} // namespace qb::http
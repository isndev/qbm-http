#pragma once

#include <functional>
#include <memory>
#include <regex>
#include <string>
#include <vector>
#include "../types.h"
#include "./path_parameters.h"
#include "./context.h"
#include "../middleware/middleware_interface.h"
#include "../middleware/middleware_chain.h"

#if defined(_WIN32)
#undef DELETE // Windows :/
#endif

namespace qb::http {

// Forward declaration
template <typename Session, typename String>
class Router;

template <typename Session, typename String>
struct RouterContext;

/**
 * @brief Base class for routes
 */
template <typename Session, typename String = std::string>
class IRoute {
public:
    using Context = RouterContext<Session, String>;

    virtual ~IRoute()                  = default;
    virtual void process(Context &ctx) = 0;
    virtual int
    priority() const {
        return 0;
    }
};

/**
 * @brief Base route class with regex-based pattern matching
 */
template <typename Session, typename String = std::string>
class ARoute : public IRoute<Session, String> {
protected:
    std::string              _path;
    std::regex               _pattern;
    std::vector<std::string> _param_names;
    PathParameters           _parameters;
    int                      _priority{0};

    void
    compile_pattern() {
        std::string                 pattern = _path;
        std::regex                  param_regex(":([^/]+)");
        std::smatch                 matches;
        std::string::const_iterator search_start(pattern.cbegin());

        while (std::regex_search(search_start, pattern.cend(), matches, param_regex)) {
            _param_names.push_back(matches[1].str());
            pattern.replace(matches[0].first - pattern.cbegin(), matches[0].length(),
                            "([^/]+)");
            search_start = matches[0].first + 1;
        }
        _pattern = std::regex("^" + pattern + "$");
    }

public:
    using Context = typename IRoute<Session, String>::Context;

    explicit ARoute(std::string path, int priority = 0)
        : _path(std::move(path))
        , _priority(priority) {
        compile_pattern();
    }

    virtual ~ARoute() = default;

    bool
    match(const std::string &path) {
        std::smatch matches;
        if (std::regex_match(path, matches, _pattern)) {
            _parameters.clear();
            for (size_t i = 0; i < _param_names.size(); ++i) {
                _parameters[_param_names[i]] = matches[i + 1].str();
            }
            return true;
        }
        return false;
    }

    bool
    match(Context &ctx, const std::string &path) {
        std::smatch matches;
        if (std::regex_match(path, matches, _pattern)) {
            _parameters.clear();
            for (size_t i = 0; i < _param_names.size(); ++i) {
                _parameters[_param_names[i]] = matches[i + 1].str();
            }
            ctx.path_params = _parameters;
            ctx.match       = path;
            return true;
        }
        return false;
    }

    [[nodiscard]] std::string const &
    path() const {
        return _path;
    }
    [[nodiscard]] PathParameters &
    parameters() {
        return _parameters;
    }
    [[nodiscard]] int
    priority() const override {
        return _priority;
    }

    ARoute &
    set_priority(int priority) {
        _priority = priority;
        return *this;
    }
};

/**
 * @brief Route implementation for function handlers
 */
template <typename Session, typename String, typename Func>
class TRoute : public ARoute<Session, String> {
    Func _func;

public:
    using Context = typename ARoute<Session, String>::Context;

    TRoute(std::string const &path, Func &&func, int priority = 0)
        : ARoute<Session, String>(path, priority)
        , _func(std::forward<Func>(func)) {}

    void
    process(Context &ctx) override {
        ctx.path_params = this->_parameters;
        _func(ctx);
        ctx.handled = true;
    }
};

/**
 * @brief A route group for organizing routes
 */
template <typename Session, typename String = std::string>
class RouteGroup {
    Router<Session, String>                                  &_router;
    std::string                                               _prefix;
    std::vector<typename Router<Session, String>::Middleware> _middleware;
    std::shared_ptr<MiddlewareChain<Session, String>>         _typed_middleware_chain;
    int                                                       _priority;

public:
    using RouterType = Router<Session, String>;
    using Context = RouterContext<Session, String>;
    using Middleware = typename RouterType::Middleware;
    using Handler = typename RouterType::Middleware;
    using TypedMiddlewarePtr = MiddlewarePtr<Session, String>;

    RouteGroup(RouterType &router, std::string prefix, int priority = 0)
        : _router(router)
        , _prefix(std::move(prefix))
        , _priority(priority) {}

#define REGISTER_GROUP_ROUTE_FUNCTION(num, name, description)      \
    template <typename _Func>                                      \
    RouteGroup &name(std::string const &path, _Func &&func) {      \
        std::string full_path = _prefix + path;                    \
        _router._routes[static_cast<http_method>(num)].push_back(  \
            std::make_unique<TRoute<Session, String, _Func>>(      \
                full_path, std::forward<_Func>(func), _priority)); \
        _router.sort_routes(static_cast<http_method>(num));        \
        return *this;                                              \
    }

    HTTP_SERVER_METHOD_MAP(REGISTER_GROUP_ROUTE_FUNCTION)

#undef REGISTER_GROUP_ROUTE_FUNCTION

    /**
     * @brief Add a middleware to this route group (legacy way)
     * @param middleware Middleware function to add
     * @return Reference to this group for chaining
     */
    RouteGroup &use(Middleware middleware) {
        _middleware.push_back(std::move(middleware));
        return *this;
    }
    
    /**
     * @brief Add a typed middleware to this route group
     * @param middleware Middleware to add
     * @return Reference to this group for chaining
     */
    RouteGroup &use(TypedMiddlewarePtr middleware) {
        // Lazily create the typed middleware chain if it doesn't exist
        if (!_typed_middleware_chain) {
            _typed_middleware_chain = std::make_shared<MiddlewareChain<Session, String>>();
        }
        
        // Add the middleware to the chain
        _typed_middleware_chain->add(std::move(middleware));
        
        // Register adapters for the middleware chain with the legacy system
        // For synchronous middleware
        use([chain = _typed_middleware_chain](Context& ctx) -> bool {
            auto result = chain->process(ctx);
            if (result.is_async()) {
                return true; // Continue to async handler
            }
            return !result.should_stop();
        });
        
        return *this;
    }
    
    /**
     * @brief Create and add a typed middleware to this route group
     * @tparam M Type of middleware to create
     * @tparam Args Types of arguments to construct the middleware
     * @param args Arguments to construct the middleware
     * @return Reference to this group for chaining
     */
    template <template<typename, typename> class M, typename... Args>
    RouteGroup &use(Args&&... args) {
        auto middleware = std::make_shared<M<Session, String>>(std::forward<Args>(args)...);
        return use(middleware);
    }

    /**
     * @brief Create a nested route group
     * @param prefix Sub-prefix for this group
     * @param priority Priority for routes in this group
     * @return The newly created route group
     */
    RouteGroup group(const String& subprefix, int priority = 0) {
        return _router.group(_prefix + subprefix, priority > 0 ? priority : _priority);
    }

    RouteGroup &set_priority(int priority) {
        _priority = priority;
        return *this;
    }

    const std::vector<Middleware> &middleware() const {
        return _middleware;
    }
    
    std::shared_ptr<MiddlewareChain<Session, String>> typed_middleware_chain() const {
        return _typed_middleware_chain;
    }
};

/**
 * @brief Controller base class for hierarchical routing
 */
template <typename Session, typename String = std::string>
class Controller {
protected:
    Router<Session, String> _router;
    std::string             _base_path;

public:
    using RouterType = Router<Session, String>;
    using Context    = RouterContext<Session, String>;

    explicit Controller(std::string base_path)
        : _base_path(std::move(base_path)) {}
    virtual ~Controller() = default;

    RouterType &
    router() {
        return _router;
    }
    const std::string &
    base_path() const {
        return _base_path;
    }

    /**
     * @brief Process a request using this controller
     *
     * @param session HTTP session
     * @param ctx Context to process
     * @return true if the request was processed successfully
     */
    bool
    process(std::shared_ptr<Session> session, Context &ctx) {
        // Process with this controller's router
        return _router.route_context(session, ctx);
    }
};

} // namespace qb::http

#if defined(_WIN32)
#define DELETE (0x00010000L)
#endif

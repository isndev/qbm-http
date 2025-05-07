#pragma once

#include <functional>
#include <memory>
#include <regex>
#include <string>
#include <vector>
#include <qb/json.h>
#include "../types.h"
#include "./path_parameters.h"
#include "./context.h"
#include "../middleware/middleware_interface.h"
#include "../middleware/middleware_chain.h"
#include "../request.h"
#include "../response.h"

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
 * @brief OpenAPI metadata for routes
 *
 * Stores OpenAPI/Swagger documentation information for a route.
 */
struct RouteMetadata {
    std::string summary;                 ///< Short summary of what the operation does
    std::string description;             ///< Verbose explanation of the operation
    std::vector<std::string> tags;       ///< Tags for API documentation control
    qb::json requestBody;                ///< Request body schema
    qb::json responses;                  ///< Response schemas
    qb::json parameters;                 ///< Additional parameters (query, header, etc.)
    bool deprecated = false;             ///< Whether the operation is deprecated
    
    /**
     * @brief Set route summary
     * @param text Summary text
     * @return Reference to this metadata object
     */
    RouteMetadata& withSummary(const std::string& text) {
        summary = text;
        return *this;
    }
    
    /**
     * @brief Set route description
     * @param text Description text
     * @return Reference to this metadata object
     */
    RouteMetadata& withDescription(const std::string& text) {
        description = text;
        return *this;
    }
    
    /**
     * @brief Set request body schema
     * @param schema JSON schema for the request body
     * @param required Whether the request body is required
     * @param contentType Content type (default: application/json)
     * @return Reference to this metadata object
     */
    RouteMetadata& withRequestBody(const qb::json& schema, bool required = true, 
                                 const std::string& contentType = "application/json") {
        requestBody = {
            {"description", "Request body"},
            {"required", required},
            {"content", {
                {contentType, {
                    {"schema", schema}
                }}
            }}
        };
        return *this;
    }
    
    /**
     * @brief Add response schema for a status code
     * @param statusCode HTTP status code
     * @param description Response description
     * @param schema JSON schema for the response (optional)
     * @param contentType Content type (default: application/json)
     * @return Reference to this metadata object
     */
    RouteMetadata& withResponse(int statusCode, const std::string& description, 
                              const qb::json& schema = qb::json::object(),
                              const std::string& contentType = "application/json") {
        if (!responses.is_object()) {
            responses = qb::json::object();
        }
        
        qb::json response = {{"description", description}};
        if (!schema.is_null() && !schema.empty()) {
            response["content"] = {
                {contentType, {
                    {"schema", schema}
                }}
            };
        }
        
        responses[std::to_string(statusCode)] = response;
        return *this;
    }
    
    /**
     * @brief Add a query parameter
     * @param name Parameter name
     * @param description Parameter description
     * @param schema Parameter schema
     * @param required Whether the parameter is required
     * @return Reference to this metadata object
     */
    RouteMetadata& withQueryParam(const std::string& name, const std::string& description,
                                const qb::json& schema = {{"type", "string"}}, 
                                bool required = false) {
        if (!parameters.is_array()) {
            parameters = qb::json::array();
        }
        
        parameters.push_back({
            {"name", name},
            {"in", "query"},
            {"description", description},
            {"required", required},
            {"schema", schema}
        });
        
        return *this;
    }
    
    /**
     * @brief Add a header parameter
     * @param name Parameter name
     * @param description Parameter description
     * @param schema Parameter schema
     * @param required Whether the parameter is required
     * @return Reference to this metadata object
     */
    RouteMetadata& withHeaderParam(const std::string& name, const std::string& description,
                                 const qb::json& schema = {{"type", "string"}}, 
                                 bool required = false) {
        if (!parameters.is_array()) {
            parameters = qb::json::array();
        }
        
        parameters.push_back({
            {"name", name},
            {"in", "header"},
            {"description", description},
            {"required", required},
            {"schema", schema}
        });
        
        return *this;
    }
    
    /**
     * @brief Add a tag to the route
     * @param tag Tag name
     * @return Reference to this metadata object
     */
    RouteMetadata& withTag(const std::string& tag) {
        if (std::find(tags.begin(), tags.end(), tag) == tags.end()) {
            tags.push_back(tag);
        }
        return *this;
    }
    
    /**
     * @brief Add multiple tags to the route
     * @param newTags Tags to add
     * @return Reference to this metadata object
     */
    RouteMetadata& withTags(const std::vector<std::string>& newTags) {
        for (const auto& tag : newTags) {
            withTag(tag);
        }
        return *this;
    }
    
    /**
     * @brief Mark the route as deprecated
     * @param value Whether the route is deprecated
     * @return Reference to this metadata object
     */
    RouteMetadata& isDeprecated(bool value = true) {
        deprecated = value;
        return *this;
    }
};

/**
 * @brief Base class for routes
 */
template <typename Session, typename String = std::string>
class IRoute {
public:
    using Context = RouterContext<Session, String>;

    virtual ~IRoute() = default;
    virtual void process(Context &ctx) = 0;
    
    /**
     * @brief Get the route priority
     * @return Priority value
     */
    virtual int priority() const {
        return 0;
    }
    
    /**
     * @brief Get the route path
     * @return Route path string
     */
    virtual std::string getPath() const {
        return "";
    }
    
    /**
     * @brief Get the route's OpenAPI metadata
     * @return Reference to metadata object
     */
    virtual const RouteMetadata& getMetadata() const {
        static RouteMetadata empty_metadata;
        return empty_metadata;
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
    RouteMetadata            _metadata;  // Added OpenAPI metadata

    void
    compile_pattern() {
        std::string pattern = _path;
        std::regex param_regex(":([^/]+)");
        std::smatch matches;
        std::string::const_iterator start = pattern.begin();
        std::string::const_iterator end = pattern.end();
        
        // Process all parameter placeholders
        while (std::regex_search(start, end, matches, param_regex)) {
            _param_names.push_back(matches[1].str());
            
            // Calculate the current position and length
            size_t match_pos = matches[0].first - pattern.begin();
            size_t match_len = matches[0].length();
            
            // Replace the pattern with a regex capture group
            pattern.replace(match_pos, match_len, "([^/]+)");
            
            // Set up iterators for the next search
            start = pattern.begin();
            end = pattern.end();
            
            // Advance the start iterator to just after the replacement
            start += match_pos + 7; // Skip the inserted "([^/]+)"
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
    
    /**
     * @brief Get the route path (override from IRoute)
     * @return Route path string
     */
    std::string getPath() const override {
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

    /**
     * @brief Get the route's OpenAPI metadata
     * @return Reference to metadata object
     */
    RouteMetadata& metadata() {
        return _metadata;
    }
    
    /**
     * @brief Get the route's OpenAPI metadata (const)
     * @return Const reference to metadata object
     */
    const RouteMetadata& getMetadata() const override {
        return _metadata;
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
    std::string _openapi_tag; // OpenAPI tag for this group
    std::vector<std::shared_ptr<RouteGroup>> _sub_groups;   // Store sub-groups for OpenAPI introspection
    RouteMetadata _metadata; // Added metadata for the group

    // Store routes for each HTTP method for OpenAPI introspection
    qb::unordered_map<http_method, std::vector<std::shared_ptr<IRoute<Session, String>>>> _routes;

public:
    using RouterType = Router<Session, String>;
    using Context = RouterContext<Session, String>;
    using Middleware = typename RouterType::Middleware;
    using Handler = typename RouterType::Middleware;
    using TypedMiddlewarePtr = MiddlewarePtr<Session, String>;
    using IRoutePtr = std::shared_ptr<IRoute<Session, String>>;

    RouteGroup(RouterType &router, std::string prefix, int priority = 0)
        : _router(router)
        , _prefix(std::move(prefix))
        , _priority(priority) {}

#define REGISTER_GROUP_ROUTE_FUNCTION(num, name, description)      \
    template <typename _Func>                                      \
    RouteGroup &name(std::string const &path, _Func &&func) {      \
        std::string full_path = _prefix + path;                    \
        auto route_ptr = std::make_shared<TRoute<Session, String, _Func>>(      \
                full_path, std::forward<_Func>(func), _priority);  \
        _router._routes[static_cast<http_method>(num)].push_back(  \
            std::unique_ptr<IRoute<Session, String>>(new TRoute<Session, String, _Func>(      \
                full_path, std::forward<_Func>(func), _priority))); \
        /* Store route for OpenAPI introspection */                \
        _routes[static_cast<http_method>(num)].push_back(route_ptr); \
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
     * @param subprefix Sub-prefix for this group
     * @param priority Priority for routes in this group
     * @return Reference to the newly created route group
     */
    RouteGroup& group(const String& subprefix, int priority = 0) {
        // Use Router's group() method which now stores pointers in a stable container
        auto& new_group = _router.group(_prefix + subprefix, priority > 0 ? priority : _priority);
        
        // Create an entry in the group hierarchy to maintain parent-child relationship
        auto* group_ptr = &new_group;
        if (_router._group_hierarchy.find(this) != _router._group_hierarchy.end()) {
            _router._group_hierarchy[this].push_back(group_ptr);
        }
        
        // Maintain _sub_groups only for API compatibility
        // Store a non-owning pointer wrapped in a shared_ptr with empty deleter
        for (const auto& existing : _sub_groups) {
            if (existing.get() == group_ptr) {
                return new_group; // Group already exists in our list
            }
        }
        _sub_groups.push_back(std::shared_ptr<RouteGroup>(std::shared_ptr<RouteGroup>{}, &new_group));
        
        return new_group;
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

    /**
     * @brief Get the route group prefix
     * @return Prefix string
     */
    const std::string& getPrefix() const {
        return _prefix;
    }

    /**
     * @brief Set OpenAPI tag for this route group
     * @param tag Tag name
     * @return Reference to this group
     */
    RouteGroup& withOpenApiTag(const std::string& tag) {
        _openapi_tag = tag;
        return *this;
    }

    /**
     * @brief Get the OpenAPI tag for this group
     * @return Tag name or empty string if not set
     */
    const std::string& getOpenApiTag() const {
        return _openapi_tag;
    }
    
    /**
     * @brief Get the route group's metadata
     * @return Reference to metadata object
     */
    RouteMetadata& metadata() {
        return _metadata;
    }
    
    /**
     * @brief Get the route group's metadata (const)
     * @return Const reference to metadata object
     */
    const RouteMetadata& getMetadata() const {
        return _metadata;
    }
    
    /**
     * @brief Set route summary
     * @param text Summary text
     * @return Reference to this group
     */
    RouteGroup& withSummary(const std::string& text) {
        _metadata.withSummary(text);
        return *this;
    }
    
    /**
     * @brief Set route description
     * @param text Description text
     * @return Reference to this group
     */
    RouteGroup& withDescription(const std::string& text) {
        _metadata.withDescription(text);
        return *this;
    }
    
    /**
     * @brief Add a tag to the group
     * @param tag Tag name
     * @return Reference to this group
     */
    RouteGroup& withTag(const std::string& tag) {
        _metadata.withTag(tag);
        return *this;
    }
    
    /**
     * @brief All routes get all tags in this group
     * @param tags Tags to add to all routes
     * @return Reference to this group
     */
    RouteGroup& withTags(const std::vector<std::string>& tags) {
        _metadata.withTags(tags);
        return *this;
    }
    
    /**
     * @brief Get all routes for a specific HTTP method
     * @param method The HTTP method
     * @return Vector of routes
     */
    const std::vector<IRoutePtr>& getRoutes(http_method method) const {
        static const std::vector<IRoutePtr> empty;
        auto it = _routes.find(method);
        return it != _routes.end() ? it->second : empty;
    }
    
    /**
     * @brief Get all nested sub-groups
     * @return Vector of sub-groups
     */
    const std::vector<std::shared_ptr<RouteGroup>>& getSubGroups() const {
        return _sub_groups;
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
    std::string _openapi_tag; // OpenAPI tag for this controller
    RouteMetadata _metadata; // Added metadata for the controller

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
    
    const RouterType &
    router() const {
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

    /**
     * @brief Set OpenAPI tag for this controller
     * @param tag Tag name
     * @return Reference to this controller
     */
    Controller& withOpenApiTag(const std::string& tag) {
        _openapi_tag = tag;
        return *this;
    }

    /**
     * @brief Get the OpenAPI tag for this controller
     * @return Tag name or empty string if not set
     */
    const std::string& getOpenApiTag() const {
        return _openapi_tag;
    }
    
    /**
     * @brief Get the controller's metadata
     * @return Reference to metadata object
     */
    RouteMetadata& metadata() {
        return _metadata;
    }
    
    /**
     * @brief Get the controller's metadata (const)
     * @return Const reference to metadata object
     */
    const RouteMetadata& getMetadata() const {
        return _metadata;
    }
    
    /**
     * @brief Set route summary
     * @param text Summary text
     * @return Reference to this controller
     */
    Controller& withSummary(const std::string& text) {
        _metadata.withSummary(text);
        return *this;
    }
    
    /**
     * @brief Set route description
     * @param text Description text
     * @return Reference to this controller
     */
    Controller& withDescription(const std::string& text) {
        _metadata.withDescription(text);
        return *this;
    }
    
    /**
     * @brief Add a tag to the controller
     * @param tag Tag name
     * @return Reference to this controller
     */
    Controller& withTag(const std::string& tag) {
        _metadata.withTag(tag);
        return *this;
    }
    
    /**
     * @brief All routes get all tags in this controller
     * @param tags Tags to add to all routes
     * @return Reference to this controller
     */
    Controller& withTags(const std::vector<std::string>& tags) {
        _metadata.withTags(tags);
        return *this;
    }
};

} // namespace qb::http

#if defined(_WIN32)
#define DELETE (0x00010000L)
#endif

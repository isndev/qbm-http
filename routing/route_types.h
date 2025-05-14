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
    std::string summary;                 ///< Short summary of what the operation does.
    std::string description;             ///< Verbose explanation of the operation.
    std::vector<std::string> tags;       ///< Tags for API documentation control (e.g., for grouping in Swagger UI).
    qb::json requestBody;                ///< OpenAPI schema for the request body.
    qb::json responses;                  ///< OpenAPI schemas for various HTTP responses.
    qb::json parameters;                 ///< OpenAPI schemas for parameters (e.g., query, header, path).
    bool deprecated = false;             ///< Whether the operation is marked as deprecated.
    
    /**
     * @brief Sets the summary for the route metadata.
     * @param text The summary text.
     * @return Reference to this RouteMetadata object for chaining.
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
     * @brief Sets the request body schema for the route metadata.
     * @param schema The JSON schema describing the request body.
     * @param required Indicates if the request body is required. Defaults to true.
     * @param content_type The content type of the request body. Defaults to "application/json".
     * @return Reference to this RouteMetadata object for chaining.
     */
    RouteMetadata& withRequestBody(const qb::json& schema, bool required = true, 
                                 const std::string& content_type = "application/json") {
        requestBody = {
            {"description", "Request body"},
            {"required", required},
            {"content", {
                {content_type, {
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
     * @param content_type Content type (default: application/json)
     * @return Reference to this metadata object
     */
    RouteMetadata& withResponse(int statusCode, const std::string& description, 
                              const qb::json& schema = qb::json::object(),
                              const std::string& content_type = "application/json") {
        if (!responses.is_object()) {
            responses = qb::json::object();
        }
        
        qb::json response = {{"description", description}};
        if (!schema.is_null() && !schema.empty()) {
            response["content"] = {
                {content_type, {
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
     * @param new_tags Tags to add
     * @return Reference to this metadata object
     */
    RouteMetadata& withTags(const std::vector<std::string>& new_tags) {
        for (const auto& tag : new_tags) {
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
 * @brief Interface (base class) for all route types.
 *
 * Defines the common contract for routes, including processing a request,
 * and providing priority, path, and metadata information.
 *
 * @tparam Session The session type used by the router.
 * @tparam String The string type (e.g., std::string) used for paths and parameters.
 */
template <typename Session, typename String = std::string>
class IRoute {
public:
    using Context = RouterContext<Session, String>; ///< Alias for the router's context type.

    virtual ~IRoute() = default;

    /**
     * @brief Processes an HTTP request using this route's logic.
     * This is the core method called by the router when a route matches.
     * @param ctx The RouterContext associated with the current request.
     */
    virtual void process(Context &ctx) = 0;
    
    /**
     * @brief Gets the priority of this route.
     * Higher values typically indicate higher precedence in matching.
     * @return The priority value (default is 0).
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
        static RouteMetadata empty_metadata; // A default empty metadata object
        return empty_metadata;
    }
};

/**
 * @brief Abstract base route class providing regex-based path pattern matching
 *        and parameter extraction capabilities.
 *
 * It handles compiling a path string (e.g., "/users/:id") into a regex pattern
 * and extracting named parameters from matching URLs.
 *
 * @tparam Session The session type.
 * @tparam String The string type for paths.
 */
template <typename Session, typename String = std::string>
class ARoute : public IRoute<Session, String> {
protected:
    std::string              _path;          ///< The original path string for this route (e.g., "/users/:id").
    std::regex               _pattern;       ///< The compiled regex pattern derived from _path.
    std::vector<std::string> _param_names;   ///< Names of parameters extracted from the path (e.g., {"id"}).
    PathParameters           _parameters;    ///< Stores extracted path parameters for the last match.
    int                      _priority{0};   ///< Priority of this route.
    RouteMetadata            _metadata;      ///< OpenAPI metadata associated with this route.

    /**
     * @brief Compiles the route's path string into a regex pattern.
     * Replaces segments like ":paramName" with regex capture groups "([^/]+)"
     * and stores the parameter names in _param_names.
     */
    void
    compile_pattern() {
        // AMÉLIORATION WORKFLOW POINT 4: Cohérence Radix/Regex
        // S'assurer que la logique de remplacement des placeholders de paramètres (ex: ":id" par "([^/]+)")
        // et la capture des noms de paramètres (_param_names) sont cohérentes avec RadixNode::insert.
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
    using Context = typename IRoute<Session, String>::Context; ///< Alias for the router's context type.

    /**
     * @brief Constructs an ARoute with a given path and optional priority.
     * @param path The path string for the route.
     * @param priority The priority of the route (default 0).
     */
    explicit ARoute(std::string path, int priority = 0)
        : _path(std::move(path))
        , _priority(priority) {
        compile_pattern();
    }

    virtual ~ARoute() = default;

    /**
     * @brief Matches a given path string against the route's compiled regex pattern.
     * If a match occurs, populates the internal _parameters map.
     * @param path The path string to match.
     * @return True if the path matches, false otherwise.
     */
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

    /**
     * @brief Matches a given path string against the route's pattern and updates the context.
     * If a match occurs, populates the internal _parameters map and also updates
     * the `path_params` and `match` fields in the provided RouterContext.
     * @param ctx The RouterContext to update upon a successful match.
     * @param path The path string to match.
     * @return True if the path matches, false otherwise.
     */
    bool
    match(Context &ctx, const std::string &path) {
        // AMÉLIORATION WORKFLOW POINT 4: Cohérence Radix/Regex
        // S'assurer que la manière dont les paramètres sont extraits des 'matches' et stockés dans ctx.path_params
        // est cohérente avec la méthode RadixNode::match.
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
     * @brief Gets the original path string of this route.
     * Implements the IRoute interface.
     * @return The route path string.
     */
    std::string getPath() const override {
        return _path;
    }
    
    [[nodiscard]] PathParameters &
    parameters() {
        return _parameters;
    }
    
    /**
     * @brief Gets the priority of this route.
     * Implements the IRoute interface.
     * @return The priority value.
     */
    [[nodiscard]] int
    priority() const override {
        return _priority;
    }

    ARoute &
    set_priority(int new_priority) {
        _priority = new_priority;
        return *this;
    }

    /**
     * @brief Provides mutable access to the route's OpenAPI metadata.
     * @return Reference to the RouteMetadata object.
     */
    RouteMetadata& metadata() {
        return _metadata;
    }
    
    /**
     * @brief Provides const access to the route's OpenAPI metadata.
     * Implements the IRoute interface.
     * @return Const reference to the RouteMetadata object.
     */
    const RouteMetadata& getMetadata() const override {
        return _metadata;
    }
};

/**
 * @brief Route implementation that wraps a function-like handler (e.g., lambda).
 *
 * This class derives from ARoute to use its regex matching capabilities and
 * executes the provided function handler when the route is processed.
 *
 * @tparam Session The session type.
 * @tparam String The string type for paths.
 * @tparam Func The type of the function or callable object that handles the route.
 */
template <typename Session, typename String, typename Func>
class TRoute : public ARoute<Session, String> {
    Func _func; ///< The function handler for this route.

public:
    using Context = typename ARoute<Session, String>::Context; ///< Alias for the router's context type.

    /**
     * @brief Constructs a TRoute.
     * @param path The path string for the route.
     * @param func The function handler (rvalue reference, will be moved or copied).
     * @param priority The priority of the route (default 0).
     */
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
 * @brief Represents a group of routes that share a common path prefix and/or middleware.
 *
 * Route groups help in organizing routes and applying common settings or logic
 * to multiple related routes.
 *
 * @tparam Session The session type.
 * @tparam String The string type for paths.
 */
template <typename Session, typename String = std::string>
class RouteGroup {
    Router<Session, String>                                  &_router;      ///< Reference to the main router this group belongs to.
    std::string                                               _prefix;       ///< The common path prefix for all routes in this group.
    std::vector<typename Router<Session, String>::Middleware> _middleware;   ///< Legacy synchronous middleware specific to this group.
    std::shared_ptr<MiddlewareChain<Session, String>>         _typed_middleware_chain; ///< Typed middleware chain for this group.
    int                                                       _priority;     ///< Default priority for routes added to this group.
    std::string _openapi_tag; ///< Optional OpenAPI tag to apply to all routes in this group.
    std::vector<std::shared_ptr<RouteGroup>> _sub_groups;   ///< Stores sub-groups for OpenAPI introspection and hierarchical processing.
    RouteMetadata _metadata; ///< OpenAPI metadata specific to the group itself (e.g., for section documentation).

    // Stores routes added directly to this group, categorized by HTTP method, primarily for OpenAPI introspection.
    qb::unordered_map<http_method, std::vector<std::shared_ptr<IRoute<Session, String>>>> _routes;

public:
    using RouterType = Router<Session, String>; ///< Alias for the Router type.
    using Context = RouterContext<Session, String>;    ///< Alias for the Context type.
    using Middleware = typename RouterType::Middleware; ///< Alias for legacy synchronous middleware function type.
    using Handler = typename RouterType::Middleware;    ///< Alias for handler function type (same as Middleware).
    using TypedMiddlewarePtr = MiddlewarePtr<Session, String>; ///< Alias for a shared pointer to a typed middleware.
    using IRoutePtr = std::shared_ptr<IRoute<Session, String>>; ///< Alias for a shared pointer to an IRoute.

    /**
     * @brief Constructs a RouteGroup.
     * @param router Reference to the parent router.
     * @param prefix The path prefix for this group.
     * @param priority Default priority for routes in this group (default 0).
     */
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
     * @brief Adds a typed middleware (IMiddleware instance) to this route group's chain.
     * @param middleware A shared pointer to the typed middleware to add.
     * @return Reference to this group for chaining.
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

    RouteGroup &set_priority(int new_priority) {
        _priority = new_priority;
        return *this;
    }

    /**
     * @brief Gets the legacy synchronous middleware functions associated with this group.
     * @return Const reference to the vector of middleware functions.
     */
    const std::vector<Middleware> &middleware() const {
        return _middleware;
    }
    
    /**
     * @brief Gets the typed middleware chain associated with this group.
     * @return Shared pointer to the MiddlewareChain, or nullptr if none has been set up.
     */
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
    RouteGroup& withOpenApiTag(const std::string& tag_name) {
        _openapi_tag = tag_name;
        return *this;
    }

    /**
     * @brief Gets the OpenAPI tag defined for this group.
     * @return The OpenAPI tag string, or an empty string if not set.
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

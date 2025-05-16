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
#include "./logging_helpers.h"

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

    void merge(const RouteMetadata& other) {
        if (!other.summary.empty()) {
            withSummary(other.summary);
        }
        if (!other.description.empty()) {
            withDescription(other.description);
        }
        if (!other.requestBody.is_null() && !other.requestBody.empty()) {
            withRequestBody(other.requestBody);
        }
        
        // Properly handle the responses JSON
        if (!other.responses.is_null() && !other.responses.empty() && other.responses.is_object()) {
            // Iterate through all responses
            for (auto it = other.responses.begin(); it != other.responses.end(); ++it) {
                int status_code = std::stoi(it.key());
                
                // Get description
                std::string description = "Response";
                if (it.value().contains("description") && it.value()["description"].is_string()) {
                    description = it.value()["description"].get<std::string>();
                }
                
                // Get schema and content type if available
                qb::json schema = qb::json::object();
                std::string content_type = "application/json";
                
                if (it.value().contains("content") && it.value()["content"].is_object() && !it.value()["content"].empty()) {
                    auto content_it = it.value()["content"].begin();
                    content_type = content_it.key();
                    
                    if (content_it.value().contains("schema")) {
                        schema = content_it.value()["schema"];
                    }
                }
                
                withResponse(status_code, description, schema, content_type);
            }
        }
        
        // Handle parameters
        if (!other.parameters.is_null() && !other.parameters.is_array() && !other.parameters.empty()) {
            for (const auto& param : other.parameters) {
                if (param.contains("name") && param.contains("description")) {
                    std::string name = param["name"].get<std::string>();
                    std::string description = param["description"].get<std::string>();
                    
                    qb::json schema = param.contains("schema") ? param["schema"] : qb::json({{"type", "string"}});
                    bool required = param.contains("required") ? param["required"].get<bool>() : false;
                    
                    if (param.contains("in") && param["in"].get<std::string>() == "header") {
                        withHeaderParam(name, description, schema, required);
                    } else {
                        withQueryParam(name, description, schema, required);
                    }
                }
            }
        }
        
        if (!other.tags.empty()) {
            withTags(other.tags);
        }
        if (other.deprecated) {
            isDeprecated();
        }
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
    // std::regex               _pattern;       ///< The compiled regex pattern derived from _path.
    // std::vector<std::string> _param_names;   ///< Names of parameters extracted from the path (e.g., {"id"}).
    PathParameters           _parameters;    ///< Stores extracted path parameters for the last match.
    int                      _priority{0};   ///< Priority of this route.
    RouteMetadata            _metadata;      ///< OpenAPI metadata associated with this route.

    /* // REMOVE/COMMENT OUT compile_pattern
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
    */

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
        // compile_pattern(); // REMOVE/COMMENT OUT appel
    }

    virtual ~ARoute() = default;

    /* // REMOVE/COMMENT OUT match(const std::string &path)
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
    */

    /* // REMOVE/COMMENT OUT match(Context &ctx, const std::string &path)
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
    */

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
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[TRoute::process ENTRY] Path: " + this->getPath() + ", CtxState@: " + utility::pointer_to_string_for_log(ctx._state.get()) + ", CtxStage: " + utility::to_string_for_log(ctx.get_processing_stage()) );
        }

        RequestProcessingStage entry_stage = ctx.get_processing_stage();
        if (entry_stage == RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[TRoute::process] Invoked on already completed context for path: " + this->getPath() + ". Stage: " + utility::to_string_for_log(entry_stage) + ". Skipping further TRoute processing.");
            }
            return;
        }

        // Also check if this handler was already executed to prevent duplicate executions
        std::string route_execution_key = "__route_executed_" + this->getPath();
        if (ctx.has(route_execution_key)) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[TRoute::process] Handler for path: " + this->getPath() + " was already executed. Skipping duplicate execution.");
            }
            return;
        }
        
        // Mark this handler as executed
        ctx.set(route_execution_key, true);

        ctx.clear_handler_initiated_async_flag(); // Clear any stale flag before handler call
        bool was_async_before_handler = ctx.is_async(); // Check before _func
        
        // Store the original context parameters to restore if the handler doesn't modify them
        // This helps with parameter inheritance through middleware and nested groups
        auto original_params = ctx.path_params;

        // Ensure all path parameters from ARoute are merged with context's parameters
        // This is crucial for correct parameter passing to handlers
        for (const auto& p : this->_parameters) {
            ctx.path_params[p.first] = p.second;
        }
        
        // If the route path uses parameters pattern (e.g., /users/:id), extract them from match
        if (this->getPath().find(':') != std::string::npos || this->getPath().find('{') != std::string::npos) {
            // Extract parameters from the actual path pattern and match
            auto match_result = RadixTree::extract_params_from_path_pattern(this->getPath(), ctx.request.uri().path());
            if (match_result && !match_result->params.empty()) {
                for (const auto& p : match_result->params) {
                    ctx.path_params[p.first] = p.second;
                }
            }
        }

        // Log initial state before handler call
        bool initial_async_state_before_handler_call = ctx.is_async();
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
             adv_test_mw_middleware_execution_log.push_back(
                "[TRoute::process] BEFORE _func(ctx) for path: " + this->getPath() +
                ", CtxState@: " + (ctx._state ? utility::pointer_to_string_for_log(ctx._state.get()) : "NULL") +
                ", CtxStage: " + utility::to_string_for_log(ctx.get_processing_stage()) +
                ", Path params count: " + std::to_string(ctx.path_params.size())
             );
        }

        // Log path parameters before calling handler
        if (adv_test_mw_middleware_execution_log.size() < 2000 && !ctx.path_params.empty()) {
            std::string params_str = "Path parameters for handler: ";
            for (const auto& param : ctx.path_params) {
                params_str += param.first + "=" + param.second + " ";
            }
            adv_test_mw_middleware_execution_log.push_back("[TRoute::process] " + params_str);
        }

        try {
            _func(ctx); // Execute the handler lambda
        } catch (const std::bad_any_cast& e) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[TRoute::process] EXCEPTION std::bad_any_cast from _func(ctx) for path: " + this->getPath() + ": " + e.what());
            }
            ctx.status(HTTP_STATUS_INTERNAL_SERVER_ERROR).body("Handler exception: bad_any_cast: " + std::string(e.what()));
            ctx.mark_handled();
            if (!ctx.has("_completed")) { ctx.complete(); }
            return;
        } catch (const std::exception& e) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[TRoute::process] EXCEPTION std::exception from _func(ctx) for path: " + this->getPath() + ": " + e.what());
            }
            ctx.status(HTTP_STATUS_INTERNAL_SERVER_ERROR).body("Handler exception: " + std::string(e.what()));
            ctx.mark_handled();
            if (!ctx.has("_completed")) { ctx.complete(); }
            return; 
        } catch (...) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[TRoute::process] UNKNOWN EXCEPTION from _func(ctx) for path: " + this->getPath());
            }
            ctx.status(HTTP_STATUS_INTERNAL_SERVER_ERROR).body("Unknown handler exception");
            ctx.mark_handled();
            if (!ctx.has("_completed")) { ctx.complete(); }
            return;
        }

        // Log current state after handler call
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
             adv_test_mw_middleware_execution_log.push_back(
                "[TRoute::process] AFTER _func(ctx) for path: " + this->getPath() +
                ", CtxState@: " + (ctx._state ? utility::pointer_to_string_for_log(ctx._state.get()) : "NULL") +
                ", CtxStage: " + utility::to_string_for_log(ctx.get_processing_stage()) +
                ", Handler Response Status: " + std::to_string(ctx.response.status_code) +
                ", ctx.is_async() after handler: " + utility::bool_to_string(ctx.is_async()) +
                ", ctx.handler_initiated_async(): " + utility::bool_to_string(ctx.handler_initiated_async())
             );
        }

        // Ensure parameters from the route context are preserved
        // Merge any new parameters set by the handler with the original ones
        for (const auto& [key, value] : original_params) {
            if (ctx.path_params.find(key) == ctx.path_params.end()) {
                ctx.path_params[key] = value;
            }
        }

        // If the handler itself marked the context as asynchronous by calling make_async(), TRoute should yield.
        if (ctx.handler_initiated_async()) { 
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back(
                    "[TRoute::process] Handler for path '" + this->getPath() +
                    "' INITIATED ASYNC (via make_async). TRoute yielding to AsyncCompletionHandler. CtxState@" +
                    (ctx._state ? utility::pointer_to_string_for_log(ctx._state.get()) : "NULL")
                );
            }
            // The AsyncCompletionHandler obtained via ctx.make_async() is now responsible for ctx.complete().
            // TRoute should not call ctx.complete() or modify response status further.
            return; // CRITICAL: Ensure this return is effective.
        }
        
        // At this point, the handler _func(ctx) itself has completed synchronously.
        // If it called ctx.make_async(), then ctx.handler_initiated_async() would be true, and we would have returned above.
        
        // If the context was marked async due to a *prior* middleware, 
        // but this handler ran synchronously, we should clear the overarching async state.
        if (was_async_before_handler) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back(
                    "[TRoute::process] SYNC handler ('" + this->getPath() +
                    "') completed after an async middleware chain (was_async_before_handler=true). Clearing broader async state."
                );
            }
            ctx.clear_async_state_for_chain_completion(); // This sets _state->is_async = false
        }
        
        // Now, ctx.is_async() should be false, as this path is for synchronous completion by TRoute.
        // The old check for `initial_async_state_before_handler_call && !ctx.is_async()` is covered by the logic above.

        // If the request is not handled by the handler itself, set a default status.
        if (!ctx.is_handled()) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back(
                    "[TRoute::process] Handler for " + this->getPath() +
                    " did not explicitly mark as handled and is not async. Setting default status 200 OK."
                );
            }
            ctx.status(HTTP_STATUS_OK);
            ctx.mark_handled();
        }

        // Final completion check:
        // Only complete if it hasn't been completed yet (e.g. by the handler calling ctx.complete() itself,
        // or if it's an async handler which we returned from above).
        if (!ctx.has("_completed")) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back(
                    "[TRoute::process] TRoute completing request for path: " + this->getPath() +
                    " with status " + std::to_string(ctx.response.status_code) +
                    ". CtxState@" + (ctx._state ? utility::pointer_to_string_for_log(ctx._state.get()) : "NULL")
                );
            }
            ctx.complete(); // This will send the response via the session
        } else {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                 adv_test_mw_middleware_execution_log.push_back(
                    "[TRoute::process] Request for path: " + this->getPath() +
                    " was already marked _completed. TRoute not calling complete() again. CtxState@" +
                    (ctx._state ? utility::pointer_to_string_for_log(ctx._state.get()) : "NULL")
                );
            }
        }
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
        , _priority(priority) {
        
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[RouteGroup CONSTRUCTOR] Created group with prefix: " + _prefix + 
                                                     ", ptr: " + utility::pointer_to_string_for_log(this));
        }
    }

#define REGISTER_GROUP_ROUTE_FUNCTION(num, name, description)                      \
    template <typename _Func>                                                      \
    RouteGroup &name(std::string const &path, _Func &&func) {                      \
        std::string full_path = _prefix + path;                                    \
        http_method method = static_cast<http_method>(num);                        \
                                                                                   \
        /* Create route with shared_ptr for our local collection */                \
        auto route_ptr = std::make_shared<TRoute<Session, String, _Func>>(         \
            full_path, std::forward<_Func>(func), _priority);                      \
                                                                                   \
        /* Store in this group's routes collection for introspection */            \
        _routes[method].push_back(route_ptr);                                      \
                                                                                   \
        /* Add to router's routes collection (which uses unique_ptr) */            \
        _router._routes[method].push_back(                                         \
            std::make_unique<TRoute<Session, String, _Func>>(                      \
                full_path, std::forward<_Func>(func), _priority));                 \
                                                                                   \
        /* Also add to router's radix tree */                                      \
        if (_router._radix_routes.find(method) == _router._radix_routes.end()) {   \
            _router._radix_routes[method] = RadixTree();                           \
        }                                                                          \
                                                                                   \
        /* Get the route we just added to the router */                            \
        using Route = ARoute<Session, String>;                                     \
        Route *ar = dynamic_cast<Route *>(_router._routes[method].back().get());   \
        if (ar) {                                                                  \
            _router._radix_routes[method].insert(ar->path(),                       \
                                              static_cast<void*>(ar),              \
                                              ar->priority(),                       \
                                              RadixMatchResult::TargetType::HANDLER); \
        }                                                                          \
                                                                                   \
        /* Log route registration */                                               \
        if (adv_test_mw_middleware_execution_log.size() < 2000) {                  \
            adv_test_mw_middleware_execution_log.push_back("REGISTER_GROUP_ROUTE: " + _prefix + " + " + path + " = " + full_path + " (method: " + std::to_string(static_cast<int>(method)) + ")"); \
        }                                                                          \
                                                                                   \
        /* Rebuild RadixTree to include the new route */                           \
        _router.build_radix_trees();                                               \
                                                                                   \
        return *this;                                                              \
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
        // Ensure the subprefix starts with a slash if needed
        std::string normalized_subprefix = subprefix;
        if (!normalized_subprefix.empty() && normalized_subprefix[0] != '/' && _prefix.back() != '/') {
            normalized_subprefix = '/' + normalized_subprefix;
        }
        
        // Calculate the full path for the new group
        std::string full_prefix = _prefix + normalized_subprefix;
        
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[RouteGroup::group] Creating subgroup with prefix: " + full_prefix + 
                                                        " (parent: " + _prefix + ", sub: " + normalized_subprefix + ")");
        }
        
        // Use Router's group() method which now stores pointers in a stable container
        auto& new_group = _router.group(full_prefix, priority > 0 ? priority : _priority);
        
        // Create an entry in the group hierarchy to maintain parent-child relationship
        auto* group_ptr = &new_group;
        if (_router._group_hierarchy.find(this) != _router._group_hierarchy.end()) {
            _router._group_hierarchy[this].push_back(group_ptr);
        }
        
        // Register this group as the parent of the new group for better hierarchy tracking
        if (_router._group_hierarchy.find(group_ptr) == _router._group_hierarchy.end()) {
            _router._group_hierarchy[group_ptr] = std::vector<RouteGroup*>();
        }
        
        // Transfer middleware to the child group if option enabled
        // By default, middleware from parent groups should be inherited
        if (!new_group.typed_middleware_chain() && _typed_middleware_chain) {
            // Create a new middleware chain for the child group
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[RouteGroup::group] Transferring typed middleware from parent group to child");
            }
            auto new_chain = std::make_shared<MiddlewareChain<Session, String>>();
            
            // Copy each middleware from parent to child
            for (const auto& mw : _typed_middleware_chain->get_middleware()) {
                new_chain->add(mw);
            }
            
            // Set the new chain on the child group
            new_group._typed_middleware_chain = new_chain;
        }
        
        // Transfer legacy middleware as well
        for (const auto& legacy_mw : _middleware) {
            new_group._middleware.push_back(legacy_mw);
        }
        
        // Transfer metadata properties like tags
        if (!_openapi_tag.empty()) {
            new_group._openapi_tag = _openapi_tag;
        }
        
        // Transfer metadata from parent to child
        new_group._metadata.merge(_metadata);
        
        // Store reference to the sub-group for introspection
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
     * @param path_for_controller_router Path for the controller's router
     * @return true if the request was processed successfully
     */
    bool
    process(std::shared_ptr<Session> session, Context &ctx, const std::string& path_for_controller_router) {
        std::string controller_ptr_str = utility::pointer_to_string_for_log(this);
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Controller@" + controller_ptr_str + "::process ENTRY] Base: " + _base_path + ", PathForMyRouter: " + path_for_controller_router + ", InitialCtxStage: " + utility::to_string_for_log(ctx.get_processing_stage()));
        }

        RequestProcessingStage stage_before_reset = ctx.get_processing_stage();
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Controller@" + controller_ptr_str + "::process] Stage before reset to INITIAL: " + utility::to_string_for_log(stage_before_reset));
        }

        // Extract and log parameters from the context before processing
        if (adv_test_mw_middleware_execution_log.size() < 2000 && !ctx.path_params.empty()) {
            std::string params_str = "Context parameters entering controller: ";
            for (const auto& param : ctx.path_params) {
                params_str += param.first + "=" + param.second + " ";
            }
            adv_test_mw_middleware_execution_log.push_back("[Controller@" + controller_ptr_str + "::process] " + params_str);
        }

        // Store a copy of the current parameters to ensure they're preserved
        PathParameters preserved_params = ctx.path_params;

        // Reset processing stage for the internal router chain
        ctx.set_processing_stage(RequestProcessingStage::INITIAL);
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Controller@" + controller_ptr_str + "::process] Stage AFTER reset to INITIAL: " + utility::to_string_for_log(ctx.get_processing_stage()));
            adv_test_mw_middleware_execution_log.push_back("[Controller@" + controller_ptr_str + "::process] Calling internal router _router.route_context(). ReqPath for internal router: " + path_for_controller_router + ", CtxStage: " + utility::to_string_for_log(ctx.get_processing_stage()));
        }
        
        // Stocker le path relatif que ce contrôleur doit utiliser pour son routeur interne
        // pour que les appels récursifs à route_context (via run_async_middleware_chain)
        // puissent le retrouver et l'utiliser.
        std::string internal_router_scope_key = "__internal_router_path_scope_" + utility::pointer_to_string_for_log(&_router);
        ctx.set(internal_router_scope_key, path_for_controller_router);

        // Merge preserved parameters back into the context to ensure they're available
        // to all middleware and handlers in the controller's router chain
        for (const auto& param : preserved_params) {
            if (ctx.path_params.find(param.first) == ctx.path_params.end()) {
                ctx.path_params[param.first] = param.second;
            }
        }

        bool internal_router_result = _router.route_context(session, ctx); 
        
        // ctx.remove(internal_router_scope_key); // Temporarily comment out to see if it helps with re-entrant calls

        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Controller@" + controller_ptr_str + "::process] Returned from internal router _router.route_context(). Result: " + utility::bool_to_string(internal_router_result) + ", CtxStage: " + utility::to_string_for_log(ctx.get_processing_stage()));
            adv_test_mw_middleware_execution_log.push_back("[Controller@" + controller_ptr_str + "::process EXIT] Base: " + _base_path + ". Final CtxStage: " + utility::to_string_for_log(ctx.get_processing_stage()));
        }
        return internal_router_result;
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



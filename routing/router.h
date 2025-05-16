#pragma once

#include <any>
#include <chrono>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>
#include <qb/uuid.h>

#include "../types.h"
#include "../request.h"
#include "../response.h"
#include "./async_completion_handler.h"
#include "./async_types.h"
#include "./context.h"
#include "./path_parameters.h"
#include "./radix_tree.h"
#include "./route_types.h"
#include "../middleware/middleware_interface.h"
#include "../middleware/middleware_chain.h"
// #include "../request_path_view.h"

#if defined(_WIN32)
#undef DELETE // Windows :/
#endif

namespace qb::http {

// Prédéclaration pour permettre l'amitié
template <typename Session, typename String>
class RouterImpl;

/**
 * @brief HTTP Router for handling incoming requests, managing routes, middleware, and controllers.
 *
 * This class is the core of the HTTP routing system. It provides methods for:
 * - Registering route handlers for different HTTP methods and path patterns.
 * - Organizing routes into groups with shared prefixes and middleware.
 * - Integrating modular controllers for hierarchical routing.
 * - Applying global and route-specific middleware (both synchronous and asynchronous).
 * - Managing the lifecycle of asynchronous requests, including timeouts and cancellations.
 * - Optionally using a Radix Tree for high-performance route matching, with a fallback to regex-based matching.
 *
 * @tparam Session The type of the session object used to handle client connections (e.g., a TCP session).
 * @tparam String The string type used for paths, parameters, etc. (defaults to std::string).
 */
template <typename Session, typename String = std::string>
class Router {
public:
    // Friend declarations
    friend class AsyncCompletionHandler<Session, String>;
    friend class RouteGroup<Session, String>;
    friend class RouterImpl<Session, String>;

    // Type aliases for external types
    using Context    = RouterContext<Session, String>;
    using Route      = ARoute<Session, String>;
    using Controller = qb::http::Controller<Session, String>;
    using RouteGroup = qb::http::RouteGroup<Session, String>;
    using IRoute     = qb::http::IRoute<Session, String>;

    // Middleware type definitions
    using Middleware = std::function<bool(Context &)>; // Legacy Sync - REINTRODUCE for API
    using AsyncMiddleware = std::function<void(Context &, std::function<void(bool)>)>; // Legacy Async - REINTRODUCE for API
    using TypedMiddlewarePtr = MiddlewarePtr<Session, String>;

    // Template for route implementation
    template <typename Func>
    using TRoute = TRoute<Session, String, Func>;

    // Constructor and destructor
    Router();
    ~Router() = default;

#define REGISTER_ROUTE_FUNCTION(num, name, description)  \
    /** @brief Registers a ##description## route for the given path with a function handler. */ \
    template <typename _Func>                            \
    Router<Session, String> &name(std::string const &path, _Func &&func); \
    /** @brief Registers a ##description## route using a custom IRoute-derived class instance. */ \
    template <typename T, typename... Args>              \
    Router<Session, String> &name(Args &&...args);

    HTTP_SERVER_METHOD_MAP(REGISTER_ROUTE_FUNCTION)

#undef REGISTER_ROUTE_FUNCTION

    /**
     * @brief Registers a controller instance for hierarchical routing.
     * All routes defined within the controller will be prefixed by the controller's base path.
     * @tparam T The controller class type (must derive from qb::http::Controller).
     * @tparam Args Types of arguments to be forwarded to the controller's constructor.
     * @param args Arguments for the controller's constructor.
     */
    template <typename T, typename... Args>
    void controller(Args &&...args);

    /**
     * @brief Creates and registers a route group with a common path prefix.
     * Routes added to the returned group will inherit its prefix and middleware.
     * @param prefix The common path prefix for all routes in this group.
     * @param priority Default priority for routes added to this group (0 if not specified).
     * @return Reference to the newly created (or existing if prefix matches) RouteGroup object.
     */
    RouteGroup &group(const std::string &prefix, int priority = 0);

    /**
     * @brief Sets a default response to be sent if no other route matches for a specific HTTP method.
     * @param method The HTTP method for which to set the default response.
     * @param response The qb::http::Response object to use as the default.
     * @return Reference to this router for chaining.
     */
    Router<Session, String> &set_default_response(http_method method, Response response);

    /**
     * @brief Adds a global legacy synchronous middleware function.
     * These middlewares are executed in the order they are added, before any route-specific logic.
     * @param middleware The middleware function (std::function<bool(Context&)>).
     *                   It should return true to continue to the next middleware/handler, or false to stop processing.
     * @return Reference to this router for chaining.
     */
    Router<Session, String> &use(Middleware middleware); // REINTRODUCE

    /**
     * @brief Adds a global legacy asynchronous middleware function.
     * These are executed after synchronous global middlewares.
     * @param middleware The asynchronous middleware function (std::function<void(Context&, std::function<void(bool)>)>).
     *                   The inner callback should be called with true to continue, false to stop.
     * @return Reference to this router for chaining.
     */
    Router<Session, String> &use(AsyncMiddleware middleware); // REINTRODUCE

    /**
     * @brief Adds a global typed middleware (IMiddleware instance) to the router's chain.
     * Typed middlewares are generally preferred for new development due to better type safety and structure.
     * @param middleware A shared pointer to the typed middleware (IMiddlewarePtr).
     * @return Reference to this router for chaining.
     */
    Router<Session, String> &use(TypedMiddlewarePtr middleware);
    
    /**
     * @brief Creates and adds a global typed middleware to the router's chain by type.
     * @tparam M The middleware class template (e.g., MyMiddleware, expecting Session and String template arguments).
     * @tparam Args Types of arguments to construct the middleware.
     * @param args Arguments to forward to the middleware's constructor.
     * @return Reference to this router for chaining.
     */
    template <template<typename, typename> class M, typename... Args>
    Router<Session, String> &use(Args&&... args) {
        auto middleware_instance = std::make_shared<M<Session, String>>(std::forward<Args>(args)...);
        return use(std::move(middleware_instance));
    }

    /**
     * @brief Sets a custom error handler function for a specific HTTP status code.
     * If a response is set to this status code and no handler has fully managed the response,
     * this handler will be invoked.
     * @param status_code The HTTP status code to handle (e.g., 404, 500).
     * @param handler A function that takes a Context& and processes the error.
     * @return Reference to this router for chaining.
     */
    Router<Session, String> &on_error(int status_code, std::function<void(RouterContext<Session, String> &)> handler);

    /**
     * @brief Enables or disables request logging for this router instance.
     * @param enable True to enable logging, false to disable. Defaults to false.
     * @return Reference to this router for chaining.
     */
    Router<Session, String> &enable_logging(bool enable);

    /**
     * @brief Clears all registered global middleware functions (synchronous and asynchronous).
     * This does not affect middleware attached to specific route groups.
     * @return Reference to this router for chaining.
     */
    Router<Session, String> &clear_middleware() {
        if (_typed_middleware_chain) { 
            _typed_middleware_chain->clear(); 
        }
        return *this;
    }

    /**
     * @brief Configures the timeout duration for asynchronous requests managed by this router.
     * Requests exceeding this duration may be automatically cancelled.
     * @param timeout_seconds Timeout duration in seconds. A value of 0 or less typically disables timeout.
     * @return Reference to this router for chaining.
     */
    Router<Session, String> &configure_async_timeout(int timeout_seconds);

    /**
     * @brief Immediately forces a timeout for all currently active asynchronous requests.
     * This will attempt to send a timeout response for each.
     * @return The number of requests that were timed out by this call.
     */
    size_t force_timeout_all_requests();

    /**
     * @brief Get the number of active async requests
     * @return Number of active async requests
     */
    [[nodiscard]] size_t active_async_requests_count() const;

    /**
     * @brief Check if a request is still active
     * @param request_id Request ID to check
     * @return True if the request is active, false otherwise
     */
    [[nodiscard]] bool is_active_request(std::uintptr_t request_id) const;

    /**
     * @brief Clean up disconnected sessions
     * @return The number of disconnected sessions that were cleaned up
     */
    size_t clean_disconnected_sessions();

    /**
     * @brief Defer request processing for a specific duration
     * @param context_id Request context ID
     * @param delay_ms Delay in milliseconds
     * @param callback Function to call after the delay
     * @return True if scheduling succeeded, false otherwise
     */
    bool defer_request(std::uintptr_t context_id, int delay_ms,
                       std::function<void()> callback);

    /**
     * @brief Route a request to the appropriate handler
     * @param session HTTP session
     * @param request HTTP request to route
     * @return true if a route was matched and processed (or will be processed
     * asynchronously)
     */
    bool route(std::shared_ptr<Session> session, TRequest<String> routing_request);

    /**
     * @brief Route a context through this router
     * @param session HTTP session
     * @param ctx Context to route
     * @param context_ptr Shared pointer to the context for lifetime management
     * @return true if the request was matched and processed
     */
    bool route_context(std::shared_ptr<Session> session, Context &ctx,
                       std::shared_ptr<Context> context_ptr           = nullptr);

    /**
     * @brief Logs details of a processed request if logging is enabled.
     * @param ctx The RouterContext of the request to log.
     */
    void log_request(const Context &ctx);

    /**
     * @brief Logs details of a processed request with explicit status and duration.
     * For backward compatibility or specific logging needs.
     * @param ctx The RouterContext of the request.
     * @param status The HTTP status code of the response.
     * @param duration The processing duration in milliseconds.
     * @param note An optional additional note for the log entry.
     */
    void log_request(const Context &ctx, int status, double duration,
                     const std::string &note = "");

    /**
     * @brief Build radix trees for all HTTP methods
     * @return Reference to this router
     */
    Router<Session, String> &build_radix_trees();

    /**
     * @brief Clear all active async requests
     */
    void clear_all_active_requests();

    /**
     * @brief Configures the maximum number of concurrent requests the router will attempt to process.
     * Requests arriving when this limit is reached may receive an immediate "Too Many Requests" response.
     * @param max_requests The maximum number of concurrent requests.
     * @return Reference to this router for chaining.
     */
    Router<Session, String> &configure_max_concurrent_requests(size_t max_requests);

    /**
     * @brief Check if a request has been cancelled
     * @param request_id ID of the request to check
     * @return true if the request has been cancelled, false otherwise
     */
    bool is_request_cancelled(std::uintptr_t request_id) const;

    /**
     * @brief Cancel a request
     * @param request_id ID of the request to cancel
     * @return true if the request was found and cancelled, false otherwise
     */
    bool cancel_request(std::uintptr_t request_id);

    /**
     * @brief Cancel a request with a custom status code and message
     * @param request_id ID of the request to cancel
     * @param status_code HTTP status code to use in the cancellation response
     * @param message Message to include in the cancellation response body
     * @return true if the request was found and cancelled, false otherwise
     */
    bool cancel_request(std::uintptr_t request_id, 
                        http_status status_code,
                        const std::string& message);

    /**
     * @brief Gets a map of all currently active asynchronous requests.
     * The key is the context ID (uintptr_t), and the value is a shared_ptr to the Context.
     * Useful for introspection and debugging.
     * @return Const reference to the map of active async requests.
     */
    const qb::unordered_map<std::uintptr_t, std::shared_ptr<Context>> &
    get_active_requests() const;

    /**
     * @brief Complete an asynchronous request and send the response
     * @param context_id Unique identifier for the context
     * @param response Response to send
     * @param state The completion state of the request
     */
    void complete_async_request(std::uintptr_t context_id, Response response,
                                AsyncRequestState state = AsyncRequestState::COMPLETED);

    /**
     * @brief Get the routes for a specific HTTP method (for introspection)
     * @param method HTTP method to get routes for
     * @return Reference to the vector of routes
     */
    const std::vector<std::unique_ptr<IRoute>>& getRoutes(http_method method) const {
        static std::vector<std::unique_ptr<IRoute>> empty;
        auto it = _routes.find(method);
        if (it != _routes.end()) {
            return it->second;
        }
        return empty;
    }
    
    /**
     * @brief Get all HTTP methods with registered routes
     * @return Vector of HTTP methods
     */
    std::vector<http_method> getRegisteredMethods() const {
        std::vector<http_method> methods;
        for (const auto& pair : _routes) {
            if (!pair.second.empty()) {
                methods.push_back(pair.first);
            }
        }
        return methods;
    }
    
    /**
     * @brief Get all controllers registered with this router
     * @return Reference to the vector of controllers
     */
    const std::vector<std::shared_ptr<Controller>>& getControllers() const {
        return _controllers;
    }
    
    /**
     * @brief Get the current route group
     * @return Pointer to the current route group, or nullptr if none
     */
    RouteGroup* getCurrentGroup() const {
        // Return the last added group or nullptr if no groups exist
        return _groups.empty() ? nullptr : _groups.back().get();
    }
    
    /**
     * @brief Get all route groups (for OpenAPI introspection)
     * @return Vector of RouteGroup pointers
     */
    std::vector<RouteGroup*> getGroups() const {
        std::vector<RouteGroup*> groups;
        for (const auto& group : _groups) {
            groups.push_back(group.get());
        }
        return groups;
    }
    
    /**
     * @brief Route metadata for OpenAPI documentation
     * @return Reference to the route metadata
     */
    RouteMetadata& metadata() {
        static RouteMetadata _metadata;
        return _metadata;
    }
    
    /**
     * @brief Route metadata for OpenAPI documentation (const)
     * @return Const reference to the route metadata
     */
    const RouteMetadata& metadata() const {
        static RouteMetadata _metadata;
        return _metadata;
    }

private:
    // Map of HTTP methods to route handlers
    qb::unordered_map<http_method, std::vector<std::unique_ptr<IRoute>>> _routes;
    // Controllers for hierarchical routing
    std::vector<std::shared_ptr<Controller>> _controllers;
    // Global middleware functions (legacy) - NO LONGER DIRECTLY STORED
    // Asynchronous middleware functions (legacy) - NO LONGER DIRECTLY STORED
    // Typed middleware chain - THIS IS THE SOLE CHAIN
    std::shared_ptr<MiddlewareChain<Session, String>> _typed_middleware_chain;
    // Error handlers for different status codes
    qb::unordered_map<int, std::function<void(Context &)>> _error_handlers;
    // Default responses for different HTTP methods (if no route matches)
    qb::unordered_map<http_method, Response> _default_responses;
    // Whether to enable logging
    bool _enable_logging{false};
    
    // Store all route groups in a stable container to prevent dangling references
    std::vector<std::shared_ptr<RouteGroup>> _groups;
    // Store the parent-child relationships between groups
    qb::unordered_map<RouteGroup*, std::vector<RouteGroup*>> _group_hierarchy;

    // Cache for recently completed request signatures to handle re-processing
    std::set<std::string> _recently_completed_request_signatures;
    // TODO: Add a mechanism to prune this cache (e.g., TTL, max size)

    // Map to track active async requests
    qb::unordered_map<std::uintptr_t, std::shared_ptr<Context>> _active_async_requests;
    
    // Timestamp of last cleanup
    std::chrono::steady_clock::time_point _last_cleanup;

    // Async request timeout in seconds (0 = no timeout)
    int _async_request_timeout{60};

    // Maximum number of concurrent requests
    size_t _max_concurrent_requests = std::numeric_limits<size_t>::max();

    // Cancelled request tracking
    std::set<std::uintptr_t> _cancelled_requests;

    // New radix tree-based routes
    qb::unordered_map<http_method, RadixTree> _radix_routes;

    // Event queue for processing deferred requests
    struct EventQueueItem {
        std::uintptr_t        context_id;
        std::function<void()> callback;
        Clock::time_point     scheduled_time;

        EventQueueItem(std::uintptr_t id, std::function<void()> cb,
                       Clock::time_point time = Clock::now())
            : context_id(id)
            , callback(std::move(cb))
            , scheduled_time(time) {}
    };

    std::vector<EventQueueItem> _event_queue;
    bool                        _processing_event_queue = false;

    // Helper methods for processing global middleware
    // bool process_global_legacy_sync_middleware(Context &ctx, std::shared_ptr<Session> session, const std::string& path_for_routing_this_instance); // REMOVED
    // bool process_global_legacy_async_middleware(std::shared_ptr<Context> context_ptr, const std::string& path_for_routing_this_instance); // REMOVED
    bool process_global_typed_middleware(std::shared_ptr<Context> context_ptr, const std::string& path_for_routing_this_instance);

    /**
     * @brief Sort routes by priority
     * @param method HTTP method to sort routes for
     */
    void sort_routes(http_method method);

    /**
     * @brief Check for timed out async requests and clean them up
     */
    void cleanup_timed_out_requests();

    // Process the next item in the event queue
    void process_next_event();

    // Method to schedule an event after a delay (would integrate with libev)
    void schedule_event(int delay_ms, std::function<void()> callback);

    // Run async middleware chain - NO LONGER NEEDED AS A SEPARATE LEGACY CHAIN RUNNER
    // void run_legacy_async_middleware_chain(std::shared_ptr<Context> context_ptr, size_t index, bool isGlobalChain); // REMOVED

    // Route to appropriate handler (extracted from the route method)
    void route_to_handler(Context &ctx, const std::string &path);

    // Helper to generate a unique signature for a request
    std::string generate_request_signature(const TRequest<String>& req);

    // Helper type trait to check if session has a get_client_ip method
    template <typename S, typename = void>
    struct has_client_ip_method : std::false_type {};

    template <typename S>
    struct has_client_ip_method<S,
                                std::void_t<decltype(std::declval<S>().get_client_ip())>>
        : std::true_type {};
    
    // Helper type trait to check if session has an ip() method
    template <typename S, typename = void>
    struct has_ip_method : std::false_type {};

    template <typename S>
    struct has_ip_method<S, 
                        std::void_t<decltype(std::declval<S>().ip())>>
        : std::true_type {};
    
    // Helper type trait to check if session has an id() method
    template <typename S, typename = void>
    struct has_id_method : std::false_type {};

    template <typename S>
    struct has_id_method<S, 
        std::void_t<decltype(std::declval<S>().id())>>
        : std::true_type {};
        
    // Helper type trait to check if session has an is_connected() method
    template <typename S, typename = void>
    struct has_method_is_connected : std::false_type {};

    template <typename S>
    struct has_method_is_connected<S, 
        std::void_t<decltype(std::declval<S>().is_connected())>>
        : std::true_type {};
};

// Implementation wrapper to enable the complete interface of Router
template <typename Session, typename String = std::string>
class RouterImpl : public Router<Session, String> {
public:
    using BaseRouter = Router<Session, String>;
    using Context = typename BaseRouter::Context;
    using RouteGroup = typename BaseRouter::RouteGroup;
    using TypedMiddlewarePtr = typename BaseRouter::TypedMiddlewarePtr;
    
    // Inherit constructors from base class
    using BaseRouter::BaseRouter;
    
    // Factory method to create router instance
    static std::unique_ptr<RouterImpl> create() {
        return std::make_unique<RouterImpl>();
    }
};

} // namespace qb::http

#if defined(_WIN32)
#define DELETE (0x00010000L)
#endif

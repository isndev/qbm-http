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
 * @brief HTTP Router for handling requests
 *
 * This class manages routes, middleware, controllers, and asynchronous request handling.
 * It uses a combination of linear searching/regex matching and optional radix trees
 * for efficient route lookups.
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
    using Controller = Controller<Session, String>;
    using RouteGroup = RouteGroup<Session, String>;
    using IRoute     = IRoute<Session, String>;

    // Middleware type definitions
    using Middleware = std::function<bool(Context &)>;
    using AsyncMiddleware = std::function<void(Context &, std::function<void(bool)>)>;
    using TypedMiddlewarePtr = MiddlewarePtr<Session, String>;

    // Template for route implementation
    template <typename Func>
    using TRoute = TRoute<Session, String, Func>;

    // Constructor and destructor
    Router();
    ~Router() = default;

#define REGISTER_ROUTE_FUNCTION(num, name, description)  \
    template <typename _Func>                            \
    Router &name(std::string const &path, _Func &&func); \
    template <typename T, typename... Args>              \
    Router &name(Args &&...args);

    HTTP_SERVER_METHOD_MAP(REGISTER_ROUTE_FUNCTION)

#undef REGISTER_ROUTE_FUNCTION

    /**
     * @brief Register a controller for hierarchical routing
     * @tparam T Controller class type
     * @tparam Args Constructor argument types
     * @param args Constructor arguments
     */
    template <typename T, typename... Args>
    void controller(Args &&...args);

    /**
     * @brief Create a route group with a common prefix
     * @param prefix Path prefix for all routes in the group
     * @param priority Priority for all routes in the group
     * @return Reference to the created route group
     */
    RouteGroup &group(const std::string &prefix, int priority = 0);

    /**
     * @brief Set the default response for a specific HTTP method
     * @param method HTTP method
     * @param response Default response
     * @return Reference to this router
     */
    Router &set_default_response(http_method method, Response response);

    /**
     * @brief Add a global middleware function (legacy way)
     * @param middleware Middleware function
     * @return Reference to this router
     */
    Router &use(Middleware middleware);

    /**
     * @brief Add an asynchronous middleware function
     * @param middleware Asynchronous middleware function
     * @return Reference to this router
     */
    Router &use(AsyncMiddleware middleware);

    /**
     * @brief Add a typed middleware to the router
     * @param middleware Middleware to add
     * @return Reference to this router for chaining
     */
    Router &use(TypedMiddlewarePtr middleware);
    
    /**
     * @brief Create and add a typed middleware to the router
     * @tparam M Type of middleware to create
     * @tparam Args Types of arguments to construct the middleware
     * @param args Arguments to construct the middleware
     * @return Reference to this router for chaining
     */
    template <template<typename, typename> class M, typename... Args>
    Router &use(Args&&... args) {
        auto middleware = std::make_shared<M<Session, String>>(std::forward<Args>(args)...);
        return use(middleware);
    }

    /**
     * @brief Set an error handler for a specific status code
     * @param status_code HTTP status code
     * @param handler Error handler function
     * @return Reference to this router
     */
    Router &on_error(int status_code, std::function<void(Context &)> handler);

    /**
     * @brief Enable or disable request logging
     * @param enable Whether to enable logging
     * @return Reference to this router
     */
    Router &enable_logging(bool enable);

    /**
     * @brief Clear all middleware functions
     * @return Reference to this router
     */
    Router &clear_middleware() {
        _middleware.clear();
        _async_middleware.clear();  // Vider aussi les middlewares asynchrones
        return *this;
    }

    /**
     * @brief Configure the timeout for async requests
     * @param timeout_seconds Timeout in seconds
     * @return Reference to this router
     */
    Router &configure_async_timeout(int timeout_seconds);

    /**
     * @brief Force timeout of all async requests
     * @return Number of requests that were timed out
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
     * @param skip_async_middleware Flag to avoid recursive calls when coming from
     * run_async_middleware_chain
     * @return true if the request was matched and processed
     */
    bool route_context(std::shared_ptr<Session> session, Context &ctx,
                       std::shared_ptr<Context> context_ptr           = nullptr,
                       bool                     skip_async_middleware = false);

    /**
     * @brief Log a request
     * @param ctx Request context
     */
    void log_request(const Context &ctx);

    // For backwards compatibility with existing implementation
    void log_request(const Context &ctx, int status, double duration,
                     const std::string &note = "");

    /**
     * @brief Enable or disable the radix tree for route matching
     * @param enable Whether to enable radix tree matching
     * @return Reference to this router
     */
    Router &enable_radix_tree(bool enable);

    /**
     * @brief Force enable radix tree for a specific HTTP method
     * @param method HTTP method to enable radix tree for
     * @return Reference to this router
     */
    Router &force_enable_radix_tree_for_method(http_method method);

    /**
     * @brief Build radix trees for all HTTP methods
     * @return Reference to this router
     */
    Router &build_radix_trees();

    /**
     * @brief Clear all active async requests
     */
    void clear_all_active_requests();

    /**
     * @brief Set the maximum number of concurrent requests
     * @param max_requests Maximum number of concurrent requests
     * @return Reference to this router
     */
    Router &configure_max_concurrent_requests(size_t max_requests);

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
     * @brief Get all active async requests
     * @return Map of active requests (request ID to context)
     */
    const std::map<std::uintptr_t, std::shared_ptr<Context>> &
    get_active_requests() const;

    /**
     * @brief Complete an asynchronous request and send the response
     * @param context_id Unique identifier for the context
     * @param response Response to send
     * @param state The completion state of the request
     */
    void complete_async_request(std::uintptr_t context_id, Response response,
                                AsyncRequestState state = AsyncRequestState::COMPLETED);

private:
    // Map of HTTP methods to route handlers
    std::map<http_method, std::vector<std::unique_ptr<IRoute>>> _routes;
    // Controllers for hierarchical routing
    std::vector<std::shared_ptr<Controller>> _controllers;
    // Global middleware functions (legacy)
    std::vector<Middleware> _middleware;
    // Asynchronous middleware functions (legacy)
    std::vector<AsyncMiddleware> _async_middleware;
    // Typed middleware chain
    std::shared_ptr<MiddlewareChain<Session, String>> _typed_middleware_chain;
    // Error handlers for different status codes
    std::map<int, std::function<void(Context &)>> _error_handlers;
    // Default responses for different HTTP methods (if no route matches)
    std::map<http_method, Response> _default_responses;
    // Whether to enable logging
    bool _enable_logging{false};
    // Current route group being configured
    std::unique_ptr<RouteGroup> _current_group;

    // Map to track active async requests
    std::map<std::uintptr_t, std::shared_ptr<Context>> _active_async_requests;
    
    // Timestamp of last cleanup
    std::chrono::steady_clock::time_point _last_cleanup;

    // Async request timeout in seconds (0 = no timeout)
    int _async_request_timeout{60};

    // Maximum number of concurrent requests
    size_t _max_concurrent_requests = std::numeric_limits<size_t>::max();

    // Cancelled request tracking
    std::set<std::uintptr_t> _cancelled_requests;

    // New radix tree-based routes
    std::unordered_map<http_method, RadixTree> _radix_routes;
    std::unordered_map<http_method, bool>      _radix_enabled;

    // Whether to use radix tree for route matching
    bool _use_radix_tree;

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

    // Run async middleware chain
    void run_async_middleware_chain(std::shared_ptr<Context> context_ptr, size_t index);

    // Route to appropriate handler (extracted from the route method)
    void route_to_handler(Context &ctx, const std::string &path);

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

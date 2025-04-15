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

#include "../request.h"
#include "../response.h"
#include "../types.h"
#include "./async_completion_handler.h"
#include "./async_types.h"
#include "./context.h"
#include "./cors_options.h"
#include "./path_parameters.h"
#include "./radix_tree.h"
#include "./route_types.h"
// #include "../request_path_view.h"

#if defined(_WIN32)
#undef DELETE // Windows :/
#endif

namespace qb::http {

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

    // Type aliases for external types
    using Context    = RouterContext<Session, String>;
    using Route      = ARoute<Session, String>;
    using Controller = Controller<Session, String>;
    using RouteGroup = RouteGroup<Session, String>;
    using IRoute     = IRoute<Session, String>;

    // Middleware function type
    using Middleware = std::function<bool(Context &)>;

    // Add an asynchronous middleware function
    using AsyncMiddleware = std::function<void(Context &, std::function<void(bool)>)>;

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

    HTTP_METHOD_MAP(REGISTER_ROUTE_FUNCTION)

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
     * @brief Add a global middleware function
     * @param middleware Middleware function
     * @return Reference to this router
     */
    Router &use(Middleware middleware);

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
    Router &clear_middleware();

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
     * @brief Add an asynchronous middleware function
     * @param middleware Asynchronous middleware function
     * @return Reference to this router
     */
    Router &use_async(AsyncMiddleware middleware);

    /**
     * @brief Clear all async middleware functions
     * @return Reference to this router
     */
    Router &clear_async_middleware();

    /**
     * @brief Configure rate limiting
     * @param requests_per_window Maximum requests per time window
     * @param window_size Time window in seconds
     * @return Reference to this router
     */
    Router &configure_rate_limit(size_t requests_per_window, int window_size_seconds);

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
     * @brief Enable CORS with the given options
     * @param options CORS options
     * @return Reference to this router
     */
    Router &enable_cors(const CorsOptions &options);

    /**
     * @brief Enable CORS with advanced options including regex-based origin matching
     * @param regex_patterns Regex patterns for origin matching
     * @param methods Allowed methods
     * @param headers Allowed headers
     * @param allow_credentials Whether to allow credentials
     * @return Reference to this router
     */
    Router &enable_cors_with_patterns(
        const std::vector<std::string> &regex_patterns,
        const std::vector<std::string> &methods = {"GET", "POST", "PUT", "DELETE"},
        const std::vector<std::string> &headers = {"Content-Type", "Authorization"},
        bool                            allow_credentials = true);

    /**
     * @brief Enable permissive CORS for development
     * @return Reference to this router
     */
    Router &enable_dev_cors();

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
    // Global middleware functions
    std::vector<Middleware> _middleware;
    // Asynchronous middleware functions
    std::vector<AsyncMiddleware> _async_middleware;
    // Error handlers for different status codes
    std::map<int, std::function<void(Context &)>> _error_handlers;
    // Default responses for different HTTP methods (if no route matches)
    std::map<http_method, Response> _default_responses;
    // Whether to enable logging
    bool _enable_logging{false};
    // Current route group being configured
    std::unique_ptr<RouteGroup> _current_group;
    // CORS options (if enabled)
    std::unique_ptr<CorsOptions> _cors_options;

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

    // Rate limiting
    struct RateLimit {
        size_t                                                      requests_per_window;
        std::chrono::seconds                                        window_size;
        std::map<std::string, std::pair<size_t, Clock::time_point>> client_counters;
    };

    std::unique_ptr<RateLimit> _rate_limit;

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

    // Check if a request is rate limited
    bool is_rate_limited(const Context &ctx);

    // Helper type trait to check if session has a get_client_ip method
    template <typename S, typename = void>
    struct has_client_ip_method : std::false_type {};

    template <typename S>
    struct has_client_ip_method<S,
                                std::void_t<decltype(std::declval<S>().get_client_ip())>>
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

} // namespace qb::http

#if defined(_WIN32)
#define DELETE (0x00010000L)
#endif

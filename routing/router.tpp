#pragma once
#include <qb/uuid.h>
#include <sstream>
#include "../utility.h"
#include "./router.h"

namespace qb::http {

// Constructor
template <typename Session, typename String>
Router<Session, String>::Router()
    : _last_cleanup(std::chrono::steady_clock::now())
    , _use_radix_tree(true) {}

// Method to add a controller
template <typename Session, typename String>
template <typename T, typename... Args>
void
Router<Session, String>::controller(Args &&...args) {
    auto ctrl = std::make_shared<T>(std::forward<Args>(args)...);
    _controllers.push_back(ctrl);
}

// Method to create a route group
template <typename Session, typename String>
typename Router<Session, String>::RouteGroup &
Router<Session, String>::group(const std::string &prefix, int priority) {
    _current_group = std::make_unique<RouteGroup>(*this, prefix, priority);
    return *_current_group;
}

// Method to set a default response
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::set_default_response(http_method method, Response response) {
    _default_responses[method] = std::move(response);
    return *this;
}

// Method to add a middleware (legacy)
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::use(Middleware middleware) {
    _middleware.push_back(std::move(middleware));
    return *this;
}

// Method to add a typed middleware
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::use(TypedMiddlewarePtr middleware) {
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
    
    // For asynchronous middleware
    use([chain = _typed_middleware_chain](Context& ctx, std::function<void(bool)> done) {
        chain->process(ctx, [done](MiddlewareResult result) {
            done(!result.should_stop());
        });
    });
    
    return *this;
}

// Method to set an error handler
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::on_error(int                            status_code,
                                  std::function<void(Context &)> handler) {
    _error_handlers[status_code] = std::move(handler);
    return *this;
}

// Method to enable/disable logging
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::enable_logging(bool enable) {
    _enable_logging = enable;
    return *this;
}

// Method to configure the timeout for asynchronous requests
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::configure_async_timeout(int timeout_seconds) {
    _async_request_timeout = timeout_seconds;
    return *this;
}

template <typename Session, typename String>
size_t
Router<Session, String>::force_timeout_all_requests() {
    size_t                      count = 0;
    std::vector<std::uintptr_t> requests;

    // Get all request IDs
    for (const auto &[context_id, _] : _active_async_requests) {
        requests.push_back(context_id);
    }

    // Process all requests with timeout
    for (auto context_id : requests) {
        Response timeout_response;
        timeout_response.status_code = HTTP_STATUS_REQUEST_TIMEOUT;
        timeout_response.body()      = "Request timed out";

        complete_async_request(context_id, std::move(timeout_response),
                               AsyncRequestState::TIMEOUT);
        count++;
    }

    return count;
}

// Method to sort routes by priority
template <typename Session, typename String>
void
Router<Session, String>::sort_routes(http_method method) {
    auto it = _routes.find(method);
    if (it != _routes.end()) {
        std::sort(
            it->second.begin(), it->second.end(),
            [](const auto &a, const auto &b) { return a->priority() > b->priority(); });
    }
}

template <typename Session, typename String>
void
Router<Session, String>::complete_async_request(std::uintptr_t    context_id,
                                                Response          response,
                                                AsyncRequestState state) {
    auto it = _active_async_requests.find(context_id);
    if (it != _active_async_requests.end()) {
        // Safety check to avoid segfaults
        if (!it->second) {
            _active_async_requests.erase(it);
            return;
        }

        auto &ctx = *(it->second);

        // Check if request is cancelled and should be skipped
        if (state != AsyncRequestState::CANCELED &&
            _cancelled_requests.find(context_id) != _cancelled_requests.end()) {
            // Simply remove the request without processing it
            _active_async_requests.erase(it);
            return;
        }

        // Check if the session is disconnected
        if (state == AsyncRequestState::DISCONNECTED || !ctx.is_session_connected()) {
            // Session disconnected, clean up resources without sending response
            _active_async_requests.erase(it);
            return;
        }

        // Session is still connected, send the response
        ctx.response = std::move(response);
        try {
            *ctx.session << ctx.response;
        } catch (...) {
            // Catch and ignore any exceptions during response sending
            // This provides extra protection for disconnected sessions
        }

        // Remove from cancelled list if it was marked as cancelled
        if (state == AsyncRequestState::CANCELED) {
            _cancelled_requests.erase(context_id);
        }

        _active_async_requests.erase(it);
    }
}

// Method to route a request
template <typename Session, typename String>
bool
Router<Session, String>::route(std::shared_ptr<Session> session, TRequest<String> routing_request) {
    // Check if we're at the concurrent request limit
    if (_active_async_requests.size() >= _max_concurrent_requests) {
        // Create a direct response for too many requests
        Response response;
        response.status_code = HTTP_STATUS_TOO_MANY_REQUESTS;
        response.body()      = "Too many concurrent requests";
        *session << response;
        return true;
    }

    // Clean up timed out requests
    cleanup_timed_out_requests();

    // Create a new context with the request
    auto context_ptr =
        std::make_shared<Context>(session, std::move(routing_request), this);
    Context &ctx = *context_ptr;

    // Route the context
    return route_context(session, ctx, context_ptr);
}

// Method to route a context
template <typename Session, typename String>
bool
Router<Session, String>::route_context(std::shared_ptr<Session> session, Context &ctx,
                                       std::shared_ptr<Context> context_ptr,
                                       bool                     skip_async_middleware) {
    // Create a shared_ptr to the context if one wasn't provided
    std::shared_ptr<Context> ctx_ptr = context_ptr;
    if (!ctx_ptr) {
        ctx_ptr = std::make_shared<Context>(ctx);
    }

    // Calculate a unique context ID
    std::uintptr_t context_id = reinterpret_cast<std::uintptr_t>(&(*ctx_ptr));

    // Record start time if not already set
    if (ctx.start_time() == Clock::time_point()) {
        ctx.start_time() = std::chrono::steady_clock::now();
    }

    ctx.add_event("route_context");

    // Handle async middleware if present and not being skipped
    if (!_async_middleware.empty() && !skip_async_middleware) {
        // Start the async middleware chain
        run_async_middleware_chain(ctx_ptr, 0);
        return true;
    }

    // Process synchronous middleware
    std::string path = std::string(ctx.request._uri.path());

    // Run through global middleware first
    for (const auto &middleware : _middleware) {
        ctx.add_event("sync_middleware");
        if (!middleware(ctx)) {
            if (ctx.handled) {
                if (ctx.is_async()) {
                    // Register for async completion
                    _active_async_requests[context_id] = ctx_ptr;
                    return true;
                }

                // Synchronous response
                *session << ctx.response;
                log_request(ctx);
                return true;
            }
            return false;
        }
    }

    ctx.add_event("route_to_handler");
    route_to_handler(ctx, path);

    // If the context wasn't handled by route_to_handler, and we have a 404 handler, use
    // it
    if (!ctx.handled &&
        _error_handlers.find(HTTP_STATUS_NOT_FOUND) != _error_handlers.end()) {
        ctx.add_event("error_handler_404");
        ctx.response.status_code = HTTP_STATUS_NOT_FOUND;
        _error_handlers[HTTP_STATUS_NOT_FOUND](ctx);
        ctx.handled = true;
    }

    // If the context is now handled but async, register it
    if (ctx.handled && ctx.is_async()) {
        _active_async_requests[context_id] = ctx_ptr;

        return true;
    }

    // Send response for handled requests that aren't async
    if (ctx.handled) {
        *session << ctx.response;
        log_request(ctx);
    }

    return ctx.handled;
}

// Method to log a request
template <typename Session, typename String>
void
Router<Session, String>::log_request(const Context &ctx) {
    if (!_enable_logging)
        return;

    // Simple logging to std::cout for now - can be replaced with a more robust solution
    auto        now   = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    // Use http_method_name for method name conversion
    const char *method_str =
        ::http_method_name(static_cast<http_method_t>(ctx.method()));

    // Calculate elapsed time
    double duration = ctx.elapsed();

    std::cout << "[" << std::ctime(&now_c) << "] " << method_str << " " << ctx.path()
              << " - " << ctx.response.status_code << " (" << duration << "ms)";

    std::cout << std::endl;
}

#define REGISTER_ROUTE_FUNCTION(num, name, description)                                \
    template <typename Session, typename String>                                       \
    template <typename _Func>                                                          \
    Router<Session, String> &Router<Session, String>::name(std::string const &path,    \
                                                           _Func            &&func) {  \
        auto route = std::make_unique<TRoute<_Func>>(path, std::forward<_Func>(func)); \
        http_method method = static_cast<http_method>(num);                            \
                                                                                       \
        /* Add to the regular routes vector */                                         \
        _routes[method].push_back(std::move(route));                                   \
                                                                                       \
        /* Also add to radix tree if enabled */                                        \
        if (_use_radix_tree) {                                                         \
            /* Make sure we have an instance for this method */                        \
            if (_radix_routes.find(method) == _radix_routes.end()) {                   \
                _radix_routes[method] = RadixTree();                                   \
            }                                                                          \
                                                                                       \
            /* Add the route to the radix tree */                                      \
            Route *ar = dynamic_cast<Route *>(_routes[method].back().get());           \
            if (ar) {                                                                  \
                _radix_routes[method].insert(ar->path(), ar, ar->priority());          \
                                                                                       \
                /* Enable radix routing after we have enough routes */                 \
                if (_routes[method].size() >= 10) {                                    \
                    _radix_enabled[method] = true;                                     \
                }                                                                      \
            }                                                                          \
        }                                                                              \
                                                                                       \
        sort_routes(method);                                                           \
        return *this;                                                                  \
    }                                                                                  \
    template <typename Session, typename String>                                       \
    template <typename T, typename... Args>                                            \
    Router<Session, String> &Router<Session, String>::name(Args &&...args) {           \
        static_assert(std::is_base_of_v<IRoute, T>,                                    \
                      "Router registering Route not base of Route");                   \
        http_method method = static_cast<http_method>(num);                            \
        _routes[method].push_back(std::make_unique<T>(std::forward<Args>(args)...));   \
                                                                                       \
        /* Also add to radix tree if enabled */                                        \
        if (_use_radix_tree) {                                                         \
            /* Make sure we have an instance for this method */                        \
            if (_radix_routes.find(method) == _radix_routes.end()) {                   \
                _radix_routes[method] = RadixTree();                                   \
            }                                                                          \
                                                                                       \
            /* Add the route to the radix tree */                                      \
            Route *ar = dynamic_cast<Route *>(_routes[method].back().get());           \
            if (ar) {                                                                  \
                _radix_routes[method].insert(ar->path(), ar, ar->priority());          \
                                                                                       \
                /* Enable radix routing after we have enough routes */                 \
                if (_routes[method].size() >= 10) {                                    \
                    _radix_enabled[method] = true;                                     \
                }                                                                      \
            }                                                                          \
        }                                                                              \
                                                                                       \
        sort_routes(method);                                                           \
        return *this;                                                                  \
    }

HTTP_SERVER_METHOD_MAP(REGISTER_ROUTE_FUNCTION)

#undef REGISTER_ROUTE_FUNCTION

// Method to clean up timed out async requests
template <typename Session, typename String>
void
Router<Session, String>::cleanup_timed_out_requests() {
    if (_async_request_timeout <= 0) {
        return; // Timeout disabled
    }

    auto now = std::chrono::steady_clock::now();

    // Only run cleanup periodically (every 5 seconds)
    auto time_since_last_cleanup =
        std::chrono::duration_cast<std::chrono::seconds>(now - _last_cleanup).count();
    if (time_since_last_cleanup < 5) {
        return;
    }

    _last_cleanup = now;

    std::vector<std::uintptr_t> timed_out_requests;

    // Identify timed out requests
    for (const auto &[context_id, ctx_ptr] : _active_async_requests) {
        auto &ctx = *ctx_ptr;
        auto  duration =
            std::chrono::duration_cast<std::chrono::seconds>(now - ctx.start_time())
                .count();

        if (duration > _async_request_timeout) {
            timed_out_requests.push_back(context_id);
        }
    }

    // Process timed out requests
    for (auto context_id : timed_out_requests) {
        Response timeout_response;
        timeout_response.status_code = HTTP_STATUS_REQUEST_TIMEOUT;
        timeout_response.body()      = "Request timed out";

        complete_async_request(context_id, std::move(timeout_response),
                               AsyncRequestState::CANCELED);
    }
}

// Method to get the number of active async requests
template <typename Session, typename String>
size_t
Router<Session, String>::active_async_requests_count() const {
    return _active_async_requests.size();
}

// Method to check if a request is still active
template <typename Session, typename String>
bool
Router<Session, String>::is_active_request(std::uintptr_t request_id) const {
    return _active_async_requests.find(request_id) != _active_async_requests.end();
}

// Method to clean up requests from disconnected sessions
template <typename Session, typename String>
size_t
Router<Session, String>::clean_disconnected_sessions() {
    size_t count = 0;
    std::vector<std::uintptr_t> to_clean;

    // Find requests with disconnected sessions
    for (const auto &[context_id, ctx_ptr] : _active_async_requests) {
        if (!ctx_ptr) {
            to_clean.push_back(context_id);
            continue;
        }

        // Check if the session is still connected
        if (!ctx_ptr->is_session_connected()) {
            to_clean.push_back(context_id);
            count++;
        }
    }

    // Clean up requests from disconnected sessions
    for (auto context_id : to_clean) {
        // Remove the async request
        _active_async_requests.erase(context_id);

        // Remove from cancelled requests if present
        _cancelled_requests.erase(context_id);
    }

    return count;
}

// Method to add an asynchronous middleware
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::use(AsyncMiddleware middleware) {
    _async_middleware.push_back(std::move(middleware));
    return *this;
}

// Method to defer request processing
template <typename Session, typename String>
bool
Router<Session, String>::defer_request(std::uintptr_t context_id, int delay_ms,
                                       std::function<void()> callback) {
    if (!is_active_request(context_id)) {
        return false;
    }

    auto scheduled_time = Clock::now() + std::chrono::milliseconds(delay_ms);
    _event_queue.emplace_back(context_id, std::move(callback), scheduled_time);

    if (!_processing_event_queue) {
        process_next_event();
    }

    return true;
}

// Method to process the next event in the queue
template <typename Session, typename String>
void
Router<Session, String>::process_next_event() {
    if (_event_queue.empty()) {
        _processing_event_queue = false;
        return;
    }

    _processing_event_queue = true;

    // Sort by scheduled time
    std::sort(_event_queue.begin(), _event_queue.end(),
              [](const EventQueueItem &a, const EventQueueItem &b) {
                  return a.scheduled_time < b.scheduled_time;
              });

    // Get the next event that's ready
    auto now = Clock::now();
    auto it  = std::find_if(
        _event_queue.begin(), _event_queue.end(),
        [&now](const EventQueueItem &item) { return item.scheduled_time <= now; });

    if (it != _event_queue.end()) {
        auto callback = it->callback;
        _event_queue.erase(it);

        // Process the event callback
        callback();

        // Continue processing other events asynchronously
        // We use a zero-delay callback to avoid stack overflow
        // This mimics the behavior of setTimeout(0) in JS event loops
        schedule_event(0, [this]() { process_next_event(); });
    } else if (!_event_queue.empty()) {
        // Schedule a timer for the next event
        auto next_time = _event_queue.front().scheduled_time;
        auto delay =
            std::chrono::duration_cast<std::chrono::milliseconds>(next_time - now)
                .count();

        schedule_event(delay, [this]() { process_next_event(); });
    } else {
        _processing_event_queue = false;
    }
}

// Method to schedule an event after a delay
template <typename Session, typename String>
void
Router<Session, String>::schedule_event(int delay_ms, std::function<void()> callback) {
    // In a real implementation, this would use libev timer events
    // For now, we'll just store in our queue with a scheduled time
    auto scheduled_time = Clock::now() + std::chrono::milliseconds(delay_ms);
    _event_queue.emplace_back(0, std::move(callback), scheduled_time);

    if (!_processing_event_queue) {
        process_next_event();
    }
}

// Method to run the asynchronous middleware chain
template <typename Session, typename String>
void
Router<Session, String>::run_async_middleware_chain(std::shared_ptr<Context> context_ptr,
                                                    size_t                   index) {
    if (index >= _async_middleware.size()) {
        // All middleware completed successfully, now run the route handler
        // but skip the async middleware to avoid infinite recursion
        Context &ctx = *context_ptr;
        route_context(ctx.session, ctx, context_ptr, true);
        return;
    }

    Context &ctx = *context_ptr;
    ctx.add_event("async_middleware_" + std::to_string(index));

    // Calculate a unique context ID for lookups
    std::uintptr_t context_id = reinterpret_cast<std::uintptr_t>(&(*context_ptr));

    // Store the context in our active async requests map so it persists
    _active_async_requests[context_id] = context_ptr;

    // Execute the current middleware with a callback
    // Important: use context_ptr to ensure we're working with the same instance
    _async_middleware[index](ctx, [this, context_ptr, index](bool continue_chain) {
        // Get the reference from our context_ptr, which is guaranteed to still be valid
        Context &ctx = *context_ptr;

        // Check if the request has been handled by the middleware
        if (ctx.is_handled()) {
            // Request was handled directly by middleware
            if (!ctx.is_async()) {
                // If the middleware doesn't want to continue (e.g. auth failed)
                // immediately send the response and stop the chain
                if (!continue_chain) {
                    // Send response immediately
                    *ctx.session << ctx.response;
                    log_request(ctx);

                    // Remove from active requests
                    _active_async_requests.erase(
                        reinterpret_cast<std::uintptr_t>(&(*context_ptr)));
                    return;
                }
            }
        }

        // Continue middleware chain if requested
        if (continue_chain) {
            run_async_middleware_chain(context_ptr, index + 1);
        } else if (ctx.is_async()) {
            // Request is handled asynchronously but chain is stopped
            // It's already registered in _active_async_requests above
        }
        // If middleware chain was stopped and not handled, it falls through
    });
}

// Method for handler processing
template <typename Session, typename String>
void
Router<Session, String>::route_to_handler(Context &ctx, const std::string &path) {
    // Direct routes
    auto it = _routes.find(ctx.request.method);
    if (it != _routes.end()) {
        // First try radix tree for faster matching if enabled
        auto radix_it = _radix_enabled.find(ctx.request.method);
        if (radix_it != _radix_enabled.end() && radix_it->second) {
            // Use radix tree for matching
            PathParameters params;
            void *handler_ptr = _radix_routes[ctx.request.method].match(path, params);

            if (handler_ptr) {
                // Found a match in the radix tree
                Route *ar = static_cast<Route *>(handler_ptr);
                // Set path parameters from radix tree match
                ctx.path_params = params;
                ctx.match       = path;
                ctx.add_event("radix_route_match");

                // Process the route
                ar->process(ctx);
                ctx.handled = true; // Mark as handled

                // Note: We don't send the response here
                // Let the caller (route_context) handle that
                log_request(ctx);
                return;
            }
        }

        // Fall back to regex matching if radix tree didn't match or isn't enabled
        for (const auto &route : it->second) {
            if (auto ar = dynamic_cast<Route *>(route.get())) {
                if (ar->match(ctx, path)) {
                    ctx.add_event("regex_route_match");
                    route->process(ctx);
                    ctx.handled = true; // Mark as handled

                    // Note: We don't send the response here
                    // Let the caller (route_context) handle that
                    log_request(ctx);
                    return;
                }
            }
        }
    }

    // Controllers
    for (const auto &ctrl : _controllers) {
        const auto &base_path = ctrl->base_path();
        if (path.compare(0, base_path.length(), base_path) == 0) {
            // Save current request URI for later restoration
            std::string original_path = std::string(ctx.request._uri.path());

            // Create a modified request with the relative path
            std::string remaining = path.substr(base_path.length());
            if (remaining.empty())
                remaining = "/";

            // Temporarily modify URI path for controller processing
            ctx.request._uri = qb::io::uri(remaining);
            ctx.add_event("controller_route");

            // Call controller process method with modified URI
            bool result = ctrl->process(ctx.session, ctx);

            // Restore original URI path
            ctx.request._uri = qb::io::uri(original_path);

            if (result) {
                log_request(ctx);
                return;
            }
        }
    }

    // Use default response if available
    auto default_it = _default_responses.find(ctx.request.method);
    if (default_it != _default_responses.end()) {
        ctx.add_event("default_response");
        ctx.response =
            Response(default_it->second); // Create a new Response via copy constructor

        // Note: We don't send the response here
        // Let the caller (route_context) handle that
        log_request(ctx);
        ctx.handled = true; // Mark request as handled when using default response
        return;
    }

    // Try error handlers
    auto error_it = _error_handlers.find(HTTP_STATUS_NOT_FOUND);
    if (error_it != _error_handlers.end()) {
        ctx.add_event("error_handler_404");
        ctx.response.status_code = HTTP_STATUS_NOT_FOUND;
        error_it->second(ctx);

        // Note: We don't send the response here
        // Let the caller (route_context) handle that
        log_request(ctx);
        ctx.handled = true; // Mark request as handled after error handler
        return;
    }
}

// Method to enable/disable radix tree for route matching
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::enable_radix_tree(bool enable) {
    _use_radix_tree = enable;
    return *this;
}

// Method to force enable radix tree for a specific HTTP method
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::force_enable_radix_tree_for_method(http_method method) {
    if (_radix_routes.find(method) == _radix_routes.end()) {
        _radix_routes[method] = RadixTree();

        // Add existing routes to the radix tree
        auto it = _routes.find(method);
        if (it != _routes.end()) {
            for (const auto &route : it->second) {
                if (auto ar = dynamic_cast<Route *>(route.get())) {
                    _radix_routes[method].insert(ar->path(), ar, ar->priority());
                }
            }
        }
    }

    _radix_enabled[method] = true;
    return *this;
}

// Method to build radix trees for all HTTP methods
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::build_radix_trees() {
    for (const auto &[method, routes] : _routes) {
        if (!routes.empty()) {
            if (_radix_routes.find(method) == _radix_routes.end()) {
                _radix_routes[method] = RadixTree();
            }

            for (const auto &route : routes) {
                if (auto ar = dynamic_cast<Route *>(route.get())) {
                    _radix_routes[method].insert(ar->path(), ar, ar->priority());
                }
            }

            _radix_enabled[method] = true;
        }
    }

    return *this;
}

// Method to clear all active async requests
template <typename Session, typename String>
void
Router<Session, String>::clear_all_active_requests() {
    _active_async_requests.clear();
    _cancelled_requests.clear();
}

// Method to configure the maximum number of concurrent requests
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::configure_max_concurrent_requests(size_t max_requests) {
    _max_concurrent_requests = max_requests;
    return *this;
}

// Method to check if a request has been cancelled
template <typename Session, typename String>
bool
Router<Session, String>::is_request_cancelled(std::uintptr_t request_id) const {
    return _cancelled_requests.find(request_id) != _cancelled_requests.end();
}

// Method to cancel a request
template <typename Session, typename String>
bool
Router<Session, String>::cancel_request(std::uintptr_t request_id) {
    if (_active_async_requests.find(request_id) != _active_async_requests.end()) {
        // Add the request to the cancelled requests list only if it's not already cancelled
        if (_cancelled_requests.find(request_id) == _cancelled_requests.end()) {
            _cancelled_requests.insert(request_id);
        }
        return true;
    }
    return false;
}

// Method to get all active async requests
template <typename Session, typename String>
const std::map<std::uintptr_t,
               std::shared_ptr<typename Router<Session, String>::Context>> &
Router<Session, String>::get_active_requests() const {
    return _active_async_requests;
}

} // namespace qb::http
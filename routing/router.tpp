#pragma once
#include <qb/uuid.h>
#include <sstream>
#include <iomanip>
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
    // Create a new group and store it in our stable container
    auto group_ptr = std::make_shared<RouteGroup>(*this, prefix, priority);
    _groups.push_back(group_ptr);
    
    // Initialize the group hierarchy entry for this new group
    _group_hierarchy[group_ptr.get()] = std::vector<RouteGroup*>();
    
    return *group_ptr;
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
    
    _typed_middleware_chain->add(std::move(middleware));
    
    this->use([chain = _typed_middleware_chain](Context& ctx) -> bool { // Legacy sync middleware signature
        auto result = chain->process(ctx); // Process with the typed chain
        if (result.is_async()) {
            return true; 
        }
        return !result.should_stop(); // Stop legacy chain if typed chain signaled stop.
    });
    
    this->use([chain = _typed_middleware_chain](Context& ctx, std::function<void(bool)> done) { // Legacy async middleware signature
        chain->process(ctx, [done_cb = std::move(done)](MiddlewareResult result) { // Renamed `done` to `done_cb` to avoid ambiguity
            if (done_cb) done_cb(!result.should_stop());
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
    std::vector<std::uintptr_t> requests_to_timeout; // Renamed for clarity

    // Collect all active request IDs to avoid issues with iterator invalidation
    for (const auto &[context_id, _] : _active_async_requests) {
        requests_to_timeout.push_back(context_id);
    }

    // Process collected requests for timeout
    for (auto context_id : requests_to_timeout) {
        Response timeout_response;
        timeout_response.status_code = HTTP_STATUS_REQUEST_TIMEOUT;
        timeout_response.body()      = "Request timed out by force_timeout_all_requests";

        // Use complete_async_request with a TIMEOUT state
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
        if (!it->second) { // Safety check for dangling context pointer
            _active_async_requests.erase(it);
            return;
        }
        auto &ctx = *(it->second);

        if (ctx.get_processing_stage() == RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) {
            ctx.add_event("complete_async_request_skipped_already_completed_sync");
            _active_async_requests.erase(it); 
            return;
        }

        bool is_request_cancelled_by_flag = _cancelled_requests.count(context_id) > 0;
        
        if (state == AsyncRequestState::CANCELED || is_request_cancelled_by_flag) {
            _active_async_requests.erase(it);
            return;
        }

        if (state == AsyncRequestState::DISCONNECTED || !ctx.is_session_connected()) {
            _active_async_requests.erase(it);
            return;
        }

        ctx.response = std::move(response); 
        try {
            ctx.add_event("complete_async_request_sending_response");
            *ctx.session << ctx.response; 
        } catch (const std::exception& e) {
            // Add logging for send exception if needed
        } catch (...) {
            // Add logging for unknown send exception if needed
        }
        
        ctx.set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
        _recently_completed_request_signatures.insert(generate_request_signature(ctx.request));
        _active_async_requests.erase(it);
    }
}

// Helper to generate a unique signature for a request
template <typename Session, typename String>
std::string Router<Session, String>::generate_request_signature(const TRequest<String>& req) {
    std::string signature = ::http_method_name(static_cast<http_method_t>(req.method));
    signature += ":";
    signature += std::string(req.uri().path());
    if (!req.uri().encoded_queries().empty()) {
        signature += "?";
        signature += std::string(req.uri().encoded_queries());
    }
    return signature;
}

// Method to route a request
template <typename Session, typename String>
bool
Router<Session, String>::route(std::shared_ptr<Session> session, TRequest<String> routing_request) {
    if (_active_async_requests.size() >= _max_concurrent_requests) {
        Response response;
        response.status_code = HTTP_STATUS_TOO_MANY_REQUESTS;
        response.body()      = "Too many concurrent requests";
        *session << response;
        return true;
    }

    cleanup_timed_out_requests();

    auto context_ptr =
        std::make_shared<Context>(session, std::move(routing_request), this);
    Context &ctx = *context_ptr;

    return route_context(session, ctx, context_ptr);
}

// Method to route a context
template <typename Session, typename String>
bool
Router<Session, String>::route_context(std::shared_ptr<Session> session, Context &ctx,
                                       std::shared_ptr<Context> context_ptr) {
    std::shared_ptr<Context> ctx_ptr_managed = context_ptr; 
    if (!ctx_ptr_managed) {
        ctx_ptr_managed = std::make_shared<Context>(ctx); 
    }
    std::uintptr_t context_id = reinterpret_cast<std::uintptr_t>(&(*ctx_ptr_managed));

    RequestProcessingStage initial_check_stage = ctx.get_processing_stage();
    if (initial_check_stage == RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) {
        ctx.add_event("route_context_entry_skipped_response_already_sent_or_completed");
        if (_active_async_requests.count(context_id)) {
            _active_async_requests.erase(context_id);
        }
        return true; 
    }

    RequestProcessingStage current_stage = ctx.get_processing_stage(); // Re-fetch after potential modification or for clarity

    if (current_stage == RequestProcessingStage::INITIAL) {
        ctx.add_event("route_context_initial_entry");
        if (!_async_middleware.empty()) {
            ctx.add_event("entering_global_async_middleware_chain_from_initial");
            ctx.set_processing_stage(RequestProcessingStage::AWAITING_GLOBAL_ASYNC_MIDDLEWARE);
            _active_async_requests[context_id] = ctx_ptr_managed;
            run_async_middleware_chain(ctx_ptr_managed, 0, true /*isGlobalChain*/);
            return true; 
        }
        ctx.set_processing_stage(RequestProcessingStage::PROCESSING_GLOBAL_SYNC_MIDDLEWARE);
        current_stage = RequestProcessingStage::PROCESSING_GLOBAL_SYNC_MIDDLEWARE; 
    } else {
        char stage_buf[32];
        snprintf(stage_buf, sizeof(stage_buf), "%d", static_cast<int>(ctx.get_processing_stage()));
        ctx.add_event(std::string("route_context_re_entry_stage_") + stage_buf);
    }

    if (current_stage == RequestProcessingStage::PROCESSING_GLOBAL_SYNC_MIDDLEWARE) {
        ctx.add_event("processing_global_sync_middleware_chain");
        for (const auto &middleware_fn : _middleware) {
            ctx.add_event("global_sync_middleware");
            if (!middleware_fn(ctx)) { 
                if (ctx.handled) {
                    if (ctx.is_async()) {
                        ctx.add_event("global_sync_middleware_handled_async");
                        ctx.set_processing_stage(RequestProcessingStage::AWAITING_HANDLER_ASYNC_COMPLETION);
                        _active_async_requests[context_id] = ctx_ptr_managed;
                    } else {
                        ctx.add_event("global_sync_middleware_handled_sync_and_sending_response");
                        ctx.set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
                        if (session) *session << ctx.response; 
                        log_request(ctx);
                    }
                    return true; 
                }
                ctx.add_event("global_sync_middleware_stopped_chain_no_handle");
                return false; 
            }
        }
        ctx.set_processing_stage(RequestProcessingStage::READY_FOR_HANDLER); 
        current_stage = RequestProcessingStage::READY_FOR_HANDLER; // Update current_stage for next block
    }

    if (current_stage == RequestProcessingStage::READY_FOR_HANDLER) {
        ctx.add_event("executing_route_handler_from_route_context");
        std::string path_for_routing = std::string(ctx.request._uri.path());
        route_to_handler(ctx, path_for_routing); 
        
        bool handler_completed_synchronously = ctx.handled && !ctx.is_async();

        if (ctx.is_async() && ctx.handled) {
             ctx.add_event("handler_marked_request_async_will_await_completion");
             ctx.set_processing_stage(RequestProcessingStage::AWAITING_HANDLER_ASYNC_COMPLETION);
             _active_async_requests[context_id] = ctx_ptr_managed; 
             return true; // Async operation started, router yields for now.
        } else if (handler_completed_synchronously) {
             ctx.add_event("handler_completed_synchronously_processing_response");
             
             if (_active_async_requests.count(context_id)) {
                 ctx.add_event("sync_handler_resolved_prior_async_chain_removing_from_active_map");
                 _active_async_requests.erase(context_id);
             }

             if (!ctx.has("_completed")) { 
                 ctx.add_event("router_sending_response_for_sync_handler");
                 
                 std::string body_before_after_callbacks = ctx.response.body().template as<std::string>();
                 ctx.add_event("body_before_execute_after_callbacks: " + body_before_after_callbacks);
                 
                 ctx.execute_after_callbacks(); 
                 
                 std::string body_after_after_callbacks = ctx.response.body().template as<std::string>();
                 ctx.add_event("body_after_execute_after_callbacks_before_send: " + body_after_after_callbacks);
                 
                 if (session) {
                     try {
                         *session << ctx.response;
                         std::string body_after_send = ctx.response.body().template as<std::string>();
                         ctx.add_event("body_potential_after_send: " + body_after_send);
                     } catch (const std::exception& e) {
                         ctx.add_event(std::string("router_send_response_exception: ") + e.what());
                     } catch (...) {
                         ctx.add_event("router_send_response_unknown_exception");
                     }
                 }
                 log_request(ctx);
                 ctx.execute_done_callbacks();
             } else {
                 ctx.add_event("sync_handler_already_called_ctx_complete_router_skips_send");
             }
             ctx.set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
             _recently_completed_request_signatures.insert(generate_request_signature(ctx.request));
             return true; 
        } else {
            ctx.add_event("handler_did_not_handle_or_ambiguous_state_falling_through");
            if (ctx.get_processing_stage() == RequestProcessingStage::READY_FOR_HANDLER) {
                ctx.set_processing_stage(RequestProcessingStage::HANDLER_PROCESSING);
            }
        }
        // current_stage variable might be stale here, always use ctx.get_processing_stage() for decisions below.
    }
    
    // Post-Handler / Default / Error Response Logic
    // This block will only execute if the request wasn't fully completed and returned by the sections above.
    RequestProcessingStage final_check_stage = ctx.get_processing_stage();

    if (final_check_stage != RequestProcessingStage::AWAITING_HANDLER_ASYNC_COMPLETION &&
        final_check_stage != RequestProcessingStage::AWAITING_GLOBAL_ASYNC_MIDDLEWARE &&
        final_check_stage != RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) { 

        if (!ctx.handled) { 
            // Try to apply a default response or a generic 404 error handler.
            auto default_it = _default_responses.find(ctx.request.method);
            if (default_it != _default_responses.end()) {
                ctx.add_event("using_default_response_in_finalize");
                ctx.response = Response(default_it->second);
                ctx.handled = true;
            } else if (_error_handlers.count(HTTP_STATUS_NOT_FOUND)) {
                ctx.add_event("using_404_error_handler_in_finalize");
                ctx.response.status_code = HTTP_STATUS_NOT_FOUND;
                _error_handlers[HTTP_STATUS_NOT_FOUND](ctx);
                ctx.handled = true;
            } else {
                 ctx.add_event("no_handler_no_default_no_404_unhandled_in_finalize_creating_generic_404");
                 ctx.response.status_code = HTTP_STATUS_NOT_FOUND; 
                 ctx.response.body() = "Not Found";
            }
        }

        bool still_needs_async_completion = _active_async_requests.count(context_id) || ctx.is_async();

        if ((ctx.handled || ctx.response.status_code == HTTP_STATUS_NOT_FOUND) && !still_needs_async_completion) { 
            if (!ctx.has("_completed")) {
                ctx.add_event("final_sync_response_preparing_to_send_by_router");
                
                ctx.execute_after_callbacks();

                ctx.add_event("final_sync_response_sending_by_router_ctx_not_self_completed");
                if (session) *session << ctx.response; 
                log_request(ctx);
                
                ctx.execute_done_callbacks(); 
            } else {
                ctx.add_event("final_sync_response_skipped_by_router_ctx_was_self_completed_or_async_handler");
            }
            ctx.set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
            _recently_completed_request_signatures.insert(generate_request_signature(ctx.request));
        } else if (ctx.handled && still_needs_async_completion) { 
            if (ctx.is_async() && !_active_async_requests.count(context_id)){
                 _active_async_requests[context_id] = ctx_ptr_managed;
            }
            ctx.add_event("final_response_deferred_to_async_completion_logic_after_handler_check");
            if(ctx.get_processing_stage() != RequestProcessingStage::AWAITING_HANDLER_ASYNC_COMPLETION && 
               ctx.get_processing_stage() != RequestProcessingStage::AWAITING_GLOBAL_ASYNC_MIDDLEWARE){
                 ctx.set_processing_stage(RequestProcessingStage::AWAITING_HANDLER_ASYNC_COMPLETION);
            }
        }
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
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    
    // Convert to local time structure and format with put_time
    std::tm tm = *std::localtime(&now_c);

    // Use http_method_name for method name conversion
    const char *method_str =
        ::http_method_name(static_cast<http_method_t>(ctx.method()));

    // Calculate elapsed time
    double duration = ctx.elapsed();

    std::cout << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] " 
              << method_str << " " << ctx.path()
              << " - " << ctx.response.status_code << " (" << duration << "ms)"
              << std::endl;
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
        _active_async_requests.erase(context_id);
        
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
                                                  size_t                   index,
                                                  bool                     isGlobalChain) {
    Context &chain_ctx = *context_ptr; 
    std::uintptr_t context_id = reinterpret_cast<std::uintptr_t>(&(*context_ptr)); 

    // Critical check - if the context is already completed, avoid continuing
    if (chain_ctx.get_processing_stage() == RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) {
        if (_active_async_requests.count(context_id)) {
            _active_async_requests.erase(context_id);
        }
        return;
    }

    const auto* actual_middlewares_to_run = &(_async_middleware); 

    if (index >= actual_middlewares_to_run->size()) {
        // Check again if the context is completed before continuing
        if (chain_ctx.get_processing_stage() == RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) {
            if (_active_async_requests.count(context_id)) {
                 _active_async_requests.erase(context_id);
            }
            return; 
        }

        if (isGlobalChain) {
            chain_ctx.set_processing_stage(RequestProcessingStage::PROCESSING_GLOBAL_SYNC_MIDDLEWARE);
        } else {
            chain_ctx.set_processing_stage(RequestProcessingStage::READY_FOR_HANDLER); 
        }
        route_context(chain_ctx.session, chain_ctx, context_ptr); 
        return;
    }

    (*actual_middlewares_to_run)[index](chain_ctx, 
        [this, context_ptr, index, context_id, isGlobalChain](bool continue_chain) { 
        Context &callback_ctx = *context_ptr; 
        
        // Check if the context was completed in the middleware
        if (callback_ctx.get_processing_stage() == RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) {
            if (_active_async_requests.count(context_id)) {
                _active_async_requests.erase(context_id);
            }
            return;
        }

        if (callback_ctx.is_handled()) {
            if (!callback_ctx.is_async()) { 
                if (!continue_chain) { 
                    callback_ctx.set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
                    if (callback_ctx.session) *callback_ctx.session << callback_ctx.response; 
                    log_request(callback_ctx);
                    _active_async_requests.erase(context_id);
                    return;
                }
            } else { 
                 callback_ctx.set_processing_stage(RequestProcessingStage::AWAITING_HANDLER_ASYNC_COMPLETION);
            }
        }

        if (continue_chain) {
            run_async_middleware_chain(context_ptr, index + 1, isGlobalChain);
        } else if (!callback_ctx.is_handled()){ 
            _active_async_requests.erase(context_id); 
        }
    });
}

// Method for handler processing
template <typename Session, typename String>
void
Router<Session, String>::route_to_handler(Context &ctx, const std::string &path) {
    // Helper lambda to execute route processing potentially after group middlewares
    auto process_route_final = [&](Context& context, Route* route_to_process) {
        route_to_process->process(context);
        context.handled = true;
    };

    // Direct routes (Radix then Regex)
    auto it = _routes.find(ctx.request.method);
    if (it != _routes.end()) {
        Route* matched_route_ptr = nullptr;
        PathParameters final_params;
        std::string matched_path_str;

        auto radix_it = _radix_enabled.find(ctx.request.method);
        if (radix_it != _radix_enabled.end() && radix_it->second) {
            PathParameters params_radix;
            void *handler_ptr = _radix_routes[ctx.request.method].match(path, params_radix);
            if (handler_ptr) {
                matched_route_ptr = static_cast<Route *>(handler_ptr);
                final_params = params_radix;
                matched_path_str = path; // Radix match is on the full path given
                ctx.add_event("radix_route_match_found: " + matched_path_str);
            }
        }

        if (!matched_route_ptr) { // If Radix didn't match or wasn't enabled for method
            for (const auto &route_unique_ptr : it->second) {
                if (auto ar = dynamic_cast<Route *>(route_unique_ptr.get())) {
                    PathParameters params_regex_iter; // ARoute::match(Context&, path) populates ctx.path_params
                    if (ar->match(ctx, path)) { // Modifies ctx with params
                        matched_route_ptr = ar;
                        final_params = ctx.path_params; // Get params from context
                        matched_path_str = ctx.matched_path(); // Get matched path from context
                        ctx.add_event("regex_route_match_found: " + matched_path_str);
                        break;
                    }
                }
            }
        }

        if (matched_route_ptr) {
            ctx.path_params = final_params; // Ensure context has the correct params for this match
            ctx.match = matched_path_str;   // And the correct matched path string

            RouteGroup* parent_group = nullptr;
            for (const auto& group_ptr_sp : _groups) {
                if (matched_path_str.rfind(group_ptr_sp->getPrefix(), 0) == 0) { // Path starts with group prefix
                    parent_group = group_ptr_sp.get();
                    ctx.add_event("route_belongs_to_group: " + parent_group->getPrefix());
                    break;
                }
            }

            if (parent_group && parent_group->typed_middleware_chain()) {
                ctx.add_event("executing_group_middleware_chain_for: " + parent_group->getPrefix());
                MiddlewareResult group_mw_result = parent_group->typed_middleware_chain()->process(ctx, nullptr);
                
                if (group_mw_result.is_async()) {
                    ctx.add_event("group_middleware_returned_async_UNHANDLED_IN_ROUTE_TO_HANDLER");
                    if (!ctx.is_handled()) ctx.mark_async(); // Mark context as async if middleware said so and hasn't handled
                    return; // Exit, expecting async completion elsewhere
                }
                
                if (!group_mw_result.should_stop()) {
                    ctx.add_event("group_middleware_chain_continued_processing_route_handler");
                    process_route_final(ctx, matched_route_ptr);
                } else {
                    ctx.add_event("group_middleware_chain_stopped_request");
                    if (!ctx.is_handled() && group_mw_result.is_error()) {
                        ctx.response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
                        ctx.response.body() = group_mw_result.error_message();
                        ctx.handled = true;
                    } else if (!ctx.is_handled()) {
                        // If stopped but not handled (e.g. middleware just returned Stop without setting response)
                        // This state might need a default error or be considered unhandled.
                        // For now, trust middleware to set ctx.handled if it sent a response.
                    }
                }
            } else {
                ctx.add_event("no_group_middleware_processing_route_handler_directly");
                process_route_final(ctx, matched_route_ptr);
            }
            return; // Route processed (either by group middleware or handler)
        }
    }

    // Controllers
    for (const auto &ctrl_sp : _controllers) {
        const auto &base_path = ctrl_sp->base_path();
        if (path.compare(0, base_path.length(), base_path) == 0) {
            // Save current request URI for later restoration
            std::string original_path = std::string(ctx.request._uri.path());

            // Create a modified request with the relative path
            std::string remaining = path.substr(base_path.length());
            if (remaining.empty())
                remaining = "/";

            ctx.add_event("controller_route");

            qb::io::uri original_uri_for_controller = ctx.request._uri; // Sauvegarde
            ctx.request._uri = qb::io::uri(remaining); // Modification temporaire pour simuler l'ancien comportement
            bool result = ctrl_sp->process(ctx.session, ctx); // Appel original
            ctx.request._uri = original_uri_for_controller; // Restauration pour la suite du code du routeur principal.
                                                        // Idéalement, cette manipulation d'URI ne devrait pas être ici.


            // Restore original URI path
            // ctx.request._uri = qb::io::uri(original_path); // Déjà géré ou modifié par l'approche du point 3

            if (result) {
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
        ctx.handled = true; // Mark request as handled when using default response
        return;
    }

    // Try error handlers
    auto error_it = _error_handlers.find(HTTP_STATUS_NOT_FOUND);
    if (error_it != _error_handlers.end()) {
        ctx.add_event("error_handler_404");
        ctx.response.status_code = HTTP_STATUS_NOT_FOUND;
        error_it->second(ctx);
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
    _cancelled_requests.clear();  // Make sure to clear both tracking structures
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
Router<Session, String>::is_request_cancelled(std::uintptr_t context_id) const {
    // Simply check if the ID exists in the cancelled_requests set
    return _cancelled_requests.find(context_id) != _cancelled_requests.end();
}

// Method to cancel a request (original version)
template <typename Session, typename String>
bool
Router<Session, String>::cancel_request(std::uintptr_t request_id) {
    // Call the overloaded version with default GONE status
    return cancel_request(request_id, HTTP_STATUS_GONE, "Request was cancelled");
}

// Method to cancel a request with custom status code and message
template <typename Session, typename String>
bool
Router<Session, String>::cancel_request(std::uintptr_t request_id, 
                                      http_status status_code,
                                      const std::string& message) {
    // Check if the request exists first
    auto it = _active_async_requests.find(request_id);
    if (it == _active_async_requests.end()) {
        // Don't modify _cancelled_requests for non-existent requests
        return false;
    }
    
    // Add to the cancelled set to mark it as cancelled
    _cancelled_requests.insert(request_id);
    
    // Get a reference to the context
    auto& ctx_ptr = it->second;
    if (ctx_ptr && ctx_ptr->is_session_connected()) {
        // Create a cancellation response with the provided status code and message
        Response cancel_response;
        cancel_response.status_code = status_code;
        cancel_response.body() = message;
        
        try {
            // Send the cancellation response
            *(ctx_ptr->session) << cancel_response;
            
            // Remove from active requests after sending the response
            _active_async_requests.erase(it);
        } catch (...) {
            // Ignore any errors when sending the cancellation response
        }
    }
    return true;
}

// Method to get all active async requests
template <typename Session, typename String>
const qb::unordered_map<std::uintptr_t,
               std::shared_ptr<typename Router<Session, String>::Context>> &
Router<Session, String>::get_active_requests() const {
    return _active_async_requests;
}

} // namespace qb::http
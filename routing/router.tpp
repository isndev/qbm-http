#pragma once
#include "./logging_helpers.h"
#include <qb/uuid.h>
#include "../utility.h"
#include "./router.h"
#include "../body.h"
#include <vector>
#include <string>
#include <optional>

namespace qb::http {

// Constructor
template <typename Session, typename String>
Router<Session, String>::Router()
    : _last_cleanup(std::chrono::steady_clock::now()) {
    // Plus besoin d'initialiser _use_radix_tree
}

// Method to add a controller
template <typename Session, typename String>
template <typename T, typename... Args>
void
Router<Session, String>::controller(Args &&...args) {
    auto ctrl = std::make_shared<T>(std::forward<Args>(args)...);
    _controllers.push_back(ctrl);

    // Add controller base path to Radix tree for all relevant HTTP methods.
    // For simplicity, adding to GET. A real system might add to a special "ANY" method Radix tree for controllers,
    // or register for all common methods if controllers are method-agnostic at the base path level.
    http_method method_to_register_controller_on = HTTP_GET; // Example
    // Or more robustly, a controller could specify methods it responds to at its base, or register for all.

    if (_radix_routes.find(method_to_register_controller_on) == _radix_routes.end()) {
        _radix_routes[method_to_register_controller_on] = RadixTree();
    }
    // Store the raw Controller pointer. Router owns the shared_ptr in _controllers.
    // This relies on the Controller object outliving its use in RadixTree.
    _radix_routes[method_to_register_controller_on].insert(ctrl->base_path(), static_cast<void*>(ctrl.get()), 1000 /* example high priority */, RadixMatchResult::TargetType::CONTROLLER /*is_ctrl_mount*/);
    
    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router::controller] Radix-inserting controller base_path: " + ctrl->base_path() + 
                                                    " for method " + std::to_string(static_cast<int>(method_to_register_controller_on)) + 
                                                    " as controller_mount.");
    }
    // build_radix_trees(); // This call might be redundant if insert itself handles tree structure, 
                          // or should be called once after all routes/controllers are defined.
                          // For now, let individual inserts manage their part of the tree.
                          // If RadixTree::insert calls RadixNode::insert which builds incrementally, this is fine.
                          // However, build_radix_trees() was used to sort _routes and then rebuild from _routes.
                          // The new RadixTree::insert should directly modify the tree.
                          // Let's ensure RadixTree::insert correctly adds to the existing tree.
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

// Method to add a middleware (legacy sync function)
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::use(Middleware legacy_sync_func) { // Middleware is std::function<bool(Context&)> 
    if (!_typed_middleware_chain) {
        _typed_middleware_chain = std::make_shared<MiddlewareChain<Session, String>>();
    }
    auto adapted_middleware = std::make_shared<LegacyMiddlewareAdapter<Session, String>>(std::move(legacy_sync_func));
    _typed_middleware_chain->add(adapted_middleware);
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
    
    _typed_middleware_chain->add(std::move(middleware)); // Add the typed middleware to the dedicated chain
    
    return *this;
}

// Method to add an asynchronous middleware (legacy async function) - RESTORE THIS IMPLEMENTATION
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::use(AsyncMiddleware legacy_async_func) { // AsyncMiddleware is std::function<void(Context&, std::function<void(bool)>)>
    if (!_typed_middleware_chain) {
        _typed_middleware_chain = std::make_shared<MiddlewareChain<Session, String>>();
    }
    auto adapted_middleware = std::make_shared<LegacyMiddlewareAdapter<Session, String>>(std::move(legacy_async_func));
    _typed_middleware_chain->add(adapted_middleware);
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
Router<Session, String>::complete_async_request(std::uintptr_t context_id, Response response_arg, // Renamed for clarity
                                               AsyncRequestState state) {
    std::string router_ptr_str = utility::pointer_to_string_for_log(this);
    
    // Log details of the incoming response_arg
    std::string incoming_body_str = "<incoming_body empty or error converting>";
    try { if(!response_arg.body().empty()) incoming_body_str = response_arg.body().template as<std::string>(); } catch(...) {}
    std::cerr << "[Router::complete_async_request INCOMING] CtxID: " << std::to_string(context_id) 
              << ", Incoming Status: " << response_arg.status_code 
              << ", Incoming Body (repr): " << incoming_body_str.substr(0, 100) // Log more of body
              << ", State: " << std::to_string(static_cast<int>(state)) << std::endl;

    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back(
            "[Router@" + router_ptr_str + "::complete_async_request ENTRY] CtxID: " + std::to_string(context_id) +
            ", ArgStatus: " + std::to_string(response_arg.status_code) + // Log arg status
            ", ArgBody: '" + incoming_body_str + "'" + // Log arg body
            ", State: " + std::to_string(static_cast<int>(state))
        );
    }

    auto it = _active_async_requests.find(context_id);
    if (it == _active_async_requests.end()) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back(
                "[Router@" + router_ptr_str + "::complete_async_request] Context not found for CtxID: " + std::to_string(context_id) + ". Response NOT SENT."
            );
        }
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

    // This is where the original context's response is updated
    ctx.response = std::move(response_arg); 
    
    // Log ctx.response just before sending via session
    std::string ctx_body_before_send_str = "<ctx_body_before_send_empty_or_err>";
    try { if(!ctx.response.body().empty()) ctx_body_before_send_str = ctx.response.body().template as<std::string>(); } catch (...) {}
    std::cerr << "[Router::complete_async_request PRE-SEND] CtxID: " << std::to_string(context_id) 
              << ", ctx.response.status: " << ctx.response.status_code 
              << ", ctx.response.body (repr): " << ctx_body_before_send_str.substr(0, 100) << std::endl;

    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        std::string final_ctx_body_str = "<final_ctx_body empty or error converting>";
        try { if(!ctx.response.body().empty()) final_ctx_body_str = ctx.response.body().template as<std::string>(); } catch(...) {}
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + 
            "::complete_async_request] AFTER MOVE. Sending response. Final Ctx Status: " + std::to_string(ctx.response.status_code) + 
            ", Final Ctx Body: '" + final_ctx_body_str + "'. Path: " + std::string(ctx.request.uri().path()));
    }

    try {
        ctx.add_event("complete_async_request_sending_response");
        if (ctx.session && ctx.is_session_connected()) {
             *ctx.session << ctx.response; 
        }
    } catch (const std::exception& e) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back(
                "[Router@" + router_ptr_str + "::complete_async_request] Send EXCEPTION: " + e.what() +
                " for CtxID: " + std::to_string(context_id)
            );
        }
    } catch (...) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back(
                "[Router@" + router_ptr_str + "::complete_async_request] Send UNKNOWN EXCEPTION for CtxID: " + std::to_string(context_id)
            );
        }
    }
    
    ctx.set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
    _recently_completed_request_signatures.insert(generate_request_signature(ctx.request));
    _active_async_requests.erase(it);
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
        if (session) { // Check if session is not null before dereferencing
        *session << response;
        }
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
    std::string router_ptr_str = utility::pointer_to_string_for_log(this);
    std::string path_for_routing_this_instance;
    
    std::string internal_router_scope_key = "__internal_router_path_scope_" + router_ptr_str;
    bool has_scoped_path_key = ctx.has(internal_router_scope_key);

    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_context_SCOCHECK] Checking for key: '" + internal_router_scope_key + "', Found: " + utility::bool_to_string(has_scoped_path_key));
    }

    if (has_scoped_path_key) {
        path_for_routing_this_instance = ctx.template get<std::string>(internal_router_scope_key);
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_context] Using SCOPED path from context key '" + internal_router_scope_key + "': \"" + path_for_routing_this_instance + "\" (Original ctx.request.uri().path(): \"" + std::string(ctx.request.uri().path()) + "\")");
        }
    } else {
        path_for_routing_this_instance = std::string(ctx.request.uri().path());
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_context] Using REGULAR ctx.request.uri().path(): \"" + path_for_routing_this_instance + "\"");
        }
    }

    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_context ENTRY] PathForThisInstance: \"" + path_for_routing_this_instance + "\", Stage: " + utility::to_string_for_log(ctx.get_processing_stage()) + ", Handled: " + utility::bool_to_string(ctx.is_handled()));
    }

    std::shared_ptr<Context> ctx_ptr_managed = context_ptr;
    if (!ctx_ptr_managed) {
        std::uintptr_t temp_context_id = reinterpret_cast<std::uintptr_t>(&ctx);
        auto active_it = _active_async_requests.find(temp_context_id);
        if (active_it != _active_async_requests.end()) {
            ctx_ptr_managed = active_it->second;
        } else {
            ctx_ptr_managed = std::shared_ptr<Context>(&ctx, [](Context*){/* non-deleting */});
        }
    }
    std::uintptr_t context_id = reinterpret_cast<std::uintptr_t>(ctx_ptr_managed.get());


    RequestProcessingStage initial_check_stage = ctx.get_processing_stage();
    if (initial_check_stage == RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) {
        ctx.add_event("route_context_entry_skipped_response_already_sent_or_completed");
        if (_active_async_requests.count(context_id)) {
            _active_async_requests.erase(context_id);
        }
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_context EXIT - SKIPPED, ALREADY COMPLETED] Path: " + std::string(ctx.request.uri().path()) + ", Stage: " + utility::to_string_for_log(ctx.get_processing_stage()));
        }
        return true; 
    }

    RequestProcessingStage current_stage = ctx.get_processing_stage(); 

    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Effective stage for this call: " + utility::to_string_for_log(current_stage) + " for path " + path_for_routing_this_instance);
    }
    
    if (current_stage == RequestProcessingStage::INITIAL) {
        ctx.add_event("route_context_initial_entry_for_router_instance_" + router_ptr_str );
        // Start with the unified typed global middleware chain
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Stage: INITIAL. Calling process_global_typed_middleware. Path: " + path_for_routing_this_instance);
        }
        if (process_global_typed_middleware(ctx_ptr_managed, path_for_routing_this_instance)) {
            // process_global_typed_middleware returns true if it initiated an async operation and yielded.
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_context EXIT - Handed to Global Typed MW Chain (which went async). Path: " + path_for_routing_this_instance);
            }
            return true; 
        }
        // If false, it means no typed global MW, or it completed synchronously, OR it re-entered route_context.
        // The stage should now be READY_FOR_HANDLER if the chain completed synchronously and continued.
        current_stage = ctx.get_processing_stage(); 
         if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] After process_global_typed_middleware (or no typed MW, or sync completion), new stage: " + utility::to_string_for_log(current_stage) + ". Path: " + path_for_routing_this_instance);
        }
    } 

    // Note: AWAITING_GLOBAL_MIDDLEWARE_CHAIN is handled by the callback within process_global_typed_middleware, 
    // which re-enters route_context. So, we don't need an explicit `if` block for that stage here.
    
    // Log avant la section READY_FOR_HANDLER
    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Checking for READY_FOR_HANDLER. Current Stage: " + utility::to_string_for_log(current_stage) + ". Path: " + path_for_routing_this_instance);
    }

    if (current_stage == RequestProcessingStage::READY_FOR_HANDLER) {
        ctx.add_event("entering_route_to_handler_for_router_instance_" + utility::pointer_to_string_for_log(this) + " effective_path_" + path_for_routing_this_instance);
        std::string path_for_dispatch = path_for_routing_this_instance; 
        
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Stage: READY_FOR_HANDLER. Calling route_to_handler. PathForDispatch: \"" + path_for_dispatch + "\" Current Context Stage: " + utility::to_string_for_log(ctx.get_processing_stage()));
        }
        route_to_handler(ctx, path_for_dispatch); 
        
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Returned from route_to_handler. Path Used: \"" + path_for_dispatch + "\" Stage: " + utility::to_string_for_log(ctx.get_processing_stage()) + ". Handled: " + utility::bool_to_string(ctx.is_handled()));
        } 
        
        if (ctx.is_async()) { 
            if (ctx.is_handled()) {
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Context marked ASYNC after handler. Path: \"" + path_for_routing_this_instance + "\" Router yields.");
                }
                ctx.add_event("handler_marked_request_async_will_await_completion");
                if (ctx.get_processing_stage() != RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) {
                    ctx.set_processing_stage(RequestProcessingStage::AWAITING_HANDLER_ASYNC_COMPLETION);
                }
                if (!_active_async_requests.count(context_id)) {
                    _active_async_requests[context_id] = ctx_ptr_managed; 
                }
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                     adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "::route_context EXIT - Handler initiated ASYNC op, router yields] Path: \"" + path_for_routing_this_instance + "\", Stage: " + utility::to_string_for_log(ctx.get_processing_stage()));
                }
                return true; 
            } else {
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Context marked ASYNC but NOT handled after handler. This is an anomaly. Path: \"" + path_for_routing_this_instance + "\"");
                }
                if (!ctx.is_handled()) {
                    ctx.response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
                    ctx.response.body() = "Async handler did not properly mark request as handled.";
                    ctx.mark_handled();
                    if (session && ctx.is_session_connected()) { try { *session << ctx.response; } catch(...){}}
                    if(_enable_logging) log_request(ctx);
                    ctx.set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
                    if (_active_async_requests.count(context_id)) _active_async_requests.erase(context_id);
                    return true;
                }
            }
        } else if (ctx.is_handled()) { 
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Context HANDLED (sync) after handler. Path: \"" + path_for_routing_this_instance + "\" Status: " + std::to_string(ctx.response.status_code));
            }
            ctx.add_event("handler_completed_synchronously_processing_response");
             
            if (_active_async_requests.count(context_id)) {
                ctx.add_event("sync_handler_resolved_prior_async_chain_removing_from_active_map");
                _active_async_requests.erase(context_id);
            }

            if (!ctx.has("_completed")) {
                if (adv_test_mw_middleware_execution_log.size() < 2000) { adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Calling ctx.complete() for sync handler.");}
                ctx.complete(); 
            } else {
                if (adv_test_mw_middleware_execution_log.size() < 2000) { adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Sync handler already called ctx.complete(). Router verifies stage.");}
            }
            if(ctx.get_processing_stage() != RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) {
                 ctx.set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
            }
            if (_active_async_requests.count(context_id)) { _active_async_requests.erase(context_id);}
            _recently_completed_request_signatures.insert(generate_request_signature(ctx.request));
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                 adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "::route_context EXIT - Sync handler completed] Path: \"" + path_for_routing_this_instance + "\" Stage: " + utility::to_string_for_log(ctx.get_processing_stage()));
            }
            return true; 
        } else {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                 adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] route_to_handler finished but context NOT handled. Falling to 404. Path: \"" + path_for_routing_this_instance + "\"");
            }
            ctx.add_event("handler_did_not_handle_falling_through_to_404_logic");
        }
    }
    
    std::uintptr_t current_context_id = reinterpret_cast<std::uintptr_t>(ctx_ptr_managed.get());
    if (_active_async_requests.count(current_context_id) && 
        ctx.get_processing_stage() != RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "::route_context EXIT - Yielding for ACTIVE ASYNC request] Path: " + path_for_routing_this_instance + ", Stage: " + utility::to_string_for_log(ctx.get_processing_stage()) + ", is_async_flag: " + utility::bool_to_string(ctx.is_async()));
        }
        return true; 
    }

    RequestProcessingStage final_processing_stage = ctx.get_processing_stage();
    
    if (final_processing_stage != RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED && !ctx.is_async()) {

        if (!ctx.is_handled()) { 
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
                 ctx.add_event("final_creating_generic_404_response");
                 ctx.response.status_code = HTTP_STATUS_NOT_FOUND; 
                 ctx.response.body() = "Not Found";
                 ctx.mark_handled(); 
            }
        }

        if (ctx.is_handled() && !(ctx.is_async() && _active_async_requests.count(context_id))) { 
            if (!ctx.has("_completed")) {
                ctx.add_event("final_sending_404_or_default_response_by_router");
                ctx.execute_after_callbacks();
                if (session && ctx.is_session_connected()) { try {*session << ctx.response;} catch(...){/*log*/} }
                if (_enable_logging) log_request(ctx);
                ctx.execute_done_callbacks(); 
            }
            ctx.set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
            _recently_completed_request_signatures.insert(generate_request_signature(ctx.request));
        } else if (ctx.is_handled() && (ctx.is_async() && _active_async_requests.count(context_id))) {
            ctx.add_event("final_response_deferred_to_async_after_404_logic");
        }
    }

    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_context EXIT] EffectivePath: \"" + path_for_routing_this_instance + "\" Final Stage: " + utility::to_string_for_log(ctx.get_processing_stage()) + ", Handled: " + utility::bool_to_string(ctx.is_handled()) + ". Async: " + utility::bool_to_string(ctx.is_async()));
    }
    return ctx.is_handled();
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
        if (_radix_routes.find(method) == _radix_routes.end()) {                   \
            _radix_routes[method] = RadixTree();                                   \
        }                                                                          \
                                                                                       \
        /* Add the route to the radix tree */                                      \
        Route *ar = dynamic_cast<Route *>(_routes[method].back().get());           \
        if (ar) {                                                                  \
            _radix_routes[method].insert(ar->path(), static_cast<void*>(ar), ar->priority(), RadixMatchResult::TargetType::HANDLER);          \
        }                                                                          \
                                                                                       \
        sort_routes(method);                                                           \
        build_radix_trees();                                                           \
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
        if (_radix_routes.find(method) == _radix_routes.end()) {                   \
            _radix_routes[method] = RadixTree();                                   \
        }                                                                          \
                                                                                       \
        /* Add the route to the radix tree */                                      \
        Route *ar = dynamic_cast<Route *>(_routes[method].back().get());           \
        if (ar) {                                                                  \
            _radix_routes[method].insert(ar->path(), static_cast<void*>(ar), ar->priority(), RadixMatchResult::TargetType::HANDLER);          \
        }                                                                          \
                                                                                       \
        sort_routes(method);                                                           \
        build_radix_trees();                                                           \
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
                               AsyncRequestState::TIMEOUT);
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

// Method for handler processing
template <typename Session, typename String>
void
Router<Session, String>::route_to_handler(Context &ctx, const std::string &path_for_matching) {
    std::string router_ptr_str = utility::pointer_to_string_for_log(this);
    std::shared_ptr<Context> ctx_ptr_managed;

    std::uintptr_t current_context_id_for_map_lookup = reinterpret_cast<std::uintptr_t>(&ctx);
    auto it_active_for_handler = _active_async_requests.find(current_context_id_for_map_lookup);
    if (it_active_for_handler != _active_async_requests.end()) {
        ctx_ptr_managed = it_active_for_handler->second;
    } else {
        ctx_ptr_managed = std::shared_ptr<Context>(&ctx, [](Context*){/* non-deleting */});
    }
    std::uintptr_t context_id_for_async = reinterpret_cast<std::uintptr_t>(ctx_ptr_managed.get());

    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler ENTRY] PathForMatching: " + path_for_matching + ". Method: " + std::to_string(static_cast<int>(ctx.request.method)) + ". Current Stage: " + utility::to_string_for_log(ctx.get_processing_stage()));
    }

    auto process_route_final_lambda = [this, router_ptr_str](Context& context_ref, ARoute<Session, String>* route_to_process_ptr) {
        if (!route_to_process_ptr) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) { adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "::r_t_h::process_route_final_lambda] route_to_process_ptr is NULL. Path: " + std::string(context_ref.request.uri().path())); }
            return;
        }
        if (adv_test_mw_middleware_execution_log.size() < 2000) { adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "::r_t_h::process_route_final_lambda] Calling route->process() for path: " + route_to_process_ptr->getPath() + ". Stage: " + utility::to_string_for_log(context_ref.get_processing_stage()));}
        
        RequestProcessingStage stage_before_handler = context_ref.get_processing_stage();
        if(stage_before_handler != RequestProcessingStage::HANDLER_PROCESSING && stage_before_handler != RequestProcessingStage::AWAITING_HANDLER_ASYNC_COMPLETION) {
             context_ref.set_processing_stage(RequestProcessingStage::HANDLER_PROCESSING);
        }
        route_to_process_ptr->process(context_ref); 
        
        if (adv_test_mw_middleware_execution_log.size() < 2000) { adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "::r_t_h::process_route_final_lambda] Returned from route->process(). Path: " + route_to_process_ptr->getPath() + ". Handled: " + utility::bool_to_string(context_ref.is_handled()) + ". Async: " + utility::bool_to_string(context_ref.is_async()));}
    };

    // Lookup route from RadixTree
    std::optional<RadixMatchResult> radix_result_opt = std::nullopt;
    
    // Try all HTTP methods if we need to find parameters but don't need the actual handler
    // This is useful for OPTIONS requests and debugging
    bool extract_params_only = false;
    
    if (ctx.request.method == HTTP_OPTIONS || ctx.has("__extract_params_only")) {
        extract_params_only = true;
    }
    
    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Looking up path: " + path_for_matching + " with method: " + std::to_string(static_cast<int>(ctx.request.method)) + 
        (extract_params_only ? " (extract_params_only)" : ""));
    }

    if (extract_params_only) {
        // Try all methods, take the first match with parameters
        for (const auto& [method, radix_tree] : _radix_routes) {
            auto temp_result = radix_tree.match(path_for_matching);
            if (temp_result && !temp_result->params.empty()) {
                radix_result_opt = temp_result;
                break;
            }
        }
    } else if (_radix_routes.count(ctx.request.method)) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Attempting RadixTree.match for method " + std::to_string(static_cast<int>(ctx.request.method)) + " with path: " + path_for_matching);
        }
        radix_result_opt = _radix_routes.at(ctx.request.method).match(path_for_matching); 
    }

    if (!radix_result_opt) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] No route found for path: " + path_for_matching);
            
            // Debug info: list all available routes in RadixTree
            if (_radix_routes.count(ctx.request.method)) {
                std::stringstream routes_debug;
                routes_debug << "Available routes for method " << std::to_string(static_cast<int>(ctx.request.method)) << ": ";
                int count = 0;
                for (const auto& route_ptr : _routes.at(ctx.request.method)) {
                    routes_debug << route_ptr->getPath() << ", ";
                    count++;
                }
                adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] " + routes_debug.str() + " (Total: " + std::to_string(count) + ")");
            }
        }
    }

    if (radix_result_opt && radix_result_opt->target_ptr) {
        RadixMatchResult& radix_result = *radix_result_opt;
        if (adv_test_mw_middleware_execution_log.size() < 2000) { 
            std::string params_str;
            for(const auto& p : radix_result.params) { params_str += " [" + p.first + ":" + p.second + "]"; }
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] RadixResult: Type=" + std::to_string((int)radix_result.type) + 
                " Target=" + utility::pointer_to_string_for_log(radix_result.target_ptr) + 
                " MatchedPrefix='" + radix_result.matched_path_prefix + 
                "' Remaining='" + radix_result.remaining_path + 
                "' Params:" + params_str);
        }

        // Add all parameters from the matching result to the context
        for (const auto& p : radix_result.params) {
            ctx.path_params[p.first] = p.second; 
        }
        ctx.match = radix_result.matched_path_prefix; 
        
        // If we only needed parameters, we can return now
        if (extract_params_only) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Parameters extracted for OPTIONS or debugging, returning early");
            }
            return;
        }

        if (radix_result.type == RadixMatchResult::TargetType::HANDLER) {
            ARoute<Session, String>* route_ptr = static_cast<ARoute<Session, String>*>(radix_result.target_ptr);
            if (adv_test_mw_middleware_execution_log.size() < 2000) { adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Radix MATCHED direct route: " + route_ptr->getPath());}
            
            // Find all matching groups for the current route path
            std::vector<RouteGroup*> parent_groups;
            std::string route_path = route_ptr->getPath();
            
            // First identify all potential parent groups
            for (const auto& group_ptr_sp : _groups) {
                // Check if the route's path starts with this group's prefix
                if (!route_path.empty() && !group_ptr_sp->getPrefix().empty()) {
                    // Proper prefix matching - ensure path starts with group prefix
                    size_t prefix_pos = route_path.find(group_ptr_sp->getPrefix());
                    if (prefix_pos == 0) {
                        // Found a potential parent group
                        parent_groups.push_back(group_ptr_sp.get());
                        
                        if (adv_test_mw_middleware_execution_log.size() < 2000) {
                            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Found parent group: " + 
                                group_ptr_sp->getPrefix() + " for route " + route_path);
                        }
                    }
                }
            }
            
            // Sort groups by prefix length to process from most specific to general
            std::sort(parent_groups.begin(), parent_groups.end(), 
                [](const RouteGroup* a, const RouteGroup* b) {
                    return a->getPrefix().length() > b->getPrefix().length();
                });
            
            // Build the actual hierarchy with parent-child relationships
            std::vector<RouteGroup*> ordered_groups;
            
            // First, find any root level groups (those without parent groups)
            for (auto* group : parent_groups) {
                bool has_parent = false;
                for (auto* potential_parent : parent_groups) {
                    if (group != potential_parent && 
                        group->getPrefix().find(potential_parent->getPrefix()) == 0 &&
                        group->getPrefix().length() > potential_parent->getPrefix().length()) {
                        has_parent = true;
                        break;
                    }
                }
                
                if (!has_parent) {
                    // This is a root level group
                    ordered_groups.push_back(group);
                    
                    // Now add all its descendants in order
                    std::function<void(RouteGroup*)> add_children = [&](RouteGroup* parent) {
                        for (auto* potential_child : parent_groups) {
                            if (potential_child != parent && 
                                potential_child->getPrefix().find(parent->getPrefix()) == 0 &&
                                potential_child->getPrefix().length() > parent->getPrefix().length()) {
                                
                                // Check if this is a direct child (no intermediate groups)
                                bool is_direct_child = true;
                                for (auto* intermediate : parent_groups) {
                                    if (intermediate != parent && intermediate != potential_child &&
                                        potential_child->getPrefix().find(intermediate->getPrefix()) == 0 &&
                                        intermediate->getPrefix().find(parent->getPrefix()) == 0 &&
                                        intermediate->getPrefix().length() > parent->getPrefix().length() &&
                                        intermediate->getPrefix().length() < potential_child->getPrefix().length()) {
                                        is_direct_child = false;
                                        break;
                                    }
                                }
                                
                                if (is_direct_child) {
                                    ordered_groups.push_back(potential_child);
                                    add_children(potential_child);
                                }
                            }
                        }
                    };
                    
                    add_children(group);
                }
            }
            
            if (!ordered_groups.empty() && adv_test_mw_middleware_execution_log.size() < 2000) {
                std::string groups_log = "Ordered group hierarchy for route " + route_path + ": ";
                for (const auto& g : ordered_groups) {
                    groups_log += g->getPrefix() + " -> ";
                }
                adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] " + groups_log);
            }

            // Track if we need to use async processing
            bool uses_async_group_mw = false;
            
            // If we have parent groups with middleware, process them in sequence
            if (!ordered_groups.empty()) {
                // Define a std::function that can be self-referential for recursive process
                std::function<void(std::size_t, MiddlewareResult)> process_group_middleware;
                
                process_group_middleware = [&](std::size_t group_index, MiddlewareResult current_result) {
                    // If we've processed all groups or the chain should stop, call the final handler
                    if (group_index >= ordered_groups.size() || current_result.should_stop()) {
                        if (current_result.should_stop()) {
                            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                                adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Group middleware chain stopped. Not processing handler.");
                            }
                            
                            // If the request isn't handled but the chain is stopped, set a default error response
                            if (!ctx.is_handled()) {
                                ctx.status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
                                ctx.body("Middleware chain stopped without handling the request");
                                ctx.mark_handled();
                                ctx.complete();
                            }
                            return;
                        }
                        
                        // All middleware processed successfully, call the final handler
                        process_route_final_lambda(ctx, route_ptr);
                        return;
                    }
                    
                    // Get the current group to process
                    RouteGroup* current_group = ordered_groups[group_index];
                    
                    // Make sure all parameters from group's path pattern are available
                    if (route_path.find(current_group->getPrefix()) == 0) {
                        // Extract parameters from group prefix if it contains patterns
                        if (current_group->getPrefix().find(':') != std::string::npos || 
                            current_group->getPrefix().find('{') != std::string::npos) {
                            
                            std::string group_prefix = current_group->getPrefix();
                            auto group_match_opt = RadixTree::extract_params_from_path_pattern(
                                group_prefix, route_path.substr(0, group_prefix.length()));
                                
                            if (group_match_opt && !group_match_opt->params.empty()) {
                                // Add group-level parameters to context
                                for (const auto& p : group_match_opt->params) {
                                    ctx.path_params[p.first] = p.second;
                                    
                                    if (adv_test_mw_middleware_execution_log.size() < 2000) {
                                        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + 
                                        "]::route_to_handler] Added group parameter from " + current_group->getPrefix() + 
                                        ": " + p.first + "=" + p.second);
                                    }
                                }
                            }
                        }
                    }
                    
                    // Process its typed middleware if any
                    auto typed_mw_chain = current_group->typed_middleware_chain();
                    if (typed_mw_chain && typed_mw_chain->get_middleware_count() > 0) {
                        if (adv_test_mw_middleware_execution_log.size() < 2000) {
                            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Processing typed middleware for group: " + current_group->getPrefix());
                        }
                        
                        // Create a callback for when this group's middleware finishes
                        auto next_group_callback = [&process_group_middleware, group_index, router_ptr_str, current_group](MiddlewareResult result) {
                            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                                adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Group middleware chain " + 
                                    (result.should_stop() ? "STOPPED" : "CONTINUED") + " for group: " + current_group->getPrefix());
                            }
                            
                            // Process the next group once this one completes
                            process_group_middleware(group_index + 1, result);
                        };
                        
                        // Process this group's middleware chain
                        MiddlewareResult group_mw_result = typed_mw_chain->process(ctx, next_group_callback);
                        
                        // If the middleware chain runs asynchronously, we're done for now
                        if (group_mw_result.is_async()) {
                            uses_async_group_mw = true;
                            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                                adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Group middleware chain is async for group: " + current_group->getPrefix());
                            }
                            return;
                        }
                        
                        // If the middleware completed synchronously but wants to stop, don't process further
                        if (group_mw_result.should_stop()) {
                            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                                adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Group middleware chain stopped synchronously for group: " + current_group->getPrefix());
                            }
                            
                            // Handle the response if not already handled
                            if (!ctx.is_handled()) {
                                ctx.status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
                                ctx.body("Middleware chain stopped without handling the request");
                                ctx.mark_handled();
                                ctx.complete();
                            }
                            return;
                        }
                    }
                    else {
                        if (adv_test_mw_middleware_execution_log.size() < 2000) {
                            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] No typed middleware for group: " + current_group->getPrefix());
                        }
                    }
                    
                    // Process legacy middleware for this group (if any)
                    for (const auto& legacy_mw : current_group->middleware()) {
                        if (!legacy_mw(ctx)) {
                            // Legacy middleware wants to stop the chain
                            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                                adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Legacy middleware stopped chain for group: " + current_group->getPrefix());
                            }
                            
                            // Handle the response if not already handled
                            if (!ctx.is_handled()) {
                                ctx.status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
                                ctx.body("Legacy middleware stopped chain without handling the request");
                                ctx.mark_handled();
                                ctx.complete();
                            }
                            return;
                        }
                    }
                    
                    // If we got here, this group's middleware is done and wants to continue
                    // Process the next group
                    process_group_middleware(group_index + 1, MiddlewareResult::Continue());
                };
                
                // Start processing the first group
                process_group_middleware(0, MiddlewareResult::Continue());
                
                // If we used async middleware, we need to return now - the async callbacks will continue the chain
                if (uses_async_group_mw) {
                    if (adv_test_mw_middleware_execution_log.size() < 2000) {
                        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Using async group middleware - returning early");
                    }
                    
                    // Register as async request if it isn't already
                    if (!_active_async_requests.count(context_id_for_async)) {
                        _active_async_requests[context_id_for_async] = ctx_ptr_managed;
                    }
                    return;
                }
            } else {
                // No parent groups, just process the route directly
                process_route_final_lambda(ctx, route_ptr);
            }
            
            // The handler has been called or the middleware has stopped the chain,
            // so we're done for this request
            if (ctx.is_handled() || ctx.is_async()) {
                 if (adv_test_mw_middleware_execution_log.size() < 2000) { adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Direct route processed (or async). Handled: " + utility::bool_to_string(ctx.is_handled()) + ", Async: " + utility::bool_to_string(ctx.is_async()));}
                return;
            }

        } else if (radix_result.type == RadixMatchResult::TargetType::CONTROLLER) {
            Controller* controller_ptr = static_cast<Controller*>(radix_result.target_ptr);
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                 adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Radix MATCHED controller. Base: " + controller_ptr->base_path() + ". Relative Path for controller: " + radix_result.remaining_path + "");
            }
            
            // Preserve original path parameters before passing control to controller
            auto original_params = ctx.path_params;
            
            ctx.set_processing_stage(RequestProcessingStage::HANDLER_PROCESSING); 
            bool controller_handled = controller_ptr->process(ctx.session, ctx, radix_result.remaining_path); 
            
            // Merge any new parameters from controller with original ones
            // This ensures parameters from parent router are not lost
            for (const auto& [key, value] : original_params) {
                if (ctx.path_params.find(key) == ctx.path_params.end()) {
                    ctx.path_params[key] = value;
                }
            }
            
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                 adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] Controller process returned. Handled by controller: " + utility::bool_to_string(controller_handled) + ". Ctx Handled: " + utility::bool_to_string(ctx.is_handled()) + ". Ctx Async: " + utility::bool_to_string(ctx.is_async()) );
            }
            if (controller_handled || ctx.is_handled() || ctx.is_async()) return; 
        }
    } else { 
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
           adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler] RadixTree match FAILED or no target_ptr for path: " + path_for_matching);
        }
    } 

    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "]::route_to_handler EXIT] PathForMatching: " + path_for_matching + ". Handled: " + utility::bool_to_string(ctx.is_handled()) + ". Async: " + utility::bool_to_string(ctx.is_async()) + ". Stage: " + utility::to_string_for_log(ctx.get_processing_stage()) );
    }
}

// Method to build radix trees for all HTTP methods
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::build_radix_trees() {
    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + "]::build_radix_trees] Building for " + std::to_string(_routes.size()) + " methods total in _routes map.");
    }
    
    // Start fresh with new RadixTrees for each method
    _radix_routes.clear();
    
    // Initialize radix trees for all HTTP methods
    for (const auto& [method, _] : _routes) {
        _radix_routes[method] = RadixTree();
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + 
                                                  "]::build_radix_trees] Created RadixTree for method " + 
                                                  std::to_string(static_cast<int>(method)));
        }
    }
    
    // If we have no trees initialized yet, create one for GET to start
    if (_radix_routes.empty()) {
        _radix_routes[HTTP_GET] = RadixTree();
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + 
                                                  "]::build_radix_trees] Created initial RadixTree for GET method");
        }
    }
    
    // Process all routes in the main router
    for (const auto &[method, routes_for_method] : _routes) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + "]::build_radix_trees] Processing method: " + std::to_string(static_cast<int>(method)) + " with " + std::to_string(routes_for_method.size()) + " routes.");
        }
        if (!routes_for_method.empty()) {
            for (const auto &route : routes_for_method) {
                // Ajouter chaque route explicitement au RadixTree
                Route *route_ptr = dynamic_cast<Route *>(route.get());
                if (route_ptr) {
                    if (adv_test_mw_middleware_execution_log.size() < 2000) {
                        adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + 
                                                                  "]::build_radix_trees] Adding route: " + route_ptr->getPath() + 
                                                                  " to RadixTree for method " + std::to_string(static_cast<int>(method)));
                    }
                    _radix_routes[method].insert(route_ptr->getPath(), 
                                               static_cast<void*>(route_ptr), 
                                               route_ptr->priority(),
                                               RadixMatchResult::TargetType::HANDLER);
                }
            }
        }
    }
    
    // Now ensure all controllers are properly registered in the RadixTree
    // Controllers need to be registered for all relevant HTTP methods
    // since they can handle multiple types of requests
    const std::vector<http_method> controller_methods = {
        HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_DELETE, HTTP_PATCH, 
        HTTP_OPTIONS, HTTP_HEAD
    };
    
    for (const auto& controller : _controllers) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + 
                                                     "]::build_radix_trees] Processing controller: " + controller->base_path());
        }
        
        // Register the controller for all HTTP methods it might handle
        for (const auto& method : controller_methods) {
            // Create the radix tree for this method if it doesn't exist
            if (_radix_routes.find(method) == _radix_routes.end()) {
                _radix_routes[method] = RadixTree();
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + 
                                                          "]::build_radix_trees] Created RadixTree for method " + 
                                                          std::to_string(static_cast<int>(method)) + 
                                                          " for controller " + controller->base_path());
                }
            }
            
            // Register the controller's base path
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + 
                                                        "]::build_radix_trees] Adding controller: " + controller->base_path() + 
                                                        " to RadixTree for method " + std::to_string(static_cast<int>(method)));
            }
            
            _radix_routes[method].insert(
                controller->base_path(), 
                static_cast<void*>(controller.get()), 
                1000, // Controllers get high priority
                RadixMatchResult::TargetType::CONTROLLER
            );
        }
        
        // Also examine the controller's internal router for routes
        // This helps with path parameter extraction for OPTIONS requests
        // and for debugging parameter hierarchy issues
        for (const auto& method : controller_methods) {
            const auto& controller_routes = controller->router().getRoutes(method);
            for (const auto& route : controller_routes) {
                // Extract the relative path from the controller's base path
                std::string route_path = route->getPath();
                if (route_path.find(controller->base_path()) == 0) {
                    std::string relative_path = route_path.substr(controller->base_path().length());
                    
                    // Register parameter patterns for the controller subtree
                    if ((relative_path.find(':') != std::string::npos || 
                         relative_path.find('{') != std::string::npos) && 
                         adv_test_mw_middleware_execution_log.size() < 2000) {
                        
                        adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + 
                                                               "]::build_radix_trees] Controller parameter pattern: " + 
                                                               controller->base_path() + " -> " + relative_path);
                    }
                }
            }
        }
    }
    
    // Verify and log group hierarchy information
    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + 
                                                 "]::build_radix_trees] Verifying group hierarchy (" + 
                                                 std::to_string(_groups.size()) + " groups)");
    }
    
    // Log group hierarchy for debugging
    if (adv_test_mw_middleware_execution_log.size() < 2000 && !_group_hierarchy.empty()) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + 
                                                 "]::build_radix_trees] Group hierarchy relationships: " + 
                                                 std::to_string(_group_hierarchy.size()) + " parent groups");
        
        for (const auto& [parent, children] : _group_hierarchy) {
            std::string hierarchy_log = "Parent: " + parent->getPrefix() + " -> Children: ";
            for (const auto& child : children) {
                hierarchy_log += child->getPrefix() + ", ";
            }
            adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + 
                                                     "]::build_radix_trees] " + hierarchy_log);
        }
    }
    
    // Verify that all groups have their middleware properly set up
    for (const auto& group : _groups) {
        if (group->typed_middleware_chain() && 
            group->typed_middleware_chain()->get_middleware_count() > 0 && 
            adv_test_mw_middleware_execution_log.size() < 2000) {
            
            adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + 
                                                    "]::build_radix_trees] Group " + group->getPrefix() + 
                                                    " has " + std::to_string(group->typed_middleware_chain()->get_middleware_count()) + 
                                                    " middleware(s)");
        }
    }
    
    return *this;
}

// Method to clear all active async requests
template <typename Session, typename String>
void
Router<Session, String>::clear_all_active_requests() {
    // ... entire body ...
}

// Method to configure the maximum number of concurrent requests
template <typename Session, typename String>
Router<Session, String> &
Router<Session, String>::configure_max_concurrent_requests(size_t max_requests) {
    // ... entire body ...
}

// Method to check if a request has been cancelled
template <typename Session, typename String>
bool
Router<Session, String>::is_request_cancelled(std::uintptr_t context_id) const {
    // ... entire body ...
}

// Method to cancel a request (original version)
template <typename Session, typename String>
bool
Router<Session, String>::cancel_request(std::uintptr_t request_id) {
    // ... entire body ...
}

// Method to cancel a request with custom status code and message
template <typename Session, typename String>
bool
Router<Session, String>::cancel_request(std::uintptr_t request_id, 
                                      http_status status_code,
                                      const std::string& message) {
    // ... entire body ...
}

// Method to get all active async requests
template <typename Session, typename String>
const qb::unordered_map<std::uintptr_t,
               std::shared_ptr<typename Router<Session, String>::Context>> &
Router<Session, String>::get_active_requests() const {
    // ... entire body ...
}

// Implementation of process_global_typed_middleware (This is the one that remains and is used)
template <typename Session, typename String>
bool
Router<Session, String>::process_global_typed_middleware(std::shared_ptr<Context> context_ptr, const std::string& path_for_routing_this_instance) {
    if (!context_ptr) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(this) + "] process_global_typed_middleware: CRITICAL ERROR - Null context_ptr");
        }
        return false;
    }

    Context &ctx = *context_ptr; 
    std::string router_ptr_str = utility::pointer_to_string_for_log(this);

    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] process_global_typed_middleware: Context@" + utility::pointer_to_string_for_log(&ctx));
    }

    // Early return if no middlewares defined
    if (!_typed_middleware_chain || _typed_middleware_chain->get_middleware_count() == 0) {
        // Set ready for handler stage
        ctx.set_processing_stage(RequestProcessingStage::READY_FOR_HANDLER);
        return false; // No middlewares to process, continue to handler directly
    }

    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Starting global typed middleware chain with " + 
            std::to_string(_typed_middleware_chain->get_middleware_count()) + " middleware(s)");
    }

    // Pre-extract route parameters so they're available to middleware
    // This helps with tests where URL parameters need to be accessed by middleware
    if (!path_for_routing_this_instance.empty()) {
        // Try to find matching routes for this path to extract parameters early
        for (const auto& [method, radix_tree] : _radix_routes) {
            auto radix_match_opt = radix_tree.match(path_for_routing_this_instance);
            if (radix_match_opt && !radix_match_opt->params.empty()) {
                // Add all parameters from the matching result to the context
                for (const auto& p : radix_match_opt->params) {
                    ctx.path_params[p.first] = p.second;
                }
                
                // Log the parameters found
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    std::string param_log = "Pre-extracted parameters from method " + 
                        std::to_string(static_cast<int>(method)) + ": ";
                    for (const auto& p : radix_match_opt->params) {
                        param_log += p.first + "=" + p.second + " ";
                    }
                    adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] " + param_log);
                }
                
                // Save the matched prefix for context routing
                ctx.match = radix_match_opt->matched_path_prefix;
                
                // Once we find parameters, don't keep checking other methods
                // This avoids multiple matches with conflicting parameters
                break;
            }
        }
    }

    // Register context in active async requests if it isn't already
    std::uintptr_t context_id = reinterpret_cast<std::uintptr_t>(context_ptr.get());
    if (!_active_async_requests.count(context_id)) {
        _active_async_requests[context_id] = context_ptr;
    }

    // Create a strong reference to this router that will exist in the lambda closure
    auto router_self = std::shared_ptr<Router<Session, String>>(this, [](Router<Session, String>*){/* non-deleting */});
    auto safe_path = path_for_routing_this_instance;

    // Define a callback that continues the chain when all middlewares are done
    auto middleware_callback = [router_self, context_ptr, safe_path, context_id](MiddlewareResult result) {
        if (!context_ptr) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[Router@" + utility::pointer_to_string_for_log(router_self.get()) + 
                    "] Global middleware callback with NULL context_ptr!");
            }
            return;
        }

        Context& safe_ctx = *context_ptr;
        std::string self_ptr_str = utility::pointer_to_string_for_log(router_self.get());
        
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + self_ptr_str + "] Global middleware chain callback with result: " + 
                (result.is_error() ? "ERROR: " + result.error_message() : 
                result.should_stop() ? "STOP" : 
                result.is_async() ? "ASYNC" : "CONTINUE"));
        }

        if (safe_ctx.get_processing_stage() == RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                adv_test_mw_middleware_execution_log.push_back("[Router@" + self_ptr_str + 
                    "] Global middleware callback - context already completed. Skipping further processing.");
            }
            
            // Clean up active request
            router_self->_active_async_requests.erase(context_id);
            return;
        }
        
        if (result.is_error() || result.should_stop()) {
            // If middleware chain stopped without handling the request, set an error response
            if (!safe_ctx.is_handled()) {
                safe_ctx.response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
                safe_ctx.response.body() = result.is_error() ? 
                    "Middleware error: " + result.error_message() :
                    "Middleware chain stopped without a handled response.";
                safe_ctx.mark_handled();
                
                try {
                    if (safe_ctx.session && safe_ctx.is_session_connected()) {
                        *(safe_ctx.session) << safe_ctx.response;
                    }
                } catch (const std::exception& e) {
                    if (adv_test_mw_middleware_execution_log.size() < 2000) {
                        adv_test_mw_middleware_execution_log.push_back("[Router@" + self_ptr_str + 
                            "] Exception sending response after middleware chain stop/error: " + std::string(e.what()));
                    }
                } catch (...) {
                    if (adv_test_mw_middleware_execution_log.size() < 2000) {
                        adv_test_mw_middleware_execution_log.push_back("[Router@" + self_ptr_str + 
                            "] Unknown exception sending response after middleware chain stop/error");
                    }
                }
                
                safe_ctx.set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
                router_self->_active_async_requests.erase(context_id);
            }
        } else {
            // Preserve any path parameters discovered during middleware execution
            // This fixes issues where path parameters were lost between middleware and handler
            if (!safe_ctx.path_params.empty()) {
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    std::string param_log = "Preserving parameters after middleware: ";
                    for (const auto& p : safe_ctx.path_params) {
                        param_log += p.first + "=" + p.second + " ";
                    }
                    adv_test_mw_middleware_execution_log.push_back("[Router@" + self_ptr_str + "] " + param_log);
                }
            }
            
            // Middleware chain completed successfully, continue to handler
            safe_ctx.set_processing_stage(RequestProcessingStage::READY_FOR_HANDLER);
            
            // If context was async due to middleware but now completed, clear async state
            if (!result.is_async() && safe_ctx.is_async() && !safe_ctx.handler_initiated_async()) {
                safe_ctx.clear_async_state_for_chain_completion();
            }
            
            // Continue routing with the same context
            std::string internal_router_scope_key = "__internal_router_path_scope_" + self_ptr_str;
            router_self->route_context(safe_ctx.session, safe_ctx, context_ptr);
        }
    };

    // Process the middleware chain
    ctx.set_processing_stage(RequestProcessingStage::AWAITING_GLOBAL_MIDDLEWARE_CHAIN);
    auto middleware_result = _typed_middleware_chain->process(ctx, middleware_callback);

    if (adv_test_mw_middleware_execution_log.size() < 2000) {
        adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Global middleware chain immediate result: " + 
            (middleware_result.is_error() ? "ERROR: " + middleware_result.error_message() : 
            middleware_result.should_stop() ? "STOP" : 
            middleware_result.is_async() ? "ASYNC" : "CONTINUE"));
    }

    // If middleware chain is async, return true to yield control
    if (middleware_result.is_async()) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + "] Async middleware chain will continue via callbacks");
        }
        return true;
    }

    // If middleware chain returned error or explicitly stopped
    if (middleware_result.is_error() || middleware_result.should_stop()) {
        if (!ctx.is_handled()) {
            // Set an error response if middleware chain stopped without handling the request
            ctx.response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
            ctx.response.body() = middleware_result.is_error() ? 
                "Middleware error: " + middleware_result.error_message() :
                "Middleware chain stopped without a handled response.";
            ctx.mark_handled();
            
            try {
                if (ctx.session && ctx.is_session_connected()) {
                    *(ctx.session) << ctx.response;
                }
            } catch (const std::exception& e) {
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + 
                        "] Exception sending response after sync middleware chain stop/error: " + std::string(e.what()));
                }
            } catch (...) {
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    adv_test_mw_middleware_execution_log.push_back("[Router@" + router_ptr_str + 
                        "] Unknown exception sending response after sync middleware chain stop/error");
                }
            }
            
            ctx.set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
            _active_async_requests.erase(context_id);
        }
        return false;
    }

    // Middleware chain completed synchronously and successfully
    ctx.set_processing_stage(RequestProcessingStage::READY_FOR_HANDLER);
    return false; // Continue to handler
}

} // namespace qb::http
#pragma once

#include <any>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <type_traits>
#include "../request.h"
#include "../response.h"
#include "./async_types.h"
#include "./path_parameters.h"
#include "./logging_helpers.h"
#include "./async_completion_handler.h"

# if defined(_WIN32)
#undef DELETE // Windows :/
#endif

namespace qb::http {

// enum class RequestProcessingStage { // MOVED TO async_types.h
// INITIAL,
// PROCESSING_GLOBAL_SYNC_MIDDLEWARE,
// AWAITING_GLOBAL_ASYNC_MIDDLEWARE,
// PROCESSING_GROUP_MIDDLEWARE,
// AWAITING_GROUP_ASYNC_MIDDLEWARE,
// READY_FOR_HANDLER,
// HANDLER_PROCESSING,
// AWAITING_HANDLER_ASYNC_COMPLETION,
// RESPONSE_SENT_OR_COMPLETED,
// ERROR_HANDLED
// };

// Forward declarations
template <typename Session, typename String>
class Router;

template <typename Session, typename String>
class AsyncCompletionHandler;

namespace detail {
// Trait to detect if a class has an is_connected() method
template <typename T, typename = void>
struct has_method_is_connected : std::false_type {};

#if __cplusplus >= 201703L
template <typename T>
struct has_method_is_connected<T, std::void_t<decltype(std::declval<T>().is_connected())>> : std::true_type {};
#else
// Manual void_t for C++11/14 if std::void_t is not found by linter
// template<typename...> using void_t = void;
// template <typename T>
// struct has_method_is_connected<T, void_t<decltype(std::declval<T>().is_connected())>> : std::true_type {};
// For now, let's assume C++17 as per instructions. The linter error needs to be understood.
// If std::void_t is truly missing, the project isn't compiling with C++17, or includes are minimal.
#endif
} // namespace detail

/**
 * @brief Context for route handlers
 */
template <typename Session, typename String = std::string>
struct RouterContext {
    // Internal state encapsulation
    struct ContextState {
        PathParameters                  path_params;
        qb::unordered_map<std::string, std::any> data;
        std::string                     match;
        bool                            handled  = false;
        bool                            is_async = false;
        bool is_deferred = false; // New flag for deferred processing
        RequestProcessingStage processing_stage = RequestProcessingStage::INITIAL; // AMÉLIORATION WORKFLOW POINT 5
        bool _handler_initiated_async = false; // Flag to indicate handler started async

        // Callbacks for different lifecycle hooks
        std::vector<std::function<void(RouterContext&)>> done_callbacks;
        std::vector<std::function<void(RouterContext&)>> before_callbacks;
        std::vector<std::function<void(RouterContext&)>> after_callbacks;
        std::vector<std::function<void(RouterContext&, const std::string&)>> error_callbacks;

        // Metrics
        Clock::time_point     start_time;
        std::optional<double> duration;

        // Event tracking
        std::vector<std::string> events; // Track middleware/handler events

        ContextState()
            : start_time(Clock::now()) {}
    };

    std::shared_ptr<ContextState> _state;

public:
    std::shared_ptr<Session>    session;    ///< Shared pointer to the session object.
    TRequest<String>            request;    ///< The HTTP request object.
    Response                    response;   ///< The HTTP response object to be populated.
    Router<Session, String>    *router = nullptr; ///< Pointer to the router instance, if available.

    // AMÉLIORATION WORKFLOW POINT 5: Accesseurs pour processing_stage
    /**
     * @brief Gets the current processing stage of the request in the router pipeline.
     * @return The current RequestProcessingStage.
     */
    RequestProcessingStage get_processing_stage() const { return _state->processing_stage; }
    /**
     * @brief Sets the current processing stage of the request.
     * @param stage The new RequestProcessingStage.
     */
    void set_processing_stage(RequestProcessingStage stage) { _state->processing_stage = stage; }

    /**
     * @brief Constructs a RouterContext.
     * @param s Shared pointer to the session.
     * @param req The HTTP request object (rvalue reference, will be moved).
     * @param r Optional pointer to the router handling this context.
     */
    RouterContext(std::shared_ptr<Session> s, TRequest<String> &&req,
                  Router<Session, String> *r = nullptr)
        : _state(std::make_shared<ContextState>())
        , session(std::move(s))
        , request(std::move(req))
        , response()
        , router(r) {}

    // Request-related methods

    /**
     * @brief Get a request header value
     * @param name Header name
     * @return Header value
     */
    [[nodiscard]] std::string
    header(const std::string &name) const {
        return request.header(name);
    }

    /**
     * @brief Get a path parameter value
     * @param name Parameter name
     * @param default_value Default value if parameter not found
     * @return Parameter value or default
     */
    [[nodiscard]] std::string
    param(const std::string &name, const std::string &default_value = "") const {
        auto it = _state->path_params.find(name);
        if (it != _state->path_params.end()) {
            return it->second;
        }
        return default_value;
    }

    /**
     * @brief Get all path parameters
     * @return Reference to path parameters map
     */
    [[nodiscard]] const PathParameters &
    params() const {
        return _state->path_params;
    }

    /**
     * @brief Set path parameters
     * @param params Path parameters to set
     */
    void
    set_path_params(const PathParameters &params) {
        _state->path_params = params;
    }

    /**
     * @brief Get the matched path
     * @return Matched path string
     */
    [[nodiscard]] const std::string &
    matched_path() const {
        return _state->match;
    }

    /**
     * @brief Set the matched path
     * @param match Matched path
     */
    void
    set_match(const std::string &match) {
        _state->match = match;
    }

    /**
     * @brief Get HTTP method of the request
     * @return HTTP method
     */
    [[nodiscard]] http_method
    method() const {
        return request.method;
    }

    /**
     * @brief Get request path
     * @return Request path
     */
    [[nodiscard]] std::string
    path() const {
        return std::string(request._uri.path());
    }

    // State management methods

    /**
     * @brief Set a custom state value
     * @param key State key
     * @param value State value
     */
    template <typename T>
    void
    set(const std::string &key, T value) {
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[CtxState@" + utility::pointer_to_string_for_log(_state.get()) + "] SET Key: '" + key + "'");
        }
        _state->data[key] = std::move(value);
    }

    /**
     * @brief Get a custom state value
     * @param key State key
     * @param default_value Default value if key not found
     * @return State value or default
     */
    template <typename T>
    T
    get(const std::string &key, T default_value = T{}) const {
        auto it = _state->data.find(key);
        if (it != _state->data.end()) {
            try {
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    adv_test_mw_middleware_execution_log.push_back("[CtxState@" + utility::pointer_to_string_for_log(_state.get()) + "] GET Key: '" + key + "' - FOUND");
                }
                return std::any_cast<T>(it->second);
            } catch (const std::bad_any_cast &) {
                if (adv_test_mw_middleware_execution_log.size() < 2000) {
                    adv_test_mw_middleware_execution_log.push_back("[CtxState@" + utility::pointer_to_string_for_log(_state.get()) + "] GET Key: '" + key + "' - BAD CAST, returning default");
                }
                return default_value;
            }
        }
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[CtxState@" + utility::pointer_to_string_for_log(_state.get()) + "] GET Key: '" + key + "' - NOT FOUND, returning default");
        }
        return default_value;
    }

    /**
     * @brief Check if a state key exists
     * @param key State key
     * @return true if key exists, false otherwise
     */
    [[nodiscard]] bool
    has(const std::string &key) const {
        bool found = _state->data.find(key) != _state->data.end();
        if (adv_test_mw_middleware_execution_log.size() < 2000) {
            adv_test_mw_middleware_execution_log.push_back("[CtxState@" + utility::pointer_to_string_for_log(_state.get()) + "] HAS Key: '" + key + "' - Result: " + utility::bool_to_string(found));
        }
        return found;
    }

    /**
     * @brief Remove a state key
     * @param key State key
     * @return true if key was removed, false if not found
     */
    bool
    remove(const std::string &key) {
        auto it = _state->data.find(key);
        if (it != _state->data.end()) {
            _state->data.erase(it);
            return true;
        }
        return false;
    }

    /**
     * @brief Clear all state data
     */
    void
    clear_state() {
        _state->data.clear();
    }

    // Response convenience methods

    /**
     * @brief Set response status code
     * @param status_code HTTP status code
     * @return Reference to this context
     */
    RouterContext &
    status(http_status status_code) {
        response.status_code = status_code;
        return *this;
    }

    /**
     * @brief Set response body
     * @param content Body content
     * @return Reference to this context
     */
    RouterContext &
    body(const std::string &content) {
        response.body() = content;
        return *this;
    }

    /**
     * @brief Set a response header
     * @param name Header name
     * @param value Header value
     * @return Reference to this context
     */
    RouterContext &
    header(const std::string &name, const std::string &value) {
        response.add_header(name, value);
        return *this;
    }

    /**
     * @brief Set JSON content type and convert body to JSON
     * @param json_object JSON object
     * @return Reference to this context
     */
    template <typename JsonT>
    RouterContext &
    json(const JsonT &json_object) {
        response.add_header("Content-Type", "application/json");
        if constexpr (std::is_convertible_v<JsonT, std::string>) {
            response.body() = json_object;
        } else {
            response.body() = qb::json(json_object).dump();
        }
        return *this;
    }

    /**
     * @brief Set redirect response
     * @param url URL to redirect to
     * @param permanent Whether the redirect is permanent (301) or temporary (302)
     * @return Reference to this context
     */
    RouterContext &
    redirect(const std::string &url, bool permanent = false) {
        response.status_code =
            permanent ? HTTP_STATUS_MOVED_PERMANENTLY : HTTP_STATUS_FOUND;
        response.add_header("Location", url);
        return *this;
    }

    // Request flow control methods

    /**
     * @brief Mark request as handled
     * @return Reference to this context
     */
    RouterContext &
    mark_handled() {
        _state->handled = true;
        return *this;
    }

    /**
     * @brief Check if request is marked as handled
     * @return true if handled, false otherwise
     */
    [[nodiscard]] bool
    is_handled() const {
        return _state && _state->handled;
    }

    /**
     * @brief Mark request as async
     * @return Reference to this context
     */
    RouterContext &
    mark_async() {
        _state->is_async = true;
        _state->handled  = true; // Async requests are also handled
        return *this;
    }

    /**
     * @brief Check if request is marked as async
     * @return true if async, false otherwise
     */
    [[nodiscard]] bool
    is_async() const {
        return _state ? _state->is_async : false;
    }

    /**
     * @brief Clears the async flag. Typically used internally when an async middleware chain
     * completes synchronously or an async handler completes its operation and calls back.
     * This ensures that subsequent synchronous processing steps are not incorrectly
     * treated as yielding for an async operation that has already concluded.
     */
    void clear_async_state_for_chain_completion() {
        if (_state) {
            _state->is_async = false;
        }
    }

    /**
     * @brief Clears the async flag when a synchronous handler has executed
     * after a preceding asynchronous middleware. This signals that the route's
     * specific synchronous processing is done, even if the broader request
     * context was initially asynchronous.
     */
    void clear_async_for_sync_handler_after_async_middleware() {
        if (_state) {
            _state->is_async = false;
            // Do not modify _state->handled here, as the handler is considered to have handled its part.
        }
    }

    // Lifecycle hooks

    /**
     * @brief Register a callback to be executed after request processing is complete
     * @param callback Function to call when request is done
     * @return Reference to this context
     */
    RouterContext& 
    on_done(std::function<void(RouterContext&)> callback) {
        _state->done_callbacks.push_back(std::move(callback));
        return *this;
    }

    /**
     * @brief Execute all registered 'done' callbacks
     */
    void 
    execute_done_callbacks() {
        for (auto& callback : _state->done_callbacks) {
            callback(*this);
        }
        _state->done_callbacks.clear();
    }

    /**
     * @brief Register a callback to be executed before request handling
     * @param callback Function to call before handling
     * @return Reference to this context
     */
    RouterContext& 
    before_handling(std::function<void(RouterContext&)> callback) {
        _state->before_callbacks.push_back(std::move(callback));
        return *this;
    }

    /**
     * @brief Execute all registered 'before' callbacks
     */
    void 
    execute_before_callbacks() {
        for (auto& callback : _state->before_callbacks) {
            callback(*this);
        }
        _state->before_callbacks.clear();
    }

    /**
     * @brief Register a callback to be executed after request handling
     * @param callback Function to call after handling
     * @return Reference to this context
     */
    RouterContext& 
    after_handling(std::function<void(RouterContext&)> callback) {
        _state->after_callbacks.push_back(std::move(callback));
        return *this;
    }

    /**
     * @brief Execute all registered 'after' callbacks
     */
    void 
    execute_after_callbacks() {
        for (const auto& callback : _state->after_callbacks) {
            callback(*this);
        }
        _state->after_callbacks.clear();
    }

    /**
     * @brief Register a callback to be executed on error
     * @param callback Function to call on error (passes error message)
     * @return Reference to this context
     */
    RouterContext& 
    on_error(std::function<void(RouterContext&, const std::string&)> callback) {
        _state->error_callbacks.push_back(std::move(callback));
        return *this;
    }

    /**
     * @brief Execute all registered 'error' callbacks
     * @param error_message Error message to pass to callbacks
     */
    void 
    execute_error_callbacks(const std::string& error_message) {
        for (auto& callback : _state->error_callbacks) {
            callback(*this, error_message);
        }
        _state->error_callbacks.clear();
    }

    // Metrics methods

    /**
     * @brief Get elapsed time since request start
     * @return Elapsed time in milliseconds
     */
    [[nodiscard]] double
    elapsed() const {
        return std::chrono::duration<double, std::milli>(Clock::now() -
                                                         _state->start_time)
            .count();
    }

    /**
     * @brief Record duration of request
     * @param duration_ms Duration in milliseconds
     */
    void
    record_duration(double duration_ms) {
        _state->duration = duration_ms;
    }

    /**
     * @brief Get recorded duration
     * @return Duration in milliseconds, or std::nullopt if not recorded
     */
    [[nodiscard]] std::optional<double>
    duration() const {
        return _state->duration;
    }

    /**
     * @brief Get request start time
     * @return Start time
     */
    [[nodiscard]] Clock::time_point
    start_time() const {
        return _state->start_time;
    }

    // Completion methods

    /**
     * @brief Complete the request and send response
     */
    void complete(bool from_async_completion_handler = false) {
        if (!_state) {
            // This case should ideally not happen if context is managed properly
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                 adv_test_mw_middleware_execution_log.push_back("[Ctx@" + utility::pointer_to_string_for_log(this) + "::complete] EARLY EXIT: _state is null. Path: " + std::string(this->request.uri().path()));
            }
            return; 
        }

        if (adv_test_mw_middleware_execution_log.size() < 2000) {
             adv_test_mw_middleware_execution_log.push_back("[Ctx@" + utility::pointer_to_string_for_log(this) + "::complete ENTRY] Path: " + std::string(this->request.uri().path()) + ", CtxState@" + utility::pointer_to_string_for_log(_state.get()) + ", from_async_cb: " + utility::bool_to_string(from_async_completion_handler));
        }

        if (has("_completed")) {
            if (!has("_completed_by_async_handler")) {
                add_event("RouterContext::complete() called on ASYNC context BEFORE AsyncCompletionHandler. Callbacks executed, but no response sent by RouterContext.");
                set("_completed", true); // Marquer comme "callbacks faits", mais pas "réponse envoyée par RouterContext"
                execute_after_callbacks(); 
                execute_done_callbacks();
            }
            return; 
        }

        if (has("_response_sent_by_router_context")) { // Sécurité pour éviter double envoi
            add_event("RouterContext::complete() called but response already marked as sent by RouterContext.");
            return;
        }

        add_event("RouterContext::complete() proceeding to finalize response.");
        execute_after_callbacks();
        execute_done_callbacks();
        
        this->_state->handled = true; 
        set("_completed", true);
        // Si ce complete() est celui qui envoie la réponse, marquer que c'est le handler async qui l'a fait (ou le sync)
        set("_completed_by_async_handler", true); 
        
        set_processing_stage(RequestProcessingStage::RESPONSE_SENT_OR_COMPLETED);
        
        if (session && is_session_connected()) {
            if (adv_test_mw_middleware_execution_log.size() < 2000) {
                std::string bdy = "<body is empty>";
                if (!_state) { // Re-check _state before accessing response.body()
                    bdy = "<_state became null before body access>";
                } else if (!response.body().empty()) {
                    try { bdy = response.body().template as<std::string>(); } catch(...) { bdy = "<error converting body to string>"; }
                }
                adv_test_mw_middleware_execution_log.push_back("[Ctx@" + utility::pointer_to_string_for_log(this) + "::complete] Sending to session. Status: " + std::to_string(response.status_code) + ", Body: '" + bdy + "'. CtxState@" + (_state ? utility::pointer_to_string_for_log(_state.get()) : "NULL") );
            }
            if (!_state) { // Final check before session send
                 if (adv_test_mw_middleware_execution_log.size() < 2000) {
                     adv_test_mw_middleware_execution_log.push_back("[Ctx@" + utility::pointer_to_string_for_log(this) + "::complete] ERROR: _state is null before sending to session. Path: " + std::string(this->request.uri().path()));
                 }
                return; // Cannot send without state
            }
            try {
                *session << response;
                set("_response_sent_by_router_context", true); 
            } catch (const std::exception& e) {
                add_event(std::string("RouterContext::complete() send exception: ") + e.what());
            } catch (...) {
                add_event("RouterContext::complete() send unknown exception.");
            }
        } else {
            add_event("RouterContext::complete(): No session or session not connected, response not sent.");
        }
    }

    // For compatibility with existing code
    PathParameters &path_params = _state->path_params;
    std::string    &match       = _state->match;
    bool           &handled     = _state->handled;

    /**
     * @brief Prepares the context for an asynchronous operation initiated by the handler.
     * 
     * This method should be called by a route handler if it intends to complete the
     * request asynchronously. It marks the context as asynchronous and returns a 
     * handler object that can be used to complete the request later.
     * 
     * @return A shared pointer to an AsyncCompletionHandler, or nullptr if the router
     *         is not available to manage the async lifecycle.
     */
    [[nodiscard]] std::shared_ptr<AsyncCompletionHandler<Session, String>>
    make_async() {
        if (!_state) { // Should ideally not happen if context is constructed properly
            // Log or handle critical error: _state is null
            return nullptr;
        }
        if (!router) {
            // Log or handle error: Router pointer is null, cannot manage async lifecycle
            // Or, if adv_test_mw_middleware_execution_log is accessible here:
            // adv_test_mw_middleware_execution_log.push_back("[Ctx::make_async] CRITICAL: Router is null. Cannot return AsyncCompletionHandler.");
            return nullptr; 
        }

        _state->is_async = true;
        _state->handled = true; // <<< Ensure this is set for async operations initiated by handler
        _state->_handler_initiated_async = true; // Mark that the handler specifically called make_async
        set_processing_stage(RequestProcessingStage::AWAITING_HANDLER_ASYNC_COMPLETION);
        
        // Ensure this context is in the router's active list
        // The router pointer itself is the key for _active_async_requests in some contexts,
        // but here, context_id is derived from the context object's address.
        std::uintptr_t context_id = reinterpret_cast<std::uintptr_t>(this);
        // This relies on Router having a method to add/get active requests if not already present.
        // For now, let's assume the router's route_context or similar logic handles adding to _active_async_requests
        // when it detects is_async is true after the handler runs.
        // Or, AsyncCompletionHandler's constructor/complete() method interacts with router's active requests.
        // The AsyncCompletionHandler itself gets the router and context_id, so it can manage this.

        // We need to provide a shared_ptr to *this context for the AsyncCompletionHandler if it needs it.
        // However, AsyncCompletionHandler takes Context&.
        // The main thing is that the Router's _active_async_requests map needs to hold a shared_ptr to this context
        // to keep it alive. This typically happens in Router::route_context when it sees the async flag.

        if (adv_test_mw_middleware_execution_log.size() < 2000 && _state) {
            adv_test_mw_middleware_execution_log.push_back(std::string("[Ctx@") + utility::pointer_to_string_for_log(this) + "::make_async] Marked async. Stage: " + utility::to_string_for_log(get_processing_stage()) + ". CtxState@" + utility::pointer_to_string_for_log(_state.get()) + "]");
        }
        
        // The AsyncCompletionHandler needs `*this` (the context) and the router pointer.
        return std::make_shared<AsyncCompletionHandler<Session, String>>(*this, router);
    }

    /**
     * @brief Checks if the current asynchronous state was initiated by the route handler.
     * @return true if the handler called make_async(), false otherwise.
     */
    [[nodiscard]] bool handler_initiated_async() const {
        return _state ? _state->_handler_initiated_async : false;
    }

    /**
     * @brief Clears the flag indicating that the handler initiated an async operation.
     * Typically called by TRoute when a synchronous handler completes after async middleware.
     */
    void clear_handler_initiated_async_flag() {
        if (_state) {
            _state->_handler_initiated_async = false;
        }
    }

    // For backward compatibility with existing tests
    // Point 2: Ensure this returns the external ::qb::http::AsyncCompletionHandler
    ::qb::http::AsyncCompletionHandler<Session, String> *
    get_completion_handler(Router<Session, String> &r) {
        mark_async();
        // This should correctly instantiate the external AsyncCompletionHandler
        // The constructor of ::qb::http::AsyncCompletionHandler takes (Context&, Router*)
        // Note: Caller is responsible for deleting the returned raw pointer.
        return new ::qb::http::AsyncCompletionHandler<Session, String>(*this, &r);
    }

    /**
     * @brief Mark request as deferred
     * @return Reference to this context
     *
     * Marks a request as deferred for later processing,
     * allowing for delayed processing in an event-driven system.
     */
    RouterContext &
    mark_deferred() {
        _state->is_deferred = true;
        _state->is_async    = true; // Deferred requests are also async
        _state->handled     = true; // Deferred requests are also handled
        return *this;
    }

    /**
     * @brief Check if request is marked as deferred
     * @return true if deferred, false otherwise
     */
    [[nodiscard]] bool
    is_deferred() const {
        return _state->is_deferred;
    }

    /**
     * @brief Add an event to the context event log
     * @param event_name Name of the event
     */
    void
    add_event(const std::string &event_name) {
        _state->events.push_back(event_name);
    }

    /**
     * @brief Get the event log
     * @return Vector of logged events
     */
    [[nodiscard]] const std::vector<std::string> &
    events() const {
        return _state->events;
    }

    // Create an AsyncMiddlewareResult for asynchronous continuation
    std::shared_ptr<AsyncMiddlewareResult>
    make_middleware_result(std::function<void(bool)> callback) {
        return std::make_shared<AsyncMiddlewareResult>(std::move(callback));
    }

    // Helper method to check if the session is still connected.
    // This checks the session object directly if available and if the session type supports an is_connected() method.
    [[nodiscard]] bool is_session_connected() const {
        if (!session) {
            return false; // No session associated with the context.
        }
        
        // Check for is_connected() method on the Session type using SFINAE/type traits.
        if constexpr (detail::has_method_is_connected<Session>::value) {
            return session->is_connected();
        }
        
        return true; // Assume connected if no is_connected method is available on the session object.
    }

    /**
     * @brief Marks the context as unhandled, for testing purposes only
     */
    void
    mark_unhandled() {
        if (_state) _state->handled = false;
    }
};

// Alias for backward compatibility
template <typename Session, typename String = std::string>
using Context = RouterContext<Session, String>;

}
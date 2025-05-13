#pragma once

#include <any>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "../request.h"
#include "../response.h"
#include "./async_types.h"
#include "./path_parameters.h"

# if defined(_WIN32)
#undef DELETE // Windows :/
#endif

namespace qb::http {

// Forward declarations
template <typename Session, typename String>
class Router;

template <typename Session, typename String>
class AsyncCompletionHandler;

namespace detail {
// Trait to detect if a class has an is_connected() method
template <typename T, typename = void>
struct has_method_is_connected : std::false_type {};

template <typename T>
struct has_method_is_connected<T, std::void_t<decltype(std::declval<T>().is_connected())>> : std::true_type {};
} // namespace detail

/**
 * @brief Context for route handlers
 */
template <typename Session, typename String = std::string>
struct RouterContext {
private:
    // Internal state encapsulation
    struct ContextState {
        PathParameters                  path_params;
        qb::unordered_map<std::string, std::any> data;
        std::string                     match;
        bool                            handled  = false;
        bool                            is_async = false;
        bool is_deferred = false; // New flag for deferred processing

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
    std::shared_ptr<Session>    session;
    TRequest<String>            request;
    Response                    response;
    Router<Session, String>    *router = nullptr;

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
                return std::any_cast<T>(it->second);
            } catch (const std::bad_any_cast &) {
                return default_value;
            }
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
        return _state->data.find(key) != _state->data.end();
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
            // Assuming json_object has a to_string() or similar method
            // This is just a placeholder and would need to be adapted
            // to the actual JSON library being used
            response.body() = json_object.dump();
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
        return _state->handled;
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
        return _state->is_async;
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
        for (auto& callback : _state->after_callbacks) {
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
    void
    complete() {
        // Execute callbacks after processing
        execute_after_callbacks();
        execute_done_callbacks();
        
        if (router) {
            router->log_request(*this);
        }
        *session << response;
    }

    // For compatibility with existing code
    PathParameters &path_params = _state->path_params;
    std::string    &match       = _state->match;
    bool           &handled     = _state->handled;

    // Generate a completion handler for the current context
    class AsyncCompletionHandler {
    private:
        RouterContext           &ctx;
        Router<Session, String> *router;

    public:
        AsyncCompletionHandler(RouterContext &context, Router<Session, String> *r)
            : ctx(context)
            , router(r) {}

        AsyncCompletionHandler &
        status(enum http_status status) {
            ctx.response.status_code = status;
            return *this;
        }

        AsyncCompletionHandler &
        header(const std::string &name, const std::string &value) {
            ctx.response.add_header(name, value);
            return *this;
        }

        AsyncCompletionHandler &
        body(const std::string &content) {
            ctx.response.body() = content;
            return *this;
        }

        /**
         * @brief Complete the request asynchronously
         */
        void
        complete() {
            // First check if request is cancelled - skip if cancelled
            // Use public API instead of accessing private member
            if (router->is_request_cancelled(reinterpret_cast<std::uintptr_t>(&ctx))) {
                // Don't do anything for cancelled requests
                return;
            }

            // Check if the session is still connected
            if (!ctx.session) {
                return;
            }
            if constexpr (detail::has_method_is_connected<Session>::value) {
                if (!ctx.session->is_connected()) {
                    // Don't try to complete a disconnected session
                    return;
                }
            }

            // Execute callbacks after processing
            ctx.execute_after_callbacks();
            ctx.execute_done_callbacks();

            // Complete the request immediately by sending the response
            if (router) {
                router->log_request(ctx); // Log before sending
            }
            *ctx.session << ctx.response; // Send the response

            // Important: After sending the response, we need to notify the router
            // that this async request is complete so it can be removed from the active map.
            // We use complete_with_state for this, similar to how cancel() does.
            if (router) {
                router->complete_async_request(reinterpret_cast<std::uintptr_t>(&ctx),
                                               ctx.response, // Pass response again (needed by router method)
                                               AsyncRequestState::COMPLETED);
            }
        }

        // For test-router-async-advanced.cpp
        void
        complete_with_state(AsyncRequestState state) {
            if (router) {
                router->complete_async_request(reinterpret_cast<std::uintptr_t>(&ctx),
                                               ctx.response, state);
            }
        }

        /**
         * @brief Cancel the request due to an error
         * @param status_code HTTP status code
         * @param error_message Error message
         */
        void
        cancel(http_status status_code, const std::string &error_message) {
            ctx.response.status_code = status_code;
            ctx.response.body()      = error_message;
            
            // Execute error callbacks
            ctx.execute_error_callbacks(error_message);
            
            if (router) {
                router->complete_async_request(reinterpret_cast<std::uintptr_t>(&ctx),
                                               ctx.response,
                                               AsyncRequestState::CANCELED);
            } else {
                *ctx.session << ctx.response;
            }
        }
    };

    // Method that combines markAsync and creates a completion handler
    std::shared_ptr<::qb::http::AsyncCompletionHandler<Session, String>>
    make_async() {
        mark_async();
        if (router) {
            return std::make_shared<::qb::http::AsyncCompletionHandler<Session, String>>(*this, router);
        }
        return nullptr;
    }

    // For backward compatibility with existing tests
    ::qb::http::AsyncCompletionHandler<Session, String> *
    get_completion_handler(Router<Session, String> &r) {
        mark_async();
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

    // Helper method to check if the session is still connected
    [[nodiscard]] bool is_session_connected() const {
        if (!session) {
            return false;
        }
        
        if constexpr (detail::has_method_is_connected<Session>::value) {
            return session->is_connected();
        }
        
        return true; // Assume connected if no is_connected method
    }
};

// Alias for backward compatibility
template <typename Session, typename String = std::string>
using Context = RouterContext<Session, String>;

} // namespace qb::http
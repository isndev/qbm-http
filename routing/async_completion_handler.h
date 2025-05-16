#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include "../response.h"
#include "./async_types.h"
#include <iostream>

namespace qb::http {

template <typename S, typename Str>
class Router;

/**
 * @brief Handler for completing asynchronous requests
 *
 * This class allows route handlers to complete asynchronous requests
 * when they are ready. It provides methods to set the response status,
 * headers, and body, and to complete the request.
 */
template <typename Session, typename String = std::string>
class AsyncCompletionHandler {
private:
    using Router = qb::http::Router<Session, String>;
    using Context = typename Router::Context;

    Router            &_router;
    std::uintptr_t     _context_id;
    Context           *_context;  // Store a pointer to the context
    Response           _fallback_response;   // Only used when context is no longer available
    bool               _is_deferred   = false;
    int                _defer_time_ms = 0;
    bool               _cancelled     = false;

public:
    // Constructor for when we have direct access to the context
    AsyncCompletionHandler(Context &ctx, Router *router_ptr)
        : _router(*router_ptr)
        , _context_id(reinterpret_cast<std::uintptr_t>(&ctx))
        , _context(&ctx) 
        // Note: The fallback_response is intentionally not initialized with ctx.response
        // to avoid redundant copying. It will only be used if the context becomes unavailable.
    {}

    /**
     * @brief Set the status code for the response.
     * 
     * Always updates the context's response if available.
     * Only falls back to the local copy if context is no longer accessible.
     *
     * @param status_code HTTP status code.
     * @return Reference to this handler for chaining.
     */
    AsyncCompletionHandler &
    status(http_status status_code) {
        std::cerr << "[ACH::status] this: " << this << ", _context: " << _context << ", setting status: " << status_code << std::endl;
        // First check if request is still active
        if (!_router.is_active_request(_context_id)) {
            // Request is no longer active, just update fallback response
            _fallback_response.status_code = status_code;
            return *this;
        }
        
        // Now safely access context if it exists
        if (_context) {
            _context->response.status_code = status_code;
        } else {
            _fallback_response.status_code = status_code;
        }
        return *this;
    }

    /**
     * @brief Set a header for the response
     * @param name Header name
     * @param value Header value
     * @return Reference to this handler
     */
    AsyncCompletionHandler &
    header(const std::string &name, const std::string &value) {
        // First check if request is still active
        if (!_router.is_active_request(_context_id)) {
            // Request is no longer active, just update fallback response
            _fallback_response.add_header(name, value);
            return *this;
        }
        
        // Now safely access context if it exists
        if (_context) {
            _context->response.add_header(name, value);
        } else {
            // Otherwise, add to fallback response
            _fallback_response.add_header(name, value);
        }
        return *this;
    }

    /**
     * @brief Set the body for the response.
     *
     * Always updates the context's response if available.
     * Only falls back to the local copy if context is no longer accessible.
     *
     * @tparam T Type of the body content.
     * @param body Body content.
     * @return Reference to this handler for chaining.
     */
    template <typename T>
    AsyncCompletionHandler &
    body(T &&body) {
        std::string body_str_repr = "<non-string_body_type>";
        if constexpr (std::is_same_v<std::decay_t<T>, std::string> || std::is_same_v<std::decay_t<T>, const char*>) {
            body_str_repr = body;
        }
        std::cerr << "[ACH::body] this: " << this << ", _context: " << _context << ", setting body (repr): " << body_str_repr.substr(0, 50) << std::endl;

        // First check if request is still active and session is connected
        if (!_router.is_active_request(_context_id)) {
            // Request is no longer active, just update fallback response
            _fallback_response.body() = std::forward<T>(body);
            return *this;
        }
        
        // Now safely access context if it exists
        if (_context) {
            _context->response.body() = std::forward<T>(body);
        } else {
            _fallback_response.body() = std::forward<T>(body);
        }
        return *this;
    }

    /**
     * @brief Check if the session is still connected
     * @return True if the session is still connected, false otherwise
     */
    bool
    is_session_connected() const {
        // Check if the request is still active
        if (!_router.is_active_request(_context_id)) {
            return false;
        }
        
        // If we have a context pointer, check if the session is still connected via the context
        if (_context) {
            return _context->is_session_connected();
        }
        
        return false; // No context or request not active, cannot verify connection
    }

    /**
     * @brief Complete the request with a specific state
     * @param state The completion state
     */
    void
    complete_with_state(AsyncRequestState state) {
        // First ensure cancellation state is set properly
        if (state == AsyncRequestState::CANCELED) {
            _cancelled = true;
            
            // Use the appropriate response for cancellation
            if (_context) {
                _router.cancel_request(_context_id, _context->response.status_code, 
                                    _context->response.body().template as<std::string>());
            } else {
                // Fallback to the local response only if context is unavailable
                _router.cancel_request(_context_id, _fallback_response.status_code, 
                                    _fallback_response.body().template as<std::string>());
            }
            return;
        }
        
        // For other states, complete normally using the appropriate response
        if (_context) {
            _router.complete_async_request(_context_id, _context->response, state);
        } else {
            _router.complete_async_request(_context_id, std::move(_fallback_response), state);
        }
    }

    /**
     * @brief Cancel the request with a specific status code and message
     * @param status_code HTTP status code for the cancellation response
     * @param message Message explaining the cancellation reason
     */
    void
    cancel(http_status status_code = HTTP_STATUS_BAD_REQUEST, 
           const std::string &message = "Request canceled by application") {
        // Set the cancellation status and message in the appropriate response
        if (_context) {
            _context->response.status_code = status_code;
            _context->response.body() = message;
        } else {
            _fallback_response.status_code = status_code;
            _fallback_response.body() = message;
        }
        
        // Mark as cancelled internally
        _cancelled = true;
        
        // Use the custom status and message for cancellation via the router
        _router.cancel_request(_context_id, status_code, message);
    }

    /**
     * @brief Complete the request asynchronously
     */
    void
    complete() {
        std::cerr << "[ACH::complete ENTRY] this: " << this << ", _context: " << _context;
        if (_context && _context->_state) { // Check _state as well for safety
            std::string current_body_repr = "<body empty or error converting in ACH::complete>";
            try { if(!_context->response.body().empty()) current_body_repr = _context->response.body().template as<std::string>(); } catch(...) {}
            std::cerr << ", _context->response.status: " << _context->response.status_code 
                      << ", _context->response.body (repr): " << current_body_repr.substr(0, 50);
        } else if (_context) {
            std::cerr << ", _context exists but _context->_state is NULL";
        } else {
            std::cerr << ", _context is NULL";
        }
        std::cerr << std::endl;

        // First check if request is cancelled
        if (_cancelled) {
            // Don't do anything for cancelled requests
            return;
        }
        
        // Check if the session is still connected
        if (!is_session_connected()) {
            // Don't try to complete a disconnected session
            return;
        }

        // Make a local copy of the response to ensure safety
        Response response_to_send;
        
        // Prepare the response either from context or fallback
        if (_context && _context->_state) {
            response_to_send = _context->response;
        } else {
            // If context is no longer valid, use fallback response
            response_to_send = _fallback_response;
        }
        
        // Handle deferred completion
        if (_is_deferred) {
            _router.defer_request(_context_id, _defer_time_ms, [this, response_to_send]() mutable {
                // Double-check connection status before completing the deferred request
                if (is_session_connected()) {
                    _router.complete_async_request(_context_id, std::move(response_to_send));
                }
            });
            return;
        }

        // Complete request immediately
        _router.complete_async_request(_context_id, std::move(response_to_send));
    }

    /**
     * @brief Defer the completion of the request
     * @param delay_ms Delay in milliseconds
     * @return Reference to this handler
     *
     * Schedules the request to be completed after the specified delay.
     * This is useful for throttling responses or implementing delays.
     */
    AsyncCompletionHandler &
    defer(int delay_ms) {
        _is_deferred   = true;
        _defer_time_ms = delay_ms;
        return *this;
    }

    /**
     * @brief Create a JSON response
     * @param json_data JSON data to include in the response
     * @return Reference to this handler
     */
    template <typename JsonT>
    AsyncCompletionHandler &
    json(const JsonT &json_data) {
        // First check if request is still active
        if (!_router.is_active_request(_context_id)) {
            // Request is no longer active, just update fallback response
            _fallback_response.add_header("Content-Type", "application/json");
            if constexpr (std::is_convertible_v<JsonT, std::string>) {
                _fallback_response.body() = json_data;
            } else {
                _fallback_response.body() = json_data.dump();
            }
            return *this;
        }

        // Set Content-Type to application/json
        // Update response in context if available, otherwise fallback response
        if (_context) {
            _context->response.add_header("Content-Type", "application/json");
            if constexpr (std::is_convertible_v<JsonT, std::string>) {
                _context->response.body() = json_data;
            } else {
                // Assuming json_data has a .dump() method (e.g., nlohmann::json)
                _context->response.body() = json_data.dump();
            }
        } else {
            _fallback_response.add_header("Content-Type", "application/json");
            if constexpr (std::is_convertible_v<JsonT, std::string>) {
                _fallback_response.body() = json_data;
            } else {
                _fallback_response.body() = json_data.dump();
            }
        }
        return *this;
    }

    /**
     * @brief Create a redirect response
     * @param url URL to redirect to
     * @param permanent Whether this is a permanent redirect
     * @return Reference to this handler
     */
    AsyncCompletionHandler &
    redirect(const std::string &url, bool permanent = false) {
        auto status = permanent ? HTTP_STATUS_MOVED_PERMANENTLY : HTTP_STATUS_FOUND;
        
        // First check if request is still active
        if (!_router.is_active_request(_context_id)) {
            // Request is no longer active, just update fallback response
            _fallback_response.status_code = status;
            _fallback_response.add_header("Location", url);
            return *this;
        }
        
        // Update response in context if available, otherwise fallback response
        if (_context) {
            _context->response.status_code = status;
            _context->response.add_header("Location", url);
        } else {
            _fallback_response.status_code = status;
            _fallback_response.add_header("Location", url);
        }
        return *this;
    }
};

} // namespace qb::http
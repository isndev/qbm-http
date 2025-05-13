#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include "../response.h"
#include "./async_types.h"

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
    Response           _response;
    bool               _is_deferred   = false;
    int                _defer_time_ms = 0;

public:
    // Constructor for when we have direct access to the context
    AsyncCompletionHandler(Context &ctx, Router *router)
        : _router(*router)
        , _context_id(reinterpret_cast<std::uintptr_t>(&ctx))
        , _context(&ctx) {}

    /**
     * @brief Set the status code for the response
     * @param status_code HTTP status code
     * @return Reference to this handler
     */
    AsyncCompletionHandler &
    status(http_status status_code) {
        // First check if request is still active
        if (!_router.is_active_request(_context_id)) {
            // Request is no longer active, just update local response
            _response.status_code = status_code;
            return *this;
        }
        
        // Now safely access context if it exists
        if (_context) {
            _context->response.status_code = status_code;
        } else {
            _response.status_code = status_code;
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
            // Request is no longer active, just update local response
            _response.add_header(name, value);
            return *this;
        }
        
        // Now safely access context if it exists
        if (_context) {
            _context->response.add_header(name, value);
        } else {
            _response.add_header(name, value);
        }
        return *this;
    }

    /**
     * @brief Set the body for the response
     * @param body Body content
     * @return Reference to this handler
     */
    template <typename T>
    AsyncCompletionHandler &
    body(T &&body) {
        // First check if request is still active and session is connected
        if (!_router.is_active_request(_context_id)) {
            // Request is no longer active, just update local response
            _response.body() = std::forward<T>(body);
            return *this;
        }
        
        // Now safely access context if it exists
        if (_context) {
            _context->response.body() = std::forward<T>(body);
        } else {
            _response.body() = std::forward<T>(body);
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
        
        // If we have a context pointer, check if the session is still connected
        if (_context) {
            return _context->is_session_connected();
        }
        
        return false; // No context, can't verify connection
    }

    /**
     * @brief Cancel the request with a specific status code and message
     * @param status_code HTTP status code for the cancellation response
     * @param message Message explaining the cancellation reason
     */
    void
    cancel(http_status status_code, const std::string &message = "") {
        // Set status and message
        if (_context) {
            _context->response.status_code = status_code;
            if (!message.empty()) {
                _context->response.body() = message;
            }
        } else {
            _response.status_code = status_code;
            if (!message.empty()) {
                _response.body() = message;
            }
        }
        
        // Complete with CANCELED state
        complete_with_state(AsyncRequestState::CANCELED);
    }

    /**
     * @brief Complete the request asynchronously
     */
    void
    complete() {
        // First check if request is cancelled - skip if cancelled
        if (_router._cancelled_requests.find(_context_id) !=
            _router._cancelled_requests.end()) {
            // Don't do anything for cancelled requests
            return;
        }
        
        // Check if the session is still connected
        if (!is_session_connected()) {
            // Don't try to complete a disconnected session
            return;
        }

        // Handle deferred completion
        if (_is_deferred) {
            _router.defer_request(_context_id, _defer_time_ms, [this]() {
                // Double-check connection status before completing
                if (is_session_connected()) {
                    if (_context) {
                        _router.complete_async_request(_context_id, _context->response);
                    } else {
                        _router.complete_async_request(_context_id, std::move(_response));
                    }
                }
            });
            return;
        }

        // Complete the request immediately
        if (_context) {
            _router.complete_async_request(_context_id, _context->response);
        } else {
            _router.complete_async_request(_context_id, std::move(_response));
        }
    }

    /**
     * @brief Complete the request with a specific state
     * @param state The completion state
     */
    void
    complete_with_state(AsyncRequestState state) {
        if (_context) {
            _router.complete_async_request(_context_id, _context->response, state);
        } else {
            _router.complete_async_request(_context_id, std::move(_response), state);
        }
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
        if (_context) {
            _context->response.add_header("Content-Type", "application/json");
            if constexpr (std::is_convertible_v<JsonT, std::string>) {
                _context->response.body() = json_data;
            } else {
                _context->response.body() = json_data.dump();
            }
        } else {
            _response.add_header("Content-Type", "application/json");
            if constexpr (std::is_convertible_v<JsonT, std::string>) {
                _response.body() = json_data;
            } else {
                _response.body() = json_data.dump();
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
        
        if (_context) {
            _context->response.status_code = status;
            _context->response.add_header("Location", url);
        } else {
            _response.status_code = status;
            _response.add_header("Location", url);
        }
        return *this;
    }
};

} // namespace qb::http
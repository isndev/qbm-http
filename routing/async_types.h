#pragma once

#include <chrono>
#include <functional>
#include <cstdint>
#include <string>
#include <qb/uuid.h>
#include <type_traits>

namespace qb::http {

// Forward declaration for async completion
template <typename Session, typename String>
class AsyncCompletionHandler;

// Forward declaration for async middleware result
class AsyncMiddlewareResult;

// Session identifier type
using SessionId = ::qb::uuid;

// Async request state enumerations
/**
 * @brief Enumerates the possible states of an asynchronous request.
 */
enum class AsyncRequestState {
    PENDING,      ///< Request is being processed asynchronously.
    COMPLETED,    ///< Request was successfully completed.
    CANCELED,     ///< Request was canceled (e.g., by application logic or client disconnect before handler completion).
    DISCONNECTED, ///< Client disconnected before the asynchronous operation could complete or send a response.
    TIMEOUT,      ///< Request timed out before completion.
    DEFERRED      ///< Request processing is scheduled for a later time.
};

// Define Clock type for consistent time measurement across async operations
using Clock = std::chrono::steady_clock;

/**
 * @brief Helper class for handling the result of an asynchronous middleware.
 *
 * This class provides a fluent interface for an asynchronous middleware
 * to signal how the middleware chain should proceed after its async operation completes.
 * It uses a callback mechanism to continue the chain.
 */
class AsyncMiddlewareResult {
private:
    bool                      _continue_chain; // Renamed for clarity
    std::function<void(bool)> _callback;       // Callback to signal continuation (true) or stop (false)

public:
    /**
     * @brief Constructs an AsyncMiddlewareResult.
     * @param callback The function to call to signal the outcome of the middleware. 
     *                 It takes a boolean: true to continue the chain, false to stop.
     */
    AsyncMiddlewareResult(std::function<void(bool)> callback)
        : _continue_chain(true) // Default to continuing the chain
        , _callback(std::move(callback)) {}

    /**
     * @brief Signals that middleware processing was successful and the
     *        request should continue to the next middleware or handler in the chain.
     */
    void
    next() {
        _continue_chain = true;
        if (_callback) _callback(_continue_chain);
    }

    /**
     * @brief Signals that middleware processing should stop, and no further
     *        middlewares or handlers in the chain should be executed.
     *        The current middleware is assumed to have handled the response.
     */
    void stop() { // Added a stop method for clarity
        _continue_chain = false;
        if (_callback) _callback(_continue_chain);
    }
};

} // namespace qb::http
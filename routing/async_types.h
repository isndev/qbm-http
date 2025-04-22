#pragma once

#include <chrono>
#include <functional>
#include <cstdint>
#include <string>
#include <qb/uuid.h>

namespace qb::http {

// Forward declaration for async completion
template <typename Session, typename String>
class AsyncCompletionHandler;

// Forward declaration for async middleware result
class AsyncMiddlewareResult;

// Type d'identifiant de session -> Session identifier type
using SessionId = ::qb::uuid;

// Async request state enumerations
enum class AsyncRequestState {
    PENDING,      // Request is being processed
    COMPLETED,    // Request was successfully completed
    CANCELED,     // Request was canceled (e.g., by timeout)
    DISCONNECTED, // Client disconnected before completion
    TIMEOUT,      // Request timed out
    DEFERRED      // Request processing is deferred
};

// Define Clock type for consistent time measurement
using Clock = std::chrono::steady_clock;

/**
 * @brief Helper class for async middleware result handling
 *
 * This class provides a simple interface for middleware to signal
 * whether to continue with the next middleware or to stop the chain.
 * It's designed to make asynchronous middleware easier to implement
 * and use by providing a fluent interface for continuations.
 */
class AsyncMiddlewareResult {
private:
    bool                      _continue;
    std::function<void(bool)> _callback;

public:
    AsyncMiddlewareResult(std::function<void(bool)> callback)
        : _continue(true)
        , _callback(std::move(callback)) {}

    /**
     * @brief Continue to the next middleware
     *
     * Signals that middleware processing was successful and the
     * request should continue to the next middleware in the chain.
     */
    void
    next() {
        _continue = true;
        _callback(_continue);
    }
};

} // namespace qb::http
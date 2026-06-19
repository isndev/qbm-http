/**
 * @file qbm/http/routing/async_task.h
 * @brief Defines the IAsyncTask interface for executable units in the HTTP request processing chain.
 *
 * This file contains the `IAsyncTask` abstract base class. Any component that can be part of
 * the sequential processing of an HTTP request, such as middleware or a final route handler,
 * should implement this interface. It defines methods for execution, cancellation, and naming.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include <memory> // For std::shared_ptr
#include <string> // For std::string

namespace qb {
namespace http {
// Forward declaration of Context, as IAsyncTask methods use std::shared_ptr<Context<SessionType>>.
// The full definition of Context is in ./context.h.
template <typename SessionType>
class Context;

/**
 * @brief Interface for an asynchronous task in the HTTP request processing chain.
 *
 * Each distinct unit of work in the request lifecycle, such as a piece of middleware
 * or the main route handler, must implement this interface. The routing system
 * executes a chain of these tasks sequentially for an incoming request.
 * The `Context` object orchestrates this execution.
 *
 * @note `IAsyncTask` instances are immutable after router `compile()` — the same
 *       instance may be reused across many concurrent requests on the same
 *       single-threaded listener (pipelining, HTTP/2 multiplexing). Implementations
 *       **must not** store per-request state on the task itself; all per-request
 *       bookkeeping (current-task cursor, in-flight flag, cancellation) is owned
 *       by the `Context`.
 *
 * @tparam SessionType The type of the session object associated with the request context.
 */
template <typename SessionType>
class IAsyncTask {
public:
    /** @brief Virtual destructor to ensure proper cleanup of derived task objects. */
    virtual ~IAsyncTask() = default;

    /**
     * @brief Executes the primary logic of this asynchronous task.
     *
     * Implementations are responsible for performing their specific processing (e.g., modifying
     * the request/response, performing I/O, business logic) and then **must** call
     * `ctx->complete(AsyncTaskResult)` to signal their outcome and allow the request processing
     * chain to proceed or finalize. If the task initiates a truly asynchronous operation
     * (e.g., a non-blocking network call or database query), it should typically capture the `ctx`
     * (e.g., in a lambda passed as a callback to the async operation) and call `ctx->complete()`
     * when that external operation finishes.
     *
     * @param ctx A `std::shared_ptr<Context<SessionType>>` representing the current HTTP request context.
     */
    virtual void execute(std::shared_ptr<Context<SessionType>> ctx) = 0;

    /**
     * @brief Called by the `Context` if the overall request processing is cancelled while this task is
     *        the currently in-flight task for the context.
     *
     * The task should attempt to gracefully terminate any ongoing operations it initiated
     * (e.g., cancel pending I/O, release resources). Because qb listeners are strictly
     * single-threaded, this method is always invoked on the same thread that is running
     * `execute()`; implementations do not need their own synchronisation.
     *
     * @warning Implementations of `cancel()` **must not** call `ctx->complete()`. The `Context` object
     *          is already managing the cancellation and finalization process.
     */
    virtual void cancel() = 0;

    /**
     * @brief Gets a descriptive name for this task, primarily for logging and debugging purposes.
     * @return A `std::string` representing the name of the task.
     */
    [[nodiscard]] virtual std::string name() const = 0;
};
} // namespace http
} // namespace qb

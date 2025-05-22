/**
 * @file qbm/http/routing/custom_route.h
 * @brief Defines the ICustomRoute interface for advanced, class-based HTTP route handlers.
 *
 * This file contains the `ICustomRoute` abstract base class. Implementations of this interface
 * can encapsulate complex, stateful, or otherwise extensive logic for handling specific HTTP routes,
 * offering more structure than simple lambda-based handlers. These custom routes are integrated
 * into the routing system and are responsible for processing the request and managing its lifecycle
 * via the provided `Context`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include <memory>  // For std::shared_ptr
#include <string>    // For std::string
// #include "./async_task.h" // Included for conceptual relation, not direct dependency of this interface's declarations.
// Implementations of ICustomRoute are often adapted into IAsyncTask.

namespace qb::http {
    // Forward declaration of Context, used in method signatures.
    // Full definition is in ./context.h.
    template<typename SessionType>
    class Context;

    /**
     * @brief Interface for a custom, class-based HTTP route handler.
     *
     * Implementing `ICustomRoute` allows developers to create more structured, stateful,
     * or complex logic for handling specific HTTP endpoints compared to using simple lambda functions.
     * An object implementing this interface takes full responsibility for processing the request
     * (available via the `Context`) and signaling its completion.
     *
     * When a route associated with an `ICustomRoute` implementation is matched, the routing
     * system (typically via a `CustomRouteAdapterTask`) will invoke its `process` method.
     *
     * @tparam SessionType The type of the session object associated with the request context.
     */
    template<typename SessionType>
    class ICustomRoute {
    public:
        /** 
         * @brief Virtual destructor.
         * Ensures that derived classes are properly destroyed when managed via base class pointers.
         */
        virtual ~ICustomRoute() = default;

        /**
         * @brief Processes the HTTP request for this custom route.
         *
         * This pure virtual function must be implemented by derived classes. The implementation
         * should contain the core logic for handling the request. This includes accessing request
         * details, performing operations, and populating the response, all via the provided `ctx`.
         *
         * Crucially, the implementation **must** eventually call `ctx->complete(AsyncTaskResult)`
         * to signal the outcome of its processing (e.g., `AsyncTaskResult::COMPLETE` if it handled
         * the request, or `AsyncTaskResult::ERROR` if an unrecoverable error occurred).
         * Failure to call `ctx->complete()` will likely result in the request hanging.
         *
         * @param ctx A `std::shared_ptr<Context<SessionType>>` providing access to the request,
         *            response, session, and other contextual information.
         */
        virtual void process(std::shared_ptr<Context<SessionType> > ctx) = 0;

        /**
         * @brief Gets a descriptive name for this custom route instance.
         * This name is primarily used for logging, debugging, and potentially for metrics or
         * administrative interfaces to identify the route handler.
         * @return A `std::string` representing the name of this custom route.
         */
        [[nodiscard]] virtual std::string name() const = 0;

        /**
         * @brief Called by the `Context` if the request processing associated with this custom route
         *        is cancelled (e.g., due to client disconnection or timeout).
         *
         * Implementations should attempt to gracefully terminate any ongoing asynchronous operations
         * or release held resources. This method might be called from a different thread than `process()`.
         * @warning Implementations of `cancel()` **should not** call `ctx->complete()`. The `Context`
         *          is already managing the cancellation and finalization sequence.
         */
        virtual void cancel() = 0;
    };
} // namespace qb::http 

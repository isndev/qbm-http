/**
 * @file qbm/http/routing/async_task.h
 * @brief Defines the IAsyncTask interface for executable units in the HTTP request processing chain.
 *
 * This file contains the `IAsyncTask` abstract base class. Any component that can be part of
 * the sequential processing of an HTTP request, such as middleware or a final route handler,
 * should implement this interface. It defines methods for execution, cancellation, and naming.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include <memory>  // For std::shared_ptr
#include <string>    // For std::string

namespace qb {
    namespace http {
        // Forward declaration of Context, as IAsyncTask methods use std::shared_ptr<Context<SessionType>>.
        // The full definition of Context is in ./context.h.
        template<typename SessionType>
        class Context;

        /**
         * @brief Interface for an asynchronous task in the HTTP request processing chain.
         *
         * Each distinct unit of work in the request lifecycle, such as a piece of middleware
         * or the main route handler, must implement this interface. The routing system
         * executes a chain of these tasks sequentially for an incoming request.
         * The `Context` object orchestrates this execution.
         *
         * @tparam SessionType The type of the session object associated with the request context.
         */
        template<typename SessionType>
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
            virtual void execute(std::shared_ptr<Context<SessionType> > ctx) = 0;

            /**
             * @brief Called by the `Context` if the overall request processing is cancelled while this task is active
             *        or before it has a chance to execute in a cancelled chain.
             *
             * The task should attempt to gracefully terminate any ongoing operations it initiated
             * (e.g., cancel pending I/O, release resources). This method might be called from a
             * different thread than `execute()` if cancellation is triggered externally.
             *
             * @warning Implementations of `cancel()` **should not** call `ctx->complete()`. The `Context` object
             *          is already managing the cancellation and finalization process.
             */
            virtual void cancel() = 0;

            /**
             * @brief Gets a descriptive name for this task, primarily for logging and debugging purposes.
             * @return A `std::string` representing the name of the task.
             */
            [[nodiscard]] virtual std::string name() const = 0;

            /** 
             * @brief Called by Context to indicate that this task is about to be executed.
             */
            void startProcessing() { _is_being_processed = true; }

            /** 
             * @brief Called by Context to indicate that this task has finished execution (normally or via exception).
             */
            void finishProcessing() { _is_being_processed = false; }

            /** 
             * @brief Checks if the Context is currently processing this task.
             * @return True if processing has started and not yet finished, false otherwise.
             */
            [[nodiscard]] bool isCurrentlyProcessing() const { return _is_being_processed; }

        private:
            /** 
             * @brief Flag indicating whether the `Context` is currently executing this task.
             * This flag is set to `true` by the `Context` just before calling `execute()` on this task,
             * and set back to `false` when this task calls `ctx->complete()` or if an exception occurs.
             * It can be inspected by the `Context` during cancellation to determine if `cancel()` needs
             * to be called on this specific task instance.
             * It is managed via startProcessing()/finishProcessing() by Context.
             */
            bool _is_being_processed = false;
        };
    }
} // namespace qb::http 

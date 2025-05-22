/**
 * @file qbm/http/routing/types.h
 * @brief Core enumerations and type aliases for the HTTP routing system.
 *
 * This file defines fundamental types used throughout the qb-http routing module,
 * including lifecycle hook points (`HookPoint`), asynchronous task outcomes (`AsyncTaskResult`),
 * and function signatures for route and middleware handlers (`RouteHandlerFn`, `MiddlewareHandlerFn`).
 * It also provides a utility function to convert HTTP method enums to strings.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include <functional>
#include <string> // For std::string
#include <memory> // Required for std::shared_ptr
#include "../types.h" // For qb::http::method, qb::http::status

namespace qb::http {
    // Forward declarations
    template<typename SessionType>
    class Context;

    /**
     * @brief Defines specific points in the HTTP request processing lifecycle where custom
     *        logic (hooks) can be attached via `Context::add_lifecycle_hook()`.
     */
    enum class HookPoint {
        PRE_ROUTING, ///< Called before the router attempts to match the request to a route.
        PRE_HANDLER_EXECUTION, ///< Called just before the main route handler (or first task in its chain) is executed.
        POST_HANDLER_EXECUTION,
        ///< Called after the main route handler chain has completed (successfully or with an error, before error chain).
        PRE_RESPONSE_SEND, ///< Called just before the HTTP response is serialized and sent to the client.
        POST_RESPONSE_SEND, ///< Called after the HTTP response has been (or attempted to be) sent.
        REQUEST_COMPLETE
        ///< Called when all processing for the request is finished and the context is about to be destroyed.
    };

    /**
     * @brief Represents the outcome of an asynchronous task (e.g., a middleware or route handler)
     *        within the request processing chain, guiding the `Context` on how to proceed.
     */
    enum class AsyncTaskResult {
        CONTINUE, ///< The current task completed successfully; proceed to the next task in the chain.
        COMPLETE, ///< The current task has fully handled the request and generated a response; finalize processing.
        CANCELLED, ///< Request processing was cancelled (e.g., by client disconnect, timeout, or explicit call).
        ERROR, ///< An error occurred in the current task; attempt to invoke the configured error handling chain.
        FATAL_SPECIAL_HANDLER_ERROR
        ///< A critical error occurred within a special handler (e.g., 404 or error chain itself);
                                       ///< bypass main error chain and respond with a generic 500 error.
    };

    /**
     * @brief Callback to signal the completion of an asynchronous task.
     */
    // template <typename Session> // This type alias seems unused with the new IAsyncTask model
    // using AsyncTaskCompletionCallback = std::function<void(Context<Session>& ctx, AsyncTaskResult result)>;

    /**
     * @brief Defines the function signature for a user-defined HTTP route handler.
     *
     * Route handlers are responsible for processing a matched request and generating a response.
     * They receive a shared pointer to the `Context` object, which provides access to the
     * request, response, session, and path parameters. The handler **must** eventually call
     * `ctx->complete(AsyncTaskResult)` to signal its outcome and allow the routing system
     * to proceed or finalize the request.
     *
     * @tparam SessionType The type of the session object associated with the request context.
     * @param ctx A `std::shared_ptr<Context<SessionType>>` for the current request.
     */
    template<typename SessionType>
    using RouteHandlerFn = std::function<void(std::shared_ptr<Context<SessionType> > ctx)>;

    /**
     * @brief Defines the function signature for a user-defined HTTP middleware handler.
     *
     * Middleware handlers intercept requests before they reach the main route handler.
     * They can inspect/modify the request, perform pre-processing, or short-circuit
     * the request by generating a response themselves.
     *
     * The middleware receives a `ContextPtr` and a `next` callback.
     * - To pass control to the next middleware or route handler in the chain, it should call `next()`.
     *   After `next()` returns (if it's synchronous, or after its async work is done if `next` initiated it),
     *   the middleware can perform post-processing on the response.
     * - To terminate processing and send a response directly, the middleware should set the response
     *   on `ctx->response()` and then call `ctx->complete(AsyncTaskResult::COMPLETE)` instead of `next()`.
     * - If an error occurs, it can call `ctx->complete(AsyncTaskResult::ERROR)`.
     *
     * @tparam SessionType The type of the session object associated with the request context.
     * @param ctx A `std::shared_ptr<Context<SessionType>>` for the current request.
     * @param next A `std::function<void()>` callback. Invoking this function passes control to the
     *             next task in the processing chain. Middleware is responsible for eventually calling
     *             `ctx->complete()` with an appropriate result (often `AsyncTaskResult::CONTINUE` after `next()`).
     */
    template<typename SessionType>
    using MiddlewareHandlerFn = std::function<void(std::shared_ptr<Context<SessionType> > ctx,
                                                   std::function<void()> next)>;
} // namespace qb::http

/**
 * @file qbm/http/routing/middleware.h
 * @brief Defines the IMiddleware interface and related classes for HTTP middleware processing.
 *
 * Middleware is a mechanism for processing HTTP requests and responses. It is used to add
 * functionality to the request/response lifecycle without modifying the core routing logic.
 *
 * Middleware is implemented as a chain of tasks, each of which is responsible for processing
 * a part of the request/response lifecycle. The chain is executed in order, and the output
 * of each task is passed as input to the next task.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

#include "../logger.h" // For LOG_HTTP_ERROR, LOG_HTTP_WARN
#include "./async_task.h"
#include "./context.h"
#include "./types.h"

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <variant>

namespace qb::http {
/**
 * @brief Interface for middleware.
 * Middleware processes a request, potentially modifies it or the response,
 * and then typically calls ctx->complete() to pass control to the next task in the chain.
 *
 * @tparam SessionType The session type carried by the request context.
 */
template <typename SessionType>
class IMiddleware {
public:
    virtual ~IMiddleware() = default;

    /**
     * @brief Handles the request.
     * @param ctx The shared context for the request.
     *            The middleware must call ctx->complete() when its processing is done
     *            to allow the chain to proceed or finalize.
     */
    virtual void process(std::shared_ptr<Context<SessionType>> ctx) = 0;

    /**
     * @brief Returns the name of the middleware instance, for logging/debugging.
     * @return The middleware name.
     */
    virtual std::string name() const = 0;

    /**
     * @brief Called if the task chain processing is cancelled.
     * Middleware can implement this to clean up any async operations.
     */
    virtual void cancel() = 0;
};

/**
 * @brief Adapts an IMiddleware instance to the IAsyncTask interface.
 *
 * Wraps an @ref IMiddleware so it can participate in an @ref IAsyncTask chain.
 * Exceptions escaping the middleware's `process()` are caught, logged, and (when
 * the context is still pending) converted into an `INTERNAL_SERVER_ERROR`
 * completion so the chain does not stall.
 *
 * @tparam SessionType The session type carried by the request context.
 */
template <typename SessionType>
class MiddlewareTask final : public IAsyncTask<SessionType> {
private:
    std::shared_ptr<IMiddleware<SessionType>> _middleware;
    std::string                               _name;

public:
    /**
     * @brief Constructs a task wrapping the given middleware.
     * @param middleware The middleware instance to adapt; must not be null.
     * @param name A human-readable name used for logging/debugging.
     * @throws std::invalid_argument If @p middleware is null.
     */
    explicit MiddlewareTask(std::shared_ptr<IMiddleware<SessionType>> middleware, std::string name = "MiddlewareTask")
        : _middleware(std::move(middleware))
        , _name(std::move(name)) {
        if (!_middleware) {
            throw std::invalid_argument("MiddlewareTask: middleware pointer cannot be null.");
        }
    }

    /**
     * @brief Executes the wrapped middleware against the given context.
     *
     * Delegates to the middleware's `process()`. Any exception thrown is caught
     * and logged; if the context is neither completed nor cancelled, the response
     * status is set to `INTERNAL_SERVER_ERROR` and the context is completed with
     * @ref AsyncTaskResult::ERROR.
     * @param ctx The shared context for the request.
     */
    void
    execute(std::shared_ptr<Context<SessionType>> ctx) override {
        try {
            _middleware->process(ctx);
            // The middleware's handle method is responsible for calling ctx->complete()
        } catch (const std::exception &e) {
            // Log the exception with request context if available
            if (ctx) {
                LOG_HTTP_ERROR("MiddlewareTask [" << name() << "]: Exception during process() - "
                                                  << "Method: " << std::to_string(ctx->request().method()) << ", "
                                                  << "Path: " << ctx->request().uri().path() << ", "
                                                  << "Error: " << e.what());
            } else {
                LOG_HTTP_ERROR("MiddlewareTask [" << name() << "]: Exception during process() - " << e.what());
            }
            // If middleware throws, it means it didn't call complete. We should signal error.
            if (ctx && !ctx->is_completed() && !ctx->is_cancelled()) {
                ctx->response().status()                     = qb::http::status::INTERNAL_SERVER_ERROR;
                const qb::http::AsyncTaskResult error_result = qb::http::AsyncTaskResult::ERROR;
                ctx->complete(error_result);
            }
        } catch (...) {
            if (ctx) {
                LOG_HTTP_ERROR("MiddlewareTask [" << name() << "]: Unknown exception during process() - "
                                                  << "Method: " << std::to_string(ctx->request().method()) << ", "
                                                  << "Path: " << ctx->request().uri().path());
            } else {
                LOG_HTTP_ERROR("MiddlewareTask [" << name() << "]: Unknown exception during process()");
            }
            if (ctx && !ctx->is_completed() && !ctx->is_cancelled()) {
                ctx->response().status()                     = qb::http::status::INTERNAL_SERVER_ERROR;
                const qb::http::AsyncTaskResult error_result = qb::http::AsyncTaskResult::ERROR;
                ctx->complete(error_result);
            }
        }
    }

    /**
     * @brief Forwards cancellation to the wrapped middleware.
     *
     * Any exception thrown by the middleware's `cancel()` is caught and logged
     * as a warning; cancellation never propagates an exception.
     */
    void
    cancel() override {
        if (_middleware) {
            try {
                _middleware->cancel();
            } catch (const std::exception &e) {
                LOG_HTTP_WARN("MiddlewareTask [" << name() << "]: Exception during cancel() - " << e.what());
            } catch (...) {
                LOG_HTTP_WARN("MiddlewareTask [" << name() << "]: Unknown exception during cancel()");
            }
        }
    }

    /**
     * @brief Returns the configured name of this task.
     * @return The task name supplied at construction.
     */
    std::string
    name() const override {
        return _name;
    }
};

/**
 * @brief Middleware implementation backed by a user-supplied handler function.
 *
 * Adapts a @ref MiddlewareHandlerFn (taking the context and a `next` callback)
 * to the @ref IMiddleware interface. Invoking the `next` callback completes the
 * context with @ref AsyncTaskResult::CONTINUE exactly once; subsequent calls are
 * ignored with a warning. If the handler neither calls `next` nor completes the
 * context itself, it is responsible for completing the context with an
 * appropriate result.
 *
 * @tparam SessionType The session type carried by the request context.
 */
template <typename SessionType>
class FunctionalMiddleware : public IMiddleware<SessionType> {
private:
    MiddlewareHandlerFn<SessionType> _handler_fn;
    std::string                      _name; // For potential use if IMiddleware gets a name(), or for debugging

public:
    /**
     * @brief Constructs a functional middleware from a handler.
     * @param handler_fn The handler invoked for each request; must not be null.
     * @param name A human-readable name used for logging/debugging.
     * @throws std::invalid_argument If @p handler_fn is null.
     */
    FunctionalMiddleware(MiddlewareHandlerFn<SessionType> handler_fn, std::string name)
        : _handler_fn(std::move(handler_fn))
        , _name(std::move(name)) {
        if (!_handler_fn) {
            throw std::invalid_argument("FunctionalMiddleware: handler_fn cannot be null.");
        }
    }

    /**
     * @brief Invokes the handler, supplying a one-shot `next` continuation.
     *
     * The `next` callback, when called the first time, completes the context with
     * @ref AsyncTaskResult::CONTINUE (unless already completed/cancelled); further
     * calls are ignored with a warning. Exceptions escaping the handler are caught
     * and logged; if the context is still pending, the response is set to
     * `INTERNAL_SERVER_ERROR` and completed with @ref AsyncTaskResult::ERROR.
     * @param ctx The shared context for the request.
     */
    void
    process(std::shared_ptr<Context<SessionType>> ctx) override {
        auto finalization_deferral = ctx->defer_finalization_scope();
        auto next_called           = std::make_shared<std::atomic_bool>(false);
        try {
            _handler_fn(ctx, [ctx_capture = ctx, middleware_name = _name, next_called]() {
                // Pass the 'next' callback
                // If 'next' is called by the MiddlewareHandlerFn, it means this middleware
                // has finished its part and wants the chain to continue.
                if (next_called->exchange(true, std::memory_order_acq_rel)) {
                    LOG_HTTP_WARN("FunctionalMiddleware [" << middleware_name << "]: next() called more than once; ignoring duplicate call.");
                    return;
                }
                if (!ctx_capture->is_completed() && !ctx_capture->is_cancelled()) {
                    ctx_capture->complete(qb::http::AsyncTaskResult::CONTINUE);
                }
            });
        } catch (const std::exception &e) {
            if (ctx) {
                LOG_HTTP_ERROR("FunctionalMiddleware [" << _name << "]: Exception during process() - "
                                                        << "Method: " << std::to_string(ctx->request().method()) << ", "
                                                        << "Path: " << ctx->request().uri().path() << ", "
                                                        << "Error: " << e.what());
            } else {
                LOG_HTTP_ERROR("FunctionalMiddleware [" << _name << "]: Exception during process() - " << e.what());
            }
            if (ctx && !ctx->is_completed() && !ctx->is_cancelled()) {
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->response().body()   = "Internal Server Error";
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                ctx->complete(qb::http::AsyncTaskResult::ERROR);
            }
        } catch (...) {
            if (ctx) {
                LOG_HTTP_ERROR("FunctionalMiddleware [" << _name << "]: Unknown exception during process() - "
                                                        << "Method: " << std::to_string(ctx->request().method()) << ", "
                                                        << "Path: " << ctx->request().uri().path());
            } else {
                LOG_HTTP_ERROR("FunctionalMiddleware [" << _name << "]: Unknown exception during process()");
            }
            if (ctx && !ctx->is_completed() && !ctx->is_cancelled()) {
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->response().body()   = "Internal Server Error";
                ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
                ctx->complete(qb::http::AsyncTaskResult::ERROR);
            }
        }
        // If the MiddlewareHandlerFn does not call its 'next' callback,
        // it is responsible for calling ctx->complete() itself with an appropriate result
        // (e.g., COMPLETE or ERROR).
    }

    /**
     * @brief Returns the configured name of this middleware.
     * @return The name supplied at construction.
     */
    std::string
    name() const override {
        return _name;
    }

    /**
     * @brief No-op cancellation hook for functional middleware.
     *
     * Functional middleware holds no async state to release; override is provided
     * to satisfy the @ref IMiddleware interface.
     */
    void
    cancel() override {
        /* Optional: Implement cancellation logic if needed */
    }
};

// Helper function to create middleware tasks, can be useful
// template <typename SessionType, typename ConcreteMiddleware, typename... Args>
// std::shared_ptr<MiddlewareTask<SessionType>> make_middleware_task(Args&&... args) {
//     auto middleware = std::make_shared<ConcreteMiddleware>(std::forward<Args>(args)...);
//     return std::make_shared<MiddlewareTask<SessionType>>(std::move(middleware));
// }
} // namespace qb::http

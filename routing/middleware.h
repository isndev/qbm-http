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
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Routing
 */
#pragma once

#include "./async_task.h"
#include "./context.h"
#include "./types.h"
#include "../logger.h" // For LOG_HTTP_ERROR, LOG_HTTP_WARN

#include <functional>
#include <string>
#include <memory>
#include <variant>

namespace qb::http {
    /**
     * @brief Interface for middleware.
     * Middleware processes a request, potentially modifies it or the response,
     * and then typically calls ctx->complete() to pass control to the next task in the chain.
     */
    template<typename SessionType>
    class IMiddleware {
    public:
        virtual ~IMiddleware() = default;

        /**
         * @brief Handles the request.
         * @param ctx The shared context for the request. 
         *            The middleware must call ctx->complete() when its processing is done 
         *            to allow the chain to proceed or finalize.
         */
        virtual void process(std::shared_ptr<Context<SessionType> > ctx) = 0;

        /**
         * @brief Returns the name of the middleware instance, for logging/debugging.
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
     */
    template<typename SessionType>
    class MiddlewareTask : public IAsyncTask<SessionType> {
    private:
        std::shared_ptr<IMiddleware<SessionType> > _middleware;
        std::string _name;

    public:
        explicit MiddlewareTask(std::shared_ptr<IMiddleware<SessionType> > middleware,
                                std::string name = "MiddlewareTask")
            : _middleware(std::move(middleware)), _name(std::move(name)) {
            if (!_middleware) {
                throw std::invalid_argument("MiddlewareTask: middleware pointer cannot be null.");
            }
        }

        void execute(std::shared_ptr<Context<SessionType> > ctx) override {
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
                    ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                    const qb::http::AsyncTaskResult error_result = qb::http::AsyncTaskResult::ERROR;
                    ctx->complete(error_result);
                }
            }
        }

        void cancel() override {
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

        std::string name() const override {
            // If IMiddleware had a get_middleware_name(), we could use it:
            // return _middleware ? _middleware->get_middleware_name() : "UnnamedMiddlewareTask";
            return _name;
        }
    };

    // Renaming Adapter Class to FunctionalMiddleware
    template<typename SessionType>
    class FunctionalMiddleware : public IMiddleware<SessionType> {
    private:
        MiddlewareHandlerFn<SessionType> _handler_fn;
        std::string _name; // For potential use if IMiddleware gets a name(), or for debugging

    public:
        FunctionalMiddleware(MiddlewareHandlerFn<SessionType> handler_fn, std::string name)
            : _handler_fn(std::move(handler_fn)), _name(std::move(name)) {
            if (!_handler_fn) {
                throw std::invalid_argument("FunctionalMiddleware: handler_fn cannot be null.");
            }
        }

        void process(std::shared_ptr<Context<SessionType> > ctx) override {
            _handler_fn(ctx, [ctx_capture = ctx, middleware_name = _name]() {
                // Pass the 'next' callback
                // If 'next' is called by the MiddlewareHandlerFn, it means this middleware
                // has finished its part and wants the chain to continue.
                if (!ctx_capture->is_completed() && !ctx_capture->is_cancelled()) {
                    ctx_capture->complete(qb::http::AsyncTaskResult::CONTINUE);
                }
            });
            // If the MiddlewareHandlerFn does not call its 'next' callback, 
            // it is responsible for calling ctx->complete() itself with an appropriate result
            // (e.g., COMPLETE or ERROR).
        }

        // This name is primarily for debugging or if IMiddleware evolves to have name()
        std::string name() const override { return _name; }

        void cancel() override {
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

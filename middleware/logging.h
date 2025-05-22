/**
 * @file qbm/http/middleware/logging.h
 * @brief Defines middleware for logging HTTP requests and responses.
 *
 * This file provides the `LoggingMiddleware` class template, which allows for flexible
 * logging of incoming HTTP requests and their corresponding outgoing responses.
 * It uses a user-provided callback function to perform the actual logging, enabling
 * integration with various logging frameworks or custom logging mechanisms.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <memory>      // For std::shared_ptr, std::make_shared
#include <functional>  // For std::function
#include <string>      // For std::string, std::to_string
#include <stdexcept>   // For std::invalid_argument
#include <utility>     // For std::move

#include "../routing/middleware.h" // For IMiddleware, Context, AsyncTaskResult, HookPoint
#include "../request.h"            // For qb::http::Request
#include "../response.h"           // For qb::http::Response
#include "../types.h"              // For qb::http::status, http_method_to_string, std::to_string(qb::http::status)

namespace qb::http {
    /** @brief Defines the severity levels for logging messages used by `LoggingMiddleware`. */
    enum class LogLevel {
        Debug, ///< Detailed diagnostic information, useful for developers.
        Info, ///< General information about system operation (e.g., request received).
        Warning, ///< Indicates a potential issue or an unusual event that is not critical.
        Error ///< Signifies an error that prevented normal operation of a specific task.
    };

    /**
     * @brief Middleware for logging HTTP requests and their corresponding responses.
     *
     * This middleware captures basic information about an incoming request (e.g., method, URI path)
     * when it processes the request. It then registers a lifecycle hook with the `Context`
     * to log information about the outgoing response (e.g., status code) once the request
     * processing is complete (at `HookPoint::REQUEST_COMPLETE`).
     *
     * Logging is performed via a user-provided `LogFunction` callback, allowing customization
     * of the logging destination and format. Different log levels can be specified for
     * request and response messages.
     *
     * @tparam SessionType The type of the session object managed by the router, used by `Context`.
     */
    template<typename SessionType>
    class LoggingMiddleware : public IMiddleware<SessionType> {
    public:
        /** @brief Convenience alias for a shared pointer to the request `Context`. */
        using ContextPtr = std::shared_ptr<Context<SessionType> >;
        /**
         * @brief Defines the signature for the user-provided logging callback function.
         * @param level The `LogLevel` indicating the severity of the log message.
         * @param message The formatted log message string.
         */
        using LogFunction = std::function<void(LogLevel level, const std::string &message)>;

        /**
         * @brief Constructs a `LoggingMiddleware` instance.
         *
         * @param log_fn The function to be called for logging messages. This function must not be null.
         * @param req_level The `LogLevel` to use for request log messages. Defaults to `LogLevel::Info`.
         * @param res_level The `LogLevel` to use for response log messages. Defaults to `LogLevel::Debug`.
         * @param instance_name An optional name for this middleware instance, useful for identification in logs
         *                      or when multiple logging middlewares are used. Defaults to "LoggingMiddleware".
         * @throws std::invalid_argument if `log_fn` is null.
         */
        LoggingMiddleware(
            LogFunction log_fn,
            LogLevel req_level = LogLevel::Info,
            LogLevel res_level = LogLevel::Debug,
            std::string instance_name = "LoggingMiddleware"
        ) noexcept(false) // std::function move constructor is noexcept, std::string move is noexcept.
        // std::invalid_argument can be thrown.
            : _log_function(std::move(log_fn))
              , _request_level(req_level)
              , _response_level(res_level)
              , _name(std::move(instance_name)) {
            if (!_log_function) {
                throw std::invalid_argument("LoggingMiddleware: log_function cannot be null.");
            }
        }

        /**
         * @brief Processes the incoming request by logging its details and registering a hook
         *        for logging the response when the request processing completes.
         * Calls `ctx->complete(AsyncTaskResult::CONTINUE)` to pass control to the next task.
         * @param ctx The shared `Context` for the current request.
         */
        void process(ContextPtr ctx) override {
            // User log_fn can throw, add_lifecycle_hook might allocate
            log_request(ctx->request());

            // Add a lifecycle hook to log the response details when the request is fully processed.
            ctx->add_lifecycle_hook([this](Context<SessionType> &ctx_ref, HookPoint point) {
                if (point == HookPoint::REQUEST_COMPLETE) {
                    log_response(ctx_ref.response());
                }
            });

            ctx->complete(AsyncTaskResult::CONTINUE);
        }

        /** @brief Gets the configured name of this middleware instance. */
        [[nodiscard]] std::string name() const noexcept override {
            return _name;
        }

        /**
         * @brief Handles a cancellation notification.
         * For this logging middleware, cancellation is a no-op as it doesn't manage long-running async tasks.
         */
        void cancel() noexcept override {
            // No specific cancellation logic needed for logging.
        }

    private:
        /**
         * @brief Logs information about the incoming HTTP request using the configured `_log_function`.
         * @param request The `Request` object to log.
         */
        void log_request(const Request &request) {
            if (!_log_function) return; // Should not happen due to constructor check
            std::string message = "Request: " + format_request_info(request);
            try {
                _log_function(_request_level, message);
            } catch (...) {
                /* Suppress exceptions from user log function */
            }
        }

        /**
         * @brief Logs information about the outgoing HTTP response using the configured `_log_function`.
         * @param response The `Response` object to log.
         */
        void log_response(const Response &response) {
            if (!_log_function) return;
            std::string message = "Response: " + format_response_info(response);
            try {
                _log_function(_response_level, message);
            } catch (...) {
                /* Suppress exceptions from user log function */
            }
        }

        /**
         * @brief Formats basic request information (method and URI path) into a string for logging.
         * @param request The `Request` object.
         * @return A formatted string (e.g., "GET /index.html").
         */
        [[nodiscard]] std::string format_request_info(const Request &request) const {
            // Assumes request.uri().path() returns a type convertible to std::string or string_view
            // and http_method_to_string is available and returns std::string.
            return std::to_string(request.method()) + " " + std::string(request.uri().path());
        }

        /**
         * @brief Formats basic response information (status code and reason phrase) into a string for logging.
         * @param response The `Response` object.
         * @return A formatted string (e.g., "200 OK").
         */
        [[nodiscard]] std::string format_response_info(const Response &response) const {
            return std::to_string(static_cast<int>(response.status())) + " " + std::to_string(response.status());
        }

        LogFunction _log_function; ///< User-provided function for actual logging.
        LogLevel _request_level; ///< Log level for request messages.
        LogLevel _response_level; ///< Log level for response messages.
        std::string _name; ///< Name of this middleware instance.
    };

    /**
     * @brief Factory function to create a `std::shared_ptr` to a `LoggingMiddleware` instance.
     * @tparam SessionType The session type used by the HTTP context.
     * @param log_fn The function to be called for logging messages. Must not be null.
     * @param request_level Log level for request messages. Defaults to `LogLevel::Info`.
     * @param response_level Log level for response messages. Defaults to `LogLevel::Debug`.
     * @param name Optional name for the middleware instance. Defaults to "LoggingMiddleware".
     * @return A `std::shared_ptr<LoggingMiddleware<SessionType>>`.
     * @throws std::invalid_argument if `log_fn` is null.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<LoggingMiddleware<SessionType> >
    logging_middleware(
        typename LoggingMiddleware<SessionType>::LogFunction log_fn,
        LogLevel request_level = LogLevel::Info,
        LogLevel response_level = LogLevel::Debug,
        const std::string &name = "LoggingMiddleware"
    ) {
        return std::make_shared<LoggingMiddleware<SessionType> >(
            std::move(log_fn),
            request_level,
            response_level,
            name
        );
    }
} // namespace qb::http

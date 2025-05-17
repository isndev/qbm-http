#pragma once

#include <memory>
#include <functional>
#include <string>
#include <chrono> // For timing if needed, though not directly used by logging now

// New Includes for qb::http routing system
#include "../routing/middleware.h" // Includes IMiddleware, Context, AsyncTaskResult
#include "../request.h"            // For qb::http::Request
#include "../response.h"           // For qb::http::Response
#include "../types.h"              // For http_method_to_string, http_status enum and potentially http_status_name
                                   // Assuming http_method_name and http_status_name are available or replaced by qb::http::http_method_to_string etc.

// Removed old middleware_interface.h

namespace qb::http {

/** @brief Defines the severity levels for logging messages. */
enum class LogLevel {
    Debug,  ///< Detailed information, typically of interest only when diagnosing problems.
    Info,   ///< Confirmation that things are working as expected.
    Warning,///< An indication that something unexpected happened, or indicative of some problem in the near future (e.g. 'disk space low'). The software is still working as expected.
    Error   ///< Due to a more serious problem, the software has not been able to perform some function.
};

// Helper to convert http_status to string. 
// Consider moving to a common utility if not already present in routing/types.h or types.h
namespace internal {
    inline std::string http_status_to_string_for_logging(qb::http::status s) {
        // This can be expanded or use a proper mapping from http_status enum if available
        // For now, just converting the integer value.
        return std::to_string(static_cast<int>(s));
    }
} // namespace internal

/**
 * @brief Middleware for logging HTTP requests and their corresponding responses.
 *
 * This middleware logs basic information about incoming requests (method, path)
 * and outgoing responses (status code). Logging occurs via a user-provided log function.
 * Request logging happens when the middleware handles the request.
 * Response logging is deferred using a lifecycle hook and occurs after the request is complete.
 *
 * @tparam SessionType The type of the session object managed by the router.
 */
template <typename SessionType>
class LoggingMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    /** 
     * @brief Function signature for the user-provided logging callback.
     * @param level The severity level of the log message.
     * @param message The log message string.
     */
    using LogFunction = std::function<void(LogLevel level, const std::string& message)>;
    
    /**
     * @brief Constructs a LoggingMiddleware instance.
     *
     * @param log_function The function to be called for logging messages. Must not be null.
     * @param request_level The log level for request messages. Defaults to LogLevel::Info.
     * @param response_level The log level for response messages. Defaults to LogLevel::Debug.
     * @param name An optional name for this middleware instance (for logging/debugging).
     * @throws std::invalid_argument if log_function is null.
     */
    LoggingMiddleware(
        LogFunction log_function,
        LogLevel request_level = LogLevel::Info,
        LogLevel response_level = LogLevel::Debug,
        std::string name = "LoggingMiddleware"
    ) : _log_function(std::move(log_function)),
        _request_level(request_level),
        _response_level(response_level),
        _name(std::move(name)) {
        if (!_log_function) {
            throw std::invalid_argument("LoggingMiddleware: log_function cannot be null.");
        }
    }
    
    /**
     * @brief Handles the incoming request by logging it and setting up a hook for response logging.
     * @param ctx The shared context for the current request.
     */
    void process(ContextPtr ctx) override {
        log_request(ctx->request());
        
        ctx->add_lifecycle_hook([this](Context<SessionType>& ctx_ref, HookPoint point) {
            if (point == HookPoint::REQUEST_COMPLETE) {
                log_response(ctx_ref.response());
            }
        });
        
        ctx->complete(AsyncTaskResult::CONTINUE);
    }
    
    /** @brief Gets the name of this middleware instance. */
    std::string name() const override {
        return _name;
    }

    /** @brief Handles cancellation; a no-op for this middleware. */
    void cancel() override {
        // No specific cancellation logic needed.
    }
    
private:
    /** @brief Logs information about the incoming request. */
    void log_request(const Request& request) {
        // _log_function already checked for null in constructor
        std::string message = "Request: " + format_request_info(request);
        _log_function(_request_level, message);
    }
    
    /** @brief Logs information about the outgoing response. */
    void log_response(const Response& response) {
        // _log_function already checked for null in constructor
        std::string message = "Response: " + format_response_info(response);
        _log_function(_response_level, message);
    }
    
    /** @brief Formats basic request information (method and path) for logging. */
    std::string format_request_info(const Request& request) const {
        return qb::http::http_method_to_string(request.method) + " " + std::string(request.uri().path());
    }
    
    /** @brief Formats basic response information (status code) for logging. */
    std::string format_response_info(const Response& response) const {
        return internal::http_status_to_string_for_logging(response.status_code);
    }
    
    LogFunction _log_function;
    LogLevel _request_level;
    LogLevel _response_level;
    std::string _name;
};

/**
 * @brief Factory function to create a LoggingMiddleware instance.
 * @tparam SessionType The session type.
 * @param log_function The function to be called for logging messages.
 * @param request_level Log level for request messages (default: Info).
 * @param response_level Log level for response messages (default: Debug).
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created LoggingMiddleware.
 */
template <typename SessionType>
std::shared_ptr<LoggingMiddleware<SessionType>>
logging_middleware(
    typename LoggingMiddleware<SessionType>::LogFunction log_function,
    LogLevel request_level = LogLevel::Info,
    LogLevel response_level = LogLevel::Debug,
    const std::string& name = "LoggingMiddleware"
) {
    return std::make_shared<LoggingMiddleware<SessionType>>(
        std::move(log_function),
        request_level,
        response_level,
        name
    );
}

} // namespace qb::http 
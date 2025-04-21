#pragma once

#include <memory>
#include <functional>
#include <string>
#include "./middleware_interface.h"
namespace qb::http {

/**
 * @brief Log level
 */
enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error
};

/**
 * @brief Middleware for logging requests and responses
 */
template <typename Session, typename String = std::string>
class LoggingMiddleware : public ISyncMiddleware<Session, String> {
public:
    using Context = typename ISyncMiddleware<Session, String>::Context;
    using LogFunction = std::function<void(LogLevel, const std::string&)>;
    
    /**
     * @brief Constructor
     * @param log_function Logging function
     * @param request_level Log level for requests
     * @param response_level Log level for responses
     * @param name Middleware name
     */
    LoggingMiddleware(
        LogFunction log_function,
        LogLevel request_level = LogLevel::Info,
        LogLevel response_level = LogLevel::Debug,
        std::string name = "LoggingMiddleware"
    ) : _log_function(std::move(log_function)),
        _request_level(request_level),
        _response_level(response_level),
        _name(std::move(name)) {}
    
    /**
     * @brief Process a request
     * @param ctx Request context
     * @return Middleware result
     */
    MiddlewareResult process(Context& ctx) override {
        log_request(ctx.request);
        
        ctx.on_done([this](Context& ctx) {
            log_response(ctx.response);
        });
        
        return MiddlewareResult::Continue();
    }
    
    /**
     * @brief Get the middleware name
     */
    std::string name() const override {
        return _name;
    }
    
private:
    void log_request(const typename Context::Request& request) {
        std::string message = "Request: " + format_request(request);
        _log_function(_request_level, message);
    }
    
    void log_response(const typename Context::Response& response) {
        std::string message = "Response: " + format_response(response);
        _log_function(_response_level, message);
    }
    
    std::string format_request(const typename Context::Request& request) {
        return request.method() + " " + request.uri();
    }
    
    std::string format_response(const typename Context::Response& response) {
        return std::to_string(response.status_code()) + " " + 
               response.status_message();
    }
    
    LogFunction _log_function;
    LogLevel _request_level;
    LogLevel _response_level;
    std::string _name;
};

/**
 * @brief Create a logging middleware
 */
template <typename Session, typename String = std::string>
auto logging_middleware(
    typename LoggingMiddleware<Session, String>::LogFunction log_function,
    LogLevel request_level = LogLevel::Info,
    LogLevel response_level = LogLevel::Debug,
    const std::string& name = "LoggingMiddleware"
) {
    auto middleware = std::make_shared<LoggingMiddleware<Session, String>>(
        std::move(log_function),
        request_level,
        response_level,
        name
    );
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

} // namespace qb::http 
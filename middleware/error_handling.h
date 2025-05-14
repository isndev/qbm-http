#pragma once

#include <memory>
#include <functional>
#include <string>
#include <vector>
#include <qb/system/container/unordered_map.h>
#include "./middleware_interface.h"

// REMOVE HACK for debugging - This should not be here
// extern std::vector<std::string> test_mw_middleware_execution_log;

namespace qb::http {

/**
 * @brief Middleware for centralized error handling
 */
template <typename Session, typename String = std::string>
class ErrorHandlingMiddleware : public ISyncMiddleware<Session, String> {
public:
    using Context = typename ISyncMiddleware<Session, String>::Context;
    using ErrorHandler = std::function<void(Context&, const std::string&)>;
    using StatusHandler = std::function<void(Context&)>;
    
    /**
     * @brief Constructor
     * @param name Middleware name
     */
    ErrorHandlingMiddleware(std::string name = "ErrorHandlingMiddleware")
        : _name(std::move(name)) {}
    
    /**
     * @brief Register an error handler for a specific status code
     * @param status_code HTTP status code to handle
     * @param handler Function to call when this status code is encountered
     * @return Reference to this middleware for chaining
     */
    ErrorHandlingMiddleware& on_status(http_status status_code, StatusHandler handler) {
        _status_handlers[status_code] = std::move(handler);
        return *this;
    }
    
    /**
     * @brief Register an error handler for a range of status codes
     * @param min_status Minimum HTTP status code in range
     * @param max_status Maximum HTTP status code in range
     * @param handler Function to call when a status in this range is encountered
     * @return Reference to this middleware for chaining
     */
    ErrorHandlingMiddleware& on_status_range(http_status min_status, http_status max_status, StatusHandler handler) {
        for (int code = min_status; code <= max_status; ++code) {
            _status_handlers[static_cast<http_status>(code)] = handler;
        }
        return *this;
    }
    
    /**
     * @brief Register a generic error handler
     * @param handler Function to call for any error
     * @return Reference to this middleware for chaining
     */
    ErrorHandlingMiddleware& on_any_error(ErrorHandler handler) {
        _generic_handler = std::move(handler);
        return *this;
    }
    
    /**
     * @brief Process a request
     * @param ctx Request context
     * @return Middleware result
     */
    MiddlewareResult process(Context& ctx) override {
        // Using ctx.add_event for internal logging within the middleware
        ctx.add_event(_name + "_process_CALLED_for_path: " + std::string(ctx.request.uri().path()));

        // Set up error handler that runs after response is generated
        ctx.after_handling([this, middleware_name = this->_name](Context& ctx_ref) { 
            ctx_ref.add_event(middleware_name + "_after_handling_lambda_CALLED_for_path: " + std::string(ctx_ref.request.uri().path()) + "_status: " + std::to_string(ctx_ref.response.status_code));
            if (ctx_ref.response.status_code >= 400) {
                this->handle_error_response(ctx_ref);
            }
        });
        
        // Set up error handler for explicit error callbacks
        ctx.on_error([this, middleware_name = this->_name](Context& ctx_err, const std::string& error_message) {
            ctx_err.add_event(middleware_name + "_on_error_lambda_CALLED_msg: " + error_message);
            if (_generic_handler) {
                _generic_handler(ctx_err, error_message);
            }
            this->handle_error_response(ctx_err);
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
    void handle_error_response(Context& ctx) {
        ctx.add_event(_name + "_handle_error_response_CALLED_status: " + std::to_string(ctx.response.status_code));
        http_status status = ctx.response.status_code;
        
        // Check if we have a specific handler for this status code
        auto it = _status_handlers.find(status);
        if (it != _status_handlers.end()) {
            ctx.add_event(_name + "_found_specific_status_handler_for_" + std::to_string(status));
            it->second(ctx);
        }
        // Otherwise, check for range handlers (4xx, 5xx)
        else if (status >= 500 && _status_handlers.find(HTTP_STATUS_INTERNAL_SERVER_ERROR) != _status_handlers.end()) {
            ctx.add_event(_name + "_using_500_range_handler_for_" + std::to_string(status));
            _status_handlers[HTTP_STATUS_INTERNAL_SERVER_ERROR](ctx);
        }
        else if (status >= 400 && _status_handlers.find(HTTP_STATUS_BAD_REQUEST) != _status_handlers.end()) {
            ctx.add_event(_name + "_using_400_range_handler_for_" + std::to_string(status));
            _status_handlers[HTTP_STATUS_BAD_REQUEST](ctx);
        }
    }
    
    std::string _name;
    qb::unordered_map<http_status, StatusHandler> _status_handlers;
    ErrorHandler _generic_handler;
};

/**
 * @brief Create an error handling middleware
 */
template <typename Session, typename String = std::string>
auto error_handling_middleware(const std::string& name = "ErrorHandlingMiddleware") {
    auto middleware = std::make_shared<ErrorHandlingMiddleware<Session, String>>(name);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

} // namespace qb::http 
#pragma once

#include <memory>
#include <string>
#include <vector>
#include "./middleware_interface.h"
#include "../auth/auth.h"

namespace qb::http {

/**
 * @brief Middleware for authentication and authorization
 * 
 * This middleware authenticates HTTP requests using JWT tokens and authorizes
 * access based on user roles. It integrates with the authentication framework
 * and provides a fluent API for configuration.
 * 
 * @tparam Session HTTP session type
 * @tparam String String type (std::string or std::string_view)
 */
template <typename Session, typename String = std::string>
class AuthMiddleware : public ISyncMiddleware<Session, String> {
public:
    using Context = typename ISyncMiddleware<Session, String>::Context;
    
    /**
     * @brief Default constructor
     */
    AuthMiddleware() 
        : _auth_manager(auth::Options())
        , _user_context_key("user")
        , _require_auth(true)
        , _required_roles({})
        , _require_all_roles(false)
        , _name("AuthMiddleware") {}
    
    /**
     * @brief Constructor with authentication options
     * @param options Authentication options
     * @param name Middleware name
     */
    explicit AuthMiddleware(
        const auth::Options& options,
        std::string name = "AuthMiddleware"
    ) : _auth_manager(options)
      , _user_context_key("user")
      , _require_auth(true)
      , _required_roles({})
      , _require_all_roles(false)
      , _name(std::move(name)) {}
    
    /**
     * @brief Process a request
     * @param ctx Request context
     * @return Middleware result
     */
    MiddlewareResult process(Context& ctx) override {
        // Extract token from header
        const auto& auth_header = ctx.request.header(_auth_manager.get_options().get_auth_header_name());
        
        // Check if authentication is required and no header is provided
        if (_require_auth && auth_header.empty()) {
            return handle_auth_error(ctx, HTTP_STATUS_UNAUTHORIZED, "Authentication required");
        }
        
        // If no header is provided and auth is optional, continue without user
        if (auth_header.empty()) {
            return MiddlewareResult::Continue();
        }
        
        // Extract token from header
        std::string token = _auth_manager.extract_token_from_header(auth_header);
        if (token.empty()) {
            // Invalid auth format (e.g., missing Bearer)
            if (_require_auth) {
                return handle_auth_error(ctx, HTTP_STATUS_UNAUTHORIZED, "Invalid authentication format");
            }
            return MiddlewareResult::Continue();
        }
        
        // Verify token and extract user information
        auto user = _auth_manager.verify_token(token);
        if (!user) {
            // Token is invalid or expired
            if (_require_auth) {
                return handle_auth_error(ctx, HTTP_STATUS_UNAUTHORIZED, "Invalid or expired token");
            }
            return MiddlewareResult::Continue();
        }
        
        // Store user information in context
        ctx.set(_user_context_key, *user);
        
        // Check role-based authorization if required
        if (!_required_roles.empty()) {
            bool authorized = _require_all_roles ? 
                user->has_all_roles(_required_roles) : 
                user->has_any_role(_required_roles);
                
            if (!authorized) {
                return handle_auth_error(ctx, HTTP_STATUS_FORBIDDEN, "Insufficient permissions");
            }
        }
        
        // Authentication and authorization successful
        return MiddlewareResult::Continue();
    }
    
    /**
     * @brief Get the middleware name
     */
    std::string name() const override {
        return _name;
    }
    
    /**
     * @brief Set the key used to store user data in context
     * @param key Context key for user data
     * @return Reference to this middleware
     */
    AuthMiddleware& with_user_context_key(const std::string& key) {
        _user_context_key = key;
        return *this;
    }
    
    /**
     * @brief Configure authentication requirements
     * @param required Whether authentication is required
     * @return Reference to this middleware
     */
    AuthMiddleware& with_auth_required(bool required) {
        _require_auth = required;
        return *this;
    }
    
    /**
     * @brief Require specific roles for authorization
     * @param roles Required roles
     * @param require_all If true, all roles are required; if false, any role is sufficient
     * @return Reference to this middleware
     */
    AuthMiddleware& with_roles(const std::vector<std::string>& roles, bool require_all = false) {
        _required_roles = roles;
        _require_all_roles = require_all;
        return *this;
    }
    
    /**
     * @brief Set a custom error handler
     * @param handler Error handler function
     * @return Reference to this middleware
     */
    AuthMiddleware& with_error_handler(
        std::function<MiddlewareResult(Context&, int, const std::string&)> handler
    ) {
        _error_handler = std::move(handler);
        return *this;
    }
    
    /**
     * @brief Set authentication options
     * @param options Authentication options
     * @return Reference to this middleware
     */
    AuthMiddleware& with_options(const auth::Options& options) {
        _auth_manager.set_options(options);
        return *this;
    }
    
    /**
     * @brief Get the underlying auth manager
     * @return Reference to the auth manager
     */
    auth::Manager& auth_manager() {
        return _auth_manager;
    }
    
    /**
     * @brief Get the underlying auth manager (const version)
     * @return Const reference to the auth manager
     */
    const auth::Manager& auth_manager() const {
        return _auth_manager;
    }
    
    /**
     * @brief Generate a token for a user
     * @param user User information
     * @return JWT token string
     */
    std::string generate_token(const auth::User& user) const {
        return _auth_manager.generate_token(user);
    }
    
    /**
     * @brief Verify a token and extract user information
     * @param token JWT token string
     * @return Optional containing user information if valid, or nullopt if invalid
     */
    std::optional<auth::User> verify_token(const std::string& token) const {
        return _auth_manager.verify_token(token);
    }
    
private:
    /**
     * @brief Handle authentication or authorization error
     * @param ctx Request context
     * @param status_code HTTP status code
     * @param message Error message
     * @return Middleware result
     */
    MiddlewareResult handle_auth_error(Context& ctx, int status_code, const std::string& message) {
        if (_error_handler) {
            return _error_handler(ctx, status_code, message);
        }
        
        // Default error handling
        ctx.response.status_code = static_cast<http_status>(status_code);
        ctx.response.add_header("Content-Type", "application/json");
        ctx.response.body() = "{\"error\":\"" + message + "\"}";
        return MiddlewareResult::Stop();
    }
    
    auth::Manager _auth_manager;
    std::string _user_context_key;
    bool _require_auth;
    std::vector<std::string> _required_roles;
    bool _require_all_roles;
    std::string _name;
    std::function<MiddlewareResult(Context&, int, const std::string&)> _error_handler;
};

/**
 * @brief Create an authentication middleware with default configuration
 * 
 * @tparam Session HTTP session type
 * @tparam String String type
 * @return Authentication middleware adapter
 */
template <typename Session, typename String = std::string>
auto auth_middleware() {
    auto middleware = std::make_shared<AuthMiddleware<Session, String>>();
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create an authentication middleware with specific options
 * 
 * @tparam Session HTTP session type
 * @tparam String String type
 * @param options Authentication options
 * @return Authentication middleware adapter
 */
template <typename Session, typename String = std::string>
auto auth_middleware(const auth::Options& options) {
    auto middleware = std::make_shared<AuthMiddleware<Session, String>>(options);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a JWT authentication middleware
 * 
 * @tparam Session HTTP session type
 * @tparam String String type
 * @param secret JWT secret key
 * @return Authentication middleware adapter
 */
template <typename Session, typename String = std::string>
auto jwt_auth_middleware(const std::string& secret) {
    auth::Options options;
    options.secret_key(secret);
    auto middleware = std::make_shared<AuthMiddleware<Session, String>>(options, "JwtAuthMiddleware");
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a role-based authentication middleware
 * 
 * @tparam Session HTTP session type
 * @tparam String String type
 * @param roles Required roles
 * @param require_all If true, all roles are required; if false, any role is sufficient
 * @return Authentication middleware adapter
 */
template <typename Session, typename String = std::string>
auto role_auth_middleware(const std::vector<std::string>& roles, bool require_all = false) {
    auto middleware = std::make_shared<AuthMiddleware<Session, String>>();
    middleware->with_roles(roles, require_all);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

/**
 * @brief Create a basic authentication middleware adapter that skips authentication
 * 
 * Useful for public routes that don't require authentication but might need user context.
 * 
 * @tparam Session HTTP session type
 * @tparam String String type
 * @return Authentication middleware adapter
 */
template <typename Session, typename String = std::string>
auto optional_auth_middleware() {
    auto middleware = std::make_shared<AuthMiddleware<Session, String>>();
    middleware->with_auth_required(false);
    return std::make_shared<SyncMiddlewareAdapter<Session, String>>(std::move(middleware));
}

} // namespace qb::http


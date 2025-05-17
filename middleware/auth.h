#pragma once

#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <functional>

#include "../routing/middleware.h"
#include "../auth.h"
#include <qb/json.h>

namespace qb::http {

/**
 * @brief Middleware for authenticating and authorizing HTTP requests.
 *
 * This middleware typically works in conjunction with a JWT processing middleware.
 * It extracts user information (potentially from a JWT payload set by a prior middleware)
 * or from an Authorization header, verifies it, and checks roles against configured requirements.
 * 
 * @tparam SessionType The type of the session object managed by the router.
 */
template <typename SessionType>
class AuthMiddleware : public IMiddleware<SessionType> {
public:
    using ContextPtr = std::shared_ptr<Context<SessionType>>;
    
    /**
     * @brief Default constructor.
     * Initializes with default authentication options, requiring authentication
     * and using "user" as the context key for storing the authenticated user.
     */
    AuthMiddleware() 
        : _auth_manager(auth::Options())
        , _user_context_key("user")
        , _require_auth(true)
        , _required_roles({})
        , _require_all_roles(false)
        , _name("AuthMiddleware") {}
    
    /**
     * @brief Constructs AuthMiddleware with specific authentication options and a name.
     * @param options The authentication options to use (e.g., secret keys, token settings).
     * @param name An optional name for this middleware instance (for logging/debugging).
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
     * @brief Handles the incoming request for authentication and authorization.
     * 
     * The process is as follows:
     * 1. Attempts to retrieve user information from a "jwt_payload" key in the context 
     *    (assumed to be set by a preceding JWT validation middleware).
     * 2. If not found in context, attempts to extract and verify a token from the Authorization header.
     * 3. If authentication is required and no valid user can be determined, an error response is sent.
     * 4. If a user is successfully determined, they are stored in the context.
     * 5. If role requirements are set, the user's roles are checked.
     * 6. If all checks pass, the middleware chain continues; otherwise, an error response is sent.
     * 
     * @param ctx The shared context for the current request.
     */
    void process(ContextPtr ctx) override {
        std::optional<auth::User> user_opt;

        if (ctx->has("jwt_payload")) {
            if (auto payload_json_opt = ctx->template get<qb::json>("jwt_payload")) {
                try {
                    user_opt = user_from_jwt_payload(*payload_json_opt);
                } catch (const qb::json::exception& /*e*/) {
                    // Malformed payload, treat as if no payload was found
                    user_opt = std::nullopt;
                }
            } else {
                // jwt_payload key exists but is not qb::json, or bad_any_cast from get<>
                // Treat as if no payload was found
            }
        }
        
        if (!user_opt) {
            // Attempt to get user from Authorization header
            const std::string auth_header_name = _auth_manager.get_options().get_auth_header_name();
            const auto& auth_header_sv = ctx->request().header(auth_header_name);
            std::string auth_header_str = std::string(auth_header_sv); // Convert to string for processing

            if (_require_auth && auth_header_str.empty()) {
                handle_auth_error(ctx, HTTP_STATUS_UNAUTHORIZED, "Authentication required: Missing token.");
                return;
            }
            
            if (auth_header_str.empty()) {
                ctx->complete(AsyncTaskResult::CONTINUE);
                return;
            }
            
            std::string token = _auth_manager.extract_token_from_header(auth_header_str);
            if (token.empty()) {
                if (_require_auth) {
                    handle_auth_error(ctx, HTTP_STATUS_UNAUTHORIZED, "Invalid authentication format.");
                    return;
                }
                ctx->complete(AsyncTaskResult::CONTINUE);
                return;
            }
            user_opt = _auth_manager.verify_token(token);
        }

        if (!user_opt) {
            if (_require_auth) {
                handle_auth_error(ctx, HTTP_STATUS_UNAUTHORIZED, "Invalid or expired token / User not determinable.");
                return;
            }
            ctx->complete(AsyncTaskResult::CONTINUE);
            return;
        }
        
        // Store the successfully authenticated user in the context
        ctx->set(_user_context_key, *user_opt);
        
        // Role-based authorization check
        if (!_required_roles.empty()) {
            bool authorized = _require_all_roles ? 
                user_opt->has_all_roles(_required_roles) : 
                user_opt->has_any_role(_required_roles);
                
            if (!authorized) {
                handle_auth_error(ctx, HTTP_STATUS_FORBIDDEN, "Insufficient permissions.");
                return;
            }
        }
        
        // Authentication and authorization successful
        ctx->complete(AsyncTaskResult::CONTINUE);
    }
    
    /**
     * @brief Gets the name of this middleware instance.
     * @return The name of the middleware.
     */
    std::string name() const override {
        return _name;
    }

    /**
     * @brief Handles cancellation of the task. For this synchronous middleware, it's a no-op.
     */
    void cancel() override {
        // No specific cancellation logic needed for this primarily synchronous middleware.
    }
    
    /**
     * @brief Sets the context key used to store the authenticated user object.
     * @param key The new context key.
     * @return A reference to this AuthMiddleware instance for chaining.
     */
    AuthMiddleware& with_user_context_key(const std::string& key) {
        _user_context_key = key;
        return *this;
    }
    
    /**
     * @brief Specifies whether authentication is strictly required.
     * If true, requests without valid authentication will be rejected.
     * If false, requests without authentication will pass through, but if authentication
     * is provided and fails, it will still be rejected.
     * @param required True if authentication is mandatory, false otherwise.
     * @return A reference to this AuthMiddleware instance for chaining.
     */
    AuthMiddleware& with_auth_required(bool required) {
        _require_auth = required;
        return *this;
    }
    
    /**
     * @brief Sets the roles required for authorization.
     * @param roles A vector of role strings.
     * @param require_all If true, the user must have all specified roles. 
     *                    If false (default), the user must have at least one of the specified roles.
     * @return A reference to this AuthMiddleware instance for chaining.
     */
    AuthMiddleware& with_roles(const std::vector<std::string>& roles, bool require_all = false) {
        _required_roles = roles;
        _require_all_roles = require_all;
        return *this;
    }
        
    /**
     * @brief Updates the authentication options used by the internal AuthManager.
     * @param options The new authentication options.
     * @return A reference to this AuthMiddleware instance for chaining.
     */
    AuthMiddleware& with_options(const auth::Options& options) {
        _auth_manager.set_options(options);
        return *this;
    }
    
    /** @brief Provides access to the internal AuthManager instance. */
    auth::Manager& auth_manager() { return _auth_manager; }
    /** @brief Provides const access to the internal AuthManager instance. */
    const auth::Manager& auth_manager() const { return _auth_manager; }
    
    /** @brief Convenience method to generate a token using the internal AuthManager. */
    std::string generate_token(const auth::User& user) const {
        return _auth_manager.generate_token(user);
    }
    
    /** @brief Convenience method to verify a token using the internal AuthManager. */
    std::optional<auth::User> verify_token(const std::string& token) const {
        return _auth_manager.verify_token(token);
    }
    
private:
    /**
     * @brief Handles authentication/authorization errors by setting an error response and completing the context.
     * @param ctx The request context.
     * @param status_code The HTTP status code for the error response.
     * @param message The error message.
     */
    void handle_auth_error(ContextPtr ctx, http_status status_code, const std::string& message) {
        ctx->response().status_code = status_code;
        ctx->response().set_header("Content-Type", "application/json"); // Changed from add_header for single value
        
        qb::json error_json_body;
        error_json_body["error"] = message;
        ctx->response().body() = error_json_body.dump();
        
        ctx->complete(AsyncTaskResult::COMPLETE); 
    }
    
    /**
     * @brief Helper to construct a User object from a JWT JSON payload.
     * @param jwt_payload The qb::json object representing the JWT payload.
     * @return An optional auth::User. Returns std::nullopt if essential fields are missing or malformed.
     */
    std::optional<auth::User> user_from_jwt_payload(const qb::json& jwt_payload) const {
        auth::User user;
        bool id_found = false;
        if (jwt_payload.contains("sub") && jwt_payload["sub"].is_string()) {
            user.id = jwt_payload["sub"].get<std::string>();
            id_found = !user.id.empty();
        }
        if (jwt_payload.contains("username") && jwt_payload["username"].is_string()) {
            user.username = jwt_payload["username"].get<std::string>();
        }
        // If no subject (user ID), consider it invalid for creating a user object from payload
        if (!id_found && user.username.empty()) { // Or if username is also critical
            return std::nullopt;
        }

        if (jwt_payload.contains("roles") && jwt_payload["roles"].is_array()) {
            for (const auto& role_item : jwt_payload["roles"]) { 
                if (role_item.is_string()) {
                    user.roles.push_back(role_item.get<std::string>());
                }
            }
        }
        return user;
    }
    
    auth::Manager _auth_manager;
    std::string _user_context_key;
    bool _require_auth;
    std::vector<std::string> _required_roles;
    bool _require_all_roles;
    std::string _name;
};

/**
 * @brief Creates an AuthMiddleware instance.
 * @tparam SessionType The session type.
 * @param options Authentication options.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created AuthMiddleware.
 */
template <typename SessionType>
std::shared_ptr<AuthMiddleware<SessionType>>
create_auth_middleware(const auth::Options& options = auth::Options(), const std::string& name = "AuthMiddleware") {
    return std::make_shared<AuthMiddleware<SessionType>>(options, name);
}

/**
 * @brief Creates an AuthMiddleware instance specifically for JWT authentication.
 * @tparam SessionType The session type.
 * @param secret The secret key for JWT signing and verification.
 * @param algorithm The JWT algorithm (e.g., "HS256"). Default is "HS256".
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created AuthMiddleware configured for JWT.
 */
template <typename SessionType>
std::shared_ptr<AuthMiddleware<SessionType>>
create_jwt_auth_middleware(const std::string& secret, const std::string& algorithm = "HS256", const std::string& name = "JwtAuthMiddleware") {
    auth::Options options;
    options.secret_key(secret);
    // Note: The 'algorithm' parameter for this factory isn't directly used by auth::Options in its current form.
    // The actual algorithm used for JWT validation is typically determined by qb::io::crypto_jwt or AuthManager internal logic.
    // If auth::Options needs an algorithm setting, it should be added there.
    return std::make_shared<AuthMiddleware<SessionType>>(options, name);
}

/**
 * @brief Creates an AuthMiddleware instance configured for role-based authorization.
 * @tparam SessionType The session type.
 * @param roles A vector of role strings required for access.
 * @param require_all If true, user must have all roles; otherwise, any one role is sufficient.
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created AuthMiddleware.
 */
template <typename SessionType>
std::shared_ptr<AuthMiddleware<SessionType>>
create_role_auth_middleware(const std::vector<std::string>& roles, bool require_all = false, const std::string& name = "RoleAuthMiddleware") {
    auto middleware = std::make_shared<AuthMiddleware<SessionType>>(auth::Options{}, name); 
    middleware->with_roles(roles, require_all);
    return middleware;
}

/**
 * @brief Creates an AuthMiddleware instance where authentication is optional.
 * If authentication details are provided and are invalid, the request is rejected.
 * If no authentication details are provided, the request proceeds without an authenticated user.
 * @tparam SessionType The session type.
 * @param options Authentication options (still used if a token is provided).
 * @param name Optional name for the middleware.
 * @return A shared pointer to the created AuthMiddleware.
 */
template <typename SessionType>
std::shared_ptr<AuthMiddleware<SessionType>>
create_optional_auth_middleware(const auth::Options& options = auth::Options(), const std::string& name = "OptionalAuthMiddleware") {
    auto middleware = std::make_shared<AuthMiddleware<SessionType>>(options, name);
    middleware->with_auth_required(false);
    return middleware;
}

} // namespace qb::http


#ifndef QBM_HTTP_MIDDLEWARE_AUTH_MIDDLEWARE_H
#define QBM_HTTP_MIDDLEWARE_AUTH_MIDDLEWARE_H

#include <memory>
#include <string>
#include <vector>
#include "../routing/routing.h"
#include "../auth/auth.h"

namespace qb {
namespace http {
namespace middleware {

/**
 * @brief Authentication middleware implementation
 *
 * This middleware handles authentication and authorization for HTTP routes.
 * It uses the AuthManager from the core auth module.
 */
template <typename Session, typename String = std::string>
class AuthMiddleware {
private:
    auth::Manager _auth_manager;
    std::string _auth_header_name;
    std::string _user_context_key = "user";

public:
    /**
     * @brief Constructor with auth options
     * @param options Authentication options
     * @param user_context_key Key used to store user data in context (default: "user")
     */
    explicit AuthMiddleware(const auth::Options& options = auth::Options(), 
                           const std::string& user_context_key = "user") 
        : _auth_manager(options)
        , _auth_header_name(options.get_auth_header_name())
        , _user_context_key(user_context_key) {}

    /**
     * @brief Get the underlying auth manager
     * @return Reference to the auth manager
     */
    auth::Manager& get_auth_manager() {
        return _auth_manager;
    }
    
    /**
     * @brief Get the underlying auth manager (const version)
     * @return Const reference to the auth manager
     */
    const auth::Manager& get_auth_manager() const {
        return _auth_manager;
    }

    /**
     * @brief Set the key used to store user data in context
     * @param key Context key for user data
     * @return Reference to this middleware
     */
    AuthMiddleware& set_user_context_key(const std::string& key) {
        _user_context_key = key;
        return *this;
    }

    /**
     * @brief Create an authentication middleware handler
     * 
     * This middleware checks for a valid authentication token in the request headers.
     * If a valid token is found, the user information is stored in the request context
     * and the request processing continues. Otherwise, an unauthorized response is sent.
     *
     * @return Middleware handler function
     */
    auto authenticate() {
        return [this](typename Router<Session, String>::Context& ctx) -> bool {
            const auto& auth_header = ctx.request.header(_auth_header_name);
            if (auth_header.empty()) {
                ctx.response.status_code = HTTP_STATUS_UNAUTHORIZED;
                ctx.response.body() = "Authentication required";
                return false;
            }

            std::string token = _auth_manager.extract_token_from_header(auth_header);
            if (token.empty()) {
                ctx.response.status_code = HTTP_STATUS_UNAUTHORIZED;
                ctx.response.body() = "Invalid authentication format";
                return false;
            }

            auto user = _auth_manager.verify_token(token);
            if (!user) {
                ctx.response.status_code = HTTP_STATUS_UNAUTHORIZED;
                ctx.response.body() = "Invalid or expired token";
                return false;
            }

            // Store user information in the request context
            ctx.set(_user_context_key, *user);
            return true;
        };
    }

    /**
     * @brief Create an authorization middleware handler
     *
     * This middleware checks if the authenticated user has the required roles.
     * It should be used after the authenticate middleware.
     *
     * @param roles Required roles
     * @param require_all If true, the user must have all specified roles; if false, only one is required
     * @return Middleware handler function
     */
    auto authorize(const std::vector<std::string>& roles, bool require_all = false) {
        return [this, roles, require_all](typename Router<Session, String>::Context& ctx) -> bool {
            // If no specific roles are required, authorization passes
            if (roles.empty()) {
                return true;
            }

            // First, check if user is authenticated
            if (!ctx.has(_user_context_key)) {
                ctx.response.status_code = HTTP_STATUS_UNAUTHORIZED;
                ctx.response.body() = "Authentication required";
                return false;
            }

            const auto& user = ctx.template get<auth::User>(_user_context_key);
            bool authorized = require_all ? 
                user.has_all_roles(roles) : 
                user.has_any_role(roles);

            if (!authorized) {
                ctx.response.status_code = HTTP_STATUS_FORBIDDEN;
                ctx.response.body() = "Insufficient permissions";
                return false;
            }

            return true;
        };
    }

    /**
     * @brief Generate an authentication token for a user
     * @param user User information
     * @return JWT token string
     */
    std::string generate_token(const auth::User& user) const {
        return _auth_manager.generate_token(user);
    }

    /**
     * @brief Verify an authentication token
     * @param token JWT token string
     * @return Optional containing user information if valid, or nullopt if invalid
     */
    std::optional<auth::User> verify_token(const std::string& token) const {
        return _auth_manager.verify_token(token);
    }
};

} // namespace middleware
} // namespace http
} // namespace qb

#endif // QBM_HTTP_MIDDLEWARE_AUTH_MIDDLEWARE_H 
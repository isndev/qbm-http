#ifndef QBM_HTTP_AUTH_USER_H
#define QBM_HTTP_AUTH_USER_H

#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>

namespace qb {
namespace http {
namespace auth {

/**
 * @brief Structure to store authenticated user information
 *
 * This structure contains all necessary information about an authenticated user,
 * including ID, username, roles, and additional metadata.
 */
struct User {
    std::string                                  id;
    std::string                                  username;
    std::vector<std::string>                     roles;
    std::unordered_map<std::string, std::string> metadata;

    /**
     * @brief Check if the user has a specific role
     * @param role Role to check for
     * @return true if the user has the role, false otherwise
     */
    bool has_role(const std::string &role) const {
        return std::find(roles.begin(), roles.end(), role) != roles.end();
    }

    /**
     * @brief Check if the user has any of the specified roles
     * @param required_roles Roles to check for
     * @return true if the user has at least one of the roles, false otherwise
     */
    bool has_any_role(const std::vector<std::string> &required_roles) const {
        for (const auto &role : required_roles) {
            if (has_role(role))
                return true;
        }
        return false;
    }

    /**
     * @brief Check if the user has all of the specified roles
     * @param required_roles Roles to check for
     * @return true if the user has all the roles, false otherwise
     */
    bool has_all_roles(const std::vector<std::string> &required_roles) const {
        for (const auto &role : required_roles) {
            if (!has_role(role))
                return false;
        }
        return true;
    }
};

// Type alias for backward compatibility
using AuthUser = User;

} // namespace auth
} // namespace http
} // namespace qb

#endif // QBM_HTTP_AUTH_USER_H 
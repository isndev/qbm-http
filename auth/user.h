#pragma once

#include <string>
#include <vector>
#include <algorithm> // For std::find
#include <qb/system/container/unordered_map.h>
// #include <iostream> // For debug logging - remove if only used by adv_test_mw_middleware_execution_log
#include "../utility.h" // Assuming this is for qb::http::utility functions, not directly used in this snippet after removal

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
    qb::unordered_map<std::string, std::string> metadata; // Assuming qb::unordered_map is the intended type

    /**
     * @brief Check if the user has a specific role.
     * @param role_to_check The role string to check for.
     * @return True if the user has the specified role, false otherwise.
     */
    bool has_role(const std::string &role_to_check) const {
        return std::find(roles.begin(), roles.end(), role_to_check) != roles.end();
    }

    /**
     * @brief Check if the user has any of the specified roles.
     * @param required_roles_list A list of roles to check against.
     * @return True if the user has at least one of the roles in the provided list, false otherwise.
     */
    bool has_any_role(const std::vector<std::string> &required_roles_list) const {
        for (const auto &role_to_check : required_roles_list) {
            if (has_role(role_to_check)) { // Calls the User::has_role method
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Check if the user has all of the specified roles.
     * @param required_roles_list A list of roles that the user must possess.
     * @return True if the user has every role in the provided list, false otherwise.
     */
    bool has_all_roles(const std::vector<std::string> &required_roles_list) const {
        for (const auto &role_to_check : required_roles_list) {
            if (!has_role(role_to_check)) { // Calls the User::has_role method
                return false;
            }
        }
        // If the list of required roles is empty, this will (correctly) return true.
        // If it's not empty and all roles were found, it will also return true.
        return true; 
    }
};

// Type alias for backward compatibility or clearer intent in some contexts
using AuthUser = User;

} // namespace auth
} // namespace http
} // namespace qb

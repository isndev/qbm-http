#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <qb/system/container/unordered_map.h>
#include <iostream> // For debug logging
#include "../utility.h"

// Assuming these are declared globally in the test file and are accessible here
extern std::vector<std::string> adv_test_mw_middleware_execution_log;

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
    qb::unordered_map<std::string, std::string> metadata;

    /**
     * @brief Check if the user has a specific role
     * @param role Role to check for
     * @return true if the user has the role, false otherwise
     */
    bool has_role(const std::string &role_to_check) const {
        bool found = std::find(roles.begin(), roles.end(), role_to_check) != roles.end();
        if (adv_test_mw_middleware_execution_log.size() < 1000) {
            std::string current_roles_str_debug;
            for(size_t i=0; i<roles.size(); ++i) { current_roles_str_debug += (i>0?",":"") + roles[i]; }
            adv_test_mw_middleware_execution_log.push_back("[User::has_role] User '" + username + "' checking for role: '" + role_to_check + "'. User has roles: [" + current_roles_str_debug + "]. Found: " + (found ? "true" : "false"));
        }
        return found;
    }

    /**
     * @brief Check if the user has any of the specified roles
     * @param required_roles Roles to check for
     * @return true if the user has at least one of the roles, false otherwise
     */
    bool has_any_role(const std::vector<std::string> &required_roles_list) const {
        if (adv_test_mw_middleware_execution_log.size() < 1000) {
             std::string req_roles_str;
             for(size_t i=0; i<required_roles_list.size(); ++i) { req_roles_str += (i>0?",":"") + required_roles_list[i]; }
             adv_test_mw_middleware_execution_log.push_back("[User::has_any_role] User '" + username + "' checking ANY of roles: [" + req_roles_str + "]");
        }
        for (const auto &role_to_check : required_roles_list) {
            if (has_role(role_to_check)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Check if the user has all of the specified roles
     * @param required_roles Roles to check for
     * @return true if the user has all the roles, false otherwise
     */
    bool has_all_roles(const std::vector<std::string> &required_roles_list) const {
         if (adv_test_mw_middleware_execution_log.size() < 1000) {
             std::string req_roles_str;
             for(size_t i=0; i<required_roles_list.size(); ++i) { req_roles_str += (i>0?",":"") + required_roles_list[i]; }
             std::string current_roles_str_debug;
             for(size_t i=0; i<roles.size(); ++i) { current_roles_str_debug += (i>0?",":"") + roles[i]; }
             adv_test_mw_middleware_execution_log.push_back("[User::has_all_roles] User '" + username + "' checking ALL of roles: [" + req_roles_str + "]. User actually has roles: [" + current_roles_str_debug + "]");
        }
        for (const auto &role_to_check : required_roles_list) {
            if (!has_role(role_to_check)) {
                return false;
            }
        }
        return true;
    }
};

// Type alias for backward compatibility
using AuthUser = User;

} // namespace auth
} // namespace http
} // namespace qb

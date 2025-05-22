/**
 * @file qbm/http/auth/user.h
 * @brief Defines the User structure for representing authenticated user information.
 *
 * This file contains the `User` struct (and its alias `AuthUser`), which is used
 * throughout the HTTP authentication module to store details about an authenticated
 * user, such as their ID, username, roles, and any associated metadata.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Auth
 */
#pragma once

#include <string>     // For std::string
#include <vector>     // For std::vector
#include <algorithm>  // For std::find
#include <qb/system/container/unordered_map.h> // For qb::unordered_map
// #include <iostream> // For debug logging - remove if only used by adv_test_mw_middleware_execution_log
#include "../utility.h" // Assuming this is for qb::http::utility functions, not directly used in this snippet after removal

namespace qb {
namespace http {
namespace auth {

/**
 * @brief Represents an authenticated user within the system.
 *
 * This structure holds essential information about a user who has been authenticated,
 * including a unique identifier, username, a list of assigned roles, and a flexible
 * map for additional metadata.
 */
struct User {
    /** @brief Unique identifier for the user (e.g., UUID, database ID). */
    std::string id;
    /** @brief Username of the user, typically for display or login purposes. */
    std::string username;
    /** @brief A list of roles assigned to the user, used for authorization checks. */
    std::vector<std::string> roles;
    /** @brief A map for storing additional, application-specific metadata about the user. */
    qb::unordered_map<std::string, std::string> metadata;

    /**
     * @brief Checks if the user possesses a specific role.
     * @param role_to_check The role string to check for. Comparison is case-sensitive.
     * @return `true` if the user has the specified role in their `roles` list, `false` otherwise.
     */
    [[nodiscard]] bool has_role(const std::string& role_to_check) const noexcept {
        return std::find(roles.begin(), roles.end(), role_to_check) != roles.end();
    }

    /**
     * @brief Checks if the user possesses at least one of the roles from a given list.
     * @param required_roles_list A vector of role strings to check against.
     * @return `true` if the user has at least one of the roles in `required_roles_list`, `false` otherwise.
     *         Returns `false` if `required_roles_list` is empty.
     */
    [[nodiscard]] bool has_any_role(const std::vector<std::string>& required_roles_list) const noexcept {
        if (required_roles_list.empty()) {
            return false; // Or true, depending on desired semantics for empty list. False seems safer.
        }
        for (const auto& role_to_check : required_roles_list) {
            if (has_role(role_to_check)) { // Calls this->has_role
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Checks if the user possesses all roles from a given list.
     * @param required_roles_list A vector of role strings that the user must have.
     * @return `true` if the user has every role specified in `required_roles_list`.
     *         Returns `true` if `required_roles_list` is empty (vacuously true).
     */
    [[nodiscard]] bool has_all_roles(const std::vector<std::string>& required_roles_list) const noexcept {
        if (required_roles_list.empty()) {
            return true; // User has all roles if no roles are required.
        }
        for (const auto& role_to_check : required_roles_list) {
            if (!has_role(role_to_check)) { // Calls this->has_role
                return false;
            }
        }
        return true;
    }
};

/** @brief Type alias for `qb::http::auth::User`, provided for backward compatibility or alternative naming preference. */
using AuthUser = User;

} // namespace auth
} // namespace http
} // namespace qb

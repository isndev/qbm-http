/**
 * @file qbm/http/auth/user.cpp
 * @brief Implements the role-query helpers of the qb::http::auth::User structure.
 *
 * This file provides the out-of-line definitions for the `User` role aggregation
 * helpers (`has_any_role` and `has_all_roles`). The trivial single-role predicate
 * `has_role` remains inline in the header.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./user.h"

namespace qb {
namespace http {
namespace auth {

bool
User::has_any_role(const std::vector<std::string> &required_roles_list) const noexcept {
    if (required_roles_list.empty()) {
        return false; // Or true, depending on desired semantics for empty list. False seems safer.
    }
    for (const auto &role_to_check : required_roles_list) {
        if (has_role(role_to_check)) {
            // Calls this->has_role
            return true;
        }
    }
    return false;
}

bool
User::has_all_roles(const std::vector<std::string> &required_roles_list) const noexcept {
    if (required_roles_list.empty()) {
        return true; // User has all roles if no roles are required.
    }
    for (const auto &role_to_check : required_roles_list) {
        if (!has_role(role_to_check)) {
            // Calls this->has_role
            return false;
        }
    }
    return true;
}

} // namespace auth
} // namespace http
} // namespace qb

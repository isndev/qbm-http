/**
 * @file qbm/http/auth.h
 * @brief Convenience header for the HTTP Authentication module.
 *
 * This header includes all essential components of the `qb::http::auth` namespace,
 * such as user representation, authentication options, and the authentication manager.
 * Include this file for easy access to the entire HTTP authentication API.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

// Core dependencies for the auth module
#include <qb/io/crypto.h> // For crypto operations used by AuthManager
#include <qb/io/crypto_jwt.h> // For JWT creation and verification capabilities used by AuthManager

// HTTP Authentication module components
#include "./auth/options.h"  // For qb::http::auth::Options
#include "./auth/user.h"     // For qb::http::auth::User
#include "./auth/manager.h"  // For qb::http::auth::Manager

namespace qb {
namespace http {
/**
 * @namespace qb::http::auth
 * @brief Provides classes and utilities for HTTP authentication and authorization.
 *
 * This namespace includes components for managing user authentication, token generation
 * (typically JWT), token verification, and defining authentication options and policies.
 */
namespace auth {

// This header serves as a single include point for all core components
// of the qb::http::auth module, simplifying their inclusion in projects.

} // namespace auth
} // namespace http
} // namespace qb
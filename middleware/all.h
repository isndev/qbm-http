/**
 * @file qbm/http/middleware/all.h
 * @brief Convenience header for including all standard HTTP middleware components.
 *
 * This header acts as an umbrella include, bringing in all available middleware
 * functionalities provided by the `qb::http` module. By including this single file,
 * users can gain access to middleware for timing, logging, CORS, authentication,
 * compression, security headers, static file serving, and more.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#pragma once

// Include all standard middleware components
#include "./conditional.h"
#include "./cors.h"
#include "./error_handling.h"
#include "./logging.h"
#include "./rate_limit.h"
#include "./timing.h"
#include "./transform.h"
#include "./validation.h"
// #include "./recaptcha.h" // Uncomment if reCAPTCHA middleware is to be included by default
#ifdef QB_HAS_SSL
#include "./auth.h"
#include "./jwt.h"
#endif
#include "./compression.h"
#include "./security_headers.h"
#include "./static_files.h"

// Unified `qb::http::middleware::make<Tag, Session>(args...)` entry point that
// aggregates every standard middleware factory under a single, tag-dispatched
// API (see F45). The legacy `create_*_middleware` / `*_middleware` helpers are
// still exported verbatim by the individual headers for source compatibility.
#include "./make.h"

// Additional custom or third-party middleware components can be added by users
// or included here if they become part of the standard set.

/**
 * @namespace qb::http
 * @brief Main namespace for QB HTTP functionalities.
 *        Middleware components are typically defined within this namespace or sub-namespaces.
 */
namespace qb::http {
// This file primarily serves as a bulk include for middleware headers.
// No specific declarations or definitions are typically placed directly here,
// beyond what the included middleware headers provide.
} // namespace qb::http

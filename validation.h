#pragma once

// Main include file for the qb::http::validation System.
// Users should typically include this file to get access to all validation components.

#include "./validation/error.h"
#include "./validation/rule.h"
#include "./validation/schema_validator.h"
#include "./validation/parameter_validator.h"
#include "./validation/sanitizer.h"
#include "./validation/request_validator.h"

// The middleware qbm/http/middleware/validation_middleware.h will include these individually as needed.

namespace qb::http {
    // Namespace alias for convenience, if desired by users of the framework.
    // namespace validation = qb::http::validation; 
} // namespace qb::http 
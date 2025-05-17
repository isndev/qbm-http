#pragma once

// Include all middleware components
#include "timing.h"
#include "logging.h"
#include "transform.h"
#include "conditional.h"
#include "error_handling.h"
#include "cors.h"
#include "validation.h"
#include "rate_limit.h" 
// #include "recaptcha.h"
#include "jwt.h"
#include "auth.h"
#include "compression.h"
#include "security_headers.h"
#include "static_files.h"

// Additional middleware components can be added here

namespace qb::http {
    // This file serves as a single include point for all middleware components
} // namespace qb::http 
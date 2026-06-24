/**
 * @file qbm/http/middleware/security_headers.cpp
 * @brief Out-of-line definitions for the security-headers middleware helpers.
 *
 * Hosts the non-template definitions declared in `security_headers.h`: the
 * CSP nonce generator and the secure-defaults factory. The middleware itself
 * is a class template and remains header-only.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./security_headers.h"

namespace qb::http {
namespace internal {
std::string
generate_random_nonce(size_t length) {
    constexpr size_t MIN_NONCE_LENGTH = 16;
    constexpr size_t MAX_NONCE_LENGTH = 128;
    if (length < MIN_NONCE_LENGTH) {
        length = MIN_NONCE_LENGTH;
    } else if (length > MAX_NONCE_LENGTH) {
        length = MAX_NONCE_LENGTH;
    }
#ifdef QB_HAS_SSL
    return qb::crypto::generate_secure_random_string(length, qb::crypto::range_hex_lower);
#else
    throw std::logic_error("CSP nonce generation requires QB_HAS_SSL");
#endif
}
} // namespace internal

SecurityHeadersOptions
SecurityHeadersOptions::secure_defaults() {
    SecurityHeadersOptions opts;
    opts._hsts_value                         = "max-age=31536000; includeSubDomains"; // 1 year
    opts._set_x_content_type_options_nosniff = true;
    opts._x_frame_options_value              = "SAMEORIGIN";
    opts._content_security_policy_value = "default-src 'self';object-src 'none';frame-ancestors 'self';base-uri 'self';form-action 'self';";
    opts._referrer_policy_value         = "strict-origin-when-cross-origin";
    opts._coop_value                    = "same-origin";
    // COEP can break sites if not carefully configured with cross-origin resources, so not enabled by default here.
    // opts._coep_value = "require-corp";
    opts._x_permitted_cross_domain_policies_value = "none";
    // Permissions-Policy is complex and highly application-specific, so no default value is set.
    return opts;
}
} // namespace qb::http

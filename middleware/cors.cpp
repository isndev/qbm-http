/**
 * @file qbm/http/middleware/cors.cpp
 * @brief Out-of-line definitions for the CORS middleware support types.
 *
 * Contains the non-template, non-inline bodies declared in @c cors.h:
 * the ReDoS-bounded regex matcher and the @c CorsOptions origin-matching and
 * preset-construction logic.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "cors.h"

namespace qb::http {

[[nodiscard]] bool
regex_match_with_timeout(const std::string &origin, const std::regex &pattern, qb::duration /*timeout*/) noexcept {
    try {
        if (origin.length() > cors_security_limits::MAX_ORIGIN_LENGTH) {
            return false;
        }
        return std::regex_match(origin, pattern);
    } catch (...) {
        return false;
    }
}

CorsOptions
CorsOptions::permissive() {
    // credentials(No) is deliberate and load-bearing: this is the DEFAULT config
    // (CorsMiddleware()/cors_middleware()/dev()), and combining a wildcard origin with
    // credentials is a genuine cross-origin credential-theft hole. The CORS spec forbids
    // Access-Control-Allow-Origin:* together with Allow-Credentials:true; the old
    // credentials(Yes) here made process() work around that ban by REFLECTING the caller's
    // Origin and adding Allow-Credentials:true, so any site could read a logged-in victim's
    // authenticated responses. A permissive default is for PUBLIC (non-credentialed)
    // resources: allow every origin, emit a literal '*', send no credentials. Apps that need
    // credentialed cross-origin must enumerate their origins via CorsOptions::secure().
    return CorsOptions()
        .origins({"*"})
        .all_methods()
        .common_headers()
        .credentials(AllowCredentials::No)
        .expose_headers({"Content-Length", "X-Request-Id", "X-Response-Time"}); // Renamed from expose
}

CorsOptions
CorsOptions::secure(const std::vector<std::string> &allowed_origins_list) {
    return CorsOptions()
        .origins(allowed_origins_list)
        .methods({"GET", "POST", "OPTIONS"})        // Common safe methods
        .headers({"Content-Type", "Authorization"}) // Common necessary headers
        .credentials(AllowCredentials::No)          // More secure default
        .max_age(std::chrono::seconds(3600));       // 1 hour cache for preflight
}

bool
CorsOptions::is_origin_allowed(const std::string &origin) const {
    if (origin.empty())
        return false; // Origin header must be present
    if (origin.length() > cors_security_limits::MAX_ORIGIN_LENGTH)
        return false;

    switch (_match_strategy) {
        case OriginMatchStrategy::Exact:
            if (std::find(_origins.begin(), _origins.end(), "*") != _origins.end()) {
                return true; // Wildcard matches all
            }
            return std::find(_origins.begin(), _origins.end(), origin) != _origins.end();
        case OriginMatchStrategy::Regex:
            ensure_patterns_compiled();
            for (const auto &pattern : _regex_patterns) {
                if (regex_match_with_timeout(origin, pattern)) {
                    return true;
                }
            }
            return false;
        case OriginMatchStrategy::Function:
            if (!_origin_matcher_fn) {
                return false;
            }
            try {
                return _origin_matcher_fn(origin);
            } catch (...) {
                // Fail closed: an exception in user matcher must not
                // grant CORS access or break request processing.
                return false;
            }
        default:
            return false;
    }
}

void
CorsOptions::ensure_patterns_compiled() const {
    if (!_patterns_compiled && _match_strategy == OriginMatchStrategy::Regex) {
        _regex_patterns.clear();

        // Security: Limit number of patterns to prevent memory/compilation overhead
        std::size_t patterns_to_compile = std::min(_origins.size(), cors_security_limits::MAX_REGEX_PATTERNS);

        for (std::size_t i = 0; i < patterns_to_compile; ++i) {
            const auto &pattern_str = _origins[i];

            // Security: Skip patterns that exceed maximum length
            if (pattern_str.length() > cors_security_limits::MAX_REGEX_PATTERN_LENGTH) {
                continue;
            }

            try {
                // Use optimized flag for better performance
                _regex_patterns.emplace_back(pattern_str, std::regex_constants::ECMAScript | std::regex_constants::optimize);
            } catch (const std::regex_error & /*e*/) {
                // Optionally log invalid regex patterns from config, but don't let it stop middleware.
            }
        }
        _patterns_compiled = true;
    }
}

} // namespace qb::http

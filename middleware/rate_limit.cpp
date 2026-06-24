/**
 * @file qbm/http/middleware/rate_limit.cpp
 * @brief Out-of-line definitions for the HTTP rate-limiting middleware.
 *
 * Houses the non-template member bodies of `qb::http::RateLimitOptions` whose
 * declarations live in `rate_limit.h`. Templated entities (the
 * `RateLimitMiddleware` class template, the templated extractor accessors, and
 * the factory function templates) remain header-only by design.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./rate_limit.h"

namespace qb::http {

RateLimitOptions
RateLimitOptions::permissive() noexcept {
    return RateLimitOptions()
        .max_requests(1000) // Higher limit
        .window(std::chrono::minutes(1))
        .message("You have reached the rate limit. Please try again later.");
}

RateLimitOptions
RateLimitOptions::secure() noexcept {
    return RateLimitOptions()
        .max_requests(60) // Stricter limit
        .window(std::chrono::minutes(1))
        .message("Rate limit exceeded. Please try again later.");
}

} // namespace qb::http

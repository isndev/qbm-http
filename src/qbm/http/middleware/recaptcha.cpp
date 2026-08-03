/**
 * @file qbm/http/middleware/recaptcha.cpp
 * @brief Out-of-line definitions for the reCAPTCHA verification middleware.
 *
 * Hosts the non-template helper used to assemble the URL-encoded body sent to
 * Google's site verification API. The middleware class itself is templated on
 * the session type and therefore remains header-only.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./recaptcha.h"

namespace qb::http {
namespace detail {
std::string
build_recaptcha_verification_body(std::string_view secret, std::string_view response, std::optional<std::string_view> remote_ip) {
    std::string request_body = "secret=" + qb::io::uri::encode(secret) + "&response=" + qb::io::uri::encode(response);
    if (remote_ip && !remote_ip->empty()) {
        request_body += "&remoteip=" + qb::io::uri::encode(*remote_ip);
    }
    return request_body;
}
} // namespace detail
} // namespace qb::http

/**
 * @file qbm/http/auth/options.cpp
 * @brief Implements non-inline members of qb::http::auth::Options.
 *
 * This file provides the out-of-line definition for
 * `Options::algorithm_from_string`, which resolves a textual JWT algorithm
 * identifier into the corresponding `Options::Algorithm` enum value.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include "./options.h"
#include "../utility.h" // For qb::http::utility::iequals

namespace qb {
namespace http {
namespace auth {

std::optional<Options::Algorithm>
Options::algorithm_from_string(std::string_view algorithm_str) noexcept {
    if (qb::http::utility::iequals(algorithm_str, "HS256"))
        return Algorithm::HMAC_SHA256;
    if (qb::http::utility::iequals(algorithm_str, "HS384"))
        return Algorithm::HMAC_SHA384;
    if (qb::http::utility::iequals(algorithm_str, "HS512"))
        return Algorithm::HMAC_SHA512;
    if (qb::http::utility::iequals(algorithm_str, "RS256"))
        return Algorithm::RSA_SHA256;
    if (qb::http::utility::iequals(algorithm_str, "RS384"))
        return Algorithm::RSA_SHA384;
    if (qb::http::utility::iequals(algorithm_str, "RS512"))
        return Algorithm::RSA_SHA512;
    if (qb::http::utility::iequals(algorithm_str, "ES256"))
        return Algorithm::ECDSA_SHA256;
    if (qb::http::utility::iequals(algorithm_str, "ES384"))
        return Algorithm::ECDSA_SHA384;
    if (qb::http::utility::iequals(algorithm_str, "ES512"))
        return Algorithm::ECDSA_SHA512;
    if (qb::http::utility::iequals(algorithm_str, "EdDSA"))
        return Algorithm::ED25519;
    return std::nullopt;
}

} // namespace auth
} // namespace http
} // namespace qb

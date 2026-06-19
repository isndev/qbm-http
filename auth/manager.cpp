/**
 * @file qbm/http/auth/manager.cpp
 * @brief Implements the qb::http::auth::Manager class for authentication.
 *
 * This file provides the definitions for the methods of the `Manager` class,
 * including token payload generation, token creation using `qb::jwt`,
 * extraction of tokens from HTTP headers, and token verification with user extraction.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Auth
 */

#include "./manager.h"
#include "../logger.h"  // For LOG_HTTP_WARN
#include "../utility.h" // For qb::http::utility::iequals (used in extract_token_from_header)

#include <qb/io/crypto_jwt.h> // For qb::jwt::create, qb::jwt::verify, and related options/structs
#include <qb/json.h>          // For qb::json manipulation

#include <algorithm> // For std::transform, std::find_if_not
#include <charconv>
#include <chrono>  // For std::chrono::system_clock, std::time (used via current_timestamp)
#include <ctime>   // For std::time_t, std::time, std::gmtime (if timestamp_to_iso8601 were used)
#include <iomanip> // For std::put_time, std::get_time (if ISO8601 helpers were used)
#include <limits>
#include <sstream> // For std::ostringstream, std::istringstream (if ISO8601 helpers were used)

namespace qb {
namespace http {
namespace auth {
using json = qb::json;

// Convert epoch timestamp to ISO8601
// static std::string timestamp_to_iso8601(uint64_t timestamp) {
//     std::time_t time = static_cast<std::time_t>(timestamp);
//     std::tm tm = *std::gmtime(&time);
//     std::ostringstream oss;
//     oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
//     return oss.str();
// }

// Convert ISO8601 to epoch timestamp
// static uint64_t iso8601_to_timestamp(const std::string &iso8601) {
//     std::tm tm = {};
//     std::istringstream iss(iso8601);
//     iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
//     return static_cast<uint64_t>(std::mktime(&tm));
// }

// Get current timestamp
static uint64_t
current_timestamp() noexcept {
    // Using std::chrono for a more C++ idiomatic way to get current time.
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
}

static std::optional<json>
decode_unverified_payload(const std::string &token) {
    try {
        const auto token_parts = qb::jwt::decode(token);
        return json::parse(token_parts.payload);
    } catch (...) {
        return std::nullopt;
    }
}

static std::optional<int64_t>
parse_time_claim_as_int64(const json &claim) noexcept {
    if (claim.is_number_integer()) {
        return claim.get<int64_t>();
    }
    if (claim.is_number_unsigned()) {
        const auto as_uint = claim.get<uint64_t>();
        if (as_uint > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            return std::nullopt;
        }
        return static_cast<int64_t>(as_uint);
    }
    if (claim.is_string()) {
        const auto &s        = claim.get_ref<const std::string &>();
        int64_t     parsed   = 0;
        const char *begin    = s.data();
        const char *end      = begin + s.size();
        const auto [ptr, ec] = std::from_chars(begin, end, parsed);
        if (ec == std::errc() && ptr == end) {
            return parsed;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

// Helper: Create payload JSON without serializing to string
// PERFORMANCE FIX: Avoids double conversion (serialize then immediately parse)
static json
create_payload_json(const User &user, const Options &_options) {
    json payload;

    // Standard claims
    payload["sub"] = user.id;
    payload["iat"] = current_timestamp();

    // Expiration if enabled
    if (_options.get_verify_expiration()) {
        payload["exp"] = current_timestamp() + _options.get_token_expiration().count();
    }

    // Add issuer if configured
    if (_options.get_verify_issuer()) {
        payload["iss"] = _options.get_token_issuer();
    }

    // Add audience if configured
    if (_options.get_verify_audience()) {
        payload["aud"] = _options.get_token_audience();
    }

    // User-specific information
    payload["username"] = user.username;
    payload["roles"]    = user.roles;

    // Additional metadata
    if (!user.metadata.empty()) {
        json meta;
        for (const auto &[key, value] : user.metadata) {
            meta[key] = value;
        }
        payload["metadata"] = meta;
    }

    return payload;
}

// Implementation of generate_token_payload
std::string
Manager::generate_token_payload(const User &user) const {
    // PERFORMANCE FIX: Use helper to create JSON, then serialize once
    return create_payload_json(user, _options).dump();
}

// Implementation of generate_token
std::string
Manager::generate_token(const User &user) const {
    // PERFORMANCE FIX: Get JSON directly without serialize/parse cycle
    // Previously: generate_token_payload() serialized to string, then we parsed it back
    // Now: Get JSON object directly and convert to map
    json payload_json = create_payload_json(user, _options);

    // Convert to std::map<std::string, std::string>
    std::map<std::string, std::string> jwt_payload;
    for (auto it = payload_json.begin(); it != payload_json.end(); ++it) {
        if (it.value().is_string()) {
            jwt_payload[it.key()] = it.value().get<std::string>();
        } else {
            jwt_payload[it.key()] = it.value().dump();
        }
    }

    // Configure JWT options
    qb::jwt::CreateOptions options;

    // Map the algorithm
    switch (_options.get_algorithm()) {
        case Options::Algorithm::HMAC_SHA256:
            options.algorithm = qb::jwt::Algorithm::HS256;
            break;
        case Options::Algorithm::HMAC_SHA384:
            options.algorithm = qb::jwt::Algorithm::HS384;
            break;
        case Options::Algorithm::HMAC_SHA512:
            options.algorithm = qb::jwt::Algorithm::HS512;
            break;
        case Options::Algorithm::RSA_SHA256:
            options.algorithm = qb::jwt::Algorithm::RS256;
            break;
        case Options::Algorithm::RSA_SHA384:
            options.algorithm = qb::jwt::Algorithm::RS384;
            break;
        case Options::Algorithm::RSA_SHA512:
            options.algorithm = qb::jwt::Algorithm::RS512;
            break;
        case Options::Algorithm::ECDSA_SHA256:
            options.algorithm = qb::jwt::Algorithm::ES256;
            break;
        case Options::Algorithm::ECDSA_SHA384:
            options.algorithm = qb::jwt::Algorithm::ES384;
            break;
        case Options::Algorithm::ECDSA_SHA512:
            options.algorithm = qb::jwt::Algorithm::ES512;
            break;
        case Options::Algorithm::ED25519:
            options.algorithm = qb::jwt::Algorithm::EdDSA;
            break;
        default:
            options.algorithm = qb::jwt::Algorithm::HS256;
            break;
    }

    // Set the key based on algorithm
    if (options.algorithm == qb::jwt::Algorithm::HS256 || options.algorithm == qb::jwt::Algorithm::HS384
        || options.algorithm == qb::jwt::Algorithm::HS512) {
        // For HMAC, convert the byte vector to string
        options.key = std::string(_options.get_secret_key().begin(), _options.get_secret_key().end());
    } else {
        // For asymmetric, use the private key
        options.key = _options.get_private_key();
    }

    // Generate token using qb::jwt
    return qb::jwt::create(jwt_payload, options);
}

// Implementation of extract_token_from_header
// Operates on `std::string_view` to avoid the chain of intermediate
// string allocations the previous implementation triggered for every
// authenticated request (F42). Only the returned token string allocates.
std::string
Manager::extract_token_from_header(const std::string &auth_header) const {
    constexpr std::string_view whitespace{" \t\n\r\f\v"};
    std::string_view           view{auth_header};

    const auto first = view.find_first_not_of(whitespace);
    if (first == std::string_view::npos) {
        return {};
    }
    view.remove_prefix(first);

    const std::string_view scheme{_options.get_auth_scheme()};
    if (view.length() < scheme.length() + 2) {
        return {};
    }

    // Case-insensitive scheme comparison without intermediate copies.
    if (!qb::http::utility::iequals(view.substr(0, scheme.length()), scheme)) {
        return {};
    }

    // Reject "SchemeToken": a whitespace character must follow the scheme.
    if (std::string_view{" \t\n\r\f\v"}.find(view[scheme.length()]) == std::string_view::npos) {
        return {};
    }

    std::string_view rest        = view.substr(scheme.length());
    const auto       token_begin = rest.find_first_not_of(whitespace);
    if (token_begin == std::string_view::npos) {
        return {};
    }
    rest.remove_prefix(token_begin);

    const auto token_end = rest.find_last_not_of(whitespace);
    if (token_end == std::string_view::npos) {
        return {};
    }
    return std::string{rest.substr(0, token_end + 1)};
}

// Implementation of verify_token
std::optional<User>
Manager::verify_token(const std::string &token) const {
    json payload_json;
    if (_options.get_require_signature_verification()) {
        qb::jwt::VerifyOptions options;

        switch (_options.get_algorithm()) {
            case Options::Algorithm::HMAC_SHA256:
                options.algorithm = qb::jwt::Algorithm::HS256;
                break;
            case Options::Algorithm::HMAC_SHA384:
                options.algorithm = qb::jwt::Algorithm::HS384;
                break;
            case Options::Algorithm::HMAC_SHA512:
                options.algorithm = qb::jwt::Algorithm::HS512;
                break;
            case Options::Algorithm::RSA_SHA256:
                options.algorithm = qb::jwt::Algorithm::RS256;
                break;
            case Options::Algorithm::RSA_SHA384:
                options.algorithm = qb::jwt::Algorithm::RS384;
                break;
            case Options::Algorithm::RSA_SHA512:
                options.algorithm = qb::jwt::Algorithm::RS512;
                break;
            case Options::Algorithm::ECDSA_SHA256:
                options.algorithm = qb::jwt::Algorithm::ES256;
                break;
            case Options::Algorithm::ECDSA_SHA384:
                options.algorithm = qb::jwt::Algorithm::ES384;
                break;
            case Options::Algorithm::ECDSA_SHA512:
                options.algorithm = qb::jwt::Algorithm::ES512;
                break;
            case Options::Algorithm::ED25519:
                options.algorithm = qb::jwt::Algorithm::EdDSA;
                break;
            default:
                options.algorithm = qb::jwt::Algorithm::HS256;
                break;
        }

        if (options.algorithm == qb::jwt::Algorithm::HS256 || options.algorithm == qb::jwt::Algorithm::HS384
            || options.algorithm == qb::jwt::Algorithm::HS512) {
            options.key = std::string(_options.get_secret_key().begin(), _options.get_secret_key().end());
        } else {
            options.key = _options.get_public_key();
        }

        options.verify_expiration = _options.get_verify_expiration();
        options.verify_issuer     = _options.get_verify_issuer();
        options.verify_audience   = _options.get_verify_audience();
        options.verify_not_before = _options.get_verify_not_before();
        options.clock_skew        = _options.get_clock_skew_tolerance();

        if (_options.get_verify_issuer()) {
            options.issuer = _options.get_token_issuer();
        }

        if (_options.get_verify_audience()) {
            options.audience = _options.get_token_audience();
        }

        auto result = qb::jwt::verify(token, options);
        if (!result.is_valid()) {
            return std::nullopt;
        }

        payload_json = json::object();
        for (const auto &[key, value] : result.payload) {
            try {
                payload_json[key] = json::parse(value);
            } catch (...) {
                payload_json[key] = value;
            }
        }
    } else {
        auto payload_opt = decode_unverified_payload(token);
        if (!payload_opt || !payload_opt->is_object()) {
            return std::nullopt;
        }
        payload_json = std::move(*payload_opt);

        const auto now  = static_cast<int64_t>(current_timestamp());
        const auto skew = _options.get_clock_skew_tolerance().count();

        if (_options.get_verify_expiration() && payload_json.contains("exp")) {
            const auto exp_opt = parse_time_claim_as_int64(payload_json["exp"]);
            if (!exp_opt) {
                return std::nullopt;
            }
            const int64_t exp = *exp_opt;
            if (now > exp + skew) {
                return std::nullopt;
            }
        }

        if (_options.get_verify_not_before() && payload_json.contains("nbf")) {
            const auto nbf_opt = parse_time_claim_as_int64(payload_json["nbf"]);
            if (!nbf_opt) {
                return std::nullopt;
            }
            const int64_t nbf = *nbf_opt;
            if (now + skew < nbf) {
                return std::nullopt;
            }
        }

        if (_options.get_verify_issuer()) {
            if (!payload_json.contains("iss") || !payload_json["iss"].is_string()
                || payload_json["iss"].get<std::string>() != _options.get_token_issuer()) {
                return std::nullopt;
            }
        }

        if (_options.get_verify_audience()) {
            if (!payload_json.contains("aud")) {
                return std::nullopt;
            }
            if (payload_json["aud"].is_string()) {
                if (payload_json["aud"].get<std::string>() != _options.get_token_audience()) {
                    return std::nullopt;
                }
            } else if (payload_json["aud"].is_array()) {
                bool found = false;
                for (const auto &aud : payload_json["aud"]) {
                    if (aud.is_string() && aud.get<std::string>() == _options.get_token_audience()) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    return std::nullopt;
                }
            } else {
                return std::nullopt;
            }
        }
    }

    // Extract user data
    User user;

    // Extract standard claims
    if (payload_json.contains("sub") && payload_json["sub"].is_string()) {
        user.id = payload_json["sub"].get<std::string>();
    }

    if (payload_json.contains("username") && payload_json["username"].is_string()) {
        user.username = payload_json["username"].get<std::string>();
    }

    if (user.id.empty() && user.username.empty()) {
        LOG_HTTP_WARN("AuthManager: Token payload does not contain a usable subject or username");
        return std::nullopt;
    }

    if (payload_json.contains("roles")) {
        try {
            json roles_json = payload_json["roles"].is_string() ? json::parse(payload_json["roles"].get<std::string>()) : payload_json["roles"];
            if (roles_json.is_array()) {
                for (const auto &role : roles_json) {
                    user.roles.push_back(role.get<std::string>());
                }
            }
        } catch (...) {
            // SECURITY FIX: Add logging for silent exception swallowing
            // In case of parsing error, leave roles empty but log for audit trail
            LOG_HTTP_WARN("AuthManager: Failed to parse roles JSON for user: " << user.username);
        }
    }

    if (payload_json.contains("metadata")) {
        try {
            json metadata_json =
                payload_json["metadata"].is_string() ? json::parse(payload_json["metadata"].get<std::string>()) : payload_json["metadata"];
            if (metadata_json.is_object()) {
                for (json::iterator it = metadata_json.begin(); it != metadata_json.end(); ++it) {
                    if (it.value().is_string()) {
                        user.metadata[it.key()] = it.value().get<std::string>();
                    } else {
                        user.metadata[it.key()] = it.value().dump();
                    }
                }
            }
        } catch (...) {
            // SECURITY FIX: Add logging for silent exception swallowing
            // In case of parsing error, leave metadata empty but log for audit trail
            LOG_HTTP_WARN("AuthManager: Failed to parse metadata JSON for user: " << user.username);
        }
    }

    return user;
}
} // namespace auth
} // namespace http
} // namespace qb

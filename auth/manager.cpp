#include "manager.h"
#include <ctime>
#include <iomanip>
#include <qb/io/crypto_jwt.h>
#include <qb/json.h>
#include <sstream>

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
static uint64_t current_timestamp() {
    return static_cast<uint64_t>(std::time(nullptr));
}

// Implementation of generate_token_payload
std::string Manager::generate_token_payload(const User &user) const {
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
    payload["roles"] = user.roles;

    // Additional metadata
    if (!user.metadata.empty()) {
        json meta;
        for (const auto &[key, value] : user.metadata) {
            meta[key] = value;
        }
        payload["metadata"] = meta;
    }

    return payload.dump();
}

// Implementation of generate_token
std::string Manager::generate_token(const User &user) const {
    std::string payload = generate_token_payload(user);

    // Parse the payload JSON
    json payload_json = json::parse(payload);

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
    if (options.algorithm == qb::jwt::Algorithm::HS256 ||
        options.algorithm == qb::jwt::Algorithm::HS384 ||
        options.algorithm == qb::jwt::Algorithm::HS512) {
        // For HMAC, convert the byte vector to string
        options.key = std::string(_options.get_secret_key().begin(),
                                  _options.get_secret_key().end());
    } else {
        // For asymmetric, use the private key
        options.key = _options.get_private_key();
    }

    // Generate token using qb::jwt
    return qb::jwt::create(jwt_payload, options);
}

// Implementation of extract_token_from_header
std::string Manager::extract_token_from_header(const std::string &auth_header) const {
    // Expected format: "<scheme> <token>"
    const auto &scheme = _options.get_auth_scheme();
    if (auth_header.length() <= scheme.length() + 1) {
        return "";
    }

    if (auth_header.substr(0, scheme.length()) != scheme) {
        return "";
    }

    // Skip the scheme and space
    return auth_header.substr(scheme.length() + 1);
}

// Implementation of verify_token
std::optional<User> Manager::verify_token(const std::string &token) const {
    // Configure JWT verification options
    qb::jwt::VerifyOptions options;

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
    if (options.algorithm == qb::jwt::Algorithm::HS256 ||
        options.algorithm == qb::jwt::Algorithm::HS384 ||
        options.algorithm == qb::jwt::Algorithm::HS512) {
        // For HMAC, convert the byte vector to string
        options.key = std::string(_options.get_secret_key().begin(),
                                  _options.get_secret_key().end());
    } else {
        // For asymmetric, use the public key
        options.key = _options.get_public_key();
    }

    // Configure verification options
    options.verify_expiration = _options.get_verify_expiration();
    options.verify_issuer = _options.get_verify_issuer();
    options.verify_audience = _options.get_verify_audience();
    options.verify_not_before = _options.get_verify_not_before();
    options.clock_skew = _options.get_clock_skew_tolerance();

    if (_options.get_verify_issuer()) {
        options.issuer = _options.get_token_issuer();
    }

    if (_options.get_verify_audience()) {
        options.audience = _options.get_token_audience();
    }

    // Verify the token
    auto result = qb::jwt::verify(token, options);

    if (!result.is_valid()) {
        return std::nullopt;
    }

    // Extract user data
    User user;

    // Extract standard claims
    if (result.payload.find("sub") != result.payload.end()) {
        user.id = result.payload["sub"];
    }

    if (result.payload.find("username") != result.payload.end()) {
        user.username = result.payload["username"];
    }

    // Extract roles (from string JSON representation)
    if (result.payload.find("roles") != result.payload.end()) {
        try {
            json roles_json = json::parse(result.payload["roles"]);
            if (roles_json.is_array()) {
                for (const auto &role : roles_json) {
                    user.roles.push_back(role.get<std::string>());
                }
            }
        } catch (...) {
            // In case of parsing error, leave roles empty
        }
    }

    // Extract metadata (from string JSON representation)
    if (result.payload.find("metadata") != result.payload.end()) {
        try {
            json metadata_json = json::parse(result.payload["metadata"]);
            if (metadata_json.is_object()) {
                for (json::iterator it = metadata_json.begin();
                     it != metadata_json.end(); ++it) {
                    if (it.value().is_string()) {
                        user.metadata[it.key()] = it.value().get<std::string>();
                    } else {
                        user.metadata[it.key()] = it.value().dump();
                    }
                }
            }
        } catch (...) {
            // In case of parsing error, leave metadata empty
        }
    }

    return user;
}

} // namespace auth
} // namespace http
} // namespace qb 
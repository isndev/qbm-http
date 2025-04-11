#include "auth.h"
#include <qb/json.h>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <qb/io/crypto_jwt.h>

namespace qb {
namespace http {

using json = qb::json;

// Convertir un timestamp epoch en ISO8601
std::string timestamp_to_iso8601(uint64_t timestamp) {
    std::time_t time = static_cast<std::time_t>(timestamp);
    std::tm tm = *std::gmtime(&time);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

// Convertir ISO8601 en timestamp epoch
uint64_t iso8601_to_timestamp(const std::string& iso8601) {
    std::tm tm = {};
    std::istringstream iss(iso8601);
    iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return static_cast<uint64_t>(std::mktime(&tm));
}

// Obtenir le timestamp actuel
uint64_t current_timestamp() {
    return static_cast<uint64_t>(std::time(nullptr));
}

// Implémentation de generate_token_payload
std::string AuthManager::generate_token_payload(const AuthUser& user) const {
    json payload;
    
    // Claims standard
    payload["sub"] = user.id;
    payload["iat"] = current_timestamp();
    
    // Expiration si activée
    if (_options.get_verify_expiration()) {
        payload["exp"] = current_timestamp() + _options.get_token_expiration().count();
    }
    
    // Ajout de l'émetteur si configuré
    if (_options.get_verify_issuer()) {
        payload["iss"] = _options.get_token_issuer();
    }
    
    // Ajout de l'audience si configurée
    if (_options.get_verify_audience()) {
        payload["aud"] = _options.get_token_audience();
    }
    
    // Informations utilisateur spécifiques
    payload["username"] = user.username;
    payload["roles"] = user.roles;
    
    // Métadonnées supplémentaires
    if (!user.metadata.empty()) {
        json meta;
        for (const auto& [key, value] : user.metadata) {
            meta[key] = value;
        }
        payload["metadata"] = meta;
    }
    
    return payload.dump();
}

// Implémentation de generate_token
std::string AuthManager::generate_token(const AuthUser& user) const {
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
        case AuthOptions::Algorithm::HMAC_SHA256:
            options.algorithm = qb::jwt::Algorithm::HS256;
            break;
        case AuthOptions::Algorithm::HMAC_SHA384:
            options.algorithm = qb::jwt::Algorithm::HS384;
            break;
        case AuthOptions::Algorithm::HMAC_SHA512:
            options.algorithm = qb::jwt::Algorithm::HS512;
            break;
        case AuthOptions::Algorithm::RSA_SHA256:
            options.algorithm = qb::jwt::Algorithm::RS256;
            break;
        case AuthOptions::Algorithm::RSA_SHA384:
            options.algorithm = qb::jwt::Algorithm::RS384;
            break;
        case AuthOptions::Algorithm::RSA_SHA512:
            options.algorithm = qb::jwt::Algorithm::RS512;
            break;
        case AuthOptions::Algorithm::ECDSA_SHA256:
            options.algorithm = qb::jwt::Algorithm::ES256;
            break;
        case AuthOptions::Algorithm::ECDSA_SHA384:
            options.algorithm = qb::jwt::Algorithm::ES384;
            break;
        case AuthOptions::Algorithm::ECDSA_SHA512:
            options.algorithm = qb::jwt::Algorithm::ES512;
            break;
        case AuthOptions::Algorithm::ED25519:
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
        options.key = std::string(_options.get_secret_key().begin(), _options.get_secret_key().end());
    } else {
        // For asymmetric, use the private key
        options.key = _options.get_private_key();
    }
    
    // Generate token using qb::jwt
    return qb::jwt::create(jwt_payload, options);
}

// Implémentation de extract_token_from_header
std::string AuthManager::extract_token_from_header(const std::string& auth_header) const {
    // Format attendu: "<scheme> <token>"
    const auto& scheme = _options.get_auth_scheme();
    if (auth_header.length() <= scheme.length() + 1) {
        return "";
    }
    
    if (auth_header.substr(0, scheme.length()) != scheme) {
        return "";
    }
    
    // Skip le schéma et l'espace
    return auth_header.substr(scheme.length() + 1);
}

// Implémentation de verify_token
std::optional<AuthUser> AuthManager::verify_token(const std::string& token) const {
    // Configure JWT verification options
    qb::jwt::VerifyOptions options;
    
    // Map the algorithm
    switch (_options.get_algorithm()) {
        case AuthOptions::Algorithm::HMAC_SHA256:
            options.algorithm = qb::jwt::Algorithm::HS256;
            break;
        case AuthOptions::Algorithm::HMAC_SHA384:
            options.algorithm = qb::jwt::Algorithm::HS384;
            break;
        case AuthOptions::Algorithm::HMAC_SHA512:
            options.algorithm = qb::jwt::Algorithm::HS512;
            break;
        case AuthOptions::Algorithm::RSA_SHA256:
            options.algorithm = qb::jwt::Algorithm::RS256;
            break;
        case AuthOptions::Algorithm::RSA_SHA384:
            options.algorithm = qb::jwt::Algorithm::RS384;
            break;
        case AuthOptions::Algorithm::RSA_SHA512:
            options.algorithm = qb::jwt::Algorithm::RS512;
            break;
        case AuthOptions::Algorithm::ECDSA_SHA256:
            options.algorithm = qb::jwt::Algorithm::ES256;
            break;
        case AuthOptions::Algorithm::ECDSA_SHA384:
            options.algorithm = qb::jwt::Algorithm::ES384;
            break;
        case AuthOptions::Algorithm::ECDSA_SHA512:
            options.algorithm = qb::jwt::Algorithm::ES512;
            break;
        case AuthOptions::Algorithm::ED25519:
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
        options.key = std::string(_options.get_secret_key().begin(), _options.get_secret_key().end());
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
    AuthUser user;
    
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
                for (const auto& role : roles_json) {
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
                for (json::iterator it = metadata_json.begin(); it != metadata_json.end(); ++it) {
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

} // namespace http
} // namespace qb 
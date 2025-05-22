/**
 * @file qbm/http/auth/manager.cpp
 * @brief Implements the qb::http::auth::Manager class for authentication.
 *
 * This file provides the definitions for the methods of the `Manager` class,
 * including token payload generation, token creation using `qb::jwt`,
 * extraction of tokens from HTTP headers, and token verification with user extraction.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Auth
 */

#include "./manager.h"
#include "../utility.h" // For qb::http::utility::iequals (used in extract_token_from_header)

#include <qb/json.h>          // For qb::json manipulation
#include <qb/io/crypto_jwt.h> // For qb::jwt::create, qb::jwt::verify, and related options/structs

#include <chrono>      // For std::chrono::system_clock, std::time (used via current_timestamp)
#include <ctime>       // For std::time_t, std::time, std::gmtime (if timestamp_to_iso8601 were used)
#include <iomanip>     // For std::put_time, std::get_time (if ISO8601 helpers were used)
#include <sstream>     // For std::ostringstream, std::istringstream (if ISO8601 helpers were used)
#include <algorithm>   // For std::transform, std::isspace, std::find_if_not
#include <cctype>      // For std::tolower, std::isspace

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
            static uint64_t current_timestamp() noexcept {
                // Using std::chrono for a more C++ idiomatic way to get current time.
                return static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()
                    ).count()
                );
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
                    for (const auto &[key, value]: user.metadata) {
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
                // Trim leading whitespace from the input auth_header string
                size_t first_char_pos = auth_header.find_first_not_of(" \t\n\r\f\v");
                if (std::string::npos == first_char_pos) {
                    // Header is all whitespace or empty
                    return "";
                }
                std::string trimmed_auth_header = auth_header.substr(first_char_pos);

                const std::string &config_scheme = _options.get_auth_scheme();

                // Minimum length check: scheme + 1 space + at least 1 char for token
                if (trimmed_auth_header.length() < config_scheme.length() + 2) {
                    return "";
                }

                // Extract the scheme part from the trimmed header
                std::string header_scheme_part = trimmed_auth_header.substr(0, config_scheme.length());

                // Convert both to lowercase for case-insensitive comparison
                std::string lower_header_scheme = header_scheme_part;
                std::transform(lower_header_scheme.begin(), lower_header_scheme.end(), lower_header_scheme.begin(),
                               [](unsigned char c) { return std::tolower(c); });

                std::string lower_config_scheme = config_scheme;
                std::transform(lower_config_scheme.begin(), lower_config_scheme.end(), lower_config_scheme.begin(),
                               [](unsigned char c) { return std::tolower(c); });

                if (lower_header_scheme != lower_config_scheme) {
                    return "";
                }

                // After matching the scheme, check if the character immediately following it is a space.
                // This ensures that "SchemeToken" is rejected, while "Scheme Token" is processed.
                if (trimmed_auth_header.length() <= config_scheme.length() ||
                    !std::isspace(static_cast<unsigned char>(trimmed_auth_header[config_scheme.length()]))) {
                    // No character after scheme, or the character is not a space.
                    return "";
                }

                // Find the start of the token part (skip scheme and any following spaces)
                size_t token_start_pos = config_scheme.length();
                while (token_start_pos < trimmed_auth_header.length() && std::isspace(
                           static_cast<unsigned char>(trimmed_auth_header[token_start_pos]))) {
                    token_start_pos++;
                }

                if (token_start_pos >= trimmed_auth_header.length()) {
                    // Only scheme and spaces, no token
                    return "";
                }

                // Extract the token part from the trimmed header
                std::string token = trimmed_auth_header.substr(token_start_pos);

                // Trim trailing whitespace from the token (though JWTs are not expected to have it)
                // Find the last non-whitespace character
                size_t end_pos = token.find_last_not_of(" \t\n\r\f\v");
                if (std::string::npos != end_pos) {
                    token = token.substr(0, end_pos + 1);
                } else {
                    // Token is all whitespace, or empty after leading trim by substr
                    return "";
                }

                return token;
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
                            for (const auto &role: roles_json) {
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

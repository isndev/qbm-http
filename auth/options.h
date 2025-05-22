/**
 * @file qbm/http/auth/options.h
 * @brief Configuration options for HTTP authentication.
 *
 * This file defines the `Options` class (and its alias `AuthOptions`) which encapsulates
 * all configurable settings for the HTTP authentication module. This includes cryptographic keys,
 * chosen algorithms, token expiration policies, issuer/audience verification, and other
 * parameters related to token generation and validation (typically JWTs).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Auth
 */
#pragma once

#include <chrono>      // For std::chrono::seconds
#include <string>      // For std::string
#include <vector>      // For std::vector<unsigned char>
#include <utility>     // For std::move (used in setters if string is rvalue)

namespace qb {
    namespace http {
        namespace auth {
            /**
             * @brief Manages configuration options for HTTP authentication processes.
             *
             * This class provides a comprehensive set of configurable parameters that govern
             * how authentication tokens (e.g., JWTs) are generated and validated. It supports
             * various cryptographic algorithms, key management, and claim verification policies.
             * The fluent-style setters allow for easy and readable configuration chaining.
             */
            class Options {
            public:
                /**
                 * @brief Enumerates the supported cryptographic algorithms for signing and verifying tokens.
                 */
                enum class Algorithm {
                    HMAC_SHA256, ///< HMAC with SHA-256
                    HMAC_SHA384, ///< HMAC with SHA-384
                    HMAC_SHA512, ///< HMAC with SHA-512
                    RSA_SHA256, ///< RSASSA-PKCS1-v1_5 with SHA-256
                    RSA_SHA384, ///< RSASSA-PKCS1-v1_5 with SHA-384
                    RSA_SHA512, ///< RSASSA-PKCS1-v1_5 with SHA-512
                    ECDSA_SHA256, ///< ECDSA with P-256 curve and SHA-256
                    ECDSA_SHA384, ///< ECDSA with P-384 curve and SHA-384
                    ECDSA_SHA512, ///< ECDSA with P-521 curve and SHA-512
                    ED25519 ///< EdDSA with Ed25519 curve
                };

            private:
                // Cryptographic key materials
                std::vector<unsigned char> _secret_key; ///< Secret key for HMAC-based algorithms.
                std::string _public_key; ///< Public key (PEM format) for asymmetric algorithms (verification).
                std::string _private_key; ///< Private key (PEM format) for asymmetric algorithms (signing).

                // Algorithm and token lifetime
                Algorithm _algorithm = Algorithm::HMAC_SHA256; ///< Default signing algorithm.
                std::chrono::seconds _token_expiration{3600}; ///< Token validity duration (default: 1 hour).
                std::chrono::seconds _clock_skew_tolerance{0};
                ///< Clock skew tolerance for time-based claim validation (default: 0s).

                // Standard JWT claims for verification
                std::string _token_issuer; ///< Expected token issuer (`iss` claim).
                std::string _token_audience; ///< Expected token audience (`aud` claim).

                // Header and scheme for token extraction
                std::string _auth_header_name = "Authorization"; ///< HTTP header name to find the token.
                std::string _auth_scheme = "Bearer"; ///< Authentication scheme prefix (e.g., "Bearer").

                // Verification policy flags
                bool _require_signature_verification = true; ///< Whether token signature must be verified.
                bool _verify_expiration = true; ///< Whether to verify token expiration (`exp` claim).
                bool _verify_not_before = true; ///< Whether to verify token not-before time (`nbf` claim).
                bool _verify_issuer = false; ///< Whether to verify the issuer (`iss` claim).
                bool _verify_audience = false; ///< Whether to verify the audience (`aud` claim).

            public:
                /** @brief Default constructor. Initializes options with sensible defaults. */
                Options() = default;

                // --- Fluent Setters ---

                /**
                 * @brief Sets the secret key for HMAC-based algorithms (HS256, HS384, HS512).
                 * @param secret The secret key as a string. It will be converted to bytes.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &secret_key(const std::string &secret) {
                    _secret_key.assign(secret.begin(), secret.end());
                    return *this;
                }

                /**
                 * @brief Sets the secret key for HMAC-based algorithms using a byte vector.
                 * @param secret The secret key as a vector of unsigned chars.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &secret_key(const std::vector<unsigned char> &secret) {
                    _secret_key = secret;
                    return *this;
                }

                /**
                * @brief Sets the secret key for HMAC-based algorithms using a moved byte vector.
                * @param secret The secret key as a vector of unsigned chars (rvalue).
                * @return Reference to this `Options` object for chaining.
                */
                Options &secret_key(std::vector<unsigned char> &&secret) noexcept {
                    _secret_key = std::move(secret);
                    return *this;
                }

                /**
                 * @brief Sets the public key for asymmetric algorithms (RSA, ECDSA, EdDSA) used for token verification.
                 * @param key The public key, typically in PEM format.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &public_key(std::string key) {
                    // Pass by value for potential move
                    _public_key = std::move(key);
                    return *this;
                }

                /**
                 * @brief Sets the private key for asymmetric algorithms (RSA, ECDSA, EdDSA) used for token signing.
                 * @param key The private key, typically in PEM format.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &private_key(std::string key) {
                    // Pass by value for potential move
                    _private_key = std::move(key);
                    return *this;
                }

                /**
                 * @brief Sets the cryptographic algorithm to be used for signing and verifying tokens.
                 * @param alg The `Algorithm` enum value.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &algorithm(Algorithm alg) noexcept {
                    _algorithm = alg;
                    return *this;
                }

                /**
                 * @brief Sets the default validity duration for generated tokens.
                 * @param seconds The duration for which tokens should be valid.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &token_expiration(std::chrono::seconds seconds) noexcept {
                    _token_expiration = seconds;
                    return *this;
                }

                /**
                 * @brief Sets the expected issuer (`iss` claim) for token validation.
                 * If set, `_verify_issuer` is automatically enabled.
                 * @param issuer The issuer identifier string.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &token_issuer(std::string issuer) {
                    // Pass by value
                    _token_issuer = std::move(issuer);
                    _verify_issuer = !_token_issuer.empty();
                    return *this;
                }

                /**
                 * @brief Sets the expected audience (`aud` claim) for token validation.
                 * If set, `_verify_audience` is automatically enabled.
                 * @param audience The audience identifier string.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &token_audience(std::string audience) {
                    // Pass by value
                    _token_audience = std::move(audience);
                    _verify_audience = !_token_audience.empty();
                    return *this;
                }

                /**
                 * @brief Sets the name of the HTTP header from which to extract the token (e.g., "Authorization").
                 * @param name The header name.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &auth_header_name(std::string name) {
                    // Pass by value
                    _auth_header_name = std::move(name);
                    return *this;
                }

                /**
                 * @brief Sets the authentication scheme prefix used in the authorization header (e.g., "Bearer").
                 * @param scheme The scheme string.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &auth_scheme(std::string scheme) {
                    // Pass by value
                    _auth_scheme = std::move(scheme);
                    return *this;
                }

                /**
                 * @brief Enables or disables the requirement for token signature verification.
                 * @param verify `true` to require signature verification (default, recommended), `false` to disable.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &require_signature_verification(bool verify) noexcept {
                    _require_signature_verification = verify;
                    return *this;
                }

                /**
                 * @brief Enables or disables verification of the token's expiration time (`exp` claim).
                 * @param verify `true` to verify expiration (default), `false` to disable.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &verify_expiration(bool verify) noexcept {
                    _verify_expiration = verify;
                    return *this;
                }

                /**
                 * @brief Enables or disables verification of the token's not-before time (`nbf` claim).
                 * @param verify `true` to verify not-before time (default), `false` to disable.
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &verify_not_before(bool verify) noexcept {
                    _verify_not_before = verify;
                    return *this;
                }

                /**
                 * @brief Sets the clock skew tolerance for validating time-based claims (e.g., `exp`, `nbf`).
                 * This allows for slight discrepancies between server and client clocks.
                 * @param tolerance The tolerance duration (e.g., `std::chrono::seconds(60)` for 1 minute).
                 * @return Reference to this `Options` object for chaining.
                 */
                Options &clock_skew_tolerance(std::chrono::seconds tolerance) noexcept {
                    _clock_skew_tolerance = tolerance;
                    return *this;
                }

                // --- Getters ---
                [[nodiscard]] const std::vector<unsigned char> &get_secret_key() const noexcept { return _secret_key; }
                [[nodiscard]] const std::string &get_public_key() const noexcept { return _public_key; }
                [[nodiscard]] const std::string &get_private_key() const noexcept { return _private_key; }
                [[nodiscard]] Algorithm get_algorithm() const noexcept { return _algorithm; }
                [[nodiscard]] std::chrono::seconds get_token_expiration() const noexcept { return _token_expiration; }

                [[nodiscard]] std::chrono::seconds get_clock_skew_tolerance() const noexcept {
                    return _clock_skew_tolerance;
                }

                [[nodiscard]] const std::string &get_token_issuer() const noexcept { return _token_issuer; }
                [[nodiscard]] const std::string &get_token_audience() const noexcept { return _token_audience; }
                [[nodiscard]] const std::string &get_auth_header_name() const noexcept { return _auth_header_name; }
                [[nodiscard]] const std::string &get_auth_scheme() const noexcept { return _auth_scheme; }

                [[nodiscard]] bool get_require_signature_verification() const noexcept {
                    return _require_signature_verification;
                }

                [[nodiscard]] bool get_verify_expiration() const noexcept { return _verify_expiration; }
                [[nodiscard]] bool get_verify_not_before() const noexcept { return _verify_not_before; }
                [[nodiscard]] bool get_verify_issuer() const noexcept { return _verify_issuer; }
                [[nodiscard]] bool get_verify_audience() const noexcept { return _verify_audience; }
            };

            /** @brief Type alias for `qb::http::auth::Options` for backward compatibility or conciseness. */
            using AuthOptions = Options;
        } // namespace auth
    } // namespace http
} // namespace qb

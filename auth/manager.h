/**
 * @file qbm/http/auth/manager.h
 * @brief Defines the AuthManager for handling HTTP authentication tokens and user data.
 *
 * This file contains the `Manager` class (aliased as `AuthManager`), which provides
 * a centralized interface for generating and verifying authentication tokens (typically JWTs),
 * extracting tokens from HTTP headers, and managing authentication options via the `Options` class.
 * It works in conjunction with the `User` structure to represent authenticated entities.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Auth
 */
#pragma once

#include <string>
#include <optional>    // For std::optional
#include <functional>  // For std::function (if used by future extensions)

// #include <qb/io/crypto.h> // General crypto, crypto_jwt is more specific if only JWTs are handled here
#include <qb/io/crypto_jwt.h> // For qb::jwt::* types and functions used by Manager

#include "./options.h"  // For qb::http::auth::Options
#include "./user.h"     // For qb::http::auth::User

namespace qb {
    namespace http {
        namespace auth {
            /**
             * @brief Manages authentication processes, including token generation and verification.
             *
             * The `Manager` class (often aliased as `AuthManager`) serves as the primary
             * interface for handling authentication tasks. It uses an `Options` object
             * for configuration and interacts with `User` data to create and validate
             * authentication tokens, typically JSON Web Tokens (JWTs).
             */
            class Manager {
            private:
                /** @brief Configuration options for authentication behavior. */
                Options _options;

                /**
                 * @brief (Private) Generates the JSON payload string for a new token.
                 * This method is responsible for constructing the claims that will be included
                 * in the token, based on the provided `User` object and the current `_options`
                 * (e.g., issuer, audience, expiration).
                 * @param user The `User` object for whom the token payload is being generated.
                 * @return A JSON string representing the token payload.
                 * @note The definition of this method is in `manager.cpp`.
                 */
                [[nodiscard]] std::string generate_token_payload(const User &user) const;

            public:
                /**
                 * @brief Constructs an `Manager` with specified authentication options.
                 * @param options The `Options` object containing configuration for token
                 *                generation and verification. Defaults to default-constructed `Options`.
                 */
                explicit Manager(const Options &options = Options()) noexcept
                    : _options(options) {
                }

                /**
                 * @brief Generates an authentication token for the given user.
                 * The token format and signing algorithm are determined by the current `_options`.
                 * @param user The `User` object for whom to generate the token.
                 * @return A string representing the generated authentication token.
                 * @throws May throw exceptions if token generation fails (e.g., cryptographic errors).
                 * @note The definition of this method is in `manager.cpp`.
                 */
                [[nodiscard]] std::string generate_token(const User &user) const;

                /**
                 * @brief Extracts an authentication token from an HTTP Authorization header string.
                 * It expects the header to follow the scheme defined in `_options` (e.g., "Bearer <token>").
                 * The scheme comparison is case-insensitive.
                 * @param auth_header_value The full value of the Authorization header.
                 * @return The extracted token string if found and format is correct; otherwise, an empty string.
                 * @note This method does not verify the token, only extracts it.
                 *       Definition is in `manager.cpp`.
                 */
                [[nodiscard]] std::string extract_token_from_header(const std::string &auth_header_value) const;

                /**
                 * @brief Verifies an authentication token and, if valid, extracts user information.
                 * Verification includes checking the signature, expiration, and other configured claims
                 * based on the current `_options`.
                 * @param token The authentication token string to verify.
                 * @return An `std::optional<User>` containing the authenticated user's information if the token
                 *         is valid. Returns `std::nullopt` if verification fails for any reason
                 *         (e.g., invalid signature, expired, malformed, claims mismatch).
                 * @note The definition of this method is in `manager.cpp`.
                 */
                [[nodiscard]] std::optional<User> verify_token(const std::string &token) const;

                /**
                 * @brief Gets a constant reference to the current authentication options.
                 * @return `const Options&`.
                 */
                [[nodiscard]] const Options &get_options() const noexcept {
                    return _options;
                }

                /**
                 * @brief Updates the authentication options used by this manager.
                 * @param options The new `Options` object to use.
                 */
                void set_options(const Options &options) noexcept {
                    _options = options;
                }
            };

            /** @brief Type alias for `qb::http::auth::Manager` for convenience or backward compatibility. */
            using AuthManager = Manager;
        } // namespace auth
    } // namespace http
} // namespace qb

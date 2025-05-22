/**
 * @file qbm/http/middleware/auth.h
 * @brief Defines AuthMiddleware for HTTP request authentication and authorization.
 *
 * This file provides the `AuthMiddleware` class template, designed to integrate
 * into the qb::http routing system. It handles the verification of user credentials,
 * typically from HTTP headers (e.g., Authorization with a Bearer token) or from
 * context data set by preceding middleware (like a JWT parser). It can also perform
 * role-based authorization checks against an authenticated user.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2025 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Middleware
 */
#pragma once

#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <functional>

#include "../routing/middleware.h"
#include "../auth.h"
#include "../types.h"
#include <qb/json.h>

namespace qb::http {
    /**
     * @brief Middleware for authenticating and authorizing HTTP requests.
     *
     * This middleware uses an `auth::Manager` to verify tokens (typically JWTs)
     * extracted from requests. It can check for tokens in the `Authorization` header
     * or look for pre-validated user information (e.g., a decoded JWT payload)
     * in the request `Context` set by a prior middleware.
     *
     * If authentication is successful, the `auth::User` object is stored in the `Context`.
     * Optionally, it can perform role-based authorization checks.
     *
     * @tparam SessionType The type of the session object managed by the router, used by `Context`.
     */
    template<typename SessionType>
    class AuthMiddleware : public IMiddleware<SessionType> {
    public:
        using ContextPtr = std::shared_ptr<Context<SessionType> >;

        /**
         * @brief Default constructor.
         *
         * Initializes the middleware with default `auth::Options`.
         * By default, authentication is required, and the authenticated `auth::User` object
         * will be stored in the `Context` with the key "user".
         */
        AuthMiddleware()
            : _auth_manager(auth::Options()) // Default AuthManager with default Options
              , _user_context_key("user")
              , _require_auth(true)
              , _required_roles({})
              , _require_all_roles(false)
              , _name("AuthMiddleware") {
        }

        /**
         * @brief Constructs `AuthMiddleware` with specific authentication options and a name.
         * @param options The `auth::Options` to configure the internal `auth::Manager`.
         * @param name An optional name for this middleware instance, useful for logging or debugging.
         */
        explicit AuthMiddleware(
            const auth::Options &options,
            std::string name = "AuthMiddleware"
        ) : _auth_manager(options)
            , _user_context_key("user")
            , _require_auth(true)
            , _required_roles({})
            , _require_all_roles(false)
            , _name(std::move(name)) {
        }

        /**
         * @brief Processes the incoming request for authentication and authorization.
         *
         * The processing flow is as follows:
         * 1. Checks if a "jwt_payload" (or similar, based on upstream middleware conventions)
         *    is present in the `Context`. If so, attempts to construct an `auth::User` from it.
         * 2. If no user is derived from the context, it attempts to extract a token from the
         *    HTTP `Authorization` header (or other configured location via `auth::Options`).
         * 3. If a token is found, it is verified using the internal `auth::Manager`.
         * 4. If authentication is required (`with_auth_required(true)`) and no valid `auth::User`
         *    can be established (either from context or token), an error response (e.g., 401 Unauthorized)
         *    is sent, and processing stops by calling `ctx->complete(AsyncTaskResult::COMPLETE)`.
         * 5. If authentication is not strictly required (`with_auth_required(false)`) and no token is provided
         *    or is invalid, processing continues via `ctx->complete(AsyncTaskResult::CONTINUE)` without an authenticated user.
         *    However, if a token IS provided but is invalid, an error response is still sent.
         * 6. If an `auth::User` is successfully authenticated, it is stored in the `Context` under the key
         *    specified by `with_user_context_key()`.
         * 7. If role requirements are configured (via `with_roles()`), the authenticated user's roles
         *    are checked. If authorization fails, an error response (e.g., 403 Forbidden) is sent.
         * 8. If all checks pass, processing continues to the next task in the chain via `ctx->complete(AsyncTaskResult::CONTINUE)`.
         *
         * @param ctx The shared `Context` for the current request.
         */
        void process(ContextPtr ctx) override {
            std::optional<auth::User> user_opt;

            // 1. Check context for pre-validated user data (e.g., from a preceding JWT parsing middleware)
            if (ctx->has("jwt_payload")) {
                // "jwt_payload" is a conventional key
                if (auto payload_json_opt = ctx->template get<qb::json>("jwt_payload")) {
                    try {
                        user_opt = user_from_jwt_payload(*payload_json_opt);
                    } catch (const qb::json::exception & /*e*/) {
                        // Malformed payload in context; treat as if no payload was found.
                        user_opt = std::nullopt;
                    }
                } else {
                    // jwt_payload key exists but is not qb::json, or bad_any_cast from get<>
                }
            }

            // 2. If no user from context, try extracting and verifying token from header
            if (!user_opt) {
                const std::string &auth_header_name = _auth_manager.get_options().get_auth_header_name();
                // header() returns String type of TRequest, convert to std::string for processing
                std::string auth_header_str = std::string(ctx->request().header(auth_header_name));

                if (auth_header_str.empty()) {
                    if (_require_auth) {
                        handle_auth_error(ctx, qb::http::status::UNAUTHORIZED,
                                          "Authentication required: Missing token or authorization header.");
                        return;
                    }
                    // Not required and no header, proceed without auth user
                    ctx->complete(AsyncTaskResult::CONTINUE);
                    return;
                }

                std::string token = _auth_manager.extract_token_from_header(auth_header_str);
                if (token.empty()) {
                    // Header present but format incorrect or no token after scheme
                    if (_require_auth) {
                        handle_auth_error(ctx, qb::http::status::UNAUTHORIZED,
                                          "Invalid authentication format in header.");
                        return;
                    }
                    // Not required, but malformed header - could be an error or proceed. Let's proceed for now.
                    ctx->complete(AsyncTaskResult::CONTINUE);
                    return;
                }
                // Token extracted, now verify it
                user_opt = _auth_manager.verify_token(token);
            }

            // 3. Evaluate authentication result
            if (!user_opt) {
                // Still no user after trying context and header+token
                if (_require_auth) {
                    handle_auth_error(ctx, qb::http::status::UNAUTHORIZED,
                                      "Invalid or expired token; user authentication failed.");
                    return;
                }
                // Not required and token verification failed (or no token initially), proceed without auth user
                ctx->complete(AsyncTaskResult::CONTINUE);
                return;
            }

            // 4. Authentication successful, store user in context
            ctx->set(_user_context_key, *user_opt);

            // 5. Role-based authorization check (if roles are required)
            if (!_required_roles.empty()) {
                bool authorized_by_role = _require_all_roles
                                              ? user_opt->has_all_roles(_required_roles)
                                              : user_opt->has_any_role(_required_roles);

                if (!authorized_by_role) {
                    handle_auth_error(ctx, qb::http::status::FORBIDDEN,
                                      "Insufficient permissions based on user roles.");
                    return;
                }
            }

            // 6. All checks passed
            ctx->complete(AsyncTaskResult::CONTINUE);
        }

        /**
         * @brief Gets the configured name of this middleware instance.
         * @return The name of the middleware.
         */
        [[nodiscard]] std::string name() const noexcept override {
            return _name;
        }

        /**
         * @brief Handles cancellation notification. Currently a no-op for this middleware
         * as its `process` method is largely synchronous or delegates to synchronous `auth::Manager` calls.
         */
        void cancel() noexcept override {
            // No specific asynchronous operations to cancel within this middleware itself.
            // If AuthManager's methods were async and cancellable, logic would go here.
        }

        // --- Fluent Configuration Methods ---

        /**
         * @brief Sets the key under which the authenticated `auth::User` object will be stored in the `Context`.
         * @param key The context key string. Default is "user".
         * @return Reference to this `AuthMiddleware` instance for chaining.
         */
        AuthMiddleware &with_user_context_key(std::string key) noexcept {
            _user_context_key = std::move(key);
            return *this;
        }

        /**
         * @brief Specifies whether authentication is strictly required for the request to proceed.
         * @param required If `true` (default), requests lacking valid authentication will be rejected.
         *                 If `false`, requests can proceed without authentication, but if authentication
         *                 is attempted (e.g., token provided) and fails, it will still be rejected.
         * @return Reference to this `AuthMiddleware` instance for chaining.
         */
        AuthMiddleware &with_auth_required(bool required) noexcept {
            _require_auth = required;
            return *this;
        }

        /**
         * @brief Sets the roles required for the authenticated user to be authorized.
         * @param roles A vector of role strings. If empty, no role-based check is performed.
         * @param require_all If `true`, the user must possess all roles in the `roles` list.
         *                    If `false` (default), the user must possess at least one of the roles.
         * @return Reference to this `AuthMiddleware` instance for chaining.
         */
        AuthMiddleware &with_roles(std::vector<std::string> roles, bool require_all = false) {
            // Can alloc
            _required_roles = std::move(roles);
            _require_all_roles = require_all;
            return *this;
        }

        /**
         * @brief Updates the `auth::Options` used by the internal `auth::Manager`.
         * @param options The new authentication options to apply.
         * @return Reference to this `AuthMiddleware` instance for chaining.
         */
        AuthMiddleware &with_options(const auth::Options &options) noexcept {
            _auth_manager.set_options(options); // AuthManager::set_options is noexcept
            return *this;
        }

        /** @brief Gets a mutable reference to the internal `auth::Manager`. */
        [[nodiscard]] auth::Manager &auth_manager() noexcept { return _auth_manager; }
        /** @brief Gets a constant reference to the internal `auth::Manager`. */
        [[nodiscard]] const auth::Manager &auth_manager() const noexcept { return _auth_manager; }

        /**
         * @brief Convenience method to generate a token using the internal `auth::Manager`.
         * @param user The `auth::User` for whom to generate the token.
         * @return The generated token string.
         * @throws May throw if token generation in `auth::Manager` fails.
         */
        [[nodiscard]] std::string generate_token(const auth::User &user) const {
            return _auth_manager.generate_token(user);
        }

        /**
         * @brief Convenience method to verify a token using the internal `auth::Manager`.
         * @param token The token string to verify.
         * @return An `std::optional<auth::User>` containing user info if valid, else `std::nullopt`.
         */
        [[nodiscard]] std::optional<auth::User> verify_token(const std::string &token) const {
            return _auth_manager.verify_token(token);
        }

    private:
        /**
         * @brief (Private) Helper to send a standardized JSON error response and complete the context.
         * @param ctx The request `Context`.
         * @param status_code The HTTP status code for the error (e.g., 401, 403).
         * @param message A general error message for the JSON response body.
         */
        void handle_auth_error(ContextPtr ctx, qb::http::status status_code, const std::string &message) {
            ctx->response().status() = status_code;
            ctx->response().set_header("Content-Type", "application/json; charset=utf-8");

            qb::json error_json_body;
            error_json_body["error"] = message; // Simple error structure
            ctx->response().body() = error_json_body.dump();

            ctx->complete(AsyncTaskResult::COMPLETE); // Stop further processing
        }

        /**
         * @brief (Private) Helper to construct an `auth::User` object from a `qb::json` payload.
         *
         * Typically used when a JWT payload has already been decoded and verified by another middleware
         * and placed into the context (e.g., under the key "jwt_payload").
         * This function extracts standard claims like "sub" (subject/ID), "username", and "roles".
         * @param jwt_payload The `qb::json` object representing the JWT payload.
         * @return An `std::optional<auth::User>`. Returns `std::nullopt` if essential claims
         *         (like `sub` or `username` if considered mandatory) are missing or malformed.
         *         Roles are expected to be a JSON array of strings.
         */
        [[nodiscard]] std::optional<auth::User> user_from_jwt_payload(const qb::json &jwt_payload) const {
            if (!jwt_payload.is_object()) return std::nullopt;

            auth::User user;
            bool id_found = false;

            if (jwt_payload.contains("sub") && jwt_payload["sub"].is_string()) {
                user.id = jwt_payload["sub"].get<std::string>();
                if (!user.id.empty()) id_found = true;
            }
            if (jwt_payload.contains("username") && jwt_payload["username"].is_string()) {
                user.username = jwt_payload["username"].get<std::string>();
                // If username is a primary identifier, ensure it's found if id isn't.
                if (!user.username.empty() && !id_found) id_found = true;
            }

            // Require at least some form of identifier (sub or username)
            if (!id_found) {
                return std::nullopt;
            }

            if (jwt_payload.contains("roles") && jwt_payload["roles"].is_array()) {
                for (const auto &role_item: jwt_payload["roles"]) {
                    if (role_item.is_string()) {
                        user.roles.push_back(role_item.get<std::string>());
                    }
                }
            }
            // Metadata parsing could be added here if expected in jwt_payload
            return user;
        }

        auth::Manager _auth_manager; ///< Manages token operations based on _options.
        std::string _user_context_key; ///< Context key for storing the authenticated User.
        bool _require_auth; ///< If true, unauthenticated requests are rejected.
        std::vector<std::string> _required_roles; ///< List of roles for authorization.
        bool _require_all_roles; ///< If true, all _required_roles are needed; else, any one suffices.
        std::string _name; ///< Name of this middleware instance.
    };

    // --- Factory Functions ---

    /**
     * @brief Creates a shared_ptr to an `AuthMiddleware` instance with specified options.
     * @tparam SessionType The session type used by the HTTP context.
     * @param options Authentication options to configure the middleware. Defaults to default `auth::Options`.
     * @param name An optional name for the middleware instance (for logging/debugging).
     * @return `std::shared_ptr<AuthMiddleware<SessionType>>`.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<AuthMiddleware<SessionType> >
    create_auth_middleware(
        const auth::Options &options = auth::Options(),
        const std::string &name = "AuthMiddleware"
    ) {
        return std::make_shared<AuthMiddleware<SessionType> >(options, name);
    }

    /**
     * @brief Creates an `AuthMiddleware` instance configured for JWT processing.
     * @tparam SessionType The session type.
     * @param secret The secret key (for HMAC) or public key (for asymmetric) for JWT verification.
     * @param algorithm The expected JWT algorithm string (e.g., "HS256"). This is used to set up
     *                  the `auth::Options` which in turn configures the internal `auth::Manager`.
     * @param name Optional name for the middleware instance.
     * @return `std::shared_ptr<AuthMiddleware<SessionType>>`.
     * @note The `algorithm` string should map to one of `auth::Options::Algorithm` values.
     *       The underlying `auth::Manager` and `qb::jwt` library handle the specifics.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<AuthMiddleware<SessionType> >
    create_jwt_auth_middleware(
        const std::string &secret,
        const std::string &algorithm_str = "HS256", // String representation of algorithm
        const std::string &name = "JwtAuthMiddleware"
    ) {
        auth::Options options;
        // Determine if secret is for HMAC or if it's a public key for asymmetric
        // This logic is simplified; a real scenario might need more context or different setters in Options
        if (algorithm_str.rfind("HS", 0) == 0) {
            // Starts with HS -> HMAC
            options.secret_key(secret);
        } else {
            // Assume it's a public key for RSA/EC/EdDSA
            options.public_key(secret);
        }

        // Convert string algorithm to enum Options::Algorithm
        // This mapping should be robust. For brevity, a simple if-else chain.
        if (utility::iequals(algorithm_str, "HS256")) options.algorithm(auth::Options::Algorithm::HMAC_SHA256);
        else if (utility::iequals(algorithm_str, "HS384")) options.algorithm(auth::Options::Algorithm::HMAC_SHA384);
        else if (utility::iequals(algorithm_str, "HS512")) options.algorithm(auth::Options::Algorithm::HMAC_SHA512);
        else if (utility::iequals(algorithm_str, "RS256")) options.algorithm(auth::Options::Algorithm::RSA_SHA256);
        else if (utility::iequals(algorithm_str, "RS384")) options.algorithm(auth::Options::Algorithm::RSA_SHA384);
        else if (utility::iequals(algorithm_str, "RS512")) options.algorithm(auth::Options::Algorithm::RSA_SHA512);
        else if (utility::iequals(algorithm_str, "ES256")) options.algorithm(auth::Options::Algorithm::ECDSA_SHA256);
        else if (utility::iequals(algorithm_str, "ES384")) options.algorithm(auth::Options::Algorithm::ECDSA_SHA384);
        else if (utility::iequals(algorithm_str, "ES512")) options.algorithm(auth::Options::Algorithm::ECDSA_SHA512);
        else if (utility::iequals(algorithm_str, "EdDSA")) options.algorithm(auth::Options::Algorithm::ED25519);
        // else: default in Options is HS256, or could throw std::invalid_argument here

        return std::make_shared<AuthMiddleware<SessionType> >(options, name);
    }

    /**
     * @brief Creates an `AuthMiddleware` instance configured specifically for role-based authorization.
     * Assumes authentication (populating user in context) is handled by a preceding middleware.
     * @tparam SessionType The session type.
     * @param roles A vector of role strings required for access.
     * @param require_all If `true`, the user must have all roles in the list; otherwise (default),
     *                    possession of any one role from the list is sufficient.
     * @param name Optional name for the middleware instance.
     * @return `std::shared_ptr<AuthMiddleware<SessionType>>`.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<AuthMiddleware<SessionType> >
    create_role_auth_middleware(
        const std::vector<std::string> &roles,
        bool require_all = false,
        const std::string &name = "RoleAuthMiddleware"
    ) {
        // Uses default auth::Options, as token verification might not be its primary role if user is pre-populated.
        auto middleware = std::make_shared<AuthMiddleware<SessionType> >(auth::Options{}, name);
        middleware->with_roles(roles, require_all);
        // Typically, for a pure role checker, require_auth might be true to ensure a user object exists.
        middleware->with_auth_required(true);
        return middleware;
    }

    /**
     * @brief Creates an `AuthMiddleware` instance where authentication is optional.
     *
     * If authentication details (e.g., a token) are provided in the request and are found to be invalid,
     * the request is still rejected with an appropriate error (e.g., 401 Unauthorized).
     * However, if no authentication details are provided at all, the request is allowed to proceed,
     * but no authenticated `auth::User` will be available in the context for downstream handlers.
     * @tparam SessionType The session type.
     * @param options Authentication options to use if a token is provided. Defaults to default `auth::Options`.
     * @param name Optional name for the middleware instance.
     * @return `std::shared_ptr<AuthMiddleware<SessionType>>`.
     */
    template<typename SessionType>
    [[nodiscard]] std::shared_ptr<AuthMiddleware<SessionType> >
    create_optional_auth_middleware(
        const auth::Options &options = auth::Options(),
        const std::string &name = "OptionalAuthMiddleware"
    ) {
        auto middleware = std::make_shared<AuthMiddleware<SessionType> >(options, name);
        middleware->with_auth_required(false); // Key change for optional authentication
        return middleware;
    }
} // namespace qb::http

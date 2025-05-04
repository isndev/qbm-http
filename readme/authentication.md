# `qbm-http`: Authentication & Authorization

(`qbm/http/auth/`, `qbm/http/middleware/auth.h`, `qbm/http/middleware/jwt.h`)

The HTTP module provides a flexible system for handling authentication and authorization, primarily focused on JWT (JSON Web Tokens) but adaptable to other schemes.

## Core Components (`qbm/http/auth/`)

*   **`qb::http::auth::Options` (`options.h`):** Configures the authentication process.
    *   `secret_key(key)` / `public_key(pem)` / `private_key(pem)`: Keys for signing/verification.
    *   `algorithm(Algorithm)`: Signing algorithm (HMAC, RSA, ECDSA, EdDSA).
    *   `token_expiration(duration)`: Default token lifetime.
    *   `token_issuer(issuer_string)`: Expected token issuer (`iss` claim).
    *   `token_audience(audience_string)`: Expected token audience (`aud` claim).
    *   `auth_header_name(name)`: HTTP header to check (default: "Authorization").
    *   `auth_scheme(scheme)`: Scheme prefix in header (default: "Bearer").
    *   `verify_expiration(bool)`, `verify_not_before(bool)`, `verify_issuer(bool)`, `verify_audience(bool)`: Flags to enable/disable specific claim validations.
    *   `clock_skew_tolerance(duration)`: Allowance for clock differences during time validation.
*   **`qb::http::auth::User` (`user.h`):** Represents an authenticated user.
    *   `id`: Unique user identifier (often the JWT `sub` claim).
    *   `username`: User's name.
    *   `roles`: `std::vector<std::string>` of assigned roles.
    *   `metadata`: `qb::unordered_map<std::string, std::string>` for additional custom data.
    *   Helper methods: `has_role()`, `has_any_role()`, `has_all_roles()`.
*   **`qb::http::auth::Manager` (`manager.h`):** The main class for auth operations.
    *   `Manager(const Options&)`: Constructor.
    *   `generate_token(const User&)`: Creates and signs a JWT for the user based on configured options.
    *   `verify_token(const std::string& token)`: Verifies a token's signature and claims based on configured options. Returns `std::optional<User>` containing the extracted user info if valid, `std::nullopt` otherwise.
    *   `extract_token_from_header(header_value)`: Extracts the token part from a header (e.g., removes "Bearer ").

## JWT Integration (`qb::jwt`)

(`qb/io/crypto_jwt.h` - Requires OpenSSL)

The `AuthManager` uses the underlying `qb::jwt` class for JWT operations.

*   `qb::jwt::create(payload_map, CreateOptions)`: Generates a JWT.
*   `qb::jwt::verify(token, VerifyOptions)`: Verifies a JWT.
*   Supports algorithms: HS256/384/512, RS256/384/512, ES256/384/512, EdDSA (Ed25519).
*   Handles standard claims validation (exp, nbf, iss, aud, sub, iat, jti).

## Authentication Middleware (`AuthMiddleware`)

(`middleware/auth.h`)

This is the primary way to integrate authentication into the routing process.

*   **Creation:**
    ```cpp
    #include <qbm/http/middleware/auth.h>

    qb::http::auth::Options auth_options; // Configure as needed
    // ... setup options.secret_key() or public/private keys ...

    auto auth_mw = qb::http::auth_middleware<MySession>(auth_options);
    // Or using the direct class:
    // auto auth_mw_ptr = std::make_shared<qb::http::AuthMiddleware<MySession>>(auth_options);
    // auto adapted_mw = std::make_shared<qb::http::SyncMiddlewareAdapter<MySession>>(auth_mw_ptr);
    ```
*   **Functionality:**
    1.  Extracts the token from the request (using `Options::auth_header_name` and `auth_scheme`).
    2.  Calls `AuthManager::verify_token()`.
    3.  If verification succeeds:
        *   Stores the extracted `auth::User` object in `ctx.set("user", user_object)` (key configurable via `with_user_context_key`).
        *   Proceeds to role authorization check (if configured).
        *   If authorization passes, continues the middleware chain (`MiddlewareResult::Continue()`).
    4.  If verification or authorization fails:
        *   Sets appropriate error status code (`401 Unauthorized` or `403 Forbidden`).
        *   Optionally calls a custom error handler (`with_error_handler`).
        *   Stops the middleware chain (`MiddlewareResult::Stop()`).
*   **Configuration (Fluent API):**
    *   `with_user_context_key(key)`: Change the context key for storing the `User` object.
    *   `with_auth_required(bool)`: If `false`, allows requests without a valid token to proceed (but `ctx.get("user")` will be empty).
    *   `with_roles(roles_vector, require_all)`: Enables role-based authorization.
    *   `with_error_handler(handler_func)`: Set a custom function to generate error responses.
    *   `with_options(auth_options)`: Update the authentication options after creation.

## Authorization

Authorization is typically performed *after* successful authentication.

1.  **Role-Based (via `AuthMiddleware`):**
    *   Configure the `AuthMiddleware` using `with_roles()`.
    ```cpp
    // Require either 'editor' OR 'admin'
    auth_mw->with_roles({"editor", "admin"});

    // Require BOTH 'auditor' AND 'manager'
    auth_mw->with_roles({"auditor", "manager"}, true); // require_all = true
    ```
    *   The middleware automatically checks the `roles` vector in the authenticated `User` object stored in the context.
2.  **Custom Logic (in Route Handler or separate Middleware):**
    *   Access the authenticated user from the context: `const auto& user = ctx.get<qb::http::auth::User>("user");`
    *   Perform custom checks based on user ID, roles, metadata, or resource ownership.
    ```cpp
    router.get("/documents/:docId", [](Context& ctx) {
        if (!ctx.has("user")) { /* Handle unauthenticated */ return; }
        const auto& user = ctx.get<auth::User>("user");
        std::string docId = ctx.param("docId");

        if (userCanAccessDocument(user, docId)) {
            // Serve document
        } else {
            ctx.response.status_code = HTTP_STATUS_FORBIDDEN;
            ctx.response.body() = "Access Denied";
            ctx.complete();
        }
    });
    ```

## Example Workflow (Token Authentication)

1.  **Login Route:** A public route (e.g., `/login`) verifies user credentials (e.g., username/password against a database).
2.  **Token Generation:** Upon successful login, the handler creates an `auth::User` object and uses `auth_manager.generate_token(user)` to create a JWT.
3.  **Token Response:** The JWT is sent back to the client (e.g., in the response body or a cookie).
4.  **Subsequent Requests:** The client includes the token in the `Authorization: Bearer <token>` header.
5.  **`AuthMiddleware`:** Intercepts the request, extracts the token, verifies it using `auth_manager.verify_token()`, and performs optional role checks.
6.  **Route Handler:** If authentication/authorization succeeds, the handler executes and can access the authenticated `auth::User` details from `ctx.get("user")`.

**(See also:** `test-auth.cpp`, `test-middleware-auth.cpp`, `test-crypto-jwt.cpp`**)** 
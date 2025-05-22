# 11: Authentication System (`qb::http::auth`)

The `qb::http::auth` namespace provides a dedicated subsystem for handling authentication and user representation within your HTTP application. It is designed to work seamlessly with the routing and middleware components.

Key components of this subsystem include:

-   `qb::http::auth::Options`: Configures authentication behavior, including algorithms, keys, and token validation policies.
-   `qb::http::auth::User`: Represents an authenticated user with an ID, username, roles, and metadata.
-   `qb::http::auth::Manager`: Manages token generation (typically JWTs) and verification using the configured options and user data.

These components are often used in conjunction with specific authentication middleware like `qb::http::AuthMiddleware` or `qb::http::JwtMiddleware`.

## `auth::Options`

This class (`http/auth/options.h`) is crucial for configuring how authentication tokens are created and validated. It offers a fluent interface for setting various parameters:

-   **Cryptographic Keys**:
    -   `secret_key(std::string | std::vector<unsigned char>)`: For HMAC-based algorithms (HS256, HS384, HS512).
    -   `public_key(std::string pem)`: For asymmetric algorithms (RSA, ECDSA, EdDSA) during token verification.
    -   `private_key(std::string pem)`: For asymmetric algorithms during token signing.
-   **Algorithm**: `algorithm(Options::Algorithm alg)` specifies the signing algorithm (e.g., `Options::Algorithm::HMAC_SHA256`, `Options::Algorithm::RSA_SHA256`).
-   **Token Lifetime**: `token_expiration(std::chrono::seconds)` sets the validity duration for generated tokens.
-   **Claim Verification**:
    -   `token_issuer(std::string issuer)`: Sets the expected issuer (`iss` claim). Enables `verify_issuer`.
    -   `token_audience(std::string audience)`: Sets the expected audience (`aud` claim). Enables `verify_audience`.
    -   `verify_expiration(bool)`: Enable/disable `exp` claim check.
    -   `verify_not_before(bool)`: Enable/disable `nbf` claim check.
    -   `clock_skew_tolerance(std::chrono::seconds)`: Allows for clock differences when validating time-based claims.
-   **Token Extraction**: Defines how tokens are found in requests:
    -   `auth_header_name(std::string name)`: Default `"Authorization"`.
    -   `auth_scheme(std::string scheme)`: Default `"Bearer"`.

```cpp
#include <http/auth/options.h>

qb::http::auth::Options auth_opts;
auth_opts.secret_key("your-very-strong-hmac-secret")
    .algorithm(qb::http::auth::Options::Algorithm::HMAC_SHA256)
    .token_expiration(std::chrono::hours(1))
    .token_issuer("my-app.com")
    .token_audience("my-app-clients")
    .auth_scheme("JWT"); // Expect "JWT <token>"
```

## `auth::User`

This structure (`http/auth/user.h`) represents an authenticated user:

```cpp
struct User {
    std::string id;          // Unique identifier
    std::string username;    // Username
    std::vector<std::string> roles; // User roles
    qb::unordered_map<std::string, std::string> metadata; // Additional data

    bool has_role(const std::string& role_to_check) const noexcept;
    bool has_any_role(const std::vector<std::string>& required_roles_list) const noexcept;
    bool has_all_roles(const std::vector<std::string>& required_roles_list) const noexcept;
};
```

-   It provides helper methods like `has_role`, `has_any_role`, and `has_all_roles` for easy authorization checks.

## `auth::Manager`

The `qb::http::auth::Manager` class (`http/auth/manager.h`) is the workhorse for token operations. It is initialized with an `auth::Options` object.

-   **`generate_token(const User& user) const`**: Creates a new authentication token (typically a JWT) for the given user. The payload includes standard claims (sub, iat, exp, iss, aud based on options) and user-specific information (username, roles, metadata).

-   **`extract_token_from_header(const std::string& auth_header_value) const`**: Parses an HTTP authorization header value (e.g., `"Bearer mytoken123"` or `"JWT mytoken123"`) based on the configured `auth_scheme` and returns the raw token string. The scheme comparison is case-insensitive.

-   **`verify_token(const std::string& token) const`**: Verifies the given token string. This involves:
    1.  Decoding the token.
    2.  Verifying the signature using the configured algorithm and key (`secret_key` for HMAC, `public_key` for asymmetric).
    3.  Validating standard claims like expiration (`exp`), not-before (`nbf`), issuer (`iss`), and audience (`aud`) if enabled in `auth::Options`.
    4.  If verification is successful, it constructs and returns an `std::optional<User>` populated with information from the token's payload.
    5.  If verification fails for any reason (invalid signature, expired, claim mismatch), it returns `std::nullopt`.

The underlying JWT operations (`qb::jwt::create`, `qb::jwt::verify`) are handled by the `qb-io` crypto library.

```cpp
#include <http/auth.h> // Convenience header for auth components

// Setup
qb::http::auth::Options my_auth_options;
my_auth_options.secret_key("supersecretkey").token_issuer("myapi");
qb::http::auth::Manager auth_manager(my_auth_options);

// User creation & Token Generation
qb::http::auth::User user_to_auth;
user_to_auth.id = "u101";
user_to_auth.username = "alice";
user_to_auth.roles = {"editor", "contributor"};

std::string token_str = auth_manager.generate_token(user_to_auth);
std::cout << "Generated token: " << token_str << std::endl;

// Token Verification (e.g., from an incoming request)
std::string auth_header = "Bearer " + token_str;
std::string extracted_token = auth_manager.extract_token_from_header(auth_header);

if (!extracted_token.empty()) {
    std::optional<qb::http::auth::User> authenticated_user = auth_manager.verify_token(extracted_token);
    if (authenticated_user) {
        std::cout << "User " << authenticated_user->username << " authenticated." << std::endl;
        if (authenticated_user->has_role("editor")) {
            std::cout << "User has editor role." << std::endl;
        }
    } else {
        std::cout << "Token verification failed." << std::endl;
    }
} else {
    std::cout << "Token could not be extracted from header." << std::endl;
}
```

## Integration with Middleware

While `auth::Manager` can be used directly, it's commonly leveraged by authentication middleware for seamless integration into the request processing pipeline.

### `qb::http::AuthMiddleware`

This is a general-purpose authentication middleware (see `http/middleware/auth.h`) that uses an `auth::Manager` internally. Its key responsibilities are:

1.  **Token Extraction**: It automatically attempts to extract a token from the request based on the `auth::Options` configured for its internal `auth::Manager` (e.g., from the `Authorization` header).
2.  **Token Verification**: It calls `auth_manager.verify_token()`.
3.  **Context Population**: If authentication is successful, it retrieves the `auth::User` object and stores it in the `qb::http::Context` (default key: `"user"`), making it available to downstream handlers and middleware.
    ```cpp
    // In a downstream handler or middleware:
    if (auto user_opt = ctx->get<qb::http::auth::User>("user")) {
        // User is authenticated, user_opt->id, user_opt->username, etc. are available
    }
    ```
4.  **Authorization**: It can perform role-based authorization checks using `auth::User::has_role()`, `has_any_role()`, or `has_all_roles()` if configured via its `with_roles()` method.
5.  **Flow Control**: If authentication is required (`with_auth_required(true)`) and fails, it sends an appropriate error response (e.g., 401 Unauthorized or 403 Forbidden) and short-circuits the request chain (`ctx->complete(AsyncTaskResult::COMPLETE)`).
   If authentication is optional (`with_auth_required(false)`) and a token is not provided or is invalid, it may allow the request to proceed without an authenticated user in the context.

**Usage:**
```cpp
// Create auth options for the manager used by AuthMiddleware
qb::http::auth::Options manager_opts;
manager_opts.secret_key("your-app-secret")
            .token_issuer("my-app")
            .algorithm(qb::http::auth::Options::Algorithm::HMAC_SHA384);

// Create AuthMiddleware instance, it will construct its own AuthManager with these options
auto auth_mw = qb::http::create_auth_middleware<MySession>(manager_opts);
auth_mw->with_auth_required(true)                // Authentication is mandatory
       .with_user_context_key("current_user")  // Store User object under this key
       .with_roles({"administrator"}, true);    // Requires the 'administrator' role

router.use(auth_mw);

router.get("/admin/dashboard", [](auto ctx) {
    // At this point, if reached, current_user exists and has the 'administrator' role.
    auto user = ctx->template get<qb::http::auth::User>("current_user");
    // ... handler logic ...
    ctx->complete();
});
```

### `qb::http::JwtMiddleware`

This middleware (see `http/middleware/jwt.h`) is specifically for JWT-based authentication. While `AuthMiddleware` can also handle JWTs (as its default behavior assumes JWTs via `qb::jwt`), `JwtMiddleware` provides a more direct interface if you are only working with JWTs and might offer slightly different configuration options or focuses through `qb::http::JwtOptions`.

-   It extracts and verifies JWTs based on its `JwtOptions` (secret, algorithm, expected claims, token location like header/cookie/query).
-   Upon successful verification, it places the decoded JWT payload (as a `qb::json` object) into the context, typically under the key `"jwt_payload"`.
-   It supports custom payload validation and success/error handling callbacks.

**Usage:**
```cpp
qb::http::JwtOptions jwt_opts;
jwt_opts.secret = "your-jwt-secret";
jwt_opts.algorithm = "HS256";
jwt_opts.token_location = qb::http::JwtTokenLocation::HEADER;
jwt_opts.token_name = "Authorization";
jwt_opts.auth_scheme = "Bearer";
jwt_opts.verify_exp = true;
jwt_opts.verify_iss = true;
jwt_opts.issuer = "my-api.com";

auto jwt_auth_mw = qb::http::jwt_middleware_with_options<MySession>(jwt_opts);
jwt_auth_mw->require_claims({"user_id", "roles"}); // Ensure these claims exist

router.use(jwt_auth_mw);

router.get("/data", [](auto ctx) {
    if (auto payload_opt = ctx->template get<qb::json>("jwt_payload")) {
        const qb::json& payload = *payload_opt;
        std::string user_id = payload.value("user_id", "");
        // Process with user_id and other claims...
        ctx->response().body() = "Data for user: " + user_id;
    } else {
        ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
        ctx->response().body() = "JWT payload missing after auth.";
    }
    ctx->complete();
});
```

**Choosing between `AuthMiddleware` and `JwtMiddleware`:

-   If you need to work directly with a typed `auth::User` object in your handlers and leverage role-based access control helpers, `AuthMiddleware` is generally preferred. It abstracts away the JWT-specifics after validation.
-   If you need direct access to the raw JWT payload as a `qb::json` object for more complex claim interpretation, or if your token isn't strictly tied to the `auth::User` structure, `JwtMiddleware` can be more direct.
-   Both can be configured to achieve similar JWT validation outcomes.

This authentication subsystem provides a flexible and secure way to protect your HTTP endpoints.

Previous: [The Request Context](./10-request-context.md)
Next: [Validation System](./12-validation.md)

---
Return to [Index](./README.md) 
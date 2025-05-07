# `qbm-http`: Built-in Middleware

(`qbm/http/middleware/`)

The `qbm-http` module provides several pre-built middleware components for common web application tasks. These can be easily added to your router globally or to specific route groups.

## Available Middleware

### 1. Authentication (`AuthMiddleware`)

*   **Header:** `middleware/auth.h`
*   **Purpose:** Verifies authentication tokens (typically JWT) and authorizes requests based on user roles.
*   **Dependencies:** `qbm/http/auth/auth.h`, `qb/io/crypto_jwt.h` (requires OpenSSL).
*   **Key Features:**
    *   Integrates with `qb::http::auth::Manager` and `Options`.
    *   Primarily extracts tokens from HTTP headers (e.g., `Authorization: Bearer ...`) as configured by `auth::Options`. Direct support for cookie or query parameter token extraction via `AuthMiddleware` typically requires custom `auth::Manager` logic or specific `auth::Options` setup if the manager supports it. (For more direct cookie/query JWT handling, see `JwtMiddleware`).
    *   Verifies token signature, expiration, issuer, audience using the configured `auth::Manager` (which often uses `qb::jwt::verify` internally).
    *   Stores the authenticated `qb::http::auth::User` object in the request context (default key: "user").
    *   Optional role-based authorization (`with_roles(roles, require_all)`).
    *   Customizable error handling.
*   **Usage:**
    ```cpp
    #include <http/middleware/auth.h>
    #include <http/auth/auth.h>

    // Setup Auth Options
    qb::http::auth::Options auth_options;
    auth_options.secret_key("your-super-secret-key")
                .algorithm(qb::http::auth::Options::Algorithm::HMAC_SHA256)
                .token_issuer("my_api");

    // Create middleware instance
    auto auth_mw = qb::http::auth_middleware<MySession>(auth_options);

    // Apply globally
    // router.use(auth_mw);

    // Apply to a group
    auto& protected_group = router.group("/protected");
    protected_group.use(auth_mw);

    // Require specific roles
    auto& admin_group = router.group("/admin");
    admin_group.use(qb::http::auth_middleware<MySession>(auth_options)
                      .with_roles({"admin"}));
    ```
*   **(See also:** [`authentication.md`](./authentication.md)**)**

### 2. JWT Middleware (`JwtMiddleware`)

*   **Header:** `middleware/jwt.h`
*   **Purpose:** Specifically focuses on JWT verification. Less feature-rich than `AuthMiddleware` regarding user objects and roles but provides direct JWT handling.
*   **Dependencies:** `qb/io/crypto_jwt.h`.
*   **Key Features:**
    *   Verifies JWT signature, expiration, nbf, issuer, audience, subject.
    *   Extracts tokens from header, cookie, or query.
    *   Stores the *decoded JSON payload* of the JWT in the context (default key: "jwt_payload").
    *   Allows custom validators and error handlers.
*   **Usage:**
    ```cpp
    #include <http/middleware/jwt.h>

    qb::http::JwtOptions jwt_options;
    jwt_options.secret = "your-secret";
    jwt_options.verify_aud = true;
    jwt_options.audience = "my_app";

    // Create middleware instance
    auto jwt_mw = qb::http::jwt_middleware_with_options<MySession>(jwt_options);

    // router.use(jwt_mw);
    ```

### 3. CORS (`CorsMiddleware`)

*   **Header:** `middleware/cors.h`
*   **Purpose:** Handles Cross-Origin Resource Sharing headers.
*   **Key Features:**
    *   Configurable allowed origins (exact match, regex, custom function, wildcard `*`).
    *   Configurable allowed methods and headers.
    *   Handles preflight (OPTIONS) requests automatically.
    *   Supports credentials (`Access-Control-Allow-Credentials`).
    *   Configurable exposed headers (`Access-Control-Expose-Headers`).
    *   Configurable max age for preflight results (`Access-Control-Max-Age`).
    *   Includes presets: `CorsOptions::permissive()` and `CorsOptions::secure(origins)`.
*   **Usage:**
    ```cpp
    #include <http/middleware/cors.h>

    // Permissive (Development)
    // router.use(qb::http::cors_dev_middleware<MySession>());

    // Secure (Production)
    qb::http::CorsOptions cors_opts = qb::http::CorsOptions::secure({"https://myfrontend.com"});
    // router.use(qb::http::cors_middleware<MySession>(cors_opts));
    ```

### 4. Error Handling (`ErrorHandlingMiddleware`)

*   **Header:** `middleware/error_handling.h`
*   **Purpose:** Centralizes the handling of responses with error status codes (>= 400).
*   **Key Features:**
    *   Register handlers for specific status codes (`on_status(HTTP_STATUS_NOT_FOUND, ...)`).
    *   Register handlers for status code ranges (`on_status_range(400, 499, ...)`).
    *   Register a generic error handler triggered by `ctx.execute_error_callbacks()`. 
    *   Handlers can modify the response (e.g., render a custom error page).
*   **Usage:**
    ```cpp
    #include <http/middleware/error_handling.h>

    auto error_mw = qb::http::error_handling_middleware<MySession>();
    error_mw->on_status(HTTP_STATUS_NOT_FOUND, [](Context& ctx){
        ctx.response.add_header("Content-Type", "text/html");
        ctx.response.body() = "<h1>404 Not Found</h1>";
    });
    error_mw->on_status_range(500, 599, [](Context& ctx){
        // Log server error
        ctx.response.body() = "<h1>Internal Server Error</h1>";
    });

    // Register *early* in the chain if you want it to catch middleware errors
    // Register *late* if you only want it to catch route handler errors
    // router.use(error_mw);
    ```

### 5. Logging (`LoggingMiddleware`)

*   **Header:** `middleware/logging.h`
*   **Purpose:** Logs basic information about incoming requests and outgoing responses.
*   **Key Features:**
    *   Requires a logging function (`std::function<void(LogLevel, const std::string&)>`) passed to the constructor.
    *   Configurable log levels for requests and responses.
    *   Logs method, URI, and response status code by default.
*   **Usage:**
    ```cpp
    #include <http/middleware/logging.h>
    #include <iostream> // Or your logging library

    auto logger = [](qb::http::LogLevel level, const std::string& msg){
        // Simple console logger
        std::cout << "[" << (int)level << "] " << msg << std::endl;
    };

    // router.use(qb::http::logging_middleware<MySession>(logger));
    ```

### 6. Rate Limiting (`RateLimitMiddleware`)

*   **Header:** `middleware/rate_limit.h`
*   **Purpose:** Limits the number of requests a client can make within a time window.
*   **Key Features:**
    *   Configurable max requests and time window (`RateLimitOptions`).
    *   Client identification based on IP (default) or custom extractor function.
    *   Sets standard `X-RateLimit-*` headers on responses.
    *   Customizable error response (status code, message).
    *   Includes presets: `RateLimitOptions::permissive()` and `RateLimitOptions::secure()`.
*   **Usage:**
    ```cpp
    #include <http/middleware/rate_limit.h>

    // Secure default: 60 requests per minute per IP
    // router.use(qb::http::rate_limit_secure_middleware<MySession>());

    // Custom:
    // qb::http::RateLimitOptions rl_options;
    // rl_options.max_requests(10).window(std::chrono::seconds(10));
    // router.use(qb::http::rate_limit_middleware<MySession>(rl_options));
    ```

### 7. Request Timing (`TimingMiddleware`)

*   **Header:** `middleware/timing.h`
*   **Purpose:** Measures and reports the processing time for each request.
*   **Key Features:**
    *   Requires a callback function (`std::function<void(std::chrono::milliseconds)>`) to receive the duration.
*   **Usage:**
    ```cpp
    #include <http/middleware/timing.h>
    #include <iostream>

    auto timing_callback = [](std::chrono::milliseconds duration){
        std::cout << "Request processed in: " << duration.count() << " ms" << std::endl;
    };
    // router.use(qb::http::timing_middleware<MySession>(timing_callback));
    ```

### 8. Request/Response Transformation (`TransformMiddleware`)

*   **Header:** `middleware/transform.h`
*   **Purpose:** Allows modification of the request *before* it reaches the handler or the response *after* the handler executes but *before* it's sent.
*   **Key Features:**
    *   Accepts optional request and/or response transformer functions.
*   **Usage:**
    ```cpp
    #include <qbm/http/middleware/transform.h>

    // Add a request header
    auto req_transformer = [](qb::http::Request& req){
        req.add_header("X-Request-Processed", "true");
    };

    // Add a response header
    auto resp_transformer = [](qb::http::Response& resp){
        resp.add_header("X-Response-Processed", "true");
    };

    // router.use(qb::http::transform_middleware<MySession>(req_transformer, resp_transformer));
    ```

### 9. Validation (`ValidatorMiddleware`)

*   **Header:** `middleware/validator.h`
*   **Purpose:** Validates incoming requests based on defined rules.
*   **Dependencies:** `qbm/http/validation/validation.h`.
*   **Key Features:**
    *   Integrates with the `qb::http::Validator` class.
    *   Supports JSON Schema validation for request bodies.
    *   Supports validation and sanitization of query parameters.
    *   Handles error responses automatically or via a custom error handler.
*   **Usage:**
    ```cpp
    #include <http/middleware/validator.h>
    #include <http/validation/validation.h>

    // Validate JSON body against a schema
    // qb::json schema = { ... };
    // auto validator_mw = qb::http::validator_middleware<MySession>(schema);
    // router.use(validator_mw);

    // Validate query parameters by configuring the middleware instance
    // auto validator_mw_for_query = qb::http::validator_middleware<MySession>();
    // validator_mw_for_query->validator()->with_query_param("page", qb::http::QueryParamRules().as_integer().min_value(1));
    // router.use(validator_mw_for_query);
    ```
*   **(See also:** [`validation.md`](./validation.md)**)**

### 10. Conditional Execution (`ConditionalMiddleware`)

*   **Header:** `middleware/conditional.h`
*   **Purpose:** Executes one middleware branch or another (or none) based on a predicate function.
*   **Key Features:**
    *   Takes a predicate `std::function<bool(const Context&)>`.
    *   Takes an `if_middleware` (executed if predicate is true).
    *   Takes an optional `else_middleware` (executed if predicate is false).
*   **Usage:**
    ```cpp
    #include <http/middleware/conditional.h>

    auto is_admin_request = [](const Context& ctx) {
        return ctx.request.uri().path().find("/admin") == 0;
    };

    // router.use(qb::http::conditional_middleware<MySession>(
    //     is_admin_request,
    //     admin_auth_middleware_ptr, // Middleware for admin routes
    //     nullptr                    // No middleware for non-admin routes
    // ));
    ```

### 11. reCAPTCHA (`RecaptchaMiddleware`)

*   **Header:** `middleware/recaptcha.h`
*   **Purpose:** Verifies Google reCAPTCHA v3 tokens submitted with requests.
*   **Dependencies:** Requires an HTTP client capability within the middleware (or passed to it) to call the Google API.
*   **Key Features:**
    *   Extracts token from header, body, or query.
    *   Calls Google's verification API asynchronously.
    *   Validates response success and score against a threshold.
    *   Stores verification result (`RecaptchaResult`) in context.
*   **Usage:**
    ```cpp
    #include <http/middleware/recaptcha.h>

    // qb::http::RecaptchaOptions recaptcha_options("YOUR_RECAPTCHA_SECRET_KEY");
    // recaptcha_options.min_score(0.5f);
    // 
    // // This middleware is asynchronous, needs adapter
    // auto recaptcha_mw = std::make_shared<qb::http::RecaptchaMiddleware<MySession>>(recaptcha_options);
    // router.use(std::make_shared<qb::http::AsyncMiddlewareAdapter<MySession>>(recaptcha_mw));
    ```

**(See also:** [`middleware.md`](./middleware.md)**)** 
# 08: Standard Middleware

The `qb::http` module comes with a collection of pre-built middleware components designed to address common web application needs. These can be found under the `qbm/http/middleware/` directory and are often included via `http/middleware/all.h` or by including their specific headers.

This section provides an overview of these standard middleware components and how to use them. For detailed options and advanced usage, refer to the respective header files (e.g., `auth.h`, `cors.h`).

## Using Standard Middleware

Standard middleware are typically classes derived from `qb::http::IMiddleware<SessionType>` or are provided with factory functions that return a `std::shared_ptr<IMiddleware<SessionType>>`. You add them to your `Router`, `RouteGroup`, or `Controller` using the `use()` method.

```cpp
#include <http/http.h>        // For Router, etc.
#include <http/middleware/all.h> // Conveniently includes all standard middleware

// In your server setup:
// qb::http::Router<MySession> router;

// Example: Adding LoggingMiddleware
auto logging_mw = qb::http::logging_middleware<MySession>([](qb::http::LogLevel level, const std::string& msg) {
    // Your actual logging implementation (e.g., to std::cout, a file, or a logging library)
    std::cout << "[" << static_cast<int>(level) << "] " << msg << std::endl;
});
router.use(logging_mw);

// Example: Adding CORS middleware with permissive options for development
auto cors_mw = qb::http::cors_dev_middleware<MySession>();
router.use(cors_mw);

router.get("/some_path", my_handler_lambda);
router.compile();
```

## Overview of Standard Middleware Components

Here's a summary of the available standard middleware components:

### 1. Timing Middleware (`qb::http::TimingMiddleware`)

-   **Header**: `http/middleware/timing.h`
-   **Purpose**: Measures the processing time of a request from when it first passes through this middleware until just before the response is sent.
-   **Features**:
    -   Adds an `X-Response-Time` header to the response (e.g., `"123.45ms"`).
    -   Invokes a user-provided callback with the measured duration (`std::chrono::milliseconds`).
-   **Factory**: `qb::http::timing_middleware<SessionType>(TimingCallback callback, std::string name = ...)`
-   **Usage Example**:
    ```cpp
    auto timing_cb = [](const std::chrono::milliseconds& duration) {
        std::cout << "Request processed in: " << duration.count() << "ms" << std::endl;
    };
    router.use(qb::http::timing_middleware<MySession>(timing_cb));
    ```

### 2. Logging Middleware (`qb::http::LoggingMiddleware`)

-   **Header**: `http/middleware/logging.h`
-   **Purpose**: Logs basic information about incoming requests (method, URI path) and outgoing responses (status code).
-   **Features**:
    -   Uses a configurable `LogFunction` callback for actual log output, allowing integration with any logging backend.
    -   Configurable log levels for request and response messages (`qb::http::LogLevel`).
-   **Factory**: `qb::http::logging_middleware<SessionType>(LogFunction log_fn, LogLevel req_level = ..., LogLevel res_level = ..., std::string name = ...)`

### 3. Transform Middleware (`qb::http::TransformMiddleware`)

-   **Header**: `http/middleware/transform.h`
-   **Purpose**: Allows modification of the `qb::http::Request` object before it reaches downstream handlers or middleware.
-   **Features**:
    -   Takes a `RequestTransformer` function (`std::function<void(Request& request)>`) which can modify the request in place (e.g., add/remove headers, change body).
    -   Handles exceptions from the transformer function by signaling an error to the context.
-   **Factory**: `qb::http::transform_middleware<SessionType>(RequestTransformer transformer, std::string name = ...)`

### 4. Conditional Middleware (`qb::http::ConditionalMiddleware`)

-   **Header**: `http/middleware/conditional.h`
-   **Purpose**: Conditionally executes one of two child middleware instances based on a predicate function evaluated against the request context.
-   **Features**:
    -   `Predicate`: `std::function<bool(const std::shared_ptr<Context<SessionType>>&)>`.
    -   Executes `if_middleware` if predicate is true, `else_middleware` (if provided) if false.
    -   If predicate is false and no `else_middleware` exists, it continues to the next task.
-   **Factory**: `qb::http::conditional_middleware<SessionType>(Predicate p, ChildMiddlewarePtr if_mw, ChildMiddlewarePtr else_mw = nullptr, std::string name = ...)`

### 5. Error Handling Middleware (`qb::http::ErrorHandlingMiddleware`)

-   **Header**: `http/middleware/error_handling.h`
-   **Purpose**: Centralized generation of custom error responses. Typically used in the router's dedicated error chain.
-   **Features**:
    -   Registers handlers for specific HTTP status codes or ranges.
    -   Provides a generic fallback error handler.
    -   Modifies `ctx->response()` to customize the error output.
-   **Factory**: `qb::http::error_handling_middleware<SessionType>(std::string name = ...)`
-   **Configuration**: Use `on_status(status, handler_fn)`, `on_status_range(min, max, handler_fn)`, `on_any_error(handler_fn)`.

### 6. CORS Middleware (`qb::http::CorsMiddleware`)

-   **Header**: `http/middleware/cors.h`
-   **Purpose**: Handles Cross-Origin Resource Sharing (CORS) requests, including preflight (OPTIONS) requests.
-   **Features**:
    -   Configurable via `qb::http::CorsOptions` (allowed origins, methods, headers, credentials, max age, etc.).
    -   Adds appropriate `Access-Control-*` headers to responses.
-   **Factories**: `qb::http::cors_middleware<SessionType>(CorsOptions opts, ...)` , `cors_dev_middleware()`, `cors_secure_middleware(...)`.

### 7. Validation Middleware (`qb::http::ValidationMiddleware`)

-   **Header**: `http/middleware/validation.h`
-   **Purpose**: Validates incoming HTTP requests using a `qb::http::validation::RequestValidator`.
-   **Features**:
    -   If validation fails, automatically generates a 400 Bad Request (or similar) response with a JSON body detailing validation errors.
    -   Integrates with the [Validation System](./12-validation.md).
-   **Factory**: `qb::http::validation_middleware<SessionType>(std::shared_ptr<validation::RequestValidator> validator, ...)`

### 8. Rate Limiting Middleware (`qb::http::RateLimitMiddleware`)

-   **Header**: `http/middleware/rate_limit.h`
-   **Purpose**: Limits the number of requests from client identifiers (e.g., IP address) within a defined time window.
-   **Features**:
    -   Configurable via `qb::http::RateLimitOptions` (max requests, window duration, custom client ID extractor).
    -   Adds standard `X-RateLimit-*` headers to responses.
    -   Responds with a configurable status code (default 429) when the limit is exceeded.
-   **Factories**: `qb::http::rate_limit_middleware<SessionType>(RateLimitOptions opts, ...)` , `rate_limit_dev_middleware()`, `rate_limit_secure_middleware()`.

### 9. JWT Middleware (`qb::http::JwtMiddleware`)

-   **Header**: `http/middleware/jwt.h`
-   **Purpose**: Authenticates requests using JSON Web Tokens (JWTs).
-   **Features**:
    -   Extracts JWTs from headers, cookies, or query parameters.
    -   Verifies token signature, expiration, NBF, issuer, audience, and subject based on `qb::http::JwtOptions`.
    -   Stores the decoded JWT payload (as `qb::json`) in the context variable `"jwt_payload"` upon success.
    -   Supports custom payload validation and success/error handling callbacks.
-   **Factories**: `qb::http::jwt_middleware<SessionType>(secret, algorithm = ...)` , `jwt_middleware_with_options(...)`.

### 10. Authentication Middleware (`qb::http::AuthMiddleware`)

-   **Header**: `http/middleware/auth.h`
-   **Purpose**: A more comprehensive authentication and authorization middleware that uses an `qb::http::auth::Manager`.
-   **Features**:
    -   Integrates with the [Authentication System](./11-authentication.md).
    -   Extracts tokens (typically JWTs) using `auth::Manager` based on `auth::Options`.
    -   Verifies tokens and constructs an `auth::User` object.
    -   Stores the `auth::User` in the context (default key: `"user"`).
    -   Can perform role-based authorization checks.
    -   Configurable to require authentication or allow optional authentication.
-   **Factories**: `qb::http::create_auth_middleware<SessionType>(auth::Options opts, ...)` , `create_jwt_auth_middleware(...)`, `create_role_auth_middleware(...)`, `create_optional_auth_middleware(...)`.

### 11. Compression Middleware (`qb::http::CompressionMiddleware`)

-   **Header**: `http/middleware/compression.h`
-   **Purpose**: Handles automatic decompression of request bodies and compression of response bodies (e.g., gzip, deflate). Requires `QB_IO_WITH_ZLIB`.
-   **Features**:
    -   Configurable via `qb::http::CompressionOptions` (enable request/response processing, min size to compress, preferred encodings).
    -   Inspects `Content-Encoding` for requests and `Accept-Encoding` for responses.
    -   Sets appropriate headers (`Content-Encoding`, `Vary`) for compressed responses.
-   **Factories**: `qb::http::compression_middleware<SessionType>(CompressionOptions opts, ...)` , `max_compression_middleware()`, `fast_compression_middleware()`.

### 12. Security Headers Middleware (`qb::http::SecurityHeadersMiddleware`)

-   **Header**: `http/middleware/security_headers.h`
-   **Purpose**: Adds various HTTP security-related headers to responses to help protect against common web vulnerabilities.
-   **Features**:
    -   Configurable via `qb::http::SecurityHeadersOptions`.
    -   Can set headers like `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` (with nonce support), `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-*` policies.
    -   Provides `secure_defaults()` for a strong baseline configuration.
-   **Factory**: `qb::http::security_headers_middleware<SessionType>(SecurityHeadersOptions opts = ..., ...)`

### 13. Static Files Middleware (`qb::http::StaticFilesMiddleware`)

-   **Header**: `http/middleware/static_files.h`
-   **Purpose**: Serves static files (HTML, CSS, JS, images, etc.) from a specified root directory in the filesystem.
-   **Features**:
    -   Configurable via `qb::http::StaticFilesOptions` (root directory, index file serving, MIME types, caching headers, ETag/Last-Modified support, Range requests, directory listing).
    -   Handles path normalization and security to prevent directory traversal.
    -   Sets appropriate `Content-Type`, `Content-Length`, and caching headers.
-   **Factory**: `qb::http::static_files_middleware<SessionType>(StaticFilesOptions opts, ...)`

This set of standard middleware provides a robust foundation for building secure, efficient, and feature-rich HTTP applications. For custom processing needs, refer to [Custom Middleware](./09-custom-middleware.md).

Previous: [Middleware Overview](./07-middleware.md)
Next: [Custom Middleware](./09-custom-middleware.md)

---
Return to [Index](./README.md) 
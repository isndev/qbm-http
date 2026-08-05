# Standard middleware

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 3.0.0 (C++20 default, C++23 supported)

The middleware that ships with the module — CORS, JWT, rate limiting, compression, timing, static files, full authentication, and security headers — together with the exact configuration options each exposes and the time type each duration field uses.

**Prerequisites:** [the middleware model and chain order](./07-middleware.md), and [the request context](./10-request-context.md) for `ctx->set/get`. **See also:** [custom middleware](./09-custom-middleware.md), [authentication](./11-authentication.md), [validation](./12-validation.md), and the doc map [`README.md`](./README.md).

## What this page covers

Each shipped middleware is a class template parameterized on your session type, paired with one or more free-function factories. Each factory returns a `std::shared_ptr` to its concrete middleware class — for example `cors_middleware<S>(...)` returns `std::shared_ptr<CorsMiddleware<S>>` — which converts to the `std::shared_ptr<IMiddleware<SessionType>>` that `Router::use` accepts. You attach an instance with `Router::use(...)`, `RouteGroup::use(...)`, or a `Controller`; the chain order and inheritance rules are described in [the middleware overview](./07-middleware.md). This page is the reference for the *configuration surface* of each one — every option, its default, and — where a duration is involved — whether it is a `qb::duration`, a `std::chrono::seconds`, or a plain string.

Two corrections to keep in mind throughout:

- **The module is a compiled library, not header-only.** You link `qbm::http`; the umbrella header `<qbm/http/http.h>` brings the declarations in. Middleware headers live under `<qbm/http/middleware/>`.
- **Several of these are SSL-gated.** JWT and full authentication are only compiled when the framework is built with `QB_HAS_SSL`; CSP nonce generation in the security-headers middleware also requires `QB_HAS_SSL`. The umbrella `<qbm/http/middleware/all.h>` guards the JWT and auth includes behind `#ifdef QB_HAS_SSL`. Compression depends on a separate flag, `QB_HAS_COMPRESSION`. See [feature gates](#feature-gates-and-includes) below.

## Including the middleware

You can pull in everything with one header, or include only what you use.

```cpp
#include <qbm/http/http.h>            // Router, Context, status, Request, Response
#include <qbm/http/middleware/all.h>  // every standard middleware factory
```
<!-- src: qbm/http/src/qbm/http/middleware/all.h -->

The umbrella `all.h` also includes [`make.h`](#the-unified-make-entry-point), which exposes a single tag-dispatched factory over every standard middleware. To keep compile times down, include the individual header instead — for example `<qbm/http/middleware/cors.h>` or `<qbm/http/middleware/rate_limit.h>`.

All factories follow the same shape:

```cpp
// Attach permissive CORS at the router root.
qb::http::Router<MySession> router;
router.use(qb::http::cors_dev_middleware<MySession>());
router.compile();
```
<!-- src: qbm/http/src/qbm/http/middleware/cors.h:511 -->

`Router::use` accepts a `std::shared_ptr<IMiddleware<SessionType>>` (what every factory returns), a `(ctx, next)` lambda, or in-place constructor arguments. See [the middleware overview](./07-middleware.md) for the three overloads.

## CORS

- **Header:** `<qbm/http/middleware/cors.h>` · **Class:** `qb::http::CorsMiddleware<SessionType>`
- **Purpose:** answer cross-origin preflight (`OPTIONS`) requests and add `Access-Control-*` headers to actual responses, per the W3C CORS model.

Configuration lives in `qb::http::CorsOptions`, a fluent builder. The full surface:

| Option | Method | Type / default |
|---|---|---|
| Allowed origins (exact) | `origins(std::vector<std::string>)` | exact, case-sensitive; `"*"` matches all |
| Allowed origins (regex) | `origin_patterns(std::vector<std::string>)` | ECMAScript regex, ReDoS-bounded |
| Allowed origins (function) | `origin_matcher(std::function<bool(const std::string&)>)` | custom predicate; fails closed on throw |
| Allowed methods | `methods(std::vector<std::string>)` / `all_methods()` | default `{"GET","HEAD","POST"}` |
| Allowed request headers | `headers(std::vector<std::string>)` / `common_headers()` | empty by default |
| Exposed response headers | `expose_headers(std::vector<std::string>)` | empty by default |
| Credentials | `credentials(CorsOptions::AllowCredentials)` | `No` by default |
| Preflight cache | `max_age(qb::duration)` | default 24 h (`86400` s) |

The `max_age` setter takes a **`qb::duration`** and stores it internally as whole seconds (it is emitted as `Access-Control-Max-Age`):

```cpp
#include <qbm/http/http.h>
#include <qbm/http/middleware/cors.h>
#include <chrono>

using MySession = qb::http::DefaultSession;

qb::http::CorsOptions opts;
opts.origins({"https://app.example.com"})
    .methods({"GET", "POST", "OPTIONS"})
    .headers({"Content-Type", "Authorization"})
    .credentials(qb::http::CorsOptions::AllowCredentials::Yes)
    .max_age(std::chrono::hours(1));        // qb::duration

router.use(qb::http::cors_middleware<MySession>(opts));
```
<!-- src: qbm/http/src/qbm/http/middleware/cors.h:243 -->

**Presets and factories:**

| Factory | Behavior |
|---|---|
| `cors_middleware<S>(opts = CorsOptions::permissive())` | from explicit options |
| `cors_dev_middleware<S>()` | `CorsOptions::permissive()` — all origins, all methods, credentials allowed; development only |
| `cors_secure_middleware<S>(allowed_origins_list)` | `CorsOptions::secure(...)` — listed origins, `{GET,POST,OPTIONS}`, credentials off, 1 h preflight cache |

`CorsOptions::permissive()` sets `origins({"*"})` *and* `credentials(Yes)`. That combination is rejected at response time by user agents and is intended for local development only; reach for `cors_secure_middleware` in production.

> **ReDoS note.** With `origin_patterns` (regex matching), the middleware bounds origin length (`MAX_ORIGIN_LENGTH = 2048`), pattern count, and pattern length to mitigate catastrophic backtracking. Keep your patterns linear — no nested quantifiers — because qb's HTTP stack is single-threaded per listener and cannot interrupt a runaway `std::regex` match.

## JWT

- **Header:** `<qbm/http/middleware/jwt.h>` · **Class:** `qb::http::JwtMiddleware<SessionType>`
- **Requires:** `QB_HAS_SSL` (the header includes `<qb/io/crypto_jwt.h>`).
- **Purpose:** extract a JSON Web Token from a header, cookie, or query parameter, verify it, and stash the decoded payload in the context.

On success the middleware stores the decoded payload under the context key `"jwt_payload"` as a `qb::json` and continues the chain; on failure it produces an error response (overridable via `with_error_handler`).

Configuration is the `qb::http::JwtOptions` struct:

| Field | Type | Default |
|---|---|---|
| `secret` | `std::string` | — (HMAC secret or PEM public key) |
| `algorithm` | `std::string` | `"HS256"` |
| `verify_exp` / `verify_nbf` / `verify_iat` | `bool` | `true` |
| `verify_iss` / `verify_aud` / `verify_sub` | `bool` | `false` |
| `issuer` / `audience` / `subject` | `std::string` | empty (checked when the matching `verify_*` is set) |
| `leeway` | **`std::chrono::seconds`** | `0` |
| `token_location` | `JwtTokenLocation` | `HEADER` |
| `token_name` | `std::string` | `"Authorization"` |
| `auth_scheme` | `std::string` | `"Bearer"` |

`leeway` is **`std::chrono::seconds`**, not `qb::duration`. JWT time claims (`exp`, `nbf`, `iat`) are RFC 7519 NumericDate values measured in seconds since the Unix epoch; the leeway is the clock-skew tolerance applied against them, so seconds is the correct, deliberate unit — keep it as seconds and do not convert it to `qb::duration`.

```cpp
#include <qbm/http/http.h>
#include <qbm/http/middleware/jwt.h>
#include <chrono>

using MySession = qb::http::DefaultSession;

qb::http::JwtOptions opts;
opts.secret    = "replace-with-your-secret";
opts.algorithm = "HS256";
opts.verify_iss = true;
opts.issuer     = "my-service";
opts.leeway     = std::chrono::seconds(30);   // RFC NumericDate skew tolerance

auto jwt = qb::http::jwt_middleware_with_options<MySession>(opts);
// Optional: require claims, attach validators / handlers.
jwt->require_claims({"sub", "role"})
   .with_success_handler([](auto ctx, const qb::json& payload) {
       // payload is also available later via ctx->get<qb::json>("jwt_payload")
   });
router.use(jwt);
```
<!-- src: qbm/http/src/qbm/http/middleware/jwt.h:49 -->

**Factories:** `jwt_middleware<S>(secret, algorithm = "HS256")` for the common case, and `jwt_middleware_with_options<S>(JwtOptions)` for the full surface. Fluent setters on the instance — `from_header`, `from_cookie`, `from_query`, `require_claims`, `with_validator`, `with_error_handler`, `with_success_handler`, `with_options` — return `*this` for chaining.

For full token issuance, role checks, and an `auth::User` object, prefer the [authentication middleware](#authentication) below, which wraps an `auth::Manager`.

## Rate limiting

- **Header:** `<qbm/http/middleware/rate_limit.h>` · **Class:** `qb::http::RateLimitMiddleware<SessionType>`
- **Purpose:** cap requests per client identifier within a rolling window; emit `X-RateLimit-*` headers and reject over-limit requests.

Configuration is `qb::http::RateLimitOptions`:

| Option | Method | Type / default |
|---|---|---|
| Max requests per window | `max_requests(size_t)` | `100` |
| Window length | `window(qb::duration)` | `std::chrono::minutes(1)` |
| Over-limit status | `status_code(qb::http::status)` | `TOO_MANY_REQUESTS` (429) |
| Over-limit body | `message(std::string)` | "Rate limit exceeded…" |
| Client identifier | `client_id_extractor(fn)` | trusted-proxy header chain, then a per-session placeholder |

The window is a **`qb::duration`**. When you do not supply a `client_id_extractor`, the default extractor consults, in order, `CF-Connecting-IP`, then `True-Client-IP`, then the rightmost (closest-to-server) hop of `X-Forwarded-For`; if none of those headers is present it falls back to a per-session placeholder id, and finally to `"unknown_client"`. The rightmost `X-Forwarded-For` hop is chosen deliberately because the leftmost entries are client-controlled and forgeable.

```cpp
#include <qbm/http/http.h>
#include <qbm/http/middleware/rate_limit.h>
#include <chrono>

using MySession = qb::http::DefaultSession;

qb::http::RateLimitOptions opts;
opts.max_requests(100)
    .window(std::chrono::minutes(1))       // qb::duration
    .message("Slow down.");

router.use(qb::http::rate_limit_middleware<MySession>(opts));
```
<!-- src: qbm/http/src/qbm/http/middleware/rate_limit.h:104 -->

**Presets:** `RateLimitOptions::permissive()` (1000 req/min) and `RateLimitOptions::secure()` (60 req/min) are the option presets; `rate_limit_dev_middleware<S>()` and `rate_limit_secure_middleware<S>()` build the middleware directly from them. `rate_limit_middleware<S>(opts)` takes explicit options.

> A `RateLimitMiddleware` instance owns mutable per-client counters and is **not** shareable across listener threads. Construct one per listener; do not reuse a single instance across cores.

## Compression

- **Header:** `<qbm/http/middleware/compression.h>` · **Class:** `qb::http::CompressionMiddleware<SessionType>`
- **Requires:** `QB_HAS_COMPRESSION` for the actual codec work. The middleware compiles without it but becomes a no-op for the compress/decompress steps.
- **Purpose:** decompress request bodies by `Content-Encoding` and compress response bodies negotiated against `Accept-Encoding`, setting `Content-Encoding`, `Vary`, and `Content-Length`.

Configuration is `qb::http::CompressionOptions` (no time fields):

| Option | Method | Type / default |
|---|---|---|
| Compress responses | `compress_responses(bool)` | `true` |
| Decompress requests | `decompress_requests(bool)` | `true` |
| Minimum body to compress | `min_size_to_compress(size_t)` | `1024` bytes |
| Preferred encodings | `preferred_encodings(std::vector<std::string>)` | `{"gzip","deflate"}` |

The `CompressionOptions` builder and the `compression_middleware<S>(...)` factory compile in every build — they are *not* behind the `#ifdef`. Only the codec calls inside the middleware are gated, so attaching it in a build without `QB_HAS_COMPRESSION` is harmless: it simply passes bodies through untouched. You therefore do not need to guard the construction.

```cpp
#include <qbm/http/http.h>
#include <qbm/http/middleware/compression.h>

using MySession = qb::http::DefaultSession;

qb::http::CompressionOptions opts;
opts.min_size_to_compress(512)
    .preferred_encodings({"gzip", "deflate"});
router.use(qb::http::compression_middleware<MySession>(opts));
```
<!-- src: qbm/http/src/qbm/http/middleware/compression.h:40 -->

**Presets:** `CompressionOptions::max_compression()` (compress from 256 bytes) and `CompressionOptions::fast_compression()` (compress from 2048 bytes); the matching factories are `max_compression_middleware<S>()` and `fast_compression_middleware<S>()`. `compression_middleware<S>(opts)` takes explicit options.

## Timing

- **Header:** `<qbm/http/middleware/timing.h>` · **Class:** `qb::http::TimingMiddleware<SessionType>`
- **Purpose:** measure how long a request spends in the chain, add an `X-Response-Time` header (floating-point milliseconds), and report the duration to a callback.

The middleware uses a monotonic `std::chrono::steady_clock` and reports `std::chrono::milliseconds` to your callback:

```cpp
#include <qbm/http/http.h>
#include <qbm/http/middleware/timing.h>
#include <chrono>

using MySession = qb::http::DefaultSession;

auto timing = qb::http::timing_middleware<MySession>(
    [](const std::chrono::milliseconds& d) {
        // record d.count() to your metrics sink
    });
router.use(timing);
```
<!-- src: qbm/http/src/qbm/http/middleware/timing.h:56 -->

The callback type is `TimingMiddleware<S>::TimingCallback = std::function<void(const std::chrono::milliseconds&)>`. The constructor throws `std::invalid_argument` if you pass a null callback.

## Static files

- **Header:** `<qbm/http/middleware/static_files.h>` · **Class:** `qb::http::StaticFilesMiddleware<SessionType>`
- **Purpose:** serve files from a filesystem root with index files, MIME types, conditional requests, range requests, and optional directory listing.

Configuration is `qb::http::StaticFilesOptions`, constructed with the root directory and refined with `with_*` setters:

| Option | Setter | Type / default |
|---|---|---|
| Root directory | constructor / `with_root_directory(path)` | `std::filesystem::path` |
| Serve index file | `with_serve_index_file(bool)` | `true` |
| Index file name | `with_index_file_name(std::string)` | `"index.html"` |
| Default MIME type | `with_default_mime_type(std::string)` | `"application/octet-stream"` |
| Extra MIME types | `add_mime_type(ext, type)` | seeded with common types |
| Strip path prefix | `with_path_prefix_to_strip(std::string)` | none |
| Cache-Control | `with_cache_control(bool, std::string)` | on, `"public, max-age=3600"` |
| ETags | `with_etags(bool)` | `true` |
| Last-Modified | `with_last_modified(bool)` | `true` |
| Range requests | `with_range_requests(bool)` | `true` |
| Directory listing | `with_directory_listing(bool)` | `false` |
| Max file size | `with_max_file_size(std::size_t)` | `64` MiB; `0` disables the cap. Over-size requests get `413` |
| Reject symlinks | `with_reject_symlinks(bool)` | `false` (links escaping the root are rejected regardless) |

The freshness lifetime is **not** a duration type: `with_cache_control` takes a literal `Cache-Control` header *string* (`"public, max-age=3600"`), so the `max-age` token is whatever you write into that string. Directory listing defaults to off for safety, and the middleware normalizes paths to reject directory traversal.

`root_directory` is a `std::filesystem::path`, and a **relative** root is resolved through `qb::io::sys::resolve_resource` when the middleware is constructed: it is looked up against the current working directory first (historical behaviour), then against the executable's own directory, before being canonicalised. A binary shipped next to its asset directory therefore serves them from **any** working directory — no `cd`, no environment setup. An **absolute** root is used unchanged. The root must exist and be a directory at construction time, or the constructor throws.

```cpp
#include <qbm/http/http.h>
#include <qbm/http/middleware/static_files.h>

using MySession = qb::http::DefaultSession;

qb::http::StaticFilesOptions opts("./public");
opts.with_serve_index_file(true)
    .with_cache_control(true, "public, max-age=86400, immutable")
    .with_directory_listing(false)
    .with_reject_symlinks(true);

router.use(qb::http::static_files_middleware<MySession>(opts));
```
<!-- src: qbm/http/src/qbm/http/middleware/static_files.h:757 -->

`static_files_middleware<S>(StaticFilesOptions)` is the only factory; there is no default-constructed form because the root directory is required.

## Authentication

- **Header:** `<qbm/http/middleware/auth.h>` · **Class:** `qb::http::AuthMiddleware<SessionType>`
- **Requires:** `QB_HAS_SSL` (it wraps an `auth::Manager`).
- **Purpose:** the full authentication and authorization path — token extraction, verification, building an `auth::User`, storing it in the context, and optional role checks.

This is the richer counterpart to the [JWT middleware](#jwt). It integrates with the [authentication system](./11-authentication.md): an `auth::Manager` configured by `auth::Options` handles tokens, and the resulting `auth::User` is stored under a context key (default `"user"`).

Fluent configuration on the instance:

| Concern | Method |
|---|---|
| Context key for the user | `with_user_context_key(std::string)` — default `"user"` |
| Require authentication | `with_auth_required(bool)` |
| Role requirement | `with_roles(std::vector<std::string>, bool require_all = false)` |
| Replace options | `with_options(const auth::Options&)` |

The duration fields live on `auth::Options`, not on the middleware, and both are **`std::chrono::seconds`** — for the same RFC NumericDate reason as JWT leeway:

- `auth::Options::token_expiration(std::chrono::seconds)` — token validity, default `3600` s.
- `auth::Options::clock_skew_tolerance(std::chrono::seconds)` — verification skew, default `0`.

```cpp
#include <qbm/http/http.h>
#include <qbm/http/middleware/auth.h>
#include <qbm/http/auth.h>              // qb::http::auth::Options
#include <chrono>

using MySession = qb::http::DefaultSession;

qb::http::auth::Options opts;
opts.secret_key("your-app-secret")
    .token_expiration(std::chrono::seconds(3600))   // std::chrono::seconds
    .clock_skew_tolerance(std::chrono::seconds(30));

auto auth = qb::http::auth_middleware<MySession>(opts);
auth->with_roles({"admin", "editor"})   // any of these roles
    .with_auth_required(true);
router.use(auth);
```
<!-- src: qbm/http/src/qbm/http/middleware/auth.h:383; qbm/http/src/qbm/http/auth/options.h:161 -->

**Factories:**

| Factory | Use |
|---|---|
| `auth_middleware<S>(opts = auth::Options{})` | general case from options |
| `jwt_auth_middleware<S>(secret, algorithm = "HS256")` | JWT-configured; `HS*` uses `secret_key`, otherwise `public_key` |
| `role_auth_middleware<S>(roles, require_all = false)` | role check assuming a user is already in context; sets `with_auth_required(true)` |
| `optional_auth_middleware<S>(opts = auth::Options{})` | authentication optional: missing credentials pass, but malformed or invalid credentials are still rejected |

## Security headers

- **Header:** `<qbm/http/middleware/security_headers.h>` · **Class:** `qb::http::SecurityHeadersMiddleware<SessionType>`
- **Purpose:** add response headers that harden the browser side — HSTS, `X-Content-Type-Options`, `X-Frame-Options`, CSP, `Referrer-Policy`, `Permissions-Policy`, and the cross-origin isolation policies.

Configuration is `qb::http::SecurityHeadersOptions`, a builder of optional string values. Each header is set by its literal value — there is **no** duration type here; HSTS `max-age` is part of the header string you supply.

| Header | Setter |
|---|---|
| `Strict-Transport-Security` | `with_hsts(std::string)` / `without_hsts()` |
| `X-Content-Type-Options: nosniff` | `with_x_content_type_options_nosniff(bool = true)` |
| `X-Frame-Options` | `with_x_frame_options(std::string)` / `without_x_frame_options()` |
| `Content-Security-Policy` | `with_content_security_policy(std::string)` |
| `Content-Security-Policy-Report-Only` | `with_content_security_policy_report_only(std::string)` |
| CSP nonce generation | `with_csp_nonce(bool = true)` — **requires `QB_HAS_SSL`** |
| `Referrer-Policy` | `with_referrer_policy(std::string)` |
| `Permissions-Policy` | `with_permissions_policy(std::string)` |
| `Cross-Origin-Opener-Policy` | `with_cross_origin_opener_policy(std::string)` |
| `Cross-Origin-Embedder-Policy` | `with_cross_origin_embedder_policy(std::string)` |
| `Cross-Origin-Resource-Policy` | `with_cross_origin_resource_policy(std::string)` |

`SecurityHeadersOptions::secure_defaults()` is a strong baseline: HSTS `max-age=31536000; includeSubDomains`, `nosniff`, `X-Frame-Options: SAMEORIGIN`, a restrictive CSP, `Referrer-Policy: strict-origin-when-cross-origin`, `Cross-Origin-Opener-Policy: same-origin`, and `X-Permitted-Cross-Domain-Policies: none`. COEP and `Permissions-Policy` are left unset because they are application-specific.

```cpp
#include <qbm/http/http.h>
#include <qbm/http/middleware/security_headers.h>

using MySession = qb::http::DefaultSession;

auto sec = qb::http::security_headers_middleware<MySession>(
    qb::http::SecurityHeadersOptions::secure_defaults());
router.use(sec);
```
<!-- src: qbm/http/src/qbm/http/middleware/security_headers.h:408 -->

> **CSP nonce gate.** `with_csp_nonce(true)` requires `QB_HAS_SSL` — the per-request nonce comes from the framework CSPRNG. In a plain-HTTP build, leave nonce generation off; constructing the middleware with it enabled throws `std::logic_error`. The middleware itself remains available without SSL as long as you do not request nonces.

## Structural and observability middleware

Four more middleware ship for flow control and instrumentation. They take callables rather than option structs, so there is no duration surface; each has both a class template and a free factory.

| Middleware | Header · Class | Factory | Purpose |
|---|---|---|---|
| Conditional | `<qbm/http/middleware/conditional.h>` · `ConditionalMiddleware<S>` | `conditional_middleware<S>(predicate, if_middleware, else_middleware = nullptr)` | Run one of two child middleware on a `bool(Context)` predicate — the `if_middleware` branch when true, the optional `else_middleware` branch when false (continue otherwise). Throws `std::invalid_argument` if the predicate or `if_middleware` is null. |
| Transform | `<qbm/http/middleware/transform.h>` · `TransformMiddleware<S>` | `transform_middleware<S>(request_transformer = nullptr)` | Apply a `RequestTransformer` to `ctx->request()` before the chain proceeds; a null transformer is a pass-through. |
| Logging | `<qbm/http/middleware/logging.h>` · `LoggingMiddleware<S>` | `logging_middleware<S>(log_fn, request_level = LogLevel::Info, response_level = LogLevel::Debug)` | Log request/response at configurable `LogLevel`s via a user `LogFunction`. Throws `std::invalid_argument` on a null log function; exceptions from the user function are suppressed. |
| Error handling | `<qbm/http/middleware/error_handling.h>` · `ErrorHandlingMiddleware<S>` | `error_handling_middleware<S>(name = "ErrorHandlingMiddleware")` | Centralised error-to-response translation; register handlers for specific status codes / exception types with fluent setters. |

<!-- src: qbm/http/src/qbm/http/middleware/conditional.h:147, transform.h:128, logging.h:213, error_handling.h:217 -->

## reCAPTCHA

- **Header:** `<qbm/http/middleware/recaptcha.h>` · **Class:** `qb::http::RecaptchaMiddleware<SessionType>`
- **Gate:** the factories and the `RecaptchaMiddleware` class in `<qbm/http/middleware/recaptcha.h>` are always available once that header is included (it is not pulled in by `all.h` by default); only the unified `make` tags (`recaptcha`/`recaptcha_v3`/`recaptcha_strict`) are compiled behind `QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE`.
- **Purpose:** verify a Google reCAPTCHA v2/v3 token (via an outbound verification call) before the chain proceeds.

Configuration is `qb::http::RecaptchaOptions` (secret key, minimum score, etc.). Three factories cover the common presets:

| Factory | Use |
|---|---|
| `recaptcha_middleware<S>(options)` / `recaptcha_middleware<S>(secret_key, min_score = 0.5f)` | full options, or v3 with a secret + score |
| `recaptcha_v3_middleware<S>(secret_key, min_score = 0.5f)` | reCAPTCHA v3 preset |
| `recaptcha_strict_middleware<S>(secret_key)` | strict preset |

<!-- src: qbm/http/src/qbm/http/middleware/recaptcha.h:579-626 -->

Construction throws `std::invalid_argument` if the secret key is empty. The free factories and class compile without any define once `<qbm/http/middleware/recaptcha.h>` is included; only the `make` tags for them are gated behind `QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE`.

## The unified `make` entry point

`<qbm/http/middleware/make.h>` (pulled in by `all.h`) exposes one tag-dispatched factory over every standard middleware, so you can build any of them through a single call:

```cpp
#include <qbm/http/middleware/all.h>   // includes make.h

namespace mw = qb::http::middleware;

auto cors = mw::make<mw::tags::cors_secure, MySession>(
    std::vector<std::string>{"https://app.example.com"});
auto rl   = mw::make<mw::tags::rate_limit_dev, MySession>();
router.use(cors);
router.use(rl);
```
<!-- src: qbm/http/src/qbm/http/middleware/make.h:287 (make<>); tags at make.h:62-109 -->

The signature is `make<Tag, SessionType, Args...>(Args&&...)`; it forwards to the matching free factory. Tags mirror the factories above and live in `qb::http::middleware::tags`:

- **CORS:** `cors`, `cors_dev`, `cors_secure`
- **Compression:** `compression`, `compression_fast`, `compression_max`
- **Rate limiting:** `rate_limit`, `rate_limit_dev`, `rate_limit_secure`
- **Security & delivery:** `security_headers`, `static_files`
- **Observability:** `logging`, `timing`
- **Structural:** `transform`, `conditional`, `error_handling`
- **SSL-gated (`QB_HAS_SSL`):** `jwt`, `auth`, `jwt_auth`, `role_auth`, `optional_auth`
- **reCAPTCHA-gated (`QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE`):** `recaptcha`, `recaptcha_v3`, `recaptcha_strict`

The `jwt`/`auth`/`jwt_auth`/`role_auth`/`optional_auth` tags are compiled only under `QB_HAS_SSL`, and the `recaptcha*` tags only under `QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE` — referencing a tag the build did not compile is a compile error, exactly as for an unknown tag. The factories are all spelled `*_middleware` (for example `cors_middleware`, `jwt_middleware`, `rate_limit_middleware`); the earlier `create_*_middleware` free functions were renamed to this form and no longer exist, so call the `*_middleware` factory (or `make<Tag, S>(...)`) directly.

## Feature gates and includes

| Middleware | Header | Build gate |
|---|---|---|
| CORS | `<qbm/http/middleware/cors.h>` | none |
| Rate limiting | `<qbm/http/middleware/rate_limit.h>` | none |
| Timing | `<qbm/http/middleware/timing.h>` | none |
| Logging | `<qbm/http/middleware/logging.h>` | none |
| Conditional | `<qbm/http/middleware/conditional.h>` | none |
| Transform | `<qbm/http/middleware/transform.h>` | none |
| Error handling | `<qbm/http/middleware/error_handling.h>` | none |
| Static files | `<qbm/http/middleware/static_files.h>` | none |
| Security headers | `<qbm/http/middleware/security_headers.h>` | none; CSP nonce needs `QB_HAS_SSL` |
| Compression | `<qbm/http/middleware/compression.h>` | codec work needs `QB_HAS_COMPRESSION` |
| JWT | `<qbm/http/middleware/jwt.h>` | `QB_HAS_SSL` |
| Authentication | `<qbm/http/middleware/auth.h>` | `QB_HAS_SSL` |
| reCAPTCHA | `<qbm/http/middleware/recaptcha.h>` | `QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE` |

Because module dependencies are linked `PUBLIC`, the upstream `QB_HAS_SSL` and `QB_HAS_COMPRESSION` defines reach your translation units, so these `#ifdef` gates resolve correctly in your code. Guard SSL-only middleware accordingly:

```cpp
#ifdef QB_HAS_SSL
router.use(qb::http::jwt_middleware<MySession>("secret"));
#endif
```

## Time types at a glance

| Field | Middleware / type | Time type |
|---|---|---|
| CORS preflight cache | `CorsOptions::max_age` | `qb::duration` |
| Rate-limit window | `RateLimitOptions::window` | `qb::duration` |
| JWT clock-skew leeway | `JwtOptions::leeway` | `std::chrono::seconds` (RFC NumericDate boundary) |
| Auth token expiration | `auth::Options::token_expiration` | `std::chrono::seconds` |
| Auth clock-skew tolerance | `auth::Options::clock_skew_tolerance` | `std::chrono::seconds` |
| Timing callback | `TimingMiddleware::TimingCallback` | `std::chrono::milliseconds` |
| Static-files / HSTS `max-age` | `with_cache_control` / `with_hsts` | plain string (`max-age=…`) |

The `std::chrono::seconds` fields are at the JWT/RFC boundary, where NumericDate claims are defined in seconds — keep them as seconds rather than converting to `qb::duration`. The `qb::duration` fields are the framework-native spans.

## Pitfalls

- **Order matters.** Add `cors`, `security_headers`, `rate_limit`, and `compression` at the router root before authentication so they apply to every response, including error responses; see the inheritance rules in [the middleware overview](./07-middleware.md). Note that global root middleware is *not* auto-prepended to a user-defined error chain set via `set_error_task_chain`.
- **`permissive`/`dev` presets are for development.** `cors_dev_middleware` and `rate_limit_dev_middleware` are deliberately loose. Use the `secure` variants in production.
- **Per-listener state.** `RateLimitMiddleware` holds mutable counters; build one instance per listener, never share across cores.
- **SSL gates are compile-time.** JWT and auth middleware do not exist in a non-SSL build. Wrap their construction in `#ifdef QB_HAS_SSL` or your code will not compile there.
- **`max-age` is a string in two places.** Static-files `Cache-Control` and security-headers HSTS take literal header strings, not duration objects. Only CORS `max_age` and the rate-limit `window` are `qb::duration`.
- **Use the current time vocabulary.** Framework-native spans are `qb::duration`; the JWT/auth NumericDate boundary uses `std::chrono::seconds`; the HTTP date API uses `qb::wall_time`. The earlier capitalized time aliases and the old HTTP date-conversion helpers were retired — none of them appear in this module's API.

## See also

- [Middleware overview](./07-middleware.md) — the chain model, inheritance, and `use()` overloads.
- [Custom middleware](./09-custom-middleware.md) — write your own `IMiddleware`.
- [Authentication](./11-authentication.md) — `auth::Manager`, `auth::Options`, and `auth::User` in depth.
- [Validation](./12-validation.md) — the validation middleware and `RequestValidator`.
- [Request context](./10-request-context.md) — `ctx->set/get` for `"jwt_payload"` and `"user"`.

---

Previous: [Middleware overview](./07-middleware.md) · Next: [Custom middleware](./09-custom-middleware.md) · Up: [Index](./README.md)

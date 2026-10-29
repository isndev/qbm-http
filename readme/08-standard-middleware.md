# Standard middleware

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 3.3.0 (C++20 default, C++23 supported)

The middleware that ships with the module — CORS, CSRF protection, JWT, rate limiting, compression, timing, request ids, static files, full authentication, and security headers — together with the exact configuration options each exposes and the time type each duration field uses.

**Prerequisites:** [the middleware model and chain order](./07-middleware.md), and [the request context](./10-request-context.md) for `ctx->set/get`. **See also:** [custom middleware](./09-custom-middleware.md), [authentication](./11-authentication.md), [validation](./12-validation.md), and the doc map [`README.md`](./README.md).

## What this page covers

Each shipped middleware is a class template parameterized on your session type, paired with one or more free-function factories. Each factory returns a `std::shared_ptr` to its concrete middleware class — for example `cors_middleware<S>(...)` returns `std::shared_ptr<CorsMiddleware<S>>` — which converts to the `std::shared_ptr<IMiddleware<SessionType>>` that `Router::use` accepts. You attach an instance with `Router::use(...)`, `RouteGroup::use(...)`, or a `Controller`; the chain order and inheritance rules are described in [the middleware overview](./07-middleware.md). This page is the reference for the *configuration surface* of each one — every option, its default, and — where a duration is involved — whether it is a `qb::duration`, a `std::chrono::seconds`, or a plain string.

Two corrections to keep in mind throughout:

- **The module is a compiled library, not header-only.** You link `qbm::http`; the umbrella header `<qbm/http/http.h>` brings the declarations in. Middleware headers live under `<qbm/http/middleware/>`.
- **Several of these are SSL-gated.** JWT and full authentication are only compiled when the framework is built with `QB_HAS_SSL`; CSP nonce generation in the security-headers middleware and the CSRF middleware's tokens also require `QB_HAS_SSL`. The umbrella `<qbm/http/middleware/all.h>` guards the JWT and auth includes behind `#ifdef QB_HAS_SSL`. Compression depends on a separate flag, `QB_HAS_COMPRESSION`. See [feature gates](#feature-gates-and-includes) below.

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
<!-- src: qbm/http/src/qbm/http/middleware/cors.h:534 -->

`Router::use` accepts a `std::shared_ptr<IMiddleware<SessionType>>` (what every factory returns), a coroutine `(ctx) -> qb::io::async::task<void>` handler, a sync `(ctx, next)` lambda, or in-place constructor arguments. See [the middleware overview](./07-middleware.md) for the four overloads.

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
<!-- src: qbm/http/src/qbm/http/middleware/cors.h:127,171,190,222,234,522 -->

**Presets and factories:**

| Factory | Behavior |
|---|---|
| `cors_middleware<S>(opts = CorsOptions::permissive())` | from explicit options |
| `cors_dev_middleware<S>()` | `CorsOptions::permissive()` — all origins, all methods, **credentials off**; development only |
| `cors_secure_middleware<S>(allowed_origins_list)` | `CorsOptions::secure(...)` — listed origins, `{GET,POST,OPTIONS}`, credentials off, 1 h preflight cache |

`CorsOptions::permissive()` sets `origins({"*"})` and `credentials(AllowCredentials::No)`. The two are
a package, and the `No` is load-bearing rather than incidental: `permissive()` is the **default** for
`CorsMiddleware()` / `cors_middleware()` / `cors_dev_middleware()`, and a wildcard origin combined with
`Allow-Credentials: true` is a cross-origin credential-theft hole — the CORS specification forbids the
pair, and an implementation that "works around" the ban by reflecting the caller's `Origin` lets any
site read a logged-in victim's authenticated responses. Do not restore `credentials(Yes)` here. A
permissive policy is for **public, non-credentialed** resources; if you need credentialed cross-origin
requests, enumerate the origins explicitly with `CorsOptions::secure(...)` / `cors_secure_middleware`.

> **ReDoS note.** With `origin_patterns` (regex matching), the middleware bounds origin length (`MAX_ORIGIN_LENGTH = 2048`), pattern count, and pattern length to mitigate catastrophic backtracking. Keep your patterns linear — no nested quantifiers — because qb's HTTP stack is single-threaded per listener and cannot interrupt a runaway `std::regex` match.

## JWT

- **Header:** `<qbm/http/middleware/jwt.h>` · **Class:** `qb::http::JwtMiddleware<SessionType>`
- **Requires:** `QB_HAS_SSL` (the header includes `<qb/io/crypto_jwt.h>`).
- **Purpose:** extract a JSON Web Token from a header, cookie, or query parameter, verify it, and stash the decoded payload in the context.

On success the middleware stores the decoded payload under the context key `"jwt_payload"` as a `qb::json` and continues the chain. `qb::jwt` hands every claim over as text; the middleware gives back JSON booleans and numbers for claims that read as such (`"true"`, `"5"`, `"3.14"`), except the textual claims `is_textual_claim` names — `iss`, `sub`, `aud`, `jti` (RFC 7519 StringOrURI) and `username` — which stay the strings that were signed, so a subject `"123"` reaches an `AuthMiddleware` as the subject `"123"`. <!-- src: qbm/http/src/qbm/http/middleware/jwt.h:345-351, qbm/http/src/qbm/http/middleware/jwt.h:418-420 -->

On failure it produces an error response (overridable via `with_error_handler`).

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
| Client identifier | `client_id_extractor(fn)` | the socket peer IP |
| Trust proxy headers | `trust_forwarded_headers(bool)` | `false` — **opt-in** |

The window is a **`qb::duration`**, and it is honoured at the clock's own resolution: the reset, the stale-entry sweep and `X-RateLimit-Reset` compare the elapsed `now - last_reset_time` with the window without rounding it to whole milliseconds first, so a 500 µs window ends after 500 µs. <!-- src: qbm/http/src/qbm/http/middleware/rate_limit.h:438, qbm/http/src/qbm/http/middleware/rate_limit.h:568, qbm/http/src/qbm/http/middleware/rate_limit.h:600 -->

With no `client_id_extractor`, the default extractor keys on the **socket peer IP** — the actual TCP source, which cannot be forged, so a client cannot mint a fresh bucket per request by inventing a header. It reads the forwarding headers **only** when you opt in with `trust_forwarded_headers(true)` (or when the session type exposes no `ip()`, as a test mock may not).

> **Behind a reverse proxy this is the setting you must change.** nginx / ALB / Cloudflare terminate the connection, so the peer IP is the *proxy's* — every request in the fleet lands in one bucket and a single busy tenant 429s everyone. Call `trust_forwarded_headers(true)`, and only where the proxy is genuinely trusted: the headers are client-supplied on a direct connection.

On the opt-in path the extractor consults, in order, `CF-Connecting-IP`, then `True-Client-IP`, then the rightmost (closest-to-server) hop of `X-Forwarded-For`; failing all three it falls back to a per-session placeholder id, and finally to `"unknown_client"`. The rightmost `X-Forwarded-For` hop is chosen deliberately because the leftmost entries are client-controlled and forgeable.

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
| Preferred encodings | `preferred_encodings(std::vector<std::string>)` | `{"zstd","br","gzip","deflate"}`, holding only the codecs the build registers |

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

The response gets the encoding the client rates highest (`q`); this list breaks a tie — and a browser rates every codec it lists at 1, so the list decides what browsers get — and a name the build does not register is passed over, never chosen. zstd and brotli are there only when qb was built with `QB_WITH_ZSTD` / `QB_WITH_BROTLI` (3.3, Huly QB-93); without them the list is `{"gzip","deflate"}`. The default order is measured (qb's `compress-codecs` bench, the `Codec` cases): zstd compresses JSON and HTML 1.6 to 4 times as fast as gzip at 4 KiB and 6.8 to 14 times as fast from 64 KiB, within 8 % of its ratio, and the middleware compresses on the loop that serves the connection; brotli's output is 0 to 17 % smaller than gzip's, as fast or faster from 64 KiB and up to 1.7 times slower at 4 KiB (on Windows and Linux).

**Presets:** `CompressionOptions::max_compression()` (compress from 256 bytes; smallest output first: `{"br","gzip","deflate","zstd"}`) and `CompressionOptions::fast_compression()` (compress from 2048 bytes; cheapest encoder first: `{"zstd","deflate","gzip","br"}`), each holding only the codecs the build registers; the matching factories are `max_compression_middleware<S>()` and `fast_compression_middleware<S>()`. `compression_middleware<S>(opts)` takes explicit options.

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

## Request id

- **Header:** `<qbm/http/middleware/request_id.h>` · **Class:** `qb::http::RequestIdMiddleware<SessionType>`
- **Purpose:** give every request an id, store it in the context for the handlers and the logs, and answer it in a response header (Huly QB-166).

Each request gets a fresh random UUID version 4 (`qb::generate_random_uuid()`, 36 characters) unless the middleware is told to trust the client: with `trust_incoming_id()`, an id the client sent in the same header is adopted when it is 1 to 128 characters of `[A-Za-z0-9._-]` (`qb::http::is_valid_request_id`), and replaced by a fresh one otherwise. An id the client chose is not trusted by default, and a refused one is never echoed: the id goes into logs unchanged.

```cpp
#include <qbm/http/http.h>
#include <qbm/http/middleware/request_id.h>

using MySession = qb::http::DefaultSession;

router.use(qb::http::request_id_middleware<MySession>());                 // first: X-Request-ID, generated
// behind a proxy that stamps its own id:
// router.use(qb::http::request_id_middleware<MySession>(
//     qb::http::RequestIdOptions{}.header("X-Correlation-ID").trust_incoming_id()));

router.get("/orders/:id", [](auto ctx) {
    const std::string *rid = ctx->get_if(qb::http::request_id_slot);    // never null after the middleware
    ctx->json(qb::json{{"request_id", rid ? *rid : ""}});
});
```
<!-- src: qbm/http/src/qbm/http/middleware/request_id.h:37 (request_id_slot), qbm/http/src/qbm/http/middleware/request_id.h:63 (RequestIdOptions), qbm/http/src/qbm/http/middleware/request_id.h:171 (request_id_middleware) -->

The id is stored under `qb::http::request_id_slot` — a `Slot<std::string>` keyed `"request.id"`, the key [the request context](./10-request-context.md) uses for a hand-made id — and the response header (`X-Request-ID` unless `RequestIdOptions::header()` names another) is set as the middleware runs, so it is on the answer whatever the handler sends, a 404 or a 500 included. Install it first, as global middleware: the middleware before it see no id, and global middleware also runs for the 404 and 405 answers. A request the router answers before any chain runs (a path over its length limit) gets none. `LoggingMiddleware` prefixes both of its lines with `[<id>] ` when the slot is set. The id is a correlation, not a secret: the UUID comes from a `std::mt19937`. An empty header name throws `std::invalid_argument`.

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

For GET and HEAD, a present `If-None-Match` takes precedence over `If-Modified-Since`; a differing ETag serves the representation even when the supplied date is newer. A directory's configured index file is checked against the canonical root and the `reject_symlinks` option before serving it. Its `Content-Type` follows the configured index filename, including when that filename is a symlink to a file with another extension.

A filesystem root (`/`, `C:\`) is a valid root: its canonical form already ends with the separator, and the containment check accepts what lies below it, while a sibling that merely shares an ordinary root's string prefix (`www` and `www_old`) stays refused. The directory listing writes the request path into each link escaped for the HTML attribute (`&` becomes `&amp;`, percent-encodings are left as they are) and led by one slash however many the path begins with -- a link that begins with `//` names another host (Huly QB-1177) -- and each entry name percent-encoded. <!-- src: qbm/http/src/qbm/http/middleware/static_files.cpp:153-170, qbm/http/src/qbm/http/middleware/static_files.cpp:321-337 -->

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
<!-- src: qbm/http/src/qbm/http/middleware/static_files.h:865 -->

`static_files_middleware<S>(StaticFilesOptions)` is the only factory; there is no default-constructed form because the root directory is required.

ETags derived from file size and modification time are **weak**, prefixed with `W/`.
The opaque value uses a compact, distinct encoding of the same full-width size and
signed modification-seconds fields. Clients should echo the tag, not parse it.
`If-None-Match` compares weakly and still accepts previously issued decimal tags,
with or without the weak prefix; the legacy value is formatted only after a miss
on the current tag. Formatting uses bounded local buffers, and the response owns
its header value. They cannot prove byte-for-byte identity for resuming
a download. `If-Range` therefore makes the middleware ignore `Range` and serve the full
representation with 200 for its metadata validators; filesystem dates are also treated
as weak because the middleware cannot establish whether a file changed twice in one
second. This follows the strong-validator requirement of
[RFC 9110 §13.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.1.5).
No file hash or additional read is needed. Without `If-Range`, existing single-range
206/416 behavior is unchanged. Cache preconditions run before range handling, and HEAD
always ignores Range and sends the full representation's headers without a body.

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

**HSTS follows the connection, not the request target** (RFC 6797 §7.1, §7.2): `Strict-Transport-Security` is sent on a response that leaves over secure transport and never over plain TCP. For an HTTP/1.1 or HTTP/2 session the middleware asks the session's transport (`is_secure()`, a compile-time property of `tcp` and `stcp`), so an ordinary origin-form request on a TLS connection — whose URI carries no scheme — gets the header, and an absolute-form `https://` target sent on a plain socket does not. A session without a transport (an HTTP/3 stream session, whose URI is rebuilt from `:scheme`, or a test double) falls back to the scheme of the request URI. <!-- src: qbm/http/src/qbm/http/middleware/security_headers.h:51-71, qbm/http/src/qbm/http/middleware/security_headers.h:337 -->

`SecurityHeadersOptions::secure_defaults()` is a strong baseline: HSTS `max-age=31536000; includeSubDomains`, `nosniff`, `X-Frame-Options: SAMEORIGIN`, a restrictive CSP, `Referrer-Policy: strict-origin-when-cross-origin`, `Cross-Origin-Opener-Policy: same-origin`, and `X-Permitted-Cross-Domain-Policies: none`. COEP and `Permissions-Policy` are left unset because they are application-specific.

```cpp
#include <qbm/http/http.h>
#include <qbm/http/middleware/security_headers.h>

using MySession = qb::http::DefaultSession;

auto sec = qb::http::security_headers_middleware<MySession>(
    qb::http::SecurityHeadersOptions::secure_defaults());
router.use(sec);
```
<!-- src: qbm/http/src/qbm/http/middleware/security_headers.h:433 -->

> **CSP nonce gate.** `with_csp_nonce(true)` requires `QB_HAS_SSL` — the per-request nonce comes from the framework CSPRNG. In a plain-HTTP build, leave nonce generation off; constructing the middleware with it enabled throws `std::logic_error`. The middleware itself remains available without SSL as long as you do not request nonces.

## CSRF protection

- **Header:** `<qbm/http/middleware/csrf.h>` · **Class:** `qb::http::CsrfMiddleware<SessionType>` · **Factory:** `csrf_middleware<SessionType>(CsrfOptions = {}, name)`
- **Purpose:** refuse a cross-site request forgery — a page of another site making the user's browser send an unsafe request, with the user's cookies, to yours — before it reaches the handler.

A browser attaches a site's cookies to every request sent to it, whichever page sent it. The middleware checks two things; a refusal is `403 Forbidden`, `text/plain`, the reason in the body (`Forbidden: origin mismatch`), and the chain stops.

1. **Where the request comes from** — always on, nothing to configure, no token, no client code. `GET`, `HEAD` and `OPTIONS` pass (they must not change state). Otherwise the browser's `Sec-Fetch-Site` decides when it is present: `same-origin` and `none` (a typed address, a bookmark) pass, `same-site` and `cross-site` are refused — a sibling subdomain is another origin. Without it, `Origin` must name the request's own host and port — the `Host` field, or the authority of a target that carries a scheme (HTTP/2 and HTTP/3 rebuild it from `:scheme` and `:authority`; an absolute-form HTTP/1.1 target), never the `//host` of an origin-form path — and, over a TLS connection, the `https` scheme (behind a TLS-terminating proxy the scheme is not compared, as in Go, and HSTS covers that case). A request with neither header passes: every browser sends one of them on an unsafe request, so it is not a browser. This is the algorithm of Go's `net/http.CrossOriginProtection` (Go 1.25) and the current OWASP recommendation.
2. **A signed double-submit token** — opt in with `CsrfOptions::tokens(secret)` (at least 32 bytes; `QB_HAS_SSL`), for defence in depth or for clients the first layer cannot see. Each response to a request without a valid token cookie sets one — never a refusal of where the request comes from, so an unsafe request another site's page makes rotates nothing; a cross-site link under `cookie_same_site(SameSite::Strict)`, whose request carries no Strict cookie, and an exempt request do get one — `__Host-csrf`, `Secure`, `Path=/`, `SameSite=Lax`, readable by the page's scripts, read back as the first cookie spelled exactly so (`Request::cookie_value_exact()`: a `__host-csrf`, a `__Host -csrf` or a bare `__Host-csrf` another host planted neither replaces nor hides it; a nameless `=__Host-csrf=X`, which a browser older than RFC 6265bis sends as `__Host-csrf=X`, is the one shape no server can tell apart -- `session_binding()` makes such a token fail, but it can still hide the real one on that browser) — holding a random value and its HMAC-SHA256 under the secret, bound to the session when `session_binding()` names it. An unsafe request must echo it in `X-CSRF-Token`, or in the `_csrf` field of an `application/x-www-form-urlencoded` or `multipart/form-data` body (a form with a file input); the request's token is in `qb::http::csrf_token_slot` for a page to embed in its forms.

| Option | Default | What it does |
|---|---|---|
| `trusted_origin("https://app.example.com")` | none | an origin you control that may send unsafe requests (another host's front end); skips both layers. `scheme://host[:port]`, http or https, else `std::invalid_argument` |
| `exempt(predicate)` | none | `bool(const Request&)`: a request it accepts skips both layers (a webhook authenticated otherwise) |
| `tokens(secret)` | off | the token layer; changing the secret invalidates every token, re-issued on the next request |
| `session_binding(fn)` | none | `std::string(const Request&)`, the session identifier a token is bound to — without it a token is only signed |
| `cookie_name(name)` / `cookie_secure(bool)` | `__Host-csrf` / `true` | a `__Host-` or `__Secure-` name must stay `Secure`; for plain HTTP in development, name it otherwise and turn `Secure` off |
| `cookie_same_site(SameSite)` / `cookie_max_age(qb::duration)` | `Lax` / none | the cookie's attributes (no `Max-Age`: a browser-session cookie; 1 s to 400 days else `std::invalid_argument`; `SameSite::None` needs `Secure`) |
| `header_name(name)` / `form_field(name)` | `X-CSRF-Token` / `_csrf` | where an unsafe request submits the token; an empty field name reads the header only |

`CsrfOptions::check(request, secure_connection)` gives the decision on its own (`qb::http::CsrfVerdict`: `allowed`, `cross_site`, `origin_mismatch`, `token_missing`, `token_invalid`), and `on_reject(fn)` on the middleware writes your own refusal (`fn(Context&, CsrfVerdict)`; the middleware completes it).

```cpp
#include <qbm/http/http.h>
#include <qbm/http/middleware/csrf.h>

using MySession = qb::http::DefaultSession;

// Where requests come from: enough for a browser application on one origin.
router.use(qb::http::csrf_middleware<MySession>());

// With tokens bound to the session cookie, and a front end on another host.
qb::http::CsrfOptions options;
options.tokens(secret)  // a std::string of 32 bytes or more, the same on every instance
    .session_binding([](const qb::http::Request &r) { return r.cookie_value("sid"); })
    .trusted_origin("https://app.example.com");
auto csrf = qb::http::csrf_middleware<MySession>(std::move(options));
csrf->on_reject([](qb::http::Context<MySession> &ctx, qb::http::CsrfVerdict verdict) {
    ctx.response().status() = qb::http::status::FORBIDDEN;
    ctx.response().body()   = qb::json{{"error", std::string(qb::http::to_string(verdict))}};
});
router.use(csrf);
router.get("/form", [](auto ctx) {
    const std::string *token = ctx->get_if(qb::http::csrf_token_slot);
    ctx->html("<form method=post><input type=hidden name=_csrf value=\"" + (token ? *token : "") + "\"></form>");
});
```
<!-- src: qbm/http/src/qbm/http/middleware/csrf.h:64 (CsrfVerdict), :78 (csrf_token_slot), :116 (CsrfOptions), :249 (CsrfMiddleware), :327 (csrf_middleware) -->

> **Who needs it.** What a browser can send with the user's cookies: forms, an API a page calls with `fetch` and cookie authentication. An API authenticated by a bearer token in a header (JWT through `Authorization`) cannot be forged this way — a page of another site cannot set that header without a CORS preflight your server refuses.

> **What it does not cover.** A WebSocket upgrade is a `GET`: check its `Origin` in the upgrade handler (cross-site WebSocket hijacking). A DNS-rebound name makes `Origin` equal `Host`: serve only the host names you expect. Without `session_binding()` any visitor can obtain a valid token pair for themselves (the `__Host-` cookie is what keeps it out of the victim's browser), and a token has no expiry of its own: rotate the secret, or set `cookie_max_age`. Requests that arrive at once without a cookie (tabs restored together, a page's first parallel calls) are each issued a token and the last cookie set wins: a script reads the token from the cookie when it sends.

## Structural and observability middleware

Four more middleware ship for flow control and instrumentation. They take callables rather than option structs, so there is no duration surface; each has both a class template and a free factory.

| Middleware | Header · Class | Factory | Purpose |
|---|---|---|---|
| Conditional | `<qbm/http/middleware/conditional.h>` · `ConditionalMiddleware<S>` | `conditional_middleware<S>(predicate, if_middleware, else_middleware = nullptr)` | Run one of two child middleware on a `bool(Context)` predicate — the `if_middleware` branch when true, the optional `else_middleware` branch when false (continue otherwise). Throws `std::invalid_argument` if the predicate or `if_middleware` is null. |
| Transform | `<qbm/http/middleware/transform.h>` · `TransformMiddleware<S>` | `transform_middleware<S>(request_transformer = nullptr)` | Apply a `RequestTransformer` to `ctx->request()` before the chain proceeds; a null transformer is a pass-through. |
| Logging | `<qbm/http/middleware/logging.h>` · `LoggingMiddleware<S>` | `logging_middleware<S>(log_fn, request_level = LogLevel::Info, response_level = LogLevel::Debug)` | Log request/response at configurable `LogLevel`s via a user `LogFunction`; both lines begin with `[<id>] ` when a [request id](#request-id) is set. Throws `std::invalid_argument` on a null log function; exceptions from the user function are suppressed. |
| Error handling | `<qbm/http/middleware/error_handling.h>` · `ErrorHandlingMiddleware<S>` | `error_handling_middleware<S>(name = "ErrorHandlingMiddleware")` | Centralised error-to-response translation; register handlers for specific status codes / exception types with fluent setters. |

<!-- src: qbm/http/src/qbm/http/middleware/conditional.h:154, qbm/http/src/qbm/http/middleware/transform.h:128, qbm/http/src/qbm/http/middleware/logging.h:229, qbm/http/src/qbm/http/middleware/error_handling.h:217 -->

Conditional selection is per context. Cancellation of a pending conditional request reaches its selected child, including a nested leaf, without re-evaluating the predicate or changing another context's selection. Completing or cancelling in the predicate prevents the old child from starting. See [Middleware](./07-middleware.md#conditional-middleware) for the cancellation boundary of a shared child instance.
<!-- src: qbm/http/src/qbm/http/middleware/conditional.h:87-111; qbm/http/src/qbm/http/routing/context.h:1349-1381 -->

The access log (`AccessLog`) and the request metrics (`RequestMetrics`) live in `<qbm/http/middleware/access_log.h>` and `<qbm/http/middleware/metrics.h>` and are listed in `all.h`, but they are router observers, installed with `router.add_observer(...)`, not middleware: see [observability](./22-observability.md).

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

<!-- src: qbm/http/src/qbm/http/middleware/recaptcha.h:596-650 -->

The verification result is stored in the context under `"recaptcha_result"` as a `qb::http::RecaptchaResult`. Its `challenge_ts` is the instant Google announces — the RFC 3339 timestamp of the reply (`2026-01-02T03:04:05Z`, a fraction and a numeric offset accepted), converted to UTC — and `has_challenge_ts` says whether the reply carried a readable one, as `has_score` does for the score. An absent or unreadable timestamp leaves `challenge_ts` at the epoch; it never decides the verdict. <!-- src: qbm/http/src/qbm/http/middleware/recaptcha.h:248-260, qbm/http/src/qbm/http/middleware/recaptcha.h:542-549, qbm/http/src/qbm/http/middleware/recaptcha.cpp:32-113 -->

Construction throws `std::invalid_argument` if the secret key is empty. The free factories and class compile without any define once `<qbm/http/middleware/recaptcha.h>` is included; only the `make` tags for them are gated behind `QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE`.

## The unified `make` entry point

`<qbm/http/middleware/make.h>` (pulled in by `all.h`) exposes one tag-dispatched factory over every standard middleware, so you can build any of them through a single call:

```cpp
#include <qbm/http/middleware/all.h>   // includes make.h
#include <qb/io/async.h>               // required for qb::io::async::task<void>

namespace mw = qb::http::middleware;

auto cors = mw::make<mw::tags::cors_secure, MySession>(
    std::vector<std::string>{"https://app.example.com"});
auto rl   = mw::make<mw::tags::rate_limit_dev, MySession>();
router.use(cors);
router.use(rl);
```
<!-- src: qbm/http/src/qbm/http/middleware/make.h:303 (make<>); tags at qbm/http/src/qbm/http/middleware/make.h:64-113 -->

The signature is `make<Tag, SessionType, Args...>(Args&&...)`; it forwards to the matching free factory. Tags mirror the factories above and live in `qb::http::middleware::tags`:

- **CORS:** `cors`, `cors_dev`, `cors_secure`
- **Compression:** `compression`, `compression_fast`, `compression_max`
- **Rate limiting:** `rate_limit`, `rate_limit_dev`, `rate_limit_secure`
- **Security & delivery:** `security_headers`, `csrf`, `static_files`
- **Observability:** `logging`, `timing`, `request_id`
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
| Request id | `<qbm/http/middleware/request_id.h>` | none |
| Conditional | `<qbm/http/middleware/conditional.h>` | none |
| Transform | `<qbm/http/middleware/transform.h>` | none |
| Error handling | `<qbm/http/middleware/error_handling.h>` | none |
| Static files | `<qbm/http/middleware/static_files.h>` | none |
| Security headers | `<qbm/http/middleware/security_headers.h>` | none; CSP nonce needs `QB_HAS_SSL` |
| CSRF protection | `<qbm/http/middleware/csrf.h>` | none; tokens need `QB_HAS_SSL` |
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
| CSRF token cookie lifetime | `CsrfOptions::cookie_max_age` | `qb::duration` |
| JWT clock-skew leeway | `JwtOptions::leeway` | `std::chrono::seconds` (RFC NumericDate boundary) |
| Auth token expiration | `auth::Options::token_expiration` | `std::chrono::seconds` |
| Auth clock-skew tolerance | `auth::Options::clock_skew_tolerance` | `std::chrono::seconds` |
| Timing callback | `TimingMiddleware::TimingCallback` | `std::chrono::milliseconds` |
| Static-files / HSTS `max-age` | `with_cache_control` / `with_hsts` | plain string (`max-age=…`) |

The `std::chrono::seconds` fields are at the JWT/RFC boundary, where NumericDate claims are defined in seconds — keep them as seconds rather than converting to `qb::duration`. The `qb::duration` fields are the framework-native spans.

## Pitfalls

- **Order matters.** Add `cors`, `security_headers`, `rate_limit`, and `compression` at the router root before authentication so they apply to every response, including error responses; see the inheritance rules in [the middleware overview](./07-middleware.md). Note that global root middleware is *not* auto-prepended to a user-defined error chain set via `set_error_task_chain`.
- **`permissive`/`dev` presets are for development.** `cors_dev_middleware` and `rate_limit_dev_middleware` are deliberately loose. Use the `secure` variants in production.
- **CSRF tokens behind a load balancer.** Every instance must sign with the same secret, or a token issued by one is refused by the next. A token bound to the session changes at login: the login's own response still carries one bound to the session before it, and the first request after it is issued a new one — a page posts after a safe request (the redirect a login answers with does it), never right after the login itself.
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

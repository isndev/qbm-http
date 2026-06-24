# Changelog

All notable changes to the qbm-http module are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the module tracks the qb framework's
[Semantic Versioning](https://semver.org/). Framework-wide policy is in the qb
[VERSIONING](../../qb/VERSIONING.md) document.

## [Unreleased]

Tracks changes on the development branch not yet part of a tagged release. This cycle reworks
the accessor surface, the routing/middleware registration API, and the coroutine handler ergonomics,
and hardens the request-stringify, http2 back-pressure, and JWT/auth paths.

### Added

- Concept-driven routing verbs. Each verb (`get/post/put/del/patch/options/head`) on the router,
  route group, and controller now resolves through a single template constrained by
  `RouteHandlerLike` (in `routing/coro_task.h`) plus a member-function overload:
  ```cpp
  router().get("/users", [](auto ctx) { ctx->json(...); });          // sync lambda / fn-ptr / std::function
  router().get("/feed",  [](auto ctx) -> qb::io::async::task<void> { // coroutine, auto-detected
      auto reply = co_await qb::http::GET(req);
      ctx->json(reply.response.body().as<qb::json>());
  });
  router().get("/me", this, &MyController::handle_me);               // member-function overload
  ```
  Coroutine handlers are detected via `if constexpr (CoroRouteHandler<...>)`; no explicit wrapper call
  is needed. `del` maps to `qb::http::method::DEL` (the `DELETE` keyword is avoided).
- `*_or` by-value accessor variants for every "miss returns static-empty ref" accessor, so a custom
  fallback no longer collapses into a dangling temporary:
  `Headers::header_or(name, fallback)`, `Request::query_or(name, fallback)` /
  `Request::cookie_value_or(name, fallback)`, `qb::io::uri::query_or(name, fallback)`, and the
  `Context` typed `path_param_or` / `query_param_or` / `get_or`.
- `Context` response sinks `json()` / `text()` / `html()` as by-value move-sinks that set the right
  content type and finalize the task (`complete(AsyncTaskResult::COMPLETE)`); plus `redirect()`,
  `no_content()`, chainable `status()`, and the `bad_request/unauthorized/forbidden/not_found/internal_server_error`
  shorthands.
- Unified middleware entry point `qb::http::middleware::make<Tag, SessionType>(args...)` dispatching to
  the per-family factories via tags in `qb::http::middleware::tags::*`; unknown tag is a compile error.

### Changed

- Accessor base/`_or` split. The reference-returning accessors (`header`, `query`, `cookie_value`,
  `uri::query`, `Context::path_param`) now always bind to a process-wide static empty string on a miss
  (`qb::http::detail::empty_string_value`) — never a temporary, never a fallback argument. The former
  fallback-argument overloads are gone; use the new `*_or` variants for a custom default.
- `Context::get_ptr<T>` renamed to `Context::get_if<T>` (both mutable and `const` overloads, plus the
  typed-`Slot<T>` overload), mirroring `std::get_if` semantics.
- Middleware factory functions renamed from `create_*_middleware` to `*_middleware`
  (e.g. `create_cors_middleware` → `cors_middleware`, `create_jwt_auth_middleware` → `jwt_auth_middleware`).
  The auth/JWT families remain gated on `QB_HAS_SSL`.
- `Headers` de-templated. It is now a plain class (no `StringType` parameter); values are owning
  `std::string` and the historical zero-copy `std::string_view` mode was retired (the input pipe
  relocates buffer bytes between reads, so views cannot survive the shared `Context`/middleware/coroutine
  lifecycle). `refresh_content_type()` re-syncs the cached `ContentType` after raw `headers()` mutation.
- Coroutine HTTP/1.1 client and http2 client request timeouts are `qb::duration` (the legacy
  `double`-seconds signatures and the blocking `Response GET(Request, double)` helpers were removed).
- `controller<C>(...)` is now `[[nodiscard]]` and `requires DerivedFrom<C, Controller<S>>`.
- Removed the per-verb explicit `RouteHandlerFn` / `std::function` sync overloads, the `MEMBER_HANDLER`
  macro, and the explicit `coro_handler<S>(...)` / `coro_middleware<S>(...)` wrappers — all folded into
  the concept-driven verb template and the `(path, obj, member)` overload.

### Fixed

- `Method` string conversions are abort-safe for the default/unmapped state. A default-constructed
  `Method` is `Value::UNINITIALIZED`; its `operator std::string` / `operator std::string_view`
  (and `std::to_string`) route through `name_view()`, which returns `"UNINITIALIZED"` instead of
  calling vendored llhttp `http_method_name()` (which would `abort()` on the unmapped value).
  `Status` string ops return `"Unknown Status"` on a null code.

### Security

- http2 back-pressure DoS guard. The client bounds outstanding (pending + active) requests via
  `set_max_pending_requests()` (default 1024); past the cap, `push_request()` / `push_requests()`
  reject with `503 Service Unavailable`, matching http1/http3.
- JWT NumericDate hardening. `verify_token` parses `exp`/`nbf`/`iat` through `parse_int64_claim`, which
  accepts integer, unsigned (rejecting values above the int64 max), and float NumericDate (truncated
  toward zero, rejecting non-finite or out-of-`[-2^63, 2^63)` values). Numeric-claim reconstruction
  accepts a `strtod` result only when the string is JSON-number-shaped, `errno == 0`, and finite —
  deliberately rejecting `inf` / `nan` / hex-floats so they stay strings rather than silently becoming
  float claims. The `iat` future-check applies clock-skew leeway.
- `jwt_auth_middleware` selects the key slot off the resolved `auth::Options::Algorithm` enum (via
  case-insensitive `algorithm_from_string`, falling back to `HMAC_SHA256`): HMAC algorithms use
  `secret_key`, asymmetric algorithms use `public_key`, instead of matching a raw string prefix.

## [2.0.0]

Aligns qbm-http with the qb 2.0 framework and hardens the HTTP/2, HTTP/3, WebSocket, and parsing paths.

### Changed

- Time handling migrated to the canonical chrono model: cookie `max_age`, CORS max-age, and rate-limit
  windows are `qb::duration`; the HTTP date API uses `qb::wall_time`; JWT leeway and expiry remain
  `std::chrono::seconds` (RFC NumericDate). The retired `qb::Timestamp` / `qb::Duration` types are gone.
- HTTP/3 build integration: `QBM_HTTP_HAS_HTTP3` is defined PUBLIC so consumers can gate on it.
- Percent-decoding deduplicated into `qb::http::utility`.
- Builds clean under `-Wall -Wextra`.

### Fixed

- HTTP/2: stream use-after-free in handler-throw containment; iterator invalidation during push-promise
  creation; trailer deduplication via a populated initial-frame header set; removed a dead
  `associated_push_promises` field.
- HTTP/1.1: throwing routing/response handlers are contained in the server session.
- Rate-limit client-id extractor made type-safe.

### Security

- HPACK: reject Huffman padding longer than 7 bits (RFC 7541 §5.2).
- Multipart: enforce part-count and total-size limits.
- WebSocket: bound message reassembly by default (denial-of-service hardening).
- HTTP/3: contain exceptions in nghttp3 callbacks and fail closed on RNG error; bound the client
  pending-request queue.
- Reject control characters in quoted header-attribute values.

[Unreleased]: https://github.com/isndev/qbm-http/compare/main...HEAD

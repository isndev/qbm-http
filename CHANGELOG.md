# Changelog

All notable changes to the qbm-http module are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the module tracks the qb framework's
[Semantic Versioning](https://semver.org/). Framework-wide policy is in the qb
[VERSIONING](https://github.com/isndev/qb/blob/main/VERSIONING.md) document.

## [Unreleased]

Nothing yet. Entries land here as they are merged, and move under a version heading when that version is tagged.

## [3.2.1] - 2026-09-24

### Fixed

- **A malformed HTTP/3 message closed the whole connection, not its stream, for what this module
  checks itself (Huly QB-234).** More than `MAX_HEADERS_COUNT` fields, a field value over its
  length limit, a request method the module does not know, a `trailer` field inside the trailer
  section: each of the four validation sites of the protocol connection failed its nghttp3
  callback, which fails the engine's read, and the read's answer to that is `CONNECTION_CLOSE` --
  every other exchange multiplexed on the connection went down with the malformed one, on the
  server (a request) and on the client (a response); behind a gateway that multiplexes several
  users onto one upstream connection, one user's malformed request failed the others'. RFC 9114
  section 4.1.2 makes a malformed message a STREAM error, and the stream alone is refused now: reset
  with `H3_MESSAGE_ERROR`, what still arrives on it dropped, the message never handed to the router
  or to the response callback, the connection and its other streams untouched, the peer seeing the
  reset (a client's 502) -- the shape the body-over-limit site took in 3.2.0. **The other tier is
  the library's.** nghttp3's own validator runs before any callback (pseudo-header order, presence
  and uniqueness, field-name syntax and a 256-byte name cap in its QPACK decoder, the
  connection-specific fields, content-length arithmetic, `:status`), and what it rejects comes back from `nghttp3_conn_read_stream2` as a negative read:
  by its contract a connection error after which only `nghttp3_conn_del` is legal, so those
  malformations still close the connection -- as they do in every nghttp3-based server, ngtcp2's
  reference server included -- and the docs now say which checks belong to which tier. That close
  carried the raw library code (105, 107) as the QUIC application error code; it carries the H3
  code nghttp3 infers from it (`H3_MESSAGE_ERROR`, `H3_FRAME_ERROR`, the QPACK codes) now, on the
  read and on the write path. Tests: four direct-connection cases feeding the frames a malformed peer
  sends (`*RefusesTheStreamNotTheConnection`; the header-count limit in both polarities), each
  failing against the previous code, one pinning the library tier's error code
  (`AMalformationNghttp3RejectsClosesTheConnectionWithMessageError`), and the loopback
  `ClientRejectsResponseContentLengthMismatch` proving the client's connection serves the next
  request after a refused response.

## [3.2.0] - 2026-09-21

### Added

- **`qb::http::RetryPolicy` (`retry_policy.h`) and the HTTP/2 client's reconnection run (Huly
  QB-103).** The same shape as `qb::redis::RetryPolicy` -- `max_attempts` (-1 = unlimited),
  `initial_delay` 100 ms, `max_delay` 30 s, `multiplier` 2, `jitter` +-25 %, `on_retry(attempt,
  next_delay)`, the `with_*` builders -- plus one pure function, `next_delay(attempt, rng)`, the wait
  after `attempt` failed attempts (the redis arithmetic, in integer milliseconds), so the policy is
  unit-tested on its own. `qb::http2::Client` gains `enable_auto_reconnect(RetryPolicy)` /
  `disable_auto_reconnect()` (the redis names; `set_auto_reconnect(bool)` stays and keeps the
  policy), `is_reconnecting()` and `reconnect_attempts()`. A run is the sequence of attempts between
  a connection loss and the next connection that comes up: attempt 1 immediate, then the policy's
  waits; once exhausted the waiting requests fail with a 503 `Reconnection attempts exhausted (N)`
  and the client stays down until the next `connect()`, explicit or the auto-connect of a later
  push. An explicit `disconnect()` starts no run (the HTTP/1.1 client's `_intentional_disconnect`
  rule): its verdict is `"Connection closed"` and a push after it connects on its own. The
  `connect_timeout` field of the redis policy is not carried: `set_connect_timeout()` applies to
  every attempt. Tests: `unit/retry-policy/retry-policy.cpp` (the arithmetic, its caps,
  its jitter bounds, its pathological inputs) and ten system cases at the end of
  `system/http2/http2-client.cpp` (the run observed end to end against a server that only speaks
  http/1.1: 40/80/160 ms waits measured, the verdict, the count; `max_attempts` 0; the server coming
  back during a wait; a disconnect cancelling the scheduled attempt; a disconnect while connecting;
  jitter spreading a run; a peer drop with a request in flight served by the run; an explicit
  disconnect failing it once and starting none; a deferred connect and a follow-up push both
  served; auto-reconnect off).

### Fixed

- **An HTTP/3 server's `graceful_shutdown()` cut the response it was waiting for.** A connection
  that was shutting down closed as soon as its last handler had answered, that is once the
  response had been HANDED to the QUIC transport. Handed is not sent: the transport's send queue
  holds whatever the congestion window or the pacer will not let out yet, and `CONNECTION_CLOSE`,
  which neither holds back, overtook it. Any response wider than one flight was truncated, every
  time -- a 256 KiB body arrived as a 503 `QUIC connection close received` -- and so was a
  response of a few bytes whenever the pacer deferred its second packet, which a real round trip
  does as a rule and a loopback does on a loaded host (seen once on the arm64 CI guest, as a
  failure of `GracefulShutdownWaitsForActiveAsyncContext`; never in 400 quiet repetitions). The
  connection now closes when its last request stream has CLOSED, which the transport reports once
  the peer has acknowledged the final byte. `graceful_shutdown()` therefore returns with such a
  connection still open and the close follows the acknowledgement; a peer that has gone away is
  ended by the transport's idle timeout, as before. Test:
  `GracefulShutdownDeliversResponseWiderThanTheCongestionWindow`, which fails against the previous
  code on every run and on every platform.
- **An HTTP/3 connection kept every exchange it had ever carried, client and server.** The
  protocol connection keeps state beside each stream -- the request, the response and the copy of
  the body the HTTP/3 engine reads from -- and releases it when the engine reports the stream
  closed. nghttp3 has no view of the transport and reports that only when it is TOLD the QUIC
  stream closed; nothing told it, so the release callback was dead code and the state lived as long
  as the connection: forty requests of 4 KiB over one connection left 43 entries on each side where
  3 requests leave 6. A long-lived connection grew by the size of everything it served. The QUIC
  stream-closed event now reaches the engine (`connection::close_stream()`; a close delivered
  while an engine call is on the stack is parked and replayed when it unwinds, because the engine's
  write vectors point into the stream being freed). `Server::http3_stream_state_count()` and
  `Client::get_stream_state_count()` expose the figure, which follows the requests in flight, not
  the requests served. Test: `StreamStateFollowsRequestsInFlightNotRequestsServed` (43 against 6 on
  both sides without the fix).
- **A body over the HTTP/3 limit closed the whole connection, not the stream.** `set_max_body_size`
  is documented as resetting the stream, and the stream was reset -- then the callback that saw
  the overflow failed, which fails the HTTP/3 engine's read, and the read's answer to that is
  `CONNECTION_CLOSE`: every other exchange multiplexed on the connection went down with the
  oversized one, on the server (a request body) and on the client (a response body). The peer did
  not even see the same error twice: the pacer can hold a `RESET_STREAM` back, nothing holds a
  `CONNECTION_CLOSE`, so it reported now the stream reset (502) and now a lost connection (503) --
  61 times in 300 for `ServerRejectsRequestBodyOverLimit` on a loaded arm64 guest, never on a quiet
  host. The stream alone is refused now: reset in both directions, what still arrives on it dropped,
  the message never handed to the router or to the response callback; the connection and its other
  streams are untouched. Test: `BodyOverLimitRefusesTheStreamNotTheConnection` (the same
  connection serves the next request; without the fix it is gone and the follow-up answers 503).
- **The HTTP/2 client's automatic reconnection was immediate and unbounded, and started from
  inside the handler that observed the failure (Huly QB-103).** `attempt_reconnection()` called
  `connect()` on the spot -- the `client.cpp:703` comment said "you might want exponential
  backoff" -- so a client with work pending against a server in incident reconnected as fast as
  the failure came back, for as long as its callbacks re-queued. Every attempt now fires from the
  client's own one-shot timer (the connect and request deadlines' mechanism), on the next pass at
  the earliest, so the transport that dropped is disposed before the next one is opened.
- **A request pushed from a failure callback connected on its own, bypassing any reconnection
  policy.** `push_request()` auto-connects when nothing is connecting, and a failure handler had
  already cleared `_is_connecting` when it ran the callbacks, so the retry pattern -- push it back
  on failure -- was itself the immediate reconnection. During a failure pass such a push queues
  behind the attempt the run decides on; with auto-reconnect off it connects at once, as before.
- **Every connection loss failed the re-queued work two or three times.** The `disconnected`
  handler ran a second failure pass over what the first pass's callbacks had just pushed back, the
  `dispose` handler (raised by the same `dispose()`, right after) ran a third with
  `"Client disposed"` and reset the state of a reconnection the disconnected pass had already
  started; the h2 connection-error and non-graceful GOAWAY paths failed once more through
  `disconnect()`'s own pass. One pass now, with the message that says why, from a single
  `close_connection()`; the transport's `disconnected` keeps the re-queued work and decides on the
  reconnection; `dispose` does nothing the disconnected handler has not done.
- **`disconnect()` while a connect was in flight left the connect callback unanswered (a coroutine
  awaiting `connect()` hung) and let the late completion bring the client back up.** The connector
  carries the epoch it was started with; a completion the client gave up on -- its own connect
  deadline fired first, or `disconnect()` -- is dropped and its socket closes. The callbacks get
  `"Connection closed"` at the disconnect.
- **A transport whose TCP+TLS leg came up but whose handshake failed (no h2 over ALPN, no
  protocol) was left open, its watcher registered.** The next attempt's `start()` then found an
  active watcher on a dead fd. It is closed at the failure, and the `disconnected` it raises finds
  the state settled and the pending work preserved.
- **A reconnection sent the previous connection's unflushed bytes ahead of the h2 preface.** The
  client is the io object of every connection it makes and never reset its buffers: a request
  pushed and disconnected in the same tick stayed in `out()`, went out first on the next
  connection, and the server closed that connection with a protocol error (measured: the server
  session's reason -1). `start_connection()` resets `in()`/`out()` now, as the pgsql client's
  `prepare_reconnect()` does.
- **Each attempt of a run leaked its protocol instances.** `start_connection()` switches to a fresh
  handshake protocol and a success to a fresh h2 one; the base keeps every instance until told
  otherwise, so an unlimited run against a dead server grew by two objects an attempt. The
  scheduled attempt clears them before it connects -- from the timer, never from inside a
  protocol's handler.
- The `[Unreleased]` compare link named `v3.0.0`; the module has shipped `v3.1.0` since.

## [3.1.0] - 2026-08-30

Lockstep release with the qb 3.1.0 train; no change in this repository (the version says
compatible, this section says unchanged).

## [3.0.1] - 2026-08-29

Lockstep patch with the qb 3.0.1 train (cut for qb-examples, Huly QB-4). In this repository only
tooling: a nightly CI run against qb's `develop` of the day, and `scripts/gen-llms-txt.py` strips
HTML comments by scanning rather than by regex.

## [3.0.0] - 2026-08-20

Tracks changes not yet part of a tagged release. Since 2026-08-11 that is **both** branches:
`main` was fast-forwarded to `develop` for the release, so the module version is **3.0.0** on either,
in lockstep with the qb framework; see the qb CHANGELOG for what makes that release major.

### Fixed

- **The >100MB body-rejection path was exercised by no lane and no CI job.**
  `{Request,Response}SerializeLimitsTest.BodyExceedingLimitIsRejected` are the only cases that
  *enforce* `protocol_limits::MAX_BODY_SIZE` rather than compare it to a literal, and both sat
  behind `QBM_HTTP_RUN_HUGE_BODY`, which nothing set — so both silently reported `SKIPPED` inside a
  binary ctest called `Passed`. A security limit nothing exercises is a limit nobody knows is
  broken. `tests/CMakeLists.txt` now registers
  `qbm-http-test-unit-http1-serialize-limits-huge-body`, a ctest entry that sets the variable and
  filters to those two cases, so a plain `ctest` runs them; `ctest -LE huge-body` opts back out on a
  memory-constrained runner without dropping the other cases in the same binary. It carries
  PASS/FAIL regexes requiring `2 tests` to have run, because an env var that failed to propagate or
  a filter that matched nothing would otherwise exit 0 and read as coverage — which is how this path
  came to have none.
- **Two installed HTTP/2 headers failed with a raw template diagnostic in an SSL-off install.**
  `qbm/http/2/client.h` names `qb::io::transport::stcp` in its base-clause with no `QB_HAS_SSL`
  guard anywhere in the file, so `#include`ing it (or `2/http2.h`, which pulls it in) directly
  against an SSL-off prefix produced
  `error: no member named 'stcp' in namespace 'qb::io::transport'` — naming neither SSL nor
  HTTP/2. It never fired through the umbrella, because `qbm/http/http.h` already wraps both in
  `#ifdef QB_HAS_SSL`; the installed-header sweep is what reaches them. Eleven sibling headers
  already self-diagnose with an `#error` (`ws/ws.h`, `auth.h`, the HTTP/3 set) — these two were the
  exceptions, and now match.
- **`CMakeLists.txt` had no `cmake_minimum_required()`, and a standalone configure died on an
  unhelpful error.** CMake reported `No cmake_minimum_required command is present` alongside
  `Unknown CMake command "qb_status_message"` — which reads like a missing include rather than
  "wrong entry point". This module is built from the qb-dev superproject, which loads qb's CMake
  helpers first; an *installed* qb ships none of them (`lib/cmake/qb/` carries only `qbConfig`,
  `qbConfigVersion`, `qbTargets` and the `Find` modules), so pointing `CMAKE_PREFIX_PATH` at one
  does not help — the exact mistake the old error invited. There is now a
  `cmake_minimum_required(VERSION 3.24)` and a guard that names the constraint and points at the
  superproject root and the `package` preset.

- **`qbm/http/chunk.h` was not self-contained.** It specialises
  `qb::allocator::pipe<char>::put<qb::http::Chunk>` while including only `<cstddef>`, so a TU whose
  first http include was this header failed on `no template named 'pipe'`. It now includes
  `<qb/system/allocator/pipe.h>`. Found by qb's new installed-header gate
  (`qb/scripts/check-installed-headers.sh`), which compiles every installed header **alone** against
  an installed prefix; the superproject's `package-consume.yml` runs it over the whole `qbm` tree.

### Removed

- **BREAKING — `qbm/http/routing/router.tpp` no longer exists.** Its 39 template definitions moved
  verbatim to the tail of `routing/router.h`, at exactly the position the `#include "./router.tpp"`
  on that file's last line used to splice them into; the preprocessed token stream of `router.h` is
  byte-identical, which is how the move was verified. Nothing is lost and no definition changed.

  This only breaks a consumer who included the fragment **directly** — `#include
  <qbm/http/routing/router.tpp>`. That was never a supported spelling (the file opened
  `namespace qb::http` and defined members of a class it did not declare, so it could not compile
  alone; qb's installed-header gate carried it as a named "by-design fragment" exclusion). Replace
  it with `#include <qbm/http/routing/router.h>`, or with the `<qbm/http/http.h>` umbrella.

  With this the tree contains zero `.tpp` — qb retired its own four in the same release. The
  reason is the one recorded in the qb CHANGELOG: a file included by both the library TU and every
  consumer TU is one non-template line away from a duplicate symbol, and a separate file cannot
  supply what such definitions actually need, which is a *position*.

### Changed
- **`listen()` arms the accept watcher, so a separate `start()` is no longer required** (recorded
  2026-09-20, from `src/qbm/http/1.1/http.h` and `src/qbm/http/2/http2.h`): an extra `start()` stays
  harmless, and `listen_no_start()` is the opt-out for a server that must finish wiring before it
  accepts.

- **Logging call sites use qb's prefixed `QB_LOG_*` macros** (1 sites). qb 3.0.0 renamed
  `LOG_DEBUG` / `LOG_VERB` / `LOG_INFO` / `LOG_WARN` / `LOG_CRIT` to `QB_LOG_*` because the
  unprefixed spellings — three of which are also POSIX `<syslog.h>` names — reached every consumer
  of this module's umbrella header and silently replaced a consumer's own. qb still defines the
  unprefixed names as `#ifndef`-guarded aliases, and that guard is exactly why these call sites had
  to move: a consumer who defines `LOG_INFO` first now keeps their definition, and this module's
  headers would otherwise have started logging through *it*.

- **BREAKING — the public include prefix is now `<qbm/http/...>`** (was `<http/...>`). Every consumer
  edits its `#include` lines: `#include <http/http.h>` becomes `#include <qbm/http/http.h>`. The CMake
  target is unchanged (`qbm::http`), and so is the installed location `<prefix>/include/qbm/http/`.
  The old spelling existed only because `qb_register_module` made this module's include root its
  PARENT directory — the superproject's `qbm/`, which does not exist in this repository at all — and
  mirrored it with `<prefix>/include/qbm` on the consumer's include path. That put the maximally
  generic top-level name `http` in every consumer's include namespace. Now the module's own `src/`
  IS the include root and is copied verbatim to `<prefix>/include`, so `<qbm/http/...>` is the same
  string in this tree and in an installed prefix, and the two cannot drift.
- **The source tree moved to `src/qbm/http/`** — one pure `git mv`, 100 % rename detection, zero
  content change, so `git blame` and every line-numbered citation survive intact. `1.1/`, `2/`, `3/`, `auth/`, `middleware/`, `routing/`, `validation/`, `ws/` and the message types
  at the root moved with it; `not-qb/llhttp/` deliberately did NOT — the fork's `.c` sources and its
  generator-input `api.h` must not become reachable from an include root, and only its single public
  header now sits at `src/qbm/http/vendor/llhttp.h`. `<prefix>/include/qbm/http/.github/workflows/`,
  which the install really was creating as empty directories, is now structurally impossible.
  `tests/`, `readme/`, `scripts/` and `cmake/` live BESIDE `src/`, never inside it, which is what
  makes a stray `#include <tests/fixture.h>` impossible rather than merely unlikely.
  The test suite now includes the shipped spelling instead of resolving `"../http.h"` by string
  concatenation onto a `-I <mod>/tests` flag.
- **`project(qbm-http VERSION ...)` is now `3.0.0`**, tracking `QB_FRAMEWORK_VERSION`. It had been
  left at `2.6.0` while the framework moved on. The module is not standalone-configurable (it calls
  `qb_register_module` / `qb_add_test`, which an installed qb does not ship), so its version can only
  ever mean "the qb this was built against" — and the structural breaks queued for 3.0.0 land hardest
  in the modules, where a package still claiming `2.6.0` would be actively misleading.
- **`scripts/doc-lint.sh` now validates the *value* of the `Verified-against:` markers**, not just
  their presence. It previously checked only that the marker existed, which is how every page in this
  module sat at `qb 2.6.0` across two version bumps unnoticed. The expected version is read from
  `project(qbm-http VERSION ...)` — the one authoritative version available when this repo is checked
  out alone, as it is in its own CI — and cross-checked against `QB_FRAMEWORK_VERSION` whenever a qb
  tree is reachable. A version it cannot determine is a hard stop, never a skip.
- **The default outbound `User-Agent` is derived from the framework version.** It was the hard-coded
  literal `"qb/2.6.0"` in two separate places (`src/qbm/http/1.1/client.cpp`, `src/qbm/http/1.1/http.h`), so every request from
  a post-2.6.0 build advertised a version that was simply wrong. It is now
  `qb::http::default_user_agent` (`headers.h`), composed at compile time from `QB_VERSION`, so it
  cannot drift again; `headers.h` hard-`#error`s if `QB_VERSION` is absent. Callers that set their own
  `User-Agent` are still never overridden.

## [2.6.0] - 2026-08-02

This cycle reworks the accessor surface, the routing/middleware registration API, and the coroutine
handler ergonomics, and hardens the request-stringify, http2 back-pressure, and JWT/auth paths.

### Added

- Concept-driven routing verbs. Each verb (`get/post/put/del/patch/options/head`) on the router,
  route group, and controller now resolves through a single template constrained by
  `RouteHandlerLike` (in `src/qbm/http/routing/coro_task.h`) plus a member-function overload:
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
- `StaticFilesOptions::root_directory` is now `std::filesystem::path` and is resolved through
  `qb::io::sys::resolve_resource` when the middleware is constructed: a relative root is anchored
  against the cwd first then the executable's own directory, so a static-file server serves its
  bundled assets from **any** working directory (absolute roots unchanged).
- `http::listen` takes `std::filesystem::path cert_file` / `key_file` (HTTP/1.1 with `{}` defaults,
  HTTP/2 and HTTP/3) instead of `std::string`, matching the framework's filesystem-path policy.

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

[Unreleased]: https://github.com/isndev/qbm-http/compare/v3.2.1...HEAD
[3.2.1]: https://github.com/isndev/qbm-http/compare/v3.2.0...v3.2.1
[3.2.0]: https://github.com/isndev/qbm-http/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/isndev/qbm-http/compare/v3.0.1...v3.1.0
[3.0.1]: https://github.com/isndev/qbm-http/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/isndev/qbm-http/compare/v2.6.0...v3.0.0
[2.6.0]: https://github.com/isndev/qbm-http/releases/tag/v2.6.0

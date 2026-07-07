# The request context

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 2.6.0 (C++20 default, C++23 supported)

`qb::http::Context<Session>` is the per-request object the router hands to every middleware and handler: it carries the request and response, the matched path parameters, a typed scratchpad shared across the chain, and the `complete()` / `cancel()` state machine that drives the request to a sent response.

**Prerequisites:** [Routing overview](./03-routing-overview.md) · [Core HTTP concepts](./01-core-concepts.md) — **See also:** [Middleware](./07-middleware.md) · [Custom middleware](./09-custom-middleware.md) · [Error handling](./13-error-handling.md)

## What this page covers

When the router matches a request, it builds one `Context<Session>` and runs the route's task chain on it: zero or more middleware, then the route handler, all sharing that single object. This page covers what the context carries, how it lives across the chain, how you complete or cancel it, and the lifecycle hooks that let cross-cutting code observe the stages of a request.

Everything here is in the `qb::http` namespace and reachable through the umbrella header:

```cpp
#include <http/http.h>   // pulls in qb::http::Context, Slot, HookPoint, AsyncTaskResult
```

`Session` is your server's per-connection session type (for the bundled servers, `qb::http::DefaultSession` or `qb::http::ssl::DefaultSecureSession`). You almost never spell `Context<Session>` out in full; handlers and middleware receive a `std::shared_ptr<Context<Session>>` and you write the session type once at the server declaration.

<!-- src: qbm/http/routing/context.h:68-108, routing/types.h:38-59, routing/slot.h:78-98 -->

## Concepts

### One context, always a shared pointer

`Context` derives from `std::enable_shared_from_this` and is **always owned and passed as `std::shared_ptr<Context<Session>>`**. The router creates exactly one per request and threads the same pointer through the whole chain, so anything a middleware writes onto the context is visible to every task downstream and to the handler. The shared pointer is also what makes asynchronous handlers safe: capture `ctx` in your async callback and the context stays alive until you call `complete()`.

```cpp
// A route handler. The session type is fixed at the server; here it is MySession.
router.get("/users/:id", [](std::shared_ptr<qb::http::Context<MySession>> ctx) {
    ctx->json(qb::json{{"id", ctx->path_param("id")}});   // see "Completing a response"
});
```

<!-- src: qbm/http/routing/context.h:68, 508 -->

### The session is held weakly

The context holds the session by `std::weak_ptr`, not a strong reference — this breaks the ownership cycle between the session (which owns the in-flight context) and the context (which needs to reach the session to send). The consequence for your code: `session()` returns `std::shared_ptr<Session>` that **may be `nullptr` if the client has already disconnected**. Null-check before you touch it.

```cpp
if (auto s = ctx->session()) {
    // safe to use s
}
```

In normal request handling you rarely call `session()` directly — completing the context sends the response for you. You reach for it only in advanced flows (streaming, server-sent events, protocol upgrades) where you drive the transport by hand.

<!-- src: qbm/http/routing/context.h:113-114, 472-484 -->

### Tasks are shared; per-request state lives on the context

After `router.compile()`, the task objects in a chain (`IAsyncTask`, middleware, handlers) are **immutable and shared** across concurrent requests — HTTP/1.1 pipelining and HTTP/2 multiplexing run many requests against the same task instances on one listener. Never store per-request state on a task. All per-request bookkeeping — the current-task cursor, the in-flight flag, cancellation, your custom data — lives on the `Context`, which is the one object that is unique per request.

<!-- src: qbm/http/routing/async_task.h:34-41 -->

## What the context carries

### Request and response

`request()` and `response()` return mutable references. Middleware reads and rewrites the request on the way in; handlers and middleware build up the response. Both have const overloads.

| Accessor | Returns | Notes |
| --- | --- | --- |
| `request()` | `Request&` / `const Request&` | the inbound request; mutable so middleware can rewrite headers/body |
| `response()` | `Response&` / `const Response&` | the response under construction |
| `session()` | `std::shared_ptr<Session>` | weak-locked; **may be `nullptr`** (see above) |
| `path_parameters()` | `PathParameters&` | all extracted `:params` and `*wildcards` |
| `path_param(name)` | `const std::string&` | URL-decoded single parameter; static-empty string on miss |
| `path_param<T>(name)` | `std::optional<T>` | typed parse; `nullopt` on miss or parse error |
| `path_param_or<T>(name, fallback)` | `T` | typed parse, or `fallback` on miss/error |
| `query_param<T>(name)` | `std::optional<T>` | typed query-string value (`T` defaults to `std::string`); `nullopt` on absent/empty/parse-fail |
| `query_param_or<T>(name, fallback)` | `T` | typed query-string value, or `fallback` on absent/empty/parse-fail |
| `bind<T>()` | `std::optional<T>` | no-throw body deserializer; `nullopt` on failure (see below) |

<!-- src: qbm/http/routing/context.h:472-617 -->

### Path parameters

`path_parameters()` exposes the values the radix tree extracted from the matched pattern; `path_param(name)` is the convenience accessor for one of them.

```cpp
router.get("/orders/:order_id/items/:item_id", [](auto ctx) {
    const std::string& order = ctx->path_param("order_id");
    std::string item  = ctx->path_param_or<std::string>("item_id", "unknown");   // fallback if absent
    // ...
    ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
});
```

`PathParameters::get(name)` returns `std::optional<std::string_view>` (a view of the owned value string) if you want to distinguish "absent" from "empty". Note the lifetime contract: parameter **values are owned strings**, but parameter **keys are `string_view` into the route pattern** stored by the router. The router outlives every context, so this is safe by construction — but do not stash a parameter key `string_view` somewhere that outlives the router.

<!-- src: qbm/http/routing/path_parameters.h:32-43, 79; context.h:488-510 -->

### Query parameters and body binding

The context also offers typed accessors over the query string and the request body, mirroring the typed `path_param<T>` accessors.

`query_param<T>(name)` parses one query-string value into `T` (which defaults to `std::string`) and returns `std::optional<T>` — `std::nullopt` when the parameter is **absent, empty, or fails to parse**. `query_param_or<T>(name, fallback)` returns the parsed value or the supplied `fallback` for those same cases.

```cpp
router.get("/search", [](auto ctx) {
    auto q    = ctx->query_param("q");                       // std::optional<std::string>
    int  page = ctx->query_param_or<int>("page", 1);          // typed, with a default
    // ...
    ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
});
```

`bind<T>()` deserializes the request body into `T` without throwing, returning `std::optional<T>` (`std::nullopt` on any parse/convert failure). `bind<qb::json>()` parses JSON, `bind<std::string>()` returns the raw body, and any other `T` is parsed as JSON then converted via `qb::json::get<T>()` — for example a `NLOHMANN_DEFINE_TYPE` model. (`bind<std::string_view>()` is a compile error, because the view would dangle into a temporary `qb::json`.)

```cpp
auto dto = ctx->bind<CreateTask>();        // std::optional<CreateTask>
if (!dto) { ctx->bad_request("invalid body"); return; }
use(*dto);
```

<!-- src: qbm/http/routing/context.h:571-617 -->

### Per-request custom data

The context is also a typed scratchpad for passing values down the chain — an authenticated user from an auth middleware, a decoded JWT payload, a parsed DTO, a trace id. Storage is a `qb::unordered_map<std::string, std::any>` (`CustomDataMap`), and there are two interchangeable APIs over it.

**Typed slots (recommended).** A `qb::http::Slot<T>` binds a compile-time name to the value type stored under it. Declare a slot once — usually an `inline constexpr` global in a header shared by the producer middleware and the consumer handler — and the type is checked at every call site.

```cpp
// shared_slots.h
struct AuthUser { std::string id; std::string email; };
inline constexpr qb::http::Slot<AuthUser>    kAuthUser{"auth.user"};
inline constexpr qb::http::Slot<std::string> kTraceId{"trace.id"};

// producer (middleware)
ctx->set(kAuthUser, std::move(user));                 // type-checked: storing the wrong T is a compile error
ctx->emplace(kAuthUser, "u-1", "alice@example.com");  // in-place construction, no move

// consumer (handler)
if (const auto* user = ctx->get_if(kAuthUser)) {      // T* or nullptr, no copy
    ctx->response().body() = user->email;
}
std::string tid = ctx->get_or(kTraceId, std::string{"<none>"});
if (ctx->contains(kAuthUser)) { /* ... */ }
ctx->remove(kAuthUser);
```

| Slot method | Signature | Behavior |
| --- | --- | --- |
| `set(slot, value)` | `void set(const Slot<T>&, T)` | store (moves into the `std::any`); wrong `T` is a compile error |
| `emplace(slot, args...)` | `T& emplace(const Slot<T>&, Args&&...)` | construct in place, return a reference |
| `get(slot)` | `std::optional<T>` | copy out if present |
| `get_if(slot)` | `T*` / `const T*` (`noexcept`) | pointer or `nullptr`; the hot-path read |
| `get_or(slot, fallback)` | `T` | value or `fallback` |
| `contains(slot)` | `bool` (`noexcept`) | key presence (does not re-check type) |
| `remove(slot)` | `bool` | erase; `true` if something was removed |

**String-keyed API.** Use when the key is computed at runtime, or to interoperate with code that predates slots. The two APIs share the same underlying map, so `ctx->set(kAuthUser, x)` and `ctx->set<AuthUser>("auth.user", x)` are strictly equivalent and round-trip across each other.

```cpp
ctx->set<std::string>("request.id", make_uuid());
if (auto id = ctx->get<std::string>("request.id")) {           // std::optional<std::string>
    ctx->response().set_header("X-Request-Id", *id);
}
const std::string* raw = ctx->get_if<std::string>("request.id");  // T* or nullptr
bool present = ctx->has("request.id");                             // contains() is an alias
ctx->remove("request.id");
```

Why prefer slots: `ctx->set<int>("k", 1)` written one place and `ctx->get<std::size_t>("k")` read another **compiles and silently returns `std::nullopt`** at runtime. A slot makes that a compile error, documents at the declaration what gets stored under the key and by whom, and keeps the same `any_cast` read cost. Both APIs swallow `std::bad_any_cast` and return `nullopt` / `nullptr` on a type mismatch — a wrong-type read fails silently rather than throwing, which is exactly the footgun slots remove.

<!-- src: qbm/http/routing/context.h:655-896; slot.h:56-104 -->

## Completing a response

Every middleware, route handler, `ICustomRoute::process()`, and `IAsyncTask::execute()` **must eventually call `ctx->complete(AsyncTaskResult)` on every code path**, including inside asynchronous callbacks. If you don't, the request hangs forever — the router is waiting for the signal that this task is done. (Functional middleware may instead call `next()`, which completes `CONTINUE` for you; see [Middleware](./07-middleware.md).)

```cpp
void complete(AsyncTaskResult result = AsyncTaskResult::COMPLETE);
```

`AsyncTaskResult` tells the router how to proceed:

| Result | Meaning | Effect |
| --- | --- | --- |
| `CONTINUE` | this task is done; run the next one | advances to the next task in the chain |
| `COMPLETE` | the response in `ctx->response()` is ready | finalizes; no further tasks run |
| `ERROR` | unrecoverable error in this task | switches to the configured error chain, or sets 500 and finalizes if none |
| `CANCELLED` | processing was cancelled | sets 503 and finalizes (normally reached via `cancel()`, not directly) |
| `FATAL_SPECIAL_HANDLER_ERROR` | a 404/error-chain handler itself failed | hardcoded 500, finalizes immediately, no error-chain re-entry |

`complete()` is **idempotent after finalization**: once the context is `Finalised` (or cancelled), further `complete()` calls are ignored — except `CANCELLED`, which is always honored. State only moves forward: `Ready → Running → Finalised`. This is what makes the late-arriving callback of an already-cancelled request harmless.

<!-- src: qbm/http/routing/context.h:1068-1148 -->

### Response helpers are terminal

The context exposes one-call helpers that set status, headers, and body and then finalize. **Each of these calls `complete(AsyncTaskResult::COMPLETE)` for you**, so set any custom headers or body *before* calling them — nothing you do after returns:

| Helper | Sets |
| --- | --- |
| `json(data, status=OK)` | `application/json; charset=utf-8` body |
| `text(data, status=OK, content_type="text/plain; charset=utf-8")` | plain-text body |
| `html(data, status=OK)` | `text/html; charset=utf-8` body |
| `redirect(url, status=FOUND)` | `Location` header + redirect status |
| `no_content()` | 204, clears body, drops `Content-Type`/`Content-Length` |
| `bad_request` / `unauthorized` / `forbidden` / `not_found` / `internal_server_error` | the matching 4xx/5xx + plain-text message |

```cpp
router.get("/health", [](auto ctx) {
    ctx->response().set_header("Cache-Control", "no-store");   // headers BEFORE the helper
    ctx->json(qb::json{{"status", "ok"}});                     // sets body + completes
});
```

The one **non-terminal, chainable** helper is `status()`: it sets the status code and returns `*this`, so you build the rest of the response yourself and call `complete()` (or another terminal helper) when ready.

```cpp
router.post("/items", [](auto ctx) {
    ctx->status(qb::http::status::CREATED);          // chainable, does NOT finalize
    ctx->response().set_header("Location", "/items/42");
    ctx->response().body() = "created";
    ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
});
```

Statuses are `qb::http::status` and JSON bodies are `qb::json` — see [Core HTTP concepts](./01-core-concepts.md).

<!-- src: qbm/http/routing/context.h:900-1046 -->

### Suppressing the response on ownership transfer

If you hand the request or response off to another subsystem — most commonly a **WebSocket upgrade**, where the connection stops being an HTTP request/response exchange — call `ctx->suppress_response()`. It marks the context finalized *without* invoking the send callback, so the destructor won't push a stale or moved-from HTTP response back over a transport you no longer own. After this, `is_completed()` is `true` and neither the finalization callback nor `POST_HANDLER_EXECUTION` hooks run.

<!-- src: qbm/http/routing/context.h:1250-1255 -->

## Cancellation

`cancel(reason)` stops a request in flight — for an application-level timeout, a precondition failure that should abort everything, or a deliberate teardown.

```cpp
void cancel(const std::string& reason = "Cancelled by application") noexcept;
```

It sets the sticky cancellation flag, records the reason, calls `cancel()` on the in-flight task (so it can release pending I/O), sets the response to **503 Service Unavailable**, and completes with `CANCELLED`. It is a no-op if the context is already cancelled or finalized. Query it with:

- `is_cancelled()` — `true` once `cancel()` has run (sticky; never clears).
- `cancellation_reason()` — `std::optional<std::string>` with the reason, if one was given.

The asymmetry to remember: a **handler or middleware** signals failure with `complete(AsyncTaskResult::ERROR)`; a task's own **`cancel()` override must not call `complete()`** — the context owns the cancellation-and-finalization sequence, and a second completion would double-finalize. For async work, check `is_cancelled()` in your completion callback before doing anything further; if it's set, clean up and return — the context is already finalizing.

```cpp
// A deferred continuation of the handler (defer = next loop turn; a bare callback(fn)
// would run inline here instead). For a timed wait use callback(fn, delay).
qb::io::async::defer([ctx]() {
    if (ctx->is_cancelled())
        return;                      // already finalized elsewhere; do NOT complete()
    ctx->json(load_result());        // terminal helper completes for us
});
```

<!-- src: qbm/http/routing/context.h:1151-1226; async_task.h:64-76 -->

## Lifecycle hooks

A `LifecycleHook` is `std::function<void(Context<Session>&, HookPoint)>` you register to observe a request without being a full task in the chain — for logging, metrics, tracing, or injecting final headers. Register one per request with `ctx->add_lifecycle_hook(fn)`, or register it router-wide with `Router::add_lifecycle_hook(fn)` (copied into every new context before routing begins).

`HookPoint` and where each one actually fires:

| HookPoint | Fired by | When |
| --- | --- | --- |
| `PRE_ROUTING` | `RouterCore` | before route matching — **only observable via `Router::add_lifecycle_hook`** (a context-local hook is added too late) |
| `PRE_HANDLER_EXECUTION` | `RouterCore` | after a route matches, just before its task chain starts |
| `POST_HANDLER_EXECUTION` | `Context` (during finalize) | after the chain's logical processing, before the send callback |
| `PRE_RESPONSE_SEND` | default finalize callback | immediately before the response is serialized and sent — ideal for final headers (`Date`, `Server`) or end-of-timing |
| `POST_RESPONSE_SEND` | session / IO layer | after the response bytes have progressed through the transport write path — the HTTP/2 session fires it when the stream's bytes have been written (not at enqueue); the HTTP/1 IO layer is responsible for firing it |
| `REQUEST_COMPLETE` | `Context` destructor | when the context is about to be destroyed — final logging, releasing request-scoped resources |

```cpp
ctx->add_lifecycle_hook([](qb::http::Context<MySession>& c, qb::http::HookPoint point) {
    if (point == qb::http::HookPoint::PRE_RESPONSE_SEND) {
        c.response().set_header("X-Served-By", "edge-1");
    }
});
```

Two contracts that matter:

- **Hook exceptions are caught and suppressed** — a throwing hook never aborts request processing.
- The Context destructor is `noexcept` and fires `REQUEST_COMPLETE` as a safety net. **A hook running from the destructor must not call `shared_from_this()`** — the control block is already in terminal release.

To observe `PRE_ROUTING` at all, you must use the router-level registration:

```cpp
// the ONLY way to see PRE_ROUTING; per-context hooks can only be added once handlers run
router.add_lifecycle_hook([](qb::http::Context<MySession>& c, qb::http::HookPoint point) {
    if (point == qb::http::HookPoint::PRE_ROUTING) { /* log raw request */ }
});
```

<!-- src: qbm/http/routing/context.h:196-204, 226, 426, 626-641; router_core.h:328, 418; router.tpp:20; 2/http2.h:300,324 -->

## Lifecycle in order

For a normal matched route, the context moves through these stages:

1. **Creation** — `RouterCore` builds the `Context` (state `Ready`).
2. `PRE_ROUTING` hooks run (router-level only).
3. **Route matching** — path + method against the compiled radix tree.
4. **Chain setup** — middleware + handler tasks are set on the context; path parameters are populated.
5. `PRE_HANDLER_EXECUTION` hooks run.
6. **Chain execution** — state becomes `Running`; each task calls `complete(...)`. `CONTINUE` advances; `COMPLETE` / `CANCELLED` / `ERROR` (when no error chain remains) drive finalization.
7. **Finalize** — state becomes `Finalised`; `POST_HANDLER_EXECUTION` hooks run, then the send callback fires.
8. `PRE_RESPONSE_SEND` hooks run inside the default send callback, then the response is serialized and sent.
9. `POST_RESPONSE_SEND` hooks run once the transport has written the bytes (session/IO layer).
10. **Destruction** — `REQUEST_COMPLETE` hooks run as the last `shared_ptr` drops.

When a route is not matched, or a task returns `ERROR`, the same machinery runs a different chain — `ProcessingPhase` records which one (`NORMAL_CHAIN`, `NOT_FOUND_CHAIN`, `METHOD_NOT_ALLOWED_CHAIN`, `ERROR_CHAIN`). See [Error handling](./13-error-handling.md) for how the error chain is wired.

<!-- src: qbm/http/routing/context.h:76-95, 196-226, 406-426; router_core.h:291-328, 418; router.tpp:17-32 -->

### Introspection (advanced)

These read-only queries exist mainly for instrumentation, coroutine adapters, and tests — the normal request path never needs them: `is_completed()`, `state()`, `get_processing_phase()`, `last_task_result()`, and `completion_count()` (how many times `complete()` has been called). `defer_finalization_scope()` returns an RAII guard that holds back finalization until it leaves scope; it is the mechanism behind synchronous post-`next()` mutation in functional middleware, and you should not need it directly.

<!-- src: qbm/http/routing/context.h:1221-1296, 385 -->

## Pitfalls

- **Forgetting `complete()`.** Every task must call `complete()` (or `next()` in functional middleware) on every path, including async callbacks and early returns. A missed call hangs the request until the connection times out.
- **Mutating the response after a terminal helper.** `json`/`text`/`html`/`redirect`/`no_content` and the error helpers all finalize. Set headers and body first; use the chainable `status()` if you need to keep building.
- **Calling `complete()` from a task's `cancel()` override.** The context drives cancellation itself; a second completion double-finalizes. Use `complete(ERROR)` for failures instead.
- **Assuming `session()` is non-null.** It is weak-locked and returns `nullptr` after a disconnect — null-check before sending or streaming by hand.
- **Storing per-request state on a task.** Tasks are shared across pipelined/multiplexed requests after `compile()`; per-request state belongs on the `Context`.
- **Silent type mismatches in custom data.** Reading a key with the wrong `T` returns `nullopt`/`nullptr`, not an error. Use `Slot<T>` so the mismatch is a compile error.
- **Expecting `PRE_ROUTING` from a per-context hook.** It fires before any handler runs, so only router-level hooks can observe it.
- **Forgetting `suppress_response()` on upgrade.** After a WebSocket upgrade (or any ownership transfer), suppress the response so the destructor doesn't send a stale one.

## See also

- [Routing overview](./03-routing-overview.md) — how the router builds and dispatches the chain that runs on the context.
- [Middleware](./07-middleware.md) and [Custom middleware](./09-custom-middleware.md) — the tasks that share the context, and the `next()` shorthand for `complete(CONTINUE)`.
- [Error handling](./13-error-handling.md) — the `ERROR` result, error chains, and `ProcessingPhase`.
- [Core HTTP concepts](./01-core-concepts.md) — the `Request`, `Response`, `status`, and `qb::json` types the context carries.
- [WebSocket](./20-websocket.md) — where `suppress_response()` and the upgrade path apply.

---

Previous: [Custom middleware](./09-custom-middleware.md) · Next: [Authentication system](./11-authentication.md) · Up: [Index](./README.md)

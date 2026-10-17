<!-- Verified-against: qbm-http @ qb 3.2.1. Source of truth: the headers under qbm/http/src/qbm/http/. -->
# qbm-http — concepts for writing correct code

> Audience: an LLM that must emit compiling, idiomatic qbm-http (qb actor framework, C++20-first; optional C++23). Every signature here is verified against the headers under `qbm/http/` and the FACTBOOK. When in doubt, the umbrella header `<qbm/http/http.h>` is your single include.

<!-- llms-txt:lead -->
> qbm-http is the HTTP stack of the qb Actor Framework (QBAF), C++20-first: asynchronous
> HTTP/1.1, HTTP/2, HTTP/3 and WebSocket servers and clients over qb-io's non-blocking,
> single-thread-per-listener I/O, plus a fluent router (path parameters, groups, controllers),
> a middleware pipeline, request validation and sanitization, cookies, multipart, JWT
> authentication, and both callback and C++20-coroutine client APIs. A **compiled** library — link `qbm::http` — behind
> one umbrella header, `<qbm/http/http.h>`.

Six rules decide whether generated qbm-http code is correct; everything else is detail.

1. **Feature gates are real `#ifdef` boundaries.** HTTP/1.1, routing, middleware, validation,
   cookies and multipart are always available. HTTPS, HTTP/2, WebSocket (`ws://` included),
   JWT and `qb::http::auth` need `QB_HAS_SSL`; HTTP/3 needs `QBM_HTTP_HAS_HTTP3`. Gate on
   those two, never on the private `QBM_HTTP_HAS_SSL`.
2. **`router().compile()` after every route is declared, before serving.** Routes added after
   compilation are not routed.
3. **Every task completes exactly once.** A handler, `IMiddleware::process`,
   `ICustomRoute::process` or async callback must call `ctx->complete(...)` on every path or
   the request hangs; functional middleware may call `next()` instead. A `cancel()` override
   must never call `ctx->complete()`. Capture `ctx` (a `shared_ptr`) into async callbacks,
   complete from the callback, and guard on `ctx->is_cancelled()`.
4. **Handlers and middleware are shared across concurrent requests.** Never store per-request
   state on them — put it in the `Context` via `Slot<T>`. `ctx->session()` is weak-locked and
   may be `nullptr` after a disconnect. A routed context retains its compiled parameter names
   even after the router is destroyed; standalone parameter-key views remain borrowed.
5. **DELETE is `qb::http::method::DEL`** (`router().del(...)`); `method::DELETE` does not
   exist. `Body` and `Headers` are base classes, so it is `req.set_header(...)` and
   `req.body()`, not `req.headers().set(...)`.
6. **Time is `std::chrono`.** Cookie `max_age`, CORS preflight, rate-limit windows and every
   client or protocol timeout are `qb::duration` (`qb::duration::zero()` means *no* timeout,
   not an immediate one); JWT `token_expiration` / `leeway` / `clock_skew_tolerance` are
   `std::chrono::seconds` by RFC 7519. Never emit `qb::Timestamp`, `qb::Duration`,
   `qb::TimePoint`, `to_timestamp(` or `to_time_point(`: they do not exist.
<!-- /llms-txt:lead -->

## Purpose

`qbm-http` gives a qb actor asynchronous HTTP servers and clients over qb-io's non-blocking, single-thread-per-listener I/O: **HTTP/1.1 always**, plus **HTTP/2, HTTP/3, WebSocket, JWT, and authentication on builds that enable SSL/QUIC**. It ships a fluent routing engine (path params, groups, controllers), a middleware pipeline, request validation/sanitization, cookies/multipart, and both callback and C++20-coroutine client APIs. WebSocket is part of this module (`qb::http::ws`, under `qbm/http/src/qbm/http/ws/`); there is no separate ws module.

## Mental model

- **It is a compiled library, not header-only.** The CMake build registers it with `qb_register_module` + a `SOURCES` list (`request.cpp`, `response.cpp`, `body.cpp`, the HTTP/1.1 protocol/client, the validation engine, and SSL-gated `auth/`, `ws/`, `2/` sources). You must link `qbm::http`; including headers alone will not resolve symbols.
- **One umbrella header.** `#include <qbm/http/http.h>` pulls in `Request`, `Response`, `Headers`, `Body`, `Method`, `Status`, `Router`, `Context`, the validation surface, and — under the right gates — HTTP/2 and WebSocket. Focused headers: `<qbm/http/auth.h>`, `<qbm/http/validation.h>`, `<qbm/http/ws.h>`, `<qbm/http/middleware/all.h>`.
- **The message model is protocol-agnostic.** `Request`/`Response` derive from `internal::MessageBase`, which multiply-inherits `Headers` (case-insensitive, multi-value) and `Body` (backed by `qb::allocator::pipe<char>`). The same objects flow through HTTP/1.1, HTTP/2, and HTTP/3 unchanged; only the wire framing differs. `MessageBase::stream_id` carries the multiplexed stream id (0 for HTTP/1.1).
- **A server is an actor that mixes in a server base.** `qb::http::Server<>` (default session `qb::http::DefaultSession`) gives you `router()`, `listen(...)`, `start()`. You define routes on `router()`, call `router().compile()`, then `listen` + `start`. Handlers receive a `std::shared_ptr<qb::http::Context<Session>>` (`ctx`), read `ctx->request()`, write `ctx->response()`, and call `ctx->complete()`.
- **Routing → context → task chain.** The session parses bytes into a `Request`, the `Router` matches it (radix tree), builds one `Context<Session>` per request, and runs a compiled chain (middleware…, then handler) against it. Each task drives the chain by calling `ctx->complete(AsyncTaskResult)`.
- **Compile gates are real `#ifdef` boundaries that propagate `PUBLIC` to your target.** `QB_HAS_SSL` ⇒ HTTPS, HTTP/2, WebSocket (even `ws://`), JWT, `qb::http::auth`. `QBM_HTTP_HAS_HTTP3` (needs `QB_HAS_SSL` + `QB_HAS_QUIC` + libnghttp3) ⇒ HTTP/3. Gate your own optional code on these exact macros (never on the private `QBM_HTTP_HAS_SSL`).
- **Single-thread-per-listener.** No internal threads for HTTP logic. Never block in a handler/middleware; use `qb::io::async::callback`, actor messages, or the async client. Fan CPU/business work out through actors and post the response back to the owning listener.

## Namespaces

`qb::http` (core + router + context + helpers + `Server`/`make_server`), `qb::http::auth`, `qb::http::validation`, `qb::http::ws`, `qb::http1` (persistent HTTP/1.1 client + `make_client`), `qb::http2` (HTTP/2 server/client), `qb::http3` (HTTP/3), `qb::http::async` (one-shot client types: `Reply`, `awaiter`), `qb::protocol::http*` / `qb::protocol::hpack` (protocol internals — rarely touched).

---

## HTTP/1.1 server

```cpp
#include <qbm/http/http.h>
#include <qb/main.h>

class ApiServer : public qb::Actor, public qb::http::Server<> {   // default session = DefaultSession
public:
    qb::io::async::task<bool> onInit() override {
        router().get("/", [](auto ctx) {
            ctx->response().body() = "Hello from qbm-http";
            ctx->complete();                         // sends the response
        });
        router().get("/users/:id", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "user " + ctx->path_param("id");
            ctx->complete();
        });
        router().compile();                          // REQUIRED before serving
        if (listen({"tcp://0.0.0.0:8080"})) { start(); co_return true; }
        co_return false;
    }
};

int main() {
    qb::Main engine;
    engine.addActor<ApiServer>(0);
    engine.start();   // launches one worker thread per used core, then returns
    engine.join();    // blocks until every actor terminates
}
```

Standalone (no actor) variant uses the factory: `auto s = qb::http::make_server();` (returns `std::unique_ptr<qb::http::Server<DefaultSession>>`), then `s->router()...`, `s->router().compile()`, `s->listen(qb::io::uri("http://0.0.0.0:8080"))`, `s->start()`, and drive `qb::io::async::run()`.

## Message types

```cpp
qb::http::Request req{qb::http::method::POST, qb::io::uri("/submit?type=test")};
req.set_header("User-Agent", "qb-client/2.0");        // replaces all values
req.add_header("Accept-Encoding", "gzip");             // appends (multi-value)
req.set_content_type("application/json");
req.body() = R"({"key":"value"})";

const std::string &ua = req.header("user-agent");      // case-insensitive; ref to default if absent (never throws)
const std::string &q  = req.query("type");             // query param, "" if absent
req.parse_cookie_header();                              // request cookies are NOT parsed automatically
const qb::http::Cookie *c = req.cookie("name1");       // nullptr if absent

qb::http::Response res;                                 // defaults to 200 OK
res.status() = qb::http::status::CREATED;
res.set_content_type("application/json; charset=utf-8");
res.body() = qb::json{{"message", "ok"}};               // qb::json serializes into the buffer
res.add_cookie("session", "abc123");                    // jar + matching Set-Cookie header, in sync
int code = res.status().code();                         // 200..., st.str() -> "OK"
```

- `Body`/`Headers` are **base classes, not members**: call `req.set_header(...)` / `req.body()` directly. `headers()` returns the raw map for bulk inspection; after direct mutation call `refresh_content_type()` (the typed `content_type()` is derived from the raw header on the next read, and only when read).
- Body extraction is closed: only `std::string`, `std::string_view`, `qb::json`, `Multipart`, `Form` convert out; anything else is a compile error. Two accessors share that set — `as<T>()` **throws** on malformed input, `try_as<T>()` returns `std::optional<T>` and is `noexcept`. **Use `try_as<T>()` for anything a client sent you**, so a bad payload becomes a `nullopt` you turn into a 400 instead of an exception crossing your handler. Append/constructor accepts `Body`, `Chunk`, `Multipart`, `qb::json`, `std::string`, `std::string_view`, `std::vector<char>`, arithmetic values, built-in `char[N]` arrays, and `char*`/`const char*`; assignment has explicit support for `std::string`, `std::vector<char>`, `qb::json`, `Multipart`, `Form`, `std::string_view`, and `const char*`. `Form` is assignment-only; arithmetic is append-only.
- **DELETE is `qb::http::method::DEL`** (`delete` is a keyword); `method::DELETE_METHOD` is an alias. Default `Method` is `UNINITIALIZED`; `Request{uri}` defaults to `GET`.
- **Trailers are a section of their own: `msg.trailers()`** (a `Headers`; QB-1073), on HTTP/1.1 (chunked), HTTP/2 and HTTP/3 alike. **Received** trailer fields are in `trailers()` **and also** in the header fields, after the header-section values of the same name -- kept for 3.x source compatibility; read `trailers()` to tell a trailer field from a header field and never trust one as the other (RFC 9110 §6.5.1). **To send** trailers: `res.trailers().set_header("grpc-status", "0");` -- the protocol announces them (a `trailer` header, when the message has none) and sends them after the body; HTTP/1.1 only for a `Transfer-Encoding: chunked` message (Content-Length framing and `MessageHead` send none). A field that frames, routes, manages the connection or authenticates to a proxy (`qb::http::detail::is_forbidden_trailer_field`, one list for the three protocols) refuses the message. The non-const `trailers()` allocates the section: read with `has_trailers()` or a const message.

## Routing

```cpp
router().get   ("/users",        h);   // also post, put, del (DELETE), patch, options, head
router().add_route("/x", qb::http::method::GET, h);          // computed verb
router().get<MyCustomRoute>("/users/:id", ctor_args...);     // construct ICustomRoute in place

// Path patterns: static "users", parameter ":id" (one segment), wildcard "*rest" (must be last).
router().get("/files/*path", [](auto ctx) {
    ctx->text("serving " + ctx->path_param("path"));   // "docs/a.pdf" for /files/docs/a.pdf
});
```

- Handler type: `RouteHandlerFn<S> = std::function<void(std::shared_ptr<Context<S>>)>`. No return value; signal outcome via `ctx->complete(...)`.
- `ctx->path_param("name")` returns the decoded value by `const std::string&` (static-empty string on miss, never throws); use `ctx->path_param_or<std::string>("name", "fallback")` for a fallback. Query string is **not** a path param — use `ctx->request().query("q")`.
- **Typed accessors (no exceptions, no `std::stoi`):**
  - `ctx->path_param<int>("id")` → `std::optional<int>` (integral/floating via `std::from_chars`, `bool` from `true/false/1/0`, `std::string`/`string_view` pass through). `nullopt` on absence or parse error. `ctx->path_param_or<int>("id", -1)` for a fallback.
  - `ctx->query_param<int>("page")` / `query_param_or<int>("page", 1)` — same for query strings.
  - `ctx->bind<T>()` → `std::optional<T>`: `bind<qb::json>()` parses JSON, `bind<std::string>()` is the raw body, any other `T` is JSON→`get<T>()` (e.g. a `NLOHMANN_DEFINE_TYPE` model). `nullopt` on any parse/convert failure — no try/catch needed.
  ```cpp
  router().get("/lots/:id", [this](auto ctx) -> qb::io::async::task<void> {
      auto id = ctx->path_param<int>("id");
      if (!id) { ctx->bad_request("bad id"); co_return; }
      auto dto = ctx->bind<CreateLot>();           // POST body → model
      if (!dto) { ctx->bad_request("bad body"); co_return; }
      ctx->json(co_await fetch(*id));
  });
  ```
- Precedence: static > parameter > wildcard. A wildcard not last, an empty segment, or a duplicate capture name throws `std::invalid_argument` from `compile()`.
- **`router().compile()` is mandatory** after all routes/groups/controllers/middleware are declared and before serving (auto-compile on first match is a safety net, not a substitute). Router-facade mutations reset the compiled flag; direct mutations through retained group/controller handles do not, so recompile explicitly.
- Class-based handler: implement `qb::http::ICustomRoute<S>` — `process(ctx)` (must `complete()`), `name()`, `cancel()` (must NOT `complete()`). Handler/task instances are **shared across concurrent requests**; keep per-request state on the `Context`, never on the task.

Groups and controllers share the same verb API:

```cpp
auto api = router().group("/api");          // path prefix + scoped middleware
api->use<RequireApiKey<MySession>>();
api->get("/users", h);                      // effective path /api/users
```

## Coroutine routes (server-side)

A coroutine handler is registered **directly** — the verb methods auto-detect a
`task<void>` return via the `CoroRouteHandler` concept and wrap it automatically.
No explicit wrapper, no repeated session type. Same three forms on `router()`, any `group()`, and `Controller`:

```cpp
// 1. coroutine lambda — co_await DB / Redis / HTTP, then write the response
router().get("/lots", [this](auto ctx) -> qb::io::async::task<void> {
    auto r = co_await _db->execute("select_lots", {});
    ctx->json(build(r));                      // auto-completes on co_return
});

// 2. member function (sync OR coroutine) — no binding lambda, no wrapper
router().get("/lots", this, &MyActor::handle_lots);   // task<void> handle_lots(ctx)
router().post("/lots/:id/bids", this, &MyActor::place_bid);

// 3. coroutine middleware (auto-wrapped; default outcome = CONTINUE)
router().use([](auto ctx) -> qb::io::async::task<void> { co_await gate(ctx); });
```

- Inside a `Controller::initialize_routes()`: `get("/:id", this, &MyController::get_user)`
  (the bound member may be sync or coroutine — the router auto-detects via concept).
- Sync lambdas (`[](auto ctx){ ... }`) keep working unchanged (they already convert to
  `RouteHandlerFn`). Coroutine handlers default to `COMPLETE`, coroutine middleware to
  `CONTINUE`, unless the body already called `ctx->complete(...)`. Exceptions → `500`.

## Async route

```cpp
router().get("/slow", [](auto ctx) {
    qb::io::async::callback([ctx]() {        // ctx is a shared_ptr -> keeps context alive
        if (ctx->is_cancelled()) return;     // already finalized elsewhere; do NOT complete
        ctx->text("done");                   // terminal helper completes here, off the call stack
    }, std::chrono::milliseconds(250));   // qb::io::async::callback takes a std::chrono::duration, never a bare double
    // handler returns now; request stays open until the callback completes it
});
```

## Context

```cpp
ctx->request(); ctx->response();             // mutable refs
ctx->session();                              // std::shared_ptr<Session>, MAY be nullptr after disconnect
ctx->path_param("id"); ctx->path_parameters();

// Typed per-request scratchpad (preferred over string keys):
inline constexpr qb::http::Slot<AuthUser> kUser{"auth.user"};
ctx->set(kUser, std::move(user));            // wrong T is a compile error
if (const auto* u = ctx->get_if(kUser)) { /* T* or nullptr, hot path */ }
// String-keyed equivalent (shares the same map): ctx->set<T>("k", v); ctx->get<T>("k") -> std::optional<T>

ctx->complete(qb::http::AsyncTaskResult::COMPLETE);  // COMPLETE is the default arg
ctx->cancel("reason");                       // sets 503, finalizes; is_cancelled() sticky
```

Terminal response helpers (each sets body/status/content-type **and** calls `complete()` — set custom headers/body first): `ctx->json(data, status=OK)`, `ctx->text(...)`, `ctx->html(...)`, `ctx->no_content()` (204), `ctx->redirect(url, status=FOUND)`, `ctx->bad_request/unauthorized/forbidden/not_found/internal_server_error(...)`. The one non-terminal helper is `ctx->status(code)` (chainable, does not finalize).

Lifecycle hooks: `ctx->add_lifecycle_hook(fn)` or router-wide `router().add_lifecycle_hook(fn)`. `HookPoint`s: `PRE_ROUTING` (router-level only), `PRE_HANDLER_EXECUTION`, `POST_HANDLER_EXECUTION`, `PRE_RESPONSE_SEND` (best place for final headers), `POST_RESPONSE_SEND`, `REQUEST_COMPLETE`. Hook exceptions are caught and suppressed; a destructor-time hook must not call `shared_from_this()`.

Hooks registered during dispatch are published after the outermost dispatch returns. The current dispatch and nested dispatches retain the old published list; the next separate phase sees additions in registration order. Active callable state is preserved, and registration affects only this context. _(src/qbm/http/routing/context.h:219-245,694-707)_

Router-extracted parameter values are owned; their key views are backed by compiled storage retained through the context's existing `IAsyncTask` chain. A retained context may outlive its router or session, including `REQUEST_COMPLETE`; `session()` remains weak and may return null. A 405 or error-chain transition retains the matching compilation's names. A standalone `PathParameters` copy still borrows keys: retain the original context or copy names into owned strings. _(src/qbm/http/routing/path_parameters.h:32-57; src/qbm/http/routing/async_task.h:92-115; src/qbm/http/routing/router_core.h:84-90,419-428)_

Conditional middleware records the selected pending child on the context; cancellation notifies that child once, including a nested leaf. A predicate that completes/cancels or a child that throws after synchronous completion cannot replace newer work. The unchanged `IMiddleware::cancel()` has no context argument: do not promise per-operation native cancellation inside a shared user child. _(src/qbm/http/middleware/conditional.h:87-111; src/qbm/http/routing/context.h:1268-1300; src/qbm/http/routing/middleware.h:58-61)_

Context and HTTP session templates contain updated private lifecycle bookkeeping. Rebuild consumers that share the same specializations with consistent headers; public signatures do not imply that mixed template definitions have compatible layout.

## Middleware

```cpp
// Functional (ctx, next) — call next() to continue, or complete(COMPLETE) to short-circuit:
router().use([](std::shared_ptr<qb::http::Context<MySession>> ctx, std::function<void()> next) {
    ctx->set<qb::wall_time>("start", qb::wall_now());
    next();                                   // wrapper translates this to complete(CONTINUE)
}, "RequestTimer");

// Object middleware: implement qb::http::IMiddleware<S>
class HeaderGuard : public qb::http::IMiddleware<MySession> {
public:
    std::string name() const override { return "HeaderGuard"; }
    void cancel() override {}                  // release I/O only; never complete() here
    void process(std::shared_ptr<qb::http::Context<MySession>> ctx) override {
        if (!ctx->request().has_header("X-Api-Key")) {
            ctx->response().status() = qb::http::status::UNAUTHORIZED;
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);   // short-circuit; no later task runs
            return;
        }
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);       // next task
    }
};
router().use(std::make_shared<HeaderGuard>());
router().use<HeaderGuard>();                  // in-place construction, forwards ctor args
```

- `AsyncTaskResult`: `CONTINUE` (next task), `COMPLETE` (final response, stop chain), `ERROR` (run error chain), `CANCELLED`, `FATAL_SPECIAL_HANDLER_ERROR`.
- Chain order per route: global → outer group → inner group → controller → handler (parent before child, declaration order within a level).
- Adapters wrap `process()` in try/catch: an uncaught exception becomes a 500 + `ERROR` (so prefer not to throw deliberately — call `complete(ERROR)` with a set status instead).
- Async middleware: capture `ctx` (shared_ptr), call `complete()` exactly once, guard `ctx->is_cancelled()` in the callback.
- Global middleware **is** prepended to 404/405 chains, but **not** to the user-defined error chain (`Router::set_error_task_chain`) — add cross-cutting concerns there explicitly.
- Built-in middleware (`<qbm/http/middleware/all.h>`) factories: `qb::http::cors_middleware<S>(CorsOptions::permissive())`, `compression_middleware<S>(...)`, `security_headers_middleware<S>(...)`, `rate_limit_middleware<S>(...)`, static files (`StaticFilesMiddleware`), plus the auth/validation/jwt factories below. There is also `qb::http::conditional_middleware<S>(predicate, if_mw[, else_mw])`. `SecurityHeadersMiddleware` sends HSTS by the connection (the session transport's `is_secure()` for HTTP/1.1 and HTTP/2), never by the request URI's scheme.
- **Static files serve from any cwd.** `StaticFilesOptions`'s `root_directory` is a `std::filesystem::path` (string literals convert implicitly); a **relative** root is resolved by the middleware ctor via `qb::io::sys::resolve_resource` (cwd first, then the executable's own directory), so `static_files_middleware<S>(StaticFilesOptions{"public"})` finds assets bundled next to the binary regardless of where the process is launched. Absolute roots are used unchanged; the resolved root must exist or the ctor throws.

## Authentication & JWT (needs `QB_HAS_SSL`)

```cpp
#include <qbm/http/auth.h>
#include <qbm/http/middleware/auth.h>
#include <chrono>

qb::http::auth::Options opts;
opts.secret_key("a-strong-32-byte-minimum-hmac-secret")
    .algorithm(qb::http::auth::Options::Algorithm::HMAC_SHA256)
    .token_expiration(std::chrono::hours(1))      // std::chrono::seconds (RFC NumericDate) — NOT qb::duration
    .token_issuer("my-api")                        // non-empty auto-enables iss verification
    .clock_skew_tolerance(std::chrono::seconds(30));

const qb::http::auth::Manager manager(opts);       // const: safe to share on the request path
qb::http::auth::User alice; alice.id = "u-101"; alice.username = "alice"; alice.roles = {"editor"};
std::string token = manager.generate_token(alice);
std::string raw   = manager.extract_token_from_header("Bearer " + token);   // "" on format mismatch
if (auto user = manager.verify_token(raw)) { /* user->id, user->has_role("editor") */ }
// verify_token NEVER throws; returns std::nullopt on any failure. Algorithm/key come from Options, not the token header.

using MySession = qb::http::DefaultSession;
auto gate = qb::http::auth_middleware<MySession>(opts);
gate->with_auth_required(true).with_user_context_key("user").with_roles({"administrator"});
router().use(gate);
router().get("/admin", [](auto ctx) {
    auto u = ctx->template get<qb::http::auth::User>("user");   // std::optional<User>
    ctx->json(qb::json{{"hello", u->username}});
});
```

Auth factories (`<S>`-templated): `auth_middleware`, `jwt_auth_middleware(secret, algo="HS256")`, `role_auth_middleware(roles, require_all=false)`, `optional_auth_middleware`. `JwtMiddleware` (`<qbm/http/middleware/jwt.h>`) stores the raw payload as `qb::json` under `"jwt_payload"` (no `User`); claims that read as JSON booleans/numbers are coerced there, but `iss`/`sub`/`aud`/`jti`/`username` stay the signed strings, and `auth::Manager::verify_token` rebuilds the `User` from the token's own JSON payload, so a textual id such as `"123"` survives both; `JwtOptions::leeway` is `std::chrono::seconds`. Never ship `require_signature_verification(false)` or `verify_expiration(false)`.

## Validation (always available)

```cpp
#include <qbm/http/validation.h>
using namespace qb::http::validation;

auto rv = std::make_shared<RequestValidator>();
rv->for_body({                                     // JSON-Schema subset; throws if not a JSON object
    {"type", "object"},
    {"properties", {{"message", {{"type", "string"}, {"minLength", 1}}}}},
    {"required", {"message"}}
});
rv->for_query_param("id", ParameterRuleSet("id").set_type(DataType::INTEGER).set_required());
rv->add_header_sanitizer("X-Custom-Input", PredefinedSanitizers::trim());
rv->set_error_value_policy(Result::ErrorValuePolicy::Preview, 256);

router().use(qb::http::validation_middleware<qb::http::DefaultSession>(rv));  // 400 + JSON error list on failure
```

- `validate()` **mutates the request** (sanitizers rewrite query/header values in place; a sanitized body is re-serialized). Capture raw input before validating if you need it.
- A changed `Content-Type` sanitizer result refreshes `request.content_type()`; error-value policy reaches both body schema and parameters regardless of whether it is set before or after `for_body`.
- A parameter `CustomRule` returning `false` without adding an error still rejects the request with a generic error named for that rule. Report the value it received with `result.add_error(path, rule, message, value)`: the `qb::json` overload takes that `const qb::json&` under nlohmann 3.11 and 3.12 alike (QB-1008). `Preview` trims to a complete UTF-8 prefix within its byte limit.
- String length rules count Unicode code points, not UTF-8 bytes; malformed programmatic strings fail without echoing their invalid bytes. JSON numeric limits and `enum`/`uniqueItems` preserve exact 64-bit integer distinctions, including inside arrays and objects. Numeric `exclusiveMinimum`/`exclusiveMaximum` are independent bounds; the prior boolean form beside `minimum`/`maximum` remains an extension for existing schemas.
- Cached schema numeric rules own a typed scalar bound selected when the rule is compiled. Standalone numeric rules retain their JSON storage. Both paths report a non-finite programmatic bound before the nonnumeric-value pass-through and share exact comparison and diagnostic logic.
- A schema node with valid `minLength` and `maxLength` shares one Unicode count in its cached evaluation. It still reports both keyword errors in order; standalone and parameter rules retain their own evaluation.
- Most primitive rules are type-gated and pass silently for the wrong kind — always assert `type` first.
- `SchemaValidator` caches compiled rules lazily and mutates a recursion-depth counter on every validation. Warm-up does not make it safe to share across cores; use one per core or serialize every call.

## HTTP/2 (needs `QB_HAS_SSL`, TLS-only, ALPN `h2`)

```cpp
#include <qbm/http/http.h>     // pulls <qbm/http/2/http2.h> under QB_HAS_SSL
qb::io::async::init();
auto server = qb::http2::make_server();            // std::unique_ptr<Server<DefaultSession>>
server->router().get("/hello", [](auto ctx) {
    ctx->response().body() = "Hello over HTTP/2";
    ctx->complete();                               // session sets the matching stream_id automatically
});
server->router().compile();
server->listen({"https://0.0.0.0:8443"}, "cert.pem", "key.pem");  // builds SSL_CTX, ALPN {"h2","http/1.1"}
server->start();
qb::io::async::run();
```

- Routing/middleware/controllers/validation are identical to HTTP/1.1 — the same `Router`.
- Client is `qb::http2::Client` via `qb::http2::make_client("https://...")` (returns `std::shared_ptr`; non-copyable/non-movable — always keep the shared_ptr). `push_request(req, cb)`, `push_requests(vec, batch_cb)`, or coroutine overloads. Callback `connect` has no zero-arg overload — use `connect(nullptr)` for fire-and-forget.
- An HTTP/2 batch callback may disconnect or enqueue another batch: the completed batch leaves the registry before user code runs. _(src/qbm/http/2/client.cpp:389-401)_
- A failed pending send calls user code. The queue drain retains the client and rechecks the connection and h2 protocol before its next iteration, so a callback may disconnect or enqueue work without sending on the old connection. _(src/qbm/http/2/client.cpp:479-525)_
- There is no plaintext h2c. Never write a response with `stream_id == 0` (it is the HTTP/1.1 sentinel). Server caps concurrency at 50 streams; client at 100. Server push is off by default and not a router feature.

- The stock server collects completed contexts with closed native streams on write progress and full-drain EOS. It selects batches of 32 IDs (128 bytes of stack ID scratch, no heap scratch), refinds and rechecks each ID, then detaches one owner before `POST_RESPONSE_SEND` and releases it before the next candidate. The last release runs `REQUEST_COMPLETE` and member destruction; external owners can postpone that destruction. Same-drain rescans catch silent eligibility changes from hooks or destruction, even with no hooks registered, within the removal budget fixed to the registry size at entry. No iterator or pointer to a native stream crosses user code. Selection is unordered, with no public stream-ID ordering contract. Reentry is suppressed; protocol, connection and output size are checked before each scan/candidate. Changed output size defers collection; first-POST extraction cancels the remaining contexts. EOS means framework output drain, not peer acknowledgment, and partial-write timing remains. The batching changes no public API or Session data members; no measured performance gain is claimed. _(src/qbm/http/2/http2.h:120-175,428-472)_
- Peer resets of unfinished routed streams cancel the stock context, including `NO_ERROR`, without turning a neutral reset into `Http2StreamErrorEvent`. The optional internal notification adds no required callback to custom protocol I/O. The private `on_peer_stream_reset` hook removes registry ownership before cancellation; late completion remains inert. _(src/qbm/http/2/protocol/server.h:793-814; src/qbm/http/2/http2.h:181-188,508-517)_
- Reconnection is a RUN with a backoff, not a loop: `client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_initial_delay(100ms).with_max_attempts(5))` (`qb::http::RetryPolicy`, the redis shape; `set_auto_reconnect(bool)` keeps the policy). A loss fails the outstanding work with a 503 and what the failure callbacks push back is what the run reconnects for — attempt 1 at once, then the policy's waits, `on_retry(attempt, next_delay)` before each; exhausted, the waiting requests get `503 Reconnection attempts exhausted (N)` and nothing reconnects until the next `connect()` or push. A push made from a failure callback queues behind the scheduled attempt: never `connect()` from one to "retry faster". `is_reconnecting()` / `reconnect_attempts()` are the observable state. _(src/qbm/http/2/client.h:472-497)_

## HTTPS / TLS (needs `QB_HAS_SSL`)

```cpp
auto server = qb::http::ssl::make_server();        // std::unique_ptr<ssl::Server<DefaultSecureSession>>
server->router().get("/secure-ping", [](auto ctx) { ctx->response().body() = "pong over TLS"; ctx->complete(); });
server->router().compile();
server->listen(qb::io::uri("https://0.0.0.0:8443"), "cert.pem", "key.pem");  // false if cert/key fails to load
server->start();
```

For mTLS/cipher policy, build the `SSL_CTX` yourself with `qb::io::ssl::create_server_context(TLS_server_method(), cert, key)`, configure via `qb::io::ssl::set_tls_protocol_versions/set_ciphersuites_tls13/configure_mtls_server_context`, then `server->transport().init(ctx)` (transport takes ownership — do not free it), `server->transport().set_supported_alpn_protocols({...})`, `server->transport().listen(uri)`. Client verification is secure by default (`verify_peer=true`); disable only for trusted/self-signed endpoints, and set it before connecting.

- **Cert/key (and CA/DH) paths are self-locating.** The HTTP/1.1 `listen(uri, cert, key)` here takes defaulted `std::filesystem::path cert={}, key={}`; the http2/http3/dual-stack `listen` overloads take `std::filesystem::path` cert/key too but WITHOUT defaults (both are required). `create_server_context` (and the CA/mTLS helpers) resolve a **relative** path via `qb::io::sys::resolve_resource` (`<qb/io/system/file.h>`): cwd first, then the executable's own directory — so certs shipped next to the binary load from any working directory; absolute paths are used unchanged. String literals convert implicitly, so `"cert.pem"` keeps working.

## HTTP/3 (needs `QBM_HTTP_HAS_HTTP3`)

An HTTP/3 GOAWAY callback may call `client->disconnect()`: inside the native read, the client becomes logically disconnected at once while protocol and QUIC teardown wait until that read returns. GOAWAY may still invoke other pending-request callbacks during the read; the remaining active requests fail after it. A reentrant `connect(callback)` fails without starting a handshake, new requests get an immediate `503`, and explicit disconnect starts no automatic reconnect. Ordinary disconnect also marks the client down before failure callbacks and rejects their reentrant connect or request attempts until close finishes. _(src/qbm/http/3/client.cpp:76-85,119-171,235-240,300-311,749-757,813-851)_

An HTTP/3 event callback can release the last external `shared_ptr`: the client is retained until endpoint dispatch unwinds. Explicit cancellation of an active request also retains the client through its callback and stream reset. The pending-request drain likewise retains the client and checks the connection, protocol and shutdown state before each submission, including after failed submit invokes user code. Failure to start QUIC, a connect timeout or a remote close retires the old transport and requests before connection callbacks can queue a new attempt; qb-io refreshes its internally owned native backend on retry. _(src/qbm/http/3/client.cpp:20-36,93-115,276-287,386-467,500-542,623-640,773-810,813-851,854-872; qb/src/qb/io/async/quic/endpoint.h:98-135,478-507)_

The connection timeout belongs to one attempt: `disconnect()` of an in-progress attempt reports failure to its connection callbacks once, and that attempt's timer cannot fail a later attempt still connecting on the same client. _(src/qbm/http/3/client.cpp:101-114,119-171,470-527,623-640)_

`max_streams_bidi` limits HTTP/3 requests in flight, not requests over the connection's lifetime. Qb returns a bidirectional slot on close for client-initiated streams delivered through `stream_open_cb`; ngtcp2 handles implicit openings itself. The loopback test completes 130 sequential requests on one connection with the default QUIC limit of 100. _(qb/src/qb/io/quic.cpp:1061,1565-1592; qbm/http/tests/system/http3/http3-loopback.cpp:1319-1378)_

If QUIC closes synchronously during request submission, the request already removed from the queue receives a `503` and is not entered into the active registry of the closed connection, even if an old failure callback throws during teardown; its saved exception propagates afterward. Connect success/failure notify their other callbacks before propagating a user callback exception; explicit disconnect also completes transport cleanup. _(src/qbm/http/3/client.cpp:119-171,386-467,470-527,545-595)_

```cpp
#ifdef QBM_HTTP_HAS_HTTP3
#include <qbm/http/http.h>     // pulls qb::http3 when the macro is defined; 3/ headers #error otherwise
qb::io::async::init();
auto server = qb::http3::make_server();
server->router().get("/ping", [](auto ctx) {
    ctx->response().set_header("x-protocol", "HTTP/3");
    ctx->response().body() = "pong-h3";
    ctx->complete();
});
server->router().compile();
server->listen(qb::io::uri("https://0.0.0.0:4433"), "cert.pem", "key.pem");  // ALPN fixed to {"h3"}

auto client = qb::http3::make_client("https://127.0.0.1:4433");  // std::shared_ptr; same-origin only; throws if not https
client->push_request(qb::http::Request{qb::io::uri("/ping")}, [](qb::http::Response res) { /* runs on I/O thread */ });
#endif
```

Runs HTTP semantics over QUIC (UDP), reusing the same `Router`/`Context`/`Request`/`Response`. `qb::http::make_dual_stack_server()` runs h2 (TCP/TLS) and h3 (QUIC) against one route table — `listen(tcp_uri, quic_uri, cert, key)` starts the HTTP/2 server but relies on the qb-io loop to drive the QUIC endpoint. Detect protocol via `ctx->request().major_version == 3`. Always guard HTTP/3 application code with `#ifdef QBM_HTTP_HAS_HTTP3`. A `dual_stack_server` is moved only before `listen()`; its moves keep `router()` bound to the destination. The h3 client's `push_requests` admits members one by one against `set_max_pending_requests` (503 at the index past it), and `:authority` brackets an IPv6 literal (`[::1]:8443`).

## WebSocket (`qb::http::ws`, needs `QB_HAS_SSL` even for `ws://`)

WebSocket is merged into qbm-http (lives in `qbm/http/src/qbm/http/ws/`). A server session starts as HTTP/1.1, validates the RFC 6455 `GET` upgrade, then switches the connection to WebSocket framing.

```cpp
#include <qbm/http/http.h>
#include <qbm/http/ws.h>

class WsServer;
class WsSession : public qb::io::use<WsSession>::tcp::client<WsServer> {
public:
    using Protocol    = qb::http::protocol<WsSession>;       // HTTP/1.1 parser
    using ws_protocol = qb::http::ws::protocol<WsSession>;   // WebSocket framer
    explicit WsSession(WsServer &server) : client(server) {}

    void on(Protocol::request &&request) {                    // HTTP upgrade arrives
        if (!this->switch_protocol<ws_protocol>(*this, request))  // validates, queues 101, installs framer
            disconnect();
    }
    void on(ws_protocol::message &&event) {                   // a complete framed message
        *this << event.ws;                                    // echo (event.ws owns; event.data/.size are a view)
    }
    void on(ws_protocol::ping &&) {}   // framer auto-replies with pong
    void on(ws_protocol::close &&) {}
};
class WsServer : public qb::io::use<WsServer>::tcp::server<WsSession> {};
```

Sending frames — value types streamed with `<<`, then `session << frame`:

```cpp
qb::http::ws::MessageText text; text << R"({"event":"hello"})"; *this << text;
qb::http::ws::MessageBinary bin; bin << bytes; *this << bin;
qb::http::ws::MessageClose bye(qb::http::ws::CloseStatus::Normal, "done"); *this << bye;
```

Client (CRTP or callback):

```cpp
class Client : public qb::http::ws::WebSocket<Client> {       // WebSocketSecure<Self> for wss
public:
    void on(connected &&) { set_ping_interval(std::chrono::seconds(30)); /* qb::duration keepalive */ }
    void on(message &&e)  { qb::io::cout() << std::string_view(e.data, e.size) << '\n'; }
    void on(closed &&) {} void on(error &&) {} void on(disconnected &&) {}
};
Client ws; ws.connect(qb::io::uri("ws://localhost:9000/chat"));  // connect(uri, timeout=zero, verify_peer=true)

qb::http::ws::client cb;                                      // callback form; client_secure for wss
cb.on_connected([](auto&){}).on_message([](auto& e){}).on_error([](auto&){});
cb.connect(qb::io::uri("ws://localhost:9000/"));
```

WebSocket notes: a positive `connect` timeout is one deadline across transport and HTTP Upgrade; the ping timer starts only after the 101 is validated. An unoffered server `Sec-WebSocket-Extensions` header fails the handshake, and destroying a stack or `unique_ptr` client during transport connect is safe. `connected`, parsed-handshake/protocol `error`, and `disconnected` callbacks run after parser dispatch and may release the client; a transport connect failure or explicit pending `disconnect()` may report `error` synchronously. A request hook that cancels or replaces the attempt sends no Upgrade. A reconnect retires the old transport and clears its input/output buffers. The masking direction is enforced (client→server masked, server→client not — `operator<<` forces `masked=true` on outbound, do not pre-mask). Reassembly is capped at `protocol_limits::MAX_BODY_SIZE`; `set_max_payload_size(0)` removes the guard. `MessageClose` throws on reserved (`1004/1005/1006/1015`) or out-of-`[1000,4999]` codes. When handing an upgrade off to another actor, call `ctx->suppress_response()` so the routing context destructor does not send a moved-from HTTP response. Coroutine API: `qb::http::ws::coro_client`/`coro_session` with `co_await connect/receive/close_async`; a lowered `set_pending_cap` trims the queue at once (0 never purges), and a refused `coro_session` upgrade answers the hook's status when ≥ 300, else `400`. A framer protocol failure marks the connection failed before it reports `on(error)` to an I/O handler, and an exception from that observer is contained.

A destroyed suspended WebSocket receive/next-frame/close awaiter makes its slot inactive; a successor can reserve it, while a genuinely concurrent live waiter still throws. An older awaiter cannot clear a newer reservation. Frame buffering remains bounded; abandoning a close waiter does not retract queued bytes. Close codes and UTF-8 reasons are validated before coroutine state is published, permitting a valid later close after rejection. No full allocation/serialization rollback or new actor-cancellation behavior is promised. Use `auto`/`co_await` and consistent rebuilt headers for the new concrete WebSocket awaiter types; ordinary HTTP callback factories retain their path. _(src/qbm/http/coro.h:93-112,182-218,232-259; src/qbm/http/ws/coro.h:431-484,886-941)_

## Clients (one-shot + persistent)

```cpp
// One-shot callback (HTTP/1.1). Self-deleting heap session; callback fires exactly once.
qb::http::GET(std::move(req), [](qb::http::async::Reply&& reply) {     // also POST/PUT/DEL/HEAD/OPTIONS/PATCH/REQUEST
    if (reply.response.status() == qb::http::status::OK)
        use(reply.response.body().as<std::string_view>());
}, qb::duration::zero() /* timeout: zero == NO timeout */, /*verify_peer=*/true);

// One-shot coroutine (same verb names, 2-arg form returns an awaiter):
auto reply = co_await qb::http::GET(std::move(req), 5s);              // inside a coroutine
auto r2    = qb::http::run_sync(qb::http::GET(qb::http::Request{{"http://localhost:8080/"}}));  // from main/tests

// Persistent, connection-reusing, same-origin (own via shared_ptr from make_client):
auto client = qb::http1::make_client("http://api.example.com");
auto connected = qb::http::run_sync(client->connect());              // ConnectResult is bool-convertible
auto resp = qb::http::run_sync(client->push_request(qb::http::Request{qb::io::uri("/items/42")}));
client->set_connect_timeout(std::chrono::seconds(10));               // default 30s; request default 60s
client->set_verify_peer(false);                                      // BEFORE connect
```

`qb::http::async::Reply` = `{ Request request; Response response; }`. Every client writes `Host` (HTTP/1.1, WebSocket) and `:authority` (HTTP/2, HTTP/3) with `qb::http::origin::authority(uri)`: an IPv6 literal between brackets without its zone identifier, the scheme's default port left out (QB-1064). One-shot helpers compare URI schemes case-insensitively for transport selection: unsupported schemes fail locally with 400, and HTTPS without SSL support fails locally with 503; neither opens a socket. Qb-io also resolves default ports for portless mixed-case HTTP(S) URLs (QB-919). A local rejection may invoke the callback before the helper returns; the coroutine awaiter schedules its continuation. Other failures synthesize 503 (cannot connect), 504 (timeout), 400 (the request cannot be compressed or serialized -- e.g. a raw SP or control byte in the URI's query), or 502 (the session is disposed before a complete response: a peer close, a protocol error, a read limit). The callback runs exactly once, and a response delimited by the connection close (no Content-Length, no Transfer-Encoding) is delivered at EOF (QB-507). Persistent clients (`http1`/`http2`/`http3`) are non-copyable/non-movable, single-origin, and must be owned through `make_client`'s `shared_ptr`. Timeouts everywhere are `qb::duration`; `qb::duration::zero()` means **no timeout**. `qb::http::run_sync(awaitable)` (used above; declared in `coro.h`, pulled in by `<qbm/http/http.h>`) drives one awaitable to completion on the current I/O thread — it bridges synchronous top-level code and tests, **not** code inside an already driven coroutine. The WebSocket side has its own alias, `qb::http::ws::run_sync`; both re-export `qb::io::async::run_sync`. A coroutine parked on a client request shows as `"http"` in qb's `CoroutineScheduler::dump()` when its thread tracks suspensions (3.3).

HTTP/1.1 closing response callbacks see the client down. Disconnect/failure/timeout retires the old request and connect-callback cohort before user notification; new callback submissions belong to the next cycle. An explicit connect accepted during retirement starts after the old callback/protocol dispatch returns, and pending work may queue behind that intent with auto-reconnect disabled. Destruction abandons pending connect observers; explicit disconnect reports cancellation once. _(src/qbm/http/1.1/client.cpp:235-239,275-310,341-352,568-633,693-752)_

---

## Invariants (must hold)

- Call `router().compile()` after all definitions, before serving.
- Every task (handler, `IMiddleware::process`, `ICustomRoute::process`, async callback) calls `ctx->complete(...)` exactly once on every path — or the request hangs. Functional middleware may call `next()` instead (= `complete(CONTINUE)`).
- A task's `cancel()` override must never call `ctx->complete()`.
- Capture `ctx` (a shared_ptr) into async callbacks; complete from the callback, not before the handler returns. Guard `ctx->is_cancelled()` in the callback.
- Never store per-request state on a handler/middleware/task object — it is shared across concurrent (pipelined/multiplexed) requests. Use the `Context` (`Slot<T>`).
- Null-check `ctx->session()` — it is weak-locked and may be `nullptr` after disconnect.
- Gate SSL features on `QB_HAS_SSL`, HTTP/3 on `QBM_HTTP_HAS_HTTP3` (never on the private `QBM_HTTP_HAS_SSL`).
- Link `qbm::http`; this is a compiled library.

## Gotchas

- **DELETE ⇒ `qb::http::method::DEL`** and `router().del(...)`. `method::DELETE` does not exist.
- `Body`/`Headers` are base classes — `req.set_header(...)`/`req.body()`, not `req.headers().set(...)`. After mutating `headers()` directly, call `refresh_content_type()`; `content_type()` derives itself from the raw header on the next read.
- Request cookies need an explicit `req.parse_cookie_header()`; response cookie edits via the pointer/jar need `update_cookie_header(name)`.
- Terminal context helpers (`json`, `text`, `redirect`, `no_content`, the 4xx/5xx ones) call `complete()` internally — set custom headers/body first. Only `ctx->status(code)` is chainable.
- `Body::as<T>()`/`try_as<T>()` and the assignment set are closed; non-supported `T` is a compile error. `as<T>()` throws on a malformed payload — reach for `try_as<T>() -> std::optional<T>` (`noexcept`) on request bodies.
- `out << msg` writes a COMPLETE HTTP/1.1 message — an empty chunked body is its last-chunk — and a request with a raw SP, control byte or DEL in its URI's query throws `std::length_error` (percent-encode it; `qb::io::uri` already refuses them in a path), as does one with no method (a default-constructed `Request`) or an invalid URI; an empty path goes out as `/`. A refusal writes nothing and keeps what the pipe held before it (QB-1066). A chunked message's `Trailer`-announced fields and its `trailers()` go out after the last chunk, and received trailer fields land in `trailers()` and, for 3.x, in `headers()` too, as on HTTP/2 and HTTP/3 (QB-1067, QB-1073). To stream chunks yourself, write `qb::http::MessageHead{msg}` (start line + header section only), then the `Chunk`s and the terminating `Chunk{}`.
- Assigning a C++-constructed `qb::json` with invalid UTF-8 to `Body` throws for const and rvalue JSON alike and clears partial output; a routed `Context::json` handler becomes a 500 instead of terminating the process.
- HTTP/2 / HTTP/3 are TLS-only with ALPN; no plaintext h2c. HTTP/2 client `connect(nullptr)` for fire-and-forget.
- The request limits are the server's `set_request_limits(qb::http::request_limits)` on HTTP/1.1, HTTP/2, HTTP/3 and
  the dual stack alike (0 = none; read live, so they apply to requests that arrive after the call; defaults the
  `protocol_limits` constants -- a 100 MiB body, 64 MiB on h3; `set_max_body_size` sets the body alone). A request over
  one is answered before the handler runs, the same everywhere: `414` target, `431` field name, value or a section's
  field count, `413` body (or an h1 chunk); h1 with `Connection: close` and the close after its delivery, h2 on the
  stream then `RST_STREAM(NO_ERROR)`, h3 on the stream then STOP_SENDING(`H3_NO_ERROR`) (Huly QB-168, QB-94; until 3.3
  h1 closed with no answer, h2 had no field limits and h3 reset the stream). _(1.1/http.h:622-624; 2/http2.h:588-590;
  3/http3.h:482-484)_
- `verify_peer` defaults to `true`; disable only for trusted/self-signed endpoints, and set it before connecting on persistent clients.
- Validation `validate()` mutates the request; type-gated rules pass silently for the wrong kind (assert `type` first).
- `PRE_ROUTING` is observable only via `router().add_lifecycle_hook(...)`, not a per-context hook.

## Time vocabulary (verify, never invent)

- Cookie `max_age`/`expires_in`, CORS preflight, rate-limit windows, all client/protocol timeouts ⇒ `qb::duration` (`qb::duration::zero()` = no timeout). Use `qb::wall_now()` for wall-clock stamps.
- JWT `token_expiration`, `clock_skew_tolerance`, `JwtOptions::leeway`, and `exp`/`nbf` ⇒ `std::chrono::seconds` (RFC 7519 NumericDate; deliberately seconds resolution).
- HTTP date API (`qb::http::date`) bridges `std::chrono::system_clock` and `qb::wall_time` — it has NO `qb::Timestamp` overloads and NO `to_timestamp(`/`to_time_point(`.
- **Never write in examples:** `qb::Timestamp`, `qb::Duration`, `qb::TimePoint`, `to_timestamp(`, `to_time_point(`. (Name them only to warn off.)

## Build / integration (one line)

`add_subdirectory(qb)` (must precede), then `qb_load_modules("${CMAKE_CURRENT_SOURCE_DIR}/qbm")`, then `target_link_libraries(app PRIVATE qbm::http)` (PUBLIC-propagates qb::core/qb::io/llhttp and the `QB_HAS_SSL`/`QBM_HTTP_HAS_HTTP3` defines + `cxx_std_${QB_CXX_STANDARD}` — `cxx_std_20` by default, `cxx_std_23` when the C++23 preset is selected), and `#include <qbm/http/http.h>`.

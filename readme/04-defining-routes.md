# Defining routes

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 2.0.0 (C++20 default, C++23 supported)

Bind an HTTP method and a path pattern to a handler, extract path parameters from the URL, and drive each request through the `Context` it receives.

**Prerequisites:** [Routing overview](./03-routing-overview.md), [Core HTTP concepts](./01-core-concepts.md) — **See also:** [Route groups](./05-route-groups.md), [Controllers](./06-controllers.md), [The request context](./10-request-context.md)

## What a route is

A route is the terminal binding in the routing tree: one HTTP method plus one path pattern, pointing at a handler. You register routes on a `qb::http::Router<SessionType>` (or on a [`RouteGroup`](./05-route-groups.md) or [`Controller`](./06-controllers.md), which share the same API). After every route, group, controller, and middleware is declared, you call `router.compile()` once — that flattens the tree into the `RadixTree` task chains the dispatcher actually runs. See [Routing overview](./03-routing-overview.md) for the match algorithm and the compile step.

Inside a `qb::http::Server<>`, the router is reached through the inherited `router()` accessor; the session type defaults to `qb::http::DefaultSession`, so handlers receive a `std::shared_ptr<qb::http::Context<qb::http::DefaultSession>>`. Every sample on this page lives in a server actor's `onInit()`, registered against `router()`.

## Method handlers

`Router` (and `RouteGroup` and `Controller`) expose one method per HTTP verb. Each returns a reference to the router so calls chain, and each takes a path pattern followed by a handler:

<!-- src: qbm/http/routing/router.h:82-101 -->
```cpp
Router<SessionType> &get    (std::string path, RouteHandlerFn<SessionType> handler_fn);
Router<SessionType> &post   (std::string path, RouteHandlerFn<SessionType> handler_fn);
Router<SessionType> &put    (std::string path, RouteHandlerFn<SessionType> handler_fn);
Router<SessionType> &del    (std::string path, RouteHandlerFn<SessionType> handler_fn);  // DELETE
Router<SessionType> &patch  (std::string path, RouteHandlerFn<SessionType> handler_fn);
Router<SessionType> &options(std::string path, RouteHandlerFn<SessionType> handler_fn);
Router<SessionType> &head   (std::string path, RouteHandlerFn<SessionType> handler_fn);
```

The verb is `del`, not `delete` — `delete` is a C++ keyword, so the framework names the DELETE handler `del` (the underlying enumerator is `qb::http::method::DEL`).

When the verb is computed rather than literal, use the general form, which takes a `qb::http::method` value:

<!-- src: qbm/http/routing/router.h:79-80 -->
```cpp
Router<SessionType> &add_route(std::string path, qb::http::method method,
                               RouteHandlerFn<SessionType> handler_fn);
```

`router.get("/x", h)` is shorthand for `router.add_route("/x", qb::http::method::GET, h)`.

## The handler signature

A handler is a `qb::http::RouteHandlerFn<SessionType>` — a `std::function` taking a shared pointer to the request context and returning `void`:

<!-- src: qbm/http/routing/types.h:82-83 -->
```cpp
template<typename SessionType>
using RouteHandlerFn = std::function<void(std::shared_ptr<Context<SessionType>> ctx)>;
```

The handler receives everything it needs through `ctx`: the request, the response to populate, the session, and the extracted path parameters. There is no return value — the handler signals its outcome by calling `ctx->complete(...)`.

**Every handler must eventually call `ctx->complete(...)`.** Until it does, the request is parked and no response is sent. The argument is a `qb::http::AsyncTaskResult`; for a route handler that produced the response, that is `AsyncTaskResult::COMPLETE` (the default), so `ctx->complete()` with no argument is the common case. The response-builder helpers on `Context` (`ctx->json(...)`, `ctx->text(...)`, `ctx->html(...)`, `ctx->no_content()`, `ctx->redirect(...)`, `ctx->bad_request(...)`, and so on) each finalize the response *and* call `complete()` for you, so they are the terminal statement of a handler — see [The request context](./10-request-context.md).

If a handler kicks off asynchronous work (a `qb::io::async::callback`, an actor message round-trip, a database query), it must capture `ctx` (it is already a `shared_ptr`, so it keeps the context alive) and call `complete()` from inside that continuation, not before it returns. See [Asynchronous routes](#asynchronous-routes) below.

### Lambda handlers

The fastest way to define a route is a lambda. It conforms to `RouteHandlerFn` automatically:

<!-- src: derived from examples/qbm/http/03_basic_routing.cpp (setup_routes) -->
```cpp
#include <http/http.h>  // Router, Context, status, method, Server — the whole qbm-http surface

class ApiServer : public qb::Actor, public qb::http::Server<> {
public:
    bool onInit() override {
        // GET /health — no body, just a status helper.
        router().get("/health", [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
            ctx->no_content();  // 204; finalizes the context for you
        });

        // POST /users — read the JSON body, echo a created resource.
        router().post("/users", [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
            auto payload = ctx->request().body().as<qb::json>();
            qb::json created = {{"id", 42}, {"name", payload.value("name", "")}};
            ctx->json(created, qb::http::status::CREATED);  // 201, sets Content-Type, completes
        });

        router().compile();  // mandatory before serving — see Routing overview
        return listen({"tcp://0.0.0.0:8080"}) && (start(), true);
    }
};
```

When the handler delegates to a member function, `[this](auto ctx) { ... }` keeps the registration terse while letting the body name the concrete `Context` type:

<!-- src: examples/qbm/http/03_basic_routing.cpp:88-90 (registration) + derived member -->
```cpp
router().get("/users/:id", [this](auto ctx) { handle_get_user(ctx); });

// ...
void handle_get_user(std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
    int id = std::stoi(ctx->path_param("id"));
    // look up id, populate ctx->response(), then complete
    ctx->complete();
}
```

### Class-based handlers (`ICustomRoute`)

For a stateful, reusable, or unit-testable handler, implement `qb::http::ICustomRoute<SessionType>`. It is a three-method interface:

<!-- src: qbm/http/routing/custom_route.h:42-86 -->
```cpp
template<typename SessionType>
class ICustomRoute {
public:
    virtual ~ICustomRoute() = default;
    virtual void process(std::shared_ptr<Context<SessionType>> ctx) = 0;  // your logic; must complete()
    [[nodiscard]] virtual std::string name() const = 0;                   // for logs and diagnostics
    virtual void cancel() = 0;                                            // on disconnect/timeout
};
```

`process()` carries the same contract as a lambda handler: it must call `ctx->complete(...)`. `cancel()` is the inverse — it is invoked when the request is torn down (client disconnect, timeout) while this handler is the in-flight task, and it **must not** call `ctx->complete()`; the `Context` owns the cancellation and finalization sequence. Use `cancel()` only to release resources or abort in-flight async work.

<!-- src: derived from qbm/http/tests/test-router-api.cpp:28-44 (SimpleApiCustomRoute) -->
```cpp
#include <http/http.h>

class UserProfileRoute : public qb::http::ICustomRoute<qb::http::DefaultSession> {
public:
    explicit UserProfileRoute(UserStore &store) : _store(store) {}

    void process(std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) override {
        const std::string id = ctx->path_param("id");
        if (auto user = _store.find(id))
            ctx->json(*user);                              // 200 + completes
        else
            ctx->not_found("no such user");                // 404 + completes
    }

    [[nodiscard]] std::string name() const override { return "UserProfileRoute"; }
    void cancel() override { /* nothing async in flight to abort */ }

private:
    UserStore &_store;
};
```

You register an `ICustomRoute` two ways. Pass a pre-built instance as a `std::shared_ptr` to the verb method:

<!-- src: qbm/http/routing/router.h:104-105 -->
```cpp
auto route = std::make_shared<UserProfileRoute>(user_store);
router().get("/users/:id", route);
```

Or let the router construct it in place with the typed overload, forwarding the constructor arguments after the path. The type is constrained to derive from `ICustomRoute<SessionType>`:

<!-- src: qbm/http/routing/router.h:139-142 -->
```cpp
router().get<UserProfileRoute>("/users/:id", user_store);  // forwards user_store to the ctor
```

There is also a typed general form, mirroring `add_route`:

<!-- src: qbm/http/routing/router.h:135-137 -->
```cpp
router().add_custom_route<UserProfileRoute>("/users/:id", qb::http::method::GET, user_store);
```

> One handler instance, many requests. After `compile()`, the task wrapping a route handler is **shared across concurrent requests** (HTTP/1.1 pipelining, HTTP/2 multiplexing). Do not store per-request state on an `ICustomRoute`; keep all request-scoped data on the `Context`. Member fields are fine for immutable dependencies like the `UserStore &` above.

## Path patterns and parameters

A path pattern is a `/`-separated sequence of three segment kinds (full grammar in [Routing overview](./03-routing-overview.md#path-pattern-syntax)):

| Segment | Syntax | Captures | Example match |
|---|---|---|---|
| Static | `users` | nothing | `/users` |
| Parameter | `:id` | one segment | `/users/42` → `id = "42"` |
| Wildcard | `*rest` | the remainder of the path, slashes included | `/files/docs/a.pdf` → `rest = "docs/a.pdf"` |

A parameter (`:name`) matches exactly one path segment. A wildcard (`*name`) matches everything left, including embedded slashes, and **must be the last segment** in the pattern. Each capture name must be unique within a pattern. A `:` or `*` with no name, an empty segment, or a name collision throws `std::invalid_argument` — the pattern is parsed and validated when the tree is built, so the throw fires from `compile()` (or from the auto-compile on the first `route()`), not from the verb call that declared the route.

Read captured values off the context with `path_param`:

<!-- src: qbm/http/routing/context.h:467-470 -->
```cpp
[[nodiscard]] std::string path_param(const std::string &name,
                                     const std::string &not_found_value = "") const;
```

It returns the captured string, or `not_found_value` (default empty) when the name was not part of the matched pattern — so it never throws for a missing key. The value is always a decoded `std::string`; convert it yourself (`std::stoi`, etc.) and validate, since a client can send any value the pattern shape allows.

<!-- src: derived from examples/qbm/http/03_basic_routing.cpp:88-113 (route shapes) -->
```cpp
// One path parameter.
router().get("/users/:id", [](auto ctx) {
    const std::string id = ctx->path_param("id");          // "42" for /users/42
    ctx->text("user " + id);
});

// Several parameters in one pattern.
router().get("/orgs/:org/repos/:repo", [](auto ctx) {
    ctx->json({{"org", ctx->path_param("org")},
               {"repo", ctx->path_param("repo")}});
});

// Wildcard: captures the rest of the path under the given name.
router().get("/files/*path", [](auto ctx) {
    const std::string rel = ctx->path_param("path");       // "docs/report.pdf" for /files/docs/report.pdf
    ctx->text("serving " + rel);
});
```

For the whole parameter set at once — iteration, `has`, `size` — reach for `ctx->path_parameters()`, which returns the `qb::http::PathParameters` map (string-view keys into the route pattern, owned string values).

> Query-string arguments are **not** path parameters. `path_param` reads `:`/`*` captures only; for `?q=...` read `ctx->request().query("q")` (see [Core HTTP concepts](./01-core-concepts.md)).

## The request context

The `ctx` passed to a handler is a `std::shared_ptr<qb::http::Context<SessionType>>` — the single object that carries one request through its lifecycle. For route definition you mainly use four accessors:

<!-- src: qbm/http/routing/context.h:423-470 -->
```cpp
Request  &request();         // the incoming request: method, URI, headers, body, query()
Response &response();        // the response you populate: status(), set_header(), body()
std::shared_ptr<SessionType> session();   // the client session (may be null after disconnect)
std::string path_param(const std::string &name, const std::string &not_found_value = "") const;
```

Set the response by hand and then `complete()`, or use a response helper that does both. The two styles are equivalent; the helpers are shorter and harder to get wrong:

```cpp
// Manual: set status, headers, body, then finalize.
ctx->response().status() = qb::http::status::OK;
ctx->response().set_header("Content-Type", "application/json");
ctx->response().body() = qb::json{{"ok", true}};
ctx->complete();

// Helper: one call sets Content-Type, body, status, and completes.
ctx->json(qb::json{{"ok", true}});
```

`session()` returns a `shared_ptr` obtained from a `weak_ptr`, so check it for null before use — by the time an async handler resumes, the client may have disconnected. The richer `Context` surface (typed data slots for passing state between middleware and the handler, lifecycle hooks, `cancel()`, the full helper set) is covered in [The request context](./10-request-context.md).

### Asynchronous routes

A handler does not have to finish synchronously. Capture `ctx` into a continuation, return without completing, and call `complete()` when the async work lands:

<!-- src: qbm/http/tests/test-router-async.cpp -->
```cpp
router().get("/slow", [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
    // Defer work onto the event loop; ctx (a shared_ptr) keeps the context alive.
    qb::io::async::callback([ctx]() {
        ctx->text("done");   // resolves later, off the original call stack — completes here
    }, std::chrono::milliseconds(250));
    // handler returns now; the request stays open until the callback fires
});
```

The request is held open until that `complete()` runs. If your async path can fail, complete with `AsyncTaskResult::ERROR` (or call a response helper such as `ctx->internal_server_error(...)`) so the configured error chain runs — see [Error handling strategies](./13-error-handling.md).

## Compiling routes

Defining routes only builds the tree. Before the router can match anything, call `compile()` once, after all routes, groups, controllers, and middleware are declared:

<!-- src: examples/qbm/http/03_basic_routing.cpp:42 -->
```cpp
router().compile();
```

`compile()` flattens the node hierarchy, resolves the inherited middleware chain for each endpoint, and populates the `RadixTree`. Any later mutation (adding a route, group, or middleware) marks the router un-compiled; `route()` auto-compiles on first use if you forgot, but relying on that hides definition errors that an explicit `compile()` would surface. Call it explicitly at the end of setup. See [Routing overview](./03-routing-overview.md) for the full compile model.

## Pitfalls

- **Forgetting `ctx->complete(...)`.** The request hangs indefinitely with no response. Every code path through a handler — including early returns and error branches — must reach a `complete()` or a response helper that calls it. The helpers (`json`, `text`, `no_content`, `redirect`, `bad_request`, …) are the safe default.
- **Calling `complete()` from `ICustomRoute::cancel()`.** `cancel()` must not complete the context; the `Context` is already finalizing. Use it only to release resources.
- **Storing per-request state on a handler object.** A compiled handler task is shared across concurrent requests. Keep request-scoped data on the `Context` (typed slots), not in `ICustomRoute` members.
- **Completing before async work finishes.** If you start a `qb::io::async::callback` or send an actor message, do not call `complete()` in the handler body — call it from the continuation, or the response goes out before the work is done.
- **Confusing path and query parameters.** `path_param("q")` returns the not-found default for `?q=...`; that argument is `ctx->request().query("q")`. A wildcard `*name` captures embedded slashes; a `:name` parameter captures a single segment only.
- **A wildcard that is not last, or a duplicate capture name.** Both throw `std::invalid_argument` when the tree is built — from `compile()` (or the first `route()` that auto-compiles), not from the verb call that declared the route. Fix the pattern; do not catch and ignore.
- **Skipping `compile()`.** Without it the router has no `RadixTree` to match against. Auto-compile on first `route()` is a safety net, not a substitute — call `compile()` at the end of `onInit()`.

## See also

- [Routing overview](./03-routing-overview.md) — the match algorithm, the radix tree, and the compile step.
- [Route groups](./05-route-groups.md) — share a path prefix and scope middleware across many routes.
- [Controllers](./06-controllers.md) — organize routes as class members with `MEMBER_HANDLER`.
- [The request context](./10-request-context.md) — the full `Context` surface: helpers, typed slots, lifecycle hooks.
- [Middleware overview](./07-middleware.md) — insert logic into the task chain before and after the handler.
- [Error handling strategies](./13-error-handling.md) — the error chain and the not-found handler.

---
Previous: [Routing overview](./03-routing-overview.md) · Next: [Route groups](./05-route-groups.md) · Up: [Index](./README.md)

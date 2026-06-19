# Controllers

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 2.0.0 (C++20 default, C++23 supported)

Group related route handlers, their shared state, and their middleware into a single class that mounts onto the router under a base path.

**Prerequisites:** [Defining routes](./04-defining-routes.md), [Route groups](./05-route-groups.md) — **See also:** [Middleware overview](./07-middleware.md), [The request context](./10-request-context.md), [Custom middleware](./09-custom-middleware.md)

## What a controller is

A [`RouteGroup`](./05-route-groups.md) bundles routes under a path prefix, but its routes are still anonymous lambdas declared inline. A `qb::http::Controller<SessionType>` is the class-based equivalent: you subclass it, declare the group's routes once in an overridden method, and back each route with a member function. Because the controller is an object, those member functions share the controller's member variables — a database handle, a service client, a cache, a counter — without capturing anything into a lambda.

A controller is itself an `IHandlerNode<SessionType>`, the same tree-node abstraction as `Route` and `RouteGroup`. It owns a path segment, a stack of per-node middleware inherited by all of its routes, and the `compile_tasks_and_register` step that flattens it into the router's radix tree. Mounting a controller is therefore indistinguishable, at the routing level, from mounting a group: the controller's routes appear at `parent_path + base_path_segment + route_path`, and parent middleware flows down into them.

Reach for a controller when:

- A set of routes shares state or an injected dependency (a service, a connection pool).
- You want the route definitions and their handlers to live together in one testable unit.
- You want to mount the same set of routes more than once, under different prefixes or with different constructor arguments.

For a handful of stateless endpoints, an inline `RouteGroup` is lighter. Controllers earn their weight as the surface grows.

## Anatomy of a controller

<!-- src: qbm/http/routing/controller.h:51-166, tests/test-router-controller.cpp:92-141 -->

```cpp
#include <http/http.h>   // qb::http::Controller, Context, Router, status
#include <memory>
#include <string>

// Your application's session type — see 01-core-concepts.md.
struct MySession;

// An injected dependency the controller's handlers will share.
struct UserService {
    std::string fetch(const std::string &id) { return "user:" + id; }
    void        create(std::string_view body) { /* ... */ }
};

class UserController : public qb::http::Controller<MySession> {
public:
    // Constructor receives dependencies. Anything the router's controller<>()
    // call forwards lands here.
    explicit UserController(std::shared_ptr<UserService> svc)
        : _svc(std::move(svc)) {}

    // Required override: declare the controller's routes and middleware here.
    void initialize_routes() override {
        // Member functions become handlers via MEMBER_HANDLER.
        this->get("/:id", MEMBER_HANDLER(&UserController::get_user));
        this->post("/",   MEMBER_HANDLER(&UserController::create_user));

        // A plain lambda works too, when no member state is needed.
        this->get("/health", [](std::shared_ptr<Context> ctx) {
            ctx->response().body() = "ok";
            ctx->complete();
        });
    }

private:
    void get_user(std::shared_ptr<Context> ctx) {
        const std::string id = ctx->path_param("id");
        ctx->response().body() = _svc->fetch(id);
        ctx->complete();
    }

    void create_user(std::shared_ptr<Context> ctx) {
        _svc->create(ctx->request().body().template as<std::string_view>());
        ctx->response().status() = qb::http::status::CREATED;
        ctx->complete();
    }

    std::shared_ptr<UserService> _svc;
};
```

The pieces:

- **Subclass `Controller<MySession>`.** The base injects two convenience aliases inside the class body: `SessionType` (= `MySession`) and `Context` (= `qb::http::Context<MySession>`). Use the short `Context` spelling for handler signatures.
- **Override `initialize_routes()`.** This is the one pure-virtual method. Declare routes with `this->get(...)`, `this->post(...)`, etc., and per-controller middleware with `this->use(...)`. The router calls this method for you during compilation — never call it yourself in normal use.
- **Write handlers as member functions** taking `std::shared_ptr<Context>` and returning `void`. They drive the request through the same `Context` object documented in [The request context](./10-request-context.md): set `response()`, read `path_param(...)`, then call `complete()`.
- **Hold state in members.** Each handler sees the controller's members directly, so a `UserService`, a request counter, or a config struct is shared across every route the controller defines.

### The route-definition API

Inside `initialize_routes()`, a controller exposes the same verb methods as a router or group, all relative to the controller's base path:

| Method | Maps to |
| --- | --- |
| `get`, `post`, `put`, `del`, `patch`, `options`, `head` | `qb::http::method::GET … HEAD` |

`del` (not `delete`) is the spelling for `DELETE` throughout the verb API — `delete` is a C++ keyword and cannot be a method name. Each verb has three overloads, mirroring [Defining routes](./04-defining-routes.md):

- `get(path, RouteHandlerFn)` — a lambda or `MEMBER_HANDLER`-wrapped member.
- `get<MyCustomRoute>(path, ctor_args...)` — constructs an [`ICustomRoute`](./09-custom-middleware.md) in place.
- `get(path, std::shared_ptr<ICustomRoute<MySession>>)` — a pre-built custom route.

Every verb method returns `Controller<MySession>&`, so calls chain. Paths are relative to the controller's mount point — a leading `/` is normalized, so `"/users"` and `"users"` behave identically.

### The `MEMBER_HANDLER` macro

<!-- src: qbm/http/routing/controller.h:301-302 -->

`MEMBER_HANDLER(&Class::method)` expands to a lambda that captures `this` and forwards the `Context` to the named member:

```cpp
#define MEMBER_HANDLER(handler_ptr) \
    [this](std::shared_ptr<Context> ctx_param) { (this->*handler_ptr)(ctx_param); }
```

The bound member must have the signature `void method(std::shared_ptr<Context>)`. Because the macro captures `this`, it is valid only inside a controller method (it is defined as a member-scope macro), and the captured `this` must outlive every request — which it does, since the router owns the controller for the router's lifetime. If you prefer not to use the macro, an explicit `[this](std::shared_ptr<Context> ctx){ this->method(ctx); }` is exactly equivalent — the controller tests use both spellings interchangeably.

## Mounting a controller

<!-- src: qbm/http/routing/router.h:178-188, route_group.h:207-223, tests/test-router-controller.cpp:559-570 -->

Mount a controller on a `Router` or a `RouteGroup` with `controller<C>(path_prefix, ctor_args...)`:

```cpp
#include <http/http.h>
#include <memory>

qb::http::Router<MySession> router;
auto svc = std::make_shared<UserService>();

// Construct UserController(svc) and mount it under "/users".
std::shared_ptr<UserController> users =
    router.controller<UserController>("/users", svc);

router.compile();   // flatten the tree — required before serving
```

- `C` is your controller type. The signature is constrained — on `Router` by `requires DerivedFrom<C, Controller<SessionType>>`, on `RouteGroup` by an equivalent `enable_if` — so a non-controller type fails to compile.
- `path_prefix` is the controller's base path segment. It combines with the parent's path: a controller mounted at `"/users"` on the router answers at `/users/...`; the same controller mounted at `"/users"` inside a group created with `group("/api/v1")` answers at `/api/v1/users/...`.
- `ctor_args...` are forwarded to `C`'s constructor. The `controller<>()` call constructs the instance immediately, so a throwing constructor throws out of `controller<>()`, before `compile()`.

The call returns `std::shared_ptr<C>` — the concrete type, not the base — so you can keep configuring the instance after mounting (for example, `users->use(...)` to add middleware, as shown below). The router co-owns the controller; the returned handle is a shared reference, not the sole owner.

With the mount above and the `UserController` from earlier, the routing table resolves:

| Request | Handler |
| --- | --- |
| `GET /users/42` | `UserController::get_user`, `path_param("id") == "42"` |
| `POST /users/` | `UserController::create_user` |
| `GET /users/health` | the inline `/health` lambda |

### Mounting inside a group

A controller composes with [route groups](./05-route-groups.md). Mount it on a group to inherit the group's prefix and middleware:

```cpp
auto api = router.group("/api/v1");
api->use<AuthMiddleware>();                       // applies to everything under /api/v1
api->controller<UserController>("/users", svc);   // -> /api/v1/users/...
router.compile();
```

`AuthMiddleware` here runs ahead of any controller-level middleware and ahead of the route handlers, because parent middleware is always inherited first. See [Middleware overview](./07-middleware.md) for the full ordering rules.

## Controller-scoped middleware

<!-- src: qbm/http/routing/controller.h:314-358, tests/test-router-controller.cpp:538-552, 773-786 -->

Middleware declared on a controller applies to **all** routes the controller defines, and only those routes. Declare it from inside `initialize_routes()` with `this->use(...)`, or add it after mounting through the returned handle. Three forms, matching the router and group APIs:

```cpp
class AdminController : public qb::http::Controller<MySession> {
public:
    void initialize_routes() override {
        // 1) Functional middleware: (ctx, next) — call next() to continue.
        this->use(
            [](std::shared_ptr<Context> ctx, std::function<void()> next) {
                if (ctx->request().has_header("X-Admin-Token")) {
                    next();                                  // continue the chain
                } else {
                    ctx->response().status() = qb::http::status::UNAUTHORIZED;
                    ctx->complete();                         // short-circuit
                }
            },
            "AdminGate");                                    // optional name for tracing

        // 2) An IMiddleware instance, constructed in place from ctor args.
        this->use<RateLimitMiddleware>(/* ctor args */);

        this->get("/stats", MEMBER_HANDLER(&AdminController::stats));
    }
private:
    void stats(std::shared_ptr<Context> ctx) { /* ... */ }
};
```

You can also add middleware to the live instance after mounting — useful when the middleware needs runtime configuration the controller's constructor did not receive:

```cpp
auto admin = router.controller<AdminController>("/admin");
admin->use(std::make_shared<AuditMiddleware>("admin-audit"));   // 3) shared_ptr form
router.compile();
```

All three `use` overloads return `Controller<MySession>&` for chaining. Within a single controller, middleware runs in declaration order, after any inherited parent middleware, and before the matched route's handler. The `(ctx, next)` functional form and the `IMiddleware`/`ICustomRoute` interfaces are documented in [Custom middleware](./09-custom-middleware.md); the bundled middleware (CORS, auth, rate limiting, compression, and so on) in [Standard middleware](./08-standard-middleware.md).

## State and reuse

Because a controller is a plain object, it holds state across requests and can be mounted more than once. The router owns one instance per mount, and that instance lives for the router's lifetime — so a member counter accumulates across every request the mount serves:

<!-- src: tests/test-router-controller.cpp:499-536, 663-707 -->

```cpp
class CounterController : public qb::http::Controller<MySession> {
public:
    explicit CounterController(std::string label) : _label(std::move(label)) {}

    void initialize_routes() override {
        this->get("/hit", MEMBER_HANDLER(&CounterController::hit));
    }
private:
    void hit(std::shared_ptr<Context> ctx) {
        ctx->response().body() = _label + ": " + std::to_string(++_count);
        ctx->complete();
    }
    std::string _label;
    int         _count = 0;   // survives across requests to this mount
};

// Two independent instances, two independent counters.
router.controller<CounterController>("/a", std::string{"A"});
router.controller<CounterController>("/b", std::string{"B"});
router.compile();
```

That shared mutable state is exactly why controllers carry a concurrency contract. The session type parameter and the actor that owns the router decide the threading model. If the controller is reachable from one actor only — the common qb pattern, where an HTTP server actor owns its router — the member state is single-threaded and needs no locking. If you deliberately share a controller across cores, its members become shared mutable state and you are responsible for synchronizing them. Prefer the single-owner model; it is what the framework is built around.

## How a controller compiles

<!-- src: qbm/http/routing/controller.h:372-401 -->

You rarely touch this, but the mechanics explain a few behaviors worth knowing. During `router.compile()`, each controller's `compile_tasks_and_register` runs once:

1. If routes were not already populated, it calls `initialize_routes()` exactly once and marks the controller initialized. If the controller already populated its route list (for example, by calling `initialize_routes()` from its own constructor), the compile step does **not** call it again — guarding against double registration. A controller that declares only middleware and no routes still has `initialize_routes()` invoked exactly once.
2. It computes the controller's full base path from the parent path plus its own segment.
3. It combines inherited middleware with the controller's own middleware into one task list.
4. It compiles each declared route against that base path and task list, registering the flattened chains in the radix tree.

`compile()` is idempotent and safe to call repeatedly; `initialize_routes()` still fires only once. Any mutation of the routing tree after compilation resets the compiled flag, and `route()` auto-compiles on first use if you forgot — but call `compile()` explicitly once during setup so the cost is paid at startup, not on the first request. See [Routing overview](./03-routing-overview.md) for the compile model.

## Pitfalls

- **Define routes in `initialize_routes()`, not in the constructor — unless you mean to.** The compile step calls `initialize_routes()` only when the controller's route list is still empty. If your constructor already declared routes, the override is skipped. Pick one location; declaring in both means the constructor wins and the override silently never runs.
- **`del`, not `delete`.** The DELETE verb method is `del()`. `delete` is a C++ keyword and cannot be a method name.
- **Handlers must call `complete()` (or `cancel()`).** Each handler must signal terminal status on its `Context`, exactly as standalone route handlers do. A handler that returns without completing leaves the request hanging. For deferred work, capture the `std::shared_ptr<Context>` into the async task and call `complete()` from the continuation — the controller test suite drives precisely this pattern.
- **`MEMBER_HANDLER` is member-scope only.** It expands to a `this`-capturing lambda, so it compiles only inside a controller method. Outside the class, write the explicit lambda.
- **Compile after every controller is mounted.** Mount all controllers, groups, and global middleware first, then call `compile()` once. Mounting a controller after `compile()` invalidates the compiled tree; you must compile again before those routes resolve.
- **A throwing controller constructor throws from `controller<>()`.** The instance is built eagerly at mount time. Wrap the `controller<>()` call, not `compile()`, if construction can fail.

## See also

- [Route groups](./05-route-groups.md) — the lambda-based equivalent and the shared path/middleware model.
- [Defining routes](./04-defining-routes.md) — the verb overloads, path patterns, and parameter extraction controllers reuse.
- [Middleware overview](./07-middleware.md) — inheritance and execution order across router, group, and controller layers.
- [Custom middleware](./09-custom-middleware.md) — writing `IMiddleware` and `ICustomRoute` implementations used by `use<>` and `get<>`.
- [The request context](./10-request-context.md) — the `Context` every controller handler receives.

---

Previous: [Route groups](./05-route-groups.md) · Next: [Middleware overview](./07-middleware.md) · Up: [Index](./README.md)

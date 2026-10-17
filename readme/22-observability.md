# Observability: request ids, observers, access logs and metrics

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 3.2.1 (C++20 default, C++23 supported)

What a server says about the requests it answers, and how it says it without paying for it on the requests nobody observes: a request id carried from the client to the logs, router observers that see every request once at each end, a one-line-per-request access log, request metrics, and their exposition in the Prometheus text format.

**Prerequisites:** [the request context](./10-request-context.md) and [standard middleware](./08-standard-middleware.md). **See also:** the doc map [`README.md`](./README.md).

## The pieces, and where each one runs

| Piece | What it is | Installed with |
|---|---|---|
| Request id | `RequestIdMiddleware`: a chain middleware that gives each request an id, in the context (`request_id_slot`) and the response header | `router.use(...)`, first ([request id](./08-standard-middleware.md#request-id)) |
| Route pattern | `ctx->route_pattern()`: the pattern of the route that matched (`/users/:id`), never the raw path | nothing: the router sets it |
| Router observer | `IRequestObserver<S>`: told when each request is received and when its response is decided | `router.add_observer(...)` |

A chain middleware runs inside the chain of the route that matched: it sees a request only when a chain runs, and to act after the response it registers a lifecycle hook per request. An observer is the router's: it sees every request the router creates a context for, once at each end, whatever chain ran or did not, and costs nothing per request beyond what it does itself.

## The route pattern

`ctx->route_pattern()` names the route that matched, in its canonical form: its segments joined by `/`, captures with their `:` or `*` -- `/`, `/users/:id`, `/api/v1/items/:item` through a group, `/files/*path` -- whatever slashes the registration used. Two methods registered on one path share one pattern. A 405 names the route whose path matched; a 404, and a request the router answers before matching (a path over its length limit), have none: the view is empty. The pattern is what a metric or a log should name a request by -- its cardinality is the application's routes, where the raw path's is whatever the clients send.

```cpp
router.get("/users/:id", [](auto ctx) {
    std::string_view route = ctx->route_pattern();   // "/users/:id", for /users/42 and /users/7
    ctx->text(std::string(route));
});
```
<!-- src: qbm/http/src/qbm/http/routing/context.h:656 -->

The view is valid for the context's whole life, the router's destruction included: it points into the compiled route names, which the context's task chain retains (`qbm/http/src/qbm/http/routing/radix_tree.h:60`).

## Router observers

An observer derives from `qb::http::IRequestObserver<S>` and is registered on the router. `on_request` runs once the context exists, before the `PRE_ROUTING` hooks; `on_response` runs exactly once per context `on_request` saw, when its response is decided -- after the `PRE_RESPONSE_SEND` hooks and the hand-over to the session, so `ctx.response()` is what was sent and `ctx.route_pattern()` is set -- and before the `REQUEST_COMPLETE` hooks.

```cpp
struct SlowRequests final : qb::http::IRequestObserver<qb::http::DefaultSession> {
    void on_response(qb::http::Context<qb::http::DefaultSession> const &ctx,
                     qb::http::RequestEnd const &end) noexcept override {
        if (end.duration > std::chrono::milliseconds(250))
            qb::io::cout() << "slow: " << ctx.route_pattern() << '\n';
    }
};
router().add_observer(std::make_shared<SlowRequests>());
```
<!-- src: qbm/http/src/qbm/http/routing/observer.h:65; qbm/http/src/qbm/http/routing/router.h:294 -->

`RequestEnd` says how the request ended and how long it took (`qbm/http/src/qbm/http/routing/observer.h:39`):

| `outcome` | when |
|---|---|
| `RESPONDED` | the response was decided and handed to the session that received the request |
| `SESSION_GONE` | the response was decided after the session had gone -- the client left: nothing was sent, and the status is what the context ended with (503 for a cancellation) |
| `SUPPRESSED` | the context was finalized without a response (`suppress_response()`, a WebSocket upgrade handed over); told when the context is destroyed |

`duration` runs from the router receiving the request -- before the `PRE_ROUTING` hooks -- to the response handed to the session: the routing, the middleware, the handler however long an asynchronous one kept the request, the `PRE_RESPONSE_SEND` hooks and the protocol's serialization of the response (into the connection's output on HTTP/1.1, into frames on HTTP/2 and HTTP/3). The transmission to the peer is not in it, and neither are the reading and parsing of the request. For a suppressed response it runs to the context's destruction.

Both functions run on the router's thread and are `noexcept`: an exception escaping one terminates. An observer is shared by every request of its router, like a middleware: per-request state goes in the context. A context keeps the observers registered when it was created; `router.clear()` removes them all; a null observer is ignored.

A request a session answers without routing it reaches no observer: a request over a size limit, which the protocol refuses before routing (`414`, `431`, `413`), and the HTTP/3 server's fallback `404` when its router hands back no context at all (only a router without its core, which a constructed `Router` never is).

### What an unobserved router pays

Nothing it did not pay before but two tests of a null pointer per request, one when the router creates the context and one when the context is finalized, and the 16-byte store of the route pattern. The context grows by 40 bytes inside the allocation it already makes. A router with observers hands each context its observer list (one reference count), reads the monotonic clock when the request is received and when it ends, and makes one virtual call per observer at each end; nothing is allocated per request. Lifecycle hooks, by comparison, are copied into every context (a `std::function` each, and the hooks vector), and a duration measured with them needs its start time stored in the context's custom data.

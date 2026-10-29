# Observability: request ids, observers, access logs and metrics

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 3.3.0 (C++20 default, C++23 supported)

What a server says about the requests it answers, and how it says it without paying for it on the requests nobody observes: a request id carried from the client to the logs, router observers that see every request once at each end, a one-line-per-request access log, request metrics, and their exposition in the Prometheus text format.

**Prerequisites:** [the request context](./10-request-context.md) and [standard middleware](./08-standard-middleware.md). **See also:** the doc map [`README.md`](./README.md).

## The pieces, and where each one runs

| Piece | What it is | Installed with |
|---|---|---|
| Request id | `RequestIdMiddleware`: a chain middleware that gives each request an id, in the context (`request_id_slot`) and the response header | `router.use(...)`, first ([request id](./08-standard-middleware.md#request-id)) |
| Route pattern | `ctx->route_pattern()`: the pattern of the route that matched (`/users/:id`), never the raw path | nothing: the router sets it |
| Router observer | `IRequestObserver<S>`: told when each request is received and when its response is decided | `router.add_observer(...)` |
| Access log | `AccessLog<S>`: one line per request, Apache common or combined, or JSON | `router.add_observer(qb::http::access_log<S>(sink))` |
| Request metrics | `RequestMetrics<S>`: `qb_http_*` counts and durations by route pattern | `router.add_observer(...)`, published through a `qb::metrics::Registry` |

A chain middleware runs inside the chain of the route that matched: it sees a request only when a chain runs, and to act after the response it registers a lifecycle hook per request. An observer is the router's: it sees every request the router creates a context for, once at each end, whatever chain ran or did not, and costs nothing per request beyond what it does itself.

## The route pattern

`ctx->route_pattern()` names the route that matched, in its canonical form: its segments joined by `/`, captures with their `:` or `*` -- `/`, `/users/:id`, `/api/v1/items/:item` through a group, `/files/*path` -- whatever slashes the registration used. Two methods registered on one path share one pattern. A 405 names the route whose path matched; a 404, and a request the router answers before matching (a path over its length limit), have none: the view is empty. The pattern is what a metric or a log should name a request by -- its cardinality is the application's routes, where the raw path's is whatever the clients send.

```cpp
router.get("/users/:id", [](auto ctx) {
    std::string_view route = ctx->route_pattern();   // "/users/:id", for /users/42 and /users/7
    ctx->text(std::string(route));
});
```
<!-- src: qbm/http/src/qbm/http/routing/context.h:670 -->

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
<!-- src: qbm/http/src/qbm/http/routing/observer.h:70; qbm/http/src/qbm/http/routing/router.h:294 -->

`RequestEnd` says how the request ended and how long it took (`qbm/http/src/qbm/http/routing/observer.h:39`):

| `outcome` | when |
|---|---|
| `RESPONDED` | the response was decided and handed to the session that received the request |
| `SESSION_GONE` | the response was decided after the session had gone -- the client left: nothing was sent, and the status is what the context ended with (503 for a cancellation) |
| `SUPPRESSED` | the context was finalized without a response (`suppress_response()`, a WebSocket upgrade handed over); told when the context is destroyed |

`duration` runs from the router receiving the request -- before the `PRE_ROUTING` hooks -- to the response handed to the session: the routing, the middleware, the handler however long an asynchronous one kept the request, the `PRE_RESPONSE_SEND` hooks and the protocol's serialization of the response (into the connection's output on HTTP/1.1, into frames on HTTP/2 and HTTP/3). The transmission to the peer is not in it, and neither are the reading and parsing of the request. For a suppressed response it runs to the context's destruction.

Both functions run on the router's thread and are `noexcept`: an exception escaping one terminates. An observer is shared by every request of its router, like a middleware: per-request state goes in the context. A context keeps the observers registered when it was created; `router.clear()` removes them all; a null observer is ignored.

A request a session answers without routing it reaches no observer: a request over a size limit, which the protocol refuses before routing (`414`, `431`, `413`), a request whose target names no resource (`400`, Huly QB-1177), and the HTTP/3 server's fallback `404` when its router hands back no context at all (only a router without its core, which a constructed `Router` never is).

### What an unobserved router pays

A test of a null pointer when the router creates the context and one when the context is finalized, the route pattern carried from the matched node to the context, and the new members of the context -- 40 bytes inside the allocation it already makes -- initialised and destroyed. Measured with callgrind on g++-14 (release), routing one request through a router of 19 routes costs 22 to 25 more instructions than before for a match (of 5 500 to 8 000: +0.3 to +0.4 %) and 6 more for a 404. A router with observers hands each context its observer list (one reference count), reads the monotonic clock when the request is received and when it ends, and makes one virtual call per observer at each end; nothing is allocated per request. Lifecycle hooks, by comparison, are copied into every context (a `std::function` each, and the hooks vector), and a duration measured with them needs its start time stored in the context's custom data.

## The access log

`AccessLog<S>` is an observer that writes one line per request to a sink -- a callable taking a `std::string_view`, without the line feed -- in the format a formatter gives it. Three formats ship (`qb::http::access_log_format`):

| Format | Line |
|---|---|
| `common` | Apache's Common Log Format: `127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /a?b=1 HTTP/1.1" 200 2326` |
| `combined` (the default) | the common line, then `"<Referer>" "<User-Agent>"` (`-` when absent) |
| `json` | one object per line: `time` (RFC 3339, UTC, milliseconds), `remote`, `method`, `target`, `protocol`, `status`, `bytes`, `duration_seconds` (rounded to the microsecond), `referer`, `user_agent`, `request_id`, `route` (`null` when no route matched), `outcome` |

```cpp
#include <qbm/http/middleware/access_log.h>
#include <qbm/http/middleware/request_id.h>

router().use(qb::http::request_id_middleware<qb::http::DefaultSession>());
router().add_observer(qb::http::access_log<qb::http::DefaultSession>(
    [](std::string_view line) { qb::io::cout() << line << '\n'; },
    qb::http::access_log_format::json));
```
<!-- src: qbm/http/src/qbm/http/middleware/access_log.h:91 (AccessLog), qbm/http/src/qbm/http/middleware/access_log.h:160 (access_log) -->

The line is written when the request's response is decided, with what that response really carries: its status, the size of its body, after the `PRE_RESPONSE_SEND` hooks (compression included). A request the router answered without a chain -- a 404, the early 400 -- is logged like any other; a request whose client left is logged with `outcome` `session_gone` in JSON. The time is when the router received the request (UTC); `%b` is `-` for an empty body. The common and combined lines are Apache's byte for byte -- tools parse them -- so they carry no request id; the JSON line does, and a formatter of your own receives every field (`AccessLogRecord`). The quoted fields of the Apache formats escape `"`, `\` and every non-printable byte (`\"`, `\\`, `\xhh`); JSON escapes `"`, `\` and control characters, and copies other bytes as they are. The client's address comes from the session's `ip()`, empty once the session is gone. Stock socket transports cache a successful peer lookup for the socket's lifetime between ownership/connection changes; custom transports keep their own lookup behavior. The accessor still returns a string value, so caching is not an allocation-free guarantee. The line is formatted into a buffer the instance reuses; an exception from the formatter or the sink is contained and logged.
<!-- src: qb/src/qb/io/async/tcp/client.h:151-156; qb/src/qb/io/system/sys__socket.h:1218-1229; qbm/http/src/qbm/http/middleware/access_log.h:110-118 -->

`qbm-http-bench-http1-access-log-loopback` compares logging off, common and JSON on batches of 32 real HTTP/1 loopback requests over one persistent connection. The fixture checks status/body of every response, routed/logged totals, connection liveness and presence of the peer address in each line. Input construction and validation are outside the timed batch; socket, client, server and event-loop work remain inside. Both warm and first-request cells select `UseRealTime()`: durations and rates use their instrumented wall-clock windows. Timing-boundary work remains part of the instrument, so these are not pure per-operation costs; historical CPU-clock results remain a separate series. The warm cell measures the whole batch, not an isolated formatter call or per-request latency percentile. A separate first-request cell opens a fresh connection outside its timed interval and measures exactly one request; setup and teardown remain outside. It fixes eight iterations per repetition: automatic calibration would create thousands of TCP pairs and can exhaust ephemeral ports before a valid sample completes. Both sides use the same bound, and the first-request dispersion must be reported separately. Raw durations and host conditions are required before making a performance claim.
<!-- src: qbm/http/tests/benchmark/http1/access-log-loopback.bench.cpp:21-74,87-189,266-282; qbm/http/tests/CMakeLists.txt:289 -->

What a line costs, measured with callgrind on g++-14 (release) per request routed through a router of 19 routes, for a request with a query string, a 101-byte `User-Agent`, a `Referer` and a request id (16 150 instructions with no observer): `common` about +1 520 instructions, `combined` +2 040, `json` +2 440; for a request with none of those, +1 270, +1 370 and +1 740. That is the observer's two clock reads, the record -- three lookups: `Referer`, `User-Agent`, the request id -- and the line itself: it is built in a stack buffer and appended once to the reused one, the quoted fields are scanned sixteen bytes at a time (eight where SSE2 is not the baseline) and copied whole between the bytes they escape, and the formatted second is kept per thread and reformatted only when the second changes. Those earlier observer-fixture counts excluded the session's peer-address lookup and copy. The persistent loopback fixture above includes the stock transport's cache path and the surrounding request/response flow; its numbers are not interchangeable with these instruction counts.

## Request metrics

`RequestMetrics<S>` is an observer that counts the requests of its router in the `qb::metrics` model (`<qb/core/metrics.h>`):

| Family | Type | Labels |
|---|---|---|
| `qb_http_requests_total` | counter | `method`, `route`, `status` |
| `qb_http_request_duration_seconds` | histogram (`_bucket`, `_sum`, `_count`) | `method`, `route` |
| `qb_http_requests_in_flight` | gauge | -- |
| `qb_http_connections` (from `add_connections`) | gauge | `protocol` |

`route` is the route pattern, `unmatched` for a request no route matched. The duration is `RequestEnd::duration` -- from the router receiving the request to the response handed to the session, transmission excluded -- in buckets of `qb::metrics::default_duration_buckets` (5 ms to 10 s) unless `RequestMetricsOptions::with_buckets` gives others. The counts are plain integers of the router's thread: a series is allocated the first time it is seen, and nothing after. Measured the same way, `RequestMetrics` costs about +530 instructions a request on the request above (+410 on a bare one): the observer's two clock reads, then the route's series found by its pattern (a hash of the pattern: about a hundred instructions), its count for the method and status, and its bucket.

```cpp
#include <qb/core/metrics_registry.h>
#include <qbm/http/middleware/metrics.h>

// in the server actor's onInit(), on a core that has a qb::metrics::Registry:
_metrics = qb::http::request_metrics<qb::http::DefaultSession>();
router().add_observer(_metrics);
_source = getService<qb::metrics::Registry>()->add_source([this](qb::metrics::snapshot &s) {
    _metrics->collect(s);
    qb::http::add_connections(s, "http/1.1", session_count());
});
```
<!-- src: qbm/http/src/qbm/http/middleware/metrics.h:127 (RequestMetrics), qbm/http/src/qbm/http/middleware/metrics.h:185 (add_connections) -->

Publishing through the core's registry (`add_source`) is what lets a scrape read the counts on their own core. One `RequestMetrics` per router; several servers on several cores each publish theirs, and a scrape sums the series they share. The ticket that asked for them called them `MetricsMiddleware` and `AccessLogMiddleware`: they are observers, not chain middleware, and are named for what they are.

## The `/metrics` endpoint

`metrics_handler<S>(actor, options)` is a coroutine route handler: it scrapes every core's `qb::metrics::Registry` through the registry of the actor's own core -- the core counters of each core, the sources each core's actors added, `RequestMetrics` among them -- and answers the Prometheus text format 0.0.4 (`metrics_response`: 200, `Content-Type: text/plain; version=0.0.4; charset=utf-8`). Nothing mounts it: it exposes the process's internals, so put it behind authentication or on a listener of its own.

```cpp
#include <qb/core/metrics_registry.h>
#include <qbm/http/middleware/metrics.h>

// main(): a registry on every core the scrape asks
for (qb::CoreId core : {0, 1})
    engine.addActor<qb::metrics::Registry>(core);

// the server actor's onInit():
router().get("/metrics", qb::http::metrics_handler<qb::http::DefaultSession>(
                             *this, qb::http::MetricsEndpointOptions{}.with_timeout(std::chrono::milliseconds(500))));
```
<!-- src: qbm/http/src/qbm/http/middleware/metrics.h:238 (metrics_handler), qbm/http/src/qbm/http/middleware/metrics.h:190 (MetricsEndpointOptions) -->

Each core is asked at the same time and has `timeout` to answer; a core that does not -- no registry there, or a handler holding its thread -- is `qb_scrape_core_up{core="N"} 0` in the answer, never an error, and `qb_scrape_duration_seconds` says how long the scrape took. `options.cores` limits the scrape to some cores; empty, it asks every core of the engine. A scrape from a core that has no registry is a `500`. Between two scrapes nothing runs: every counter stays a plain integer of the core that owns it, read on that core when the scrape asks (`qb/src/qb/core/metrics_registry.h`, and [the engine's counters](https://github.com/isndev/qb/blob/main/readme/4_qb_core/engine.md)).

A Prometheus scrape configuration needs nothing else:

```yaml
scrape_configs:
  - job_name: my-qb-service
    metrics_path: /metrics
    static_configs:
      - targets: ["localhost:8080"]
```

## A complete two-core monitoring example

`07-applications/04-observability` in qb-examples combines an HTTP application on core 0
with PostgreSQL `SELECT 1` and Redis `PING` on core 1. Each core has a `qb::metrics::Registry`.
The database/client use the explicit `<qbm/pgsql/metrics.h>` and `<qbm/redis/metrics.h>`
snapshot adapters; they do not install completion hooks. Redis latency remains explicitly
opt-in. Source handles are removed on their owner core before client teardown.

The application listens on loopback port 18080; its **separate** metrics server defaults to
loopback port 19090. The example includes a pinned Compose stack, Prometheus scrape
configuration, provisioned Grafana dashboard and an executable smoke check of both core
series and real backend operations. The README describes the explicit bind override needed
for a container to reach the native process; publishing a metrics listener beyond loopback
requires a monitoring network or authentication boundary.

For a standalone HTTP loop, no registry is required: construct a snapshot on its thread,
call `qb::metrics::describe_dispatch(snapshot, loop.dispatch_timing(), loop.nb_invoked_event(),
labels)`, then `qb::http::metrics_response(*ctx, snapshot)`. The last-run event count is a
gauge, not a lifetime counter; watcher dispatch timing excludes deferred work and coroutine
resumes outside that dispatch. The model links `qb::core` even without actor instances.

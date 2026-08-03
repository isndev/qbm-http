# Advanced topics: streaming, connection lifecycle, performance, actor composition

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 3.0.0 (C++20 default, C++23 supported)

How qbm-http handles chunked bodies, persistent connections and protocol upgrades, where the performance levers are, and how an HTTP server composes with the rest of your qb actor system.

**Prerequisites:** [Core HTTP concepts](./01-core-concepts.md), [The request context](./10-request-context.md), the qb framework [`readme/`](https://github.com/isndev/qb/tree/main/readme/) (actors, `qb-io` async). — **See also:** [HTTP message body deep dive](./02-body-deep-dive.md), [Custom middleware](./09-custom-middleware.md), [HTTP/2 protocol specifics](./17-http2-protocol.md), [WebSocket](./20-websocket.md).

## Summary

This page is the meeting point of several earlier ones. It covers four things the day-to-day guides only touch: how the body is framed on the wire (chunked transfer encoding, and what "streaming" does and does not mean here), how a connection persists or upgrades across requests (keep-alive, pipelining, the WebSocket handoff), the performance characteristics worth knowing before you tune anything, and how an HTTP server sits inside the actor model alongside your other actors. Every claim is grounded in the shipped headers — `qbm/http/src/qbm/http/1.1/http.h`, `qbm/http/src/qbm/http/chunk.h`, `qbm/http/src/qbm/http/body.h`, `qbm/http/src/qbm/http/response.cpp`, and `qbm/http/src/qbm/http/routing/context.h`.

There is no separate "streaming API" to learn. The body is a `qb::allocator::pipe<char>` (see [Body deep dive](./02-body-deep-dive.md)), the connection is a qb-io session, and the server is an actor mixin. The advanced behavior falls out of composing those three primitives correctly.

## Chunked transfer encoding and what "streaming" means

`qb::http::Chunk` (`qbm/http/src/qbm/http/chunk.h`) is a non-owning `{const char* data, std::size_t size}` view of one chunked-transfer-encoding segment. A default-constructed `Chunk{}` (size 0) is the terminating chunk that ends the stream.

```cpp
// src: qbm/http/src/qbm/http/chunk.h:42-80
qb::http::Chunk seg(buffer.data(), buffer.size());  // one chunk, non-owning
qb::http::Chunk last;                                // size 0 -> end of stream
```

Because `Chunk` does not own its bytes, the referenced memory must stay valid for as long as the chunk is serialized — exactly the lifetime discipline described under [`string_view` lifetime](#string_view-and-lifetime) below.

**Inbound (parsing).** The HTTP/1.1 parser handles `Transfer-Encoding: chunked` transparently. It de-chunks the body into the message's `qb::allocator::pipe<char>` as fragments arrive, bounded by `protocol_limits::MAX_CHUNK_SIZE` (16 MB per chunk) and the overall body cap; a chunk over the limit fails the connection (`qbm/http/src/qbm/http/1.1/protocol/base.h:56-57,373-374`). By the time your handler runs, `ctx->request().body()` holds the fully reassembled body. You never see individual chunks at the routing layer.

**Outbound (serialization).** This is the part that surprises people. When you set `Transfer-Encoding: chunked` on a `Response`, the serializer in `pipe<char>::put<Response>` emits the response body as a *single* chunk followed by the terminating chunk, in one write:

```cpp
// src: qbm/http/src/qbm/http/response.cpp:327-329
if (transfer.chunked) {
    *this << qb::http::endl
          << qb::http::Chunk(r.body().raw().begin(), length)  // whole body, one chunk
          << qb::http::Chunk();                                // terminator
}
```

So setting `Transfer-Encoding: chunked` on a high-level `Response` changes the *framing* (no `Content-Length`; the body arrives as chunks), but it does **not** let you trickle bytes to the client over time from a single handler. The handler still assembles the full body, then `ctx->complete()` serializes and sends it. The serializer also rejects contradictory framing: declaring both `Transfer-Encoding` and `Content-Length`, or chunked encoding on a status that must not carry a body, throws `std::length_error` (`qbm/http/src/qbm/http/response.cpp:243-270`) — which the server session catches and turns into a connection failure rather than letting it escape the noexcept I/O boundary.

If you need true incremental, time-spaced delivery (server-sent events, a long-lived download generated on the fly), you have three options, in increasing order of fit:

- **Buffer and send chunked.** Fine when the body is large but bounded and produced quickly. Build the body, set `Transfer-Encoding: chunked`, `complete()`.
- **Write `Chunk`s directly to a long-lived session.** The body-level helpers `body().add_chunk(chunk)` and `body().add_final_chunk()` (`qbm/http/src/qbm/http/body.h:224-238`) append chunk framing into the pipe; combined with direct session writes (`*session << ...`) you can emit chunks across multiple event-loop ticks. This is a low-level pattern: you own the framing, the `Content-Length`/`Transfer-Encoding` headers, and the terminating chunk, and you must call `ctx->suppress_response()` so the context does not also send a response (see [actor composition](#composing-with-qb-actors)).
- **Use a protocol designed for streaming.** HTTP/2 DATA frames (`END_STREAM`) and HTTP/3 give you real multiplexed streaming; WebSocket gives you bidirectional message framing. For genuinely streaming workloads, reach for [HTTP/2](./17-http2-protocol.md) or [WebSocket](./20-websocket.md) rather than HTTP/1.1 chunking. These are feature-gated: HTTP/2 and WebSocket compile only with `QB_HAS_SSL`, and HTTP/3 needs `QBM_HTTP_HAS_HTTP3` (`QB_HAS_SSL` + `QB_HAS_QUIC` + libnghttp3). HTTP/1.1 chunking has no such gate.

> HTTP/2 and HTTP/3 do not use chunked transfer encoding. `Transfer-Encoding` is a hop-by-hop header forbidden in HTTP/2 messages (`qb::http::well_known::is_hop_by_hop`); streaming there is expressed with DATA frames and the `END_STREAM` flag. See [HTTP/2 protocol specifics](./17-http2-protocol.md).

## Keep-alive, pipelining, and the connection lifecycle

The HTTP/1.1 server session (`internal::session` in `qbm/http/src/qbm/http/1.1/http.h`) owns the persistence decision per connection.

**Keep-alive.** Two inputs decide whether a connection survives a response: the per-message `keep_alive` flag the parser computes from the request (llhttp's `http_should_keep_alive`, factoring HTTP version and the `Connection` header), and an application-level override you set with `session::keep_alive(bool)` (`qbm/http/src/qbm/http/1.1/http.h:449-451`). The effective decision is `request.keep_alive || session_override`. After the response is fully transmitted (`event::eos`), the session either closes — `disconnect(DisconnectedReason::ResponseTransmitted)` — or stays open for the next request:

```cpp
// src: qbm/http/src/qbm/http/1.1/http.h:342-346
if (!_active_should_keep_alive) {
    this->disconnect(DisconnectedReason::ResponseTransmitted);
    return;
}
start_next_request_if_possible();
```

The session also normalizes the outgoing `Connection` header for you: it adds `Connection: close` when the connection will not persist, and `Connection: keep-alive` for an HTTP/1.0 response that will (`qbm/http/src/qbm/http/1.1/http.h:169-175`). A response that itself carries `Connection: close` forces the connection shut regardless of the keep-alive inputs.

**Pipelining.** While a response is in flight, further requests on the same connection queue rather than interleave. The queue is bounded by `session::max_pipelined_requests(std::size_t)` (default 128). Exceeding the cap disconnects the connection with `DisconnectedReason::ByProtocolError` (`qbm/http/src/qbm/http/1.1/http.h:137,255-262`). Each queued request is routed in order once the active context finishes (`start_next_request_if_possible`), so handlers for one connection never run concurrently — they are serialized on the session's I/O thread.

**Inactivity timeout.** A session arms a 60-second inactivity timeout on construction (`setTimeout(std::chrono::seconds(60))`, `qbm/http/src/qbm/http/1.1/http.h:426`) and re-arms it on each write. On expiry it disconnects with `DisconnectedReason::ByTimeout` unless your session type defines an `on(event::timeout)` handler. Tune it from your session's constructor with `this->setTimeout(...)` (a qb-io facility; see the qb [`readme/`](https://github.com/isndev/qb/tree/main/readme/)).

**HEAD requests.** The session strips the response body for a `HEAD` request while preserving `Content-Length`, so a `HEAD` reply reports the size the corresponding `GET` would return without sending the bytes (`qbm/http/src/qbm/http/1.1/http.h:162-167`).

## Protocol upgrade: HTTP to WebSocket

A WebSocket connection begins life as an HTTP/1.1 session. The opening `GET` with `Upgrade: websocket` is parsed as a normal HTTP request; your session's `on(Protocol::request&&)` validates it and calls `switch_protocol<ws::protocol>` to hand the live connection from HTTP request/response parsing to WebSocket framing. After a successful switch, the connection no longer returns to HTTP parsing — it is a WebSocket for the rest of its life.

The lifecycle hazard is the request context. When you upgrade (or otherwise transfer ownership of the connection), call `ctx->suppress_response()` so the `Context` destructor does not send a stale, moved-from HTTP response over a transport that now speaks WebSocket (`qbm/http/src/qbm/http/routing/context.h:1250-1255`). If you reject a failed upgrade with an HTTP error response, send it and use `close_after_deliver()` so the connection closes cleanly after the rejection flushes. The full upgrade walkthrough — handshake validation, subprotocol negotiation, the callback and coroutine session APIs — is in [WebSocket](./20-websocket.md) and [WebSocket coroutines](./21-websocket-coroutines.md).

```cpp
// src: qbm/http/tests/system/ws/ws-lifecycle.cpp:109-114 (shape)
void on(Protocol::request&& request) {      // HTTP upgrade arrives
    if (!this->switch_protocol<WS_Protocol>(*this, request))
        disconnect();
}
```

## Performance characteristics

These are the levers that matter, grounded in how the types are built rather than benchmarks.

- **Zero-copy reads via `string_view`.** Header lookups and many body conversions hand back `std::string_view` over the parse buffer rather than copying. Reading request data in a synchronous handler is allocation-free; the cost shows up only when you copy out. See [lifetime](#string_view-and-lifetime).

- **The body is a `qb::allocator::pipe<char>`.** `qb::http::Body` stores its payload in qb-io's I/O-optimized ring-style allocator (`qbm/http/src/qbm/http/body.h`, [Body deep dive](./02-body-deep-dive.md)). Appends and assigns avoid reallocation where possible, and `body.raw()` gives you the pipe directly for custom (de)serialization. Use move assignment to hand large payloads in without copying:

  ```cpp
  // src: qbm/http/src/qbm/http/body.h:203-204 (move operator=)
  std::string payload = build_large_json();
  ctx->response().body() = std::move(payload);   // moves, does not copy
  ```

  Appendable types are constrained at compile time by `Body::is_body_appendable` (byte-like ranges, `Chunk`/`Multipart`/`qb::json`, or arithmetic which is stringified); other types are rejected by the compiler rather than producing malformed output (`qbm/http/src/qbm/http/body.h:104-158`). `Form` is deliberately not appendable — assign it wholesale (`body = form`), not `body << form`.

- **The router compiles once.** `router().compile()` builds an optimized radix tree for path matching. Call it once, after all routes are defined and before serving; it is not designed to be re-run on a hot path. See [Routing overview](./03-routing-overview.md).

- **Middleware runs per request.** Global middleware executes for every request on the matched chain; group- and controller-scoped middleware narrows that to the routes that need it. Scope middleware to the smallest node that covers the routes — inherited middleware runs parent-first, then the node's own, then the handler (`qbm/http/src/qbm/http/routing/route_group.h`, [Route groups](./05-route-groups.md)). Keep per-request work proportional to what the route actually needs.

- **One thread per connection, no locks on the hot path.** A session and its context are confined to the `VirtualCore` (thread) that owns the connection. Handlers for one connection are serialized; the framework takes no locks to dispatch them. This is what makes the body and context safe to touch without synchronization — and what makes blocking inside a handler a correctness problem, not just a latency one (see below).

- **Compression is opt-in and automatic where enabled.** With `QB_HAS_COMPRESSION`, the one-shot client sets `Accept-Encoding` and decompresses responses; setting `Content-Encoding` on a request body compresses it (`qbm/http/src/qbm/http/1.1/http.h:724-728,748-758`). On the server, set `Content-Encoding` on the response, or use the compression middleware ([Standard middleware](./08-standard-middleware.md)).

### Never block the event loop

A handler runs on the I/O thread. Blocking it — a synchronous database call, a sleeping syscall, a busy loop — stalls every other connection on that core. For I/O-bound work, return control to the loop and finish the response from a continuation:

- **Defer with `qb::io::async::callback`.** Schedule a continuation after a `qb::duration` delay; capture the context `shared_ptr` and complete from the callback (pattern below).
- **Hand work to another actor.** Send an event to a worker actor and complete the context when its reply arrives ([actor composition](#composing-with-qb-actors)).
- **Use the coroutine handlers.** `co_await` an awaiter (e.g. an outbound `qb::http::GET`) inside a coroutine route handler; the framework suspends and resumes you on the same thread without blocking it ([Custom middleware](./09-custom-middleware.md), [Async HTTP client](./14-async-http-client.md)).

## Asynchronous handlers and context lifecycle

When a handler or middleware starts async work and returns before completing, the request stays alive because the `Context` is a `std::shared_ptr`. Capture it by value into the continuation; complete it there.

```cpp
// In a route handler, IAsyncTask::execute, or ICustomRoute::process
auto ctx_kept = ctx;                         // shared_ptr keeps the request alive
my_service.fetch(key, [ctx_kept](Result r) {
    if (ctx_kept->is_cancelled())            // connection may have dropped
        return;                              // do NOT complete a cancelled context
    ctx_kept->response().body() = serialize(r);
    ctx_kept->complete(qb::http::AsyncTaskResult::COMPLETE);
});
// handler returns; the request is now pending on the captured context
```

Three rules carry real weight here, all enforced or documented in the headers:

1. **Something must eventually call `ctx->complete(...)`** (or, for functional middleware, `next()`), or the request hangs forever. Every `IAsyncTask`/handler/`ICustomRoute`/`IMiddleware` path is on the hook for it (`qbm/http/src/qbm/http/routing/async_task.h`, `custom_route.h`, `types.h`). The terminal response helpers — `json`, `text`, `html`, `redirect`, `no_content`, the error helpers — call `complete(COMPLETE)` for you, so set headers and body *before* calling them; only `status()` is non-terminal and chainable (`qbm/http/src/qbm/http/routing/context.h:905-1057`).

2. **`cancel()` must not call `complete()`.** If your task supports cancellation, its `cancel()` implementation tears down the pending work but leaves finalization to the `Context` — calling `complete()` from `cancel()` is a contract violation (`qbm/http/src/qbm/http/routing/async_task.h:62-76`). `complete()` is idempotent after finalization and `is_cancelled()` is sticky (`qbm/http/src/qbm/http/routing/context.h:145-168,1068-1075`), so a late callback that checks `is_cancelled()` first is safe.

3. **Check `is_cancelled()` before doing work in a late callback.** The connection may have dropped or timed out while your async operation was in flight. The context survives (you hold a `shared_ptr`), but completing it does nothing useful.

## Composing with qb actors

The HTTP server is an ordinary qb actor. You make one by mixing `qb::http::Server<>` into a `qb::Actor`, defining routes in `onInit`, compiling, then `listen` + `start`:

```cpp
// src: qbm/http/README.md (Quickstart: a server)
#include <qbm/http/http.h>
#include <qb/main.h>

class ApiServer : public qb::Actor, public qb::http::Server<> {
public:
    qb::io::async::task<bool> onInit() override {
        router().get("/health", [](auto ctx) {
            ctx->response().body() = "ok";
            ctx->complete();
        });
        router().compile();                       // once, before serving
        if (listen({"tcp://0.0.0.0:8080"})) {     // qb::io::uri; returns "is listening"
            start();
            co_return true;
        }
        co_return false;
    }
};

int main() {
    qb::Main engine;
    engine.addActor<ApiServer>(0);                // pin to core 0
    engine.start();                               // async by default: returns immediately
    engine.join();                                // blocks until every actor terminates
    return 0;
}
```

`make_server()` / `qb::http::make_server()` returns a `std::unique_ptr<Server<>>` for the cases where you want the server as a member rather than a base class — but the actor-mixin form above is the idiomatic one, because it puts the server's event loop on a `VirtualCore` you control.

Three composition patterns follow from the actor model:

**Pin servers to cores; run several.** Each `Server` actor runs its accept loop and all its sessions on one core. Place a server on a dedicated core, or run several server actors on different cores behind a load balancer, by passing the core index to `addActor`. Sessions never migrate between cores, so there is no cross-core sharing to synchronize within a server.

**Hand request work to worker actors.** A handler holds the `Context` `shared_ptr` and can reach the connection through `ctx->session()` (a `std::shared_ptr<SessionType>` obtained by locking an internal weak pointer; it may be empty if the connection is gone — `qbm/http/src/qbm/http/routing/context.h:471-482`). The clean pattern is: capture the context, `push` an event to a worker actor, and complete the context from the actor's reply handler. Because the worker runs on its own core, this offloads CPU- or I/O-bound work off the I/O thread without blocking it. Mind that the reply handler runs on the *server* actor's core (qb routes the event back), so completing the captured context there is thread-correct.

```cpp
// In a route handler on the server actor
auto ctx_kept = ctx;
push<WorkRequest>(worker_id, ctx_kept, std::move(ctx->request().body()));
// ...later, in the server actor's reply handler:
void on(WorkDone& ev) {
    if (!ev.ctx->is_cancelled()) {
        ev.ctx->response().body() = std::move(ev.result);
        ev.ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    }
}
```

Carrying a `std::shared_ptr<Context<Session>>` inside an event is sound: the context outlives the round-trip because every party holds a reference, and only the server actor's core ever calls `complete()` on it. See the qb [`readme/`](https://github.com/isndev/qb/tree/main/readme/) for actor referencing, events, and `push`.

**Drive the client from any actor.** The one-shot `GET`/`POST`/`REQUEST` helpers and the persistent `qb::http1::Client` run on whatever core their actor lives on, using that core's event loop. An actor can be both an HTTP server and an HTTP client — handle inbound requests and fan out to upstream services from the same actor — because both sit on the one qb-io loop. See [Asynchronous HTTP client](./14-async-http-client.md).

## `string_view` and lifetime

`std::string_view` returned from `RequestView`/`ResponseView`, from header accessors, or from `Body::as<std::string_view>()` is **non-owning**. It points into the parse buffer or the body's pipe.

- Within a single synchronous handler or middleware `process()` call, using these views is safe — the underlying buffer outlives the call.
- The moment data must outlive the request buffer — stored in an async callback, carried in an event to another actor, cached past the response — **copy it into an owning type** (`std::string`, `std::vector<char>`). A view that outlives its buffer is a dangling read and undefined behavior.
- `Chunk` carries the same rule: it borrows its bytes (`qbm/http/src/qbm/http/chunk.h:32-33,57-59`). Keep the source alive until the chunk is serialized.

## Pitfalls

- **Expecting `Transfer-Encoding: chunked` to stream incrementally from one handler.** It changes framing, not timing — the whole body is emitted as one chunk at `complete()` (`qbm/http/src/qbm/http/response.cpp:327-329`). For real streaming use direct session writes, HTTP/2, or WebSocket.
- **Setting both `Content-Length` and `Transfer-Encoding`.** The response serializer throws `std::length_error`, which the session turns into a connection failure (`qbm/http/src/qbm/http/response.cpp:264-266`). Set one framing mode, not both.
- **Blocking inside a handler.** It stalls every connection on that core. Defer with `qb::io::async::callback`, offload to a worker actor, or `co_await`.
- **Forgetting `ctx->complete()`.** The request hangs until the inactivity timeout closes it. Terminal response helpers complete for you; raw `body =`/`status()` do not.
- **Calling `complete()` from `cancel()`.** Contract violation — the `Context` manages its own finalization (`qbm/http/src/qbm/http/routing/async_task.h:62-76`).
- **Omitting `suppress_response()` on upgrade or ownership transfer.** The `Context` destructor will send a stale HTTP response over a transport that has moved on (`qbm/http/src/qbm/http/routing/context.h:1250-1255`).
- **Holding a `string_view` (or `Chunk`) past the request buffer.** Copy into an owning type before crossing an async or inter-actor boundary.
- **Re-compiling the router on the hot path.** `compile()` is a setup-time, single-threaded operation; the router is not safe to mutate while serving.

## See also

- [HTTP message body deep dive](./02-body-deep-dive.md) — the `pipe<char>`-backed `Body`, conversions, compression.
- [Custom middleware](./09-custom-middleware.md) — functional, class-based, and coroutine middleware; the async task model.
- [The request context](./10-request-context.md) — `complete`/`cancel`, response helpers, typed data slots, lifecycle hooks.
- [Asynchronous HTTP client](./14-async-http-client.md) — callback and coroutine clients, the persistent `http1::Client`.
- [HTTP/2 protocol specifics](./17-http2-protocol.md) — streams, flow control, and DATA-frame streaming.
- [WebSocket](./20-websocket.md) and [WebSocket coroutines](./21-websocket-coroutines.md) — the upgrade path and bidirectional framing.
- The qb framework [`readme/`](https://github.com/isndev/qb/tree/main/readme/) — actors, events, `push`, `qb-io` async, and coroutines.

---

Previous: [HTTP message parsing](./15-http-parsing.md) · Next: [HTTP/2 protocol specifics](./17-http2-protocol.md) · Up: [Documentation map](./README.md)

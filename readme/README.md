# qbm-http documentation map

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 2.0.0 (C++20 default, C++23 supported)

This is the table of contents for the qbm-http narrative documentation: twenty-one numbered pages covering HTTP/1.1, HTTP/2, HTTP/3, WebSocket, routing, middleware, authentication, and validation, ordered as a learning path.

**Prerequisites:** working knowledge of the qb actor framework — see [`qb/README.md`](../../../qb/README.md) and the qb [`readme/`](../../../qb/readme/) docs for actors, `qb-io` async, and coroutines. **See also:** the module front door [`../README.md`](../README.md) for positioning, the build/feature matrix, and a 60-second quickstart.

## What this module is

qbm-http is a compiled library — not header-only — that adds HTTP and WebSocket to the qb framework. The build registers it through `qb_register_module` with a `SOURCES` list (`qbm/http/CMakeLists.txt`), so consuming it links a real archive rather than only including headers. The umbrella header is `<http/http.h>`.

The module is layered. HTTP/1.1 (client and server), the message types, routing, middleware, and validation are always available. Several capabilities are gated behind build features and are documented as such throughout these pages:

| Feature | Build gate | Notes |
|---|---|---|
| WebSocket (and WSS), HTTPS, JWT, the `auth` subsystem, HTTP/2 | `QB_HAS_SSL` | Derived upstream from OpenSSL detection; propagated `PUBLIC` to consumers. WebSocket needs OpenSSL for the handshake hash, so `<ws/ws.h>` `#error`s without it — the whole subsystem is gated, not only the secure transport. |
| HTTP/3 over QUIC | `QBM_HTTP_HAS_HTTP3` | Requires `QB_HAS_SSL` + `QB_HAS_QUIC` + libnghttp3. |

If your build lacks `QB_HAS_SSL`, the SSL-backed pages still describe the API surface but the code will not compile until SSL is present. Each page states its gate where one applies.

## Integration in one place

You consume qbm-http through the qb module loader, not `find_package`:

<!-- src: qbm/http/README.md -->
```cmake
add_subdirectory(qb)                                   # the framework first
qb_load_modules("${CMAKE_CURRENT_SOURCE_DIR}/qbm")     # discovers and adds qbm modules
# ...
target_link_libraries(your_app PRIVATE qbm::http)      # PUBLIC deps: qb::core, qb::io, vendored llhttp
```

```cpp
#include <http/http.h>   // umbrella: HTTP/1.1 always; HTTP/2 + WebSocket under QB_HAS_SSL;
                         //           HTTP/3 under QBM_HTTP_HAS_HTTP3
```

See [`../README.md`](../README.md) for the full build matrix and a runnable example. To detect features from application code, test `QB_HAS_SSL` (propagated `PUBLIC` from the framework) for the SSL-backed surface and `QBM_HTTP_HAS_HTTP3` (defined `PUBLIC` on the module target) for HTTP/3. The `QBM_HTTP_VERSION` and `QBM_HTTP_HAS_SSL` markers are compiled into the module `PRIVATE` and are not visible to consumers; do not gate your code on them.

## A note on time vocabulary

These pages use qb's chrono types deliberately, and the distinction matters when you read the API:

- **`qb::duration`** — cookie `max_age`/`expires_in`, CORS preflight max-age, rate-limit windows, and connection/request timeouts.
- **`std::chrono::seconds`** — JWT `exp`/`nbf` leeway and lifetimes, kept as seconds because RFC 7519 NumericDate is a whole-second boundary.
- **`qb::wall_time`** — the HTTP date API (`qb::http::date`), which bridges to `std::chrono::system_clock` for RFC 1123/850/asctime formatting and parsing.

## Pages

Read top to bottom for a first pass. Each row links the page and gives its one-line scope; the **Gate** column flags pages whose primary subject requires a build feature.

| # | Page | What it covers | Gate |
|---|---|---|---|
| 01 | [Core HTTP concepts](./01-core-concepts.md) | `Request`, `Response`, `Method`, `Status`, `Headers`, and the shared message model. | — |
| 02 | [HTTP message body deep dive](./02-body-deep-dive.md) | `qb::http::Body` over `qb::allocator::pipe<char>`: typed conversions, chunks, gzip/deflate. | — |
| 03 | [Routing overview](./03-routing-overview.md) | The `Router`, path matching, path parameters, and the compiled handler tree. | — |
| 04 | [Defining routes](./04-defining-routes.md) | `get`/`post`/`put`/`del`/…, lambda handlers, and `ICustomRoute` class-based routes. | — |
| 05 | [Route groups](./05-route-groups.md) | `RouteGroup`: shared path prefixes and group-scoped middleware. | — |
| 06 | [Controllers](./06-controllers.md) | `Controller<Session>` and `MEMBER_HANDLER` for class-based route organization. | — |
| 07 | [Middleware overview](./07-middleware.md) | The middleware concept, the task chain, and execution flow through a request. | — |
| 08 | [Standard middleware](./08-standard-middleware.md) | The shipped middleware set: CORS, compression, logging, rate-limit, security headers, and more. | — |
| 09 | [Custom middleware](./09-custom-middleware.md) | Writing your own functional or class-based middleware and coroutine middleware. | — |
| 10 | [The request context](./10-request-context.md) | `Context<Session>`: request/response access, response helpers, typed data slots, lifecycle hooks, `complete`/`cancel`. | — |
| 11 | [Authentication system](./11-authentication.md) | `auth::Options`/`User`/`Manager` for JWT issue and verify; the auth and JWT middleware. | SSL |
| 12 | [Validation system](./12-validation.md) | `RequestValidator`, `SchemaValidator`, parameter rules, and sanitizers. | — |
| 13 | [Error handling strategies](./13-error-handling.md) | The router error chain, the not-found handler, and error-handling middleware. | — |
| 14 | [Asynchronous HTTP client](./14-async-http-client.md) | Callback `GET`/`POST`/`REQUEST`, the coroutine overloads with `run_sync`, and the persistent `http1::Client`. | — |
| 15 | [HTTP message parsing](./15-http-parsing.md) | The llhttp-based `Parser` and the `qb::protocol::http` wire protocol. | — |
| 16 | [Advanced topics and best practices](./16-advanced-topics.md) | `string_view` usage, body handling, pipelining, and performance guidance. | — |
| 17 | [HTTP/2 protocol specifics](./17-http2-protocol.md) | `http2::Server`/`Client`, HPACK, streams, and flow control over TLS+ALPN h2. | SSL |
| 18 | [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md) | Secure client and server, certificates, and ALPN negotiation. | SSL |
| 19 | [HTTP/3 protocol](./19-http3-protocol.md) | QUIC transport, the nghttp3 adapter, `http3::Client`/`Server`, and the dual-stack server. | HTTP/3 |
| 20 | [WebSocket](./20-websocket.md) | HTTP/1.1 upgrade, RFC 6455 framing, the CRTP/callback `WebSocket` client, and WSS. | SSL |
| 21 | [WebSocket coroutines](./21-websocket-coroutines.md) | `coro_client`, `coro_session`, the awaiters, and connection lifecycle. | SSL |

## Suggested learning order

The numbering is the recommended path, but you do not need all of it for every task:

1. **Foundations (01–02).** Start here regardless of role — every other page assumes the message and body model.
2. **Build a server (03–10).** Routing, middleware, and the request context are the core of server-side work. Read these in order; controllers and groups build on plain routes.
3. **Harden it (11–13).** Authentication, validation, and error handling layer onto the routing model. Page 11 requires `QB_HAS_SSL`.
4. **Talk to other services (14–15).** The client APIs and the parser stand alone; jump here directly if you only need an HTTP client.
5. **Scale and modernize the transport (16–19).** Performance practices, then HTTP/2, HTTPS, and HTTP/3 in increasing build-requirement order.
6. **Real-time (20–21).** WebSocket, callback-style first, then the coroutine API. Both pages require `QB_HAS_SSL`.

If you only want an async HTTP client, read 01, 02, and 14. If you are standing up a JSON API server, read 01–13. For protocol upgrades and real-time, add 17–21 as your build features allow.

## See also

- [`../README.md`](../README.md) — module positioning, build/feature matrix, quickstart.
- [`qb/README.md`](../../../qb/README.md) — the actor framework these pages build on.
- The qb framework [`readme/`](../../../qb/readme/) — actors, events, `qb-io` async, and coroutines.

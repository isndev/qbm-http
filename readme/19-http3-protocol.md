# HTTP/3 over QUIC

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 2.0.0 (C++20 default, C++23 supported)

`qb::http3` delivers native HTTP/3 — a same-origin async client, a Router-integrated server, and a dual-stack wrapper — layered on the qb-io QUIC transport and `libnghttp3`, and gated behind the `QBM_HTTP_HAS_HTTP3` build macro.

**Prerequisites:** [HTTPS & SSL/TLS](./18-https-ssl-tls.md), [HTTP/2 Protocol](./17-http2-protocol.md), [Async HTTP Client](./14-async-http-client.md) — **See also:** [Routing Overview](./03-routing-overview.md), [Request Context](./10-request-context.md)

## Summary

HTTP/3 runs HTTP semantics over QUIC (UDP), not over TCP. Inside `qbm/http`, the `qb-io` layer provides a generic QUIC transport — connections, bidirectional and unidirectional streams, flow-control credit, stream reset — with no knowledge of requests, responses, QPACK, or routing. The HTTP/3 framing and QPACK state machine live in `libnghttp3`, wrapped by `qb::protocol::http3::connection<Owner>`. On top of that sit three public surfaces:

- `qb::http3::Server<Session>` — a native HTTP/3 server that reuses the same `Router`, `Context`, middleware, `Request`, and `Response` types as the rest of the module.
- `qb::http3::Client` — a persistent, same-origin async client that connects with ALPN `h3` and multiplexes requests over one QUIC connection.
- `qb::http::dual_stack_server<...>` — a convenience wrapper that runs an HTTP/2 (TCP+TLS) server and an HTTP/3 (QUIC) server against one shared route table.

Everything in this page is behind one compile-time gate. Read the build section first.

## Build requirement: `QBM_HTTP_HAS_HTTP3`

HTTP/3 is optional and triple-gated. The entire `3/` tree — client, server, dual stack, protocol adapter — is compiled and visible **only** when all three conditions hold at qb configure time:

| Requirement | Source of truth |
| --- | --- |
| `QB_HAS_SSL` (OpenSSL detected) | derived upstream from OpenSSL discovery; exposed `PUBLIC` to consumers |
| `QB_HAS_QUIC` (qb-io QUIC transport, itself requiring SSL) | `qb/cmake/qbDependencies.cmake` |
| `libnghttp3` discoverable via `pkg-config` | `pkg_check_modules(PC_NGHTTP3 libnghttp3)` |

<!-- src: qbm/http/CMakeLists.txt:49-70,101-103 -->

When all three are present, `qbm/http`'s CMake sets `QBM_HTTP_HAS_HTTP3`, creates the imported target `Nghttp3::nghttp3`, appends `3/client.cpp` to the module sources, and — critically — defines `QBM_HTTP_HAS_HTTP3=1` **`PUBLIC`** on the `qbm-http` target so the `#ifdef` gate in `<http/http.h>` resolves the same way in your code as in the library:

```cmake
# qbm/http/CMakeLists.txt
if(QBM_HTTP_HAS_HTTP3)
    target_compile_definitions(qbm-http PUBLIC QBM_HTTP_HAS_HTTP3=1)
endif()
```

If any requirement is missing, the module still builds normally — HTTP/1.1, and (with SSL) HTTP/2 and WebSocket — but `QBM_HTTP_HAS_HTTP3` is never defined, and `<http/http.h>` does not include the `3/` headers. Including a `3/` header in that configuration is a hard error by design:

```cpp
// qbm/http/3/client.h:7-9 — and identically in http3.h, dual_stack.h, protocol/connection.h
#ifndef QBM_HTTP_HAS_HTTP3
#error "HTTP/3 support is not enabled. Build qbm/http with QBM_HTTP_HAS_HTTP3."
#endif
```

> `qbm/http` is a **compiled** library (it registers with `qb_register_module` and a `SOURCES` list), not header-only. `3/client.cpp` is one of its translation units. Guard any HTTP/3-specific application code with `#ifdef QBM_HTTP_HAS_HTTP3` so it degrades cleanly on builds without QUIC or nghttp3.

### Integration

Consume the module the standard way; the QUIC/SSL feature macros flow to you through the `PUBLIC` link:

```cmake
add_subdirectory(qb)                                 # the framework
qb_load_modules("${CMAKE_CURRENT_SOURCE_DIR}/qbm")   # discovers qbm/http

add_executable(app main.cpp)
target_link_libraries(app PRIVATE qbm::http)         # PUBLIC deps: qb::core, qb::io, vendored llhttp
```

Because module dependencies link `PUBLIC`, the `QB_HAS_SSL=1` / `QB_HAS_QUIC=1` defines and the `QBM_HTTP_HAS_HTTP3=1` define reach your target — that is what makes the `#ifdef` gates in `<http/http.h>` resolve correctly in your own sources.

```cpp
#include <http/http.h>   // umbrella; pulls in qb::http3 when QBM_HTTP_HAS_HTTP3 is defined
```

## Concepts

These terms recur throughout the API. They map directly to the protocol adapter and the QUIC transport.

- **ALPN `h3`** — the only application protocol this slice offers or accepts over QUIC. A handshake that negotiates anything else is failed by the client and closed by the server (application error `0x010c`).
- **QUIC endpoint** — `qb::io::async::quic::endpoint`, the qb-io base class that both `Client` and the HTTP/3 server inherit. It provides the connection and stream primitives; it is the one polymorphic node in the HTTP tree.
- **bidirectional stream** — a QUIC stream carrying one request/response exchange, keyed by its `stream_id`. `MessageBase::stream_id` carries this QUIC stream id on HTTP/3 (it is `0` on HTTP/1.1 and carries the frame stream id on HTTP/2).
- **control / QPACK streams** — three local unidirectional streams (HTTP/3 control + QPACK encoder + QPACK decoder) bound once per connection by `bind_local_streams()`.
- **pseudo-header** — a header beginning with `:` (`:method`, `:scheme`, `:authority`, `:path`, `:status`). Pseudo-headers must precede all regular headers; violations close the connection with `NGHTTP3_H3_MESSAGE_ERROR`.
- **same-origin** — the `Client` is bound to one origin (scheme + host + port). Requests to a different origin are rejected with `400 Bad Request`; it is not a general-purpose URL fetcher.

All HTTP/3 work is **event-loop affine**: the client and server have no internal locking and run entirely on the qb-io thread that drives them (`qb::io::async::run(...)`). Push/connect/cancel calls and the response callbacks all run on that one I/O thread.

## Server

An HTTP/3 server is constructed with `qb::http3::make_server()`. It exposes the same `Router` as every other server in the module, so routes, middleware, controllers, and contexts behave identically — the transport is the only thing that differs.

```cpp
// src: qbm/http/tests/test-http3-client.cpp:264-299 (adapted)
#include <http/http.h>

#ifdef QBM_HTTP_HAS_HTTP3
qb::io::async::init();

auto server = qb::http3::make_server();

server->router().get("/ping", [](auto ctx) {
    ctx->response().status() = qb::http::status::OK;
    ctx->response().set_header("x-protocol", "HTTP/3");
    ctx->response().body() = "pong-h3";
    ctx->complete();
});
server->router().compile();

// QUIC listener: scheme is https, transport is UDP/QUIC, ALPN is fixed to {"h3"}.
server->listen(qb::io::uri("https://0.0.0.0:4433"), "cert.pem", "key.pem");
#endif
```

`make_server<Session>()` returns a `std::unique_ptr<qb::http3::Server<Session>>`; `make_server()` defaults to `DefaultSession`. `listen(uri, cert, key)` forwards to the QUIC endpoint with ALPN locked to `{"h3"}` and returns `true` on a successful bind. The server is then driven by the surrounding qb-io event loop.

Custom sessions follow the same CRTP shape as HTTP/2:

```cpp
// src: qbm/http/tests/test-http3-client.cpp:29-35
class CustomHttp3Session;
using CustomHttp3Server = qb::http3::Server<CustomHttp3Session>;

class CustomHttp3Session
    : public qb::http3::use<CustomHttp3Session>::session<CustomHttp3Server> {
public:
    using Base = qb::http3::use<CustomHttp3Session>::session<CustomHttp3Server>;

    explicit CustomHttp3Session(CustomHttp3Server& server)
        : Base(server) {}
};
```

You can also subclass the server itself to add `on(...)` hooks for QUIC `connected` / `connection_closed` events — the server `dispatch` overrides invoke `static_cast<Derived&>(*this).on(ev)` when that method exists.

The server caps inbound request bodies via `set_max_body_size` (default 64 MiB); a body exceeding the cap resets the stream with `NGHTTP3_H3_REQUEST_CANCELLED` rather than buffering unbounded data.

## Client

`qb::http3::make_client(uri)` returns a `std::shared_ptr<qb::http3::Client>` bound to one `https://host:port` origin. The client requires the `https` scheme (the constructor throws `std::invalid_argument` otherwise) and only ever serves same-origin requests. Its API mirrors the HTTP/2 client: explicit or implicit connect, callback requests, batch requests, cancellation, and coroutine awaiters.

### Callback request

`push_request` connects lazily on the first request, multiplexes over the live QUIC connection thereafter, and invokes the callback on the I/O thread when the response (or an error response) is ready.

```cpp
// src: qbm/http/tests/test-http3-client.cpp:279-296 (adapted)
auto client = qb::http3::make_client("https://127.0.0.1:4433");
client->set_verify_peer(false);   // self-signed dev certificate only

qb::http::Request request{qb::io::uri("https://127.0.0.1:4433/ping")};
client->push_request(std::move(request), [](qb::http::Response res) {
    // res.status(), res.body(), res.headers()
});
```

`push_request(request, callback)` returns `false` only when the callback is null. Errors are delivered *through* the callback as a synthesized `Response`: a missing host or wrong scheme yields `400`, an exceeded pending-request cap yields `503`, transport failures yield `502 Bad Gateway`.

### Coroutine request

The awaiter overloads integrate with the module's coroutine layer (`#include <http/http.h>` already pulls in `coro.h`):

```cpp
// src: qbm/http/3/client.h:101-116
qb::http::async::awaiter<ConnectResult>            connect();
qb::http::async::awaiter<qb::http::Response>       push_request(qb::http::Request request);
qb::http::async::awaiter<std::vector<qb::http::Response>>
                                                   push_requests(std::vector<qb::http::Request> requests);
```

```cpp
auto result = co_await client->connect();   // ConnectResult: { bool ok; std::string error_message; }
if (result) {
    auto response = co_await client->push_request(
        qb::http::Request{qb::io::uri("/ping")});  // relative URI resolves against the bound origin
}
```

`ConnectResult` is explicitly convertible to `bool` (`true` when `ok`). For tests and scripts, `qb::http::run_sync(client->push_request(...))` drives the loop until the awaiter completes and returns the `Response`.

### Batch requests

`push_requests` issues a vector of requests concurrently over independent QUIC streams and completes once with the responses in submission order:

```cpp
// src: qbm/http/tests/test-http3-client.cpp:463-476 (adapted)
std::vector<qb::http::Request> requests;
requests.emplace_back(qb::io::uri("/item/1"));
requests.emplace_back(qb::io::uri("/item/2"));

client->push_requests(std::move(requests), [](std::vector<qb::http::Response> res) {
    // res[0], res[1] in submission order
});
```

### Cancellation

Queue a request with an id and cancel it while pending or active:

```cpp
// src: qbm/http/3/client.h:109-112
auto id = client->push_request_with_id(request, callback);
client->cancel_request(id, "cancelled by application");
```

Cancellation of an active request sends a QUIC stream reset with the HTTP/3 application error code `0x0105` (`NGHTTP3_H3_REQUEST_CANCELLED`) and completes the callback with status `CLIENT_CLOSED_REQUEST` (499). `cancel_request` returns `false` if the id is unknown.

### Tuning

All setters are `noexcept` and take effect on subsequent connects/requests:

| Method | Default | Notes |
| --- | --- | --- |
| `set_verify_peer(bool)` | `true` | set `false` only for self-signed dev certs |
| `set_max_concurrent_streams(std::size_t)` | `100` | concurrent in-flight requests |
| `set_max_body_size(std::size_t)` | 64 MiB | caps response bodies; over-cap resets the stream |
| `set_connect_timeout(qb::duration)` | 30 s | |
| `set_request_timeout(qb::duration)` | 60 s | |
| `set_auto_reconnect(bool)` | `true` | |

`get_stats()` returns `{total, successful, failed}` request counts; `get_active_request_count()` and `get_base_uri()` round out the read-only surface.

## Trailers

HTTP/3 trailers use the same `Request`/`Response` header container as HTTP/2. Announce trailer field names with the `Trailer` header, then set those fields on the same message; the adapter emits the announced fields in the HTTP/3 trailer section rather than duplicating them in the leading header block:

```cpp
ctx->response().set_header("trailer", "x-checksum");
ctx->response().set_header("x-checksum", checksum);
ctx->complete();
```

Incoming trailers are surfaced through the ordinary header APIs on `Request` / `Response`.

## Dual stack

HTTP/2 and HTTP/3 use **different transports** — TCP/TLS for HTTP/1.1 and HTTP/2, UDP/QUIC for HTTP/3 — so they cannot share a socket. `qb::http::make_dual_stack_server()` runs both servers behind a single route facade, registering each route on *both* routers. It returns a `std::unique_ptr<qb::http::dual_stack_server<...>>`.

```cpp
// src: qbm/http/tests/test-http3-client.cpp:309-322 (adapted)
auto server = qb::http::make_dual_stack_server();

server->router().get("/shared", [](auto ctx) {
    // Same handler, both protocols; detect which one served the request:
    const bool over_h3 = ctx->request().major_version == 3;
    ctx->response().status() = qb::http::status::OK;
    ctx->response().set_header("x-version", over_h3 ? "h3" : "h2");
    ctx->response().body() = over_h3 ? "shared-over-h3" : "shared-over-h2";
    ctx->complete();
});
server->router().compile();   // compiles BOTH routers

// listen() takes two distinct URIs — TCP/TLS first, then UDP/QUIC — plus one cert/key pair.
server->listen(qb::io::uri("https://0.0.0.0:443"),   // TCP/TLS: HTTP/2 (with HTTP/1.1 fallback)
               qb::io::uri("https://0.0.0.0:443"),   // UDP/QUIC: HTTP/3
               "cert.pem", "key.pem");
```

The facade exposes the same `get/post/put/del/patch/options/head/add_route` verbs as a normal router, but it is *not* a full `Router`: it forwards each registration to both underlying routers and offers `compile()`. Reach the real per-protocol routers and servers through `http2_server()` and `http3_server()` for protocol-specific tuning.

Important behaviors to design around:

- `listen()` `start()`s the **HTTP/2** server internally but does **not** start the HTTP/3 server — the QUIC endpoint is driven by the surrounding qb-io event loop. `listen()` returns `true` only when both listeners bind.
- The two sides close independently: `close_http2()`, `close_http3()`, or `close()` (both). Closing one transport does not imply the other.

## Lifecycle and graceful shutdown

A `qb::http3::Server` owns a QUIC endpoint. Each QUIC connection owns one nghttp3 connection adapter; each request stream maps to a lightweight session/context pair routed through the normal `on(...)` / router / context machinery.

`graceful_shutdown()` submits the HTTP/3 shutdown notice (GOAWAY) through nghttp3 for active connections, drains pending protocol output, and closes connections that have no active contexts — while keeping the UDP endpoint able to accept new clients until you call `close()`.

```cpp
server->graceful_shutdown();   // drain in-flight, stop accepting new streams per-connection
// ... later ...
server->close();               // tear down the UDP endpoint
```

On the **client** side, a server-initiated GOAWAY sets an internal shutdown flag: pending requests drain with `503 Service Unavailable`, and new same-origin requests are rejected with `503` while the connection is still draining. `client->disconnect()` fails all outstanding callbacks and closes the QUIC connection.

## Limits and guards

HTTP/3 enforces the same safety posture as HTTP/1.1 and HTTP/2, plus QUIC-specific guards:

- **ALPN** must negotiate `h3`; otherwise the client fails the connection and the server closes it with `0x010c`.
- **Body limits** are configurable with `set_max_body_size`; over-cap streams reset with `NGHTTP3_H3_REQUEST_CANCELLED` instead of buffering.
- **Header and message validation** is strict: pseudo-headers must precede regular headers; a request requires `:method`/`:scheme`/`:authority`/`:path`, a response a valid `:status`; duplicate or forbidden pseudo-headers and `content-length` mismatches close the connection with `NGHTTP3_H3_MESSAGE_ERROR`.
- **Hop-by-hop headers** are rejected in HTTP/3 header blocks.
- **Pending-request cap** bounds the client's queued + active requests; over-cap requests fail fast with `503`.
- **Timeouts, cancellation, stream reset, connection close, and graceful shutdown** all complete outstanding callbacks — no request hangs silently.

## Pitfalls

- **Do not include `3/` headers on a non-HTTP/3 build.** Every header in `3/` is a hard `#error` unless `QBM_HTTP_HAS_HTTP3` is defined. Gate HTTP/3 application code with `#ifdef QBM_HTTP_HAS_HTTP3`. `<http/http.h>` already does this for you.
- **The client is single-origin.** A request whose URI resolves to a different scheme, host, or port than the client's base URI fails with `400`. Use one client per origin. (Relative request URIs resolve against the bound origin, which is the idiomatic call.)
- **Exceptions do not escape protocol callbacks.** nghttp3 invokes the adapter across a C ABI; every callback runs under a guard that converts any C++ exception into `NGHTTP3_ERR_CALLBACK_FAILURE` — a clean stream/connection failure, not a propagated throw. Handlers reached from these callbacks must not rely on exceptions unwinding out of the protocol layer.
- **CSPRNG failure is fail-closed.** If OpenSSL `RAND_bytes` fails inside the nghttp3 rand callback, the process calls `std::abort()` rather than hand predictable material to QUIC. This is intentional.
- **`dual_stack_server::listen` does not start HTTP/3.** It starts the HTTP/2 server but relies on the qb-io loop to drive the QUIC endpoint. Make sure a loop is running (`qb::io::async::run(...)`), or no HTTP/3 traffic moves.
- **`router()` on the dual stack registers on both protocols.** There is no per-protocol routing through the facade; reach `http2_server().router()` / `http3_server().router()` directly if you need divergent route tables.
- **Keep QUIC affinity.** The HTTP/3 v1 surface does not expose server push, and a request stream stays on its owning listener thread. Fan CPU/business work out through actors or application queues and post the response back to the owning listener — do not move QUIC streams between threads.

## Interop testing

The in-tree integration suite (`tests/test-http3-client.cpp`) covers handshake, routing, bodies, batches, concurrency, cancellation, trailers, limits, malformed-length handling, graceful shutdown, and dual-stack regression against HTTP/1.1, HTTP/2, and coroutines. It skips when TLS test certificates are unavailable.

External interop is optional and auto-detected or env-configured; each external command is bounded by a test-side timeout and skipped when the tool is absent:

| Variable / tool | Purpose |
| --- | --- |
| Homebrew `curl --http3-only` (auto on macOS) or `QB_HTTP3_CURL` | curl-driven interop |
| `QB_HTTP3_NGHTTP3_CLIENT=/path/to/nghttp3-client` | nghttp3 reference client |
| `QB_HTTP3_H3SPEC=/path/to/h3spec` | h3spec conformance |
| `QB_HTTP3_EXTERNAL_SERVER_URL=https://host:port/path` | run `qb::http3::Client` against a live server |
| `QB_HTTP3_EXTERNAL_INSECURE=1` | accept self-signed external endpoints |
| `QB_HTTP3_EXTERNAL_EXPECT_STATUS` / `QB_HTTP3_EXTERNAL_EXPECT_BODY` | external assertions |

## See also

- [HTTP/2 Protocol](./17-http2-protocol.md) — the TLS-only sibling transport and the dual-stack partner
- [HTTPS & SSL/TLS](./18-https-ssl-tls.md) — certificate setup shared by HTTP/2 and HTTP/3
- [Async HTTP Client](./14-async-http-client.md) — callback and coroutine client patterns
- [Routing Overview](./03-routing-overview.md) · [Request Context](./10-request-context.md) — the Router and Context types reused unchanged by HTTP/3

---

Previous: [HTTPS & SSL/TLS](./18-https-ssl-tls.md)
Next: [WebSocket](./20-websocket.md)

---

Return to [Index](./README.md)

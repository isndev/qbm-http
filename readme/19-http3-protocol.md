# HTTP/3 Protocol

`qbm/http` provides native HTTP/3 when the build has both QB-IO QUIC support and `libnghttp3` available. HTTP/3 lives in `qb::http3`; the lower `qb-io` layer remains a generic QUIC transport and does not know about requests, responses, routing, QPACK, or HTTP semantics.

## Build Requirements

HTTP/3 is optional. It is enabled only when:

- QB was configured with QUIC support (`QB_WITH_QUIC=ON`) and the QUIC backend is available.
- `libnghttp3` is discoverable through `pkg-config`.

When those requirements are not met, `qbm/http` still builds normally without defining `QBM_HTTP_HAS_HTTP3`.

## Server

HTTP/3 servers use the same router, context, middleware, request, and response types as the rest of `qbm/http`.

```cpp
#include <http/http.h>

auto server = qb::http3::make_server();

server->router().get("/ping", [](auto ctx) {
    ctx->response().status() = qb::http::status::OK;
    ctx->response().body() = "pong-h3";
    ctx->complete();
});
server->router().compile();

server->listen(qb::io::uri{"https://0.0.0.0:4433"}, "cert.pem", "key.pem");
```

Custom sessions follow the same CRTP style as HTTP/2:

```cpp
class MySession;
using MyServer = qb::http3::Server<MySession>;

class MySession : public qb::http3::use<MySession>::session<MyServer> {
public:
    using Base = qb::http3::use<MySession>::session<MyServer>;

    explicit MySession(MyServer& server)
        : Base(server) {}
};
```

## Client

The HTTP/3 client mirrors the HTTP/2 client shape: explicit connect, callback requests, batch requests, and coroutine awaiters.

```cpp
auto client = qb::http3::make_client("https://127.0.0.1:4433");
client->set_verify_peer(false);

client->push_request(qb::http::Request{qb::io::uri{"/ping"}},
                     [](qb::http::Response response) {
    // response.status(), response.body(), response.headers()
});
```

Coroutine usage:

```cpp
auto result = co_await client->connect();
if (result) {
    auto response = co_await client->push_request(
        qb::http::Request{qb::io::uri{"/ping"}});
}
```

For explicit cancellation, queue a request with an id and cancel it while it is pending or active:

```cpp
auto id = client->push_request_with_id(request, callback);
client->cancel_request(id, "cancelled by application");
```

Cancellation sends a QUIC stream reset for active requests and completes the callback with `CLIENT_CLOSED_REQUEST`.

## Trailers

HTTP/3 uses the existing QB header container, matching the HTTP/2 convention. Announce trailer fields with the `Trailer` header, then set those fields on the same message:

```cpp
ctx->response().set_header("trailer", "x-checksum");
ctx->response().set_header("x-checksum", checksum);
ctx->complete();
```

The announced fields are sent in the HTTP/3 trailer section, not duplicated in the initial header block. Incoming trailers are exposed through the same `Request`/`Response` header APIs.

## Lifecycle

`qb::http3::server` owns a QB-IO QUIC endpoint. Each QUIC connection owns one nghttp3 connection adapter, and each HTTP request stream maps to a lightweight HTTP session/context pair. The application callbacks still run through normal QB `on(...)`/router/context mechanisms.

Graceful shutdown is available with:

```cpp
server->graceful_shutdown();
```

This submits the HTTP/3 shutdown notice through nghttp3 for active connections, drains pending protocol output, and closes the affected QUIC connections while keeping the UDP endpoint able to accept future clients until `server->close()`.

## Dual Stack Helper

HTTP/2 and HTTP/3 use distinct transports: TCP/TLS for HTTP/1.1+HTTP/2, UDP/QUIC for HTTP/3. `qbm/http` therefore keeps the servers separate, but provides a convenience wrapper for sharing route registration explicitly:

```cpp
auto server = qb::http::make_dual_stack_server();

server->router().get("/ping", [](auto ctx) {
    ctx->response().body() = "pong";
    ctx->complete();
});
server->router().compile();

server->listen("https://0.0.0.0:443",   // TCP/TLS: HTTP/2 with HTTP/1.1 fallback
               "https://0.0.0.0:443",   // UDP/QUIC: HTTP/3
               "cert.pem", "key.pem");
```

The helper does not hide the architecture: `http2_server()` and `http3_server()` remain accessible for protocol-specific tuning, and closing one transport does not imply the other unless the wrapper `close()` is used.

For explicit lifecycle control, use `close_http2()` and `close_http3()` when shutting down only one side of the stack. `close()` closes both.

## Limits And Guards

HTTP/3 enforces the same module-level safety posture as HTTP/1.1 and HTTP/2:

- ALPN must negotiate `h3`.
- Request and response body limits are configurable with `set_max_body_size`.
- Header count, header name length, header value length, and URL length are validated.
- `content-length` is parsed and checked.
- Hop-by-hop headers are rejected for HTTP/3 header blocks.
- Request timeouts, connect timeouts, cancellation, stream reset, connection close, and graceful shutdown all complete outstanding callbacks.

## Interop

Local integration tests cover client/server handshake, routing, bodies, batches, concurrency, cancellation, trailers, limits, malformed length handling, graceful shutdown, and regression with HTTP/1.1/HTTP/2/coroutines.

External interop is optional:

- Homebrew `curl --http3-only` is auto-detected on macOS, or configured with `QB_HTTP3_CURL`.
- `nghttp3-client` is enabled by setting `QB_HTTP3_NGHTTP3_CLIENT=/path/to/nghttp3-client`.
- `h3spec` is enabled by setting `QB_HTTP3_H3SPEC=/path/to/h3spec`.
- `qb::http3::Client` can be tested against an already running external HTTP/3 server with `QB_HTTP3_EXTERNAL_SERVER_URL=https://host:port/path`. Use `QB_HTTP3_EXTERNAL_INSECURE=1` for local self-signed endpoints, and optionally set `QB_HTTP3_EXTERNAL_EXPECT_STATUS` or `QB_HTTP3_EXTERNAL_EXPECT_BODY`.

These tests are skipped when the tools are absent and each external command is bounded by a test-side timeout.

## V1 Limits

HTTP/3 v1 intentionally does not expose server push. The transport keeps QUIC endpoint affinity: HTTP/3 contexts should perform CPU/business fanout through actors or application queues and post responses back to the owning listener rather than moving QUIC streams between listeners.

Return to [Index](./README.md)

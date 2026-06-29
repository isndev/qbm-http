# Asynchronous HTTP client

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 2.6.0 (C++20 default, C++23 supported)

Make non-blocking outbound HTTP/1.1, HTTP/2, and HTTP/3 requests over the qb-io event loop — through one-shot callbacks, single-shot coroutine awaiters, or a persistent connection-reusing client.

**Prerequisites:** [Core concepts](./01-core-concepts.md), [Request and Response bodies](./02-body-deep-dive.md) — **See also:** [HTTP/2 protocol specifics](./17-http2-protocol.md), [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md), [HTTP/3 protocol](./19-http3-protocol.md), [WebSocket](./20-websocket.md)

The qbm-http client surface is non-blocking from the ground up. Every request is driven by the same per-thread qb-io reactor that powers the server side, so a single I/O thread can have hundreds of outbound calls in flight without one thread per request. There are three layers, from simplest to most capable:

- **One-shot callback client** — the free functions `qb::http::GET`, `POST`, `PUT`, `DEL`, `HEAD`, `OPTIONS`, `PATCH`, and the generic `REQUEST`. Each heap-allocates a self-deleting session, performs a single HTTP/1.1 request, and delivers an `async::Reply` to your callback.
- **One-shot coroutine client** — the same verb names, overloaded to return an awaiter you `co_await`. Driven from a coroutine, or run to completion with `qb::http::run_sync(...)`.
- **Persistent client** — `qb::http1::Client`, `qb::http2::Client`, and `qb::http3::Client`. Long-lived, same-origin, connection-reusing clients with a request queue, batching, configurable connect/request timeouts, and automatic reconnection. HTTP/2 and HTTP/3 are only available through their persistent clients.

> **Feature gates.** HTTP/2 and the WebSocket subsystem require `QB_HAS_SSL` — `<http/http.h>` includes `2/http2.h` and `ws/ws.h` only under `#ifdef QB_HAS_SSL`, and `ws/ws.h` itself `#error`s without it (the handshake needs OpenSSL). HTTP/3 (`qb::http3`) requires `QBM_HTTP_HAS_HTTP3`, which CMake defines only when `QB_HAS_SSL`, `QB_HAS_QUIC`, and libnghttp3 are all present. The HTTP/1.1 client works without SSL; `https://` targets additionally require `QB_HAS_SSL`. Plaintext HTTP/1.1 is the only unconditional client.

## Concepts

### `async::Reply` — the one-shot result

The one-shot APIs (callback and coroutine) yield a `qb::http::async::Reply`, which pairs the original request with the server response so you can correlate the two — useful for tracing or request IDs.

<!-- src: qbm/http/1.1/http.h:652-655 -->
```cpp
namespace qb::http::async {
    struct Reply {
        Request  request;   // the request that was sent (moved in)
        Response response;  // the parsed response (or a synthesized error)
    };
}
```

The persistent clients (`qb::http1::Client`, `qb::http2::Client`, `qb::http3::Client`) yield a bare `qb::http::Response` instead, since the client already owns the request lifecycle.

### Timeouts are `qb::duration`, and zero means "no timeout"

Every connect and request timeout in the client surface is a `qb::duration`. The default is `qb::duration::zero()`, which means **no timeout** — not an immediate deadline. Pass a real duration to bound a call:

```cpp
using namespace std::chrono_literals;

co_await qb::http::GET(std::move(req), 5s);   // 5-second socket timeout
co_await qb::http::GET(std::move(req));        // qb::duration::zero() -> no timeout
```

The persistent clients carry their own defaults: a 30-second connect timeout and a 60-second request timeout, both adjustable via `set_connect_timeout(qb::duration)` and `set_request_timeout(qb::duration)`.

### `verify_peer` — TLS certificate verification

For `https://` (and `wss://`, h2, h3) targets, `verify_peer` controls server-certificate chain and hostname verification. It defaults to `true` everywhere. Passing `false` (or calling `set_verify_peer(false)`) disables verification and must only be used for trusted or self-signed endpoints. On the persistent clients, set it **before** connecting.

### Single-shot awaiters and the mono-thread model

The coroutine entry points return `qb::http::async::awaiter<T>` (defined in [`coro.h`](../coro.h)). An awaiter is single-shot, non-copyable, and non-movable: you construct it as a prvalue from a factory and `co_await` it immediately. A `shared_ptr` alive sentinel guards against late callbacks if the awaiter is destroyed before the operation completes, and resumption is routed through `qb::io::async::coro_scheduler()`, so the continuation always runs on the I/O thread that started the call. This is the same mono-thread-per-listener contract as the rest of the framework — never share a client or drive its awaiters across threads.

`qb::http::run_sync(awaitable)` is a thin re-export of `qb::io::async::run_sync`. It pumps the *current* thread's event loop just enough to resolve one awaitable, without spawning threads or mutating the global scheduler. Use it from tests, `main`, or any synchronous bootstrap code.

## Preparing a request

All three clients consume a `qb::http::Request`. Build it the same way regardless of protocol:

<!-- src: qbm/http/tests/system/coro/coro-client-http1.cpp:197-206 -->
```cpp
#include <http/http.h>
#include <qb/io/uri.h>

// A GET with custom headers.
qb::http::Request get_req(qb::io::uri("http://api.example.com/data"));
get_req.set_header("X-API-Key", "your_api_key");
get_req.add_header("Accept", "application/json");

// A POST with a JSON body. DELETE is spelled DEL throughout the verb API.
qb::http::Request post_req(qb::http::method::POST,
                           qb::io::uri("http://api.example.com/submit"));
post_req.set_content_type("application/json");
post_req.body() = R"({"name":"test","value":123})";
```

The clients fill in standard headers for you:

- **Host** — set automatically from `request.uri()` (bracketed IPv6, default ports omitted for `http:80` / `https:443`).
- **User-Agent** — the one-shot HTTP/1.1 sessions default to `qb/2.6.0` if you do not set one.
- **Accept-Encoding** — added automatically when compression is compiled in (`QB_HAS_COMPRESSION`); matching `Content-Encoding` responses are decompressed transparently.
- **Content-Length** — computed from the body for requests that carry one.

To send a *compressed* request body, compress it yourself and set `Content-Encoding` before handing the request to the client (`request.body().compress("gzip")`). See [Request and Response bodies](./02-body-deep-dive.md).

## One-shot callback client (HTTP/1.1)

The callback form is the native non-blocking API. You provide a callable taking `qb::http::async::Reply&&`; it runs on the I/O thread when the response arrives or the request fails.

<!-- src: qbm/http/1.1/http.h:869-874 -->
```cpp
template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply&&>, void>
GET(Request request, _Func&& func,
    qb::duration timeout = qb::duration::zero(), bool verify_peer = true);
// Same shape for POST, PUT, DEL, HEAD, OPTIONS, PATCH, and the generic REQUEST.
```

```cpp
#include <http/http.h>
#include <qb/io/uri.h>
#include <qb/io/async.h>

void handle(qb::http::async::Reply&& reply) {
    if (reply.response.status() == qb::http::status::OK) {
        std::cout << reply.response.body().as<std::string_view>() << '\n';
    } else {
        std::cerr << "failed: " << reply.response.status().code() << '\n';
    }
}

int main() {
    qb::io::async::init();  // one event loop per thread

    qb::http::Request req(qb::io::uri("http://api.example.com/data"));
    req.add_header("Accept", "application/json");

    using namespace std::chrono_literals;
    qb::http::GET(std::move(req), &handle, 5s);  // 5-second timeout

    qb::io::async::run();  // drive the loop until the call completes
    return 0;
}
```

Each one-shot session is heap-allocated with `new`, performs exactly one request/response, and `delete`s itself on completion or disposal — never stack-allocate or manually delete it. On failure the callback still fires exactly once, with a synthesized error response: `SERVICE_UNAVAILABLE` (503) when the connection cannot be opened, `GATEWAY_TIMEOUT` (504) on timeout, and `BAD_GATEWAY` (502) when the peer disconnects unexpectedly.

For `REQUEST`, set `request.method()` yourself; the verb-named functions set it for you.

## One-shot coroutine client (HTTP/1.1)

Every verb is also overloaded to return an awaiter. These overloads are thin wrappers over the callback API — they allocate no extra thread or event loop, they only bridge the callback into `co_await`. Overload resolution distinguishes them by arity: the 3-argument form (`request, func, timeout`) is callback-style; the 2-argument form (`request, timeout`) is coroutine-style.

<!-- src: qbm/http/1.1/http.h:1024-1035 -->
```cpp
namespace qb::http {
    [[nodiscard]] async::awaiter<async::Reply>
    GET(Request request, qb::duration timeout = qb::duration::zero(),
        bool verify_peer = true);
    // Same shape for REQUEST, POST, PUT, DEL, HEAD, OPTIONS, PATCH.
}
```

From inside a coroutine, the call reads top to bottom — request out, response back, error handling is a plain `if`:

<!-- src: qbm/http/tests/system/coro/coro-client-http1.cpp:284-302 -->
```cpp
#include <http/http.h>
#include <qb/io/async/coroutine.h>

qb::io::async::task<void> fetch() {
    qb::http::Request req(qb::io::uri("http://api.example.com/data"));
    req.add_header("Accept", "application/json");

    using namespace std::chrono_literals;
    auto reply = co_await qb::http::GET(std::move(req), 5s);

    if (reply.response.status() == qb::http::status::OK) {
        // reply.request is the original request; reply.response the parsed reply.
        handle(reply.response.body().as<std::string_view>());
    }
    co_return;
}
```

To drive a single call from synchronous code, wrap it in `run_sync`:

<!-- src: qbm/http/coro.h:198-201 -->
```cpp
#include <http/http.h>

int main() {
    qb::io::async::init();

    qb::http::Request req(qb::io::uri("http://api.example.com/data"));
    auto reply = qb::http::run_sync(qb::http::GET(std::move(req)));

    if (reply.response.status() == qb::http::status::OK) {
        std::cout << reply.response.body().as<std::string_view>() << '\n';
    }
    return 0;
}
```

To skip TLS verification for a self-signed endpoint, pass the third argument:

<!-- src: qbm/http/1.1/http.h:1024-1035 -->
```cpp
auto reply = qb::http::run_sync(
    qb::http::GET(std::move(req), qb::duration::zero(), /*verify_peer=*/false));
```

## Persistent client capability matrix

The three persistent clients share the connect / `push_request` / `push_requests` shape but differ in transport, gating, and a few protocol-specific knobs:

| Capability | `http1::Client` | `http2::Client` | `http3::Client` |
|---|---|---|---|
| Compile gate | none¹ | `QB_HAS_SSL` | `QBM_HTTP_HAS_HTTP3` |
| Transport (ALPN) | TCP / TLS | TLS only (`h2`) | QUIC (`h3`) |
| Base URI scheme | `http://` or `https://` | `https://` only | `https://` only |
| Concurrency | one active request, rest queued | multiplexed streams | multiplexed streams |
| `set_max_concurrent_streams` | — | ✓ (default 100) | ✓ (default 100) |
| `set_max_pending_requests` | ✓ | ✓ | — |
| `push_request_with_id` / `cancel_request` | — | — | ✓ |
| `set_max_body_size` | — | — | ✓ (default 64 MiB) |
| `set_auto_reconnect` | ✓ (default true) | ✓ (default true) | ✓ (default true) |
| Connect / request timeout | 30s / 60s | 30s / 60s | 30s / 60s |
| `set_verify_peer` default | true | true | true |

¹ HTTP/1.1 itself needs no gate; only `https://` base URIs require `QB_HAS_SSL`.

## Persistent HTTP/1.1 client (`qb::http1::Client`)

When you make many requests to the *same origin*, the one-shot helpers reconnect every time. The persistent client keeps one TCP/TLS connection open, sends one active request at a time (queuing the rest), preserves batch order, and reconnects only when it is safe to do so.

The client must be owned by a `std::shared_ptr` — use `qb::http1::make_client`. Its callbacks, timers, and coroutines capture `weak_from_this()` and silently no-op if the client was destroyed, so stack-allocating one breaks `shared_from_this`.

<!-- src: qbm/http/1.1/client.h:107-152,203-204 -->
```cpp
namespace qb::http1 {
    std::shared_ptr<Client> make_client(std::string const& base_uri);
    std::shared_ptr<Client> make_client(qb::io::uri const& uri);

    class Client {
        // Connect (callback or coroutine).
        bool connect(ConnectionCallback callback);
        [[nodiscard]] qb::http::async::awaiter<ConnectResult> connect();
        void disconnect();

        // Single request (callback or coroutine).
        bool push_request(qb::http::Request request, ResponseCallback callback);
        [[nodiscard]] qb::http::async::awaiter<qb::http::Response>
            push_request(qb::http::Request request);

        // Ordered batch (callback or coroutine).
        bool push_requests(std::vector<qb::http::Request> requests,
                           BatchResponseCallback callback);
        [[nodiscard]] qb::http::async::awaiter<std::vector<qb::http::Response>>
            push_requests(std::vector<qb::http::Request> requests);

        void set_connect_timeout(qb::duration value) noexcept;  // default 30s
        void set_request_timeout(qb::duration value) noexcept;  // default 60s
        void set_auto_reconnect(bool value) noexcept;           // default true
        void set_max_pending_requests(std::size_t value) noexcept;
        void set_verify_peer(bool value) noexcept;              // default true
    };
}
```

A typical coroutine flow — connect once, then fire requests against the same connection:

<!-- src: qbm/http/tests/system/http1/http1-client.cpp:361-378 -->
```cpp
#include <http/http.h>

auto client = qb::http1::make_client("http://api.example.com");

auto connected = qb::http::run_sync(client->connect());
if (!connected) {               // ConnectResult is bool-convertible
    std::cerr << connected.error_message << '\n';
    return;
}

qb::http::Request req(qb::io::uri("/items/42"));  // relative URI -> rewritten against base
auto response = qb::http::run_sync(client->push_request(std::move(req)));
```

Notes specific to the persistent HTTP/1.1 client:

- **Same-origin only.** A request whose absolute URI origin differs from the base URI is rejected with a `400` response. Relative request URIs are rewritten against the base origin.
- **Lazy connect.** You can `push_request` before `connect` completes; requests queue and flush once the connection is up.
- **Connection reuse.** Two sequential requests share one connection — `get_stats()` and a server-side connection counter both confirm a single TCP connection per origin.
- **TLS.** `https://` base URIs require `QB_HAS_SSL`.

## Persistent HTTP/2 client (`qb::http2::Client`)

HTTP/2 is TLS-only with ALPN. The client advertises only `h2` and fails the connection if ALPN does not negotiate it — plaintext `h2c` is not supported, so `qb::http2::Client` requires `QB_HAS_SSL` and an `https://` base URI. It multiplexes concurrent requests over a single connection and preserves batch order.

Like every persistent client, it is non-copyable, non-movable, and must be owned by a `shared_ptr` via `qb::http2::make_client`.

<!-- src: qbm/http/2/client.h:83-87,224-364,523 -->
```cpp
namespace qb::http2 {
    struct ConnectResult {
        bool        ok{false};
        std::string error_message;
        explicit operator bool() const noexcept;
    };

    class Client {
        bool connect(ConnectionCallback callback);  // pass nullptr for fire-and-forget
        [[nodiscard]] qb::http::async::awaiter<ConnectResult> connect();
        void disconnect();

        bool push_request(qb::http::Request request, ResponseCallback callback);
        [[nodiscard]] qb::http::async::awaiter<qb::http::Response>
            push_request(qb::http::Request request);

        bool push_requests(std::vector<qb::http::Request> requests,
                           BatchResponseCallback callback);
        [[nodiscard]] qb::http::async::awaiter<std::vector<qb::http::Response>>
            push_requests(std::vector<qb::http::Request> requests);

        void set_connect_timeout(qb::duration timeout);        // default 30s
        void set_request_timeout(qb::duration timeout);        // default 60s
        void set_max_concurrent_streams(size_t max_streams);   // default 100
        void set_auto_reconnect(bool enable);                  // default true
        void set_verify_peer(bool value) noexcept;             // default true
    };

    std::shared_ptr<Client> make_client(const std::string& base_uri);
}
```

The coroutine form connects lazily — `push_request` establishes the connection on first use, so you can `co_await` without calling `connect()` first:

<!-- src: qbm/http/tests/system/http2/http2-client-coro.cpp:211-216 -->
```cpp
auto response = qb::http::run_sync([]() -> qb::io::async::task<qb::http::Response> {
    auto client = qb::http2::make_client("https://api.example.com");
    qb::http::Request request{qb::io::uri("https://api.example.com/data")};
    co_return co_await client->push_request(std::move(request));
}());
```

Two cautions unique to the HTTP/2 client:

- **`connect(nullptr)` for fire-and-forget.** The callback `connect` has no default-argument overload, so the coroutine `connect()` stays unambiguous. Call `connect(nullptr)` when you do not need a connection callback.

  <!-- src: qbm/http/tests/system/http2/http2-client.cpp:249-253 -->
  ```cpp
  http2_client->connect(nullptr);  // queue requests now, flush on handshake
  ```

- **Same-origin only.** Cross-origin requests are rejected with `400 Bad Request` and the body `"HTTP/2 persistent client only accepts same-origin requests"`; a non-`https` request URI is rejected with `"HTTP/2 request URI must use https"`.

For HPACK, streams, flow control, and GOAWAY handling, see [HTTP/2 protocol specifics](./17-http2-protocol.md).

## Persistent HTTP/3 client (`qb::http3::Client`)

HTTP/3 runs over QUIC. The entire `qb::http3` slice is compile-time gated behind `QBM_HTTP_HAS_HTTP3` — including its header — so guard any HTTP/3 code with that macro. Only ALPN `h3` is accepted, the base URI must be `https`, and (as with HTTP/2) requests must be same-origin.

<!-- src: qbm/http/3/client.h:105-150,206 -->
```cpp
#ifdef QBM_HTTP_HAS_HTTP3
namespace qb::http3 {
    class Client {
        bool connect(ConnectionCallback callback);
        [[nodiscard]] qb::http::async::awaiter<ConnectResult> connect();
        void disconnect();

        bool push_request(qb::http::Request request, ResponseCallback callback);
        [[nodiscard]] request_id push_request_with_id(qb::http::Request request,
                                                      ResponseCallback callback);
        bool cancel_request(request_id id,
                            std::string const& reason = "HTTP/3 request cancelled");
        [[nodiscard]] qb::http::async::awaiter<qb::http::Response>
            push_request(qb::http::Request request);
        [[nodiscard]] qb::http::async::awaiter<std::vector<qb::http::Response>>
            push_requests(std::vector<qb::http::Request> requests);

        void set_max_concurrent_streams(std::size_t value) noexcept;  // default 100
        void set_max_body_size(std::size_t value) noexcept;           // default 64 MiB
        void set_connect_timeout(qb::duration value) noexcept;        // default 30s
        void set_request_timeout(qb::duration value) noexcept;        // default 60s
        void set_verify_peer(bool value) noexcept;                    // default true
    };

    std::shared_ptr<Client> make_client(std::string const& base_uri);
}
#endif
```

The callback form, run-to-completion driven by the event loop:

<!-- src: qbm/http/tests/system/http3/http3-loopback.cpp:178-197 -->
```cpp
#ifdef QBM_HTTP_HAS_HTTP3
auto client = qb::http3::make_client("https://127.0.0.1:31943");
client->set_verify_peer(false);  // self-signed local endpoint; default is true

qb::http::Request request{qb::io::uri("/resource")};  // relative -> rewritten against base
client->push_request(std::move(request), [&](qb::http::Response res) {
    // runs on the I/O thread
});
// ... drive qb::io::async::run() ...
client->disconnect();
#endif
```

And the coroutine form with lazy connect:

<!-- src: qbm/http/tests/system/http3/http3-loopback.cpp:283-294 -->
```cpp
auto client = qb::http3::make_client("https://127.0.0.1:31992");
client->set_verify_peer(false);  // self-signed local endpoint; default is true
auto response = qb::http::run_sync(
    client->push_request(qb::http::Request{qb::io::uri("/h3-only")}));
```

The HTTP/3 client adds two capabilities the others lack:

- **`push_request_with_id` / `cancel_request`** — submit a request and keep a `request_id` so you can cancel it later. A cancelled request completes with a `CLIENT_CLOSED_REQUEST` response.
- **`set_max_body_size`** — caps the reassembled response body (default 64 MiB); a larger response resets the stream instead of buffering unbounded data.

Request callbacks always run exactly once: on success with the server `Response`, or with a synthesized error (`SERVICE_UNAVAILABLE` on shutdown/disconnect, `REQUEST_TIMEOUT` on timeout, `BAD_GATEWAY` on stream close, `CLIENT_CLOSED_REQUEST` on cancel). A null callback is rejected — `push_request` returns `false` and `push_request_with_id` returns `0`.

For the QUIC transport and the dual-stack (h2 + h3) server, see [HTTP/3 protocol](./19-http3-protocol.md).

## Pitfalls

- **A `qb::duration` timeout of zero means "no timeout," not "fail now."** Always pass an explicit duration when you need a deadline, e.g. `5s`. Leaving the default `qb::duration::zero()` lets a stalled call wait indefinitely.
- **Never stack-allocate a persistent client.** `qb::http1::Client`, `qb::http2::Client`, and `qb::http3::Client` all rely on `enable_shared_from_this`; construct them with `make_client` and hold the `shared_ptr`. A stack instance corrupts the `weak_from_this()` captures in their timers and callbacks.
- **Do not drive a client or its awaiters across threads.** The whole client surface is single-thread-per-listener. Every `push`, `connect`, `cancel`, awaiter resumption, and callback runs on the I/O thread that owns the transport.
- **One-shot sessions delete themselves.** The free-function HTTP/1.1 sessions are heap-allocated and self-deleting. Never `delete` the result or capture a pointer to one.
- **HTTP/2 callback `connect` needs an explicit argument.** Write `connect(nullptr)` for fire-and-forget — there is no zero-argument callback overload, by design, so the coroutine `connect()` resolves unambiguously.
- **Persistent clients are same-origin.** A cross-origin request is rejected with `400`, not silently re-pointed. Build a separate client per origin, or use the one-shot helpers for ad-hoc cross-origin calls.
- **Feature gates are real.** `qb::http2::Client` needs `QB_HAS_SSL`; `qb::http3::Client` needs `QBM_HTTP_HAS_HTTP3` (its header `#error`s otherwise). Guard HTTP/3 code paths accordingly.
- **`verify_peer` defaults to `true`.** Disable it only for trusted or self-signed endpoints, and on the persistent clients set it before `connect()`.

## See also

- [HTTP/2 protocol specifics](./17-http2-protocol.md) — HPACK, streams, multiplexing, and flow control.
- [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md) — certificates, ALPN, and `verify_peer`.
- [HTTP/3 protocol](./19-http3-protocol.md) — QUIC transport, the nghttp3 adapter, and the dual-stack server.
- [WebSocket](./20-websocket.md) and [WebSocket coroutines](./21-websocket-coroutines.md) — persistent bidirectional conversations, when a one-request client is not enough.
- [Request and Response bodies](./02-body-deep-dive.md) — body access, compression, and content types.

---

Previous: [Error handling strategies](./13-error-handling.md) · Next: [HTTP message parsing](./15-http-parsing.md)

Return to [Index](./README.md)

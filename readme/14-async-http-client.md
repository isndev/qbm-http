# Asynchronous HTTP client

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 3.3.0 (C++20 default, C++23 supported)

Make non-blocking outbound HTTP/1.1, HTTP/2, and HTTP/3 requests over the qb-io event loop — through one-shot callbacks, single-shot coroutine awaiters, or a persistent connection-reusing client.

**Prerequisites:** [An HTTP server is an actor](./00-http-in-an-actor.md), [Core concepts](./01-core-concepts.md), [Request and Response bodies](./02-body-deep-dive.md) — **See also:** [HTTP/2 protocol specifics](./17-http2-protocol.md), [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md), [HTTP/3 protocol](./19-http3-protocol.md), [WebSocket](./20-websocket.md)

The qbm-http client surface is non-blocking from the ground up. Every request is driven by the same per-thread qb-io reactor that powers the server side, so a single I/O thread can have hundreds of outbound calls in flight without one thread per request. There are three layers, from simplest to most capable:

- **One-shot callback client** — the free functions `qb::http::GET`, `POST`, `PUT`, `DEL`, `HEAD`, `OPTIONS`, `PATCH`, and the generic `REQUEST`. Without redirect options, each heap-allocates a self-deleting session, performs a single HTTP/1.1 request, and delivers an `async::Reply` to your callback.
- **One-shot coroutine client** — the same verb names, overloaded to return an awaiter you `co_await`. Driven from a coroutine, or run to completion with `qb::http::run_sync(...)`.
- **Persistent client** — `qb::http1::Client`, `qb::http2::Client`, and `qb::http3::Client`. Long-lived, same-origin, connection-reusing clients with a request queue, batching, configurable connect/request timeouts, and automatic reconnection. HTTP/2 and HTTP/3 are only available through their persistent clients.

> **Feature gates.** HTTP/2 and the WebSocket subsystem require `QB_HAS_SSL` — `<qbm/http/http.h>` includes `src/qbm/http/2/http2.h` and `src/qbm/http/ws/ws.h` only under `#ifdef QB_HAS_SSL`, and `src/qbm/http/ws/ws.h` itself `#error`s without it (the handshake needs OpenSSL). HTTP/3 (`qb::http3`) requires `QBM_HTTP_HAS_HTTP3`, which CMake defines only when `QB_HAS_SSL`, `QB_HAS_QUIC`, and libnghttp3 are all present. The HTTP/1.1 client works without SSL; `https://` targets additionally require `QB_HAS_SSL`. Plaintext HTTP/1.1 is the only unconditional client.

## Concepts

### Informational responses

HTTP/1.1 and HTTP/2 clients wait through `100 Continue`, `103 Early Hints` and other
informational responses. Only the final response completes your callback or coroutine;
the request's timeout and cancellation still apply while it waits. Interim fields such
as an Early Hints `Link` are not merged into that final response, and an HTTP/1.1 queued
request does not start because a 1xx arrived.

HTTP/2 also accepts repeated and CONTINUATION-split informational header blocks. A 1xx
that sets END_STREAM, status 101, or DATA before final headers is a stream protocol
error. HTTP/1.1 status 101 keeps its existing upgrade handling. This follows
[RFC 9110 section 15.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2) and
[RFC 9113 section 8.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1).

The clients still send a request's body immediately, even if you set
`Expect: 100-continue`. There is no wait-for-100 upload handshake or separate callback
for informational responses.

### `async::Reply` — the one-shot result

The legacy one-shot APIs (callback and coroutine) yield a `qb::http::async::Reply`, which pairs the request snapshot for that attempt with the server response. Normal preparation may add headers or compress the body; a failure may occur before transmission. The opt-in redirect overloads below return a separate `async::RedirectReply`.

<!-- src: qbm/http/src/qbm/http/1.1/http.h:1302-1305 -->
```cpp
namespace qb::http::async {
    struct Reply {
        Request  request;   // the attempt's request snapshot (moved in)
        Response response;  // the parsed response (or a synthesized error)
    };
}
```

The persistent clients (`qb::http1::Client`, `qb::http2::Client`, `qb::http3::Client`) yield a bare `qb::http::Response` instead, since the client already owns the request lifecycle.

### Timeouts are `qb::duration`, and zero means "no timeout"

Every connect and request timeout in the client surface is a `qb::duration`. The legacy one-shot helpers default to `qb::duration::zero()`, which means **no timeout** — not an immediate deadline. Pass a real duration to bound a call:

```cpp
using namespace std::chrono_literals;

co_await qb::http::GET(std::move(req), 5s);   // 5-second socket timeout
co_await qb::http::GET(std::move(req));        // qb::duration::zero() -> no timeout
```

The persistent clients carry their own defaults: a 30-second connect timeout and a 60-second request timeout, both adjustable via `set_connect_timeout(qb::duration)` and `set_request_timeout(qb::duration)`.

### `verify_peer` — TLS certificate verification

For `https://` (and `wss://`, h2, h3) targets, `verify_peer` controls server-certificate chain and hostname verification. The legacy helpers and persistent clients default to `true`; the opt-in redirect overloads require an explicit argument. Passing `false` (or calling `set_verify_peer(false)`) disables verification and must only be used for trusted or self-signed endpoints. On the persistent clients, set it **before** connecting.

### Single-shot awaiters and the mono-thread model

The legacy coroutine entry points return `qb::http::async::awaiter<T>` (defined in [`coro.h`](../src/qbm/http/coro.h)). An awaiter is single-shot, non-copyable, and non-movable: you construct it as a prvalue from a factory and `co_await` it immediately. A `shared_ptr` alive sentinel guards against late callbacks if the awaiter is destroyed before the operation completes, and resumption is routed through `qb::io::async::coro_scheduler()`, so the continuation always runs on the I/O thread that started the call. This is the same mono-thread-per-listener contract as the rest of the framework — never share a client or drive its awaiters across threads.

`qb::http::run_sync(awaitable)` is a thin re-export of `qb::io::async::run_sync`. It pumps the *current* thread's event loop just enough to resolve one awaitable, without spawning threads or mutating the global scheduler. Use it from tests, `main`, or any synchronous bootstrap code.

### Driving a request from inside an actor

Inside a `qb::Main`, the "current thread's event loop" is a `VirtualCore`, which changes which of the three layers is correct — and makes one of them a defect:

| From | Use | Why |
|---|---|---|
| A **coroutine route handler** | `co_await qb::http::GET(req, timeout)` directly | The router already drove your body as a coroutine; the `ctx` shared pointer keeps the request alive across the suspension. |
| An **actor event handler** | `Actor::spawn`, then `co_await` inside it | A handler must return. Copy what the coroutine needs by value first, and answer through the context. |
| An **actor**, anywhere | **never** `run_sync` | It stops the `VirtualCore` — every actor and every connection on that core — until the awaitable resolves, with no diagnostic. |
| `main()`, a test, a CLI | `qb::http::run_sync(...)` | The thread it stops is yours. |

The awaiter these entry points return is **not cancellation-aware**: it registers no `on_cancel` hook, so `Actor::kill()` neither wakes nor unwinds a coroutine parked on an in-flight request. The timeout argument is what bounds it — and the default is `qb::duration::zero()`, meaning none. [An HTTP server is an actor](./00-http-in-an-actor.md#what-cancellation-means-here) owns that rule and its consequences for shutdown; [C++20 coroutines](https://github.com/isndev/qb/blob/main/readme/3_qb_io/coroutines.md#every-awaitable-and-what-cancellation-does-to-it) owns the framework-wide inventory it belongs to.

## Preparing a request

All three clients consume a `qb::http::Request`. Build it the same way regardless of protocol:

```cpp
#include <qbm/http/http.h>
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

The HTTP/1.1 one-shot and persistent clients fill in these standard headers for you:

- **Host** — set automatically from `request.uri()` by `qb::http::origin::authority`, the authority every protocol writes: an IPv6 literal between brackets without its zone identifier, the scheme's default port omitted (`http:80`, `https:443`; Huly QB-1064).
- **User-Agent** — defaults to `qb::http::default_user_agent` (`qb/<framework version>`, derived at compile time) if you do not set one.
- **Accept-Encoding** — populated with supported codecs when compression is compiled in (`QB_HAS_COMPRESSION`); these HTTP/1.1 clients decompress `Content-Encoding` responses transparently.
- **Content-Length** — computed from the body for requests that carry one.
<!-- src: qbm/http/src/qbm/http/1.1/http.h:1353-1359,1436-1446; qbm/http/src/qbm/http/1.1/client.cpp:149-168,377-395; qbm/http/src/qbm/http/headers.cpp:320-325 -->

The HTTP/2 and HTTP/3 clients do not add `Accept-Encoding` or decode `Content-Encoding` responses for you. Set the negotiation header yourself, and decode a response explicitly when your application needs its plaintext body (`Body::uncompress` requires `QB_HAS_COMPRESSION`).
<!-- src: qbm/http/src/qbm/http/2/client.cpp:248-261,604-619; qbm/http/src/qbm/http/3/client.cpp:191-203,760-769; qbm/http/src/qbm/http/body.h:291-312 -->

For an HTTP/1.1 one-shot or persistent client built with `QB_HAS_COMPRESSION`, assign the **uncompressed** body and set `Content-Encoding: gzip`; the client compresses it once before sending. Do not call `request.body().compress("gzip")` first: that would add a second gzip layer while declaring only one. Without `QB_HAS_COMPRESSION`, these HTTP/1.1 clients remove `Content-Encoding` and send the body unchanged; do not rely on this path to send a precompressed request. For an HTTP/2 or HTTP/3 request, which does not have that HTTP/1.1 client compression step, compress the body yourself (when `QB_HAS_COMPRESSION` is available) before setting its `Content-Encoding`. See [Request and Response bodies](./02-body-deep-dive.md).
<!-- src: qbm/http/src/qbm/http/1.1/http.h:1401-1408; qbm/http/src/qbm/http/1.1/client.cpp:122-135 -->

## One-shot callback client (HTTP/1.1)

The callback form is the native non-blocking API. You provide a callable taking `qb::http::async::Reply&&`. Network responses and failures invoke it on the I/O thread; a locally rejected scheme or missing SSL capability invokes it on the calling thread before the helper returns.

<!-- src: qbm/http/src/qbm/http/1.1/http.h:1427-1447,1527-1542,1577-1582 -->
```cpp
template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply&&>, void>
GET(Request request, _Func&& func,
    qb::duration timeout = qb::duration::zero(), bool verify_peer = true);
// Same shape for POST, PUT, DEL, HEAD, OPTIONS, PATCH, and the generic REQUEST.
```

```cpp
#include <qbm/http/http.h>
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

Each supported one-shot request creates a heap-allocated session for one request/response and deletes it on completion or disposal — never stack-allocate or manually delete it. The transport selector compares URI schemes case-insensitively; qb-io also resolves default ports for portless mixed-case HTTP(S) URLs. An unsupported scheme is rejected locally with `BAD_REQUEST` (400); HTTPS when SSL is unavailable is rejected locally with `SERVICE_UNAVAILABLE` (503), without creating a session or opening a socket. Those local rejections can invoke a callback before the helper returns; the coroutine overload schedules its continuation normally. Other failures yield 503 when the connection cannot be opened, `GATEWAY_TIMEOUT` (504) on timeout, `BAD_REQUEST` (400) when the request cannot be compressed or serialized (an unknown `Content-Encoding`, a raw space or control byte in the URI's query), and `BAD_GATEWAY` (502) when the session is disposed before a complete response — the peer closes early, the response is not HTTP, a read limit is hit. A response delimited by the connection close (no `Content-Length`, no `Transfer-Encoding`) is complete at EOF and delivered then. The callback fires exactly once, whatever ends the session.

For `REQUEST`, set `request.method()` yourself; the verb-named functions set it for you.

## One-shot coroutine client (HTTP/1.1)

Every verb is also overloaded to return an awaiter. These overloads are thin wrappers over the callback API — they allocate no extra thread or event loop, they only bridge the callback into `co_await`. Overload resolution distinguishes them by arity: the 3-argument form (`request, func, timeout`) is callback-style; the 2-argument form (`request, timeout`) is coroutine-style.

<!-- src: qbm/http/src/qbm/http/1.1/http.h:1713-1718 -->
```cpp
namespace qb::http {
    [[nodiscard]] async::awaiter<async::Reply>
    GET(Request request, qb::duration timeout = qb::duration::zero(),
        bool verify_peer = true);
    // Same shape for REQUEST, POST, PUT, DEL, HEAD, OPTIONS, PATCH.
}
```

From inside a coroutine, the call reads top to bottom — request out, response back, error handling is a plain `if`:

<!-- src: qbm/http/tests/system/coro/coro-client-http1.cpp:330-348 -->
```cpp
#include <qbm/http/http.h>
#include <qb/io/async/coroutine.h>

qb::io::async::task<void> fetch() {
    qb::http::Request req(qb::io::uri("http://api.example.com/data"));
    req.add_header("Accept", "application/json");

    using namespace std::chrono_literals;
    auto reply = co_await qb::http::GET(std::move(req), 5s);

    if (reply.response.status() == qb::http::status::OK) {
        // reply.request is this attempt's snapshot; reply.response is the processed reply.
        handle(reply.response.body().as<std::string_view>());
    }
    co_return;
}
```

To drive a single call from synchronous code, wrap it in `run_sync`:

<!-- src: qbm/http/src/qbm/http/coro.h:284-287 -->
```cpp
#include <qbm/http/http.h>

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

<!-- src: qbm/http/src/qbm/http/1.1/http.h:1713-1718 -->
```cpp
auto reply = qb::http::run_sync(
    qb::http::GET(std::move(req), qb::duration::zero(), /*verify_peer=*/false));
```

## Opt-in redirects (HTTP/1.1)

Include `<qbm/http/redirect.h>` explicitly. `RedirectOptions` is required as the final argument; `<qbm/http/http.h>` and the existing overloads continue to perform one attempt. The same opt-in forms exist for `REQUEST`, `GET`, `POST`, `PUT`, `DEL`, `HEAD`, `OPTIONS`, and `PATCH`:

```cpp
namespace qb::http {
    struct RedirectOptions {
        std::size_t max_hops = 5;
        bool allow_cross_origin = false;
    };

    template <typename Completion>
    requires std::is_invocable_v<std::decay_t<Completion>&, async::RedirectReply&&>
    void GET(Request request, Completion&& complete, qb::duration timeout,
             bool verify_peer, RedirectOptions options); // all five arguments required

    [[nodiscard]] auto GET(Request request, qb::duration timeout,
                           bool verify_peer, RedirectOptions options); // all four required
}
```
<!-- src: qbm/http/src/qbm/http/redirect.h:25-38,234-243 -->

From inside a coroutine:

```cpp
#include <chrono>
#include <qbm/http/redirect.h>

auto reply = co_await qb::http::GET(
    qb::http::Request{qb::io::uri{"https://example.test/start"}},
    std::chrono::seconds{5}, true, qb::http::RedirectOptions{});
```

The callback takes `qb::http::async::RedirectReply&&`; it is stored by value, so a named callable is copied and a move-only callable must be moved. Final callback delivery is deferred until after the previous session's dispatch, including locally completed attempts. The coroutine form yields `async::RedirectReply`; destroying its awaiter prevents later attempts but does not cancel a session already started. Keep the originating listener running until completion: clearing or destroying it drops queued callbacks without invoking them and releases their captures. Exceptions from the final callback are contained by the listener's deferred drain.

Before the first reply, setup exceptions propagate to the caller. A recoverable preparation or startup exception on a later hop returns the preceding completed reply. Startup ownership is guarded, including a session that deletes itself during an inline completion. This is not a general resource-exhaustion guarantee: failure to enqueue deferred work remains fatal at the existing noexcept callback boundary.
<!-- src: qbm/http/src/qbm/http/redirect.h:92-162,174-200; qb/src/qb/io/async/listener.h:622-675,866-888,1189-1201 -->

`RedirectReply` derives from the unchanged `async::Reply` and adds `std::vector<Reply> hops`. Its inherited `request` and `response` are the terminal exchange. `hops` contains each exchange actually followed, in order, without repeating the terminal one; after at least one followed hop, `hops.front().request` is the first attempt's snapshot. Every snapshot has the legacy preparation state: it may include automatic headers and a compressed request body. It is not a pristine pre-preparation input copy.

| Policy | Behavior |
|---|---|
| Followable response | 301, 302, 303, 307 or 308 with exactly one usable Location value |
| Hop cap | `max_hops=5` allows five followed hops after the initial attempt; zero follows none. At the cap, the last reply is returned, including its 3xx; no synthetic 508 |
| Origin | Same-origin by default. `allow_cross_origin=true` permits a new origin and removes Authorization, Proxy-Authorization, Cookie, Origin and Referer, and clears the parsed cookie jar. Removed credentials are not restored on a later return hop |
| Downgrade | HTTPS to HTTP stops the chain, even with cross-origin enabled |
| Method and content | 301/302 turn POST into GET and drop content. 303 drops content and uses GET, except HEAD remains HEAD. 307/308 preserve method and logical body |
| Timeout | The supplied connect/inactivity timeout applies separately to every attempt; zero disables it. It is not a whole-chain deadline |

<!-- src: qbm/http/src/qbm/http/detail/redirect.cpp:233-270; qbm/http/src/qbm/http/redirect.h:128-150,174-200 -->

Location resolution preserves encoded octets, repeated/trailing slashes and an explicitly empty query. A relative Location is resolved against the preceding attempt. An absent fragment inherits the prior fragment; an explicit empty `#` clears it, and fragments stay out of the wire target. Missing or multiple Location values, invalid syntax or percent escapes, userinfo, scoped IPv6 and IPvFuture are not followed. A single empty Location is an empty URI reference and is still bounded by the hop cap. A forbidden target or next-attempt preparation failure returns the last completed reply through the usual one-shot response processing.

Each attempt receives a fresh copy of the logical request body, so replay does not compress an already-compressed snapshot. Body-dropping rewrites clear trailers and body/framing metadata; preserved-body rewrites recalculate Content-Length, and Host is rebuilt for the destination. Cross-origin permission can therefore also permit replaying a retained body to the new origin.

History retains complete request and response bodies. The cap bounds followed hops, not retained bytes: storage grows with actual followed exchanges rather than being reserved up front from `max_hops`. A very large cap permits a correspondingly large history.
<!-- src: qbm/http/src/qbm/http/redirect.h:25-38,128-150,174-200; qbm/http/src/qbm/http/origin.cpp:159-216; qbm/http/src/qbm/http/detail/redirect.cpp:64-112,123-151,161-229,233-270 -->

## Persistent client capability matrix

The three persistent clients share the connect / `push_request` / `push_requests` shape but differ in transport, gating, and a few protocol-specific knobs:

| Capability | `http1::Client` | `http2::Client` | `http3::Client` |
|---|---|---|---|
| Compile gate | none¹ | `QB_HAS_SSL` | `QBM_HTTP_HAS_HTTP3` |
| Transport (ALPN) | TCP / TLS | TLS only (`h2`) | QUIC (`h3`) |
| Base URI scheme | `http://` or `https://` | `https://` only | `https://` only |
| Concurrency | one active request, rest queued | multiplexed streams | multiplexed streams |
| `set_max_concurrent_streams` | — | ✓ (default 100) | ✓ (default 100) |
| `set_max_pending_requests` | ✓ | ✓ | ✓ (default 10000) |
| `push_request_with_id` / `cancel_request` | — | — | ✓ |
| `set_max_body_size` | — | — | ✓ (default 64 MiB) |
| `set_auto_reconnect` | ✓ (default true) | ✓ (default true) | ✓ (default true) |
| `enable_auto_reconnect(RetryPolicy)` — backoff, cap, `on_retry` | — (immediate) | ✓ | — (immediate) |
| Connect / request timeout | 30s / 60s | 30s / 60s | 30s / 60s |
| `set_verify_peer` default | true | true | true |

¹ HTTP/1.1 itself needs no gate; only `https://` base URIs require `QB_HAS_SSL`.

## Persistent HTTP/1.1 client (`qb::http1::Client`)

When you make many requests to the *same origin*, the one-shot helpers reconnect every time. The persistent client keeps one TCP/TLS connection open, sends one active request at a time (queuing the rest), preserves batch order, and reconnects only when it is safe to do so.

The client must be owned by a `std::shared_ptr` — use `qb::http1::make_client`. Late transport completions cannot access a destroyed client. Destruction abandons pending connect observers; an explicit `disconnect()` instead reports their cancelled attempt once while the client still has a live owner.

<!-- src: qbm/http/src/qbm/http/1.1/client.h:96-158,212-213 -->
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

<!-- src: qbm/http/tests/system/http1/http1-client.cpp:703-714 -->
```cpp
#include <qbm/http/http.h>

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

### Reentry from a response or failure callback

A closing response marks the client disconnected **before** its callback runs. The active response is delivered once, while queued remainder follows the normal reconnect policy. On disconnect, connect failure, or timeout, the old request and connect-callback cohort is detached before its notifications. A request submitted by one of those callbacks belongs to the next cycle and cannot be consumed by the old failure loop. Batch order, callback counts, and existing pending-request deadlines are preserved.

If a callback requests `connect()`, the new attempt is accepted but starts only after the old callbacks and protocol/I/O dispatch have unwound. `is_connecting()` can therefore be true while `is_connected()` remains false. Work queued behind this explicit intent is admitted even with `set_auto_reconnect(false)`; without such an intent, a disconnected client with automatic reconnect disabled still rejects work with 503. A direct `disconnect()` outside callback dispatch releases the retired connection before returning. Callback exceptions remain contained, so one throwing old callback does not prevent the remaining old notifications.
<!-- src: qbm/http/src/qbm/http/1.1/client.cpp:240-244,280-315,346-357,502-518,573-601,605-638,698-757 -->

## Persistent HTTP/2 client (`qb::http2::Client`)

HTTP/2 is TLS-only with ALPN. The client advertises only `h2` and fails the connection if ALPN does not negotiate it — plaintext `h2c` is not supported, so `qb::http2::Client` requires `QB_HAS_SSL` and an `https://` base URI. It multiplexes concurrent requests over a single connection and preserves batch order.

A stream reset locally by the protocol is retired before its error callback runs. The
callback can cancel that same stream again or enqueue another request without a duplicate
notification or a reference to the retired stream.

Like every persistent client, it is non-copyable, non-movable, and must be owned by a `shared_ptr` via `qb::http2::make_client`.

<!-- src: qbm/http/src/qbm/http/2/client.h:104-108,282-432,472-497,662 -->
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
        void enable_auto_reconnect(RetryPolicy policy = {}) noexcept;  // the backoff of the run
        void disable_auto_reconnect() noexcept;
        [[nodiscard]] bool is_reconnecting() const noexcept;
        [[nodiscard]] int  reconnect_attempts() const noexcept;
        void set_verify_peer(bool value) noexcept;             // default true
    };

    std::shared_ptr<Client> make_client(const std::string& base_uri);
}
```

The coroutine form connects lazily — `push_request` establishes the connection on first use, so you can `co_await` without calling `connect()` first:

<!-- src: qbm/http/tests/system/http2/http2-client-coro.cpp:212-216 -->
```cpp
auto response = qb::http::run_sync([]() -> qb::io::async::task<qb::http::Response> {
    auto client = qb::http2::make_client("https://api.example.com");
    qb::http::Request request{qb::io::uri("https://api.example.com/data")};
    co_return co_await client->push_request(std::move(request));
}());
```

Two cautions unique to the HTTP/2 client:

- **`connect(nullptr)` for fire-and-forget.** The callback `connect` has no default-argument overload, so the coroutine `connect()` stays unambiguous. Call `connect(nullptr)` when you do not need a connection callback.

  <!-- src: qbm/http/tests/system/http2/http2-client.cpp:490-494 -->
  ```cpp
  http2_client->connect(nullptr);  // queue requests now, flush on handshake
  ```

- **Same-origin only.** Cross-origin requests are rejected with `400 Bad Request` and the body `"HTTP/2 persistent client only accepts same-origin requests"`; a non-`https` request URI is rejected with `"HTTP/2 request URI must use https"`.

### Reconnection is a run with a backoff

A connection loss fails every outstanding request with a `503` whose body says why (`"Connection lost"`, `"Connection closed"`, `"Connection failed: ..."`), once. What the failure callbacks push back — the retry pattern — is what the automatic reconnection reconnects for, and it does so as a **run** shaped by a `qb::http::RetryPolicy` (`qb::http2::RetryPolicy` is the same type, and so is `qb::redis::RetryPolicy`: all three are qb-io's `qb::io::reconnect_policy`): attempt 1 at once, attempt 2 after `initial_delay`, every further one after a wait multiplied by `multiplier` up to `max_delay`, each wait jittered by up to a quarter either way, `on_retry(attempt, next_delay)` told before each wait how many attempts have failed. `max_attempts` bounds the run: exhausted, the waiting requests get `503` with the body `"Reconnection attempts exhausted (N)"` and the client stays down until the next `connect()` — explicit, or the auto-connect of a request pushed afterwards — which starts a fresh run. A connection that comes up ends the run and resets its count, as do an explicit `connect()` and an explicit `disconnect()` — which also cancels the scheduled attempt and starts no run: the user asked out, the outstanding work fails with `"Connection closed"`, and only a request pushed afterwards (from that verdict's callback included) connects again, on its own, exactly as on the HTTP/1.1 client.

<!-- src: qbm/http/src/qbm/http/retry_policy.h:25; qbm/http/src/qbm/http/2/client.h:472-497 -->
```cpp
client->enable_auto_reconnect(qb::http2::RetryPolicy{}
                                  .with_initial_delay(100ms)   // before attempt 2; attempt 1 is immediate
                                  .with_multiplier(2.0)
                                  .with_max_delay(10s)
                                  .with_jitter(true)           // +-25 % on every wait
                                  .with_max_attempts(8)        // then "Reconnection attempts exhausted (8)"
                                  .with_on_retry([](int failed, qb::duration next) { /* log it */ }));
```

Two things the run guarantees, and that a hand-rolled retry cannot: every attempt fires from the client's own timer after the transport that dropped has been disposed — never from inside the handler that saw the failure — and a request pushed from a failure callback **queues** behind the scheduled attempt instead of connecting on its own. So do not call `connect()` from a failure callback to "retry faster": it resets the run (an explicit `connect()` is a fresh intent) and hands you back the immediate, unbounded reconnection the policy exists to replace. `set_auto_reconnect(false)` / `disable_auto_reconnect()` disarm the run (a scheduled attempt still fires); with it disarmed a push from a failure callback connects at once, as it always did. `is_reconnecting()` and `reconnect_attempts()` are the observable state.

For HPACK, streams, flow control, and GOAWAY handling, see [HTTP/2 protocol specifics](./17-http2-protocol.md).

## Persistent HTTP/3 client (`qb::http3::Client`)

HTTP/3 runs over QUIC. The entire `qb::http3` slice is compile-time gated behind `QBM_HTTP_HAS_HTTP3` — including its header — so guard any HTTP/3 code with that macro. Only ALPN `h3` is accepted, the base URI must be `https`, and (as with HTTP/2) requests must be same-origin.

<!-- src: qbm/http/src/qbm/http/3/client.h:110-114,184-191,214-256,258-293,406 -->
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

<!-- src: qbm/http/tests/system/http3/http3-loopback.cpp:184-203 -->
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

<!-- src: qbm/http/tests/system/http3/http3-loopback.cpp:288-299 -->
```cpp
auto client = qb::http3::make_client("https://127.0.0.1:31992");
client->set_verify_peer(false);  // self-signed local endpoint; default is true
auto response = qb::http::run_sync(
    client->push_request(qb::http::Request{qb::io::uri("/h3-only")}));
```

The HTTP/3 client adds two capabilities the others lack:

- **`push_request_with_id` / `cancel_request`** — submit a request and keep a `request_id` so you can cancel it later. A cancelled request completes with a `CLIENT_CLOSED_REQUEST` response.
- **`set_max_body_size`** — caps the reassembled response body (default 64 MiB); a larger response resets the stream instead of buffering unbounded data.

Request callbacks always run exactly once: on success with the server `Response`, or with a synthesized error (`SERVICE_UNAVAILABLE` on shutdown/disconnect, `REQUEST_TIMEOUT` on timeout, `BAD_GATEWAY` on stream close, `CLIENT_CLOSED_REQUEST` on cancel). A null callback is rejected — `push_request` returns `false` and `push_request_with_id` returns `0`. A request the pending-request cap refuses gets its `503` through the callback and `push_request` returns `false`; `push_requests` returns `false` when the cap refused at least one member — the HTTP/1.1 and HTTP/2 clients answer the same.

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

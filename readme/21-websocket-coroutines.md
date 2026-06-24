# WebSocket coroutines

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 2.0.0 (C++20 default, C++23 supported)

Write a WebSocket conversation as a single straight-line coroutine — `co_await` the connect, each inbound frame, and the close handshake — instead of scattering the logic across CRTP `on(...)` callbacks.

**Prerequisites:** [WebSocket](./20-websocket.md), [Asynchronous HTTP client](./14-async-http-client.md) (for the awaiter / `run_sync` model), and working knowledge of qb-io coroutines — see the qb [`readme/`](../../../qb/readme/) docs. **See also:** [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md) for `wss://`.

The coroutine API in `<http/ws.h>` is a thin, allocation-light layer over the same RFC 6455 framing engine that drives the callback `WebSocket<T>` client and `ws::protocol` server. It exists for the common case where a WebSocket exchange is naturally sequential — connect, authenticate, subscribe, wait for frames, reply, close — and reads more clearly as a loop than as a handler bag. Resumption is routed through `qb::io::async::coro_scheduler()`, so the continuation always runs on the listener thread that owns the socket; the single-threaded qb-io model is preserved end to end.

This is not a separate module. The coroutine types live alongside the callback API under `qb::http::ws`; you link `qbm::http` and include the same umbrella header. The secure client variant (`wss://`) requires `QB_HAS_SSL`, exactly as the callback secure client does.

```cpp
#include <http/http.h>
#include <http/ws.h>
```

## Concepts

| Type | Role |
|---|---|
| `qb::http::ws::coro_client<Transport>` | Coroutine-first client. `co_await connect / receive / close_async`. Defaults to `tcp` (`ws://`). |
| `qb::http::ws::coro_client_secure` | Alias for `coro_client<qb::io::transport::stcp>` (`wss://`, TLS). Needs `QB_HAS_SSL`. |
| `qb::http::ws::coro_session<Self, Server>` | Server-side CRTP base. You write `task<void> run()`; the base drives the upgrade and spawns it. |
| `qb::http::ws::IncomingFrame` | Owning value type returned by `receive()` / `next_frame()`. Safe to store past the `co_await`. |
| `qb::http::ws::ConnectResult` / `CloseResult` | Small `{ bool ok; }` outcomes for `connect` / `close_async`. |
| `qb::http::ws::run_sync(awaitable)` | Drive a WebSocket awaitable to completion on the current I/O thread. |

The coroutine entry points return awaiters built by `qb::http::async::make_awaiter<T>`, the same machinery the HTTP coroutine client uses. You consume them from any `qb::io::async::task<...>` coroutine, or drive a top-level one with `run_sync`. <!-- src: qbm/http/ws/coro.h:376-460 -->

### `IncomingFrame` — an owning event

`receive()` and `next_frame()` resolve to one `IncomingFrame`. Unlike the zero-copy pointers handed to the classical `on(message)` callbacks, an `IncomingFrame` owns copies of its `payload` and `close_reason`, so you may keep it past the end of the `co_await` expression.

```cpp
struct IncomingFrame {
    enum class Kind : std::uint8_t {
        Message,      // text or binary data frame
        Ping,         // incoming ping (the protocol layer auto-sends the Pong)
        Pong,         // incoming pong (reply to a locally sent ping)
        Close,        // peer requested close; close_code / close_reason are set
        Disconnected  // transport went away before another frame arrived
    };
    Kind          kind{Kind::Disconnected};
    std::string   payload{};       // owning copy of the frame payload
    bool          is_text{false};  // true when kind == Message and the type is Text
    std::uint16_t close_code{0};   // parsed close code (meaningful only for Close)
    std::string   close_reason{};  // human-readable close reason
};
```
<!-- src: qbm/http/ws/coro.h:115-129 -->

`Ping` and `Pong` are surfaced for observation only — the framing engine already auto-replies to a Ping with a matching Pong before you see it, so you do not echo it yourself.

## The coroutine client

`connect(uri, timeout)` performs both the TCP/TLS connection and the HTTP `Upgrade` handshake. The timeout is a `qb::duration` (default `qb::duration::zero()`, meaning no client-side deadline). `ConnectResult::ok` is `true` only when both phases succeed; on failure the result stays intentionally small — bind a `sending_http_request` callback or inspect the transport log before `connect()` if you need wire-level detail.

```cpp
// <!-- src: qbm/http/tests/test-ws-coro-server.cpp:294-314 -->
#include <http/http.h>
#include <http/ws.h>

qb::io::async::task<std::string> echo_round_trip() {
    qb::http::ws::coro_client ws;

    auto c = co_await ws.connect("ws://localhost:19941/",
                                 qb::duration{std::chrono::seconds{3}});
    if (!c.ok)
        co_return std::string{};

    qb::http::ws::MessageText msg;
    msg << "echo-me";
    ws << msg;                       // outbound send is synchronous (queued on the reactor)

    auto frame = co_await ws.receive();
    if (frame.kind == qb::http::ws::IncomingFrame::Kind::Message)
        co_return frame.payload;     // owning copy, safe to return
    co_return std::string{};
}
```

Sending is not a coroutine: `operator<<` queues an outbound frame on the reactor and returns immediately. Build outbound frames with `MessageText`, `MessageBinary`, `MessagePing`, `MessagePong`, and `MessageClose` exactly as in the callback API — see [WebSocket](./20-websocket.md). Client-to-server frames are masked unconditionally on send.

`receive()` yields successive inbound frames in delivery order. If frames arrive while no coroutine is parked on `receive()`, they are buffered (see [Back-pressure and the pending cap](#back-pressure-and-the-pending-cap)). Once the transport has dropped, every subsequent `receive()` resolves immediately with a `Disconnected` frame — the awaiter never hangs on a dead connection.

### Subprotocols and secure transport

The coroutine client inherits the subprotocol API from the shared CRTP base. Offer tokens in preference order before `connect()`; read the server's selection after it resolves.

```cpp
// <!-- src: qbm/http/tests/test-ws-coro-server.cpp:353-368 -->
qb::http::ws::coro_client ws;
ws.set_subprotocols({"chat.v1", "chat.v2"});

auto c = co_await ws.connect("ws://localhost:19943/");
if (c.ok) {
    std::string_view selected = ws.negotiated_subprotocol();  // "" if the server picked none
    (void) selected;
}
```

For `wss://`, use the secure alias. It is identical apart from the TLS transport and requires `QB_HAS_SSL`:

```cpp
qb::http::ws::coro_client_secure ws;
auto c = co_await ws.connect("wss://localhost:20443/ws");
```

### Closing

`close_async(status, reason)` queues a Close frame and suspends until the peer echoes it (or the transport drops). It is a half-duplex close — it does **not** tear down the TCP stream. Call `disconnect()` explicitly if you want a hard tear-down after the close handshake.

```cpp
auto res = co_await ws.close_async(qb::http::ws::CloseStatus::Normal, "done");
(void) res.ok;
```

A reserved or out-of-range close code is fail-fast: `close_async` re-dispatches through the `MessageClose` constructor, which throws `std::invalid_argument` for codes `1004/1005/1006/1015` or anything outside `1000..4999`. The throw surfaces inside your coroutine, so guard it if you forge codes. <!-- src: qbm/http/tests/test-ws-coro-negative.cpp:152-169 -->

## The coroutine server session

`coro_session<Self, Server>` is the server-side mirror of `coro_client`. Instead of a bag of `on(...)` handlers, you express the whole session as one `run()` coroutine. The base wires the HTTP protocol at construction, accepts the upgrade, installs `ws::protocol` on success, and spawns `run()` exactly once.

```cpp
// <!-- src: qbm/http/tests/test-ws-coro-server.cpp:53-89 -->
#include <http/http.h>
#include <http/ws.h>

class EchoServer;

class EchoSession
    : public qb::http::ws::coro_session<EchoSession, EchoServer> {
public:
    using base = qb::http::ws::coro_session<EchoSession, EchoServer>;
    using base::base;

    qb::io::async::task<void> run() {
        while (true) {
            auto frame = co_await this->next_frame();
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected ||
                frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
                co_return;                          // terminal — let the session retire
            }
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Message) {
                if (frame.is_text) {
                    qb::http::ws::MessageText reply;
                    reply << frame.payload;
                    *this << reply;
                } else {
                    qb::http::ws::MessageBinary reply;
                    reply << frame.payload;
                    *this << reply;
                }
            }
        }
    }
};

class EchoServer
    : public qb::io::use<EchoServer>::tcp::server<EchoSession> {
public:
    void on(IOSession &) {}
};
```

Contract:

- `Self` **must** define `qb::io::async::task<void> run()`. The base spawns it as soon as the upgrade succeeds.
- Inbound frames arrive through `next_frame()`, which has the same one-consumer rule, buffering, and `Disconnected`-after-drop behavior as the client's `receive()`.
- Closing is symmetric: `co_await close_async(status, reason)` queues a Close frame and resumes once the peer echoes it or the transport drops.

### Handshake hook

Customize or reject the upgrade with `set_handshake_hook(...)` **before** the session starts (the constructor is the right place). The hook runs once, on the upgrade request, before the `101` response is sent. Return `true` to accept; mutate the response to negotiate a subprotocol or add headers. Return `false` to refuse — set a non-success status and the base sends that response as-is, then drops the connection.

```cpp
// <!-- src: qbm/http/tests/test-ws-coro-server.cpp:177-186 -->
RejectingSession(RejectingServer &s) : base(s) {
    set_handshake_hook(
        [](RejectingSession &, qb::http::Request &, qb::http::Response &res) {
            res.status() = qb::http::status::FORBIDDEN;
            res.body()   = "not allowed";
            return false;
        });
}
```

If the hook returns `false` without setting a status, the base falls back to `400 Bad Request`. To advertise a subprotocol, append it to the response inside the hook:

```cpp
// <!-- src: qbm/http/tests/test-ws-coro-server.cpp:107-137 (condensed) -->
set_handshake_hook(
    [](MySession &, qb::http::Request &req, qb::http::Response &res) {
        const auto &offered = req.header("Sec-WebSocket-Protocol");
        if (offered.find("chat.v2") != std::string::npos)
            res.headers()["Sec-WebSocket-Protocol"].emplace_back("chat.v2");
        return true;
    });
```

### Driving the upgrade from a router

If an HTTP router has already parsed the upgrade request, hand it to `accept_upgrade(request, response)`. This is the single integration point between an external router and a coroutine session: it applies the hook, runs `switch_protocol<WS_Protocol>`, sends the response, and spawns `run()`. Pass a freshly constructed `qb::http::Response` as scratch. Call it on the io-handler thread that owns the transport — calling it from elsewhere violates the qb-io single-thread invariant. <!-- src: qbm/http/ws/coro.h:717-751 -->

## Lifetimes

The single sharpest rule of the server session: **`run()` must eventually return.**

To keep `*this` valid across every suspension point inside `run()`, the base captures the session's `shared_ptr` from the server registry when it spawns the loop. That keeps the session alive for the entire life of the coroutine — which is what you want at each `co_await`, but it also means a `run()` that never returns silently keeps that `shared_ptr` alive and leaks the session. Always provide a terminal branch on a `Close` or `Disconnected` frame, as in the echo example above. <!-- src: qbm/http/ws/coro.h:606-651 -->

If `run()` throws, the base catches it, makes a best-effort `1011` (`CloseStatus::UnexpectedReason`) Close to notify the peer, and disconnects; any secondary failure during that shutdown is swallowed because the transport may already be gone. <!-- src: qbm/http/ws/coro.h:627-648 -->

The client (`coro_client`) is a stack-owned object with deleted copy and move; it has no such retention model. You own its lifetime directly — keep it alive for as long as the coroutine that drives it is suspended on one of its awaiters.

### Driving a top-level awaitable

For tests, tools, and `main()`, run a WebSocket coroutine to completion synchronously with `run_sync`. It is a thin re-export of `qb::io::async::run_sync`, provided so code that already includes `<http/ws.h>` need not reach into another namespace.

```cpp
// <!-- src: qbm/http/ws/coro.h:55-58 -->
int main() {
    qb::io::async::init();
    auto out = qb::http::ws::run_sync(echo_round_trip());
    qb::io::cout() << out << '\n';
}
```

## Pitfalls

- **One consumer at a time.** A second overlapping `receive()` / `next_frame()`, or a second pending `close_async()`, throws `std::logic_error`. The API fails fast rather than silently dropping the earlier awaiter. Never park two awaiters of the same kind on one client or session. <!-- src: qbm/http/ws/coro.h:248-250, 447-450, 856-859, 873-876 -->
- **`run()` that never returns leaks the session.** The base intentionally retains the session for the coroutine's lifetime; you must reach a `co_return`, normally on a `Close`/`Disconnected` frame.
- **The close handshake does not close the socket.** `close_async` only queues a Close frame; the TCP stream stays up until the peer's echo or an explicit `disconnect()`. Do not assume the connection is gone the instant `close_async` resolves.
- **Reserved close codes throw.** `1004/1005/1006/1015` and any code outside `1000..4999` raise `std::invalid_argument` from `close_async`. The exception surfaces inside your coroutine.
- **Reconnecting a client resets it.** `connect()` on an already-used `coro_client` clears buffered frames and forcibly completes any parked `receive`/`close` awaiter with a `Disconnected`/failure result before reconnecting. A single instance can be reused, but an awaiter from the previous session is torn down. <!-- src: qbm/http/ws/coro.h:376-403 -->
- **Buffered frames are bounded.** See below; do not rely on an unbounded inbound queue.

### Back-pressure and the pending cap

Frames that arrive while no awaiter is parked are buffered, up to a per-client/per-session cap. The default cap is `1024`. When the cap is hit, the **oldest** buffered frame is dropped to make room — the tail of the stream (close frames, the latest state update) is usually what a slow consumer cares about. Setting the cap to `0` disables buffering entirely: any frame received with no awaiter parked is discarded.

```cpp
ws.set_pending_cap(64);   // bound the inbound backlog; 0 disables buffering
```
<!-- src: qbm/http/ws/coro.h:272-275, 213-230 -->

This cap governs only the coroutine adapter's inbound queue. The reassembled message-size limit and the wire-level RFC 6455 validation are unchanged from the callback path — see [WebSocket](./20-websocket.md).

## See also

- [WebSocket](./20-websocket.md) — the RFC 6455 upgrade flow, framing, and the callback `WebSocket<T>` client.
- [Asynchronous HTTP client](./14-async-http-client.md) — the awaiter model and `run_sync` shared with the HTTP coroutine client.
- [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md) — transport setup for `wss://`.

---

Previous: [WebSocket](./20-websocket.md)

Return to [Index](./README.md)

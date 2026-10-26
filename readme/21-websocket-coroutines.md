# WebSocket coroutines

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 3.3.0 (C++20 default, C++23 supported)

Write a WebSocket conversation as a single straight-line coroutine — `co_await` the connect, each inbound frame, and the close handshake — instead of scattering the logic across CRTP `on(...)` callbacks.

**Prerequisites:** [WebSocket](./20-websocket.md), [Asynchronous HTTP client](./14-async-http-client.md) (for the awaiter / `run_sync` model), [An HTTP server is an actor](./00-http-in-an-actor.md), and working knowledge of qb-io coroutines — see [C++20 coroutines](https://github.com/isndev/qb/blob/main/readme/3_qb_io/coroutines.md). **See also:** [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md) for `wss://`.

The coroutine API in `<qbm/http/ws.h>` is a thin, allocation-light layer over the same RFC 6455 framing engine that drives the callback `WebSocket<T>` client and `ws::protocol` server. It exists for the common case where a WebSocket exchange is naturally sequential — connect, authenticate, subscribe, wait for frames, reply, close — and reads more clearly as a loop than as a handler bag. Resumption is routed through `qb::io::async::coro_scheduler()`, so the continuation always runs on the listener thread that owns the socket; the single-threaded qb-io model is preserved end to end.

This is not a separate module. The coroutine types live alongside the callback API under `qb::http::ws`; you link `qbm::http` and include the same umbrella header. The secure client variant (`wss://`) requires `QB_HAS_SSL`, exactly as the callback secure client does.

```cpp
#include <qbm/http/http.h>
#include <qbm/http/ws.h>
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

The coroutine entry points return `http_awaiter` operations. `connect()` keeps the ordinary HTTP callback adapter; receive and close operations use an internal lifetime-aware slot completion. You consume them from any `qb::io::async::task<...>` coroutine, or drive a top-level one with `run_sync`. Public HTTP `async::awaiter<T>` and `make_awaiter` retain their callback contracts. Use `auto` or `co_await` for the WebSocket operations; their concrete deduced awaiter types and private client/session layouts require a consistent consumer rebuild when these headers change. <!-- src: qbm/http/src/qbm/http/coro.h:162-218,232-259; qbm/http/src/qbm/http/ws/coro.h:392,431-484,895-915,925-953 -->

Destroying an actually suspended task destroys its awaiter and makes that waiter reservation inactive. A successor `receive()` or `next_frame()` can take the slot; a frame arriving while no live waiter is parked follows the existing bounded-buffer policy. Destruction of an older completed awaiter cannot clear a newer reservation. A second **live** waiter still throws `std::logic_error`. Abandoning a close waiter releases its reservation, but does not retract an already queued Close frame. These lifetime rules do not make `Actor::kill()` cancel or destroy the suspended task automatically.
<!-- src: qbm/http/src/qbm/http/coro.h:93-112,182-184; qbm/http/src/qbm/http/ws/coro.h:216-258,431-484,622-637,895-915,925-953 -->

### Inside an actor: what ends a `receive()` loop

Two facts follow from that shared machinery, and together they are the whole lifetime story for a WebSocket coroutine running under `qb::Main`.

**The awaiter is not cancellation-aware.** It registers no `on_cancel` hook, so `Actor::kill()` neither wakes nor unwinds a coroutine parked on `receive()` or `close_async()`. What *does* resolve it is the transport: once the session is disconnected, `receive()` completes immediately with `IncomingFrame::Kind::Disconnected` instead of parking, so a `while` loop over `receive()` terminates on its own the moment the peer or your own `disconnect()` ends the stream.
<!-- src: qbm/http/src/qbm/http/ws/coro.h:431-447 (receive: buffered frame, else a Disconnected frame once _disconnected, else park) -->

**`coro_session::run()` is spawned outside your actor's scope.** The base drives the upgrade and then hands `run()` to `qb::io::async::coro_scheduler()` — the current thread's scheduler, which is the `VirtualCore`'s — capturing a `std::shared_ptr<Self>` so the session outlives every suspension inside the body. Like a coroutine route handler, it is therefore **not** counted by `has_active_coroutines()` and **not** cancelled by `kill()`; it ends when `run()` ends, and an uncaught exception in it sends a `1011` Close and drops the transport.
<!-- src: qbm/http/src/qbm/http/ws/coro.h:657-698 (spawn_run_loop: shared_ptr capture, scheduler spawn, 1011 on throw) -->

The practical consequence for shutdown: to stop a WebSocket coroutine, **disconnect the session**; `kill()` alone will not reach it. See [An HTTP server is an actor](./00-http-in-an-actor.md#shutting-down).

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
<!-- src: qbm/http/src/qbm/http/ws/coro.h:110-124 -->

`Ping` and `Pong` are surfaced for observation only — the framing engine already auto-replies to a Ping with a matching Pong before you see it, so you do not echo it yourself.

## The coroutine client

`connect(uri, timeout)` performs both the TCP/TLS connection and the HTTP `Upgrade` handshake. The timeout is one deadline across both phases, as a `qb::duration` (default `qb::duration::zero()`, meaning no client-side deadline). A server that withholds its upgrade response makes the awaiter resume once with `ConnectResult::ok == false` when that deadline expires. `ConnectResult::ok` is `true` only when both phases succeed; on failure the result stays intentionally small — bind a `sending_http_request` callback or inspect the transport log before `connect()` if you need wire-level detail. <!-- src: src/qbm/http/ws/ws.h:1471-1569, src/qbm/http/ws/coro.h:391-412 -->

```cpp
// <!-- src: qbm/http/tests/system/ws/ws-coro-client.cpp:375-397 -->
#include <qbm/http/http.h>
#include <qbm/http/ws.h>

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
// <!-- src: qbm/http/tests/system/ws/ws-coro-server.cpp:362-379 -->
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

A reserved or out-of-range close code is fail-fast: `close_async` re-dispatches through the `MessageClose` constructor, which throws `std::invalid_argument` for codes `1004/1005/1006/1015` or anything outside `1000..4999`. The throw surfaces inside your coroutine, so guard it if you forge codes. <!-- src: qbm/http/tests/system/ws/ws-coro-handshake-negative.cpp:113-126 -->

The Close frame is validated before the coroutine publishes its waiter or close-sent state. A rejected code or invalid UTF-8 reason therefore leaves the operation ready for a valid later close or peer-close echo. This validation guarantee does not promise atomic rollback of queued bytes or all base-class close flags if serialization or allocation fails.
<!-- src: qbm/http/src/qbm/http/ws/coro.h:459-482,925-953; qbm/http/src/qbm/http/ws/ws.cpp:210-230 -->

For a server-side `coro_session`, a close already sent through `close_async()` or initiated by an owning HTTP server's drain is awaited without another Close frame. The received Close is still delivered to `next_frame()` with its code/reason; its continuation runs through the scheduler, not inline inside the parser. A later disconnect completes a remaining close waiter. Invalid code/reason validation still precedes waiter state. This server-side behavior does not change the callback client's ownership or the cancellation rules above.
<!-- src: qbm/http/src/qbm/http/ws/coro.h:616-618,837-864,925-952; qbm/http/src/qbm/http/coro.h:104-112 -->

## The coroutine server session

`coro_session<Self, Server>` is the server-side mirror of `coro_client`. Instead of a bag of `on(...)` handlers, you express the whole session as one `run()` coroutine. The base wires the HTTP protocol at construction, accepts the upgrade, installs `ws::protocol` on success, and spawns `run()` exactly once.

```cpp
// <!-- src: qbm/http/tests/system/ws/ws-coro-server.cpp:62-92 -->
#include <qbm/http/http.h>
#include <qbm/http/ws.h>

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
// <!-- src: qbm/http/tests/system/ws/ws-coro-server.cpp:164-176 -->
RejectingSession(RejectingServer &s) : base(s) {
    set_handshake_hook(
        [](RejectingSession &, qb::http::Request &, qb::http::Response &res) {
            res.status() = qb::http::status::FORBIDDEN;
            res.body()   = "not allowed";
            return false;
        });
}
```

If the hook returns `false` without setting a status, the base falls back to `400 Bad Request`. A refusal always answers an error or a redirect: a status of 300 or more is sent as the hook set it, and anything below — the `200` a fresh `Response` starts with, a `101`, any `2xx` — becomes `400`. A hook that throws refuses the upgrade the same way. <!-- src: qbm/http/src/qbm/http/ws/coro.h:639-655 --> To advertise a subprotocol, append it to the response inside the hook:

```cpp
// <!-- src: qbm/http/tests/system/ws/ws-coro-server.cpp:101-134 (condensed) -->
set_handshake_hook(
    [](MySession &, qb::http::Request &req, qb::http::Response &res) {
        const auto &offered = req.header("Sec-WebSocket-Protocol");
        if (offered.find("chat.v2") != std::string::npos)
            res.headers()["Sec-WebSocket-Protocol"].emplace_back("chat.v2");
        return true;
    });
```

### Driving the upgrade from a router

If an HTTP router has already parsed the upgrade request, hand it to `accept_upgrade(request, response)`. This is the single integration point between an external router and a coroutine session: it applies the hook, runs `switch_protocol<WS_Protocol>`, sends the response, and spawns `run()`. Pass a freshly constructed `qb::http::Response` as scratch. Call it on the io-handler thread that owns the transport — calling it from elsewhere violates the qb-io single-thread invariant. <!-- src: qbm/http/src/qbm/http/ws/coro.h:770-801 -->

## Lifetimes

The single sharpest rule of the server session: **`run()` must eventually return.**

To keep `*this` valid across every suspension point inside `run()`, the base captures the session's `shared_ptr` from the server registry when it spawns the loop. That keeps the session alive for the entire life of the coroutine — which is what you want at each `co_await`, but it also means a `run()` that never returns silently keeps that `shared_ptr` alive and leaks the session. Always provide a terminal branch on a `Close` or `Disconnected` frame, as in the echo example above. <!-- src: qbm/http/src/qbm/http/ws/coro.h:657-697 -->

If `run()` throws, the base catches it, makes a best-effort `1011` (`CloseStatus::UnexpectedReason`) Close to notify the peer, and disconnects; any secondary failure during that shutdown is swallowed because the transport may already be gone. <!-- src: qbm/http/src/qbm/http/ws/coro.h:673-694 -->

The client (`coro_client`) is a stack-owned object with deleted copy and move; it has no such retention model. You own its lifetime directly — keep it alive for as long as the coroutine that drives it is suspended on one of its awaiters.

### Driving a top-level awaitable

For tests, tools, and `main()`, run a WebSocket coroutine to completion synchronously with `run_sync`. It is a thin re-export of `qb::io::async::run_sync`, provided so code that already includes `<qbm/http/ws.h>` need not reach into another namespace.

```cpp
// <!-- src: qbm/http/src/qbm/http/ws/coro.h:55-58 -->
int main() {
    qb::io::async::init();
    auto out = qb::http::ws::run_sync(echo_round_trip());
    qb::io::cout() << out << '\n';
}
```

## Pitfalls

- **One consumer at a time.** A second overlapping `receive()` / `next_frame()`, or a second pending `close_async()`, throws `std::logic_error`. The API fails fast rather than silently dropping the earlier awaiter. Never park two awaiters of the same kind on one client or session. <!-- src: qbm/http/src/qbm/http/ws/coro.h:250-254,461-464,909-912,927-930 -->
- **`run()` that never returns leaks the session.** The base intentionally retains the session for the coroutine's lifetime; you must reach a `co_return`, normally on a `Close`/`Disconnected` frame.
- **The close handshake does not close the socket.** `close_async` only queues a Close frame; the TCP stream stays up until the peer's echo or an explicit `disconnect()`. Do not assume the connection is gone the instant `close_async` resolves.
- **Reserved close codes throw.** `1004/1005/1006/1015` and any code outside `1000..4999` raise `std::invalid_argument` on the `close_async` path. The throw is not in `close_async` itself: it comes from the `MessageClose` constructor `close_async` builds, which rejects every code `is_sendable_close_code` refuses. The exception surfaces inside your coroutine. <!-- src: qbm/http/src/qbm/http/ws/coro.h:469,935; qbm/http/src/qbm/http/ws/ws.cpp:210-214; qbm/http/src/qbm/http/ws/ws.h:257-270 -->
- **Reconnecting a client resets it.** `connect()` on an already-used `coro_client` clears buffered frames and forcibly completes any parked `receive`/`close` awaiter with a `Disconnected`/failure result before reconnecting. A single instance can be reused, but an awaiter from the previous session is torn down. <!-- src: qbm/http/src/qbm/http/ws/coro.h:385-412 -->
- **Buffered frames are bounded.** See below; do not rely on an unbounded inbound queue.

### Back-pressure and the pending cap

Frames that arrive while no awaiter is parked are buffered, up to a per-client/per-session cap. The default cap is `1024`. When the cap is hit, the **oldest** buffered frame is dropped to make room — the tail of the stream (close frames, the latest state update) is usually what a slow consumer cares about. Setting the cap to `0` disables buffering entirely: any frame received with no awaiter parked is discarded. A lowered cap applies at once: a queue already above it loses its oldest frames, down to the cap. A cap of `0` is the exception — it discards arrivals and never purges what is already buffered. <!-- src: qbm/http/src/qbm/http/ws/coro.h:267-286, qbm/http/src/qbm/http/ws/coro.h:709-724 -->

```cpp
ws.set_pending_cap(64);   // bound the inbound backlog; 0 disables buffering
```
<!-- src: qbm/http/src/qbm/http/ws/coro.h:268-286, 213-231 -->

This cap governs only the coroutine adapter's inbound queue. The reassembled message-size limit and the wire-level RFC 6455 validation are unchanged from the callback path — see [WebSocket](./20-websocket.md).

## See also

- [WebSocket](./20-websocket.md) — the RFC 6455 upgrade flow, framing, and the callback `WebSocket<T>` client.
- [Asynchronous HTTP client](./14-async-http-client.md) — the awaiter model and `run_sync` shared with the HTTP coroutine client.
- [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md) — transport setup for `wss://`.

---

Previous: [WebSocket](./20-websocket.md)

Return to [Index](./README.md)

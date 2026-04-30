# Coroutine-First WebSocket API

`qb::http::ws` ships a coroutine surface that complements the existing
callback / CRTP API. It lives in a single header:

```cpp
#include <http/ws/coro.h>
```

The design mirrors `qbm/http/coro.h`, `qbm/redis`, and `qbm/pgsql`:

- One-shot, prvalue-only awaiter types built on top of the shared
  `qb::http::async::http_awaiter<T>` machinery.
- Resumption runs on the **same I/O thread** that owns the socket.
  `qb-io` is strictly mono-thread per listener and the coroutine API
  never escapes that contract — no extra thread, no locks.
- The classical callback / CRTP entry points stay supported, unchanged.
  You can mix both styles in the same application.

## Table of Contents

- [Why coroutines?](#why-coroutines)
- [Coroutine client](#coroutine-client)
  - [`connect(uri, timeout)`](#connecturi-timeout)
  - [`receive()`](#receive)
  - [`close_async(status, reason)`](#close_asyncstatus-reason)
  - [Buffering policy](#buffering-policy)
- [Coroutine server session](#coroutine-server-session)
  - [Upgrade flow](#upgrade-flow)
  - [Lifetime guarantees](#lifetime-guarantees)
  - [Handshake hook (subprotocols)](#handshake-hook-subprotocols)
  - [Error handling](#error-handling)
- [`run_sync`](#run_sync)
- [When NOT to use the coroutine API](#when-not-to-use-the-coroutine-api)

---

## Why coroutines?

Conversational WebSocket protocols — RPC-over-WS, JSON-RPC, custom
request/reply flows — often need to express a linear state machine:

```
connect → send("auth") → receive("ok") → send("subscribe") → loop { receive(...); … }
```

Expressed as callbacks, each arrow becomes a separate lambda with
captured state shuttled through member variables. With coroutines the
same flow reads top-to-bottom, exception-safe, and trivially composable
with any other `qb::io::async::task<T>`.

---

## Coroutine client

```cpp
qb::io::async::task<void> login_and_greet() {
    qb::http::ws::coro_client ws;

    auto c = co_await ws.connect("ws://api.example.com/socket",
                                 std::chrono::seconds{3});
    if (!c.ok) co_return; // connect + handshake failed

    qb::http::ws::MessageText hello; hello << R"({"op":"hello"})";
    ws << hello;

    while (true) {
        auto frame = co_await ws.receive();
        switch (frame.kind) {
          case qb::http::ws::IncomingFrame::Kind::Message:
            handle_message(frame.payload, frame.is_text);
            break;
          case qb::http::ws::IncomingFrame::Kind::Close:
          case qb::http::ws::IncomingFrame::Kind::Disconnected:
            co_return;
          case qb::http::ws::IncomingFrame::Kind::Ping:
          case qb::http::ws::IncomingFrame::Kind::Pong:
            break; // auto-acked by the protocol layer
        }
    }
}
```

### `connect(uri, timeout)`

- Performs both the TCP connection and the HTTP upgrade. The returned
  `ConnectResult::ok` is `true` iff both succeeded.
- `timeout` is a `std::chrono::milliseconds`. A value of `0` disables
  the timeout.
- Also accepts a `std::string_view` URI overload for terser test code.

### `receive()`

- Resolves with the next inbound `IncomingFrame`. `IncomingFrame::Kind`
  enumerates all possible outcomes:
  - `Message` — text or binary data frame (use `is_text` + `payload`).
  - `Ping` / `Pong` — observational copies; Pongs are automatically
    emitted by the protocol layer in reply to peer Pings.
  - `Close` — a Close frame from the peer; `close_code` and
    `close_reason` are populated.
  - `Disconnected` — the TCP stream was lost before the next frame
    arrived. The awaiter **never hangs** on a dropped connection.
- Only **one** coroutine may be parked on `receive()` at a time; a
  second concurrent `co_await ws.receive()` throws `std::logic_error`.
  If you need fan-out, buffer the frames yourself or split into several
  clients.

### `close_async(status, reason)`

- Queues a Close frame and suspends until the peer echoes it or the
  transport drops first. The reason string is UTF-8 and capped at 123
  bytes (RFC 6455 control frame limit).
- If the peer closes and the transport tears down very quickly, your
  next observable frame may be `Disconnected` instead of `Close`; both
  outcomes are valid terminal states.
- Reserved close codes (`1004`, `1005`, `1006`, `1015`, or anything
  outside `[1000..4999]`) raise `std::invalid_argument` at construction
  time — building such a frame is always a programming bug.

### Subprotocol negotiation

The client advertises subprotocol offers through the CRTP base:

```cpp
qb::http::ws::coro_client ws;
ws.set_subprotocols({"chat.v2", "chat.v1"});   // preference order
auto c = co_await ws.connect("wss://api.example.com/socket");
if (!c.ok) co_return;

const std::string_view chosen = ws.negotiated_subprotocol();
// chosen == "chat.v2" when the server picks that token, empty otherwise.
```

- `set_subprotocols(list)` overwrites the offer list.
- `add_subprotocol(name)` appends a single token.
- The client sends exactly one `Sec-WebSocket-Protocol` header with the
  comma-separated list (RFC 6455 §4.1).
- `negotiated_subprotocol()` becomes valid after `connect()` resolves
  successfully and stays empty if the server omitted the header or did
  not accept any offer.

### Buffering policy

- Between two `receive()` calls, inbound frames queue up. The cap is
  `1024` by default; configure it with `set_pending_cap(N)`.
- When the cap is reached, the **oldest** frame is dropped to make
  room — the tail of a stream is usually more interesting than its
  head (latest state update, Close frame, ...).
- Setting the cap to `0` disables buffering entirely.

---

## Coroutine server session

Server-side sessions can be written as a single `run()` coroutine. The
base class handles the HTTP upgrade, pumps inbound frames into a queue,
and spawns `run()` as soon as the `101 Switching Protocols` response
leaves the wire.

```cpp
class ChatServer;

class ChatSession
    : public qb::http::ws::coro_session<ChatSession, ChatServer> {
public:
    using base = qb::http::ws::coro_session<ChatSession, ChatServer>;
    using base::base;

    qb::io::async::task<void> run() {
        while (true) {
            auto frame = co_await this->next_frame();
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Close ||
                frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected) {
                co_return;
            }
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Message) {
                qb::http::ws::MessageText reply;
                reply << "echo:" << frame.payload;
                *this << reply;
            }
        }
    }
};
```

### Upgrade flow

1. The classical CRTP pipeline delivers a `qb::http::Request` to
   `coro_session::on(Protocol::request&&)`.
2. The base runs your (optional) handshake hook, then calls
   `switch_protocol<WS_Protocol>(*this, req, response)`.
3. On success, the `101` response is written, **`run()` is spawned
   once**, and subsequent ws frames start landing in the queue.

### Lifetime guarantees

- The base retrieves a `std::shared_ptr<Self>` from the owning
  io_handler's session registry **before** spawning `run()`, and
  captures it in the coroutine lambda. That means the session lives
  exactly as long as the coroutine needs it — every `co_await` point
  is guaranteed to resume on a valid `*this`.
- Conversely, the coroutine **must** eventually return. Typical exit
  conditions are a `Disconnected` or `Close` frame surfaced through
  `next_frame()`. If you lose track of those, the session will leak
  until the process exits.

### Handshake hook (subprotocols)

Call `set_handshake_hook(...)` before the first request arrives
(typically in the session constructor):

```cpp
ChatSession(ChatServer& s) : base(s) {
    set_handshake_hook(
        [](ChatSession&, qb::http::Request& req, qb::http::Response& res) {
            const auto& offers = req.header("Sec-WebSocket-Protocol");
            if (offers.find("chat.v1") != std::string::npos) {
                res.headers()["Sec-WebSocket-Protocol"]
                    .emplace_back("chat.v1");
                return true;  // accept
            }
            res.status() = qb::http::status::UPGRADE_REQUIRED;
            return false;     // reject (base sends `res`, then disconnects)
        });
}
```

Return `false` to reject the upgrade: the response you populate is
sent verbatim (a `400 Bad Request` is used if the status was left at
`0`), then the TCP stream is closed.

### Error handling

- Exceptions escaping `run()` are caught by the base. The peer
  receives a `1011 UnexpectedReason` Close frame (best-effort; the
  transport may already be gone) and the connection is torn down.
- `std::invalid_argument` from `close_async(...)` for a reserved code
  follows the same path — document your close codes accordingly.

---

## `run_sync`

Synchronous entry points (tests, `main()`, CLI tools) can drive any
awaitable to completion:

```cpp
int main() {
    qb::io::async::init();
    qb::http::ws::run_sync(login_and_greet());
}
```

This is a thin re-export of `qb::io::async::run_sync` — kept here so
code that has already included `<http/ws/coro.h>` doesn't need to reach for
another namespace.

---

## When NOT to use the coroutine API

- Fan-in of many independent peers on the same session: CRTP or
  `io_handler::stream(...)` is a better fit.
- Single-frame, fire-and-forget dispatchers: the callback client
  (`qb::http::ws::client`) stays the most compact choice.
- Existing callback-based codebases: there is no migration cost — the
  callback API remains stable.

# 21: WebSocket Coroutines

`qb::http::ws` provides coroutine-friendly WebSocket clients and server sessions
through the umbrella header:

```cpp
#include <http/ws.h>
```

Use the coroutine API when a WebSocket conversation is naturally sequential:
connect, authenticate, subscribe, wait for frames, reply, then close. The API is
built on `qb::io::async::task<T>` and resumes on the same `qb-io` listener that
owns the socket.

## Coroutine Client

```cpp
qb::io::async::task<void> talk_to_echo() {
    qb::http::ws::coro_client ws;

    auto connected = co_await ws.connect("ws://localhost:20197/",
                                         std::chrono::seconds{3});
    if (!connected.ok) co_return;

    qb::http::ws::MessageText hello;
    hello << "hello";
    ws << hello;

    auto frame = co_await ws.receive();
    if (frame.kind == qb::http::ws::IncomingFrame::Kind::Message) {
        qb::io::cout() << frame.payload << '\n';
    }

    co_await ws.close_async(qb::http::ws::CloseStatus::Normal, "done");
}
```

`connect(uri, timeout)` performs both the TCP/TLS connection and the HTTP
WebSocket upgrade. `ConnectResult::ok` is true only when both phases succeed.

`receive()` yields an owning `IncomingFrame`:

- `Message`: text or binary data, with `payload` and `is_text`;
- `Ping` / `Pong`: control-frame observations;
- `Close`: peer close with `close_code` and `close_reason`;
- `Disconnected`: transport loss before another frame arrived.

Only one coroutine may wait on `receive()` at a time. A second overlapping
awaiter throws `std::logic_error`, which makes misuse explicit instead of
dropping callbacks silently.

## Subprotocols

The coroutine client uses the same CRTP client base as the callback API:

```cpp
qb::http::ws::coro_client ws;
ws.set_subprotocols({"chat.v2", "chat.v1"});

auto connected = co_await ws.connect("wss://localhost:20443/ws");
if (connected.ok) {
    auto selected = ws.negotiated_subprotocol();
    (void) selected;
}
```

The client sends one `Sec-WebSocket-Protocol` header containing the offered
tokens in preference order. The selected token is available after a successful
handshake, or empty if the server did not select one.

## Coroutine Server Session

`coro_session<Self, Server>` wraps the normal HTTP upgrade and then starts a
single `run()` coroutine for the WebSocket lifetime.

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

The base keeps the session alive while `run()` is active and surfaces terminal
states through `next_frame()`. `run()` must eventually return after close or
disconnect; otherwise the session remains intentionally retained by its
coroutine.

## Handshake Hook

Use `set_handshake_hook(...)` to accept/reject an upgrade or select a
subprotocol before the `101` response is sent:

```cpp
ChatSession(ChatServer& server) : base(server) {
    set_handshake_hook(
        [](ChatSession&, qb::http::Request& req, qb::http::Response& res) {
            if (req.header("Sec-WebSocket-Protocol").find("chat.v1") !=
                std::string::npos) {
                res.headers()["Sec-WebSocket-Protocol"].emplace_back("chat.v1");
                return true;
            }
            res.status() = qb::http::status::UPGRADE_REQUIRED;
            res.body() = "chat.v1 required";
            return false;
        });
}
```

When the hook returns false, the response is delivered and the connection is
closed. If no status was set, the base falls back to `400 Bad Request`.

## `run_sync`

Tests, tools, and small programs can drive a WebSocket awaitable synchronously:

```cpp
int main() {
    qb::io::async::init();
    qb::http::ws::run_sync(talk_to_echo());
}
```

This is a thin alias over `qb::io::async::run_sync`, provided so users that
already include `<http/ws.h>` do not need to reach into another namespace.

Previous: [WebSocket](./20-websocket.md)

---
Return to [Index](./README.md)

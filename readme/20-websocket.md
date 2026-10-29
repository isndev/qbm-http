# WebSocket (RFC 6455)

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 3.3.0 (C++20 default, C++23 supported)

Upgrade an HTTP/1.1 connection to a full-duplex RFC 6455 WebSocket — server-side handshake validation, the CRTP/callback client, automatic ping keepalive, strict framing, and WSS over TLS.

**Prerequisites:** [Core concepts](./01-core-concepts.md), [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md) — **See also:** [WebSocket coroutines](./21-websocket-coroutines.md), [Asynchronous HTTP client](./14-async-http-client.md)

WebSocket lives under `qb::http::ws`. It is not a separate module: an application that already links `qbm::http` gets it for free through the umbrella header. A connection begins life as an ordinary HTTP/1.1 `GET` carrying `Upgrade: websocket`; once the handshake succeeds the byte stream stops being parsed as HTTP and is handed to `qb::http::ws::protocol`, which turns frames into `on(...)` events.

> **Feature gate.** The entire WebSocket subsystem requires `QB_HAS_SSL`, not only secure WS. `<qbm/http/http.h>` includes `src/qbm/http/ws/ws.h` only under `#ifdef QB_HAS_SSL`, and `src/qbm/http/ws/ws.h` itself opens with `#error "websocket protocol requires OpenSSL crypto library"` — even plaintext `ws://` cannot compile without OpenSSL, because the handshake hash (SHA-1 + base64) and the masking-key CSPRNG come from `qb::crypto`. In an SSL-less build, `qb::http::ws::*` simply does not exist. <!-- src: qbm/http/src/qbm/http/http.h:45-48, src/qbm/http/ws/ws.h:22-25 -->

```cpp
#include <qbm/http/http.h>   // umbrella: pulls in WebSocket support under QB_HAS_SSL
// or use the focused public header:
// #include <qbm/http/ws.h>
```

This page covers the HTTP/1.1 upgrade path only. WebSocket over HTTP/2 extended `CONNECT` and WebTransport over HTTP/3 are not part of this integration. For a coroutine-shaped API over the same wire protocol, see [WebSocket coroutines](./21-websocket-coroutines.md).

## Concepts

The WebSocket subsystem is split across a few namespaces. You normally only touch `qb::http::ws`; the protocol templates re-export the rest. <!-- src: src/qbm/http/ws/ws.h:1119-1136 -->

| Symbol | Namespace | Role |
| --- | --- | --- |
| `protocol<IO_>` | `qb::http::ws` | The per-connection framer. Resolves to a server or client variant from `IO_::has_server`. Installed by `switch_protocol`. |
| `MessageText`, `MessageBinary`, `MessagePing`, `MessagePong`, `MessageClose` | `qb::http::ws` | Outbound frame value types. Stream payload in with `operator<<`, then send the value with `session << msg`. |
| `CloseStatus` | `qb::http::ws` | RFC 6455 §7.4 close codes (`Normal`, `GoingAway`, `ProtocolError`, …). |
| `WebSocket<T, Transport>` | `qb::http::ws` | CRTP client. `T` receives `connected` / `message` / `ping` / `pong` / `closed` events. |
| `WebSocketSecure<T>` | `qb::http::ws` | `WebSocket<T, qb::io::transport::stcp>` — the TLS-backed client. |
| `client`, `client_secure` (`Client<Transport>`) | `qb::http::ws` | Callback client: register lambdas instead of subclassing. |
| `WebSocketRequest` | `qb::http` | A `Request` preloaded with the four upgrade headers -- not `Host`: set it before writing one by hand, or a qbm-http server answers 400 (Huly QB-1186). |
| `generateKey()` | `qb::http::ws` | A fresh base64 `Sec-WebSocket-Key` (16 random bytes). |

A few mechanics worth knowing before you wire anything up:

- **The handshake is an HTTP exchange.** The client sends `GET` with `Sec-WebSocket-Key`; the server replies `101 Switching Protocols` with `Sec-WebSocket-Accept = base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`. The client verifies that accept value in constant time. <!-- src: src/qbm/http/ws/ws.h:869,872-879,946-955,1074-1099 -->

```mermaid
sequenceDiagram
    participant Cl as ws client
    participant Sv as http server
    Cl->>Sv: GET / · Upgrade: websocket · Sec-WebSocket-Key
    Note over Sv: validate · Sec-WebSocket-Accept =<br/>base64(sha1(key + RFC 6455 GUID))
    Sv-->>Cl: 101 Switching Protocols · Sec-WebSocket-Accept
    Note over Cl: verify accept in constant time
    Note over Cl,Sv: switch_protocol → ws::protocol,<br/>byte stream is now WebSocket frames
    Cl->>Sv: masked text / binary / ping frames
    Sv-->>Cl: on(MessageText) · auto-pong to ping
```
- **Masking is directional and mandatory.** Every client-to-server frame (control frames included) must be masked; every server-to-client frame must not be. The framer enforces both directions: a server that receives an unmasked frame, or a client that receives a masked one, fails the connection with `ProtocolError`. On the send side `WebSocket::operator<<` forces `masked = true` on outbound frames regardless of what you set. <!-- src: src/qbm/http/ws/ws.h:724-736, src/qbm/http/ws/ws.h:1820-1823 -->
- **A protocol failure is final before anyone hears of it.** When the framer refuses a frame, `fail_connection` marks the connection failed and clears its reassembly state first, queues one Close (`1002`, `1007` or `1009`), and only then `notify_protocol_error` reports `on(error)` to an I/O handler that declares an `error` event — so the observer finds the connection already closed to input, and the failure is reported once. The report comes from inside the parser, which is `noexcept`: an exception thrown by the observer is logged and contained, never propagated. The CRTP and callback clients run their `on(error)` / `on_error` later, after parser dispatch. <!-- src: qbm/http/src/qbm/http/ws/ws.h:446-507 -->
- **Reassembly is bounded by default.** A message reassembled from continuation fragments is capped at `qb::http::protocol_limits::MAX_BODY_SIZE`; a peer streaming unbounded fragments is cut off with `CloseStatus::MessageTooBig`. Call `set_max_payload_size(0)` only deliberately to lift the cap. <!-- src: src/qbm/http/ws/ws.h:444, src/qbm/http/ws/ws.h:603-607, src/qbm/http/ws/ws.h:680-683 -->
- **Ping keepalive is a `qb::duration`.** `set_ping_interval(qb::duration)` arms the ping timer after the upgrade succeeds; on each tick it sends a `MessagePing`, and the framer auto-replies to inbound pings with a same-payload `MessagePong`. A zero interval disables it. <!-- src: src/qbm/http/ws/ws.h:1391-1394, src/qbm/http/ws/ws.h:564-572, src/qbm/http/ws/ws.h:1798-1805 -->

## Server: upgrade an existing HTTP session

A WebSocket server session is an ordinary `qb-io` TCP session that starts by parsing HTTP. When the upgrade `GET` arrives, you call `switch_protocol<ws_protocol>(...)`, which validates the request, emits the `101` response, and swaps in the WebSocket framer. After that, frames arrive as `on(ws_protocol::message&&)` (plus `ping` / `pong` / `close`).

For a bare WebSocket endpoint, subclass `qb::io::use<Self>::tcp::client<Server>` — an HTTP-parsing TCP session bound to its listener.

<!-- src: qbm/http/tests/system/ws/ws-lifecycle.cpp:108-147 -->
```cpp
#include <qbm/http/http.h>
#include <qb/io/async.h>

class WsServer;

// One connected WebSocket peer.
class WsSession : public qb::io::use<WsSession>::tcp::client<WsServer> {
public:
    using Protocol    = qb::http::protocol<WsSession>;     // HTTP/1.1 parser
    using ws_protocol = qb::http::ws::protocol<WsSession>; // WebSocket framer

    explicit WsSession(WsServer &server) : client(server) {}

    // Initial HTTP request: try the upgrade.
    void on(Protocol::request &&request) {
        // The request-only overload validates the handshake, queues the 101
        // response, and installs the framer. It returns a ws_protocol* — and
        // yields nullptr (leaving the protocol not_ok) when the request is not
        // a valid upgrade.
        if (!this->switch_protocol<ws_protocol>(*this, request))
            disconnect();
    }

    // A complete text or binary message arrived.
    void on(ws_protocol::message &&event) {
        // event.ws is the qb::http::ws::Message; event.data / event.size are a
        // read-only view of the unmasked payload. Echo it back here.
        *this << event.ws;
    }

    void on(ws_protocol::ping &&) {}  // auto-pong already sent by the framer
    void on(ws_protocol::pong &&) {}
    void on(ws_protocol::close &&) {} // peer Close: defining this handler
                                      // suppresses the framer's auto-echo —
                                      // re-send a peer-initiated Close, but do not echo
                                      // when the active protocol's server_draining() is true
};

// The listener: accepts sockets and spawns WsSession instances.
class WsServer : public qb::io::use<WsServer>::tcp::server<WsSession> {
public:
    void on(IOSession &) {}  // optional: called per new connection
};
```

`switch_protocol` has two server overloads. It constructs the selected protocol and returns its pointer on success. <!-- src: qb/src/qb/io/async/io.h:928-939 -->

- **One-call form** — validates the handshake, builds the `101` response, **and queues it on the session** before installing the framer. This is the form shown above. <!-- src: src/qbm/http/ws/ws.h:1028-1035 -->
- **`switch_protocol<ws_protocol>(*this, request, response)`** — fills a `response` you own but does **not** send it, so you can add headers (or transfer the socket to another actor) before flushing it yourself with `session << response`. Use this when an HTTP router handled the request and you want to hand the upgrade off. <!-- src: src/qbm/http/ws/ws.h:1044-1053; examples/06-modules/ws/01-chat-server.cpp:621-641 -->

`switch_protocol<_Protocol>(...)` returns a `_Protocol*` (here a `ws_protocol*`), not a `bool`: it yields the installed protocol pointer on success and `nullptr` — marking the protocol `not_ok` — when the request is not a valid RFC 6455 upgrade. Test it as a pointer (`if (!this->switch_protocol<ws_protocol>(...))`). On failure, either `disconnect()` or queue a `400` HTTP response and `close_after_deliver()` so the client sees the error before the socket closes. <!-- src: qb/src/qb/io/async/io.h:928-939 -->

### What the handshake validator enforces

`populate_handshake_response` rejects anything that is not a strict RFC 6455 §4.2.1 upgrade. The request must be: HTTP `GET`; `Upgrade: websocket` (case-insensitive); `Connection` containing the `Upgrade` token; `Sec-WebSocket-Version: 13`; and a `Sec-WebSocket-Key` that is exactly 24 base64 characters decoding to 16 bytes with a clean base64 round-trip. Otherwise the response is `400 Bad Request` and the protocol goes `not_ok`. <!-- src: src/qbm/http/ws/ws.h:971-1001 -->

### Broadcasting from a server

A server (or `io_handler`) owns its sessions, so `stream(...)` fans a frame out to every connected session and `stream_if(predicate, ...)` to a filtered subset. Build the frame once and pass it by value: <!-- src: qb/src/qb/io/async/io_handler.h:317-362, examples/06-modules/ws/01-chat-server.cpp:693-699 -->

```cpp
qb::http::ws::MessageText msg;
msg << R"({"type":"system","text":"server restarting"})";

server().stream(msg);                                  // every peer
server().stream_if([this](const WsSession &s) {        // a subset
    return &s != this;                                 // all but the sender
}, msg);
```

### Handing the upgrade off to another actor

A common pattern (see `examples/06-modules/ws/01-chat-server.cpp`) keeps the HTTP listener separate from the WebSocket actor: the HTTP route extracts the transport with `extractSession(...)`, ships it to the WebSocket actor in a `qb::Event`, and calls `ctx->suppress_response()` so the routing context destructor does not send a stale, moved-from HTTP response over the now-transferred socket. The receiving actor calls `registerSession(...)`, then the three-argument `switch_protocol` overload, then flushes the `101`: <!-- src: examples/06-modules/ws/01-chat-server.cpp:544,555-566,621-641; qbm/http/src/qbm/http/routing/context.h:1446-1450 -->

```cpp
void on(TransferToWebSocketEvent &event) {
    // registerSession returns nullptr (and closes the transport) when the
    // io_handler session limit is reached — null-check before use.
    auto *session = registerSession(std::move(event.data->transport));
    if (!session)
        return;
    if (session->switch_protocol<WsSession::ws_protocol>(
            *session, event.data->request, event.data->response)) {
        *session << event.data->response;  // finalize with the 101
    } else {
        session->disconnect();             // not a valid upgrade
    }
}
```

### Draining an in-place HTTP upgrade

`qb::http::Server::drain(deadline, on_drained)` includes a WebSocket upgraded in place while the session remains in that server's ownership (Huly QB-1097). It queues Close `1001 Going Away`, stops dispatching new Data/Ping/Pong to the application, and waits for the closing session or the shared drain deadline. The protocol still answers Ping with Pong until the peer Close arrives ([RFC 6455 §5.5.2](https://www.rfc-editor.org/rfc/rfc6455#section-5.5.2)); application Ping/Pong callbacks stay suppressed. A valid peer Close is still delivered to its Close observer; output already queued is finished before transport closure. A custom Close handler can inspect the active `ws_protocol`'s `server_draining()` and must not echo an acknowledgement of the Close the drain already sent.

This does **not** extend the old HTTP server's ownership: after `extractSession`, the receiving actor/server must manage the transferred connection's shutdown. A raw `qb::io::tcp::server` is not automatically an HTTP server with this drain API. Coroutine sessions preserve `IncomingFrame::Close` and its code/reason; waiting with `close_async()` after a close has begun sends no duplicate frame.
<!-- src: src/qbm/http/1.1/http.h:989-1030,1069-1090,1121-1135; src/qbm/http/ws/ws.h:510-580,583-585,655-674; src/qbm/http/ws/coro.h:837-864,925-952 -->

## Sending frames

Each outbound frame is a value type derived from `qb::http::ws::Message`. Stream the payload in with `operator<<`, then send the whole value with `session << frame`. The framer attaches the correct opcode, length encoding, and (on the client) masking. <!-- src: src/qbm/http/ws/ws.h:100,150,165,181,197 -->

```cpp
qb::http::ws::MessageText text;
text << R"({"event":"hello"})";
*this << text;

qb::http::ws::MessageBinary bin;
bin << some_bytes;          // any type the qb::allocator::pipe<char> accepts
*this << bin;

qb::http::ws::MessagePing  ping;   // empty keepalive ping
*this << ping;
```

### Closing

`MessageClose` carries a 2-byte status code plus an optional UTF-8 reason, capped at 125 bytes total (2 status + 123 reason). Construction is fail-fast: a reserved code (`1004` / `1005` / `1006` / `1015`) or one outside `[1000, 4999]` throws `std::invalid_argument`, and an over-long reason is truncated on a UTF-8 boundary. <!-- src: src/qbm/http/ws/ws.cpp:210-234, src/qbm/http/ws/ws.h:287-302 -->

```cpp
qb::http::ws::MessageClose bye(qb::http::ws::CloseStatus::Normal, "done");
*this << bye;
```

RFC 6455 §5.5.1 is a two-way handshake: after sending Close, wait for the peer's Close before ending the transport. Outside a server-initiated drain, the framer auto-echoes a valid peer Close when no `on(close)` handler is defined, then goes `not_ok`. Defining that handler makes the application responsible for its echo. During an owning HTTP server's drain, Close has already been queued: the peer Close callback still runs, but a custom handler must check the active protocol's `server_draining()` and avoid another echo. Queued output is finished before transport closure; `disconnect()` remains an immediate abort. <!-- src: src/qbm/http/ws/ws.h:510-563,655-674 -->

## Client: the CRTP form

Subclass `WebSocket<Self>` (or `WebSocketSecure<Self>` for WSS) when the client holds state. You receive lifecycle and frame events as `on(...)` overloads; only the handlers you actually define are wired up. <!-- src: src/qbm/http/ws/ws.h:1153-1829,1838-1839 -->

Early frames enter an owning queue through a cold helper, keeping queue construction outside established frame dispatch. The queued frame retains its payload and reconstructs the event when delivered. <!-- src: src/qbm/http/ws/ws.h:1284-1293 -->

<!-- src: src/qbm/http/ws/ws.h:1312-1324 (illustrative of the public WebSocket<T> event API) -->
```cpp
#include <qbm/http/http.h>
#include <qb/io/async.h>
#include <chrono>

class Client : public qb::http::ws::WebSocket<Client> {
public:
    void on(connected &&) {                    // 101 verified, framer installed
        set_ping_interval(std::chrono::seconds(30)); // qb::duration keepalive
        qb::http::ws::MessageText hello;
        hello << R"({"event":"hello"})";
        *this << hello;
    }

    void on(message &&event) {                 // a complete message
        qb::io::cout() << std::string_view(event.data, event.size) << '\n';
    }

    void on(closed &&) {}                        // peer Close frame
    void on(error  &&) {}                         // handshake / protocol failure
    void on(disconnected &&) {}                   // TCP stream gone
};

// Drive it from an actor or a standalone qb-io listener:
Client ws;
ws.connect(qb::io::uri("ws://localhost:9000/chat"));  // takes a uri, not a string; "wss://" for TLS
```

The `connect(...)` signature is `connect(const qb::io::uri &remote, qb::duration timeout = qb::duration::zero(), bool verify_peer = true)`. It establishes the TCP (or TLS) connection, sends the upgrade `GET`, and verifies the `101` before firing `connected`. A positive `timeout` is one deadline across both phases; zero disables it. The ping timer starts only after a verified upgrade. `verify_peer` controls TLS certificate verification on the secure transport. A retry requested from a failure callback starts after the old transport's disconnect dispatch, with old input/output buffers cleared. After the peer has closed the connection, qb-io's `dispose()` has closed the transport already, so a `connect()` from the `disconnected` handler starts at once, in the same loop pass. A client may be stack-owned or held in a `unique_ptr`; its pending connector callback becomes inert when it is destroyed. <!-- src: src/qbm/http/ws/ws.h:1471-1569, src/qbm/http/ws/ws.h:1172-1196, src/qbm/http/ws/ws.h:1349-1353, src/qbm/http/ws/ws.h:1230-1255 -->

The `connected`, parsed-handshake/protocol `error`, and `disconnected` handlers run after parser and I/O dispatch. They may release their client. Frames that arrive with the 101 reach user handlers after `connected`. <!-- src: src/qbm/http/ws/ws.h:1580-1651, src/qbm/http/ws/ws.h:1751-1789 -->

A transport connect failure or explicit pending `disconnect()` may call `error` synchronously. If a peer closes before the 101, `error` reports the failed connect once. <!-- src: src/qbm/http/ws/ws.h:1258-1273, src/qbm/http/ws/ws.h:1359-1374 -->

A `sending_http_request` hook still runs synchronously, but a hook that cancels, replaces or destroys its client stops that attempt's Upgrade from being sent. <!-- src: src/qbm/http/ws/ws.h:1545-1556 -->

## Client: the callback form

For compact, stateless clients, use `qb::http::ws::client` (or `client_secure` for WSS) and register lambdas. Each `on_*` returns `*this` so the calls chain. <!-- src: src/qbm/http/ws/ws.h:2038-2039 -->

<!-- src: qbm/http/tests/system/ws/ws-client-echo.cpp:222-258 -->
```cpp
#include <qbm/http/http.h>

qb::http::ws::client ws;

ws.on_connected([&](auto &) {
      qb::io::cout() << "connected\n";
  })
  .on_message([](auto &event) {
      qb::io::cout() << std::string_view(event.data, event.size) << '\n';
  })
  .on_error([](auto &) {
      qb::io::cout() << "handshake failed\n";
  });

ws.connect(qb::io::uri("ws://localhost:9000/"));
```

Both client forms expose the same connection controls: `set_ping_interval(qb::duration)`, `close(CloseStatus, reason)`, `disconnect()` or `disconnect(reason)` with an `int` or `qb::io::async::event::disconnect_reason`, and the subprotocol API below. A supplied disconnect reason reaches the `disconnected` handler after teardown. <!-- src: src/qbm/http/ws/ws.h:1359-1380 -->

## Subprotocol negotiation

Advertise an ordered list of subprotocols before `connect()`. The client serializes them into `Sec-WebSocket-Protocol`; the server must echo exactly one (case-sensitive) of them or omit the header. After `connected` fires, `negotiated_subprotocol()` returns the chosen token, or empty if the server picked none. <!-- src: src/qbm/http/ws/ws.h:1423-1426, src/qbm/http/ws/ws.h:1457-1458, src/qbm/http/ws/ws.h:1542, src/qbm/http/ws/ws.h:1598-1618 -->

```cpp
qb::http::ws::client ws;
ws.set_subprotocols({"chat.v2", "chat.v1"});   // or add_subprotocol("chat.v1")
ws.on_connected([&](auto &) {
    auto chosen = ws.negotiated_subprotocol();  // "chat.v2", "chat.v1", or ""
});
ws.connect(qb::io::uri("ws://localhost:9000/"));
```

Offers must be valid RFC 7230 tokens — `set_subprotocols` / `add_subprotocol` throw `std::invalid_argument` otherwise — and the negotiation check is strict: a server that returns multiple tokens, an unoffered token, or any token when the client offered none triggers `on(error)` and a disconnect. <!-- src: src/qbm/http/ws/ws.h:1431-1438, src/qbm/http/ws/ws.h:1445-1450, src/qbm/http/ws/ws.h:1598-1618 -->

The client does not offer WebSocket extensions. If a server selects one in `Sec-WebSocket-Extensions`, the client rejects the response before reporting `connected`. <!-- src: src/qbm/http/ws/ws.h:1580-1588 -->

## Secure WebSocket (WSS)

WSS reuses the same TLS transport as HTTPS — the only change is the transport template argument and the `wss://` scheme. On the client, use `WebSocketSecure<Self>` (CRTP) or `client_secure` (callback):

```cpp
qb::http::ws::client_secure ws;            // = Client<qb::io::transport::stcp>
ws.connect(qb::io::uri{"wss://localhost:9443/ws"}); // verify_peer defaults to true
```

Server-side WSS follows the HTTPS server pattern: build the session on a secure transport (`qb::io::use<Self>::tcp::ssl::client<Server>` / `...ssl::server<Session>`), initialize it with a certificate/key pair as in [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md), then run the identical HTTP/1.1 upgrade flow — `switch_protocol<ws_protocol>` is transport-agnostic. <!-- src: qbm/http/tests/system/ws/ws-client-echo.cpp:275-378, src/qbm/http/ws/ws.h:1154,1838-1839 -->

## Pitfalls

- **The subsystem is SSL-gated, not just WSS.** Plaintext `ws://` still needs `QB_HAS_SSL`; `src/qbm/http/ws/ws.h` `#error`s without OpenSSL because the handshake hash and masking CSPRNG come from `qb::crypto`. Build with `QB_WITH_SSL=ON`. <!-- src: src/qbm/http/ws/ws.h:22-25 -->
- **Do not pre-mask or pre-unmask by hand.** `WebSocket::operator<<` forces `masked = true` on every outbound frame; setting `masked` yourself has no effect on the client send path. The receive path validates masking per direction and fails the connection on a violation. <!-- src: src/qbm/http/ws/ws.h:1820-1823, src/qbm/http/ws/ws.h:724-736 -->
- **`MessageClose` throws on reserved/out-of-range codes.** `is_sendable_close_code` forbids the full reserved set — `1004` (reserved), `1005` ("no status received"), `1006` ("abnormal closure"), and `1015` ("TLS handshake failure") — none of which may appear on the wire, plus anything outside `[1000, 4999]`. Passing any of those to `MessageClose` throws `std::invalid_argument`. Receiving a 1-byte Close payload, or a reserved code on the wire, is itself a `ProtocolError`. <!-- src: src/qbm/http/ws/ws.h:257-270 (is_sendable_close_code), src/qbm/http/ws/ws.cpp:210-234, src/qbm/http/ws/ws.h:519-529 -->
- **`set_max_payload_size(0)` removes the memory guard.** The default cap (`MAX_BODY_SIZE`) is what stops a peer from exhausting memory with unbounded continuation fragments. Lift it only when you have an independent bound. <!-- src: src/qbm/http/ws/ws.h:444, src/qbm/http/ws/ws.h:603-607 -->
- **Transfer ownership cleanly.** When you move a session's transport to another actor for the upgrade, call `ctx->suppress_response()` so the routing context destructor does not send a moved-from HTTP response over the transferred socket. <!-- src: qbm/http/src/qbm/http/routing/context.h:1446-1450 -->
- **Frame events are views, not owners.** `event.data` / `event.size` point into the framer's reassembly buffer and are valid only during the `on(...)` call; copy out anything you need to keep. The owning `event.ws` (`qb::http::ws::Message`) is what you forward when echoing. <!-- src: src/qbm/http/ws/ws.h:396-400 -->

## See also

- [WebSocket coroutines](./21-websocket-coroutines.md) — `coro_client`, `coro_session`, the `co_await` awaiters, and the server-side handshake hook.
- [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md) — certificate setup for the WSS transport.
- [Asynchronous HTTP client](./14-async-http-client.md) — the HTTP/1.1 client the upgrade builds on.
- [Core concepts](./01-core-concepts.md) — sessions, protocols, and the `switch_protocol` mechanism.

Previous: [HTTP/3 protocol](./19-http3-protocol.md)
Next: [WebSocket coroutines](./21-websocket-coroutines.md)

---
Return to [Index](./README.md)

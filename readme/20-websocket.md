# 20: WebSocket (`qb::http::ws`)

`qbm-http` includes RFC 6455 WebSocket support directly under
`qb::http::ws`. It is not a separate module: applications link only
`qbm::http` and include the WebSocket umbrella header:

```cpp
#include <http/http.h>
#include <http/ws.h>
```

WebSocket starts as an HTTP/1.1 `GET` request with `Upgrade: websocket`.
After the handshake succeeds, the connection stops being parsed as HTTP and is
handled by `qb::http::ws::protocol`.

HTTP/2 extended CONNECT and WebSocket-over-HTTP/3/WebTransport are not part of
this integration. The supported path is the RFC 6455 HTTP/1.1 upgrade flow.

## Server Upgrade Flow

A server session receives the initial HTTP request with its normal HTTP
protocol, then calls `switch_protocol` to validate the request, populate the
`101 Switching Protocols` response, and install the WebSocket parser.

```cpp
class WsServer;

class WsSession : public qb::http::use<WsSession>::session<WsServer> {
public:
    using base        = qb::http::use<WsSession>::session<WsServer>;
    using Protocol    = qb::http::protocol<WsSession>;
    using ws_protocol = qb::http::ws::protocol<WsSession>;

    explicit WsSession(WsServer& server) : base(server) {}

    void on(Protocol::request&& event) {
        if (!this->template switch_protocol<ws_protocol>(*this, event.http)) {
            qb::http::Response response(qb::http::status::BAD_REQUEST,
                                        "Expected WebSocket upgrade");
            *this << response;
            this->close_after_deliver();
        }
    }

    void on(ws_protocol::message&& event) {
        *this << event.ws;
    }

    void on(ws_protocol::ping&&) {}
    void on(ws_protocol::pong&&) {}
    void on(ws_protocol::close&&) {}
};
```

The handshake validator enforces:

- HTTP method is `GET`;
- `Upgrade` and `Connection` contain the required tokens;
- `Sec-WebSocket-Version` is `13`;
- `Sec-WebSocket-Key` is canonical base64 and decodes to 16 bytes.

If an application rejects the upgrade after creating an HTTP response, it should
queue the response and call `close_after_deliver()` so the client receives the
HTTP error before the transport closes.

## Frames And Messages

`qb::http::ws::protocol` converts WebSocket frames into `on(...)` events:

- `message`: complete text or binary message;
- `ping`: incoming ping, with automatic pong behavior in the protocol layer;
- `pong`: incoming pong;
- `close`: peer close request.

Outgoing frames are built with `MessageText`, `MessageBinary`, `MessagePing`,
`MessagePong`, and `MessageClose`:

```cpp
qb::http::ws::MessageText text;
text << "hello";
*this << text;

qb::http::ws::MessageClose close(qb::http::ws::CloseStatus::Normal, "done");
*this << close;
```

The implementation is strict on both receive and send paths:

- client-to-server frames must be masked and server-to-client frames must not;
- RSV bits require an extension and are rejected by default;
- reserved or unknown opcodes are rejected;
- control frames must not be fragmented and must be at most 125 bytes;
- non-minimal payload length encodings and invalid 64-bit lengths are rejected;
- close payloads validate length, status code, and UTF-8 reason;
- text messages validate UTF-8.

## Client APIs

The callback client is useful for compact applications:

```cpp
qb::http::ws::client ws;

ws.on_connected([] {
      qb::io::cout() << "connected\n";
  })
  .on_message([](auto&& event) {
      qb::io::cout() << std::string_view(event.data, event.size) << '\n';
  })
  .connect("ws://localhost:20197/");
```

For stateful code, inherit from `qb::http::ws::WebSocket<T>`:

```cpp
class Client : public qb::http::ws::WebSocket<Client> {
public:
    void on(connected&&) {
        qb::http::ws::MessageText hello;
        hello << "hello";
        *this << hello;
    }

    void on(message&& event) {
        qb::io::cout() << std::string_view(event.data, event.size) << '\n';
    }
};
```

Both client styles support subprotocol offers:

```cpp
qb::http::ws::client ws;
ws.set_subprotocols({"chat.v2", "chat.v1"});
```

After a successful handshake, `negotiated_subprotocol()` returns the selected
token or an empty string if the server omitted `Sec-WebSocket-Protocol`.

## WSS

Secure WebSocket uses the same SSL/TLS transport foundations as HTTPS:

```cpp
qb::http::ws::client_secure secure_client;
secure_client.connect("wss://localhost:20443/ws");
```

Use `qb::http::ws::WebSocketSecure<T>` for the inheritance-based secure client.
Server-side WSS follows the same pattern as HTTPS sessions: initialize the
secure transport with a certificate/key pair, then perform the normal
HTTP/1.1 WebSocket upgrade.

See also:

- [HTTPS & SSL/TLS](./18-https-ssl-tls.md)
- [WebSocket Coroutines](./21-websocket-coroutines.md)

Previous: [HTTP/3 Protocol](./19-http3-protocol.md)
Next: [WebSocket Coroutines](./21-websocket-coroutines.md)

---
Return to [Index](./README.md)

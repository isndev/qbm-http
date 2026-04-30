# `qb::http::ws`: Handshake Process

This document details the WebSocket handshake process as handled by the `qbm-http` and `qb::http::ws` modules.

## Overview

The WebSocket protocol uses an HTTP Upgrade mechanism to transition an existing HTTP connection into a persistent WebSocket connection. This initial handshake is crucial for establishing compatibility and security.

## Client Request

The process begins with the client sending a standard HTTP GET request to the server, but with specific headers indicating the intent to upgrade:

```http
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: http://example.com
[Other headers like Sec-WebSocket-Protocol, Sec-WebSocket-Extensions may be present]
```

**Key Headers:**

*   `Host`: Standard HTTP Host header.
*   HTTP method: must be `GET`.
*   `Upgrade: websocket`: Declares the desired protocol is WebSocket.
*   `Connection: Upgrade`: Signals that this is an upgrade request.
*   `Sec-WebSocket-Key`: A **required**, randomly generated, 16-byte nonce, Base64 encoded. The server validates both decode length (16 bytes) and canonical base64 representation.
*   `Sec-WebSocket-Version: 13`: Specifies the WebSocket protocol version the client wishes to use. Version 13 is the standard defined by RFC 6455 and the only version supported by `qb::http::ws`.
*   `Origin` (Optional but common): Indicates the origin of the script initiating the connection (important for browser security).
*   `Sec-WebSocket-Protocol` (Optional): A comma-separated list of subprotocols the client is willing to use.
*   `Sec-WebSocket-Extensions` (Optional): A comma-separated list of extensions the client wants to use.

**QB Client Implementation:**
*   The `qb::http::ws::WebSocket<T>` client class template (`http/ws/ws.h`) is the primary way to create a client. It internally calls `qb::http::ws::generateKey()` to create a random key.
*   It then instantiates a `qb::http::WebSocketRequest` object, passing the generated key to its constructor. This request object automatically includes the required `Upgrade`, `Connection`, and `Sec-WebSocket-Version` headers.
*   You can add optional headers like `Sec-WebSocket-Protocol` manually to the `request.headers()` map before the connection is initiated.

## Server Response

If the server supports WebSockets and agrees to the upgrade, it responds with an HTTP `101 Switching Protocols` status:

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
[Other headers like Sec-WebSocket-Protocol, Sec-WebSocket-Extensions may be present]
```

**Key Headers:**

*   `Upgrade: websocket`: Confirms the protocol switch.
*   `Connection: Upgrade`: Confirms the upgrade.
*   `Sec-WebSocket-Accept`: **Required**. This is the crucial header. The server calculates this value by:
    1.  Concatenating the client's `Sec-WebSocket-Key` with the WebSocket magic string "`258EAFA5-E914-47DA-95CA-C5AB0DC85B11`".
    2.  Calculating the SHA-1 hash of the resulting string.
    3.  Base64 encoding the 20-byte SHA-1 hash.
*   `Sec-WebSocket-Protocol` (Optional): If the client offered subprotocols and the server chose one, this header indicates the selected subprotocol.
*   `Sec-WebSocket-Extensions` (Optional): If the client offered extensions and the server agreed to any, this header lists the activated extensions.

If the server cannot or does not want to upgrade the connection, it responds with a standard HTTP error code (e.g., 400 Bad Request, 404 Not Found, 426 Upgrade Required with details).

**QB Server Implementation:**
*   An HTTP server component (e.g., based on `qb::http::protocol_view`) receives the initial GET request.
*   The server logic validates the method (`GET`) and inspects the headers (`Upgrade`, `Connection`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version`) with strict token/OWS validation.
*   If the headers are valid, the server calculates the `Sec-WebSocket-Accept` value using `qb::crypto::sha1` and `qb::crypto::base64::encode`.
*   The server constructs an HTTP `Response` with status `101` and the required headers (`Upgrade`, `Connection`, `Sec-WebSocket-Accept`).
*   Crucially, **before** sending the `101` response, the server typically uses `switch_protocol<qb::http::ws::protocol>(...)` to change the protocol handler for that specific connection from the HTTP handler to the WebSocket handler (`qb::http::ws::protocol`).
*   After `switch_protocol`, the `101` response is sent. From this point on, the `qb::http::ws::protocol` instance handles all further communication on that socket, interpreting WebSocket frames instead of HTTP messages.

## Protocol Switch

After the client receives the `101` response and validates the `Sec-WebSocket-Accept` key, and the server has sent the `101` response after switching protocols, the handshake is complete. The connection is now a WebSocket connection, and both ends start communicating using WebSocket frames as defined in RFC 6455.

**QB Implementation:**
*   **Server:** The call to `switch_protocol` is the key step.
*   **Client:** The `qb::http::ws::WebSocket` class template (`http/ws/ws.h`) uses an internal HTTP protocol handler initially. Upon receiving a valid `101` response and verifying:
    * `Upgrade: websocket`,
    * `Connection` containing the token `Upgrade`,
    * `Sec-WebSocket-Accept` equality (OWS-trimmed, constant-time compare),
    it internally calls `switch_protocol` to start using the `qb::http::ws::protocol` for subsequent data.

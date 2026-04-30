# `qb::http::ws`: Core WebSocket Concepts

This document explains the fundamental concepts of the WebSocket protocol (RFC 6455) as implemented in the `qb::http::ws` module.

## 1. Handshake

WebSocket connections start as standard HTTP requests. The client sends an HTTP GET request with specific headers indicating a desire to upgrade the connection to WebSocket:

*   `Upgrade: websocket`
*   `Connection: Upgrade`
*   `Sec-WebSocket-Key`: A randomly generated Base64-encoded nonce.
*   `Sec-WebSocket-Version: 13` (This module only supports version 13).

The server, if it supports WebSockets and accepts the request, responds with an HTTP `101 Switching Protocols` status code and includes:

*   `Upgrade: websocket`
*   `Connection: Upgrade`
*   `Sec-WebSocket-Accept`: A hash derived from the client's `Sec-WebSocket-Key` and a predefined magic string ("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"), proving the server understood the WebSocket handshake.

Once the handshake is complete, the underlying TCP connection is reused for bidirectional WebSocket message framing, and HTTP is no longer used on that connection.

**QB Implementation:**
*   The initial HTTP request/response is handled by `qbm-http`.
*   `qb::http::WebSocketRequest` helps clients formulate the upgrade request.
*   The `qb::http::ws::protocol::WebSocket` class (or its client/server wrappers) handles the verification of the `Sec-WebSocket-Accept` header (client) or the calculation and sending of it (server).
*   Successful handshake typically involves `switch_protocol` to transition from an HTTP protocol handler to the `ws::protocol` handler.

## 2. Framing

After the handshake, communication occurs via **frames**. WebSocket is message-based, but messages can be split into multiple frames.

Each frame has a header containing:

*   **FIN bit:** 1 if this is the final frame of a message, 0 otherwise.
*   **RSV1, RSV2, RSV3 bits:** Reserved for extensions (must be 0 unless an extension is negotiated).
*   **Opcode (4 bits):** Indicates the type of frame.
*   **Mask bit:** 1 if the payload is masked, 0 otherwise.
*   **Payload length:** The length of the payload data (encoded using 7 bits, 7+16 bits, or 7+64 bits).
*   **Masking key (optional):** A 4-byte key used to mask the payload if the Mask bit is 1.
*   **Payload data:** The actual application data or control information.

**QB Implementation:**
*   The `qb::http::ws::protocol::WebSocket` class is responsible for parsing incoming byte streams into frames and assembling message payloads.
*   The `qb::http::ws::Message` class and its derivatives (`MessageText`, etc.) are used to construct frames for sending, setting the appropriate opcode and FIN bit.
*   Serialization logic in `ws.cpp` (e.g., `fill_masked_message`, `fill_unmasked_message`) handles frame construction.

## 3. Opcodes

The opcode determines the frame's purpose:

*   **`0x0` (Continuation):** Indicates this frame continues the payload of the previous frame.
*   **`0x1` (Text):** The payload is UTF-8 encoded text data.
*   **`0x2` (Binary):** The payload is arbitrary binary data.
*   **`0x3` - `0x7`:** Reserved for future non-control frames.
*   **`0x8` (Close):** Initiates or confirms connection closure. Payload may contain a status code and reason.
*   **`0x9` (Ping):** A keepalive or heartbeat mechanism. The recipient should respond with a Pong.
*   **`0xA` (Pong):** The response to a Ping frame. Must contain the same payload data as the Ping it's responding to.
*   **`0xB` - `0xF`:** Reserved for future control frames.

`qb::http::ws` rejects reserved/unknown opcodes at parse time and also
refuses to serialize outgoing frames that carry reserved opcodes or RSV bits.

**QB Implementation:**
*   The `qb::http::ws::opcode` enum defines constants for common opcodes (with FIN bit typically set).
*   The `Message` subclasses (`MessageText`, `MessageBinary`, `MessagePing`, etc.) set the appropriate opcode during construction.
*   The `protocol` class dispatches different events based on the received opcode (e.g., `on(ws::ping&&)`, `on(ws::message&&)`).

## 4. Masking

**All frames sent from the client to the server MUST be masked.** This is a security measure to prevent cache poisoning attacks on intermediaries.
Frames sent from the server to the client MUST NOT be masked.

The masking process involves XORing each byte of the payload data with a byte from the 4-byte masking key. The key byte used cycles: `payload[i] XOR key[i % 4]`.

**QB Implementation:**
*   Client-side: `WebSocket<T>::operator<<` enforces masking for all outgoing WebSocket frames automatically (`client -> server`).
*   Server-side: outgoing frames are emitted unmasked (`server -> client`).
*   Receiver-side: the parser enforces directionality (server rejects unmasked client frames; client rejects masked server frames) and only then applies XOR unmasking when required.

## 5. Close, UTF-8, and Control Limits

`qb::http::ws` enforces RFC constraints on control/close path:

*   Close codes must be in `[1000..4999]` and not in the reserved set (`1004`, `1005`, `1006`, `1015`) when sent.
*   Text payload and close reason must be valid UTF-8 (invalid payloads trigger protocol close).
*   Control-frame payload is limited to 125 bytes; outgoing oversized control frames are rejected at serialization with `std::invalid_argument`.

## 6. Message Types (`qb::http::ws::Message`)

The `qb::http::ws` module uses a class hierarchy for constructing messages:

*   **`qb::http::ws::Message`:** Base class holding the `fin_rsv_opcode`, `masked` flag, and payload data (`_data` which is a `qb::allocator::pipe<char>`).
*   **`qb::http::ws::MessageText`:** Inherits `Message`, sets opcode to `0x1` (Text).
*   **`qb::http::ws::MessageBinary`:** Inherits `Message`, sets opcode to `0x2` (Binary).
*   **`qb::http::ws::MessagePing`:** Inherits `Message`, sets opcode to `0x9` (Ping).
*   **`qb::http::ws::MessagePong`:** Inherits `Message`, sets opcode to `0xA` (Pong).
*   **`qb::http::ws::MessageClose`:** Inherits `Message`, sets opcode to `0x8` (Close), and its constructor formats the payload with a status code and reason.

These classes simplify sending correctly formatted frames.

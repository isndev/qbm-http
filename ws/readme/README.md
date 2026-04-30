# `qb::http::ws` - Detailed Documentation

Welcome to the detailed documentation for the `qb::http::ws` WebSocket module.

This section provides in-depth information on the concepts, protocol implementation, and usage of WebSockets within the QB C++ Actor Framework. Please refer to the main [qb::http::ws README](../README.md) for a general overview.

## Table of Contents

*   **[Core Concepts](./concepts.md):** Explains the fundamentals of the WebSocket protocol as implemented in this module, including the handshake process, frame types (Text, Binary, Ping, Pong, Close), opcodes, and the masking mechanism.
*   **[Handshake Process](./handshake.md):** Details the HTTP Upgrade mechanism, the roles of `Sec-WebSocket-Key`, `Sec-WebSocket-Accept`, and how `qbm-http` and `qb::http::ws` interact during connection establishment.
*   **[WebSocket Protocol](./protocol.md):** Describes the `qb::http::ws::protocol` class, its strict RFC 6455 frame validation rules, masking enforcement, fragmentation handling, and event dispatch (`ws::message`, `ws::ping`, etc.).
*   **[Usage Guide](./usage.md):** Provides practical examples and guidance on integrating WebSocket functionality into your `qb-io` applications, covering both client and server implementations, sending/receiving messages, and handling lifecycle events.
*   **[Coroutine API](./coroutines.md):** Describes the C++23 coroutine-first client (`coro_client`) and server session (`coro_session`) APIs introduced on top of `qb::io::async::task<T>`, including lifetime guarantees, buffering policy, and subprotocol negotiation.

# QB HTTP WebSocket Support

**RFC 6455 Compliant WebSocket Implementation for the QB Actor Framework**

<p align="center">
  <img src="https://img.shields.io/badge/WebSocket-RFC%206455-blue.svg" alt="WebSocket"/>
  <img src="https://img.shields.io/badge/C%2B%2B-23-blue.svg" alt="C++23"/>
  <img src="https://img.shields.io/badge/Cross--Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg" alt="Cross Platform"/>
  <img src="https://img.shields.io/badge/Arch-x86__64%20%7C%20ARM64-lightgrey.svg" alt="Architecture"/>
  <img src="https://img.shields.io/badge/SSL-WSS-green.svg" alt="SSL/WSS"/>
  <img src="https://img.shields.io/badge/License-Apache%202.0-green.svg" alt="License"/>
</p>

WebSocket support is part of the `qbm-http` module and provides production-ready
RFC 6455 real-time bidirectional communication. Built on top of QB's asynchronous
I/O foundations, it integrates directly with HTTP servers, clients, routing, and
the HTTP/1.1 upgrade lifecycle.

Whether you're building chat applications, real-time data streaming, or
collaborative tools, `qb::http::ws` provides the foundation you need with minimal
complexity.

## Quick Integration with QB

### Adding to Your QB Project

```bash
# Add the HTTP module
git submodule add https://github.com/isndev/qbm-http qbm/http

```

### CMake Configuration

```cmake
# QB Framework setup
add_subdirectory(qb)
include_directories(${QB_PATH}/include)

# Load QB modules
qb_load_modules("${CMAKE_CURRENT_SOURCE_DIR}/qbm")

# WebSocket support is built into qbm::http
target_link_libraries(your_target PRIVATE qbm::http)
```

### Include and Usage

```cpp
#include <http/http.h>   // Required for HTTP handshake
#include <http/ws/ws.h>       // WebSocket protocol implementation
```

## Why Choose `qb::http::ws`?

-   **RFC 6455 Compliant**: Complete WebSocket protocol implementation including handshake, framing, masking, and all control frames.
-   **Seamless HTTP Integration**: Effortlessly upgrades standard HTTP connections to WebSocket, leveraging the power of `qbm-http`.
-   **High Performance**: Built on `qb-io`'s non-blocking event loop to handle thousands of concurrent connections with low overhead.
-   **Flexible Client APIs**: Choose between a simple, modern callback-based client or a powerful, stateful inheritance-based one.
-   **Secure by Default**: Full, easy-to-use support for Secure WebSockets (WSS) over TLS.
-   **Hardened RFC Validation**: Strict handshake and framing checks (masking direction, reserved opcodes, close-code validity, UTF-8 validation, control-frame size constraints).

## Protocol Hardening (Current Behavior)

The module enforces a strict RFC 6455 interpretation on both receive and send paths:

- Handshake validation checks `Upgrade` / `Connection` token semantics, `Sec-WebSocket-Version == 13`, and canonical base64 `Sec-WebSocket-Key` (16-byte decoded nonce).
- Incoming frames reject reserved opcodes, non-zero RSV bits (without negotiated extension), non-minimal payload-length encodings, invalid close payloads/codes, and invalid UTF-8 in text/close reason.
- Client/server masking direction is enforced (`client -> server` masked, `server -> client` unmasked).
- Outgoing control frames (`Ping`, `Pong`, `Close`) are capped to 125-byte payload, otherwise serialization throws `std::invalid_argument`.

## Core Concept: The HTTP Upgrade

WebSockets begin their life as a standard HTTP `GET` request containing special `Upgrade` headers. The server responds with a `101 Switching Protocols` status, and from that moment, the underlying TCP connection is repurposed for the WebSocket binary framing protocol.

`qb::http::ws` manages this handshake gracefully. An HTTP server receives the upgrade request, and then "hands over" the connection's I/O transport to a WebSocket protocol handler. This allows for incredible flexibility, such as running a REST API and a WebSocket service on the same port.

## Your First WebSocket Server in 60 Seconds

This example creates a self-contained "pure" WebSocket echo server. It's a lightweight TCP server that listens on a port, handles the initial HTTP upgrade handshake itself, and then communicates using the WebSocket protocol. This is the most direct way to create a dedicated WebSocket service.

```cpp
#include <qb/main.h>
#include <http/http.h> // For handshake and response objects
#include <http/ws/ws.h>
#include <iostream>

class EchoServer; // Forward declaration

// This session class handles a single client connection.
class EchoClientSession : public qb::io::use<EchoClientSession>::tcp::client<EchoServer> {
public:
    // Define the protocol handlers we'll use.
    using http_protocol = qb::http::protocol_view<EchoClientSession>;
    using ws_protocol = qb::http::ws::protocol<EchoClientSession>;

    explicit EchoClientSession(EchoServer &server) : client(server) {}

    // 1. This is the first handler called for a new connection.
    //    It receives the raw HTTP request and attempts the handshake.
    void on(http_protocol::request &&request) {
        std::cout << "Server received an HTTP request for upgrade." << std::endl;

        // 2. switch_protocol is the core mechanism. It attempts the handshake
        //    using the provided request. If successful, it atomically replaces the
        //    HTTP parser on this connection with the WebSocket parser.
        //    It returns 'false' if the handshake fails.
        if (!this->template switch_protocol<ws_protocol>(*this, request)) {
            std::cerr << "Failed to switch to WebSocket protocol." << std::endl;
            this->disconnect();
        } else {
            std::cout << "Successfully upgraded to WebSocket protocol." << std::endl;
        }
    }

    // 3. This handler is now active and will be called for all subsequent
    //    WebSocket data frames (Text or Binary).
    void on(ws_protocol::message &&event) {
        std::cout << "Server received message: "
                  << std::string_view(event.data, event.size) << std::endl;

        // Echo the message back to the client.
        *this << event.ws;
    }

    // Handle client disconnection.
    void on(qb::io::async::event::disconnected &&) {
        std::cout << "Client disconnected." << std::endl;
    }
};

// The server class itself. It's a simple TCP server that creates
// an EchoClientSession for each new connection.
class EchoServer : public qb::Actor,
                   public qb::io::use<EchoServer>::tcp::server<EchoClientSession> {
public:
    bool onInit() override {
        // This is a lower-level TCP listen, not the http::server listen.
        if (this->transport().listen_v6(8080)) {
            this->start();
            std::cout << "Pure WebSocket echo server running at ws://localhost:8080/" << std::endl;
            return true;
        }
        std::cerr << "Failed to listen on port 8080" << std::endl;
        return false;
    }

    // (Optional) Hook called by the server base when a new session is created.
    void on(EchoClientSession &session) {
        std::cout << "New client connecting..." << std::endl;
    }
};

int main() {
    qb::Main engine;
    engine.addActor<EchoServer>(0);
    engine.start();
    engine.join(); // Keep server running
    return 0;
}
```

## Advanced Architecture: Integrating with an HTTP Server

For applications that need to serve both a standard HTTP/REST API and a WebSocket service on the same port, `qb::http::ws` integrates seamlessly with `qbm-http`. This is the recommended pattern for production.

The key is separating responsibilities:
1.  An **HttpServer Actor** handles all HTTP traffic using the `qb::http::Router`. When a request comes to `/ws`, it...
2.  **Extracts the I/O transport** from the connection and sends it in an event to a...
3.  **WebSocketServer Actor**, which is purely an `io_handler`. It takes ownership of the connection and manages the WebSocket lifecycle.

### The Event: Transferring the Connection

The link between the two servers is an actor event. The event must carry the three essential components to complete the handshake on the other side.

```cpp
// This event acts as a container to move the connection state between actors.
struct TransferToWebSocketEvent : public qb::Event {
    // A struct is used to hold the data to ensure proper lifetime management.
    struct Data {
        // 1. The underlying I/O transport (the raw socket connection).
        //    This is the most critical piece.
        HttpSession::transport_io_type transport;

        // 2. The original HTTP request, containing the necessary upgrade headers.
        qb::http::Request request;

        // 3. The response object, which will be used to send the
        //    "101 Switching Protocols" reply back down the transport.
        qb::http::Response response;
    };

    std::unique_ptr<Data> data;

    TransferToWebSocketEvent() : data(std::make_unique<Data>()) {}
};
```

### The Integrated Flow

#### 1. HTTP Server Extracts and Forwards the Connection

```cpp
// In your main HttpServer class (which inherits from qb::http::server)
class HttpServer : public qb::Actor,
                   public qb::http::use<HttpServer>::server<HttpSession> {
public:
    bool onInit() override {
        // The /ws route handler is now defined directly in the router setup.
        router().get("/ws", [this](auto ctx) {
            std::cout << "[HTTP] WebSocket upgrade requested. Transferring to handler..." << std::endl;

            // Extract the underlying TCP transport from the HTTP session.
            auto [transport, success] = this->extractSession(ctx->session()->id());

            if (success) {
                // Create an actor event and move the connection state into it.
                auto &event = push<TransferToWebSocketEvent>(_webSocketHandlerId);
                event.data->transport = std::move(transport);
                event.data->request   = std::move(ctx->request());
                event.data->response  = std::move(ctx->response());
            } else {
                ctx->response().status() = qb::http::Status::INTERNAL_SERVER_ERROR;
                ctx->response().body() = "Failed to upgrade to WebSocket";
                ctx->complete();
            }
        });

        router().compile();
        // ... listen and start ...
        return true;
    }
private:
    qb::ActorId _webSocketHandlerId;
};
```

#### 2. WebSocket Handler Actor Receives and Finalizes the Handshake

```cpp
// In your WebSocketServer class (which inherits from qb::io::io_handler)
class WebSocketServer : public qb::Actor,
                        public qb::io::use<WebSocketServer>::tcp::io_handler<ChatSession> {
public:
    void on(TransferToWebSocketEvent& event) {
        // 1. Receive the transport from the event and create a new WebSocket session.
        auto& chat_session = registerSession(std::move(event.data->transport));

        // 2. The key step: switch the protocol from HTTP to WebSocket.
        //    This call attempts the handshake using the original request's headers.
        //    If the handshake is valid, it returns true and populates the response
        //    object with the correct "101 Switching Protocols" headers.
        if (chat_session.template switch_protocol<ChatSession::ws_protocol>(chat_session, event.data->request, event.data->response)) {
            // 3. Handshake succeeded. Send the populated response to the client
            //    to finalize the protocol switch.
            std::cout << "[WS] Handshake successful. Sending 101 response." << std::endl;
            chat_session << event.data->response;
        } else {
            // 4. Handshake failed. The request was not a valid WebSocket upgrade.
            //    The connection should be terminated.
            std::cerr << "[WS] Handshake failed. Disconnecting." << std::endl;
            chat_session.disconnect();
        }
    }
};
```
This pattern provides excellent separation of concerns, making your application more modular and scalable.

## WebSocket Clients

`qb::http::ws` provides two convenient ways to create clients.

### 1. The Simple Way: Callback-Based Client

The `qb::http::ws::client` provides a clean, modern API using method chaining and lambdas. This is perfect for most use cases and can be used in a standalone `qb-io` application without the full `qb::Main` engine.

```cpp
#include <http/ws/ws.h>
#include <qb/io/async.h> // For pure async mode
#include <iostream>

int main() {
    // Initialize the thread-local async listener.
    qb::io::async::init();

    // Use client_secure for wss://
    qb::http::ws::client ws_client;

    // Configure callbacks using method chaining
    ws_client.on_connected([&](auto &event) {
        std::cout << "✓ Connected to WebSocket!" << std::endl;
        qb::http::ws::MessageText msg;
        msg << "Hello from callback client!";
        ws_client << msg;
    })
    .on_message([](auto &event) {
        std::cout << "Received: " << std::string_view(event.data, event.size) << std::endl;
        // For this example, close after one message.
        ws_client.disconnect();
    })
    .on_disconnected([](auto &event) {
        std::cout << "✗ Disconnected." << std::endl;
        // Stop the event loop.
        qb::io::async::break_parent();
    });

    // Connect to the server
    ws_client.connect({"ws://localhost:8080/"});

    // Run the event loop. This is a blocking call.
    qb::io::async::run();

    std::cout << "Event loop finished." << std::endl;
    return 0;
}
```

### 2. The Advanced Way: Inheritance-Based Client

For more complex clients that need to maintain state, you can inherit from `qb::http::ws::WebSocket`.

```cpp
#include <http/ws/ws.h>
#include <qb/main.h>
#include <iostream>

// Your class must inherit from WebSocket<YourClass>
class MyClient : public qb::Actor, public qb::http::ws::WebSocket<MyClient> {
public:
    bool onInit() override {
        // Connect to the server
        this->connect({"ws://localhost:8080/ws"});
        return true;
    }

    // Callback for when the WebSocket is fully connected after handshake.
    void on(connected &&event) {
        std::cout << "✓ WebSocket connection established." << std::endl;

        qb::http::ws::MessageText msg;
        msg << "Hello from inheritance client!";
        *this << msg;
    }

    void on(message &&event) {
        std::string_view received(event.data, event.size);
        std::cout << "Received: " << received << std::endl;
        this->kill(); // Exit after one message
    }

    void on(disconnected &&event) {
        std::cout << "✗ TCP connection lost." << std::endl;
        this->kill();
    }
};

int main() {
    qb::Main engine;
    engine.addActor<MyClient>(0);
    engine.start();
    engine.join();
    return 0;
}
```

## Coroutine-First API (C++23)

For conversational protocols — REST-over-WebSocket, RPC, request/reply flows
— callback-driven code quickly becomes painful. `qb::http::ws` ships a
coroutine-first surface (`http/ws/coro.h`) that lets you express both
clients and servers as a single linear `qb::io::async::task<void>`, with
no extra threads and no scheduler plumbing.

It follows the same idioms already used in `qbm/redis`, `qbm/pgsql` and
the coroutine surface of `qbm/http`. Strictly mono-thread per listener —
resumption always runs on the I/O thread that owns the socket.

### Coroutine Client

```cpp
#include <http/ws/coro.h>
#include <qb/io/async.h>

qb::io::async::task<std::string>
talk_to_echo() {
    qb::http::ws::coro_client ws;

    auto c = co_await ws.connect("ws://localhost:9001/",
                                 std::chrono::seconds{5});
    if (!c.ok) co_return "connect failed";

    qb::http::ws::MessageText msg;
    msg << "ping";
    ws << msg;

    auto frame = co_await ws.receive();
    // frame.kind == IncomingFrame::Kind::Message
    // frame.payload == "ping" (echo)

    co_await ws.close_async(qb::http::ws::CloseStatus::Normal, "done");
    co_return frame.payload;
}

int main() {
    qb::io::async::init();
    auto reply = qb::http::ws::run_sync(talk_to_echo());
    std::cout << reply << "\n";
}
```

Highlights:
- `co_await ws.connect(...)` performs both the TCP connect and the HTTP
  upgrade; the result carries a single `ok` boolean.
- `co_await ws.receive()` suspends until the next frame (message, ping,
  pong, close, or transport disconnect). If the peer drops the TCP
  stream while you're parked, the awaiter resolves with
  `IncomingFrame::Kind::Disconnected` instead of hanging.
- `co_await ws.close_async(status, reason)` queues a Close frame and
  resumes once the peer has echoed it (or the transport dropped first).
- `ws.set_subprotocols({"chat.v2", "chat.v1"})` before `connect()` offers
  RFC 6455 subprotocols; after a successful handshake,
  `ws.negotiated_subprotocol()` returns the token the server picked (or
  an empty view when none was negotiated).
- `qb::http::ws::coro_client_secure` is the `wss://` flavour (TLS by
  default).

### Coroutine Server Session

Server sessions can be written as a single coroutine method `run()`.
The base class takes care of the HTTP upgrade, dispatches inbound frames
into a queue, and spawns `run()` on successful upgrade — holding the
session alive for the entire life of the coroutine.

```cpp
#include <http/ws/coro.h>

class ChatServer;

class ChatSession
    : public qb::http::ws::coro_session<ChatSession, ChatServer> {
public:
    using base = qb::http::ws::coro_session<ChatSession, ChatServer>;
    using base::base;

    // Optional: negotiate a subprotocol before the upgrade is accepted.
    ChatSession(ChatServer& s) : base(s) {
        set_handshake_hook([](ChatSession&, qb::http::Request& req,
                              qb::http::Response& res) {
            // res.headers()["Sec-WebSocket-Protocol"].emplace_back("chat.v1");
            return true; // accept
        });
    }

    qb::io::async::task<void> run() {
        while (true) {
            auto frame = co_await this->next_frame();
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected ||
                frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
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

class ChatServer : public qb::io::use<ChatServer>::tcp::server<ChatSession> {
public:
    void on(IOSession&) {}
};
```

Key guarantees:
- The session is kept alive for the whole life of the coroutine: every
  suspension point is guaranteed to resume on a valid `*this`.
- Return normally from `run()` (typically on a `Disconnected` or `Close`
  frame) to release the session.
- Thrown exceptions are caught by the base class, translated to a
  `1011 UnexpectedReason` Close frame, and the TCP stream is torn down.
- Pings received from the peer are automatically acknowledged with a
  Pong (RFC 6455 §5.5.3) — you still receive the `Ping` frame through
  `next_frame()` if you want to observe it.

### When to Use Which API

| Need                                                    | Use                                    |
|---------------------------------------------------------|----------------------------------------|
| Dispatching many unrelated events in parallel            | Classical CRTP (`WebSocket`, `Client`) |
| Linear request/reply style, stateful conversations       | `coro_client` / `coro_session`         |
| One-shot handshake + single round-trip from `main()`     | `coro_client` + `qb::http::ws::run_sync` |
| Existing callback-driven codebase                        | Classical CRTP (no migration cost)     |

The two styles share the same underlying protocol implementation, so
you can mix them within a single application — e.g. a coroutine-based
admin client and a callback-based broadcaster on the same server.

## Secure WebSockets (WSS)

Enabling secure communication is straightforward.

### Server-Side

Simply listen on a `wss://` URI and provide your certificate and key files. `qbm-http` handles the rest. This requires a `server` that uses a secure transport, typically by inheriting from `qb::http::use<...>::ssl::server`.

```cpp
// In your server's onInit()
// This requires an SSL-enabled server transport.
listen({"wss://0.0.0.0:8443"}, "path/to/cert.pem", "path/to/key.pem");
```

### Client-Side

Use the `qb::http::ws::client_secure` alias or the `qb::http::ws::WebSocketSecure` template and connect to a `wss://` URI.

```cpp
// Callback-based secure client
qb::http::ws::client_secure secure_client;
secure_client.connect({"wss://example.com/secure"});

// Inheritance-based secure client
class MySecureClient : public qb::Actor, public qb::http::ws::WebSocketSecure<MySecureClient> {
    // ... same implementation ...
};
```

## Key Features

-   **Protocol Support**: Complete RFC 6455 implementation with text/binary messages, fragmentation, and all control frames (ping, pong, close).
-   **Seamless Integration**: Designed to extend `qbm-http`, allowing WebSocket and HTTP/API endpoints to coexist on the same port.
-   **Flexible Architecture**: Supports both simple, self-contained servers and advanced, decoupled architectures for maximum maintainability.
-   **Dual Client APIs**: Provides a simple callback-based client for rapid development and a powerful inheritance-based client for complex, stateful applications.
-   **Performance**: Leverages QB's non-blocking, actor-based core to handle a massive number of concurrent connections efficiently.
-   **Security**: Out-of-the-box support for secure WebSocket (WSS) connections via TLS.

## Build Information

### Prerequisites

-   **QB Framework**: This module requires the core QB Actor Framework.
-   **`qbm-http`**: The WebSocket module is an extension of the HTTP module and depends on it.
-   **C++23** compatible compiler (GCC 13+, Clang 17+, MSVC 19.38+).
-   **CMake 3.14+**.

### Optional Dependencies

-   **OpenSSL**: **Required** for all WebSocket functionality, as it is used for the SHA1 hashing in the handshake. Must be enabled in the core `qb-io` build with `QB_IO_WITH_SSL=ON`.

## Documentation & Examples

For complete examples and detailed usage patterns, please see the `examples/` directory within this module.

-   **`examples/qbm/http/ws/01_chat_server.cpp`**: A complete, production-ready chat application demonstrating the advanced separated-server architecture.
-   **`examples/qbm/http/ws/02_chat_client.cpp`**: A command-line client for the chat server.

## Detailed Documentation

For comprehensive technical documentation, implementation details, and in-depth guides on the concepts and protocol implementation:

**📖 [View the Detailed `qb::http::ws` Documentation](./readme/README.md)**

---

**Part of the [QB Actor Framework](https://github.com/isndev/qb) ecosystem - Build the future of concurrent C++ applications.**

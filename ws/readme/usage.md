# `qb::http::ws`: Usage Guide

This guide provides practical examples on how to use the `qb::http::ws` module to build WebSocket clients and servers within the QB Actor Framework.

## Important Behavioral Notes (Current Module State)

- Client API (`qb::http::ws::WebSocket<T>` and `qb::http::ws::client`) masks outgoing frames automatically; avoid forcing masking manually unless you are building raw frames.
- Server-side outgoing frames are unmasked by default.
- Parser side is strict RFC 6455: invalid opcodes, RSV misuse, invalid close payload/code, invalid UTF-8, and malformed length encodings are rejected.
- Serialization is also strict: outgoing frames with RSV bits, reserved opcodes, fragmented control frames, or oversized control payloads throw `std::invalid_argument`.
- Server handshakes require an HTTP `GET` upgrade request with valid `Upgrade`, `Connection`, `Sec-WebSocket-Key`, and `Sec-WebSocket-Version: 13`.

## 1. Building a WebSocket Server

WebSocket servers typically start as HTTP servers that handle the upgrade request.

**Steps:**

1.  **Define a Server Class:** Inherit from `qb::io::use<YourServer>::tcp::server<YourClientHandler>` (or `ssl::server` for WSS).
2.  **Define a Client Handler Class:** Inherit from `qb::io::use<YourClientHandler>::tcp::client<YourServer>` (or `ssl::client`). This class will manage individual client connections.
3.  **Handle HTTP Request in Client Handler:** Implement `on(qb::http::protocol_view::request&& event)`.
    *   Check if it's a valid WebSocket upgrade request (check headers like `Upgrade`, `Connection`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version`).
    *   If valid, call `this->switch_protocol<qb::http::ws::protocol>(*this, event.http)`. This calculates and sends the `101 Switching Protocols` response with the correct `Sec-WebSocket-Accept` header and replaces the HTTP protocol handler with the WebSocket one for this connection.
    *   If invalid, send an appropriate HTTP error (e.g., 400 Bad Request) and disconnect.
4.  **Handle WebSocket Events in Client Handler:** Implement handlers for WebSocket events dispatched by `qb::http::ws::protocol`:
    *   `on(qb::http::ws::protocol::message&& event)`: Process incoming Text or Binary messages. Check `event.ws.fin_rsv_opcode` to distinguish.
    *   `on(qb::http::ws::protocol::ping&& event)`: Ping received (Pong is sent automatically).
    *   `on(qb::http::ws::protocol::pong&& event)`: Pong received.
    *   `on(qb::http::ws::protocol::close&& event)`: Client initiated closure.
5.  **Handle Disconnection:** Implement `on(qb::io::async::event::disconnected&& event)` for cleanup.
6.  **Start the Server:** Create an instance of your server class, call `transport().listen(...)`, and `start()`.
7.  **Run the Event Loop:** Use `qb::io::async::run()`.

**Example (`DetailedServer` / `DetailedHandler` from `README.md`):**

```cpp
#include <qb/io/async.h>
#include <http/ws/ws.h>
#include <iostream>
#include <string>
#include <atomic>

// Forward declaration
class DetailedHandler;

// Server
class DetailedServer : public qb::io::use<DetailedServer>::tcp::server<DetailedHandler> {
    std::atomic<std::size_t> _connection_count{0};
    std::atomic<std::size_t> _message_count{0};
public:
    bool start(int port) {
        auto status = this->transport().listen_v6(port);
        if (status != qb::io::SocketStatus::Done) {
            std::cerr << "Server listen failed on port " << port << std::endl;
            return false;
        }
        this->server::start();
        std::cout << "Server listening on port " << port << std::endl;
        return true;
    }
    void on(qb::io::IOSession&) { ++_connection_count; }
    void on(qb::io::async::event::disconnected&) { --_connection_count; }
    void increment_message_count() { ++_message_count; }
    std::size_t connection_count() const { return _connection_count; }
    std::size_t message_count() const { return _message_count; }
};

// Client Handler (handles one connection on the server)
class DetailedHandler : public qb::io::use<DetailedHandler>::tcp::client<DetailedServer> {
    std::string _client_id;
public:
    using http_protocol = qb::http::protocol_view<DetailedHandler>;
    using ws_protocol = qb::http::ws::protocol<DetailedHandler>;

    explicit DetailedHandler(qb::io::IOServer& server) :
        qb::io::use<DetailedHandler>::tcp::client<DetailedServer>(server) {
        static std::atomic<int> id_counter{0};
        _client_id = "client_" + std::to_string(++id_counter);
        std::cout << _client_id << " connecting..." << std::endl;
    }

    ~DetailedHandler() {
        std::cout << _client_id << " handler destroyed." << std::endl;
    }

    // 1. Handle initial HTTP Request
    void on(http_protocol::request&& event) {
        std::cout << _client_id << " received HTTP request for: " << event.http.uri().path() << std::endl;

        std::cout << _client_id << " attempting WebSocket upgrade..." << std::endl;
        // switch_protocol validates the RFC 6455 GET upgrade, computes
        // Sec-WebSocket-Accept, queues the 101 response, and installs WS.
        if (this->switch_protocol<ws_protocol>(*this, event.http)) {
            std::cout << _client_id << " WebSocket upgrade successful." << std::endl;
            // Optionally send a welcome message
            qb::http::ws::MessageText welcome;
            welcome.masked = false; // Server->Client MUST NOT be masked
            welcome << "Welcome " << _client_id;
            *this << welcome;
        } else {
            std::cerr << _client_id << " WebSocket upgrade failed!" << std::endl;
            qb::http::Response res(qb::http::status::BAD_REQUEST, "Expected WebSocket Upgrade");
            *this << res;
            close_after_deliver();
        }
    }

    // 2. Handle WebSocket Messages
    void on(ws_protocol::message&& event) {
        server().increment_message_count();
        bool is_text = (event.ws.fin_rsv_opcode & 0x0F) == 0x01;
        if (is_text) {
            std::string text(event.data, event.size);
            std::cout << _client_id << " sent text: " << text << std::endl;
            // Echo back
            event.ws.masked = false;
            *this << event.ws;
        } else {
            std::cout << _client_id << " sent binary data: " << event.size << " bytes" << std::endl;
            // Echo back
            event.ws.masked = false;
            *this << event.ws;
        }
    }

    // 3. Handle Control Frames (Optional)
    void on(ws_protocol::ping&& event) {
        std::cout << _client_id << " sent ping (" << event.size << " bytes)" << std::endl;
        // Pong is sent automatically by the protocol
    }
    void on(ws_protocol::pong&& event) {
        std::cout << _client_id << " sent pong (" << event.size << " bytes)" << std::endl;
    }
    void on(ws_protocol::close&& event) {
        std::cout << _client_id << " sent close frame." << std::endl;
        // The protocol handler usually initiates disconnection after receiving close
    }

    // 4. Handle Disconnection
    void on(qb::io::async::event::disconnected&&) {
        std::cout << _client_id << " disconnected." << std::endl;
    }
};

// Main function to run the server
// int main() {
//     qb::io::async::init();
//     DetailedServer server;
//     if (!server.start(20197)) return 1;
//     qb::io::async::run(); // Run event loop
//     return 0;
// }
```

## 2. Building a WebSocket Client

The `qb::http::ws` module provides the `qb::http::ws::WebSocket<T>` class template (`WebSocketSecure<T>` for WSS) to simplify client creation.

**Steps:**

1.  **Define a Client Class:** This class will contain the `WebSocket<YourClient>` instance and handle its events.
2.  **Instantiate `WebSocket<YourClient>`:** Create a member variable `qb::http::ws::WebSocket<YourClient> ws{*this};`.
3.  **Connect:** Call `ws.connect(uri)` with the `ws://` or `wss://` URI.
4.  **Handle Events:** Implement `on(...)` methods in your client class for the events dispatched by `WebSocket<T>`:
    *   `on(qb::http::ws::WebSocket<T>::connected&&)`: Handshake successful, connection ready.
    *   `on(qb::http::ws::WebSocket<T>::message&& event)`: Message received.
    *   `on(qb::http::ws::WebSocket<T>::ping&& event)`: Ping received.
    *   `on(qb::http::ws::WebSocket<T>::pong&& event)`: Pong received.
    *   `on(qb::http::ws::WebSocket<T>::closed&& event)`: Server initiated closure.
    *   `on(qb::http::ws::WebSocket<T>::error&&)`: Handshake or protocol error.
    *   `on(qb::io::async::event::disconnected&&)`: Underlying TCP connection lost.
    *   `on(qb::http::ws::WebSocket<T>::sending_http_request&& event)` (Optional): Modify the handshake request before sending.
5.  **Send Messages:** Once connected, use the stream operator `ws << message_object;` where `message_object` is an instance of `MessageText`, `MessageBinary`, `MessagePing`, or `MessageClose`.
6.  **Run the Event Loop:** Use `qb::io::async::run()`.

**Example (`DetailedClient` from `README.md`):**

```cpp
#include <qb/io/async.h>
#include <http/ws/ws.h>
#include <iostream>
#include <string>
#include <vector>
#include <atomic>

class DetailedClient {
    std::atomic<bool> _connected{false};
public:
    qb::http::ws::WebSocket<DetailedClient> ws{*this}; // 1. Instantiate

    DetailedClient() { ws.set_ping_interval(10000); /* 10s ping */ }

    // 2. Connect
    void connect(const std::string& url) {
        std::cout << "Connecting to " << url << std::endl;
        ws.connect(qb::io::uri(url));
    }

    // 4. Send Messages
    void send(const std::string& text) {
        if (!_connected) return;
        std::cout << "Sending: " << text << std::endl;
        qb::http::ws::MessageText msg;
        msg << text;
        ws << msg;
    }

    void close() {
        if (!_connected) return;
        std::cout << "Sending Close frame" << std::endl;
        qb::http::ws::MessageClose msg(qb::http::ws::CloseStatus::Normal);
        ws << msg;
    }

    bool is_connected() const { return _connected; }

    // 3. Handle Events
    void on(qb::http::ws::WebSocket<DetailedClient>::connected&&) {
        _connected = true;
        std::cout << "WebSocket Connected!" << std::endl;
        send("Hello from QB Client!");
    }

    void on(qb::http::ws::WebSocket<DetailedClient>::message&& event) {
        bool is_text = (event.ws.fin_rsv_opcode & 0x0F) == 0x01;
        if (is_text) {
            std::string text(event.data, event.size);
            std::cout << "Received Text: " << text << std::endl;
        } else {
            std::cout << "Received Binary: " << event.size << " bytes" << std::endl;
        }
    }

    void on(qb::http::ws::WebSocket<DetailedClient>::ping&& event) {
        std::cout << "Ping received (" << event.size << " bytes payload)" << std::endl;
    }

    void on(qb::http::ws::WebSocket<DetailedClient>::pong&& event) {
        std::cout << "Pong received (" << event.size << " bytes payload)" << std::endl;
    }

    void on(qb::http::ws::WebSocket<DetailedClient>::closed&& event) {
        _connected = false;
        std::cout << "WebSocket Closed by server." << std::endl;
    }

    void on(qb::http::ws::WebSocket<DetailedClient>::error&&) {
        _connected = false;
        std::cerr << "WebSocket Error!" << std::endl;
    }

    void on(qb::io::async::event::disconnected&&) {
        _connected = false;
        std::cout << "TCP Disconnected." << std::endl;
    }
};

// Main function to run the client
// int main() {
//     qb::io::async::init();
//     DetailedClient client;
//     client.connect("ws://localhost:20197");
//     qb::io::async::run(); // Run event loop
//     return 0;
// }
```

## 3. Secure WebSockets (WSS)

*   **Server:** Use `qb::io::use<...>::tcp::ssl::server` and `ssl::client` for your base classes. You will need to initialize the server transport with SSL context using `server.transport().init(...)`, providing paths to your certificate and key files.
*   **Client:** Use `qb::http::ws::WebSocketSecure<T>` instead of `WebSocket<T>`. It inherits from `qb::io::async::tcp::ssl::client` and handles the TLS handshake automatically. Connect using a `wss://` URI.

Remember to generate or obtain valid SSL/TLS certificates for WSS.

# `qbm-http`: HTTP Server

(`qbm/http/http.h`, `qb/io/async/tcp/server.h`, `qb/io/tcp/ssl/server.h`)

The `qbm-http` module provides a high-performance, asynchronous HTTP/1.1 server integrated with the QB Actor Framework.

## Server Architecture

The server typically involves two main components working together:

1.  **The Server Actor/Class:** This is the main entry point. It's responsible for:
    *   Listening for incoming connections (TCP or SSL/TLS).
    *   Accepting new connections.
    *   Creating and managing client sessions.
    *   Holding the `qb::http::Router` instance to route requests.
2.  **The Session Actor/Class:** This class handles the communication for a *single* connected client.
    *   It manages the underlying socket (`qb::io::tcp::socket` or `ssl::socket`).
    *   It uses the HTTP protocol parser (`qb::protocol::http_server` or `http_server_view`) to parse incoming data into `qb::http::Request` objects.
    *   It forwards the parsed requests to the Server's router.
    *   It receives `qb::http::Response` objects (usually populated by route handlers) and sends them back to the client.

## Using `qb::http::use<>` Helpers

The easiest way to build an HTTP server is by using the `qb::http::use<>` helper templates:

*   **`qb::http::use<MyServer>::server<MySession>`:** Inherit from this in your main server class/actor. It combines:
    *   An acceptor (`qb::io::async::tcp::acceptor` or `ssl::acceptor`).
    *   A session manager (`qb::io::async::io_handler`).
    *   Provides `transport()` (the listener) and `router()` access.
*   **`qb::http::use<MySession>::session<MyServer>`:** Inherit from this in your session handling class/actor. It combines:
    *   An underlying client connection (`qb::io::async::tcp::client` or `ssl::client`).
    *   The HTTP protocol parser (`qb::protocol::http_server`).
    *   Provides `transport()` (the client socket), `server()` (access to the parent server), `request()`, `response()`, and the `on(protocol::request&&)` handler.

## Basic Server Example (within an Actor)

```cpp
#include <qb/http.h>
#include <qb/main.h>
#include <qb/actor.h>
#include <iostream>

// Forward declare the server to use in the session
class MyServerActor;

// Define the Session class
// It needs access to the ServerActor to use its router
class MyHttpSession : public qb::http::use<MyHttpSession>::session<MyServerActor> {
public:
    // Constructor takes a reference to the ServerActor
    explicit MyHttpSession(MyServerActor& server) : session(server) {}

    // This is called by the internal protocol when a full request is parsed
    void on(qb::http::protocol<MyHttpSession>::request&& req) override {
        // Forward the request to the server's router
        // The router will find the matching handler and populate this session's response
        // We need to pass the session shared_ptr to route_context
        if (!this->server().router().route_context(this->shared_from_this(), req.http)) {
            // If no route matched, send a default 404
            response().status_code = HTTP_STATUS_NOT_FOUND;
            response().body() = "Not Found";
            *this << response(); // Send the 404 response
        }
        // If route() returned true, the handler (sync or async) is responsible for sending the response.
    }

    // Optional: Handle disconnection
    void on(qb::http::event::disconnected&& event) override {
         std::cout << "Client disconnected (session: " << this->id() << ")\n";
         // Server's io_handler base automatically cleans up the session map
    }
};

// Define the Server Actor
class MyServerActor : public qb::Actor, public qb::http::use<MyServerActor>::server<MyHttpSession> {
public:
    bool onInit() override {
        // --- Configure Router ---
        router()
            .get("/", [](Context& ctx) {
                ctx.response.add_header("Content-Type", "text/plain");
                ctx.response.body() = "Hello from QB HTTP Server!";
                // Send response via the session associated with this context
                ctx.complete();
            })
            .get("/info", [](Context& ctx) {
                qb::json info = {{"server", "QB-HTTP"}, {"version", "1.0"}};
                ctx.response.add_header("Content-Type", "application/json");
                ctx.response.body() = info;
                ctx.complete();
            });
        // -------------------------

        // --- Start Listening ---
        // Use qb::io::uri for clarity
        qb::io::uri listen_uri("tcp://0.0.0.0:8080");
        if (transport().listen(listen_uri)) { // Error code is non-zero on failure
            std::cerr << "Failed to listen on " << listen_uri.source() << std::endl;
            return false; // Abort actor initialization
        }
        std::cout << "Server listening on " << listen_uri.source() << std::endl;
        start(); // Start accepting connections (part of acceptor base)
        // -----------------------

        registerEvent<qb::KillEvent>(*this);
        return true;
    }

    // Called by the io_handler base when a new session is accepted and created
    void on(std::shared_ptr<MyHttpSession> new_session) override {
        std::cout << "New connection accepted. Session ID: " << new_session->id() << std::endl;
        // Optional: Perform actions when a new session connects
    }

    void on(const qb::KillEvent&) {
        std::cout << "Shutting down server..." << std::endl;
        transport().close(); // Stop accepting new connections
        // Existing sessions will be disconnected as their actors terminate
        kill();
    }
};

// --- Main Function ---
int main() {
    qb::Main engine;
    engine.addActor<MyServerActor>(0); // Add server to core 0
    engine.start(false); // Run the engine synchronously
    return 0;
}
```

## Key Steps

1.  **Define Session Class:** Create a class inheriting from `qb::http::use<YourSession>::session<YourServer>`. Implement `on(protocol::request&& req)` to forward requests to the server's router (`this->server().router().route_context(...)`). Handle `on(event::disconnected&&)` if needed.
2.  **Define Server Class/Actor:** Inherit from `qb::Actor` (if using actors) and `qb::http::use<YourServer>::server<YourSession>`. Access the router via `router()` and the listener via `transport()`.
3.  **Configure Router:** In the server's `onInit` (or constructor), define routes using `router().get(...)`, `router().post(...)`, etc. Add any global middleware using `router().use(...)`.
4.  **Listen:** Call `transport().listen(...)` with a `qb::io::uri` or host/port.
5.  **Start Accepting:** Call `start()` (from the `acceptor` base) to begin accepting connections.
6.  **Handle Requests:** Implement route handlers (lambdas, functions) that take `Context& ctx`. Modify `ctx.response` and call `ctx.complete()` (or use async handling).
7.  **Run Engine:** Create a `qb::Main` instance, add the server actor, and call `main.start()`.

**(See also:** [`routing.md`](./routing.md), [`middleware.md`](./middleware.md), [`async_handling.md`](./async_handling.md), `test-session-http.cpp`**)** 
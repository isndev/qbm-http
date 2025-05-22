# QB HTTP Module Documentation

Welcome to the documentation for the `qb::http` module, a high-performance C++17 library for building asynchronous HTTP clients and servers, integrated with the QB Actor Framework.

This module provides a comprehensive suite for HTTP/1.1 communication, featuring a powerful routing system, middleware support, and robust request/response handling. It is designed for efficiency, type safety, and ease of use for developers familiar with modern C++ and asynchronous programming paradigms.

## 📚 Documentation Index

This documentation is broken down into several sections to help you understand and effectively use the `qb::http` module:

1.  **Core Concepts:** 
    *   [Request, Response, and Message Handling](./01-core-concepts.md)
    *   [HTTP Message Body Deep Dive](./02-body-deep-dive.md)
2.  **Routing System:**
    *   [Routing Overview](./03-routing-overview.md) (Path matching, parameters)
    *   [Defining Routes](./04-defining-routes.md) (GET, POST, lambdas, `ICustomRoute`)
    *   [Route Groups](./05-route-groups.md) (Organizing routes, shared prefixes)
    *   [Controllers](./06-controllers.md) (Class-based route organization)
3.  **Middleware:**
    *   [Middleware Overview](./07-middleware.md) (Concept, chaining, execution flow)
    *   [Standard Middleware](./08-standard-middleware.md) (Usage of provided middleware)
    *   [Custom Middleware](./09-custom-middleware.md) (Creating your own middleware)
4.  **Request Lifecycle & Context:**
    *   [The Request Context](./10-request-context.md) (`Context` object, lifecycle hooks)
5.  **Authentication & Authorization:**
    *   [Authentication System](./11-authentication.md) (`AuthManager`, `AuthOptions`, `User`, `AuthMiddleware`, `JwtMiddleware`)
6.  **Data Validation & Sanitization:**
    *   [Validation System](./12-validation.md) (`RequestValidator`, `SchemaValidator`, rules, sanitizers)
7.  **Error Handling:**
    *   [Error Handling Strategies](./13-error-handling.md) (Router error chain, `ErrorHandlingMiddleware`)
8.  **Client & Low-Level Details:**
    *   [Asynchronous HTTP Client](./14-async-http-client.md) (Using `qb::http::async`)
    *   [HTTP Message Parsing](./15-http-parsing.md) (Overview of internal parser)
9.  **Advanced Topics:**
    *   [Advanced Usage & Performance](./16-advanced-topics.md) (Best practices, `string_view`, body handling)

## 🚀 Minimal Usage Example

Here's a brief example of how to define a simple server with a single route using the `qb::http` module:

```cpp
#include <http/http.h> // Main include for the HTTP module
#include <qb/io/async.h>  // For the async listener
#include <iostream>

// Forward declaration for the server class
class MyHttpServer;

// Define a session type for our server
class MySession : public qb::http::use<MySession>::session<MyHttpServer> {
public:
    MySession(MyHttpServer &server_ref)
        : qb::http::use<MySession>::session<MyHttpServer>(server_ref) {}

    // Optional: Add custom session logic if needed
};

// Define the server class
class MyHttpServer : public qb::http::use<MyHttpServer>::server<MySession> {
public:
    MyHttpServer() {
        // Define a simple GET route
        router().get("/hello", [](std::shared_ptr<qb::http::Context<MySession>> ctx) {
            std::cout << "Request received for /hello" << std::endl;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Hello from qb::http!";
            ctx->response().set_header("Content-Type", "text/plain");
            ctx->complete(); // Signal that request processing is done
        });

        // Compile routes after defining them
        router().compile();
    }

    // Optional: Override on(IOSession &) to track connections
    void on(qb::http::use<MyHttpServer>::server<MySession>::IOSession &s) {
        std::cout << "New client connected to MyHttpServer. Session ID: "
                  // << s.id() // Assuming session has an id() method or similar
                  << std::endl;
    }
};

int main() {
    // Initialize the asynchronous I/O system for the main thread
    qb::io::async::init();

    MyHttpServer http_server;

    // Listen on port 8080
    if (!http_server.transport().listen_v4(8080)) {
        std::cerr << "Failed to listen on port 8080" << std::endl;
        return 1;
    }
    std::cout << "Server listening on port 8080..." << std::endl;

    http_server.start(); // Start accepting connections

    // Run the event loop
    qb::io::async::run(); // Blocks until qb::io::async::break_loop() is called elsewhere

    return 0;
}

```
This example demonstrates setting up a basic HTTP server that listens on port 8080 and responds to GET requests on the `/hello` path.

---

We encourage you to explore the detailed sections linked above to gain a comprehensive understanding of the `qb::http` module's capabilities. 
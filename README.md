# QB HTTP Module (`qbm-http`)

This module provides a comprehensive, high-performance, and flexible HTTP/1.1 client and server implementation, deeply integrated with the asynchronous capabilities of the QB C++ Actor Framework (`qb-io` and `qb-core`). It's designed for building robust, scalable web applications and services in C++17.

## Core Philosophy

*   **Asynchronous & Non-Blocking:** Built entirely on the non-blocking I/O foundation of `qb-io` to maximize performance and concurrency.
*   **Flexibility & Extensibility:** Offers a powerful middleware system and clear interfaces for customization.
*   **Performance:** Utilizes efficient parsing (llhttp), optimized routing (Radix Tree option), and modern C++ techniques.
*   **Ease of Use:** Provides both high-level APIs for common tasks (client requests, simple routing) and detailed control for complex scenarios.

## Key Features

*   **HTTP/1.1 Compliance:** Full support for the HTTP/1.1 protocol.
*   **Client & Server:** Includes implementations for both asynchronous HTTP clients and servers.
*   **Robust Routing (`qb::http::Router`):**
    *   Method-based routing (GET, POST, PUT, DELETE, etc.).
    *   Path parameter extraction (e.g., `/users/:id`).
    *   Route grouping (`router.group("/api")`).
    *   Hierarchical controllers (`qb::http::Controller`).
    *   Optional high-performance Radix Tree matching.
    *   Route priorities.
*   **Powerful Middleware System (`qb::http::IMiddleware`):**
    *   Intercept and modify requests/responses.
    *   Supports both synchronous and asynchronous middleware.
    *   Chainable execution order.
    *   Built-in middleware for common tasks (Logging, Timing, CORS, Error Handling, Validation, Authentication, Rate Limiting, JWT, reCAPTCHA).
*   **Asynchronous Request Handling:**
    *   Route handlers can perform long-running operations without blocking the server thread using `Context::make_async()` and `AsyncCompletionHandler`.
    *   Built-in timeout management for async requests.
*   **Request/Response Abstraction (`qb::http::Request`, `qb::http::Response`):**
    *   Easy access to method, URI, headers, body, query parameters.
    *   Type-safe header management (case-insensitive).
    *   Flexible body handling (`Body::as<T>()`, `Body::raw()`).
    *   Cookie parsing and management (`qb::http::Cookie`, `CookieJar`).
    *   Multipart/form-data support (`qb::http::Multipart`).
*   **Authentication & Authorization (`qbm/http/auth`, `middleware/auth.h`, `middleware/jwt.h`):**
    *   JWT generation and verification (`qb::jwt`).
    *   Flexible `AuthManager` for token handling.
    *   `AuthMiddleware` for request authentication and role-based authorization.
*   **Validation (`qbm/http/validation`, `middleware/validator.h`):**
    *   Request validation using JSON Schema.
    *   Query parameter validation with type checking, ranges, patterns, enums.
    *   Input sanitization.
*   **Content Handling:**
    *   Automatic Content-Length calculation.
    *   Chunked Transfer Encoding support.
    *   Optional Content Compression (Gzip, Deflate via `qb-io` if built with Zlib).
*   **Transport:** Built on `qb::io::tcp::socket` and `qb::io::tcp::ssl::socket`.

## Quick Start

### Simple HTTP Server

```cpp
#include <http/http.h>
#include <qb/main.h>
#include <qb/actor.h>
#include <iostream>

// Define the Session Type based on the Server
class MyHttpServer;
class MyHttpSession : public qb::http::use<MyHttpSession>::session<MyHttpServer> {
public:
    explicit MyHttpSession(MyHttpServer& server) : session(server) {}
};

// Define the Server Actor
class MyHttpServer : public qb::Actor, public qb::http::use<MyHttpServer>::server<MyHttpSession> {
public:
    bool onInit() override {
        // Configure Router
        router()
            .get("/", [](Context& ctx) {
                ctx.response.add_header("Content-Type", "text/html");
                ctx.response.body() = "<h1>Hello from QB HTTP!</h1>";
                ctx.complete(); // Send the response
            })
            .get("/hello/:name", [](Context& ctx) {
                std::string name = ctx.param("name", "World");
                ctx.response.body() = "Hello, " + name + "!";
                ctx.complete();
            });

        // Add middleware (optional)
        router().use([](Context& ctx) {
            std::cout << "Middleware: Processing " << ctx.request.method_name() << " " << ctx.request.uri().path() << std::endl;
            ctx.response.add_header("X-Served-By", "QB-HTTP");
            return true; // Continue processing
        });

        // Listen on port 8080
        if (transport().listen({ "tcp://0.0.0.0:8080" })) {
             std::cerr << "Failed to listen on port 8080" << std::endl;
             return false;
        }
        std::cout << "Server listening on http://0.0.0.0:8080" << std::endl;
        start(); // Start accepting connections
        registerEvent<qb::KillEvent>(*this);
        return true;
    }

    void on(const qb::KillEvent&) {
        transport().close(); // Close listener socket
        kill();
    }
};

int main() {
    qb::Main engine;
    engine.addActor<MyHttpServer>(0);
    engine.start(false); // Run synchronously
    return 0;
}
```

### Simple HTTP Client

```cpp
#include <http/http.h>
#include <qb/io.h> // For qb::io::cout()
#include <iostream>

int main() {
    qb::http::Request req("http://httpbin.org/get");
    req.add_header("Accept", "application/json");

    // Asynchronous Request
    std::atomic<bool> done = false;
    qb::http::GET(req, [&done](qb::http::async::Reply&& reply) {
        qb::io::cout() << "--- Async Response ---" << std::endl;
        qb::io::cout() << "Status: " << reply.response.status() << std::endl;
        qb::io::cout() << "Body: " << reply.response.body().as<std::string>() << std::endl;
        done = true;
    });

    // Need an event loop to process the async reply
    while(!done) {
        qb::io::async::run(EVRUN_ONCE);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Synchronous Request
    qb::io::cout() << "\n--- Sync Response ---" << std::endl;
    try {
        qb::http::Response res = qb::http::GET(req, 5.0); // 5 second timeout
        qb::io::cout() << "Status: " << res.status() << std::endl;
        qb::io::cout() << "Body: " << res.body().as<std::string>() << std::endl;
    } catch (const std::exception& e) {
        qb::io::cout() << "Sync request failed: " << e.what() << std::endl;
    }

    return 0;
}
```

## Documentation

**Start here for detailed documentation:** **[`./readme/README.md`](./readme/README.md)**

Detailed documentation for specific features can also be found directly in the `readme/` directory:

*   **Core Concepts:**
    *   [`Core Concepts`](./readme/core_concepts.md): Fundamental ideas (Request/Response, Routing, Middleware, Async).
    *   [`Request & Response`](./readme/request_response.md): Details on `Request`, `Response`, `Headers`, `Body` classes.
    *   [`Routing System`](./readme/routing.md): In-depth look at the router, path parameters, groups, controllers, and Radix Tree matching.
    *   [`Middleware`](./readme/middleware.md): Explains the middleware concept, chain execution, synchronous vs. asynchronous middleware, and how to create custom middleware.
    *   [`Asynchronous Handling`](./readme/async_handling.md): Covers handling long-running tasks in route handlers using `make_async` and `AsyncCompletionHandler`, including timeouts and cancellation.
    *   [`Cookie Management`](./readme/cookies.md): Details on parsing, creating, and managing HTTP cookies using `Cookie` and `CookieJar`.
    *   [`Multipart/form-data Handling`](./readme/multipart.md): Parsing and creating multipart messages.
*   **Built-in Components:**
    *   [`Built-in Middleware`](./readme/builtin_middleware.md): Documentation for provided middleware like CORS, Logging, Rate Limiting, etc.
    *   [`Authentication & Authorization`](./readme/authentication.md): Details on the `AuthManager`, JWT integration, and the `AuthMiddleware`.
    *   [`Validation`](./readme/validation.md): How to use the `Validator` system, JSON Schema, query parameter validation, and sanitizers.
*   **Client & Server:**
    *   [`HTTP Client`](./readme/client.md): Using the global functions (`qb::http::GET`, `POST`, etc.) for making requests.
    *   [`HTTP Server`](./readme/server.md): Building servers using the `use<...>::server` and `use<...>::session` templates.
*   **Utilities & Reference:**
    *   [`Utilities`](./readme/utils.md): Covers `qb::http::date`, `qb::http::utility`, and other helpers.
    *   [`OpenAPI/Swagger Integration`](./readme/openapi.md): Generating API documentation.
    *   [`Dependencies`](./readme/dependencies.md): Lists the required and optional dependencies for the module.

## Building

Ensure `qb-core` is built or installed. Then, include this module in your CMake project:

```cmake
# Find the installed qbm-http package
# find_package(qbm-http REQUIRED)

# Or, if building alongside source:
# add_subdirectory(path/to/qbm/http)

# Link your target against the http module
# target_link_libraries(your_target PRIVATE qbm::http)
```

## Dependencies

*   `qb-core` (which includes `qb-io`)
*   `llhttp` (Bundled)
*   OpenSSL (Optional, required for HTTPS client/server and JWT asymmetric algorithms)
*   Zlib (Optional, required for content compression)

## API Documentation

- [Core Concepts](./readme/core_concepts.md)
- [Routing](./readme/routing.md)
- [Request/Response](./readme/request_response.md)
- [Middleware](./readme/middleware.md)
- [Authentication](./readme/authentication.md)
- [Built-in Middleware](./readme/builtin_middleware.md)
- [Validation](./readme/validation.md)
- [Async Handling](./readme/async_handling.md)
- [Cookies](./readme/cookies.md)
- [Multipart](./readme/multipart.md)
- [OpenAPI/Swagger Integration](./readme/openapi.md)
- [HTTP Client](./readme/client.md)
- [Server](./readme/server.md)
- [Utilities](./readme/utils.md)
- [Dependencies](./readme/dependencies.md)

```
Copyright (c) 2011-2025 qb - isndev (cpp.actor). All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

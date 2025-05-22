# QB HTTP Module (`qbm-http`)

Welcome to `qb-http`, a modern C++17 library for building high-performance, asynchronous HTTP/1.1 clients and servers. Part of the QB Actor Framework, `qb-http` is designed for developers seeking efficiency, type safety, and a clean, expressive API for their web services and applications.

Whether you're crafting a REST API, serving static content, or making outbound HTTP requests, `qb-http` provides the tools you need with a focus on asynchronous operations and ease of use.

## Core Philosophy

*   **Asynchronous & Non-Blocking:** Built entirely on the non-blocking I/O foundation of `qb-io` to maximize performance and concurrency.
*   **Modern C++17:** Leverages modern C++ features for clarity, safety, and performance.
*   **Flexibility & Extensibility:** Offers a powerful routing and middleware system for customization.
*   **Simplicity & Power:** Provides high-level APIs for common tasks while allowing deep control when needed.

## Key Features at a Glance

*   **HTTP/1.1 Client & Server:** Robust implementations for both roles.
*   **Expressive Routing Engine (`qb::http::Router`):**
    *   Method-based routing (GET, POST, PUT, DELETE, etc.).
    *   Path parameters (`/users/:id`) and wildcards (`/files/*filepath`).
    *   Route grouping and class-based Controllers for organization.
    *   Efficient Radix Tree-based matching.
*   **Flexible Middleware System (`qb::http::IMiddleware`):**
    *   Easily intercept and modify requests/responses.
    *   Support for synchronous and asynchronous middleware.
    *   Chainable execution with clear flow control.
    *   Comprehensive set of [standard middleware](./readme/08-standard-middleware.md) (Logging, CORS, Auth, Validation, etc.).
*   **Asynchronous Request Handling:**
    *   Route handlers and middleware can perform non-blocking I/O seamlessly.
    *   Built around the `qb::http::Context` for managing request lifecycle.
*   **Rich Request/Response API (`qb::http::Request`, `qb::http::Response`):
    *   Intuitive access to methods, URI, headers, body, cookies.
    *   Flexible body handling with `Body::as<T>()` and `Body::raw()`.
    *   Automatic `Content-Length`, cookie parsing, and multipart support.
*   **Built-in Authentication & Validation:**
    *   JWT generation & verification via `qb::http::auth` and `qb::jwt`.
    *   Request validation (body, params, headers) using JSON Schema-like definitions.
*   **Content Negotiation:** Automatic compression/decompression (Gzip/Deflate if Zlib enabled).

## Quick Start: A Simple HTTP Server

Let's create a server that says hello!

```cpp
#include <http/http.h> // Main include for this module

// Forward declare your server to define a session type
class MySimpleServer;

// Define a session type associated with your server
class MySimpleSession : public qb::http::use<MySimpleSession>::session<MySimpleServer> {
public:
    // Constructor boilerplate, passes server reference to base
    explicit MySimpleSession(MySimpleServer& server_ref)
        : qb::http::use<MySimpleSession>::session<MySimpleServer>(server_ref) {}
    
    // Optional: Add custom session-specific logic or state here if needed
};

// Define your server by inheriting from qb::http::use<...>::server<...>
class MySimpleServer : public qb::http::use<MySimpleServer>::server<MySimpleSession> {
public:
    MySimpleServer() {
        std::cout << "Configuring server routes..." << std::endl;

        // Define a GET route for the root path "/"
        router().get("/", [](auto ctx) { // ctx is std::shared_ptr<qb::http::Context<MySimpleSession>>
            std::cout << "Request to / received" << std::endl;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Type", "text/html; charset=utf-8");
            ctx->response().body() = "<h1>Hello from QB HTTP!</h1><p>Welcome to your first qb-http server.</p>";
            ctx->complete(); // Signal that request processing is finished
        });

        // Define a GET route with a path parameter
        router().get("/hello/:name", [](auto ctx) {
            auto name = ctx->path_param("name", "World"); // Get path param "name", default to "World"
            std::cout << "Request to /hello/" << name << " received" << std::endl;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Type", "text/plain; charset=utf-8");
            ctx->response().body() = "Hello, " + std::string(name) + "!";
            ctx->complete();
        });

        // Define an asynchronous route simulation
        router().get("/async-data", [](auto ctx) {
            std::cout << "Request to /async-data received, simulating async work..." << std::endl;
            auto shared_ctx = ctx; // Capture context for the async callback
            
            // Simulate an asynchronous operation using qb::io::async::callback
            qb::io::async::callback([shared_ctx]() {
                std::cout << "Async work for /async-data completed." << std::endl;
                if (shared_ctx->is_cancelled()) {
                    std::cout << "Async work for /async-data was cancelled before completion." << std::endl;
                    // Context is already completing with CANCELLED, just return
                    return;
                }
                shared_ctx->response().status() = qb::http::status::OK;
                shared_ctx->response().set_header("Content-Type", "application/json");
                shared_ctx->response().body() = R"({"data": "This is asynchronously fetched data!", "delay_simulated": "100ms"})";
                shared_ctx->complete();
            }, std::chrono::milliseconds(100)); // Simulate a 100ms delay
        });

        // Add a simple logging middleware for all routes
        router().use([](auto ctx, auto next){
            std::cout << "[Middleware] Request: " << std::to_string(ctx->request().method()) 
                      << " " << ctx->request().uri().path() << std::endl;
            ctx->response().set_header("X-Served-By", "QB-HTTP-Server");
            next(); // Call next to proceed to the next middleware or handler
            // This line will execute after the handler (or subsequent middleware) calls next() or complete()
            // Note: For async handlers/middleware, this post-processing part might execute *before* the async operation completes.
            // To reliably log after the full response, use a HookPoint::REQUEST_COMPLETE or similar.
            std::cout << "[Middleware] Response Status (after handler chain attempt): " << ctx->response().status().code() << std::endl;
        }, "SimpleLogger");

        // Important: Compile routes after defining them
        router().compile();
        std::cout << "Routes compiled." << std::endl;
    }

    // Optional: Callback for when a new client connection is accepted by the server transport
    void on(qb::http::use<MySimpleServer>::server<MySimpleSession>::IOSession& new_session_io) {
        std::cout << "New client connection established." << std::endl;
        // Note: The MySimpleSession object itself is created later by the framework 
        // when this IOSession is associated with a protocol.
    }
};

int main(int argc, char* argv[]) {
    // Initialize the qb-io asynchronous system for the main thread
    qb::io::async::init();

    MySimpleServer server_instance;

    // Listen on port 8080 on all IPv4 interfaces
    if (!server_instance.transport().listen_v4(8080)) {
        std::cerr << "Error: Failed to listen on port 8080." << std::endl;
        return 1;
    }
    std::cout << "Server listening on http://0.0.0.0:8080" << std::endl;

    server_instance.start(); // Start accepting connections and processing events

    // Run the main event loop (blocks until stopped or no more events)
    qb::io::async::run(); 

    std::cout << "Server shutting down." << std::endl;
    return 0;
}
```

## Quick Start: An HTTP Client (Asynchronous and Synchronous)

Making HTTP requests is just as straightforward, with both asynchronous and synchronous options.

```cpp
#include <qb/http/http.h>

int main() {
    qb::io::async::init(); // Initialize the async system

    // --- Asynchronous Request Example --- 
    std::cout << "--- Asynchronous GET Request Example ---" << std::endl;
    qb::http::Request async_req(qb::io::uri("http://worldtimeapi.org/api/ip"));
    async_req.add_header("Accept", "application/json");
    async_req.set_header("User-Agent", "QB-HTTP-Client-Async-Example/1.0");

    std::atomic<bool> async_request_done{false};

    qb::http::GET(std::move(async_req), 
        [&async_request_done](qb::http::async::Reply&& reply) { 
            std::cout << "Async Response Received for: " << reply.request.uri().to_string() << std::endl;
            std::cout << "Status: " << reply.response.status().code() 
                      << " " << std::string(reply.response.status()) << std::endl;
            if (reply.response.status() == qb::http::status::OK) {
                std::cout << "Body:\n" << reply.response.body().as<std::string>() << std::endl;
            } else {
                std::cerr << "Async Request failed. Body: " << reply.response.body().as<std::string>() << std::endl;
            }
            async_request_done = true;
        },
        5.0 // 5-second timeout
    );

    std::cout << "Async request sent, waiting for response (event loop processing required)..." << std::endl;
    while(!async_request_done.load()) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT); 
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); 
    }

    // --- Synchronous Request Example --- 
    std::cout << "\n--- Synchronous GET Request Example ---" << std::endl;
    qb::http::Request sync_req(qb::io::uri("http://httpbin.org/get"));
    sync_req.add_header("X-Sync-Test", "true");
    sync_req.set_header("User-Agent", "QB-HTTP-Client-Sync-Example/1.0");
    try {
        std::cout << "Sending synchronous GET request to httpbin.org..." << std::endl;
        // The synchronous call blocks until completion or timeout
        auto sync_res = qb::http::GET(std::move(sync_req), 3.0); // 3-second timeout
        std::cout << "Sync Status: " << sync_res.status().code() << std::endl;
        // httpbin.org/get echoes headers, so let's check our custom one
        auto echoed_json_body = sync_res.body().as<qb::json>();
        if (echoed_json_body.contains("headers") && echoed_json_body["headers"].contains("X-Sync-Test")) {
             std::cout << "Echoed X-Sync-Test header: " << echoed_json_body["headers"]["X-Sync-Test"].get<std::string>() << std::endl;
        }
        std::cout << "Sync Body (first 100 chars): " << sync_res.body().as<std::string_view>().substr(0, 100) << "..." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Synchronous request failed: " << e.what() << std::endl;
    }

    std::cout << "\nClient examples finished." << std::endl;
    return 0;
}
```

## Dive Deeper

This `README.md` provides a high-level overview. For detailed information, please refer to our comprehensive documentation set located in the [`./readme/`](./readme/README.md) directory. It covers:

*   Core Concepts (Request, Response, Body, Headers, URI)
*   The Routing System (Router, path matching, groups, controllers)
*   Middleware (overview, standard middleware, custom middleware)
*   Request Lifecycle and the `Context` object
*   Authentication and Authorization systems
*   Data Validation and Sanitization
*   Error Handling strategies
*   Advanced topics and best practices

**Start with the [Full Documentation Index](./readme/README.md).**

## Building `qbm-http`

To use `qbm-http` in your CMake project:

1.  Ensure `qb-core` (which includes `qb-io`) is available (built or installed).
2.  Add `qbm-http` to your project. If it's a subdirectory:
    ```cmake
    # Assuming qbm-http is in a subdirectory like 'libs/qb/qbm/http'
    add_subdirectory(libs/qb/qbm/http)
    ```
    Or, if `qbm-http` is installed system-wide or via `find_package`:
    ```cmake
    find_package(qbm-http REQUIRED)
    ```
3.  Link against the target:
    ```cmake
    target_link_libraries(your_application_target PRIVATE qbm::http)
    ```

### Dependencies

*   **Required**: `qb-core` (and its dependency `qb-io`), C++17 compiler, CMake.
*   **Bundled**: `llhttp` (for HTTP parsing).
*   **Optional**:
    *   OpenSSL: For HTTPS client/server functionality and JWT asymmetric algorithms. Enable with `QB_IO_WITH_SSL=ON` when building `qb-io`.
    *   Zlib: For Gzip/Deflate content compression/decompression. Enable with `QB_IO_WITH_ZLIB=ON` when building `qb-io`.

## Acknowledgements

This module stands on the shoulders of giants. We extend our sincere thanks to:

*   The **Node.js team and contributors** for `llhttp`, providing a fast and robust HTTP parser.
*   **Niels Lohmann** for the `nlohmann/json` library, used for JSON handling within the validation system and potentially by users for request/response bodies.

Their excellent work significantly contributes to the capabilities of `qb-http`.

---
*Copyright (c) 2011-2025 qb - isndev (cpp.actor). All rights reserved.*
*Licensed under the Apache License, Version 2.0.*

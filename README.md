# QB HTTP Module (`qbm-http`)

Welcome to `qb-http`, your C++17 toolkit for crafting high-performance, asynchronous HTTP/1.1 and HTTP/2 applications. As a key component of the QB Actor Framework, `qb-http` empowers developers with efficiency, type safety, and an elegant API for modern web services and clients.

Build blazing-fast REST APIs, serve static content with ease, or perform concurrent outbound HTTP requests – `qb-http` is designed for the demands of today's network programming, focusing on asynchronous operations and developer productivity.

## Why Choose `qb-http`? ✨

*   🚀 **Performance-First**: Built on the non-blocking, event-driven I/O of `qb-io`, ensuring high throughput and scalability.
*   💎 **Modern C++17 Design**: Leverages the latest C++ features for clean, safe, and maintainable code.
*   🔗 **Flexible & Extensible**: A powerful routing engine and a versatile middleware system allow deep customization.
*   🛠️ **Simplicity Meets Power**: High-level APIs for common tasks, with pathways for fine-grained control when you need it.
*   🔄 **HTTP/1.1 & HTTP/2 Support**: Comprehensive support for both major HTTP versions. HTTP/2 servers (via HTTPS/ALPN) can often serve HTTP/1.1 clients too.
*   🛡️ **Security & Validation Built-in**:
    *   Robust JWT generation and verification (`qb::http::auth`).
    *   Schema-based request validation for body, parameters, and headers (`qb::http::validation`).
    *   Standard middleware for CORS, security headers, and more.
*   🗜️ **Content Negotiation**: Automatic Gzip/Deflate compression and decompression (with Zlib).
*   🧩 **Modular Documentation**: Explore detailed guides for every aspect of the module.

## 🚀 Feature Showcase: HTTP/2 Server Example

This example demonstrates setting up an HTTP/2 server (which requires HTTPS) and showcases key features like routing, middleware, groups, controllers, path parameters, and query parameters. For HTTP/1.1 or HTTPS/1.1, the API is very similar!

```cpp
#include <http/http.h>      // Core HTTP/1.1 components (Request, Response, Router etc.)
#include <http/2/http2.h>  // For qb::http2::make_server and HTTP/2 specifics
#include <qb/io/async.h>   // For the asynchronous event loop
#include <filesystem>      // For std::filesystem::path
#include <iostream>        // For std::cout, std::cerr
#include <memory>          // For std::make_shared

// --- Define a Session Type (can be shared across server types) ---
// For HTTP/2, qb::http2::DefaultSession is often sufficient.
// For HTTP/1.1, qb::http::DefaultSession or qb::http::ssl::DefaultSecureSession.
// Let's use qb::http2::DefaultSession for the HTTP/2 example.
using MySessionType = qb::http2::DefaultSession;

// --- Simple Logging Middleware ---
class SimpleLoggerMiddleware : public qb::http::IMiddleware<MySessionType> {
public:
    std::string name() const override { return "SimpleLogger"; }
    void cancel() override {}
    void process(std::shared_ptr<qb::http::Context<MySessionType>> ctx) override {
        std::cout << "[Log] Request: " << std::to_string(ctx->request().method())
                  << " " << ctx->request().uri().path() << std::endl;
        // Add a hook to log response status after handler completion
        ctx->add_lifecycle_hook([](auto& context, qb::http::HookPoint point){
            if (point == qb::http::HookPoint::REQUEST_COMPLETE) {
                 std::cout << "[Log] Response: " << context.response().status().code() << std::endl;
            }
        });
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

// --- Example Controller ---
class UserController : public qb::http::Controller<MySessionType> {
public:
    UserController(std::string greeting) : _greeting(std::move(greeting)) {}

    void initialize_routes() override {
        // Path parameter: /api/users/{userId}
        this->get("/:userId", [this](auto ctx) {
            std::string user_id = ctx->path_param("userId");
            ctx->response().body() = _greeting + ", User " + user_id + "! From Controller.";
            ctx->complete();
        });
    }
    std::string get_node_name() const override { return "UserController"; }
private:
    std::string _greeting;
};

int main(int argc, char* argv[]) {
    qb::io::async::init(); // Initialize the asynchronous I/O system

    // --- HTTP/2 Server (Secure) ---
    // For HTTP/2, HTTPS is typically required. Certificates are needed.
    if (argc < 3) {
        std::cerr << "Usage for HTTP/2: " << argv[0] << " <cert_file.pem> <key_file.pem>" << std::endl;
        std::cerr << "Skipping HTTP/2 server example." << std::endl;
    } else {
        std::filesystem::path cert_path = argv[1];
        std::filesystem::path key_path = argv[2];

        if (!std::filesystem::exists(cert_path) || !std::filesystem::exists(key_path)) {
            std::cerr << "Certificate or key file not found. Skipping HTTP/2 server." << std::endl;
        } else {
            auto http2_server = qb::http2::make_server(); // Uses MySessionType via default

            // 1. Apply Global Middleware
            http2_server->router().use(std::make_shared<SimpleLoggerMiddleware>());

            // 2. Define a Route Group
            auto api_group = http2_server->router().group("/api");
            api_group->get("/status", [](auto ctx) {
                ctx->response().body() = "API Status: Healthy";
                ctx->complete();
            });

            // 3. Mount a Controller within the group
            // Full path will be /api/users/:userId
            api_group->controller<UserController>("/users", "Greetings"); 

            // 4. Route with Query Parameter
            http2_server->router().get("/search", [](auto ctx) {
                std::string query_term = ctx->request().query("q", 0, "default_term");
                ctx->response().body() = "Search results for: " + query_term;
                ctx->complete();
            });

            http2_server->router().compile();

            // HTTP/2 listen (requires SSL certs and key)
            // ALPN will negotiate "h2" for HTTP/2, can also offer "http/1.1" for fallback.
            if (!http2_server->listen({"https://0.0.0.0:9443"}, cert_path, key_path)) {
                std::cerr << "HTTP/2 Server: Failed to listen on port 9443." << std::endl;
            } else {
                std::cout << "HTTP/2 Server listening on https://0.0.0.0:9443" << std::endl;
                http2_server->start();
            }
        }
    }

    // --- Comments for Alternative Server Setups ---
    // 
    // // To create a plain HTTP/1.1 server:
    // // auto http1_server = qb::http::make_server(); 
    // // http1_server->router()... (configure as above)
    // // http1_server->router().compile();
    // // if (!http1_server->transport().listen_v4(8080)) { /* error */ }
    // // http1_server->start();
    // 
    // // To create an HTTPS/1.1 server:
    // // auto https1_server = qb::http::ssl::make_server();
    // // https1_server->router()... (configure as above)
    // // https1_server->router().compile();
    // // // The listen method for qb::http::ssl::Server also takes certs/key
    // // if (!https1_server->listen({"https://0.0.0.0:8443"}, cert_path, key_path)) { /* error */ }
    // // https1_server->start();

    std::cout << "Main event loop running... Press Ctrl+C to exit." << std::endl;
    qb::io::async::run(); // Blocks until qb::io::async::break_loop() is called elsewhere

    std::cout << "Server(s) shutting down." << std::endl;
    return 0;
}
```

**In this example, we've showcased:**
*   **HTTP/2 Server**: The primary server instance is HTTP/2, requiring SSL certificates.
*   **Middleware**: `SimpleLoggerMiddleware` is applied globally to log requests.
*   **Route Groups**: Routes under `/api` are grouped, potentially sharing group-specific middleware (not shown in this concise example, but possible).
*   **Controllers**: `UserController` organizes user-related routes like `/api/users/:userId`.
*   **Path Parameters**: `:userId` is extracted from the URL.
*   **Query Parameters**: `/search?q=term` demonstrates query parameter retrieval.
*   **Simplicity**: The API for defining routes and structuring the application remains clean and intuitive.

## Asynchronous HTTP Client
Making outbound requests is just as powerful, supporting both fully asynchronous operations with callbacks and convenient synchronous-style calls for simpler use cases.

```cpp
#include <http/http.h> // For HTTP/1.1 client
#include <http/2/client.h> // For HTTP/2 client (if needed for specific H2 features)

// HTTP/1.1 Asynchronous GET example
qb::http::Request req_http1(qb::io::uri("http://worldtimeapi.org/api/ip"));
qb::http::GET(std::move(req_http1), [](qb::http::async::Reply&& reply) {
    if (reply.response.status() == qb::http::status::OK) {
        std::cout << "HTTP/1.1 Async Response: " << reply.response.body().as<std::string_view>().substr(0, 60) << "..." << std::endl;
    }
});

// HTTP/1.1 Synchronous GET example
qb::http::Request sync_req(qb::io::uri("http://httpbin.org/get"));
sync_req.add_header("X-Sync-Test", "true");
qb::http::Response sync_response = qb::http::GET(std::move(sync_req), 3.0 /*timeout_sec*/);
std::cout << "HTTP/1.1 Sync Response Status: " << sync_response.status().code() << std::endl;
// Process sync_response.body() ...

// HTTP/2 Client Example (requires server from above example to be running)
// auto h2_client = qb::http2::make_client("https://localhost:9443");
// h2_client->connect([&](bool connected, const std::string& err_msg){
//     if(connected) {
//         qb::http::Request h2_req(qb::io::uri("/"));
//         h2_client->push_request(std::move(h2_req), [](qb::http::Response res){
//             std::cout << "HTTP/2 Client Response Status: " << res.status().code() << std::endl;
//         });
//     } else { std::cerr << "H2 client connect failed: " << err_msg << std::endl; }
// });

// Ensure qb::io::async::run() is active to process these.
```

## 📚 Dive Deeper: Full Documentation
This `README.md` is just a glimpse. For comprehensive details, explore our documentation set:

*   [**Full Documentation Index**](./readme/README.md)
    *   Covers Core Concepts, Routing, Middleware (Standard & Custom), Context, Auth, Validation, HTTP/2 Specifics, HTTPS, and more.

## Building `qbm-http`

1.  Ensure `qb-core` (which includes `qb-io`) is available.
2.  Add `qbm-http` to your CMake project:
    ```cmake
    # If qbm-http is a subdirectory
    add_subdirectory(path/to/qbm-http) 
    # Or if installed/found via find_package
    # find_package(qbm-http REQUIRED)
    target_link_libraries(your_application_target PRIVATE qbm::http)
    ```
### Dependencies
*   **Required**: `qb-core`, C++17 compiler, CMake.
*   **Bundled**: `llhttp` (for HTTP/1.1 parsing).
*   **Optional**:
    *   OpenSSL: For HTTPS & JWT. Enable `QB_IO_WITH_SSL=ON` when building `qb-io`.
    *   Zlib: For content compression. Enable `QB_IO_WITH_ZLIB=ON` when building `qb-io`.

## Acknowledgements
Special thanks to the Node.js team for `llhttp` and Niels Lohmann for `nlohmann/json`.

---
*Copyright (c) 2011-2025 qb - isndev (cpp.actor). All rights reserved.*
*Licensed under the Apache License, Version 2.0.*

# QB HTTP Module (qbm-http)

The HTTP module for the QB C++ Actor Framework provides a comprehensive, high-performance implementation of the HTTP/1.1 protocol. It supports both client and server implementations with synchronous and asynchronous APIs.

## Features

- **HTTP/1.1 Protocol Support**: Complete implementation of the HTTP/1.1 protocol.
- **High Performance**: Built on top of the llhttp parser for maximum efficiency.
- **Asynchronous API**: Event-driven architecture for non-blocking operations.
- **Synchronous API**: Simple request/response API for ease of use.
- **Content Compression**: Support for gzip, deflate and other compression algorithms when built with zlib support.
- **Multipart Form Data**: Built-in support for handling multipart/form-data.
- **Cookie Handling**: Parse and manage HTTP cookies.
- **Header Management**: Easy access to HTTP headers with case-insensitive lookup.
- **Routing System**: Flexible routing system for server implementations.
- **Transport Abstraction**: Support for TCP and SSL/TLS transports.
- **Timeout Handling**: Automatic session timeout management.

## Requirements

- QB C++ Actor Framework
- C++17 compatible compiler
- CMake 3.14 or newer
- Optional: zlib for compression support

## Integration

Add the module to your QB project:

```cmake
# In your CMakeLists.txt
qb_use_module(http)
```

## Basic Usage

### HTTP Client

#### Asynchronous Request

```cpp
#include <qb/http.h>

void make_async_request() {
    // Create a request
    qb::http::Request req("https://example.com");
    
    // Send it asynchronously
    qb::http::GET(req, [](qb::http::async::Reply&& reply) {
        if (reply.response.status_code == qb::http::HTTP_STATUS_OK) {
            std::cout << "Response: " << reply.response.body().as<std::string>() << std::endl;
        } else {
            std::cout << "Error: " << reply.response.status_code << std::endl;
        }
    });
    
    // Run the event loop until completion
    qb::io::async::run();
}
```

#### Synchronous Request

```cpp
#include <qb/http.h>

void make_sync_request() {
    // Create a request
    qb::http::Request req("https://example.com");
    
    // Send it synchronously
    auto response = qb::http::GET(req);
    
    if (response.status_code == qb::http::HTTP_STATUS_OK) {
        std::cout << "Response: " << response.body().as<std::string>() << std::endl;
    } else {
        std::cout << "Error: " << response.status_code << std::endl;
    }
}
```

### HTTP Server

```cpp
#include <qb/http.h>

class MyHTTPServer {
public:
    void run() {
        qb::http::use<MyHTTPServer>::server<Session> server;
        
        // Setup router with routes
        server.router()
            .GET("/hello", [](auto& ctx) {
                ctx.response.body() = "Hello, World!";
                ctx.session << ctx.response;
            })
            .GET("/json", [](auto& ctx) {
                ctx.response.headers()["Content-Type"] = {"application/json"};
                ctx.response.body() = "{\"message\": \"Hello, JSON!\"}";
                ctx.session << ctx.response;
            });
            
        // Start listening on port 8080
        server.bind("0.0.0.0", 8080);
        server.listen();
        
        // Run the event loop
        qb::io::async::run();
    }
    
private:
    // Define the session type
    using Session = qb::http::use<MyHTTPServer>::session<MyHTTPServer>;
};

int main() {
    MyHTTPServer server;
    server.run();
    return 0;
}
```

## Advanced Features

### Custom Middleware

You can implement middleware to process requests:

```cpp
// Authentication middleware
router.GET("/protected", [](auto& ctx) {
    auto auth = ctx.auth("Bearer");
    if (auth.empty()) {
        ctx.response.status_code = qb::http::HTTP_STATUS_UNAUTHORIZED;
        ctx.session << ctx.response;
        return;
    }
    
    // Process authenticated request...
    ctx.response.body() = "Protected content";
    ctx.session << ctx.response;
});
```

### Route Parameters

The routing system supports dynamic route parameters:

```cpp
router.GET("/users/:id", [](auto& ctx) {
    auto user_id = ctx.param("id");
    // Process user ID...
    ctx.response.body() = "User ID: " + user_id;
    ctx.session << ctx.response;
});
```

### Multipart Form Data

Handle file uploads and form data:

```cpp
router.POST("/upload", [](auto& ctx) {
    if (ctx.request.has_header("Content-Type") && 
        ctx.request.header("Content-Type").find("multipart/form-data") != std::string::npos) {
        
        auto multipart = ctx.request.body().as<qb::http::Multipart>();
        for (const auto& part : multipart.parts()) {
            // Process each part (file or form field)
            auto content_disposition = part.header("Content-Disposition");
            // ...
        }
    }
    
    ctx.response.body() = "Upload complete";
    ctx.session << ctx.response;
});
```

## Architecture

The HTTP module is built on top of the llhttp parser and integrated with the QB C++ Actor Framework's asynchronous I/O system. It provides:

- **Protocol Handlers**: Implementation of HTTP protocol parsing and generation
- **Transport Abstraction**: Support for different transport layers (TCP, SSL/TLS)
- **Session Management**: Handling connection lifecycle and timeouts
- **Routing System**: Mapping of URLs to handler functions
- **Content Processing**: Parsing and generation of HTTP content (including compression)

## License

Licensed under the Apache License, Version 2.0. See LICENSE file for details.
# QB HTTP Module (`qbm-http`)

**High-Performance HTTP/1.1 & HTTP/2 Client/Server for the QB Actor Framework**

<p align="center">
  <img src="https://img.shields.io/badge/HTTP-1.1%20%7C%202.0-blue.svg" alt="HTTP Versions"/>
  <img src="https://img.shields.io/badge/C%2B%2B-17-blue.svg" alt="C++17"/>
  <img src="https://img.shields.io/badge/Cross--Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg" alt="Cross Platform"/>
  <img src="https://img.shields.io/badge/Arch-x86__64%20%7C%20ARM64-lightgrey.svg" alt="Architecture"/>
  <img src="https://img.shields.io/badge/License-Apache%202.0-green.svg" alt="License"/>
</p>

`qbm-http` delivers production-ready HTTP/1.1 and HTTP/2 capabilities to the QB Actor Framework, enabling you to build high-performance web services and clients with minimal code complexity. Built on QB's asynchronous I/O foundation, it provides exceptional throughput while maintaining clean, expressive APIs.

Whether you're building REST APIs, serving static content, or performing concurrent HTTP requests, `qbm-http` eliminates the traditional complexity of web development without sacrificing performance.

## Quick Integration with QB

### Adding to Your QB Project

```bash
# Add the module as a submodule
git submodule add https://github.com/isndev/qbm-http qbm/http
```

### CMake Setup

```cmake
# QB framework setup
add_subdirectory(qb)
include_directories(${QB_PATH}/include)

# Load QB modules (automatically discovers qbm-http)
qb_load_modules("${CMAKE_CURRENT_SOURCE_DIR}/qbm")

# Link against the HTTP module
target_link_libraries(your_target PRIVATE qbm::http)
```

### Include and Use

```cpp
#include <http/http.h>                    // Core HTTP components
#include <http/middleware/all.h>          // For middleware (optional)
```

## Why Choose `qbm-http`?

**Performance First**: Built on QB's non-blocking I/O engine, ensuring high throughput and scalability without the complexity of traditional async programming.

**Simplicity**: Clean, modern C++ APIs that get out of your way. Build complete HTTP servers in just a few lines of code.

**Flexibility**: Powerful routing engine and middleware system allow complete customization while maintaining simplicity for common use cases.

**Cross-Platform**: Same code runs on Linux, macOS, Windows (x86_64, ARM64) with identical performance characteristics.

**HTTP/2 Ready**: Full HTTP/2 support with automatic negotiation, while maintaining HTTP/1.1 compatibility.

## Your First HTTP Server in 60 Seconds

```cpp
#include <http/http.h>
#include <qb/main.h>

class SimpleHttpServer : public qb::Actor, public qb::http::Server<> {
public:
    bool onInit() override {
        // Define routes
        router().get("/", [](auto ctx) {
            ctx->response().body() = "Hello from QB!";
            ctx->complete();
        });
        
        router().get("/api/status", [](auto ctx) {
            ctx->response().body() = R"({"status": "ok", "framework": "qb-http"})";
            ctx->complete();
        });
        
        // Start listening
        router().compile();
        if (listen({"tcp://0.0.0.0:8080"})) {
            start();
            std::cout << "Server running on http://localhost:8080" << std::endl;
            return true;
        }
        return false;
    }
};

int main() {
    qb::Main engine;
    engine.addActor<SimpleHttpServer>(0);
    engine.start();
    return 0;
}
```

**That's it!** No complex threading, no callback hell, no manual memory management. Just clean, actor-based HTTP serving.

## Real-World HTTP Server Example

Here's a more complete example showing routing, middleware, and controllers:

### Basic REST API Server

```cpp
#include <http/http.h>
#include <http/middleware/all.h>
#include <qb/main.h>
#include <qb/json.h>

// Custom middleware for request logging
class RequestLogger : public qb::http::IMiddleware<qb::http::DefaultSession> {
public:
    std::string name() const override { return "RequestLogger"; }
    
    void process(std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) override {
        auto& req = ctx->request();
        qb::io::cout() << "[" << qb::time::now() << "] " 
                       << req.method_string() << " " << req.uri().path() << std::endl;
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

// User controller with CRUD operations
class UserController : public qb::http::Controller<qb::http::DefaultSession> {
private:
    qb::json _users = qb::json::array();
    
public:
    void initialize_routes() override {
        // GET /users
        get("/", [this](auto ctx) {
            ctx->response().body() = _users.dump();
            ctx->complete();
        });
        
        // GET /users/:id
        get("/:id", [this](auto ctx) {
            int user_id = std::stoi(ctx->path_param("id"));
            if (user_id < _users.size()) {
                ctx->response().body() = _users[user_id].dump();
            } else {
                ctx->response().status() = qb::http::Status::NOT_FOUND;
                ctx->response().body() = R"({"error": "User not found"})";
            }
            ctx->complete();
        });
        
        // POST /users
        post("/", [this](auto ctx) {
            auto user_data = qb::json::parse(ctx->request().body().as<std::string>());
            user_data["id"] = _users.size();
            _users.push_back(user_data);
            
            ctx->response().status() = qb::http::Status::CREATED;
            ctx->response().body() = user_data.dump();
            ctx->complete();
        });
    }
    
    std::string get_node_name() const override { return "UserController"; }
};

class ApiServer : public qb::Actor, public qb::http::Server<> {
public:
    bool onInit() override {
        // Global middleware
        router().use(std::make_shared<RequestLogger>());
        
        // API routes group
        auto api = router().group("/api/v1");
        api->controller<UserController>("/users");
        
        // Static route
        router().get("/health", [](auto ctx) {
            ctx->response().body() = R"({"status": "healthy", "timestamp": ")" + 
                                    qb::time::now().to_string() + "\"}";
            ctx->complete();
        });
        
        router().compile();
        
        if (listen({"tcp://0.0.0.0:8080"})) {
            start();
            qb::io::cout() << "API Server running on http://localhost:8080" << std::endl;
            qb::io::cout() << "Try: curl http://localhost:8080/health" << std::endl;
            return true;
        }
        return false;
    }
};

int main() {
    qb::Main engine;
    engine.addActor<ApiServer>(0);
    engine.start();
    return 0;
}
```

### HTTP/2 Secure Server

```cpp
#include <http/http.h>
#include <qb/main.h>
#include <filesystem>

class Http2Server : public qb::Actor {
    std::unique_ptr<qb::http2::Server<>> _server;
    std::filesystem::path _cert_path;
    std::filesystem::path _key_path;
    
public:
    Http2Server(const std::filesystem::path& cert_path, const std::filesystem::path& key_path) 
        : _cert_path(cert_path), _key_path(key_path) {
        _server = qb::http2::make_server();
        
        // Configure routes
        _server->router().get("/", [](auto ctx) {
            ctx->response().body() = "HTTP/2 Server powered by QB!";
            ctx->complete();
        });
        
        _server->router().get("/api/data", [](auto ctx) {
            // Demonstrate query parameters
            auto format = ctx->request().query("format", 0, "json");
            
            if (format == "json") {
                ctx->response().body() = R"({"message": "Hello HTTP/2", "protocol": "h2"})";
            } else {
                ctx->response().body() = "Hello HTTP/2 (text)";
            }
            ctx->complete();
        });
        
        _server->router().compile();
    }
    
    bool onInit() override {
        // Start HTTPS server (HTTP/2 requires TLS)
        if (_server->listen({"https://0.0.0.0:8443"}, _cert_path.string(), _key_path.string())) {
            _server->start();
            qb::io::cout() << "HTTP/2 server running on https://localhost:8443" << std::endl;
            return true;
        }
        return false;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <cert.pem> <key.pem>" << std::endl;
        return 1;
    }
    
    qb::Main engine;
    engine.addActor<Http2Server>(0, argv[1], argv[2]);
    engine.start();
    return 0;
}
```

### HTTP/2 Client

```cpp
#include <http/http.h>
#include <qb/main.h>

class Http2ClientActor : public qb::Actor {
public:
    bool onInit() override {
        // Create HTTP/2 client
        auto client = qb::http2::make_client("https://localhost:8443");
        client->set_connect_timeout(10.0);
        
        // Connect to the server
        client->connect([this, client](bool connected, const std::string& error) {
            if (connected) {
                qb::io::cout() << "Connected to HTTP/2 server!" << std::endl;
                make_requests(client);
            } else {
                qb::io::cout() << "Connection failed: " << error << std::endl;
                kill();
            }
        });
        
        return true;
    }
    
private:
    void make_requests(std::shared_ptr<qb::http2::Client> client) {
        // Simple GET request
        qb::http::Request get_request;
        get_request.method() = qb::http::Method::GET;
        get_request.uri() = qb::io::uri("/");
        
        client->push_request(get_request, [this, client](qb::http::Response response) {
            qb::io::cout() << "GET Response: " << response.status().code() 
                           << " - " << response.body().as<std::string>() << std::endl;
            
            // Make a POST request after GET completes
            make_post_request(client);
        });
    }
    
    void make_post_request(std::shared_ptr<qb::http2::Client> client) {
        qb::http::Request post_request;
        post_request.method() = qb::http::Method::POST;
        post_request.uri() = qb::io::uri("/api/data");
        post_request.add_header("Content-Type", "application/json");
        post_request.body() = R"({"message": "Hello HTTP/2", "version": 2})";
        
        client->push_request(post_request, [this, client](qb::http::Response response) {
            qb::io::cout() << "POST Response: " << response.status().code() 
                           << " - " << response.body().as<std::string>() << std::endl;
            
            // Make concurrent requests
            make_concurrent_requests(client);
        });
    }
    
    void make_concurrent_requests(std::shared_ptr<qb::http2::Client> client) {
        // Prepare multiple requests
        std::vector<qb::http::Request> requests;
        for (int i = 1; i <= 3; ++i) {
            qb::http::Request request;
            request.method() = qb::http::Method::GET;
            request.uri() = qb::io::uri("/api/data?id=" + std::to_string(i));
            requests.push_back(std::move(request));
        }
        
        // Send batch requests (HTTP/2 multiplexing)
        client->push_requests(requests, [this](std::vector<qb::http::Response> responses) {
            qb::io::cout() << "Received " << responses.size() << " concurrent responses:" << std::endl;
            
            for (size_t i = 0; i < responses.size(); ++i) {
                qb::io::cout() << "  Request " << (i+1) << ": " 
                               << responses[i].status().code() << std::endl;
            }
            
            qb::io::cout() << "All HTTP/2 requests completed!" << std::endl;
            kill(); // Done
        });
    }
};

int main() {
    qb::Main engine;
    engine.addActor<Http2ClientActor>(0);
    engine.start();
    return 0;
}
```

## HTTP Client Examples

### Simple HTTP Client

```cpp
#include <http/http.h>
#include <qb/main.h>

class HttpClientActor : public qb::Actor {
public:
    bool onInit() override {
        // Asynchronous GET request
        qb::http::Request req(qb::io::uri("https://api.github.com/repos/isndev/qb"));
        req.add_header("User-Agent", "QB-HTTP-Client/1.0");
        
        qb::http::GET(std::move(req), [this](qb::http::async::Reply&& reply) {
            if (reply.response.status() == qb::http::status::OK) {
                auto data = qb::json::parse(reply.response.body().as<std::string>());
                qb::io::cout() << "QB Repository stars: " << data["stargazers_count"] << std::endl;
            } else {
                qb::io::cout() << "Request failed: " << reply.response.status().code() << std::endl;
            }
            kill(); // Done with request
        });
        
        return true;
    }
};

int main() {
    qb::Main engine;
    engine.addActor<HttpClientActor>(0);
    engine.start();
    return 0;
}
```

### Synchronous Client Usage

```cpp
#include <http/http.h>

int main() {
    qb::io::async::init(); // Required for sync usage
    
    // Simple synchronous GET
    qb::http::Request req(qb::io::uri("https://httpbin.org/json"));
    auto response = qb::http::GET(std::move(req), 5.0 /* timeout */);
    
    if (response.status() == qb::http::status::OK) {
        std::cout << "Response: " << response.body().as<std::string>() << std::endl;
    }
    
    return 0;
}
```

## Key Features

**Routing Engine:**
- Path parameters (`/users/:id`)
- Query parameters with defaults
- Route groups for organization
- Wildcard matching

**Middleware System:**
- Built-in middleware (CORS, compression, security headers)
- Custom middleware with lifecycle hooks
- Per-route or global application

**Controllers:**
- Object-oriented route organization
- Dependency injection support
- Hierarchical route mounting

**Security & Validation:**
- JWT generation and verification
- Request body/header validation
- CORS with configurable policies
- Security headers middleware

**Content Handling:**
- Automatic compression (Gzip/Deflate)
- JSON parsing and generation
- File serving with MIME type detection
- Multipart form handling

**Performance:**
- Zero-copy where possible
- Connection pooling for clients
- HTTP/2 server push
- Configurable buffer sizes

## Build Information

### Requirements
- **QB Framework**: This module requires the QB Actor Framework as its foundation
- **C++17** compatible compiler
- **CMake 3.14+**

### Optional Dependencies
- **OpenSSL**: For HTTPS & JWT support. Enable with `QB_IO_WITH_SSL=ON` when building QB
- **Zlib**: For content compression. Enable with `QB_IO_WITH_ZLIB=ON` when building QB

### Building with QB
When using the QB project template, simply add this module as shown in the integration section above. The `qb_load_modules()` function will automatically handle the configuration.

### Manual Build (Advanced)
```cmake
# If building outside QB framework context
find_package(qb REQUIRED)
target_link_libraries(your_target PRIVATE qbm-http)
```

## Advanced Documentation

For comprehensive technical documentation, implementation details, and in-depth guides:

**📖 [Complete HTTP Module Documentation](./readme/README.md)**

This detailed documentation covers:
- **[Core Concepts](./readme/01-core-concepts.md)** - HTTP fundamentals, request/response lifecycle, session management
- **[Body Deep Dive](./readme/02-body-deep-dive.md)** - Request/response body handling, streaming, and memory management
- **[Routing Overview](./readme/03-routing-overview.md)** - URL routing principles and pattern matching
- **[Defining Routes](./readme/04-defining-routes.md)** - Route definition syntax, parameters, and wildcards
- **[Route Groups](./readme/05-route-groups.md)** - Organizing routes with groups and nested structures
- **[Controllers](./readme/06-controllers.md)** - Object-oriented request handling and controller patterns
- **[Middleware](./readme/07-middleware.md)** - Middleware architecture and execution pipeline
- **[Standard Middleware](./readme/08-standard-middleware.md)** - Built-in middleware for common tasks
- **[Custom Middleware](./readme/09-custom-middleware.md)** - Creating your own middleware components
- **[Request Context](./readme/10-request-context.md)** - Context lifecycle and data sharing
- **[Authentication](./readme/11-authentication.md)** - JWT, session-based, and custom authentication
- **[Validation](./readme/12-validation.md)** - Request validation, sanitization, and error handling
- **[Error Handling](./readme/13-error-handling.md)** - Error management strategies and custom error pages
- **[Async HTTP Client](./readme/14-async-http-client.md)** - Making HTTP requests with the async client
- **[HTTP Parsing](./readme/15-http-parsing.md)** - Low-level HTTP parsing and protocol details
- **[Advanced Topics](./readme/16-advanced-topics.md)** - Performance tuning, security, and best practices
- **[HTTP/2 Protocol](./readme/17-http2-protocol.md)** - HTTP/2 features, server push, and optimization
- **[HTTPS & SSL/TLS](./readme/18-https-ssl-tls.md)** - Secure connections, certificates, and encryption

## Documentation & Examples

For comprehensive examples and detailed usage patterns, explore:

- **[QB Examples Repository](https://github.com/isndev/qb-examples):** Real-world HTTP server and client implementations
- **[Full Module Documentation](./readme/README.md):** Complete API reference and guides

**Example Categories:**
- Basic servers and routing
- Middleware development and usage
- Controller patterns and REST APIs
- JWT authentication and validation
- HTTPS and HTTP/2 configuration
- Static file serving
- Performance optimization

## Contributing

We welcome contributions! Please see the main [QB Contributing Guidelines](https://github.com/isndev/qb/blob/master/CONTRIBUTING.md) for details.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for details.

## Acknowledgments

The QB HTTP Module builds upon the excellent work of:

- **[llhttp](https://github.com/nodejs/llhttp)** - For HTTP1.1 protocol parsing structures (I/O handled by qb-io)

This library enables the module to efficiently parse HTTP protocol messages while maintaining QB's high-performance asynchronous I/O capabilities.

---

**Part of the [QB Actor Framework](https://github.com/isndev/qb) ecosystem - Build the future of concurrent C++ applications.**

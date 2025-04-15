# QB HTTP Module (qbm-http)

The HTTP module for the QB C++ Actor Framework provides a comprehensive, fast, and flexible implementation of the HTTP/1.1 protocol. It is designed for high-performance applications requiring robust, asynchronous, and scalable HTTP processing.

## Table of Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
  - [HTTP Client](#http-client)
  - [HTTP Server](#http-server)
- [Routing System](#routing-system)
  - [Basic Routes](#basic-routes)
  - [Route Parameters](#route-parameters)
  - [Route Groups](#route-groups)
  - [Controllers](#controllers)
- [Middleware](#middleware)
  - [Synchronous Middleware](#synchronous-middleware)
  - [Asynchronous Middleware](#asynchronous-middleware)
  - [Middleware Chaining](#middleware-chaining)
  - [Middleware Cancellation](#middleware-cancellation)
- [Asynchronous Request Handling](#asynchronous-request-handling)
  - [Deferred Processing](#deferred-processing)
  - [Parallel Operations](#parallel-operations)
  - [Asynchronous Error Handling](#asynchronous-error-handling)
  - [Timeout](#timeout)
- [Authentication and Authorization](#authentication-and-authorization)
  - [JWT (JSON Web Tokens)](#jwt-json-web-tokens)
  - [Authentication Middleware](#authentication-middleware)
  - [Role-Based Access Control](#role-based-access-control)
- [CORS Management](#cors-management)
  - [Simple Configuration](#simple-configuration)
  - [Advanced Configuration](#advanced-configuration)
- [Multipart and File Transfers](#multipart-and-file-transfers)
- [Performance Optimizations](#performance-optimizations)
  - [Radix Tree for Routing](#radix-tree-for-routing)
  - [String_view to Reduce Copying](#string_view-to-reduce-copying)
  - [Rate Limiting](#rate-limiting)
- [Advanced Examples](#advanced-examples)
- [API Reference](#api-reference)
- [License](#license)

## Key Features

- **Complete HTTP/1.1 Protocol**: Full support for the HTTP/1.1 specification.
- **Client and Server**: APIs for both client and server applications.
- **Asynchronous Architecture**: Non-blocking, event-based processing.
- **Synchronous API**: Simplified API for straightforward use cases.
- **Powerful Middleware**: Synchronous and asynchronous middleware for extending functionality.
- **Flexible Routing System**: Routing based on regular expressions and Radix Tree.
- **Hierarchical Controllers**: Modular organization of your routes.
- **Route Parameters**: URL parameter extraction.
- **Header Management**: Easy handling of HTTP headers.
- **Cookies**: Complete support for cookie management.
- **Message Body Handling**: Advanced HTTP content processing.
- **Multipart/form-data**: Support for form processing and file uploads.
- **Content Compression**: Support for gzip, deflate, and other compression algorithms.
- **Authentication and Authorization**: Built-in JWT and middleware for security.
- **CORS**: Configurable Cross-Origin Resource Sharing support.
- **Performance Optimizations**: Radix Tree for routing, string_view to avoid copying.
- **Robust Error Handling**: Configurable middleware and error handlers.
- **Extensive Testing**: Comprehensive test suite to ensure reliability.

## Architecture

The HTTP module is built on a layered architecture:

### Transport Layer
- TCP/IP and SSL/TLS connection management
- Transport abstraction for different connection types
- Asynchronous I/O management

### Protocol Layer
- HTTP message parsing and generation
- High-performance parser based on http
- Headers and message body management

### Routing Layer
- URL mapping to appropriate handlers
- Support for route parameters and regular expressions
- Optimization via Radix Tree for high-performance routing

### Application Layer
- Middleware for custom logic
- Controllers for modular organization
- High-level APIs for specific use cases

## Installation

To use the HTTP module in your QB project, add it to your CMakeLists.txt:

```cmake
# In your CMakeLists.txt
qb_use_module(http)
```

Make sure you have the following dependencies installed:
- QB C++ Actor Framework
- C++17 compatible compiler
- CMake 3.14 or newer
- OpenSSL (optional, for SSL/TLS)
- zlib (optional, for compression)

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
        
        // Configure router with routes
        server.router()
            .GET("/hello", [](auto& ctx) {
                ctx.response.body() = "Hello, World!";
                ctx.session << ctx.response;
            })
            .GET("/json", [](auto& ctx) {
                ctx.response.add_header("Content-Type", "application/json");
                ctx.response.body() = "{\"message\": \"Hello, JSON!\"}";
                ctx.session << ctx.response;
            })
            .GET("/users/:id", [](auto& ctx) {
                auto id = ctx.param("id");
                ctx.response.body() = "User ID: " + id;
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

## Routing System

The routing system is one of the most powerful features of the HTTP module. It allows mapping HTTP requests to appropriate handlers based on the HTTP method and URL path.

### Basic Routes

```cpp
// Basic route configuration
router
    .GET("/", [](auto& ctx) {
        ctx.response.body() = "Homepage";
        ctx.session << ctx.response;
    })
    .POST("/users", [](auto& ctx) {
        // Create a user
        ctx.response.status_code = qb::http::HTTP_STATUS_CREATED;
        ctx.session << ctx.response;
    })
    .PUT("/users/:id", [](auto& ctx) {
        // Update a user
        ctx.session << ctx.response;
    })
    .DELETE("/users/:id", [](auto& ctx) {
        // Delete a user
    ctx.session << ctx.response;
});
```

### Route Parameters

Route parameters are specified with the `:` prefix in the route path:

```cpp
router.GET("/users/:id/orders/:order_id", [](auto& ctx) {
    auto user_id = ctx.param("id");
    auto order_id = ctx.param("order_id");
    
    ctx.response.body() = "Order " + order_id + " for user " + user_id;
    ctx.session << ctx.response;
});
```

### Route Groups

Route groups allow you to organize routes with a common prefix:

```cpp
auto api = router.group("/api/v1", 10); // Priority 10

api.GET("/users", [](auto& ctx) {
    // List users
    ctx.session << ctx.response;
});

api.GET("/products", [](auto& ctx) {
    // List products
    ctx.session << ctx.response;
});
```

### Controllers

Controllers allow modular organization of routes:

```cpp
class UsersController : public Router::Controller {
public:
    UsersController() : Router::Controller("/users") {
        router().GET("/", [](auto& ctx) {
            // List users
            ctx.session << ctx.response;
        });
        
        router().GET("/:id", [](auto& ctx) {
            auto id = ctx.param("id");
            // User details
            ctx.session << ctx.response;
        });
        
        router().POST("/", [](auto& ctx) {
            // Create a user
            ctx.session << ctx.response;
        });
    }
};

// Register the controller
router.controller<UsersController>();
```

## Middleware

The middleware system allows intercepting and modifying requests and responses at different points in the processing pipeline.

### Synchronous Middleware

```cpp
// Logging middleware
router.use([](auto& ctx) {
    std::cout << ctx.request.method << " " << ctx.path() << std::endl;
    return true; // Continue processing
});

// Security middleware
router.use([](auto& ctx) {
    if (ctx.header("X-API-Key") != "secret-key") {
        ctx.response.status_code = qb::http::HTTP_STATUS_UNAUTHORIZED;
        ctx.session << ctx.response;
        return false; // Stop processing
    }
    return true; // Continue
});
```

### Asynchronous Middleware

Asynchronous middleware allows non-blocking operations:

```cpp
router.use_async([](auto& ctx, auto next) {
    // Asynchronous operation, e.g., authentication check
    std::thread([ctx, next]() mutable {
        // Simulate an asynchronous operation
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Authentication successful
        ctx.set<std::string>("user_id", "12345");
        next(true); // Continue processing
    }).detach();
});
```

### Middleware Chaining

Middleware is executed in the order it's registered:

```cpp
router
    .use(middleware1) // First middleware
    .use(middleware2) // Second middleware
    .use_async(async_middleware) // Asynchronous middleware
    .GET("/route", handler); // Route handler
```

### Middleware Cancellation

A middleware can decide to stop the chain:

```cpp
router.use_async([](auto& ctx, auto next) {
    if (error_condition) {
        ctx.response.status_code = qb::http::HTTP_STATUS_BAD_REQUEST;
        ctx.session << ctx.response;
        next(false); // Stop the chain
        return;
    }
    next(true); // Continue
});
```

## Asynchronous Request Handling

The HTTP module offers powerful mechanisms for handling asynchronous requests.

### Deferred Processing

```cpp
router.GET("/long-operation", [](auto& ctx) {
    // Mark the request as asynchronous
    auto handler = ctx.make_async();
    
    // Process in another thread or later
    std::thread([handler]() mutable {
        // Simulate a long operation
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // Complete the request
        handler->status(qb::http::HTTP_STATUS_OK)
                .body("Operation completed")
                .complete();
    }).detach();
});
```

### Parallel Operations

```cpp
router.use_async([](auto& ctx, auto next) {
    // Counter for completed operations
    auto completed = std::make_shared<std::atomic<int>>(0);
    auto total_operations = 3;
    
    // Operation 1
    std::thread([ctx, completed, total_operations, next]() mutable {
        // Operation 1
        if (++(*completed) == total_operations) {
            next(true); // All operations are completed
        }
    }).detach();
    
    // Operation 2
    std::thread([ctx, completed, total_operations, next]() mutable {
        // Operation 2
        if (++(*completed) == total_operations) {
            next(true);
        }
    }).detach();
    
    // Operation 3
    std::thread([ctx, completed, total_operations, next]() mutable {
        // Operation 3
        if (++(*completed) == total_operations) {
            next(true);
        }
    }).detach();
});
```

### Asynchronous Error Handling

```cpp
router.use_async([](auto& ctx, auto next) {
    try {
        // Operation that might fail
        std::thread([ctx, next]() mutable {
            try {
                // Risky operation
                if (error) {
                    throw std::runtime_error("Operation error");
                }
                next(true);
            } catch (const std::exception& e) {
                ctx.response.status_code = qb::http::HTTP_STATUS_INTERNAL_SERVER_ERROR;
                ctx.response.body() = e.what();
                next(false);
            }
        }).detach();
    } catch (const std::exception& e) {
        ctx.response.status_code = qb::http::HTTP_STATUS_INTERNAL_SERVER_ERROR;
        ctx.response.body() = e.what();
        next(false);
    }
});
```

### Timeout

```cpp
// Configure timeout for asynchronous requests
router.configure_async_timeout(30); // 30 seconds

// Use a route-specific timeout
router.GET("/long-operation", [](auto& ctx) {
    auto handler = ctx.make_async();
    
    // Start a timer
    auto timer_id = start_timer(20000, [handler]() {
        // Cancel the request after 20 seconds
        handler->status(qb::http::HTTP_STATUS_REQUEST_TIMEOUT)
                .body("Operation timed out")
                .complete();
    });
    
    std::thread([handler, timer_id]() mutable {
        // Long operation
        std::this_thread::sleep_for(std::chrono::seconds(15));
        
        // Cancel the timer
        cancel_timer(timer_id);
        
        // Complete the request
        handler->status(qb::http::HTTP_STATUS_OK)
                .body("Operation completed")
                .complete();
    }).detach();
});
```

## Authentication and Authorization

The HTTP module includes a comprehensive authentication and authorization system.

### JWT (JSON Web Tokens)

```cpp
// Configure authentication options
qb::http::AuthOptions options;
options.secret_key("my-very-secure-secret")
       .algorithm(qb::http::AuthOptions::Algorithm::HMAC_SHA256)
       .token_expiration(std::chrono::hours(24))
       .token_issuer("my-api")
       .token_audience("my-app");
       
// Create the authentication manager
qb::http::AuthManager auth_manager(options);

// Generate a token
qb::http::AuthUser user;
user.id = "12345";
user.username = "john.doe";
user.roles = {"user", "admin"};
user.metadata["email"] = "john.doe@example.com";

std::string token = auth_manager.generate_token(user);
```

### Authentication Middleware

```cpp
// Authentication middleware
router.use(auth_manager.authenticate<Router>());

// Protected route
router.GET("/admin", [](auto& ctx) {
    // User is already authenticated here
    const auto& user = ctx.get<qb::http::AuthUser>("user");
    ctx.response.body() = "Welcome, " + user.username;
    ctx.session << ctx.response;
});
```

### Role-Based Access Control

```cpp
// Route accessible only to administrators
router.GET("/admin-panel", 
    auth_manager.authorize<Router>({"admin"}),
    [](auto& ctx) {
        ctx.response.body() = "Administration Panel";
        ctx.session << ctx.response;
    }
);

// Route requiring multiple roles
router.GET("/reports", 
    auth_manager.authorize<Router>({"admin", "analyst"}, true), // require_all = true
    [](auto& ctx) {
        ctx.response.body() = "Confidential Reports";
        ctx.session << ctx.response;
    }
);
```

## CORS Management

The HTTP module offers comprehensive support for CORS (Cross-Origin Resource Sharing).

### Simple Configuration

```cpp
// Enable CORS with default options (permissive)
router.enable_dev_cors();
```

### Advanced Configuration

```cpp
// Custom CORS configuration
qb::http::CorsOptions cors_options;
cors_options.origins({"https://my-app.com", "https://dev.my-app.com"})
           .methods({"GET", "POST", "PUT", "DELETE"})
           .headers({"Content-Type", "Authorization", "X-Requested-With"})
           .credentials(qb::http::CorsOptions::AllowCredentials::Yes)
           .expose({"X-Total-Count"})
           .age(3600);

router.enable_cors(cors_options);

// CORS configuration with regular expressions
router.enable_cors_with_patterns(
    {"^https://.*\\.my-app\\.com$", "^https://partner\\.com$"},
    {"GET", "POST", "PUT", "DELETE"},
    {"Content-Type", "Authorization"},
    true // allow_credentials
);
```

## Multipart and File Transfers

The HTTP module supports processing multipart/form-data.

```cpp
router.POST("/upload", [](auto& ctx) {
    if (ctx.request.has_header("Content-Type") && 
        ctx.request.header("Content-Type").find("multipart/form-data") != std::string::npos) {
        
        auto multipart = ctx.request.body().as<qb::http::Multipart>();
        
        for (const auto& part : multipart.parts()) {
            auto name = part.get_name();
            auto filename = part.get_filename();
            
            if (!filename.empty()) {
                // It's a file
                std::ofstream file(filename, std::ios::binary);
                file.write(part.body().raw().data(), part.body().raw().size());
                
                ctx.response.body() = "File uploaded: " + filename;
            } else {
                // It's a form field
                std::string value(part.body().raw().begin(), part.body().raw().end());
                std::cout << "Field: " << name << " = " << value << std::endl;
            }
        }
    }
    
    ctx.session << ctx.response;
});
```

## Performance Optimizations

The HTTP module includes several optimizations for high-performance applications.

### Radix Tree for Routing

The Radix Tree offers faster routing than regular expressions for a large number of routes.

```cpp
// Enable Radix Tree (enabled by default)
router.enable_radix_tree(true);

// Force Radix Tree for a specific method
router.force_enable_radix_tree_for_method(qb::http::HTTP_GET);

// Build Radix Trees for all methods
router.build_radix_trees();
```

### String_view to Reduce Copying

The HTTP module uses string_view to avoid string copies.

```cpp
// Use the optimized version with string_view
using OptimizedSession = qb::http::use<MyServer>::session_view<MyServer>;
qb::http::use<MyServer>::server<OptimizedSession> server;
```

### Rate Limiting

```cpp
// Configure rate limiting: 100 requests per minute
router.configure_rate_limit(100, 60);
```

## Advanced Examples

### Using HTTPS

```cpp
// Create an HTTPS server
using SecureSession = qb::http::use<MyServer>::ssl::session<MyServer>;
qb::http::use<MyServer>::ssl::server<SecureSession> secure_server;

// Configure SSL
secure_server.setSSLCertificateChainFile("cert.pem");
secure_server.setSSLPrivateKeyFile("key.pem");

// Start the server on port 443
secure_server.bind("0.0.0.0", 443);
secure_server.listen();
```

### Sessions and User State

```cpp
router.GET("/set-session", [](auto& ctx) {
    // Store session data
    ctx.set<std::string>("session_id", generate_session_id());
    ctx.set<int>("visit_count", 1);
    
    ctx.response.body() = "Session created";
    ctx.session << ctx.response;
});

router.GET("/get-session", [](auto& ctx) {
    // Retrieve session data
    if (ctx.has("session_id")) {
        auto session_id = ctx.get<std::string>("session_id");
        auto visit_count = ctx.get<int>("visit_count", 0) + 1;
        
        // Update the counter
        ctx.set<int>("visit_count", visit_count);
    
        ctx.response.body() = "Session ID: " + session_id + 
                             ", Visits: " + std::to_string(visit_count);
    } else {
        ctx.response.body() = "No active session";
    }
    
    ctx.session << ctx.response;
});
```

### Response Streaming

```cpp
router.GET("/stream", [](auto& ctx) {
    ctx.response.add_header("Content-Type", "text/event-stream");
    ctx.response.add_header("Cache-Control", "no-cache");
    ctx.response.add_header("Connection", "keep-alive");
    
    auto handler = ctx.make_async();
    
    // Start data streaming
    std::thread([handler]() mutable {
        for (int i = 0; i < 10; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            // Send an event
            std::string data = "data: " + std::to_string(i) + "\n\n";
            handler->body(data)
                  .complete();
            
            // Create a new handler for the next event
            handler = /* create a new handler */;
        }
        
        // End streaming
        handler->body("data: [END]\n\n")
              .complete();
    }).detach();
});
```

## API Reference

For a complete API reference, consult the header files:

- **http.h**: Main entry point of the module
- **request.h**: HTTP request handling
- **response.h**: HTTP response handling
- **router.h**: Routing system
- **auth.h**: Authentication and authorization
- **body.h**: Message body processing
- **multipart.h**: Multipart/form-data processing
- **cookie.h**: Cookie management
- **headers.h**: HTTP header management

## License

This module is distributed under the Apache License, Version 2.0. See the LICENSE file for details.

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
# QB HTTP Module (qbm-http)

The HTTP module for the QB C++ Actor Framework provides a comprehensive, fast, and flexible implementation of the HTTP/1.1 protocol. It is designed for high-performance applications requiring robust, asynchronous, and scalable HTTP processing.

## Table of Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
  - [HTTP Client](#http-client)
  - [HTTP Server](#http-server)
- [Core Components](#core-components)
  - [Request](#request)
  - [Response](#response)
  - [Headers](#headers)
  - [Body](#body)
  - [Cookie](#cookie)
  - [Multipart](#multipart)
- [Routing System](#routing-system)
  - [Basic Routes](#basic-routes)
  - [Route Parameters](#route-parameters)
  - [Route Groups](#route-groups)
  - [Controllers](#controllers)
  - [Radix Tree](#radix-tree)
- [Middleware](#middleware)
  - [Synchronous Middleware](#synchronous-middleware)
  - [Asynchronous Middleware](#asynchronous-middleware)
  - [Middleware Chaining](#middleware-chaining)
  - [Middleware Cancellation](#middleware-cancellation)
  - [Built-in Middleware](#built-in-middleware)
- [Authentication](#authentication-and-authorization)
  - [Auth Manager](#auth-manager)
  - [User Authentication](#user-authentication)
  - [Role-Based Access Control](#role-based-access-control)
- [Validation](#validation)
  - [JSON Schema Validation](#json-schema-validation)
  - [Query Parameter Validation](#query-parameter-validation)
  - [Custom Validators](#custom-validators)
- [Advanced Features](#advanced-features)
  - [CORS Management](#cors-management)
  - [Rate Limiting](#rate-limiting)
  - [File Transfers](#file-transfers)
  - [Content Compression](#content-compression)
- [Examples](#examples)
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
- High-performance parser based on llhttp
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

## Core Components

### Request

The `Request` class represents an HTTP request with methods, headers, and body content:

```cpp
// Create a request with a URL
qb::http::Request req("https://example.com/api/users");

// Set HTTP method
req.method = qb::http::HTTP_GET;

// Add headers
req.add_header("Authorization", "Bearer token123");
req.add_header("Accept", "application/json");

// Add query parameters
req.add_query_param("page", "1");
req.add_query_param("limit", "10");

// Set body content (for POST, PUT, etc.)
qb::json::Object json_body;
json_body["name"] = "John Doe";
json_body["email"] = "john@example.com";
req.body() = json_body;
```

### Response

The `Response` class represents an HTTP response with status code, headers, and body:

```cpp
// Create a response
qb::http::Response res;

// Set status code
res.status_code = qb::http::HTTP_STATUS_OK;

// Add headers
res.add_header("Content-Type", "application/json");
res.add_header("Cache-Control", "no-cache");

// Set body content
qb::json::Object json_response;
json_response["id"] = 123;
json_response["name"] = "John Doe";
res.body() = json_response;

// Add a cookie
res.add_cookie("session_id", "abc123", {
    .max_age = 3600,
    .path = "/",
    .secure = true,
    .http_only = true
});
```

### Headers

The `Headers` class manages HTTP headers with case-insensitive key lookup:

```cpp
// Access response headers
auto content_type = res.header("Content-Type");

// Check if a header exists
if (req.has_header("Authorization")) {
    auto auth = req.header("Authorization");
}

// Add multiple values for the same header
res.add_header("Access-Control-Allow-Origin", "https://example.com");
res.add_header("Access-Control-Allow-Origin", "https://admin.example.com");

// Get all values for a header
auto origins = res.headers()["Access-Control-Allow-Origin"];
```

### Body

The `Body` class handles HTTP message bodies with content type awareness:

```cpp
// Set JSON body
req.body() = qb::json::Object{{"name", "John"}, {"age", 30}};

// Set string body
res.body() = "Plain text response";

// Set raw binary data
std::vector<char> binary_data = /* ... */;
req.body().raw() = std::move(binary_data);

// Access body as different types
auto json_body = res.body().as<qb::json::Value>();
auto text_body = res.body().as<std::string>();
```

### Cookie

The `Cookie` class handles HTTP cookies with all RFC 6265 attributes:

```cpp
// Parse cookies from a request
auto cookies = qb::http::Cookie::parse(req.header("Cookie"));
auto session_id = cookies["session_id"];

// Create a cookie with attributes
qb::http::CookieOptions options;
options.max_age = 3600; // 1 hour
options.path = "/";
options.domain = "example.com";
options.secure = true;
options.http_only = true;
options.same_site = qb::http::SameSite::Strict;

res.add_cookie("user_id", "12345", options);
```

### Multipart

The `Multipart` class handles multipart/form-data for file uploads and form submissions:

```cpp
// Process a multipart form submission
auto multipart = req.body().as<qb::http::Multipart>();

for (const auto& part : multipart.parts()) {
    // Get part name and filename
    auto name = part.get_name();
    auto filename = part.get_filename();
    
    if (!filename.empty()) {
        // It's a file upload
        auto content_type = part.get_content_type();
        auto file_data = part.body().raw();
        
        // Save to disk
        std::ofstream file(filename, std::ios::binary);
        file.write(file_data.data(), file_data.size());
    } else {
        // It's a form field
        auto field_value = part.body().as<std::string>();
    }
}
```

## Routing System

The routing system maps HTTP requests to appropriate handlers based on HTTP method and URL path.

### Basic Routes

```cpp
// Basic route configuration
router
    .GET("/", [](auto& ctx) {
        ctx.response.body() = "Homepage";
        ctx.session << ctx.response;
    })
    .POST("/users", [](auto& ctx) {
        // Create a user from request body
        auto json = ctx.request.body().as<qb::json::Value>();
        std::string name = json["name"].as<std::string>();
        
        ctx.response.status_code = qb::http::HTTP_STATUS_CREATED;
        ctx.response.body() = "User created: " + name;
        ctx.session << ctx.response;
    })
    .PUT("/users/:id", [](auto& ctx) {
        // Update a user
        auto id = ctx.param("id");
        auto json = ctx.request.body().as<qb::json::Value>();
        
        ctx.response.body() = "User updated: " + id;
        ctx.session << ctx.response;
    })
    .DELETE("/users/:id", [](auto& ctx) {
        // Delete a user
        auto id = ctx.param("id");
        
        ctx.response.status_code = qb::http::HTTP_STATUS_NO_CONTENT;
        ctx.session << ctx.response;
    });
```

### Route Parameters

Route parameters are specified with the `:` prefix in the route path:

```cpp
router.GET("/users/:id/posts/:post_id", [](auto& ctx) {
    auto user_id = ctx.param("id");
    auto post_id = ctx.param("post_id");
    
    ctx.response.body() = "Post " + post_id + " by user " + user_id;
    ctx.session << ctx.response;
});

// Optional parameters with wildcards
router.GET("/files/*path", [](auto& ctx) {
    auto path = ctx.param("path");
    
    ctx.response.body() = "Requested file: " + path;
    ctx.session << ctx.response;
});

// Regular expression parameters
router.GET("/products/:product_id([0-9]+)", [](auto& ctx) {
    auto product_id = ctx.param("product_id");
    
    ctx.response.body() = "Product ID: " + product_id;
    ctx.session << ctx.response;
});
```

### Route Groups

Route groups allow you to organize routes with a common prefix:

```cpp
// Create an API group with priority 10
auto api = router.group("/api/v1", 10);

// Add routes to the group
api.GET("/users", [](auto& ctx) {
    // List users
    ctx.response.body() = "Users list";
    ctx.session << ctx.response;
});

api.GET("/products", [](auto& ctx) {
    // List products
    ctx.response.body() = "Products list";
    ctx.session << ctx.response;
});

// Nested groups
auto admin = api.group("/admin");
admin.GET("/stats", [](auto& ctx) {
    // Admin statistics
    ctx.response.body() = "Admin statistics";
    ctx.session << ctx.response;
});
```

### Controllers

Controllers allow modular organization of routes:

```cpp
class UsersController : public Router::Controller {
public:
    UsersController() : Router::Controller("/users") {
        // Define routes relative to the controller base path
        
        // GET /users
        router().GET("/", [](auto& ctx) {
            ctx.response.body() = "List of users";
            ctx.session << ctx.response;
        });
        
        // GET /users/:id
        router().GET("/:id", [](auto& ctx) {
            auto id = ctx.param("id");
            ctx.response.body() = "User details for ID: " + id;
            ctx.session << ctx.response;
        });
        
        // POST /users
        router().POST("/", [](auto& ctx) {
            ctx.response.status_code = qb::http::HTTP_STATUS_CREATED;
            ctx.response.body() = "User created";
            ctx.session << ctx.response;
        });
        
        // PUT /users/:id
        router().PUT("/:id", [](auto& ctx) {
            auto id = ctx.param("id");
            ctx.response.body() = "User updated: " + id;
            ctx.session << ctx.response;
        });
        
        // DELETE /users/:id
        router().DELETE("/:id", [](auto& ctx) {
            auto id = ctx.param("id");
            ctx.response.status_code = qb::http::HTTP_STATUS_NO_CONTENT;
            ctx.session << ctx.response;
        });
    }
};

// Register the controller with the router
router.controller<UsersController>();
```

### Radix Tree

The Radix Tree provides high-performance routing for a large number of routes:

```cpp
// Enable Radix Tree for all HTTP methods (enabled by default)
router.enable_radix_tree(true);

// Force Radix Tree for specific methods
router.force_enable_radix_tree_for_method(qb::http::HTTP_GET);
router.force_enable_radix_tree_for_method(qb::http::HTTP_POST);

// Build Radix Trees for all methods (called automatically when server starts)
router.build_radix_trees();
```

## Middleware

The middleware system allows intercepting and modifying requests and responses at different points in the processing pipeline.

### Synchronous Middleware

```cpp
// Logging middleware
router.use([](auto& ctx) {
    std::cout << "[" << qb::http::Date::now_as_string() << "] "
              << ctx.request.method << " " << ctx.path() << std::endl;
    return true; // Continue processing
});

// Request validation middleware
router.use([](auto& ctx) {
    if (!ctx.has_header("X-API-Key")) {
        ctx.response.status_code = qb::http::HTTP_STATUS_UNAUTHORIZED;
        ctx.response.body() = "API key required";
        ctx.session << ctx.response;
        return false; // Stop processing
    }
    return true; // Continue processing
});

// Response modification middleware
router.use([](auto& ctx) {
    // Add common headers to all responses
    ctx.response.add_header("X-Powered-By", "QB HTTP");
    ctx.response.add_header("X-Frame-Options", "DENY");
    ctx.response.add_header("X-Content-Type-Options", "nosniff");
    return true; // Continue processing
});
```

### Asynchronous Middleware

Asynchronous middleware allows non-blocking operations:

```cpp
router.use_async([](auto& ctx, auto next) {
    // Asynchronous database check
    check_database_async(ctx.request.header("Authorization"), [ctx, next](bool valid, std::string user_id) {
        if (valid) {
            // Store user ID in context for later use
            ctx.set<std::string>("user_id", user_id);
            next(true); // Continue processing
        } else {
            ctx.response.status_code = qb::http::HTTP_STATUS_UNAUTHORIZED;
            ctx.response.body() = "Invalid credentials";
            ctx.session << ctx.response;
            next(false); // Stop processing
        }
    });
});
```

### Middleware Chaining

Middleware is executed in the order it's registered:

```cpp
// Chain multiple middleware functions for specific routes
router.GET("/protected",
    // First middleware: Authentication check
    [](auto& ctx) {
        if (!ctx.has_header("Authorization")) {
            ctx.response.status_code = qb::http::HTTP_STATUS_UNAUTHORIZED;
            ctx.session << ctx.response;
            return false;
        }
        return true;
    },
    // Second middleware: Authorization check
    [](auto& ctx) {
        auto auth = ctx.request.header("Authorization");
        if (!is_admin(auth)) {
            ctx.response.status_code = qb::http::HTTP_STATUS_FORBIDDEN;
            ctx.session << ctx.response;
            return false;
        }
        return true;
    },
    // Final handler
    [](auto& ctx) {
        ctx.response.body() = "Protected content";
        ctx.session << ctx.response;
    }
);
```

### Middleware Cancellation

A middleware can decide to stop the chain and handle the response:

```cpp
router.use_async([](auto& ctx, auto next) {
    auto cache_key = "cache:" + ctx.path();
    
    check_cache_async(cache_key, [ctx, next](bool cache_hit, std::string cached_response) {
        if (cache_hit) {
            // Serve from cache
            ctx.response.body() = cached_response;
            ctx.response.add_header("X-Cache", "HIT");
            ctx.session << ctx.response;
            next(false); // Stop processing - already handled
        } else {
            // Continue to generate a fresh response
            ctx.set<std::string>("cache_key", cache_key);
            next(true);
        }
    });
});
```

### Built-in Middleware

The HTTP module includes several built-in middleware components:

```cpp
// CORS middleware
auto cors_options = qb::http::CorsOptions()
    .origins({"https://example.com"})
    .methods({"GET", "POST", "PUT", "DELETE"})
    .headers({"Content-Type", "Authorization"})
    .credentials(true);
router.use(qb::http::middleware::cors(cors_options));

// Rate limiting middleware
router.use(qb::http::middleware::rate_limit(100, 60)); // 100 requests per minute

// Request validation middleware
router.use(qb::http::middleware::validate_json({
    {"name", qb::http::validator::type::string()},
    {"email", qb::http::validator::type::email()},
    {"age", qb::http::validator::type::integer().minimum(18)}
}));

// Authentication middleware
router.use(auth_manager.authenticate<Router>());

// Logging middleware
router.use(qb::http::middleware::logging());

// Error handling middleware
router.use(qb::http::middleware::error_handler());
```

## Authentication and Authorization

The HTTP module includes a comprehensive authentication and authorization system.

### Auth Manager

```cpp
// Configure authentication options
qb::http::AuthOptions options;
options.secret_key("my-secure-secret-key")
       .algorithm(qb::http::AuthOptions::Algorithm::HMAC_SHA256)
       .token_expiration(std::chrono::hours(24))
       .token_issuer("my-api")
       .token_audience("my-app");
       
// Create the authentication manager
qb::http::AuthManager auth_manager(options);
```

### User Authentication

```cpp
// Create a user object
qb::http::AuthUser user;
user.id = "12345";
user.username = "john.doe";
user.roles = {"user", "admin"};
user.metadata["email"] = "john.doe@example.com";

// Generate a JWT token
std::string token = auth_manager.generate_token(user);

// Verify and decode a token
auto result = auth_manager.verify_token(token);
if (result) {
    auto decoded_user = result.value();
    std::cout << "User ID: " << decoded_user.id << std::endl;
    std::cout << "Username: " << decoded_user.username << std::endl;
}

// Add authentication middleware
router.use(auth_manager.authenticate<Router>());

// Access the authenticated user in a route handler
router.GET("/profile", [](auto& ctx) {
    const auto& user = ctx.get<qb::http::AuthUser>("user");
    
    qb::json::Object profile;
    profile["id"] = user.id;
    profile["username"] = user.username;
    profile["email"] = user.metadata.at("email");
    
    ctx.response.body() = profile;
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

// Route with custom authorization logic
router.GET("/resources/:id",
    [](auto& ctx) {
        const auto& user = ctx.get<qb::http::AuthUser>("user");
        auto resource_id = ctx.param("id");
        
        if (!user_owns_resource(user.id, resource_id)) {
            ctx.response.status_code = qb::http::HTTP_STATUS_FORBIDDEN;
            ctx.response.body() = "Access denied";
            ctx.session << ctx.response;
            return false;
        }
        return true;
    },
    resourceHandler
);
```

## Validation

The HTTP module includes a robust validation system for requests.

### JSON Schema Validation

```cpp
// Define a JSON schema for user creation
auto user_schema = qb::http::validation::json_schema({
    {"name", qb::http::validator::type::string().required()},
    {"email", qb::http::validator::type::email().required()},
    {"age", qb::http::validator::type::integer().minimum(18).required()},
    {"address", qb::http::validator::type::object({
        {"street", qb::http::validator::type::string().required()},
        {"city", qb::http::validator::type::string().required()},
        {"country", qb::http::validator::type::string().required()},
        {"postal_code", qb::http::validator::type::string()}
    })},
    {"tags", qb::http::validator::type::array().items(
        qb::http::validator::type::string()
    )}
});

// Apply validation middleware to a route
router.POST("/users", 
    qb::http::middleware::validate_json(user_schema),
    [](auto& ctx) {
        // The request body is already validated
        auto json = ctx.request.body().as<qb::json::Value>();
        
        // Process the validated data
        std::string name = json["name"].as<std::string>();
        std::string email = json["email"].as<std::string>();
        int age = json["age"].as<int>();
        
        ctx.response.status_code = qb::http::HTTP_STATUS_CREATED;
        ctx.response.body() = "User created";
        ctx.session << ctx.response;
    }
);
```

### Query Parameter Validation

```cpp
// Define validation rules for query parameters
auto search_params = qb::http::validation::query_validator({
    {"q", qb::http::validator::type::string().required()},
    {"page", qb::http::validator::type::integer().minimum(1).default_value(1)},
    {"limit", qb::http::validator::type::integer().between(1, 100).default_value(20)},
    {"sort", qb::http::validator::type::string().one_of({"asc", "desc"}).default_value("asc")},
    {"filters", qb::http::validator::type::array()}
});

// Apply validation middleware to a route
router.GET("/search", 
    qb::http::middleware::validate_query(search_params),
    [](auto& ctx) {
        // Access validated and normalized query parameters
        auto& query = ctx.get<qb::http::validation::QueryParams>("query_params");
        
        std::string search_term = query.get<std::string>("q");
        int page = query.get<int>("page");
        int limit = query.get<int>("limit");
        std::string sort = query.get<std::string>("sort");
        
        // Perform search with validated parameters
        ctx.response.body() = "Search results for: " + search_term;
        ctx.session << ctx.response;
    }
);
```

### Custom Validators

```cpp
// Create a custom validator for UUIDs
auto uuid_validator = qb::http::validator::type::string()
    .pattern("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    .message("Must be a valid UUID");

// Create a custom validator for dates
auto date_validator = qb::http::validator::type::string()
    .custom([](const std::string& value) {
        // Custom validation logic
        try {
            auto date = qb::http::Date::from_string(value);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    })
    .message("Must be a valid date in ISO format");

// Apply custom validators
router.POST("/events", 
    qb::http::middleware::validate_json({
        {"id", uuid_validator.required()},
        {"name", qb::http::validator::type::string().required()},
        {"date", date_validator.required()}
    }),
    eventHandler
);
```

## Advanced Features

### CORS Management

```cpp
// Simple CORS configuration for development
router.enable_dev_cors();

// Custom CORS configuration
qb::http::CorsOptions cors_options;
cors_options.origins({"https://app.example.com", "https://admin.example.com"})
           .methods({"GET", "POST", "PUT", "DELETE"})
           .headers({"Content-Type", "Authorization", "X-Requested-With"})
           .expose({"X-Total-Count", "X-Rate-Limit"})
           .credentials(true)
           .max_age(3600);

router.enable_cors(cors_options);

// CORS with regex patterns for origins
router.enable_cors_with_patterns(
    {"^https://.*\\.example\\.com$", "^https://partner\\.org$"},
    {"GET", "POST", "PUT", "DELETE"},
    {"Content-Type", "Authorization"},
    true
);
```

### Rate Limiting

```cpp
// Global rate limiting
router.configure_rate_limit(1000, 60); // 1000 requests per minute

// Route-specific rate limiting
router.POST("/login", 
    qb::http::middleware::rate_limit(10, 60, "ip"), // 10 login attempts per minute per IP
    loginHandler
);

// Resource-specific rate limiting
router.PUT("/users/:id",
    qb::http::middleware::rate_limit(5, 60, [](auto& ctx) {
        // Use the user ID as the rate limit key
        return "user:" + ctx.param("id");
    }),
    updateUserHandler
);

// Custom rate limit response
auto rate_limiter = qb::http::middleware::rate_limit(100, 60)
    .on_limit_exceeded([](auto& ctx) {
        ctx.response.status_code = qb::http::HTTP_STATUS_TOO_MANY_REQUESTS;
        ctx.response.add_header("Retry-After", "60");
        
        qb::json::Object error;
        error["error"] = "rate_limit_exceeded";
        error["message"] = "Too many requests";
        error["retry_after"] = 60;
        
        ctx.response.body() = error;
        ctx.session << ctx.response;
    });

router.use(rate_limiter);
```

### File Transfers

```cpp
// File download handler
router.GET("/files/:filename", [](auto& ctx) {
    auto filename = ctx.param("filename");
    auto file_path = "uploads/" + filename;
    
    // Check if file exists
    if (!file_exists(file_path)) {
        ctx.response.status_code = qb::http::HTTP_STATUS_NOT_FOUND;
        ctx.session << ctx.response;
        return;
    }
    
    // Set appropriate headers
    ctx.response.add_header("Content-Type", get_mime_type(filename));
    ctx.response.add_header("Content-Disposition", "attachment; filename=\"" + filename + "\"");
    
    // Stream the file
    auto file = qb::io::transport::File::open(file_path);
    if (file) {
        ctx.response.body().raw() = file.read_all();
    }
    
    ctx.session << ctx.response;
});

// File upload handler with multipart
router.POST("/upload", [](auto& ctx) {
    if (ctx.request.content_type() && ctx.request.content_type().find("multipart/form-data") != std::string::npos) {
        auto multipart = ctx.request.body().as<qb::http::Multipart>();
        
        std::vector<std::string> uploaded_files;
        
        for (const auto& part : multipart.parts()) {
            auto filename = part.get_filename();
            
            if (!filename.empty()) {
                // Create upload directory if it doesn't exist
                std::filesystem::create_directories("uploads");
                
                // Generate a unique filename
                auto unique_filename = generate_unique_filename(filename);
                auto file_path = "uploads/" + unique_filename;
                
                // Save file
                std::ofstream file(file_path, std::ios::binary);
                file.write(part.body().raw().data(), part.body().raw().size());
                
                uploaded_files.push_back(unique_filename);
            }
        }
        
        // Return information about uploaded files
        qb::json::Object response;
        response["success"] = true;
        response["files"] = uploaded_files;
        
        ctx.response.body() = response;
    } else {
        ctx.response.status_code = qb::http::HTTP_STATUS_BAD_REQUEST;
        ctx.response.body() = "Expected multipart/form-data";
    }
    
    ctx.session << ctx.response;
});
```

### Content Compression

```cpp
// Enable compression for responses
router.GET("/large-data", [](auto& ctx) {
    // Generate a large response
    std::string large_data = generate_large_data();
    
    // Check if client supports compression
    auto accept_encoding = ctx.request.header("Accept-Encoding");
    if (accept_encoding.find("gzip") != std::string::npos) {
        // Compress the response
        auto compressed = qb::io::compression::gzip_compress(large_data);
        
        // Set appropriate headers
        ctx.response.add_header("Content-Encoding", "gzip");
        ctx.response.body().raw() = std::move(compressed);
    } else {
        // Send uncompressed
        ctx.response.body() = large_data;
    }
    
    ctx.session << ctx.response;
});

// Automatic compression middleware
router.use([](auto& ctx) {
    // Only hook the response, not modifying the request
    ctx.on_response([](auto& response, auto& request) {
        // Check if response is large enough to warrant compression
        if (response.body().raw().size() > 1024) {
            // Check if client supports compression
            auto accept_encoding = request.header("Accept-Encoding");
            
            if (accept_encoding.find("gzip") != std::string::npos) {
                // Compress with gzip
                auto compressed = qb::io::compression::gzip_compress(response.body().raw());
                
                // Set headers
                response.add_header("Content-Encoding", "gzip");
                response.body().raw() = std::move(compressed);
            } else if (accept_encoding.find("deflate") != std::string::npos) {
                // Compress with deflate
                auto compressed = qb::io::compression::deflate_compress(response.body().raw());
                
                // Set headers
                response.add_header("Content-Encoding", "deflate");
                response.body().raw() = std::move(compressed);
            }
        }
    });
    
    return true;
});
```

## Examples

### Basic HTTP Server

```cpp
#include <qb/http.h>

class MyHTTPServer {
public:
    void run() {
        qb::http::use<MyHTTPServer>::server<Session> server;
        
        // Configure router
        server.router()
            .GET("/", [](auto& ctx) {
                ctx.response.body() = "<h1>Welcome to QB HTTP Server</h1>";
                ctx.response.add_header("Content-Type", "text/html");
                ctx.session << ctx.response;
            })
            .GET("/api/users", [](auto& ctx) {
                qb::json::Array users = {
                    qb::json::Object{{"id", 1}, {"name", "Alice"}},
                    qb::json::Object{{"id", 2}, {"name", "Bob"}},
                    qb::json::Object{{"id", 3}, {"name", "Charlie"}}
                };
                
                ctx.response.add_header("Content-Type", "application/json");
                ctx.response.body() = users;
                ctx.session << ctx.response;
            })
            .GET("/api/users/:id", [](auto& ctx) {
                auto id = ctx.param("id");
                
                qb::json::Object user;
                user["id"] = std::stoi(id);
                user["name"] = "User " + id;
                
                ctx.response.add_header("Content-Type", "application/json");
                ctx.response.body() = user;
                ctx.session << ctx.response;
            });
            
        // Start the server
        server.bind("0.0.0.0", 8080);
        std::cout << "Server starting on http://localhost:8080" << std::endl;
        server.listen();
        
        // Run the event loop
        qb::io::async::run();
    }
    
private:
    using Session = qb::http::use<MyHTTPServer>::session<MyHTTPServer>;
};

int main() {
    MyHTTPServer server;
    server.run();
    return 0;
}
```

### REST API with Authentication

```cpp
#include <qb/http.h>
#include <qb/json.h>
#include <unordered_map>

class RESTfulAPI {
public:
    void run() {
        // Configure authentication
        qb::http::AuthOptions auth_options;
        auth_options.secret_key("secret-key-change-in-production")
                  .algorithm(qb::http::AuthOptions::Algorithm::HMAC_SHA256)
                  .token_expiration(std::chrono::hours(24));
        
        _auth_manager = std::make_unique<qb::http::AuthManager>(auth_options);
        
        // Configure server
        qb::http::use<RESTfulAPI>::server<Session> server;
        auto& router = server.router();
        
        // Middleware for all routes
        router.use([](auto& ctx) {
            // Add common headers
            ctx.response.add_header("Server", "QB HTTP");
            return true;
        });
        
        // Enable CORS
        qb::http::CorsOptions cors_options;
        cors_options.origins({"*"})
                  .methods({"GET", "POST", "PUT", "DELETE", "OPTIONS"})
                  .headers({"Content-Type", "Authorization"})
                  .credentials(true);
        router.enable_cors(cors_options);
        
        // Public routes
        router.POST("/api/login", [this](auto& ctx) {
            auto json = ctx.request.body().as<qb::json::Value>();
            std::string username = json["username"].as<std::string>();
            std::string password = json["password"].as<std::string>();
            
            // Validate credentials (simplified)
            if (username == "admin" && password == "password") {
                // Create user and generate token
                qb::http::AuthUser user;
                user.id = "1";
                user.username = username;
                user.roles = {"admin"};
                
                std::string token = _auth_manager->generate_token(user);
                
                qb::json::Object response;
                response["token"] = token;
                response["user"] = qb::json::Object{
                    {"id", user.id},
                    {"username", user.username},
                    {"roles", user.roles}
                };
                
                ctx.response.add_header("Content-Type", "application/json");
                ctx.response.body() = response;
            } else {
                ctx.response.status_code = qb::http::HTTP_STATUS_UNAUTHORIZED;
                ctx.response.body() = qb::json::Object{
                    {"error", "Invalid credentials"}
                };
            }
            
            ctx.session << ctx.response;
        });
        
        // Protected API routes
        auto api = router.group("/api");
        
        // Add authentication middleware to API group
        api.use(_auth_manager->authenticate<decltype(router)>());
        
        // Define API routes
        api.GET("/users", [](auto& ctx) {
            qb::json::Array users = {
                qb::json::Object{{"id", 1}, {"name", "Alice"}},
                qb::json::Object{{"id", 2}, {"name", "Bob"}},
                qb::json::Object{{"id", 3}, {"name", "Charlie"}}
            };
            
            ctx.response.add_header("Content-Type", "application/json");
            ctx.response.body() = users;
            ctx.session << ctx.response;
        });
        
        api.GET("/profile", [](auto& ctx) {
            const auto& user = ctx.get<qb::http::AuthUser>("user");
            
            qb::json::Object profile;
            profile["id"] = user.id;
            profile["username"] = user.username;
            profile["roles"] = user.roles;
            
            ctx.response.add_header("Content-Type", "application/json");
            ctx.response.body() = profile;
            ctx.session << ctx.response;
        });
        
        // Admin-only routes
        auto admin = api.group("/admin");
        admin.use(_auth_manager->authorize<decltype(router)>({"admin"}));
        
        admin.GET("/stats", [](auto& ctx) {
            qb::json::Object stats;
            stats["users"] = 1000;
            stats["active"] = 250;
            stats["cpu_usage"] = 42.5;
            stats["memory_usage"] = 512;
            
            ctx.response.add_header("Content-Type", "application/json");
            ctx.response.body() = stats;
            ctx.session << ctx.response;
        });
        
        // Start the server
        server.bind("0.0.0.0", 8080);
        std::cout << "API server starting on http://localhost:8080" << std::endl;
        server.listen();
        
        // Run the event loop
        qb::io::async::run();
    }
    
private:
    using Session = qb::http::use<RESTfulAPI>::session<RESTfulAPI>;
    std::unique_ptr<qb::http::AuthManager> _auth_manager;
};

int main() {
    RESTfulAPI api;
    api.run();
    return 0;
}
```

### HTTP Client

```cpp
#include <qb/http.h>
#include <iostream>

void async_http_client() {
    // Create a request
    qb::http::Request req("https://api.example.com/users");
    
    // Add headers
    req.add_header("Authorization", "Bearer token123");
    req.add_header("Accept", "application/json");
    
    // Send asynchronously
    qb::http::GET(req, [](qb::http::async::Reply&& reply) {
        if (reply.response.status_code == qb::http::HTTP_STATUS_OK) {
            // Parse JSON response
            auto json = reply.response.body().as<qb::json::Value>();
            
            // Process data
            std::cout << "Users: " << json.size() << std::endl;
            for (const auto& user : json.as<qb::json::Array>()) {
                std::cout << "User: " << user["name"].as<std::string>() << std::endl;
            }
        } else {
            std::cout << "Error: " << reply.response.status_code << std::endl;
            if (!reply.response.body().raw().empty()) {
                std::cout << "Message: " << reply.response.body().as<std::string>() << std::endl;
            }
        }
    });
    
    // Run the event loop
    qb::io::async::run();
}

void sync_http_client() {
    // Create a request
    qb::http::Request req("https://api.example.com/users/1");
    
    // Add headers
    req.add_header("Accept", "application/json");
    
    // Send synchronously
    auto response = qb::http::GET(req);
    
    if (response.status_code == qb::http::HTTP_STATUS_OK) {
        // Parse JSON response
        auto json = response.body().as<qb::json::Value>();
        
        // Process data
        std::cout << "User: " << json["name"].as<std::string>() << std::endl;
        std::cout << "Email: " << json["email"].as<std::string>() << std::endl;
    } else {
        std::cout << "Error: " << response.status_code << std::endl;
    }
}

void post_data() {
    // Create a request
    qb::http::Request req("https://api.example.com/users");
    
    // Add headers
    req.add_header("Content-Type", "application/json");
    req.add_header("Authorization", "Bearer token123");
    
    // Set JSON body
    qb::json::Object user;
    user["name"] = "John Doe";
    user["email"] = "john@example.com";
    user["age"] = 30;
    
    req.body() = user;
    
    // Send request
    auto response = qb::http::POST(req);
    
    if (response.status_code == qb::http::HTTP_STATUS_CREATED) {
        std::cout << "User created successfully" << std::endl;
        
        // Get the new user ID from the response
        auto json = response.body().as<qb::json::Value>();
        std::cout << "New user ID: " << json["id"].as<std::string>() << std::endl;
    } else {
        std::cout << "Error: " << response.status_code << std::endl;
    }
}

int main() {
    std::cout << "Asynchronous HTTP GET:" << std::endl;
    async_http_client();
    
    std::cout << "\nSynchronous HTTP GET:" << std::endl;
    sync_http_client();
    
    std::cout << "\nHTTP POST:" << std::endl;
    post_data();
    
    return 0;
}
```

## API Reference

For a complete API reference, consult the header files:

- **http.h**: Main entry point of the module
- **request.h**: HTTP request handling
- **response.h**: HTTP response handling
- **headers.h**: HTTP header management
- **body.h**: Message body processing
- **cookie.h**: Cookie management
- **date.h**: HTTP date handling
- **multipart.h**: Multipart/form-data processing
- **routing/**: Routing system components
- **auth/**: Authentication and authorization
- **validation/**: Request validation
- **middleware/**: Built-in middleware components

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
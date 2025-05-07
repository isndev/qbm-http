# OpenAPI/Swagger Integration

The qbm-http library provides integration with OpenAPI 3.0 (formerly known as Swagger) to automatically generate API documentation from your routes. This makes it easy to document your REST APIs and provide interactive documentation for developers.

## Overview

The OpenAPI integration consists of three main components:

1. **Route Metadata** - Attach documentation to your routes
2. **Document Generator** - Build OpenAPI specifications from your router
3. **Swagger UI Middleware** - Serve interactive documentation

## Basic Example

Here's a minimal example of how to use the OpenAPI integration:

```cpp
#include <http/http.h>
#include <http/openapi/document.h>
#include <http/middleware/swagger.h>

using namespace qb::http;
using namespace qb::http::openapi;

int main() {
    // Create a router
    Router<WebSocketSession> router;
    
    // Set up some routes
    router.get("/users", [](auto& ctx) {
        ctx.response.json({{"users", {}}});
    }).metadata()  // Add OpenAPI metadata
        .withSummary("List users")
        .withDescription("Returns a list of all users")
        .withTag("Users");
    
    // Create an OpenAPI document generator
    DocumentGenerator openapi("My API", "1.0.0", "API Documentation");
    
    // Generate the documentation from the router
    openapi.processRouter(router);
    
    // Add Swagger UI middleware
    router.use(swagger_middleware<WebSocketSession>(openapi, "/api-docs"));
    
    // Start the server
    start_server(router, 8080);
    
    return 0;
}
```

With this setup, your API will be documented at `/api-docs` with the OpenAPI JSON spec available at `/api-docs/openapi.json`.

## Detailed Usage

### Adding Metadata to Routes

Routes can be documented with detailed metadata:

```cpp
router.get("/users/:id", [](auto& ctx) {
    // Handler implementation
}).metadata()
    .withSummary("Get user by ID")
    .withDescription("Returns a user by their ID")
    .withTag("Users")
    .withResponse(200, "User found", {
        {"type", "object"},
        {"properties", {
            {"id", {{"type", "integer"}}},
            {"name", {{"type", "string"}}}
        }}
    })
    .withResponse(404, "User not found")
    .withPathParam("id", "User ID", {{"type", "integer"}, {"minimum", 1}});
```

### Route Groups and Controllers

Route groups and controllers can have associated OpenAPI tags:

```cpp
// Route group with tag
auto& userGroup = router.group("/users");
userGroup.withOpenApiTag("Users");

userGroup.get("/", [](auto& ctx) {
    // Handler implementation
});

// Controller with tag
class ProductController : public Controller<WebSocketSession> {
public:
    ProductController() : Controller("/products") {
        withOpenApiTag("Products");
        
        router().get("/", [](auto& ctx) {
            // Handler implementation
        });
    }
};

router.controller<ProductController>();
```

### Document Generator Configuration

The `DocumentGenerator` class provides methods to configure the OpenAPI document:

```cpp
DocumentGenerator openapi("My API", "1.0.0", "API Description");

// Set basic info
openapi.setContact("API Support", "support@example.com", "https://example.com/support");
openapi.setLicense("MIT", "https://opensource.org/licenses/MIT");

// Add servers
openapi.addServer("https://api.example.com/v1", "Production");
openapi.addServer("https://staging-api.example.com/v1", "Staging");

// Add security schemes
openapi.addBearerAuth("bearerAuth", "bearer", "JWT");
openapi.addApiKeyAuth("apiKey", "header", "X-API-Key");

// Add tags
openapi.addTag("Users", "User management endpoints");
openapi.addTag("Products", "Product endpoints");

// Add custom schema definitions
openapi.addSchemaDefinition("User", {
    {"type", "object"},
    {"properties", {
        {"id", {{"type", "integer"}}},
        {"name", {{"type", "string"}}},
        {"email", {{"type", "string"}, {"format", "email"}}}
    }}
});
```

### Swagger UI Middleware

The Swagger UI middleware serves the OpenAPI specification and an interactive UI:

```cpp
// Basic usage
router.use(swagger_middleware<WebSocketSession>(openapi));

// Customized paths
router.use(swagger_middleware<WebSocketSession>(
    openapi,            // DocumentGenerator instance
    "/documentation",   // Base path (default: /api-docs)
    "/spec.json"        // Spec path (default: /openapi.json)
));
```

## Schema Definition

Schemas for request/response bodies and parameters follow the OpenAPI/JSON Schema format:

```cpp
// Simple types
qb::json schema = {{"type", "string"}};

// Object with properties
qb::json schema = {
    {"type", "object"},
    {"required", {"name", "email"}},
    {"properties", {
        {"id", {{"type", "integer"}}},
        {"name", {{"type", "string"}, {"minLength", 1}}},
        {"email", {{"type", "string"}, {"format", "email"}}},
        {"age", {{"type", "integer"}, {"minimum", 18}, {"maximum", 150}}},
        {"address", {
            {"type", "object"},
            {"properties", {
                {"street", {{"type", "string"}}},
                {"city", {{"type", "string"}}},
                {"country", {{"type", "string"}}}
            }}
        }}
    }}
};

// Array of items
qb::json schema = {
    {"type", "array"},
    {"items", {
        {"type", "object"},
        {"properties", {
            {"id", {{"type", "integer"}}},
            {"name", {{"type", "string"}}}
        }}
    }}
};
```

## Advanced Features

### Custom Path Parameters

By default, path parameters are detected from route paths (e.g., `/users/:id`). You can provide more specific documentation:

```cpp
route.metadata()
    .withPathParam("id", "User ID", {{"type", "integer"}, {"minimum", 1}});
```

### Request Body Documentation

```cpp
route.metadata()
    .withRequestBody({
        {"type", "object"},
        {"required", {"name"}},
        {"properties", {
            {"name", {{"type", "string"}}},
            {"email", {{"type", "string"}, {"format", "email"}}},
            {"phone", {{"type", "string"}, {"pattern", "^\\\\+[0-9]{10,15}$"}}}
        }}
    }, "User information");
```

### Custom Response Headers

Response headers are defined as part of the response object within the OpenAPI specification. For example, when using `withResponse`:

```cpp
route.metadata()
    .withResponse(200, "Successful operation with custom header", 
        qb::json::object(), // Optional response body schema
        "application/json",
        {{ "X-Rate-Limit-Remaining", {
            {"description", "Requests remaining for the current window"},
            {"schema", {{"type", "integer"}}}
        }}}
    );
```

### Security Requirements

Security requirements for an operation are typically defined by adding a `security` field to the operation object in the OpenAPI specification. This field is an array of security requirement objects, where each object maps security scheme names (defined in `components.securitySchemes` via `generator.addBearerAuth()`, etc.) to a list of scope names required for execution (empty for OAuth2 if no specific scopes, or for API keys/HTTP auth).

The `DocumentGenerator` has a method `extractSecurityRequirements` (currently a TODO in implementation) intended to help automate this from middleware chains. For manual specification, you would modify the JSON generated by `processSimpleRoute` or by directly manipulating the `_paths` member of the `DocumentGenerator` before final JSON generation.

Example of a security requirement in the OpenAPI JSON for an operation:
```json
"security": [
  { "bearerAuth": [] }, 
  { "apiKeyAuth": [] }
]
```

## Swagger UI Assets

The current implementation includes a stub for the Swagger UI assets. In a production environment, you should:

1. Download the latest Swagger UI from the [official repository](https://github.com/swagger-api/swagger-ui)
2. Use a tool like [incbin](https://github.com/graphitemaster/incbin) to embed the assets
3. Update the `swagger_ui.cpp` file with the real asset data

## Conclusion

The OpenAPI integration makes it easy to document your API without maintaining separate documentation that can get out of sync. By adding metadata directly to your routes, you ensure that the documentation is always up-to-date with your implementation. 
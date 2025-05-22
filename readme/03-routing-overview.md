# 03: Routing Overview

Effective HTTP routing is crucial for any web service or API. The `qb::http` module provides a powerful and flexible routing system built around the `qb::http::Router` class. This system allows you to define how incoming HTTP requests are directed to specific handler logic based on their URI path and HTTP method.

## The `qb::http::Router`

The `qb::http::Router<SessionType>` is the central component for defining your application's routes. It internally uses a `qb::http::RadixTree` for efficient path matching.

Key responsibilities of the Router include:

1.  **Route Definition**: Provides a fluent API (e.g., `router.get("/path", handler)`) to associate HTTP methods and path patterns with specific handler logic.
2.  **Middleware Management**: Allows application of middleware at global, group, or controller levels.
3.  **Compilation**: Before processing requests, the router compiles all defined routes, groups, and controllers into an optimized internal structure (the Radix Tree). This step resolves middleware chains and prepares handlers for execution.
4.  **Request Dispatching**: For each incoming request, the router attempts to match its path and method against the compiled routes. If a match is found, it creates a `qb::http::Context` for the request and dispatches it to the appropriate handler chain.
5.  **Error Handling**: Manages default and custom handlers for "404 Not Found" and general processing errors.

## Path Matching

The router matches incoming request paths against defined route patterns. It supports three main types of path segments:

1.  **Static Segments**: These are literal strings that must match exactly. For example, in a route `/users/list`, `users` and `list` are static segments.

2.  **Parameterized Segments**: These segments start with a colon (`:`) followed by a parameter name (e.g., `/:id`, `/:category`). They capture the actual value from the corresponding segment in the request URI and make it available to the handler via `ctx->path_param("name")`.
    -   Example: A route `GET /products/:productId` will match `GET /products/123`, and `productId` will be `"123"`.

3.  **Wildcard Segments**: These segments start with an asterisk (`*`) followed by a parameter name (e.g., `/*filepath`). They match any sequence of characters for the rest of the path, including multiple segments containing slashes. Wildcard segments **must be the last segment** in a route pattern.
    -   Example: A route `GET /files/*path` will match `GET /files/documents/report.pdf`, and `path` will be `"documents/report.pdf"`.
    -   It can also match an empty path part, e.g., `/files/*path` matching `/files/` would result in `path` being an empty string.

### Matching Precedence

When multiple route patterns could potentially match a request path, the router follows a specific precedence:

1.  **Static segments** have the highest priority. If a static segment matches, it's chosen over a parameterized or wildcard segment at the same position.
    -   `/users/active` will be chosen over `/users/:status` for a request to `/users/active`.
2.  **Parameterized segments** have the next priority, over wildcard segments.
    -   `/api/:version/data` will be chosen over `/api/*path` for a request to `/api/v1/data`.
3.  **Wildcard segments** have the lowest priority and act as a catch-all for the remainder of the path.

### Path Normalization

-   **Trailing Slashes**: The router generally treats paths with and without a trailing slash as equivalent for matching static or parameterized routes (e.g., `/users` and `/users/` might match the same route definition for `/users`). This is due to how path segments are typically split and normalized before radix tree insertion.
-   **Consecutive Slashes**: Multiple consecutive slashes in a path (e.g., `/foo///bar`) are usually collapsed into a single slash (`/foo/bar`) during path processing.

## Path Parameters

When a route with parameterized or wildcard segments is matched, the values extracted from the request URI path are stored in a `qb::http::PathParameters` object. This object is then made available within the `qb::http::Context` passed to your handlers and middleware.

```cpp
// Example: Accessing path parameters in a handler
router.get("/books/:genre/page/:pageNumber", [](auto ctx) {
    std::string genre = ctx->path_param("genre");
    std::string page_str = ctx->path_param("pageNumber");
    // Potentially convert page_str to an integer

    ctx->response().body() = "Genre: " + genre + ", Page: " + page_str;
    ctx->complete();
});

// Request to /books/fiction/page/2
// genre will be "fiction"
// page_str will be "2"
```

Path parameter names are defined in the route pattern (e.g., `:genre`, `*filepath`). The `PathParameters` object within the `Context` provides a `get(name)` method which returns an `std::optional<std::string_view>` (or similar, depending on `PathParameters` internal storage/API, which uses `std::string` for values). The `Context::path_param(name, default_value)` provides a convenient way to get the string value directly or a default if not found.

Path parameters are automatically URL-decoded before being stored in `PathParameters` if they were URL-encoded in the request path (e.g., a segment like `books%20and%20authors` matching `/:category` would result in `category` being `"books and authors"`).

## ASCII Diagram: Route Matching Logic (Conceptual Radix Tree)

```
        /
       |
    (static)
    users --:id -- (static) -- profile  (Handler for GET /users/:id/profile)
       |
    (static)
    posts --:postId                 (Handler for GET /posts/:postId)
       |
    (wildcard)
    *filepath                       (Handler for GET /*filepath)

Incoming Request: GET /users/alice/profile

1. Match "/" (root)
2. Next segment "users": Found static child "users". Current node = "users".
3. Next segment "alice": No static child "alice". Check for param child ":id". Found.
   - Store param: id = "alice". Current node = ":id" node.
4. Next segment "profile": Found static child "profile". Current node = "profile" node.
5. Path exhausted. Check for GET handler at "profile" node. Found.
6. Execute handler with params {"id": "alice"}.
```

This overview introduces the basic mechanics of how the `qb::http::Router` handles incoming requests. The following sections will delve deeper into defining various types of routes, structuring them with groups and controllers, and applying middleware.

Previous: [HTTP Message Body: Deep Dive](./02-body-deep-dive.md)
Next: [Defining Routes](./04-defining-routes.md)

---
Return to [Index](./README.md) 
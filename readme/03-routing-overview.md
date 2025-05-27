# 03: Routing Overview

Effective HTTP routing is crucial for any web service or API. The `qb::http` module provides a powerful and flexible routing system built around the `qb::http::Router` class. This system allows you to define how incoming HTTP requests are directed to specific handler logic based on their URI path and HTTP method.

At its core, the routing mechanism relies on `qb::http::RouterCore`, which manages a specialized data structure called a `qb::http::RadixTree`. This tree is optimized for extremely fast path matching by breaking down URL paths into segments and storing routes in a prefix-based manner. When you define routes using the `Router` API, you are constructing a hierarchy of `IHandlerNode` objects (routes, groups, controllers). During the `router.compile()` step, `RouterCore` traverses this hierarchy, resolves middleware chains, and populates the `RadixTree` with the final, executable task chains for each endpoint.

## The `qb::http::Router`

The `qb::http::Router<SessionType>` is the central component for defining your application's routes. It internally uses a `qb::http::RadixTree` for efficient path matching.

Key responsibilities of the Router include:

1.  **Route Definition**: Provides a fluent API (e.g., `router.get("/path", handler)`) to associate HTTP methods and path patterns with specific handler logic.
2.  **Middleware Management**: Allows application of middleware at global, group, or controller levels.
3.  **Compilation**: Before processing requests, the router compiles all defined routes, groups, and controllers into an optimized internal structure (the `RadixTree` managed by `RouterCore`). This step resolves middleware chains and prepares handlers for execution.
4.  **Request Dispatching**: For each incoming request, `RouterCore` attempts to match its path and method against the compiled `RadixTree`. If a match is found, it creates a `qb::http::Context` for the request and dispatches it to the appropriate handler chain.
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

When a route with parameterized segments (e.g., `/:id`) or wildcard segments (e.g., `/*filepath`) is matched by the `RadixTree`, the values extracted from the request URI path are automatically URL-decoded and stored in a `qb::http::PathParameters` object. This object is then made available within the `qb::http::Context` passed to your handlers and middleware.

-   **Access via `Context`**: You can retrieve a specific path parameter by its name using `ctx->path_param("name", "default_value_if_not_found")` or access the entire `PathParameters` object via `ctx->path_parameters()`.
-   **Parameter Names**: The names are derived from your route definition (e.g., `id` from `/:id`, `filepath` from `/*filepath`).

```cpp
// Example: Accessing path parameters in a handler
router.get("/books/:genre/page/:pageNumber", [](auto ctx) {
    // Using ctx->path_param() for convenient access with a default
    std::string genre = ctx->path_param("genre", "unknown");
    std::string page_str = ctx->path_param("pageNumber", "1");
    
    // Alternatively, access the PathParameters object directly:
    // const qb::http::PathParameters& params = ctx->path_parameters();
    // std::optional<std::string_view> genre_sv_opt = params.get("genre");
    // std::optional<std::string_view> page_sv_opt = params.get("pageNumber");

    // Potentially convert page_str to an integer
    int page_num = 1;
    try {
        if (!page_str.empty()) page_num = std::stoi(page_str);
    } catch (const std::exception& e) { /* handle conversion error */ }

    ctx->response().body() = "Genre: " + genre + ", Page: " + std::to_string(page_num);
    ctx->complete();
});

// Request to /books/fiction/page/2
// genre will be "fiction"
// page_str will be "2"
```

Path parameters are automatically URL-decoded. For instance, if a request path is `/notes/My%20Document` and the route is `/notes/:title`, `ctx->path_param("title")` will yield `"My Document"`.

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
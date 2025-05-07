# `qbm-http`: Routing System

(`qbm/http/routing/`)

The `qbm-http` router is responsible for matching incoming HTTP requests (based on method and path) to specific handler functions or controllers.

## Core Component: `qb::http::Router<Session, String>`

(`routing/router.h`, `routing/router.tpp`)

This is the main class for defining routes and middleware.

*   **Template Parameters:**
    *   `Session`: The type representing a client connection (e.g., `MyHttpSession`).
    *   `String`: The string type used (`std::string` or `std::string_view`).
*   **Instantiation:** Typically created within your server class (e.g., one inheriting from `qb::http::use<...>::server`).
*   **Route Registration:** Uses HTTP method functions (`.get()`, `.post()`, `.put()`, `.del()`, etc.).

## Defining Basic Routes

Routes map an HTTP method and a path pattern to a handler.

```cpp
#include <http/http.h>

// Assume 'router' is an instance of qb::http::Router<MySession>

// GET request to the root path
router.get("/", [](TestRouter::Context& ctx) {
    ctx.response.body() = "Homepage";
    ctx.complete(); // Mark as handled and send response
});

// POST request to /users
router.post("/users", [](TestRouter::Context& ctx) {
    // Logic to create a user, potentially parsing ctx.request.body()
    ctx.response.status_code = HTTP_STATUS_CREATED;
    ctx.response.body() = "User Created";
    ctx.complete();
});

// Handling any method for a specific path (less common)
router.any("/any_method_route", [](TestRouter::Context& ctx) {
    ctx.response.body() = "Handled by ANY";
    ctx.complete();
});
```

*   **Handler Signature:** Route handlers are typically lambdas or functions taking `Context& ctx` (where `Context` is `qb::http::RouterContext<YourSessionType>`).
*   **Response:** The handler *must* eventually send a response, usually by modifying `ctx.response` and calling `ctx.complete()` or `ctx.session << ctx.response;` for synchronous handlers, or using `ctx.make_async()` and `AsyncCompletionHandler` for asynchronous ones.

## Path Parameters

Define dynamic segments in paths using the colon prefix (`:`).

```cpp
router.get("/users/:id", [](Context& ctx) {
    // Extract the 'id' parameter
    std::string user_id = ctx.param("id");
    // Use default value if parameter might be missing
    // std::string user_id = ctx.param("id", "default_id");

    ctx.response.body() = "Details for user: " + user_id;
    ctx.complete();
});

router.get("/users/:userId/posts/:postId", [](Context& ctx) {
    std::string user_id = ctx.param("userId");
    std::string post_id = ctx.param("postId");
    ctx.response.body() = "Post " + post_id + " by user " + user_id;
    ctx.complete();
});
```

*   Parameters are captured as strings.
*   Access them using `ctx.param("parameter_name")`.

## Route Groups

Organize related routes under a common prefix and apply middleware specifically to that group.

```cpp
// Create a group for API v1
auto& api_v1 = router.group("/api/v1");

// Add middleware specific to this group
api_v1.use([](Context& ctx) {
    ctx.response.add_header("X-API-Version", "1.0");
    return true; // Continue
});

// Define routes within the group (paths are relative to "/api/v1")
api_v1.get("/status", [](Context& ctx) {
    ctx.response.body() = "API v1 Status: OK";
    ctx.complete();
});

api_v1.get("/items", [](Context& ctx) {
    ctx.response.body() = "API v1 Items List";
    ctx.complete();
});

// Nested groups
auto& admin_group = api_v1.group("/admin");
admin_group.use([](Context& ctx){ /* Admin auth middleware */ return true; });
admin_group.get("/settings", [](Context& ctx){ /* ... */ ctx.complete(); });
// Full path: /api/v1/admin/settings
```

*   The path specified in `.get()`, `.post()`, etc. within a group is appended to the group's prefix.
*   Middleware added via `group.use()` applies only to routes defined within that group and its subgroups.

## Controllers

Provide class-based organization for routes, typically grouping all routes related to a specific resource.

```cpp
#include <http/http.h>

class ProductController : public qb::http::Controller<MySession> {
public:
    // Base path for all routes in this controller
    ProductController() : Controller("/products") {
        // Define routes relative to the base path

        // GET /products/
        router().get("/", [](Context& ctx) {
            ctx.response.body() = "List all products";
            ctx.complete();
        });

        // GET /products/:id
        router().get("/:id", [](Context& ctx) {
            ctx.response.body() = "Product details: " + ctx.param("id");
            ctx.complete();
        });
    }
};

// In your server setup:
// router.controller<ProductController>();
```

*   Inherit from `qb::http::Controller<YourSessionType>`.
*   Pass the base path to the `Controller` constructor.
*   Define routes in the controller's constructor using `router().get(...)` etc.
*   Register the controller with the main router using `main_router.controller<YourControllerClass>();`.

## Route Matching & Radix Tree

(`routing/radix_tree.h`, `routing/radix_tree.cpp`)

*   **Default:** The router uses a high-performance **Radix Tree** for matching static path segments and parameters.
*   **Fallback:** If Radix Tree matching fails or for more complex patterns (like regex within parameters, although not directly supported in parameters themselves), it may fall back to linear iteration and regex matching defined in `ARoute`.
*   **Optimization:** The Radix Tree significantly speeds up routing, especially with a large number of routes, compared to purely regex-based routers.
*   **Configuration:**
    *   `router.enable_radix_tree(bool)`: Enable/disable Radix Tree globally (default: enabled).
    *   `router.force_enable_radix_tree_for_method(http_method)`: Ensure Radix Tree is used for a specific method, even if few routes exist.
    *   `router.build_radix_trees()`: Manually build/rebuild trees (usually done automatically).

## Route Priorities

*   **Implicit:** Static routes generally have higher priority than routes with parameters if they could both potentially match the same path segment (e.g., `/users/profile` vs `/users/:id`). The more specific static route is usually checked first.
*   **Explicit (Groups/Controllers):** You can assign an integer priority when creating a `group()` or `controller()`. Higher numbers have higher priority.
*   **Explicit (Routes):** Individual routes can also be assigned priority: `router.get("/path", handler, priority_value);`.
*   **Ordering:** The router sorts routes within each method based on priority (descending) to ensure higher priority routes are checked first. 
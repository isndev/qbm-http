# 05: Route Groups

As your application grows, managing a flat list of routes can become cumbersome. `qb::http::RouteGroup` provides a way to organize your routes hierarchically, applying common path prefixes and middleware to a collection of related endpoints.

## Creating and Using Route Groups

A `RouteGroup` is created from an existing `Router` instance or another `RouteGroup` instance using the `group(path_prefix)` method.

-   `path_prefix`: A `std::string` that defines the common base path for all routes and subgroups defined within this group. This prefix is prepended to the paths of its children.

```cpp
#include <http/http.h> // Main include for Router, RouteGroup, etc.

// Assuming 'router' is a qb::http::Router<MySession> instance
// and handlers like users_list_handler are defined.
// qb::http::Router<MySession> router;

// Create a group for API version 1, prefixed with "/api/v1"
auto v1_api_group = router.group("/api/v1");

// Routes defined on v1_api_group will be relative to "/api/v1"
v1_api_group->get("/users", users_list_handler);         // effective path: /api/v1/users
v1_api_group->post("/products", products_create_handler); // effective path: /api/v1/products

// Nested groups are also possible
auto admin_group = v1_api_group->group("/admin");
admin_group->get("/settings", admin_settings_handler); // effective path: /api/v1/admin/settings
```

### Path Resolution

The `RouteGroup` itself is an `IHandlerNode`. When routes are compiled, the router traverses this hierarchy:

-   The `path_prefix` of a `RouteGroup` is combined with the `current_built_path` from its parent (either the main router or another `RouteGroup`).
-   Routes (`qb::http::Route`) or `Controller`s added to a `RouteGroup` have their own path segments, which are then appended to the group's full path.

**Example Path Resolution:**

```cpp
#include <http/http.h> // Main include

// Assuming router is qb::http::Router<MySession> and handlers exist.
// router.get("/health", ...);                           // -> /health
// auto user_group = router.group("/users");           // Group prefix: /users
// user_group->get("/:id", ...);                       // -> /users/:id
// user_group->post("/", ...);                         // -> /users/
// auto profile_group = user_group->group("/profiles"); // Nested group prefix: /users/profiles
// profile_group->get("/:userId/view", ...);           // -> /users/profiles/:userId/view
```

## Group-Specific Middleware

One of the primary benefits of `RouteGroup` is the ability to apply middleware that is specific to all routes and sub-nodes (other groups or controllers) within that group. Middleware applied to a group is executed *after* any middleware from its parent group or the main router, and *before* any middleware specific to a child node or the final route handler.

```cpp
#include <http/http.h> // Main include
#include <http/middleware/all.h> // Or specific middleware headers
#include <memory>      // For std::make_shared

// Assume MySession and relevant handlers are defined.
// Placeholder Middleware definitions:
class ApiAuthMiddleware : public qb::http::IMiddleware<MySession> {
public:
    ApiAuthMiddleware(std::string name) : _name(name) {}
    std::string name() const override { return _name; }
    void process(std::shared_ptr<qb::http::Context<MySession>> ctx) override { 
        // Minimal implementation for example
        std::cout << "ApiAuthMiddleware: " << ctx->request().uri().path() << std::endl;
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE); 
    }
    void cancel() override {}
private: std::string _name;
};
class V1LoggingMiddleware : public qb::http::IMiddleware<MySession> { 
public:
    V1LoggingMiddleware(std::string name) : _name(name) {}
    std::string name() const override { return _name; }
    void process(std::shared_ptr<qb::http::Context<MySession>> ctx) override { 
        std::cout << "V1LoggingMiddleware: " << ctx->request().uri().path() << std::endl;
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE); 
    }
    void cancel() override {}
private: std::string _name;
 };
// qb::http::Router<MySession> router;

// ... in server setup ...
auto api_group = router.group("/api");
api_group->use(std::make_shared<ApiAuthMiddleware>("api_auth")); // Applies to all /api/* routes

auto v1_group = api_group->group("/v1");
v1_group->use(std::make_shared<V1LoggingMiddleware>("v1_logger")); // Applies to all /api/v1/* routes

v1_group->get("/status", [](auto ctx) { /* ... */ ctx->complete(); });
// Request to /api/v1/status will execute:
// 1. Any global router middleware
// 2. ApiAuthMiddleware (from api_group)
// 3. V1LoggingMiddleware (from v1_group)
// 4. The /status route handler

auto v2_group = api_group->group("/v2");
// v2_group implicitly inherits ApiAuthMiddleware from api_group
// but does NOT inherit V1LoggingMiddleware from its sibling v1_group.
v2_group->get("/info", [](auto ctx) { /* ... */ ctx->complete(); });
// Request to /api/v2/info will execute:
// 1. Any global router middleware
// 2. ApiAuthMiddleware (from api_group)
// 3. The /info route handler
```

Middleware is added to a `RouteGroup` using the same `use()` methods available on the `Router`:

-   `group.use(MiddlewareHandlerFn<SessionType> mw_fn, std::string name)`: For lambda-based middleware.
-   `group.use(std::shared_ptr<IMiddleware<SessionType>> mw_ptr, std::string name_override)`: For pre-created middleware instances.
-   `group.use<MiddlewareType, Args...>(Args&&... args)`: To construct middleware in-place.

## Mounting Controllers within Groups

Controllers can also be mounted within `RouteGroup`s. The controller's routes will then be prefixed by the group's full path, and requests to those controller routes will pass through the group's middleware stack (in addition to any global middleware and the controller's own middleware).

```cpp
#include <http/http.h> // Main include
#include <memory>      // For std::make_shared

// Assuming MyUserController and UserGroupSpecificMiddleware are defined
// class MyUserController : public qb::http::Controller<MySession> { /* ... */ };
// class UserGroupSpecificMiddleware : public qb::http::IMiddleware<MySession> { /* ... */ };
// qb::http::Router<MySession> router;

auto api_users_group = router.group("/api/users");
// api_users_group->use(std::make_shared<UserGroupSpecificMiddleware>());

// Mount MyUserController at /api/users/manage
// If MyUserController defines a route GET "/:id", its full path will be /api/users/manage/:id
// auto user_controller = api_users_group->controller<MyUserController>("/manage");
```

## Defining Routes Directly on Groups

Just like the main `Router`, `RouteGroup` instances provide the same HTTP method functions (`get`, `post`, `put`, etc.) for defining routes directly within the group. These routes are relative to the group's prefix.

```cpp
#include <http/http.h> // Main include

// Assuming AdminAuthMiddleware and handlers are defined
// qb::http::Router<MySession> router;

auto admin_panel = router.group("/admin-panel");
// admin_panel->use<AdminAuthMiddleware>();

// admin_panel->get("/dashboard", admin_dashboard_handler); // Path: /admin-panel/dashboard
// admin_panel->post("/settings/update", update_settings_handler); // Path: /admin-panel/settings/update
```

## ASCII Diagram: Group and Middleware Chaining

```
Router
  |- Global Middleware 1 (GM1)
  |
  |- Route: GET /public/info (Handler P)
  |   Exec: GM1 -> Handler P
  |
  |- Group: /api (prefix: /api)
  |   |- Group Middleware A (GMA)
  |   |
  |   |- Route: GET /users (Handler U)
  |   |   Exec: GM1 -> GMA -> Handler U
  |   |
  |   |- Group: /v1 (prefix: /api/v1)
  |   |   |- Group Middleware B (GMB)
  |   |   |
  |   |   |- Route: POST /items (Handler I)
  |   |   |   Exec: GM1 -> GMA -> GMB -> Handler I
  |   |   |
  |   |   |- Controller: /products (prefix: /api/v1/products)
  |   |       |- Controller Middleware C (CMC)
  |   |       |
  |   |       |- Route: GET /:id (Handler ProdId)
  |   |           Exec: GM1 -> GMA -> GMB -> CMC -> Handler ProdId
```

This diagram illustrates how path prefixes accumulate and middleware chains are built up from the router root down through nested groups and controllers.

Route groups are a powerful tool for structuring larger applications, promoting code organization and reusability of middleware logic across related parts of your API.

Previous: [Defining Routes](./04-defining-routes.md)
Next: [Controllers](./06-controllers.md)

---
Return to [Index](./README.md) 
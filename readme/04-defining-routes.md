# 04: Defining Routes

Routes are the core of your HTTP application, mapping specific URL paths and HTTP methods to your handler logic. The `qb::http::Router` provides a fluent and flexible API for defining these routes.

## Basic Route Definition

The primary way to define routes is using the HTTP method-specific functions on a `Router` instance or a `RouteGroup` instance (see [Route Groups](./05-route-groups.md) and [Controllers](./06-controllers.md)).

Common methods include:

-   `router.get(path, handler)`
-   `router.post(path, handler)`
-   `router.put(path, handler)`
-   `router.del(path, handler)` (or `router.delete_()`, check API for exact naming if `delete` is a keyword issue)
-   `router.patch(path, handler)`
-   `router.options(path, handler)`
-   `router.head(path, handler)`

Each of these methods takes:

1.  `path`: A `std::string` representing the path pattern. This can include static segments, [parameterized segments](./03-routing-overview.md#path-matching) (e.g., `/:id`), and [wildcard segments](./03-routing-overview.md#path-matching) (e.g., `/*filepath`).
2.  `handler`: The logic to execute when the route is matched. This can be a lambda function or an instance of a class implementing `ICustomRoute`.

### Using Lambda Functions as Handlers

For straightforward route logic, lambda functions are often the most concise way to define handlers. The lambda must conform to the `qb::http::RouteHandlerFn<SessionType>` signature:

```cpp
// Defined in http/routing/types.h (or similar)
// Included via <http/http.h> or <http/routing.h>
template<typename SessionType>
using RouteHandlerFn = std::function<void(std::shared_ptr<qb::http::Context<SessionType>> ctx)>;
```

The lambda receives a `std::shared_ptr<qb::http::Context<SessionType>>` which provides access to the request, response, path parameters, and other contextual information. **Crucially, the handler lambda is responsible for eventually calling `ctx->complete()`** to signal that its processing is finished and the router can proceed (e.g., send the response or move to an error state).

```cpp
#include <http/http.h> // Main include for Router, Context, status, method, etc.
#include <iostream>    // For std::cout in more complex examples (not strictly needed for this one)

// Assuming MySession is defined elsewhere or is a type alias like qb::http::DefaultSession
// using MySession = qb::http::DefaultSession; // Example alias

// In your server setup code, assuming 'router' is an instance of qb::http::Router<MySession>
// qb::http::Router<MySession> router;

// GET /simple
router.get("/simple", [](std::shared_ptr<qb::http::Context<MySession>> ctx) {
    ctx->response().status() = qb::http::status::OK;
    ctx->response().body() = "Simple GET response";
    ctx->complete();
});

// POST /submit
router.post("/submit", [](std::shared_ptr<qb::http::Context<MySession>> ctx) {
    std::string request_body_str = ctx->request().body().as<std::string>();
    // Process request_body_str ...
    ctx->response().status() = qb::http::status::CREATED;
    ctx->response().body() = "Data submitted: " + request_body_str;
    ctx->complete();
});

// Route with path parameter
router.get("/users/:userId", [](std::shared_ptr<qb::http::Context<MySession>> ctx) {
    std::string user_id = ctx->path_param("userId");
    ctx->response().status() = qb::http::status::OK;
    ctx->response().body() = "Profile for user: " + user_id;
    ctx->complete();
});
```

**Important**: If the lambda initiates an asynchronous operation (e.g., a database query through `qb::io::async::callback` or another actor message), it must capture the `ctx` (typically as a `std::shared_ptr`) and call `ctx->complete()` within the callback of that asynchronous operation.

### Using `ICustomRoute` for Complex Handlers

For more complex, stateful, or reusable route logic, you can define a class that implements the `qb::http::ICustomRoute<SessionType>` interface. This interface requires you to implement:

-   `void process(std::shared_ptr<Context<SessionType>> ctx)`: Contains the core request handling logic. Similar to lambdas, this method **must** call `ctx->complete()`.
-   `std::string name() const`: Returns a descriptive name for the route handler, useful for logging and debugging.
-   `void cancel()`: Called if the request processing is cancelled while this handler is active.

There are two ways to register an `ICustomRoute`:

1.  **Passing a `std::shared_ptr<ICustomRoute<SessionType>>`:**

    ```cpp
    #include <http/http.h> // For ICustomRoute, Context, etc.
    #include <memory>      // For std::make_shared
    #include <string>      // For std::string

    // Assume MySession and some MyDatabaseService are defined
    // using MySession = qb::http::DefaultSession;
    // struct MyDatabaseService { /* ... */ };

    class UserProfileHandler : public qb::http::ICustomRoute<MySession> {
    public:
        std::string name() const override { return "UserProfileHandler"; }
        void cancel() override { /* cleanup if needed */ }

        void process(std::shared_ptr<qb::http::Context<MySession>> ctx) override {
            std::string user_id = ctx->path_param("id");
            // ... fetch user profile ...
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body() = "Profile for user (custom route): " + user_id;
            ctx->complete();
        }
    };

    auto user_profile_route = std::make_shared<UserProfileHandler>();
    router.get("/profiles/:id", user_profile_route);
    ```

2.  **Using the typed template method (constructs in-place):**
    The router provides templated versions of its method-specific functions (`get`, `post`, etc.) that can construct your `ICustomRoute` derived class in-place.

    ```cpp
    #include <http/http.h> // For ICustomRoute, Context, etc.
    #include <memory>      // For std::make_shared
    #include <string>      // For std::string
    #include <utility>     // For std::move

    // Assume MySession is defined
    // using MySession = qb::http::DefaultSession;

    class ProductDetailsHandler : public qb::http::ICustomRoute<MySession> {
    private:
        std::string _product_prefix;
    public:
        ProductDetailsHandler(std::string prefix) : _product_prefix(std::move(prefix)) {}
        std::string name() const override { return _product_prefix + "ProductDetailsHandler"; }
        void cancel() override { /* ... */ }

        void process(std::shared_ptr<qb::http::Context<MySession>> ctx) override {
            std::string product_sku = ctx->path_param("sku");
            ctx->response().body() = _product_prefix + " Details for SKU: " + product_sku;
            ctx->complete();
        }
    };

    // Construct ProductDetailsHandler in-place, passing "Item:" to its constructor
    router.get<ProductDetailsHandler>("/inventory/:sku", "Item:");
    ```

Using `ICustomRoute` is beneficial for separating concerns, testing handler logic in isolation, and managing complex state or dependencies within the handler.

## Route Compilation

After all routes, groups, and controllers have been defined, you **must** call `router.compile()` before the router can start processing requests.

```cpp
#include <http/http.h> // For Router, etc.

// Assume MyHttpServer is your server class, MySession its session type
// and status_handler_lambda is defined.
// MyHttpServer() {
//     router.get("/status", status_handler_lambda);
// ... existing code ...

router.compile(); // Crucial step
// }
```

Compilation analyzes the defined routing hierarchy, resolves middleware chains for each endpoint, and builds the internal `RadixTree` for efficient request matching. Attempting to route requests before compilation will result in undefined behavior or errors.

## General Route Definition (`router.add_route()`)

While the HTTP method-specific functions (`get`, `post`, etc.) are the most common way to define routes, the `Router` (and `RouteGroup`) also provides a more general `add_route` method:

```cpp
#include <http/http.h> // For Router, method, etc.

// Assume router, data_put_lambda_handler, MyDeleteResourceHandler, MyConfigHandler are defined.
// qb::http::Router<MySession> router;

// For lambda handlers
// ... existing code ...

// For ICustomRoute shared_ptr
auto custom_delete_handler = std::make_shared<MyDeleteResourceHandler>();
router.add_route("/resources/:resourceId", qb::http::method::DEL, custom_delete_handler);

// For typed ICustomRoute with constructor arguments
router.add_custom_route<MyConfigHandler>("/config", qb::http::method::PATCH, "config_arg1");
```

These are useful if the HTTP method is determined dynamically or for more programmatic route construction.

Previous: [Routing Overview](./03-routing-overview.md)
Next: [Route Groups](./05-route-groups.md)

---
Return to [Index](./README.md) 
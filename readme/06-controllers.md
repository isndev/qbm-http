# 06: Controllers

For larger applications, or when route handling logic becomes more complex and stateful, organizing routes directly within `Router` or `RouteGroup` lambdas can become less manageable. `qb::http::Controller<SessionType>` provides a class-based approach to structure related route handlers, their dependencies, and controller-specific middleware.

## What is a Controller?

A `Controller` is a class that you derive from `qb::http::Controller<YourSessionType>`. It serves as a container for:

-   **Route Definitions**: You define routes (GET, POST, etc.) within a special `initialize_routes()` method.
-   **Handler Methods**: The actual logic for these routes is typically implemented as member functions of your controller class.
-   **Controller-Specific Middleware**: Middleware applied directly to the controller will affect all routes defined within it.
-   **State and Dependencies**: Being a class, a controller can have member variables, allowing it to hold state or manage dependencies (e.g., database connections, service clients) that are shared among its route handlers.

## Creating a Controller

1.  **Inherit**: Create a class that inherits from `qb::http::Controller<SessionType>`.
2.  **Implement `initialize_routes()`**: This pure virtual method is where you define your controller's routes using methods like `this->get()`, `this->post()`, `this->use()`.
3.  **Implement Handler Methods**: Write member functions that will handle the requests for the routes you define. These methods typically take a `std::shared_ptr<qb::http::Context<SessionType>>` as an argument.

```cpp
#include <http/http.h> // For Controller, Context, etc.

// Assume MySession is your application's session type
class MyUserController : public qb::http::Controller<MySession> {
public:
    // Constructor can take dependencies
    MyUserController(std::shared_ptr<MyDatabaseService> db_service)
        : _db_service(std::move(db_service)) {}

    // This method is called by the router to set up routes
    void initialize_routes() override {
        // Middleware specific to this controller
        this->use([](auto ctx, auto next) {
            std::cout << "UserController middleware: Path " << ctx->request().uri().path() << std::endl;
            next();
        });

        // Define routes, binding them to member functions
        this->get("/:userId", MEMBER_HANDLER(&MyUserController::getUserProfile));
        this->post("/", MEMBER_HANDLER(&MyUserController::createUser));
        this->put("/:userId", MEMBER_HANDLER(&MyUserController::updateUser));

        // Example of a route using a lambda directly within the controller
        this->get("/status", [](std::shared_ptr<qb::http::Context<MySession>> ctx) {
            ctx->response().body() = "User controller is active!";
            ctx->complete();
        });
    }

    // Handler methods
    void getUserProfile(std::shared_ptr<qb::http::Context<MySession>> ctx) {
        std::string user_id = ctx->path_param("userId");
        // Use _db_service to fetch user data...
        ctx->response().body() = "Profile for user " + user_id;
        ctx->complete();
    }

    void createUser(std::shared_ptr<qb::http::Context<MySession>> ctx) {
        // Process ctx->request().body()...
        ctx->response().status() = qb::http::status::CREATED;
        ctx->response().body() = "User created.";
        ctx->complete();
    }

    void updateUser(std::shared_ptr<qb::http::Context<MySession>> ctx) {
        std::string user_id = ctx->path_param("userId");
        ctx->response().body() = "User " + user_id + " updated.";
        ctx->complete();
    }

    // Required by IHandlerNode (Controller inherits from it)
    std::string get_node_name() const override {
        return "MyUserController";
    }

private:
    std::shared_ptr<MyDatabaseService> _db_service;
};
```

### The `MEMBER_HANDLER` Macro

To bind a controller's member function as a route handler, the `MEMBER_HANDLER(ptr_to_member_fn)` macro is provided. It simplifies creating a lambda that captures `this` and calls the specified member function.

`ptr_to_member_fn` should be the address of your member function, e.g., `&MyUserController::getUserProfile`.

## Mounting a Controller

Controllers are mounted onto a `Router` or a `RouteGroup` using the `controller<ControllerType>(path_prefix, constructor_args...)` method.

-   `ControllerType`: The type of your derived controller class.
-   `path_prefix`: The base path segment under which this controller's routes will be available.
-   `constructor_args...`: Any arguments required by your controller's constructor.

```cpp
// In your server setup:
// auto my_db_service = std::make_shared<MyDatabaseService>();

// Mount MyUserController under "/users"
auto user_ctrl_ptr = router.controller<MyUserController>("/users", my_db_service);

// After router.compile(), requests like:
// GET /users/123         -> MyUserController::getUserProfile (with userId="123")
// POST /users/           -> MyUserController::createUser
// GET /users/status      -> Lambda defined in MyUserController::initialize_routes
```

**Path Resolution for Controllers:**

-   The `path_prefix` provided during mounting is combined with the parent's path (router root or group prefix).
-   Path patterns defined within `initialize_routes()` are relative to this controller's effective base path.

Example:
If `router.controller<MyUserController>("/admin/users", ...)` is called,
and `MyUserController` defines `get("/:id", ...)`, the full path for that route becomes `/admin/users/:id`.

## Controller-Specific Middleware

Middleware can be applied directly within a controller's `initialize_routes()` method using `this->use(...)`. This middleware will apply to **all routes defined within that controller**, after any middleware from parent groups or the router, but before the specific route handler.

```cpp
void MySecureController::initialize_routes() {
    // This authentication middleware applies to all routes in MySecureController
    this->use<ControllerSpecificAuthMiddleware>(/* constructor args if any */);

    this->get("/data", MEMBER_HANDLER(&MySecureController::getSecureData));
    this->post("/config", MEMBER_HANDLER(&MySecureController::updateSecureConfig));
}
```

## Benefits of Using Controllers

-   **Organization**: Groups related routes and logic into a single, cohesive class.
-   **Encapsulation**: Allows route handlers to share state or dependencies (e.g., a database service) encapsulated within the controller instance.
-   **Reusability**: Controllers can be instantiated multiple times, potentially under different path prefixes or with different configurations if their constructors allow.
-   **Testability**: Controller classes can often be unit-tested more easily than scattered lambda handlers, as dependencies can be mocked and injected.
-   **Scoped Middleware**: Apply middleware that is relevant only to the set of routes managed by the controller.

Controllers provide a structured and scalable way to build complex HTTP APIs by promoting modularity and clear separation of concerns.

Previous: [Route Groups](./05-route-groups.md)
Next: [Middleware Overview](./07-middleware.md)

---
Return to [Index](./README.md) 
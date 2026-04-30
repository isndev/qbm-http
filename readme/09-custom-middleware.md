# 09: Custom Middleware

While the `qb::http` module provides a rich set of [standard middleware](./08-standard-middleware.md), you'll often need to implement custom logic specific to your application's requirements. This can range from highly specialized authentication schemes to unique request/response transformations or integrations with other services.

The routing system is designed for extensibility, allowing you to create and integrate your own middleware components seamlessly.

## Creating Custom Middleware

There are two primary ways to create custom middleware:

1.  **Implementing `IMiddleware`**: For more complex, stateful, or reusable middleware, you can create a class that inherits from `qb::http::IMiddleware<SessionType>`.
2.  **Using Functional Middleware**: For simpler, often stateless middleware, you can use a lambda function or a `std::function` that matches the `qb::http::MiddlewareHandlerFn<SessionType>` signature.

### 1. Implementing the `IMiddleware` Interface

To create a class-based middleware, you need to:

-   Inherit from `qb::http::IMiddleware<SessionType>` (where `SessionType` is your application's session type).
-   Implement the pure virtual methods:
    -   `void process(std::shared_ptr<Context<SessionType>> ctx)`: Contains the core logic of your middleware. It must call `ctx->complete(AsyncTaskResult::...)` to control the flow.
    -   `std::string name() const`: Returns a descriptive name for your middleware.
    -   `void cancel()`: Handles cancellation if your middleware performs long-running asynchronous operations.

```cpp
#include <http/http.h> // For IMiddleware, Context, AsyncTaskResult

// Assume MySession is your application's session type

class MyCustomHeaderMiddleware : public qb::http::IMiddleware<MySession> {
public:
    MyCustomHeaderMiddleware(std::string header_name, std::string header_value)
        : _header_name(std::move(header_name)), _header_value(std::move(header_value)) {}

    std::string name() const override {
        return "MyCustomHeaderMiddleware(" + _header_name + ")";
    }

    void cancel() override {
        // Called if the request processing is cancelled.
        // Clean up any async operations this middleware might have started.
        std::cout << name() << " received cancel signal." << std::endl;
    }

    void process(std::shared_ptr<qb::http::Context<MySession>> ctx) override {
        std::cout << name() << ": Adding header '" << _header_name << ": " << _header_value << "' to request." << std::endl;
        ctx->request().set_header(_header_name, _header_value);

        // After processing, pass control to the next middleware or handler in the chain.
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }

private:
    std::string _header_name;
    std::string _header_value;
};
```

**Using the Class-Based Middleware:**

You can add an instance of your custom middleware to the router, a route group, or a controller using `use()`:

```cpp
// Using std::make_shared
auto custom_header_mw = std::make_shared<MyCustomHeaderMiddleware>("X-Custom-Processed", "true");
router.use(custom_header_mw);

// Or, if your middleware has a suitable constructor, you can use the templated use method:
router.use<MyCustomHeaderMiddleware>("X-Another-Custom", "some_value");
```

This approach is ideal when your middleware needs to maintain state across multiple requests (though this is less common for typical HTTP middleware), manage complex dependencies (e.g., injected services), or when its logic is substantial enough to warrant its own class.

### 2. Using Functional Middleware (Lambdas)

For simpler or stateless middleware, a lambda function is often more concise. The lambda must match the `qb::http::MiddlewareHandlerFn<SessionType>` signature:

```cpp
// Defined in http/routing/types.h
template<typename SessionType>
using MiddlewareHandlerFn = std::function<void(
    std::shared_ptr<qb::http::Context<SessionType>> ctx,
    std::function<void()> next // The 'next' callback
)>;
```

Key aspects of a functional middleware lambda:

-   It receives the `Context` and a `next` callback.
-   **To pass control to the next task in the chain**: Call `next()`.
    -   You can perform actions *before* calling `next()` (pre-processing on `ctx->request()`).
    -   You can perform actions *after* `next()` returns (post-processing on `ctx->response()`) for synchronous downstream chains. For asynchronous downstream work, register a `PRE_RESPONSE_SEND` lifecycle hook when the mutation must run at final send time.
-   **To short-circuit and finalize the response**: Do *not* call `next()`. Instead, populate `ctx->response()` and call `ctx->complete(AsyncTaskResult::COMPLETE)`.
-   **To signal an error**: Do *not* call `next()`. Call `ctx->complete(AsyncTaskResult::ERROR)`.

```cpp
// Example: A simple request logging functional middleware
router.use([](std::shared_ptr<qb::http::Context<MySession>> ctx, std::function<void()> next) {
    std::cout << "[Functional MW] Incoming request: " << std::to_string(ctx->request().method()) 
              << " " << ctx->request().uri().path() << std::endl;

    next(); // Pass control to the next middleware/handler

    // For synchronous downstream chains, this runs before the response is sent.
    // For async downstream work, prefer a PRE_RESPONSE_SEND lifecycle hook.
    std::cout << "[Functional MW] Outgoing response status: " << ctx->response().status().code() << std::endl;
}, "RequestLoggerMiddleware");

// Example: Functional middleware that conditionally short-circuits
router.use([](std::shared_ptr<qb::http::Context<MySession>> ctx, std::function<void()> next) {
    if (ctx->request().header("X-Maintenance-Mode") == "true") {
        ctx->response().status() = qb::http::status::SERVICE_UNAVAILABLE;
        ctx->response().body() = "Server is in maintenance mode.";
        ctx->response().set_header("Retry-After", "3600");
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE); // Short-circuit
    } else {
        next(); // Continue normally
    }
}, "MaintenanceModeCheck");
```

When you provide a lambda to `use()`, the router internally wraps it in a `qb::http::FunctionalMiddleware` adapter, which itself implements `IMiddleware`. This adapter manages the execution of your lambda and the `next` callback, ensuring it integrates correctly with the `Context`'s completion mechanism.

Specifically, when `next()` is called by your functional middleware:
1. The `FunctionalMiddleware` adapter calls `ctx->complete(AsyncTaskResult::CONTINUE)` internally to suspend its own execution and let the chain proceed.
2. Once the rest of the chain (subsequent middleware and the final route handler) completes and control unwinds back to the `FunctionalMiddleware` adapter, the code in your lambda *after* the `next()` call is executed.
3. During that synchronous unwind, final response publication is deferred until your lambda returns, so post-`next()` response mutations are visible before the response is sent. The adapter does not call `complete()` a second time; the downstream task's terminal result remains authoritative.

## Coroutine Middleware &amp; Handlers (`qb::http::coro_*`)

For server-side code, `qbm/http` ships two small helpers that adapt a coroutine-returning lambda into the classical middleware / route-handler signatures the router expects. They are declared in `qbm/http/routing/coro_task.h` (transparently included by `routing.h`).

```cpp
namespace qb::http {

    // Concept: the callable must have signature task<void>(shared_ptr<Context<Session>>).
    template <typename F, typename SessionType>
    concept CoroRouteHandler      = /* ... */;
    template <typename F, typename SessionType>
    concept CoroMiddlewareHandler = /* ... */;

    template <typename SessionType, typename CoroFn>
        requires CoroRouteHandler<CoroFn, SessionType>
    RouteHandlerFn<SessionType>      coro_handler(CoroFn&&);

    template <typename SessionType, typename CoroFn>
        requires CoroMiddlewareHandler<CoroFn, SessionType>
    MiddlewareHandlerFn<SessionType> coro_middleware(CoroFn&&);

} // namespace qb::http
```

**Default outcomes** when the coroutine body returns normally without having called `ctx->complete(...)` or `ctx->cancel()`:

| Wrapper               | Default terminal outcome                     | Rationale                                |
|-----------------------|----------------------------------------------|------------------------------------------|
| `coro_handler`        | `AsyncTaskResult::COMPLETE`                  | A handler is the leaf &mdash; the response is ready. |
| `coro_middleware`     | `AsyncTaskResult::CONTINUE`                  | A middleware's job is to yield to the next task. |

If the body calls `ctx->complete(...)` explicitly, the wrapper **does not** override that decision &mdash; the existing outcome wins. Exceptions thrown from the body are caught, logged with route context, and translated into `500 Internal Server Error` with `AsyncTaskResult::ERROR` (same policy as `RouteLambdaTask`).

**Usage example &mdash; handler + middleware with `co_await`:**

```cpp
#include <qbm/http/http.h>
#include <qbm/http/coro.h>

using Session = MySession;

router.use(qb::http::coro_middleware<Session>(
    [this](auto ctx) -> qb::io::async::task<void> {
        if (auto user = co_await auth_lookup(ctx->request().header("Authorization"))) {
            ctx->template set<CurrentUser>(std::move(*user));
            co_return;                          // default: CONTINUE
        }
        ctx->response().status() = qb::http::status::UNAUTHORIZED;
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE); // short-circuit
        co_return;
    }));

router.get("/users/:id",
    qb::http::coro_handler<Session>(
        [this](auto ctx) -> qb::io::async::task<void> {
            auto profile = co_await db_load_profile(ctx->path_param("id"));
            auto stats   = co_await stats_service(profile.id);
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = render(profile, stats);
            co_return;                          // default: COMPLETE
        }));
```

**Design notes:**

-   The coroutine body receives a `std::shared_ptr<Context<Session>>`, which outlives every suspension point the body may hit, so it is safe to capture it across `co_await`s.
-   `coro_middleware` does **not** give the body an explicit `next()` callback &mdash; the framework drives chain progress via `ctx->complete(...)`. Short-circuiting is therefore just *setting the response and calling `complete(COMPLETE)`*.
-   The body is spawned on `qb::io::async::coro_scheduler()` &mdash; the same thread-local scheduler the rest of `qb-io` uses, preserving the mono-thread-per-listener contract.

## Asynchronous Custom Middleware

If your custom middleware needs to perform non-blocking asynchronous operations (e.g., querying a database, calling an external service):

-   **Class-based (`IMiddleware`)**: Your `process()` method will initiate the async operation. Capture the `std::shared_ptr<Context<SessionType>> ctx`. In the callback of your async operation, use the captured `ctx` to call `ctx->complete(...)` with the appropriate `AsyncTaskResult`.

    ```cpp
    class MyAsyncDataFetchingMiddleware : public qb::http::IMiddleware<MySession> {
    public:
        // ... name(), cancel(), constructor ...
        void process(std::shared_ptr<qb::http::Context<MySession>> ctx) override {
            auto shared_ctx = ctx; // Capture for async callback
            // Assume _my_async_service->fetchData takes a callback
            _my_async_service->fetchData(shared_ctx->request().query("some_id"), 
                [shared_ctx](std::optional<std::string> data, bool success) {
                    if (shared_ctx->is_cancelled()) return;

                    if (success && data) {
                        shared_ctx->set("fetched_data", *data);
                        shared_ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
                    } else {
                        shared_ctx->response().status() = qb::http::status::SERVICE_UNAVAILABLE;
                        shared_ctx->complete(qb::http::AsyncTaskResult::ERROR);
                    }
                }
            );
        }
    private:
        // MyAsyncService* _my_async_service; // Injected dependency
    };
    ```

-   **Functional (Lambda)**: The same principle applies. The lambda initiates the async work. The `next` callback (or a direct `ctx->complete(...)` call if short-circuiting) must be invoked from the async operation's completion handler.

    ```cpp
    router.use([](auto ctx, auto next) {
        auto shared_ctx = ctx;
        std::string lookup_key = std::string(shared_ctx->request().header("X-Lookup-Key"));

        // Example: using qb::io::async::callback for a delayed operation
        qb::io::async::callback([shared_ctx, next_fn = next, key = lookup_key]() {
            // Simulate an async operation that might take some time
            std::cout << "[Async Functional MW] Async operation for key '" << key << "' completed." << std::endl;

            if (shared_ctx->is_cancelled()) {
                std::cout << "[Async Functional MW] Context was cancelled. Aborting." << std::endl;
                // If context is cancelled, it might have already called complete(CANCELLED).
                // If not, and we want to ensure it, we could call it here, but usually cancel() on context handles this.
                return; 
            }

            if (key == "valid_key_for_next") {
                shared_ctx->request().set_header("X-Async-Lookup-Result", "DataFoundForNext");
                next_fn(); // Proceed to the next middleware/handler
            } else if (key == "valid_key_for_complete") {
                shared_ctx->response().status() = qb::http::status::OK;
                shared_ctx->response().body() = "Async operation completed and handled by middleware.";
                shared_ctx->set<std::string>("async_op_data", "SpecificDataFromAsyncMW");
                shared_ctx->complete(qb::http::AsyncTaskResult::COMPLETE); // Short-circuit and finalize
            } else {
                shared_ctx->response().status() = qb::http::status::NOT_FOUND;
                shared_ctx->response().body() = "Async lookup failed for key: " + key;
                shared_ctx->complete(qb::http::AsyncTaskResult::ERROR); // Signal an error
            }
        }, std::chrono::milliseconds(20)); // Simulate a 20ms async delay

        // The main lambda body returns immediately after scheduling the async task.
        // The FunctionalMiddleware adapter has already called ctx->suspend() or similar internally
        // to indicate that completion will happen later.
    }, "AsyncLookupFunctionalMW");
    ```

    **Important for Functional Async Middleware**:
    - When your lambda returns after initiating an asynchronous operation (like scheduling a `qb::io::async::callback`), the `FunctionalMiddleware` wrapper that the router uses internally understands that the task is not yet complete. It effectively suspends the current middleware's processing in the chain.
    - When your asynchronous callback eventually runs and calls `next_fn()`, this signals to the `FunctionalMiddleware` wrapper to resume the chain by calling `ctx->complete(AsyncTaskResult::CONTINUE)` (or similar mechanism to pass control onwards).
    - If your asynchronous callback instead calls `ctx->complete(AsyncTaskResult::COMPLETE)` or `ctx->complete(AsyncTaskResult::ERROR)`, it directly finalizes or errors out the request processing for that context.
    - Ensure that `ctx->complete()` or `next_fn()` is called *exactly once* for every execution path of your asynchronous logic to maintain correct control flow.

## Registering Custom Middleware

Custom middleware, whether class-based (as `std::shared_ptr<IMiddleware<SessionType>>`) or functional, is added to the processing chain using the `use()` method on a `Router`, `RouteGroup`, or `Controller` instance.

```cpp
#include <http/http.h> // For Router, RouteGroup, Controller, IMiddleware
#include <memory>      // For std::make_shared

// Assuming MySession, MyCustomHeaderMiddleware, my_functional_logging_mw, 
// MyApiV1AuthMiddleware, MyControllerSpecificCacheMiddleware are defined.
// And router, api_v1 are initialized qb::http::Router<MySession> or RouteGroup<MySession> instances.

// struct MySession; // Or using MySession = qb::http::DefaultSession;
// class MyCustomHeaderMiddleware : public qb::http::IMiddleware<MySession> { /* ... */ };
// auto my_functional_logging_mw = [](auto ctx, auto next){ /* ... */ next(); };
// class MyApiV1AuthMiddleware : public qb::http::IMiddleware<MySession> { /* ... */ };

// qb::http::Router<MySession> router;

// Router level (global)
// router.use(std::make_shared<MyCustomHeaderMiddleware>("X-Global", "true"));
// router.use(my_functional_logging_mw, "GlobalLogger");

// Group level
// auto api_v1 = router.group("/api/v1");
// api_v1->use<MyApiV1AuthMiddleware>(); // Constructed in-place

// Controller level (within initialize_routes of a Controller<MySession> derived class)
// this->use(std::make_shared<MyControllerSpecificCacheMiddleware>());
```

By understanding these patterns, you can effectively extend the `qb::http` module with tailored processing logic to meet your application's unique needs.

Previous: [Standard Middleware](./08-standard-middleware.md)
Next: [The Request Context](./10-request-context.md)

---
Return to [Index](./README.md)

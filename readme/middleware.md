# `qbm-http`: Middleware

(`qbm/http/middleware/`)

Middleware allows you to define logic that runs before or after your main route handlers. It's a powerful mechanism for handling cross-cutting concerns like logging, authentication, data validation, CORS, rate limiting, and request/response modification.

## Middleware Concept

Middleware functions or objects are arranged in a **chain**. When a request comes in:

1.  The request passes through the middleware chain in the order they were registered.
2.  Each middleware can:
    *   **Inspect/Modify the Request:** Read headers, check query parameters, parse the body.
    *   **Inspect/Modify the Response:** Add headers, transform the body (often done via `ctx.after_handling`).
    *   **Pass Control:** Call `next(true)` (for async) or return `MiddlewareResult::Continue()` / `true` (for sync) to pass control to the next middleware in the chain or the final route handler.
    *   **End the Request:** Handle the request completely (e.g., return an error response) and stop further processing by calling `next(false)` or returning `MiddlewareResult::Stop()` / `false`.
    *   **Perform Asynchronous Operations:** Asynchronous middleware can perform non-blocking I/O or other delayed tasks before deciding whether to continue or stop the chain.

## Core Interfaces

(`middleware/middleware_interface.h`)

*   **`qb::http::IMiddleware<Session, String>`:** The unified interface. All middleware must implement this.
    *   `virtual MiddlewareResult process(Context& ctx, CompletionCallback callback = nullptr) = 0;`
    *   `virtual std::string name() const = 0;`
*   **`qb::http::ISyncMiddleware<Session, String>`:** Interface for purely synchronous middleware.
    *   `virtual MiddlewareResult process(Context& ctx) = 0;`
*   **`qb::http::IAsyncMiddleware<Session, String>`:** Interface for purely asynchronous middleware.
    *   `virtual void process_async(Context& ctx, CompletionCallback callback) = 0;`
*   **`qb::http::MiddlewareResult`:** Return type indicating the outcome (`Continue`, `Stop`, `Error`, `Async`, `Skip`).
*   **`qb::http::MiddlewarePtr<Session, String>`:** Alias for `std::shared_ptr<IMiddleware<...>>`.
*   **Adapters:** `SyncMiddlewareAdapter`, `AsyncMiddlewareAdapter`, `FunctionMiddleware`, `LegacyMiddlewareAdapter` convert synchronous, asynchronous, function-based, or older middleware styles to the unified `IMiddleware` interface.

## Middleware Chain (`qb::http::MiddlewareChain`)

(`middleware/middleware_chain.h`)

*   Manages a sequence of `MiddlewarePtr` objects.
*   Executes them in order.
*   Handles the flow control based on `MiddlewareResult`.
*   Supports adding middleware (`add()`).
*   Can have its own error handler (`on_error()`).
*   The `Router` uses a `MiddlewareChain` internally for global and group-level middleware.

## Registering Middleware

Middleware can be applied at different levels:

1.  **Global:** Applied to *all* requests handled by the router.
    ```cpp
    router.use(qb::http::middleware::logging(/*...*/)); // Built-in
    router.use(my_custom_middleware_ptr);              // Custom typed
    router.use([](Context& ctx){ /* legacy sync */ return true; });
    ```
2.  **Group Level:** Applied only to routes within a specific group and its subgroups.
    ```cpp
    auto& api_group = router.group("/api");
    api_group.use(auth_middleware_ptr);
    api_group.use([](Context& ctx){ /* ... */ return true; });
    ```

## Creating Custom Middleware

### Synchronous Middleware (Class)

Inherit from `ISyncMiddleware` and implement `process`.

```cpp
#include <qb/http.h>

class CustomHeaderMiddleware : public qb::http::ISyncMiddleware<MySession> {
public:
    std::string name() const override { return "CustomHeaderMiddleware"; }

    qb::http::MiddlewareResult process(Context& ctx) override {
        ctx.response.add_header("X-Custom-Sync", "Processed");
        return qb::http::MiddlewareResult::Continue();
    }
};

// Registering:
// auto sync_middleware = std::make_shared<CustomHeaderMiddleware>();
// router.use(std::make_shared<qb::http::SyncMiddlewareAdapter<MySession>>(sync_middleware));
// Or using the helper:
// router.use(qb::http::make_middleware(sync_middleware)); // Needs adjustment in make_middleware
```

### Synchronous Middleware (Function)

Use the `qb::http::make_middleware` helper.

```cpp
router.use(qb::http::make_middleware<MySession>([](qb::http::Context<MySession>& ctx) {
    ctx.response.add_header("X-Sync-Lambda", "Executed");
    return qb::http::MiddlewareResult::Continue();
}, "SyncLambdaMiddleware"));
```

### Asynchronous Middleware (Class)

Inherit from `IAsyncMiddleware` and implement `process_async`.

```cpp
#include <qb/http.h>
#include <qb/io/async.h>

class AsyncDataFetchMiddleware : public qb::http::IAsyncMiddleware<MySession> {
public:
    std::string name() const override { return "AsyncDataFetchMiddleware"; }

    void process_async(Context& ctx, CompletionCallback callback) override {
        // Simulate fetching data asynchronously
        qb::io::async::callback([&ctx, callback]() {
            // Assume data fetching complete
            ctx.set<std::string>("fetched_data", "some_async_data");
            ctx.response.add_header("X-Async-Data", "Fetched");
            callback(qb::http::MiddlewareResult::Continue()); // Signal completion
        }, 0.1); // 100ms delay
    }
};

// Registering:
// auto async_middleware = std::make_shared<AsyncDataFetchMiddleware>();
// router.use(std::make_shared<qb::http::AsyncMiddlewareAdapter<MySession>>(async_middleware));
```

### Asynchronous Middleware (Function)

Use the `qb::http::make_middleware` helper for the async function signature.

```cpp
router.use(qb::http::make_middleware<MySession>(
    [](qb::http::Context<MySession>& ctx, qb::http::IMiddleware<MySession>::CompletionCallback callback) {
        qb::io::async::callback([&ctx, callback](){
            ctx.response.add_header("X-Async-Lambda", "Completed");
            callback(qb::http::MiddlewareResult::Continue());
        }, 0.05);
    },
    "AsyncLambdaMiddleware"
));
```

**(See also:** [`builtin_middleware.md`](./builtin_middleware.md), [`async_handling.md`](./async_handling.md)**)** 
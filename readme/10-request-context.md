# 10: The Request Context (`qb::http::Context`)

The `qb::http::Context<SessionType>` object is a central and pivotal component in the `qb::http` routing and middleware system. It encapsulates all information and state related to a single HTTP request throughout its processing lifecycle. A new `Context` instance is created by the `RouterCore` for each incoming request and is passed sequentially through the chain of applicable middleware and finally to the route handler.

## Purpose of the Context

The `Context` serves several key purposes:

1.  **Data Carrier**: It holds the `qb::http::Request` and `qb::http::Response` objects, allowing middleware and handlers to inspect the request and build up the response.
2.  **Session Access**: It provides a `std::shared_ptr` to the `SessionType` object, representing the underlying client connection or session state.
3.  **Parameter Storage**: It stores `qb::http::PathParameters` extracted from the URI by the router during path matching.
4.  **State Sharing**: It offers a mechanism (`CustomDataMap` via `set`/`get`/`has`/`remove` methods) for middleware and handlers to share arbitrary data related to the current request, facilitating communication and state passing between different stages of the processing chain.
5.  **Flow Control**: It is the primary means by which middleware and handlers signal their completion status and control the execution flow of the task chain using the `complete(AsyncTaskResult)` method.
6.  **Cancellation Management**: It manages the cancellation state of the request processing and provides a `cancel(reason)` method.
7.  **Lifecycle Hooks**: It allows registration of `LifecycleHook` functions to be executed at specific points during the request processing lifecycle.

## Key Components of the Context

-   **`request()`**: Returns a mutable reference to the `qb::http::Request` object.
-   **`response()`**: Returns a mutable reference to the `qb::http::Response` object.
-   **`session()`**: Returns a `std::shared_ptr<SessionType>` to the associated session.
-   **`path_parameters()`**: Returns a reference to the `qb::http::PathParameters` (values extracted from path segments like `/:id`).
-   **`path_param(name, default_value)`**: Convenience method to directly access a specific decoded path parameter by name.

### Custom Data Storage

Middleware and handlers can store and retrieve custom, request-specific data within the context. This is useful for passing information between middleware (e.g., an authenticated user object) or from middleware to a handler.

-   **`set<T>(key, value)`**: Stores a value of type `T` associated with a string `key`.
-   **`get<T>(key)`**: Retrieves an `std::optional<T>` for the given `key`. Returns `std::nullopt` if the key doesn't exist or if the stored type doesn't match `T`.
-   **`get_ptr<T>(key)`**: Returns a raw pointer `T*` or `const T*` to the stored data, or `nullptr` if not found or type mismatch. Useful for non-copyable types stored via `std::any`.
-   **`has(key)`**: Checks if a key exists.
-   **`remove(key)`**: Removes data associated with a key.

```cpp
// Middleware A
ctx->set<std::string>("user_id", "usr_123");
ctx->set<std::shared_ptr<MyDataObject>>("complex_data", std::make_shared<MyDataObject>());

// Middleware B or Handler
if (auto user_id_opt = ctx->get<std::string>("user_id")) {
    std::cout << "User ID from context: " << *user_id_opt << std::endl;
}

if (auto* data_ptr = ctx->get_ptr<std::shared_ptr<MyDataObject>>("complex_data")) {
    // Use (*data_ptr)->some_method();
}
```

## Controlling the Execution Flow

The `complete(AsyncTaskResult result)` method is the **most critical** function for any `IAsyncTask` (which includes middleware and route handlers) to call.

-   `ctx->complete(AsyncTaskResult::CONTINUE)`: Signals that the current task has finished its processing and the router should proceed to the next task in the chain.
-   `ctx->complete(AsyncTaskResult::COMPLETE)`: Signals that the current task has fully handled the request and the response in `ctx->response()` is ready to be sent. No further tasks in the *current* chain will be executed.
-   `ctx->complete(AsyncTaskResult::ERROR)`: Signals that an unrecoverable error occurred. The router will typically halt the current chain and invoke its configured error handling chain.
-   `ctx->complete(AsyncTaskResult::CANCELLED)`: Signals that processing was cancelled. This is usually called internally when `ctx->cancel()` is invoked.

**Failure to call `ctx->complete()` in every possible path of an `IAsyncTask::execute()` or `ICustomRoute::process()` method (especially in asynchronous operations) will lead to the request hanging indefinitely.**

## Cancellation

-   **`cancel(reason)`**: Initiates cancellation of the request processing. This sets an internal flag and typically results in `complete(AsyncTaskResult::CANCELLED)` being called. It also attempts to call the `cancel()` method on the currently active `IAsyncTask` in the chain, if any.
-   **`is_cancelled()`**: Returns `true` if `cancel()` has been called on this context.
-   **`cancellation_reason()`**: Returns an `std::optional<std::string>` with the reason for cancellation, if provided.

Asynchronous tasks should check `ctx->is_cancelled()` in their callbacks before proceeding or calling `ctx->complete()`.

## Lifecycle Hooks

The `Context` allows registering custom functions (`LifecycleHook`) to be executed at specific points in its lifecycle. This is useful for cross-cutting concerns that need to tap into different stages of request processing without being a full middleware in the main chain.

-   **`add_lifecycle_hook(LifecycleHook hook_fn)`**: Registers a hook.
-   **`execute_hook(HookPoint point)`**: Called internally by the `Context` or `RouterCore` to trigger hooks for a given point.

`HookPoint` enum values include:

-   `PRE_ROUTING`: Before route matching.
-   `PRE_HANDLER_EXECUTION`: Before the main task chain for the matched route begins.
-   `POST_HANDLER_EXECUTION`: After the main task chain completes (normally or with error, but before any router-level error chain might run for that error).
-   `PRE_RESPONSE_SEND`: Just before the response is serialized and sent (e.g., `TimingMiddleware` uses this).
-   `POST_RESPONSE_SEND`: After the response has been sent (or attempted).
-   `REQUEST_COMPLETE`: When all processing for the request is finished and the context is about to be destroyed (e.g., `LoggingMiddleware` uses this for response logging).

```cpp
// Example: Adding a lifecycle hook
ctx->add_lifecycle_hook([](qb::http::Context<MySession>& current_ctx, qb::http::HookPoint point) {
    if (point == qb::http::HookPoint::PRE_RESPONSE_SEND) {
        current_ctx.response().set_header("X-Timestamp-PreSend", qb::http::date::now());
    }
});
```

## Context Lifecycle and Finalization

1.  **Creation**: `RouterCore` creates a `Context` for an incoming request.
2.  `PRE_ROUTING` hooks execute.
3.  **Route Matching**: Router matches path and method.
4.  **Task Chain Setup**: Based on match (or 404), an appropriate task chain (middleware + handler) is set on the context.
5.  `PRE_HANDLER_EXECUTION` hooks execute.
6.  **Task Chain Execution**: `Context` starts executing the task chain (`ctx->set_task_chain_and_start(chain)`).
    -   Each task calls `ctx->complete(AsyncTaskResult::...)`.
    -   `CONTINUE` moves to the next task.
    -   `COMPLETE` or `ERROR` (if no error chain or error chain completes) or `CANCELLED` leads to finalization.
7.  `POST_HANDLER_EXECUTION` hooks execute after the main chain (or error chain derived from it) finishes its logical processing but before the final response callback.
8.  **Finalization Callback**: The `_on_finalized_callback` (provided to `Context` by `RouterCore` during construction) is invoked. This callback is typically responsible for sending the `ctx->response()` back to the client via the `SessionType` object.
9.  `PRE_RESPONSE_SEND` hooks execute just before this callback sends the data.
10. `POST_RESPONSE_SEND` hooks (if implemented by session/transport layer, not directly by context) might execute after data is written.
11. **Destruction**: `REQUEST_COMPLETE` hooks execute when the `Context` shared_ptr is about to be destroyed.

Understanding the `Context` is key to effectively using and extending the `qb::http` routing system, especially when writing middleware or asynchronous handlers.

Previous: [Custom Middleware](./09-custom-middleware.md)
Next: [Authentication System](./11-authentication.md)

---
Return to [Index](./README.md) 
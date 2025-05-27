# 10: The Request Context (`qb::http::Context`)

The `qb::http::Context<SessionType>` object is a central and pivotal component in the `qb::http` routing and middleware system. It encapsulates all information and state related to a single HTTP request throughout its processing lifecycle. A new `Context` instance is created by the `RouterCore` for each incoming request and is passed sequentially through the chain of applicable middleware and finally to the route handler.

## Purpose of the Context

The `Context` serves several key purposes:

1.  **Data Carrier**: It holds the `qb::http::Request` and `qb::http::Response` objects, allowing middleware and handlers to inspect the request and build up the response.
2.  **Session Access**: It provides a `std::shared_ptr` to the `SessionType` object, representing the underlying client connection or session state. This allows interaction with the transport layer, for example, to send the response or close the connection.
3.  **Parameter Storage**: It stores `qb::http::PathParameters` extracted from the URI by the router during path matching (e.g., `/users/:id` -> `id = "123"`).
4.  **State Sharing**: It offers a flexible key-value store (`CustomDataMap` using `std::any`) for middleware and handlers to share arbitrary data related to the current request. This is invaluable for passing information like an authenticated user object, parsed request data, or tracing IDs between different stages of the processing chain.
5.  **Flow Control**: It is the primary means by which middleware and handlers signal their completion status and control the execution flow of the task chain using the `complete(AsyncTaskResult)` method. The `AsyncTaskResult` (e.g., `CONTINUE`, `COMPLETE`, `ERROR`) dictates whether processing continues to the next task, finalizes the response, or triggers an error handling sequence.
6.  **Cancellation Management**: It manages the cancellation state of the request processing (e.g., if the client disconnects or a timeout occurs). Middleware and handlers can check `is_cancelled()` and react accordingly. The `cancel(reason)` method can be used to programmatically stop processing.
7.  **Lifecycle Hooks**: It allows registration of `LifecycleHook` functions (`std::function<void(Context<SessionType>&, HookPoint)>`) to be executed at specific, predefined points during the request processing lifecycle. This enables modules to tap into various stages (e.g., before routing, before sending the response, after the request is fully complete) for tasks like logging, metrics, or resource management.

## Key Components of the Context

-   **`request()`**: Returns a mutable reference to the `qb::http::Request` object. This allows modification of request headers or body by middleware before it reaches the final handler.
-   **`response()`**: Returns a mutable reference to the `qb::http::Response` object. Middleware and handlers populate this object to build the response that will be sent to the client.
-   **`session()`**: Returns a `std::shared_ptr<SessionType>` to the associated session. This can be used to access session-specific data or, in advanced scenarios, interact directly with the client connection (e.g., for streaming or server-sent events, if the `SessionType` supports it).
-   **`path_parameters()`**: Returns a reference to the `qb::http::PathParameters` object, which contains values extracted from parameterized path segments (e.g., `:id` in `/users/:id`).
-   **`path_param(name, default_value)`**: A convenience method to directly access a specific URL-decoded path parameter by its name (e.g., `ctx->path_param("id")`).

### Custom Data Storage (`set`, `get`, `get_ptr`, `has`, `remove`)

Middleware and handlers can store and retrieve arbitrary, request-specific data within the context using a type-safe mechanism based on `std::any`. This is particularly useful for passing state between different middleware components or from a middleware to a route handler.

-   **`set<T>(const std::string& key, T value)`**: Stores a value of type `T` (e.g., `std::string`, `int`, `std::shared_ptr<MyUserObject>`) associated with a string `key`.
    *Example: An authentication middleware might store the authenticated user object: `ctx->set<std::shared_ptr<auth::User>>("authenticated_user", user_ptr);`*
-   **`get<T>(const std::string& key)`**: Retrieves an `std::optional<T>` for the given `key`. If the key exists and the stored value is of type `T` (or convertible), it returns the value. Otherwise, it returns `std::nullopt`. Handles `std::bad_any_cast` internally.
    *Example: A handler retrieves the user: `if (auto user_opt = ctx->get<std::shared_ptr<auth::User>>("authenticated_user")) { (*user_opt)->doSomething(); }`*
-   **`get_ptr<T>(const std::string& key)`**: Returns a raw pointer `T*` (or `const T*` for const context) to the stored data if the key exists and the type matches. Returns `nullptr` otherwise. This is useful for accessing non-copyable types stored in `std::any` or for modifying objects in place (if `T*` is non-const).
-   **`has(const std::string& key)`**: Checks if a custom data entry with the given `key` exists.
-   **`remove(const std::string& key)`**: Removes the custom data associated with `key`.

**Use Cases for Custom Data:**
-   An authentication middleware stores the `auth::User` object.
-   A JWT middleware stores the decoded JWT payload as `qb::json`.
-   A request parsing middleware stores a parsed and validated data transfer object (DTO).
-   A rate limiting middleware might store request count information temporarily.
-   A tracing middleware could store a transaction ID.

```cpp
// Middleware A: Sets user information
// Assume User struct { std::string id; std::string name; };
User authenticated_user = {"usr_123", "Alice"};
ctx->set<User>("current_user", authenticated_user);
ctx->set<std::string>("trace_id", qb::generate_random_uuid().to_string()); // Assuming uuid generation

// Middleware B or Handler: Retrieves user information
if (auto user_opt = ctx->get<User>("current_user")) {
    std::cout << "Processing for user: " << user_opt->name << std::endl;
} else {
    std::cout << "No authenticated user found in context." << std::endl;
}

if (auto trace_id_ptr = ctx->get_ptr<std::string>("trace_id")) {
    ctx->response().set_header("X-Trace-Id", *trace_id_ptr);
}
```

## Controlling the Execution Flow

The `complete(AsyncTaskResult result)` method is the **most critical** function for any `IAsyncTask` (which includes middleware and route handlers) to call. It signals the outcome of the task and dictates how the router should proceed.

-   `ctx->complete(AsyncTaskResult::CONTINUE)`: The current task has finished its work (e.g., modified the request, logged information). Processing should pass to the **next task** in the current chain (another middleware or the final route handler).
-   `ctx->complete(AsyncTaskResult::COMPLETE)`: The current task has fully handled the request and the response in `ctx->response()` is ready to be sent. **No further tasks** in the *current* processing chain (e.g., subsequent middleware or the main route handler for this route) will be executed. The response is typically sent after this.
-   `ctx->complete(AsyncTaskResult::ERROR)`: An unrecoverable error occurred within the current task. The router will halt the current processing chain and attempt to invoke a configured **error handling chain**. If no specific error chain is defined, or if an error occurs within the error chain itself, a default server error response (e.g., 500 Internal Server Error) is usually generated.
-   `ctx->complete(AsyncTaskResult::CANCELLED)`: Indicates that the request processing was cancelled (e.g., due to client disconnection, timeout detected by a supervising entity, or an explicit call to `ctx->cancel()`). This typically leads to a specific error response (e.g., 503 Service Unavailable or 499 Client Closed Request).
-   `ctx->complete(AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR)`: A rare, critical error occurred within a special handler itself (like the 404 Not Found handler or a task in the error handling chain). This results in a hardcoded, minimal 500 Internal Server Error response to prevent error loops.

**Failure to call `ctx->complete()` in every possible execution path of an `IAsyncTask::execute()` or `ICustomRoute::process()` method, especially in asynchronous operations, will lead to the request hanging indefinitely.**

## Cancellation

-   **`cancel(const std::string& reason = "Cancelled by application")`**: Initiates cancellation of the request processing. This sets an internal cancellation flag, stores the `reason`, and typically results in `complete(AsyncTaskResult::CANCELLED)` being called (often after attempting to notify the currently active task via its `cancel()` method).
-   **`is_cancelled()`**: Returns `true` if `cancel()` has been called on this context.
-   **`cancellation_reason()`**: Returns an `std::optional<std::string>` with the reason for cancellation, if one was provided.

Asynchronous tasks (e.g., those using `qb::io::async::callback` or interacting with other actors) should check `ctx->is_cancelled()` in their completion callbacks before proceeding with further processing or calling `ctx->complete()`. If cancelled, they should typically just return or clean up, as the context is already being finalized.

## Lifecycle Hooks

The `Context` allows registering custom functions (`LifecycleHook`) to be executed at specific points in its lifecycle. This is useful for cross-cutting concerns that need to tap into different stages of request processing without being a full middleware in the main chain.

-   **`add_lifecycle_hook(LifecycleHook hook_fn)`**: Registers a hook function. The function signature is `void(Context<SessionType>& context, HookPoint point)`.
-   **`execute_hook(HookPoint point)`**: Called internally by the `Context` or `RouterCore` to trigger all registered hooks for a given `HookPoint`.

`HookPoint` enum values include:

-   `PRE_ROUTING`: Before the router attempts to match the request to a route. Useful for early request modifications or logging raw requests.
-   `PRE_HANDLER_EXECUTION`: Just before the main task chain (middleware + route handler) for the matched route begins. Good for setup tasks that depend on the matched route (though route info isn't directly in context yet, path params are).
-   `POST_HANDLER_EXECUTION`: After the main task chain (or an error chain derived from it) finishes its logical processing, but before the response is sent. Useful for final modifications based on the outcome or for metrics gathering.
-   `PRE_RESPONSE_SEND`: Immediately before the `_on_finalized_callback` (which typically sends the response) is invoked. Ideal for adding final headers like `Date` or `Server`, or for `TimingMiddleware` to record the end time.
-   `POST_RESPONSE_SEND`: (Conceptual) Would be called after the response data has been successfully written to the transport. `qb-http`'s `Context` itself doesn't directly manage this; it would be part of the `SessionType` or I/O layer's responsibility.
-   `REQUEST_COMPLETE`: When all processing for the request is finished and the `Context` shared_ptr is about to be destroyed. Ideal for final logging (like `LoggingMiddleware` does for responses) or releasing request-scoped resources.

```cpp
// Example: Adding a lifecycle hook in a middleware or handler
ctx->add_lifecycle_hook([](qb::http::Context<MySession>& current_ctx, qb::http::HookPoint point) {
    if (point == qb::http::HookPoint::PRE_RESPONSE_SEND) {
        current_ctx.response().set_header("X-Request-Processed-At", qb::http::date::now());
    } else if (point == qb::http::HookPoint::REQUEST_COMPLETE) {
        // Log final request status, perhaps to an audit trail
        // std::cout << "Request to " << current_ctx.request().uri().path() 
        //           << " completed with status " << current_ctx.response().status().code() << std::endl;
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
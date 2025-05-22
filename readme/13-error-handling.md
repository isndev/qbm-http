# 13: Error Handling Strategies

Robust error handling is essential for creating reliable HTTP services. The `qb::http` routing system provides mechanisms for managing errors that occur during request processing, both from application logic and within the routing infrastructure itself.

## Signaling Errors from Handlers and Middleware

Tasks within the request processing chain (route handlers or middleware) can signal an error by calling `ctx->complete(AsyncTaskResult::ERROR)` on the `qb::http::Context` object.

```cpp
// Example: Route handler signaling an error
router.get("/items/:id", [](auto ctx) {
    std::string item_id = ctx->path_param("id");
    std::optional<Item> item = find_item_by_id(item_id);

    if (!item) {
        ctx->response().status() = qb::http::status::NOT_FOUND; // 404
        // It's good practice to set an appropriate status on the response
        // before signaling ERROR, so the error handler has context.
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
        return;
    }
    // ... process item ...
    ctx->response().body() = item->to_json_string();
    ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
});
```

When `AsyncTaskResult::ERROR` is signaled:

1.  The current processing chain (e.g., the sequence of global, group, controller middleware and the route handler) is typically halted.
2.  The `RouterCore` then attempts to invoke a configured **error handling chain**.

## The Router's Error Handling Chain

The `qb::http::Router` allows you to define a specific chain of `IAsyncTask`s (usually middleware) to handle errors. This is set using `router.set_error_task_chain(std::list<std::shared_ptr<IAsyncTask<SessionType>>> error_chain)`.

-   If an error chain is set, it will be executed when a task in the normal processing flow calls `ctx->complete(AsyncTaskResult::ERROR)`.
-   Middleware in the error chain can inspect `ctx->response().status()` (which might have been set by the task that signaled the error) and `ctx->get<std::string>("__error_message")` (if set by the original erroring task or context) to customize the error response.
-   The error handling chain is responsible for ultimately calling `ctx->complete(AsyncTaskResult::COMPLETE)` to send the final error response, or it could potentially signal `ERROR` again if it encounters an issue (which would lead to a fatal error response).

```cpp
// Example: Setting a simple error handling chain
auto error_response_formatter = std::make_shared<MyErrorFormattingMiddleware>();
std::list<std::shared_ptr<qb::http::IAsyncTask<MySession>>> error_tasks;
error_tasks.push_back(
    std::make_shared<qb::http::MiddlewareTask<MySession>>(error_response_formatter)
);
router.set_error_task_chain(error_tasks);
```

If no error handling chain is explicitly set via `set_error_task_chain`, or if the set chain is empty, the `RouterCore` will typically finalize the request with a default HTTP 500 Internal Server Error response, using any status and body already present in `ctx->response()` if set by the erroring task.

### `qb::http::ErrorHandlingMiddleware`

A standard middleware, `qb::http::ErrorHandlingMiddleware` (see `http/middleware/error_handling.h` and [Standard Middleware](./08-standard-middleware.md)), is provided to simplify the creation of sophisticated error responses. It is typically the primary (or only) task in the router's error handling chain.

This middleware allows you to register specific handlers for:

-   Exact HTTP status codes (e.g., a handler for 404, another for 403).
-   Ranges of HTTP status codes (e.g., a handler for all 5xx errors).
-   A generic fallback handler for any error not caught by more specific handlers.

```cpp
// In server setup:
auto error_mw = qb::http::error_handling_middleware<MySession>();

error_mw->on_status(qb::http::status::NOT_FOUND, [](auto ctx) {
    ctx->response().body() = R"({"error": "Resource was not found", "code": 404})" ;
    ctx->response().set_content_type("application/json");
    // ErrorHandlingMiddleware calls complete(COMPLETE) after this lambda
});

error_mw->on_status_range(qb::http::status::BAD_REQUEST, qb::http::status::UNSUPPORTED_MEDIA_TYPE, // 400-4xx client errors
    [](auto ctx) {
        ctx->response().body() = "Client Error: " + std::to_string(ctx->response().status().code());
    }
);

error_mw->on_any_error([](auto ctx, const std::string& message_from_context) {
    ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR; // Ensure it's 500 if not set
    ctx->response().body() = "A generic server error occurred: " + message_from_context;
});

std::list<std::shared_ptr<qb::http::IAsyncTask<MySession>>> error_chain;
error_chain.push_back(std::make_shared<qb::http::MiddlewareTask<MySession>>(error_mw));
router.set_error_task_chain(error_chain);
```

The `ErrorHandlingMiddleware` inspects `ctx->response().status()` and dispatches to the most appropriate registered handler. After the chosen handler executes (and potentially modifies `ctx->response()`), `ErrorHandlingMiddleware` calls `ctx->complete(AsyncTaskResult::COMPLETE)`.

## Unhandled Exceptions

-   **Exceptions from Middleware/Handlers**: If an `IMiddleware::process` or `ICustomRoute::process` method (or a lambda handler) throws an exception that is not caught within the handler itself, the `MiddlewareTask` or `CustomRouteAdapterTask` (or `RouteLambdaTask`) wrapper provided by the routing system is designed to catch these exceptions. When caught, the adapter task will typically:
    1.  Set `ctx->response().status()` to HTTP 500 Internal Server Error.
    2.  Optionally set a generic error message in `ctx->response().body()`.
    3.  Call `ctx->complete(AsyncTaskResult::ERROR)`.
    This then triggers the router's configured error handling chain as described above.

-   **Exceptions from Error Handling Chain**: If a task within the error handling chain itself signals `AsyncTaskResult::ERROR` or throws an unhandled exception, this is considered a fatal error in error processing. The `RouterCore` will then typically finalize the request with a hardcoded, minimal HTTP 500 Internal Server Error response to prevent infinite error loops. The `AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR` is used in such cases.

-   **Exceptions from `Context` methods or Router internals**: These are generally indicative of programming errors or unexpected system states and might lead to less graceful termination or behavior depending on the context of the qb-Actor system they run in.

## Flow Control during Errors

It's important to understand how `AsyncTaskResult::ERROR` interacts with the processing flow:

1.  A task (M1) in the normal chain `[GlobalM, M1, M2, RouteH]` calls `ctx->complete(AsyncTaskResult::ERROR)`.
2.  The `Context` stops processing the normal chain. M2 and RouteH are **not** executed.
3.  The `Context` (via `RouterCore`) switches to the configured error handling chain, e.g., `[ErrorFormattingMW, ErrorLoggingMW]`.
4.  `ErrorFormattingMW` runs. It might call `ctx->complete(AsyncTaskResult::CONTINUE)`.
5.  `ErrorLoggingMW` runs. It should ideally call `ctx->complete(AsyncTaskResult::COMPLETE)` to send the formatted error response.

If an error handler also signals `ERROR`, it can lead to the `FATAL_SPECIAL_HANDLER_ERROR` state mentioned earlier.

## Best Practices for Error Handling

-   **Set Specific Status Codes**: Before signaling `AsyncTaskResult::ERROR`, set an appropriate HTTP status code on `ctx->response()` (e.g., 400 for bad input, 404 for not found, 403 for forbidden, 500 for server issues). This gives the error handling chain more context.
-   **Use `ErrorHandlingMiddleware`**: Leverage `ErrorHandlingMiddleware` for consistent and customizable error responses.
-   **Avoid Throwing Exceptions from Handlers/Middleware**: Prefer to catch internal exceptions and translate them into an appropriate `ctx->complete(AsyncTaskResult::ERROR)` call with a relevant status code set on the response. This allows the router's error handling chain to take over gracefully.
-   **Keep Error Handlers Simple**: Error handlers themselves should be robust and avoid complex logic that might also fail.
-   **Log Errors**: Ensure that server-side errors are logged appropriately, either within the erroring task or within the error handling chain, to aid in debugging.

By combining these mechanisms, you can build a resilient error handling strategy for your `qb::http` application.

Previous: [Validation System](./12-validation.md)
Next: [Asynchronous HTTP Client](./14-async-http-client.md)

---
Return to [Index](./README.md) 
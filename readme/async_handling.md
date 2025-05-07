# `qbm-http`: Asynchronous Request Handling

(`routing/async_completion_handler.h`, `routing/async_types.h`)

A key feature of `qbm-http` is its ability to handle requests asynchronously, preventing route handlers from blocking the server's event loop thread (`VirtualCore`). This is crucial for performance when handlers need to perform I/O operations (database queries, calls to other services) or long computations.

## The Problem with Blocking Handlers

Synchronous route handlers execute entirely within the `VirtualCore`'s event loop. If a handler performs a blocking operation:

```cpp
router.get("/blocking", [](Context& ctx) {
    // BAD: This blocks the entire VirtualCore!
    auto db_result = synchronous_database_query("SELECT ...");
    std::this_thread::sleep_for(std::chrono::seconds(5)); // Also bad!

    ctx.response.body() = format_result(db_result);
    ctx.complete();
});
```

The `VirtualCore` running this handler cannot process *any* other requests or events for *any* other actor or session assigned to it until the blocking operation completes. This severely limits concurrency and throughput.

## The Asynchronous Solution

The router provides a mechanism to defer sending the response while the handler performs work asynchronously.

**1. Mark the Request as Async:**

Inside your route handler, call `ctx.make_async()`:

```cpp
router.get("/async-task", [](Context& ctx) {
    // 1. Mark as async & get completion handler
    auto completion_handler_ptr = ctx.make_async();
    if (!completion_handler_ptr) {
        // Handle error: router might not be available, or other issue
        ctx.response.status_code = HTTP_STATUS_INTERNAL_SERVER_ERROR;
        ctx.response.body() = "Failed to initialize async operation";
        ctx.complete();
        return;
    }

    // ... rest of the handler, using completion_handler_ptr->method() ...
});
```

*   This tells the router **not** to send a response automatically when the handler function returns.
*   It registers the request context (`ctx`) with the router's internal tracking for active asynchronous requests.
*   It returns a `std::shared_ptr<AsyncCompletionHandler<Session, String>>` (or `nullptr` if it fails, e.g. if the router pointer in context is null).

**2. Perform Asynchronous Work:**

Use mechanisms like `qb::io::async::callback` (if running within `qb-core`) or other asynchronous libraries (e.g., database client async APIs) to schedule the actual work.

```cpp
router.get("/async-task", [](Context& ctx) {
    auto completion = ctx.make_async();
    if (!completion) { /* ... error handling ... */ return; }

    std::string user_id = ctx.get<std::string>("user_id"); // From auth middleware

    // 2. Schedule async work (e.g., using qb::io::async::callback)
    qb::io::async::callback([completion, user_id]() mutable {
        // --- This lambda executes later on the event loop --- 

        // Perform the potentially long-running operation (e.g., DB query)
        // In a real scenario, this itself might be asynchronous!
        std::string result = fetch_user_data_from_db(user_id);

        // 3. Use the completion handler to send the response
        completion->status(HTTP_STATUS_OK)
                  .header("Content-Type", "application/json")
                  .body(result) // Assuming result is JSON string
                  .complete();

        // IMPORTANT: 'completion' handler should be moved or copied into the async lambda
        // to ensure it stays alive until complete() is called.

    }, 0.0); // Schedule immediately (or with delay)
});
```

**3. Complete the Request:**

Once the asynchronous operation finishes, use the captured `std::shared_ptr<AsyncCompletionHandler>` object (`completion` in the example) to build and send the final response.

*   **`completion->status(code)`:** Sets the HTTP status code.
*   **`completion->header(name, value)`:** Adds response headers.
*   **`completion->body(content)`:** Sets the response body.
*   **`completion->complete()`:** Sends the response and signals the router that the asynchronous request is finished.
*   **`completion->cancel(status_code, message)`:** Sends an error response and signals cancellation.
*   **`completion->is_session_connected()`:** Check if the client is still connected before attempting to send the response.

## Asynchronous Middleware

Middleware can also be asynchronous using the `IAsyncMiddleware` interface or the async function signature with `qb::http::make_middleware`.

```cpp
// Example using the functional approach
router.use(qb::http::make_middleware<MySession>(
    [](Context& ctx, qb::http::IMiddleware<MySession>::CompletionCallback next) {
        // Start an async operation
        perform_async_check(ctx.request.header("Some-Header"),
            [&ctx, next](bool check_passed) {
                if (check_passed) {
                    ctx.set<bool>("check_passed", true);
                    next(MiddlewareResult::Continue()); // Continue chain
                } else {
                    ctx.response.status_code = HTTP_STATUS_BAD_REQUEST;
                    ctx.response.body() = "Async check failed";
                    ctx.mark_handled();
                    next(MiddlewareResult::Stop()); // Stop chain
                }
            }
        );
    },
    "MyAsyncMiddleware"
));
```

*   The middleware function receives the `Context` and a `CompletionCallback` named `next`.
*   Inside the async operation's callback, `next(MiddlewareResult)` is called to signal completion and whether the chain should continue or stop.

## Timeout Handling

(`routing/router.h`)

*   The router automatically tracks active asynchronous requests.
*   Use `router.configure_async_timeout(seconds)` to set a global timeout (default is 60 seconds).
*   If an `AsyncCompletionHandler`'s `complete()` method is not called within the timeout period, the router will:
    1.  Send an `HTTP_STATUS_REQUEST_TIMEOUT` (408) response to the client.
    2.  Remove the request from its internal tracking.
*   Use `router.force_timeout_all_requests()` to manually time out all pending async requests (e.g., during shutdown).
*   Use `router.clean_disconnected_sessions()` periodically or on disconnect events to remove tracked requests whose clients have disconnected.

## Cancellation

(`routing/router.h`)

*   `router.cancel_request(context_id)`: Mark a specific async request (identified by its context pointer cast to `uintptr_t`) as cancelled.
*   `router.is_request_cancelled(context_id)`: Check if a request has been marked for cancellation.
*   When `AsyncCompletionHandler::complete()` is called for a cancelled request, the router simply removes the request without sending the potentially computed response.
*   Alternatively, the `AsyncCompletionHandler` can call `complete_with_state(AsyncRequestState::CANCELED)` to signal cancellation explicitly, potentially after sending a specific cancellation response (e.g., 499 Client Closed Request).

**(See also:** `test-router-async-advanced.cpp`, `test-router-async-middleware.cpp`**)** 
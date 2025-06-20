# 16: Advanced Topics & Best Practices

This section covers advanced usage patterns, performance considerations, and best practices when working with the `qb::http` module.

## Performance Considerations

-   **`string_view` Usage**: `RequestView` and `ResponseView` utilize `std::string_view` for header values and potentially for body representation. This avoids string allocations and copies when parsing incoming data, offering significant performance benefits, especially for read-only access to request data.

-   **`qb::allocator::pipe<char>`**: The `qb::http::Body` class uses `qb::allocator::pipe<char>` for its internal buffer. This is a specialized allocator designed for efficient I/O, minimizing reallocations when building or consuming message bodies.

-   **Asynchronous Operations**: Leverage the asynchronous nature of route handlers and middleware, especially for I/O-bound tasks (database queries, external API calls). Use `qb::io::async::callback` or integrate with the actor model to prevent blocking the `VirtualCore`'s event loop.
    -   When an async operation is initiated, capture the `std::shared_ptr<Context<SessionType>> ctx` and call `ctx->complete()` in the async operation's callback.

-   **Middleware Selectivity**: Apply middleware judiciously. Global middleware runs for every request. Group-level or controller-level middleware offers better scoping. Use conditional middleware if certain processing is only needed for a subset of requests matching a broader pattern.

-   **Route Compilation**: The `router.compile()` step is crucial. It builds an optimized `RadixTree` for fast path matching. Ensure it's called once after all routes are defined and before the server starts accepting requests. Re-compiling frequently at runtime is not an intended use case for a hot path.

## `string_view` and Lifetime Management

When using `RequestView` or `ResponseView`, or when `qb::http::Body::as<std::string_view>()` is called, be mindful of the lifetime of the underlying data:

-   The `std::string_view`s obtained are non-owning. They point to data within the original request buffer or the `Body`'s internal pipe.
-   If the original buffer is released or the `Body` object is modified or destroyed, these `string_view`s will become dangling pointers, leading to undefined behavior.
-   Typically, within the scope of a single synchronous request handler or middleware `process` call, using `string_view` is safe.
-   If you need to store data from a `string_view` beyond the lifetime of the original data source (e.g., in an asynchronous callback that outlives the request buffer), copy it into a `std::string`.

## Efficient Body Handling

-   **Streaming**: For very large request or response bodies, consider streaming approaches if the underlying `qb-io` transport and protocol layers support it. The current high-level `qb::http::Body` typically accumulates the full body in memory.
-   **`Body::raw()`**: For direct, low-level access to the internal `qb::allocator::pipe<char>`, use `body.raw()`. This can be useful for custom serialization/deserialization or when integrating with libraries that operate on raw character buffers.
-   **Move Semantics**: Utilize `std::move` when assigning `std::string` or `std::vector<char>` to `qb::http::Body` to avoid unnecessary copies if the source object is an rvalue or no longer needed.

    ```cpp
    std::string large_json_payload = generate_large_json();
    request.body() = std::move(large_json_payload); // Efficiently moves content
    ```

## HTTP Chunked Transfer Encoding

The `qb::http::Chunk` class (`http/chunk.h`) represents a single chunk in an HTTP message using chunked transfer encoding.

For HTTP/1.1, `Transfer-Encoding: chunked` is handled by the transport layer. The `qb::http::Parser` transparently assembles incoming chunked request bodies.
For outgoing responses, if `Transfer-Encoding: chunked` is set and `Content-Length` is not, the HTTP/1.1 server session will typically send the body in chunks.

HTTP/2 does not use chunked transfer encoding in the same way as HTTP/1.1. Its own framing mechanism (DATA frames with END_STREAM flag) achieves similar streaming capabilities.

## Custom `ICustomRoute` vs. Lambdas

-   **Lambdas**: Excellent for concise, often stateless handlers. Ideal for simple endpoints.
-   **`ICustomRoute`**: Preferable for:
    -   Complex logic that benefits from class structure.
    -   Stateful handlers (though state should generally be request-specific or carefully managed if shared).
    -   Handlers with multiple dependencies that can be injected via the constructor.
    -   Improving testability by isolating handler logic into a dedicated class.
    -   Reusing handler logic across different routes or with different configurations.

## Managing Asynchronous Operations in Handlers/Middleware

When a handler or middleware initiates an asynchronous operation (e.g., using `qb::io::async::callback`, or sending a message to another actor and awaiting a reply), it's crucial to manage the `Context` lifecycle correctly:

1.  **Capture `ctx`**: Capture the `std::shared_ptr<qb::http::Context<SessionType>> ctx` by value in the lambda or callback for the asynchronous operation.

    ```cpp
    // In an IAsyncTask::execute or ICustomRoute::process method
    auto shared_ctx = ctx; // Capture by value for the async callback
    _my_async_service->perform_operation([shared_ctx](ResultType result) {
        // Check if context is still valid/not cancelled before proceeding
        if (shared_ctx->is_cancelled()) {
            // Potentially log that work was done but context cancelled
            return; 
        }
        // ... process result ...
        shared_ctx->response().body() = process_result(result);
        shared_ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    });
    // The handler/middleware method returns here; a task is now pending.
    ```

2.  **Call `ctx->complete()`**: The callback of the asynchronous operation **must** call `shared_ctx->complete()` with the appropriate `AsyncTaskResult`. Failure to do so will leave the HTTP request hanging.

3.  **Cancellation**: If the asynchronous operation is cancellable, the `cancel()` method of your `IMiddleware` or `ICustomRoute` should attempt to cancel it. The asynchronous callback should also check `shared_ctx->is_cancelled()` before proceeding with processing the result or calling `complete()`.

## Advanced SSL/TLS and HTTP/2 Considerations

-   **ALPN (Application-Layer Protocol Negotiation)**: When using HTTPS, ALPN is essential for HTTP/2. The `qb::http2::Server` and `qb::http2::Client` are designed to use ALPN to negotiate "h2". Ensure your SSL/TLS setup (certificates, server configuration) supports ALPN if HTTP/2 is desired. Refer to the [HTTPS/SSL/TLS documentation](./18-https-ssl-tls.md) for more details.
-   **HTTP/2 Server Push**: While the HTTP/2 protocol supports server push, direct, high-level application control for initiating server pushes from within `qb::http2::Server` handlers might require specific patterns or may be a feature for future enhancement. The underlying `qb::protocol::http2::ServerHttp2Protocol` has methods like `send_push_promise` for protocol-level interaction.
-   **HTTP/2 Flow Control**: HTTP/2 has its own flow control mechanisms (WINDOW_UPDATE frames) at both the connection and stream levels. The `qb::http2::Client` and the underlying `qb::protocol::http2::*` protocol handlers manage this automatically. Default window sizes are usually sufficient, but can be tuned via SETTINGS frames if needed.
-   **HPACK Context Synchronization**: Header compression in HTTP/2 (HPACK) is stateful. Both client and server maintain dynamic tables. The `qb-http` HPACK implementation (`qb::protocol::hpack`) handles this. Issues with HPACK (e.g., compression errors, desynchronization) can lead to connection errors (`COMPRESSION_ERROR`).

## Thread Safety

-   **Router, RouteGroup, Controller**: These objects are generally not thread-safe for modification after `router.compile()` has been called and the router is actively serving requests. Route definitions should occur during a setup phase, typically single-threaded.
-   **Context**: Each `Context` object is typically confined to the `VirtualCore` (thread) processing its request. Middleware and handlers operating on a specific `Context` instance usually don't need to worry about concurrent access *to that context* from other threads.
-   **Shared State**: If middleware or handlers access shared state (e.g., global caches, shared service clients that are not actor-based), standard C++ synchronization primitives (mutexes, atomics) or actor-based synchronization must be used.
-   **Custom `IMiddleware` / `ICustomRoute` Instances**: If a `std::shared_ptr` to the *same instance* of a stateful middleware or custom route is used for multiple route definitions, its `process()` method must be thread-safe or reentrant if requests for those routes can be processed concurrently on different `VirtualCore`s. It's often safer for such shared instances to be stateless or manage their state carefully.

This concludes the initial documentation set for the `qb::http` module. Further deep dives into specific standard middleware or advanced `qb-io` integration patterns could expand upon this foundation.

Previous: [HTTP Message Parsing](./15-http-parsing.md)

---
Return to [Index](./README.md) 
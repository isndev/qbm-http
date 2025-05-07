# `qbm-http`: Core Concepts

This document outlines the fundamental classes and concepts within the `qbm-http` module.

## Request & Response Model

HTTP interactions are modeled using two primary classes:

*   **`qb::http::Request` / `TRequest<String>` (`request.h`):** Represents an incoming (server-side) or outgoing (client-side) HTTP request.
    *   **Key Members:** `method` (`http_method`), `uri()` (`qb::io::uri`), `headers()` (`qb::http::headers_map`), `body()` (`qb::http::Body`), `cookies()` (`qb::http::CookieJar`).
    *   Provides methods for accessing URI components (`path()`, `query()`), headers (`header()`, `has_header()`), cookies (`cookie()`, `cookie_value()`), and the request body (`body().as<T>()`).
    *   Template parameter `String` can be `std::string` (default, mutable) or `std::string_view` (read-only, potentially more performant).
*   **`qb::http::Response` / `TResponse<String>` (`response.h`):** Represents an outgoing (server-side) or incoming (client-side) HTTP response.
    *   **Key Members:** `status_code` (`http_status`), `status` (reason phrase string, optional), `headers()`, `body()`, `cookies()` (`CookieJar` for *setting* response cookies).
    *   Provides methods for setting status, headers (`add_header()`, `set_header()`), cookies (`add_cookie()`, `remove_cookie()`), and the response body.

**(See also:** [`request_response.md`](./request_response.md)**)**

## Routing (`qb::http::Router` and `qb::http::RouterContext`)

(`routing/router.h`, `routing/route_types.h`, `routing/context.h`)

The `Router` is the core component for mapping incoming server requests to specific handler logic based on the HTTP method and URI path. The `RouterContext` (often aliased as `Context`) encapsulates the request, response, session, and routing-specific data for each request.

*   **Route Definition:** Routes are registered using methods like `router.get("/path", handler)`, `router.post(...)`, etc.
*   **Handlers:** Can be lambda functions, function pointers, or functors taking a `Context& ctx`.
*   **Path Parameters:** Defined using `:name` syntax (e.g., `/users/:id`) and accessed via `ctx.param("id")`.
*   **Route Groups:** Organize routes under a common path prefix and apply middleware to the group.
*   **Controllers:** Class-based organization for related routes under a base path.
*   **Matching:** Uses efficient Radix Tree matching by default for performance, with regex fallback.

**(See also:** [`routing.md`](./routing.md)**)**

## Middleware (`qb::http::IMiddleware`)

(`middleware/middleware_interface.h`, `middleware/middleware_chain.h`)

Middleware provides a mechanism to intercept and process requests and responses in a chain before or after the main route handler executes. Middleware functions also operate on the `RouterContext`.

*   **Purpose:** Used for cross-cutting concerns like logging, authentication, authorization, validation, CORS, rate limiting, request/response transformation, etc.
*   **Types:** Supports both **synchronous** (`ISyncMiddleware`) and **asynchronous** (`IAsyncMiddleware`) middleware, unified under `IMiddleware`. Adapters like `SyncMiddlewareAdapter` and `AsyncMiddlewareAdapter` facilitate their use.
*   **Chaining:** Middleware functions are executed sequentially via `MiddlewareChain`. A middleware can choose to:
    *   **Continue:** Pass control to the next middleware or handler (e.g., `MiddlewareResult::Continue()`).
    *   **Stop:** Handle the request completely and prevent further processing (e.g., `MiddlewareResult::Stop()`).
    *   **Error:** Signal an error condition (e.g., `MiddlewareResult::Error("message")`).
*   **Context Sharing:** Middleware functions share the same `RouterContext` object, allowing them to pass data between each other (e.g., `ctx.set("user", user_object)`).

**(See also:** [`middleware.md`](./middleware.md), [`builtin_middleware.md`](./builtin_middleware.md)**)**

## Asynchronous Handling

(`routing/async_completion_handler.h`, `routing/async_types.h`, `routing/context.h`)

Route handlers and asynchronous middleware can perform non-blocking operations.

*   **`RouterContext::make_async()`:** Marks the request context as asynchronous, preventing the router from sending an immediate response. It returns a `std::shared_ptr<AsyncCompletionHandler<Session, String>>`.
*   **`AsyncCompletionHandler`:** This handler *must* be captured (e.g., in a lambda) and used later to send the response via its methods like `status()`, `header()`, `body()`, and finally `complete()` or `cancel()`.
*   **Integration:** Typically used with `qb::io::async::callback` or actor message passing to perform background work and then call the `AsyncCompletionHandler` methods when the result is ready.
*   **Timeouts:** The `Router` manages timeouts for async requests (`configure_async_timeout`), automatically sending a timeout response if `complete()` isn\'t called within the configured duration.

**(See also:** [`async_handling.md`](./async_handling.md)**)**

## Server and Session

(`http.h`, integration with `qb/io/async/tcp/server.h`, `qb/io/async/tcp/client.h`)

The `qbm-http` module integrates with `qb-io` server components to handle HTTP communication.

*   **`qb::http::use<...>::server<SessionType>`:** A CRTP base class template for the main server logic. It typically combines an underlying `qb-io` TCP or SSL server (which includes an `acceptor` for new connections and an `io_handler` for managing sessions) with the HTTP `Router`.
*   **`qb::http::use<...>::session<ServerType>`:** A CRTP base class template for handling individual client connections (sessions). It typically inherits from a `qb-io` client transport (like `qb::io::async::tcp::client`) and integrates an HTTP protocol parser (like `qb::protocol::http_server` or `qb::protocol::http_server_view`).
*   **Workflow:** The `server` component listens for and accepts new connections. For each connection, it creates a `session` instance. The `session` then uses its internal HTTP protocol parser to parse incoming byte streams into `Request` objects. These `Request` objects, along with the session and response objects, are encapsulated in a `RouterContext` and passed to the `server`'s `router` for processing by the appropriate route handlers or middleware.

## Key Utilities

*   **`qb::http::Cookie` / `CookieJar` (`cookie.h`):** Managing HTTP cookies.
*   **`qb::http::Multipart` / `MultipartView` (`multipart.h`):** Handling `multipart/form-data`.
*   **`qb::http::date` (`date.h`):** Parsing and formatting HTTP-compliant dates.
*   **`qb::http::utility` (`utility.h`):** Helper functions for string splitting, case-insensitive comparison etc. 
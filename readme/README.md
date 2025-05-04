# `qbm-http` - Detailed Documentation

Welcome to the detailed documentation for the `qbm-http` module of the QB C++ Actor Framework.

This section provides in-depth information on the various components and functionalities of the HTTP module. Please refer to the main [qbm-http README](../README.md) for a general overview and quick start examples.

## Table of Contents

Below is a list of detailed documents covering specific aspects of the `qbm-http` module:

*   **Core Concepts:**
    *   [Core Concepts](./core_concepts.md): Fundamental ideas (Request/Response, Routing, Middleware, Async).
    *   [Request & Response](./request_response.md): Details on `Request`, `Response`, `Headers`, `Body` classes.
    *   [Routing System](./routing.md): In-depth look at the router, path parameters, groups, controllers, and Radix Tree matching.
    *   [Middleware](./middleware.md): Explains the middleware concept, chain execution, synchronous vs. asynchronous middleware, and how to create custom middleware.
    *   [Asynchronous Handling](./async_handling.md): Covers handling long-running tasks in route handlers using `make_async` and `AsyncCompletionHandler`, including timeouts and cancellation.
    *   [Cookie Management](./cookies.md): Details on parsing, creating, and managing HTTP cookies using `Cookie` and `CookieJar`.
    *   [Multipart/form-data Handling](./multipart.md): Parsing and creating multipart messages.
*   **Built-in Components:**
    *   [Built-in Middleware](./builtin_middleware.md): Documentation for provided middleware like CORS, Logging, Rate Limiting, etc.
    *   [Authentication & Authorization](./authentication.md): Details on the `AuthManager`, JWT integration, and the `AuthMiddleware`.
    *   [Validation](./validation.md): How to use the `Validator` system, JSON Schema, query parameter validation, and sanitizers.
*   **Client & Server:**
    *   [HTTP Client](./client.md): Using the global functions (`qb::http::GET`, `POST`, etc.) for making requests.
    *   [HTTP Server](./server.md): Building servers using the `use<...>::server` and `use<...>::session` templates.
*   **Utilities & Reference:**
    *   [Utilities](./utils.md): Covers `qb::http::date`, `qb::http::utility`, and other helpers.
    *   [Dependencies](./dependencies.md): Lists the required and optional dependencies for the module. 
# `qbm-http`: HTTP Client

(`qbm/http/http.h`)

The HTTP module provides functions for making both synchronous and asynchronous HTTP requests.

## Making Requests

The primary way to make requests is using the global functions corresponding to HTTP methods (GET, POST, PUT, DELETE, etc.).

**Key Functions:**

*   `qb::http::GET(Request& req, [Callback cb], [double timeout])`
*   `qb::http::POST(Request& req, [Callback cb], [double timeout])`
*   `qb::http::PUT(Request& req, [Callback cb], [double timeout])`
*   `qb::http::DEL(Request& req, [Callback cb], [double timeout])`
*   `qb::http::OPTIONS(Request& req, [Callback cb], [double timeout])`
*   `qb::http::HEAD(Request& req, [Callback cb], [double timeout])`
*   `qb::http::PATCH(Request& req, [Callback cb], [double timeout])`
*   `qb::http::REQUEST(Request& req, [Callback cb], [double timeout])` (For custom methods)

**Parameters:**

*   `req`: A `qb::http::Request` object containing the method (usually overwritten by the function name, except for `REQUEST`), URI, headers, and body.
*   `cb` (Optional): A callback function (lambda, `std::function`, etc.) for **asynchronous** requests. It receives a `qb::http::async::Reply&&` object.
*   `timeout` (Optional): A timeout in seconds (as a `double`) for the request. Defaults to 3 seconds for synchronous requests.

**Return Value:**

*   **Synchronous (no callback provided):** Returns a `qb::http::Response` object. Throws `std::exception` (or derived) on connection errors or timeouts.
*   **Asynchronous (callback provided):** Returns `void`. The result is delivered later via the callback function.

## `qb::http::Request` Object

(`qbm/http/request.h`)

Before making a request, you construct a `Request` object:

```cpp
#include <qb/http.h>

// Create request for GET
qb::http::Request get_req("https://api.example.com/data?id=123");
get_req.add_header("Accept", "application/json");
get_req.add_header("User-Agent", "My QB Client/1.0");

// Create request for POST with JSON body
qb::http::Request post_req("https://api.example.com/users");
post_req.method = HTTP_POST; // Set method (optional for POST func, mandatory for REQUEST)
post_req.add_header("Content-Type", "application/json");

qb::json post_body;
post_body["name"] = "Alice";
post_body["role"] = "user";
post_req.body() = post_body; // Assign JSON object to body
```

## Synchronous Client Example

Blocks the calling thread until the response is received or timeout occurs.

```cpp
#include <http/http.h>
#include <qb/io.h>
#include <iostream>

try {
    qb::http::Request req("http://httpbin.org/get");
    req.add_header("X-Custom", "SyncTest");

    qb::http::Response res = qb::http::GET(req, 5.0); // 5 second timeout

    if (res.status_code == HTTP_STATUS_OK) {
        qb::io::cout() << "Sync Response Status: " << res.status_code << std::endl;
        // Access headers (case-insensitive)
        qb::io::cout() << "Sync Content-Type: " << res.header("content-type") << std::endl;
        // Access body as string
        qb::io::cout() << "Sync Body: " << res.body().as<std::string>() << std::endl;
    } else {
        qb::io::cout() << "Sync Request failed with status: " << res.status_code << std::endl;
    }

} catch (const std::exception& e) {
    qb::io::cout() << "Sync Request Error: " << e.what() << std::endl;
}
```

## Asynchronous Client Example

Does not block. Requires an event loop (like `qb::io::async::run()` or the one inside `qb-core`) to process the callback.

```cpp
#include <http/http.h>
#include <qb/io.h>
#include <iostream>
#include <atomic>

std::atomic<bool> async_done = false;

qb::http::Request req("http://httpbin.org/post");
req.method = HTTP_POST;
req.add_header("Content-Type", "application/x-www-form-urlencoded");
req.body() = "key=value&another=param";

qb::http::POST(req, [](qb::http::async::Reply&& reply) {
    // This lambda executes when the response arrives
    qb::io::cout() << "--- Async POST Response ---" << std::endl;
    qb::io::cout() << "Status: " << reply.response.status_code << std::endl;
    qb::io::cout() << "Body: " << reply.response.body().as<std::string>() << std::endl;

    // Signal completion
    async_done = true;
});

qbi::io::cout() << "Async request sent. Waiting for response..." << std::endl;

// Run the event loop to process the callback
// In a real app, this might be part of the main loop or QB engine
while (!async_done) {
    qb::io::async::run(EVRUN_ONCE); // Process events once
    std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Prevent busy-waiting
}
```

*   The callback receives `qb::http::async::Reply&&` which contains `request` (the original request) and `response`.

## HTTPS (SSL/TLS)

*   **Requirement:** `QB_IO_WITH_SSL=ON` must be enabled during build.
*   **Usage:** Simply use a URI with the `https://` scheme. The client automatically attempts an SSL/TLS connection.
    ```cpp
    qb::http::Request req("https://google.com");
    auto res = qb::http::GET(req);
    // ... process response ...
    ```
*   **Certificate Verification:** Default behavior depends on the underlying OpenSSL configuration. For production, ensure proper CA certificate setup or provide custom verification callbacks if needed (advanced usage, not directly exposed by these high-level functions).

## Content Compression

*   **Requirement:** `QB_IO_WITH_ZLIB=ON` must be enabled during build.
*   **Request:** The client automatically adds an `Accept-Encoding: gzip, deflate` (or similar) header to requests.
*   **Response:** If the server responds with a `Content-Encoding` header (e.g., `gzip`) and the corresponding algorithm is supported, the client automatically **decompresses** the response body before making it available via `response.body().as<T>()`.

## Under the Hood

These functions internally use `qb::http::async::HTTP` or `qb::http::async::HTTPS` session classes (`http.h`) which are derived from `qb::io::async::tcp::client` (or `ssl::client`) and `qb::protocol::http_client`. They manage the connection, request sending, response parsing, and callback invocation. 
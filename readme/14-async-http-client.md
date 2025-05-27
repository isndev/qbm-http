# 14: Asynchronous HTTP Client (`qb::http::async`)

The `qb::http` module includes a powerful asynchronous HTTP client, located in the `qb::http::async` namespace, designed for making non-blocking HTTP/1.1 requests. This client is built on top of the `qb-io` asynchronous I/O layer, making it efficient for applications that need to perform many concurrent outbound HTTP calls without dedicating a thread per request.

It supports:
-   HTTP and HTTPS (if `QB_IO_WITH_SSL` is enabled).
-   Standard HTTP methods (GET, POST, PUT, DELETE, etc.).n-   Custom headers, request bodies.
-   Automatic `Accept-Encoding` header for supported compressions (e.g., gzip, deflate if `QB_IO_WITH_ZLIB` is enabled).
-   Automatic decompression of response bodies if `Content-Encoding` is present and supported.
-   Connection timeouts.

## Core Client Usage

The client offers two main ways to make requests, both stemming from functions available directly under the `qb::http` namespace (e.g., `qb::http::GET`, `qb::http::POST`) which are defined in `http/http.h` and implemented in `http/http.cpp`.

1.  **Asynchronous Calls with Callbacks**: This is the native non-blocking way. You provide a callback function that will be invoked when the HTTP response is received or an error occurs.
2.  **Synchronous-Style Calls**: These are convenience wrappers around the asynchronous calls. They block the calling thread until the response is received or a timeout occurs, returning the `qb::http::Response` directly. These are useful for simpler scenarios or when integrating with synchronous code, but should be used judiciously in highly concurrent actors to avoid blocking their event processing.

### Preparing a Request (`qb::http::Request`)

Before making a call, you construct a `qb::http::Request` object:

```cpp
#include <http/http.h>
#include <qb/io/uri.h>

// Create a GET request
qb::http::Request get_req(qb::io::uri("http://api.example.com/data"));
get_req.set_header("X-API-Key", "your_api_key");
get_req.add_header("Accept", "application/json");

// Create a POST request with a JSON body
qb::http::Request post_req(qb::http::method::POST, qb::io::uri("http://api.example.com/submit"));
post_req.set_content_type("application/json");
post_req.body() = R"({"name": "test", "value": 123})";
post_req.set_header("User-Agent", "My QB App/1.0");
```

**Important Notes for Client Requests:**

-   **Host Header**: The `Host` header is automatically set based on the `request.uri().host()`.
-   **User-Agent**: It's good practice to set a `User-Agent` header. If not set, the client may use a default like `"qb/1.0.0"`.
-   **Accept-Encoding**: The client automatically adds an `Accept-Encoding` header listing supported compression algorithms (e.g., `"gzip, deflate, chunked"`) if `QB_IO_WITH_ZLIB` is enabled. The server's response will be decompressed automatically if it uses one of these encodings.
-   **Content-Length**: For requests with a body (POST, PUT, PATCH), if you don't set the `Content-Length` header explicitly, it will be automatically calculated and added based on `request.body().size()` before the request is sent.
-   **Body Compression**: If you need to send a *compressed* request body, you must compress it yourself using `request.body().compress("gzip")` (or another encoding) and set the `Content-Encoding` header accordingly *before* passing the request to the client functions.

### 1. Asynchronous Calls with Callbacks

This is the recommended approach for high-concurrency applications. You provide a lambda or function object that will be called with a `qb::http::async::Reply` object.

`qb::http::async::Reply` structure:
```cpp
struct Reply {
    qb::http::Request request;  // The original request object sent
    qb::http::Response response; // The response received from the server
};
```

**Function Signatures (from `http/http.h`):**

```cpp
template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply&&>, void>
GET(Request request, _Func&& func, double timeout = 0.);

template <typename _Func>
std::enable_if_t<std::is_invocable_v<_Func, async::Reply&&>, void>
POST(Request request, _Func&& func, double timeout = 0.);

// Similar functions for PUT, DELETE, PATCH, HEAD, OPTIONS, and a general REQUEST method:
// qb::http::REQUEST(Request request, _Func&& func, double timeout = 0.);
// For REQUEST, if request.method() is not already set (e.g. HTTP_UNINITIALIZED),
// it allows sending a request with a method specified in request.method().
```

-   `request`: The `qb::http::Request` object (typically moved).
-   `func`: A callable (e.g., lambda) that takes an `qb::http::async::Reply&&`.
-   `timeout`: Optional timeout in seconds (double). If 0, it may use a default system timeout or wait indefinitely, depending on the underlying transport configuration.

**Example:**

```cpp
#include <http/http.h>
#include <qb/io/uri.h>
#include <qb/io/async.h> // For qb::io::async::run() if in a standalone qb-io app

void handle_api_response(qb::http::async::Reply&& reply) {
    std::cout << "Response received for URI: " << reply.request.uri().to_string() << std::endl;
    if (reply.response.status() == qb::http::status::OK) {
        std::cout << "Success! Body: " << reply.response.body().as<std::string_view>() << std::endl;
    } else {
        std::cerr << "Request failed. Status: " << reply.response.status().code()
                  << " Body: " << reply.response.body().as<std::string_view>() << std::endl;
    }
    // If this is the last operation, you might break an event loop or signal completion.
}

int main() {
    qb::io::async::init(); // Initialize event loop for the current thread

    qb::http::Request req(qb::io::uri("http://worldtimeapi.org/api/ip"));
    req.add_header("Accept", "application/json");

    std::cout << "Sending async GET request..." << std::endl;
    qb::http::GET(std::move(req), &handle_api_response, 5.0); // 5 second timeout

    // The event loop needs to run for the async operation to complete.
    // In a qb-actor application, the actor's VirtualCore runs this loop.
    // In a standalone qb-io app, you'd call qb::io::async::run().
    // For a simple test like this, a loop with a break condition might be used:
    // while (/* not_all_replies_received */) { qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT); }

    // For this example, assume qb::io::async::run() is handled elsewhere or test ends.
    qb::io::async::run(); // Example: run until explicitly stopped or no more events
    return 0;
}
```

If the request fails due to connection issues or timeouts before a response is fully parsed, the `reply.response.status()` will typically be set to an error status like `qb::http::status::SERVICE_UNAVAILABLE` (503) or `qb::http::status::GATEWAY_TIMEOUT` (504).

### 2. Synchronous-Style Calls

For convenience, especially in less performance-critical sections or simpler applications, synchronous wrappers are provided. These functions block until the response is available.

**Function Signatures (from `http/http.h`):**

```cpp
Response GET(Request request, double timeout = 3.);
Response POST(Request request, double timeout = 3.);
// Similar functions for PUT, DELETE, PATCH, HEAD, OPTIONS, and REQUEST
```

-   `request`: The `qb::http::Request` object (typically moved).
-   `timeout`: Optional timeout in seconds. Default is often around 3 seconds.
-   Returns: A `qb::http::Response` object.

**Example:**

```cpp
#include <http/http.h>
#include <qb/io/uri.h>
#include <qb/io/async.h> // Required for the underlying async mechanisms

int main() {
    qb::io::async::init(); // Still needed for the underlying async operations

    qb::http::Request req(qb::io::uri("http://worldtimeapi.org/api/ip"));
    req.add_header("Accept", "application/json");

    std::cout << "Sending sync GET request..." << std::endl;
    qb::http::Response response = qb::http::GET(std::move(req), 5.0); // 5 second timeout

    if (response.status() == qb::http::status::OK) {
        std::cout << "Sync Success! Body: " << response.body().as<std::string_view>() << std::endl;
    } else {
        std::cerr << "Sync Request failed. Status: " << response.status().code()
                  << " Body: " << response.body().as<std::string_view>() << std::endl;
    }
    // No need to explicitly run event loop for the sync call itself in this simple main,
    // as qb::http::GET (sync) internally runs qb::io::async::run_until().
    return 0;
}
```

Internally, these synchronous functions use `qb::io::async::run_until(wait_flag)` to drive the event loop just enough for that single request to complete.

**Caution**: Extensive use of synchronous client calls in an actor or a single-threaded event loop designed for high concurrency can lead to performance bottlenecks, as they block the calling thread.

## HTTPS Support

If the `qb-io` library was compiled with SSL support (`QB_IO_WITH_SSL=ON`), the HTTP client can make HTTPS requests simply by specifying `https` as the scheme in the URI. This applies to both HTTP/1.1 and HTTP/2 requests made through their respective client interfaces (`qb::http::GET` etc. for HTTP/1.1, and `qb::http2::Client` for HTTP/2).

```cpp
// For HTTP/1.1 client (qb::http::GET, etc.)
qb::http::Request secure_req_http1(qb::io::uri("https://api.example.com/data_http1"));

qb::http::GET(std::move(secure_req_http1), [](qb::http::async::Reply&& reply) {
    // ... handle HTTPS/1.1 reply ...
});

// For HTTP/2 client (qb::http2::Client)
// (Client construction already shown in 17-http2-protocol.md for HTTPS base URI)
// auto h2_client = qb::http2::make_client("https://my-http2-service.com");
// qb::http::Request secure_req_http2(qb::io::uri("/api/resource")); // Path relative to client's base URI
// h2_client->push_request(std::move(secure_req_http2), ...);
```

The underlying `qb::io::transport::stcp` (Secure TCP) will handle the TLS handshake. Default system certificates are typically used for server certificate validation. For HTTP/2, ALPN (Application-Layer Protocol Negotiation) is used during the TLS handshake to negotiate the "h2" protocol.

For more advanced TLS configurations (e.g., client certificates, custom CA bundles), you would need to configure the `SSL_CTX` at a lower level if the high-level HTTP client API doesn't expose these options directly. Refer to the [HTTPS/SSL/TLS documentation](./18-https-ssl-tls.md) for more server-side details and general SSL concepts.

## Underlying Mechanism (`qb::http::async::session` for HTTP/1.1)

The high-level functions (`qb::http::GET`, `
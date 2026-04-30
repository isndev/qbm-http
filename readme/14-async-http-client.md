# 14: Asynchronous HTTP Client (`qb::http::async`)

The `qb::http` module includes a powerful asynchronous HTTP client, located in the `qb::http::async` namespace, designed for making non-blocking HTTP/1.1 requests. This client is built on top of the `qb-io` asynchronous I/O layer, making it efficient for applications that need to perform many concurrent outbound HTTP calls without dedicating a thread per request.

It supports:
-   HTTP and HTTPS (if `QB_WITH_SSL=ON`, exposed to code as `QB_HAS_SSL`).
-   Standard HTTP methods (GET, POST, PUT, DELETE, etc.).
-   Custom headers, request bodies.
-   Automatic `Accept-Encoding` header for supported compressions (e.g., gzip, deflate if `QB_WITH_COMPRESSION=ON`, exposed to code as `QB_HAS_COMPRESSION`).
-   Automatic decompression of response bodies if `Content-Encoding` is present and supported.
-   Connection timeouts.

For persistent WebSocket conversations, use `qb::http::ws` instead of the
one-request HTTP client helpers. The WebSocket callback and coroutine APIs are
documented in [WebSocket](./20-websocket.md) and
[WebSocket Coroutines](./21-websocket-coroutines.md).

## Core Client Usage

The client offers two APIs, both available directly under the `qb::http` namespace (defined in `qbm/http/1.1/http.h` / `qbm/http/coro.h`):

1.  **Callback-based asynchronous calls** &mdash; the native non-blocking form. You pass a callable that receives the `qb::http::async::Reply` when the response is ready (or an error occurs). Signatures live in `qb::http::async::*`.
2.  **Coroutine-style calls** &mdash; the recommended form for modern application code. `qb::http::GET`, `POST`, `PUT`, `DEL`, `HEAD`, `OPTIONS`, `PATCH`, and the generic `REQUEST` return an *awaiter* that yields a `qb::http::async::Reply`. You can `co_await` it from any coroutine, or drive it synchronously via `qb::http::run_sync(...)`.

The old blocking overloads (`Response GET(Request, timeout)`) have been retired &mdash; the coroutine API plus `run_sync` covers the same use case without threading an implicit event-loop pump through every call site. See [Coroutine-Style Calls](#coroutine-style-calls) below.

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
-   **Accept-Encoding**: The client automatically adds an `Accept-Encoding` header listing supported compression algorithms (e.g., `"gzip, deflate"`) if `QB_HAS_COMPRESSION` is available. The server's response will be decompressed automatically if it uses one of these encodings.
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

### 2. Coroutine-Style Calls {#coroutine-style-calls}

Every HTTP verb under `qb::http` is also exposed as a coroutine-returning overload. These overloads are thin wrappers over the callback-based API and do **not** allocate a new thread or a dedicated event loop; they merely bridge the callback to `co_await`.

**Function Signatures (from `qbm/http/coro.h` / `qbm/http/1.1/http.h`):**

```cpp
namespace qb::http {

    // HTTP/1.1 coroutine client: one overload per verb.
    [[nodiscard]] async::awaiter<async::Reply> REQUEST(Request request, double timeout = 3.);
    [[nodiscard]] async::awaiter<async::Reply> GET    (Request request, double timeout = 3.);
    [[nodiscard]] async::awaiter<async::Reply> POST   (Request request, double timeout = 3.);
    [[nodiscard]] async::awaiter<async::Reply> PUT    (Request request, double timeout = 3.);
    [[nodiscard]] async::awaiter<async::Reply> DEL    (Request request, double timeout = 3.);
    [[nodiscard]] async::awaiter<async::Reply> HEAD   (Request request, double timeout = 3.);
    [[nodiscard]] async::awaiter<async::Reply> OPTIONS(Request request, double timeout = 3.);
    [[nodiscard]] async::awaiter<async::Reply> PATCH  (Request request, double timeout = 3.);

    // Convenience: drive any awaitable to completion on the current thread's
    // qb-io event loop. Alias over qb::io::async::run_sync.
    template <typename Awaitable>
    auto run_sync(Awaitable&& a);

} // namespace qb::http
```

**`async::Reply`** carries both the original `Request` (useful for correlating traces / request IDs) and the parsed `Response`, so there is no information loss compared to the legacy synchronous API.

**Usage from inside a coroutine:**

```cpp
#include <http/http.h>
#include <qbm/http/coro.h>

qb::io::async::task<void> fetch_time() {
    qb::http::Request req(qb::io::uri("http://worldtimeapi.org/api/ip"));
    req.add_header("Accept", "application/json");

    auto reply = co_await qb::http::GET(std::move(req), 5.0);

    if (reply.response.status() == qb::http::status::OK) {
        // reply.request is the original request; reply.response the parsed reply.
        handle_json(reply.response.body().as<std::string_view>());
    }
    co_return;
}
```

**Driving a single call from non-coroutine code (tests, bootstrap, CLIs):**

```cpp
#include <http/http.h>
#include <qbm/http/coro.h>

int main() {
    qb::io::async::init();

    qb::http::Request req(qb::io::uri("http://worldtimeapi.org/api/ip"));
    auto reply = qb::http::run_sync(qb::http::GET(std::move(req), 5.0));

    if (reply.response.status() == qb::http::status::OK) {
        std::cout << reply.response.body().as<std::string_view>() << '\n';
    }
    return 0;
}
```

`qb::http::run_sync` pumps the *current* thread's `qb-io` event loop just enough to resolve the awaitable, without ever spawning threads or mutating the global scheduler &mdash; consistent with the mono-thread-per-listener contract of the framework.

**HTTP/2 coroutine surface (`qb::http2::Client`):**

```cpp
struct qb::http2::ConnectResult {
    bool        ok;
    std::string error_message;
    explicit operator bool() const noexcept;
};

class qb::http2::Client {
public:
    // ... existing callback-based overloads ...

    [[nodiscard]] async::awaiter<ConnectResult>             connect();
    [[nodiscard]] async::awaiter<qb::http::Response>        push_request(qb::http::Request);
    [[nodiscard]] async::awaiter<std::vector<Response>>     push_requests(std::vector<qb::http::Request>);
};
```

Typical usage:

```cpp
auto client = qb::http2::make_client("https://api.example.com");

qb::io::async::task<void> run() {
    if (!co_await client->connect()) co_return;             // bool-converts
    auto resp = co_await client->push_request(build_req());
    std::cout << resp.status().code() << '\n';
    co_return;
}
```

**Why coroutines here?** The coroutine style eliminates the need for a separately blocking synchronous API without giving up readability. Compared to the callback form, call-site logic reads top-to-bottom: the request is sent, the response arrives, error handling is a regular `if`/`try`, and loops over multiple calls simply `co_await` in sequence or via `qb::io::async::all(...)` for fan-out.

## HTTPS Support

If the `qb-io` library was compiled with SSL support (`QB_WITH_SSL=ON`,
available to code as `QB_HAS_SSL`), the HTTP client can make HTTPS requests
simply by specifying `https` as the scheme in the URI. This applies to both
HTTP/1.1 and HTTP/2 requests made through their respective client interfaces
(`qb::http::GET` etc. for HTTP/1.1, and `qb::http2::Client` for HTTP/2).

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

The high-level functions (`qb::http::GET`, `qb::http::POST`, and friends)
are convenience wrappers over the HTTP/1.1 async client session. For repeated
requests to the same origin, prefer the persistent `qb::http1::Client` API
described in the main README and tests: it keeps one TCP/TLS connection per
origin, sends one active HTTP/1.1 request at a time, preserves batch order, and
reconnects only when doing so is safe.

The one-shot helpers remain useful for simple calls and backwards-compatible
examples. They create the request, drive the async session, and report the final
`Reply` through the callback or coroutine awaiter.

Previous: [Error Handling Strategies](./13-error-handling.md)
Next: [HTTP Message Parsing](./15-http-parsing.md)

---

Return to [Index](./README.md)

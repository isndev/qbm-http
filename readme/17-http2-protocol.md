# 17: HTTP/2 Protocol Specifics

The `qb::http` module provides comprehensive support for HTTP/2, enabling high-performance, multiplexed communication for both client and server implementations. This section details how to leverage HTTP/2 features within your QB applications.

## Overview of HTTP/2 Support

HTTP/2 introduces several key improvements over HTTP/1.1, all of which are supported by `qb-http` when using the `qb::http2` namespace components:

-   **Multiplexing**: Multiple requests and responses can be sent and received concurrently over a single TCP connection, eliminating head-of-line blocking.
-   **Header Compression (HPACK)**: Reduces header overhead using HPACK compression (RFC 7541). The `qb::protocol::hpack` namespace provides the underlying implementation (`HpackEncoderImpl`, `HpackDecoderImpl`).
-   **Server Push**: Allows the server to proactively send resources to the client that it anticipates will be needed (though direct application-level control of push might be evolving or require specific patterns).
-   **Binary Framing Layer**: HTTP/2 messages are broken down into binary frames (DATA, HEADERS, SETTINGS, etc.), simplifying parsing and reducing ambiguity compared to HTTP/1.1's text-based format.
-   **Stream Prioritization**: Allows clients to indicate preference for how streams are allocated resources (though server-side implementation of prioritization can vary).

**Important**: HTTP/2 in `qb-http` (specifically `qb::http2::Server` and `qb::http2::Client`) is typically used over TLS (HTTPS) and relies on ALPN (Application-Layer Protocol Negotiation) to select the "h2" protocol.

## `qb::http2::Client`

The `qb::http2::Client` class (in `http/2/client.h`) provides a modern, asynchronous interface for making HTTP/2 requests.

### Key Features of `qb::http2::Client`

-   **Automatic Connection Management**: Handles connection establishment, including ALPN negotiation for "h2".
-   **Stream Management**: Internally manages HTTP/2 stream IDs for concurrent requests.
-   **Concurrent Requests**: Supports sending multiple requests simultaneously over a single connection.
-   **Batch Requests**: Can group multiple requests into a logical batch with a single callback for all responses.
-   **Timeout Handling**: Built-in connection and request timeouts.
-   **Elegant API**: Uses callbacks for asynchronous response handling.
-   **Flow Control**: Adheres to HTTP/2 flow control mechanisms (`WINDOW_UPDATE`) for sending request bodies.
-   **HPACK**: Uses HPACK for request header compression.

### Creating and Using the HTTP/2 Client

```cpp
#include <http/2/client.h> // For qb::http2::Client
#include <http/request.h>  // For qb::http::Request
#include <http/response.h> // For qb::http::Response
#include <qb/io/uri.h>
#include <qb/io/async.h>   // For event loop (qb::io::async::run)

int main() {
    qb::io::async::init(); // Initialize async system for the current thread

    // Create a client for a specific base URI (must be HTTPS for typical HTTP/2)
    auto h2_client = qb::http2::make_client("https://httpbin.org");

    // Configure timeouts (optional)
    h2_client->set_connect_timeout(10.0); // 10 seconds
    h2_client->set_request_timeout(30.0); // 30 seconds

    std::atomic<int> responses_received{0};

    // Connection callback (optional)
    h2_client->connect([&](bool connected, const std::string& err_msg) {
        if (connected) {
            std::cout << "HTTP/2 client connected successfully!" << std::endl;

            // Send a single GET request
            qb::http::Request req1;
            req1.uri() = qb::io::uri("/get"); // Path relative to base URI
            req1.add_header("X-Custom-Header", "Test1");

    h2_client->push_request(std::move(req1), [&](qb::http::Response res1) {
                std::cout << "Response 1 (GET /get):\n" 
                          << "Status: " << res1.status().code() << std::endl
                          << "Body (first 100 chars): " << res1.body().as<std::string_view>().substr(0, 100) << "..." << std::endl;
                responses_received++;
            });

            // Send a POST request
            qb::http::Request req2;
            req2.method() = qb::http::method::POST;
            req2.uri() = qb::io::uri("/post");
            req2.set_content_type("application/json");
            req2.body() = R"({"message": "Hello HTTP/2"})";

    h2_client->push_request(std::move(req2), [&](qb::http::Response res2) {
                std::cout << "Response 2 (POST /post):\n"
                          << "Status: " << res2.status().code() << std::endl
                          << "Body (first 100 chars): " << res2.body().as<std::string_view>().substr(0, 100) << "..." << std::endl;
                responses_received++;
            });

        } else {
            std::cerr << "HTTP/2 client connection failed: " << err_msg << std::endl;
            responses_received = 2; // Ensure loop terminates
        }
    });

    // Event loop to process async operations
    while (responses_received < 2) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    h2_client->disconnect();
    std::cout << "Client finished." << std::endl;
    return 0;
}
```

Key methods:
-   `qb::http2::make_client(base_uri)`: Factory function to create a `std::shared_ptr<Client>`.
-   `client->connect(ConnectionCallback cb)`: Initiates connection (asynchronous).
-   `client->push_request(Request req, ResponseCallback cb)`: Sends a single request.
-   `client->push_requests(std::vector<Request> reqs, BatchResponseCallback cb)`: Sends multiple requests as a batch.
-   `client->disconnect()`: Closes the connection.
-   Various `set_*` methods for configuration (timeouts, max concurrent streams).

The client handles the underlying HTTP/2 protocol details (frames, streams, flow control, HPACK) via `qb::protocol::http2::ClientHttp2Protocol`.

## `qb::http2::Server`

The `qb::http2::Server` class (in `http/2/http2.h`) enables you to build HTTP/2 capable servers.

### Key Features of `qb::http2::Server`

-   **Built on `qb::http::Router`**: Utilizes the same powerful routing engine as the HTTP/1.1 server, allowing you to define routes, groups, and controllers.
-   **TLS Requirement**: HTTP/2 server implementation in `qb-http` is designed for secure connections (HTTPS). Plaintext HTTP/2 (h2c) is not the primary focus for this server component.
-   **ALPN for Protocol Negotiation**: Relies on ALPN during the TLS handshake to negotiate "h2" (for HTTP/2) or "http/1.1". If "h2" is negotiated, the connection uses `qb::protocol::http2::ServerHttp2Protocol`.
-   **Flow Control**: Manages HTTP/2 flow control for sending response bodies.
-   **HPACK**: Uses HPACK for response header compression.

### Creating and Using the HTTP/2 Server

Setting up an HTTP/2 server is very similar to the HTTP/1.1 server, with the primary difference being the server class used and the ALPN configuration.

```cpp
#include <http/2/http2.h>  // For qb::http2::Server, qb::http2::DefaultSession
#include <http/routing.h> // For qb::http::Router and related types
#include <qb/io/async.h>

// Using the make_server factory for convenience (uses qb::http2::DefaultSession internally)
// For custom session types, you would derive from qb::http2::Server as shown previously
// or create a make_server equivalent for your custom session server.

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <cert_file.pem> <key_file.pem>" << std::endl;
        return 1;
    }
    std::filesystem::path cert_file = argv[1];
    std::filesystem::path key_file = argv[2];

    qb::io::async::init();

    auto server_instance = qb::http2::make_server();

    server_instance->router().get("/hello-h2", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Hello from HTTP/2 Server (make_server)!";
        ctx->response().add_header("X-Protocol-Version", "HTTP/2");
        ctx->complete();
    });
    server_instance->router().get("/", [](auto ctx) { // Serve a simple HTML page
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_content_type("text/html; charset=utf-8");
        ctx->response().body() = "<html><body><h1>HTTP/2 Works! (make_server)</h1></body></html>";
        ctx->complete();
    });
    server_instance->router().compile();

    // Listen for HTTPS connections, enabling HTTP/2 via ALPN
    if (!server_instance->listen({"https://0.0.0.0:8443"}, cert_file, key_file)) {
        std::cerr << "Error: Failed to listen on port 8443 for HTTP/2 server." << std::endl;
        return 1;
    }
    std::cout << "HTTP/2 server listening on https://0.0.0.0:8443" << std::endl;

    server_instance->start();
    qb::io::async::run();

    return 0;
}
```

Key steps:
1.  Derive your session from `qb::http2::use<YourSession>::session<YourServer>`.
2.  Derive your server from `qb::http2::use<YourServer>::server<YourSession>`.
3.  Use `router()` to define routes as usual.
4.  Call `server_instance->listen({"https://0.0.0.0:8443"}, cert_file, key_file)`. The `listen` method correctly initializes the SSL context and sets ALPN to negotiate "h2" (for HTTP/2) and often "http/1.1" as a fallback.

The server uses `qb::protocol::http2::ServerHttp2Protocol` internally to manage HTTP/2 streams, frame parsing/serialization, and HPACK.

## HTTP/2 Frames and Streams (Internal)

While application developers primarily interact with `Request` and `Response` objects, the underlying HTTP/2 protocol operates on frames and streams:

-   **Frames (`http/2/protocol/frames.h`)**: Smallest unit of communication in HTTP/2, each with a specific type (DATA, HEADERS, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, RST_STREAM, PRIORITY, PUSH_PROMISE, CONTINUATION).
    -   `FrameHeader`: Common 9-octet header for all frames.
    -   Specific structs for each frame type (e.g., `DataFrame`, `HeadersFrame`).
-   **Streams (`http/2/protocol/stream.h`)**: Independent, bidirectional sequences of frames exchanged between client and server. Each stream has a unique ID.
    -   `Http2StreamConcreteState`: Manages the lifecycle of a stream (IDLE, OPEN, HALF_CLOSED, CLOSED, etc.).
    -   Flow control is managed per-stream and per-connection using `WINDOW_UPDATE` frames.

### Header Compression: HPACK (`http/2/protocol/hpack.h`)

HTTP/2 uses HPACK (Header Compression for HTTP/2, RFC 7541) to compress request and response headers, reducing latency and bandwidth usage. Key aspects:

-   **Static Table**: A predefined table of common header fields (e.g., `:method: GET`, `accept-encoding: gzip`).
-   **Dynamic Table**: Maintained by both encoder and decoder. It stores frequently sent header fields that are not in the static table. This table is updated with new entries from header blocks.
-   **Encoding Strategies**:
    -   **Indexed Header Field**: References an entry in the static or dynamic table.
    -   **Literal Header Field with Incremental Indexing**: Sends a header field literally and adds it to the dynamic table.
    -   **Literal Header Field without Indexing**: Sends a header field literally but does not add it to the dynamic table (e.g., for sensitive headers or one-time headers).
    -   **Literal Header Field Never Indexed**: Similar to "without indexing," but also instructs intermediaries never to index it.
-   **Huffman Coding**: String literals (names and values) can be optionally Huffman coded for further size reduction.
-   **SETTINGS_HEADER_TABLE_SIZE**: An HTTP/2 setting allows endpoints to declare the maximum size (in octets) of the dynamic table their decoder can handle. Encoders must respect this limit. The `qb::protocol::hpack::HpackEncoderImpl` and `HpackDecoderImpl` manage these table sizes.

`qb-http` handles HPACK encoding and decoding transparently within `ClientHttp2Protocol` and `ServerHttp2Protocol`.

### Flow Control

HTTP/2 provides flow control mechanisms to prevent a sender from overwhelming a receiver with data. This operates at two levels:

-   **Stream-Level Flow Control**: Each stream has its own flow control window. The receiver advertises how much data it is prepared to receive on a specific stream using `WINDOW_UPDATE` frames for that stream ID.
-   **Connection-Level Flow Control**: There is also a global flow control window for the entire connection, also managed by `WINDOW_UPDATE` frames (with stream ID 0).

A sender must not send DATA frames that would exceed the receiver's advertised window for either the stream or the connection.

-   `qb::http2::Client` and the underlying protocol classes manage sending and processing `WINDOW_UPDATE` frames automatically. The initial window size is defined by `SETTINGS_INITIAL_WINDOW_SIZE` (default 65,535 octets), and can be changed during the connection.
-   When sending large request or response bodies, these components will segment the data into DATA frames respecting the current flow control windows.

### Server Push

HTTP/2 allows a server to proactively send responses (pushes) to a client for resources it anticipates the client will request. This is initiated with a `PUSH_PROMISE` frame from the server, which includes the request headers the server *would have received* for the pushed resource.

-   **Client-Side**: `qb::http2::Client` can receive `PUSH_PROMISE` frames. By default, it might reject pushes. The `Http2PushPromiseEvent` allows an application using the `qb::http2::Client` to be notified of a push and potentially accept or reject it (e.g., via `ClientHttp2Protocol::application_reject_push(promised_stream_id)`).
-   **Server-Side**: The `qb::protocol::http2::ServerHttp2Protocol` has a `send_push_promise` method that can be used to initiate a server push. Integrating this into high-level application handlers in `qb::http2::Server` might require a specific API pattern, which could be an area for future framework enhancement if not already fully exposed at the application handler level.
    -   The server must respect the client's `SETTINGS_ENABLE_PUSH` setting (defaults to allowed, but client can disable it).
    -   Pushed streams consume a stream ID and count towards the client's `SETTINGS_MAX_CONCURRENT_STREAMS` limit for server-initiated streams.

These details are largely abstracted by the `qb::http2::Client` and `qb::http2::Server` layers, but understanding their existence is useful for debugging or advanced protocol interaction.

## Logging

HTTP/2 specific logging can be found in the code using macros like `LOG_HTTP_DEBUG_PA(stream_id, ...)` or `LOG_HTTP_ERROR_PA(stream_id, ...)` (from `http/logger.h`), which include the stream ID for better context in multiplexed environments.

By leveraging the `qb::http2` components, you can build efficient and modern web services that take full advantage of the HTTP/2 protocol's capabilities.

Previous: [Advanced Usage & Performance](./16-advanced-topics.md)
Next: [Enabling HTTPS (SSL/TLS)](./18-https-ssl-tls.md)

---
Return to [Index](./README.md) 
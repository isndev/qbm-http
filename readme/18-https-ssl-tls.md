# 18: Enabling HTTPS (SSL/TLS)

Secure communication is paramount for modern web applications. The `qb::http` module provides robust support for HTTPS (HTTP over SSL/TLS) for both its HTTP/1.1 and HTTP/2 server and client implementations. This relies on the SSL/TLS capabilities of the underlying `qb-io` library, which in turn typically uses OpenSSL.

## Prerequisites

-   **OpenSSL**: Ensure OpenSSL development libraries are installed on your system.
-   **`QB_IO_WITH_SSL=ON`**: The `qb-io` library (and consequently `qb-core` and `qbm-http`) must be compiled with the `QB_IO_WITH_SSL` CMake option enabled. This links against OpenSSL and enables the secure transport components.
-   **SSL Certificates**: You will need an SSL certificate and a corresponding private key for your server.
    -   **For production**: Obtain certificates from a trusted Certificate Authority (CA) (e.g., Let's Encrypt, DigiCert, Comodo).
    -   **For development/testing**: You can generate self-signed certificates. Browsers will show warnings for self-signed certificates, but they are suitable for local testing. Common tools like OpenSSL can be used for this purpose. For example, a simple command to generate a self-signed certificate and private key pair using OpenSSL might look like:
        ```bash
        openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
        ```
        *(This command creates `key.pem` and `cert.pem` valid for 365 days for `localhost`. Adjust parameters as needed. Using `-nodes` omits passphrase protection for the private key, suitable for some development servers but consider security implications.)*

## Enabling HTTPS for Servers

Both HTTP/1.1 and HTTP/2 servers in `qb-http` are configured for HTTPS through their respective `listen` methods and transport initialization.

### HTTP/1.1 Server (`qb::http::ssl::Server`)

The `qb::http::ssl::Server` class template (from `http/1.1/http.h`, via `qb::http::use<...>::ssl::server`) is used for secure HTTP/1.1 connections.

```cpp
#include <http/http.h> // For qb::http::ssl::Server, qb::http::ssl::DefaultSecureSession
#include <qb/io/async.h>
#include <qb/io/ssl_context.h> // For qb::io::ssl::create_server_context, TLS_server_method
#include <filesystem>      // For std::filesystem::path

// Using qb::http::ssl::make_server() for convenience.
// This factory function creates a qb::http::ssl::Server<qb::http::ssl::DefaultSecureSession>.

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <cert_file.pem> <key_file.pem>" << std::endl;
        return 1;
    }
    std::filesystem::path cert_file = argv[1];
    std::filesystem::path key_file = argv[2];

    qb::io::async::init();
    auto server_instance = qb::http::ssl::make_server();

    server_instance->router().get("/secure-ping", [](auto ctx) {
        ctx->response().body() = "Pong from HTTPS/1.1 (make_server)!";
        ctx->complete();
    });
    server_instance->router().compile();

    // 1. Create SSL Server Context
    auto ssl_ctx = qb::io::ssl::create_server_context(TLS_server_method(), cert_file, key_file);
    if (!ssl_ctx) {
        std::cerr << "Error: Failed to create SSL server context." << std::endl;
        return 1;
    }

    // 2. Initialize the server's transport with the SSL context.
    //    The transport type is qb::io::transport::saccept for qb::http::use<...>::ssl::server.
    server_instance->transport().init(std::move(ssl_ctx));

    // 3. Specify ALPN protocols (optional but recommended for HTTP/2, good practice for HTTP/1.1 over TLS)
    //    For a pure HTTP/1.1 server, "http/1.1" is typical.
    server_instance->transport().set_supported_alpn_protocols({"http/1.1"});

    // 4. Listen on the desired HTTPS port (typically 443)
    if (!server_instance->transport().listen_v4(8443)) { // Using 8443 for example
        std::cerr << "Error: Failed to listen on port 8443 for HTTPS server." << std::endl;
        return 1;
    }
    std::cout << "HTTPS/1.1 server listening on https://0.0.0.0:8443" << std::endl;

    server_instance->start();
    qb::io::async::run();
    return 0;
}
```

Key steps for `qb::http::ssl::Server`:
1.  **Create SSL Context**: Use `qb::io::ssl::create_server_context(method, cert_path, key_path)`.
    -   `method`: Typically `TLS_server_method()` (or specific versions like `TLSv1_2_server_method()`).
    -   Provide paths to your server certificate and private key files.
2.  **Initialize Transport**: Call `server_instance.transport().init(ssl_ctx)`.
3.  **Set ALPN (Optional for HTTP/1.1)**: Call `server_instance.transport().set_supported_alpn_protocols({"http/1.1"})` if you want to explicitly state ALPN support, though it's primarily for HTTP/2 negotiation.
4.  **Listen**: Call `server_instance.transport().listen_v4(port)` or `listen_v6(port)`.

### HTTP/2 Server (`qb::http2::Server`)

The `qb::http2::Server` (from `http/2/http2.h`) inherently requires TLS and uses ALPN to negotiate the "h2" protocol.

```cpp
#include <http/2/http2.h>  // For qb::http2::Server
#include <qb/io/async.h>
#include <qb/io/ssl_context.h>
#include <filesystem>

// Using qb::http2::make_server() for convenience.
// This factory function creates a qb::http2::Server<qb::http2::DefaultSession>.

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
        ctx->response().body() = "Hello from secure HTTP/2 (make_server)!";
        ctx->complete();
    });
    server_instance->router().compile();

    // The listen method for qb::http2::Server handles SSL context creation and ALPN for "h2".
    // It takes a qb::io::uri (for address/port) and paths to cert/key files.
    qb::io::uri listen_uri("https://0.0.0.0:9443"); // Example URI

    if (!server_instance->listen(listen_uri, cert_file, key_file)) {
        std::cerr << "Error: Failed to listen on " << listen_uri.to_string() 
                  << " for HTTP/2 server." << std::endl;
        return 1;
    }
    std::cout << "HTTP/2 server listening on " << listen_uri.to_string() << std::endl;

    server_instance->start();
    qb::io::async::run();
    return 0;
}
```

Key steps for `qb::http2::Server`:
1.  **Call `server_instance.listen(uri, cert_path, key_path)`**: This method (defined in `http/2/http2.h` within `qb::http2::internal::server`) internally:
    -   Creates an SSL server context using `qb::io::ssl::create_server_context()`.
    -   Initializes the server's transport (`qb::io::transport::saccept`).
    -   **Crucially, sets the ALPN supported protocols to `{"h2", "http/1.1"}`** (or similar, depending on `http2.h` implementation specifics), enabling HTTP/2 negotiation over TLS.
    -   Starts listening on the specified address and port from the URI.

### Application-Layer Protocol Negotiation (ALPN)

ALPN is a TLS extension that allows the client and server to negotiate which application protocol will be used over the secure connection. This is how HTTP/2 is typically established:

1.  **Client (during TLS handshake)**: Sends a list of protocols it supports (e.g., `h2`, `http/1.1`) in the ALPN extension.
2.  **Server (during TLS handshake)**: Selects one protocol from the client's list that it also supports. If the server supports HTTP/2 and the client offers "h2", this will typically be chosen. This negotiation is critical for HTTP/2 to function over TLS.

-   The `qb::http::async::tcp::ssl::socket` (client-side) and `qb::io::transport::saccept` (server-side transport, underlying `qb::http2::Server` and `qb::http::ssl::Server`) handle ALPN.
-   `qb::http2::Server::listen(...)` configures its transport to support "h2" (and often "http/1.1" as a fallback if the server is designed to handle both on the same port).
-   `qb::http::ssl::Server` can also be configured with ALPN preferences (e.g., `server_instance.transport().set_supported_alpn_protocols({"http/1.1"})` if it only intends to serve HTTP/1.1 over TLS, or `{"h2", "http/1.1"}` if it can handle both through protocol switching logic after ALPN).
-   `qb::http2::Client` (via its internal `HandshakeProtocol` and `stcp` transport) will attempt to negotiate "h2" for `https://` URIs.
-   The `qb::http::async::HTTPS` client (for HTTP/1.1 over TLS) will typically negotiate "http/1.1".

After the TLS handshake, the server session (`qb::http2::internal::session` for HTTP/2, or the HTTP/1.1 session) checks the negotiated ALPN protocol (`this->transport().get_alpn_selected_protocol()`).
- For `qb::http2::internal::session`, if "h2" is selected, it switches to `Http2Protocol`. If "http/1.1" is selected (and the server is configured to fall back), it switches to `Http1Protocol`.
- For a dedicated HTTP/1.1 SSL server, it expects "http/1.1" or no ALPN negotiation resulting in HTTP/1.1 by default over TLS.

## Enabling HTTPS for Clients

### HTTP/1.1 Client (`qb::http::async::HTTPS`)

To make HTTPS requests using the HTTP/1.1 client, simply use a URI with the `https` scheme. The client functionality is provided via template alias `qb::http::async::HTTPS` (defined in `http/1.1/http.h`), which uses `qb::io::transport::stcp`.

```cpp
#include <http/http.h>

qb::http::Request secure_req(qb::io::uri("https://api.example.com/data"));

qb::http::GET(std::move(secure_req), [](qb::http::async::Reply&& reply) {
    if (reply.response.status() == qb::http::status::OK) {
        // Process successful HTTPS response
    }
});
```

No explicit SSL setup is usually needed on the client-side for basic requests; the system's default CA certificates are typically used to verify the server's certificate.

### HTTP/2 Client (`qb::http2::Client`)

The `qb::http2::Client` (from `http/2/client.h`) automatically uses HTTPS when the base URI provided to `qb::http2::make_client()` has an `https` scheme.

```cpp
#include <http/2/client.h>

auto h2_client = qb::http2::make_client("https://my-http2-service.com");

h2_client->connect([&](bool connected, const std::string& /*err_msg*/){
    if(connected){
        qb::http::Request req(qb::io::uri("/api/resource"));
        h2_client->push_request(std::move(req), [](qb::http::Response res){
            // ... handle HTTP/2 response over HTTPS ...
        });
    }
});
```

The `qb::http2::Client` also relies on ALPN to negotiate "h2" during the TLS handshake.

## Advanced SSL/TLS Configuration

For more advanced SSL/TLS settings (e.g., client certificates, specific cipher suites, custom CA certificate paths for clients), you would typically need to interact with the `SSL_CTX*` object more directly.

-   **Server-Side**: `qb::io::ssl::create_server_context()` can take further OpenSSL `SSL_CTX` setup calls before being passed to `transport().init()`.
-   **Client-Side**: While the high-level HTTP clients (`qb::http::GET`, `qb::http2::Client`) don't directly expose `SSL_CTX` configuration, custom client implementations using `qb::io::async::tcp::ssl::socket` can set up the `SSL_CTX` before connecting.

Refer to `qb-io` documentation and OpenSSL documentation for details on `SSL_CTX` manipulation.

Secure communication with HTTPS is a fundamental part of modern web applications. `qb-http` provides the necessary tools to integrate SSL/TLS seamlessly into both your HTTP/1.1 and HTTP/2 services.

Previous: [HTTP/2 Protocol Specifics](./17-http2-protocol.md)
Next: [Index](./README.md) (or new section)

---
Return to [Index](./README.md) 
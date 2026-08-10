# Enabling HTTPS (SSL/TLS)

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 3.0.0 (C++20 default, C++23 supported)

Serve and consume HTTPS by layering OpenSSL on top of the qb-io secure transports — server certificate setup, client trust and verification, and ALPN negotiation.

**Prerequisites:** [Core concepts](./01-core-concepts.md), [Asynchronous HTTP client](./14-async-http-client.md) — **See also:** [HTTP/2 protocol specifics](./17-http2-protocol.md), [HTTP/3 protocol](./19-http3-protocol.md), [WebSocket](./20-websocket.md), [Authentication system](./11-authentication.md)

TLS is not bolted onto qbm-http; it is the qb-io secure transport layer (`qb::io::transport::stcp` for streams, `qb::io::transport::saccept` for acceptors) exposed through the same server and client types you already use. A plaintext HTTP/1.1 server and an HTTPS server differ by one transport parameter and one extra argument to `listen`; an `http://` client and an `https://` client differ only by the URI scheme. Everything below — certificates, ALPN, peer verification — is configured through that thin seam.

## The SSL feature gate

HTTPS, secure WebSocket (`wss://`), HTTP/2, HTTP/3, and JWT/auth are all **compiled only when the framework is built with OpenSSL**. The build derives `QB_HAS_SSL` from OpenSSL detection upstream and propagates it `PUBLIC` to your target, so the `#ifdef QB_HAS_SSL` gates inside `<qbm/http/http.h>` resolve the same way in your code as in the module.

<!-- src: qbm/http/CMakeLists.txt:74-82; qbm/http/src/qbm/http/http.h:45-48 -->
```cpp
#include <qbm/http/http.h>

#ifndef QB_HAS_SSL
#  error "This translation unit needs an OpenSSL-enabled qb build for HTTPS."
#endif
```

Practical consequences:

- `qb::http::ssl::Server`, `qb::http::ssl::make_server`, the `qb::http::async::HTTPS` session type, `qb::http2::*`, and `qb::http::ws::*` exist **only** in an SSL build. Without `QB_HAS_SSL`, `<qbm/http/http.h>` does not even include `src/qbm/http/2/http2.h` or `src/qbm/http/ws/ws.h`.
- Plain HTTP/1.1 servers and clients still compile and run in an SSL-less build; you simply cannot open a secure listener or make an `https://` request.
- This module is a **compiled library** (`qb_register_module` with a `SOURCES` list, not a header-only target). Exactly four translation units are SSL-only and appended to the build only when the gate is on: `src/qbm/http/auth/manager.cpp`, `src/qbm/http/ws/ws.cpp`, `src/qbm/http/2/http2.cpp`, `src/qbm/http/2/client.cpp`. The `2/protocol/*.cpp` files are **not** among them — the HTTP/2 wire codec (frame layer, HPACK, stream state machine) is transport-independent and compiles unconditionally, so its unit tests keep running in an SSL-less build even though no transport can reach it there. There is nothing to `#define` yourself; the gate follows the framework build.

Gate your own SSL-dependent code on `QB_HAS_SSL`, never on `QBM_HTTP_HAS_SSL` — the latter is a `PRIVATE` module-internal marker and is not visible to consumers. See [the module front door](../README.md) for the full feature matrix.

## Certificates

A TLS server needs a certificate chain and the matching private key, both PEM-encoded. `qb::io::ssl::Context::server(cert, key)` loads them from files by path (a `std::filesystem::path` — the same type `listen(uri, cert, key)` forwards), delegating to `Context::identity`, which also checks that the key matches the certificate. Each path is resolved through `qb::io::sys::resolve_resource()` before OpenSSL opens it: an absolute path is used unchanged, while a relative path is looked up against the current working directory first, then against the running executable's own directory. A server shipped next to its `cert.pem` / `key.pem` therefore loads them regardless of the cwd it was launched from — the same resolution applies to `Context::trust`, to the legacy raw `create_server_context`, and to the CA, client-certificate, and DH-parameter helpers below.

<!-- src: qb/src/qb/io/tcp/ssl/context.cpp:269-277,352-364,328-341; qb/src/qb/io/tcp/ssl/socket.cpp:186-204; qb/src/qb/io/system/file.h:377-387 -->

- **Production** — obtain a certificate from a trusted CA (Let's Encrypt, your internal PKI, a commercial CA). Deploy the leaf certificate (concatenated with any intermediates) and the private key as PEM files.
- **Development** — a self-signed certificate is fine for local testing. Browsers and verifying clients reject it unless you add it to a trust store or disable verification (see [Peer verification](#peer-verification-and-trust)).

```bash
# Self-signed cert + key valid for localhost, no passphrase (dev only).
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -sha256 -days 365 \
  -subj "/CN=localhost"
```

The same `cert.pem` / `key.pem` pair drives every server flavor below — HTTP/1.1 over TLS, HTTP/2, and (when QUIC is present) HTTP/3.

## The qb-io secure transports

qbm-http never touches OpenSSL directly for the common path. Two qb-io transports do the work, and the HTTP server/client types are templated over them:

| Transport | Role | Used by |
| --- | --- | --- |
| `qb::io::transport::saccept` | Secure acceptor — accepts a TCP connection and drives the TLS handshake, yielding a `qb::io::tcp::ssl::socket` per client. | `qb::http::ssl::Server`, `qb::http2::Server` |
| `qb::io::transport::stcp` | Secure stream — an SSL/TLS socket as a read/write stream, including SSL-buffer draining on read. | `qb::http::async::HTTPS`, the persistent `http1::Client` (https), `qb::http2::Client` |

<!-- src: qb/src/qb/io/transport/saccept.h:44-50; qb/src/qb/io/transport/stcp.h:44-47 -->

Both expose `static constexpr bool is_secure()` returning `true`, which is how the server `listen` method (below) decides whether to build a TLS context at all. The context type lives in `qb::io::ssl` and is `Context` — RAII, value-semantic, reference-counted, secure-by-default:

<!-- src: qb/src/qb/io/tcp/ssl/context.h:127,138,146,156,163 -->
```cpp
namespace qb::io::ssl {
class Context {
public:
    // Server: load this server's certificate chain and private key. TLS 1.2+, VerifyMode::none.
    static Context server(std::filesystem::path cert, std::filesystem::path key);

    // Client: secure by default — TLS 1.2+, system trust store, VerifyMode::peer.
    static Context client();

    // Escape hatches over a raw SSL_CTX: adopt() TAKES your reference, share() adds one.
    static Context adopt(SSL_CTX *raw) noexcept;
    static Context share(SSL_CTX *raw) noexcept;
};
}
```

There is **no user-visible `SSL_CTX_free`**: copies share one `SSL_CTX`, which is freed once the last copy and the last `SSL` minted from it are gone. `Context::client()` already sets TLS 1.2+, the system trust store, and peer verification, so a secure default costs no configuration.

The older raw-pointer factories `qb::io::ssl::create_server_context(method, cert, key)` and `create_client_context(method)` still exist and still take an explicit `TLS_server_method()` / `TLS_client_method()`, but they are the **escape hatch**, not the common path — `listen` uses `Context`, and `listener::init` documents the `Context` overload as preferred.

<!-- src: qb/src/qb/io/tcp/ssl/socket.h:84,95; qb/src/qb/io/tcp/ssl/listener.h:104-105 -->

The caller owns the returned raw `SSL_CTX`. Handing one to `listener::init(SSL_CTX*)` **transfers** that single reference into the listener's `qb::io::ssl::Context` (through `Context::adopt`, which takes no extra reference), so you must not `SSL_CTX_free` it afterwards. It is not a `unique_ptr`: the listener member is a value-semantic, reference-counted `Context` shared with every accepted connection, and the `SSL_CTX` is freed exactly once, when the last copy of the context and the last `SSL` minted from it are gone.

<!-- src: qb/src/qb/io/tcp/ssl/listener.h:45,98-107,115; qb/src/qb/io/tcp/ssl/listener.cpp:37-42; qb/src/qb/io/tcp/ssl/context.h:148-156 -->

## Serving HTTPS over HTTP/1.1

The secure HTTP/1.1 server is `qb::http::ssl::Server<Session>`, defaulting to `qb::http::ssl::DefaultSecureSession`. Use the `qb::http::ssl::make_server()` factory and the server's `listen(uri, cert, key)` overload — that one call builds a `qb::io::ssl::Context` from the cert and key with ALPN `{"http/1.1"}` folded in, installs it on the `saccept` transport, and starts listening.

<!-- src: qbm/http/src/qbm/http/1.1/http.h:583-601 -->
```cpp
#include <qbm/http/http.h>
#include <qb/io/async.h>
#include <filesystem>
#include <iostream>

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " <cert.pem> <key.pem>\n";
        return 1;
    }
    const std::filesystem::path cert = argv[1];
    const std::filesystem::path key  = argv[2];

    qb::io::async::init();

    auto server = qb::http::ssl::make_server();   // unique_ptr<ssl::Server<DefaultSecureSession>>

    server->router().get("/secure-ping", [](auto ctx) {
        ctx->response().body() = "pong over TLS";
        ctx->complete();
    });
    server->router().compile();

    // One call: builds SSL_CTX from cert+key, installs ALPN {"http/1.1"}, listens.
    if (!server->listen(qb::io::uri("https://0.0.0.0:8443"), cert, key)) {
        std::cerr << "failed to start TLS listener on :8443\n";
        return 1;
    }
    std::cout << "HTTPS/1.1 listening on https://0.0.0.0:8443\n";

    server->start();
    qb::io::async::run();
    return 0;
}
```

`listen` returns `false` if the certificate or key fails to load, so check the result. Under the hood it does exactly this for a secure transport:

<!-- src: qbm/http/src/qbm/http/1.1/http.h:589-596 -->
```cpp
using tpt = std::decay_t<decltype(this->transport())>;
if constexpr (tpt::is_secure()) {
    this->transport().init(
        qb::io::ssl::Context::server(std::move(cert_file), std::move(key_file))
            .alpn({"http/1.1"}));
    if (!this->transport().context().ok()) {          // cert/key load or config failed
        LOG_HTTP_ERROR("Failed to initialize SSL/TLS server context: "
                       << this->transport().context().error());
        return false;
    }
}
```

Two details matter if you replicate this by hand. ALPN is **folded into the `Context`** by the chained `.alpn({"http/1.1"})` — there is no separate `set_supported_alpn_protocols` call on this path. And the failure check is `context().ok()`, not a null handle: a `Context` that failed to load its cert or key is falsy and carries the reason in `context().error()`. The whole block is inside `if constexpr (tpt::is_secure())`, so the same `listen` compiles unchanged for a plaintext transport, where it just binds the socket.

<!-- src: qb/src/qb/io/tcp/ssl/context.h:146,179,199,201 -->

The SSL-off build takes the `#else` arm, which discards `cert_file`/`key_file` and only listens.

<!-- src: qbm/http/src/qbm/http/1.1/http.h:585,597-601 -->

### Tuning the context before listening

The convenience `listen` covers the common case. When you need cipher policy, a minimum TLS version, mTLS, or a custom ALPN set, build a `qb::io::ssl::Context` yourself, install it with `transport().init(...)`, then call the plain `transport().listen(uri)`. The setters are fluent and chainable, each returns `Context&`, and each becomes a no-op once the context has recorded an error — so one `ok()` check at the end covers the whole chain:

<!-- src: qb/src/qb/io/tcp/ssl/context.h:62,72,127,146,173-176,179,181,199,201; qb/src/qb/io/tcp/ssl/listener.h:115 -->
```cpp
#include <qbm/http/http.h>
#include <qb/io/tcp/ssl/context.h>

auto server = qb::http::ssl::make_server();
// ... routes, compile() ...

auto ctx = qb::io::ssl::Context::server(cert, key)
               .min_version(qb::io::ssl::TlsVersion::v1_2)
               .max_version(qb::io::ssl::TlsVersion::v1_3)
               .ciphersuites("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
               // Mutual TLS: require a client certificate and verify it against this CA.
               .trust("client-ca.pem")
               .verify(qb::io::ssl::VerifyMode::peer_require)
               .alpn({"http/1.1"});
if (!ctx.ok()) { /* ctx.error() says why */ }

server->transport().init(std::move(ctx));   // shared by refcount with every accepted connection
server->transport().listen(qb::io::uri("https://0.0.0.0:8443"));
server->start();
```

`Context` also covers curves, DH parameters, server session caching and timeout, and typed callbacks for keylog, custom verification, and SNI routing (`on_sni` returns the `Context` to switch to). `native()` borrows the raw `SSL_CTX` for anything it does not wrap.

<!-- src: qb/src/qb/io/tcp/ssl/context.h:182-185,190,192,194,207 -->

**The raw `SSL_CTX` path still exists as an escape hatch.** `qb::io::ssl::create_server_context` plus the free helpers (`set_cipher_list`, `set_ciphersuites_tls13`, `set_tls_protocol_versions`, `configure_mtls_server_context`) all take an `SSL_CTX*`, and `listener::init(SSL_CTX*)` adopts it — but its own documentation says to prefer the `Context` overload, and ALPN on that path needs the separate `set_supported_alpn_protocols` member because `adopt()` treats a bare context as client-role. Reach for it only for an OpenSSL feature `Context` does not expose. The listener mirrors the free helpers as members once a context is installed — `set_cipher_list`, `set_ciphersuites_tls13`, `configure_mtls`, `set_supported_alpn_protocols` — and adds OCSP stapling, SNI host selection, and session caching; see `qb/src/qb/io/tcp/ssl/socket.h` and `qb/src/qb/io/tcp/ssl/listener.h`.

<!-- src: qb/src/qb/io/tcp/ssl/socket.h:95,123,132,142,154; qb/src/qb/io/tcp/ssl/listener.h:104-105,107,173,180,196,271; qb/src/qb/io/tcp/ssl/context.h:152-154 -->

The same secure HTTP/1.1 transport carries secure WebSocket (`wss://`): the connection upgrades over TLS exactly as plaintext WebSocket upgrades over TCP. See [WebSocket](./20-websocket.md).

## Serving HTTPS over HTTP/2

HTTP/2 in qbm-http is **TLS-only with ALPN** — there is no plaintext `h2c`. `qb::http2::Server::listen` mirrors the HTTP/1.1 overload but advertises `{"h2", "http/1.1"}`, so a client that negotiates `h2` gets HTTP/2 and one that does not falls back to HTTP/1.1 on the same port.

<!-- src: qbm/http/src/qbm/http/2/http2.h:499-508 -->
```cpp
#include <qbm/http/http.h>   // pulls in <qbm/http/2/http2.h> under QB_HAS_SSL
#include <qb/io/async.h>

qb::io::async::init();
auto server = qb::http2::make_server();

server->router().get("/hello", [](auto ctx) {
    ctx->response().body() = "served over HTTP/2";
    ctx->complete();
});
server->router().compile();

// listen(uri, cert, key): builds SSL_CTX, sets ALPN {"h2","http/1.1"}, listens.
if (!server->listen(qb::io::uri("https://0.0.0.0:9443"), cert, key)) { /* handle error */ }

server->start();
qb::io::async::run();
```

The protocol the session ends up speaking is decided after the handshake by inspecting the negotiated ALPN string — `"h2"` switches the session to the HTTP/2 protocol, anything else falls back to HTTP/1.1. For HPACK, streams, and flow control specifics see [HTTP/2 protocol specifics](./17-http2-protocol.md).

## Consuming HTTPS

### One-shot and coroutine clients

The callback and coroutine free functions (`qb::http::GET`, `POST`, `REQUEST`, …) pick the transport from the request URI scheme automatically. A `https://` URI routes through the secure `async::HTTPS` session (`stcp` transport); `http://` routes through plaintext. No SSL setup is required on the client for the common case — the system's default CA store verifies the server certificate.

<!-- src: qbm/http/src/qbm/http/1.1/http.h:866-893, 837-840, 808-809 -->
```cpp
#include <qbm/http/http.h>

qb::http::GET(
    qb::http::Request{qb::io::uri("https://api.example.com/data")},
    [](qb::http::async::Reply &&reply) {
        if (reply.response.status() == qb::http::status::OK) {
            // verified TLS response body in reply.response.body()
        }
    });
```

Every one-shot verb and the generic `REQUEST` take an optional trailing `bool verify_peer = true`. Leaving it at the default performs full certificate-chain and hostname verification; passing `false` disables both and **must only be used for trusted or self-signed endpoints you control**:

<!-- src: qbm/http/src/qbm/http/1.1/http.h:860, 873 -->
```cpp
// Dev only: accept a self-signed server certificate.
qb::http::GET(std::move(req), on_reply,
              qb::duration::zero() /* no timeout */,
              /*verify_peer=*/false);
```

The coroutine overloads carry the same `verify_peer` parameter and `co_await` the same way. See [Asynchronous HTTP client](./14-async-http-client.md) for the full client surface, including `run_sync`.

### Persistent HTTP/1.1 client

`qb::http1::Client` reuses one connection across requests. It defaults `verify_peer` to `true`; toggle it with `set_verify_peer(bool)` **before** connecting, since it is applied when the secure connection opens. The connect timeout is a `qb::duration` (default 30 seconds).

<!-- src: qbm/http/src/qbm/http/1.1/client.h:130, 134, 227, 252 -->
```cpp
#include <qbm/http/http.h>

auto client = qb::http1::make_client("https://service.internal:8443");
client->set_verify_peer(false);                       // self-signed internal endpoint
client->set_connect_timeout(std::chrono::seconds(10));
client->connect([client](bool ok, const std::string &err) {
    if (!ok) { /* err */ return; }
    // ... push_request over the established TLS connection ...
});
```

### HTTP/2 client

`qb::http2::Client` is HTTPS-only — `make_client` requires an `https://` base URI and the client offers **only** `{"h2"}` in ALPN, failing the connection if the server does not negotiate `h2`. It defaults `verify_peer` to `true`; call `set_verify_peer(false)` before `connect()` for trusted self-signed servers.

<!-- src: qbm/http/src/qbm/http/2/client.h:189, 343-346 -->
```cpp
#include <qbm/http/http.h>

auto client = qb::http2::make_client("https://h2.example.com");
client->set_verify_peer(true);                        // default; verify the chain
client->connect([client](bool connected, const std::string &/*err*/) {
    if (!connected) return;
    // ... client->push_request(...) over HTTP/2 ...
});
```

## ALPN negotiation in one paragraph

ALPN is a TLS extension where the client advertises the application protocols it supports and the server picks one during the handshake. qbm-http wires it for you: an HTTP/1.1 secure server advertises `{"http/1.1"}`, an HTTP/2 server advertises `{"h2", "http/1.1"}` and switches the session based on what was selected, the HTTP/2 client advertises `{"h2"}` only, and HTTP/3 negotiates `"h3"` over QUIC (a separate transport — see [HTTP/3 protocol](./19-http3-protocol.md)). You override the server's advertised set only when you build the context by hand: chain `.alpn({...})` on the `qb::io::ssl::Context` you pass to `transport().init(...)`, which is what both `listen` overloads do. `transport().set_supported_alpn_protocols({...})` is the raw-`SSL_CTX` counterpart, needed only on the `init(SSL_CTX*)` escape hatch.

<!-- src: qb/src/qb/io/tcp/ssl/context.h:179; qb/src/qb/io/tcp/ssl/listener.h:271; qbm/http/src/qbm/http/1.1/http.h:591; qbm/http/src/qbm/http/2/http2.h:501 -->

## Peer verification and trust

Client-side certificate verification is **secure by default** across every client surface — the one-shot verbs, the persistent `http1::Client`, and the `http2::Client` all default `verify_peer` to `true`, performing certificate-chain and hostname checks against the system CA store.

- Disable verification (`verify_peer=false` / `set_verify_peer(false)`) **only** for endpoints you trust and control, typically self-signed development servers. It turns off both chain and hostname checks and exposes the connection to interception.
- For private PKI, prefer adding your CA to the trust store over disabling verification. At the qb-io level you can load CAs into a client `SSL_CTX` with `qb::io::ssl::load_ca_certificates(ctx, path)` or `load_ca_directory(ctx, dir)`, set SNI/ALPN on the socket (`set_sni_hostname`, `set_alpn_protocols`), and present a client certificate (`configure_client_certificate`) for mTLS.

<!-- src: qb/src/qb/io/tcp/ssl/socket.h:104,114,164,822,834 -->

## Pitfalls

- **Do not assume HTTP/2 or HTTP/3 are always available.** They are SSL-gated (HTTP/3 additionally needs QUIC and libnghttp3). In an SSL-less build `qb::http2::*` and `qb::http::ws::*` are not even declared. Gate dependent code on `QB_HAS_SSL` (and `QBM_HTTP_HAS_HTTP3`), not on guesswork.
- **Do not gate on `QBM_HTTP_HAS_SSL`.** That marker is `PRIVATE` to the module build and invisible to consumers. The consumer-facing gate is the `PUBLIC` `QB_HAS_SSL`.
- **There is no plaintext `h2c`.** An HTTP/2 server is TLS-only; an HTTP/2 client that cannot negotiate `h2` over ALPN fails the connection rather than downgrading.
- **`listen` returning `false` usually means the cert/key failed to load.** A bad path, wrong permissions, or a key that does not match the certificate all surface as a `false` return and a context-creation log line — check the result and verify your PEM files.
- **`verify_peer=false` is a footgun, not a default.** It disables chain *and* hostname verification. Reserve it for trusted self-signed endpoints; never ship it pointed at the public internet.
- **`set_verify_peer` must be set before connecting.** On both `http1::Client` and `http2::Client` it is captured when the secure connection opens; changing it after `connect()` has no effect on the live connection.
- **The raw `SSL_CTX` you pass to `transport().init(...)` is adopted by the listener.** Do not `SSL_CTX_free` it yourself: `init(SSL_CTX*)` transfers your single reference into the listener's `qb::io::ssl::Context` (no up-ref), and that reference-counted context frees it. It is not a `unique_ptr` — the context is copied by reference count into every accepted connection. Prefer `init(qb::io::ssl::Context)`, where there is no raw handle to reason about. <!-- src: qb/src/qb/io/tcp/ssl/listener.cpp:37-42; qb/src/qb/io/tcp/ssl/listener.h:45,104-105,115 -->

## See also

- [Asynchronous HTTP client](./14-async-http-client.md) — the full client surface, `verify_peer`, and coroutine overloads.
- [HTTP/2 protocol specifics](./17-http2-protocol.md) — TLS+ALPN `h2`, HPACK, streams, flow control.
- [HTTP/3 protocol](./19-http3-protocol.md) — QUIC, the `h3` ALPN, and the dual-stack server.
- [WebSocket](./20-websocket.md) — `wss://` over the same secure HTTP/1.1 transport.
- [Authentication system](./11-authentication.md) — JWT issue/verify, another `QB_HAS_SSL`-gated surface.
- [Module front door](../README.md) — the build and feature matrix.

# qbm-http — HTTP/1.1, HTTP/2, HTTP/3, and WebSocket for the qb Actor Framework (QBAF)

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 3.0.0 (C++20 default, C++23 supported)

`qbm-http` is a compiled module of the qb Actor Framework (QBAF) that gives an actor asynchronous HTTP servers and clients — HTTP/1.1 always, plus HTTP/2, HTTP/3, WebSocket, JWT, and authentication on builds that enable SSL and QUIC — over qb-io's non-blocking I/O.

**Prerequisites:** a working [qb framework](https://github.com/isndev/qb) checkout (`qb-core` + `qb-io`); a C++20 toolchain (C++23 optional); CMake 3.24+. — **See also:** [readme/README.md](./readme/README.md) (full guide), [routing](./readme/03-routing-overview.md), [async client](./readme/14-async-http-client.md), [WebSocket](./readme/20-websocket.md).

## What this module is

`qbm-http` builds REST APIs, static-content servers, request clients, and WebSocket endpoints as qb actors. It is **not header-only**: the CMake build registers it as a compiled library (`qb_register_module` with a `SOURCES` list — `request.cpp`, `response.cpp`, `body.cpp`, the HTTP/1.1 protocol and client, the validation engine, and SSL-gated `auth/`, `ws/`, and HTTP/2 sources). You still consume it through a single umbrella header, `<qbm/http/http.h>`.

On top of the wire protocols it ships a fluent routing engine (path parameters, groups, controllers), a middleware pipeline, request validation and sanitization, cookie and multipart handling, JWT-based authentication, and both callback and C++20-coroutine client APIs.

The protocol surface is gated by the underlying qb build:

- **HTTP/1.1, routing, middleware, validation, cookies, multipart, the callback/coroutine HTTP/1.1 client** — always available.
- **HTTPS, HTTP/2, WebSocket (both `ws://` and `wss://`), JWT, and `qb::http::auth`** — require `QB_HAS_SSL` (OpenSSL). Without it, CMake prints `HTTP SSL-backed features disabled: HTTPS/WSS/JWT/HTTP3 and the HTTP/2 transport (client + server session) will not be built; the HTTP/2 wire codec under 2/protocol/ still is, so its unit tests keep running`, and those translation units are not compiled. The transport-independent HTTP/2 wire codec (`2/protocol/`) *is* still compiled, but nothing in an SSL-off build can reach it — `qb::http2` remains undeclared.
- **HTTP/3** — requires `QBM_HTTP_HAS_HTTP3`, which is set only when `QB_HAS_SSL`, `QB_HAS_QUIC`, and `libnghttp3` are all present. `libnghttp3` is located by the module's own `cmake/FindNghttp3.cmake`, which treats `pkg-config` as a hint and falls back to `find_path` / `find_library`, so an installation without a `.pc` file is still found.

These gates are real `#ifdef` boundaries in the headers, so feature availability in your code matches what was compiled. `<qbm/http/http.h>` includes `src/qbm/http/2/http2.h` and `src/qbm/http/ws/ws.h` only under `#ifdef QB_HAS_SSL`, and the HTTP/3 headers only under `#ifdef QBM_HTTP_HAS_HTTP3`.

## Feature and build matrix

<!-- src: qbm/http/CMakeLists.txt:26-103, qbm/http/src/qbm/http/http.h:43-53 -->

| Capability | Header / namespace | Compile gate | Required dependency |
|---|---|---|---|
| HTTP/1.1 server & client | `<qbm/http/http.h>` · `qb::http`, `qb::http1` | always | vendored `llhttp` |
| Routing, middleware, controllers | `<qbm/http/http.h>` · `qb::http` | always | — |
| Validation & sanitization | `<qbm/http/http.h>` · `qb::http::validation` | always | — |
| Cookies, multipart, HTTP dates | `<qbm/http/http.h>` · `qb::http` | always | — |
| HTTPS server & client | `qb::http::ssl`, `qb::http1::Client` (TLS) | `QB_HAS_SSL` | OpenSSL |
| HTTP/2 server & client | `qb::http2` | `QB_HAS_SSL` | OpenSSL (ALPN `h2`) |
| WebSocket / WSS | `<qbm/http/ws.h>` · `qb::http::ws` | `QB_HAS_SSL` (both `ws://` and `wss://`) | OpenSSL (handshake crypto + TLS) |
| JWT & authentication | `<qbm/http/auth.h>` · `qb::http::auth` | `QB_HAS_SSL` | OpenSSL |
| HTTP/3 server & client | `qb::http3`, `qb::http::dual_stack_server` | `QBM_HTTP_HAS_HTTP3` | OpenSSL + QUIC + `libnghttp3` |

The entire WebSocket surface requires `QB_HAS_SSL`, including plain `ws://` — `src/qbm/http/ws/ws.h` opens with `#error "websocket protocol requires OpenSSL crypto library"` because the RFC 6455 handshake (`qb::http::ws::generateKey`, the `base64(sha1(key + GUID))` accept, and CSPRNG frame masking) builds on qb-io's `crypto::sha1` / `crypto::base64`. The umbrella `<qbm/http/http.h>` pulls in `src/qbm/http/ws/ws.h` and `src/qbm/http/2/http2.h` only under `#ifdef QB_HAS_SSL`, so reach for `qb::http::ws` and `qb::http2` in SSL-enabled builds.

## Integration

Two supported modes, both giving the same target (`qbm::http`) and the same header spelling (`<qbm/http/...>`).

**Embedded** — add qb as a subdirectory, load the modules directory, link the target:

```cmake
# CMakeLists.txt
add_subdirectory(qb)                                  # configures qb-core + qb-io, sets QB_FOUND
qb_load_modules("${CMAKE_CURRENT_SOURCE_DIR}/qbm")    # discovers and registers qbm/http

add_executable(app main.cpp)
target_link_libraries(app PRIVATE qbm::http)          # PUBLIC-pulls qb::core, qb::io, llhttp
```

**Installed** — consume a `cmake --install`ed tree. You do **not** need a `find_package(qb)` line: the module's package config resolves qb (and, for an HTTP/3 build, nghttp3) itself.

```cmake
find_package(qbm-http CONFIG REQUIRED)                # find_dependency(qb) happens inside
add_executable(app main.cpp)
target_link_libraries(app PRIVATE qbm::http)
```

The package lands headers under `<prefix>/include/qbm/http/...` and its CMake files under `<prefix>/lib/cmake/qbm-http/`; `<prefix>/include` is a verbatim copy of this repository's `src/`, so `#include <qbm/http/http.h>` is unchanged between the two modes. `qbm-httpConfig.cmake` hard-fails at configure time if the installed qb is a different version than the one this module was compiled against, or disagrees with it about `QB_HAS_SSL` / `QB_HAS_QUIC` — the module's public headers are `#ifdef`-gated on those.

`qb_load_modules` globs and sorts the module subdirectories under the given path and `add_subdirectory`s each that has a `CMakeLists.txt`. The `http` module guards on `QB_FOUND` and returns early if qb has not been configured first, so the `add_subdirectory(qb)` line must come before `qb_load_modules`.

Because module dependencies link `PUBLIC`, the `QB_HAS_SSL` / `QB_HAS_QUIC` compile definitions and the `qb::core` / `qb::io` headers propagate to your target — that is what makes the `#ifdef QB_HAS_SSL` and `#ifdef QBM_HTTP_HAS_HTTP3` gates resolve consistently in your own code. The module also propagates the framework C++ standard as a `PUBLIC` usage requirement — `cxx_std_${QB_CXX_STANDARD}`, i.e. `cxx_std_20` by default, or `cxx_std_23` when the build is configured with `QB_CXX_STANDARD=23`.

```cpp
#include <qbm/http/http.h>            // umbrella: HTTP/1.1 always; HTTP/2 + WS under SSL; HTTP/3 under QUIC
#include <qbm/http/ws.h>              // WebSocket message/protocol/coroutine surface (SSL build)
#include <qbm/http/auth.h>            // qb::http::auth — JWT options, user, manager (SSL build)
#include <qbm/http/middleware/all.h>  // built-in middleware (CORS, compression, security headers, ...)
```

## Quickstart: a server

An HTTP/1.1 server is an actor that mixes in `qb::http::Server<>`, defines routes on `router()`, compiles the router, then `listen` + `start`.

<!-- src: examples/qbm/http/03_basic_routing.cpp:23-56 -->

```cpp
#include <qbm/http/http.h>
#include <qb/main.h>
#include <iostream>

class ApiServer : public qb::Actor, public qb::http::Server<> {
public:
    qb::io::async::task<bool> onInit() override {
        router().get("/", [](auto ctx) {
            ctx->response().body() = "Hello from qbm-http";
            ctx->complete();
        });

        router().get("/users/:id", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "user " + ctx->path_param("id");
            ctx->complete();
        });

        router().compile();                      // required before serving

        if (listen({"tcp://0.0.0.0:8080"})) {    // qb::io::uri
            start();
            std::cout << "listening on http://localhost:8080\n";
            co_return true;
        }
        co_return false;
    }
};

int main() {
    qb::Main engine;
    engine.addActor<ApiServer>(0);
    engine.start();   // launches one worker thread per used core, then returns
    engine.join();    // blocks until every actor terminates
    return 0;
}
```

Each handler receives a `ctx` (a `std::shared_ptr<qb::http::Context<Session>>`), reads `ctx->request()`, writes `ctx->response()`, and calls `ctx->complete()` to send. Path parameters come from `ctx->path_param("id")`. Note that the HTTP `DELETE` verb is spelled `qb::http::Method::DEL` (and `router().del(...)`) because `delete` is a C++ keyword.

For TLS, mix in `qb::http::ssl::Server<>` instead and pass certificate and key paths to `listen` (`QB_HAS_SSL` only). For HTTP/2, use `qb::http2::Server<>` / `qb::http2::make_server()` over an `https://` listener.

## Quickstart: a client

The one-shot client free functions (`GET`, `POST`, `REQUEST`, ...) heap-allocate a self-deleting session, run a single request, and deliver an `qb::http::async::Reply` (the original request plus the response). The callback form takes a `qb::duration` timeout.

<!-- src: qbm/http/src/qbm/http/1.1/http.h:858-872 -->

```cpp
#include <qbm/http/http.h>
#include <qb/main.h>

class FetchActor : public qb::Actor {
public:
    qb::io::async::task<bool> onInit() override {
        qb::http::Request req{{"http://localhost:8080/users/42"}};
        req.add_header("User-Agent", "qbm-http/1.0");

        qb::http::GET(std::move(req), [this](qb::http::async::Reply&& reply) {
            if (reply.response.status() == qb::http::status::OK)
                qb::io::cout() << "body: " << reply.response.body().as<std::string>() << "\n";
            kill();
        });
        co_return true;
    }
};
```

The same `GET`/`POST`/`REQUEST` names also have coroutine overloads that return `qb::http::async::awaiter<qb::http::async::Reply>`. Drive them with `co_await` inside a coroutine, or with `qb::http::run_sync(...)` from a plain function:

<!-- src: qbm/http/tests/system/coro/coro-client-http1.cpp:196-200 -->

```cpp
#include <qbm/http/http.h>

int main() {
    qb::io::async::init();                       // one event loop on this thread
    auto reply = qb::http::run_sync(
        qb::http::GET(qb::http::Request{{"http://localhost:8080/"}}));
    if (reply.response.status() == qb::http::status::OK)
        std::cout << reply.response.body().as<std::string>() << "\n";
    return 0;
}
```

For connection reuse against a single origin, use `qb::http1::Client` (request queue, batching, timeouts, auto-reconnect) — see [the async client guide](./readme/14-async-http-client.md). HTTP/2 and HTTP/3 expose analogous `qb::http2::Client` / `qb::http3::Client` types with multiplexed `push_request` / `push_requests`.

## WebSocket at a glance

WebSocket is part of `qbm-http` (namespace `qb::http::ws`); there is no separate module. A server session starts as HTTP/1.1, validates the RFC 6455 `GET` upgrade, then switches the connection from HTTP parsing to WebSocket framing with `switch_protocol`.

<!-- src: qbm/http/tests/system/ws/ws-lifecycle.cpp:100-119 -->

```cpp
#include <qbm/http/http.h>
#include <qbm/http/ws.h>

class WsSession : public qb::io::use<WsSession>::tcp::client<WsServer> {
public:
    using Protocol    = qb::http::protocol<WsSession>;
    using WS_Protocol = qb::http::ws::protocol<WsSession>;

    explicit WsSession(IOServer& server) : client(server) {}

    void on(Protocol::request&& request) {       // HTTP upgrade arrives
        if (!this->switch_protocol<WS_Protocol>(*this, request))
            disconnect();
    }

    void on(WS_Protocol::message&& event) {       // framed WS message
        *this << event.ws;                        // echo
    }
};
```

Clients can use the callback API (`qb::http::ws::WebSocket<T>`, `qb::http::ws::client`) or the coroutine API (`qb::http::ws::coro_client`, `co_await connect/receive/close_async`). See [WebSocket](./readme/20-websocket.md) and [WebSocket coroutines](./readme/21-websocket-coroutines.md).

## Time and duration vocabulary

`qbm-http` follows qb's chrono model:

- Cookie `max_age` / `expires_in`, CORS preflight, and rate-limit windows are `qb::duration`.
- JWT token lifetime and clock-skew tolerance are `std::chrono::seconds` — the RFC 7519 `NumericDate` boundary, deliberately kept at seconds resolution.
- HTTP date formatting/parsing (`qb::http::date`) bridges `std::chrono::system_clock` and `qb::wall_time`.

## Pitfalls

- **Compile the router.** `router().compile()` must run after all routes are defined and before serving, or no route matches.
- **`complete()` is mandatory.** A handler that never calls `ctx->complete()` (or `ctx->cancel()`) leaves the request hanging until the inactivity timeout fires.
- **Feature gates are build-time.** `qb::http2`, `qb::http::ws` (WSS), and `qb::http::auth` only exist when `QB_HAS_SSL` was on; `qb::http3` only when `QBM_HTTP_HAS_HTTP3` was set. Guard optional code paths with the same macros if your project ships in both configurations.
- **`DELETE` is `DEL`.** Use `qb::http::Method::DEL` and `router().del(...)`.
- **Not header-only.** Don't try to consume the headers without linking `qbm::http`; the message types, protocol, validation, and SSL-gated features live in compiled translation units.
- **Configure qb first.** The module's `CMakeLists` returns early unless `QB_FOUND` is true, so `add_subdirectory(qb)` precedes `qb_load_modules`.

## Documentation map

The full guide lives under [`readme/`](./readme/README.md):

| Topic | Guide |
|---|---|
| Request / response / message model | [01-core-concepts.md](./readme/01-core-concepts.md) |
| Body, streaming, compression | [02-body-deep-dive.md](./readme/02-body-deep-dive.md) |
| Routing overview & path matching | [03-routing-overview.md](./readme/03-routing-overview.md) |
| Defining routes & parameters | [04-defining-routes.md](./readme/04-defining-routes.md) |
| Route groups | [05-route-groups.md](./readme/05-route-groups.md) |
| Controllers | [06-controllers.md](./readme/06-controllers.md) |
| Middleware pipeline | [07-middleware.md](./readme/07-middleware.md) |
| Standard middleware | [08-standard-middleware.md](./readme/08-standard-middleware.md) |
| Custom middleware | [09-custom-middleware.md](./readme/09-custom-middleware.md) |
| Request context & lifecycle | [10-request-context.md](./readme/10-request-context.md) |
| Authentication & JWT | [11-authentication.md](./readme/11-authentication.md) |
| Validation & sanitization | [12-validation.md](./readme/12-validation.md) |
| Error handling | [13-error-handling.md](./readme/13-error-handling.md) |
| Async / coroutine HTTP client | [14-async-http-client.md](./readme/14-async-http-client.md) |
| HTTP message parsing | [15-http-parsing.md](./readme/15-http-parsing.md) |
| Advanced topics & performance | [16-advanced-topics.md](./readme/16-advanced-topics.md) |
| HTTP/2 protocol | [17-http2-protocol.md](./readme/17-http2-protocol.md) |
| HTTPS / SSL / TLS | [18-https-ssl-tls.md](./readme/18-https-ssl-tls.md) |
| HTTP/3 protocol | [19-http3-protocol.md](./readme/19-http3-protocol.md) |
| WebSocket (RFC 6455, WSS) | [20-websocket.md](./readme/20-websocket.md) |
| WebSocket coroutines | [21-websocket-coroutines.md](./readme/21-websocket-coroutines.md) |

Runnable examples are under [`examples/qbm/http/`](https://github.com/isndev/qb-examples/tree/main/qbm/http) in the repository.

## For AI assistants

This repository publishes machine-readable documentation following the
[llms.txt](https://llmstxt.org/) convention, so a coding agent can read qbm-http without
guessing:

- **[`llms.txt`](./llms.txt)** — the index: a one-paragraph summary, the six rules that decide whether generated qbm-http code is correct, and a link
  list of every document in this repository.
- **[`llms-full.txt`](./llms-full.txt)** — ~30k tokens: `llm/qbm-http.llm.md` (the mental model, invariants and gotchas) and `llm/qbm-http.llm.api.md` (a deterministic public-API reference, every signature verified against the headers under `src/qbm/http/`), concatenated into one fetch.

Both files are generated by `scripts/gen-llms-txt.py` from `llm/` and checked in CI
(`scripts/doc-lint.sh` section 1d), so they cannot drift from the documentation they index.

**Use it over MCP, with nothing to host and nothing to install.**
[GitMCP](https://gitmcp.io) exposes any public GitHub repository as an MCP endpoint and reads
`llms.txt` first (its documented order is `llms.txt`, then an AI-optimised documentation
build, then `README.md`):

```json
{ "mcpServers": { "qbm-http": { "url": "https://gitmcp.io/isndev/qbm-http" } } }
```

Claude Desktop and other clients without native remote-MCP support wrap the same URL:
`"command": "npx", "args": ["mcp-remote", "https://gitmcp.io/isndev/qbm-http"]`.

**Cursor `@Docs`** — add
`https://raw.githubusercontent.com/isndev/qbm-http/main/llms-full.txt`.

## License

Apache License 2.0. See [LICENSE](./LICENSE). HTTP/1.1 parsing structures come from [llhttp](https://github.com/nodejs/llhttp) — a fork with the upstream `llhttp_*` symbols renamed to `http_*`, so it is owned rather than published: the C sources are vendored under `not-qb/llhttp` and its single public header is `src/qbm/http/vendor/llhttp.h`, reached as `<qbm/http/vendor/llhttp.h>`. I/O is handled entirely by qb-io.

---

Part of the [qb actor framework](https://github.com/isndev/qb).

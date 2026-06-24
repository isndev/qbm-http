# Core HTTP concepts

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 2.0.0 (C++20 default, C++23 supported)

The value types every other page builds on: `Request`, `Response`, the case-insensitive multi-value `Headers` map, the `Body` payload, and the `Method`/`Status` wrappers — all in the `qb::http` namespace, all riding on qb-io's asynchronous sessions.

**Prerequisites:** working knowledge of the qb actor framework and `qb-io` async I/O — see [`qb/README.md`](../../../qb/README.md). **See also:** the doc map [`README.md`](./README.md), the [body deep dive](./02-body-deep-dive.md), and [the request context](./10-request-context.md) for how these types reach a handler.

## What this page covers

This page describes the data model. It is protocol-agnostic: the same `Request`, `Response`, `Headers`, and `Body` flow through HTTP/1.1, HTTP/2, and HTTP/3 unchanged — only the wire framing differs. The protocol-specific machinery (servers, clients, parsers) is covered in later pages.

Everything here lives in the `qb::http` namespace and is reachable through the umbrella header. qbm-http is a **compiled library**, not header-only: the build registers it with `qb_register_module` and a `SOURCES` list (`qbm/http/CMakeLists.txt`), so consuming it links a real archive. You still include one header:

```cpp
#include <http/http.h>   // pulls in qb::http::Request, Response, Headers, Body, Method, Status
```

## The message model

Both message types derive from a single internal base.

<!-- src: qbm/http/message_base.h -->
```cpp
namespace qb::http::internal {
    struct MessageBase
        : public Headers   // case-insensitive multi-value header map + ContentType helper
        , public Body       // the payload, backed by qb::allocator::pipe<char>
    {
        uint16_t      major_version;     // 1 for HTTP/1.1
        uint16_t      minor_version;     // 1 for HTTP/1.1
        bool          upgrade{};         // connection upgrade requested (e.g. WebSocket)
        std::uint64_t stream_id{0};      // HTTP/2 / HTTP/3 stream id; 0 for HTTP/1.1
        bool          keep_alive{false}; // HTTP/1.x persistence decision from the parser
    };
}
```

`MessageBase` *multiply inherits* `Headers` and `Body`. That is why a `Request` or `Response` is itself a header map and itself a body — you call `req.set_header(...)` and `req.body()` directly on the message, with no intermediate accessor. The version fields default to HTTP/1.1; the parser sets `stream_id`, `keep_alive`, and `upgrade` as it reads the wire. Construction is `noexcept` and starts from a clean header map.

| Type | Alias | Header | Adds over `MessageBase` |
|---|---|---|---|
| `qb::http::Request` | `qb::http::request` | `<http/http.h>` | `Method`, `qb::io::uri`, request `CookieJar` |
| `qb::http::Response` | `qb::http::response` | `<http/http.h>` | `Status`, response `CookieJar` (serialized to `Set-Cookie`) |

## `qb::http::Request`

A `Request` carries a method, a target URI, headers, a body, and a jar of parsed `Cookie` headers. The default constructor leaves the method `UNINITIALIZED` with an empty URI; the single-argument `Request(qb::io::uri)` constructor defaults the method to `GET`, and the two-argument constructor takes an explicit method and a `qb::io::uri`. (`reset()` sets the method to `GET`.)

<!-- src: qbm/http/request.h -->
```cpp
#include <http/http.h>

// method + URI; headers and body default-construct.
qb::http::Request req{qb::http::method::POST, qb::io::uri("/submit?type=test")};
req.set_header("User-Agent", "qb-client/2.0");
req.set_content_type("application/json");
req.body() = R"({"key":"value"})";

const qb::http::Method &m   = req.method();              // qb::http::method::POST
const qb::io::uri      &uri = req.uri();                 // full parsed URI
const std::string      &q   = req.query("type");         // "test" (empty string if absent)
const std::string      &ua  = req.header("User-Agent");  // "qb-client/2.0"
```

Key accessors, each verified against `request.h`:

| Member | Returns | Notes |
|---|---|---|
| `method()` | `const Method&` / `Method&` | the HTTP verb; see [methods and statuses](#methods-and-statuses) |
| `uri()` | `const qb::io::uri&` / `qb::io::uri&` | scheme, host, path, query, fragment — a qb-io type |
| `query(name, index = 0)` | `const std::string&` | a single query parameter; `index` selects among repeated keys. On a miss returns a process-wide static empty string (never a temporary). For a custom fallback use `query_or(name, fallback, index = 0)`, which returns `std::string` by value. Delegates to `uri().query(...)` |
| `queries()` | the URI's query map | `qb::icase_unordered_map<std::vector<std::string>>` |
| `parse_cookie_header()` | `void` | parses the `Cookie` header into the jar; call it before reading cookies |
| `cookie(name)` | `const Cookie*` | `nullptr` if absent (case-insensitive name) |
| `cookie_value(name)` | `const std::string&` | the value, or a static empty string on a miss. For a custom fallback use `cookie_value_or(name, fallback)`, which returns `std::string` by value |
| `has_cookie(name)` | `bool` | presence test |

Request cookies are not parsed automatically — call `parse_cookie_header()` once the headers are present, then read from the jar.

<!-- src: qbm/http/tests/test-cookie.cpp -->
```cpp
qb::http::Request request;
request.add_header("Cookie", "name1=value1; name2=value2");
request.parse_cookie_header();                       // populate the jar
const qb::http::Cookie *c = request.cookie("name1"); // -> "value1", or nullptr
```

The `with_*` fluent setters (`with_method`, `with_uri`, `with_header`, `with_body`, `with_cookie`, ...) each return `Request&` for chaining. Only `with_method` is `noexcept`; the others allocate.

## `qb::http::Response`

A `Response` carries a status, headers, a body, and a `CookieJar` whose entries serialize to `Set-Cookie` headers. The default constructor sets `200 OK`.

<!-- src: qbm/http/response.h -->
```cpp
#include <http/http.h>

qb::http::Response res;                          // defaults to 200 OK
res.status() = qb::http::status::OK;             // explicit, equivalent
res.set_content_type("application/json; charset=utf-8");
res.body() = R"({"message":"ok"})";

int code = res.status().code();                  // 200
std::string_view reason = res.status().str();    // "OK"
```

Status is the only response-specific scalar; everything else (headers, body) comes from `MessageBase`. The cookie surface differs from `Request` because responses *set* cookies rather than read them:

| Member | Effect |
|---|---|
| `status()` | `const Status&` / `Status&` — the status code |
| `add_cookie(Cookie)` / `add_cookie(name, value)` | adds to the jar **and** appends a matching `Set-Cookie` header |
| `remove_cookie(name[, domain, path])` | emits a `Set-Cookie` with `Max-Age: 0` and a past expiry, telling the client to drop it |
| `cookie(name)` | `const Cookie*` / `Cookie*` scheduled to be set |
| `update_cookie_header(name)` / `update_cookie_headers()` | re-sync `Set-Cookie` after editing the jar directly |
| `parse_set_cookie_headers()` | parse existing `Set-Cookie` headers into the jar (e.g. when proxying) |

`add_cookie` keeps the jar and the raw `Set-Cookie` headers in lockstep. If you mutate a cookie through the pointer or the jar reference, you must call `update_cookie_header(name)` (or `update_cookie_headers()`) afterward — the header text does not update itself.

<!-- src: qbm/http/tests/test-cookie.cpp -->
```cpp
qb::http::Response response;
response.add_cookie("session", "abc123");          // jar + Set-Cookie header, in sync
bool present = response.has_header("Set-Cookie");  // true
```

Cookie attributes (`max_age`, `expires_in`, `Path`, `Domain`, `SameSite`) are covered in the cookie material; note `max_age` is a `qb::duration`.

## Headers

`qb::http::Headers` is the shared header container, aliased as `qb::http::headers`. It is a **case-insensitive, multi-value** map: header names compare case-insensitively, and one name may hold several values (`Set-Cookie`, `Via`, `Accept-Encoding`, ...). The underlying type is `qb::icase_unordered_map<std::vector<std::string>>` (`qb::http::headers_map`).

> Header values are owning `std::string`, not `std::string_view`. A zero-copy view mode existed historically but was retired: the qb input pipe relocates buffer bytes between reads, and the async request lifecycle (shared `Context`, middleware chain, coroutines) cannot guarantee a captured view outlives the socket read. Owning strings make the lifetime safe.

<!-- src: qbm/http/headers.h -->
```cpp
#include <http/http.h>

qb::http::Request req;

req.set_header("X-Request-Id", "12345");      // replaces any existing values
req.add_header("Accept-Encoding", "gzip");    // first value
req.add_header("Accept-Encoding", "deflate"); // appends a second value

const std::string &id = req.header("x-request-id"); // case-insensitive lookup -> "12345"
bool has = req.has_header("Accept-Encoding");        // true

// multi-value access: index selects among values for one name
const std::string &enc0 = req.header("Accept-Encoding", 0); // "gzip"
const std::string &enc1 = req.header("Accept-Encoding", 1); // "deflate"
```

| Member | Behavior |
|---|---|
| `header(name, index = 0)` | value at `index`; on a miss returns a reference to a process-wide static empty string (never a temporary). For a custom fallback use `header_or(name, fallback, index = 0)`, which returns `std::string` by value |
| `set_header(name, value)` | replace all values for `name` with this one |
| `add_header(name, value)` | append a value (multi-value support) |
| `has_header(name)` | presence test (case-insensitive) |
| `remove_header(name)` | erase all values for `name` |
| `headers()` | the underlying `headers_map` (direct mutation) |
| `attributes(name, index = 0, default_to_parse = "")` | parse the header value's parameters into a `qb::icase_unordered_map<std::string>` (e.g. `Content-Disposition` fields) |
| `header_count()` | number of distinct header names |
| `exceeds_header_limit(max = 100)` | DoS guard; the parser caps inbound headers at `protocol_limits::MAX_HEADERS_COUNT` (100) |

`header(...)` returns a reference, not a copy, and never throws on a missing name — it returns a stable reference to a process-wide static empty string. There is no fallback argument; for a custom default use `header_or(name, fallback)`, which returns `std::string` by value. If you mutate the map directly through `headers()`, call `refresh_content_type()` so the cached `Content-Type` helper stays correct; the typed setters keep it in sync automatically.

### The `Content-Type` helper

`Headers` caches a parsed `Content-Type` so you do not re-parse the MIME type and charset on every read. `set_content_type(value)` updates both the raw header and the cached helper; `content_type()` returns the parsed view.

<!-- src: qbm/http/tests/test-headers.cpp -->
```cpp
qb::http::Headers headers;
headers.set_header("Content-Type", "text/html; charset=UTF-16");

headers.content_type().type();    // "text/html"
headers.content_type().charset(); // "UTF-16"
```

Defaults apply when the header is absent or unparseable: `application/octet-stream` for the type, `utf-8` for the charset.

## The body

`qb::http::Body` is the message payload, backed by `qb::allocator::pipe<char>` — a dynamic buffer tuned for I/O that minimizes reallocation. Because `Request` and `Response` inherit `Body` through `MessageBase`, `req.body()` and `res.body()` hand you the `Body` subobject directly.

<!-- src: qbm/http/body.h -->
```cpp
#include <http/http.h>

qb::http::Response res;

res.body() = "Hello, world!";                   // assign text
std::string text = res.body().as<std::string>();

res.body() = qb::json{{"count", 42}};            // assign JSON (serialized to the buffer)
qb::json j = res.body().as<qb::json>();          // parse back out

res.body().clear();
res.body() << "Part1" << ' ' << "Part2" << 123;  // append; arithmetics are stringified
std::size_t n = res.body().size();               // byte count; empty() also available
```

The body accepts a constrained set of types on assignment and append — `std::string`, `std::string_view`, `const char*`, `std::vector<char>`, `qb::json`, `Form`, `Multipart`, `Chunk`, and arithmetic types (stringified). Conversion out via `as<T>()` is implemented only for `std::string`, `std::string_view`, `qb::json`, `Multipart`, and `Form`; any other `T` is a compile-time error. The full type matrix, chunked encoding, and gzip/deflate `compress`/`uncompress` (gated on `QB_HAS_COMPRESSION`) are in [the body deep dive](./02-body-deep-dive.md).

## Methods and statuses

`qb::http::Method` and `qb::http::Status` are value-type wrappers over llhttp's enums (`http_method`, `http_status`), aliased as `qb::http::method` and `qb::http::status`. They give you type safety, string conversion, and comparisons instead of raw integers.

<!-- src: qbm/http/types.h -->
```cpp
#include <http/http.h>

qb::http::Method m = qb::http::method::POST;
std::string_view name = m;                 // "POST" (implicit conversion)
std::string s = std::to_string(m);         // "POST" (std::to_string is overloaded for Method/Status)

qb::http::Status st = qb::http::status::NOT_FOUND;
int code = st.code();                      // 404
std::string_view reason = st.str();        // "Not Found"
bool ok = (st == qb::http::status::OK);    // false
```

Two practical notes from `types.h`:

- The DELETE verb is spelled **`qb::http::method::DEL`** (`DELETE` collides with the C++ `delete` keyword); `method::DELETE_METHOD` is a readable alias for the same value. A default-constructed `Method` is `UNINITIALIZED`.
- A default-constructed `Status` is `200 OK`. `Status` constructs from an `int`, so `qb::http::Status{418}` is valid.

The header also defines `qb::http::endl` (`"\r\n"`) and `qb::http::sep` (a space) for raw message assembly, plus `std::to_string(method|status)` overloads and `std::hash` specializations for both wrappers (all declared in namespace `std`).

## How these types sit on qb-io sessions

The message types are pure data; the protocol layer moves them across qb-io's asynchronous transports. On the server side, a per-connection **session** is a CRTP type built on `qb::io::async::tcp::client`. The session's protocol parses inbound bytes into a `qb::http::Request`, hands it to the `Router`, and serializes the resulting `qb::http::Response` back onto the socket — all inside the qb event loop, never blocking.

<!-- src: qbm/http/1.1/http.h -->
```cpp
#include <http/http.h>

auto server = qb::http::make_server();              // DefaultSession over plain TCP
server->router().get("/api/data", [](auto ctx) {
    ctx->response().status() = qb::http::status::OK;
    ctx->response().body() = qb::json{{"message", "Hello"}};
    ctx->complete();                                 // hand the response back to the session
});
server->router().compile();                          // required before serving requests
server->listen(qb::io::uri("http://0.0.0.0:8080"));
```

The same `Request`/`Response` objects you build by hand are the ones the session parses and serializes. Inside a handler you reach them through `ctx->request()` and `ctx->response()` on the `Context<Session>` the router constructs — see [the request context](./10-request-context.md). Serialization is provided by `qb::allocator::pipe<char>::put` specializations for `Request` and `Response` (declared in `request.h`/`response.h`), which the session invokes when writing to the socket; oversized messages throw `std::length_error` against `qb::http::protocol_limits`.

The transport under the session selects the protocol and the feature gate:

| Surface | Transport | Build gate |
|---|---|---|
| `qb::http::make_server` / `DefaultSession` | plain TCP | none (HTTP/1.1 always available) |
| `qb::http::ssl::make_server` / `DefaultSecureSession` | TLS | `QB_HAS_SSL` |
| `qb::http2::make_server` | TLS + ALPN `h2` | `QB_HAS_SSL` |
| `qb::http3::make_server` | QUIC + ALPN `h3` | `QBM_HTTP_HAS_HTTP3` |

HTTP/2 and HTTP/3 reuse the message model wholesale: HPACK/QPACK decode into the same `Headers` map, `:status` maps to `Response::status()`, and `:method`/`:scheme`/`:authority`/`:path` reconstruct the `Request`'s method and `qb::io::uri`. The `stream_id` field on `MessageBase` carries the multiplexed stream identity for those protocols.

## Pitfalls

- **`Body`/`Headers` are base classes, not members.** Call `req.set_header(...)` and `req.body()` on the message directly. There is no `req.headers().set(...)` setter — `headers()` returns the raw map for inspection or bulk replacement, after which you call `refresh_content_type()`.
- **Request cookies need `parse_cookie_header()`.** The jar is empty until you parse. Reading `req.cookie("x")` before parsing returns `nullptr`.
- **Editing a response cookie in place desyncs the header.** After mutating through `cookie(name)` (non-const) or the `cookies()` jar, call `update_cookie_header(name)` or `update_cookie_headers()`.
- **DELETE is `method::DEL`.** `method::DELETE` does not exist; use `DEL` or the `DELETE_METHOD` alias.
- **`as<T>()` is closed.** Only `std::string`, `std::string_view`, `qb::json`, `Multipart`, and `Form` convert out of a `Body`; anything else fails to compile.
- **Header values are `std::string`, not views.** Do not assume zero-copy header storage; the view mode was removed for lifetime safety.

## See also

- [HTTP message body deep dive](./02-body-deep-dive.md) — the full `Body` conversion matrix, chunked transfer, and compression.
- [The request context](./10-request-context.md) — how `Request`/`Response` reach a handler and the response helpers (`json`, `text`, `redirect`, status shortcuts).
- [Routing overview](./03-routing-overview.md) — how the session dispatches a parsed `Request`.
- [Asynchronous HTTP client](./14-async-http-client.md) — building `Request` objects to send rather than receive.
- The module front door [`../README.md`](../README.md) — build matrix, feature gates, and a runnable example.

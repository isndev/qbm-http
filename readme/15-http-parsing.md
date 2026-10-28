# HTTP message parsing and framing

> **Audience:** Contributor · **Status:** stable · **Verified-against:** qbm-http @ qb 3.3.0 (C++20 default, C++23 supported)

How raw bytes off a qb-io socket become a `qb::http::Request` or `qb::http::Response`: the llhttp-backed `qb::http::Parser`, the `qb::protocol::http` framing layer that drives it, and the security limits that gate every message.

**Prerequisites:** [Core concepts](./01-core-concepts.md) for `Request`/`Response`/`Headers`, and [the message body deep dive](./02-body-deep-dive.md) for `qb::http::Body` over `qb::allocator::pipe<char>`. **See also:** [Advanced topics](./16-advanced-topics.md) for pipelining, [WebSocket](./20-websocket.md) for the post-upgrade frame protocol, and the doc map [`README.md`](./README.md).

## What this page covers

This is the HTTP/1.1 parsing internals. You almost never call any of it directly — the server router, the async client functions, and `http1::Client` all sit on top of it. Read this when you are writing a custom transport, debugging a framing edge case, or need to understand exactly which messages the parser rejects and why.

Two types do the work, both in the `1.1/protocol/` headers:

- `qb::http::Parser<MessageType>` (`src/qbm/http/1.1/protocol/base.h`) — a thin C++ wrapper around the vendored **llhttp** C parser. It owns parser state and the in-progress message.
- `qb::protocol::http::base<IO_Handler, Trait>` (same file) — a `qb::io::async::AProtocol` that frames a byte stream into discrete messages, with `server<IO_Handler>` and `client<IO_Handler>` specializations (`src/qbm/http/1.1/protocol/server.h`, `src/qbm/http/1.1/protocol/client.h`).

HTTP/2 and HTTP/3 do **not** use this parser. HTTP/2 framing lives under `2/protocol/` (HPACK + RFC 9113 frames, see [HTTP/2 protocol specifics](./17-http2-protocol.md)); HTTP/3 framing is delegated to nghttp3 under `3/protocol/` (see [HTTP/3](./19-http3-protocol.md)). This page is HTTP/1.1 only.

This module is a **compiled library**, not header-only — the parser templates are header-defined, but the vendored llhttp C sources (`qbm/http/not-qb/llhttp`) are compiled into `qbm::http` itself. See [Core concepts](./01-core-concepts.md) for the integration recipe.

## The llhttp dependency

`Parser` wraps **llhttp**, the parser that powers Node.js. Its C sources are vendored under `qbm/http/not-qb/llhttp` and built as an `OBJECT` library target named `llhttp`, whose objects are part of libqbm-http: no llhttp archive is built, linked, exported or installed, so packaging qbm-http never collides with a system llhttp's `libllhttp` file. That target has **no public include directory**. Its single public header lives with the module's own headers, at `qbm/http/src/qbm/http/vendor/llhttp.h`.

<!-- src: qbm/http/CMakeLists.txt:64,185; qbm/http/not-qb/llhttp/CMakeLists.txt:8,38 -->

```cmake
# qbm/http/CMakeLists.txt — llhttp is a build dependency of qbm-http,
# not a header you pull in yourself.
add_subdirectory(not-qb/llhttp)                            # an OBJECT library
target_sources(qbm-http PRIVATE $<TARGET_OBJECTS:llhttp>)  # its objects live in libqbm-http
```

This is a **fork**, not a swappable dependency, so `qbm::http` owns the name rather than publishing it: the vendored copy renames llhttp's public symbols from the upstream `llhttp_*` prefix to a `http_*` prefix — the parser handle is `http_t`, the settings struct is `http_settings_s`, error codes are `http_errno_t`, and the entry points are `http_init` / `http_execute` / `http_resume`. A system llhttp cannot substitute for it, and conversely an installed `qbm-http` must not drop a file called `llhttp.h` on a consumer's include path. The vendored parser is upstream llhttp at commit 8371b40 — between the 9.2.1 and 9.3.0 releases, which is why its version macros say 9.2.1 — plus the local changes `THIRD-PARTY-NOTICES` lists with the procedure that regenerates it; one of them accepts a trailing horizontal tab after the `Content-Length` digits and after `chunked` as the optional whitespace RFC 9110 makes it. Hence the `vendor/` location and the spelling `<qbm/http/vendor/llhttp.h>` (`types.h`), which resolves through the same `qbm/` include root as every other qbm header, in the build tree and in an installed tree alike. It is pulled in transitively via `<qbm/http/http.h>` and used directly by `src/qbm/http/1.1/protocol/base.h`. The `http_method` and `http_status` enums that back `qb::http::Method` and `qb::http::Status` are the same llhttp enums (see [Core concepts](./01-core-concepts.md)).

Its functions also link under their own names: the `http_` prefix is Node's older http_parser's too, and two names are shared outright (`http_should_keep_alive`, `http_errno_name`), so every function the fork defines links as `qb_` + its upstream name — `http_execute` is `qb_llhttp_execute` in the archive — through one `#define` per name at the top of the vendored header; source keeps the `http_` spelling. `qbm-http-test-unit-llhttp-link-names` links an http_parser stand-in beside qbm-http and checks both run their own code, and `qbm-http-test-unit-llhttp-symbols` fails on any exported `http_*` left unrenamed (Huly QB-1139).

llhttp is event-driven: you feed it bytes with `http_execute`, and it invokes callbacks as it crosses each boundary of the message (message-begin, URL, status, header field, header value, headers-complete, body, message-complete). `Parser` registers a fixed `static const http_settings_s` table and translates those callbacks into mutations on the message it is building.

## `qb::http::Parser<MessageType>`

`Parser` is templated on the message type and lives in `namespace qb::http`:

<!-- src: src/qbm/http/1.1/protocol/base.h:142,168-169,660-661,681-682,770-771,787-788,806-807 -->

```cpp
#include <qbm/http/http.h>

template <typename MessageType>      // qb::http::Request or qb::http::Response
struct qb::http::Parser : public http_t {
    http_errno_t parse(const char *buffer, std::size_t size);  // feed bytes
    void         reset() noexcept;                             // clear state for a new message
    void         resume() noexcept;                            // continue after the headers pause
    [[nodiscard]] MessageType &get_parsed_message() noexcept;  // the in-progress message
    [[nodiscard]] bool         headers_completed() const noexcept;
};
```

`MessageType` selects the parsing mode through `MessageType::type` (`HTTP_REQUEST` or `HTTP_RESPONSE`), so the same code parses requests on the server and responses on the client. `Parser` derives from `http_t` itself, so the llhttp fields it sets — `content_length`, `error_pos`, `status_code`, `http_major`/`http_minor` — are members you read directly off the parser after `parse()` returns.

### The parsing contract

- **`parse()` is incremental.** Call it repeatedly with successive byte ranges; the parser keeps state across calls. A return of `HPE_OK` means "consumed everything, need more data."
- **The parser pauses at end-of-headers.** The `on_headers_complete` callback returns `HPE_PAUSED` *by design*, so `parse()` returns `HPE_PAUSED` and `headers_completed()` flips to `true` the moment the header block is complete. This lets the framing layer inspect the headers (content length, transfer encoding, upgrade) before committing to read the body.
- **`resume()` clears the pause** so the next `parse()` continues into the body. Call it only after `headers_completed()` is true.
- **`reset()` returns to a clean state** for the next message. It re-initializes llhttp, placement-constructs a fresh `MessageType` (it deliberately avoids assigning into a moved-from message — `onMessage()` moves the message out before resetting), and clears the body buffer and all bookkeeping.
- **`on_message_complete` returns `1`,** which surfaces as `HPE_CB_MESSAGE_COMPLETE`. The framing layer keys off that specific code on the body/resume path (see below).

```mermaid
flowchart TD
    F["parse(bytes) — incremental feed"] --> CB["llhttp callbacks:<br/>message-begin · URL / status · header field / value"]
    CB --> HC{"headers complete?"}
    HC -- "no (HPE_OK, need more)" --> F
    HC -- "yes → HPE_PAUSED" --> INSPECT["framing layer inspects headers<br/>content-length · transfer-encoding · upgrade"]
    INSPECT --> RES["resume() → parse() continues into the body"]
    RES --> MC{"message complete?"}
    MC -- no --> RES
    MC -- "yes (HPE_CB_MESSAGE_COMPLETE)" --> DONE["onMessage() moves the message out → reset()"]
    DONE --> F
```

Here is the contract exercised directly, taken from the test suite:

<!-- src: tests/unit/http1/http1-parse-limits.cpp:133-141 -->

```cpp
#include <qbm/http/http.h>
using namespace qb::http;

Parser<Request> parser;
std::string raw = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

// Header-only request: the parser pauses at end-of-headers.
assert(parser.parse(raw.data(), raw.size()) == HPE_PAUSED);
assert(parser.headers_completed());
assert(parser.content_length == 0u);   // normalized — see "Body framing" below
```

And fragmented input — the case the framing layer is built around — reassembles correctly:

<!-- src: tests/unit/http1/http1-parse-limits.cpp:196-213 -->

```cpp
Parser<Request> parser;
// A single header split across five parse() calls.
parser.parse("GET / HTTP/1.1\r\nX-Cus", 21);   // HPE_OK
parser.parse("tom-Hea",                   7);   // HPE_OK
parser.parse("der: value-",              11);   // HPE_OK
parser.parse("part-1",                    6);   // HPE_OK
parser.parse("part-2\r\n\r\n",           10);   // HPE_PAUSED

assert(parser.get_parsed_message().header("X-Custom-Header") == "value-part-1part-2");
```

### Callbacks and message construction

`Parser` registers a fixed callback table (`static const http_settings_s inline settings`); the callbacks that carry meaning are these. You do not call them — they are the bridge between llhttp's event stream and the `Request`/`Response` you get back.

| llhttp callback | What `Parser` does |
| --- | --- |
| `on_url` | (requests only) Sets `msg.method()` from the parser's method, appends URL bytes into an owning buffer, and assigns `msg.uri()`. Tolerates a URL split across calls. |
| `on_status` | (responses only) Sets `msg.status()` from `parser->status_code`. |
| `on_header_field` / `on_header_value` | Accumulate the current name/value pair into owning `std::string`s; on the next field, push the completed pair into `msg.headers()`. Multiple values for one name are stored as a vector. |
| `on_headers_complete` | Flushes the last header pair, sets `msg.major_version`/`minor_version`, validates transfer encoding (see below), normalizes the body length, sets `msg.upgrade` and `msg.keep_alive`, then **returns `HPE_PAUSED`**. The parser fills the raw header map only: the typed `content_type()` derives from the raw `Content-Type` header on its first read, on every framing path — the Content-Length, empty, HEAD and close-delimited paths never reach `on_message_complete` — and a message nobody asks never parses it. |
| `on_body` | Appends body bytes into an internal `qb::allocator::pipe<char>` (`_chunked`), enforcing the chunk and total-body limits. |
| `on_message_complete` | Moves the accumulated body into `msg.body().raw()` and returns `1`. |

`msg.keep_alive` is computed here from llhttp's `http_should_keep_alive`; it is the HTTP/1.x persistence decision and is ignored by HTTP/2 and HTTP/3 (those set `stream_id` instead — see `message_base.h`).

> **Header callbacks APPEND across `http_execute` calls — the header block really is fed incrementally.** `on_header_field` / `on_header_value` append into `_last_header_key` / `_last_header_value` and clear only on a field↔value transition, committing each completed pair into `msg.headers()` exactly once; `on_url` accumulates through `_url_buffer` the same way. A name or value split across any number of `parse()` calls therefore reassembles correctly, which is what lets the framing layer feed only the newly-arrived bytes (next section). Do not re-feed the whole buffer to "protect" a split header: that is the O(n²) shape this design replaced. <!-- src: qbm/http/src/qbm/http/1.1/protocol/base.h:925-934 -->

## The framing layer: `qb::protocol::http::base`

`qb::protocol::http::base<IO_Handler, Trait>` is a `qb::io::async::AProtocol`. A protocol's job in qb-io is to answer one question — *does the input buffer hold a complete message yet, and if so how big is it?* — via `getMessageSize()`, and then to hand that message to the I/O component via `onMessage()`. See the [protocol interface](https://github.com/isndev/qb/blob/main/src/qb/io/async/protocol.h) for the full contract.

The two specializations are:

<!-- src: src/qbm/http/1.1/protocol/server.h:45-46; src/qbm/http/1.1/protocol/client.h:43-44 -->

```cpp
namespace qb::protocol::http {
    template <typename IO_Handler>
    class server : public base<IO_Handler, qb::http::Request>  { /* parses requests  */ };

    template <typename IO_Handler>
    class client : public base<IO_Handler, qb::http::Response> { /* parses responses */ };
}
```

Both are wired in by the server/client session types as `using protocol = qb::protocol::http::server<IO_Handler>;` (and `::client`). You normally reach them through `qb::http::make_server` or `http1::make_client`, never by hand.

### `getMessageSize()` — framing in three phases

`getMessageSize()` is called on the hot path every time bytes arrive. It runs the parser against the *unconsumed* portion of the I/O input pipe (`_io.in()`) and returns the size of one complete message, or `0` (`IProtocol::kNoMessage`) when more data is needed.

<!-- src: src/qbm/http/1.1/protocol/base.h:912-914,954-982,986-994,996-1009,1033-1041 -->

**Phase 1 — headers.** While `headers_completed()` is false, it feeds **only the bytes that arrived since the last call** — `parse(buf + header_parsed, total - header_parsed)` — and returns 0 immediately when nothing is new (`total <= header_parsed`). If that returns `HPE_OK` (headers still incomplete), it records `header_parsed = total` and returns 0, keeping llhttp's incremental state rather than resetting it; the header callbacks append across calls, so a split name or value still reassembles. Cost is therefore **linear** in header bytes. (It formerly reset the parser and re-fed the whole buffer on every arrival: O(n²) in the header size with the *peer* controlling the segmentation — a 793 KB header block delivered in 64-byte segments cost ~1.5 s of parsing on a single-threaded `VirtualCore`, i.e. a remote CPU denial of service from one legal request. Do not reintroduce it.) If the parse ends without the headers completing and without `HPE_OK`, the message failed: a request over the server's body cap is handed to the session, which answers it 413 (`fail_message()`, Huly QB-168); anything else marks the protocol `not_ok()`. Once the parser pauses (`HPE_PAUSED`), `body_offset` is computed from `error_pos` (llhttp's absolute "where I stopped" pointer) relative to `begin()`, and `header_parsed` is cleared.

**Phase 2 — HEAD / bodyless responses.** On the client side, if the I/O handler exposes `http1_response_body_forbidden()` and it returns true (a response to a HEAD request, where the server sends headers describing a body that is not actually transmitted), framing stops at the end of the headers and returns the header size. This is detected with a `requires`-expression, so handlers that do not opt in are unaffected.

**Phase 3 — body.** With headers in hand:

- **Chunked** (`Transfer-Encoding` present): `resume()` the parser and feed the post-header bytes. `HPE_CB_MESSAGE_COMPLETE` means the final chunk arrived — return the full message size. `HPE_OK` means more chunks are pending — advance `body_offset` and return 0. Anything else marks the protocol `not_ok()`.
- **Content-Length** (the common case): the message is complete once `_io.in().size() >= body_offset + content_length`. When complete, a temporary `string_view` identifies the bytes in the input buffer; assigning it to `Body` **copies** them into the owning pipe before the total size is returned. Otherwise return 0 and keep accumulating.
<!-- src: qbm/http/src/qbm/http/1.1/protocol/base.h:1033-1043; qbm/http/src/qbm/http/body.cpp:697-700 -->

When `getMessageSize()` returns a non-zero size, qb-io consumes exactly that many bytes and calls `onMessage()`. If the parser ever marks itself `not_ok()`, the framework disconnects the connection.

### `onMessage()` — dispatch

`server::onMessage` and `client::onMessage` are the dispatch step. Both are `noexcept` (they sit on a noexcept `AProtocol` boundary), so each wraps cookie parsing in a `try/catch` — a malformed `Cookie` / `Set-Cookie` header is logged and ignored rather than escaping to `std::terminate`. The HTTP/2 and HTTP/3 servers parse the request's cookies under the same `try` before routing; the HTTP/2 server called the parser outside it until Huly QB-1174, and one request with a cookie name over 1024 bytes terminated the process. They then **move** the parsed message into the I/O handler and reset the parser:

<!-- src: src/qbm/http/1.1/protocol/server.h:76-95 -->

```cpp
void onMessage(std::size_t) noexcept final {
    auto &request_obj = this->_http_obj.get_parsed_message();
    try {
        request_obj.parse_cookie_header();          // may throw — contained here
    } catch (const std::exception &e) {
        LOG_HTTP_WARN("Failed to parse Cookie header: " << e.what());
    } catch (...) {
        LOG_HTTP_WARN("Failed to parse Cookie header: unknown exception");
    }
    this->_io.on(std::move(request_obj));            // hand off to the session/router
    this->_http_obj.reset();                          // ready for the next message
}
```

Because the message is *owned* (header strings and a `Body` pipe, not views into the socket buffer), the handler may move it into a long-lived structure — the shared `Context`, a middleware chain, or a coroutine frame — and it stays valid after the socket read that produced it. The retired `server_view` / `client_view` variants used view semantics and could not satisfy that requirement; the qb-io input pipe may `memmove` or reallocate between reads. See [the request context](./10-request-context.md) for how ownership flows through the async pipeline.

After `_io.on(...)`, server sessions apply pipelining and keep-alive: while a response is in flight, further requests queue up to `max_pipelined_requests` (default 128); exceeding the cap disconnects with `DisconnectedReason::ByProtocolError`. When the parser-computed `keep_alive` is false (or the session overrides it), the server closes after `ResponseTransmitted`. See [Advanced topics](./16-advanced-topics.md).

## Body framing and the normalization rules

`on_headers_complete` normalizes the body length so downstream framing never waits for an impossible body:

<!-- src: src/qbm/http/1.1/protocol/base.h:438-468 -->

- **Header-only requests.** llhttp reports `ULLONG_MAX` ("unknown length") when neither `Content-Length` nor `Transfer-Encoding` is present. For requests this is normalized to `content_length = 0` (RFC 9112 framing — a request with no framing headers has an empty body).
- **Bodyless responses.** Responses with a `1xx`, `204`, or `304` status force `content_length = 0` regardless of any declared `Content-Length` header (RFC 9112 §6.3). The test suite asserts this for both `304 Not Modified` and `204 No Content`.
- **Reservation.** When the body length is known and within `MAX_BODY_SIZE`, the body buffer is `reserve`d up front for that many bytes — one allocation instead of repeated growth.

## Security limits and rejected messages

The parser is hardened against framing attacks. Its limits are a `qb::http::request_limits` value -- the server's own, `set_request_limits()`, read when each request begins; their defaults are the constants of `namespace qb::http::protocol_limits` (`src/qbm/http/1.1/protocol/base.h`), and 0 in any of them means no limit of that kind. Each is enforced *during* parsing: a message over one fails with `HPE_USER` (via `http_set_error_reason`) and records the status that answers it as the parser's `refusal_status()` -- `414 URI Too Long` for the target, `431 Request Header Fields Too Large` for a field name, a field value or the number of regular fields of a section, `413 Content Too Large` for a chunk or the body. The server's session answers it with `Connection: close`, after every request received before it, then the connection closes after that delivery (Huly QB-168, QB-94); until 3.3 every breach but the body's closed the connection with no answer, against constants.

<!-- src: src/qbm/http/1.1/protocol/base.h:45-63 -->

| `request_limits` field | Default constant | Value | Enforced on | Answer |
| --- | --- | --- | --- | --- |
| `max_url_length` | `MAX_URL_LENGTH` | 8 KB (8192) | request URL/target | 414 |
| `max_header_name_length` | `MAX_HEADER_NAME_LENGTH` | 1 KB (1024) | each field name | 431 |
| `max_header_value_length` | `MAX_HEADER_VALUE_LENGTH` | 8 KB (8192) | each field value | 431 |
| `max_headers_count` | `MAX_HEADERS_COUNT` | 100 | fields per section -- the header section, then the trailer section on its own | 431 |
| `max_chunk_size` | `MAX_CHUNK_SIZE` | 16 MB | a single chunk | 413 |
| `max_body_size` | `MAX_BODY_SIZE` | 100 MB | declared `Content-Length` and accumulated body (`set_max_body_size` sets it alone) | 413 |

The body limit is checked twice: once against the declared `Content-Length` *before* any body buffer is reserved (so an oversized declaration is rejected before allocation), and again against the running total as body bytes arrive. Whatever the limit, the protocol hands the refused request to the session (`http1_refuse_request`), which answers it once every request received before it is answered, and drops what the client sends meanwhile. The limits are read from the server when a request begins (the session's `http_request_limits()` hook), so a new value applies to the next request. The HTTP/2 and HTTP/3 servers take the same `request_limits` and give the same answers (Huly QB-94).

<!-- src: src/qbm/http/1.1/protocol/base.h:94-111,263-265,479-481,516-519,716-718,751-753; src/qbm/http/1.1/http.h:593-600,613-618,684-686 -->

Two framing defenses go beyond size limits, both in `on_headers_complete`:

<!-- src: src/qbm/http/1.1/protocol/base.h:196-213,435-462 -->

- **Request smuggling.** A message carrying both `Transfer-Encoding` and `Content-Length` is rejected (`"HTTP Transfer-Encoding with Content-Length is forbidden"`). This is the classic TE.CL / CL.TE smuggling vector.
- **Transfer-Encoding allowlist.** Only a single `chunked` token is accepted. Any other value — `gzip, chunked`, a second encoding, anything non-`chunked` — is rejected (`"Unsupported HTTP Transfer-Encoding"`).

These are exercised directly against `Parser`:

<!-- src: tests/unit/http1/http1-parse-limits.cpp:61-171 -->

```cpp
Parser<Request> parser;

// Oversized URL → rejected (not HPE_OK).
std::string big_url = "GET /" + std::string(protocol_limits::MAX_URL_LENGTH + 1, 'x') + " HTTP/1.1\r\n\r\n";
assert(parser.parse(big_url.data(), big_url.size()) != HPE_OK);

// TE + CL → smuggling defense.
parser.reset();
std::string smuggle = "POST /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n";
assert(parser.parse(smuggle.data(), smuggle.size()) != HPE_PAUSED);

// "gzip, chunked" → not on the allowlist.
parser.reset();
std::string bad_te = "POST /u HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
auto err = parser.parse(bad_te.data(), bad_te.size());
assert(err != HPE_OK && err != HPE_PAUSED);
```

## Serialization (the reverse direction)

Parsing turns bytes into objects; serialization is the inverse, and it is **not** part of `Parser`. It is a `qb::allocator::pipe<char>::put<>` specialization for each message type, declared in `request.h` / `response.h` and defined in `request.cpp` / `response.cpp`:

<!-- src: qbm/http/src/qbm/http/request.h:390; qbm/http/src/qbm/http/response.h:358; qbm/http/src/qbm/http/request.cpp:418-420; qbm/http/src/qbm/http/response.cpp:368-370 -->

```cpp
template <>
qb::allocator::pipe<char> &
qb::allocator::pipe<char>::put<qb::http::Request>(const qb::http::Request &r);

template <>
qb::allocator::pipe<char> &
qb::allocator::pipe<char>::put<qb::http::Response>(const qb::http::Response &r);
```

These write the request line / status line, the headers, and the body to the output pipe — `out() << response_obj;` is how a session emits a response. The status line carries the code's reason phrase (`HTTP/1.1 404 Not Found`, `Status::str()`), and header names go out in lower case (`content-type: ...`), the form `Headers` keys them by. They add a `Content-Length` header when one is absent and the body is non-empty, and they enforce the same `protocol_limits`: serializing a message whose body, headers, or estimated wire size exceeds the limit throws `std::length_error`. Each writes a COMPLETE message: a chunked body ends with its last-chunk `0\r\n\r\n`, an empty one included. The request serializer also refuses, before writing anything, a request-target byte the request line cannot carry — SP, HTAB, CR, LF, NUL, any other control, DEL: `qb::io::uri` keeps the raw bytes of a query, so percent-encode them — a method llhttp does not name (a default-constructed `Request` has none), and a URI that failed to parse; an empty path is sent as `/` (RFC 9112 §3.2.1). Every refusal comes before the first byte is written, so the pipe keeps the messages queued before a refused one. A chunked message's announced trailer fields (its `Trailer` header), then its `trailers()`, are written after the last chunk instead of in the header section, and the parser stores every field of a received trailer section in the message's `trailers()` -- and, for 3.x, in its headers too (Huly QB-1073) — the HTTP/2 and HTTP/3 contract — refusing a message whose trailer section carries a field that frames, routes or manages the connection (Huly QB-1067). See [the message body deep dive](./02-body-deep-dive.md) for how the body is laid out in the pipe.

`out << qb::http::MessageHead{msg}` writes the start line and the header section and nothing after them — no body, no last-chunk — with the same validation. The HTTP/1.1 server session serializes every `HEAD` response that way, whatever framing headers it carries, and it is the head to write before a body you stream yourself as `Chunk`s.

<!-- src: qbm/http/src/qbm/http/message_base.h:323-329; qbm/http/src/qbm/http/request.h:400; qbm/http/src/qbm/http/response.h:368 -->

## After the upgrade: WebSocket

The HTTP/1.1 parser handles only the *opening* handshake of a WebSocket connection — the HTTP `GET` upgrade request and the `101 Switching Protocols` response. Once the connection calls `switch_protocol` with `qb::http::ws::protocol<IO_>` and it succeeds, the same socket is parsed as RFC 6455 frames by an entirely different protocol (`qb::protocol::ws_internal::base`), not by `qb::protocol::http::base`. The framing rules, limits, and state machine for that phase are covered in [WebSocket](./20-websocket.md).

## Pitfalls

- **Feed only new bytes to an incremental parser.** The header-field and header-value callbacks append fragments across `http_execute` calls. A custom driver passes each newly arrived range once, keeps parser state between reads, and never re-feeds bytes already consumed; the framing layer does the same with `header_parsed`. Replaying the whole input buffer would duplicate parsed data and restore the old quadratic work. Reset only between messages or after an error.
<!-- src: qbm/http/src/qbm/http/1.1/protocol/base.h:362-412,954-982 -->
- **A `Parser` may be copied or moved mid-message.** It keeps no pointer to itself — its callbacks find it through the `http_t` llhttp executes — so a copy continues the parse into its own message and leaves the source alone, at any phase.
- **`reset()` before reuse, always.** A `Parser` carries the previous message's state until reset. The framing layer resets after every `onMessage()`; a hand-rolled loop must too. `reset()` is also what makes the parser usable after an error.
- **`content_length == 0` does not mean "no `Content-Length` header."** For requests with no framing headers, and for `1xx`/`204`/`304` responses, the parser normalizes the length to 0 even when a (misleading) `Content-Length` header was present. Read the body, not the raw header, to know what arrived.
- **The parsed body owns its bytes before `onMessage`.** Inside `getMessageSize()`, the temporary `string_view` passed to `Body::operator=` is copied into the body's pipe. `onMessage()` moves that owning message to the handler. Do not keep a reference to `get_parsed_message()` across `parse()`, `reset()`, or message delivery.
<!-- src: qbm/http/src/qbm/http/1.1/protocol/base.h:1038-1043; qbm/http/src/qbm/http/body.cpp:697-700; qbm/http/src/qbm/http/1.1/protocol/server.h:76-95 -->
- **The limits are the server's.** `set_request_limits()` (and `set_max_body_size()` for the body alone) is read when each request begins; 0 means none, and the defaults are the `protocol_limits` constants. A Content-Length body is buffered whole, so `QB_MAX_READ_BUFFER_SIZE` (200 MB) still bounds it; the session leaves the transport's generic message cap (`QB_MAX_MESSAGE_SIZE`) to the protocol, which states its bounds and answers a breach -- a body at the default cap plus its header section was past it, and was cut with no answer (Huly QB-168). The HTTP/2 and HTTP/3 layers keep their own framing limits (`qb::http2::protocol_limits`, nghttp3's), and their servers take the same `request_limits` with the same answers (Huly QB-94); a client reads responses under the defaults.
- **This is HTTP/1.1 only.** Neither `Parser` nor `qb::protocol::http::base` is involved in HTTP/2 (`2/protocol/`) or HTTP/3 (`3/protocol/`) framing; what the three share is `request_limits`, whose defaults are these `protocol_limits` constants. Do not reason about h2/h3 framing from this page.

## See also

- [Core concepts](./01-core-concepts.md) — `Request`, `Response`, `Headers`, `Method`/`Status`, and the build/integration recipe.
- [HTTP message body deep dive](./02-body-deep-dive.md) — `qb::http::Body` over `qb::allocator::pipe<char>`, chunks, and compression.
- [Advanced topics and best practices](./16-advanced-topics.md) — pipelining, keep-alive, and performance.
- [HTTP/2 protocol specifics](./17-http2-protocol.md) and [HTTP/3](./19-http3-protocol.md) — the other framing layers.
- [WebSocket](./20-websocket.md) — the RFC 6455 frame protocol the connection switches to after the upgrade.
- The doc map: [`README.md`](./README.md).

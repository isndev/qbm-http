# HTTP message body: a deep dive

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 2.0.0 (C++20 default, C++23 supported)

`qb::http::Body` is the payload of every request and response: a `qb::allocator::pipe<char>` buffer with typed views (`as<T>()`), constrained append/assign, chunked-transfer helpers, and optional gzip/deflate (de)compression.

**Prerequisites:** [Request, Response, and message handling](./01-core-concepts.md) — **See also:** [HTTP message parsing](./15-http-parsing.md), [Advanced usage and performance](./16-advanced-topics.md)

## Summary

`Request` and `Response` both derive from an internal `MessageBase` that multiply-inherits `Headers` and `Body`, so the entire body API in this page is reachable directly on a message — `req.body()` returns the `Body`, and `req.body().as<qb::json>()` parses it (see [Core concepts](./01-core-concepts.md)). The `Body` class itself wraps a single `qb::allocator::pipe<char>` member and exposes three things on top of it:

- **Append and assign** through a compile-time-constrained `operator<<` / `operator=`, accepting only byte-like ranges, `Chunk`, `Multipart`, `Form`, `qb::json`, or arithmetic types. Anything else (a raw `nullptr`, a `std::map`) is rejected by the compiler rather than silently stringified.
- **Typed reads** through `as<T>()`, defined only for `std::string_view`, `std::string`, `qb::json`, `Multipart`, and `Form`. Any other `T` is a hard compile error.
- **Optional compression** (`compress` / `uncompress`), gated on `QB_HAS_COMPRESSION`, which the protocol layer drives automatically from `Content-Encoding`.

The buffer is owning. The historical zero-copy `string_view` body mode was retired because the input pipe relocates bytes between socket reads and an async handler cannot guarantee a captured view outlives the read — so a `Body` always owns stable, movable bytes.

## The `pipe<char>` backing store

A `Body` holds exactly one private member:

<!-- src: qbm/http/body.h:56-57 -->
```cpp
class Body {
    qb::allocator::pipe<char> _data;
    // ...
};
```

`pipe<char>` is the same growable byte buffer qb-io uses for socket I/O (defined in `qb/system/allocator/pipe.h`). Reusing it here means a body can be appended to the output pipe without an intermediate copy, and an inbound body is constructed directly from parser output. You reach it through `raw()`:

<!-- src: qbm/http/body.h:308-320 -->
```cpp
[[nodiscard]] qb::allocator::pipe<char> const &raw() const noexcept;
[[nodiscard]] qb::allocator::pipe<char>       &raw()       noexcept;
```

`Body` forwards the common buffer queries so you rarely need `raw()` directly:

| Member | Returns | Notes |
| --- | --- | --- |
| `size()` | `std::size_t` | byte count, `noexcept` |
| `empty()` | `bool` | `noexcept` |
| `clear()` | `void` | resets the pipe, `noexcept` |
| `begin()` / `end()` | iterators | raw byte iteration over the pipe |

Copies are explicit and deep — the copy constructor and copy-assignment delegate to the pipe's copy semantics; move is defaulted and cheap:

<!-- src: qbm/http/body.h:64-70, body.cpp:65-75 -->
```cpp
Body(Body &&) noexcept = default;          // move: steals the pipe
Body(Body const &);                        // copy: deep-copies the pipe
Body &operator=(Body &&) noexcept = default;
Body &operator=(Body const &);
```

Prefer moving a `Body` into a message when you own it; the copy path duplicates every byte.

## Appending and assigning

### What is appendable

Both the variadic constructor and `operator<<` are constrained by a single compile-time predicate, `Body::is_body_appendable_v<T>`. The accepted categories are fixed:

<!-- src: qbm/http/body.h:104-121 -->
```cpp
// Accepted: Body, Chunk, Multipart, Form, qb::json,
//           std::string, std::string_view, std::vector<char>,
//           char[N] / const char*, and any arithmetic type.
```

This is deliberate. A generic `pipe::put` fallback would compile `Body(42)` into `Body("42")` and would happily accept `Body(nullptr)` or `Body(std::map<int,int>{})` to produce ill-formed output. The predicate rejects all of those at the call site instead. Arithmetic types are accepted *explicitly* and stringified, so `body << 42` yields the bytes `42` — predictable, not accidental.

```cpp
#include <http/http.h>

qb::http::Body body;
body << "id=" << 42 << ";name=" << std::string_view{"qb"};
// body now holds: id=42;name=qb

// body << nullptr;             // ill-formed: nullptr is not appendable
// body << std::map<int,int>{}; // ill-formed: rejected by is_body_appendable
```

The variadic constructor folds the same way, so you can build a body in one expression:

<!-- src: qbm/http/body.h:133-140 -->
```cpp
qb::http::Body body{"chunk-", 1, "-of-", 3};   // "chunk-1-of-3"
```

(The single-`Body`-argument case is excluded from the variadic forms so copy/move construction is selected instead.)

### Assignment replaces the whole body

`operator=` clears the existing bytes, then writes the new value. Specializations exist for each owning or serializable type; the move overloads additionally clear the source.

| Assigned type | Behavior | `noexcept`? |
| --- | --- | --- |
| `std::string const &` | copy bytes | no |
| `std::string &&` | copy bytes, then `str.clear()` | yes |
| `std::string_view` (lvalue or rvalue) | copy the viewed bytes | rvalue overload `noexcept` |
| `const char (&)[N]` | copy literal | yes |
| `const char *` | copy, `nullptr` yields empty body | no |
| `std::vector<char> const &` | copy bytes | no |
| `std::vector<char> &&` | copy bytes, then `vec.clear()` | yes |
| `qb::json` (copy or move) | serialize via `<<` (compact `dump()`) | move overload `noexcept` |
| `Form` (copy) | serialize as `application/x-www-form-urlencoded` | no |
| `Form &&` | serialize, then `form.clear()` | yes |
| `Multipart const &` | serialize the full multipart wire form | no |

```cpp
#include <http/http.h>

qb::http::Body body;

body = std::string{"hello"};        // copy
std::string tmp = "world";
body = std::move(tmp);              // move; tmp is now empty

body = qb::json{{"ok", true}};      // serialized to {"ok":true}
body = "literal";                   // const char[N] fast path
body = nullptr;                     // body is now empty
```

A `std::string_view` never owns its data, so the rvalue overload is a copy in disguise — there is nothing to steal. The source string/vector is the only thing emptied on move.

> Wire-serialization guards apply when the message is finally written: `pipe<char>::put` for a `Request`/`Response` throws `std::length_error` if the assembled message exceeds `qb::http::protocol_limits` (oversized body, headers, or estimated wire size). Assigning to the body does not check the limit; serialization does.

## Typed reads with `as<T>()`

`as<T>()` is a member template with exactly five specializations. Calling it with any other type is a compile error — the static_assert names the supported set:

<!-- src: qbm/http/body.h:374-381 -->
```cpp
template<typename T>
[[nodiscard]] T as() const;   // only: string_view, string, qb::json, Multipart, Form
```

### `as<std::string_view>()` and `as<std::string>()`

<!-- src: qbm/http/body.cpp:695-711 -->
```cpp
std::string_view sv  = body.as<std::string_view>();   // zero-copy view of the pipe
std::string      str = body.as<std::string>();         // owning copy
```

`as<std::string_view>()` returns a view straight into the pipe with no allocation. It is valid only until the body is next modified, moved, or destroyed — read it, do not store it across an append. `as<std::string>()` allocates and copies, and is safe to keep.

### `as<qb::json>()`

<!-- src: qbm/http/body.cpp:719-723 -->
```cpp
qb::json doc = body.as<qb::json>();   // qb::json::parse over the pipe view
```

This calls `qb::json::parse` on the body bytes. On malformed input it throws `qb::json::parse_error` (the nlohmann-json exception type re-exported by qb). Wrap untrusted bodies:

```cpp
#include <http/http.h>

try {
    auto doc = req.body().as<qb::json>();
    handle(doc.at("user").get<std::string>());
} catch (const qb::json::parse_error &e) {
    // 400 Bad Request — the body was not valid JSON
}
```

### `as<Form>()`

Parses `application/x-www-form-urlencoded` bytes into a [`Form`](#the-form-container). Keys and values are URI-decoded (so `%40` becomes `@`); a `+` in form data decodes to a space, consistent with the encoding used on assignment. A pair with no `=` is stored with an empty value; empty keys are dropped. The parser does not throw on odd input — it does its best and returns what it found.

<!-- src: qbm/http/body.cpp:839-877 -->
```cpp
#include <http/http.h>

qb::http::Body body = std::string{"user=alice&tags=a&tags=b&flag"};
qb::http::Form form = body.as<qb::http::Form>();

form.get_first("user").value_or("");   // "alice"
form.get("tags");                       // {"a", "b"}  (multi-valued)
form.get_first("flag").value_or("");    // ""          (key present, empty value)
```

### `as<Multipart>()`

Parses `multipart/form-data` into a [`Multipart`](#the-multipart-container). This overload extracts the boundary from the **first line of the body itself** (it expects the body to begin with `--<boundary>\r\n`), not from the `Content-Type` header. It throws `std::runtime_error` if no boundary is found, the boundary is empty, or the underlying state machine reports an error.

<!-- src: qbm/http/body.cpp:738-775 -->
```cpp
#include <http/http.h>

try {
    qb::http::Multipart mp = req.body().as<qb::http::Multipart>();
    for (const auto &part : mp.parts()) {
        auto disposition = part.header("Content-Disposition");
        // part.body holds the decoded part payload
    }
} catch (const std::runtime_error &e) {
    // malformed multipart, or boundary not present at the start of the body
}
```

If you have the boundary in a header instead, use [`parse_boundary`](#parsing-an-inbound-multipart-with-an-explicit-boundary) and the streaming parser directly — covered below.

## Chunked bodies

`Chunk` models a single HTTP/1.1 chunked-transfer segment. It is a **non-owning** `{const char* data, std::size_t size}` view — it does not copy or own the bytes it points at, so the referenced memory must outlive the `Chunk` for as long as it is serialized.

<!-- src: qbm/http/chunk.h:31-81 -->
```cpp
namespace qb::http {
    class Chunk {
    public:
        Chunk() noexcept;                          // empty/terminating chunk
        Chunk(const char *data, std::size_t size) noexcept;
        const char  *data() const noexcept;
        std::size_t  size() const noexcept;
    };
    using chunk = Chunk;
}
```

A default-constructed `Chunk{}` (size 0) is the **terminating** chunk: serialized, it emits `0\r\n\r\n`, which marks the end of a chunked stream. `Body` gives you two helpers so you do not have to construct the terminator by hand:

<!-- src: qbm/http/body.h:214-226 -->
```cpp
Body &add_chunk(Chunk const &c);   // append one segment
Body &add_final_chunk();           // append the 0-length terminator
```

```cpp
#include <http/http.h>

std::string a = "first";
std::string b = "second";

qb::http::Body body;
body.add_chunk(qb::http::Chunk{a.data(), a.size()});
body.add_chunk(qb::http::Chunk{b.data(), b.size()});
body.add_final_chunk();   // 0\r\n\r\n terminator
```

Serialization (the `pipe<char>::put<Chunk>` specialization) writes each segment as `<hex-size>\r\n<data>\r\n`, and the empty chunk as `0\r\n\r\n`:

<!-- src: qbm/http/body.cpp:41-60 -->
```text
5\r\nfirst\r\n6\r\nsecond\r\n0\r\n\r\n
```

Because `Chunk` borrows memory, keep `a` and `b` alive until the body is written. On the server side, the framework also enforces inbound framing limits (a single `chunked` transfer-encoding token, max chunk 16 MB, max body 100 MB) at the protocol layer; see [HTTP message parsing](./15-http-parsing.md).

## The `Form` container

`Form` is an `application/x-www-form-urlencoded` key→values map. Field names are **case-sensitive**, and a single key may hold multiple values (it is backed by `qb::unordered_map<std::string, std::vector<std::string>>`).

<!-- src: qbm/http/form.h:30-113 -->
```cpp
namespace qb::http {
    class Form {
    public:
        void add(const std::string &key, const std::string &value);   // copy
        void add(std::string &&key, std::string &&value);             // move

        std::vector<std::string>           get(const std::string &key) const;        // all values
        std::optional<std::string>         get_first(const std::string &key) const;  // first value
        const qb::unordered_map<std::string, std::vector<std::string>> &fields() const noexcept;

        void clear() noexcept;
        bool empty() const noexcept;
    };
    using form = Form;
}
```

Building a form and assigning it to a body URI-encodes both keys and values:

```cpp
#include <http/http.h>

qb::http::Form form;
form.add("user", "alice");
form.add("email", "alice@example.com");   // '@' is percent-encoded on serialize

qb::http::Body body;
body = form;                               // user=alice&email=alice%40example.com
```

The pair order follows the underlying unordered map and is not guaranteed. Round-tripping (`body = form` then `body.as<Form>()`) preserves keys, values, and multiplicity, not order.

## The `Multipart` container

`Multipart` builds and represents `multipart/form-data` (RFC 7578). Each part is a `Multipart::Part`, which **derives from `Headers`** and adds a `std::string body` — so you set a part's headers with the full `Headers` API (`set_header`, `set_content_type`, `header`, `has_header`).

<!-- src: qbm/http/multipart.h:806-935 -->
```cpp
namespace qb::http {
    class Multipart {
    public:
        struct Part : public Headers {
            std::string body;
            std::size_t size() const;
        };

        Multipart();                          // random, RFC-2046-compliant boundary
        explicit Multipart(std::string boundary);

        Part &create_part();                  // append a new part, return a reference
        std::size_t content_length() const;   // exact serialized byte count
        std::string const &boundary() const;
        std::vector<Part> const &parts() const;
        std::vector<Part>       &parts();
    };
    using multipart = Multipart;
}
```

A default-constructed `Multipart` generates a random boundary (OpenSSL-backed secure random when `QB_HAS_SSL` is set, a UUID fallback otherwise — so multipart works in plain-HTTP builds too). Build parts, then assign to a body:

<!-- src: qbm/http/tests/test-body.cpp:13-23 -->
```cpp
#include <http/http.h>

qb::http::Multipart mp;

auto &field = mp.create_part();
field.set_header("Content-Disposition", "form-data; name=\"title\"");
field.body = "Hello";

auto &file = mp.create_part();
file.set_header("Content-Disposition", "form-data; name=\"f\"; filename=\"a.txt\"");
file.set_content_type("text/plain");
file.body = "file contents";

qb::http::Body body;
body = mp;   // serialize parts + boundaries
// then set the request's Content-Type to: multipart/form-data; boundary=<mp.boundary()>
```

<!-- src: qbm/http/multipart.cpp:125-182 -->
Serialization writes, for each part, `--<boundary>\r\n`, the part headers as `Name: value\r\n`, a blank line, the part body, and `\r\n`; the message ends with `--<boundary>--`. The serializer validates the boundary and every part header name/value first, throwing `std::length_error` on an invalid boundary or header — so a hand-built `Multipart` with a malformed boundary fails loudly at write time rather than emitting a broken wire form.

### Parsing an inbound multipart with an explicit boundary

`Body::as<Multipart>()` reads the boundary from the body's leading line. When you instead have the boundary in the `Content-Type` header, extract it with `parse_boundary` and drive the streaming `MultipartParser` yourself. The parser is a callback-driven state machine bounded by `multipart_limits`:

<!-- src: qbm/http/multipart.h:50-65 -->
| Limit | Constant | Value |
| --- | --- | --- |
| Boundary length | `multipart_limits::MAX_BOUNDARY_LENGTH` | 70 |
| Part header name | `multipart_limits::MAX_HEADER_NAME_LENGTH` | 1 KB |
| Part header value | `multipart_limits::MAX_HEADER_VALUE_LENGTH` | 8 KB |
| Parts per message | `multipart_limits::MAX_PARTS_COUNT` | 1000 |
| Total payload | `multipart_limits::MAX_TOTAL_SIZE` | 100 MB |

<!-- src: qbm/http/multipart.h:768-784, 553-578 -->
```cpp
#include <http/http.h>

std::string boundary = qb::http::parse_boundary(req.header("Content-Type"));
// parse_boundary returns "" when the Content-Type is not multipart/form-data,
// and throws std::runtime_error on a syntactically invalid boundary parameter.
qb::http::MultipartParser parser{boundary};   // ERROR state if boundary empty,
                                              // > 70 chars, or has control chars
// wire onPartBegin / onHeaderField / onHeaderValue / onPartData / onEnd callbacks,
// then feed bytes:
auto consumed = parser.feed(req.body().raw().begin(), req.body().size());
if (parser.hasError())
    throw std::runtime_error(parser.getErrorMessage());
```

`setBoundary` (called by the constructor) rejects an empty boundary, one longer than `MAX_BOUNDARY_LENGTH`, or one containing control characters by leaving the parser in its `ERROR` state; `feed` on an errored or empty input returns 0. For most server code you do not touch `MultipartParser` directly — `Body::as<Multipart>()` wraps it. Reach for the parser only when streaming very large uploads chunk-by-chunk.

## Optional compression

Compression is **feature-gated** on `QB_HAS_COMPRESSION` (zlib, enabled via the qb `QB_WITH_COMPRESSION` build option). When the macro is defined, `Body` exposes:

<!-- src: qbm/http/body.h:241-301 -->
```cpp
#ifdef QB_HAS_COMPRESSION
std::size_t compress(std::string const &encoding);     // returns compressed size
std::size_t uncompress(const std::string &encoding);   // returns decompressed size
#endif
```

Both replace the body in place and return the new byte count. The `encoding` argument is a `Content-Encoding`-style token list; `"gzip"` and `"deflate"` are the built-in codecs. Behavior:

- `compress` with an empty body or empty encoding is a no-op (returns the current size). `identity` / `chunked` tokens select no compressor; an unknown token throws `std::runtime_error`.
- `uncompress` throws `std::runtime_error` for an unsupported encoding or when more than one compression algorithm is stacked. It also caps decompressed output at `qb::http::protocol_limits::MAX_BODY_SIZE` and throws `std::length_error` if exceeded — an explicit zip-bomb guard.

<!-- src: qbm/http/body.cpp:456-568 -->
```cpp
#include <http/http.h>

#ifdef QB_HAS_COMPRESSION
qb::http::Body body = std::string(4096, 'x');
std::size_t original = body.size();

std::size_t packed = body.compress("gzip");    // body now holds gzip bytes
// ... set Content-Encoding: gzip on the response ...

std::size_t back = body.uncompress("gzip");    // body holds the original bytes again
// back == original
#endif
```

In normal server and client flows you rarely call these by hand: the protocol layer compresses outbound bodies when you set a `Content-Encoding` header and decompresses inbound bodies automatically (a decompression failure on an incoming message is surfaced as a `400 Bad Request`). Call `compress` / `uncompress` directly only when you manage encoding yourself. Always guard the calls with `#ifdef QB_HAS_COMPRESSION`, since the methods do not exist in a build without zlib.

## Pitfalls

- **A `string_view` from `as<std::string_view>()` is borrowed.** It points into the pipe and is invalidated by the next append, assignment, move, or destruction of the body. Copy into a `std::string` if you need to keep it.
- **`as<T>()` only has five specializations.** `std::string_view`, `std::string`, `qb::json`, `Multipart`, `Form`. Anything else is a compile error, not a runtime fallback — there is no `as<int>()`.
- **`Chunk` owns nothing.** Keep the source buffer alive until the body containing the `Chunk` is serialized. A `Chunk{}` is the stream terminator, not an empty data segment.
- **`as<Multipart>()` reads the boundary from the body, not the header.** If your multipart bytes do not begin with `--<boundary>\r\n`, parse the boundary from `Content-Type` and use `MultipartParser` instead.
- **Assignment does not enforce size limits; serialization does.** You can build an arbitrarily large body, but writing a `Request`/`Response` whose wire form exceeds `qb::http::protocol_limits` throws `std::length_error`. `uncompress` enforces `MAX_BODY_SIZE` directly.
- **Compression is conditional.** `compress` / `uncompress` exist only under `QB_HAS_COMPRESSION`. Do not reference them unconditionally.
- **Move where you can.** Copying a `Body` deep-copies every byte. Move it into messages, and use the `&&` assignment overloads (`std::string`, `std::vector<char>`, `Form`) when the source is disposable.

## See also

- [Request, Response, and message handling](./01-core-concepts.md) — how `Body` attaches to a message via `MessageBase`.
- [HTTP message parsing](./15-http-parsing.md) — inbound framing limits (chunk size, body size, transfer-encoding rules).
- [Advanced usage and performance](./16-advanced-topics.md) — buffer reuse and `string_view` body handling.
- [Validation system](./12-validation.md) — body-schema validation re-serializes the body after sanitization.

---

Previous: [Request, Response, and message handling](./01-core-concepts.md) · Next: [Routing overview](./03-routing-overview.md) · [Index](./README.md)

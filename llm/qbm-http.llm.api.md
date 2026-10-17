<!-- Verified-against: qbm-http @ qb 3.2.1. Source of truth: the headers under qbm/http/src/qbm/http/. -->
# qbm-http — API Reference (deterministic)

Module: `qbm/http` — the HTTP/1.1/2/3 + WebSocket stack of the qb C++20-first actor framework (optional C++23).
Every signature below is confirmed against the real headers under `qbm/http/src/qbm/http/`. Human docs: `qbm/http/README.md` and the 21 numbered chapters under `qbm/http/readme/` (`01-core-concepts.md` … `21-websocket-coroutines.md`).

## How to read this file

- Grouped by namespace, then class / free function. Each entry: **signature** · purpose · returns/throws · one minimal usage line.
- This is a **compiled** library (not header-only). Link `qbm::http`, include `<qbm/http/http.h>`, integrate with `qb_load_modules(...)`.
- **Feature gates** (CMake): HTTP/2, HTTPS/TLS, WebSocket, JWT, auth need `QB_HAS_SSL`; HTTP/3 needs `QBM_HTTP_HAS_HTTP3`; body compression needs `QB_HAS_COMPRESSION`; reCAPTCHA middleware needs `QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE`. Each gated symbol is tagged inline.
- WebSocket lives **inside** this module (`qb::http::ws`, headers under `qbm/http/src/qbm/http/ws/`). There is no separate `qbm-ws` module.

### Time vocabulary (do not mix)

- **`qb::duration`** — cookie `max_age` / `expires_in`, CORS `max_age`, rate-limit `window`, HTTP/2-3 timeouts, WS ping interval, client connect/request timeouts. `qb::duration::zero()` = "no timeout" (not an immediate timeout) for every client call.
- **`qb::wall_time`** — returned by `qb::http::date::parse(...)`. The `date` namespace has **no** `qb::Timestamp` overloads and **no** `to_timestamp` / `to_time_point`.
- **`std::chrono::seconds`** — JWT `leeway` / `token_expiration` / `clock_skew_tolerance` (RFC NumericDate semantics).
- **`std::chrono::system_clock::time_point`** — raw date format/parse and cookie `expires`.
- **FORBIDDEN in usage** (never write these): `qb::Timestamp`, `qb::Duration`, `qb::TimePoint`, `to_timestamp(`, `to_time_point(` — retired/never-existed; named here only to warn you off.

---

# Namespace `qb::http` — core message types

### `qb::http::Method` (alias `method`) — `types.h:274`
`class Method { enum class Value:int { GET, POST, DEL, ... }; constexpr Method(Value); constexpr Method(::http_method); explicit Method(std::string_view); operator ::http_method()/Value()/std::string()/std::string_view(); }`
Value-type wrapper over llhttp `http_method`; case-insensitive string ctor; **`DEL` is DELETE** (alias `DELETE_METHOD`); static constants `Method::GET`, `Method::POST`, …
Returns: a method value. Throws: nothing on enum ctors.
Usage: `qb::http::method m = qb::http::method::GET;`

### `qb::http::Status` (alias `status`) — `types.h:509`
`class Status { enum class Value:int { OK=200, NOT_FOUND=404, ... }; constexpr Status(Value); constexpr Status(::http_status); constexpr Status(int); constexpr int code() const; std::string_view str() const; operator std::string()/std::string_view()/::http_status()/Value(); }`
Value-type wrapper over llhttp `http_status`; **default-constructs to 200 OK**; `code()` returns the numeric code; static constants `Status::OK`, `Status::NOT_FOUND`, … `str()`, the string conversions, `std::to_string(Status)` and `operator<<` return the reason phrase the HTTP/1.1 status line carries: the IANA registry's text (`"Not Found"`, 413 `"Content Too Large"`), a defining document's for 306, 418 and the unregistered codes llhttp maps, `"Unknown Status"` for any other code -- not the enum identifier (`NOT_FOUND`) they returned before 3.3 (Huly QB-1062).
Returns: a status value. Throws: nothing.
Usage: `resp.status() = qb::http::status::NOT_FOUND;`

### `qb::http::DisconnectedReason` — `types.h:934`
`enum DisconnectedReason:int { ByUser=0, ByTimeout, ResponseTransmitted, ServerError, ByProtocolError, Undefined }`
Reason codes supplied on HTTP session disconnect.

### `qb::http::endl` / `sep` — `types.h:916` / `:924`
`constexpr char endl[]="\r\n"; constexpr char sep=' ';` — HTTP CRLF terminator and SP separator.

### std helpers — `types.h:951`
`template<> struct std::hash<qb::http::method>; template<> struct std::hash<qb::http::status>; std::string std::to_string(qb::http::method); std::string std::to_string(qb::http::status);`
Make method/status usable as unordered-map keys and stringifiable.

### `qb::http::internal::MessageBase` — `message_base.h:116`
`struct MessageBase : public Headers, public Body { uint16_t major_version{1}, minor_version{1}; bool upgrade{}; std::uint64_t stream_id{0}; bool keep_alive{false}; Body& body() noexcept; const Body& body() const noexcept; Headers& trailers(); const Headers& trailers() const noexcept; bool has_trailers() const noexcept; void reset() noexcept; }`
Common base for Request/Response; **multiply inherits Headers and Body** (so `req.set_header(...)`, `req.body()`, `resp.as<T>()` via `body()` are all directly available). `stream_id` is 0 for HTTP/1.1.
**Trailer section** (`message_base.h:274`, `:282`, `:286`; Huly QB-1073): `trailers()` is the message's trailer section (RFC 9110 §6.5), a `Headers` of its own, the same on HTTP/1.1 (chunked), HTTP/2 and HTTP/3. Received: every trailer field is in `trailers()` **and**, for 3.x source compatibility, in the header fields after the header-section values of its name (`detail::store_received_trailer`, `message_base.h:302`) -- read `trailers()` to tell them apart. Sent: its fields follow the body, after the fields the `Trailer` header announces, announced by a `trailer` field the protocol adds when the message has none; HTTP/1.1 sends them only for a chunked message (not for Content-Length framing nor a `MessageHead`). A field the one trailer list forbids (`detail::is_forbidden_trailer_field`, `headers.h:598`: framing, connection, routing, `te`, `http2-settings`, proxy authentication) or that no header field could be refuses the message before anything is sent: `std::length_error` from the HTTP/1.1 serializer, a stream error from HTTP/2 `send_response`, `false` from `send_request` and from HTTP/3 `submit_*`. The non-const accessor allocates the section on first call; `trailers() const` (an empty process-wide section when none) and `has_trailers()` allocate nothing. Copy deep-copies it, `reset()` drops it.

### `qb::http::Request` (alias `request`) — `request.h:36`
`class Request : public internal::MessageBase { Request() noexcept; Request(method m, qb::io::uri u, headers_map h={}, Body b={}); explicit Request(qb::io::uri u, headers_map h={}, Body b={}); const Method& method() const noexcept; Method& method() noexcept; const qb::io::uri& uri() const; const std::string& query(name, idx=0) const; std::string query_or(name, std::string fallback, idx=0) const; void parse_cookie_header(); const Cookie* cookie(name) const noexcept; bool has_cookie(name) const noexcept; const std::string& cookie_value(name) const noexcept; std::string cookie_value_or(name, std::string fallback) const; Request& with_method(Method) noexcept; Request& with_uri(uri); Request& with_header(string,string); Request& with_body(BodyType&&); void reset() noexcept; }`
Owning request: method, `qb::io::uri`, query accessors, CookieJar (populated by `parse_cookie_header()`), chainable `with_*`. Of the chainable `with_*`, only `with_method` is `noexcept`. `method()` has **both** a const and a mutating overload (`request.h:98, :102`) — `req.method() = qb::http::method::POST;` is valid. `Request{uri}` (the uri-only ctor, `request.h:84`) defaults the method to **GET** (`request.h:86`); the default ctor leaves it `UNINITIALIZED`. **Accessor model:** `query(name)` / `cookie_value(name)` return a `const std::string&` bound to a process-wide static empty string on a miss (never a temporary, always safe to keep) — for a custom fallback use the by-value `query_or(...)` / `cookie_value_or(...)` variants.
Usage: `qb::http::Request r{qb::http::method::GET, qb::io::uri{"https://h/x"}}; r.with_header("Accept","*/*");`

### `qb::http::Response` (alias `response`) — `response.h:36`
`class Response : public internal::MessageBase { Response() noexcept; Response(Status s, headers_map h={}, Body b={}); const Status& status() const noexcept; Status& status() noexcept; void parse_set_cookie_headers(); void add_cookie(const Cookie&); Cookie& add_cookie(name,value); void remove_cookie(name); void update_cookie_header(name); void update_cookie_headers(); Response& with_status(Status) noexcept; Response& with_cookie(const Cookie&); Response& with_body(BodyType&&); void reset() noexcept; }`
Owning response: default-constructs to 200 OK (`response.h:56-58`), CookieJar serialized to `Set-Cookie`. Mutating cookies directly needs `update_cookie_header(s)` to resync. Of the chainable `with_*`, only `with_status` is `noexcept`. `status()` has **both** a const and a mutating overload (`response.h:76, :80`) — `resp.status() = qb::http::status::CREATED;` is valid.
Usage: `qb::http::Response resp{qb::http::status::OK}; resp.with_body("hi");`

### `qb::http::Headers` (alias `headers`) — `headers.h:162`
`class Headers { headers_map_type& headers(); const std::string& header(name, idx=0) const; std::string header_or(name, std::string fallback, idx=0) const; bool has_header(name) const noexcept; qb::icase_unordered_map<std::string> attributes(name, idx=0, std::string_view default_to_parse="") const; void set_header(name,value); void add_header(name,value); void remove_header(name) noexcept; void set_content_type(string_view); const ContentType& content_type() const noexcept; void refresh_content_type() noexcept; std::size_t header_count() const; bool exceeds_header_limit(max=100) const; }`
Case-insensitive multi-value store, keyed by the lower-cased name: iteration and the HTTP/1.1 serializer yield `content-type`, whatever case it was set in (field names are case-insensitive, RFC 9110 §5.1; HTTP/2 and HTTP/3 require lower case), values keep their bytes. The typed `ContentType` is DERIVED from the raw `Content-Type` header (its first value, or the defaults) on the first `content_type()` read after the message was built, parsed, or had that header changed through a typed mutator; a message whose typed Content-Type is never read never parses it (QB-506). After raw `headers()` mutation call `refresh_content_type()`, which only marks it for re-derivation. `set_header` builds its new value before clearing the old ones, so the value may be a view of, or the `header()` reference to, the value it replaces (Huly QB-490); `remove_header` folds every name form, a `const std::string` included (QB-279). `has_header` and `remove_header` are `noexcept` and allocate nothing whatever the name's length: a name up to qb's `lookup_fold_capacity` (128 bytes) is folded on the stack, a longer one matched against each stored name (QB-1068). The first `content_type()` read may allocate (a type or charset past the small-string capacity); as a `noexcept` read, an allocation failure there terminates, like qb's `push`. A raw `headers()` edit of `Content-Type` after a read leaves the typed view stale until `refresh_content_type()` -- the static files middleware uses `remove_header` (QB-1068). **Accessor model:** `header(name, idx)` returns a `const std::string&` bound to a process-wide static empty string on a miss — never a temporary, always safe to keep for the message's lifetime. For a custom fallback use the by-value `header_or(name, fallback, idx)` (no lifetime caveat). `attributes(name, ...)` parses the header value's `name=value; n2="q v"` params via `parse_header_attributes`.
`headers_map = qb::icase_unordered_map<std::vector<std::string>>` (`headers.h:53`).

### `qb::http::Headers::ContentType` — `headers.h:183`
`class ContentType { static std::pair<std::string,std::string> parse(std::string_view); ContentType() noexcept; explicit ContentType(std::string_view); void assign(std::string_view); const std::string& type() const; const std::string& charset() const; }`
Parses Content-Type into MIME type + charset; defaults to `application/octet-stream` / `utf-8` (never reports "no type"). The defaults are not stored: a default-constructed or typeless `ContentType` holds empty strings and reports them from one process-wide `std::string` each, so building one allocates nothing.

### Header free functions
- `parse_header_attributes(const char*, size_t)` (+ string/string_view overloads) — `headers.h:68` — parse `name=value; n2="q v"` params. Throws `std::runtime_error` on malformed/oversized/unterminated input. Bounds: `ATTRIBUTE_NAME_MAX=1024`, `ATTRIBUTE_VALUE_MAX=8192` (`headers.h:38`).
- `std::string accept_encoding();` / `std::string content_encoding(std::string_view accept_encoding_header);` — `headers.h:98` — build `Accept-Encoding` from server capability; pick a `Content-Encoding`: q=0 or a malformed q refuses a coding, and the first acceptable coding in the header's order wins -- not the highest q (`CompressionMiddleware::select_best_encoding` ranks by q). `*` stands for any coding the field does not refuse, wherever the refusal is listed -- after the wildcard too (QB-492). Empty when compression disabled.

### `qb::http::Body` — `body.h:57`
`class Body { template<typename...A> requires (is_body_appendable_v<A> && ...) Body(A&&...); template<typename...A> requires (is_body_appendable_v<A> && ...) Body& operator<<(A&&...); template<typename T> Body& operator=(...); template<typename T> T as() const; template<typename T> [[nodiscard]] std::optional<T> try_as() const noexcept; Body& add_chunk(const Chunk&); Body& add_final_chunk(); pipe<char>& raw(); std::size_t size() const; bool empty() const; void clear() noexcept; }`
`Body::operator=(qb::json&&)` and the const JSON assignment can throw on invalid UTF-8 (`body.h:439-443`); both clear partial output before propagation (`body.cpp:769-791`).
Backed by `qb::allocator::pipe<char>`. `is_body_appendable` gates only the variadic constructor and `operator<<`: `Body`, `Chunk`, `Multipart`, `qb::json`, `std::string`, `std::string_view`, `std::vector<char>`, arithmetic values, built-in `char[N]` arrays, and `char*`/`const char*`. `Form` is deliberately not appendable. Assignment is a separate explicit-specialization set: `std::string`, `std::vector<char>`, `qb::json`, `Multipart`, `Form`, `std::string_view`, and `const char*` (plus Body copy/move). A `nullptr` literal is not a supported assignment; use `clear()`. The extraction set is closed: `as<T>()` / `try_as<T>()` accept only `std::string_view`, `std::string`, `qb::json`, `Multipart`, `Form` (anything else is a `static_assert`, `body.h:387`); explicit specializations of `as<T>` at `body.h:460-473`. Conversions defined in `body.cpp`. `as<Multipart>()` throws (`try_as` yields `nullopt`) unless the document is closed by its final delimiter: a body that ends inside a part or its headers is truncated, not shorter; bytes after the closing delimiter (the epilogue) are ignored (QB-491).
**Prefer `try_as<T>()` for client-supplied bodies** (`body.h:404`): it returns `std::optional<T>` and is `noexcept`, so a malformed JSON/multipart payload yields `std::nullopt` (→ reply 400) instead of an exception you must catch at the call site. `as<T>()` throws on malformed input; the string conversions never fail.
Usage: `req.body() = "payload"; if (auto j = resp.body().try_as<qb::json>()) { /* use *j */ }`

### `qb::http::Body` compression — `Body::compress` at `body.h:272` · **needs `QB_HAS_COMPRESSION`**
`std::size_t compress(const std::string& encoding); std::size_t uncompress(const std::string& encoding); static std::unique_ptr<qb::compression::compress_provider> get_compressor_from_header(const std::string& encoding); static std::unique_ptr<qb::compression::decompress_provider> get_decompressor_from_header(const std::string& encoding);`
Lines: `compress` `body.h:272`, `uncompress` `body.h:311`, `get_compressor_from_header` `body.h:253`, `get_decompressor_from_header` `body.h:289`.
`uncompress`/`get_decompressor` throw `std::runtime_error` on unsupported/multiple encodings.

### `qb::http::Chunk` (alias `chunk`) — `chunk.h:32`
`class Chunk { Chunk() noexcept; Chunk(const char* data, std::size_t size) noexcept; const char* data() const; std::size_t size() const; }`
Non-owning view of one chunked-transfer segment (caller owns bytes); a zero-size chunk marks end-of-chunks.

### `qb::http::Form` (alias `form`) — `form.h:30`
`class Form { void add(const string&,const string&); void add(string&&,string&&); std::vector<string> get(key) const; std::optional<string> get_first(key) const; const qb::unordered_map<string,vector<string>>& fields() const; void clear() noexcept; bool empty() const; }`
`application/x-www-form-urlencoded` multi-value store; field names **case-sensitive**.

### `qb::http::Multipart` (alias `multipart`) — `multipart.h:499`
`class Multipart { struct Part : public Headers { std::string body; std::size_t size() const; }; Multipart(); explicit Multipart(std::string boundary); Part& create_part(); std::size_t content_length() const; const std::string& boundary() const; std::vector<Part>& parts(); }`
RFC 7578 builder; default ctor generates a secure-random boundary (OpenSSL when `QB_HAS_SSL`, UUID fallback), bounded to ≤70 chars.
Usage: `qb::http::Multipart mp; auto& p = mp.create_part(); p.set_header("Content-Disposition","form-data; name=\"f\""); p.body="v";`

### `qb::http::MultipartParser` — `multipart.h:74`
`class MultipartParser { typedef void (*Callback)(const char* buffer,size_t start,size_t end,void* userData); MultipartParser(); MultipartParser(std::string boundary); void setBoundary(std::string); size_t feed(const char* buffer,size_t len); bool succeeded()/hasError()/stopped() const; const char* getErrorMessage() const; Callback onPartBegin/onHeaderField/onHeaderValue/onHeaderEnd/onHeadersEnd/onPartData/onPartEnd/onEnd; void* userData; }` — `succeeded()` holds from the closing delimiter on, whatever follows it in the same `feed()` (the epilogue is skipped; `succeeded` at `multipart.h:420`); an incomplete document is neither succeeded nor errored, so a streaming consumer feeds again.
Callback-driven streaming state machine; `feed` returns bytes consumed. Limits in `multipart_limits` (`multipart.h:50`): `MAX_BOUNDARY_LENGTH=70`, `MAX_HEADER_NAME_LENGTH=1024`, `MAX_HEADER_VALUE_LENGTH=8192`, `MAX_PARTS_COUNT=1000`, `MAX_TOTAL_SIZE=100 MiB`.
- `std::string::const_iterator find_boundary(str, boundary); std::string parse_boundary(content_type);` — `multipart.h:462` — locate / extract boundary (empty if not multipart).

### `qb::http::Cookie` — `cookie.h:64`
`class Cookie { Cookie() noexcept; Cookie(const string& name,const string& value); Cookie(string&&,string&&) noexcept; const string& name()/value() const; Cookie& value(string); const std::optional<system_clock::time_point>& expires() const; Cookie& expires(tp); Cookie& expires_in(qb::duration ttl); const std::optional<int>& max_age() const; Cookie& max_age(qb::duration ttl); Cookie& domain/path(string); bool secure()/http_only() const; Cookie& secure/http_only(bool); const std::optional<SameSite>& same_site() const; Cookie& same_site(SameSite); std::string to_header() const; std::string serialize() const; }`
RFC 6265 cookie. **`max_age(qb::duration)`** stored as integer seconds; **`expires_in(qb::duration)`** computes a `system_clock` time_point; `path` defaults to `/`; `to_header()` yields a `Set-Cookie` value.
Usage: `qb::http::Cookie c{"sid","abc"}; c.http_only(true).max_age(std::chrono::hours(1));`
- `enum class SameSite { None, Lax, Strict, NOT_SET }` (`cookie.h:50`) — passing `NOT_SET` resets the optional.

### `qb::http::CookieJar` — `cookie.h:300`
`class CookieJar { void add(const Cookie&); void add(Cookie&&); Cookie& add(string name,string value); bool remove(name) /* case-insensitive for every name form -- QB-279 */; void clear(); const Cookie* get(name) const; Cookie* get(name); bool has(name) const; const qb::icase_unordered_map<Cookie>& all() const; size_t size() const; bool empty() const; }`
Case-insensitive-name container; `add` replaces an existing same-name cookie. Bounds: `COOKIE_NAME_MAX=1024`, `COOKIE_VALUE_MAX=4096` (`cookie.h:33`).
- `parse_cookies(ptr,len,set_cookie)` / `parse_cookies(string_view,set_cookie)` / `std::optional<Cookie> parse_set_cookie(string_view)` — `cookie.h:438`.

### `qb::http::origin` helpers — `origin.h:34`
`bool scheme_eq(string_view,string_view) noexcept; bool host_eq(string_view,string_view) noexcept; std::string_view effective_port(const qb::io::uri&) noexcept; std::optional<std::uint32_t> effective_port_number(const qb::io::uri&) noexcept; bool same(const qb::io::uri& a, const qb::io::uri& b) noexcept;`
Same-origin comparison: case-insensitive scheme/host, scheme-default ports (http and ws 80, https and wss 443); `same()` requires both ports resolvable and equal.
`std::string authority(const qb::io::uri&);` (`origin.h:100`, Huly QB-1064) — the authority every protocol sends: the HTTP/1.1 and WebSocket `Host` value, the HTTP/2 and HTTP/3 `:authority`. The host, an IPv6 literal between brackets without its zone identifier (`[fe80::1%25eth0]` -> `[fe80::1]`, RFC 9844 §6), `:port` unless it is the scheme's default (case-insensitive scheme); empty when the URI has no host. `qb::io::uri` fills the default port in, so `https://h/` gives `h`, `https://h:8443/` gives `h:8443`.

### `qb::http::utility` — `utility.h:34` / `:258-260`
Char/string helpers: `is_char/is_control/is_special/is_digit/is_hex_digit(int)`, `hex_value(char)`, `decode_path_component(string_view)`, `constexpr char ascii_to_lower(char)`, `bool iequals(string_view,string_view)`, `is_http_whitespace`, `trim_http_whitespace`, `escape_html`, `uri_encode_component`. Splitting/joining: `split_and_trim_header_list`, `split_string<String>(...)`, `split_string_by<...>`, lazy `class split_view`, `join(vector<T>, delim)`.
Usage: `if (qb::http::utility::iequals(a,b)) ...;`

### pipe serialization — `request.h:386` / `response.h:358` / `chunk.h:106` / `multipart.h:629`
`template<> pipe<char>& pipe<char>::put<Request>(const Request&); ...<Response>; ...<MessageHead<Request>>; ...<MessageHead<Response>>; ...<Chunk>; ...<Multipart>;`
Wire-serialize into the qb pipe; Request/Response throw `std::length_error` if the message exceeds `protocol_limits`. Each writes a COMPLETE message: a chunked body ends with its last-chunk `0\r\n\r\n` even when empty (QB-493). The Request refuses a request-target byte the request line cannot carry — SP, HTAB, CR, LF, NUL, any other control, DEL — before writing anything (`std::length_error`; percent-encode it, QB-494): `qb::io::uri` keeps raw query bytes. It refuses too a request whose method llhttp does not name (a default-constructed `Request`'s `UNINITIALIZED`, which aborted the process) and an invalid URI, and sends an empty path as `/` (RFC 9112 §3.2.1). A refusal writes nothing of its message and keeps what the pipe already held -- the responses queued before it (QB-1066; it used to clear the pipe). Trailers, the HTTP/2 and HTTP/3 contract (QB-1067): a complete chunked message writes the fields its `Trailer` header announces after the last chunk, not in the head (a field trailers must not carry, `qb::http::detail::is_forbidden_trailer_field`, stays in the head; a `MessageHead` keeps every field); the parser stores every received trailer field in the message's `trailers()` -- and in its headers too, for 3.x (QB-1073) -- and refuses a message whose trailer section carries a forbidden one. A chunked message's `trailers()` follow the announced fields after the last chunk, announced by a `trailer` field it gains when it has none; the serializer asks `detail::writes_trailer_section` (`chunk.h:133`) before it writes a byte -- the check of `trailers()`; a refusal writes nothing -- then writes the start line and hands the rest to `detail::write_trailed_chunked_message` (`chunk.h:150`). A message framed by Content-Length writes no trailer section.

### `qb::http::MessageHead<Message>` — `message_base.h:323`
`template<typename Message> struct MessageHead { const Message& message; };` + deduction guide `MessageHead{msg}`. `out << MessageHead{msg}` writes the start line and header section only — framing headers included, no body, no last-chunk — with the full serializer's validation (`request.h:396`, `response.h:368`). The HTTP/1.1 server session writes every HEAD response this way; it is also the head to write before a body you stream as `Chunk`s.

---

# Namespace `qb::http::date` — date/time (current API only)

> The `date` namespace deals in `std::chrono::system_clock::time_point` and **`qb::wall_time`** only. There are **no** `qb::Timestamp` overloads and **no** `to_timestamp`/`to_time_point`.

### `date.h:50`
`std::string format_http_date(std::chrono::system_clock::time_point) noexcept;`
`std::string format_cookie_date(std::chrono::system_clock::time_point) noexcept;`
Format as RFC 1123 GMT date (empty on failure); cookie variant is functionally identical.
Usage: `auto s = qb::http::date::format_http_date(std::chrono::system_clock::now());`

### `date.h:75`
`std::optional<system_clock::time_point> parse_http_date(std::string_view) noexcept;` (+ `const std::string&` overload) — every fixed-width numeric field must be all digits (no sign, no trailing byte: `08:4x:37` is `nullopt`, QB-599)
`std::optional<system_clock::time_point> parse_cookie_date(...) noexcept;`
Parse RFC 1123 / RFC 850 / asctime; `nullopt` on failure.

### `date.h:114`
`std::string now() noexcept;` — current RFC 1123 `Date` value.
`std::string to_string(system_clock::time_point) noexcept;` — equivalent to `format_http_date`.
`qb::wall_time parse(std::string_view) noexcept;` and `qb::wall_time parse(const std::string&) noexcept;` — returns `qb::wall_time`; on failure returns epoch `qb::wall_time{}`.
`std::string format_timestamp(const system_clock::time_point&) noexcept(false);` — local-time `"YYYY-MM-DD HH:MM:SS"`.
Usage: `qb::wall_time wt = qb::http::date::parse(resp.header("Date"));`

---

# Namespace `qb::http` — routing

> `SessionType` is the per-connection session (`qb::http::DefaultSession` for plaintext HTTP/1.1, etc.). Get the router from a server via `server->router()`.

### `qb::http::Router<SessionType>` — `src/qbm/http/routing/router.h:54`
`template<typename SessionType> class Router`
Main router: a RouterCore + a root RouteGroup. **Must `compile()` before `route()`** — `route()` auto-compiles if needed.
- `add_route(path, method, RouteHandlerFn) -> Router&` and per-verb `get/post/put/del/patch/options/head(path, handler)` (`router.h:79`). Each call clears the compiled flag; DELETE is `method::DEL`.
- per-verb ICustomRoute overloads `get(path, std::shared_ptr<ICustomRoute<S>>)` (`router.h:89`).
- `template<typename C,typename...A> requires DerivedFrom<C,ICustomRoute<S>> add_custom_route(path, method, A&&...)` + typed `get<T>/post<T>/...` (`router.h:170`).
- `[[nodiscard]] std::shared_ptr<RouteGroup<S>> group(path_prefix)` (`router.h:208`).
- `template<typename C,typename...A> requires DerivedFrom<C,Controller<S>> [[nodiscard]] std::shared_ptr<C> controller(path_prefix, A&&...)` (`router.h:220`).
- `use()` — global middleware on the root group. **FOUR overloads**, not three: `use(H&&, name="UnnamedCoroMiddleware")` gated on `CoroMiddlewareHandler` (`router.h:154`) / `use(H&&, name="UnnamedGlobalFunctionalMiddleware")` gated on `SyncMiddleware` (`router.h:234`) / `use(std::shared_ptr<IMiddleware<S>>, name_override="")` (`router.h:248`) / `template<typename MW,typename...A> requires DerivedFrom<MW,IMiddleware<S>> use(A&&...)` (`router.h:259`). The coro and sync forms are SEPARATE overloads — there is no union concept for `use()` (contrast the verbs, below). Same four at `RouteGroup` (`route_group.h:148`, `:251`, `:267`, `:297`) and `Controller` (`controller.h:218`, `:327`, `:342`, `:370`). `IHandlerNode` declares none (only `add_middleware`, `handler_node.h:205`).
- `void set_not_found_handler(RouteHandlerFn)` (`router.h:265`) — global middleware still prepended.
- `void set_error_task_chain(std::vector<std::shared_ptr<IAsyncTask<S>>>)` (`router.h:272`) — global middleware **not** auto-prepended.
- `Router& add_lifecycle_hook(typename Context<S>::LifecycleHook)` (`router.h:282`) — only way to observe `PRE_ROUTING`.
- `Router& add_observer(std::shared_ptr<IRequestObserver<S>>)` (`router.h:294`) — an observer of every request this router routes, told at each end (below); null ignored; a context keeps the observers registered when it was created; `clear()` removes them.
- `void compile()` (`router.h:302`); `std::shared_ptr<Context<S>> route(std::shared_ptr<S> session, qb::http::Request)` (`router.h:314`); `std::weak_ptr<RouterCore<S>> get_router_core_weak_ptr() noexcept` (`router.h:322`).
- `void clear()` (`router.h:329`, requires recompile).
Usage: `server->router().get("/", [](auto ctx){ ctx->text("hi"); }); server->router().compile();`

### `qb::http::RouteGroup<Session>` — `src/qbm/http/routing/route_group.h:50`
`template<typename Session> class RouteGroup : public IHandlerNode<Session>`
Non-terminal node grouping routes under a shared prefix + inherited middleware. Same verb/`use`/`group`/`controller`/`add_custom_route` API as Router.
- `[[nodiscard]] std::shared_ptr<RouteGroup<S>> group(prefix); template<...> requires DerivedFrom<C,Controller<S>> [[nodiscard]] std::shared_ptr<C> controller(prefix, A&&...); void add_child(std::shared_ptr<IHandlerNode<S>>)` (`route_group.h:308`).
Usage: `auto api = router.group("/api"); api->get("/users", h);`

### `qb::http::Controller<Session>` — `src/qbm/http/routing/controller.h:53`
`template<typename Session> class Controller : public IHandlerNode<Session>`
Base for class-based controllers; exposes `SessionType` / `Context` aliases. Mounted at a base path.
- `virtual void initialize_routes() = 0` (`controller.h:168`) — declare routes/middleware here; called once at compile.
- `void set_base_path_segment(std::string) noexcept` (`controller.h:135`).
- Bind member functions with the unified verb API inside `initialize_routes()`: `this->get(path, this, &MyCtl::method)`. The bound member may be sync (`void(ctx)`) or coroutine (`task<void>(ctx)`) — auto-detected via concept.
Usage: `this->get("/me", this, &MyCtl::me);`

### `qb::http::Route<SessionType>` — `src/qbm/http/routing/route.h:239`
`template<typename SessionType> class Route : public IHandlerNode<SessionType>`
Terminal node binding one method+segment to a `RouteHandlerFn` or `ICustomRoute` (`std::variant`). Ctors throw `std::invalid_argument` on null handler; exposes `get_http_method()`.

### Tree / chain interfaces
- `IHandlerNode<Session>` — `src/qbm/http/routing/handler_node.h:136` — base for tree nodes: `set_parent/get_parent`, `get_path_segment`, `add_middleware`, pure-virtual `compile_tasks_and_register` + `get_node_name`.
- `detail::join_paths(parent, segment)` / `detail::normalize_path_segment(segment)` — `handler_node.h:84` — slash-normalizing path joins (`""+""` → `/`).
- `IAsyncTask<SessionType>` — `src/qbm/http/routing/async_task.h:47` — `virtual void execute(ctx)=0; virtual void cancel()=0; virtual std::string name() const=0;`. `execute()` must eventually call `ctx->complete()`; `cancel()` must **not**.
- `ICustomRoute<SessionType>` — `src/qbm/http/routing/custom_route.h:43` — `virtual void process(ctx)=0; std::string name() const=0; void cancel()=0;`. Adapted via `CustomRouteAdapterTask`.
- `IMiddleware<SessionType>` — `src/qbm/http/routing/middleware.h:39` — `virtual void process(ctx)=0; std::string name() const=0; void cancel()=0;`. `process()` must call `ctx->complete()` to advance.
- `MiddlewareTask<SessionType>` — `middleware.h:75` — `explicit MiddlewareTask(std::shared_ptr<IMiddleware<S>>, name="MiddlewareTask")`. Adapts IMiddleware→IAsyncTask; on exception sets 500 + ERROR. Throws `std::invalid_argument` on null.
- `FunctionalMiddleware<SessionType>` — `middleware.h:183` — `FunctionalMiddleware(MiddlewareHandlerFn, name)`. Adapts a `(ctx,next)` lambda; calling `next()` once completes CONTINUE; duplicate `next()` ignored.
- `RouteLambdaTask<S>` / `CustomRouteAdapterTask<S>` — `route.h:51, :139` — wrap a lambda handler / an ICustomRoute; thrown exceptions → 500 + ERROR; throw `std::invalid_argument` on null.

### `qb::http::Context<SessionType>` — `src/qbm/http/routing/context.h:77`
`template<typename SessionType> class Context : public std::enable_shared_from_this<Context<SessionType>>`
Per-request state; always handled as `std::shared_ptr<Context>`.
- Accessors (`context.h:574`): `Request& request() noexcept; Response& response() noexcept; std::shared_ptr<S> session() noexcept` (null if session expired); `PathParameters& path_parameters() noexcept; const std::string& path_param(std::string_view name) const` (static-empty on miss); typed `std::optional<T> path_param<T>(name)` / `T path_param_or<T>(name, fallback)`; typed query `template<typename T=std::string> std::optional<T> query_param(name)` (nullopt on empty/absent/parse-fail) / `T query_param_or<T>(name, fallback)`; `template<typename T> std::optional<T> bind() const` (body→T: `qb::json` / `std::string` / NLOHMANN model; nullopt on fail). Typed parsing goes through `static parse_value<T>(string_view) noexcept` (integral/floating via `std::from_chars` whole-string match, `bool` from `true/false/1/0`, string passthrough; `static_assert` otherwise).
- `void complete(AsyncTaskResult = COMPLETE)` (`context.h:1265`) — advance/finalize the chain. CONTINUE→next; COMPLETE/CANCELLED/ERROR/FATAL drive finalization or error chain.
- `void cancel(reason="Cancelled by application") noexcept` (`context.h:1349`) — notifies the in-flight task, or the conditional child selected by this context, once; sets 503 + completes CANCELLED. The no-context child cancellation interface does not promise per-operation native preemption inside a shared user middleware.
- `void add_lifecycle_hook(LifecycleHook); void execute_hook(HookPoint)` (`context.h:775`) — hook exceptions are caught/suppressed. Registrations during dispatch become visible after the outermost dispatch returns; active/nested dispatches keep the published list and the next separate phase sees additions in order.
- string-keyed store: `template<typename T> void set(key,T); template<typename T> std::optional<T> get(key) const; template<typename T> T* get_if(key) noexcept; bool has(key) const noexcept; bool remove(key) noexcept` — `set` `context.h:818`, `get` `:832`, `get_if` `:854` (const overload `:872`), `has` `:886`, `remove` `:906`. Backed by `qb::unordered_map<std::string,std::any>` — bad cast swallowed (returns nullopt/nullptr).
- typed-slot store (`context.h:941`): `template<typename T> void set(const Slot<T>&,T); template<typename T,typename...A> T& emplace(const Slot<T>&,A&&...); template<typename T> T* get_if(const Slot<T>&) noexcept; template<typename T,typename U=T> T get_or(const Slot<T>&,U&&) const`. `get_if` is the zero-copy hot read.
- response helpers (`context.h:1089`): `void json(qb::json json_data, status=OK); void text(std::string text_data, status=OK, const std::string& content_type="text/plain; charset=utf-8"); void html(std::string html_data, status=OK); void no_content(); void redirect(const std::string& url, status=FOUND); void bad_request(...)/unauthorized(...)/forbidden(...)/not_found(...)/internal_server_error(...); Context& status(status)`. **The body sinks take their payload BY VALUE (move-sink)**; `json` sets `application/json; charset=utf-8`, `text` defaults `text/plain; charset=utf-8`, `html` `text/html; charset=utf-8`, `no_content` → 204 (clears body + CT/CL). **All except `status()` set the response and `complete(COMPLETE)`** — set headers/body first. `status()` only sets the code and is chainable.
- `std::string_view route_pattern() const noexcept` (`context.h:656`) — the canonical pattern of the route that matched (`/users/:id`, `/files/*path`, `/`), whatever slashes the registration used; empty for a 404 or a request answered before matching; a 405 names the route whose path matched. Valid for the context's life (the compiled names its chain retains).
- `void suppress_response() noexcept` (`context.h:1420`) — finalize without firing the send callback (e.g. on WebSocket upgrade).
- introspection (`context.h:1387`): `bool is_cancelled()/is_completed() const noexcept; State state() const noexcept; ProcessingPhase get_processing_phase() const noexcept; std::uint64_t completion_count() const noexcept; [[nodiscard]] ScopedFinalizationDeferral defer_finalization_scope() noexcept`.
Usage: `ctx->json(qb::json{{"ok",true}});`

### Context-scoped types — `src/qbm/http/routing/context.h:86`
`enum class ProcessingPhase{INITIAL,NORMAL_CHAIN,NOT_FOUND_CHAIN,METHOD_NOT_ALLOWED_CHAIN,ERROR_CHAIN}; enum class State:uint8_t{Ready,Running,Finalised}; using LifecycleHook = std::function<void(Context<S>&,HookPoint)>; using CustomDataMap = qb::unordered_map<std::string,std::any>;`

### Request observers — `src/qbm/http/routing/observer.h:65`
`template<typename S> class IRequestObserver { virtual void on_request(Context<S> const&) noexcept /* no-op by default */; virtual void on_response(Context<S> const&, RequestEnd const&) noexcept = 0; }` — registered with `Router::add_observer`. `on_request` runs once the context exists, before `PRE_ROUTING`; `on_response` runs exactly once per such context when its response is decided: after the `PRE_RESPONSE_SEND` hooks and the hand-over to the session (`ctx.response()` is what was sent), before `REQUEST_COMPLETE`. Both on the router's thread; a throw terminates. Seen: matches, 404, 405, error chains, the early path-length 400, a client that left. Not seen: a request a session refuses before routing (414/431/413).
- `enum class RequestOutcome : std::uint8_t { RESPONDED, SESSION_GONE, SUPPRESSED }` (`observer.h:32`) — handed to the session; decided after the session had gone (nothing sent); finalized by `suppress_response()` (told at the context's destruction).
- `struct RequestEnd { RequestOutcome outcome; qb::duration duration; }` (`observer.h:39`) — `duration`: from the router receiving the request (before `PRE_ROUTING`) to the response handed to the session (routing, middleware, the handler however long it waited, `PRE_RESPONSE_SEND` hooks, the protocol's serialization); transmission and request parsing excluded; to the destruction for a suppressed response.
- Cost: a router with no observer pays one null test when it creates a context and one when the context is finalized; an observed request costs two monotonic clock reads, one reference count and one virtual call per observer at each end, no allocation.

### `qb::http::PathParameters` — `src/qbm/http/routing/path_parameters.h:32`
`class PathParameters { void set(string_view key,string_view value); std::optional<string_view> get(string_view) const noexcept; bool has(string_view) const noexcept; ... at/find/begin/end/size/reserve }`
Keys are borrowed `string_view`s; values are owned decoded copies. Router-extracted keys are backed by compiled storage retained by the routed Context's shared `IAsyncTask` chain through `REQUEST_COMPLETE`, including after router/session destruction and 405/error-chain transitions. A standalone copied `PathParameters` does not acquire that owner: retain the context or copy names into owned strings. (`src/qbm/http/routing/async_task.h:92-115`; `src/qbm/http/routing/router_core.h:88-94,443-453`.)

### `qb::http::Slot<T>` — `src/qbm/http/routing/slot.h:79`
`template<typename T> struct Slot { using value_type=T; std::string_view name; consteval explicit Slot(std::string_view); consteval explicit Slot(const char*); constexpr std::string_view key() const noexcept; }`
Compile-time typed key for Context custom data; declare as `inline constexpr` globals. Two slots with same name but different `T` are distinct types; both alias the same any-map entry as the string API.
Usage: `inline constexpr qb::http::Slot<int> kCount{"count"}; ctx->set(kCount, 1);`

### Coroutine route and middleware detection
The verb methods (`get`, `post`, `put`, `del`, `patch`, `options`, `head`) have a **unified overload** gated on `RouteHandlerLike = SyncRouteHandler || CoroRouteHandler` (`coro_task.h:101`), dispatched by `if constexpr` — one overload accepts sync OR coroutine handlers. `use()` does **not**: `CoroMiddlewareHandler` (`coro_task.h:82`) and `SyncMiddleware` (`coro_task.h:109`) gate two **separate** overloads, with no union concept. Either way, pass the lambda directly — no wrapper needed.
- Coroutine route handler: `task<void>(ctx)` lambda passed to a verb → auto-detected as `CoroRouteHandler`; normal return auto-completes `COMPLETE` (unless already completed/cancelled); exceptions → 500/ERROR; spawns on the thread-local `coro_scheduler`.
- Coroutine middleware: `task<void>(ctx)` lambda passed to `use()` → auto-detected as `CoroMiddlewareHandler`; default outcome `CONTINUE`; short-circuit via `ctx->complete(COMPLETE)`.
- Member-function binding: `verb(path, this, &MyActor::method)` — the bound member may be sync or coroutine.
Usage: `router.get("/a", [](auto ctx)->qb::io::async::task<void>{ co_return; });`

### Routing aliases / enums — `src/qbm/http/routing/types.h`
- `template<typename S> using RouteHandlerFn = std::function<void(std::shared_ptr<Context<S>>)>;` and `MiddlewareHandlerFn = std::function<void(std::shared_ptr<Context<S>>, std::function<void()> next)>` (`src/qbm/http/routing/types.h:83, :108`).
- `enum class HookPoint { PRE_ROUTING, PRE_HANDLER_EXECUTION, POST_HANDLER_EXECUTION, PRE_RESPONSE_SEND, POST_RESPONSE_SEND, REQUEST_COMPLETE }` (`src/qbm/http/routing/types.h:38`).
- `enum class AsyncTaskResult { CONTINUE, COMPLETE, CANCELLED, ERROR, FATAL_SPECIAL_HANDLER_ERROR }` (`src/qbm/http/routing/types.h:53`) — `src/qbm/http/routing/types.h` `#undef ERROR`s it first, at `:54` (Win32 clash).
- concepts: `DerivedFrom<Derived,Base>=is_base_of_v<Base,Derived>` (`src/qbm/http/routing/types.h:123`); coroutine callable-matching concepts `CoroRouteHandler<F,S>` (`coro_task.h:69`), `CoroMiddlewareHandler<F,S>` (`coro_task.h:82`), `SyncRouteHandler`/`RouteHandlerLike`/`SyncMiddleware` (`coro_task.h:92, :101, :109`).

---

# Namespace `qb::http` — standard middleware

> All middleware are class templates over `SessionType`; each ships a `*_middleware<S>(...)` factory returning `std::shared_ptr<...>`. Register via `router.use(...)` / `group->use(...)`. Generic builder: `qb::http::middleware::make<Tag,S>(args...)` (`src/qbm/http/middleware/make.h`).

## CORS — `src/qbm/http/middleware/cors.h`
### `qb::http::CorsOptions` — `cors.h:94`
Fluent config; setters return `CorsOptions&`:
`CorsOptions(); explicit CorsOptions(std::vector<std::string> origins); origins(vector) / origin_patterns(vector) / origin_matcher(std::function<bool(const std::string&)>) ; methods(vector) / all_methods(); headers(vector) / common_headers(); expose_headers(vector); credentials(AllowCredentials); CorsOptions& max_age(qb::duration);`
`enum class AllowCredentials{No,Yes}; enum class OriginMatchStrategy{Exact,Regex,Function};` Presets: `static CorsOptions permissive(); static CorsOptions secure(const std::vector<std::string>& origins);`. **`max_age` takes `qb::duration`** (serialized as integer seconds; default 86400s). Default methods `{GET,HEAD,POST}`, default credentials `No`.
Usage: `auto opt = qb::http::CorsOptions::secure({"https://app"}).max_age(std::chrono::hours(1));`

### `qb::http::CorsMiddleware<S>` — `cors.h:319`
`CorsMiddleware(); explicit CorsMiddleware(const CorsOptions&, name="CorsMiddleware"); static std::shared_ptr<...> dev(name); static std::shared_ptr<...> secure(origins, name); const CorsOptions& get_cors_options() const; CorsMiddleware& update_options(const CorsOptions&);`
Adds `Access-Control-*` headers; handles preflight OPTIONS. Default ctor = permissive.
Factories (`cors.h:522`): `cors_middleware<S>(options=permissive(), name)`, `cors_dev_middleware<S>(name)`, `cors_secure_middleware<S>(origins, name)`.
Usage: `router.use(qb::http::cors_secure_middleware<S>({"https://app"}));`

## JWT — `src/qbm/http/middleware/jwt.h` · **needs `QB_HAS_SSL`**
### `qb::http::JwtOptions` — `jwt.h:48`
`struct JwtOptions { std::string secret; std::string algorithm="HS256"; bool verify_exp=true,verify_nbf=true,verify_iat=true,verify_iss=false,verify_aud=false,verify_sub=false; std::string issuer,audience,subject; std::chrono::seconds leeway{0}; JwtTokenLocation token_location=HEADER; std::string token_name="Authorization"; std::string auth_scheme="Bearer"; }`
**`leeway` is `std::chrono::seconds`** (clock-skew tolerance for exp/nbf). `enum class JwtTokenLocation{HEADER,COOKIE,QUERY}` (`jwt.h:39`). `enum class JwtError{NONE,MISSING_TOKEN,INVALID_TOKEN,TOKEN_EXPIRED,TOKEN_NOT_ACTIVE,INVALID_SIGNATURE,INVALID_CLAIM,ALGORITHM_MISMATCH}` + `struct JwtErrorInfo{JwtError code; std::string message;}` (`jwt.h:67, :79`).

### `qb::http::JwtMiddleware<S>` — `jwt.h:90`
`explicit JwtMiddleware(const std::string& secret, const std::string& algorithm="HS256"); explicit JwtMiddleware(JwtOptions);`
Fluent (each returns `JwtMiddleware&`): `from_header(name,scheme="Bearer") / from_cookie(name) / from_query(name); require_claims(vector); with_validator(Validator) / with_error_handler(ErrorHandler) / with_success_handler(SuccessHandler) / with_options(const JwtOptions&)`.
`using Validator=std::function<bool(const qb::json&,JwtErrorInfo&)>; using ErrorHandler=std::function<void(ContextPtr,const JwtErrorInfo&)>; using SuccessHandler=std::function<void(ContextPtr,const qb::json&)>`. On success stores decoded payload in context under key `"jwt_payload"`: claims that read as JSON booleans or numbers are coerced, except the textual `iss`, `sub`, `aud`, `jti`, `username`, which stay the signed strings (`src/qbm/http/middleware/jwt.h:345-351`). On failure replies 401. Statics: `create(secret,algorithm="HS256")`, `create_with_options(options)`.
Factories (`jwt.h:542`): `jwt_middleware<S>(secret, algorithm="HS256")`, `jwt_middleware_with_options<S>(options)`.
Usage: `router.use(qb::http::jwt_middleware<S>(secret));`

## Auth (token + roles) — `src/qbm/http/middleware/auth.h` · **needs `QB_HAS_SSL`**
### `qb::http::AuthMiddleware<S>` — `middleware/auth.h:44`
`AuthMiddleware(); explicit AuthMiddleware(const auth::Options&, name="AuthMiddleware");`
Reads context `auth::User`/`"jwt_payload"` or extracts+verifies a token via an internal `auth::Manager`; stores `auth::User` in context. Fluent (return `AuthMiddleware&`): `with_user_context_key(key) /*default "user"*/; with_auth_required(bool); with_roles(std::vector<std::string>, require_all=false); with_options(const auth::Options&)`. Also `auth::Manager& auth_manager()`, `std::string generate_token(const auth::User&) const`, `std::optional<auth::User> verify_token(const std::string&) const`.
Factories (`src/qbm/http/middleware/auth.h:383`): `auth_middleware<S>(options=auth::Options(), name)`, `jwt_auth_middleware<S>(secret, algorithm_str="HS256", name)` (HS*→secret_key, else public_key), `role_auth_middleware<S>(roles, require_all=false, name)`, `optional_auth_middleware<S>(options=auth::Options(), name)`.
Usage: `router.use(qb::http::role_auth_middleware<S>({"admin"}));`

## Rate limiting — `src/qbm/http/middleware/rate_limit.h`
### `qb::http::RateLimitOptions` — `rate_limit.h:67`
`RateLimitOptions() noexcept` (defaults 100 req / 1 min). Setters return `RateLimitOptions&`:
`max_requests(size_t) noexcept; RateLimitOptions& window(qb::duration) noexcept; status_code(qb::http::status) noexcept; message(std::string); template<typename S> RateLimitOptions& client_id_extractor(std::function<std::string(const Context<S>&)>); RateLimitOptions& trust_forwarded_headers(bool enabled=true) noexcept;` — the extractor setter is at `rate_limit.h:142`, the proxy-trust toggle at `rate_limit.h:167`. Getters: `get_max_requests()`, `get_window() -> qb::duration`, `get_status_code()`, `get_message()`. Presets: `static RateLimitOptions permissive()` (1000/min), `static RateLimitOptions secure()` (60/min). **`window` is `qb::duration`.** The method is `client_id_extractor` — there is **no** `with_client_id_extractor`. Without one, the built-in extractor keys on the real socket peer IP; `trust_forwarded_headers` is **off by default** and must be enabled only behind a trusted proxy (client IDs are truncated to `rate_limit_security::MAX_CLIENT_ID_LENGTH = 256`, `rate_limit.h:48`).
Usage: `auto opt = qb::http::RateLimitOptions().max_requests(60).window(std::chrono::minutes(1));`

### `qb::http::RateLimitMiddleware<S>` — `rate_limit.h:348`
`explicit RateLimitMiddleware(name="RateLimitMiddleware"); RateLimitMiddleware(RateLimitOptions, name); RateLimitMiddleware& reset_all_clients() noexcept; RateLimitMiddleware& reset_client(const std::string&); std::size_t evict_stale_entries_now();`
Adds `X-RateLimit-*` headers; over-limit replies with configured status (default 429). Stale-entry cleanup interval `rate_limit_security::STALE_ENTRY_CLEANUP_INTERVAL = std::chrono::minutes{1}` (`rate_limit.h:51`).
Factories (`rate_limit.h:619`): `rate_limit_middleware<S>(options=RateLimitOptions(), name)`, `rate_limit_dev_middleware<S>(name)`, `rate_limit_secure_middleware<S>(name)`.
Usage: `router.use(qb::http::rate_limit_secure_middleware<S>());`

## Compression — `src/qbm/http/middleware/compression.h` · response/request compression gated on `QB_HAS_COMPRESSION`
### `qb::http::CompressionOptions` — `compression.h:40`
`CompressionOptions() noexcept; compress_responses(bool) noexcept; decompress_requests(bool) noexcept; min_size_to_compress(size_t) noexcept; preferred_encodings(std::vector<std::string>);` (each returns `CompressionOptions&`). The default list is `{zstd,br,gzip,deflate}` and the presets are `static CompressionOptions max_compression()` (min 256, `{br,gzip,deflate,zstd}`) and `static CompressionOptions fast_compression()` (min 2048, `{zstd,deflate,gzip,br}`), each list holding only the codecs this build registers (`{gzip,deflate}` without qb's opt-in `QB_WITH_ZSTD` / `QB_WITH_BROTLI`); negotiation takes the client's highest q-value, breaks a tie by this order and passes over a name the build does not register (3.3, Huly QB-93). Getters `should_compress_responses()/should_decompress_requests()/get_min_size_to_compress()/get_preferred_encodings()`.

### `qb::http::CompressionMiddleware<S>` — `compression.h:161`
`CompressionMiddleware(name); CompressionMiddleware(CompressionOptions, name); void update_options(CompressionOptions) noexcept;`
Decompresses request bodies by `Content-Encoding`; compresses responses at `HookPoint::PRE_RESPONSE_SEND` based on `Accept-Encoding`.
Factories (`compression.h:541`): `compression_middleware<S>(options=CompressionOptions(), name)`, `max_compression_middleware<S>(name)`, `fast_compression_middleware<S>(name)`.
Usage: `router.use(qb::http::compression_middleware<S>());`

## Timing — `src/qbm/http/middleware/timing.h`
### `qb::http::TimingMiddleware<S>` — `timing.h:41`
`using Clock=std::chrono::steady_clock; using Duration=std::chrono::milliseconds; using TimingCallback=std::function<void(Duration)>; TimingMiddleware(TimingCallback callback, std::string name="TimingMiddleware");` Throws `std::invalid_argument` if callback is null.
Measures request duration; sets an `X-Response-Time: <ms>ms` header and invokes the callback with `std::chrono::milliseconds`.
Factory (`timing.h:158`): `timing_middleware<S>(callback, name="TimingMiddleware")`.
Usage: `router.use(qb::http::timing_middleware<S>([](auto ms){ LOG(ms.count()); }));`

## Static files — `src/qbm/http/middleware/static_files.h`
### `qb::http::StaticFilesOptions` — `static_files.h:39`
`explicit StaticFilesOptions(std::filesystem::path root);` Public member `std::filesystem::path root_directory;` + fluent setters (return `StaticFilesOptions&`): `with_root_directory(std::filesystem::path); with_serve_index_file(bool) /*index.html*/; with_index_file_name(string); with_default_mime_type(string); with_path_prefix_to_strip(string); add_mime_type(ext, mime); with_cache_control(bool, value="public, max-age=3600"); with_etags(bool); with_last_modified(bool); with_range_requests(bool); with_directory_listing(bool) /*default false*/; with_max_file_size(std::size_t) noexcept /*default 64 MiB; 0=unlimited*/; with_reject_symlinks(bool) noexcept;`
**`root_directory` is a `std::filesystem::path`** (string-literal/`std::string` arguments convert implicitly). A **relative** root is resolved by the middleware ctor via `qb::io::sys::resolve_resource` (`<qb/io/system/file.h>`): looked up against the current working directory first, then against the executable's own directory — so a binary shipped next to its assets serves them from **any** cwd. An absolute root is used unchanged.

### `qb::http::StaticFilesMiddleware<S>` — `static_files.h:281`
`explicit StaticFilesMiddleware(StaticFilesOptions options, std::string name="StaticFilesMiddleware");`
Serves GET/HEAD; path-traversal hardened (canonicalised, symlink-escape rejected), including configured directory index files; supports ETag/If-None-Match, Last-Modified/If-Modified-Since (`If-None-Match` takes precedence when present), `Range`/`206`/`416`, optional directory listing (links escape the request path for the HTML attribute). A filesystem root (`/`, `C:\`) is a valid root: `internal::sanitize_and_resolve_path` accepts its descendants and still refuses a prefix-sharing sibling (`src/qbm/http/middleware/static_files.cpp:92-158`). **Ctor anchors a relative `root_directory` via `qb::io::sys::resolve_resource` (cwd then exe dir), then requires it to exist and canonicalise.** Throws `std::invalid_argument` if root empty, `std::runtime_error` if root (after resolution) missing/not a directory or not canonicalisable.
Factory (`static_files.h:809`): `static_files_middleware<S>(options, name="StaticFilesMiddleware")`.
Usage: `router.use(qb::http::static_files_middleware<S>(qb::http::StaticFilesOptions{"public"}.with_path_prefix_to_strip("/static")));  // "public" found relative to cwd or the executable's dir`

## Security headers — `src/qbm/http/middleware/security_headers.h`
### `qb::http::SecurityHeadersOptions` — `security_headers.h:78`
`SecurityHeadersOptions();` Fluent (return `SecurityHeadersOptions&`): `with_hsts(value)/without_hsts(); with_x_content_type_options_nosniff(bool=true); with_x_frame_options(value)/without_x_frame_options(); with_content_security_policy(value)/without...; with_content_security_policy_report_only(value)/without...; with_referrer_policy(value)/without...; with_permissions_policy(value)/without...; with_cross_origin_opener_policy(value)/without...; with_cross_origin_embedder_policy(value)/without...; with_cross_origin_resource_policy(value)/without...; with_x_permitted_cross_domain_policies(value)/without...; with_csp_nonce(bool=true);` Preset: `static SecurityHeadersOptions secure_defaults()` (HSTS 1y, nosniff, `X-Frame-Options: SAMEORIGIN`, a default CSP, `Referrer-Policy`, COOP `same-origin`, `X-Permitted-Cross-Domain-Policies: none`).

### `qb::http::SecurityHeadersMiddleware<S>` — `security_headers.h:308`
`SecurityHeadersMiddleware(const SecurityHeadersOptions&, name); void update_options(const SecurityHeadersOptions&);`
Adds the configured security headers to every response.
Factory (`security_headers.h:433`): `security_headers_middleware<S>(options=SecurityHeadersOptions::secure_defaults(), name)`.
Usage: `router.use(qb::http::security_headers_middleware<S>());`

## reCAPTCHA — `src/qbm/http/middleware/recaptcha.h` · **needs `QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE`**
### `qb::http::RecaptchaOptions` — `recaptcha.h:72`
`RecaptchaOptions()=default; explicit RecaptchaOptions(std::string secret_key);` Fluent: `min_score(float) noexcept; challenge_type(ChallengeType) noexcept; from_header(...) / from_body(...) / from_query(...);` `enum class TokenLocation{Header,Body,Query}; enum class ChallengeType{V2,V3,Auto};` Presets: `static RecaptchaOptions v3(secret, min_score=0.5f); v2(secret); strict(secret)`. Getters `get_min_score()/get_token_location()/get_challenge_type()`. `struct RecaptchaResult` carries `success`, `score` + `has_score`, `action`, `hostname`, `error_codes`, `challenge_ts` (`std::chrono::system_clock::time_point`: the RFC 3339 instant Google announces, in UTC) + `has_challenge_ts` (false, and `challenge_ts` at the epoch, when absent or unreadable) (`src/qbm/http/middleware/recaptcha.h:248-260`).

### `qb::http::RecaptchaMiddleware<S>` — `recaptcha.h:280`
`using VerificationCallback=std::function<void(qb::http::async::Reply&&)>; using VerificationClient=std::function<void(qb::http::Request, VerificationCallback)>; explicit RecaptchaMiddleware(RecaptchaOptions, name); RecaptchaMiddleware(const std::string& secret, float min_score=0.5f, name);` Statics `v3(secret,min_score=0.5f,name)`, `strict(secret,name)`. Verifies the token against Google (async); rejects below `min_score`.
Factories (`recaptcha.h:601`): `recaptcha_middleware<S>(RecaptchaOptions, name)`, `recaptcha_middleware<S>(secret, min_score=0.5f, name)`, `recaptcha_v3_middleware<S>(secret, min_score=0.5f, name)`, `recaptcha_strict_middleware<S>(secret, name)`. All throw `std::invalid_argument` on empty secret.

## Logging — `src/qbm/http/middleware/logging.h`
### `qb::http::LoggingMiddleware<S>` — `logging.h:57`
`enum class LogLevel{Debug,Info,Warning,Error}; using LogFunction=std::function<void(LogLevel,const std::string&)>; LoggingMiddleware(LogFunction log_fn, LogLevel req_level=Info, LogLevel res_level=Debug, std::string name="LoggingMiddleware") noexcept(false);` Throws `std::invalid_argument` if `log_fn` is null. Logs request on entry and response via a hook; both lines begin with `"[<id>] "` when `request_id_slot` is set (a `RequestIdMiddleware` ran first).
Factory (`logging.h:229`): `logging_middleware<S>(log_fn, request_level=Info, response_level=Debug, name)`.
Usage: `router.use(qb::http::logging_middleware<S>([](auto lvl,auto&m){ /*...*/ }));`

## Request id — `src/qbm/http/middleware/request_id.h`
### `qb::http::request_id_slot` — `request_id.h:37`
`inline constexpr Slot<std::string> request_id_slot{"request.id"};` The request's id once `RequestIdMiddleware` ran: `ctx->get_if(qb::http::request_id_slot)` (`const std::string*`, null otherwise). `inline constexpr std::size_t max_request_id_length = 128;` `[[nodiscard]] constexpr bool is_valid_request_id(std::string_view) noexcept;` — 1..128 characters of `[A-Za-z0-9._-]` (`request_id.h:49`).
### `qb::http::RequestIdOptions` — `request_id.h:63`
Members `std::string header_name = "X-Request-ID"; bool trust_incoming = false;` Fluent: `header(std::string)`, `trust_incoming_id(bool = true) noexcept` (return `RequestIdOptions&`).
### `qb::http::RequestIdMiddleware<S>` — `request_id.h:103`
`explicit RequestIdMiddleware(RequestIdOptions options = {}, std::string name = "RequestIdMiddleware"); RequestIdOptions const& options() const noexcept;` Throws `std::invalid_argument` on an empty header name. `process()`: the client's id when `trust_incoming` and `is_valid_request_id`, else `uuids::to_string(qb::generate_random_uuid())` (UUID v4, 36 chars); sets the response header, stores the id under `request_id_slot`, `CONTINUE`. A refused id is never echoed. Install first, globally (runs for 404/405 too; not for a request the router answers before any chain).
Factory (`request_id.h:171`): `request_id_middleware<S>(RequestIdOptions = {}, name = "RequestIdMiddleware")`; tag `qb::http::middleware::tags::request_id`.
Usage: `router.use(qb::http::request_id_middleware<S>());`

## Access log — `src/qbm/http/middleware/access_log.h` (a router observer, QB-90)
### `qb::http::AccessLogRecord` — `access_log.h:40`
`std::string_view remote_address, method, target, referer, user_agent, request_id, route; qb::wall_time received; int major_version, minor_version, status; std::uint64_t bytes; qb::duration duration; RequestOutcome outcome;` — views valid during the formatter call; `remote_address` empty when unknown, `route` empty for no match, `request_id` empty without `RequestIdMiddleware`.
### Formats — `using AccessLogFormatter = std::function<void(AccessLogRecord const&, std::string& line)>;` (`access_log.h:58`)
`qb::http::access_log_format::common` (`access_log.h:68`) — Apache CLF `%h %l %u %t "%r" %>s %b`, UTC, `-` for an empty body, `"`/`\`/non-printable escaped `\"`/`\\`/`\xhh`; `combined` — common + `"Referer" "User-Agent"` (`-` when absent); `json` (`access_log.h:77`) — one object: `time` (RFC 3339 UTC ms), `remote`, `method`, `target`, `protocol`, `status`, `bytes`, `duration_seconds` (rounded to the µs), `referer`, `user_agent`, `request_id`, `route` (`null` when none), `outcome` (`responded`/`session_gone`/`suppressed`). Each appends one line without a line feed.
### `qb::http::AccessLog<S>` — `access_log.h:91`
`using Sink = std::function<void(std::string_view)>; explicit AccessLog(Sink, AccessLogFormatter = access_log_format::combined);` Throws `std::invalid_argument` on an empty sink or formatter. An `IRequestObserver<S>`: writes one line per routed request when its response is decided (status, body size and headers as sent); reuses its line buffer; a throwing formatter/sink is contained and logged. The remote address costs a `getpeername` (`ip()`) per line. Measured (callgrind, a request with a query, a 101-byte User-Agent, a Referer, a request id): `common` about +1 520 instructions a request, `combined` +2 040, `json` +2 440.
Factory (`access_log.h:160`): `access_log<S>(sink, formatter = access_log_format::combined)`.
Usage: `router.add_observer(qb::http::access_log<S>([](std::string_view l){ qb::io::cout() << l << '\n'; }, qb::http::access_log_format::json));`

## Request metrics — `src/qbm/http/middleware/metrics.h` (a router observer, QB-90/QB-154)
### `qb::http::RequestMetricsOptions` — `metrics.h:48`
`std::vector<double> buckets` (seconds; `qb::metrics::default_duration_buckets` by default); fluent `with_buckets(std::vector<double>)`.
### `qb::http::RequestMetrics<S>` — `metrics.h:127`
`explicit RequestMetrics(RequestMetricsOptions = {});` throws `std::invalid_argument` on empty, non-finite or non-ascending buckets. An `IRequestObserver<S>`: counts each request under its route PATTERN (`unmatched` for none), method and status; observes `RequestEnd::duration`. `void collect(qb::metrics::snapshot&) const` — `qb_http_requests_total{method,route,status}` (counter), `qb_http_request_duration_seconds{method,route}` (histogram with `_sum`), `qb_http_requests_in_flight` (gauge). `std::uint64_t count(method, std::string_view route, int status) const noexcept` (`route` empty = unmatched); `std::uint64_t in_flight() const noexcept`. Plain integers of the router's thread; one instance per router; a series allocated on first sighting only.
Factory (`metrics.h:175`): `request_metrics<S>(RequestMetricsOptions = {})`. Publish it as a source of the core's `qb::metrics::Registry` (qb: `Registry::add_source`) whose callable calls `collect`.
### `qb::http::add_connections` — `metrics.h:185`
`void add_connections(qb::metrics::snapshot&, std::string_view protocol, std::size_t open);` — `qb_http_connections{protocol}` (gauge).

### `qb::http::MetricsEndpointOptions` — `metrics.h:190`
`qb::duration timeout = 1s; std::vector<qb::CoreId> cores` (empty: every core, the actor's `getCoreSet()`); fluent `with_timeout(qb::duration) noexcept`, `with_cores(std::vector<qb::CoreId>)`.
### `qb::http::metrics_handler<S>` / `metrics_response<S>` — `metrics.h:238` / `:219`
`template<typename S> [[nodiscard]] auto metrics_handler(qb::Actor& actor, MetricsEndpointOptions = {})` — a coroutine route handler for `router().get("/metrics", ...)`: `co_await qb::metrics::scrape(actor, cores, timeout)` (every core's `qb::metrics::Registry`, through the registry of `actor`'s core), then `metrics_response`. A core that does not answer is `qb_scrape_core_up{core} 0`; no registry on `actor`'s core answers 500 (the scrape throws `std::logic_error`). `actor` must outlive the router (it owns it, as a server actor does). `template<typename S> void metrics_response(Context<S>&, qb::metrics::snapshot const&)` — 200, `Content-Type: text/plain; version=0.0.4; charset=utf-8`, the text, completed. Nothing mounts the endpoint for you: put it behind authentication or on a listener of its own.
Usage: `router().get("/metrics", qb::http::metrics_handler<S>(*this, qb::http::MetricsEndpointOptions{}.with_timeout(500ms)));`

## Error handling — `src/qbm/http/middleware/error_handling.h`
### `qb::http::ErrorHandlingMiddleware<S>` — `error_handling.h:54`
`using ErrorHandler=std::function<void(ContextPtr,const std::string&)>; using StatusHandler=std::function<void(ContextPtr)>; explicit ErrorHandlingMiddleware(std::string name="ErrorHandlingMiddleware") noexcept;` Fluent (return `ErrorHandlingMiddleware&`): `on_status(qb::http::status, StatusHandler); on_status_range(min_status, max_status, StatusHandler); on_any_error(ErrorHandler);` Centralises error-to-response translation. Put it in the router's error task chain: `process()` always completes the context, so mounting it as ordinary global middleware would terminate every normal request before its route handler.
Factory (`error_handling.h:217`): `error_handling_middleware<S>(name="ErrorHandlingMiddleware")`.
Usage: `auto eh = qb::http::error_handling_middleware<S>(); eh->on_status(qb::http::status::NOT_FOUND, [](auto ctx){ ctx->text("nope"); });`

## Transform — `src/qbm/http/middleware/transform.h`
### `qb::http::TransformMiddleware<S>` — `transform.h:39`
`using RequestTransformer=std::function<void(Request&)>; explicit TransformMiddleware(RequestTransformer transformer=nullptr, std::string name="TransformMiddleware") noexcept(...);` Applies the transformer to the request; a throwing transformer yields 500 + ERROR.
Factory (`transform.h:128`): `transform_middleware<S>(request_transformer=nullptr, name)`.
Usage: `router.use(qb::http::transform_middleware<S>([](auto& req){ req.set_header("X-Tag","1"); }));`

## Conditional (branching) — `src/qbm/http/middleware/conditional.h`
### `qb::http::ConditionalMiddleware<S>` — `conditional.h:42`
`using Predicate=std::function<bool(const ContextPtr&)>; using ChildMiddlewarePtr=std::shared_ptr<IMiddleware<S>>; ConditionalMiddleware(Predicate, ChildMiddlewarePtr if_mw, ChildMiddlewarePtr else_mw=nullptr, std::string name="ConditionalMiddleware");` Throws `std::invalid_argument` if `predicate` or `if_mw` is null. Runs `if_mw` when predicate true, else `else_mw` (or continues).
Factory (`conditional.h:154`): `conditional_middleware<S>(predicate, if_middleware, else_middleware=nullptr, name)`.

## Validation (middleware) — `src/qbm/http/middleware/validation.h`
### `qb::http::ValidationMiddleware<S>` — `middleware/validation.h:45`
`explicit ValidationMiddleware(std::shared_ptr<qb::http::validation::RequestValidator> validator, std::string name="ValidationMiddleware");` Throws `std::invalid_argument` if validator is null. Runs the `RequestValidator` (sanitize then validate); on failure replies with a JSON error body.
Factory (`src/qbm/http/middleware/validation.h:141`): `validation_middleware<S>(validator, name)`.
Usage: `router.use(qb::http::validation_middleware<S>(my_request_validator));`

## Generic builder — `src/qbm/http/middleware/make.h`
`template<typename Tag, typename SessionType, typename... Args> [[nodiscard]] auto make(Args&&... args);` — namespace `qb::http::middleware`.
Tag-dispatches to the right factory. Tags (namespace `qb::http::middleware::tags`): `auth, jwt_auth, role_auth, optional_auth, cors, cors_dev, cors_secure, compression, compression_fast, compression_max, logging, timing, request_id, rate_limit, rate_limit_dev, rate_limit_secure, security_headers, static_files, transform, conditional, error_handling, jwt, recaptcha, recaptcha_v3, recaptcha_strict`. Include `src/qbm/http/middleware/all.h` for everything (or `make.h`).
Usage: `auto mw = qb::http::middleware::make<qb::http::middleware::tags::cors_secure, S>(std::vector<std::string>{"https://app"});`

---

# Namespace `qb::http::auth` — token manager (auth/) · **needs `QB_HAS_SSL`**

### `qb::http::auth::Options` (alias `AuthOptions`) — `src/qbm/http/auth/options.h:36`
`class Options` — JWT config; fluent setters return `Options&`.
`enum class Algorithm{HMAC_SHA256,HMAC_SHA384,HMAC_SHA512,RSA_SHA256,RSA_SHA384,RSA_SHA512,ECDSA_SHA256,ECDSA_SHA384,ECDSA_SHA512,ED25519}` (default HMAC_SHA256, `options.h:41`).
- `secret_key(const std::string&) / secret_key(const std::vector<unsigned char>&) / secret_key(std::vector<unsigned char>&&) noexcept` (`options.h:93`).
- `public_key(std::string)` / `private_key(std::string)` (PEM) (`options.h:126, :138`).
- `algorithm(Algorithm) noexcept` (`options.h:150`).
- **`token_expiration(std::chrono::seconds) noexcept`** (default 3600s) (`options.h:161`).
- `token_issuer(std::string)` / `token_audience(std::string)` — non-empty auto-enables verification (`options.h:173, :187`).
- `auth_header_name(std::string)` (default `Authorization`) / `auth_scheme(std::string)` (default `Bearer`) (`options.h:200, :212`).
- `require_signature_verification(bool) noexcept` / `verify_expiration(bool) noexcept` / `verify_not_before(bool) noexcept` (`options.h:224, :235, :246`).
- **`clock_skew_tolerance(std::chrono::seconds) noexcept`** (default 0s) (`options.h:258`).
- getters (`options.h:267`): `get_secret_key()/get_public_key()/get_private_key()/get_token_issuer()/get_token_audience()/get_auth_header_name()/get_auth_scheme()/get_algorithm()/get_token_expiration() -> std::chrono::seconds/get_clock_skew_tolerance() -> std::chrono::seconds/get_require_signature_verification()/get_verify_expiration()/get_verify_not_before()/get_verify_issuer()/get_verify_audience()`.
- `static std::optional<Algorithm> algorithm_from_string(std::string_view) noexcept` (`options.h:358`) — maps `"HS256"/"RS512"/"ES256"/"EdDSA"/...`.
Usage: `qb::http::auth::Options o; o.secret_key("k").token_expiration(std::chrono::hours(1));`

### `qb::http::auth::User` (alias `AuthUser`) — `src/qbm/http/auth/user.h:33`
`struct User { std::string id, username; std::vector<std::string> roles; qb::unordered_map<std::string,std::string> metadata; bool has_role(const std::string&) const noexcept; bool has_any_role(const std::vector<std::string>&) const noexcept; bool has_all_roles(const std::vector<std::string>&) const noexcept; }`
`has_any_role({})` → false; `has_all_roles({})` → true (vacuous).

### `qb::http::auth::Manager` (alias `AuthManager`) — `src/qbm/http/auth/manager.h:36`
`explicit Manager(const Options& = Options()) noexcept; std::string generate_token(const User&) const; std::string extract_token_from_header(const std::string& auth_header_value) const; std::optional<User> verify_token(const std::string& token) const; const Options& get_options() const noexcept; void set_options(const Options&) noexcept;`
`generate_token` may throw on crypto failure; `extract_token_from_header` returns empty string on mismatch (no verification); `verify_token` returns `nullopt` on any failure.
Usage: `qb::http::auth::Manager m{o}; auto tok = m.generate_token(user); auto u = m.verify_token(tok);`

---

# Namespace `qb::http::validation` — request validation (validation/)

### `qb::http::validation::Error` — `src/qbm/http/validation/error.h:31`
`struct Error { std::string field_path, rule_violated, message; std::optional<qb::json> offending_value; Error(path, rule, msg, value=std::nullopt); }`

### `qb::http::validation::Result` — `src/qbm/http/validation/error.h:62`
`class Result { enum class ErrorValuePolicy{Full,Preview,None}; Result& set_error_value_policy(ErrorValuePolicy, std::size_t preview_bytes=256) noexcept; bool success() const; const std::vector<Error>& errors() const; void add_error(path,rule,msg,std::optional<qb::json> value=std::nullopt); template<class Json> requires std::same_as<std::remove_cvref_t<Json>, qb::json> void add_error(path,rule,msg,Json&& value); void add_error(Error); void clear(); void merge(const Result&); Result make_child() const; }`
The `qb::json` overload (`src/qbm/http/validation/error.h:152-157`, Huly QB-1008) takes the `const qb::json&` a `CustomRule` receives, which nlohmann 3.12 cannot convert to `std::optional<qb::json>` implicitly; it delegates to the optional form. Any other value (a string, a number, `std::nullopt`, a `std::optional`) takes the optional form, as before.
`success() == errors().empty()`; `preview_bytes` clamped to `[16, 64*1024]`.
`Preview` keeps the longest complete UTF-8 prefix within the byte budget for strings and serialized compound values.

### Rules — `src/qbm/http/validation/rule.h`
- `enum class DataType{STRING,INTEGER,NUMBER,BOOLEAN,OBJECT,ARRAY,NUL,ANY}` (`rule.h:32`).
- `class IRule { virtual bool validate(const qb::json&, const std::string& field_path, Result&) const=0; virtual std::string rule_name() const=0; }` (`rule.h:39`).
- `TypeRule(DataType)` (+ `static std::string data_type_to_string(DataType) noexcept`), `RequiredRule`, `MinLengthRule(size_t)`, `MaxLengthRule(size_t)`, `PatternRule(std::string)` (ctor throws `std::invalid_argument` on >1024-char/invalid), `MinimumRule(double,exclusive=false)` / `MaximumRule(double,exclusive=false)` (also `qb::json` and integral bounds), `EnumRule(qb::json)` (ctor throws if not array), `UniqueItemsRule`, `MinItemsRule(size_t)`, `MaxItemsRule(size_t)`, `MinPropertiesRule(size_t)`, `MaxPropertiesRule(size_t)`, `PropertyNamesRule(const qb::json&)`, `ItemsRule(ItemsRuleLogic, additional_items_policy=true)`, `CustomRule(CustomValidateFn, std::string rule_name)`.
- String lengths count Unicode code points in valid UTF-8; malformed programmatic strings fail without copying them into an error. Numeric bounds retain signed/unsigned integer precision, and `EnumRule` / `UniqueItemsRule` compare JSON numbers exactly at every nesting level. A numeric `exclusiveMinimum` / `exclusiveMaximum` stands alone; the earlier boolean form beside `minimum` / `maximum` remains supported.
- `using ItemsRuleLogic=std::variant<std::shared_ptr<SchemaValidator>, std::vector<std::shared_ptr<SchemaValidator>>>` (`rule.h:373`); `using CustomValidateFn=std::function<bool(const qb::json&,const std::string&,Result&)>` (`rule.h:403`).

### `qb::http::validation::SchemaValidator` — `src/qbm/http/validation/schema_validator.h:33`
`explicit SchemaValidator(const qb::json& schema);` (throws `std::invalid_argument` if not an object) `bool validate(const qb::json& data, Result&) const; SchemaValidator& set_error_value_policy(ErrorValuePolicy, preview_bytes=256) noexcept; std::optional<qb::json> make_offending_value(const qb::json&) const;` `enum class ErrorValuePolicy{Full,Preview,None}`. Nesting bound: 64 sub-schemas per validation, one budget shared by every keyword that holds a sub-schema (`properties`, `items`, `additionalItems`, `additionalProperties`, `propertyNames`, `allOf`/`anyOf`/`oneOf`/`not`); past it, error `schemaTooDeep` (`src/qbm/http/validation/schema_validator.h:162-168`).
Usage: `qb::http::validation::SchemaValidator v{schema}; qb::http::validation::Result r; v.validate(data, r);`

### Parameters — `src/qbm/http/validation/parameter_validator.h`
- `struct ParameterRuleSet { std::string name; DataType expected_type=STRING; bool required=false; std::optional<std::string> default_value; std::vector<std::shared_ptr<IRule>> rules; std::function<qb::json(const std::string&,bool&)> custom_parser; }` + fluent `set_type/set_required/set_default/add_rule/set_custom_parser` (`parameter_validator.h:35`).
- `class ParameterValidator { explicit ParameterValidator(bool strict_mode=false); void add_param(ParameterRuleSet); bool validate(const qb::icase_unordered_map<std::string>& params, Result&, const std::string& source_name) const; qb::json validate_single(name, const std::optional<std::string>& value, const ParameterRuleSet&, Result&, source_name) const; const qb::icase_unordered_map<ParameterRuleSet>& get_param_definitions() const; void set_strict_mode(bool); bool is_strict_mode() const; }` (`parameter_validator.h:115`).
  A rule returning `false` without adding an error produces a generic error named by `rule_name()`; an explicit rule error is not duplicated.

### Sanitizers — `src/qbm/http/validation/sanitizer.h`
- `using SanitizerFunction=std::function<std::string(const std::string&)>` (`sanitizer.h:26`).
- `class Sanitizer { void add_rule(const std::string& field_path, SanitizerFunction); void sanitize(qb::json&) const; }` (`sanitizer.h:35`) — `[N]`=index, `[*]`=all array elements; only string nodes modified.
- `namespace PredefinedSanitizers`: `trim()`, `to_lower_case()`, `to_upper_case()`, `escape_html()`, `strip_html_tags()` (not XSS-safe), `alphanumeric_only()`, `normalize_whitespace()`, `escape_sql_like()` (not general SQLi prevention) — all `SanitizerFunction` (`sanitizer.h:68`).

### `qb::http::validation::RequestValidator` — `src/qbm/http/validation/request_validator.h:34`
`class RequestValidator { RequestValidator& for_body(const qb::json& schema); for_query_param(name, ParameterRuleSet); for_header(name, ParameterRuleSet); for_path_param(name, ParameterRuleSet) /*strict*/; add_body_sanitizer(field_path, SanitizerFunction); add_query_param_sanitizer(name, SanitizerFunction); add_header_sanitizer(name, SanitizerFunction); bool validate(qb::http::Request&, Result&, const qb::http::PathParameters* =nullptr); RequestValidator& set_error_value_policy(Result::ErrorValuePolicy, preview_bytes=256) noexcept; }`
Composes body-schema + query/header/path validators + sanitizers. `validate()` mutates the request (sanitizers run first), merges errors, returns true if fully valid. `for_body` may throw if schema not an object.
The configured error-value policy reaches the body schema in either setter/`for_body` order. A header sanitizer that changes `Content-Type` refreshes the typed `request.content_type()` cache before validation continues.
Usage: `auto rv = std::make_shared<qb::http::validation::RequestValidator>(); rv->for_body(schema);`

---

# Namespace `qb::http` / `qb::http1` — HTTP/1.1 server, one-shot client, persistent client (`1.1/`)

### Server (plaintext) — `src/qbm/http/1.1/http.h`
- `qb::http::DefaultSession` — default non-SSL per-connection session.
- `template<typename Session=DefaultSession> class Server : public use<Server<Session>>::server<Session>` — HTTP/1.1 server; `Router<Session>& router()`; listen via inherited `internal::server::listen`. Alias `template<...> using server = Server<Session>`.
- `template<typename Session=DefaultSession> std::unique_ptr<Server<Session>> make_server();` — factory.
- `internal::server::listen(qb::io::uri uri, std::filesystem::path cert_file={}, std::filesystem::path key_file={}) -> bool` — bind/listen; **returns true == listening** (it returns `!transport().listen(...)`). Secure transport sets ALPN `{"http/1.1"}`.
- `internal::session::keep_alive(bool=true)`; `internal::session::max_pipelined_requests(std::size_t) noexcept` (default 128, exceed → disconnect `ByProtocolError`); `internal::session::context() -> std::shared_ptr<Context<Derived>>` (null when idle); `internal::session::send_response(ContextType&)`; `internal::io_handler::router() -> Router&`.
Usage: `auto s = qb::http::make_server(); s->router().get("/", h); s->router().compile(); s->listen(qb::io::uri{"tcp://0.0.0.0:8080"}); s->start();`

### Server (HTTPS) — `src/qbm/http/1.1/http.h` · **needs `QB_HAS_SSL`**
- `qb::http::ssl::DefaultSecureSession`; `template<typename Session=DefaultSecureSession> class ssl::Server` (`router()` const+non-const); `template<typename Session=DefaultSecureSession> std::unique_ptr<ssl::Server<Session>> ssl::make_server();` Pass cert/key to `listen(...)`.
- `listen` cert/key are `std::filesystem::path` (here and on the http2/http3/dual-stack `listen` overloads). Secure listen builds the `SSL_CTX` via `qb::io::ssl::create_server_context`, which resolves a **relative** cert/key path through `qb::io::sys::resolve_resource` (cwd first, then the executable's own directory); absolute paths are used unchanged. So `listen(uri, "cert.pem", "key.pem")` finds certs shipped next to the binary from any working directory. (String literals convert implicitly to `std::filesystem::path`.)
- `template<typename Derived> struct use { ... };` — type-builder mapping a Derived type to internal session/io_handler/server (tcp; `ssl::*` mirror for stcp/saccept).

### One-shot async client — `src/qbm/http/1.1/http.h`
- `struct qb::http::async::Reply { Request request; Response response; }` — result pairing.
- `template<typename Func> using async::HTTP = session<Func, qb::io::transport::tcp>;` and `async::HTTPS = session<Func, qb::io::transport::stcp>` (**HTTPS needs `QB_HAS_SSL`**).
- Callback form: `template<typename Func> REQUEST(Request, Func&&, qb::duration timeout=qb::duration::zero(), bool verify_peer=true)` (method taken from request); verb helpers `GET/POST/PUT/DEL/HEAD/OPTIONS/PATCH(Request, Func&&, timeout, verify_peer)` force the method. `Func` is invoked with `async::Reply&&`. Sets Host/User-Agent/Accept-Encoding if absent.
- Coroutine form: `[[nodiscard]] async::awaiter<async::Reply> REQUEST(Request, qb::duration timeout=qb::duration::zero(), bool verify_peer=true)` and `GET/POST/PUT/DEL/HEAD/OPTIONS/PATCH(...)` — `co_await` yields `async::Reply`.
- `std::string host_header_value(const qb::io::uri&)` — Host header value: `origin::authority(uri)` (brackets IPv6 without its zone identifier, omits the scheme's default port).
- `template<typename Awaitable> auto run_sync(Awaitable&&)` — `src/qbm/http/coro.h:287` — drive any qbm-http awaitable to completion on the current I/O thread; a thin re-export of `qb::io::async::run_sync` so callers need not reach into `qb::io`. This is the **non-ws** `qb::http::run_sync`; `qb::http::ws::run_sync` (`src/qbm/http/ws/coro.h:505`) is the WebSocket-side alias of the same primitive. Use it from `main()`/tests, never from inside a coroutine already being driven.
  Usage: `auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{"http://localhost:8080/"}}));`
- **`qb::duration::zero()` means "no timeout"**, not an immediate timeout.
Usage (coro): `auto reply = co_await qb::http::GET(qb::http::Request{qb::http::method::GET, qb::io::uri{"https://h/x"}});`

### Persistent client — `qb::http1::Client` (alias `client`) — `src/qbm/http/1.1/client.h`
`class Client : public std::enable_shared_from_this<Client>` — same-origin keep-alive client; **non-copyable, must live in a `shared_ptr`**.
- `explicit Client(const std::string& base_uri); explicit Client(const qb::io::uri&);` — throws `std::invalid_argument` on non-http(s) scheme / missing host (http-only when `QB_HAS_SSL` off).
- `bool connect(ConnectionCallback);` and `[[nodiscard]] async::awaiter<ConnectResult> connect();` — `ConnectionCallback = void(bool connected, const std::string& error)`. During retirement it accepts the next intent but starts it after old callback/protocol dispatch unwinds; `is_connecting()` may be true before connected. Work may queue behind explicit intent with automatic reconnect disabled.
- `void disconnect();` — marks down before old notifications, fails the detached active + pending cohort with SERVICE_UNAVAILABLE, and reports the old connect callbacks cancelled once. Reentrant requests/connects belong to the next cycle. Destruction abandons pending connect callbacks instead of notifying them. (`src/qbm/http/1.1/client.cpp:235-239,275-310,341-352,568-633`.)
- `bool push_request(Request, ResponseCallback);` and `[[nodiscard]] async::awaiter<Response> push_request(Request);` — `ResponseCallback=void(Response)`; callback form returns false if callback null or pending limit reached.
- `bool push_requests(std::vector<Request>, BatchResponseCallback);` and `[[nodiscard]] async::awaiter<std::vector<Response>> push_requests(std::vector<Request>);` — `BatchResponseCallback=void(std::vector<Response>)`, responses index-aligned.
- `void set_connect_timeout(qb::duration) noexcept` (default 30s); `set_request_timeout(qb::duration)` (default 60s); `set_auto_reconnect(bool)`; `set_max_pending_requests(...)` (default 1024); `void set_verify_peer(bool) noexcept` (default true, before connect) + `bool verify_peer() const noexcept`.
- `std::tuple<uint64_t,uint64_t,uint64_t> get_stats() const noexcept` = {total, successful, failed}; `bool is_connected()/is_connecting() const noexcept`; `get_active_request_count()`; `get_base_uri()`.
- `struct ConnectResult { bool ok{false}; std::string error_message; explicit operator bool() const noexcept; }`; aliases `ResponseCallback/BatchResponseCallback/ConnectionCallback`.
- `std::shared_ptr<Client> qb::http1::make_client(const std::string& base_uri);` / `make_client(const qb::io::uri&);` — required ownership form.
Usage: `auto c = qb::http1::make_client("https://h"); co_await c->connect(); auto resp = co_await c->push_request(req);`

### HTTP/1.1 protocol/parser — `1.1/protocol/*`
- `template<typename MessageType> struct Parser : public http_t` (`base.h:131`) — llhttp incremental parser; `parse(buffer,size)->http_errno_t`, `reset()`, `resume()`, `get_parsed_message()`, `headers_completed()`. Copyable and movable at every phase: it holds no pointer to itself, its callbacks find it through the state llhttp executes (QB-510). The parser fills the raw header map only; the message's typed `content_type()` derives from it on first read, on every framing path (QB-506).
- `template<typename IO_Handler,typename Trait> class base` (`base.h`) — `AProtocol`; `getMessageSize()` does Content-Length + chunked framing.
- `template<typename IO_Handler> class server` (`server.h`) / `client` (`client.h`) — parse Cookie / Set-Cookie (exceptions contained) and dispatch via `_io.on(...)`.
- `template<typename IO_Handler> using qb::http::protocol = ...` — selects server vs client by `IO_Handler::has_server`.

---

# Namespace `qb::http2` — HTTP/2 (`2/`) · **needs `QB_HAS_SSL`**

### Constants — `src/qbm/http/2/http2.h`
`namespace constants`: `DEFAULT_SESSION_TIMEOUT = std::chrono::seconds(60)` (qb::duration), `DEFAULT_MAX_CONCURRENT_STREAMS = 50`, `STREAM_IDLE_TIMEOUT = std::chrono::seconds(30)`, `STREAM_INCOMPLETE_TIMEOUT = std::chrono::seconds(10)`, `CLEANUP_INTERVAL = std::chrono::seconds(5)` (all `qb::duration`).

### Server
- `class DefaultSession : public qb::http2::use<DefaultSession>::session<Server<DefaultSession>>` (`http2.h:655`).
- `template<typename SessionType=DefaultSession> class Server : public internal::server<Server<SessionType>,SessionType>` — `Router& router()` (`http2.h:679`).
- `template<typename Session=DefaultSession> std::unique_ptr<Server<Session>> make_server();` (`http2.h:719`).
- `internal::server::listen(qb::io::uri, std::filesystem::path cert, std::filesystem::path key) -> bool` — ALPN `{h2, http/1.1}`; binds **and** starts accepting, like the qb-io acceptor it derives from (`http2.h:598`). `listen_no_start(...)` is the bind-only opt-out (`http2.h:615`).
- `internal::session`: `[[nodiscard]] bool reset_stream(uint32_t stream_id, ErrorCode=CANCEL, const std::string& reason={})`; `auto& operator<<(qb::http::Response&)` (validates stream_id>0 + status 100..599); `Router& router()`.
- `template<typename Derived> struct use { ... session/io_handler/server ... }` (`http2.h:631-641`).
Usage: `auto s = qb::http2::make_server(); s->router().get("/", h); s->router().compile(); s->listen(uri,"cert.pem","key.pem");`

Stock session lifecycle: write progress and full-drain EOS collect logically completed contexts whose native stream is closed. Selection uses batches of 32 IDs (128 bytes of stack ID scratch, no heap scratch); each ID is refound and rechecked. One context leaves the registry before `POST_RESPONSE_SEND` and is released before the next candidate. The last owner triggers `REQUEST_COMPLETE` and member destruction; external owners may delay them. Same-drain rescans catch silent eligibility changes, including destruction with no hooks registered, while actual removals consume a budget fixed to the initial registry size. Selection is unordered, without a public stream-ID ordering guarantee. Reentry, active-protocol, connection and output-size guards apply before each scan/candidate; first-POST extraction cancels the remaining contexts. This changes no public API or Session data members and establishes no measured performance gain. Partial-write timing remains; EOS means framework output drain, not peer acknowledgment. Peer resets of unfinished routed streams, including `NO_ERROR`, cancel the stock context without a neutral public error event or a required new custom-I/O callback. (`src/qbm/http/2/http2.h:120-188,375-419`; `src/qbm/http/2/protocol/server.h:789-810`.)

### `qb::http2::Client` (alias `client`) — `src/qbm/http/2/client.h:163`
`class Client : public std::enable_shared_from_this<Client>, public qb::io::async::tcp::client<Client,qb::io::transport::stcp>, public qb::io::use<Client>::timeout` — TLS+ALPN-h2 only; **non-copyable, non-movable**; via `make_client`/`shared_ptr`.
- `explicit Client(const std::string& base_uri); explicit Client(const qb::io::uri&);`
- `bool connect(ConnectionCallback)` (pass `nullptr` for fire-and-forget; no default arg) / `[[nodiscard]] async::awaiter<ConnectResult> connect();`
- `void disconnect(); bool is_connected()/is_connecting() const noexcept` (connected = TCP + h2 handshake). `disconnect()` fails the outstanding work at once (`503`), sends `GOAWAY(NO_ERROR)` after what the connection still had to send, then qb-io shuts the sending side down (the server reads the GOAWAY, then EOF, no reset; the descriptor is released on the next connection or destruction) — at the latest after `static constexpr qb::duration Client::GOAWAY_FLUSH_LIMIT` (1 s) when the server stopped reading (`src/qbm/http/2/client.cpp:154-214`, `src/qbm/http/2/client.cpp:1108-1118`).
- `bool push_request(Request, ResponseCallback)` / `[[nodiscard]] async::awaiter<Response> push_request(Request)` (lazy connect). Past the pending cap `push_request` **rejects with `503 Service Unavailable`**; `push_requests` admits member by member, a member past the cap getting `503` at its index (callback still once, in order; returns `false` then) (DoS guard, matches http1/http3; `src/qbm/http/2/client.cpp:357-368`).
- `bool push_requests(std::vector<Request>, BatchResponseCallback)` / `[[nodiscard]] async::awaiter<std::vector<Response>> push_requests(std::vector<Request>)` (separate streams, request order).
- A completed batch leaves the client's batch registry before its callback runs; that callback may call `disconnect()` or enqueue another batch (`src/qbm/http/2/client.cpp:389-401`).
- A batch the client fails before every member is answered (explicit `disconnect()`, connection loss, exhausted reconnection run) still gets ONE callback: the responses already received are kept as received (an empty `200` stays a `200`, an admission-refused member keeps its `400`) and every unanswered member gets `503` with the failure reason as body (`src/qbm/http/2/client.cpp:332-339`).
- While sending queued requests, the client retains itself and rechecks its connection and h2 protocol before each send. A failed-send callback may disconnect or enqueue new work without sending the next request on a retired connection (`src/qbm/http/2/client.cpp:479-525`).
- Client stream identifiers are 31-bit (RFC 9113 §5.1.1): once a connection has opened stream 2^31-1, `ClientHttp2Protocol::stream_ids_exhausted()` is true and its `send_request` refuses; the client drains that connection like a graceful GOAWAY (active requests finish on it) and sends the pending ones on a new connection, or fails them with `503` when automatic reconnection is off (`src/qbm/http/2/client.cpp:491-499`, `src/qbm/http/2/protocol/client.h:1295-1306`).
- `void set_connect_timeout(qb::duration)` (default 30s); `set_request_timeout(qb::duration)` (default 60s); `void set_max_concurrent_streams(size_t)` (default 100); `void set_max_pending_requests(size_t) noexcept` (default 1024; bound on outstanding pending+active requests, 503 over-limit); `set_auto_reconnect(bool)` (default true; keeps the policy); `void set_verify_peer(bool) noexcept` (default true) + `bool verify_peer() const noexcept`.
- Reconnection run (`src/qbm/http/2/client.h:472-497`): `void enable_auto_reconnect(RetryPolicy policy = RetryPolicy{}) noexcept` / `void disable_auto_reconnect() noexcept` (the redis names; a scheduled attempt still fires); `[[nodiscard]] bool is_reconnecting() const noexcept` (an attempt scheduled or in flight); `[[nodiscard]] int reconnect_attempts() const noexcept` (attempts in the current run: reset by a connection that comes up, an explicit `connect()`, an explicit `disconnect()` — which starts no run, as on http1: a push after it connects on its own). `qb::http2::RetryPolicy` is `qb::http::RetryPolicy` (`src/qbm/http/2/client.h:93`). Attempt 1 immediate, then the policy's waits; exhausted -> the waiting requests get `503` with body `Reconnection attempts exhausted (N)` and the client stays down until the next `connect()` (explicit, or a later push's auto-connect). Every attempt fires from the client's timer, never from inside the failing handler; a push made from a failure callback queues behind the scheduled attempt.
- `std::tuple<uint64_t,uint64_t,uint64_t> get_stats() const noexcept`; `get_active_request_count()`; `get_base_uri()`.
- `struct ConnectResult { bool ok{false}; std::string error_message; explicit operator bool() const noexcept; }`; aliases `ResponseCallback/BatchResponseCallback/ConnectionCallback`.
- `std::shared_ptr<Client> qb::http2::make_client(const std::string&);` / `make_client(const qb::io::uri&);`
Usage: `auto c = qb::http2::make_client("https://h"); auto resp = co_await c->push_request(req);`

### `qb::http::RetryPolicy` — `src/qbm/http/retry_policy.h:34`
`struct`. The reconnection backoff shared by the qbm-http clients (the HTTP/2 client today); the same shape as `qb::redis::RetryPolicy` minus its `connect_timeout` (an HTTP client owns that setting). **All time fields are `qb::duration`.**

```cpp
struct RetryPolicy {
  int           max_attempts  = -1;        // per run, -1 = unlimited
  qb::duration  initial_delay = 100ms;     // the wait before attempt 2
  qb::duration  max_delay     = 30s;       // the wait never grows past this
  double        multiplier    = 2.0;       // below 1 reads as 1
  bool          jitter        = true;      // +-25 % on every wait
  std::function<void(int attempt, qb::duration next_delay)> on_retry;  // before each wait: attempts failed so far
};
```
Fluent setters (each returns `RetryPolicy&`): `with_max_attempts(int)`, `with_initial_delay(qb::duration)`, `with_max_delay(qb::duration)`, `with_multiplier(double)`, `with_jitter(bool)`, `with_on_retry(std::function<void(int,qb::duration)>)`. Pure: `[[nodiscard]] qb::duration next_delay(int attempt, std::mt19937 *rng = nullptr) const` (`retry_policy.h:90`) — the wait after `attempt` failed attempts: 0 for `attempt < 1`, `initial_delay * multiplier^(attempt-1)` capped at `max_delay` (integer milliseconds, the redis arithmetic), jittered when `rng` is given and `jitter` is on, never below 1 ms once positive; a zero wait stays zero.

### HPACK (RFC 7541) — `src/qbm/http/2/protocol/hpack.h`
- `class Encoder { bool encode(const std::vector<HeaderField>&, std::vector<uint8_t>&); void set_peer_max_dynamic_table_size(uint32_t); void set_max_capacity(uint32_t); void reset(); }` — value-owned. `encode` validates every field first: on `false` nothing is appended and the table is untouched. The table holds min(`set_max_capacity`, peer limit); a size change is announced by a Dynamic Table Size Update at the start of the next block (the smallest size reached first, RFC 7541 §4.2). A field marked `sensitive` stays a never-indexed literal even on an exact table match; default-sensitive names and pseudo headers are never indexed. Value octets 0x80–0xFF are valid.
- `class Decoder { bool decode(const std::vector<uint8_t>&, std::vector<HeaderField>&, bool& out_is_possibly_incomplete); void set_max_dynamic_table_size(uint32_t); void set_max_header_list_size(uint32_t); void reset(); }` — false on protocol errors.
- `class DynamicTable { struct AddResult{bool added; std::size_t evicted;}; AddResult add(string,string); std::size_t set_max_byte_size(std::size_t); operator[](size_t); }` — ring buffer, newest-first, non-copyable/movable.
- `struct HeaderField { std::string name,value; bool sensitive=false; std::size_t hpack_size() const; bool is_pseudo_header() const; bool is_sensitive_by_default() const noexcept; }`.
- `namespace static_table`: `find_name_match(string_view)`, `find_exact_match(string_view,string_view)`, `get_entry(size_t)`, `is_valid_index(size_t)`; `constexpr std::array<...,61> STATIC_TABLE`.
- `enum class HpackError{SUCCESS,INVALID_INDEX,INTEGER_OVERFLOW,INSUFFICIENT_DATA,INVALID_INSTRUCTION,TABLE_SIZE_EXCEEDED,HEADER_LIST_SIZE_EXCEEDED,HUFFMAN_DECODE_ERROR,UNKNOWN_ERROR}`; `enum class InstructionType:uint8_t{...}`.
- `namespace convenience`: `encode_headers(vector<HeaderField>) -> vector<uint8_t>` (throws `std::invalid_argument` on an invalid field, never a partial block); `decode_headers(vector<uint8_t>) -> std::optional<vector<HeaderField>>`; `make_header(string,string) -> HeaderField`.

### Streams + frame handlers — `src/qbm/http/2/protocol/stream.h`, `src/qbm/http/2/protocol/server.h`
- `enum class Http2StreamConcreteState{IDLE,OPEN,RESERVED_LOCAL,RESERVED_REMOTE,HALF_CLOSED_LOCAL,HALF_CLOSED_REMOTE,CLOSED}`.
- `class Http2StreamBase { uint32_t id; Http2StreamConcreteState state; int64_t local_window_size,peer_window_size; bool is_closed()/can_send_data()/can_receive_data(); void transition_state(bool,bool); void mark_reset(ErrorCode,bool); }`; `struct Http2ClientStream : Http2StreamBase {...}`; `struct Http2ServerStream : Http2StreamBase {...}`.
- `class FlowControlManager { static int64_t update_window_safe(int64_t,uint32_t,int64_t) /*-1 on overflow*/; static bool should_send_window_update(uint32_t,uint32_t); static uint32_t calculate_window_threshold(int64_t,int divisor=2); }`.
- `template<typename StreamType> class StreamManager { struct CleanupCriteria{ qb::duration max_idle_time, max_age; bool cleanup_closed_streams, cleanup_reset_streams; uint32_t max_total_streams; }; std::size_t cleanup_streams(const CleanupCriteria&); StreamStats get_statistics() const; }` — **timeouts are `qb::duration`** (0 = no limit).
- events: `struct Http2StreamErrorEvent{uint32_t stream_id; ErrorCode; std::string message;}`, `Http2GoAwayEvent{ErrorCode; uint32_t last_stream_id; std::string debug_data;}`, `Http2PushPromiseEvent{uint32_t associated/promised_stream_id; qb::http::Headers headers;}`, `Http2ConnectionErrorEvent{ErrorCode; std::string message; bool fatal;}`.
- `template<typename IO_Handler> class ServerHttp2Protocol` (`src/qbm/http/2/protocol/server.h:78`) — non-copyable/non-movable:
  - `bool send_response(uint32_t stream_id, const qb::http::Response&)` — a response to `HEAD` ends the stream on its HEADERS (no DATA, `content-length` kept); the fields named by the response's `trailer` header, then its `trailers()`, leave in the trailer block after the body -- an empty body included -- not in the leading HEADERS, which gain a `trailer` announcement when the response has none — the request side follows the same rule, `ClientHttp2Protocol::send_request` sending them as soon as the body is out (`src/qbm/http/2/protocol/base.h:336-394`, Huly QB-1073); a forbidden field of `trailers()` refuses the response (stream error) or the request (`false`) before anything is sent. A received trailer section is checked against the one trailer list on both sides and lands in `trailers()` (and the headers, for 3.x); the client completes a response whose trailer section was not announced (a second header block that ends the stream). A request announcing fields it does not set waits for `send_request_trailers()` on the protocol (`set_explicit_request_trailers(true)`, the default); `qb::http2::Client` sets it false, so such a stream ends after the body with an empty trailer block (`src/qbm/http/2/protocol/client.h:1308-1325`);
  - `[[nodiscard]] std::optional<PushPromiseFailureReason> send_push_promise(uint32_t associated, uint32_t promised /*even, non-zero*/, qb::http::Request pseudo_headers)` (needs peer `SETTINGS_ENABLE_PUSH=1`); on success answer the reserved stream with `send_response(promised, response)`;
  - `void send_rst_stream(uint32_t, ErrorCode, const std::string& msg="", bool close_context=true) noexcept`;
  - `uint32_t cleanup_idle_streams(qb::duration max_idle=std::chrono::seconds(30), qb::duration max_incomplete=std::chrono::seconds(10)) noexcept` — idle counts from the last progress the sweep observed (response HEADERS/DATA sent, stream WINDOW_UPDATE received); `max_incomplete` bounds the AGE of a stream whose request is incomplete;
  - `[[nodiscard]] bool is_stream_closed(uint32_t) const`; `static bool is_valid_header_field(const std::string& name, const std::string& value) noexcept`.
- `template<typename IO_Handler> using client_protocol/server_protocol = ClientHttp2Protocol/ServerHttp2Protocol<IO_Handler>` (`http2.h:72-76`).
- `bool qb::http::well_known::is_hop_by_hop(const std::string& header_name)` (`src/qbm/http/2/protocol/server.h:53`) — classifies hop-by-hop headers (forbidden in HTTP/2).

---

# Namespace `qb::http3` — HTTP/3 / QUIC (`3/`) · **needs `QBM_HTTP_HAS_HTTP3`**

### `qb::http3::Client` (alias `client`) — `src/qbm/http/3/client.h:110`
`class Client : public std::enable_shared_from_this<Client>, public qb::io::async::quic::endpoint` — persistent same-origin client; **heap-owned via `shared_ptr`**.
- `explicit Client(const std::string& base_uri); explicit Client(const qb::io::uri&);` — throws `std::invalid_argument` unless scheme is https.
- `bool connect(ConnectionCallback)` (ALPN `{"h3"}`) / `[[nodiscard]] async::awaiter<ConnectResult> connect();`
- `void disconnect(); [[nodiscard]] bool is_connected() const noexcept` (QUIC + h3 ready).
- From a callback inside a native HTTP/3 read, `disconnect()` marks the client logically down at once. Protocol teardown, QUIC close and failure of still-active requests wait until the read returns; GOAWAY may continue invoking other pending-request callbacks meanwhile. A reentrant `connect(callback)` fails without starting a handshake, new requests get an immediate `503`, and explicit disconnect does not auto-reconnect (`src/qbm/http/3/client.cpp:76-85,119-171,235-240,300-311,749-757,813-851`).
- During ordinary `disconnect()`, the client publishes the closed state before failure callbacks run and rejects their reentrant connect or request attempts until close finishes (`src/qbm/http/3/client.cpp:119-171`). Event callbacks retain the client through endpoint dispatch even if user code releases its last external `shared_ptr` (`src/qbm/http/3/client.cpp:20-36,773-787,813-817,854-872`).
- Failure to start the QUIC connection, a connect timeout or a remote close retires the old transport before failure callbacks can start another attempt. Old requests are failed before connection callbacks can queue new work; the qb-io endpoint refreshes its internally owned native backend on retry (`src/qbm/http/3/client.cpp:93-115,500-542,623-640,783-810`; `qb/src/qb/io/async/quic/endpoint.h:98-135,478-507`).
- The connect timer captures its attempt's epoch and does nothing after a later attempt begins. Explicit `disconnect()` of an in-progress attempt reports failure to that attempt's connection callbacks once; their cancelled timer cannot fail the next attempt (`src/qbm/http/3/client.cpp:101-114,119-171,470-527,623-640`).
- The pending-request drain retains the client and rechecks connection, protocol and shutdown state before each submission, including after a failed submit invokes user code (`src/qbm/http/3/client.cpp:386-467`).
- If the transport closes synchronously during request submission, the request already removed from the pending queue receives a synthesized `503` instead of being installed in the active registry of the closed connection, even if an old failure callback throws; its saved exception propagates afterward. Connect success/failure notify their other callbacks before propagating a callback exception; explicit disconnect also completes transport cleanup (`src/qbm/http/3/client.cpp:119-171,386-467,470-527,545-595`).
- `bool push_request(Request, ResponseCallback)` (auto-connects; false if callback null or the pending cap refused the request, its 503 already delivered — as http1/http2) / `[[nodiscard]] async::awaiter<Response> push_request(Request)`.
- `[[nodiscard]] request_id push_request_with_id(Request, ResponseCallback)` (`request_id=std::uint64_t`; 0 on immediate failure); `bool cancel_request(request_id id, const std::string& reason="HTTP/3 request cancelled")` (resets active stream with H3 error 0x010c = `NGHTTP3_H3_REQUEST_CANCELLED`; false if id unknown). Active cancellation retains the client through its callback and stream reset even if the callback releases the last external owner (`src/qbm/http/3/client.cpp:276-287`).
- `bool push_requests(std::vector<Request>, BatchResponseCallback)` / `[[nodiscard]] async::awaiter<std::vector<Response>> push_requests(std::vector<Request>)` (index-aligned; empty input → `callback({})`). Members are admitted one by one exactly as `push_request` admits one: an invalid member gets its 400 and a member past `set_max_pending_requests` its 503, at its index, before any state exists for it; the callback runs once, at once when nothing was admitted; returns `false` when the cap refused a member, as http1/http2 (`src/qbm/http/3/client.cpp:330-340`).
- `void set_max_pending_requests(std::size_t) noexcept` (default 10000; queued + active bound, 503 past it); `void set_max_concurrent_streams(std::size_t) noexcept` (default 100); `void set_max_body_size(std::size_t) noexcept` (default 64 MiB, exceed resets stream); `void set_connect_timeout(qb::duration) noexcept` (default 30s, ≤0 disables); `void set_request_timeout(qb::duration) noexcept` (default 60s, ≤0 disables); `void set_auto_reconnect(bool) noexcept` (default true); `void set_verify_peer(bool) noexcept` (default true).
- The QUIC peer's `max_streams_bidi` is a concurrent stream quota, not a lifetime request count. Qb returns a slot on close for a client-initiated request stream delivered through `stream_open_cb`; ngtcp2 renews implicitly opened streams itself. Sequential requests can reuse one HTTP/3 connection beyond the initial quota (`qb/src/qb/io/quic.cpp:1061,1565-1592`; `qbm/http/tests/system/http3/http3-loopback.cpp:1319-1378`).
- `std::tuple<uint64_t,uint64_t,uint64_t> get_stats() const noexcept`; `get_active_request_count()`; `get_stream_state_count()` (streams the connection keeps state for; does not grow with the requests made); `max_http3_body_size()`; `get_base_uri()`.
- `struct ConnectResult { bool ok{false}; std::string error_message; explicit operator bool() const noexcept; }`; aliases `ResponseCallback/BatchResponseCallback/ConnectionCallback/request_id`.
- `std::shared_ptr<Client> qb::http3::make_client(const std::string&);` / `make_client(const qb::io::uri&);`
Usage: `auto c = qb::http3::make_client("https://h"); auto resp = co_await c->push_request(req);`

### Server — `src/qbm/http/3/http3.h`
- `class DefaultSession : public qb::http3::use<DefaultSession>::session<Server<DefaultSession>>` (`http3.h:743`).
- `template<typename SessionType=DefaultSession> class Server : public internal::server<Server<SessionType>,SessionType>` (`http3.h:756`); `template<typename Session=DefaultSession> std::unique_ptr<Server<Session>> make_server();` (`http3.h:769`); alias `template<...> using server = Server<Session>`.
- `internal::server::listen(const qb::io::uri&, const std::filesystem::path& cert, const std::filesystem::path& key) -> bool` (ALPN `{"h3"}`; also a `std::string`-uri overload) (`http3.h:501`); `[[nodiscard]] Router& router() noexcept` (`http3.h:452`); `void set_max_body_size(std::size_t) noexcept` (`http3.h:465`); `void graceful_shutdown()` (`http3.h:526`) — GOAWAY, then each connection closes once its last request stream has CLOSED (response acknowledged by the peer), not when the handler answered: returns with connections in flight still open; `[[nodiscard]] std::size_t http3_stream_state_count() const noexcept` — streams the HTTP/3 connections keep state for (follows requests in flight, not requests served).
- `internal::session`: per-stream server session; `operator<<(Response&)` (HEAD-aware) (`http3.h:221`).
- Trailers and `:authority`, both sides: the adapter's `submit_response` / `submit_request` (`src/qbm/http/3/protocol/connection.h:1365`, `:1424`) build the trailer section with `detail::plan_trailers` (`:409`) and `make_trailer_block` (`:391`) before anything is submitted -- the fields the `trailer` header announces, then `trailers()`; an announced-but-unset field or an empty body still sends the message -- and a received trailer section lands in `trailers()` (and the headers, for 3.x), refused on the one trailer list (Huly QB-1073). `:authority` is `qb::http::origin::authority` (Huly QB-1064).
- `template<typename Derived> struct use { ... session/server ... }` (`http3.h:727`).

### Dual-stack (HTTP/2 + HTTP/3) — `src/qbm/http/3/dual_stack.h` · **namespace `qb::http`** (not `qb::http3`)
- `template<typename Http2Session=qb::http2::DefaultSession, typename Http3Session=qb::http3::DefaultSession> class qb::http::dual_stack_server` (`dual_stack.h:47`) — runs HTTP/2 (TCP+TLS) and HTTP/3 (QUIC) side by side; `router()` returns a `router_facade` registering each route on **both** tables.
- `class router_facade { add_route/get/post/put/del/patch/options/head(...); compile(); }`.
- `bool listen(qb::io::uri tcp_tls_uri, qb::io::uri quic_uri, const std::filesystem::path& cert, const std::filesystem::path& key)` (also a `std::string`-uri overload) — true only if both bind; **all-or-nothing** (rolls back the side that came up and returns false if the other fails) (`dual_stack.h:296-297`).
- Not copyable; `noexcept` move construction and assignment keep `router()` bound to the destination, and the moved-from server holds no stack (destroy or assign only). Move it before `listen()` (`src/qbm/http/3/dual_stack.h:226-252`).
- `template<...> std::unique_ptr<dual_stack_server<...>> qb::http::make_dual_stack_server();` (`dual_stack.h:371`).
Usage: `auto s = qb::http::make_dual_stack_server(); s->router().get("/", h); s->router().compile(); s->listen(tcp_uri, quic_uri, "cert.pem","key.pem");`

### nghttp3 connection adapter — `src/qbm/http/3/protocol/connection.h`
`template<typename Owner> class connection` (Owner supplies stream-I/O + event hooks via `requires`; non-copyable, move-constructible):
- `enum class role{client,server}`; `connection(Owner&, std::uint64_t connection_id, role)` — qpack_blocked_streams=32, max_field_section_size=64 KiB; throws `std::runtime_error` on nghttp3 failure.
- `bool bind_local_streams(); bool read_stream(std::uint64_t, std::string_view data, bool fin); void add_ack_offset(std::uint64_t, std::uint64_t bytes); bool submit_request(std::uint64_t, const qb::http::Request&); bool submit_response(std::uint64_t, const qb::http::Response&); bool submit_shutdown_notice(); bool shutdown(); [[nodiscard]] bool is_drained() const noexcept;`

---

# Namespace `qb::http::ws` — WebSocket (RFC 6455) (`ws/`) · **needs `QB_HAS_SSL`**

> WebSocket is part of qbm-http (not a separate module). Include `<qbm/http/http.h>` (pulls `src/qbm/http/ws/ws.h` under `QB_HAS_SSL`).

### Messages — `src/qbm/http/ws/ws.h`
- `enum opcode : unsigned char { Continuation=0, _Text=1, _Binary=2, _Close=8, _Ping=9, _Pong=10, Text=129, Binary=130, Close=136, Ping=137, Pong=138 }` — lowercase-prefixed are bare opcodes; capitalized are FIN-set composites.
- `bool is_utf8(std::string_view) noexcept` — RFC 3629 validator (gates Text payloads and close reasons).
- `struct Message { unsigned char fin_rsv_opcode=0; bool masked=false; qb::allocator::pipe<char> _data; pipe<char>& data() noexcept; std::size_t size() const noexcept; template<typename T> Message& operator<<(T const&); void reset(); }`.
- `struct MessageText : Message` (0x81; UTF-8 on wire); `struct MessageBinary : Message` (0x82); `struct MessagePing : Message` (peer must echo); `struct MessagePong : Message`.
- `enum class CloseStatus : std::uint16_t { Normal=1000, GoingAway=1001, ProtocolError=1002, DataNotAccepted=1003, ... MessageTooBig=1009, ... TLSHandshakeFailed=1015 }` — 1004/1005/1006/1015 reserved and rejected.
- `constexpr bool is_sendable_close_code(std::uint16_t) noexcept` — true iff in [1000..4999] and not 1004/1005/1006/1015.
- `struct MessageClose : Message { MessageClose()=delete; explicit MessageClose(CloseStatus=Normal, std::string_view reason="closed normally"); explicit MessageClose(std::uint16_t status, std::string_view reason); }` — throws `std::invalid_argument` on reserved/out-of-range code; truncates reason to 123 bytes on a UTF-8 boundary.
- `std::string generateKey()` — base64 of a random 16-byte nonce for `Sec-WebSocket-Key`.
- `struct qb::http::WebSocketRequest : http::Request { WebSocketRequest()=delete; explicit WebSocketRequest(const std::string& key); }` — pre-filled upgrade GET.

### Protocol framer — `src/qbm/http/ws/ws.h`
- `template<typename IO_> class qb::protocol::ws_internal::base : public qb::io::async::AProtocol<IO_> { base()=delete; explicit base(IO_& io); void set_max_payload_size(size_t); std::size_t getMessageSize() noexcept final; void onMessage(std::size_t) noexcept final; void reset() noexcept final; using close=event_close; ping=event_ping; pong=event_pong; message=event_message; }` — shared RFC 6455 framer; masking direction, opcode/RSV/length-minimality/UTF-8 validation, fragment reassembly, auto Ping reply, auto Close echo. `set_max_payload_size(0)`=unlimited (default `protocol_limits::MAX_BODY_SIZE`; exceed → close `MessageTooBig`).
- `template<typename IO_> class qb::protocol::ws_server` — server handshake (validates GET + Upgrade/Connection + key + Version 13; emits 101 with `Sec-WebSocket-Accept`; rejects with 400 + `not_ok()`); `struct sending_http_response { qb::http::Response& response; }`.
- `template<typename IO_> class qb::protocol::ws_client` — client handshake validator (checks 101, tokens, `Sec-WebSocket-Accept` in constant time; `not_ok()` on mismatch).
- `template<typename IO_> using qb::http::ws::protocol = ...` — selects `ws_server` when `IO_::has_server` else `ws_client`.

### CRTP client — `src/qbm/http/ws/ws.h`
`template<typename T, typename Transport=qb::io::transport::tcp> class WebSocket : public qb::io::async::tcp::client<WebSocket<T,Transport>,Transport>, public qb::io::use<WebSocket<T,Transport>>::timeout`
Drives TCP connect + HTTP upgrade + protocol switch; forwards `ping/pong/message/closed/disconnected/error/connected` events to parent `T::on(...)` if present.
- `void set_ping_interval(qb::duration interval=qb::duration::zero())` — auto-ping keepalive after a verified upgrade; **zero/negative disables**.
- `void connect(const qb::io::uri& remote, qb::duration timeout=qb::duration::zero(), bool verify_peer=true)` — connect to `ws://`/`wss://`, install protocol, send upgrade. A positive timeout is one deadline across transport and Upgrade; zero disables it. An active transport is retired before reconnect, and its input/output buffers are cleared before the next handshake. A retry from a failure callback starts after the old transport's disconnect dispatch; after the peer's EOF that transport is closed already (qb-io `dispose()`), so a `connect()` from the `disconnected` callback starts in the same loop pass. The client rejects an unoffered `Sec-WebSocket-Extensions` response before `connected`.
- `void disconnect(int reason=1)` / `void disconnect(qb::io::async::event::disconnect_reason reason)` — cancel an unfinished connection and its deadline, then close the transport while forwarding the reason to qb-io's `disconnected` event. The zero-argument call remains valid through the default. An in-flight connector callback is inert after cancellation or client destruction; stack and `unique_ptr` clients are supported.
- `connected`, parsed-handshake/protocol `error`, and `disconnected` user callbacks are delivered after parser/I/O dispatch and may release the client. A transport connect failure or explicit pending `disconnect()` may report `error` synchronously. A pre-101 transport close reports `error` once. The `sending_http_request` hook remains synchronous; after it returns, a cancelled, replaced, or destroyed attempt sends no Upgrade request. Frames pipelined with the 101 are delivered after `connected`, in wire order.
- `void close(CloseStatus=Normal, std::string_view reason="closed normally")` — queue a Close frame (no TCP teardown); throws `std::invalid_argument` on reserved code; call `disconnect()` after for immediate teardown.
- `void set_subprotocols(std::vector<std::string>)` / `void add_subprotocol(std::string)` — offer list; each must be a valid RFC 7230 token (else `std::invalid_argument`); before connect.
- `std::string_view negotiated_subprotocol() const noexcept` — selected subprotocol (valid after `connected`).
- `template<typename ToSend> WebSocket& operator<<(ToSend&& msg)` — queue outbound; Message-derived values forcibly masked (client frames MUST be masked); sending `MessageClose` sets `_close_sent`.
- `template<typename T> using WebSocketSecure = WebSocket<T, qb::io::transport::stcp>` — wss flavor.

### Callback client — `src/qbm/http/ws/ws.h`
`template<typename Transport=qb::io::transport::tcp> class Client : public WebSocket<Client<Transport>,Transport>` — chainable setters (each returns `Client&`): `on_connected/on_message/on_ping/on_pong/on_closed/on_error/on_disconnected/on_sending_http_request`.
Aliases: `using ClientSecure = Client<stcp>; using client = Client<tcp>; using client_secure = Client<stcp>`.
Usage: `qb::http::ws::client c; c.on_message([](auto&&){...}).on_connected([](auto&&){...}); c.connect(qb::io::uri{"ws://h/path"});`

### Coroutine API — `src/qbm/http/ws/coro.h`
- `struct ConnectResult { bool ok{false}; }`; `struct CloseResult { bool ok{true}; }`.
- `struct IncomingFrame { enum class Kind:std::uint8_t{Message,Ping,Pong,Close,Disconnected}; Kind kind{Disconnected}; std::string payload; bool is_text{false}; std::uint16_t close_code{0}; std::string close_reason; }` — owning value safe to store past the `co_await`.
- `template<typename Transport=qb::io::transport::tcp> class coro_client : public WebSocket<coro_client<Transport>,Transport>` — coroutine-first; non-copyable/non-movable:
  - `[[nodiscard]] auto connect(const qb::io::uri& remote, qb::duration timeout=qb::duration::zero());` and `connect(std::string_view remote_uri, qb::duration timeout=qb::duration::zero())` — yields `ConnectResult`.
  - `[[nodiscard]] auto receive()` — yields next `IncomingFrame` in order; resolves immediately with `Disconnected` once gone; throws `std::logic_error` if another live awaiter is parked (one consumer). Destruction of a suspended awaiter makes its reservation inactive; later delivery uses a successor or the existing buffer policy.
  - `[[nodiscard]] auto close_async(CloseStatus=Normal, std::string_view reason="closed normally")` — yields `CloseResult`; validates the Close frame before publishing coroutine state, so reserved code/invalid UTF-8 rejection leaves a later valid close available; `std::logic_error` if another live close waiter is pending. Abandoning a waiter does not retract queued frame bytes; no complete allocation/serialization rollback guarantee.
  - `void set_pending_cap(std::size_t) noexcept` (default 1024; full→drop oldest; 0 disables buffering). A lowered cap applies at once (a queue above it is trimmed to its newest frames); 0 never purges what is buffered (`src/qbm/http/ws/coro.h:267-286`).
  - `using coro_client_secure = coro_client<qb::io::transport::stcp>`.
- `template<typename Awaitable> auto run_sync(Awaitable&&)` — drive a WS awaitable to completion on the current I/O thread (thin alias over `qb::io::async::run_sync`).
- `template<typename Self, typename Server> class coro_session : public qb::io::use<Self>::tcp::template client<Server>` — CRTP base for a server-side WS session written as a coroutine (`Self` defines `task<void> run()`); keeps the session shared_ptr alive across suspensions:
  - `bool accept_upgrade(qb::http::Request&, qb::http::Response&)` — single router integration point: apply handshake hook, `switch_protocol<WS_Protocol>`, send response, spawn `run()`. Returns false (and disconnects) on refusal/invalid handshake. Must run on the transport's I/O thread.
  - `[[nodiscard]] auto next_frame()` — yields next inbound `IncomingFrame`; after close always resolves `Disconnected`; throws `std::logic_error` if a live awaiter is already parked. A destroyed suspended awaiter releases its reservation as on the client.
  - `[[nodiscard]] auto close_async(CloseStatus=Normal, std::string_view reason="closed normally")` — server-side close; throws as above.
  - `using HandshakeHook = std::function<bool(Self&, qb::http::Request&, qb::http::Response&)>; void set_handshake_hook(HandshakeHook)` — pre-upgrade hook (negotiate subprotocol / add headers / return false to reject; a throwing hook is a rejection); before `accept_upgrade`. A refusal keeps a status ≥ 300 (redirect or error) and answers `400` for anything below, the default 200 included (`src/qbm/http/ws/coro.h:633-649`).
  - `void set_pending_cap(std::size_t) noexcept` (default 1024).
Usage (coro client): `qb::http::ws::coro_client ws; auto r = co_await ws.connect(qb::io::uri{"ws://h/p"}); auto f = co_await ws.receive();`

The `http_awaiter` returned by `receive()` / `next_frame()` / `close_async()` now has a lifetime-aware concrete deduced operation type. Keep `auto`/`co_await` at call sites and rebuild consumers sharing these template definitions consistently. Public ordinary HTTP `async::awaiter<T>` / `make_awaiter` keep their existing callback path; actor cancellation is unchanged. (`src/qbm/http/coro.h:182-218,232-259`; `src/qbm/http/ws/coro.h:431-484,886-941`.)

### WS pipe serialization — `src/qbm/http/ws/ws.h:1999`
`template<> pipe<char>& pipe<char>::put<Message>(const Message&);` (and `MessagePing/MessagePong/MessageText/MessageBinary/MessageClose/WebSocketRequest`) — frame onto the outbound pipe (masks when `msg.masked`); invoked indirectly via `operator<<`.

---

# Build / integration

- `find_package` / `qb_load_modules(...)`, link target `qbm::http`, include `<qbm/http/http.h>`.
- `http.h` pulls: `src/qbm/http/1.1/http.h` + `src/qbm/http/1.1/client.h` always; `src/qbm/http/2/http2.h` + `src/qbm/http/ws/ws.h` under `QB_HAS_SSL`; `src/qbm/http/3/http3.h` + `src/qbm/http/3/client.h` + `src/qbm/http/3/dual_stack.h` under `QBM_HTTP_HAS_HTTP3`. Both `src/qbm/http/1.1/http.h` and `src/qbm/http/1.1/client.h` include `coro.h` — which defines `async::http_awaiter` (`src/qbm/http/coro.h:162`), the `async::awaiter<T>` alias (`src/qbm/http/coro.h:232`), `async::make_awaiter` (`src/qbm/http/coro.h:247`) and `qb::http::run_sync` (`src/qbm/http/coro.h:287`) — so it always arrives with the umbrella header; you never include it directly. Middleware: include `src/qbm/http/middleware/all.h` (or individual headers / `src/qbm/http/middleware/make.h`).
- Reference qb-core / qb-io types (`qb::io::uri`, `qb::allocator::pipe<char>`, `qb::json`, `qb::duration`, `qb::wall_time`, `qb::icase_unordered_map`, `qb::unordered_map`, async client/awaiter, transports) in the qb framework Factbook — not restated here.

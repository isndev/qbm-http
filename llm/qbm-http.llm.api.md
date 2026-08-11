<!-- Verified-against: qbm-http @ qb 3.0.0. Source of truth: the headers under qbm/http/src/qbm/http/. -->
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

### `qb::http::Method` (alias `method`) — `types.h:71`
`class Method { enum class Value:int { GET, POST, DEL, ... }; constexpr Method(Value); constexpr Method(::http_method); explicit Method(std::string_view); operator ::http_method()/Value()/std::string()/std::string_view(); }`
Value-type wrapper over llhttp `http_method`; case-insensitive string ctor; **`DEL` is DELETE** (alias `DELETE_METHOD`); static constants `Method::GET`, `Method::POST`, …
Returns: a method value. Throws: nothing on enum ctors.
Usage: `qb::http::method m = qb::http::method::GET;`

### `qb::http::Status` (alias `status`) — `types.h:306`
`class Status { enum class Value:int { OK=200, NOT_FOUND=404, ... }; constexpr Status(Value); constexpr Status(::http_status); constexpr Status(int); constexpr int code() const; std::string_view str() const; operator std::string()/std::string_view()/::http_status()/Value(); }`
Value-type wrapper over llhttp `http_status`; **default-constructs to 200 OK**; `code()` returns the numeric code; static constants `Status::OK`, `Status::NOT_FOUND`, …
Returns: a status value. Throws: nothing.
Usage: `resp.status() = qb::http::status::NOT_FOUND;`

### `qb::http::DisconnectedReason` — `types.h:731`
`enum DisconnectedReason:int { ByUser=0, ByTimeout, ResponseTransmitted, ServerError, ByProtocolError, Undefined }`
Reason codes supplied on HTTP session disconnect.

### `qb::http::endl` / `sep` — `types.h:713` / `:721`
`constexpr char endl[]="\r\n"; constexpr char sep=' ';` — HTTP CRLF terminator and SP separator.

### std helpers — `types.h:748`
`template<> struct std::hash<qb::http::method>; template<> struct std::hash<qb::http::status>; std::string std::to_string(qb::http::method); std::string std::to_string(qb::http::status);`
Make method/status usable as unordered-map keys and stringifiable.

### `qb::http::internal::MessageBase` — `message_base.h:37`
`struct MessageBase : public Headers, public Body { uint16_t major_version{1}, minor_version{1}; bool upgrade{}; std::uint64_t stream_id{0}; bool keep_alive{false}; Body& body() noexcept; const Body& body() const noexcept; void reset() noexcept; }`
Common base for Request/Response; **multiply inherits Headers and Body** (so `req.set_header(...)`, `req.body()`, `resp.as<T>()` via `body()` are all directly available). `stream_id` is 0 for HTTP/1.1.

### `qb::http::Request` (alias `request`) — `request.h:36`
`class Request : public internal::MessageBase { Request() noexcept; Request(method m, qb::io::uri u, headers_map h={}, Body b={}); explicit Request(qb::io::uri u, headers_map h={}, Body b={}); const Method& method() const noexcept; Method& method() noexcept; const qb::io::uri& uri() const; const std::string& query(name, idx=0) const; std::string query_or(name, std::string fallback, idx=0) const; void parse_cookie_header(); const Cookie* cookie(name) const noexcept; bool has_cookie(name) const noexcept; const std::string& cookie_value(name) const noexcept; std::string cookie_value_or(name, std::string fallback) const; Request& with_method(Method) noexcept; Request& with_uri(uri); Request& with_header(string,string); Request& with_body(BodyType&&); void reset() noexcept; }`
Owning request: method, `qb::io::uri`, query accessors, CookieJar (populated by `parse_cookie_header()`), chainable `with_*`. Of the chainable `with_*`, only `with_method` is `noexcept`. `method()` has **both** a const and a mutating overload (`request.h:97, :101`) — `req.method() = qb::http::method::POST;` is valid. `Request{uri}` (the uri-only ctor, `request.h:83`) defaults the method to **GET** (`request.h:85`); the default ctor leaves it `UNINITIALIZED`. **Accessor model:** `query(name)` / `cookie_value(name)` return a `const std::string&` bound to a process-wide static empty string on a miss (never a temporary, always safe to keep) — for a custom fallback use the by-value `query_or(...)` / `cookie_value_or(...)` variants.
Usage: `qb::http::Request r{qb::http::method::GET, qb::io::uri{"https://h/x"}}; r.with_header("Accept","*/*");`

### `qb::http::Response` (alias `response`) — `response.h:36`
`class Response : public internal::MessageBase { Response() noexcept; Response(Status s, headers_map h={}, Body b={}); const Status& status() const noexcept; Status& status() noexcept; void parse_set_cookie_headers(); void add_cookie(const Cookie&); Cookie& add_cookie(name,value); void remove_cookie(name); void update_cookie_header(name); void update_cookie_headers(); Response& with_status(Status) noexcept; Response& with_cookie(const Cookie&); Response& with_body(BodyType&&); void reset() noexcept; }`
Owning response: default-constructs to 200 OK (`response.h:56-58`), CookieJar serialized to `Set-Cookie`. Mutating cookies directly needs `update_cookie_header(s)` to resync. Of the chainable `with_*`, only `with_status` is `noexcept`. `status()` has **both** a const and a mutating overload (`response.h:75, :79`) — `resp.status() = qb::http::status::CREATED;` is valid.
Usage: `qb::http::Response resp{qb::http::status::OK}; resp.with_body("hi");`

### `qb::http::Headers` (alias `headers`) — `headers.h:151`
`class Headers { headers_map_type& headers(); const std::string& header(name, idx=0) const; std::string header_or(name, std::string fallback, idx=0) const; bool has_header(name) const noexcept; qb::icase_unordered_map<std::string> attributes(name, idx=0, std::string_view default_to_parse="") const; void set_header(name,value); void add_header(name,value); void remove_header(name); void set_content_type(string_view); const ContentType& content_type() const; void refresh_content_type() noexcept; std::size_t header_count() const; bool exceeds_header_limit(max=100) const; }`
Case-insensitive multi-value store; typed mutators keep the cached `ContentType` in sync — call `refresh_content_type()` after raw `headers()` mutation. **Accessor model:** `header(name, idx)` returns a `const std::string&` bound to a process-wide static empty string on a miss — never a temporary, always safe to keep for the message's lifetime. For a custom fallback use the by-value `header_or(name, fallback, idx)` (no lifetime caveat). `attributes(name, ...)` parses the header value's `name=value; n2="q v"` params via `parse_header_attributes`.
`headers_map = qb::icase_unordered_map<std::vector<std::string>>` (`headers.h:52`).

### `qb::http::Headers::ContentType` — `headers.h:167`
`class ContentType { static std::pair<std::string,std::string> parse(std::string_view); explicit ContentType(std::string_view=""); const std::string& type() const; const std::string& charset() const; }`
Parses Content-Type into MIME type + charset; defaults to `application/octet-stream` / `utf-8` (never reports "no type").

### Header free functions
- `parse_header_attributes(const char*, size_t)` (+ string/string_view overloads) — `headers.h:67` — parse `name=value; n2="q v"` params. Throws `std::runtime_error` on malformed/oversized/unterminated input. Bounds: `ATTRIBUTE_NAME_MAX=1024`, `ATTRIBUTE_VALUE_MAX=8192` (`headers.h:37`).
- `std::string accept_encoding();` / `std::string content_encoding(std::string_view accept_encoding_header);` — `headers.h:97` — build `Accept-Encoding` from server capability; pick a `Content-Encoding` (no q-value weighting). Empty when compression disabled.

### `qb::http::Body` — `body.h:57`
`class Body { template<typename...A> Body(A&&...); template<typename...A> Body& operator<<(A&&...); template<typename T> Body& operator=(...); template<typename T> T as() const; template<typename T> [[nodiscard]] std::optional<T> try_as() const noexcept; Body& add_chunk(const Chunk&); Body& add_final_chunk(); pipe<char>& raw(); std::size_t size() const; bool empty() const; void clear() noexcept; }`
Backed by `qb::allocator::pipe<char>`. Append/assign constrained by `is_body_appendable` (string-like, Chunk/Multipart/Form/`qb::json`, arithmetic). The extraction set is closed: `as<T>()` / `try_as<T>()` accept only `std::string_view`, `std::string`, `qb::json`, `Multipart`, `Form` (anything else is a `static_assert`, `body.h:387`); explicit specializations of `as<T>` at `body.h:460-473`. Conversions defined in `body.cpp`.
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
`class MultipartParser { typedef void (*Callback)(const char* buffer,size_t start,size_t end,void* userData); MultipartParser(); MultipartParser(std::string boundary); void setBoundary(std::string); size_t feed(const char* buffer,size_t len); bool succeeded()/hasError()/stopped() const; const char* getErrorMessage() const; Callback onPartBegin/onHeaderField/onHeaderValue/onHeaderEnd/onHeadersEnd/onPartData/onPartEnd/onEnd; void* userData; }`
Callback-driven streaming state machine; `feed` returns bytes consumed. Limits in `multipart_limits` (`multipart.h:50`): `MAX_BOUNDARY_LENGTH=70`, `MAX_HEADER_NAME_LENGTH=1024`, `MAX_HEADER_VALUE_LENGTH=8192`, `MAX_PARTS_COUNT=1000`, `MAX_TOTAL_SIZE=100 MiB`.
- `std::string::const_iterator find_boundary(str, boundary); std::string parse_boundary(content_type);` — `multipart.h:462` — locate / extract boundary (empty if not multipart).

### `qb::http::Cookie` — `cookie.h:64`
`class Cookie { Cookie() noexcept; Cookie(const string& name,const string& value); Cookie(string&&,string&&) noexcept; const string& name()/value() const; Cookie& value(string); const std::optional<system_clock::time_point>& expires() const; Cookie& expires(tp); Cookie& expires_in(qb::duration ttl); const std::optional<int>& max_age() const; Cookie& max_age(qb::duration ttl); Cookie& domain/path(string); bool secure()/http_only() const; Cookie& secure/http_only(bool); const std::optional<SameSite>& same_site() const; Cookie& same_site(SameSite); std::string to_header() const; std::string serialize() const; }`
RFC 6265 cookie. **`max_age(qb::duration)`** stored as integer seconds; **`expires_in(qb::duration)`** computes a `system_clock` time_point; `path` defaults to `/`; `to_header()` yields a `Set-Cookie` value.
Usage: `qb::http::Cookie c{"sid","abc"}; c.http_only(true).max_age(std::chrono::hours(1));`
- `enum class SameSite { None, Lax, Strict, NOT_SET }` (`cookie.h:50`) — passing `NOT_SET` resets the optional.

### `qb::http::CookieJar` — `cookie.h:300`
`class CookieJar { void add(const Cookie&); void add(Cookie&&); Cookie& add(string name,string value); bool remove(name); void clear(); const Cookie* get(name) const; Cookie* get(name); bool has(name) const; const qb::icase_unordered_map<Cookie>& all() const; size_t size() const; bool empty() const; }`
Case-insensitive-name container; `add` replaces an existing same-name cookie. Bounds: `COOKIE_NAME_MAX=1024`, `COOKIE_VALUE_MAX=4096` (`cookie.h:33`).
- `parse_cookies(ptr,len,set_cookie)` / `parse_cookies(string_view,set_cookie)` / `std::optional<Cookie> parse_set_cookie(string_view)` — `cookie.h:438`.

### `qb::http::origin` helpers — `origin.h:32`
`bool scheme_eq(string_view,string_view) noexcept; bool host_eq(string_view,string_view) noexcept; std::string_view effective_port(const qb::io::uri&) noexcept; std::optional<std::uint32_t> effective_port_number(const qb::io::uri&) noexcept; bool same(const qb::io::uri& a, const qb::io::uri& b) noexcept;`
Same-origin comparison: case-insensitive scheme/host, scheme-default ports (http=80, https=443); `same()` requires both ports resolvable and equal.

### `qb::http::utility` — `utility.h:34` / `:258-260`
Char/string helpers: `is_char/is_control/is_special/is_digit/is_hex_digit(int)`, `hex_value(char)`, `decode_path_component(string_view)`, `constexpr char ascii_to_lower(char)`, `bool iequals(string_view,string_view)`, `is_http_whitespace`, `trim_http_whitespace`, `escape_html`, `uri_encode_component`. Splitting/joining: `split_and_trim_header_list`, `split_string<String>(...)`, `split_string_by<...>`, lazy `class split_view`, `join(vector<T>, delim)`.
Usage: `if (qb::http::utility::iequals(a,b)) ...;`

### pipe serialization — `request.h:384` / `chunk.h:106` / `multipart.h:629`
`template<> pipe<char>& pipe<char>::put<Request>(const Request&); ...<Response>; ...<Chunk>; ...<Multipart>;`
Wire-serialize into the qb pipe; Request/Response throw `std::length_error` if the message exceeds `protocol_limits`.

---

# Namespace `qb::http::date` — date/time (current API only)

> The `date` namespace deals in `std::chrono::system_clock::time_point` and **`qb::wall_time`** only. There are **no** `qb::Timestamp` overloads and **no** `to_timestamp`/`to_time_point`.

### `date.h:50`
`std::string format_http_date(std::chrono::system_clock::time_point) noexcept;`
`std::string format_cookie_date(std::chrono::system_clock::time_point) noexcept;`
Format as RFC 1123 GMT date (empty on failure); cookie variant is functionally identical.
Usage: `auto s = qb::http::date::format_http_date(std::chrono::system_clock::now());`

### `date.h:75`
`std::optional<system_clock::time_point> parse_http_date(std::string_view) noexcept;` (+ `const std::string&` overload)
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
- `void compile()` (`router.h:290`); `std::shared_ptr<Context<S>> route(std::shared_ptr<S> session, qb::http::Request)` (`router.h:302`); `std::weak_ptr<RouterCore<S>> get_router_core_weak_ptr() noexcept` (`router.h:310`); `void clear()` (`router.h:317`, requires recompile).
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
- `IAsyncTask<SessionType>` — `src/qbm/http/routing/async_task.h:44` — `virtual void execute(ctx)=0; virtual void cancel()=0; virtual std::string name() const=0;`. `execute()` must eventually call `ctx->complete()`; `cancel()` must **not**.
- `ICustomRoute<SessionType>` — `src/qbm/http/routing/custom_route.h:43` — `virtual void process(ctx)=0; std::string name() const=0; void cancel()=0;`. Adapted via `CustomRouteAdapterTask`.
- `IMiddleware<SessionType>` — `src/qbm/http/routing/middleware.h:39` — `virtual void process(ctx)=0; std::string name() const=0; void cancel()=0;`. `process()` must call `ctx->complete()` to advance.
- `MiddlewareTask<SessionType>` — `middleware.h:75` — `explicit MiddlewareTask(std::shared_ptr<IMiddleware<S>>, name="MiddlewareTask")`. Adapts IMiddleware→IAsyncTask; on exception sets 500 + ERROR. Throws `std::invalid_argument` on null.
- `FunctionalMiddleware<SessionType>` — `middleware.h:183` — `FunctionalMiddleware(MiddlewareHandlerFn, name)`. Adapts a `(ctx,next)` lambda; calling `next()` once completes CONTINUE; duplicate `next()` ignored.
- `RouteLambdaTask<S>` / `CustomRouteAdapterTask<S>` — `route.h:51, :139` — wrap a lambda handler / an ICustomRoute; thrown exceptions → 500 + ERROR; throw `std::invalid_argument` on null.

### `qb::http::Context<SessionType>` — `src/qbm/http/routing/context.h:68`
`template<typename SessionType> class Context : public std::enable_shared_from_this<Context<SessionType>>`
Per-request state; always handled as `std::shared_ptr<Context>`.
- Accessors (`context.h:439`): `Request& request() noexcept; Response& response() noexcept; std::shared_ptr<S> session() noexcept` (null if session expired); `PathParameters& path_parameters() noexcept; const std::string& path_param(std::string_view name) const` (static-empty on miss); typed `std::optional<T> path_param<T>(name)` / `T path_param_or<T>(name, fallback)`; typed query `template<typename T=std::string> std::optional<T> query_param(name)` (nullopt on empty/absent/parse-fail) / `T query_param_or<T>(name, fallback)`; `template<typename T> std::optional<T> bind() const` (body→T: `qb::json` / `std::string` / NLOHMANN model; nullopt on fail). Typed parsing goes through `static parse_value<T>(string_view) noexcept` (integral/floating via `std::from_chars` whole-string match, `bool` from `true/false/1/0`, string passthrough; `static_assert` otherwise).
- `void complete(AsyncTaskResult = COMPLETE)` (`context.h:1106`) — advance/finalize the chain. CONTINUE→next; COMPLETE/CANCELLED/ERROR/FATAL drive finalization or error chain.
- `void cancel(reason="Cancelled by application") noexcept` (`context.h:1189`) — sets 503 + completes CANCELLED.
- `void add_lifecycle_hook(LifecycleHook); void execute_hook(HookPoint)` (`context.h:626`) — hook exceptions are caught/suppressed.
- string-keyed store: `template<typename T> void set(key,T); template<typename T> std::optional<T> get(key) const; template<typename T> T* get_if(key) noexcept; bool has(key) const noexcept; bool remove(key) noexcept` — `set` `context.h:659`, `get` `:673`, `get_if` `:695` (const overload `:713`), `has` `:727`, `remove` `:747`. Backed by `qb::unordered_map<std::string,std::any>` — bad cast swallowed (returns nullopt/nullptr).
- typed-slot store (`context.h:782`): `template<typename T> void set(const Slot<T>&,T); template<typename T,typename...A> T& emplace(const Slot<T>&,A&&...); template<typename T> T* get_if(const Slot<T>&) noexcept; template<typename T,typename U=T> T get_or(const Slot<T>&,U&&) const`. `get_if` is the zero-copy hot read.
- response helpers (`context.h:930`): `void json(qb::json json_data, status=OK); void text(std::string text_data, status=OK, const std::string& content_type="text/plain; charset=utf-8"); void html(std::string html_data, status=OK); void no_content(); void redirect(const std::string& url, status=FOUND); void bad_request(...)/unauthorized(...)/forbidden(...)/not_found(...)/internal_server_error(...); Context& status(status)`. **The body sinks take their payload BY VALUE (move-sink)**; `json` sets `application/json; charset=utf-8`, `text` defaults `text/plain; charset=utf-8`, `html` `text/html; charset=utf-8`, `no_content` → 204 (clears body + CT/CL). **All except `status()` set the response and `complete(COMPLETE)`** — set headers/body first. `status()` only sets the code and is chainable.
- `void suppress_response() noexcept` (`context.h:1251`) — finalize without firing the send callback (e.g. on WebSocket upgrade).
- introspection (`context.h:1218`): `bool is_cancelled()/is_completed() const noexcept; State state() const noexcept; ProcessingPhase get_processing_phase() const noexcept; std::uint64_t completion_count() const noexcept; [[nodiscard]] ScopedFinalizationDeferral defer_finalization_scope() noexcept`.
Usage: `ctx->json(qb::json{{"ok",true}});`

### Context-scoped types — `src/qbm/http/routing/context.h:76`
`enum class ProcessingPhase{INITIAL,NORMAL_CHAIN,NOT_FOUND_CHAIN,METHOD_NOT_ALLOWED_CHAIN,ERROR_CHAIN}; enum class State:uint8_t{Ready,Running,Finalised}; using LifecycleHook = std::function<void(Context<S>&,HookPoint)>; using CustomDataMap = qb::unordered_map<std::string,std::any>;`

### `qb::http::PathParameters` — `src/qbm/http/routing/path_parameters.h:32`
`class PathParameters { void set(string_view key,string_view value); std::optional<string_view> get(string_view) const noexcept; bool has(string_view) const noexcept; ... at/find/begin/end/size/reserve }`
Keys are `string_view`s into the long-lived route pattern; values are owned decoded copies.

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
`using Validator=std::function<bool(const qb::json&,JwtErrorInfo&)>; using ErrorHandler=std::function<void(ContextPtr,const JwtErrorInfo&)>; using SuccessHandler=std::function<void(ContextPtr,const qb::json&)>`. On success stores decoded payload in context under key `"jwt_payload"`. On failure replies 401. Statics: `create(secret,algorithm="HS256")`, `create_with_options(options)`.
Factories (`jwt.h:531`): `jwt_middleware<S>(secret, algorithm="HS256")`, `jwt_middleware_with_options<S>(options)`.
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
Factories (`rate_limit.h:618`): `rate_limit_middleware<S>(options=RateLimitOptions(), name)`, `rate_limit_dev_middleware<S>(name)`, `rate_limit_secure_middleware<S>(name)`.
Usage: `router.use(qb::http::rate_limit_secure_middleware<S>());`

## Compression — `src/qbm/http/middleware/compression.h` · response/request compression gated on `QB_HAS_COMPRESSION`
### `qb::http::CompressionOptions` — `compression.h:40`
`CompressionOptions() noexcept; compress_responses(bool) noexcept; decompress_requests(bool) noexcept; min_size_to_compress(size_t) noexcept; preferred_encodings(std::vector<std::string>);` (each returns `CompressionOptions&`). Presets: `static CompressionOptions max_compression()` (min 256, `{gzip,deflate}`), `static CompressionOptions fast_compression()` (min 2048, `{deflate,gzip}`). Getters `should_compress_responses()/should_decompress_requests()/get_min_size_to_compress()/get_preferred_encodings()`.

### `qb::http::CompressionMiddleware<S>` — `compression.h:162`
`CompressionMiddleware(name); CompressionMiddleware(CompressionOptions, name); void update_options(CompressionOptions) noexcept;`
Decompresses request bodies by `Content-Encoding`; compresses responses at `HookPoint::PRE_RESPONSE_SEND` based on `Accept-Encoding`.
Factories (`compression.h:536`): `compression_middleware<S>(options=CompressionOptions(), name)`, `max_compression_middleware<S>(name)`, `fast_compression_middleware<S>(name)`.
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
Serves GET/HEAD; path-traversal hardened (canonicalised, symlink-escape rejected); supports ETag/If-None-Match, Last-Modified/If-Modified-Since, `Range`/`206`/`416`, optional directory listing. **Ctor anchors a relative `root_directory` via `qb::io::sys::resolve_resource` (cwd then exe dir), then requires it to exist and canonicalise.** Throws `std::invalid_argument` if root empty, `std::runtime_error` if root (after resolution) missing/not a directory or not canonicalisable.
Factory (`static_files.h:757`): `static_files_middleware<S>(options, name="StaticFilesMiddleware")`.
Usage: `router.use(qb::http::static_files_middleware<S>(qb::http::StaticFilesOptions{"public"}.with_path_prefix_to_strip("/static")));  // "public" found relative to cwd or the executable's dir`

## Security headers — `src/qbm/http/middleware/security_headers.h`
### `qb::http::SecurityHeadersOptions` — `security_headers.h:53`
`SecurityHeadersOptions();` Fluent (return `SecurityHeadersOptions&`): `with_hsts(value)/without_hsts(); with_x_content_type_options_nosniff(bool=true); with_x_frame_options(value)/without_x_frame_options(); with_content_security_policy(value)/without...; with_content_security_policy_report_only(value)/without...; with_referrer_policy(value)/without...; with_permissions_policy(value)/without...; with_cross_origin_opener_policy(value)/without...; with_cross_origin_embedder_policy(value)/without...; with_cross_origin_resource_policy(value)/without...; with_x_permitted_cross_domain_policies(value)/without...; with_csp_nonce(bool=true);` Preset: `static SecurityHeadersOptions secure_defaults()` (HSTS 1y, nosniff, `X-Frame-Options: SAMEORIGIN`, a default CSP, `Referrer-Policy`, COOP `same-origin`, `X-Permitted-Cross-Domain-Policies: none`).

### `qb::http::SecurityHeadersMiddleware<S>` — `security_headers.h:283`
`SecurityHeadersMiddleware(const SecurityHeadersOptions&, name); void update_options(const SecurityHeadersOptions&);`
Adds the configured security headers to every response.
Factory (`security_headers.h:408`): `security_headers_middleware<S>(options=SecurityHeadersOptions::secure_defaults(), name)`.
Usage: `router.use(qb::http::security_headers_middleware<S>());`

## reCAPTCHA — `src/qbm/http/middleware/recaptcha.h` · **needs `QB_HTTP_HAS_RECAPTCHA_MIDDLEWARE`**
### `qb::http::RecaptchaOptions` — `recaptcha.h:58`
`RecaptchaOptions()=default; explicit RecaptchaOptions(std::string secret_key);` Fluent: `min_score(float) noexcept; challenge_type(ChallengeType) noexcept; from_header(...) / from_body(...) / from_query(...);` `enum class TokenLocation{Header,Body,Query}; enum class ChallengeType{V2,V3,Auto};` Presets: `static RecaptchaOptions v3(secret, min_score=0.5f); v2(secret); strict(secret)`. Getters `get_min_score()/get_token_location()/get_challenge_type()`. `struct RecaptchaResult` carries `score`, `challenge_ts` (`std::chrono::system_clock::time_point`), etc.

### `qb::http::RecaptchaMiddleware<S>` — `recaptcha.h:264`
`using VerificationCallback=std::function<void(qb::http::async::Reply&&)>; using VerificationClient=std::function<void(qb::http::Request, VerificationCallback)>; explicit RecaptchaMiddleware(RecaptchaOptions, name); RecaptchaMiddleware(const std::string& secret, float min_score=0.5f, name);` Statics `v3(secret,min_score=0.5f,name)`, `strict(secret,name)`. Verifies the token against Google (async); rejects below `min_score`.
Factories (`recaptcha.h:584`): `recaptcha_middleware<S>(RecaptchaOptions, name)`, `recaptcha_middleware<S>(secret, min_score=0.5f, name)`, `recaptcha_v3_middleware<S>(secret, min_score=0.5f, name)`, `recaptcha_strict_middleware<S>(secret, name)`. All throw `std::invalid_argument` on empty secret.

## Logging — `src/qbm/http/middleware/logging.h`
### `qb::http::LoggingMiddleware<S>` — `logging.h:52`
`enum class LogLevel{Debug,Info,Warning,Error}; using LogFunction=std::function<void(LogLevel,const std::string&)>; LoggingMiddleware(LogFunction log_fn, LogLevel req_level=Info, LogLevel res_level=Debug, std::string name="LoggingMiddleware") noexcept(false);` Throws `std::invalid_argument` if `log_fn` is null. Logs request on entry and response via a hook.
Factory (`logging.h:213`): `logging_middleware<S>(log_fn, request_level=Info, response_level=Debug, name)`.
Usage: `router.use(qb::http::logging_middleware<S>([](auto lvl,auto&m){ /*...*/ }));`

## Error handling — `src/qbm/http/middleware/error_handling.h`
### `qb::http::ErrorHandlingMiddleware<S>` — `error_handling.h:54`
`using ErrorHandler=std::function<void(ContextPtr,const std::string&)>; using StatusHandler=std::function<void(ContextPtr)>; explicit ErrorHandlingMiddleware(std::string name="ErrorHandlingMiddleware") noexcept;` Fluent (return `ErrorHandlingMiddleware&`): `on_status(qb::http::status, StatusHandler); on_status_range(min_status, max_status, StatusHandler); on_any_error(ErrorHandler);` Centralises error-to-response translation; typically set as the error task chain or a global middleware.
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
Factory (`conditional.h:147`): `conditional_middleware<S>(predicate, if_middleware, else_middleware=nullptr, name)`.

## Validation (middleware) — `src/qbm/http/middleware/validation.h`
### `qb::http::ValidationMiddleware<S>` — `middleware/validation.h:45`
`explicit ValidationMiddleware(std::shared_ptr<qb::http::validation::RequestValidator> validator, std::string name="ValidationMiddleware");` Throws `std::invalid_argument` if validator is null. Runs the `RequestValidator` (sanitize then validate); on failure replies with a JSON error body.
Factory (`src/qbm/http/middleware/validation.h:141`): `validation_middleware<S>(validator, name)`.
Usage: `router.use(qb::http::validation_middleware<S>(my_request_validator));`

## Generic builder — `src/qbm/http/middleware/make.h`
`template<typename Tag, typename SessionType, typename... Args> [[nodiscard]] auto make(Args&&... args);` — namespace `qb::http::middleware`.
Tag-dispatches to the right factory. Tags (namespace `qb::http::middleware::tags`): `auth, jwt_auth, role_auth, optional_auth, cors, cors_dev, cors_secure, compression, compression_fast, compression_max, logging, timing, rate_limit, rate_limit_dev, rate_limit_secure, security_headers, static_files, transform, conditional, error_handling, jwt, recaptcha, recaptcha_v3, recaptcha_strict`. Include `src/qbm/http/middleware/all.h` for everything (or `make.h`).
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

### `qb::http::validation::Error` — `src/qbm/http/validation/error.h:28`
`struct Error { std::string field_path, rule_violated, message; std::optional<qb::json> offending_value; Error(path, rule, msg, value=std::nullopt); }`

### `qb::http::validation::Result` — `src/qbm/http/validation/error.h:59`
`class Result { enum class ErrorValuePolicy{Full,Preview,None}; Result& set_error_value_policy(ErrorValuePolicy, std::size_t preview_bytes=256) noexcept; bool success() const; const std::vector<Error>& errors() const; void add_error(path,rule,msg,value=std::nullopt); void add_error(Error); void clear(); void merge(const Result&); Result make_child() const; }`
`success() == errors().empty()`; `preview_bytes` clamped to `[16, 64*1024]`.

### Rules — `src/qbm/http/validation/rule.h`
- `enum class DataType{STRING,INTEGER,NUMBER,BOOLEAN,OBJECT,ARRAY,NUL,ANY}` (`rule.h:31`).
- `class IRule { virtual bool validate(const qb::json&, const std::string& field_path, Result&) const=0; virtual std::string rule_name() const=0; }` (`rule.h:38`).
- `TypeRule(DataType)` (+ `static std::string data_type_to_string(DataType) noexcept`), `RequiredRule`, `MinLengthRule(size_t)`, `MaxLengthRule(size_t)`, `PatternRule(std::string)` (ctor throws `std::invalid_argument` on >1024-char/invalid), `MinimumRule(double,exclusive=false)`, `MaximumRule(double,exclusive=false)`, `EnumRule(qb::json)` (ctor throws if not array), `UniqueItemsRule`, `MinItemsRule(size_t)`, `MaxItemsRule(size_t)`, `MinPropertiesRule(size_t)`, `MaxPropertiesRule(size_t)`, `PropertyNamesRule(const qb::json&)`, `ItemsRule(ItemsRuleLogic, additional_items_policy=true)`, `CustomRule(CustomValidateFn, std::string rule_name)`.
- `using ItemsRuleLogic=std::variant<std::shared_ptr<SchemaValidator>, std::vector<std::shared_ptr<SchemaValidator>>>` (`rule.h:358`); `using CustomValidateFn=std::function<bool(const qb::json&,const std::string&,Result&)>` (`rule.h:388`).

### `qb::http::validation::SchemaValidator` — `src/qbm/http/validation/schema_validator.h:33`
`explicit SchemaValidator(const qb::json& schema);` (throws `std::invalid_argument` if not an object) `bool validate(const qb::json& data, Result&) const; SchemaValidator& set_error_value_policy(ErrorValuePolicy, preview_bytes=256) noexcept; std::optional<qb::json> make_offending_value(const qb::json&) const;` `enum class ErrorValuePolicy{Full,Preview,None}`.
Usage: `qb::http::validation::SchemaValidator v{schema}; qb::http::validation::Result r; v.validate(data, r);`

### Parameters — `src/qbm/http/validation/parameter_validator.h`
- `struct ParameterRuleSet { std::string name; DataType expected_type=STRING; bool required=false; std::optional<std::string> default_value; std::vector<std::shared_ptr<IRule>> rules; std::function<qb::json(const std::string&,bool&)> custom_parser; }` + fluent `set_type/set_required/set_default/add_rule/set_custom_parser` (`parameter_validator.h:35`).
- `class ParameterValidator { explicit ParameterValidator(bool strict_mode=false); void add_param(ParameterRuleSet); bool validate(const qb::icase_unordered_map<std::string>& params, Result&, const std::string& source_name) const; qb::json validate_single(name, const std::optional<std::string>& value, const ParameterRuleSet&, Result&, source_name) const; const qb::icase_unordered_map<ParameterRuleSet>& get_param_definitions() const; void set_strict_mode(bool); bool is_strict_mode() const; }` (`parameter_validator.h:115`).

### Sanitizers — `src/qbm/http/validation/sanitizer.h`
- `using SanitizerFunction=std::function<std::string(const std::string&)>` (`sanitizer.h:26`).
- `class Sanitizer { void add_rule(const std::string& field_path, SanitizerFunction); void sanitize(qb::json&) const; }` (`sanitizer.h:35`) — `[N]`=index, `[*]`=all array elements; only string nodes modified.
- `namespace PredefinedSanitizers`: `trim()`, `to_lower_case()`, `to_upper_case()`, `escape_html()`, `strip_html_tags()` (not XSS-safe), `alphanumeric_only()`, `normalize_whitespace()`, `escape_sql_like()` (not general SQLi prevention) — all `SanitizerFunction` (`sanitizer.h:68`).

### `qb::http::validation::RequestValidator` — `src/qbm/http/validation/request_validator.h:34`
`class RequestValidator { RequestValidator& for_body(const qb::json& schema); for_query_param(name, ParameterRuleSet); for_header(name, ParameterRuleSet); for_path_param(name, ParameterRuleSet) /*strict*/; add_body_sanitizer(field_path, SanitizerFunction); add_query_param_sanitizer(name, SanitizerFunction); add_header_sanitizer(name, SanitizerFunction); bool validate(qb::http::Request&, Result&, const qb::http::PathParameters* =nullptr); RequestValidator& set_error_value_policy(Result::ErrorValuePolicy, preview_bytes=256) noexcept; }`
Composes body-schema + query/header/path validators + sanitizers. `validate()` mutates the request (sanitizers run first), merges errors, returns true if fully valid. `for_body` may throw if schema not an object.
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
- `std::string host_header_value(const qb::io::uri&)` — Host header value (brackets IPv6, omits default ports).
- `template<typename Awaitable> auto run_sync(Awaitable&&)` — `coro.h:201` — drive any qbm-http awaitable to completion on the current I/O thread; a thin re-export of `qb::io::async::run_sync` so callers need not reach into `qb::io`. This is the **non-ws** `qb::http::run_sync`; `qb::http::ws::run_sync` (`src/qbm/http/ws/coro.h:486`) is the WebSocket-side alias of the same primitive. Use it from `main()`/tests, never from inside a coroutine already being driven.
  Usage: `auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{"http://localhost:8080/"}}));`
- **`qb::duration::zero()` means "no timeout"**, not an immediate timeout.
Usage (coro): `auto reply = co_await qb::http::GET(qb::http::Request{qb::http::method::GET, qb::io::uri{"https://h/x"}});`

### Persistent client — `qb::http1::Client` (alias `client`) — `src/qbm/http/1.1/client.h`
`class Client : public std::enable_shared_from_this<Client>` — same-origin keep-alive client; **non-copyable, must live in a `shared_ptr`**.
- `explicit Client(const std::string& base_uri); explicit Client(const qb::io::uri&);` — throws `std::invalid_argument` on non-http(s) scheme / missing host (http-only when `QB_HAS_SSL` off).
- `bool connect(ConnectionCallback);` and `[[nodiscard]] async::awaiter<ConnectResult> connect();` — `ConnectionCallback = void(bool connected, const std::string& error)`.
- `void disconnect();` — fails active + pending with SERVICE_UNAVAILABLE.
- `bool push_request(Request, ResponseCallback);` and `[[nodiscard]] async::awaiter<Response> push_request(Request);` — `ResponseCallback=void(Response)`; callback form returns false if callback null or pending limit reached.
- `bool push_requests(std::vector<Request>, BatchResponseCallback);` and `[[nodiscard]] async::awaiter<std::vector<Response>> push_requests(std::vector<Request>);` — `BatchResponseCallback=void(std::vector<Response>)`, responses index-aligned.
- `void set_connect_timeout(qb::duration) noexcept` (default 30s); `set_request_timeout(qb::duration)` (default 60s); `set_auto_reconnect(bool)`; `set_max_pending_requests(...)` (default 1024); `void set_verify_peer(bool) noexcept` (default true, before connect) + `bool verify_peer() const noexcept`.
- `std::tuple<uint64_t,uint64_t,uint64_t> get_stats() const noexcept` = {total, successful, failed}; `bool is_connected()/is_connecting() const noexcept`; `get_active_request_count()`; `get_base_uri()`.
- `struct ConnectResult { bool ok{false}; std::string error_message; explicit operator bool() const noexcept; }`; aliases `ResponseCallback/BatchResponseCallback/ConnectionCallback`.
- `std::shared_ptr<Client> qb::http1::make_client(const std::string& base_uri);` / `make_client(const qb::io::uri&);` — required ownership form.
Usage: `auto c = qb::http1::make_client("https://h"); co_await c->connect(); auto resp = co_await c->push_request(req);`

### HTTP/1.1 protocol/parser — `1.1/protocol/*`
- `template<typename MessageType> struct Parser : public http_t` (`base.h`) — llhttp incremental parser; `parse(buffer,size)->http_errno_t`, `reset()`, `resume()`, `get_parsed_message()`, `headers_completed()`.
- `template<typename IO_Handler,typename Trait> class base` (`base.h`) — `AProtocol`; `getMessageSize()` does Content-Length + chunked framing.
- `template<typename IO_Handler> class server` (`server.h`) / `client` (`client.h`) — parse Cookie / Set-Cookie (exceptions contained) and dispatch via `_io.on(...)`.
- `template<typename IO_Handler> using qb::http::protocol = ...` — selects server vs client by `IO_Handler::has_server`.

---

# Namespace `qb::http2` — HTTP/2 (`2/`) · **needs `QB_HAS_SSL`**

### Constants — `src/qbm/http/2/http2.h`
`namespace constants`: `DEFAULT_SESSION_TIMEOUT = std::chrono::seconds(60)` (qb::duration), `DEFAULT_MAX_CONCURRENT_STREAMS = 50`, `STREAM_IDLE_TIMEOUT = std::chrono::seconds(30)`, `STREAM_INCOMPLETE_TIMEOUT = std::chrono::seconds(10)`, `CLEANUP_INTERVAL = std::chrono::seconds(5)` (all `qb::duration`).

### Server
- `class DefaultSession : public qb::http2::use<DefaultSession>::session<Server<DefaultSession>>` (`http2.h:540`).
- `template<typename SessionType=DefaultSession> class Server : public internal::server<Server<SessionType>,SessionType>` — `Router& router()` (`http2.h:564`).
- `template<typename Session=DefaultSession> std::unique_ptr<Server<Session>> make_server();` (`http2.h:604`).
- `internal::server::listen(qb::io::uri, std::filesystem::path cert, std::filesystem::path key) -> bool` — ALPN `{h2, http/1.1}` (`http2.h:500`).
- `internal::session`: `[[nodiscard]] bool reset_stream(uint32_t stream_id, ErrorCode=CANCEL, const std::string& reason={})`; `auto& operator<<(qb::http::Response&)` (validates stream_id>0 + status 100..599); `Router& router()`.
- `template<typename Derived> struct use { ... session/io_handler/server ... }` (`http2.h:516-526`).
Usage: `auto s = qb::http2::make_server(); s->router().get("/", h); s->router().compile(); s->listen(uri,"cert.pem","key.pem");`

### `qb::http2::Client` (alias `client`) — `src/qbm/http/2/client.h:155`
`class Client : public std::enable_shared_from_this<Client>, public qb::io::async::tcp::client<Client,qb::io::transport::stcp>, public qb::io::use<Client>::timeout` — TLS+ALPN-h2 only; **non-copyable, non-movable**; via `make_client`/`shared_ptr`.
- `explicit Client(const std::string& base_uri); explicit Client(const qb::io::uri&);`
- `bool connect(ConnectionCallback)` (pass `nullptr` for fire-and-forget; no default arg) / `[[nodiscard]] async::awaiter<ConnectResult> connect();`
- `void disconnect(); bool is_connected()/is_connecting() const noexcept` (connected = TCP + h2 handshake).
- `bool push_request(Request, ResponseCallback)` / `[[nodiscard]] async::awaiter<Response> push_request(Request)` (lazy connect). Past the pending cap both **reject with `503 Service Unavailable`** (DoS guard, matches http1/http3).
- `bool push_requests(std::vector<Request>, BatchResponseCallback)` / `[[nodiscard]] async::awaiter<std::vector<Response>> push_requests(std::vector<Request>)` (separate streams, request order).
- `void set_connect_timeout(qb::duration)` (default 30s); `set_request_timeout(qb::duration)` (default 60s); `void set_max_concurrent_streams(size_t)` (default 100); `void set_max_pending_requests(size_t) noexcept` (default 1024; bound on outstanding pending+active requests, 503 over-limit); `set_auto_reconnect(bool)` (default true); `void set_verify_peer(bool) noexcept` (default true) + `bool verify_peer() const noexcept`.
- `std::tuple<uint64_t,uint64_t,uint64_t> get_stats() const noexcept`; `get_active_request_count()`; `get_base_uri()`.
- `struct ConnectResult { bool ok{false}; std::string error_message; explicit operator bool() const noexcept; }`; aliases `ResponseCallback/BatchResponseCallback/ConnectionCallback`.
- `std::shared_ptr<Client> qb::http2::make_client(const std::string&);` / `make_client(const qb::io::uri&);`
Usage: `auto c = qb::http2::make_client("https://h"); auto resp = co_await c->push_request(req);`

### HPACK (RFC 7541) — `src/qbm/http/2/protocol/hpack.h`
- `class Encoder { bool encode(const std::vector<HeaderField>&, std::vector<uint8_t>&); void set_peer_max_dynamic_table_size(uint32_t); void set_max_capacity(uint32_t); void reset(); }` — value-owned; sensitive & pseudo headers never indexed.
- `class Decoder { bool decode(const std::vector<uint8_t>&, std::vector<HeaderField>&, bool& out_is_possibly_incomplete); void set_max_dynamic_table_size(uint32_t); void set_max_header_list_size(uint32_t); void reset(); }` — false on protocol errors.
- `class DynamicTable { struct AddResult{bool added; std::size_t evicted;}; AddResult add(string,string); std::size_t set_max_byte_size(std::size_t); operator[](size_t); }` — ring buffer, newest-first, non-copyable/movable.
- `struct HeaderField { std::string name,value; bool sensitive=false; std::size_t hpack_size() const; bool is_pseudo_header() const; bool is_sensitive_by_default() const noexcept; }`.
- `namespace static_table`: `find_name_match(string_view)`, `find_exact_match(string_view,string_view)`, `get_entry(size_t)`, `is_valid_index(size_t)`; `constexpr std::array<...,61> STATIC_TABLE`.
- `enum class HpackError{SUCCESS,INVALID_INDEX,INTEGER_OVERFLOW,INSUFFICIENT_DATA,INVALID_INSTRUCTION,TABLE_SIZE_EXCEEDED,HEADER_LIST_SIZE_EXCEEDED,HUFFMAN_DECODE_ERROR,UNKNOWN_ERROR}`; `enum class InstructionType:uint8_t{...}`.
- `namespace convenience`: `encode_headers(vector<HeaderField>) -> vector<uint8_t>`; `decode_headers(vector<uint8_t>) -> std::optional<vector<HeaderField>>`; `make_header(string,string) -> HeaderField`.

### Streams + frame handlers — `src/qbm/http/2/protocol/stream.h`, `src/qbm/http/2/protocol/server.h`
- `enum class Http2StreamConcreteState{IDLE,OPEN,RESERVED_LOCAL,RESERVED_REMOTE,HALF_CLOSED_LOCAL,HALF_CLOSED_REMOTE,CLOSED}`.
- `class Http2StreamBase { uint32_t id; Http2StreamConcreteState state; int64_t local_window_size,peer_window_size; bool is_closed()/can_send_data()/can_receive_data(); void transition_state(bool,bool); void mark_reset(ErrorCode,bool); }`; `struct Http2ClientStream : Http2StreamBase {...}`; `struct Http2ServerStream : Http2StreamBase {...}`.
- `class FlowControlManager { static int64_t update_window_safe(int64_t,uint32_t,int64_t) /*-1 on overflow*/; static bool should_send_window_update(uint32_t,uint32_t); static uint32_t calculate_window_threshold(int64_t,int divisor=2); }`.
- `template<typename StreamType> class StreamManager { struct CleanupCriteria{ qb::duration max_idle_time, max_age; bool cleanup_closed_streams, cleanup_reset_streams; uint32_t max_total_streams; }; std::size_t cleanup_streams(const CleanupCriteria&); StreamStats get_statistics() const; }` — **timeouts are `qb::duration`** (0 = no limit).
- events: `struct Http2StreamErrorEvent{uint32_t stream_id; ErrorCode; std::string message;}`, `Http2GoAwayEvent{ErrorCode; uint32_t last_stream_id; std::string debug_data;}`, `Http2PushPromiseEvent{uint32_t associated/promised_stream_id; qb::http::Headers headers;}`, `Http2ConnectionErrorEvent{ErrorCode; std::string message; bool fatal;}`.
- `template<typename IO_Handler> class ServerHttp2Protocol` (`src/qbm/http/2/protocol/server.h:77`) — non-copyable/non-movable:
  - `bool send_response(uint32_t stream_id, const qb::http::Response&)`;
  - `[[nodiscard]] std::optional<PushPromiseFailureReason> send_push_promise(uint32_t associated, uint32_t promised /*even, non-zero*/, qb::http::Request pseudo_headers)` (needs peer `SETTINGS_ENABLE_PUSH=1`);
  - `void send_rst_stream(uint32_t, ErrorCode, const std::string& msg="", bool close_context=true) noexcept`;
  - `uint32_t cleanup_idle_streams(qb::duration max_idle=std::chrono::seconds(30), qb::duration max_incomplete=std::chrono::seconds(10)) noexcept`;
  - `[[nodiscard]] bool is_stream_closed(uint32_t) const`; `static bool is_valid_header_field(const std::string& name, const std::string& value) noexcept`.
- `template<typename IO_Handler> using client_protocol/server_protocol = ClientHttp2Protocol/ServerHttp2Protocol<IO_Handler>` (`http2.h:71-75`).
- `bool qb::http::well_known::is_hop_by_hop(const std::string& header_name)` (`src/qbm/http/2/protocol/server.h:52`) — classifies hop-by-hop headers (forbidden in HTTP/2).

---

# Namespace `qb::http3` — HTTP/3 / QUIC (`3/`) · **needs `QBM_HTTP_HAS_HTTP3`**

### `qb::http3::Client` (alias `client`) — `src/qbm/http/3/client.h:108`
`class Client : public std::enable_shared_from_this<Client>, public qb::io::async::quic::endpoint` — persistent same-origin client; **heap-owned via `shared_ptr`**.
- `explicit Client(const std::string& base_uri); explicit Client(const qb::io::uri&);` — throws `std::invalid_argument` unless scheme is https.
- `bool connect(ConnectionCallback)` (ALPN `{"h3"}`) / `[[nodiscard]] async::awaiter<ConnectResult> connect();`
- `void disconnect(); [[nodiscard]] bool is_connected() const noexcept` (QUIC + h3 ready).
- `bool push_request(Request, ResponseCallback)` (auto-connects; false if callback null) / `[[nodiscard]] async::awaiter<Response> push_request(Request)`.
- `[[nodiscard]] request_id push_request_with_id(Request, ResponseCallback)` (`request_id=std::uint64_t`; 0 on immediate failure); `bool cancel_request(request_id id, const std::string& reason="HTTP/3 request cancelled")` (resets active stream with H3 error 0x010c = `NGHTTP3_H3_REQUEST_CANCELLED`; false if id unknown).
- `bool push_requests(std::vector<Request>, BatchResponseCallback)` / `[[nodiscard]] async::awaiter<std::vector<Response>> push_requests(std::vector<Request>)` (index-aligned; empty input → `callback({})`).
- `void set_max_concurrent_streams(std::size_t) noexcept` (default 100); `void set_max_body_size(std::size_t) noexcept` (default 64 MiB, exceed resets stream); `void set_connect_timeout(qb::duration) noexcept` (default 30s, ≤0 disables); `void set_request_timeout(qb::duration) noexcept` (default 60s, ≤0 disables); `void set_auto_reconnect(bool) noexcept` (default true); `void set_verify_peer(bool) noexcept` (default true).
- `std::tuple<uint64_t,uint64_t,uint64_t> get_stats() const noexcept`; `get_active_request_count()`; `max_http3_body_size()`; `get_base_uri()`.
- `struct ConnectResult { bool ok{false}; std::string error_message; explicit operator bool() const noexcept; }`; aliases `ResponseCallback/BatchResponseCallback/ConnectionCallback/request_id`.
- `std::shared_ptr<Client> qb::http3::make_client(const std::string&);` / `make_client(const qb::io::uri&);`
Usage: `auto c = qb::http3::make_client("https://h"); auto resp = co_await c->push_request(req);`

### Server — `src/qbm/http/3/http3.h`
- `class DefaultSession : public qb::http3::use<DefaultSession>::session<Server<DefaultSession>>` (`http3.h:720`).
- `template<typename SessionType=DefaultSession> class Server : public internal::server<Server<SessionType>,SessionType>` (`http3.h:733`); `template<typename Session=DefaultSession> std::unique_ptr<Server<Session>> make_server();` (`http3.h:746`); alias `template<...> using server = Server<Session>`.
- `internal::server::listen(const qb::io::uri&, const std::filesystem::path& cert, const std::filesystem::path& key) -> bool` (ALPN `{"h3"}`; also a `std::string`-uri overload) (`http3.h:477`); `[[nodiscard]] Router& router() noexcept` (`http3.h:445`); `void set_max_body_size(std::size_t) noexcept` (`http3.h:458`); `void graceful_shutdown()` (`http3.h:501`).
- `internal::session`: per-stream server session; `operator<<(Response&)` (HEAD-aware) (`http3.h:221`).
- `template<typename Derived> struct use { ... session/server ... }` (`http3.h:704`).

### Dual-stack (HTTP/2 + HTTP/3) — `src/qbm/http/3/dual_stack.h` · **namespace `qb::http`** (not `qb::http3`)
- `template<typename Http2Session=qb::http2::DefaultSession, typename Http3Session=qb::http3::DefaultSession> class qb::http::dual_stack_server` (`dual_stack.h:47`) — runs HTTP/2 (TCP+TLS) and HTTP/3 (QUIC) side by side; `router()` returns a `router_facade` registering each route on **both** tables.
- `class router_facade { add_route/get/post/put/del/patch/options/head(...); compile(); }`.
- `bool listen(qb::io::uri tcp_tls_uri, qb::io::uri quic_uri, const std::filesystem::path& cert, const std::filesystem::path& key)` (also a `std::string`-uri overload) — true only if both bind; **all-or-nothing** (rolls back the side that came up and returns false if the other fails) (`dual_stack.h:263-264`).
- `template<...> std::unique_ptr<dual_stack_server<...>> qb::http::make_dual_stack_server();` (`dual_stack.h:341`).
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
- `void set_ping_interval(qb::duration interval=qb::duration::zero())` — auto-ping keepalive; **zero/negative disables**.
- `void connect(const qb::io::uri& remote, qb::duration timeout=qb::duration::zero(), bool verify_peer=true)` — connect to `ws://`/`wss://`, install protocol, send upgrade.
- `void close(CloseStatus=Normal, std::string_view reason="closed normally")` — queue a Close frame (no TCP teardown); throws `std::invalid_argument` on reserved code; call `disconnect()` after for immediate teardown.
- `void set_subprotocols(std::vector<std::string>)` / `void add_subprotocol(std::string)` — offer list; each must be a valid RFC 7230 token (else `std::invalid_argument`); before connect.
- `std::string_view negotiated_subprotocol() const noexcept` — selected subprotocol (valid after `connected`).
- `template<typename ToSend> WebSocket& operator<<(ToSend&& msg)` — queue outbound; Message-derived values forcibly masked (client frames MUST be masked); sending `MessageClose` sets `_close_sent`.
- `template<typename T> using WebSocketSecure = WebSocket<T, qb::io::transport::stcp>` — wss flavor.

### Callback client — `src/qbm/http/ws/ws.h`
`template<typename Transport=qb::io::transport::tcp> class Client : public WebSocket<Client<Transport>,Transport>` — chainable setters (each returns `Client&`): `on_connected/on_message/on_ping/on_pong/on_closed/on_error/on_disconnected/on_sending_http_request`.
Aliases: `using ClientSecure = Client<stcp>; using client = Client<tcp>; using client_secure = Client<stcp>`.
Usage: `qb::http::ws::client c; c.on_message([](auto&&){...}).on_connected([]{...}); c.connect(qb::io::uri{"ws://h/path"});`

### Coroutine API — `src/qbm/http/ws/coro.h`
- `struct ConnectResult { bool ok{false}; }`; `struct CloseResult { bool ok{true}; }`.
- `struct IncomingFrame { enum class Kind:std::uint8_t{Message,Ping,Pong,Close,Disconnected}; Kind kind{Disconnected}; std::string payload; bool is_text{false}; std::uint16_t close_code{0}; std::string close_reason; }` — owning value safe to store past the `co_await`.
- `template<typename Transport=qb::io::transport::tcp> class coro_client : public WebSocket<coro_client<Transport>,Transport>` — coroutine-first; non-copyable/non-movable:
  - `[[nodiscard]] auto connect(const qb::io::uri& remote, qb::duration timeout=qb::duration::zero());` and `connect(std::string_view remote_uri, qb::duration timeout=qb::duration::zero())` — yields `ConnectResult`.
  - `[[nodiscard]] auto receive()` — yields next `IncomingFrame` in order; resolves immediately with `Disconnected` once gone; throws `std::logic_error` if another awaiter is parked (one consumer).
  - `[[nodiscard]] auto close_async(CloseStatus=Normal, std::string_view reason="closed normally")` — yields `CloseResult`; throws `std::invalid_argument` on reserved code, `std::logic_error` if a close awaiter is pending.
  - `void set_pending_cap(std::size_t) noexcept` (default 1024; full→drop oldest; 0 disables buffering).
  - `using coro_client_secure = coro_client<qb::io::transport::stcp>`.
- `template<typename Awaitable> auto run_sync(Awaitable&&)` — drive a WS awaitable to completion on the current I/O thread (thin alias over `qb::io::async::run_sync`).
- `template<typename Self, typename Server> class coro_session : public qb::io::use<Self>::tcp::template client<Server>` — CRTP base for a server-side WS session written as a coroutine (`Self` defines `task<void> run()`); keeps the session shared_ptr alive across suspensions:
  - `bool accept_upgrade(qb::http::Request&, qb::http::Response&)` — single router integration point: apply handshake hook, `switch_protocol<WS_Protocol>`, send response, spawn `run()`. Returns false (and disconnects) on refusal/invalid handshake. Must run on the transport's I/O thread.
  - `[[nodiscard]] auto next_frame()` — yields next inbound `IncomingFrame`; after close always resolves `Disconnected`; throws `std::logic_error` if an awaiter is already parked.
  - `[[nodiscard]] auto close_async(CloseStatus=Normal, std::string_view reason="closed normally")` — server-side close; throws as above.
  - `using HandshakeHook = std::function<bool(Self&, qb::http::Request&, qb::http::Response&)>; void set_handshake_hook(HandshakeHook)` — pre-upgrade hook (negotiate subprotocol / add headers / return false to reject; a throwing hook is a rejection); before `accept_upgrade`.
  - `void set_pending_cap(std::size_t) noexcept` (default 1024).
Usage (coro client): `qb::http::ws::coro_client ws; auto r = co_await ws.connect(qb::io::uri{"ws://h/p"}); auto f = co_await ws.receive();`

### WS pipe serialization — `src/qbm/http/ws/ws.h:1717`
`template<> pipe<char>& pipe<char>::put<Message>(const Message&);` (and `MessagePing/MessagePong/MessageText/MessageBinary/MessageClose/WebSocketRequest`) — frame onto the outbound pipe (masks when `msg.masked`); invoked indirectly via `operator<<`.

---

# Build / integration

- `find_package` / `qb_load_modules(...)`, link target `qbm::http`, include `<qbm/http/http.h>`.
- `http.h` pulls: `src/qbm/http/1.1/http.h` + `src/qbm/http/1.1/client.h` always; `src/qbm/http/2/http2.h` + `src/qbm/http/ws/ws.h` under `QB_HAS_SSL`; `src/qbm/http/3/http3.h` + `src/qbm/http/3/client.h` + `src/qbm/http/3/dual_stack.h` under `QBM_HTTP_HAS_HTTP3`. Both `src/qbm/http/1.1/http.h` and `src/qbm/http/1.1/client.h` include `coro.h` — which defines `async::http_awaiter` (`coro.h:94`), the `async::awaiter<T>` alias (`coro.h:159`), `async::make_awaiter` (`coro.h:174`) and `qb::http::run_sync` (`coro.h:201`) — so it always arrives with the umbrella header; you never include it directly. Middleware: include `src/qbm/http/middleware/all.h` (or individual headers / `src/qbm/http/middleware/make.h`).
- Reference qb-core / qb-io types (`qb::io::uri`, `qb::allocator::pipe<char>`, `qb::json`, `qb::duration`, `qb::wall_time`, `qb::icase_unordered_map`, `qb::unordered_map`, async client/awaiter, transports) in the qb framework Factbook — not restated here.

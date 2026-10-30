# Changelog

All notable changes to the qbm-http module are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the module tracks the qb framework's
[Semantic Versioning](https://semver.org/). Framework-wide policy is in the qb
[VERSIONING](https://github.com/isndev/qb/blob/main/VERSIONING.md) document.

## [Unreleased]

### Added

- **Cross-site request forgery protection: `qb::http::CsrfMiddleware` and `qb::http::CsrfOptions` (Huly QB-95).** The
  module had none: a browser attaches a site's cookies to every request sent to it, whichever page sent it, and every
  application authenticated by a cookie had to build its own defence. `router().use(qb::http::csrf_middleware<S>())`
  refuses an unsafe request another site's page made the browser send, with no token and no client code: `GET`, `HEAD`
  and `OPTIONS` pass; otherwise `Sec-Fetch-Site` decides when the browser sends it (`same-origin` and `none` pass,
  `same-site`, `cross-site` and any other value are refused), else `Origin` must name the request's own host and port
  -- the `Host` field, or the authority of a target that carries a scheme (HTTP/2 and HTTP/3 rebuild it from `:scheme`
  and `:authority`, or the `host` field that stands for it; an absolute-form HTTP/1.1 target), never the `//host` of
  an origin-form path -- compared case-insensitively on its effective port, and over a TLS connection with the `https`
  scheme (behind a TLS-terminating proxy the scheme is not compared, as in Go, and HSTS covers it); a request with
  neither header passes, since every browser sends one of them on an unsafe request. That is the algorithm of Go
  1.25's `net/http.CrossOriginProtection` and the current OWASP recommendation. Opt in to a second layer with
  `CsrfOptions::tokens(secret)` (at least 32 bytes; `QB_HAS_SSL`; wiped before it is released or replaced): the OWASP
  signed double-submit cookie -- a random nonce and its HMAC-SHA256 under the secret, domain-separated and
  length-prefixed, bound to the session when `session_binding()` names it -- set as `__Host-csrf` (`Secure`, `Path=/`,
  no `Domain`, `SameSite=Lax`, readable by the page's scripts; read back as the first cookie spelled exactly so, which
  a `__host-csrf`, a `__Host -csrf` or a bare `__Host-csrf` another host planted neither replaces nor hides -- short
  of a nameless `=__Host-csrf=X` on a browser older than RFC 6265bis, which no server can tell from the real one
  (`csrf.h`)) on every response to a request without a valid one -- a token refusal's included, never one refused for
  where it comes from, so an unsafe request another site's page makes rotates nothing (a cross-site link under
  `SameSite=Strict` and an exempt request do get one) -- after the handler (a handler that rebuilds the response keeps
  it), and offered to the page in `qb::http::csrf_token_slot`; an unsafe request echoes it in `X-CSRF-Token` or the
  `_csrf` field of a urlencoded or multipart/form-data body (a form with a file input; the body is read only when the
  cookie and the header leave it to), compared in constant time. `trusted_origin()` (validated:
  `scheme://host[:port]`, http or https) and `exempt(predicate)` skip both layers; configuration a browser would
  silently defeat is refused (a non-token cookie name, `Secure` off under a `__Host-`/`__Secure-` name or with
  `SameSite=None`, a `Max-Age` outside 1 s to 400 days, a short secret); a refusal is `403 Forbidden` with the verdict
  in a `text/plain` body (`qb::http::CsrfVerdict`, `to_string`) unless `on_reject()` writes it;
  `CsrfOptions::check(request, secure_connection)` gives the decision on its own; the factory tag is
  `qb::http::middleware::tags::csrf`. Out of its reach, and said so: a WebSocket upgrade is a `GET` (cross-site
  WebSocket hijacking is the upgrade handler's), and a DNS-rebound name makes `Origin` equal `Host`. Proven by
  `qbm-http-test-unit-middleware-csrf` (30 cases: every `Sec-Fetch-Site` value, `Origin` against `Host` and against
  the URI's authority, an origin-form `//host` target, default and explicit ports, IPv6, case, `null`, an origin with
  a path, neither header, a missing authority, the scheme over TLS; trusted origins and the forms they refuse;
  exemptions; `on_reject`; the cookie, its attributes, its exact name -- look-alikes sent first included -- and its
  slot, no re-issue of a valid token, none on a refusal of where the request comes from, the header and both form
  fields, a missing, different, forged, other-secret or other-session token, malformed tokens, a handler that rebuilds
  the response, the configuration refusals; without SSL, `tokens()` refusing), three loopback cases on the real
  servers (HTTP/1.1 on the wire with an origin-form `//evil.test/csrf` and an absolute-form target, and HTTP/1.1 over
  TLS refusing an `http://` Origin, `qbm-http-test-system-middleware-pipeline-system`; HTTP/2 with `:authority` and
  lower-case names, `-system-http2-client`), and 53 mutants of the middleware, the cookie reads it relies on and the
  servers' cookie catches, each caught when planted.

- **A response body streamed as it is produced, with backpressure, on HTTP/1.1 (Huly QB-86).**
  `Context::begin_stream()` sends the head at once and returns a `qb::http::ResponseStream` the handler writes the body
  through. `write(bytes)` returns at once with a verdict: `taken`; `wait` (the session's output is too full for the
  piece -- nothing was written, and after a drain it fits); `too_large` (the piece cannot fit even into a drained
  output, or, buffered, the body would pass `protocol_limits::MAX_BODY_SIZE`); `closed`. `needs_drain()` says when the
  session holds `high_watermark()` bytes the socket has not taken (1 MiB by default; `set_watermarks()` per stream,
  `stream_high_watermark()` per session, the high mark at most half the session's hard output cap, the low one under
  it); `co_await drain()` or `on_drain(fn)` waits until the output falls to `low_watermark()`. The stream owns the
  completion: `complete()` is ignored until `end()`, `abort()` or the stream's destruction completes the context, so a
  handler -- a coroutine included -- may hand its stream to a producer and return, on every protocol, and a handler
  that throws after handing it on leaves the answer to it. `begin_stream()` returns `nullptr` once the context is
  finalised, cancelled or holding back a completion. The framing is decided from the head as the `PRE_RESPONSE_SEND`
  hooks leave it: the hooks run first, seeing an empty body -- a body already in the response is the stream's first
  piece, so `CompressionMiddleware` leaves a streamed body alone -- then a valid `Content-Length` is honoured and
  enforced (a piece past it, or an `end()` short of it, closes the connection rather than deliver a message the peer
  would misread), a `Transfer-Encoding` whose only coding is `chunked` is chunked as it stands, and otherwise
  `Transfer-Encoding: chunked` is set. The response to HEAD is whole at its head: its exchange ends there and the next
  request on the connection is served while the producer, whose pieces are counted and discarded, runs on. The producer
  owns the stream: one dropped before `end()` is aborted -- the connection closes; buffered, a 500 without the failed
  body's framing and coding headers -- and the peer leaving, an application `cancel()`, an extraction or the inactivity
  timeout cancels it: a parked `drain()` resumes with `false`, `write()` returns `closed`, the context is cancelled,
  and a server destroyed under a live stream releases it; a drain callback still registered when its stream dies is
  released without running. A response that cannot be streamed -- a status without a body, HTTP/1.0 without a length, a
  session without the hooks of the new `qb::http::streaming_session` concept, which the HTTP/2 and HTTP/3 sessions do
  not offer yet -- gets a buffered stream with the same interface, sent whole at `end()` through the ordinary
  completion, its hooks included. Observers read a streamed response at its end: the head's status, even when it was
  cut short, and `Context::streamed_bytes()`, which `AccessLog` logs as its size.
  `qbm-http-test-system-response-stream` (38 cases, the TLS ones over `ssl::DefaultSecureSession`) and
  `qbm-http-test-system-response-stream-huge-body` hold every decision over a raw loopback client that asserts the
  bytes of the wire; two HTTP/2 cases in `qbm-http-test-system-http2-client` hold the buffered fallback. The HTTPS
  cases depend on qb's QB-1176.

- **Client statistics snapshot cost instrument (Huly QB-248).** Two cells in each loopback bench,
  `qbm-http-bench-http2-client-loopback` and `qbm-http-bench-http3-client-loopback`
  (`BM_H2_StatsSnapshot{Unrequested,Requested}/requests:32`, `BM_H3_...`), run the same burst of 32 GETs at a
  concurrency limit of one -- one `push_request()` and one callback per response, on the warm TLS connection for
  HTTP/2, on a fresh QUIC connection per burst opened outside timing for HTTP/3 -- with no snapshot and with one
  `get_stats()` requested and consumed in every response callback: what a program pays to READ the three counters
  the client always maintains (their maintenance has no switch and is not measured). The oracle, outside timing:
  every response 200 with its id in order, the counters moved by exactly 32 / 32 / 0 between two snapshots, and
  the Requested reads summing to 1 + ... + 32 because both clients count before they call back. Measured on an
  i9-12900K as an A/A of the same build (three physical copies a side, eight seeded rounds, 48 processes a cell):
  under WSL2 g++ 14.2 the request costs 13.25 → 13.23 µs over HTTP/2 and 33.56 → 33.54 µs over HTTP/3 with the read,
  ratios 0.999 inside A/A bands of ±0.5 % and ±0.3 %; under Windows 11 MSVC 19.51, 27.04 → 27.14 µs and 60.84 → 60.78 µs,
  ratios 1.004 and 0.999 inside ±1.6 % and ±0.6 % -- the read is below the owners' resolution on both toolchains, under
  ~60 ns a response on g++. The cells sit in `dev/bench/instrument-cases.txt`, not in the gate; three mutants per owner (the read
  not consumed, one request short, the read disarmed after the preflights) are refused.

### Fixed

- **A request's URI is the target the client sent: an HTTP/1.1 `//host/path` is a path, a target that is none of the
  four forms is answered 400, and an HTTP/2 or HTTP/3 `:path` or `host` field names no other authority (Huly
  QB-1177).** The HTTP/1.1 server read every request target as a URI reference (RFC 3986 §4.1), where an origin-form
  `//evil.test/transfer` -- an absolute path whose first segment is empty (RFC 9112 §3.2.1) -- names the host
  `evil.test`: `request.uri().host()` was the one the client chose, whatever `Host` said, and the route served was
  `/transfer`. `///x` came out as `/x`, `//u@a/x` gained a userinfo, a CONNECT `example.com:443` was the scheme
  `example.com` and the path `443`, and a target with a byte the parser refuses -- `/a|b`, `/a{b}`, sent raw -- was
  dispatched with an empty path, to the route of `/`. `qb::http::origin::request_target_uri()` reads the target by
  its form now (RFC 9112 §3.2), once it has ended (llhttp's `on_url_complete`, instead of on each piece of it), into
  the request's own uri: origin-form with `qb::io::uri::read_origin_form()` -- `//a/b` is the path `//a/b` with an
  empty host, routed by its segments (`/a/b`), the authority being the `Host` field; absolute-form as a URI whose
  authority has a host and no userinfo (`http://victim.test@evil.test/x` and `http:///x` are refused); the
  authority-form of CONNECT, and only of it, with `qb::io::uri::read_authority_form()`, the host and the port
  (`[::1]:443` included, so a CONNECT is routed at the path `/`); the asterisk-form of OPTIONS, and only of it, as
  `*`. In place, because the first form of this change read every target into a uri built apart and moved into the
  request -- two moves of its strings and its query map, 830 instructions a request on g++ 14, 54 ns of a 263 ns parse
  of a two-line GET (`qbm-http-bench-http1-parser`, `BM_Http1Parse_WholeBuffer/corpus:0` against the previous release's
  parser with the same bench code on both sides, 3 physical copies a side in a seeded order, +20 % with a 1.2 % A/A
  band; the uri's parse itself was 6 instructions cheaper). Read in place, the same request executes 767 fewer
  instructions (5 126 -> 4 359; 4 076 before the train, the rest QB-1186's check) and the cell reads 265 / 329 / 272
  ns -- the previous release, the first form, this one (ratios 1.238 and 1.026 [1.022, 1.033]; the same host and
  protocol, 4 sides, 48 launches); `Fragmented/corpus:0` is level with the previous release again (314 -> 313 ns, 0.997
  [0.970, 1.044]), the 9-line GET +1.9 %, and the byte-at-a-time parses keep the gain of one parse per target (0.86 on
  the 7-byte target, 0.70 on the 28-byte one). The HTTP/2 and HTTP/3 readers (`origin::request_uri`) are unchanged: on
  x86 the h2 request already executes 1 326 fewer instructions than before this change. Anything else -- a fragment, `*` for another
  method (`GET *` was a 404), a byte the parser refuses, a target llhttp refuses itself such as `?x`, which closed the
  connection on silence -- names no resource: the server answers `400 Bad Request` and closes, as it answers a target
  over the URL limit 414, and the percent-encoded spelling (`/a%7Cb`) is served (QB-1187 weighs the bytes browsers
  send raw). The HTTP/2 and HTTP/3 servers composed `:scheme://:authority` followed by `:path` by hand: on HTTP/2 a
  `:path` `@evil.test/x` made `evil.test` the host, and on both `OPTIONS *` the host `example.test*`.
  `qb::http::origin::request_uri()` composes it for both: `:path` is an absolute path, with no fragment, space or
  control byte, or the `*` of an OPTIONS request (its URI is `*`, without an authority, as HTTP/1.1's); `:scheme` a
  scheme; `:authority` one `is_request_authority()` accepts -- an IP literal that is an IPv6 address, or a reg-name or
  an IPv4 address with no `:`, `[` or `]` and well-formed percent-encodings, and a port of digits no greater than
  65535 (the authorities `:443`, `a:b:c` and `h:99999` were accepted, `[127.0.0.1]` read as the IPv4 host
  `127.0.0.1`, and a reg-name could hold any byte the URI parser let through; the redirect target check, which had its
  own copy of the grammar, shares this one) -- and the text one the parser accepts. HTTP/3 also refuses a `host` field that does not name
  `:authority` (RFC 9114 §4.3.1), which nghttp3 passes and `header("Host")` returned as a second authority the client
  chose. A malformed request is `RST_STREAM(PROTOCOL_ERROR)` on HTTP/2 and its stream refused with `H3_MESSAGE_ERROR`
  on HTTP/3; nghttp3 refuses several shapes itself, a connection error. An origin-form request's `uri().host()` is
  empty: its authority is the `Host` field, which the server checks (QB-1186, below). `CsrfMiddleware` never
  read an origin-form authority (QB-95). `uri().path()` is the target's own path on every protocol, `//` and empty
  segments included: a guard that tests a prefix (`uri().path().starts_with("/admin")`) does not see `//admin/x`,
  which the router serves as `/admin/x` -- guard the route group -- and a file path built by stripping one slash is
  absolute for `//etc/passwd` (the static files middleware strips them all), and a `Location` or a link that echoes it
  without collapsing its leading slashes names another host. A directory listing of a path that
  begins with `//` led every link with it -- `href="//file1.txt"`, a link to the host `file1.txt` -- and leads it with
  one slash now. Tests: the HTTP/1.1 router on the wire (`//a/where/x` reaches `/a/where/*`, `///where/x` keeps its
  slashes, `//u@a/where/x` is no route, the refused targets 400, a pipelined request before a refused one answered
  and the one after it never read, `OPTIONS *` reaching the router), a target split over two reads, both readers'
  accepted and refused targets and fields, the authority grammar, HTTP/2 and HTTP/3 servers fed them -- each refusal
  on the layer that makes it --, the listing's links.

- **The HTTP/1.1 server checks the `Host` field -- one, naming a host and an optional port, or the request is answered
  400 --, an absolute-form target's authority is the field's value, and a field value ends at its last octet that is no
  whitespace (Huly QB-1186).** The server read no `Host` field: an HTTP/1.1 request without one was served, two field
  lines (`Host: a`, then `Host: b`) were served with `header("Host")` reading the first while a proxy before the server
  may route by the other, and a value that is no authority -- `a b`, `u@a`, `a/b`, `a:99999`, `[127.0.0.1]` -- was
  served (measured on the wire before this change); since QB-1177 that field alone is an origin-form request's authority
  (RFC 9112 §3.3). The parser checks it once the header section has ended (RFC 9112 §3.2): an HTTP/1.1 request carries
  one `Host` field -- an HTTP/1.0 request may carry none --, no request two field lines of it, and its value is empty (a
  target URI with no authority) or an authority `qb::http::origin::is_request_authority()` accepts, the grammar of
  `:authority` on HTTP/2 and HTTP/3; otherwise the session answers `400 Bad Request` and closes, after every request
  received before it, as it answers a target that names no resource. An absolute-form target (§3.2.2), and CONNECT's
  authority-form (§3.3), names the authority itself and the field is ignored: it is still required and checked, and it
  then reads the target's authority as the client wrote it, so `GET http://site.test/ HTTP/1.1` with `Host: evil.test`
  no longer hands `evil.test` to a handler that builds a link from `header("Host")` (an HTTP/1.0 request that sends no
  `Host` has none: its URI names the authority). A field line's value excludes the whitespace around it (RFC 9112 §5):
  llhttp drops the run before it and the parser kept the run after it, so `Host: a ` would have been refused and every
  field -- a header section's and a trailer section's alike -- was read with its trailing spaces and tabs; they are
  dropped, the whitespace inside a value kept. The request serializer writes no `Host` by itself: every client of the
  module sets one, and a request written by hand through `pipe << request` needs one to reach a qbm-http server. The
  check is on the path of every request, and the parser benchmark measures it: a first version cost the minimal request
  10.9 % (A/B on the M4 Pro, three copies of each binary in a seeded random order, eight rounds); the authority grammar
  now reads a 256-octet table in one pass -- 12.2 to 6.25 ns for `example.test`, which every caller of
  `is_request_authority()` gains, HTTP/2's and HTTP/3's `:authority` and the redirect check included --, the parser
  counts the `Host` lines where it stores them instead of looking the field up, and the trim tests the last octet first.
  What remained on the M4: `BM_Http1Parse_WholeBuffer/corpus:0` 236.5 to 245.8 ns (+3.9 %), an eight-field request +2.0 %,
  inside the gate's macOS threshold (5.64 %); the HTTP/1.1 request it measures costs microseconds end to end. On x86 the
  same check read +18 ns on the same cell (317 to 335 ns on an i9-12900K under g++ 14, 3 physical copies a side in a
  seeded order, the parse of a two-line GET; 217 instructions a request, 171 of them `is_request_authority()` -- a call
  that scanned the host, then re-read the port with `std::from_chars`), so the grammar is one pass now, inline where the
  parser stores each field line: the host's octets through the table, the port's digits bounded as they are read, nothing
  allocated, only an IP literal calling out (`origin::detail::is_ip_literal_authority`); the accept / refuse set is the
  first form's, byte for byte -- a differential run of the two forms over 72 903 generated values (every octet alone
  and in pairs, every octet at every position of 27 short host / port / literal templates, 29 port and 55 IPv6-literal
  edge cases, the NUL and cut-encoding cases of the unit test; 7 130 accepted) found no disagreement -- and the gated
  parse executes 84 fewer instructions a request for it (4 359 -> 4 275 with QB-1177's in-place reader; 4 076 before
  the train), 273 against 280 ns on the same host in the same campaign (0.976), 1.024 [0.998, 1.041] of the previous
  release's parse -- level with it within that campaign's 1.7 % A/A band. MSVC 19.51 read the same cell +34 ns (318 ->
  352 ns, +11 %, [1.079, 1.127]): it kept the parser's three helpers around the check (`without_trailing_whitespace`,
  `note_host_field`, `check_host_field`) out of line -- three calls a request where g++ inlined them -- and, once those
  were forced, `is_request_authority()`; the four are `QB_MSVC_FORCEINLINE` (plain `inline` on g++ and clang, whose
  binary is byte-identical), 352 -> 338 ns (0.959 [0.952, 0.966]); the +20 ns (+6 %) that remain there are the check's
  own MSVC codegen. Tests: the router
  on the wire (each refused shape answered 400, an HTTP/1.0 request without `Host` served, an absolute-form target's
  `Host` reading its authority, a pipelined request without `Host` refused after the one before it and the one after it
  never read), the parser (each shape and its refusal status; the field a CONNECT, an absolute-form and an asterisk-form
  target leave), the protocol (the 400 handed to the session; a value's end at each of the three places a field is
  stored). The hand-written requests of the parser and framing tests carry a `Host` field, so each of their refusals is
  still their own, and so does the parser benchmark's POST corpus (`corpus:2`, not gated), whose exact-message oracle
  names the field: without it, the check would have refused the corpus and the preflight failed its three drivers.

- **A request's `Cookie` header is read as a browser sends it: pairs split on `;` alone, a malformed pair dropped
  instead of the header, so a cookie another host plants can no longer replace, hide or wipe a prefixed one (Huly
  QB-95, its fourth to seventh reviews).** One case is left, the CsrfMiddleware entry's: a nameless `=__Host-csrf=X`
  on a browser older than RFC 6265bis, which no server can tell from the real one. The parser read a request header
  with Set-Cookie's grammar, and three cookie-tossing paths followed. Whitespace inside a name was dropped, so
  `__Host -csrf` -- which another host can
  set, a browser protecting only the exact prefix -- was stored as `__Host-csrf`; after a quoted value a `,` separated
  pairs and a quoted value ran across `;`, so a cookie of another name valued `"x",__Host-csrf=E` added a
  `__Host-csrf` of its choice ahead of the real one, and one opening a quote that a later cookie's closed swallowed
  the real one; and one malformed pair -- a control character, an unclosed quote, a name over 1024 bytes -- refused
  the whole header, so one planted cookie emptied the jar (every session cookie gone). A request header now has its
  own parser: split on `;` alone, the whitespace around a name and a value (SP, HTAB) removed, a value wrapped in `"`
  read without the two quotes and nothing inside unescaped -- RFC 6265 has no quoted-pair, and `parse_set_cookie()`
  never unescaped (a quoted value used to lose its `\`, and a `'` was taken for a quote) -- and every other byte kept,
  a `"`, a `[`, a space or a UTF-8 byte in a name or a value included (`prefs={"theme":"dark"}`, PHP's `cart[1]`,
  which the fifth review's token-only names and quote rules dropped; the sixth restored them). A pair is dropped, the
  others kept, when it has no `=` -- a nameless cookie, which a browser sends as its value alone (RFC 6265bis), where
  `flag` used to read as a cookie named `flag` and a bare `__Host-csrf` sent first hid the real one from the exact
  read -- when its name is empty or `$`-prefixed, or its name or its value holds a control character other than HTAB
  or is over its cap (1024, 4096 bytes); only a header over `max_cookie_header_size` (16 KiB) is refused -- a size
  several cookies planted near the value cap reach together (a cookie bomb), which then still empties the jar. The jar
  folds case and keeps a name's first pair, so a planted `__host-x` sent first is still what
  `cookie_value("__Host-x")` returns: `Request::cookie_value_exact(name)` reads the first pair spelled exactly `name`
  from the header section's lines (never a trailer section's, nothing for a refused header), over
  `parse_cookie_pairs()`, which keeps the order, the spelling and every duplicate. The Set-Cookie side of
  `parse_cookies()` keeps the whitespace inside a name too. Proven by `qbm-http-test-unit-cookie` (64 -> 69 cases)
  and, on the final parser, twenty-four mutants, each caught: a `,` separating, Set-Cookie's grammar for a request
  header, a malformed value refusing the header, the value not trimmed, no value cap, no name cap, the inner
  whitespace of a name dropped, the exact read folding case, an unquoted `"` dropping the pair, quoted-pairs
  unescaped, names restricted to tokens, HTAB counted as a control character, only a space trimmed, `$` names kept, a
  `'` taken for a quote, an opening quote stripped alone, a control character kept in a name, DEL taken for no control
  character; and, of the seventh review, a nameless cookie read as a name, a tab inside a name or a UTF-8 value
  dropped, any `$` taken for a legacy prefix, a quoted value trimmed inside its quotes or measured with them.

- **An HTTP/2 request may carry a `host` field that names `:authority`, as RFC 9113 §8.3.1 lets an intermediary
  retain one, and a response may carry a `host` field (Huly QB-1189).** `HeaderValidator::is_forbidden_header()`
  counted `host` among the connection-specific fields -- RFC 9113 §8.2.2 names `connection`, `proxy-connection`,
  `keep-alive`, `transfer-encoding` and `upgrade`, and `te` but for `trailers`, not `host` --: the server reset every
  request stream that carried one with `RST_STREAM(PROTOCOL_ERROR)` -- measured on a TLS loopback server fed raw
  HPACK blocks, `host: example.test` beside `:authority: example.test` included --, a response the application gave
  a `Host` header was a stream error and never sent, and the client reset a response that carried one. `host` is off
  the list, which keeps those five and the h2c upgrade's `http2-settings` (`te` is judged by its value, as before),
  and the server checks a request's `host` as HTTP/3 does since QB-1177: one field, naming `:authority` as text
  without regard to case (`example.test:443` does not name `example.test`, the normalization RFC 9113 §8.3.1 leaves
  to an origin server), else the request is malformed (`RST_STREAM(PROTOCOL_ERROR)`, the connection kept) --
  another authority or port, an empty value, a second field --, refused before a field over the request limits or a
  `:path` over the target limit is answered, as a malformed regular field is; `header("Host")` is never a second
  authority the client chose; without `:authority`, the `host` field names the request's authority (the next
  entry, Huly QB-1195). The server sends a response's `host` field, as HTTP/1.1 does (HTTP/3 drops every `host`
  field it would send), and the client delivers it. The client never sends `host`: a request's `Host` header names
  `:authority` when its URI has no host and is dropped otherwise. Push promises are unchanged. The check costs nothing
  measurable: the new `qbm-http-bench-http2-server-request` (a browser-shaped GET with 14 fields, framed, decoded,
  validated, dispatched and answered on a socket-less server, logging at WARN; 3 copies of each binary in a seeded
  order over 10 rounds, macOS arm64) read every difference inside the spread of one binary's copies (up to 1.4 %):
  after slower by 0.4 to 0.8 % in three sessions on QB-1177 (3320 to 3346, 3332 to 3346, 3329 to 3345 ns a
  request), faster by 0.5 % with both sides built with 64-byte function and loop alignment (3379 to 3361; in that
  session the alignment alone moved the before binary 1.5 %), faster by 0.3 % on QB-1186 (3382 to 3370). The loop
  gains one length test per field; `is_forbidden_header()` lost three comparisons per name. Tests: the server fed
  a `host` that names `:authority` in another case, with a port, as an IPv6 literal, and every refused shape, a
  well-formed `host` over the value limit answered 431, a malformed one beside a field or a `:path` over the limits
  a stream error; every connection-specific field refused in a request received, a response sent and a response
  received; a response with `host` sent and delivered; the client's emitted header block.

- **An HTTP/2 or HTTP/3 request may name its authority in its `host` field alone, without `:authority` (Huly
  QB-1195).** Both servers required `:authority`: measured on the base, a request that named its authority in its one
  `host` field was reset with `RST_STREAM(PROTOCOL_ERROR)` on HTTP/2 and its stream refused with `H3_MESSAGE_ERROR` on
  HTTP/3 (by qbm-http: nghttp3 lets it through), although RFC 9114 §4.3.1 asks for an `:authority` or a `Host` field,
  RFC 9113 §8.3.1 sets `Host` aside only when `:authority` is present, and a user agent sends `Host` unless it sends
  `:authority` (RFC 9110 §7.2) -- the rule that has a client write `:authority` binds clients, not what a server
  accepts. A request's authority is now its `:authority`, else its one `host` field, read as `:authority` is: an
  authority `qb::http::origin::is_request_authority()` accepts, composed into the URI by
  `qb::http::origin::request_uri()`, `header("Host")` giving it. A request that names neither, whatever its scheme (qb
  composes no URI without an authority), an empty `:authority`, a second `host` field or a `host` field that is no
  authority (`:443`, `a:b:c`, `example.test:99999`, `[127.0.0.1]`) stays malformed, as does a `host` field beside
  `:authority` that does not name it (QB-1177, QB-1189): `RST_STREAM(PROTOCOL_ERROR)` on HTTP/2, the stream refused
  with `H3_MESSAGE_ERROR` on HTTP/3, where nghttp3 (1.18.0 measured) refuses some shapes itself first, a connection
  error -- no authority at all, an empty field, a second `host` field, a `host` holding `@`, `/` or a space. The
  `host` field that stands for `:authority` is held to the field limits like any field: over the value limit, the
  request is answered 431, once it is known well-formed. On HTTP/2 the 414 and 431 answers now come after the method
  and the URI are composed, as on HTTP/3: an unknown `:method`, or a malformed `:scheme`, `:authority` or `:path`,
  beside a field or a `:path` over the limits was answered 431 or 414 and is now a stream error, as a malformed `host`
  already was. On HTTP/3 a field over the limits is dropped, but the first `host` field of the header section over
  them is now kept for the checks and the others counted (trailer sections are unchanged): a `host` over the limits
  beside `:authority` that names another authority refuses the stream, where it was answered 431 unread, and a second
  one stays malformed. `HeaderValidator::validate_request_pseudo_headers()`, a public helper the server does not call,
  accepts a request without `:authority` when one non-empty `host` field is among the fields it is given (it checks
  presence, no value against another, as before). The HTTP/2 request path costs nothing measurable:
  `qbm-http-bench-http2-server-request` against QB-1189 (3 copies of each binary in a seeded order over 10 rounds,
  macOS arm64) read a browser-shaped GET 3343 to 3351 ns a request (+0.2 %), the same with a `host` field 3429 to 3418
  (-0.3 %), and the first with both sides built with 64-byte function and loop alignment 3385 to 3368 (-0.5 %), each
  inside the spread of one binary's copies (up to 1.2 %). Tests: on both servers, a request naming its authority in
  its `host` field served with the URI the same value sent as `:authority` composes (another case, a port, an empty
  port, an IPv6 and an IPv4 literal, `//` in the path, `OPTIONS *`, `http`); every refused shape -- on HTTP/3 refused
  by qbm-http where nghttp3 lets it through, by either layer where nghttp3 refuses it first --; the field limits both
  ways, each malformed shape beside them a stream error; the validator.

- **One request could terminate any qb HTTP/2 server: a `Cookie` header the parser refuses escaped the server's
  `noexcept` frame handlers (Huly QB-1174, security).** `dispatch_complete_request` called `parse_cookie_header()`
  outside the `try` that contains the application's exceptions, and `parse_cookies()` throws on a cookie name over
  1024 bytes, a value over 4096 or a control character -- all within the default field limits (8192) -- or a header
  over 16 KiB. One unauthenticated request with `cookie: <1025 bytes>=v` ended the process (`libc++abi: terminating
  due to uncaught exception of type std::runtime_error`, exit 134), in every release since 3.0.0. The HTTP/2 server
  now parses under a `try` and serves such a request without cookies, as the HTTP/1.1 server always did. Two more
  cookie defects went with it: the HTTP/3 server parsed no `Cookie` header at all (`cookie_value()` was empty on
  HTTP/3 and on the HTTP/3 side of the dual-stack server), and `Request::parse_cookie_header()` read only the first
  `Cookie` field line, while HTTP/2 and HTTP/3 let a client split it into one line per cookie (RFC 9113 §8.2.3, RFC
  9114 §4.2.1) -- the second cookie was lost. Every line is read now, as if joined with `; ` (a name's first value
  wins), a header over 16 KiB leaves the jar empty (a malformed pair is dropped since, see the entry above), and the
  HTTP/3 server parses before routing under the same `try`. The docs said the servers did not parse request cookies at
  all; they do, on all three protocols. Proven by a loopback case per protocol (`qbm-http-test-system-http2-client`,
  `-http3-loopback`; HTTP/1.1 already had its own) and two unit cases (`qbm-http-test-unit-cookie`), and by five
  mutants of the fix, all caught -- the unguarded HTTP/2 call reproduces the termination. An independent review then
  found two gaps, closed before the fix landed: a `Cookie` line of a request's trailer section was read as a cookie --
  received trailer fields are also added to the header fields, and RFC 9110 §6.5.1 forbids trusting one as a header
  field, so an intermediary that filters the header section's cookies was bypassed -- and the 16 KiB cap applied per
  line, so a request split into 99 lines carried some 800 KB of cookies. Only the header section's lines are read now,
  and `max_cookie_header_size` (16 KiB) caps them joined; two unit cases more, each caught by its mutant.

- **An HTTP/1.1 session extracted from its server runs its extraction handler: its watcher stops and the context
  it was answering is cancelled (Huly QB-1182).** `extractSession()` -- a WebSocket upgrade, an ownership transfer --
  runs a session's `on(event::extracted)` only when io_handler's probe, `qb::has_on<Session, event::extracted>`, sees it
  on the concrete session type, and the HTTP/1.1 session's handler was private and befriended for the internal base
  only: the probe answered false for `DefaultSession`, `ssl::DefaultSecureSession` and every user session, and no
  extraction ran the handler. The session kept watching the socket it had handed over -- bytes the new owner's peer
  sent next were reported to it, it read its moved-out transport, failed, and was torn down, running its disconnection
  hooks -- and its context was neither cancelled nor released, against what the module's docs state. The detector is
  now befriended whole, so a probe on the concrete session -- or on a class deriving from it -- sees the handler; a
  session class that declares an `on()` of its own (the

- **An HTTP/1.1 or HTTP/2 session extracted from its server runs its extraction handler: its watcher stops and the
  contexts it was answering are cancelled (Huly QB-1182).** `extractSession()` -- a WebSocket upgrade, an ownership
  transfer -- runs a session's `on(event::extracted)` only when io_handler's probe,
  `qb::has_on<Session, event::extracted>`, sees it on the concrete session type, and the HTTP/1.1 session's handler was
  private and befriended for the internal base only: the probe answered false for `DefaultSession`,
  `ssl::DefaultSecureSession` and every user session, and no extraction ran the handler. The session kept watching the
  socket it had handed over -- bytes the new owner's peer sent next were reported to it, it read its moved-out
  transport, failed, and was torn down, running its disconnection hooks -- and its context was neither cancelled nor
  released, against what the module's docs state. The detector is now befriended whole, so a probe on the concrete
  session -- or on a class deriving from it -- sees the handler; a session class that declares an `on()` of its own (the
  `on(qb::http::event::disconnected &&)` the session forwards to it, say) hides the base's handler from the probe all
  the same, so the server's `extractSession()` runs it for that one, through the new `http1_extracted()` server hook.
  The HTTP/2 session's handler is public, and hidden all the same from a session class that declares an `on()` of its
  own -- name hiding ignores access: such a session kept its watcher and the contexts of its live streams; the HTTP/2
  server's `extractSession()` runs it for that one too, through `http2_extracted()`. A `static_assert` beside
  `DefaultSession`, `ssl::DefaultSecureSession` and the HTTP/2 `DefaultSession` (whose public handler was already seen)
  keeps a regression from compiling. Checked and not affected: the events io<> probes on the internal base
  (`pending_write`, `eos`, `disconnected`), the servers' accept and disconnection gates, the WebSocket and HTTP/3 types
  (no handler behind a gate on a derived type). `qbm-http-test-system-http1-extraction` drives both session shapes on
  one loop and asserts the behaviour -- the context cancelled, the watcher stopped, the peer's next bytes reaching no
  handler of the stale session: red at 819add3 and 2d695d2 for both, red for the session with its own `on()` with the
  friend fix alone, green with both; `Http2Extraction` in `qbm-http-test-system-http2-client` extracts an HTTP/2 session
  of that shape under a live stream: red at 12a8802 (the context not cancelled, the watcher still on), green with the
  fallback.

- **qbm-http and Node's http_parser linked in one program each run their own parser, and no `llhttp` archive is
  installed any more (Huly QB-1139).** The llhttp fork's `http_` prefix keeps it from colliding with a system
  llhttp, but it is http_parser's prefix too, and two names are shared outright with other signatures:
  `http_should_keep_alive` and `http_errno_name`. A program that linked qbm-http and anything carrying
  http_parser held two definitions of each and the link line chose: measured on ld64 against a stand-in, qbm-http's
  HTTP/1.1 parser called the foreign `http_should_keep_alive` and a `Connection: close` request came out
  keep-alive, behind a `duplicate symbol` warning; GNU ld and MSVC refuse the second definition. Every function
  the fork defines (123) now links as `qb_` + its upstream name (`http_execute` is `qb_llhttp_execute`) through one
  `#define` per name at the top of `src/qbm/http/vendor/llhttp.h`, read before any declaration; source keeps the
  `http_` spelling. The fork is also compiled into qbm-http's own archive, as an `OBJECT` library folded in with
  `$<TARGET_OBJECTS:llhttp>`: the installed tree carried `lib/libllhttp.a` (`lib/llhttp.lib`), the exact file the
  vcpkg and Debian llhttp packages install, and `qbm::llhttp` in the export set -- both are gone, and
  `find_package(qbm-http)` needs nothing new. `qbm-http-test-unit-llhttp-link-names` links an http_parser stand-in
  BEFORE qbm-http and checks both sides (it fails as above without the renaming), and
  `qbm-http-test-unit-llhttp-symbols` reads the built archive and fails on any exported `http_*` or `llhttp_*`
  left unrenamed.
- **The WebSocket loopback fixture binds 127.0.0.1 and keeps the OS error of a refused bind: the report
  names address, port and code instead of "failed" on an address it had not bound, and the hardening
  scenarios stop instead of driving their client at port 0 (Huly QB-1125).** `WsServerThread` listened
  on every interface while its message said 127.0.0.1 and dropped the code; it now binds the loopback
  like the module's other fixtures, reads `get_last_errno()` before anything else touches a socket --
  a refused bind reads `listen_v4 failed on 127.0.0.1:<port> (native error 98: Address already in use)` --
  and exposes `listening()`.
  A lifecycle test holds a port with an intruder listener and asserts the reported address, port and
  code (EADDRINUSE, WSAEADDRINUSE on Windows). Test fixtures only; no shipped code changes.

- **The WebSocket handoff test no longer races its own server thread on Windows: the registerSession()==nullptr
  case reads the dead-path flag with a 2 s bound instead of at the instant the client saw its socket dropped
  (13 red runs in 200 on MSVC before, 0 after; Huly QB-1152).** `registerSession` closes the socket it is
  handed before the test's handler can store its flag, so a preemption between the two left the flag unread;
  the bound separates "not written yet" from "never taken", which stays a named failure. Test only; nothing
  changes on the capped-handoff path, which still drops the connection.

## [3.3.0] - 2026-10-26

### Added

- **Matched performance fixtures for schema patterns and static files.** Pattern cells use
  identical success and rejection inputs for anchored search, unanchored search and standalone
  full matching. The static-file fixture verifies GET, HEAD, conditional and range responses
  over a private local file; context lifecycle, metadata calls and reads are timed, without a socket. Both
  revisions must use these same fixtures when comparing a correctness change.

- **TLS configuration and certificate rotation on HTTPS and HTTP/2 servers (Huly QB-98).**
  `set_tls_context`, `reload_certificates` and explicit-context `listen`/`listen_no_start`
  overloads install policy without restarting the listener. Invalid renewal leaves the serving
  context intact; established and already accepted connections retain their original context.
  ALPN is pinned to HTTP/1.1 or h2 with HTTP/1.1 fallback. Supply a fresh unpublished context:
  copies share SSL_CTX, and SNI-selected children need matching ALPN before publication.
  Fresh raw TLS server/generic contexts are supported; client-only and DTLS contexts are refused.
  Certificate-only reload replaces the entire configuration with defaults, including callbacks,
  mTLS and session state. HTTP/3 and dual-stack rotation are outside this API's scope.

- **Opt-in one-shot redirects (Huly QB-169).** Include `<qbm/http/redirect.h>` and pass the required
  trailing `RedirectOptions` to any of the eight HTTP/HTTPS helpers. The default permits five
  same-origin followed hops; the cap returns the last 3xx rather than creating 508. The separate
  `async::RedirectReply` carries the terminal attempt and ordered followed replies, preserving
  legacy prepared-request snapshots. Replayed bodies come from the logical request, avoiding
  double compression. Timeout is per attempt; history retains whole bodies and grows with actual
  followed hops. Cross-origin following is explicit and strips credentials; HTTPS-to-HTTP,
  invalid Location values, userinfo, scoped IPv6 and IPvFuture are not followed. Final completion
  is deferred until after dispatch. Existing overloads and the `async::Reply` layout are unchanged.

- **Persistent HTTP/1 access-log comparison (Huly QB-1106).** The existing benchmark suite gains
  `qbm-http-bench-http1-access-log-loopback`: batches of 32 real loopback requests on a persistent
  connection, logging off, common, or JSON. It checks response bodies and status, routed/logged
  totals and the peer address in each emitted line. Request construction and verification are
  outside the timed batch; client, server, event-loop and socket work remain inside. This is a
  measurement fixture, not a claim of a native speedup or an isolated formatter cost.

- **`drain(deadline, on_drained)` on the HTTP/1.1 server: stop it without dropping a request it has
  received (Huly QB-167).** The listening socket closes, so a new connection is refused; an idle
  session closes at once, gracefully (its sending side shut down, what its client still sends
  dropped until the client closes); a busy session answers every request it has received, in order,
  the last answer `Connection: close`, then closes. `on_drained` runs once, on the server's loop:
  `qb::http::drain_outcome::drained` when the last owned HTTP or in-place WebSocket session is gone, or `deadline` when the
  deadline came first, after aborting what is still open. `draining()` tells a draining server.
  A WebSocket upgraded in place and still owned by this server receives `1001 Going Away` and keeps
  the drain pending until it closes or the deadline aborts it (Huly QB-1097). Its Close callback is
  preserved; coroutine close waiters do not enqueue a second Close when the drain already began.
  A session extracted to another owner remains outside this server's drain. `qb::http::DisconnectedReason::ServerDraining`
  is new, appended after `Undefined`: the existing values do not move; it reports a session the
  drain closed while idle or aborted at the deadline. `drain_outcome` is meant for the HTTP/2 and
  HTTP/3 servers' drains too. Witness: `qbm-http-test-system-server-drain`.

- **`drain(deadline, on_drained)` on the HTTP/2, HTTP/3 and dual-stack servers: each connection ends
  in two GOAWAYs (Huly QB-91; RFC 9113 §6.8, RFC 9114 §5.2).** The contract is the HTTP/1.1 server's:
  one report, on the server's loop, `drain_outcome::drained` when no connection is left or
  `deadline` when the deadline came first, before `drain()` returns when none is open; `draining()`
  tells; a second call returns false. HTTP/2 closes its listener and sends each connection a GOAWAY
  naming the largest stream id and a PING; on the PING's ACK, a round trip later, the final GOAWAY
  names the last stream the client opened -- the streams up to it are served, one above it is
  refused (`REFUSED_STREAM`) -- and the connection closes after its last stream. A connection whose
  TLS handshake ends during the drain serves nothing: its one GOAWAY names stream 0; an HTTP/1.1
  connection of the ALPN fallback that has received nothing closes. At the deadline a connection
  that never answered the PING is sent the final GOAWAY and closed once it is delivered, within
  qb-io's linger bound. HTTP/3 sends the notice, a GOAWAY naming the largest stream id, then the
  final GOAWAY after two of that connection's smoothed round trips (at least 1 ms, at most the
  deadline); one shared timer services the individual due times. Older custom backends without
  a per-connection RTT retain the aggregate fallback. Each connection closes once its last request
  stream has and its GOAWAY is acknowledged. During drain, the native backend refuses new Initial
  packets without allocating a connection (Huly QB-1098). A handshake already in progress, or one
  accepted by a legacy backend without admission control, still receives GOAWAY stream 0 before
  any request is routed and closes after its acknowledgement. The UDP endpoint stays bound until
  `close()`. The dual-stack server drains both stacks with one deadline and reports once,
  `deadline` when either met it. `ServerHttp2Protocol::begin_graceful_shutdown()` and
  `complete_graceful_shutdown()` are the two HTTP/2 phases. Witnesses:
  `qbm-http-test-system-server-drain-h2`, `-unit-http2-server-protocol`, `-system-http3-loopback`.

- **`trailers()`: a message's trailer section, kept apart from its header fields, on HTTP/1.1,
  HTTP/2 and HTTP/3 (Huly QB-1073; RFC 9110 §6.5).** `Request` and `Response` gain
  `Headers &trailers()`, `const Headers &trailers() const noexcept` and `bool has_trailers() const
  noexcept`. Received: every field of the peer's trailer section is in `trailers()`, and -- the 3.x
  source-compatibility decision -- in the header fields too, after the header-section values of the
  same name, as before: code that read a trailer through `header()` keeps working, and `trailers()`
  tells a trailer field from a header field, which RFC 9110 §6.5.1 asks a recipient not to confuse.
  Sent: the fields of `trailers()` travel in the trailer section after the body -- after the fields
  the `Trailer` header announces, the 3.x way, which keeps working -- announced by a `trailer` field
  the protocol adds when the message carries none; HTTP/1.1 has a trailer section only in a chunked
  message (`Transfer-Encoding: chunked`), and a message framed otherwise, or a `MessageHead`, sends no
  trailers. A field of `trailers()` a trailer section must not carry, or that no header field could
  be, refuses the message before anything of it is sent. The section is allocated on first write: a
  message without trailers carries one null pointer; measured with callgrind on g++-14 against
  `8a2abfa` (Ir per operation), the member costs +27 per HTTP/1.1 parse alone, and the message
  constructors no longer reset the state the base constructor just built (an out-of-line call), so a
  parse costs 66-67 fewer instructions in total, a message built, moved twice, copied and destroyed
  141 fewer, and the HTTP/1.1 serializers, which reach the trailer path only for a chunked message,
  5-24 fewer. The serializers ask `qb::http::detail::writes_trailer_section` before they write a byte and
  write the start line themselves in both cases, handing the rest of a trailed message to
  `write_trailed_chunked_message` after it: the first shape wrote the start line through a second,
  out-of-line writer in the same translation unit, which made MSVC stop inlining the status code's
  `pipe<char>::operator<<` into `serialize_response` and re-allocate the header loop's registers
  (`serialize_response` 529 to 495 instructions, `serialize_request` 585 to 443; g++ unaffected). With
  one writer the two serializers are develop's instruction streams again (+9 instructions each, the
  check) and run 2 to 35 fewer instructions a message than develop on g++ (callgrind, 20 000
  messages of each of the four `http1-serialize` cells); on MSVC those cells sit within the spread of
  their own layouts (a nop-shifted family of each side spans 4 to 8 %: `BM_Http1Serialize_HeaderBlock`
  develop 280 to 304 ns), so no wall-clock difference can be read there.
- **`qb::http::origin::authority(uri)`: the authority every protocol sends (Huly QB-1064).** One
  writer for the HTTP/1.1 and WebSocket `Host` value and the HTTP/2 and HTTP/3 `:authority`, which
  five places wrote (HTTP/1.1 `host_header_value`, the HTTP/2 client and its server's push promise,
  the WebSocket client, HTTP/3): the host, an IPv6 literal between brackets without its zone
  identifier, `:port` unless it is the scheme's default. `host_header_value` returns it. Cost
  (callgrind, `8a2abfa`): the HTTP/1.1 Host value of three URIs 1115 -> 1066 instructions; an HTTP/2
  request/response round trip with the same `:authority` text 84764 -> 83857 (with the trailer
  changes), HTTP/3 request/response field blocks 6504 -> 6234 and 4215 -> 3938.
- **`validation::Result::add_error(path, rule, message, qb::json)` (Huly QB-1008).** The call a
  `CustomRule` makes with the `const qb::json &` it received did not compile under nlohmann 3.12
  (vcpkg, Homebrew): json's conversion operator to `std::optional<json>` competes with the optional's
  constructor. A member template constrained to a `qb::json` argument, of any value category,
  delegates to the `std::optional` form; any other value -- a string, a number, `std::nullopt`, a
  `std::optional` -- keeps that form and its behaviour. A plain `const qb::json &` overload, the
  first design, made each of those calls ambiguous under nlohmann 3.11 and 3.12 alike, this module's
  own parameter validator included.
- **`RecaptchaResult::has_challenge_ts` (Huly QB-537).** Whether Google's reply carried a
  readable `challenge_ts`, beside `has_score`; appended after `challenge_ts`, so positional
  aggregate initialisation keeps compiling.
- **`qb::http::MessageHead{msg}` writes a message's start line and header section, and nothing after them (Huly
  QB-493).** `out << MessageHead{request_or_response}` validates exactly as the full serialization and stops at the
  empty line that ends the header section: no body, no chunked last-chunk. The HTTP/1.1 server session now writes
  every `HEAD` response this way, and it is the head to write before a body streamed by hand as `Chunk`s (see the
  complete-message entry under Changed).
- **HTTP/3 active cancellation retains the client through its callback (Huly QB-960).** A
  cancellation callback may release the last external `shared_ptr`; the client stays alive until
  the active stream has been reset and the pending queue has resumed.
- **HTTP/3 request and response bodies advance past the initial QUIC receive window (Huly QB-503).**
  The receiver now returns flow-control credit for every DATA payload handled by nghttp3, including
  bytes discarded when a stream is refused. nghttp3's separate consumed-byte count continues to
  cover framing. Direct adapter tests check exact credit in both directions, and a QUIC/TLS loopback
  crosses multiple small stream and connection windows.
- **WebSocket client connection hardening (Huly QB-513, QB-609, QB-517).** A client destroyed
  during an in-flight transport connect no longer leaves a callback that can access it. A
  nonzero connect timeout now covers the transport and the HTTP Upgrade as one deadline, with
  one failure completion when the server withholds its response. A retry started from that
  failure callback waits for the retired transport to finish closing and drops its buffered bytes.
  Parsed handshake errors, established notifications and disconnect callbacks run after parser
  dispatch, so they may release the client;
  a request hook that cancels or replaces an attempt cannot send its retired Upgrade. A peer
  close before the 101 reports a failed connect, and clients reject a 101 response that selects
  an extension they did not offer. The qb-io integer and typed `disconnect(reason)` overloads
  remain available through the WebSocket client.
- **A coroutine parked on a client request says so in qb's `CoroutineScheduler::dump()` (Huly QB-71).** `http_awaiter`
  -- every coroutine form of the client -- begins its `await_suspend` with `qb::io::async::track_suspension(h,
  "http")`: with suspension tracking on, the dump shows the coroutine waiting on `"http"`, for how long. An awaiter
  without the call would leave the coroutine with the record of its previous wait, ageing. Off -- the default -- the
  call is one predictable branch. Pinned by `TheDumpSaysACoroutineWaitsOnARequest` in
  `tests/system/coro/coro-client-http1.cpp`; qb's `scripts/check-awaiter-tracking.py`, run over this module from the
  superproject, refuses an awaiter without it.

- **`RequestIdMiddleware`: one id per request, generated or propagated, in the context and the
  response (Huly QB-166).** `<qbm/http/middleware/request_id.h>`: `request_id_middleware<S>(options)`
  (tag `middleware::tags::request_id`, listed in `all.h`) gives each request a random UUID version 4,
  stores it under `qb::http::request_id_slot` (`Slot<std::string>`, the key `"request.id"`) and sets it
  in the response header (`X-Request-ID`, `RequestIdOptions::header()` names another) before the
  handler runs. The client's id is not trusted by default; with `trust_incoming_id()` it is adopted
  only when it is 1 to 128 characters of `[A-Za-z0-9._-]` (`is_valid_request_id`), and replaced
  otherwise -- never echoed, since the id goes into logs unchanged.

- **`Context::route_pattern()` and router observers: `Router::add_observer(std::shared_ptr<IRequestObserver<S>>)`
  (Huly QB-90).** `route_pattern()` names the route that matched in its canonical form (`/users/:id`,
  `/files/*path`, `/`, whatever slashes the registration used; a 405 names the route whose path matched; empty
  for a 404), a view of the compiled route names the context's chain retains -- what a metric or a log names a
  request by, since the raw path's cardinality is the client's to choose. `<qbm/http/routing/observer.h>`: an
  `IRequestObserver<S>` is told `on_request(ctx)` when the router creates the request's context and, exactly once,
  `on_response(ctx, RequestEnd{outcome, duration})` when its response is decided -- after the `PRE_RESPONSE_SEND`
  hooks and the hand-over to the session, before `REQUEST_COMPLETE`: every routed request, a 404, a 405, an error
  chain, the early path-length 400, a client that left (`SESSION_GONE`) and a suppressed response (`SUPPRESSED`,
  at the context's destruction). `duration` runs from the router receiving the request to the response handed to
  the session (the protocol's serialization included, the transmission not). Unlike router lifecycle hooks, which
  are copied into every context, an observer costs no allocation per request. A router with none pays a null-pointer
  test when it creates a context and one when it finalizes it (two instructions in
  `Context::finalize_processing_internal`, g++-14 -O3), the route pattern carried from the matched node, and the new
  context members (40 bytes inside its existing allocation) initialised and destroyed: measured with callgrind on
  g++-14 release against develop `d5f2d32`, a routed request costs 22 to 25 more instructions for a match (of 5 500
  to 8 000, +0.3 to +0.4 %) and 6 more for a 404. A request a session refuses before routing (414, 431, 413)
  reaches no observer.

- **`AccessLog` and `RequestMetrics`: an access log and request metrics, as router observers (Huly QB-90).** The
  ticket named them `AccessLogMiddleware` and `MetricsMiddleware`; they are observers (`Router::add_observer`), not
  chain tasks, and are named for what they are: they see every request the router routes -- a 404, a 405, an error
  chain, the early 400, a client that left -- once its response is decided, with no allocation per request.
  `<qbm/http/middleware/access_log.h>`: `access_log<S>(sink, formatter)` writes one line per request to a sink, in
  `access_log_format::common` or `combined` (Apache's lines, byte for byte, UTC, Apache's escaping) or `json` (one
  object per line, with the request id `RequestIdMiddleware` gave the request, the route pattern, the duration and
  the outcome); a formatter of your own receives an `AccessLogRecord`; the line buffer is reused; a throwing sink is
  contained. `<qbm/http/middleware/metrics.h>`: `request_metrics<S>(options)` counts
  `qb_http_requests_total{method,route,status}`, `qb_http_request_duration_seconds{method,route}` (a histogram,
  `qb::metrics::default_duration_buckets` unless `with_buckets`) and `qb_http_requests_in_flight`, labelled by route
  PATTERN (`unmatched` for none), never by raw path; plain integers of the router's thread, a series allocated on its
  first sighting; `collect(snapshot&)` describes them for a `qb::metrics::Registry` source. `add_connections(snapshot,
  protocol, open)` describes `qb_http_connections{protocol}`. Both listed in `middleware/all.h`. Measured with
  callgrind (g++-14 release, a router of 19 routes, a request with a query, a 101-byte `User-Agent`, a `Referer` and a
  request id: 16 150 instructions with no observer): `common` about +1 520 instructions a request, `combined` +2 040,
  `json` +2 440, `RequestMetrics` +530. The line is built in a stack buffer, its quoted fields are scanned sixteen
  bytes at a time and copied whole between escapes, and its time is formatted once a second per thread; the JSON
  `duration_seconds` is rounded to the microsecond.

- **The `/metrics` endpoint: `metrics_handler<S>(actor, options)` and `metrics_response<S>(ctx, snapshot)` (Huly
  QB-154).** `<qbm/http/middleware/metrics.h>`: a coroutine route handler that scrapes every core's
  `qb::metrics::Registry` (`qb::metrics::scrape`, through the registry of the actor's own core) and answers the
  Prometheus text format 0.0.4 (`Content-Type: text/plain; version=0.0.4; charset=utf-8`): the core counters of each
  core, `RequestMetrics`, the sources of the other modules. A core that does not answer within
  `MetricsEndpointOptions::timeout` is `qb_scrape_core_up{core} 0`, never an error. Opt-in and mounted explicitly:
  the endpoint exposes the process's internals.

### Changed

- **Schema patterns search within strings (Huly QB-548).** JSON Schema `pattern` now uses
  unanchored ECMAScript search, including nested schemas and `propertyNames`; use `^...$`
  when the whole field must match. Standalone `PatternRule` keeps full-string matching.
  Both paths retain the pattern/input limits and regex-engine error handling, and schema
  rules remain compiled once per cached node.
  A leading `^` without alternation now restricts the search to the original starting position,
  avoiding pointless retries on long rejected inputs; it still accepts partial matches such as `^es`
  on `estonia`. A complete positive ASCII character class, optionally followed by `+`, searches
  its byte set directly; contiguous sets use bounded SIMD loads on SSE2 targets. Other expressions
  retain general regex search, including negation, escapes, nested classes and additional syntax.
  Regex compilation still validates every pattern. Both pattern paths read the JSON string by
  reference instead of copying it. Rejection cost can still grow with input length, because a
  valid match may occur at the final byte.
- **Static-file validators and conditional ranges (Huly QB-541).** Metadata-derived ETags
  are now marked weak (`W/`): size and second-resolution modification time do not identify
  exact file bytes. `If-None-Match` retains weak comparison, including previously issued
  tags. `If-Range` can no longer authorise a partial response with these weak tags or with
  filesystem dates whose strong-validator status cannot be established; the response is
  the full representation with 200, even for a malformed or unsatisfiable Range. Ordinary
  Range requests still produce 206/416, HEAD still sends no body, and cache preconditions
  are evaluated first. Weak tags use a compact opaque encoding built in bounded stack buffers;
  legacy decimal validators remain accepted on conditional requests. The response owns its
  header value. No content hashing, narrowed metadata or additional file read is introduced.

- **JWT generation and verification share the configured-algorithm mapping.** The ten
  supported algorithms and existing fallback retain their behavior; signing and
  verification still select their private/public keys separately. Auth-manager tests
  now assert the emitted algorithm name independently of the sign/verify round trip.

- **The HTTP/3 server's `graceful_shutdown()` sends its two GOAWAYs a round trip apart (Huly QB-91;
  RFC 9114 §5.2).** It sent the shutdown notice and the final GOAWAY back to back, which left the
  requests already on their way no time to arrive before the final GOAWAY rejected them: the
  notice goes first, the final GOAWAY two smoothed round trips later (at least 1 ms), and the call
  returns at once. Unlike `drain()`, it serves a connection made afterwards and reports nothing.
  Witness: `qbm-http-test-system-http3-loopback`
  (`GracefulShutdownSendsTheNoticeThenTheFinalGoawayARoundTripLater`, red on the previous tip: the two
  GOAWAYs arrived together).
- **A request over the body cap is answered `413 Content Too Large`, on HTTP/1.1, HTTP/2 and HTTP/3,
  and the cap is the server's own `set_max_body_size` (Huly QB-168).** HTTP/1.1 closed the connection
  with no answer at all: the parser refused the message and the protocol was invalidated. HTTP/2 reset
  the stream with `ENHANCE_YOUR_CALM`, against the HTTP/1.1 constant; HTTP/3 reset it with
  `H3_REQUEST_CANCELLED`, a client's 502. Now the answer is the same whatever the version: HTTP/1.1
  sends `413` with `Connection: close` after every request the client sent before the refused one,
  drops what the client sends meanwhile, and closes after that delivery -- after the client, through
  qb-io's lingering close (Huly QB-1089), so a client still uploading reads the answer: on Windows a
  client sending 4 MiB lost it 39 runs in 40 when the server closed at once; HTTP/2 answers `413` on
  the stream, then `RST_STREAM(NO_ERROR)` (RFC 9113 §8.1), and the connection goes on; HTTP/3 answers
  `413` on the stream, then STOP_SENDING with `H3_NO_ERROR` (RFC 9114 §4.1.1). A declared length over
  the cap is answered before a byte of the body is read on all three. `set_max_body_size(std::size_t)`
  / `max_body_size()` are new on the HTTP/1.1 and HTTP/2 servers -- the HTTP/3 server's name -- read
  live (a request that begins after the call is judged under the new value), 0 meaning none; the
  defaults are unchanged (`protocol_limits::MAX_BODY_SIZE`, 100 MiB; 64 MiB on HTTP/3). The HTTP/1.1
  requests of the HTTP/2 server's ALPN fallback get the HTTP/1.1 answer. The HTTP/1.1 sessions no
  longer apply the transport's generic message cap (`QB_MAX_MESSAGE_SIZE`): it cut, with no answer, a
  request whose body was at the default cap -- its header section put the message past 100 MiB; the
  protocol states its bounds and answers a breach. A `Connection: close` response, and the HTTP/2
  server's HTTP/1.1 fallback, also close after the client now, through `close_after_deliver()`.
  Witnesses: `qbm-http-test-unit-http1-protocol-framing`, `-unit-http2-server-protocol`,
  `-unit-http2-server-coverage-deep`, `-system-make-server-factory-http1`,
  `-system-make-server-factory-huge-body` (new, label `huge-body`), `-system-make-server-factory-tls`,
  `-system-http3-connection-direct`, `-system-http3-loopback`.

- **The request limits are the server's, set at run time, and every version answers a request over one
  the same way (Huly QB-94).** `qb::http::request_limits` -- the target, a field name, a field value,
  the regular fields of a section, an HTTP/1.1 chunk, the body; each defaults to its
  `protocol_limits` constant, 0 means none -- is set with `set_request_limits()` / read with
  `request_limits()` on the HTTP/1.1, HTTP/2, HTTP/3 and dual-stack servers (`set_max_body_size()`
  stays, for the body alone) and read as each request arrives. The answers: `414 URI Too Long` for
  the target, `431 Request Header Fields Too Large` for a field name, a field value or a section's
  field count, `413 Content Too Large` for the body or a chunk. HTTP/1.1 sends it with
  `Connection: close` after every request received before it and closes after the client; it used
  to close with no answer for all but the body, against constants. HTTP/2 answers on the stream then
  `RST_STREAM(NO_ERROR)`; it had no field limit at all but the 1 MiB HPACK header list, which stays,
  so a request with a field value past 8 KiB, or more than 100 fields, that HTTP/2 used to route is
  now answered `431` under the defaults. HTTP/3 answers on the stream then STOP_SENDING(`H3_NO_ERROR`)
  once the section is known well-formed; it reset the stream (a client's 502). A trailer section
  counts its fields on its own on HTTP/1.1 too, as HTTP/2 and HTTP/3 count theirs, and HTTP/3 counts
  regular fields only, as the other two do. Clients read responses under the defaults. Witnesses:
  `qbm-http-test-unit-http1-protocol-framing`, `-unit-http2-server-protocol`,
  `-system-http3-connection-direct`, `-system-make-server-factory-http1`,
  `-system-make-server-factory-tls`, `-system-http3-loopback`.
- **`qb::http::RetryPolicy` is qb-io's `qb::io::reconnect_policy` (Huly QB-126).** The struct moved to
  `qb/io/reconnect.h` so qbm-redis, qbm-pgsql and the qbm-http clients share one reconnection policy;
  `qbm/http/retry_policy.h` keeps the name as an alias. Every field, builder and `next_delay()` reads as before.
  It gains `connect_timeout` / `with_connect_timeout()` (zero, the default, keeps each attempt's deadline at the
  client's own `set_connect_timeout()`) and `allows_attempt()`. Its arithmetic is pinned in qb by
  `qb-io-test-unit-reconnect-contract`; the module's `retry-policy` unit test, which pinned the same cases, is gone.

- **One trailer list and one trailer section for HTTP/1.1, HTTP/2 and HTTP/3 (Huly QB-1073).** The
  three protocols kept three lists of the fields a trailer section must not carry, and each refused
  a field another accepted. `qb::http::detail::is_forbidden_trailer_field` is now the one list, their
  union: `content-length`, `transfer-encoding`, `trailer`, `host`, `connection`, `keep-alive`,
  `proxy-connection`, `te`, `upgrade`, `http2-settings`, `proxy-authenticate`,
  `proxy-authorization`. A received trailer section carrying one now refuses the message (HTTP/1.1:
  `http2-settings` added) or the stream (HTTP/2: proxy authentication added, and the client now
  checks the list at all, see Fixed; HTTP/3: `host` and `te` added). The trailer section a message
  sends is built by one function, `qb::http::detail::plan_outgoing_trailers`, for the three; the
  HTTP/2 helpers `announced_trailer_names`, `is_trailer_field`, `announced_trailer_fields`,
  `remove_announced_trailer_fields` and the HTTP/3 helpers `announced_trailers`,
  `is_announced_trailer`, `make_trailers` are replaced by `outgoing_trailer_fields`,
  `prepare_trailed_header_block`, `plan_trailers` and `make_trailer_block` (internal namespaces);
  `HeaderValidator::is_forbidden_trailer_header` answers with the one list. An announced field a
  trailer section must not carry stays in the header section on HTTP/3 as on HTTP/1.1 and HTTP/2:
  HTTP/3 refused the message, after its headers were queued.
- **`Host` and `:authority` leave out the scheme's default port and an IPv6 zone identifier (Huly
  QB-1064).** HTTP/2 and HTTP/3 sent `:authority: example.test:443` for `https://example.test/` --
  `qb::io::uri` fills the default port in -- where HTTP/1.1 sent `Host: example.test`; every protocol
  now sends the latter (RFC 3986 §6.2.3), and a server still rebuilds the same URI, port included. A
  zone identifier (`[fe80::1%25eth0]`) has local significance only and is no longer sent (RFC 9844
  §6). The WebSocket client compared the scheme case-sensitively: `WS://host:80` kept its `:80`.
- **`hpack::convenience::encode_headers` throws on an invalid field (Huly QB-563).** It used to return
  the bytes of the fields ahead of the invalid one as if they were the whole block; it now throws
  `std::invalid_argument` and never returns a partial block. An empty list still returns an empty
  block. The `Encoder` class also gained private state for pending table-size updates: rebuild
  translation units that embed an `Encoder` (the HTTP/2 protocol templates) together.

- **`JwtMiddleware` textual claims and HSTS are corrected observably (Huly QB-553, QB-539).** No
  signature changes. `"jwt_payload"` holds `iss`, `sub`, `aud`, `jti` and `username` as the strings
  that were signed (a numeric-looking `sub` was a JSON number); HSTS is no longer sent on a plain-TCP
  connection for an absolute-form `https://` request target.
- **A refused coroutine WebSocket upgrade left below 300 answers `400` (Huly QB-610).** No signature
  change; a hook that refused with the default `200` (or a `101`) used to send it.
- **An HTTP/3 batch past the pending-request bound gets 503s instead of queuing beyond it (Huly
  QB-499).** No signature change; see the Fixed entry. `Client::push_request` and
  `Client::push_requests` return `false` when the bound refused the request or a batch member (the
  503 already delivered through the callback), as the HTTP/1.1 and HTTP/2 clients do; they returned
  `true` for any non-null callback.
- **The HTTP/1.1 serializers validate each field once, and their refusals are out of line (QB-1066/1067/1068
  follow-up).** Every header name and value was validated twice -- a first pass refused before anything was
  written, a second one, with the same predicates, while writing, whose refusal could no longer be reached. The
  second pass is gone, the refusals are cold out-of-line calls (messages unchanged), the trailer section is written
  by an out-of-line function a message reaches only when it is chunked and announces trailers, and the parser
  stores trailer fields through a callback installed for chunked messages only: a response costs about 27 % fewer
  instructions to serialize, a request 23 %, and parsing what it did before these follow-ups.
- **HTTP/1.1 chunked trailers follow the HTTP/2 and HTTP/3 contract (Huly QB-1067).** A complete chunked message
  writes the fields its `Trailer` header announces after the last chunk instead of in its header section (a field a
  trailer section must not carry stays in the head; a `MessageHead` keeps every field). The parser stores every
  received trailer field in the message's headers, as HTTP/2 and HTTP/3 surface theirs, and refuses a message whose
  trailer section carries a field that frames, routes or manages the connection, as they refuse their stream.
- **The typed `Content-Type` is derived from the raw header on first read, and nothing is allocated for the
  defaults (Huly QB-506 follow-up).** `content_type()` parses the raw `Content-Type` header (its first value,
  or the defaults) the first time it is read after a message was built, parsed, or had that header changed
  through `set_header`, `add_header`, `remove_header` or `set_content_type`; `refresh_content_type()` only marks
  it for re-derivation. The HTTP/1.1 parser no longer parses it for every header section it frames, nor does
  `set_content_type` parse it (twice) at every call: a message whose typed Content-Type nobody reads never parses
  it, and a reader pays one parse. A `ContentType` holds empty strings for the defaults and reports
  `application/octet-stream` / `utf-8` from one process-wide `std::string` each, so constructing a message no
  longer heap-allocates a 24-byte string it will most likely never show; `ContentType()` is the defaults,
  `assign(value)` re-parses in place. `content_type()` is no longer `constexpr` (it could not be evaluated at
  compile time before either). The derivation is a `const` read's side effect on `mutable` members; a message
  is, like every qb object, used by one thread at a time.
  A parameter list in the plain shape (`name=value` tokens, no quote, no backslash, no control byte) is read
  without the attribute state machine, with the machine's exact verdict; every other shape still goes through it.
- **Serializing a `Request` or `Response` writes a COMPLETE message: an empty chunked body is its last-chunk (Huly
  QB-493).** A message declaring `Transfer-Encoding: chunked` with no body used to serialize as its header section
  alone, which left the peer waiting for a body that never came (RFC 9112 §7.1). Behaviour change, source compatible:
  code that relied on that header-only output to stream its own `Chunk`s afterwards writes
  `qb::http::MessageHead{msg}` first instead. The repository's one such site, the `http1-loopback` chunked round
  trip, now does.
- **The request serializer refuses a request-target byte the request line cannot carry (Huly QB-494).** SP, HTAB, CR,
  LF, NUL, any other control byte and DEL in the URI's raw query now throw `std::length_error` before a byte is
  written, as an invalid header value already did: `qb::io::uri` keeps the query's raw bytes (its path admits only
  path characters already), so percent-encode them.
  Percent-encoded forms and every printable byte keep their exact bytes. A one-shot client answers such a request
  400 without sending it; the persistent client already answered a serialization failure 400.
  The check takes sixteen bytes per step where SSE2 is the baseline (eight elsewhere) and re-reads the last block
  overlapped instead of looping over a tail, so a query costs one block per sixteen bytes and nothing else.
- **`Body::as<Multipart>()` refuses a document its closing delimiter does not end (Huly QB-491).** A body that stops
  inside a part or its headers now throws, and `try_as<Multipart>()` yields `nullopt`, instead of returning the
  parts read so far as a complete document. Bytes after the closing delimiter (the epilogue) stay ignored.
- **The HTTP/1.1 parser accepts a trailing horizontal tab after the `Content-Length` digits and after `chunked`
  (Huly QB-555).** It is optional whitespace (RFC 9110 §5.6.3), as a trailing space already was; the message frames
  exactly as the space form does. Such a request used to be refused, and such a response read until the connection
  closed. A local patch of the vendored llhttp, recorded in `THIRD-PARTY-NOTICES`.
- **HTTP dates refuse a fixed-width numeric field that is not all digits (Huly QB-599).** `08:4x:37` or a signed
  two-digit year used to parse (as `08:04:37`, or the year 1991 for `-9`); they now yield `nullopt`, as the
  `parse_http_date` contract promises for an unknown format. Cookie `Expires` and `If-Modified-Since` read through it.
- **The HTTP/1.1 status line carries the registered reason phrase, and `Status::str()` returns it (Huly QB-1062).**
  `400 BAD_REQUEST` and `101 SWITCHING_PROTOCOLS` were llhttp's enum identifiers; the line now reads
  `400 Bad Request`, `101 Switching Protocols` -- the IANA registry's text (RFC 9110: 413 `Content Too Large`, 422
  `Unprocessable Content`), a defining document's for 306, 418 and the unregistered codes llhttp maps. Behaviour
  change, source compatible: `str()`, the string conversions, `std::to_string(Status)` and `operator<<` return that
  phrase, as their documentation always said, instead of the identifier -- so does the logging middleware's
  `"404 Not Found"`. The serializer writes it from a static table without building a string. Header names keep
  going out in lower case, now documented: field names are case-insensitive, and `Headers` keys them folded.
- **HTTP coroutine and routing templates require consistent consumer headers (Huly QB-511, QB-535, QB-514, QB-498).**
  Context hook/cancellation bookkeeping, HTTP/2 reclamation state, and coroutine WebSocket waiter storage have changed privately.
  Public method signatures remain, but WebSocket receive and close methods return newly deduced concrete
  awaiter types through `auto`. Rebuild translation units and application boundaries that share these
  template specializations together; ordinary HTTP callback factories keep their existing contracts.

- **Paired schema length bounds share one Unicode scan (Huly QB-549).**
  Cached `minLength` and `maxLength` evaluation uses one validated code-point count,
  retaining ordered keyword errors, offending-value policies and array behavior.
  Standalone length rules and parameter validation keep their existing evaluation.
  Two-byte UTF-8 blocks check all overlong leads together; exact unsigned numeric
  comparisons read the guarded integer storage without generic conversions.
  Cached schema numeric rules specialize their scalar bound once when compiled,
  preserving exact comparisons, diagnostics and non-finite-bound errors.
  Standalone numeric rules retain their JSON storage and object layout.

- **Early WebSocket frame queuing stays outside established dispatch (Huly QB-513).**
  A cold helper builds the owning queue entry; established-message forwarding keeps a
  smaller compiled path while retaining payload ownership and delivery order.

- **HTTP/2 batch completion callbacks may disconnect or enqueue another batch (Huly QB-496).** The completed
  batch now leaves the registry before invoking user code, so a disconnect cannot free its iterator during
  callback return. Ordered responses and callback cardinality are preserved.
- **HTTP/2 pending sends tolerate a failure callback that disconnects or replaces the client (Huly QB-926).**
  The client retains itself while draining the queue and checks the connection and protocol again before each
  send, so a callback cannot make the next request use a retired connection.
- **HTTP/3 callbacks can close or release their client during event delivery (Huly QB-501, QB-924, QB-927).**
  A `disconnect()` reached inside an nghttp3 read marks the client down immediately and waits until that read
  returns to destroy the protocol, close QUIC and fail remaining active work. GOAWAY's pending-request callbacks
  continue to run during the read. Reentrant connect attempts fail, new requests receive `503`, and that explicit
  close does not start an automatic reconnect. A callback that releases the last external `shared_ptr` leaves the
  client alive until the endpoint has finished dispatching the event.
- **HTTP/3 retries start with a retired transport and request cohort (Huly QB-929).** Connect-start failures,
  timeouts and remote closes close the old QUIC transport before failure callbacks can initiate another attempt;
  those callbacks see the old requests failed before they queue new work. On retry, the qb-io endpoint refreshes
  its internally owned native backend.
- **An HTTP/3 connect timer belongs to one attempt (Huly QB-500).** A cancelled attempt reports failure to its
  connection callbacks once. Its timer cannot time out a later attempt on the same client, even if that later
  attempt is still connecting when the old deadline passes.
- **HTTP/3 pending sends stop after a reentrant teardown (Huly QB-931).** The queue drain retains the client and
  rechecks connection, protocol and shutdown state before each submission, including after a failed submit and
  its callback.
- **HTTP/3 can serve sequential requests past the initial QUIC stream limit (Huly QB-934).** For a
  client-initiated request stream delivered through ngtcp2's `stream_open` callback, qb returns its
  bidirectional slot on close; ngtcp2 handles implicit openings itself. A loopback client completed 130
  sequential requests on one connection with the default limit of 100.
- **A synchronous QUIC close during HTTP/3 submission settles the in-between request (Huly QB-932).** The
  client defers teardown until native submission returns, then gives a `503` to the request already removed
  from the pending queue before it could enter the active registry. That notification still runs if an old
  request's failure callback throws during teardown; the saved exception propagates afterward.
- **HTTP/3 connect and disconnect transitions finish notification after a callback throws (Huly QB-933).**
  A throwing connection or request callback no longer strands the close or silently skips the other callbacks
  in that transition; explicit disconnect completes transport cleanup before propagating the saved exception.

- **The compression middleware offers zstd and brotli, and never chooses a codec the build cannot produce (Huly
  QB-93).** `CompressionOptions`'s default list is the codecs of `{zstd, br, gzip, deflate}` this build registers --
  `{gzip, deflate}` unless qb was built with the opt-in `QB_WITH_ZSTD` / `QB_WITH_BROTLI` (qb, Huly QB-79), and empty
  without compression; `max_compression()` holds `{br, gzip, deflate, zstd}` and `fast_compression()`
  `{zstd, deflate, gzip, br}` the same way. A browser rates every codec it lists at 1, so this order is what it gets.
  It is measured (qb's `compress-codecs` bench, a provider per stream, MSVC and g++-14): zstd compresses JSON and HTML
  1.6 to 4 times as fast as gzip at 4 KiB and 6.8 to 14 times as fast from 64 KiB, within 8 % of its ratio, and the
  middleware compresses on the loop that serves the connection; brotli's output is 0 to 17 % smaller than gzip's, as
  fast or faster from 64 KiB and up to 1.7 times slower at 4 KiB. Negotiation now passes over a name the build does
  not register: listed ahead of an accepted codec, it was chosen, refused by `Body::compress`, and the response went
  out uncompressed. The HTTP/1.1 client already advertised every registered codec (`accept_encoding()`). Pinned by
  `tests/unit/middleware/middleware-compression.cpp` -- the three lists in every build (both codecs, neither, no
  compression), a browser's `Accept-Encoding` answered with the first codec of the default order and decoded, an
  unregistered name passed over -- which catches five defects planted one at a time.

- **`LoggingMiddleware` prefixes its two lines with `[<id>] ` when the request has an id (Huly
  QB-166).** When `request_id_slot` is set -- a `RequestIdMiddleware` ran before it -- the request and
  response messages read `[<id>] Request: GET /path` and `[<id>] Response: 200 OK`; without an id they
  are unchanged.

### Fixed

- **Gateway test refusal-port ownership.** Keep the refused upstream's loopback
  port bound without listening until the gateway has stopped. A later ephemeral
  bind can no longer reuse the target; the refusal case also checks that another
  listener cannot take the reserved port. Runtime behavior is unchanged.

- **Redirect callback test isolation.** Run the throwing-completion lifetime
  oracle on a fresh thread-local listener. Pending slots inherited from an earlier
  test no longer fail its setup; the callback-count, capture-release and final
  no-work checks remain intact.

- **Verify the WebSocket benchmark's actual echo (Huly QB-519).** The server serializes the decoded
  message during its callback, while that message is valid. The preflight checks exact wire bytes
  and an inverse client decode, and rejects same-size payload and opcode corruption. The cell is
  renamed from `BM_WS_EchoRoundTrip` to `BM_WS_ServerEchoText`: its timed span covers server decode
  and serialization, without a socket, handshake setup or client decoding. This corrects the
  measurement fixture, not the production codec. Compare both revisions using this same fixture;
  historical measurements from the former cell are not directly comparable.
- **HTTP/1.1 and HTTP/2 clients wait for the final response after informational responses
  (Huly QB-508).** `100 Continue`, repeated `103 Early Hints` and other non-upgrade 1xx
  responses no longer complete a request, advance the HTTP/1.1 queue or cancel its timeout.
  Their fields are discarded; callback and coroutine results contain the final response.
  HTTP/2 accepts informational HEADERS split across CONTINUATION frames and preserves the
  connection's HPACK state. A 1xx with END_STREAM, HTTP/2 status 101, or DATA before final
  headers resets that stream with PROTOCOL_ERROR. HTTP/1.1 status 101 keeps its existing
  upgrade handling. Request bodies are still sent immediately; this adds no Expect handshake
  or informational callback API.

- **HTTP/2 stream errors retire their protocol state before notifying user code.** A handler
  that re-entered RST_STREAM for the same stream could trigger a second error notification
  and leave the outer reset reading freed state. The dormant reserved-push rejection path
  likewise no longer writes to the stream after resetting it. Public server push remains disabled.

- **Wall-clock timing for fragmented benchmark windows (Huly QB-1116).** Select `UseRealTime()`
  for warm and first-request access logging, warm HTTP/3 response/data-credit handling, static-hit,
  parameter-hit and miss routing, and WebSocket masked decoding and echo. Durations and rates use
  the instrumented wall-clock windows, avoiding rate calculations from CPU fragments rounded to
  zero. Work, pauses and validation stay unchanged; timing-boundary overhead remains, so this is
  not a pure operation cost. The `/real_time` series stays separate from historical CPU results.

- **HTTP/1 serialization preserves an explicitly empty query (Huly QB-169).** A request for
  `/path?` keeps its trailing `?`, including when written through `MessageHead`; it previously
  became `/path`. URI fragments remain absent from the wire target. The serializer acquires
  output space once for the method, separator, path and optional query, avoiding repeated
  pipe capacity and alias checks while retaining every validation before the first write.

- **Source and test comments follow the current handlers (Huly QB-1102).** Correct stale
  authentication, Cookie, date, frame-parser, WebSocket and multipart references. Describe
  malformed Base64 as an empty decode result, and distinguish nonempty CONTINUATION sequencing
  from the separate empty-frame test. Request handling and test assertions are unchanged.

- **An HTTP/3 graceful close could overtake its GOAWAY, and carried no HTTP/3 code (Huly QB-91).** A
  shutting-down connection with no request open was closed as soon as the final GOAWAY was handed
  to QUIC; `CONNECTION_CLOSE` overtakes the stream data QUIC still holds and is never retransmitted,
  so the client could miss the one frame that tells it which requests were never processed. The
  close now waits until the peer has acknowledged the control stream that carries the GOAWAY, and
  carries `H3_NO_ERROR` (0x100) instead of 0, which is no HTTP/3 error code. Not witnessed by a
  test: a loopback loses no packet, and qb-io does not report the code of a peer's
  `CONNECTION_CLOSE`.
- **Benchmark workload oracles (Huly QB-584, QB-585).** The fragmented HTTP/1.1
  driver resumes at the parser's actual pause position, including the remaining
  body bytes in the same fragment. Untimed probes check the complete message,
  callbacks and every single split boundary; body-bearing cells require message
  completion. Historical fragmented POST timings measured incomplete work and
  are not comparable to the corrected cell. The routing benchmark also checks
  pass-through middleware count and registration order with an untimed probe
  session, while retaining the original empty callback in the measured session.
  These changes affect benchmark fixtures, not the protocol or router runtime.
- **The HTTP/2 client refuses a response trailer section that frames, routes or authenticates
  (Huly QB-1073).** It checked only the connection-specific fields there: a trailer `content-length`,
  `trailer`, `proxy-authenticate` or `proxy-authorization` was accepted and merged into the
  response's headers. The stream is now reset (`PROTOCOL_ERROR`), as the server does for a request.
- **The HTTP/2 client completes a response whose trailer section was not announced (Huly QB-1073).**
  The `Trailer` header is a SHOULD (RFC 9110 §6.6.2); a header block that ends the stream after the
  DATA frames is the trailer section (RFC 9113 §8.1), split over CONTINUATION frames or not. The
  client reset such a stream ("Multiple HEADERS frames not as trailers"). A second header block that
  leaves the stream open is still refused.
- **An HTTP/2 response with an empty body sends its trailer section (Huly QB-1073).** Its leading
  HEADERS ended the stream, and the announced trailer fields, taken out of them, were sent nowhere.
- **HTTP/3 sends a message whose trailer section is empty or whose body is (Huly QB-1073).** A
  request or response announcing a trailer field it did not set was refused, as was one with trailers
  and no body (nghttp3 ended the stream on the HEADERS without a data reader, and the trailer
  submission failed) -- each after its headers had been queued. The trailer section is now built and
  checked before anything is submitted, and a reader is given whenever trailers follow.
- **HTTP/2 batch admits its members one by one against the pending bound (Huly QB-1063).**
  `qb::http2::Client::push_requests` refused a whole batch with 503s when it would exceed
  `set_max_pending_requests`, its admissible members included. Each member is now admitted as
  `push_request` admits one, as the HTTP/1.1 and HTTP/3 clients do (QB-499). A member past the
  bound gets `503` at its index before anything is allocated for it, the others are sent, and the
  callback runs once, in request order. `push_requests` returns `false` when a member was
  refused, as `push_request` does.
- **HTTP/2 client request trailers are sent once, and always (Huly QB-1061).** The fields a
  request's `Trailer` header announces went out in the leading HEADERS and again in the trailer
  block. When the body fit the flow-control windows, or there was none, that trailer block waited
  for a WINDOW_UPDATE the server had no reason to send, so the request never ended. The client now
  follows the QB-1058 contract, through the same helpers in `protocol/base.h`, shared with the
  server (since Huly QB-1073 `outgoing_trailer_fields` and `prepare_trailed_header_block`). The
  announced fields leave only in the trailer block, which `send_request` sends as soon as the body
  is out. A request that announces fields without setting them waits, on `ClientHttp2Protocol`,
  for `send_request_trailers`; `qb::http2::Client`, which never calls it, sets the new
  `set_explicit_request_trailers(false)`, so the stream ends after the body with an empty trailer
  block instead of waiting for the request timeout. `Http2ClientStream::_expected_trailer_names`
  is gone.
- **HTTP/2 client completes a response that announced trailers and sent none (Huly QB-1061).** A
  response whose `Trailer` header announced fields but whose last DATA frame ended the stream was
  never dispatched: the client waited for a trailer block that could no longer come. END_STREAM on
  DATA now completes it, with no trailer fields, once.
- **HTTP/2 client announces an explicit disconnect with GOAWAY (Huly QB-1059).**
  `qb::http2::Client::disconnect()` closed a live connection with no GOAWAY. It now queues
  `GOAWAY(NO_ERROR)` behind what the connection still had to send, through the new
  `ClientHttp2Protocol::send_shutdown_goaway()`, and lets the io deliver it before the connection
  ends -- its sending side shut down, the server reading the GOAWAY then EOF; a server that stopped
  reading holds that end at most `Client::GOAWAY_FLUSH_LIMIT` (1 s). Every GOAWAY the client sends now names the last stream the
  server initiated that the client accepted (0 while push is disabled), as RFC 9113 §6.8 defines
  it for the sender, instead of the client's own last request.
- **HTTP/2 server sends response trailers in the trailer block (Huly QB-1058).** Every response
  header, announced trailer fields included, went out in the leading HEADERS, and the trailer
  block that ended the stream was empty. The fields a response's `Trailer` header names now leave
  only in the trailer block, after the body; a field trailers forbid stays in the leading block.
  Same contract as HTTP/3. The per-response set that recorded every header sent
  (`Http2ServerStream::headers_sent_in_initial_frame`) is gone.
- **HTTP/2 server answers HEADERS after END_STREAM with STREAM_CLOSED (Huly QB-1058).** A
  HEADERS frame on a stream the client had ended was reset with `PROTOCOL_ERROR`; RFC 9113 §5.1
  prescribes a stream error of type `STREAM_CLOSED`. The client now applies a
  `SETTINGS_INITIAL_WINDOW_SIZE` change through the same `Http2StreamBase` rule as the server.
- **HTTP/2 client's disconnect reaches the server as EOF (Huly QB-1021).** The client is the io of
  every connection it makes, and qb-io's `dispose()` used to stop a standalone client's watcher and
  leave its transport as it was: after an explicit `disconnect()` (or a drained GOAWAY) the socket
  stayed open, and the server kept the connection and its routed contexts alive until the client
  connected again or was destroyed. qb-io's `dispose()` now ends the transport itself (qb QB-1060):
  a connection the client ended has its sending side shut down, so the server reads everything
  queued, then EOF, with no reset. The client relies on it; it does not close the socket itself, a
  full close that reset a server whose bytes it had left unread. The system test
  `AbruptDisconnectWithInflightStreamsIsClean` no longer closes the transport by hand.
- **HTTP/2 batch failure answers its unanswered members with 503 (Huly QB-495).** A failure pass
  (explicit `disconnect()`, connection loss, exhausted reconnection run) detached the batch registry before
  failing the members, so their failures found no batch and recorded nothing, and the final pass
  only answered slots whose status was 0 while an unanswered slot held a default `Response`, a
  `200`: the batch callback (and its coroutine overload) reported those members as empty
  successes. An unanswered slot now holds status 0 until a response fills it; the failure pass
  answers exactly those with `503` and the failure reason, keeps every received response (an
  empty `200` included) and the admission `400`s, and still calls back once.
  `BatchRequestContext`'s layout is unchanged. Witnesses in
  `tests/unit/http2/http2-client-validation.cpp` and `tests/system/http2/http2-client.cpp`.
- **HTTP/2 client renews a connection whose stream identifiers are exhausted (Huly QB-525).** The
  client stream counter grew past 2^31-1: the next id carried the reserved bit, the frame header
  masked it to stream 1 on the wire while the stream map kept the unmasked key, and the request
  never completed. `ClientHttp2Protocol::send_request` now refuses once the last identifier is
  used (`stream_ids_exhausted()`), and `qb::http2::Client` drains that connection like a graceful
  GOAWAY and sends its pending requests on a new one (RFC 9113 §5.1.1). A reset protocol counts
  from 1 again. Witnesses in `tests/unit/http2/http2-client-protocol.cpp` and
  `tests/system/http2/http2-client.cpp`; they reach the bound through `ProtocolTestPeer`, a
  test-only friend the protocol declares.
- **HTTP/2 idle sweep measures idleness from the last progress (Huly QB-531).** Nothing on the
  server ever refreshed a stream's activity time, so the sweep compared every stream's age with
  the 30 s idle budget and cancelled a response still sending like a dead one. Response HEADERS or
  DATA sent and a stream WINDOW_UPDATE received now mark the stream (a flag store on the frame
  path), and the sweep -- which already reads the clock -- stamps the time it observed them; idle
  time runs from there. A request not yet complete keeps an absolute age bound
  (`STREAM_INCOMPLETE_TIMEOUT`), so a slow upload cannot hold a stream. Witnesses in
  `tests/unit/http2/http2-server-protocol.cpp`.
- **A client's graceful GOAWAY lets the server answer its requests (Huly QB-530).** The server
  applied the last-stream-id of a client's GOAWAY to the client's own requests, closing every
  request above it -- all of them for the common `last_stream_id = 0` -- and then the connection,
  before their responses. That id bounds the server-initiated streams the client processed
  (RFC 9113 §6.8): a `NO_ERROR` GOAWAY now drops only the pushes above it and refuses new streams,
  every accepted request is answered, and the connection closes once the last stream finishes. An
  error GOAWAY closes every stream and the connection. Witnesses in
  `tests/unit/http2/http2-server-protocol.cpp`.
- **HTTP/2 server responses: HEAD sends no DATA; a promised stream can be answered (Huly QB-527,
  QB-529).** `send_response` took the body of a HEAD response as content and sent it in DATA
  frames, while HTTP/1.1 and HTTP/3 strip it; a HEAD response now ends the stream on its HEADERS,
  keeping the representation's `content-length` (RFC 9110 §9.3.2). After a successful
  `send_push_promise`, its documented next step -- `send_response` on the promised stream --
  refused the reserved state and reset the stream, so no promise could be fulfilled; the response
  HEADERS now move the promised stream to half-closed (remote) and its end closes it (RFC 9113
  §5.1, §8.4). The push API itself is unchanged (QB-102). Witnesses in
  `tests/unit/http2/http2-protocol-state.cpp` and `http2-server-coverage-deep.cpp`.
- **HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE reaches every sending stream; negative windows are a debt
  (Huly QB-528, QB-532).** The server applied a change of the peer's initial window size to OPEN,
  half-closed (local) and reserved streams but not to half-closed (remote) ones -- the state of a
  response to a finished request -- so a response waiting for credit stayed stuck until a stream
  WINDOW_UPDATE the client had no reason to send. Every stream that can still send now moves by
  the delta (RFC 9113 §6.9.2), through `Http2StreamBase::update_peer_window_size`, which no longer
  refuses a legal negative result nor a decrease near the 2^31-1 maximum; only a window pushed past
  the maximum fails, unchanged. Witnesses in `tests/unit/http2/http2-server-protocol.cpp` and
  `http2-stream-state.cpp`.
- **HTTP/2 keeps the received compression state in step (Huly QB-533, QB-534).** A header block
  the HPACK decoder could not decode reset only its stream, and the connection decoded on with a
  dynamic table possibly changed by the fields ahead of the failure; it is now a connection
  `COMPRESSION_ERROR` (RFC 9113 §4.3). A field that decodes but breaks an HTTP/2 rule still only
  resets its stream. A header block refused without decoding -- over the concurrency cap, during
  shutdown, on a closed or reset stream, after END_STREAM, on both the server and the client --
  left the table behind the peer's encoder, so the next block referencing its entries failed or
  decoded to other fields; refused blocks are now assembled across their CONTINUATION frames,
  decoded and dropped, never routed. Witnesses in `tests/unit/http2/http2-server-protocol.cpp`
  and `http2-client-protocol.cpp`.
- **HTTP/2 header blocks respect the peer's frame size and request trailers follow the body
  (Huly QB-522, QB-521).** Request trailers (explicit and automatic), response trailers and
  PUSH_PROMISE blocks were each written as one frame whatever their size; a block larger than the
  peer's `SETTINGS_MAX_FRAME_SIZE` was refused with FRAME_SIZE_ERROR. Every header block now
  leaves through one emitter that splits it over CONTINUATION frames. Trailers handed to
  `send_request_trailers` while the body still waited for window credit went out at once with
  END_STREAM, and the resumed body followed the end of the stream: the server dispatched a
  truncated request. They now wait for the last DATA frame; a second trailer section is refused,
  and a stream that has sent END_STREAM sends nothing more. Automatic trailer names taken from
  the `Trailer` header value are sent lowercase. Witnesses in
  `tests/unit/http2/http2-client-protocol.cpp` and `http2-server-protocol.cpp`.
- **HTTP/2 framer ends and opens header blocks on empty fragments too; ENABLE_PUSH checked by role
  (Huly QB-497, QB-567).** An empty final CONTINUATION carrying END_HEADERS left the framer
  expecting another CONTINUATION, so the next ordinary frame (a PING, a new request) killed the
  connection with PROTOCOL_ERROR; an empty HEADERS without END_HEADERS escaped the CONTINUATION
  gate. One end-of-block transition now follows every HEADERS, PUSH_PROMISE and CONTINUATION
  frame, empty or not, on both roles (RFC 9113 §6.10). A server's `SETTINGS_ENABLE_PUSH = 1` is a
  connection PROTOCOL_ERROR at the client (RFC 9113 §6.5.2); 0 stays accepted. Witnesses in
  `tests/unit/http2/http2-frame-layer.cpp` and `http2-client-protocol.cpp`.
- **HPACK encoder keeps one compression state with the peer (Huly QB-520, QB-526, QB-563, QB-523,
  QB-524).** A table size change -- the peer lowering `SETTINGS_HEADER_TABLE_SIZE`, or the
  encoder's own capacity -- is announced by a Dynamic Table Size Update at the start of the next
  block, the smallest size reached first (RFC 7541 §4.2, §6.3); the table never exceeds the peer's
  limit. A list with an invalid field is refused whole, with nothing appended and the table
  untouched, so the next block cannot reference an entry the peer never received. A field marked
  never-indexed stays a never-indexed literal on an exact table match (RFC 7541 §6.2.3). Value
  octets 0x80-0xFF are accepted whatever the signedness of `char` (they killed the connection on
  x86-64 GCC/Clang and MSVC builds). `validate_huffman_encoded_data` returns the decoder's verdict:
  eight `'0'` symbols, five zero octets, are valid. Witnesses in
  `tests/unit/http2/hpack-encoder-strategy.cpp`, `hpack-codec.cpp` and `http2-protocol-roundtrip.cpp`.
- **HTTP/3 batches respect the pending-request bound (Huly QB-499).** `Client::push_requests` and
  its coroutine form admit each member as `push_request` would: a member that would take the
  queued + active count past `set_max_pending_requests` completes with a 503 at its index before
  any context or timer is allocated for it. The callback still runs once, in request order, and at
  once when no member was admitted; `push_requests` returns `false` when a member was refused.
- **A moved HTTP/3 connection keeps its callbacks and state (Huly QB-502).** nghttp3 calls back
  with the user data it was given at creation and cannot be told another, so `connection<Owner>`
  now hands it a heap anchor that a move re-points: callbacks reach the destination, and the bound
  local streams, a started shutdown and parked closes travel with it. The source can be destroyed
  at once; the move used to leave every callback on it (a heap-use-after-free under ASan).
- **A moved `dual_stack_server` routes on its own stacks (Huly QB-504).** Explicit move
  construction and assignment keep the router facade bound to the server that owns the stacks; the
  implicit moves copied its pointer to the source.
- **HTTP/3 keeps the brackets of an IPv6 `:authority` (Huly QB-572).** A request to
  `https://[::1]:8443/` sent `:authority: ::1:8443`; the builder now writes the IP literal between
  brackets with the port after them (RFC 3986 section 3.2.2, RFC 9114 section 4.3.1), and the
  persistent client completes a relative target from its base the same way.
- **A WebSocket reconnect after the peer's EOF starts in the same loop pass (Huly QB-1069).** Since
  qb-io's `dispose()` closes a standalone client's transport when the peer ended the connection (Huly
  QB-1060), the cleanup the client defers for it found no socket to close and left the connection
  marked retiring: a `connect()` from the `disconnected` callback waited one more loop pass for a
  launch with nothing to retire. The cleanup now clears that state when the transport is closed
  already.
- **A WebSocket protocol-error observer cannot terminate the process (Huly QB-516).** A frame
  header the parser refuses fails the connection from `getMessageSize()`, which is `noexcept`. The
  failure now marks the connection closed before any application code runs, queues its Close
  once, and contains an exception from an `on(error)` observer of the I/O handler. The public
  client already ran its `on_error` deferred, outside the parser.
- **Lowering a coroutine WebSocket pending cap bounds the queue (Huly QB-518).** A queue already
  above a lowered `set_pending_cap` kept its length, one pop per push; the setter now drops the
  oldest frames down to the new cap at once, on `coro_client` and `coro_session`, and the arrival
  path is unchanged. A cap of 0 still only discards arrivals and never purges what is buffered.
- **A refused coroutine WebSocket upgrade answers an error (Huly QB-610).** A handshake hook that
  returned `false` or threw without choosing a status answered `200 OK`, and one that left `101`
  announced the upgrade it refused. A refusal with a status below 300 is now answered `400 Bad
  Request`; 3xx, 4xx and 5xx are sent as set.
- **A sub-millisecond rate-limit window ends at its own length (Huly QB-536).** The reset, the
  stale-entry sweep and `X-RateLimit-Reset` compared the elapsed time truncated to whole
  milliseconds, so a 500 us window never ended before 1 ms. They compare in the clock's own units.
- **reCAPTCHA `challenge_ts` is the announced instant (Huly QB-537).** The result recorded the
  parsing time. The RFC 3339 timestamp Google sends is now parsed (fraction, `Z` or numeric offset)
  and converted to UTC; an absent or unreadable value leaves `challenge_ts` at the epoch with
  `has_challenge_ts == false`. The verification verdict never depends on it.
- **HSTS follows the connection (Huly QB-539).** `SecurityHeadersMiddleware` decided from the
  request URI's scheme, which an ordinary origin-form request on an HTTP/1.1 TLS connection does
  not carry: configured HSTS was missing on HTTPS. The decision is now the session transport's
  `is_secure()` for HTTP/1.1 and HTTP/2 sessions (RFC 6797 sections 7.1, 7.2), falling back to the
  URI scheme only for a session without a transport (HTTP/3 stream sessions, test doubles).
- **Static files under a filesystem root are served (Huly QB-542).** A root that already ends with
  a separator (`/`, `C:\`) refused every descendant: the containment check demanded a second
  separator. A prefix-sharing sibling of an ordinary root stays refused.
- **The directory listing escapes its link prefix (Huly QB-543).** The request path was written
  raw into `href`, so a legal `&copy;` in it became a character reference. The prefix is now
  escaped for the attribute; percent-encodings are left as they are.
- **One schema-nesting budget per validation (Huly QB-552).** `additionalProperties` and
  `propertyNames` validated through a fresh `SchemaValidator` whose count restarted at zero, so a
  chain of them never met the 64-level bound that `properties`, `items` and the combinators
  enforce. They validate in place now, under the same budget, with the cached rules and without
  copying the sub-schema. The standalone `PropertyNamesRule` is unchanged.
- **A verified token gives back its `User` verbatim (Huly QB-553).** `auth::Manager::verify_token`
  re-read every verified claim as JSON, so an id or username such as `"123"`, `"true"` or `"null"`
  vanished, and a token whose two identifiers looked like JSON was refused. The signed branch now
  reads the token's own payload, as the unsigned branch already did. `JwtMiddleware` keeps its
  claim coercion except for the textual claims (`iss`, `sub`, `aud`, `jti`, `username`).
- **`Headers::has_header` and `remove_header` allocate nothing, whatever the name's length (Huly QB-1068).** Both are
  `noexcept`, and the header map converts a lookup key past its 128-byte stack fold into a `std::string`: a
  `std::bad_alloc` there was `std::terminate`. A longer name is now matched against each stored name. The typed
  `content_type()`'s first read may still allocate; its contract now says so (an allocation failure in that
  `noexcept` read terminates, as one in qb's `push` does).
- **The static files middleware's 304 and 416 responses drop the typed Content-Type too (Huly QB-1068).** They erased
  the raw header, which the typed `content_type()` cached by an earlier read does not follow: a later reader -- the
  compression middleware's content-type check included -- saw the type the response no longer carried. They use
  `remove_header` now.
- **The last field of an HTTP/1.1 trailer section is kept (Huly QB-1067).** The parser stored a field when the next
  one began or when the header section ended; a trailer section has neither after its last field, so it was lost --
  the only one, for a one-field trailer.
- **A refused HTTP/1.1 serialization keeps what was queued before it (Huly QB-1066).** The serializers cleared the
  whole output pipe on a refusal, dropping the responses or requests queued ahead of the refused one -- a
  pipelined response lost because the next was invalid. Every refusal now comes before the first byte is
  written, and none clears the pipe. Behaviour change: the tests that pinned the clearing now pin this.
- **Serializing a `Request` without a method is refused instead of aborting the process (Huly QB-1066).** A
  default-constructed `Request` has `Method::UNINITIALIZED`, and the serializer named the method through llhttp's
  `http_method_name()`, whose switch ends in `abort()`. Such a request, or any method value llhttp does not map,
  now throws `std::length_error`; so does an invalid URI. An empty path is sent as `/` (RFC 9112 §3.2.1), where
  the request line read `GET  HTTP/1.1`.
- **The persistent HTTP/1.1 client delivers a close-delimited response at the peer's close only (Huly QB-1066).**
  It delivered the buffered body as complete on any disconnect, a read or message cap included; it now does so
  only for a graceful close, as the one-shot client does, and the request fails otherwise.
- **`Headers::remove_header` and `CookieJar::remove` find a name passed as a `const std::string` (Huly QB-279).**
  The case-insensitive map's `erase` looked that one key form up unfolded (fixed in qb's `icase_basic_map`), so the
  header or cookie stayed whenever the name passed had an upper-case letter.
- **`set_header` accepts a view of, or the `header()` reference to, the value it replaces (Huly QB-490).** It cleared
  the stored values before building the new one, reading freed storage (a heap-use-after-free under
  AddressSanitizer, garbage bytes otherwise); the new value is now built first.
- **`content_encoding()` keeps a coding refused after the wildcard out of the wildcard (Huly QB-492).** `*, gzip;q=0`
  returned `gzip`: the refusals were collected while walking the field, too late for a `*` listed before them. They
  are collected first; selection still follows the field's order, not the q-values (QB-100).
- **A dispatched HTTP/1.1 message's typed `content_type()` matches its raw `Content-Type` on every framing path (Huly
  QB-506).** Only a chunked message refreshed it; Content-Length, empty, `HEAD` and close-delimited messages kept
  `application/octet-stream`. The parser now refreshes it where the header section ends, and a chunked message
  without a `Content-Type` no longer gains an empty one.
- **The one-shot HTTP/1.1 client answers exactly once (Huly QB-507).** A response delimited by the connection close
  (no Content-Length, no Transfer-Encoding) is delivered at EOF instead of a 502; a session disposed for any other
  reason before a verdict -- a protocol error, a read limit -- answers 502 instead of never, so a coroutine awaiting it
  no longer waits forever; and a compression or serialization failure answers 400 instead of letting the exception
  out of the connect completion.
- **A `HEAD` response that declares `Transfer-Encoding` is sent (Huly QB-493).** The server session added a
  `Content-Length` beside it, which the serializer refuses, and dropped the connection; it now keeps the response's
  own framing and writes its header section only.
- **A copied or moved `Parser` parses into itself (Huly QB-510).** The callbacks reached the parser through a
  self-pointer the implicit copy and move copied verbatim, so a copy wrote into its source -- or into a destroyed
  object. They now find it through the state llhttp executes; copy and move are complete at every phase.
- **`MultipartParser` keeps its end state when bytes follow the closing delimiter in the same feed (Huly QB-491).**
  It returned without committing it, so `succeeded()` was false for any document followed by a CRLF.
- **The vendored llhttp's provenance note says what the code is (Huly QB-554).** The files claimed llhttp 9.2.1 with
  only the symbol prefix changed; they are llhttp at upstream commit 8371b40 (between 9.2.1 and 9.3.0, whose version
  macros still read 9.2.1), with a local `HTTP_UNINITIALIZED` enumerator, an `api.c` wasm table as upstream wrote it
  later, and the QB-555 patch. `THIRD-PARTY-NOTICES` lists each difference and the procedure that regenerates the
  sources, verified byte for byte.
- **API documentation checks reject comment-only names and invalid later citations (Huly QB-561, QB-562).**
  The shipped guard indexes C++ code without comments or literals and examines every
  citation on a line before accepting it.
- **Module build and CI paths cover the code they claim to check (Huly QB-557–560, QB-621).**
  The C llhttp parser receives sanitizer compile flags; scheduled tests check out paired
  `develop` branches; doc-lint runs after checker or workflow edits. The pull request template
  points to the public superbuild recipe and clang-tidy includes module headers.
- **HTTP/1.1 callback reentry preserves the next connection cycle (Huly QB-509).** A closing response
  publishes disconnected state before its callback. Failure notifications settle a detached old cohort,
  while new requests and explicit connect intents survive for the next cycle. Reentrant connect starts
  after old callback/protocol dispatch returns, including with automatic reconnect disabled. Destruction
  still abandons pending connect observers; explicit disconnect reports cancellation once.
- **Lifecycle hook registration stays stable during dispatch (Huly QB-511).** Hooks added by a hook
  become visible after the outermost dispatch returns, preserving active callable state, registration
  order, and isolation between request contexts.
- **Retained request contexts keep route-parameter names valid (Huly QB-512).** Compiled chains retain
  their matching name storage through teardown, 405/error transitions, and `REQUEST_COMPLETE`, including
  contexts retained after their router or session is gone. Standalone copied `PathParameters` still borrow
  key names. A pre-handler hook's completion or error chain is preserved when routing resumes.
- **Conditional cancellation reaches the selected child (Huly QB-535).** Selection is per context and
  reaches nested pending leaves once. Predicate completion/cancellation and a throw after synchronous
  child completion cannot replace newer work. The existing child `cancel()` remains a notification,
  without native-operation preemption guarantees for a shared middleware instance.
- **Destroyed WebSocket awaiters release their waiter reservations (Huly QB-514).** Abandoned receive,
  next-frame, and close waiters no longer block a successor or consume its later completion. A second
  live waiter still fails explicitly; frame buffering and actor cancellation behavior are unchanged.
- **WebSocket close validates before publishing coroutine state (Huly QB-515).** Rejected codes and
  invalid UTF-8 reasons leave a valid later close or peer-close echo available. This does not add a full
  allocation/serialization rollback guarantee for queued bytes or the base WebSocket close state.
- **HTTP/2 full output drain releases completed stream contexts (Huly QB-498).** EOS uses the same
  completed/native-closed collection as write progress. Registry ownership is removed before hooks, and
  reentry or newly queued output cannot invalidate an iterator or earn cleanup before its later write.
  Collection selects batches of 32 IDs with 128 bytes of stack ID scratch and no heap scratch,
  refinds and rechecks each ID, and releases one detached context after POST before considering the next.
  Same-drain rescans catch silent eligibility changes from hooks or destruction, including the no-hook
  case, within a removal budget fixed to the registry size at entry. Selection remains unordered. First-POST
  session extraction cancels the remaining contexts. Public API and Session data members are unchanged;
  this is not a measured performance-gain claim.
- **Neutral HTTP/2 peer resets cancel unfinished routed work (Huly QB-568).** `RST_STREAM(NO_ERROR)`
  reaches the stock session lifecycle without becoming a public stream-error event. Context ownership
  is removed before cancellation; custom protocol I/O handlers acquire no required new callback.

- **JSON Schema validation preserves Unicode and numeric meaning (Huly QB-549, QB-550, QB-551).**
  `minLength`/`maxLength` count Unicode code points rather than UTF-8 bytes, rejecting malformed
  programmatic strings without echoing them in an error. Numeric bounds compare signed, unsigned,
  and floating values without rounding 64-bit integers through `double`; numeric exclusive bounds
  work on their own while the earlier boolean form remains supported. `uniqueItems` and `enum`
  use recursive JSON equality, so mixed numeric representations compare by value even inside objects.
  Long multibyte strings now require a linear Unicode scan where the former byte-count check
  was constant-time; the short-ASCII path remains fast.
- **Static file index paths stay inside the configured root (Huly QB-538).** Directory index selection now checks
  the canonical target and applies the symlink policy before serving the file; its MIME type follows the configured
  index name.
- **Static file validators follow HTTP precedence (Huly QB-540).** A present `If-None-Match` now takes precedence
  over `If-Modified-Since`, including when the entity tag differs or the header value is empty.
- **Request validation keeps error policies and verdicts consistent (Huly QB-544, QB-546).** A body schema now
  receives the request validator's Full, Preview, or None policy and byte budget in either configuration order.
  Nested `additionalProperties` errors keep their already-shaped value when their field path is prefixed, so a
  compound Preview is captured once.
  A parameter rule that returns `false` without adding an error now emits one named for that rule, so both direct
  parameter validation and routed requests reject it; explicit rule errors retain their detail.
- **Validation previews keep complete UTF-8 characters (Huly QB-545).** Truncating a valid multibyte value at
  the preview byte limit no longer turns a JSON validation response into a 500.
- **Sanitized Content-Type refreshes its typed view (Huly QB-547).** A changed raw header is reflected in
  `Request::content_type()` before downstream validation and handlers read it.

- **Out-of-range native unsigned token times are rejected by `auth::Manager` (Huly QB-983).** In the explicitly
  signature-unchecked verification mode, an unsigned `nbf` above `INT64_MAX` could become negative when converted to
  `int64_t` and pass the time check. The manager now checks the unsigned range before converting it; in-range signed,
  unsigned, and string claims keep their existing behavior.

- **WebSocket client connection hardening (Huly QB-513, QB-609, QB-517).** A client destroyed
  during an in-flight transport connect no longer leaves a callback that can access it. A
  nonzero connect timeout now covers the transport and the HTTP Upgrade as one deadline, with
  one failure completion when the server withholds its response. A retry started from that
  failure callback waits for the retired transport to finish closing and drops its buffered bytes.
  Parsed handshake errors, established notifications and disconnect callbacks run after parser
  dispatch, so they may release the client;
  a request hook that cancels or replaces an attempt cannot send its retired Upgrade. A peer
  close before the 101 reports a failed connect, and clients reject a 101 response that selects
  an extension they did not offer. The qb-io integer and typed `disconnect(reason)` overloads
  remain available through the WebSocket client.

- **HTTP/3 `set_verify_peer(false)` takes effect in optimized AppleClang consumers (Huly QB-939).** In an
  AppleClang 21 Release build of a large client translation unit, the inlined setter wrote eight bytes before
  `_verify_peer`. The client still verified a self-signed certificate and failed the QUIC handshake with TLS
  alert 48. The setter now lives in the module binary, preserving its API and object layout while writing the
  intended field.
- **JSON response serialization errors reach the router instead of terminating the process (Huly QB-489).**
  The rvalue `Body` JSON assignment was `noexcept` despite strict UTF-8 validation in the serializer. It now
  propagates the error like const JSON assignment, and both paths clear partial output before throwing. A
  `Context::json` handler can therefore finish through the router's 500 path. Unit tests pin invalid and valid
  UTF-8, the rvalue termination boundary, partial-body cleanup, and the routed error response.
- **One-shot HTTP clients choose TLS for mixed-case HTTPS at an explicit port (Huly QB-505).** The shared
  case-insensitive scheme comparison selects the secure transport. Other schemes fail locally with 400; HTTPS on
  a build without SSL fails locally with 503. Neither rejection opens a connection. Loopback tests cover TLS and
  plaintext servers, including the SSL-disabled build. The paired qb-io default-port lookup (QB-919) now also
  handles portless mixed-case URLs.

- **A large incompressible body survives compression, and a truncated one is refused (Huly QB-464).**
  `Body::compress` and `Body::uncompress` stopped as soon as their INPUT was consumed, not when the codec said the
  stream was done. A codec may take every byte and still hold output -- deflate's stored blocks and the gzip header
  outgrow the `size + 32` window on incompressible data -- so a 1 MiB random body came back 1 048 438 bytes long
  under gzip (1 048 446 under deflate), and `uncompress` accepted the truncated stream as a shorter, valid-looking
  body. The HTTP/1.1 client compresses the request it sends under a `Content-Encoding`, so it sent such a body cut
  short, and every `uncompress` -- the client's on a response, the `CompressionMiddleware`'s on a request -- took a cut
  stream for the whole body. The middleware's own responses were spared: it keeps a result only when it is SMALLER
  than the body, which a stream cut at the `size + 32` window never is. Both loops now run until `done`; `uncompress`
  grows its output geometrically and throws `std::runtime_error` when the stream ends before its end marker. Pinned by
  `tests/unit/message/body-codec.cpp` (1 MiB random and 8 MiB compressible, through every registered codec) and
  `tests/unit/message/body-uncompress-malformed.cpp` (every truncation point of a gzip stream is an error). The zstd
  and brotli codecs (qb, Huly QB-79) failed the same way on the old loops: the random body came back 1 048 575 bytes
  long under zstd, the 8 MiB one 28 bytes long under brotli.

- **A server's listening socket going down now reaches the server, and stops the watcher (Huly QB-252).** The
  acceptor routes `event::disconnected` to the HTTP/1.1 and HTTP/2 servers through `qb::has_own_on`, which could
  not see their private handlers, so it threw "Acceptor has been disconnected" instead; the event loop contained
  the exception, and the throw had left `dispose()` before it stopped the watcher -- the listening socket stayed
  armed on a disposed acceptor, a client then waiting in the backlog made every loop pass dispatch it, and the
  derived server never heard that it had stopped accepting. Both servers now befriend the detector; the HTTP/2
  server forwards `qb::http::event::disconnected` to the derived server and logs, as the HTTP/1.1 one does (its
  handler used to be empty).

- **The router's "deferred completion" system test defers (Huly QB-300).** `AsyncHandlerCompletesOverTheLoop`
  (`tests/system/routing/router-e2e-advanced.cpp`) completed its response from `qb::io::async::callback(...,
  qb::duration::zero())`, which calls the lambda inline before it returns: the response was finished inside the
  handler, and only the immediate path was ever exercised. The route now arms a 1 ms callback and the response
  carries its phase -- whether the handler had returned (`X-Handler-Returned`) and how many loop dispatches completed
  between arming and completion (`X-Dispatches-Between`, from the listener's `total_events_processed()`) -- which the
  test asserts ("yes", above zero). The zero-delay route stays as the control,
  `ZeroDelayCallbackCompletesInlineBeforeTheHandlerReturns`, asserting the other phase ("no", 0). Test only.

### Removed

- **`Http2ServerStream::server_will_send_trailers` (Huly QB-102)** -- a member declared "REVIEW if needed" and
  read nowhere. `ServerHttp2Protocol::send_push_promise` stays: it is a documented, tested public API (push is
  disabled by default, and our client advertises `SETTINGS_ENABLE_PUSH = 0`).

### Documentation

- **The HTTP book and agent reference now match the shipped routing, body, validation, cancellation, and WebSocket contracts (Huly QB-600–606, QB-615, QB-618–620, QB-622).** Coroutine middleware takes only `ctx`; direct group/controller mutations require an explicit recompile; schema validators remain core-local; Body append and assignment sets are distinct; cancellation and error-result paths now state their actual status behavior. WebSocket examples use public headers, `qb::io::uri`, and the callback event argument, and the support policy no longer embeds a stale minor line.

- **`content_encoding()` says what it does (Huly QB-100).** The API sheet said "no q-value weighting" and
  `headers.h` said q-values were not parsed: q=0 or a malformed q refuses a coding, and among the acceptable
  codings the FIRST in the header's order wins, not the highest q -- `CompressionMiddleware` ranks by q itself.
- **Six `readme/` citations re-derived (Huly QB-254).** Each range started on the blank line above the block it
  meant (`03-routing-overview`, `09-custom-middleware`, `10-request-context`, `11-authentication` twice,
  `14-async-http-client`); found by the strengthened `scripts/cite-check.py`, which now reads a range's first line,
  the `src:` form's blank targets, bare basenames, slash-joined lists and citations embedded in prose tokens.

## [3.2.1] - 2026-09-24

### Fixed

- **A malformed HTTP/3 message closed the whole connection, not its stream, for what this module
  checks itself (Huly QB-234).** More than `MAX_HEADERS_COUNT` fields, a field value over its
  length limit, a request method the module does not know, a `trailer` field inside the trailer
  section: each of the four validation sites of the protocol connection failed its nghttp3
  callback, which fails the engine's read, and the read's answer to that is `CONNECTION_CLOSE` --
  every other exchange multiplexed on the connection went down with the malformed one, on the
  server (a request) and on the client (a response); behind a gateway that multiplexes several
  users onto one upstream connection, one user's malformed request failed the others'. RFC 9114
  section 4.1.2 makes a malformed message a STREAM error, and the stream alone is refused now: reset
  with `H3_MESSAGE_ERROR`, what still arrives on it dropped, the message never handed to the router
  or to the response callback, the connection and its other streams untouched, the peer seeing the
  reset (a client's 502) -- the shape the body-over-limit site took in 3.2.0. **The other tier is
  the library's.** nghttp3's own validator runs before any callback (pseudo-header order, presence
  and uniqueness, field-name syntax and a 256-byte name cap in its QPACK decoder, the
  connection-specific fields, content-length arithmetic, `:status`), and what it rejects comes back from `nghttp3_conn_read_stream2` as a negative read:
  by its contract a connection error after which only `nghttp3_conn_del` is legal, so those
  malformations still close the connection -- as they do in every nghttp3-based server, ngtcp2's
  reference server included -- and the docs now say which checks belong to which tier. That close
  carried the raw library code (105, 107) as the QUIC application error code; it carries the H3
  code nghttp3 infers from it (`H3_MESSAGE_ERROR`, `H3_FRAME_ERROR`, the QPACK codes) now, on the
  read and on the write path. Tests: four direct-connection cases feeding the frames a malformed peer
  sends (`*RefusesTheStreamNotTheConnection`; the header-count limit in both polarities), each
  failing against the previous code, one pinning the library tier's error code
  (`AMalformationNghttp3RejectsClosesTheConnectionWithMessageError`), and the loopback
  `ClientRejectsResponseContentLengthMismatch` proving the client's connection serves the next
  request after a refused response.

## [3.2.0] - 2026-09-21

### Added

- **`qb::http::RetryPolicy` (`retry_policy.h`) and the HTTP/2 client's reconnection run (Huly
  QB-103).** The same shape as `qb::redis::RetryPolicy` -- `max_attempts` (-1 = unlimited),
  `initial_delay` 100 ms, `max_delay` 30 s, `multiplier` 2, `jitter` +-25 %, `on_retry(attempt,
  next_delay)`, the `with_*` builders -- plus one pure function, `next_delay(attempt, rng)`, the wait
  after `attempt` failed attempts (the redis arithmetic, in integer milliseconds), so the policy is
  unit-tested on its own. `qb::http2::Client` gains `enable_auto_reconnect(RetryPolicy)` /
  `disable_auto_reconnect()` (the redis names; `set_auto_reconnect(bool)` stays and keeps the
  policy), `is_reconnecting()` and `reconnect_attempts()`. A run is the sequence of attempts between
  a connection loss and the next connection that comes up: attempt 1 immediate, then the policy's
  waits; once exhausted the waiting requests fail with a 503 `Reconnection attempts exhausted (N)`
  and the client stays down until the next `connect()`, explicit or the auto-connect of a later
  push. An explicit `disconnect()` starts no run (the HTTP/1.1 client's `_intentional_disconnect`
  rule): its verdict is `"Connection closed"` and a push after it connects on its own. The
  `connect_timeout` field of the redis policy is not carried: `set_connect_timeout()` applies to
  every attempt. Tests: `unit/retry-policy/retry-policy.cpp` (the arithmetic, its caps,
  its jitter bounds, its pathological inputs) and ten system cases at the end of
  `system/http2/http2-client.cpp` (the run observed end to end against a server that only speaks
  http/1.1: 40/80/160 ms waits measured, the verdict, the count; `max_attempts` 0; the server coming
  back during a wait; a disconnect cancelling the scheduled attempt; a disconnect while connecting;
  jitter spreading a run; a peer drop with a request in flight served by the run; an explicit
  disconnect failing it once and starting none; a deferred connect and a follow-up push both
  served; auto-reconnect off).

### Fixed

- **An HTTP/3 server's `graceful_shutdown()` cut the response it was waiting for.** A connection
  that was shutting down closed as soon as its last handler had answered, that is once the
  response had been HANDED to the QUIC transport. Handed is not sent: the transport's send queue
  holds whatever the congestion window or the pacer will not let out yet, and `CONNECTION_CLOSE`,
  which neither holds back, overtook it. Any response wider than one flight was truncated, every
  time -- a 256 KiB body arrived as a 503 `QUIC connection close received` -- and so was a
  response of a few bytes whenever the pacer deferred its second packet, which a real round trip
  does as a rule and a loopback does on a loaded host (seen once on the arm64 CI guest, as a
  failure of `GracefulShutdownWaitsForActiveAsyncContext`; never in 400 quiet repetitions). The
  connection now closes when its last request stream has CLOSED, which the transport reports once
  the peer has acknowledged the final byte. `graceful_shutdown()` therefore returns with such a
  connection still open and the close follows the acknowledgement; a peer that has gone away is
  ended by the transport's idle timeout, as before. Test:
  `GracefulShutdownDeliversResponseWiderThanTheCongestionWindow`, which fails against the previous
  code on every run and on every platform.
- **An HTTP/3 connection kept every exchange it had ever carried, client and server.** The
  protocol connection keeps state beside each stream -- the request, the response and the copy of
  the body the HTTP/3 engine reads from -- and releases it when the engine reports the stream
  closed. nghttp3 has no view of the transport and reports that only when it is TOLD the QUIC
  stream closed; nothing told it, so the release callback was dead code and the state lived as long
  as the connection: forty requests of 4 KiB over one connection left 43 entries on each side where
  3 requests leave 6. A long-lived connection grew by the size of everything it served. The QUIC
  stream-closed event now reaches the engine (`connection::close_stream()`; a close delivered
  while an engine call is on the stack is parked and replayed when it unwinds, because the engine's
  write vectors point into the stream being freed). `Server::http3_stream_state_count()` and
  `Client::get_stream_state_count()` expose the figure, which follows the requests in flight, not
  the requests served. Test: `StreamStateFollowsRequestsInFlightNotRequestsServed` (43 against 6 on
  both sides without the fix).
- **A body over the HTTP/3 limit closed the whole connection, not the stream.** `set_max_body_size`
  is documented as resetting the stream, and the stream was reset -- then the callback that saw
  the overflow failed, which fails the HTTP/3 engine's read, and the read's answer to that is
  `CONNECTION_CLOSE`: every other exchange multiplexed on the connection went down with the
  oversized one, on the server (a request body) and on the client (a response body). The peer did
  not even see the same error twice: the pacer can hold a `RESET_STREAM` back, nothing holds a
  `CONNECTION_CLOSE`, so it reported now the stream reset (502) and now a lost connection (503) --
  61 times in 300 for `ServerRejectsRequestBodyOverLimit` on a loaded arm64 guest, never on a quiet
  host. The stream alone is refused now: reset in both directions, what still arrives on it dropped,
  the message never handed to the router or to the response callback; the connection and its other
  streams are untouched. Test: `BodyOverLimitRefusesTheStreamNotTheConnection` (the same
  connection serves the next request; without the fix it is gone and the follow-up answers 503).
- **The HTTP/2 client's automatic reconnection was immediate and unbounded, and started from
  inside the handler that observed the failure (Huly QB-103).** `attempt_reconnection()` called
  `connect()` on the spot -- the [`2/client.cpp` L703](https://github.com/isndev/qbm-http/blob/438e977f167e057a757101bd4de504d407dd23de/src/qbm/http/2/client.cpp#L703) comment said "you might want exponential
  backoff" -- so a client with work pending against a server in incident reconnected as fast as
  the failure came back, for as long as its callbacks re-queued. Every attempt now fires from the
  client's own one-shot timer (the connect and request deadlines' mechanism), on the next pass at
  the earliest, so the transport that dropped is disposed before the next one is opened.
- **A request pushed from a failure callback connected on its own, bypassing any reconnection
  policy.** `push_request()` auto-connects when nothing is connecting, and a failure handler had
  already cleared `_is_connecting` when it ran the callbacks, so the retry pattern -- push it back
  on failure -- was itself the immediate reconnection. During a failure pass such a push queues
  behind the attempt the run decides on; with auto-reconnect off it connects at once, as before.
- **Every connection loss failed the re-queued work two or three times.** The `disconnected`
  handler ran a second failure pass over what the first pass's callbacks had just pushed back, the
  `dispose` handler (raised by the same `dispose()`, right after) ran a third with
  `"Client disposed"` and reset the state of a reconnection the disconnected pass had already
  started; the h2 connection-error and non-graceful GOAWAY paths failed once more through
  `disconnect()`'s own pass. One pass now, with the message that says why, from a single
  `close_connection()`; the transport's `disconnected` keeps the re-queued work and decides on the
  reconnection; `dispose` does nothing the disconnected handler has not done.
- **`disconnect()` while a connect was in flight left the connect callback unanswered (a coroutine
  awaiting `connect()` hung) and let the late completion bring the client back up.** The connector
  carries the epoch it was started with; a completion the client gave up on -- its own connect
  deadline fired first, or `disconnect()` -- is dropped and its socket closes. The callbacks get
  `"Connection closed"` at the disconnect.
- **A transport whose TCP+TLS leg came up but whose handshake failed (no h2 over ALPN, no
  protocol) was left open, its watcher registered.** The next attempt's `start()` then found an
  active watcher on a dead fd. It is closed at the failure, and the `disconnected` it raises finds
  the state settled and the pending work preserved.
- **A reconnection sent the previous connection's unflushed bytes ahead of the h2 preface.** The
  client is the io object of every connection it makes and never reset its buffers: a request
  pushed and disconnected in the same tick stayed in `out()`, went out first on the next
  connection, and the server closed that connection with a protocol error (measured: the server
  session's reason -1). `start_connection()` resets `in()`/`out()` now, as the pgsql client's
  `prepare_reconnect()` does.
- **Each attempt of a run leaked its protocol instances.** `start_connection()` switches to a fresh
  handshake protocol and a success to a fresh h2 one; the base keeps every instance until told
  otherwise, so an unlimited run against a dead server grew by two objects an attempt. The
  scheduled attempt clears them before it connects -- from the timer, never from inside a
  protocol's handler.
- The `[Unreleased]` compare link named `v3.0.0`; the module has shipped `v3.1.0` since.

## [3.1.0] - 2026-08-30

Lockstep release with the qb 3.1.0 train; no change in this repository (the version says
compatible, this section says unchanged).

## [3.0.1] - 2026-08-29

Lockstep patch with the qb 3.0.1 train (cut for qb-examples, Huly QB-4). In this repository only
tooling: a nightly CI run against qb's `develop` of the day, and `scripts/gen-llms-txt.py` strips
HTML comments by scanning rather than by regex.

## [3.0.0] - 2026-08-20

Tracks changes not yet part of a tagged release. Since 2026-08-11 that is **both** branches:
`main` was fast-forwarded to `develop` for the release, so the module version is **3.0.0** on either,
in lockstep with the qb framework; see the qb CHANGELOG for what makes that release major.

### Fixed

- **The >100MB body-rejection path was exercised by no lane and no CI job.**
  `{Request,Response}SerializeLimitsTest.BodyExceedingLimitIsRejected` are the only cases that
  *enforce* `protocol_limits::MAX_BODY_SIZE` rather than compare it to a literal, and both sat
  behind `QBM_HTTP_RUN_HUGE_BODY`, which nothing set — so both silently reported `SKIPPED` inside a
  binary ctest called `Passed`. A security limit nothing exercises is a limit nobody knows is
  broken. `tests/CMakeLists.txt` now registers
  `qbm-http-test-unit-http1-serialize-limits-huge-body`, a ctest entry that sets the variable and
  filters to those two cases, so a plain `ctest` runs them; `ctest -LE huge-body` opts back out on a
  memory-constrained runner without dropping the other cases in the same binary. It carries
  PASS/FAIL regexes requiring `2 tests` to have run, because an env var that failed to propagate or
  a filter that matched nothing would otherwise exit 0 and read as coverage — which is how this path
  came to have none.
- **Two installed HTTP/2 headers failed with a raw template diagnostic in an SSL-off install.**
  `qbm/http/2/client.h` names `qb::io::transport::stcp` in its base-clause with no `QB_HAS_SSL`
  guard anywhere in the file, so `#include`ing it (or `2/http2.h`, which pulls it in) directly
  against an SSL-off prefix produced
  `error: no member named 'stcp' in namespace 'qb::io::transport'` — naming neither SSL nor
  HTTP/2. It never fired through the umbrella, because `qbm/http/http.h` already wraps both in
  `#ifdef QB_HAS_SSL`; the installed-header sweep is what reaches them. Eleven sibling headers
  already self-diagnose with an `#error` (`ws/ws.h`, `auth.h`, the HTTP/3 set) — these two were the
  exceptions, and now match.
- **`CMakeLists.txt` had no `cmake_minimum_required()`, and a standalone configure died on an
  unhelpful error.** CMake reported `No cmake_minimum_required command is present` alongside
  `Unknown CMake command "qb_status_message"` — which reads like a missing include rather than
  "wrong entry point". This module is built from the qb-dev superproject, which loads qb's CMake
  helpers first; an *installed* qb ships none of them (`lib/cmake/qb/` carries only `qbConfig`,
  `qbConfigVersion`, `qbTargets` and the `Find` modules), so pointing `CMAKE_PREFIX_PATH` at one
  does not help — the exact mistake the old error invited. There is now a
  `cmake_minimum_required(VERSION 3.24)` and a guard that names the constraint and points at the
  superproject root and the `package` preset.

- **`qbm/http/chunk.h` was not self-contained.** It specialises
  `qb::allocator::pipe<char>::put<qb::http::Chunk>` while including only `<cstddef>`, so a TU whose
  first http include was this header failed on `no template named 'pipe'`. It now includes
  `<qb/system/allocator/pipe.h>`. Found by qb's new installed-header gate
  (`qb/scripts/check-installed-headers.sh`), which compiles every installed header **alone** against
  an installed prefix; the superproject's `package-consume.yml` runs it over the whole `qbm` tree.

### Removed

- **BREAKING — `qbm/http/routing/router.tpp` no longer exists.** Its 39 template definitions moved
  verbatim to the tail of `routing/router.h`, at exactly the position the `#include "./router.tpp"`
  on that file's last line used to splice them into; the preprocessed token stream of `router.h` is
  byte-identical, which is how the move was verified. Nothing is lost and no definition changed.

  This only breaks a consumer who included the fragment **directly** — `#include
  <qbm/http/routing/router.tpp>`. That was never a supported spelling (the file opened
  `namespace qb::http` and defined members of a class it did not declare, so it could not compile
  alone; qb's installed-header gate carried it as a named "by-design fragment" exclusion). Replace
  it with `#include <qbm/http/routing/router.h>`, or with the `<qbm/http/http.h>` umbrella.

  With this the tree contains zero `.tpp` — qb retired its own four in the same release. The
  reason is the one recorded in the qb CHANGELOG: a file included by both the library TU and every
  consumer TU is one non-template line away from a duplicate symbol, and a separate file cannot
  supply what such definitions actually need, which is a *position*.

### Changed
- **`listen()` arms the accept watcher, so a separate `start()` is no longer required** (recorded
  2026-09-20, from `src/qbm/http/1.1/http.h` and `src/qbm/http/2/http2.h`): an extra `start()` stays
  harmless, and `listen_no_start()` is the opt-out for a server that must finish wiring before it
  accepts.

- **Logging call sites use qb's prefixed `QB_LOG_*` macros** (1 sites). qb 3.0.0 renamed
  `LOG_DEBUG` / `LOG_VERB` / `LOG_INFO` / `LOG_WARN` / `LOG_CRIT` to `QB_LOG_*` because the
  unprefixed spellings — three of which are also POSIX `<syslog.h>` names — reached every consumer
  of this module's umbrella header and silently replaced a consumer's own. qb still defines the
  unprefixed names as `#ifndef`-guarded aliases, and that guard is exactly why these call sites had
  to move: a consumer who defines `LOG_INFO` first now keeps their definition, and this module's
  headers would otherwise have started logging through *it*.

- **BREAKING — the public include prefix is now `<qbm/http/...>`** (was `<http/...>`). Every consumer
  edits its `#include` lines: `#include <http/http.h>` becomes `#include <qbm/http/http.h>`. The CMake
  target is unchanged (`qbm::http`), and so is the installed location `<prefix>/include/qbm/http/`.
  The old spelling existed only because `qb_register_module` made this module's include root its
  PARENT directory — the superproject's `qbm/`, which does not exist in this repository at all — and
  mirrored it with `<prefix>/include/qbm` on the consumer's include path. That put the maximally
  generic top-level name `http` in every consumer's include namespace. Now the module's own `src/`
  IS the include root and is copied verbatim to `<prefix>/include`, so `<qbm/http/...>` is the same
  string in this tree and in an installed prefix, and the two cannot drift.
- **The source tree moved to `src/qbm/http/`** — one pure `git mv`, 100 % rename detection, zero
  content change, so `git blame` and every line-numbered citation survive intact. `1.1/`, `2/`, `3/`, `auth/`, `middleware/`, `routing/`, `validation/`, `ws/` and the message types
  at the root moved with it; `not-qb/llhttp/` deliberately did NOT — the fork's `.c` sources and its
  generator-input `api.h` must not become reachable from an include root, and only its single public
  header now sits at `src/qbm/http/vendor/llhttp.h`. `<prefix>/include/qbm/http/.github/workflows/`,
  which the install really was creating as empty directories, is now structurally impossible.
  `tests/`, `readme/`, `scripts/` and `cmake/` live BESIDE `src/`, never inside it, which is what
  makes a stray `#include <tests/fixture.h>` impossible rather than merely unlikely.
  The test suite now includes the shipped spelling instead of resolving `"../http.h"` by string
  concatenation onto a `-I <mod>/tests` flag.
- **`project(qbm-http VERSION ...)` is now `3.0.0`**, tracking `QB_FRAMEWORK_VERSION`. It had been
  left at `2.6.0` while the framework moved on. The module is not standalone-configurable (it calls
  `qb_register_module` / `qb_add_test`, which an installed qb does not ship), so its version can only
  ever mean "the qb this was built against" — and the structural breaks queued for 3.0.0 land hardest
  in the modules, where a package still claiming `2.6.0` would be actively misleading.
- **`scripts/doc-lint.sh` now validates the *value* of the `Verified-against:` markers**, not just
  their presence. It previously checked only that the marker existed, which is how every page in this
  module sat at `qb 2.6.0` across two version bumps unnoticed. The expected version is read from
  `project(qbm-http VERSION ...)` — the one authoritative version available when this repo is checked
  out alone, as it is in its own CI — and cross-checked against `QB_FRAMEWORK_VERSION` whenever a qb
  tree is reachable. A version it cannot determine is a hard stop, never a skip.
- **The default outbound `User-Agent` is derived from the framework version.** It was the hard-coded
  literal `"qb/2.6.0"` in two separate places (`src/qbm/http/1.1/client.cpp`, `src/qbm/http/1.1/http.h`), so every request from
  a post-2.6.0 build advertised a version that was simply wrong. It is now
  `qb::http::default_user_agent` (`headers.h`), composed at compile time from `QB_VERSION`, so it
  cannot drift again; `headers.h` hard-`#error`s if `QB_VERSION` is absent. Callers that set their own
  `User-Agent` are still never overridden.

## [2.6.0] - 2026-08-02

This cycle reworks the accessor surface, the routing/middleware registration API, and the coroutine
handler ergonomics, and hardens the request-stringify, http2 back-pressure, and JWT/auth paths.

### Added

- Concept-driven routing verbs. Each verb (`get/post/put/del/patch/options/head`) on the router,
  route group, and controller now resolves through a single template constrained by
  `RouteHandlerLike` (in `src/qbm/http/routing/coro_task.h`) plus a member-function overload:
  ```cpp
  router().get("/users", [](auto ctx) { ctx->json(...); });          // sync lambda / fn-ptr / std::function
  router().get("/feed",  [](auto ctx) -> qb::io::async::task<void> { // coroutine, auto-detected
      auto reply = co_await qb::http::GET(req);
      ctx->json(reply.response.body().as<qb::json>());
  });
  router().get("/me", this, &MyController::handle_me);               // member-function overload
  ```
  Coroutine handlers are detected via `if constexpr (CoroRouteHandler<...>)`; no explicit wrapper call
  is needed. `del` maps to `qb::http::method::DEL` (the `DELETE` keyword is avoided).
- `*_or` by-value accessor variants for every "miss returns static-empty ref" accessor, so a custom
  fallback no longer collapses into a dangling temporary:
  `Headers::header_or(name, fallback)`, `Request::query_or(name, fallback)` /
  `Request::cookie_value_or(name, fallback)`, `qb::io::uri::query_or(name, fallback)`, and the
  `Context` typed `path_param_or` / `query_param_or` / `get_or`.
- `Context` response sinks `json()` / `text()` / `html()` as by-value move-sinks that set the right
  content type and finalize the task (`complete(AsyncTaskResult::COMPLETE)`); plus `redirect()`,
  `no_content()`, chainable `status()`, and the `bad_request/unauthorized/forbidden/not_found/internal_server_error`
  shorthands.
- Unified middleware entry point `qb::http::middleware::make<Tag, SessionType>(args...)` dispatching to
  the per-family factories via tags in `qb::http::middleware::tags::*`; unknown tag is a compile error.

### Changed

- Accessor base/`_or` split. The reference-returning accessors (`header`, `query`, `cookie_value`,
  `uri::query`, `Context::path_param`) now always bind to a process-wide static empty string on a miss
  (`qb::http::detail::empty_string_value`) — never a temporary, never a fallback argument. The former
  fallback-argument overloads are gone; use the new `*_or` variants for a custom default.
- `Context::get_ptr<T>` renamed to `Context::get_if<T>` (both mutable and `const` overloads, plus the
  typed-`Slot<T>` overload), mirroring `std::get_if` semantics.
- Middleware factory functions renamed from `create_*_middleware` to `*_middleware`
  (e.g. `create_cors_middleware` → `cors_middleware`, `create_jwt_auth_middleware` → `jwt_auth_middleware`).
  The auth/JWT families remain gated on `QB_HAS_SSL`.
- `Headers` de-templated. It is now a plain class (no `StringType` parameter); values are owning
  `std::string` and the historical zero-copy `std::string_view` mode was retired (the input pipe
  relocates buffer bytes between reads, so views cannot survive the shared `Context`/middleware/coroutine
  lifecycle). `refresh_content_type()` re-syncs the cached `ContentType` after raw `headers()` mutation.
- Coroutine HTTP/1.1 client and http2 client request timeouts are `qb::duration` (the legacy
  `double`-seconds signatures and the blocking `Response GET(Request, double)` helpers were removed).
- `controller<C>(...)` is now `[[nodiscard]]` and `requires DerivedFrom<C, Controller<S>>`.
- Removed the per-verb explicit `RouteHandlerFn` / `std::function` sync overloads, the `MEMBER_HANDLER`
  macro, and the explicit `coro_handler<S>(...)` / `coro_middleware<S>(...)` wrappers — all folded into
  the concept-driven verb template and the `(path, obj, member)` overload.
- `StaticFilesOptions::root_directory` is now `std::filesystem::path` and is resolved through
  `qb::io::sys::resolve_resource` when the middleware is constructed: a relative root is anchored
  against the cwd first then the executable's own directory, so a static-file server serves its
  bundled assets from **any** working directory (absolute roots unchanged).
- `http::listen` takes `std::filesystem::path cert_file` / `key_file` (HTTP/1.1 with `{}` defaults,
  HTTP/2 and HTTP/3) instead of `std::string`, matching the framework's filesystem-path policy.

### Fixed

- `Method` string conversions are abort-safe for the default/unmapped state. A default-constructed
  `Method` is `Value::UNINITIALIZED`; its `operator std::string` / `operator std::string_view`
  (and `std::to_string`) route through `name_view()`, which returns `"UNINITIALIZED"` instead of
  calling vendored llhttp `http_method_name()` (which would `abort()` on the unmapped value).
  `Status` string ops return `"Unknown Status"` on a null code.

### Security

- http2 back-pressure DoS guard. The client bounds outstanding (pending + active) requests via
  `set_max_pending_requests()` (default 1024); past the cap, `push_request()` / `push_requests()`
  reject with `503 Service Unavailable`, matching http1/http3.
- JWT NumericDate hardening. `verify_token` parses `exp`/`nbf`/`iat` through `parse_int64_claim`, which
  accepts integer, unsigned (rejecting values above the int64 max), and float NumericDate (truncated
  toward zero, rejecting non-finite or out-of-`[-2^63, 2^63)` values). Numeric-claim reconstruction
  accepts a `strtod` result only when the string is JSON-number-shaped, `errno == 0`, and finite —
  deliberately rejecting `inf` / `nan` / hex-floats so they stay strings rather than silently becoming
  float claims. The `iat` future-check applies clock-skew leeway.
- `jwt_auth_middleware` selects the key slot off the resolved `auth::Options::Algorithm` enum (via
  case-insensitive `algorithm_from_string`, falling back to `HMAC_SHA256`): HMAC algorithms use
  `secret_key`, asymmetric algorithms use `public_key`, instead of matching a raw string prefix.

## [2.0.0]

Aligns qbm-http with the qb 2.0 framework and hardens the HTTP/2, HTTP/3, WebSocket, and parsing paths.

### Changed

- Time handling migrated to the canonical chrono model: cookie `max_age`, CORS max-age, and rate-limit
  windows are `qb::duration`; the HTTP date API uses `qb::wall_time`; JWT leeway and expiry remain
  `std::chrono::seconds` (RFC NumericDate). The retired `qb::Timestamp` / `qb::Duration` types are gone.
- HTTP/3 build integration: `QBM_HTTP_HAS_HTTP3` is defined PUBLIC so consumers can gate on it.
- Percent-decoding deduplicated into `qb::http::utility`.
- Builds clean under `-Wall -Wextra`.

### Fixed

- HTTP/2: stream use-after-free in handler-throw containment; iterator invalidation during push-promise
  creation; trailer deduplication via a populated initial-frame header set; removed a dead
  `associated_push_promises` field.
- HTTP/1.1: throwing routing/response handlers are contained in the server session.
- Rate-limit client-id extractor made type-safe.

### Security

- HPACK: reject Huffman padding longer than 7 bits (RFC 7541 §5.2).
- Multipart: enforce part-count and total-size limits.
- WebSocket: bound message reassembly by default (denial-of-service hardening).
- HTTP/3: contain exceptions in nghttp3 callbacks and fail closed on RNG error; bound the client
  pending-request queue.
- Reject control characters in quoted header-attribute values.

[Unreleased]: https://github.com/isndev/qbm-http/compare/v3.3.0...HEAD
[3.3.0]: https://github.com/isndev/qbm-http/compare/v3.2.1...v3.3.0
[3.2.1]: https://github.com/isndev/qbm-http/compare/v3.2.0...v3.2.1
[3.2.0]: https://github.com/isndev/qbm-http/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/isndev/qbm-http/compare/v3.0.1...v3.1.0
[3.0.1]: https://github.com/isndev/qbm-http/compare/v3.0.0...v3.0.1
[3.0.0]: https://github.com/isndev/qbm-http/compare/v2.6.0...v3.0.0
[2.6.0]: https://github.com/isndev/qbm-http/releases/tag/v2.6.0

# Changelog

All notable changes to the qbm-http module are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the module tracks the qb framework's
[Semantic Versioning](https://semver.org/). Framework-wide policy is in the qb
[VERSIONING](https://github.com/isndev/qb/blob/main/VERSIONING.md) document.

## [Unreleased]

### Added

- **A response body streams on HTTP/2 and HTTP/3 too, and `qb::http::sse` writes Server-Sent Events over the stream
  on every protocol (Huly QB-86, second lot).** The HTTP/2 and HTTP/3 server sessions offer the `streaming_session`
  hooks: `Context::begin_stream()` sends the HEADERS (the header section) at once and each `write()` as DATA frames,
  `end()` as END_STREAM (FIN on HTTP/3), after the response's `trailers()` as a trailing header block when it has any
  by then; a head with neither `Content-Length` nor `Transfer-Encoding` is the new `stream_framing::end_of_stream`,
  with no coding header added (`Transfer-Encoding` is hop-by-hop there); a declared `Content-Length` keeps its
  framing and its enforcement. The hooks take the stream they concern (`ResponseStream::stream_id()`, the request's):
  one connection serves many. On HTTP/2 a piece wider than the peer's `SETTINGS_MAX_FRAME_SIZE` is split into frames,
  never refused, and what the stream's or the connection's send window cannot take yet waits in the protocol's stream
  state: `pending()` counts it with the socket's output, `needs_drain()` holds at the high mark, and the
  `WINDOW_UPDATE` that lets the pieces go resumes `drain()`; `write()` answers `wait` at the hard cap alone, as on
  HTTP/1.1, and a flush is bounded by the socket's room under that cap too (what every stream held back for a window
  would otherwise leave together on one `WINDOW_UPDATE`, past the cap `publish()` disconnects at), the session's next
  write pass sending the rest; a `Transfer-Encoding: chunked` a handler written for HTTP/1.1 said is dropped, not
  refused. On HTTP/3 the pieces are handed to nghttp3 through a data reader that answers `NGHTTP3_ERR_WOULDBLOCK`
  with nothing to hand out and is resumed by each write (`nghttp3_conn_resume_stream`), each piece kept until the peer
  acknowledges it; `pending()` is what the peer has not acknowledged, and the acknowledgements resume the drain
  (the connection calls a three-argument `on_http3_stream_acked(connection_id, stream_id, bytes)` where the owner has
  one). The peer ending the stream alone -- a `RST_STREAM`, a `GOAWAY` that ends the connection, a QUIC stream reset or
  `STOP_SENDING` -- cancels the stream exactly as the peer leaving does on HTTP/1.1 (a parked `drain()` resumes `false`,
  `write()` answers `closed`, the context is cancelled, the observers read the bytes streamed); an application
  `cancel()`, an `abort()`, a dropped handle or a declared length not reached reset THE STREAM -- `RST_STREAM`
  `INTERNAL_ERROR`, `H3_REQUEST_CANCELLED` -- never the connection, which serves its other streams and the next
  request; a trailer section the stream cannot carry at `end()` resets it and cancels the context on both. A HEAD's
  response is its HEADERS with END_STREAM, the producer counted. A streamed stream holds its concurrency slot
  (`SETTINGS_MAX_CONCURRENT_STREAMS`), is seen by the stream sweep (one that writes nothing for the session's
  inactivity timeout beside streams that keep its connection busy, or whose peer takes nothing of it for 30 s, is
  reset `CANCEL`; alone on its connection it ends with it: an event stream's heartbeat is for that) and by the Rapid
  Reset accounting of QB-1244
  as any open stream is, until its END_STREAM or a reset; the session's inactivity timeout ends a producer whose peer
  never updates its window. `POST_RESPONSE_SEND` runs once per streamed response on HTTP/3 as on the others (the
  context is not adopted while it is being routed). The HTTP/1.1 path is byte-identical (its suite is the oracle); the HTTP/1.1
  fallback of an HTTP/2 server still buffers. `StaticFilesMiddleware` therefore streams a body over its
  `stream_threshold` on HTTP/2 and HTTP/3 too, where it read it whole under `max_file_size`, which no longer bounds a
  streamed body there (QB-101's rule, on every protocol). The SSE helper: `ctx->begin_sse(sse::Options)` (or
  `qb::http::sse::begin(ctx, options)`) sets the head of an event stream -- `Content-Type: text/event-stream;
  charset=utf-8`, `Cache-Control: no-cache`, `Connection: keep-alive` on HTTP/1.1 alone (hop-by-hop elsewhere) and
  only when the request keeps the connection (the parser's verdict) and the session is not draining, `X-Accel-Buffering: no` on request -- begins the stream and returns an
  `sse::Stream<S>`, or `nullptr` where the stream would be buffered (an HTTP/1.0 request, the HTTP/1.1 fallback of an
  HTTP/2 server): an event stream buffered until its end is none, so the request is answered 500 and the handler is
  told. `send(sse::Event{name, data, id, retry})` writes one event (`event:`, `id:`, `retry:` in milliseconds, one
  `data:` line per line of the data -- LF, CR or CRLF, a trailing one giving an empty last line so the data arrives as
  sent -- and one at least, since a client dispatches nothing without it; nothing escaped, a CR or LF inside `name`,
  `id` or a comment dropped since it would start another field; a blank line ends it) with the stream's verdict, `comment(text)` the `: text` line a client ignores, `co_await send_async(event)` for a
  coroutine (it writes again after a drain on `wait` and waits for one when the stream asks), `heartbeat(interval)` a
  comment line at that interval on a `qb::io::async::callback` timer holding the stream weakly -- it stops by itself
  at its next tick once the stream is gone, ended or cancelled, a dropped handle's timer firing once more and stopping -- `end()`, `abort()`;
  `sse::last_event_id(request)` is the `Last-Event-ID` a reconnecting client sends, `sse::format`, `comment_line`,
  `retry_line` the wire forms. Proven by `qbm-http-test-unit-http2-server-stream` (19 cases on the socket-less
  harness: the head without END_STREAM, the split at the peer's frame size, the stream and the connection windows and
  the WINDOW_UPDATE that lets the pieces go, a write refused between `end()` and the END_STREAM a window holds back, two streams' held pieces flushed under the socket's write cap and the
  rest on the next pass, a trailer section waiting unencoded for the socket's room (the HPACK table advanced once), the idle sweep resetting a silent stream and sparing one that wrote, END_STREAM on the last
  piece or an empty frame, trailers after the held pieces, a forbidden trailer field, HEAD, abandon, a peer reset, a
  forbidden header, the 51st stream refused while a streamed one is open and accepted once it ended, the
  whole-response path beside it), `qbm-http-test-system-http2-response-stream` (13 cases over a raw TLS HTTP/2 client
  that reads the frames: arrival before the end, a 16 KiB window and the drain it parks, a peer RST_STREAM under that
  parked drain, the inactivity timeout under a window never updated, RST_STREAM, two GOAWAY shapes, HEAD, trailers, a
  declared length kept and one cut short, the chunked coding a handler said dropped, the concurrency slot),
  `qbm-http-test-system-http3-response-stream` (15 cases: the nghttp3 adapter driven directly -- the head, a piece
  before the end, WOULDBLOCK and the resume, the acknowledgements and the three-argument hook, trailers, a forbidden
  trailer field (the stream abandoned), abandon, a second response -- then the real server and client over QUIC
  loopback: the pieces acknowledged before `end()`, HEAD, a cancel, a short length and a refused trailer section reset the
  stream -- the context cancelled -- and the connection serves on, a declared length, trailers, the client leaving), `qbm-http-test-unit-sse-format` (18 cases,
  one per field, the data split and its empty last line, a lone CR, the line breaks dropped from a name, an id and a comment (a value of line breaks alone no field),
  the comment and retry lines, `Last-Event-ID`), `qbm-http-test-system-sse-stream` (14 cases on HTTP/1.1, HTTP/2 and
  HTTP/3: the head, three events read before the end -- unacknowledged then acknowledged on HTTP/3, the framing
  `end_of_stream` --, `Last-Event-ID`, the heartbeat while idle and its silence after the end, a dropped stream and
  its reset on each protocol (its timer's death on HTTP/1.1), `send_async`, a buffered stream refused with 500 and
  the whole head taken off (HTTP/1.0), the same connection serving on after a stream, no keep-alive under a
  `Connection: close` token, a HEAD's ended stream, the response-sent hook once per response -- from a synchronous
  and from a coroutine handler, GET and HEAD -- on each protocol), the HTTP/2
  and HTTP/3 static-file cases turned to the streamed truth, and the example `examples/06-modules/http/16-sse.cpp`. Performance, A/B
  against the base (its own libraries, 3 copies a side, seeded order, under the bench marker): HTTP/1.1 and the HTTP/2
  client neutral; the HTTP/2 server's plain GET read +2.1 % until the per-stream pipe -- 4 KiB at construction, paid by
  every stream for a buffer only a streamed response fills -- became lazy, then +0.4 to +1.0 % over four more windows
  against A/A spreads of 0.2 to 1.4 % between copies, the per-request protocol code otherwise identical to the base
  (the head collection inlined back into its callers, 16 bytes of per-stream state). Mutants: 36 planted one at a time
  in the flush, the windows and the room, the END_STREAM and trailer paths, the HTTP/3 data reader and its
  acknowledgements, the hooks' context ownership and the SSE formatter and head -- 34 caught by the suites above after
  a green control; one survived for want of a knob (the session's write pass resuming the streams the socket held
  back before it consults its map needs qb-io's write cap lowered in a test, which the session exposes since: under
  Fixed), one is equivalent (the HTTP/3 session cancels its live stream before the context's cancel, which
  `_stream_gone` already keeps from resetting a stream the peer ended).

- **A streamed static download its client stops taking is ended at an idle deadline, 60 s by default, and under a
  minimum rate when one is set (Huly QB-1212).** Since QB-101 a download over `stream_threshold` held its file and its
  connection for as long as the client took: a client reading 64 KiB a minute held a 16 MiB file for hours, and
  staggered connections made that permanent. `ResponseStream` now carries a stall watch.
  `set_idle_deadline(qb::duration)` is the longest the stream may wait, while bytes wait in the session's output (on
  HTTP/2 the pieces the stream's windows hold back too, on HTTP/3 the bytes the peer has not acknowledged), for the
  socket -- the peer, on HTTP/2 and HTTP/3 -- to accept one more: an IDLE deadline between two acceptances, never a
  total one, so a slow but steady client finishes however large the file, and a slow producer with nothing waiting is
  never cut. `set_min_rate(bytes_per_second, window = 10 s)` adds a floor under the rate at which the socket accepts
  the stream's bytes, over a sliding window -- sampled every eighth of it while bytes wait, judged once the samples
  span a whole window -- for the deployments that refuse a client reading an octet a minute; off by default (a
  download's floor: a producer that writes less than it itself, with bytes waiting at every sample, is cut as a slow
  peer is). Past either the stream is aborted exactly as `abort()` does it: the producer released with what it holds
  (a static file's descriptor), the connection closed on HTTP/1.1, the stream alone reset on HTTP/2 (`RST_STREAM`
  `INTERNAL_ERROR`) and HTTP/3 (`H3_REQUEST_CANCELLED`) while the connection serves on, the context cancelled (the
  observers read it). `qb::duration::zero()` disables the deadline and 0 the floor; `idle_deadline()`, `min_rate()`,
  `min_rate_window()` and `accepted()` read them back; both are settable at any time, per stream, as
  `set_watermarks()` is, a change taking effect at once, armed or not. The watch is one timer the stream owns, created
  at its first setting and gone with the watch (an ended stream leaves none behind), never on a buffered or a HEAD's
  stream; acceptance is what the session reports to the stream at its write passes -- on HTTP/2 this stream's own
  bytes, kept apart from its siblings' on the shared output (the pieces its windows hold back, and its last DATA
  frame's distance from leaving the output, drained in order), so another stream's traffic is not this one's
  acceptance and a producer idle beside a busy sibling is not a stalled peer -- and an unwatched stream pays a flag
  test at each write and report; setting the same value again changes nothing, a new one restarts the clock.
  `StaticFilesOptions::stream_idle_deadline` (60 s, nginx's `send_timeout`; `with_stream_idle_deadline()`) and
  `stream_min_rate` with `stream_min_rate_window` (0: none; `with_stream_min_rate()`) are set on every download the
  middleware streams, before its producer runs, so an earlier middleware may set a stream's own once its `next()`
  returns. Proofs (`qbm-http-test-system-static-files-stream`, `-http2-response-stream`, `-http3-response-stream`,
  `-response-stream`): a client that stops reading is cut within the deadline after the socket's last acceptance on
  HTTP/1.1, after the stream window filled on HTTP/2 (a window that never grows) and HTTP/3 (credit never returned),
  its file closed, its stream released, the connection closed on HTTP/1.1 and serving on on the others; a peer that
  stops reading the HTTP/2 connection under a wide-open window is cut too; a stalled download beside a sibling stream
  whose bytes keep leaving the shared output is cut all the same, while a producer idle beside that sibling is never
  cut; a healthy reader taking its HTTP/2 download in bursts, and an HTTP/3 peer crediting its window in bursts,
  finish under the deadline; a client taking 256 KiB then pausing 100 ms under a 1 s deadline, bytes waiting the whole
  way, finishes 16 MiB; a client taking 128 KiB every 100 ms is cut under a 4 MiB/s floor while it still takes bytes
  -- with no deadline, and under the 60 s default -- and finishes over a 64 KiB/s one; zero disables and reaches the
  stream as zero; a stream's own shorter deadline set on one already armed at the middleware's cuts at once; a
  producer writing every 700 ms under a 250 ms deadline, to a client that reads, is never cut.
- **A streamed body is coded on the fly: `CompressionMiddleware` sets a content coding on the stream `begin_stream()`
  creates, so a static file over `stream_threshold` leaves compressed when the client accepts it (Huly QB-1208).** The
  middleware's `PRE_RESPONSE_SEND` hook, which runs inside `begin_stream()` with an empty body, now reads
  `Context::stream_beginning()`: when the client accepts a coding the build registers (gzip and deflate are the proven
  ones; zstd and brotli come through the same provider where their builds are on), the type is compressible, the
  status is not 206, no coding is on the head already and a declared length is not under `min_size_to_compress`, it
  hands the context a `qb::http::stream_filter` through `Context::set_stream_coding()`: qb-io's incremental compressor
  (`qb::http::detail::StreamCoding`), each piece flushed as it is coded (a partial flush: what a piece produced leaves
  with it), finished at `end()`. Once every hook ran and the framing is known, the CONTEXT sets the head:
  `Content-Length` dropped (the coded length is unknown: chunked on HTTP/1.1, END_STREAM or FIN on HTTP/2 and HTTP/3,
  whatever a later hook declared), `Content-Encoding`, `Vary: Accept-Encoding` (listed once), a strong `ETag` made
  weak, `Accept-Ranges` dropped (a coded 200 resumed under a `Range` without `If-Range` would splice identity octets
  into a coded body); a later hook that coded the answer itself or made it a range keeps its own head, uncoded here;
  an HTTP/1.0 request, which reads no chunked body, keeps its length and gets no coding, and streams as before.
  `ResponseStream::write()` admits a piece against the coding's bound of it BEFORE coding it, so a piece refused for
  room (`wait`, `too_large`) was never consumed and is written again as it is; `written()` and `streamed_bytes()`
  count the producer's own bytes, the wire carries the coded form; `filter()` says which. The memory bound of QB-101
  holds: the session's high watermark, a piece, its coded form and the codec's state (zlib: about 384 KiB). Never on a
  buffered stream (the body leaves whole, compressed at its completion as before), on a HEAD's stream (a HEAD the
  static files answer whole describes the identity representation, as before; a HEAD a handler streams carries the
  coded head its GET would, and nothing to code), or under a length a hook kept. A range is never coded, on the
  whole-body path either: a 206 read whole left compressed until this lot; that path weakens a strong `ETag`, drops
  `Accept-Ranges` and lists `Accept-Encoding` in `Vary` once, as the stream's does. An event stream (`begin_sse()`) is
  coded like any streamed body, each event flushed as its own chunk, so a client inflates it event by event. The coder
  is made at the first piece: a HEAD's stream, or one buffered after all, never allocates it. A middleware's own filter, set from a
  `PRE_RESPONSE_SEND` hook while `stream_beginning()`, follows the same contract. The documented workaround (raising
  `stream_threshold` to keep large text assets compressed, at the cost of reading each whole) is gone with its cause;
  the QB-101 upgrade note below is superseded. Proofs: on HTTP/1.1, HTTP/2 and HTTP/3 the bytes a client inflates are the
  file (text, and a 16 MiB random file on HTTP/2), the head says `Content-Encoding`, no length, `Vary`, a weak ETag; a
  streamed range (206) and one read whole, an HTTP/1.0 request and a client that accepts no coding get the file as it
  is; a client that stops reading a coded download holds the output under the high watermark plus one coded piece and
  releases the producer, the stream and the file when it leaves; a handler's own stream with a preamble is coded from
  its first piece, its strong ETag weakened and a weak one left, a piece under the room as it is but over it under its
  bound refused before the coder sees it, a buffered stream it drops answered 500 uncoded.
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
  piece, so `CompressionMiddleware` left a streamed body alone until Huly QB-1208, above -- then a valid `Content-Length` is honoured and
  enforced (a piece past it, or an `end()` short of it, closes the connection rather than deliver a message the peer
  would misread), a `Transfer-Encoding` whose only coding is `chunked` is chunked as it stands, and otherwise
  `Transfer-Encoding: chunked` is set. The response to HEAD is whole at its head: its exchange ends there and the next
  request on the connection is served while the producer, whose pieces are counted and discarded, runs on. The producer
  owns the stream: one dropped before `end()` is aborted -- the connection closes; buffered, a 500 without the failed
  body's framing and coding headers -- and the peer leaving, an application `cancel()` or `complete(CANCELLED)` (a
  middleware's, after `next()`: until Huly QB-101 it finalised the context alone, its observers read nothing streamed,
  and the stream ran on to its end on a connection that served the next request), an extraction or the inactivity
  timeout cancels it: a parked `drain()` resumes with `false`, `write()` returns `closed`, the context is cancelled,
  and a server destroyed under a live stream releases it; a drain callback still registered when its stream dies is
  released without running. A response that cannot be streamed -- a status without a body, HTTP/1.0 without a length, a
  session without the hooks of the new `qb::http::streaming_session` concept (the HTTP/2 and HTTP/3 sessions offer them
  since the second lot, below) -- gets a buffered stream with the same interface, sent whole at `end()` through the ordinary
  completion, its hooks included. Observers read a streamed response at its end: the head's status, even when it was
  cut short, and `Context::streamed_bytes()`, which `AccessLog` logs as its size.
  `qbm-http-test-system-response-stream` (42 cases, the two TLS ones over `ssl::DefaultSecureSession`) and
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

- **`qb::http1::Client::set_max_body_size(std::size_t)` and `max_body_size()` (Huly QB-1248).** The persistent HTTP/1.1
  client takes the largest response body it accepts: `qb::http::protocol_limits::MAX_BODY_SIZE` (100 MiB) by default, 0
  for none, read as each response begins. A body that declares its length past it fails before a byte of it is read, a
  chunked or close-delimited one once the bytes it delivered pass it, with a 502 whose error names the limit. It had no
  setting: the constant was every response's bound. The one-shot verbs stay on the default, the persistent client is
  the way past it; the HTTP/3 client's `set_max_body_size` takes 0 for none too, now written. Witnesses in the entry
  "The HTTP/1.1 clients read a body of exactly their limit" below.

- **`qb::http2::Client::set_max_body_size(std::size_t)` and `max_body_size()` (Huly QB-1248).** The persistent HTTP/2
  client takes the largest response body it accepts, as the HTTP/1.1 client does: `qb::http::protocol_limits::MAX_BODY_SIZE`
  (100 MiB) by default, 0 for none. A response that declares a `content-length` past it is refused at its header block,
  one that delivers more at the `DATA` frame that passes it: its stream is reset (`ENHANCE_YOUR_CALM`) and its request
  fails with a 502 whose error names the limit -- "HTTP/2 response body exceeds the client's limit of N bytes", where it
  read "exceeds configured limit" with no number. It had no setting: the constant was every response's bound. Only the
  stream ends, the connection serving its other requests on, so the rule of the HTTP/1.1 client -- a connection a bound
  cut is closed at once -- has no counterpart here. Witnesses: `qbm-http-test-system-http2-client` (past a limit of
  1024, a declared and a streamed body each failing with the limit named while the other requests of the connection are
  answered, 1024 itself delivered; the default read back; 0 delivering what 1024 refused),
  `qbm-http-test-unit-http2-client-protocol` (the limit read from the io: past it, declared or delivered, the stream
  reset `ENHANCE_YOUR_CALM` with the limit named; exactly it delivered; a declaration past the default accepted under 0;
  the constant for an io without the setting) and `qbm-http-test-system-http2-client-huge-body` (under a limit of none,
  a body past the default delivered, nothing reset; past the default, the error names 104857600 bytes).

- **`http2_sweep_streams(now)` on the HTTP/2 server session, and `cleanup_idle_streams(now, max_idle,
  max_incomplete, max_unanswered)` and `has_streams()` on its protocol (Huly QB-1248).** The sweep of a connection's
  streams, handed its time. The session's own timer runs `http2_sweep_streams(std::chrono::steady_clock::now())` while
  the connection has streams, or a refused header block left open (`has_streams()`; the Fixed entry "The streams of an
  HTTP/2 connection are swept from a timer of the session's own"), and goes on whoever else calls it: the member is
  public for a test, which steps the time instead of sleeping, and for an application that wants a sweep before the
  next tick -- not to replace the schedule. `now` is the steady clock's time, or a test's stepped from it, never
  earlier than a previous call's: the streams' clocks are stamped with it. It holds the io's `protocol_pass()` and
  returns the number of streams it reset: 0 on a session that does not run HTTP/2, and on one whose connection ended
  or left it (a disconnection, an extraction). The protocol's sweep takes the time and the three bounds; its
  two-argument form remains. An io that offers `protocol()` answers there the protocol it runs: a server protocol that
  reads another one there holds itself retired, and writes nothing. An io that offers `http2_refused_block_open()` is
  told when a `HEADERS` the server refuses leaves its block open: the session arms its sweep there.

- **An HTTP/2 IO handler may keep the clock the bucket of the frames that make no progress reads (Huly QB-1270).**
  `qb::protocol::http2::keeps_no_progress_clock`: a handler with `std::int64_t no_progress_clock_seconds() const` is
  read by `Http2Protocol::refuse_no_progress_frame()` instead of `std::chrono::steady_clock`, a clock that reads earlier
  counting one second. The test suite's fake handlers keep one, so that the bucket's refill is tested by stepping time
  rather than by sleeping through it; every qb-io session reads the steady clock, as before.

- **`Http2GoAwayEvent::sent` says who sent an HTTP/2 GOAWAY (Huly QB-1270).** The client and server protocols dispatch
  `qb::protocol::http2::Http2GoAwayEvent` for the `GOAWAY` they receive and for the `GOAWAY` with an error they send
  themselves; the new `bool sent` is `true` for the latter, and the constructor's new trailing parameter defaults to
  `false`, so code that builds the event as before compiles unchanged. `debug_data` is now the frame's debug data as
  on the wire on both sides: for its own `GOAWAY` the protocol prefixed it with « GOAWAY sent by client: » or « GOAWAY
  sent by server: », the only way a handler could tell it from the peer's -- and a peer's debug data could carry the
  same words. A handler of the event sees the reason alone now, and `sent` (Changed, below). The struct gains a
  member: rebuild what includes it (qb promises no binary compatibility between versions).

### Changed

- **The name `inactivity_timer_t` is reserved in an HTTP/1.1 or HTTP/2 server session type (Huly QB-1248).** Each
  server session names its inactivity timer so, for qb-io's `extractSession()`, which stops that timer (Fixed: "An
  HTTP/1.1 or HTTP/2 server session keeps the first reason it ended with"). A session type that declares an
  `inactivity_timer_t` of its own no longer compiles, and inside a class deriving from a server session an unqualified
  `inactivity_timer_t` names the session's alias, not one at namespace scope (in a class template, whose base is
  dependent, the unqualified name is still the namespace's).
- **The HTTP/2 server bounds a stream by whose turn it is, on every connection (Huly QB-1248).** What an application
  written against the last release sees, each from a Fixed entry below. A request its handler has not answered, or not
  finished, within the session's inactivity timeout (60 s by default) is reset `RST_STREAM(CANCEL)` and its context
  cancelled, on a connection its other streams keep busy too -- where a silent stream was reset after 30 s when a
  sweep ran, and never on a connection that did not write: a long poll or an event stream that stays silent past the
  timeout writes a heartbeat or raises the session's timeout, as on HTTP/1.1 -- the timeout is the connection's, so
  every request of an HTTP/2 connection has the one in force at the sweep, whichever handler set it last. The bound is
  the session's timeout whatever its value: a session that set one under 30 s gives a handler that timeout on a busy
  connection too, where a dispatched stream had 30 s -- a server whose handlers take longer than its timeout raises it
  --, and one lowered at run time holds at the next sweep for the requests in progress. The bounds of a request that
  is not complete (10 s without an octet of its body) and of a response its peer does not take (30 s) apply on every
  connection, where they needed a write that left bytes queued; a download that flows slowly is no longer reset, and a
  `WINDOW_UPDATE` alone keeps nothing. Responses that wait for the same credit are served a DATA frame each, in turns,
  where the first took all of it: their frames interleave. `reset_stream()` returns `false`, and a response is
  dropped, on a session whose protocols the application cleared or whose connection left it (an extraction), and the
  server's drain no longer waits for a session that cleared them. A client that leaves a refused header block open
  for more than 10 s has its connection closed. A promised stream never
  answered has the session's timeout too, where it had 30 s. `ServerHttp2Protocol::cleanup_idle_streams(max_idle,
  max_incomplete)`, for a caller that sweeps by itself, counts a dispatched request's idle time from the sweep that
  sees its dispatch.

- **A request field that cannot be sent refuses its request, the same way on the three clients: `400`, with a reason
  that names the field (a change of the clients' contract; Huly QB-1191).** The same request meant one thing or another
  by protocol. HTTP/1.1's serializer refused a field whose name is not a token, or whose value carries CR, LF, NUL,
  another control byte but HTAB, or DEL -- `400`, but "header value exceeds MAX_HEADER_VALUE_LENGTH" whatever the
  fault, and naming no field. In 3.3.0 the HTTP/2 client dropped such a field and sent the request without it, without
  a word -- a dropped `authorization` sent it unauthenticated --, and the HTTP/3 client refused the request `503`.
  QB-1191's earlier policy, below under Fixed, made HTTP/3 drop it too, and dropped a value with SP or HTAB at its
  edges on both. The rule is now one, HTTP/1.1's, applied where each client already reads
  the fields, and nowhere else:
  - **A field HTTP/1.1 cannot write** -- by `qb::http::detail::sendable_field_name()` and `sendable_field_value()`,
    the serializer's own predicates, which the three clients share (a name past `MAX_HEADER_NAME_LENGTH`, a value past
    `MAX_HEADER_VALUE_LENGTH`, included) -- **refuses the request**, in its header section or its `trailers()`:
    `400`, "HTTP/2 request header field `x-probe` cannot be sent: its value carries LF" (`qb::http::detail::
    unsendable_field()`), an answer the client gives by itself, through its one queue. Nothing of the request is
    written -- on HTTP/2 nothing is encoded, and no stream identifier is spent; on HTTP/3 no stream is opened, and
    nghttp3 never sees it --; the connection stays, and the other requests are served. Any other refusal of a request
    is still `503`.
  - **A connection-specific field is still dropped**, as a translating intermediary must (RFC 9113 §8.2.2, RFC 9114
    §4.2): `connection` and the fields it names, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`,
    `http2-settings`, a `te` other than `trailers`, `host` (folded into `:authority`), `content-length` (written from
    the body).
  - **A value with SP or HTAB at its edges is sent without them** on HTTP/2 and HTTP/3, which is what HTTP/1.1 means:
    they are not part of the value (RFC 9110 §5.5), and an HTTP/1.1 receiver strips them. A value of whitespace alone
    is sent empty. Whitespace inside a value is part of it.
  `ClientHttp2Protocol::send_request()` takes a `std::string *field_refusal` that says which field refused the request;
  the HTTP/3 adapter builds a request's sections with `prepare_request()` before a stream is opened for it, and
  submits them with `submit_prepared()` (`submit_request()` is the two). The field loop reads each name and each value
  once, as before, with the predicate that refuses it; the trim reads a value's edges and copies nothing more than
  before. The server's fields, and the promised request of a `PUSH_PROMISE`, are unchanged.
  Witnesses, each red on the base of this change but the pins: on the three clients a value with LF, with NUL, with
  CR, a name with SP, a `cookie` with CR, and a trailer with LF each refuse their request `400`, the reason naming
  the field, the connection kept and the request behind it served; a raw HTTP/2 peer reads one HEADERS, the request
  behind on stream 1; the HTTP/3 client resets no stream; `" v "` arrives as `v`, `"  "` arrives empty, and
  `connection: close` and `te: gzip` are still left out and their request served (pins).
  Mutants, the whole binary each, the unmutated tree first and the restored tree last: 16 planted, 16 caught -- a value
  that carries any byte, a name that carries SP, a reason that names no field; HTTP/1.1's serializer writing such a
  value, or such a trailer value; on HTTP/2 and on HTTP/3, such a value dropped and the request sent (QB-1191's earlier
  policy), a value sent with its edges, the refusal answered `503`, a trailer field under the protocol's own rule; on
  HTTP/2, a connection-specific field sent, a trailer value sent with its edges; on HTTP/3, a stream opened for a
  request refused for a field. The HTTP/3 drop is caught by the field block's own case
  (`qbm-http-test-unit-http3-validation`): the client reads the refusal the pass names before it returns, so the
  loopback cases alone do not tell it. The 63 mutants that stand from the rounds before, planted again on this tree: 59
  caught, the same four surviving.

- **An HTTPS or `wss` connection qb ends now ends its TLS stream with a `close_notify`: an OpenSSL peer reads a
  clean end of stream where it read an unexpected EOF (qb 3.4, Huly QB-1270).** qb-io sends the alert before the
  TCP FIN whenever this side ends a TLS connection and has written everything it queued, and every TLS connection
  of qbm-http is a qb-io stream: the HTTPS/1.1 server's response with `Connection: close`, a session its
  inactivity timeout or a drain closes, the HTTP/2 server's and client's connections, the HTTP/1.1 clients
  (`qb::http::async::HTTPS`, the persistent `qb::http1::Client`), and `wss` sessions and clients. A browser, curl or
  any OpenSSL 3 program that read such a connection got `SSL_ERROR_SSL` with `SSL_R_UNEXPECTED_EOF_WHILE_READING`
  (reason 294), which it cannot tell from a truncated stream; it now reads the last bytes, then
  `SSL_ERROR_ZERO_RETURN`, then the FIN -- measured on the HTTPS/1.1 server against a raw OpenSSL client, a
  response with `Connection: close`, an idle timeout and a server destroyed after a completed response (the test
  of the next entry). Nothing changes in qbm-http's API, and a plain HTTP connection is untouched. No
  `close_notify` is sent when output still queued is dropped -- that stream is cut, and its peer reads the unexpected
  EOF as before -- nor when the peer ended the connection with a bare EOF or a reset; a peer that ended the TLS
  session with its own `close_notify` is answered with this side's. The rule, its limits and its cost are in qb's
  CHANGELOG, under the same issue.
- **An HTTPS/1.1 streamed response the server abandons ends its TLS session without the `close_notify`, so the
  peer reads the cut as one (Huly QB-1270).** qb-io announces a stream whole whenever what it queued is written,
  and a streamed response the server abandons usually has nothing queued: the alert of the entry above would tell
  the peer that a truncated response is complete. The HTTP/1.1 session knows better -- a streamed head is out and
  its `end()` is not -- and ends the TLS session quietly first (`transport().quiet_shutdown()`, compiled away on a
  plain transport). In `stream_abort()`, which every abort reaches -- `ResponseStream::abort()`, an `end()` short
  of a declared `Content-Length`, a piece past it, a content coding that fails on a piece or at `end()`, a dropped
  stream, a cancellation of the context, the idle deadline or the rate floor -- before the context's cancellation
  runs any application code. In `on(event::disconnected)`, before the session class's own handler, for a
  connection that ends under a live stream for any other reason: the inactivity timeout, the drain's deadline, a
  pipelining limit, a local `disconnect()`, the peer's own `close_notify` (which qb-io answers when nothing is
  queued). And in the session's destructor, for a server destroyed with a live
  stream. A session extracted under a live stream (`extractSession()`) does not end its TLS session, which goes on
  with the socket's next owner: it marks the stream cut (`transport().mark_cut()`), so that the next owner's close
  sends no alert, whatever it wrote. An OpenSSL peer now reads `SSL_ERROR_SSL`, reason 294, after the bytes that
  left, which is what HTTP's own framing says too (no last-chunk, a short body). A response that completes keeps
  its alert, whatever closes or takes over the connection after it. HTTP/2 and HTTP/3 reset the stream alone and
  keep the connection, WebSocket ends with its Close frame, and the HTTP/1.1 clients write a request whole, so none
  of them needs the same. Proven by `qbm-http-test-system-http1-tls-cut-response` (23 cases, a raw OpenSSL client):
  on the unchanged session the 17 abandoning cases read `SSL_ERROR_ZERO_RETURN` -- each response short of what it
  promised, no last-chunk or a body under its `Content-Length` -- and with the change they read the unexpected EOF,
  the 6 completed ones the clean end (g++ 14, OpenSSL 3.5.7). Eighteen mutants of the change, planted one at a
  time -- each call removed, each guard dropped, each call moved after the application code it must precede, the
  call planted on the completed path, the session ended where it must only be marked -- are each caught.
- **`Request` and `Response` build a message with no body without making one: their constructors are overloads, not
  one form with two defaulted arguments (Huly QB-1270).** `Response{status}`, `Request{method, uri}` and
  `Request{uri}`, and the forms with headers alone, made an empty header map and an empty `Body` for the call and
  moved both into the message; `internal::MessageBase` gains a headers-only constructor and the messages are built in
  place. Every call that compiled still does, and means the same. Why it is here: an empty `Body` made for the call
  and moved is the one shape g++ 14 cannot follow under `-fsanitize=address` -- the body's pipe does not exist yet
  (Huly QB-1216), and the compiler reads its move as a read of uninitialised storage -- and every such message it
  inlined reported `-Wmaybe-uninitialized` in `qb/system/allocator/pipe.h`: 132 lines in thirteen of the module's
  test translation units, none now. The sanitized build is not warning-free for it: libstdc++'s
  own `std_function.h` still reports the same warning inside `<regex>` in five translation units -- qb's `cpu.cpp`,
  `middleware/cors.cpp`, `validation/rule.cpp` and the unit tests of the last two -- which is not qb's code to change.
  Instructions (callgrind, g++ 14; nothing timed): a client GET is level. A server's browser GET first cost about 110
  more in 48 000 in a plain Release build: with the constructors' shapes changed, GCC called libstdc++'s
  `operator==(const std::string &, const char *)` out of line at one more of the seven header-name comparisons of
  `ServerHttp2Protocol::process_complete_header_block()`. Those comparisons go through `detail::name_is` now -- the
  literal's length a constant, `[[gnu::always_inline]]` -- so that none is out of line, and the request costs about
  110 fewer than before the constructors changed in each of three alignment families, with and without
  `-march=native` (157 fewer without it, where the inliner also takes a string move inline: not this change's doing).
- **A connection the HTTP/2 server or client ends for a flood is closed at once (Huly QB-1270).** qb-io now closes a
  connection an endpoint ended itself after its peer, reading what the peer still sends for `linger()`, up to 16 MiB
  (qb's CHANGELOG). A connection ended with the endpoint's own `GOAWAY(ENHANCE_YOUR_CALM)` -- every flood rule of the
  two protocols sends that code -- is the one case where that is wrong: the loop would read on the peer it has just
  refused to read. The server session and `qb::http2::Client` set a linger of zero for that close, which is qb-io's
  "close at once"; the client puts its own `linger()` back in `on(event::dispose)`, unless the application set
  another, non-zero one meanwhile (a zero set during that close reads as the client's own and is replaced). Proven by
  `Http2ServerCloseAfterPeerTest.AFloodingConnectionIsClosedAtOnceAndNeverReachesTheLoop` and
  `Http2ClientCloseAfterPeerTest.AConnectionTheClientEndsForAFloodIsClosedAtOnceAndKeepsItsLinger` over real TLS
  sockets (without the change the flooder's socket takes 17 MB after the close and the loop holds its descriptor) and
  by `...ALingerTheApplicationSetsDuringAFloodsCloseIsKept`.
- **The `debug_data` of a GOAWAY an HTTP/2 protocol sends itself is the frame's debug data alone (Huly QB-1270).** The
  client and server protocols dispatch `Http2GoAwayEvent` for their own `GOAWAY` with an error; its `debug_data` was
  the reason behind « GOAWAY sent by client: » or « GOAWAY sent by server: », and is the reason alone now, as on the
  wire, the new `sent` member telling the two apart (Added, above). A handler that recognised its endpoint's own
  `GOAWAY` by that prefix reads `sent` instead: it would take its own for the peer's without a word. The
  `qb::http2::Client`'s failure text is unchanged, « GOAWAY sent by client: <reason> », and the server session logs
  its own as « Sent GOAWAY to client », no longer as received.

- **Every chunked body of a kept HTTP/1.1 connection starts from the pipe's initial buffer, and the protocol reserves
  nothing for a declared body it copies (Huly QB-1248).** The parser reads a chunked body -- and any body when it is
  driven directly, `Parser::parse()` past the headers -- into a buffer it moves into each message, so from the second
  such body of a connection the buffer was null, and its first write took the pipe's slow path: 8 KiB for five octets,
  twice what the first took. A null buffer is given the pipe's initial one when the first write fits it
  (`Parser::body_buffer()`); a first write past it grows from null as it would from that buffer, and a message that
  declares no length allocates nothing. Read per message on a kept connection, at the protocol: a chunked request of
  five octets 8440 bytes before, 4344 now, a chunked response of two 8360 and 4264, the allocations as many; a
  `Content-Length` body is copied from the input buffer, never through this one, and a GET reads the same (the
  reserve, below, aside). Read on a `Parser` driven directly: the second body takes 8192 before, 4096 now, declared or
  chunked, in one allocation, as before. A chunked body whose first chunk fits 4096 and that grows past it reallocates
  once more on the way (4096, then 8192, copying what it holds, at most 4 KiB), as from a default-constructed buffer.
  The same 4096 comes from qb's own fix of the slow path (qb CHANGELOG, Huly QB-1248); this one keeps the parser from
  depending on the pipe's growth policy. `Parser::body_buffer()` tests the buffer in line and calls
  `restore_body_buffer()`, out of line on the unlikely branch, only for a null one, and a declared length of 0 makes
  no call (defined out of line, the test was a call on every message under g++: Huly QB-1248). The reserve of a
  declared length is kept for a `Parser` driven directly past the headers, which writes the body into it; the
  protocol, server and client, copies such a body from its input buffer and never writes it, so its parser reserves
  none now. Before, a declared length past 4 KiB grew that buffer, up to the reserve's cap of 64 KiB, and the
  connection held it until a chunked body took it over -- one header line held 64 KiB -- and a declared body after a
  chunked one allocated a buffer it never wrote (8 KiB in 3.3.0; one allocation more than after a declared one, server
  and client alike).

- **The HTTP/1.1 parser checks a `Transfer-Encoding` field without an allocation (Huly QB-1248).** The check --
  exactly one non-empty token across the field lines, `chunked` in any case, HTTP whitespace trimmed -- split the
  field into a vector of strings, two allocations or more for every message that named a coding, chunked bodies
  included (a token past the small-string buffer adds up to two); it now scans the field lines in place over views.
  The verdict is the same for every shape: `qbm-http-test-unit-http1-parse-limits` (`TransferCodingScan`) holds the
  parser to the split, kept in the test as the oracle, over a table, every join of one to three pieces (tokens,
  whitespace, nothing) on one field line and a stride sample of pairs of them on two, green before and after.
  `qbm-http-test-unit-content-length-preallocation` counts the allocations of a header section that names
  `Transfer-Encoding: chunked` against the same section with a field of the same length that names nothing: on macOS
  with libc++, 5 against 3 before, 3 against 3 now. `qbm-http-bench-http1-parser` gains `BM_Http1Parse_Chunked`, a
  chunked POST parsed whole.

- **The WebSocket frame decoder allocates nothing per frame (Huly QB-1247).** `onMessage()` built a local
  `ws::Message` for every frame, whose pipe allocated 4 KiB at construction and freed it at the end of the frame --
  an allocation and a free for a 16-byte text frame or an empty Ping. The frame's payload lands in a buffer the
  protocol keeps now, reset between frames; each frame writes its own `_expected_size` bytes, so nothing of a longer
  frame is read after a shorter one, and the reassembled message stays a buffer of its own. Counted with a replaced
  `operator new` on 64 decoded frames of each shape (a 16-byte masked text, an empty Ping and a 125-octet one
  answered by their Pong, an empty text): 64 allocations a shape before, 0 now. A/B on an M4, qb unchanged on both
  sides (3 copies a side, seeded order), `ws-throughput.bench.cpp`: `BM_WS_DecodeMaskedText/bytes:16` -4.1 %,
  `BM_WS_DecodePingAutoPong/bytes:0` -4.4 %, against an A/A spread of 0.5 to 1.8 %. The buffer is the connection's, 4
  KiB from the handshake on; a frame that grows it past 64 KiB frees it at its end, so a connection does not hold a
  second copy of its largest message between frames (the reassembly buffer keeps its own, as before), and the next
  frame allocates once. The reuse makes a null frame buffer reachable -- after such a frame, or on a client whose
  Ping, Pong or Close handler moves `event.ws._data` out -- so the unmasked copy is guarded: an empty frame there
  would be `memcpy(nullptr, src, 0)`, undefined. An empty Ping, Pong or Close after such a frame carries a null
  `event.data` with its size of 0: a view, as before, to be copied by its size.

- **The HTTP/2 server moves a regular field's NAME into the request beside its value (Huly QB-1216).** The value moved
  since QB-1215; the name was still copied and folded by qb's `string_to_lower::convert()`, which took only a const
  string -- three allocations a browser's request (the names past 15 octets). With qb's new `convert(std::string &&)`
  the name is folded in place and moved into the header map: 3 blocks and 62 bytes fewer a request, ~620 instructions
  (callgrind, g++ 14, on top of the lazy body). A/B on top of the lazy body (3 copies a side, seeded order, pinned
  P-core): g++ 14 0.998 / 0.992 (default family) and 0.979 / 0.978 (`-falign-functions=64`), MSVC 19.51 0.960 / 0.960
  and 0.968 / 0.966 / 0.991 across three `/FUNCTIONPADMIN` layouts. Taken without the lazy body it reads 4..6 % SLOWER
  on g++'s `BrowserGet`: while the two 4 KiB bodies keep `malloc_consolidate()` running, the request's new allocation
  pattern sends 8 more small allocations a request down `_int_malloc`'s slow path.

- **A `Body` creates its pipe at its first write: an empty request or response body allocates nothing, and the HTTP/2
  request path no longer makes glibc consolidate its fast bins (Huly QB-1216).** A default-constructed
  `qb::allocator::pipe` allocates 4 KiB up front, and `Body` held one by value, so every `Request` and `Response` paid
  4 KiB for a body most of them never write -- every GET, every bodiless response, the two messages of an HTTP/2 stream
  (8 192 of the 12 108 bytes a browser's HTTP/2 request asked for, and two of the allocations past glibc's 1 KiB
  threshold that made `_int_malloc` run `malloc_consolidate()` on every request); the HTTP/1.1 parser paid it twice a
  message (the message rebuilt by `reset()`, then replaced by the parser's buffer). The body is now an optional pipe
  created by the first write (`operator=`, `operator<<`, the variadic constructor, `add_chunk`, the non-const `raw()`);
  `size()`, `empty()`, `clear()`, `as<>()` and the const `raw()` read an empty body without creating one (one shared
  empty pipe). **The non-const `raw()` is a write: it creates the pipe and is no longer `noexcept`** -- read a body you do
  not write through `size()`, `as<>()` or `std::as_const(body).raw()`. The HTTP/1.1 parser hands its buffer over by
  `Body::operator=(qb::allocator::pipe<char> &&)` (new). Counters (g++ 14): an HTTP/2 request 55 015 -> 48 496
  instructions, `malloc_consolidate` 1 526 -> 0, 61 -> 59 blocks and 12 108 -> 3 932 bytes; a 2-line HTTP/1.1 parse 6 -> 4
  blocks. A/B against the tip (3 copies a side, seeded order, pinned P-core): g++ 14 reads the HTTP/2 request 12.5 % / 9.4 %
  faster (0.875 [0.867, 0.880], 0.906 [0.897, 0.913]; 3 539 -> 3 096 ns), under `-falign-functions=64` 12.4 % / 9.1 %, the
  2-line HTTP/1.1 parse 19 % / 22 %, the warm HTTP/1.1 loopback 2.0 % / 2.4 %; MSVC 19.51 reads the 2-line HTTP/1.1 parse 15 % faster (338 -> 288 ns) and the HTTP/2 request level-to-faster across three `/FUNCTIONPADMIN` layouts (1.000, 0.997, 0.981), every other cell level. The WebSocket
  masked-text decode cell reads 7.3 % slower on g++: its per-frame `ws::Message` still allocates a 4 KiB pipe, and with two
  fewer 4 KiB chunks freed around it that allocation takes a longer path through glibc's bins (`_int_malloc` 142 -> 601
  instructions a frame in the timed decode; no page fault).

- **The HTTP/1.1 Host check tests a four-octet field name with one 32-bit load (Huly QB-1218, follow-up of QB-1186).**
  `note_host_field()` compared every four-octet name with `utility::iequals(name, "host")`, which MSVC 19.51 renders as
  four byte compares with three branches each on the header-complete path of every request; it now ORs one 32-bit load
  with `0x20202020` and compares it with `host` (`is_host_name()`): the only octets that fold to `h`, `o`, `s`, `t` under
  that OR are the two cases of each letter, so the verdict is the same for every input. MSVC's header-complete path is
  15 instructions shorter (`on_headers_complete` 419 -> 404, `on_header_field` 250 -> 237). The +2.6 % MSVC read on
  `BM_Http1Parse_WholeBuffer/corpus:0` when this form was first measured is code placement: across three `/FUNCTIONPADMIN`
  layouts the cell reads 1.023, 0.979 and 0.964 (the sign flips); g++ 14 reads it level in two alignment families (0.998,
  1.004). Absent, duplicate and malformed Host fields are judged as before (RFC 9112 Section 3.2).

- **An HTTP/3 connection copies a received field once, when it keeps it, and keeps a section once (Huly QB-1203, points
  2 and 3).** `recv_header_cb` copied each field's name and value before judging it -- a field then dropped for the
  limits included, so the CPU a section cost followed the length the peer chose -- and the section's fields were
  copied again into the message while the section itself stayed in the stream's state until the stream closed: two
  copies of every section, up to the 64 KiB bound each, for as long as a body took to come. Fields are now read in
  place, a kept one copied once -- a header section's moved into the message, a trailer section's copied there --,
  and the section released once read (or refused), allocating nothing: the empty section assigned in its place, and
  at the start of every section, allocated a map and a node under libstdc++. A received section no longer builds the
  `nghttp3_nv` views a section that is sent needs, which nothing read: a vector grown field by field. Measured on the
  in-process nghttp3 pair (macOS, libc++): six dropped values of 9 000 bytes allocated 79 784 bytes on the base and
  25 736 now (the stream's state and the 431 answer); a request with 56 KB of fields, its body still to come, kept
  130 KB and now under 84 KB; a browser's 18-field GET read by the server on a warm connection allocates 16 057 bytes
  where it allocated 18 914. The section bound itself (point 1) is the next entry.

- **The HTTP/3 field-section bound is 1 MiB, the bound HTTP/2 puts on a header list (Huly QB-1203, point 1; the
  maintainer's decision of 2026-11-03).** 3.3.0 advertised 64 KiB as `SETTINGS_MAX_FIELD_SECTION_SIZE` and enforced
  nothing; QB-1196 (under Fixed) and QB-1204 enforced that 64 KiB on both roles, beside request limits that are
  settable: under the default limits -- 100 fields, a value of 8 KiB -- a request of 90 fields of 8 000 bytes, some 0.7
  MiB, which the HTTP/2 server serves, was refused by the HTTP/3 client before it was sent (the server's 64 KiB) and
  answered `431` by the HTTP/3 server that read it; a response of that size was never submitted by the server (the
  client's 64 KiB), and a client that read one discarded it. Both roles now advertise and enforce 1 MiB: such a section
  crosses both ways. The default limits keep every section a well-formed request within them can carry below the bound
  (nghttp3 decodes a name of 256 bytes at most), so it binds a server whose limits are raised: exactly 1 MiB is served,
  a byte more answered `431`. A client's limits are fixed, so its bound is never reached. A section a stream keeps while
  its body comes can now reach what the limits allow, under 1 MiB (some 0.9 MB under the default limits), as an HTTP/2
  stream's header list can: with QUIC's 100 concurrent streams a connection's sections can hold some 90 MB, where the 64
  KiB kept them near 6.5 MB (HTTP/2: 50 streams). A peer that advertises less is still held to its own bound (Huly
  QB-1204).

- **The HTTP/2 server's request path allocates 14 blocks and 5 KiB less a request (Huly QB-1215).** A browser's
  18-field request cost the server 75 allocations and 17 385 bytes, and glibc's allocator 27 % of its instructions
  (`qbm-http-bench-http2-server-request`, DHAT and callgrind on g++ 14; the P9 finding). Each stream owned a fresh
  `std::vector<HeaderField>` that grew 1 -> 2 -> 4 -> 8 -> 16 -> 32 fields for that request -- six allocations, 4 536
  bytes, two of them past 1 KiB --, copied every regular field's value into the request's header map, copied the raw
  header block into the stream "for PUSH_PROMISE validation" (read by nothing), carried a `qb::io::uri`, a `method`
  string and two more members nothing read (a 1 080-byte node), and every response grew a fresh field vector and
  copied its encoded block into the HEADERS frame. Now the block is decoded into ONE vector a connection
  (`ServerHttp2Protocol::_decoded_header_fields`), cleared on every exit of the block handler and after a refused
  block is dropped -- its capacity serves every stream, nothing of one stream reaches the next --; a regular field's
  value moves into the request (a `host` value is still copied: it names the authority after the loop); the block copy
  and the four dead members of `Http2ServerStream` are gone (the struct is private to the protocol; the request's
  method and URI are `assembled_request`'s); the response's fields go to one vector a connection too, and a block that
  fits one frame is moved into it, CONTINUATION frames sent only when it does not. DHAT: 61 blocks / 12 108 bytes a
  request (75 / 17 385 before); callgrind: 55 015 instructions a request (61 135 before, -10 %). A/B (3 physical
  copies a side, seeded order, a pinned P-core, against the tip): g++ 14 reads the request 7.6 % / 10.2 % faster
  (0.924 [0.911, 0.940] and 0.899 [0.886, 0.904] with `host`; 3 850 -> 3 557 ns and 3 920 -> 3 523 ns), under
  `-falign-functions=64` 8.0 % / 9.3 % (0.920 [0.912, 0.929] and 0.908 [0.904, 0.916]); MSVC 19.51, whose heap charges
  more per allocation, reads it 17.0 % / 15.9 % faster (0.830 [0.821, 0.841] and 0.841 [0.829, 0.846]; 4 958 -> 4 115
  ns and 5 069 -> 4 262 ns). What stays is named in the ticket: the header map's own 39 allocations (a node, a value
  vector and the strings of each field: the container's shape), the 3 folded key copies (qb's
  `string_to_lower::convert()` takes no rvalue), the URI's and the cookies' 6 each, and the two 4 KiB buffers a
  default-constructed `qb::allocator::pipe` allocates for the Request's and the Response's empty bodies -- 8 KiB a
  stream, the large allocations that still make glibc consolidate on every request (a qb primitive). No behaviour
  changes: the header-list bound, the dynamic table, the whitespace rule, the limits and the 431 / 414 / 413 answers
  are as they were; `ctest -L http2` on the landed tree, g++ 14: 19 registered / 19 executed / 0 skipped, 0 failed,
  Release and under ASan+UBSan alike.

- **Upgrade note: under `CompressionMiddleware`, a static file larger than `StaticFilesOptions::stream_threshold` is
  no longer compressed on HTTP/1.1 (Huly QB-101).** Superseded in this same release by Huly QB-1208 above: a streamed
  body is now coded on the fly, and the threshold no longer decides whether a large text asset leaves compressed. The
  static files stream such a body (next entry), and a streamed body reached the `PRE_RESPONSE_SEND` hooks empty, so
  the compression hook left it alone until QB-1208. With the default threshold, 1 MiB, a text asset over 1 MiB -- a bundled
  script, a stylesheet, a JSON, CSV or SVG file -- that 3.3 sent compressed to an HTTP/1.1 client is sent as it is on
  disk, its `Content-Length` the file's and no `Content-Encoding`. HTTP/2 and HTTP/3, which read every body whole,
  still compress it, and so does HTTP/1.1 below the threshold. To keep compressing such assets on HTTP/1.1, raise the
  threshold above the largest of them (`with_stream_threshold()`; `SIZE_MAX` streams nothing): each of their downloads
  then holds the whole file in memory again, as in 3.3, under `max_file_size`.
- **`StaticFilesMiddleware` streams a body over `StaticFilesOptions::stream_threshold` on HTTP/1.1: a download holds
  the stream's high watermark and two 64 KiB pieces, not the file, so N concurrent downloads no longer cost N copies
  of it (Huly QB-101).** Every request used to read the whole file, or the whole range, into the response, and the
  session then held two more copies while it sent it: under 16 slow clients a 64 MiB file took the server's footprint
  to 2,117 MiB (132 MiB a request), and a file over `max_file_size` (64 MiB by default) could not be served at all. A
  body (the file, or the range asked for) of more than `stream_threshold` bytes -- 1 MiB by default,
  `default_stream_high_watermark`; `with_stream_threshold()`, `0` streams every non-empty body, `SIZE_MAX` none -- now
  goes through `Context::begin_stream()` (Huly QB-86) where the session is a `streaming_session` (the HTTP/1.1 and
  HTTPS/1.1 server sessions): `internal::StaticFileStreamer` reads it in pieces of at most 64 KiB (half the high mark
  at most) and reads the next one only while the connection's output is under the high watermark, waiting on
  `on_drain()`; after a turn's worth of pieces that did not fill the output (a session that is disconnecting takes
  writes it drops) it gives the turn back, so the disconnection reaches the stream before the file is read through.
  The same 16 downloads now peak at 43 MiB (2.6 MiB a request) in the same 2.5 s, every body checked byte for byte;
  with clients that read as fast as they can, 41.5 MiB against 2,117 MiB, in 1.31 s against 1.53 s; and 16 downloads
  of a 512 MiB file, which the base refused, peak at 56 MiB. The answer is the one a buffered response gives -- status,
  `Content-Length`, `Content-Range`, `ETag`, `Last-Modified`, `Accept-Ranges`, `Cache-Control`, bytes -- for a full
  GET, a range, a suffix and an open range, `If-None-Match`, `If-Modified-Since`, `If-Range`, an unsatisfiable or a
  multiple range and `HEAD`, which a test compares against the same server with streaming off; `HEAD`, `304` and `416`
  never stream. What changes, and is documented in `readme/08`: `max_file_size` bounds a body read whole only, so a
  streamed body is served whatever its size and a `HEAD` or a range of a file over the cap gets what its `GET` would
  (`200`, `206`, `416`, not `413`); a streamed body was not compressed until Huly QB-1208, above (`PRE_RESPONSE_SEND` hooks see
  an empty body); a file that fails or shrinks after the head has left
  closes the connection short of its declared length; a download keeps its file open until its last byte, for as long
  as its client takes -- read through qb-io's descriptor (`internal::StaticFileSource` over `qb::io::sys::file`), which
  on Windows shares delete (Huly QB-320), so a file being downloaded can be renamed away and its name removed there
  too, where `std::ifstream` refused both until the download's last byte (an operator replaces a served file by
  renaming the old one away first: a rename over it is refused on Windows while it is read). A
  `PRE_RESPONSE_SEND` hook that leaves a head a stream cannot carry gets the body read whole, under the cap, and over
  it the 413 a buffered server gives; one that answers a status without a body leaves the file unread -- it used to be
  read, and the serializer then refused the 304 it carried. HTTP/2 and HTTP/3 read every body whole, under
  `max_file_size`, as before: their sessions offer no streaming hooks yet. No `sendfile()`: it would bypass the
  session's output buffer, cannot serve TLS, and qb-io's transports do not offer it. The whole-read path's seek and
  read failures answer their 500 without the length and range they no longer describe (the serializer refused the
  pair, and the connection dropped with no answer). Small files take the path they always took: an A/B against the base (three byte-identical copies a side, seeded order, a drained host) puts loopback GETs of a 16 B to 1 MiB file and the middleware benchmark's GET, HEAD, range and `304` cells within 2 % of the base, inside the spread between identical copies, and serves a 4 MiB file, now streamed, 20 % faster. Proven by
  `qbm-http-test-system-static-files-stream` (26 cases over a raw loopback client, one over TLS: every byte, the
  output bound under a client that does not read, the differential against a buffered server, the cap, a peer that
  leaves, a file that shrinks, a session that drops what it is given, HTTP/1.0, pipelining, chunked framing, every
  hook case, compression, a file renamed away and replaced under a download, and a parked download's producer,
  stream and file released after the peer leaves, a cancel and an abort), a case each in `qbm-http-test-system-http2-client` and
  `qbm-http-test-system-http3-loopback` (the buffered path, the cap still enforced) and two in
  `qbm-http-test-unit-middleware-static-files`; 11 of the first 13 fail on the base. 44 mutants on the final code: 38 caught, 6 equivalent or unreachable, each explained in the commit.

- **`connect()` on the three HTTP clients answers a refusal by its return value alone, and the HTTP/3 client starts
  the `connect()` asked during a close once that close has run (Huly QB-1246).** In 3.3.0 a `connect(callback)` that
  started nothing could call its callback with `false` from inside the call, then return `false`: `qb::http1::Client`
  with no shared owner (a plain object, not `make_client`'s) or called from a callback its destructor ran, and
  `qb::http3::Client` in ordinary operation -- whenever a close was under way (asked from a failure callback of
  `disconnect()`, from a response callback that had just called `disconnect()`, or from a response callback whose read
  had lost the connection) and whenever the attempt could not start. A callback that dials again when it hears `false`
  was then called from inside its own `connect()`, again and again: the witnesses stop it at 64 dials, and measured 64
  calls nested in one another. `connect()` now returns `false` only when nothing starts, and never calls its callback
  then; `true` means the callback will hear the outcome, inside the call only when the client is already connected. On
  HTTP/3, a `connect(callback)` asked while a close is under way returns `true`, as the HTTP/2 client's does: the
  handshake starts once the close has run -- at the end of `disconnect()` for an explicit close, when the read returns
  for one that read deferred and for a connection lost during it -- and the callback hears that attempt's outcome. A
  `disconnect()` before the attempt starts gives it up: its callback hears `false` from that close. `disconnect()`
  never starts a `connect()` asked before it, one asked from a failure callback of the lost connection's teardown
  included; one its own callbacks ask starts at its end. The coroutine `connect()` is the one form that does not wait
  for a close, on the three clients: awaited from a callback of one, it completes `false` without waiting for an attempt
  ("... connection is closing"), as what it would wait for is, after most of them, heard only once that callback
  returns. That `false` is an answer the client gives by itself, under the rule of the first bullet below: heard on the
  client's turn of the loop, which a `run_sync()` runs -- in 3.3.0, where it was given, inside the `co_await`. A close
  is every close and every failure of a connection or an attempt: `disconnect()`, a response or a read that ends its
  connection, a connection lost or closed by the server, an error GOAWAY or the end of a graceful GOAWAY's drain on
  HTTP/2, an attempt that failed or timed out. A coroutine that a loop nested in such a callback resumes is answered
  the same: the rule reads what the client is doing, not who awaits. What a `run_sync()` of it did there is in each
  client's bullet. A request pushed during the close is taken or refused as before: on HTTP/3 it is refused, `503`,
  during a `disconnect()` or once the server's GOAWAY has come; on HTTP/1.1 it is queued behind the next connection
  with automatic reconnection on, refused `503` with it off; on HTTP/2 it is queued for the next connection --
  the reconnection run's, or one it starts for it once the close's transport has ended. The three clients are also
  destroyed under one contract (the entry under Fixed). What a program sees change against 3.3.0, every change of the
  two entries, client by client:
  - **A callback that always pushes again (HTTP/1.1, HTTP/2, HTTP/3): a change of the clients' contract, which the
    maintainer accepted on 2026-11-20.** The contract as accepted on 2026-11-13 answered a push made from a callback
    inside that push -- in ordinary operation as 3.3.0 did, and from the callbacks the destructor runs -- and left the
    program to "bound every retry": a callback that always pushes again was called from inside its own push, without
    end. It now reads: what the client answers by itself to a push made from one of its own callbacks is heard on the
    client's next turn of the loop, and while the client is destroyed a push made from inside the answer of a push is
    refused, `false`, its callback never called. Each of the three clients keeps one queue of the answers it owes,
    oldest first. Two things hear it: the client's own turn of the loop, and its destructor. An answer the client gives
    by itself -- a refusal known at once (another origin, the pending bound, a target that cannot be sent, a request
    that cannot be written or submitted, one the connection cannot take on HTTP/2 -- the server's limit of concurrent
    streams --, no connection with automatic reconnection off on HTTP/1.1, a `disconnect()` under way or a server's
    GOAWAY on HTTP/3, a batch whose members are all refused),
    `connect()` on a client that is connected, an empty batch, a cancellation on HTTP/3, a
    coroutine push completed at once, the `false` of a coroutine `connect()` awaited during a close, what a
    `disconnect()` the program calls ends (the requests it fails, the `connect()` it gives up), what a connection lost
    under a push's own submission ends on HTTP/3 -- is given inside the call only when no callback of this client is on
    the stack and nothing is owed; otherwise it joins the queue. An answer the loop brings -- a response, a timeout, a
    failure, a close -- is given directly when nothing is owed, and joins the queue behind what is. A turn hears what
    was owed as it started; what those callbacks push waits for the next turn. A callback that pushes its request back
    at every failure is then called once a loop turn, never from inside its own push; in 3.3.0 each refusal was answered
    inside the push, one frame deeper each time. The rule is each client's own: a callback of one client that pushes to
    another gets that other's refusal inside the push. What follows from it. Every answer is heard exactly once, in the
    order the client came to owe it, and a request has one outcome: its answer, or the exception that left its own
    push before any answer, never both. On HTTP/2 and HTTP/3 a push lets through what the callback of another request
    throws when that push answers it on its way, and on HTTP/3 what cuts its submission short (the two entries under
    Fixed): what it was pushing is then taken back, unanswered, and the requests that waited behind the one whose
    callback threw are still sent before the exception goes on. The HTTP/1.1 client logs what a callback throws. And
    what a callback the loop brought throws -- a response, a failure, a timeout, a close -- is contained and logged by
    the three clients: it costs no other request its answer, no connection, and not the process (under Fixed).
    "Logged", in this entry and in those below, is a WARN line where the build has a logger: with `QB_WITH_LOGGING`,
    the default, in qb's log -- `./qb.1.log`, or the file `qb::io::log::init()` names --; with `QB_STDOUT_LOGGING` in
    its place, on the standard output. A build with neither writes nothing, and contains the exception all the same.
    With callbacks that run no loop turn of their own, no callback of a client is called inside another one of the same
    client: nesting is exactly one outside the destructor. A callback that runs the loop -- `qb::io::async::run()`,
    `run_once()`, `run_until()`, `run_sync()` -- receives inside that loop whatever the client owes, its own refusals
    included: one that pushes a refused request back and then runs the loop recurses once per refusal. To relaunch
    without nesting, push back and return. That is how a coroutine awaited from a callback with `run_sync()` completes.
    With nothing owed, an answer is given where 3.3.0 gave it, but for the answers the client gives by itself under one
    of its own callbacks, which 3.3.0 gave inside the call.
    While the client is destroyed no later turn exists. Its destructor hears what is still owed first, in order, each
    as a callback the destructor runs: a request pushed from one is answered inside that push, and one pushed from
    inside THAT answer returns `false` and is never answered (`push_requests()` likewise, an empty batch included). An
    answer that comes meanwhile takes its place behind what is still owed, as in ordinary operation: one the loop brings
    -- a callback the destructor runs ran the loop --, and one the client gives by itself -- such a callback called
    `disconnect()`, whose failures were heard ahead of a refusal owed before them. The coroutine
    `push_request()` and `push_requests()` awaited from a callback of a close complete `503`, "... connection is
    closing", without waiting for a connection: an answer the client gives by itself, which the loop turn of a
    `run_sync()` hears. A `run_sync()` of one there waited for the request's timeout on HTTP/1.1 (`408`), for the
    attempt it had started on HTTP/3; on HTTP/2, under a close the client makes for a frame it refuses, it did not
    return -- the request waited for a connection that starts only once the callback has returned. No request leaves
    a timer armed behind it, refused or answered: on HTTP/1.1 and HTTP/3 by the entry on the request's timer, under
    Fixed; the HTTP/2 client arms one timeout, for the nearest deadline of what it still holds.
    **What stays the program's: bound every retry, and space the attempts.** A callback that pushes back at once at
    every failure is not called from inside its own push, but it spins: one push a loop turn for as long as the cause
    lasts. Give a retry a count of attempts or a deadline, and a delay between two. On a client of any protocol with
    no shared owner, a refusal is answered inside every push: an unbounded retry there recurses until the stack
    overflows.
    Witnesses, each red on the code before it: on HTTP/1.1 a callback that always pushes back, automatic reconnection
    off, hears fifty refusals, one a turn, then is served by the push that connects (it nested 64 deep, where the case
    stops it); on HTTP/3 one goes through two rounds of a `disconnect()` with a request in flight, one call deep, and
    each of the four refusals it knows at once is pushed back twenty times from its own callback, one answer a push; a
    batch pushed back at every refusal (ten deep before); on both clients a callback that pushes back and then pushes an
    empty batch, calls `connect()` on a connected client or, on HTTP/3, cancels a request -- one call a turn, each of
    those answers behind the refusal (two hundred deep inside the program's first push when such an answer heard what
    was owed before it was given); the order of the answers, a coroutine push completed at once and the `false` of a
    `connect()` a close gives up among them; a kept refusal heard once by the loop turn its callback runs, once from the
    destructor, and two of them heard alike there; a callback the destructor hears that runs the loop, the turn that was
    asked finding no client to hear for; a callback that pushes back while ten queued requests time out -- sixty-nine
    calls, each exactly one deep, when it returns, and when it runs the loop every call under the loop turns it runs
    itself and no other (an invariant the code before held too: ten and seven deep there, one here, sixty -- the case's
    cap -- where the loop it runs delivers what the client owes); a member of a batch refused before a close, which
    keeps its own answer and is counted once; the loop's count of watchers unchanged after twenty refusals; a request
    timed in flight, left in the queue and behind a connection, alone or in a batch; at the destruction three pushes get
    two answers on each client. On the three clients, while the destructor hears what is owed: a response the loop
    brings takes its place behind it (it went ahead of the second of two refusals), the failures of a `disconnect()`
    its callback calls wait behind it too, and an empty batch pushed back from its own callback ends at its second
    push (a hundred calls, a hundred deep, where the case stops it); and the `false` of a coroutine `connect()` awaited
    during a close has its place in the order of the answers, behind the refusal owed before it (it came ahead).
    On HTTP/2, in `qbm-http-test-system-http2-client`, the same set, fifteen cases, eleven
    red on the code before -- the four others pin what did not change --: a callback that pushes back at every refusal
    (another origin, the bound of the queue, a request past the server's limit of concurrent streams), two hundred
    deep inside the program's push before and one call a turn now; the same followed by an empty batch or a `connect()`
    on a connected client; the ten timeouts (sixty-nine calls, one deep when it returns, fifty-nine of them under
    another call before; sixty deep, the case's cap, under the fifty-nine loop turns it runs itself); the order of the
    answers, a timeout, a response, a coroutine push and the `false` of a `connect()` among them; the destructor's
    second push, for a request and for a batch (sixty-four pushes before, three now); a callback the destructor hears
    that runs the loop; a `run_sync()` of a coroutine push from the failure callback of a close, which did not return;
    and a callback that drops the last reference to a client owned apart from its control block, from ten callers --
    under `disconnect()` and under the timer's pass the client went on writing into itself, freed.
    Mutants of the code these changes leave, the unmutated tree first and the restored tree
    last: the rule, on HTTP/3 27 planted, 26 caught, on HTTP/1.1 19 planted, 17 caught -- of the three that survive,
    two are read only by a failed allocation (the turn asked again at the end of a turn, on each client: the answer that
    was kept has asked already) and one holds the client where every answer leaves a hold of its own (the turn's task
    on HTTP/1.1). The hold `push_requests()` takes on HTTP/3 is no such case, as this entry first had it: without it a
    batch refused whole, whose callback drops the last reference, went on in freed memory -- that batch is its witness,
    pushed by the program on a client owned both ways. The address fallback, 6
    planted, 5 caught -- the sixth is equivalent (an address given up after the deadline: the connect timeout has ended
    the attempt by then); where a request is timed on HTTP/3, 4 planted, 3 caught -- the fourth is equivalent since a
    request's answer stops its timer first (a request timed where it is queued, and refused where it is submitted).
    On HTTP/2, the rule, each answer the client gives by itself, the destructor's level and the five holds: 33 planted,
    32 caught -- the survivor is the protocol pass `process_pending_requests()` opens: the one dispatch a send raises
    under it is the HPACK encoder's refusal, the last thing that send does, and nothing reads the protocol after it.
    The destructor's order, its empty batch and the `false` of the coroutine `connect()`, five a client, planted on the
    destructor's one rule: 15 planted, 15 caught -- three of them, the client's own answer given inside the call while
    the destructor still has answers to hear, by the case of a `disconnect()` its callback calls.
  - **All three.** `false` from `connect()` now always means that nothing started and that the callback is never called,
    and `true` that the callback will hear the outcome, inside the call only when the client is already connected,
    with no callback of that client on the stack and nothing owed, by the bullet above; each client's bullet says what
    that changes for it. A request pushed from a callback the destructor runs is answered inside the push. One pushed
    from inside that answer returns `false` and is never answered, so a callback that pushes its request back on every
    failure ends at its second push (the bullet above). That is new on HTTP/2, whose destructor queued such a push. It
    is not new on HTTP/1.1:
    3.3.0 already answered such a push inside it, its destructor having no owner left to connect for it. It is partly
    new on HTTP/3: 3.3.0 answered a push inside the push during a `disconnect()` or once the server's GOAWAY had come,
    the destructor's close included, but queued one made from a callback of the destructor's first pass, before its
    close.
  - **HTTP/1.1.** The callbacks of a `connect()` still waiting when the client is destroyed hear `false`, once (they
    were destroyed unheard), and a coroutine parked on `connect()` is then resumed with `ok == false` when the loop
    still runs (it stayed parked for ever). `connect(callback)` on a client with no shared owner, or called from a
    callback the destructor runs, returns `false` and calls nothing (it called the callback inside the call, with
    "HTTP/1.1 client no longer available"). The coroutine `connect()` awaited from a callback the client runs while a
    connection is retired -- of `disconnect()`, of a response that closes its connection, of a lost connection, a
    timeout or a failed attempt -- completes `false` without waiting, "HTTP/1.1 connection is closing":
    `connect(callback)` there is deferred until those callbacks have unwound, and a `run_sync()` of it never returned
    (measured from a failure callback of `disconnect()` and from the callback of a response that closes its connection).
    With automatic reconnection off, a request queued behind a response that closes its connection, or behind a 101 its
    request never asked for, fails inside that close, the connection still retired; so does, with it on, a request
    kept for the next connection behind one whose connection a timeout or the server ended, once the failure callback
    of that one turns automatic reconnection off (a policy that gives up). The coroutine `connect()` awaited from its
    callback then completes `false` without waiting: the request failed at the tail of that loop turn, from the reset of
    the retired connection, where that `connect()` was not refused, and the refusal of the attempt it started waited in
    the loop's deferred queue, which a nested pump cannot drain -- a `run_sync()` of it blocked until the connect
    timeout (30 s by default), for ever when the refusal is known at once. Awaited again once an attempt failed, outside
    its callbacks, it gets the next attempt's own outcome, as before. A loop pumped from a callback of a close -- a
    `run_sync()` of any coroutine there, the refused `connect()` included -- no longer leaves the connection retired:
    the reset it waited for ran in that pump, the callback still on the stack, and gave up, and
    the connection stayed retired until the client next ran a callback. A request pushed then, automatic reconnection on
    (the default), waited for its request timeout (408, 60 s by default), whose callback restarted the connection;
    without one it was never answered. What the callback of a `connect()` made on a connected client throws is logged
    and goes no further, as for every other callback of this client (it reached the caller of `connect()`). No deadline
    is armed for a request pushed from a callback the destructor runs (one was: asked of the loop after it, a timer
    stops the process). Such a request was already answered inside its push -- `503`, but `400` for one the client
    refuses, for another origin, which now gets `503` too --, and a callback that threw was already logged.
  - **HTTP/2.** A request or a batch pushed from a callback the destructor runs is answered inside the push, `503`
    "Client destroyed" (it was queued with a deadline armed, and sent on the connection the destructor was closing or
    on one started for it; the destructor's close then failed it, `503` "Connection closed", and a request pushed from
    a callback of that close was destroyed unanswered). `connect()` from such a callback returns `false`, calls
    nothing and starts nothing (it started a connection). What such a callback throws is logged, and the destructor
    goes on (the process ended in `std::terminate()`). The destructor arms no timer (it armed the deadline and the
    connect timeout of what its callbacks asked: after the loop, a write into freed memory). A callback that pushes
    back on every failure ends there at its second push (its pushes were queued). A request pushed from the callback
    of a `connect()` that failed, or that a close refused, is the next attempt's: it is not failed with the attempt
    that ended -- "Connection failed: ...", "Connection closed" --, and with automatic reconnection on it waits for the
    attempt the run schedules, as one pushed from a request's failure callback does (it connected on its own, at once,
    then was failed by the pass that followed, its attempt going on for nobody). A `connect(callback)` asked from a
    callback of a lost connection starts once that connection is torn down, never under the callback: a callback that
    then ran the loop saw the attempt connect under the teardown, which stopped the new connection on its way out
    (the entry under Fixed). A close ends the transport it found and no other: the next connection, which a callback
    that ran the loop saw come up, is no longer ended by the close of the one before it (the same entry). A
    callback may drop the last reference to the client from under `disconnect()` and from a timeout. A `connect()`
    asked from the callback of a waiting `connect()` whose transport ended before the client had read anything of it --
    the peer closing it once its TLS handshake was complete -- starts an attempt of its own, whose callback hears its
    outcome (it joined the attempt that had just ended and returned `true`: nothing started for it, and its callback was
    never called, not even by the destructor). The coroutine `connect()` awaited from a callback of a close or of a
    failure -- `disconnect()` (of a connection, of a connector in flight, of neither), a connection error or an error
    GOAWAY, the end of a transport (the server's close, a lost connection), a graceful GOAWAY's drain, an attempt that
    failed or timed out -- completes `false` without waiting, "HTTP/2 connection is closing". A `run_sync()` of it there
    blocked for the connect timeout, for ever with none -- measured after a failed handshake (2000 ms with a 2 s one),
    after the end of a transport before its handshake and after a connector that failed at once (1 s with a 1 s one:
    qb-io delivers such a failure through the loop's deferred queue, which runs no nested drain, and the next attempt's
    failure came the same way) --; after a GOAWAY's drain it had not returned past 5 s, the bound of its witness; after
    a `disconnect()` of a connection or of a connector in flight it got a connection the close then ended. From a
    failure callback of a connection the server closed, the attempt it started connected inside the handler of the
    transport's end, where qb-io stops a build with assertions on its `io::start() from inside dispose()` assertion
    (without them, by reading, dispose() ended that connection once the handler returned). From the callback of a
    connect deadline whose connector was still in flight (measured), and of a connector failure whose next attempt
    reached a server (by reading), a `run_sync()` of it returned that next attempt's outcome; it completes `false` at
    once there too now: one rule for every close and failure. `connect(callback)` from a close or a failure still
    waits for it, or starts as before. A connection started right after an explicit `disconnect()` whose failure
    callback ran the loop -- a `run_sync()` there -- is no longer cut, `GOAWAY_FLUSH_LIMIT` later, by that close's
    flush limit: the pass had delivered the GOAWAY and ended the transport, and the close then armed its limit for a
    transport already gone. The flag that keeps the queue for the end of a closing transport is set the same way,
    before the callbacks: a request such a callback pushed before its pass rides the next connection (it was failed
    "Connection lost" by an end that found the flag not yet set), and a request pushed after such a close hears the
    end of its own connection when that ends before its handshake (it waited for its request timeout, for ever with
    none). The two other closes that run callbacks before they end the transport -- a failure once a transport is up
    (a connect deadline, a handshake that negotiates no h2) and the end of a graceful GOAWAY's drain -- set the same
    flags before their callbacks too: after one whose failure callback ran the loop until the transport ended, a
    request pushed afterwards hears the end of its own connection (it waited for an end that never came, for ever with
    no deadline). A `disconnect()` of a connector still in flight, which has no transport to end, no longer closes the
    io nor sets that flag: on the client's first connection the `disconnected` that close raised failed a `connect()`
    asked in the same turn, "Connection lost (reason: 1)" -- the attempt then connected unheard, and a `connect()`
    asked again from that `false` started a second one beside it --; on a later one, whose io qb-io had disposed, it
    raised none, the flag stayed set, and a request pushed afterwards whose connection ended before its handshake
    waited for its request timeout, for ever with none. "Failing all requests" is logged only when a request or a
    batch is failed (every pass logged it), and such a pass no longer logs "Received response for unknown batch" once
    for each member of a batch it fails, nor "Failing incomplete batch".
  - **HTTP/3.** `connect(callback)` asked during a close returns `true` and starts once that close has run (it answered
    `false` inside the call, "HTTP/3 connection is closing"); a `disconnect()` before the attempt starts gives it up.
    The coroutine `connect()` awaited from a callback of a close or of a failure -- `disconnect()`, a read that
    disconnected or lost its connection, a connection lost or closed by the server, an attempt that failed or timed out,
    and the request whose submission closed its connection -- completes `false` without waiting, "HTTP/3 connection is
    closing".
    In 3.3.0 it did from a callback of `disconnect()` and of a read that lost its connection; but on a connection that
    still delivered data a loop pumped there by a `run_sync()` of it read that data, the read completed the close from
    inside the close, and the awaiter got a connection that the close, once resumed, ended -- what a closing connection
    still delivers to such a loop is now dropped with it. From a callback of a failure it started an attempt whose
    `connected` the endpoint delivers only once its dispatch, on the stack, has returned: a `run_sync()` of it there
    blocked for the connect timeout, for ever with none, the server answering (measured with none, after a connection
    lost during a read and after one the server closed). From the failure callback of a request whose submission closed
    its connection, run after the teardown's, it started the next attempt and returned its outcome; it completes `false`
    there too now, for one rule. From the callbacks of an attempt that timed out, run from a timer, it started the next
    attempt and waited for it; it completes `false` there too now. A `connect()` whose attempt cannot start -- a name
    that resolves to no address, a UDP socket that cannot be opened or bound, an address whose first datagram the
    network refuses -- returns `true` and its callback hears `false` on a later turn of the loop, as on the two other
    clients (it called the callback inside the call and returned `false`, and ran the failure of what was waiting from
    inside the call); a `WARN` line says that nothing started, and which of the two it was: no UDP socket opened and
    bound, or a first datagram the network refused. A client with no shared owner keeps the return value alone. A host
    name now connects (the entry under Fixed). With a connect timeout set, an address that does not answer is no longer
    given up at QUIC's own handshake timeout, ten seconds by default: QUIC's bound on a handshake follows the connect
    timeout attempt by attempt -- a lone address has thirty seconds by default, where it had ten. curl's ngtcp2 backend
    does the same since it takes that bound from the connect timeout (`quic_settings()` in 8.16.0; 8.10.1 used a fixed
    ten seconds). The bound of a `connect()` is the connect timeout, or QUIC's idle timeout when that is shorter: the
    client leaves the program's `idle_timeout` as it is -- thirty seconds by default, as the connect timeout, whose
    timer is due first --, and it ends an attempt that hears nothing, "QUIC idle timeout". With no connect timeout,
    QUIC's own bounds stay the ones there are. A request or a batch pushed from a callback the destructor runs is
    answered inside the push, `503` "HTTP/3 client disconnect" (it was queued with a deadline armed and a connection
    asked for it, then failed by the destructor's close with the same answer). `connect()` from such a callback returns
    `false`, calls nothing and starts nothing (it started a connection, or answered `false` inside the call). What a
    callback the destructor runs throws is logged (it was dropped without a word).
  Witnesses, on the commit before these two entries (a65bf95) unless said: in `qbm-http-test-system-http3-loopback`, an
  explicit `disconnect()` whose failure callback connects, a redial asked from a response callback that disconnected and
  one asked of a connection lost during its read (with and without a failure callback that throws), a `disconnect()`
  after the `connect()` in three shapes -- in the same callback after an explicit close, in the same callback after a
  lost connection, and from the failure callback of another request of that lost connection --, a host that is not an
  address, the GOAWAY case rewritten to the same rule, and a `run_sync()` of the coroutine `connect()` from a failure
  callback of `disconnect()` while the connection still delivers data, of a connection lost during a read, of a
  connection the server closed and of a request whose submission closed its connection, each failing there; and, passing
  there as the coroutine form answered `false` there in 3.3.0 and still does, the coroutine `connect()` awaited from a
  callback of a close -- started by hand from a failure callback of `disconnect()` and from a read that lost its
  connection, and through `run_sync()` on a quiet connection --: they hold that the queueing of `connect(callback)` does
  not reach it. In `qbm-http-test-system-http1-client`, a client with no shared owner, a coroutine parked on
  `connect()`, a `run_sync()` of `connect()` from a failure callback of `disconnect()`, from the callback of a response
  that closes its connection, from one that disconnected, from one the body limit cut and, automatic reconnection off,
  from the failure of a request queued behind a response that closes its connection or behind a 101 its request never
  asked for and, automatic reconnection on, of one kept behind a request whose connection a timeout or the server ended
  and whose failure callback turned automatic reconnection off, which did not return within the bound of their watchdog,
  and the next request after a loop pumped from the callback of a close -- a `run_sync()` of a coroutine that completes
  at once --, never answered, and a throwing callback of a `connect()` made on a connected client, and a request for
  another origin pushed from a callback of the destructor, answered `400` there; and, passing there, a coroutine that
  awaits `connect()` again after a failed attempt. In `qbm-http-test-system-http2-client`, a `run_sync()` of `connect()`
  from a failure callback of an explicit `disconnect()`, of a `disconnect()` of a connector in flight, of a failed
  handshake, of a connection the server closed and of a graceful GOAWAY's drain, a connection started after a
  `disconnect()` whose failure callback ran the loop and a request pushed before that pass, a request pushed after it,
  or after a connect deadline or a graceful GOAWAY's drain whose failure callback ran the loop until the transport
  ended, whose connection ends before its handshake, a `connect()` asked right after a `disconnect()` of the client's
  first connector in flight, which heard `false` and the attempt then connected unheard, and a request pushed after such
  a close of a later connector, whose connection ended before its handshake, which waited for its request timeout, and,
  for the one rule, a `run_sync()` from the callback of a connect deadline, from the callback of a `connect()` whose
  connector failed at once and from that of a `connect()` whose transport the peer ended once its TLS handshake was
  complete, with a redial from that callback; in `qbm-http-test-system-http2-client-static-exit`, that redial with the
  client in static storage. A `run_sync()` that does not return ends the process under a watchdog, saying so. Passing
  there too, a witness holds the flush limit of an earlier close away from a later close whose GOAWAY cannot be
  delivered while a callback of it pumps the loop, and two hold what a close or a failure with no transport leaves
  behind: a request pushed right after a `disconnect()` of a connector in flight is served by its own connection, and
  one pushed after a connector failure is answered by the first end of its own. Passing before and after, to hold what
  the entry says: the coroutine `connect()` for a host that is not an address, which completes `false` once.

### Fixed

- **A WebSocket client delivers what it receives in the order it happened, whatever its "connected" callback does
  (Huly QB-1246).** A frame the server sends with its `101` reaches the client before it has been told it is
  connected: it waits for that, and was held aside until the "connected" callback RETURNED. When that callback pumped
  the loop -- it sends, and waits for the answer with `run_sync()` or `run_until()` -- what the pump brought was
  delivered ahead of the frame that was waiting: a later message at once, in front of an earlier one; and, since qb's
  loop runs deferred callbacks under a nested turn (qb, Huly QB-1246), the end of the connection too, so
  `on(disconnected)` came before a message received before it. The events that wait for "connected" now stay queued
  until they are delivered, and "connected" is said when its callback is entered. From then on an event that arrives
  while others wait goes behind them, and the queue is delivered -- oldest first, each once
  (`WebSocket::flush_early_events()`) -- by the loop's deferred queue: at the tail of the loop pass that brought the
  event, inside the pump; when the "connected" callback returns; and before the end of the connection is said. Never
  from under the read of a frame: a handler of an event that waited may destroy the client or begin another
  connection, as it always could. A protocol error is notified behind them as well: it was notified ahead of a message
  received before it when "connected" pumped. The client's own `disconnect()` drops what was still waiting, as before:
  nothing follows it but `on(disconnected)`, which is said once -- also when a handler of an event that waited
  disconnects a connection the peer had already ended. A client that never pumps from "connected" sees what it saw:
  "connected", then the frames that waited, then the rest. The path of a frame still pays one test, and the waiting
  queue allocates nothing for a client no frame ever waited on. Proved by fifteen
  cases of `tests/system/ws/ws-client-hardening.cpp`, eleven of them failing on the client as it was, and by 22
  mutants of `ws.h`, one at a time: 19 fail the cases, three survive -- one equivalent (the delivery an event asks
  for always runs before another connection can receive anything), one that costs time and nothing else
  (`BM_WS_ClientMessageForward` holds it), one that only keeps delivered events in memory until the connection
  goes.

- **A request target the HTTP/1.1 parser cannot store is answered `503`, not `400` (Huly QB-1248).**
  `origin::request_target_uri()` reads the target into the request's uri with qb::io::uri's in-place readers, which
  report an allocation failure -- the copy of the target, its query map -- as a failed read whose `source()` is empty,
  where they terminated the process before (qb CHANGELOG, Huly QB-1248). A failed read was a target that names no
  resource, so such a request would have been refused `400`; `request_target_uri()` now throws `std::bad_alloc` for
  it, and the parser answers `503` ("HTTP parser could not allocate"), as for every allocation that fails in one of
  its callbacks. A malformed target keeps its text in `source()` and is still `400`.
  `qbm-http-test-unit-http1-parse-alloc-failure` now sweeps the piece that ends the target too: each allocation of the
  read fails in turn, each a `503`.

- **An HTTP/3 client kept in static storage ends cleanly at process exit, and its destructor accepts nothing from the
  callbacks it runs (Huly QB-1246).** `exit()` destroys the main thread's event loop, a thread-local, before the
  objects with static storage: a `static` `std::shared_ptr<qb::http3::Client>` is destroyed after the loop it ran on.
  Connected, such a client ended the process on `free(): corrupted unsorted chunks`, `corrupted double-linked list`
  or a segmentation fault in a g++ 14 Release build, and on a heap-use-after-free under AddressSanitizer: the QUIC
  endpoint it is built on armed its timer on the freed loop while closing. That is fixed in qb-io (`close()` no longer
  arms its timer). The client's own destructor also failed its requests BEFORE it stopped accepting: a callback that
  pushed the
  request again, the retry pattern, had it queued, a deadline armed for it and a connection started for it from the
  destructor -- after the loop, the first of those stops the process on qb-io's named line. The destructor now accepts
  nothing from its first callback on: a request pushed again is answered at once with `503`
  and "HTTP/3 client disconnect", a `connect()` is refused. Every request in flight or queued still hears once, with
  `503` and "HTTP/3 client destroyed", and a `connect()` still waiting hears `false`.

- **A one-shot request in flight when its event loop ends is destroyed with it (Huly QB-1246).** The session of
  `qb::http::GET(request, callback)` and of the other one-shot verbs deletes itself when its request ends, and nothing
  else did: a request still in flight when the loop it waits on was torn down -- the thread that sent it ending, a
  core stopping, the process exiting -- stayed for the life of the process, with its buffers and its connection, open
  until the process was gone. LeakSanitizer reports 14 312 bytes in 17 allocations for one such request, and its
  server reads no end of stream while the process lives. The session is now the loop's, as an `async::callback` is:
  `listener::clear()` destroys it, its connection is closed and its server reads a clean end of stream. Its callback
  is released WITHOUT being run -- the one case where a one-shot callback never hears, which the session's contract
  now states. A session that answered and waits for its disposal goes the same way; one whose callback is running
  when the loop is cleared (the callback cleared it, or called `exit()`) is left to the path that called it.

- **A request pushed again from the destructor of an HTTP/1.1 client arms no deadline (Huly QB-1246).**
  `qb::http1::Client`'s destructor disconnects, which fails every request in flight or queued once, with `503`. A
  callback that pushed the request again from there had a pending-timeout armed for it, though the client, with no
  owner left, could only fail it at once. With the client in static storage -- destroyed after its thread's event
  loop -- that timer was a request the loop stops the process for: `qb: listener::current.registerEvent() ... was
  requested after that thread's event loop (listener::current) was destroyed`, then `std::terminate()`. A request
  pushed from a callback the destructor runs is now answered inside the push, with `503`, and nothing is armed while
  the client is being destroyed (the entry on the clients' destruction contract, below).

- **The HTTP/1.1 client, the one-shot verbs, the WebSocket clients and the HTTP/3 client are witnessed through
  process exit, in every state (Huly QB-1246).**
  `qbm-http-test-system-client-static-exit` runs each of them with static storage to the end of a child process:
  never connected, a connect in flight, a handshake in flight, connected and idle, a request in flight with its
  callback pending or a coroutine parked on it, the retry pattern, disconnected by the program -- ended from `main`,
  from a callback of the loop, from a callback of the client and from a coroutine. Each child must end with the code
  its judge chose and print the judge's line and nothing else; the judge, an `atexit` handler registered before the
  client, asserts that the client was destroyed after the loop -- the client itself, not only a pointer to it; where
  `exit()` is called inside its own dispatch, that it was left alive --, reads the end of the peer's stream (a clean
  EOF, never a reset) and asks LeakSanitizer. On the code as it was, 19 of the 65 cases it then had failed under
  AddressSanitizer
  and 17 in a g++ 14 Release build, where a write into freed memory does not always stop the process; the
  HTTP/1.1 client and the WebSocket clients passed every state but the retry pattern. What a client in static storage
  does at exit is written in
  `readme/14-async-http-client.md` and in the `llm/` reference. The HTTP/2 client has a binary of its own, in the
  entry below.

- **An HTTP/2 client kept in static storage ends cleanly at process exit (Huly QB-1246).** `qb::http2::Client`'s
  destructor failed its requests first, and a failure ends in the client re-arming its timer for the deadlines left
  (`arm_request_timeout()`). With a connect or a TLS handshake in flight, a reconnection waiting for its next attempt,
  or a request whose failure callback pushed it again, a deadline was left: a client in static storage, destroyed
  after its thread's event loop, started a timer in the freed loop. Measured on Linux with g++ 14, the process ended
  on an abort or a segmentation fault; under AddressSanitizer, on a heap-use-after-free in each of the four states;
  under MSVC, it did not end, or ended on 0xC0000374, a heap corruption. The destructor now arms nothing and connects
  nothing: it marks the client first, and from there on no timer is armed, `connect()` is refused and a request pushed
  is answered inside its push (the entry on the clients' destruction contract, below). Every request in flight or
  queued hears once, with `503` and "Client destroyed", and a `connect()` still waiting hears `false`. Witness:
  `qbm-http-test-system-http2-client-static-exit`, the client to the end of a child process in each of its states,
  ended from `main` and from a callback of the loop where both apply -- 41 cases; with the HTTP/2 client as it was, 27
  of them fail under AddressSanitizer (macOS arm64, Apple clang 21).

- **An HTTP/2 client's close ends the connection it found and no other, and its callbacks may run the loop, ask
  `connect()` and drop the client (Huly QB-1246).** Eight defects of `qb::http2::Client`, each reached by a callback
  that does more than return.
  A close read "a transport to end" before it called the callbacks of what it ends, and ended "the transport the client
  holds" after them. A callback that ran the loop until the peer had ended the connection, then asked `connect()` and
  ran the loop until the answer, saw the next connection come up; the close, resumed, ended that one. The client now
  counts the transports it starts, and a close ends the one it owns only if it has not ended meanwhile -- in
  `disconnect()` of a connection whose TLS is up before its SETTINGS, at a connect deadline that expires there, and at
  the end of a graceful GOAWAY's drain a request's deadline ends. Under a read (a GOAWAY, a connection error, a failed
  handshake) qb-io cannot tear the transport down under its own dispatch: a `connect()` asked there starts once the
  callback has returned.
  The handler of a transport's end runs while qb-io disposes of the connection, and stops the io's watcher once that
  handler returns. A `connect()` asked from a callback it calls -- the failure of a request the lost connection
  carried, a `connect()` that waited -- started its connector at once: a callback that then ran the loop saw the
  attempt complete and the next transport start under that teardown, which stopped it on the way out. The connection
  came up, was reported, and never read again; a build with assertions stops on qb-io's
  `io::start() from inside dispose()`. The handler now holds `connect()` back while its callbacks run and starts what
  was asked once they have returned.
  A `connect()` held back until a transport has ended had no deadline of its own, only the one that whatever armed the
  client's timer next gave it. A callback of a lost connection that asked `connect()` and ran the loop until the answer
  waited for ever -- that transport is torn down once the callback returns --; with a request pushed after the
  `connect()`, it heard `false` at the connect timeout. The deadline is now armed where the `connect()` is asked, and
  counts from there: both hear `false`, "Connection timeout", at the connect timeout. Return instead of running the
  loop there, and the attempt starts. One timeout covers that wait and the attempt: the attempt was stamped again where
  it started, and had the whole timeout once more -- a `connect()` that had waited 700 ms heard `false` 1.7 s after it
  was asked, for a timeout of one second. The HTTP/3 client stamped the attempt of a `connect()` held back by a close
  where it started, to the same effect, and counts from the ask as well. Told `false`, such a `connect()` stayed marked
  as waiting: the client connected by
  itself once the callback had returned, automatic reconnection off, an attempt nobody had asked for; nothing starts
  now. And the failure of an attempt cleared the mark that keeps the queue through the end of the transport still
  closing: a request pushed once that `connect()` had been told `false` was failed by that end, "Connection lost",
  though it never rode that transport. It rides the next attempt.
  A request pushed from the callback of a `connect()` that failed, or that a close refused, was failed by the pass over
  the requests that followed those callbacks, with the error of an attempt it never rode. The requests are now taken
  out before any callback, as the HTTP/1.1 and HTTP/3 clients do.
  A failure callback of `disconnect()`, or of a request's timeout, that dropped the last reference destroyed the client
  under the call that had called it, which went on writing into it. Both now hold the client to their end; a response,
  a failed connect and a lost connection already did, through the io's own dispatch.
  Witnesses in `qbm-http-test-system-http2-client`, red on the code before each change: a request pushed from the
  callback of a failed `connect()` (automatic reconnection off and on), from one a failure inside that callback did not
  close the pass of, and from one a `disconnect()` refused; the three closes, each leaving open the connection its
  callback saw come up; a `connect()` asked from a callback of a lost connection that runs the loop; ten callers of a
  callback that drops the last reference to a client owned apart from its control block; that `connect()` at its
  deadline -- alone, with a request pushed after it, and with a server listening again before the callback returns:
  `false` once, between 0.9 and 2.5 s for a connect timeout of one second, and no connection afterwards --; a request
  pushed once a `connect()` held back has timed out, served by the next attempt; a `connect()` held back for 700 ms,
  answered `false` between 0.9 and 1.45 s after it was asked, on HTTP/2 and on HTTP/3. Mutants, the whole binary
  each, the unmutated tree first and the restored tree last: 16 planted, 16 caught -- the order of the passes, and for
  each of the three closes "ends whatever the client holds" and "reads what it owns after its callbacks" --, then 3
  planted, 3 caught: no deadline at the ask, a `connect()` told `false` that still starts, the mark cleared; then
  3 planted, 3 caught: the attempt stamped again on HTTP/2, no stamp at the ask and a stamp at the start on HTTP/3.

- **An answered request no longer leaves its timer armed (HTTP/1.1, HTTP/3; Huly QB-1246).** The timer of a request's
  timeout belonged to the loop: armed when the request was queued, and never stopped. An answered request left it
  armed for the whole request timeout -- on `qb::http3::Client` every request, on `qb::http1::Client` every request
  that had waited for a connection or for its turn: as many live timers as requests in the last sixty seconds, at the
  default. Each request now owns its timer, one at most, and whatever gives the request its answer stops it first: a
  response, a failure, a cancellation, a refusal, a close, the destructor. On HTTP/1.1 the timer of a wait also stops
  when the request is sent, where its connection times it; a request sent at once has none. On HTTP/3 a request is
  timed once it has come to rest, in flight or left in the queue, its timeout still counted from its push. A stale
  timer could not reach another request -- it looked its own up by an identifier that is never used twice --: the cost
  was the timers, not a wrong answer. Witnesses in `qbm-http-test-system-http3-loopback` and
  `qbm-http-test-system-http1-client`, the loop's count of watchers read with no loop turn between two readings
  wherever the answers allow: twenty requests cancelled in flight and twenty queued, each callback reading its own
  timer gone; a close of ten in flight and ten queued, every callback reading all twenty gone; a request refused where
  it is submitted after a wait; requests served; on HTTP/1.1 two clients alike, one with ten requests queued,
  disconnected in turn, and three requests whose wait times out. Twenty timers were left in each HTTP/3 case, ten and
  nine in the HTTP/1.1 ones. Nine mutants, nine caught: the ninth, a timer that fires before the request timeout and
  is not armed again for the time left, by a request whose timeout is raised once it is pushed -- the timer armed for
  150 ms fires with 450 ms left --, in the queue and in flight.

- **`disconnect()` called from a callback no longer calls the client's callbacks inside the call (HTTP/1.1, HTTP/2,
  HTTP/3; Huly QB-1246).** What a `disconnect()` ends -- the requests in flight and queued, which it fails, and a
  `connect()` still waiting, which it gives up -- it answered inside the call, wherever the call was made; 3.3.0 did
  too. Called from a callback of the same client, that is one callback inside another, and for a callback that also
  pushes back it had no end: on HTTP/1.1 and HTTP/2, ten requests whose callbacks each reset the connection and retry
  made 1023 calls inside the program's one `disconnect()`, ten deep -- each nested close ends the retries the callbacks
  before it have just pushed, 2^n - 1 calls for n requests --, and a callback that pushes back, then disconnects, was
  called a hundred deep, where the case stops it, with no loop turn anywhere. HTTP/3 refuses a push during a close, so
  neither shape nested there; its failures came inside the call all the same. Those answers are now the client's own,
  under the rule of the entry on callbacks, under Changed: given inside the call when the program calls `disconnect()`
  with no callback of this client on the stack and nothing owed, and heard on the client's turn of the loop otherwise,
  in order. What `disconnect()` does to the connection is unchanged; only its callbacks wait. Asio's `close()` and
  `cancel()` never run a handler inside the call, and Node emits what a `destroy()` ends on the next tick. Unchanged
  too: the destructor's own close, where no later turn exists, and a close the loop completes -- the end of a read, a
  timer --, whose answers are given directly when nothing is owed.
  Witnesses, red on the code before, in the three clients' binaries: the failures of a `disconnect()` a callback calls
  -- of a request in flight, of a batch, of a queued request, of a `connect()` still waiting --, none heard before that
  callback returns; on HTTP/1.1 and HTTP/2 the callback that pushes back, then disconnects (one deep), and the ten
  requests that reset and retry: twelve pushes, twelve answers, each one deep, two of them inside the program's
  `disconnect()` -- what it gives until an answer is owed -- and ten on the client's turn. On HTTP/3 ten requests that
  push back and disconnect, one deep before and after. Mutants, the whole binary each, the unmutated tree first and the
  restored tree last: 16 planted, 16 caught -- on each client `disconnect()` answering as the loop, and each kind of
  answer a close gives taken as the loop's whoever closes.

- **A request whose target cannot be sent is refused where it is pushed, on the three persistent clients (Huly
  QB-1246).** `qb::io::uri` keeps a query as written, and the HTTP/1.1 serializer refuses one that carries SP, a
  control byte or DEL (QB-494). The HTTP/2 and HTTP/3 clients serialize nothing: the query went into `:path` as it was.
  On `qb::http2::Client` the HPACK encoder refuses a control byte: the client sent its own GOAWAY from under the push,
  "HPACK encoding failed for new request headers", and every request on the connection failed for the fault of one --
  pushed from a callback, the five in flight heard their failures inside that push, two deep; a query with SP was sent.
  `qb::http3::Client` wrote the byte: a qb server closed the connection, and the request in flight failed with it. And
  a URI that failed to parse -- such a byte in its path -- was made absolute against the client's origin and sent, on
  the three clients, as a request for another target, answered `200`. Each client now asks one helper before anything
  else, which makes the serializer's three refusals of a target, in its order and on what it measures: a URI that is
  invalid, a path and a query longer together than `MAX_URL_LENGTH`, and a query the request line could not carry --
  that last test is the serializer's own function, no copy of it. Such a request is refused where it is pushed, `400`,
  "HTTP/2 request URI cannot be sent: the query carries SP, a control byte or DEL; percent-encode it" -- an answer the
  client gives by itself, under the rule of the entry on callbacks, under Changed. Nothing is written, the connection
  stays, and the other requests are served on it. A raw SP in a query, which the HTTP/2 and HTTP/3 clients sent, is
  refused with the rest: percent-encode it. A target that is too long was refused where it was written on HTTP/1.1 and
  where it was submitted on HTTP/3 (`503`), a stream opened for it. The limit is one, on one quantity, for the three
  clients: the HTTP/3 engine's own bound counted the `?` between the path and the query, so a path and a query of
  `MAX_URL_LENGTH` together, which the two other clients send, were refused there. It measures what the serializer
  measures.
  Witnesses, red on the code before, in `qbm-http-test-system-http1-client`, `-http2-client` and `-http3-loopback`: LF,
  CR, 0x1F, DEL and SP, in the query and in the path, each refused where it is pushed and the next request served on
  the same connection -- on HTTP/2 and HTTP/3 with a request in flight, which is not failed; a path one octet past
  `MAX_URL_LENGTH`, refused where it is pushed, and one at the limit, sent, with a query and without. Mutants, the
  whole binary each, the unmutated tree first and the restored tree last: 5 planted, 5 caught, then 2 planted, 2
  caught, then 1 planted, 1 caught -- the check left out of each client, each of its halves, the length off by one, the
  engine's bound on the target again.

- **A callback that throws no longer costs the process, the connection or another request its answer (HTTP/2, HTTP/3;
  Huly QB-1246).** What a callback of `qb::http2::Client` or `qb::http3::Client` threw went to whatever frame was above
  it, and which one was the peer's choice. On HTTP/2: under a response the protocol swallowed it, and the request that
  waited for that stream was not sent until something else ran a pass; under a RST_STREAM or a GOAWAY frame, under the
  handshake's event -- the callback of a `connect()`, come up or failed -- and under the timer's pass -- a connect
  timeout, a request's timeout, the hook of a retry policy -- a `noexcept` handler was on the stack, the protocol's own
  or qb-io's, and the process ended (`std::terminate`); under the end of a lost connection qb-io's loop took it, but
  the handler had left before it asked for the reconnection or started a `connect()` held back, and a request a failure
  callback had pushed back waited for a connection nothing would open. On HTTP/3, under a response it went into the
  engine's callback, which reports a failure: the connection ended, and the requests behind failed with it, "HTTP/3
  protocol read error (258)".
  The rule is now one, the one qb-io applies at its loop's boundaries and the HTTP/1.1 client already had: **what a
  callback the loop brought throws is contained by the client where it calls that callback.** A response, a failure, a
  timeout, a close, a GOAWAY, a reset, a connection that comes up, the client's turn, the hook of a retry policy: no
  call of the program is there to hear the exception, so it is logged at WARN -- "exception escaped an HTTP/2 client
  callback; contained", with what it says -- and goes no further. The line is written where the build has a logger
  (`QB_WITH_LOGGING`, the default, or `QB_STDOUT_LOGGING`: the entry on a callback that always pushes again, under
  Changed, says where it goes); a build with neither contains the exception and says nothing. What the call was part
  of goes on: every other request is answered, once; the close runs to its end and ends its transport; the
  reconnection is asked; the next request is sent. It ends neither the process nor the connection.
  **Under a call of the program it still reaches that call.** `disconnect()` answers every request and every
  `connect()` it ends, ends its transport, then rethrows the first exception: it left at the first callback that threw
  -- with TLS up and no SETTINGS and three requests waiting, one callback heard, two never, and the next `connect()`
  unanswered after six seconds for a connect timeout of one, waiting for an end of transport that never came. A push
  that an exception leaves -- thrown by the callback of a request its pass refuses on the way -- takes back what it
  pushed, a request or a batch: it stayed queued, the next pass sent it, and its callback heard a `200`, a request the
  program had been thrown at for. It is taken back inside the pass, under the hold the pass has on the client: a push
  holds nothing, and reads nothing of the client once its pass has returned or thrown. Taken back by the push after
  the pass, the request was looked up in a client that a callback under the pass had just destroyed -- one that drops
  the last reference and throws, or, on HTTP/3, the failure callback of another request when a submission cut short
  ends the connection: a heap-use-after-free.
  **And it reaches that call once it has finished for the others**, as under `disconnect()`. The pass of a push stopped
  at the callback that threw: a request that waited behind the refused one was not sent -- three seconds later it
  still waited --, and went out with the next push. The pass now runs again, to its end, once what the push itself
  pushed has been taken back, so that it is not sent; what one more callback throws under it is dropped, and the first
  exception is the one that leaves the push. `cancel_request()` on HTTP/3 left at the callback of the request it
  cancelled, before it reset the stream and before its pass: the client kept the stream's state, and a request that
  waited for that stream stayed queued until the next push. The stream is reset and the pass run, then the exception
  goes on. And a push takes back what it pushed wherever that has got to. A callback that pushes, then throws, runs a
  pass of its own, which takes the first push's request out of the queue before the exception reaches that push: sent,
  its response was heard after its push had thrown; refused there, its refusal was heard on the client's next turn, and
  a batch's likewise. An answer already owed is now never heard, and a request in flight is given up on the wire as
  well, as a cancellation is: `RST_STREAM(CANCEL)` on its stream on HTTP/2, a reset with `H3_REQUEST_CANCELLED` on
  HTTP/3, the members of a batch in flight alike. That frees the stream for what waits and tells the server that
  nobody does: left in flight with its answer dropped, the request held its stream for as long as the server took to
  answer. An answer that still comes finds no request; and where no reset can be written, the connection ending, the
  request hears nothing of the close that ends it. `ClientHttp2Protocol::cancel_request()` is the HTTP/2 protocol's
  entry for it: it had none that gave up one request.
  While the client is destroyed nothing changes: what a callback throws is logged and goes no further.
  Two loops of the clients' own were cut short the same way, and are whole: a graceful GOAWAY on HTTP/2 fails every
  request above the stream it names, then looks at the drain's end -- the others were destroyed unheard, and a drained
  connection left open --, and a server's GOAWAY on HTTP/3 refuses every request that waited -- the others stayed
  queued, to be failed with their connection under another text. A refusal the HTTP/3 client gives where the loop
  submits is contained too, and the pass goes on to what waits behind it.
  Do not throw from a callback all the same: under the loop the log is all that hears it, and in a build with no
  logger nothing does.
  Witnesses, red on the code before, in `qbm-http-test-system-http2-client`, one an entry point of the loop: a response
  whose callback throws, a request's and a batch's -- the request behind it sent with no other push (it stalled); a
  RST_STREAM; a GOAWAY read from the connection, naming a stream below two requests; a `connect()` callback that throws
  as the connection comes up, and one that throws with the callback of a request when the handshake fails; a connect
  timeout with TLS up, and a request's timeout; a retry hook -- the process ended in each of these seven, and each now
  goes on to the answers that follow, the transport closed where one was. A lost connection whose first failure
  callback throws -- the request another pushes back served, by the reconnection and by a `connect()` that callback
  asks --; a connection lost before it is up, whose `connect()` callback throws; a GOAWAY that names no stream,
  delivered by hand -- both requests heard, the connection closed --; the end of a graceful GOAWAY's drain. Under a
  call of the program: that `disconnect()`, its thrower the callback of a request and the callback of a `connect()`
  that waits -- three answers, the exception out of the call, the transport ended --; a request and a batch pushed
  while the callback of a refused one throws -- the exception out of the push, nothing heard for it, then or after the
  next push --, and the same with a client owned apart from its control block whose callback drops the last reference
  first. In `qbm-http-test-system-http3-loopback`: a response whose callback throws, a request's and a batch's -- the
  request behind it served on the same connection --; a refusal under a pass the loop runs; a server's GOAWAY whose
  first callback throws; that last push case, and a submission cut short whose close drops the last reference. A
  `connect()` callback that throws as an HTTP/3 connection comes up, and a lost HTTP/3 connection whose first failure
  callback throws, held before and are pinned: qb-io took the first one frame out, and a request pushed back there
  connects by itself. Under a push whose pass goes on, in both binaries: behind a request in flight wait one refused
  where it is sent, whose callback throws, one the server never answers, a second refused one whose callback throws,
  and a valid one; then a push -- the first exception out of the push, both callbacks called, the two others sent by
  that pass, with no response to run another, and the request of the push neither heard nor sent, by the server's
  count (the pass stopped at the first). What a pass under the callback had taken before the exception reached the
  push -- a request and a batch in flight, a request and a batch refused --, never heard once that push has thrown
  (three of the four were; a batch in flight already found no batch, a pin). On HTTP/3, a cancellation whose callback
  throws: the exception out of the call, the request that waited served with no other push, and as many stream states
  kept as with a callback that returns (4 against 3, and the request left queued).
  What a push takes back while in flight, in both binaries: one stream allowed; a request the server never answers,
  then a batch of two, sent on it by a pass under the callback that throws; and a request that waits for that stream.
  The server sees the request cancelled on a connection that stays, the request that waited is sent on that stream by
  the same push and served, and nothing is heard for what was taken back (the stream stayed taken, and what waited
  was never sent). On HTTP/2 a peer that answers nothing reads the frame: one `RST_STREAM`, on stream 1, `CANCEL`. On
  HTTP/3 the client's own reset is read with its code, `H3_REQUEST_CANCELLED`; and where a submission cut short ends
  the connection under the push, what that push had in flight hears nothing of the close (it held before: a pin).
  The line logged is read by a case of `qbm-http-test-system-http2-client`, in a log of its own: the suites build with
  `QB_WITH_LOGGING`, and no case read it (it held before, a pin).
  Mutants, the whole binary each, the unmutated tree first and the restored tree last. The containments, one removed
  at a time -- a request's callback, a `connect()`'s, a batch's, the retry hook, the refusal under the loop's pass, and
  the rule turned round (the program's own call contained too): 10 planted, 9 caught. The survivor throws on what a
  `connect()` callback throws as an HTTP/3 connection comes up: qb-io takes it one frame out, the client having gone
  on to the pass first, and only the line logged differs. What stands of the forms before, planted again: the close
  of `disconnect()` and the take-back inside the pass, 11 planted, 9 caught; the two that survive drop what a push
  takes back when its own `connect()` throws, one a client -- only an allocation under that `connect()` reaches it.
  The pass that goes on, what a push takes back and the cancellation, on the tree that has them: 22 planted, 22
  caught -- the pass not run again, the take-back done after it, the pass that runs again stopped at the next throw,
  the exception not thrown on or never leaving the pass, a request in flight or an answer owed left to be heard, an
  answer owed that does not say whose it is, the line logged changed; on HTTP/3 the reset, the pass and the exception
  of a cancellation each left out. The 21 mutants of this paragraph and the one on the engine's bound, planted again
  on that tree: 22 planted, 19 caught, the same three surviving.
  The reset of what a push takes back while in flight: 9 planted, 8 caught -- no reset asked, a batch's members left
  out, another code than the cancellation's, the HTTP/2 protocol refusing a request it holds, and on HTTP/3 the
  request left in the registry when its stream is reset: the transport raises the stream's end inside the reset,
  which retires the request a second time and counts it failed twice (`get_stats()`). That one was first counted a
  survivor, by reading what is heard; the case now reads the counters, and catches it, as it catches the count left
  out. One survives, on HTTP/3: a reset written though a close is under way, which changes nothing that is heard and
  nothing counted. The 44 mutants of this paragraph planted again on that tree: 44 planted, 41 caught, the same three
  surviving.
  What a push takes back is taken back by its own number, and nothing else is, on both clients: a request and a batch
  can carry the same number, as the client counts them apart on HTTP/2, and a Request object pushed twice is two
  requests. Cases now read it: the same object pushed as the request taken back and as another; a request and a batch
  of its number, each way on HTTP/2, one way on HTTP/3 (which numbers a batch's members with its requests); and a
  close made under the callback that throws, whose answers are owed -- what the push pushed, a request or a batch,
  never heard; the other request answered once; the client connects again. Mutants of what an answer owed is tagged
  with, and of what the take-back matches: 5 planted, 5 caught, each caught before by a probe alone.

- **An HTTP/2 request that times out gives its stream back, and what waited for it is sent (Huly QB-1246).** A request
  of `qb::http2::Client` in flight past its request timeout was answered `408` and left the client's registry, and
  nothing was written: its stream stayed open on the server, which went on working for nobody, and in the client's
  protocol, which counts the streams it holds against the server's `SETTINGS_MAX_CONCURRENT_STREAMS`. Once as many
  requests had timed out as the server allows streams -- 50 for a qb server --, every later request on that
  connection was refused where it was sent, `503` "Failed to send HTTP/2 request", for as long as the connection
  lived; and a late answer still arrived, for a request no longer there. The stream is now reset with `CANCEL` --
  the request is given up (RFC 9113 section 7), as the HTTP/3 client gives it up at its timeout --, before the
  request hears its `408`; what the server sent on it before it read the reset is discarded. The members of a batch
  that time out alike, each on its stream. And what waited for those streams is sent at once: the timer's pass ran
  none, and a request queued behind one that timed out waited for the next push, or timed out in its turn.
  `ClientHttp2Protocol::cancel_request()` takes `tell_the_handler`, false for a request the application answers
  itself. The other ways a request of this client leaves its registry with its stream open were read, none left
  open: what the protocol refuses -- a body past the client's limit or its `content-length`, a malformed response
  -- it resets itself; what a server reset or a GOAWAY ended, the server ended; a close ends the connection.
  Witnesses, red on the code before, in `qbm-http-test-system-http2-client`: one stream allowed on both sides (a peer
  that advertises one, and answers only the second request), a request that times out and one that waits -- the peer
  reads `RST_STREAM` on stream 1 with `CANCEL`, and the request that waited is answered `200` before its own deadline
  (it timed out while pending, and nothing was reset); a batch of two that times out -- two resets, streams 1 and 3,
  both `CANCEL` (none); 60 requests a qb server never answers, timed out in two waves of 30, then one more -- served,
  and the server sees its 60 requests cancelled (the last ten of the second wave and the one after them refused,
  `503` "Failed to send HTTP/2 request"); against a qb server too, one stream allowed by the client, a request that
  times out and one that waits for its stream -- answered `200` before its own deadline (`408` "Request timeout while
  pending" at it).
  The timer's pass takes the requests that timed out by their place in the client's registry and by the connection
  they were sent on, never by stream number, and looks each up again before it answers it. A `408` callback is the
  program's: one that disconnects, connects again and runs the loop until connected left the pass naming the new
  connection's streams by the numbers it held -- a request pushed there with a 10 s timeout was answered `408` at once,
  by the old connection's pass, and its stream reset. A case: two requests time out in one pass, and the first `408`'s
  callback reconnects and pushes two more -- neither is answered, and no stream of the new connection is reset (red on
  the code before). The other passes that take first and answer later were read: GOAWAY's and the closes' own what they
  answer; `withdraw()` runs none of the program's callbacks between one reset and the next; the timeouts of the queue
  are a prefix of it, so every `408` callback runs before anything is set aside; the HTTP/3 client times each request
  by its own number.
  Mutants: 3 planted, 1 caught -- the pass taking stream numbers again. The connection check dropped survives,
  equivalent today: every end of a connection takes its requests out of the registry, and a request sent again takes a
  new number. The reset's guard without the connection's flag survives as before: a callback's close ends the pass
  before it.
  Mutants, the whole binary each, the unmutated tree first and the restored tree last: 5 planted, 4 caught -- no reset
  at the timeout, the reset told to the handler (the request failed a second time, 502), no pass after the timeouts,
  the protocol telling the handler of a reset it was asked to keep quiet. The survivor drops the connection's flag
  from the guard of the reset, which every close clears with the protocol: the same guard. The 27 mutants of the
  HTTP/2 client planted again on that tree: 26 caught, the same one surviving.

- **An HTTP/3 submission that an exception cuts short gives its request one outcome and ends the connection (Huly
  QB-1246).** `qb::http3::Client` takes a request out of its queue, opens a stream and submits it. An exception out of
  that -- an allocation, or what a hook of the transport throws under the send -- left the request destroyed unheard:
  it was in no registry yet. And a close deferred to the end of that submission, the transport lost under it or a
  `disconnect()` called there, was never run: the client stayed "connected" to a transport that was gone, every later
  request queued behind it, or kept every later `disconnect()` and `connect()` out. The submission now ends as a read
  does, by a close, and the exception goes on to whoever made the call. The close is the one the submission deferred
  or, with none, the client's own: "HTTP/3 submission cut short by an exception". The engine hands its bytes to the
  transport, then is told how many went, and an exception between the two makes it write them again. On the request's
  own stream that is nothing, the stream is reset; the QPACK encoder's stream lives on, and a peer that advertises a
  dynamic table reads an instruction twice -- it ends the connection, or keeps another table than the client's.
  Nothing in the client knows whether the transport took the bytes, so the connection is not kept, as nghttp3 itself
  treats the failure of a callback. Measured with the connection kept, against a server that advertises a table of
  4096 octets: after one submission cut short, 26 of the next 30 requests failed, "HTTP/3 protocol read error (514)",
  H3_QPACK_ENCODER_STREAM_ERROR; none read a wrong value. A qb server advertises no table.
  A request has exactly one outcome, by the rule of Asio's `async_initiate`: an initiating call that throws never
  invokes its completion handler. Thrown inside the program's own call for that request -- `push_request()`,
  `push_requests()`, the `co_await` of either --, the exception is that outcome: what the call pushed is taken back
  before the close runs -- a batch whole, the members already submitted ending unheard with the connection --, no
  callback is called and no awaiter completed, and a coroutine that catches the exception and awaits another request
  hears that request's own answer. Thrown where the loop submits, or under a call the program makes for another request
  (a `cancel_request()`), the request is answered `503`, once, as every refusal the client gives by itself -- inside
  that call when no callback of this client is on the stack and nothing is owed, on the client's turn otherwise --, and
  the exception goes on to that caller, logged where it is the loop. The other requests the close ends are answered
  once each, as answers the client gives by itself: inside a push the program makes with no callback of this client on
  the stack and nothing owed, on the client's turn otherwise -- under a callback's push they came inside it.
  The outcome is one, too, when the exception cuts no submission short: the pass a push runs submits what waited
  before its own request, and the callback of one the engine refuses there may throw. The exception leaves the push
  with its request still queued, and the push takes it back, a request or a batch; left there, it was sent by the next
  pass and answered. The connection stays.
  The reset of a stream the client abandons has a `try` of its own in each of the three places that write one. Where a
  request is refused as it is submitted, the refusal is given first: a hook that throws under the reset takes no answer
  away. In `cancel_request()` and at a request's timeout, a reset that threw skipped the pass behind it: the request
  that waited for that stream stayed queued until the next push. No close can be left half done any more, so the line
  of the destructor that cleared one, and its witness, are gone.
  Witnesses: a client derived in the test throws from the two hooks the QUIC endpoint runs inside a send -- at the end
  of a send, once and again at the close that follows; at the close a send delivers when it loses its connection, with
  and without a `disconnect()` called there -- under a callback push, a batch (thrown at its first member and at its
  second) and a coroutine push whose next `co_await` hears its own answer: no callback called, the exception out of
  the call, the connection ended, the next request served on a new one. Where a timer's pass and where the
  cancellation of another request submit, under each of the same hooks: the request answered once, the connection
  ended, the next request served. Against a test server that advertises a dynamic table: ten requests echoed, one
  submission cut short, thirty more echoed right on one new connection. A push whose submission loses the connection,
  made by the program and from a callback: the other request's failure one deep and in order. A request and a batch
  pushed while the callback of a refused one throws: the exception out of the push, nothing heard for it, the next
  request served. A cancellation and a timeout whose reset throws: what waited for the stream is submitted by that
  call. A refusal whose reset throws: answered once, no exception out of the push. And a `disconnect()` whose first
  callback throws, pinned: the two others hear, the exception leaves the call, the client connects again. No request
  was heard on the cut-short paths before, and the client served nothing more. Mutants, the whole binary each, the
  unmutated tree first and the restored tree last: 16 planted, 15 caught. The survivor resets the stream of a
  request cut short under a read on a connection that is going as well: equivalent, the end of that read closes the
  connection.


- **A response callback of the HTTP/1.1 client that runs the loop, then drops the last reference, no longer destroys the
  client under its own connection (Huly QB-1246).** What keeps `qb::http1::Client` alive under its connection's handler
  is a closure in the loop's deferred queue, queued as each callback is entered. A loop turn the callback runs -- a
  `run_sync()`, a pump by hand -- drains it while the callback is on the stack, and another was queued only while a
  connection was being retired: on a connection that is kept, a callback that ran the loop and then released the last
  `shared_ptr` had the client destroyed when the handler returned, and its connection with it, inside that connection's
  own read pass (a heap-use-after-free). The hold is now counted, and one is queued whenever a callback returns with
  none left. And every callback holds the client itself to its end: the answer of a refusal inside a push the program
  makes, the callback of a `connect()` on a connected client and that of an empty batch had only the hold behind them,
  so one that ran the loop and dropped the last reference had the client destroyed under it -- its destructor left the
  refusals it owed unheard, and the end of the call ran on freed memory. Witnesses in
  `qbm-http-test-system-http1-client`: a response callback that runs the loop, pushes the next request, and whose own
  callback runs the loop and drops the last reference; a refusal's answer and a connected `connect()`'s callback that
  push a refused request, run the loop and drop the last reference, the kept refusal heard once before the client
  goes -- each red under AddressSanitizer on the code before it. Six mutants of the count, six caught; the callback's
  own hold, the order of the answers and the refusal before the queue are planted with the rule's (under Changed), the
  timer of a wait with the timers' (the entry on the request's timer).

- **The HTTP/3 client connects to a host name (Huly QB-1246).** `qb::http3::Client` handed the QUIC endpoint its base
  URI, and the endpoint takes a host for a numeric address: `make_client("https://localhost:4433")` never connected. The
  client now resolves the host when it connects, into every address of the family the URI names (IPv4 for a host name,
  IPv6 for a bracketed literal), in the resolver's order, and the endpoint is handed an address, as the core of every
  QUIC stack is. The resolution is blocking, like the TCP clients': it is qb-io's `tcp::resolve_endpoints()`, which the
  connector of the HTTP/1.1 and HTTP/2 clients calls. One connect timeout covers the lookup and every address -- a
  lookup that outlasts it fails the `connect()` with nothing dialled.
  The connect timeout bounds the `connect()`, as on the two other clients: QUIC's own bound on a handshake follows it
  for each attempt -- the attempt's time, and a second more so that the client's timers decide --, as curl's ngtcp2
  backend takes its from the connect timeout when one is set. A lone address that does not answer was given up at the
  endpoint's own handshake timeout, ten seconds by default, of a connect timeout of thirty. The program's QUIC settings
  are left as the program set them, the idle timeout among them, which ends an attempt that hears nothing: the bound is
  the connect timeout, or QUIC's idle timeout when that is shorter -- thirty seconds each by default, and the client's
  timer is due first. QUIC holds an idle timeout at three probe timeouts at least (RFC 9000 section 10.1): about three
  seconds before any answer has been measured.
  An address leaves its place to the next, without a word to the callbacks, in three cases. It does not answer in its
  share of the connect timeout, by the connector's rule: what is left over the addresses left, two seconds at least,
  and no share for an address that would have all of what is left. QUIC gives it up -- a transport error, its idle
  timeout; or, with no connect timeout, the endpoint's own handshake timeout. Or the network refuses its first
  datagram -- no route to an address of that family, a host that is unreachable --, which the endpoint reports inside
  its own `connect()`. A refusal is an answer, and final: an address whose server answers and is refused, by TLS or
  by the peer, ends the `connect()`. The name stays the one sent as SNI and checked against the certificate.
  No fallback across families, as on the two other clients: a name that has AAAA records only resolves to no address
  here, and its `connect()` fails as one that cannot start -- name the IPv6 literal.
  Witnesses in `qbm-http-test-system-http3-loopback`: a request served through `localhost` (red on the commit before:
  `connect()` answered that nothing could start); a silent address giving way to the next at 2.5 s of a 5 s timeout;
  a lone silent address failing at its timeout -- at eleven seconds of eleven where QUIC's own ten ended it, and at
  1.5 s where the program had set QUIC's to 300 ms; one given up for "QUIC idle timeout" before a connect timeout of
  four seconds, under an idle timeout of one, with nothing added when the four seconds come; with no connect timeout, an
  address QUIC gives up at 300 ms (the `connect()` failed there); the broadcast address, whose datagram `sendto()`
  refuses, alone and before an address that answers (its callback heard `false` inside `connect()`, six deep for a
  callback that dials again); a server whose certificate is not verified, twice in the list, one attempt; a lookup that
  outlasts the timeout; an attempt started with nothing left of the timeout (three addresses were dialled from inside
  one another); two addresses under a connect timeout of one second, where the first has all of it and no share is armed
  -- the loop's count of watchers against a lone address, and against a share that is armed. Seven mutants of the
  resolution, six caught; the seventh -- `connect()` handing on the end of its lookup for its start -- needs a lookup
  that lasts, which no case makes; what is done with that moment is held (the timeout counted from the end of the lookup
  is caught), with the mutants of the fallback, under Changed.

- **The HTTP/1.1, HTTP/2 and HTTP/3 clients are destroyed under one contract (Huly QB-1246).** The three destructors
  differed in what a program hears, and none was safe after the event loop in every state. `qb::http1::Client`,
  `qb::http2::Client` and `qb::http3::Client` now end alike, at process exit as anywhere: every request in flight or
  queued hears once, with `503` and the client's own text; every `connect()` still waiting hears `false`, once; a
  request pushed from one of those callbacks, alone or in a batch, is answered inside the push, with `503` -- nothing
  queued, nothing armed, nothing connected for it; on HTTP/1.1 and HTTP/3 one pushed from inside that answer is refused
  by its return value alone, its callback never called --; a `connect()` called from one is refused by its return value
  alone; and what such a callback throws is logged and goes no further. What that changes for a
  program, client by client and against 3.3.0, is the list of the entry on `connect()`, under Changed. What was wrong in
  3.3.0. HTTP/2: a request a callback of the destructor pushed again was queued, a deadline armed for it and a
  connection used or started for it -- in static storage, after the loop, a timer started in freed memory, a
  heap-use-after-free under AddressSanitizer --, a callback that threw ended the process in `std::terminate()`, and a
  `connect()` asked from the callback of a waiting `connect()` whose transport ended before the client had read anything
  of it joined the attempt that had just ended: its callback was never called, not even by the destructor, which
  disconnects only a client connected or connecting. HTTP/1.1: the callbacks of a `connect()` still waiting were
  destroyed unheard, and a request pushed from a callback of the destructor had its deadline armed after the loop, which
  stops the process on qb-io's line (`listener::current.registerEvent() ... was requested after that thread's event loop
  ... was destroyed`). HTTP/3: such a request was queued, a deadline armed and a connection asked for it, with the same
  end after the loop. How: each destructor sets one flag first, `_destroying`, and everything reads it --
  `push_request()` and `push_requests()` answer at their entry, `connect()` returns `false`, and nothing arms a timer
  (`arm_request_timeout()`, `arm_pending_timeout()`, `arm_connect_timeout()`); the callbacks run through one helper
  (`detail::contained()`, and `detail::notify()` for the two clients that contain a callback only while they are
  destroyed: `detail/client_callback.h`, internal), which the HTTP/1.1 client already did by hand everywhere but in the
  callback of a `connect()` made on a connected client, now contained too. An answer is made inside the call of its
  callback, so a failed allocation there is contained with it, and what a destructor's own pass could still throw stops
  at the destructor, on each of the three. The HTTP/3 client's close is the whole close however it is left: its mark
  goes with it whatever ends it, and a read or a submission that an exception cuts short completes the close it
  deferred -- a mark left behind kept every later `disconnect()` out, the destructor's included, and a `connect()`
  still waiting was destroyed unheard (the entry on the submission, above). The HTTP/2 client's end of a transport
  settles its state before
  a waiting `connect()` hears it, as its other closes do. The HTTP/2 destructor logs "Failing all requests" only when
  there is something to fail. The HTTP/1.1 and HTTP/3 destructors gain no line of their own -- logging at the end of a
  process is a risk of its own --: the one line a destruction can add is the helper's, when a callback throws. A request
  path gains the test of the flag where it pushes and where it arms a deadline, nothing else. One rule for the program:
  bound every retry (the list, under Changed). Witnesses: `qbm-http-test-system-client-static-exit` (HTTP/1.1
  and HTTP/3), `qbm-http-test-system-http2-client-static-exit`, `qbm-http-test-system-http3-loopback` and
  `qbm-http-test-system-http1-client` -- on the three clients, a callback that would push four times: the push its
  first failure makes seen answered before it returns, a deadline asked on the way, the push made from inside that
  answer seen refused and never answered, alone and as a batch (on HTTP/2 each of the four was answered inside its
  push, and the batch form went three batches deep, until its client took the same rule); a waiting `connect()` whose
  callback connects again, in the connect and in the handshake (TLS for HTTP/1.1 and HTTP/2, QUIC for
  HTTP/3: the peer has read the first flight and answers nothing); callbacks that throw (a request's, a batch's, a
  `connect()`'s, and that of a request or a batch pushed from one); a callback that disconnects; and, on HTTP/2, a
  waiting `connect()` whose transport the peer ends once its TLS handshake is complete, whose callback connects again.
  Every outcome a case's callbacks hear is kept: a wrong status between two right ones fails the case. 77 of the 457
  cases of those four binaries and of `qbm-http-test-system-http2-client` fail on the commit before these two entries
  (a65bf95; AddressSanitizer, macOS arm64, Apple clang 21, the last two added in a Release build): 13 of them under a
  watchdog that ends the process when a `run_sync()` does not return, 1 on qb-io's `io::start() from inside dispose()`
  assertion. 119 mutants in nine batteries, each on the code as it then stood: 90 caught where planted. 3 of the 21 that
  survived the first three are settled by the fourth: two, planted again, are caught by its witnesses; the third, a
  close counted with no transport, is now the code, and its inverse is caught. The sixth settles 2 more, planted again
  and caught: the HTTP/1.1 entry answer of `push_request()`, and a race the fifth left. The seventh, on the HTTP/2 flags
  this entry moves before the callbacks, catches all 6; one catch of the sixth is withdrawn -- the queue's flag set for
  a close with no transport, caught by a race of its witness. The eighth catches all 8: that flag planted again, now
  that such a close closes no io, the io closed, both, the HTTP/1.1 queue behind a closing response or an unasked switch
  left to the retirement's reset, and three HTTP/2 flags set after the callbacks, planted again on the rewritten
  witnesses. The ninth, on the HTTP/1.1 queue a timeout or a lost connection keeps for automatic reconnection, catches 4
  of 8: its settle removed, or moved before the failure callbacks, in each of the two. Of the 23 that survive, 2 put
  back what was removed and show it redundant, 5 take away one of two guards in a row (the pair is caught, or the next
  line refuses the same), 3 take away a guard no path reaches while the others stand, 5 take away what only a failed
  allocation reaches -- the `try` in each of the three destructors, the HTTP/3 close's mark cleared on an early exit,
  the close a throwing read completes --, 6 are equivalent (that mark cleared a second time; the HTTP/2 flush limit
  armed for a transport already gone, which then finds its flag cleared; and, finding nothing to do, the gate of the
  two settles the ninth plants in, the settle of a 101 with no request in flight, and the backstop of the reset), 1
  was counted equivalent and is not -- the HTTP/1.1 hold armed at every return to no callback, a retirement pending or
  not, is what keeps a client whose callback ran the loop, and is now the code (the entry on that hold, above) --, and
  1 changes only what is logged; each is named in the commit. The counts of this paragraph are those of that measure:
  the cases and the mutants of the entries above on the relaunch rule, the hold and the address fallback, added since,
  are counted there.

- **A response to HEAD that declares a `Content-Length` past the client's body limit is delivered (Huly QB-1248).** A
  response to HEAD declares the length a GET's would have and carries no body (RFC 9110 §9.3.2). The HTTP/1.1 client's
  parser checked that length against `max_body_size` (100 MB by default) at the end of the header section and refused
  it, before the protocol asked whether a body may follow (`http1_response_body_forbidden()`): the request failed and
  its connection was dropped, though no body byte was coming. The protocol now asks once, when each response begins,
  and tells its parser (`_body_forbidden`, a protected member the protocol's parser type exposes: `Parser`'s public
  API is unchanged); the parser reads the declared length of a HEAD's response as none, as it does for 1xx, 204 and
  304, and the protocol frames the response on its header section from the same answer. The response is delivered with
  its status and header section, the declared length kept, its body empty, and a kept-alive connection serves the next
  request. A response to another method that declares past the limit is still refused, and so is one a `Parser` driven
  directly reads, which nobody tells about the request. Witnesses: `qbm-http-test-unit-http1-protocol-framing` (the
  response to HEAD, then the next response framed, the client asked once per response; its header section cut at every
  byte; the two refusals as they were) and `qbm-http-test-system-http1-client` (the persistent client and the one-shot
  session, over the server's own answer to HEAD).

- **A response to HEAD that declares no length keeps its connection (Huly QB-1248).** It ends at its header section
  (RFC 9112 §6.3), and llhttp marks a response to HEAD (`F_SKIPBODY`) only when `on_headers_complete` returns 1; the
  HTTP/1.1 parser pauses there instead. Unmarked, a response to HEAD with neither `Content-Length` nor
  `Transfer-Encoding` had its `keep_alive` computed as for a body delimited by the connection's close: false, and the
  persistent client retired a connection it could keep (qb's own server never answers HEAD in that shape with a status
  that carries a body: an empty body gets `content-length: 0`; a foreign server may). The parser now marks the
  response when the protocol says it answers a HEAD (`_body_forbidden`), before `keep_alive` is computed; the protocol
  framed such a response at its header section already, and the mark changes nothing else of the parser's state, which
  is reset before the next response. The one-shot session's response reports `keep_alive` true too; that session
  disconnects after every response anyway. A response to another method with no length, a response to HEAD that says
  `Connection: close` or an HTTP/1.0 one that does not ask to be kept, and a `Parser` driven directly keep the
  keep-alive they had. Witnesses: `qbm-http-test-unit-http1-protocol-framing` (the response kept, the responses after
  it framed, by their length and by the close; HTTP/1.0 with `Connection: keep-alive`; the controls) and
  `qbm-http-test-system-http1-client` (the persistent client against a scripted peer: one connection for the HEAD and
  the GET after it, two before).

- **A response to HEAD, a `204` or a `304` is accepted whatever transfer coding it names (Huly QB-1248).** The
  HTTP/1.1 parser accepted `chunked` alone and refused every other coding (`gzip, chunked`, `gzip`) at the end of the
  header section, on every message. A response to HEAD and a `304` may carry the coding the origin would have applied
  (RFC 9112 §6.1), and a response to HEAD, a `204` and a `304` end at their header section whatever their fields say
  (§6.3): nothing follows to decode, yet the client lost the response and its connection. The parser now skips the
  coding check for a response to HEAD the protocol names (`_body_forbidden`, a `1xx` answering a HEAD included), a
  `204` (which breaks §6.1 naming a coding, but §6.3 frames it all the same) and a `304`; the new test of the response
  runs only when the coding is not `chunked` alone, so no other message pays for it. The protocol frames a response to
  HEAD at its header section, and resumes the parser on a `204` or a `304` that names a coding, which llhttp ends
  there by its status. A `Parser` driven directly accepts a `204` or a `304` that names a coding too: its status says
  no body follows. Every other `1xx` joins them (the entry below). A response with a body is held to `chunked`, which
  is all qb decodes. `Transfer-Encoding` beside `Content-Length` is refused on every message, as before (by llhttp, at
  its field line). Witnesses: `qbm-http-test-unit-http1-protocol-framing` (a response to HEAD, a `1xx` answering one,
  a `204` and a `304` naming `gzip`, `gzip, chunked` or `br`, each followed by a response it must not eat; a `304`
  that ends the buffer; a `Parser` driven directly; the controls, each refused case fed alone) and
  `qbm-http-test-system-http1-client` (the persistent client against a scripted peer: one connection for a HEAD, a
  `304` and a GET; three before).

- **Every `1xx` ends at its header section, whatever transfer coding it names (Huly QB-1248).** A client handles an
  unknown `1xx` as interim (RFC 9110 §15.2), and every `1xx` ends at its header section (RFC 9112 §6.3). A `1xx` that
  named a coding other than `chunked` alone was refused, whatever its status (a `103` naming `gzip` among them); one
  that named `Transfer-Encoding: chunked` was read as a chunked body once the protocol resumed the parser, unless
  llhttp ended it by its status (`100`, `102`, `103`) or completed it to leave for the upgrade (`101`): the final
  response's status line taken for a chunk size, the request failed with its connection. The HTTP/1.1 parser now marks
  every `1xx` `F_SKIPBODY`, llhttp's own mark of a message with no body, before the parser can be resumed on it, and
  lets every `1xx` name any coding: nothing follows to decode. A `101`'s `upgrade` flag is set before the mark, which
  llhttp's upgrade test reads only to leave as it did, and a `1xx` was already kept alive by its status: neither
  changes. Witnesses: `qbm-http-test-unit-http1-protocol-framing` (a `104` and a `199` naming `chunked`, a `199`
  naming `gzip`, a `104` naming `gzip, chunked` and a `103` naming `gzip`, each followed by the final response; a
  `101` naming `gzip`, framed alone, since nothing after a `101` is HTTP; the controls: `100`, `102`, `103` and `101`
  naming `chunked`, a `101` with its upgrade, a `1xx` with no length, a `200` naming `chunked`) and
  `qbm-http-test-system-http1-client` (the persistent client against a scripted peer waits past a `104` naming
  `chunked` for the final response, on one connection; two before).

- **A `101 Switching Protocols` ends HTTP/1.1 on its connection, and one to a protocol the request did not offer
  fails it (Huly QB-1248).** After a `101` the connection speaks the protocol the server switched to (RFC 9110
  §15.2.2), and llhttp ends the message at its header section for that reason. The persistent client delivered every
  `101` as the answer and kept its connection: the bytes the server sent after it were read as the response of the
  next request, which a queued request received without the server having read it (a scripted peer's `101` followed
  by `HTTP/1.1 200 OK ... smuggled`: the second request got `smuggled`). A server must not switch to a protocol the
  request did not offer in its `Upgrade` field (§7.8), and both clients took any `101` for the answer. The persistent
  client now retires the connection at any `101`, one that arrives with no request in flight included, the queue going
  to a new connection (with auto-reconnect, the default; without it the queue fails as after any retired connection):
  a `101` whose `Upgrade` names only protocols the request offered (every field line of either read as one list, `*` a
  name like any) is that request's answer, as before; any other -- to a request that offered none, to another
  protocol, or naming none -- fails the request with `502 Bad Gateway`,
  counted a failure. The one-shot session answers 502 to the latter as well; it disconnects after every answer
  already. curl 8.7.1, measured against the same peer, takes an unasked `101` for the final response, reads what
  follows as its body until the connection closes, and never reuses the connection. Witnesses:
  `qbm-http-test-system-http1-client` (the persistent client with the request behind it queued: an unasked switch, an
  offered one, one to another protocol and one naming none, two connections each; a `101` with no request in flight;
  the one-shot session, unasked, offered and to another protocol).

- **`max_chunk_size` holds a request's chunk by the size it declares, before a byte of it is read (Huly QB-1248).**
  The HTTP/1.1 parser compared the chunk limit with each piece of the body llhttp handed `on_body`, and a reader hands
  the pieces it reads: the server's are no larger than a read (64 KiB), so a chunk of any size passed a limit of 64 KiB
  or more -- with the default 16 MiB limit a 20 MiB chunk was served, with a 64 KiB limit a 128 KiB one. The parser
  now checks the size a request's chunk-size line declares when the line ends (`on_chunk_header`, llhttp's chunk
  length): past the limit the request is refused with `413 Content Too Large`, as the body limit refuses it, before a
  byte of the chunk is read. A response's chunk is held by the body limit alone, as it was in practice: nothing is
  sized from a chunk's size, a client sets no limit of its own, and a server may write a buffer of any size as one
  chunk. qb's serializers write a whole chunked body as one chunk, and the chunk serializer now writes one past 64 KiB
  -- a server's read -- as frames of 64 KiB, so a qb server whose chunk limit is at least that takes a chunked request
  of any size under its body limit from a qb client. The comparison with each piece is gone: it no longer stopped anything a chunk
  could carry, and it refused a `Content-Length` body a `Parser` driven directly was handed in one piece larger than
  the chunk limit, as if that body were a chunk. llhttp reports a refusal from `on_chunk_header` as
  `HPE_CB_CHUNK_HEADER` (it reported `HPE_USER` from `on_body`); the refusal status is what the protocol answers.
  Witnesses: `qbm-http-test-unit-http1-parse-limits` (a chunk declaring past the limit refused at its size line, its
  data handed in pieces of 1 KiB; the controls: a chunk at the limit read in pieces and whole, the body limit across
  chunks; a `Content-Length` body in one piece past the chunk limit), `qbm-http-test-unit-http1-protocol-framing` (a
  128 KiB chunk under a 64 KiB limit refused with 413 whatever pieces it arrives in, one at the limit dispatched; a
  response's chunk past the default limit read; a chunked request of 16 MiB + 5 written in frames of 64 KiB a server
  dispatches at its default limit and at 1 MiB, a chunk of 64 KiB one frame) and `qbm-http-test-system-http1-client` (a qb client's
  chunked upload and a qb server's chunked response of 16 MiB + 5, both ways at the default limits). A chunk of one
  frame at most -- every chunk but a whole body's -- is written by the serializer's straight path, past a single
  branch; the frames of a larger one go out of line, the same bytes (measured with g++ 14 on x86-64: written as one
  loop over the frames, the serializer cost every chunked message +30 to +46 instructions against the one it replaced).

- **A request whose framing is refused is answered `400`, then the connection closed (Huly QB-1248).** A
  `Content-Length` llhttp refuses -- past 2^64-1 (its overflow), not a number, given twice, beside `Transfer-Encoding`
  -- a `Transfer-Encoding` that names `chunked` twice or not last, a chunk size llhttp refuses (not hexadecimal, or
  past 2^64-1), a field the trailer section must not carry: the HTTP/1.1 server closed the connection with no answer
  for each, where RFC 9112 §6.3 says the server answers `400` and then closes (and §6.1 for a request carrying both
  fields). Only a target that names no resource, a version other than 1 and a `Host` that names no authority were
  answered. The protocol now hands the request to the session as it does those (`http1_refuse_request`), which answers
  `400 Bad Request` with `Connection: close` and closes; nothing the request carried is served. A coding before a
  final `chunked` -- `gzip, chunked`, which the server does not implement -- is answered `501 Not Implemented` (§6.1).
  The parser records the status for its own refusals (`refusal_status()`); llhttp's refusals are mapped by its error
  code. A response whose framing is refused still fails the client's request, unanswered; every other malformed
  request is answered too (the entry below). Witnesses: `qbm-http-test-unit-http1-protocol-framing` (fourteen framings
  refused with 400, one with 501, the request after each never dispatched; the controls: each framing well-formed is
  dispatched, a response's refusal fails the client's protocol, a malformed field line is still not answered) and
  `qbm-http-test-system-http1-client` (a `Content-Length` of 2^64, `abc` and given twice answered 400 with
  `Connection: close` on the wire, then the close).

- **Every malformed request is answered `400`, then the connection closed (Huly QB-1248).** A request llhttp refused
  as malformed with no status of its own -- a method that is no token, a version llhttp refuses (`HTTP/9.9`,
  `HTTQ/1.1`), a field name that is no token or whitespace before its colon, a CR with no LF, a control byte in a
  field value, a chunk or a chunk-size line not ended by CRLF, bytes that are no HTTP (a TLS ClientHello on a plain
  port) -- closed the connection with no answer, where RFC 9112 §2.2 says the server SHOULD answer `400` and close.
  The protocol now answers every refusal llhttp makes of a request `400`, as it answered a target and, since the entry
  above, a framing it refuses: one rule, not a list of codes. The exceptions are named: a pause is no refusal (the
  header section's, an upgrade's) and never reaches the refusal; a refusal with a status of its own keeps it (a limit,
  a target, `Host`, the version, a framing, an exception in a callback); an io that cannot answer -- the client's --
  closes, and a response still fails the request. A `Content-Length` given twice is refused even when the values agree
  (`1` and `1`, `1, 1`), kept deliberately against the "unless" of §6.3, which lets a recipient take the single value:
  llhttp, Node.js and nginx refuse it too, so no two parsers in a chain can disagree on the length (answered `400`
  since the entry above). Witnesses: `qbm-http-test-unit-http1-protocol-framing` (ten malformed requests answered
  `400`, the request after each never dispatched; the controls: an io that cannot answer closes, a limit keeps its
  `414`; a duplicated `Content-Length` refused three ways) and `qbm-http-test-system-http1-client` (a method that is
  no token answered `400` with `Connection: close` on the wire, then the close). The answer waits behind the requests
  still in flight: a malformed request pipelined behind a request not yet answered closed the connection before that
  request's response, which the client lost; the response now goes first, then the `400`. Nothing pipelined behind a
  request that carries `Connection: close` is answered (RFC 9112 §9.6), a malformed request included: the session
  closes after that request's response and reads nothing more, and llhttp's refusal of data after `Connection: close`
  never comes, its parser stopping at each message's end and starting the next afresh. Witnesses (same binary): the
  response in flight answered before the `400`; behind a "close" request answered at once or 50 ms later, a request, no
  request and a target past the limit, each unanswered.

- **The HTTP/1.1 server's inactivity timeout restarts at a request's first byte and at each read of its body (Huly
  QB-1248).** Only the server's writes restarted it, as readme/16 said: a request had to arrive whole within the
  timeout -- 60 s by default -- of the connection's opening or of the last response. A body sent slowly but steadily
  was cut with no answer (a chunk of one byte every 5 s: closed at 60.0 s), and a request begun 59 s after a response
  had 1 s left to arrive. The timeout now runs as nginx's three: between two requests from the last write (the
  keep-alive close is unchanged); over a request's header section from its first byte, however the section is cut --
  a header section sent slowly is still cut, its bound unchanged; over its body between two reads of it
  (`client_body_timeout`). No setting is added: the session's timeout is the one value, and a session that sets its own
  (`setTimeout()`) gets the three with it. The HTTP/1.1 requests of an HTTP/2 server's ALPN fallback restart it the same
  way. A body sent at one byte per timeout keeps its connection, as on nginx: its memory stays under the body limit,
  the connections under `set_max_sessions()`. HTTP/3 needs none of it: its inactivity is QUIC's idle timeout, which
  every packet restarts (readme/19, with the measurements and its residual). Witnesses:
  `qbm-http-test-unit-http1-protocol-framing` (the hook called at a request's first byte and at each read of its body,
  either framing, never inside a header section nor for the read that completes a message),
  `qbm-http-test-system-http1-client` (at a 1 s timeout: a body sent over 3 s is served
  in both framings; a request begun 0.75 s after a response and sent over 0.5 s is served; the controls: a header
  section dribbled from its first byte ends a timeout after it, a stalled body a timeout after its last read, an idle
  connection a timeout after its last response) and `qbm-http-test-system-http2-client` (the same body over the ALPN
  http/1.1 fallback is served).

- **The HTTP/2 server's inactivity timeout restarts at a request's first `HEADERS` frame and at each `DATA` frame of
  its body (Huly QB-1248).** It restarted on the server's writes and at a request's dispatch: a request had to arrive
  whole within the timeout -- 60 s by default -- of the connection's last write. Measured: a body sent one `DATA` byte
  every 5 s was cut at 60.0 s with no answer, and a request begun late had what was left of the timeout. And the
  sweep's bound on a stream whose request is not complete, `STREAM_INCOMPLETE_TIMEOUT` (10 s), was an age, counted from
  the stream's opening whatever happened on it, as readme/17 said: a sweep 10 s into an upload still arriving reset it
  (`CANCEL`). Both now move on what the client sends of the request, and on nothing else. A header block has the whole
  timeout from its first `HEADERS` frame -- the stream is created there, and its clock starts there -- and its
  `CONTINUATION` frames restart nothing, so a header block dribbled is still cut. A `DATA` frame that brings octets of
  the body restarts the timeout and moves the stream's clock: a body sent slowly but steadily is served, and one whose
  octets stop arriving is cut a timeout after its last frame, its stream reset by a sweep once the incomplete bound
  has passed. A body that drips an octet within each bound keeps its stream and its connection, as on nginx: what it
  holds stays under the body limit a stream and the concurrency limit a connection, every octet of it one the client
  sent. An empty `DATA` restarts nothing and moves nothing, by design: the frame layer counts it among the frames
  that make no progress, and a peer that could restart the timeout with it would hold a connection, and an incomplete
  request, for free -- no octet ever counted against the body limit. A stream `WINDOW_UPDATE` moves nothing of a
  request not yet complete, by design: it acknowledges nothing of the request, and a peer must not keep an incomplete
  request alive by acknowledging the server's window (what it does for a response is the next entry's). The sweep that
  enforces the bound runs from a timer of the session's own (the next entry): it ran on write activity alone. The
  protocol tells the session through a hook found by a requires-expression, as the HTTP/1.1
  protocol does: `http2_request_progress()`. Witnesses: `qbm-http-test-system-http2-client` (at a 1 s session timeout:
  a body sent over 3 s is served; a request begun 0.75 s after a response, its header block sent over 0.5 s, is served;
  a body that stalls ends a timeout after its last `DATA`, cut on the base before it stalled; empty `DATA` frames a
  quarter of the timeout apart end the connection a timeout after its `HEADERS`; the controls: a header block dribbled
  in `CONTINUATION` frames ends a timeout after its first `HEADERS`, an idle connection a timeout after its last
  response) and `qbm-http-test-unit-http2-server-protocol` (the hook called at a request's first `HEADERS` and at each
  `DATA` that brings octets, never at a `CONTINUATION`, an empty `DATA`, the frame that completes the request or a
  `WINDOW_UPDATE`; the sweep sparing an incomplete request whose body arrives past the bound, resetting it once its
  octets stop -- an empty `DATA` saves nothing -- and resetting one whose only frames since its last `DATA` are stream
  `WINDOW_UPDATE`s).

- **The streams of an HTTP/2 connection are swept from a timer of the session's own, each bounded by whose turn it is
  (Huly QB-1248).** The sweep ran from `on(pending_write)` alone -- a write that leaves bytes queued: a connection that
  only read, as an upload's, or whose writes always drained was never swept, and once the inactivity timeout restarted
  on what a request brings (the entry above) nothing bounded the connection's other streams. Fifty streams, forty-nine
  filled close to the body limit then left there, the fiftieth dripping an octet under the timeout: some 4.9 GiB at the
  default limits, held for as long as the client wished. The session now arms a timer at a connection's first stream
  and for as long as it has streams -- an idle connection has no tick --, every half of the smallest bound: 5 s by
  default, less under a shorter session timeout, 50 ms at least. And a stream is bounded by the time since its last
  progress, by a bound that depends on whose turn it is. Its client's, while its request is not complete:
  `STREAM_INCOMPLETE_TIMEOUT` (10 s), as above. Its peer's, while it has not taken what the response has for it -- DATA
  a window or the socket's room holds back, frames the socket has not taken, a pushed response waiting for room under
  the client's concurrency limit: `STREAM_IDLE_TIMEOUT` (30 s). Its handler's, while it has not answered, or not
  finished: the session's own inactivity timeout (60 s by default, none when the session has none), what an HTTP/1.1
  exchange has. It was one bound, 30 s, for every dispatched stream. The peer's clock starts when the application hands
  the stream something its peer did not already owe -- a handler that answered within its own bound is not judged on
  the time it took --, and it moves on what the SOCKET takes of the stream's frames, no longer on what the protocol
  queued: a download that flowed slowly was reset 30 s after its last DATA frame was written, however the socket
  drained, and DATA queued behind a socket that took nothing counted as progress each time a `WINDOW_UPDATE` let some
  out. What counts is an octet the socket takes while the stream has frames queued for it, its own or those in front
  of them: a frame written after the socket's last drain is credited with nothing, and a stream that writes again
  keeps what the socket took of its earlier frames. A response that waits on what the connection shares -- DATA its
  own window does not hold back: the connection's window, the socket's room, its turn; a pushed response's room under
  the client's concurrency limit, while that limit is above 0 -- moves with the connection's DATA, any stream's,
  read the same way: fifty downloads behind a connection window a slow reader reopens a frame at a time are each
  served once in fifty frames, and none of them is a response its peer does not take; one its own window holds waits
  on its peer, whatever the connection moves, and so does a pushed response under a limit the client lowered to 0
  after the promise, whatever pushed stream is still open: nothing the connection sends lets it out. A stream
  `WINDOW_UPDATE` is no progress of its own. The handler's bound is the session's timeout as it is at the sweep, on
  the request's own clock. A peer that takes an octet within each bound keeps its response, and one octet of the
  connection's DATA keeps every response that waits on the connection -- as under nginx's `send_timeout` and Go's
  `WriteByteTimeout`, which is the connection's: no rate is asked of a peer, and a streamed response is held to one
  by its own `set_min_rate()`. The stall watch a stream may set (`set_idle_deadline()`, the 60 s of a streamed static
  file) stays that stream's own: it ends a stream none of whose bytes left for that long, whatever its neighbours
  send -- so a stream among N that share a slow connection, served a turn in N, needs its turn within its deadline:
  at 60 s and with turns of 16 KiB, the largest, some 273 octets a second for each of them at most (derived from the
  two figures, not measured; smaller credits make smaller turns, and ask less). `cleanup_idle_streams()` is handed
  the time of the sweep and the three bounds, `cleanup_idle_streams(now, max_idle, max_incomplete, max_unanswered)`;
  its two-argument form remains, with one bound for every dispatched stream. A connection that has ended is not
  swept, and has nothing for the sweep to go on for (`has_streams()`): no frame leaves it, so a stream past its bound
  was erased without its RST_STREAM and without its observer.
  Witnesses: `qbm-http-test-unit-http2-server-protocol` (the clock stepped by hand, no sleep: each of the three turns
  reset at its own bound and at no other; a session with no timeout leaving a handler unbounded; a response the socket
  takes slowly kept for a minute, then reset 30 s after the last of it left; DATA queued behind a socket that takes
  nothing; a frame written after the socket's last drain; what the socket took of a stream before it wrote again; what
  the socket takes of another stream; a head the socket has not taken, and one it took; a stream `WINDOW_UPDATE`; the
  dispatch starting its handler's clock; a piece, a response, a streamed head and a streamed end written 40 s into a
  handler's turn each having the peer's whole bound, and what is written to a peer that already owes, or an empty
  piece, moving nothing; a pushed response waiting on the client's limit, and one the sweep's own reset lets out,
  neither handed over again nor credited with a drain that came before its frame, in either order of the table; five
  responses behind the connection's window, served a frame every 20 s in turns, kept for five minutes then reset 30 s
  after the connection's DATA stops, and three for two minutes on an io that does not count; one its own window
  holds, the answers to a peer's PINGs and a neighbour's HEADERS keeping nothing; a streamed end waiting for the
  socket's room with its window spent; DATA taken whole then followed by more before the sweep; a pushed response
  waiting for the client's room kept while the push in front of it leaves, and reset at the peer's bound once the
  client's limit is 0, a download flowing beside it or a pushed stream still open and read a frame at a time, and
  kept by a sweep run while the place it waits for is being freed; a connection that has ended, left as it is; the
  drain's last delivery -- the protocol not ok, its connection still active --, not swept, a late response refused
  and its stream left open; a graceful shutdown in progress, still swept, ended by the reset of its last stream; a
  protocol reset forgetting the block it was discarding and the last connection's DATA) and
  `qbm-http-test-system-http2-client` (at a 1 s session timeout, a request its handler never answers reset between one
  and two timeouts beside an upload that drips, on a connection the server writes nothing to -- never, on the code as
  it was --, the connection serving on; the same beside a response the server streams, nothing arriving from the
  client; a session extracted under the sweep, which no later tick touches and the public sweep leaves alone; and, the
  time stepped by hand, a session with no timeout leaving a request to its handler however long, then the timeout it
  is given bounding the request from its dispatch; the session asserted to count its output, without
  which the sweep reads a response on the frames written).

- **Streams that wait share what lets them send, in turns (Huly QB-1248).** On a connection `WINDOW_UPDATE`, on a
  `SETTINGS_INITIAL_WINDOW_SIZE` that reopens stream windows together, on a `SETTINGS_MAX_CONCURRENT_STREAMS` or a
  sweep that lets several pushed responses out together and when the socket makes room, the streams that waited were
  served in the order of the server's table -- the pushed responses in the order they were answered --, each as far
  as the windows went: the first took everything, every time, and the others waited for it to finish. They send one
  DATA frame each, of 16 KiB at most whatever frame size the peer allows, the least recently served first, round
  after round, until none can send (`resume_waiting_streams()`); a stream that begins to wait takes its place behind
  those that already do, so that a download is not passed over by the requests that come after it, and DATA handed in
  while the turns are served -- a pushed response the turn that ended its neighbour lets out, a response or a
  streamed piece an observer writes from inside a turn -- waits for a turn of its own, at the place its stream takes
  there and then, or the one it has; a stream alone is served everything at once, as before. Witnesses, red on the
  code as it was: `qbm-http-test-unit-http2-server-protocol` (three responses behind the connection's window: credit
  for three frames serves each one frame, then credit a frame at a time a different stream each time; a setting that
  reopens three stream windows; two streamed responses sharing the socket's room; a pushed response let out in
  another stream's turn, served before the stream served after it began to wait; three pushed responses the client's
  limit releases together, and two that one sweep lets out; a streamed piece an observer writes inside a turn; a peer
  that allows frames of 1 MiB, buffered and streamed responses; a download beside twenty-four requests that each
  arrive before a credit; a stream alone), and, held by their mutants, the round that follows one whose turns sent
  nothing and the place a stream keeps when it is handed more during a round.

- **A stream the HTTP/2 server resets while its header block is still arriving no longer ends the connection (Huly
  QB-1248).** The sweep resets a request that is not complete; one whose header block -- or trailer block -- was still
  arriving left its `CONTINUATION` frames to meet an unknown stream: `GOAWAY(PROTOCOL_ERROR)`, a connection error of
  the server's own making. They are read for the HPACK table and dropped, as a refused block's are
  (`send_rst_stream()`), under the same size and count limits. And a refused block left open -- that one, or a block
  refused at its `HEADERS` -- has a bound, an incomplete request's: 10 s (`STREAM_INCOMPLETE_TIMEOUT`) from the sweep
  that first sees it refused, whatever `CONTINUATION` frames it receives, then the connection ends,
  `GOAWAY(ENHANCE_YOUR_CALM)`; a block whose stream the sweep reset has had that stream's own bound first. Nothing
  bounded it: no stream is left for it, and the session's timeout restarts on the server's own writes, so a client
  that had opened an event stream first held the block -- up to the header block limit, on a connection that may
  send nothing else meanwhile -- for as long as the stream wrote. The sweep goes on while such a block is open
  (`has_streams()`), and the session arms it for one (`http2_refused_block_open()`, which the protocol calls, on an
  io that has it, when a `HEADERS` it refuses leaves its block open): on a connection whose last stream had ended no
  tick was due, and a session with no timeout held the block for ever. The session is released at once, as for
  every error it ends a connection with: sent from the sweep's timer, outside the read dispatch, the GOAWAY frame is
  dropped with it, and the client reads the end of its connection -- delivering it would keep a session whose
  protocol has ended, with its contexts and its output, for as long as the client took to read. Witnesses:
  `qbm-http-test-unit-http2-server-protocol` (red on the code as it was: a block cut in two and in three, a trailer
  block -- the connection serves on, and the next request names the dropped block's entry by its index; a block left
  open after the sweep reset its stream, ended 11 s after the sweep that saw it, an octet of `CONTINUATION` changing
  nothing; a block refused at its `HEADERS`, one that ends in time leaving its clock to no other; the io told of a
  block left open, and of no other) and `qbm-http-test-system-http2-client` (a refused block on a connection whose
  sweep had lapsed: the session's own tick sees it, and the connection ends at the block's bound -- the session
  disconnected when that sweep returns, and gone from the server a dispatch later).

- **A reset the HTTP/2 server makes outside the read dispatch no longer runs its protocol under an observer that
  cleared it (Huly QB-1248).** A reset's observer cancels the stream's context, and a hook of that context may clear
  the session's protocols. Inside the read dispatch they are retired (qb, Huly QB-1278); outside it they were destroyed
  at once, under the function that was running them: `reset_stream()` called from a timer or a coroutine resumed
  later, a streamed response aborted -- the stall watch's timer -- or ended with a trailer section the protocol
  refuses, the write pass that resumes a streamed response, the sweep (ASan: heap-use-after-free in
  `send_rst_stream()`). The session holds qb's `protocol_pass()` at every such entry, and a protocol its reset's
  observer retired is neither active nor ok any more: the reset itself lets no waiting pushed response out, its caller
  writes nothing after it -- no `GOAWAY` past the Rapid Reset ceiling or for a window overflow, told to the io, no
  connection `WINDOW_UPDATE` --, the sweep and the turns stop there, and a SETTINGS frame whose turns ended that way is
  not acknowledged, its later entries writing nothing. And the session
  read `_http2_protocol` bare, a pointer it never lowers: a second reset, or a response sent late, ran the freed
  object. It reads it through the io and through the lifetime of the object it installed (`live_http2_protocol()`; the
  HTTP/1.1 fallback's the same way, and the TLS handshake's pointer is lowered once the session replaced it): once the
  protocols were cleared `reset_stream()` returns `false` and a response is dropped, and a protocol installed later at
  the same address is not taken for the one that is gone -- by a reset, nor by the server's drain, which counted such
  a session as one that still spoke HTTP and waited for it until its deadline. Nor is the protocol live to a session
  its connection left: an extraction leaves it installed and the session "connected", and a reset, a response or a
  sweep acted on streams whose connection another owner had. Witnesses:
  `qbm-http-test-system-http2-client` (a reset, an abort and an end with a refused trailer section, each made outside
  the read dispatch with a hook that clears the protocols -- heap-use-after-free on the code as it was --; the hook
  under the sweep's reset ending its own connection alone, the server serving the next; a protocol as large as the
  session's own installed after the clear, where the HTTP/2 one was and where the fallback's was, out of a reset and
  out of the drain -- skipped where the allocator does not hand the block back, a sanitizer's; neither the sweep nor a
  reset acting on a session the server extracted) and `qbm-http-test-unit-http2-server-protocol` (the sweep and the
  turns stopping at the reset whose observer retired the protocol: no frame written after it, no waiting pushed
  response let out, no SETTINGS ACK, nothing written for the entries that follow in the same SETTINGS frame; no `GOAWAY`
  from a provoked reset past the ceiling nor from a window overflow, no `WINDOW_UPDATE` from the frame handler of a
  provoked reset).

- **The last delivery of an HTTP/2 server's drain has its bound whatever the client takes (Huly QB-91, found by the
  reviews of QB-1248).** At the drain's deadline a connection that never answered the `PING` is sent its final
  `GOAWAY` and closes once that is delivered, "within qb-io's linger bound". The bound was the session's inactivity
  timeout, set to the linger -- and that timeout restarts at every write that leaves octets queued: a client whose
  reading made the server write within each linger kept its session, with its contexts and its output, for as long
  as it wished (measured by the ninth independent review: still up 9 s after the deadline under the default linger
  of 2 s, the client reading 5 ms every 300 ms; it is the server's writes that restarted it, not the client's
  reads -- with megabytes waiting in the kernel the server writes once in a while, and the timeout could lapse,
  the tenth review measured). The delivery has a one-shot timer of the session's own, counted from the deadline,
  which nothing restarts. At the bound a session whose output is not delivered is aborted with what
  is left of it (`DisconnectedReason::ServerDraining`, what the enum says of a session aborted at the deadline; a
  client that read nothing was reported `ByTimeout`); one that is delivered is in qb-io's lingering close, which
  waits for its peer for the linger bound again, and is left to it -- cut there, its socket would close under a
  client that may not have read what it was just sent. The session's inactivity timeout is over from the deadline:
  the delivery has that one bound, whole, whatever the timeout was (a session whose timeout was shorter than its
  linger had the linger, as before). A session extracted during the delivery has no bound left: its connection is
  its next owner's. A `set_linger()` of zero or less aborts at once, as before, and so does a loop that refuses the
  timer. A session something else ended first keeps the reason it ended with (the entry below). The `deadline`
  report still comes right after the final `GOAWAY`s are queued, before their delivery: those connections end
  within two lingers of it, and a server destroyed on the report cuts them. Witnesses:
  `qbm-http-test-system-server-drain-h2` (32 MiB queued behind a send buffer of 16 KiB asked -- Linux grants twice
  that --, so that the server writes again whenever its client's reading makes room, every few tens of
  milliseconds, and a client taking 256 KiB every quarter of a second: aborted a linger
  after the deadline, `ServerDraining`, not before and less than a linger late -- on the code as it was the
  session outlived the case's three seconds, 20 runs of 20 under g++ 14 Release and 20 of 20 under ASan --; a
  delivery completed 150 ms after the deadline, the session ending a linger after the delivery, by itself -- a
  linger after the deadline on the code as it was --; a session extracted in the pass of the deadline, read past
  the bound as the extraction left it; a session disconnected in the pass of the bound, keeping its reason).

- **An HTTP/1.1 or HTTP/2 server session keeps the first reason it ended with (Huly QB-1248, found by its reviews).**
  qb-io's `disconnect()` updates the reason at each call; a session something ends in a pass of the loop is released
  a dispatch later -- after the timers and the deferred completions of that pass when the poll had made its watcher
  pending (output queued, or input arrived), before them otherwise -- and, held by a capture after its release, still
  takes the ticks of its timers. A later disconnection of the session's own reported its reason over the cause: the
  inactivity timeout's `ByTimeout`; the drain deadline's `ServerDraining` (HTTP/1.1, a bare session of the HTTP/1.1
  server, and HTTP/2 wherever its deadline aborts at once: a linger of zero, the HTTP/1.1 fallback, a session still
  in its TLS handshake or whose protocol has ended); a response or a streamed response completed from a callback.
  Every disconnection of the session's own now goes through one check, and the HTTP/1.1 session's timeout does
  nothing for a session that has ended: a session type's own `on(event::timeout)` is no longer called there -- it
  was, and its disconnection was reported over the cause before the release when the session had output queued, and
  read after the release when it had none. Neither session's inactivity timeout acts on a session in qb-io's
  lingering close any more -- a response delivered with `Connection: close`, an HTTP/2 connection that ended
  gracefully, waiting for its peer --, a session type's own `on(event::timeout)` included: the linger has its own
  bound, and the timeout ended the session `ByTimeout`, its socket closed under a peer that may not have read what
  was just delivered. A session whose close is under way, its output not delivered yet, does not linger: its
  timeout still ends it (but for the HTTP/2 drain's last delivery, which its own bound ends, the timeout over). Each
  server session names its inactivity timer for qb-io (`inactivity_timer_t`), and an extraction stops that one: a
  timer a session type keeps of its own -- a `use<S>::timeout`, a `with_timeout` base of its own type -- is left to
  tick (the first was stopped in its place, the second left the inactivity timer armed beside it, and a session held
  past its extraction was timed out). The name is reserved: a session type that declares an `inactivity_timer_t` of
  its own does not compile (it hid the session's, and the extraction stopped another timer), and inside a class
  deriving from a server session an unqualified `inactivity_timer_t` names the session's (in a class template, whose
  base is dependent, it does not: `typename MySession::inactivity_timer_t` does). A `disconnect()` the application
  makes itself is qb-io's, unchanged. Witnesses: `qbm-http-test-system-http1-loopback-basic` and
  `qbm-http-test-system-http2-client` (a session disconnected by a callback in the pass of its inactivity timeout,
  its response queued, and with nothing queued -- released first, its timer ticking after the release --; a session
  type's own timeout handler, not called; a disconnection, and a timeout, in the pass of the drain's deadline, a
  bare session's too; each reading the reason at the release and after it; a lingering session whose client keeps
  its end open a second, under a timeout of 150 ms; a `Connection: close` response not yet written when its timeout
  runs, timed out; a session held past its extraction, with and without a timeout handler of its own, running no
  timeout -- qb's `extractSession()` stops the timer --, and with a timer of its own of either shape, which ticks)
  and `qbm-http-test-system-server-drain-h2` (a session disconnected in the pass of the last delivery's bound; a
  session lingering after a graceful drain, under a timeout of 150 ms); refused at build, a session type that
  declares an `inactivity_timer_t` of its own: `qbm-http-test-unit-inactivity-timer-name-h1` and `-h2`.

- **The HTTP/1.1 clients read a body of exactly their limit, and name the limit when a body passes it (Huly
  QB-1248).** Neither the persistent client nor the one-shot verbs read a response whose body is exactly the 100 MiB
  limit: qb-io's generic message cap (`QB_MAX_MESSAGE_SIZE`, 100 MiB), which their connections kept, cut the response --
  body and header section -- before the parser's limit was reached, a 502 "Connection closed" (measured: 100 MiB - 64
  KiB delivered, exactly 100 MiB refused). Both connections lift it, as the server session did (Huly QB-168): the
  parser's body limit is the bound, and qb-io's read cap (`QB_MAX_READ_BUFFER_SIZE`, 200 MiB) the ceiling of a
  response held whole in the input buffer. A body past the limit failed with the same 502 "Connection closed"; the
  persistent client's error, and the one-shot verbs' 502 body, now name the limit, as the HTTP/2 client's names its
  own -- and the bound that cut a response is the one named: qb-io's read cap when the input buffer filled once the
  header section was read (under a limit of none, or one raised past the cap, which read "Connection closed"), the limit
  only when the parser refused the body on it, never a limit of none. Witnesses (`qbm-http-test-system-http1-client`): a
  body past the read cap under a limit of none and under one raised past it, each failing with the cap named; a body of
  exactly 100 MiB delivered by both clients (a 502 on the base); past a limit of 1024, a declared, chunked and
  close-delimited body each failing with an error naming it, 1024 itself delivered; the default unchanged, one byte past
  100 MiB failing with the limit named by both clients; a limit raised past 100 MiB, and 0, delivering a body the default
  refuses.

- **A streamed chunked response's admission counts every frame its piece leaves as (Huly QB-1248).** Since the chunk
  serializer writes a piece past 64 KiB as frames of 64 KiB, each with its own size line and CRLF pair, `ResponseStream`
  budgeted the framing of one chunk for a piece that leaves as several: under a write cap, a piece it admitted could
  pass it (measured: under a 1 MiB cap, a piece one byte past the room admitted,
  and both pieces written). `chunk_overhead()` counts the frames from the constant the serializer writes them with,
  `qb::http::chunk_frame_size`, so the two cannot drift. Witnesses (`qbm-http-test-system-response-stream`): the
  overhead equal to the serializer's framing to the byte across frame boundaries; under a 1 MiB cap, the largest piece
  whose frames fit taken and one byte more `too_large`.

- **A `Transfer-Encoding` that ends in an empty list element is refused `400`, by decision (Huly QB-1248).** RFC 9110
  §5.6.1.2 lets a recipient ignore an empty list element, so `Transfer-Encoding: chunked,` could be read as chunked;
  it is refused instead, as a `Content-Length` given twice is: Transfer-Encoding is the field request smuggling plays
  on, and a value two parsers in a chain could read differently is a value to refuse. The refusal is llhttp's, which
  marks a body chunked only when `chunked` ends the field (`HPE_INVALID_TRANSFER_ENCODING`, with no status of the
  parser's own -- qb's own scan reads `chunked` last), answered `400` by the rule of the entry "Every malformed request
  is answered `400`"; `,chunked` ends in `chunked` and is read as chunked. Documented in readme/15 beside the
  duplicated `Content-Length`. Witness: `qbm-http-test-unit-http1-protocol-framing` (`chunked,`, `chunked, ` and
  `chunked ,` each answered `400`, nothing dispatched, the parser's error llhttp's with no status of its own; `,chunked`
  read as chunked).

- **An HTTP/1.1 client closes at once the connection of a response a bound cut (Huly QB-1248 with QB-1270).** A
  response refused for the client's body limit, or cut by qb-io's read cap, comes from a server that is still sending
  it. Since qb-io closes a connection this side ends after its peer, that connection was handed to the thread's loop,
  to be read and dropped for `linger()` -- up to 16 MiB of a body the client had just refused -- and a thread that
  ran no loop pass after its request (`qb::http::run_sync()` returns, then other work) left the server blocked in
  its write for as long as the thread lived. The persistent client's connection and the one-shot verbs' session now
  set a linger of zero when a bound cut the response (`cut_by()`), which qb-io reads as "close at once": the server's
  next write fails. A response failed for any other reason still closes after its peer. Witness:
  `qbm-http-test-system-http1-client` (`ABodyPastTheClientsLimitFailsWithAnErrorThatNamesIt`: nothing left on the
  loop after each refusal -- a declared, a chunked and a 100 MiB body, and the one-shot verb -- and one closing socket
  after a response failed for a length that is no number, the control). On the composed train the case hung before
  the fix, its server thread in a write nobody read; its server now writes without blocking, so a regression fails in
  a quarter of a second. Mutants, the unmutated tree green before and after: the persistent client keeping its
  linger (three expectations fail), the one-shot session keeping its own (one) -- 2 planted, 2 caught.

- **A request pushed from the failure callback of a response a bound cut goes to a new connection (Huly QB-1248).**
  The persistent HTTP/1.1 client failed the request of a response its body limit, or qb-io's read cap, cut before it
  retired the connection: the callback ran while `is_connected()` was still true and the transport open -- the
  disconnection's handler runs before the transport ends -- so the request next in line, one the callback pushed or
  one already queued behind the cut one, was written to the connection being closed, and the disconnect that followed
  failed it with 502 "Connection closed", whatever the reconnection policy. Every other end of a connection retired it
  first: a response that closes, a `101`, a timeout, a disconnect. A cut now fails through the same path as a
  disconnect -- the cohort detached, the connection retired, then the callbacks -- and its error names the bound as
  before. A request pushed from that callback goes to a new connection; with automatic reconnection off it is refused
  at once, 503 "HTTP/1.1 client is not connected", inside the push, as any work a disconnected client is given. A
  request QUEUED behind the cut one goes the same way: out on the new connection, or failed once, 503 -- "HTTP/1.1
  client is not connected" when the callback itself switches reconnection off, the request having waited for a
  connection that is then never made, and "Connection lost" when reconnection was off before the cut: it ends with the
  connection it waited behind. Witness (`qbm-http-test-system-http1-client`,
  `ACallbackOfAResponseTheBodyLimitCutQueuesItsNextRequestOnANewConnection`, under three policies -- reconnection on,
  switched off in the callback, off before the cut): a callback that pushes a request after a response of 4096 bytes
  cut at a limit of 1024, a second request queued behind it. On the base `is_connected()` read true in the callback
  and the queued request, next in line, failed 502 "Connection closed" under each policy; with reconnection off the
  pushed request failed after its push had returned, 503 "Connection lost". Now it reads false, and both requests are
  answered 200 on a second connection, or, with reconnection off, the pushed one is refused 503 before its push
  returns and the queued one fails once, 503, with the text of its policy. Mutants, the unmutated tree green first:
  the callbacks before the retirement, the cut no longer named -- 2 planted, 2 caught.

- **An HTTP/1.0 message with `Transfer-Encoding` closes its connection after it (Huly QB-1248).** HTTP/1.0 defines no
  transfer coding: a recipient of such a message treats its framing as faulty and closes the connection after
  processing it (RFC 9112 §6.1). The server read an HTTP/1.0 request's chunked body and kept the connection when the
  request said `Connection: keep-alive`, or under the session's keep-alive override; measured on the wire, the request
  pipelined behind it was served in both cases, and the persistent client kept the connection of such a response. The
  parser now reads the `keep_alive` of a message that carries the field as false whenever its version is not HTTP/1.1
  -- every version but HTTP/1.1 reads llhttp's keep-alive flag --, a request's and a response's, and the session's
  override keeps no such request: the message is processed, its answer says `Connection: close`, the connection closes
  and nothing behind it is served; a client retires the connection of such a response, one to HEAD or a `204`
  included. An interim response is such a message too: after `HTTP/1.0 100 Continue` that names a coding, the
  persistent client retires the connection once the final response is delivered, whatever that one says -- it returned
  on a 1xx before it looked at it, and kept the connection. Decided against answering `400`, which nginx does, and
  against ignoring the field, which Go's `net/http` does on an HTTP/1.0 message: the wording of §6.1 is what qb does.
  `Transfer-Encoding` beside `Content-Length` stays refused `400` on HTTP/1.0 as on HTTP/1.1, and nothing changes for
  an HTTP/1.1 message. Nothing is added to a message without the field, nor to a request that keeps its connection:
  the flag is cleared in the branch a `Transfer-Encoding` field already takes, and the override's test runs only for a
  request that does not keep its connection, under an override that is set. Witnesses:
  `qbm-http-test-unit-http1-protocol-framing`
  (`AnHttp10MessageWithTransferEncodingIsProcessedThenItsConnectionCloses`: a chunked HTTP/1.0 request and response
  that ask to be kept, read whole, a response to HEAD, a `204` and an `HTTP/0.9` response, `keep_alive` false -- true
  for each on the base; the controls keep theirs: the same request and response framed by a length, an HTTP/1.1
  chunked request) and `qbm-http-test-system-http1-client`
  (`AnHttp10RequestWithTransferEncodingIsServedThenItsConnectionCloses`: on the base the statuses read `200 200` then,
  under the override, `200 200 200` -- with `Connection: keep-alive` and with no `Connection` field --, the pipelined
  request served and the connection left open; now `200` and `200 200`, then the close; the controls: a length-framed
  HTTP/1.0 keep-alive request keeps its connection, and the override still keeps a length-framed HTTP/1.0 request;
  `AnHttp10ResponseWithTransferEncodingRetiresItsConnection`: the request after such a response goes to a second
  connection, one on the base, and after the same response framed by its length to the same one; so does the request
  after `HTTP/1.0 100 Continue` that names a coding, whatever version the final response carries -- one connection on
  the base --, where an HTTP/1.0 interim response that names none and an HTTP/1.1 one that names `chunked` keep
  theirs). Mutants: the flag not cleared, the flag cleared for a minor version of 0 only, the override keeping the
  request, the override refusing every request with the field -- 4 planted, 4 caught; for the interim response, its
  faulty framing never remembered, remembered for any interim response of such a version, remembered whatever the
  version, not applied to the final response -- 4 planted, 4 caught, and a fifth, what was remembered never forgotten,
  is equivalent: the connection it retires is not used again.

- **The session's keep-alive override never keeps a request that says `Connection: close` (Huly QB-1248).** A server
  that receives the `close` connection option MUST initiate the closure of the connection after it sends the final
  response (RFC 9112 §9.6). `session::keep_alive(true)`, the application's override, kept such a connection: measured
  on the wire, three requests of which the second said `close` were answered `200 200 200` -- HTTP/1.1 or HTTP/1.0,
  the option alone or one of a list --, the request behind it served and the connection left open. The override now
  fills a silence, and never contradicts the request: it applies only to a request that does not keep its connection
  and carries neither a `Connection` nor a `Proxy-Connection` field -- llhttp reads the second as the first, so
  `Proxy-Connection: close` ends an HTTP/1.1 request's connection as `Connection: close` does. One that says `close`
  in either field is answered with `Connection: close`, the connection closes, and nothing behind it is served; so is
  an HTTP/1.0 request that carries either field without `keep-alive`, whatever its options. What the override keeps is
  what it is for: HTTP/1.0 with neither field, which closes by default -- the only request it applies to, as an
  HTTP/1.1 request the parser does not keep carries one of the two, and llhttp reads no minor version past 1. The rule
  is a lookup of the two fields, not a scan of their options, made only under an override that is set, for a request
  the parser read as closing: a request that keeps its connection pays nothing, and the response's path is the code it
  was, instruction for instruction (Apple clang 21 and g++ 16, arm64). Witnesses: `qbm-http-test-system-http1-client`
  (`TheKeepAliveOverrideNeverKeepsARequestThatSaysClose`: ten requests -- eight that say `close`, in `Connection` or
  in `Proxy-Connection`, alone, in a list, before a HTAB, beside `keep-alive` on HTTP/1.0, with a chunked body, and
  two HTTP/1.0 ones whose only option is `te` --, each `200 200 200` on the base, now `200 200`, `Connection: close`
  and the close; the controls keep their connection: an HTTP/1.1 and an HTTP/1.0 request that carry neither field, an
  HTTP/1.1 one whose option is `closed`, one of each version that asks `keep-alive` through `Proxy-Connection`, and an
  HTTP/1.1 request with a chunked body) and `qbm-http-test-unit-http1-protocol-framing`
  (`AnHttp11RequestThatIsNotKeptCarriesAConnectionOrAProxyConnectionField`, what the rule relies on, green before and
  after: of 80 requests -- two versions, eight shapes of the two fields, five framings -- every HTTP/1.1 one the
  parser does not keep carries one of the fields, and `HTTP/1.2` is refused `400`). Mutants: the `Connection` field
  not looked up, the `Proxy-Connection` field not looked up, the override keeping nothing, its test run for a request
  that keeps its connection too, the override applied whatever the session's setting -- 5 planted, 5 caught.

- **`close` has precedence over `keep-alive` on every version, and a HTAB after a `Connection` option ends it as a SP
  does (Huly QB-1248).** Two shapes of a message that says `close` kept their connection. An HTTP/1.0 message whose
  `Connection` field names both options -- `keep-alive, close`, in either order, on one field line or on two -- was
  kept: below HTTP/1.1 llhttp's `http_should_keep_alive()` reads its keep-alive flag alone, where `close` has
  precedence when both are present (RFC 9112 §9.3). The parser now reads `keep_alive` false for any message whose
  close flag is set, a request's and a response's, on every version. And an option followed by a HTAB was not read at
  all: llhttp's state after `close`, `keep-alive` or `upgrade` accepted a SP, a comma and the end of the line, and
  took a HTAB for more of the option's name, so `Connection: close<HTAB>` set no close flag -- an HTTP/1.1 connection
  kept, the request pipelined behind it served -- and `Connection: keep-alive<HTAB>` no keep-alive flag: an HTTP/1.0
  connection closed. HTAB is optional whitespace as SP is (RFC 9110 §5.6.3): the vendored llhttp now reads it so, one
  `case` in that state, a local patch recorded in `THIRD-PARTY-NOTICES` beside the earlier ones. `keep-alive` and
  `upgrade` followed by a HTAB are read as such too: an HTTP/1.0 request with `Connection: keep-alive<HTAB>` keeps its
  connection, and a request with `Connection: Upgrade<HTAB>` beside `Upgrade: websocket` is an upgrade -- its
  `upgrade` set --, which the server's WebSocket handshake and the client's check of a `101` read: both accept now
  what they refused. `Proxy-Connection`, which llhttp reads as `Connection`, follows both rules. Nothing changes for
  an option followed by other octets (`close<HTAB>x`, as `close x`, is no `close`), for an HTTP/1.1 message that names
  both options, nor for a message that names one. Cost: one test of the close flag where `keep_alive` is computed, 2
  or 3 instructions for a message that keeps its connection (g++ 16, Apple clang 21; arm64), none for one that does
  not. Witnesses: `qbm-http-test-unit-http1-protocol-framing`
  (`CloseHasPrecedenceAndAnOptionEndsAtTheWhitespaceAfterIt`, 23 rows read as a request and as a response: on the base
  the five HTTP/1.0 rows that name both options, one of them through `Proxy-Connection`, and the four HTTP/1.1 rows
  with a HTAB after `close` read `keep_alive` true, the two HTTP/1.0 rows with a HTAB after `keep-alive` false; the
  twelve controls read as before; and four upgrade requests: with `Upgrade<HTAB>`, alone and after `keep-alive`,
  `upgrade` false on the base, now true; the option alone, and followed by another octet, as before) and
  `qbm-http-test-system-http1-client` (`ARequestThatSaysCloseEndsItsConnectionWhateverElseItsConnectionFieldSays`:
  seven requests, each answered and the request pipelined behind it served on the base, `200 200`, the connection left
  open; now `200`, `Connection: close` and the close; `keep-alive<HTAB>` on HTTP/1.0 read `200` and the close on the
  base, now `200 200`; three controls keep their connection before and after). Mutants: llhttp's verdict taken alone,
  the HTAB not read as whitespace, the HTAB read as a list separator -- 3 planted, 3 caught.

- **A `CONNECT` request that declares content is answered `400` (Huly QB-1248).** A `CONNECT` has no content (RFC 9110
  §9.3.6). Measured on the base: one that named `chunked` was routed at the end of its header section, as a `CONNECT`
  with no content is -- llhttp completes it there, for the tunnel -- and what followed was read as the next request of
  the connection: a request written right behind the header section, where a peer that reads the coding sees a chunked
  body, was served. One that named `gzip, chunked` was answered `501`. One that declared a `Content-Length` had that
  many octets read as its content: `CONNECT a:443` with `Content-Length: 32` and the 32 octets of a `GET /admin`
  behind its header section was one request, answered once, the `GET` swallowed -- where llhttp, and a peer that ends
  a `CONNECT` at its header section, read two. It is the same disagreement on where the message ends, in the other
  direction. Each is now refused at the end of its header section, as every refused framing is: `400` with
  `Connection: close`, then the close, nothing it carried served. A `CONNECT` that declares no content -- no field, or
  a `Content-Length` of 0 -- is routed as before. The check is a comparison of the request's length with 0 and, for a
  length other than 0, of its method: a request with neither framing field pays the first at most. In the compiled
  parser (Apple clang 21 and g++ 16, arm64, `-O3`) such a request runs the instructions it ran; one that declares a
  length other than 0 runs 3 to 7 more, one with a chunked body 3 or 4, once per request. Witnesses:
  `qbm-http-test-unit-http1-protocol-framing` (`ARequestWhoseFramingIsRefusedIsAnswered`, seven `CONNECT` rows: on the
  base the three chunked ones were dispatched at the end of their header section, what followed left in the buffer,
  the fourth answered `501`, and the three that declare a length dispatched with what followed as their content, or
  left waiting for it; the controls: a `CONNECT` with no field, and one with a length of 0, dispatched) and
  `qbm-http-test-system-http1-client` (`AConnectRequestThatDeclaresContentIsAnswered400ThenClosed`: a request right
  behind the header section, three shapes of a chunked body, `gzip, chunked`, and three lengths -- 32 octets that are
  a request, 3 that are not, 1 never sent; on the base `404` or `501` and the request behind the header section
  served, and for a length `404` with what followed swallowed, or no answer; now `400`, `Connection: close` and the
  close, no request served; the controls, a `CONNECT` with no field and one with a length of 0, still routed).
  Mutants: the refusal of a coding removed, the refusal of a length removed, any method refused for a length, a length
  of 0 refused -- 4 planted, 4 caught; a fifth, the method read whatever the parser's type, is equivalent: llhttp
  leaves the method of a response parser at 0.

- **An HTTP/2 connection preface whose target names a resource is answered `400` (Huly QB-1248).** The preface an
  HTTP/2 client sends, `PRI * HTTP/2.0` (RFC 9113 §3.4), is refused at its target, `400`. One whose target names a
  resource -- `PRI /x HTTP/2.0` and the preface's `SM` line -- passes that check, and llhttp stops at the `SM` line,
  before any field, with a code of its own (`HPE_PAUSED_H2_UPGRADE`) that the rule "every malformed request is
  answered `400`" left out with the pauses: the connection closed with no answer. It is no pause the parser resumes
  from, and no request this HTTP/1.1 server reads: `400` with `Connection: close`, then the close, what follows the
  preface dropped, as for `PRI *` (RFC 9112 §2.2). The two pauses still left out never reach the refusal: the header
  section's is no failure, and the parser stops at the end of a message before an upgrade's. Witnesses:
  `qbm-http-test-unit-http1-protocol-framing` (`AnHttp2ClientOverCleartextKeepsItsHttp11Answers`: the preface with a
  target that names a resource, alone and with a request behind it -- no refusal recorded on the base, the protocol
  failed and its input left unread; now one `400`, the input dropped; `PRI *` and `Upgrade: h2c` as before) and
  `qbm-http-test-system-http1-client` (`AnHttp2PrefaceIsAnswered400WhateverItsTarget`: the targets `/x` and `/ping`
  closed with no answer on the base, now `400`, `Connection: close` and the close; `*` answered `400` before and
  after; no request served). Mutants: llhttp's code left out again -- 1 planted, 1 caught; two more, each of the two
  pauses no longer left out, are equivalent: neither reaches the refusal.

- **`chunked` named twice is `400` by the parser's own scan too (Huly QB-1248).** No request qb serves is answered
  differently: llhttp refuses `chunked` named twice in a request, on one field line or on two, before the parser's
  scan of the field is reached -- of 762 shapes of one to three list elements on one or two field lines, the 351 that
  name it twice were each refused by llhttp itself on the base (`HPE_INVALID_TRANSFER_ENCODING`), which the server
  answers `400`. The scan's own verdict for such a list was `501`, the answer to a coding the server does not
  implement before a final `chunked`: read behind an llhttp told to let every coding through
  (`http_set_lenient_transfer_encoding`, which qb never sets), 288 of the 351 got it, the others `400`. The scan now
  counts the `chunked` it reads: named twice is `400` -- applied twice it is no framing (RFC 9112 §6.1) -- and `501`
  stays the answer to another coding before a final `chunked` (§6.1). Witnesses:
  `qbm-http-test-unit-http1-protocol-framing` (`TheParsersOwnScanRefusesChunkedNamedTwiceWith400`, behind the lenient
  llhttp: five shapes `501` on the base, now `400`; the controls `gzip, chunked` on one line and on two `501`,
  `chunked` alone accepted; and two rows more in `ARequestWhoseFramingIsRefusedIsAnswered`, `chunked` on two field
  lines, `400` before and after) and `qbm-http-test-system-http1-client`
  (`ATransferEncodingThatNamesChunkedTwiceIsAnswered400`: on the wire three shapes `400`, two `501`, before and
  after). Mutants: the count ignored, `501` never answered, any list that names `chunked` once accepted -- 3 planted,
  3 caught.

- **Every refusal of the HTTP/1.1 parser keeps the reason it gave (Huly QB-1279).** llhttp keeps the reason a span
  callback sets (the target, a field line, a body piece), but writes its own over the reason of a callback it checks
  itself: `User callback error` after `on_headers_complete`, `` `on_url_complete` callback error ``,
  `` `on_header_value_complete` callback error `` (a trailer field), `` `on_chunk_header` callback error ``. Ten of the
  parser's refusals read as llhttp's through `http_get_error_reason()`: the version, the three `Host` refusals, a
  declared length past the body limit, an unsupported coding, a target that names no resource, a trailer field the
  section must not carry or past the value limit, a chunk past the chunk limit -- readme/15 quoted two of them. The
  parser now keeps the reason it gives (`fail_with_reason()`) and `Parser::parse()` sets it again after llhttp
  returns; `reset()` clears it. The error code is llhttp's, as before (`HPE_USER` from a span callback, the
  callback's own `HPE_CB_*` code otherwise), and so is the status the peer is answered (`refusal_status()`): only the
  reason read locally changes. Witnesses: `qbm-http-test-unit-http1-parse-limits` (each of the ten reasons read back
  after its refusal; a span callback's three kept as before, the controls; a failed parser's next call keeps the
  reason and `reset()` clears it). The restore runs out of line, the result passing through it: kept in line, it held
  a callee-saved register across the call in every message's parse -- +8 to +10 instructions a message on x86-64
  (g++ 14, callgrind) --, now the test of the reason and its branch.

- **The HTTP/2 server's error GOAWAY reaches a client that was still sending, and a server that keeps writing into a
  connection `qb::http2::Client` ended is no longer left blocked (Huly QB-1270, after QB-1060; qb-io's close of a
  connection an endpoint ends).** Two faces of one qb-io defect, fixed in qb (its CHANGELOG has the mechanism). The
  server session disconnects on the GOAWAY it sends with an error and its socket was closed with the client's bytes
  unread, a reset: on Windows a client that was still sending read no GOAWAY at all. The session is still released at
  once and its streams cancelled then; when the frame was written whole its descriptor goes to the loop, which closes
  it after the client. A GOAWAY still queued behind output the client has not taken -- a large response to a slow
  reader -- is dropped with the session, as before: the bound on resources wins over delivery there. And
  `qb::http2::Client`, after `disconnect()` or a GOAWAY of its own, kept its half-closed socket until its next
  connection or its destruction: a server that went on writing blocked once the socket buffers were full (4.2 MB on
  Linux, 180 KB on Windows) and no write ever failed. The client now holds no descriptor after its close and the
  server's writes fail within qb-io's bound. Proven over real TLS sockets by
  `qbm-http-test-system-http2-close-after-peer`:
  `TheErrorGoawayReachesAClientThatWasStillSending` is red on the base on Windows,
  `AServerThatWritesWithoutReadingIntoAConnectionTheClientEndedSeesItsWritesFail` and
  `AnErrorGoawayLeavesThroughTheLoopUntilTheClientCloses` on both systems.
- **The test suite builds with MSVC 19.52 again (Huly QB-1109).** `tests/system/server/tls-operations.cpp` declared a
  class inside a lambda's body and called a member template on a member of it
  (`result->response.body().as<std::string>()`). MSVC 19.52 reads a class local to a lambda's body as a dependent type
  and reports C4864, « expected 'template' keyword before dependent template name », an error under `/WX`: the Windows
  gate stopped building in four presets when its runner's compiler moved from 19.51 to 19.52. The class is declared at
  the test's scope. The cause was isolated on that compiler -- ten minimal reproductions, and the translation unit
  compiled eight ways with its own command line: only the place of the class matters, not the lambda's return type, the
  `shared_ptr`, a generic lambda beside it or the class template behind `Response` -- and the release preset built to
  the end reports no other site.
- **The flood case of `qbm-http-test-system-http2-control-replies` holds on macOS (Huly QB-1270).**
  `AClientThatNeverReadsIsCutOnceAThousandRepliesAreQueued` read the server's verdict -- a thousand replies, then its
  `GOAWAY(ENHANCE_YOUR_CALM)` -- from what the session's output still held when it closed, and took a loopback socket
  that the replies had filled, its client reading nothing, to take nothing more. macOS does not keep it full: a socket
  that refused part of a write takes more a millisecond later, its reader's receive buffer growing whatever `SO_RCVBUF`
  that reader set (measured on GitHub's macOS 26 image, isndev/qbm-http run 43489561448). The write that followed the
  verdict could take the thousand replies and the `GOAWAY`: the session then closed at once with nothing queued, the
  bound kept, and the case read nothing -- red with OpenSSL 4.1.0 and 3.5.9 alike, under ThreadSanitizer in 17 runs of
  30 with each (the PING and SETTINGS floods; runs 43490785398, 43499030693), in Release in 6 floods of 330, every red
  one of that shape (instrumented, runs 43499003035, 43499016623). The client now first asks for a response of 32 MiB
  its connection's buffers never take whole, and reads only its head: every reply waits behind that body on every
  system, and the case reads the rest of it, exactly a thousand replies and the `GOAWAY`. The flood must also end on a
  write the closed connection refuses, within half the session's inactivity timeout, and the client must read no reply.
  Green on that image with both majors: 20 runs of 20 in Release and under ThreadSanitizer. The server is unchanged.

- **A streamed response's trailer section is held to the client's `SETTINGS_MAX_HEADER_LIST_SIZE`, as a buffered
  response's is (Huly QB-86 with Huly QB-1240, a composition fix of the 3.4.0 train 6).** QB-1240 holds the trailer
  section `send_response()` sends to the bound RFC 9113 §6.5.2 counts -- judged before it is encoded, and again when it
  leaves, by the bound then in force -- and the second lot of QB-86, written on a tree without that bound, encoded the
  trailer section of a streamed response (`end()` with `trailers()`) past it. `end_streamed_response()` now refuses a
  section past the bound in force at the end as it refuses a forbidden trailer field (the stream reset with
  `INTERNAL_ERROR`, the context cancelled), and `flush_streamed_response()` judges it again by the bound in force when
  it leaves, before anything is encoded, so the HPACK table stays in step with the client's. Two unit tests of the
  streamed response prove both: a byte past the bound at the end resets the stream and encodes nothing while a section
  at the bound exactly leaves whole, and a bound the client lowers while the body waits for credit refuses the section
  after the DATA, no HEADERS encoded.

- **The HTTP/2 and HTTP/1.1 sessions read their real write-buffer cap, and a streamed HTTP/2 response takes no end
  once its connection is closing (Huly QB-86).** The HTTP/2 protocol bounded a streamed flush by the socket's room
  under qb-io's default cap, and the two sessions' `stream_write_cap()` reported that constant to their response
  streams: a tcp session could neither read its transport's cap nor set another. qb exposes both now on the session
  (`max_write_buffer_size()`, `set_max_write_buffer_size()`), and the protocol and `stream_write_cap()` -- a const
  member now, no longer `static constexpr` -- read the session's cap: a session that lowers it gets flushes that stop
  under it and streams begun after it whose watermarks and admission follow it, where `publish()` would have cut the
  peer (a stream reads the cap when it begins; HTTP/3 keeps qb-io's constant). Over a
  real TLS connection, two streams whose producers wrote 24 KiB each and ended, under a cap lowered to 32 KiB, leave
  whole on one read of two `WINDOW_UPDATE`s; read as qb-io's default the cap would have let both flushes pass it. The
  session's write pass resumes the streams held back for the socket before it consults its producers, which ended
  streams have left -- an order a mutant of the second lot survived on, for want of a way to lower the cap in a
  test, and which this case now holds. `end_streamed_response()` had no guard on a connection that failed: after a `GOAWAY` a producer's `end()`
  still sent its END_STREAM (or its trailer section); it is refused now, as `write()` was. `reset()` forgets that
  streams waited for the socket's room.

- **An HTTP/2 session no longer reads its protocol after a hook cleared it (Huly QB-86, a residual found by QB-1212's
  sanitizer run).** The second lot of QB-86 made the session's write pass and end of stream resume the streams held
  back for the socket through its protocol pointer, which a drain's `POST_RESPONSE_SEND` hook calling
  `clear_protocols()` (the lifecycle suite does) or the io's own disconnect had freed: a heap use-after-free under
  ASan in `Http2ServerLifecycle.DrainPostCanClearTheActiveProtocolBeforeAnotherCandidate`. The session now reads the
  protocol only while the io still runs it (`live_http2_protocol()`), as its other paths already did.

- **Security: the HTTP/2 server's Rapid Reset guard counts the streams a client opened, not its highest stream id, and
  the resets it provokes (Huly QB-1244; CVE-2023-44487, CVE-2025-8671).** The guard closes the connection with
  `GOAWAY(ENHANCE_YOUR_CALM)` once a client has reset more than `MAX_RAPID_RESETS` (100) streams and more than half of
  the streams it opened, and it took the streams opened as the highest client id over two. A client may skip ids (RFC
  9113 §5.1.1): one that opened stream 2^30+1 first, then sent a HEADERS(END_STREAM) and a RST_STREAM on each id after
  it, was counted more than 2^29 streams opened and never tripped the guard -- some 5 x 10^8 requests dispatched then
  cancelled on one connection, the amplification the guard exists to bound. A stream now counts as opened when its
  request is dispatched to the application, whatever the application answers, or when the client cancels it before its
  request is complete (an upload, as before); a stream the protocol layer refuses itself -- answered 413, 414 or 431,
  or malformed -- is none, else a client that sent such a request before each pair would open as many streams as it
  resets; a protocol reset forgets the count. Measured on a client-to-server frame exchange: no `GOAWAY` after 400
  pairs from stream 2^30+1, nor after 400 pairs each behind a malformed request or a `431`; the 101st reset trips it
  now, as for a client that starts at stream 1, and after 300 requests served the 301st (more than half of 300 + r). A
  client that cancels fewer than half of its streams is served as before: 133 of 400 GETs reset, answered later or
  inside the dispatch, or 3 uploads cancelled in every 8 requests. The guard now also counts the resets a client makes
  the server send (MadeYouReset, CVE-2025-8671). DATA or HEADERS after the client's END_STREAM, or a WINDOW_UPDATE
  that takes a stream's window past 2^31-1, on a request dispatched and not yet answered, makes the server reset the
  stream: the concurrency slot is freed as the client's own RST_STREAM would free it, the application's work may go on,
  and the reset was never counted. It counts now as the client's RST_STREAM does; the server's own resets -- a handler
  that throws, a response HTTP/2 cannot carry -- are not the client's and never count. Measured on the same exchange:
  no `GOAWAY` after 400 such pairs for each of the three frames on the base, `GOAWAY(ENHANCE_YOUR_CALM)` at the 101st
  now, and for DATA at the 301st after 300 requests served; 400 requests whose handler throws, 400 answered with a
  field HTTP/2 cannot carry, and a client that sends a WINDOW_UPDATE on each of 400 streams and cancels one in three
  draw no `GOAWAY`. A WINDOW_UPDATE of 0 on a stream already ends the connection (the frame layer refuses it), so a
  client provokes one such reset per connection. The ceiling bounds the share of streams reset, not the work in
  flight: a client that sends a request answered at once beside each one it resets stays at half and is not closed,
  one request cancelled for each one served.

- **The HTTP/2 client holds a request to the server's `SETTINGS_MAX_HEADER_LIST_SIZE` (Huly QB-1274).**
  `ClientHttp2Protocol` stored the bound the server announced and never read it: a request whose header list or
  trailer section passed it left anyway, and a server held to its own bound answered `431` or reset the stream. The
  client judges both now as the server judges a response (Huly QB-1235, QB-1240), counted as RFC 9113 §6.5.2 counts
  it -- each name and value, and 32 octets -- before the block is encoded, so the HPACK table never runs ahead of the
  server's: past it `send_request()` returns `false` with nothing written (`qb::http2::Client` answers the caller
  `503`), and a trailer section is judged again when it is handed to `send_request_trailers()` and when it leaves, by
  the bound then in force -- one whose body waited for credit while the server lowered its bound resets the stream
  with `INTERNAL_ERROR`, the section never sent, and so does one handed over past the bound,
  `send_request_trailers()` returning `false` at once. A request refused before anything is sent -- past the bound,
  or with a trailer section `trailers()` cannot carry (Huly QB-1073) -- gives its stream id back: it stayed spent,
  never on the wire, and a frame the server sent on it was read as one on a closed stream until the next request
  opened a higher id. Read on a client against a 2 KiB bound: a request one octet past it left; it is refused now
  with zero bytes on the socket, the next request takes its stream id, and one of exactly 2048 octets leaves.

- **The HTTP/2 server resets every response it refuses itself with `INTERNAL_ERROR` (Huly QB-1273; the maintainer's
  decision of 2026-11-06).** `send_response()` reset a response carrying a forbidden or an invalid field, an invalid
  or conflicting `content-length`, or a refused trailer section with `PROTOCOL_ERROR` -- which says the client
  violated the protocol -- and one whose body passes `MAX_BODY_SIZE` with `ENHANCE_YOUR_CALM` -- which says it
  generates excessive load. The request was well-formed, and the server met "an unexpected internal error" in the
  application's response (RFC 9113 §7), the reasoning of Huly QB-1241 and QB-1265: all six use `INTERNAL_ERROR` now,
  as a contradicted `content-length` and a list past the client's bound already did. Read by the client off the wire,
  on a client/server pair, one case each: `0x1` (`0xb` for the body) before, `0x2` now; nothing is sent before the
  reset, and the same connection serves the next request.

- **The HTTP/2 server resets a response whose body contradicts its `content-length` with `INTERNAL_ERROR`, not
  `PROTOCOL_ERROR` (Huly QB-1265; the maintainer's decision of 2026-11-03).** `send_response()` reset the stream with
  `PROTOCOL_ERROR`, a protocol error the endpoint detected (RFC 9113 §7); the request was well-formed, and the server met
  "an unexpected internal error" in the application's response. A header list past the client's
  `SETTINGS_MAX_HEADER_LIST_SIZE` already used `INTERNAL_ERROR` (3.3.0 did; Huly QB-1235 moved that check before
  encoding): both now use it, as decided (HTTP/3
  resets the same cases with `H3_REQUEST_CANCELLED`, Huly QB-1241). Read by the client off the wire, on a client/server
  pair: `PROTOCOL_ERROR` for a contradicted `content-length`, `INTERNAL_ERROR` now; nothing is sent before the reset,
  and the same connection serves the next request. The other refusals of an invalid response follow (Huly QB-1273).

- **Security: the HTTP/2 server bounds the resets it sends on closed streams, closes a refused stream's id, frees the
  slot of a handler that throws, and makes a `WINDOW_UPDATE` of 0 and a short `PRIORITY` stream errors (Huly QB-1270;
  CVE-2019-9514 on closed streams).** Each `DATA` or `HEADERS` a client sent on a closed stream -- and a
  `WINDOW_UPDATE` past 2^31-1 on one still resident -- drew a `RST_STREAM`, without a bound: the reset flood of
  CVE-2019-9514, on closed streams. At most `MAX_QUEUED_CONTROL_REPLIES` (1000) are sent now between two streams the
  client opens -- a request dispatched, or one it cancels, both weighed by the Rapid Reset guard; never a frame it
  sends for nothing, as an empty `DATA` -- and past them the connection is closed with `GOAWAY(ENHANCE_YOUR_CALM)`:
  on a client-to-server frame exchange, 1100 `DATA` or `HEADERS` frames on a closed stream drew 1100 resets and no
  `GOAWAY`; the 1001st closes the connection now, even with an empty `DATA` on an open upload after every 999, while
  900 between requests, three times over, are answered for a client that reads them (the resets sent before a request
  is dispatched joined that budget, and a client that reads nothing is held to the count of the replies queued, in the
  two entries below). A stream refused with `REFUSED_STREAM` -- the concurrency limit, a shutdown -- left its
  id idle: a `DATA`, `WINDOW_UPDATE` or `RST_STREAM` the client had sent on it before it saw the refusal closed the
  connection with `GOAWAY(PROTOCOL_ERROR)` (RFC 9113 §5.1.1), and a `HEADERS` on it was refused again or served as
  a new request reusing the id. The id is closed now, each of those a frame on a closed stream, a `GOAWAY` still names the last
  stream accepted, the refusal itself -- a reset the client solicits, unbounded too -- shares the budget, and the
  client's reset of a refused stream counts against the Rapid Reset ceiling. A handler that threw inside the `DATA`
  completing an upload reset its stream and kept it resident, half-closed, holding a concurrency slot until the idle
  sweep (30 s): 50 such uploads refused the 51st stream, which is served now, the stream reclaimed. A `WINDOW_UPDATE`
  of 0 on a stream and a `PRIORITY` that is not 5 octets, an empty one included, are stream errors (RFC 9113 §6.9,
  §6.3), for which the frame layer ended the connection at the first such frame, without a `GOAWAY`: the stream is
  reset now (`PROTOCOL_ERROR`, `FRAME_SIZE_ERROR`) and the connection serves on, the reset counted against the Rapid
  Reset ceiling on a request in flight (the 101st such pair closes the connection) and against the budget on a closed
  stream; on an idle stream, which no `RST_STREAM` may name (§6.4), the connection is closed with a `GOAWAY`, as on
  stream 0. A `PRIORITY` naming its own stream stays ignored: RFC 9113 deprecates priority signals and keeps no
  self-dependency error (§5.3.2; RFC 7540 §5.3.1 had one, which h2spec's RFC 7540 cases still check).

- **Security: the HTTP/2 server bounds the resets it sends before a request is dispatched (Huly QB-1270;
  CVE-2019-9514).** A reset the server sent on a new stream before its request was dispatched -- a
  malformed request or trailer section, a stream error on an upload (a body past or short of its `content-length`, DATA
  over the window, a `WINDOW_UPDATE` of 0, trailers that do not end the stream), a request refused for a limit (413, 414,
  431, then `RST_STREAM(NO_ERROR)`) -- was in no count: the published form of the reset flood, one reset per new stream
  id, 1100 malformed requests drawing 1100 resets and no `GOAWAY`. These resets share the budget of the resets on
  closed streams and of the streams refused: at most `MAX_QUEUED_CONTROL_REPLIES` (1000) between two streams the client
  opens, then `GOAWAY(ENHANCE_YOUR_CALM)`, the 1001st reset left unsent; a client whose requests are refused now and
  then, and that reads the refusals, is never cut, a request served beside each of 2000 refusals keeping the connection
  open (a client that reads nothing is held to the count of the replies queued, in the entry below). A `PRIORITY`
  naming its own stream stays ignored, as RFC 9113 §5.3.2 has it.

- **Security: the HTTP/2 guard of the replies a peer solicits counts those still queued in the output -- PONGs,
  SETTINGS ACKs and resets: a peer that reads nothing is closed at a thousand, one that reads never is by this count
  (Huly QB-1270; CVE-2019-9512, CVE-2019-9515, CVE-2019-9514).** On the server and on the client alike.
  The replies a peer solicits with `PING` and `SETTINGS` frames are exempt from flow control, and the guard bounded them
  at `MAX_QUEUED_CONTROL_REPLIES` (1000) between two frames accepted onto a stream. A `DATA` or `HEADERS` frame the
  server accepted forgave the count, as did a `DATA` or a completed response on the client -- an empty `DATA` after
  every 999 `PING`s held it at zero -- so a peer that read nothing made the replies queue up to the write-buffer cap
  (200 MiB by default): over real TLS sockets a client that read nothing and had a request served after every 999 drew
  every reply it solicited, 64 MiB of them, and was still served. And a connection that only pinged, a keep-alive with
  no request in flight, was closed at its 1001st `PING` whatever it read. The guard now counts what is queued, modelled
  on nghttp2's `max_outbound_ack`: a reply counts from the moment it is written to the session's output until the socket
  has taken its last byte, and once a thousand are queued the next is not written -- the connection is closed with
  `GOAWAY(ENHANCE_YOUR_CALM)`. Nothing the peer sends forgives a queued reply: an octet of a body or a request served
  after every 999 `PING`s no longer does, and neither does a completed response on the client. The output draining
  does: 5000 `PING`s, or `SETTINGS`, each answered before the next, leave the connection open with no stream opened;
  a slow reader with a thousand replies queued is served as long as one leaves for each one it solicits; a reply cut
  by a partial write is forgiven when its last byte has left, not before. On the server the resets a client solicits
  on streams it never opened -- a frame on a closed stream, a stream refused, a request reset or refused before its
  dispatch -- are replies it draws for nothing too, and their budget between two streams the client opens is
  forgiven by a request served: alone, it let a client that read nothing and had a request served after every 999 of
  them queue them without a bound, as the PONGs. They are counted in the same queued count as well, a thousand replies
  of any kind, and they keep that budget, which reading them does not forgive. A peer is closed by the queued count when a thousand of its
  replies wait in the output at once, and only then; two things make them wait. A reply waits behind what the output
  already holds, a large response included. And the replies to the frames of one read are written after that read, so
  a thousand solicited within one read count as queued: a read is one `SSL_read`, one TLS record at most, which holds
  963 `PING`s but 1820 empty `SETTINGS`. nghttp2 differs twice: it forgives an ACK when the frame leaves its queue to
  be serialized, and it sends ACKs ahead of the data it has queued. A peer whose socket takes nothing is not handed
  the `GOAWAY`: the session closes the connection without waiting for it. The position of a reply is read from the
  session's own count of bytes written (`bytes_written()`) and the size of its output, when a reply is solicited and
  nowhere on the write path; a protocol instantiated on an io handler without that count forgives its replies when
  the handler's output is empty. On the client the count holds the PONGs, the SETTINGS ACKs and the resets of
  anything but a request in flight. Each `HEADERS` a server sent on a stream that had closed -- by a completed
  response, by a reset of either side -- drew a `RST_STREAM(STREAM_CLOSED)`, in no count at all: over real TLS sockets a
  server that answered one request, then sent `HEADERS` on that stream and read nothing drew every reset it solicited,
  5 162 832 of them (64 MiB), the client still connected and its next request still waiting. They are replies the
  server draws for nothing -- on a stream the client reset itself, none is drawn since the entry below -- and count with
  the PONGs and the ACKs now: the 1001st queued is not written and the client
  closes the connection with `GOAWAY(ENHANCE_YOUR_CALM)`, the request in flight failing with that reason, while a server
  that reads them -- 3000 in rounds of 500 over the same sockets -- is never cut. The reset of a request in flight, a
  response the client refuses, is not counted: it retires the request, so a server draws one for each request the
  client opens and no more. And a frame on an idle stream is a connection error on the client whatever the stream's
  parity (RFC 9113 §5.1, §5.1.1, §6.4): the client disables push, so a server can reserve no stream and every even id
  stays idle, yet a `HEADERS` or a `DATA` on one was reset and the connection kept -- a 13-octet reply for each -- and
  a `WINDOW_UPDATE` or a `RST_STREAM` there was ignored. Each closes the connection with `GOAWAY(PROTOCOL_ERROR)` now,
  as on an odd id past the client's last request -- the `DATA`, the `WINDOW_UPDATE` and the `RST_STREAM` beside the
  `HEADERS` the maintainer's decision named, which he signed off on 2026-11-11; a `PRIORITY`, which an idle stream may
  receive, stays read and ignored, and a frame the frame layer refuses first -- a `WINDOW_UPDATE` of 0, a `PRIORITY`
  that is not 5 octets -- ends the connection with a `GOAWAY` since the entry below. The client keeps no second budget
  for its resets, as the server does: a server that reads them is held to no number of them, as with its `PING`s.

- **The HTTP/2 client serves on when a response it resets has more frames in flight, sends a GOAWAY for the errors
  its frame layer reports, bounds its log of HEADERS on closed streams and names its own reason once (Huly QB-1270).**
  A server whose response passed what the client accepts on one stream -- a legitimate body past `MAX_BODY_SIZE`, a
  body past its `content-length` -- had that stream reset, and the `DATA` it had already sent behind it closed the connection with
  `GOAWAY(PROTOCOL_ERROR)`: over real TLS sockets a body streamed past 100 MiB on stream 1 failed the request answered
  next on stream 3 with « Server sent GOAWAY: GOAWAY sent by client: DATA for unknown client stream ». The client now
  remembers the streams it reset while the server could still send on them, the last `MAX_RESET_STREAMS_REMEMBERED`
  (1000) -- only its own resets of the streams it holds add to that memory, at most one per request it opens; a frame on
  a stream it does not hold adds nothing -- and discards what the server sent on them before it read the reset (RFC 9113
  §5.1): a `DATA` still counts against the connection window and is given back with the connection `WINDOW_UPDATE`
  (§6.9), and a header block is still decoded, so the HPACK table keeps step (§4.3). The request on stream 3 is answered
  on the same connection, its field named by an index the discarded trailers put in the table. A `HEADERS` on such a
  stream drew a `RST_STREAM`, one more reply the server drew for nothing: it draws none. A frame on a stream the server
  had ended stays an error (of type `STREAM_CLOSED` since the frame-layer GOAWAY entry below). The octets of the frame a stream is reset for count at the reset, so a `WINDOW_UPDATE`
  they make due leaves with it, not with the next `DATA` read. `HEADERS` and `DATA` on stream 0 are connection errors,
  `GOAWAY(PROTOCOL_ERROR)` (§6.1, §6.2): they were taken for frames on a closed stream and the connection kept. A
  `WINDOW_UPDATE` of 0 on a stream and a `PRIORITY` that is not 5 octets are stream errors on the client too (§6.9,
  §6.3), as they are on the server since the first QB-1270 entry above: the stream is reset and the connection serves on
  -- the reset counted as a reply the server draws for nothing on a stream that has closed, the frame ignored on a
  stream the client reset -- and on an idle stream or on stream 0 the connection ends with a `GOAWAY`. Every other
  error the frame layer reports once it has read a frame -- a frame of the wrong size, a padding past its payload, a
  missing `CONTINUATION` -- ends the connection with a `GOAWAY` of the error's code (§5.4.1): each ended it without one,
  the protocol no longer ok() when the frame layer reported the error, and over real sockets a `PING` of 7 octets failed
  the request in flight with « Connection lost (reason: -1) ». Three of the checks the frame layer makes before it
  dispatches a frame -- a frame longer than `SETTINGS_MAX_FRAME_SIZE`, a `SETTINGS`, `PING` or `GOAWAY` on a stream
  other than 0 -- ended the connection without one too, on the client as on the server, until the frame-layer GOAWAY entry below. A `HEADERS` on a closed stream wrote one `WARN`
  line each, without a bound -- 5000 lines for 5000 frames of a server that read its resets: the first is logged, then
  one line each time their count on the connection reaches a power of two, with its stream and the count, 13 lines for
  5000. And a request the client's own `GOAWAY` fails names the client's reason once, « GOAWAY sent by client:
  <reason> », where it read « Server sent GOAWAY: GOAWAY sent by client: <reason> ».

- **Security: the HTTP/2 client and server bound the frames that make no progress and draw no reply (Huly QB-1270;
  CVE-2019-9518).** The maintainer's mandate of 2026-11-11. An empty `DATA` without `END_STREAM`, a `DATA` of padding
  alone, a `HEADERS` of an empty block without `END_STREAM`, a `CONTINUATION` of an empty fragment without
  `END_HEADERS`, a `PRIORITY`, a frame of an unknown type, a `SETTINGS` or `PING` ACK that answers nothing the
  endpoint sent and a `GOAWAY` repeated each cost their receiver a dispatch and draw no reply -- each copy of a `GOAWAY`
  was dispatched again and logged at `WARN` twice, by the protocol and by the stock session or client; so do, on the
  client, every `HEADERS` it discards on a stream it reset, a stream error of the frame layer it ignores there and an
  empty `DATA` with `END_STREAM` there. Unless another count met them first -- on the server an empty `HEADERS` is a malformed
  request, whose reset is counted, and a block takes at most `MAX_CONTINUATION_FRAMES` `CONTINUATION` frames -- a
  peer could send them for as long as it liked. Each now takes a token from a bucket of
  `qb::http2::protocol_limits::NO_PROGRESS_FRAME_BURST` (10000) that regains `NO_PROGRESS_FRAME_RATE` (330) tokens a
  second, on both sides; with none left the connection ends with `GOAWAY(ENHANCE_YOUR_CALM)`, « Excessive frames
  making no progress (flood) ». A `GOAWAY` is dispatched the first time; each after it takes a token, and one that
  changes nothing -- the same last-stream-id, `NO_ERROR` -- is not dispatched again; a `GOAWAY` is logged at `WARN`
  when it carries an error or when its number on the connection is a power of two. It is nghttp2's glitch rate limiter
  (added in 1.67.0 at 1000 and 33, these values since 1.69.0), which of these frames charges at v1.69.0 an empty
  `DATA` without `END_STREAM` on a stream it holds -- a padded one only when nothing follows its Pad Length --, a
  `HEADERS` of an empty block, as a malformed message whose stream it resets, a `PRIORITY`, a frame of an unknown type
  and a `HEADERS` whose header block it ignores, once on the `HEADERS`; the rest is qb's own: an empty `DATA` on a
  stream it does not hold, which nghttp2 ignores before it counts, a `DATA` of padding alone, an empty `CONTINUATION`,
  which nghttp2 bounds otherwise, an ACK that answers nothing, which nghttp2 makes a connection error at once (a `SETTINGS` ACK) or takes for free (a `PING`
  ACK), a `GOAWAY` after the first, which nghttp2 refuses only when it raises its last-stream-id or names the wrong
  parity (qb checks no parity), and on a stream the client reset the empty `DATA` with `END_STREAM` and the stream
  errors, which nghttp2 ignores for free (a `WINDOW_UPDATE` of 0) or makes a connection error on any stream (a
  `PRIORITY` that is not 5 octets). A peer that sends fewer than that rate, beyond the burst, is never cut -- nor is one that sends two or three
  `GOAWAY`s, a graceful notice and the last-stream-id it settles on; elsewhere an empty `DATA` or `HEADERS` that ends
  its stream takes no token, nor does a `WINDOW_UPDATE` or a `RST_STREAM` on a stream that has closed, which RFC 9113
  §5.1 lets cross its end. A `DATA` the client discards on a stream it reset counts against the window that stream had
  left when it was reset, which the client never grows again: past it the server sends what it may not (§6.9.1), a
  connection error of type `FLOW_CONTROL_ERROR`. Only the connection window counted it, given back each time, and a
  server could send `DATA` on a stream the client reset for as long as it liked.

- **Nothing is written after the GOAWAY that ends an HTTP/2 connection, and a GOAWAY that raises its last-stream-id
  is a connection error (Huly QB-1270).** RFC 9113 §5.4.1 has an endpoint close the connection after the `GOAWAY` of a
  connection error. A response the application sent to a request read before it, the trailers of an upload and a
  reset the application asked for were written after it, and so was what an observer of the endpoint's own `GOAWAY`,
  or of the peer's `GOAWAY` of an error, sent while the event was dispatched: the protocol said `ok()` until its
  observers had run. Every frame the client and the server write but that `GOAWAY` now goes through one place that
  refuses it once the connection has ended, and the connection ends before the observers run. A `GOAWAY` whose
  last-stream-id is higher than the peer's last one is a connection error of type `PROTOCOL_ERROR` (RFC 9113 §6.8:
  endpoints MUST NOT increase it), as nghttp2 makes it; it was taken as a new `GOAWAY`.

- **Every connection error the HTTP/2 frame layer finds ends the connection with its GOAWAY, on the server whatever
  stream the frame names; a frame after END_STREAM is STREAM_CLOSED on the client; the server no longer logs its own
  GOAWAY as received (Huly QB-1270).** The maintainer's « Yes, as recommended » of 2026-11-11. Three checks the frame
  layer makes on a frame's header alone, before it dispatches the frame -- a `SETTINGS`, `PING` or `GOAWAY` on a stream
  other than 0, a frame longer than the `SETTINGS_MAX_FRAME_SIZE` the endpoint advertised (RFC 9113 §6.5, §6.7, §6.8,
  §4.2) -- closed the connection without a `GOAWAY`, on the client and on the server: each sends the `GOAWAY` the
  connection error owes now (§5.4.1), its code and the reason as debug data, and a request of `qb::http2::Client`
  such a frame fails reads « GOAWAY sent by client: <reason> », not « Connection lost (reason: -1) ». So does a `DATA`
  or a `HEADERS` of no octet whose `PADDED` or `PRIORITY` flag calls for some, `FRAME_SIZE_ERROR` (§4.2): it was
  dispatched as an empty frame. The server answered a connection error
  the frame layer reports on a stream other than 0 -- a `RST_STREAM` or a `WINDOW_UPDATE` of the wrong size, a padding
  past its payload, a frame where a `CONTINUATION` is due (§6.4, §6.9, §6.1, §6.10) -- with a `RST_STREAM` of that
  stream, an idle one's included, which §6.4 forbids, and closed without a `GOAWAY`: it ends the connection with the
  `GOAWAY` and resets nothing, as the client does; the stream errors the frame layer finds (a `WINDOW_UPDATE` of 0, a
  `PRIORITY` that is not 5 octets) still reset their stream alone. On the client, a frame the server sends on a
  stream it ended gets the code §5.1 names: a `DATA` on a stream that has closed -- its response completed, or the
  server reset it -- ends the connection with `GOAWAY(STREAM_CLOSED)`, the connection error §5.1 permits, not
  `PROTOCOL_ERROR`; in half-closed (remote), a request whose body or trailer section is still on its way, a `HEADERS`
  is reset `STREAM_CLOSED`, the stream error §5.1 requires, not `PROTOCOL_ERROR`, and after a
  trailer section it was not refused at all -- decoded as a second trailer section of a response already delivered --,
  and a `DATA` is reset with its octets counted in the connection window and given back (§6.9): they were left out,
  and the server's view of the window shrank by them for good. The server already answered both so (Huly QB-1058,
  QB-1244). The server session logged the `GOAWAY` its protocol sent as « Received GOAWAY from client ... Debug:
  GOAWAY sent by server: ... »: it logs « Sent GOAWAY to client » for its own now, told by `Http2GoAwayEvent::sent`
  (Added). A request the client's own `GOAWAY` fails still reads « GOAWAY sent by client: <reason> », told by the same
  field: a server's debug data that began with those words read as the client's.

- **The HTTP/2 server holds a promised request and a trailer section to the client's `SETTINGS_MAX_HEADER_LIST_SIZE`,
  as it holds a response's header list (Huly QB-1240).** Since Huly QB-1235 `send_response()` judges a response's list
  against that bound before encoding it -- each name and value, and 32 octets (RFC 9113 §6.5.2); the two other blocks
  the server encodes were sent past it: the promised request of a `PUSH_PROMISE`, and a response's trailer section.
  `send_push_promise()` now refuses a promise past the bound with a new enumerator,
  `PushPromiseFailureReason::PEER_HEADER_LIST_SIZE_EXCEEDED` (appended: the others keep their values, and an
  exhaustive `switch` over the enum needs a case for it), before its stream is reserved and ahead of the one refusal
  that only has to wait, `PEER_CONCURRENCY_LIMIT_REACHED` (Huly QB-1202). A trailer section past the bound refuses the
  response at `send_response()` as a leading block does -- `RST_STREAM(INTERNAL_ERROR)`, `false`, nothing sent -- and
  is judged again when it leaves, by the bound then in force: a body that waited for credit while the client lowered
  its bound is followed by a reset. Neither block is encoded when refused, so the HPACK table stays in step with the
  client's. Measured on a client-to-server frame exchange: under a bound of 233 octets a promise of 234 was sent and
  is refused now, the same id promised at 233 right after with the indexed field the refused one carried, every block
  that follows decoded by the client; under 100 a trailer section of 101 octets was sent after the leading block and
  is refused with nothing sent now, one of 100 leaves and ends its stream.

- **The HTTP/3 server closes a connection that negotiated another application protocol with
  `H3_GENERAL_PROTOCOL_ERROR`, not `H3_REQUEST_CANCELLED` (Huly QB-1267).** `0x010c` is the code of a request stream
  the endpoint cancels (RFC 9114 §8.1), never a connection's. `http3::Server::listen()` offers `h3` alone and qb-io
  closes a handshake that negotiated nothing before the server sees it, so the case is a server whose base endpoint
  `listen()` offers a second protocol. Measured on a loopback with a raw QUIC peer that negotiates `hq-interop`: the
  server closed with `0x010c`, it closes with `0x0101` now; an `h3` peer of the same server is served.

- **The HTTP/3 client sends as many regular fields as a server reads, and holds `:authority` to the value bound (Huly
  QB-1266).** A server of this module reads `MAX_HEADERS_COUNT` (100) regular fields, the pseudo-headers aside, as
  HTTP/1.1 and HTTP/2 count them; `make_request_headers()` counted a request's four pseudo-headers among them and
  `make_response_headers()` a response's `:status`, so the client refused to send a request of 97 to 100 fields that
  the server would serve, and the server a response of 100. Both count the regular fields alone now. `:authority` had
  no bound at all where `:path` and every regular field have one: a request whose host was 300 000 bytes was
  submitted, and a peer's nghttp3 closes the connection past 64 KiB a value, every stream with it. It is held to
  `MAX_HEADER_VALUE_LENGTH`, the bound of the `host` field that may stand for it, and refused before anything is
  queued. Measured on a client/server connection pair: 100 regular fields were refused both ways and are submitted and
  delivered now, 101 refused; an authority of 8193 bytes was submitted and is refused now, one of 8192 served.

- **A moved HTTP/3 `connection` keeps its control stream and what the peer acknowledged of it, and the peer's SETTINGS
  are read through `recv_settings2` from nghttp3 1.14 (Huly QB-1242).** The move constructor took the streams, the
  bindings and a started shutdown, not the control stream's id nor the bytes sent and acknowledged on it: after a
  move, `control_stream_acknowledged()` read their defaults -- every byte of a GOAWAY not yet acknowledged counted as
  acknowledged, so a graceful close could leave before the client had the GOAWAY -- and an acknowledgment of the
  control stream reached nghttp3 as a request stream's, never counted. The servers and clients hold a connection by
  pointer and never move it; a program that moves one is served now. Measured on a client/server connection pair:
  after a move, a GOAWAY with one byte acknowledged read as acknowledged; now it reads so only once its last byte is.
  nghttp3 deprecated `recv_settings` in 1.14 ("New settings will not be notified"); the connection reads
  `SETTINGS_MAX_FIELD_SECTION_SIZE` through `recv_settings2` where it exists, and through `recv_settings` on the
  module's floor, 1.12; `is_drained()` likewise reads `nghttp3_conn_is_drained2` from 1.16 and the deprecated
  `nghttp3_conn_is_drained` below.

- **The HTTP/3 server resets a response it cannot submit with `H3_REQUEST_CANCELLED`, not `H3_MESSAGE_ERROR` (Huly
  QB-1241; the maintainer's decision of 2026-11-03).** `send_response()` reset the stream with `0x010e` when
  `submit_response()` refused the response -- a field a response cannot carry (`te`, Huly QB-1191), a `content-length`
  its body contradicts (Huly QB-234), a section past the client's `SETTINGS_MAX_FIELD_SECTION_SIZE` (Huly QB-1204), a
  name the client's nghttp3 cannot decode (Huly QB-1210): H3_MESSAGE_ERROR tells the client that its own message was
  malformed, and the request was not. RFC 9114 §4.1.1: "When a server abandons a response after partial processing, it
  SHOULD abort its response stream with the error code H3_REQUEST_CANCELLED." Read on the wire by the client over a real
  QUIC loopback, the code was 0x010e for a contradicted `content-length` and for `te`, and is 0x010c now. The module's
  client settles such an exchange as a `502` whatever the code, and the connection serves on.

- **The HTTP/2 server ignores a frame on a pushed stream that has ended, and a client that cancels pushes is no Rapid
  Reset (Huly QB-1239).** A pushed stream is erased once it ends, and a WINDOW_UPDATE or a RST_STREAM the client sent
  on it before it saw the end was judged against the client's own stream ids: an idle stream, `GOAWAY(PROTOCOL_ERROR)`,
  every stream of the connection with it. RFC 9113 §5.1: an endpoint that ends a stream "might receive a WINDOW_UPDATE
  or RST_STREAM frame from its peer in the time before the peer receives and processes the frame that closes the
  stream", and §6.9 "MUST NOT treat this as an error"; a pushed id is idle only above the largest promised (§5.1.1).
  The client's resets of pushed streams counted toward the
  Rapid Reset guard (CVE-2023-44487) whenever their ids sat below its own, so a client cancelling the pushes it did
  not want could close the connection with `ENHANCE_YOUR_CALM`. Since QB-1202 a promised stream that a client's GOAWAY
  or the idle sweep cancels is erased at once, which a crossing reset met the same way.

- **The HTTP/2 server judges a response against the client's `SETTINGS_MAX_HEADER_LIST_SIZE` before it encodes it,
  and counts the list as RFC 9113 §6.5.2 does (Huly QB-1235).** `send_response()` encoded the header block, then
  compared its ENCODED size with the bound and, past it, reset the stream and dropped the block. The HPACK encoder
  indexes fields as it encodes, so a dropped block left the server's dynamic table ahead of the client's: the next
  response carrying the same field sent it indexed in one octet, the client could not decode it, and the connection
  closed with `COMPRESSION_ERROR`, every stream with it (RFC 9113 §4.3). And a list past the bound left whenever its
  Huffman encoding did not. Measured on the base with a client advertising 100: a 235-octet list was reset, the same
  response on the next stream went out referencing an entry the client never saw, and a 137-octet list encoded under
  100 was sent. The list is now summed uncompressed (each name and value, and 32 octets), only when the client
  advertised a bound, and a response past it is refused before anything is encoded -- `RST_STREAM(INTERNAL_ERROR)`,
  `send_response()` returning `false`, as before. A bound of 0, which the old comparison skipped, is a bound too: a
  client advertising it has every response refused.
- **HTTP/3 never sends a field name a peer's nghttp3 cannot decode (Huly QB-1210).** nghttp3's QPACK decoder takes a
  field name of 256 bytes at most and, coded by Huffman, a code of 160 bytes at most (8/5 of it, the most a code can
  expand, is 256); past either it closes the CONNECTION with `H3_INTERNAL_ERROR`, every stream multiplexed on it with
  it. The client sent names up to `MAX_HEADER_NAME_LENGTH` (1024 bytes), and the server too in a response: measured on
  nghttp3 1.18.0, names of `a` (a five-bit code) are served up to 256 bytes, of `n` up to 213, of `x` up to 182, of
  `!` (sent raw, its code longer) up to 256 -- one byte more, and the peer closed the connection, a name of 256 `n`
  included. `detail::sent_field_name_fits()` holds a request, a response and a trailer section to that rule -- a name
  of 160 bytes or less always fits, one past 256 never, one between them unless the QPACK encoder codes it by Huffman
  past 160 -- and refuses the message before anything is submitted, as one past the other field bounds is: the client
  answers the caller `503`, the server resets the stream.
- **HTTP/3: a response carrying `te` is refused, a message past the peer's field-section bound is never sent, a
  response too large is discarded with `H3_REQUEST_CANCELLED`, and the late end of a refused or answered stream no
  longer closes the connection (Huly QB-1204, points 2 to 5).** Measured on the base, the in-process nghttp3 pair:
  - a response carrying `te: trailers` was delivered: nghttp3 (1.18.0) accepts it and so did the client, where RFC
    9114 §4.2 allows `te` in a request alone and §4.1.2 has a client refuse a malformed response; it is refused on its
    stream with `H3_MESSAGE_ERROR`, as the HTTP/2 client refuses it;
  - the peer's `SETTINGS_MAX_FIELD_SECTION_SIZE` was ignored: the client sent a section of 64 KiB and a byte to a
    server advertising 64 KiB (§4.2.2: an implementation "SHOULD NOT send an HTTP message header that exceeds the
    indicated size"). The connection reads the peer's SETTINGS, and `submit_request()` / `submit_response()` refuse a
    header or trailer section past the bound before anything is queued -- the client answers `503`, the server resets
    the stream; the bound is unlimited until the peer's SETTINGS arrive;
  - a request answered `431`, `414` or `413` -- or refused -- before its end arrived kept being read by nghttp3, and a
    `content-length` the end contradicted closed the CONNECTION with `H3_MESSAGE_ERROR` (the QB-1197 residual), in
    the three shapes where the end comes in a later read: its read side is now shut when the stream is refused or
    answered (`nghttp3_conn_shutdown_stream_read`) -- an answer the client cannot take, past its field-section bound,
    falling back to a reset that shuts it too -- and what still arrives is discarded; a response the client discards
    alike. In the read that refused it, a DATA frame -- empty or not -- or a reserved one then the end are still
    judged by nghttp3, as any stream it finds malformed;
  - a response whose field or section passed the client's limits reset its stream with `H3_MESSAGE_ERROR`, the code
    of a malformed message; it is discarded with `H3_REQUEST_CANCELLED`, the code the client's body cap already sent
    (§8.1: "The request or its response ... is cancelled").
- **The HTTP/2 client advertises the header-list bound it enforces, and a response past it fails its request instead of
  closing the connection (Huly QB-1211).** The client's HPACK decoder stops at 1 MiB of decoded list
  (`qb::http2::protocol_limits::MAX_HEADER_LIST_SIZE`), but the client advertised no `SETTINGS_MAX_HEADER_LIST_SIZE`,
  and a response list past it failed the decode: `GOAWAY(COMPRESSION_ERROR)`, every request multiplexed on the
  connection with it -- the client's twin of what QB-1196 fixed on the server. Measured on the base: a response list
  of 1 MiB and 38 octets, and a 4 KiB dynamic-table entry referenced 300 times (4.3 KB of block, 1.2 MiB of list),
  each closed the connection. The client now advertises the bound; a list past it is decoded to the end of its block
  -- the dynamic table kept in step with the server's encoder, RFC 9113 §10.5.1 ("The field block MUST be processed to
  ensure a consistent connection state") -- its fields past the bound dropped, and the response is discarded once the
  fields kept say it is well-formed: `RST_STREAM(ENHANCE_YOUR_CALM)`, the code of the client's other refusals of a
  response too large, and an `Http2StreamErrorEvent` that fails its request; the connection serves the next one. A
  list past 16 times the bound still closes the connection, as on the server.
- **A field a request's `connection` header names never leaves in its trailer section either, on HTTP/2 and HTTP/3
  (Huly QB-1202).** RFC 9110 §7.6.1 has an intermediary remove "any header or trailer field(s)" a `connection` option
  names, and RFC 9113 §8.2.2 and RFC 9114 §4.2 have one translating an HTTP/1.1 message do so. QB-1191 dropped them
  from the header section only: `connection: x-hop` with `x-hop` among the fields the `trailer` header announces, or
  in `trailers()`, sent `x-hop` in the trailer block of both clients, and the announcement the clients compose for
  `trailers()` named it; `ClientHttp2Protocol::send_request_trailers()` sent it too. Each section now leaves without
  it, an announcement does not name it, and whether a request sets its trailer fields is read from the section it
  plans, never from what is left: a section whose every field is nominated still ends the stream, with an empty
  HTTP/2 block or no HTTP/3 trailer section -- a first attempt waited for `send_request_trailers()` for ever (review
  R3 of QB-1191). The same rule now holds behind a body that waited for flow-control credit: a request announcing
  fields it does not set ended its stream there with an empty block as soon as the credit came, under explicit request
  trailers (the protocol's default), and the trailers handed over next were refused; it waits for them, as a request
  whose body fit the windows does.
- **`ServerHttp2Protocol::send_push_promise()` judges what can never succeed before what only has to wait, counts the
  pushed streams the client's limit counts, and a pushed response opens within that limit (Huly QB-1202).** It
  returned `PEER_CONCURRENCY_LIMIT_REACHED` before `INVALID_ASSOCIATED_STREAM` and `INVALID_PROMISED_REQUEST`, so a
  caller retrying on the transient refusal retried a promise that could never be made; that refusal comes last now.
  It counted the reserved streams toward the client's `SETTINGS_MAX_CONCURRENT_STREAMS`, which RFC 9113 §5.1.2
  excludes ("Streams in either of the "reserved" states do not count toward the stream limit"): under a limit of one a
  second promise was refused. A reserved stream counts once its HEADERS open it, and "Endpoints MUST NOT exceed the
  limit set by their peer": `send_response()` on a promised stream sent those HEADERS at once, past a limit the client
  had lowered. A promised response without room now waits, kept, and leaves -- in the order the responses were given
  -- as a pushed stream ends or the client raises its limit (`send_response()` returns `true` for it, `false` for a
  second response on the stream). It is judged first, as any response is: a field HTTP/2 cannot carry, a list past
  the client's `SETTINGS_MAX_HEADER_LIST_SIZE`, refuse it at once; and judged again when it leaves, by the bounds then
  in force. One answered from an observer of the stream whose close makes room waits behind those already waiting.
  One that waits as long as the idle sweep's `max_idle` without progress (`cleanup_idle_streams()`, 30 s by default,
  counted from its answer, then from the connection's DATA its peer takes while the client's limit is above 0, Huly
  QB-1248) is cancelled as a response its peer does not take is. A client's NO_ERROR `GOAWAY` cancels every promised
  stream still reserved, its response waiting or not given yet, one answered from an observer of the GOAWAY included --
  `RST_STREAM(CANCEL)` at or below its last-stream-id, dropped without a frame above it as the pushes it names
  unprocessed are; an error GOAWAY ends every stream without one: its HEADERS would open a stream, and "Receivers of a
  GOAWAY frame MUST NOT open additional streams" (§6.8). A promised stream at or below the last-stream-id was
  answerable after the GOAWAY, and held the graceful close open until it was. A client allowing no pushed stream (a
  limit of zero) still gets `PEER_CONCURRENCY_LIMIT_REACHED`.
- **An HTTP/2 or HTTP/3 request whose `:path` holds a byte from 0x80 up in its query is malformed, as the same target
  is on HTTP/1.1 (Huly QB-1187).** HTTP/1.1 reads a target with llhttp built strict, which refuses such a byte in a
  query as it refuses a control byte (`HPE_INVALID_URL`: `400 Bad Request`, then the connection closes);
  `qb::http::origin::request_uri()`, which composes the HTTP/2 and HTTP/3 request URI, refused there only `#`, a space,
  a control byte and DEL, so `/search?q=` followed by the octets C3 A9 (an e acute in UTF-8, not percent-encoded) was
  answered 400 on one protocol and served on the two others, the raw octets in `query("q")` -- as 3.3.0 served it on
  both. It refuses the byte now, as
  llhttp does: an HTTP/2 client gets `RST_STREAM(PROTOCOL_ERROR)` for that request and an HTTP/3 client its stream
  refused with `H3_MESSAGE_ERROR`, the connection staying open on both, as for any other malformed `:path`. The
  percent-encoded query (`?q=%C3%A9`) is served on every protocol. A `qb::io::uri` built from raw UTF-8 keeps the raw
  octets in its query, and the module's clients send them as they are (the HTTP/1.1 serializer refuses only a space, a
  control byte and DEL): percent-encode them, `qb::io::uri::encode()`, for a qbm-http server or any strict one.
  `OriginTest.EveryProtocolReadsTheSameRequestPath` reads `/a?b<byte>c` for every byte through the HTTP/1.1 parser and
  `request_uri()`: the two agree on all 256 bytes, where they differed on the 128 from 0x80 up.

- **An allocation that fails while the HTTP/1.1 parser stores a message refuses it -- a request is answered `503
  Service Unavailable` -- instead of unwinding through llhttp and terminating the server (Huly QB-1186).** llhttp is C
  and calls the parser's callbacks from its own frames. Storing the target, a field line, a chunk, a trailer field or
  the `Host` value an absolute-form target rewrites (QB-1186's check) allocates, and a `std::bad_alloc` there unwound
  through llhttp -- undefined behaviour -- up to the protocol's `noexcept` `getMessageSize()`, which terminated. Every
  callback llhttp calls is `noexcept` now, and the ones that allocate end in a handler that refuses the message: `503`
  for an allocation failure -- the server cannot take the request now, and a client may send it again (RFC 9110
  §15.6.4) -- and `500` for any other exception, which none of them throws today. The session answers it as it
  answers a request over a limit, with `Connection: close`, and closes the connection if it cannot build the answer; a
  client reading a response closes the connection. Reading the target goes through `qb::io::uri`'s readers, `noexcept`
  as every parse of a uri is: an allocation failure there still terminates, inside qb's code. Test:
  `qbm-http-test-unit-http1-parse-alloc-failure` replaces the global `operator new` and makes each allocation of a
  request's parse and of a response's fail in turn, piece by piece (32 and 28 failures, at least one in every piece
  but the request's end of target and the response's status line): on the base the first failure of each of the nine
  pieces unwinds through llhttp, and the server's `getMessageSize()` terminates; now each refuses the message, the
  server's with 503. The handlers cost the
  whole-buffer parse nothing -- callgrind on g++ 14 -O3, instructions per parse of `qbm-http-bench-http1-parser`:
  `WholeBuffer` 4 250 -> 4 250, 18 447 -> 18 407 and 5 666 -> 5 664 for the three corpora, `Fragmented` 4 901 -> 4 900,
  18 857 -> 18 821 and level -- and the byte-at-a-time parses one or two instructions a callback call, 9 181 -> 9 198,
  46 140 -> 46 249 and 13 011 -> 13 049 (+0.19 to +0.29 %): g++ keeps the data pointer of `on_url` and
  `on_header_field` on the stack across the new exception edges.

- **The HTTP/1.1 client and server write the version of their connection: a request or a response received over HTTP/2
  or HTTP/3 and forwarded goes out as `HTTP/1.1`, not `HTTP/2.0` or `HTTP/3.0` (Huly QB-1186).** The request and
  response serializers wrote the message's `major_version`.`minor_version` on the request line and the status line,
  and a message received over HTTP/2 or HTTP/3 carries 2.0 or 3.0: a request forwarded through the HTTP/1.1 client
  went out as `GET /x HTTP/2.0`, which a qbm-http server answers 505 (above) and which closed the connection under the
  requests queued behind it (502 `Connection lost`), and a response from an HTTP/3 upstream that a handler forwarded
  went out as `HTTP/3.0 200 OK`, which no HTTP/1.1 client parses (the module's own failed with 502 `Connection
  closed`). One rule now writes both lines, `qb::http::detail::http1_version()`: `HTTP/1.0` for a message whose
  version is 1.0, set on purpose, and `HTTP/1.1` for any other -- 2.0, 3.0, 0.9 alike; the message keeps its own
  version, which a handler still reads. Every HTTP/1.x writer goes through those two serializers: the persistent and
  the one-shot client and the redirects they follow, the WebSocket client's upgrade request, the server sessions'
  responses and refusals, a `MessageHead`. The HTTP/2 and HTTP/3 writers send no version. The line costs less too, one
  token where two numbers were formatted: callgrind on g++ 14 -O3, `qbm-http-bench-http1-serialize`, 85 to 137 fewer
  instructions a message in every cell -- a 0-byte fixed-length response 1 589 -> 1 489, a request with no query 989
  -> 898. Tests: `Http1Serialization.AMessageHeadCarriesTheVersionOfItsConnection` (every version, request and
  response, whole and `MessageHead`: 12 failures on the base),
  `Http1ClientTest.AForwardedRequestGoesOutInTheVersionOfTheConnection` (2.0 and 3.0 answered 505 and 502 on the base,
  served as 1.1 now; 1.0 stays 1.0) and `Http1ClientTest.AForwardedResponseGoesOutInTheVersionOfTheConnection`
  (`HTTP/3.0 200 OK` and `HTTP/2.0 200 OK` on the wire on the base, the client 502; `HTTP/1.1` now, 1.0 kept).

- **An HTTP/1.1 server answers `505 HTTP Version Not Supported` to a request whose major version is not 1 -- HTTP/0.9
  and HTTP/2.0, the two others llhttp reads -- instead of serving it as HTTP/1.x (Huly QB-1186).** llhttp reads a
  request line with no version -- `GET /admin` then CRLF -- as HTTP/0.9, and the field lines after it as a header
  section; the parser took it for a request older than HTTP/1.1, which needs no `Host`, so `GET /` or `GET /admin`
  followed by a field line or none, then an empty line, reached its route with no version and no authority. It reads
  `HTTP/2.0` on a request line too, and the server served `GET / HTTP/2.0` carrying a `Host` as an HTTP/1.1 request,
  its body read with HTTP/1.1 framing (one with no `Host` was answered 400); 3.3.0 dispatched all of them, as it
  checked no `Host`. The parser refuses a request whose major version is not 1 once its header section has ended,
  before the `Host` rule and before a body byte, with the status RFC 9110 §15.6.6 gives a major version the server
  does not support; the session answers it with `Connection: close` and closes, as it answers a target that names no
  resource. A client that sends the request line alone and waits, as an HTTP/0.9 client does, gets nothing until it
  ends a header section or the server's timeout closes the connection. qbm-http speaks HTTP/2 over TLS with ALPN only,
  and the two cleartext openings of an HTTP/2 client keep their answers: the prior-knowledge preface (`PRI *
  HTTP/2.0`, RFC 9113 §3.3) is still answered 400, its target `*` refused before its version is read, and an `Upgrade:
  h2c` request is an HTTP/1.1 request, served as one. A request received over HTTP/2 or HTTP/3 carries 2.0 or 3.0, and
  forwarded through the HTTP/1.1 client it goes out in the version of the connection, `HTTP/1.1` (below): nothing to
  set before forwarding it. No test or example sends another version. Tests:
  `Http1ProtocolFraming.AnHttp09RequestIsRefusedWith505` and
  `Http1ProtocolFraming.ARequestLineOfHttp20IsRefusedWith505`, whose requests are each dispatched on their base (the
  HTTP/2.0 one with no `Host` refused 400), and
  `Http1ProtocolFraming.AnHttp2ClientOverCleartextKeepsItsHttp11Answers`, green before and after.

- **A request's URI is the target the client sent: an HTTP/1.1 `//host/path` is a path, a target that is none of the
  four forms is answered 400, and an HTTP/2 or HTTP/3 `:path` or `host` field names no other authority (Huly
  QB-1177).** The HTTP/1.1 server read every request target as a URI reference (RFC 3986 §4.1), where an origin-form
  `//evil.test/transfer` -- an absolute path whose first segment is empty (RFC 9112 §3.2.1) -- names the host
  `evil.test`: `request.uri().host()` was the one the client chose, whatever `Host` said, and the route served was
  `/transfer`. `///x` came out as `/x`, `//u@a/x` gained a userinfo, a CONNECT `example.com:443` was the scheme
  `example.com` and the path `443`, and a target with a byte the parser refuses -- `/a{b}`, `/a^b`, sent raw -- was
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
  over the URL limit 414, and the percent-encoded spelling (`/a%7Bb`) is served (`[`, `]` and `|`, which browsers send
  raw, are path bytes since QB-1187). The HTTP/2 and HTTP/3 servers composed `:scheme://:authority` followed by
  `:path` by hand: on HTTP/2 a `:path` `@evil.test/x` made `evil.test` the host, and on both `OPTIONS *` the host
  `example.test*`.
  `qb::http::origin::request_uri()` composes it for both: `:path` is an absolute path, with no fragment, space,
  control byte or byte from 0x80 up (in the query too, below), or the `*` of an OPTIONS request (its URI is `*`, without an authority, as HTTP/1.1's); `:scheme` a
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
  one slash now. The static files compare their prefix to strip as the router reads the path, its leading slashes
  collapsed: `//static/a.txt`, which the router sends where `/static/a.txt` goes, was passed on by the middleware and
  answered 404, and is served now, what follows the prefix being what `/static/a.txt` leaves (a path that matches as
  it is is not touched; `qbm-http-test-unit-middleware-static-files`, through the router's root and a route group). Tests: the HTTP/1.1 router on the wire (`//a/where/x` reaches `/a/where/*`, `///where/x` keeps its
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

- **A cancelled context whose stream was begun but whose head never left answers a well-formed 503: no body, and none
  of the representation headers that head declared (Huly QB-101).** A buffered stream (HTTP/2, HTTP/3, HTTP/1.0
  without a length, a head with two framings) cancelled before `end()`, or a stream a `PRE_RESPONSE_SEND` hook
  cancelled inside `begin_stream()` -- through `cancel()` or `complete(CANCELLED)` -- kept the `Content-Length` the
  handler had declared with an empty or partial body: on HTTP/1.1 the client waited for bytes that never came and read
  the next answer as them, or the serializer refused the pair and dropped the connection; on HTTP/2 the response was
  malformed. Its 503 now drops `Content-Type`, `Content-Length`, `Transfer-Encoding`, `Content-Encoding`,
  `Content-Range`, `Content-Language`, `Content-Location`, `Content-Disposition`, `ETag`, `Last-Modified`,
  `Cache-Control` and `Expires` with the body, at the first cancellation: what a
  middleware writes after `next()` on the cancelled request is kept, and an answer already decided (a buffered stream
  that ended) is left alone. `qbm-http-test-system-response-stream`, `qbm-http-test-system-http2-client` and
  `qbm-http-test-system-static-files-stream` hold each header, the body, the order against a middleware's own answer
  and the decided answer.

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

- **The HTTP/2 and HTTP/3 fields this module sends follow the rules its servers apply on receipt: a `PUSH_PROMISE`
  promises a `GET` or a `HEAD` with a request's fields, the HTTP/2 client sends no `http2-settings`, and HTTP/3 sends
  `te` only as `trailers`, in a request (Huly QB-1191).** Two HTTP/2 paths built a request header block with rules of
  their own. `send_push_promise` copied the promised request's fields as they were: measured, a promise carried
  `connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`, `http2-settings`, `te: gzip`,
  `content-length` and a `host` naming another authority than `:authority`, a promise the client must treat as malformed
  (RFC 9113 §8.2.2, §8.3.1); a value with a CR failed the whole promise in the HPACK encoder; and a `POST`, a body, a
  trailer section, any even stream id (a smaller, a reused one, one past 2^31-1), a push on a pushed stream and a push
  after a `GOAWAY` were promised (§8.4, §5.1.1, §6.8). The client's own list lacked `http2-settings`, which a qbm-http
  server answers with `RST_STREAM(PROTOCOL_ERROR)`, and it sent any list of `trailers` as `te` and the fields a
  `connection` header names. Both now build the block with `append_sent_request_fields()`:
  `HeaderValidator::is_sent_request_field()` -- no connection-specific field, `te` only as the one value `trailers`, no
  `host` (`:authority` names the authority), no `content-length` but the one the client writes from the body, no field
  HTTP/2 cannot carry -- less the fields the `connection` header names (RFC 9110 §7.6.1; `te` excepted); a field that
  fails is dropped, as an intermediary translating an HTTP/1.1 message drops it. A promise is refused before a stream is
  reserved: another method than `GET` or `HEAD`, a body, `trailers()` or a `trailer` header
  (`INVALID_PROMISED_REQUEST`), an id not above every one promised before or past 2^31-1 (`INVALID_PROMISED_STREAM`), a
  stream the client did not open (`INVALID_ASSOCIATED_STREAM`), any push once a `GOAWAY` was received or sent, the
  shutdown notice included (`CONNECTION_INACTIVE`). The names were lowercase already: the headers map stores them
  folded. On HTTP/3, `submit_request()` sent any `te` -- `te: gzip` made the peer's nghttp3 close the whole connection
  (`H3_MESSAGE_ERROR`) -- and `submit_response()` sent one: a request now carries `te` only as `trailers` (any case, as
  nghttp3 judges it), a response never, else the message is refused before anything is queued, as for the other
  connection-specific fields. A field the `connection` header names still leaves in a request's trailer section (Huly
  QB-1202). Push stays off by default. The client's field loop no longer copies and folds every name: a browser's
  request through the HTTP/2 client measured 2.4 % faster, A/B against the base. HTTP/3's `te` test costs a response's
  field block 1.5 % to 2.6 % (at most 17 ns) in a micro-benchmark; a whole HTTP/3 request served is within the noise
  (-0.2 %). Tests: the client's emitted block for each left-out field, each request then served by a qbm-http server;
  the push's emitted fields; every refused promise and the ordering of promised ids; HTTP/3 `te` on both sides, and on a
  direct client/server pair the connection kept.

- **A malformed HTTP/2 or HTTP/3 request beside the request limits stays a stream error: a `content-length` that its
  body contradicts, a `content-length` over a limit, a field a section must not carry over a limit are no longer
  answered `431`, `414` or `413` (Huly QB-1197).** QB-94's rule -- a request over the limits is answered once it is
  known well-formed -- still had exceptions. Measured on the base: a `HEADERS` that ends the stream with
  `content-length: 5` beside a field over the value, name or count limit, or a `:path` over the target limit, in either
  order, was answered `431` or `414` on both servers (HTTP/2 judged the length after those answers; HTTP/3 at the
  stream's end, after them, and nghttp3 then closed the connection for the mismatch), and on HTTP/3 a `content-length`
  over the body cap on such a stream `413`; a `content-length` that was itself over a limit was not read (HTTP/2 skipped
  its parse, so one that is no number or contradicts another, past the count, got `431`; HTTP/3 dropped it); on HTTP/3 a
  trailer section over the limits was answered `431` before the body was checked against `content-length`, and a field a
  trailer section must not carry (`host`, `te`, the proxy authentication fields, `trailer`, `http2-settings`) -- or, in
  the header section, one this module refuses beyond nghttp3 (`proxy-authorization`, `proxy-authenticate`) -- over the
  value or name limit or past the count was dropped unread and the request answered `431`; on HTTP/2 a DATA frame past
  `content-length` and the body limit was answered `413`. Now HTTP/2 parses and compares `content-length` before the
  limits, refuses a block that ends the stream with a `content-length` its empty body contradicts before `414`, `431`
  and `413`, and refuses a DATA frame past `content-length` before the body limit, giving its connection credit back;
  HTTP/3 judges a field over the limits by the rules that need no other field before dropping it, keeps one
  `content-length` over the limits as it keeps the first `host` (nghttp3 refuses a second itself), and checks the body
  against `content-length` before any answer when the stream ends with its header section or with a trailer section, on
  both roles (HEAD and 304 exempt). nghttp3 still closes the connection for such a mismatch; the stream is refused first
  and nothing is answered. A request whose body may still come is no known malformation and is answered as before -- on
  HTTP/3 too when the stream's end arrives in a later read than its header section (Huly QB-1204). Measured with QB-1191
  and QB-1196, A/B against the base: a browser's request served within the noise over HTTP/2 (+0.03 %, -0.46 % with a
  `host` field) and over HTTP/3 (-0.2 %). Tests: each shape beside each limit in both orders and over `CONTINUATION`,
  the `content-length` itself over the value or name limit or past the count, the trailer-section mismatch, the DATA
  overrun and its `WINDOW_UPDATE`, the well-formed controls answered `431`.

- **An HTTP/3 field section is bounded by the size the connection advertises, 1 MiB since Huly QB-1203 -- nghttp3 does
  not enforce `max_field_section_size` -- and a request whose section passes it is answered `431` (Huly QB-1196).**
  nghttp3.h (1.18.0) says it does not, while `llm.api`, readme 19 and a test comment said a larger section was a
  connection error. Measured: sections of 72 KiB, 160 KiB and 800 KiB, every field within the request limits, reached
  the server, and a 120 KB response section the client, whose informational (1xx) responses also added their fields to
  the final response's. nghttp3 bounds one field -- a name at 256 bytes, a value at 64 KiB, by the length they decode
  to, a Huffman-coded string at 8/5 of its encoded length (46811 bytes of `v` pass, 46812 do not) -- a connection error
  with `H3_INTERNAL_ERROR`. The connection now counts every section as RFC 9114 §4.2.2 does -- each field's name and
  value and 32 bytes, pseudo-headers included -- against `detail::max_field_section_size`, the value its SETTINGS carry:
  past it a field is over the limits (judged, then dropped, the first `host` and one `content-length` kept), a
  pseudo-header is kept, a request is answered `431` once known well-formed and a response's stream refused. Each
  section -- a trailer section, an informational response's -- is counted on its own, and a 1xx response's fields go
  with it. The bound is 1 MiB, the entry under Changed (Huly QB-1203: it was 64 KiB, fixed beside request limits a
  server sets). Measured with QB-1191 and QB-1197, A/B against the base: an HTTP/3 request's field block +0.3 % (the
  copies spread 1.6 %), a browser's request served -0.2 %. Tests (at 1 MiB since QB-1203): exactly the bound served, a
  byte more answered `431`, a pseudo-header's bytes counted; a trailer section at and past it; each malformed shape past
  it refused, each well-formed one answered; a response, its trailer section and an interim section past the client's
  limits; three 103s and a 200 delivering the 200's fields alone.

- **An HTTP/3 header section may carry `proxy-authorization` and `proxy-authenticate`, as an HTTP/2 one does (Huly
  QB-1197).** `detail::is_forbidden_h3_header()` counted them among the connection-specific fields, which RFC 9114
  §4.2 does not, and nghttp3 lets them through: a request carrying `proxy-authorization` had its stream refused with
  `H3_MESSAGE_ERROR` (over the request limits too, where it is now answered `431`), the client refused to submit it,
  and the server a `407` carrying `proxy-authenticate`. HTTP/2 served all three. A trailer section still may not carry
  them (`is_forbidden_trailer_field`). Tests: a request through the client and one built on the wire served with the
  field, the `407` delivered with its challenge, the connection kept; over each request limit, answered `431`.

- **An HTTP/3 request leaves with the fields an HTTP/2 one leaves with: a field the server would refuse is dropped,
  not the request (Huly QB-1191).** The HTTP/2 client builds a request's fields with
  `HeaderValidator::is_sent_request_field()` less the fields its `connection` header names, and drops what fails; the
  HTTP/3 client refused the whole request instead -- failed locally with `503` -- for a `connection: keep-alive` or a
  `te: gzip` copied from an HTTP/1.1 message, a field HTTP/3 cannot carry (a CR in a value, a pseudo-header name), a
  field its `connection` header names was sent, and a declared `content-length` was sent as it was, a request whose
  body contradicted it refused. `submit_request()` (`detail::make_request_headers()`) now applies the HTTP/2 client's
  rule (RFC 9114 §4.2, RFC 9113 §8.2.2) and writes the body's `content-length`, a declared one left out, as the HTTP/2
  client does; a field past `MAX_HEADER_NAME_LENGTH` or `MAX_HEADER_VALUE_LENGTH`, or more than `MAX_HEADERS_COUNT`,
  still refuses the request (a peer's nghttp3 takes a field past its own bound for a connection error). Since then a
  field HTTP/1.1 cannot write, one past its length bound included, refuses the request on the three clients, `400`,
  naming it, rather than being dropped (the entry under Changed); more than `MAX_HEADERS_COUNT` is still `503`.
  Responses are unchanged: a connection-specific field, a `te` or an invalid field refuses one on both protocols.
  Tests: each left-out field and each field a `connection` header names, through the field block, the direct
  client/server pair and the loopback client, the request served without it; the body's length over a contradicting
  declared one and one with whitespace around it; a field past the bounds refused.

- **A field value that starts or ends with SP or HTAB is malformed on HTTP/2 and never sent on HTTP/2 or HTTP/3
  (Huly QB-1191).** RFC 9113 §8.2.1 makes such a value malformed, and RFC 9114 §4.2 holds an HTTP/3 one to RFC 9110
  §5.5's field-content, whose first and last octets are visible; nghttp2 resets the stream that carries one. The
  HTTP/2 server accepted it in a request's header or trailer section, the HTTP/2 client in a response's, and both
  clients and both servers sent it. `HeaderValidator::is_valid_header_value()` and HTTP/3's
  `detail::is_valid_header_field()` / `is_valid_incoming_header_field()` now refuse it: received over HTTP/2, the
  stream is reset `PROTOCOL_ERROR`, the connection kept; sent, a response is refused, and a request's value now
  leaves without the SP and HTAB at its edges (the entry under Changed: it left without the field). Received over
  HTTP/3, nghttp3 (1.18.0) removes such a field before this module sees it, the message delivered without it; the
  module's own check holds for a nghttp3 that delivers one. HTTP/1.1 is unchanged: the parser reads a field value
  without the OWS around it (RFC 9112 §5). Whitespace inside a value is part of it. Tests: every edge shape on the
  HTTP/2 server's header and trailer sections, the next stream served; the HTTP/2 client's request and the response
  it receives; each server's response and trailer section refused; the HTTP/3 field block, and a raw HTTP/3 request
  served without the field.

- **The HTTP/2 server advertises the header-list bound it enforces, and a request past it is answered `431` on its
  stream instead of closing the connection (Huly QB-1196).** The server's HPACK decoder stops at 1 MiB of decoded list
  (`qb::http2::protocol_limits::MAX_HEADER_LIST_SIZE`, RFC 9113 §6.5.2's count) but the server advertised the
  unlimited default for `SETTINGS_MAX_HEADER_LIST_SIZE`, and a list past the bound failed the decode: `GOAWAY
  (COMPRESSION_ERROR)`, every stream multiplexed on the connection with it -- HTTP/3's twin of QB-1196. Measured on the
  base: a list of 1 MiB + 1 octet of Huffman-coded fields within the encoded block cap, and a 4 KiB dynamic-table entry
  referenced 300 times from 4.3 KB of block (1.2 MiB of list), each closed the connection. The server now advertises 1
  MiB, and `hpack::Decoder` gains a `decode()` overload that decodes such a block to its end -- the dynamic table kept
  in step with the client's encoder, as RFC 9113 §10.5.1 asks -- drops the fields past the bound without copying them,
  and reports it; the request is answered `431` once the fields kept say it is well-formed, its stream alone. A block
  whose list passes 16 times the bound (`hpack::HPACK_DISCARDED_LIST_FACTOR`) still closes the connection: decoding a
  1 MiB block of literals that index a large table name to its end would copy up to ~2 GiB. A refused HEADERS block
  (a closed or reset stream, over the concurrency cap) is decoded the same way. The client is unchanged. Tests: the
  advertised value; a list of exactly 1 MiB served, one octet more answered `431` and the next stream served with a
  field the refused block indexed past the bound; the amplification shape answered `431`, its table entries in step;
  20 MiB of references closing the connection. The decoder's indexed fields were then built as two temporaries moved
  into the vector (`std::string(name), std::string(value)`), the two literal arms through a conditional expression that
  materialised a third: g++ 14 read a browser's request (`qbm-http-bench-http2-server-request`, 18 fields, 15 of them
  indexed) +6.7 % (+270 ns) with 435 FEWER instructions, in two alignment families (an i9-12900K, 3 copies a side,
  seeded order) -- the exact-length buffers fell into a glibc bin the request's own `malloc_consolidate()` empties,
  fifteen allocations a request past the tcache (`_int_malloc` +205 instructions a request, callgrind). A kept field is
  now written into the vector from the two views, name then value, and the literal name moves straight in: g++ reads
  the request 4 % FASTER than the train before this fix, in both alignment families (0.957 [0.944, 0.968] and 0.952
  [0.940, 0.973] with `host`, 0.959 / 0.961 under `-falign-functions=64`; the temporaries alone 1.067 / 1.042), MSVC 19.51,
  whose allocator never had the bin walk, reads it where it read the temporaries (0.973 / 0.970 against the train, 0.974 /
  0.977 before). No behaviour changes.

- **The HTTP/2 server's response fields, the HTTP/2 client's response parse and HTTP/3's field paths no longer copy
  and fold each field name (Huly QB-1191).** QB-1191 removed the copy from the HTTP/2 client's request loop only; the
  server's response loop still copied and folded every name before the field's own copy, the client's response parse
  copied and folded it with `::tolower` after validating it lowercase, and HTTP/3 copied a name twice to send it and
  once to receive it (`detail::is_forbidden_h3_header()` folded a copy on every call) -- an allocation for every name
  past 15 octets. The headers map stores names folded, HTTP/2 validates a received name lowercase and nghttp3 refuses
  an uppercase one, so each path reads the name it has; `is_forbidden_h3_header()` compares in place, by length then
  without regard to case, and is `noexcept`; `detail::lower_header_name()` is gone. Measured with callgrind on a
  micro-loop (a response of eight typical fields, three names past 15 octets; twelve request names), instructions
  per operation before and after: `make_response_headers()` 14,015 to 9,188 (-34 %), twelve
  `is_forbidden_h3_header()` calls 2,672 to 225, the HTTP/2 server's `send_response()` -4,715 and the HTTP/2 client's
  response receipt -2,681 per response. No behaviour changes.

- **The HTTP/3 server sends a response's `host` field, as HTTP/1.1 and HTTP/2 send it (Huly QB-1189).** QB-1189 made
  the HTTP/2 server send it -- `host` is no connection-specific field (RFC 9113 §8.2.2, RFC 9114 §4.2) and a response
  names no authority -- while HTTP/3's `detail::add_regular_headers()` dropped every `host` it would send, a request's
  and a response's alike. A response's is sent now, and the HTTP/3 client delivers it; a request's is still left out
  (`:authority` names the authority). Tests: the response field block, and a response through the direct
  client/server pair.

- **An HTTP/3 request's `host` and `content-length` over the request limits are judged as they arrive and no longer kept
  (Huly QB-1196).** To judge them at the end of the section, the server kept the first `host` field and one
  `content-length` over the limits whole -- nghttp3 caps a value at 64 KiB, so 64 KiB of zeros was a `content-length`
  it let through -- for as long as the stream lived, the request answered `431`: measured, a request of 60 KB of
  `host` and 60 KB of zeros of `content-length` grew the heap by 310 KB until the client closed its stream. A `host`
  is now judged when it arrives -- against `:authority`, which precedes every regular field, or as an authority without
  it (`qb::http::origin::is_request_authority()`) -- and counted; a `content-length` is parsed and its number kept;
  neither field is kept (under 32 KB for the same request). The verdicts are unchanged: well-formed, the request is
  answered `431`; a `host` naming another authority, no authority, a second `host`, a `content-length` that is no
  number or that the body contradicts, refuse the stream. Tests: the heap the stream keeps (glibc builds without a
  sanitizer), and the verdicts at receipt.

- **HTTP/2 and HTTP/3 refuse a CONNECT request, either shape (Huly QB-1177).** CONNECT names a tunnel by `:authority`
  alone (RFC 9113 §8.5, RFC 9114 §4.4), and neither server opens one. A CONNECT carrying `:scheme` and `:path`, which
  RFC 9113 §8.5 makes malformed, reached the HTTP/2 router as a CONNECT on an ordinary path, and so did a `connect` in
  any case on HTTP/2 and HTTP/3 -- the method table reads methods without regard to case, and nghttp3 matches
  `CONNECT` in capitals only. Both are now a stream error (`RST_STREAM(PROTOCOL_ERROR)`, `H3_MESSAGE_ERROR`), as a
  CONNECT without `:scheme` and `:path` already was; nghttp3 still closes the connection for an uppercase `CONNECT`
  carrying them. HTTP/1.1 is unchanged: it routes an authority-form CONNECT. Tests: each shape on HTTP/2, the next
  stream served; on the direct HTTP/3 pair, `connect` and a CONNECT without `:scheme` and `:path` refused, the
  connection serving on, and nghttp3's own verdict.

- **Documented: on HTTP/3 a `host` field nghttp3 finds invalid is removed before qbm-http sees it, so a request carrying
  `:authority: example.test` and `host: user@evil.test` is served, with no `Host` (Huly QB-1195).** nghttp3 (1.18.0)
  removes a `host` holding a byte outside its authority table -- `@`, a space, `/`, `?`, `#`, a control byte, ... --
  and calls no hook for it; `llm.md` and readme 19 said such a field refused the stream, as it does on HTTP/2. Beside
  `:authority`, the request is served with `:authority`'s authority and no `Host`; of two `host` fields without
  `:authority`, the one nghttp3 keeps names the authority; alone, the request has no authority and nghttp3 refuses it.
  A test pins the first two, so that a nghttp3 that delivers the field shows (qbm-http would then refuse both).

- **A request path may hold `[`, `]` and `|` as browsers send them, on HTTP/1.1, HTTP/2 and HTTP/3, and the router and
  the static files take each for its percent-encoding (Huly QB-1187).** RFC 3986 forbids the three in a path, and the
  WHATWG URL Standard's path percent-encode set leaves them unencoded (§1.3 of the Living Standard of 19 October 2026),
  so a browser follows `/search/a|b` or `/doc/[1]` as it is -- measured on macOS with a capture server, one `<img>` per
  printable octet: WebKit (Safari 26.6.2) and Node 24's `fetch` send all three raw, Chrome 156 `[` and `]` (it encodes
  `|`); `^`, which the standard percent-encodes since whatwg/url#846 (2025), none; curl 8.7.1 sends every octet as
  typed. Since QB-1177 such a request was answered 400 on HTTP/1.1 (3.3.0 dispatched it to the route of `/`, QB-1177's
  measurement) and refused as malformed on HTTP/2 and HTTP/3. Every protocol now reads the path with
  `qb::io::is_request_path_character()` -- RFC 3986's path bytes and these three -- through `qb::io::uri::origin_form()`
  and the new `qb::io::uri::absolute_form()`: `qb::http::origin::request_target_uri()` reads an HTTP/1.1 absolute-form
  target with it, and `qb::http::origin::request_uri()` the text it composes from `:scheme`, `:authority` and `:path`;
  llhttp passes the three. No other octet is accepted: `\`, which a browser turns into `/` and Windows takes for a
  separator, `^`, a space, a control, `"`, `<`, `>`, `` ` ``, `{`, `}` and a byte past 0x7F are still refused --
  answered 400 on HTTP/1.1, where a space or LF ends the request line and the connection closes unanswered, a stream
  error on HTTP/2 and HTTP/3 --, and a URI a client builds is still read as an RFC 3986 reference
  (`qb::io::uri("http://h/a|b")` stays invalid). `qb::http::utility::decode_raw_path_octets()` gives the spelling the
  router and the static files compare: `%5B`, `%5D` and `%7C`, in either case of hex digit, decoded, every other byte
  and escape kept (`%2F` stays inside its segment, `%257C` is `%7C` once decoded, never `|`). The router reads a request
  path and each static segment of a route pattern so -- `/a|b` and `/a%7Cb` reach the route registered as either, the
  405 answer included, a capture's name is kept as written, `route_pattern()` reports the decoded spelling --, and the
  static files compare the prefix to strip so on both sides (the rest of a path was already decoded whole before it
  named a file). `uri().path()` keeps what the client sent. The per-request cost, A/B against `2b2a55a` and qb
  `a904abf6`, each side linked to its own libraries (3 copies of each binary, a seeded order, 8 rounds, a quiet host
  under the shared marker, macOS arm64): `BM_Http1Parse_WholeBuffer` corpus 0, 1 and 2 253.5 to 248.4 ns (-2.0 %, the
  gated cell), 1019.5 to 1012.0 and 335.5 to 335.3; `BM_Http2Server_BrowserGet` 3387.8 to 3415.4 (+0.8 %), with a `host`
  field 3512.9 to 3507.2 (-0.2 %); `BM_Route_*/routes:16` over two sessions, a static hit +0.4 % and +0.1 %, a parameter
  hit +0.7 % and +0.9 %, a 404 +3.5 % and +2.3 % (1103 to 1142 ns) -- one memchr of the path in `match()`, and again in
  `allowed_methods()` on a miss, which a component bench of the same router does not tell from noise (-2.7 % on a 404,
  +0.4 % on a hit). On MSVC 19.51 that memchr was `__std_find_trivial_1` behind a call, with a `std::string` whose buffer
  put a security cookie on every `match()`: +8..11 ns on a static hit and +15..25 ns on a 404 (an i9-12900K, six placements
  a side relinked from the frozen objects, 3 copies each). `match()` now notices a `%` in the one pass over the bytes the
  split already makes and decodes out of line only then (`match_decoded()`): MSVC reads the pre-QB-1187 figures again on the
  six cells (fix / before 0.976-0.992, the pre-QB-1187 train 0.980-0.988, 48 launches in a seeded order), g++ 14 level on
  all six (0.997-1.009); `allowed_methods()`, the 405 answer, keeps its decode. qb reads a target's path from a table now: `request_target_uri("/health")` 24.8 to 22.0 ns,
  `request_uri()` 211.7 to 202.4. Tests: for each of the 256 bytes, the HTTP/1.1 origin-form and absolute-form readers
  and the HTTP/2-HTTP/3 one accept a path together or refuse it together, against a written-out set, and the HTTP/1.1
  protocol dispatches it with its path as sent or answers 400 (a space and LF end the line); the three raw on each
  server, over TCP through the router, and fragmented across two reads; the router (static, encoded pattern, parameter,
  wildcard, 405, `%25`, `%2F`, capture names) and the static files (each spelling of `[x].txt` and `a|b.txt`, a prefix
  written with either spelling); every escape of the decoder, in both cases of hex digit.

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

- **`router-error-handling` no longer hangs under TSan on macOS: its invalid-JSON case asserts the 500 in its own
  process instead of a death test (7 hangs in 2,000 runs before, 0 after; Huly QB-1193).** The death test forked
  while qb's log writer -- a thread qb starts before `main()` -- formatted the lines the binary's earlier routed
  requests had queued, and TSan's fork handler deadlocks against libSystem's there: it takes its slot locks, then
  `libSystem_atfork_prepare` waits for a lock the writer took while formatting a timestamp (the locale lock
  `strftime` and `snprintf` take, or an Objective-C runtime lock in the first `gmtime()`), while the writer waits for
  a slot lock. Sampled in every hang: the parent alone, blocked inside `fork()`. 2,000 lines queued before the fork
  hung 13 runs in 200, the same lines drained first none. The assertions are the old child's; the guarantee that a
  JSON serialization error propagates instead of terminating keeps its death test in `body-codec`, whose binary
  logs nothing. Test only.
- **A completion delivered after the thread's loop is destroyed is dropped (Huly QB-1246).** The two coroutine
  completions of `qbm/http/coro.h` -- the slot of `ws` `receive()` / `close_async()` and of the redirecting client,
  and the awaiter of `connect()` / `push_request()` -- resumed their coroutine through
  `coro_scheduler().schedule_resume()`. Called from the destructor of an object with static storage, after the main
  thread's `listener::current`, that built a scheduler inside the destroyed listener; with qb's new door it would
  have stopped the process instead. They go through `qb::io::async::resume_via_current()`: queued on the thread's
  current scheduler while the loop lives -- the rule of qb-io's own wakers; it was the thread's listener's
  scheduler, which is the same one on a core -- and dropped once it is gone. Requires the qb of the same train.

### Removed

- **`qb::protocol::http2::HeaderValidator::validate_request_pseudo_headers()` (Huly QB-1195).** No source called it --
  the HTTP/2 server checks a request's pseudo-headers in its own pass over the decoded fields -- and it accepted what
  the server refuses: any `host` field, compared with nothing and read as no authority. It was in no documented API
  (`llm/qbm-http.llm.api.md`); keeping it would have meant a second rule to hold in step, and calling it from the server
  a second pass over every request's fields. Its cases -- each pseudo-header once and not empty, an unknown one -- are
  now asserted on the server itself. `validate_response_pseudo_headers()`, which the client calls, stays.

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

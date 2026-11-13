# Advanced topics: streaming, connection lifecycle, performance, actor composition

> **Audience:** Adopter · **Status:** stable · **Verified-against:** qbm-http @ qb 3.3.0 (C++20 default, C++23 supported)

How qbm-http handles chunked bodies, persistent connections and protocol upgrades, where the performance levers are, and how an HTTP server composes with the rest of your qb actor system.

**Prerequisites:** [An HTTP server is an actor](./00-http-in-an-actor.md), [Core HTTP concepts](./01-core-concepts.md), [The request context](./10-request-context.md), the qb framework [`readme/`](https://github.com/isndev/qb/tree/main/readme/) (actors, `qb-io` async). — **See also:** [HTTP message body deep dive](./02-body-deep-dive.md), [Custom middleware](./09-custom-middleware.md), [HTTP/2 protocol specifics](./17-http2-protocol.md), [WebSocket](./20-websocket.md).

## Summary

This page is the meeting point of several earlier ones. It covers four things the day-to-day guides only touch: how the body is framed on the wire (chunked transfer encoding, and what "streaming" does and does not mean here), how a connection persists or upgrades across requests (keep-alive, pipelining, the WebSocket handoff), the performance characteristics worth knowing before you tune anything, and how an HTTP server sits inside the actor model alongside your other actors. Every claim is grounded in the shipped headers — `qbm/http/src/qbm/http/1.1/http.h`, `qbm/http/src/qbm/http/chunk.h`, `qbm/http/src/qbm/http/body.h`, `qbm/http/src/qbm/http/response.cpp`, and `qbm/http/src/qbm/http/routing/context.h`.

The body is a `qb::allocator::pipe<char>` (see [Body deep dive](./02-body-deep-dive.md)), the connection is a qb-io session, and the server is an actor mixin. The advanced behavior falls out of composing those three primitives correctly, with one exception made a call of its own: a body delivered while it is produced is begun on the context with `ctx->begin_stream()` and written through the stream it returns.

## Chunked transfer encoding and what "streaming" means

`qb::http::Chunk` (`qbm/http/src/qbm/http/chunk.h`) is a non-owning `{const char* data, std::size_t size}` view of one chunked-transfer-encoding segment. A default-constructed `Chunk{}` (size 0) is the terminating chunk that ends the stream.

```cpp
// src: qbm/http/src/qbm/http/chunk.h:42-80
qb::http::Chunk seg(buffer.data(), buffer.size());  // one chunk, non-owning
qb::http::Chunk last;                                // size 0 -> end of stream
```

Because `Chunk` does not own its bytes, the referenced memory must stay valid for as long as the chunk is serialized — exactly the lifetime discipline described under [`string_view` lifetime](#string_view-and-lifetime) below.

**Inbound (parsing).** The HTTP/1.1 parser handles `Transfer-Encoding: chunked` transparently. It de-chunks the body into the message's `qb::allocator::pipe<char>` as fragments arrive, bounded by `protocol_limits::MAX_CHUNK_SIZE` (16 MB per chunk, the size each chunk-size line declares) and the overall body cap; a chunk declaring past the server's chunk limit and a body over its cap (`set_max_body_size`) are answered `413`, the chunk before a byte of it is read (`qbm/http/src/qbm/http/1.1/protocol/base.h:64-65,653-660,669-674`). By the time your handler runs, `ctx->request().body()` holds the fully reassembled body. You never see individual chunks at the routing layer. The fields of a trailer section — after the last chunk — reach the message's `trailers()`, every one of them, and, for 3.x, the ordinary header API too, as HTTP/2's and HTTP/3's trailers do (Huly QB-1073); a trailer field that frames, routes or manages the connection (`content-length`, `transfer-encoding`, `host`, `connection`, ...) refuses the message, as those protocols refuse their stream (Huly QB-1067).

**Outbound (serialization).** This is the part that surprises people. When you set `Transfer-Encoding: chunked` on a `Response`, the serializer in `pipe<char>::put<Response>` emits the response body as one chunk -- written as frames of 64 KiB past that size (Huly QB-1248) -- followed by the terminating chunk, in one write:

```cpp
// src: qbm/http/src/qbm/http/response.cpp:320-326
if (transfer.chunked) {
    out << qb::http::endl;
    if (!content_suppressed) {                                       // false unless a MessageHead
        if (length)
            out << qb::http::Chunk(r.body().raw().begin(), length); // whole body, one chunk (frames of 64 KiB)
        out << qb::http::Chunk();                                   // terminator, an empty body included
    }
}
```

A message whose `Trailer` header announces fields, or that carries `trailers()`, takes another, out-of-line path: the serializer asks `qb::http::detail::writes_trailer_section` (`chunk.h`) before it writes a byte — the check of `trailers()` — writes the start line itself, and hands the rest to `qb::http::detail::write_trailed_chunked_message`: the announced fields, then `trailers()`, travel in a trailer section after the last chunk, and not in the header section — the contract HTTP/2 and HTTP/3 send by — and the head gains a `trailer` field naming `trailers()` when the message announces nothing itself. A field a trailer section must not carry stays in the head even when announced, one set in `trailers()` refuses the message before a byte is written, and a `MessageHead` (which writes no trailer section of its own) keeps every field in the head and writes no `trailers()` (Huly QB-1067, QB-1073). A message framed by `Content-Length` has no trailer section: its `trailers()` are not written.

So setting `Transfer-Encoding: chunked` on a high-level `Response` changes the *framing* (no `Content-Length`; the body arrives as chunks), not the timing: the handler still assembles the full body, then `ctx->complete()` serializes and sends it. The serializer also rejects contradictory framing: declaring both `Transfer-Encoding` and `Content-Length`, or chunked encoding on a status that must not carry a body, throws `std::length_error` (`qbm/http/src/qbm/http/response.cpp:231-248`) — which the server session catches and turns into a connection failure rather than letting it escape the noexcept I/O boundary.

If you need true incremental, time-spaced delivery (server-sent events, a long-lived download generated on the fly), begin a stream: `ctx->begin_stream()`, the next section, is the supported way on HTTP/1.1, HTTP/2 and HTTP/3 alike. The other shapes, for comparison:

- **Buffer and send chunked.** Fine when the body is large but bounded and produced quickly. Build the body, set `Transfer-Encoding: chunked`, `complete()`.
- **Write `Chunk`s directly to a long-lived session.** The body-level helpers `body().add_chunk(chunk)` and `body().add_final_chunk()` (`qbm/http/src/qbm/http/body.h:240-254`) append chunk framing into the pipe; combined with direct session writes (`*session << ...`) you can emit chunks across multiple event-loop ticks. This is a low-level pattern: you own the framing, the `Content-Length`/`Transfer-Encoding` headers, and the terminating chunk, and you must call `ctx->suppress_response()` so the context does not also send a response (see [actor composition](#composing-with-qb-actors)). Write the head with `*session << qb::http::MessageHead{response}` — the status line and header section, nothing after them — then the chunks: `*session << response` writes a COMPLETE message, so an empty chunked body would already carry its terminator. `begin_stream()` does all of this for you, with backpressure.
- **Use a protocol designed for streaming.** HTTP/2 DATA frames (`END_STREAM`) and HTTP/3 give you real multiplexed streaming; WebSocket gives you bidirectional message framing. For genuinely streaming workloads, reach for [HTTP/2](./17-http2-protocol.md) or [WebSocket](./20-websocket.md) rather than HTTP/1.1 chunking. These are feature-gated: HTTP/2 and WebSocket compile only with `QB_HAS_SSL`, and HTTP/3 needs `QBM_HTTP_HAS_HTTP3` (`QB_HAS_SSL` + `QB_HAS_QUIC` + libnghttp3). HTTP/1.1 chunking has no such gate.

> HTTP/2 and HTTP/3 do not use chunked transfer encoding. `Transfer-Encoding` is a hop-by-hop header forbidden in HTTP/2 messages (`qb::http::well_known::is_hop_by_hop`); streaming there is expressed with DATA frames and the `END_STREAM` flag -- which is what `begin_stream()` does on those sessions: `stream_framing::end_of_stream`, each piece a DATA frame, no coding header (Huly QB-86). See [HTTP/2 protocol specifics](./17-http2-protocol.md).

### Streaming a body as it is produced: `begin_stream()`

A handler that should not hold its whole body before answering begins a stream on its context (Huly QB-86). The head leaves at once, the body follows in the pieces the handler writes, the session's output bounds how far the handler may run ahead of a slow peer, and `end()` closes the message and completes the context. Until then the stream owns the completion, so the handler may also hand the stream to a producer and return. One handler serves every protocol: chunked on HTTP/1.1, DATA frames on HTTP/2 and HTTP/3. `StaticFilesMiddleware` serves a file body over its `stream_threshold` this way ([large files stream](./08-standard-middleware.md#large-files-stream), Huly QB-101), and [`begin_sse()`](#server-sent-events-begin_sse) writes an event stream over it.

```cpp
// src: qbm/http/src/qbm/http/routing/context.h:1525; qbm/http/src/qbm/http/routing/response_stream.h:228-240
using Stream = qb::http::ResponseStream<MySession>;
router().get("/export", [](std::shared_ptr<qb::http::Context<MySession>> ctx) -> qb::io::async::task<void> {
    ctx->response().status() = qb::http::status::OK;        // status and headers first: they leave now
    ctx->response().set_header("Content-Type", "text/csv");
    auto stream = ctx->begin_stream();                       // no Content-Length set: chunked on HTTP/1.1, DATA frames on HTTP/2 and HTTP/3
    if (!stream)
        co_return;                                           // the request had already ended
    for (std::string const &row : load_rows()) {
        if (stream->needs_drain() && !co_await stream->drain())
            co_return;                                       // the peer left: stop
        if (stream->write(row) != Stream::write_result::taken)
            co_return;                                       // otherwise stop: a stream dropped before end() aborts the exchange
    }
    stream->end();                                           // the last-chunk (END_STREAM, FIN), then the context completes
});
```

The contract, in the order a producer meets it (`ResponseStream`, `qbm/http/src/qbm/http/routing/response_stream.h:162-228`):

- **`write(bytes)` returns at once, with a verdict** (`write_result`, `qbm/http/src/qbm/http/routing/response_stream.h:235-240`). `taken`: on its way. `wait`: the session's output holds too much for the piece; nothing was written, so wait for `drain()` and write the piece again, and after a drain it fits. `too_large`: the piece cannot fit even into a drained output (the room is the session's hard cap, as it stands when the stream begins -- on HTTP/1.1 and HTTP/2 its write-buffer cap, `max_write_buffer_size()`, qb-io's `QB_MAX_WRITE_BUFFER_SIZE`, 200 MiB, unless the session set another with `set_max_write_buffer_size()`; on HTTP/3 qb-io's constant -- less the high mark and the five bytes kept for the last-chunk), or, buffered, the body would pass `protocol_limits::MAX_BODY_SIZE`; split it, or end the response. `closed`: the peer is gone, the context is over, or the stream is. A piece that would pass a declared `Content-Length` aborts the exchange, since a message cannot be lengthened. The framing bytes of a chunk count with its payload: a size line and a CRLF pair per frame of at most 64 KiB (`qb::http::chunk_frame_size`), the frames the chunk serializer writes a larger piece as (Huly QB-1248: one was counted, so a write admitted under the cap could pass it). On HTTP/2 a piece wider than the peer's `SETTINGS_MAX_FRAME_SIZE` is split into DATA frames, and what the stream's or the connection's window cannot take yet waits in the session until a `WINDOW_UPDATE` lets it go: nothing is refused for a window, `pending()` counts it. On HTTP/3 the pieces are handed to nghttp3 as they come and leave as the QUIC stream's credit allows.
- **Backpressure is the producer's to honour.** `needs_drain()` turns true once the session holds `high_watermark()` bytes the peer has not taken -- on HTTP/1.1 the socket's output; on HTTP/2 that output, shared by the connection's streams, and the pieces this stream's windows hold back; on HTTP/3 the bytes the peer has not acknowledged: 1 MiB by default (`default_stream_high_watermark`), `set_watermarks(high, low)` per stream, `stream_high_watermark(bytes)` per session (the HTTP/1.1 and HTTP/2 connection sessions, the HTTP/3 request-stream session). The marks stay under the session's hard output cap: the high one at most half of it, the low one under the high one. In a coroutine, `co_await stream->drain()` resumes with `true` once the output falls to `low_watermark()` (half the high mark by default) -- on HTTP/2 a `WINDOW_UPDATE` that lets the held pieces go brings it there, on HTTP/3 the peer's acknowledgements do -- with `false` once the stream is cancelled or ended. Without one, `stream->on_drain(fn)` runs `fn` once, at the end of an event-loop turn (`qb::io::async::defer`), never inside the session's I/O handlers; `fn` reads `cancelled()` and `ended()` first, and a callback still registered when the stream is destroyed is released without running. One producer at a time: a second `drain()` while one is parked resumes at once with `false`.
- **A peer that stops taking bytes may be given a deadline** (Huly QB-1212). `set_idle_deadline(d)` ends the stream once the socket -- the peer, on HTTP/2 and HTTP/3 -- has accepted none of the bytes waiting for it for `d`: an idle deadline between two acceptances, never over the whole body, counted only while bytes wait, so a slow producer with nothing waiting is never cut and a slow but steady peer finishes. `set_min_rate(bytes_per_second, window)` ends it instead when the socket accepts fewer bytes a second than that over a sliding window -- sampled every eighth of the window while bytes wait, judged once the samples span a whole window, so the burst that fills the socket's buffers never counts; the floor is a download's, and a producer that writes less than it itself, with bytes waiting at every sample, is cut as a slow peer is. Past either the stream is aborted as `abort()` does it: the connection closes on HTTP/1.1, the stream alone is reset on HTTP/2 and HTTP/3, the context is cancelled, a parked `drain()` resumes with `false` and the next `write()` answers `closed`. Zero disables the deadline and 0 the floor, both the default for a handler's stream, and both may be set at any time, as the watermarks; `StaticFilesMiddleware` sets a 60 s deadline on every download it streams (`stream_idle_deadline`, [large files stream](./08-standard-middleware.md#large-files-stream)). On HTTP/2 the stream's own bytes are told apart from its siblings' on the shared output -- the pieces its windows hold back, and its last DATA frame's distance from leaving the output, which is drained in order: another stream's traffic is not this one's acceptance, and a producer idle beside a busy sibling is not a stalled peer. Setting the same value again changes nothing; a new one restarts the clock. The watch is one timer the stream owns while a setting is on, armed anew by every change, and it runs while the stream is open: once `end()` was called, what still waits in the output -- a body of at most the high watermark leaves in one go -- is the session's inactivity timeout's, the producer released already; a stream without one pays a flag test at each write. <!-- src: qbm/http/src/qbm/http/routing/response_stream.h:605,627,926 -->
- **`end()` closes the message and completes the context.** Chunked, the last-chunk goes out; `end_of_stream`, END_STREAM on HTTP/2 and FIN on HTTP/3, after the response's `trailers()` as a trailing header block when it has any (set them before `end()`: the head has left). A declared length not reached aborts the exchange instead, since the peer would wait for bytes that never come. `abort()` does it on purpose, for a source that failed mid-body: the connection closes on HTTP/1.1, the stream alone is reset on HTTP/2 (`RST_STREAM`, `INTERNAL_ERROR`) and HTTP/3 (`H3_REQUEST_CANCELLED`), and the connection serves its other streams and the next request; buffered, nothing has left, and the context answers 500 with an empty body, the failed body's `Content-Length`, `Transfer-Encoding` and `Content-Encoding` dropped.
- **The stream owns the completion.** From `begin_stream()` until the stream ends, `ctx->complete()` is ignored: a handler's own call and a coroutine route's automatic one alike (`qbm/http/src/qbm/http/routing/context.h:1265,1316-1318`). Only `end()`, `abort()`, the stream's destruction or a cancellation completes the context. A handler may therefore hand its stream to a producer (a timer chain, a subscription) and return, a coroutine included, on every protocol; a handler that throws while its stream is open leaves the answer to the stream, since the adapters answer 500 only when no stream is open.
- **A middleware may code the pieces** (Huly QB-1208). A `PRE_RESPONSE_SEND` hook that runs inside `begin_stream()` -- `ctx->stream_beginning()` says so: the head has not left, the body will come through a stream -- may hand the context a `qb::http::stream_filter` with `ctx->set_stream_coding()`; once every hook ran and the framing is known, the context sets the head for it (`Content-Encoding` the filter's name, no `Content-Length`, `Vary: Accept-Encoding`, a strong `ETag` made weak, no `Accept-Ranges`) and the stream takes the filter (chunked, END_STREAM or FIN: the coded length is unknown), codes each piece as it is written and the filter's tail at `end()`, and counts the producer's own bytes in `written()`. An HTTP/1.0 request, which reads no chunked body, keeps its length and gets no coding. A piece is admitted against the filter's `bound()` of it before it is coded: refused for room, it was never consumed and is written again as it is. `CompressionMiddleware` does this for every streamed body the client accepts a coding for, `StaticFilesMiddleware`'s downloads included; a buffered stream, a HEAD's and a declared length a hook kept get no filter. <!-- src: qbm/http/src/qbm/http/routing/response_stream.h:145; qbm/http/src/qbm/http/routing/context.h:1629,1647 -->
- **The producer owns the stream.** `begin_stream()` hands out the only strong reference; the context and the session keep weak ones. A stream dropped before `end()` aborts: on the wire the exchange ends -- the connection closes on HTTP/1.1, rather than leave the peer waiting or a pipelined request queued behind a dead stream; the stream is reset on HTTP/2 and HTTP/3 -- and buffered, the context answers 500.
- **The peer may leave at any time.** A connection that ends under a live stream, for any reason (the peer closing, the inactivity timeout, a local `disconnect()`), cancels the stream, and so does the session's extraction; on HTTP/2 and HTTP/3 so does the peer ending the stream alone -- a `RST_STREAM`, a `GOAWAY` that ends the connection, a QUIC stream reset or `STOP_SENDING` -- while the connection serves its other streams: a parked `drain()` resumes with `false`, the next `write()` returns `closed`, and the context is cancelled. `ctx->cancel()` does the same from the application's side, and ends the exchange under a streamed head, since the message can no longer be completed (the connection closes on HTTP/1.1, the stream is reset on HTTP/2 and HTTP/3, never the connection); a buffered stream, or one a `PRE_RESPONSE_SEND` hook cancels inside `begin_stream()`, answers 503 with no body and without the representation headers its head declared -- type, framing, coding, range, validators, caching (Huly QB-101). The producer's only duty is to stop. A server destroyed under a live stream releases it: the session's destructor cancels its streams -- `cancel_live_stream()` on HTTP/1.1 (`qbm/http/src/qbm/http/1.1/http.h:564-566`) and HTTP/3, `cancel_all_streams()` on HTTP/2 -- so a parked `drain()` resumes with `false` and an `on_drain()` callback runs or is released with the event loop instead of keeping the stream alive.

`begin_stream()` decides, in this order (`qbm/http/src/qbm/http/routing/context.h:1525`), and `framing()` reports the outcome:

1. **Whether the response can stream as the handler left it.** The session offers the hooks the `streaming_session` concept names (`qbm/http/src/qbm/http/routing/response_stream.h:109`) and answers this context, the status carries a body (not 1xx, 204, 304), and the head frames one: a valid `Content-Length`, a `Transfer-Encoding` whose only coding is `chunked`, or neither, to a request that is not HTTP/1.0. The HTTP/1.1, HTTPS/1.1, HTTP/2 and HTTP/3 server sessions offer the hooks (since Huly QB-86's second lot for the last two); an HTTP/1.1 connection an HTTP/2 server took through ALPN fallback does not. Otherwise the stream is **buffered**, with the same interface: the pieces gather in `response().body()` after what is there and leave whole at `end()` through the ordinary completion, its hooks included; `pending()` reads 0, `drain()` never waits, and `write()` answers `too_large` rather than let the body pass `protocol_limits::MAX_BODY_SIZE`. A handler is written once for every protocol.
2. **The `PRE_RESPONSE_SEND` hooks run**, the head's last chance: they see the head that will leave and an empty body. A body already in the response is moved aside, to be the stream's first piece, and `CompressionMiddleware`, finding the body empty, hands the context a content coding for the stream instead -- its `code_streamed_response()` (`qbm/http/src/qbm/http/middleware/compression.h:501`, Huly QB-1208).
3. **The framing is decided from the head as the hooks left it.** A valid `Content-Length` is honoured and enforced, the first piece included, on every protocol; a `Transfer-Encoding` whose only coding is `chunked` is chunked framing as it stands; neither is `Transfer-Encoding: chunked`, added -- on a session that delimits its messages itself (`stream_delimits_messages()`: HTTP/2 by END_STREAM, HTTP/3 by FIN) it is `end_of_stream` framing instead, and no coding header is added, since `Transfer-Encoding` is hop-by-hop there. A head the hooks turned into something a stream cannot carry (a status without a body, another coding, a malformed or a second framing header) is buffered after all, the first piece back in the body and the hooks marked as run, so the completion does not run them twice.
4. **The head leaves, then the first piece.** The response to `HEAD` is whole at its head: its exchange ends there, the context completes, and the next request on the connection is served while the producer runs on; the stream counts its pieces and discards them, never faulting them against a declared length. A head the session cannot write ends the exchange (the connection on HTTP/1.1, the stream on HTTP/2 and HTTP/3) and cancels the context.

`PRE_RESPONSE_SEND` runs once: at `begin_stream()` when the response may stream, and at the ordinary completion when it is buffered from the start (`qbm/http/src/qbm/http/routing/router.h:364-365`). `POST_RESPONSE_SEND` runs once the last byte is delivered, as for any response. Each piece refreshes the session's inactivity timeout; a stream that writes nothing for longer ends like a peer that left, so a stream of events writes a heartbeat or raises the timeout. A request pipelined behind a streamed one is answered after its `end()`, in order.

**On HTTP/2 and HTTP/3** the stream is one of the connection's many, told apart by `stream_id()` (the request's). The HEADERS leave at `begin_stream()` without END_STREAM; each piece leaves as DATA frames of at most the peer's frame size, as far as the stream's and the connection's send windows go, the rest waiting in the protocol's stream state until a `WINDOW_UPDATE` (the client's acknowledgements, on HTTP/3) lets it go; `end()` sends END_STREAM -- on the last DATA frame, on an empty one, or on the trailer section's HEADERS -- and FIN on HTTP/3, after `nghttp3_conn_submit_trailers` when the response has trailers. A streamed stream counts toward `SETTINGS_MAX_CONCURRENT_STREAMS` until that END_STREAM, as any open stream does, and the idle sweep and the Rapid Reset accounting see it as open. A HEAD's response is its HEADERS with END_STREAM, the exchange over there. The HTTP/1.1 fallback of an HTTP/2 server (ALPN `http/1.1`) buffers.

### Server-Sent Events: `begin_sse()`

An event stream (`text/event-stream`, the format a browser's `EventSource` reads) is a response that writes each event when it happens and ends when the server decides: a stream, with the head of an event stream. `ctx->begin_sse()` -- or `qb::http::sse::begin(ctx, options)` -- sets that head (`Content-Type: text/event-stream; charset=utf-8`, `Cache-Control: no-cache`, `Connection: keep-alive` on HTTP/1.1 alone, since the field is hop-by-hop on HTTP/2 and HTTP/3, `X-Accel-Buffering: no` on request, and no `Content-Length`), begins the context's stream and returns a `qb::http::sse::Stream<S>` that writes events through it, on every protocol (Huly QB-86).

```cpp
// src: qbm/http/src/qbm/http/sse.h:308
router().get("/events", [](auto ctx) -> qb::io::async::task<void> {
    const std::string &last = qb::http::sse::last_event_id(ctx->request());     // the id a reconnecting client saw last, or empty
    auto events = ctx->begin_sse(qb::http::sse::Options{.retry = 3000ms, .heartbeat = 15s});
    if (!events)
        co_return;
    std::uint32_t last_seen = 0;                                                   // the client's value: parsed without throwing, bounded
    std::from_chars(last.data(), last.data() + last.size(), last_seen);
    for (std::uint64_t n = std::uint64_t{last_seen} + 1; running(); ++n) {
        qb::http::sse::Event event{.name = "tick", .data = payload(n), .id = std::to_string(n)};
        if (!co_await events->send_async(event))                                   // waits for the client when the stream asks; false: it left
            co_return;
    }
    events->end();
});
```

- **An event** is `qb::http::sse::Event{name, data, id, retry}`: `event:` when `name` is set, one `data:` line per line of `data` (LF, CR or CRLF end a line; the client joins them back with LF and drops the last one, so a `data` that ends with a line break gets an empty last line and arrives as it was sent; an empty `data` still writes one line, since a client dispatches nothing without a `data:` line), `id:` when set, `retry:` in milliseconds when set, then the blank line that ends the event. Nothing is escaped; a CR or LF inside `name`, `id` or a comment is dropped, since it would start another field (an `id` echoed from a client must not forge an event). `qb::http::sse::format(event)` is the wire form; `comment_line(text)` the `: text` line a client ignores; `retry_line(ms)` the reconnection time alone.
- **Writing** is the stream's contract: `send(event)` returns the `write_result` -- `taken`, `wait` (the output is at its hard cap; write it again after `drain()`), `too_large`, `closed` (the client left or the stream ended) -- and `comment(text)` and `retry(ms)` the same; `co_await send_async(event)` writes again after a drain when the piece had to wait and waits for one when the stream asks (`needs_drain()`), `false` once the stream is over. `needs_drain()`, `drain()` and `on_drain(fn)` are the stream's, `stream()` the `ResponseStream` beneath, `events_sent()` the count.
- **An event stream is streamed or it is nothing.** Where `begin_stream()` can only buffer -- an HTTP/1.0 request, the HTTP/1.1 fallback of an HTTP/2 server, a session without the hooks -- the events would gather until `end()`, never for a stream that does not end: `begin_sse()` refuses, the request is answered 500 with an empty body (the buffered stream aborted) and `nullptr` comes back; a handler that wants a buffered fallback writes it itself. A `Connection: keep-alive` is said on HTTP/1.1 only when the request keeps the connection (the parser's verdict over every `Connection` token) and the server is not draining the session, which would answer `close`. A HEAD gets the head alone and an ended stream back: `send()` answers `closed`, `ended()` holds, no heartbeat starts -- a producer that loops on `cancelled()` alone must read `ended()` too.
- **The end and the life of the connection**: `end()` closes the message and completes the context; `abort()` ends the exchange. A stream that writes nothing for the session's inactivity timeout -- or, on HTTP/2, whose stream sent no frame for the connection's idle sweep (30 s, `RST_STREAM(CANCEL)`, whatever its window) -- ends like a client that left: `heartbeat(interval, text)` writes a comment line at that interval on a `qb::io::async::callback` timer that holds the stream weakly, so the timer stops by itself at its next tick once the stream is gone, ended or cancelled (a dropped handle's timer fires once more, finds no stream and stops); `Options::heartbeat` starts it at `begin()`. A tick whose comment the stream cannot take (`wait`) is skipped: the client is behind already.
- **Reconnection** is the client's: a browser reconnects by itself, after the last `retry:` it received, with the `id:` of the last event it saw in a `Last-Event-ID` header. `qb::http::sse::last_event_id(request)` reads it (empty when absent); the handler resumes from there. `Options::retry` writes the `retry:` line first.

The example `examples/06-modules/http/16-sse.cpp` is the whole shape: a route, a heartbeat, a client that resumes. The tests are `qbm-http-test-unit-sse-format` (the wire form, one case per field) and `qbm-http-test-system-sse-stream` (the head, events read by the client before the end, `Last-Event-ID`, the heartbeat and the death of a dropped stream's timer, `send_async`, the response-sent hook once per response from a synchronous and from a coroutine handler, on HTTP/1.1, HTTP/2 and HTTP/3; the refusal of a buffered stream and a HEAD's ended stream on HTTP/1.1).

Observers and the access log read a streamed response when its stream ends, at `end()`, `abort()` or a cancellation (`qbm/http/src/qbm/http/routing/observer.h:59-65`). `ctx.response()` then holds the head that left and an empty body, `ctx.streamed_bytes()` the body bytes the stream handed to the session, framing excluded (`qbm/http/src/qbm/http/routing/context.h:1668`), and a stream cut short keeps its head's status, with `ctx.is_cancelled()` set. `AccessLog` logs `streamed_bytes()` as the size of a streamed response (`qbm/http/src/qbm/http/middleware/access_log.h:128`).

## Keep-alive, pipelining, and the connection lifecycle

The HTTP/1.1 server session (`internal::session` in `qbm/http/src/qbm/http/1.1/http.h`) owns the persistence decision per connection.

**Keep-alive.** Two inputs decide whether a connection survives a response: the per-message `keep_alive` flag the parser computes from the request (llhttp's `http_should_keep_alive`, factoring HTTP version and the `Connection` header -- or `Proxy-Connection`, which llhttp reads as `Connection`; `close` has precedence over `keep-alive` on every version, RFC 9112 §9.3, where llhttp alone read `keep-alive` first below HTTP/1.1, and whitespace after an option ends it, a HTAB as a SP, where the vendored llhttp read no option followed by a HTAB: Huly QB-1248), and an application-level override you set with `session::keep_alive(bool)` (`qbm/http/src/qbm/http/1.1/http.h:645-647`). The override fills a silence, and never contradicts the request: it applies only to a request that does not keep its connection by itself and carries neither a `Connection` nor a `Proxy-Connection` field -- HTTP/1.0 with neither, which closes by default; an HTTP/1.1 request the parser does not keep carries one of the two. A request that carries the `close` connection option, in either field, closes its connection after its response: a server that receives it MUST initiate the closure (RFC 9112 §9.6; until 3.4 the override kept such a connection, and served what was pipelined behind the request, Huly QB-1248). So does an HTTP/1.0 request that carries either field without `keep-alive`, whatever its options. And an HTTP/1.0 request that carries `Transfer-Encoding` closes its connection after it -- its framing is treated as faulty (RFC 9112 §6.1), and the parser already reads its `keep_alive` as false (Huly QB-1248). A response that does not keep the connection is published with `close_after_deliver()`: the io closes once it is delivered, after its peer (qb-io's lingering close, Huly QB-1089), so a client still sending reads it before the close; the session's `on(event::disconnected)` still reports `ResponseTransmitted`. After a response that keeps it (`event::eos`), the session starts the next pipelined request:

```cpp
// src: qbm/http/src/qbm/http/1.1/http.h:446-453
if (!_active_should_keep_alive) {
    // The io closes after this delivery (close_after_response()); a response that did not go through it
    // still closes here, at once, as before.
    if (!_closing)
        this->disconnect(DisconnectedReason::ResponseTransmitted);
    return;
}
start_next_request_if_possible();
```

The session also normalizes the outgoing `Connection` header for you: it adds `Connection: close` when the connection will not persist, and `Connection: keep-alive` for an HTTP/1.0 response that will (`qbm/http/src/qbm/http/1.1/http.h:228-234`). A response that itself carries `Connection: close` forces the connection shut regardless of the keep-alive inputs.

**Pipelining.** While a response is in flight, further requests on the same connection queue rather than interleave. The queue is bounded by `session::max_pipelined_requests(std::size_t)` (default 128). Exceeding the cap disconnects the connection with `DisconnectedReason::ByProtocolError` (`qbm/http/src/qbm/http/1.1/http.h:146,348-355`). Each queued request is routed in order once the active context finishes (`start_next_request_if_possible`), so handlers for one connection never run concurrently — they are serialized on the session's I/O thread.

**Inactivity timeout.** A session arms a 60-second inactivity timeout on construction (`setTimeout(std::chrono::seconds(60))`, `qbm/http/src/qbm/http/1.1/http.h:547`). Each write restarts it, and so does what a read brings of a request -- its first byte, each piece of its body (Huly QB-1248) -- so it runs as nginx's three timeouts do: between two requests from the last write (`keepalive_timeout`); over a request's header section from its first byte, however the section is cut, so a header section sent slowly is still cut (`client_header_timeout`); over its body between two reads of it, so a body sent slowly but steadily is served and one that stalls ends a timeout after its last read (`client_body_timeout`). Until 3.4 only writes restarted it: a request had to arrive whole within the timeout of the connection's opening or of its last response. The HTTP/1.1 requests of an HTTP/2 server's ALPN fallback restart it the same way. On expiry it disconnects with `DisconnectedReason::ByTimeout` unless your session type defines an `on(event::timeout)` handler. Tune it from your session's constructor with `this->setTimeout(...)` (a qb-io facility; see the qb [`readme/`](https://github.com/isndev/qb/tree/main/readme/)): the three share the one value. A body sent at one byte per timeout keeps its connection, as on nginx; its memory stays under the body limit, and the number of such connections under the server's `set_max_sessions()`.

**Draining.** `server.drain(deadline, on_drained)` stops an HTTP/1.1 server without dropping a request it has received (Huly QB-167). The listening socket closes, so a new connection is refused and the port is free. A session with nothing to do -- no request being answered, none queued, no byte of one buffered -- closes at once, gracefully: its sending side is shut down and what its client still sends is dropped until the client closes (qb-io's lingering close); it reports `DisconnectedReason::ServerDraining`. A busy session answers every request it has received, in order, and the answer to the last one carries `Connection: close`, after which the connection closes; the protocol tells it whether another request follows in its buffer (`dispatching_size()`). `on_drained` runs once, on the server's loop: with `drain_outcome::drained` when the last owned HTTP or in-place WebSocket session is gone -- a lingering one counts until then -- or with `drain_outcome::deadline` when the deadline came first, after the sessions still open are aborted (`ServerDraining`). With no session open it runs before `drain()` returns. A WebSocket upgraded in place and still owned by this server receives `1001 Going Away` and keeps the drain pending until it closes or the deadline aborts it (Huly QB-1097). Its Close observer remains notified. A session extracted for an upgrade is no longer this server's and remains outside its drain; the new owner is responsible for its closure. The HTTP/2, HTTP/3 and dual-stack servers have the same `drain()`, each connection ended in two `GOAWAY`s (Huly QB-91; see the HTTP/2 and HTTP/3 chapters).

<!-- src: qbm/http/src/qbm/http/1.1/http.h:201-216,605-623,1003-1044,1083-1104,1121-1125,1135-1149; qbm/http/src/qbm/http/ws/ws.h:510-563,660-674; qbm/http/src/qbm/http/1.1/protocol/server.h:90-92; qbm/http/src/qbm/http/types.h:942-953 -->

**HEAD requests.** The session strips the response body for a `HEAD` request while preserving `Content-Length` — the body's size becomes it unless the response already declares `Content-Length` or `Transfer-Encoding` — so a `HEAD` reply reports the size the corresponding `GET` would return without sending the bytes (`qbm/http/src/qbm/http/1.1/http.h:218-226`). It serializes the reply as `qb::http::MessageHead{response}`: the header section only, so a chunked `HEAD` reply carries `Transfer-Encoding: chunked` and no last-chunk (`:250-253`).

## Protocol upgrade: HTTP to WebSocket

A WebSocket connection begins life as an HTTP/1.1 session. The opening `GET` with `Upgrade: websocket` is parsed as a normal HTTP request; your session's `on(Protocol::request&&)` validates it and calls `switch_protocol<ws::protocol>` to hand the live connection from HTTP request/response parsing to WebSocket framing. After a successful switch, the connection no longer returns to HTTP parsing — it is a WebSocket for the rest of its life.

The lifecycle hazard is the request context. When you upgrade (or otherwise transfer ownership of the connection), call `ctx->suppress_response()` so the `Context` destructor does not send a stale, moved-from HTTP response over a transport that now speaks WebSocket (`qbm/http/src/qbm/http/routing/context.h:1490-1494`). If you reject a failed upgrade with an HTTP error response, send it and use `close_after_deliver()` so the connection closes cleanly after the rejection flushes. The full upgrade walkthrough — handshake validation, subprotocol negotiation, the callback and coroutine session APIs — is in [WebSocket](./20-websocket.md) and [WebSocket coroutines](./21-websocket-coroutines.md).

```cpp
// src: qbm/http/tests/system/ws/ws-lifecycle.cpp:129-134 (shape)
void on(Protocol::request&& request) {      // HTTP upgrade arrives
    if (!this->switch_protocol<WS_Protocol>(*this, request))
        disconnect();
}
```

## Performance characteristics

These are the levers that matter, grounded in how the types are built rather than benchmarks.

- **Borrowed reads of owned data.** Parsed header names and values live in owning `std::string` storage; `header()` returns a borrowed `const std::string&`. `Body::as<std::string_view>()` borrows from the body's owning pipe without another body copy. Parsing and assigning a `string_view` to `Body` can still allocate and copy; no allocation-free parsing or measured speedup is implied. See [lifetime](#string_view-and-lifetime).
<!-- src: qbm/http/src/qbm/http/headers.h:154-170,372-379; qbm/http/src/qbm/http/body.cpp:717-721,827-830 -->

- **The body is a `qb::allocator::pipe<char>`.** `qb::http::Body` stores its payload in qb-io's I/O-optimized ring-style allocator (`qbm/http/src/qbm/http/body.h`, [Body deep dive](./02-body-deep-dive.md)). `body.raw()` gives you the pipe directly for custom (de)serialization. Assigning a `std::string` copies its bytes into the pipe even with an rvalue; the rvalue overload then clears the source string:

  ```cpp
  // src: qbm/http/src/qbm/http/body.cpp:701-705 (std::string rvalue assignment)
  std::string payload = build_large_json();
  ctx->response().body() = std::move(payload);   // copies bytes into the pipe, then clears payload
  ```

  Assigning `std::string_view` also copies its bytes into the pipe. Moving an entire `Body` instead uses its move assignment for the owned pipe; that is a different operation from moving a string or a view into a `Body`.
  <!-- src: qbm/http/src/qbm/http/body.h:80-90; qbm/http/src/qbm/http/body.cpp:701-721,1020-1024 -->

  Appendable types are constrained at compile time by `Body::is_body_appendable` (byte-like ranges, `Chunk`/`Multipart`/`qb::json`, or arithmetic which is stringified); other types are rejected by the compiler rather than producing malformed output (`qbm/http/src/qbm/http/body.h:119-173`). `Form` is deliberately not appendable — assign it wholesale (`body = form`), not `body << form`.

- **The router compiles once.** `router().compile()` builds an optimized radix tree for path matching. Call it once, after all routes are defined and before serving; it is not designed to be re-run on a hot path. See [Routing overview](./03-routing-overview.md).

- **Middleware runs per request.** Global middleware executes for every request on the matched chain; group- and controller-scoped middleware narrows that to the routes that need it. Scope middleware to the smallest node that covers the routes — inherited middleware runs parent-first, then the node's own, then the handler (`qbm/http/src/qbm/http/routing/route_group.h`, [Route groups](./05-route-groups.md)). Keep per-request work proportional to what the route actually needs.

- **One thread per connection, no locks on the hot path.** A session and its context are confined to the `VirtualCore` (thread) that owns the connection. Handlers for one connection are serialized; the framework takes no locks to dispatch them. This is what makes the body and context safe to touch without synchronization — and what makes blocking inside a handler a correctness problem, not just a latency one (see below).

- **One declared encoding, one transformation.** With `QB_HAS_COMPRESSION`, HTTP/1.1 one-shot and persistent clients compress an *uncompressed* request body when `Content-Encoding` is set, and decompress encoded responses. Do not precompress an HTTP/1.1 request before passing it to those clients. The response serializer emits the body's bytes unchanged: if you compress manually, set `Content-Encoding` after `body().compress(...)`; if you leave the body plain, use the compression middleware, which negotiates `Accept-Encoding`, compresses when worthwhile, and sets the header itself. An existing `Content-Encoding` makes that middleware skip response compression. See [Asynchronous HTTP client](./14-async-http-client.md) and [Standard middleware](./08-standard-middleware.md).
<!-- src: qbm/http/src/qbm/http/1.1/http.h:1449-1494; qbm/http/src/qbm/http/1.1/client.cpp:122-135,149-174; qbm/http/src/qbm/http/response.cpp:308-331; qbm/http/src/qbm/http/middleware/compression.h:421-463 -->

### Never block the event loop

A handler runs on the I/O thread. Blocking it — a synchronous database call, a sleeping syscall, a busy loop — stalls every other connection on that core. For I/O-bound work, return control to the loop and finish the response from a continuation:

- **Defer with `qb::io::async::callback`.** Schedule a continuation after a `qb::duration` delay; capture the context `shared_ptr` and complete from the callback (pattern below).
- **Hand work to another actor.** Send an event to a worker actor and complete the context when its reply arrives ([actor composition](#composing-with-qb-actors)).
- **Use the coroutine handlers.** `co_await` an awaiter (e.g. an outbound `qb::http::GET`) inside a coroutine route handler; the framework suspends and resumes you on the same thread without blocking it ([Custom middleware](./09-custom-middleware.md), [Async HTTP client](./14-async-http-client.md)).

## Asynchronous handlers and context lifecycle

When a handler or middleware starts async work and returns before completing, the request stays alive because the `Context` is a `std::shared_ptr`. Capture it by value into the continuation; complete it there.

```cpp
// In a route handler, IAsyncTask::execute, or ICustomRoute::process
auto ctx_kept = ctx;                         // shared_ptr keeps the request alive
my_service.fetch(key, [ctx_kept](Result r) {
    if (ctx_kept->is_cancelled())            // connection may have dropped
        return;                              // do NOT complete a cancelled context
    ctx_kept->response().body() = serialize(r);
    ctx_kept->complete(qb::http::AsyncTaskResult::COMPLETE);
});
// handler returns; the request is now pending on the captured context
```

Three rules carry real weight here, all enforced or documented in the headers:

1. **Something must eventually call `ctx->complete(...)`** (or, for functional middleware, `next()`), or the request hangs forever. Every `IAsyncTask`/handler/`ICustomRoute`/`IMiddleware` path is on the hook for it (`qbm/http/src/qbm/http/routing/async_task.h`, `custom_route.h`, `types.h`). The terminal response helpers — `json`, `text`, `html`, `redirect`, `no_content`, the error helpers — call `complete(COMPLETE)` for you, so set headers and body *before* calling them; only `status()` is non-terminal and chainable (`qbm/http/src/qbm/http/routing/context.h:1108-1261`).

2. **`cancel()` must not call `complete()`.** If your task supports cancellation, its `cancel()` implementation tears down the pending work but leaves finalization to the `Context` — calling `complete()` from `cancel()` is a contract violation (`qbm/http/src/qbm/http/routing/async_task.h:65-79`). `complete()` is idempotent after finalization and `is_cancelled()` is sticky (`qbm/http/src/qbm/http/routing/context.h:177-207,1274-1281`), so a late callback that checks `is_cancelled()` first is safe.

3. **Check `is_cancelled()` before doing work in a late callback.** The connection may have dropped or timed out while your async operation was in flight. The context survives (you hold a `shared_ptr`), but completing it does nothing useful.

## Composing with qb actors

The server-actor shape itself — `qb::Actor` + `qb::http::Server<>`, routes and `listen()` in `onInit`, one request end to end on one thread — is owned by [An HTTP server is an actor](./00-http-in-an-actor.md). This section is what you build *on top* of it once you have more than one actor.

Three composition patterns follow from the actor model:

**Pin servers to cores; run several.** Each `Server` actor runs its accept loop and all its sessions on one core. Place a server on a dedicated core, or run several server actors on different cores behind a load balancer, by passing the core index to `addActor`. Sessions never migrate between cores, so there is no cross-core sharing to synchronize within a server.

**Hand request work to worker actors.** A handler holds the `Context` `shared_ptr` and can reach the connection through `ctx->session()` (a `std::shared_ptr<SessionType>` obtained by locking an internal weak pointer; it may be empty if the connection is gone — `qbm/http/src/qbm/http/routing/context.h:650-661`). The clean pattern is: capture the context, `push` an event to a worker actor, and complete the context from the actor's reply handler. Because the worker runs on its own core, this offloads CPU- or I/O-bound work off the I/O thread without blocking it. Mind that the reply handler runs on the *server* actor's core (qb routes the event back), so completing the captured context there is thread-correct.

```cpp
// In a route handler on the server actor
auto ctx_kept = ctx;
push<WorkRequest>(worker_id, ctx_kept, std::move(ctx->request().body()));
// ...later, in the server actor's reply handler:
void on(WorkDone& ev) {
    if (!ev.ctx->is_cancelled()) {
        ev.ctx->response().body() = std::move(ev.result);
        ev.ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    }
}
```

Carrying a `std::shared_ptr<Context<Session>>` inside an event is sound: the context outlives the round-trip because every party holds a reference, and only the server actor's core ever calls `complete()` on it. See the qb [`readme/`](https://github.com/isndev/qb/tree/main/readme/) for actor referencing, events, and `push`.

**Drive the client from any actor.** The one-shot `GET`/`POST`/`REQUEST` helpers and the persistent `qb::http1::Client` run on whatever core their actor lives on, using that core's event loop. An actor can be both an HTTP server and an HTTP client — handle inbound requests and fan out to upstream services from the same actor — because both sit on the one qb-io loop. See [Asynchronous HTTP client](./14-async-http-client.md).

## `string_view` and lifetime

The retired `RequestView`/`ResponseView` types are not part of this API. For a present header, `header()` returns a borrowed `const std::string&` into the owning message's header map; for an absent header, it returns a reference to a process-wide static empty string. `Body::as<std::string_view>()` returns a borrowed view into the owning body's pipe. Neither accessor transfers ownership.
<!-- src: qbm/http/src/qbm/http/headers.h:154-170,372-379; qbm/http/src/qbm/http/body.cpp:827-830 -->

- While the owning message and its storage stay alive and unmodified, using those borrowed values is safe. Mutating a header map or body can invalidate a reference or view even inside one handler call.
- If data must outlive the message or its storage — stored in an async callback, carried in an event to another actor, cached past the response — **copy it into an owning type** (`std::string`, `std::vector<char>`) or move the owning message/`Body` with the lifetime you need. A borrowed value that outlives its owner is a dangling read and undefined behavior.
- `Chunk` carries the same rule: it borrows its bytes (`qbm/http/src/qbm/http/chunk.h:32-33,57-59`). Keep the source alive until the chunk is serialized.

## Pitfalls

- **Expecting `Transfer-Encoding: chunked` to stream incrementally from one handler.** It changes framing, not timing — the whole body is emitted as one chunk (in frames of 64 KiB) at `complete()` (`qbm/http/src/qbm/http/response.cpp:320-326`). To deliver a body while it is produced, begin a stream with `ctx->begin_stream()`.
- **Ignoring `needs_drain()` on a stream.** `write()` takes pieces up to the transport's hard cap, so a producer that never waits can queue 200 MiB for one slow client before it sees `wait`. Wait on `drain()` when `needs_drain()` says so.
- **Completing a streamed context by hand.** Once `begin_stream()` returned a stream, `ctx->complete()` and the terminal helpers complete nothing until the stream ends: the stream owns the completion. End it with `stream->end()`, or `abort()` it.
- **Reading a streamed response's size from its body.** `response().body()` is empty once the head left at `begin_stream()`; `ctx.streamed_bytes()` holds what the stream handed to the session.
- **Setting `Connection: keep-alive` or `Transfer-Encoding` on an event stream yourself.** Both are hop-by-hop: HTTP/2 refuses the head (the stream is reset). `begin_sse()` sets what each protocol takes; a handler that builds the head by hand sets neither on HTTP/2 and HTTP/3.
- **A silent event stream.** A stream that writes nothing for the session's inactivity timeout (60 s on HTTP/2 by default) is ended like a client that left: `heartbeat()` is what keeps it.
- **Setting both `Content-Length` and `Transfer-Encoding`.** The response serializer throws `std::length_error`, which the session turns into a connection failure (`qbm/http/src/qbm/http/response.cpp:244-245`). Set one framing mode, not both.
- **Blocking inside a handler.** It stalls every connection on that core. Defer with `qb::io::async::callback`, offload to a worker actor, or `co_await`.
- **Forgetting `ctx->complete()`.** The request hangs until the inactivity timeout closes it. Terminal response helpers complete for you; raw `body =`/`status()` do not.
- **Calling `complete()` from `cancel()`.** Contract violation — the `Context` manages its own finalization (`qbm/http/src/qbm/http/routing/async_task.h:65-79`).
- **Omitting `suppress_response()` on upgrade or ownership transfer.** The `Context` destructor will send a stale HTTP response over a transport that has moved on (`qbm/http/src/qbm/http/routing/context.h:1490-1494`).
- **Holding a borrowed body view, header reference, or `Chunk` past its owner.** Copy into an owning type, or transfer ownership of the message/`Body`, before crossing an async or inter-actor boundary.
- **Re-compiling the router on the hot path.** `compile()` is a setup-time, single-threaded operation; the router is not safe to mutate while serving.

## See also

- [HTTP message body deep dive](./02-body-deep-dive.md) — the `pipe<char>`-backed `Body`, conversions, compression.
- [Custom middleware](./09-custom-middleware.md) — functional, class-based, and coroutine middleware; the async task model.
- [The request context](./10-request-context.md) — `complete`/`cancel`, response helpers, typed data slots, lifecycle hooks.
- [Asynchronous HTTP client](./14-async-http-client.md) — callback and coroutine clients, the persistent `http1::Client`.
- [HTTP/2 protocol specifics](./17-http2-protocol.md) — streams, flow control, and DATA-frame streaming.
- [WebSocket](./20-websocket.md) and [WebSocket coroutines](./21-websocket-coroutines.md) — the upgrade path and bidirectional framing.
- The qb framework [`readme/`](https://github.com/isndev/qb/tree/main/readme/) — actors, events, `push`, `qb-io` async, and coroutines.

---

Previous: [HTTP message parsing](./15-http-parsing.md) · Next: [HTTP/2 protocol specifics](./17-http2-protocol.md) · Up: [Documentation map](./README.md)

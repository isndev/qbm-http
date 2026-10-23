/**
 * @file qbm/http/tests/benchmark/ws/ws-throughput.bench.cpp
 * @brief Google-benchmark harness for the RFC 6455 frame hot path (qbm-http WebSocket).
 *
 * Isolates the WebSocket data-plane that runs on every received/sent message.
 * The frame cells use no event loop or socket:
 *
 *   - ENCODE: `qb::allocator::pipe<char> << MessageText/MessageBinary`, which
 *     drives the serializer in `ws/ws.cpp` — header byte(s), extended length
 *     (7/16/64-bit), the 4-byte mask pull from the per-thread CSPRNG, and the
 *     word-at-a-time masking XOR (`fill_masked_message` / `fill_unmasked_message`).
 *   - DECODE: a socket-less server-side FakeIO satisfies the `AProtocol` IO
 *     concept (`in()`/`out()`/`operator<<`/`on(message&&)`, `has_server == true`)
 *     so we can feed raw masked client→server frame bytes into the input pipe and
 *     run the framer's `getMessageSize()` + `onMessage()` loop — the exact path
 *     the protocol parser pins in tests/unit/ws + tests/system/ws. This exercises
 *     the unmasking XOR, the reassembly-buffer append, and the auto-Pong on a Ping.
 *   - ECHO: decode a prepared masked client frame server-side and serialize the
 *     decoded Message during its callback. Exact wire bytes and inverse client
 *     decoding are checked outside the timed span, including corrupted inputs.
 *   - CLIENT FORWARD: deliver a prebuilt message event through the established
 *     CRTP client callback, without a socket or parser setup in the timed loop.
 *   - CORO RECEIVE: deliver one valid message event to a parked coro_client
 *     receive operation and run its continuation on the local scheduler, with
 *     no socket or parser setup.
 *
 * The frame shapes (text/binary sizes 16B..64KiB, plus a Ping control frame) and
 * the masked client→server framing mirror the dropped `ws-stress` throughput
 * corpus, which now lives only as this benchmark. The masked client frame builder
 * reuses the deterministic fixed-mask layout from tests/shared/ws_loopback.h's
 * `make_client_frame` (generalized here past the 125-byte control limit so the
 * larger data shapes can be driven through the same path).
 *
 * Requires OpenSSL: `ws/ws.h` hard-`#error`s without `QB_HAS_SSL` (the handshake
 * helpers link `qb::io::crypto` SHA-1/base64) and the masked-encode path pulls
 * its mask from the framework CSPRNG batch. The integrator gates this bench
 * REQUIRES ssl.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * @ingroup Http
 */

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <benchmark/benchmark.h>

#include <qb/system/allocator/pipe.h>
#include <qb/io/async.h>

#include <qbm/http/ws.h>

namespace {

// ---------------------------------------------------------------------------
// Deterministic payload corpus (no allocation inside the timed region).
// ---------------------------------------------------------------------------

std::string
make_payload(std::size_t size) {
    std::string payload(size, '\0');
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<char>('a' + (i % 26u));
    }
    return payload;
}

// Literal RFC 6455 headers for this benchmark's registered payload sizes.
// This oracle is independent of the serializer and keeps the existing payload.
std::string_view
expected_unmasked_binary_prefix(std::size_t size) {
    switch (size) {
        case 16:
            return {"\x82\x10", 2};
        case 256:
            return {"\x82\x7e\x01\x00", 4};
        case 4 * 1024:
            return {"\x82\x7e\x10\x00", 4};
        case 64 * 1024:
            return {"\x82\x7f\x00\x00\x00\x00\x00\x01\x00\x00", 10};
        default:
            throw std::logic_error("unregistered unmasked binary oracle size");
    }
}

// Build one masked client->server WebSocket frame, mirroring
// tests/shared/ws_loopback.h::make_client_frame but generalized to the 16-bit
// and 64-bit extended length forms so the large data shapes are exercised. The
// 4-byte mask is fixed (0xAA 0x55 0x01 0xFE) so frames are byte-deterministic.
std::vector<std::uint8_t>
make_masked_client_frame(std::uint8_t opcode_with_flags, std::string_view payload) {
    const std::array<std::uint8_t, 4> mask{{0xAA, 0x55, 0x01, 0xFE}};
    const std::size_t                 len = payload.size();

    // The header is written into a fixed buffer first and the vector is then sized ONCE, exactly.
    // The previous shape was `reserve(len + 14)` followed by push_back: correct, but only because
    // 14 is the largest header this function can emit, which the compiler cannot see. gcc-14 at
    // -O3 therefore kept the reallocation path live and reported it as a possible
    // `operator delete` on a non-heap pointer (-Wfree-nonheap-object). Sizing the vector to the
    // amount actually needed removes the branch rather than the diagnostic, and drops the
    // per-byte capacity check from the payload masking loop as well.
    std::array<std::uint8_t, 10> header{};
    std::size_t                  hdr = 0;
    header[hdr++]                    = opcode_with_flags;
    if (len < 126u) {
        header[hdr++] = static_cast<std::uint8_t>(0x80u | len);
    } else if (len <= 0xFFFFu) {
        header[hdr++] = static_cast<std::uint8_t>(0x80u | 126u);
        header[hdr++] = static_cast<std::uint8_t>((len >> 8) & 0xFFu);
        header[hdr++] = static_cast<std::uint8_t>(len & 0xFFu);
    } else {
        header[hdr++] = static_cast<std::uint8_t>(0x80u | 127u);
        for (int shift = 56; shift >= 0; shift -= 8)
            header[hdr++] = static_cast<std::uint8_t>((static_cast<std::uint64_t>(len) >> shift) & 0xFFu);
    }

    std::vector<std::uint8_t> out(hdr + mask.size() + len);
    std::copy_n(header.begin(), hdr, out.begin());
    std::copy(mask.begin(), mask.end(), out.begin() + static_cast<std::ptrdiff_t>(hdr));

    auto *body = out.data() + hdr + mask.size();
    for (std::size_t i = 0; i < len; ++i)
        body[i] = static_cast<std::uint8_t>(static_cast<std::uint8_t>(payload[i]) ^ mask[i & 3u]);
    return out;
}

// ---------------------------------------------------------------------------
// Socket-less server-side IO harness satisfying the WS AProtocol IO concept.
//
// The frame parser (qb::protocol::ws_server<IO_>) needs: base_io_t, a static
// `has_server`, in()/out() pipes, an operator<< frame sink, and an
// `on(message&&)` handler (qb::has_on<IO_, message> gates the data-frame
// dispatch). `error` is declared so notify_protocol_error() has a sink.
// ---------------------------------------------------------------------------
struct WsServerFakeIO {
    using base_io_t                  = WsServerFakeIO;
    static constexpr bool has_server = true;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;

    std::size_t message_count = 0;
    std::size_t last_size     = 0;

    struct error {};

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    qb::allocator::pipe<char> &
    out() noexcept {
        return output;
    }

    template <typename T>
    WsServerFakeIO &
    operator<<(const T &msg) {
        output.put(msg);
        return *this;
    }

    void
    on(qb::protocol::ws_internal::event_message &&event) {
        ++message_count;
        last_size = event.size;
    }

    void
    on(error &&) {}
};

using WsServerProtocol = qb::protocol::ws_server<WsServerFakeIO>;

// Minimal valid WS upgrade request so ws_server reaches the established state (it computes
// Sec-WebSocket-Accept from the key); RFC 6455 example key, version 13.
//
// `req.upgrade = true` is load-bearing: ws_server::populate_handshake_response()
// gates the whole handshake on the parsed `upgrade` flag (`if (!request.upgrade)
// return false`), NOT on the presence of the `Upgrade` header. The real HTTP/1.1
// parser sets that flag when it sees `Upgrade: websocket`; a hand-built Request
// must set it explicitly. Without it the constructor rejects the handshake,
// calls not_ok(), and getMessageSize() short-circuits to 0 — so no frame is ever
// decoded and the DECODE/ECHO correctness gates fail.
static qb::http::Request
ws_upgrade_request() {
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("/");
    req.upgrade  = true;
    req.set_header("Upgrade", "websocket");
    req.set_header("Connection", "Upgrade");
    req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    req.set_header("Sec-WebSocket-Version", "13");
    return req;
}

// Feed raw bytes into the input pipe and run the getMessageSize/onMessage loop
// until the framer can extract no further complete message.
template <typename Protocol, typename IO>
void
drive(Protocol &protocol, IO &io) {
    std::size_t n;
    while ((n = protocol.getMessageSize()) > 0) {
        protocol.onMessage(n);
        io.input.free_front(n);
        if (!protocol.ok()) {
            break;
        }
    }
}

// Echo only during the callback: the parser resets its Message immediately
// afterwards, so a retained event.data view would no longer be valid.
struct WsEchoServerIO : WsServerFakeIO {
    using base_io_t = WsEchoServerIO;

    void
    on(qb::protocol::ws_internal::event_message &&event) {
        WsServerFakeIO::on(std::move(event));
        output << event.ws;
    }
};

struct WsClientProbeIO : WsServerFakeIO {
    using base_io_t                  = WsClientProbeIO;
    static constexpr bool has_server = false;
    std::string           received;
    unsigned char         opcode = 0;

    void
    on(qb::protocol::ws_internal::event_message &&event) {
        WsServerFakeIO::on(std::move(event));
        received.assign(event.data, event.size);
        opcode = event.ws.fin_rsv_opcode;
    }
};

// Both exact wire comparison and the inverse production decoder are outside
// the timed span. The fixed handshake uses RFC 6455's example key/accept pair.
bool
echo_matches(const std::vector<std::uint8_t> &frame, std::string_view payload) {
    WsEchoServerIO                          io;
    qb::protocol::ws_server<WsEchoServerIO> server(io, ws_upgrade_request());
    io.output.reset(); // discard the successful HTTP upgrade response
    std::memcpy(io.input.allocate_back(frame.size()), frame.data(), frame.size());
    drive(server, io);

    std::string expected(expected_unmasked_binary_prefix(payload.size()));
    expected[0] = '\x81'; // FIN + text, independent of the outgoing serializer
    expected += payload;
    if (!server.ok() || io.message_count != 1u || io.last_size != payload.size() || !io.input.empty() || io.output.view() != expected)
        return false;

    qb::http::Response handshake;
    handshake.status() = qb::http::status::SWITCHING_PROTOCOLS;
    handshake.upgrade  = true;
    handshake.set_header("Upgrade", "websocket");
    handshake.set_header("Connection", "Upgrade");
    handshake.set_header("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    WsClientProbeIO                          client_io;
    qb::protocol::ws_client<WsClientProbeIO> client(client_io, handshake, "dGhlIHNhbXBsZSBub25jZQ==");
    client_io.input << io.output;
    drive(client, client_io);
    return client.ok() && client_io.message_count == 1u && client_io.input.empty() && client_io.opcode == 0x81u
           && client_io.received == payload;
}

// ===========================================================================
// ENCODE: outbound masked client frame serialization (header + masking XOR).
// ===========================================================================
void
BM_WS_EncodeMaskedText(benchmark::State &state) {
    const auto size    = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(size);

    // Correctness gate (out of the timed loop): a non-empty masked frame must
    // carry header + 4-byte mask + payload, i.e. strictly more than the payload.
    {
        qb::allocator::pipe<char> out;
        qb::http::ws::MessageText msg;
        msg.masked = true;
        msg << payload;
        out << msg;
        if (out.size() <= payload.size()) {
            state.SkipWithError("masked frame must be larger than its payload");
            return;
        }
    }

    qb::http::ws::MessageText msg;
    msg.masked = true;
    msg << payload;

    qb::allocator::pipe<char> out;
    for (auto _ : state) {
        out.reset();
        out << msg;
        auto produced = out.size();
        benchmark::DoNotOptimize(produced);
        benchmark::DoNotOptimize(out.begin());
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(size));
    state.SetItemsProcessed(state.iterations());
}

void
BM_WS_EncodeUnmaskedBinary(benchmark::State &state) {
    const auto size    = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(size);

    // Correctness gate (out of the timed loop): compare every header and
    // payload byte. The 256-byte case must be exactly 260 wire bytes.
    {
        qb::allocator::pipe<char>   probe_out;
        qb::http::ws::MessageBinary probe;
        probe.masked = false;
        probe << payload;
        probe_out << probe;
        std::string expected(expected_unmasked_binary_prefix(size));
        expected += payload;
        if (probe_out.view() != expected) {
            state.SkipWithError("unmasked binary frame differs from exact header and payload");
            return;
        }
    }

    qb::http::ws::MessageBinary msg;
    msg.masked = false;
    msg << payload;

    qb::allocator::pipe<char> out;
    for (auto _ : state) {
        out.reset();
        out << msg;
        auto produced = out.size();
        benchmark::DoNotOptimize(produced);
        benchmark::DoNotOptimize(out.begin());
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(size));
    state.SetItemsProcessed(state.iterations());
}

// ===========================================================================
// DECODE: inbound masked client frame parse + unmask XOR + reassembly.
// ===========================================================================
void
BM_WS_DecodeMaskedText(benchmark::State &state) {
    const auto size    = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(size);
    const auto frame   = make_masked_client_frame(0x81u /* FIN + text */, payload);

    // Correctness gate: one frame decodes to exactly one delivered message of
    // the right size.
    {
        WsServerFakeIO   io;
        WsServerProtocol protocol(io, ws_upgrade_request());
        std::memcpy(io.input.allocate_back(frame.size()), frame.data(), frame.size());
        drive(protocol, io);
        if (io.message_count != 1u || io.last_size != size) {
            state.SkipWithError("decode did not yield exactly one message of the expected size");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        WsServerFakeIO   io;
        WsServerProtocol protocol(io, ws_upgrade_request());
        std::memcpy(io.input.allocate_back(frame.size()), frame.data(), frame.size());
        state.ResumeTiming();

        drive(protocol, io);
        auto delivered = io.message_count;
        benchmark::DoNotOptimize(delivered);
        benchmark::DoNotOptimize(io.last_size);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(size));
    state.SetItemsProcessed(state.iterations());
}

// Control-frame path: a masked Ping must be decoded and auto-answered with a
// Pong appended to the output pipe (processControlFrame).
void
BM_WS_DecodePingAutoPong(benchmark::State &state) {
    const auto size    = static_cast<std::size_t>(state.range(0)); // <= 125 (control)
    const auto payload = make_payload(size);
    const auto frame   = make_masked_client_frame(0x89u /* FIN + ping */, payload);

    {
        WsServerFakeIO   io;
        WsServerProtocol protocol(io, ws_upgrade_request());
        // The successful handshake already wrote the 101 response into output;
        // snapshot that baseline so we measure the Pong specifically, not the
        // handshake bytes.
        const auto handshake_bytes = io.output.size();
        std::memcpy(io.input.allocate_back(frame.size()), frame.data(), frame.size());
        drive(protocol, io);
        // A Pong must have been appended on top of the handshake response; the
        // data-message path must NOT have fired for a control frame.
        if (io.output.size() <= handshake_bytes || io.message_count != 0u) {
            state.SkipWithError("ping did not produce an auto-pong on the output pipe");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        WsServerFakeIO   io;
        WsServerProtocol protocol(io, ws_upgrade_request());
        std::memcpy(io.input.allocate_back(frame.size()), frame.data(), frame.size());
        state.ResumeTiming();

        drive(protocol, io);
        auto pong_bytes = io.output.size();
        benchmark::DoNotOptimize(pong_bytes);
    }

    state.SetItemsProcessed(state.iterations());
}

// ===========================================================================
// ECHO: server decode + reply, with inverse client decoding in the oracle.
// ===========================================================================
void
BM_WS_ServerEchoText(benchmark::State &state) {
    const auto size    = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(size);
    const auto frame   = make_masked_client_frame(0x81u, payload);

    if (!echo_matches(frame, payload)) {
        state.SkipWithError("echo differs from exact text payload or inverse client decode");
        return;
    }
    auto corrupted = frame;
    corrupted.back() ^= 1u; // a different ASCII byte, with unchanged wire length
    if (echo_matches(corrupted, payload)) {
        state.SkipWithError("echo oracle accepted a same-size payload corruption");
        return;
    }
    corrupted    = frame;
    corrupted[0] = 0x82u; // binary instead of text, with unchanged payload and length
    if (echo_matches(corrupted, payload)) {
        state.SkipWithError("echo oracle accepted an opcode corruption");
        return;
    }

    for (auto _ : state) {
        state.PauseTiming();
        WsEchoServerIO                          io;
        qb::protocol::ws_server<WsEchoServerIO> protocol(io, ws_upgrade_request());
        std::memcpy(io.input.allocate_back(frame.size()), frame.data(), frame.size());
        io.output.reset();
        state.ResumeTiming();

        drive(protocol, io);
        auto produced = io.output.size();
        benchmark::DoNotOptimize(produced);
        benchmark::DoNotOptimize(io.output.begin());
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(size));
    state.SetItemsProcessed(state.iterations());
}

// Exercise the client-side CRTP forwarder itself. A connected WebSocket's
// message event is already parsed; construction, event storage, and the
// correctness probe stay outside the measured loop.
struct WsForwardClient : qb::http::ws::WebSocket<WsForwardClient> {
    using base         = qb::http::ws::WebSocket<WsForwardClient>;
    using message      = typename base::message;
    using disconnected = typename base::disconnected;

    std::size_t forwarded_bytes = 0;

    void
    on(message &&event) {
        forwarded_bytes += event.size;
    }
    void
    on(disconnected &&) {}
};

void
BM_WS_ClientMessageForward(benchmark::State &state) {
    qb::io::async::init();
    WsForwardClient           client;
    qb::http::ws::MessageText payload;
    payload << "forward";
    auto event = WsForwardClient::message{payload.size(), payload.data().cbegin(), payload};

    static_cast<WsForwardClient::base &>(client).on(std::move(event));
    if (client.forwarded_bytes != payload.size()) {
        state.SkipWithError("client message forwarding did not reach the callback");
        return;
    }
    client.forwarded_bytes = 0;

    for (auto _ : state) {
        static_cast<WsForwardClient::base &>(client).on(std::move(event));
        benchmark::DoNotOptimize(client.forwarded_bytes);
    }
    state.SetItemsProcessed(state.iterations());
}

namespace ws_receive_bench {

struct SchedulerCleanup {
    ~SchedulerCleanup() {
        if (qb::io::async::listener::current.has_coro_scheduler()) {
            qb::io::async::run_for(std::chrono::milliseconds(5));
            qb::io::async::listener::current.reset_coro_scheduler();
        }
        qb::io::async::listener::current.clear();
    }
};

// The owner, callback and continuation stay on this thread. There is one live
// receive awaiter and one valid message per operation on both source trees.
qb::io::async::task<qb::http::ws::IncomingFrame>
receive_one(qb::http::ws::coro_client<> &client, std::size_t &completed) {
    auto frame = co_await client.receive();
    ++completed;
    co_return frame;
}

bool
drain_until_done(const qb::io::async::task<qb::http::ws::IncomingFrame> &operation) {
    for (int turn = 0; turn != 16 && !operation.handle().done(); ++turn)
        qb::io::async::run(EVRUN_NOWAIT);
    return operation.handle().done();
}

} // namespace ws_receive_bench

// Socket-less ordinary receive: the public on(message) path copies a valid
// frame into IncomingFrame and completes one parked coroutine through the
// scheduler. Message creation and result checks are outside the measured span.
void
BM_WS_CoroReceiveMessage(benchmark::State &state) {
    qb::io::async::init();
    ws_receive_bench::SchedulerCleanup cleanup;
    qb::http::ws::coro_client<>        client;
    const auto                         size = static_cast<std::size_t>(state.range(0));
    const auto                         text = make_payload(size);
    qb::http::ws::MessageText          message;
    message << text;

    // One out-of-loop proof first: delivery must resume the sole consumer
    // with an owned, exact text payload and no pre-existing buffered frame.
    {
        std::size_t completed = 0;
        auto        operation = ws_receive_bench::receive_one(client, completed);
        operation.handle().resume();
        const bool parked = !operation.handle().done();
        client.on(qb::http::ws::coro_client<>::message{message.size(), message.data().cbegin(), message});
        if (!parked || !ws_receive_bench::drain_until_done(operation) || completed != 1u) {
            state.SkipWithError("coroutine receive did not complete exactly one parked operation");
            return;
        }
        const auto frame = operation.await_resume();
        if (frame.kind != qb::http::ws::IncomingFrame::Kind::Message || !frame.is_text || frame.payload != text) {
            state.SkipWithError("coroutine receive produced the wrong text frame");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        {
            std::size_t completed = 0;
            auto        event     = qb::http::ws::coro_client<>::message{message.size(), message.data().cbegin(), message};
            state.ResumeTiming();

            auto operation = ws_receive_bench::receive_one(client, completed);
            operation.handle().resume();
            const bool parked = !operation.handle().done();
            client.on(std::move(event));
            const bool done = ws_receive_bench::drain_until_done(operation);

            state.PauseTiming();
            if (!parked || !done || completed != 1u) {
                state.SkipWithError("coroutine receive did not complete exactly one parked operation");
                return;
            }
            const auto frame = operation.await_resume();
            if (frame.kind != qb::http::ws::IncomingFrame::Kind::Message || !frame.is_text || frame.payload != text) {
                state.SkipWithError("coroutine receive produced the wrong text frame");
                return;
            }
            benchmark::DoNotOptimize(frame.payload.data());
        }
        state.ResumeTiming();
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(size));
    state.SetItemsProcessed(state.iterations());
}

} // namespace

BENCHMARK(BM_WS_EncodeMaskedText)->Arg(16)->Arg(256)->Arg(4 * 1024)->Arg(64 * 1024)->ArgNames({"bytes"})->Unit(benchmark::kNanosecond);

BENCHMARK(BM_WS_EncodeUnmaskedBinary)->Arg(16)->Arg(256)->Arg(4 * 1024)->Arg(64 * 1024)->ArgNames({"bytes"})->Unit(benchmark::kNanosecond);

BENCHMARK(BM_WS_DecodeMaskedText)
    ->Arg(16)
    ->Arg(256)
    ->Arg(4 * 1024)
    ->Arg(64 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kNanosecond)
    ->UseRealTime();

BENCHMARK(BM_WS_DecodePingAutoPong)->Arg(0)->Arg(32)->Arg(125)->ArgNames({"bytes"})->Unit(benchmark::kNanosecond);

BENCHMARK(BM_WS_ServerEchoText)
    ->Arg(16)
    ->Arg(256)
    ->Arg(4 * 1024)
    ->Arg(64 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kNanosecond)
    ->UseRealTime();

BENCHMARK(BM_WS_ClientMessageForward)->Unit(benchmark::kNanosecond);

BENCHMARK(BM_WS_CoroReceiveMessage)->Arg(16)->Arg(256)->ArgNames({"bytes"})->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();

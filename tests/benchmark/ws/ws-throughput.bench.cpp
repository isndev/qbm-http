/**
 * @file qbm/http/tests/benchmark/ws/ws-throughput.bench.cpp
 * @brief Google-benchmark harness for the RFC 6455 frame hot path (qbm-http WebSocket).
 *
 * Isolates the WebSocket data-plane that runs on every received/sent message,
 * with no event loop and no socket:
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
 *   - ECHO: encode a masked client frame, decode it server-side, re-encode the
 *     server's reply — one full message round-trip per iteration.
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

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <benchmark/benchmark.h>

#include <qb/system/allocator/pipe.h>

#include "../ws.h"

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

// Build one masked client->server WebSocket frame, mirroring
// tests/shared/ws_loopback.h::make_client_frame but generalized to the 16-bit
// and 64-bit extended length forms so the large data shapes are exercised. The
// 4-byte mask is fixed (0xAA 0x55 0x01 0xFE) so frames are byte-deterministic.
std::vector<std::uint8_t>
make_masked_client_frame(std::uint8_t opcode_with_flags, std::string_view payload) {
    std::vector<std::uint8_t>         out;
    const std::array<std::uint8_t, 4> mask{{0xAA, 0x55, 0x01, 0xFE}};
    out.reserve(payload.size() + 14u);
    out.push_back(opcode_with_flags);

    const std::size_t len = payload.size();
    if (len < 126u) {
        out.push_back(static_cast<std::uint8_t>(0x80u | len));
    } else if (len <= 0xFFFFu) {
        out.push_back(static_cast<std::uint8_t>(0x80u | 126u));
        out.push_back(static_cast<std::uint8_t>((len >> 8) & 0xFFu));
        out.push_back(static_cast<std::uint8_t>(len & 0xFFu));
    } else {
        out.push_back(static_cast<std::uint8_t>(0x80u | 127u));
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.push_back(static_cast<std::uint8_t>((static_cast<std::uint64_t>(len) >> shift) & 0xFFu));
        }
    }

    for (auto b : mask) {
        out.push_back(b);
    }
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(static_cast<std::uint8_t>(static_cast<std::uint8_t>(payload[i]) ^ mask[i & 3u]));
    }
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
    using base_io_t = WsServerFakeIO;
    static constexpr bool has_server = true;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;

    std::size_t message_count = 0;
    std::size_t last_size      = 0;

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
static qb::http::Request ws_upgrade_request() {
    qb::http::Request req;
    req.method()  = qb::http::method::GET;
    req.uri()     = qb::io::uri("/");
    req.upgrade   = true;
    req.set_header("Upgrade", "websocket");
    req.set_header("Connection", "Upgrade");
    req.set_header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
    req.set_header("Sec-WebSocket-Version", "13");
    return req;
}

// Feed raw bytes into the input pipe and run the getMessageSize/onMessage loop
// until the framer can extract no further complete message.
void
drive(WsServerProtocol &protocol, WsServerFakeIO &io) {
    std::size_t n;
    while ((n = protocol.getMessageSize()) > 0) {
        protocol.onMessage(n);
        io.input.free_front(n);
        if (!protocol.ok()) {
            break;
        }
    }
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

    // Correctness gate (out of the timed loop): an unmasked binary frame must
    // carry at least a 2+ byte header on top of the payload, i.e. strictly more
    // than the payload — so a broken serializer can't quietly post a number.
    {
        qb::allocator::pipe<char>  probe_out;
        qb::http::ws::MessageBinary probe;
        probe.masked = false;
        probe << payload;
        probe_out << probe;
        if (probe_out.size() <= payload.size()) {
            state.SkipWithError("unmasked frame must be larger than its payload");
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
// ECHO: full client->server->client round-trip of a single text message.
// ===========================================================================
void
BM_WS_EchoRoundTrip(benchmark::State &state) {
    const auto size    = static_cast<std::size_t>(state.range(0));
    const auto payload = make_payload(size);
    const auto frame   = make_masked_client_frame(0x81u, payload);

    {
        WsServerFakeIO   io;
        WsServerProtocol protocol(io, ws_upgrade_request());
        std::memcpy(io.input.allocate_back(frame.size()), frame.data(), frame.size());
        drive(protocol, io);
        qb::http::ws::MessageText reply;
        reply.masked = false; // server->client frames are not masked
        reply << payload;
        qb::allocator::pipe<char> server_out;
        server_out << reply;
        if (io.message_count != 1u || server_out.size() <= size) {
            state.SkipWithError("echo round-trip did not decode + re-encode correctly");
            return;
        }
    }

    qb::allocator::pipe<char> server_out;
    for (auto _ : state) {
        state.PauseTiming();
        WsServerFakeIO   io;
        WsServerProtocol protocol(io, ws_upgrade_request());
        std::memcpy(io.input.allocate_back(frame.size()), frame.data(), frame.size());
        server_out.reset();
        state.ResumeTiming();

        drive(protocol, io);
        // Re-encode the server's reply (unmasked) as it would go back on the wire.
        qb::http::ws::MessageText reply;
        reply.masked = false;
        reply << payload;
        server_out << reply;
        auto produced = server_out.size();
        benchmark::DoNotOptimize(produced);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(size));
    state.SetItemsProcessed(state.iterations());
}

} // namespace

BENCHMARK(BM_WS_EncodeMaskedText)
    ->Arg(16)
    ->Arg(256)
    ->Arg(4 * 1024)
    ->Arg(64 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kNanosecond);

BENCHMARK(BM_WS_EncodeUnmaskedBinary)
    ->Arg(16)
    ->Arg(256)
    ->Arg(4 * 1024)
    ->Arg(64 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kNanosecond);

BENCHMARK(BM_WS_DecodeMaskedText)
    ->Arg(16)
    ->Arg(256)
    ->Arg(4 * 1024)
    ->Arg(64 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kNanosecond);

BENCHMARK(BM_WS_DecodePingAutoPong)->Arg(0)->Arg(32)->Arg(125)->ArgNames({"bytes"})->Unit(benchmark::kNanosecond);

BENCHMARK(BM_WS_EchoRoundTrip)
    ->Arg(16)
    ->Arg(256)
    ->Arg(4 * 1024)
    ->Arg(64 * 1024)
    ->ArgNames({"bytes"})
    ->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();

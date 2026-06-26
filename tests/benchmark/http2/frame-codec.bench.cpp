/**
 * @file qbm/http/tests/benchmark/http2/frame-codec.bench.cpp
 * @brief google-benchmark harness for the HTTP/2 frame-layer codec hot path.
 *
 * Every HTTP/2 frame crosses these socket-free helpers: the big-endian
 * extract/encode integer primitives (base.h), the 9-octet FrameHeader's
 * 24-bit length / 31-bit stream-id pack+unpack (frames.h), and the
 * HEADERS+CONTINUATION fragmentation arithmetic that splits an encoded header
 * block across max-frame-size-bounded frames (mirrors
 * Http2Protocol::send_headers_with_continuation, modelled here as a pure
 * wire-buffer build with no IO handler).
 *
 * Seeds (byte-exact fixtures reused so the benchmark measures the same code
 * the tests pin):
 *   - tests/unit/http2/http2-frame-layer.cpp: extract/encode_uint16/32_be
 *     round-trip vectors, FrameHeader WireByteLayoutRoundTrip (len 0x010203,
 *     flags 0x05, stream 0x04050607).
 *   - tests/unit/http2/http2-server-protocol.cpp: HEADERS frame emission with
 *     FLAG_END_HEADERS|FLAG_END_STREAM, 16384 max frame size, multi-fragment
 *     chunking (12000-byte chunks).
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

#include <benchmark/benchmark.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include "../2/protocol/base.h"

namespace h2 = qb::protocol::http2;

namespace {

// Build a HEADERS + CONTINUATION wire-frame sequence from an encoded header
// block, splitting it into <= max_fragment_size fragments. This reproduces
// the fragmentation/flag arithmetic of Http2Protocol::send_headers_with_
// continuation without an IO handler: we write the 9-octet FrameHeader image
// (via the same FrameHeader setters the framer uses) followed by each
// fragment into a contiguous wire buffer.
//
// Returns the number of frames emitted so the caller can assert the chunk
// count outside the timed loop.
std::size_t
build_header_frames(const std::vector<uint8_t> &block, std::size_t max_fragment_size, uint32_t stream_id, uint8_t first_frame_flags,
                    std::vector<uint8_t> &wire_out) {
    wire_out.clear();
    const std::size_t fragment_cap = std::max<std::size_t>(1, max_fragment_size);

    std::size_t offset      = 0;
    bool        first_frame = true;
    std::size_t frame_count = 0;

    do {
        const std::size_t remaining     = block.size() - offset;
        const std::size_t fragment_size = std::min(fragment_cap, remaining);
        const bool        last_fragment = (offset + fragment_size) == block.size();

        h2::FrameHeader fh{};
        if (first_frame) {
            fh.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
            fh.flags = first_frame_flags;
            if (last_fragment) {
                fh.flags |= h2::FLAG_END_HEADERS;
            } else {
                fh.flags &= static_cast<uint8_t>(~h2::FLAG_END_HEADERS);
            }
        } else {
            fh.type  = static_cast<uint8_t>(h2::FrameType::CONTINUATION);
            fh.flags = last_fragment ? h2::FLAG_END_HEADERS : 0;
        }
        fh.set_stream_id(stream_id);
        fh.set_payload_length(static_cast<uint32_t>(fragment_size));

        // #pragma pack(1): the in-memory image IS the wire image.
        const auto *fh_bytes = reinterpret_cast<const uint8_t *>(&fh);
        wire_out.insert(wire_out.end(), fh_bytes, fh_bytes + h2::FRAME_HEADER_SIZE);
        wire_out.insert(wire_out.end(), block.begin() + offset, block.begin() + offset + fragment_size);

        offset += fragment_size;
        first_frame = false;
        ++frame_count;
    } while (offset < block.size());

    return frame_count;
}

} // namespace

// ===========================================================================
// Big-endian integer extract / encode primitives (base.h)
// ===========================================================================

void
BM_Frame_ExtractUint32Be(benchmark::State &state) {
    // Seed: http2-frame-layer.cpp ExtractUint32BigEndian / Uint32RoundTrip.
    const uint8_t data[4] = {0x12, 0x34, 0x56, 0x78};

    if (h2::extract_uint32_be(data) != 0x12345678u) {
        state.SkipWithError("extract_uint32_be mismatch");
        return;
    }

    for (auto _ : state) {
        uint32_t v = h2::extract_uint32_be(data);
        benchmark::DoNotOptimize(v);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * 4);
}

void
BM_Frame_ExtractUint31Be(benchmark::State &state) {
    // Seed: ExtractUint31MasksReservedBit (R bit set, masked to 31 bits).
    const uint8_t data[4] = {0xFF, 0xFF, 0xFF, 0xFF};

    if (h2::extract_uint31_be(data) != 0x7FFFFFFFu) {
        state.SkipWithError("extract_uint31_be mask mismatch");
        return;
    }

    for (auto _ : state) {
        uint32_t v = h2::extract_uint31_be(data);
        benchmark::DoNotOptimize(v);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * 4);
}

void
BM_Frame_EncodeUint32Be(benchmark::State &state) {
    // Seed: EncodeUint32BigEndian.
    uint8_t out[4] = {0, 0, 0, 0};

    h2::encode_uint32_be(0x12345678u, out);
    if (out[0] != 0x12 || out[3] != 0x78) {
        state.SkipWithError("encode_uint32_be mismatch");
        return;
    }

    uint32_t v = 0;
    for (auto _ : state) {
        h2::encode_uint32_be(v++, out);
        benchmark::DoNotOptimize(out[0]);
        benchmark::DoNotOptimize(out[3]);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * 4);
}

// Round-trip: encode_uint32_be then extract_uint32_be, the framer's
// serialize -> parse path for a 32-bit field (window increment, error code).
void
BM_Frame_Uint32RoundTrip(benchmark::State &state) {
    uint8_t buf[4] = {0, 0, 0, 0};

    h2::encode_uint32_be(0x7FFFFFFFu, buf);
    if (h2::extract_uint32_be(buf) != 0x7FFFFFFFu) {
        state.SkipWithError("uint32 round-trip mismatch");
        return;
    }

    uint32_t v = 0;
    for (auto _ : state) {
        h2::encode_uint32_be(v, buf);
        uint32_t back = h2::extract_uint32_be(buf);
        benchmark::DoNotOptimize(back);
        ++v;
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * 4);
}

// ===========================================================================
// FrameHeader pack / unpack (frames.h) — the 24-bit len + 31-bit stream id
// ===========================================================================

// Pack a header (set_payload_length + set_stream_id + type/flags) and memcpy
// it to a 9-octet wire image — exactly what the framer writes per frame.
void
BM_Frame_HeaderPack(benchmark::State &state) {
    // Seed: WireByteLayoutRoundTrip fixture.
    {
        h2::FrameHeader fh{};
        fh.set_payload_length(0x010203u);
        fh.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
        fh.flags = h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM;
        fh.set_stream_id(0x04050607u);
        uint8_t wire[9] = {};
        std::memcpy(wire, &fh, sizeof(fh));
        if (wire[0] != 0x01 || wire[4] != 0x05 || wire[8] != 0x07) {
            state.SkipWithError("FrameHeader wire layout mismatch");
            return;
        }
    }

    uint32_t len = 0;
    for (auto _ : state) {
        h2::FrameHeader fh{};
        fh.set_payload_length(len & h2::MAX_FRAME_SIZE_LIMIT);
        fh.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
        fh.flags = h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM;
        fh.set_stream_id(0x04050607u);

        uint8_t wire[9] = {};
        std::memcpy(wire, &fh, sizeof(fh));
        benchmark::DoNotOptimize(wire[0]);
        benchmark::ClobberMemory();
        ++len;
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(h2::FRAME_HEADER_SIZE));
}

// Unpack: memcpy a 9-octet wire image into a FrameHeader and read every
// accessor (the framer's per-frame parse in EXPECTING_FRAME_HEADER).
void
BM_Frame_HeaderUnpack(benchmark::State &state) {
    // Seed: WireByteLayoutRoundTrip wire image.
    const uint8_t wire[9] = {0x01, 0x02, 0x03, static_cast<uint8_t>(h2::FrameType::HEADERS), 0x05, 0x04, 0x05, 0x06, 0x07};

    {
        h2::FrameHeader parsed{};
        std::memcpy(&parsed, wire, sizeof(parsed));
        if (parsed.get_payload_length() != 0x010203u || parsed.get_stream_id() != 0x04050607u
            || parsed.get_type() != h2::FrameType::HEADERS) {
            state.SkipWithError("FrameHeader unpack mismatch");
            return;
        }
    }

    for (auto _ : state) {
        h2::FrameHeader parsed{};
        std::memcpy(&parsed, wire, sizeof(parsed));
        uint32_t       len = parsed.get_payload_length();
        uint32_t       sid = parsed.get_stream_id();
        h2::FrameType  ty  = parsed.get_type();
        benchmark::DoNotOptimize(len);
        benchmark::DoNotOptimize(sid);
        benchmark::DoNotOptimize(ty);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(h2::FRAME_HEADER_SIZE));
}

// ===========================================================================
// HEADERS + CONTINUATION chunking (send_headers_with_continuation arithmetic)
// ===========================================================================

// Split a header block across max-frame-size fragments and write the framed
// wire image. block_bytes < 16384 -> single HEADERS frame; larger -> HEADERS +
// N CONTINUATION frames. Seeds the 16384 max frame size from the server tests.
void
BM_Frame_HeaderBlockChunking(benchmark::State &state) {
    const auto        block_bytes = static_cast<std::size_t>(state.range(0));
    const std::size_t max_frame   = h2::DEFAULT_MAX_FRAME_SIZE; // 16384

    // Deterministic header-block bytes (0x7A == 'z', as in the server test's
    // 12000-byte chunk fixture).
    const std::vector<uint8_t> block(block_bytes, 0x7A);

    {
        std::vector<uint8_t> probe;
        const std::size_t    frames = build_header_frames(block, max_frame, /*stream_id=*/1,
                                                          h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, probe);
        const std::size_t    expected_frames = (block_bytes + max_frame - 1) / max_frame;
        if (frames != std::max<std::size_t>(1, expected_frames) || probe.empty()) {
            state.SkipWithError("header-block chunking produced wrong frame count");
            return;
        }
    }

    std::vector<uint8_t> wire;
    std::size_t          frames_per_iter = 0;
    for (auto _ : state) {
        frames_per_iter =
            build_header_frames(block, max_frame, /*stream_id=*/1, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, wire);
        benchmark::DoNotOptimize(wire.data());
        benchmark::DoNotOptimize(frames_per_iter);
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations() * static_cast<std::int64_t>(frames_per_iter));
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(block_bytes));
}

BENCHMARK(BM_Frame_ExtractUint32Be)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Frame_ExtractUint31Be)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Frame_EncodeUint32Be)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Frame_Uint32RoundTrip)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Frame_HeaderPack)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Frame_HeaderUnpack)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Frame_HeaderBlockChunking)
    ->Arg(64)
    ->Arg(16 * 1024)
    ->Arg(64 * 1024)
    ->Arg(256 * 1024)
    ->ArgNames({"block_bytes"})
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();

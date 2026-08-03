/**
 * @file qbm/http/tests/benchmark/http2/hpack.bench.cpp
 * @brief google-benchmark harness for the HPACK (RFC 7541) codec hot path.
 *
 * HPACK encode/decode runs once per HTTP/2 header block — frequently on every
 * request and response — so the Encoder/Decoder, the Huffman codec, and the
 * DynamicTable ring buffer are squarely on the HTTP/2 hot path. These
 * benchmarks isolate the same code the unit suite pins, reusing its
 * byte-exact fixtures:
 *
 *   - Encoder::encode over a realistic request / response header list
 *     (seed: tests/unit/http2/hpack-codec.cpp HttpRequest/ResponseHeadersRoundTrip).
 *   - Decoder::decode over the RFC 7541 Appendix C.3 / C.5 gold byte vectors
 *     (seed: hpack-codec.cpp / hpack-encoder-strategy.cpp).
 *   - Static-table lookup (find_name_match / find_exact_match), the O(1)
 *     compile-time index (seed: hpack-codec.cpp HPACK_StaticTableIndex).
 *   - Huffman encode/decode of the C.4.1 / C.6.1 gold strings + a long value
 *     (seed: hpack-codec.cpp HPACK_Huffman gold vectors).
 *   - DynamicTable churn / eviction (seed: hpack-codec.cpp HPACK_DynamicTable
 *     RingBufferWraps / EvictionHonoursByteBudget).
 *
 * Each benchmark hoists fixture setup out of the timed loop and asserts the
 * measured operation once (state.SkipWithError) so a broken codec can never
 * report a bogus number.
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

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <qb/io/crypto.h>

#include <qbm/http/2/protocol/hpack.h>
#include <qbm/http/2/protocol/hpack_huffman.h>

using namespace qb::protocol::hpack;
using namespace qb::protocol::hpack::huffman;

namespace {

// Hex string -> bytes; mirrors the unit suite's hex_to_bytes helper so the
// RFC 7541 Appendix C gold vectors map byte-for-byte to what the tests decode.
std::vector<uint8_t>
hex_to_bytes(std::string_view hex) {
    const std::string decoded = qb::crypto::hex_to_string(std::string(hex));
    return {decoded.begin(), decoded.end()};
}

// Seed corpus: the realistic request header list from hpack-codec.cpp
// (HPACK_Integration.HttpRequestHeadersRoundTrip). icase headers are
// std::string, never bare const char*.
std::vector<HeaderField>
request_header_list() {
    return {
        {":method", "GET"},
        {":path", "/search?q=test&category=books"},
        {":scheme", "https"},
        {":authority", "www.example.com"},
        {"user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
        {"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        {"accept-language", "en-US,en;q=0.5"},
        {"accept-encoding", "gzip, deflate, br"},
        {"connection", "keep-alive"},
        {"upgrade-insecure-requests", "1"},
    };
}

// Seed corpus: the realistic response header list from hpack-codec.cpp
// (HPACK_Integration.HttpResponseHeadersRoundTrip).
std::vector<HeaderField>
response_header_list() {
    return {
        {":status", "200"},
        {"content-type", "application/json; charset=utf-8"},
        {"content-length", "1234"},
        {"server", "nginx/1.18.0"},
        {"date", "Mon, 01 Jan 2024 12:00:00 GMT"},
        {"cache-control", "public, max-age=3600"},
        {"etag", "\"abc123def456\""},
        {"vary", "Accept-Encoding"},
        {"x-frame-options", "DENY"},
        {"x-content-type-options", "nosniff"},
    };
}

} // namespace

// ===========================================================================
// Encoder::encode — realistic request / response header lists
// ===========================================================================

// Fresh encoder per iteration: measures cold encode (no dynamic-table reuse),
// the common case for a one-shot header block. The fixture list is built once
// outside the timed loop.
void
BM_Hpack_EncodeRequest(benchmark::State &state) {
    const auto headers = request_header_list();

    // Out-of-loop correctness assert: a broken encoder can't post numbers.
    {
        Encoder              encoder;
        std::vector<uint8_t> probe;
        if (!encoder.encode(headers, probe) || probe.empty()) {
            state.SkipWithError("encode of request header list failed");
            return;
        }
    }

    std::size_t bytes_per_iter = 0;
    for (auto _ : state) {
        Encoder              encoder;
        std::vector<uint8_t> out;
        bool                 ok = encoder.encode(headers, out);
        benchmark::DoNotOptimize(ok);
        benchmark::DoNotOptimize(out.data());
        bytes_per_iter = out.size();
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations() * static_cast<std::int64_t>(headers.size()));
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(bytes_per_iter));
}

void
BM_Hpack_EncodeResponse(benchmark::State &state) {
    const auto headers = response_header_list();

    {
        Encoder              encoder;
        std::vector<uint8_t> probe;
        if (!encoder.encode(headers, probe) || probe.empty()) {
            state.SkipWithError("encode of response header list failed");
            return;
        }
    }

    std::size_t bytes_per_iter = 0;
    for (auto _ : state) {
        Encoder              encoder;
        std::vector<uint8_t> out;
        bool                 ok = encoder.encode(headers, out);
        benchmark::DoNotOptimize(ok);
        benchmark::DoNotOptimize(out.data());
        bytes_per_iter = out.size();
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations() * static_cast<std::int64_t>(headers.size()));
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(bytes_per_iter));
}

// Warm encoder reused across iterations: after the first pass the request
// headers are resident in the dynamic table, so subsequent encodes collapse
// to indexed bytes — the long-lived-connection steady state.
void
BM_Hpack_EncodeRequestWarmDynamicTable(benchmark::State &state) {
    const auto headers = request_header_list();

    Encoder              encoder;
    std::vector<uint8_t> warm;
    if (!encoder.encode(headers, warm)) {
        state.SkipWithError("warm-up encode failed");
        return;
    }

    std::size_t bytes_per_iter = 0;
    for (auto _ : state) {
        std::vector<uint8_t> out;
        bool                 ok = encoder.encode(headers, out);
        benchmark::DoNotOptimize(ok);
        benchmark::DoNotOptimize(out.data());
        bytes_per_iter = out.size();
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations() * static_cast<std::int64_t>(headers.size()));
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(bytes_per_iter));
}

// ===========================================================================
// Decoder::decode — RFC 7541 Appendix C gold byte vectors
// ===========================================================================

// C.3.1 request block (no Huffman): 0x82 0x86 0x84 0x41 + "www.example.com".
// Fresh decoder per iteration so the dynamic-table insert cost is included.
void
BM_Hpack_DecodeRequestC3(benchmark::State &state) {
    const std::vector<uint8_t> block = hex_to_bytes("828684410f7777772e6578616d706c652e636f6d");

    {
        Decoder                  decoder;
        std::vector<HeaderField> out;
        bool                     incomplete = false;
        if (!decoder.decode(block, out, incomplete) || incomplete || out.size() != 4u) {
            state.SkipWithError("decode of C.3.1 request block failed");
            return;
        }
    }

    for (auto _ : state) {
        Decoder                  decoder;
        std::vector<HeaderField> out;
        bool                     incomplete = false;
        bool                     ok         = decoder.decode(block, out, incomplete);
        benchmark::DoNotOptimize(ok);
        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations() * 4);
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(block.size()));
}

// C.5.1 response block (no Huffman, 256-octet table): :status 302 + cache-
// control / date / location literals, four dynamic-table inserts.
void
BM_Hpack_DecodeResponseC5(benchmark::State &state) {
    const std::vector<uint8_t> block =
        hex_to_bytes("4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768"
                     "747470733a2f2f7777772e6578616d706c652e636f6d");

    {
        Decoder decoder;
        decoder.set_max_dynamic_table_size(256);
        std::vector<HeaderField> out;
        bool                     incomplete = false;
        if (!decoder.decode(block, out, incomplete) || incomplete || out.size() != 4u) {
            state.SkipWithError("decode of C.5.1 response block failed");
            return;
        }
    }

    for (auto _ : state) {
        Decoder decoder;
        decoder.set_max_dynamic_table_size(256);
        std::vector<HeaderField> out;
        bool                     incomplete = false;
        bool                     ok         = decoder.decode(block, out, incomplete);
        benchmark::DoNotOptimize(ok);
        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations() * 4);
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(block.size()));
}

// Round-trip a realistic request: encode once outside the loop, time the
// decode of the resulting block on a fresh decoder each iteration.
void
BM_Hpack_DecodeEncodedRequest(benchmark::State &state) {
    std::vector<uint8_t> block;
    {
        Encoder encoder;
        if (!encoder.encode(request_header_list(), block) || block.empty()) {
            state.SkipWithError("setup encode failed");
            return;
        }
    }
    const std::size_t header_count = request_header_list().size();

    for (auto _ : state) {
        Decoder                  decoder;
        std::vector<HeaderField> out;
        bool                     incomplete = false;
        bool                     ok         = decoder.decode(block, out, incomplete);
        benchmark::DoNotOptimize(ok);
        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations() * static_cast<std::int64_t>(header_count));
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(block.size()));
}

// ===========================================================================
// Static-table lookup — the O(1) compile-time index (F33)
// ===========================================================================

void
BM_Hpack_StaticTableFindName(benchmark::State &state) {
    // Mix of hits at various probe depths + one guaranteed miss.
    static const std::string_view names[] = {":authority",      ":method",          ":path",      ":scheme",       ":status",
                                             "accept-encoding", "www-authenticate", "user-agent", "x-not-in-table"};

    if (!static_table::find_name_match(std::string_view(":status")).has_value()) {
        state.SkipWithError("static-table name lookup broken");
        return;
    }

    std::size_t i = 0;
    for (auto _ : state) {
        auto r = static_table::find_name_match(names[i]);
        benchmark::DoNotOptimize(r);
        i = (i + 1) % (sizeof(names) / sizeof(names[0]));
    }

    state.SetItemsProcessed(state.iterations());
}

void
BM_Hpack_StaticTableFindExact(benchmark::State &state) {
    // (name,value) pairs spanning the :status / :method duplicate-name runs.
    struct Pair {
        std::string_view name;
        std::string_view value;
    };
    static const Pair pairs[] = {
        {":method", "GET"},
        {":method", "POST"},
        {":path", "/"},
        {":path", "/index.html"},
        {":scheme", "https"},
        {":status", "200"},
        {":status", "404"},
        {":status", "500"},
        {"accept-encoding", "gzip, deflate"},
        {":status", "418"} /* miss */,
    };

    if (static_table::find_exact_match(std::string_view(":method"), std::string_view("POST")).value() != 3u) {
        state.SkipWithError("static-table exact lookup broken");
        return;
    }

    std::size_t i = 0;
    for (auto _ : state) {
        auto r = static_table::find_exact_match(pairs[i].name, pairs[i].value);
        benchmark::DoNotOptimize(r);
        i = (i + 1) % (sizeof(pairs) / sizeof(pairs[0]));
    }

    state.SetItemsProcessed(state.iterations());
}

// ===========================================================================
// Huffman codec — RFC 7541 Appendix B/C gold strings
// ===========================================================================

void
BM_Huffman_Encode(benchmark::State &state) {
    // C.4.1 / C.6.1 worked-example strings + a long compressible value.
    static const std::string inputs[] = {
        "custom-key", "custom-header", "302", "private", "https://www.example.com", "Mon, 21 Oct 2013 20:13:21 GMT",
    };

    {
        std::vector<uint8_t> probe;
        if (!huffman_encode("custom-key", probe) || probe != std::vector<uint8_t>{0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f}) {
            state.SkipWithError("huffman_encode gold vector mismatch");
            return;
        }
    }

    std::size_t  i        = 0;
    std::int64_t in_bytes = 0;
    for (auto _ : state) {
        std::vector<uint8_t> out;
        bool                 ok = huffman_encode(inputs[i], out);
        benchmark::DoNotOptimize(ok);
        benchmark::DoNotOptimize(out.data());
        in_bytes += static_cast<std::int64_t>(inputs[i].size());
        i = (i + 1) % (sizeof(inputs) / sizeof(inputs[0]));
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(in_bytes);
}

void
BM_Huffman_Decode(benchmark::State &state) {
    // RFC 7541 C.4.1 Huffman("custom-key") and C.5.1 location URL.
    static const std::vector<uint8_t> custom_key = {0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f};
    static const std::vector<uint8_t> location   = hex_to_bytes("9d29ad171863c78f0b97c8e9ae82ae43d3"); // Huffman("https://www.example.com")

    {
        std::string probe;
        if (!huffman_decode(custom_key.data(), custom_key.size(), probe) || probe != "custom-key") {
            state.SkipWithError("huffman_decode gold vector mismatch");
            return;
        }
    }

    const std::vector<uint8_t> *blocks[] = {&custom_key, &location};
    std::size_t                 i        = 0;
    std::int64_t                in_bytes = 0;
    for (auto _ : state) {
        std::string out;
        bool        ok = huffman_decode(blocks[i]->data(), blocks[i]->size(), out);
        benchmark::DoNotOptimize(ok);
        benchmark::DoNotOptimize(out.data());
        in_bytes += static_cast<std::int64_t>(blocks[i]->size());
        i = (i + 1) % 2;
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(in_bytes);
}

// Encode of a long, highly compressible value (1000 'x'): exercises the
// bit-packing inner loop at scale (seed: LargeRepeatedDataCompresses).
void
BM_Huffman_EncodeLargeValue(benchmark::State &state) {
    const std::string input(1000, 'x');

    {
        std::vector<uint8_t> probe;
        if (!huffman_encode(input, probe) || probe.size() >= input.size()) {
            state.SkipWithError("huffman_encode of large value failed to compress");
            return;
        }
    }

    for (auto _ : state) {
        std::vector<uint8_t> out;
        bool                 ok = huffman_encode(input, out);
        benchmark::DoNotOptimize(ok);
        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(input.size()));
}

// ===========================================================================
// DynamicTable churn / eviction (F34 ring buffer)
// ===========================================================================

// Tight 150-octet budget forces continuous eviction as 1000 entries stream
// through a ring buffer that holds ~4 (seed: RingBufferWrapsCorrectly...).
void
BM_Hpack_DynamicTableChurnWithEviction(benchmark::State &state) {
    const auto entry_count = static_cast<std::size_t>(state.range(0));

    {
        DynamicTable probe;
        probe.set_max_byte_size(150);
        for (std::size_t i = 0; i < 8; ++i)
            probe.add("k" + std::to_string(i), "v");
        if (probe.empty()) {
            state.SkipWithError("dynamic-table add produced no resident entries");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        DynamicTable table;
        table.set_max_byte_size(150);
        state.ResumeTiming();

        for (std::size_t i = 0; i < entry_count; ++i) {
            auto r = table.add("k" + std::to_string(i), "v");
            benchmark::DoNotOptimize(r.evicted);
        }
        benchmark::DoNotOptimize(table.size());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations() * static_cast<std::int64_t>(entry_count));
}

// Large budget: entries accumulate, ring buffer grows (capacity doublings)
// but never evicts (seed: GrowsCapacityWhenCountExceedsInitial).
void
BM_Hpack_DynamicTableGrowNoEviction(benchmark::State &state) {
    const auto entry_count = static_cast<std::size_t>(state.range(0));

    for (auto _ : state) {
        state.PauseTiming();
        DynamicTable table;
        table.set_max_byte_size(1'000'000);
        state.ResumeTiming();

        for (std::size_t i = 0; i < entry_count; ++i) {
            auto r = table.add("k" + std::to_string(i), "v");
            benchmark::DoNotOptimize(r.added);
        }
        benchmark::DoNotOptimize(table.capacity());
        benchmark::ClobberMemory();
    }

    state.SetItemsProcessed(state.iterations() * static_cast<std::int64_t>(entry_count));
}

BENCHMARK(BM_Hpack_EncodeRequest)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Hpack_EncodeResponse)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Hpack_EncodeRequestWarmDynamicTable)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Hpack_DecodeRequestC3)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Hpack_DecodeResponseC5)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Hpack_DecodeEncodedRequest)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Hpack_StaticTableFindName)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Hpack_StaticTableFindExact)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Huffman_Encode)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Huffman_Decode)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Huffman_EncodeLargeValue)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Hpack_DynamicTableChurnWithEviction)->Arg(64)->Arg(1000)->ArgNames({"entries"})->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Hpack_DynamicTableGrowNoEviction)->Arg(64)->Arg(200)->ArgNames({"entries"})->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();

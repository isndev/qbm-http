/**
 * @file qbm/http/tests/benchmark/http1/http1-serialize.bench.cpp
 * @brief Benchmarks for outbound HTTP/1.1 message serialization (operator<<(pipe, msg)).
 *
 * Measures the wire-encode hot path every response (and outbound request) drives:
 * `qb::allocator::pipe<char> << Request/Response`. The serializer writes the
 * request-line / status-line, the header block, runs the Content-Length vs
 * Transfer-Encoding vs no-body-status validation contract, and emits the body —
 * either as a fixed-length payload or framed into chunked transfer-encoding.
 *
 * Wire fixtures are lifted from http1-serialization.cpp so the bench encodes exactly
 * the bytes those tests pin:
 *   - a fixed-length response with a body (Content-Length path),
 *   - a chunked request/response (RequestChunksPresentBody / ResponseChunksPresentBody:
 *     "...\r\n\r\n3\r\nabc\r\n0\r\n\r\n"),
 *   - a multi-header response (header-block width on the X axis).
 *
 * The pipe is the IO layer's reusable output buffer; following pipe-buffer-throughput.cpp
 * we keep ONE pipe and `reset()` it each iteration (PauseTiming around the reset) so the
 * reported number is the serialize cost, not buffer churn. SetBytesProcessed reports the
 * encoded wire size; one out-of-loop assert pins that the encode actually produced bytes.
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
#include <cstddef>
#include <cstdint>
#include <string>

#include <qb/system/allocator/pipe.h>

#include "../http.h" // qb::http::Request, Response, method, status

namespace {

std::string
make_payload(std::size_t size) {
    std::string payload(size, '\0');
    for (std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<char>('a' + (i % 26u));
    return payload;
}

// ---------------------------------------------------------------------------
// Fixture builders (seeded from http1-serialization.cpp). Each returns a fully
// configured value type that serializes without throwing.
// ---------------------------------------------------------------------------

// Fixed-length response: status-line + a couple headers + a Content-Length body.
qb::http::Response
make_fixed_length_response(std::size_t body_size) {
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("Content-Type", "application/json");
    response.set_header("Server", "qb-bench/1.0");
    response.body() = make_payload(body_size);
    return response;
}

// Chunked response (ResponseChunksPresentBody): Transfer-Encoding: chunked forces
// the serializer's chunk-framing path; no Content-Length is emitted.
qb::http::Response
make_chunked_response(std::size_t body_size) {
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    response.set_header("Transfer-Encoding", "chunked");
    response.body() = make_payload(body_size);
    return response;
}

// Chunked request (RequestChunksPresentBody): the outbound-client framing path.
qb::http::Request
make_chunked_request(std::size_t body_size) {
    qb::http::Request request{qb::http::method::POST, {"http://example.test/upload"}};
    request.set_header("Transfer-Encoding", "chunked");
    request.body() = make_payload(body_size);
    return request;
}

// Header-heavy response (no body): isolates header-block encoding width.
qb::http::Response
make_many_header_response(int header_count) {
    qb::http::Response response;
    response.status() = qb::http::status::OK;
    for (int i = 0; i < header_count; ++i)
        response.set_header("X-Bench-Header-" + std::to_string(i), "value-" + std::to_string(i));
    return response;
}

// ---------------------------------------------------------------------------
// Generic serialize loop: ONE reusable pipe, reset (out of band) each iteration.
// ---------------------------------------------------------------------------
template <typename Message>
void
serialize_loop(benchmark::State &state, const Message &message) {
    qb::allocator::pipe<char> out;

    // One out-of-loop correctness assert: a no-op encode must not report throughput.
    out << message;
    const std::size_t encoded_size = out.size();
    if (encoded_size == 0u) {
        state.SkipWithError("serializer produced no bytes");
        return;
    }
    out.reset();

    for (auto _ : state) {
        out << message;
        benchmark::DoNotOptimize(out.begin());
        benchmark::DoNotOptimize(out.size());

        // reset() is three integer assignments (pipe.h:308-311) — no free. Resetting inline costs
        // far less than the PauseTiming/ResumeTiming pair it used to be wrapped in (each ~hundreds
        // of ns), which only added wall-time + noise. Matches route-match / ws-throughput.
        out.reset();
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(encoded_size));
    state.SetItemsProcessed(state.iterations());
}

// --- Benchmarks -------------------------------------------------------------

void
BM_Http1Serialize_FixedLengthResponse(benchmark::State &state) {
    const auto response = make_fixed_length_response(static_cast<std::size_t>(state.range(0)));
    serialize_loop(state, response);
}

void
BM_Http1Serialize_ChunkedResponse(benchmark::State &state) {
    const auto response = make_chunked_response(static_cast<std::size_t>(state.range(0)));
    serialize_loop(state, response);
}

void
BM_Http1Serialize_ChunkedRequest(benchmark::State &state) {
    const auto request = make_chunked_request(static_cast<std::size_t>(state.range(0)));
    serialize_loop(state, request);
}

void
BM_Http1Serialize_HeaderBlock(benchmark::State &state) {
    const auto response = make_many_header_response(static_cast<int>(state.range(0)));
    serialize_loop(state, response);
}

} // namespace

BENCHMARK(BM_Http1Serialize_FixedLengthResponse)
    ->Arg(0)
    ->Arg(256)
    ->Arg(4 * 1024)
    ->Arg(64 * 1024)
    ->ArgNames({"body_bytes"})
    ->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http1Serialize_ChunkedResponse)->Arg(256)->Arg(4 * 1024)->Arg(64 * 1024)->ArgNames({"body_bytes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http1Serialize_ChunkedRequest)->Arg(256)->Arg(4 * 1024)->Arg(64 * 1024)->ArgNames({"body_bytes"})->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http1Serialize_HeaderBlock)->Arg(1)->Arg(8)->Arg(32)->ArgNames({"headers"})->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();

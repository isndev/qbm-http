/**
 * @file qbm/http/tests/benchmark/http2/server-request.bench.cpp
 * @brief google-benchmark harness for the HTTP/2 server's request path below the router.
 *
 * One HEADERS frame (END_HEADERS | END_STREAM) carrying a browser-shaped GET is framed, HPACK-decoded,
 * validated field by field -- the per-field loop of ServerHttp2Protocol's header-block handler: the
 * connection-specific fields, `te`, the limits, `content-length`, and since Huly QB-1189 the `host`
 * field against `:authority` --, assembled into a qb::http::Request whose URI `origin::request_uri`
 * composes, and handed to the IO. A status-only 200 then closes the stream. No socket, no TLS, no
 * router: what one request costs the protocol layer, the cost a per-field check adds to.
 *
 * The header block is encoded twice by one HPACK encoder and the first encoding is fed once during
 * setup: the timed block is the second, as a browser's second request on a connection is -- its fields
 * indexed in the static or the server decoder's dynamic table, but for `:authority`, `:path` and
 * `cookie`, which the encoder sends as literals never indexed, so the timed block adds nothing to the
 * table. The measured operation is asserted once before the loop; after it, every iteration's request
 * must have been routed and answered, the last one with every field and its stream closed
 * (state.SkipWithError), so a refused, mis-parsed or unanswered request never reports a number. The
 * server's INFO lines (a request dispatched, answered, its context released) are not the protocol's
 * work: main() raises the log level to WARN first, and refuses to run under stdout logging, which
 * cannot be filtered.
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
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <qb/io.h>
#include <qbm/http/2/protocol/server.h>

namespace {

namespace h2 = qb::protocol::http2;

// The socket-less IO the server protocol writes to and reports to.
struct BenchIO {
    using base_io_t = BenchIO;

    qb::allocator::pipe<char> input;
    qb::allocator::pipe<char> output;

    std::size_t requests    = 0;
    std::size_t errors      = 0; ///< stream errors, GOAWAYs and responses send_response() refused
    std::size_t last_fields = 0;

    qb::allocator::pipe<char> &
    in() noexcept {
        return input;
    }
    qb::allocator::pipe<char> &
    out() noexcept {
        return output;
    }

    template <typename Frame>
    BenchIO &
    operator<<(const Frame &frame) {
        output.put(frame);
        return *this;
    }

    void
    on(qb::http::Request &&request, uint32_t) {
        ++requests;
        last_fields = request.headers().size();
        benchmark::DoNotOptimize(request);
    }
    void
    on(const h2::Http2StreamErrorEvent &) {
        ++errors;
    }
    void
    on(const h2::Http2GoAwayEvent &) {
        ++errors;
    }
    void
    on(const h2::Http2PushPromiseEvent &) {}
};

using Server = h2::ServerHttp2Protocol<BenchIO>;

void
push_bytes(BenchIO &io, const void *p, std::size_t n) {
    std::memcpy(io.input.allocate_back(n), p, n);
}

void
push_frame(BenchIO &io, h2::FrameType type, uint8_t flags, uint32_t stream_id, const std::vector<uint8_t> &payload) {
    h2::FrameHeader fh{};
    fh.set_payload_length(static_cast<uint32_t>(payload.size()));
    fh.type  = static_cast<uint8_t>(type);
    fh.flags = flags;
    fh.set_stream_id(stream_id);
    push_bytes(io, &fh, sizeof(fh));
    if (!payload.empty()) {
        push_bytes(io, payload.data(), payload.size());
    }
}

void
drive(Server &server, BenchIO &io) {
    std::size_t size = 0;
    while ((size = server.getMessageSize()) > 0) {
        server.onMessage(size);
        io.input.free_front(size);
        if (!server.ok()) {
            break;
        }
    }
}

// A browser's navigation request: the pseudo-header fields, then 14 regular fields.
std::vector<qb::protocol::hpack::HeaderField>
browser_get(bool with_host) {
    std::vector<qb::protocol::hpack::HeaderField> fields{
        {":method", "GET"},
        {":scheme", "https"},
        {":authority", "example.test"},
        {":path", "/bench/items?id=42&sort=desc"},
        {"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"},
        {"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
        {"accept-language", "en-US,en;q=0.9"},
        {"accept-encoding", "gzip, deflate, br, zstd"},
        {"sec-ch-ua", "\"Chromium\";v=\"130\", \"Not?A_Brand\";v=\"99\""},
        {"sec-ch-ua-mobile", "?0"},
        {"sec-ch-ua-platform", "\"macOS\""},
        {"sec-fetch-site", "none"},
        {"sec-fetch-mode", "navigate"},
        {"sec-fetch-dest", "document"},
        {"sec-fetch-user", "?1"},
        {"upgrade-insecure-requests", "1"},
        {"cookie", "session=4f9a1c2e7b; theme=dark"},
        {"priority", "u=0, i"}
    };
    if (with_host) {
        fields.push_back({"host", "example.test"}); // what an intermediary that retains it sends (RFC 9113 section 8.3.1)
    }
    return fields;
}

// One request on a fresh, handshaken server: framed, decoded, validated, dispatched, then answered.
void
serve(Server &server, BenchIO &io, uint32_t stream_id, const std::vector<uint8_t> &block, const qb::http::Response &response) {
    push_frame(io, h2::FrameType::HEADERS, h2::FLAG_END_HEADERS | h2::FLAG_END_STREAM, stream_id, block);
    drive(server, io);
    if (!server.send_response(stream_id, response)) {
        ++io.errors;
    }
    io.output.reset();
}

void
run_browser_get(benchmark::State &state, bool with_host) {
    BenchIO io;
    Server  server(io);
    push_bytes(io, HTTP2_CONNECTION_PREFACE.data(), HTTP2_CONNECTION_PREFACE.size());
    push_frame(io, h2::FrameType::SETTINGS, 0, 0, {});
    drive(server, io);

    qb::protocol::hpack::Encoder encoder;
    std::vector<uint8_t>         first, repeated;
    const auto                   fields = browser_get(with_host);
    if (!server.ok() || !encoder.encode(fields, first) || !encoder.encode(fields, repeated)) {
        state.SkipWithError("handshake or HPACK encoding failed");
        return;
    }

    qb::http::Response response;
    response.status() = qb::http::status::OK;

    uint32_t stream_id = 1;
    serve(server, io, stream_id, first, response); // fills the server decoder's dynamic table
    stream_id += 2;
    serve(server, io, stream_id, repeated, response);
    const std::size_t regular = fields.size() - 4;
    if (!server.ok() || io.requests != 2 || io.errors != 0 || io.last_fields != regular || !server.is_stream_closed(stream_id)) {
        state.SkipWithError("the request was not routed with every regular field");
        return;
    }

    for (auto _ : state) {
        stream_id += 2;
        serve(server, io, stream_id, repeated, response);
    }

    if (!server.ok() || io.errors != 0 || io.requests != 2 + static_cast<std::size_t>(state.iterations()) || io.last_fields != regular
        || !server.is_stream_closed(stream_id)) {
        state.SkipWithError("a timed request was refused, left unanswered or left open");
        return;
    }
    state.SetItemsProcessed(state.iterations());
    state.counters["regular_fields"] = static_cast<double>(regular);
}

void
BM_Http2Server_BrowserGet(benchmark::State &state) {
    run_browser_get(state, false);
}

void
BM_Http2Server_BrowserGetWithHost(benchmark::State &state) {
    run_browser_get(state, true);
}

} // namespace

BENCHMARK(BM_Http2Server_BrowserGet)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Http2Server_BrowserGetWithHost)->Unit(benchmark::kNanosecond);

int
main(int argc, char **argv) {
#if defined(QB_WITH_LOGGING)
    qb::io::log::setLevel(qb::io::log::Level::WARN);
#elif defined(QB_STDOUT_LOGGING)
    std::cerr << "http2-server-request requires filterable logging or logging disabled; stdout logging cannot be filtered\n";
    return 2;
#endif
    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}

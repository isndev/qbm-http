/**
 * @file qbm/http/tests/benchmark/message/body-codec.bench.cpp
 * @brief google-benchmark harness for the qb::http::Body codecs.
 *
 * Every request/response body that is not opaque bytes goes through one of three
 * codecs on the hot path: `Form` URL-encode/decode (HTML form posts and query
 * bodies), `Multipart` parse (file uploads — driven by a callback-emitting
 * boundary scanner), and `Body::as<qb::json>()` round-trips (JSON APIs). These
 * benchmarks isolate each codec from the transport so the parse/serialize cost
 * is measured directly.
 *
 * Fixtures are the byte-exact payloads pinned by tests/unit/message/body-codec.cpp:
 *   - the `create_simple_form()` field set (incl. a repeated `param` key);
 *   - the `MultipartConversionPreservesPartDataAcrossMultipleParserCallbacks`
 *     "tricky" payload, whose body embeds boundary-lookalike runs
 *     ("--Boundary123X" / "--Boundary123Y") that force the multipart scanner
 *     through its multi-callback fragment-reassembly path — the worst case;
 *   - the 64-bit / double JSON object from
 *     `JsonSerializationPreserves64BitAndDouble`.
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

#include <cstdint>
#include <string>

#include <benchmark/benchmark.h>

#include <qb/json.h>

#include "../http.h" // qb::http::{Body, Form, Multipart} (resolves via tests/ include dir)

namespace {

using qb::http::Body;
using qb::http::Form;
using qb::http::Multipart;

// ---------------------------------------------------------------------------
// Fixtures lifted byte-exact from tests/unit/message/body-codec.cpp.
// ---------------------------------------------------------------------------

// create_simple_form(): two scalar fields + a repeated `param` key.
Form
make_simple_form() {
    Form form;
    form.add("name", "test_user");
    form.add("email", "test@example.com");
    form.add("param", "value1");
    form.add("param", "value2");
    return form;
}

// MultipartConversionPreservesPartDataAcrossMultipleParserCallbacks:
// the body embeds boundary-lookalike runs so the scanner must reassemble across
// callbacks instead of cutting at the first "--Boundary123" it sees.
const std::string &
make_tricky_multipart_wire() {
    static const std::string boundary       = "Boundary123";
    static const std::string tricky_payload = "alpha\r\n--Boundary123Xbeta\r\n--Boundary123Ygamma";
    static const std::string wire           = "--" + boundary
                                              + "\r\n"
                                                "Content-Disposition: form-data; name=\"file\"\r\n"
                                                "\r\n"
                                              + tricky_payload + "\r\n--" + boundary + "--";
    return wire;
}

// JsonSerializationPreserves64BitAndDouble: a 64-bit / double / string object.
qb::json
make_wide_json() {
    qb::json j;
    j["i64"]   = 1782214248072LL;        // > 2^31
    j["neg64"] = -5000000000LL;          // < -2^31
    j["u64"]   = 9000000000ULL;          // > 2^32
    j["dbl"]   = 0.1;                    // not representable as float
    j["dmax"]  = 1.7976931348623157e308; // double max
    j["small"] = 7;
    j["str"]   = "hello";
    return j;
}

// ---------------------------------------------------------------------------
// Form URL-encode: serialize a Form into a body (Body::operator=<Form>).
// ---------------------------------------------------------------------------
void
BM_Body_FormEncode(benchmark::State &state) {
    const Form form = make_simple_form();

    // Out-of-loop correctness gate.
    {
        Body probe;
        probe = form;
        if (probe.as<std::string>().find("email=test%40example.com") == std::string::npos) {
            state.SkipWithError("form url-encode mismatch");
            return;
        }
    }

    std::int64_t bytes = 0;
    for (auto _ : state) {
        Body body;
        body                = form;
        std::string encoded = body.as<std::string>();
        bytes               = static_cast<std::int64_t>(encoded.size());
        benchmark::DoNotOptimize(encoded.data());
    }

    state.SetBytesProcessed(state.iterations() * bytes);
    state.SetItemsProcessed(state.iterations());
}

// ---------------------------------------------------------------------------
// Form URL-decode: parse a urlencoded body back into a Form (Body::as<Form>).
// ---------------------------------------------------------------------------
void
BM_Body_FormDecode(benchmark::State &state) {
    // Pre-encode the body ONCE (out of the timed loop).
    std::string encoded;
    {
        Body seed;
        seed    = make_simple_form();
        encoded = seed.as<std::string>();

        Form probe = seed.as<Form>();
        if (probe.get_first("name").value_or("") != "test_user") {
            state.SkipWithError("form url-decode mismatch");
            return;
        }
    }

    for (auto _ : state) {
        // Per-iteration body construction is the unavoidable setup; pause it so
        // only the as<Form>() decode work is timed.
        state.PauseTiming();
        Body body;
        body = encoded;
        state.ResumeTiming();

        Form form = body.as<Form>();
        benchmark::DoNotOptimize(form);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(encoded.size()));
    state.SetItemsProcessed(state.iterations());
}

// ---------------------------------------------------------------------------
// Multipart parse: the boundary-lookalike worst case (multi-callback reassembly).
// ---------------------------------------------------------------------------
void
BM_Body_MultipartParse(benchmark::State &state) {
    const std::string &wire = make_tricky_multipart_wire();

    {
        Body probe;
        probe               = wire;
        Multipart parsed_mp = probe.as<Multipart>();
        if (parsed_mp.parts().size() != 1u) {
            state.SkipWithError("multipart parse mismatch (expected exactly 1 part)");
            return;
        }
    }

    for (auto _ : state) {
        state.PauseTiming();
        Body body;
        body = wire;
        state.ResumeTiming();

        Multipart mp = body.as<Multipart>();
        benchmark::DoNotOptimize(mp);
    }

    state.SetBytesProcessed(state.iterations() * static_cast<std::int64_t>(wire.size()));
    state.SetItemsProcessed(state.iterations());
}

// ---------------------------------------------------------------------------
// JSON round-trip: assign a wide json body (serialize) then parse it back.
// ---------------------------------------------------------------------------
void
BM_Body_JsonRoundTrip(benchmark::State &state) {
    const qb::json j = make_wide_json();

    {
        Body probe;
        probe                 = j;
        const qb::json parsed = qb::json::parse(probe.as<std::string>());
        if (parsed["i64"].get<std::int64_t>() != 1782214248072LL) {
            state.SkipWithError("json body round-trip lost 64-bit fidelity");
            return;
        }
    }

    std::int64_t bytes = 0;
    for (auto _ : state) {
        Body body;
        body            = j;                   // serialize via pipe::put<json>
        qb::json parsed = body.as<qb::json>(); // parse back
        bytes           = static_cast<std::int64_t>(body.size());
        benchmark::DoNotOptimize(parsed); // non-const lvalue (avoids deprecated const-ref overload)
    }

    state.SetBytesProcessed(state.iterations() * bytes);
    state.SetItemsProcessed(state.iterations());
}

} // namespace

BENCHMARK(BM_Body_FormEncode)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Body_FormDecode)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Body_MultipartParse)->Unit(benchmark::kNanosecond);
BENCHMARK(BM_Body_JsonRoundTrip)->Unit(benchmark::kNanosecond);

BENCHMARK_MAIN();

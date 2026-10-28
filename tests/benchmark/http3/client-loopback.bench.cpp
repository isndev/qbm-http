#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <benchmark/benchmark.h>

#include <qbm/http/http.h>

#include "../client-loopback.h"

namespace http3_client_loopback_bench {

class BenchServer;

class BenchSession : public qb::http3::use<BenchSession>::session<BenchServer> {
public:
    explicit BenchSession(BenchServer &server)
        : session(server) {}
};

class BenchServer : public qb::http3::use<BenchServer>::server<BenchSession> {
public:
    std::atomic<int> connected_events{0};

    void
    on(qb::io::async::quic::event::connected const &) {
        ++connected_events;
    }
};

struct Fixture {
    std::unique_ptr<BenchServer>       server;
    std::shared_ptr<qb::http3::Client> client;
    std::string                        origin;
    bool                               ready = false;

    struct NoSetup {};

    explicit Fixture(NoSetup) {}

    Fixture() {
        const auto [cert, key] = http_client_bench::certificates();
        if (!std::filesystem::exists(cert) || !std::filesystem::exists(key)) {
            return;
        }
        qb::io::async::init();
        const auto port = http_client_bench::free_udp_port();
        if (!port) {
            return;
        }
        origin = "https://127.0.0.1:" + std::to_string(port);
        server = std::make_unique<BenchServer>();
        server->router().get("/bench/:id", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = ctx->path_param("id");
            ctx->complete();
        });
        server->router().compile();
        if (!server->listen(qb::io::uri(origin), cert, key)) {
            return;
        }
        client = connected_client();
        ready  = static_cast<bool>(client);
    }

    std::shared_ptr<qb::http3::Client>
    connected_client() const {
        auto next = qb::http3::make_client(origin);
        next->set_verify_peer(false);
        next->set_max_concurrent_streams(1); // exercise pending-to-active dispatch
        next->set_connect_timeout(std::chrono::seconds(5));
        if (!next->connect(nullptr) || !http_client_bench::pump_until([&] { return next->is_connected(); })) {
            next->disconnect();
            return {};
        }
        return next;
    }

    ~Fixture() {
        if (client) {
            client->disconnect();
        }
        client.reset();
        if (server) {
            server->close();
        }
        server.reset();
        qb::io::async::listener::current.clear();
    }
};

std::vector<qb::http::Request>
requests(int first, int count) {
    std::vector<qb::http::Request> result;
    result.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        result.emplace_back(qb::http::method::GET, qb::io::uri("/bench/" + std::to_string(first + i)));
    }
    return result;
}

bool
valid(const std::vector<qb::http::Response> &responses, int first, int count) {
    if (responses.size() != static_cast<std::size_t>(count)) {
        return false;
    }
    for (int i = 0; i < count; ++i) {
        const auto &response = responses[static_cast<std::size_t>(i)];
        if (response.status() != qb::http::status::OK || response.body().as<std::string>() != std::to_string(first + i)) {
            return false;
        }
    }
    return true;
}

bool
one_request(Fixture &fixture, int id) {
    std::vector<qb::http::Response> responses;
    bool                            done = false;
    if (!fixture.client->push_requests(requests(id, 1), [&](auto result) {
            responses = std::move(result);
            done      = true;
        })) {
        return false;
    }
    if (!http_client_bench::pump_until([&] { return done; })) {
        fixture.client->disconnect();
        return false;
    }
    return valid(responses, id, 1);
}

void
BM_H3_WarmResponseCallbacks(benchmark::State &state) {
    Fixture fixture;
    if (!fixture.ready || !one_request(fixture, 999)) {
        state.SkipWithError("HTTP/3 loopback handshake or response preflight failed");
        return;
    }
    // The warm cell measures 32 responses on each already-connected client. A
    // fresh connection per iteration keeps the old control below its 100-stream
    // correctness defect; the separate continuous-stream preflight exposes it.
    fixture.client->disconnect();
    fixture.client.reset();
    constexpr int kCount = 32;
    int           first  = 1000;
    for (auto _ : state) {
        state.PauseTiming();
        auto client = fixture.connected_client();
        if (!client) {
            state.SkipWithError("HTTP/3 warm callbacks could not open a fresh connection");
            return;
        }
        auto                            work = requests(first, kCount);
        std::vector<qb::http::Response> responses;
        bool                            done = false;
        state.ResumeTiming();
        const bool accepted  = client->push_requests(std::move(work), [&](auto result) {
            responses = std::move(result);
            done      = true;
        });
        const bool completed = accepted && http_client_bench::pump_until([&] { return done; });
        state.PauseTiming();
        const bool correct   = valid(responses, first, kCount);
        const bool connected = client->is_connected();
        if (!completed || !correct || !connected) {
            std::string detail = "HTTP/3 warm callbacks: id=" + std::to_string(first) + " accepted=" + std::to_string(accepted)
                                 + " completed=" + std::to_string(completed) + " correct=" + std::to_string(correct)
                                 + " responses=" + std::to_string(responses.size()) + " connected=" + std::to_string(connected);
            const auto [total, successful, failed] = client->get_stats();
            detail += " totals=" + std::to_string(total) + "/" + std::to_string(successful) + "/" + std::to_string(failed);
            if (!responses.empty()) {
                detail += " first_status=" + std::to_string(static_cast<int>(responses.front().status()));
                detail += " first_body=" + responses.front().body().as<std::string>().substr(0, 80);
            }
            client->disconnect();
            state.SkipWithError(detail.c_str());
            return;
        }
        client->disconnect();
        client.reset();
        first += kCount;
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations() * kCount);
}

void
BM_H3_ContinuousStreamsCorrectness(benchmark::State &state) {
    Fixture fixture;
    if (!fixture.ready || !one_request(fixture, 999)) {
        state.SkipWithError("HTTP/3 continuous-stream handshake or first response failed");
        return;
    }
    constexpr int kMoreStreams = 128;
    const int     connections  = fixture.server->connected_events.load();
    if (connections != 1) {
        state.SkipWithError("HTTP/3 continuous-stream preflight did not start on one connection");
        return;
    }
    for (int i = 0; i < kMoreStreams; ++i) {
        if (!one_request(fixture, 2000 + i) || !fixture.client->is_connected() || fixture.server->connected_events.load() != connections) {
            const std::string detail =
                "HTTP/3 continuous-stream correctness failed after " + std::to_string(i + 1) + " responses on one connection";
            state.SkipWithError(detail.c_str());
            return;
        }
    }
    // This registered case is a correctness probe only. The runner retains its
    // pass/fail verdict and never turns this no-op timing into a speed ratio.
    for (auto _ : state) {
        benchmark::DoNotOptimize(fixture.client->is_connected());
    }
}

void
BM_H3_ExplicitReconnect(benchmark::State &state) {
    Fixture fixture;
    if (!fixture.ready || !one_request(fixture, 999)) {
        state.SkipWithError("HTTP/3 loopback handshake or response preflight failed");
        return;
    }
    // The old implementation may fail this correctness preflight. Such a control
    // has no comparable latency; report the failure instead of a speed ratio.
    fixture.client->disconnect();
    if (!one_request(fixture, 998)) {
        state.SkipWithError("HTTP/3 reconnect preflight failed");
        return;
    }

    int id = 1000;
    for (auto _ : state) {
        state.PauseTiming();
        auto                            work = requests(id, 1);
        std::vector<qb::http::Response> responses;
        bool                            done = false;
        state.ResumeTiming();
        fixture.client->disconnect();
        const bool accepted  = fixture.client->push_requests(std::move(work), [&](auto result) {
            responses = std::move(result);
            done      = true;
        });
        const bool completed = accepted && http_client_bench::pump_until([&] { return done; });
        state.PauseTiming();
        if (!completed || !valid(responses, id, 1) || !fixture.client->is_connected()) {
            fixture.client->disconnect();
            state.SkipWithError("HTTP/3 reconnect did not deliver the expected response");
            return;
        }
        ++id;
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations());
}

// ---- QB-248: the cost of READING the client's statistics snapshot, once per response -------------------------------
//
// The HTTP/3 twin of the HTTP/2 pair (http2/client-loopback.bench.cpp): `Client::get_stats()` copies three counters
// the client always maintains, with no switch, so their maintenance is not measured here (dev/bench/INSTRUMENTS.md);
// the READ is. The work of `WarmResponseCallbacks` -- a fresh connection before every timed iteration, then 32
// distinct GETs at a concurrency limit of one -- admitted by one `push_request()` and answered by one callback per
// response, with no snapshot (Unrequested) and with one `get_stats()` requested and consumed in every response
// callback (Requested). Outside timing, the oracle of every burst: the 32 responses 200 with their ids in order; the
// counters moved by exactly 32 total, 32 successful and 0 failed (two oracle snapshots, in both modes); in Requested
// the i-th callback saw i successes -- `Client::on_http3_response()` counts before it calls back -- so the reads sum
// to 1 + ... + 32 = 528. Connection setup and teardown stay outside timing, as in the reference cell.
using SnapshotStats = std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>;

constexpr int           kSnapshotRequests       = 32;
constexpr std::uint64_t kSnapshotObservationSum = 528; // 1 + 2 + ... + 32: the i-th callback sees i successes

struct SnapshotBurst {
    std::vector<qb::http::Response> responses;
    std::uint64_t                   observation = 0; ///< Requested: the sum over callbacks of (successful - before)
    std::uint64_t                   reads       = 0; ///< Requested: snapshots requested and consumed

    void
    reset() {
        responses.clear();
        observation = 0;
        reads       = 0;
    }
    bool
    complete() const {
        return responses.size() == static_cast<std::size_t>(kSnapshotRequests);
    }
};

/// Admit the burst on `client`: one `push_request()` per GET; the callback stores the response and, in Requested, reads first.
template <bool Snapshot>
bool
admit_snapshot_burst(qb::http3::Client &client, SnapshotBurst &burst, int first, std::uint64_t successful_before) {
    auto work = requests(first, kSnapshotRequests);
    for (auto &request : work) {
        const bool admitted = client.push_request(std::move(request), [&client, &burst, successful_before](qb::http::Response response) {
            if constexpr (Snapshot) {
                const auto [total, successful, failed] = client.get_stats(); // the read under measurement ...
                burst.observation += successful - successful_before;         // ... consumed, never discarded
                burst.reads += total >= successful + failed ? 1u : 0u;       // all three fields read: the counters' own invariant
            } else {
                (void) client; // the same closure in both cells: the pair differs by the read alone
                (void) successful_before;
            }
            burst.responses.push_back(std::move(response));
        });
        if (!admitted)
            return false;
    }
    return true;
}

/// The oracle of one burst, outside timing: the responses, the counter deltas, and the Requested reads' sum.
bool
valid_snapshot_burst(SnapshotBurst const &burst, int first, bool snapshot, SnapshotStats const &before, SnapshotStats const &after) {
    const auto [total_before, successful_before, failed_before] = before;
    const auto [total_after, successful_after, failed_after]    = after;
    return valid(burst.responses, first, kSnapshotRequests) && total_after - total_before == static_cast<std::uint64_t>(kSnapshotRequests)
           && successful_after - successful_before == static_cast<std::uint64_t>(kSnapshotRequests) && failed_after == failed_before
           && burst.reads == (snapshot ? static_cast<std::uint64_t>(kSnapshotRequests) : 0u)
           && burst.observation == (snapshot ? kSnapshotObservationSum : 0u);
}

/// One burst on a fresh connection, outside timing, with both oracles: the preflight of each mode.
template <bool Snapshot>
bool
snapshot_preflight(Fixture &fixture, int first) {
    auto client = fixture.connected_client();
    if (!client)
        return false;
    SnapshotBurst burst;
    burst.responses.reserve(kSnapshotRequests);
    const auto before   = client->get_stats();
    const bool admitted = admit_snapshot_burst<Snapshot>(*client, burst, first, std::get<1>(before));
    const bool complete = admitted && http_client_bench::pump_until([&] { return burst.complete(); });
    const bool valid    = complete && valid_snapshot_burst(burst, first, Snapshot, before, client->get_stats()) && client->is_connected();
    client->disconnect();
    return valid;
}

template <bool Snapshot>
void
measure_h3_stats_snapshot(benchmark::State &state) {
    Fixture fixture;
    if (!fixture.ready || !one_request(fixture, 999)) {
        state.SkipWithError("HTTP/3 loopback handshake or response preflight failed");
        return;
    }
    if (state.range(0) != kSnapshotRequests) {
        state.SkipWithError("HTTP/3 stats snapshot roster requires 32 requests");
        return;
    }
    // As in WarmResponseCallbacks: the fixture's first connection served the preflight request; every burst below
    // runs on a connection of its own, opened and closed outside timing.
    fixture.client->disconnect();
    fixture.client.reset();
    int first = 1000;
    if (!snapshot_preflight<false>(fixture, first) || !snapshot_preflight<true>(fixture, first + kSnapshotRequests)) {
        state.SkipWithError("HTTP/3 stats snapshot pair preflight violated its work/count contract");
        return;
    }
    first += 2 * kSnapshotRequests;
    SnapshotBurst burst;
    burst.responses.reserve(kSnapshotRequests);
    for (auto _ : state) {
        state.PauseTiming();
        auto client = fixture.connected_client();
        if (!client) {
            state.SkipWithError("HTTP/3 stats snapshot could not open a fresh connection");
            return;
        }
        burst.reset();
        const auto before = client->get_stats(); // oracle snapshot 1 of 2, outside timing
        state.ResumeTiming();
        const bool admitted  = admit_snapshot_burst<Snapshot>(*client, burst, first, std::get<1>(before));
        const bool completed = admitted && http_client_bench::pump_until([&] { return burst.complete(); });
        state.PauseTiming();
        const auto after     = client->get_stats(); // oracle snapshot 2 of 2
        const bool connected = client->is_connected();
        if (!completed || !connected || !valid_snapshot_burst(burst, first, Snapshot, before, after)) {
            client->disconnect();
            state.SkipWithError("measured HTTP/3 stats snapshot burst failed responses or counter deltas");
            return;
        }
        client->disconnect();
        client.reset();
        first += kSnapshotRequests;
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations() * kSnapshotRequests);
    state.counters["work_units"]          = static_cast<double>(kSnapshotRequests);
    state.counters["requested_snapshots"] = Snapshot ? static_cast<double>(kSnapshotRequests) : 0.0;
    state.counters["oracle_snapshots"]    = 2.0;
    state.counters["connections"]         = 1.0;
    state.SetLabel("fresh connection per burst outside timing; 32 GETs at concurrency one, one callback per response; snapshot "
                   "requested+consumed per response; counters always on");
}

void
BM_H3_StatsSnapshotUnrequested(benchmark::State &state) {
    measure_h3_stats_snapshot<false>(state);
}

void
BM_H3_StatsSnapshotRequested(benchmark::State &state) {
    measure_h3_stats_snapshot<true>(state);
}

} // namespace http3_client_loopback_bench

namespace http3_data_credit_bench {

using http3_client_loopback_bench::BenchServer;
using http3_client_loopback_bench::Fixture;

constexpr std::size_t kRequestSize  = 160 * 1024;
constexpr std::size_t kResponseSize = 192 * 1024;
constexpr int         kCount        = 32;

std::string
payload(std::string const &id, std::size_t size, char fill) {
    std::string result(size, fill);
    result.replace(0, id.size(), id);
    result.replace(size - id.size(), id.size(), id);
    return result;
}

struct DataBatch {
    std::vector<std::string>    ids;
    std::vector<std::string>    expected_requests;
    std::vector<std::string>    expected_responses;
    std::vector<std::string>    received_ids;
    std::vector<qb::http::Body> received_bodies;
    std::string                 response_length = std::to_string(kResponseSize);
    bool                        overflow        = false;
};

struct DataOutcome {
    std::vector<qb::http::Response> responses;
    bool                            done = false;
};

struct DataFixture : Fixture {
    std::shared_ptr<DataBatch> data = std::make_shared<DataBatch>();

    DataFixture()
        : Fixture(NoSetup{}) {
        const auto [cert, key] = http_client_bench::certificates();
        if (!std::filesystem::exists(cert) || !std::filesystem::exists(key)) {
            return;
        }
        qb::io::async::init();
        const auto port = http_client_bench::free_udp_port();
        if (!port) {
            return;
        }
        origin = "https://127.0.0.1:" + std::to_string(port);
        server = std::make_unique<BenchServer>();
        qb::io::quic::settings flow;
        flow.stream_recv_window          = 256 * 1024;
        flow.connection_recv_window      = 8 * 1024 * 1024;
        flow.max_stream_data_bidi_local  = 256 * 1024;
        flow.max_stream_data_bidi_remote = 256 * 1024;
        flow.max_stream_data_uni         = 256 * 1024;
        server->set_settings(flow);
        server->router().post("/bench-data/:id", [batch = data](auto ctx) {
            const auto index = batch->received_ids.size();
            if (index >= batch->expected_responses.size()) {
                batch->overflow = true;
                ctx->bad_request("Unexpected DATA request");
                return;
            }
            const auto &id = ctx->path_param("id");
            batch->received_ids.push_back(id);
            // Keep the reassembled bytes for validation while timing is paused.
            // Moving Body avoids adding a full request copy to the measured path.
            batch->received_bodies.push_back(std::move(ctx->request().body()));
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("x-bench-id", id);
            ctx->response().set_header("content-length", batch->response_length);
            ctx->response().body() = batch->expected_responses[index];
            ctx->complete();
        });
        server->router().compile();
        ready = server->listen(qb::io::uri(origin), cert, key);
    }

    std::shared_ptr<qb::http3::Client>
    connected_client() const {
        const int before = server->connected_events.load();
        auto      next   = qb::http3::make_client(origin);
        next->set_settings(server->settings());
        next->set_verify_peer(false);
        next->set_max_concurrent_streams(1);
        next->set_connect_timeout(std::chrono::seconds(5));
        if (!next->connect(nullptr)
            || !http_client_bench::pump_until([&] { return next->is_connected() && server->connected_events.load() == before + 1; })) {
            next->disconnect();
            return {};
        }
        return next;
    }

    std::vector<qb::http::Request>
    prepare(std::uint64_t first, int count) {
        data->ids.clear();
        data->expected_requests.clear();
        data->expected_responses.clear();
        data->received_ids.clear();
        data->received_bodies.clear();
        data->overflow  = false;
        const auto size = static_cast<std::size_t>(count);
        data->ids.reserve(size);
        data->expected_requests.reserve(size);
        data->expected_responses.reserve(size);
        data->received_ids.reserve(size);
        data->received_bodies.reserve(size);
        std::vector<qb::http::Request> work;
        work.reserve(size);
        for (int i = 0; i < count; ++i) {
            auto id = std::to_string(first + static_cast<std::uint64_t>(i));
            data->ids.push_back(id);
            data->expected_requests.push_back(payload(id, kRequestSize, 'Q'));
            data->expected_responses.push_back(payload(id, kResponseSize, 'R'));
            work.emplace_back(qb::http::method::POST, qb::io::uri("/bench-data/" + id));
            work.back().body() = data->expected_requests.back();
            work.back().set_header("content-length", std::to_string(kRequestSize));
        }
        return work;
    }

    bool
    valid(std::shared_ptr<qb::http3::Client> const &next, DataOutcome const &outcome, int connections) const {
        const auto count                       = data->ids.size();
        const auto [total, successful, failed] = next->get_stats();
        if (!outcome.done || data->overflow || outcome.responses.size() != count || data->received_ids.size() != count
            || data->received_bodies.size() != count || !next->is_connected() || !server->is_open()
            || server->connected_events.load() != connections || total != count || successful != count || failed != 0
            || next->get_active_request_count() != 0) {
            return false;
        }
        for (std::size_t i = 0; i < count; ++i) {
            const auto &response = outcome.responses[i];
            if (data->received_ids[i] != data->ids[i] || data->received_bodies[i].as<std::string>() != data->expected_requests[i]
                || response.status() != qb::http::status::OK || response.header("x-bench-id") != data->ids[i]
                || response.body().as<std::string>() != data->expected_responses[i]) {
                return false;
            }
        }
        return true;
    }
};

bool
complete_batch(std::shared_ptr<qb::http3::Client> const &client, std::vector<qb::http::Request> work,
               std::shared_ptr<DataOutcome> const &outcome) {
    const bool accepted = client->push_requests(std::move(work), [outcome](auto responses) {
        outcome->responses = std::move(responses);
        outcome->done      = true;
    });
    return accepted && http_client_bench::pump_until([outcome] { return outcome->done; }, std::chrono::seconds(10));
}

void
BM_H3_WarmDataCredit(benchmark::State &state) {
    DataFixture fixture;
    if (!fixture.ready) {
        state.SkipWithError("HTTP/3 DATA loopback server setup failed");
        return;
    }
    {
        auto      work   = fixture.prepare(999, 1);
        const int before = fixture.server->connected_events.load();
        auto      client = fixture.connected_client();
        if (!client) {
            state.SkipWithError("HTTP/3 DATA loopback handshake preflight failed");
            return;
        }
        const int  connections = fixture.server->connected_events.load();
        auto       outcome     = std::make_shared<DataOutcome>();
        const bool completed   = complete_batch(client, std::move(work), outcome);
        const bool correct     = connections == before + 1 && fixture.valid(client, *outcome, connections);
        client->disconnect();
        if (!completed || !correct) {
            state.SkipWithError("HTTP/3 DATA loopback response preflight failed");
            return;
        }
    }
    // Per fresh, established connection: 5 MiB request DATA and 6 MiB response
    // DATA fit inside each side's initial 8 MiB connection credit. Each body also
    // fits inside 256 KiB stream credit, so the pre-fix control can finish the
    // same valid work. Crossing exhausted small windows is a separate proof.
    std::uint64_t first = 1000;
    for (auto _ : state) {
        state.PauseTiming();
        auto      work   = fixture.prepare(first, kCount);
        const int before = fixture.server->connected_events.load();
        auto      client = fixture.connected_client();
        if (!client) {
            state.SkipWithError("HTTP/3 DATA callbacks could not open a fresh connection");
            return;
        }
        const int connections = fixture.server->connected_events.load();
        if (connections != before + 1) {
            client->disconnect();
            state.SkipWithError("HTTP/3 DATA batch did not establish exactly one connection");
            return;
        }
        auto outcome = std::make_shared<DataOutcome>();
        state.ResumeTiming();
        const bool completed = complete_batch(client, std::move(work), outcome);
        state.PauseTiming();
        const bool correct                     = fixture.valid(client, *outcome, connections);
        const auto [total, successful, failed] = client->get_stats();
        client->disconnect();
        client.reset();
        if (!completed || !correct) {
            const std::string detail = "HTTP/3 DATA callbacks: id=" + std::to_string(first) + " completed=" + std::to_string(completed)
                                       + " correct=" + std::to_string(correct) + " responses=" + std::to_string(outcome->responses.size())
                                       + " requests=" + std::to_string(fixture.data->received_ids.size()) + " totals=" + std::to_string(total)
                                       + "/" + std::to_string(successful) + "/" + std::to_string(failed);
            state.SkipWithError(detail.c_str());
            return;
        }
        outcome.reset();
        first += kCount;
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations() * kCount);
    state.SetBytesProcessed(state.iterations() * kCount * static_cast<std::int64_t>(kRequestSize + kResponseSize));
}

} // namespace http3_data_credit_bench

using http3_client_loopback_bench::BM_H3_ContinuousStreamsCorrectness;
using http3_client_loopback_bench::BM_H3_ExplicitReconnect;
using http3_client_loopback_bench::BM_H3_StatsSnapshotRequested;
using http3_client_loopback_bench::BM_H3_StatsSnapshotUnrequested;
using http3_client_loopback_bench::BM_H3_WarmResponseCallbacks;
using http3_data_credit_bench::BM_H3_WarmDataCredit;

BENCHMARK(BM_H3_WarmResponseCallbacks)->Unit(benchmark::kMicrosecond)->UseRealTime();
BENCHMARK(BM_H3_StatsSnapshotUnrequested)
    ->Arg(http3_client_loopback_bench::kSnapshotRequests)
    ->ArgName("requests")
    ->Unit(benchmark::kMicrosecond)
    ->UseRealTime();
BENCHMARK(BM_H3_StatsSnapshotRequested)
    ->Arg(http3_client_loopback_bench::kSnapshotRequests)
    ->ArgName("requests")
    ->Unit(benchmark::kMicrosecond)
    ->UseRealTime();
BENCHMARK(BM_H3_WarmDataCredit)->Unit(benchmark::kMicrosecond)->UseRealTime();
BENCHMARK(BM_H3_ContinuousStreamsCorrectness)->Iterations(1);
BENCHMARK(BM_H3_ExplicitReconnect)->Unit(benchmark::kMicrosecond);
BENCHMARK_MAIN();

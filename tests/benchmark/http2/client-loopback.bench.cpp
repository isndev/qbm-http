#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <benchmark/benchmark.h>

#include <qbm/http/2/client.h>
#include <qbm/http/2/http2.h>
#include <qbm/http/http.h>

#include <qb/io/tcp/listener.h>

#include "../client-loopback.h"

namespace {

class BenchServer;

class BenchSession : public qb::http2::use<BenchSession>::session<BenchServer> {
public:
    explicit BenchSession(BenchServer &server)
        : session(server) {}
};

class BenchServer : public qb::http2::use<BenchServer>::server<BenchSession> {
public:
    using Context = qb::http::Context<BenchSession>;

    std::vector<std::shared_ptr<Context>> held;
    std::vector<int>                      post_hooks;
    int                                   routed     = 0;
    int                                   post_total = 0;
    bool                                  valid_ids  = true;

    explicit BenchServer(int hold_slots = 0)
        : held(static_cast<std::size_t>(hold_slots))
        , post_hooks(static_cast<std::size_t>(hold_slots), 0) {
        router().get("/bench/:id", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = ctx->path_param("id");
            ctx->complete();
        });
        if (hold_slots > 0) {
            router().get("/hold/:id", [this](auto ctx) {
                const auto id = ctx->template path_param<int>("id");
                if (!id || *id < 0 || static_cast<std::size_t>(*id) >= held.size() || held[static_cast<std::size_t>(*id)]) {
                    valid_ids = false;
                    ctx->text("invalid hold ID");
                    return;
                }
                held[static_cast<std::size_t>(*id)] = std::move(ctx);
                ++routed;
            });
            router().add_lifecycle_hook([this](auto &ctx, qb::http::HookPoint point) {
                if (point != qb::http::HookPoint::POST_RESPONSE_SEND || ctx.request().uri().path().substr(0, 6) != "/hold/") {
                    return;
                }
                const auto id = ctx.template path_param<int>("id");
                if (!id || *id < 0 || static_cast<std::size_t>(*id) >= post_hooks.size()) {
                    valid_ids = false;
                    return;
                }
                ++post_hooks[static_cast<std::size_t>(*id)];
                ++post_total;
            });
        }
        router().compile();
    }
};

struct Fixture {
    std::unique_ptr<BenchServer>       server;
    std::shared_ptr<qb::http2::Client> client;
    bool                               ready     = false;
    bool                               connected = false;

    explicit Fixture(int hold_slots = 0, int concurrency = 1) {
        const auto [cert, key] = http_client_bench::certificates();
        if (!std::filesystem::exists(cert) || !std::filesystem::exists(key)) {
            return;
        }
        qb::io::async::init();
        server = std::make_unique<BenchServer>(hold_slots);
        server->transport().init(qb::io::ssl::Context::server(cert.string(), key.string()).alpn({"h2", "http/1.1"}));
        if (server->transport().listen_v4(0, "127.0.0.1") != 0) {
            return;
        }
        server->start();
        const auto port = server->transport().local_endpoint().port();
        if (!port) {
            return;
        }
        client = qb::http2::make_client("https://localhost:" + std::to_string(port));
        client->set_verify_peer(false);
        client->set_max_concurrent_streams(static_cast<std::size_t>(concurrency)); // existing bursts use one pending stream
        client->set_connect_timeout(std::chrono::seconds(5));
        if (!client->connect([this](bool ok, const std::string &) { connected = ok; })
            || !http_client_bench::pump_until([&] { return connected; })) {
            return;
        }
        ready = client->is_connected();
    }

    ~Fixture() {
        if (client) {
            client->disconnect();
        }
        client.reset();
        if (server && !server->held.empty()) {
            server->held.clear();
            server->sessions().clear();
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

struct DrainReplies {
    std::vector<qb::http::Response> responses;
    std::vector<int>                calls;

    explicit DrainReplies(int count)
        : responses(static_cast<std::size_t>(count))
        , calls(static_cast<std::size_t>(count), 0) {}

    [[nodiscard]] bool
    valid(int id) const {
        const auto index = static_cast<std::size_t>(id);
        return calls[index] == 1 && responses[index].status() == qb::http::status::OK
               && responses[index].body().as<std::string>() == std::to_string(id);
    }
};

// Spread K completions through the request IDs. Hash-table traversal order is
// deliberately not inferred from these IDs; a profile must establish visits.
bool
complete_in_measured_drain(int index, int requests_per_wave, int complete_per_wave) {
    const int position = (index + requests_per_wave / 2) % requests_per_wave;
    return ((position + 1) * complete_per_wave) / requests_per_wave != (position * complete_per_wave) / requests_per_wave;
}

// Correctness-equivalent response work on the published base and candidate.
// The base retains Contexts after EOS, so post_hooks/reclaimed are diagnostic
// counters, not a requirement that both roles perform the same lifecycle work.
void
BM_H2_ValidDrain(benchmark::State &state) {
    const int    requests_per_wave = static_cast<int>(state.range(0));
    const int    complete_per_wave = static_cast<int>(state.range(1));
    const int    waves             = static_cast<int>(state.range(2));
    const int    open_anchors      = static_cast<int>(state.range(3));
    const int    total_requests    = open_anchors + requests_per_wave * waves;
    const int    concurrency       = open_anchors + requests_per_wave;
    std::int64_t queued_bytes      = 0;
    std::int64_t post_on_drain     = 0;
    std::int64_t reclaimed         = 0;

    for (auto _ : state) {
        state.PauseTiming();
        {
            Fixture fixture(total_requests, concurrency);
            if (!fixture.ready) {
                state.SkipWithError("HTTP/2 drain loopback TLS handshake failed or certificate missing");
                return;
            }
            auto                                             replies = std::make_shared<DrainReplies>(total_requests);
            std::vector<std::weak_ptr<BenchServer::Context>> weak_closed(static_cast<std::size_t>(total_requests));
            auto                                             push = [&](int id) {
                return fixture.client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/hold/" + std::to_string(id))},
                                                    [replies, id](auto response) {
                                                        const auto index          = static_cast<std::size_t>(id);
                                                        replies->responses[index] = std::move(response);
                                                        ++replies->calls[index];
                                                    });
            };

            for (int id = 0; id < open_anchors; ++id) {
                if (!push(id)) {
                    state.SkipWithError("HTTP/2 drain anchor request rejected");
                    return;
                }
            }
            if (!http_client_bench::pump_until([&] { return fixture.server->routed == open_anchors; }) || !fixture.server->valid_ids) {
                state.SkipWithError("HTTP/2 drain anchor did not route");
                return;
            }

            std::shared_ptr<BenchSession> session;
            for (int wave = 0; wave < waves; ++wave) {
                if (session)
                    session->start();
                const int first = open_anchors + wave * requests_per_wave;
                for (int i = 0; i < requests_per_wave; ++i) {
                    if (!push(first + i)) {
                        state.SkipWithError("HTTP/2 drain request rejected");
                        return;
                    }
                }
                const int routed_total = first + requests_per_wave;
                if (!http_client_bench::pump_until([&] { return fixture.server->routed == routed_total; }) || !fixture.server->valid_ids) {
                    state.SkipWithError("HTTP/2 drain request did not route");
                    return;
                }
                if (!session)
                    session = fixture.server->held.front()->session();
                if (!session || !fixture.client->is_connected()) {
                    state.SkipWithError("HTTP/2 drain session disconnected before output");
                    return;
                }
                session->stop();
                if (session->out().size() != 0) {
                    state.SkipWithError("HTTP/2 drain setup left old output queued");
                    return;
                }
                auto *protocol = static_cast<BenchSession::Http2Protocol *>(session->protocol());
                if (!protocol) {
                    state.SkipWithError("HTTP/2 drain protocol missing");
                    return;
                }
                const int post_before = fixture.server->post_total;
                for (int i = 0; i < requests_per_wave; ++i) {
                    const int id  = first + i;
                    auto     &ctx = fixture.server->held[static_cast<std::size_t>(id)];
                    if (!ctx || ctx->session() != session || ctx->is_completed()) {
                        state.SkipWithError("HTTP/2 drain setup lost or completed a context");
                        return;
                    }
                    const auto stream_id = static_cast<std::uint32_t>(ctx->request().stream_id);
                    if (protocol->is_stream_closed(stream_id)) {
                        state.SkipWithError("HTTP/2 drain setup has a closed native stream");
                        return;
                    }
                    if (complete_in_measured_drain(i, requests_per_wave, complete_per_wave)) {
                        weak_closed[static_cast<std::size_t>(id)] = ctx;
                        ctx->text(std::to_string(id));
                        if (!ctx->is_completed() || !protocol->is_stream_closed(stream_id)) {
                            state.SkipWithError("HTTP/2 drain response did not close its native stream");
                            return;
                        }
                        ctx.reset();
                    }
                }
                const auto bytes = session->out().size();
                if (!bytes || fixture.server->post_total != post_before) {
                    state.SkipWithError("HTTP/2 drain output or pre-drain hook precondition failed");
                    return;
                }
                const auto written_before = session->bytes_written();
                session->start();
                session->ready_to_write();
                state.ResumeTiming();
                qb::io::async::run(EVRUN_NOWAIT);
                state.PauseTiming();
                session->stop();
                if (session->out().size() != 0 || session->bytes_written() - written_before != bytes) {
                    state.SkipWithError("HTTP/2 drain did not write exactly the queued bytes in one owner-loop turn");
                    return;
                }
                queued_bytes += static_cast<std::int64_t>(bytes);

                int expired = 0;
                for (int i = 0; i < requests_per_wave; ++i) {
                    if (!complete_in_measured_drain(i, requests_per_wave, complete_per_wave))
                        continue;
                    const int id = first + i;
                    expired += weak_closed[static_cast<std::size_t>(id)].expired() ? 1 : 0;
                }
                const int post_delta = fixture.server->post_total - post_before;
                // Old EOS does not reclaim; candidate EOS does. Only 0 or all K is
                // coherent here, and both must still deliver every valid response.
                if (!fixture.server->valid_ids || (post_delta != 0 && post_delta != complete_per_wave) || expired != post_delta) {
                    state.SkipWithError("HTTP/2 drain lifecycle observation was partial or inconsistent");
                    return;
                }
                post_on_drain += post_delta;
                reclaimed += expired;
                if (!http_client_bench::pump_until([&] {
                        for (int i = 0; i < requests_per_wave; ++i) {
                            if (complete_in_measured_drain(i, requests_per_wave, complete_per_wave)
                                && replies->calls[static_cast<std::size_t>(first + i)] != 1)
                                return false;
                        }
                        return true;
                    })) {
                    state.SkipWithError("HTTP/2 drain timed out waiting for valid replies");
                    return;
                }
                for (int i = 0; i < requests_per_wave; ++i) {
                    const int id = first + i;
                    if (complete_in_measured_drain(i, requests_per_wave, complete_per_wave)) {
                        if (!replies->valid(id) || fixture.server->post_hooks[static_cast<std::size_t>(id)] != (post_delta ? 1 : 0)) {
                            state.SkipWithError("HTTP/2 drain lost or corrupted a completed reply");
                            return;
                        }
                    } else if (replies->calls[static_cast<std::size_t>(id)] != 0
                               || fixture.server->post_hooks[static_cast<std::size_t>(id)] != 0
                               || !fixture.server->held[static_cast<std::size_t>(id)]
                               || fixture.server->held[static_cast<std::size_t>(id)]->is_completed()) {
                        state.SkipWithError("HTTP/2 drain completed an open control early");
                        return;
                    }
                }
            }

            // Finish every held-open control outside timing, including the four
            // anchors in the 8 x 32 = 256 cumulative case.
            session->start();
            for (int id = 0; id < total_requests; ++id) {
                auto &ctx = fixture.server->held[static_cast<std::size_t>(id)];
                if (ctx) {
                    ctx->text(std::to_string(id));
                    ctx.reset();
                }
            }
            if (!http_client_bench::pump_until([&] {
                    for (int id = 0; id < total_requests; ++id) {
                        if (replies->calls[static_cast<std::size_t>(id)] != 1)
                            return false;
                    }
                    return true;
                })
                || !fixture.client->is_connected()) {
                state.SkipWithError("HTTP/2 drain open controls did not finish");
                return;
            }
            for (int id = 0; id < total_requests; ++id) {
                if (!replies->valid(id)) {
                    state.SkipWithError("HTTP/2 drain final response checksum failed");
                    return;
                }
            }
        }
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations() * complete_per_wave * waves);
    state.counters["queued_bytes/op"]  = static_cast<double>(queued_bytes) / static_cast<double>(state.iterations());
    state.counters["post_on_drain/op"] = static_cast<double>(post_on_drain) / static_cast<double>(state.iterations());
    state.counters["reclaimed/op"]     = static_cast<double>(reclaimed) / static_cast<double>(state.iterations());
}

void
BM_H2_WarmPendingBurst(benchmark::State &state) {
    Fixture fixture;
    if (!fixture.ready) {
        state.SkipWithError("HTTP/2 loopback TLS handshake failed or certificate missing");
        return;
    }
    constexpr int kCount = 32;
    int           first  = 1000;
    for (auto _ : state) {
        state.PauseTiming();
        auto                            work = requests(first, kCount);
        std::vector<qb::http::Response> responses;
        bool                            done = false;
        state.ResumeTiming();
        const bool accepted  = fixture.client->push_requests(std::move(work), [&](auto result) {
            responses = std::move(result);
            done      = true;
        });
        const bool completed = accepted && http_client_bench::pump_until([&] { return done; });
        state.PauseTiming();
        if (!completed || !valid(responses, first, kCount)) {
            fixture.client->disconnect();
            state.SkipWithError("HTTP/2 pending burst lost or corrupted a response");
            return;
        }
        first += kCount;
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations() * kCount);
}

void
BM_H2_BatchCallbackRequeue(benchmark::State &state) {
    Fixture fixture;
    if (!fixture.ready) {
        state.SkipWithError("HTTP/2 loopback TLS handshake failed or certificate missing");
        return;
    }
    constexpr int kCount = 8;
    int           first  = 1000;
    for (auto _ : state) {
        state.PauseTiming();
        auto                            initial = requests(first, kCount);
        std::vector<qb::http::Response> first_responses;
        std::vector<qb::http::Response> second_responses;
        bool                            accepted_followup = false;
        bool                            done              = false;
        state.ResumeTiming();
        const bool accepted = fixture.client->push_requests(std::move(initial), [&](auto result) {
            first_responses   = std::move(result);
            accepted_followup = fixture.client->push_requests(requests(first + kCount, kCount), [&](auto followup) {
                second_responses = std::move(followup);
                done             = true;
            });
        });
        const bool completed =
            accepted && http_client_bench::pump_until([&] { return done || (!accepted_followup && !first_responses.empty()); });
        state.PauseTiming();
        if (!completed || !accepted_followup || !valid(first_responses, first, kCount) || !valid(second_responses, first + kCount, kCount)) {
            fixture.client->disconnect();
            state.SkipWithError("HTTP/2 batch callback requeue lost or corrupted a response");
            return;
        }
        first += 2 * kCount;
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations() * 2 * kCount);
}

// ---- QB-248: the cost of READING the client's statistics snapshot, once per response -------------------------------
//
// `Client::get_stats()` copies three counters the client always maintains (`_total_requests`, `_successful_requests`,
// `_failed_requests`): there is no switch, so the maintenance of the counters -- three increments a request -- has no
// honest "off" and is not measured here (dev/bench/INSTRUMENTS.md says so). What a program pays to READ them is
// measurable: the burst of `WarmPendingBurst` -- 32 distinct GETs admitted at once at a concurrency limit of one --
// admitted by one `push_request()` and answered by one callback per response, so that a read has a place, with no
// snapshot (Unrequested) and with one `get_stats()` requested and consumed in every response callback (Requested).
// Outside timing, the oracle of every burst: the 32 responses 200 with their ids in order; the counters moved by
// exactly 32 total, 32 successful and 0 failed (two oracle snapshots, in both modes); and in Requested the i-th
// callback saw i successes -- `Client::complete_request()` counts before it calls back -- so the reads sum to
// 1 + ... + 32 = 528, a sum a skipped or misplaced read cannot forge.
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

/// Admit the burst: one `push_request()` per GET; the callback stores the response and, in Requested, reads first.
template <bool Snapshot>
bool
admit_snapshot_burst(Fixture &fixture, SnapshotBurst &burst, int first, std::uint64_t successful_before) {
    auto work = requests(first, kSnapshotRequests);
    for (auto &request : work) {
        const bool admitted =
            fixture.client->push_request(std::move(request), [&fixture, &burst, successful_before](qb::http::Response response) {
                if constexpr (Snapshot) {
                    const auto [total, successful, failed] = fixture.client->get_stats(); // the read under measurement ...
                    burst.observation += successful - successful_before;                  // ... consumed, never discarded
                    burst.reads += total >= successful + failed ? 1u : 0u;                // all three fields read: the counters' own invariant
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

/// One burst outside timing with both oracles: the preflight of each mode before the measured loop.
template <bool Snapshot>
bool
snapshot_preflight(Fixture &fixture, int first) {
    SnapshotBurst burst;
    burst.responses.reserve(kSnapshotRequests);
    const auto before   = fixture.client->get_stats();
    const bool admitted = admit_snapshot_burst<Snapshot>(fixture, burst, first, std::get<1>(before));
    const bool complete = admitted && http_client_bench::pump_until([&] { return burst.complete(); });
    const bool valid    = complete && valid_snapshot_burst(burst, first, Snapshot, before, fixture.client->get_stats());
    if (!valid)
        fixture.client->disconnect(); // a pending callback, if any, fires now, into a burst still alive
    return valid;
}

template <bool Snapshot>
void
measure_h2_stats_snapshot(benchmark::State &state) {
    Fixture fixture;
    if (!fixture.ready) {
        state.SkipWithError("HTTP/2 loopback TLS handshake failed or certificate missing");
        return;
    }
    if (state.range(0) != kSnapshotRequests) {
        state.SkipWithError("HTTP/2 stats snapshot roster requires 32 requests");
        return;
    }
    int first = 1000;
    if (!snapshot_preflight<false>(fixture, first) || !snapshot_preflight<true>(fixture, first + kSnapshotRequests)) {
        fixture.client->disconnect();
        state.SkipWithError("HTTP/2 stats snapshot pair preflight violated its work/count contract");
        return;
    }
    first += 2 * kSnapshotRequests;
    SnapshotBurst burst;
    burst.responses.reserve(kSnapshotRequests);
    for (auto _ : state) {
        state.PauseTiming();
        burst.reset();
        const auto before = fixture.client->get_stats(); // oracle snapshot 1 of 2, outside timing
        state.ResumeTiming();
        const bool admitted  = admit_snapshot_burst<Snapshot>(fixture, burst, first, std::get<1>(before));
        const bool completed = admitted && http_client_bench::pump_until([&] { return burst.complete(); });
        state.PauseTiming();
        const auto after = fixture.client->get_stats(); // oracle snapshot 2 of 2
        if (!completed || !valid_snapshot_burst(burst, first, Snapshot, before, after)) {
            fixture.client->disconnect();
            state.SkipWithError("measured HTTP/2 stats snapshot burst failed responses or counter deltas");
            return;
        }
        first += kSnapshotRequests;
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations() * kSnapshotRequests);
    state.counters["work_units"]          = static_cast<double>(kSnapshotRequests);
    state.counters["requested_snapshots"] = Snapshot ? static_cast<double>(kSnapshotRequests) : 0.0;
    state.counters["oracle_snapshots"]    = 2.0;
    state.counters["connections"]         = 1.0;
    state.SetLabel(
        "32 pending GETs at concurrency one, one callback per response; snapshot requested+consumed per response; counters always on");
}

void
BM_H2_StatsSnapshotUnrequested(benchmark::State &state) {
    measure_h2_stats_snapshot<false>(state);
}

void
BM_H2_StatsSnapshotRequested(benchmark::State &state) {
    measure_h2_stats_snapshot<true>(state);
}

} // namespace

BENCHMARK(BM_H2_WarmPendingBurst)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_H2_BatchCallbackRequeue)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_H2_StatsSnapshotUnrequested)->Arg(kSnapshotRequests)->ArgName("requests")->Unit(benchmark::kMicrosecond)->UseRealTime();
BENCHMARK(BM_H2_StatsSnapshotRequested)->Arg(kSnapshotRequests)->ArgName("requests")->Unit(benchmark::kMicrosecond)->UseRealTime();
BENCHMARK(BM_H2_ValidDrain)
    ->Args({1, 1, 1, 0})
    ->Args({8, 1, 1, 0})
    ->Args({8, 4, 1, 0})
    ->Args({32, 1, 1, 0})
    ->Args({32, 4, 1, 0})
    ->Args({32, 16, 1, 0})
    ->Args({50, 1, 1, 0})
    ->Args({50, 7, 1, 0})
    ->Args({50, 25, 1, 0})
    ->Args({32, 32, 8, 4}) // 256 completed in eight waves, never 256 active streams
    ->ArgNames({"requests", "closed", "waves", "anchors"})
    ->Unit(benchmark::kMicrosecond);
BENCHMARK_MAIN();

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <benchmark/benchmark.h>

#include <qbm/http/http.h>

#include "../client-loopback.h"

namespace {

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

} // namespace

BENCHMARK(BM_H3_WarmResponseCallbacks)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_H3_ContinuousStreamsCorrectness)->Iterations(1);
BENCHMARK(BM_H3_ExplicitReconnect)->Unit(benchmark::kMicrosecond);
BENCHMARK_MAIN();

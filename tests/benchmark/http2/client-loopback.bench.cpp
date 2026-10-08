#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
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
    BenchServer() {
        router().get("/bench/:id", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = ctx->path_param("id");
            ctx->complete();
        });
        router().compile();
    }
};

struct Fixture {
    std::unique_ptr<BenchServer>       server;
    std::shared_ptr<qb::http2::Client> client;
    bool                               ready     = false;
    bool                               connected = false;

    Fixture() {
        const auto [cert, key] = http_client_bench::certificates();
        if (!std::filesystem::exists(cert) || !std::filesystem::exists(key)) {
            return;
        }
        qb::io::async::init();
        server = std::make_unique<BenchServer>();
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
        client->set_max_concurrent_streams(1); // every burst takes the pending queue
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

} // namespace

BENCHMARK(BM_H2_WarmPendingBurst)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_H2_BatchCallbackRequeue)->Unit(benchmark::kMicrosecond);
BENCHMARK_MAIN();

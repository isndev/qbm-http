/**
 * @file qbm/http/tests/benchmark/http1/access-log-loopback.bench.cpp
 * @brief Real persistent HTTP requests with access logging disabled, common or JSON (Huly QB-1106).
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */
#include <benchmark/benchmark.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <qbm/http/1.1/client.h>
#include <qbm/http/http.h>
#include <qbm/http/middleware/access_log.h>
#include "../client-loopback.h"

namespace access_log_loopback_bench {
constexpr int batch_size = 32;

struct Fixture {
    std::unique_ptr<qb::http::Server<>> server;
    std::shared_ptr<qb::http1::Client>  client;
    std::uint64_t                       routed               = 0;
    std::uint64_t                       logged               = 0;
    bool                                valid_lines          = true;
    bool                                ready                = false;
    bool                                connection_completed = false;
    bool                                connected            = false;
    std::string                         failure_message;

    explicit Fixture(int format) {
        qb::io::async::init();
        server = qb::http::make_server();
        server->router().get("/bench/:id", [this](auto ctx) {
            ++routed;
            ctx->text(ctx->path_param("id"));
        });
        if (format) {
            server->router().add_observer(std::make_shared<qb::http::AccessLog<qb::http::DefaultSession>>(
                [this](std::string_view line) {
                    ++logged;
                    valid_lines = valid_lines && line.find("127.0.0.1") != std::string_view::npos;
                    benchmark::DoNotOptimize(line.data());
                    benchmark::DoNotOptimize(line.size());
                },
                format == 1 ? qb::http::access_log_format::common : qb::http::access_log_format::json));
        }
        server->router().compile();
        if (server->transport().listen_v4(0, "127.0.0.1") != 0) {
            failure_message = "listen errno=" + std::to_string(qb::io::socket::get_last_errno());
            return;
        }
        server->start();
        client = qb::http1::make_client("http://127.0.0.1:" + std::to_string(server->transport().local_endpoint().port()));
        client->set_auto_reconnect(false);
        if (!client->connect([this](bool ok, const std::string &error) {
                connected            = ok;
                connection_completed = true;
                if (!ok)
                    failure_message = error;
            }))
            return;
        ready = http_client_bench::pump_until([this] { return connection_completed; }) && connected;
    }

    ~Fixture() {
        if (client)
            client->disconnect();
        client.reset();
        server.reset();
        qb::io::async::listener::current.clear();
    }
};

std::vector<qb::http::Request>
requests(int first, int count = batch_size) {
    std::vector<qb::http::Request> result;
    result.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        result.emplace_back(qb::http::method::GET, qb::io::uri("/bench/" + std::to_string(first + i)));
        result.back().set_header("User-Agent", "qb access-log comparison");
    }
    return result;
}

bool
valid(const std::vector<qb::http::Response> &responses, int first, int count = batch_size) {
    if (responses.size() != static_cast<std::size_t>(count))
        return false;
    for (int i = 0; i < count; ++i) {
        const auto &response = responses[static_cast<std::size_t>(i)];
        if (response.status() != qb::http::status::OK || response.body().as<std::string>() != std::to_string(first + i))
            return false;
    }
    return true;
}

void
BM_Http1_AccessLogWarm(benchmark::State &state) {
    const int format = static_cast<int>(state.range(0));
    Fixture   fixture(format);
    if (!fixture.ready) {
        state.SkipWithError("HTTP/1 access-log connection failed");
        return;
    }
    struct Replies {
        std::vector<qb::http::Response> responses;
        bool                            done = false;
    };
    auto replies = std::make_shared<Replies>();
    if (!fixture.client->push_requests(requests(0),
                                       [replies](auto r) {
                                           replies->responses = std::move(r);
                                           replies->done      = true;
                                       })
        || !http_client_bench::pump_until([&] { return replies->done; }) || !valid(replies->responses, 0)) {
        state.SkipWithError("HTTP/1 access-log preflight did not deliver all responses");
        return;
    }
    if (fixture.server->sessions().size() != 1) {
        state.SkipWithError("HTTP/1 warm preflight did not retain exactly one connection");
        return;
    }
    const auto    connection_id = fixture.server->sessions().cbegin()->first;
    std::uint64_t completed     = batch_size;
    int           first         = batch_size;
    for (auto _ : state) {
        state.PauseTiming();
        auto work = requests(first);
        replies->responses.clear();
        replies->done = false;
        state.ResumeTiming();
        const bool accepted = fixture.client->push_requests(std::move(work), [replies](auto r) {
            replies->responses = std::move(r);
            replies->done      = true;
        });
        const bool received = accepted && http_client_bench::pump_until([&] { return replies->done; });
        state.PauseTiming();
        completed += batch_size;
        if (!received || !valid(replies->responses, first) || !fixture.client->is_connected() || !fixture.valid_lines
            || fixture.routed != completed || fixture.logged != (format ? completed : 0) || fixture.server->sessions().size() != 1
            || fixture.server->sessions().cbegin()->first != connection_id) {
            state.SkipWithError("HTTP/1 access-log request/response/log conservation failed");
            return;
        }
        first = first == batch_size ? 2 * batch_size : batch_size;
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations() * batch_size);
    state.counters["responses"] = static_cast<double>(completed);
    state.counters["log_lines"] = static_cast<double>(fixture.logged);
}
// The first request exercises cache fill; connection setup and teardown are outside its interval.
void
BM_Http1_AccessLogFirstRequest(benchmark::State &state) {
    const int format = static_cast<int>(state.range(0));
    for (auto _ : state) {
        state.PauseTiming();
        {
            Fixture fixture(format);
            if (!fixture.ready) {
                state.SkipWithError(("HTTP/1 first-request connection failed: " + fixture.failure_message).c_str());
                return;
            }
            struct Replies {
                std::vector<qb::http::Response> responses;
                bool                            done = false;
            };
            auto replies = std::make_shared<Replies>();
            auto work    = requests(17, 1);
            state.ResumeTiming();
            const bool accepted = fixture.client->push_requests(std::move(work), [replies](auto result) {
                replies->responses = std::move(result);
                replies->done      = true;
            });
            const bool received = accepted && http_client_bench::pump_until([&] { return replies->done; });
            state.PauseTiming();
            if (!received || !valid(replies->responses, 17, 1) || fixture.routed != 1
                || fixture.logged != static_cast<std::uint64_t>(format != 0) || !fixture.valid_lines || !fixture.client->is_connected()
                || fixture.server->sessions().size() != 1) {
                state.SkipWithError("HTTP/1 first-request work or log was incomplete");
                return;
            }
        }
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations());
}
// Legacy API only: the common source can be built unchanged on both revisions.
// Each interval starts at GET and includes connection setup, response delivery
// and complete client/server connection teardown. Request/observation construction,
// correctness checks and destruction of the returned Reply are outside timing.
void
BM_Http1_LegacyOneShotLifecycle(benchmark::State &state) {
    Fixture fixture(0);
    if (!fixture.ready) {
        state.SkipWithError("HTTP/1 one-shot fixture connection failed");
        return;
    }
    const std::string origin = "http://127.0.0.1:" + std::to_string(fixture.server->transport().local_endpoint().port());
    // Fixture's historical persistent connection is setup only. Neither its
    // socket nor its deferred self-hold may enter the one-shot measurements.
    std::weak_ptr<qb::http1::Client> setup_client = fixture.client;
    fixture.client->disconnect();
    fixture.client.reset();
    if (!http_client_bench::pump_until(
            [&] { return setup_client.expired() && fixture.server->sessions().empty() && !qb::io::async::listener::current.has_deferred(); })
        || fixture.routed != 0 || fixture.logged != 0) {
        state.SkipWithError("HTTP/1 one-shot setup connection did not retire cleanly");
        return;
    }

    struct Observed {
        qb::http::async::Reply reply;
        unsigned               delivered = 0;
    };
    std::uint64_t completed = 0;
    for (auto _ : state) {
        state.PauseTiming();
        const std::string id   = completed % 2 == 0 ? "17" : "23";
        const std::string path = "/bench/" + id;
        qb::http::Request work{qb::http::method::GET, qb::io::uri(origin + path)};
        work.set_header("User-Agent", "qb legacy one-shot comparison");
        auto observed = std::make_shared<Observed>();
        state.ResumeTiming();
        qb::http::GET(
            std::move(work),
            [observed](qb::http::async::Reply &&reply) {
                ++observed->delivered;
                observed->reply = std::move(reply);
            },
            qb::duration::zero());
        const bool settled = http_client_bench::pump_until([&] {
            // The one-shot session owns a copy of this callback. A sole observer
            // owner proves its destruction, not just receipt of the response.
            return observed->delivered != 0 && observed.use_count() == 1 && fixture.server->sessions().empty()
                   && !qb::io::async::listener::current.has_deferred();
        });
        state.PauseTiming();
        ++completed;
        if (!settled || observed->delivered != 1 || observed->reply.response.status() != qb::http::status::OK
            || observed->reply.response.body().as<std::string>() != id || observed->reply.request.method() != qb::http::method::GET
            || observed->reply.request.uri().path() != path || fixture.routed != completed || fixture.logged != 0
            || !fixture.server->sessions().empty()) {
            state.SkipWithError("HTTP/1 legacy one-shot work or connection teardown was incomplete");
            return;
        }
        benchmark::DoNotOptimize(observed->reply.response.body().raw().size());
        // A late callback still owns observed if the watchdog ever fails; no
        // stack-reference capture escapes. Normal Reply destruction is untimed.
        observed.reset();
        state.ResumeTiming();
    }
    if (fixture.routed != completed || fixture.logged != 0 || !fixture.server->sessions().empty()) {
        state.SkipWithError("HTTP/1 legacy one-shot final conservation failed");
        return;
    }
    state.SetItemsProcessed(state.iterations());
    state.counters["responses"]             = static_cast<double>(completed);
    state.counters["connections_completed"] = static_cast<double>(completed);
    state.counters["routed"]                = static_cast<double>(fixture.routed);
}
} // namespace access_log_loopback_bench

BENCHMARK(access_log_loopback_bench::BM_Http1_AccessLogWarm)
    ->Arg(0)
    ->Arg(1)
    ->Arg(2)
    ->ArgNames({"format"})
    ->Unit(benchmark::kMicrosecond)
    ->UseRealTime();
BENCHMARK(access_log_loopback_bench::BM_Http1_AccessLogFirstRequest)
    ->Arg(0)
    ->Arg(1)
    ->Arg(2)
    ->ArgNames({"format"})
    // Automatic calibration creates thousands of fresh TCP pairs outside timing
    // and exhausts the host's ephemeral ports. Bound identical work on both sides.
    ->Iterations(8)
    ->UseRealTime()
    ->Unit(benchmark::kMicrosecond);
BENCHMARK(access_log_loopback_bench::BM_Http1_LegacyOneShotLifecycle)
    // Bound fresh TCP pairs per process; calibration must not exhaust ephemeral ports.
    ->Iterations(32)
    ->UseRealTime()
    ->Unit(benchmark::kMicrosecond);
BENCHMARK_MAIN();

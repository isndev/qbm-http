/**
 * @file qbm/http/tests/system/middleware/metrics-endpoint.cpp
 * @brief The `/metrics` endpoint: `metrics_handler` scrapes every core's `qb::metrics::Registry` and answers the
 *        Prometheus text (Huly QB-154).
 *
 * An engine of two cores, a registry on each. A server actor on core 0 routes through its own router (a capturing
 * session, no socket): it publishes its `RequestMetrics` and its connections through core 0's registry, a worker
 * publishes a counter through core 1's, one request is answered, then `GET /metrics`. Pinned: the answer is a 200
 * with the exposition's content type; it holds the request counted under its route pattern, the `/metrics` request
 * itself in flight, the connections, the worker's counter from the other core, each core's `qb_core_*` counters and
 * `qb_scrape_core_up` 1 for both; the scraping actor registers nothing (the registry receives the answers).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include <qb/core/metrics_registry.h>
#include <qb/main.h>
#include <qbm/http/http.h>
#include <qbm/http/middleware/metrics.h>

namespace metrics_endpoint_test {

using namespace std::chrono_literals;

struct Answered : qb::Event {};
struct Ready : qb::Event {};

std::string g_body;
std::string g_content_type;
int         g_status = 0;

/// A session that keeps the response and tells its owner.
struct Session {
    qb::http::Response    response;
    std::function<void()> on_write;
    Session &
    operator<<(qb::http::Response const &r) {
        response = r;
        if (on_write)
            on_write();
        return *this;
    }
};
using Ctx = qb::http::Context<Session>;

qb::http::Request
get(std::string const &path) {
    qb::http::Request req;
    req.method()      = qb::http::method::GET;
    req.uri()         = qb::io::uri(path);
    req.major_version = 1;
    req.minor_version = 1;
    return req;
}

// Publishes a counter through core 1's registry, then tells the server it may scrape.
class Worker : public qb::Actor {
    qb::ActorId                _server;
    qb::metrics::source_handle _source;

public:
    explicit Worker(qb::ActorId server) noexcept
        : _server(server) {}
    qb::io::async::task<bool>
    onInit() override {
        auto *registry = getService<qb::metrics::Registry>();
        if (!registry)
            co_return false;
        _source = registry->add_source([](qb::metrics::snapshot &s) { s.counter("test_worker_jobs_total", "Jobs.").add({}, 5); });
        push<Ready>(_server);
        co_return true;
    }
};

class Server : public qb::Actor {
    qb::http::Router<Session>                          _router;
    std::shared_ptr<qb::http::RequestMetrics<Session>> _metrics = qb::http::request_metrics<Session>();
    qb::metrics::source_handle                         _source;
    std::shared_ptr<Session>                           _scraper = std::make_shared<Session>();

public:
    qb::io::async::task<bool>
    onInit() override {
        registerEvent<Answered>(*this);
        registerEvent<Ready>(*this);
        auto *registry = getService<qb::metrics::Registry>();
        if (!registry)
            co_return false;
        _source = registry->add_source([m = _metrics](qb::metrics::snapshot &s) {
            m->collect(s);
            qb::http::add_connections(s, "http/1.1", 1);
        });
        _router.add_observer(_metrics);
        _router.get("/users/:id", [](std::shared_ptr<Ctx> ctx) { ctx->text("user"); });
        _router.get("/metrics", qb::http::metrics_handler<Session>(*this, qb::http::MetricsEndpointOptions{}.with_timeout(10s)));
        _router.compile();
        co_return true;
    }
    void
    on(Ready const &) {
        _router.route(std::make_shared<Session>(), get("/users/1"));
        _scraper->on_write = [this] {
            push<Answered>(id());
        };
        _router.route(_scraper, get("/metrics")); // answered once every core has
    }
    void
    on(Answered const &) {
        g_status       = static_cast<int>(_scraper->response.status());
        g_content_type = _scraper->response.header("Content-Type");
        g_body         = _scraper->response.body().as<std::string>();
        broadcast<qb::KillEvent>();
    }
};

bool
has_line(std::string const &line) {
    return g_body.find(line + "\n") != std::string::npos;
}

TEST(MetricsEndpoint, ScrapesEveryCoreAndAnswersTheText) {
    if (std::thread::hardware_concurrency() < 2u)
        GTEST_SKIP() << "requires-multicore: the scrape must reach another core";
    g_body.clear();
    g_content_type.clear();
    g_status = 0;
    qb::Main main;
    main.addActor<qb::metrics::Registry>(0);
    main.addActor<qb::metrics::Registry>(1);
    const auto server = main.addActor<Server>(0);
    main.addActor<Worker>(1, server);
    main.start(false);
    main.join();
    ASSERT_FALSE(main.hasError());

    EXPECT_EQ(g_status, 200);
    EXPECT_EQ(g_content_type, "text/plain; version=0.0.4; charset=utf-8");
    EXPECT_TRUE(has_line("qb_http_requests_total{method=\"GET\",route=\"/users/:id\",status=\"200\"} 1")) << g_body;
    EXPECT_TRUE(has_line("qb_http_requests_in_flight 1")) << "the /metrics request, while it scrapes:\n" << g_body;
    EXPECT_TRUE(has_line("qb_http_connections{protocol=\"http/1.1\"} 1")) << g_body;
    EXPECT_TRUE(has_line("test_worker_jobs_total 5")) << g_body;
    EXPECT_TRUE(has_line("qb_scrape_core_up{core=\"0\"} 1")) << g_body;
    EXPECT_TRUE(has_line("qb_scrape_core_up{core=\"1\"} 1")) << g_body;
    EXPECT_NE(g_body.find("qb_core_loop_passes_total{core=\"1\"} "), std::string::npos) << g_body;
}

} // namespace metrics_endpoint_test

/**
 * @file qbm/http/tests/unit/middleware/middleware-metrics.cpp
 * @brief `RequestMetrics` and `add_connections` (Huly QB-90, QB-154).
 *
 * Pinned: a router observed by `RequestMetrics` counts every request under its route PATTERN (two ids, one series),
 * its method and its status -- a 404 under `unmatched`, a 405 under the route whose path matched; the duration
 * histogram counts the same requests (its `+Inf` bucket and `_count`); the in-flight gauge holds an asynchronous
 * request until it is answered; the description is the `qb_http_*` families, byte for byte where nothing depends
 * on time; custom buckets are used and bad ones refused; `add_connections` describes open connections.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <chrono>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <qb/core/metrics.h>
#include <qbm/http/http.h>
#include <qbm/http/middleware/metrics.h>

#include "../../shared/mock_session.h"

namespace middleware_metrics_test {

using qb::http::test::create_request;
using qb::http::test::MockSession;
using Ctx = qb::http::Context<MockSession>;

bool
has_line(std::string const &text, std::string const &line) {
    return text.find(line + "\n") != std::string::npos;
}

class RequestMetricsTest : public ::testing::Test {
protected:
    qb::http::Router<MockSession>                          router;
    std::shared_ptr<qb::http::RequestMetrics<MockSession>> metrics = qb::http::request_metrics<MockSession>();
    std::shared_ptr<Ctx>                                   held;

    void
    SetUp() override {
        router.add_observer(metrics);
        router.get("/users/:id", [](std::shared_ptr<Ctx> ctx) { ctx->text("user"); });
        router.get("/slow", [this](std::shared_ptr<Ctx> ctx) { held = std::move(ctx); });
        router.compile();
    }

    void
    route(qb::http::method method, std::string const &path) {
        router.route(std::make_shared<MockSession>(), create_request(method, path));
    }

    [[nodiscard]] std::string
    text() const {
        qb::metrics::snapshot s;
        metrics->collect(s);
        return qb::metrics::write_text(s);
    }
};

TEST_F(RequestMetricsTest, CountsEveryRequestUnderItsPatternMethodAndStatus) {
    route(qb::http::method::GET, "/users/1");
    route(qb::http::method::GET, "/users/2");
    route(qb::http::method::GET, "/nowhere");
    route(qb::http::method::GET, "/elsewhere");
    route(qb::http::method::POST, "/users/1");

    EXPECT_EQ(metrics->count(qb::http::method::GET, "/users/:id", 200), 2u) << "two ids, one series";
    EXPECT_EQ(metrics->count(qb::http::method::GET, "", 404), 2u) << "unmatched";
    EXPECT_EQ(metrics->count(qb::http::method::POST, "/users/:id", 405), 1u);
    EXPECT_EQ(metrics->in_flight(), 0u);

    const std::string t = text();
    EXPECT_TRUE(has_line(t, "# TYPE qb_http_requests_total counter")) << t;
    EXPECT_TRUE(has_line(t, "qb_http_requests_total{method=\"GET\",route=\"/users/:id\",status=\"200\"} 2")) << t;
    EXPECT_TRUE(has_line(t, "qb_http_requests_total{method=\"POST\",route=\"/users/:id\",status=\"405\"} 1")) << t;
    EXPECT_TRUE(has_line(t, "qb_http_requests_total{method=\"GET\",route=\"unmatched\",status=\"404\"} 2")) << t;
    EXPECT_TRUE(has_line(t, "# TYPE qb_http_request_duration_seconds histogram")) << t;
    EXPECT_TRUE(has_line(t, "qb_http_request_duration_seconds_bucket{method=\"GET\",route=\"/users/:id\",le=\"+Inf\"} 2")) << t;
    EXPECT_TRUE(has_line(t, "qb_http_request_duration_seconds_count{method=\"GET\",route=\"/users/:id\"} 2")) << t;
    EXPECT_TRUE(has_line(t, "qb_http_request_duration_seconds_count{method=\"GET\",route=\"unmatched\"} 2")) << t;
    EXPECT_NE(t.find("qb_http_request_duration_seconds_bucket{method=\"GET\",route=\"/users/:id\",le=\"0.005\"} "), std::string::npos)
        << "the default buckets, from 5 ms";
    EXPECT_TRUE(has_line(t, "qb_http_requests_in_flight 0")) << t;
    EXPECT_EQ(t.find("/users/1"), std::string::npos) << "never the raw path";
}

TEST_F(RequestMetricsTest, AnAsynchronousRequestIsInFlightUntilAnswered) {
    route(qb::http::method::GET, "/slow");
    EXPECT_EQ(metrics->in_flight(), 1u);
    EXPECT_TRUE(has_line(text(), "qb_http_requests_in_flight 1"));
    EXPECT_EQ(metrics->count(qb::http::method::GET, "/slow", 200), 0u);
    held->text("done");
    held.reset();
    EXPECT_EQ(metrics->in_flight(), 0u);
    EXPECT_EQ(metrics->count(qb::http::method::GET, "/slow", 200), 1u);
}

TEST(RequestMetricsOptions, CustomBucketsAreUsedAndBadOnesRefused) {
    qb::http::Router<MockSession> router;
    auto                          metrics = qb::http::request_metrics<MockSession>(qb::http::RequestMetricsOptions{}.with_buckets({1.0, 60.0}));
    router.add_observer(metrics);
    router.get("/x", [](std::shared_ptr<Ctx> ctx) { ctx->text("x"); });
    router.compile();
    router.route(std::make_shared<MockSession>(), create_request(qb::http::method::GET, "/x"));

    qb::metrics::snapshot s;
    metrics->collect(s);
    const std::string t = qb::metrics::write_text(s);
    EXPECT_TRUE(has_line(t, "qb_http_request_duration_seconds_bucket{method=\"GET\",route=\"/x\",le=\"1\"} 1")) << t;
    EXPECT_TRUE(has_line(t, "qb_http_request_duration_seconds_bucket{method=\"GET\",route=\"/x\",le=\"60\"} 1")) << t;
    EXPECT_EQ(t.find("le=\"0.005\""), std::string::npos) << t;

    EXPECT_THROW((void) qb::http::request_metrics<MockSession>(qb::http::RequestMetricsOptions{}.with_buckets({})), std::invalid_argument);
    EXPECT_THROW((void) qb::http::request_metrics<MockSession>(qb::http::RequestMetricsOptions{}.with_buckets({1.0, 1.0})),
                 std::invalid_argument);
    EXPECT_THROW((void) qb::http::request_metrics<MockSession>(
                     qb::http::RequestMetricsOptions{}.with_buckets({1.0, std::numeric_limits<double>::infinity()})),
                 std::invalid_argument);
}

TEST(RequestMetricsStore, ADurationLandsInTheFirstBucketItDoesNotExceed) {
    qb::http::detail::request_metrics_store store({0.1, 1.0});
    for (auto const d :
         {std::chrono::milliseconds(50), std::chrono::milliseconds(100), std::chrono::milliseconds(500), std::chrono::milliseconds(1000),
          std::chrono::milliseconds(2000)}) {
        store.started();
        store.finished(qb::http::method::GET, "/r", 200, d);
    }
    qb::metrics::snapshot s;
    store.collect(s);
    const std::string t = qb::metrics::write_text(s);
    EXPECT_TRUE(has_line(t, "qb_http_request_duration_seconds_bucket{method=\"GET\",route=\"/r\",le=\"0.1\"} 2")) << t; // 50, 100 (le)
    EXPECT_TRUE(has_line(t, "qb_http_request_duration_seconds_bucket{method=\"GET\",route=\"/r\",le=\"1\"} 4")) << t;   // + 500, 1000
    EXPECT_TRUE(has_line(t, "qb_http_request_duration_seconds_bucket{method=\"GET\",route=\"/r\",le=\"+Inf\"} 5")) << t;
    EXPECT_NE(t.find("qb_http_request_duration_seconds_sum{method=\"GET\",route=\"/r\"} 3.6"), std::string::npos) << t; // 3.65, as doubles add
    EXPECT_EQ(store.in_flight(), 0u);
}

TEST(AddConnections, DescribesOpenConnectionsByProtocol) {
    qb::metrics::snapshot s;
    qb::http::add_connections(s, "http/1.1", 3);
    qb::http::add_connections(s, "h2", 1);
    EXPECT_EQ(qb::metrics::write_text(s), "# HELP qb_http_connections Open HTTP connections, by protocol.\n"
                                          "# TYPE qb_http_connections gauge\n"
                                          "qb_http_connections{protocol=\"http/1.1\"} 3\n"
                                          "qb_http_connections{protocol=\"h2\"} 1\n");
}

} // namespace middleware_metrics_test

/**
 * @file qbm/http/tests/unit/middleware/middleware-rate-limit-window.cpp
 * @brief Wall-clock window-EXPIRY tests for qb::http::RateLimitMiddleware (SLOW).
 *
 * This is the SLOW half of the rate-limit unit suite (the integrator tags it
 * with the `slow` label). It holds exactly the scenarios that require crossing
 * a *real* time window because `RateLimitMiddleware` reads
 * `std::chrono::steady_clock::now()` directly and exposes no injectable clock:
 *
 *   - window recovery: an exhausted client is allowed again after the window
 *     elapses (the post-429 "recover" arc collapsed out of the fast core);
 *   - straddling the window boundary (counter survives within-window, resets
 *     across it), incl. the monotonic-decreasing X-RateLimit-Reset assertion;
 *   - the F41 opportunistic periodic cleanup recovering capacity once short
 *     windows have genuinely elapsed.
 *
 * Windows here are kept as small as practical (60-120 ms) to bound the wall
 * time while staying comfortably above scheduler jitter on a loaded CI box;
 * the sleeps use a generous margin (~2x the window) so they do not race.
 *
 * FRAMEWORK FOLLOW-UP: if `RateLimitMiddleware` gained an injectable `now()`
 * source (e.g. a `Clock` template param or a settable time function), every
 * test in THIS file could move back into the deterministic fast core and this
 * `slow` file could be retired entirely. See this suite's manifest.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <string>
#include <thread>

#include <gtest/gtest.h>

#include <qb/system/parse.h>

#include "../../shared/middleware_test_fixture.h"
#include "../middleware/rate_limit.h"

using qb::http::test::MiddlewareTestFixture;
using qb::http::test::MockMiddlewareSession;

namespace {

[[nodiscard]] std::string
header_value(const qb::http::Response &resp, const std::string &name) {
    return std::string(resp.header(name));
}

} // namespace

/**
 * @brief Slow rate-limit fixture: same shared mock session + X-Forwarded-For helper.
 */
class RateLimitWindowTest : public MiddlewareTestFixture<MockMiddlewareSession> {
protected:
    qb::http::Request
    request_for(const std::string &path = "/mw_test", const std::string &client_ip = "") {
        qb::http::Request req = create_request(qb::http::method::GET, path);
        if (!client_ip.empty()) {
            req.set_header(std::string("X-Forwarded-For"), client_ip);
        }
        return req;
    }
};

// The canonical allow -> exhaust -> 429 -> (window elapses) -> allow-again arc.
// This is the single consolidation of the four redundant recovery arcs that
// previously lived in the monolithic file.
TEST_F(RateLimitWindowTest, ClientIsAllowedAgainAfterWindowElapses) {
    constexpr auto kWindow = std::chrono::milliseconds(80);
    qb::http::RateLimitOptions options;
    options.max_requests(2).window(kWindow);
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    // Exhaust the window: 2 OK then 1 429.
    configure_router_and_run(mw, request_for("/mw_test", "client_W"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "1");

    configure_router_and_run(mw, request_for("/mw_test", "client_W"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "0");

    configure_router_and_run(mw, request_for("/mw_test", "client_W"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Let the window fully elapse (generous 2x margin), then the next request
    // starts a fresh window and is allowed again.
    std::this_thread::sleep_for(kWindow * 2);

    configure_router_and_run(mw, request_for("/mw_test", "client_W"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "1");

    // Reset seconds on a fresh window is bounded by the (sub-second) window.
    const long long reset =
        qb::to_number<long long>(header_value(_session->_response, "X-RateLimit-Reset")).value();
    EXPECT_GE(reset, 0);
    EXPECT_LE(reset, 1);
}

// Requests within the same window share the counter; once the window rolls
// over, the counter resets. Also pins the X-RateLimit-Reset progression.
TEST_F(RateLimitWindowTest, RequestsStraddlingWindowBoundary) {
    constexpr auto kWindow = std::chrono::milliseconds(120);
    qb::http::RateLimitOptions options;
    options.max_requests(2).window(kWindow);
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    // Request 1 (start of window) -> OK, Remaining 1.
    configure_router_and_run(mw, request_for("/mw_test", "straddle"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "1");

    // Stay within the window (well under kWindow), then Request 2 -> still OK.
    std::this_thread::sleep_for(kWindow / 3);
    configure_router_and_run(mw, request_for("/mw_test", "straddle"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "0");

    // Request 3 within the same window -> 429.
    configure_router_and_run(mw, request_for("/mw_test", "straddle"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Cross the boundary with a generous margin -> Request 4 starts a new window.
    std::this_thread::sleep_for(kWindow * 2);
    configure_router_and_run(mw, request_for("/mw_test", "straddle"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "1");
    const long long reset =
        qb::to_number<long long>(header_value(_session->_response, "X-RateLimit-Reset")).value();
    EXPECT_GE(reset, 0);
    EXPECT_LE(reset, 1);
}

// F41: a flood of short-lived clients must not permanently consume tracking
// slots. After their (short) windows elapse, an on-demand sweep reclaims every
// slot. This requires a real elapsed window, hence it lives here.
TEST_F(RateLimitWindowTest, OpportunisticCleanupRecoversCapacityAfterWindowElapses) {
    constexpr auto kWindow = std::chrono::milliseconds(60);
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(kWindow);
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    constexpr int kBurst = 20;
    for (int i = 0; i < kBurst; ++i) {
        configure_router_and_run(mw, request_for("/mw_test", "burst_" + std::to_string(i)));
        EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    }
    EXPECT_EQ(mw->tracked_client_count(), static_cast<std::size_t>(kBurst));

    // Every window has now elapsed (generous margin); the sweep reclaims all.
    std::this_thread::sleep_for(kWindow * 2);
    const auto evicted = mw->evict_stale_entries_now();
    EXPECT_EQ(evicted, static_cast<std::size_t>(kBurst));
    EXPECT_EQ(mw->tracked_client_count(), 0U);
}

// Surgical eviction across a real boundary: a client whose window has elapsed
// is evicted, while one whose window is still fresh survives with its counter.
TEST_F(RateLimitWindowTest, StaleEvictedActiveSurvivesAcrossRealWindow) {
    constexpr auto kWindow = std::chrono::milliseconds(80);
    qb::http::RateLimitOptions options;
    options.max_requests(3).window(kWindow);
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    // Stale client: hit once, then let its window elapse.
    configure_router_and_run(mw, request_for("/mw_test", "stale"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    std::this_thread::sleep_for(kWindow * 2);

    // Active client: hit right before the sweep — its window is fresh.
    configure_router_and_run(mw, request_for("/mw_test", "active"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    const auto evicted = mw->evict_stale_entries_now();
    EXPECT_EQ(evicted, 1U);                     // only `stale`
    EXPECT_EQ(mw->tracked_client_count(), 1U);  // only `active` survives

    // The survivor keeps its counter: next request sees remaining = 1 (3 - 2).
    configure_router_and_run(mw, request_for("/mw_test", "active"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "1");
}

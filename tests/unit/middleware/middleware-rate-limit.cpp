/**
 * @file qbm/http/tests/unit/middleware/middleware-rate-limit.cpp
 * @brief Fast, deterministic unit tests for qb::http::RateLimitMiddleware.
 *
 * This is the FAST core of the rate-limit suite. It exercises everything that
 * does NOT require crossing a real wall-clock window boundary: fixed-window
 * counting, `X-RateLimit-*` header emission, the default vs. custom client-id
 * extractor (incl. the throwing-extractor fallback and the type-erased
 * SessionType-mismatch guard), factory/preset configuration, the
 * `reset_client` / `reset_all_clients` admin API, the F41 stale-entry eviction
 * API driven on-demand, and a concurrency / lost-update data-race probe.
 *
 * The window-EXPIRY (clock recovery) scenarios live in the sibling
 * `middleware-rate-limit-window.cpp` (labelled `slow`) because
 * `RateLimitMiddleware` reads `std::chrono::steady_clock::now()` directly and
 * exposes no injectable clock, so those cases must sleep across a real window.
 * See that file's header and this suite's manifest for the framework
 * follow-up (an injectable `now()` source would let the whole family run
 * deterministically without any `sleep_for`).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <qb/system/parse.h>

#include "../../shared/middleware_test_fixture.h"
#include "../middleware/rate_limit.h"

using qb::http::test::MiddlewareTestFixture;
using qb::http::test::MockMiddlewareSession;

namespace {

/// @brief Convenience: read a response header as a std::string for exact compares.
[[nodiscard]] std::string
header_value(const qb::http::Response &resp, const std::string &name) {
    return std::string(resp.header(name));
}

/// @brief Session that exposes a socket peer IP — like a real transport-backed session, and
///        unlike MockMiddlewareSession — so the built-in extractor's secure `session->ip()`
///        default (rather than the header fallback) is exercised.
struct MockSessionWithIp : qb::http::test::MockMiddlewareSession {
    std::string _ip;
    [[nodiscard]] std::string
    ip() const {
        return _ip;
    }
};

} // namespace

/**
 * @brief Fast rate-limit fixture: shared mock session + per-run router reset.
 *
 * Adds a small helper to attach an `X-Forwarded-For` header (the default
 * client-id source) to a request built by the shared fixture's
 * `create_request`.
 */
class RateLimitFastTest : public MiddlewareTestFixture<MockMiddlewareSession> {
protected:
    /// @brief Build a GET request for @p path optionally carrying an X-Forwarded-For client IP.
    qb::http::Request
    request_for(const std::string &path = "/mw_test", const std::string &client_ip = "") {
        qb::http::Request req = create_request(qb::http::method::GET, path);
        if (!client_ip.empty()) {
            req.set_header(std::string("X-Forwarded-For"), client_ip);
        }
        return req;
    }
};

// ---------------------------------------------------------------------------
// Secure default: key on the socket peer IP, not spoofable forwarding headers.
// ---------------------------------------------------------------------------

class RateLimitPeerIpTest : public MiddlewareTestFixture<MockSessionWithIp> {
protected:
    qb::http::Request
    request_with_xff(const std::string &spoofed_ip) {
        qb::http::Request req = create_request(qb::http::method::GET, "/mw_test");
        if (!spoofed_ip.empty()) {
            req.set_header(std::string("X-Forwarded-For"), spoofed_ip);
        }
        return req;
    }
};

TEST_F(RateLimitPeerIpTest, PeerIpIsDefaultKeyAndSpoofedForwardedForIsIgnored) {
    _session->_ip = "10.0.0.1";
    qb::http::RateLimitOptions options;
    options.max_requests(3).window(std::chrono::minutes(5));
    auto mw = qb::http::rate_limit_middleware<MockSessionWithIp>(options);

    // Each request forges a DIFFERENT X-Forwarded-For. With the secure default they all key on the
    // real peer IP (10.0.0.1), so the 4th is limited — forging the header buys no fresh bucket.
    for (int i = 1; i <= 3; ++i) {
        configure_router_and_run(mw, request_with_xff("1.1.1." + std::to_string(i)));
        EXPECT_EQ(_session->_response.status(), qb::http::status::OK) << "request " << i;
    }
    configure_router_and_run(mw, request_with_xff("1.1.1.99"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
}

TEST_F(RateLimitPeerIpTest, TrustForwardedHeadersOptInKeysOnForwardedForNotPeerIp) {
    _session->_ip = "10.0.0.1";
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::minutes(5)).trust_forwarded_headers(true);
    auto mw = qb::http::rate_limit_middleware<MockSessionWithIp>(options);

    // trust_forwarded_headers(true): each distinct X-Forwarded-For is its own bucket despite the
    // shared peer IP, so two different forwarded IPs each pass their single allowed request.
    configure_router_and_run(mw, request_with_xff("203.0.113.1"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    configure_router_and_run(mw, request_with_xff("203.0.113.2"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    // The first forwarded IP again -> now limited.
    configure_router_and_run(mw, request_with_xff("203.0.113.1"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
}

// ---------------------------------------------------------------------------
// Fixed-window counting + header emission (no window crossing).
// ---------------------------------------------------------------------------

// Collapses the former BasicRateLimiting / RateLimitHeadersAreAccurate /
// TestSecureConfiguration "allow -> exhaust -> 429" arcs into one exact,
// sleep-free assertion of the counter + header progression. The recovery
// (post-window) half of those arcs now lives in middleware-rate-limit-window.
TEST_F(RateLimitFastTest, CountsRequestsAndEmitsHeadersUntilLimit) {
    qb::http::RateLimitOptions options;
    // Large window so wall-clock never crosses it during the test; pure counting.
    options.max_requests(3).window(std::chrono::minutes(5));
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    // Request 1 -> OK, Remaining 2.
    configure_router_and_run(mw, request_for("/mw_test", "client_A"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Limit"), "3");
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "2");

    // Request 2 -> OK, Remaining 1.
    configure_router_and_run(mw, request_for("/mw_test", "client_A"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "1");

    // Request 3 -> OK, Remaining 0 (limit reached but this one still passes).
    configure_router_and_run(mw, request_for("/mw_test", "client_A"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "0");

    // Request 4 -> 429, handler NOT called, Remaining stays 0.
    configure_router_and_run(mw, request_for("/mw_test", "client_A"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Limit"), "3");
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "0");

    // X-RateLimit-Reset on the limited response is a bounded, non-negative
    // seconds-until-reset within the (5 minute = 300 s) window.
    const long long reset = qb::to_number<long long>(header_value(_session->_response, "X-RateLimit-Reset")).value();
    EXPECT_GE(reset, 0);
    EXPECT_LE(reset, 300);
}

// Two distinct client IDs are tracked independently: exhausting one does not
// affect the other. (Subsumes the old NoRateLimitForDifferentClients arc with
// an exact-header assertion and no sleep.)
TEST_F(RateLimitFastTest, DistinctClientsAreTrackedIndependently) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::minutes(5));
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    // Client 1: first OK, second 429.
    configure_router_and_run(mw, request_for("/mw_test", "client_1"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "0");

    // Client 2: independent counter, first request still OK.
    configure_router_and_run(mw, request_for("/mw_test", "client_2"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "0");

    // Client 1: now exhausted -> 429.
    configure_router_and_run(mw, request_for("/mw_test", "client_1"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Client 2: now exhausted -> 429.
    configure_router_and_run(mw, request_for("/mw_test", "client_2"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
}

TEST_F(RateLimitFastTest, ZeroMaxRequestsBlocksEveryRequest) {
    qb::http::RateLimitOptions options;
    options.max_requests(0).window(std::chrono::minutes(5));
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    configure_router_and_run(mw, request_for("/mw_test", "zero_max_client"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Limit"), "0");
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "0");
}

TEST_F(RateLimitFastTest, CustomErrorMessageAndStatusCode) {
    qb::http::RateLimitOptions options;
    options
        .max_requests(0) // Reject immediately.
        .window(std::chrono::minutes(5))
        .status_code(qb::http::status::SERVICE_UNAVAILABLE)
        .message("Custom rate limit message.");
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    configure_router_and_run(mw, request_for("/mw_test", "client_B"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Custom rate limit message.");
    EXPECT_EQ(header_value(_session->_response, "Content-Type"), "text/plain; charset=utf-8");
}

// ---------------------------------------------------------------------------
// Client-id extraction.
// ---------------------------------------------------------------------------

TEST_F(RateLimitFastTest, CustomClientIdExtractorKeysOffHeader) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::minutes(5));
    options.client_id_extractor<MockMiddlewareSession>(
        [](const qb::http::Context<MockMiddlewareSession> &ctx) { return std::string(ctx.request().header(std::string("X-Client-ID"))); });
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    auto req1 = create_request(qb::http::method::GET, "/mw_test");
    req1.set_header(std::string("X-Client-ID"), "custom_client_1");
    configure_router_and_run(mw, std::move(req1));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    // Same custom client -> 429.
    auto req2 = create_request(qb::http::method::GET, "/mw_test");
    req2.set_header(std::string("X-Client-ID"), "custom_client_1");
    configure_router_and_run(mw, std::move(req2));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Different custom client -> independent, OK.
    auto req3 = create_request(qb::http::method::GET, "/mw_test");
    req3.set_header(std::string("X-Client-ID"), "custom_client_2");
    configure_router_and_run(mw, std::move(req3));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(RateLimitFastTest, ThrowingCustomExtractorFallsBackToDefaultExtraction) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::minutes(5));
    options.client_id_extractor<MockMiddlewareSession>(
        [](const qb::http::Context<MockMiddlewareSession> & /*ctx*/) -> std::string { throw std::runtime_error("extractor crash"); });
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    // The throw is swallowed; the default X-Forwarded-For path keys the client.
    EXPECT_NO_THROW(configure_router_and_run(mw, request_for("/mw_test", "10.0.0.1")));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    EXPECT_NO_THROW(configure_router_and_run(mw, request_for("/mw_test", "10.0.0.1")));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
}

TEST_F(RateLimitFastTest, EmptyClientIdIsASingleTrackedBucket) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::minutes(5));
    options.client_id_extractor<MockMiddlewareSession>(
        [](const qb::http::Context<MockMiddlewareSession> & /*ctx*/) -> std::string { return std::string(); });
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    // Two requests both resolve to the "" bucket: first OK, second 429.
    configure_router_and_run(mw, create_request(qb::http::method::GET, "/mw_test"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "0");

    configure_router_and_run(mw, create_request(qb::http::method::GET, "/mw_test"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "0");
}

// ---------------------------------------------------------------------------
// Forwarding-header client-id extraction.
//
// MockMiddlewareSession exposes no ip(), so the built-in extractor's secure
// peer-IP default is unavailable and it falls through to the forwarding-header
// logic even at the default trust_forwarded_headers=false. These cases cover the
// CF-Connecting-IP / True-Client-IP precedence arms and the X-Forwarded-For
// rightmost-IP extraction, none of which the single-token XFF tests above reach.
// ---------------------------------------------------------------------------

TEST_F(RateLimitFastTest, CfConnectingIpIsPreferredClientKey) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::minutes(5));
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    auto with_cf = [this](const std::string &cf, const std::string &xff) {
        auto req = create_request(qb::http::method::GET, "/mw_test");
        req.set_header(std::string("CF-Connecting-IP"), cf);
        if (!xff.empty()) {
            req.set_header(std::string("X-Forwarded-For"), xff);
        }
        return req;
    };

    // First request keyed on CF-Connecting-IP -> OK.
    configure_router_and_run(mw, with_cf("cf-1.2.3.4", "9.9.9.9"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    // Same CF, DIFFERENT X-Forwarded-For -> still the same bucket (CF wins) -> 429.
    configure_router_and_run(mw, with_cf("cf-1.2.3.4", "8.8.8.8"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Different CF -> independent bucket -> OK.
    configure_router_and_run(mw, with_cf("cf-5.6.7.8", "9.9.9.9"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(RateLimitFastTest, TrueClientIpUsedWhenCfAbsent) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::minutes(5));
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    auto with_true_client = [this](const std::string &tci, const std::string &xff) {
        auto req = create_request(qb::http::method::GET, "/mw_test");
        req.set_header(std::string("True-Client-IP"), tci);
        if (!xff.empty()) {
            req.set_header(std::string("X-Forwarded-For"), xff);
        }
        return req;
    };

    // No CF header present: True-Client-IP is the key.
    configure_router_and_run(mw, with_true_client("akamai-1.1.1.1", "9.9.9.9"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    // Same True-Client-IP, different XFF -> same bucket -> 429.
    configure_router_and_run(mw, with_true_client("akamai-1.1.1.1", "7.7.7.7"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Different True-Client-IP -> independent bucket -> OK.
    configure_router_and_run(mw, with_true_client("akamai-2.2.2.2", "9.9.9.9"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

TEST_F(RateLimitFastTest, XForwardedForKeysOnRightmostIp) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::minutes(5));
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    // Only X-Forwarded-For set: the extractor takes the RIGHTMOST IP (closest to
    // the server, least spoofable) and trims the leading whitespace after the comma.
    configure_router_and_run(mw, request_for("/mw_test", "1.1.1.1, 203.0.113.7"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);

    // Different leftmost, SAME rightmost -> same bucket -> 429.
    configure_router_and_run(mw, request_for("/mw_test", "2.2.2.2, 203.0.113.7"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    // Different rightmost -> independent bucket -> OK.
    configure_router_and_run(mw, request_for("/mw_test", "2.2.2.2, 198.51.100.9"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

// A client id longer than MAX_CLIENT_ID_LENGTH (256) is rejected with 400 before
// any counting, via a custom extractor that returns a 300-char string.
TEST_F(RateLimitFastTest, OverlongClientIdIsRejectedWithBadRequest) {
    qb::http::RateLimitOptions options;
    options.max_requests(100).window(std::chrono::minutes(5));
    options.client_id_extractor<MockMiddlewareSession>(
        [](const qb::http::Context<MockMiddlewareSession> & /*ctx*/) -> std::string { return std::string(300, 'x'); });
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    configure_router_and_run(mw, request_for("/mw_test"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Invalid client identifier");
    EXPECT_EQ(header_value(_session->_response, "Content-Type"), "text/plain; charset=utf-8");
}

// ---------------------------------------------------------------------------
// Admin reset API.
// ---------------------------------------------------------------------------

TEST_F(RateLimitFastTest, ResetClientClearsASingleClient) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::minutes(5));
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    configure_router_and_run(mw, request_for("/mw_test", "client_to_reset"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    configure_router_and_run(mw, request_for("/mw_test", "client_to_reset"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS);

    mw->reset_client("client_to_reset");

    configure_router_and_run(mw, request_for("/mw_test", "client_to_reset"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "0");
}

TEST_F(RateLimitFastTest, ResetAllClientsClearsEveryClient) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::minutes(5));
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    for (const auto *client : {"clientA", "clientB"}) {
        configure_router_and_run(mw, request_for("/mw_test", client));
        EXPECT_EQ(_session->_response.status(), qb::http::status::OK) << client;
        configure_router_and_run(mw, request_for("/mw_test", client));
        EXPECT_EQ(_session->_response.status(), qb::http::status::TOO_MANY_REQUESTS) << client;
    }

    mw->reset_all_clients();
    EXPECT_EQ(mw->tracked_client_count(), 0U);

    for (const auto *client : {"clientA", "clientB"}) {
        configure_router_and_run(mw, request_for("/mw_test", client));
        EXPECT_EQ(_session->_response.status(), qb::http::status::OK) << client;
        EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "0");
    }
}

// ---------------------------------------------------------------------------
// Factory presets + option getters.
// ---------------------------------------------------------------------------

TEST_F(RateLimitFastTest, FactoryPresetsNameAndConfigureMiddleware) {
    auto default_mw = qb::http::rate_limit_middleware<MockMiddlewareSession>();
    ASSERT_NE(default_mw, nullptr);
    EXPECT_EQ(default_mw->name(), "RateLimitMiddleware");
    EXPECT_EQ(default_mw->get_options().get_max_requests(), 100U);
    EXPECT_EQ(default_mw->get_options().get_window(), std::chrono::minutes(1));
    EXPECT_EQ(default_mw->get_options().get_status_code(), qb::http::status::TOO_MANY_REQUESTS);

    auto dev_mw = qb::http::rate_limit_dev_middleware<MockMiddlewareSession>("MyDevRateLimiter");
    ASSERT_NE(dev_mw, nullptr);
    EXPECT_EQ(dev_mw->name(), "MyDevRateLimiter");
    const auto &dev_opts = dev_mw->get_options();
    EXPECT_EQ(dev_opts.get_max_requests(), 1000U);
    EXPECT_EQ(dev_opts.get_window(), std::chrono::minutes(1));
    EXPECT_EQ(dev_opts.get_status_code(), qb::http::status::TOO_MANY_REQUESTS);
    EXPECT_EQ(dev_opts.get_message(), "You have reached the rate limit. Please try again later.");

    auto secure_mw = qb::http::rate_limit_secure_middleware<MockMiddlewareSession>();
    ASSERT_NE(secure_mw, nullptr);
    EXPECT_EQ(secure_mw->name(), "SecureRateLimitMiddleware");
    const auto &sec_opts = secure_mw->get_options();
    EXPECT_EQ(sec_opts.get_max_requests(), 60U);
    EXPECT_EQ(sec_opts.get_window(), std::chrono::minutes(1));
    EXPECT_EQ(sec_opts.get_status_code(), qb::http::status::TOO_MANY_REQUESTS);
    EXPECT_EQ(sec_opts.get_message(), "Rate limit exceeded. Please try again later.");
}

TEST_F(RateLimitFastTest, PermissivePresetEmitsExpectedHeadersOnFirstRequest) {
    auto mw = qb::http::rate_limit_dev_middleware<MockMiddlewareSession>();
    configure_router_and_run(mw, request_for("/mw_test", "client_perm"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Limit"), "1000");
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "999");
}

TEST_F(RateLimitFastTest, SecurePresetEmitsExpectedHeadersOnFirstRequest) {
    auto mw = qb::http::rate_limit_secure_middleware<MockMiddlewareSession>();
    configure_router_and_run(mw, request_for("/mw_test", "client_sec"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Limit"), "60");
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "59");
}

// ---------------------------------------------------------------------------
// F41 stale-entry eviction (driven on-demand, no window crossing needed when
// the window is zero-length: a 0 ms window makes every prior entry instantly
// stale, so the sweep is deterministic without any sleep).
// ---------------------------------------------------------------------------

TEST_F(RateLimitFastTest, StaleEntriesEvictedOnDemand) {
    qb::http::RateLimitOptions options;
    // Zero-length window: each entry is "stale" the instant after it is written,
    // because (now - last_reset_time) >= 0 == window for any later `now`.
    options.max_requests(5).window(std::chrono::milliseconds(0));
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    for (const auto *client : {"c_one", "c_two", "c_three"}) {
        configure_router_and_run(mw, request_for("/mw_test", client));
        EXPECT_EQ(_session->_response.status(), qb::http::status::OK) << client;
    }
    EXPECT_EQ(mw->tracked_client_count(), 3U);

    const auto evicted = mw->evict_stale_entries_now();
    EXPECT_EQ(evicted, 3U);
    EXPECT_EQ(mw->tracked_client_count(), 0U);

    // A fresh request after eviction re-creates the entry from scratch.
    configure_router_and_run(mw, request_for("/mw_test", "c_one"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "4");
    EXPECT_EQ(mw->tracked_client_count(), 1U);
}

TEST_F(RateLimitFastTest, ActiveEntriesSurviveEviction) {
    // A huge window keeps every entry "active" (never stale), so the sweep is a
    // deterministic no-op: this proves the eviction is surgical, no sleep needed.
    qb::http::RateLimitOptions options;
    options.max_requests(3).window(std::chrono::hours(1));
    auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

    configure_router_and_run(mw, request_for("/mw_test", "active_one"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    configure_router_and_run(mw, request_for("/mw_test", "active_two"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(mw->tracked_client_count(), 2U);

    const auto evicted = mw->evict_stale_entries_now();
    EXPECT_EQ(evicted, 0U); // nothing stale
    EXPECT_EQ(mw->tracked_client_count(), 2U);

    // Surviving counter is preserved: active_one already spent 1 of 3.
    configure_router_and_run(mw, request_for("/mw_test", "active_one"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(header_value(_session->_response, "X-RateLimit-Remaining"), "1");
}

// ---------------------------------------------------------------------------
// Type-safety: a SessionType-mismatched custom extractor must NOT be invoked
// (its static_cast<Context<A>*> on a Context<B>* would be UB). The recorded
// type tag forces a fall-through to the built-in X-Forwarded-For extractor.
// ---------------------------------------------------------------------------

namespace {
/// @brief A second, distinct session type to mismatch the extractor's SessionType.
struct OtherRateLimitSession {
    qb::http::Response _response;

    [[nodiscard]] qb::http::Response &
    get_response_ref() {
        return _response;
    }
    OtherRateLimitSession &
    operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }
    void
    reset() {
        _response = qb::http::Response();
    }
};
} // namespace

TEST(RateLimitMiddlewareTypeSafety, MismatchedExtractorSessionTypeFallsBackToDefault) {
    qb::http::RateLimitOptions options;
    options.max_requests(1).window(std::chrono::minutes(5));
    // Extractor configured for MockMiddlewareSession, used by a middleware
    // instantiated for OtherRateLimitSession: it must NOT fire.
    options.client_id_extractor<MockMiddlewareSession>([](const qb::http::Context<MockMiddlewareSession> &) -> std::string { return "FIXED"; });

    auto mw = qb::http::rate_limit_middleware<OtherRateLimitSession>(options);

    auto run = [&](const std::string &ip) {
        auto                                    session = std::make_shared<OtherRateLimitSession>();
        qb::http::Router<OtherRateLimitSession> router;
        router.use(mw);
        router.get("/r", [](std::shared_ptr<qb::http::Context<OtherRateLimitSession>> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router.compile();
        qb::http::Request req;
        req.method() = qb::http::method::GET;
        req.uri()    = qb::io::uri("/r");
        req.set_header(std::string("X-Forwarded-For"), ip);
        router.route(session, std::move(req));
        return session->_response.status();
    };

    // Two distinct IPs keyed by the built-in extractor are independent clients;
    // both pass the limit-of-1. Had the mismatched extractor been (mis)used,
    // both would share the "FIXED" bucket and the second would 429 — or worse,
    // be UB.
    EXPECT_EQ(run("10.0.0.1"), qb::http::status::OK);
    EXPECT_EQ(run("10.0.0.2"), qb::http::status::OK);
}

// ---------------------------------------------------------------------------
// Concurrency / data-race probe (NEW — spec §2 "ADD concurrency/data-race case").
//
// The middleware documents a strict mono-thread-per-listener model: its client
// map is intentionally lock-free and MUST be driven from a single thread per
// instance. This test honours that contract by giving each thread its OWN
// middleware instance + router (the supported multi-listener topology), then
// hammering each from its own thread. The assertion is that, with no shared
// mutable state across threads, counting stays exact per instance — i.e. the
// per-listener design is sound under real thread pressure (run under TSan/ASan
// this is the data-race tripwire).
// ---------------------------------------------------------------------------

TEST(RateLimitMiddlewareConcurrency, PerListenerInstancesCountExactlyUnderThreads) {
    constexpr int         kThreads           = 8;
    constexpr int         kRequestsPerThread = 50; // > limit, so a deterministic # are 429.
    constexpr std::size_t kLimit             = 20;

    std::vector<std::thread> threads;
    std::vector<int>         allowed(kThreads, 0);
    std::vector<int>         limited(kThreads, 0);
    threads.reserve(kThreads);

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([t, &allowed, &limited]() {
            // Each thread owns its own instance + router + session: the
            // supported per-listener topology. No shared mutable state.
            qb::http::RateLimitOptions options;
            options.max_requests(kLimit).window(std::chrono::minutes(5));
            auto mw = qb::http::rate_limit_middleware<MockMiddlewareSession>(options);

            qb::http::Router<MockMiddlewareSession> router;
            router.use(mw);
            router.get("/r", [](std::shared_ptr<qb::http::Context<MockMiddlewareSession>> ctx) {
                ctx->response().status() = qb::http::status::OK;
                ctx->complete();
            });
            router.compile();

            for (int i = 0; i < kRequestsPerThread; ++i) {
                auto              session = std::make_shared<MockMiddlewareSession>();
                qb::http::Request req;
                req.method() = qb::http::method::GET;
                req.uri()    = qb::io::uri("/r");
                req.set_header(std::string("X-Forwarded-For"), "192.168.0." + std::to_string(t));
                router.route(session, std::move(req));
                if (session->_response.status() == qb::http::status::TOO_MANY_REQUESTS) {
                    ++limited[t];
                } else if (session->_response.status() == qb::http::status::OK) {
                    ++allowed[t];
                }
            }
        });
    }
    for (auto &th : threads) {
        th.join();
    }

    // Each independent instance must have allowed exactly `kLimit` and limited
    // the rest — no lost updates, no over/under-count.
    for (int t = 0; t < kThreads; ++t) {
        EXPECT_EQ(allowed[t], static_cast<int>(kLimit)) << "thread " << t;
        EXPECT_EQ(limited[t], kRequestsPerThread - static_cast<int>(kLimit)) << "thread " << t;
    }
}

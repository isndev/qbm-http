/**
 * @file qbm/http/tests/unit/http2/http2-client-validation.cpp
 * @brief Server-free validation tests for the persistent HTTP/2 client object.
 *
 * The unit half of the former `test-coro-http2-client.cpp`. These cases drive
 * `qb::http2::Client` WITHOUT a live server, a socket, or TLS: they exercise the
 * deterministic, parallel-safe portion of the public client surface —
 *
 *   - construction-time base-URI scheme validation (`make_client` rejects plain
 *     `http://`),
 *   - same-origin enforcement on absolute request URIs (single + batch),
 *   - per-request statistics (`get_stats()` total/successful/failed),
 *   - reentrancy of the batch failure path (a failure callback may queue a new
 *     batch that a later failure pass must still drain),
 *   - awaiter lifetime when the client is destroyed before the coroutine is
 *     resumed (connect awaiter, and a request awaiter destroyed mid-flight).
 *
 * No TLS handshake RUNS here — but the TU is nonetheless `REQUIRES ssl`, and that is
 * not a conservatism. `qb::http2::Client` is *defined* as
 * `qb::io::async::tcp::client<Client, qb::io::transport::stcp>` and the `2/http2.h`
 * server it pulls in as `::acceptor<..., qb::io::transport::saccept>`; neither transport
 * type exists when `QB_HAS_SSL=OFF`, so this file does not compile there. (An earlier
 * comment here claimed the opposite and the test was registered un-gated — which is
 * exactly how the SSL-off lane broke.) The live loopback+TLS half lives in
 * `system/http2/http2-client-coro.cpp`.
 *
 * The twelve sibling http2 unit TUs really are OpenSSL-free: they include only the
 * `2/protocol/` wire codec (frame layer, HPACK, stream state), which is compiled
 * unconditionally into libqbm-http.
 *
 * The `origin::same` comparison helper is also pinned here because the client's
 * same-origin rejection is built on it and these are the most direct, fixture-
 * free assertions of that contract.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <qbm/http/2/client.h>
#include <qbm/http/2/http2.h>
#include <qbm/http/coro.h>
#include <qbm/http/origin.h>

using namespace std::chrono_literals;

namespace {

// ---------------------------------------------------------------------------
// origin::same — the same-origin oracle the client's request validation rests on
// ---------------------------------------------------------------------------

TEST(HttpOriginTest, ComparesHostCaseInsensitivelyAndNormalizesDefaultPorts) {
    using qb::http::origin::same;
    using qb::io::uri;

    // Host case-insensitivity + implicit-vs-explicit default https port (443).
    EXPECT_TRUE(same(uri("https://LOCALHOST/resource"), uri("https://localhost:443/")));
    // Leading zeros in the port are still the default port.
    EXPECT_TRUE(same(uri("https://localhost:0443/resource"), uri("https://localhost:443/")));
    // Default http port (80), explicit vs implicit, host case-insensitive.
    EXPECT_TRUE(same(uri("http://Example.com:80/path"), uri("http://example.COM/")));
    EXPECT_TRUE(same(uri("http://example.com:00080/path"), uri("http://EXAMPLE.com/")));

    // Different explicit port -> different origin.
    EXPECT_FALSE(same(uri("https://localhost:444/path"), uri("https://localhost/")));
    // Out-of-range port string must not silently compare equal to the default.
    EXPECT_FALSE(same(uri("https://localhost:65536/path"), uri("https://localhost:443/")));
    // Different scheme -> different origin even with the same host.
    EXPECT_FALSE(same(uri("http://localhost/path"), uri("https://localhost/")));
}

// ---------------------------------------------------------------------------
// Construction-time scheme validation
// ---------------------------------------------------------------------------

TEST(Http2ClientConfigTest, MakeClientRejectsPlainHttpBaseUri) {
    EXPECT_THROW(
        {
            auto client = qb::http2::make_client("http://localhost:29881");
            (void) client;
        },
        std::invalid_argument);
}

TEST(Http2ClientConfigTest, MakeClientAcceptsHttpsBaseUriAndExposesIt) {
    auto client = qb::http2::make_client("https://localhost:8443");
    ASSERT_NE(client, nullptr);
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());
    EXPECT_EQ(client->get_active_request_count(), 0u);

    const auto &base = client->get_base_uri();
    EXPECT_EQ(base.scheme(), "https");
    EXPECT_EQ(base.host(), "localhost");

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 0u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 0u);
}

// Pure configuration accessor surface: the verify_peer round-trip plus the
// max-concurrent-streams / max-pending setters (pure stores) that the rest of the
// suite does not otherwise reach.
TEST(Http2ClientConfigTest, ConfigurationAccessorsRoundTrip) {
    auto client = qb::http2::make_client("https://localhost:8443");

    EXPECT_TRUE(client->verify_peer()); // default: TLS verification on
    client->set_verify_peer(false);
    EXPECT_FALSE(client->verify_peer());
    client->set_verify_peer(true);
    EXPECT_TRUE(client->verify_peer());

    // Pure stores; assert callable on the public API (no observable getter, but
    // they must compile + run without disturbing the request counters / state).
    client->set_connect_timeout(5s);
    client->set_request_timeout(7s);
    client->set_max_concurrent_streams(8);
    client->set_max_pending_requests(64);
    client->set_auto_reconnect(false);

    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());
    EXPECT_EQ(client->get_active_request_count(), 0u);
    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 0u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 0u);
}

// max_pending_requests(0): a same-origin request that PASSES scheme/origin
// validation still trips the outstanding-request bound (0 pending + 0 active >= 0)
// and is rejected synchronously with 503 "pending request limit reached", failing
// the request and returning false — without ever connecting.
TEST(Http2ClientConfigTest, PendingRequestLimitRejectsValidatedRequestWith503) {
    auto client = qb::http2::make_client("https://localhost:443");
    client->set_max_pending_requests(0);

    bool               done = false;
    qb::http::Response response;
    qb::http::Request  request{qb::io::uri("https://localhost:443/ping")};
    const bool         queued = client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    });

    EXPECT_FALSE(queued); // over the bound -> push_request returns false
    ASSERT_TRUE(done);    // synchronous error callback
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(response.body().template as<std::string>(), "HTTP/2 client pending request limit reached");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);
}

// An empty batch is a synchronous no-op completion: the callback fires with an
// empty vector and the client never connects (push_requests "requests.empty()").
TEST(Http2ClientConfigTest, EmptyBatchCompletesImmediatelyWithEmptyVector) {
    auto client = qb::http2::make_client("https://localhost:443");

    bool                            done = false;
    std::vector<qb::http::Response> responses{qb::http::Response{}}; // pre-seed non-empty
    const bool                      queued = client->push_requests({}, [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done      = true;
    });

    EXPECT_TRUE(queued);
    ASSERT_TRUE(done);
    EXPECT_TRUE(responses.empty());
    EXPECT_FALSE(client->is_connecting());
}

// Empty callbacks are rejected up front (return false) with no counter side
// effects, for both the single- and batch-request entry points.
TEST(Http2ClientConfigTest, EmptyCallbacksAreRejectedWithoutSideEffects) {
    auto client = qb::http2::make_client("https://localhost:443");

    qb::http::Request req{qb::io::uri("https://localhost:443/ping")};
    EXPECT_FALSE(client->push_request(std::move(req), qb::http2::ResponseCallback{}));

    std::vector<qb::http::Request> reqs;
    reqs.emplace_back(qb::io::uri("https://localhost:443/ping"));
    EXPECT_FALSE(client->push_requests(std::move(reqs), qb::http2::BatchResponseCallback{}));

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 0u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 0u);
}

// ---------------------------------------------------------------------------
// Per-request validation rejects (callback API, no connection)
// ---------------------------------------------------------------------------

TEST(Http2ClientConfigTest, RejectsPlainHttpAbsoluteRequestWithoutConnecting) {
    auto client = qb::http2::make_client("https://localhost:1");
    client->set_connect_timeout(10ms);

    bool               done = false;
    qb::http::Response response;
    qb::http::Request  request{qb::io::uri("http://localhost:1/plain")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    // The reject is synchronous: the callback fires before push_request returns,
    // and the client never enters a connecting/connected state.
    EXPECT_TRUE(done);
    EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(response.body().template as<std::string>(), "HTTP/2 request URI must use https");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);
}

TEST(Http2ClientConfigTest, RejectsCrossOriginAbsoluteRequestWithoutConnecting) {
    auto client = qb::http2::make_client("https://localhost:443");

    bool               done = false;
    qb::http::Response response;
    qb::http::Request  request{qb::io::uri("https://example.com:443/other")};
    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response res) {
        response = std::move(res);
        done     = true;
    }));

    EXPECT_TRUE(done);
    EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(response.body().template as<std::string>(), "HTTP/2 persistent client only accepts same-origin requests");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);
}

TEST(Http2ClientConfigTest, BatchRejectsInvalidSchemesWithoutConnecting) {
    auto client = qb::http2::make_client("https://localhost:1");
    client->set_connect_timeout(10ms);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("http://localhost:1/plain"));
    requests.emplace_back(qb::io::uri("ws://localhost:1/ws"));

    bool                            done = false;
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done      = true;
    }));

    ASSERT_TRUE(done);
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[0].body().template as<std::string>(), "HTTP/2 request URI must use https");
    EXPECT_EQ(responses[1].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[1].body().template as<std::string>(), "HTTP/2 request URI must use https");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 2u);
}

TEST(Http2ClientConfigTest, BatchRejectsCrossOriginRequestsAndPreservesOrder) {
    auto client = qb::http2::make_client("https://localhost:443");

    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::io::uri("https://example.com/first"));        // cross-origin host
    requests.emplace_back(qb::io::uri("http://localhost/plain"));           // wrong scheme
    requests.emplace_back(qb::io::uri("https://localhost:444/wrong-port")); // cross-origin port

    bool                            done = false;
    std::vector<qb::http::Response> responses;
    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done      = true;
    }));

    ASSERT_TRUE(done);
    ASSERT_EQ(responses.size(), 3u);
    // Responses must come back positionally aligned with the requests.
    EXPECT_EQ(responses[0].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[0].body().template as<std::string>(), "HTTP/2 persistent client only accepts same-origin requests");
    EXPECT_EQ(responses[1].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[1].body().template as<std::string>(), "HTTP/2 request URI must use https");
    EXPECT_EQ(responses[2].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[2].body().template as<std::string>(), "HTTP/2 persistent client only accepts same-origin requests");
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 3u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 3u);
}

// ---------------------------------------------------------------------------
// Coroutine validation path (no connection): rejection surfaces through co_await
// ---------------------------------------------------------------------------

TEST(Http2ClientConfigTest, CoroPushRequestRejectsCrossOriginWithoutConnecting) {
    auto response = qb::http::run_sync([]() -> qb::io::async::task<qb::http::Response> {
        auto              client = qb::http2::make_client("https://localhost:443");
        qb::http::Request request{qb::io::uri("https://example.com:443/coro")};
        co_return co_await client->push_request(std::move(request));
    }());

    EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(response.body().template as<std::string>(), "HTTP/2 persistent client only accepts same-origin requests");
}

// ---------------------------------------------------------------------------
// Reentrancy: a failure callback may queue another batch that a later failure
// pass must still observe and complete.
// ---------------------------------------------------------------------------

TEST(Http2ClientReentrancyTest, BatchCallbackMayQueueAnotherBatchAcrossFailurePasses) {
    auto client = qb::http2::make_client("https://localhost:1");
    client->set_auto_reconnect(false);

    auto make_get_request = [](const std::string &path) {
        qb::http::Request req;
        req.method() = qb::http::Method::GET;
        req.uri()    = qb::io::uri(path);
        return req;
    };

    bool        first_batch_callback_called  = false;
    bool        second_batch_callback_called = false;
    std::size_t second_batch_response_count  = 0;

    ASSERT_TRUE(client->push_requests({make_get_request("/first")}, [&](std::vector<qb::http::Response> responses) {
        first_batch_callback_called = true;
        EXPECT_EQ(responses.size(), 1u);
        // Re-enter from inside the failure callback: queue a fresh batch.
        ASSERT_TRUE(client->push_requests({make_get_request("/second")}, [&](std::vector<qb::http::Response> second_responses) {
            second_batch_callback_called = true;
            second_batch_response_count  = second_responses.size();
        }));
    }));

    // First failure pass completes the first batch but must NOT recursively
    // drain the batch that callback just queued.
    client->on(qb::io::async::event::disconnected{1});
    EXPECT_TRUE(first_batch_callback_called);
    EXPECT_FALSE(second_batch_callback_called);

    // A subsequent failure pass observes and completes the queued batch.
    client->on(qb::io::async::event::disconnected{1});
    EXPECT_TRUE(second_batch_callback_called);
    EXPECT_EQ(second_batch_response_count, 1u);
}

// ---------------------------------------------------------------------------
// Awaiter lifetime: the client may die before the coroutine is resumed.
// ---------------------------------------------------------------------------

TEST(Http2ClientLifetimeTest, ConnectAwaiterReturnsErrorWhenClientExpiresBeforeAwait) {
    auto connect_result = qb::io::async::run_sync([]() -> qb::io::async::task<qb::http2::ConnectResult> {
        auto client  = qb::http2::make_client("https://localhost:1");
        auto awaiter = client->connect();
        client.reset(); // destroy the client before the awaiter is co_awaited
        co_return co_await awaiter;
    }());

    EXPECT_FALSE(connect_result.ok);
    EXPECT_FALSE(connect_result.error_message.empty());
}

TEST(Http2ClientLifetimeTest, PushRequestAwaiterCompletesWhenClientExpiresBeforeAwait) {
    // A request awaiter held past the client's own lifetime must still resolve
    // (to a failure Response) rather than dangle or hang the run loop.
    auto response = qb::io::async::run_sync([]() -> qb::io::async::task<qb::http::Response> {
        auto client = qb::http2::make_client("https://localhost:1");
        client->set_connect_timeout(10ms);
        qb::http::Request request{qb::io::uri("https://localhost:1/never")};
        auto              awaiter = client->push_request(std::move(request));
        client.reset(); // destroy mid-flight, before resuming the awaiter
        co_return co_await awaiter;
    }());

    // The exact status depends on teardown timing, but the coroutine MUST resume
    // with a concrete error response (never a 2xx, never a hang).
    EXPECT_GE(static_cast<int>(response.status().code()), 400);
    EXPECT_FALSE(response.body().template as<std::string>().empty());
}

TEST(Http2ClientLifetimeTest, AbandonedRequestAwaiterDestroyedWithoutAwaitDoesNotCrash) {
    // Destroy-while-awaiting in its most adversarial form: build the awaiter,
    // never co_await it, and let both it and the client go out of scope. The
    // completion handler the awaiter registered with the client must be safely
    // dropped (no use-after-free, no leaked timer firing into freed state).
    {
        auto client = qb::http2::make_client("https://localhost:1");
        client->set_connect_timeout(10ms);
        qb::http::Request request{qb::io::uri("https://localhost:1/abandon")};
        auto              awaiter = client->push_request(std::move(request));
        (void) awaiter; // never co_awaited; destroyed at end of scope with client
    }
    // Pumping the loop afterwards must not resurrect any dead continuation.
    qb::io::async::init();
    for (int i = 0; i < 8; ++i) {
        qb::io::async::run(EVRUN_NOWAIT);
    }
    SUCCEED();
}

} // namespace

/**
 * @file qbm/http/tests/system/http1/http1-loopback.cpp
 * @brief System (loopback) round-trip tests for the HTTP/1.1 protocol over qb-io.
 *
 * The runtime half of the former `test-session-http.cpp`: real qb-io HTTP/1.1
 * client/server pairs over plaintext loopback (and, for the TLS case, over a
 * self-signed loopback TLS socket). Each test stands up a server, drives a
 * worker-thread client, and pumps BOTH the client and server event loops to a
 * deterministic completion barrier via the shared `pump_until` helper — no
 * fixed iteration caps, no multi-minute wall budget, ephemeral ports throughout.
 *
 * The TLS case is a HARD prerequisite on `qb::http::test::certs_available()`:
 * a secure build with the test certs missing FAILS loudly rather than skipping.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <atomic>
#include <chrono>
#include <exception>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

#include "../http.h"

using namespace qb::io;
using namespace std::chrono_literals;
using qb::http::test::ephemeral_port;
using qb::http::test::ServerThread;

namespace {

// A loopback throughput round-trip count. Small enough to stay fast and
// deterministic on a CI loopback, large enough to exercise keep-alive reuse and
// pipelining across many request/response pairs. (The legacy 4096 + NB*5 busy
// cap was a flake source with no added coverage value.)
constexpr std::size_t NB_ITERATION     = 256;
constexpr const char  STRING_MESSAGE[] = "Here is my content test";

/// Pump the current thread's async loop until @p done() or @p budget elapses.
/// FAILS LOUD (ADD_FAILURE) on timeout — never hangs the suite. Mirrors the
/// shared ServerThread::pump_until contract but uses EVRUN_ONCE so a blocking
/// reactor pass still makes progress on both server and client threads.
template <typename F>
bool
pump_loop_until(const F &done, std::chrono::milliseconds budget = std::chrono::seconds(20)) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!done()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            ADD_FAILURE() << "pump_loop_until: predicate not satisfied within " << budget.count()
                          << "ms";
            return false;
        }
        async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
    return true;
}

// ---- Host-header-on-the-wire fixture -------------------------------------

class HostHeaderCaptureServer;

class HostHeaderCaptureClient
    : public qb::io::use<HostHeaderCaptureClient>::tcp::client<HostHeaderCaptureServer> {
public:
    constexpr static const bool has_server = true;
    using Protocol                         = qb::http::protocol<HostHeaderCaptureClient>;

    explicit HostHeaderCaptureClient(HostHeaderCaptureServer &server)
        : client(server) {}

    static std::atomic<bool> got_request;
    static std::string       captured_host_header;

    void
    on(Protocol::request &&request) {
        captured_host_header = request.header("host");
        qb::http::Response r;
        r.status() = qb::http::status::OK;
        r.body()   = "ok";
        *this << r;
        got_request.store(true);
    }
};

class HostHeaderCaptureServer
    : public qb::http::use<HostHeaderCaptureServer>::server<HostHeaderCaptureClient> {};

std::atomic<bool> HostHeaderCaptureClient::got_request{false};
std::string       HostHeaderCaptureClient::captured_host_header;

} // namespace

TEST(Http1Loopback, ClientSetsHostHeaderWithNonDefaultPort) {
    const std::uint16_t port = ephemeral_port();

    async::init();
    HostHeaderCaptureClient::captured_host_header.clear();
    HostHeaderCaptureClient::got_request.store(false);

    HostHeaderCaptureServer server;
    ASSERT_EQ(server.transport().listen_v4(port), 0);
    server.start();

    qb::http::Request req{{"http://localhost:" + std::to_string(port) + "/host-check"}};
    auto              reply = qb::http::run_sync(qb::http::GET(req, 3s));

    EXPECT_EQ(reply.response.status(), HTTP_STATUS_OK);
    EXPECT_TRUE(HostHeaderCaptureClient::got_request.load());
    EXPECT_EQ(HostHeaderCaptureClient::captured_host_header, "localhost:" + std::to_string(port));
}

// ---- Plain-TCP HTTP/1.1 round-trip throughput ----------------------------

namespace {

std::atomic<std::size_t> msg_count_server_side{0};
std::atomic<std::size_t> msg_count_client_side{0};

// Server-side request observations, captured per request and asserted from the
// test body AFTER the worker joins. The server's on() handler may run on whichever
// thread pumps the server loop, so it must NOT call gtest EXPECT/ASSERT directly
// (a failed EXPECT off the main thread is lost/UB). It records into these atomics
// instead; the test body does the asserting.
std::atomic<std::size_t> server_bad_method{0};      ///< requests whose method != GET.
std::atomic<std::size_t> server_empty_headers{0};   ///< requests with no headers.
std::atomic<std::size_t> server_bad_connection{0};  ///< requests whose Connection != keep-alive.
std::atomic<std::size_t> server_bad_query{0};       ///< requests whose ?happy != true.

bool
all_done() {
    return msg_count_server_side.load() == NB_ITERATION && msg_count_client_side.load() == NB_ITERATION;
}

class TestServer;

class TestServerClient : public qb::io::use<TestServerClient>::tcp::client<TestServer> {
public:
    constexpr static const bool has_server = true;
    using Protocol                         = qb::http::protocol<TestServerClient>;

    explicit TestServerClient(TestServer &server)
        : client(server) {}

    void
    on(Protocol::request &&request) {
        // Runs on the server-loop thread: capture observable evidence into atomics
        // and let the test body assert after join (never EXPECT/ASSERT here).
        if (request.method() != HTTP_GET) {
            ++server_bad_method;
        }
        if (request.headers().size() == 0u) {
            ++server_empty_headers;
        }
        if (request.header("connection") != "keep-alive") {
            ++server_bad_connection;
        }
        if (request.query("happy") != "true") {
            ++server_bad_query;
        }

        qb::http::Response r;
        r.status() = qb::http::status::OK;
        r.body()   = std::move(request.body());
        *this << r;

        ++msg_count_server_side;
    }
};

class TestServer : public qb::http::use<TestServer>::server<TestServerClient> {
public:
    std::atomic<std::size_t> connection_count{0};

    void
    on(IOSession &) {
        ++connection_count;
    }
};

class TestClient : public use<TestClient>::tcp::client<> {
public:
    using Protocol = qb::http::protocol<TestClient>;

    std::atomic<bool> saw_non_ok{false};

    void
    on(Protocol::response &&response) {
        if (response.status() != HTTP_STATUS_OK) {
            saw_non_ok.store(true);
        }
        ++msg_count_client_side;
    }
};

} // namespace

TEST(Http1Loopback, ChunkedRequestsRoundTripOverPlainTcp) {
    const std::uint16_t port = ephemeral_port();

    async::init();
    msg_count_server_side = 0;
    msg_count_client_side = 0;
    server_bad_method     = 0;
    server_empty_headers  = 0;
    server_bad_connection = 0;
    server_bad_query      = 0;

    TestServer server;
    ASSERT_EQ(server.transport().listen_v4(port), 0);
    server.start();

    std::atomic<bool>  client_saw_non_ok{false};
    std::exception_ptr worker_error;
    std::thread        t([&] {
        try {
            async::init();
            TestClient client;
            if (SocketStatus::Done != client.transport().connect_v4("127.0.0.1", port)) {
                throw std::runtime_error("could not connect");
            }
            client.start();

            qb::http::Request r{
                HTTP_GET,
                {"http://127.0.0.1:" + std::to_string(port) + "/?happy=true"},
                {{"Host", {"127.0.0.1:" + std::to_string(port)}},
                 {"Connection", {"keep-alive"}},
                 {"Transfer-Encoding", {"chunked"}}}
            };

            for (auto i = 0u; i < NB_ITERATION; ++i) {
                client << r;
                client << qb::http::Chunk(STRING_MESSAGE, sizeof(STRING_MESSAGE) - 1) << qb::http::Chunk();
            }

            pump_loop_until([] { return all_done(); });
            client_saw_non_ok.store(client.saw_non_ok.load());
        } catch (...) {
            worker_error = std::current_exception();
        }
    });

    pump_loop_until([&] { return all_done() || worker_error != std::exception_ptr(); });
    t.join();

    if (worker_error) {
        std::rethrow_exception(worker_error);
    }

    EXPECT_EQ(msg_count_server_side.load(), NB_ITERATION);
    EXPECT_EQ(msg_count_client_side.load(), NB_ITERATION);
    EXPECT_FALSE(client_saw_non_ok.load());
    EXPECT_GE(server.connection_count.load(), 1u);

    // Server-side per-request observations, captured off the test thread and
    // asserted here after the worker joined: every request must have been a
    // well-formed GET with non-empty headers, keep-alive, and ?happy=true.
    EXPECT_EQ(server_bad_method.load(), 0u);
    EXPECT_EQ(server_empty_headers.load(), 0u);
    EXPECT_EQ(server_bad_connection.load(), 0u);
    EXPECT_EQ(server_bad_query.load(), 0u);
}

TEST(Http1Loopback, AsyncGetRoundTripsOverPlainTcp) {
    const std::uint16_t port = ephemeral_port();

    async::init();
    msg_count_server_side = 0;
    msg_count_client_side = 0;

    TestServer server;
    ASSERT_EQ(server.transport().listen_v4(port), 0);
    server.start();

    std::atomic<bool>  any_status_mismatch{false};
    std::exception_ptr worker_error;
    std::thread        t([&] {
        try {
            async::init();

            qb::http::Request r{
                {"http://localhost:" + std::to_string(port) + "/?happy=true"},
                {{"Host", {"127.0.0.1:" + std::to_string(port)}},
                 {"Connection", {"keep-alive"}},
                 {"Authorization", {"None"}}},
                {STRING_MESSAGE}
            };

            for (auto i = 0u; i < NB_ITERATION; ++i) {
                auto res = qb::http::run_sync(qb::http::GET(r)).response;
                if (res.status() != HTTP_STATUS_OK) {
                    any_status_mismatch.store(true);
                }
                ++msg_count_client_side;
            }
        } catch (...) {
            worker_error = std::current_exception();
        }
    });

    pump_loop_until([&] { return all_done() || worker_error != std::exception_ptr(); });
    t.join();

    if (worker_error) {
        std::rethrow_exception(worker_error);
    }

    EXPECT_EQ(msg_count_server_side.load(), NB_ITERATION);
    EXPECT_EQ(msg_count_client_side.load(), NB_ITERATION);
    EXPECT_FALSE(any_status_mismatch.load());
}

// ---- Secure (TLS) HTTP/1.1 round-trip ------------------------------------

#ifdef QB_HAS_SSL

namespace {

class TestSecureServer;

class TestSecureServerClient
    : public use<TestSecureServerClient>::tcp::ssl::client<TestSecureServer> {
public:
    using Protocol = qb::http::protocol<TestSecureServerClient>;

    explicit TestSecureServerClient(IOServer &server)
        : client(server) {}

    void
    on(Protocol::request &&request) {
        EXPECT_EQ(request.method(), HTTP_GET);
        EXPECT_EQ(request.header("connection"), "keep-alive");
        EXPECT_EQ(request.query("happy"), "true");

        qb::http::Response r;
        r.status() = qb::http::status::OK;
        r.body()   = std::move(request.body());
        *this << r;

        ++msg_count_server_side;
    }
};

class TestSecureServer : public use<TestSecureServer>::tcp::ssl::server<TestSecureServerClient> {
public:
    std::atomic<std::size_t> connection_count{0};

    void
    on(IOSession &) {
        ++connection_count;
    }
};

class TestSecureClient : public use<TestSecureClient>::tcp::ssl::client<> {
public:
    using Protocol = qb::http::protocol<TestSecureClient>;

    std::atomic<bool> saw_non_ok{false};

    void
    on(Protocol::response &&response) {
        if (response.status() != HTTP_STATUS_OK) {
            saw_non_ok.store(true);
        }
        ++msg_count_client_side;
    }
};

} // namespace

TEST(Http1Loopback, SecureRequestsRoundTripOverTls) {
    // HARD prerequisite: a secure build MUST have the test certs; missing certs
    // are a build/config error, not a reason to silently skip TLS coverage.
    ASSERT_TRUE(qb::http::test::certs_available())
        << "Missing TLS test resources: " << qb::http::test::ssl_cert_path() << " / "
        << qb::http::test::ssl_key_path();

    const auto          cert_path = qb::http::test::ssl_cert_path();
    const auto          key_path  = qb::http::test::ssl_key_path();
    const std::uint16_t port      = ephemeral_port("::1");

    async::init();
    msg_count_server_side = 0;
    msg_count_client_side = 0;

    TestSecureServer server;
    server.transport().init(
        ssl::create_server_context(TLS_server_method(), cert_path.string(), key_path.string()));
    ASSERT_EQ(server.transport().listen_v6(port), 0);
    server.start();

    std::atomic<bool>  client_saw_non_ok{false};
    std::exception_ptr worker_error;
    std::thread        t([&] {
        try {
            async::init();
            TestSecureClient client;
            // Self-signed test certificate: opt out of qb-io's secure-by-default
            // peer verification for this local fixture.
            client.transport().set_insecure();
            if (SocketStatus::Done !=
                client.transport().connect(uri{"tcp://[::1]:" + std::to_string(port), AF_INET6})) {
                throw std::runtime_error("could not connect");
            }
            client.start();

            qb::http::Request r{
                HTTP_GET,
                {"http://127.0.0.1:" + std::to_string(port) + "/?happy=true"},
                {{"Host", {"127.0.0.1:" + std::to_string(port)}}, {"Connection", {"keep-alive"}}},
                {STRING_MESSAGE}
            };

            for (auto i = 0u; i < NB_ITERATION; ++i) {
                client << r;
            }

            pump_loop_until([] { return all_done(); });
            client_saw_non_ok.store(client.saw_non_ok.load());
        } catch (...) {
            worker_error = std::current_exception();
        }
    });

    pump_loop_until([&] { return all_done() || worker_error != std::exception_ptr(); });
    t.join();

    if (worker_error) {
        std::rethrow_exception(worker_error);
    }

    EXPECT_EQ(msg_count_server_side.load(), NB_ITERATION);
    EXPECT_EQ(msg_count_client_side.load(), NB_ITERATION);
    EXPECT_FALSE(client_saw_non_ok.load());
    EXPECT_EQ(server.connection_count.load(), 1u);
}

#endif // QB_HAS_SSL

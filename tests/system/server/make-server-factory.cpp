/**
 * @file qbm/http/tests/system/server/make-server-factory.cpp
 * @brief Live loopback tests for the qbm-http server factory functions.
 *
 * The system-tier successor to `test-integration-make-server.cpp`. It verifies
 * the three factory entry points produce a server that actually serves over the
 * loopback interface:
 *
 *   - `qb::http::make_server()`        -> plaintext HTTP/1.1   (UN-GATED)
 *   - `qb::http::ssl::make_server()`   -> HTTPS                (REQUIRES ssl)
 *   - `qb::http2::make_server()`       -> HTTP/2 over TLS+ALPN (REQUIRES ssl)
 *
 * Differences from the legacy file (per the restructure spec, §2/§7):
 *   - DROP the misleading `integration-` prefix (loopback, not daemon).
 *   - UN-GATE the plaintext HTTP/1.1 fixture: it has no SSL dependency and must
 *     build/run on `QB_HAS_SSL=OFF`. Only the https/h2 fixtures stay behind
 *     `#if QB_HAS_SSL`.
 *   - The hand-rolled server threads (fixed magic ports 29878/29880/29882,
 *     `server_ready` busy flags, 200ms/100ms `sleep_for` settles) are replaced
 *     by the shared `ServerThread<>` RAII (loopback_server.h): readiness via
 *     condition variable, ephemeral ports, worker-thread run loops.
 *   - The self-incremented client/server smoke counters are dropped; tests
 *     assert OBSERVABLE response state. The server-side request counter that
 *     still carries signal (proving the handler ran exactly once) is an atomic
 *     owned by the test and asserted in the test body after completion.
 *   - The cert-missing `GTEST_SKIP` + `check_test_certs_exist()` helper is
 *     replaced by the shared `certs_available()` HARD prerequisite.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include <qb/io/async.h>
#include <qb/io/uri.h>

#include <qbm/http/http.h>

#include "../../shared/loopback_server.h"
#if QB_HAS_SSL && !defined(QBM_TEST_FACTORY_PLAINTEXT_ONLY)
#include <qbm/http/2/client.h>
#include <qbm/http/2/http2.h>
#include "../../shared/ssl_test_resource.h"
#endif

using namespace std::chrono_literals;

namespace {

// ===========================================================================
// Plaintext HTTP/1.1 factory (UN-GATED — no SSL dependency)
// ===========================================================================

#if !defined(QBM_TEST_FACTORY_TLS_ONLY)
using PlainServer       = qb::http::Server<>;
using PlainServerThread = qb::http::test::ServerThread<PlainServer>;

// Server-side request count: the one counter that still carries signal (it
// proves the factory-built handler actually ran). It is an atomic so the test
// thread can read it after the request round-trips.
std::atomic<int> g_plain_server_requests{0};

class HttpMakeServerTest : public ::testing::Test {
protected:
    std::uint16_t                      _port{0};
    std::unique_ptr<PlainServerThread> _server;

    void
    SetUp() override {
        qb::io::async::init();
        g_plain_server_requests = 0;

        // Bind :0 on the socket that ACTUALLY SERVES and read the port back, rather than probing
        // for a free port and binding it a moment later. `ephemeral_port()` documents the hole
        // this closes: its probe must be shut before the caller can bind, so under `ctest -j`
        // another test PROCESS can take the port in that window (measured: 2 failures in 12
        // full-suite runs). Binding :0 here leaves no window at all.
        _server = std::make_unique<PlainServerThread>([] { return qb::http::make_server(); },
                                                      [](PlainServer &srv) -> bool {
                                                          srv.router().get(
                                                              "/ping", [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
                                                                  ++g_plain_server_requests;
                                                                  ctx->response().status() = qb::http::status::OK;
                                                                  ctx->response().body()   = "pong_http_default";
                                                                  ctx->complete();
                                                              });
                                                          srv.router().compile();
                                                          if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
                                                              return false;
                                                          }
                                                          srv.start();
                                                          return true;
                                                      });
        ASSERT_TRUE(_server->ready()) << "plaintext HTTP/1.1 loopback server failed to start";
        // The ServerThread ctor already blocked on the readiness barrier, so the transport is
        // bound and its assigned port is visible to this thread.
        _port = _server->server().transport().local_endpoint().port();
        ASSERT_NE(_port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    }

    void
    TearDown() override {
        _server.reset();
    }

    [[nodiscard]] std::string
    base_url() const {
        return "http://localhost:" + std::to_string(_port);
    }
};

TEST_F(HttpMakeServerTest, PingDefaultSessionHttpServer) {
    qb::http::Request request{{base_url() + "/ping"}};
    auto              response = qb::http::run_sync(qb::http::GET(request)).response;

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("pong_http_default", response.body().as<std::string>());
    EXPECT_EQ(1, g_plain_server_requests.load());
}

std::mutex      g_probe_mutex;
std::thread::id g_probe_constructed_on;
std::thread::id g_probe_destroyed_on;

struct ThreadOwnershipProbe {
    ThreadOwnershipProbe() {
        std::lock_guard<std::mutex> lock(g_probe_mutex);
        g_probe_constructed_on = std::this_thread::get_id();
    }
    ~ThreadOwnershipProbe() {
        std::lock_guard<std::mutex> lock(g_probe_mutex);
        g_probe_destroyed_on = std::this_thread::get_id();
    }
};

void
run_failed_server_configuration(bool throws) {
    qb::http::test::ServerThread<ThreadOwnershipProbe> server([] { return std::make_unique<ThreadOwnershipProbe>(); },
                                                              [throws](ThreadOwnershipProbe &) -> bool {
                                                                  if (throws) {
                                                                      throw std::runtime_error("controlled configure failure");
                                                                  }
                                                                  return false;
                                                              });
    EXPECT_FALSE(server.ready());
    EXPECT_THROW((void) server.server(), std::logic_error);
}

TEST(ServerThreadFixture, FailedStartupDestroysServerOnItsWorker) {
    const auto caller_thread = std::this_thread::get_id();
    for (const bool throws : {false, true}) {
        {
            std::lock_guard<std::mutex> lock(g_probe_mutex);
            g_probe_constructed_on = {};
            g_probe_destroyed_on   = {};
        }

        if (throws) {
            EXPECT_NONFATAL_FAILURE(run_failed_server_configuration(true), "configure callback failed or threw during startup");
        } else {
            EXPECT_NONFATAL_FAILURE(run_failed_server_configuration(false), "configure callback failed or threw during startup");
        }

        std::lock_guard<std::mutex> lock(g_probe_mutex);
        EXPECT_NE(g_probe_constructed_on, std::thread::id{});
        EXPECT_EQ(g_probe_destroyed_on, g_probe_constructed_on);
        EXPECT_NE(g_probe_destroyed_on, caller_thread);
    }
}
#endif

#if QB_HAS_SSL && !defined(QBM_TEST_FACTORY_PLAINTEXT_ONLY)

// ===========================================================================
// HTTPS factory (REQUIRES ssl)
// ===========================================================================

using SecureServer       = qb::http::ssl::Server<>;
using SecureServerThread = qb::http::test::ServerThread<SecureServer>;

std::atomic<int> g_https_server_requests{0};

class HttpsMakeServerTest : public ::testing::Test {
protected:
    std::uint16_t                       _port{0};
    std::unique_ptr<SecureServerThread> _server;

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available())
            << "Missing TLS test certificates (looked for " << qb::http::test::ssl_cert_path() << " and " << qb::http::test::ssl_key_path()
            << "). The HTTPS factory system suite REQUIRES them.";

        qb::io::async::init();
        g_https_server_requests = 0;

        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();

        // Bind :0 on the socket that ACTUALLY SERVES and read the port back (see the plaintext
        // fixture above for why): the probe-then-bind window is a cross-process race under
        // `ctest -j`, and binding :0 on the serving socket removes it entirely.
        _server = std::make_unique<SecureServerThread>(
            [] { return qb::http::ssl::make_server(); },
            [cert, key](SecureServer &srv) -> bool {
                auto tls = qb::io::ssl::Context::server(cert, key);
                if (!tls.ok()) {
                    return false;
                }
                srv.transport().init(std::move(tls));
                srv.router().get("/ping_ssl", [](std::shared_ptr<qb::http::Context<qb::http::ssl::DefaultSecureSession>> ctx) {
                    ++g_https_server_requests;
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   = "pong_https_default";
                    ctx->complete();
                });
                srv.router().compile();
                if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
                    return false;
                }
                srv.start();
                return true;
            });
        ASSERT_TRUE(_server->ready()) << "HTTPS loopback server failed to start";
        _port = _server->server().transport().local_endpoint().port();
        ASSERT_NE(_port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    }

    void
    TearDown() override {
        _server.reset();
    }

    [[nodiscard]] std::string
    base_url() const {
        return "https://localhost:" + std::to_string(_port);
    }
};

TEST_F(HttpsMakeServerTest, PingDefaultSessionHttpsServer) {
    qb::http::Request request{{base_url() + "/ping_ssl"}};
    // Self-signed test certificate: opt out of secure-by-default verification.
    auto response = qb::http::run_sync(qb::http::GET(request, qb::duration::zero(), /*verify_peer=*/false)).response;

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("pong_https_default", response.body().as<std::string>());
    EXPECT_EQ(1, g_https_server_requests.load());
}

TEST_F(HttpsMakeServerTest, MixedCaseHttpsOneShotUsesTlsTransport) {
    std::string origin = base_url();
    origin.replace(0, 5, "HtTpS");
    qb::http::Request request{{origin + "/ping_ssl"}};
    auto              response = qb::http::run_sync(qb::http::GET(request, std::chrono::seconds(2), /*verify_peer=*/false)).response;

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("pong_https_default", response.body().as<std::string>());
    EXPECT_EQ(1, g_https_server_requests.load());
}

// ===========================================================================
// HTTP/2 factory (REQUIRES ssl)
// ===========================================================================

using Http2FactoryServer       = qb::http2::Server<>;
using Http2FactoryServerThread = qb::http::test::ServerThread<Http2FactoryServer>;

std::atomic<int> g_http2_server_requests{0};

class Http2MakeServerTest : public ::testing::Test {
protected:
    std::uint16_t                             _port{0};
    std::unique_ptr<Http2FactoryServerThread> _server;

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available())
            << "Missing TLS test certificates (looked for " << qb::http::test::ssl_cert_path() << " and " << qb::http::test::ssl_key_path()
            << "). The HTTP/2 factory system suite REQUIRES them.";

        qb::io::async::init();
        g_http2_server_requests = 0;

        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();

        // Bind :0 on the socket that ACTUALLY SERVES and read the port back (see the plaintext
        // fixture above for why): the probe-then-bind window is a cross-process race under
        // `ctest -j`, and binding :0 on the serving socket removes it entirely.
        _server = std::make_unique<Http2FactoryServerThread>(
            [] { return qb::http2::make_server(); },
            [cert, key](Http2FactoryServer &srv) -> bool {
                auto tls = qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"});
                if (!tls.ok()) {
                    return false;
                }
                srv.transport().init(std::move(tls));
                srv.router().get("/ping_http2", [](std::shared_ptr<qb::http::Context<qb::http2::DefaultSession>> ctx) {
                    ++g_http2_server_requests;
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   = "pong_http2_default";
                    ctx->complete();
                });
                // A response larger than the default per-stream send window forces
                // the factory-built server through its flow-control / pending-DATA
                // path over a real socket.
                srv.router().get("/big_http2", [](std::shared_ptr<qb::http::Context<qb::http2::DefaultSession>> ctx) {
                    std::string body;
                    body.reserve(300 * 1024);
                    body += "BIG-START;";
                    while (body.size() < 300 * 1024) {
                        body += static_cast<char>('a' + (body.size() % 26));
                    }
                    body += ";BIG-END";
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   = std::move(body);
                    ctx->complete();
                });
                srv.router().compile();
                if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
                    return false;
                }
                srv.start();
                return true;
            });
        ASSERT_TRUE(_server->ready()) << "HTTP/2 loopback server failed to start";
        _port = _server->server().transport().local_endpoint().port();
        ASSERT_NE(_port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    }

    void
    TearDown() override {
        _server.reset();
    }

    [[nodiscard]] std::string
    base_url() const {
        return "https://localhost:" + std::to_string(_port);
    }
};

TEST_F(Http2MakeServerTest, PingHttp2Server) {
    auto client = std::make_shared<qb::http2::Client>(base_url());
    client->set_verify_peer(false); // self-signed test cert
    client->set_connect_timeout(5s);

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

    qb::http::Request request{{base_url() + "/ping_http2"}};
    request.method() = qb::http::Method::GET;

    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(Http2FactoryServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("pong_http2_default", response.body().as<std::string>());
    EXPECT_EQ(1, g_http2_server_requests.load());

    client->disconnect();
}

// A >256KiB response from the factory-built HTTP/2 server: the per-stream send
// window cannot hold it, so the server's flow-control machinery (pending-DATA
// queue + client WINDOW_UPDATE accounting in 2/protocol/server.h) carries the
// body to completion. Asserting the reassembled sentinels proves end-to-end
// integrity across many flow-controlled DATA frames.
TEST_F(Http2MakeServerTest, FactoryServerStreamsLargeFlowControlledResponse) {
    auto client = std::make_shared<qb::http2::Client>(base_url());
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

    qb::http::Request request{{base_url() + "/big_http2"}};
    request.method() = qb::http::Method::GET;

    ASSERT_TRUE(client->push_request(std::move(request), [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(Http2FactoryServerThread::pump_until([&] { return response_received.load(); }, 15s));

    EXPECT_EQ(qb::http::status::OK, response.status());
    const std::string body = response.body().as<std::string>();
    EXPECT_GT(body.size(), 300u * 1024u);
    EXPECT_EQ(body.compare(0, 10, "BIG-START;"), 0);
    EXPECT_NE(body.find(";BIG-END"), std::string::npos);

    client->disconnect();
}

// Two concurrent streams on one factory-built HTTP/2 connection are each
// answered, and the per-handler request counter advances exactly twice —
// exercising the server session's multiplexed request dispatch + per-stream
// response/cleanup across a real socket.
TEST_F(Http2MakeServerTest, FactoryServerMultiplexesConcurrentStreams) {
    auto client = std::make_shared<qb::http2::Client>(base_url());
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);

    std::atomic<int>                responses_received{0};
    std::vector<qb::http::Response> responses(2);

    for (int i = 0; i < 2; ++i) {
        qb::http::Request request{{base_url() + "/ping_http2"}};
        request.method() = qb::http::Method::GET;
        ASSERT_TRUE(client->push_request(std::move(request), [&, i](qb::http::Response r) {
            responses[i] = std::move(r);
            ++responses_received;
        }));
    }
    client->connect(nullptr);

    ASSERT_TRUE(Http2FactoryServerThread::pump_until([&] { return responses_received.load() == 2; }));

    for (const auto &r : responses) {
        EXPECT_EQ(qb::http::status::OK, r.status());
        EXPECT_EQ("pong_http2_default", r.body().as<std::string>());
    }
    EXPECT_EQ(2, g_http2_server_requests.load());

    client->disconnect();
}

// The factory HTTP/2 server advertises {h2, http/1.1}. A plain HTTPS/1.1 client
// (run_sync) negotiates http/1.1 over ALPN and is served by the SAME handler
// through the session's HTTP/1.1 protocol branch — proving the factory server
// transparently supports the ALPN fallback.
TEST_F(Http2MakeServerTest, FactoryServerServesHttp1FallbackOverAlpn) {
    qb::http::Request request{{base_url() + "/ping_http2"}};
    auto              response = qb::http::run_sync(qb::http::GET(request, qb::duration::zero(), /*verify_peer=*/false)).response;

    EXPECT_EQ(qb::http::status::OK, response.status());
    EXPECT_EQ("pong_http2_default", response.body().as<std::string>());
    EXPECT_EQ(1, g_http2_server_requests.load());
}

#endif // QB_HAS_SSL

} // namespace

#if !defined(QBM_TEST_FACTORY_TLS_ONLY)
namespace server_context_teardown_test {
using PlainContext = qb::http::Context<qb::http::DefaultSession>;

struct NameObservations {
    int                      completions = 0;
    std::vector<std::string> names;

    void
    observe(PlainContext &context, qb::http::HookPoint point) {
        if (point != qb::http::HookPoint::REQUEST_COMPLETE)
            return;
        ++completions;
        for (const auto &[name, value] : context.path_parameters().get_all()) {
            EXPECT_EQ(value, "value");
            names.emplace_back(name);
        }
    }
};

bool
dispatch_request(const std::shared_ptr<qb::http::DefaultSession> &session, std::string_view method = "GET") {
    const std::string raw = std::string(method)
                            + " /records/value HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n"
                              "Content-Length: 0\r\n\r\n";
    session->in().write(raw.data(), raw.size());
    auto      *protocol = session->protocol();
    const auto size     = protocol->getMessageSize();
    if (size != raw.size()) {
        ADD_FAILURE() << "the existing stock parser must consume this complete request";
        return false;
    }
    protocol->onMessage(size);
    return true;
}

class PendingErrorTask : public qb::http::IAsyncTask<qb::http::DefaultSession> {
    int &_calls;
    int *_cancellations;

public:
    explicit PendingErrorTask(int &calls, int *cancellations = nullptr)
        : _calls(calls)
        , _cancellations(cancellations) {}
    void
    execute(std::shared_ptr<PlainContext> context) override {
        EXPECT_EQ(context->state(), PlainContext::State::Running);
        ++_calls;
    }
    void
    cancel() override {
        if (_cancellations)
            ++*_cancellations;
    }
    std::string
    name() const override {
        return "PendingErrorTask";
    }
};

enum class EarlyDecision { PreRoutingCancel, Cancel, Complete, Continue, Error, EmptyChain };

// Candidate-only lifetime controls: observations after router destruction
// deliberately rely on the compiled chain's name ownership being installed.
void
early_hook_teardown(EarlyDecision decision) {
    qb::io::async::init();
    const std::string             parameter_name(128, 'h');
    NameObservations              observations;
    std::shared_ptr<PlainContext> held;
    int                           handlers            = 0;
    int                           error_tasks         = 0;
    int                           error_cancellations = 0;
    auto                          server              = qb::http::make_server();
    auto                          weak_core           = server->router().get_router_core_weak_ptr();
    server->router().get("/records/:" + parameter_name, [&](auto context) {
        ++handlers;
        context->text("handler must not run");
    });
    server->router().set_error_task_chain({std::make_shared<PendingErrorTask>(error_tasks, &error_cancellations)});
    server->router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        observations.observe(context, point);
        const auto selected_point =
            decision == EarlyDecision::PreRoutingCancel ? qb::http::HookPoint::PRE_ROUTING : qb::http::HookPoint::PRE_HANDLER_EXECUTION;
        if (point != selected_point)
            return;
        held = context.shared_from_this();
        switch (decision) {
            case EarlyDecision::PreRoutingCancel:
            case EarlyDecision::Cancel:
                context.cancel("early hook");
                break;
            case EarlyDecision::Complete:
                context.complete();
                break;
            case EarlyDecision::Continue:
                context.complete(qb::http::AsyncTaskResult::CONTINUE);
                break;
            case EarlyDecision::Error:
                context.complete(qb::http::AsyncTaskResult::ERROR);
                break;
            case EarlyDecision::EmptyChain:
                break;
        }
    });
    server->router().compile();
    if (decision == EarlyDecision::EmptyChain) {
        auto core = weak_core.lock();
        ASSERT_NE(core, nullptr);
        core->register_compiled_route("/records/:" + parameter_name, qb::http::method::GET, {});
    }
    auto session = std::make_shared<qb::http::DefaultSession>(*server);
    server->sessions().emplace(session->id(), session);
    ASSERT_TRUE(dispatch_request(session));
    if (decision == EarlyDecision::EmptyChain)
        held = session->context(); // The empty-chain terminal branch precedes PRE_HANDLER.
    ASSERT_NE(held, nullptr);
    EXPECT_EQ(handlers, 0);
    EXPECT_EQ(error_tasks, decision == EarlyDecision::Error ? 1 : 0);
    if (decision == EarlyDecision::Error) {
        EXPECT_FALSE(held->is_completed());
        EXPECT_EQ(held->state(), PlainContext::State::Running);
        EXPECT_EQ(held->get_processing_phase(), PlainContext::ProcessingPhase::ERROR_CHAIN);
        server->router().compile(); // Error ownership must keep the previous names.
    } else {
        EXPECT_TRUE(held->is_completed());
    }
    session.reset();
    server.reset();
    EXPECT_TRUE(weak_core.expired()) << "retaining names must not retain RouterCore";
    EXPECT_EQ(held->session(), nullptr);
    EXPECT_EQ(held->path_param(parameter_name), "value");
    if (decision == EarlyDecision::Error) {
        held->cancel("pending error task");
        held->cancel("duplicate cancellation");
        EXPECT_EQ(error_cancellations, 1);
    }
    EXPECT_TRUE(held->is_completed());
    EXPECT_EQ(error_tasks, decision == EarlyDecision::Error ? 1 : 0);
    EXPECT_EQ(observations.completions, 0);
    held.reset();
    EXPECT_EQ(observations.completions, 1);
    EXPECT_EQ(observations.names, (std::vector<std::string>{parameter_name}));
}

void
error_after_recompile_teardown(bool method_not_allowed) {
    qb::io::async::init();
    const std::string             parameter_name(128, 'e');
    NameObservations              observations;
    std::shared_ptr<PlainContext> held;
    int                           error_tasks = 0;
    auto                          server      = qb::http::make_server();
    auto                          weak_core   = server->router().get_router_core_weak_ptr();
    if (method_not_allowed) {
        server->router().use([&](std::shared_ptr<PlainContext> context, auto) { held = std::move(context); });
        server->router().get("/records/:" + parameter_name, [](auto context) { context->text("GET handler must not run"); });
    } else {
        server->router().get("/records/:" + parameter_name, [&](auto context) { held = std::move(context); });
    }
    server->router().set_error_task_chain({std::make_shared<PendingErrorTask>(error_tasks)});
    server->router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) { observations.observe(context, point); });
    server->router().compile();
    auto session = std::make_shared<qb::http::DefaultSession>(*server);
    server->sessions().emplace(session->id(), session);
    ASSERT_TRUE(dispatch_request(session, method_not_allowed ? "POST" : "GET"));
    ASSERT_NE(held, nullptr);
    ASSERT_FALSE(held->is_completed());
    if (method_not_allowed) {
        EXPECT_EQ(held->get_processing_phase(), PlainContext::ProcessingPhase::METHOD_NOT_ALLOWED_CHAIN);
        EXPECT_EQ(held->response().status(), qb::http::status::METHOD_NOT_ALLOWED);
        EXPECT_EQ(held->response().header("Allow"), "GET");
    }
    server->router().compile();
    held->complete(qb::http::AsyncTaskResult::ERROR);
    ASSERT_FALSE(held->is_completed());
    EXPECT_EQ(held->get_processing_phase(), PlainContext::ProcessingPhase::ERROR_CHAIN);
    EXPECT_EQ(error_tasks, 1);
    session.reset();
    server.reset();
    EXPECT_TRUE(weak_core.expired());
    EXPECT_EQ(held->session(), nullptr);
    EXPECT_EQ(held->path_param(parameter_name), "value");
    held->complete();
    EXPECT_EQ(error_tasks, 1);
    held.reset();
    EXPECT_EQ(observations.completions, 1);
    EXPECT_EQ(observations.names, (std::vector<std::string>{parameter_name}));
}

// QB-512 uses the real factory server, real DefaultSession, its stock protocol,
// stock router and stock session registry. No caller retains Context/RouterCore.
// Input is handed to IProtocol synchronously and no transport write is driven:
// pendingWrite proves that the Context is still owned at server destruction.
void
pending_response_teardown(bool retire_sessions_first, bool wildcard = false) {
    qb::io::async::init();
    const std::string        parameter_name(128, 'p');
    std::vector<std::string> names_seen;
    int                      completions = 0;
    auto                     server      = qb::http::make_server();
    server->router().get(std::string("/records/") + (wildcard ? "*" : ":") + parameter_name, [](auto context) { context->text("queued"); });
    server->router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (point == qb::http::HookPoint::REQUEST_COMPLETE) {
            ++completions;
            for (const auto &[name, value] : context.path_parameters().get_all()) {
                EXPECT_EQ(value, "value");
                names_seen.emplace_back(name);
            }
        }
    });
    server->router().compile();
    auto session = std::make_shared<qb::http::DefaultSession>(*server);
    server->sessions().emplace(session->id(), session);
    const std::string raw = "GET /records/value HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
    session->in().write(raw.data(), raw.size());
    auto      *protocol = session->protocol();
    const auto size     = protocol->getMessageSize();
    ASSERT_EQ(size, raw.size());
    protocol->onMessage(size);
    ASSERT_NE(session->context(), nullptr);
    ASSERT_TRUE(session->context()->is_completed());
    ASSERT_GT(session->out().size(), 0u);
    std::weak_ptr<qb::http::Context<qb::http::DefaultSession>> weak_context = session->context();
    session.reset();
    ASSERT_FALSE(weak_context.expired());
    if (retire_sessions_first)
        server->sessions().clear();
    server.reset();
    EXPECT_TRUE(weak_context.expired());
    EXPECT_EQ(completions, 1);
    EXPECT_EQ(names_seen, (std::vector<std::string>{parameter_name}));
}
} // namespace server_context_teardown_test

TEST(HttpMakeServerTeardown, PendingResponseContextKeepsRouteNamesUntilServerTeardown) {
    for (const bool wildcard : {false, true}) {
        SCOPED_TRACE(wildcard ? "wildcard name" : "parameter name");
        server_context_teardown_test::pending_response_teardown(false, wildcard);
    }
}

TEST(HttpMakeServerTeardown, ExplicitSessionTeardownKeepsRouteNamesValid) {
    for (const bool wildcard : {false, true}) {
        SCOPED_TRACE(wildcard ? "wildcard name" : "parameter name");
        server_context_teardown_test::pending_response_teardown(true, wildcard);
    }
}

TEST(HttpMakeServerTeardown, ExternallyRetainedContextKeepsNamesAfterRouterAndSessionDestruction) {
    using namespace server_context_teardown_test;
    qb::io::async::init();
    const std::string             parameter_name(128, 'a');
    NameObservations              observations;
    std::shared_ptr<PlainContext> held;
    auto                          server    = qb::http::make_server();
    auto                          weak_core = server->router().get_router_core_weak_ptr();
    // No router hooks: use the ordinary setter/start path, and register the
    // teardown observer from the actual handler after chain adoption.
    server->router().get("/records/:" + parameter_name, [&](auto context) {
        held = std::move(context);
        held->add_lifecycle_hook([&](auto &ctx, qb::http::HookPoint point) { observations.observe(ctx, point); });
    });
    server->router().compile();
    auto session = std::make_shared<qb::http::DefaultSession>(*server);
    server->sessions().emplace(session->id(), session);
    ASSERT_TRUE(dispatch_request(session));
    ASSERT_NE(held, nullptr);
    ASSERT_FALSE(held->is_completed());
    session.reset();
    server.reset();
    EXPECT_TRUE(weak_core.expired());
    EXPECT_EQ(held->session(), nullptr);
    EXPECT_EQ(held->path_param(parameter_name), "value");
    held->text("late completion with no session");
    EXPECT_TRUE(held->is_completed());
    EXPECT_EQ(observations.completions, 0);
    held.reset();
    EXPECT_EQ(observations.completions, 1);
    EXPECT_EQ(observations.names, (std::vector<std::string>{parameter_name}));
}

TEST(HttpMakeServerTeardown, PreRoutingCancelRetainsTheNamesMatchedAfterFinalization) {
    server_context_teardown_test::early_hook_teardown(server_context_teardown_test::EarlyDecision::PreRoutingCancel);
}

TEST(HttpMakeServerTeardown, PreHandlerCancelRetainsNamesWithoutStartingTheHandler) {
    server_context_teardown_test::early_hook_teardown(server_context_teardown_test::EarlyDecision::Cancel);
}

TEST(HttpMakeServerTeardown, PreHandlerCompleteRetainsNamesWithoutStartingTheHandler) {
    server_context_teardown_test::early_hook_teardown(server_context_teardown_test::EarlyDecision::Complete);
}

TEST(HttpMakeServerTeardown, PreHandlerContinueKeepsItsTerminalPolicyAndNames) {
    server_context_teardown_test::early_hook_teardown(server_context_teardown_test::EarlyDecision::Continue);
}

TEST(HttpMakeServerTeardown, PreHandlerErrorStartsItsPendingErrorTaskOnlyOnce) {
    server_context_teardown_test::early_hook_teardown(server_context_teardown_test::EarlyDecision::Error);
}

TEST(HttpMakeServerTeardown, EmptyMatchedChainRetainsNamesBeforeItsTerminalCompletion) {
    server_context_teardown_test::early_hook_teardown(server_context_teardown_test::EarlyDecision::EmptyChain);
}

TEST(HttpMakeServerTeardown, ErrorAfterRecompileRetainsTheOriginalParameterNames) {
    server_context_teardown_test::error_after_recompile_teardown(false);
}

TEST(HttpMakeServerTeardown, MethodNotAllowedErrorAfterRecompileRetainsTheMatchedGeneration) {
    server_context_teardown_test::error_after_recompile_teardown(true);
}

#endif // !QBM_TEST_FACTORY_TLS_ONLY

#if QB_HAS_SSL && !defined(QBM_TEST_FACTORY_PLAINTEXT_ONLY)
TEST(HttpMakeServerTeardown, Http2FactoryPendingContextKeepsNamesUntilServerTeardown) {
    qb::io::async::init();
    ASSERT_TRUE(qb::http::test::certs_available());
    const std::string                                             parameter_name(128, 't');
    std::vector<std::string>                                      names_seen;
    int                                                           completions = 0;
    std::shared_ptr<qb::http::Context<qb::http2::DefaultSession>> held;
    auto                                                          server = qb::http2::make_server();
    server->router().get("/records/:" + parameter_name, [&](auto context) { held = std::move(context); });
    server->router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (point != qb::http::HookPoint::REQUEST_COMPLETE)
            return;
        ++completions;
        for (const auto &[name, value] : context.path_parameters().get_all()) {
            EXPECT_EQ(value, "value");
            names_seen.emplace_back(name);
        }
    });
    server->router().compile();
    server->transport().init(qb::io::ssl::Context::server(qb::http::test::ssl_cert_path().string(), qb::http::test::ssl_key_path().string())
                                 .alpn({"h2", "http/1.1"}));
    ASSERT_EQ(server->transport().listen_v4(0, "127.0.0.1"), 0);
    server->start();
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server->transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/records/value")}, [](auto) {}));
    ASSERT_TRUE(Http2FactoryServerThread::pump_until([&] { return held != nullptr; }));
    auto session = held->session();
    ASSERT_NE(session, nullptr);
    session->stop();
    ASSERT_EQ(session->out().size(), 0u);
    held->text("factory response queued before teardown");
    ASSERT_TRUE(held->is_completed());
    ASSERT_GT(session->out().size(), 0u);
    auto *protocol = static_cast<qb::http2::DefaultSession::Http2Protocol *>(session->protocol());
    ASSERT_TRUE(protocol->is_stream_closed(static_cast<std::uint32_t>(held->request().stream_id)));
    std::weak_ptr<qb::http::Context<qb::http2::DefaultSession>> weak_context = held;
    held.reset();
    session.reset();
    ASSERT_FALSE(weak_context.expired());
    server.reset();
    EXPECT_TRUE(weak_context.expired());
    EXPECT_EQ(completions, 1);
    EXPECT_EQ(names_seen, (std::vector<std::string>{parameter_name}));
    client->disconnect();
    Http2FactoryServerThread::pump_until([&] { return !client->is_connected(); });
}
#endif

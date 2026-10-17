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
#include <algorithm>
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
#include <qb/io/tcp/socket.h>
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

/// The request body cap the servers below set with `set_max_body_size` (Huly QB-168).
constexpr std::size_t kBodyCap = 1024;

/// A POST whose body is @p size bytes.
[[maybe_unused]] qb::http::Request
post_of(std::string const &url, std::size_t size) {
    qb::http::Request request{{url}};
    request.method() = qb::http::method::POST;
    request.body()   = std::string(size, 'b');
    return request;
}

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

/// What a raw client saw while it uploaded a request body: what the server sent before the
/// connection ended, whether it ended on EOF, the error that ended the read if one did, and the
/// error a send failed with -- a reset of the connection while the client was still sending.
struct RawUpload {
    std::string received;
    bool        closed      = false;
    int         read_error  = 0;
    int         write_error = 0;
    std::size_t sent        = 0;
};

/**
 * Writes @p head, then up to @p body_bytes of body, as an uploading client does, and collects what
 * the server sends until the connection ends or @p budget elapses. With @p read_after_upload the
 * client reads nothing while it still has bytes to send -- a client that answers only once its
 * request is out -- which is the deterministic shape of a server closing while bytes it never read
 * are still arriving: the close becomes a reset, and a reset can take the answer with it.
 */
RawUpload
raw_upload(std::uint16_t port, std::string const &head, std::size_t body_bytes, bool read_after_upload,
           std::chrono::milliseconds budget = 10s) {
    RawUpload           out;
    qb::io::tcp::socket sock;
    if (sock.connect_v4("127.0.0.1", port) != 0) {
        ADD_FAILURE() << "the raw client could not connect";
        return out;
    }
    (void) sock.set_nonblocking(true);
    const std::string chunk(64 * 1024, 'x');
    std::string       pending    = head;
    std::size_t       body_sent  = 0;
    bool              write_open = true;
    char              buffer[4096];
    const auto        deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        bool progressed = false;
        if (write_open && pending.empty() && body_sent < body_bytes) {
            const auto n = std::min(chunk.size(), body_bytes - body_sent);
            pending.assign(chunk.data(), n);
            body_sent += n;
        }
        if (write_open && !pending.empty()) {
            const int written = sock.write(pending.data(), pending.size());
            if (written > 0) {
                out.sent += static_cast<std::size_t>(written);
                pending.erase(0, static_cast<std::size_t>(written));
                progressed = true;
            } else if (written < 0 && !qb::io::socket::not_send_error(qb::io::socket::get_last_errno())) {
                out.write_error = qb::io::socket::get_last_errno();
                write_open      = false; // the server reset the connection: nothing more can be sent
            }
        }
        const bool uploading = write_open && (!pending.empty() || body_sent < body_bytes);
        if (!read_after_upload || !uploading) {
            const int got = sock.read(buffer, sizeof(buffer));
            if (got > 0) {
                out.received.append(buffer, static_cast<std::size_t>(got));
                progressed = true;
            } else {
                // tcp::socket::read() answers -1 at EOF too, with the error cleared to 0.
                const int error = got == 0 ? 0 : qb::io::socket::get_last_errno();
                if (error == 0) {
                    out.closed = true;
                    break;
                }
                if (!qb::io::socket::not_recv_error(error)) {
                    out.read_error = error;
                    break;
                }
            }
        }
        if (!progressed)
            std::this_thread::sleep_for(1ms);
    }
    sock.close();
    return out;
}

/// The head of a POST whose declared body is one byte over @p cap.
std::string
oversized_post_head(std::size_t cap) {
    return "POST /ping HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + std::to_string(cap + 1) + "\r\n\r\n";
}

// A request declaring a body over the server's cap -- here the default, MAX_BODY_SIZE -- is answered
// 413 with `Connection: close`, and the connection ends after it. It used to close with no answer at
// all (Huly QB-168). The client keeps uploading meanwhile: the answer must reach it anyway, whether
// it reads while it sends or only once it has stopped sending.
TEST_F(HttpMakeServerTest, ARequestOverTheBodyCapIsAnswered413ThenClosed) {
    struct Shape {
        const char *name;
        std::size_t upload;
        bool        read_after_upload;
    };
    for (const Shape shape :
         {Shape{"client sends the head only", 0, false}, Shape{"client reads while it uploads", 4 * 1024 * 1024, false},
          Shape{"client reads after its upload", 4 * 1024 * 1024, true}}) {
        SCOPED_TRACE(shape.name);
        const auto head = oversized_post_head(qb::http::protocol_limits::MAX_BODY_SIZE);
        const auto seen = raw_upload(_port, head, shape.upload, shape.read_after_upload);
        EXPECT_EQ(seen.received.rfind("HTTP/1.1 413 ", 0), 0u)
            << "no 413 reached the client (read error " << seen.read_error << ", " << seen.sent << " bytes sent): [" << seen.received << "]";
        EXPECT_NE(seen.received.find("connection: close\r\n"), std::string::npos) << seen.received;
        EXPECT_TRUE(seen.closed) << "the connection must end after the answer, on EOF (read error " << seen.read_error << ")";
        // The server closes after its peer (qb-io's lingering close, Huly QB-1089): an upload in progress is never
        // reset, and one that reads only afterwards runs out, read and dropped, before the connection ends.
        EXPECT_EQ(seen.write_error, 0) << "the client was reset while it was still sending";
        if (shape.read_after_upload) {
            EXPECT_EQ(seen.sent, head.size() + shape.upload) << "the upload did not run out";
        }
    }
    EXPECT_EQ(0, g_plain_server_requests.load()) << "a refused request is never routed";
}

// A body exactly at the default cap is served: make-server-factory-huge-body.cpp, its own binary (~200 MiB).

// The server's own cap, `set_max_body_size`, through qb's own client: a body exactly at it is served, one
// byte over is answered 413 -- and so is an upload of 4 MiB, whose client is still sending when the answer
// comes (Huly QB-168).
TEST(HttpServerBodyCap, TheCapIsTheServersSetMaxBodySize) {
    qb::io::async::init();
    PlainServerThread server([] { return qb::http::make_server(); },
                             [](PlainServer &srv) -> bool {
                                 srv.router().post("/echo", [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) {
                                     ctx->text(std::to_string(ctx->request().body().size()));
                                 });
                                 srv.set_max_body_size(kBodyCap);
                                 srv.router().compile();
                                 if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                                     return false;
                                 srv.start();
                                 return true;
                             });
    ASSERT_TRUE(server.ready());
    const auto url = "http://localhost:" + std::to_string(server.server().transport().local_endpoint().port()) + "/echo";

    const auto at_cap = qb::http::run_sync(qb::http::POST(post_of(url, kBodyCap), 5s)).response;
    EXPECT_EQ(at_cap.status(), qb::http::status::OK);
    EXPECT_EQ(at_cap.body().as<std::string>(), std::to_string(kBodyCap));
    EXPECT_EQ(qb::http::run_sync(qb::http::POST(post_of(url, kBodyCap + 1), 5s)).response.status(), qb::http::status::PAYLOAD_TOO_LARGE);
    EXPECT_EQ(qb::http::run_sync(qb::http::POST(post_of(url, 4 * 1024 * 1024), 5s)).response.status(), qb::http::status::PAYLOAD_TOO_LARGE);
}

/// A request target of exactly @p size bytes on @p origin: `/limits?q=` padded.
[[maybe_unused]] std::string
target_of(std::string const &origin, std::size_t size) {
    std::string target = "/limits?q=";
    target += std::string(size - target.size(), 'a');
    return origin + target;
}

// The server's request limits (`set_request_limits`, Huly QB-94), through qb's own client: a target and a field
// value exactly at their limits are served, one byte over each is answered -- 414, 431 -- where the connection
// used to close with no answer.
TEST(HttpServerRequestLimits, TheLimitsAreTheServersAndEachBreachIsAnswered) {
    qb::io::async::init();
    PlainServerThread server([] { return qb::http::make_server(); },
                             [](PlainServer &srv) -> bool {
                                 srv.router().get("/limits",
                                                  [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) { ctx->text("ok"); });
                                 qb::http::request_limits limits;
                                 limits.max_url_length          = 64;
                                 limits.max_header_value_length = 64;
                                 srv.set_request_limits(limits);
                                 srv.router().compile();
                                 if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                                     return false;
                                 srv.start();
                                 return true;
                             });
    ASSERT_TRUE(server.ready());
    const auto origin = "http://localhost:" + std::to_string(server.server().transport().local_endpoint().port());
    const auto get    = [](qb::http::Request request) {
        return qb::http::run_sync(qb::http::GET(std::move(request), 5s)).response;
    };

    EXPECT_EQ(get(qb::http::Request{{target_of(origin, 64)}}).status(), qb::http::status::OK);
    EXPECT_EQ(get(qb::http::Request{{target_of(origin, 65)}}).status(), qb::http::status::URI_TOO_LONG);

    qb::http::Request at_limit{{origin + "/limits"}};
    at_limit.set_header("x-v", std::string(64, 'v'));
    EXPECT_EQ(get(std::move(at_limit)).status(), qb::http::status::OK);
    qb::http::Request over{{origin + "/limits"}};
    over.set_header("x-v", std::string(65, 'v'));
    EXPECT_EQ(get(std::move(over)).status(), qb::http::status::REQUEST_HEADER_FIELDS_TOO_LARGE);
}

// The default limits are the constants (Huly QB-94): a server that never set its own serves a target and a field
// value exactly at them, and answers one byte past each -- 414, 431 -- where it closed with no answer until 3.3.
TEST(HttpServerRequestLimits, TheDefaultLimitsAreAnswered) {
    qb::io::async::init();
    PlainServerThread server([] { return qb::http::make_server(); },
                             [](PlainServer &srv) -> bool {
                                 srv.router().get("/limits",
                                                  [](std::shared_ptr<qb::http::Context<qb::http::DefaultSession>> ctx) { ctx->text("ok"); });
                                 srv.router().compile();
                                 if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                                     return false;
                                 srv.start();
                                 return true;
                             });
    ASSERT_TRUE(server.ready());
    const auto origin = "http://localhost:" + std::to_string(server.server().transport().local_endpoint().port());
    const auto get    = [](qb::http::Request request) {
        return qb::http::run_sync(qb::http::GET(std::move(request), 5s)).response;
    };

    EXPECT_EQ(get(qb::http::Request{{target_of(origin, qb::http::protocol_limits::MAX_URL_LENGTH)}}).status(), qb::http::status::OK);
    EXPECT_EQ(get(qb::http::Request{{target_of(origin, qb::http::protocol_limits::MAX_URL_LENGTH + 1)}}).status(),
              qb::http::status::URI_TOO_LONG);
    // qb's own client will not SEND a field value past the constant (its serializer holds it), so the over-long
    // one goes out raw.
    const auto        port = server.server().transport().local_endpoint().port();
    const std::string head =
        "GET /limits HTTP/1.1\r\nHost: h\r\nx-v: " + std::string(qb::http::protocol_limits::MAX_HEADER_VALUE_LENGTH + 1, 'v') + "\r\n\r\n";
    const auto seen = raw_upload(port, head, 0, false);
    EXPECT_EQ(seen.received.rfind("HTTP/1.1 431 ", 0), 0u) << "[" << seen.received.substr(0, 120) << "]";
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
                srv.router().post("/echo_ssl", [](std::shared_ptr<qb::http::Context<qb::http::ssl::DefaultSecureSession>> ctx) {
                    ctx->text(std::to_string(ctx->request().body().size()));
                });
                srv.set_max_body_size(kBodyCap);
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

// The same cap over TLS: the 413 reaches a client still uploading 4 MiB (Huly QB-168).
TEST_F(HttpsMakeServerTest, TheCapIsTheServersSetMaxBodySize) {
    const auto url    = base_url() + "/echo_ssl";
    const auto at_cap = qb::http::run_sync(qb::http::POST(post_of(url, kBodyCap), 5s, /*verify_peer=*/false)).response;
    EXPECT_EQ(at_cap.status(), qb::http::status::OK);
    EXPECT_EQ(at_cap.body().as<std::string>(), std::to_string(kBodyCap));
    EXPECT_EQ(qb::http::run_sync(qb::http::POST(post_of(url, kBodyCap + 1), 5s, false)).response.status(), qb::http::status::PAYLOAD_TOO_LARGE);
    EXPECT_EQ(qb::http::run_sync(qb::http::POST(post_of(url, 4 * 1024 * 1024), 5s, false)).response.status(),
              qb::http::status::PAYLOAD_TOO_LARGE);
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
                srv.router().post("/echo_http2", [](std::shared_ptr<qb::http::Context<qb::http2::DefaultSession>> ctx) {
                    ctx->text(std::to_string(ctx->request().body().size()));
                });
                // The connection a request came on, by its session's id: two answers name the same one only
                // when no new connection was made between them.
                srv.router().get("/session_http2", [](std::shared_ptr<qb::http::Context<qb::http2::DefaultSession>> ctx) {
                    auto session = ctx->session();
                    ctx->text(session ? uuids::to_string(session->id()) : std::string{});
                });
                // The request limits the QB-94 case below reads (a 64-byte target, a 64-byte field value), then
                // the body cap alone, which the QB-168 cases read.
                qb::http::request_limits limits;
                limits.max_url_length          = 64;
                limits.max_header_value_length = 64;
                srv.set_request_limits(limits);
                srv.set_max_body_size(kBodyCap);
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

// The HTTP/2 server's cap, `set_max_body_size`: a body at it is served, one byte over is answered 413 on its
// stream -- then RST_STREAM(NO_ERROR) -- and the SAME connection serves the next request (Huly QB-168).
TEST_F(Http2MakeServerTest, TheCapIsTheServersSetMaxBodySizeAndTheConnectionGoesOn) {
    auto client = std::make_shared<qb::http2::Client>(base_url());
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);
    client->set_request_timeout(5s);
    const auto url        = base_url() + "/echo_http2";
    const auto connection = [&] {
        return qb::http::run_sync(client->push_request(qb::http::Request{{base_url() + "/session_http2"}})).body().as<std::string>();
    };
    const auto before = connection();
    ASSERT_FALSE(before.empty());

    const auto at_cap = qb::http::run_sync(client->push_request(post_of(url, kBodyCap)));
    EXPECT_EQ(at_cap.status(), qb::http::status::OK);
    EXPECT_EQ(at_cap.body().as<std::string>(), std::to_string(kBodyCap));
    EXPECT_EQ(qb::http::run_sync(client->push_request(post_of(url, kBodyCap + 1))).status(), qb::http::status::PAYLOAD_TOO_LARGE);
    EXPECT_EQ(qb::http::run_sync(client->push_request(post_of(url, 256 * 1024))).status(), qb::http::status::PAYLOAD_TOO_LARGE)
        << "a body larger than a stream's flow-control window is refused too";

    EXPECT_EQ(connection(), before) << "the refusals ended streams, never the connection";
    client->disconnect();
}

// The HTTP/1.1 requests of the server's ALPN fallback are judged under the same cap, and answered 413 with
// `Connection: close` -- read by a client still uploading (Huly QB-168).
TEST_F(Http2MakeServerTest, TheHttp1FallbackAnswersOverTheCapWith413) {
    const auto url = base_url() + "/echo_http2";
    EXPECT_EQ(qb::http::run_sync(qb::http::POST(post_of(url, kBodyCap), 5s, false)).response.status(), qb::http::status::OK);
    EXPECT_EQ(qb::http::run_sync(qb::http::POST(post_of(url, 4 * 1024 * 1024), 5s, false)).response.status(),
              qb::http::status::PAYLOAD_TOO_LARGE);
}

// The HTTP/2 server's request limits (`set_request_limits`, Huly QB-94): a `:path` and a field value exactly at
// their limits are routed, one byte over each is answered on its stream -- 414, 431 -- and the SAME connection
// serves the next request.
TEST_F(Http2MakeServerTest, TheRequestLimitsAreAnsweredOnTheStreamAndTheConnectionGoesOn) {
    auto client = std::make_shared<qb::http2::Client>(base_url());
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);
    client->set_request_timeout(5s);
    const auto send = [&](qb::http::Request request) {
        return qb::http::run_sync(client->push_request(std::move(request)));
    };
    const auto connection = [&] {
        return send(qb::http::Request{{base_url() + "/session_http2"}}).body().as<std::string>();
    };
    const auto padded = [&](std::size_t size) {
        std::string target = "/ping_http2?q=";
        target += std::string(size - target.size(), 'a');
        return base_url() + target;
    };
    const auto before = connection();
    ASSERT_FALSE(before.empty());

    EXPECT_EQ(send(qb::http::Request{{padded(64)}}).status(), qb::http::status::OK);
    EXPECT_EQ(send(qb::http::Request{{padded(65)}}).status(), qb::http::status::URI_TOO_LONG);

    qb::http::Request at_limit{{base_url() + "/ping_http2"}};
    at_limit.set_header("x-v", std::string(64, 'v'));
    EXPECT_EQ(send(std::move(at_limit)).status(), qb::http::status::OK);
    qb::http::Request over{{base_url() + "/ping_http2"}};
    over.set_header("x-v", std::string(65, 'v'));
    EXPECT_EQ(send(std::move(over)).status(), qb::http::status::REQUEST_HEADER_FIELDS_TOO_LARGE);

    EXPECT_EQ(connection(), before) << "the refusals ended streams, never the connection";
    EXPECT_EQ(2, g_http2_server_requests.load()) << "only the requests within the limits are routed";
    client->disconnect();
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

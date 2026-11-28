/**
 * @file qbm/http/tests/system/http2/http2-client.cpp
 * @brief Live loopback+TLS tests for the callback HTTP/2 client API.
 *
 * The system half of the former `test-integration-http2-client.cpp`. These
 * cases drive `qb::http2::Client` (callback surface) against a REAL in-process
 * HTTP/2-over-TLS server reached over the loopback interface with ALPN `h2`.
 *
 * Differences from the legacy file (per the restructure spec, §7):
 *   - DROP the misleading `integration-` prefix: this is a loopback system test,
 *     not a daemon/integration test.
 *   - The cert-missing `GTEST_SKIP` (+ per-test `IsSkipped()` re-guards) is
 *     replaced by a HARD resource prerequisite: `certs_available()` is asserted
 *     in SetUp, so a secure build that lost its certificates FAILS loudly
 *     instead of silently green-skipping the whole TLS/h2 suite.
 *   - The hand-rolled server thread (fixed magic port 29877, `server_ready`
 *     busy flag, 200ms SSL warmup `sleep_for`) is replaced by the shared
 *     `ServerThread<>` RAII (loopback_server.h): readiness via condition
 *     variable, an ephemeral port (no parallel-CTest port collisions), and a
 *     worker-thread run loop.
 *   - The `h2_server_side_assertions` / `h2_expected_server_assertions`
 *     echo-counter (which only re-asserted values the test itself fed) is
 *     RETIRED. Every test now asserts OBSERVABLE response state (status, body,
 *     headers) plus, where it adds signal, an independent server-derived header.
 *   - Client-side completion is awaited with the shared bounded `pump_until`
 *     (fails loud on timeout) instead of ad-hoc deadline/`sleep_for` spins.
 *   - `std::cout`/`std::cerr` debug noise and the file-local `main()` are stripped.
 *
 * New coverage added per spec: GOAWAY-adjacent graceful drain on disconnect, the previously-dead `/api/large` route,
 * and a bad-ALPN negative case (server offers only `http/1.1`, so the `h2` client connect must fail observably). The
 * automatic reconnection (Huly QB-103) has its own section: the backoff run through `RetryPolicy`, its cap, its end on a
 * connection that comes up, a disconnect while connecting, and the retry pattern -- a request pushed back from a failure
 * callback -- queuing behind the scheduled attempt. So do the server's inactivity timeout, driven by the raw client of
 * `shared/http2_raw_client.h`, and the client's body limit (Huly QB-1248).
 *
 * REQUIRES: ssl + live. This TU stays inside the `if(QB_HAS_SSL)` block.
 *
 * A case declares what its callbacks write BEFORE its client: a client answers every callback it still holds from its
 * destructor (Huly QB-1246), and a case that fails returns early, so state declared after the client is dead by then.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <qbm/http/2/client.h>
#include <qbm/http/2/http2.h>
#include <qbm/http/http.h> // qb::http::run_sync / GET — drives the HTTP/1.1-over-ALPN fallback path.
#include <qbm/http/middleware/csrf.h>
#include <qbm/http/middleware/static_files.h>

#include <qb/io/tcp/listener.h>
#include <qb/io/tcp/ssl/listener.h>

#include "../../shared/fail_wait.h"
#include "../../shared/http2_planned_peer.h"
#include "../../shared/http2_raw_client.h"
#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"
#include "../../shared/tls_closing_peer.h"
#include "../../shared/watchdog.h"

using namespace std::chrono_literals;

namespace {

class H2Server;

class H2Session : public qb::http2::use<H2Session>::session<H2Server> {
public:
    explicit H2Session(H2Server &server)
        : session(server) {}
};

// HTTP/2 server exercising the route surface the callback client tests use.
// Routes echo back enough of the request (id, body, method) that the test body
// can assert correctness from the OBSERVABLE response alone — no server-side
// smoke counters.
class H2Server : public qb::http2::use<H2Server>::server<H2Session> {
    using Context = qb::http::Context<H2Session>;

    struct HangProbeState {
        std::atomic<int>    routed{0};
        std::atomic<int>    cancelled{0};
        mutable std::mutex  context_mutex;
        std::weak_ptr<void> context;
    };

    std::shared_ptr<HangProbeState>      _hang_probe{std::make_shared<HangProbeState>()};
    std::deque<std::shared_ptr<Context>> _serialized_contexts;
    std::atomic<int>                     _serialized_admitted{0};
    std::atomic<int>                     _serialized_active{0};
    std::atomic<int>                     _serialized_peak{0};

public:
    H2Server() {
        // 1. Basic GET.
        router().get("/api/test", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "HTTP/2 GET Success";
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 1b. The request's cookies, as the server parsed them (Huly QB-1174).
        router().get("/api/cookies", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().add_header("X-Cookie-A", ctx->request().cookie_value("a"));
            ctx->response().add_header("X-Cookie-B", ctx->request().cookie_value("b"));
            ctx->response().body() = "cookies";
            ctx->complete();
        });

        // 1c. Behind the CSRF middleware: HTTP/2 carries the authority in :authority, and its header names in lower
        // case (Huly QB-95).
        auto csrf = router().group("/csrf");
        csrf->use(qb::http::csrf_middleware<H2Session>());
        csrf->post("/post", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "posted";
            ctx->complete();
        });

        // 2. POST echoing the request body back into the response.
        router().post("/api/data", [](auto ctx) {
            const std::string request_body = ctx->request().body().template as<std::string>();
            ctx->response().status()       = qb::http::status::CREATED;
            ctx->response().body()         = "Data received: " + request_body + " - created successfully";
            ctx->response().add_header("Content-Type", "application/json");
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 3. Path-parameter echo.
        router().get("/api/users/:id", [](auto ctx) {
            const std::string id     = ctx->path_param("id");
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "User ID: " + id + " (via HTTP/2)";
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 4. Large response (previously a dead route — now exercised).
        router().get("/api/large", [](auto ctx) {
            std::string large_body;
            large_body.reserve(64 * 1024);
            for (int i = 0; i < 1000; ++i) {
                large_body += "This is line " + std::to_string(i) + " of a large HTTP/2 response.\n";
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = large_body;
            ctx->response().add_header("Content-Type", "text/plain");
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 4b. Flow-control route: a response far larger than the default 64KiB
        //     per-stream send window, so the server MUST queue pending DATA and
        //     resume only as the client returns capacity via WINDOW_UPDATE. This
        //     drives the server-side flow-control machinery (pending-data queue,
        //     WINDOW_UPDATE handling, connection/stream window accounting) over a
        //     real socket — unreachable through the socket-less FakeIO.
        router().get("/api/flood", [](auto ctx) {
            std::string flood;
            flood.reserve(512 * 1024);
            // Deterministic, position-checkable payload: 512 KiB of 'A'..'P' cycles
            // with sentinel markers at both ends.
            flood += "FLOOD-START;";
            while (flood.size() < 512 * 1024) {
                flood += static_cast<char>('A' + (flood.size() % 16));
            }
            flood += ";FLOOD-END";
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::move(flood);
            ctx->response().add_header("Content-Type", "application/octet-stream");
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        router().post("/api/informational", [](auto ctx) {
            auto session = ctx->session();
            ASSERT_NE(session, nullptr);
            namespace h2 = qb::protocol::http2;
            h2::Http2FrameData<h2::HeadersFrame> info;
            info.header.type  = static_cast<uint8_t>(h2::FrameType::HEADERS);
            info.header.flags = h2::FLAG_END_HEADERS;
            info.header.set_stream_id(static_cast<uint32_t>(ctx->request().stream_id));
            // Literal without indexing, indexed name :status (8). This independent wire
            // fixture leaves the server encoder's dynamic table untouched.
            info.payload.header_block_fragment = {0x08, 0x03, '1', '0', '0'};
            info.header.set_payload_length(5);
            *session << info;
            info.payload.header_block_fragment.back() = '3';
            *session << info;
            *session << info;
            ctx->response().body() = ctx->request().body().template as<std::string>();
            ctx->response().set_header("X-Final", "yes");
            ctx->complete();
        });

        // 5. Error route.
        router().get("/api/error", [](auto ctx) {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->response().body()   = "HTTP/2 server error occurred";
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 6. Server-initiated RST_STREAM: maps to a BAD_GATEWAY stream error
        //    on the client, observable through the per-request callback.
        router().get("/api/reset-stream", [](auto ctx) {
            auto session = ctx->session();
            if (session) {
                (void) session->reset_stream(static_cast<uint32_t>(ctx->request().stream_id), qb::protocol::http2::ErrorCode::CANCEL,
                                             "test initiated stream reset");
            }
        });

        // 7. HEAD with metadata-only Content-Length.
        router().head("/api/head-metadata", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "123");
            ctx->response().add_header("X-Protocol", "HTTP/2");
            ctx->complete();
        });

        // 8b. A stream the server never completes. The counters and weak owner
        //     give the peer-disconnect test a deterministic "routed and alive"
        //     barrier plus cancellation/ownership post-conditions.
        const auto hang_probe = _hang_probe;
        router().get("/api/hang", [hang_probe](auto ctx) {
            ctx->add_lifecycle_hook([hang_probe](auto &context, qb::http::HookPoint point) {
                if (point == qb::http::HookPoint::POST_HANDLER_EXECUTION && context.is_cancelled()) {
                    ++hang_probe->cancelled;
                }
            });
            {
                std::lock_guard lock(hang_probe->context_mutex);
                hang_probe->context = ctx;
            }
            ++hang_probe->routed;
        });

        // 8c. A held response used to observe the concurrent-stream cap. A
        //     second client calls release-one; both routes execute on the server
        //     loop, so no test-thread completion crosses the session boundary.
        router().get("/api/serialized/:id", [this](auto ctx) {
            const int active = ++_serialized_active;
            int       peak   = _serialized_peak.load();
            while (active > peak && !_serialized_peak.compare_exchange_weak(peak, active)) {
            }
            ++_serialized_admitted;
            _serialized_contexts.push_back(std::move(ctx));
        });
        router().get("/api/release-one", [this](auto ctx) {
            if (_serialized_contexts.empty()) {
                ctx->response().status() = qb::http::status::CONFLICT;
                ctx->complete();
                return;
            }
            auto held = std::move(_serialized_contexts.front());
            _serialized_contexts.pop_front();
            --_serialized_active;
            held->response().status() = qb::http::status::OK;
            held->response().body()   = "User ID: " + held->path_param("id") + " (serialized via HTTP/2)";
            held->complete();
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });

        // 8. Response carrying trailers.
        router().get("/api/trailers", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "HTTP/2 response with trailers";
            ctx->response().add_header("Trailer", "X-Checksum");
            ctx->response().add_header("X-Checksum", "h2-trailer-ok");
            ctx->complete();
        });

        router().compile();
    }

    [[nodiscard]] int
    hang_routed() const noexcept {
        return _hang_probe->routed.load();
    }

    [[nodiscard]] int
    hang_cancelled() const noexcept {
        return _hang_probe->cancelled.load();
    }

    [[nodiscard]] bool
    hang_context_expired() const {
        std::lock_guard lock(_hang_probe->context_mutex);
        return _hang_probe->context.expired();
    }

    [[nodiscard]] int
    serialized_admitted() const noexcept {
        return _serialized_admitted.load();
    }

    [[nodiscard]] int
    serialized_active() const noexcept {
        return _serialized_active.load();
    }

    [[nodiscard]] int
    serialized_peak() const noexcept {
        return _serialized_peak.load();
    }
};

using ServerThread = qb::http::test::ServerThread<H2Server>;

/**
 * @brief HTTP/2 callback-client fixture over a real loopback TLS server.
 *
 * The server runs on its own worker thread (shared ServerThread RAII, ALPN
 * offers `h2` then `http/1.1`); the test body drives the client on the main
 * thread's event loop. The TLS certificate pair is a HARD prerequisite.
 */
class Http2ClientTest : public ::testing::Test {
protected:
    std::uint16_t                 _port{0};
    std::unique_ptr<ServerThread> _server;

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available())
            << "Missing TLS test certificates (looked for " << qb::http::test::ssl_cert_path() << " and " << qb::http::test::ssl_key_path()
            << "). The HTTP/2 client system suite REQUIRES them.";

        qb::io::async::init();

        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();

        // Bind :0 and read the port BACK, rather than probing for a free one and binding it a
        // moment later. `ephemeral_port()` documents the hole this closes: its probe must be shut
        // before the caller can bind, so under `ctest -j` another test PROCESS can take the port in
        // that window. Binding :0 on the socket that actually serves leaves no window at all.
        _server = std::make_unique<ServerThread>([cert, key](H2Server &srv) -> bool {
            srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
                return false;
            }
            srv.start();
            return true;
        });
        ASSERT_TRUE(_server->ready()) << "HTTP/2 loopback server failed to start";
        // The ServerThread ctor already blocked on the readiness barrier, so the transport is bound.
        _port = _server->port();
        ASSERT_NE(_port, 0) << "listen_v4(0) did not yield a kernel-assigned port";
    }

    void
    TearDown() override {
        _server.reset();
    }

    [[nodiscard]] std::string
    url() const {
        return "https://localhost:" + std::to_string(_port);
    }

    [[nodiscard]] std::shared_ptr<qb::http2::Client>
    make_test_client() const {
        auto client = qb::http2::make_client(url());
        client->set_verify_peer(false); // self-signed test cert
        client->set_connect_timeout(5s);
        return client;
    }
};

// ---------------------------------------------------------------------------
// Single request round-trips
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, ACookieHeaderSplitIntoSeveralFieldLinesIsReadWhole) {
    // RFC 9113 8.2.3: an HTTP/2 client may split the Cookie header into one field line per cookie-pair (browsers do,
    // for HPACK); the server reads them all, as if joined with "; " (Huly QB-1174).
    std::atomic<bool>  response_received{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/cookies");
    request.add_header("cookie", "a=1");
    request.add_header("cookie", "b=2");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);
    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("X-Cookie-A"), "1");
    EXPECT_EQ(response.header("X-Cookie-B"), "2") << "the second cookie field line was dropped";
    client->disconnect();
}

TEST_F(Http2ClientTest, CsrfMiddlewareReadsTheAuthorityAndTheFetchMetadataOfAnHttp2Request) {
    // The h2 server rebuilds the URI from :scheme and :authority and sends no Host: the middleware compares Origin with
    // that authority. Header names arrive in lower case (Huly QB-95).
    std::atomic<int>                  done{0};
    std::array<qb::http::Response, 3> responses;
    auto                              client = make_test_client();
    auto                              post   = [&](std::size_t const slot, std::vector<std::pair<std::string, std::string>> const &headers) {
        qb::http::Request request;
        request.method() = qb::http::Method::POST;
        request.uri()    = qb::io::uri("/csrf/post");
        request.body()   = "x";
        for (auto const &[name, value] : headers)
            request.add_header(name, value);
        EXPECT_TRUE(client->push_request(request, [&responses, &done, slot](qb::http::Response r) {
            responses[slot] = std::move(r);
            ++done;
        }));
    };
    post(0, {{"origin", url()}});
    post(1, {{"origin", "https://evil.test"}});
    post(2, {{"sec-fetch-site", "cross-site"}, {"origin", url()}});
    client->connect(nullptr);
    ASSERT_TRUE(ServerThread::pump_until([&] { return done.load() == 3; }));
    EXPECT_EQ(responses[0].status(), qb::http::status::OK) << responses[0].body().template as<std::string>();
    EXPECT_EQ(responses[1].status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(responses[1].body().template as<std::string>(), "Forbidden: origin mismatch");
    EXPECT_EQ(responses[2].status(), qb::http::status::FORBIDDEN);
    EXPECT_EQ(responses[2].body().template as<std::string>(), "Forbidden: cross-site request");
    client->disconnect();
}

TEST_F(Http2ClientTest, ACookieHeaderTheParserRefusesDoesNotStopTheServer) {
    // Cookie lines that each fit the field limits (8192) but join past max_cookie_header_size (16 KiB) make
    // parse_cookie_header() throw -- the one refusal left since a malformed pair is dropped instead (QB-95). The server
    // ignores the cookies of such a request, as the HTTP/1.1 server does, and keeps serving (Huly QB-1174).
    std::atomic<int>   responses{0};
    qb::http::Response refused, after;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/cookies");
    request.add_header("cookie", "a=1");
    for (int line = 0; line < 3; ++line)
        request.add_header("cookie", "pad" + std::to_string(line) + "=" + std::string(6000, 'v'));
    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        refused = std::move(r);
        ++responses;
    }));
    client->connect(nullptr);
    ASSERT_TRUE(ServerThread::pump_until([&] { return responses.load() == 1; })) << "the server did not answer";
    EXPECT_EQ(refused.status(), qb::http::status::OK);
    EXPECT_EQ(refused.header("X-Cookie-A"), "") << "a Cookie header the parser refuses yields no cookie";

    qb::http::Request next;
    next.method() = qb::http::Method::GET;
    next.uri()    = qb::io::uri("/api/test");
    ASSERT_TRUE(client->push_request(next, [&](qb::http::Response r) {
        after = std::move(r);
        ++responses;
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return responses.load() == 2; })) << "the server stopped serving";
    EXPECT_EQ(after.status(), qb::http::status::OK);
    client->disconnect();
}

TEST_F(Http2ClientTest, SimpleGetRequest) {
    std::atomic<bool>  response_received{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/test");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "HTTP/2 GET Success");
    EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
    client->disconnect();
}

TEST_F(Http2ClientTest, InformationalResponsesCompleteCallbackAndCoroutineOnlyOnFinal) {
    int               calls  = 0;
    auto              client = make_test_client();
    qb::http::Request request{qb::http::method::POST, qb::io::uri("/api/informational")};
    request.body() = "callback-body";
    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response response) {
        ++calls;
        EXPECT_EQ(response.status(), qb::http::status::OK);
        EXPECT_EQ(response.body().as<std::string>(), "callback-body");
        EXPECT_EQ(response.header("X-Final"), "yes");
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return calls != 0; }));
    request.body() = "coroutine-body";
    auto response  = qb::http::run_sync(client->push_request(request));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().as<std::string>(), "coroutine-body");
    EXPECT_EQ(response.header("X-Final"), "yes");
    client->disconnect();
    EXPECT_EQ(calls, 1);
}

TEST_F(Http2ClientTest, PostRequestEchoesBody) {
    std::atomic<bool>  response_received{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::POST;
    request.uri()    = qb::io::uri("/api/data");
    request.add_header("Content-Type", "application/json");
    request.body() = R"({"key": "test_data", "value": 123})";

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::CREATED);
    // Independent assertion on the server-echoed body, not a smoke counter.
    EXPECT_EQ(response.body().template as<std::string>(), R"(Data received: {"key": "test_data", "value": 123} - created successfully)");
    EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
    client->disconnect();
}

TEST_F(Http2ClientTest, ErrorStatusIsPropagated) {
    std::atomic<bool>  response_received{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/error");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_NE(response.body().template as<std::string>().find("server error"), std::string::npos);
    EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
    client->disconnect();
}

// ---------------------------------------------------------------------------
// Large response (formerly a dead route)
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, LargeResponseIsReassembledAcrossDataFrames) {
    std::atomic<bool>  response_received{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/large");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    const std::string body = response.body().template as<std::string>();
    // The body is large enough to span multiple DATA frames; assert the
    // boundary lines survived reassembly, end to end.
    EXPECT_NE(body.find("This is line 0 of a large HTTP/2 response."), std::string::npos);
    EXPECT_NE(body.find("This is line 999 of a large HTTP/2 response."), std::string::npos);
    EXPECT_GT(body.size(), 10000u);
    EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
    client->disconnect();
}

// ---------------------------------------------------------------------------
// Flow control: a >512KiB response forces the server past the default 64KiB
// per-stream/connection send window, so the body only completes as the client
// returns capacity via WINDOW_UPDATE. End-to-end integrity of the reassembled
// payload proves the server's pending-DATA queue + WINDOW_UPDATE accounting
// (2/protocol/server.h) work over a real socket.
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, FlowControlledLargeResponseCompletesIntact) {
    std::atomic<bool>  response_received{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/flood");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    // Generous budget: the round-trip spans many DATA frames gated by flow
    // control, but the bounded pump still fails loud rather than hanging.
    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }, 15s));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    const std::string body = response.body().template as<std::string>();
    EXPECT_GT(body.size(), 512u * 1024u);
    // Both sentinels survived reassembly across the flow-controlled DATA frames.
    EXPECT_EQ(body.compare(0, 12, "FLOOD-START;"), 0);
    EXPECT_NE(body.find(";FLOOD-END"), std::string::npos);
    EXPECT_EQ(response.header("Content-Type"), "application/octet-stream");
    client->disconnect();
}

// ---------------------------------------------------------------------------
// Multiplexing
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, ConcurrentRequestsAreEachAnswered) {
    std::atomic<int>                responses_received{0};
    std::vector<qb::http::Response> responses(3); // before the client, which answers what it still holds when it is destroyed
    auto                            client = make_test_client();

    for (int i = 0; i < 3; ++i) {
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri("/api/users/" + std::to_string(100 + i));

        ASSERT_TRUE(client->push_request(request, [&, i](qb::http::Response r) {
            responses[i] = std::move(r);
            ++responses_received;
        }));
    }
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return responses_received.load() == 3; }));

    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(responses[i].status(), qb::http::status::OK);
        EXPECT_EQ(responses[i].body().template as<std::string>(), "User ID: " + std::to_string(100 + i) + " (via HTTP/2)");
        EXPECT_EQ(responses[i].header("X-Protocol"), "HTTP/2");
    }
    client->disconnect();
}

TEST_F(Http2ClientTest, BatchRequestsPreserveOrder) {
    std::atomic<bool>               batch_completed{false};
    std::vector<qb::http::Response> batch_responses;
    auto                            client = make_test_client();

    std::vector<qb::http::Request> requests;
    for (int i = 0; i < 3; ++i) {
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri("/api/users/" + std::to_string(200 + i));
        requests.push_back(std::move(request));
    }

    ASSERT_TRUE(client->push_requests(requests, [&](std::vector<qb::http::Response> responses) {
        batch_responses = std::move(responses);
        batch_completed = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return batch_completed.load(); }));

    ASSERT_EQ(batch_responses.size(), 3u);
    for (std::size_t i = 0; i < batch_responses.size(); ++i) {
        EXPECT_EQ(batch_responses[i].status(), qb::http::status::OK);
        EXPECT_EQ(batch_responses[i].body().template as<std::string>(),
                  "User ID: " + std::to_string(200 + static_cast<int>(i)) + " (via HTTP/2)");
        EXPECT_EQ(batch_responses[i].header("X-Protocol"), "HTTP/2");
    }
    client->disconnect();
}

TEST_F(Http2ClientTest, CompletedBatchCanDisconnectInsideItsCallback) {
    int                             calls = 0;
    std::vector<qb::http::Response> responses;
    auto                            client = make_test_client(); // owner survives the callback
    std::vector<qb::http::Request>  requests;
    requests.emplace_back(qb::http::method::GET, qb::io::uri("/api/users/301"));
    requests.emplace_back(qb::http::method::GET, qb::io::uri("/api/users/302"));

    ASSERT_TRUE(client->push_requests(std::move(requests), [&](std::vector<qb::http::Response> result) {
        ++calls;
        responses = std::move(result);
        client->disconnect();
    }));

    ASSERT_TRUE(ServerThread::pump_until([&] { return calls == 1; }));
    ASSERT_EQ(calls, 1);
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::OK);
    EXPECT_EQ(responses[1].status(), qb::http::status::OK);
    EXPECT_EQ(responses[0].body().as<std::string>(), "User ID: 301 (via HTTP/2)");
    EXPECT_EQ(responses[1].body().as<std::string>(), "User ID: 302 (via HTTP/2)");
    EXPECT_FALSE(client->is_connected());
}

TEST_F(Http2ClientTest, CompletedBatchCallbackCanQueueAnotherBatch) {
    int                             first_calls = 0, second_calls = 0;
    std::vector<qb::http::Response> first_responses, second_responses;
    auto                            client = make_test_client();
    std::vector<qb::http::Request>  first;
    first.emplace_back(qb::http::method::GET, qb::io::uri("/api/users/401"));

    ASSERT_TRUE(client->push_requests(std::move(first), [&](std::vector<qb::http::Response> result) {
        ++first_calls;
        first_responses = std::move(result);
        std::vector<qb::http::Request> next;
        next.emplace_back(qb::http::method::GET, qb::io::uri("/api/users/402"));
        EXPECT_TRUE(client->push_requests(std::move(next), [&](std::vector<qb::http::Response> followup) {
            ++second_calls;
            second_responses = std::move(followup);
        }));
    }));

    ASSERT_TRUE(ServerThread::pump_until([&] { return second_calls == 1; }));
    EXPECT_EQ(first_calls, 1);
    EXPECT_EQ(second_calls, 1);
    ASSERT_EQ(first_responses.size(), 1u);
    ASSERT_EQ(second_responses.size(), 1u);
    EXPECT_EQ(first_responses[0].body().as<std::string>(), "User ID: 401 (via HTTP/2)");
    EXPECT_EQ(second_responses[0].body().as<std::string>(), "User ID: 402 (via HTTP/2)");
    client->disconnect();
}

TEST_F(Http2ClientTest, ResponseCallbackMayReleaseLastClientOwner) {
    int                              calls                  = 0;
    bool                             alive_after_owner_drop = false;
    std::weak_ptr<qb::http2::Client> weak_client; // before the client, which answers what it still holds when it is destroyed
    auto                             client = make_test_client();
    weak_client                             = client;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/users/403")}, [&](qb::http::Response response) {
        ++calls;
        EXPECT_EQ(response.status(), qb::http::status::OK);
        if (!weak_client.expired()) // not under the client's destructor (a case that failed): nothing left to drop
            client.reset();
        alive_after_owner_drop = !weak_client.expired();
    }));

    ASSERT_TRUE(ServerThread::pump_until([&] { return calls == 1; }));
    EXPECT_EQ(calls, 1);
    EXPECT_TRUE(alive_after_owner_drop) << "the response stack must keep the client alive through callback return";
    EXPECT_TRUE(weak_client.expired()) << "the event stack must release its temporary owner afterward";
}

// ---------------------------------------------------------------------------
// Stream reset mapping (server RST_STREAM -> client BAD_GATEWAY)
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, StreamResetIsMappedToTheCorrectConcurrentRequest) {
    std::atomic<int>   responses_received{0};
    qb::http::Response ok_response;
    qb::http::Response reset_response;
    auto               client = make_test_client();

    qb::http::Request ok_request;
    ok_request.method() = qb::http::Method::GET;
    ok_request.uri()    = qb::io::uri("/api/test");

    qb::http::Request reset_request;
    reset_request.method() = qb::http::Method::GET;
    reset_request.uri()    = qb::io::uri("/api/reset-stream");

    ASSERT_TRUE(client->push_request(ok_request, [&](qb::http::Response r) {
        ok_response = std::move(r);
        ++responses_received;
    }));
    ASSERT_TRUE(client->push_request(reset_request, [&](qb::http::Response r) {
        reset_response = std::move(r);
        ++responses_received;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return responses_received.load() == 2; }));

    EXPECT_EQ(ok_response.status(), qb::http::status::OK);
    EXPECT_EQ(ok_response.body().template as<std::string>(), "HTTP/2 GET Success");
    EXPECT_EQ(reset_response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_NE(reset_response.body().template as<std::string>().find("Stream error"), std::string::npos);
    client->disconnect();
}

// ---------------------------------------------------------------------------
// HEAD + trailers
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, HeadResponseAllowsMetadataContentLengthWithoutBody) {
    std::atomic<bool>  response_received{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::HEAD;
    request.uri()    = qb::io::uri("/api/head-metadata");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("content-length"), "123");
    EXPECT_TRUE(response.body().empty());
    EXPECT_EQ(response.header("x-protocol"), "HTTP/2");
    client->disconnect();
}

TEST_F(Http2ClientTest, ResponseTrailersCompleteStream) {
    std::atomic<bool>  response_received{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/trailers");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "HTTP/2 response with trailers");
    EXPECT_EQ(response.header("X-Checksum"), "h2-trailer-ok");
    client->disconnect();
}

// ---------------------------------------------------------------------------
// GOAWAY-adjacent: graceful drain on client-initiated disconnect
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, GracefulDisconnectDrainsInflightRequest) {
    std::atomic<bool>  response_received{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/test");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));
    EXPECT_EQ(response.status(), qb::http::status::OK);

    // After the in-flight stream completes, a clean disconnect must leave the
    // client with no active requests and report disconnected — the observable
    // end state of the GOAWAY/drain machinery.
    client->disconnect();
    EXPECT_TRUE(ServerThread::pump_until([&] { return !client->is_connected(); }));
    EXPECT_EQ(client->get_active_request_count(), 0u);
}

// ---------------------------------------------------------------------------
// Bad-ALPN negative: server offers only http/1.1, so the h2 client fails
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, ConnectFailsWhenServerDoesNotOfferH2) {
    // A second, independent server that advertises ONLY http/1.1 over ALPN.
    const std::string cert = qb::http::test::ssl_cert_path().string();
    const std::string key  = qb::http::test::ssl_key_path().string();

    // Bind :0 on the serving socket and read the port back — no probe-then-bind window for another
    // test process to slip into (see `ephemeral_port()`'s @warning).
    ServerThread http1_only_server([cert, key](H2Server &srv) -> bool {
        srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"http/1.1"})); // no "h2"
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
            return false;
        }
        srv.start();
        return true;
    });
    ASSERT_TRUE(http1_only_server.ready());
    const std::uint16_t port = http1_only_server.port();
    ASSERT_NE(port, 0) << "listen_v4(0) did not yield a kernel-assigned port";

    std::atomic<bool> callback_called{false};
    std::atomic<bool> connected{true};
    std::string       error_message;
    auto              client = qb::http2::make_client("https://localhost:" + std::to_string(port));
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);

    client->connect([&](bool ok, const std::string &err) {
        connected       = ok;
        error_message   = err;
        callback_called = true;
    });

    ASSERT_TRUE(ServerThread::pump_until([&] { return callback_called.load(); }));

    EXPECT_FALSE(connected.load()) << "h2 client must not consider itself connected when ALPN did not negotiate h2";
    EXPECT_FALSE(client->is_connected());
    EXPECT_NE(error_message.find("ALPN"), std::string::npos) << "expected an ALPN-negotiation failure message, got: " << error_message;
}

// ---------------------------------------------------------------------------
// Unknown path: the compiled router answers with its standard 404 handler, so
// the server `on(Request&&, stream_id)` dispatches a real NOT_FOUND response
// over the stream (rather than the never-routed RST path). This exercises the
// server's full request->response->end-of-stream machinery for a non-2xx,
// handler-produced status across the live socket.
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, UnknownPathIsAnsweredWithNotFound) {
    std::atomic<bool>  response_received{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/no-such-route-exists");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response          = std::move(r);
        response_received = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response_received.load(); }));

    EXPECT_EQ(response.status(), qb::http::status::NOT_FOUND);
    client->disconnect();
}

TEST_F(Http2ClientTest, NotFoundStreamDoesNotPoisonAdjacentStream) {
    // A 404 stream must complete in isolation: a concurrent, well-routed stream
    // on the SAME connection still answers normally. Proves per-stream response
    // dispatch keeps the connection and sibling streams healthy.
    std::atomic<int>   responses_received{0};
    qb::http::Response good_response;
    qb::http::Response missing_response;
    auto               client = make_test_client();

    qb::http::Request good_request;
    good_request.method() = qb::http::Method::GET;
    good_request.uri()    = qb::io::uri("/api/test");

    qb::http::Request missing_request;
    missing_request.method() = qb::http::Method::GET;
    missing_request.uri()    = qb::io::uri("/api/totally-unknown");

    ASSERT_TRUE(client->push_request(good_request, [&](qb::http::Response r) {
        good_response = std::move(r);
        ++responses_received;
    }));
    ASSERT_TRUE(client->push_request(missing_request, [&](qb::http::Response r) {
        missing_response = std::move(r);
        ++responses_received;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return responses_received.load() == 2; }));

    EXPECT_EQ(good_response.status(), qb::http::status::OK);
    EXPECT_EQ(good_response.body().template as<std::string>(), "HTTP/2 GET Success");
    EXPECT_EQ(missing_response.status(), qb::http::status::NOT_FOUND);
    client->disconnect();
}

// ---------------------------------------------------------------------------
// HTTP/1.1 fallback over ALPN: the H2Server advertises {h2, http/1.1}. A plain
// HTTPS/1.1 client (run_sync) offers no `h2`, so the server negotiates
// http/1.1 and serves the request through its `switch_protocol<Http1Protocol>`
// branch — exercising the session's `on(Request&&)` (HTTP/1.1) and `on(eos&&)`
// paths in 2/http2.h that the h2 client can never reach.
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, Http1ClientFallsBackOverAlpnAndIsServed) {
    qb::http::Request request{{url() + "/api/test"}};
    auto              response = qb::http::run_sync(qb::http::GET(request, qb::duration::zero(), /*verify_peer=*/false)).response;

    // The same route handler answers, this time through the HTTP/1.1 protocol
    // object switched in by ALPN — the response is identical at the HTTP layer.
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "HTTP/2 GET Success");
    EXPECT_EQ(response.header("X-Protocol"), "HTTP/2");
}

TEST_F(Http2ClientTest, Http1FallbackPostEchoesBodyOverAlpn) {
    // Drive the HTTP/1.1 fallback with a body so the h1 request-with-content
    // path (and the route's body echo) is exercised over the negotiated
    // http/1.1 protocol object, not h2.
    qb::http::Request request{{url() + "/api/data"}};
    request.method() = qb::http::Method::POST;
    request.add_header("Content-Type", "application/json");
    request.body() = R"({"over":"http1.1"})";

    auto response = qb::http::run_sync(qb::http::POST(request, qb::duration::zero(), /*verify_peer=*/false)).response;

    EXPECT_EQ(response.status(), qb::http::status::CREATED);
    EXPECT_EQ(response.body().template as<std::string>(), R"(Data received: {"over":"http1.1"} - created successfully)");
}

// ---------------------------------------------------------------------------
// Abrupt peer disconnect with an in-flight stream: the server's session
// `on(disconnected&&)` must cancel every still-open stream context and clear
// the context map. We force an in-flight stream by issuing a request whose
// handler the server never completes, wait until that Context is retained,
// then disconnect the client from under it.
// ---------------------------------------------------------------------------

TEST_F(Http2ClientTest, AbruptDisconnectWithInflightStreamsIsClean) {
    std::atomic<int>   response_count{0};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/hang");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response = std::move(r);
        ++response_count;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == 1; }));
    EXPECT_FALSE(_server->server().hang_context_expired());
    EXPECT_EQ(client->get_active_request_count(), 1u);
    EXPECT_EQ(response_count.load(), 0);

    // disconnect() alone: its deferred disposal closes the transport, the peer sees EOF and
    // cancels the stream. It used to leave the socket open -- and the server's context alive --
    // until the client connected again or was destroyed (Huly QB-1021).
    client->disconnect();

    ASSERT_TRUE(ServerThread::pump_until([&] {
        return _server->server().hang_cancelled() == 1 && _server->server().hang_context_expired() && response_count.load() == 1;
    })) << "cancelled="
        << _server->server().hang_cancelled() << " expired=" << _server->server().hang_context_expired()
        << " responses=" << response_count.load() << " client_connected=" << client->is_connected();
    EXPECT_FALSE(client->is_connected());
    EXPECT_EQ(client->get_active_request_count(), 0u);
    EXPECT_EQ(response_count.load(), 1);
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_FALSE(response.body().template as<std::string>().empty());
}

} // namespace

// Test seam (declared by the protocol): jump the client stream-id counter to the 31-bit bound.
template <>
struct qb::protocol::http2::ProtocolTestPeer<qb::http2::Client::H2Protocol> {
    static void
    set_next_stream_id(qb::http2::Client::H2Protocol &protocol, uint32_t id) {
        protocol._next_client_stream_id = id;
    }
};

namespace {

// A connection that has used its last client stream id (2^31-1, RFC 9113 §5.1.1)
// is drained like a graceful GOAWAY: the request on the last id is answered on it,
// the next one waits and is sent on stream 1 of a new connection (Huly QB-525).
// It used to go out as stream 2^31+1, masked to 1 on the wire: the server reset a
// stream it had already seen and the request never completed.
TEST_F(Http2ClientTest, ExhaustedStreamIdsRenewTheConnection) {
    bool                            connected = false;
    std::vector<qb::http::Response> responses;
    auto                            client = make_test_client();
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));

    auto *protocol = dynamic_cast<qb::http2::Client::H2Protocol *>(client->protocol());
    ASSERT_NE(protocol, nullptr);
    qb::protocol::http2::ProtocolTestPeer<qb::http2::Client::H2Protocol>::set_next_stream_id(*protocol, 0x7FFFFFFFu);

    for (int i = 0; i < 2; ++i) {
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri("/api/test");
        ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) { responses.push_back(std::move(r)); }));
    }

    ASSERT_TRUE(ServerThread::pump_until([&] { return responses.size() == 2; })) << responses.size() << " response(s)";
    for (const auto &r : responses) {
        EXPECT_EQ(r.status(), qb::http::status::OK);
        EXPECT_EQ(r.body().template as<std::string>(), "HTTP/2 GET Success");
    }
    ASSERT_TRUE(ServerThread::pump_until([&] { return client->is_connected(); }));
    auto *renewed = dynamic_cast<qb::http2::Client::H2Protocol *>(client->protocol());
    ASSERT_NE(renewed, nullptr);
    EXPECT_EQ(renewed->last_initiated_stream_id(), 1u) << "the second request opened stream 1 of a new connection";
    client->disconnect();
}

// A batch is admitted member by member, as push_request admits one: the members
// within the outstanding-request bound are sent, a member past it is answered
// 503 at its index before anything exists for it, and the callback runs once,
// with every response in request order. push_requests returns false, as
// push_request does for a request the bound refuses. The whole batch used to be
// refused up front, its admissible members included (Huly QB-1063): HTTP/1 and
// HTTP/3 (Huly QB-499) admit member by member.
TEST_F(Http2ClientTest, BatchPastThePendingLimitRefusesOnlyTheMembersOverIt) {
    int                             calls = 0;
    std::vector<qb::http::Response> out;
    auto                            client = make_test_client();
    client->set_max_pending_requests(2);

    std::vector<qb::http::Request> reqs;
    for (int i = 0; i < 3; ++i) {
        qb::http::Request r;
        r.method() = qb::http::Method::GET;
        r.uri()    = qb::io::uri("/api/test");
        reqs.push_back(std::move(r));
    }

    EXPECT_FALSE(client->push_requests(reqs, [&](std::vector<qb::http::Response> rs) {
        out = std::move(rs);
        ++calls;
    })) << "one member was refused by the bound";
    EXPECT_EQ(calls, 0) << "two members were admitted: the batch waits for their responses";
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return calls > 0; }));
    ASSERT_EQ(out.size(), 3u);
    for (std::size_t i = 0; i < 2; ++i) {
        EXPECT_EQ(out[i].status(), qb::http::status::OK) << "member " << i;
        EXPECT_EQ(out[i].body().template as<std::string>(), "HTTP/2 GET Success") << "member " << i;
    }
    EXPECT_EQ(out[2].status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(out[2].body().template as<std::string>(), "HTTP/2 client pending request limit reached");
    for (int pass = 0; pass < 20; ++pass) {
        qb::io::async::run(EVRUN_NOWAIT);
    }
    EXPECT_EQ(calls, 1);
    client->disconnect();
}

// Connecting to a port with no listener fails via the transport connect-completion
// path (TCP/SSL connection failed), invoking the connect callback with success=false.
TEST_F(Http2ClientTest, ConnectToRefusedPortFails) {
    const auto        dead = qb::http::test::ephemeral_port(); // bound then closed -> refused
    std::atomic<bool> cb{false};
    std::atomic<bool> ok{true};
    auto              client = qb::http2::make_client("https://localhost:" + std::to_string(dead));
    client->set_verify_peer(false);
    client->set_connect_timeout(2s);

    client->connect([&](bool o, const std::string &) {
        ok = o;
        cb = true;
    });
    ASSERT_TRUE(ServerThread::pump_until([&] { return cb.load(); }));
    EXPECT_FALSE(ok.load());
    EXPECT_FALSE(client->is_connected());
}

// ---------------------------------------------------------------------------
// Synchronous request-validation / limit guards (no connection, no event loop):
// each of these exercises a push_request/push_requests early-return branch that
// fires its callback in-line before any TCP/TLS work.
// ---------------------------------------------------------------------------

// A single request that would exceed the outstanding-request bound is rejected
// synchronously with a 503 and push_request returns false — the single-request
// twin of BatchPastThePendingLimitRefusesOnlyTheMembersOverIt.
TEST_F(Http2ClientTest, SingleRequestOverPendingLimitIsRejectedWith503) {
    std::atomic<bool>  done{false};
    qb::http::Response response;
    auto               client = make_test_client();
    client->set_max_pending_requests(0); // the very first push already exceeds the bound

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/test");

    EXPECT_FALSE(client->push_request(request, [&](qb::http::Response r) {
        response = std::move(r);
        done     = true;
    }));
    ASSERT_TRUE(done.load()); // the error callback fired synchronously
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_FALSE(client->is_connecting()); // rejected before any connect attempt
}

// push_request / push_requests with an EMPTY callback are rejected up front
// (return false) and never touch the request counters.
TEST_F(Http2ClientTest, NullCallbackRequestsAreRejectedWithoutSideEffects) {
    auto              client = make_test_client();
    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/test");

    EXPECT_FALSE(client->push_request(request, qb::http2::ResponseCallback{}));

    std::vector<qb::http::Request> reqs;
    reqs.push_back(request);
    EXPECT_FALSE(client->push_requests(std::move(reqs), qb::http2::BatchResponseCallback{}));

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 0u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 0u);
}

// An empty batch completes immediately by invoking the callback with an empty
// vector (the requests.empty() early-out), no connection required.
TEST_F(Http2ClientTest, EmptyBatchCompletesImmediatelyWithEmptyVector) {
    bool                            done = false;
    std::vector<qb::http::Response> out{qb::http::Response{}}; // pre-seed non-empty
    auto                            client = make_test_client();

    EXPECT_TRUE(client->push_requests(std::vector<qb::http::Request>{}, [&](std::vector<qb::http::Response> rs) {
        out  = std::move(rs);
        done = true;
    }));
    ASSERT_TRUE(done);
    EXPECT_TRUE(out.empty());
}

// A request whose (absolute) URI uses a non-https scheme is rejected with a
// synthesized BAD_REQUEST (prepare_request https guard) before it hits the wire.
TEST_F(Http2ClientTest, NonHttpsRequestIsRejectedWithBadRequest) {
    std::atomic<bool>  done{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("http://localhost:" + std::to_string(_port) + "/api/test");

    EXPECT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response = std::move(r);
        done     = true;
    }));
    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_NE(response.body().template as<std::string>().find("https"), std::string::npos);
}

// An absolute request whose origin differs from the client's base origin is
// rejected with BAD_REQUEST (prepare_request same-origin guard).
TEST_F(Http2ClientTest, CrossOriginRequestIsRejectedWithBadRequest) {
    std::atomic<bool>  done{false};
    qb::http::Response response;
    auto               client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("https://example.invalid:8443/api/test");

    EXPECT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response = std::move(r);
        done     = true;
    }));
    ASSERT_TRUE(done.load());
    EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_NE(response.body().template as<std::string>().find("same-origin"), std::string::npos);
}

// A batch mixing an invalid (cross-origin) member with a valid one completes
// with per-request results in submission order: the invalid member is filled
// with a synthesized BAD_REQUEST during queueing (prepare_request error path
// inside the batch loop), the valid member round-trips a real 200 over the live
// h2 connection. Exercises the batch's partial-error accounting.
TEST_F(Http2ClientTest, BatchWithInvalidMemberPreservesOrderAndErrors) {
    std::atomic<bool>               done{false};
    std::vector<qb::http::Response> out;
    auto                            client = make_test_client();

    std::vector<qb::http::Request> reqs;
    {
        qb::http::Request bad;
        bad.method() = qb::http::Method::GET;
        bad.uri()    = qb::io::uri("https://example.invalid:8443/api/test");
        reqs.push_back(std::move(bad));
    }
    {
        qb::http::Request good;
        good.method() = qb::http::Method::GET;
        good.uri()    = qb::io::uri("/api/test");
        reqs.push_back(std::move(good));
    }

    ASSERT_TRUE(client->push_requests(std::move(reqs), [&](std::vector<qb::http::Response> rs) {
        out  = std::move(rs);
        done = true;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return done.load(); }));
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(out[1].status(), qb::http::status::OK);
    EXPECT_EQ(out[1].body().template as<std::string>(), "HTTP/2 GET Success");
    client->disconnect();
}

// A batch the connection fails under keeps what it received and answers the rest
// with 503, through ONE callback: the empty 200 the server sent stays a 200, the
// invalid member keeps its 400, the member never answered gets 503. The failure
// pass used to hand that member over as a default-constructed Response -- a 200
// with no body, indistinguishable from a success (Huly QB-495).
TEST_F(Http2ClientTest, BatchFailureKeepsReceivedResponsesAndAnswersTheRestWith503) {
    std::atomic<int>                calls{0};
    std::vector<qb::http::Response> out;
    auto                            client = make_test_client();

    std::vector<qb::http::Request> reqs(3);
    reqs[0].method() = qb::http::Method::HEAD;
    reqs[0].uri()    = qb::io::uri("/api/head-metadata"); // answered: 200, no body
    reqs[1].method() = qb::http::Method::GET;
    reqs[1].uri()    = qb::io::uri("https://example.invalid:8443/api/test"); // refused: 400
    reqs[2].method() = qb::http::Method::GET;
    reqs[2].uri()    = qb::io::uri("/api/hang"); // never answered

    ASSERT_TRUE(client->push_requests(std::move(reqs), [&](std::vector<qb::http::Response> rs) {
        out = std::move(rs);
        ++calls;
    }));
    client->connect(nullptr);

    // The HEAD answer is in (one request still active) and the hang is routed.
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == 1 && client->get_active_request_count() == 1; }));
    EXPECT_EQ(calls.load(), 0);
    client->disconnect();

    ASSERT_TRUE(ServerThread::pump_until([&] { return calls.load() == 1; }));
    for (int pass = 0; pass < 50; ++pass) {
        qb::io::async::run(EVRUN_NOWAIT);
    }
    EXPECT_EQ(calls.load(), 1);
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0].status(), qb::http::status::OK);
    EXPECT_EQ(out[0].header("x-protocol"), "HTTP/2") << "the 200 the server sent";
    EXPECT_TRUE(out[0].body().empty());
    EXPECT_EQ(out[1].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(out[2].status(), qb::http::status::SERVICE_UNAVAILABLE) << "an unanswered member is not a 200";
    EXPECT_FALSE(out[2].body().template as<std::string>().empty());
}

// With the concurrent-stream cap set to 1, three requests drain one at a time:
// process_pending_requests submits a single stream, then re-drives from
// complete_request as each response lands (the _active_requests.size() <
// _max_concurrent_streams loop bound). All three still complete over the one
// connection.
TEST_F(Http2ClientTest, MaxConcurrentStreamsSerializesRequests) {
    std::atomic<int>                received{0};
    std::atomic<int>                control_replies{0};
    std::vector<qb::http::Response> responses(3); // before the client, which answers what it still holds when it is destroyed
    auto                            client = make_test_client();
    client->set_max_concurrent_streams(1);

    for (int i = 0; i < 3; ++i) {
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri("/api/serialized/" + std::to_string(300 + i));
        ASSERT_TRUE(client->push_request(request, [&, i](qb::http::Response r) {
            responses[i] = std::move(r);
            ++received;
        }));
    }
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().serialized_admitted() == 1; }));
    EXPECT_EQ(client->get_active_request_count(), 1u);
    EXPECT_EQ(_server->server().serialized_active(), 1);
    EXPECT_EQ(_server->server().serialized_peak(), 1);

    auto control = make_test_client();
    for (int released = 1; released <= 3; ++released) {
        qb::http::Request release;
        release.method() = qb::http::Method::GET;
        release.uri()    = qb::io::uri("/api/release-one");
        ASSERT_TRUE(control->push_request(std::move(release), [&](qb::http::Response r) {
            EXPECT_EQ(r.status(), qb::http::status::NO_CONTENT);
            ++control_replies;
        }));
        if (released == 1) {
            control->connect(nullptr);
        }

        ASSERT_TRUE(ServerThread::pump_until([&] {
            const int next_admission = std::min(released + 1, 3);
            return control_replies.load() == released && received.load() == released
                   && _server->server().serialized_admitted() == next_admission;
        }));
        EXPECT_LE(client->get_active_request_count(), 1u);
        EXPECT_LE(_server->server().serialized_active(), 1);
        EXPECT_EQ(_server->server().serialized_peak(), 1);
    }

    ASSERT_EQ(received.load(), 3);
    EXPECT_EQ(_server->server().serialized_active(), 0);
    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(responses[i].status(), qb::http::status::OK);
        EXPECT_EQ(responses[i].body().template as<std::string>(), "User ID: " + std::to_string(300 + i) + " (serialized via HTTP/2)");
    }
    control->disconnect();
    client->disconnect();
}

TEST_F(Http2ClientTest, FailedSendCallbackMayDisconnectAndQueueAnotherRequest) {
    int                warmup_calls      = 0;
    int                failed_send_calls = 0, followup_calls = 0;
    qb::http::Response followup_response;
    auto               client = make_test_client();
    client->set_max_concurrent_streams(60); // above the server's advertised 50
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/users/400")}, [&](qb::http::Response response) {
        EXPECT_EQ(response.status(), qb::http::status::OK);
        ++warmup_calls;
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return warmup_calls == 1; }));

    for (int i = 0; i < 51; ++i) {
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/hang")}, [&](qb::http::Response response) {
            if (response.body().as<std::string>() != "Failed to send HTTP/2 request") {
                return;
            }
            ++failed_send_calls;
            client->disconnect();
            EXPECT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/users/404")}, [&](qb::http::Response next) {
                ++followup_calls;
                followup_response = std::move(next);
            }));
        }));
    }

    ASSERT_TRUE(ServerThread::pump_until([&] { return failed_send_calls == 1 && followup_calls == 1; }))
        << "failed_send_calls=" << failed_send_calls << " followup_calls=" << followup_calls;
    EXPECT_EQ(failed_send_calls, 1);
    EXPECT_EQ(followup_calls, 1);
    EXPECT_EQ(followup_response.status(), qb::http::status::OK);
    EXPECT_EQ(followup_response.body().as<std::string>(), "User ID: 404 (via HTTP/2)");
    client->disconnect();
}

TEST_F(Http2ClientTest, FailedSendCallbackMayReleaseLastClientOwner) {
    int                              warmup_calls          = 0;
    int                              failed_send_calls     = 0;
    bool                             alive_inside_callback = false;
    std::weak_ptr<qb::http2::Client> weak_client; // before the client, which answers what it still holds when it is destroyed
    auto                             client = make_test_client();
    client->set_max_concurrent_streams(60);
    weak_client = client;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/users/400")}, [&](qb::http::Response response) {
        EXPECT_EQ(response.status(), qb::http::status::OK);
        ++warmup_calls;
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return warmup_calls == 1; }));

    for (int i = 0; i < 50; ++i) {
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/hang")}, [](qb::http::Response) {}));
    }
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/hang")}, [&](qb::http::Response response) {
        EXPECT_EQ(response.body().as<std::string>(), "Failed to send HTTP/2 request");
        ++failed_send_calls;
        if (!weak_client.expired()) // not under the client's destructor (a case that failed): nothing left to drop
            client.reset();
        alive_inside_callback = !weak_client.expired();
    }));
    EXPECT_EQ(failed_send_calls, 1);
    EXPECT_TRUE(alive_inside_callback);
    EXPECT_TRUE(weak_client.expired());
}

// ---------------------------------------------------------------------------
// Automatic reconnection (Huly QB-103): the run backs off through the policy,
// is bounded, ends on a connection that comes up, and a request pushed from a
// failure callback queues behind the attempt the run schedules. Until 3.2 the
// reconnection was immediate, unbounded, started from inside the failing
// handler, and every drop failed the re-queued work a second and a third time
// (the disconnected and dispose passes over what the first pass's callbacks
// had just pushed back) -- the cases below pin each of those.
// ---------------------------------------------------------------------------

namespace reconnect {

// A second, independent server that advertises ONLY http/1.1 over ALPN: every h2 attempt against
// it comes up at the TCP+TLS level and fails at the handshake, fast and the same way on every host
// -- unlike a refused port, which Winsock takes ~2 s to report.
std::unique_ptr<ServerThread>
make_http1_only_server() {
    const std::string cert = qb::http::test::ssl_cert_path().string();
    const std::string key  = qb::http::test::ssl_key_path().string();
    return std::make_unique<ServerThread>([cert, key](H2Server &srv) -> bool {
        srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"http/1.1"})); // no "h2"
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
            return false;
        }
        srv.start();
        return true;
    });
}

// The fixture's server shape, on a port the test chose (the "server comes back" case).
std::unique_ptr<ServerThread>
make_h2_server_on(std::uint16_t port) {
    const std::string cert = qb::http::test::ssl_cert_path().string();
    const std::string key  = qb::http::test::ssl_key_path().string();
    return std::make_unique<ServerThread>([cert, key, port](H2Server &srv) -> bool {
        srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
        if (srv.transport().listen_v4(port, "127.0.0.1") != 0) {
            return false;
        }
        srv.start();
        return true;
    });
}

std::uint16_t
port_of(ServerThread &srv) {
    return srv.port();
}

std::shared_ptr<qb::http2::Client>
make_client_for(std::uint16_t port) {
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(port));
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);
    return client;
}

qb::http::Request
get_test() {
    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/test");
    return request;
}

struct Failure {
    std::chrono::steady_clock::time_point at;
    qb::http::status                      status;
    std::string                           body;
};

long long
ms_between(const Failure &earlier, const Failure &later) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(later.at - earlier.at).count();
}

} // namespace reconnect

namespace http2_run_sync_connect_test {

/// What run_sync(client->connect()) gave, called from a callback of a close, and how long it blocked.
struct Blocked {
    bool                      returned = false;
    qb::http2::ConnectResult  result;
    std::chrono::milliseconds took{0};
};

/// Completes at its first resumption: a run_sync() of it is one pass of the loop.
qb::io::async::task<void>
completes_at_once() {
    co_return;
}

/// run_sync(client->connect()) -- a coroutine the caller blocks on, the loop pumped until it completes -- bounded by a
/// watchdog that ends the process, saying so, instead of letting the test hang.
void
run_sync_connect(qb::http2::Client &client, Blocked &blocked, char const *const from) {
    const auto               started = std::chrono::steady_clock::now();
    qb::http::test::watchdog bound(std::string("run_sync(connect()) from ") + from, 5s);
    blocked.result   = qb::io::async::run_sync(client.connect());
    blocked.took     = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    blocked.returned = true;
}

/// A TLS peer, ALPN h2, on its own thread, for two connections. On the first it sends an empty SETTINGS -- the client's
/// handshake event comes with the first thing it reads -- and reads until the client ends it. On the second it opens every
/// window as wide as HTTP/2 allows, then reads nothing more: what the client sends past the socket buffers -- a body, then
/// the GOAWAY of its close -- stays in the client.
class StallingPeer {
public:
    StallingPeer() {
        _listener.init(qb::io::ssl::Context::server(qb::http::test::ssl_cert_path(), qb::http::test::ssl_key_path())
                           .alpn({"h2"})
                           .max_version(qb::io::ssl::TlsVersion::v1_2));
        if (_listener.listen_v4(0, "127.0.0.1") != 0 || _listener.set_optval(SOL_SOCKET, SO_RCVBUF, 16384) != 0)
            return;
        _listener.set_nonblocking(true);
        _port   = _listener.local_endpoint().port();
        _thread = std::thread([this] { run(); });
    }
    ~StallingPeer() {
        _release = true;
        if (_thread.joinable())
            _thread.join();
    }
    StallingPeer(StallingPeer const &)            = delete;
    StallingPeer &operator=(StallingPeer const &) = delete;

    [[nodiscard]] std::uint16_t
    port() const noexcept {
        return _port;
    }

    /// The second connection is up and its windows open: from here on the peer reads nothing.
    [[nodiscard]] bool
    stalled() const noexcept {
        return _stalled.load();
    }

private:
    bool
    accept_one(qb::io::tcp::ssl::socket &socket) {
        const auto deadline = std::chrono::steady_clock::now() + 20s;
        qb::http::test::peer_wait_until([&] { return _release || (_listener.accept(socket) == 0 && socket.is_open()); }, deadline);
        if (!socket.is_open())
            return false;
        socket.set_nonblocking(true);
        bool refused = false;
        qb::http::test::peer_wait_until(
            [&] {
                if (socket.handshake_complete() || _release)
                    return true;
                refused = socket.do_handshake() < 0;
                return refused || socket.handshake_complete();
            },
            deadline);
        return !refused && socket.handshake_complete();
    }

    bool
    send_all(qb::io::tcp::ssl::socket &socket, std::string const &bytes) {
        std::size_t sent   = 0;
        bool        failed = false;
        // Each look writes what the socket takes: all of it, a failure, or a socket that takes no more for now.
        qb::http::test::peer_wait_until(
            [&] {
                while (!_release && sent < bytes.size()) {
                    const int n = socket.write(bytes.data() + sent, bytes.size() - sent);
                    if (n < 0) {
                        failed = true;
                        return true;
                    }
                    sent += static_cast<std::size_t>(n);
                    if (n == 0)
                        return false;
                }
                return true;
            },
            qb::http::test::fail_wait::never);
        return !failed && sent == bytes.size();
    }

    void
    run() {
        static std::string const empty_settings("\x00\x00\x00\x04\x00\x00\x00\x00\x00", 9);
        // SETTINGS_INITIAL_WINDOW_SIZE = 2^31-1, then WINDOW_UPDATE on the connection by 2^31-1 - 65535.
        static std::string const open_windows("\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x04\x7f\xff\xff\xff"
                                              "\x00\x00\x04\x08\x00\x00\x00\x00\x00\x7f\xff\x00\x00",
                                              28);
        {
            qb::io::tcp::ssl::socket socket;
            if (!accept_one(socket) || !send_all(socket, empty_settings))
                return;
            char buffer[16384];
            qb::http::test::peer_wait_until([&] { return _release || socket.read(buffer, sizeof(buffer)) < 0; },
                                            qb::http::test::fail_wait::never);
            socket.close();
        }
        qb::io::tcp::ssl::socket socket;
        if (!accept_one(socket) || !send_all(socket, open_windows))
            return;
        _stalled = true;
        qb::http::test::peer_wait_until([this] { return _release.load(); }, qb::http::test::fail_wait::never,
                                        qb::http::test::fail_wait::nap{5ms});
        socket.close();
    }

    qb::io::tcp::ssl::listener _listener;
    std::uint16_t              _port = 0;
    std::atomic<bool>          _stalled{false};
    std::atomic<bool>          _release{false};
    std::thread                _thread; // last: started once every member it reads is built
};

} // namespace http2_run_sync_connect_test

// run_sync(client->connect()) from a failure callback of an explicit disconnect() of a live connection returns at once,
// `false`, "HTTP/2 connection is closing", and nothing connects for it. The connect() it asked waited for the end of the
// transport: the GOAWAY the close announced was delivered and the transport closed inside the pump, the attempt connected
// and the awaiter heard `true` -- then the close, resumed, ended that connection (Huly QB-1246).
TEST_F(Http2ClientTest, ARunSyncOfConnectFromAFailureCallbackOfAnExplicitDisconnectAnswersFalseAtOnce) {
    using http2_run_sync_connect_test::Blocked;
    bool    connected = false;
    Blocked blocked;
    int     failed = 0;
    auto    client = make_test_client();
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));
    qb::http::Request held;
    held.method() = qb::http::Method::GET;
    held.uri()    = qb::io::uri("/api/hang");
    ASSERT_TRUE(client->push_request(std::move(held), [&](qb::http::Response) {
        ++failed;
        http2_run_sync_connect_test::run_sync_connect(*client, blocked, "a failure callback of disconnect()");
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() >= 1; }));

    client->disconnect();
    EXPECT_EQ(failed, 1);
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/2 connection is closing");
    EXPECT_LT(blocked.took, 1s);
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    const auto until = std::chrono::steady_clock::now() + 500ms;
    while (std::chrono::steady_clock::now() < until)
        qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_FALSE(client->is_connected());
    EXPECT_FALSE(client->is_connecting());
}

// The same from a failure callback of a handshake that fails -- the server speaks no h2 over ALPN, so the client closes
// the transport after its failure pass, with no GOAWAY --, with no connect timeout set. It returns at once, `false`. The
// connect() it asked waited for the end of a transport the pass had not closed yet: for the connect timeout when one is
// set (2 s, measured), for ever with none (Huly QB-1246).
TEST_F(Http2ClientTest, ARunSyncOfConnectFromAFailureCallbackOfAFailedHandshakeAnswersFalseAtOnce) {
    using http2_run_sync_connect_test::Blocked;
    auto http1_only = reconnect::make_http1_only_server();
    ASSERT_TRUE(http1_only->ready());
    Blocked blocked;
    int     failed = 0;
    auto    client = reconnect::make_client_for(reconnect::port_of(*http1_only));
    client->set_connect_timeout(qb::duration::zero());
    client->set_auto_reconnect(false);
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
        if (++failed == 1)
            http2_run_sync_connect_test::run_sync_connect(*client, blocked, "a failure callback of a failed handshake");
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return failed != 0; }));
    EXPECT_EQ(failed, 1);
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/2 connection is closing");
    EXPECT_LT(blocked.took, 1s);
    const auto until = std::chrono::steady_clock::now() + 300ms;
    while (std::chrono::steady_clock::now() < until)
        qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    EXPECT_FALSE(client->is_connected());
    client->disconnect();
}

// A connect() whose connection the peer ends once its TLS handshake is complete -- before the client has read anything of
// it -- hears `false`, "Connection lost", and a connect() its callback asks starts an attempt of its own, whose callback
// hears its outcome. The handler of the transport's end called the waiting callbacks before it cleared the connecting
// state: the redial joined the attempt that had just ended and returned true, nothing started for it, and its callback
// was never called -- nor by the destructor, which disconnects only a client connected or connecting (Huly QB-1246; in
// 3.3.0 as well).
TEST_F(Http2ClientTest, ARedialFromTheCallbackOfAConnectionThePeerEndedAfterItsTlsHandshakeStartsAnAttemptOfItsOwn) {
    qb::http::test::TlsClosingPeer peer(2);
    ASSERT_NE(peer.port(), 0);
    int         first = 0, second = 0;
    bool        redialled = false, second_ok = true;
    std::string first_error;
    auto        client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &error) {
        ++first;
        first_error = error;
        if (!ok) {
            redialled = client->connect([&](bool again, const std::string &) {
                ++second;
                second_ok = again;
            });
        }
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return first != 0; }));
    EXPECT_EQ(first_error, "Connection lost") << "the transport's end, read once the connector handed it over";
    EXPECT_TRUE(redialled);
    EXPECT_TRUE(ServerThread::pump_until([&] { return second != 0; }, 5s)) << "the callback of the redial was never called";
    EXPECT_EQ(first, 1);
    EXPECT_EQ(second, 1);
    EXPECT_FALSE(second_ok);
    EXPECT_EQ(peer.ended(), 2) << "the redial reached the peer: an attempt of its own";
    EXPECT_FALSE(client->is_connecting());
}

// The same through run_sync(client->connect()) from that callback: it returns at once, `false`, "HTTP/2 connection is
// closing", and nothing connects for it. It joined the attempt that had just ended and waited for its connect timeout --
// 1 s with a 1 s one --, for ever with none (Huly QB-1246).
TEST_F(Http2ClientTest, ARunSyncOfConnectFromTheCallbackOfAConnectionThePeerEndedAfterItsTlsHandshakeAnswersFalseAtOnce) {
    using http2_run_sync_connect_test::Blocked;
    qb::http::test::TlsClosingPeer peer(2);
    ASSERT_NE(peer.port(), 0);
    Blocked     blocked;
    int         heard = 0;
    std::string error;
    auto        client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    client->set_connect_timeout(1s);
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &why) {
        error = why;
        if (++heard == 1 && !ok)
            http2_run_sync_connect_test::run_sync_connect(*client, blocked, "the callback of a connect() whose connection the peer ended");
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return heard != 0; }));
    EXPECT_EQ(heard, 1);
    EXPECT_EQ(error, "Connection lost");
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/2 connection is closing");
    EXPECT_LT(blocked.took, 500ms);
    const auto until = std::chrono::steady_clock::now() + 300ms;
    while (std::chrono::steady_clock::now() < until)
        qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    EXPECT_EQ(peer.ended(), 1);
}

// run_sync(client->connect()) from the failure callback of a request whose connection the server closed returns at once,
// `false`, and nothing connects for it. The attempt it asked started inside the handler of the transport's end, and
// connected in the pump -- the server back on its port --: the awaiter heard `true`, and dispose(), resumed once that
// handler returned, ended the connection (Huly QB-1246; in 3.3.0 as well).
TEST_F(Http2ClientTest, ARunSyncOfConnectFromAFailureCallbackOfAConnectionTheServerClosedAnswersFalseAtOnce) {
    using http2_run_sync_connect_test::Blocked;
    auto first = reconnect::make_h2_server_on(0); // a port of its own, which a later server of the case binds again
    ASSERT_TRUE(first->ready()) << "could not start the first server";
    const std::uint16_t port      = reconnect::port_of(*first);
    bool                connected = false;
    Blocked             blocked;
    int                 failed = 0;
    auto                client = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));
    qb::http::Request held;
    held.method() = qb::http::Method::GET;
    held.uri()    = qb::io::uri("/api/hang");
    ASSERT_TRUE(client->push_request(std::move(held), [&](qb::http::Response) {
        ++failed;
        http2_run_sync_connect_test::run_sync_connect(*client, blocked, "a failure callback of a connection the server closed");
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return first->server().hang_routed() >= 1; }));

    first.reset();                                   // the server's thread ends, and with it the connection
    auto again = reconnect::make_h2_server_on(port); // back on its port before the client reads that end
    ASSERT_TRUE(again->ready());
    ASSERT_TRUE(ServerThread::pump_until([&] { return failed != 0; }));
    EXPECT_EQ(failed, 1);
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/2 connection is closing");
    EXPECT_LT(blocked.took, 1s);
    const auto until = std::chrono::steady_clock::now() + 500ms;
    while (std::chrono::steady_clock::now() < until)
        qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_FALSE(client->is_connected());
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
}

// The same from a failure callback of a disconnect() asked while the connector is in flight -- no transport yet: the close
// ends the io all the same, once its callbacks have returned. It returns at once, `false`. The attempt it asked connected
// in the pump, the awaiter heard `true`, and the close, resumed, ended that connection (Huly QB-1246).
TEST_F(Http2ClientTest, ARunSyncOfConnectFromAFailureCallbackOfADisconnectBeforeAnyTransportAnswersFalseAtOnce) {
    using http2_run_sync_connect_test::Blocked;
    Blocked blocked;
    int     failed = 0;
    auto    client = make_test_client();
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
        ++failed;
        http2_run_sync_connect_test::run_sync_connect(*client, blocked, "a failure callback of disconnect() before any transport");
    }));
    ASSERT_TRUE(client->is_connecting()) << "the push asked a connection: its connector is in flight";

    client->disconnect();
    EXPECT_EQ(failed, 1);
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/2 connection is closing");
    EXPECT_LT(blocked.took, 1s);
    const auto until = std::chrono::steady_clock::now() + 500ms;
    while (std::chrono::steady_clock::now() < until)
        qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_FALSE(client->is_connected());
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
}

// The same from the failure callback of a request a graceful GOAWAY's drain fails -- pushed while the connection drained,
// automatic reconnection off. It returns at once, `false`. The drain's close runs that callback before it ends the
// transport, and the attempt connect() asked waits for that end (Huly QB-1246).
TEST_F(Http2ClientTest, ARunSyncOfConnectFromAFailureCallbackOfAGracefulGoawaysDrainAnswersFalseAtOnce) {
    using http2_run_sync_connect_test::Blocked;
    qb::http::test::Http2PlannedPeer peer(qb::http::test::Http2PlannedPeer::Plan::goaways_lowered, 30s);
    ASSERT_NE(peer.port(), 0);
    Blocked     blocked;
    int         answered = 0, failed = 0;
    std::string failure;
    auto        client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
        ++answered;
        // The connection drains: a request pushed now waits for the drain's end, which fails it.
        EXPECT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
            ++failed;
            failure = response.body().as<std::string>();
            http2_run_sync_connect_test::run_sync_connect(*client, blocked, "a failure callback of a graceful GOAWAY's drain");
        }));
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return failed != 0; }, 10s));
    EXPECT_EQ(answered, 1);
    EXPECT_EQ(failed, 1);
    EXPECT_EQ(failure, "Server sent GOAWAY and automatic reconnection is disabled");
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/2 connection is closing");
    EXPECT_LT(blocked.took, 1s);
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
}

// The same from the callback of a connect() whose connector failed at once -- the port refuses it, no transport was handed
// over --: it returns at once, `false`. qb-io delivers such a failure through the loop's deferred queue, which runs no
// nested drain: the next attempt's failure, deferred the same way, could not be delivered in the pump, and run_sync()
// returned with the connect timeout's -- after 3 s with a 3 s one, for ever with none (Huly QB-1246). The deadline is 3 s
// for Winsock, which reports a refusal after some 2 s.
TEST_F(Http2ClientTest, ARunSyncOfConnectFromTheCallbackOfAConnectWhoseConnectorFailedAnswersFalseAtOnce) {
    using http2_run_sync_connect_test::Blocked;
    const std::uint16_t port = 1; // refused: nothing listens on it, and no test binds it, nor does an ephemeral bind
    Blocked             blocked;
    int                 heard = 0;
    std::string         error;
    auto                client = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    client->set_connect_timeout(3s);
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &why) {
        error = why;
        if (++heard == 1 && !ok)
            http2_run_sync_connect_test::run_sync_connect(*client, blocked, "the callback of a connect() whose connector failed");
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return heard != 0; }));
    EXPECT_EQ(heard, 1);
    EXPECT_EQ(error, "TCP/SSL connection failed");
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/2 connection is closing");
    EXPECT_LT(blocked.took, 500ms);
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
}

// The same from the callback of a connect deadline, the connector still in flight -- a listener that completes TCP and
// never answers the ClientHello: it returns at once, `false`. A failure run from a timer: there run_sync() started the
// next attempt and returned its outcome, after another deadline. One rule for every close and failure (Huly QB-1246).
TEST_F(Http2ClientTest, ARunSyncOfConnectFromTheCallbackOfAConnectDeadlineAnswersFalseAtOnce) {
    using http2_run_sync_connect_test::Blocked;
    qb::io::tcp::listener silent;
    ASSERT_EQ(silent.listen_v4(0, "127.0.0.1"), 0);
    Blocked     blocked;
    int         heard = 0;
    std::string error;
    auto        client = reconnect::make_client_for(silent.local_endpoint().port());
    client->set_auto_reconnect(false);
    client->set_connect_timeout(300ms);
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &why) {
        error = why;
        if (++heard == 1 && !ok)
            http2_run_sync_connect_test::run_sync_connect(*client, blocked, "the callback of a connect deadline");
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return heard != 0; }));
    EXPECT_EQ(heard, 1);
    EXPECT_EQ(error, "Connection timeout");
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/2 connection is closing");
    EXPECT_LT(blocked.took, 1s);
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
}

// A connection started right after an explicit disconnect() whose failure callback ran the loop for a pass -- a refused
// run_sync(client->connect()) -- is not cut by that close's flush limit. The pass delivered the GOAWAY and ended the
// transport; the close then armed its limit for a transport already gone, and the new connection was closed by it,
// GOAWAY_FLUSH_LIMIT later. A request that callback pushed before the pump rides the connection the close's end starts:
// it was failed "Connection lost" by that end, which found the queue's flag not yet set (Huly QB-1246).
TEST_F(Http2ClientTest, AConnectionStartedAfterADisconnectWhoseFailureCallbackRanTheLoopOutlivesItsFlushLimit) {
    using http2_run_sync_connect_test::Blocked;
    bool             connected = false;
    Blocked          blocked;
    int              failed        = 0;
    int              pushed        = 0;
    qb::http::status pushed_status = qb::http::status::INTERNAL_SERVER_ERROR;
    bool             again         = false;
    int              answered      = 0;
    qb::http::status status        = qb::http::status::INTERNAL_SERVER_ERROR;
    auto             client        = make_test_client();
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));
    qb::http::Request held;
    held.method() = qb::http::Method::GET;
    held.uri()    = qb::io::uri("/api/hang");
    ASSERT_TRUE(client->push_request(std::move(held), [&](qb::http::Response) {
        ++failed;
        // Pushed before the pump: it waits for the connection the close's end starts (a connect of its own).
        EXPECT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
            ++pushed;
            pushed_status = response.status();
        }));
        http2_run_sync_connect_test::run_sync_connect(*client, blocked, "a failure callback of disconnect()");
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() >= 1; }));

    client->disconnect();
    EXPECT_EQ(failed, 1);
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_TRUE(ServerThread::pump_until([&] { return pushed != 0; }, 2s));
    EXPECT_EQ(pushed_status, qb::http::status::OK) << "the request pushed before the pump was failed with the transport it never rode";
    client->connect([&](bool ok, const std::string &) { again = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return again; })) << "the next connection never came up";
    const auto until = std::chrono::steady_clock::now() + qb::http2::Client::GOAWAY_FLUSH_LIMIT + 500ms;
    while (std::chrono::steady_clock::now() < until)
        qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_TRUE(client->is_connected()) << "the flush limit of the previous close ended the new connection";
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
        ++answered;
        status = response.status();
    }));
    EXPECT_TRUE(ServerThread::pump_until([&] { return answered != 0; }, 2s));
    EXPECT_EQ(status, qb::http::status::OK);
    client->disconnect();
}

// An explicit disconnect() whose failure callback ran the loop for a pass leaves nothing behind for the next connection: a
// request pushed afterwards, whose connection ends before its handshake -- a peer on the port that closes each connection
// once TLS is complete --, is failed with that end. The flag that keeps the queue for the end of a closing transport was
// set after the callbacks, for a transport already gone, and kept it for the next one: the request waited for its
// deadline, for ever with none (Huly QB-1246; in 3.3.0 as well).
TEST_F(Http2ClientTest, ARequestPushedAfterADisconnectWhoseFailureCallbackRanTheLoopHearsTheEndOfItsOwnConnection) {
    int              answered = 0; // before the client, which answers what it still holds when it is destroyed
    qb::http::status status   = qb::http::status::OK;
    auto             first    = reconnect::make_h2_server_on(0); // a port of its own, which a later server of the case binds again
    ASSERT_TRUE(first->ready()) << "could not start the first server";
    const std::uint16_t port      = reconnect::port_of(*first);
    bool                connected = false;
    bool                pumped    = false;
    auto                client    = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));
    qb::http::Request held;
    held.method() = qb::http::Method::GET;
    held.uri()    = qb::io::uri("/api/hang");
    ASSERT_TRUE(client->push_request(std::move(held), [&](qb::http::Response) {
        qb::io::async::run_sync(http2_run_sync_connect_test::completes_at_once()); // one pass of the loop
        pumped = true;
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return first->server().hang_routed() >= 1; }));
    client->disconnect();
    ASSERT_TRUE(pumped);
    EXPECT_FALSE(client->is_connecting());

    first.reset(); // the port now ends each connection once its TLS handshake is complete
    qb::http::test::TlsClosingPeer peer(1, port);
    ASSERT_EQ(peer.port(), port) << "could not bind the port the server just released";
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
        ++answered;
        status = response.status();
    }));
    EXPECT_TRUE(ServerThread::pump_until([&] { return answered != 0; }, 2s)) << "the request waited behind the previous close's flag";
    EXPECT_EQ(answered, 1);
    EXPECT_NE(status, qb::http::status::OK);
}

// A request pushed in the same turn of the loop as a disconnect() of a connector still in flight rides its own connection
// and is served. That close has no transport to end, and ends no io: closing one, it had qb-io raise a `disconnected` a
// loop pass later -- for an io not yet disposed, a first connection's --, and the request was failed by it, "Connection
// lost (reason: 1)", with a server up (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedRightAfterADisconnectOfAConnectorInFlightIsServedByItsOwnConnection) {
    int              answered = 0; // before the client, which answers what it still holds when it is destroyed
    qb::http::status status   = qb::http::status::INTERNAL_SERVER_ERROR;
    std::string      body;
    auto             server = reconnect::make_h2_server_on(0); // up from the start: the abandoned connector may reach it, its epoch drops it
    ASSERT_TRUE(server->ready()) << "could not start the server";
    const std::uint16_t port   = reconnect::port_of(*server);
    auto                client = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->connect(nullptr));
    client->disconnect(); // the connector is in flight: nothing to end
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
        ++answered;
        status = response.status();
        body   = response.body().as<std::string>();
    }));
    EXPECT_TRUE(ServerThread::pump_until([&] { return answered != 0; }, 3s));
    EXPECT_EQ(answered, 1);
    EXPECT_EQ(status, qb::http::status::OK) << body;
}

// A connect() whose connector fails at once -- the port refuses it, no transport was handed over -- leaves nothing behind
// for the next connection: a request pushed afterwards, whose connection ends before its handshake, is failed by that end,
// the first its connection meets. No `disconnected` comes for such a failure, so the flag that keeps the queue for one is
// not set by it: set, the request outlived that end and waited for a second connection (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedAfterAConnectorFailureHearsTheFirstEndOfItsOwnConnection) {
    int                   answered = 0, failed = 0; // before the client, which answers what it still holds when it is destroyed
    qb::http::status      status = qb::http::status::OK;
    qb::io::tcp::listener holder; // a port of ours, closed: the first attempt is refused there, and the peer then binds it
    ASSERT_EQ(holder.listen_v4(0, "127.0.0.1"), 0);
    const std::uint16_t port = holder.local_endpoint().port();
    holder.close();
    auto client = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &) { failed += ok ? 0 : 1; }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return failed != 0; }));
    qb::http::test::TlsClosingPeer peer(2, port);
    ASSERT_EQ(peer.port(), port) << "could not bind the port the holder released";
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
        ++answered;
        status = response.status();
    }));
    EXPECT_TRUE(ServerThread::pump_until([&] { return answered != 0; }, 2s));
    EXPECT_EQ(answered, 1);
    EXPECT_NE(status, qb::http::status::OK);
    EXPECT_EQ(peer.accepted(), 1) << "the request outlived the end of its first connection: the failure's flag";
}

// A connect() asked in the same turn of the loop as a disconnect() of the client's first connector, still in flight,
// hears its own attempt, once: connected. That close has no transport to end, and closed the io anyway: qb-io raised a
// `disconnected` for it -- an io not yet disposed --, which failed the waiting connect(), "Connection lost (reason: 1)";
// the attempt then connected and nobody was told, and a connect() asked again from that `false` started a second one
// beside it (Huly QB-1246).
TEST_F(Http2ClientTest, AConnectAskedRightAfterADisconnectOfAFirstConnectorInFlightHearsItsOwnAttempt) {
    std::vector<std::pair<bool, std::string>> heard; // before the client, which answers what it still holds when it is destroyed
    int                                       given_up = 0;
    std::string                               given_up_with;
    auto                                      server = reconnect::make_h2_server_on(0);
    ASSERT_TRUE(server->ready()) << "could not start the server";
    auto client = reconnect::make_client_for(reconnect::port_of(*server));
    client->set_auto_reconnect(false);
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &why) {
        given_up += ok ? 0 : 1;
        given_up_with = why;
    }));
    client->disconnect(); // the connector is in flight: no transport to end
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &why) { heard.emplace_back(ok, why); }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return !heard.empty() && client->is_connected(); }, 3s));
    for (const auto settle = std::chrono::steady_clock::now() + 300ms; std::chrono::steady_clock::now() < settle;)
        qb::io::async::run(EVRUN_NOWAIT); // what a stray close would still deliver
    EXPECT_EQ(given_up, 1);
    EXPECT_EQ(given_up_with, "Connection closed");
    ASSERT_EQ(heard.size(), 1u);
    EXPECT_TRUE(heard[0].first) << heard[0].second;
    EXPECT_TRUE(client->is_connected());
}

// The same close on a later connector -- the client's first connection over, its io disposed -- leaves nothing behind:
// a request pushed afterwards, whose connection ends before its handshake, is failed by that end. qb-io raises no
// `disconnected` for an io already disposed, and the flag that keeps the queue for one stayed set: the request outlived
// the end of its connection and waited for its deadline -- 60 s by default, for ever with none (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedAfterADisconnectOfALaterConnectorInFlightHearsTheEndOfItsOwnConnection) {
    int                            ended = 0, answered = 0; // before the client, which answers what it still holds when it is destroyed
    qb::http::status               status = qb::http::status::OK;
    qb::http::test::TlsClosingPeer peer(3); // ends each connection once its TLS handshake is complete, on a port of its own
    ASSERT_NE(peer.port(), 0);
    auto client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &) { ended += ok ? 0 : 1; }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return ended != 0 && !client->transport().is_open(); }));
    for (const auto settle = std::chrono::steady_clock::now() + 100ms; std::chrono::steady_clock::now() < settle;)
        qb::io::async::run(EVRUN_NOWAIT); // the first connection's io disposed
    ASSERT_TRUE(client->connect(nullptr));
    client->disconnect(); // a later connector in flight: no transport to end
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
        ++answered;
        status = response.status();
    }));
    EXPECT_TRUE(ServerThread::pump_until([&] { return answered != 0; }, 3s)) << "the request outlived the end of its connection";
    EXPECT_EQ(answered, 1);
    EXPECT_NE(status, qb::http::status::OK);
}

// A connect deadline that expires once the transport is up -- the peer completes TLS, never sends its SETTINGS, and ends
// the connection a little later -- and whose failure callback runs the loop until that end leaves nothing behind for the
// next connection: a request pushed afterwards, whose connection ends before its handshake, is failed with that end. The
// flags that keep a connect() and the queue for the end of the transport were set after the callbacks, for a transport
// already gone: the request waited for an end that never came, for ever with no deadline (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedAfterAConnectTimeoutWhoseFailureCallbackRanTheLoopHearsTheEndOfItsOwnConnection) {
    int              failed = 0, answered = 0; // before the client, which answers what it still holds when it is destroyed
    bool             open_at_entry = false, ended_in_pump = false;
    qb::http::status status = qb::http::status::OK;
    // Two connections, each held 2 s past its TLS handshake with no SETTINGS, then ended: the first outlives the 1 s
    // connect deadline, the second ends before its handshake. The margins leave a loaded host a second for TLS.
    qb::http::test::TlsClosingPeer silent(2, 0, std::vector<std::string>{"h2"}, 2s);
    const auto                     port = silent.port();
    ASSERT_NE(port, 0);
    auto client = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    client->set_connect_timeout(1s);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
        if (++failed != 1)
            return;
        open_at_entry = client->transport().is_open(); // the deadline found TLS done: the end below is this transport's
        qb::http::test::discard(qb::http::test::wait_until([&] { return !client->transport().is_open(); }, 5s),
                                "ended_in_pump records it, which the case asserts"); // the peer's end is read here
        ended_in_pump = !client->transport().is_open();
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return failed != 0; }, 10s));
    if (!open_at_entry)
        GTEST_SKIP() << "the host ran too slowly: the 1 s deadline fired before the TLS handshake, no transport to see end";
    ASSERT_TRUE(ended_in_pump) << "the peer's end was not read inside the failure callback: the case proves nothing";

    client->set_connect_timeout(qb::duration::zero()); // no deadline rescues the next request
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
        ++answered;
        status = response.status();
    }));
    EXPECT_TRUE(ServerThread::pump_until([&] { return answered != 0; }, 8s)) << "the request waited behind the timed-out attempt's flags";
    EXPECT_EQ(answered, 1);
    EXPECT_NE(status, qb::http::status::OK);
}

// The same after a graceful GOAWAY's drain that a request deadline ends -- the peer names the request's stream in its
// GOAWAY, never answers it, and ends the connection a little later. The deadline fails that request, whose callback
// pushes another; the drain then fails that one -- automatic reconnection off --, and its failure callback runs the loop
// until the peer's end. A request pushed afterwards, whose connection ends before its handshake, is failed with that end.
// The queue's flag was set after that callback, for a transport already gone, and kept the queue of the next one from
// hearing its end (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedAfterAGracefulGoawaysDrainWhoseFailureCallbackRanTheLoopHearsTheEndOfItsOwnConnection) {
    int              first = 0, failed = 0, answered = 0; // before the client, which answers what it still holds when it is destroyed
    bool             ended_in_pump = false;
    std::string      failure;
    qb::http::status status = qb::http::status::OK;
    auto       planned = std::make_unique<qb::http::test::Http2PlannedPeer>(qb::http::test::Http2PlannedPeer::Plan::goaway_then_close, 30s);
    const auto port    = planned->port();
    ASSERT_NE(port, 0);
    bool up     = false;
    auto client = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    client->set_request_timeout(200ms); // from here: the connection is up, the deadline bounds the request alone
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
        ++first;
        // The connection drains: a request pushed now waits for the drain's end, which fails it.
        EXPECT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
            ++failed;
            failure = response.body().as<std::string>();
            qb::http::test::discard(qb::http::test::wait_until([&] { return !client->transport().is_open(); }, 3s),
                                    "ended_in_pump records it, which the case asserts"); // the peer's end is read here
            ended_in_pump = !client->transport().is_open();
        }));
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return failed != 0; }, 10s));
    EXPECT_EQ(first, 1);
    EXPECT_EQ(failure, "Server sent GOAWAY and automatic reconnection is disabled");
    ASSERT_TRUE(ended_in_pump) << "the peer's end was not read inside the failure callback: the case proves nothing";

    client->set_request_timeout(qb::duration::zero()); // no deadline rescues the next request
    planned.reset();                                   // the port now ends each connection once its TLS handshake is complete
    qb::http::test::TlsClosingPeer peer(1, port);
    ASSERT_EQ(peer.port(), port) << "could not bind the port the planned peer just released";
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
        ++answered;
        status = response.status();
    }));
    EXPECT_TRUE(ServerThread::pump_until([&] { return answered != 0; }, 2s)) << "the request waited behind the drain's flag";
    EXPECT_EQ(answered, 1);
    EXPECT_NE(status, qb::http::status::OK);
}

// A close whose GOAWAY cannot be delivered -- the peer reads nothing, the client's output full of a body -- keeps its
// transport while its callbacks run, whatever an earlier close armed: a callback that pumps the loop past the flush limit
// of the close before it finds this transport still open. That limit matches no later close (Huly QB-1246).
TEST_F(Http2ClientTest, AnEarlierCloseFlushLimitNeverEndsALaterCloseWhileItsCallbacksRun) {
    http2_run_sync_connect_test::StallingPeer peer;
    ASSERT_NE(peer.port(), 0);
    bool                                  up = false;
    std::chrono::steady_clock::time_point first_close;
    bool                                  again           = false;
    int                                   failed          = 0;
    bool                                  open_after_pump = false;
    auto                                  client          = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    first_close = std::chrono::steady_clock::now();
    client->disconnect(); // its GOAWAY is read, its transport ends, its limit is armed for GOAWAY_FLUSH_LIMIT
    client->connect([&](bool ok, const std::string &) { again = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return again && peer.stalled(); }, 2s));
    ASSERT_EQ(qb::io::socket::set_optval(client->transport().native_handle(), SOL_SOCKET, SO_SNDBUF, 16384), 0);

    qb::http::Request big{qb::http::method::POST, qb::io::uri("/upload")};
    big.body() = std::string(1024 * 1024, 'x'); // far more than the capped socket buffers hold: the peer reads nothing
    ASSERT_TRUE(client->push_request(std::move(big), [&](qb::http::Response) {
        ++failed;
        const auto until = first_close + qb::http2::Client::GOAWAY_FLUSH_LIMIT + 300ms;
        while (std::chrono::steady_clock::now() < until)
            qb::io::async::run(EVRUN_NOWAIT);
        open_after_pump = client->transport().is_open();
    }));
    for (const auto settle = std::chrono::steady_clock::now() + 100ms; std::chrono::steady_clock::now() < settle;)
        qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_GT(client->out().size(), 0u) << "the body left the client: nothing would hold its GOAWAY back";
    if (std::chrono::steady_clock::now() >= first_close + qb::http2::Client::GOAWAY_FLUSH_LIMIT - 200ms)
        GTEST_SKIP() << "the host ran too slowly: the second close must come well before the first one's limit";

    client->disconnect(); // its GOAWAY waits behind the body
    EXPECT_EQ(failed, 1);
    EXPECT_TRUE(open_after_pump) << "the first close's flush limit ended the transport of the second while its callbacks ran";
    EXPECT_TRUE(ServerThread::pump_until([&] { return !client->transport().is_open(); }, 3s)) << "its own limit ends it";
}

// The whole run, observed from outside: a request against a server that will never speak h2, a
// retry callback that pushes it back on every failure, a policy of four attempts at 40/80/160 ms.
// The failures must come 6 deep (the explicit auto-connect, the four attempts, the verdict), the
// waits must be at least the policy's, on_retry must be told before each wait with the number of
// failed attempts, and a push from a failure callback must never connect on its own.
TEST_F(Http2ClientTest, AutoReconnectBacksOffThroughThePolicyUntilTheRunIsExhausted) {
    auto http1_only = reconnect::make_http1_only_server();
    ASSERT_TRUE(http1_only->ready());
    std::vector<std::pair<int, qb::duration>> retries;
    std::vector<reconnect::Failure>           failures;
    bool                                      exhausted = false;
    std::function<void(qb::http::Response)>   on_response;
    bool                                      again  = false;
    auto                                      client = reconnect::make_client_for(reconnect::port_of(*http1_only));

    client->enable_auto_reconnect(qb::http2::RetryPolicy{}
                                      .with_initial_delay(40ms)
                                      .with_multiplier(2.0)
                                      .with_max_delay(1s)
                                      .with_jitter(false)
                                      .with_max_attempts(4)
                                      .with_on_retry([&](int attempt, qb::duration delay) {
                                          retries.emplace_back(attempt, delay);
                                          // Told as the wait starts: the run is waiting, nothing is connecting.
                                          EXPECT_TRUE(client->is_reconnecting());
                                          EXPECT_FALSE(client->is_connecting());
                                          EXPECT_EQ(client->reconnect_attempts(), attempt + 1);
                                      }));

    on_response = [&](qb::http::Response r) {
        failures.push_back({std::chrono::steady_clock::now(), r.status(), r.body().template as<std::string>()});
        if (failures.back().body.find("exhausted") != std::string::npos) {
            exhausted = true;
            return;
        }
        // The retry pattern: push it back from the failure callback. It must QUEUE behind the
        // attempt the run schedules, never start a connection of its own.
        ASSERT_TRUE(client->push_request(reconnect::get_test(), on_response));
        EXPECT_FALSE(client->is_connecting()) << "a push from a failure callback must not connect on its own";
    };
    ASSERT_TRUE(client->push_request(reconnect::get_test(), on_response));

    ASSERT_TRUE(ServerThread::pump_until([&] { return exhausted; }, 30s));

    ASSERT_EQ(failures.size(), 6u) << "the explicit auto-connect, four attempts, the verdict";
    for (std::size_t i = 0; i + 1 < failures.size(); ++i) {
        EXPECT_EQ(failures[i].status, qb::http::status::SERVICE_UNAVAILABLE) << "failure " << i;
        EXPECT_NE(failures[i].body.find("ALPN"), std::string::npos) << "failure " << i << " said: " << failures[i].body;
    }
    EXPECT_EQ(failures.back().status, qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(failures.back().body, "Reconnection attempts exhausted (4)");

    ASSERT_EQ(retries.size(), 3u) << "three waits: before attempts 2, 3 and 4 (attempt 1 is immediate)";
    EXPECT_EQ(retries[0].first, 1);
    EXPECT_EQ(retries[0].second, 40ms);
    EXPECT_EQ(retries[1].first, 2);
    EXPECT_EQ(retries[1].second, 80ms);
    EXPECT_EQ(retries[2].first, 3);
    EXPECT_EQ(retries[2].second, 160ms);

    // failures[1..4] are the four attempts; the gap before each of attempts 2..4 is its wait, at
    // least. The upper bound only says "waited, not stalled": the handshake itself costs a few ms.
    EXPECT_GE(reconnect::ms_between(failures[1], failures[2]), 40);
    EXPECT_GE(reconnect::ms_between(failures[2], failures[3]), 80);
    EXPECT_GE(reconnect::ms_between(failures[3], failures[4]), 160);
    EXPECT_LT(reconnect::ms_between(failures[1], failures[4]), 5000);

    EXPECT_EQ(client->reconnect_attempts(), 4) << "the exhausted run keeps its count until the next connect()";
    EXPECT_FALSE(client->is_reconnecting());
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());

    // The next push is a fresh intent: it auto-connects at once and starts a run of its own; this
    // callback does not push back, so that run never begins (no work waits) and the count resets.
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response r) {
        EXPECT_EQ(r.status(), qb::http::status::SERVICE_UNAVAILABLE);
        again = true;
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return again; }));
    EXPECT_EQ(client->reconnect_attempts(), 0);
    EXPECT_FALSE(client->is_reconnecting());
    EXPECT_EQ(retries.size(), 3u) << "no wait was scheduled: nothing was waiting";
}

// `max_attempts` of zero: the run is exhausted before its first attempt. The work the failure
// callback pushed back fails with the verdict at once, and no attempt is ever scheduled.
TEST_F(Http2ClientTest, ZeroMaxAttemptsNeverReconnects) {
    auto http1_only = reconnect::make_http1_only_server();
    ASSERT_TRUE(http1_only->ready());
    int                      on_retry_calls = 0;
    std::vector<std::string> verdicts;
    auto                     client = reconnect::make_client_for(reconnect::port_of(*http1_only));

    client->enable_auto_reconnect(
        qb::http2::RetryPolicy{}.with_max_attempts(0).with_jitter(false).with_on_retry([&](int, qb::duration) { ++on_retry_calls; }));

    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response r) {
        verdicts.push_back(r.body().template as<std::string>());
        ASSERT_TRUE(client->push_request(reconnect::get_test(),
                                         [&](qb::http::Response second) { verdicts.push_back(second.body().template as<std::string>()); }));
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return verdicts.size() == 2u; }));
    EXPECT_NE(verdicts[0].find("ALPN"), std::string::npos);
    EXPECT_EQ(verdicts[1], "Reconnection attempts exhausted (0)");
    EXPECT_EQ(on_retry_calls, 0);
    EXPECT_EQ(client->reconnect_attempts(), 0);
    EXPECT_FALSE(client->is_reconnecting());
    EXPECT_FALSE(client->is_connecting());
}

// The run ends the way it is meant to: the server comes back while the run waits, the next
// attempt connects, the request that waited is served, the count resets. The "server that is
// down" is a listener that accepts TCP and never speaks TLS -- the attempt comes up at the TCP
// level and dies on the connect deadline, the one failure shape a refused port cannot give the
// same way on Winsock and on POSIX -- and the server takes over its port during the wait.
TEST_F(Http2ClientTest, ReconnectionSucceedsWhenTheServerComesBackDuringTheWait) {
    qb::io::tcp::listener silent;
    ASSERT_EQ(silent.listen_v4(0, "127.0.0.1"), 0);
    const std::uint16_t port = silent.local_endpoint().port();
    ASSERT_NE(port, 0);

    std::vector<std::pair<int, qb::duration>> retries;
    std::vector<reconnect::Failure>           failures;
    std::optional<qb::http::Response>         served;
    std::function<void(qb::http::Response)>   on_response;
    auto                                      client = reconnect::make_client_for(port);
    client->set_connect_timeout(300ms); // the silent listener is left on this, not on a refusal

    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_initial_delay(800ms).with_jitter(false).with_on_retry(
        [&](int attempt, qb::duration delay) { retries.emplace_back(attempt, delay); }));

    on_response = [&](qb::http::Response r) {
        if (r.status() == qb::http::status::OK) {
            served = std::move(r);
            return;
        }
        failures.push_back({std::chrono::steady_clock::now(), r.status(), r.body().template as<std::string>()});
        ASSERT_TRUE(client->push_request(reconnect::get_test(), on_response));
    };
    ASSERT_TRUE(client->push_request(reconnect::get_test(), on_response));

    // The explicit auto-connect and attempt 1 both die on the deadline; the first wait (800 ms,
    // before attempt 2) is when the server takes the port over.
    ASSERT_TRUE(ServerThread::pump_until([&] { return !retries.empty(); }, 20s));
    ASSERT_EQ(retries[0].first, 1);
    ASSERT_EQ(retries[0].second, 800ms);
    EXPECT_EQ(failures.size(), 2u);
    EXPECT_TRUE(client->is_reconnecting());
    EXPECT_EQ(client->reconnect_attempts(), 2);

    silent.close();
    auto server = reconnect::make_h2_server_on(port);
    ASSERT_TRUE(server->ready()) << "the h2 server could not take the port the silent listener just released";

    ASSERT_TRUE(ServerThread::pump_until([&] { return served.has_value(); }, 20s));
    EXPECT_EQ(served->body().template as<std::string>(), "HTTP/2 GET Success");
    EXPECT_EQ(failures.size(), 2u) << "the request that waited was served, not failed again";
    EXPECT_EQ(retries.size(), 1u) << "one wait, before the attempt that connected";
    EXPECT_EQ(client->reconnect_attempts(), 0) << "a connection that came up ends the run";
    EXPECT_FALSE(client->is_reconnecting());
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
}

// An explicit disconnect ends the run: the scheduled attempt is cancelled, the count resets, and
// nothing connects afterwards on its own.
TEST_F(Http2ClientTest, ExplicitDisconnectCancelsTheScheduledAttempt) {
    auto http1_only = reconnect::make_http1_only_server();
    ASSERT_TRUE(http1_only->ready());
    int                                     retries = 0;
    std::vector<std::string>                verdicts;
    std::function<void(qb::http::Response)> on_response;
    auto                                    client = reconnect::make_client_for(reconnect::port_of(*http1_only));

    client->enable_auto_reconnect(
        qb::http2::RetryPolicy{}.with_initial_delay(150ms).with_jitter(false).with_on_retry([&](int, qb::duration) { ++retries; }));

    on_response = [&](qb::http::Response r) {
        verdicts.push_back(r.body().template as<std::string>());
        if (verdicts.size() < 3) { // keep the run alive through attempt 1; stop pushing after that
            ASSERT_TRUE(client->push_request(reconnect::get_test(), on_response));
        }
    };
    ASSERT_TRUE(client->push_request(reconnect::get_test(), on_response));

    // After attempt 1 failed, attempt 2 is scheduled 150 ms out and a request waits for it.
    ASSERT_TRUE(ServerThread::pump_until([&] { return retries == 1; }));
    ASSERT_TRUE(client->is_reconnecting());
    ASSERT_EQ(client->reconnect_attempts(), 2);
    ASSERT_EQ(verdicts.size(), 2u);

    client->disconnect();
    EXPECT_FALSE(client->is_reconnecting());
    EXPECT_EQ(client->reconnect_attempts(), 0);
    // The waiting request got the disconnect's verdict, once; its callback (verdicts.size() == 3)
    // pushed nothing back, so no run follows.
    ASSERT_TRUE(ServerThread::pump_until([&] { return verdicts.size() == 3u; }));
    EXPECT_EQ(verdicts[2], "Connection closed");

    // Well past the cancelled wait: no attempt fired, nothing connected, nothing counted.
    const auto until = std::chrono::steady_clock::now() + 400ms;
    while (std::chrono::steady_clock::now() < until) {
        qb::io::async::run(EVRUN_NOWAIT);
    }
    EXPECT_EQ(retries, 1);
    EXPECT_EQ(verdicts.size(), 3u);
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_reconnecting());
    EXPECT_EQ(client->reconnect_attempts(), 0);
}

// A disconnect() while the connect is in flight: the connect callback gets its verdict (it used
// to get nothing, and a coroutine awaiting connect() hung), and the late completion of the
// connector is dropped rather than bringing the client up behind the caller's back.
TEST_F(Http2ClientTest, DisconnectWhileConnectingFailsTheConnectCallbackAndDropsTheLateCompletion) {
    std::optional<bool> outcome;
    std::string         message;
    auto                client = make_test_client();

    client->connect([&](bool ok, const std::string &err) {
        outcome = ok;
        message = err;
    });
    ASSERT_TRUE(client->is_connecting());
    client->disconnect();

    ASSERT_TRUE(ServerThread::pump_until([&] { return outcome.has_value(); }));
    EXPECT_FALSE(*outcome);
    EXPECT_EQ(message, "Connection closed");
    EXPECT_FALSE(client->is_connecting());

    // The connector completes on its own time against a live server: the completion must be
    // dropped. Pump well past a loopback TLS handshake and the client must still be down.
    const auto until = std::chrono::steady_clock::now() + 500ms;
    while (std::chrono::steady_clock::now() < until) {
        qb::io::async::run(EVRUN_NOWAIT);
    }
    EXPECT_FALSE(client->is_connected());
    EXPECT_FALSE(client->is_connecting());

    // And the client is reusable: an explicit connect() after that comes up.
    outcome.reset();
    client->connect([&](bool ok, const std::string &err) {
        outcome = ok;
        message = err;
    });
    ASSERT_TRUE(ServerThread::pump_until([&] { return outcome.has_value(); }));
    EXPECT_TRUE(*outcome) << message;
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
}

// An EXPLICIT disconnect() with a request in flight: the request is failed ONCE, with the
// disconnect's verdict, and no reconnection run follows -- the user asked out, the rule the
// HTTP/1.1 client's `_intentional_disconnect` applies. What the verdict's callback pushes back
// connects on its own (a push's auto-connect, as on http1) and is served; it is not failed a
// second time by the transport's own disconnected pass, nor a third by the dispose pass, which is
// what a retry callback saw until 3.2.
TEST_F(Http2ClientTest, ExplicitDisconnectFailsTheInFlightRequestOnceAndStartsNoRun) {
    int                               retries   = 0;
    bool                              connected = false;
    std::vector<std::string>          verdicts;
    std::optional<qb::http::Response> served;
    auto                              client = make_test_client();
    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_jitter(false).with_on_retry([&](int, qb::duration) { ++retries; }));

    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));

    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response r) {
        verdicts.push_back(r.body().template as<std::string>());
        ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response again) {
            if (again.status() == qb::http::status::OK) {
                served = std::move(again);
            } else {
                verdicts.push_back(again.body().template as<std::string>());
            }
        }));
        // Not a failure pass: the push connected on its own, and no run is counting it.
        EXPECT_TRUE(client->is_connecting());
        EXPECT_FALSE(client->is_reconnecting());
        EXPECT_EQ(client->reconnect_attempts(), 0);
    }));
    ASSERT_EQ(client->get_active_request_count(), 1u) << "sent on the live connection, awaiting its response";
    client->disconnect(); // fails the in-flight request now; its callback pushes one back

    ASSERT_TRUE(ServerThread::pump_until([&] { return served.has_value() || verdicts.size() > 1; }));
    ASSERT_EQ(verdicts.size(), 1u) << "the pushed-back request was failed again with: " << (verdicts.size() > 1 ? verdicts[1] : "");
    EXPECT_EQ(verdicts[0], "Connection closed");
    ASSERT_TRUE(served.has_value());
    EXPECT_EQ(served->body().template as<std::string>(), "HTTP/2 GET Success");
    EXPECT_EQ(retries, 0) << "an explicit disconnect starts no reconnection run";
    EXPECT_EQ(client->reconnect_attempts(), 0);
    EXPECT_FALSE(client->is_reconnecting());
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
}

// A connect() deferred behind a closing transport (see _connect_after_close), plus a second push
// arriving while it waits, both reach the reconnected server: the deferred attempt starts from the
// close's `disconnected`, and the request the outside push queued rides the same new connection.
// The client is a few connect-timeouts old when the disconnect fires, so the deferred attempt also
// runs on a freshly stamped deadline rather than the closed connection's.
TEST_F(Http2ClientTest, ADeferredConnectAndAFollowUpPushBothReachTheReconnectedServer) {
    bool                              connected = false;
    std::vector<std::string>          verdicts;
    std::optional<qb::http::Response> served;
    std::optional<qb::http::Response> second;
    auto                              client = make_test_client();
    client->set_connect_timeout(200ms);
    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_jitter(false));

    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));
    const auto older_than_the_timeout = std::chrono::steady_clock::now() + 350ms;
    while (std::chrono::steady_clock::now() < older_than_the_timeout) {
        qb::io::async::run(EVRUN_NOWAIT);
    }
    ASSERT_TRUE(client->is_connected());

    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response r) {
        verdicts.push_back(r.body().template as<std::string>());
        ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response again) {
            if (again.status() == qb::http::status::OK) {
                served = std::move(again);
            } else {
                verdicts.push_back(again.body().template as<std::string>());
            }
        }));
    }));
    client->disconnect(); // the verdict's push connects, deferred behind this close
    ASSERT_TRUE(client->is_connecting());
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response r) { second = std::move(r); }));

    ASSERT_TRUE(ServerThread::pump_until([&] { return (served.has_value() && second.has_value()) || verdicts.size() > 1; }));
    ASSERT_EQ(verdicts.size(), 1u) << "the deferred connect was failed with: " << (verdicts.size() > 1 ? verdicts[1] : "");
    ASSERT_TRUE(served.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->status(), qb::http::status::OK);
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
}

// A PEER drop (not a disconnect() of ours) with a request in flight: the request fails once with
// "Connection lost", what its callback pushes back queues behind the run's immediate attempt (it
// does not connect on its own), and the run serves it once the server is back -- each failed
// attempt fails the waiting work, as the HTTP/1.1 client does, and the retry callback pushes it
// back. The drop is the server's: its thread is stopped while `/api/hang` holds the stream open,
// and a new server takes the port back during the run's first wait.
TEST_F(Http2ClientTest, WorkPushedBackFromAPeerDropIsServedByTheReconnectionRun) {
    auto first = reconnect::make_h2_server_on(0); // a port of its own, which a later server of the case binds again
    ASSERT_TRUE(first->ready()) << "could not start the first server";
    const std::uint16_t port = reconnect::port_of(*first);

    std::vector<std::pair<int, qb::duration>> retries;
    bool                                      connected = false;
    std::vector<std::string>                  verdicts;
    std::optional<qb::http::Response>         served;
    std::function<void(qb::http::Response)>   on_response;
    auto                                      client = reconnect::make_client_for(port);
    client->set_connect_timeout(3s);
    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_initial_delay(500ms).with_jitter(false).with_on_retry(
        [&](int attempt, qb::duration delay) { retries.emplace_back(attempt, delay); }));

    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));

    on_response = [&](qb::http::Response r) {
        if (r.status() == qb::http::status::OK) {
            served = std::move(r);
            return;
        }
        verdicts.push_back(r.body().template as<std::string>());
        ASSERT_TRUE(client->push_request(reconnect::get_test(), on_response));
        EXPECT_FALSE(client->is_connecting()) << "a push from a failure callback queues behind the run";
    };
    qb::http::Request hang;
    hang.method() = qb::http::Method::GET;
    hang.uri()    = qb::io::uri("/api/hang"); // the server never completes it: in flight until the peer drops
    ASSERT_TRUE(client->push_request(hang, on_response));
    ASSERT_EQ(client->get_active_request_count(), 1u);
    first.reset(); // the peer drops us; the port is free again

    // The drop fails the request once ("Connection lost"); the run's immediate attempt finds nothing
    // listening and fails the pushed-back request once more ("Connection failed: ..."), whose callback
    // pushes again; attempt 2 waits 500 ms: the server comes back inside that wait.
    ASSERT_TRUE(ServerThread::pump_until([&] { return !retries.empty() || served.has_value(); }, 20s));
    ASSERT_EQ(retries.size(), 1u);
    EXPECT_EQ(retries[0].first, 1);
    EXPECT_EQ(retries[0].second, 500ms);
    ASSERT_EQ(verdicts.size(), 2u) << "the drop, then the refused attempt";
    EXPECT_NE(verdicts[0].find("Connection lost"), std::string::npos) << verdicts[0];
    EXPECT_NE(verdicts[1].find("Connection failed"), std::string::npos) << verdicts[1];
    EXPECT_TRUE(client->is_reconnecting());
    auto second = reconnect::make_h2_server_on(port);
    ASSERT_TRUE(second->ready()) << "the second server could not take the port back";

    ASSERT_TRUE(ServerThread::pump_until([&] { return served.has_value(); }, 20s));
    EXPECT_EQ(verdicts.size(), 2u) << "no further failure: attempt 2 served the request";
    EXPECT_EQ(served->body().template as<std::string>(), "HTTP/2 GET Success");
    EXPECT_EQ(client->reconnect_attempts(), 0) << "the connection that came up ended the run";
    EXPECT_FALSE(client->is_reconnecting());
    client->disconnect();
}

// Auto-reconnect off: a push from a failure callback connects on its own, at once, as it always
// did -- the run never exists, on_retry is never told, and the client settles idle rather than
// hanging with a queued request nobody connects for.
TEST_F(Http2ClientTest, WithAutoReconnectOffAPushFromAFailureCallbackConnectsOnItsOwn) {
    auto http1_only = reconnect::make_http1_only_server();
    ASSERT_TRUE(http1_only->ready());
    int                      on_retry_calls = 0;
    std::vector<std::string> verdicts;
    auto                     client = reconnect::make_client_for(reconnect::port_of(*http1_only));

    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_on_retry([&](int, qb::duration) { ++on_retry_calls; }));
    client->disable_auto_reconnect(); // keeps the policy, disarms the run

    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response r) {
        verdicts.push_back(r.body().template as<std::string>());
        ASSERT_TRUE(client->push_request(reconnect::get_test(),
                                         [&](qb::http::Response second) { verdicts.push_back(second.body().template as<std::string>()); }));
        EXPECT_TRUE(client->is_connecting()) << "with the run disarmed, the push connects on its own";
        EXPECT_FALSE(client->is_reconnecting());
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return verdicts.size() == 2u; }));
    EXPECT_NE(verdicts[0].find("ALPN"), std::string::npos);
    EXPECT_NE(verdicts[1].find("ALPN"), std::string::npos);
    EXPECT_EQ(on_retry_calls, 0);
    EXPECT_EQ(client->reconnect_attempts(), 0);

    const auto until = std::chrono::steady_clock::now() + 300ms;
    while (std::chrono::steady_clock::now() < until) {
        qb::io::async::run(EVRUN_NOWAIT);
    }
    EXPECT_EQ(verdicts.size(), 2u) << "no third verdict: the transport's own disconnected pass has nothing left to fail";
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_reconnecting());
}

// The jitter is real when it is on: the same policy, the same attempt, spread across a run. Pinned
// on the client rather than on the policy alone because the client is what hands the generator in.
TEST_F(Http2ClientTest, JitterSpreadsTheWaitsOfARun) {
    auto http1_only = reconnect::make_http1_only_server();
    ASSERT_TRUE(http1_only->ready());
    std::vector<long long>                  waits_ms;
    bool                                    exhausted = false;
    std::function<void(qb::http::Response)> on_response;
    auto                                    client = reconnect::make_client_for(reconnect::port_of(*http1_only));

    client->enable_auto_reconnect(qb::http2::RetryPolicy{}
                                      .with_initial_delay(40ms)
                                      .with_multiplier(1.0)
                                      .with_max_delay(40ms)
                                      .with_jitter(true)
                                      .with_max_attempts(9)
                                      .with_on_retry([&](int, qb::duration delay) {
                                          waits_ms.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(delay).count());
                                      }));

    on_response = [&](qb::http::Response r) {
        if (r.body().template as<std::string>().find("exhausted") != std::string::npos) {
            exhausted = true;
            return;
        }
        ASSERT_TRUE(client->push_request(reconnect::get_test(), on_response));
    };
    ASSERT_TRUE(client->push_request(reconnect::get_test(), on_response));
    ASSERT_TRUE(ServerThread::pump_until([&] { return exhausted; }, 30s));

    ASSERT_EQ(waits_ms.size(), 8u) << "eight waits for nine attempts";
    for (const auto w : waits_ms) {
        EXPECT_GE(w, 30);
        EXPECT_LE(w, 50);
    }
    const bool all_equal = std::all_of(waits_ms.begin(), waits_ms.end(), [&](long long w) { return w == waits_ms.front(); });
    EXPECT_FALSE(all_equal) << "eight draws of a uniform +-10 ms that all agree: the jitter is not applied";
}

} // namespace

namespace http2_server_lifecycle_test {
using Context     = qb::http::Context<H2Session>;
using SessionBase = qb::http2::use<H2Session>::session<H2Server>;

// Reuse H2Server/H2Session and the existing TLS resources, on one owner loop.
// This is deliberately not another network fixture: it only configures the
// existing server type without ServerThread, so ownership can be inspected.
bool
configure_owner_loop(H2Server &server) {
    if (!qb::http::test::certs_available()) {
        ADD_FAILURE() << "HTTP/2 lifecycle witnesses require the existing TLS certificates";
        return false;
    }
    server.transport().init(qb::io::ssl::Context::server(qb::http::test::ssl_cert_path().string(), qb::http::test::ssl_key_path().string())
                                .alpn({"h2", "http/1.1"}));
    if (server.transport().listen_v4(0, "127.0.0.1") != 0)
        return false;
    server.start();
    return server.transport().local_endpoint().port() != 0;
}

// Observers and held contexts are destroyed while the actual Router is still
// alive, including ASSERT exits. This guard is test teardown, not the repair.
struct ReplyObservation {
    int                replies = 0;
    qb::http::Response response;
};

struct ClearSessionsBeforeObservations {
    H2Server                 &server;
    std::shared_ptr<Context> &held;
    ~ClearSessionsBeforeObservations() {
        held.reset();
        server.sessions().clear();
    }
};

class PendingMiddleware : public qb::http::IMiddleware<H2Session> {
    std::shared_ptr<Context> &_held;
    int                      &_cancel_count;

public:
    PendingMiddleware(std::shared_ptr<Context> &held, int &cancel_count)
        : _held(held)
        , _cancel_count(cancel_count) {}
    void
    process(std::shared_ptr<Context> context) override {
        _held = std::move(context);
    }
    std::string
    name() const override {
        return "PendingMiddleware";
    }
    void
    cancel() noexcept override {
        ++_cancel_count;
    }
};
} // namespace http2_server_lifecycle_test

// QB-498: native H2 closure and drain are separate observations. Queue a
// response only after stopping the server watcher, then run one owner-loop
// turn through the real TLS watcher. A complete write of every queued byte selects
// eos; there is no pending_write event between enqueue and the assertion.
TEST(Http2ServerLifecycle, TotalTransportDrainReclaimsCompletedContextsBeforeDisconnect) {
    using namespace http2_server_lifecycle_test;
    qb::io::async::init();
    std::shared_ptr<Context>        held;
    int                             post_send        = 0;
    int                             request_complete = 0;
    H2Server                        server;
    ClearSessionsBeforeObservations cleanup{server, held};
    server.router().get("/drain-observe", [&](auto context) { held = std::move(context); });
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (context.request().uri().path() != "/drain-observe")
            return;
        if (point == qb::http::HookPoint::POST_RESPONSE_SEND)
            ++post_send;
        if (point == qb::http::HookPoint::REQUEST_COMPLETE)
            ++request_complete;
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    std::shared_ptr<H2Session> session;
    for (int request_index = 0; request_index != 3; ++request_index) {
        if (session)
            session->start();
        auto reply = std::make_shared<ReplyObservation>();
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/drain-observe")}, [reply](auto result) {
            reply->response = std::move(result);
            ++reply->replies;
        }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return held != nullptr; }));
        ASSERT_FALSE(held->is_completed());
        session = held->session();
        ASSERT_NE(session, nullptr);
        session->stop();
        ASSERT_EQ(session->out().size(), 0u) << "the old handshake/control output must already be drained";
        std::weak_ptr<Context> weak_context    = held;
        auto                   externally_held = request_index == 1 ? held : std::shared_ptr<Context>{};
        const auto             stream_id       = static_cast<std::uint32_t>(held->request().stream_id);
        held->text("drain-" + std::to_string(request_index));
        ASSERT_TRUE(held->is_completed());
        auto *protocol = static_cast<H2Session::Http2Protocol *>(session->protocol());
        ASSERT_TRUE(protocol->is_stream_closed(stream_id));
        const auto queued_bytes = session->out().size();
        ASSERT_GT(queued_bytes, 0u);
        held.reset();
        EXPECT_EQ(post_send, request_index) << "enqueue alone is not transport completion";
        EXPECT_FALSE(weak_context.expired());
        session->stop();
        const auto written_before = session->bytes_written();
        session->start();
        session->ready_to_write();
        qb::io::async::run(EVRUN_NOWAIT);
        session->stop();
        ASSERT_EQ(session->out().size(), 0u) << "red precondition: this single write must drain entirely";
        ASSERT_EQ(session->bytes_written() - written_before, queued_bytes);
        if (externally_held) {
            EXPECT_FALSE(weak_context.expired()) << "external ownership survives transport completion";
            EXPECT_EQ(request_complete, request_index);
            externally_held.reset();
        }
        EXPECT_TRUE(weak_context.expired()) << "a completed Context must be released after eos, while the connection stays live";
        EXPECT_EQ(post_send, request_index + 1);
        EXPECT_EQ(request_complete, request_index + 1);
        static_cast<SessionBase &>(*session).on(qb::io::async::event::eos{});
        EXPECT_EQ(post_send, request_index + 1) << "a repeated drain event must not repeat the lifecycle hook";
        EXPECT_EQ(request_complete, request_index + 1);
        ASSERT_TRUE(ServerThread::pump_until([&] { return reply->replies == 1; }));
        EXPECT_EQ(reply->response.status(), qb::http::status::OK);
        EXPECT_EQ(reply->response.body().as<std::string>(), "drain-" + std::to_string(request_index));
        EXPECT_TRUE(client->is_connected());
    }
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

// QB-568: a fully dispatched request is held by real middleware. Send a
// RST_STREAM from the peer's public transport output, not a direct cancel()
// and not an incomplete POST. CANCEL is the positive control for NO_ERROR.
TEST(Http2ServerLifecycle, PeerResetNoErrorCancelsTheActiveContextWithoutClosingTheConnection) {
    using namespace http2_server_lifecycle_test;
    namespace h2 = qb::protocol::http2;
    qb::io::async::init();
    std::shared_ptr<Context>        held;
    int                             cancellations    = 0;
    int                             request_complete = 0;
    H2Server                        server;
    ClearSessionsBeforeObservations cleanup{server, held};
    auto                            group = server.router().group("/reset-owner");
    group->use(std::make_shared<PendingMiddleware>(held, cancellations));
    group->get("/hold", [](auto context) { context->text("late handler must not run"); });
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (point == qb::http::HookPoint::REQUEST_COMPLETE && context.request().uri().path() == "/reset-owner/hold")
            ++request_complete;
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    int expected_cancellations = 0;
    int expected_completions   = 0;
    for (const auto code : {h2::ErrorCode::CANCEL, h2::ErrorCode::NO_ERROR}) {
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/reset-owner/hold")}, [](auto) {}));
        ASSERT_TRUE(ServerThread::pump_until([&] { return held != nullptr; }));
        ASSERT_FALSE(held->is_completed());
        ASSERT_FALSE(held->is_cancelled());
        auto session = held->session();
        ASSERT_NE(session, nullptr);
        std::weak_ptr<Context> weak_context = held;
        const auto             stream_id    = static_cast<std::uint32_t>(held->request().stream_id);
        auto                  *protocol     = static_cast<H2Session::Http2Protocol *>(session->protocol());
        ASSERT_FALSE(protocol->is_stream_closed(stream_id));
        h2::Http2FrameData<h2::RstStreamFrame> reset;
        reset.header.type = static_cast<std::uint8_t>(h2::FrameType::RST_STREAM);
        reset.header.set_stream_id(stream_id);
        reset.payload.error_code = code;
        client->publish(reset);
        ASSERT_TRUE(ServerThread::pump_until([&] { return protocol->is_stream_closed(stream_id); }));
        ++expected_cancellations;
        EXPECT_TRUE(held->is_cancelled()) << "peer reset must reach the active Context even for NO_ERROR";
        EXPECT_TRUE(held->is_completed());
        EXPECT_EQ(cancellations, expected_cancellations);
        EXPECT_FALSE(weak_context.expired()) << "the caller still owns the cancelled Context";
        client->publish(reset); // Its duplicate is parsed before the following request on this connection.
        held->complete(qb::http::AsyncTaskResult::CONTINUE);
        EXPECT_EQ(cancellations, expected_cancellations) << "a late completion must not repeat cancellation";
        held.reset();
        EXPECT_TRUE(weak_context.expired()) << "the reset must release the session's ownership";
        ++expected_completions;
        EXPECT_EQ(request_complete, expected_completions);
        EXPECT_TRUE(client->is_connected());
        auto adjacent = std::make_shared<ReplyObservation>();
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/api/test")}, [adjacent](auto result) {
            adjacent->response = std::move(result);
            ++adjacent->replies;
        }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return adjacent->replies == 1; }));
        EXPECT_EQ(adjacent->response.status(), qb::http::status::OK);
        EXPECT_EQ(adjacent->response.body().as<std::string>(), "HTTP/2 GET Success");
        EXPECT_EQ(cancellations, expected_cancellations) << "the duplicate reset must not cancel another Context";
        EXPECT_EQ(request_complete, expected_completions);
        EXPECT_TRUE(client->is_connected());
    }
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

// A hook can finish a different native stream and recursively report eos.
// The newly queued response earns its own real drain, not the predecessor's.
TEST(Http2ServerLifecycle, DrainHookCanCompleteAnotherStreamAndReenterEos) {
    using namespace http2_server_lifecycle_test;
    qb::io::async::init();
    std::shared_ptr<Context>        first;
    std::shared_ptr<Context>        second;
    int                             first_post_send  = 0;
    int                             second_post_send = 0;
    H2Server                        server;
    ClearSessionsBeforeObservations first_cleanup{server, first};
    ClearSessionsBeforeObservations second_cleanup{server, second};
    server.router().get("/drain-first", [&](auto context) { first = std::move(context); });
    server.router().get("/drain-second", [&](auto context) { second = std::move(context); });
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (point != qb::http::HookPoint::POST_RESPONSE_SEND)
            return;
        if (context.request().uri().path() == "/drain-first") {
            ++first_post_send;
            ASSERT_NE(second, nullptr);
            second->text("second response");
            auto session = context.session();
            ASSERT_NE(session, nullptr);
            static_cast<SessionBase &>(*session).on(qb::io::async::event::eos{});
            EXPECT_EQ(first_post_send, 1);
            EXPECT_EQ(second_post_send, 0) << "the second response is still queued";
        } else if (context.request().uri().path() == "/drain-second") {
            ++second_post_send;
        }
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    auto first_reply  = std::make_shared<ReplyObservation>();
    auto second_reply = std::make_shared<ReplyObservation>();
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/drain-first")}, [first_reply](auto result) {
        first_reply->response = std::move(result);
        ++first_reply->replies;
    }));
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/drain-second")}, [second_reply](auto result) {
        second_reply->response = std::move(result);
        ++second_reply->replies;
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return first && second; }));
    auto session = first->session();
    ASSERT_NE(session, nullptr);
    ASSERT_EQ(session, second->session());
    session->stop();
    ASSERT_EQ(session->out().size(), 0u);
    auto                  *protocol    = static_cast<H2Session::Http2Protocol *>(session->protocol());
    const auto             first_id    = static_cast<std::uint32_t>(first->request().stream_id);
    const auto             second_id   = static_cast<std::uint32_t>(second->request().stream_id);
    std::weak_ptr<Context> weak_first  = first;
    std::weak_ptr<Context> weak_second = second;
    first->text("first response");
    ASSERT_TRUE(protocol->is_stream_closed(first_id));
    ASSERT_FALSE(protocol->is_stream_closed(second_id));
    const auto first_bytes = session->out().size();
    ASSERT_GT(first_bytes, 0u);
    first.reset();
    const auto written_before = session->bytes_written();
    session->start();
    session->ready_to_write();
    qb::io::async::run(EVRUN_NOWAIT);
    session->stop();
    ASSERT_EQ(session->bytes_written() - written_before, first_bytes);
    ASSERT_EQ(first_post_send, 1);
    EXPECT_TRUE(weak_first.expired());
    ASSERT_TRUE(second->is_completed());
    ASSERT_TRUE(protocol->is_stream_closed(second_id));
    const auto second_bytes = session->out().size();
    ASSERT_GT(second_bytes, 0u);
    second.reset();
    EXPECT_FALSE(weak_second.expired()) << "the session must retain the newly queued response until its drain";
    EXPECT_EQ(second_post_send, 0);
    const auto second_written_before = session->bytes_written();
    session->start();
    session->ready_to_write();
    qb::io::async::run(EVRUN_NOWAIT);
    session->stop();
    ASSERT_EQ(session->out().size(), 0u);
    ASSERT_EQ(session->bytes_written() - second_written_before, second_bytes);
    EXPECT_TRUE(weak_second.expired());
    EXPECT_EQ(first_post_send, 1);
    EXPECT_EQ(second_post_send, 1);
    ASSERT_TRUE(ServerThread::pump_until([&] { return first_reply->replies == 1 && second_reply->replies == 1; }));
    EXPECT_EQ(first_reply->response.body().as<std::string>(), "first response");
    EXPECT_EQ(second_reply->response.body().as<std::string>(), "second response");
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

// Candidate control: invoke the native reset entry directly after opening a
// real stream. The observer deletes that protocol; no framer loop or test
// expression may touch its old pointer after the call returns.
TEST(Http2ServerLifecycle, NeutralResetObserverCanClearTheActiveProtocol) {
    using namespace http2_server_lifecycle_test;
    namespace h2 = qb::protocol::http2;
    qb::io::async::init();
    std::shared_ptr<Context>        held;
    int                             cancellations   = 0;
    int                             protocol_clears = 0;
    H2Server                        server;
    ClearSessionsBeforeObservations cleanup{server, held};
    auto                            group = server.router().group("/reset-clear");
    group->use(std::make_shared<PendingMiddleware>(held, cancellations));
    group->get("/hold", [](auto context) { context->text("late handler must not run"); });
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (point != qb::http::HookPoint::POST_HANDLER_EXECUTION || !context.is_cancelled()
            || context.request().uri().path() != "/reset-clear/hold")
            return;
        auto session = context.session();
        ASSERT_NE(session, nullptr);
        context.suppress_response();
        session->clear_protocols();
        ++protocol_clears;
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/reset-clear/hold")}, [](auto) {}));
    ASSERT_TRUE(ServerThread::pump_until([&] { return held != nullptr; }));
    auto session = held->session();
    ASSERT_NE(session, nullptr);
    session->stop();
    const auto stream_id = static_cast<std::uint32_t>(held->request().stream_id);
    auto      *protocol  = static_cast<H2Session::Http2Protocol *>(session->protocol());
    ASSERT_FALSE(protocol->is_stream_closed(stream_id));
    std::weak_ptr<Context>                 weak_context = held;
    h2::Http2FrameData<h2::RstStreamFrame> reset;
    reset.header.type = static_cast<std::uint8_t>(h2::FrameType::RST_STREAM);
    reset.header.set_stream_id(stream_id);
    reset.payload.error_code = h2::ErrorCode::NO_ERROR;
    protocol->on(std::move(reset));
    EXPECT_EQ(session->protocol(), qb::io::async::no_protocol());
    EXPECT_EQ(protocol_clears, 1);
    EXPECT_EQ(cancellations, 1);
    EXPECT_TRUE(held->is_cancelled());
    EXPECT_TRUE(held->is_completed());
    held.reset();
    EXPECT_TRUE(weak_context.expired());
    session->disconnect();
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

// The same observer, reached from a reset the SERVER makes outside the read dispatch -- an application's
// reset_stream() from a timer, or from a coroutine resumed later (Huly QB-1248). The read path above re-checks the io's
// protocol after its observer; send_rst_stream() went on into the protocol the hook had destroyed (ASan: use after
// free). The session holds the io's protocol_pass() around the reset, and afterwards reads its protocol through the io:
// `_http2_protocol` is never lowered, and a second reset or a late response went through the freed object.
TEST(Http2ServerLifecycle, AResetMadeOutsideTheReadDispatchLetsItsObserverClearTheProtocols) {
    using namespace http2_server_lifecycle_test;
    qb::io::async::init();
    std::shared_ptr<Context>        held;
    int                             cancellations   = 0;
    int                             protocol_clears = 0;
    H2Server                        server;
    ClearSessionsBeforeObservations cleanup{server, held};
    auto                            group = server.router().group("/reset-out");
    group->use(std::make_shared<PendingMiddleware>(held, cancellations));
    group->get("/hold", [](auto context) { context->text("late handler must not run"); });
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (point != qb::http::HookPoint::POST_HANDLER_EXECUTION || !context.is_cancelled()
            || context.request().uri().path() != "/reset-out/hold")
            return;
        auto session = context.session();
        ASSERT_NE(session, nullptr);
        context.suppress_response();
        session->clear_protocols();
        ++protocol_clears;
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/reset-out/hold")}, [](auto) {}));
    ASSERT_TRUE(ServerThread::pump_until([&] { return held != nullptr; }));
    auto session = held->session();
    ASSERT_NE(session, nullptr);
    session->stop();
    const auto stream_id = static_cast<std::uint32_t>(held->request().stream_id);

    ASSERT_TRUE(session->reset_stream(stream_id)); // its observer cancels the context, whose hook clears the protocols
    EXPECT_EQ(session->protocol(), qb::io::async::no_protocol());
    EXPECT_EQ(protocol_clears, 1);
    EXPECT_EQ(cancellations, 1);
    EXPECT_TRUE(held->is_cancelled());

    // Nothing answers on this connection any more, and nothing reads the protocol that is gone.
    EXPECT_FALSE(session->reset_stream(stream_id));
    const auto         queued = session->appended_total(); // what the session's output ever took
    qb::http::Response late;
    late.status()  = qb::http::status::OK;
    late.stream_id = stream_id;
    late.body()    = "late";
    *session << late;
    EXPECT_EQ(session->appended_total(), queued) << "a response written once the protocols were cleared";
    EXPECT_EQ(protocol_clears, 1);

    held.reset();
    session->disconnect();
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

// A protocol installed later is not the one the session negotiated, even at the address of the one that was cleared:
// the session reads the lifetime of the object it installed, not the pointer alone -- for a reset, and for the server's
// drain, which a session switched to another protocol is out of (it counted such a session, waited for it and aborted
// it at its deadline). The replacement is as large as the session's own, the protocol and a lifetime, so an allocator
// that hands blocks back at once hands back that one. One that does not -- a sanitizer's quarantine -- leaves nothing to
// tell apart: the case says SKIPPED there, rather than pass on nothing.
TEST(Http2ServerLifecycle, AProtocolInstalledWhereTheSessionsWasIsNotTakenForIt) {
    using namespace http2_server_lifecycle_test;
    qb::io::async::init();
    std::shared_ptr<Context>        held;
    int                             cancellations = 0;
    H2Server                        server;
    ClearSessionsBeforeObservations cleanup{server, held};
    auto                            group = server.router().group("/replaced");
    group->use(std::make_shared<PendingMiddleware>(held, cancellations));
    group->get("/hold", [](auto context) { context->text("late handler must not run"); });
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (point == qb::http::HookPoint::POST_HANDLER_EXECUTION && context.is_cancelled())
            context.suppress_response();
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    std::optional<qb::http::drain_outcome> outcome;
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/replaced/hold")}, [](auto) {}));
    ASSERT_TRUE(ServerThread::pump_until([&] { return held != nullptr; }));
    auto session = held->session();
    ASSERT_NE(session, nullptr);
    session->stop();
    const auto        stream_id = static_cast<std::uint32_t>(held->request().stream_id);
    const void *const cleared   = static_cast<const void *>(static_cast<H2Session::Http2Protocol *>(session->protocol()));
    ASSERT_TRUE(session->http2_speaks_http());

    session->clear_protocols(); // outside the read dispatch: destroyed at once, its block free
    ASSERT_EQ(session->protocol(), qb::io::async::no_protocol());
    EXPECT_FALSE(session->http2_speaks_http()) << "no protocol at all";
    struct AsLargeAsTheSessionsOwn final : H2Session::Http2Protocol {
        using H2Session::Http2Protocol::Http2Protocol;
        std::shared_ptr<void> lifetime;
    };
    auto *const replacement = session->template switch_protocol<AsLargeAsTheSessionsOwn>(*session);
    ASSERT_NE(replacement, nullptr);
    if (static_cast<const void *>(static_cast<H2Session::Http2Protocol *>(replacement)) != cleared) {
        GTEST_SKIP() << "the allocator did not hand the cleared protocol's block back: nothing to tell apart";
    }
    EXPECT_FALSE(session->reset_stream(stream_id)) << "the session ran a protocol it did not install";
    EXPECT_FALSE(session->http2_speaks_http()) << "the replacement is taken for the protocol the session negotiated";
    ASSERT_TRUE(server.drain(qb::duration::zero(), [&](qb::http::drain_outcome o) { outcome = o; }));
    ASSERT_TRUE(outcome.has_value());
    EXPECT_TRUE(*outcome == qb::http::drain_outcome::drained) << "the drain waited for a session that no longer speaks HTTP";

    held.reset();
    session->disconnect();
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

// The public sweep does nothing on a session the server extracted (the third independent review's finding): the
// extraction leaves the protocol in place and the session "connected", and a caller's sweep reset a stream there and
// wrote its RST_STREAM into a session whose transport had left. Two sweeps: the first would only see the dispatch.
TEST(Http2ServerLifecycle, NeitherTheSweepNorAResetActsOnASessionTheServerExtracted) {
    using namespace http2_server_lifecycle_test;
    qb::io::async::init();
    std::shared_ptr<Context>                    held;
    std::optional<H2Session::transport_io_type> extracted;
    int                                         cancellations = 0;
    int                                         suppressed    = 0;
    H2Server                                    server;
    ClearSessionsBeforeObservations             cleanup{server, held};
    auto                                        group = server.router().group("/sweep-extracted");
    group->use(std::make_shared<PendingMiddleware>(held, cancellations));
    group->get("/hold", [](auto context) { context->text("late handler must not run"); });
    // A cancelled context answers nothing (its 503 would close the stream): the protocol keeps the stream the
    // extraction left behind, the one a later sweep could reach.
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (point != qb::http::HookPoint::POST_HANDLER_EXECUTION || !context.is_cancelled())
            return;
        context.suppress_response();
        ++suppressed;
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/sweep-extracted/hold")}, [](auto) {}));
    ASSERT_TRUE(ServerThread::pump_until([&] { return held != nullptr; }));
    auto session = held->session();
    ASSERT_NE(session, nullptr);
    const auto t0        = std::chrono::steady_clock::now();
    const auto stream_id = static_cast<std::uint32_t>(held->request().stream_id);

    auto transfer = server.extractSession(session->id());
    ASSERT_TRUE(transfer.second);
    extracted.emplace(std::move(transfer.first));
    ASSERT_TRUE(held->is_cancelled()) << "the extraction did not cancel the context: the case proves nothing";
    ASSERT_EQ(suppressed, 1) << "the cancelled context answered, its stream is gone: the case proves nothing";
    const auto before = session->appended_total();
    EXPECT_EQ(session->http2_sweep_streams(t0), 0u);
    EXPECT_EQ(session->http2_sweep_streams(t0 + 1h), 0u) << "the public sweep reset a stream of a session the server extracted";
    EXPECT_EQ(session->appended_total(), before) << "the public sweep wrote into an extracted session";
    // Nor does a reset (the fourth independent review's witness): it returned true, and wrote its RST_STREAM.
    EXPECT_FALSE(session->reset_stream(stream_id)) << "reset_stream() acted on a session the server extracted";
    EXPECT_EQ(session->appended_total(), before) << "reset_stream() wrote into an extracted session";

    session->stop();
    held.reset();
    client->disconnect();
    extracted->close();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

// The session's sweep, stepped by hand (http2_sweep_streams(now)): a request its handler has not answered has the
// session's own timeout as it is at the sweep -- none when the session has none, however long it takes, and the new
// one as soon as the session is given one. (Handed the raw 0, the sweep reset every dispatched request at its second
// look.)
TEST(Http2ServerLifecycle, ARequestItsHandlerHasNotAnsweredHasTheSessionsTimeoutAsItIsAtTheSweep) {
    using namespace http2_server_lifecycle_test;
    qb::io::async::init();
    std::shared_ptr<Context>        held;
    int                             cancellations = 0;
    H2Server                        server;
    ClearSessionsBeforeObservations cleanup{server, held};
    auto                            group = server.router().group("/sweep-out");
    group->use(std::make_shared<PendingMiddleware>(held, cancellations));
    group->get("/hold", [](auto context) { context->text("late handler must not run"); });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/sweep-out/hold")}, [](auto) {}));
    ASSERT_TRUE(ServerThread::pump_until([&] { return held != nullptr; }));
    auto session = held->session();
    ASSERT_NE(session, nullptr);
    const auto t0 = std::chrono::steady_clock::now();

    session->setTimeout(qb::duration::zero());       // no timeout: no bound for a handler
    EXPECT_EQ(session->http2_sweep_streams(t0), 0u); // the sweep that sees the dispatch
    EXPECT_EQ(session->http2_sweep_streams(t0 + 24h), 0u) << "reset on a session with no timeout";
    EXPECT_FALSE(held->is_cancelled());

    // A timeout: the bound, read at the sweep and counted on the request's own clock -- from its dispatch, a day ago.
    session->setTimeout(48h);
    EXPECT_EQ(session->http2_sweep_streams(t0 + 47h), 0u);
    EXPECT_FALSE(held->is_cancelled());
    EXPECT_EQ(session->http2_sweep_streams(t0 + 49h), 1u);
    EXPECT_TRUE(held->is_cancelled());
    EXPECT_EQ(cancellations, 1);
    EXPECT_EQ(session->http2_sweep_streams(t0 + 72h), 0u);

    held.reset();
    session->disconnect();
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

// And from a streamed response the application aborts outside the read dispatch -- what the stall watch's timer does
// (Huly QB-1212): the abort resets the stream, the reset's observer cancels the context, the hook clears the protocols.
TEST(Http2ServerLifecycle, AStreamAbortedOutsideTheReadDispatchLetsItsObserverClearTheProtocols) {
    using namespace http2_server_lifecycle_test;
    qb::io::async::init();
    std::shared_ptr<Context>        held;
    std::function<void()>           abort_stream;
    int                             protocol_clears = 0;
    H2Server                        server;
    ClearSessionsBeforeObservations cleanup{server, held};
    server.router().get("/abort-out/stream", [&](std::shared_ptr<Context> context) {
        context->response().status() = qb::http::status::OK;
        auto stream                  = context->begin_stream();
        (void) stream->write("a first piece");
        abort_stream = [stream] {
            stream->abort();
        };
        held = std::move(context);
    });
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (point != qb::http::HookPoint::POST_HANDLER_EXECUTION || !context.is_cancelled()
            || context.request().uri().path() != "/abort-out/stream")
            return;
        auto session = context.session();
        ASSERT_NE(session, nullptr);
        session->clear_protocols();
        ++protocol_clears;
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/abort-out/stream")}, [](auto) {}));
    ASSERT_TRUE(ServerThread::pump_until([&] { return held != nullptr; }));
    auto session = held->session();
    ASSERT_NE(session, nullptr);
    session->stop();
    ASSERT_TRUE(abort_stream);

    abort_stream();
    EXPECT_EQ(session->protocol(), qb::io::async::no_protocol());
    EXPECT_EQ(protocol_clears, 1);
    EXPECT_TRUE(held->is_cancelled());

    abort_stream = nullptr;
    held.reset();
    session->disconnect();
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

// And from a streamed response ended, outside the read dispatch, with a trailer section the protocol refuses -- a
// framing field in it: the refusal resets the stream, and the hook clears the protocols under end_streamed_response().
TEST(Http2ServerLifecycle, AStreamEndedWithARefusedTrailerSectionOutsideTheReadDispatchLetsItsObserverClearTheProtocols) {
    using namespace http2_server_lifecycle_test;
    qb::io::async::init();
    std::shared_ptr<Context>        held;
    std::function<void()>           end_stream;
    int                             protocol_clears = 0;
    H2Server                        server;
    ClearSessionsBeforeObservations cleanup{server, held};
    server.router().get("/end-out/stream", [&](std::shared_ptr<Context> context) {
        context->response().status() = qb::http::status::OK;
        auto stream                  = context->begin_stream();
        (void) stream->write("a first piece");
        end_stream = [stream, raw = context.get()] {
            raw->response().trailers().set_header("content-length", "13"); // never in a trailer section
            stream->end();
        };
        held = std::move(context);
    });
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (point != qb::http::HookPoint::POST_HANDLER_EXECUTION || !context.is_cancelled()
            || context.request().uri().path() != "/end-out/stream")
            return;
        auto session = context.session();
        ASSERT_NE(session, nullptr);
        session->clear_protocols();
        ++protocol_clears;
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/end-out/stream")}, [](auto) {}));
    ASSERT_TRUE(ServerThread::pump_until([&] { return held != nullptr; }));
    auto session = held->session();
    ASSERT_NE(session, nullptr);
    session->stop();
    ASSERT_TRUE(end_stream);

    end_stream();
    EXPECT_EQ(session->protocol(), qb::io::async::no_protocol());
    EXPECT_EQ(protocol_clears, 1);
    EXPECT_TRUE(held->is_cancelled());

    end_stream = nullptr;
    held.reset();
    session->disconnect();
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

TEST(Http2ServerLifecycle, DrainHookCanExtractItsSessionWithoutRetainingMapIterators) {
    using namespace http2_server_lifecycle_test;
    qb::io::async::init();
    std::shared_ptr<Context>                    first;
    std::shared_ptr<Context>                    second;
    std::optional<H2Session::transport_io_type> extracted;
    int                                         post_send        = 0;
    int                                         request_complete = 0;
    H2Server                                    server;
    ClearSessionsBeforeObservations             first_cleanup{server, first};
    ClearSessionsBeforeObservations             second_cleanup{server, second};
    server.router().get("/drain-extract-first", [&](auto context) { first = std::move(context); });
    server.router().get("/drain-extract-second", [&](auto context) { second = std::move(context); });
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (!context.request().uri().path().starts_with("/drain-extract-"))
            return;
        if (point == qb::http::HookPoint::REQUEST_COMPLETE)
            ++request_complete;
        if (point != qb::http::HookPoint::POST_RESPONSE_SEND)
            return;
        ++post_send;
        if (post_send != 1)
            return;
        auto session = context.session();
        ASSERT_NE(session, nullptr);
        auto transfer = server.extractSession(session->id());
        ASSERT_TRUE(transfer.second);
        extracted.emplace(std::move(transfer.first));
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    auto first_reply  = std::make_shared<ReplyObservation>();
    auto second_reply = std::make_shared<ReplyObservation>();
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/drain-extract-first")}, [first_reply](auto result) {
        first_reply->response = std::move(result);
        ++first_reply->replies;
    }));
    ASSERT_TRUE(
        client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/drain-extract-second")}, [second_reply](auto result) {
            second_reply->response = std::move(result);
            ++second_reply->replies;
        }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return first && second; }));
    auto session = first->session();
    ASSERT_NE(session, nullptr);
    ASSERT_EQ(session, second->session());
    session->stop();
    ASSERT_EQ(session->out().size(), 0u);
    std::weak_ptr<Context> weak_first  = first;
    std::weak_ptr<Context> weak_second = second;
    first->text("first extracted response");
    second->text("second extracted response");
    const auto queued_bytes = session->out().size();
    ASSERT_GT(queued_bytes, 0u);
    first.reset();
    second.reset();
    const auto written_before = session->bytes_written();
    session->start();
    session->ready_to_write();
    qb::io::async::run(EVRUN_NOWAIT);
    session->stop();
    ASSERT_EQ(session->bytes_written() - written_before, queued_bytes);
    ASSERT_TRUE(extracted.has_value());
    EXPECT_TRUE(server.sessions().empty());
    EXPECT_TRUE(weak_first.expired());
    EXPECT_TRUE(weak_second.expired());
    EXPECT_EQ(post_send, 1) << "extraction removes the remaining context while the first hook runs";
    EXPECT_EQ(request_complete, 2);
    ASSERT_TRUE(ServerThread::pump_until([&] { return first_reply->replies == 1 && second_reply->replies == 1; }));
    EXPECT_EQ(first_reply->response.body().as<std::string>(), "first extracted response");
    EXPECT_EQ(second_reply->response.body().as<std::string>(), "second extracted response");
    client->disconnect();
    extracted->close();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

namespace http2_server_lifecycle_test {
struct ClearSessionsBeforeContextList {
    H2Server                              &server;
    std::vector<std::shared_ptr<Context>> &held;
    ~ClearSessionsBeforeContextList() {
        held.clear();
        server.sessions().clear();
    }
};

enum class SilentCompletion { Post, RequestComplete, MemberDestructor };

// A native response may already have been sent by the application while its
// routed Context is still incomplete. Finalizing it via suppress_response()
// transfers no new bytes. Two initially complete donors make the ordering of
// their destruction observable without depending on the map's iteration order.
void
check_silent_completion_drain(SilentCompletion transition, bool observe_hooks = true,
                              std::source_location const where = std::source_location::current()) {
    qb::http::test::fail_wait::called_from const caller{where};
    qb::io::async::init();
    std::vector<std::shared_ptr<Context>> held(3);
    std::weak_ptr<Context>                silent;
    int                                   post_send         = 0;
    int                                   request_complete  = 0;
    int                                   member_cleanup    = 0;
    int                                   transitions       = 0;
    const auto                            complete_silently = [&]() {
        if (auto context = silent.lock(); context && !context->is_completed()) {
            auto session = context->session();
            ASSERT_NE(session, nullptr);
            const auto pending_bytes = session->out().size();
            context->suppress_response();
            ++transitions;
            static_cast<SessionBase &>(*session).on(qb::io::async::event::eos{});
            EXPECT_EQ(session->out().size(), pending_bytes);
        }
    };
    H2Server                       server;
    ClearSessionsBeforeContextList cleanup{server, held};
    server.router().get("/silent-drain/:index", [&](auto context) {
        const auto index = context->template path_param<std::size_t>("index");
        ASSERT_TRUE(index.has_value());
        ASSERT_LT(*index, held.size());
        // The final member release is user code even if no lifecycle hook was
        // registered. Keep this payload solely in the Context's custom data.
        context->set("member-cleanup", std::shared_ptr<int>(new int{0}, [&](int *value) {
                         delete value;
                         ++member_cleanup;
                         if (transition == SilentCompletion::MemberDestructor)
                             complete_silently();
                     }));
        held[*index] = std::move(context);
    });
    if (observe_hooks) {
        server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
            if (!context.request().uri().path().starts_with("/silent-drain/"))
                return;
            if (point == qb::http::HookPoint::POST_RESPONSE_SEND) {
                EXPECT_EQ(request_complete, post_send) << "the preceding Context must finish destruction before another POST";
                EXPECT_EQ(member_cleanup, post_send) << "member destructors finish before the next candidate";
                ++post_send;
                if (transition == SilentCompletion::Post)
                    complete_silently();
            } else if (point == qb::http::HookPoint::REQUEST_COMPLETE) {
                ++request_complete;
                if (transition == SilentCompletion::RequestComplete)
                    complete_silently();
            }
        });
    }
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    std::vector<std::shared_ptr<ReplyObservation>> replies;
    for (std::size_t index = 0; index != held.size(); ++index) {
        auto reply = std::make_shared<ReplyObservation>();
        replies.push_back(reply);
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/silent-drain/" + std::to_string(index))},
                                         [reply](auto response) {
                                             reply->response = std::move(response);
                                             ++reply->replies;
                                         }));
    }
    ASSERT_TRUE(
        ServerThread::pump_until([&] { return std::all_of(held.begin(), held.end(), [](auto &context) { return context != nullptr; }); }));
    auto session = held.front()->session();
    ASSERT_NE(session, nullptr);
    session->stop();
    ASSERT_EQ(session->out().size(), 0u);
    auto                               *protocol = static_cast<H2Session::Http2Protocol *>(session->protocol());
    std::vector<std::weak_ptr<Context>> weak;
    silent = held[1];
    for (std::size_t index = 0; index != held.size(); ++index) {
        ASSERT_EQ(held[index]->session(), session);
        weak.push_back(held[index]);
        held[index]->response().body() = "silent-" + std::to_string(index);
        if (index == 1) {
            (*session) << held[index]->response();
            ASSERT_FALSE(held[index]->is_completed());
        } else {
            held[index]->complete();
            ASSERT_TRUE(held[index]->is_completed());
        }
        ASSERT_TRUE(protocol->is_stream_closed(static_cast<std::uint32_t>(held[index]->request().stream_id)));
    }
    const auto queued_bytes = session->out().size();
    ASSERT_GT(queued_bytes, 0u);
    for (auto &context : held)
        context.reset();
    const auto written_before = session->bytes_written();
    session->start();
    session->ready_to_write();
    qb::io::async::run(EVRUN_NOWAIT);
    session->stop();
    ASSERT_EQ(session->out().size(), 0u);
    ASSERT_EQ(session->bytes_written() - written_before, queued_bytes);
    EXPECT_EQ(transitions, 1);
    EXPECT_EQ(member_cleanup, 3);
    for (auto &context : weak)
        EXPECT_TRUE(context.expired()) << "silently completed native closure must be reclaimed in the same real drain";
    if (observe_hooks) {
        EXPECT_EQ(post_send, 3);
        EXPECT_EQ(request_complete, 3);
    }
    static_cast<SessionBase &>(*session).on(qb::io::async::event::eos{});
    EXPECT_EQ(member_cleanup, 3) << "a repeated EOS has no further owner to release";
    if (observe_hooks) {
        EXPECT_EQ(post_send, 3);
    }
    ASSERT_TRUE(
        ServerThread::pump_until([&] { return std::all_of(replies.begin(), replies.end(), [](auto &reply) { return reply->replies == 1; }); }));
    for (std::size_t index = 0; index != replies.size(); ++index) {
        EXPECT_EQ(replies[index]->response.status(), qb::http::status::OK);
        EXPECT_EQ(replies[index]->response.body().as<std::string>(), "silent-" + std::to_string(index));
    }
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

void
publish_control_ping(H2Session &session) {
    namespace h2 = qb::protocol::http2;
    h2::Http2FrameData<h2::PingFrame> ping;
    ping.header.type = static_cast<std::uint8_t>(h2::FrameType::PING);
    ping.header.set_stream_id(0);
    session.publish(ping);
}
} // namespace http2_server_lifecycle_test

TEST(Http2ServerLifecycle, DrainPostCanSilentlyCompleteAnAlreadyClosedNativeStream) {
    http2_server_lifecycle_test::check_silent_completion_drain(http2_server_lifecycle_test::SilentCompletion::Post);
}

TEST(Http2ServerLifecycle, RequestCompleteCanSilentlyCompleteAnotherStreamBeforeTheNextPost) {
    http2_server_lifecycle_test::check_silent_completion_drain(http2_server_lifecycle_test::SilentCompletion::RequestComplete);
}

TEST(Http2ServerLifecycle, MemberDestructorCanSilentlyCompleteAnotherStreamBeforeTheNextPost) {
    http2_server_lifecycle_test::check_silent_completion_drain(http2_server_lifecycle_test::SilentCompletion::MemberDestructor);
}

TEST(Http2ServerLifecycle, MemberDestructorCanCompleteAnotherStreamWithoutLifecycleHooks) {
    http2_server_lifecycle_test::check_silent_completion_drain(http2_server_lifecycle_test::SilentCompletion::MemberDestructor, false);
}

TEST(Http2ServerLifecycle, DrainPostCanClearTheActiveProtocolBeforeAnotherCandidate) {
    using namespace http2_server_lifecycle_test;
    qb::io::async::init();
    std::vector<std::shared_ptr<Context>> held;
    int                                   post_send        = 0;
    int                                   request_complete = 0;
    H2Server                              server;
    ClearSessionsBeforeContextList        cleanup{server, held};
    server.router().get("/drain-post-clear", [&](auto context) { held.push_back(std::move(context)); });
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (context.request().uri().path() != "/drain-post-clear")
            return;
        if (point == qb::http::HookPoint::REQUEST_COMPLETE)
            ++request_complete;
        if (point == qb::http::HookPoint::POST_RESPONSE_SEND) {
            ++post_send;
            auto session = context.session();
            ASSERT_NE(session, nullptr);
            session->clear_protocols();
        }
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    std::vector<std::shared_ptr<ReplyObservation>> replies;
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    for (int index = 0; index != 2; ++index) {
        auto reply = std::make_shared<ReplyObservation>();
        replies.push_back(reply);
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/drain-post-clear")}, [reply](auto response) {
            reply->response = std::move(response);
            ++reply->replies;
        }));
    }
    ASSERT_TRUE(ServerThread::pump_until([&] { return held.size() == 2; }));
    auto session = held.front()->session();
    ASSERT_NE(session, nullptr);
    session->stop();
    ASSERT_EQ(session->out().size(), 0u);
    auto                               *protocol = static_cast<H2Session::Http2Protocol *>(session->protocol());
    std::vector<std::weak_ptr<Context>> weak;
    for (auto &context : held) {
        ASSERT_EQ(context->session(), session);
        weak.push_back(context);
        context->text("post cleared protocol");
        ASSERT_TRUE(protocol->is_stream_closed(static_cast<std::uint32_t>(context->request().stream_id)));
        context.reset();
    }
    const auto queued_bytes   = session->out().size();
    const auto written_before = session->bytes_written();
    ASSERT_GT(queued_bytes, 0u);
    session->start();
    session->ready_to_write();
    qb::io::async::run(EVRUN_NOWAIT);
    session->stop();
    ASSERT_EQ(session->out().size(), 0u);
    ASSERT_EQ(session->bytes_written() - written_before, queued_bytes);
    EXPECT_EQ(session->protocol(), qb::io::async::no_protocol());
    EXPECT_EQ(post_send, 1);
    EXPECT_EQ(request_complete, 1);
    EXPECT_EQ(std::count_if(weak.begin(), weak.end(), [](auto &context) { return context.expired(); }), 1);
    static_cast<SessionBase &>(*session).on(qb::io::async::event::eos{});
    EXPECT_EQ(post_send, 1) << "a cleared protocol stops a repeated drain too";
    ASSERT_TRUE(
        ServerThread::pump_until([&] { return std::all_of(replies.begin(), replies.end(), [](auto &reply) { return reply->replies == 1; }); }));
    for (auto &reply : replies) {
        EXPECT_EQ(reply->response.status(), qb::http::status::OK);
        EXPECT_EQ(reply->response.body().as<std::string>(), "post cleared protocol");
    }
    session->disconnect();
    ASSERT_TRUE(ServerThread::pump_until([&] { return server.sessions().empty(); }));
    EXPECT_EQ(request_complete, 2);
    for (auto &context : weak)
        EXPECT_TRUE(context.expired());
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

// Two valid 40-stream waves stay below the advertised native cap of 50. The
// application sends each response before silently finalizing its Context, so
// the session can retain more than 50 Contexts while native streams are closed.
// Two Contexts complete initially. Their first POST queues a real PING, so
// collection of the other must stop until that new output drains.
TEST(Http2ServerLifecycle, DrainReclaimsMoreThanFiftyContextsFromValidWavesAcrossMultipleBatches) {
    using namespace http2_server_lifecycle_test;
    qb::io::async::init();
    std::vector<std::shared_ptr<Context>> held;
    int                                   post_send        = 0;
    int                                   request_complete = 0;
    H2Server                              server;
    ClearSessionsBeforeContextList        cleanup{server, held};
    server.router().get("/drain-wave", [&](auto context) { held.push_back(std::move(context)); });
    server.router().add_lifecycle_hook([&](auto &context, qb::http::HookPoint point) {
        if (context.request().uri().path() != "/drain-wave")
            return;
        if (point == qb::http::HookPoint::REQUEST_COMPLETE)
            ++request_complete;
        if (point == qb::http::HookPoint::POST_RESPONSE_SEND && ++post_send == 1) {
            auto session = context.session();
            ASSERT_NE(session, nullptr);
            publish_control_ping(*session);
        }
    });
    server.router().compile();
    ASSERT_TRUE(configure_owner_loop(server));
    std::vector<std::shared_ptr<ReplyObservation>> replies;
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    client->set_max_concurrent_streams(40);
    std::vector<std::weak_ptr<Context>> weak;
    std::shared_ptr<H2Session>          session;
    for (std::size_t wave = 0; wave != 2; ++wave) {
        if (session)
            session->start();
        for (int index = 0; index != 40; ++index) {
            auto reply = std::make_shared<ReplyObservation>();
            replies.push_back(reply);
            ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("/drain-wave")}, [reply](auto response) {
                reply->response = std::move(response);
                ++reply->replies;
            }));
        }
        const auto wave_end = (wave + 1) * 40;
        ASSERT_TRUE(ServerThread::pump_until([&] { return held.size() == wave_end; }));
        session = held.back()->session();
        ASSERT_NE(session, nullptr);
        session->stop();
        ASSERT_EQ(session->out().size(), 0u);
        auto *protocol = static_cast<H2Session::Http2Protocol *>(session->protocol());
        for (auto index = wave * 40; index != wave_end; ++index) {
            ASSERT_EQ(held[index]->session(), session);
            ASSERT_FALSE(held[index]->is_completed());
            weak.push_back(held[index]);
            held[index]->response().body() = "wave-" + std::to_string(index);
            if (index < 2)
                held[index]->complete();
            else
                (*session) << held[index]->response();
            ASSERT_TRUE(protocol->is_stream_closed(static_cast<std::uint32_t>(held[index]->request().stream_id)));
        }
        if (wave == 0) {
            held.front().reset();
            held[1].reset();
        }
        const auto queued_bytes   = session->out().size();
        const auto written_before = session->bytes_written();
        ASSERT_GT(queued_bytes, 0u);
        session->start();
        session->ready_to_write();
        qb::io::async::run(EVRUN_NOWAIT);
        session->stop();
        ASSERT_EQ(session->bytes_written() - written_before, queued_bytes);
        EXPECT_EQ(post_send, wave == 0 ? 1 : 2);
        EXPECT_EQ(request_complete, wave == 0 ? 1 : 2);
        if (wave == 0) {
            EXPECT_EQ(std::count_if(weak.begin(), weak.begin() + 2, [](auto &context) { return context.expired(); }), 1);
            const auto ping_bytes = session->out().size();
            ASSERT_EQ(ping_bytes, qb::protocol::http2::FRAME_HEADER_SIZE + 8u);
            const auto ping_written_before = session->bytes_written();
            session->start();
            session->ready_to_write();
            qb::io::async::run(EVRUN_NOWAIT);
            session->stop();
            ASSERT_EQ(session->bytes_written() - ping_written_before, ping_bytes);
            EXPECT_EQ(post_send, 2);
            EXPECT_EQ(request_complete, 2);
            EXPECT_TRUE(weak[0].expired());
            EXPECT_TRUE(weak[1].expired());
        }
        ASSERT_EQ(session->out().size(), 0u);
        ASSERT_TRUE(ServerThread::pump_until(
            [&] { return std::all_of(replies.begin(), replies.end(), [](auto &reply) { return reply->replies == 1; }); }));
        EXPECT_EQ(client->get_active_request_count(), 0u);
    }
    ASSERT_EQ(weak.size(), 80u);
    for (std::size_t index = 2; index != held.size(); ++index) {
        ASSERT_FALSE(held[index]->is_completed());
        held[index]->suppress_response();
        held[index].reset();
        ASSERT_FALSE(weak[index].expired()) << "the session alone retains each completed Context before the final drain";
    }
    EXPECT_EQ(post_send, 2);
    EXPECT_EQ(request_complete, 2);
    ASSERT_EQ(session->out().size(), 0u);
    publish_control_ping(*session);
    const auto queued_bytes   = session->out().size();
    const auto written_before = session->bytes_written();
    ASSERT_EQ(queued_bytes, qb::protocol::http2::FRAME_HEADER_SIZE + 8u);
    session->start();
    session->ready_to_write();
    qb::io::async::run(EVRUN_NOWAIT);
    session->stop();
    ASSERT_EQ(session->out().size(), 0u);
    ASSERT_EQ(session->bytes_written() - written_before, queued_bytes);
    EXPECT_EQ(post_send, 80);
    EXPECT_EQ(request_complete, 80);
    for (auto &context : weak)
        EXPECT_TRUE(context.expired());
    static_cast<SessionBase &>(*session).on(qb::io::async::event::eos{});
    EXPECT_EQ(post_send, 80);
    EXPECT_EQ(request_complete, 80);
    for (std::size_t index = 0; index != replies.size(); ++index) {
        EXPECT_EQ(replies[index]->response.status(), qb::http::status::OK);
        EXPECT_EQ(replies[index]->response.body().as<std::string>(), "wave-" + std::to_string(index));
    }
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    ServerThread::pump_until([&] { return !client->is_connected(); });
}

// ===========================================================================
// An explicit disconnect() announces the close (RFC 9113 §6.8): the peer reads
// GOAWAY(NO_ERROR) before the end of the connection (Huly QB-1059). A peer that
// has stopped reading cannot hold the close: it ends within the flush limit.
// Both run against a minimal TLS + h2 peer whose reads the test controls.
// ===========================================================================
namespace http2_client_goaway_test {

/// One-connection TLS + h2 peer on its own thread (non-blocking sockets, polled, every wait bounded):
/// it negotiates ALPN h2, answers the client's SETTINGS with its own -- in Silent mode a 2^31-1 initial
/// window and connection window, so the client can queue far more than the socket buffers hold -- and
/// then records every frame until EOF (Reading) or stops reading once its SETTINGS are acknowledged
/// (Silent) until released. Once the client's GOAWAY has arrived, the end of the connection is read
/// from the socket itself, so a clean EOF (the client's FIN) and a reset are told apart. Silent also
/// accepts the client's next connection and completes its TLS handshake, so the moment the client
/// reconnects after a disconnect() -- after its previous transport was disposed -- is observable.
class RawH2Peer {
public:
    enum class Mode { Reading, Silent };
    struct Frame {
        uint8_t              type      = 0;
        uint8_t              flags     = 0;
        uint32_t             stream_id = 0;
        std::vector<uint8_t> payload;
    };

    explicit RawH2Peer(Mode mode)
        : _mode(mode) {
        _listener.init(qb::io::ssl::Context::server(qb::http::test::ssl_cert_path(), qb::http::test::ssl_key_path()).alpn({"h2"}));
        if (_listener.listen_v4(0, "127.0.0.1") != 0) {
            return;
        }
        _listener.set_nonblocking(true);
        _port   = _listener.local_endpoint().port();
        _thread = std::thread([this] { run(); });
    }
    ~RawH2Peer() {
        _release = true;
        if (_thread.joinable()) {
            _thread.join();
        }
    }
    RawH2Peer(const RawH2Peer &)            = delete;
    RawH2Peer &operator=(const RawH2Peer &) = delete;

    [[nodiscard]] uint16_t
    port() const noexcept {
        return _port;
    }
    /// The client acknowledged the peer's SETTINGS: it has applied them.
    [[nodiscard]] bool
    settings_acked() const noexcept {
        return _settings_acked.load();
    }
    [[nodiscard]] bool
    eof() const noexcept {
        return _eof.load();
    }
    /// The connection ended with a reset (ECONNRESET), not the client's FIN.
    [[nodiscard]] bool
    reset() const noexcept {
        return _reset.load();
    }
    /// Ask the peer to send the client a PING (frames the client will have left unread if it stops
    /// reading before they are processed).
    void
    send_ping() noexcept {
        _ping_requested = true;
    }
    [[nodiscard]] bool
    ping_sent() const noexcept {
        return _ping_sent.load();
    }
    [[nodiscard]] std::vector<Frame>
    frames() const {
        std::lock_guard lock(_mutex);
        return _frames;
    }
    [[nodiscard]] std::size_t
    count(uint8_t type) const {
        std::lock_guard lock(_mutex);
        return static_cast<std::size_t>(std::count_if(_frames.begin(), _frames.end(), [&](const Frame &f) { return f.type == type; }));
    }

private:
    static void
    append_frame(std::vector<uint8_t> &out, uint8_t type, uint8_t flags, uint32_t stream_id, const std::vector<uint8_t> &payload) {
        const auto n = static_cast<uint32_t>(payload.size());
        out.insert(out.end(), {static_cast<uint8_t>(n >> 16), static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n), type, flags,
                               static_cast<uint8_t>(stream_id >> 24), static_cast<uint8_t>(stream_id >> 16),
                               static_cast<uint8_t>(stream_id >> 8), static_cast<uint8_t>(stream_id)});
        out.insert(out.end(), payload.begin(), payload.end());
    }

    bool
    write_all(qb::io::tcp::ssl::socket &sock, const std::vector<uint8_t> &bytes) {
        std::size_t off    = 0;
        bool        failed = false;
        // Each look writes what the socket takes: all of it, a failure, or a socket that takes no more for now.
        qb::http::test::peer_wait_until(
            [&] {
                while (off < bytes.size() && !_release) {
                    const int n = sock.write(bytes.data() + off, bytes.size() - off);
                    if (n < 0) {
                        failed = true;
                        return true;
                    }
                    if (n == 0) {
                        return false;
                    }
                    off += static_cast<std::size_t>(n);
                }
                return true;
            },
            qb::http::test::fail_wait::never);
        return !failed && off == bytes.size();
    }

    void
    run() {
        const auto               deadline = std::chrono::steady_clock::now() + 30s;
        qb::io::tcp::ssl::socket sock;
        qb::http::test::peer_wait_until([&] { return _release || (_listener.accept(sock) == 0 && sock.is_open()); }, deadline);
        if (!sock.is_open()) {
            return;
        }
        sock.set_nonblocking(true);

        constexpr std::size_t    preface_size = 24;
        std::vector<uint8_t>     in;
        bool                     preface_seen = false;
        bool                     answered     = false;
        char                     buffer[16384];
        bool                     goaway_seen = false;
        qb::io::tcp::ssl::socket next;         // Silent: the client's next connection
        bool                     quit = false; // a write failed: the peer's thread ends there
        qb::http::test::peer_wait_until(
            [&] {
                if (_release)
                    return true;
                if (_ping_requested && !_ping_sent && answered) {
                    std::vector<uint8_t> ping;
                    append_frame(ping, 0x6, 0, 0, {1, 2, 3, 4, 5, 6, 7, 8});
                    if (!write_all(sock, ping)) {
                        _eof = true;
                        return true;
                    }
                    _ping_sent = true;
                }
                if (_mode == Mode::Silent && _settings_acked) {
                    // Reads nothing more on this connection: the client's sends pile up. Its next
                    // connection is accepted and its TLS handshake driven.
                    if (!next.is_open()) {
                        if (_listener.accept(next) == 0 && next.is_open()) {
                            next.set_nonblocking(true);
                        }
                    } else {
                        static_cast<void>(next.read(buffer, sizeof(buffer)));
                    }
                    std::this_thread::sleep_for(1ms);
                    return false;
                }
                if (goaway_seen) {
                    // The client's GOAWAY is in: what ends the connection is read from the socket itself
                    // -- 0, the client's FIN; an error, a reset. A FIN followed by a reset still reads 0, so
                    // the peer then answers with its own GOAWAY, twice: a client that only shut its sending
                    // side down still receives it, one that closed its socket resets it.
                    const auto raw = ::recv(sock.native_handle(), buffer, static_cast<int>(sizeof(buffer)), 0);
                    if (raw == 0) {
                        std::vector<uint8_t> reply;
                        append_frame(reply, 0x7, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0});
                        int attempt = 0; // two at most, 20 ms before each
                        qb::http::test::peer_wait_until([&] { return attempt == 2 || _reset; }, qb::http::test::fail_wait::never,
                                                        [&] {
                                                            std::this_thread::sleep_for(20ms);
                                                            _reset = !write_all(sock, reply);
                                                            ++attempt;
                                                        });
                        _eof = true;
                        return true;
                    }
                    if (raw < 0) {
                        const int err = qb::io::socket::get_last_errno();
                        if (qb::io::socket::not_recv_error(err)) {
                            std::this_thread::sleep_for(1ms);
                            return false;
                        }
                        _reset = true;
                        _eof   = true;
                        return true;
                    }
                    return false; // a TLS record after the GOAWAY: ignored
                }
                const int n = sock.read(buffer, sizeof(buffer));
                if (n < 0) {
                    _eof = true;
                    return true;
                }
                if (n == 0) {
                    std::this_thread::sleep_for(1ms);
                    return false;
                }
                in.insert(in.end(), buffer, buffer + n);
                if (!preface_seen) {
                    if (in.size() < preface_size) {
                        return false;
                    }
                    in.erase(in.begin(), in.begin() + preface_size);
                    preface_seen = true;
                }
                std::vector<uint8_t> reply; // written once the frames of this read are taken in: the loop over them waits for nothing
                while (in.size() >= 9) {
                    const std::size_t length = (std::size_t{in[0]} << 16) | (std::size_t{in[1]} << 8) | in[2];
                    if (in.size() < 9 + length) {
                        break;
                    }
                    Frame f;
                    f.type      = in[3];
                    f.flags     = in[4];
                    f.stream_id = ((uint32_t{in[5]} << 24) | (uint32_t{in[6]} << 16) | (uint32_t{in[7]} << 8) | in[8]) & 0x7FFFFFFFu;
                    f.payload.assign(in.begin() + 9, in.begin() + 9 + static_cast<std::ptrdiff_t>(length));
                    in.erase(in.begin(), in.begin() + 9 + static_cast<std::ptrdiff_t>(length));
                    if (f.type == 0x4 && (f.flags & 0x1)) {
                        _settings_acked = true;
                    } else if (f.type == 0x7) {
                        goaway_seen = true;
                    } else if (f.type == 0x4 && !answered) {
                        if (_mode == Mode::Silent) {
                            append_frame(reply, 0x4, 0, 0, {0x00, 0x04, 0x7F, 0xFF, 0xFF, 0xFF}); // INITIAL_WINDOW_SIZE 2^31-1
                            const uint32_t inc = 0x7FFFFFFFu - 65535u;
                            append_frame(reply, 0x8, 0, 0,
                                         {static_cast<uint8_t>(inc >> 24), static_cast<uint8_t>(inc >> 16), static_cast<uint8_t>(inc >> 8),
                                          static_cast<uint8_t>(inc)}); // connection window 2^31-1
                        } else {
                            append_frame(reply, 0x4, 0, 0, {});
                        }
                        append_frame(reply, 0x4, 0x1, 0, {}); // SETTINGS ACK
                        answered = true;
                    }
                    std::lock_guard lock(_mutex);
                    _frames.push_back(std::move(f));
                }
                if (!reply.empty() && !write_all(sock, reply)) {
                    _eof = true;
                    quit = true;
                    return true;
                }
                return false;
            },
            deadline, qb::http::test::fail_wait::no_turn{});
        if (quit)
            return;
        qb::http::test::peer_wait_until([this] { return _release.load(); }, deadline); // Silent: hold the connection until released
        sock.disconnect();
        sock.close();
    }

    Mode                       _mode;
    qb::io::tcp::ssl::listener _listener;
    uint16_t                   _port = 0;
    std::atomic<bool>          _release{false};
    std::atomic<bool>          _settings_acked{false};
    std::atomic<bool>          _eof{false};
    std::atomic<bool>          _reset{false};
    std::atomic<bool>          _ping_requested{false};
    std::atomic<bool>          _ping_sent{false};
    mutable std::mutex         _mutex;
    std::vector<Frame>         _frames;
    std::thread                _thread;
};

class Http2ClientGoawayTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "the HTTP/2 client system suite REQUIRES the TLS test certificates";
        qb::io::async::init();
    }

    [[nodiscard]] static std::shared_ptr<qb::http2::Client>
    make_client(uint16_t port) {
        auto client = qb::http2::make_client("https://localhost:" + std::to_string(port));
        client->set_verify_peer(false);
        client->set_connect_timeout(5s);
        return client;
    }
};

TEST_F(Http2ClientGoawayTest, ExplicitDisconnectSendsGoawayBeforeClosing) {
    RawH2Peer peer(RawH2Peer::Mode::Reading);
    ASSERT_NE(peer.port(), 0);
    bool                              connected = false;
    std::optional<qb::http::Response> response;
    auto                              client = make_client(peer.port());
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected && peer.settings_acked(); }));

    qb::http::Request request; // one the peer never answers
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/pending");
    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) { response = std::move(r); }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return peer.count(0x1) == 1; })); // its HEADERS arrived

    client->disconnect();
    ASSERT_TRUE(response.has_value()) << "the outstanding request fails at once";
    EXPECT_EQ(response->status(), qb::http::status::SERVICE_UNAVAILABLE);

    ASSERT_TRUE(ServerThread::pump_until([&] { return peer.eof(); }));
    const auto frames = peer.frames();
    ASSERT_FALSE(frames.empty());
    const auto &last = frames.back();
    ASSERT_EQ(last.type, 0x7) << "the connection ended without a GOAWAY";
    ASSERT_GE(last.payload.size(), 8u);
    const uint32_t last_stream_id =
        ((uint32_t{last.payload[0]} << 24) | (uint32_t{last.payload[1]} << 16) | (uint32_t{last.payload[2]} << 8) | last.payload[3])
        & 0x7FFFFFFFu;
    const uint32_t error_code =
        (uint32_t{last.payload[4]} << 24) | (uint32_t{last.payload[5]} << 16) | (uint32_t{last.payload[6]} << 8) | last.payload[7];
    EXPECT_EQ(error_code, 0u) << "NO_ERROR";
    EXPECT_EQ(last_stream_id, 0u) << "a client's last-stream-id names server-initiated streams: none were accepted";
    EXPECT_EQ(last.stream_id, 0u);
    EXPECT_FALSE(peer.reset()) << "the connection ended with a reset, not the client's FIN";
}

// The server's own bytes may still sit unread in the client's socket when it closes -- here a PING
// that arrives after the client stopped reading. The connection must still end with the GOAWAY then
// the client's FIN: qb-io ends a connection the object ended by shutting its sending side down (Huly
// QB-1060), and the client no longer closes the socket outright on dispose, which, with those bytes
// unread, made the kernel answer with a reset (Huly QB-1021, QB-1059).
TEST_F(Http2ClientGoawayTest, ExplicitDisconnectEndsWithGoawayThenEofEvenWithUnreadServerBytes) {
    RawH2Peer peer(RawH2Peer::Mode::Reading);
    ASSERT_NE(peer.port(), 0);
    bool connected = false;
    auto client    = make_client(peer.port());
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected && peer.settings_acked(); }));

    // The PING reaches the client's socket while its loop does not run: it stays unread.
    peer.send_ping();
    qb::http::test::expect_until([&] { return peer.ping_sent(); }, 5s, "wait_until", qb::http::test::fail_wait::nap{1ms});
    ASSERT_TRUE(peer.ping_sent());
    std::this_thread::sleep_for(50ms);

    client->disconnect();
    ASSERT_TRUE(ServerThread::pump_until([&] { return peer.eof(); }));
    const auto frames = peer.frames();
    ASSERT_FALSE(frames.empty());
    EXPECT_EQ(frames.back().type, 0x7) << "the GOAWAY, then the end of the connection";
    EXPECT_FALSE(peer.reset()) << "the connection ended with a reset: the client closed with the server's bytes unread";
}

TEST_F(Http2ClientGoawayTest, DisconnectFromAPeerThatStoppedReadingClosesWithinTheFlushLimit) {
    RawH2Peer peer(RawH2Peer::Mode::Silent);
    ASSERT_NE(peer.port(), 0);
    bool connected   = false;
    bool reconnected = false;
    auto client      = make_client(peer.port());
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected && peer.settings_acked(); }));

    // The windows allow 2^31-1: the whole body is framed at once, far more than the socket buffers hold.
    qb::http::Request request;
    request.method() = qb::http::Method::POST;
    request.uri()    = qb::io::uri("/upload");
    request.body()   = std::string(32u << 20, 'u');
    ASSERT_TRUE(client->push_request(std::move(request), [](qb::http::Response) {}));
    const auto settle = std::chrono::steady_clock::now() + 300ms;
    while (std::chrono::steady_clock::now() < settle) {
        qb::io::async::run(EVRUN_NOWAIT); // the io writes until the socket refuses
    }
    ASSERT_GT(client->out().size(), 0u) << "the socket buffers absorbed the whole body: nothing would wait for the peer";

    // A connect() asked while the transport closes starts once its dispose() has run: the moment
    // the client reconnects is the moment the close was done.
    const auto started = std::chrono::steady_clock::now();
    client->disconnect();
    client->connect([&](bool ok, const std::string &) { reconnected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return reconnected; }, 10s)) << "a peer that stopped reading held the close";
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_GE(elapsed, qb::http2::Client::GOAWAY_FLUSH_LIMIT - 100ms) << "the GOAWAY was given its chance to be delivered";
    EXPECT_LE(elapsed, qb::http2::Client::GOAWAY_FLUSH_LIMIT + 2s) << "the close is bounded by the flush limit";
}

} // namespace http2_client_goaway_test

// ===========================================================================
// A request whose `Trailer` header announces a field it sets ends with that
// field as its trailer section as soon as the body is out -- here a body that
// fits the windows at once. The trailer block used to wait for a WINDOW_UPDATE
// the server had no reason to send: the request never ended and never got its
// response (Huly QB-1061).
// ===========================================================================
namespace http2_client_trailers_test {

TEST_F(Http2ClientTest, RequestSettingItsAnnouncedTrailersCompletesOnce) {
    std::optional<qb::http::Response> response;
    int                               calls  = 0;
    auto                              client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::POST;
    request.uri()    = qb::io::uri("/api/data");
    request.body()   = R"({"t":1})";
    request.set_header("trailer", "X-Checksum");
    request.set_header("x-checksum", "cafe");

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response = std::move(r);
        ++calls;
    }));
    client->connect(nullptr);

    ASSERT_TRUE(ServerThread::pump_until([&] { return response.has_value(); })) << "the request never ended";
    EXPECT_EQ(response->status(), qb::http::status::CREATED);
    EXPECT_EQ(response->body().template as<std::string>(), R"(Data received: {"t":1} - created successfully)");
    for (int pass = 0; pass < 20; ++pass) {
        qb::io::async::run(EVRUN_NOWAIT);
    }
    EXPECT_EQ(calls, 1);
    client->disconnect();
}

// The high-level client never calls send_request_trailers(): a request that
// announces trailers without setting them ends its stream once the body is out,
// with an empty trailer block, rather than waiting for its request timeout. The
// protocol keeps that stream open for send_request_trailers(), and the client
// used to inherit it: the request never ended (Huly QB-1061).
TEST_F(Http2ClientTest, RequestAnnouncingUnsetTrailersCompletesPromptly) {
    std::optional<qb::http::Response> response;
    int                               calls  = 0;
    auto                              client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::POST;
    request.uri()    = qb::io::uri("/api/data");
    request.body()   = R"({"t":2})";
    request.set_header("trailer", "X-Checksum"); // announced, never set

    ASSERT_TRUE(client->push_request(request, [&](qb::http::Response r) {
        response = std::move(r);
        ++calls;
    }));
    client->connect(nullptr);

    const auto started = std::chrono::steady_clock::now();
    ASSERT_TRUE(ServerThread::pump_until([&] { return response.has_value(); })) << "the request waited for trailers no one would send";
    EXPECT_LT(std::chrono::steady_clock::now() - started, 2s) << "completed by the body, not by a timeout";
    EXPECT_EQ(response->status(), qb::http::status::CREATED);
    EXPECT_EQ(response->body().template as<std::string>(), R"(Data received: {"t":2} - created successfully)");
    for (int pass = 0; pass < 20; ++pass) {
        qb::io::async::run(EVRUN_NOWAIT);
    }
    EXPECT_EQ(calls, 1);
    client->disconnect();
}

} // namespace http2_client_trailers_test

// ===========================================================================
// A response stream on HTTP/2 through the module's own client (Huly QB-86). The HTTP/2 session offers the streaming
// hooks since train 6: begin_stream() sends the HEADERS at once and each piece as DATA frames (`end_of_stream`
// framing: no Transfer-Encoding, END_STREAM at end()), and a handler written for HTTP/1.1 runs unchanged. The stream
// owns the completion here too: a coroutine handler that hands its stream to a timer chain and returns is not answered
// under it. An application cancel() or an abort() under a streamed head resets THE STREAM (RST_STREAM INTERNAL_ERROR),
// which this client reports as 502 -- never the connection, which serves the next request. The frame-level witnesses
// (arrival before end(), windows, RST_STREAM, GOAWAY, HEAD, trailers) are system/http2/http2-response-stream.cpp's.
// ===========================================================================
namespace http2_response_stream_test {

class StreamH2Server;

class StreamH2Session : public qb::http2::use<StreamH2Session>::session<StreamH2Server> {
public:
    explicit StreamH2Session(StreamH2Server &server)
        : session(server) {}
};

using StreamCtx = qb::http::Context<StreamH2Session>;
using H2Stream  = qb::http::ResponseStream<StreamH2Session>;

static_assert(qb::http::streaming_session<StreamH2Session>, "the HTTP/2 session streams since Huly QB-86's train-6 lot");

inline std::atomic<int> g_h2_framing{-1};

/// `n` pieces, one per event-loop turn (1 ms apart), then end().
void
h2_pieces(std::shared_ptr<H2Stream> stream, int i, int n) {
    if (i == n) {
        stream->end();
        return;
    }
    (void) stream->write("piece-" + std::to_string(i) + ";");
    qb::io::async::callback([stream = std::move(stream), i, n]() mutable { h2_pieces(std::move(stream), i + 1, n); }, 1ms);
}

class StreamH2Server : public qb::http2::use<StreamH2Server>::server<StreamH2Session> {
public:
    StreamH2Server() {
        router().get("/stream/handoff", [](std::shared_ptr<StreamCtx> ctx) -> qb::io::async::task<void> {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Type", "text/plain");
            auto stream  = ctx->begin_stream();
            g_h2_framing = static_cast<int>(stream->framing());
            (void) stream->write("piece-0;");
            h2_pieces(std::move(stream), 1, 4);
            co_return;
        });
        router().get("/stream/cancel", [](std::shared_ptr<StreamCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "64");
            ctx->response().set_header("Content-Encoding", "gzip");
            ctx->response().set_header("Content-Type", "application/json");
            auto stream  = ctx->begin_stream();
            g_h2_framing = static_cast<int>(stream->framing());
            (void) stream->write("never whole");
            ctx->cancel("cancelled before the end");
        });
        router().get("/stream/abort", [](std::shared_ptr<StreamCtx> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "64");
            auto stream  = ctx->begin_stream();
            g_h2_framing = static_cast<int>(stream->framing());
            (void) stream->write("never whole");
            stream->abort();
        });
        router().get("/plain", [](std::shared_ptr<StreamCtx> ctx) { ctx->text("still served"); });
        router().compile();
    }
};

class Http2ResponseStreamTest : public ::testing::Test {
protected:
    std::uint16_t                                                 _port{0};
    std::unique_ptr<qb::http::test::ServerThread<StreamH2Server>> _server;

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "Missing TLS test certificates (" << qb::http::test::ssl_cert_path() << ")";
        qb::io::async::init();
        g_h2_framing           = -1;
        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();
        _server                = std::make_unique<qb::http::test::ServerThread<StreamH2Server>>([cert, key](StreamH2Server &srv) -> bool {
            srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(_server->ready());
        _port = _server->port();
        ASSERT_NE(_port, 0);
    }

    void
    TearDown() override {
        _server.reset();
    }

    /// `first`, then `second` on the same connection once `first` is answered: the connection outlives a reset stream.
    [[nodiscard]] std::pair<qb::http::Response, qb::http::Response>
    get_twice(std::string const &first, std::string const &second, std::source_location const where = std::source_location::current()) const {
        qb::http::test::fail_wait::called_from const caller{where};
        auto                                         client = qb::http2::make_client("https://localhost:" + std::to_string(_port));
        client->set_verify_peer(false);
        client->set_connect_timeout(5s);
        std::optional<qb::http::Response> r1, r2;
        qb::http::Request                 request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri(first);
        EXPECT_TRUE(client->push_request(request, [&](qb::http::Response r) { r1 = std::move(r); }));
        client->connect(nullptr);
        EXPECT_TRUE(qb::http::test::ServerThread<StreamH2Server>::pump_until([&] { return r1.has_value(); }));
        if (!second.empty()) {
            request.uri() = qb::io::uri(second);
            EXPECT_TRUE(client->push_request(request, [&](qb::http::Response r) { r2 = std::move(r); }));
            EXPECT_TRUE(qb::http::test::ServerThread<StreamH2Server>::pump_until([&] { return r2.has_value(); }));
        }
        client->disconnect();
        return {r1.value_or(qb::http::Response{}), r2.value_or(qb::http::Response{})};
    }

    [[nodiscard]] qb::http::Response
    get(std::string const &path, std::source_location const where = std::source_location::current()) const {
        qb::http::test::fail_wait::called_from const caller{where};
        return get_twice(path, "").first;
    }
};

TEST_F(Http2ResponseStreamTest, AStreamIsSentAsDataFramesAndOwnsItsCompletion) {
    const auto response = get("/stream/handoff");
    EXPECT_EQ(g_h2_framing.load(), static_cast<int>(qb::http::stream_framing::end_of_stream));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_TRUE(response.header("Transfer-Encoding").empty()) << "no coding on HTTP/2: " << response.header("Transfer-Encoding");
    EXPECT_TRUE(response.header("Content-Length").empty()) << "no length: the end of the stream delimits the body";
    EXPECT_EQ(response.body().template as<std::string>(), "piece-0;piece-1;piece-2;piece-3;")
        << "the response ended at end(), not when the handler returned";
}

TEST_F(Http2ResponseStreamTest, ACancelledStreamResetsItsStreamAndTheConnectionServesOn) {
    const auto [cancelled, next] = get_twice("/stream/cancel", "/plain");
    EXPECT_EQ(g_h2_framing.load(), static_cast<int>(qb::http::stream_framing::content_length));
    EXPECT_EQ(cancelled.status(), qb::http::status::BAD_GATEWAY) << "the head left, the stream was reset (RST_STREAM), not the connection";
    EXPECT_EQ(next.status(), qb::http::status::OK);
    EXPECT_EQ(next.body().template as<std::string>(), "still served");
}

TEST_F(Http2ResponseStreamTest, AnAbortedStreamResetsItsStreamAndTheConnectionServesOn) {
    const auto [aborted, next] = get_twice("/stream/abort", "/plain");
    EXPECT_EQ(g_h2_framing.load(), static_cast<int>(qb::http::stream_framing::content_length));
    EXPECT_EQ(aborted.status(), qb::http::status::BAD_GATEWAY) << "a declared length never reached: the stream is reset";
    EXPECT_EQ(next.status(), qb::http::status::OK);
}

} // namespace http2_response_stream_test

// ===========================================================================
// Static files over HTTP/2 stream (Huly QB-101, QB-86): the HTTP/2 session offers the streaming hooks since train 6, so a
// body over StaticFilesOptions::stream_threshold is served through a stream, never materialised, and max_file_size --
// the bound of a body read whole -- no longer bounds it, exactly as on HTTP/1.1 (system/middleware/static-files-stream.cpp).
// ===========================================================================
namespace http2_static_files_test {

class StaticH2Server;

class StaticH2Session : public qb::http2::use<StaticH2Session>::session<StaticH2Server> {
public:
    explicit StaticH2Session(StaticH2Server &server)
        : session(server) {}
};

class StaticH2Server : public qb::http2::use<StaticH2Server>::server<StaticH2Session> {};

static_assert(qb::http::streaming_session<StaticH2Session>, "the HTTP/2 session streams since Huly QB-86's train-6 lot");

/// A temporary directory removed with its scope, an early failure included.
struct TempRoot {
    std::filesystem::path path;
    explicit TempRoot(std::string const &prefix)
        : path(std::filesystem::temp_directory_path()
               / (prefix + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()))) {
        std::filesystem::create_directories(path);
    }
    ~TempRoot() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
};

TEST(Http2StaticFilesTest, ABodyOverTheStreamThresholdStreamsAndMaxFileSizeNoLongerBoundsIt) {
    ASSERT_TRUE(qb::http::test::certs_available()) << "Missing TLS test certificates (" << qb::http::test::ssl_cert_path() << ")";
    qb::io::async::init();
    const TempRoot temp("qbm-h2-static-");
    const auto    &root = temp.path;
    ASSERT_TRUE(std::filesystem::is_directory(root));
    std::string whole(std::size_t{512} * 1024, '\0');
    for (std::size_t i = 0; i < whole.size(); ++i)
        whole[i] = static_cast<char>((i * 131 + i / 251) & 0xff);
    {
        std::ofstream(root / "whole.bin", std::ios::binary).write(whole.data(), static_cast<std::streamsize>(whole.size()));
        std::ofstream(root / "over.bin", std::ios::binary) << std::string(std::size_t{2} * 1024 * 1024, 'o');
    }
    const std::string cert = qb::http::test::ssl_cert_path().string();
    const std::string key  = qb::http::test::ssl_key_path().string();
    const auto        opts =
        qb::http::StaticFilesOptions(root).with_stream_threshold(std::size_t{64} * 1024).with_max_file_size(std::size_t{1024} * 1024);
    auto server = std::make_unique<qb::http::test::ServerThread<StaticH2Server>>([cert, key, opts](StaticH2Server &srv) -> bool {
        srv.router().use(qb::http::static_files_middleware<StaticH2Session>(opts));
        srv.router().compile();
        srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        srv.start();
        return true;
    });
    ASSERT_TRUE(server->ready());
    const auto port = server->port();

    const auto get = [port](std::string const &path, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        std::optional<qb::http::Response>            response;
        auto                                         client = qb::http2::make_client("https://localhost:" + std::to_string(port));
        client->set_verify_peer(false);
        client->set_connect_timeout(5s);
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri(path);
        EXPECT_TRUE(client->push_request(request, [&](qb::http::Response r) { response = std::move(r); }));
        client->connect(nullptr);
        EXPECT_TRUE(qb::http::test::ServerThread<StaticH2Server>::pump_until([&] { return response.has_value(); }, 10s));
        client->disconnect();
        return response.value_or(qb::http::Response{});
    };
    const auto served = get("/whole.bin");
    EXPECT_EQ(served.status(), qb::http::status::OK);
    EXPECT_TRUE(served.body().template as<std::string>() == whole) << "the streamed body differs from the file's";
    const auto over = get("/over.bin");
    EXPECT_EQ(over.status(), qb::http::status::OK) << "a streamed body is never materialised: max_file_size does not bound it (as on HTTP/1.1)";
    EXPECT_EQ(over.body().size(), std::size_t{2} * 1024 * 1024);

    server.reset();
}

} // namespace http2_static_files_test

// ===========================================================================
// An HTTP/2 session extracted from its server runs its extraction handler (Huly QB-1182). The handler is public on
// the HTTP/2 session, but a session class that declares an on() of its own hides every on() of the base from
// io_handler's probe on its type -- name hiding ignores access -- so extractSession() skipped it: the session kept its
// watcher on the socket it gave away, and the contexts of its live streams were neither cancelled nor released. The
// server's extractSession() now runs it for such a session, as the HTTP/1.1 server does. The case extracts a session
// of that shape while a stream's context is live (its handler answers nothing) and asserts the behaviour.
// ===========================================================================
namespace http2_extraction_test {

class ExtractH2Server;

/// A user session with an on() of its own -- the base's on(event::extracted) is public, and hidden all the same.
class HookedH2Session : public qb::http2::use<HookedH2Session>::session<ExtractH2Server> {
public:
    explicit HookedH2Session(ExtractH2Server &server)
        : session(server) {}

    void
    on(qb::http::event::disconnected &&) {}

    /// Whether the session's I/O watcher is still registered with the event loop (the io base's: the inactivity timer
    /// has a watcher of its own).
    [[nodiscard]] bool
    watching() const noexcept {
        return this->base_io_t::_async_event.is_active();
    }
};

static_assert(!qb::has_on<HookedH2Session, qb::io::async::event::extracted>,
              "the case needs a session whose own on() hides the base's extraction handler from the probe");

using ExtractCtx = qb::http::Context<HookedH2Session>;

/// What the server saw, published for the test's thread.
struct Extraction {
    std::atomic<bool> done{false};
    std::atomic<bool> found{false};
    std::atomic<bool> watching_before{false};
    std::atomic<bool> live_before{false};
    std::atomic<bool> cancelled{false};
    std::atomic<bool> watching_after{true};

    void
    reset() {
        done            = false;
        found           = false;
        watching_before = false;
        live_before     = false;
        cancelled       = false;
        watching_after  = true;
    }
};
inline Extraction g_extraction;

class ExtractH2Server : public qb::http2::use<ExtractH2Server>::server<HookedH2Session> {
public:
    ExtractH2Server() {
        // The stream's context stays live: the handler answers nothing. On a later turn the session is extracted, as
        // a WebSocket upgrade or an ownership transfer extracts one, and the new owner closes what it was given.
        router().get("/extract", [this](std::shared_ptr<ExtractCtx> ctx) {
            qb::io::async::callback(
                [this, ctx] {
                    auto session = ctx->session();
                    if (session) {
                        g_extraction.watching_before = session->watching();
                        g_extraction.live_before     = !ctx->is_completed() && !ctx->is_cancelled();
                        auto [io, ok]                = extractSession(session->id());
                        g_extraction.found           = ok;
                        g_extraction.cancelled       = ctx->is_cancelled();
                        g_extraction.watching_after  = session->watching();
                        io.close();
                    }
                    g_extraction.done = true;
                },
                1ms);
        });
        router().compile();
    }
};

TEST(Http2Extraction, ASessionDeclaringItsOwnOnCancelsItsStreamsContextsAndStopsWatching) {
    ASSERT_TRUE(qb::http::test::certs_available()) << "Missing TLS test certificates (" << qb::http::test::ssl_cert_path() << ")";
    qb::io::async::init();
    g_extraction.reset();
    const std::string cert = qb::http::test::ssl_cert_path().string();
    const std::string key  = qb::http::test::ssl_key_path().string();

    qb::http::test::ServerThread<ExtractH2Server> server([cert, key](ExtractH2Server &srv) -> bool {
        srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        srv.start();
        return true;
    });
    ASSERT_TRUE(server.ready());
    ASSERT_NE(server.port(), 0);

    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.port()));
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);
    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/extract");
    ASSERT_TRUE(client->push_request(request, [](qb::http::Response) {}));
    client->connect(nullptr);
    ASSERT_TRUE(qb::http::test::ServerThread<ExtractH2Server>::pump_until([] { return g_extraction.done.load(); }))
        << "the request never reached its handler";
    client->disconnect();

    ASSERT_TRUE(g_extraction.found.load()) << "the session was not extracted";
    ASSERT_TRUE(g_extraction.watching_before.load()) << "the session did not watch its socket before: the case proves nothing";
    ASSERT_TRUE(g_extraction.live_before.load()) << "the stream's context was not live before: the case proves nothing";
    EXPECT_TRUE(g_extraction.cancelled.load()) << "the extraction did not cancel the context of the session's live stream";
    EXPECT_FALSE(g_extraction.watching_after.load()) << "the session still watches a socket it gave away";
}

} // namespace http2_extraction_test

// An HTTP/2 server's HTTP/1.1 fallback restarts the inactivity timeout as an HTTP/1.1 session does (Huly QB-1248): a body
// sent over ALPN http/1.1 slowly but steadily is served. The fallback runs the same protocol on the session's timer, which
// only the server's writes restarted. At 1 s, set by the session as an application's own may set it.
namespace http2_fallback_timeout_test {
constexpr std::chrono::milliseconds kTimeout{1000};

class Server;
class Session : public qb::http2::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
};
class Server : public qb::http2::use<Server>::server<Session> {
public:
    Server() {
        router().post("/up", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::to_string(ctx->request().body().size());
            ctx->complete();
        });
        router().compile();
    }
};
Session::Session(Server &server)
    : session(server) {
    this->setTimeout(kTimeout);
}
} // namespace http2_fallback_timeout_test

TEST(Http2FallbackTimeout, ABodySentSlowlyButSteadilyOverTheHttp11FallbackIsServed) {
    using namespace http2_fallback_timeout_test;
    const std::string                    cert = qb::http::test::ssl_cert_path().string();
    const std::string                    key  = qb::http::test::ssl_key_path().string();
    qb::http::test::ServerThread<Server> thread([cert, key](Server &srv) -> bool {
        srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        srv.start();
        return true;
    });
    ASSERT_TRUE(thread.ready());
    qb::io::tcp::ssl::socket sock{qb::io::ssl::Context::client().alpn({"http/1.1"})};
    sock.set_insecure();
    ASSERT_EQ(sock.connect_v4("127.0.0.1", thread.port()), 0);
    ASSERT_EQ(sock.get_alpn_selected_protocol(), "http/1.1");
    ASSERT_EQ(sock.set_nonblocking(true), 0);

    std::string answer;
    const auto  closed_within = [&](std::chrono::milliseconds window, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where}; // reads what comes; true once the connection ended
        char                                         buffer[4096];
        bool                                         closed = false;
        return qb::http::test::wait_until([&] { return closed; }, window, "closed_within",
                                          [&] {
                                              const int n = sock.read(buffer, sizeof buffer);
                                              if (n < 0)
                                                  closed = true;
                                              else if (n > 0)
                                                  answer.append(buffer, static_cast<std::size_t>(n));
                                              else
                                                  std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                          });
    };
    const auto send = [&](std::string const &bytes, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        std::size_t                                  sent   = 0;
        bool                                         failed = false;
        // Each look writes what the socket takes: all of it, a failure, or a socket that takes no more for now.
        return qb::http::test::wait_until(
                   [&] {
                       while (sent < bytes.size()) {
                           const int n = sock.write(bytes.data() + sent, bytes.size() - sent);
                           if (n < 0) {
                               failed = true;
                               return true;
                           }
                           if (n == 0)
                               return false;
                           sent += static_cast<std::size_t>(n);
                       }
                       return true;
                   },
                   std::chrono::seconds(10), "send", qb::http::test::fail_wait::nap{})
               && !failed;
    };

    ASSERT_TRUE(send("POST /up HTTP/1.1\r\nHost: localhost\r\nContent-Length: 12\r\n\r\n"));
    for (int piece = 0; piece < 12; ++piece) { // a quarter of the timeout apart: three timeouts in all
        ASSERT_FALSE(closed_within(kTimeout / 4)) << "cut after " << piece << " pieces";
        ASSERT_TRUE(send("x"));
    }
    bool ended = false; // each turn reads for 50 ms, or until the connection ended
    qb::http::test::expect_until([&] { return ended || answer.find("\r\n\r\n") != std::string::npos; }, std::chrono::seconds(3), "the answer",
                                 [&] { ended = closed_within(std::chrono::milliseconds(50)); });
    EXPECT_EQ(answer.rfind("HTTP/1.1 200 ", 0), 0u) << answer;
}

// ===========================================================================
// What a server sends on a stream the client reset, over real TLS sockets, and what the client says when it closes a
// connection itself (Huly QB-1270, the maintainer's « Oui, tout dans QB-1270 » of 2026-11-11). A legitimate server
// whose response passes what the client accepts on one stream has the next frames of that stream in flight when the
// client resets it: they closed the connection, and every other request on it failed. And a request failed by the
// client's own GOAWAY read « Server sent GOAWAY: GOAWAY sent by client: ... ».
// ===========================================================================
namespace http2_client_crossing_test {

using qb::http::test::Http2PlannedPeer;

class Http2ClientCrossingTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "the HTTP/2 client system suite REQUIRES the TLS test certificates";
        qb::io::async::init();
    }

    [[nodiscard]] static std::shared_ptr<qb::http2::Client>
    connected_client(uint16_t port, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        auto                                         client = qb::http2::make_client("https://localhost:" + std::to_string(port));
        client->set_verify_peer(false);
        client->set_connect_timeout(5s);
        client->set_request_timeout(90s); // a request ends with its response or with the connection, not on its own
        client->disable_auto_reconnect();
        // Shared with the callback: a client that did not connect here calls it after this has returned, when it is destroyed.
        auto connected = std::make_shared<bool>(false);
        client->connect([connected](bool ok, const std::string &) { *connected = ok; });
        EXPECT_TRUE(ServerThread::pump_until([&] { return *connected; }));
        return client;
    }

    [[nodiscard]] static qb::http::Request
    get(const char *path) {
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri(path);
        return request;
    }
};

// A server whose body passes its content-length on stream 1 while the client's other request waits on
// stream 3. The client resets stream 1 at the DATA that passes it; the server had already written the next DATA of that
// stream and its trailers, then the response to stream 3. The DATA closed the connection with GOAWAY(PROTOCOL_ERROR),
// « DATA for unknown client stream », and the request on stream 3 failed with it. It is discarded now (RFC 9113 §5.1):
// the request on stream 3 is answered on the same connection, its header named by an index the discarded trailers put
// in the HPACK table; the client sent one reset, of stream 1, and its only GOAWAY is the NO_ERROR of the test's
// disconnect(). The body past MAX_BODY_SIZE, 100 MiB on the wire, is http2-client-huge-body.cpp's.
TEST_F(Http2ClientCrossingTest, ADataCrossingTheClientsResetLeavesTheOtherRequestOfTheConnectionServed) {
    Http2PlannedPeer peer(Http2PlannedPeer::Plan::body_past_its_content_length);
    ASSERT_NE(peer.port(), 0);
    std::optional<qb::http::Response> large, other; // before the client, which answers what it still holds when it is destroyed
    auto                              client = connected_client(peer.port());
    ASSERT_TRUE(client->is_connected()) << "the client did not connect";
    ASSERT_TRUE(client->push_request(get("/large"), [&](qb::http::Response r) { large = std::move(r); }));
    ASSERT_TRUE(client->push_request(get("/other"), [&](qb::http::Response r) { other = std::move(r); }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return (large.has_value() && other.has_value()) || peer.eof(); }, 30s));
    ASSERT_TRUE(large.has_value()) << "the response past its content-length was not refused";
    EXPECT_NE(large->status(), qb::http::status::OK);
    EXPECT_NE(large->body().as<std::string>().find("exceeds content-length"), std::string::npos) << large->body().as<std::string>();
    ASSERT_TRUE(other.has_value()) << "the connection ended before the other request was answered";
    EXPECT_EQ(other->status(), qb::http::status::OK) << other->body().as<std::string>();
    EXPECT_EQ(other->body().as<std::string>(), "three");
    EXPECT_EQ(other->header("x-crossed"), "one");
    EXPECT_TRUE(client->is_connected());

    client->disconnect(); // GOAWAY(NO_ERROR) behind everything the client wrote: the peer reads it all
    ASSERT_TRUE(ServerThread::pump_until([&] { return peer.eof(); }, 30s));
    const auto resets = peer.resets();
    ASSERT_EQ(resets.size(), 1u) << "what crossed the reset was answered";
    EXPECT_EQ(resets.front().first, 1u);
    EXPECT_EQ(resets.front().second, 0x1u) << "PROTOCOL_ERROR";
    ASSERT_TRUE(peer.goaway());
    const auto [code, debug] = peer.first_goaway();
    EXPECT_EQ(code, 0u) << "the client closed the connection: " << debug;
}

// A connection the client closes itself -- a HEADERS on an idle stream, a DATA on stream 0, a PING of 7 octets, each a
// connection error (RFC 9113 §5.1.1, §6.1, §6.7) -- fails the request in flight with the client's reason, once:
// « GOAWAY sent by client: <reason> », and the server reads that GOAWAY. It read « Server sent GOAWAY: GOAWAY sent by
// client: <reason> » (the HEADERS); a DATA on stream 0 closed nothing, the request waiting for its timeout; and the PING
// ended the connection without a GOAWAY, the request failing with « Connection lost ». The same holds for the frames
// the frame layer refuses on their header alone -- a SETTINGS, a PING or a GOAWAY on stream 1, a DATA past
// SETTINGS_MAX_FRAME_SIZE (§6.5, §6.7, §6.8, §4.2) -- which ended the connection without a GOAWAY until part 6 of Huly
// QB-1270. The client tells its own GOAWAY by `Http2GoAwayEvent::sent` now, no longer by a prefix of the debug data:
// the request's text is the same, and the server reads the reason alone.
TEST_F(Http2ClientCrossingTest, ARequestTheClientsOwnGoawayFailsNamesTheClientsReasonOnce) {
    struct kind {
        Http2PlannedPeer::Plan plan;
        const char            *reason;
        uint32_t               code;
    };
    // Each kind on a connection of its own, and judged on its own: a fatal assertion ends that kind, not the test.
    const auto closes = [&](const kind &each, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        SCOPED_TRACE(each.reason);
        Http2PlannedPeer peer(each.plan);
        ASSERT_NE(peer.port(), 0);
        std::optional<qb::http::Response> response; // before the client, which answers what it still holds when it is destroyed
        auto                              client = connected_client(peer.port());
        ASSERT_TRUE(client->is_connected()) << "the client did not connect";
        ASSERT_TRUE(client->push_request(get("/pending"), [&](qb::http::Response r) { response = std::move(r); }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return response.has_value(); }, 10s)) << "the client did not close the connection";
        EXPECT_EQ(response->status(), qb::http::status::SERVICE_UNAVAILABLE);
        EXPECT_EQ(response->body().as<std::string>(), std::string("GOAWAY sent by client: ") + each.reason);
        ASSERT_TRUE(ServerThread::pump_until([&] { return peer.goaway() || peer.eof(); }, 10s));
        ASSERT_TRUE(peer.goaway()) << "the connection ended without a GOAWAY";
        const auto [code, debug] = peer.first_goaway();
        EXPECT_EQ(code, each.code);
        EXPECT_EQ(debug, each.reason);
        client->disconnect();
    };
    closes(kind{Http2PlannedPeer::Plan::headers_on_an_idle_stream, "HEADERS frame received on idle client stream", 0x1u});
    closes(kind{Http2PlannedPeer::Plan::data_on_stream_zero, "DATA frame received on stream 0", 0x1u});
    closes(kind{Http2PlannedPeer::Plan::ping_of_seven_octets, "PING frame payload incorrect size.", 0x6u});
    closes(kind{Http2PlannedPeer::Plan::settings_on_a_stream, "SETTINGS frame on non-zero stream_id", 0x1u});
    closes(kind{Http2PlannedPeer::Plan::ping_on_a_stream, "PING frame on non-zero stream_id", 0x1u});
    closes(kind{Http2PlannedPeer::Plan::goaway_on_a_stream, "GOAWAY frame on non-zero stream_id", 0x1u});
    closes(kind{Http2PlannedPeer::Plan::frame_past_max_frame_size, "Frame size 16385 exceeds SETTINGS_MAX_FRAME_SIZE 16384", 0x6u});
}

// A server that sends a DATA on a stream whose response it ended (a 200 with END_STREAM) -- after END_STREAM, on a stream
// that has closed -- commits the connection error RFC 9113 §5.1 names STREAM_CLOSED. The client answered it with
// GOAWAY(PROTOCOL_ERROR), « DATA for unknown client stream »; it sends GOAWAY(STREAM_CLOSED) now, and the request still
// waiting on stream 3 fails with that reason, named once.
TEST_F(Http2ClientCrossingTest, ADataAfterTheResponseEndedIsAConnectionErrorOfTypeStreamClosed) {
    Http2PlannedPeer peer(Http2PlannedPeer::Plan::data_after_the_response_completed);
    ASSERT_NE(peer.port(), 0);
    std::optional<qb::http::Response> ended, waiting; // before the client, which answers what it still holds when it is destroyed
    auto                              client = connected_client(peer.port());
    ASSERT_TRUE(client->is_connected()) << "the client did not connect";
    ASSERT_TRUE(client->push_request(get("/ended"), [&](qb::http::Response r) { ended = std::move(r); }));
    ASSERT_TRUE(client->push_request(get("/waiting"), [&](qb::http::Response r) { waiting = std::move(r); }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return ended.has_value() && waiting.has_value(); }, 10s))
        << "the client did not close the connection";
    EXPECT_EQ(ended->status(), qb::http::status::OK) << ended->body().as<std::string>();
    EXPECT_EQ(waiting->status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(waiting->body().as<std::string>(), "GOAWAY sent by client: DATA for closed client stream");
    ASSERT_TRUE(ServerThread::pump_until([&] { return peer.goaway() || peer.eof(); }, 10s));
    ASSERT_TRUE(peer.goaway()) << "the connection ended without a GOAWAY";
    const auto [code, debug] = peer.first_goaway();
    EXPECT_EQ(code, 0x5u) << "STREAM_CLOSED";
    EXPECT_EQ(debug, "DATA for closed client stream");
    EXPECT_TRUE(peer.resets().empty());
    client->disconnect();
}

// The empty-frame flood (CVE-2019-9518): a server that answers with a 200, then sends empty DATA frames without
// END_STREAM -- each a dispatch for the client, no reply, counted nowhere -- 10000 at once, then 1000 at a time behind a
// PING whose PONG it waits for. The client took them for ever. It ends the connection with GOAWAY(ENHANCE_YOUR_CALM)
// once its bucket of NO_PROGRESS_FRAME_BURST is spent, and the request fails with that reason. The rounds were of one
// frame, which outran the 330 tokens the bucket regains a second only while a round trip took under 3 ms: a slow host
// was never cut, and the test waited out its 10 s (Huly QB-1270). A server that sends a few empty DATA frames between
// its chunks is never cut.
TEST_F(Http2ClientCrossingTest, AFloodOfEmptyDataFramesEndsTheConnectionAndAFewNeverDo) {
    {
        SCOPED_TRACE("a flood of empty DATA frames");
        Http2PlannedPeer peer(Http2PlannedPeer::Plan::empty_data_flood);
        ASSERT_NE(peer.port(), 0);
        std::optional<qb::http::Response> response; // before the client, which answers what it still holds when it is destroyed
        auto                              client = connected_client(peer.port());
        ASSERT_TRUE(client->is_connected()) << "the client did not connect";
        ASSERT_TRUE(client->push_request(get("/flood"), [&](qb::http::Response r) { response = std::move(r); }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return response.has_value(); }, 10s));
        EXPECT_EQ(response->status(), qb::http::status::SERVICE_UNAVAILABLE) << response->body().as<std::string>();
        EXPECT_EQ(response->body().as<std::string>(), "GOAWAY sent by client: Excessive frames making no progress (flood)");
        ASSERT_TRUE(ServerThread::pump_until([&] { return peer.goaway() || peer.eof(); }, 10s));
        ASSERT_TRUE(peer.goaway()) << "the connection ended without a GOAWAY";
        const auto [code, debug] = peer.first_goaway();
        EXPECT_EQ(code, 0xbu) << "ENHANCE_YOUR_CALM";
        EXPECT_EQ(debug, "Excessive frames making no progress (flood)");
        client->disconnect();
    }
    {
        SCOPED_TRACE("200 chunks, three empty DATA frames after each");
        Http2PlannedPeer peer(Http2PlannedPeer::Plan::empty_data_between_chunks);
        ASSERT_NE(peer.port(), 0);
        std::optional<qb::http::Response> response; // before the client, which answers what it still holds when it is destroyed
        auto                              client = connected_client(peer.port());
        ASSERT_TRUE(client->is_connected()) << "the client did not connect";
        ASSERT_TRUE(client->push_request(get("/chunks"), [&](qb::http::Response r) { response = std::move(r); }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return response.has_value(); }, 10s));
        EXPECT_EQ(response->status(), qb::http::status::OK) << response->body().as<std::string>();
        EXPECT_EQ(response->body().as<std::string>().size(), 600u);
        EXPECT_TRUE(client->is_connected());
        EXPECT_FALSE(peer.goaway());
        client->disconnect();
    }
}

#ifdef QB_WITH_LOGGING
/// What the process logged while @p body ran: a log of its own, closed and drained by the next qb::io::log::init()
/// before that returns (the capture of qbm-redis's consumer-unknown-push.cpp), then the process's own file again
/// (LogInitializer's "./qb", 512 MB).
[[nodiscard]] std::string
log_of(const std::function<void()> &body) {
    const auto      dir = std::filesystem::temp_directory_path() / ("qbm-http-h2-client-log-" + std::to_string(std::random_device{}()));
    std::error_code ec;
    EXPECT_TRUE(std::filesystem::create_directory(dir, ec)) << ec.message();
    const auto base = dir / "capture";
    qb::io::log::init(base.string(), 64);
    EXPECT_TRUE(nanolog::log_file_opened());
    EXPECT_TRUE(nanolog::is_logged(qb::io::log::Level::WARN));
    body();
    qb::io::log::init("./qb", 512);
    std::string content;
    {
        std::ifstream      in(base.string() + ".1.log", std::ios::binary);
        std::ostringstream bytes;
        bytes << in.rdbuf();
        content = bytes.str();
    }
    std::filesystem::remove_all(dir, ec);
    return content;
}

[[nodiscard]] std::size_t
occurrences(const std::string &text, std::string_view needle) {
    std::size_t n = 0;
    for (std::size_t at = text.find(needle); at != std::string::npos; at = text.find(needle, at + needle.size())) {
        ++n;
    }
    return n;
}

// A server that lowers its GOAWAY's last-stream-id 100 times, each GOAWAY dispatched: qb::http2::Client logs « Server
// sent GOAWAY » once, for the first, and its protocol at each power of two of their count -- #1, #2, #4 and so on to #64,
// 7 lines. Each was logged twice, 202 lines; the request, below every last-stream-id, is answered.
TEST_F(Http2ClientCrossingTest, AServersGoawaysAreLoggedOnceByTheClient) {
    std::optional<qb::http::Response> response;
    const std::string                 log = log_of([&] {
        Http2PlannedPeer peer(Http2PlannedPeer::Plan::goaways_lowered);
        ASSERT_NE(peer.port(), 0);
        auto client = connected_client(peer.port());
        ASSERT_TRUE(client->is_connected()) << "the client did not connect";
        ASSERT_TRUE(client->push_request(get("/lowered"), [&](qb::http::Response r) { response = std::move(r); }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return response.has_value(); }, 10s));
        client->disconnect();
    });
    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->status(), qb::http::status::OK) << response->body().as<std::string>();
    EXPECT_EQ(occurrences(log, "Server sent GOAWAY"), 1u) << "the client logged each NO_ERROR GOAWAY of the server";
    EXPECT_EQ(occurrences(log, "Client: Received GOAWAY frame"), 7u) << "the protocol logged a GOAWAY past the powers of two";
}
#endif // QB_WITH_LOGGING

} // namespace http2_client_crossing_test

// ===========================================================================
// The HTTP/2 server's inactivity timeout restarts at what the client sends of a request (Huly QB-1248): a request's first
// HEADERS -- its header block has the whole timeout from there, its CONTINUATION frames restart nothing -- and each DATA
// of a request not yet complete. It restarted on the server's writes and at a request's dispatch only: a request had to
// arrive whole within the timeout of the connection's last write. The server is the fallback's above, its session's
// timeout 1 s; the client the raw one of shared/http2_raw_client.h. Every wait is a read for the connection's end, so
// nothing is written to a connection that ended; each end a control measures falls within 0.8 to 1.4 timeouts.
// ===========================================================================
namespace http2_native_timeout_test {
using http2_fallback_timeout_test::kTimeout;
using http2_fallback_timeout_test::Server;
using Raw   = qb::http::test::Http2RawClient;
using Clock = std::chrono::steady_clock;

[[nodiscard]] std::vector<uint8_t>
slice(std::vector<uint8_t> const &block, std::size_t from, std::size_t to) {
    return {block.begin() + static_cast<std::ptrdiff_t>(from), block.begin() + static_cast<std::ptrdiff_t>(to)};
}

class Http2NativeTimeout : public ::testing::Test {
protected:
    std::unique_ptr<qb::http::test::ServerThread<Server>> thread;
    Raw                                                   raw;

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "the HTTP/2 client system suite REQUIRES the TLS test certificates";
        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();
        thread                 = std::make_unique<qb::http::test::ServerThread<Server>>([cert, key](Server &srv) -> bool {
            srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread->ready());
        ASSERT_TRUE(raw.connect(thread->port()));
        ASSERT_TRUE(raw.read_until([this] { return raw.settings_acked; }, std::chrono::seconds(3)));
    }

    /// Reads what comes for at most @p window; true once the connection ended (a GOAWAY, or its close).
    bool
    ended_within(std::chrono::milliseconds window) {
        return raw.read_until([this] { return raw.eof || raw.goaway_seen; }, window);
    }

    /// Reads until stream @p id is answered whole or reset, or the connection ends; the answer's status, 0 for none.
    int
    answer(std::uint32_t id) {
        raw.read_until([this, id] { return raw.streams[id].end_stream || raw.streams[id].reset; }, std::chrono::seconds(3));
        return raw.streams[id].end_stream ? raw.streams[id].status() : 0;
    }

    /// The connection ends within 0.8 to 1.4 timeouts of @p since.
    void
    expect_ended_a_timeout_after(Clock::time_point since, const char *what) {
        ASSERT_TRUE(ended_within(kTimeout * 3)) << what << ": the connection did not end";
        const auto after = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - since);
        EXPECT_GE(after, kTimeout * 8 / 10) << what;
        EXPECT_LE(after, kTimeout * 14 / 10) << what;
    }
};
} // namespace http2_native_timeout_test

using http2_native_timeout_test::Http2NativeTimeout;

TEST_F(Http2NativeTimeout, ABodySentSlowlyButSteadilyIsServed) {
    using namespace http2_native_timeout_test;
    const auto block = raw.next_header_block("/up");
    ASSERT_TRUE(raw.frame(Raw::HEADERS, Raw::END_HEADERS, block.first, block.second));
    for (int piece = 0; piece < 12; ++piece) { // a quarter of the timeout apart: three timeouts in all
        ASSERT_FALSE(ended_within(kTimeout / 4)) << "cut after " << piece << " pieces";
        ASSERT_TRUE(raw.frame(Raw::DATA, piece == 11 ? Raw::END_STREAM : 0, block.first, std::vector<uint8_t>(1, 'x')));
    }
    EXPECT_EQ(answer(block.first), 200);
    EXPECT_EQ(raw.streams[block.first].body(), "12");
}

TEST_F(Http2NativeTimeout, ARequestBegunJustBeforeTheTimeoutHasItsWholeHeaderBlock) {
    using namespace http2_native_timeout_test;
    ASSERT_EQ(answer(raw.request("/up", "POST")), 200);
    ASSERT_FALSE(ended_within(kTimeout * 3 / 4)) << "the connection ended before the second request began";
    const auto block = raw.next_header_block("/up");
    ASSERT_GE(block.second.size(), 3u);
    const std::size_t third = block.second.size() / 3;
    ASSERT_TRUE(raw.frame(Raw::HEADERS, Raw::END_STREAM, block.first, slice(block.second, 0, third))); // the timeout restarts
    ASSERT_FALSE(ended_within(kTimeout / 4)) << "cut after the header block's first frame";
    ASSERT_TRUE(raw.frame(Raw::CONTINUATION, 0, block.first, slice(block.second, third, 2 * third)));
    ASSERT_FALSE(ended_within(kTimeout / 4)) << "cut before the header block's last frame";
    ASSERT_TRUE(raw.frame(Raw::CONTINUATION, Raw::END_HEADERS, block.first, slice(block.second, 2 * third, block.second.size())));
    EXPECT_EQ(answer(block.first), 200);
}

TEST_F(Http2NativeTimeout, AHeaderBlockSentSlowlyStillEndsATimeoutAfterItsFirstHeaders) {
    using namespace http2_native_timeout_test;
    const auto block = raw.next_header_block("/up", "POST", {{"x-padding", std::string(48, 'p')}});
    ASSERT_GE(block.second.size(), 16u) << "too short a block to dribble past the timeout";
    const auto first = Clock::now();
    ASSERT_TRUE(raw.frame(Raw::HEADERS, Raw::END_STREAM, block.first, slice(block.second, 0, 1)));
    std::size_t at   = 1;
    bool        over = false; // the connection ended, or took no more
    // One octet a quarter of the timeout apart, never the last: each turn waits a quarter, then sends the next.
    qb::http::test::discard(
        qb::http::test::wait_until([&] { return over || at + 1 >= block.second.size(); },
                                   kTimeout / 4 * static_cast<int>(block.second.size()) + std::chrono::seconds(5), "a block dribbled",
                                   [&] {
                                       if (ended_within(kTimeout / 4)
                                           || !raw.frame(Raw::CONTINUATION, 0, block.first, slice(block.second, at, at + 1)))
                                           over = true;
                                       else
                                           ++at;
                                   }),
        "how the connection ended is expect_ended_a_timeout_after()'s to say");
    expect_ended_a_timeout_after(first, "a header block dribbled in CONTINUATION frames");
}

TEST_F(Http2NativeTimeout, ABodyThatStallsEndsATimeoutAfterItsLastData) {
    using namespace http2_native_timeout_test;
    const auto block = raw.next_header_block("/up");
    ASSERT_TRUE(raw.frame(Raw::HEADERS, Raw::END_HEADERS, block.first, block.second));
    for (int piece = 0; piece < 6; ++piece) { // a timeout and a half of steady pieces, then nothing
        ASSERT_FALSE(ended_within(kTimeout / 4)) << "cut after " << piece << " pieces";
        ASSERT_TRUE(raw.frame(Raw::DATA, 0, block.first, std::vector<uint8_t>(1, 'x')));
    }
    expect_ended_a_timeout_after(Clock::now(), "a body that stalled");
}

// An empty DATA restarts nothing, by design: the frame layer counts it among the frames that make no progress, and a peer
// that could restart the timeout with it would hold a connection for free.
TEST_F(Http2NativeTimeout, EmptyDataFramesDoNotHoldTheConnection) {
    using namespace http2_native_timeout_test;
    const auto block   = raw.next_header_block("/up");
    const auto headers = Clock::now();
    ASSERT_TRUE(raw.frame(Raw::HEADERS, Raw::END_HEADERS, block.first, block.second));
    int  frames = 0;
    bool over   = false; // the connection ended, or took no more
    // A quarter of the timeout apart, three timeouts at most, nothing in them: each turn waits a quarter, then sends one.
    qb::http::test::discard(qb::http::test::wait_until([&] { return over || frames == 12; }, kTimeout * 3 + std::chrono::seconds(5),
                                                       "empty DATA frames",
                                                       [&] {
                                                           if (ended_within(kTimeout / 4) || !raw.frame(Raw::DATA, 0, block.first, {}))
                                                               over = true;
                                                           else
                                                               ++frames;
                                                       }),
                            "how the connection ended is expect_ended_a_timeout_after()'s to say");
    expect_ended_a_timeout_after(headers, "empty DATA frames");
}

TEST_F(Http2NativeTimeout, AnIdleConnectionStillEndsATimeoutAfterItsLastResponse) {
    using namespace http2_native_timeout_test;
    ASSERT_EQ(answer(raw.request("/up", "POST")), 200);
    expect_ended_a_timeout_after(Clock::now(), "an idle connection");
}

// ===========================================================================
// The streams of an HTTP/2 connection are swept from a timer of the session's own (Huly QB-1248). The sweep ran from
// on(pending_write) alone -- a write that leaves bytes queued: on a connection that only reads, as an upload's, it never
// ran, and with the session's timeout now restarting on what a request brings, nothing bounded the connection's other
// streams. The witness is a request its handler never answers beside an upload that drips: the handler's bound is the
// session's timeout, 1 s here, so the stream is reset between one and two of them (the sweep's period is half the
// smallest bound) while the connection serves on. The raw client reads; nothing here is written by the server.
// ===========================================================================
namespace http2_stream_sweep_test {
using http2_fallback_timeout_test::kTimeout;
using Raw   = qb::http::test::Http2RawClient;
using Clock = std::chrono::steady_clock;

class Server;
class Session : public qb::http2::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
};
class Server : public qb::http2::use<Server>::server<Session> {
public:
    std::vector<std::shared_ptr<qb::http::Context<Session>>> held;                      ///< the requests no handler answers
    std::atomic<int>                                        *cancelled       = nullptr; ///< the contexts cancelled, counted
    bool                                                     clear_on_cancel = false;   ///< the hook clears the protocols
    Server() {
        router().post("/up", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::to_string(ctx->request().body().size());
            ctx->complete();
        });
        router().get("/never", [this](auto ctx) { held.push_back(std::move(ctx)); });
        // A response the server streams by itself: a piece a quarter of the timeout apart, for five timeouts.
        router().get("/ticker", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            tick(ctx->begin_stream(), 0);
        });
        router().add_lifecycle_hook([this](auto &context, qb::http::HookPoint point) {
            if (point != qb::http::HookPoint::POST_HANDLER_EXECUTION || !context.is_cancelled())
                return;
            if (cancelled)
                ++*cancelled;
            if (clear_on_cancel) {
                auto session = context.session();
                context.suppress_response();
                session->clear_protocols(); // under the sweep's reset: retired by the session's pass, ended after the sweep
                session->disconnect();
            }
        });
        router().compile();
    }

private:
    template <typename Stream>
    static void
    tick(Stream stream, int piece) {
        using S = typename Stream::element_type;
        if (!stream || piece == 20 || stream->write(".") == S::write_result::closed) {
            if (stream)
                stream->end();
            return;
        }
        qb::io::async::callback([stream = std::move(stream), piece]() mutable { tick(std::move(stream), piece + 1); }, kTimeout / 4);
    }
};
Session::Session(Server &server)
    : session(server) {
    this->setTimeout(kTimeout);
}

// The sweep reads a response's progress on what the socket takes only on an io that counts its output, and falls back
// to "a frame written is progress" on any other, silently: the session is held to be one.
static_assert(qb::protocol::http2::counts_drained_output<qb::http2::use<Session>::session<Server>>,
              "the HTTP/2 server session no longer counts its output: the sweep would judge a response on the frames written");

class Http2StreamSweep : public ::testing::Test {
protected:
    std::atomic<int>                                      cancelled{0};
    std::unique_ptr<qb::http::test::ServerThread<Server>> thread;
    Raw                                                   raw;

    void
    start(bool clear_on_cancel, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        ASSERT_TRUE(qb::http::test::certs_available()) << "the HTTP/2 client system suite REQUIRES the TLS test certificates";
        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();
        thread = std::make_unique<qb::http::test::ServerThread<Server>>([cert, key, clear_on_cancel, this](Server &srv) -> bool {
            srv.cancelled       = &cancelled;
            srv.clear_on_cancel = clear_on_cancel;
            srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread->ready());
        ASSERT_TRUE(connected(raw));
    }
    [[nodiscard]] bool
    connected(Raw &client) {
        return client.connect(thread->port()) && client.read_until([&client] { return client.settings_acked; }, std::chrono::seconds(3));
    }
    [[nodiscard]] static bool
    ended(Raw const &client) {
        return client.eof || client.goaway_seen;
    }
};
} // namespace http2_stream_sweep_test

using http2_stream_sweep_test::Http2StreamSweep;

TEST_F(Http2StreamSweep, ARequestItsHandlerDoesNotAnswerIsResetOnAConnectionThatWritesNothing) {
    using namespace http2_stream_sweep_test;
    start(/*clear_on_cancel=*/false);
    const auto never  = raw.request("/never");
    const auto begun  = Clock::now();
    const auto upload = raw.next_header_block("/up");
    ASSERT_TRUE(raw.frame(Raw::HEADERS, Raw::END_HEADERS, upload.first, upload.second));
    // An octet of the upload a quarter of the timeout apart: the session's timeout keeps restarting, the server has
    // nothing to write. Five timeouts at most: the reset is due between one and two.
    int        pieces = 0;
    bool       taken  = true; // the connection took every piece
    const auto swept  = [&] {
        return raw.streams[never].reset || ended(raw);
    };
    // Each turn reads for a quarter of the timeout, then sends the next piece: until the reset, twenty pieces at most.
    qb::http::test::discard(qb::http::test::wait_until([&] { return !taken || pieces == 20 || swept(); },
                                                       kTimeout * 5 + std::chrono::seconds(5), "the sweep",
                                                       [&] {
                                                           if (raw.read_until(swept, kTimeout / 4))
                                                               return;
                                                           taken = raw.frame(Raw::DATA, 0, upload.first, std::vector<uint8_t>(1, 'x'));
                                                           ++pieces;
                                                       }),
                            "the case asserts what ended it right after");
    ASSERT_TRUE(taken);
    const auto after = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - begun);
    ASSERT_FALSE(ended(raw)) << "the connection ended";
    ASSERT_TRUE(raw.streams[never].reset) << "a connection that writes nothing was never swept";
    EXPECT_EQ(raw.streams[never].reset_code, 8u) << "CANCEL";
    EXPECT_GE(after, kTimeout) << "reset before its handler had the session's timeout";
    EXPECT_EQ(cancelled.load(), 1) << "the handler's context is told";

    // The connection serves on: the upload ends, and is answered.
    ASSERT_TRUE(raw.frame(Raw::DATA, Raw::END_STREAM, upload.first, std::vector<uint8_t>(1, 'x')));
    raw.read_until([&] { return raw.streams[upload.first].end_stream || raw.streams[upload.first].reset || ended(raw); },
                   std::chrono::seconds(3));
    ASSERT_TRUE(raw.streams[upload.first].end_stream);
    EXPECT_EQ(raw.streams[upload.first].status(), 200);
}

// The sweep goes on by itself: nothing arrives from the client after its two requests -- no frame re-arms the timer --
// while the server's own writes keep the session's timeout restarting. The tick arms the next one while streams remain.
TEST_F(Http2StreamSweep, TheSweepGoesOnWhileStreamsRemainWithNothingArrivingFromTheClient) {
    using namespace http2_stream_sweep_test;
    start(/*clear_on_cancel=*/false);
    const auto never  = raw.request("/never");
    const auto begun  = Clock::now();
    const auto ticker = raw.request("/ticker");
    ASSERT_TRUE(raw.read_until([&] { return raw.streams[never].reset || ended(raw); }, kTimeout * 4)) << "the first tick armed no second one";
    const auto after = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - begun);
    ASSERT_FALSE(ended(raw)) << "the connection ended";
    EXPECT_EQ(raw.streams[never].reset_code, 8u) << "CANCEL";
    EXPECT_GE(after, kTimeout);
    EXPECT_FALSE(raw.streams[ticker].reset) << "a response that flows was reset";
    EXPECT_FALSE(raw.streams[ticker].body().empty());
}

// The reset's observer cancels the handler's context, and a hook of it clears the session's protocols: the sweep runs
// from a timer, outside the read dispatch, where a clear destroyed the protocol at once -- under the sweep that was
// running it (ASan: use after free, without the session's protocol_pass()). Only that connection ends: the server
// accepts and serves the next one.
TEST_F(Http2StreamSweep, AHookThatClearsTheProtocolsUnderTheSweepsResetEndsOnlyItsConnection) {
    using namespace http2_stream_sweep_test;
    start(/*clear_on_cancel=*/true);
    (void) raw.request("/never");
    // The upload drips as above: the session's own timeout keeps restarting, so it is the sweep that cancels the request
    // -- not the end of the connection -- and the hook runs under the sweep's reset.
    const auto upload = raw.next_header_block("/up");
    ASSERT_TRUE(raw.frame(Raw::HEADERS, Raw::END_HEADERS, upload.first, upload.second));
    int  pieces = 0;
    bool over   = false; // the connection ended: read so, or under a write
    // Each turn reads for a quarter of the timeout, then sends the next piece: twenty pieces at most.
    qb::http::test::discard(qb::http::test::wait_until([&] { return over || pieces == 20; }, kTimeout * 5 + std::chrono::seconds(5),
                                                       "the swept upload",
                                                       [&] {
                                                           if (raw.read_until([&] { return raw.eof; }, kTimeout / 4)
                                                               || !raw.frame(Raw::DATA, 0, upload.first, std::vector<uint8_t>(1, 'x')))
                                                               over = true;
                                                           else
                                                               ++pieces;
                                                       }),
                            "the case asserts the end right after");
    ASSERT_TRUE(raw.eof || raw.read_until([&] { return raw.eof; }, kTimeout)) << "the swept request's hook did not end its connection";
    EXPECT_EQ(cancelled.load(), 1);

    Raw next;
    ASSERT_TRUE(connected(next));
    const auto id = next.request("/up", "POST");
    next.read_until([&] { return next.streams[id].end_stream || next.streams[id].reset || ended(next); }, std::chrono::seconds(3));
    ASSERT_TRUE(next.streams[id].end_stream);
    EXPECT_EQ(next.streams[id].status(), 200);
}

// A hook of a context the sweep's reset cancels extracts its session (as an ownership transfer does): on(extracted)
// stops the sweep, and it stays stopped. The tick under which the extraction happened armed the next one -- an
// extraction leaves the protocol in place and the session "connected" -- and that tick reset a stream of the session
// the extraction had left behind, writing into it. The first independent review's witness: observed on the server's
// thread, the session's appended_total() 100 ms after the extraction and 1.5 s after (a period is 1 s here; the
// session's own 2 s timeout cannot end it before).
namespace http2_stream_sweep_extract_test {
constexpr std::chrono::milliseconds kExtractTimeout{2000};
using Raw = qb::http::test::Http2RawClient;

/// What one run observes, on the server's thread: the run's own (a second run in the same process starts afresh).
struct Seen {
    std::atomic<bool>          extracted{false};
    std::atomic<bool>          done{false};
    std::atomic<std::uint64_t> mark{0};
    std::atomic<std::uint64_t> later{0};
    std::atomic<int>           cancelled{0};
};

class Server;
class Session : public qb::http2::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
};
class Server : public qb::http2::use<Server>::server<Session> {
public:
    std::vector<std::shared_ptr<qb::http::Context<Session>>> held;
    std::optional<Session::transport_io_type>                taken;
    bool                                                     extract_once = true;
    Seen                                                    *seen         = nullptr; ///< the run's, set before start()
    Server() {
        router().post("/up", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router().get("/never", [this](auto ctx) { held.push_back(std::move(ctx)); });
        router().add_lifecycle_hook([this](auto &context, qb::http::HookPoint point) {
            if (point != qb::http::HookPoint::POST_HANDLER_EXECUTION || !context.is_cancelled())
                return;
            context.suppress_response();
            ++seen->cancelled;
            if (!extract_once || context.request().uri().path() != "/never")
                return;
            extract_once    = false;
            auto session    = context.session();
            auto transfer   = extractSession(session->id());
            seen->extracted = transfer.second;
            taken.emplace(std::move(transfer.first));
            qb::io::async::callback([session, observed = seen] { observed->mark = session->appended_total(); }, std::chrono::milliseconds(100));
            qb::io::async::callback(
                [session, observed = seen] {
                    observed->later = session->appended_total();
                    observed->done  = true;
                },
                std::chrono::milliseconds(1500));
        });
        router().compile();
    }
};
Session::Session(Server &server)
    : session(server) {
    this->setTimeout(kExtractTimeout);
}
} // namespace http2_stream_sweep_extract_test

TEST(Http2StreamSweepExtraction, NoTickRunsOnASessionExtractedUnderTheSweep) {
    using namespace http2_stream_sweep_extract_test;
    using Clock = std::chrono::steady_clock;
    ASSERT_TRUE(qb::http::test::certs_available());
    const std::string                    cert = qb::http::test::ssl_cert_path().string();
    const std::string                    key  = qb::http::test::ssl_key_path().string();
    Seen                                 seen; // declared before the server's thread: it outlives it
    qb::http::test::ServerThread<Server> thread([cert, key, &seen](Server &srv) -> bool {
        srv.seen = &seen;
        srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        srv.start();
        return true;
    });
    ASSERT_TRUE(thread.ready());
    Raw raw;
    ASSERT_TRUE(raw.connect(thread.port()) && raw.read_until([&] { return raw.settings_acked; }, std::chrono::seconds(3)));
    const auto begun = Clock::now();
    ASSERT_NE(raw.request("/never"), 0u); // two requests the first tick stamps: reset together, the hook extracting at the first
    ASSERT_NE(raw.request("/never"), 0u);
    const auto upload = raw.next_header_block("/up");
    ASSERT_TRUE(raw.frame(Raw::HEADERS, Raw::END_HEADERS, upload.first, upload.second));
    bool third = false;
    qb::http::test::expect_until(
        [&] { return seen.done.load(); }, begun + std::chrono::seconds(12), "the sweep",
        [&] {
            if (!third && Clock::now() - begun > std::chrono::milliseconds(1400)) {
                third = raw.request("/never") != 0; // a third, stamped a tick later: it outlives the sweep that extracts
            }
            (void) raw.frame(Raw::DATA, 0, upload.first, std::vector<uint8_t>(1, 'x')); // the session's timeout keeps restarting
            raw.read_for(std::chrono::milliseconds(250));
        });
    ASSERT_TRUE(third);
    ASSERT_TRUE(seen.extracted.load()) << "no session was extracted under the sweep: the case proves nothing";
    ASSERT_TRUE(seen.done.load()) << "the observations did not run";
    // The third request was dispatched before the extraction -- its context cancelled with the two others --: it is
    // the stream a later tick would have reset. Sent after, the case would pass whatever the sweep did.
    ASSERT_GE(seen.cancelled.load(), 3) << "the third request came after the extraction: the case proves nothing";
    EXPECT_EQ(seen.later.load(), seen.mark.load())
        << "a tick ran on the extracted session and wrote " << (seen.later.load() - seen.mark.load()) << " octets into it";
}

// A refused header block left open on a connection whose sweep had lapsed (the seventh independent review's finding):
// the session arms its sweep for the block. Its last stream had ended, a tick had found nothing and armed no other,
// and on a session with no timeout the block was held for ever.
//
// The block's bound is ten seconds from the sweep that first sees it. Here that sweep is the armed tick's, a period
// (200 ms) after the block; the case then asks the server's thread for ONE sweep eleven seconds ahead, which ends the
// connection. A session whose sweep was not armed sees the block at that sweep for the first time, stamps it, and
// keeps its connection: the server's thread restarts the session's timeout for the whole case, as the server's own
// writes on another stream would.
namespace http2_refused_block_test {
constexpr std::chrono::milliseconds kBlockTimeout{400}; // the sweep's period is half of it
using Raw = qb::http::test::Http2RawClient;

/// What the test asks of the server's thread, and what that thread did: the run's own.
struct Asked {
    std::atomic<bool> sweep{false}; ///< run one sweep, eleven seconds ahead
    std::atomic<bool> swept{false};
    std::atomic<bool> up_after_the_sweep{true}; ///< the session, when that sweep returned
    std::atomic<int>  sessions_left{-1};        ///< the server's sessions at the watch's run that found it ended
};

class Server;
class Session : public qb::http2::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
    /// What the server's thread reads and does of its session, by name.
    [[nodiscard]] bool
    up() noexcept {
        return this->is_connected();
    }
    /// The timeout set again, not only restarted (updateTimeout() records a time and leaves the timer armed as it was):
    /// its timer is armed afresh, past the next run of the watch -- which calls this as its last act, once that next
    /// run is armed, so that a hold-up anywhere in its own run comes before it. Coming out of a hold-up of the server's
    /// thread the watch then runs first, and the timeout does not end the session (the ninth independent review
    /// measured one hold-up past the timeout in twenty or so ending it; the tenth, one placed after this call).
    void
    hold_timeout() noexcept {
        this->setTimeout(kBlockTimeout);
    }
};
class Server : public qb::http2::use<Server>::server<Session> {
public:
    Asked *asked = nullptr; ///< the run's, set before start()
    Server() {
        router().get("/first", [this](auto ctx) {
            watch(ctx->session(), this);
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router().compile();
    }

private:
    /// Every 20 ms on the server's thread, while @p session is connected: its timeout is held off, and the sweep the
    /// test asked for runs, once.
    static void
    watch(std::shared_ptr<Session> session, Server *server) {
        Asked *const asked = server->asked;
        if (!session->up()) {
            asked->sessions_left = static_cast<int>(server->sessions().size());
            return;
        }
        if (asked->sweep.exchange(false)) {
            (void) session->http2_sweep_streams(std::chrono::steady_clock::now() + std::chrono::seconds(11));
            asked->up_after_the_sweep = session->up();
            asked->swept              = true;
        }
        Session *const held = session.get(); // the next run's callback keeps it alive
        qb::io::async::callback([session = std::move(session), server]() mutable { watch(std::move(session), server); },
                                std::chrono::milliseconds(20));
        held->hold_timeout(); // the run's last act, the next run armed: the timeout always expires after that run
    }
};
Session::Session(Server &server)
    : session(server) {
    this->setTimeout(kBlockTimeout);
}
} // namespace http2_refused_block_test

TEST(Http2RefusedBlock, TheSessionArmsItsSweepForARefusedBlockLeftOpen) {
    using namespace http2_refused_block_test;
    ASSERT_TRUE(qb::http::test::certs_available()) << "the HTTP/2 client system suite REQUIRES the TLS test certificates";
    const std::string                    cert = qb::http::test::ssl_cert_path().string();
    const std::string                    key  = qb::http::test::ssl_key_path().string();
    Asked                                asked; // declared before the server's thread: it outlives it
    qb::http::test::ServerThread<Server> thread([cert, key, &asked](Server &srv) -> bool {
        srv.asked = &asked;
        srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        srv.start();
        return true;
    });
    ASSERT_TRUE(thread.ready());
    Raw raw;
    ASSERT_TRUE(raw.connect(thread.port()) && raw.read_until([&] { return raw.settings_acked; }, std::chrono::seconds(3)));
    const auto ended = [&raw] {
        return raw.eof || raw.goaway_seen;
    };
    const auto first = raw.request("/first"); // answered: the server's thread watches its session from there
    ASSERT_NE(first, 0u);
    raw.read_until([&] { return raw.streams[first].end_stream || raw.streams[first].reset || ended(); }, std::chrono::seconds(3));
    ASSERT_TRUE(raw.streams[first].end_stream) << "the first request was not answered";
    // The tick that request armed finds no stream and arms no other: five of its periods.
    raw.read_for(kBlockTimeout / 2 * 5);
    ASSERT_FALSE(ended()) << "the connection ended before the block";

    // A HEADERS on the answered stream, without END_HEADERS: refused (STREAM_CLOSED), its block left open.
    const auto block = raw.next_header_block("/late", "GET", {{"x-padding", std::string(32, 'p')}});
    ASSERT_GT(block.second.size(), 4u);
    ASSERT_TRUE(raw.frame(Raw::HEADERS, 0, first, std::vector<uint8_t>(block.second.begin(), block.second.begin() + 2)));
    // The session's sweep, armed for the block, sees it at its tick, a period later; ten are waited for, so that a
    // server thread held up for less than nine of them changes nothing (the session's timeout is held off by the
    // watch, hold_timeout()).
    raw.read_for(kBlockTimeout / 2 * 10);
    ASSERT_FALSE(ended()) << "the connection ended before the block's bound";

    asked.sweep = true; // one sweep, eleven seconds ahead: past the bound of a block a tick has seen
    ASSERT_TRUE(raw.read_until(ended, std::chrono::seconds(3)))
        << "the block was first seen by the sweep the case asked for: the session's own was not armed for it";
    EXPECT_TRUE(asked.swept.load());
    // At that GOAWAY the session is released as at every error GOAWAY: disconnected when the sweep returns, gone from
    // the server a dispatch later. A session that stayed to deliver the frame kept its contexts and its output for as
    // long as its client took to read (the eighth independent review; delivering it was written, and withdrawn).
    EXPECT_FALSE(asked.up_after_the_sweep.load()) << "the session outlived the sweep's GOAWAY: it stayed to deliver it";
    qb::http::test::expect_until([&] { return asked.sessions_left.load() >= 0; }, std::chrono::seconds(3), "wait_until",
                                 qb::http::test::fail_wait::nap{std::chrono::milliseconds(5)});
    EXPECT_EQ(asked.sessions_left.load(), 0) << "the server still holds the session";
}

// An HTTP/2 session keeps the first reason it ended with (Huly QB-1248; the eleventh and twelfth independent reviews).
// qb-io's disconnect() updates the reason at each call: a session that something ended in a pass of the loop, and that
// a later disconnection of the session's own ended again, reported the later reason -- its inactivity timeout's
// ByTimeout, the drain deadline's ServerDraining. Each case holds a request, answers it from a callback outside the read
// dispatch (nothing is written before the loop's next pass), sets in motion what ends the session, and holds the
// server's thread past what expires; the reason is read twice: at the session's release (the server's disconnected()
// hook: the session is still in its map) and 100 ms after the hold-up. With output queued the session's watcher is made
// pending by the poll that follows the hold-up and its release comes after the expired timers; with nothing queued it
// is released first, and its timer -- the capture of the case keeps the session -- ticks after its release: the two
// readings see the two orders.
namespace http2_reason_test {
using std::chrono::milliseconds;
using Raw = qb::http::test::Http2RawClient;

/// What a case sets in motion from the callback, once the request is answered (or not).
enum class Plan : int {
    disconnect_then_timeout,                  ///< a disconnection 30 ms later; the session's 150 ms timeout
    nothing_queued_then_timeout,              ///< the same, the request never answered: nothing queued
    disconnect_then_drain_deadline,           ///< a disconnection 30 ms later; the server drains, its deadline 40 ms away
    disconnect_then_drain_deadline_lingering, ///< the same, the session's linger 200 ms: the deadline arms the delivery's bound
    timeout_then_drain_deadline,              ///< the session's 30 ms timeout; the server drains, its deadline 60 ms away
};

/// What the server's thread saw: the run's own.
struct Seen {
    std::atomic<std::size_t> queued{0};    ///< the session's output when the thread was held
    std::atomic<int>         reported{-1}; ///< the session's reason at its release
    std::atomic<int>         reason{-1};   ///< the session's reason, read 100 ms after the hold-up
    std::atomic<bool>        done{false};
};
inline Seen *g_seen = nullptr; ///< the run's, set before its server's thread starts, cleared once that thread is joined

class Server;
class Session : public qb::http2::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
    /// What the server's thread reads of its session, by name.
    [[nodiscard]] std::size_t
    queued() noexcept {
        return this->out().size();
    }
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
};
class Server : public qb::http2::use<Server>::server<Session> {
public:
    Plan plan = Plan::disconnect_then_timeout;
    Server() {
        router().get("/held", [this](auto ctx) {
            Seen *const observed = g_seen;
            const Plan  how      = plan;
            Server     *server   = this;
            qb::io::async::callback(
                [ctx, observed, how, server] {
                    const auto session   = ctx->session();
                    const int  undefined = static_cast<int>(qb::http::DisconnectedReason::Undefined);
                    const auto record    = [](qb::http::drain_outcome) {
                    };
                    if (how != Plan::nothing_queued_then_timeout) {
                        ctx->response().status() = qb::http::status::OK;
                        ctx->complete();
                    }
                    observed->queued = session->queued();
                    switch (how) {
                        case Plan::disconnect_then_timeout:
                        case Plan::nothing_queued_then_timeout:
                            // The disconnection's timer first: it expires before the timeout whatever holds the thread between.
                            qb::io::async::callback([session, reason = undefined] { session->disconnect(reason); }, milliseconds(30));
                            session->setTimeout(milliseconds(150)); // armed afresh from here
                            std::this_thread::sleep_for(milliseconds(300));
                            break;
                        case Plan::disconnect_then_drain_deadline:
                        case Plan::disconnect_then_drain_deadline_lingering:
                            qb::io::async::callback([session, reason = undefined] { session->disconnect(reason); }, milliseconds(30));
                            (void) server->drain(milliseconds(40), record);
                            std::this_thread::sleep_for(milliseconds(100));
                            break;
                        case Plan::timeout_then_drain_deadline:
                            session->setTimeout(milliseconds(30));
                            (void) server->drain(milliseconds(60), record);
                            std::this_thread::sleep_for(milliseconds(150));
                            break;
                    }
                    qb::io::async::callback(
                        [session, observed] {
                            observed->reason = session->ended_for();
                            observed->done   = true;
                        },
                        milliseconds(100));
                },
                milliseconds(20));
        });
        router().compile();
    }
    /// The session is still in the map, its on(disconnected) has run.
    void
    disconnected(qb::uuid id) {
        auto const &all = this->sessions();
        if (auto it = all.find(id); it != all.end() && it->second && g_seen)
            g_seen->reported = it->second->ended_for();
        qb::http2::use<Server>::server<Session>::disconnected(id);
    }
};
Session::Session(Server &server)
    : session(server) {
    // The deadline aborts at once with a linger of zero; with one, it arms the bound of the last delivery.
    this->set_linger(server.plan == Plan::disconnect_then_drain_deadline_lingering ? qb::duration(milliseconds(200)) : qb::duration::zero());
}

/// Runs @p plan, and returns what was seen once the server's thread is joined.
inline void
run(Plan plan, Seen &seen, std::source_location const where = std::source_location::current()) {
    qb::http::test::fail_wait::called_from const caller{where};
    ASSERT_TRUE(qb::http::test::certs_available()) << "the HTTP/2 client system suite REQUIRES the TLS test certificates";
    const std::string cert = qb::http::test::ssl_cert_path().string();
    const std::string key  = qb::http::test::ssl_key_path().string();
    g_seen                 = &seen;
    {
        qb::http::test::ServerThread<Server> thread([cert, key, plan](Server &srv) -> bool {
            srv.plan = plan;
            srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread.ready());
        Raw raw;
        ASSERT_TRUE(raw.connect(thread.port()) && raw.read_until([&] { return raw.settings_acked; }, std::chrono::seconds(3)));
        ASSERT_NE(raw.request("/held"), 0u);
        qb::http::test::expect_until([&] { return seen.done.load(); }, std::chrono::seconds(5), "wait_until",
                                     qb::http::test::fail_wait::nap{milliseconds(5)});
    }
    g_seen = nullptr;
    ASSERT_TRUE(seen.done.load()) << "the session was not read after its release";
}

[[nodiscard]] constexpr int
reason(qb::http::DisconnectedReason r) {
    return static_cast<int>(r);
}
} // namespace http2_reason_test

// Ended by a callback in the pass of its timeout, its response queued: the timeout's tick ran before the release, and
// disconnected it again.
TEST(Http2SessionReason, ADisconnectionInThePassOfTheTimeoutKeepsItsReason) {
    using namespace http2_reason_test;
    Seen seen;
    ASSERT_NO_FATAL_FAILURE(run(Plan::disconnect_then_timeout, seen));
    ASSERT_GT(seen.queued.load(), 0u) << "nothing queued: the case is the next one";
    EXPECT_EQ(seen.reported.load(), reason(qb::http::DisconnectedReason::Undefined)) << "reported at the release";
    EXPECT_EQ(seen.reason.load(), reason(qb::http::DisconnectedReason::Undefined)) << "read after the hold-up";
}

// The same with nothing queued: released first, its timer ticked after the release, the capture holding the session.
TEST(Http2SessionReason, AReleasedSessionKeepsItsReasonAtItsTimeout) {
    using namespace http2_reason_test;
    Seen seen;
    ASSERT_NO_FATAL_FAILURE(run(Plan::nothing_queued_then_timeout, seen));
    ASSERT_EQ(seen.queued.load(), 0u);
    EXPECT_EQ(seen.reported.load(), reason(qb::http::DisconnectedReason::Undefined)) << "reported at the release";
    EXPECT_EQ(seen.reason.load(), reason(qb::http::DisconnectedReason::Undefined)) << "read after the hold-up";
}

// Ended by a callback in the pass of the drain's deadline: the deadline aborted it again, ServerDraining over the
// cause -- at once with a linger of zero; with one, the deadline arms the bound of the last delivery, which leaves a
// session that has ended (the control).
TEST(Http2SessionReason, ADisconnectionInThePassOfTheDrainDeadlineKeepsItsReason) {
    using namespace http2_reason_test;
    for (const Plan plan : {Plan::disconnect_then_drain_deadline, Plan::disconnect_then_drain_deadline_lingering}) {
        Seen seen;
        ASSERT_NO_FATAL_FAILURE(run(plan, seen));
        ASSERT_GT(seen.queued.load(), 0u) << "nothing queued: its watcher is not pending, the case proves nothing";
        EXPECT_EQ(seen.reported.load(), reason(qb::http::DisconnectedReason::Undefined)) << "reported at the release";
        EXPECT_EQ(seen.reason.load(), reason(qb::http::DisconnectedReason::Undefined)) << "read after the hold-up";
    }
}

// Ended by its own timeout in the pass of the drain's deadline: it reports the timeout, the first cause.
TEST(Http2SessionReason, ATimeoutInThePassOfTheDrainDeadlineKeepsItsReason) {
    using namespace http2_reason_test;
    Seen seen;
    ASSERT_NO_FATAL_FAILURE(run(Plan::timeout_then_drain_deadline, seen));
    ASSERT_GT(seen.queued.load(), 0u) << "nothing queued: its watcher is not pending, the case proves nothing";
    EXPECT_EQ(seen.reported.load(), reason(qb::http::DisconnectedReason::ByTimeout)) << "reported at the release";
    EXPECT_EQ(seen.reason.load(), reason(qb::http::DisconnectedReason::ByTimeout)) << "read after the hold-up";
}

// A session held past its extraction has its INACTIVITY timer stopped -- the one the HTTP/2 session names
// (`inactivity_timer_t`) -- and a timer the session type keeps of its own is left to tick (the fourteenth independent
// review of Huly QB-1248, for HTTP/1.1; the same here): with a `use<S>::timeout` of its own, qb-io's rule by type
// stopped that one and left the inactivity timer armed; with a timer of its own type as a base, neither was stopped.
// Inactivity 100 ms, own timer 300 ms, read 450 ms after the extraction.
namespace http2_own_timer_test {
using std::chrono::milliseconds;
using Raw = qb::http::test::Http2RawClient;

struct Seen {
    std::atomic<bool>      extracted{false};
    std::atomic<bool>      done{false};
    std::atomic<int>       reason_after{-1};
    std::atomic<int>       server_unknown{0};
    std::atomic<int>       own_ticks{0};
    std::atomic<long long> inactivity_ms{-1};
    std::atomic<long long> own_ms{-1};
};
inline Seen *g_seen = nullptr;

template <typename S>
class Server;

/// Its own timer is `use<S>::timeout`.
class UseTimeoutSession
    : public qb::http2::use<UseTimeoutSession>::session<Server<UseTimeoutSession>>
    , public qb::io::use<UseTimeoutSession>::timeout {
    using http_base = qb::http2::use<UseTimeoutSession>::session<Server<UseTimeoutSession>>;
    using own_base  = qb::io::async::with_timeout<UseTimeoutSession>;

public:
    explicit UseTimeoutSession(Server<UseTimeoutSession> &server)
        : http_base(server)
        , own_base(qb::duration::zero()) {}
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
    void
    set_inactivity(qb::duration d) noexcept {
        static_cast<http_base &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    inactivity() noexcept {
        return static_cast<http_base &>(*this).getTimeout();
    }
    void
    set_own(qb::duration d) noexcept {
        static_cast<own_base &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    own() noexcept {
        return static_cast<own_base &>(*this).getTimeout();
    }
    void
    on(qb::io::async::event::timer const &) {
        if (g_seen)
            ++g_seen->own_ticks;
    }
};

/// The same, declared final (the seventeenth independent review's W171): qb-io's probe cannot derive from it, and
/// the name -- the session's public alias -- is looked up in it directly.
class FinalUseTimeoutSession final
    : public qb::http2::use<FinalUseTimeoutSession>::session<Server<FinalUseTimeoutSession>>
    , public qb::io::use<FinalUseTimeoutSession>::timeout {
    using http_base = qb::http2::use<FinalUseTimeoutSession>::session<Server<FinalUseTimeoutSession>>;
    using own_base  = qb::io::async::with_timeout<FinalUseTimeoutSession>;

public:
    explicit FinalUseTimeoutSession(Server<FinalUseTimeoutSession> &server)
        : http_base(server)
        , own_base(qb::duration::zero()) {}
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
    void
    set_inactivity(qb::duration d) noexcept {
        static_cast<http_base &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    inactivity() noexcept {
        return static_cast<http_base &>(*this).getTimeout();
    }
    void
    set_own(qb::duration d) noexcept {
        static_cast<own_base &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    own() noexcept {
        return static_cast<own_base &>(*this).getTimeout();
    }
    void
    on(qb::io::async::event::timer const &) {
        if (g_seen)
            ++g_seen->own_ticks;
    }
};

/// Its own timer is a base of its own type.
struct Tick : qb::io::async::with_timeout<Tick> {
    Tick()
        : qb::io::async::with_timeout<Tick>(qb::duration::zero()) {}
    void
    on(qb::io::async::event::timer const &) {
        if (g_seen)
            ++g_seen->own_ticks;
    }
};
class TickSession
    : public qb::http2::use<TickSession>::session<Server<TickSession>>
    , public Tick {
    using http_base = qb::http2::use<TickSession>::session<Server<TickSession>>;

public:
    explicit TickSession(Server<TickSession> &server)
        : http_base(server) {}
    [[nodiscard]] int
    ended_for() noexcept {
        return this->disconnection_reason();
    }
    void
    set_inactivity(qb::duration d) noexcept {
        static_cast<http_base &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    inactivity() noexcept {
        return static_cast<http_base &>(*this).getTimeout();
    }
    void
    set_own(qb::duration d) noexcept {
        static_cast<Tick &>(*this).setTimeout(d);
    }
    [[nodiscard]] qb::duration
    own() noexcept {
        return static_cast<Tick &>(*this).getTimeout();
    }
    /// An on() of its own, as a session type that handles something has: it hides both bases' (no ambiguous lookup).
    struct Unused {};
    void
    on(Unused) {}
};

template <typename S>
class Server : public qb::http2::use<Server<S>>::template server<S> {
public:
    std::optional<typename S::transport_io_type> taken; ///< the extracted transport: it ends with the server
    Server() {
        this->router().get("/x", [this](auto ctx) {
            Seen *const observed = g_seen;
            qb::io::async::callback(
                [this, ctx, observed] {
                    auto session = ctx->session();
                    session->set_inactivity(milliseconds(100));
                    session->set_own(milliseconds(300));
                    auto transfer       = this->extractSession(session->id());
                    observed->extracted = transfer.second;
                    taken.emplace(std::move(transfer.first));
                    qb::io::async::callback(
                        [session, observed] {
                            observed->reason_after  = session->ended_for();
                            observed->inactivity_ms = std::chrono::duration_cast<milliseconds>(session->inactivity()).count();
                            observed->own_ms        = std::chrono::duration_cast<milliseconds>(session->own()).count();
                            observed->done          = true;
                        },
                        milliseconds(450));
                },
                milliseconds(10));
        });
        this->router().compile();
    }
    void
    disconnected(qb::uuid id) {
        if (g_seen && this->sessions().find(id) == this->sessions().end())
            ++g_seen->server_unknown;
        qb::http2::use<Server<S>>::template server<S>::disconnected(id);
    }
};

template <typename S>
void
expect_the_inactivity_timer_alone_stopped(std::source_location const where = std::source_location::current()) {
    qb::http::test::fail_wait::called_from const caller{where};
    ASSERT_TRUE(qb::http::test::certs_available()) << "the HTTP/2 client system suite REQUIRES the TLS test certificates";
    const std::string cert = qb::http::test::ssl_cert_path().string();
    const std::string key  = qb::http::test::ssl_key_path().string();
    Seen              seen;
    g_seen = &seen;
    {
        qb::http::test::ServerThread<Server<S>> thread([cert, key](Server<S> &srv) -> bool {
            srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread.ready());
        Raw raw;
        ASSERT_TRUE(raw.connect(thread.port()) && raw.read_until([&] { return raw.settings_acked; }, std::chrono::seconds(3)));
        ASSERT_NE(raw.request("/x"), 0u);
        qb::http::test::expect_until([&] { return seen.done.load(); }, std::chrono::seconds(5), "wait_until",
                                     qb::http::test::fail_wait::nap{milliseconds(5)});
    }
    g_seen = nullptr;
    ASSERT_TRUE(seen.extracted.load()) << "no session was extracted: the case proves nothing";
    ASSERT_TRUE(seen.done.load()) << "the extracted session was not read";
    EXPECT_EQ(seen.reason_after.load(), 0) << "the session whose transport was taken was disconnected";
    EXPECT_EQ(seen.server_unknown.load(), 0) << "the server was told of a session it no longer had";
    EXPECT_EQ(seen.inactivity_ms.load(), 0) << "the inactivity timer was not stopped";
    EXPECT_EQ(seen.own_ms.load(), 300) << "the session's own timer was stopped";
    EXPECT_EQ(seen.own_ticks.load(), 1) << "the session's own timer did not tick";
}
} // namespace http2_own_timer_test

TEST(Http2SessionReason, AnExtractedSessionWithATimerOfItsOwnHasItsInactivityTimerAloneStopped) {
    using namespace http2_own_timer_test;
    expect_the_inactivity_timer_alone_stopped<UseTimeoutSession>();
    expect_the_inactivity_timer_alone_stopped<FinalUseTimeoutSession>();
    expect_the_inactivity_timer_alone_stopped<TickSession>();
}

// What `Http2ServerLifecycle.AProtocolInstalledWhereTheSessionsWasIsNotTakenForIt` proves of the HTTP/2 protocol,
// for the HTTP/1.1 fallback of an HTTP/2 server: once the application cleared the session's protocols and installed
// one of its own, the session does not speak HTTP for the server's drain -- even when that protocol sits at the
// address of the HTTP/1.1 one the session had installed (Huly QB-1248). Everything happens on the server's thread,
// from a deferred callback: outside the read dispatch, where a clear destroys at once and the block is free.
namespace http2_fallback_identity_test {
struct Seen {
    std::atomic<bool> done{false};
    std::atomic<bool> spoke_before{false};
    std::atomic<bool> speaks_after_clear{true};
    std::atomic<bool> speaks_after_replacement{true};
    std::atomic<bool> same_address{false};
    std::atomic<bool> drain_answered{false};
    std::atomic<bool> drained{false};
};

class Server;
class Session : public qb::http2::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
};
class Server : public qb::http2::use<Server>::server<Session> {
public:
    Seen                                       *seen = nullptr; ///< the run's, set before start()
    std::shared_ptr<qb::http::Context<Session>> held;
    Server() {
        router().get("/swap", [this](auto ctx) {
            auto session = ctx->session();
            held         = std::move(ctx);
            qb::io::async::callback([this, session] { swap(*session); }, std::chrono::milliseconds(20));
        });
        router().compile();
    }

private:
    void
    swap(Session &session) {
        struct AsLargeAsTheSessionsOwn final : Session::Http1Protocol {
            using Session::Http1Protocol::Http1Protocol;
            std::shared_ptr<void> lifetime;
        };
        const void *const installed = static_cast<const void *>(static_cast<Session::Http1Protocol *>(session.protocol()));
        seen->spoke_before          = session.http2_speaks_http();
        session.clear_protocols();
        seen->speaks_after_clear       = session.http2_speaks_http();
        auto *const replacement        = session.template switch_protocol<AsLargeAsTheSessionsOwn>(session);
        seen->same_address             = static_cast<const void *>(static_cast<Session::Http1Protocol *>(replacement)) == installed;
        seen->speaks_after_replacement = session.http2_speaks_http();
        std::optional<qb::http::drain_outcome> outcome;
        const bool began     = this->drain(qb::duration::zero(), [&outcome](qb::http::drain_outcome o) { outcome = o; });
        seen->drain_answered = began && outcome.has_value();
        seen->drained        = outcome.has_value() && *outcome == qb::http::drain_outcome::drained;
        seen->done           = true;
    }
};
Session::Session(Server &server)
    : session(server) {}
} // namespace http2_fallback_identity_test

TEST(Http2FallbackIdentity, AProtocolInstalledWhereTheFallbacksWasDoesNotSpeakHttpForTheDrain) {
    using namespace http2_fallback_identity_test;
    ASSERT_TRUE(qb::http::test::certs_available());
    const std::string                    cert = qb::http::test::ssl_cert_path().string();
    const std::string                    key  = qb::http::test::ssl_key_path().string();
    Seen                                 seen; // declared before the server's thread: it outlives it
    qb::http::test::ServerThread<Server> thread([cert, key, &seen](Server &srv) -> bool {
        srv.seen = &seen;
        srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        srv.start();
        return true;
    });
    ASSERT_TRUE(thread.ready());
    qb::io::tcp::ssl::socket sock{qb::io::ssl::Context::client().alpn({"http/1.1"})};
    sock.set_insecure();
    ASSERT_EQ(sock.connect_v4("127.0.0.1", thread.port()), 0);
    ASSERT_EQ(sock.get_alpn_selected_protocol(), "http/1.1");
    const std::string request = "GET /swap HTTP/1.1\r\nHost: localhost\r\n\r\n";
    ASSERT_EQ(sock.write(request.data(), request.size()), static_cast<int>(request.size()));
    qb::http::test::expect_until([&] { return seen.done.load(); }, std::chrono::seconds(5), "wait_until",
                                 qb::http::test::fail_wait::nap{std::chrono::milliseconds(5)});
    ASSERT_TRUE(seen.done.load()) << "the swap did not run";
    EXPECT_TRUE(seen.spoke_before.load());
    EXPECT_FALSE(seen.speaks_after_clear.load()) << "no protocol at all";
    if (!seen.same_address.load()) {
        GTEST_SKIP() << "the allocator did not hand the cleared protocol's block back: nothing to tell apart";
    }
    EXPECT_FALSE(seen.speaks_after_replacement.load()) << "the replacement is taken for the fallback the session installed";
    ASSERT_TRUE(seen.drain_answered.load());
    EXPECT_TRUE(seen.drained.load()) << "the drain waited for a session that no longer speaks HTTP";
}

// ===========================================================================
// The HTTP/2 client's body limit (Huly QB-1248): `set_max_body_size()`, the constant by default, 0 for none. Past it the
// response's stream is reset and its request fails with a 502 whose error names the limit -- a body that declares its
// length at its header block, one that delivers more at the DATA that passes it -- while the connection serves the
// other requests on. A body past the default under a limit of none is http2-client-huge-body.cpp's: 100 MiB on the wire.
// ===========================================================================
namespace http2_client_body_limit_test {
class Server;
class Session : public qb::http2::use<Session>::session<Server> {
public:
    explicit Session(Server &server)
        : session(server) {}
};
class Server : public qb::http2::use<Server>::server<Session> {
public:
    Server() {
        router().get("/declared-2048", [](auto ctx) { sized(ctx, 2048); });
        router().get("/declared-1024", [](auto ctx) { sized(ctx, 1024); });
        router().get("/small", [](auto ctx) { sized(ctx, 5); });
        router().get("/streamed-2048", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream(); // no content-length: the body is what the DATA frames bring
            static_cast<void>(stream->write(std::string(2048, 's')));
            stream->end();
        });
        router().compile();
    }

private:
    template <typename Ctx>
    static void
    sized(Ctx const &ctx, std::size_t size) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("content-length", std::to_string(size));
        ctx->response().body() = std::string(size, 'd');
        ctx->complete();
    }
};

class Http2ClientBodyLimit : public ::testing::Test {
protected:
    std::unique_ptr<qb::http::test::ServerThread<Server>> thread;
    std::shared_ptr<qb::http2::Client>                    client;

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "the HTTP/2 client system suite REQUIRES the TLS test certificates";
        qb::io::async::init();
        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();
        thread                 = std::make_unique<qb::http::test::ServerThread<Server>>([cert, key](Server &srv) -> bool {
            srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2"}));
            if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            srv.start();
            return true;
        });
        ASSERT_TRUE(thread->ready());
        client = qb::http2::make_client("https://localhost:" + std::to_string(thread->port()));
        client->set_verify_peer(false);
        client->set_connect_timeout(5s);
        client->disable_auto_reconnect();
    }

    void
    TearDown() override {
        if (client)
            client->disconnect();
    }

    /// The responses to @p paths, requested at once on the client's one connection.
    std::vector<std::optional<qb::http::Response>>
    get_all(std::vector<const char *> const &paths, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        // Shared with the callbacks: a request not answered here is answered by TearDown()'s close, once the case has returned.
        auto responses = std::make_shared<std::vector<std::optional<qb::http::Response>>>(paths.size());
        for (std::size_t i = 0; i < paths.size(); ++i) {
            qb::http::Request request;
            request.method() = qb::http::Method::GET;
            request.uri()    = qb::io::uri(paths[i]);
            EXPECT_TRUE(client->push_request(request, [responses, i](qb::http::Response r) { (*responses)[i] = std::move(r); }));
        }
        client->connect(nullptr);
        EXPECT_TRUE(qb::http::test::ServerThread<Server>::pump_until([&responses] {
            return std::all_of(responses->begin(), responses->end(), [](auto const &r) { return r.has_value(); });
        })) << "not every request was answered";
        return *responses;
    }
};
} // namespace http2_client_body_limit_test

using http2_client_body_limit_test::Http2ClientBodyLimit;

TEST_F(Http2ClientBodyLimit, ABodyPastTheClientsLimitFailsWithAnErrorThatNamesItAndTheConnectionServesOn) {
    client->set_max_body_size(1024);
    EXPECT_EQ(client->max_body_size(), 1024u);
    const auto responses = get_all({"/declared-2048", "/streamed-2048", "/declared-1024", "/small"});
    ASSERT_EQ(responses.size(), 4u);
    for (std::size_t i = 0; i < 2; ++i) {
        SCOPED_TRACE(i == 0 ? "declared past the limit" : "delivered past the limit");
        ASSERT_TRUE(responses[i].has_value());
        EXPECT_EQ(responses[i]->status(), qb::http::status::BAD_GATEWAY);
        EXPECT_NE(responses[i]->body().as<std::string>().find("HTTP/2 response body exceeds the client's limit of 1024 bytes"),
                  std::string::npos)
            << responses[i]->body().as<std::string>();
    }
    ASSERT_TRUE(responses[2].has_value() && responses[3].has_value());
    EXPECT_EQ(responses[2]->status(), qb::http::status::OK) << "a body of exactly the limit: " << responses[2]->body().as<std::string>();
    EXPECT_EQ(responses[2]->body().size(), 1024u);
    EXPECT_EQ(responses[3]->status(), qb::http::status::OK);
    EXPECT_TRUE(client->is_connected()) << "a stream reset ended the connection";
}

TEST_F(Http2ClientBodyLimit, TheClientsBodyLimitIsTheConstantByDefaultAndNoneAtZero) {
    EXPECT_EQ(client->max_body_size(), qb::http::protocol_limits::MAX_BODY_SIZE);
    client->set_max_body_size(1024);
    client->set_max_body_size(0);
    EXPECT_EQ(client->max_body_size(), 0u);
    const auto responses = get_all({"/declared-2048", "/streamed-2048"});
    ASSERT_EQ(responses.size(), 2u);
    for (auto const &response : responses) {
        ASSERT_TRUE(response.has_value());
        EXPECT_EQ(response->status(), qb::http::status::OK) << response->body().as<std::string>();
        EXPECT_EQ(response->body().size(), 2048u);
    }
}

// ---------------------------------------------------------------------------
// The client's callbacks and its connections (Huly QB-1246): what a callback may do -- push, connect, run the loop --
// and what the client then owes it. The cases of this section are in a namespace of their own, at the end of the file.
// ---------------------------------------------------------------------------

namespace http2_client_callbacks_test {

/// A GET the server routes and never answers.
qb::http::Request
hang() {
    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/api/hang");
    return request;
}

/// Runs the loop from inside a callback until @p done; whether it came. Nine seconds without it are a failure of the
/// case, recorded here and naming @p what: the kit's wait, which the battery can fail. A loop turn that never returns is
/// bounded by a watchdog that ends the process, saying so.
template <typename Done>
bool
run_the_loop_until(Done &&done, char const *const what, std::source_location const where = std::source_location::current()) {
    qb::http::test::fail_wait::called_from const caller{where};
    qb::http::test::watchdog                     bound(what, 10s);
    return qb::http::test::expect_until(std::forward<Done>(done), 9s, what, [] { qb::io::async::run(EVRUN_NOWAIT); });
}

/// What one request was answered with.
struct Answer {
    int              count  = 0;
    qb::http::status status = qb::http::status::OK;
    std::string      body;

    void
    operator()(qb::http::Response response) {
        ++count;
        status = response.status();
        body   = response.body().as<std::string>();
    }
};

// A request pushed from the callback of a connect() that failed is the next attempt's: it is not answered with the error
// of the attempt that failed, which it never rode. The connect() callbacks were called before the client took its
// requests out, so the pass that followed failed the request just pushed -- "Connection failed: TCP/SSL connection
// failed" -- while the attempt that push had started went on, for nobody (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedFromACallbackOfAFailedConnectIsNotFailedWithThatAttempt) {
    Answer                        answer; // before the client, which answers what it still holds when it is destroyed
    bool                          told = false;
    std::string                   why;
    std::unique_ptr<ServerThread> server;
    const auto                    port   = qb::http::test::ephemeral_port(); // bound then closed: refused
    auto                          client = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &error) {
        if (ok || std::exchange(told, true))
            return;
        why    = error;
        server = reconnect::make_h2_server_on(port); // there for the next attempt
        if (server->ready())
            client->push_request(reconnect::get_test(), std::ref(answer));
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return answer.count != 0; }, 10s));
    ASSERT_TRUE(server && server->ready()) << "no server on the port that refused: the case proves nothing";
    EXPECT_EQ(why, "TCP/SSL connection failed");
    EXPECT_EQ(answer.count, 1);
    EXPECT_EQ(answer.status, qb::http::status::OK) << answer.body;
}

// The same with the automatic reconnection on: the request queues for the attempt the run schedules, as one pushed from
// the failure callback of a request does, and that attempt serves it. The connect() callbacks were called outside the
// failure pass: the push connected on its own, at once, and the pass that followed failed it (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedFromACallbackOfAFailedConnectQueuesForTheReconnectionRun) {
    Answer                        answer; // before the client, which answers what it still holds when it is destroyed
    bool                          told = false, connecting_after_push = true, reconnecting_after_callback = false;
    std::unique_ptr<ServerThread> server;
    const auto                    port   = qb::http::test::ephemeral_port(); // bound then closed: refused
    auto                          client = reconnect::make_client_for(port);
    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_initial_delay(50ms).with_jitter(false));
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &) {
        if (ok || std::exchange(told, true))
            return;
        server = reconnect::make_h2_server_on(port); // there for the next attempt
        if (!server->ready())
            return;
        client->push_request(reconnect::get_test(), std::ref(answer));
        connecting_after_push = client->is_connecting();
    }));
    ASSERT_TRUE(ServerThread::pump_until(
        [&] {
            reconnecting_after_callback = reconnecting_after_callback || client->is_reconnecting();
            return answer.count != 0;
        },
        10s));
    ASSERT_TRUE(server && server->ready()) << "no server on the port that refused: the case proves nothing";
    EXPECT_FALSE(connecting_after_push) << "a push from a callback of a failure must not connect on its own";
    EXPECT_TRUE(reconnecting_after_callback) << "no attempt was scheduled for the request";
    EXPECT_EQ(answer.count, 1);
    EXPECT_EQ(answer.status, qb::http::status::OK) << answer.body;
}

// A failure pass is open until the failure that opened it has called its last callback, whatever failed meanwhile: a
// callback of a connect() that failed asks connect() again and runs the loop until that attempt fails too -- a failure
// inside the failure, with its own callbacks --, then pushes a request, which still queues for the run (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedAfterAFailureInsideACallbackOfAFailureStillQueuesForTheRun) {
    Answer                        answer; // before the client, which answers what it still holds when it is destroyed
    bool                          told = false, asked = false, inner_answered = false, inner_ok = true, connecting_after_push = true;
    std::unique_ptr<ServerThread> server;
    const auto                    port   = qb::http::test::ephemeral_port(); // bound then closed: refused
    auto                          client = reconnect::make_client_for(port);
    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_initial_delay(50ms).with_jitter(false));
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &) {
        if (ok || std::exchange(told, true))
            return;
        asked = client->connect([&](bool ok_again, const std::string &) {
            inner_answered = true;
            inner_ok       = ok_again;
        });
        if (!asked)
            return; // refused, and never answered: the destructor of a case that failed answers this callback
        run_the_loop_until([&] { return inner_answered; }, "the loop a callback of a failed connect() runs until the next attempt fails");
        server = reconnect::make_h2_server_on(port); // there for the attempt the run schedules
        if (!server->ready())
            return;
        client->push_request(reconnect::get_test(), std::ref(answer));
        connecting_after_push = client->is_connecting();
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return answer.count != 0; }, 10s));
    ASSERT_TRUE(server && server->ready()) << "no server on the port that refused: the case proves nothing";
    ASSERT_TRUE(asked && inner_answered && !inner_ok) << "no failure inside the failure's callback: the case proves nothing";
    EXPECT_FALSE(connecting_after_push) << "the failure inside closed the pass of the failure around it";
    EXPECT_EQ(answer.count, 1);
    EXPECT_EQ(answer.status, qb::http::status::OK) << answer.body;
}

/// What a callback of a close did while the close waited for it: asked connect(), then ran the loop until the answer.
struct NextConnection {
    bool   asked = false, answered = false, up = false;
    Answer riding; ///< a request pushed once the next connection is up, never answered by the server: only that connection's end fails it

    void
    ask(qb::http2::Client &client, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        asked = client.connect([this, &client](bool ok, const std::string &) {
            answered = true;
            up       = ok;
            if (ok)
                client.push_request(hang(), std::ref(riding));
        });
        if (asked) // refused by a client being destroyed: nothing will answer
            run_the_loop_until([this] { return answered; }, "the loop a callback of a close runs until its connect() is answered");
    }

    /// The connection the callback saw come up is still the client's: a round trip on it -- by its answer every loop turn
    /// a close fed before it would need has run --, and the request that rides it is still unanswered.
    void
    expect_left_open(qb::http2::Client &client, Answer &probe, std::source_location const where = std::source_location::current()) const {
        qb::http::test::fail_wait::called_from const caller{where};
        ASSERT_TRUE(asked && up) << "the next connection did not come up inside the callback: the case proves nothing";
        ASSERT_TRUE(client.push_request(reconnect::get_test(), std::ref(probe)));
        EXPECT_TRUE(ServerThread::pump_until([&] { return probe.count != 0; }, 5s));
        EXPECT_EQ(probe.status, qb::http::status::OK) << probe.body;
        EXPECT_EQ(riding.count, 0) << "the close of one connection ended the next: " << riding.body;
        EXPECT_TRUE(client.is_connected());
    }
};

// A request pushed from the callback of a connect() that a close refused is new work: the close does not fail it. Here
// the program's disconnect() ends an attempt in flight; its connect() hears "Connection closed" and pushes a request, which
// connects on its own and is served. close_connection() called the connect() callbacks before it took the requests out, as
// the failed connect did: the request was failed with "Connection closed" (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedFromACallbackOfAConnectACloseRefusedIsNotFailedWithThatClose) {
    Answer      answer; // before the client, which answers what it still holds when it is destroyed
    int         told = 0;
    std::string why;
    auto        client = make_test_client();
    client->set_auto_reconnect(false);
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &error) {
        if (ok || ++told != 1)
            return;
        why = error;
        client->push_request(reconnect::get_test(), std::ref(answer));
    }));
    client->disconnect(); // the connector is in flight
    ASSERT_EQ(told, 1);
    EXPECT_EQ(why, "Connection closed");
    ASSERT_TRUE(ServerThread::pump_until([&] { return answer.count != 0; }, 10s));
    EXPECT_EQ(answer.count, 1);
    EXPECT_EQ(answer.status, qb::http::status::OK) << answer.body;
}

/// Runs the loop from inside a callback until the client's transport has ended -- the peer's end is read there; a
/// transport still open after nine seconds is a failure of the case, recorded by the wait.
inline bool
run_the_loop_until_the_transport_ends(qb::http2::Client &client, std::source_location const where = std::source_location::current()) {
    qb::http::test::fail_wait::called_from const caller{where};
    return run_the_loop_until([&] { return !client.transport().is_open(); }, "the loop a callback of a close runs until the peer's end");
}

// A close ends the transport it found and no other. It calls the callbacks of what it ends before it ends that transport:
// one that runs the loop until the peer has ended the connection, then asks connect() and runs the loop until the answer,
// sees the next connection come up. The close, resumed, then ended the transport the client held: the next connection,
// closed by the close of the one before it. Here the program's disconnect() ends a connection whose TLS is up and whose
// peer -- silent, gone 400 ms later -- never sent its SETTINGS (Huly QB-1246).
TEST_F(Http2ClientTest, ACloseWhoseCallbackSawTheNextConnectionComeUpLeavesThatConnectionOpen) {
    Answer                        probe; // before the client, which answers what it still holds when it is destroyed
    NextConnection                next;
    int                           told = 0;
    std::string                   why;
    std::unique_ptr<ServerThread> server;
    auto                          peer = std::make_unique<qb::http::test::TlsClosingPeer>(1, 0, std::vector<std::string>{"h2"}, 400ms);
    const auto                    port = peer->port();
    ASSERT_NE(port, 0);
    auto client = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &error) {
        if (ok || ++told != 1)
            return;
        why = error;
        run_the_loop_until_the_transport_ends(*client);
        peer.reset();                                // its one connection is over: the port is free
        server = reconnect::make_h2_server_on(port); // and speaks h2 from here on
        if (server->ready())
            next.ask(*client);
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return client->transport().is_open(); })) << "TLS did not come up";
    if (!client->transport().is_open() || told != 0)
        GTEST_SKIP() << "the host ran too slowly: the peer ended the connection before the test could close it";
    client->disconnect(); // TLS up, no SETTINGS: a transport to end, and nothing to announce
    ASSERT_EQ(told, 1);
    EXPECT_EQ(why, "Connection closed");
    ASSERT_TRUE(server && server->ready()) << "no h2 server on the port the peer left: the case proves nothing";
    next.expect_left_open(*client, probe);
}

// The same for a connect deadline that expires once TLS is up, which ends the transport: the peer never sends its
// SETTINGS and ends the connection a little after the deadline (Huly QB-1246).
TEST_F(Http2ClientTest, AConnectDeadlineWhoseCallbackSawTheNextConnectionComeUpLeavesThatConnectionOpen) {
    Answer                        probe; // before the client, which answers what it still holds when it is destroyed
    NextConnection                next;
    int                           told          = 0;
    bool                          open_at_entry = false;
    std::string                   why;
    std::unique_ptr<ServerThread> server;
    // One connection, held 1500 ms past its TLS handshake with no SETTINGS, then ended: it outlives the 700 ms deadline.
    auto       peer = std::make_unique<qb::http::test::TlsClosingPeer>(1, 0, std::vector<std::string>{"h2"}, 1500ms);
    const auto port = peer->port();
    ASSERT_NE(port, 0);
    auto client = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    client->set_connect_timeout(700ms);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &error) {
        if (ok || ++told != 1)
            return;
        why           = error;
        open_at_entry = client->transport().is_open(); // the deadline found TLS done: a transport to end
        if (!open_at_entry)
            return;
        run_the_loop_until_the_transport_ends(*client);
        peer.reset();                                // its one connection is over: the port is free
        server = reconnect::make_h2_server_on(port); // and speaks h2 from here on
        client->set_connect_timeout(5s);
        if (server->ready())
            next.ask(*client);
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return told != 0; }, 10s));
    if (!open_at_entry)
        GTEST_SKIP() << "the host ran too slowly: the 700 ms deadline fired before the TLS handshake, no transport to end";
    EXPECT_EQ(why, "Connection timeout");
    ASSERT_TRUE(server && server->ready()) << "no h2 server on the port the peer left: the case proves nothing";
    next.expect_left_open(*client, probe);
}

// The same for the end of a graceful GOAWAY's drain: the peer names the request's stream in its GOAWAY, never answers it
// and ends the connection a little later; the request's deadline fails it, its callback pushes another, which the drain's
// end fails -- automatic reconnection off --, and that failure's callback runs the loop until the peer's end, then asks
// connect() -- an h2 server on the port by then -- and runs the loop until the answer (Huly QB-1246).
TEST_F(Http2ClientTest, AGracefulGoawaysDrainWhoseCallbackSawTheNextConnectionComeUpLeavesThatConnectionOpen) {
    Answer                        probe; // before the client, which answers what it still holds when it is destroyed
    NextConnection                next;
    int                           first = 0, failed = 0;
    bool                          up = false, ended_in_the_callback = false;
    std::string                   failure;
    std::unique_ptr<ServerThread> server;
    auto       planned = std::make_unique<qb::http::test::Http2PlannedPeer>(qb::http::test::Http2PlannedPeer::Plan::goaway_then_close, 30s);
    const auto port    = planned->port();
    ASSERT_NE(port, 0);
    auto client = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    client->set_request_timeout(200ms); // from here: the connection is up, the deadline bounds the request alone
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
        ++first;
        // The connection drains: a request pushed now waits for the drain's end, which fails it.
        EXPECT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
            if (++failed != 1)
                return;
            failure = response.body().as<std::string>();
            client->set_request_timeout(qb::duration::zero()); // no deadline for what rides the next connection
            ended_in_the_callback =
                run_the_loop_until([&] { return !client->transport().is_open(); }, "the loop a callback of a drain runs until the peer's end");
            planned.reset();                             // the port is free
            server = reconnect::make_h2_server_on(port); // and serves from here on
            if (server->ready())
                next.ask(*client);
        }));
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return failed != 0; }, 10s));
    EXPECT_EQ(first, 1);
    EXPECT_EQ(failure, "Server sent GOAWAY and automatic reconnection is disabled");
    ASSERT_TRUE(ended_in_the_callback);
    ASSERT_TRUE(server && server->ready()) << "no h2 server on the port the peer left: the case proves nothing";
    next.expect_left_open(*client, probe);
}

// A connect() asked from a callback of a connection that was lost starts once the teardown of that connection is over:
// never under it. The callback is called from the handler of the transport's end, which the io runs while it disposes
// of the connection; connect() started its connector at once, and a callback that then ran the loop saw the attempt
// complete and the next transport start under that teardown -- which stops the io's watcher on its way out: a
// connection that came up and never read again (a debug assertion of qb-io, `io::start() from inside dispose()`). Now
// nothing answers inside the callback, and the connection it asked serves once it has returned (Huly QB-1246).
TEST_F(Http2ClientTest, AConnectAskedFromACallbackOfALostConnectionThatRunsTheLoopStartsAfterTheTeardown) {
    Answer first, probe; // before the client, which answers what it still holds when it is destroyed
    bool   up = false, asked = false, answered = false, again = false, answered_in_the_callback = true, connecting = false;
    std::unique_ptr<ServerThread> server;
    auto                          client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response response) {
        first(std::move(response));
        if (first.count != 1)
            return;
        server = reconnect::make_h2_server_on(_port); // the port the fixture's server left
        if (!server->ready())
            return;
        asked      = client->connect([&](bool ok, const std::string &) {
            answered = true;
            again    = ok;
        });
        connecting = client->is_connecting();
        // Long enough for an attempt started here to connect: TLS and SETTINGS on the loopback.
        qb::http::test::discard(qb::http::test::wait_until([&] { return answered; }, 500ms),
                                "a window: answered_in_the_callback records what it saw, which the case asserts");
        answered_in_the_callback = answered;
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == 1; }));
    _server.reset(); // the server goes: the connection is lost
    ASSERT_TRUE(ServerThread::pump_until([&] { return first.count != 0; }, 10s));
    EXPECT_NE(first.body.find("Connection lost"), std::string::npos) << first.body;
    ASSERT_TRUE(server && server->ready()) << "no h2 server on the port the fixture's left: the case proves nothing";
    ASSERT_TRUE(asked);
    EXPECT_TRUE(connecting) << "a connect() that waits for the teardown is still a connection being made";
    EXPECT_FALSE(answered_in_the_callback) << "the attempt connected under the teardown of the connection that was lost";
    ASSERT_TRUE(ServerThread::pump_until([&] { return answered; }, 5s));
    EXPECT_TRUE(again);
    ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(probe)));
    EXPECT_TRUE(ServerThread::pump_until([&] { return probe.count != 0; }, 5s)) << "the connection came up and reads nothing";
    EXPECT_EQ(probe.status, qb::http::status::OK) << probe.body;
}

// ---- One queue of the answers the client owes (Huly QB-1246) ----

/// A request for another origin: refused where it is pushed, 400.
qb::http::Request
elsewhere() {
    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("https://other.invalid/");
    return request;
}

/// Runs the loop for @p span: the client's turns, and what the connection brings.
inline void
settle(std::chrono::milliseconds const span = 50ms, std::source_location const where = std::source_location::current()) {
    qb::http::test::fail_wait::called_from const caller{where};
    for (const auto until = std::chrono::steady_clock::now() + span; std::chrono::steady_clock::now() < until;)
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
}

/// A client that tells when it is destroyed.
struct Told : qb::http2::Client {
    int &destroyed;
    Told(std::string const &origin, int &count)
        : qb::http2::Client(origin)
        , destroyed(count) {}
    ~Told() {
        ++destroyed;
    }
};

/// A callback that pushes its request back at every refusal -- it never gives up -- and then does one thing more.
struct Relaunch {
    std::function<qb::http::Request()> request = elsewhere; ///< the request the client refuses
    int                                pushes = 0, calls = 0, depth = 0, deepest = 0, cap = 200;
    int                                loop_turns         = 0; ///< the loop turns this callback is running, one inside the other
    int                                deepest_loop_turns = 0; ///< the most of them a call found on the stack
    int                                under_another      = 0; ///< calls made under another one with no such turn between the two
    std::function<void()>              then               = [] {
    }; ///< what the callback does once it has pushed its request back
    std::shared_ptr<qb::http2::Client> client; ///< last, so destroyed first: its destructor still calls `request` and `then`

    void
    push() {
        ++pushes;
        client->push_request(request(), [this](qb::http::Response response) {
            EXPECT_NE(response.status(), qb::http::status::OK);
            deepest            = std::max(deepest, ++depth);
            deepest_loop_turns = std::max(deepest_loop_turns, loop_turns);
            under_another += depth != loop_turns + 1;
            if (++calls < cap) {
                push(); // refused at once, and kept for the client's turn: pushed from a callback
                then();
            }
            --depth;
        });
    }

    void
    run_the_loop(std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        ++loop_turns;
        for (int pass = 0; pass < 4; ++pass) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        }
        --loop_turns;
    }
};

// A callback that pushes its request back at every refusal is never called from inside its own push: the refusal of a
// request pushed from a callback of the client is heard on the client's turn, one loop turn later. Three refusals the
// client gives by itself -- a request for another origin, one past the bound of the queue, one the connection cannot
// take (the server's limit of concurrent streams) -- and the exact count: one push, one answer, never two deep. Answered
// inside the push, the callback was called from inside the call it had just made, one frame deeper at every refusal: as
// deep as the case lets it go, all of it inside the push the program made (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedBackAtEveryRefusalIsNeverAnsweredFromInsideItsOwnPush) {
    for (const std::string_view refusal : {"another origin", "the bound of the queue", "a send the connection cannot take"}) {
        SCOPED_TRACE(refusal);
        int      held = 0, warm = 0; // before the client: its callbacks count here
        bool     up = false;
        Relaunch r;
        r.client = make_test_client();
        r.client->set_auto_reconnect(false);
        r.client->set_request_timeout(qb::duration::zero());
        if (refusal == "the bound of the queue") {
            r.client->set_max_pending_requests(0);
            r.request = reconnect::get_test;
        } else if (refusal == "a send the connection cannot take") {
            r.client->connect([&](bool ok, const std::string &) { up = ok; });
            ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
            // A round trip first: the server's limit of concurrent streams comes with its SETTINGS.
            r.client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++warm; });
            ASSERT_TRUE(ServerThread::pump_until([&] { return warm == 1; }));
            r.client->set_max_concurrent_streams(200); // the client would send more than the server takes
            const auto before = _server->server().hang_routed();
            for (int i = 0; i < 100 && r.client->get_active_request_count() == static_cast<std::size_t>(i); ++i)
                r.client->push_request(hang(), [&](qb::http::Response) { ++held; }); // each takes a stream, to the server's limit
            const auto streams = static_cast<int>(r.client->get_active_request_count());
            ASSERT_GT(streams, 0);
            ASSERT_LT(streams, 100) << "the server took every stream: nothing is refused";
            ASSERT_EQ(held, 1) << "the request past the server's limit was not refused where it was pushed";
            ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + streams; }));
            r.request = hang;
            r.cap     = 40;
        }
        r.push();
        EXPECT_EQ(r.calls, 1) << "the push the program makes is refused inside it, and nothing else is heard there";
        EXPECT_EQ(r.pushes, 2);
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT); // one loop turn: one turn of the client
        EXPECT_EQ(r.calls, 2) << "a turn of the client hears what was owed as it started, and no more";
        ASSERT_TRUE(ServerThread::pump_until([&] { return r.calls == r.cap; }));
        settle();
        EXPECT_EQ(r.calls, r.cap);
        EXPECT_EQ(r.pushes, r.cap) << "every push is answered once";
        EXPECT_EQ(r.deepest, 1) << "the callback was called from inside a push it made";
        r.client->disconnect();
    }
}

// The same callback, which then makes a call the client answers by itself -- an empty batch, a connect() on a client that
// is connected --, is never called under itself: such an answer takes its place behind the refusal kept for the client's
// turn. Given inside the call, it heard that refusal first (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedBackThenACallTheClientAnswersByItselfIsNeverAnsweredUnderItsCallback) {
    for (const std::string_view call : {"an empty batch", "a connect() on a connected client"}) {
        SCOPED_TRACE(call);
        int      answered = 0, answered_under_the_callback = 0; // before the client: its callbacks count here
        bool     up = false;
        Relaunch r;
        r.client = make_test_client();
        r.client->set_auto_reconnect(false);
        if (call == "an empty batch") {
            r.then = [&] {
                EXPECT_TRUE(r.client->push_requests({}, [&](std::vector<qb::http::Response> responses) {
                    EXPECT_TRUE(responses.empty());
                    ++answered;
                    answered_under_the_callback += r.depth != 0;
                }));
            };
        } else {
            r.client->connect([&](bool ok, const std::string &) { up = ok; });
            ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
            r.then = [&] {
                EXPECT_TRUE(r.client->connect([&](bool ok, const std::string &) {
                    EXPECT_TRUE(ok);
                    ++answered;
                    answered_under_the_callback += r.depth != 0;
                }));
            };
        }
        r.push();
        EXPECT_EQ(r.calls, 1) << "the push the program makes is refused inside it, and nothing else is heard there";
        EXPECT_EQ(answered, 0) << "an answer the client gives by itself was given under a callback of this client";
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT); // one loop turn: one turn of the client
        EXPECT_EQ(r.calls, 2) << "a turn of the client hears what was owed as it started, and no more";
        EXPECT_EQ(answered, 1);
        ASSERT_TRUE(ServerThread::pump_until([&] { return r.calls == r.cap; }));
        settle();
        EXPECT_EQ(r.calls, r.cap);
        EXPECT_EQ(r.pushes, r.cap) << "every push is answered once";
        EXPECT_EQ(answered, r.cap - 1) << "one for each call that pushed back";
        EXPECT_EQ(answered_under_the_callback, 0);
        EXPECT_EQ(r.deepest, 1) << "the callback was called from inside a call it made";
        r.client->disconnect();
    }
}

// The same callback while ten other requests of the client time out in the queue, in two shapes (Huly QB-1246).
// Returning once it has pushed back, it is never called inside another call of this client: every call is exactly one
// deep, whatever the loop brings in between -- the ten timeouts, and the refusals that keep coming. Running the loop
// itself once it has pushed back -- qb::io::async::run() here; run_once(), run_until() and run_sync() are such turns
// too --, it receives inside that loop whatever the client owes, the refusal it has just earned included: it recurses
// once for each refusal, and that recursion is the program's. So that shape checks an invariant, not a depth: every
// call finds on the stack the loop turns this callback is itself running, and one call more. Every push is answered
// once in both shapes: the ten the timeouts make, and one for each call before the sixtieth.
TEST_F(Http2ClientTest, ARequestPushedBackWhileOthersTimeOutIsCalledUnderItselfOnlyThroughTheLoopTurnsItsCallbackRuns) {
    for (const bool runs_the_loop : {false, true}) {
        SCOPED_TRACE(runs_the_loop ? "the callback runs the loop" : "the callback returns");
        int      timed_out = 0; // before the client: its callbacks count here
        Relaunch r;
        // TLS comes up and the peer never sends its SETTINGS: the requests wait in the queue, behind a connection.
        qb::http::test::TlsClosingPeer silent(1, 0, std::vector<std::string>{"h2"}, 15s);
        ASSERT_NE(silent.port(), 0);
        r.client = reconnect::make_client_for(silent.port());
        r.client->set_auto_reconnect(false);
        r.client->set_connect_timeout(20s);
        r.client->set_request_timeout(150ms);
        r.cap  = 60;
        r.then = [&] {
            if (runs_the_loop) {
                r.run_the_loop();
            }
        };
        for (int i = 0; i < 10; ++i) {
            r.client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
                EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT);
                ++timed_out; // runs no loop turn, and is not counted in the depth: the callback that pushes back is
                r.push();
            });
        }
        ASSERT_TRUE(ServerThread::pump_until([&] { return timed_out == 10 && r.calls == r.pushes && r.calls >= r.cap; }, 10s));
        settle();
        EXPECT_EQ(timed_out, 10);
        EXPECT_EQ(r.pushes, 69) << "the ten the timeouts made, and one for each of the fifty-nine calls that pushed back";
        EXPECT_EQ(r.calls, 69) << "every push is answered once";
        EXPECT_EQ(r.under_another, 0) << "a call of the callback found something else on the stack than the loop turns it runs itself";
        EXPECT_EQ(r.deepest, r.deepest_loop_turns + 1);
        if (runs_the_loop) {
            RecordProperty("deepest", r.deepest); // measured, not asserted: the recursion of the program, which the loop it runs allows
            RecordProperty("deepest_loop_turns", r.deepest_loop_turns);
        } else {
            EXPECT_EQ(r.deepest_loop_turns, 0);
            EXPECT_EQ(r.deepest, 1) << "a callback that runs no loop turn was called inside another call of this client";
        }
        r.client->disconnect();
    }
}

// An answer the client gives by itself waits for the client's turn under any callback of this client, with nothing owed
// too (Huly QB-1246): given inside the call, the callback of a `connect()`, of an empty batch or of a batch refused
// whole ran under the callback that made the call.
TEST_F(Http2ClientTest, AnAnswerTheClientGivesByItselfIsNotGivenUnderACallbackOfThisClient) {
    for (const std::string_view call : {"an empty batch", "a batch refused whole", "a connect() on a connected client"}) {
        SCOPED_TRACE(call);
        int  heard = 0, heard_inside_the_call = -1; // before the client: its callbacks count here
        bool up     = false;
        auto client = make_test_client();
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        client->push_request(elsewhere(), [&](qb::http::Response) {
            // Answered inside the program's push: one callback of this client on the stack, and nothing owed.
            if (call == "an empty batch") {
                EXPECT_TRUE(client->push_requests({}, [&](std::vector<qb::http::Response>) { ++heard; }));
            } else if (call == "a batch refused whole") {
                std::vector<qb::http::Request> two;
                two.push_back(elsewhere());
                two.push_back(elsewhere());
                EXPECT_TRUE(client->push_requests(std::move(two), [&](std::vector<qb::http::Response> responses) {
                    EXPECT_EQ(responses.size(), 2u);
                    ++heard;
                }));
            } else {
                EXPECT_TRUE(client->connect([&](bool, const std::string &) { ++heard; }));
            }
            heard_inside_the_call = heard;
        });
        EXPECT_EQ(heard_inside_the_call, 0) << "an answer the client gives by itself was given under a callback of this client";
        settle();
        EXPECT_EQ(heard, 1);
        client->disconnect();
    }
}

// The failures of a disconnect() are answers the client gives by itself, as a cancellation's is: the program asked for
// them (Huly QB-1246). Called from a callback of this client, disconnect() gives them on the client's turn -- the
// failure of a request, the answer of a batch, the `false` of a connect() still waiting --; called with no callback on
// the stack and nothing owed, inside the call, as before. They were the loop's answers, given inside the call whoever
// made it -- 3.3.0 gave them so too --: an answer of the client ran inside another with no loop turn of the program's.
TEST_F(Http2ClientTest, TheFailuresOfADisconnectACallbackCallsAreHeardOnTheClientsTurn) {
    for (const std::string_view what : {"a request in flight", "a batch in flight", "a request in the queue", "a connect() still waiting"}) {
        SCOPED_TRACE(what);
        int  heard = 0, heard_inside_the_call = -1; // before the client: its callbacks count here
        int  asked  = 0;                            // the requests the server must have routed before the close
        auto client = make_test_client();
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        const auto routed = _server->server().hang_routed();
        const auto start  = [&] {
            if (what == "a request in the queue") { // behind the connection its push asks for: closed before the loop turns
                client->push_request(hang(), [&](qb::http::Response) { ++heard; });
            } else if (what == "a request in flight") {
                client->push_request(hang(), [&](qb::http::Response) { ++heard; });
                asked += 1;
            } else if (what == "a batch in flight") {
                std::vector<qb::http::Request> two;
                two.push_back(hang());
                two.push_back(hang());
                client->push_requests(std::move(two), [&](std::vector<qb::http::Response> responses) {
                    EXPECT_EQ(responses.size(), 2u);
                    ++heard;
                });
                asked += 2;
            } else {
                EXPECT_TRUE(client->connect([&](bool ok, const std::string &) {
                    EXPECT_FALSE(ok);
                    ++heard;
                }));
            }
        };
        const auto under_way = [&] {
            return what == "a connect() still waiting" || what == "a request in the queue" ? client->is_connecting()
                                                                                           : _server->server().hang_routed() == routed + asked;
        };
        start();
        ASSERT_TRUE(ServerThread::pump_until(under_way));
        client->push_request(elsewhere(), [&](qb::http::Response) { // answered inside the push
            client->disconnect();
            heard_inside_the_call = heard;
        });
        EXPECT_EQ(heard_inside_the_call, 0) << "an answer of a disconnect() was heard under the callback that called it";
        EXPECT_EQ(heard, 0);
        settle();
        EXPECT_EQ(heard, 1);
        start(); // and with no callback on the stack and nothing owed: inside the call
        ASSERT_TRUE(ServerThread::pump_until(under_way));
        client->disconnect();
        EXPECT_EQ(heard, 2) << "the program's own disconnect() did not answer inside the call";
        settle();
    }
}

// A callback that pushes its request back at every failure and then calls disconnect() is never called under itself
// (Huly QB-1246). The request it has just pushed is accepted, for the next connection, and its disconnect() ends it:
// that failure is the client's own answer, heard on the client's turn. Given inside the disconnect(), the callback was
// called from inside the call it had just made, one frame deeper at every failure, all of it inside the one
// disconnect() the program made.
TEST_F(Http2ClientTest, ARequestPushedBackThenADisconnectFromItsCallbackIsNeverCalledUnderItself) {
    int                   calls = 0, pushes = 0, depth = 0, deepest = 0, calls_inside_the_programs_disconnect = -1; // before the client
    const int             cap = 100;
    std::function<void()> push; // before the client too: its callbacks call it
    auto                  client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    push = [&] {
        ++pushes;
        client->push_request(hang(), [&](qb::http::Response response) {
            EXPECT_NE(response.status(), qb::http::status::OK);
            deepest = std::max(deepest, ++depth);
            if (++calls < cap) {
                push();               // accepted: queued for the next connection
                client->disconnect(); // ends it
            }
            --depth;
        });
    };
    push();
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == 1; }));
    client->disconnect(); // the program's own: its request in flight fails inside this call
    calls_inside_the_programs_disconnect = calls;
    EXPECT_EQ(calls_inside_the_programs_disconnect, 1)
        << "the failures of the disconnect() its callback called were heard inside the program's";
    ASSERT_TRUE(ServerThread::pump_until([&] { return calls == cap; }, 10s));
    settle();
    EXPECT_EQ(calls, cap);
    EXPECT_EQ(pushes, cap) << "every push is answered once";
    EXPECT_EQ(deepest, 1) << "the callback was called from inside a disconnect() it made";
}

// The other order, with ten requests in flight: every failure callback resets the connection, then pushes its request
// back -- disconnect(), then push --, and the program calls disconnect() once. Each of the ten is failed once, one deep;
// each disconnect() a callback makes ends the request the callback before it pushed back, and that failure waits for
// the client's turn, as every answer after it does. Given inside the call, each nested close ran the retries of the ones before it:
// 2^n - 1 calls for n requests (Huly QB-1246).
TEST_F(Http2ClientTest, TenRequestsThatEachResetTheConnectionAndRetryAreEachFailedOnceAndOneDeep) {
    int                   calls = 0, heard = 0, pushes = 0, depth = 0, deepest = 0; // before the client
    bool                  stop = false;
    std::function<void()> push; // before the client too: its callbacks call it
    auto                  client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    push = [&] {
        ++pushes;
        client->push_request(hang(), [&](qb::http::Response response) {
            EXPECT_NE(response.status(), qb::http::status::OK);
            deepest = std::max(deepest, ++depth);
            ++heard;
            if (!stop && ++calls < 20000) {
                client->disconnect(); // reset the connection
                push();               // and try again: accepted, queued for the next connection
            }
            --depth;
        });
    };
    for (int i = 0; i < 10; ++i) {
        push();
    }
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == 10; }));
    client->disconnect(); // the program's own
    // Two inside the call, each one deep: the second callback's disconnect() ends the retry of the first, whose failure is
    // then owed, and the eight other requests' failures take their place behind it.
    EXPECT_EQ(calls, 2) << "a failure was heard inside the program's disconnect() with another one owed before it";
    EXPECT_EQ(deepest, 1);
    stop = true; // what is still owed is heard, and pushes nothing back
    settle();
    client->disconnect(); // ends the last request pushed back
    settle();
    EXPECT_EQ(pushes, 12) << "the ten requests, and the retries of the two heard before the program stopped";
    EXPECT_EQ(heard, 12) << "every push is answered once";
    EXPECT_EQ(deepest, 1);
}

/// A coroutine that earns a refusal -- kept for the client's turn when it runs under a callback of the client --, then
/// awaits a push of its own, or a batch, and says when it got past it.
qb::io::async::task<void>
refused_then_awaits(qb::http2::Client &client, std::vector<int> &order, int kept, int done, bool batch) {
    client.push_request(elsewhere(), [&order, kept](qb::http::Response) { order.push_back(kept); });
    if (batch) {
        std::vector<qb::http::Request> two;
        two.push_back(reconnect::get_test());
        two.push_back(reconnect::get_test());
        static_cast<void>(co_await client.push_requests(std::move(two)));
    } else {
        static_cast<void>(co_await client.push_request(reconnect::get_test()));
    }
    order.push_back(done);
}

/// The same, awaiting connect(): from a callback of a close it completes `false` at once -- behind what is owed.
qb::io::async::task<void>
refused_then_connects(qb::http2::Client &client, std::vector<int> &order, int kept, int done) {
    client.push_request(elsewhere(), [&order, kept](qb::http::Response) { order.push_back(kept); });
    const auto connected = co_await client.connect();
    order.push_back(connected ? -done : done);
}

// The answers come in the order the client came to owe them (Huly QB-1246): one queue, oldest first, heard on the
// client's turn. While a refusal is kept for that turn, every answer that comes after it takes its place behind it --
// the refusal of a push the program makes next, an empty batch, the failures of a disconnect() the same callback
// calls, the `false` of a connect() that close gives up, a coroutine push completed at once, a timeout, a response. Each
// of those was given at once, ahead of the refusal still waiting for its turn.
TEST_F(Http2ClientTest, ARefusalKeptIsHeardBeforeAnyAnswerGivenAfterIt) {
    {
        SCOPED_TRACE("a refusal of the program's next push");
        std::vector<int> order; // declared before the client: its destructor may still hear a refusal
        auto             client = make_test_client();
        client->push_request(elsewhere(), [&](qb::http::Response) {
            order.push_back(1);
            client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // kept: pushed from a callback
        });
        EXPECT_EQ(order, (std::vector<int>{1}));
        client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(3); }); // behind what is owed
        EXPECT_EQ(order, (std::vector<int>{1})) << "an answer was given inside the push with another one owed before it";
        settle();
        EXPECT_EQ(order, (std::vector<int>{1, 2, 3}));
    }
    {
        SCOPED_TRACE("an empty batch the same callback pushes");
        std::vector<int> order; // declared before the client: its destructor may still hear a refusal
        auto             client = make_test_client();
        client->push_request(elsewhere(), [&](qb::http::Response) {
            order.push_back(1);
            client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // kept
            client->push_requests({}, [&](std::vector<qb::http::Response>) { order.push_back(4); });
        });
        EXPECT_EQ(order, (std::vector<int>{1})) << "an empty batch was answered under a callback of this client";
        settle();
        EXPECT_EQ(order, (std::vector<int>{1, 2, 4}));
    }
    {
        SCOPED_TRACE("the failures of a disconnect() the same callback calls");
        std::vector<int> order; // declared before the client: its destructor may still hear a refusal
        auto             client = make_test_client();
        client->set_request_timeout(qb::duration::zero());
        const auto before = _server->server().hang_routed();
        client->push_request(hang(), [&](qb::http::Response) { order.push_back(5); }); // in flight
        ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 1; }));
        client->push_request(elsewhere(), [&](qb::http::Response) {
            order.push_back(1);
            client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // kept
            client->disconnect();                                                               // fails the request in flight
        });
        EXPECT_EQ(order, (std::vector<int>{1})) << "a failure of the close was given ahead of the refusal owed before it";
        settle();
        EXPECT_EQ(order, (std::vector<int>{1, 2, 5}));
    }
    {
        SCOPED_TRACE("the `false` of a connect() the close gives up");
        std::vector<int> order; // declared before the client: its destructor may still hear a refusal
        auto             client = make_test_client();
        ASSERT_TRUE(client->connect([&](bool ok, const std::string &) {
            EXPECT_FALSE(ok);
            order.push_back(7);
        }));
        ASSERT_TRUE(client->is_connecting());
        client->push_request(elsewhere(), [&](qb::http::Response) {
            order.push_back(1);
            client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // kept
            client->disconnect();                                                               // gives the connect() up
        });
        EXPECT_EQ(order, (std::vector<int>{1})) << "the callback of the connect() overtook the refusal owed before it";
        settle();
        EXPECT_EQ(order, (std::vector<int>{1, 2, 7}));
    }
    {
        SCOPED_TRACE("the coroutine pushes a callback of a close completes at once");
        std::vector<int> order; // declared before the client: its destructor may still hear a refusal
        auto             client = make_test_client();
        client->set_request_timeout(qb::duration::zero());
        const auto before = _server->server().hang_routed();
        client->push_request(hang(), [&](qb::http::Response) { // in flight: fails with the close
            order.push_back(9);
            qb::http::test::watchdog bound("run_sync() of a push from the callback of a close", 10s);
            // Each coroutine earns a refusal (3, then 5), kept for the client's turn, and awaits a push the close completes
            // at once: completed behind that refusal, by a loop turn run_sync() runs, it gets past its await after it.
            qb::io::async::run_sync(refused_then_awaits(*client, order, 3, 10, false));
            qb::io::async::run_sync(refused_then_awaits(*client, order, 5, 11, true));
            // And one that awaits connect(): its `false` at once is an answer the client gives by itself too (7, then 12).
            qb::io::async::run_sync(refused_then_connects(*client, order, 7, 12));
        });
        ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 1; }));
        client->disconnect();
        EXPECT_EQ(order, (std::vector<int>{9, 3, 10, 5, 11, 7, 12}))
            << "a coroutine push or connect() completed at once overtook the refusal owed before it";
        settle();
        EXPECT_EQ(order, (std::vector<int>{9, 3, 10, 5, 11, 7, 12}));
    }
    {
        SCOPED_TRACE("a timeout that comes while a refusal is owed");
        std::vector<int> order; // declared before the client: its destructor may still hear a refusal
        // TLS comes up and the peer never sends its SETTINGS: the two requests wait in the queue, and time out in one pass.
        qb::http::test::TlsClosingPeer silent(1, 0, std::vector<std::string>{"h2"}, 15s);
        ASSERT_NE(silent.port(), 0);
        auto client = reconnect::make_client_for(silent.port());
        client->set_auto_reconnect(false);
        client->set_connect_timeout(20s);
        client->set_request_timeout(100ms);
        client->push_request(reconnect::get_test(), [&](qb::http::Response) {
            order.push_back(1);
            client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // kept: pushed from a callback
        });
        client->push_request(reconnect::get_test(), [&](qb::http::Response response) { // the same pass: behind what is owed
            EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT);
            order.push_back(3);
        });
        ASSERT_TRUE(ServerThread::pump_until([&] { return order.size() == 3; }));
        EXPECT_EQ(order, (std::vector<int>{1, 2, 3})) << "the timeout overtook the refusal owed before it";
        client->disconnect();
    }
    {
        SCOPED_TRACE("a response that comes while the callback runs the loop");
        std::vector<int> order; // declared before the client: its destructor may still hear a refusal
        bool             up     = false;
        auto             client = make_test_client();
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        client->push_request(reconnect::get_test(), [&](qb::http::Response response) { // its response is on its way
            EXPECT_EQ(response.status(), qb::http::status::OK);
            order.push_back(9);
        });
        client->push_request(elsewhere(), [&](qb::http::Response) {
            order.push_back(1);
            client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // kept
            // The loop turns of this callback: the client's turn, and the response.
            qb::http::test::expect_until([&] { return order.size() >= 3; }, 5s);
        });
        EXPECT_EQ(order, (std::vector<int>{1, 2, 9})) << "the response overtook the refusal owed before it";
        client->disconnect();
    }
}

// An answer the client gives by itself is given inside the call while the client is destroyed, where no turn is left to
// keep it for (Huly QB-1246): an empty batch pushed from a callback the destructor runs.
TEST_F(Http2ClientTest, AnEmptyBatchPushedFromACallbackTheDestructorRunsIsAnsweredInsideThePush) {
    int answers = 0, batches = 0, batches_inside_the_push = -1;
    {
        auto client = make_test_client();
        client->push_request(reconnect::get_test(), [&, raw = client.get()](qb::http::Response) { // fails with the client
            ++answers;
            EXPECT_TRUE(raw->push_requests({}, [&](std::vector<qb::http::Response> responses) {
                EXPECT_TRUE(responses.empty());
                ++batches;
            }));
            batches_inside_the_push = batches;
        });
        ASSERT_TRUE(client->is_connecting()); // queued behind a connection the loop has not made
    } // destroyed with that request waiting
    EXPECT_EQ(answers, 1);
    EXPECT_EQ(batches_inside_the_push, 1) << "an answer was kept for a turn that a client being destroyed does not have";
    EXPECT_EQ(batches, 1);
}

// A request pushed from a callback the destructor runs is answered inside its push, and one pushed from inside THAT
// answer is refused by the return value alone, its callback destroyed unheard: no later turn exists to hear it on, and
// answered there a callback that always pushes again was called from inside its own push without end. Three pushes, two
// answers, never deeper than two; the same for a batch (Huly QB-1246).
TEST_F(Http2ClientTest, ARequestPushedBackFromTheDestructorsCallbacksEndsAtItsSecondPush) {
    for (const bool batch : {false, true}) {
        SCOPED_TRACE(batch ? "a batch" : "a request");
        int                   pushes = 0, answers = 0, depth = 0, deepest = 0;
        std::vector<bool>     accepted;
        qb::http2::Client    *raw = nullptr;
        std::function<void()> push;
        push = [&] {
            const auto index = static_cast<std::size_t>(pushes++); // a push returns after the ones its callback makes
            accepted.resize(index + 1);
            const auto heard = [&] {
                deepest = std::max(deepest, ++depth);
                ++answers;
                if (deepest < 64) {
                    push();
                }
                --depth;
            };
            if (batch) {
                std::vector<qb::http::Request> one;
                one.push_back(reconnect::get_test());
                accepted[index] = raw->push_requests(std::move(one), [&, heard](std::vector<qb::http::Response> responses) {
                    ASSERT_EQ(responses.size(), 1u);
                    EXPECT_NE(responses[0].status(), qb::http::status::OK);
                    heard();
                });
            } else {
                accepted[index] = raw->push_request(reconnect::get_test(), [&, heard](qb::http::Response response) {
                    EXPECT_NE(response.status(), qb::http::status::OK);
                    heard();
                });
            }
        };
        {
            auto client = make_test_client();
            raw         = client.get();
            push(); // queued behind a connection the loop has not made
            ASSERT_TRUE(client->is_connecting());
        } // destroyed with that request waiting
        EXPECT_EQ(pushes, 3);
        EXPECT_EQ(answers, 2);
        EXPECT_EQ(deepest, 2);
        EXPECT_EQ(accepted, (std::vector<bool>{true, true, false}));
    }
}

// Two refusals owed their turn when the client is destroyed with no turn left (Huly QB-1246): the destructor hears
// both, in order and alike. Each is a callback the destructor runs, so the request each pushes back is answered inside
// that push, 503, and accepted.
TEST_F(Http2ClientTest, TwoRefusalsOwedWhenTheClientIsDestroyedAreHeardAlike) {
    int               kept = 0, answers = 0;
    std::vector<int>  order;
    std::vector<bool> accepted;
    {
        auto        client = make_test_client(); // never connected
        auto *const raw    = client.get();
        raw->push_request(elsewhere(), [&, raw](qb::http::Response) {
            for (int i = 1; i <= 2; ++i) {
                raw->push_request(elsewhere(), [&, raw, i](qb::http::Response) { // kept for the client's turn
                    ++kept;
                    order.push_back(i);
                    accepted.push_back(raw->push_request(elsewhere(), [&, i](qb::http::Response response) {
                        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
                        ++answers;
                        order.push_back(10 * i);
                    }));
                });
            }
        });
        EXPECT_EQ(kept, 0) << "a refusal of a push made from a callback was heard inside the push";
    } // destroyed with both owed, and no turn of the loop
    EXPECT_EQ(kept, 2);
    EXPECT_EQ(answers, 2) << "a push made from a callback the destructor runs was not answered";
    EXPECT_EQ(accepted, (std::vector<bool>{true, true}));
    EXPECT_EQ(order, (std::vector<int>{1, 10, 2, 20})) << "each refusal owed, then the answer of the push its callback made";
}

// The callback of an answer heard on the client's turn may drop the last reference to the client (Huly QB-1246): the
// client lives to the end of that turn, through everything else the turn hears. Both ways of owning the client -- with
// the storage of the object in the control block, which a weak reference keeps, and apart from it, which a sanitizer
// then sees freed.
TEST_F(Http2ClientTest, AnEmptyBatchPushedWithARefusalOwedWhoseCallbackDropsTheLastReferenceEndsCleanly) {
    for (const std::string_view owned : {"in one block", "apart"}) {
        SCOPED_TRACE(owned);
        int         destroyed = 0, destroyed_when_the_batch_heard = -1, kept_heard = 0, batch_heard = 0;
        auto        client = owned == "apart" ? std::shared_ptr<Told>(new Told(url(), destroyed)) : std::make_shared<Told>(url(), destroyed);
        auto *const raw    = client.get();
        raw->push_request(elsewhere(), [&, raw](qb::http::Response) { // `raw` by value: it is declared after the client
            raw->push_request(elsewhere(), [&](qb::http::Response) {  // kept for its turn
                ++kept_heard;
                if (destroyed == 0) // the last reference -- not under the client's destructor (a case that failed)
                    client.reset();
            });
        });
        EXPECT_EQ(kept_heard, 0);
        raw->push_requests({}, [&](std::vector<qb::http::Response>) {
            ++batch_heard;
            destroyed_when_the_batch_heard = destroyed;
        });
        EXPECT_EQ(kept_heard + batch_heard, 0) << "an answer was given inside the push of the batch, with another owed before it";
        settle();
        EXPECT_EQ(kept_heard, 1);
        EXPECT_EQ(batch_heard, 1);
        EXPECT_EQ(destroyed_when_the_batch_heard, 0) << "the batch's callback was called by a destroyed client";
        EXPECT_EQ(destroyed, 1);
    }
}

// A callback the destructor hears -- the answer of what is still owed when the client is destroyed -- may run the loop
// (Huly QB-1246). The turn that was asked for that answer is still in the loop's queue, and the loop the callback runs
// reaches it: it finds no client to hear for, and touches nothing. What the callback pushes then is answered as from
// any callback the destructor runs: inside the push, and by the return value alone from inside that answer. And a
// response on its way when the client is destroyed may come in that loop: its request hears once, the response or the
// close. The client is owned apart from its control block, so that a sanitizer sees the object freed.
TEST_F(Http2ClientTest, ACallbackTheDestructorHearsThatRunsTheLoopEndsCleanly) {
    for (const std::string_view with : {"nothing else under way", "a response on its way"}) {
        SCOPED_TRACE(with);
        int                   destroyed = 0, kept = 0, answers = 0, first = 0;      // before the client: its callbacks count here
        int                   destroyed_when_heard = -1;                            // 1: heard by the destructor, the object's end begun
        int                   second = 0, second_under_the_first = 0, in_first = 0; // a second answer owed behind the first
        bool                  up = false;
        std::vector<bool>     accepted;
        std::shared_ptr<Told> client(new Told(url(), destroyed));
        auto *const           raw = client.get();
        raw->set_verify_peer(false);
        raw->set_connect_timeout(5s);
        if (with == "a response on its way") {
            raw->connect([&](bool ok, const std::string &) { up = ok; });
            ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
            raw->push_request(reconnect::get_test(), [&](qb::http::Response) { ++first; }); // sent at once: in flight
        }
        raw->push_request(elsewhere(), [&, raw](qb::http::Response) {     // answered inside the program's push
            raw->push_request(elsewhere(), [&, raw](qb::http::Response) { // kept: the destructor's
                ++kept;
                in_first             = 1;
                destroyed_when_heard = destroyed;
                settle(100ms); // the turn that was asked runs here, and what the connection brings
                const bool outer = raw->push_request(reconnect::get_test(), [&, raw](qb::http::Response response) {
                    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
                    ++answers;
                    accepted.push_back(raw->push_request(reconnect::get_test(), [&](qb::http::Response) { ++answers; }));
                });
                accepted.push_back(outer);
                in_first = 0;
            });
            raw->push_request(elsewhere(), [&](qb::http::Response) { // kept behind it: the destructor's too, once the first has returned
                ++second;
                second_under_the_first += in_first;
            });
        });
        EXPECT_EQ(kept, 0) << "a refusal of a push made from a callback was heard inside the push";
        client.reset(); // the last reference, with those answers owed and their turn asked: no loop turn since
        EXPECT_EQ(destroyed, 1);
        EXPECT_EQ(kept, 1);
        EXPECT_EQ(destroyed_when_heard, 1) << "the answer owed was not heard by the destructor: the case shows nothing";
        EXPECT_EQ(answers, 1)
            << "a push made from a callback the destructor runs is answered inside it; one made from inside that answer is not";
        EXPECT_EQ(accepted, (std::vector<bool>{false, true}));
        EXPECT_EQ(second, 1) << "the second answer owed is heard once";
        EXPECT_EQ(second_under_the_first, 0) << "the turn that was asked heard for a client being destroyed, inside the loop its callback ran";
        settle(100ms);
        EXPECT_EQ(kept, 1) << "the turn that was asked heard for a client that is gone";
        EXPECT_EQ(second, 1);
        EXPECT_EQ(answers, 1);
        EXPECT_EQ(first, with == "a response on its way" ? 1 : 0) << "the request in flight when the client was destroyed hears once";
    }
}

// A member of a batch has its own answer, whatever becomes of the batch, and is counted once (Huly QB-1246): its answer
// is recorded in the batch when it is given, never kept for a turn. Here a batch of two is pushed from a callback of the
// client: its first member takes the last stream the server allows and is in flight, its second is refused where it is
// sent; the same callback then closes the client. The close answers the batch: the member in flight with the close's
// text, the member refused with its own.
TEST_F(Http2ClientTest, ABatchMemberRefusedBeforeACloseKeepsItsOwnAnswerAndIsCountedOnce) {
    int                             batch_calls = 0, held = 0, warm = 0; // before the client: its callbacks count here
    std::vector<qb::http::Response> heard;
    auto                            client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    // A round trip first: the server's limit of concurrent streams, 50, comes with its SETTINGS.
    client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++warm; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return warm == 1; }));
    client->set_max_concurrent_streams(200);
    for (int i = 0; i < 49; ++i)
        client->push_request(hang(), [&](qb::http::Response) { ++held; }); // all but one of the streams the server allows
    ASSERT_EQ(client->get_active_request_count(), 49u);
    ASSERT_EQ(held, 0);
    const auto [total_before, served_before, failed_before] = client->get_stats();
    client->push_request(elsewhere(), [&](qb::http::Response) { // a callback of the client
        std::vector<qb::http::Request> two;
        two.push_back(hang()); // the fiftieth stream: in flight
        two.push_back(hang()); // past the server's limit: refused where it is sent
        EXPECT_TRUE(client->push_requests(std::move(two), [&](std::vector<qb::http::Response> responses) {
            ++batch_calls;
            heard = std::move(responses);
        }));
        EXPECT_EQ(client->get_active_request_count(), 50u) << "the first member is not in flight: the case proves nothing";
        EXPECT_EQ(batch_calls, 0);
        client->disconnect();
    });
    settle();
    EXPECT_EQ(batch_calls, 1);
    EXPECT_EQ(held, 49);
    ASSERT_EQ(heard.size(), 2u);
    EXPECT_EQ(heard[0].status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(heard[0].body().as<std::string>(), "Connection closed");
    EXPECT_EQ(heard[1].status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(heard[1].body().as<std::string>(), "Failed to send HTTP/2 request") << "the member refused before the close lost its own answer";
    const auto [total, served, failed] = client->get_stats();
    EXPECT_EQ(total - total_before, 3u);
    EXPECT_EQ(served, served_before);
    EXPECT_EQ(failed - failed_before, 52u) << "the request for another origin, the two members and the 49 requests the close failed, each once";
}

// The coroutine push_request() and push_requests() take the rule of the coroutine connect() (Huly QB-1246): awaited from
// a callback of a close, they complete at once, 503 "HTTP/2 connection is closing". The callback form queues the request
// behind an attempt that starts only once that callback has returned: a coroutine blocked on it -- run_sync() runs the
// loop until it completes -- waited for the request's timeout, or for ever with none. Here the client closes for a frame
// it refuses, a DATA on stream 0, and the callback of the request that close fails blocks on a push.
TEST_F(Http2ClientTest, ARunSyncOfAPushFromAFailureCallbackOfACloseAnswersAtOnce) {
    using qb::http::test::Http2PlannedPeer;
    for (const bool batch : {false, true}) {
        SCOPED_TRACE(batch ? "push_requests()" : "push_request()");
        int                             failed = 0; // before the client: its callbacks count here
        bool                            up = false, returned = false;
        std::vector<qb::http::Response> got;
        std::chrono::milliseconds       took{0};
        Http2PlannedPeer                planned(Http2PlannedPeer::Plan::data_on_stream_zero, 30s);
        ASSERT_NE(planned.port(), 0);
        auto client = reconnect::make_client_for(planned.port());
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero()); // no deadline rescues a push that waits
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
            if (++failed != 1)
                return;
            const auto               started = std::chrono::steady_clock::now();
            qb::http::test::watchdog bound("run_sync() of a push from a failure callback of a close", 5s);
            if (batch) {
                std::vector<qb::http::Request> two;
                two.push_back(reconnect::get_test());
                two.push_back(reconnect::get_test());
                got = qb::io::async::run_sync(client->push_requests(std::move(two)));
            } else {
                got.push_back(qb::io::async::run_sync(client->push_request(reconnect::get_test())));
            }
            took     = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
            returned = true;
        }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return failed != 0; }, 10s));
        ASSERT_TRUE(returned);
        ASSERT_EQ(got.size(), batch ? 2u : 1u);
        for (const auto &response : got) {
            EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
            EXPECT_EQ(response.body().as<std::string>(), "HTTP/2 connection is closing");
        }
        EXPECT_LT(took, 1s);
        client->disconnect();
    }
}

// An answered request leaves nothing armed (Huly QB-1246). The client arms one timeout, for the nearest deadline of what
// it holds: once the only request it held is answered -- a response, a refusal, a failure of a close --, none is armed,
// read as soon as the call that brought the answer has returned.
TEST_F(Http2ClientTest, AnAnsweredRequestLeavesNoTimeoutArmed) {
    int  answered = 0; // before the client: its callbacks count here
    bool up       = false;
    auto client   = make_test_client();
    client->set_auto_reconnect(false);
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    EXPECT_EQ(client->getTimeout(), qb::duration::zero()) << "a connected client that holds nothing has a timeout armed";
    client->set_request_timeout(30s);

    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++answered; }));
    EXPECT_GT(client->getTimeout(), qb::duration::zero()) << "a request in flight has no deadline armed";
    // Each turn blocks until the loop has an event: it returns from the turn that brought the response.
    qb::http::test::expect_until([&] { return answered != 0; }, 10s, "wait_until", [] { qb::io::async::run(EVRUN_ONCE); });
    EXPECT_EQ(client->getTimeout(), qb::duration::zero()) << "a response left its request's deadline armed";

    ASSERT_TRUE(client->push_request(elsewhere(), [&](qb::http::Response) { ++answered; }));
    EXPECT_EQ(answered, 2);
    EXPECT_EQ(client->getTimeout(), qb::duration::zero()) << "a refusal armed a deadline";

    const auto before = _server->server().hang_routed();
    ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response) { ++answered; }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 1; }));
    EXPECT_GT(client->getTimeout(), qb::duration::zero());
    client->disconnect(); // fails it inside the call
    EXPECT_EQ(answered, 3);
    EXPECT_EQ(client->getTimeout(), qb::duration::zero()) << "a close left the deadline of a request it failed armed";
}

// A callback of the client may drop the last reference to it, whoever calls it (Huly QB-1246): the client lives to the
// end of the call that gave the answer -- a push that refuses, a connect() on a connected client, a batch answered where
// it is pushed, the program's disconnect(), a timeout, a response, a failed connect, a lost connection. The client is
// owned apart from its control block, so that a sanitizer sees the object freed.
TEST_F(Http2ClientTest, ACallbackThatDropsTheLastReferenceEndsCleanlyWhoeverCallsIt) {
    for (const std::string_view call :
         {"a refusal inside its push", "the bound of the queue", "an empty batch", "a batch refused whole", "a connect() on a connected client",
          "a failure of the program's disconnect()", "a request's timeout", "a response", "a failed connect", "a lost connection"}) {
        SCOPED_TRACE(call);
        int                                             destroyed = 0, heard = 0, destroyed_when_heard = -1;
        std::unique_ptr<qb::http::test::TlsClosingPeer> silent;
        std::unique_ptr<ServerThread>                   server; // one of its own for the connection that is lost
        std::string                                     origin = url();
        if (call == "a request's timeout") { // TLS comes up and the peer never sends its SETTINGS: the request waits in the queue
            silent = std::make_unique<qb::http::test::TlsClosingPeer>(1, 0, std::vector<std::string>{"h2"}, 15s);
            ASSERT_NE(silent->port(), 0);
            origin = "https://localhost:" + std::to_string(silent->port());
        } else if (call == "a failed connect") {
            origin = "https://localhost:" + std::to_string(qb::http::test::ephemeral_port()); // bound then closed: refused
        } else if (call == "a lost connection") {
            server = reconnect::make_h2_server_on(0);
            ASSERT_TRUE(server->ready());
            origin = "https://localhost:" + std::to_string(reconnect::port_of(*server));
        }
        bool                  up = false; // before the client, which answers what it still holds when it is destroyed
        std::function<void()> drop;       // and so is what its callbacks call: assigned once the client is there
        std::shared_ptr<Told> client(new Told(origin, destroyed));
        auto *const           raw = client.get();
        raw->set_verify_peer(false);
        raw->set_connect_timeout(5s);
        raw->set_auto_reconnect(false);
        drop = [&] {
            ++heard;
            destroyed_when_heard = destroyed;
            if (destroyed == 0) // the last reference -- not under the client's destructor (a case that failed)
                client.reset();
        };
        const auto connected = [&](std::source_location const where = std::source_location::current()) {
            qb::http::test::fail_wait::called_from const caller{where};
            raw->connect([&](bool ok, const std::string &) { up = ok; });
            return ServerThread::pump_until([&] { return up; });
        };
        if (call == "a refusal inside its push") {
            raw->push_request(elsewhere(), [&](qb::http::Response) { drop(); });
        } else if (call == "the bound of the queue") {
            raw->set_max_pending_requests(0);
            EXPECT_FALSE(raw->push_request(reconnect::get_test(), [&](qb::http::Response) { drop(); }));
        } else if (call == "an empty batch") {
            raw->push_requests({}, [&](std::vector<qb::http::Response>) { drop(); });
        } else if (call == "a batch refused whole") {
            std::vector<qb::http::Request> two;
            two.push_back(elsewhere());
            two.push_back(elsewhere());
            raw->push_requests(std::move(two), [&](std::vector<qb::http::Response>) { drop(); });
        } else if (call == "a connect() on a connected client") {
            ASSERT_TRUE(connected());
            raw->connect([&](bool, const std::string &) { drop(); });
        } else if (call == "a failure of the program's disconnect()") {
            ASSERT_TRUE(connected());
            raw->set_request_timeout(qb::duration::zero());
            const auto before = _server->server().hang_routed();
            raw->push_request(hang(), [&](qb::http::Response) { drop(); });
            ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 1; }));
            raw->disconnect();
        } else if (call == "a request's timeout") {
            raw->set_connect_timeout(20s);
            raw->set_request_timeout(100ms);
            raw->push_request(reconnect::get_test(), [&](qb::http::Response response) {
                EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT);
                drop();
            });
        } else if (call == "a response") {
            ASSERT_TRUE(connected());
            raw->push_request(reconnect::get_test(), [&](qb::http::Response response) {
                EXPECT_EQ(response.status(), qb::http::status::OK);
                drop();
            });
        } else if (call == "a failed connect") {
            raw->connect([&](bool ok, const std::string &) {
                EXPECT_FALSE(ok);
                drop();
            });
        } else {
            ASSERT_TRUE(connected());
            raw->set_request_timeout(qb::duration::zero());
            raw->push_request(hang(), [&](qb::http::Response) { drop(); });
            ASSERT_TRUE(ServerThread::pump_until([&] { return server->server().hang_routed() == 1; }));
            server.reset(); // the server goes: the connection is lost
        }
        EXPECT_TRUE(ServerThread::pump_until([&] { return heard != 0; }, 10s));
        settle();
        EXPECT_EQ(heard, 1);
        EXPECT_EQ(destroyed_when_heard, 0) << "the callback was called by a destroyed client";
        EXPECT_EQ(destroyed, 1);
    }
}

// While the destructor hears what the client still owes, an answer the loop brings takes its place behind it, as in
// ordinary operation (Huly QB-1246). Two refusals are owed when the last reference goes; the callback of the first runs
// the loop, and the response of a request in flight comes in that loop. The order the client came to owe them is the
// first refusal (1; -1 marks the end of its callback), the second (2), then the response (9). The response was given at
// once, under the first callback and ahead of the second refusal: 1 9 -1 2.
TEST_F(Http2ClientTest, AResponseThatComesWhileTheDestructorHearsWhatIsOwedTakesItsPlaceBehindIt) {
    int                   destroyed = 0; // before the client: its callbacks write here
    bool                  up        = false;
    std::vector<int>      order;
    std::shared_ptr<Told> client(new Told(url(), destroyed));
    auto *const           raw = client.get();
    raw->set_verify_peer(false);
    raw->set_connect_timeout(5s);
    raw->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    raw->push_request(reconnect::get_test(), [&](qb::http::Response) { order.push_back(9); }); // in flight
    raw->push_request(elsewhere(), [&, raw](qb::http::Response) {                              // inside the program's push
        raw->push_request(elsewhere(), [&](qb::http::Response) {                               // owed first
            order.push_back(1);
            settle(150ms); // the response comes in this loop
            order.push_back(-1);
        });
        raw->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // owed second
    });
    client.reset(); // the last reference: the destructor hears what is owed
    EXPECT_EQ(destroyed, 1);
    EXPECT_EQ(order, (std::vector<int>{1, -1, 2, 9})) << "an answer the loop brought was given ahead of one still owed";
    settle();
}

// And so does an answer the client gives by itself there: the destructor has one rule, the order the client came to owe
// its answers (Huly QB-1246). Two refusals are owed when the last reference goes; the callback of the first calls
// disconnect(), which ends a request in flight. That failure (9) takes its place behind the second refusal (2), as it
// would in ordinary operation. It was given inside the disconnect(), ahead of it: 1 9 -1 2.
TEST_F(Http2ClientTest, ADisconnectFromACallbackTheDestructorHearsGivesItsFailuresBehindWhatIsOwed) {
    int                   destroyed = 0; // before the client: its callbacks write here
    bool                  up        = false;
    std::vector<int>      order;
    std::shared_ptr<Told> client(new Told(url(), destroyed));
    auto *const           raw = client.get();
    raw->set_verify_peer(false);
    raw->set_connect_timeout(5s);
    raw->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    raw->push_request(reconnect::get_test(), [&](qb::http::Response) { order.push_back(9); }); // in flight
    raw->push_request(elsewhere(), [&, raw](qb::http::Response) {                              // inside the program's push
        raw->push_request(elsewhere(), [&, raw](qb::http::Response) {                          // owed first
            order.push_back(1);
            raw->disconnect(); // ends the request in flight
            order.push_back(-1);
        });
        raw->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // owed second
    });
    client.reset(); // the last reference: the destructor hears what is owed
    EXPECT_EQ(destroyed, 1);
    EXPECT_EQ(order, (std::vector<int>{1, -1, 2, 9})) << "an answer the client gave by itself was given ahead of one still owed";
    settle();
}

// An empty batch pushed from a callback the destructor runs follows the destructor's rule, as a request does (Huly
// QB-1246): it is answered inside the push, and one pushed from inside that answer is refused by the return value alone,
// its callback unheard. An empty batch pushed back from its own callback had no end there: a hundred calls, a hundred
// deep, where the case stops it.
TEST_F(Http2ClientTest, AnEmptyBatchPushedBackFromTheDestructorsCallbacksEndsAtItsSecondPush) {
    int                   calls = 0, depth = 0, deepest = 0;
    std::vector<bool>     accepted;
    qb::http2::Client    *raw = nullptr;
    std::function<void()> push_empty;
    push_empty = [&] {
        const auto index = accepted.size(); // a push returns after the ones its callback makes
        accepted.push_back(false);
        const bool taken = raw->push_requests({}, [&](std::vector<qb::http::Response>) {
            deepest = std::max(deepest, ++depth);
            if (++calls < 100) {
                push_empty();
            }
            --depth;
        });
        accepted[index]  = taken;
    };
    {
        auto client = make_test_client();
        raw         = client.get();
        client->push_request(reconnect::get_test(), [&](qb::http::Response) { push_empty(); }); // fails with the client
        ASSERT_TRUE(client->is_connecting()); // queued behind a connection the loop has not made
    } // destroyed with that request waiting
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(deepest, 1);
    EXPECT_EQ(accepted, (std::vector<bool>{true, false}));
}

// A run_sync() of a coroutine push made from a callback the client's turn hears completes. The refusal it awaits is
// kept for the client's next turn -- a callback of the client is on the stack --, and the loop run_sync() runs brings
// that turn from the loop's deferred queue, whose drain is still running the first turn. qb-io runs deferred callbacks
// under a nested turn (Huly QB-1246, in qb): where that drain does not nest, this wait never ends -- the one queue of
// owed answers needs that drain, and must not be used without it.
TEST_F(Http2ClientTest, ARunSyncOfACoroutinePushFromACallbackTheClientsTurnHearsCompletes) {
    bool             done   = false; // before the client: its callbacks write here
    qb::http::status status = qb::http::status::OK;
    auto             client = make_test_client();
    client->push_request(elsewhere(), [&](qb::http::Response) {     // answered inside the program's push
        client->push_request(elsewhere(), [&](qb::http::Response) { // kept: heard by the client's turn
            qb::http::test::watchdog bound("run_sync() of a coroutine push from a callback the client's turn hears", 5s);
            status = qb::io::async::run_sync(client->push_request(elsewhere())).status();
            done   = true;
        });
    });
    EXPECT_FALSE(done) << "a refusal of a push made from a callback was heard inside the push";
    ASSERT_TRUE(ServerThread::pump_until([&] { return done; }));
    EXPECT_EQ(status, qb::http::status::BAD_REQUEST);
}

// ---- What a callback throws, and a connect() asked while a transport closes (Huly QB-1246) ----

/// A request the protocol refuses where it is sent, with no frame and no GOAWAY: a trailer section may not carry
/// content-length. 400, the reason naming the field (503 "Failed to send HTTP/2 request" until Huly QB-1246).
inline qb::http::Request
unsendable() {
    auto request = reconnect::get_test();
    request.trailers().set_header("content-length", "3");
    return request;
}

// A push has one outcome: its answer through the callback, or the exception that leaves it (Huly QB-1246). The pass a
// push runs sends what waited before its own request, and the callback of one the protocol refuses there may throw. A
// is in flight on the one stream the client allows; B waits behind it, a request the protocol refuses where it is sent,
// and its callback throws; the limit is raised and R is pushed -- a request, then a batch. The exception left push(R),
// and R stayed queued: the next pass sent it, and its callback was called with a 200 -- thrown at AND answered.
TEST_F(Http2ClientTest, ACallbackThatThrowsUnderAnotherPushLeavesThatPushOneOutcome) {
    for (const std::string_view form : {"a request", "a batch"}) {
        SCOPED_TRACE(form);
        int  a = 0, b = 0, r = 0, x = 0; // before the client, which answers what it still holds when it is destroyed
        bool up     = false;
        auto client = make_test_client();
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        client->set_max_concurrent_streams(1);
        const auto before = _server->server().hang_routed();
        ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response) { ++a; }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 1; }));
        ASSERT_TRUE(client->push_request(unsendable(), [&](qb::http::Response response) {
            ++b;
            EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
            throw std::runtime_error("the callback of the request that waited throws");
        }));
        ASSERT_EQ(b, 0) << "the request that waits was answered already: the case proves nothing";
        client->set_max_concurrent_streams(10);
        bool threw = false;
        try {
            if (form == "a request") {
                client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++r; });
            } else {
                std::vector<qb::http::Request> two;
                two.push_back(reconnect::get_test());
                two.push_back(reconnect::get_test());
                client->push_requests(std::move(two), [&](std::vector<qb::http::Response>) { ++r; });
            }
        } catch (std::runtime_error const &) {
            threw = true;
        }
        ASSERT_TRUE(threw) << "nothing reached the caller of the push: the case proves nothing";
        EXPECT_EQ(b, 1);
        EXPECT_EQ(r, 0);
        settle(200ms);
        EXPECT_EQ(r, 0) << "the push threw, and what it pushed was sent all the same";
        ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) { // the next pass
            x += response.status() == qb::http::status::OK ? 1 : 0;
        }));
        EXPECT_TRUE(ServerThread::pump_until([&] { return x == 1; }, 5s)) << "the client was left unable to serve a request";
        settle(100ms);
        EXPECT_EQ(r, 0) << "the push threw, and its callback was called by the next pass: two outcomes";
        EXPECT_TRUE(client->is_connected());
        client->disconnect();
        settle();
        EXPECT_EQ(a, 1);
        EXPECT_EQ(r, 0);
    }
}

// A close calls every callback it owes and ends its transport, whatever one of them throws; the first exception goes on
// once that is done (Huly QB-1246). TLS is up and the peer never sends its SETTINGS: three requests wait, the program
// disconnects, and the callback of the first throws. The exception left the close at once: the two other requests were
// never answered, and the transport stayed marked as closing and was never closed -- a connect() asked afterwards
// waited for its end, for ever.
TEST_F(Http2ClientTest, ADisconnectWhoseFirstCallbackThrowsStillAnswersTheOthersAndEndsItsTransport) {
    for (const std::string_view thrower : {"the callback of a request", "the callback of the connect() that waits"}) {
        SCOPED_TRACE(thrower);
        int                            first = 0, second = 0, third = 0, told = 0, connect_answers = 0; // before the client
        qb::http::test::TlsClosingPeer silent(1, 0, std::vector<std::string>{"h2"}, 15s);
        ASSERT_NE(silent.port(), 0);
        auto client = reconnect::make_client_for(silent.port());
        client->set_connect_timeout(20s);
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        if (thrower == "the callback of the connect() that waits") {
            ASSERT_TRUE(client->connect([&](bool ok, const std::string &) {
                ++told;
                EXPECT_FALSE(ok);
                throw std::runtime_error("the callback of the connect() throws");
            }));
        }
        ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
            ++first;
            if (thrower == "the callback of a request")
                throw std::runtime_error("the first failure callback throws");
        }));
        ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++second; }));
        ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++third; }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return client->transport().is_open(); }, 5s));
        settle(300ms); // TLS comes up; the handshake waits for SETTINGS that never come
        bool threw = false;
        try {
            client->disconnect();
        } catch (std::runtime_error const &) {
            threw = true;
        }
        EXPECT_TRUE(threw) << "what the callback threw did not reach the caller of disconnect()";
        EXPECT_EQ(first + second + third, 3) << "a request behind the callback that threw was not answered";
        settle(200ms);
        EXPECT_EQ(first, 1);
        EXPECT_EQ(second, 1);
        EXPECT_EQ(third, 1);
        EXPECT_EQ(told, thrower == "the callback of a request" ? 0 : 1);
        EXPECT_FALSE(client->transport().is_open()) << "the close left its transport open behind the callback that threw";
        // The next connect() starts: the peer takes no second connection, so its own deadline answers it.
        client->set_connect_timeout(1s);
        ASSERT_TRUE(client->connect([&](bool, const std::string &) { ++connect_answers; }));
        EXPECT_TRUE(ServerThread::pump_until([&] { return connect_answers != 0; }, 6s))
            << "a connect() after that disconnect() waits for the end of a transport that was never closed";
        client->disconnect();
        settle();
        EXPECT_EQ(connect_answers, 1);
    }
}

// The same for an attempt that fails: the callback of the connect() throws, and the requests that waited for that
// attempt still hear (Huly QB-1246). The port refuses; two requests wait behind the connect(). The exception left the
// failure before it had failed them: they were never answered.
TEST_F(Http2ClientTest, AFailedConnectWhoseCallbackThrowsStillAnswersTheRequestsThatWaited) {
    Answer     first, second; // before the client, which answers what it still holds when it is destroyed
    int        told = 0, again = 0;
    const auto port   = qb::http::test::ephemeral_port(); // bound then closed: refused
    auto       client = reconnect::make_client_for(port);
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &) {
        ++told;
        EXPECT_FALSE(ok);
        throw std::runtime_error("the callback of the connect() throws");
    }));
    ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(first)));
    ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(second)));
    const auto run = [](std::chrono::milliseconds const span, auto &&done, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where}; // what leaves the loop's own failure is not this case's
        qb::http::test::discard(qb::http::test::wait_until(done, span, "run",
                                                           [] {
                                                               try {
                                                                   qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
                                                               } catch (std::runtime_error const &) {
                                                               }
                                                           }),
                                "a window, or a wait whose condition the case asserts right after each run()");
    };
    run(5s, [&] { return told != 0; });
    ASSERT_EQ(told, 1) << "the attempt did not fail: the case proves nothing";
    run(300ms, [] { return false; });
    EXPECT_EQ(first.count, 1) << "a request that waited for the attempt was not answered";
    EXPECT_EQ(second.count, 1);
    EXPECT_EQ(first.status, qb::http::status::SERVICE_UNAVAILABLE) << first.body;
    ASSERT_TRUE(client->connect([&](bool, const std::string &) { ++again; }));
    run(5s, [&] { return again != 0; });
    EXPECT_EQ(again, 1) << "the next connect() was never answered";
    client->disconnect();
    settle();
    EXPECT_EQ(first.count + second.count, 2) << "a request was answered twice";
}

// And for the end of a graceful GOAWAY's drain (Huly QB-1246). The peer announces its GOAWAY and answers the request in
// flight; the request pushed while the connection drained is failed by the drain's end -- automatic reconnection off --
// and its callback throws. The transport is ended all the same; the peer never ends it. The exception left the drain's
// end before its close: the connection stayed open behind a client that held it for closed.
TEST_F(Http2ClientTest, AGracefulGoawaysDrainWhoseCallbackThrowsStillEndsItsTransport) {
    int                              answered = 0, failed = 0; // before the client
    qb::http::test::Http2PlannedPeer peer(qb::http::test::Http2PlannedPeer::Plan::goaways_lowered, 30s);
    ASSERT_NE(peer.port(), 0);
    auto client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
        ++answered;
        // The connection drains: a request pushed now waits for the drain's end, which fails it.
        EXPECT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
            ++failed;
            throw std::runtime_error("the callback of the request the drain's end fails throws");
        }));
    }));
    const auto run = [](std::chrono::milliseconds const span, auto &&done, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where}; // what leaves the loop's own failure is not this case's
        qb::http::test::discard(qb::http::test::wait_until(done, span, "run",
                                                           [] {
                                                               try {
                                                                   qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
                                                               } catch (std::runtime_error const &) {
                                                               }
                                                           }),
                                "a window, or a wait whose condition the case asserts right after each run()");
    };
    run(10s, [&] { return failed != 0; });
    ASSERT_EQ(answered, 1);
    ASSERT_EQ(failed, 1) << "the drain's end failed nothing: the case proves nothing";
    run(1s, [&] { return !client->transport().is_open(); });
    EXPECT_FALSE(client->transport().is_open()) << "the drain's end left its transport open behind the callback that threw";
    EXPECT_FALSE(client->is_connected());
    client->disconnect();
    settle();
    EXPECT_EQ(failed, 1) << "the request was answered twice";
}

// The connect timeout of a connect() counts from the moment it is asked, on the three clients (Huly QB-1246). Asked from
// the failure callback of a lost connection, the attempt starts once that transport is torn down, never under the
// callback; its deadline was armed only by whatever armed the client's timer next. A callback that ran the loop until
// its connect() was answered waited for ever; with a request pushed after the connect(), it heard `false` at one second.
// Both now hear `false`, "Connection timeout", at the connect timeout -- and nothing starts afterwards for a connect()
// that was told `false`: the client connected by itself once the callback had returned, an attempt nobody waited for.
TEST_F(Http2ClientTest, AConnectAskedFromACallbackOfALostConnectionHasItsDeadlineFromTheAsk) {
    for (const std::string_view then : {"nothing more", "a request pushed after it", "a server listens again"}) {
        SCOPED_TRACE(then);
        int                           failures = 0, connect_answers = 0, pushed = 0; // before the client
        bool                          up = false, ok_again = true, answered_in_the_loop = false;
        std::string                   why;
        std::chrono::milliseconds     waited{0};
        std::unique_ptr<ServerThread> again;
        auto                          server = reconnect::make_h2_server_on(0);
        ASSERT_TRUE(server->ready());
        const auto port   = reconnect::port_of(*server);
        auto       client = reconnect::make_client_for(port);
        client->set_connect_timeout(1s);
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response) {
            if (++failures != 1)
                return;
            client->connect([&](bool ok, const std::string &error) {
                ++connect_answers;
                ok_again = ok;
                why      = error;
            });
            if (then != "nothing more")
                client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++pushed; });
            const auto began = std::chrono::steady_clock::now();
            {
                qb::http::test::watchdog bound("the loop a callback runs until its connect() is answered", 10s);
                const auto               until = began + 3s; // a program's loop has no bound
                qb::http::test::discard(
                    qb::http::test::wait_until([&] { return connect_answers != 0; },
                                               std::chrono::duration_cast<std::chrono::milliseconds>(until - std::chrono::steady_clock::now())),
                    "answered_in_the_loop records it, which the case asserts");
            }
            waited               = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - began);
            answered_in_the_loop = connect_answers != 0;
            if (then == "a server listens again")
                again = reconnect::make_h2_server_on(port); // before the callback returns
        }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return server->server().hang_routed() == 1; }));
        server.reset(); // the connection is lost
        ASSERT_TRUE(ServerThread::pump_until([&] { return failures != 0; }, 10s));
        EXPECT_TRUE(answered_in_the_loop) << "the connect() asked from the callback had no deadline";
        EXPECT_FALSE(ok_again);
        EXPECT_EQ(why, "Connection timeout");
        EXPECT_GE(waited, 900ms) << "answered before the connect timeout";
        EXPECT_LT(waited, 2500ms) << "answered long after the connect timeout";
        settle(800ms);
        EXPECT_EQ(connect_answers, 1) << "the connect() was answered twice";
        EXPECT_FALSE(client->is_connecting()) << "an attempt started for a connect() that was told false";
        EXPECT_FALSE(client->is_connected()) << "the client connected by itself after its connect() was told false";
        if (then != "nothing more") {
            EXPECT_EQ(pushed, 1) << "the request pushed with that connect() is answered once, with it";
        }
        client->disconnect();
        settle(100ms);
    }
}

// What is pushed once such a connect() has timed out is the next attempt's, not the closing transport's (Huly QB-1246).
// TLS is up and the peer never sends its SETTINGS; the program disconnects; the callback of the request that waited asks
// connect() -- deferred: that transport still closes -- and runs the loop until it is told `false` at the connect
// timeout, then pushes a request, an h2 server on the port by then. The failure of that attempt cleared the mark that
// keeps the queue through the closing transport's end: the request was failed by that end, "Connection lost", though it
// never rode that transport.
TEST_F(Http2ClientTest, ARequestPushedOnceADeferredConnectTimedOutRidesTheNextAttempt) {
    Answer                        waiting, next; // before the client, which answers what it still holds when it is destroyed
    int                           connect_answers = 0;
    bool                          told_false      = false;
    std::unique_ptr<ServerThread> server;
    auto                          silent = std::make_unique<qb::http::test::TlsClosingPeer>(1, 0, std::vector<std::string>{"h2"}, 15s);
    const auto                    port   = silent->port();
    ASSERT_NE(port, 0);
    auto client = reconnect::make_client_for(port);
    client->set_connect_timeout(20s);
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
        waiting(std::move(response));
        if (waiting.count != 1)
            return;
        client->set_connect_timeout(1s);
        client->connect([&](bool ok, const std::string &) {
            ++connect_answers;
            told_false = !ok;
        });
        {
            qb::http::test::watchdog bound("the loop a callback runs until its connect() is answered", 10s);
            qb::http::test::discard(qb::http::test::wait_until([&] { return connect_answers != 0; }, 3s),
                                    "a callback's bounded pass: connect_answers and told_false record it, which the case asserts");
        }
        silent.reset();                              // the port is free
        server = reconnect::make_h2_server_on(port); // and serves h2 from here on
        client->set_connect_timeout(5s);
        if (server->ready())
            client->push_request(reconnect::get_test(), std::ref(next));
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return client->transport().is_open(); }, 5s));
    settle(300ms); // TLS comes up; the handshake waits for SETTINGS that never come
    client->disconnect();
    ASSERT_EQ(waiting.count, 1);
    ASSERT_TRUE(told_false) << "the connect() asked while the transport closes was not told false at its deadline: the case proves nothing";
    ASSERT_TRUE(server && server->ready()) << "no h2 server on the port the peer left: the case proves nothing";
    EXPECT_TRUE(ServerThread::pump_until([&] { return next.count != 0; }, 8s));
    EXPECT_EQ(next.count, 1);
    EXPECT_EQ(next.status, qb::http::status::OK) << "failed with an attempt it never rode: " << next.body;
    client->disconnect();
    settle();
}

/// Targets no client may send: a query that carries SP, a control byte or DEL as written (the path of a URI holds path
/// characters only: such a byte there fails the parse, and the URI names no target).
struct UnsendableTarget {
    std::string_view what;
    std::string      target;
};
inline const UnsendableTarget k_unsendable_targets[] = {
    {"LF in the query", std::string("/api/test?q=a\nb")},
    {"CR in the query", std::string("/api/test?q=a\rb")},
    {"0x1F in the query", std::string("/api/test?q=a\x1F") + "b"},
    {"DEL in the query", std::string("/api/test?q=a\x7F") + "b"},
    {"SP in the query", std::string("/api/test?q=a b")},
    {"LF in the path", std::string("/api/test/a\nb")},
    {"CR in the path", std::string("/api/test/a\rb")},
    {"0x1F in the path", std::string("/api/test/a\x1F") + "b"},
    {"DEL in the path", std::string("/api/test/a\x7F") + "b"},
    {"SP in the path", std::string("/api/test/a b")},
};

// A request whose target cannot be sent is refused where it is pushed, 400, as a refusal the client gives by itself, and
// costs nothing else (Huly QB-1246): the connection stays, what it carries goes on, the next request is served on it.
// The check is the HTTP/1.1 serializer's, shared by the three clients. On HTTP/2 such a query reached the field
// encoder, which refuses a control byte: the client ended the connection with its own GOAWAY from under the push, and
// every request on it failed for the fault of one; a URI that failed to parse was sent, to another resource.
TEST_F(Http2ClientTest, ARequestWhoseTargetCannotBeSentIsRefusedWhereItIsPushedAndNoOtherWithIt) {
    for (const auto &row : k_unsendable_targets) {
        SCOPED_TRACE(row.what);
        Answer held, refused, after; // before the client, which answers what it still holds when it is destroyed
        bool   up     = false;
        auto   client = make_test_client();
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        const auto before = _server->server().hang_routed();
        ASSERT_TRUE(client->push_request(hang(), std::ref(held)));
        ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 1; }));
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri(row.target);
        EXPECT_TRUE(client->push_request(std::move(request), std::ref(refused)));
        EXPECT_EQ(refused.count, 1) << "the request was not refused where it was pushed";
        EXPECT_EQ(refused.status, qb::http::status::BAD_REQUEST) << refused.body;
        EXPECT_NE(refused.body.find("cannot be sent"), std::string::npos) << refused.body;
        EXPECT_TRUE(client->is_connected()) << "a request refused for its own target ended the connection";
        EXPECT_EQ(held.count, 0) << "and the request in flight with it: " << held.body;
        ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(after)));
        EXPECT_TRUE(ServerThread::pump_until([&] { return after.count != 0; }, 5s));
        EXPECT_EQ(after.status, qb::http::status::OK) << after.body;
        EXPECT_EQ(held.count, 0) << held.body;
        EXPECT_EQ(refused.count, 1);
        client->disconnect();
        settle();
    }
}

// ---- A push that reads nothing of the client after its pass; the ends an exception no longer cuts short; one timeout a
// connect(); the length of a target (Huly QB-1246) ----

// The pass takes back what its push queued, under its own hold on the client: nothing reads the client once the pass
// has thrown (Huly QB-1246). As ACallbackThatThrowsUnderAnotherPushLeavesThatPushOneOutcome, the client owned apart
// from its control block: the callback of the request that waited drops the last reference, then throws. The push
// took its request back after the pass -- in a client the end of that pass had just destroyed: a heap-use-after-free.
TEST_F(Http2ClientTest, ACallbackUnderAPushThatDropsTheLastReferenceAndThrowsLeavesNoClientToRead) {
    for (const std::string_view form : {"a request", "a batch"}) {
        SCOPED_TRACE(form);
        int                   destroyed = 0, destroyed_as_the_push_left = -1, a = 0, b = 0, r = 0; // before the client
        bool                  up = false;
        std::shared_ptr<Told> client(new Told(url(), destroyed));
        auto *const           raw = client.get();
        raw->set_verify_peer(false);
        raw->set_auto_reconnect(false);
        raw->set_request_timeout(qb::duration::zero());
        raw->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        raw->set_max_concurrent_streams(1);
        const auto before = _server->server().hang_routed();
        ASSERT_TRUE(raw->push_request(hang(), [&](qb::http::Response) { ++a; }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 1; }));
        ASSERT_TRUE(raw->push_request(unsendable(), [&](qb::http::Response) {
            ++b;
            if (destroyed == 0) // the last reference -- not under the client's destructor (a case that failed)
                client.reset();
            throw std::runtime_error("the callback of the request that waited drops the client and throws");
        }));
        ASSERT_EQ(b, 0) << "the request that waits was answered already: the case proves nothing";
        raw->set_max_concurrent_streams(10);
        bool threw = false;
        try {
            if (form == "a request") {
                raw->push_request(reconnect::get_test(), [&](qb::http::Response) { ++r; });
            } else {
                std::vector<qb::http::Request> two;
                two.push_back(reconnect::get_test());
                two.push_back(reconnect::get_test());
                raw->push_requests(std::move(two), [&](std::vector<qb::http::Response>) { ++r; });
            }
        } catch (std::runtime_error const &) {
            threw = true;
        }
        destroyed_as_the_push_left = destroyed;
        ASSERT_TRUE(threw) << "nothing reached the caller of the push: the case proves nothing";
        EXPECT_EQ(b, 1);
        EXPECT_EQ(destroyed_as_the_push_left, 1) << "the client outlived the push under which its last reference was dropped";
        settle(200ms);
        EXPECT_EQ(r, 0) << "the push threw, and what it pushed was answered: two outcomes";
        EXPECT_EQ(a, 1) << "the request in flight hears once, from the destructor";
        EXPECT_EQ(destroyed, 1);
    }
}

// The end of a lost connection runs to its own end whatever a failure callback throws (Huly QB-1246). Three requests
// are in flight; the server goes, and another listens on its port. The first failure callback called throws, and the
// second pushes a request back -- for the reconnection the client makes by itself, or, with automatic reconnection off,
// for a connect() it asks there, held back until the transport that ended is torn down. The client connects again, and
// that request is served. The exception left the handler before it had asked for the reconnection, or started the
// connect() held back: the request pushed back waited for a connection that nothing would open.
TEST_F(Http2ClientTest, ALostConnectionWhoseFirstFailureCallbackThrowsStillReconnectsForWhatWasPushedBack) {
    for (const std::string_view by : {"the reconnection the client makes by itself", "a connect() the callback asks"}) {
        SCOPED_TRACE(by);
        Answer again; // before the client, which answers what it still holds when it is destroyed
        int    failures = 0;
        bool   up       = false;
        auto   server   = reconnect::make_h2_server_on(0);
        ASSERT_TRUE(server->ready());
        const auto port   = reconnect::port_of(*server);
        auto       client = reconnect::make_client_for(port);
        client->set_connect_timeout(2s);
        client->set_request_timeout(qb::duration::zero());
        if (by == "the reconnection the client makes by itself")
            client->enable_auto_reconnect();
        else
            client->set_auto_reconnect(false);
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        for (int i = 0; i < 3; ++i) {
            ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response) {
                const int nth = ++failures;
                if (nth == 2) {
                    if (by == "a connect() the callback asks")
                        client->connect(nullptr);
                    client->push_request(reconnect::get_test(), std::ref(again));
                }
                if (nth == 1)
                    throw std::runtime_error("the first failure callback throws");
            }));
        }
        ASSERT_TRUE(ServerThread::pump_until([&] { return server->server().hang_routed() == 3; }));
        server.reset(); // the connection is lost
        auto back = reconnect::make_h2_server_on(port);
        ASSERT_TRUE(back->ready()) << "no h2 server on the port the first left: the case proves nothing";
        qb::http::test::expect_until([&] { return again.count != 0; }, 8s, "wait_until",
                                     [] {
                                         try {
                                             qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
                                         } catch (std::runtime_error const &) { // what leaves the loop's own failure is not this case's
                                         }
                                     });
        EXPECT_EQ(failures, 3) << "a request behind the callback that threw was not answered";
        EXPECT_EQ(again.count, 1) << "the request a failure callback pushed back was never served";
        EXPECT_EQ(again.status, qb::http::status::OK) << again.body;
        EXPECT_TRUE(client->is_connected());
        client->disconnect();
        settle();
    }
}

// The same when the connection is lost before it is up, and the callback that throws is the connect()'s (Huly QB-1246).
// The peer ends the connection once TLS is complete; a request waits behind the connect(), whose callback throws. The
// request hears all the same. The exception left the handler before its failure pass: the request stayed queued behind
// a connection that nothing would open, never answered.
TEST_F(Http2ClientTest, ALostAttemptWhoseConnectCallbackThrowsStillAnswersTheRequestThatWaited) {
    Answer                         waiting; // before the client, which answers what it still holds when it is destroyed
    int                            told = 0;
    qb::http::test::TlsClosingPeer peer(1);
    ASSERT_NE(peer.port(), 0);
    auto client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &) {
        ++told;
        EXPECT_FALSE(ok);
        throw std::runtime_error("the callback of the connect() throws");
    }));
    ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(waiting)));
    const auto run = [](std::chrono::milliseconds const span, auto &&done, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where}; // what leaves the loop's own failure is not this case's
        qb::http::test::discard(qb::http::test::wait_until(done, span, "run",
                                                           [] {
                                                               try {
                                                                   qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
                                                               } catch (std::runtime_error const &) {
                                                               }
                                                           }),
                                "a window, or a wait whose condition the case asserts right after each run()");
    };
    run(5s, [&] { return told != 0; });
    ASSERT_EQ(told, 1) << "the attempt was not lost: the case proves nothing";
    run(300ms, [&] { return waiting.count != 0; });
    EXPECT_EQ(waiting.count, 1) << "the request that waited behind the connect() was never answered";
    EXPECT_NE(waiting.body.find("Connection lost"), std::string::npos) << waiting.body;
    client->disconnect();
    settle();
    EXPECT_EQ(waiting.count, 1) << "the request was answered twice";
}

// A graceful GOAWAY fails every request above the stream it names, and the drain it starts is ended when it has failed
// them all, whatever a callback throws (Huly QB-1246). A GOAWAY that names no stream is delivered by hand, as the loop
// delivers one, with two requests in flight and automatic reconnection off. The first callback called throws: both
// hear, nothing leaves the handler, and the connection, drained, is closed. The exception left the loop over the
// requests -- the other was destroyed unheard -- and the handler before it had looked at the drain's end: the
// connection stayed open, held for a drain with nothing left to wait for.
TEST_F(Http2ClientTest, AGracefulGoawayThatFailsEveryRequestUnderACallbackThatThrowsStillEndsItsDrain) {
    int  failures = 0; // before the client
    bool up       = false;
    auto client   = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    const auto before = _server->server().hang_routed();
    for (int i = 0; i < 2; ++i) {
        ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response) {
            if (++failures == 1)
                throw std::runtime_error("the first callback of a request the GOAWAY fails throws");
        }));
    }
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 2; }));
    EXPECT_NO_THROW(client->on(qb::protocol::http2::Http2GoAwayEvent{qb::protocol::http2::ErrorCode::NO_ERROR, 0, "delivered by hand"}))
        << "what a callback the loop brought threw left the handler";
    EXPECT_EQ(failures, 2) << "the request behind the callback that threw was never answered";
    settle(200ms);
    EXPECT_FALSE(client->transport().is_open()) << "the drained connection was left open behind the callback that threw";
    EXPECT_FALSE(client->is_connected());
    client->disconnect();
    settle();
    EXPECT_EQ(failures, 2) << "a request was answered twice";
}

// One timeout covers a connect() from the moment it is asked: its wait for a transport that still closes, then its
// attempt (Huly QB-1246). TLS is up and the peer never sends its SETTINGS; the program disconnects, and the callback of
// the request that waited asks connect() -- held back: that transport still closes --, keeps the loop for 700 ms and
// returns. The attempt starts then, against a peer that answers nothing, and hears `false` one second after the ask.
// It was given the whole timeout again where it started: `false` came 1.7 s after the ask.
TEST_F(Http2ClientTest, AConnectHeldBackHasOneTimeoutForItsWaitAndItsAttempt) {
    Answer                                waiting; // before the client, which answers what it still holds when it is destroyed
    int                                   connect_answers = 0;
    bool                                  ok_again = true, answered_in_the_callback = false;
    std::chrono::steady_clock::time_point asked{}, answered{};
    qb::http::test::TlsClosingPeer        silent(1, 0, std::vector<std::string>{"h2"}, 15s);
    ASSERT_NE(silent.port(), 0);
    auto client = reconnect::make_client_for(silent.port());
    client->set_connect_timeout(20s);
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) {
        waiting(std::move(response));
        if (waiting.count != 1)
            return;
        client->set_connect_timeout(1s);
        asked = std::chrono::steady_clock::now();
        client->connect([&](bool ok, const std::string &) {
            ++connect_answers;
            ok_again = ok;
            answered = std::chrono::steady_clock::now();
        });
        for (const auto until = asked + 700ms; std::chrono::steady_clock::now() < until;) // the wait: that transport still closes
            qb::io::async::run(EVRUN_NOWAIT);
        answered_in_the_callback = connect_answers != 0;
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return client->transport().is_open(); }, 5s));
    settle(300ms); // TLS comes up; the handshake waits for SETTINGS that never come
    client->disconnect();
    ASSERT_EQ(waiting.count, 1);
    ASSERT_FALSE(answered_in_the_callback) << "the connect() was answered while it waited: the case proves nothing";
    EXPECT_TRUE(ServerThread::pump_until([&] { return connect_answers != 0; }, 5s)) << "the connect() was never answered";
    ASSERT_EQ(connect_answers, 1);
    EXPECT_FALSE(ok_again);
    const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(answered - asked);
    EXPECT_GE(took, 900ms) << "answered before its timeout";
    EXPECT_LT(took, 1450ms) << "the attempt was given the whole timeout again once the wait was over";
    client->disconnect();
    settle();
}

// A target longer than the serializer allows is refused where it is pushed, and one at the limit is sent (Huly QB-1246):
// the shared check measures what serialize_request() measures, the path and the query together against MAX_URL_LENGTH.
TEST_F(Http2ClientTest, ATargetPastTheUrlLimitIsRefusedWhereItIsPushedAndOneAtTheLimitIsSent) {
    Answer held, refused, at_the_limit; // before the client, which answers what it still holds when it is destroyed
    bool   up     = false;
    auto   client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    const auto before = _server->server().hang_routed();
    ASSERT_TRUE(client->push_request(hang(), std::ref(held)));
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 1; }));
    const auto of = [](std::size_t const length) { // a path of that many octets, and no query
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri("/" + std::string(length - 1, 'a'));
        return request;
    };
    EXPECT_TRUE(client->push_request(of(qb::http::protocol_limits::MAX_URL_LENGTH + 1), std::ref(refused)));
    EXPECT_EQ(refused.count, 1) << "the request was not refused where it was pushed";
    EXPECT_EQ(refused.status, qb::http::status::BAD_REQUEST) << refused.body;
    EXPECT_NE(refused.body.find("cannot be sent"), std::string::npos) << refused.body;
    EXPECT_NE(refused.body.find("MAX_URL_LENGTH"), std::string::npos) << refused.body;
    EXPECT_TRUE(client->is_connected()) << "a request refused for its own target ended the connection";
    ASSERT_TRUE(client->push_request(of(qb::http::protocol_limits::MAX_URL_LENGTH), std::ref(at_the_limit)));
    EXPECT_EQ(at_the_limit.count, 0) << "a target at the limit was refused where it was pushed: " << at_the_limit.body;
    EXPECT_TRUE(ServerThread::pump_until([&] { return at_the_limit.count != 0; }, 5s));
    // Sent: the answer is the server's (its router finds the path too long for a route), not one of the client's own.
    EXPECT_EQ(at_the_limit.body.find("cannot be sent"), std::string::npos) << at_the_limit.body;
    EXPECT_NE(at_the_limit.status, qb::http::status::SERVICE_UNAVAILABLE) << "the client did not send it: " << at_the_limit.body;
    EXPECT_TRUE(client->is_connected());
    // One limit for the three clients, on one quantity: a path and a query of MAX_URL_LENGTH together -- the `?` between
    // them is not counted -- are sent as well.
    Answer     with_a_query;
    const auto at = [](std::string const &target) {
        qb::http::Request request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri(target);
        return request;
    };
    ASSERT_TRUE(client->push_request(at("/q?" + std::string(qb::http::protocol_limits::MAX_URL_LENGTH - 2, 'a')), std::ref(with_a_query)));
    EXPECT_EQ(with_a_query.count, 0) << "a path and a query at the limit were refused where they were pushed: " << with_a_query.body;
    EXPECT_TRUE(ServerThread::pump_until([&] { return with_a_query.count != 0; }, 5s));
    EXPECT_EQ(with_a_query.body.find("cannot be sent"), std::string::npos) << with_a_query.body;
    EXPECT_NE(with_a_query.status, qb::http::status::SERVICE_UNAVAILABLE) << "the client did not send it: " << with_a_query.body;
    EXPECT_EQ(held.count, 0) << held.body;
    client->disconnect();
    settle();
}

// ---- What a callback the loop brought throws is contained by the client, where it is called (Huly QB-1246) ----
// One case an entry point of the loop. Before, the same exception was taken by qb-io's read dispatch, swallowed by the
// protocol with the request behind left unsent, or ended the process, by the frame that happened to carry the answer.

/// Runs the loop until @p done or for @p span; nothing leaves it into the case. Under `QBM_HTTP_TEST_FAIL_WAIT_AT` the
/// wait it names fails at once, as a wait that reached its end does (fail_wait.h).
template <typename Done>
bool
loop_until(Done &&done, std::chrono::milliseconds const span = 5s, std::source_location const where = std::source_location::current()) {
    qb::http::test::fail_wait::called_from const caller{where};
    return qb::http::test::wait_until(std::forward<Done>(done), span, "loop_until");
}

// Under a response. One stream allowed; A is in flight, B waits for A's stream, and A's callback throws -- a request's,
// then a batch's. B is sent once A is answered, with no other push to run a pass. The exception left the handler before
// its tail, and the protocol swallowed it: B stayed queued until something else ran a pass.
TEST_F(Http2ClientTest, AResponseCallbackThatThrowsIsContainedAndTheRequestBehindItIsSent) {
    for (const std::string_view form : {"a request", "a batch"}) {
        SCOPED_TRACE(form);
        Answer behind; // before the client, which answers what it still holds when it is destroyed
        int    a      = 0;
        bool   up     = false;
        auto   client = make_test_client();
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        client->set_max_concurrent_streams(1);
        if (form == "a request") {
            ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
                ++a;
                throw std::runtime_error("the response callback throws");
            }));
        } else {
            std::vector<qb::http::Request> one;
            one.push_back(reconnect::get_test());
            ASSERT_TRUE(client->push_requests(std::move(one), [&](std::vector<qb::http::Response>) {
                ++a;
                throw std::runtime_error("the batch's callback throws");
            }));
        }
        ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(behind)));
        EXPECT_TRUE(loop_until([&] { return behind.count != 0; }, 3s)) << "the request that waited for that stream was not sent";
        EXPECT_EQ(a, 1);
        EXPECT_EQ(behind.status, qb::http::status::OK) << behind.body;
        EXPECT_TRUE(client->is_connected());
        client->disconnect();
        settle();
        EXPECT_EQ(behind.count, 1);
    }
}

// Under a RST_STREAM. The server resets the stream of a request (a query with an octet from 0x80 up, which a qb server
// refuses), and the callback of that request throws; another is in flight. The process lives, the connection stays, the
// other request is not failed and the next is served. The frame's handler is noexcept: the process ended.
TEST_F(Http2ClientTest, ACallbackOfARequestTheServerResetsThatThrowsIsContained) {
    Answer      held, after; // before the client, which answers what it still holds when it is destroyed
    int         reset = 0;
    bool        up    = false;
    std::string why;
    auto        client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    const auto before = _server->server().hang_routed();
    ASSERT_TRUE(client->push_request(hang(), std::ref(held)));
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 1; }));
    qb::http::Request refused_by_the_server;
    refused_by_the_server.method() = qb::http::Method::GET;
    refused_by_the_server.uri()    = qb::io::uri(std::string("/api/test?q=a\x80") + "z");
    ASSERT_TRUE(client->push_request(std::move(refused_by_the_server), [&](qb::http::Response response) {
        ++reset;
        why = response.body().as<std::string>();
        throw std::runtime_error("the callback of a request the server reset throws");
    }));
    ASSERT_TRUE(loop_until([&] { return reset != 0; }));
    ASSERT_NE(why.find("RST_STREAM"), std::string::npos) << "the server did not reset the stream: the case proves nothing (" << why << ")";
    settle(100ms);
    EXPECT_TRUE(client->is_connected()) << "the connection did not outlive the throw";
    EXPECT_EQ(held.count, 0) << "the request in flight was failed with it: " << held.body;
    ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(after)));
    EXPECT_TRUE(loop_until([&] { return after.count != 0; }));
    EXPECT_EQ(after.status, qb::http::status::OK) << after.body;
    EXPECT_EQ(reset, 1);
    client->disconnect();
    settle();
}

// Under a GOAWAY frame read from the connection. The peer names stream 1 and answers nothing; the two requests on the
// streams above it are failed by that GOAWAY, and the callback of the first of them called throws. The other hears, and
// the process lives. The frame's handler is noexcept: the process ended.
TEST_F(Http2ClientTest, AGoawayReadFromTheConnectionWhoseFirstFailureCallbackThrowsStillAnswersTheOtherRequest) {
    int                              named = 0, above = 0; // before the client
    std::string                      why;
    qb::http::test::Http2PlannedPeer peer(qb::http::test::Http2PlannedPeer::Plan::goaway_then_close, 30s);
    ASSERT_NE(peer.port(), 0);
    auto client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++named; })); // stream 1
    for (int i = 0; i < 2; ++i) {
        ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response response) { // streams 3 and 5
            if (++above == 1) {
                why = response.body().as<std::string>();
                throw std::runtime_error("the first callback of a request the GOAWAY fails throws");
            }
        }));
    }
    ASSERT_TRUE(loop_until([&] { return above != 0; }));
    ASSERT_EQ(named, 0) << "the request the GOAWAY names was failed with the others: the case proves nothing";
    EXPECT_NE(why.find("GOAWAY"), std::string::npos) << why;
    EXPECT_TRUE(loop_until([&] { return above == 2; }, 300ms)) << "the request behind the callback that threw was never answered";
    client->disconnect();
    settle();
    EXPECT_EQ(above, 2) << "a request was answered twice";
    EXPECT_EQ(named, 1);
}

// Under the handshake's event, a connection that comes up. The callback of the connect() throws: the request that
// waited for the connection is sent and served. qb-io's handshake handler is noexcept: the process ended.
TEST_F(Http2ClientTest, AConnectCallbackThatThrowsOnSuccessIsContainedAndWhatWaitedIsServed) {
    Answer waiting; // before the client, which answers what it still holds when it is destroyed
    int    told   = 0;
    auto   client = make_test_client();
    client->set_auto_reconnect(false);
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &) {
        ++told;
        EXPECT_TRUE(ok);
        throw std::runtime_error("the callback of a connect() that succeeded throws");
    }));
    ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(waiting)));
    EXPECT_TRUE(loop_until([&] { return waiting.count != 0; }));
    EXPECT_EQ(told, 1);
    EXPECT_EQ(waiting.status, qb::http::status::OK) << waiting.body;
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    settle();
}

// Under the handshake's event, a handshake that fails: the server speaks no h2 over ALPN. The callback of the connect()
// throws, and so does the callback of the first request that waited: the other request hears, and the transport of the
// attempt is closed. The process ended there.
TEST_F(Http2ClientTest, AFailedHandshakeWhoseCallbacksThrowStillAnswersWhatWaitedAndEndsItsTransport) {
    int  told = 0, first = 0, second = 0; // before the client
    auto http1_only = reconnect::make_http1_only_server();
    ASSERT_TRUE(http1_only->ready());
    auto client = reconnect::make_client_for(reconnect::port_of(*http1_only));
    client->set_connect_timeout(qb::duration::zero());
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->connect([&](bool ok, const std::string &) {
        ++told;
        EXPECT_FALSE(ok);
        throw std::runtime_error("the callback of the connect() throws");
    }));
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
        ++first;
        throw std::runtime_error("the first failure callback throws");
    }));
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++second; }));
    ASSERT_TRUE(loop_until([&] { return told != 0; }));
    EXPECT_TRUE(loop_until([&] { return second != 0 && !client->transport().is_open(); }, 1s));
    EXPECT_EQ(first, 1);
    EXPECT_EQ(second, 1) << "the request behind the callbacks that threw was not answered";
    EXPECT_FALSE(client->transport().is_open()) << "the transport of the attempt that failed was left open";
    EXPECT_FALSE(client->is_connecting());
    client->disconnect();
    settle();
    EXPECT_EQ(told + first + second, 3) << "a callback was called twice";
}

// Under the timer's pass, a connect timeout. TLS is up and the peer never sends its SETTINGS: the connect timeout fails
// the attempt, and the callback of the first request that waited throws. The other request hears, and the transport of
// that attempt is ended. qb-io's timer handler is noexcept: the process ended.
TEST_F(Http2ClientTest, AnAttemptThatTimesOutUnderACallbackThatThrowsStillAnswersTheOthersAndEndsItsTransport) {
    int                            first = 0, second = 0; // before the client
    bool                           was_open = false;
    qb::http::test::TlsClosingPeer silent(1, 0, std::vector<std::string>{"h2"}, 15s);
    ASSERT_NE(silent.port(), 0);
    auto client = reconnect::make_client_for(silent.port());
    client->set_connect_timeout(1s);
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
        ++first;
        throw std::runtime_error("the first failure callback throws");
    }));
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++second; }));
    ASSERT_TRUE(loop_until([&] { return (was_open = was_open || client->transport().is_open()) && first != 0; }));
    ASSERT_TRUE(was_open) << "TLS never came up: the case proves nothing";
    EXPECT_TRUE(loop_until([&] { return second != 0 && !client->transport().is_open(); }, 500ms));
    EXPECT_EQ(second, 1) << "the request behind the callback that threw was not answered";
    EXPECT_FALSE(client->transport().is_open()) << "the transport of the attempt that failed was left open";
    client->disconnect();
    settle();
    EXPECT_EQ(first + second, 2) << "a request was answered twice";
}

// Under the timer's pass, a request's timeout. Three requests are in flight and never answered; the callback of the
// first whose timeout comes throws. The two others hear theirs, and the next request is served. The process ended.
TEST_F(Http2ClientTest, ARequestTimeoutWhoseCallbackThrowsStillTimesOutTheOthers) {
    Answer after; // before the client, which answers what it still holds when it is destroyed
    int    timed_out = 0;
    bool   up        = false;
    auto   client    = make_test_client();
    client->set_auto_reconnect(false);
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    client->set_request_timeout(300ms);
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response response) {
            EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT) << response.body().as<std::string>();
            if (++timed_out == 1)
                throw std::runtime_error("the first timeout callback throws");
        }));
    }
    EXPECT_TRUE(loop_until([&] { return timed_out == 3; }, 3s)) << "a request behind the callback that threw never timed out";
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(after)));
    EXPECT_TRUE(loop_until([&] { return after.count != 0; }));
    EXPECT_EQ(after.status, qb::http::status::OK) << after.body;
    client->disconnect();
    settle();
    EXPECT_EQ(timed_out, 3);
}

// The hook of a retry policy is the program's too, and the loop brings it. The server speaks no h2: each attempt fails
// under the handshake's event, the failure callback pushes the request back, and the hook the policy calls before each
// wait throws. The run goes on to its last attempt, as with a hook that returns. The process ended at the first call.
TEST_F(Http2ClientTest, ARetryHookThatThrowsIsContainedAndTheRunGoesOn) {
    int  hooks = 0, failures = 0; // before the client
    bool exhausted  = false;
    auto http1_only = reconnect::make_http1_only_server();
    ASSERT_TRUE(http1_only->ready());
    std::function<void(qb::http::Response)> on_response;
    auto                                    client = reconnect::make_client_for(reconnect::port_of(*http1_only));
    client->enable_auto_reconnect(
        qb::http2::RetryPolicy{}.with_initial_delay(20ms).with_multiplier(1.0).with_jitter(false).with_max_attempts(3).with_on_retry(
            [&](int, qb::duration) {
                ++hooks;
                throw std::runtime_error("the retry hook throws");
            }));
    on_response = [&](qb::http::Response response) {
        ++failures;
        if (response.body().as<std::string>().find("exhausted") != std::string::npos) {
            exhausted = true;
            return;
        }
        client->push_request(reconnect::get_test(), on_response);
    };
    ASSERT_TRUE(client->push_request(reconnect::get_test(), on_response));
    EXPECT_TRUE(loop_until([&] { return exhausted; }, 10s)) << "the run did not go on to its end";
    EXPECT_EQ(hooks, 2) << "the hook is told before the waits of attempts 2 and 3";
    EXPECT_EQ(failures, 5) << "the explicit auto-connect, three attempts, the verdict";
    client->disconnect();
    settle();
}

// ---- A callback that throws under a push costs no other request its turn, and its push one outcome (Huly QB-1246) ----

// Under a push, the pass goes on. A is in flight on the one stream the client allows. Behind it wait B, a request the
// protocol refuses where it is sent and whose callback throws; C, which the server routes and never answers; B2, as B;
// D, valid. The limit is raised and R is pushed: the exception of B's callback reaches push(R) -- the first, not B2's
// --, R is taken back before the pass can send it, and C and D are sent by that same pass: no other push runs one, and
// no response comes that would (A and C are never answered). The exception left the pass at B: C and D waited for the
// next push.
TEST_F(Http2ClientTest, ACallbackThatThrowsUnderAPushCostsNoRequestBehindItItsTurn) {
    Answer d; // before the client, which answers what it still holds when it is destroyed
    int    a = 0, b = 0, c = 0, b2 = 0, r = 0;
    bool   up     = false;
    auto   client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    client->set_max_concurrent_streams(1);
    const auto before = _server->server().hang_routed();
    ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response) { ++a; }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 1; }));
    ASSERT_TRUE(client->push_request(unsendable(), [&](qb::http::Response) {
        ++b;
        throw std::runtime_error("the first");
    }));
    ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response) { ++c; }));
    ASSERT_TRUE(client->push_request(unsendable(), [&](qb::http::Response) {
        ++b2;
        throw std::runtime_error("the second");
    }));
    ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(d)));
    ASSERT_EQ(b + b2 + c + d.count, 0) << "what waits was answered already: the case proves nothing";
    client->set_max_concurrent_streams(10);
    std::string thrown;
    try {
        client->push_request(hang(), [&](qb::http::Response) { ++r; }); // a request the server counts, were it sent
    } catch (std::runtime_error const &e) {
        thrown = e.what();
    }
    EXPECT_EQ(thrown, "the first") << "the exception that reaches the push is the first one thrown";
    EXPECT_EQ(b, 1);
    EXPECT_EQ(b2, 1) << "the pass did not go on to the second request the protocol refuses";
    EXPECT_TRUE(loop_until([&] { return d.count != 0; }, 3s)) << "what waited behind the second was not sent by that pass";
    EXPECT_EQ(d.status, qb::http::status::OK) << d.body;
    EXPECT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() >= before + 2; }, 3s))
        << "what waited behind the first was not sent by that pass";
    settle(200ms);
    EXPECT_EQ(_server->server().hang_routed(), before + 2) << "A and C, and not the request of the push that threw";
    EXPECT_EQ(r, 0);
    EXPECT_EQ(a + c, 0);
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    settle();
    EXPECT_EQ(a + c, 2);
    EXPECT_EQ(r, 0) << "the push threw, and its request was answered: two outcomes";
    EXPECT_EQ(d.count, 1);
}

// One outcome, whatever a pass under the callback did first. B's callback pushes X, then throws: the push of X runs a
// pass of its own under that callback, and that pass takes R from the queue before the exception reaches push(R) --
// sends it, or, R being one the protocol refuses, answers it, with that answer kept for the client's turn. push(R)
// throws, and R is never heard. It was: a request in flight by its response, one refused on the client's next turn, a
// batch refused likewise. (A batch in flight was not: its answers found no batch. A pin.)
TEST_F(Http2ClientTest, WhatAPassUnderTheCallbackTookIsNeverHeardOnceItsPushHasThrown) {
    for (const std::string_view form : {"a request, sent", "a batch, sent", "a request, refused", "a batch, refused"}) {
        SCOPED_TRACE(form);
        Answer x; // before the client, which answers what it still holds when it is destroyed
        int    a = 0, b = 0, r = 0;
        bool   up     = false;
        auto   client = make_test_client();
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        client->set_max_concurrent_streams(1);
        const auto before = _server->server().hang_routed();
        ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response) { ++a; }));
        ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == before + 1; }));
        ASSERT_TRUE(client->push_request(unsendable(), [&](qb::http::Response) {
            ++b;
            client->push_request(reconnect::get_test(), std::ref(x)); // its pass takes what waits: R, then X
            throw std::runtime_error("the callback throws, once a pass under it has taken the request of the push");
        }));
        client->set_max_concurrent_streams(10);
        const bool sent  = form.find("sent") != std::string_view::npos;
        bool       threw = false;
        try {
            if (form.find("a request") == 0) {
                client->push_request(sent ? reconnect::get_test() : unsendable(), [&](qb::http::Response) { ++r; });
            } else {
                std::vector<qb::http::Request> two;
                two.push_back(sent ? reconnect::get_test() : unsendable());
                two.push_back(sent ? reconnect::get_test() : unsendable());
                client->push_requests(std::move(two), [&](std::vector<qb::http::Response>) { ++r; });
            }
        } catch (std::runtime_error const &) {
            threw = true;
        }
        ASSERT_TRUE(threw) << "nothing reached the caller of the push: the case proves nothing";
        EXPECT_EQ(b, 1);
        EXPECT_EQ(r, 0);
        EXPECT_TRUE(loop_until([&] { return x.count != 0; }, 3s)) << "the request pushed from the callback was not served";
        EXPECT_EQ(x.status, qb::http::status::OK) << x.body;
        settle(200ms); // the response of a request sent, the client's turn for one refused
        EXPECT_EQ(r, 0) << "the push threw, and what it pushed was answered: two outcomes";
        EXPECT_TRUE(client->is_connected());
        client->disconnect();
        settle();
        EXPECT_EQ(a, 1);
        EXPECT_EQ(r, 0);
    }
}

// What a push takes back while it is in flight is given up on the wire too: RST_STREAM(CANCEL) on its stream, which
// frees it for what waits. Nothing is sent while the limit is 0: B waits, a request the protocol refuses where it is
// sent, whose callback pushes W, then throws. The limit is set to one stream and R is pushed -- a request the server
// never answers, then a batch of two of them. The pass of W's push sends R on the one stream, and W waits for it; the
// exception reaches push(R); R is reset -- the server sees its request cancelled, on a connection that stays --, and W
// is sent on the stream R held, by that same push. R's answer was dropped and nothing else was done: its stream
// stayed taken until the server answered, which it never does, and W waited behind it without end.
TEST_F(Http2ClientTest, WhatAPushTakesBackWhileInFlightIsResetAndItsStreamGoesToWhatWaits) {
    for (const std::string_view form : {"a request", "a batch"}) {
        SCOPED_TRACE(form);
        Answer w; // before the client, which answers what it still holds when it is destroyed
        int    b = 0, r = 0;
        bool   up     = false;
        auto   client = make_test_client();
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        client->set_max_concurrent_streams(0);
        const auto routed = _server->server().hang_routed(), cancelled = _server->server().hang_cancelled();
        ASSERT_TRUE(client->push_request(unsendable(), [&](qb::http::Response) {
            ++b;
            client->push_request(reconnect::get_test(), std::ref(w)); // its pass sends R on the one stream: W waits for it
            throw std::runtime_error("the callback throws, once a pass under it has sent the request of the push");
        }));
        ASSERT_EQ(b, 0) << "the request that waits was answered already: the case proves nothing";
        client->set_max_concurrent_streams(1);
        bool threw = false;
        try {
            if (form == "a request") {
                client->push_request(hang(), [&](qb::http::Response) { ++r; });
            } else {
                std::vector<qb::http::Request> two;
                two.push_back(hang());
                two.push_back(hang());
                client->push_requests(std::move(two), [&](std::vector<qb::http::Response>) { ++r; });
            }
        } catch (std::runtime_error const &) {
            threw = true;
        }
        ASSERT_TRUE(threw) << "nothing reached the caller of the push: the case proves nothing";
        EXPECT_EQ(b, 1);
        EXPECT_EQ(client->get_active_request_count(), 1u) << "one stream: W's, once R's is given up";
        EXPECT_TRUE(loop_until([&] { return w.count != 0; }, 3s)) << "what waited was not sent on the stream the push gave up";
        EXPECT_EQ(w.status, qb::http::status::OK) << w.body;
        EXPECT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_cancelled() == cancelled + 1; }, 3s))
            << "the server was not told that nobody waits for the request: " << _server->server().hang_cancelled() - cancelled;
        EXPECT_EQ(_server->server().hang_routed(), routed + 1) << "one request of the push reached the server, and no more";
        EXPECT_TRUE(client->is_connected()) << "the reset is of one stream: the connection stays";
        settle(200ms);
        EXPECT_EQ(r, 0) << "the push threw, and what it pushed was answered: two outcomes";
        client->disconnect();
        settle();
        EXPECT_EQ(r, 0);
        EXPECT_EQ(w.count, 1);
    }
}

// The frame that gives it up, read by a peer that answers nothing: RST_STREAM on the stream of the request taken back,
// with CANCEL (0x8) -- the stream is no longer needed (RFC 9113 section 7) --, and no other. B is refused before
// anything of it is written, so R is stream 1; W, sent behind the reset on the one stream allowed, is stream 3.
TEST_F(Http2ClientTest, WhatAPushTakesBackWhileInFlightIsResetWithCancel) {
    int                              b = 0, r = 0, w = 0; // before the client
    bool                             up = false;
    qb::http::test::Http2PlannedPeer peer(qb::http::test::Http2PlannedPeer::Plan::no_answer, 30s);
    ASSERT_NE(peer.port(), 0);
    auto client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(loop_until([&] { return up; }));
    client->set_max_concurrent_streams(0);
    ASSERT_TRUE(client->push_request(unsendable(), [&](qb::http::Response) {
        ++b;
        client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++w; }); // its pass sends R: W waits for its stream
        throw std::runtime_error("the callback throws, once a pass under it has sent the request of the push");
    }));
    client->set_max_concurrent_streams(1);
    bool threw = false;
    try {
        client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++r; });
    } catch (std::runtime_error const &) {
        threw = true;
    }
    ASSERT_TRUE(threw) << "nothing reached the caller of the push: the case proves nothing";
    EXPECT_EQ(b, 1);
    EXPECT_TRUE(loop_until([&] { return !peer.resets().empty(); }, 3s)) << "no RST_STREAM reached the peer";
    settle(200ms);
    const auto resets = peer.resets();
    ASSERT_EQ(resets.size(), 1u) << "one stream is given up, and only that one";
    EXPECT_EQ(resets[0].first, 1u) << "the stream of the request the push took back";
    EXPECT_EQ(resets[0].second, 0x8u) << "CANCEL";
    EXPECT_EQ(client->get_active_request_count(), 1u) << "W, on the stream given up";
    EXPECT_FALSE(peer.goaway());
    EXPECT_TRUE(client->is_connected());
    EXPECT_EQ(r + w, 0);
    client->disconnect();
    settle();
    EXPECT_EQ(r, 0) << "the push threw, and what it pushed was answered: two outcomes";
    EXPECT_EQ(w, 1) << "the request in flight when the client disconnects hears it";
}

// ---- A request that times out gives its stream back (Huly QB-1246) ----

// One stream, on both sides: the peer allows one (SETTINGS_MAX_CONCURRENT_STREAMS 1) and never answers the first
// request, the client allows one too. A is sent and times out; B, pushed while A is in flight, waits for its stream. At
// A's timeout the client resets A's stream -- RST_STREAM(CANCEL), which the peer reads -- and sends B on the stream that
// freed, at once, before B's own deadline; the peer answers B. A's stream was left open: the client's protocol counted
// it against the server's limit, so B was refused where it was sent, once something ran a pass -- and nothing did on
// the timer's path: B waited for the next push, or timed out in its turn.
TEST_F(Http2ClientTest, ARequestThatTimesOutIsResetAndWhatWaitsIsSentOnTheStreamItFreed) {
    Answer                           a, b; // before the client, which answers what it still holds when it is destroyed
    bool                             up = false;
    qb::http::test::Http2PlannedPeer peer(qb::http::test::Http2PlannedPeer::Plan::one_stream_the_second_answered, 30s);
    ASSERT_NE(peer.port(), 0);
    auto client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(loop_until([&] { return up; }));
    client->set_max_concurrent_streams(1);
    client->set_request_timeout(400ms);
    ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(a))); // stream 1
    settle(150ms);
    ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(b))); // waits for A's stream; its deadline is 150 ms after A's
    ASSERT_EQ(a.count + b.count, 0) << "an answer came before the timeout: the case proves nothing";
    EXPECT_TRUE(loop_until([&] { return a.count != 0; }, 3s));
    EXPECT_EQ(a.status, qb::http::status::REQUEST_TIMEOUT) << a.body;
    EXPECT_TRUE(loop_until([&] { return b.count != 0; }, 3s));
    EXPECT_EQ(b.status, qb::http::status::OK) << "what waited was not sent on the stream the timeout freed: " << b.body;
    const auto resets = peer.resets();
    ASSERT_EQ(resets.size(), 1u) << "the stream of the request that timed out is reset, and no other";
    EXPECT_EQ(resets[0].first, 1u);
    EXPECT_EQ(resets[0].second, 0x8u) << "CANCEL";
    EXPECT_FALSE(peer.goaway());
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    settle();
    EXPECT_EQ(a.count, 1) << "the request that timed out was answered twice";
    EXPECT_EQ(b.count, 1);
}

// The members of a batch that time out are reset too, each on its stream, and the batch hears its 408s once.
TEST_F(Http2ClientTest, TheMembersOfABatchThatTimeOutAreResetEachOnItsStream) {
    int                              heard = 0; // before the client
    std::vector<qb::http::Response>  responses;
    bool                             up = false;
    qb::http::test::Http2PlannedPeer peer(qb::http::test::Http2PlannedPeer::Plan::no_answer, 30s);
    ASSERT_NE(peer.port(), 0);
    auto client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(loop_until([&] { return up; }));
    client->set_request_timeout(300ms);
    std::vector<qb::http::Request> two;
    two.push_back(reconnect::get_test());
    two.push_back(reconnect::get_test());
    ASSERT_TRUE(client->push_requests(std::move(two), [&](std::vector<qb::http::Response> r) {
        ++heard;
        responses = std::move(r);
    }));
    EXPECT_TRUE(loop_until([&] { return heard != 0; }, 3s));
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_EQ(responses[1].status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_TRUE(loop_until([&] { return peer.resets().size() >= 2; }, 1s));
    settle(100ms);
    auto resets = peer.resets();
    std::sort(resets.begin(), resets.end());
    ASSERT_EQ(resets.size(), 2u);
    EXPECT_EQ(resets[0], std::make_pair(1u, 0x8u));
    EXPECT_EQ(resets[1], std::make_pair(3u, 0x8u));
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    settle();
    EXPECT_EQ(heard, 1);
}

// Against a qb server, which allows 50 streams: 60 requests it never answers time out, in two waves of 30, then a
// request is pushed and served. The streams of those that timed out stayed open in the client's protocol, which refused
// every request past the server's 50 where it was sent, 503 "Failed to send HTTP/2 request": the last ten of the
// second wave, and every request after them on that connection, for as long as it lived. The server is told of each:
// it sees its 60 requests cancelled.
TEST_F(Http2ClientTest, RequestsThatTimeOutDoNotUseUpTheStreamsTheServerAllows) {
    Answer after; // before the client, which answers what it still holds when it is destroyed
    int    timed_out = 0, other = 0;
    bool   up     = false;
    auto   client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    const auto cancelled = _server->server().hang_cancelled();
    client->set_request_timeout(400ms);
    for (int wave = 1; wave <= 2; ++wave) {
        SCOPED_TRACE(wave);
        const auto routed = _server->server().hang_routed();
        for (int i = 0; i < 30; ++i) {
            ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response response) {
                (response.status() == qb::http::status::REQUEST_TIMEOUT ? timed_out : other) += 1;
            }));
        }
        EXPECT_TRUE(loop_until([&] { return timed_out + other == 30 * wave; }, 5s)) << timed_out << " timed out, " << other << " else";
        EXPECT_EQ(_server->server().hang_routed(), routed + 30) << "the server did not take the 30 requests of the wave";
    }
    EXPECT_EQ(timed_out, 60);
    EXPECT_EQ(other, 0) << "a request past the server's limit was refused where it was sent";
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(after)));
    EXPECT_TRUE(loop_until([&] { return after.count != 0; }));
    EXPECT_EQ(after.status, qb::http::status::OK) << "the streams that timed out were still counted: " << after.body;
    EXPECT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_cancelled() == cancelled + 60; }, 5s))
        << "the server was not told: " << _server->server().hang_cancelled() - cancelled << " of 60";
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    settle();
    EXPECT_EQ(timed_out, 60);
}

// The same against a qb server: one stream allowed by the client. A, a request the server never answers, times out at
// 400 ms; B, pushed 200 ms after A, waits for A's stream, its own deadline at 600 ms. A pass at A's timeout sends B, which
// the server answers at once, before B's deadline. No pass ran there: B waited, and heard 408 "Request timeout while
// pending" at 600 ms.
TEST_F(Http2ClientTest, WhatWaitsForTheStreamOfARequestThatTimesOutIsSentAtOnce) {
    Answer a, b; // before the client, which answers what it still holds when it is destroyed
    bool   up     = false;
    auto   client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(400ms);
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    client->set_max_concurrent_streams(1);
    ASSERT_TRUE(client->push_request(hang(), std::ref(a)));
    settle(200ms);
    qb::http::Request user;
    user.method() = qb::http::Method::GET;
    user.uri()    = qb::io::uri("/api/users/6");
    ASSERT_TRUE(client->push_request(std::move(user), std::ref(b)));
    EXPECT_TRUE(loop_until([&] { return b.count != 0; }, 3s));
    EXPECT_EQ(a.status, qb::http::status::REQUEST_TIMEOUT) << a.body;
    EXPECT_EQ(b.status, qb::http::status::OK) << "the request that waited for the stream of a timed-out request was not sent: " << b.body;
    EXPECT_EQ(b.body, "User ID: 6 (via HTTP/2)");
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    settle();
    EXPECT_EQ(a.count + b.count, 2);
}

// ---- What a push takes back is taken back by its own number, and nothing else is (Huly QB-1246) ----

// What a push takes back is named by its number: the request's, or the batch's. The client numbers its requests and its
// batches apart, both from 1, so a request and a batch can carry the same number; and a Request object pushed twice is
// two requests. X is refused where it is sent; its callback pushes P, then throws. R is pushed: a pass under X's callback
// refuses R, then P -- both answers owed, each tagged. push(R) throws: R's answer is never heard, P's is heard once.
//   - the same Request object pushed as R and as P;
//   - R a request and P a batch with R's number: X request 1, R request 2, P batch 2 (a batch served first is batch 1);
//   - R a batch and P a request with R's number: X a batch of one (batch 1), R batch 2, P request 2 (a request served
//     first is request 1).
TEST_F(Http2ClientTest, WhatAPushTakesBackIsNamedByItsNumberAndNothingElseIsTakenBack) {
    for (const std::string_view form : {"the same object", "a request, a batch of its number", "a batch, a request of its number"}) {
        SCOPED_TRACE(form);
        int                   r = 0, p = 0, x = 0; // before the client, which answers what it still holds when it is destroyed
        int                   p_status     = -1;
        bool                  up           = false;
        int                   served       = 0; // the request or the batch served first, so that the two numbers meet
        const auto            u            = unsendable();
        const bool            r_is_a_batch = form == "a batch, a request of its number";
        const bool            p_is_a_batch = form == "a request, a batch of its number";
        std::function<void()> push_p; // what X's callback calls: assigned once the client is there
        auto                  client = make_test_client();
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        if (p_is_a_batch) {
            std::vector<qb::http::Request> one;
            one.push_back(reconnect::get_test());
            ASSERT_TRUE(client->push_requests(std::move(one), [&](std::vector<qb::http::Response>) { ++served; }));
            ASSERT_TRUE(loop_until([&] { return served == 1; }));
        } else if (r_is_a_batch) {
            ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) { ++served; }));
            ASSERT_TRUE(loop_until([&] { return served == 1; }));
        }
        client->set_max_concurrent_streams(0);
        push_p = [&] {
            if (p_is_a_batch) {
                std::vector<qb::http::Request> two{u, u};
                client->push_requests(std::move(two), [&](std::vector<qb::http::Response> responses) {
                    ++p;
                    p_status = responses.empty() ? -1 : static_cast<int>(responses[0].status().code());
                });
            } else {
                client->push_request(qb::http::Request(u), [&](qb::http::Response response) {
                    ++p;
                    p_status = static_cast<int>(response.status().code());
                });
            }
        };
        if (r_is_a_batch) {
            std::vector<qb::http::Request> one{u};
            ASSERT_TRUE(client->push_requests(std::move(one), [&](std::vector<qb::http::Response>) {
                ++x;
                push_p();
                throw std::runtime_error("X's callback throws, once a pass under it has refused R and P");
            }));
        } else {
            ASSERT_TRUE(client->push_request(unsendable(), [&](qb::http::Response) {
                ++x;
                push_p();
                throw std::runtime_error("X's callback throws, once a pass under it has refused R and P");
            }));
        }
        client->set_max_concurrent_streams(1);
        bool threw = false;
        try {
            if (r_is_a_batch) {
                std::vector<qb::http::Request> two{u, u};
                client->push_requests(std::move(two), [&](std::vector<qb::http::Response>) { ++r; });
            } else {
                client->push_request(qb::http::Request(u), [&](qb::http::Response) { ++r; });
            }
        } catch (std::runtime_error const &) {
            threw = true;
        }
        ASSERT_TRUE(threw) << "nothing reached the caller of the push: the case proves nothing";
        EXPECT_EQ(x, 1);
        settle(300ms); // the client's turn
        EXPECT_EQ(r, 0) << "the push threw, and what it pushed was answered: two outcomes";
        EXPECT_EQ(p, 1) << "another request's answer was taken back with what the push pushed";
        EXPECT_EQ(p_status, static_cast<int>(qb::http::status::BAD_REQUEST));
        client->disconnect();
        settle();
        EXPECT_EQ(r, 0);
        EXPECT_EQ(p, 1);
    }
}

// The connection ends under the callback, then the callback throws. X's callback pushes W -- whose pass sends R, a
// request the server never answers, then a batch of two of them, on the one stream allowed --, calls disconnect(), then
// throws. The close answers R and W, under a callback: their answers are owed, R's tagged with its number, through the
// failure of a request or of a batch. push(R) throws: R hears nothing, W hears its 503 once, and the client connects
// again and is served.
TEST_F(Http2ClientTest, WhatAPushTakesBackIsTakenBackFromTheAnswersOfACloseMadeUnderTheCallback) {
    for (const std::string_view form : {"a request", "a batch"}) {
        SCOPED_TRACE(form);
        Answer w, again; // before the client, which answers what it still holds when it is destroyed
        int    b = 0, r = 0;
        bool   up     = false;
        auto   client = make_test_client();
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        client->set_max_concurrent_streams(0);
        ASSERT_TRUE(client->push_request(unsendable(), [&](qb::http::Response) {
            ++b;
            client->push_request(reconnect::get_test(), std::ref(w)); // its pass sends R: W waits for its stream
            client->disconnect();                                     // R and W answered by the close: owed, under this callback
            throw std::runtime_error("the callback throws, once the close has answered what the push pushed");
        }));
        client->set_max_concurrent_streams(1);
        bool threw = false;
        try {
            if (form == "a request") {
                client->push_request(hang(), [&](qb::http::Response) { ++r; });
            } else {
                std::vector<qb::http::Request> two;
                two.push_back(hang());
                two.push_back(hang());
                client->push_requests(std::move(two), [&](std::vector<qb::http::Response>) { ++r; });
            }
        } catch (std::runtime_error const &) {
            threw = true;
        }
        ASSERT_TRUE(threw) << "nothing reached the caller of the push: the case proves nothing";
        EXPECT_EQ(b, 1);
        settle(300ms); // the client's turn
        EXPECT_EQ(r, 0) << "the push threw, and the close it made under the callback answered what it pushed: two outcomes";
        EXPECT_EQ(w.count, 1);
        EXPECT_EQ(w.status, qb::http::status::SERVICE_UNAVAILABLE) << w.body;
        up = false;
        ASSERT_TRUE(client->connect([&](bool ok, const std::string &) { up = ok; }));
        ASSERT_TRUE(loop_until([&] { return up; }, 3s)) << "the client did not connect again";
        ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(again)));
        EXPECT_TRUE(loop_until([&] { return again.count != 0; }));
        EXPECT_EQ(again.status, qb::http::status::OK) << again.body;
        client->disconnect();
        settle();
        EXPECT_EQ(r, 0);
        EXPECT_EQ(w.count, 1);
    }
}

// ---- A request field that cannot be sent refuses its request, the same way on the three clients (Huly QB-1191) ----

/// Requests that carry a field HTTP/1.1 cannot write, and the name the refusal says: LF, NUL, CR, DEL and 0x01 in a
/// value, SP, DEL and 0x01 in a name, CR in a cookie, LF in a trailer field, and a trailer field a trailer section must
/// not carry. Their target is a route the server counts and never answers. @p shown is the name as the reason prints
/// it, when it is not the name; @p says what the reason says of the fault.
struct UnsendableField {
    std::string_view what;
    std::string      name;
    std::string      value;
    bool             trailer;
    std::string_view shown = {};
    std::string_view says  = {};
};
inline const UnsendableField k_unsendable_fields[] = {
    {"LF in a value", "x-probe", "a\nb", false},
    {"NUL in a value", "x-probe", std::string("a\0b", 3), false},
    {"CR in a value", "x-probe", "a\rb", false},
    {"SP in a name", "x probe", "v", false},
    {"CR in a cookie", "cookie", "session=1\r", false},
    {"LF in a trailer field", "x-sum", "a\nb", true},
    {"DEL in a value",
     "x-probe",
     "a\x7f"
     "b",
     false,
     {},
     "its value carries DEL"},
    {"0x01 in a value",
     "x-probe",
     "a\x01"
     "b",
     false,
     {},
     "its value carries \\x01"},
    {"DEL in a name",
     "x\x7f"
     "probe",
     "v", false, "xDELprobe", "its name carries DEL"},
    {"0x01 in a name",
     "x\x01"
     "probe",
     "v", false, "x\\x01probe", "its name carries \\x01"},
    {"a trailer field a trailer section must not carry", "content-length", "1", true, {}, "a trailer section must not carry it"},
};

/// The name as the reason prints it, between backquotes.
inline std::string
named(const UnsendableField &field) {
    return "`" + (field.shown.empty() ? field.name : std::string(field.shown)) + "`";
}

/// A request to @p target carrying @p field.
inline qb::http::Request
carrying(const UnsendableField &field, const char *target = "/api/hang") {
    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri(target);
    if (field.trailer) {
        request.trailers().set_header(field.name, field.value);
    } else {
        request.set_header(field.name, field.value);
    }
    return request;
}

// Each is refused where the client writes its fields, 400, with a reason that names the field, as the HTTP/1.1 client
// refuses it: nothing of it reaches the server, the connection stays, and the request behind it is served. Such a field
// was dropped and the request sent without it -- a dropped `authorization` sent the request unauthenticated, without a
// word; a trailer field that HTTP/2 cannot carry refused the request 503, "Failed to send HTTP/2 request".
TEST_F(Http2ClientTest, ARequestFieldThatCannotBeSentRefusesItsRequestAndTheConnectionServesOn) {
    for (const auto &field : k_unsendable_fields) {
        SCOPED_TRACE(field.what);
        Answer refused, behind; // before the client, which answers what it still holds when it is destroyed
        bool   up     = false;
        auto   client = make_test_client();
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        const auto routed = _server->server().hang_routed();
        ASSERT_TRUE(client->push_request(carrying(field), std::ref(refused)));
        ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(behind)));
        EXPECT_TRUE(loop_until([&] { return refused.count != 0 && behind.count != 0; }, 3s));
        EXPECT_EQ(refused.status, qb::http::status::BAD_REQUEST) << refused.body;
        EXPECT_NE(refused.body.find(named(field)), std::string::npos) << "the refusal does not name the field: " << refused.body;
        EXPECT_NE(refused.body.find("cannot be sent"), std::string::npos) << refused.body;
        EXPECT_NE(refused.body.find(field.says), std::string::npos) << refused.body;
        EXPECT_EQ(behind.status, qb::http::status::OK) << behind.body;
        settle(100ms);
        EXPECT_EQ(_server->server().hang_routed(), routed) << "the request refused reached the server";
        EXPECT_TRUE(client->is_connected()) << "the refusal cost the connection";
        client->disconnect();
        settle();
        EXPECT_EQ(refused.count + behind.count, 2);
    }
}

// Nothing of a request refused for a field is written: a peer that answers nothing reads the HEADERS of the request
// behind them alone, on stream 1 -- the refused requests spent no stream identifier. They went out with the field dropped,
// one HEADERS each.
TEST_F(Http2ClientTest, ARequestRefusedForAFieldWritesNothing) {
    int                              heard = 0; // before the client
    bool                             up    = false;
    qb::http::test::Http2PlannedPeer peer(qb::http::test::Http2PlannedPeer::Plan::no_answer, 30s);
    ASSERT_NE(peer.port(), 0);
    auto client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(loop_until([&] { return up; }));
    for (const auto &field : k_unsendable_fields) {
        ASSERT_TRUE(client->push_request(
            carrying(field), [&](qb::http::Response response) { heard += response.status() == qb::http::status::BAD_REQUEST ? 1 : 0; }));
    }
    ASSERT_TRUE(client->push_request(reconnect::get_test(), [](qb::http::Response) {}));
    EXPECT_TRUE(loop_until([&] { return !peer.requests().empty() && heard == static_cast<int>(std::size(k_unsendable_fields)); }, 3s));
    settle(200ms);
    const auto requests = peer.requests();
    ASSERT_EQ(requests.size(), 1u) << "a request refused for a field was written";
    EXPECT_EQ(requests[0], 1u);
    bool test_path = false;
    for (const auto &[name, value] : peer.fields_of(1)) {
        test_path = test_path || (name == ":path" && value == "/api/test");
    }
    EXPECT_TRUE(test_path) << "stream 1 is not the request behind the refused ones";
    EXPECT_EQ(heard, static_cast<int>(std::size(k_unsendable_fields)));
    client->disconnect();
    settle();
}

// A value leaves without the SP and HTAB at its edges, which are not part of it (RFC 9110 section 5.5, RFC 9113
// section 8.2.1): " v " is sent "v", and a value of whitespace alone is sent empty -- an HTTP/1.1 receiver reads the
// same. Whitespace inside a value is part of it. Such a value was dropped, and the field with it. A connection-specific
// field is still left out, as a translating intermediary must (RFC 9113 section 8.2.2): `connection: close`, `te: gzip`
// (pins).
TEST_F(Http2ClientTest, AValueLeavesWithoutTheWhitespaceAtItsEdgesAndAConnectionFieldIsStillLeftOut) {
    bool                             up = false; // before the client
    qb::http::test::Http2PlannedPeer peer(qb::http::test::Http2PlannedPeer::Plan::no_answer, 30s);
    ASSERT_NE(peer.port(), 0);
    auto client = reconnect::make_client_for(peer.port());
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(loop_until([&] { return up; }));
    qb::http::Request edges = reconnect::get_test();
    edges.set_header("x-edge", " v ");
    edges.set_header("x-blank", "  ");
    edges.set_header("x-inside", "a \t b");
    ASSERT_TRUE(client->push_request(std::move(edges), [](qb::http::Response) {}));
    qb::http::Request hop = reconnect::get_test();
    hop.set_header("connection", "close");
    hop.set_header("te", "gzip");
    hop.set_header("x-kept", "1");
    ASSERT_TRUE(client->push_request(std::move(hop), [](qb::http::Response) {}));
    qb::http::Request trailed = reconnect::get_test(); // a trailer field's value, likewise (its trailer section's HEADERS)
    trailed.trailers().set_header("x-sum", " v ");
    ASSERT_TRUE(client->push_request(std::move(trailed), [](qb::http::Response) {}));
    EXPECT_TRUE(loop_until([&] { return peer.requests().size() == 4; }, 3s)) << "three header sections and one trailer section";
    settle(100ms);
    const auto field = [&](uint32_t stream, std::string_view name) -> std::optional<std::string> {
        for (const auto &[n, v] : peer.fields_of(stream)) {
            if (n == name) {
                return v;
            }
        }
        return std::nullopt;
    };
    EXPECT_EQ(field(1, "x-edge"), std::optional<std::string>("v")) << "the value was not sent trimmed";
    EXPECT_EQ(field(1, "x-blank"), std::optional<std::string>("")) << "a value of whitespace alone was not sent empty";
    EXPECT_EQ(field(1, "x-inside"), std::optional<std::string>("a \t b"));
    EXPECT_EQ(field(3, "connection"), std::nullopt);
    EXPECT_EQ(field(3, "te"), std::nullopt);
    EXPECT_EQ(field(3, "x-kept"), std::optional<std::string>("1"));
    EXPECT_EQ(field(5, "x-sum"), std::optional<std::string>("v")) << "the trailer field's value was not sent trimmed";
    client->disconnect();
    settle();
}

// ---- The timeouts of a connection are answered on that connection, whatever a 408 callback does (Huly QB-1246) ----

// Two requests the server never answers time out in one pass of the timer (the thread sleeps past both deadlines). The
// first 408's callback disconnects -- the other request hears 503 --, connects again, runs the loop until connected,
// raises the timeout to 10 s and pushes C and D, which take streams 1 and 3 of the new connection. The pass goes on with
// what it had taken: nothing of it is on the new connection. It took stream numbers: it went on with one that named C's
// or D's stream now, answered that request 408 at once, though its timeout was 10 s, and reset its stream.
TEST_F(Http2ClientTest, TheTimeoutsOfAConnectionAreNeverAnsweredOnTheNextOne) {
    Answer c, d; // before the client, which answers what it still holds when it is destroyed
    int    timed_out = 0, refused = 0, other = 0;
    bool   up = false, again = false, reconnected = false;
    auto   client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(300ms);
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    const auto routed = _server->server().hang_routed(), cancelled = _server->server().hang_cancelled();
    const auto first = [&](qb::http::Response response, std::source_location const where = std::source_location::current()) {
        qb::http::test::fail_wait::called_from const caller{where};
        if (response.status() == qb::http::status::REQUEST_TIMEOUT) {
            ++timed_out;
        } else if (response.status() == qb::http::status::SERVICE_UNAVAILABLE) {
            ++refused;
        } else {
            ++other;
        }
        if (response.status() != qb::http::status::REQUEST_TIMEOUT || reconnected) {
            return;
        }
        reconnected = true;
        client->disconnect();
        client->connect([&](bool ok, const std::string &) { again = ok; });
        (void) loop_until([&] { return again; }, 3s);
        client->set_request_timeout(10s);
        (void) client->push_request(hang(), std::ref(c));
        (void) client->push_request(hang(), std::ref(d));
    };
    ASSERT_TRUE(client->push_request(hang(), first));
    ASSERT_TRUE(client->push_request(hang(), first));
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == routed + 2; }));
    std::this_thread::sleep_for(400ms); // the timer's pass comes late: both are past their deadline when it runs
    ASSERT_TRUE(loop_until([&] { return timed_out + refused + other == 2; }, 3s));
    ASSERT_TRUE(again) << "the callback did not connect again";
    EXPECT_TRUE(loop_until([&] { return _server->server().hang_routed() == routed + 4; }, 3s)) << "C and D were not sent";
    settle(500ms);
    EXPECT_EQ(timed_out, 1);
    EXPECT_EQ(refused, 1) << "the request behind is answered by the disconnect()";
    EXPECT_EQ(other, 0);
    EXPECT_EQ(c.count + d.count, 0) << "a request of the new connection was answered by the pass of the old one's timeouts: " << c.body
                                    << d.body;
    EXPECT_EQ(client->get_active_request_count(), 2u);
    // A's stream reset, B's ended with its connection: two on the server, and none of the new connection's.
    EXPECT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_cancelled() >= cancelled + 2; }));
    settle(200ms);
    EXPECT_EQ(_server->server().hang_cancelled(), cancelled + 2) << "a stream of the new connection was reset";
    client->disconnect();
    settle();
    EXPECT_EQ(c.count + d.count, 2);
}

// ---- The queue's timeouts are set aside before a 408 callback runs (Huly QB-1246) ----

// One stream allowed: A in flight and B queued behind it are both past their deadline when the timer's pass runs (the
// thread sleeps past them), and A's 408 callback pushes C. The pass took the queue's timeouts after the requests in
// flight: the pass C's push ran sent B -- a request that had timed out already -- on the stream A freed, where it was
// reset and answered 408 at the next tick, C waiting for it. B is never sent and hears one 408, "Request timeout while
// pending"; C is sent on A's stream.
TEST_F(Http2ClientTest, AQueuedRequestThatTimedOutIsNeverSentFromA408CallbackOfThePass) {
    Answer b, c; // before the client, which answers what it still holds when it is destroyed
    int    a      = 0;
    bool   up     = false;
    auto   client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_max_concurrent_streams(1);
    client->set_request_timeout(300ms);
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    const auto routed = _server->server().hang_routed();
    ASSERT_TRUE(client->push_request(hang(), [&](qb::http::Response response) {
        ++a;
        if (response.status() == qb::http::status::REQUEST_TIMEOUT) {
            (void) client->push_request(reconnect::get_test(), std::ref(c));
        }
    }));
    ASSERT_TRUE(client->push_request(hang(), std::ref(b)));
    ASSERT_TRUE(ServerThread::pump_until([&] { return _server->server().hang_routed() == routed + 1; }));
    ASSERT_EQ(client->get_active_request_count(), 1u) << "B did not wait for A's stream: the case proves nothing";
    std::this_thread::sleep_for(400ms); // the timer's pass comes late: A and B are past their deadline when it runs
    EXPECT_TRUE(loop_until([&] { return a == 1 && b.count == 1 && c.count == 1; }, 3s));
    settle(300ms);
    EXPECT_EQ(a, 1);
    EXPECT_EQ(b.count, 1);
    EXPECT_EQ(b.status, qb::http::status::REQUEST_TIMEOUT) << b.body;
    EXPECT_EQ(b.body, "Request timeout while pending") << "B was sent, though it had timed out already";
    EXPECT_EQ(c.status, qb::http::status::OK) << c.body;
    EXPECT_EQ(_server->server().hang_routed(), routed + 1) << "the queued request that had timed out reached the server";
    client->disconnect();
    settle();
}

// ---- What waits for a stream a stream error frees is sent; a 304 is never refused for its length (Huly QB-1246) ----

class LimitServer;
class LimitSession : public qb::http2::use<LimitSession>::session<LimitServer> {
public:
    explicit LimitSession(LimitServer &server)
        : session(server) {}
};
using LimitContext = qb::http::Context<LimitSession>;

/// A body of n octets declared by its content-length (/declared/n) or delivered without one (/streamed/n), a stream the
/// server resets (/reset), a 304 that declares the representation's length (/not-modified/n), and /small.
class LimitServer : public qb::http2::use<LimitServer>::server<LimitSession> {
public:
    LimitServer() {
        router().get("/declared/:n", [](std::shared_ptr<LimitContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::string(std::stoul(std::string(ctx->path_param("n"))), 'd');
            ctx->complete();
        });
        router().get("/streamed/:n", [](std::shared_ptr<LimitContext> ctx) {
            ctx->response().status() = qb::http::status::OK;
            auto stream              = ctx->begin_stream(); // no content-length: its DATA frames are the body
            (void) stream->write(std::string(std::stoul(std::string(ctx->path_param("n"))), 's'));
            stream->end();
        });
        router().get("/reset", [](std::shared_ptr<LimitContext> ctx) {
            if (auto session = ctx->session()) {
                (void) session->reset_stream(static_cast<uint32_t>(ctx->request().stream_id), qb::protocol::http2::ErrorCode::CANCEL,
                                             "reset by the test");
            }
        });
        router().get("/not-modified/:n", [](std::shared_ptr<LimitContext> ctx) {
            ctx->response().status() = qb::http::status::NOT_MODIFIED;
            ctx->response().set_header("content-length", std::string(ctx->path_param("n")));
            ctx->complete();
        });
        router().get("/small", [](std::shared_ptr<LimitContext> ctx) { ctx->text("small"); });
        router().compile();
    }
};

using LimitThread = qb::http::test::ServerThread<LimitServer>;

inline std::unique_ptr<LimitThread>
start_limit_server() {
    const std::string cert = qb::http::test::ssl_cert_path().string(), key = qb::http::test::ssl_key_path().string();
    return std::make_unique<LimitThread>([cert, key](LimitServer &srv) -> bool {
        srv.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2"}));
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0) {
            return false;
        }
        srv.start();
        return true;
    });
}

inline qb::http::Request
get_of(const std::string &target) {
    qb::http::Request request;
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri(target);
    return request;
}

// A request that a stream error ends frees its stream, and what waited for it is sent at once, as after a response. One
// stream allowed; A, then B behind it. A ends by a stream error: a body past the client's limit of 1 KiB, declared by
// its content-length and then delivered without one, which the client resets (ENHANCE_YOUR_CALM), and a stream the
// server resets. B is answered 200 at once. No pass ran there: B waited for the next push or response, and heard its own
// 408, "Request timeout while pending", at its deadline. The control: A's body within the limit.
TEST_F(Http2ClientTest, WhatWaitsForTheStreamAStreamErrorFreesIsSentAtOnce) {
    struct Shape {
        std::string_view what;
        const char      *first;
        qb::http::status first_status;
    };
    const Shape shapes[] = {
        {"a body declared past the limit", "/declared/4096", qb::http::status::BAD_GATEWAY},
        {"a body delivered past the limit", "/streamed/4096", qb::http::status::BAD_GATEWAY},
        {"a stream the server resets", "/reset", qb::http::status::BAD_GATEWAY},
        {"the control: a body within the limit", "/declared/512", qb::http::status::OK},
    };
    const auto server = start_limit_server();
    ASSERT_TRUE(server->ready());
    for (const auto &shape : shapes) {
        SCOPED_TRACE(shape.what);
        Answer a, b; // before the client, which answers what it still holds when it is destroyed
        bool   up     = false;
        auto   client = reconnect::make_client_for(server->port());
        client->set_auto_reconnect(false);
        client->set_max_concurrent_streams(1);
        client->set_max_body_size(1024);
        client->set_request_timeout(3s);
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(loop_until([&] { return up; }));
        ASSERT_TRUE(client->push_request(get_of(shape.first), std::ref(a)));
        ASSERT_TRUE(client->push_request(get_of("/small"), std::ref(b)));
        ASSERT_EQ(client->get_active_request_count(), 1u) << "B did not wait for A's stream: the case proves nothing";
        EXPECT_TRUE(loop_until([&] { return a.count != 0 && b.count != 0; }, 2s)) << "B was not sent once A's stream was free";
        EXPECT_EQ(a.status, shape.first_status) << a.body;
        EXPECT_EQ(b.status, qb::http::status::OK) << b.body;
        EXPECT_EQ(b.body, "small");
        client->disconnect();
        settle();
        EXPECT_EQ(a.count + b.count, 2);
    }
}

// A 304 may declare the length its representation would have (RFC 9110 section 8.6), and no content follows it: the
// client's body limit never refuses it, nor a 1xx, a 204 or a response to HEAD -- the exemption the client applies to a
// response's content-length; HTTP/1.1 reads such a length as 0. Judged where the field was read, before :status was
// known, a 304 that declared 4 KiB under a limit of 1 KiB failed 502. The control: a 200 that declares the same, 502.
TEST_F(Http2ClientTest, ANotModifiedThatDeclaresALengthPastTheBodyLimitIsAnswered304) {
    const auto server = start_limit_server();
    ASSERT_TRUE(server->ready());
    Answer      not_modified, declared; // before the client, which answers what it still holds when it is destroyed
    std::string length;
    bool        up     = false;
    auto        client = reconnect::make_client_for(server->port());
    client->set_auto_reconnect(false);
    client->set_max_body_size(1024);
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(loop_until([&] { return up; }));
    ASSERT_TRUE(client->push_request(get_of("/not-modified/4096"), [&](qb::http::Response response) {
        length = std::string(response.header("content-length"));
        not_modified(std::move(response));
    }));
    ASSERT_TRUE(client->push_request(get_of("/declared/4096"), std::ref(declared)));
    EXPECT_TRUE(loop_until([&] { return not_modified.count != 0 && declared.count != 0; }, 3s));
    EXPECT_EQ(not_modified.status, qb::http::status::NOT_MODIFIED) << not_modified.body;
    EXPECT_EQ(length, "4096") << "the 304 declared no length: the case proves nothing";
    EXPECT_EQ(declared.status, qb::http::status::BAD_GATEWAY) << declared.body;
    EXPECT_NE(declared.body.find("exceeds the client's limit of 1024 bytes"), std::string::npos) << declared.body;
    EXPECT_TRUE(client->is_connected()) << "a refused stream cost the connection";
    client->disconnect();
    settle();
}

// ---- What a push takes back is given up without a pass under it (Huly QB-1246, the final review) ----

// withdraw() resets the streams of what a push takes back without telling the protocol's handler. Told, the first reset
// ran a pass inside withdraw() (on(Http2StreamErrorEvent)), and the callback of a request that pass refused may
// disconnect, connect again and run the loop, as readme/14 allows: the stream numbers withdraw() still held then named
// the new connection's requests -- one answered 502 to the program, "request given up by the client", the next reset.
// Nothing is sent while the limit is 0: B waits, a request the protocol refuses where it is sent. The limit is raised
// to two streams and a batch of two requests the server never answers is pushed: the pass refuses B, whose callback
// pushes Y -- another such request, which waits behind the two streams the batch's members hold -- and throws. The push
// throws and takes the batch back, both streams reset; Y is refused once they are free, and its callback disconnects,
// connects again, runs the loop until connected and pushes N1 and N2, streams 1 and 3 of the new connection, which the
// server answers 200.
TEST_F(Http2ClientTest, WhatAPushTakesBackIsGivenUpWithNoPassThatACallbackCouldReconnectFrom) {
    Answer                                  n1, n2; // before the client, which answers what it still holds when it is destroyed
    int                                     b = 0, r = 0, y = 0;
    std::size_t                             in_flight = 0;
    bool                                    up = false, again = false;
    std::function<void(qb::http::Response)> reconnecting; // what a callback of the client calls: assigned once it is there
    auto                                    client = make_test_client();
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    client->connect([&](bool ok, const std::string &) { up = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
    client->set_max_concurrent_streams(0);
    reconnecting = [&](qb::http::Response response) {
        if (client.use_count() == 0)
            return; // under the client's destructor (a case that failed): nothing to reconnect, no loop to run there
        ++y;
        EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST) << response.body().as<std::string>();
        client->disconnect();
        client->connect([&](bool ok, const std::string &) { again = ok; });
        (void) loop_until([&] { return again; }, 3s);
        (void) client->push_request(reconnect::get_test(), std::ref(n1));
        (void) client->push_request(reconnect::get_test(), std::ref(n2));
    };
    ASSERT_TRUE(client->push_request(unsendable(), [&](qb::http::Response) {
        ++b;
        client->push_request(unsendable(), reconnecting); // it waits behind the two streams the batch's members hold
        in_flight = client->get_active_request_count();
        throw std::runtime_error("the callback throws, once a pass under it has sent both members of the batch");
    }));
    ASSERT_EQ(b, 0) << "the request that waits was answered already: the case proves nothing";
    client->set_max_concurrent_streams(2);
    bool threw = false;
    try {
        std::vector<qb::http::Request> two;
        two.push_back(hang());
        two.push_back(hang());
        client->push_requests(std::move(two), [&](std::vector<qb::http::Response>) { ++r; });
    } catch (std::runtime_error const &) {
        threw = true;
    }
    ASSERT_TRUE(threw) << "nothing reached the caller of the push: the case proves nothing";
    EXPECT_EQ(b, 1);
    EXPECT_EQ(in_flight, 2u) << "the batch's members were not both in flight: withdraw() had one stream at most to give up";
    ASSERT_TRUE(loop_until([&] { return y != 0 && again; }, 3s))
        << "Y's callback did not run, or did not connect again: the case proves nothing";
    EXPECT_TRUE(loop_until([&] { return n1.count != 0 && n2.count != 0; }, 3s)) << "the new connection's requests were not answered";
    EXPECT_EQ(n1.status, qb::http::status::OK) << "a request of the new connection was answered by withdraw(): " << n1.body;
    EXPECT_EQ(n2.status, qb::http::status::OK) << "a stream of the new connection was reset by withdraw(): " << n2.body;
    EXPECT_TRUE(client->is_connected());
    settle(200ms);
    EXPECT_EQ(y, 1);
    EXPECT_EQ(n1.count + n2.count, 2);
    client->disconnect();
    settle();
    EXPECT_EQ(r, 0) << "the push threw, and what it pushed was answered: two outcomes";
}

#ifdef QB_WITH_LOGGING
// What the client contains it says, at WARN, where the build has a logger -- QB_WITH_LOGGING, as here, with the log
// started at that level; QB_STDOUT_LOGGING writes the same line to the standard output; a build with neither says
// nothing. One line a callback: the client, what was called, what it threw.
TEST_F(Http2ClientTest, WhatTheClientContainsIsLoggedAtWarnInABuildWithALogger) {
    Answer            behind; // before the client, which answers what it still holds when it is destroyed
    int               a   = 0;
    const std::string log = http2_client_crossing_test::log_of([&] {
        bool up     = false;
        auto client = make_test_client();
        client->set_auto_reconnect(false);
        client->set_request_timeout(qb::duration::zero());
        client->connect([&](bool ok, const std::string &) { up = ok; });
        ASSERT_TRUE(ServerThread::pump_until([&] { return up; }));
        client->set_max_concurrent_streams(1);
        ASSERT_TRUE(client->push_request(reconnect::get_test(), [&](qb::http::Response) {
            ++a;
            throw std::runtime_error("the response callback throws");
        }));
        ASSERT_TRUE(client->push_request(reconnect::get_test(), std::ref(behind)));
        EXPECT_TRUE(loop_until([&] { return behind.count != 0; }, 3s));
        client->disconnect();
        settle();
    });
    EXPECT_EQ(a, 1);
    EXPECT_EQ(behind.status, qb::http::status::OK) << behind.body;
    EXPECT_EQ(
        http2_client_crossing_test::occurrences(log, "exception escaped an HTTP/2 client callback; contained: the response callback throws"),
        1u)
        << log;
}
#endif // QB_WITH_LOGGING

} // namespace http2_client_callbacks_test

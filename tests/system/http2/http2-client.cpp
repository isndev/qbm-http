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
 * New coverage added per spec: GOAWAY-adjacent graceful drain on disconnect,
 * the previously-dead `/api/large` route, and a bad-ALPN negative case (server
 * offers only `http/1.1`, so the `h2` client connect must fail observably).
 * The automatic reconnection (Huly QB-103) has its own section at the end: the
 * backoff run through `RetryPolicy`, its cap, its end on a connection that
 * comes up, a disconnect while connecting, and the retry pattern -- a request
 * pushed back from a failure callback -- queuing behind the scheduled attempt.
 *
 * REQUIRES: ssl + live. This TU stays inside the `if(QB_HAS_SSL)` block.
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
#include <string>
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

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

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
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

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
    auto                              client = make_test_client();
    std::array<qb::http::Response, 3> responses;
    std::atomic<int>                  done{0};
    auto                              post = [&](std::size_t const slot, std::vector<std::pair<std::string, std::string>> const &headers) {
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
    auto client = make_test_client();

    std::atomic<int>   responses{0};
    qb::http::Response refused, after;

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
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

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
    auto              client = make_test_client();
    int               calls  = 0;
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
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

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
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

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
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

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
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

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
    auto client = make_test_client();

    std::atomic<int>                responses_received{0};
    std::vector<qb::http::Response> responses(3);

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
    auto client = make_test_client();

    std::atomic<bool>               batch_completed{false};
    std::vector<qb::http::Response> batch_responses;

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
    auto                           client = make_test_client(); // owner survives the callback
    std::vector<qb::http::Request> requests;
    requests.emplace_back(qb::http::method::GET, qb::io::uri("/api/users/301"));
    requests.emplace_back(qb::http::method::GET, qb::io::uri("/api/users/302"));

    int                             calls = 0;
    std::vector<qb::http::Response> responses;
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
    auto                            client      = make_test_client();
    int                             first_calls = 0, second_calls = 0;
    std::vector<qb::http::Response> first_responses, second_responses;
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
    auto                             client                 = make_test_client();
    std::weak_ptr<qb::http2::Client> weak_client            = client;
    int                              calls                  = 0;
    bool                             alive_after_owner_drop = false;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/users/403")}, [&](qb::http::Response response) {
        ++calls;
        EXPECT_EQ(response.status(), qb::http::status::OK);
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
    auto client = make_test_client();

    std::atomic<int>   responses_received{0};
    qb::http::Response ok_response;
    qb::http::Response reset_response;

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
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

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
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

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
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

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

    auto client = qb::http2::make_client("https://localhost:" + std::to_string(port));
    client->set_verify_peer(false);
    client->set_connect_timeout(5s);

    std::atomic<bool> callback_called{false};
    std::atomic<bool> connected{true};
    std::string       error_message;

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
    auto client = make_test_client();

    std::atomic<bool>  response_received{false};
    qb::http::Response response;

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
    auto client = make_test_client();

    std::atomic<int>   responses_received{0};
    qb::http::Response good_response;
    qb::http::Response missing_response;

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
    auto client = make_test_client();

    std::atomic<int>   response_count{0};
    qb::http::Response response;

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
    auto client    = make_test_client();
    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));

    auto *protocol = dynamic_cast<qb::http2::Client::H2Protocol *>(client->protocol());
    ASSERT_NE(protocol, nullptr);
    qb::protocol::http2::ProtocolTestPeer<qb::http2::Client::H2Protocol>::set_next_stream_id(*protocol, 0x7FFFFFFFu);

    std::vector<qb::http::Response> responses;
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
    auto client = make_test_client();
    client->set_max_pending_requests(2);

    std::vector<qb::http::Request> reqs;
    for (int i = 0; i < 3; ++i) {
        qb::http::Request r;
        r.method() = qb::http::Method::GET;
        r.uri()    = qb::io::uri("/api/test");
        reqs.push_back(std::move(r));
    }

    int                             calls = 0;
    std::vector<qb::http::Response> out;
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
    const auto dead   = qb::http::test::ephemeral_port(); // bound then closed -> refused
    auto       client = qb::http2::make_client("https://localhost:" + std::to_string(dead));
    client->set_verify_peer(false);
    client->set_connect_timeout(2s);

    std::atomic<bool> cb{false};
    std::atomic<bool> ok{true};
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
    auto client = make_test_client();
    client->set_max_pending_requests(0); // the very first push already exceeds the bound

    std::atomic<bool>  done{false};
    qb::http::Response response;
    qb::http::Request  request;
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
    auto client = make_test_client();

    bool                            done = false;
    std::vector<qb::http::Response> out{qb::http::Response{}}; // pre-seed non-empty
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
    auto client = make_test_client();

    std::atomic<bool>  done{false};
    qb::http::Response response;
    qb::http::Request  request;
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
    auto client = make_test_client();

    std::atomic<bool>  done{false};
    qb::http::Response response;
    qb::http::Request  request;
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
    auto client = make_test_client();

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

    std::atomic<bool>               done{false};
    std::vector<qb::http::Response> out;
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
    auto client = make_test_client();

    std::vector<qb::http::Request> reqs(3);
    reqs[0].method() = qb::http::Method::HEAD;
    reqs[0].uri()    = qb::io::uri("/api/head-metadata"); // answered: 200, no body
    reqs[1].method() = qb::http::Method::GET;
    reqs[1].uri()    = qb::io::uri("https://example.invalid:8443/api/test"); // refused: 400
    reqs[2].method() = qb::http::Method::GET;
    reqs[2].uri()    = qb::io::uri("/api/hang"); // never answered

    std::atomic<int>                calls{0};
    std::vector<qb::http::Response> out;
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
    auto client = make_test_client();
    client->set_max_concurrent_streams(1);

    std::atomic<int>                received{0};
    std::vector<qb::http::Response> responses(3);
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

    auto             control = make_test_client();
    std::atomic<int> control_replies{0};
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
    auto client = make_test_client();
    client->set_max_concurrent_streams(60); // above the server's advertised 50
    int warmup_calls = 0;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/users/400")}, [&](qb::http::Response response) {
        EXPECT_EQ(response.status(), qb::http::status::OK);
        ++warmup_calls;
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return warmup_calls == 1; }));
    int                failed_send_calls = 0, followup_calls = 0;
    qb::http::Response followup_response;

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
    auto client = make_test_client();
    client->set_max_concurrent_streams(60);
    std::weak_ptr<qb::http2::Client> weak_client  = client;
    int                              warmup_calls = 0;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/users/400")}, [&](qb::http::Response response) {
        EXPECT_EQ(response.status(), qb::http::status::OK);
        ++warmup_calls;
    }));
    ASSERT_TRUE(ServerThread::pump_until([&] { return warmup_calls == 1; }));

    int  failed_send_calls     = 0;
    bool alive_inside_callback = false;
    for (int i = 0; i < 50; ++i) {
        ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/hang")}, [](qb::http::Response) {}));
    }
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri("/api/hang")}, [&](qb::http::Response response) {
        EXPECT_EQ(response.body().as<std::string>(), "Failed to send HTTP/2 request");
        ++failed_send_calls;
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

// The whole run, observed from outside: a request against a server that will never speak h2, a
// retry callback that pushes it back on every failure, a policy of four attempts at 40/80/160 ms.
// The failures must come 6 deep (the explicit auto-connect, the four attempts, the verdict), the
// waits must be at least the policy's, on_retry must be told before each wait with the number of
// failed attempts, and a push from a failure callback must never connect on its own.
TEST_F(Http2ClientTest, AutoReconnectBacksOffThroughThePolicyUntilTheRunIsExhausted) {
    auto http1_only = reconnect::make_http1_only_server();
    ASSERT_TRUE(http1_only->ready());
    auto client = reconnect::make_client_for(reconnect::port_of(*http1_only));

    std::vector<std::pair<int, qb::duration>> retries;
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

    std::vector<reconnect::Failure>         failures;
    bool                                    exhausted = false;
    std::function<void(qb::http::Response)> on_response;
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
    bool again = false;
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
    auto client = reconnect::make_client_for(reconnect::port_of(*http1_only));

    int on_retry_calls = 0;
    client->enable_auto_reconnect(
        qb::http2::RetryPolicy{}.with_max_attempts(0).with_jitter(false).with_on_retry([&](int, qb::duration) { ++on_retry_calls; }));

    std::vector<std::string> verdicts;
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

    auto client = reconnect::make_client_for(port);
    client->set_connect_timeout(300ms); // the silent listener is left on this, not on a refusal

    std::vector<std::pair<int, qb::duration>> retries;
    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_initial_delay(800ms).with_jitter(false).with_on_retry(
        [&](int attempt, qb::duration delay) { retries.emplace_back(attempt, delay); }));

    std::vector<reconnect::Failure>         failures;
    std::optional<qb::http::Response>       served;
    std::function<void(qb::http::Response)> on_response;
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
    auto client = reconnect::make_client_for(reconnect::port_of(*http1_only));

    int retries = 0;
    client->enable_auto_reconnect(
        qb::http2::RetryPolicy{}.with_initial_delay(150ms).with_jitter(false).with_on_retry([&](int, qb::duration) { ++retries; }));

    std::vector<std::string>                verdicts;
    std::function<void(qb::http::Response)> on_response;
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
    auto client = make_test_client();

    std::optional<bool> outcome;
    std::string         message;
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
    auto client  = make_test_client();
    int  retries = 0;
    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_jitter(false).with_on_retry([&](int, qb::duration) { ++retries; }));

    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));

    std::vector<std::string>          verdicts;
    std::optional<qb::http::Response> served;
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
    auto client = make_test_client();
    client->set_connect_timeout(200ms);
    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_jitter(false));

    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));
    const auto older_than_the_timeout = std::chrono::steady_clock::now() + 350ms;
    while (std::chrono::steady_clock::now() < older_than_the_timeout) {
        qb::io::async::run(EVRUN_NOWAIT);
    }
    ASSERT_TRUE(client->is_connected());

    std::vector<std::string>          verdicts;
    std::optional<qb::http::Response> served;
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
    std::optional<qb::http::Response> second;
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
    qb::io::tcp::listener holder; // keeps a port of ours until the first server takes it
    ASSERT_EQ(holder.listen_v4(0, "127.0.0.1"), 0);
    const std::uint16_t port = holder.local_endpoint().port();
    holder.close();
    auto first = reconnect::make_h2_server_on(port);
    ASSERT_TRUE(first->ready()) << "could not bind the port the holder just released";

    auto client = reconnect::make_client_for(port);
    client->set_connect_timeout(3s);
    std::vector<std::pair<int, qb::duration>> retries;
    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_initial_delay(500ms).with_jitter(false).with_on_retry(
        [&](int attempt, qb::duration delay) { retries.emplace_back(attempt, delay); }));

    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected; }));

    std::vector<std::string>                verdicts;
    std::optional<qb::http::Response>       served;
    std::function<void(qb::http::Response)> on_response;
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
    auto client = reconnect::make_client_for(reconnect::port_of(*http1_only));

    int on_retry_calls = 0;
    client->enable_auto_reconnect(qb::http2::RetryPolicy{}.with_on_retry([&](int, qb::duration) { ++on_retry_calls; }));
    client->disable_auto_reconnect(); // keeps the policy, disarms the run

    std::vector<std::string> verdicts;
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
    auto client = reconnect::make_client_for(reconnect::port_of(*http1_only));

    std::vector<long long> waits_ms;
    client->enable_auto_reconnect(qb::http2::RetryPolicy{}
                                      .with_initial_delay(40ms)
                                      .with_multiplier(1.0)
                                      .with_max_delay(40ms)
                                      .with_jitter(true)
                                      .with_max_attempts(9)
                                      .with_on_retry([&](int, qb::duration delay) {
                                          waits_ms.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(delay).count());
                                      }));

    bool                                    exhausted = false;
    std::function<void(qb::http::Response)> on_response;
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
check_silent_completion_drain(SilentCompletion transition, bool observe_hooks = true) {
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
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    std::vector<std::shared_ptr<ReplyObservation>> replies;
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
    auto client = qb::http2::make_client("https://localhost:" + std::to_string(server.transport().local_endpoint().port()));
    client->set_verify_peer(false);
    client->set_request_timeout(5s);
    client->set_max_concurrent_streams(40);
    std::vector<std::shared_ptr<ReplyObservation>> replies;
    std::vector<std::weak_ptr<Context>>            weak;
    std::shared_ptr<H2Session>                     session;
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
        std::size_t off = 0;
        while (off < bytes.size() && !_release) {
            const int n = sock.write(bytes.data() + off, bytes.size() - off);
            if (n < 0) {
                return false;
            }
            if (n == 0) {
                std::this_thread::sleep_for(1ms);
            }
            off += static_cast<std::size_t>(n);
        }
        return off == bytes.size();
    }

    void
    run() {
        const auto               deadline = std::chrono::steady_clock::now() + 30s;
        qb::io::tcp::ssl::socket sock;
        while (!_release && std::chrono::steady_clock::now() < deadline) {
            if (_listener.accept(sock) == 0 && sock.is_open()) {
                break;
            }
            std::this_thread::sleep_for(1ms);
        }
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
        qb::io::tcp::ssl::socket next; // Silent: the client's next connection
        while (!_release && std::chrono::steady_clock::now() < deadline) {
            if (_ping_requested && !_ping_sent && answered) {
                std::vector<uint8_t> ping;
                append_frame(ping, 0x6, 0, 0, {1, 2, 3, 4, 5, 6, 7, 8});
                if (!write_all(sock, ping)) {
                    _eof = true;
                    break;
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
                continue;
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
                    for (int attempt = 0; attempt < 2 && !_reset; ++attempt) {
                        std::this_thread::sleep_for(20ms);
                        _reset = !write_all(sock, reply);
                    }
                    _eof = true;
                    break;
                }
                if (raw < 0) {
                    const int err = qb::io::socket::get_last_errno();
                    if (qb::io::socket::not_recv_error(err)) {
                        std::this_thread::sleep_for(1ms);
                        continue;
                    }
                    _reset = true;
                    _eof   = true;
                    break;
                }
                continue; // a TLS record after the GOAWAY: ignored
            }
            const int n = sock.read(buffer, sizeof(buffer));
            if (n < 0) {
                _eof = true;
                break;
            }
            if (n == 0) {
                std::this_thread::sleep_for(1ms);
                continue;
            }
            in.insert(in.end(), buffer, buffer + n);
            if (!preface_seen) {
                if (in.size() < preface_size) {
                    continue;
                }
                in.erase(in.begin(), in.begin() + preface_size);
                preface_seen = true;
            }
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
                    std::vector<uint8_t> reply;
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
                    if (!write_all(sock, reply)) {
                        _eof = true;
                        return;
                    }
                    answered = true;
                }
                std::lock_guard lock(_mutex);
                _frames.push_back(std::move(f));
            }
        }
        while (!_release && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(1ms); // Silent: hold the connection until released
        }
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
    auto client    = make_client(peer.port());
    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected && peer.settings_acked(); }));

    qb::http::Request request; // one the peer never answers
    request.method() = qb::http::Method::GET;
    request.uri()    = qb::io::uri("/pending");
    std::optional<qb::http::Response> response;
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
    auto client    = make_client(peer.port());
    bool connected = false;
    client->connect([&](bool ok, const std::string &) { connected = ok; });
    ASSERT_TRUE(ServerThread::pump_until([&] { return connected && peer.settings_acked(); }));

    // The PING reaches the client's socket while its loop does not run: it stays unread.
    peer.send_ping();
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!peer.ping_sent() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(1ms);
    }
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
    auto client    = make_client(peer.port());
    bool connected = false;
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
    bool reconnected = false;
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
    auto client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::POST;
    request.uri()    = qb::io::uri("/api/data");
    request.body()   = R"({"t":1})";
    request.set_header("trailer", "X-Checksum");
    request.set_header("x-checksum", "cafe");

    std::optional<qb::http::Response> response;
    int                               calls = 0;
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
    auto client = make_test_client();

    qb::http::Request request;
    request.method() = qb::http::Method::POST;
    request.uri()    = qb::io::uri("/api/data");
    request.body()   = R"({"t":2})";
    request.set_header("trailer", "X-Checksum"); // announced, never set

    std::optional<qb::http::Response> response;
    int                               calls = 0;
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
// A response stream on HTTP/2 (Huly QB-86). The HTTP/2 session offers no streaming hooks yet, so begin_stream()
// gives a BUFFERED stream with the interface of a streamed one -- the pieces gather and leave whole at end() -- and a
// handler written for HTTP/1.1 runs unchanged. The stream owns the completion here too: a coroutine handler that hands
// its stream to a timer chain and returns is not answered under it (it used to be, with its first piece alone and a
// content-length of that piece). A buffered abort answers 500 with an empty body, without the Content-Length the
// handler had declared (kept, the server reset the stream for a length mismatch instead).
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

static_assert(!qb::http::streaming_session<StreamH2Session>, "the HTTP/2 session is expected to buffer streams for now");

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

    [[nodiscard]] qb::http::Response
    get(std::string const &path) const {
        auto client = qb::http2::make_client("https://localhost:" + std::to_string(_port));
        client->set_verify_peer(false);
        client->set_connect_timeout(5s);
        std::optional<qb::http::Response> response;
        qb::http::Request                 request;
        request.method() = qb::http::Method::GET;
        request.uri()    = qb::io::uri(path);
        EXPECT_TRUE(client->push_request(request, [&](qb::http::Response r) { response = std::move(r); }));
        client->connect(nullptr);
        EXPECT_TRUE(qb::http::test::ServerThread<StreamH2Server>::pump_until([&] { return response.has_value(); }));
        client->disconnect();
        return response.value_or(qb::http::Response{});
    }
};

TEST_F(Http2ResponseStreamTest, AStreamIsBufferedWholeAndOwnsItsCompletion) {
    const auto response = get("/stream/handoff");
    EXPECT_EQ(g_h2_framing.load(), static_cast<int>(qb::http::stream_framing::buffered));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "piece-0;piece-1;piece-2;piece-3;")
        << "the response left when the handler returned, not at end()";
}

TEST_F(Http2ResponseStreamTest, ACancelledBufferedStreamAnswers503WithoutItsBodyLengthOrCoding) {
    const auto response = get("/stream/cancel");
    EXPECT_EQ(g_h2_framing.load(), static_cast<int>(qb::http::stream_framing::buffered));
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_TRUE(response.body().empty()) << response.body().template as<std::string>();
    EXPECT_TRUE(response.header("Content-Encoding").empty()) << "the coding of a body the 503 does not carry (Huly QB-101)";
    EXPECT_TRUE(response.header("Content-Type").empty()) << response.header("Content-Type");
    EXPECT_NE(response.header("Content-Length"), "64");
}

TEST_F(Http2ResponseStreamTest, ABufferedAbortAnswers500WithoutTheDeclaredLength) {
    const auto response = get("/stream/abort");
    EXPECT_EQ(g_h2_framing.load(), static_cast<int>(qb::http::stream_framing::buffered));
    EXPECT_EQ(response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(response.body().empty()) << "not the server's 500: " << response.body().template as<std::string>();
}

} // namespace http2_response_stream_test

// ===========================================================================
// Static files over HTTP/2 keep the buffered path (Huly QB-101). The HTTP/2 session offers no streaming hooks, so a
// body over StaticFilesOptions::stream_threshold is read whole, as every body was, and max_file_size still bounds it;
// HTTP/1.1 streams the same body (system/middleware/static-files-stream.cpp).
// ===========================================================================
namespace http2_static_files_test {

class StaticH2Server;

class StaticH2Session : public qb::http2::use<StaticH2Session>::session<StaticH2Server> {
public:
    explicit StaticH2Session(StaticH2Server &server)
        : session(server) {}
};

class StaticH2Server : public qb::http2::use<StaticH2Server>::server<StaticH2Session> {};

static_assert(!qb::http::streaming_session<StaticH2Session>, "the HTTP/2 session is expected to buffer streams for now");

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

TEST(Http2StaticFilesTest, ABodyOverTheStreamThresholdIsReadWholeAndTheCapStillBoundsIt) {
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

    const auto get = [port](std::string const &path) {
        auto client = qb::http2::make_client("https://localhost:" + std::to_string(port));
        client->set_verify_peer(false);
        client->set_connect_timeout(5s);
        std::optional<qb::http::Response> response;
        qb::http::Request                 request;
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
    EXPECT_TRUE(served.body().template as<std::string>() == whole) << "the body read whole differs from the file's";
    EXPECT_EQ(get("/over.bin").status(), qb::http::status::PAYLOAD_TOO_LARGE) << "a body read whole stays bounded by max_file_size";

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

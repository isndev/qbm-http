/**
 * @file qbm/http/tests/system/http1/http1-client.cpp
 * @brief System (loopback) tests for the qb::http1 client + HTTP/1.x wire framing.
 *
 * Spins a real qbm-http server on a worker thread (via the shared
 * @ref qb::http::test::ServerThread harness on an ephemeral port) and drives it
 * with both the public `qb::http1` client and a hand-rolled raw TCP socket to
 * assert HTTP/1.0 vs HTTP/1.1 connection/keep-alive/pipelining behaviour on the
 * wire. No external daemon, no TLS — plaintext loopback only.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// The raw_socket harness below talks to the server over a plain TCP socket.
// Use qb-io's cross-platform socket layer instead of the POSIX headers directly:
// <qb/io/system/sys__socket.h> pulls in the right platform socket headers, the
// `socket_type` alias and the `closesocket()` shim, so the harness builds on POSIX
// and Windows alike. Winsock is initialised by qb-io's global ws2_32 guard, which
// is linked in here because the test drives a qb HTTP server (qb-io sockets).
#include <qb/io/system/sys__socket.h>

#include "../../shared/loopback_server.h"

#include "../http.h"

using namespace std::chrono_literals;
using qb::http::test::ephemeral_port;
using qb::http::test::ServerThread;

namespace {

class Http1ClientTestServer;

class Http1ClientTestSession
    : public qb::http::use<Http1ClientTestSession>::session<Http1ClientTestServer> {
public:
    explicit Http1ClientTestSession(Http1ClientTestServer &server);
};

// Connection/request counters live on the SERVER object (not file globals) so a
// test reads them only AFTER it has joined on the observable client outcome.
class Http1ClientTestServer
    : public qb::http::use<Http1ClientTestServer>::server<Http1ClientTestSession> {
public:
    std::atomic<int> connection_count{0};
    std::atomic<int> request_count{0};

    Http1ClientTestServer() {
        router().get("/ping", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "pong";
            ctx->response().set_header("X-Protocol", "HTTP/1.1");
            ctx->complete();
        });

        router().get("/close", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "bye";
            ctx->response().set_header("Connection", "close");
            ctx->complete();
        });

        router().get("/item/:id", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = ctx->path_param("id");
            ctx->complete();
        });

        router().get("/hold/:id", [this](auto ctx) {
            ++request_count;
            auto id = ctx->path_param("id");
            qb::io::async::callback(
                [ctx, id = std::move(id)]() mutable {
                    ctx->response().status() = qb::http::status::OK;
                    ctx->response().body()   = id;
                    ctx->complete();
                },
                50ms);
        });

        router().get("/never", [this](auto ctx) {
            ++request_count;
            (void) ctx;
        });

        router().post("/echo", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::CREATED;
            ctx->response().body()   = ctx->request().body().template as<std::string>();
            ctx->complete();
        });

        router().head("/head-length", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Content-Length", "123");
            ctx->response().set_header("X-Head", "ok");
            ctx->complete();
        });

        router().get("/no-content", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });

        router().compile();
    }

    void
    on(IOSession &) {
        ++connection_count;
    }
};

Http1ClientTestSession::Http1ClientTestSession(Http1ClientTestServer &server)
    : session(server) {
    max_pipelined_requests(4);
}

/**
 * @brief RAII loopback HTTP/1 server bound to an ephemeral port.
 *
 * Wraps the shared @ref ServerThread (readiness barrier, no sleep warmup) and
 * exposes the worker-thread server's atomic counters plus a `url()` helper. The
 * counters are atomics owned by the server object and are only read by the test
 * body after it has observed the client-side completion, so there is no
 * cross-thread data race on the integers we assert.
 */
struct LoopbackHttp1Server {
    // Declaration order is load-bearing: `srv` MUST precede `thread`. The
    // `ServerThread` constructor runs the configure lambda on the worker thread
    // and blocks until readiness, and that lambda publishes `srv = &server`. If
    // `srv` were declared after `thread`, its `= nullptr` member-initializer would
    // run AFTER the thread ctor completed and clobber the pointer back to null,
    // making every connection_count()/request_count() read return -1. The
    // worker's write is safely visible to the test thread because the
    // ServerThread ctor's readiness wait establishes a happens-before edge.
    std::uint16_t                                port = ephemeral_port();
    Http1ClientTestServer                       *srv  = nullptr;
    ServerThread<Http1ClientTestServer>          thread;

    LoopbackHttp1Server()
        : thread([this](Http1ClientTestServer &server) {
              srv = &server;
              if (server.transport().listen_v4(port) != 0) {
                  return false;
              }
              server.start();
              return true;
          }) {}

    [[nodiscard]] std::string
    url(std::string const &path) const {
        return "http://127.0.0.1:" + std::to_string(port) + path;
    }

    [[nodiscard]] int
    connection_count() const {
        return srv ? srv->connection_count.load() : -1;
    }

    [[nodiscard]] int
    request_count() const {
        return srv ? srv->request_count.load() : -1;
    }
};

qb::http::Request
request(qb::http::method method, std::string const &target) {
    qb::http::Request req{method, qb::io::uri(target)};
    return req;
}

[[nodiscard]] std::string
lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

class raw_socket {
    socket_type _fd = qb::io::inet::invalid_socket;

public:
    explicit raw_socket(int port) {
        _fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (_fd == qb::io::inet::invalid_socket) {
            throw std::runtime_error("socket failed");
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<uint16_t>(port));
        if (::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
            throw std::runtime_error("inet_pton failed");
        }
        if (::connect(_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
            throw std::runtime_error("connect failed");
        }
    }

    ~raw_socket() {
        if (_fd != qb::io::inet::invalid_socket) {
            closesocket(_fd);
        }
    }

    raw_socket(raw_socket const &)            = delete;
    raw_socket &operator=(raw_socket const &) = delete;

    void
    send_all(std::string const &wire) {
        const char *data      = wire.data();
        std::size_t remaining = wire.size();
        while (remaining) {
            const auto sent = ::send(_fd, data, static_cast<int>(remaining), 0);
            if (sent <= 0) {
                throw std::runtime_error("send failed");
            }
            data += sent;
            remaining -= static_cast<std::size_t>(sent);
        }
    }

    [[nodiscard]] std::string
    read_until(std::string const &marker, std::chrono::milliseconds budget = std::chrono::seconds(5)) {
        std::string out;
        const auto  deadline = std::chrono::steady_clock::now() + budget;
        char        buffer[4096];
        while (std::chrono::steady_clock::now() < deadline && out.find(marker) == std::string::npos) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(_fd, &fds);
            timeval    tv{0, 50 * 1000};
            const auto ready = ::select(static_cast<int>(_fd) + 1, &fds, nullptr, nullptr, &tv);
            if (ready < 0 && errno == EINTR) {
                continue;
            }
            if (ready < 0) {
                throw std::runtime_error("select failed");
            }
            if (ready == 0) {
                continue;
            }
            const auto n = ::recv(_fd, buffer, static_cast<int>(sizeof(buffer)), 0);
            if (n <= 0) {
                break;
            }
            out.append(buffer, static_cast<std::size_t>(n));
        }
        return out;
    }

    [[nodiscard]] bool
    closes_within(std::chrono::milliseconds budget) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        char       c;
        while (std::chrono::steady_clock::now() < deadline) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(_fd, &fds);
            timeval    tv{0, 50 * 1000};
            const auto ready = ::select(static_cast<int>(_fd) + 1, &fds, nullptr, nullptr, &tv);
            if (ready > 0) {
                const auto n = ::recv(_fd, &c, 1, MSG_PEEK);
                return n == 0;
            }
        }
        return false;
    }
};

} // namespace

TEST(Http1ClientTest, ConnectCallbackAndSequentialRequestsReuseOneConnection) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    bool connected = false;
    client->connect([&](bool ok, std::string const &error) {
        EXPECT_TRUE(ok) << error;
        connected = ok;
    });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));

    auto first  = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));
    auto second = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/item/42")));

    EXPECT_EQ(first.status(), qb::http::status::OK);
    EXPECT_EQ(first.body().template as<std::string>(), "pong");
    EXPECT_EQ(second.status(), qb::http::status::OK);
    EXPECT_EQ(second.body().template as<std::string>(), "42");
    EXPECT_TRUE(client->is_connected());
    EXPECT_EQ(server.connection_count(), 1);
    EXPECT_EQ(server.request_count(), 2);
}

TEST(Http1ClientTest, CoroutineConnectAndSinglePostRequest) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    auto connect_result = qb::http::run_sync(client->connect());
    ASSERT_TRUE(connect_result) << connect_result.error_message;
    auto second_connect = qb::http::run_sync(client->connect());
    ASSERT_TRUE(second_connect) << second_connect.error_message;

    auto req      = request(qb::http::method::POST, "/echo");
    req.body()    = "hello-http1";
    auto response = qb::http::run_sync(client->push_request(std::move(req)));

    EXPECT_EQ(response.status(), qb::http::status::CREATED);
    EXPECT_EQ(response.body().template as<std::string>(), "hello-http1");
    EXPECT_TRUE(client->is_connected());
    EXPECT_EQ(server.connection_count(), 1);
}

// The four sub-cases below each exercise a distinct "user callback releases the
// last client reference / disconnects" path. They were previously one giant
// multi-block test; each is now its own TEST with an observable post-condition.

TEST(Http1ClientTest, ConnectCallbackMayDropLastClientReference) {
    LoopbackHttp1Server server;

    auto client                  = qb::http1::make_client(server.url("/"));
    bool connect_callback_called = false;
    client->connect([&](bool ok, std::string const &) {
        EXPECT_TRUE(ok);
        connect_callback_called = true;
        client.reset(); // drop the last strong ref from inside the callback
    });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connect_callback_called; }));
    EXPECT_TRUE(connect_callback_called);
    EXPECT_EQ(client, nullptr); // observable: the callback released the client
}

TEST(Http1ClientTest, ResponseCallbackMayDropLastClientReference) {
    LoopbackHttp1Server server;

    auto             client                   = qb::http1::make_client(server.url("/"));
    qb::http::status response_status          = qb::http::status::IM_A_TEAPOT;
    bool             response_callback_called = false;
    client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        response_status          = response.status();
        response_callback_called = true;
        client.reset();
    });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return response_callback_called; }));
    EXPECT_EQ(response_status, qb::http::status::OK);
    EXPECT_EQ(client, nullptr);
}

TEST(Http1ClientTest, ResponseCallbackMayDisconnectClient) {
    LoopbackHttp1Server server;

    auto             client                   = qb::http1::make_client(server.url("/"));
    qb::http::status response_status          = qb::http::status::IM_A_TEAPOT;
    bool             response_callback_called = false;
    client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        response_status          = response.status();
        response_callback_called = true;
        client->disconnect();
    });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return response_callback_called; }));
    EXPECT_EQ(response_status, qb::http::status::OK);
    EXPECT_FALSE(client->is_connected());
}

TEST(Http1ClientTest, ConnectCallbackDisconnectFailsTheInFlightRequest) {
    LoopbackHttp1Server server;

    auto             client                   = qb::http1::make_client(server.url("/"));
    qb::http::status response_status          = qb::http::status::OK;
    bool             response_callback_called = false;
    bool             connect_callback_called  = false;
    client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        response_status          = response.status();
        response_callback_called = true;
    });
    client->connect([&](bool ok, std::string const &) {
        EXPECT_TRUE(ok);
        connect_callback_called = true;
        client->disconnect(); // tears the transport down before the request can flush
    });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until(
        [&] { return response_callback_called && connect_callback_called; }));
    EXPECT_TRUE(connect_callback_called);
    EXPECT_TRUE(response_callback_called);
    EXPECT_EQ(response_status, qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_FALSE(client->is_connected());
}

TEST(Http1ClientTest, BatchRequestsAreSequentialAndOrderPreserved) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    std::vector<qb::http::Request> requests;
    requests.emplace_back(request(qb::http::method::GET, "/item/1"));
    requests.emplace_back(request(qb::http::method::GET, "/item/2"));
    requests.emplace_back(request(qb::http::method::GET, "/item/3"));

    auto responses = qb::http::run_sync(client->push_requests(std::move(requests)));
    ASSERT_EQ(responses.size(), 3u);
    EXPECT_EQ(responses[0].body().template as<std::string>(), "1");
    EXPECT_EQ(responses[1].body().template as<std::string>(), "2");
    EXPECT_EQ(responses[2].body().template as<std::string>(), "3");
    EXPECT_EQ(server.connection_count(), 1);
    EXPECT_EQ(server.request_count(), 3);
}

TEST(Http1ClientTest, AbsoluteRequestWithExplicitDefaultPortMatchesBaseOrigin) {
    // An absolute request URL whose explicit :<port> equals the base origin's
    // port must reuse the SAME connection and round-trip to a real 200 — not be
    // rejected as cross-origin. We stand up a real loopback server and point the
    // absolute target at its concrete port so the assertion is observable.
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    auto response = qb::http::run_sync(
        client->push_request(request(qb::http::method::GET, server.url("/ping"))));

    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.body().template as<std::string>(), "pong");
    EXPECT_EQ(server.connection_count(), 1);
    EXPECT_EQ(server.request_count(), 1);
}

TEST(Http1ClientTest, SerializationFailureDoesNotBlockQueuedRequests) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    auto bad   = request(qb::http::method::POST, "/echo");
    bad.body() = "too-long";
    bad.set_header("Content-Length", "1");

    std::vector<qb::http::Request> requests;
    requests.emplace_back(std::move(bad));
    requests.emplace_back(request(qb::http::method::GET, "/ping"));

    auto responses = qb::http::run_sync(client->push_requests(std::move(requests)));
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(responses[1].status(), qb::http::status::OK);
    EXPECT_EQ(responses[1].body().template as<std::string>(), "pong");
    EXPECT_EQ(server.request_count(), 1);
}

TEST(Http1ClientTest, PendingRequestTimesOutBehindBlockedActiveRequest) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));
    client->set_request_timeout(50ms);

    std::vector<qb::http::Request> requests;
    requests.emplace_back(request(qb::http::method::GET, "/never"));
    requests.emplace_back(request(qb::http::method::GET, "/ping"));

    auto responses = qb::http::run_sync(client->push_requests(std::move(requests)));
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::GATEWAY_TIMEOUT);
    EXPECT_EQ(responses[1].status(), qb::http::status::REQUEST_TIMEOUT);
    EXPECT_EQ(server.request_count(), 1);
}

TEST(Http1ClientTest, ConnectionCloseResponseReconnectsBeforeNextRequest) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    auto closing = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/close")));
    EXPECT_EQ(closing.status(), qb::http::status::OK);
    EXPECT_EQ(closing.body().template as<std::string>(), "bye");

    auto after = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));
    EXPECT_EQ(after.status(), qb::http::status::OK);
    EXPECT_EQ(after.body().template as<std::string>(), "pong");
    EXPECT_GE(server.connection_count(), 2);
}

TEST(Http1ClientTest, HeadAndNoContentDoNotStealNextResponseBytes) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    auto head       = qb::http::run_sync(client->push_request(request(qb::http::method::HEAD, "/head-length")));
    auto no_content = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/no-content")));
    auto ping       = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));

    EXPECT_EQ(head.status(), qb::http::status::OK);
    EXPECT_EQ(head.header("Content-Length"), "123");
    EXPECT_TRUE(head.body().empty());
    EXPECT_EQ(no_content.status(), qb::http::status::NO_CONTENT);
    EXPECT_TRUE(no_content.body().empty());
    EXPECT_EQ(ping.status(), qb::http::status::OK);
    EXPECT_EQ(ping.body().template as<std::string>(), "pong");
    EXPECT_EQ(server.connection_count(), 1);
}

TEST(Http1ClientTest, Http10ClosesByDefaultButKeepAliveCanPersist) {
    LoopbackHttp1Server server;

    {
        raw_socket socket{server.port};
        socket.send_all("GET /ping HTTP/1.0\r\nHost: localhost\r\n\r\n");
        const auto response = socket.read_until("pong");
        const auto lower    = lowercase(response);
        EXPECT_NE(response.find("HTTP/1.1 200"), std::string::npos);
        EXPECT_NE(lower.find("connection: close"), std::string::npos);
        EXPECT_TRUE(socket.closes_within(std::chrono::seconds(2)));
    }

    {
        raw_socket socket{server.port};
        socket.send_all("GET /item/10 HTTP/1.0\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n");
        auto first = socket.read_until("10");
        EXPECT_NE(lowercase(first).find("connection: keep-alive"), std::string::npos);
        socket.send_all("GET /item/11 HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        auto second = socket.read_until("11");
        EXPECT_NE(second.find("11"), std::string::npos);
        EXPECT_TRUE(socket.closes_within(std::chrono::seconds(2)));
    }
}

TEST(Http1ClientTest, BackToBackHttp11RequestsAreAnsweredInRequestOrder) {
    LoopbackHttp1Server server;
    raw_socket          socket{server.port};

    socket.send_all("GET /item/first HTTP/1.1\r\nHost: localhost\r\n\r\n"
                    "GET /item/second HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    const auto response   = socket.read_until("second");
    const auto first_pos  = response.find("first");
    const auto second_pos = response.find("second");

    ASSERT_NE(first_pos, std::string::npos);
    ASSERT_NE(second_pos, std::string::npos);
    EXPECT_LT(first_pos, second_pos);
    EXPECT_TRUE(socket.closes_within(std::chrono::seconds(2)));
    EXPECT_EQ(server.request_count(), 2);
}

TEST(Http1ClientTest, ExcessivePipelinedRequestsAreCapped) {
    LoopbackHttp1Server server;
    raw_socket          socket{server.port};

    std::string wire;
    for (int i = 0; i < 8; ++i) {
        wire += "GET /hold/";
        wire += std::to_string(i);
        wire += " HTTP/1.1\r\nHost: localhost\r\n\r\n";
    }
    socket.send_all(wire);

    EXPECT_TRUE(socket.closes_within(std::chrono::seconds(2)));
    EXPECT_LE(server.request_count(), 5);
}

TEST(Http1ClientTest, ConnectAwaiterReturnsErrorWhenClientExpiresBeforeAwait) {
    auto result = qb::io::async::run_sync([]() -> qb::io::async::task<qb::http1::ConnectResult> {
        auto client  = qb::http1::make_client("http://127.0.0.1:1");
        auto awaiter = client->connect();
        client.reset();
        auto connect_result = co_await awaiter;
        co_return connect_result;
    }());

    EXPECT_FALSE(result.ok);
    EXPECT_FALSE(result.error_message.empty());
}

TEST(Http1ClientTest, ImplicitConnectFailureCompletesQueuedRequest) {
    auto client = qb::http1::make_client("http://127.0.0.1:1");
    client->set_connect_timeout(200ms);

    auto response = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));
    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_FALSE(response.body().empty());
    EXPECT_FALSE(client->is_connected());
}

// Regression: dropping the last client reference while a connect() callback is
// still registered must NOT leave a dangling callback that fires into freed
// memory. Previously this ended in SUCCEED() — only ASan could prove anything.
// Now the connect targets a real loopback server so we can observe that the
// connection callback NEVER fires (the client was destroyed first) AND that the
// server records zero completed connections for it, i.e. no late callback ran.
TEST(Http1ClientTest, DestroyingClientDuringConnectDoesNotLeaveDanglingCallback) {
    LoopbackHttp1Server server;

    std::atomic<int> callback_invocations{0};
    {
        auto client = qb::http1::make_client(server.url("/"));
        client->connect([&](bool, std::string const &) { ++callback_invocations; });
        // Drop the only strong reference immediately, before the connect can
        // resolve: the registered callback must be torn down, not fired.
    }

    // Pump the loop generously; if a dangling callback existed it would fire (or
    // crash under ASan) within this window.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
    while (std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }

    EXPECT_EQ(callback_invocations.load(), 0)
        << "connect callback fired after the client was destroyed";
}

// Regression: a user response callback is invoked from the protocol's noexcept
// onMessage dispatch. Before the invoke_user_callback chokepoint, an exception
// thrown by the callback escaped that noexcept boundary and called
// std::terminate (aborting the whole test binary). The throw must now be
// contained and the client must remain usable.
TEST(Http1ClientTest, ThrowingUserCallbackIsContainedAndClientSurvives) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    bool             first_called    = false;
    qb::http::status observed_status = qb::http::status::IM_A_TEAPOT;
    client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        observed_status = response.status();
        first_called    = true;
        throw std::runtime_error("user callback boom");
    });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return first_called; }));
    EXPECT_EQ(observed_status, qb::http::status::OK);

    // Process survived the throw; the keep-alive connection is intact and the
    // client still serves a subsequent request.
    auto after = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));
    EXPECT_EQ(after.status(), qb::http::status::OK);
}

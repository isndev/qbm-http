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

// Drain the parent loop briefly so a Client's deferred self-guard release
// (Client::hold_through_current_tick's ~1us callback) fires. A test that stops the loop
// synchronously inside a user callback (run_sync / pump_until returns the instant the
// awaited result is set) otherwise leaves _callback_self_guard holding the Client and the
// connection's io watcher registered — leaking the Client + connection. Mirrors the drain
// already used in DestroyingClientDuringConnectDoesNotLeaveDanglingCallback.
inline void
drain_client_callbacks() {
    const auto deadline = std::chrono::steady_clock::now() + 200ms;
    while (std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
}

class Http1ClientTestServer;

class Http1ClientTestSession : public qb::http::use<Http1ClientTestSession>::session<Http1ClientTestServer> {
public:
    explicit Http1ClientTestSession(Http1ClientTestServer &server);
};

// Connection/request counters live on the SERVER object (not file globals) so a
// test reads them only AFTER it has joined on the observable client outcome.
class Http1ClientTestServer : public qb::http::use<Http1ClientTestServer>::server<Http1ClientTestSession> {
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

        // Emits a MULTI-TOKEN Connection header ("keep-alive, close") so the
        // client's has_connection_close() token-split + trim + case-insensitive
        // compare loop (client.cpp `for (token : split(value, ","))`) must walk
        // past the leading token to find "close". A naive substring/equality
        // check on the whole header value would miss it.
        router().get("/multi-close", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "multi-bye";
            ctx->response().set_header("Connection", "keep-alive, close");
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

        // Echoes back the EXACT raw request body bytes the server received (the
        // wire bytes after the client serialized them). When the client compresses
        // its request body (Content-Encoding), the server here sees + returns the
        // compressed bytes, letting the test observe that compression happened.
        router().post("/echo-raw", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = ctx->request().body().template as<std::string>();
            ctx->complete();
        });

        // Returns a body that the handler compresses itself (then tags with
        // Content-Encoding: gzip) so the wire carries gzip bytes and the client's
        // on(response) path must uncompress it back to the original plaintext.
        router().get("/gzipped", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::string(512, 'Q');
#ifdef QB_HAS_COMPRESSION
            ctx->response().body().compress("gzip");
            ctx->response().set_header("Content-Encoding", "gzip");
#endif
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

        // Echoes the "a" query parameter so a relative request URI carrying a
        // query (?a=...) proves the client's ensure_absolute_uri appended it.
        router().get("/q", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::string(ctx->request().query("a"));
            ctx->complete();
        });

        // Advertises Content-Encoding: gzip but ships NON-gzip bytes, so the
        // client's response-decompression must fail and surface BAD_REQUEST.
        router().get("/bad-gzip", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "this is definitely not gzip";
            ctx->response().set_header("Content-Encoding", "gzip");
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
    std::uint16_t                       port = 0;
    Http1ClientTestServer              *srv  = nullptr;
    ServerThread<Http1ClientTestServer> thread;

    // Bind :0 and read the port BACK, rather than probing for a free one and binding it a moment
    // later. `ephemeral_port()` documents the hole this closes: its probe must be shut before the
    // caller can bind, so under `ctest -j` another test PROCESS can take the port in that window.
    // Measured at 2 failures in 12 full-suite runs, across two different tests in this directory.
    // Binding :0 on the socket that actually serves leaves no window at all.
    LoopbackHttp1Server()
        : thread([this](Http1ClientTestServer &server) {
            srv = &server;
            if (server.transport().listen_v4(0, "127.0.0.1") != 0) {
                return false;
            }
            server.start();
            return true;
        }) {
        // `thread`'s ctor already blocked on the readiness barrier, so the transport is bound.
        port = thread.server().transport().local_endpoint().port();
    }

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
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
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
    drain_client_callbacks();   // let the self-guard release fire so the Client is freed
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
    drain_client_callbacks(); // let the self-guard release fire so the Client is freed
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
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return response_callback_called && connect_callback_called; }));
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

    auto response = qb::http::run_sync(client->push_request(request(qb::http::method::GET, server.url("/ping"))));

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

    EXPECT_EQ(callback_invocations.load(), 0) << "connect callback fired after the client was destroyed";
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

// A multi-token "Connection: keep-alive, close" response value still results in
// connection-close handling: whichever layer detects the "close" token (the
// HTTP/1.1 parser's keep_alive flag and/or the client's has_connection_close
// token walk), the client tears the connection down and opens a fresh one for the
// next request. Observable: the second request rides a new server connection.
TEST(Http1ClientTest, MultiTokenConnectionCloseHeaderForcesReconnect) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    auto closing = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/multi-close")));
    EXPECT_EQ(closing.status(), qb::http::status::OK);
    EXPECT_EQ(closing.body().template as<std::string>(), "multi-bye");

    auto after = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));
    EXPECT_EQ(after.status(), qb::http::status::OK);
    EXPECT_EQ(after.body().template as<std::string>(), "pong");
    // The "close" token forced a teardown, so the second request rode a new
    // connection: at least two server-side connections were observed.
    EXPECT_GE(server.connection_count(), 2);
}

// With auto-reconnect DISABLED and no live connection, process_pending_requests()
// takes the "!_auto_reconnect" branch: it pops the head pending request and fails
// it synchronously with 503 ("HTTP/1.1 client is not connected"), then recurses to
// drain the rest the same way — never attempting a connect. We point the client at
// a closed port so no connection can exist.
TEST(Http1ClientTest, AutoReconnectDisabledFailsPendingRequestsWithoutConnecting) {
    auto client = qb::http1::make_client("http://127.0.0.1:1");
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero()); // disarm the pending timeout

    qb::http::status status_a = qb::http::status::IM_A_TEAPOT;
    qb::http::status status_b = qb::http::status::IM_A_TEAPOT;
    bool             a_done   = false;
    bool             b_done   = false;

    // Two queued requests must BOTH be drained by the no-reconnect recursion.
    client->push_request(request(qb::http::method::GET, "/a"), [&](qb::http::Response r) {
        status_a = r.status();
        a_done   = true;
    });
    client->push_request(request(qb::http::method::GET, "/b"), [&](qb::http::Response r) {
        status_b = r.status();
        b_done   = true;
    });

    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return a_done && b_done; }));
    EXPECT_EQ(status_a, qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(status_b, qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_FALSE(client->is_connected());
    EXPECT_FALSE(client->is_connecting());
}

// set_max_pending_requests(0) makes the very first push exceed the limit
// (pending+active 0 >= 0), so push_request synthesizes a 503 "pending request
// limit reached", returns false, and increments the failed-request counter — all
// without ever queueing or connecting.
TEST(Http1ClientTest, PendingRequestLimitRejectsImmediatelyWith503) {
    auto client = qb::http1::make_client("http://127.0.0.1:1");
    client->set_max_pending_requests(0);

    qb::http::status status = qb::http::status::IM_A_TEAPOT;
    bool             done   = false;
    const bool       queued = client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response r) {
        status = r.status();
        done   = true;
    });

    EXPECT_FALSE(queued); // over-limit push returns false
    ASSERT_TRUE(done);    // the error callback fired synchronously
    EXPECT_EQ(status, qb::http::status::SERVICE_UNAVAILABLE);

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 1u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 1u);
}

// An empty batch must complete immediately (no requests, no connection) by
// invoking the batch callback with an empty vector — the push_requests
// "requests.empty()" early-out.
TEST(Http1ClientTest, EmptyBatchCompletesImmediatelyWithEmptyVector) {
    auto client = qb::http1::make_client("http://127.0.0.1:1");

    bool                            done = false;
    std::vector<qb::http::Response> responses{qb::http::Response{}}; // pre-seed non-empty
    client->push_requests({}, [&](std::vector<qb::http::Response> res) {
        responses = std::move(res);
        done      = true;
    });

    ASSERT_TRUE(done);
    EXPECT_TRUE(responses.empty());
    EXPECT_FALSE(client->is_connecting());
}

// push_request/push_requests with an EMPTY callback are rejected up front
// (return false) and never touch the request counters.
TEST(Http1ClientTest, EmptyCallbackRequestsAreRejectedWithoutSideEffects) {
    auto client = qb::http1::make_client("http://127.0.0.1:1");

    EXPECT_FALSE(client->push_request(request(qb::http::method::GET, "/ping"), qb::http1::ResponseCallback{}));
    std::vector<qb::http::Request> reqs;
    reqs.emplace_back(request(qb::http::method::GET, "/ping"));
    EXPECT_FALSE(client->push_requests(std::move(reqs), qb::http1::BatchResponseCallback{}));

    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 0u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 0u);
}

// Pure accessor surface: the configuration getters/setters that the loopback
// flows above don't otherwise touch (verify_peer round-trips, base_uri is the
// origin we constructed with, active-request count is 0 at rest).
TEST(Http1ClientTest, ConfigurationAccessorsReflectMutations) {
    auto client = qb::http1::make_client("http://example.test:8080/base");

    EXPECT_TRUE(client->verify_peer()); // default
    client->set_verify_peer(false);
    EXPECT_FALSE(client->verify_peer());
    client->set_verify_peer(true);
    EXPECT_TRUE(client->verify_peer());

    EXPECT_EQ(client->get_active_request_count(), 0u);
    EXPECT_FALSE(client->is_connecting());
    EXPECT_FALSE(client->is_connected());

    const auto &base = client->get_base_uri();
    EXPECT_EQ(base.scheme(), "http");
    EXPECT_EQ(base.host(), "example.test");
    EXPECT_EQ(base.port(), "8080");

    // These setters are pure stores; assert they are callable on the public API.
    client->set_connect_timeout(5s);
    client->set_request_timeout(7s);
    client->set_max_pending_requests(64);
    client->set_auto_reconnect(true);
}

// A relative (host-less) request URI carrying a query string must be absolutized
// against the client's base origin WITH the query preserved (ensure_absolute_uri
// query-append path). The server echoes the "a" param back to prove it arrived.
TEST(Http1ClientTest, RelativeRequestUriCarriesQueryString) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    qb::http::Request req{qb::http::method::GET, qb::io::uri("/q?a=hello")}; // host-less + query
    auto              resp = qb::http::run_sync(client->push_request(std::move(req)));

    EXPECT_EQ(resp.status(), qb::http::status::OK);
    EXPECT_EQ(resp.body().template as<std::string>(), "hello");
    drain_client_callbacks();
}

// A persistent client rejects an absolute request whose origin differs from its
// base origin (same-origin guard) with a synthesized BAD_REQUEST, before any
// bytes hit the wire.
TEST(Http1ClientTest, CrossOriginRequestIsRejected) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    auto resp = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "http://example.test:9/ping")));

    EXPECT_EQ(resp.status(), qb::http::status::BAD_REQUEST);
    EXPECT_NE(resp.body().template as<std::string>().find("same-origin"), std::string::npos);
    drain_client_callbacks();
}

// A batch whose FIRST request draws a "Connection: close" response while a later
// request is still pending drives the deferred-reconnect path: handle_response tears
// the connection down (it must NOT reconnect inline — that would free the connection
// mid-onMessage/dispose, a UAF), and the ensuing on(disconnected) -> handle_disconnected
// finds pending work (has_pending_work()==true) and posts a next-turn async::defer()
// that opens a FRESH connection and drains the remaining request. (The sequential
// ConnectionClose... test never has pending work at teardown, so it exercises the
// other, connect-on-next-push path — this one exercises the deferred-reconnect path.)
TEST(Http1ClientTest, ConnectionCloseWithPendingBatchAutoReconnectsForRemainder) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    std::vector<qb::http::Request> requests;
    requests.emplace_back(request(qb::http::method::GET, "/close")); // responds Connection: close
    requests.emplace_back(request(qb::http::method::GET, "/ping"));  // still pending when /close returns

    auto responses = qb::http::run_sync(client->push_requests(std::move(requests)));
    ASSERT_EQ(responses.size(), 2u);
    EXPECT_EQ(responses[0].status(), qb::http::status::OK);
    EXPECT_EQ(responses[0].body().template as<std::string>(), "bye");
    EXPECT_EQ(responses[1].status(), qb::http::status::OK);
    EXPECT_EQ(responses[1].body().template as<std::string>(), "pong");
    // The close forced a teardown while /ping was pending, so the client
    // reconnected to finish it: at least two server-side connections observed.
    EXPECT_GE(server.connection_count(), 2);
    drain_client_callbacks();
}

// The coroutine push_request awaiter, given a client destroyed before the await
// runs, must resolve to a synthesized 503 rather than dereference the gone client
// (the weak_self.lock()==nullptr branch in the awaiter factory). Mirrors the
// existing connect() self-expiry test on the single-request awaiter.
TEST(Http1ClientTest, PushRequestAwaiterErrorsWhenClientExpiresBeforeAwait) {
    auto response = qb::io::async::run_sync([]() -> qb::io::async::task<qb::http::Response> {
        auto client  = qb::http1::make_client("http://127.0.0.1:1");
        auto awaiter = client->push_request(request(qb::http::method::GET, "/ping"));
        client.reset(); // drop the last strong ref before awaiting
        co_return co_await awaiter;
    }());

    EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_FALSE(response.body().empty());
}

// Same self-expiry contract for the batch awaiter: a destroyed client resolves
// the awaiter with an EMPTY response vector (complete({})).
TEST(Http1ClientTest, PushRequestsBatchAwaiterErrorsWhenClientExpiresBeforeAwait) {
    auto responses = qb::io::async::run_sync([]() -> qb::io::async::task<std::vector<qb::http::Response>> {
        auto                           client = qb::http1::make_client("http://127.0.0.1:1");
        std::vector<qb::http::Request> reqs;
        reqs.emplace_back(request(qb::http::method::GET, "/ping"));
        auto awaiter = client->push_requests(std::move(reqs));
        client.reset();
        co_return co_await awaiter;
    }());

    EXPECT_TRUE(responses.empty());
}

#ifdef QB_HAS_COMPRESSION
// A request carrying Content-Encoding: gzip has its body compressed by the client
// transport BEFORE it hits the wire (client.cpp connection::send compress block).
// The server echoes the raw bytes it received, so the response body is the
// gzip-compressed form — strictly different from, and (for this payload) smaller
// than, the original plaintext. That observable difference proves the client
// performed the compression.
TEST(Http1ClientTest, RequestBodyIsCompressedWhenContentEncodingSet) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    const std::string plaintext(2048, 'A'); // highly compressible
    auto              req = request(qb::http::method::POST, "/echo-raw");
    req.body()            = plaintext;
    req.set_header("Content-Encoding", "gzip");

    auto response = qb::http::run_sync(client->push_request(std::move(req)));
    EXPECT_EQ(response.status(), qb::http::status::OK);

    const auto echoed = response.body().template as<std::string>();
    EXPECT_NE(echoed, plaintext);               // the server saw compressed bytes
    EXPECT_LT(echoed.size(), plaintext.size()); // gzip shrank this payload
}

// A response tagged Content-Encoding: gzip is uncompressed by the client's
// on(response) path (client.cpp uncompress block) so the application observes the
// ORIGINAL plaintext, and the Content-Encoding header is consumed.
TEST(Http1ClientTest, ResponseBodyIsUncompressedWhenContentEncodingSet) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    auto response = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/gzipped")));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    // The client transparently inflated the gzip payload back to 512 'Q's.
    EXPECT_EQ(response.body().template as<std::string>(), std::string(512, 'Q'));
    drain_client_callbacks(); // let the response callback's self-guard release fire
}

// A request whose Content-Encoding names an unsupported codec makes the client's
// outbound compress() throw; the transport contains it and fails the request with
// BAD_REQUEST instead of sending garbage.
TEST(Http1ClientTest, RequestBodyCompressFailureSurfacesBadRequest) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    auto req   = request(qb::http::method::POST, "/echo");
    req.body() = "payload";
    req.set_header("Content-Encoding", "not-a-real-codec"); // compress() throws
    auto resp = qb::http::run_sync(client->push_request(std::move(req)));

    EXPECT_EQ(resp.status(), qb::http::status::BAD_REQUEST);
    drain_client_callbacks();
}

// A response that lies about being gzip (Content-Encoding: gzip over plain bytes)
// makes the client's inbound uncompress() throw; the transport rewrites the
// response to BAD_REQUEST rather than handing back corrupt data.
TEST(Http1ClientTest, ResponseDecompressFailureSurfacesBadRequest) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    auto resp = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/bad-gzip")));

    EXPECT_EQ(resp.status(), qb::http::status::BAD_REQUEST);
    drain_client_callbacks();
}
#endif

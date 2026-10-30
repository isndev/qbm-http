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
#include <initializer_list>
#include <memory>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// The raw_socket harness below talks to the server over a plain TCP socket.
// Use qb-io's cross-platform socket layer instead of the POSIX headers directly:
// <qb/io/system/sys__socket.h> pulls in the right platform socket headers, the
// `socket_type` alias and the `QB_CLOSESOCKET()` shim, so the harness builds on POSIX
// and Windows alike. Winsock is initialised by qb-io's global ws2_32 guard, which
// is linked in here because the test drives a qb HTTP server (qb-io sockets).
#include <qb/io/system/sys__socket.h>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"

#include <qbm/http/http.h>
#include <qbm/http/redirect.h>

#ifdef QB_HAS_COMPRESSION
#include <zlib.h>
#endif

using namespace std::chrono_literals;
using qb::http::test::ephemeral_port;
using qb::http::test::ServerThread;

namespace {

// Drain the parent loop briefly so a Client's deferred self-guard release
// (Client::hold_through_current_tick's tail-of-turn defer) fires, and so the connection's
// io watcher is unregistered. A test that stops the loop synchronously inside a user
// callback (run_sync / pump_until returns the instant the awaited result is set) otherwise
// leaves both queued. The self-hold itself is no longer at risk — it is owned by the
// deferred closure, so dropping the queue releases it (see ClientIsReleasedWhenItsLoopEnds
// WithoutAnotherTurn) — but draining is still the tidy way to let the turn finish. Mirrors
// the drain already used in DestroyingClientDuringConnectDoesNotLeaveDanglingCallback.
inline void
drain_client_callbacks() {
    const auto deadline = std::chrono::steady_clock::now() + 200ms;
    while (std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
}

#ifdef QB_HAS_COMPRESSION
// Decode the echoed wire bytes through zlib directly. This is deliberately
// independent of Body::uncompress(), the client path whose output the test is
// checking, so an empty or truncated stream cannot satisfy the oracle.
[[nodiscard]] std::optional<std::string>
gunzip_reference(std::string_view compressed) {
    z_stream stream{};
    if (inflateInit2(&stream, 15 + 16) != Z_OK) {
        return std::nullopt;
    }
    struct InflateGuard {
        z_stream *stream;
        ~InflateGuard() {
            inflateEnd(stream);
        }
    } guard{&stream};

    stream.next_in  = reinterpret_cast<Bytef *>(const_cast<char *>(compressed.data()));
    stream.avail_in = static_cast<uInt>(compressed.size());

    std::string output(4096, '\0');
    std::size_t produced = 0;
    for (;;) {
        if (produced == output.size()) {
            output.resize(output.size() * 2);
        }
        stream.next_out  = reinterpret_cast<Bytef *>(output.data() + produced);
        stream.avail_out = static_cast<uInt>(output.size() - produced);

        const auto before_in  = stream.avail_in;
        const auto before_out = stream.avail_out;
        const int  rc         = inflate(&stream, Z_NO_FLUSH);
        produced              = output.size() - stream.avail_out;
        if (rc == Z_STREAM_END) {
            if (stream.avail_in != 0) {
                return std::nullopt;
            }
            output.resize(produced);
            return output;
        }
        if (rc != Z_OK || (stream.avail_in == before_in && stream.avail_out == before_out)) {
            return std::nullopt;
        }
    }
}
#endif

class Http1ClientTestServer;

class Http1ClientTestSession : public qb::http::use<Http1ClientTestSession>::session<Http1ClientTestServer> {
public:
    explicit Http1ClientTestSession(Http1ClientTestServer &server);
};

// Connection/request counters live on the SERVER object (not file globals) so a
// test reads them only AFTER it has joined on the observable client outcome.
class Http1ClientTestServer : public qb::http::use<Http1ClientTestServer>::server<Http1ClientTestSession> {
public:
    std::atomic<int>           connection_count{0};
    std::atomic<int>           request_count{0};
    std::atomic<std::uint16_t> redirect_peer_port{0};

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

        // A normal close-delimited response exercises the persistent client's
        // EOF delivery before its disconnected notification retires the transport.
        router().get("/close-delimited", [this](auto ctx) {
            ++request_count;
            auto session = ctx->session();
            ctx->suppress_response();
            session->publish("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\neof-body");
            session->close_after_deliver();
        });

        // Close the real peer before any response bytes exist. The client must
        // retire its active/pending cohort through the disconnected event.
        router().get("/peer-close-without-response", [this](auto ctx) {
            ++request_count;
            auto session = ctx->session();
            ASSERT_NE(session, nullptr);
            ctx->suppress_response();
            session->disconnect();
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

        // The version a request arrived in, as the parser read it.
        router().get("/version", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::to_string(ctx->request().major_version) + "." + std::to_string(ctx->request().minor_version);
            ctx->complete();
        });

        // A response whose version came from elsewhere, as one an HTTP/2 or HTTP/3 upstream returned and a handler forwards.
        router().get("/response-version/:major/:minor", [this](auto ctx) {
            ++request_count;
            ctx->response().status()      = qb::http::status::OK;
            ctx->response().major_version = static_cast<std::uint16_t>(std::stoul(ctx->path_param("major")));
            ctx->response().minor_version = static_cast<std::uint16_t>(std::stoul(ctx->path_param("minor")));
            ctx->response().body()        = "forwarded-" + ctx->path_param("major") + "." + ctx->path_param("minor");
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

        router().post("/informational", [this](auto ctx) {
            ++request_count;
            auto session = ctx->session();
            ASSERT_NE(session, nullptr);
            session->publish("HTTP/1.1 100 Continue\r\n\r\n"
                             "HTTP/1.1 103 Early Hints\r\nLink: </first>\r\n\r\n"
                             "HTTP/1.1 103 Early Hints\r\nLink: </second>\r\n\r\n");
            ctx->response().body() = ctx->request().body().template as<std::string>();
            ctx->response().set_header("X-Final", "yes");
            ctx->complete();
        });

        router().get("/informational-only", [this](auto ctx) {
            ++request_count;
            auto session = ctx->session();
            ASSERT_NE(session, nullptr);
            ctx->suppress_response();
            session->publish("HTTP/1.1 103 Early Hints\r\nLink: </never>\r\n\r\n");
        });

        router().get("/informational-close", [this](auto ctx) {
            ++request_count;
            auto session = ctx->session();
            ASSERT_NE(session, nullptr);
            ctx->suppress_response();
            session->publish("HTTP/1.1 100 Continue\r\n\r\n");
            session->close_after_deliver();
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
            ctx->response().set_header("X-Received-Content-Encoding", ctx->request().header("Content-Encoding"));
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

        // QB-493: chunked responses the server session serializes itself — an empty one (it
        // still needs its last-chunk) and a non-empty one whose HEAD must end at its header
        // section.
        router().get("/empty-chunked", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Transfer-Encoding", "chunked");
            ctx->complete();
        });
        const auto chunked = [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Transfer-Encoding", "chunked");
            ctx->response().body() = "chunked-body";
            ctx->complete();
        };
        router().get("/chunked", chunked);
        router().head("/chunked", chunked);

        // QB-507: bytes that are not HTTP, on a connection the server keeps open, so a client's
        // protocol fails and disposes its session before any response or timeout.
        router().get("/garbage", [this](auto ctx) {
            ++request_count;
            auto session = ctx->session();
            ctx->suppress_response();
            session->publish("NOT HTTP AT ALL\r\n\r\n");
        });

        // Redirect routes share this suite's existing real socket and request counter.
        router().get("/redirect/chain/:hop", [this](auto ctx) {
            ++request_count;
            const auto hop           = std::stoul(ctx->path_param("hop"));
            ctx->response().status() = hop < 3 ? qb::http::status::FOUND : qb::http::status::OK;
            ctx->response().body()   = "chain:" + std::to_string(hop);
            if (hop < 3)
                ctx->response().set_header("Location", "/redirect/chain/" + std::to_string(hop + 1));
            ctx->complete();
        });
        router().get("/redirect/loop", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::FOUND;
            ctx->response().set_header("Location", "/redirect/loop");
            ctx->complete();
        });
        const auto inspect_redirect = [](auto ctx) {
            ctx->response().set_header("X-Seen-Method", std::string(ctx->request().method()));
            for (char const *name :
                 {"Host", "Authorization", "Proxy-Authorization", "Cookie", "Origin", "Referer", "Content-Type", "Content-Encoding",
                  "Content-Length", "Transfer-Encoding"}) {
                ctx->response().set_header(std::string("X-Seen-") + name, ctx->request().header(name));
            }
        };
        const auto redirect_echo = [this, inspect_redirect](auto ctx) {
            ++request_count;
            inspect_redirect(ctx);
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = ctx->request().body().template as<std::string>();
            ctx->complete();
        };
        router().get("/redirect/inspect", redirect_echo);
        router().post("/redirect/inspect", redirect_echo);
        router().head("/redirect/inspect", redirect_echo);
        const auto redirect_method = [this](auto ctx) {
            ++request_count;
            ctx->response().status() = std::stoi(ctx->path_param("status"));
            ctx->response().set_header("Location", "/redirect/inspect");
            ctx->complete();
        };
        router().post("/redirect/method/:status", redirect_method);
        router().head("/redirect/method/:status", redirect_method);
        router().get("/redirect/cross", [this, inspect_redirect](auto ctx) {
            ++request_count;
            inspect_redirect(ctx);
            ctx->response().status() = qb::http::status::FOUND;
            ctx->response().set_header("Location", "http://127.0.0.1:" + std::to_string(redirect_peer_port.load()) + "/redirect/return");
            ctx->complete();
        });
        router().get("/redirect/return", [this, inspect_redirect](auto ctx) {
            ++request_count;
            inspect_redirect(ctx);
            ctx->response().status() = qb::http::status::FOUND;
            ctx->response().set_header("Location", "http://127.0.0.1:" + std::to_string(redirect_peer_port.load()) + "/redirect/inspect");
            ctx->complete();
        });
        router().get("/redirect/ows", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::FOUND;
            ctx->response().set_header("Location", " \t/redirect/inspect \t");
            ctx->complete();
        });
        router().get("/redirect/refuse/:kind", [this](auto ctx) {
            ++request_count;
            ctx->response().status() = qb::http::status::FOUND;
            const auto kind          = ctx->path_param("kind");
            if (kind == "multiple") {
                ctx->response().add_header("Location", "/redirect/inspect");
                ctx->response().add_header("Location", "/ping");
            } else if (kind == "userinfo") {
                ctx->response().set_header("Location", "http://user:secret@127.0.0.1:" + std::to_string(transport().local_endpoint().port())
                                                           + "/redirect/inspect");
            } else {
                ctx->response().set_header("Location", "http://[invalid");
            }
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
        if (!thread.ready()) {
            throw std::runtime_error("HTTP/1.1 loopback server failed to start");
        }
        port = thread.port();
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
        socket_type fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd == qb::io::inet::invalid_socket) {
            throw std::runtime_error("socket failed");
        }
        try {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port   = htons(static_cast<uint16_t>(port));
            if (::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
                throw std::runtime_error("inet_pton failed");
            }
            if (::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
                throw std::runtime_error("connect failed");
            }
            _fd = fd;
        } catch (...) {
            QB_CLOSESOCKET(fd);
            throw;
        }
    }

    ~raw_socket() {
        if (_fd != qb::io::inet::invalid_socket) {
            QB_CLOSESOCKET(_fd);
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

qb::http::async::RedirectReply
request_with_redirects(qb::http::Request req, qb::http::RedirectOptions options = {}, bool verify_peer = true) {
    struct Observation {
        qb::http::async::RedirectReply result;
        unsigned                       delivered = 0;
    };
    auto observed = std::make_shared<Observation>();
    qb::http::REQUEST(
        std::move(req),
        [observed](qb::http::async::RedirectReply &&reply) {
            ++observed->delivered;
            observed->result = std::move(reply);
        },
        2s, verify_peer, options);
    EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->delivered != 0; }));
    drain_client_callbacks();
    EXPECT_EQ(observed->delivered, 1u);
    return std::move(observed->result);
}

} // namespace

TEST(Http1ClientTest, InformationalResponsesCompleteOnlyFinalAndPreserveQueuedRequests) {
    LoopbackHttp1Server             server;
    auto                            client = qb::http1::make_client(server.url("/"));
    std::vector<qb::http::Response> responses;
    auto                            req = request(qb::http::method::POST, "/informational");
    req.body()                          = "request-body";
    req.set_header("Expect", "100-continue");
    ASSERT_TRUE(client->push_request(std::move(req), [&](auto response) {
        responses.push_back(std::move(response));
        // Submitting from the final callback must not steal the queued response.
        client->push_request(request(qb::http::method::GET, "/item/reentrant"), [&](auto reply) { responses.push_back(std::move(reply)); });
    }));
    ASSERT_TRUE(
        client->push_request(request(qb::http::method::GET, "/item/queued"), [&](auto response) { responses.push_back(std::move(response)); }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return responses.size() == 3; }));
    ASSERT_EQ(responses.size(), 3u);
    EXPECT_EQ(responses[0].status(), qb::http::status::OK);
    EXPECT_EQ(responses[0].body().as<std::string>(), "request-body");
    EXPECT_EQ(responses[0].header("X-Final"), "yes");
    EXPECT_FALSE(responses[0].has_header("Link"));
    EXPECT_EQ(responses[1].body().as<std::string>(), "queued");
    EXPECT_EQ(responses[2].body().as<std::string>(), "reentrant");
    EXPECT_EQ(server.connection_count(), 1);
    client->disconnect();
    drain_client_callbacks();
    EXPECT_EQ(responses.size(), 3u);
}

TEST(Http1ClientTest, InformationalResponsesOneShotCoroutineReturnsFinal) {
    LoopbackHttp1Server server;
    auto                req = request(qb::http::method::POST, server.url("/informational"));
    req.body()              = "oneshot-body";
    req.set_header("Expect", "100-continue");
    auto reply = qb::http::run_sync(qb::http::POST(std::move(req), 2s));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.body().as<std::string>(), "oneshot-body");
    EXPECT_EQ(reply.response.header("X-Final"), "yes");
    EXPECT_FALSE(reply.response.has_header("Link"));
    drain_client_callbacks();
}

TEST(Http1ClientTest, InformationalResponseDoesNotCancelPersistentTimeout) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));
    client->set_request_timeout(100ms);
    int                calls = 0;
    qb::http::Response result;
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/informational-only"), [&](auto response) {
        ++calls;
        result = std::move(response);
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return calls != 0; }));
    EXPECT_EQ(result.status(), qb::http::status::GATEWAY_TIMEOUT);
    client->disconnect();
    drain_client_callbacks();
    EXPECT_EQ(calls, 1);
}

TEST(Http1ClientTest, InformationalResponseOneShotTimeoutAndPeerCloseAreTerminalErrors) {
    LoopbackHttp1Server server;
    auto timeout_reply = qb::http::run_sync(qb::http::GET(request(qb::http::method::GET, server.url("/informational-only")), 100ms));
    EXPECT_EQ(timeout_reply.response.status(), qb::http::status::GATEWAY_TIMEOUT);
    auto close_reply = qb::http::run_sync(qb::http::GET(request(qb::http::method::GET, server.url("/informational-close")), 2s));
    EXPECT_EQ(close_reply.response.status(), qb::http::status::BAD_GATEWAY);
    drain_client_callbacks();
}

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

// A request received over HTTP/2 or HTTP/3 carries that version (2.0, 3.0). Forwarded through the HTTP/1.1 client it
// goes out in the version of the connection, HTTP/1.1, and is served; it went out as `HTTP/2.0` or `HTTP/3.0`, which a
// qbm-http server answers 505. A request set to 1.0 on purpose stays 1.0.
TEST(Http1ClientTest, AForwardedRequestGoesOutInTheVersionOfTheConnection) {
    LoopbackHttp1Server             server;
    auto                            client = qb::http1::make_client(server.url("/"));
    std::vector<qb::http::Response> responses;
    for (auto const &[major, minor] : {std::pair<std::uint16_t, std::uint16_t>{2, 0}, {3, 0}, {1, 0}}) {
        auto req          = request(qb::http::method::GET, "/version");
        req.major_version = major;
        req.minor_version = minor;
        ASSERT_TRUE(client->push_request(std::move(req), [&](auto response) { responses.push_back(std::move(response)); }));
    }
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return responses.size() == 3; }));
    ASSERT_EQ(responses.size(), 3u);
    for (std::size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(responses[i].status(), qb::http::status::OK) << "request " << i;
        EXPECT_EQ(responses[i].body().as<std::string>(), i < 2 ? "1.1" : "1.0") << "request " << i;
    }
    client->disconnect();
    drain_client_callbacks();
}

// The server's side: a Response whose version came from elsewhere -- an HTTP/3 or HTTP/2 upstream's, which a handler
// forwards -- goes out in HTTP/1.1, where its status line read `HTTP/3.0 200 OK`, which no HTTP/1.1 client parses; one
// set to 1.0 on purpose stays 1.0.
TEST(Http1ClientTest, AForwardedResponseGoesOutInTheVersionOfTheConnection) {
    LoopbackHttp1Server server;
    raw_socket          socket{server.port};
    for (auto const &[path, status_line] :
         {std::pair<std::string, std::string>{"/response-version/3/0", "HTTP/1.1 200 OK\r\n"},
          {"/response-version/2/0", "HTTP/1.1 200 OK\r\n"},
          {"/response-version/1/0", "HTTP/1.0 200 OK\r\n"}}) {
        socket.send_all("GET " + path + " HTTP/1.1\r\nHost: localhost\r\n\r\n");
        const auto marker   = "forwarded-" + path.substr(std::string{"/response-version/"}.size(), 1) + "." + path.back();
        const auto response = socket.read_until(marker);
        EXPECT_TRUE(response.starts_with(status_line)) << path << ": " << response.substr(0, response.find('\r'));
    }
    auto                              client = qb::http1::make_client(server.url("/"));
    std::optional<qb::http::Response> reply;
    ASSERT_TRUE(
        client->push_request(request(qb::http::method::GET, "/response-version/3/0"), [&](auto response) { reply = std::move(response); }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return reply.has_value(); }));
    EXPECT_EQ(reply->status(), qb::http::status::OK) << "the HTTP/1.1 client reads the answer";
    EXPECT_EQ(reply->body().as<std::string>(), "forwarded-3.0");
    client->disconnect();
    drain_client_callbacks();
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

// Every user callback puts the client under a self-hold that must last to the tail of the
// current loop turn. Nothing promises there IS another turn: the three cases above end
// right after a synchronous callback, which is legitimate — the client's contract does not
// require the caller to keep pumping. When that hold lived in a `shared_ptr<Client>` MEMBER
// released only by the deferred callback, "no further turn" meant "released never": a
// shared_ptr pointing at its own Client, uncollectable, taking the connection and the
// protocol from switch_protocol() with it. LeakSanitizer measured 18 632 bytes in 15
// allocations on exactly these cases — every block *Indirect*, not one Direct, which is the
// signature of a cycle whose only inbound pointer is its own. macOS ships no LeakSanitizer,
// so the whole class is invisible there.
//
// weak_ptr::expired() is the allocator-independent oracle, and it needs the real ending to
// be meaningful: the hold legitimately survives the client's own scope (the queued closure
// owns it), so the client must die when its LOOP dies. Running on a dedicated thread makes
// that deterministic — `listener::current` is thread_local, and ~listener drops the deferred
// queue with it — without disturbing this binary's main loop.
TEST(Http1ClientTest, ClientIsReleasedWhenItsLoopEndsWithoutAnotherTurn) {
    std::weak_ptr<qb::http1::Client> weak;
    bool                             callback_fired = false;
    bool                             queued         = true;

    std::thread([&] {
        qb::io::async::init();
        auto client = qb::http1::make_client("http://127.0.0.1:1");
        weak        = client;
        // max_pending_requests(0) makes push_request synthesize its 503 and invoke the user
        // callback SYNCHRONOUSLY, which is what arms the self-hold.
        client->set_max_pending_requests(0);
        queued = client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) { callback_fired = true; });
        // Deliberately no drain: this is the shape under test.
    }).join(); // thread exit tears the listener down, dropping the still-queued defer

    ASSERT_FALSE(queued);
    ASSERT_TRUE(callback_fired) << "the user callback never ran, so no self-hold was ever taken and this case proves nothing";
    EXPECT_TRUE(weak.expired()) << "the client outlived its own event loop: the self-hold taken for the current turn was never "
                                   "released, so the Client holds the last reference to itself and neither it nor its connection "
                                   "can ever be reclaimed";
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
// gzip-compressed form. A direct zlib decoder must consume the complete stream
// and reproduce the original plaintext byte-for-byte.
TEST(Http1ClientTest, RequestBodyIsCompressedWhenContentEncodingSet) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));

    const std::string plaintext(2048, 'A'); // highly compressible
    auto              req = request(qb::http::method::POST, "/echo-raw");
    req.body()            = plaintext;
    req.set_header("Content-Encoding", "gzip");

    auto response = qb::http::run_sync(client->push_request(std::move(req)));
    EXPECT_EQ(response.status(), qb::http::status::OK);
    EXPECT_EQ(response.header("X-Received-Content-Encoding"), "gzip");

    const auto echoed = response.body().template as<std::string>();
    ASSERT_FALSE(echoed.empty());
    const auto decoded = gunzip_reference(echoed);
    ASSERT_TRUE(decoded.has_value()) << "the request body was not a complete valid gzip stream";
    EXPECT_EQ(*decoded, plaintext);
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

TEST(Http1ClientTest, OneShotHttpSchemesUsePlainTransportAcrossCaseVariants) {
    LoopbackHttp1Server server;
    const auto          lower     = qb::http::run_sync(qb::http::GET(qb::http::Request{{server.url("/ping")}}, std::chrono::seconds(1)));
    const std::string   mixed_url = "hTtP" + server.url("/ping").substr(4);
    const auto          mixed     = qb::http::run_sync(qb::http::GET(qb::http::Request{{mixed_url}}, std::chrono::seconds(1)));

    EXPECT_EQ(lower.response.status(), qb::http::status::OK);
    EXPECT_EQ(mixed.response.status(), qb::http::status::OK);
    EXPECT_EQ(server.request_count(), 2);
    EXPECT_EQ(server.connection_count(), 2);
}

TEST(Http1ClientTest, OneShotUnsupportedSchemeIsRejectedBeforeConnecting) {
    LoopbackHttp1Server server;
    const std::string   ftp_url = "ftp" + server.url("/ping").substr(4);
    auto                reply   = qb::http::run_sync(qb::http::GET(qb::http::Request{{ftp_url}}, std::chrono::seconds(1)));
    EXPECT_EQ(reply.response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(server.connection_count(), 0);
    EXPECT_EQ(server.request_count(), 0);
}

#if !QB_HAS_SSL
TEST(Http1ClientTest, OneShotHttpsWithoutSslIsRejectedBeforeConnecting) {
    LoopbackHttp1Server server;
    const std::string   https_url = "HTTPS" + server.url("/ping").substr(4);
    auto                reply     = qb::http::run_sync(qb::http::GET(qb::http::Request{{https_url}}, std::chrono::seconds(1)));
    EXPECT_EQ(reply.response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(server.connection_count(), 0);
    EXPECT_EQ(server.request_count(), 0);
}
#endif

namespace http1_callback_reentry_test {
struct Observation {
    bool               cleaning          = false;
    int                closing_callbacks = 0;
    int                old_callbacks     = 0;
    int                new_callbacks     = 0;
    int                connects          = 0;
    bool               reconnected       = false;
    qb::http::Response response;
};
struct Cleanup {
    std::shared_ptr<qb::http1::Client> &client;
    std::shared_ptr<Observation>        observation;
    ~Cleanup() {
        observation->cleaning = true;
        client->disconnect();
        drain_client_callbacks();
    }
};
} // namespace http1_callback_reentry_test

// QB-509: new work submitted by a callback belongs to the next connection,
// not to the response/failed cohort whose callback is currently being delivered.
TEST(Http1ClientTest, CloseResponseCallbackQueuesItsNextRequestOnANewConnection) {
    using namespace http1_callback_reentry_test;
    qb::io::async::init();
    LoopbackHttp1Server server;
    auto                client   = qb::http1::make_client(server.url(""));
    auto                observed = std::make_shared<Observation>();
    Cleanup             cleanup{client, observed};
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/close"), [&, observed](auto response) {
        if (observed->cleaning)
            return;
        ++observed->closing_callbacks;
        EXPECT_EQ(response.status(), qb::http::status::OK);
        EXPECT_FALSE(client->is_connected()) << "Connection: close must retire availability before calling user code";
        EXPECT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [observed](auto result) {
            if (observed->cleaning)
                return;
            observed->response = std::move(result);
            ++observed->new_callbacks;
        }));
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->new_callbacks != 0; }));
    EXPECT_EQ(observed->closing_callbacks, 1);
    EXPECT_EQ(observed->new_callbacks, 1);
    EXPECT_EQ(observed->response.status(), qb::http::status::OK);
    EXPECT_EQ(observed->response.body().as<std::string>(), "pong");
    EXPECT_EQ(server.connection_count(), 2);
    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 2u);
    EXPECT_EQ(failed, 0u);
}

TEST(Http1ClientTest, DisconnectFailureCallbackDoesNotFailItsNewRequestWithTheOldCohort) {
    using namespace http1_callback_reentry_test;
    qb::io::async::init();
    LoopbackHttp1Server server;
    auto                client   = qb::http1::make_client(server.url(""));
    auto                observed = std::make_shared<Observation>();
    Cleanup             cleanup{client, observed};
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/never"), [&, observed](auto response) {
        if (observed->cleaning)
            return;
        ++observed->old_callbacks;
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
        EXPECT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [observed](auto result) {
            if (observed->cleaning)
                return;
            observed->response = std::move(result);
            ++observed->new_callbacks;
        }));
        throw std::runtime_error("old failure callback threw after submitting new work");
    }));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/item/old-queued"), [observed](auto response) {
        if (observed->cleaning)
            return;
        ++observed->old_callbacks;
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return server.request_count() == 1; }));
    client->disconnect();
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->new_callbacks != 0; }));
    EXPECT_EQ(observed->old_callbacks, 2);
    EXPECT_EQ(observed->new_callbacks, 1);
    EXPECT_EQ(observed->response.status(), qb::http::status::OK);
    EXPECT_EQ(observed->response.body().as<std::string>(), "pong");
    EXPECT_EQ(server.connection_count(), 2);
    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 3u);
    EXPECT_EQ(successful, 1u);
    EXPECT_EQ(failed, 2u);
}

TEST(Http1ClientTest, PeerCloseBeforeResponseKeepsReentrantConnectOutsideTheFailedCohort) {
    using namespace http1_callback_reentry_test;
    qb::io::async::init();
    LoopbackHttp1Server server;
    auto                client   = qb::http1::make_client(server.url(""));
    auto                observed = std::make_shared<Observation>();
    Cleanup             cleanup{client, observed};
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero());
    auto connected = qb::http::run_sync(client->connect());
    ASSERT_TRUE(connected) << connected.error_message;
    ASSERT_TRUE(client->is_connected());

    // Both requests are submitted before pumping the client loop. Only the
    // first can reach the peer; the second belongs to its pending cohort.
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/peer-close-without-response"), [&, observed](auto response) {
        if (observed->cleaning)
            return;
        ++observed->old_callbacks;
        EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY);
        EXPECT_FALSE(client->is_connected());
        EXPECT_TRUE(client->connect([observed](bool ok, const std::string &) {
            if (observed->cleaning)
                return;
            ++observed->connects;
            observed->reconnected = ok;
        }));
        EXPECT_TRUE(client->is_connecting());
        EXPECT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [observed](auto result) {
            if (observed->cleaning)
                return;
            observed->response = std::move(result);
            ++observed->new_callbacks;
        }));
    }));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/item/old-queued"), [observed](auto response) {
        if (observed->cleaning)
            return;
        ++observed->old_callbacks;
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->new_callbacks != 0; }));
    EXPECT_EQ(observed->old_callbacks, 2);
    EXPECT_EQ(observed->connects, 1);
    EXPECT_TRUE(observed->reconnected);
    EXPECT_EQ(observed->new_callbacks, 1);
    EXPECT_EQ(observed->response.status(), qb::http::status::OK);
    EXPECT_EQ(observed->response.body().as<std::string>(), "pong");
    EXPECT_EQ(server.connection_count(), 2);
    EXPECT_EQ(server.request_count(), 2);
    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 3u);
    EXPECT_EQ(successful, 1u);
    EXPECT_EQ(failed, 2u);
}

TEST(Http1ClientTest, DeferredDisconnectCleanupDoesNotResetAReentrantConnect) {
    using namespace http1_callback_reentry_test;
    for (const bool auto_reconnect : {true, false}) {
        SCOPED_TRACE(auto_reconnect);
        qb::io::async::init();
        LoopbackHttp1Server server;
        auto                client   = qb::http1::make_client(server.url(""));
        auto                observed = std::make_shared<Observation>();
        Cleanup             cleanup{client, observed};
        ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&, observed, auto_reconnect](auto response) {
            if (observed->cleaning)
                return;
            EXPECT_EQ(response.status(), qb::http::status::OK);
            client->set_auto_reconnect(auto_reconnect);
            client->disconnect();
            EXPECT_TRUE(client->connect([observed](bool ok, const std::string &) {
                if (observed->cleaning)
                    return;
                ++observed->connects;
                observed->reconnected = ok;
            }));
            EXPECT_TRUE(client->is_connecting());
            EXPECT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [observed](auto result) {
                if (observed->cleaning)
                    return;
                observed->response = std::move(result);
                ++observed->new_callbacks;
            }));
        }));
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->connects != 0; }));
        ASSERT_TRUE(observed->reconnected);
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->new_callbacks != 0; }));
        EXPECT_EQ(observed->connects, 1);
        EXPECT_EQ(observed->new_callbacks, 1);
        EXPECT_EQ(observed->response.status(), qb::http::status::OK);
        EXPECT_EQ(observed->response.body().as<std::string>(), "pong");
        EXPECT_EQ(server.connection_count(), 2);
        auto [total, successful, failed] = client->get_stats();
        EXPECT_EQ(total, 2u);
        EXPECT_EQ(successful, 2u);
        EXPECT_EQ(failed, 0u);
    }
}

TEST(Http1ClientTest, DisconnectingAConnectAttemptRetiresItsCallbacksBeforeNewIntent) {
    using namespace http1_callback_reentry_test;
    qb::io::async::init();
    LoopbackHttp1Server server;
    auto                client   = qb::http1::make_client(server.url(""));
    auto                observed = std::make_shared<Observation>();
    Cleanup             cleanup{client, observed};
    client->set_auto_reconnect(false);
    ASSERT_TRUE(client->connect([&, observed](bool ok, const std::string &) {
        if (observed->cleaning)
            return;
        ++observed->old_callbacks;
        EXPECT_FALSE(ok);
        EXPECT_FALSE(client->is_connected());
        EXPECT_TRUE(client->connect([observed](bool connected, const std::string &) {
            if (observed->cleaning)
                return;
            ++observed->connects;
            observed->reconnected = connected;
        }));
        EXPECT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [observed](auto response) {
            if (observed->cleaning)
                return;
            observed->response = std::move(response);
            ++observed->new_callbacks;
        }));
    }));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/item/old-queued"), [observed](auto response) {
        if (observed->cleaning)
            return;
        ++observed->old_callbacks;
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    }));
    client->disconnect();
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->new_callbacks != 0; }));
    EXPECT_EQ(observed->old_callbacks, 2);
    EXPECT_EQ(observed->connects, 1);
    EXPECT_TRUE(observed->reconnected);
    EXPECT_EQ(observed->new_callbacks, 1);
    EXPECT_EQ(observed->response.status(), qb::http::status::OK);
    EXPECT_EQ(observed->response.body().as<std::string>(), "pong");
    EXPECT_EQ(server.request_count(), 1);
    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 1u);
    EXPECT_EQ(failed, 1u);
}

TEST(Http1ClientTest, ConnectionFailureCallbackDoesNotFailTheNextAttemptRequestEarly) {
    using namespace http1_callback_reentry_test;
    qb::io::async::init();
    auto    client   = qb::http1::make_client("http://127.0.0.1:1");
    auto    observed = std::make_shared<Observation>();
    Cleanup cleanup{client, observed};
    client->set_request_timeout(qb::duration::zero());
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/old"), [observed](auto response) {
        if (observed->cleaning)
            return;
        ++observed->old_callbacks;
        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    }));
    ASSERT_TRUE(client->connect([&, observed](bool ok, const std::string &) {
        if (observed->cleaning)
            return;
        ++observed->old_callbacks;
        EXPECT_FALSE(ok);
        EXPECT_TRUE(client->connect([observed](bool connected, const std::string &) {
            if (observed->cleaning)
                return;
            ++observed->connects;
            EXPECT_FALSE(connected);
        }));
        EXPECT_TRUE(client->push_request(request(qb::http::method::GET, "/new"), [observed](auto response) {
            if (observed->cleaning)
                return;
            EXPECT_EQ(observed->connects, 1) << "new request belongs to the next connection-failure cohort";
            ++observed->new_callbacks;
            EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
        }));
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->new_callbacks != 0; }));
    EXPECT_EQ(observed->old_callbacks, 2);
    EXPECT_EQ(observed->connects, 1);
    EXPECT_EQ(observed->new_callbacks, 1);
    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 0u);
    EXPECT_EQ(failed, 2u);
}

TEST(Http1ClientTest, RequestTimeoutCallbackQueuesNewWorkAfterRetirement) {
    using namespace http1_callback_reentry_test;
    qb::io::async::init();
    LoopbackHttp1Server server;
    auto                client   = qb::http1::make_client(server.url(""));
    auto                observed = std::make_shared<Observation>();
    Cleanup             cleanup{client, observed};
    client->set_request_timeout(1s);
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/never"), [&, observed](auto response) {
        if (observed->cleaning)
            return;
        ++observed->old_callbacks;
        EXPECT_EQ(response.status(), qb::http::status::GATEWAY_TIMEOUT);
        EXPECT_FALSE(client->is_connected());
        client->set_request_timeout(2s);
        EXPECT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [observed](auto result) {
            if (observed->cleaning)
                return;
            observed->response = std::move(result);
            ++observed->new_callbacks;
        }));
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return server.request_count() == 1; }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->new_callbacks != 0; }));
    EXPECT_EQ(observed->old_callbacks, 1);
    EXPECT_EQ(observed->new_callbacks, 1);
    EXPECT_EQ(observed->response.status(), qb::http::status::OK);
    EXPECT_EQ(observed->response.body().as<std::string>(), "pong");
    EXPECT_EQ(server.connection_count(), 2);
    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 1u);
    EXPECT_EQ(failed, 1u);
}

TEST(Http1ClientTest, FailedBatchCallbackCanQueueANewBatchAfterTheOldCohort) {
    using namespace http1_callback_reentry_test;
    qb::io::async::init();
    LoopbackHttp1Server            server;
    auto                           client   = qb::http1::make_client(server.url(""));
    auto                           observed = std::make_shared<Observation>();
    Cleanup                        cleanup{client, observed};
    std::vector<qb::http::Request> requests;
    requests.emplace_back(request(qb::http::method::GET, "/never"));
    requests.emplace_back(request(qb::http::method::GET, "/item/old-queued"));
    ASSERT_TRUE(client->push_requests(std::move(requests), [&, observed](auto responses) {
        if (observed->cleaning)
            return;
        ++observed->old_callbacks;
        ASSERT_EQ(responses.size(), 2u);
        EXPECT_EQ(responses[0].status(), qb::http::status::SERVICE_UNAVAILABLE);
        EXPECT_EQ(responses[1].status(), qb::http::status::SERVICE_UNAVAILABLE);
        std::vector<qb::http::Request> next;
        next.emplace_back(request(qb::http::method::GET, "/ping"));
        next.emplace_back(request(qb::http::method::GET, "/item/next"));
        EXPECT_TRUE(client->push_requests(std::move(next), [observed](auto results) {
            if (observed->cleaning)
                return;
            ++observed->new_callbacks;
            ASSERT_EQ(results.size(), 2u);
            EXPECT_EQ(results[0].status(), qb::http::status::OK);
            EXPECT_EQ(results[1].status(), qb::http::status::OK);
            EXPECT_EQ(results[0].body().template as<std::string>(), "pong");
            EXPECT_EQ(results[1].body().template as<std::string>(), "next");
        }));
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return server.request_count() == 1; }));
    client->disconnect();
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->new_callbacks != 0; }));
    EXPECT_EQ(observed->old_callbacks, 1);
    EXPECT_EQ(observed->new_callbacks, 1);
    EXPECT_EQ(server.connection_count(), 2);
    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 4u);
    EXPECT_EQ(successful, 2u);
    EXPECT_EQ(failed, 2u);
}

TEST(Http1ClientTest, EofBodyCallbackQueuesItsNextRequestAfterRetirement) {
    using namespace http1_callback_reentry_test;
    qb::io::async::init();
    LoopbackHttp1Server server;
    auto                client   = qb::http1::make_client(server.url(""));
    auto                observed = std::make_shared<Observation>();
    Cleanup             cleanup{client, observed};
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/close-delimited"), [&, observed](auto response) {
        if (observed->cleaning)
            return;
        ++observed->closing_callbacks;
        EXPECT_EQ(response.status(), qb::http::status::OK);
        EXPECT_EQ(response.body().template as<std::string>(), "eof-body");
        EXPECT_FALSE(client->is_connected());
        EXPECT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [observed](auto result) {
            if (observed->cleaning)
                return;
            observed->response = std::move(result);
            ++observed->new_callbacks;
        }));
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->new_callbacks != 0; }));
    EXPECT_EQ(observed->closing_callbacks, 1);
    EXPECT_EQ(observed->new_callbacks, 1);
    EXPECT_EQ(observed->response.status(), qb::http::status::OK);
    EXPECT_EQ(observed->response.body().as<std::string>(), "pong");
    EXPECT_EQ(server.connection_count(), 2);
    auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(total, 2u);
    EXPECT_EQ(successful, 2u);
    EXPECT_EQ(failed, 0u);
}

// ===========================================================================
// The one-shot session (qb::http::GET/POST/... with a callback) answers EXACTLY once
// (Huly QB-507).
//
// It delivered a response, a timeout or — for a peer close only — a 502, and nothing
// else: a close-delimited response (RFC 9112 §6.3), complete at EOF, was answered 502
// because the session never asked its protocol to deliver what it had buffered; and a
// disposal for any other reason before a verdict (a protocol error, a read limit) answered
// nothing at all, so the callback — and a coroutine awaiting it — waited forever. The
// verdict now comes from one place, at most once, and the disposal supplies the failure
// when nothing else did.
// ===========================================================================

namespace http1_one_shot_test {
struct Outcome {
    int                count = 0;
    qb::http::Response response;
};

[[nodiscard]] inline auto
recorder(std::shared_ptr<Outcome> const &outcome) {
    return [outcome](qb::http::async::Reply &&reply) {
        ++outcome->count;
        outcome->response = std::move(reply.response);
    };
}
} // namespace http1_one_shot_test

TEST(Http1ClientTest, OneShotDeliversACloseDelimitedResponseAtEof) {
    using namespace http1_one_shot_test;
    qb::io::async::init();
    LoopbackHttp1Server server;
    auto                outcome = std::make_shared<Outcome>();

    qb::http::GET(qb::http::Request{{server.url("/close-delimited")}}, recorder(outcome), std::chrono::seconds(5));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return outcome->count > 0; }, std::chrono::seconds(3)));
    drain_client_callbacks();

    EXPECT_EQ(outcome->count, 1);
    EXPECT_EQ(outcome->response.status(), qb::http::status::OK) << "a complete close-delimited response was answered as a failure";
    EXPECT_EQ(outcome->response.body().as<std::string>(), "eof-body");
}

TEST(Http1ClientTest, OneShotDisposedBeforeAVerdictStillAnswersOnce) {
    using namespace http1_one_shot_test;
    qb::io::async::init();
    LoopbackHttp1Server server;
    auto                outcome = std::make_shared<Outcome>();

    // The peer answers bytes that are not HTTP and keeps the connection open: the client's
    // protocol fails, and the session is disposed with a protocol-error reason. The budget is
    // shorter than the request timeout, so the answer cannot come from the timer.
    qb::http::GET(qb::http::Request{{server.url("/garbage")}}, recorder(outcome), std::chrono::seconds(10));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return outcome->count > 0; }, std::chrono::seconds(3)))
        << "the session was disposed and its callback never ran";
    drain_client_callbacks();

    EXPECT_EQ(outcome->count, 1);
    EXPECT_EQ(outcome->response.status(), qb::http::status::BAD_GATEWAY);
}

TEST(Http1ClientTest, OneShotSuccessAndTimeoutAnswerExactlyOnce) {
    using namespace http1_one_shot_test;
    qb::io::async::init();
    LoopbackHttp1Server server;

    auto success = std::make_shared<Outcome>();
    qb::http::GET(qb::http::Request{{server.url("/ping")}}, recorder(success), std::chrono::seconds(5));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return success->count > 0; }, std::chrono::seconds(3)));

    auto timeout = std::make_shared<Outcome>();
    qb::http::GET(qb::http::Request{{server.url("/never")}}, recorder(timeout), std::chrono::milliseconds(200));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return timeout->count > 0; }, std::chrono::seconds(3)));
    drain_client_callbacks();

    EXPECT_EQ(success->count, 1) << "the disconnect that follows a response answered a second time";
    EXPECT_EQ(success->response.status(), qb::http::status::OK);
    EXPECT_EQ(success->response.body().as<std::string>(), "pong");
    EXPECT_EQ(timeout->count, 1) << "the disconnect that follows a timeout answered a second time";
    EXPECT_EQ(timeout->response.status(), qb::http::status::GATEWAY_TIMEOUT);
}

// QB-494 through the one-shot session: a request-target the serializer refuses is answered
// 400 by the client, once, and no byte of it reaches the peer. The serializer throws inside the
// session's connect completion, which must not let the exception out of the event loop.
TEST(Http1ClientTest, OneShotRefusesARequestTargetItCannotSerialize) {
    using namespace http1_one_shot_test;
    qb::io::async::init();
    LoopbackHttp1Server server;
    auto                outcome = std::make_shared<Outcome>();

    qb::http::GET(qb::http::Request{{server.url("/q?a=1 b")}}, recorder(outcome), std::chrono::seconds(5));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return outcome->count > 0; }, std::chrono::seconds(3)));
    drain_client_callbacks();

    EXPECT_EQ(outcome->count, 1);
    EXPECT_EQ(outcome->response.status(), qb::http::status::BAD_REQUEST);
    EXPECT_EQ(server.request_count(), 0);
}

// ===========================================================================
// The server's HTTP/1.1 response framing on a kept-alive connection (Huly QB-493).
//
// An empty chunked response must still end with its last-chunk, or the client waits for a
// body that never comes. The response to HEAD keeps its framing headers but ends at its
// header section — no last-chunk either; the session states that explicitly
// (qb::http::MessageHead). It also used to add a Content-Length next to a declared
// Transfer-Encoding for HEAD, which the serializer refuses: the connection was dropped.
// ===========================================================================

TEST(Http1ClientTest, EmptyChunkedResponseIsTerminatedOnAKeptAliveConnection) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));
    client->set_request_timeout(std::chrono::seconds(3));

    auto empty = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/empty-chunked")));
    auto ping  = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));

    EXPECT_EQ(empty.status(), qb::http::status::OK);
    EXPECT_TRUE(empty.body().empty());
    EXPECT_EQ(ping.status(), qb::http::status::OK);
    EXPECT_EQ(ping.body().template as<std::string>(), "pong");
    EXPECT_EQ(server.connection_count(), 1) << "the empty chunked response did not end, so its connection could not be reused";
    drain_client_callbacks();
}

TEST(Http1ClientTest, HeadOfAChunkedRouteEndsAtItsHeaderSection) {
    LoopbackHttp1Server server;
    auto                client = qb::http1::make_client(server.url("/"));
    client->set_request_timeout(std::chrono::seconds(3));

    auto head = qb::http::run_sync(client->push_request(request(qb::http::method::HEAD, "/chunked")));
    auto get  = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/chunked")));
    auto ping = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));

    EXPECT_EQ(head.status(), qb::http::status::OK);
    EXPECT_EQ(head.header("Transfer-Encoding"), "chunked");
    EXPECT_FALSE(head.has_header("Content-Length")) << "Content-Length next to Transfer-Encoding";
    EXPECT_TRUE(head.body().empty());
    EXPECT_EQ(get.status(), qb::http::status::OK);
    EXPECT_EQ(get.body().template as<std::string>(), "chunked-body");
    EXPECT_EQ(ping.status(), qb::http::status::OK);
    EXPECT_EQ(server.connection_count(), 1) << "the HEAD response left bytes behind, or the connection was dropped";
    drain_client_callbacks();
}

// QB-169: following is opt-in; old one-shot requests still return the first 3xx.
TEST(Http1ClientTest, RedirectLegacyPathAndZeroCapNeverFollow) {
    LoopbackHttp1Server server;
    auto                legacy = qb::http::run_sync(qb::http::GET(request(qb::http::method::GET, server.url("/redirect/chain/0")), 2s));
    EXPECT_EQ(legacy.response.status(), qb::http::status::FOUND);
    EXPECT_EQ(server.request_count(), 1);
    auto zero = request_with_redirects(request(qb::http::method::GET, server.url("/redirect/chain/0")), {0, false});
    EXPECT_EQ(zero.response.status(), qb::http::status::FOUND);
    EXPECT_TRUE(zero.hops.empty());
    EXPECT_EQ(zero.request.uri().path(), "/redirect/chain/0");
    EXPECT_EQ(server.request_count(), 2);
}

TEST(Http1ClientTest, RedirectCapHistoryAndTerminalRequestAreExact) {
    LoopbackHttp1Server server;
    for (const std::size_t cap : {std::size_t{1}, std::size_t{5}, (std::numeric_limits<std::size_t>::max)()}) {
        SCOPED_TRACE(cap);
        const auto before   = server.request_count();
        const auto followed = std::min(cap, std::size_t{3});
        auto       req      = request(qb::http::method::GET, server.url("/redirect/chain/0"));
        req.set_header("X-Trace", "redirect-history");
        req.set_header("Authorization", "same-origin-secret");
        auto reply = request_with_redirects(std::move(req), {cap, false});
        EXPECT_EQ(reply.response.status(), cap < 3 ? qb::http::status::FOUND : qb::http::status::OK);
        EXPECT_EQ(reply.response.body().as<std::string>(), "chain:" + std::to_string(followed));
        EXPECT_EQ(reply.request.uri().path(), "/redirect/chain/" + std::to_string(followed));
        EXPECT_EQ(reply.request.header("Authorization"), "same-origin-secret");
        ASSERT_EQ(reply.hops.size(), followed);
        EXPECT_EQ(server.request_count() - before, static_cast<int>(followed + 1));
        for (std::size_t i = 0; i < followed; ++i) {
            EXPECT_EQ(reply.hops[i].response.status(), qb::http::status::FOUND);
            EXPECT_EQ(reply.hops[i].request.uri().path(), "/redirect/chain/" + std::to_string(i));
            EXPECT_EQ(reply.hops[i].request.header("X-Trace"), "redirect-history");
            EXPECT_EQ(reply.hops[i].request.header("Authorization"), "same-origin-secret");
            EXPECT_EQ(reply.hops[i].request.header("Host"), "127.0.0.1:" + std::to_string(server.port));
            EXPECT_FALSE(reply.hops[i].request.header("User-Agent").empty());
        }
    }
    const auto before = server.request_count();
    auto       loop   = request_with_redirects(request(qb::http::method::GET, server.url("/redirect/loop")), {1, false});
    EXPECT_EQ(loop.response.status(), qb::http::status::FOUND);
    ASSERT_EQ(loop.hops.size(), 1u);
    EXPECT_EQ(loop.request.uri().path(), "/redirect/loop");
    EXPECT_EQ(server.request_count() - before, 2);
}

TEST(Http1ClientTest, RedirectPost301302303DropsBodyAndEntityHeaders) {
    LoopbackHttp1Server server;
    for (int code : {301, 302, 303}) {
        SCOPED_TRACE(code);
        auto req   = request(qb::http::method::POST, server.url("/redirect/method/" + std::to_string(code)));
        req.body() = "discard-this-body";
        req.set_header("Content-Type", "application/octet-stream");
        req.set_header("Content-Length", "17");
        auto reply = request_with_redirects(std::move(req));
        ASSERT_EQ(reply.hops.size(), 1u);
        EXPECT_EQ(reply.hops.front().request.method(), qb::http::method::POST);
        EXPECT_EQ(reply.hops.front().response.status(), code);
        EXPECT_EQ(reply.response.status(), qb::http::status::OK);
        EXPECT_EQ(reply.response.header("X-Seen-Method"), "GET");
        EXPECT_TRUE(reply.response.body().empty());
        EXPECT_TRUE(reply.response.header("X-Seen-Content-Type").empty());
        EXPECT_TRUE(reply.response.header("X-Seen-Content-Length").empty());
        EXPECT_TRUE(reply.response.header("X-Seen-Content-Encoding").empty());
        EXPECT_TRUE(reply.response.header("X-Seen-Transfer-Encoding").empty());
        EXPECT_EQ(reply.request.method(), qb::http::method::GET);
        EXPECT_TRUE(reply.request.body().empty());
    }
}

TEST(Http1ClientTest, Redirect303KeepsHeadAndHasNoBody) {
    LoopbackHttp1Server server;
    auto                reply = request_with_redirects(request(qb::http::method::HEAD, server.url("/redirect/method/303")));
    ASSERT_EQ(reply.hops.size(), 1u);
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.header("X-Seen-Method"), "HEAD");
    EXPECT_EQ(reply.request.method(), qb::http::method::HEAD);
    EXPECT_TRUE(reply.response.body().empty());
}

#ifdef QB_HAS_COMPRESSION
TEST(Http1ClientTest, Redirect303DropsCompressionBeforePreparingNextRequest) {
    LoopbackHttp1Server server;
    auto                req = request(qb::http::method::POST, server.url("/redirect/method/303"));
    req.body()              = "discard-this-compressed-body";
    req.set_header("Content-Encoding", "gzip");
    req.set_header("Content-Type", "application/octet-stream");
    auto reply = request_with_redirects(std::move(req));
    ASSERT_EQ(reply.hops.size(), 1u);
    EXPECT_EQ(reply.hops.front().request.header("Content-Encoding"), "gzip");
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.response.header("X-Seen-Method"), "GET");
    EXPECT_TRUE(reply.response.header("X-Seen-Content-Encoding").empty());
    EXPECT_TRUE(reply.request.header("Content-Encoding").empty());
    EXPECT_TRUE(reply.request.body().empty());
    EXPECT_TRUE(reply.response.body().empty());
}

TEST(Http1ClientTest, Redirect307308ReplayLogicalBodyWithExactlyOneGzipLayer) {
    LoopbackHttp1Server server;
    const std::string   plain = std::string(2048, 'R') + "redirect-body";
    for (int code : {307, 308}) {
        SCOPED_TRACE(code);
        auto req   = request(qb::http::method::POST, server.url("/redirect/method/" + std::to_string(code)));
        req.body() = plain;
        req.set_header("Content-Encoding", "gzip");
        req.set_header("Content-Type", "application/octet-stream");
        auto reply = request_with_redirects(std::move(req));
        ASSERT_EQ(reply.hops.size(), 1u);
        EXPECT_EQ(reply.hops.front().response.status(), code);
        EXPECT_EQ(reply.response.status(), qb::http::status::OK);
        EXPECT_EQ(reply.response.header("X-Seen-Method"), "POST");
        EXPECT_EQ(reply.response.header("X-Seen-Content-Encoding"), "gzip");
        EXPECT_EQ(reply.response.header("X-Seen-Content-Type"), "application/octet-stream");
        const auto wire = gunzip_reference(reply.response.body().as<std::string>());
        ASSERT_TRUE(wire.has_value());
        EXPECT_EQ(*wire, plain);
        const auto initial  = gunzip_reference(reply.hops.front().request.body().as<std::string>());
        const auto terminal = gunzip_reference(reply.request.body().as<std::string>());
        ASSERT_TRUE(initial.has_value());
        ASSERT_TRUE(terminal.has_value());
        EXPECT_EQ(*initial, plain);
        EXPECT_EQ(*terminal, plain);
    }
}
#endif

TEST(Http1ClientTest, RedirectCrossOriginIsOptInAndNeverRestoresSecretsOnReturn) {
    LoopbackHttp1Server first;
    LoopbackHttp1Server second;
    first.srv->redirect_peer_port.store(second.port);
    second.srv->redirect_peer_port.store(first.port);
    auto make_request = [&] {
        auto req = request(qb::http::method::GET, first.url("/redirect/cross"));
        for (char const *name : {"Authorization", "Proxy-Authorization", "Cookie", "Origin", "Referer"})
            req.set_header(std::string_view{name}, "secret-value");
        req.set_header("Cookie", "header-secret=value");
        req.cookies().add("jar-secret", "value");
        req.set_header("Host", "stale.example:9");
        req.set_header("X-Trace", "retained");
        return req;
    };
    auto stopped = request_with_redirects(make_request());
    EXPECT_EQ(stopped.response.status(), qb::http::status::FOUND);
    EXPECT_TRUE(stopped.hops.empty());
    EXPECT_EQ(second.request_count(), 0);
    auto followed = request_with_redirects(make_request(), {5, true});
    ASSERT_EQ(followed.hops.size(), 2u);
    EXPECT_EQ(followed.response.status(), qb::http::status::OK);
    EXPECT_EQ(first.request_count(), 3);
    EXPECT_EQ(second.request_count(), 1);
    EXPECT_EQ(followed.hops[0].request.header("Authorization"), "secret-value");
    EXPECT_FALSE(followed.hops[0].request.cookies().empty());
    for (char const *name : {"Authorization", "Proxy-Authorization", "Cookie", "Origin", "Referer"}) {
        SCOPED_TRACE(name);
        EXPECT_TRUE(followed.hops[1].request.header(name).empty());
        EXPECT_TRUE(followed.request.header(name).empty());
        EXPECT_TRUE(followed.hops[1].response.header(std::string("X-Seen-") + name).empty());
        EXPECT_TRUE(followed.response.header(std::string("X-Seen-") + name).empty());
    }
    EXPECT_TRUE(followed.hops[1].request.cookies().empty());
    EXPECT_TRUE(followed.request.cookies().empty());
    EXPECT_EQ(followed.hops[1].response.header("X-Seen-Host"), "127.0.0.1:" + std::to_string(second.port));
    EXPECT_EQ(followed.response.header("X-Seen-Host"), "127.0.0.1:" + std::to_string(first.port));
    EXPECT_EQ(followed.request.header("X-Trace"), "retained");
}

TEST(Http1ClientTest, RedirectRefusesInvalidMultipleAndUserinfoLocations) {
    LoopbackHttp1Server server;
    for (char const *kind : {"invalid", "multiple", "userinfo"}) {
        SCOPED_TRACE(kind);
        const auto before = server.request_count();
        auto       reply  = request_with_redirects(request(qb::http::method::GET, server.url(std::string("/redirect/refuse/") + kind)));
        EXPECT_EQ(reply.response.status(), qb::http::status::FOUND);
        EXPECT_TRUE(reply.hops.empty());
        EXPECT_EQ(server.request_count() - before, 1);
    }
}

TEST(Http1ClientTest, RedirectMoveOnlyCallbackIsDeferredAndDeliveredOnce) {
    auto observed = std::make_shared<std::pair<bool, unsigned>>(false, 0u);
    qb::http::GET(
        request(qb::http::method::GET, "ftp://127.0.0.1/resource"),
        [owned = std::make_unique<int>(73), observed](qb::http::async::RedirectReply &&reply) {
            EXPECT_TRUE(observed->first);
            EXPECT_EQ(*owned, 73);
            ++observed->second;
            EXPECT_EQ(reply.response.status(), qb::http::status::BAD_REQUEST);
            EXPECT_TRUE(reply.hops.empty());
        },
        2s, true, qb::http::RedirectOptions{});
    EXPECT_EQ(observed->second, 0u);
    observed->first = true;
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->second != 0; }));
    drain_client_callbacks();
    EXPECT_EQ(observed->second, 1u);
}

TEST(Http1ClientTest, RedirectThrowingFinalCallbackIsContainedOnceAndReleasesCapture) {
    // A dedicated thread gives this lifetime oracle a fresh thread-local listener.
    // No cleanup runs before its final no-work and capture-release assertions.
    std::thread([] {
        qb::io::async::init();
        auto &listener = qb::io::async::listener::current;
        RecordProperty("inherited_active_watchers", listener.loop().active_count());
        RecordProperty("inherited_pending_events", static_cast<int>(listener.loop().pending_count()));
        RecordProperty("inherited_has_deferred", static_cast<int>(listener.has_deferred()));
        RecordProperty("inherited_has_work", static_cast<int>(listener.has_work()));
        ASSERT_FALSE(listener.has_work());
        LoopbackHttp1Server server;
        struct Observation {
            unsigned                                      delivered = 0;
            bool                                          threw     = false;
            bool                                          barrier   = false;
            std::optional<qb::http::async::RedirectReply> reply;
        };
        auto                     observed = std::make_shared<Observation>();
        auto                     capture  = std::make_shared<int>(91);
        const std::weak_ptr<int> released = capture;
        qb::http::GET(
            request(qb::http::method::GET, server.url("/redirect/chain/0")),
            [observed, capture = std::move(capture)](qb::http::async::RedirectReply &&reply) {
                ++observed->delivered;
                EXPECT_EQ(*capture, 91);
                EXPECT_EQ(reply.response.status(), qb::http::status::OK);
                EXPECT_EQ(reply.response.body().as<std::string>(), "chain:3");
                EXPECT_EQ(reply.request.uri().path(), "/redirect/chain/3");
                EXPECT_EQ(reply.hops.size(), 3u);
                if (reply.hops.size() == 3) {
                    for (std::size_t i = 0; i < reply.hops.size(); ++i) {
                        EXPECT_EQ(reply.hops[i].response.status(), qb::http::status::FOUND);
                        EXPECT_EQ(reply.hops[i].request.uri().path(), "/redirect/chain/" + std::to_string(i));
                    }
                }
                observed->reply.emplace(std::move(reply));
                observed->threw = true;
                throw std::runtime_error("owned redirect completion failure");
            },
            qb::duration::zero(), true, qb::http::RedirectOptions{});
        EXPECT_EQ(observed->delivered, 0u);
        EXPECT_FALSE(released.expired());
        // The exception leaves only the user callback; the existing defer drain
        // contains it. Waiting for all client work also completes socket disposal.
        const bool settled = ServerThread<Http1ClientTestServer>::pump_until(
            [&] { return observed->delivered != 0 && released.expired() && !listener.has_work(); });
        RecordProperty("final_delivered", static_cast<int>(observed->delivered));
        RecordProperty("final_capture_expired", static_cast<int>(released.expired()));
        RecordProperty("final_has_work", static_cast<int>(listener.has_work()));
        RecordProperty("final_has_deferred", static_cast<int>(listener.has_deferred()));
        RecordProperty("final_active_watchers", listener.loop().active_count());
        RecordProperty("final_pending_events", static_cast<int>(listener.loop().pending_count()));
        EXPECT_EQ(observed->delivered, 1u);
        EXPECT_TRUE(released.expired()) << "the final completion capture is still owned";
        EXPECT_FALSE(listener.has_work()) << "client work remains after completion";
        ASSERT_TRUE(settled) << "delivered=" << observed->delivered << ", capture_expired=" << released.expired()
                             << ", deferred=" << listener.has_deferred() << ", active=" << listener.loop().active_count()
                             << ", pending=" << listener.loop().pending_count();
        ASSERT_TRUE(observed->reply.has_value());
        EXPECT_TRUE(observed->threw);
        EXPECT_EQ(observed->delivered, 1u);
        EXPECT_EQ(observed->reply->response.status(), qb::http::status::OK);
        EXPECT_EQ(observed->reply->hops.size(), 3u);
        EXPECT_EQ(server.request_count(), 4);

        // An additional real deferred turn must neither retry completion nor send
        // another request. No elapsed-time sleep stands in for this ordering fence.
        qb::io::async::defer([observed] { observed->barrier = true; });
        ASSERT_TRUE(
            ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->barrier && !qb::io::async::listener::current.has_work(); }));
        EXPECT_EQ(observed->delivered, 1u);
        EXPECT_TRUE(released.expired());
        EXPECT_EQ(server.request_count(), 4);
    }).join();
}

TEST(Http1ClientTest, RedirectLocationWithOptionalWhitespaceFollows) {
    LoopbackHttp1Server server;
    auto                reply = request_with_redirects(request(qb::http::method::GET, server.url("/redirect/ows")));
    ASSERT_EQ(reply.hops.size(), 1u);
    EXPECT_EQ(reply.hops.front().response.status(), qb::http::status::FOUND);
    EXPECT_EQ(reply.response.status(), qb::http::status::OK);
    EXPECT_EQ(reply.request.uri().path(), "/redirect/inspect");
    EXPECT_EQ(server.request_count(), 2);
}

#if QB_HAS_SSL
TEST(Http1ClientTest, RedirectHttpsSameOriginHonorsPeerVerification) {
    ASSERT_TRUE(qb::http::test::certs_available())
        << "Missing TLS test resources: " << qb::http::test::ssl_cert_path() << " / " << qb::http::test::ssl_key_path();
    using SecureServer                  = qb::http::ssl::Server<>;
    auto                       requests = std::make_shared<std::atomic<unsigned>>(0);
    const std::string          cert     = qb::http::test::ssl_cert_path().string();
    const std::string          key      = qb::http::test::ssl_key_path().string();
    ServerThread<SecureServer> server([requests, cert, key](SecureServer &srv) {
        auto tls = qb::io::ssl::Context::server(cert, key);
        if (!tls.ok())
            return false;
        srv.transport().init(std::move(tls));
        srv.router().get("/secure-start", [requests](auto ctx) {
            ++*requests;
            ctx->response().status() = qb::http::status::FOUND;
            ctx->response().set_header("Location", "/secure-terminal");
            ctx->complete();
        });
        srv.router().get("/secure-terminal", [requests](auto ctx) {
            ++*requests;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "https-redirect-complete";
            ctx->complete();
        });
        srv.router().compile();
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        srv.start();
        return true;
    });
    ASSERT_TRUE(server.ready());
    ASSERT_NE(server.port(), 0);
    const std::string target = "https://127.0.0.1:" + std::to_string(server.port()) + "/secure-start";

    // The shipped self-signed certificate is not an authenticated loopback peer.
    // Verification must fail before any HTTP route is invoked.
    auto rejected = request_with_redirects(request(qb::http::method::GET, target), {}, true);
    EXPECT_EQ(rejected.response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_TRUE(rejected.hops.empty());
    EXPECT_EQ(requests->load(), 0u);

    // Opt out only for this owned TLS fixture. The relative Location must retain HTTPS.
    auto followed = request_with_redirects(request(qb::http::method::GET, target), {}, false);
    ASSERT_EQ(followed.hops.size(), 1u);
    EXPECT_EQ(followed.hops.front().response.status(), qb::http::status::FOUND);
    EXPECT_EQ(followed.hops.front().request.uri().scheme(), "https");
    EXPECT_EQ(followed.hops.front().request.uri().path(), "/secure-start");
    EXPECT_EQ(followed.response.status(), qb::http::status::OK);
    EXPECT_EQ(followed.response.body().as<std::string>(), "https-redirect-complete");
    EXPECT_EQ(followed.request.uri().scheme(), "https");
    EXPECT_EQ(followed.request.uri().path(), "/secure-terminal");
    EXPECT_EQ(requests->load(), 2u);
}

TEST(Http1ClientTest, RedirectHttpsNeverDowngradesEvenWithCrossOriginOptIn) {
    ASSERT_TRUE(qb::http::test::certs_available())
        << "Missing TLS test resources: " << qb::http::test::ssl_cert_path() << " / " << qb::http::test::ssl_key_path();
    LoopbackHttp1Server plaintext;
    using SecureServer                     = qb::http::ssl::Server<>;
    auto                       requests    = std::make_shared<std::atomic<unsigned>>(0);
    const std::string          cert        = qb::http::test::ssl_cert_path().string();
    const std::string          key         = qb::http::test::ssl_key_path().string();
    const std::string          destination = plaintext.url("/ping");
    ServerThread<SecureServer> server([requests, cert, key, destination](SecureServer &srv) {
        auto tls = qb::io::ssl::Context::server(cert, key);
        if (!tls.ok())
            return false;
        srv.transport().init(std::move(tls));
        srv.router().get("/downgrade", [requests, destination](auto ctx) {
            ++*requests;
            ctx->response().status() = qb::http::status::FOUND;
            ctx->response().set_header("Location", destination);
            ctx->response().body() = "retain-this-redirect";
            ctx->complete();
        });
        srv.router().compile();
        if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        srv.start();
        return true;
    });
    ASSERT_TRUE(server.ready());
    ASSERT_NE(server.port(), 0);
    const std::string target = "https://127.0.0.1:" + std::to_string(server.port()) + "/downgrade";
    auto              reply  = request_with_redirects(request(qb::http::method::GET, target), {5, true}, false);
    EXPECT_EQ(reply.response.status(), qb::http::status::FOUND);
    EXPECT_EQ(reply.response.body().as<std::string>(), "retain-this-redirect");
    EXPECT_EQ(reply.response.header("Location"), destination);
    EXPECT_EQ(reply.request.uri().scheme(), "https");
    EXPECT_EQ(reply.request.uri().path(), "/downgrade");
    EXPECT_TRUE(reply.hops.empty());
    EXPECT_EQ(requests->load(), 1u);
    EXPECT_EQ(plaintext.request_count(), 0);
    EXPECT_EQ(plaintext.connection_count(), 0);
}
#else
TEST(Http1ClientTest, RedirectHttpsWithoutSslCompletesOnceDeferredWithoutNetwork) {
    // A real owned plaintext endpoint is deliberately named with https: a wrong
    // fallback to plaintext would reach /ping, rather than failing at a closed port.
    LoopbackHttp1Server plaintext;
    auto                observed = std::make_shared<std::pair<bool, unsigned>>(false, 0u);
    qb::http::GET(
        request(qb::http::method::GET, "https://127.0.0.1:" + std::to_string(plaintext.port) + "/ping"),
        [observed](qb::http::async::RedirectReply &&reply) {
            EXPECT_TRUE(observed->first);
            ++observed->second;
            EXPECT_EQ(reply.response.status(), qb::http::status::SERVICE_UNAVAILABLE);
            EXPECT_TRUE(reply.hops.empty());
        },
        2s, false, qb::http::RedirectOptions{});
    EXPECT_EQ(observed->second, 0u);
    observed->first = true;
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->second != 0; }));
    drain_client_callbacks();
    EXPECT_EQ(observed->second, 1u);
    EXPECT_EQ(plaintext.request_count(), 0);
    EXPECT_EQ(plaintext.connection_count(), 0);
}
#endif

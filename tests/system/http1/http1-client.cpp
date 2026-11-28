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
 * A case declares what its callbacks write BEFORE its client: a client answers every callback it still holds from its
 * destructor (Huly QB-1246), and a case that fails returns early, so state declared after the client is dead by then.
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
#include <exception>
#include <functional>
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
#include <qb/io/async/lingering_close.h> // detail::closing_sockets(): what this thread's loop is closing after a peer
#include <qb/io/system/sys__socket.h>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"
#include "../../shared/watchdog.h"

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
// the drain already used in DestroyingClientDuringConnectFailsItsCallbackOnce.
inline void
drain_client_callbacks() {
    const auto deadline = std::chrono::steady_clock::now() + 200ms;
    while (std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }
}

// What a case that fails must not leave to the one that follows. A wait that fails returns from the case at once, and a
// client that is destroyed answers every callback it still holds (Huly QB-1246): from the destructor of the case's
// handle -- or, when a hold of the loop's keeps the client beyond that handle, from a later turn of the loop, by
// callbacks whose captures are gone with the case. The three below end a client inside its case. DroppedOnReturn and
// UnheldOnReturn are declared right after the client's handle; DestroyedOnReturn before the handle -- it turns the loop
// once everything declared after it is gone -- and so after everything the client's callbacks capture.

/// For a case one of whose callbacks drops the case's own handle. This gives the handle up first, as `client.reset()`
/// does, so that it is empty when the client is destroyed: the callback its destructor answers then drops nothing. Left
/// to the handle's own destructor, that callback released the client a second time, from inside its destruction.
/// Declared after the handle.
struct DroppedOnReturn {
    std::shared_ptr<qb::http1::Client> &client;
    ~DroppedOnReturn() {
        client.reset();
    }
};

/// For a case that gives up its last reference and waits for the loop to destroy the client, which counts its own end
/// in `destroyed`: when that wait has failed, the loop is turned here until the client is gone. Declared before the
/// handle, so that a handle the case still holds ends first, and with it a client that nothing else keeps.
struct DestroyedOnReturn {
    int const &destroyed;
    ~DestroyedOnReturn() {
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (destroyed == 0 && std::chrono::steady_clock::now() < deadline) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT); // runs the hold that keeps the client
        }
        if (destroyed == 0)
            ADD_FAILURE() << "the client outlived its case: what its callbacks capture is gone";
    }
};

/// For a case that waits right after a callback of its client ran inside a call the case made -- a refusal answered
/// inside a push --, with answers still owed: the hold that callback queued keeps the client one loop turn beyond the
/// case's handle. Once the case has failed, the loop is turned here until that handle is the client's only owner: what
/// is owed is heard while its callbacks still reach the client through the handle, and the end of the handle is then the
/// end of the client. A case that passes ends as it did. Declared after the handle.
struct UnheldOnReturn {
    std::shared_ptr<qb::http1::Client> const &client;
    ~UnheldOnReturn() {
        if (!::testing::Test::HasFailure() && std::uncaught_exceptions() == 0) {
            return; // a case that passes, or did not end by an exception gtest has yet to record
        }
        const auto deadline = std::chrono::steady_clock::now() + 2s;
        while (client.use_count() > 1 && std::chrono::steady_clock::now() < deadline) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        }
        if (client.use_count() > 1)
            ADD_FAILURE() << "the client outlived its case: what its callbacks capture is gone";
    }
};

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
        // The fields a request carried, as the server read them (Huly QB-1191).
        router().get("/fields", [this](auto ctx) {
            ++request_count;
            const auto shown = [&](const char *name) {
                return ctx->request().has_header(name) ? "[" + std::string(ctx->request().header(name)) + "]" : std::string("absent");
            };
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "x-edge=" + shown("x-edge") + " x-blank=" + shown("x-blank") + " x-inside=" + shown("x-inside");
            ctx->complete();
        });

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
        char        buffer[4096];
        bool        ended = false;
        // Each turn waits up to 50 ms for the socket, in select().
        qb::http::test::wait_until([&] { return ended || out.find(marker) != std::string::npos; }, budget, "read_until",
                                   [&] {
                                       fd_set fds;
                                       FD_ZERO(&fds);
                                       FD_SET(_fd, &fds);
                                       timeval    tv{0, 50 * 1000};
                                       const auto ready = ::select(static_cast<int>(_fd) + 1, &fds, nullptr, nullptr, &tv);
                                       if (ready < 0 && errno == EINTR) {
                                           return;
                                       }
                                       if (ready < 0) {
                                           throw std::runtime_error("select failed");
                                       }
                                       if (ready == 0) {
                                           return;
                                       }
                                       const auto n = ::recv(_fd, buffer, static_cast<int>(sizeof(buffer)), 0);
                                       if (n <= 0) {
                                           ended = true;
                                           return;
                                       }
                                       out.append(buffer, static_cast<std::size_t>(n));
                                   });
        return out;
    }

    [[nodiscard]] bool
    closes_within(std::chrono::milliseconds budget) {
        char                c;
        std::optional<bool> closed; // set by the turn that found the socket readable
        qb::http::test::wait_until([&] { return closed.has_value(); }, budget, "closes_within",
                                   [&] {
                                       fd_set fds;
                                       FD_ZERO(&fds);
                                       FD_SET(_fd, &fds);
                                       timeval    tv{0, 50 * 1000};
                                       const auto ready = ::select(static_cast<int>(_fd) + 1, &fds, nullptr, nullptr, &tv);
                                       if (ready > 0) {
                                           closed = ::recv(_fd, &c, 1, MSG_PEEK) == 0;
                                       }
                                   });
        return closed.value_or(false);
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
    std::vector<qb::http::Response> responses;
    auto                            client = qb::http1::make_client(server.url("/"));
    auto                            req    = request(qb::http::method::POST, "/informational");
    req.body()                             = "request-body";
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
    int                 calls = 0;
    qb::http::Response  result;
    auto                client = qb::http1::make_client(server.url("/"));
    client->set_request_timeout(100ms);
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
    bool                connected = false;
    auto                client    = qb::http1::make_client(server.url("/"));

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

    bool            connect_callback_called = false;
    auto            client                  = qb::http1::make_client(server.url("/"));
    DroppedOnReturn dropped{client}; // a case that fails still holds the client: its destructor answers the callback below
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

    bool             response_callback_called = false;
    qb::http::status response_status          = qb::http::status::IM_A_TEAPOT; // before the client, which answers what it still holds
    auto             client                   = qb::http1::make_client(server.url("/"));
    DroppedOnReturn  dropped{client}; // a case that fails still holds the client: its destructor answers the callback below
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

// A response callback that runs the loop, then drops the last reference (Huly QB-1246). What keeps the client alive
// under its connection's handler is a closure in the loop's deferred queue, queued as the callback is entered; a loop
// turn the callback runs drains it while the callback is still on the stack. On a connection that is kept nothing
// queued another: the client was destroyed when the handler returned, and its connection with it, under that
// connection's own read pass (a heap-use-after-free under AddressSanitizer). Two rounds: the first callback runs the
// loop and pushes the next request, so the hold it drained must be counted as gone, not as still queued.
TEST(Http1ClientTest, AResponseCallbackThatRunsTheLoopThenDropsTheLastReferenceLeavesItsConnectionAlive) {
    LoopbackHttp1Server server;

    bool             second_done = false;
    qb::http::status first = qb::http::status::IM_A_TEAPOT, second = qb::http::status::IM_A_TEAPOT;
    const auto       run_the_loop = [] {
        for (int pass = 0; pass < 4; ++pass) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT); // a loop turn of the callback's own: it drains what was deferred
        }
    }; // all before the client, which answers what it still holds when it is destroyed
    auto            client = qb::http1::make_client(server.url("/"));
    auto *const     raw    = client.get(); // what the first callback pushes through: the handle is empty when the destructor answers it
    DroppedOnReturn dropped{client};       // a case that fails still holds the client: its destructor answers the callbacks below
    client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        first = response.status();
        run_the_loop();
        raw->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response next) {
            second = next.status();
            run_the_loop();
            second_done = true;
            client.reset(); // the last reference, on a connection that is kept: no retirement is under way
        });
    });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return second_done; }));
    EXPECT_EQ(first, qb::http::status::OK);
    EXPECT_EQ(second, qb::http::status::OK);
    EXPECT_EQ(client, nullptr);
    drain_client_callbacks(); // the client is destroyed here, once its connection's handler has returned
}

// The same from the callback of a connect(): the connector's completion is not the connection's own handler, and
// the client destroyed there takes nothing from under it. A control: green before and after.
TEST(Http1ClientTest, AConnectCallbackThatRunsTheLoopThenDropsTheLastReferenceEndsCleanly) {
    LoopbackHttp1Server server;

    bool            connected = false, called = false;
    auto            client = qb::http1::make_client(server.url("/"));
    DroppedOnReturn dropped{client}; // a case that fails still holds the client: its destructor answers the callback below
    client->connect([&](bool ok, std::string const &) {
        connected = ok;
        for (int pass = 0; pass < 4; ++pass) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        }
        called = true;
        client.reset();
    });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return called; }));
    EXPECT_TRUE(connected);
    EXPECT_EQ(client, nullptr);
    drain_client_callbacks();
}

// A callback that pushes its request back at every failure -- it never gives up -- is never called from inside its own
// push (Huly QB-1246). With automatic reconnection off and no connection, a push is refused at once: answered inside the
// push when it is made from the program, on the loop's next turn when it is made from one of the client's own
// callbacks. Answered inside there too, the callback was called from inside its own push, again and again, each
// failure one frame deeper (the case stops such a run at 64 so that it fails, and does not overflow its stack). Here
// it hears one failure a loop turn, and ends by itself: at its fiftieth failure automatic reconnection is turned on, and
// the request the callback pushes next -- the fifty-first -- connects and is served. Fifty failures, one answer served.
TEST(Http1ClientTest, ARequestPushedBackAtEveryFailureIsNeverAnsweredFromInsideItsOwnPush) {
    LoopbackHttp1Server server;

    int                   pushes = 0, failures = 0, served = 0, depth = 0, deepest = 0;
    std::function<void()> push;
    auto                  client = qb::http1::make_client(server.url("/"));
    UnheldOnReturn        unheld{client}; // a case whose wait fails returns with a refusal owed, and the client kept for it
    client->set_auto_reconnect(false);
    push = [&] {
        ++pushes;
        client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
            deepest = std::max(deepest, ++depth);
            if (response.status() == qb::http::status::OK) {
                ++served;
            } else {
                if (++failures == 50) {
                    client->set_auto_reconnect(true); // what the callback waited for: its next push connects
                }
                if (deepest < 64) {
                    push(); // always: nothing here counts the attempts
                }
            }
            --depth;
        });
    };
    push();
    EXPECT_EQ(failures, 1) << "a push made from the program is refused inside the push, as before";
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return served != 0 || deepest >= 64; }));
    EXPECT_EQ(served, 1);
    EXPECT_EQ(failures, 50) << "each push is answered once: fifty refusals, then the one that connects";
    EXPECT_EQ(pushes, 51);
    EXPECT_EQ(deepest, 1) << "a request pushed back from its failure callback was answered from inside its own push";
    client->disconnect();
    drain_client_callbacks();
}

// A callback with no share behind it but the hold its entry queued -- the answer of a refusal inside a push the program
// makes, the callback of a connect() on a client that is connected -- may run the loop, which runs that hold, and then
// drop the last reference (Huly QB-1246). The client lives to the end of the call. Here the callback pushes a request
// refused at once, kept for the client's turn, before it runs the loop: that loop turn is the client's turn, and hears
// it, once. The client was destroyed under the callback: its destructor left the kept refusal unheard, and the end of
// the call ran on freed memory. No weak reference is kept here: it would keep the storage.
TEST(Http1ClientTest, ACallbackWithOnlyItsHoldBehindItThatRunsTheLoopThenDropsTheLastReferenceEndsCleanly) {
    struct Told : qb::http1::Client {
        int &destroyed;
        Told(std::string const &url, int &count)
            : qb::http1::Client(url)
            , destroyed(count) {}
        ~Told() {
            ++destroyed;
        }
    };
    for (const std::string_view entry : {"a refusal answered inside the program's push", "a connect() on a connected client"}) {
        SCOPED_TRACE(entry);
        LoopbackHttp1Server   server;
        int                   destroyed = 0, calls = 0, kept_heard = 0;
        bool                  connected = false;   // before the client, which answers what it still holds when it is destroyed
        Told                 *raw       = nullptr; // and so is what its callbacks reach: set once the client is there
        std::function<void()> drop;
        DestroyedOnReturn     ended{destroyed}; // a case whose wait fails returns before the loop has destroyed the client
        auto                  client = std::make_shared<Told>(server.url("/"), destroyed);
        raw                          = client.get();
        drop                         = [&] {
            if (destroyed != 0)
                return; // under the client's destructor (a case that failed): nothing to drop, and no loop to run there
            ++calls;
            raw->push_request(request(qb::http::method::GET, "http://elsewhere.invalid/x"), [&](qb::http::Response) { ++kept_heard; });
            for (int pass = 0; pass < 4; ++pass) {
                qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT); // runs the hold this callback's entry queued
            }
            client.reset(); // the last reference
        };
        if (entry == "a connect() on a connected client") {
            raw->connect([&](bool ok, std::string const &) { connected = ok; });
            ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
            raw->connect([&](bool, std::string const &) { drop(); });
        } else {
            raw->push_request(request(qb::http::method::GET, "http://elsewhere.invalid/x"), [&](qb::http::Response) { drop(); });
        }
        EXPECT_EQ(calls, 1);
        EXPECT_EQ(destroyed, 0) << "the client was destroyed under its own callback";
        EXPECT_EQ(kept_heard, 1) << "the loop turn the callback ran did not hear the refusal the client owed";
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return destroyed != 0; }));
        EXPECT_EQ(kept_heard, 1) << "a refusal kept for the client's turn is heard once, and once only";
        EXPECT_EQ(destroyed, 1);
    }
}

namespace http1_client_order_test {

/// A coroutine that earns a refusal -- kept for the client's turn when it runs under a callback of the client --, then
/// awaits a push of its own, or a batch, and says when it got past it.
qb::io::async::task<void>
refused_then_awaits(qb::http1::Client &client, std::vector<int> &order, int kept, int done, bool batch) {
    client.push_request(request(qb::http::method::GET, "http://elsewhere.invalid/x"),
                        [&order, kept](qb::http::Response) { order.push_back(kept); });
    if (batch) {
        std::vector<qb::http::Request> two;
        two.emplace_back(request(qb::http::method::GET, "/ping"));
        two.emplace_back(request(qb::http::method::GET, "/ping"));
        static_cast<void>(co_await client.push_requests(std::move(two)));
    } else {
        static_cast<void>(co_await client.push_request(request(qb::http::method::GET, "/ping")));
    }
    order.push_back(done);
}

/// The same, awaiting connect(): from a callback of a close it completes `false` at once -- behind what is owed.
qb::io::async::task<void>
refused_then_connects(qb::http1::Client &client, std::vector<int> &order, int kept, int done) {
    client.push_request(request(qb::http::method::GET, "http://elsewhere.invalid/x"),
                        [&order, kept](qb::http::Response) { order.push_back(kept); });
    const auto connected = co_await client.connect();
    order.push_back(connected ? -done : done);
}

} // namespace http1_client_order_test

// The answers come in the order the client came to owe them (Huly QB-1246): one queue, oldest first, heard on the
// client's turn. While a refusal is kept for that turn, every answer that comes after it takes its place behind it --
// the refusal of a push the program makes next, the failures of a disconnect() the same callback calls, the `false` of
// a connect() that close gives up, a coroutine push completed at once. Each of those was given at once, ahead of the
// refusal still waiting for its turn.
TEST(Http1ClientTest, ARefusalKeptIsHeardBeforeAnyAnswerGivenAfterIt) {
    const auto elsewhere = [] {
        return request(qb::http::method::GET, "http://elsewhere.invalid/x");
    }; // refused at once: 400
    {
        SCOPED_TRACE("a refusal of the program's next push");
        std::vector<int>    order; // declared before the client: its destructor may still hear a refusal
        LoopbackHttp1Server server;
        auto                client = qb::http1::make_client(server.url("/"));
        client->push_request(elsewhere(), [&](qb::http::Response) {
            order.push_back(1);
            client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // kept: pushed from a callback
        });
        EXPECT_EQ(order, (std::vector<int>{1}));
        client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(3); }); // behind what is owed
        EXPECT_EQ(order, (std::vector<int>{1})) << "an answer was given inside the push with another one owed before it";
        drain_client_callbacks();
        EXPECT_EQ(order, (std::vector<int>{1, 2, 3}));
    }
    {
        SCOPED_TRACE("the failures of a disconnect() the same callback calls");
        std::vector<int>    order; // declared before the client: its destructor may still hear a refusal
        LoopbackHttp1Server server;
        auto                client = qb::http1::make_client(server.url("/"));
        client->push_request(request(qb::http::method::GET, "/never"), [&](qb::http::Response) { order.push_back(9); }); // in flight
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return client->get_active_request_count() == 1; }));
        client->push_request(elsewhere(), [&](qb::http::Response) {
            order.push_back(1);
            client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // kept
            client->disconnect();                                                               // fails the request in flight
        });
        EXPECT_EQ(order, (std::vector<int>{1})) << "the failure of the close overtook the refusal owed before it";
        drain_client_callbacks();
        EXPECT_EQ(order, (std::vector<int>{1, 2, 9}));
    }
    {
        SCOPED_TRACE("the `false` of a connect() the close gives up");
        std::vector<int>    order; // declared before the client: its destructor may still hear a refusal
        LoopbackHttp1Server server;
        auto                client = qb::http1::make_client(server.url("/"));
        ASSERT_TRUE(client->connect([&](bool ok, std::string const &) {
            EXPECT_FALSE(ok);
            order.push_back(7);
        }));
        client->push_request(elsewhere(), [&](qb::http::Response) {
            order.push_back(1);
            client->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // kept
            client->disconnect();                                                               // gives the connect() up
        });
        EXPECT_EQ(order, (std::vector<int>{1})) << "the callback of the connect() overtook the refusal owed before it";
        drain_client_callbacks();
        EXPECT_EQ(order, (std::vector<int>{1, 2, 7}));
    }
    {
        SCOPED_TRACE("the coroutine pushes a callback of a close completes at once");
        std::vector<int>    order; // declared before the client: its destructor may still hear a refusal
        LoopbackHttp1Server server;
        auto                client = qb::http1::make_client(server.url("/"));
        client->push_request(request(qb::http::method::GET, "/never"), [&](qb::http::Response) { // in flight: fails with the close
            order.push_back(9);
            qb::http::test::watchdog bound("run_sync() of a push from the callback of a close", 10s);
            // Each coroutine earns a refusal (3, then 5), kept for the client's turn, and awaits a push the close completes
            // at once: completed behind that refusal, by a loop turn run_sync() runs, it gets past its await after it.
            qb::io::async::run_sync(http1_client_order_test::refused_then_awaits(*client, order, 3, 10, false));
            qb::io::async::run_sync(http1_client_order_test::refused_then_awaits(*client, order, 5, 11, true));
            // And one that awaits connect(): its `false` at once is an answer the client gives by itself too (7, then 12).
            qb::io::async::run_sync(http1_client_order_test::refused_then_connects(*client, order, 7, 12));
        });
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return client->get_active_request_count() == 1; }));
        client->disconnect();
        EXPECT_EQ(order, (std::vector<int>{9, 3, 10, 5, 11, 7, 12}))
            << "a coroutine push or connect() completed at once overtook the refusal owed before it";
        drain_client_callbacks();
        EXPECT_EQ(order, (std::vector<int>{9, 3, 10, 5, 11, 7, 12}));
    }
}

// An answered request leaves no timer armed (Huly QB-1246). A request that waits in the queue owns the timer of its
// wait, which goes when the request is sent or answered. It was the loop's, and stayed armed for the whole request
// timeout whatever became of the request -- one live watcher for every request that had waited. Two readings of the
// loop's count of watchers with no loop turn between them: two clients alike, each with a request in flight, one with
// ten more queued behind it, are disconnected one after the other; the second gives back ten watchers more. And ten
// requests that waited, were sent and were served leave the count no higher than it was (loop turns passed there: a
// timer of an earlier case may have expired, none been added).
TEST(Http1ClientTest, AnAnsweredRequestLeavesNoTimerArmed) {
    const auto watchers = [] {
        return static_cast<std::ptrdiff_t>(qb::io::async::listener::current.size());
    };
    {
        SCOPED_TRACE("answered by a close");
        int                         answers = 0; // declared before the clients: their destructors may still answer
        std::vector<std::ptrdiff_t> seen;        // the count as each callback reads it
        LoopbackHttp1Server         server;
        const auto                  in_flight = [&](int queued) {
            auto client = qb::http1::make_client(server.url("/"));
            for (int i = 0; i < 1 + queued; ++i) {
                client->push_request(request(qb::http::method::GET, "/never"), [&](qb::http::Response) {
                    ++answers;
                    seen.push_back(watchers());
                });
            }
            EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return client->get_active_request_count() == 1; }));
            return client;
        };
        auto       alone  = in_flight(0);
        auto       queued = in_flight(10);
        const auto first  = watchers();
        alone->disconnect();
        const auto second = watchers();
        seen.clear();
        queued->disconnect();
        const auto third = watchers();
        EXPECT_EQ(answers, 12);
        EXPECT_EQ((second - third) - (first - second), 10) << "the requests a close answered left the timers of their wait armed";
        ASSERT_EQ(seen.size(), 11u);
        EXPECT_EQ(seen, std::vector<std::ptrdiff_t>(11, seen.front())) << "a request was still timed while the callback of another ran";
        drain_client_callbacks();
    }
    {
        SCOPED_TRACE("sent, then served");
        int                 served       = 0;
        bool                first_served = false; // before the client, which answers what it still holds when it is destroyed
        LoopbackHttp1Server server;
        auto                client = qb::http1::make_client(server.url("/"));
        client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) { ++served; }); // connects
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return served == 1; }));
        {
            // A request that waited and is then sent is timed by its connection alone: its own timer stops there.
            const auto idle = watchers();
            client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) { first_served = true; });
            client->push_request(request(qb::http::method::GET, "/never"), [](qb::http::Response) {}); // waits, then is sent
            EXPECT_EQ(watchers(), idle + 1);
            ASSERT_TRUE(
                ServerThread<Http1ClientTestServer>::pump_until([&] { return first_served && client->get_active_request_count() == 1; }));
            EXPECT_LE(watchers(), idle) << "a request that was sent kept the timer of its wait";
            client->disconnect(); // answers the one in flight
            drain_client_callbacks();
            served = 0;
            client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) { ++served; }); // connects again
            ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return served == 1; }));
        }
        const auto before = watchers();
        for (int i = 0; i < 10; ++i) { // one is sent at once, nine wait for it
            client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
                EXPECT_EQ(response.status(), qb::http::status::OK);
                ++served;
            });
        }
        EXPECT_EQ(watchers(), before + 9) << "a request that waits is timed, one that is sent at once is not";
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return served == 11; }));
        EXPECT_LE(watchers(), before) << "the requests that waited, then were served, left the timers of their wait armed";
        client->disconnect();
        drain_client_callbacks();
    }
#ifdef QB_HAS_SSL
    {
        // The wait itself: no case made a queued request time out. The peer completes the TCP handshake and answers
        // nothing, so the TLS handshake lasts and the requests wait behind it for their timeout.
        SCOPED_TRACE("answered by the timeout of its wait");
        std::vector<std::ptrdiff_t> seen; // the count as each callback reads it
        std::vector<std::string>    said;
        qb::io::tcp::listener       silent;
        ASSERT_EQ(silent.listen_v4(0, "127.0.0.1"), qb::io::SocketStatus::Done);
        auto client = qb::http1::make_client("https://127.0.0.1:" + std::to_string(silent.local_endpoint().port()));
        client->set_verify_peer(false);
        client->set_connect_timeout(5s);
        client->set_request_timeout(200ms);
        const auto began = std::chrono::steady_clock::now();
        for (int i = 0; i < 3; ++i) {
            client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
                EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT);
                said.push_back(response.body().as<std::string>());
                seen.push_back(watchers());
            });
        }
        const auto armed = watchers(); // the three timers of the three waits
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return seen.size() == 3; }));
        EXPECT_GE(std::chrono::steady_clock::now() - began, 150ms);
        EXPECT_EQ(said, std::vector<std::string>(3, "HTTP/1.1 request timeout while pending"));
        // Loop turns passed since `armed` was read, so only an upper bound: its own timer is stopped before each answer.
        EXPECT_LE(seen[0], armed - 1) << "the timer of a wait was still armed when its request heard its timeout";
        EXPECT_LE(seen[2], armed - 3);
        client->disconnect();
        drain_client_callbacks();
    }
#endif
}

// A request the client refuses leaves no timer behind (Huly QB-1246). One with nothing to connect for it -- automatic
// reconnection off, no connection -- was queued, timed, then failed with the queue: the timer of its wait stayed armed
// for the request timeout, one for each push of a callback that pushes back at every failure. And one refused where it
// is sent was timed for a wait it never had. The loop's count of watchers is the same after twenty of each.
TEST(Http1ClientTest, ARequestRefusedAtOnceLeavesNoTimerBehind) {
    for (const std::string_view kind : {"nothing connects for it", "cannot be written"}) {
        SCOPED_TRACE(kind);
        LoopbackHttp1Server server;
        int                 refused   = 0;
        bool                connected = false; // before the client, which answers what it still holds when it is destroyed
        auto                client    = qb::http1::make_client(server.url("/"));
        if (kind == "cannot be written") { // refused where it is sent: on a connection
            client->connect([&](bool ok, std::string const &) { connected = ok; });
            ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
        } else {
            client->set_auto_reconnect(false);
        }
        const auto before = qb::io::async::listener::current.size();
        for (int i = 0; i < 20; ++i) {
            auto pushed = request(qb::http::method::POST, "/echo");
            if (kind == "cannot be written") {
                pushed.body() = "too-long";
                pushed.set_header("Content-Length", "1");
            }
            client->push_request(std::move(pushed), [&](qb::http::Response response) {
                EXPECT_NE(response.status(), qb::http::status::OK);
                ++refused;
            });
        }
        EXPECT_EQ(refused, 20);
        EXPECT_EQ(qb::io::async::listener::current.size(), before) << "a refused request left a timer armed";
        client->disconnect();
        drain_client_callbacks();
    }
}

// Every refusal known at once goes the same way (Huly QB-1246): a request for another origin (400), one past the
// pending bound (503) and one that cannot be written to the connection (400) are answered inside the push the program
// makes, and on the loop's next turn when the push is made from the callback of the one before. Each kind is pushed
// back twenty times: never nested.
TEST(Http1ClientTest, ARefusalKnownAtOnceOfARequestPushedFromACallbackWaitsATurn) {
    for (const std::string_view kind : {"another origin", "past the pending bound", "cannot be written"}) {
        SCOPED_TRACE(kind);
        LoopbackHttp1Server   server;
        int                   pushes = 0, failures = 0, depth = 0, deepest = 0;
        std::function<void()> push;
        bool                  connected = false; // before the client, which answers what it still holds when it is destroyed
        auto                  client    = qb::http1::make_client(server.url("/"));
        UnheldOnReturn        unheld{client}; // a case whose wait fails returns with a refusal owed, and the client kept for it
        if (kind == "cannot be written") {    // refused where it is sent: on a connection
            client->connect([&](bool ok, std::string const &) { connected = ok; });
            ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
        }
        if (kind == "past the pending bound") {
            client->set_max_pending_requests(0);
        }
        push = [&] {
            ++pushes;
            auto refused = request(qb::http::method::POST, kind == "another origin" ? "http://elsewhere.invalid/echo" : "/echo");
            if (kind == "cannot be written") {
                refused.body() = "too-long";
                refused.set_header("Content-Length", "1");
            }
            client->push_request(std::move(refused), [&](qb::http::Response response) {
                deepest = std::max(deepest, ++depth);
                EXPECT_NE(response.status(), qb::http::status::OK);
                if (++failures < 20) {
                    push();
                }
                --depth;
            });
        };
        push();
        EXPECT_EQ(failures, 1) << "a push made from the program is refused inside the push";
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return failures == 20; }));
        EXPECT_EQ(pushes, 20);
        EXPECT_EQ(deepest, 1) << "a refusal of a request pushed from a callback was answered from inside its push";
        client->disconnect();
        drain_client_callbacks();
    }
}

// A refusal kept for the client's turn is heard by that turn wherever the loop runs it (Huly QB-1246): a loop turn the
// callback that earned it runs is one, so a coroutine that callback waits for with run_sync() completes. Heard there
// once, and not again when the callback has returned.
TEST(Http1ClientTest, ARefusalKeptForItsTurnIsHeardOnceByALoopTurnItsCallbackRuns) {
    int  heard = 0, heard_inside_the_push = -1, heard_under_the_callback = -1;
    bool outer  = false;
    auto client = qb::http1::make_client("http://127.0.0.1:1");
    client->set_max_pending_requests(0); // every push is refused at once
    client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) {
        client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) { ++heard; });
        heard_inside_the_push = heard;
        for (int pass = 0; pass < 4; ++pass) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        }
        heard_under_the_callback = heard;
        outer                    = true;
    });
    ASSERT_TRUE(outer) << "a push made from the program is refused inside the push";
    EXPECT_EQ(heard_inside_the_push, 0) << "a refusal of a push made from a callback was heard inside the push";
    EXPECT_EQ(heard_under_the_callback, 1) << "the loop turns the callback ran did not hear the refusal kept for the client's turn";
    drain_client_callbacks();
    EXPECT_EQ(heard, 1) << "a refusal kept for the client's turn is heard once, and once only";
}

// A refusal kept for the next turn is heard exactly once when no turn comes (Huly QB-1246): the loop ends with it still
// owed -- the thread exits, its deferred queue dropped --, the hold that kept the client goes with the queue, and the
// client's destructor delivers the refusal, once.
TEST(Http1ClientTest, ARefusalKeptForATurnThatNeverComesIsHeardOnceFromTheDestructor) {
    int outer = 0, kept = 0;
    std::thread([&] {
        qb::io::async::init();
        auto client = qb::http1::make_client("http://127.0.0.1:1");
        client->set_max_pending_requests(0); // every push is refused at once
        client->push_request(request(qb::http::method::GET, "/ping"), [&, raw = client.get()](qb::http::Response) {
            ++outer;
            raw->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) { ++kept; }); // kept for the next turn
        });
        EXPECT_EQ(outer, 1);
        EXPECT_EQ(kept, 0) << "a refusal of a push made from a callback was heard inside the push";
        // Deliberately no turn of the loop.
    }).join();
    EXPECT_EQ(kept, 1) << "a refusal still owed its turn when its client is destroyed is heard once";
}

// The same at the client's destruction, where no later turn exists (Huly QB-1246): a request pushed from a callback the
// destructor runs is answered inside its push, and one pushed from inside THAT answer is refused by the return value
// alone, its callback destroyed unheard -- as connect() is refused there. A callback that always pushes again then
// ends: three pushes, two answers, never deeper than two. It was answered inside each push, without end.
TEST(Http1ClientTest, ARequestPushedBackFromTheDestructorsCallbacksEndsAtItsSecondPush) {
    LoopbackHttp1Server server;

    int                   pushes = 0, answers = 0, depth = 0, deepest = 0;
    std::vector<bool>     accepted;
    qb::http1::Client    *raw = nullptr;
    std::function<void()> push;
    push = [&] {
        const auto index = static_cast<std::size_t>(pushes++); // a push returns after the ones its callback makes
        accepted.resize(index + 1);
        accepted[index] = raw->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
            deepest = std::max(deepest, ++depth);
            ++answers;
            EXPECT_NE(response.status(), qb::http::status::OK);
            if (deepest < 64) {
                push();
            }
            --depth;
        });
    };
    {
        auto client = qb::http1::make_client(server.url("/"));
        raw         = client.get();
        push(); // queued behind the connection it asked for
        ASSERT_TRUE(client->is_connecting());
    } // destroyed with that request waiting
    drain_client_callbacks();
    EXPECT_EQ(pushes, 3);
    EXPECT_EQ(answers, 2);
    EXPECT_EQ(deepest, 2);
    EXPECT_EQ(accepted, (std::vector<bool>{true, true, false}));
}

// An answer the client gives by itself waits for the client's turn under any callback of this client, with nothing owed
// too (Huly QB-1246): given inside the call, the callback of a `connect()` or of an empty batch ran under the callback
// that made the call.
TEST(Http1ClientTest, AnAnswerTheClientGivesByItselfIsNotGivenUnderACallbackOfThisClient) {
    for (const std::string_view call : {"an empty batch", "a connect() on a connected client"}) {
        SCOPED_TRACE(call);
        LoopbackHttp1Server server;
        int                 heard = 0, heard_inside_the_call = -1; // before the client: its callbacks count here
        bool                connected = false;
        auto                client    = qb::http1::make_client(server.url("/"));
        client->connect([&](bool ok, std::string const &) { connected = ok; });
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
        client->push_request(request(qb::http::method::GET, "http://elsewhere.invalid/x"), [&](qb::http::Response) {
            // Answered inside the program's push: one callback of this client on the stack, and nothing owed.
            if (call == "an empty batch") {
                EXPECT_TRUE(client->push_requests({}, [&](std::vector<qb::http::Response>) { ++heard; }));
            } else {
                EXPECT_TRUE(client->connect([&](bool, std::string const &) { ++heard; }));
            }
            heard_inside_the_call = heard;
        });
        EXPECT_EQ(heard_inside_the_call, 0) << "an answer the client gives by itself was given under a callback of this client";
        drain_client_callbacks();
        EXPECT_EQ(heard, 1);
        client->disconnect();
        drain_client_callbacks();
    }
}

// The failures of a disconnect() are answers the client gives by itself, as a cancellation's is: the program asked for
// them (Huly QB-1246). Called from a callback of this client, disconnect() gives them on the client's turn -- the
// failure of a request, the answer of a batch, the `false` of a connect() still waiting --; called with no callback on
// the stack and nothing owed, inside the call, as before. They were the loop's answers, given inside the call whoever
// made it -- 3.3.0 gave them so too --: an answer of the client ran inside another with no loop turn of the program's.
TEST(Http1ClientTest, TheFailuresOfADisconnectACallbackCallsAreHeardOnTheClientsTurn) {
    for (const std::string_view what : {"a request in flight", "a batch in flight", "a connect() still waiting"}) {
        SCOPED_TRACE(what);
        LoopbackHttp1Server server;
        int                 heard = 0, heard_inside_the_call = -1; // before the client: its callbacks count here
        auto                client = qb::http1::make_client(server.url("/"));
        const auto          start  = [&] {
            if (what == "a request in flight") {
                client->push_request(request(qb::http::method::GET, "/never"), [&](qb::http::Response) { ++heard; });
            } else if (what == "a batch in flight") {
                std::vector<qb::http::Request> two;
                two.push_back(request(qb::http::method::GET, "/never"));
                two.push_back(request(qb::http::method::GET, "/never"));
                client->push_requests(std::move(two), [&](std::vector<qb::http::Response> responses) {
                    EXPECT_EQ(responses.size(), 2u);
                    ++heard;
                });
            } else {
                EXPECT_TRUE(client->connect([&](bool ok, std::string const &) {
                    EXPECT_FALSE(ok);
                    ++heard;
                }));
            }
        };
        start();
        if (what != "a connect() still waiting") {
            ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return client->get_active_request_count() == 1; }));
        }
        client->push_request(request(qb::http::method::GET, "http://elsewhere.invalid/x"), [&](qb::http::Response) { // answered inside the push
            client->disconnect();
            heard_inside_the_call = heard;
        });
        EXPECT_EQ(heard_inside_the_call, 0) << "an answer of a disconnect() was heard under the callback that called it";
        EXPECT_EQ(heard, 0);
        drain_client_callbacks();
        EXPECT_EQ(heard, 1);
        start(); // and with no callback on the stack and nothing owed: inside the call
        if (what != "a connect() still waiting") {
            ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return client->get_active_request_count() == 1; }));
        }
        client->disconnect();
        EXPECT_EQ(heard, 2) << "the program's own disconnect() did not answer inside the call";
        drain_client_callbacks();
    }
}

// A callback that pushes its request back at every failure and then calls disconnect() is never called under itself
// (Huly QB-1246). The request it has just pushed is accepted, for the next connection, and its disconnect() ends it:
// that failure is the client's own answer, heard on the client's turn. Given inside the disconnect(), the callback was
// called from inside the call it had just made, one frame deeper at every failure -- a hundred deep, where the case
// stops it, all of it inside the one disconnect() the program made, with no loop turn of the program's anywhere.
TEST(Http1ClientTest, ARequestPushedBackThenADisconnectFromItsCallbackIsNeverCalledUnderItself) {
    LoopbackHttp1Server   server;
    int                   calls = 0, pushes = 0, depth = 0, deepest = 0, calls_inside_the_programs_disconnect = -1; // before the client
    const int             cap = 100;
    std::function<void()> push; // before the client too: its callbacks call it
    auto                  client = qb::http1::make_client(server.url("/"));
    UnheldOnReturn        unheld{client}; // a case whose wait fails returns with a failure owed, and the client kept for it
    push = [&] {
        ++pushes;
        client->push_request(request(qb::http::method::GET, "/never"), [&](qb::http::Response response) {
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
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return client->get_active_request_count() == 1; }));
    client->disconnect(); // the program's own: its request in flight fails inside this call
    calls_inside_the_programs_disconnect = calls;
    EXPECT_EQ(calls_inside_the_programs_disconnect, 1)
        << "the failures of the disconnect() its callback called were heard inside the program's";
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return calls == cap; }));
    drain_client_callbacks();
    EXPECT_EQ(calls, cap);
    EXPECT_EQ(pushes, cap) << "every push is answered once";
    EXPECT_EQ(deepest, 1) << "the callback was called from inside a disconnect() it made";
}

// The other order, with ten requests: every failure callback resets the connection, then pushes its request back --
// disconnect(), then push. One request is in flight and nine are queued behind it; the program calls disconnect() once.
// Each of the ten is failed once, one deep. Each disconnect() a callback makes ends the request the callback before it
// pushed back, and that failure waits for the client's turn, as every answer after it does. Given inside the call, each nested
// close ran the retries of the ones before it: 1023 calls inside the program's disconnect(), ten deep (Huly QB-1246).
TEST(Http1ClientTest, TenRequestsThatEachResetTheConnectionAndRetryAreEachFailedOnceAndOneDeep) {
    LoopbackHttp1Server   server;
    int                   calls = 0, heard = 0, pushes = 0, depth = 0, deepest = 0; // before the client
    bool                  stop = false;
    std::function<void()> push; // before the client too: its callbacks call it
    auto                  client = qb::http1::make_client(server.url("/"));
    push                         = [&] {
        ++pushes;
        client->push_request(request(qb::http::method::GET, "/never"), [&](qb::http::Response response) {
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
        push(); // the first is written at once, nine wait behind it
    }
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return client->get_active_request_count() == 1; }));
    client->disconnect(); // the program's own
    // Two inside the call, each one deep: the second callback's disconnect() ends the retry of the first, whose failure is
    // then owed, and the eight other requests' failures take their place behind it.
    EXPECT_EQ(calls, 2) << "a failure was heard inside the program's disconnect() with another one owed before it";
    EXPECT_EQ(deepest, 1);
    stop = true; // what is still owed is heard, and pushes nothing back
    drain_client_callbacks();
    client->disconnect(); // ends the last request pushed back
    drain_client_callbacks();
    EXPECT_EQ(pushes, 12) << "the ten requests, and the retries of the two heard before the program stopped";
    EXPECT_EQ(heard, 12) << "every push is answered once";
    EXPECT_EQ(deepest, 1);
}

// An answer the client gives by itself is given inside the call while the client is destroyed, where no turn is left to
// keep it for (Huly QB-1246): an empty batch pushed from a callback the destructor runs.
TEST(Http1ClientTest, AnEmptyBatchPushedFromACallbackTheDestructorRunsIsAnsweredInsideThePush) {
    LoopbackHttp1Server server;
    int                 answers = 0, batches = 0, batches_inside_the_push = -1;
    {
        auto client = qb::http1::make_client(server.url("/"));
        client->push_request(request(qb::http::method::GET, "/ping"), [&, raw = client.get()](qb::http::Response) { // fails with the client
            ++answers;
            EXPECT_TRUE(raw->push_requests({}, [&](std::vector<qb::http::Response> responses) {
                EXPECT_TRUE(responses.empty());
                ++batches;
            }));
            batches_inside_the_push = batches;
        });
        ASSERT_TRUE(client->is_connecting()); // queued behind the connection it asked for
    } // destroyed with that request waiting
    drain_client_callbacks();
    EXPECT_EQ(answers, 1);
    EXPECT_EQ(batches_inside_the_push, 1) << "an answer was kept for a turn that a client being destroyed does not have";
    EXPECT_EQ(batches, 1);
}

// Two refusals owed their turn when the client is destroyed with no turn left (Huly QB-1246): the destructor hears
// both, in order and alike. Each is a callback the destructor runs, so the request each pushes back is answered inside
// that push, 503, and accepted. The second was heard from inside the answer of the push the first one made: the push
// of its own callback was refused by the return value alone, and never answered.
TEST(Http1ClientTest, TwoRefusalsOwedWhenTheClientIsDestroyedAreHeardAlike) {
    int               outer = 0, kept = 0, answers = 0;
    std::vector<int>  order;
    std::vector<bool> accepted;
    std::thread([&] {
        qb::io::async::init();
        auto client = qb::http1::make_client("http://127.0.0.1:1");
        client->set_max_pending_requests(0); // every push is refused at once
        client->push_request(request(qb::http::method::GET, "/ping"), [&, raw = client.get()](qb::http::Response) {
            ++outer;
            for (int i = 1; i <= 2; ++i) {
                raw->push_request(request(qb::http::method::GET, "/ping"), [&, raw, i](qb::http::Response) { // kept for the client's turn
                    ++kept;
                    order.push_back(i);
                    accepted.push_back(raw->push_request(request(qb::http::method::GET, "/ping"), [&, i](qb::http::Response response) {
                        EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
                        ++answers;
                        order.push_back(10 * i);
                    }));
                });
            }
        });
        EXPECT_EQ(outer, 1);
        EXPECT_EQ(kept, 0) << "a refusal of a push made from a callback was heard inside the push";
        // Deliberately no turn of the loop.
    }).join();
    EXPECT_EQ(kept, 2);
    EXPECT_EQ(answers, 2) << "a push made from a callback the destructor runs was not answered";
    EXPECT_EQ(accepted, (std::vector<bool>{true, true}));
    EXPECT_EQ(order, (std::vector<int>{1, 10, 2, 20})) << "each refusal owed, then the answer of the push its callback made";
}

namespace http1_client_lifetime_test {

/// A client that tells when it is destroyed.
struct Told : qb::http1::Client {
    int &destroyed;
    Told(std::string const &url, int &count)
        : qb::http1::Client(url)
        , destroyed(count) {}
    ~Told() {
        ++destroyed;
    }
};

} // namespace http1_client_lifetime_test

// A callback the destructor hears -- the answer of what is still owed when the client is destroyed -- may run the loop
// (Huly QB-1246). The turn that was asked for that answer is still in the loop's queue, and the loop the callback runs
// may reach it: it finds no client to hear for, and touches nothing. What the callback pushes then is answered as from
// any callback the destructor runs: inside the push, and by the return value alone from inside that answer. And a
// response on its way when the client is destroyed may come in that loop: its request hears once, the response or the
// close. The client is owned apart from its control block, so that a sanitizer sees the object freed. On HTTP/1.1 the
// client is destroyed by the loop turn that runs its last hold, so the callback runs the loop from inside the loop's
// pass over its queue: only a loop whose pass nests reaches the turn that was asked from there.
TEST(Http1ClientTest, ACallbackTheDestructorHearsThatRunsTheLoopEndsCleanly) {
    using http1_client_lifetime_test::Told;
    const auto elsewhere = [] {
        return request(qb::http::method::GET, "http://elsewhere.invalid/x");
    }; // refused at once
    const auto ping = [] {
        return request(qb::http::method::GET, "/ping");
    };
    for (const std::string_view with : {"nothing else under way", "a response on its way"}) {
        SCOPED_TRACE(with);
        LoopbackHttp1Server   server;
        int                   destroyed = 0, kept = 0, answers = 0, first = 0;      // before the client: its callbacks count here
        int                   destroyed_when_heard = -1;                            // 1: heard by the destructor, the object's end begun
        int                   second = 0, second_under_the_first = 0, in_first = 0; // a second answer owed behind the first
        std::vector<bool>     accepted;
        bool                  connected = false; // before the client too
        DestroyedOnReturn     ended{destroyed};  // a case whose wait fails returns before the loop has destroyed the client
        std::shared_ptr<Told> client(new Told(server.url("/"), destroyed));
        auto *const           raw = client.get();
        if (with == "a response on its way") {
            raw->connect([&](bool ok, std::string const &) { connected = ok; });
            ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
            raw->push_request(ping(), [&](qb::http::Response) { ++first; }); // written at once: in flight
        }
        const auto heard_by_the_destructor = [&, raw](qb::http::Response) {
            ++kept;
            in_first             = 1;
            destroyed_when_heard = destroyed;
            const auto until     = std::chrono::steady_clock::now() + 100ms;
            while (std::chrono::steady_clock::now() < until) {
                qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT); // the turn that was asked may run here, and what the connection brings
            }
            const bool outer = raw->push_request(ping(), [&, raw](qb::http::Response response) {
                EXPECT_EQ(response.status(), qb::http::status::SERVICE_UNAVAILABLE);
                ++answers;
                accepted.push_back(raw->push_request(ping(), [&](qb::http::Response) { ++answers; }));
            });
            accepted.push_back(outer);
            in_first = 0;
        };
        raw->push_request(elsewhere(), [&, raw](qb::http::Response) { // answered inside the program's push
            raw->push_request(elsewhere(), heard_by_the_destructor);  // kept for the client's turn: the destructor's, here
            raw->push_request(elsewhere(), [&](qb::http::Response) {  // kept behind it: the destructor's too, once the first has returned
                ++second;
                second_under_the_first += in_first;
            });
        });
        EXPECT_EQ(kept, 0) << "a refusal of a push made from a callback was heard inside the push";
        // The program's last reference. The hold the callback above left in the loop's queue keeps the client to the next
        // loop turn, which runs that hold ahead of the turn that was asked: the client is destroyed there, inside the
        // loop's own pass over its queue, and the callback it hears runs the loop from inside that pass.
        client.reset();
        EXPECT_EQ(destroyed, 0);
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return destroyed != 0; }));
        EXPECT_EQ(kept, 1);
        EXPECT_EQ(destroyed_when_heard, 1) << "the answer owed was not heard by the destructor: the case shows nothing";
        EXPECT_EQ(answers, 1)
            << "a push made from a callback the destructor runs is answered inside it; one made from inside that answer is not";
        EXPECT_EQ(accepted, (std::vector<bool>{false, true}));
        EXPECT_EQ(second, 1) << "the second answer owed is heard once";
        EXPECT_EQ(second_under_the_first, 0) << "the turn that was asked heard for a client being destroyed, inside the loop its callback ran";
        drain_client_callbacks();
        EXPECT_EQ(kept, 1) << "the turn that was asked heard for a client that is gone";
        EXPECT_EQ(second, 1);
        EXPECT_EQ(answers, 1);
        EXPECT_EQ(first, with == "a response on its way" ? 1 : 0) << "the request in flight when the client was destroyed hears once";
    }
}

namespace http1_client_relaunch_test {

/// A callback that pushes its request back at every refusal -- it never gives up -- and then does one thing more.
struct Relaunch {
    int                                pushes = 0, calls = 0, depth = 0, deepest = 0, cap = 200;
    int                                loop_turns         = 0; ///< the loop turns this callback is running, one inside the other
    int                                deepest_loop_turns = 0; ///< the most of them a call found on the stack
    int                                under_another      = 0; ///< calls made under another one with no such turn between the two
    std::function<void()>              then;                   ///< what the callback does once it has pushed its request back
    std::shared_ptr<qb::http1::Client> client;                 ///< last, so destroyed first: it answers what it still holds, `then` still there

    void
    push() {
        ++pushes;
        client->push_request(request(qb::http::method::GET, "http://elsewhere.invalid/x"), [this](qb::http::Response response) {
            EXPECT_EQ(response.status(), qb::http::status::BAD_REQUEST);
            deepest            = std::max(deepest, ++depth);
            deepest_loop_turns = std::max(deepest_loop_turns, loop_turns);
            under_another += depth != loop_turns + 1;
            if (++calls < cap) {
                push(); // refused at once -- another origin --, and kept for the client's turn: pushed from a callback
                then();
            }
            --depth;
        });
    }

    void
    run_the_loop() {
        ++loop_turns;
        for (int pass = 0; pass < 4; ++pass) {
            qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        }
        --loop_turns;
    }
};

} // namespace http1_client_relaunch_test

// A callback that pushes its request back at every refusal, and then makes a call the client answers by itself -- an
// empty batch, a connect() on a client that is connected --, is never called under itself (Huly QB-1246). Such an
// answer takes its place behind the refusal kept for the client's turn. Given inside the call, it heard that refusal
// first: the callback was called from inside the call it had just made, one frame deeper at every refusal -- two
// hundred deep here, all of them inside the push the program made.
TEST(Http1ClientTest, ARequestPushedBackThenACallTheClientAnswersByItselfIsNeverAnsweredUnderItsCallback) {
    using http1_client_relaunch_test::Relaunch;
    for (const std::string_view call : {"an empty batch", "a connect() on a connected client"}) {
        SCOPED_TRACE(call);
        LoopbackHttp1Server server;
        int                 answered = 0, answered_under_the_callback = 0; // before the client: its callbacks count here
        bool                connected = false;                             // before the client too
        Relaunch            r;
        r.client = qb::http1::make_client(server.url("/"));
        UnheldOnReturn unheld{r.client}; // a case whose wait fails returns with answers owed, and the client kept for them
        if (call == "an empty batch") {
            r.then = [&] {
                EXPECT_TRUE(r.client->push_requests({}, [&](std::vector<qb::http::Response> responses) {
                    EXPECT_TRUE(responses.empty());
                    ++answered;
                    answered_under_the_callback += r.depth != 0;
                }));
            };
        } else {
            r.client->connect([&](bool ok, std::string const &) { connected = ok; });
            ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
            r.then = [&] {
                EXPECT_TRUE(r.client->connect([&](bool ok, std::string const &) {
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
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return r.calls == r.cap; }));
        drain_client_callbacks();
        EXPECT_EQ(r.calls, 200);
        EXPECT_EQ(r.pushes, 200) << "every push is answered once";
        EXPECT_EQ(answered, 199) << "one for each call that pushed back";
        EXPECT_EQ(answered_under_the_callback, 0);
        EXPECT_EQ(r.deepest, 1) << "the callback was called from inside a call it made";
        r.client->disconnect();
        drain_client_callbacks();
    }
}

// The same callback while ten other requests of the client time out in the queue, in two shapes (Huly QB-1246).
// Returning once it has pushed back, it is never called inside another call of this client: every call is exactly one
// deep, whatever the loop brings in between -- the ten timeouts, and the refusals that keep coming. Running the loop
// itself once it has pushed back -- qb::io::async::run() here; run_once(), run_until() and run_sync() are such turns
// too --, it receives inside that loop whatever the client owes, the refusal it has just earned included: it recurses
// once for each refusal, and that recursion is the program's. So that shape checks an invariant, not a depth: every
// call finds on the stack the loop turns this callback is itself running, and one call more. The invariant also held
// on the code before the one queue, whose nesting went through the same loop turns: this is no witness of what
// changed -- the shapes that run no loop are. Every push is answered once in both shapes: the ten the timeouts make,
// and one for each call before the sixtieth.
TEST(Http1ClientTest, ARequestPushedBackWhileOthersTimeOutIsCalledUnderItselfOnlyThroughTheLoopTurnsItsCallbackRuns) {
    using http1_client_relaunch_test::Relaunch;
    for (const bool runs_the_loop : {false, true}) {
        SCOPED_TRACE(runs_the_loop ? "the callback runs the loop" : "the callback returns");
        LoopbackHttp1Server server;
        int                 timed_out = 0; // before the client: its callbacks count here
        Relaunch            r;
        r.client = qb::http1::make_client(server.url("/"));
        r.cap    = 60;
        r.then   = [&] {
            if (runs_the_loop) {
                r.run_the_loop();
            }
        };
        r.client->set_request_timeout(30s);
        r.client->push_request(request(qb::http::method::GET, "/never"), [](qb::http::Response) {}); // in flight: it keeps the connection
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return r.client->get_active_request_count() == 1; }));
        r.client->set_request_timeout(150ms);
        for (int i = 0; i < 10; ++i) { // queued behind it: each times out in the queue
            r.client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
                EXPECT_EQ(response.status(), qb::http::status::REQUEST_TIMEOUT);
                ++timed_out; // runs no loop turn, and is not counted in the depth: the callback that pushes back is
                r.push();
            });
        }
        ASSERT_TRUE(
            ServerThread<Http1ClientTestServer>::pump_until([&] { return timed_out == 10 && r.calls == r.pushes && r.calls >= r.cap; }));
        drain_client_callbacks();
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
        drain_client_callbacks();
    }
}

TEST(Http1ClientTest, ResponseCallbackMayDisconnectClient) {
    LoopbackHttp1Server server;

    bool             response_callback_called = false;
    qb::http::status response_status          = qb::http::status::IM_A_TEAPOT; // before the client, which answers what it still holds
    auto             client                   = qb::http1::make_client(server.url("/"));
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

    bool             response_callback_called = false;
    bool             connect_callback_called  = false;
    qb::http::status response_status          = qb::http::status::OK; // before the client, which answers what it still holds
    auto             client                   = qb::http1::make_client(server.url("/"));
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
    std::vector<qb::http::Response> responses;
    auto                            client = qb::http1::make_client(server.url("/"));
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
    std::optional<qb::http::Response> reply;
    auto                              client = qb::http1::make_client(server.url("/"));
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

// Dropping the last client reference while a connect() callback is still waiting: the callback hears `false`, once,
// from the client's destructor -- as the HTTP/2 and HTTP/3 clients' does (Huly QB-1246; it was abandoned, destroyed
// without a word) -- and never again: the connect targets a real loopback server, and nothing fires into freed memory
// once the loop runs. A connect() that callback asks is refused by its return value alone.
TEST(Http1ClientTest, DestroyingClientDuringConnectFailsItsCallbackOnce) {
    LoopbackHttp1Server server;

    int  callback_invocations = 0, invocations_at_destruction = -1, inner_invocations = 0;
    bool heard = true, inner_accepted = true;
    {
        auto  client = qb::http1::make_client(server.url("/"));
        auto *raw    = client.get();
        client->connect([&, raw](bool ok, std::string const &) {
            ++callback_invocations;
            heard          = ok;
            inner_accepted = raw->connect([&](bool, std::string const &) { ++inner_invocations; });
        });
        EXPECT_EQ(callback_invocations, 0);
        // Drop the only strong reference immediately, before the connect can resolve.
        client.reset();
        invocations_at_destruction = callback_invocations;
    }
    EXPECT_EQ(invocations_at_destruction, 1) << "the destructor answers the connect() that was waiting";
    EXPECT_FALSE(heard);
    EXPECT_FALSE(inner_accepted) << "a connect() asked of a client being destroyed is refused";
    EXPECT_EQ(inner_invocations, 0) << "by its return value alone";

    // Pump the loop generously; if a dangling callback existed it would fire (or
    // crash under ASan) within this window.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
    while (std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
    }

    EXPECT_EQ(callback_invocations, 1) << "connect callback fired after the client was destroyed";
    EXPECT_EQ(inner_invocations, 0);
}

#ifdef QB_HAS_SSL
namespace http1_connect_awaiter_test {

/// What the coroutine below got past its connect() with, shared with the case that reads it.
struct ConnectAwaited {
    qb::http1::ConnectResult result{true, "not resumed"};
    int                      resumed = 0;
};

/// A coroutine that awaits connect(), and counts how many times it got past it. It holds the client weakly and its state
/// by value: a case that fails returns -- its client destroyed with it -- before the coroutine has first run, or while
/// it is parked, and the coroutine then runs on a turn of the loop of a later case, where the case's locals are gone.
qb::io::async::task<void>
await_connect(std::weak_ptr<qb::http1::Client> owner, std::shared_ptr<ConnectAwaited> state) {
    auto client = owner.lock();
    if (!client)
        co_return;                       // the case and its client are gone: nobody asks
    auto connecting = client->connect(); // an awaiter, which asks connect() once awaited, through a weak reference
    client.reset();                      // the case owns the client: a parked coroutine does not keep it alive
    state->result = co_await connecting;
    ++state->resumed;
}

} // namespace http1_connect_awaiter_test

// The coroutine form of the same: a coroutine parked on connect() is resumed, once, with `ok == false`, when its client
// is destroyed while the loop lives -- the destructor answers the connect() its awaiter asked. It was never resumed: the
// callback that would have completed it was destroyed unheard, and the frame parked for ever (Huly QB-1246). The peer
// completes the TCP handshake and answers nothing, so the TLS handshake is in flight for as long as the test likes.
TEST(Http1ClientTest, ACoroutineParkedOnConnectIsResumedWithFalseWhenItsClientIsDestroyed) {
    qb::io::async::init();
    qb::io::tcp::listener silent;
    ASSERT_EQ(silent.listen_v4(0, "127.0.0.1"), qb::io::SocketStatus::Done);

    auto awaited = std::make_shared<http1_connect_awaiter_test::ConnectAwaited>();
    auto client  = qb::http1::make_client("https://127.0.0.1:" + std::to_string(silent.local_endpoint().port()));
    client->set_verify_peer(false);
    qb::io::async::coro_scheduler().spawn(http1_connect_awaiter_test::await_connect(client, awaited));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return client->is_connecting(); }));
    EXPECT_EQ(awaited->resumed, 0);

    client.reset(); // the last owner: the destructor answers the connect() the awaiter asked
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return awaited->resumed != 0; }));
    drain_client_callbacks();
    EXPECT_EQ(awaited->resumed, 1);
    EXPECT_FALSE(awaited->result.ok);
}
#endif

// A client with no shared owner -- a plain object, not make_client()'s -- cannot connect. Its connect() says so by
// its return value alone: the callback is never called. It was, inside the call, and one that dials again on `false`
// recursed without end (Huly QB-1246).
TEST(Http1ClientTest, AClientWithNoSharedOwnerRefusesConnectByItsReturnValueAlone) {
    LoopbackHttp1Server server;
    qb::http1::Client   plain{server.url("/")};

    int                                            calls = 0, dials = 0;
    std::function<void(bool, std::string const &)> redial;
    redial = [&](bool ok, std::string const &) {
        ++calls;
        if (!ok && dials < 64) {
            ++dials;
            static_cast<void>(plain.connect(redial));
        }
    };
    ++dials;
    EXPECT_FALSE(plain.connect(redial));
    EXPECT_EQ(calls, 0) << "the callback of a connect() that starts nothing is never called";
    EXPECT_EQ(dials, 1);
    EXPECT_FALSE(plain.is_connecting());
}

// Regression: a user response callback is invoked from the protocol's noexcept
// onMessage dispatch. Before the invoke_user_callback chokepoint, an exception
// thrown by the callback escaped that noexcept boundary and called
// std::terminate (aborting the whole test binary). The throw must now be
// contained and the client must remain usable.
TEST(Http1ClientTest, ThrowingUserCallbackIsContainedAndClientSurvives) {
    LoopbackHttp1Server server;
    bool                first_called    = false;
    qb::http::status    observed_status = qb::http::status::IM_A_TEAPOT; // before the client, which answers what it still holds
    auto                client          = qb::http1::make_client(server.url("/"));

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
    bool             a_done   = false;
    bool             b_done   = false;
    qb::http::status status_a = qb::http::status::IM_A_TEAPOT; // before the client, which answers what it still holds
    qb::http::status status_b = qb::http::status::IM_A_TEAPOT;
    auto             client   = qb::http1::make_client("http://127.0.0.1:1");
    client->set_auto_reconnect(false);
    client->set_request_timeout(qb::duration::zero()); // disarm the pending timeout

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
    bool             done   = false;
    qb::http::status status = qb::http::status::IM_A_TEAPOT; // before the client, which answers what it still holds
    auto             client = qb::http1::make_client("http://127.0.0.1:1");
    client->set_max_pending_requests(0);

    const bool queued = client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response r) {
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
    bool                            done = false;
    std::vector<qb::http::Response> responses{qb::http::Response{}}; // pre-seed non-empty; before the client, which answers what it still holds
    auto                            client = qb::http1::make_client("http://127.0.0.1:1");

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

namespace http1_run_sync_connect_test {

/// run_sync(client->connect()) -- a coroutine the caller blocks on, the loop pumped until it completes -- from a callback,
/// bounded by a watchdog that ends the process, saying so, instead of letting the test hang.
struct Blocked {
    bool                      returned = false;
    qb::http1::ConnectResult  result;
    std::chrono::milliseconds took{0};

    void
    run(qb::http1::Client &client, char const *const from) {
        const auto               started = std::chrono::steady_clock::now();
        qb::http::test::watchdog bound(std::string("run_sync(connect()) from ") + from, 5s);
        result   = qb::io::async::run_sync(client.connect());
        took     = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        returned = true;
    }
};

/// Completes at its first resumption: a run_sync() of it is one pass of the loop.
qb::io::async::task<void>
completes_at_once() {
    co_return;
}

/// Awaits connect() twice in a row.
qb::io::async::task<void>
connect_twice(qb::http1::Client &client, qb::http1::ConnectResult &first, qb::http1::ConnectResult &second) {
    first  = co_await client.connect();
    second = co_await client.connect();
}

/// Two requests on a connection that is up, automatic reconnection on (the default): the first on `target`, whose
/// connection its deadline (`timeout`, when not zero) or the server ends; the second queued behind it, which that close
/// keeps for the next connection. The first's failure callback turns automatic reconnection off -- a policy that gives up
/// after N failures -- and takes the listener away, so an attempt is refused; the second's runs
/// run_sync(client->connect()), which returns at once, `false`, and nothing connects for it.
void
reconnection_turned_off_by_the_failure_ahead(char const *const target, qb::duration const timeout, qb::http::status const first_status,
                                             char const *const from) {
    std::optional<LoopbackHttp1Server> server{std::in_place};
    Blocked                            blocked;
    int                                answered = 0, failed = 0;
    bool                               connected = false;
    qb::http::status                   first = qb::http::status::OK, status = qb::http::status::OK;
    std::string                        text;
    auto                               client = qb::http1::make_client(server->url(""));
    client->connect([&](bool ok, std::string const &) { connected = ok; });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
    client->set_request_timeout(timeout); // armed for the first as it is sent: at once, the client connected
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, target), [&](qb::http::Response response) {
        ++answered;
        first = response.status();
        client->set_auto_reconnect(false); // gives up
        server.reset();                    // its listener gone: an attempt is refused
    }));
    client->set_request_timeout(qb::duration::zero()); // the second has no deadline: the close alone ends it
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        ++failed;
        status = response.status();
        text   = response.body().as<std::string>();
        blocked.run(*client, from);
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return failed != 0; }));
    EXPECT_EQ(answered, 1);
    EXPECT_EQ(first, first_status);
    EXPECT_EQ(status, qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(text, "HTTP/1.1 client is not connected") << "failed under the policy the callback left: no attempt was made for it";
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/1.1 connection is closing");
    EXPECT_LT(blocked.took, 1s);
    drain_client_callbacks();
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    EXPECT_FALSE(client->is_connected());
}

} // namespace http1_run_sync_connect_test

// run_sync(client->connect()) from a failure callback of disconnect() returns at once, `false`, "HTTP/1.1 connection is
// closing", and nothing connects for it. The connect() it asked was queued until the callbacks of the close had unwound,
// which the pump it ran could not reach: it never returned -- in 3.3.0 as well (Huly QB-1246).
TEST(Http1ClientTest, ARunSyncOfConnectFromAFailureCallbackOfDisconnectReturnsFalseAtOnce) {
    qb::io::async::init();
    LoopbackHttp1Server                  server;
    http1_run_sync_connect_test::Blocked blocked;
    int                                  failed    = 0;
    bool                                 connected = false;
    auto                                 client    = qb::http1::make_client(server.url(""));
    client->connect([&](bool ok, std::string const &) { connected = ok; });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) {
        ++failed;
        blocked.run(*client, "a failure callback of disconnect()");
    }));
    client->disconnect();
    EXPECT_EQ(failed, 1);
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/1.1 connection is closing");
    EXPECT_LT(blocked.took, 1s);
    drain_client_callbacks();
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    EXPECT_FALSE(client->is_connected());
}

// The coroutine push_request() and push_requests() take the same rule (Huly QB-1246): awaited from a callback of a
// close, they complete at once, 503 "HTTP/1.1 connection is closing". The callback form queues the request for the next
// connection, which cannot start before that callback returns: a run_sync() of the coroutine form there waited for the
// request's timeout (the case gives it 2 s, and a watchdog).
TEST(Http1ClientTest, ARunSyncOfAPushFromAFailureCallbackOfDisconnectIsAnsweredAtOnce) {
    qb::io::async::init();
    LoopbackHttp1Server             server;
    int                             failed    = 0;
    bool                            connected = false;
    qb::http::Response              single;
    std::vector<qb::http::Response> batch;
    std::chrono::milliseconds       took{0};
    auto                            client = qb::http1::make_client(server.url(""));
    client->set_request_timeout(2s);
    client->connect([&](bool ok, std::string const &) { connected = ok; });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) {
        ++failed;
        const auto               started = std::chrono::steady_clock::now();
        qb::http::test::watchdog bound("run_sync(push_request()) from a failure callback of disconnect()", 10s);
        single = qb::io::async::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));
        std::vector<qb::http::Request> two;
        two.emplace_back(request(qb::http::method::GET, "/ping"));
        two.emplace_back(request(qb::http::method::GET, "/ping"));
        batch = qb::io::async::run_sync(client->push_requests(std::move(two)));
        took  = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    }));
    client->disconnect();
    EXPECT_EQ(failed, 1);
    EXPECT_EQ(single.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(single.body().as<std::string>(), "HTTP/1.1 connection is closing");
    ASSERT_EQ(batch.size(), 2u);
    EXPECT_EQ(batch[0].body().as<std::string>(), "HTTP/1.1 connection is closing");
    EXPECT_EQ(batch[1].body().as<std::string>(), "HTTP/1.1 connection is closing");
    EXPECT_LT(took, 1s) << "a coroutine push awaited from a callback of a close waited for the request's timeout";
    drain_client_callbacks();
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
}

// The same from the callback of a response that closes its connection: retired before the callback runs, the
// connection's close is under way there too.
TEST(Http1ClientTest, ARunSyncOfConnectFromTheCallbackOfAClosingResponseReturnsFalseAtOnce) {
    qb::io::async::init();
    LoopbackHttp1Server                  server;
    http1_run_sync_connect_test::Blocked blocked;
    int                                  answered = 0;
    auto                                 client   = qb::http1::make_client(server.url(""));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/close"), [&](qb::http::Response response) {
        ++answered;
        EXPECT_EQ(response.status(), qb::http::status::OK);
        blocked.run(*client, "the callback of a response that closes its connection");
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return answered != 0; }));
    EXPECT_EQ(answered, 1);
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/1.1 connection is closing");
    EXPECT_LT(blocked.took, 1s);
    drain_client_callbacks();
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    client->disconnect();
    drain_client_callbacks();
}

// A client whose close refused a run_sync(client->connect()) -- from the callback of a response that closes its
// connection -- still serves the next request, pushed once that callback has returned, with no disconnect() from
// outside a callback. The pump run_sync() ran inside the callback drained the loop's deferred queue, where the reset
// of the retired connection waited: it ran there, the callback still on the stack, and gave up. The connection
// stayed retired until the client next ran a callback: a request queued then waited for its request timeout (408,
// 60 s by default), whose callback restarted the connection -- for ever with none.
TEST(Http1ClientTest, AClientWhoseCloseRefusedARunSyncOfConnectServesTheNextRequest) {
    qb::io::async::init();
    LoopbackHttp1Server                  server;
    http1_run_sync_connect_test::Blocked blocked;
    int                                  answered = 0, pinged = 0;
    qb::http::status                     status = qb::http::status::INTERNAL_SERVER_ERROR;
    auto                                 client = qb::http1::make_client(server.url(""));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/close"), [&](qb::http::Response) {
        ++answered;
        blocked.run(*client, "the callback of a response that closes its connection");
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return answered != 0; }));
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        ++pinged;
        status = response.status();
    }));
    EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return pinged != 0; }, 2s)) << "the next request was never answered";
    EXPECT_EQ(status, qb::http::status::OK);
    client->disconnect();
    drain_client_callbacks();
}

// The same with any loop pumped there: a run_sync() of a coroutine that completes at its first resumption, from the
// callback of a response that closes its connection -- in 3.3.0 as well.
TEST(Http1ClientTest, AClientWhoseCloseCallbackRanTheLoopServesTheNextRequest) {
    qb::io::async::init();
    LoopbackHttp1Server server;
    int                 answered = 0, pinged = 0;
    qb::http::status    status = qb::http::status::INTERNAL_SERVER_ERROR;
    auto                client = qb::http1::make_client(server.url(""));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/close"), [&](qb::http::Response) {
        ++answered;
        qb::io::async::run_sync(http1_run_sync_connect_test::completes_at_once());
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return answered != 0; }));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        ++pinged;
        status = response.status();
    }));
    EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return pinged != 0; }, 2s)) << "the next request was never answered";
    EXPECT_EQ(status, qb::http::status::OK);
    client->disconnect();
    drain_client_callbacks();
}

// The same when the close is a disconnect() made from the callback of a response: a request pushed once that callback
// has returned connects again and is answered.
TEST(Http1ClientTest, AClientWhoseDisconnectFromACallbackRefusedARunSyncOfConnectServesTheNextRequest) {
    qb::io::async::init();
    LoopbackHttp1Server                  server;
    http1_run_sync_connect_test::Blocked blocked;
    int                                  answered = 0, pinged = 0;
    qb::http::status                     status = qb::http::status::INTERNAL_SERVER_ERROR;
    auto                                 client = qb::http1::make_client(server.url(""));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) {
        ++answered;
        client->disconnect();
        blocked.run(*client, "the callback of a response that disconnected");
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return answered != 0; }));
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        ++pinged;
        status = response.status();
    }));
    EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return pinged != 0; }, 2s)) << "the next request was never answered";
    EXPECT_EQ(status, qb::http::status::OK);
    client->disconnect();
    drain_client_callbacks();
}

// With automatic reconnection off, a request queued behind a response that closes its connection fails inside that close,
// the connection retired: a run_sync(client->connect()) from its callback returns at once, `false`, and nothing connects
// for it. The request was failed by the reset of the retired connection, which the loop's deferred queue runs at the tail
// of the turn, once the close has returned: no close was under way there, the connect() started an attempt, and its
// refusal, sent through that same queue, which the pump run_sync() ran could not drain, came only with the connect
// deadline -- 30 s by default, macOS reporting a loopback refusal through the socket --, for ever where connect()
// reports it at once (Huly QB-1246).
TEST(Http1ClientTest, ARunSyncOfConnectFromTheFailureOfARequestQueuedBehindAClosingResponseReturnsFalseAtOnce) {
    qb::io::async::init();
    std::optional<LoopbackHttp1Server>   server{std::in_place};
    http1_run_sync_connect_test::Blocked blocked;
    int                                  answered = 0, failed = 0;
    bool                                 connected = false;
    qb::http::status                     status    = qb::http::status::OK;
    auto                                 client    = qb::http1::make_client(server->url(""));
    client->set_auto_reconnect(false);
    client->connect([&](bool ok, std::string const &) { connected = ok; });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/close"), [&](qb::http::Response) {
        ++answered;
        server.reset(); // its listener gone: an attempt is refused
    }));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        ++failed;
        status = response.status();
        blocked.run(*client, "the failure of a request queued behind a response that closes its connection");
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return failed != 0; }));
    EXPECT_EQ(answered, 1);
    EXPECT_EQ(status, qb::http::status::SERVICE_UNAVAILABLE);
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/1.1 connection is closing");
    EXPECT_LT(blocked.took, 1s);
    drain_client_callbacks();
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
    EXPECT_FALSE(client->is_connected());
}

// With automatic reconnection on, a request queued behind one whose deadline ends its connection is kept for the next
// connection -- until the failure callback of the one ahead turns automatic reconnection off: it then fails inside that
// close, the connection retired, and a run_sync(client->connect()) from its callback returns at once, `false`. The queue
// was left to the reset of the retired connection, at the tail of the turn, which failed it there, where that connect()
// was not refused: its attempt's refusal waited in the deferred queue that reset runs from (Huly QB-1246).
TEST(Http1ClientTest, ARunSyncOfConnectFromTheFailureOfARequestKeptBehindATimeoutWhoseCallbackEndedReconnectionReturnsFalseAtOnce) {
    qb::io::async::init();
    http1_run_sync_connect_test::reconnection_turned_off_by_the_failure_ahead(
        "/never", 300ms, qb::http::status::GATEWAY_TIMEOUT,
        "the failure of a request kept behind a timeout, automatic reconnection turned off by the failure ahead");
}

// The same when the server closes the connection of the request ahead (Huly QB-1246).
TEST(Http1ClientTest, ARunSyncOfConnectFromTheFailureOfARequestKeptBehindAServerCloseWhoseCallbackEndedReconnectionReturnsFalseAtOnce) {
    qb::io::async::init();
    http1_run_sync_connect_test::reconnection_turned_off_by_the_failure_ahead(
        "/peer-close-without-response", qb::duration::zero(), qb::http::status::BAD_GATEWAY,
        "the failure of a request kept behind a server close, automatic reconnection turned off by the failure ahead");
}

// What the callback of a connect() made on a connected client throws is logged and goes no further, as for every other
// callback of this client: connect() returns true and the client stays connected. It reached the caller of connect().
TEST(Http1ClientTest, AThrowingCallbackOfAConnectOnAConnectedClientIsContained) {
    qb::io::async::init();
    LoopbackHttp1Server server;
    bool                connected = false;
    int                 called    = 0;
    auto                client    = qb::http1::make_client(server.url(""));
    client->connect([&](bool ok, std::string const &) { connected = ok; });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
    bool accepted = false;
    EXPECT_NO_THROW(accepted = client->connect([&](bool, std::string const &) {
        ++called;
        throw std::runtime_error("thrown by the callback of a connect() on a connected client");
    }));
    EXPECT_TRUE(accepted);
    EXPECT_EQ(called, 1);
    EXPECT_TRUE(client->is_connected());
    client->disconnect();
    drain_client_callbacks();
}

// A request a callback of the client's destructor pushes is answered inside the push with 503 whatever it is -- one for
// another origin included, which a live client refuses with 400: the client being destroyed accepts nothing, and says so
// before it reads the request (Huly QB-1246).
TEST(Http1ClientTest, AClientBeingDestroyedAnswersEveryRequestItsCallbacksPushWith503) {
    qb::io::async::init();
    LoopbackHttp1Server server;
    int                 heard  = 0;
    qb::http::status    pushed = qb::http::status::OK;
    {
        auto  client = qb::http1::make_client(server.url(""));
        auto *raw    = client.get();
        ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&, raw](qb::http::Response) {
            ++heard;
            raw->push_request(qb::http::Request{qb::http::method::GET, qb::io::uri("http://elsewhere.invalid/x")},
                              [&](qb::http::Response response) { pushed = response.status(); });
        }));
        client.reset(); // destroyed with its request queued
    }
    EXPECT_EQ(heard, 1);
    EXPECT_EQ(pushed, qb::http::status::SERVICE_UNAVAILABLE);
    drain_client_callbacks();
}

// A coroutine that awaits connect() again once an attempt failed -- the port refuses it -- gets the next attempt's own
// outcome, not "HTTP/1.1 connection is closing". The connector's failure is delivered through the loop's deferred queue,
// and the coroutine resumes in the same turn, the failed connection still retired: the awaiter answers at once only from
// a callback of the close, where the attempt it would wait for cannot start before that callback returns.
TEST(Http1ClientTest, ACoroutineThatAwaitsConnectAgainAfterAFailedAttemptGetsThatAttemptsOutcome) {
    qb::io::async::init();
    qb::io::tcp::listener holder;
    ASSERT_EQ(holder.listen_v4(0, "127.0.0.1"), 0);
    const std::uint16_t port = holder.local_endpoint().port();
    holder.close(); // the port refuses from here on
    auto                     client = qb::http1::make_client("http://127.0.0.1:" + std::to_string(port));
    qb::http1::ConnectResult first{true, "not returned"}, second{true, "not returned"};
    {
        qb::http::test::watchdog bound("two connect() awaited in a row", 20s);
        qb::io::async::run_sync(http1_run_sync_connect_test::connect_twice(*client, first, second));
    }
    EXPECT_FALSE(first.ok);
    EXPECT_FALSE(second.ok);
    EXPECT_NE(second.error_message, "HTTP/1.1 connection is closing");
    EXPECT_EQ(second.error_message, first.error_message) << "the second attempt's own failure";
    drain_client_callbacks();
}

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
        const qb::http::test::fail_wait::case_on_this_thread here; // the body of the case: its waits are this thread's
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

// ===========================================================================
// A response to HEAD declares the length a GET's would have and carries no body (RFC 9110 §9.3.2): a declared length
// past the client's body limit is no refusal (Huly QB-1248). The client's parser refused it at the end of the header
// section, before the protocol asked whether a body may follow: the HEAD failed, and its connection with it. Both
// clients, the persistent one and the one-shot session, over the server's own answer to HEAD.
// ===========================================================================

namespace http1_head_past_limit_test {
[[nodiscard]] inline std::string
past_the_body_limit() {
    return std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE + 1);
}

/// The test server, one route more: HEAD /head-past-limit declares one byte past the client's body limit.
struct Server {
    std::uint16_t                       port = 0;
    Http1ClientTestServer              *srv  = nullptr; // before `thread`: LoopbackHttp1Server says why
    ServerThread<Http1ClientTestServer> thread;

    Server()
        : thread([this](Http1ClientTestServer &server) {
            srv = &server;
            server.router().head("/head-past-limit", [&server](auto ctx) {
                ++server.request_count;
                ctx->response().status() = qb::http::status::OK;
                ctx->response().set_header("Content-Length", past_the_body_limit());
                ctx->response().set_header("X-Head", "past-limit");
                ctx->complete();
            });
            server.router().compile();
            if (server.transport().listen_v4(0, "127.0.0.1") != 0) {
                return false;
            }
            server.start();
            return true;
        }) {
        if (!thread.ready()) {
            throw std::runtime_error("HTTP/1.1 loopback server failed to start");
        }
        port = thread.port();
    }

    [[nodiscard]] std::string
    url(std::string const &path) const {
        return "http://127.0.0.1:" + std::to_string(port) + path;
    }
};
} // namespace http1_head_past_limit_test

TEST(Http1ClientTest, AHeadResponseDeclaringPastTheBodyLimitIsDeliveredAndKeepsItsConnection) {
    using namespace http1_head_past_limit_test;
    Server server;
    auto   client = qb::http1::make_client(server.url("/"));
    client->set_request_timeout(std::chrono::seconds(3));

    auto head = qb::http::run_sync(client->push_request(request(qb::http::method::HEAD, "/head-past-limit")));
    auto ping = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));

    EXPECT_EQ(head.status(), qb::http::status::OK) << "the response to HEAD was refused";
    EXPECT_EQ(head.header("Content-Length"), past_the_body_limit());
    EXPECT_EQ(head.header("X-Head"), "past-limit");
    EXPECT_TRUE(head.body().empty());
    EXPECT_EQ(ping.status(), qb::http::status::OK);
    EXPECT_EQ(ping.body().template as<std::string>(), "pong");
    EXPECT_EQ(server.srv->connection_count.load(), 1) << "the response to HEAD dropped its connection";
    EXPECT_EQ(server.srv->request_count.load(), 2);
    drain_client_callbacks();
}

TEST(Http1ClientTest, OneShotHeadDeclaringPastTheBodyLimitIsDelivered) {
    using namespace http1_one_shot_test;
    qb::io::async::init();
    http1_head_past_limit_test::Server server;
    auto                               outcome = std::make_shared<Outcome>();

    qb::http::HEAD(qb::http::Request{{server.url("/head-past-limit")}}, recorder(outcome), std::chrono::seconds(5));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return outcome->count > 0; }, std::chrono::seconds(3)));
    drain_client_callbacks();

    EXPECT_EQ(outcome->count, 1);
    EXPECT_EQ(outcome->response.status(), qb::http::status::OK) << "the response to HEAD was refused";
    EXPECT_EQ(outcome->response.header("Content-Length"), http1_head_past_limit_test::past_the_body_limit());
    EXPECT_EQ(outcome->response.header("X-Head"), "past-limit");
    EXPECT_TRUE(outcome->response.body().empty());
}

// A response to HEAD that declares no length ends at its header section (RFC 9112 §6.3): the persistent client keeps its
// connection (Huly QB-1248). It computed keep-alive as for a body delimited by the close and retired the connection.
// qb's own server never answers in that shape (an empty body gets `content-length: 0`), so a scripted peer does.
namespace http1_head_no_length_test {
/// A scripted HTTP/1.1 peer: it answers each request it reads, whatever the connection, with the next response of its
/// script, and counts the connections it accepted. No call blocks (the listener and each connection are non-blocking,
/// polled), and it gives up at a deadline: a client that never comes ends the thread.
class ScriptedPeer {
public:
    explicit ScriptedPeer(std::vector<std::string> script)
        : _script(std::move(script)) {
        if (_listener.listen_v4(0, "127.0.0.1") != 0 || _listener.set_nonblocking(true) != 0) {
            throw std::runtime_error("scripted peer: listen failed");
        }
        port    = _listener.local_endpoint().port();
        _thread = std::thread([this] { run(); });
    }

    ~ScriptedPeer() {
        _stop = true;
        _thread.join();
    }

    ScriptedPeer(ScriptedPeer const &)            = delete;
    ScriptedPeer &operator=(ScriptedPeer const &) = delete;

    [[nodiscard]] std::string
    url(std::string const &path) const {
        return "http://127.0.0.1:" + std::to_string(port) + path;
    }

    std::uint16_t    port = 0;
    std::atomic<int> connections{0};

private:
    void
    run() {
        const auto                       deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        std::size_t                      next     = 0;
        std::vector<qb::io::tcp::socket> peers; // every connection accepted, served side by side: a client may
        std::vector<std::string>         input; // leave one open (retired, not closed) and open the next
        qb::http::test::peer_wait_until([&] { return _stop || next >= _script.size(); }, deadline,
                                        [&] {
                                            bool idle = true;
                                            if (qb::io::tcp::socket accepted = _listener.accept(); accepted.is_open()) {
                                                static_cast<void>(accepted.set_nonblocking(true));
                                                peers.push_back(std::move(accepted));
                                                input.emplace_back();
                                                ++connections;
                                                idle = false;
                                            }
                                            for (std::size_t i = 0; i < peers.size() && next < _script.size(); ++i) {
                                                if (!peers[i].is_open()) {
                                                    continue;
                                                }
                                                char      buffer[1024];
                                                const int n = peers[i].read(buffer, sizeof(buffer));
                                                if (n == 0) {
                                                    peers[i].close(); // the client closed this connection
                                                    continue;
                                                }
                                                if (n < 0) {
                                                    continue; // nothing to read yet
                                                }
                                                idle = false;
                                                input[i].append(buffer, static_cast<std::size_t>(n));
                                                for (auto end = input[i].find("\r\n\r\n"); end != std::string::npos && next < _script.size();
                                                     end      = input[i].find("\r\n\r\n")) {
                                                    input[i].erase(0, end + 4); // a request without a body: the client sends HEAD and GET
                                                    const auto &response = _script[next++];
                                                    static_cast<void>(peers[i].write(response.data(), response.size()));
                                                }
                                            }
                                            if (idle) {
                                                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                            }
                                        });
    }

    qb::io::tcp::listener    _listener;
    std::vector<std::string> _script;
    std::atomic<bool>        _stop{false};
    std::thread              _thread;
};
} // namespace http1_head_no_length_test

TEST(Http1ClientTest, AHeadResponseWithNoLengthKeepsItsConnection) {
    http1_head_no_length_test::ScriptedPeer peer(
        {"HTTP/1.1 200 OK\r\nX-Head: no-length\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong"});
    auto client = qb::http1::make_client(peer.url("/"));
    client->set_request_timeout(std::chrono::seconds(3));

    auto head = qb::http::run_sync(client->push_request(request(qb::http::method::HEAD, "/head-no-length")));
    auto ping = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));

    EXPECT_EQ(head.status(), qb::http::status::OK);
    EXPECT_EQ(head.header("X-Head"), "no-length");
    EXPECT_FALSE(head.has_header("Content-Length"));
    EXPECT_TRUE(head.body().empty());
    EXPECT_EQ(ping.status(), qb::http::status::OK);
    EXPECT_EQ(ping.body().template as<std::string>(), "pong");
    EXPECT_EQ(peer.connections.load(), 1) << "the response to HEAD retired its connection";
    drain_client_callbacks();
}

// A response with no body may name any transfer coding (RFC 9112 §6.1, §6.3; Huly QB-1248): the persistent client
// delivers a HEAD's response and a 304 that name `gzip, chunked` and keeps its connection. It refused both, and opened a
// connection for each request after them. qb's own server sends no such coding, so the scripted peer does.
TEST(Http1ClientTest, AResponseToHeadOrA304MayNameAnyCodingAndKeepsItsConnection) {
    http1_head_no_length_test::ScriptedPeer peer(
        {"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nX-Head: coded\r\n\r\n",
         "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong"});
    auto client = qb::http1::make_client(peer.url("/"));
    client->set_request_timeout(std::chrono::seconds(3));

    auto head                 = qb::http::run_sync(client->push_request(request(qb::http::method::HEAD, "/coded")));
    auto not_modified_request = request(qb::http::method::GET, "/coded");
    not_modified_request.set_header("If-None-Match", "\"v1\"");
    auto not_modified = qb::http::run_sync(client->push_request(std::move(not_modified_request)));
    auto ping         = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));

    EXPECT_EQ(head.status(), qb::http::status::OK) << "the response to HEAD was refused";
    EXPECT_EQ(head.header("X-Head"), "coded");
    EXPECT_TRUE(head.body().empty());
    EXPECT_EQ(not_modified.status(), qb::http::status::NOT_MODIFIED) << "the 304 was refused";
    EXPECT_TRUE(not_modified.body().empty());
    EXPECT_EQ(ping.status(), qb::http::status::OK);
    EXPECT_EQ(ping.body().template as<std::string>(), "pong");
    EXPECT_EQ(peer.connections.load(), 1) << "a bodyless response that names a coding dropped its connection";
    drain_client_callbacks();
}

// An unassigned 1xx that names `chunked` is interim like any 1xx (RFC 9110 §15.2) and ends at its header section (RFC
// 9112 §6.3): the persistent client waits past it for the final response, on the same connection (Huly QB-1248). The
// final response's status line was read as a chunk size: the request failed and the connection dropped.
TEST(Http1ClientTest, AnUnassignedInformationalResponseNamingChunkedIsInterim) {
    http1_head_no_length_test::ScriptedPeer peer(
        {"HTTP/1.1 104 Unassigned\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong",
         "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\npong2"});
    auto client = qb::http1::make_client(peer.url("/"));
    client->set_request_timeout(std::chrono::seconds(3));

    auto first  = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/interim")));
    auto second = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/ping")));

    EXPECT_EQ(first.status(), qb::http::status::OK) << "the interim response failed the request";
    EXPECT_EQ(first.body().template as<std::string>(), "pong");
    EXPECT_EQ(second.status(), qb::http::status::OK);
    EXPECT_EQ(second.body().template as<std::string>(), "pong2");
    EXPECT_EQ(peer.connections.load(), 1) << "the interim response dropped its connection";
    drain_client_callbacks();
}

// A 101 ends HTTP/1.1 on its connection (RFC 9110 §15.2.2), and a server must not switch to a protocol the request did
// not offer in its Upgrade field (§7.8). The persistent client delivered any 101 as the answer and kept its connection:
// the bytes the peer sent after it -- another protocol -- were read as the response of the request queued behind it
// (Huly QB-1248). The scripted peer switches to `foo`, then writes bytes that look like a response.
namespace http1_switched_protocols_test {
const std::string switched = "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: foo\r\n\r\n"
                             "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nsmuggled";
const std::string pong     = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong";

qb::http::Request
asking_to_switch(std::string const &target, std::string const &offered = "foo") {
    auto req = request(qb::http::method::GET, target);
    req.set_header("Connection", "upgrade");
    req.set_header("Upgrade", offered);
    return req;
}
} // namespace http1_switched_protocols_test

TEST(Http1ClientTest, AnUnaskedSwitchFailsTheRequestAndNothingAfterItAnswersTheNext) {
    using namespace http1_switched_protocols_test;
    http1_head_no_length_test::ScriptedPeer peer({switched, pong});
    auto                                    client = qb::http1::make_client(peer.url("/"));
    client->set_request_timeout(std::chrono::seconds(3));

    std::vector<qb::http::Request> queued; // the second request waits behind the first, as it would under load
    queued.push_back(request(qb::http::method::GET, "/switch"));
    queued.push_back(request(qb::http::method::GET, "/ping"));
    auto replies = qb::http::run_sync(client->push_requests(std::move(queued)));

    ASSERT_EQ(replies.size(), 2u);
    EXPECT_EQ(replies[0].status(), qb::http::status::BAD_GATEWAY) << "a 101 the request never asked for was its answer";
    EXPECT_EQ(replies[1].status(), qb::http::status::OK);
    EXPECT_EQ(replies[1].body().template as<std::string>(), "pong") << "the bytes after the 101 answered the next request";
    EXPECT_EQ(peer.connections.load(), 2) << "the connection that switched protocols served the next request";
    const auto [total, successful, failed] = client->get_stats();
    EXPECT_EQ(failed, 1u) << "the unasked switch was counted a success";
    static_cast<void>(total);
    static_cast<void>(successful);
    drain_client_callbacks();
}

TEST(Http1ClientTest, AnAskedSwitchIsTheAnswerAndRetiresItsConnection) {
    using namespace http1_switched_protocols_test;
    http1_head_no_length_test::ScriptedPeer peer({switched, pong});
    auto                                    client = qb::http1::make_client(peer.url("/"));
    client->set_request_timeout(std::chrono::seconds(3));

    std::vector<qb::http::Request> queued;
    queued.push_back(asking_to_switch("/switch"));
    queued.push_back(request(qb::http::method::GET, "/ping"));
    auto replies = qb::http::run_sync(client->push_requests(std::move(queued)));

    ASSERT_EQ(replies.size(), 2u);
    EXPECT_EQ(replies[0].status(), qb::http::status::SWITCHING_PROTOCOLS) << "the switch the request asked for was not its answer";
    EXPECT_EQ(replies[0].header("Upgrade"), "foo");
    EXPECT_EQ(replies[1].status(), qb::http::status::OK);
    EXPECT_EQ(replies[1].body().template as<std::string>(), "pong") << "the bytes after the 101 answered the next request";
    EXPECT_EQ(peer.connections.load(), 2) << "the connection that switched protocols served the next request";
    drain_client_callbacks();
}

// The same behind a 101 its request never asked for, automatic reconnection off: the switch fails the request it
// answers, 502, and the request queued behind it fails inside that close too -- a run_sync(client->connect()) from its
// callback returns at once, `false`. It was failed by the reset of the retired connection, where it returned only at
// the connect deadline, as above (Huly QB-1246).
TEST(Http1ClientTest, ARunSyncOfConnectFromTheFailureOfARequestQueuedBehindAnUnaskedSwitchReturnsFalseAtOnce) {
    using namespace http1_switched_protocols_test;
    qb::io::async::init();
    std::optional<http1_head_no_length_test::ScriptedPeer> peer{std::in_place, std::vector<std::string>{switched}};
    http1_run_sync_connect_test::Blocked                   blocked;
    int                                                    answered = 0, failed = 0;
    bool                                                   connected = false;
    qb::http::status                                       first = qb::http::status::OK, status = qb::http::status::OK;
    auto                                                   client = qb::http1::make_client(peer->url("/"));
    client->set_auto_reconnect(false);
    client->connect([&](bool ok, std::string const &) { connected = ok; });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/switch"), [&](qb::http::Response response) {
        ++answered;
        first = response.status();
        peer.reset(); // its listener gone: an attempt is refused
    }));
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        ++failed;
        status = response.status();
        blocked.run(*client, "the failure of a request queued behind an unasked switch");
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return failed != 0; }));
    EXPECT_EQ(answered, 1);
    EXPECT_EQ(first, qb::http::status::BAD_GATEWAY);
    EXPECT_EQ(status, qb::http::status::SERVICE_UNAVAILABLE);
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/1.1 connection is closing");
    EXPECT_LT(blocked.took, 1s);
    drain_client_callbacks();
    EXPECT_FALSE(client->is_connecting()) << "nothing was queued for it";
}

TEST(Http1ClientTest, OneShotUnaskedSwitchFailsAndAnAskedOneIsTheAnswer) {
    using namespace http1_switched_protocols_test;
    {
        http1_head_no_length_test::ScriptedPeer peer({switched});
        auto reply = qb::http::run_sync(qb::http::GET(qb::http::Request{{peer.url("/switch")}}, std::chrono::seconds(3)));
        EXPECT_EQ(reply.response.status(), qb::http::status::BAD_GATEWAY) << "a 101 the request never asked for was its answer";
    }
    {
        http1_head_no_length_test::ScriptedPeer peer({switched});
        auto                                    req = asking_to_switch("/switch");
        req.uri()                                   = qb::io::uri(peer.url("/switch"));
        auto reply                                  = qb::http::run_sync(qb::http::GET(std::move(req), std::chrono::seconds(3)));
        EXPECT_EQ(reply.response.status(), qb::http::status::SWITCHING_PROTOCOLS) << "the switch the request asked for was not its answer";
    }
    {
        http1_head_no_length_test::ScriptedPeer peer({switched});
        auto                                    req = asking_to_switch("/switch", "websocket");
        req.uri()                                   = qb::io::uri(peer.url("/switch"));
        auto reply                                  = qb::http::run_sync(qb::http::GET(std::move(req), std::chrono::seconds(3)));
        EXPECT_EQ(reply.response.status(), qb::http::status::BAD_GATEWAY) << "a switch to a protocol the request did not offer was its answer";
    }
    drain_client_callbacks();
}

// A switch to a protocol the request did not offer -- `foo` to an offer of `websocket`, or one that names no protocol --
// fails the request as an unasked one does (§7.8, §15.2.2), and the connection is retired; a 101 with no request in flight
// retires it too, and the next request goes to a new connection (Huly QB-1248).
TEST(Http1ClientTest, ASwitchToWhatTheRequestDidNotOfferFailsIt) {
    using namespace http1_switched_protocols_test;
    for (auto const &[offered, answer] : std::vector<std::pair<std::string, std::string>>{
             {"websocket", switched},
             {"foo", "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\nsmuggled"},
             {"*", switched}, // `*` names a protocol of its own: no wildcard
             {"foo", "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: , \r\n\r\nsmuggled"}, // a field naming none
             {"foo", "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: foo\r\nUpgrade: bar\r\n\r\nsmuggled"}
         }) {
        http1_head_no_length_test::ScriptedPeer peer({answer, pong});
        auto                                    client = qb::http1::make_client(peer.url("/"));
        client->set_request_timeout(std::chrono::seconds(3));
        std::vector<qb::http::Request> queued;
        queued.push_back(asking_to_switch("/switch", offered));
        queued.push_back(request(qb::http::method::GET, "/ping"));
        auto replies = qb::http::run_sync(client->push_requests(std::move(queued)));
        ASSERT_EQ(replies.size(), 2u) << offered;
        EXPECT_EQ(replies[0].status(), qb::http::status::BAD_GATEWAY) << offered << ": a switch the request did not offer was its answer";
        EXPECT_EQ(replies[1].status(), qb::http::status::OK) << offered;
        EXPECT_EQ(replies[1].body().template as<std::string>(), "pong") << offered;
        EXPECT_EQ(peer.connections.load(), 2) << offered << ": the connection that switched protocols served the next request";
        drain_client_callbacks();
    }
}

// An offer is the request's every Upgrade field line, one list (RFC 9110 §5.3): a 101 to the protocol its second line names
// is its answer (Huly QB-1248).
TEST(Http1ClientTest, AnOfferSpreadOverFieldLinesIsReadWhole) {
    using namespace http1_switched_protocols_test;
    http1_head_no_length_test::ScriptedPeer peer({switched, pong});
    auto                                    client = qb::http1::make_client(peer.url("/"));
    client->set_request_timeout(std::chrono::seconds(3));
    auto offer = asking_to_switch("/switch", "h2c");
    offer.add_header("Upgrade", "foo");
    auto reply = qb::http::run_sync(client->push_request(std::move(offer)));
    EXPECT_EQ(reply.status(), qb::http::status::SWITCHING_PROTOCOLS) << "the offer's second field line was not read";
    drain_client_callbacks();
}

TEST(Http1ClientTest, ASwitchWithNoRequestInFlightRetiresTheConnection) {
    using namespace http1_switched_protocols_test;
    http1_head_no_length_test::ScriptedPeer peer({"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" + switched, pong});
    auto                                    client = qb::http1::make_client(peer.url("/"));
    client->set_request_timeout(std::chrono::seconds(3));
    auto first  = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/a")));
    auto second = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/b")));
    EXPECT_EQ(first.body().template as<std::string>(), "ok");
    EXPECT_EQ(second.status(), qb::http::status::OK);
    EXPECT_EQ(second.body().template as<std::string>(), "pong");
    EXPECT_EQ(peer.connections.load(), 2) << "a connection that switched protocols with no request in flight was kept";
    drain_client_callbacks();
}

// What qb writes, qb reads, at the default limits (Huly QB-1248): a chunked body past the 16 MiB chunk limit -- which the
// serializers write as one chunk, the chunk serializer as frames of at most the limit -- goes from a qb client to a qb
// server and back. With the chunk limit checked at the chunk-size line and the serializer writing one chunk, the
// server answered 413 and the client failed the response.
namespace http1_chunked_round_trip_test {
constexpr std::size_t kSize = qb::http::protocol_limits::MAX_CHUNK_SIZE + 5;

class Server;
class Session : public qb::http::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
};
class Server : public qb::http::use<Server>::server<Session> {
public:
    Server() {
        router().post("/size", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::to_string(ctx->request().body().size());
            ctx->complete();
        });
        router().get("/big", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().set_header("Transfer-Encoding", "chunked");
            ctx->response().body() = std::string(kSize, 'b');
            ctx->complete();
        });
        router().compile();
    }
};
Session::Session(Server &server)
    : session(server) {}
} // namespace http1_chunked_round_trip_test

TEST(Http1ClientTest, AChunkedBodyPastTheChunkLimitGoesFromQbToQbBothWays) {
    using namespace http1_chunked_round_trip_test;
    qb::http::test::ServerThread<Server> thread([](Server &server) {
        if (server.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        server.start();
        return true;
    });
    ASSERT_TRUE(thread.ready());
    auto client = qb::http1::make_client("http://127.0.0.1:" + std::to_string(thread.port()) + "/");
    client->set_request_timeout(std::chrono::seconds(20));

    auto upload = request(qb::http::method::POST, "/size");
    upload.set_header("Transfer-Encoding", "chunked");
    upload.body() = std::string(kSize, 'u');
    auto sized    = qb::http::run_sync(client->push_request(std::move(upload)));
    EXPECT_EQ(sized.status(), qb::http::status::OK) << "the server refused a qb client's chunked body";
    EXPECT_EQ(sized.body().template as<std::string>(), std::to_string(kSize));

    auto big = qb::http::run_sync(client->push_request(request(qb::http::method::GET, "/big")));
    EXPECT_EQ(big.status(), qb::http::status::OK) << "the client refused a qb server's chunked body";
    EXPECT_EQ(big.body().size(), kSize);
    drain_client_callbacks();
}

// On the wire (Huly QB-1248): a Content-Length llhttp refuses -- past 2^64-1, not a number, given twice -- is answered
// 400 with `Connection: close`, and the connection closes (RFC 9112 §6.3); nothing the request carried is served. The
// server closed the connection with no answer.
TEST(Http1ClientTest, ARequestWhoseLengthIsRefusedIsAnswered400ThenClosed) {
    LoopbackHttp1Server server;
    for (const std::string length : {"18446744073709551616", "abc", "1\r\nContent-Length: 2"}) {
        raw_socket peer(server.port);
        peer.send_all("POST /ping HTTP/1.1\r\nHost: a\r\nContent-Length: " + length + "\r\n\r\nGET /ping HTTP/1.1\r\nHost: a\r\n\r\n");
        const auto answer = peer.read_until("\r\n\r\n", std::chrono::seconds(3));
        EXPECT_EQ(answer.rfind("HTTP/1.1 400 ", 0), 0u) << length << ": " << answer;
        EXPECT_NE(lowercase(answer).find("connection: close"), std::string::npos) << length << ": " << answer;
        EXPECT_TRUE(peer.closes_within(std::chrono::seconds(3))) << length;
    }
    EXPECT_EQ(server.request_count(), 0) << "a request whose length is refused, or the one it carried, was served";
}

// On the wire (Huly QB-1248): a malformed request -- a method that is no token -- is answered 400 with
// `Connection: close`, then the connection closes; nothing it carried is served. It closed with no answer.
TEST(Http1ClientTest, AMalformedRequestIsAnswered400ThenClosed) {
    LoopbackHttp1Server server;
    raw_socket          peer(server.port);
    peer.send_all("G@T /ping HTTP/1.1\r\nHost: a\r\n\r\nGET /ping HTTP/1.1\r\nHost: a\r\n\r\n");
    const auto answer = peer.read_until("\r\n\r\n", std::chrono::seconds(3));
    EXPECT_EQ(answer.rfind("HTTP/1.1 400 ", 0), 0u) << answer;
    EXPECT_NE(lowercase(answer).find("connection: close"), std::string::npos) << answer;
    EXPECT_TRUE(peer.closes_within(std::chrono::seconds(3)));
    EXPECT_EQ(server.request_count(), 0) << "the request after a malformed one was served";
}

// What follows a request the server answers, malformed or behind `Connection: close` (Huly QB-1248). After a request that
// carries "close" the server answers it and closes: nothing pipelined behind it is answered (RFC 9112 §9.6), a malformed
// request included, whose 400 would be a response the client had no right to -- llhttp's own refusal of data after
// `Connection: close` (HPE_CLOSED_CONNECTION) never comes, its parser stopping at each message's end and starting the next
// afresh. Behind a request still in flight, a malformed one is answered 400 after that request's response, which goes
// first: it closed the connection with no answer, before that response, which the client lost.
namespace http1_close_pipeline_test {
class Server;
class Session : public qb::http::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
};
class Server : public qb::http::use<Server>::server<Session> {
public:
    std::atomic<int> served{0};
    Server() {
        router().get("/now", [this](auto ctx) {
            ++served;
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router().get("/later", [this](auto ctx) { // answered 50 ms later: what follows it is read first
            ++served;
            qb::io::async::callback(
                [ctx]() {
                    ctx->response().status() = qb::http::status::OK;
                    ctx->complete();
                },
                std::chrono::milliseconds(50));
        });
        router().compile();
    }
};
Session::Session(Server &server)
    : session(server) {}

// The status of every response the peer reads before the connection ends, in order.
std::string
statuses(raw_socket &peer) {
    const auto  all = peer.read_until("\r\n\r\n\r\n\r\n", std::chrono::seconds(3)); // never sent: everything until the close
    std::string out;
    for (auto at = all.find("HTTP/1.1 "); at != std::string::npos; at = all.find("HTTP/1.1 ", at + 1))
        out += (out.empty() ? "" : " ") + all.substr(at + 9, 3);
    return out;
}
} // namespace http1_close_pipeline_test

TEST(Http1ClientTest, NothingPipelinedBehindAConnectionCloseRequestIsAnswered) {
    using namespace http1_close_pipeline_test;
    Server              *server = nullptr;
    ServerThread<Server> thread([&server](Server &s) {
        server = &s;
        if (s.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        s.start();
        return true;
    });
    ASSERT_TRUE(thread.ready());
    const std::string long_target = "GET /" + std::string(qb::http::protocol_limits::MAX_URL_LENGTH + 1, 'x') + " HTTP/1.1\r\nHost: a\r\n\r\n";
    for (const char *path : {"/now", "/later"}) {
        for (const std::string &behind : {std::string("GET /now HTTP/1.1\r\nHost: a\r\n\r\n"), std::string("garbage\r\n\r\n"), long_target}) {
            const int  before = server->served.load();
            raw_socket peer(thread.port());
            peer.send_all(std::string("GET ") + path + " HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n" + behind);
            EXPECT_EQ(statuses(peer), "200") << path << ", then " << behind.substr(0, 20);
            EXPECT_EQ(server->served.load() - before, 1)
                << path << ", then " << behind.substr(0, 20) << ": a request after the close was served";
        }
    }
}

TEST(Http1ClientTest, AResponseInFlightGoesOutBeforeTheRefusalOfTheMalformedRequestBehindIt) {
    using namespace http1_close_pipeline_test;
    ServerThread<Server> thread([](Server &s) {
        if (s.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        s.start();
        return true;
    });
    ASSERT_TRUE(thread.ready());
    raw_socket peer(thread.port());
    peer.send_all("GET /later HTTP/1.1\r\nHost: a\r\n\r\ngarbage\r\n\r\n");
    EXPECT_EQ(statuses(peer), "200 400") << "the response in flight was lost, or the malformed request not answered after it";
}

// The inactivity timeout restarts at a request's first byte and at each read of its body (Huly QB-1248): nginx's
// client_header_timeout and client_body_timeout, at the session's one timeout -- 1 s here, set by the session as an
// application's own may set it. Until 3.4 only the server's writes restarted it: a body sent slowly but steadily was cut
// with no answer, and a request begun just before the timeout of the last response had what was left of it. Each wait
// below is a watch for the close, so nothing is written to a connection the server has closed.
namespace http1_inactivity_timeout_test {
constexpr std::chrono::milliseconds kTimeout{1000};

class Server;
class Session : public qb::http::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
};
class Server : public qb::http::use<Server>::server<Session> {
public:
    Server() {
        router().post("/up", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = std::to_string(ctx->request().body().size());
            ctx->complete();
        });
        router().get("/", [](auto ctx) {
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router().compile();
    }
};
Session::Session(Server &server)
    : session(server) {
    this->setTimeout(kTimeout);
}

std::unique_ptr<qb::http::test::ServerThread<Server>>
start() {
    return std::make_unique<qb::http::test::ServerThread<Server>>([](Server &server) {
        if (server.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        server.start();
        return true;
    });
}

std::chrono::milliseconds
since(std::chrono::steady_clock::time_point from) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - from);
}
} // namespace http1_inactivity_timeout_test

TEST(Http1ClientTest, ABodySentSlowlyButSteadilyIsServed) {
    using namespace http1_inactivity_timeout_test;
    const auto thread = start();
    ASSERT_TRUE(thread->ready());
    for (const bool chunked : {false, true}) {
        raw_socket peer(thread->port());
        peer.send_all(chunked ? "POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n"
                              : "POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n");
        // Twelve pieces a quarter of the timeout apart: three timeouts in all, never one without a read.
        for (int piece = 0; piece < 12; ++piece) {
            ASSERT_FALSE(peer.closes_within(kTimeout / 4)) << (chunked ? "chunked" : "length") << ": cut after " << piece << " pieces";
            peer.send_all(chunked ? "1\r\nx\r\n" : "x");
        }
        if (chunked)
            peer.send_all("0\r\n\r\n");
        const auto answer = peer.read_until("\r\n\r\n", std::chrono::seconds(3));
        EXPECT_EQ(answer.rfind("HTTP/1.1 200 ", 0), 0u) << (chunked ? "chunked: " : "length: ") << answer;
    }
}

TEST(Http1ClientTest, ARequestBegunJustBeforeTheTimeoutHasItsWholeHeaderSection) {
    using namespace http1_inactivity_timeout_test;
    const auto thread = start();
    ASSERT_TRUE(thread->ready());
    raw_socket peer(thread->port());
    peer.send_all("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    ASSERT_EQ(peer.read_until("\r\n\r\n", std::chrono::seconds(3)).rfind("HTTP/1.1 200 ", 0), 0u);
    // Three quarters of the timeout after the response a request begins; its header section takes half a timeout more.
    ASSERT_FALSE(peer.closes_within(kTimeout * 3 / 4));
    peer.send_all("GET / HTTP/1.1\r\n");
    ASSERT_FALSE(peer.closes_within(kTimeout / 2)) << "the request was cut a timeout after the last response";
    peer.send_all("Host: a\r\n\r\n");
    const auto answer = peer.read_until("\r\n\r\n", std::chrono::seconds(3));
    EXPECT_EQ(answer.rfind("HTTP/1.1 200 ", 0), 0u) << answer;
}

// The controls: the timeout still bounds a header section from its first byte, a body from its last read, an idle
// connection from its last response.
TEST(Http1ClientTest, AHeaderSectionSentSlowlyStillEndsATimeoutAfterItsFirstByte) {
    using namespace http1_inactivity_timeout_test;
    const auto thread = start();
    ASSERT_TRUE(thread->ready());
    raw_socket peer(thread->port());
    const auto first = std::chrono::steady_clock::now();
    peer.send_all("GET / HTTP/1.1\r\n");
    for (const char *piece : {"X-Slow: a", "a", "a"}) { // a quarter of the timeout apart, all within it
        ASSERT_FALSE(peer.closes_within(kTimeout / 4));
        peer.send_all(piece);
    }
    ASSERT_TRUE(peer.closes_within(std::chrono::seconds(3))) << "a header section sent slowly kept its connection";
    const auto took = since(first);
    EXPECT_GE(took, kTimeout * 8 / 10) << took.count() << " ms";
    EXPECT_LT(took, kTimeout * 14 / 10) << "a read inside the header section restarted the timeout: " << took.count() << " ms";
}

TEST(Http1ClientTest, ABodyThatStallsEndsATimeoutAfterItsLastRead) {
    using namespace http1_inactivity_timeout_test;
    const auto thread = start();
    ASSERT_TRUE(thread->ready());
    raw_socket peer(thread->port());
    peer.send_all("POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nab");
    ASSERT_FALSE(peer.closes_within(kTimeout / 2));
    peer.send_all("cd");
    const auto last = std::chrono::steady_clock::now();
    ASSERT_TRUE(peer.closes_within(std::chrono::seconds(3))) << "a stalled body kept its connection";
    const auto took = since(last);
    EXPECT_GE(took, kTimeout * 8 / 10) << "cut before a timeout after the body's last read: " << took.count() << " ms";
    EXPECT_LT(took, kTimeout * 14 / 10) << took.count() << " ms";
}

TEST(Http1ClientTest, AnIdleConnectionStillEndsATimeoutAfterItsLastResponse) {
    using namespace http1_inactivity_timeout_test;
    const auto thread = start();
    ASSERT_TRUE(thread->ready());
    raw_socket peer(thread->port());
    peer.send_all("GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    ASSERT_EQ(peer.read_until("\r\n\r\n", std::chrono::seconds(3)).rfind("HTTP/1.1 200 ", 0), 0u);
    const auto answered = std::chrono::steady_clock::now();
    ASSERT_TRUE(peer.closes_within(std::chrono::seconds(3))) << "an idle connection was kept";
    const auto took = since(answered);
    EXPECT_GE(took, kTimeout * 8 / 10) << took.count() << " ms";
    EXPECT_LT(took, kTimeout * 14 / 10) << took.count() << " ms";
}

// The HTTP/1.1 clients' response body limit (Huly QB-1248): `qb::http1::Client::set_max_body_size()`, 0 = none, 100 MiB
// (`protocol_limits::MAX_BODY_SIZE`) by default and for the one-shot verbs. A response at the limit is delivered and one past
// it fails with a 502 that names the limit. Until 3.4 the persistent client had no setting, and neither client read a body
// of exactly 100 MiB: qb-io's generic message cap (QB_MAX_MESSAGE_SIZE, 100 MiB) cut the response, body and header section,
// before the parser's limit was reached -- a 502 "Connection closed", which every failure past the limit read as too.
namespace http1_body_limit_test {
constexpr std::size_t kMiB = std::size_t{1} << 20;

std::string
hex(std::size_t n) {
    std::string out;
    do {
        out.insert(out.begin(), "0123456789abcdef"[n & 15]);
        n >>= 4;
    } while (n);
    return out;
}

// Answers the one request it is sent with `head`, then `body` bytes of body -- in chunks of at most 1 MiB when `chunked` --
// written whole; closes after it when `close` (a close-delimited body ends there).
class BodyPeer {
public:
    BodyPeer(std::string head, std::size_t body, bool chunked, bool close)
        : _head(std::move(head))
        , _body(body)
        , _chunked(chunked)
        , _close(close) {
        if (_listener.listen_v4(0, "127.0.0.1") != 0 || _listener.set_nonblocking(true) != 0)
            throw std::runtime_error("body peer: listen failed");
        port    = _listener.local_endpoint().port();
        _thread = std::thread([this] { run(); });
    }
    ~BodyPeer() {
        _stop = true;
        _thread.join();
    }
    BodyPeer(BodyPeer const &)            = delete;
    BodyPeer &operator=(BodyPeer const &) = delete;

    [[nodiscard]] std::string
    url() const {
        return "http://127.0.0.1:" + std::to_string(port) + "/";
    }
    std::uint16_t port = 0;

private:
    void
    run() {
        const auto          deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        qb::io::tcp::socket peer;
        qb::http::test::peer_wait_until(
            [&] {
                if (_stop || peer.is_open())
                    return true;
                peer = _listener.accept();
                return peer.is_open();
            },
            deadline);
        // Read and written without blocking: against a client that has stopped reading and left the connection open, a
        // blocking write never returns and this thread is never joined -- the case would hang instead of failing.
        if (!peer.is_open() || peer.set_nonblocking(true) != 0)
            return;
        std::string request;
        char        buffer[1024];
        bool        gone = false; // the client closed, or its connection failed, before its request was whole
        // Each look reads what has come of the request.
        qb::http::test::peer_wait_until(
            [&] {
                if (_stop)
                    return true;
                const int n = peer.read(buffer, sizeof(buffer));
                if (n > 0)
                    request.append(buffer, static_cast<std::size_t>(n));
                else if (n == 0 || !qb::io::socket::not_recv_error(qb::io::socket::get_last_errno()))
                    gone = true;
                return gone || request.find("\r\n\r\n") != std::string::npos;
            },
            deadline);
        if (gone || request.find("\r\n\r\n") == std::string::npos)
            return;
        const auto put = [&](std::string_view bytes) {
            // Each look writes what the socket takes. It ends on all of it, on a client that closed (a body past its
            // limit), or once the case is over; at the deadline nobody reads any more.
            qb::http::test::peer_wait_until(
                [&] {
                    while (!bytes.empty()) {
                        const int n = peer.write(bytes.data(), bytes.size());
                        if (n > 0) {
                            bytes.remove_prefix(static_cast<std::size_t>(n));
                            continue;
                        }
                        return (n < 0 && !qb::io::socket::not_send_error(qb::io::socket::get_last_errno())) || _stop;
                    }
                    return true;
                },
                deadline);
            return bytes.empty();
        };
        const std::string piece(kMiB, 'b');
        bool              written = put(_head);
        std::size_t       left    = _body;
        // Each turn writes one piece of the body, at most 1 MiB of it.
        qb::http::test::peer_wait_until([&] { return !written || left == 0; }, deadline,
                                        [&] {
                                            const auto n = std::min(left, piece.size());
                                            if (_chunked) {
                                                written = put(hex(n) + "\r\n") && put(std::string_view(piece).substr(0, n)) && put("\r\n");
                                            } else
                                                written = put(std::string_view(piece).substr(0, n));
                                            left -= n;
                                        });
        if (written && _chunked)
            written = put("0\r\n\r\n");
        if (_close) {
            peer.close();
            return;
        }
        qb::http::test::peer_wait_until([this] { return _stop.load(); }, deadline,
                                        qb::http::test::fail_wait::nap{std::chrono::milliseconds(5)});
    }

    qb::io::tcp::listener _listener;
    std::string           _head;
    std::size_t           _body;
    bool                  _chunked;
    bool                  _close;
    std::atomic<bool>     _stop{false};
    std::thread           _thread;
};

enum class framing { length, chunked, close };

std::unique_ptr<BodyPeer>
peer(framing how, std::size_t body) {
    switch (how) {
        case framing::length:
            return std::make_unique<BodyPeer>("HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body) + "\r\n\r\n", body, false, false);
        case framing::chunked:
            return std::make_unique<BodyPeer>("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", body, true, false);
        case framing::close:
        default:
            return std::make_unique<BodyPeer>("HTTP/1.1 200 OK\r\n\r\n", body, false, true);
    }
}

// One GET through a persistent client whose limit is `limit` (none given: the default).
qb::http::Response
fetch(BodyPeer const &peer, std::optional<std::size_t> limit) {
    auto client = qb::http1::make_client(peer.url());
    client->set_request_timeout(std::chrono::seconds(30));
    if (limit)
        client->set_max_body_size(*limit);
    auto response = qb::http::run_sync(client->push_request(request(qb::http::method::GET, peer.url())));
    client->disconnect();
    return response;
}
} // namespace http1_body_limit_test

TEST(Http1ClientTest, ABodyOfExactlyTheDefaultLimitIsDelivered) {
    using namespace http1_body_limit_test;
    {
        const auto source   = peer(framing::length, qb::http::protocol_limits::MAX_BODY_SIZE);
        const auto response = fetch(*source, std::nullopt);
        EXPECT_EQ(response.status(), qb::http::status::OK) << response.body().as<std::string>().substr(0, 200);
        EXPECT_EQ(response.body().size(), qb::http::protocol_limits::MAX_BODY_SIZE);
    }
    const auto source = peer(framing::length, qb::http::protocol_limits::MAX_BODY_SIZE);
    auto       reply  = qb::http::run_sync(qb::http::GET(request(qb::http::method::GET, source->url()), std::chrono::seconds(30)));
    EXPECT_EQ(reply.response.status(), qb::http::status::OK) << "the one-shot verb cut a body of exactly its limit";
    EXPECT_EQ(reply.response.body().size(), qb::http::protocol_limits::MAX_BODY_SIZE);
    drain_client_callbacks();
}

TEST(Http1ClientTest, ABodyPastTheClientsLimitFailsWithAnErrorThatNamesIt) {
    using namespace http1_body_limit_test;
    // A response the limit cut comes from a server that is still sending it. The client closes that connection AT ONCE: it
    // does not hand the descriptor to its loop, to be read and dropped for linger() (Huly QB-1270) -- this thread runs no
    // loop pass once a fetch has returned, so a connection handed over would hold its server in its write.
    const auto closing = [] {
        return qb::io::async::detail::closing_sockets();
    };
    (void) qb::io::async::detail::release_closing_sockets(); // what the cases before left on this thread's loop
    for (const auto how : {framing::length, framing::chunked, framing::close}) {
        const auto source   = peer(how, 2048);
        const auto response = fetch(*source, 1024);
        EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY) << static_cast<int>(how);
        EXPECT_NE(response.body().as<std::string>().find("limit of 1024 bytes"), std::string::npos)
            << static_cast<int>(how) << ": " << response.body().as<std::string>();
        EXPECT_EQ(closing(), 0u) << static_cast<int>(how) << ": the connection of a refused body was handed to the loop, not closed at once";
    }
    {
        const auto source   = peer(framing::length, 1024); // the limit itself is accepted
        const auto response = fetch(*source, 1024);
        EXPECT_EQ(response.status(), qb::http::status::OK);
        EXPECT_EQ(response.body().size(), 1024u);
    }
    { // The control: a response the client fails for another reason -- a length that is no number -- ends a connection
        // whose server is not sending anything refused: that one is closed after its peer, by the loop.
        BodyPeer   malformed("HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n", 0, false, false);
        const auto response = fetch(malformed, 1024);
        EXPECT_NE(response.status(), qb::http::status::OK);
        EXPECT_EQ(response.body().as<std::string>().find("limit of"), std::string::npos) << "no bound cut this response";
        EXPECT_EQ(closing(), 1u) << "a failed response no longer leaves its connection to the loop: the zeros above prove nothing";
        (void) qb::io::async::detail::release_closing_sockets();
    }
    { // the default, unchanged: one byte past 100 MiB fails, now naming the limit
        const auto source   = peer(framing::length, qb::http::protocol_limits::MAX_BODY_SIZE + 1);
        const auto response = fetch(*source, std::nullopt);
        EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY);
        EXPECT_NE(response.body().as<std::string>().find("limit of " + std::to_string(qb::http::protocol_limits::MAX_BODY_SIZE) + " bytes"),
                  std::string::npos)
            << response.body().as<std::string>();
        EXPECT_EQ(closing(), 0u) << "a server sending 100 MiB to a client that refused them was left to the loop";
    }
    const auto source = peer(framing::length, qb::http::protocol_limits::MAX_BODY_SIZE + 1);
    auto       reply  = qb::http::run_sync(qb::http::GET(request(qb::http::method::GET, source->url()), std::chrono::seconds(30)));
    EXPECT_EQ(reply.response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_NE(reply.response.body().as<std::string>().find("limit of"), std::string::npos)
        << "the one-shot verb's error: " << reply.response.body().as<std::string>();
    EXPECT_EQ(closing(), 0u) << "the one-shot verb left the connection of a refused body to the loop";
    drain_client_callbacks();
}

TEST(Http1ClientTest, TheClientsBodyLimitRaisedOrNoneDeliversWhatTheDefaultRefuses) {
    using namespace http1_body_limit_test;
    auto client = qb::http1::make_client("http://127.0.0.1:1/");
    EXPECT_EQ(client->max_body_size(), qb::http::protocol_limits::MAX_BODY_SIZE);
    client->set_max_body_size(0);
    EXPECT_EQ(client->max_body_size(), 0u);
    for (const std::size_t limit : {qb::http::protocol_limits::MAX_BODY_SIZE + kMiB, std::size_t{0}}) {
        const auto source   = peer(framing::length, qb::http::protocol_limits::MAX_BODY_SIZE + 1);
        const auto response = fetch(*source, limit);
        EXPECT_EQ(response.status(), qb::http::status::OK) << "limit " << limit << ": " << response.body().as<std::string>().substr(0, 200);
        EXPECT_EQ(response.body().size(), qb::http::protocol_limits::MAX_BODY_SIZE + 1) << "limit " << limit;
    }
    drain_client_callbacks();
}

// The error names the bound that cut the response (Huly QB-1248): qb-io's read cap when the response, held whole in the
// connection's input buffer until it completes, filled it -- under a body limit of none, or one raised past the cap -- and
// the body limit only when the parser refused the body on it. A limit of none is never named.
TEST(Http1ClientTest, AResponseCutByTheReadBufferCapFailsNamingThatCap) {
    using namespace http1_body_limit_test;
    const std::size_t cap  = QB_MAX_READ_BUFFER_SIZE;
    const std::string none = std::to_string(std::numeric_limits<std::size_t>::max());
    for (const auto &[how, limit] : {std::pair{framing::close, std::size_t{0}}, std::pair{framing::length, cap + 64 * kMiB}}) {
        const auto source   = peer(how, cap + kMiB);
        const auto response = fetch(*source, limit);
        const auto error    = response.body().as<std::string>();
        EXPECT_EQ(response.status(), qb::http::status::BAD_GATEWAY) << "limit " << limit;
        EXPECT_NE(error.find("read buffer cap of " + std::to_string(cap) + " bytes"), std::string::npos) << "limit " << limit << ": " << error;
        EXPECT_EQ(error.find("client's limit"), std::string::npos) << "limit " << limit << ": the body limit named: " << error;
        EXPECT_EQ(error.find(none), std::string::npos) << "limit " << limit << ": " << error;
    }
    drain_client_callbacks();
}

// A response the client's body limit cut (Huly QB-1248): its failure callback runs once the connection is retired, as the
// callback of a response that closes the connection does (CloseResponseCallbackQueuesItsNextRequestOnANewConnection), so
// a request the callback pushes is never written to that connection. With automatic reconnection it goes to a new one;
// without, it is refused as that close ends, as after any other end of a connection. It was written to the dying connection while
// the client still read it as connected, and the disconnect that followed failed it: 502 "Connection closed". A request
// QUEUED behind the cut one goes the same way: out on the new connection, or failed once, 503 -- it was written to the dying
// connection first, and failed with it, 502. Its 503 reads "HTTP/1.1 client is not connected" when the callback itself
// switches reconnection off -- it waited for a connection that is then never made -- and "Connection lost" when
// reconnection was off before the cut: it ends with the connection it waited behind.
TEST(Http1ClientTest, ACallbackOfAResponseTheBodyLimitCutQueuesItsNextRequestOnANewConnection) {
    using namespace http1_callback_reentry_test;
    qb::io::async::init();
    for (const std::string_view policy : {"reconnects", "switched off in the callback", "off before the cut"}) {
        SCOPED_TRACE(policy);
        const bool          auto_reconnect = policy == "reconnects";
        LoopbackHttp1Server server;
        qb::http::Response  cut, queued;
        bool                connected_in_callback = true;
        int                 answered_in_callback  = -1; // the pushed request's answers by the time its push returned
        int                 queued_callbacks      = 0;
        auto                client                = qb::http1::make_client(server.url(""));
        auto                observed              = std::make_shared<Observation>();
        Cleanup             cleanup{client, observed};
        client->set_max_body_size(1024);
        if (policy == "off before the cut") { // a client that does not reconnect is connected by hand
            client->set_auto_reconnect(false);
            ASSERT_TRUE(client->connect([observed](bool ok, std::string const &) {
                if (!observed->cleaning)
                    observed->reconnected = ok;
            }));
            ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->reconnected; }));
        }
        auto big   = request(qb::http::method::POST, "/echo");
        big.body() = std::string(4096, 'x'); // echoed: a response body past the limit
        ASSERT_TRUE(client->push_request(std::move(big), [&, observed, auto_reconnect](auto response) {
            if (observed->cleaning)
                return;
            ++observed->closing_callbacks;
            cut                   = std::move(response);
            connected_in_callback = client->is_connected();
            client->set_auto_reconnect(auto_reconnect);
            EXPECT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [observed](auto result) {
                if (observed->cleaning)
                    return;
                observed->response = std::move(result);
                ++observed->new_callbacks;
            }));
            answered_in_callback = observed->new_callbacks;
        }));
        ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&, observed](auto response) { // queued behind it
            if (observed->cleaning)
                return;
            queued = std::move(response);
            ++queued_callbacks;
        }));
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return observed->new_callbacks != 0 && queued_callbacks != 0; }));
        EXPECT_EQ(observed->closing_callbacks, 1);
        EXPECT_EQ(queued_callbacks, 1);
        EXPECT_EQ(cut.status(), qb::http::status::BAD_GATEWAY);
        EXPECT_NE(cut.body().as<std::string>().find("limit of 1024 bytes"), std::string::npos) << cut.body().as<std::string>();
        EXPECT_FALSE(connected_in_callback) << "the cut must retire the connection before it calls user code";
        EXPECT_EQ(observed->new_callbacks, 1);
        if (auto_reconnect) {
            EXPECT_EQ(answered_in_callback, 0);
            EXPECT_EQ(observed->response.status(), qb::http::status::OK) << observed->response.body().as<std::string>();
            EXPECT_EQ(observed->response.body().as<std::string>(), "pong");
            EXPECT_EQ(queued.status(), qb::http::status::OK) << "the request queued behind the cut one: " << queued.body().as<std::string>();
            EXPECT_EQ(queued.body().as<std::string>(), "pong");
            EXPECT_EQ(server.connection_count(), 2);
        } else {
            // Refused once the callback has returned, inside the same close: never inside the push a callback of the client
            // makes, where a callback that pushes back at every failure was called from inside its own push (Huly QB-1246).
            EXPECT_EQ(answered_in_callback, 0) << "a request pushed from a callback of the client was answered inside its push";
            EXPECT_EQ(observed->response.status(), qb::http::status::SERVICE_UNAVAILABLE);
            EXPECT_EQ(observed->response.body().as<std::string>(), "HTTP/1.1 client is not connected");
            EXPECT_EQ(queued.status(), qb::http::status::SERVICE_UNAVAILABLE) << "the request queued behind the cut one";
            EXPECT_EQ(queued.body().as<std::string>(), policy == "off before the cut" ? "Connection lost" : "HTTP/1.1 client is not connected");
            EXPECT_EQ(server.connection_count(), 1);
        }
    }
}

// Framing on the wire: what is refused, and what closes its connection (Huly QB-1248; RFC 9112 §6.1, §6.3, §9.6; RFC 9110 §9.3.6).
namespace http1_framing_on_the_wire_test {
class Server;
class Session : public qb::http::use<Session>::session<Server> {
public:
    explicit Session(Server &server);
};
class Server : public qb::http::use<Server>::server<Session> {
public:
    std::atomic<int> served{0};
    Server() {
        router().post("/up", [this](auto ctx) {
            ++served;
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = ctx->request().body().template as<std::string>();
            ctx->complete();
        });
        router().get("/now", [this](auto ctx) {
            ++served;
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router().get("/persist", [this](auto ctx) { // the session's keep-alive override, set for what follows
            ++served;
            ctx->session()->keep_alive(true);
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });
        router().compile();
    }
};
Session::Session(Server &server)
    : session(server) {}

// Everything the peer reads until the connection ends (the marker is never sent).
std::string
until_close(raw_socket &peer) {
    return peer.read_until("\r\n\r\n\r\n\r\n", std::chrono::seconds(3));
}

// The status of every response in `all`, in order, whatever version its status line carries.
std::string
statuses(std::string const &all) {
    std::string out;
    for (auto at = all.find("HTTP/1."); at != std::string::npos; at = all.find("HTTP/1.", at + 1))
        if (at + 12 <= all.size() && all[at + 8] == ' ')
            out += (out.empty() ? "" : " ") + all.substr(at + 9, 3);
    return out;
}

// What a connection that stays open answers, read until the statuses of @p expected are in: @p reads reads at most, of
// three seconds each.
std::string
read_statuses(raw_socket &peer, std::string_view expected, int reads) {
    std::string all;
    int         made = 0;
    qb::http::test::wait_until([&] { return made == reads || statuses(all).size() >= expected.size(); },
                               std::chrono::seconds(3) * reads + std::chrono::seconds(2), "read_statuses",
                               [&] {
                                   all += peer.read_until("\r\n\r\n", std::chrono::seconds(3));
                                   ++made;
                               });
    return all;
}

const std::string http10_chunked =
    "POST /up HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
} // namespace http1_framing_on_the_wire_test

// An HTTP/1.0 request with Transfer-Encoding (RFC 9112 §6.1): its framing is treated as faulty -- it is served, its chunked
// body read -- and its connection closes after it, `Connection: keep-alive` and the session's keep-alive override
// notwithstanding: nothing pipelined behind it is served. The connection was kept, and the request behind it served.
TEST(Http1ClientTest, AnHttp10RequestWithTransferEncodingIsServedThenItsConnectionCloses) {
    using namespace http1_framing_on_the_wire_test;
    Server              *server = nullptr;
    ServerThread<Server> thread([&server](Server &s) {
        server = &s;
        if (s.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        s.start();
        return true;
    });
    ASSERT_TRUE(thread.ready());
    { // The control: the same keep-alive request framed by its length keeps its connection.
        raw_socket peer(thread.port());
        peer.send_all("POST /up HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\nContent-Length: 3\r\n\r\nabc"
                      "GET /now HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        EXPECT_EQ(statuses(until_close(peer)), "200 200");
    }
    {
        const int  before = server->served.load();
        raw_socket peer(thread.port());
        peer.send_all(http10_chunked + "GET /now HTTP/1.1\r\nHost: a\r\n\r\n");
        const auto all = until_close(peer);
        EXPECT_EQ(statuses(all), "200") << all;
        EXPECT_NE(all.find("abc"), std::string::npos) << "the request is served, its body read: " << all;
        EXPECT_EQ(server->served.load() - before, 1) << "the request pipelined behind it was served";
        EXPECT_TRUE(peer.closes_within(std::chrono::seconds(1))) << "the connection stayed open";
    }
    // Under the session's keep-alive override, set by the request before it: with `Connection: keep-alive`, and with no
    // Connection field at all -- the silence the override fills for a request framed by its length (the control below).
    for (const std::string &chunked10 :
         {http10_chunked, std::string("POST /up HTTP/1.0\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")}) {
        const int  before = server->served.load();
        raw_socket peer(thread.port());
        peer.send_all("GET /persist HTTP/1.1\r\nHost: a\r\n\r\n" + chunked10 + "GET /now HTTP/1.1\r\nHost: a\r\n\r\n");
        const auto all = until_close(peer);
        EXPECT_EQ(statuses(all), "200 200") << chunked10 << all;
        EXPECT_EQ(server->served.load() - before, 2) << "the override kept the connection of an HTTP/1.0 message with Transfer-Encoding";
        EXPECT_TRUE(peer.closes_within(std::chrono::seconds(1))) << "the connection stayed open";
    }
    { // The control: what the override is for, it keeps -- an HTTP/1.0 request framed by its length that asks nothing. The
        // connection stays open: the three answers are read, not its end.
        raw_socket peer(thread.port());
        peer.send_all("GET /persist HTTP/1.1\r\nHost: a\r\n\r\nPOST /up HTTP/1.0\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc"
                      "GET /now HTTP/1.1\r\nHost: a\r\n\r\n");
        const std::string all = read_statuses(peer, "200 200 200", 6);
        EXPECT_EQ(statuses(all), "200 200 200") << all;
    }
}

// A request that carries the `close` connection option ends its connection after its response (RFC 9112 §9.6: a server
// that receives it MUST initiate the closure), under the session's keep-alive override too: the answer says
// `Connection: close`, the connection closes, and nothing pipelined behind it is served. The override kept the
// connection, and served what followed. It now fills a silence only: it keeps no request that carries a Connection
// field, whatever the options it names -- nor one that carries a Proxy-Connection field, which the parser reads as
// Connection: `Proxy-Connection: close` on an HTTP/1.1 request ends its connection, with a Transfer-Encoding as without.
TEST(Http1ClientTest, TheKeepAliveOverrideNeverKeepsARequestThatSaysClose) {
    using namespace http1_framing_on_the_wire_test;
    Server              *server = nullptr;
    ServerThread<Server> thread([&server](Server &s) {
        server = &s;
        if (s.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        s.start();
        return true;
    });
    ASSERT_TRUE(thread.ready());
    for (const std::string &closing :
         {std::string("GET /now HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"),
          std::string("GET /now HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, Close\r\n\r\n"), // one option of a list, any case
          std::string("POST /up HTTP/1.1\r\nHost: a\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"),
          std::string("GET /now HTTP/1.0\r\nHost: a\r\nConnection: close\r\n\r\n"),
          std::string("GET /now HTTP/1.0\r\nHost: a\r\nConnection: te\r\n\r\n"), // the field, and no `keep-alive`: no silence to fill
          std::string("GET /now HTTP/1.1\r\nHost: a\r\nProxy-Connection: close\r\n\r\n"),
          std::string("POST /up HTTP/1.1\r\nHost: a\r\nProxy-Connection: close\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"),
          std::string("GET /now HTTP/1.0\r\nHost: a\r\nProxy-Connection: te\r\n\r\n"),
          std::string("GET /now HTTP/1.0\r\nHost: a\r\nConnection: keep-alive, close\r\n\r\n"), // `close` first (§9.3)
          std::string("GET /now HTTP/1.1\r\nHost: a\r\nConnection: close\t\r\n\r\n")}) {        // whitespace after the option
        const int  before = server->served.load();
        raw_socket peer(thread.port());
        peer.send_all("GET /persist HTTP/1.1\r\nHost: a\r\n\r\n" + closing + "GET /now HTTP/1.1\r\nHost: a\r\n\r\n");
        const auto all = until_close(peer);
        EXPECT_EQ(statuses(all), "200 200") << closing << all;
        EXPECT_NE(lowercase(all).find("connection: close"), std::string::npos) << closing << all;
        EXPECT_EQ(server->served.load() - before, 2) << closing << "the request pipelined behind a request that said close was served";
        EXPECT_TRUE(peer.closes_within(std::chrono::seconds(1))) << closing << "the connection stayed open";
    }
    // The controls: under the override, a request that says nothing of the connection keeps it, HTTP/1.1 or HTTP/1.0; one
    // that asks to be kept through Proxy-Connection is; and an HTTP/1.1 request with a Transfer-Encoding keeps its connection.
    for (const std::string &kept :
         {std::string("GET /now HTTP/1.1\r\nHost: a\r\n\r\n"), std::string("GET /now HTTP/1.0\r\nHost: a\r\n\r\n"),
          std::string("GET /now HTTP/1.1\r\nHost: a\r\nConnection: closed\r\n\r\n"), // no option of that name
          std::string("GET /now HTTP/1.1\r\nHost: a\r\nProxy-Connection: keep-alive\r\n\r\n"),
          std::string("GET /now HTTP/1.0\r\nHost: a\r\nProxy-Connection: keep-alive\r\n\r\n"),
          std::string("POST /up HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")}) {
        raw_socket peer(thread.port());
        peer.send_all("GET /persist HTTP/1.1\r\nHost: a\r\n\r\n" + kept + "GET /now HTTP/1.1\r\nHost: a\r\n\r\n");
        const std::string all = read_statuses(peer, "200 200 200", 6);
        EXPECT_EQ(statuses(all), "200 200 200") << kept << all;
    }
}

// `close` has precedence over `keep-alive` on every version (RFC 9112 §9.3), and an option of Connection ends at the
// whitespace after it, a HTAB as a SP (RFC 9110 §5.6.3): a request that says `close` either way is answered, its answer says
// `Connection: close`, its connection closes, and nothing pipelined behind it is served (Huly QB-1248). An HTTP/1.0
// request that named both options was kept -- only `keep-alive` was read below HTTP/1.1 -- and an option followed by a HTAB
// was not read at all: `close<HTAB>` kept an HTTP/1.1 connection, `keep-alive<HTAB>` closed an HTTP/1.0 one.
TEST(Http1ClientTest, ARequestThatSaysCloseEndsItsConnectionWhateverElseItsConnectionFieldSays) {
    using namespace http1_framing_on_the_wire_test;
    Server              *server = nullptr;
    ServerThread<Server> thread([&server](Server &s) {
        server = &s;
        if (s.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        s.start();
        return true;
    });
    ASSERT_TRUE(thread.ready());
    for (const std::string &closing :
         {std::string("GET /now HTTP/1.0\r\nHost: a\r\nConnection: keep-alive, close\r\n\r\n"),
          std::string("GET /now HTTP/1.0\r\nHost: a\r\nConnection: Close, Keep-Alive\r\n\r\n"),
          std::string("GET /now HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n"),
          std::string("GET /now HTTP/1.0\r\nHost: a\r\nProxy-Connection: keep-alive, close\r\n\r\n"),
          std::string("GET /now HTTP/1.1\r\nHost: a\r\nConnection: close\t\r\n\r\n"),
          std::string("GET /now HTTP/1.1\r\nHost: a\r\nConnection: close \t \r\n\r\n"),
          std::string("GET /now HTTP/1.1\r\nHost: a\r\nConnection: te\t,\tclose\t\r\n\r\n")}) {
        const int  before = server->served.load();
        raw_socket peer(thread.port());
        peer.send_all(closing + "GET /now HTTP/1.1\r\nHost: a\r\n\r\n");
        const auto all = until_close(peer);
        EXPECT_EQ(statuses(all), "200") << closing << all;
        EXPECT_NE(lowercase(all).find("connection: close"), std::string::npos) << closing << all;
        EXPECT_EQ(server->served.load() - before, 1) << closing << "the request pipelined behind a request that said close was served";
        EXPECT_TRUE(peer.closes_within(std::chrono::seconds(1))) << closing << "the connection stayed open";
    }
    // Kept: an HTTP/1.0 request that asks for it -- a HTAB after the option included, which closed its connection -- and an
    // HTTP/1.1 request whose field names no `close` option, whatever follows a name that starts like it.
    for (const std::string &kept :
         {std::string("GET /now HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n"),
          std::string("GET /now HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\t\r\n\r\n"),
          std::string("GET /now HTTP/1.1\r\nHost: a\r\nConnection: closed\t\r\n\r\n"),
          std::string("GET /now HTTP/1.1\r\nHost: a\r\nConnection: close\tx\r\n\r\n")}) { // one option, `close<HTAB>x`: not `close`
        raw_socket peer(thread.port());
        peer.send_all(kept + "GET /now HTTP/1.1\r\nHost: a\r\n\r\n");
        const std::string all = read_statuses(peer, "200 200", 4);
        EXPECT_EQ(statuses(all), "200 200") << kept << all;
    }
}

// An HTTP/2 connection preface sent to this HTTP/1.1 server is answered 400, then the connection closes, whatever its
// target (RFC 9112 §2.2; Huly QB-1248). The preface a client sends (`PRI * HTTP/2.0`, RFC 9113 §3.4) is refused at its
// target, before and after this change. One whose target names a resource (`PRI /x HTTP/2.0`) passes that check and stops
// llhttp at its `SM` line, before any field: the connection was closed with no answer.
TEST(Http1ClientTest, AnHttp2PrefaceIsAnswered400WhateverItsTarget) {
    LoopbackHttp1Server server;
    for (const char *target : {"*", "/x", "/ping"}) {
        raw_socket peer(server.port);
        peer.send_all(std::string("PRI ") + target + " HTTP/2.0\r\n\r\nSM\r\n\r\n");
        const auto answer = peer.read_until("\r\n\r\n", std::chrono::seconds(3));
        EXPECT_EQ(answer.rfind("HTTP/1.1 400 ", 0), 0u) << target << ": " << answer;
        EXPECT_NE(lowercase(answer).find("connection: close"), std::string::npos) << target << ": " << answer;
        EXPECT_TRUE(peer.closes_within(std::chrono::seconds(3))) << target;
    }
    EXPECT_EQ(server.request_count(), 0);
}

// A CONNECT has no content (RFC 9110 §9.3.6): one that declares some -- a transfer coding, or a Content-Length other than
// 0 -- is answered 400, then the connection closes, nothing it carried served. One that named `chunked` was routed at the
// end of its header section -- llhttp completes a CONNECT there -- and what followed was read as the next request of the
// connection: a request written right behind the header section was served. One that named `gzip, chunked` was answered
// 501. One that declared a length had that many octets read as its content: a request written behind its header section
// was swallowed, where llhttp, and a peer that ends a CONNECT at its header section, see the next request. A CONNECT that
// declares none -- no field, or a Content-Length of 0 -- is routed as before: here, to no route.
TEST(Http1ClientTest, AConnectRequestThatDeclaresContentIsAnswered400ThenClosed) {
    LoopbackHttp1Server                                    server;
    const std::string                                      next  = "GET /ping HTTP/1.1\r\nHost: a\r\n\r\n";
    const std::vector<std::pair<std::string, std::string>> table = {
        {"Transfer-Encoding: chunked", next}, // the next request right behind the header section
        {"Transfer-Encoding: chunked", "0\r\n\r\n" + next},
        {"Transfer-Encoding: chunked", "3\r\nabc\r\n0\r\n\r\n" + next},
        {"Transfer-Encoding: chunked", "3\r\nabc\r\n" + next},
        {"Transfer-Encoding: gzip, chunked", "0\r\n\r\n" + next},
        {"Content-Length: 32", "GET /admin HTTP/1.1\r\nHost: a\r\n\r\n"}, // 32 octets: a request, or this one's content
        {"Content-Length: 3", "abc" + next},
        {"Content-Length: 1", ""}, // declared, and not sent
    };
    for (const auto &[field, after] : table) {
        raw_socket peer(server.port);
        peer.send_all("CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n" + field + "\r\n\r\n" + after);
        const auto answer = peer.read_until("\r\n\r\n", std::chrono::seconds(3));
        EXPECT_EQ(answer.rfind("HTTP/1.1 400 ", 0), 0u) << field << " " << after.size() << ": " << answer;
        EXPECT_NE(lowercase(answer).find("connection: close"), std::string::npos) << field << " " << after.size() << ": " << answer;
        EXPECT_TRUE(peer.closes_within(std::chrono::seconds(3))) << field << " " << after.size();
    }
    EXPECT_EQ(server.request_count(), 0) << "a request a refused CONNECT carried was served";
    for (const char *none : {"", "Content-Length: 0\r\n"}) { // the controls
        raw_socket peer(server.port);
        peer.send_all(std::string("CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n") + none + "\r\n");
        const auto answer = peer.read_until("\r\n\r\n", std::chrono::seconds(3));
        EXPECT_EQ(answer.rfind("HTTP/1.1 404 ", 0), 0u) << none << answer;
    }
}

// `chunked` applied twice is no framing (RFC 9112 §6.1: a sender applies it once): 400 whether the field names it twice on
// one line or one field line names it after another -- llhttp refuses both, before and after this change, and the
// parser's own scan now agrees (TheParsersOwnScanRefusesChunkedNamedTwiceWith400). Another coding before a final
// `chunked` is 501 (§6.1).
TEST(Http1ClientTest, ATransferEncodingThatNamesChunkedTwiceIsAnswered400) {
    LoopbackHttp1Server                                    server;
    const std::vector<std::pair<std::string, std::string>> table = {
        {"Transfer-Encoding: chunked, chunked", "400"},
        {"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked", "400"},
        {"Transfer-Encoding: chunked, gzip\r\nTransfer-Encoding: chunked", "400"},
        {"Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked", "501"},
        {"Transfer-Encoding: gzip, chunked", "501"},
    };
    for (auto const &[fields, status] : table) {
        raw_socket peer(server.port);
        peer.send_all("POST /echo HTTP/1.1\r\nHost: a\r\n" + fields + "\r\n\r\n0\r\n\r\n");
        const auto answer = peer.read_until("\r\n\r\n", std::chrono::seconds(3));
        EXPECT_EQ(answer.substr(0, 13), "HTTP/1.1 " + status + " ") << fields << ": " << answer;
        EXPECT_TRUE(peer.closes_within(std::chrono::seconds(3))) << fields;
    }
    EXPECT_EQ(server.request_count(), 0);
}

// An HTTP/1.0 response with Transfer-Encoding that asks to be kept (RFC 9112 §6.1; Huly QB-1248): the persistent client
// reads it, then retires its connection -- the next request goes to a new one. It kept the connection. The control, the
// same response framed by its length, keeps it. An interim response counts: `HTTP/1.0 100 Continue` that names a coding
// is such a message, and the connection is retired after the final response, whatever that one says -- it was kept, the
// client returning on a 1xx before it looked. The controls: an HTTP/1.0 interim response that names none, and an HTTP/1.1
// one that names `chunked`, keep the connection.
TEST(Http1ClientTest, AnHttp10ResponseWithTransferEncodingRetiresItsConnection) {
    using http1_switched_protocols_test::pong;
    const std::string kept10 = "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok";
    for (auto const &[head, connections] : std::vector<std::pair<std::string, int>>{
             {"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n", 2},
             {kept10, 1},
             {"HTTP/1.0 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\n" + kept10, 2},
             {"HTTP/1.0 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 2},
             {"HTTP/1.0 100 Continue\r\n\r\n" + kept10, 1},
             {"HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 1}
         }) {
        http1_head_no_length_test::ScriptedPeer peer({head, pong});
        auto                                    client = qb::http1::make_client(peer.url("/"));
        client->set_request_timeout(std::chrono::seconds(3));
        std::vector<qb::http::Request> queued;
        queued.push_back(request(qb::http::method::GET, "/first"));
        queued.push_back(request(qb::http::method::GET, "/ping"));
        auto replies = qb::http::run_sync(client->push_requests(std::move(queued)));
        ASSERT_EQ(replies.size(), 2u) << head;
        EXPECT_EQ(replies[0].status(), qb::http::status::OK) << head;
        EXPECT_EQ(replies[0].body().template as<std::string>(), "ok") << head;
        EXPECT_EQ(replies[1].body().template as<std::string>(), "pong") << head;
        EXPECT_EQ(peer.connections.load(), connections) << head;
        drain_client_callbacks();
    }
}

// run_sync(client->connect()) from the failure callback of a response the body limit cut completes `false`, and the next
// request is served: the cut retires the connection before its callback, as every other end does (Huly QB-1246, QB-1248).
TEST(Http1ClientTest, ARunSyncOfConnectFromTheCallbackOfACutResponseReturnsFalseAtOnce) {
    qb::io::async::init();
    LoopbackHttp1Server                  server;
    http1_run_sync_connect_test::Blocked blocked;
    int                                  answered = 0, pinged = 0;
    bool                                 connected_in_callback = true;
    qb::http::status                     cut = qb::http::status::OK, status = qb::http::status::INTERNAL_SERVER_ERROR;
    auto                                 client = qb::http1::make_client(server.url(""));
    client->set_max_body_size(1024);
    auto big   = request(qb::http::method::POST, "/echo");
    big.body() = std::string(4096, 'x');
    ASSERT_TRUE(client->push_request(std::move(big), [&](qb::http::Response response) {
        ++answered;
        cut                   = response.status();
        connected_in_callback = client->is_connected();
        blocked.run(*client, "the callback of a response the body limit cut");
    }));
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return answered != 0; }));
    EXPECT_EQ(cut, qb::http::status::BAD_GATEWAY);
    EXPECT_FALSE(connected_in_callback);
    ASSERT_TRUE(blocked.returned);
    EXPECT_FALSE(blocked.result.ok);
    EXPECT_EQ(blocked.result.error_message, "HTTP/1.1 connection is closing");
    ASSERT_TRUE(client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response response) {
        ++pinged;
        status = response.status();
    }));
    EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return pinged != 0; }, 2s));
    EXPECT_EQ(status, qb::http::status::OK);
    client->disconnect();
    drain_client_callbacks();
}

// While the destructor hears what the client still owes, an answer the loop brings takes its place behind it, as in
// ordinary operation (Huly QB-1246). Two refusals are owed when the last reference goes; the callback of the first runs
// the loop, and the response of a request in flight comes in that loop. The order the client came to owe them is the
// first refusal (1; -1 marks the end of its callback), the second (2), then the response (9). The response was given at
// once, under the first callback and ahead of the second refusal: 1 9 -1 2.
TEST(Http1ClientTest, AResponseThatComesWhileTheDestructorHearsWhatIsOwedTakesItsPlaceBehindIt) {
    using http1_client_lifetime_test::Told;
    LoopbackHttp1Server server;
    int                 destroyed = 0; // before the client: its callbacks write here
    bool                up        = false;
    std::vector<int>    order;
    const auto          elsewhere = [] {
        return request(qb::http::method::GET, "http://elsewhere.invalid/x");
    }; // refused at once: another origin; before the client, as everything its callbacks reach
    DestroyedOnReturn     ended{destroyed}; // a case whose wait fails returns before the loop has destroyed the client
    std::shared_ptr<Told> client(new Told(server.url("/"), destroyed));
    auto *const           raw = client.get();
    raw->connect([&](bool ok, std::string const &) { up = ok; });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return up; }));
    raw->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) { order.push_back(9); }); // in flight
    raw->push_request(elsewhere(), [&, raw](qb::http::Response) {                                                // inside the program's push
        raw->push_request(elsewhere(), [&](qb::http::Response) {                                                 // owed first
            order.push_back(1);
            const auto until = std::chrono::steady_clock::now() + 150ms;
            while (std::chrono::steady_clock::now() < until) {
                qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT); // the response comes in this loop
            }
            order.push_back(-1);
        });
        raw->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // owed second
    });
    client.reset(); // the last reference of the program: the hold of the callback above runs on the next loop turn
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return destroyed == 1; }));
    drain_client_callbacks();
    EXPECT_EQ(order, (std::vector<int>{1, -1, 2, 9})) << "an answer the loop brought was given ahead of one still owed";
}

// And so does an answer the client gives by itself there: the destructor has one rule, the order the client came to owe
// its answers (Huly QB-1246). Two refusals are owed when the last reference goes; the callback of the first calls
// disconnect(), which ends a request in flight. That failure (9) takes its place behind the second refusal (2), as it
// would in ordinary operation. It was given inside the disconnect(), ahead of it: 1 9 -1 2.
TEST(Http1ClientTest, ADisconnectFromACallbackTheDestructorHearsGivesItsFailuresBehindWhatIsOwed) {
    using http1_client_lifetime_test::Told;
    LoopbackHttp1Server server;
    int                 destroyed = 0; // before the client: its callbacks write here
    bool                up        = false;
    std::vector<int>    order;
    const auto          elsewhere = [] {
        return request(qb::http::method::GET, "http://elsewhere.invalid/x");
    }; // refused at once: another origin; before the client, as everything its callbacks reach
    DestroyedOnReturn     ended{destroyed}; // a case whose wait fails returns before the loop has destroyed the client
    std::shared_ptr<Told> client(new Told(server.url("/"), destroyed));
    auto *const           raw = client.get();
    raw->connect([&](bool ok, std::string const &) { up = ok; });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return up; }));
    raw->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) { order.push_back(9); }); // in flight
    raw->push_request(elsewhere(), [&, raw](qb::http::Response) {                                                // inside the program's push
        raw->push_request(elsewhere(), [&, raw](qb::http::Response) {                                            // owed first
            order.push_back(1);
            raw->disconnect(); // ends the request in flight
            order.push_back(-1);
        });
        raw->push_request(elsewhere(), [&](qb::http::Response) { order.push_back(2); }); // owed second
    });
    client.reset(); // the last reference of the program: the hold of the callback above runs on the next loop turn
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return destroyed == 1; }));
    drain_client_callbacks();
    EXPECT_EQ(order, (std::vector<int>{1, -1, 2, 9})) << "an answer the client gave by itself was given ahead of one still owed";
}

// An empty batch pushed from a callback the destructor runs follows the destructor's rule, as a request does (Huly
// QB-1246): it is answered inside the push, and one pushed from inside that answer is refused by the return value alone,
// its callback unheard. An empty batch pushed back from its own callback had no end there: a hundred calls, a hundred
// deep, where the case stops it.
TEST(Http1ClientTest, AnEmptyBatchPushedBackFromTheDestructorsCallbacksEndsAtItsSecondPush) {
    LoopbackHttp1Server   server;
    int                   calls = 0, depth = 0, deepest = 0;
    std::vector<bool>     accepted;
    qb::http1::Client    *raw = nullptr;
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
        auto client = qb::http1::make_client(server.url("/"));
        raw         = client.get();
        client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) { push_empty(); }); // fails with the client
        ASSERT_TRUE(client->is_connecting()); // queued behind the connection it asked for
    } // destroyed with that request waiting
    drain_client_callbacks();
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(deepest, 1);
    EXPECT_EQ(accepted, (std::vector<bool>{true, false}));
}

// A run_sync() of a coroutine push made from a callback the client's turn hears completes. The refusal it awaits is
// kept for the client's next turn -- a callback of the client is on the stack --, and the loop run_sync() runs brings
// that turn from the loop's deferred queue, whose drain is still running the first turn. qb-io runs deferred callbacks
// under a nested turn (Huly QB-1246, in qb): where that drain does not nest, this wait never ends -- the one queue of
// owed answers needs that drain, and must not be used without it.
TEST(Http1ClientTest, ARunSyncOfACoroutinePushFromACallbackTheClientsTurnHearsCompletes) {
    LoopbackHttp1Server server;
    bool                done      = false; // before the client: its callbacks write here
    qb::http::status    status    = qb::http::status::OK;
    const auto          elsewhere = [] {
        return request(qb::http::method::GET, "http://elsewhere.invalid/x");
    }; // refused at once: another origin
    auto           client = qb::http1::make_client(server.url("/"));
    UnheldOnReturn unheld{client}; // a case whose wait fails returns with a refusal owed, and the client kept for it
    client->push_request(elsewhere(), [&](qb::http::Response) {     // answered inside the program's push
        client->push_request(elsewhere(), [&](qb::http::Response) { // kept: heard by the client's turn
            qb::http::test::watchdog bound("run_sync() of a coroutine push from a callback the client's turn hears", 5s);
            status = qb::io::async::run_sync(client->push_request(elsewhere())).status();
            done   = true;
        });
    });
    EXPECT_FALSE(done) << "a refusal of a push made from a callback was heard inside the push";
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return done; }));
    EXPECT_EQ(status, qb::http::status::BAD_REQUEST);
}

namespace http1_client_target_test {
/// Targets no client may send: a query that carries SP, a control byte or DEL as written (the path of a URI holds path
/// characters only: such a byte there fails the parse, and the URI names no target).
struct UnsendableTarget {
    std::string_view what;
    std::string      target;
};
inline const UnsendableTarget k_unsendable_targets[] = {
    {"LF in the query", std::string("/ping?q=a\nb")},
    {"CR in the query", std::string("/ping?q=a\rb")},
    {"0x1F in the query", std::string("/ping?q=a\x1F") + "b"},
    {"DEL in the query", std::string("/ping?q=a\x7F") + "b"},
    {"SP in the query", std::string("/ping?q=a b")},
    {"LF in the path", std::string("/ping/a\nb")},
    {"CR in the path", std::string("/ping/a\rb")},
    {"0x1F in the path", std::string("/ping/a\x1F") + "b"},
    {"DEL in the path", std::string("/ping/a\x7F") + "b"},
    {"SP in the path", std::string("/ping/a b")},
};
} // namespace http1_client_target_test

// A request whose target cannot be sent is refused where it is pushed, 400, as a refusal the client gives by itself, and
// costs nothing else (Huly QB-1246): the connection stays, what it carries goes on, the next request is served on it.
// The check is the HTTP/1.1 serializer's, shared by the three clients. On HTTP/1.1 a query the serializer refuses was answered only once the
// request's turn to be written came, a connection made for it; and a URI that failed to parse was made absolute and
// sent, to another resource than the one asked for.
TEST(Http1ClientTest, ARequestWhoseTargetCannotBeSentIsRefusedWhereItIsPushed) {
    for (const auto &row : http1_client_target_test::k_unsendable_targets) {
        SCOPED_TRACE(row.what);
        LoopbackHttp1Server server;
        int                 refused = 0, served = 0; // before the client: its callbacks count here
        bool                connected = false;
        qb::http::status    status    = qb::http::status::OK;
        std::string         body;
        auto                client = qb::http1::make_client(server.url("/"));
        client->connect([&](bool ok, std::string const &) { connected = ok; });
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected && server.connection_count() == 1; }));
        const auto requests = server.request_count();
        EXPECT_TRUE(client->push_request(request(qb::http::method::GET, row.target), [&](qb::http::Response response) {
            ++refused;
            status = response.status();
            body   = response.body().as<std::string>();
        }));
        EXPECT_EQ(refused, 1) << "the request was not refused where it was pushed";
        EXPECT_EQ(status, qb::http::status::BAD_REQUEST) << body;
        EXPECT_NE(body.find("cannot be sent"), std::string::npos) << body;
        EXPECT_TRUE(client->is_connected());
        client->push_request(request(qb::http::method::GET, "/ping"),
                             [&](qb::http::Response response) { served += response.status() == qb::http::status::OK ? 1 : 0; });
        EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return served == 1; }));
        EXPECT_EQ(refused, 1);
        EXPECT_EQ(server.connection_count(), 1) << "the refusal cost the connection";
        EXPECT_EQ(server.request_count(), requests + 1) << "the server was sent the request that was refused";
        client->disconnect();
    }
}

// A close calls every callback it owes, whatever one of them throws (Huly QB-1246). On HTTP/1.1 nothing a callback
// throws leaves the client: it is logged, and the close goes on -- three requests wait for a connection nobody answers,
// the program disconnects, the callback of the first throws, and the two others hear all the same; a connect() asked
// afterwards starts. (The HTTP/2 client let the exception out at once: the two others were never answered, and no later
// connect() could start.)
TEST(Http1ClientTest, ADisconnectWhoseFirstCallbackThrowsStillAnswersTheOthers) {
    LoopbackHttp1Server server;
    int                 first = 0, second = 0, third = 0, served = 0; // before the client: its callbacks count here
    bool                connected = false;
    auto                client    = qb::http1::make_client(server.url("/"));
    client->connect([&](bool ok, std::string const &) { connected = ok; });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
    client->push_request(request(qb::http::method::GET, "/never"), [&](qb::http::Response) { // in flight
        ++first;
        throw std::runtime_error("the first failure callback throws");
    });
    client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) { ++second; }); // queued behind it
    client->push_request(request(qb::http::method::GET, "/ping"), [&](qb::http::Response) { ++third; });
    EXPECT_NO_THROW(client->disconnect());
    EXPECT_EQ(first, 1);
    EXPECT_EQ(second + third, 2) << "the requests behind the one whose callback threw were not answered";
    client->push_request(request(qb::http::method::GET, "/ping"),
                         [&](qb::http::Response response) { served += response.status() == qb::http::status::OK ? 1 : 0; });
    EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return served == 1; })) << "the client was left unable to connect";
    EXPECT_EQ(first + second + third, 3) << "a request was answered twice";
    client->disconnect();
}

// A target longer than the serializer allows is refused where it is pushed, as the two other clients refuse it, and one
// at the limit is sent (Huly QB-1246): the shared check measures what serialize_request() measures, the path and the
// query together against MAX_URL_LENGTH. It was refused only where the request was written, once its turn had come:
// queued behind a request in flight, it was not answered where it was pushed.
TEST(Http1ClientTest, ATargetPastTheUrlLimitIsRefusedWhereItIsPushedAndOneAtTheLimitIsSent) {
    LoopbackHttp1Server server;
    int                 refused = 0, sent = 0, never = 0; // before the client: its callbacks count here
    bool                connected      = false;
    qb::http::status    refused_status = qb::http::status::OK, sent_status = qb::http::status::OK;
    std::string         refused_body, sent_body;
    int                 with_a_query = 0;
    std::string         query_body;
    auto                client = qb::http1::make_client(server.url("/"));
    client->connect([&](bool ok, std::string const &) { connected = ok; });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected && server.connection_count() == 1; }));
    const auto of = [](std::size_t const length) {
        return "/" + std::string(length - 1, 'a');
    }; // a path, and no query
    client->push_request(request(qb::http::method::GET, of(qb::http::protocol_limits::MAX_URL_LENGTH)), [&](qb::http::Response response) {
        ++sent;
        sent_status = response.status();
        sent_body   = response.body().as<std::string>();
    });
    EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return sent != 0; }));
    // Sent: the answer is the server's, not one of the client's own.
    EXPECT_EQ(sent_body.find("cannot be sent"), std::string::npos) << sent_body;
    EXPECT_EQ(sent_body.find("serialization"), std::string::npos) << "the client did not send it: " << sent_body;
    // One limit for the three clients, on one quantity: a path and a query of MAX_URL_LENGTH together -- the `?` between
    // them is not counted -- are sent as well.
    client->push_request(request(qb::http::method::GET, "/q?" + std::string(qb::http::protocol_limits::MAX_URL_LENGTH - 2, 'a')),
                         [&](qb::http::Response response) {
                             ++with_a_query;
                             query_body = response.body().as<std::string>();
                         });
    EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return with_a_query != 0; }));
    EXPECT_EQ(query_body.find("cannot be sent"), std::string::npos) << query_body;
    EXPECT_EQ(query_body.find("serialization"), std::string::npos) << "the client did not send it: " << query_body;
    client->push_request(request(qb::http::method::GET, "/never"), [&](qb::http::Response) { ++never; }); // in flight
    client->push_request(request(qb::http::method::GET, of(qb::http::protocol_limits::MAX_URL_LENGTH + 1)), [&](qb::http::Response response) {
        ++refused;
        refused_status = response.status();
        refused_body   = response.body().as<std::string>();
    });
    EXPECT_EQ(refused, 1) << "the request was not refused where it was pushed";
    EXPECT_EQ(refused_status, qb::http::status::BAD_REQUEST) << refused_body;
    EXPECT_NE(refused_body.find("cannot be sent"), std::string::npos) << refused_body;
    EXPECT_NE(refused_body.find("MAX_URL_LENGTH"), std::string::npos) << refused_body;
    EXPECT_EQ(never, 0);
    client->disconnect();
    EXPECT_EQ(refused, 1) << "the request was answered twice";
}

namespace http1_client_fields_test {
/// Requests that carry a field the serializer cannot write: LF, NUL, CR, DEL and 0x01 in a value, SP, DEL and 0x01 in a
/// name, CR in a cookie, LF in a trailer field (a chunked body's), and a trailer field a trailer section must not carry.
/// @p shown is the name as the reason prints it, when it is not the name; @p says what the reason says of the fault.
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
} // namespace http1_client_fields_test

// The HTTP/1.1 serializer refuses such a field before it writes a byte of the request: the request hears 400, and now
// with a reason that names the field, as the two other clients answer (Huly QB-1191: it read "header value exceeds
// MAX_HEADER_VALUE_LENGTH" for a LF, and named no field). The connection stays, and the request behind is served on it.
TEST(Http1ClientTest, ARequestFieldThatCannotBeSentRefusesItsRequestAndNamesTheField) {
    for (const auto &field : http1_client_fields_test::k_unsendable_fields) {
        SCOPED_TRACE(field.what);
        LoopbackHttp1Server server;
        int                 refused = 0, served = 0; // before the client: its callbacks count here
        bool                connected = false;
        qb::http::status    status    = qb::http::status::OK;
        std::string         body;
        auto                client = qb::http1::make_client(server.url("/"));
        client->connect([&](bool ok, std::string const &) { connected = ok; });
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected && server.connection_count() == 1; }));
        const auto requests = server.request_count();
        auto       bad      = request(qb::http::method::POST, "/echo");
        if (field.trailer) {
            bad.set_header("Transfer-Encoding", "chunked");
            bad.body() = "x";
            bad.trailers().set_header(field.name, field.value);
        } else {
            bad.set_header(field.name, field.value);
        }
        client->push_request(std::move(bad), [&](qb::http::Response response) {
            ++refused;
            status = response.status();
            body   = response.body().as<std::string>();
        });
        client->push_request(request(qb::http::method::GET, "/ping"),
                             [&](qb::http::Response response) { served += response.status() == qb::http::status::OK ? 1 : 0; });
        EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return refused == 1 && served == 1; }));
        EXPECT_EQ(status, qb::http::status::BAD_REQUEST) << body;
        EXPECT_NE(body.find(http1_client_fields_test::named(field)), std::string::npos) << "the refusal does not name the field: " << body;
        EXPECT_NE(body.find("cannot be sent"), std::string::npos) << body;
        EXPECT_NE(body.find(field.says), std::string::npos) << body;
        EXPECT_EQ(server.connection_count(), 1) << "the refusal cost the connection";
        EXPECT_EQ(server.request_count(), requests + 1) << "the server was sent the request that was refused";
        client->disconnect();
    }
}

// A request's trailers() are sent, and judged, only with chunked framing on HTTP/1.1 (RFC 9112 section 7.1.2): framed by
// its content-length, or with no body, a request sends none of them, and none of them refuses it -- as Go's http.Request
// sends its Trailer only chunked. A field the serializer cannot write and one a trailer section must not carry: the
// request is served. HTTP/2 and HTTP/3 send a request's trailers() whatever its framing, and refuse it for them (a pin).
TEST(Http1ClientTest, TheTrailersOfARequestThatIsNotChunkedAreNeitherSentNorJudged) {
    for (const bool with_a_body : {true, false}) {
        SCOPED_TRACE(with_a_body ? "framed by its content-length" : "with no body");
        LoopbackHttp1Server server;
        int                 answered = 0; // before the client: its callback counts here
        qb::http::status    status   = qb::http::status::OK;
        std::string         body;
        bool                connected = false;
        auto                client    = qb::http1::make_client(server.url("/"));
        client->connect([&](bool ok, std::string const &) { connected = ok; });
        ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
        const auto requests = server.request_count();
        auto       req      = request(qb::http::method::POST, "/echo");
        if (with_a_body) {
            req.body() = "x";
        }
        req.trailers().set_header("x-sum", "a\nb");
        req.trailers().set_header("content-length", "1");
        client->push_request(std::move(req), [&](qb::http::Response response) {
            ++answered;
            status = response.status();
            body   = response.body().as<std::string>();
        });
        EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return answered == 1; }));
        EXPECT_EQ(status, qb::http::status::CREATED) << body;
        EXPECT_EQ(body, with_a_body ? "x" : "");
        EXPECT_EQ(server.request_count(), requests + 1) << "the request was not sent";
        client->disconnect();
    }
}

// HTTP/1.1 writes a value as it is, the SP and HTAB at its edges included, and the receiver strips them (RFC 9110
// section 5.5): " v " arrives "v", a value of whitespace alone arrives empty -- what the two other clients now send. A
// pin: it held before.
TEST(Http1ClientTest, AValueArrivesWithoutTheWhitespaceAtItsEdges) {
    LoopbackHttp1Server server;
    std::string         fields; // before the client: its callback writes here
    bool                connected = false;
    auto                client    = qb::http1::make_client(server.url("/"));
    client->connect([&](bool ok, std::string const &) { connected = ok; });
    ASSERT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return connected; }));
    auto req = request(qb::http::method::GET, "/fields");
    req.set_header("x-edge", " v ");
    req.set_header("x-blank", "  ");
    req.set_header("x-inside", "a \t b");
    client->push_request(std::move(req), [&](qb::http::Response response) { fields = response.body().as<std::string>(); });
    EXPECT_TRUE(ServerThread<Http1ClientTestServer>::pump_until([&] { return !fields.empty(); }));
    EXPECT_EQ(fields, "x-edge=[v] x-blank=[] x-inside=[a \t b]");
    client->disconnect();
}

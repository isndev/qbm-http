/**
 * @file qbm/http/tests/system/http1/http1-tls-cut-response.cpp
 * @brief An HTTPS/1.1 response the server abandons ends its TLS stream without a `close_notify`; one it completes ends
 *        with it (Huly QB-1270).
 *
 * Since 3.4 qb-io ends a TLS connection this side closes with a `close_notify`, the alert that tells the peer the stream
 * is whole, whenever everything the io object had QUEUED was written. It cannot know what the application still meant to
 * send: a streamed response the server abandons half-way -- `ResponseStream::abort()`, an `end()` short of a declared
 * `Content-Length`, a piece past it, a coder that fails, a producer that drops its stream, a cancellation, the
 * inactivity timeout, the drain's deadline, a pipelining limit, the application's own `disconnect()`, the server
 * destroyed, the peer's own close_notify (which qb-io answers) -- usually leaves the queue empty, and the alert would
 * announce the cut response as whole. The HTTP/1.1 session knows the response is cut (a streamed head is out and its
 * `end()` is not): it ends the TLS session quietly first, and the peer reads OpenSSL's unexpected EOF (`SSL_ERROR_SSL`,
 * reason `SSL_R_UNEXPECTED_EOF_WHILE_READING`).
 * A response that completes keeps the alert: `SSL_ERROR_ZERO_RETURN` after its last byte.
 *
 * The server runs on its own thread (the shared `ServerThread`). The peer is OpenSSL alone -- an `SSL` object over a
 * plain TCP socket, on the test's thread: what it reads is what a browser, curl or any OpenSSL program reads. Every
 * abandoning case waits until the client has read the first piece and the session's output is EMPTY before the
 * server acts, so the case is about the module's knowledge and not about a queue qb-io would judge itself, and each
 * one asserts that the response really was cut (no last-chunk; fewer body octets than declared).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <gtest/gtest.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <qb/io/async.h>
#include <qb/io/tcp/socket.h>
#include <qbm/http/http.h>

#include "../../shared/loopback_server.h"
#include "../../shared/tls_identity.h"

using namespace std::chrono_literals;

namespace http1_tls_cut_response_test {

using steady = std::chrono::steady_clock;

/// The first piece every streamed route writes, the one the client waits for before the server acts.
constexpr std::string_view PIECE = "piece-one;";
/// The second piece of a response that completes.
constexpr std::string_view LAST = "piece-two;";
/// What the next owner of an extracted session's socket writes before it ends the connection.
constexpr std::string_view NEXT_OWNER = "next-owner;";

// ------------------------------------------------------------------------------------------------ what the peer read
/// How the TLS stream ended for the raw OpenSSL client that read it.
struct TlsEnd {
    std::string   received;                      ///< The application octets read before the end: the response.
    int           error        = SSL_ERROR_NONE; ///< `SSL_get_error()` of the read that ended it (`WANT_READ`: still open).
    unsigned long first_error  = 0;              ///< The first entry of the error queue at that read.
    std::size_t   octets_after = 0;              ///< What the TCP connection carried after the TLS end.
    bool          fin          = false;          ///< Whether the TCP connection then ended with a FIN.
    int           tcp_error    = 0;              ///< ...or with this socket error.

    [[nodiscard]] bool
    clean() const noexcept {
        return error == SSL_ERROR_ZERO_RETURN;
    }

    [[nodiscard]] bool
    unexpected_eof() const noexcept {
        return error == SSL_ERROR_SSL && ERR_GET_REASON(first_error) == SSL_R_UNEXPECTED_EOF_WHILE_READING;
    }

    /// The codes, spelled: "SSL_ERROR_SSL (1), reason 294: ...; 120 octets before, 0 after, FIN".
    [[nodiscard]] std::string
    text() const {
        std::string out;
        switch (error) {
            case SSL_ERROR_ZERO_RETURN:
                out = "SSL_ERROR_ZERO_RETURN";
                break;
            case SSL_ERROR_SSL:
                out = "SSL_ERROR_SSL";
                break;
            case SSL_ERROR_SYSCALL:
                out = "SSL_ERROR_SYSCALL";
                break;
            case SSL_ERROR_WANT_READ:
                out = "SSL_ERROR_WANT_READ (still open)";
                break;
            default:
                out = "SSL_get_error";
                break;
        }
        out += " (" + std::to_string(error) + ")";
        if (first_error != 0) {
            char reason[256] = {};
            ERR_error_string_n(first_error, reason, sizeof(reason));
            out += ", reason " + std::to_string(ERR_GET_REASON(first_error)) + ": " + reason;
        }
        out += "; " + std::to_string(received.size()) + " octets before, " + std::to_string(octets_after) + " after, ";
        out += fin ? "FIN" : tcp_error ? "socket error " + std::to_string(tcp_error) : "no FIN";
        return out;
    }
};

/// What a case's peer read, on the test's output: the codes the report quotes.
void
note(std::string_view what, TlsEnd const &end) {
    std::cout << "[   PEER   ] " << what << ": " << end.text() << '\n';
}

/// The response's header section and body as they arrived (the body still framed when chunked).
struct Wire {
    std::string head;
    std::string body;
    bool        has_head = false;

    explicit Wire(std::string const &received) {
        const auto end = received.find("\r\n\r\n");
        if (end == std::string::npos)
            return;
        has_head = true;
        head     = received.substr(0, end + 2);
        body     = received.substr(end + 4);
        std::transform(head.begin(), head.end(), head.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    }

    [[nodiscard]] bool
    chunked() const {
        return head.find("transfer-encoding: chunked") != std::string::npos;
    }

    /// The declared `Content-Length`, or npos.
    [[nodiscard]] std::size_t
    content_length() const {
        const auto at = head.find("content-length:");
        if (at == std::string::npos)
            return std::string::npos;
        return static_cast<std::size_t>(std::stoul(head.substr(at + 15)));
    }

    /// A chunked body that ends with its last-chunk: the message is whole by HTTP's own framing.
    [[nodiscard]] bool
    last_chunk() const {
        return body.size() >= 5 && body.compare(body.size() - 5, 5, "0\r\n\r\n") == 0;
    }
};

// ------------------------------------------------------------------------------------------------ the raw peer
/**
 * @brief The client: OpenSSL over a plain TCP socket, nothing of qb's TLS socket in between.
 * @details Non-blocking, on the test's thread; the server's loop runs on its own. Reads are `SSL_read()` and
 *          `SSL_get_error()`. The server's certificate is not verified (a self-signed test identity).
 */
class RawTlsClient {
    SSL_CTX *_ctx = nullptr;

public:
    qb::io::tcp::socket tcp;
    SSL                *ssl = nullptr;
    std::string         received;

    RawTlsClient()
        : _ctx(SSL_CTX_new(TLS_client_method())) {
        if (_ctx)
            ssl = SSL_new(_ctx);
    }

    RawTlsClient(RawTlsClient const &)            = delete;
    RawTlsClient &operator=(RawTlsClient const &) = delete;

    ~RawTlsClient() {
        SSL_free(ssl);
        SSL_CTX_free(_ctx);
        tcp.close();
    }

    /// Connected to the server, the handshake complete.
    [[nodiscard]] ::testing::AssertionResult
    connect(std::uint16_t port) {
        if (!ssl)
            return ::testing::AssertionFailure() << "no SSL object";
        if (tcp.connect_v4("127.0.0.1", port) != 0)
            return ::testing::AssertionFailure() << "TCP connect to port " << port << " failed";
        if (tcp.set_nonblocking(true) != 0 || SSL_set_fd(ssl, static_cast<int>(tcp.native_handle())) != 1)
            return ::testing::AssertionFailure() << "the socket could not be set up";
        SSL_set_connect_state(ssl);
        const auto deadline = steady::now() + 5s;
        for (;;) {
            ERR_clear_error();
            const int ret = SSL_do_handshake(ssl);
            if (ret == 1)
                return ::testing::AssertionSuccess();
            const int error = SSL_get_error(ssl, ret);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                return ::testing::AssertionFailure() << "the handshake failed: SSL_get_error " << error;
            if (steady::now() >= deadline)
                return ::testing::AssertionFailure() << "the handshake did not complete";
            std::this_thread::sleep_for(1ms);
        }
    }

    /// Writes `what` whole.
    [[nodiscard]] ::testing::AssertionResult
    send(std::string_view what) {
        const auto  deadline = steady::now() + 5s;
        std::size_t sent     = 0;
        while (sent < what.size()) {
            ERR_clear_error();
            const int n = SSL_write(ssl, what.data() + sent, static_cast<int>(what.size() - sent));
            if (n > 0) {
                sent += static_cast<std::size_t>(n);
                continue;
            }
            const int error = SSL_get_error(ssl, n);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                return ::testing::AssertionFailure() << "SSL_write failed: SSL_get_error " << error;
            if (steady::now() >= deadline)
                return ::testing::AssertionFailure() << "the request was not written";
            std::this_thread::sleep_for(1ms);
        }
        return ::testing::AssertionSuccess();
    }

    /// Reads application octets into `received` until `done(received)` holds; false when the stream ended or the
    /// budget ran out first.
    template <typename Done>
    [[nodiscard]] bool
    read_until(Done &&done, std::chrono::milliseconds budget = 5000ms) {
        const auto deadline = steady::now() + budget;
        char       buffer[16384];
        while (!done(received)) {
            ERR_clear_error();
            const int n = SSL_read(ssl, buffer, static_cast<int>(sizeof(buffer)));
            if (n > 0) {
                received.append(buffer, static_cast<std::size_t>(n));
                continue;
            }
            const int error = SSL_get_error(ssl, n);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                return false; // the stream ended: read_to_end() reads how
            if (steady::now() >= deadline)
                return false;
            std::this_thread::sleep_for(1ms);
        }
        return true;
    }

    /// Reads the stream to its end: the application octets, how TLS ended, then what TCP still carried.
    [[nodiscard]] TlsEnd
    read_to_end(std::chrono::milliseconds budget = 5000ms) {
        TlsEnd     out;
        const auto deadline = steady::now() + budget;
        char       buffer[16384];
        for (;;) {
            ERR_clear_error();
            const int n      = SSL_read(ssl, buffer, static_cast<int>(sizeof(buffer)));
            const int system = n > 0 ? 0 : qb::io::socket::get_last_errno(); // before anything else replaces it
            if (n > 0) {
                received.append(buffer, static_cast<std::size_t>(n));
                continue;
            }
            out.error = SSL_get_error(ssl, n);
            if (out.error != SSL_ERROR_WANT_READ && out.error != SSL_ERROR_WANT_WRITE) {
                out.first_error = ERR_peek_error();
                if (out.error == SSL_ERROR_SYSCALL && system != 0) { // a reset: that is its whole end
                    out.tcp_error = system;
                    out.received  = received;
                    return out;
                }
                break;
            }
            out.error = SSL_ERROR_WANT_READ;
            if (steady::now() >= deadline) {
                out.received = received;
                return out;
            }
            std::this_thread::sleep_for(1ms);
        }
        out.received = received;
        // The TLS stream is over. What the TCP connection still carries is read raw: after a close_notify, the FIN.
        for (;;) {
            const int n = qb::io::socket::recv(tcp.native_handle(), buffer, static_cast<int>(sizeof(buffer)));
            if (n > 0) {
                out.octets_after += static_cast<std::size_t>(n);
                continue;
            }
            if (n == 0) {
                out.fin = true;
                break;
            }
            const int error = qb::io::socket::get_last_errno();
            if (!qb::io::socket::not_recv_error(error)) {
                out.tcp_error = error;
                break;
            }
            if (steady::now() >= deadline)
                break;
            std::this_thread::sleep_for(1ms);
        }
        return out;
    }
};

[[nodiscard]] std::string
request(std::string_view target, bool connection_close = false) {
    std::string out = "GET ";
    out.append(target).append(" HTTP/1.1\r\nHost: localhost\r\n");
    if (connection_close)
        out.append("Connection: close\r\n");
    return out.append("\r\n");
}

// ------------------------------------------------------------------------------------------------ what the server saw
std::atomic<bool> g_release{false}; ///< The test read the first piece: the producer may act.
std::atomic<int>  g_aborted{-1};    ///< After the act: 1 when the stream reports itself aborted, 0 when not.
std::atomic<int>  g_cancelled{-1};  ///< A parked stream: 1 when the session ended it under its producer, 0 when the park expired.
std::atomic<int>  g_extracted{-1};  ///< An extraction: 1 when the socket left the session and its next owner wrote, 0 when not.

/// A stream held past the server's life (the server-destroyed case): set on the server's thread, released on the test's
/// once that thread is joined.
template <typename Session>
std::shared_ptr<qb::http::ResponseStream<Session>> &
held() {
    static std::shared_ptr<qb::http::ResponseStream<Session>> stream;
    return stream;
}

/**
 * @brief Runs `act` on the server's loop once the test has read the first piece (`g_release`) and the session's output
 *        is EMPTY -- every byte written so far handed to TLS, so qb-io alone would end the connection as a whole stream.
 *        Polls every millisecond, up to 5 s; then it acts all the same, and the case fails on what the client read.
 */
template <typename Stream, typename Act>
void
act_when_released(std::shared_ptr<Stream> stream, Act act, int left = 5000) {
    if ((g_release.load() && stream->pending() == 0) || left <= 0) {
        act(std::move(stream));
        return;
    }
    qb::io::async::callback(
        [stream = std::move(stream), act = std::move(act), left]() mutable { act_when_released(std::move(stream), std::move(act), left - 1); },
        1ms);
}

/**
 * @brief Holds the stream and writes nothing until the session ends it under its producer (`cancelled()`). A park that
 *        expires (5 s) never drops the stream -- that would abort it and read as the outcome under test -- it hands it to
 *        `held()` and records the expiry.
 */
template <typename Session>
void
park(std::shared_ptr<qb::http::ResponseStream<Session>> stream, int left = 500) {
    if (stream->cancelled() || stream->ended()) {
        g_cancelled = stream->cancelled() ? 1 : 0;
        return;
    }
    if (left <= 0) {
        g_cancelled     = 0;
        held<Session>() = std::move(stream);
        return;
    }
    qb::io::async::callback([stream = std::move(stream), left]() mutable { park<Session>(std::move(stream), left - 1); }, 10ms);
}

/// A content coding that codes its first piece as itself and fails on the second (`code()`), or at `finish()`.
struct FailingCoder final : qb::http::stream_filter {
    bool fail_at_finish = false;
    int  pieces         = 0;

    explicit FailingCoder(bool at_finish)
        : fail_at_finish(at_finish) {}

    [[nodiscard]] std::string_view
    name() const noexcept override {
        return "x-fails";
    }
    [[nodiscard]] std::size_t
    bound(std::size_t piece) const noexcept override {
        return piece;
    }
    [[nodiscard]] bool
    code(std::string_view piece, std::string &out) override {
        if (!fail_at_finish && pieces++ != 0)
            return false;
        out.append(piece.data(), piece.size());
        return true;
    }
    [[nodiscard]] bool
    finish(std::string &) override {
        return !fail_at_finish;
    }
};

/// The routes every server of this file serves.
template <typename Session>
void
install_routes(qb::http::Router<Session> &router) {
    using Ctx    = qb::http::Context<Session>;
    using Stream = qb::http::ResponseStream<Session>;
    using Held   = std::shared_ptr<Stream>;

    // A streamed response, chunked or under a declared length, whose first piece is written; `act` runs once the client
    // read it and the output is empty.
    const auto stream_then = [](std::shared_ptr<Ctx> const &ctx, std::size_t declared, auto act) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("Content-Type", "text/plain");
        if (declared != 0)
            ctx->response().set_header("Content-Length", std::to_string(declared));
        auto stream = ctx->begin_stream();
        (void) stream->write(PIECE);
        act_when_released(std::move(stream), std::move(act));
    };
    const auto record_abort = [](Held const &stream) {
        g_aborted = stream->aborted() ? 1 : 0;
    };

    // --- completed: the alert follows the last byte -------------------------------------------------------------
    router.get("/chunked/end", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, 0, [=](Held stream) {
            (void) stream->write(LAST);
            stream->end();
            record_abort(stream);
        });
    });
    router.get("/declared/end", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, PIECE.size() + LAST.size(), [=](Held stream) {
            (void) stream->write(LAST);
            stream->end();
            record_abort(stream);
        });
    });
    // Completed on a persistent connection, which the session's inactivity timeout then ends with nothing cut (long
    // enough that it never runs out before the response completes, each piece refreshing it).
    router.get("/declared/end-then-idle", [=](std::shared_ptr<Ctx> ctx) {
        if (auto session = ctx->session())
            session->setTimeout(500ms);
        stream_then(ctx, PIECE.size() + LAST.size(), [=](Held stream) {
            (void) stream->write(LAST);
            stream->end();
            record_abort(stream);
        });
    });

    // --- abandoned through ResponseStream::abort(): stream_abort() ----------------------------------------------
    router.get("/chunked/abort", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, 0, [=](Held stream) {
            stream->abort();
            record_abort(stream);
        });
    });
    router.get("/declared/abort", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, 2 * PIECE.size(), [=](Held stream) {
            stream->abort();
            record_abort(stream);
        });
    });
    // end() short of the declared length aborts.
    router.get("/declared/short-end", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, 2 * PIECE.size(), [=](Held stream) {
            stream->end();
            record_abort(stream);
        });
    });
    // A piece past the declared length aborts.
    router.get("/declared/overrun", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, PIECE.size() + 1, [=](Held stream) {
            (void) stream->write(PIECE);
            record_abort(stream);
        });
    });
    // A content coding that fails: on a piece, or at end().
    for (const bool at_finish : {false, true}) {
        router.get(at_finish ? "/chunked/coder-fails-at-end" : "/chunked/coder-fails", [=](std::shared_ptr<Ctx> ctx) {
            ctx->add_lifecycle_hook([at_finish](Ctx &c, qb::http::HookPoint point) {
                if (point == qb::http::HookPoint::PRE_RESPONSE_SEND && c.stream_beginning())
                    c.set_stream_coding(std::make_unique<FailingCoder>(at_finish));
            });
            stream_then(ctx, 0, [=](Held stream) {
                if (at_finish)
                    stream->end();
                else
                    (void) stream->write(LAST);
                record_abort(stream);
            });
        });
    }
    // The producer drops its stream before end(): the destructor aborts it.
    router.get("/chunked/dropped", [=](std::shared_ptr<Ctx> ctx) { stream_then(ctx, 0, [](Held stream) { stream.reset(); }); });
    // The application cancels the context under the streamed head (the session holds the context while it answers it).
    router.get("/chunked/cancelled", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, 0, [=, weak = std::weak_ptr<Ctx>(ctx)](Held stream) {
            if (auto context = weak.lock())
                context->cancel("the application changed its mind");
            record_abort(stream);
            park<Session>(std::move(stream));
        });
    });
    // abort(), and a lifecycle hook that closes the transport itself when the abort cancels the context: the TLS session
    // is ended before the cancellation runs application code.
    router.get("/chunked/abort-hook-closes", [=](std::shared_ptr<Ctx> ctx) {
        ctx->add_lifecycle_hook([](Ctx &c, qb::http::HookPoint) {
            if (c.is_cancelled()) {
                if (auto session = c.session())
                    static_cast<void>(session->transport().disconnect());
            }
        });
        stream_then(ctx, 0, [=](Held stream) {
            stream->abort();
            record_abort(stream);
        });
    });

    // --- abandoned by the connection's end, the stream still live: on(event::disconnected) ----------------------
    // The inactivity timeout runs out while the producer writes nothing.
    router.get("/chunked/timeout", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, 0, [weak = std::weak_ptr<Session>(ctx->session())](Held stream) {
            if (auto session = weak.lock())
                session->setTimeout(100ms);
            park<Session>(std::move(stream));
        });
    });
    // The server drains: the session is busy with the stream, the drain's deadline aborts it.
    router.get("/chunked/drain-deadline", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, 0, [weak = std::weak_ptr<Session>(ctx->session())](Held stream) {
            if (auto session = weak.lock())
                static_cast<void>(session->server().drain(50ms));
            park<Session>(std::move(stream));
        });
    });
    // A pipelined request over the session's limit (here 0) arrives while the stream is live.
    router.get("/chunked/pipeline-limit", [=](std::shared_ptr<Ctx> ctx) {
        if (auto session = ctx->session())
            session->max_pipelined_requests(0);
        ctx->response().status() = qb::http::status::OK;
        auto stream              = ctx->begin_stream();
        (void) stream->write(PIECE);
        park<Session>(std::move(stream));
    });
    // The producer writes its first piece and then waits: the stream stays live until the connection ends under it.
    router.get("/chunked/held", [=](std::shared_ptr<Ctx> ctx) {
        ctx->response().status() = qb::http::status::OK;
        auto stream              = ctx->begin_stream();
        (void) stream->write(PIECE);
        park<Session>(std::move(stream));
    });
    // The application ends the connection itself.
    router.get("/chunked/session-disconnect", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, 0, [weak = std::weak_ptr<Session>(ctx->session())](Held stream) {
            if (auto session = weak.lock())
                session->disconnect();
            park<Session>(std::move(stream));
        });
    });

    // --- the session extracted: its socket goes on with a next owner, which writes and ends the connection ------
    // Extracts the session from its server; the next owner writes NEXT_OWNER on the socket it got, then disconnect()s.
    const auto extract_and_end = [](std::weak_ptr<Session> const &weak) {
        auto session = weak.lock();
        if (!session)
            return;
        auto [socket, found] = session->server().extractSession(session->id());
        g_extracted          = found && socket.write(NEXT_OWNER.data(), NEXT_OWNER.size()) == static_cast<int>(NEXT_OWNER.size()) ? 1 : 0;
        static_cast<void>(socket.disconnect());
    };
    // Under a live stream: the declared length is not reached, nothing is queued.
    router.get("/declared/extracted-live", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, 2 * PIECE.size(), [=, weak = std::weak_ptr<Session>(ctx->session())](Held stream) {
            extract_and_end(weak);
            g_cancelled = stream->cancelled() ? 1 : 0;
        });
    });
    // After the response completed: end() first, nothing queued, then the extraction.
    router.get("/declared/extracted-after-end", [=](std::shared_ptr<Ctx> ctx) {
        stream_then(ctx, PIECE.size(), [=, weak = std::weak_ptr<Session>(ctx->session())](Held stream) {
            stream->end();
            record_abort(stream);
            extract_and_end(weak);
        });
    });

    // --- the server destroyed with its sessions: ~session() -----------------------------------------------------
    // Under a live stream (held past the server, so that nothing but the session's destruction ends it).
    router.get("/chunked/server-destroyed", [=](std::shared_ptr<Ctx> ctx) {
        ctx->response().status() = qb::http::status::OK;
        auto stream              = ctx->begin_stream();
        (void) stream->write(PIECE);
        held<Session>() = std::move(stream);
    });
    // After a completed response, the connection persistent and idle.
    router.get("/declared/complete", [=](std::shared_ptr<Ctx> ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().set_header("Content-Length", std::to_string(PIECE.size()));
        auto stream = ctx->begin_stream();
        (void) stream->write(PIECE);
        stream->end();
    });
    router.compile();
}

// A session whose own disconnected handler closes its transport itself: `ssl::socket::disconnect()` sends the alert
// unless the session ended its TLS session first.
class ClosingSession;
using ClosingServer = qb::http::ssl::Server<ClosingSession>;

class ClosingSession : public qb::http::use<ClosingSession>::ssl::session<ClosingServer> {
public:
    using Base = qb::http::use<ClosingSession>::ssl::session<ClosingServer>;

    explicit ClosingSession(ClosingServer &server)
        : Base(server) {}

    void
    on(qb::http::event::disconnected &&) {
        static_cast<void>(this->transport().disconnect());
    }
};

using DefaultServer = qb::http::ssl::Server<>;

template <typename Server, typename Session>
class CutResponseFixture : public ::testing::Test {
protected:
    qb::http::test::tls_identity                          identity{"qbm-http1-tls-cut-response"};
    std::unique_ptr<qb::http::test::ServerThread<Server>> server;
    std::uint16_t                                         port = 0;

    void
    SetUp() override {
        ASSERT_TRUE(identity.ok());
        g_release   = false;
        g_aborted   = -1;
        g_cancelled = -1;
        g_extracted = -1;
        server      = std::make_unique<qb::http::test::ServerThread<Server>>([this](Server &s) {
            install_routes(s.router());
            return s.listen(qb::io::uri{"tcp://127.0.0.1:0"}, identity.context());
        });
        ASSERT_TRUE(server->ready());
        port = server->port();
        ASSERT_NE(port, 0);
    }

    void
    TearDown() override {
        server.reset();
        held<Session>().reset(); // the server's thread is joined: nothing else touches it
    }

    /// Asks for `target`, reads until the first piece arrived, lets the server act, and reads the stream to its end.
    [[nodiscard]] TlsEnd
    exchange(std::string_view target, bool connection_close = false) {
        RawTlsClient client;
        TlsEnd       end;
        [&] {
            ASSERT_TRUE(client.connect(port));
            ASSERT_TRUE(client.send(request(target, connection_close)));
            ASSERT_TRUE(client.read_until([](std::string const &r) { return r.find(PIECE) != std::string::npos; }))
                << "the first piece never came: " << client.received;
            g_release = true;
            end       = client.read_to_end();
        }();
        return end;
    }
};

class Http1TlsCutResponse : public CutResponseFixture<DefaultServer, qb::http::ssl::DefaultSecureSession> {};
class Http1TlsCutResponseHookClosesTransport : public CutResponseFixture<ClosingServer, ClosingSession> {};

/// The last byte, then one alert, then the FIN, nothing else: a whole response, as an OpenSSL peer reads it.
#define EXPECT_ENDS_WITH_THE_ALERT(end)                                                               \
    do {                                                                                              \
        EXPECT_TRUE((end).clean()) << "the peer read no close_notify: " << (end).text();              \
        EXPECT_EQ((end).octets_after, 0u) << "something followed the close_notify: " << (end).text(); \
        EXPECT_TRUE((end).fin) << (end).text();                                                       \
    } while (false)

/// OpenSSL's unexpected EOF: the peer reads the cut as a cut.
#define EXPECT_ENDS_CUT(end) EXPECT_TRUE((end).unexpected_eof()) << "the peer read the cut response as whole: " << (end).text()

/// The response really was cut (the vacuity guard of every case that expects no alert).
void
expect_cut(TlsEnd const &end) {
    const Wire wire{end.received};
    ASSERT_TRUE(wire.has_head) << end.received;
    EXPECT_NE(wire.body.find(PIECE), std::string::npos) << "the first piece is missing: " << end.received;
    if (wire.chunked()) {
        EXPECT_FALSE(wire.last_chunk()) << "the case proves nothing: the chunked response ended with its last-chunk";
    } else {
        ASSERT_NE(wire.content_length(), std::string::npos) << "neither chunked nor declared: " << end.received;
        EXPECT_LT(wire.body.size(), wire.content_length()) << "the case proves nothing: the declared length was reached";
    }
}

/// The response is whole by HTTP's own framing.
void
expect_whole(TlsEnd const &end) {
    const Wire wire{end.received};
    ASSERT_TRUE(wire.has_head) << end.received;
    if (wire.chunked()) {
        EXPECT_TRUE(wire.last_chunk()) << "the chunked response did not end with its last-chunk: " << end.received;
    } else {
        ASSERT_NE(wire.content_length(), std::string::npos) << "neither chunked nor declared: " << end.received;
        EXPECT_EQ(wire.body.size(), wire.content_length()) << end.received;
    }
}

/// What the server's thread published in `seen`, once it did (up to 5 s): a parked stream looks every 10 ms, so the
/// client may read the end of the connection before the park sees it.
[[nodiscard]] int
published(std::atomic<int> const &seen) {
    const auto deadline = steady::now() + 5s;
    while (seen.load() == -1 && steady::now() < deadline)
        std::this_thread::sleep_for(1ms);
    return seen.load();
}

} // namespace http1_tls_cut_response_test

using namespace http1_tls_cut_response_test;

// --- completed responses keep the alert ---------------------------------------------------------------------------

TEST_F(Http1TlsCutResponse, ACompletedChunkedResponseWithConnectionCloseEndsWithTheAlert) {
    const TlsEnd end = exchange("/chunked/end", true);
    note("completed chunked response, Connection: close", end);
    EXPECT_EQ(published(g_aborted), 0);
    expect_whole(end);
    EXPECT_ENDS_WITH_THE_ALERT(end);
}

TEST_F(Http1TlsCutResponse, ACompletedDeclaredResponseWithConnectionCloseEndsWithTheAlert) {
    const TlsEnd end = exchange("/declared/end", true);
    note("completed declared-length response, Connection: close", end);
    EXPECT_EQ(published(g_aborted), 0);
    expect_whole(end);
    EXPECT_ENDS_WITH_THE_ALERT(end);
}

// The connection persistent, the response complete, the inactivity timeout ends it: nothing is cut.
TEST_F(Http1TlsCutResponse, AnIdleTimeoutAfterACompletedResponseEndsWithTheAlert) {
    const TlsEnd end = exchange("/declared/end-then-idle");
    note("completed response, then the idle timeout", end);
    EXPECT_EQ(published(g_aborted), 0);
    expect_whole(end);
    EXPECT_ENDS_WITH_THE_ALERT(end);
}

// A server destroyed with an idle session whose response completed: nothing is cut.
TEST_F(Http1TlsCutResponse, AServerDestroyedAfterACompletedResponseEndsWithTheAlert) {
    RawTlsClient client;
    ASSERT_TRUE(client.connect(port));
    ASSERT_TRUE(client.send(request("/declared/complete")));
    ASSERT_TRUE(client.read_until([](std::string const &r) {
        const Wire wire{r};
        return wire.has_head && wire.body.size() >= wire.content_length();
    })) << client.received;
    server.reset();
    const TlsEnd end = client.read_to_end();
    note("completed response, then the server destroyed", end);
    expect_whole(end);
    EXPECT_ENDS_WITH_THE_ALERT(end);
}

// --- abandoned through the stream: stream_abort() -----------------------------------------------------------------

TEST_F(Http1TlsCutResponse, AnAbortedChunkedResponseEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/chunked/abort");
    note("chunked response, abort()", end);
    EXPECT_EQ(published(g_aborted), 1);
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, AnAbortedDeclaredResponseEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/declared/abort");
    note("declared-length response, abort()", end);
    EXPECT_EQ(published(g_aborted), 1);
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, AnEndShortOfTheDeclaredLengthEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/declared/short-end");
    note("declared-length response, end() short of it", end);
    EXPECT_EQ(published(g_aborted), 1);
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, APiecePastTheDeclaredLengthEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/declared/overrun");
    note("declared-length response, a piece past it", end);
    EXPECT_EQ(published(g_aborted), 1);
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, ACoderThatFailsOnAPieceEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/chunked/coder-fails");
    note("coded chunked response, the coder fails on a piece", end);
    EXPECT_EQ(published(g_aborted), 1);
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, ACoderThatFailsAtTheEndEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/chunked/coder-fails-at-end");
    note("coded chunked response, the coder fails at end()", end);
    EXPECT_EQ(published(g_aborted), 1);
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, AStreamItsProducerDropsEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/chunked/dropped");
    note("chunked response, the producer drops its stream", end);
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, AnApplicationCancelUnderAStreamedHeadEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/chunked/cancelled");
    note("chunked response, the context cancelled", end);
    EXPECT_EQ(published(g_aborted), 1);
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, AnAbortWhoseCancellationHookClosesTheTransportEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/chunked/abort-hook-closes");
    note("chunked response, abort(), a cancellation hook closes the transport", end);
    EXPECT_EQ(published(g_aborted), 1);
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

// --- abandoned by the connection's end under a live stream: on(event::disconnected) -------------------------------

TEST_F(Http1TlsCutResponse, TheInactivityTimeoutUnderALiveStreamEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/chunked/timeout");
    note("chunked response, the inactivity timeout", end);
    EXPECT_EQ(published(g_cancelled), 1) << "the timeout did not end the stream";
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, TheDrainDeadlineUnderALiveStreamEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/chunked/drain-deadline");
    note("chunked response, the drain's deadline", end);
    EXPECT_EQ(published(g_cancelled), 1) << "the drain's deadline did not end the stream";
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, APipeliningLimitUnderALiveStreamEndsWithoutTheAlert) {
    RawTlsClient client;
    ASSERT_TRUE(client.connect(port));
    ASSERT_TRUE(client.send(request("/chunked/pipeline-limit")));
    ASSERT_TRUE(client.read_until([](std::string const &r) { return r.find(PIECE) != std::string::npos; })) << client.received;
    ASSERT_TRUE(client.send(request("/declared/complete"))); // one request more than the limit allows
    const TlsEnd end = client.read_to_end();
    note("chunked response, a pipelined request over the limit", end);
    EXPECT_EQ(published(g_cancelled), 1) << "the limit did not end the stream";
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

// The PEER ends its TLS session under a live stream -- its close_notify, then its sending side shut down -- and reads
// on: qb-io answers a peer's close_notify when nothing queued is dropped, and nothing is queued here; the response is
// cut all the same, and the session ends its TLS session quietly before qb-io could answer.
TEST_F(Http1TlsCutResponse, APeerThatEndsItsSessionUnderALiveStreamIsNotAnswered) {
    RawTlsClient client;
    ASSERT_TRUE(client.connect(port));
    ASSERT_TRUE(client.send(request("/chunked/held")));
    ASSERT_TRUE(client.read_until([](std::string const &r) { return r.find(PIECE) != std::string::npos; })) << client.received;
    ERR_clear_error();
    ASSERT_EQ(SSL_shutdown(client.ssl), 0) << "the client's close_notify was not sent";
    ASSERT_EQ(::shutdown(client.tcp.native_handle(), QB_SD_SEND), 0);
    const TlsEnd end = client.read_to_end();
    note("chunked response, the peer's close_notify under it", end);
    EXPECT_EQ(published(g_cancelled), 1) << "the peer's end did not end the stream";
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, TheApplicationsOwnDisconnectUnderALiveStreamEndsWithoutTheAlert) {
    const TlsEnd end = exchange("/chunked/session-disconnect");
    note("chunked response, the session's disconnect()", end);
    EXPECT_EQ(published(g_cancelled), 1) << "the disconnect did not end the stream";
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

// --- the session extracted, its socket written to and ended by a next owner ---------------------------------------
// Under a live stream the response is cut whatever the next owner writes after it: the stream is marked cut before
// the socket leaves, and the next owner's disconnect() says nothing. After a completed response it ends as any other.

namespace http1_tls_cut_response_test {
/// `end` with the next owner's bytes taken off its tail (asserted there): the HTTP response as it arrived.
[[nodiscard]] TlsEnd
response_before_next_owner(TlsEnd end) {
    const bool there = end.received.size() >= NEXT_OWNER.size()
                       && end.received.compare(end.received.size() - NEXT_OWNER.size(), NEXT_OWNER.size(), NEXT_OWNER) == 0;
    EXPECT_TRUE(there) << "the next owner's bytes are not the last the client read: " << end.received;
    if (there)
        end.received.resize(end.received.size() - NEXT_OWNER.size());
    return end;
}
} // namespace http1_tls_cut_response_test

TEST_F(Http1TlsCutResponse, ASessionExtractedUnderALiveStreamEndsWithoutTheAlertWhateverItsNextOwnerWrites) {
    const TlsEnd end = exchange("/declared/extracted-live");
    note("declared-length response, the session extracted under it, its next owner writes and disconnects", end);
    EXPECT_EQ(published(g_extracted), 1) << "the socket did not leave the session, or its next owner could not write";
    EXPECT_EQ(published(g_cancelled), 1) << "the extraction did not end the stream";
    expect_cut(response_before_next_owner(end));
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponse, ASessionExtractedAfterACompletedResponseEndsWithTheAlertItsNextOwnerSends) {
    const TlsEnd end = exchange("/declared/extracted-after-end");
    note("completed declared-length response, the session extracted, its next owner writes and disconnects", end);
    EXPECT_EQ(published(g_aborted), 0);
    EXPECT_EQ(published(g_extracted), 1) << "the socket did not leave the session, or its next owner could not write";
    expect_whole(response_before_next_owner(end));
    EXPECT_ENDS_WITH_THE_ALERT(end);
}

// --- the server destroyed under a live stream: ~session() ---------------------------------------------------------

TEST_F(Http1TlsCutResponse, AServerDestroyedUnderALiveStreamEndsWithoutTheAlert) {
    RawTlsClient client;
    ASSERT_TRUE(client.connect(port));
    ASSERT_TRUE(client.send(request("/chunked/server-destroyed")));
    ASSERT_TRUE(client.read_until([](std::string const &r) { return r.find(PIECE) != std::string::npos; })) << client.received;
    server.reset(); // the sessions are destroyed with it, without a disconnected event
    ASSERT_TRUE(held<qb::http::ssl::DefaultSecureSession>()) << "the case proves nothing: the stream was not held";
    EXPECT_TRUE(held<qb::http::ssl::DefaultSecureSession>()->cancelled()) << "the session's destruction did not tell the stream";
    const TlsEnd end = client.read_to_end();
    note("chunked response, the server destroyed", end);
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

// --- a session whose disconnected handler closes the transport itself -----------------------------------------------
// The TLS session is ended before the application's handler runs: its own ssl::socket::disconnect() then says nothing.

TEST_F(Http1TlsCutResponseHookClosesTransport, TheSessionEndsTheTlsStreamBeforeItsHandlerClosesTheTransport) {
    const TlsEnd end = exchange("/chunked/session-disconnect");
    note("chunked response, disconnect(), the session's handler closes the transport", end);
    EXPECT_EQ(published(g_cancelled), 1) << "the disconnect did not end the stream";
    expect_cut(end);
    EXPECT_ENDS_CUT(end);
}

TEST_F(Http1TlsCutResponseHookClosesTransport, ACompletedResponseStillEndsWithTheAlert) {
    const TlsEnd end = exchange("/chunked/end", true);
    note("completed chunked response, Connection: close, the session's handler closes the transport", end);
    expect_whole(end);
    EXPECT_ENDS_WITH_THE_ALERT(end);
}

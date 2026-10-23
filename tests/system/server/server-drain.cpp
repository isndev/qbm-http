/**
 * @file qbm/http/tests/system/server/server-drain.cpp
 * @brief The HTTP/1.1 server's drain(deadline) over real sockets (Huly QB-167).
 *
 * drain() closes the listener, closes the sessions that wait, answers the requests already received --
 * the last one `Connection: close` -- and reports, once, on the server's loop: `drained` when the last
 * HTTP session has closed, `deadline` when the deadline came first, after aborting what is still open.
 * Owned WebSocket sessions receive Close 1001 and keep the drain pending until closed or the deadline.
 *
 * The drain is started from a route, so it runs on the server's loop; the clients are raw sockets, so what
 * goes over the wire -- each answer, its `Connection` field, the close -- is what is asserted.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <qb/io/async.h>
#include <qb/io/tcp/socket.h>

#include <qbm/http/http.h>

#include "../../shared/loopback_server.h"
#ifdef QB_HAS_SSL
#include "../../shared/ws_loopback.h"
#endif

using namespace std::chrono_literals;

namespace server_drain_test {

using PlainServer       = qb::http::Server<>;
using PlainServerThread = qb::http::test::ServerThread<PlainServer>;
using PlainContext      = std::shared_ptr<qb::http::Context<qb::http::DefaultSession>>;

/// What the drain reported: -1 before it ends, then the drain_outcome's value; how many times it ran.
std::atomic<int> g_outcome{-1};
std::atomic<int> g_reports{0};
/// The requests a test holds unanswered (their session keeps them; these only point at them), completed by a later
/// route -- all on the server's loop.
std::vector<std::weak_ptr<qb::http::Context<qb::http::DefaultSession>>> g_held;
/// Sessions extracted from the server, as a WebSocket upgrade hands its connection to another actor: kept open.
std::vector<qb::http::DefaultSession::transport_io_type> g_extracted;

void
reset_globals() {
    g_outcome = -1;
    g_reports = 0;
    g_held.clear();
    g_extracted.clear();
}

/// A raw client: what it sent is bytes, what it saw is bytes, and whether the server ended the connection.
class RawClient {
    qb::io::tcp::socket _sock;

public:
    std::string received;
    bool        connected = false;
    bool        closed    = false; ///< EOF or an error ended the read side

    explicit RawClient(std::uint16_t port) {
        connected = _sock.connect_v4("127.0.0.1", port) == 0;
        if (connected)
            (void) _sock.set_nonblocking(true);
    }

    void
    send(std::string const &bytes) {
        std::size_t off = 0;
        const auto  end = std::chrono::steady_clock::now() + 5s;
        while (off < bytes.size() && std::chrono::steady_clock::now() < end) {
            const int n = _sock.write(bytes.data() + off, bytes.size() - off);
            if (n > 0)
                off += static_cast<std::size_t>(n);
            else
                std::this_thread::sleep_for(1ms);
        }
    }

    /// Reads until @p done holds, the connection ends, or @p budget elapses.
    template <typename Pred>
    void
    read_until(Pred &&done, std::chrono::milliseconds budget = 5000ms) {
        char       buffer[4096];
        const auto end = std::chrono::steady_clock::now() + budget;
        while (!done() && !closed && std::chrono::steady_clock::now() < end) {
            const int got = _sock.read(buffer, sizeof(buffer));
            if (got > 0) {
                received.append(buffer, static_cast<std::size_t>(got));
                continue;
            }
            // tcp::socket::read() answers -1 at EOF too, with the error cleared to 0.
            const int error = got == 0 ? 0 : qb::io::socket::get_last_errno();
            if (error == 0 || !qb::io::socket::not_recv_error(error)) {
                closed = true;
                break;
            }
            std::this_thread::sleep_for(1ms);
        }
    }

    void
    read_to_close(std::chrono::milliseconds budget = 5000ms) {
        read_until([] { return false; }, budget);
    }

    [[nodiscard]] std::size_t
    responses() const {
        std::size_t n = 0;
        for (auto at = received.find("HTTP/1.1 "); at != std::string::npos; at = received.find("HTTP/1.1 ", at + 1))
            ++n;
        return n;
    }

    void
    close() {
        _sock.close();
    }

    qb::io::tcp::socket &
    socket() {
        return _sock;
    }
};

std::string
get(std::string const &target) {
    return "GET " + target + " HTTP/1.1\r\nHost: h\r\n\r\n";
}

/// Waits (from the test thread) until the drain reported.
bool
wait_for_report(std::chrono::milliseconds budget = 5000ms) {
    const auto end = std::chrono::steady_clock::now() + budget;
    while (g_reports.load() == 0 && std::chrono::steady_clock::now() < end)
        std::this_thread::sleep_for(1ms);
    return g_reports.load() != 0;
}

/// A server whose routes start the drain and hold requests: `/ping` answers, `/hold` keeps its request
/// unanswered, `/drain?ms=N` drains with an N ms deadline then answers, `/drain-release` drains (5 s) then
/// completes the held requests.
class DrainServer {
public:
    std::unique_ptr<PlainServerThread> thread;
    std::uint16_t                      port = 0;

    DrainServer() {
        reset_globals();
        thread = std::make_unique<PlainServerThread>([] { return qb::http::make_server(); },
                                                     [](PlainServer &srv) -> bool {
                                                         srv.router().get("/ping", [](PlainContext ctx) { ctx->text("pong"); });
                                                         srv.router().get("/hold", [](PlainContext ctx) { g_held.push_back(ctx); });
                                                         srv.router().get("/extract", [&srv](PlainContext ctx) {
                                                             auto [io, ok] = srv.extractSession(ctx->session()->id());
                                                             if (ok)
                                                                 g_extracted.push_back(std::move(io));
                                                             ctx->suppress_response();
                                                         });
                                                         srv.router().get("/drain", [&srv](PlainContext ctx) {
                                                             const auto ms = std::stoi(ctx->request().query_or("ms", "5000"));
                                                             srv.drain(std::chrono::milliseconds(ms), [](qb::http::drain_outcome outcome) {
                                                                 g_outcome = static_cast<int>(outcome);
                                                                 ++g_reports;
                                                             });
                                                             ctx->text("draining");
                                                         });
                                                         srv.router().get("/drain-release", [&srv](PlainContext ctx) {
                                                             srv.drain(5s, [](qb::http::drain_outcome outcome) {
                                                                 g_outcome = static_cast<int>(outcome);
                                                                 ++g_reports;
                                                             });
                                                             for (auto &held : g_held) {
                                                                 if (auto context = held.lock())
                                                                     context->text("released");
                                                             }
                                                             g_held.clear();
                                                             ctx->text("draining");
                                                         });
                                                         srv.router().compile();
                                                         if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                                                             return false;
                                                         srv.start();
                                                         return true;
                                                     });
        if (thread->ready())
            port = thread->port();
    }
};

} // namespace server_drain_test

using namespace server_drain_test;

#ifdef QB_HAS_SSL
namespace server_drain_test {
class UpgradeSession;
std::atomic<bool> g_message_preserved{false};
std::atomic<int>  g_draining_control_callbacks{0};
std::atomic<int>  g_close_callbacks{0};
using UpgradeServer = qb::http::Server<UpgradeSession>;
class UpgradeSession : public qb::http::use<UpgradeSession>::session<UpgradeServer> {
public:
    using Base       = qb::http::use<UpgradeSession>::session<UpgradeServer>;
    using WsProtocol = qb::http::ws::protocol<UpgradeSession>;
    explicit UpgradeSession(UpgradeServer &server)
        : Base(server) {}
    void
    on(WsProtocol::message &&event) {
        if (event.ws.data().view() == "drain-in-handler") {
            this->server().drain(5s, [](qb::http::drain_outcome outcome) {
                g_outcome = static_cast<int>(outcome);
                ++g_reports;
            });
            g_message_preserved = event.ws.data().view() == "drain-in-handler";
        } else {
            *this << event.ws;
        }
    }
    void
    on(WsProtocol::ping &&) {
        ++g_draining_control_callbacks;
    }
    void
    on(WsProtocol::pong &&) {
        ++g_draining_control_callbacks;
    }
    void
    on(WsProtocol::close &&event) {
        ++g_close_callbacks;
        if (!this->server().draining())
            *this << event.ws;
    }
};

class UpgradeDrainServer {
public:
    qb::http::test::ServerThread<UpgradeServer> thread;
    UpgradeDrainServer()
        : thread([] { return qb::http::make_server<UpgradeSession>(); },
                 [](UpgradeServer &server) {
                     using Ctx = std::shared_ptr<qb::http::Context<UpgradeSession>>;
                     server.router().get("/ws", [](Ctx ctx) {
                         auto session = ctx->session();
                         if (!session || !session->template switch_protocol<UpgradeSession::WsProtocol>(*session, ctx->request())) {
                             ctx->text("upgrade failed", qb::http::Status::BAD_REQUEST);
                             return;
                         }
                         ctx->suppress_response();
                     });
                     server.router().get("/drain", [&server](Ctx ctx) {
                         const auto ms = std::stoi(ctx->request().query_or("ms", "5000"));
                         server.drain(std::chrono::milliseconds(ms), [](qb::http::drain_outcome outcome) {
                             g_outcome = static_cast<int>(outcome);
                             ++g_reports;
                         });
                         ctx->text("draining");
                     });
                     server.router().compile();
                     if (server.transport().listen_v4(0, "127.0.0.1") != 0)
                         return false;
                     server.start();
                     return true;
                 }) {}
};
} // namespace server_drain_test

TEST(HttpServerDrain, WebSocketCloseIsSentAndDrainWaitsForItsReply) {
    reset_globals();
    g_close_callbacks = 0;
    UpgradeDrainServer server;
    ASSERT_TRUE(server.thread.ready());
    RawClient upgraded(server.thread.port());
    ASSERT_TRUE(upgraded.connected);
    qb::http::test::perform_upgrade(upgraded.socket(), server.thread.port(), "/ws");

    RawClient caller(server.thread.port());
    ASSERT_TRUE(caller.connected);
    caller.send(get("/drain?ms=5000"));
    caller.read_to_close();
    caller.close();
    upgraded.read_until([&] { return qb::http::test::extract_close_code(upgraded.received).has_value(); }, 500ms);
    ASSERT_EQ(qb::http::test::extract_close_code(upgraded.received), 1001);
    EXPECT_EQ(g_reports.load(), 0) << "a live WebSocket keeps the drain pending";
    EXPECT_FALSE(upgraded.closed);

    RawClient refused(server.thread.port());
    EXPECT_FALSE(refused.connected) << "the listener stays closed while a WebSocket finishes";
    auto close = qb::http::test::make_client_frame(0x88, std::string("\x03\xe9", 2));
    upgraded.send(std::string(close.begin(), close.end()));
    upgraded.read_to_close();
    EXPECT_TRUE(upgraded.closed);
    upgraded.close();
    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_reports.load(), 1);
    EXPECT_EQ(g_close_callbacks.load(), 1);
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::drained));
}

TEST(HttpServerDrain, SilentWebSocketIsAbortedAtTheDrainDeadline) {
    reset_globals();
    UpgradeDrainServer server;
    ASSERT_TRUE(server.thread.ready());
    RawClient upgraded(server.thread.port());
    ASSERT_TRUE(upgraded.connected);
    qb::http::test::perform_upgrade(upgraded.socket(), server.thread.port(), "/ws");
    RawClient caller(server.thread.port());
    ASSERT_TRUE(caller.connected);
    caller.send(get("/drain?ms=200"));
    caller.read_to_close();
    caller.close();
    upgraded.read_to_close(2000ms);
    EXPECT_EQ(qb::http::test::extract_close_code(upgraded.received), 1001);
    EXPECT_TRUE(upgraded.closed);
    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_reports.load(), 1);
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::deadline));
}

TEST(HttpServerDrain, WebSocketDrainPreservesTheMessageThatStartedItAndFlushesItsClose) {
    reset_globals();
    g_message_preserved = false;
    UpgradeDrainServer server;
    ASSERT_TRUE(server.thread.ready());
    RawClient upgraded(server.thread.port());
    ASSERT_TRUE(upgraded.connected);
    qb::http::test::perform_upgrade(upgraded.socket(), server.thread.port(), "/ws");
    auto message            = qb::http::test::make_client_frame(0x81, "drain-in-handler");
    auto simultaneous_close = qb::http::test::make_client_frame(0x88, std::string("\x03\xe9", 2));
    message.insert(message.end(), simultaneous_close.begin(), simultaneous_close.end());
    upgraded.send(std::string(message.begin(), message.end()));
    upgraded.read_to_close();
    upgraded.close();
    EXPECT_TRUE(g_message_preserved.load()) << "drain() must not reset a borrowed message under its handler";
    EXPECT_EQ(qb::http::test::extract_close_code(upgraded.received), 1001) << "a simultaneous peer Close must not discard our queued Close";
    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::drained));
}

TEST(HttpServerDrain, WebSocketDrainDoesNotDispatchDataOrControlCallbacksAfterClose) {
    reset_globals();
    g_draining_control_callbacks = 0;
    g_close_callbacks            = 0;
    UpgradeDrainServer server;
    ASSERT_TRUE(server.thread.ready());
    RawClient upgraded(server.thread.port());
    ASSERT_TRUE(upgraded.connected);
    qb::http::test::perform_upgrade(upgraded.socket(), server.thread.port(), "/ws");
    const std::string ping_payload("p\0ng\xff", 5);
    auto              wire = qb::http::test::make_client_frame(0x81, "drain-in-handler");
    // Before the peer's Close: automatic Pong remains mandatory, application callbacks stay suppressed.
    // After it: even coalesced trailing frames must not reach the protocol or publish another Pong.
    for (const auto opcode : {0x89, 0x8a, 0x82, 0x88, 0x89, 0x8a, 0x82}) {
        const auto payload = opcode == 0x88 ? std::string("\x03\xe9", 2) : ping_payload;
        auto       frame   = qb::http::test::make_client_frame(static_cast<std::uint8_t>(opcode), payload);
        wire.insert(wire.end(), frame.begin(), frame.end());
    }
    upgraded.send(std::string(wire.begin(), wire.end()));
    upgraded.read_to_close();
    upgraded.close();
    EXPECT_TRUE(upgraded.closed);
    EXPECT_EQ(g_draining_control_callbacks.load(), 0);
    EXPECT_EQ(g_close_callbacks.load(), 1);
    // Exact wire oracle: one unmasked Close 1001, then one unmasked Pong with the identical binary payload.
    // Equality also rejects echoed Data, a second Close, or a Pong for the Ping after the acknowledgement.
    const std::string expected = std::string("\x88\x11\x03\xe9", 4) + "server draining" + std::string("\x8a\x05", 2) + ping_payload;
    EXPECT_EQ(upgraded.received, expected);
    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_reports.load(), 1);
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::drained));
}
#endif

// An idle keep-alive connection is closed by the drain, without an answer; the request that started the drain
// is answered `Connection: close`; the listener refuses a new connection; the drain reports `drained` once both
// connections are gone.
TEST(HttpServerDrain, AnIdleConnectionIsClosedAndTheListenerRefusesNewOnes) {
    DrainServer server;
    ASSERT_NE(server.port, 0);

    RawClient idle(server.port);
    ASSERT_TRUE(idle.connected);
    idle.send(get("/ping"));
    idle.read_until([&] { return idle.received.find("pong") != std::string::npos; });
    ASSERT_EQ(idle.responses(), 1u) << idle.received;
    EXPECT_EQ(idle.received.find("connection: close"), std::string::npos) << "a keep-alive answer before the drain";

    RawClient caller(server.port);
    ASSERT_TRUE(caller.connected);
    caller.send(get("/drain?ms=5000"));
    caller.read_to_close();
    EXPECT_EQ(caller.received.rfind("HTTP/1.1 200 ", 0), 0u) << caller.received;
    EXPECT_NE(caller.received.find("connection: close"), std::string::npos) << "the last answer closes the connection";
    EXPECT_TRUE(caller.closed);
    caller.close();

    const auto before = idle.received.size();
    idle.read_to_close();
    EXPECT_TRUE(idle.closed) << "the idle connection is closed by the drain";
    EXPECT_EQ(idle.received.size(), before) << "and nothing is sent on it";
    idle.close();

    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::drained));
    EXPECT_EQ(g_reports.load(), 1) << "the drain reports once";

    RawClient late(server.port);
    EXPECT_FALSE(late.connected) << "the listening socket is closed";
}

// Requests pipelined before the drain are all answered, in order; only the last carries `Connection: close`,
// and the connection closes after it.
TEST(HttpServerDrain, PipelinedRequestsAreAnsweredAndOnlyTheLastClosesTheConnection) {
    DrainServer server;
    ASSERT_NE(server.port, 0);

    RawClient pipelined(server.port);
    ASSERT_TRUE(pipelined.connected);
    pipelined.send(get("/hold") + get("/ping") + get("/ping")); // the first is held: the other two wait behind it
    std::this_thread::sleep_for(100ms);

    RawClient caller(server.port);
    ASSERT_TRUE(caller.connected);
    caller.send(get("/drain-release"));
    caller.read_to_close();
    caller.close();

    pipelined.read_to_close();
    EXPECT_EQ(pipelined.responses(), 3u) << pipelined.received;
    const auto last = pipelined.received.rfind("HTTP/1.1 ");
    ASSERT_NE(last, std::string::npos);
    EXPECT_EQ(pipelined.received.find("connection: close"), pipelined.received.find("connection: close", last))
        << "only the last answer closes the connection: " << pipelined.received;
    EXPECT_NE(pipelined.received.find("connection: close", last), std::string::npos);
    EXPECT_TRUE(pipelined.closed);
    pipelined.close();

    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::drained));
}

// A request still unanswered when the deadline comes is aborted, and the drain reports `deadline`.
TEST(HttpServerDrain, TheDeadlineAbortsWhatIsStillOpen) {
    DrainServer server;
    ASSERT_NE(server.port, 0);

    RawClient held(server.port);
    ASSERT_TRUE(held.connected);
    held.send(get("/hold"));
    std::this_thread::sleep_for(100ms);

    const auto started = std::chrono::steady_clock::now();
    RawClient  caller(server.port);
    ASSERT_TRUE(caller.connected);
    caller.send(get("/drain?ms=300"));
    caller.read_to_close();
    caller.close();

    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::deadline));
    EXPECT_GE(std::chrono::steady_clock::now() - started, 250ms) << "not before the deadline";
    held.read_to_close();
    EXPECT_TRUE(held.closed) << "the session still at work is aborted";
    EXPECT_EQ(held.responses(), 0u);
    held.close();
}

// A session extracted from the server -- a WebSocket upgrade handing its connection to another actor -- is no longer
// the server's: the drain neither closes it nor waits for it, and reports `drained` while it lives (closing a
// owned WebSocket with 1001 Going Away is covered by the cases above, Huly QB-1097).
TEST(HttpServerDrain, AnExtractedSessionIsOutsideTheDrain) {
    DrainServer server;
    ASSERT_NE(server.port, 0);

    RawClient upgraded(server.port);
    ASSERT_TRUE(upgraded.connected);
    upgraded.send(get("/extract"));
    std::this_thread::sleep_for(100ms);

    RawClient caller(server.port);
    ASSERT_TRUE(caller.connected);
    caller.send(get("/drain?ms=5000"));
    caller.read_to_close();
    caller.close();

    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::drained));
    upgraded.read_until([] { return false; }, 200ms);
    EXPECT_FALSE(upgraded.closed) << "the extracted connection lives on";
    EXPECT_TRUE(upgraded.received.empty());
    upgraded.close();
}

// With no HTTP session open the drain reports `drained` at once -- before drain() returns -- and the listener is
// closed.
TEST(HttpServerDrain, WithNoSessionTheDrainReportsAtOnce) {
    reset_globals();
    std::atomic<bool> returned_after_report{false};
    PlainServerThread thread([] { return qb::http::make_server(); },
                             [&returned_after_report](PlainServer &srv) -> bool {
                                 srv.router().get("/ping", [](PlainContext ctx) { ctx->text("pong"); });
                                 srv.router().compile();
                                 if (srv.transport().listen_v4(0, "127.0.0.1") != 0)
                                     return false;
                                 srv.start();
                                 qb::io::async::callback(
                                     [&srv, &returned_after_report] {
                                         const bool started    = srv.drain(5s, [](qb::http::drain_outcome outcome) {
                                             g_outcome = static_cast<int>(outcome);
                                             ++g_reports;
                                         });
                                         returned_after_report = started && g_reports.load() == 1;
                                     },
                                     100ms);
                                 return true;
                             });
    ASSERT_TRUE(thread.ready());
    const auto port = thread.port();

    ASSERT_TRUE(wait_for_report());
    EXPECT_EQ(g_outcome.load(), static_cast<int>(qb::http::drain_outcome::drained));
    const auto until = std::chrono::steady_clock::now() + 1s;
    while (!returned_after_report.load() && std::chrono::steady_clock::now() < until)
        std::this_thread::sleep_for(1ms);
    EXPECT_TRUE(returned_after_report.load()) << "the report ran before drain() returned";
    RawClient late(port);
    EXPECT_FALSE(late.connected) << "the listening socket is closed";
}

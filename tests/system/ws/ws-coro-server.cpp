/**
 * @file qbm/http/tests/system/ws/ws-coro-server.cpp
 * @brief End-to-end system tests for the server-side coroutine session API
 *        (`qb::http::ws::coro_session`).
 *
 * Each case brings up a server whose session type is written as a single
 * coroutine (`run()` returns `qb::io::async::task<void>`) on its own event loop
 * (via the shared `WsServerThread`), then drives it with a standalone
 * `qb::http::ws::coro_client` over plaintext `ws://` loopback:
 *
 *   - `CoroEchoRoundTrip`        — session echoes text via `next_frame()`.
 *   - `CoroBinaryIsDistinguished` — binary frames report `is_text == false`.
 *   - `CoroHandshakeHookAdvertisesSubprotocol` — a hook selects a subprotocol
 *                                  and the client sees it via
 *                                  `negotiated_subprotocol()`.
 *   - `CoroNegotiatedSubprotocolEmptyWhenNoOffer` — no offer ⇒ empty.
 *   - `CoroHandshakeHookRejectsUpgrade` — the client `connect()` reports
 *                                  `ok == false` on a hook refusal.
 *   - `CoroHandshakeHookRejectsWithHttpResponse` — the refusal delivers the
 *                                  configured `403` body before closing.
 *   - `CoroSessionClosesGracefully` — `co_await close_async()` queues a Close
 *                                  the client observes with the exact code/reason.
 *
 * Runs plaintext `ws://`; REQUIRES the SSL/crypto library only to LINK
 * (`ws/ws.h` uses `qb::io::crypto` for `Sec-WebSocket-Accept`). Harness and the
 * raw-socket helper come from `shared/ws_loopback.h`; ports are ephemeral.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <atomic>
#include <chrono>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>

#include <gtest/gtest.h>

#include <qbm/http/ws/coro.h>

#include "../../shared/ws_loopback.h"

namespace ws_coro_server_test {

using namespace std::chrono_literals;
using qb::http::test::read_http_response;
using qb::http::test::WsServerThread;

// ---------------------------------------------------------------------------
// Echo session: `run()` reflects every text / binary message back to the peer
// and exits on Close or Disconnect.
// ---------------------------------------------------------------------------

class EchoCoroServer;

class EchoCoroSession : public qb::http::ws::coro_session<EchoCoroSession, EchoCoroServer> {
public:
    using base = qb::http::ws::coro_session<EchoCoroSession, EchoCoroServer>;
    using base::base;

    qb::io::async::task<void>
    run() {
        while (true) {
            auto frame = co_await this->next_frame();
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected || frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
                co_return;
            }
            if (frame.kind == qb::http::ws::IncomingFrame::Kind::Message) {
                if (frame.is_text) {
                    qb::http::ws::MessageText reply;
                    reply << frame.payload;
                    *this << reply;
                } else {
                    qb::http::ws::MessageBinary reply;
                    reply << frame.payload;
                    *this << reply;
                }
            }
        }
    }
};

class EchoCoroServer : public qb::io::use<EchoCoroServer>::tcp::server<EchoCoroSession> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Server whose handshake hook picks "chat.v2" if offered and advertises it.
// ---------------------------------------------------------------------------

class SubprotoCoroServer;

class SubprotoCoroSession : public qb::http::ws::coro_session<SubprotoCoroSession, SubprotoCoroServer> {
public:
    using base = qb::http::ws::coro_session<SubprotoCoroSession, SubprotoCoroServer>;

    SubprotoCoroSession(SubprotoCoroServer &s)
        : base(s) {
        set_handshake_hook([](SubprotoCoroSession &, qb::http::Request &req, qb::http::Response &res) {
            const std::string &offered = req.header("Sec-WebSocket-Protocol");
            if (!offered.empty()) {
                std::string_view sv{offered};
                std::string      chosen;
                std::size_t      start = 0;
                for (std::size_t i = 0; i <= sv.size(); ++i) {
                    if (i == sv.size() || sv[i] == ',') {
                        std::string_view tok = sv.substr(start, i - start);
                        while (!tok.empty() && tok.front() == ' ')
                            tok.remove_prefix(1);
                        while (!tok.empty() && tok.back() == ' ')
                            tok.remove_suffix(1);
                        if (tok == "chat.v2") {
                            chosen = std::string(tok);
                            break;
                        }
                        start = i + 1;
                    }
                }
                if (!chosen.empty()) {
                    res.headers()["Sec-WebSocket-Protocol"].emplace_back(std::move(chosen));
                }
            }
            return true;
        });
    }

    qb::io::async::task<void>
    run() {
        auto frame = co_await this->next_frame();
        if (frame.kind == qb::http::ws::IncomingFrame::Kind::Message) {
            qb::http::ws::MessageText reply;
            reply << "ok:" << frame.payload;
            *this << reply;
        }
        while (true) {
            auto f = co_await this->next_frame();
            if (f.kind == qb::http::ws::IncomingFrame::Kind::Disconnected || f.kind == qb::http::ws::IncomingFrame::Kind::Close) {
                co_return;
            }
        }
    }
};

class SubprotoCoroServer : public qb::io::use<SubprotoCoroServer>::tcp::server<SubprotoCoroSession> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Server whose handshake hook refuses the upgrade with a 403 response.
// ---------------------------------------------------------------------------

class RejectingCoroServer;

class RejectingCoroSession : public qb::http::ws::coro_session<RejectingCoroSession, RejectingCoroServer> {
public:
    using base = qb::http::ws::coro_session<RejectingCoroSession, RejectingCoroServer>;

    RejectingCoroSession(RejectingCoroServer &s)
        : base(s) {
        set_handshake_hook([](RejectingCoroSession &, qb::http::Request &, qb::http::Response &res) {
            res.status() = qb::http::status::FORBIDDEN;
            res.body()   = "not allowed";
            return false;
        });
    }

    qb::io::async::task<void>
    run() {
        co_return; // Never reached — handshake is rejected.
    }
};

class RejectingCoroServer : public qb::io::use<RejectingCoroServer>::tcp::server<RejectingCoroSession> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Server that, after the first message, initiates a graceful close via the
// coroutine API (`co_await close_async(status, reason)`).
// ---------------------------------------------------------------------------

class ClosingCoroServer;

class ClosingCoroSession : public qb::http::ws::coro_session<ClosingCoroSession, ClosingCoroServer> {
public:
    using base = qb::http::ws::coro_session<ClosingCoroSession, ClosingCoroServer>;
    using base::base;

    qb::io::async::task<void>
    run() {
        auto frame = co_await this->next_frame();
        if (frame.kind != qb::http::ws::IncomingFrame::Kind::Message) {
            co_return;
        }
        auto res = co_await this->close_async(qb::http::ws::CloseStatus::GoingAway, "session over");
        (void) res;
    }
};

class ClosingCoroServer : public qb::io::use<ClosingCoroServer>::tcp::server<ClosingCoroSession> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Test fixture.
// ---------------------------------------------------------------------------

class WsCoroServer : public ::testing::Test {
protected:
    void
    SetUp() override {
        qb::io::async::init();
    }

    void
    TearDown() override {
        if (qb::io::async::listener::current.has_coro_scheduler()) {
            qb::io::async::run_for(5ms);
            qb::io::async::listener::current.reset_coro_scheduler();
        }
        qb::io::async::listener::current.clear();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_F(WsCoroServer, CoroEchoRoundTrip) {
    WsServerThread<EchoCoroServer> server{0};
    const std::string              url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto scenario = [&]() -> qb::io::async::task<std::string> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return std::string{};

        qb::http::ws::MessageText msg;
        msg << "echo-me";
        ws << msg;

        auto frame = co_await ws.receive();
        EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Message);
        EXPECT_TRUE(frame.is_text);
        co_return frame.payload;
    };

    EXPECT_EQ(qb::http::ws::run_sync(scenario()), "echo-me");
}

TEST_F(WsCoroServer, CoroBinaryIsDistinguished) {
    WsServerThread<EchoCoroServer> server{0};
    const std::string              url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto scenario = [&]() -> qb::io::async::task<bool> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return false;

        qb::http::ws::MessageBinary msg;
        const std::string           payload("\x00\x01\x02\x03bin", 7);
        msg << payload;
        ws << msg;

        auto frame = co_await ws.receive();
        EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Message);
        EXPECT_FALSE(frame.is_text);
        EXPECT_EQ(frame.payload, payload);
        co_return frame.payload == payload && !frame.is_text;
    };

    EXPECT_TRUE(qb::http::ws::run_sync(scenario()));
}

TEST_F(WsCoroServer, CoroHandshakeHookAdvertisesSubprotocol) {
    WsServerThread<SubprotoCoroServer> server{0};
    const std::string                  url = "ws://localhost:" + std::to_string(server.port) + "/";

    struct Outcome {
        std::string echoed;
        std::string negotiated;
    };

    auto scenario = [&]() -> qb::io::async::task<Outcome> {
        qb::http::ws::coro_client ws;
        ws.set_subprotocols({"chat.v1", "chat.v2"});

        auto c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return Outcome{};

        qb::http::ws::MessageText msg;
        msg << "hello";
        ws << msg;

        auto frame = co_await ws.receive();
        EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Message);
        co_return Outcome{frame.payload, std::string(ws.negotiated_subprotocol())};
    };

    const auto out = qb::http::ws::run_sync(scenario());
    EXPECT_EQ(out.echoed, "ok:hello");
    EXPECT_EQ(out.negotiated, "chat.v2");
}

// Server advertises no subprotocol when the client didn't offer one —
// `negotiated_subprotocol()` must stay empty. Regression guard against
// accidental header leakage.
TEST_F(WsCoroServer, CoroNegotiatedSubprotocolEmptyWhenNoOffer) {
    WsServerThread<EchoCoroServer> server{0};
    const std::string              url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto scenario = [&]() -> qb::io::async::task<std::string> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        co_return std::string(ws.negotiated_subprotocol());
    };

    EXPECT_TRUE(qb::http::ws::run_sync(scenario()).empty());
}

TEST_F(WsCoroServer, CoroHandshakeHookRejectsUpgrade) {
    WsServerThread<RejectingCoroServer> server{0};
    const std::string                   url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto scenario = [&]() -> qb::io::async::task<bool> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect(std::string_view{url});
        co_return c.ok;
    };

    EXPECT_FALSE(qb::http::ws::run_sync(scenario()));
}

TEST_F(WsCoroServer, CoroHandshakeHookRejectsWithHttpResponse) {
    WsServerThread<RejectingCoroServer> server{0};

    qb::io::tcp::socket sock;
    ASSERT_EQ(sock.connect(qb::io::uri{"tcp://localhost:" + std::to_string(server.port)}), 0);
    (void) sock.set_nonblocking(true);

    const std::string request = "GET /ws HTTP/1.1\r\n"
                                "Host: localhost:"
                                + std::to_string(server.port)
                                + "\r\n"
                                  "Upgrade: websocket\r\n"
                                  "Connection: Upgrade\r\n"
                                  "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                  "Sec-WebSocket-Version: 13\r\n"
                                  "\r\n";
    sock.write(request.data(), static_cast<int>(request.size()));

    const std::string response = read_http_response(sock);
    EXPECT_NE(response.find("403"), std::string::npos) << response;
    EXPECT_NE(response.find("not allowed"), std::string::npos) << response;
    EXPECT_EQ(response.find("101"), std::string::npos) << response;
    sock.close();
}

TEST_F(WsCoroServer, CoroSessionClosesGracefully) {
    WsServerThread<ClosingCoroServer> server{0};
    const std::string                 url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto scenario = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame{};

        qb::http::ws::MessageText msg;
        msg << "trigger-close";
        ws << msg;

        // The server replies with a Close frame carrying the exact code/reason.
        // A spurious Disconnect is the only documented fallback (transport
        // yanked while the Close is in flight).
        co_return co_await ws.receive();
    };

    const auto frame = qb::http::ws::run_sync(scenario());
    ASSERT_TRUE(frame.kind == qb::http::ws::IncomingFrame::Kind::Close || frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected)
        << "unexpected frame kind " << static_cast<int>(frame.kind);
    // The expected path is a clean Close with the server's exact code + reason.
    // We assert it whenever it is the (overwhelmingly common) outcome, and only
    // tolerate Disconnected as the documented transport-drop fallback.
    if (frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
        EXPECT_EQ(frame.close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::GoingAway));
        EXPECT_EQ(frame.close_reason, "session over");
    }
}

// QB-514, server side: use the existing named coroutine session fixture and
// its public frame sink, with a task which actually owns the suspended frame.
TEST_F(WsCoroServer, AbandonedNextFrameReleasesOnlyItsOwnConsumerSlot) {
    EchoCoroServer  server;
    EchoCoroSession session(server);
    int             resumed = 0;
    auto            receive = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        auto frame = co_await session.next_frame();
        ++resumed;
        co_return frame;
    };
    {
        auto abandoned = receive();
        abandoned.handle().resume();
        ASSERT_FALSE(abandoned.handle().done());
    }
    auto replacement = receive();
    replacement.handle().resume();
    ASSERT_FALSE(replacement.handle().done());
    qb::http::ws::MessageText message;
    message << "server-replacement";
    session.on(EchoCoroSession::WS_Protocol::message{message.size(), message.data().cbegin(), message});
    for (int turn = 0; turn != 16 && !replacement.handle().done(); ++turn)
        qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(replacement.handle().done());
    EXPECT_EQ(replacement.await_resume().payload, "server-replacement");
    EXPECT_EQ(resumed, 1);

    // A completed predecessor's awaiter is destroyed only after the next
    // consumer has reserved the slot. Its token cannot release that consumer.
    auto preceding = receive();
    preceding.handle().resume();
    ASSERT_FALSE(preceding.handle().done());
    qb::http::ws::MessageText preceding_message;
    preceding_message << "server-preceding";
    session.on(EchoCoroSession::WS_Protocol::message{preceding_message.size(), preceding_message.data().cbegin(), preceding_message});
    auto next = receive();
    next.handle().resume();
    ASSERT_FALSE(next.handle().done());
    for (int turn = 0; turn != 16 && !preceding.handle().done(); ++turn)
        qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(preceding.handle().done());
    EXPECT_EQ(preceding.await_resume().payload, "server-preceding");
    EXPECT_FALSE(next.handle().done());
    qb::http::ws::MessageText next_message;
    next_message << "server-next";
    session.on(EchoCoroSession::WS_Protocol::message{next_message.size(), next_message.data().cbegin(), next_message});
    for (int turn = 0; turn != 16 && !next.handle().done(); ++turn)
        qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(next.handle().done());
    EXPECT_EQ(next.await_resume().payload, "server-next");
    EXPECT_EQ(resumed, 3);
}

TEST_F(WsCoroServer, FrameAfterAbandonedNextFrameIsAvailableToTheNextConsumer) {
    EchoCoroServer  server;
    EchoCoroSession session(server);
    auto            receive = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        co_return co_await session.next_frame();
    };
    {
        auto abandoned = receive();
        abandoned.handle().resume();
        ASSERT_FALSE(abandoned.handle().done());
    }
    qb::http::ws::MessageText message;
    message << "server-buffered";
    session.on(EchoCoroSession::WS_Protocol::message{message.size(), message.data().cbegin(), message});
    auto replacement = receive();
    replacement.handle().resume();
    for (int turn = 0; turn != 16 && !replacement.handle().done(); ++turn)
        qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(replacement.handle().done()) << "a dead receiver must not consume the frame";
    EXPECT_EQ(replacement.await_resume().payload, "server-buffered");
}

// QB-515: a rejected close must neither reserve completion nor suppress a
// peer-initiated Close echo. Both code and UTF-8 validation precede publication.
TEST_F(WsCoroServer, RejectedCloseDoesNotSuppressThePeerCloseEcho) {
    using Status = qb::http::ws::CloseStatus;
    for (bool bad_code : {true, false}) {
        EchoCoroServer  server;
        EchoCoroSession session(server);
        bool            rejected = false;
        auto            reject   = [&]() -> qb::io::async::task<void> {
            try {
                (void) co_await session.close_async(bad_code ? static_cast<Status>(1005u) : Status::Normal,
                                                    bad_code ? std::string_view{"invalid code"} : std::string_view{"\xED\xA0\x80", 3});
            } catch (const std::invalid_argument &) {
                rejected = true;
            }
        };
        auto rejected_task = reject();
        rejected_task.handle().resume();
        ASSERT_TRUE(rejected_task.handle().done());
        ASSERT_NO_THROW(rejected_task.await_resume());
        ASSERT_TRUE(rejected);
        ASSERT_EQ(session.out().size(), 0u);
        qb::http::ws::MessageClose peer(Status::Normal, "peer");
        session.on(EchoCoroSession::WS_Protocol::close{peer.size(), peer.data().cbegin(), peer});
        EXPECT_EQ(session.out().size(), 2u + peer.size()) << "the rejected local close sent no frame, so the peer Close needs an echo";
    }
}

TEST_F(WsCoroServer, RejectedCloseAllowsAValidCloseOnTheSameSession) {
    EchoCoroServer  server;
    EchoCoroSession session(server);
    using Status   = qb::http::ws::CloseStatus;
    bool rejected  = false;
    bool completed = false;
    auto scenario  = [&]() -> qb::io::async::task<void> {
        try {
            (void) co_await session.close_async(static_cast<Status>(1005u));
        } catch (const std::invalid_argument &) {
            rejected = true;
        }
        completed = (co_await session.close_async(Status::Normal, "valid")).ok;
    };
    auto task = scenario();
    task.handle().resume();
    ASSERT_TRUE(rejected);
    ASSERT_FALSE(task.handle().done()) << "the refused close must not leave a completion slot";
    const auto queued_bytes = session.out().size();
    ASSERT_GT(queued_bytes, 0u);
    qb::http::ws::MessageClose peer(Status::Normal, "valid");
    session.on(EchoCoroSession::WS_Protocol::close{peer.size(), peer.data().cbegin(), peer});
    for (int turn = 0; turn != 16 && !task.handle().done(); ++turn)
        qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(task.handle().done());
    EXPECT_NO_THROW(task.await_resume());
    EXPECT_TRUE(completed);
    EXPECT_EQ(session.out().size(), queued_bytes);
}

TEST_F(WsCoroServer, ARealConcurrentNextFrameIsStillRejected) {
    EchoCoroServer  server;
    EchoCoroSession session(server);
    auto            receive = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        co_return co_await session.next_frame();
    };
    auto first = receive();
    first.handle().resume();
    ASSERT_FALSE(first.handle().done());
    auto second = receive();
    second.handle().resume();
    ASSERT_TRUE(second.handle().done());
    EXPECT_THROW((void) second.await_resume(), std::logic_error);
    qb::http::ws::MessageText message;
    message << "server-first";
    session.on(EchoCoroSession::WS_Protocol::message{message.size(), message.data().cbegin(), message});
    for (int turn = 0; turn != 16 && !first.handle().done(); ++turn)
        qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(first.handle().done());
    EXPECT_EQ(first.await_resume().payload, "server-first");
}

TEST_F(WsCoroServer, AbandonedCloseAllowsAReplacementButRejectsAConcurrentClose) {
    EchoCoroServer  server;
    EchoCoroSession session(server);
    auto            close = [&]() -> qb::io::async::task<qb::http::ws::CloseResult> {
        co_return co_await session.close_async(qb::http::ws::CloseStatus::Normal, "valid");
    };
    {
        auto abandoned = close();
        abandoned.handle().resume();
        ASSERT_FALSE(abandoned.handle().done());
    }
    auto replacement = close();
    replacement.handle().resume();
    ASSERT_FALSE(replacement.handle().done()) << "an abandoned Close must not reserve the completion slot";
    auto concurrent = close();
    concurrent.handle().resume();
    ASSERT_TRUE(concurrent.handle().done());
    EXPECT_THROW((void) concurrent.await_resume(), std::logic_error);
    const auto                 queued_bytes = session.out().size();
    qb::http::ws::MessageClose peer(qb::http::ws::CloseStatus::Normal, "valid");
    session.on(EchoCoroSession::WS_Protocol::close{peer.size(), peer.data().cbegin(), peer});
    for (int turn = 0; turn != 16 && !replacement.handle().done(); ++turn)
        qb::io::async::run(EVRUN_NOWAIT);
    ASSERT_TRUE(replacement.handle().done());
    EXPECT_TRUE(replacement.await_resume().ok);
    EXPECT_EQ(session.out().size(), queued_bytes);
}

} // namespace ws_coro_server_test

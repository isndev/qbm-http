/**
 * @file qbm/http/tests/test-coro-server.cpp
 * @brief End-to-end tests for the server-side coroutine session API
 *        (`qb::http::ws::coro_session`).
 *
 * Each test case brings up a server whose session type is written as a
 * single coroutine (`run()` returns `qb::io::async::task<void>`), then
 * drives it with a standalone `qb::http::ws::coro_client`. The goal is
 * to prove that the high-level surface is complete and mono-thread
 * safe:
 *
 *   - `CoroEchoRoundTrip`        — session echoes text frames via
 *                                  `co_await next_frame()` / `*this << reply`.
 *   - `CoroBinaryIsDistinguished` — binary frames are reported with
 *                                  `is_text == false`.
 *   - `CoroHandshakeHookAdvertisesSubprotocol` — a handshake hook mutates
 *                                  the response to select a subprotocol,
 *                                  and the client sees it in the
 *                                  `sending_http_request` echo.
 *   - `CoroHandshakeHookRejectsUpgrade` — a hook refusing the upgrade
 *                                  sends the configured HTTP status and
 *                                  closes the connection.
 *   - `CoroSessionClosesGracefully` — `co_await close_async()` queues a
 *                                  Close frame, the client sees it, and
 *                                  both sides tear down cleanly.
 *
 * The server runs in a dedicated thread (same idiom as `test-coro-client.cpp`)
 * so the coroutine client can drive its own listener independently.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0
 */

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <thread>

#include "../ws/coro.h"

namespace {

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// Echo session: `run()` reflects every text / binary message back to the
// peer and exits on Close or Disconnect.
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
// Server whose handshake hook picks the first subprotocol offered by the
// client and advertises it in the `101 Switching Protocols` response.
// ---------------------------------------------------------------------------

class SubprotoCoroServer;

class SubprotoCoroSession : public qb::http::ws::coro_session<SubprotoCoroSession, SubprotoCoroServer> {
public:
    using base = qb::http::ws::coro_session<SubprotoCoroSession, SubprotoCoroServer>;

    SubprotoCoroSession(SubprotoCoroServer &s)
        : base(s) {
        // Install before start(): pick "chat.v2" if the client offered it,
        // otherwise leave the list empty and still accept.
        set_handshake_hook([](SubprotoCoroSession &, qb::http::Request &req, qb::http::Response &res) {
            const auto &offered = req.header("Sec-WebSocket-Protocol");
            if (!offered.empty()) {
                // Naive tokeniser (RFC 7230 §7 list syntax — spaces +
                // commas). Enough for the test.
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
        // Wait for the client to go away before we do.
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
// Test harness.
// ---------------------------------------------------------------------------

template <typename ServerT>
struct ServerThread {
    std::thread       thread;
    std::atomic<bool> ready{false};
    std::atomic<bool> running{true};
    int               port{0};

    ServerThread(int port_)
        : port(port_) {
        thread = std::thread([this] {
            qb::io::async::init();
            ServerT server;
            server.transport().listen_v4(port);
            server.start();
            ready.store(true, std::memory_order_release);
            while (running.load(std::memory_order_acquire)) {
                if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT)) {
                    std::this_thread::sleep_for(5ms);
                }
            }
        });
        while (!ready.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(5ms);
        }
        std::this_thread::sleep_for(30ms);
    }

    ~ServerThread() {
        running.store(false, std::memory_order_release);
        if (thread.joinable())
            thread.join();
    }
};

class CoroServerTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        qb::io::async::init();
    }
};

std::string
read_http_response(qb::io::tcp::socket &sock) {
    std::string response;
    for (int i = 0; i < 500 && response.find("\r\n\r\n") == std::string::npos; ++i) {
        char buf[512];
        int  n = sock.read(buf, sizeof(buf));
        if (n > 0) {
            response.append(buf, static_cast<std::size_t>(n));
        } else {
            std::this_thread::sleep_for(5ms);
        }
    }
    return response;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_F(CoroServerTest, CoroEchoRoundTrip) {
    ServerThread<EchoCoroServer> server{19941};

    auto scenario = [&]() -> qb::io::async::task<std::string> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect("ws://localhost:19941/");
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

TEST_F(CoroServerTest, CoroBinaryIsDistinguished) {
    ServerThread<EchoCoroServer> server{19942};

    auto scenario = [&]() -> qb::io::async::task<bool> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect("ws://localhost:19942/");
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

TEST_F(CoroServerTest, CoroHandshakeHookAdvertisesSubprotocol) {
    ServerThread<SubprotoCoroServer> server{19943};

    // Client-side uses the first-class `set_subprotocols` API — the
    // offer appears verbatim in the outgoing `Sec-WebSocket-Protocol`
    // header, and the selected value round-trips back through
    // `negotiated_subprotocol()` after `connect()` resolves.

    struct Outcome {
        std::string echoed;
        std::string negotiated;
    };

    auto scenario = [&]() -> qb::io::async::task<Outcome> {
        qb::http::ws::coro_client ws;
        ws.set_subprotocols({"chat.v1", "chat.v2"});

        auto c = co_await ws.connect("ws://localhost:19943/");
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
TEST_F(CoroServerTest, CoroNegotiatedSubprotocolEmptyWhenNoOffer) {
    ServerThread<EchoCoroServer> server{19946};

    auto scenario = [&]() -> qb::io::async::task<std::string> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect("ws://localhost:19946/");
        EXPECT_TRUE(c.ok);
        co_return std::string(ws.negotiated_subprotocol());
    };

    EXPECT_TRUE(qb::http::ws::run_sync(scenario()).empty());
}

TEST_F(CoroServerTest, CoroHandshakeHookRejectsUpgrade) {
    ServerThread<RejectingCoroServer> server{19944};

    auto scenario = [&]() -> qb::io::async::task<bool> {
        qb::http::ws::coro_client ws;
        // The server sends a 403 instead of a 101 — the client's handshake
        // validator refuses and `ok` is reported as false.
        auto c = co_await ws.connect("ws://localhost:19944/");
        co_return c.ok;
    };

    EXPECT_FALSE(qb::http::ws::run_sync(scenario()));
}

TEST_F(CoroServerTest, CoroHandshakeHookRejectsWithHttpResponse) {
    ServerThread<RejectingCoroServer> server{19946};

    qb::io::tcp::socket sock;
    ASSERT_EQ(sock.connect(qb::io::uri{"tcp://localhost:19946"}), 0);
    (void) sock.set_nonblocking(true);

    const std::string request = "GET /ws HTTP/1.1\r\n"
                                "Host: localhost:19946\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                "Sec-WebSocket-Version: 13\r\n"
                                "\r\n";
    sock.write(request.data(), static_cast<int>(request.size()));

    const auto response = read_http_response(sock);
    EXPECT_NE(response.find("403"), std::string::npos) << response;
    EXPECT_NE(response.find("not allowed"), std::string::npos) << response;
    EXPECT_EQ(response.find("101"), std::string::npos) << response;
    sock.close();
}

TEST_F(CoroServerTest, CoroSessionClosesGracefully) {
    ServerThread<ClosingCoroServer> server{19945};

    auto scenario = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        auto                      c = co_await ws.connect("ws://localhost:19945/");
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame{};

        qb::http::ws::MessageText msg;
        msg << "trigger-close";
        ws << msg;

        // First event arrives from the server: either the immediate Close
        // frame (most common) or — in the event of a spurious Disconnect
        // while it is in flight — the `Disconnected` signal.
        auto frame = co_await ws.receive();
        co_return frame;
    };

    auto frame = qb::http::ws::run_sync(scenario());
    EXPECT_TRUE(frame.kind == qb::http::ws::IncomingFrame::Kind::Close || frame.kind == qb::http::ws::IncomingFrame::Kind::Disconnected);
    if (frame.kind == qb::http::ws::IncomingFrame::Kind::Close) {
        EXPECT_EQ(frame.close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::GoingAway));
        EXPECT_EQ(frame.close_reason, "session over");
    }
}

} // namespace

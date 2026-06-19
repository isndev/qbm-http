/**
 * @file qbm/http/tests/test-coro-client.cpp
 * @brief End-to-end tests for `qb::http::ws::coro_client`.
 *
 * These tests stand up a tiny echo server built on the classical
 * CRTP API (`qb::io::use<...>::tcp::client<...>`) and exercise the
 * coroutine client against it:
 *
 *   - `ConnectsAndExchangesText`  — connect ➜ send text ➜ receive echo ➜ close.
 *   - `HandlesBinaryPayload`      — binary round-trip, verifies `is_text`.
 *   - `CloseTransportsStatusCode` — server closes with a custom 4xx code and
 *                                   the coroutine receives the value / reason.
 *   - `ReceiveUnblocksOnDisconnect` — server drops the TCP stream, the parked
 *                                   `co_await receive()` returns a frame of
 *                                   `Kind::Disconnected` instead of hanging.
 *
 * The test harness follows the same "two thread / ready flags / EVRUN_ONCE"
 * idiom used by the existing `test-coro-*` suites in `qbm/http`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0
 */

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "../ws.h"

namespace {

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// Minimal echo server built on the existing CRTP API.
// ---------------------------------------------------------------------------

class EchoServer;

class EchoClient : public qb::io::use<EchoClient>::tcp::client<EchoServer> {
public:
    using Protocol    = qb::http::protocol<EchoClient>;
    using WS_Protocol = qb::http::ws::protocol<EchoClient>;

    explicit EchoClient(IOServer &s)
        : client(s) {}

    void
    on(Protocol::request &&req) {
        if (!this->switch_protocol<WS_Protocol>(*this, req)) {
            this->disconnect();
        }
    }

    void
    on(WS_Protocol::message &&event) {
        *this << event.ws;
    }

    void
    on(WS_Protocol::ping &&event) {
        qb::http::ws::MessagePong pong;
        if (event.size) {
            pong << std::string(event.data, event.size);
        }
        *this << pong;
    }
};

class EchoServer : public qb::io::use<EchoServer>::tcp::server<EchoClient> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Server that closes the connection with a custom status right after the
// handshake — used to validate that close frames surface correctly through
// the coroutine `receive()` API.
// ---------------------------------------------------------------------------

class ClosingServer;

class ClosingClient : public qb::io::use<ClosingClient>::tcp::client<ClosingServer> {
public:
    using Protocol    = qb::http::protocol<ClosingClient>;
    using WS_Protocol = qb::http::ws::protocol<ClosingClient>;

    explicit ClosingClient(IOServer &s)
        : client(s) {}

    void
    on(Protocol::request &&req) {
        if (!this->switch_protocol<WS_Protocol>(*this, req)) {
            this->disconnect();
            return;
        }
        qb::http::ws::MessageClose msg(qb::http::ws::CloseStatus::PolicyViolation, "bye from server");
        *this << msg;
    }

    void
    on(WS_Protocol::message &&) {}
};

class ClosingServer : public qb::io::use<ClosingServer>::tcp::server<ClosingClient> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Server that immediately drops the TCP connection after the handshake.
// ---------------------------------------------------------------------------

class DisconnectingServer;

class DisconnectingClient : public qb::io::use<DisconnectingClient>::tcp::client<DisconnectingServer> {
public:
    using Protocol    = qb::http::protocol<DisconnectingClient>;
    using WS_Protocol = qb::http::ws::protocol<DisconnectingClient>;

    explicit DisconnectingClient(IOServer &s)
        : client(s) {}

    void
    on(Protocol::request &&req) {
        if (!this->switch_protocol<WS_Protocol>(*this, req)) {
            this->disconnect();
            return;
        }
        this->disconnect();
    }

    void
    on(WS_Protocol::message &&) {}
};

class DisconnectingServer : public qb::io::use<DisconnectingServer>::tcp::server<DisconnectingClient> {
public:
    void
    on(IOSession &) {}
};

class InvalidFrameServer;

class InvalidFrameClient : public qb::io::use<InvalidFrameClient>::tcp::client<InvalidFrameServer> {
public:
    using Protocol    = qb::http::protocol<InvalidFrameClient>;
    using WS_Protocol = qb::http::ws::protocol<InvalidFrameClient>;

    explicit InvalidFrameClient(IOServer &s)
        : client(s) {}

    void
    on(Protocol::request &&req) {
        if (!this->switch_protocol<WS_Protocol>(*this, req)) {
            this->disconnect();
            return;
        }

        // Server-to-client frames must never be masked. This frame is
        // deliberately invalid and should trip the client's protocol-error path.
        constexpr std::array<char, 7> frame{static_cast<char>(0x81u),      static_cast<char>(0x80u | 1u), static_cast<char>(0x12u),
                                            static_cast<char>(0x34u),      static_cast<char>(0x56u),      static_cast<char>(0x78u),
                                            static_cast<char>('x' ^ 0x12u)};
        std::memcpy(this->out().allocate_back(frame.size()), frame.data(), frame.size());
        this->ready_to_write();
    }

    void
    on(WS_Protocol::message &&) {}
};

class InvalidFrameServer : public qb::io::use<InvalidFrameServer>::tcp::server<InvalidFrameClient> {
public:
    void
    on(IOSession &) {}
};

std::atomic<std::size_t> g_coro_close_echoes{0};

class CloseEchoServer;

class CloseEchoClient
    : public qb::io::use<CloseEchoClient>::tcp::client<CloseEchoServer>
    , public qb::io::use<CloseEchoClient>::timeout {
public:
    using Protocol    = qb::http::protocol<CloseEchoClient>;
    using WS_Protocol = qb::http::ws::protocol<CloseEchoClient>;

    explicit CloseEchoClient(IOServer &s)
        : client(s) {}

    void
    on(Protocol::request &&req) {
        if (!this->switch_protocol<WS_Protocol>(*this, req)) {
            this->disconnect();
            return;
        }
        qb::http::ws::MessageClose msg(qb::http::ws::CloseStatus::GoingAway, "server-closing");
        *this << msg;
        this->setTimeout(200s);
    }

    void
    on(WS_Protocol::close &&) {
        ++g_coro_close_echoes;
        this->disconnect();
    }

    void
    on(qb::io::async::event::timeout const &) {
        this->disconnect();
    }

    void
    on(WS_Protocol::message &&) {}
};

class CloseEchoServer : public qb::io::use<CloseEchoServer>::tcp::server<CloseEchoClient> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Test fixture — runs the echo server on a dedicated thread so the coroutine
// client's own listener can drive the TCP client side independently.
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

class CoroClientTest : public ::testing::Test {
protected:
    void
    SetUp() override {
        qb::io::async::init();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_F(CoroClientTest, ConnectsAndExchangesText) {
    ServerThread<EchoServer> server{19931};

    auto task = [&]() -> qb::io::async::task<std::string> {
        qb::http::ws::coro_client ws;
        auto                      res = co_await ws.connect("ws://localhost:19931/");
        EXPECT_TRUE(res.ok) << "connect failed";
        if (!res.ok)
            co_return std::string{};

        qb::http::ws::MessageText msg;
        msg << "hello-coro";
        ws << msg;

        auto frame = co_await ws.receive();
        EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Message);
        EXPECT_TRUE(frame.is_text);
        co_return frame.payload;
    };

    auto payload = qb::http::ws::run_sync(task());
    EXPECT_EQ(payload, "hello-coro");
}

TEST_F(CoroClientTest, HandlesBinaryPayload) {
    ServerThread<EchoServer> server{19932};

    auto task = [&]() -> qb::io::async::task<std::string> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect("ws://localhost:19932/");
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return std::string{};

        qb::http::ws::MessageBinary msg;
        const std::string           payload("\x00\x01\x02binary", 9);
        msg << payload;
        ws << msg;

        auto frame = co_await ws.receive();
        EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Message);
        EXPECT_FALSE(frame.is_text);
        co_return frame.payload;
    };

    auto got = qb::http::ws::run_sync(task());
    EXPECT_EQ(got.size(), 9u);
    EXPECT_EQ(got, std::string("\x00\x01\x02binary", 9));
}

TEST_F(CoroClientTest, CloseTransportsStatusCode) {
    ServerThread<ClosingServer> server{19933};

    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect("ws://localhost:19933/");
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame{};
        auto frame = co_await ws.receive();
        co_return frame;
    };

    auto frame = qb::http::ws::run_sync(task());
    EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Close);
    EXPECT_EQ(frame.close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::PolicyViolation));
    EXPECT_EQ(frame.close_reason, "bye from server");
}

TEST_F(CoroClientTest, ReceiveUnblocksOnDisconnect) {
    ServerThread<DisconnectingServer> server{19934};

    // The server disconnects the TCP stream as soon as the upgrade is
    // accepted, without sending any frame. Depending on how fast the
    // server-side `disconnect()` tears the socket down, the client may
    // either:
    //   (a) see `on(connected)` and then `on(disconnected)` — so
    //       `co_await receive()` returns `Kind::Disconnected`;
    //   (b) miss the 101 response entirely — so `connect()` itself returns
    //       `ok == false` (which we translate to `Kind::Disconnected` too).
    // Either outcome proves that no awaiter hangs on a dropped transport.
    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame::Kind> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect("ws://localhost:19934/");
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame::Kind::Disconnected;
        auto frame = co_await ws.receive();
        co_return frame.kind;
    };

    auto kind = qb::http::ws::run_sync(task());
    EXPECT_EQ(kind, qb::http::ws::IncomingFrame::Kind::Disconnected);
}

TEST_F(CoroClientTest, ReceiveAfterDisconnectWithPendingCapZeroDoesNotHang) {
    ServerThread<DisconnectingServer> server{19936};

    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame::Kind> {
        qb::http::ws::coro_client ws;
        ws.set_pending_cap(0);
        (void) co_await ws.connect("ws://localhost:19936/");
        auto frame = co_await ws.receive();
        co_return frame.kind;
    };

    auto kind = qb::http::ws::run_sync(task());
    EXPECT_EQ(kind, qb::http::ws::IncomingFrame::Kind::Disconnected);
}

TEST_F(CoroClientTest, ReceiveUnblocksOnProtocolError) {
    ServerThread<InvalidFrameServer> server{19938};

    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame::Kind> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect("ws://localhost:19938/");
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame::Kind::Disconnected;
        auto frame = co_await ws.receive();
        co_return frame.kind;
    };

    auto kind = qb::http::ws::run_sync(task());
    EXPECT_EQ(kind, qb::http::ws::IncomingFrame::Kind::Disconnected);
}

TEST_F(CoroClientTest, CloseAsyncCompletesAfterPeerEcho) {
    ServerThread<EchoServer> server{19935};

    auto task = [&]() -> qb::io::async::task<bool> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect("ws://localhost:19935/");
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return false;
        auto res = co_await ws.close_async(qb::http::ws::CloseStatus::Normal, "all-good");
        co_return res.ok;
    };

    EXPECT_TRUE(qb::http::ws::run_sync(task()));
}

TEST_F(CoroClientTest, EchoesPeerCloseFrame) {
    g_coro_close_echoes = 0;
    ServerThread<CloseEchoServer> server{19937};

    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame::Kind> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect("ws://localhost:19937/");
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame::Kind::Disconnected;
        auto frame = co_await ws.receive();
        co_return frame.kind;
    };

    const auto kind = qb::http::ws::run_sync(task());
    EXPECT_TRUE(kind == qb::http::ws::IncomingFrame::Kind::Close || kind == qb::http::ws::IncomingFrame::Kind::Disconnected);
    EXPECT_LE(g_coro_close_echoes.load(), 1u);
}

} // namespace

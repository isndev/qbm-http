/**
 * @file qbm/http/tests/system/ws/ws-coro-client.cpp
 * @brief End-to-end system tests for `qb::http::ws::coro_client`.
 *
 * These tests stand up a tiny echo / close / disconnect server built on the
 * classical CRTP API (`qb::io::use<...>::tcp::client<...>`) on its own event
 * loop (via the shared `WsServerThread`), then exercise the coroutine client
 * against it over plaintext `ws://` loopback:
 *
 *   - `ConnectsAndExchangesText`     — connect ➜ send text ➜ receive echo.
 *   - `HandlesBinaryPayload`         — binary round-trip, verifies `is_text`.
 *   - `EchoesLargePayloadOver64KiB`  — a >64 KiB data frame (8-byte length
 *                                      form) round-trips intact.
 *   - `ReassemblesFragmentedMessage` — a server-sent fragmented data message
 *                                      (text + continuation) is delivered as a
 *                                      single reassembled `Message` frame.
 *   - `PingFromServerSurfacesAsPing` — a server ping surfaces as `Kind::Ping`
 *                                      with payload preserved.
 *   - `ClientPingElicitsPong`        — a client `MessagePing` is answered by the
 *                                      server's pong and surfaces as `Kind::Pong`.
 *   - `CloseTransportsStatusCode`    — a server Close with a custom code / reason
 *                                      surfaces through `receive()`.
 *   - `ReceiveUnblocksOnDisconnect` / `...WithPendingCapZero` / `...OnProtocolError`
 *                                      — a parked `receive()` never hangs.
 *   - `CloseAsyncCompletesAfterPeerEcho` — the close handshake resolves.
 *   - `EchoesPeerCloseFrame`         — a peer-initiated Close is echoed exactly
 *                                      once (asserted `== 1`, not `<= 1`).
 *
 * Runs plaintext `ws://`; REQUIRES the SSL/crypto library only to LINK
 * (`ws/ws.h` uses `qb::io::crypto` for `Sec-WebSocket-Accept`). Harness comes
 * from `shared/ws_loopback.h`; ports are ephemeral.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <qbm/http/ws.h>

#include "../../shared/ws_loopback.h"

namespace {

using namespace std::chrono_literals;
using qb::http::test::WsServerThread;

// ---------------------------------------------------------------------------
// Echo server: reflects every data message, answers pings with a pong carrying
// the same payload. Used for text / binary / large-frame / ping round-trips.
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
// Server that, right after the handshake, sends a server ping (so the client's
// `on(ping)` path is exercised independently of the echo flow).
// ---------------------------------------------------------------------------

class PingingServer;

class PingingClient : public qb::io::use<PingingClient>::tcp::client<PingingServer> {
public:
    using Protocol    = qb::http::protocol<PingingClient>;
    using WS_Protocol = qb::http::ws::protocol<PingingClient>;

    explicit PingingClient(IOServer &s)
        : client(s) {}

    void
    on(Protocol::request &&req) {
        if (!this->switch_protocol<WS_Protocol>(*this, req)) {
            this->disconnect();
            return;
        }
        qb::http::ws::MessagePing ping;
        ping << std::string("ping-payload");
        *this << ping;
    }

    void
    on(WS_Protocol::message &&) {}
};

class PingingServer : public qb::io::use<PingingServer>::tcp::server<PingingClient> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Server that sends a FRAGMENTED text message right after the handshake:
// frame 1 = text/!FIN "Hello, ", frame 2 = continuation/FIN "World!". The
// client framer must reassemble these into a single Message("Hello, World!").
// Frames are server→client and therefore unmasked.
// ---------------------------------------------------------------------------

class FragmentServer;

class FragmentClient : public qb::io::use<FragmentClient>::tcp::client<FragmentServer> {
public:
    using Protocol    = qb::http::protocol<FragmentClient>;
    using WS_Protocol = qb::http::ws::protocol<FragmentClient>;

    explicit FragmentClient(IOServer &s)
        : client(s) {}

    void
    on(Protocol::request &&req) {
        if (!this->switch_protocol<WS_Protocol>(*this, req)) {
            this->disconnect();
            return;
        }
        send_unmasked_frame(0x01u, "Hello, "); // text, FIN clear
        send_unmasked_frame(0x80u, "World!");  // continuation (opcode 0), FIN set
    }

    void
    on(WS_Protocol::message &&) {}

private:
    // first_byte already encodes FIN|RSV|opcode. Payloads here are <126 bytes,
    // so the 7-bit length form (no mask bit, server→client) is used.
    void
    send_unmasked_frame(std::uint8_t first_byte, std::string_view payload) {
        // Written straight into the output pipe instead of through a reserve() +
        // push_back() staging vector, and that is deliberate — do not "simplify" it
        // back. GCC 14 at -O3 inlines reserve() and the two push_back()s into one
        // chain, mis-tracks the _M_realloc_append guard's pointer, and emits
        //     error: 'void operator delete(void*, std::size_t)' called on pointer
        //            '<unknown>' with nonzero offset [-Werror=free-nonheap-object]
        // naming the push_back at what used to be this function's fourth line. It is
        // a false positive (reserve() guarantees the two push_backs never reallocate),
        // but QB_TESTS_WERROR defaults to QB_CI so it is fatal on every runner and
        // invisible on the maintainer's clang. allocate_back() already returns writable
        // storage of exactly the requested size, so the staging vector bought nothing.
        const std::size_t n   = payload.size() + 2u;
        char *const       out = this->out().allocate_back(n);
        out[0]                = static_cast<char>(first_byte);
        out[1]                = static_cast<char>(payload.size()); // mask bit clear
        std::memcpy(out + 2, payload.data(), payload.size());
        this->ready_to_write();
    }
};

class FragmentServer : public qb::io::use<FragmentServer>::tcp::server<FragmentClient> {
public:
    void
    on(IOSession &) {}
};

// ---------------------------------------------------------------------------
// Server that closes the connection with a custom status right after the
// handshake.
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

// ---------------------------------------------------------------------------
// Server that sends a deliberately MASKED server→client frame — illegal per
// RFC 6455 §5.1 — to trip the client's protocol-error path.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Server that initiates a Close and counts how many times the peer echoes it.
// The counter is an atomic OWNED BY THE TEST (on the main thread's stack) and
// handed to the server via the WsServerThread config callback — no module
// globals, and the read happens on the main thread AFTER the server thread has
// joined (so the write is fully synchronized by the join).
// ---------------------------------------------------------------------------

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
        this->setTimeout(5s);
    }

    void on(WS_Protocol::close &&);

    void
    on(qb::io::async::event::timeout const &) {
        this->disconnect();
    }

    void
    on(WS_Protocol::message &&) {}
};

class CloseEchoServer : public qb::io::use<CloseEchoServer>::tcp::server<CloseEchoClient> {
public:
    std::atomic<std::size_t> *close_echoes{nullptr};

    void
    on(IOSession &) {}
};

inline void
CloseEchoClient::on(WS_Protocol::close &&) {
    if (this->server().close_echoes != nullptr) {
        this->server().close_echoes->fetch_add(1u, std::memory_order_relaxed);
    }
    this->disconnect();
}

// ---------------------------------------------------------------------------
// Test fixture.
// ---------------------------------------------------------------------------

class WsCoroClient : public ::testing::Test {
protected:
    void
    SetUp() override {
        qb::io::async::init();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_F(WsCoroClient, ConnectsAndExchangesText) {
    WsServerThread<EchoServer> server{0};
    const std::string          url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto task = [&]() -> qb::io::async::task<std::string> {
        qb::http::ws::coro_client ws;
        auto                      res = co_await ws.connect(std::string_view{url});
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

    EXPECT_EQ(qb::http::ws::run_sync(task()), "hello-coro");
}

TEST_F(WsCoroClient, HandlesBinaryPayload) {
    WsServerThread<EchoServer> server{0};
    const std::string          url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto task = [&]() -> qb::io::async::task<std::string> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect(std::string_view{url});
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

    const auto got = qb::http::ws::run_sync(task());
    EXPECT_EQ(got.size(), 9u);
    EXPECT_EQ(got, std::string("\x00\x01\x02binary", 9));
}

TEST_F(WsCoroClient, EchoesLargePayloadOver64KiB) {
    WsServerThread<EchoServer> server{0};
    const std::string          url = "ws://localhost:" + std::to_string(server.port) + "/";

    // 100 KiB exceeds 0xFFFF, forcing the 8-byte length form on the wire.
    const std::string big(100u * 1024u, '\x5A');

    auto task = [&]() -> qb::io::async::task<std::string> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return std::string{};

        qb::http::ws::MessageBinary msg;
        msg << big;
        ws << msg;

        auto frame = co_await ws.receive();
        EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Message);
        co_return frame.payload;
    };

    const auto got = qb::http::ws::run_sync(task());
    EXPECT_EQ(got.size(), big.size());
    EXPECT_EQ(got, big);
}

TEST_F(WsCoroClient, ReassemblesFragmentedMessage) {
    WsServerThread<FragmentServer> server{0};
    const std::string              url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame{};
        co_return co_await ws.receive();
    };

    const auto frame = qb::http::ws::run_sync(task());
    EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Message);
    EXPECT_TRUE(frame.is_text);
    EXPECT_EQ(frame.payload, "Hello, World!");
}

TEST_F(WsCoroClient, PingFromServerSurfacesAsPing) {
    WsServerThread<PingingServer> server{0};
    const std::string             url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame{};
        co_return co_await ws.receive();
    };

    const auto frame = qb::http::ws::run_sync(task());
    EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Ping);
    EXPECT_EQ(frame.payload, "ping-payload");
}

TEST_F(WsCoroClient, ClientPingElicitsPong) {
    WsServerThread<EchoServer> server{0};
    const std::string          url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame{};

        qb::http::ws::MessagePing ping;
        ping << std::string("are-you-there");
        ws << ping;

        co_return co_await ws.receive();
    };

    const auto frame = qb::http::ws::run_sync(task());
    EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Pong);
    EXPECT_EQ(frame.payload, "are-you-there");
}

TEST_F(WsCoroClient, CloseTransportsStatusCode) {
    WsServerThread<ClosingServer> server{0};
    const std::string             url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame{};
        co_return co_await ws.receive();
    };

    const auto frame = qb::http::ws::run_sync(task());
    EXPECT_EQ(frame.kind, qb::http::ws::IncomingFrame::Kind::Close);
    EXPECT_EQ(frame.close_code, static_cast<std::uint16_t>(qb::http::ws::CloseStatus::PolicyViolation));
    EXPECT_EQ(frame.close_reason, "bye from server");
}

TEST_F(WsCoroClient, ReceiveUnblocksOnDisconnect) {
    WsServerThread<DisconnectingServer> server{0};
    const std::string                   url = "ws://localhost:" + std::to_string(server.port) + "/";

    // The server disconnects the TCP stream as soon as the upgrade is accepted,
    // without sending any frame. Either `connect()` fails (101 missed) or
    // `receive()` returns `Kind::Disconnected` — both prove no awaiter hangs.
    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame::Kind> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect(std::string_view{url});
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame::Kind::Disconnected;
        auto frame = co_await ws.receive();
        co_return frame.kind;
    };

    EXPECT_EQ(qb::http::ws::run_sync(task()), qb::http::ws::IncomingFrame::Kind::Disconnected);
}

TEST_F(WsCoroClient, ReceiveAfterDisconnectWithPendingCapZeroDoesNotHang) {
    WsServerThread<DisconnectingServer> server{0};
    const std::string                   url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame::Kind> {
        qb::http::ws::coro_client ws;
        ws.set_pending_cap(0);
        (void) co_await ws.connect(std::string_view{url});
        auto frame = co_await ws.receive();
        co_return frame.kind;
    };

    EXPECT_EQ(qb::http::ws::run_sync(task()), qb::http::ws::IncomingFrame::Kind::Disconnected);
}

TEST_F(WsCoroClient, ReceiveUnblocksOnProtocolError) {
    WsServerThread<InvalidFrameServer> server{0};
    const std::string                  url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto task = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame::Kind> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame::Kind::Disconnected;
        auto frame = co_await ws.receive();
        co_return frame.kind;
    };

    EXPECT_EQ(qb::http::ws::run_sync(task()), qb::http::ws::IncomingFrame::Kind::Disconnected);
}

TEST_F(WsCoroClient, CloseAsyncCompletesAfterPeerEcho) {
    WsServerThread<EchoServer> server{0};
    const std::string          url = "ws://localhost:" + std::to_string(server.port) + "/";

    auto task = [&]() -> qb::io::async::task<bool> {
        qb::http::ws::coro_client ws;
        const auto                c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return false;
        auto res = co_await ws.close_async(qb::http::ws::CloseStatus::Normal, "all-good");
        co_return res.ok;
    };

    EXPECT_TRUE(qb::http::ws::run_sync(task()));
}

TEST_F(WsCoroClient, EchoesPeerCloseFrame) {
    // Per-test counter on the main thread's stack; the server thread writes
    // through the pointer, and we read it live (it is atomic). The bounded poll
    // below fails loud if the echo is never observed.
    std::atomic<std::size_t> echoes{0};

    WsServerThread<CloseEchoServer> server{0, [&echoes](CloseEchoServer &s) { s.close_echoes = &echoes; }};
    const std::string               url = "ws://localhost:" + std::to_string(server.port) + "/";

    // The coro_client echoes a server-initiated Close exactly once. We keep the
    // client object alive on the I/O thread until the server has observed that
    // echo (driving the loop ourselves), so the count is deterministic.
    qb::http::ws::coro_client ws;

    auto connect_and_receive = [&]() -> qb::io::async::task<qb::http::ws::IncomingFrame::Kind> {
        const auto c = co_await ws.connect(std::string_view{url});
        EXPECT_TRUE(c.ok);
        if (!c.ok)
            co_return qb::http::ws::IncomingFrame::Kind::Disconnected;
        co_return (co_await ws.receive()).kind;
    };

    const auto kind = qb::http::ws::run_sync(connect_and_receive());
    EXPECT_TRUE(kind == qb::http::ws::IncomingFrame::Kind::Close || kind == qb::http::ws::IncomingFrame::Kind::Disconnected);

    // Pump the client loop while polling the server-observed echo count with a
    // hard budget. The client's outbound Close echo was queued during receive();
    // these pumps flush it and let the server parse it.
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (echoes.load(std::memory_order_relaxed) == 0u && std::chrono::steady_clock::now() < deadline) {
        qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT);
        std::this_thread::sleep_for(2ms);
    }

    EXPECT_EQ(echoes.load(std::memory_order_relaxed), 1u) << "a peer-initiated Close must be echoed exactly once";
}

} // namespace

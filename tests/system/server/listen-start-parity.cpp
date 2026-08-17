/**
 * @file qbm/http/tests/system/server/listen-start-parity.cpp
 * @brief Pins the postcondition of `qbm::http` `listen()`: it BINDS, it does not ACCEPT.
 *
 * The pair here is `qb::io::async::tcp::acceptor::listen()` — the base method, which binds
 * **and** starts, and which offers `listen_no_start()` for the bind-only case — against
 * `qb::http::internal::server::listen()` and `qb::http2::internal::server::listen()`, which
 * *hide* it with a body that is semantically `listen_no_start()`. Same name, inverted
 * postcondition, on a derived class.
 *
 * That asymmetry costs a debugging session every time it is met, because the failure is
 * silent and looks like anything but a missing call: `listen()` returns `true`, the port is
 * held so nothing else can bind it, no accept watcher is ever registered, and every client
 * hangs to its own timeout with nothing in any log naming the cause. The examples corpus hit
 * exactly this.
 *
 * Nothing tested it because the suite only ever exercised the working sequence. Every server
 * test in this module calls `listen()`/`listen_v4()` and then `start()`, so "what happens if
 * you stop after the first call?" was never asked — the defining shape of a defect that
 * survives a green suite. This file asks it, in both polarities:
 *
 *   - after `listen()` alone, a connecting client is NOT accepted;
 *   - after the subsequent `start()`, it is;
 *   - and the base class's own `listen()` still auto-starts, so the two contracts are pinned
 *     against each other rather than each against itself.
 *
 * Plaintext HTTP/1.1 deliberately: the defect is in the acceptor layer, shared verbatim with
 * the HTTP/2 server (`qbm/http/src/qbm/http/2/http2.h`), so gating this on SSL would only
 * make it harder to run.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <chrono>
#include <string>

#include <gtest/gtest.h>
#include <qb/io/async.h>
#include <qb/io/protocol/text.h>
#include <qb/io/tcp/socket.h>
#include <qbm/http/http.h>

using namespace std::chrono_literals;

namespace listen_start_parity_test {

// A minimal plain-TCP server built DIRECTLY on qb::io::async::tcp::acceptor, used below to
// pin the base class's own listen() contract against the qbm override that hides it.
class EchoServer;

class EchoSession : public qb::io::use<EchoSession>::tcp::client<EchoServer> {
public:
    using Protocol = qb::protocol::text::command<EchoSession>;
    explicit EchoSession(IOServer &s)
        : client(s) {}
    void
    on(Protocol::message &&) {}
};

class EchoServer : public qb::io::use<EchoServer>::tcp::server<EchoSession> {
public:
    void
    on(IOSession &) {}
};

/// Pump the local event loop for a bounded window, returning as soon as `pred` holds.
template <typename Pred>
bool
pump_until(Pred pred, std::chrono::milliseconds budget) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred())
            return true;
        qb::io::async::run_for(5ms);
    }
    return pred();
}

class ListenStartParity : public ::testing::Test {
protected:
    void
    SetUp() override {
        qb::io::async::init();
    }
    void
    TearDown() override {
        qb::io::async::listener::current.clear();
    }
};

TEST_F(ListenStartParity, HttpListenBindsButDoesNotAcceptUntilStart) {
    qb::http::Server<> server;

    // `listen()` reports success and takes the port...
    ASSERT_TRUE(server.listen(qb::io::uri("tcp://127.0.0.1:0"))) << "listen() failed to bind";
    const auto port = server.transport().local_endpoint().port();
    ASSERT_NE(port, 0) << "port 0 did not yield a kernel-assigned port";

    // ...and the bind is real: a second server cannot take the same port.
    {
        qb::http::Server<> other;
        EXPECT_FALSE(other.listen(qb::io::uri("tcp://127.0.0.1:" + std::to_string(port)))) << "the port must genuinely be held after listen()";
    }

    // ...but nothing is accepting. The client's connect() completes against the kernel
    // backlog, so the client cannot tell; only the server's session count can.
    qb::io::tcp::socket client;
    ASSERT_EQ(client.connect_v4("127.0.0.1", port), qb::io::SocketStatus::Done);

    EXPECT_FALSE(pump_until([&] { return server.session_count() > 0; }, 250ms))
        << "listen() must NOT register the accept watcher — that is what start() is for";
    EXPECT_EQ(server.session_count(), 0u);

    // start() is the missing half.
    server.start();
    EXPECT_TRUE(pump_until([&] { return server.session_count() > 0; }, 3s))
        << "start() must register the accept watcher and pick up the pending connection";
    EXPECT_GE(server.session_count(), 1u);

    client.disconnect();
}

TEST_F(ListenStartParity, BaseAcceptorListenStillAutoStarts) {
    // The other half of the pair, so the divergence is asserted rather than assumed. The base
    // acceptor's listen() is documented "Auto-start"; a plain tcp server built directly on it
    // accepts with no second call. If this ever stops being true the two contracts have
    // converged and the @warning on the qbm servers is stale.
    EchoServer server;
    // NOTE: no start() anywhere in this test — that is the point.
    ASSERT_TRUE(server.listen(qb::io::uri("tcp://127.0.0.1:0"))) << "base acceptor listen() failed";
    const auto port = server.transport().local_endpoint().port();
    ASSERT_NE(port, 0);

    qb::io::tcp::socket client;
    ASSERT_EQ(client.connect_v4("127.0.0.1", port), qb::io::SocketStatus::Done);

    EXPECT_TRUE(pump_until([&] { return server.session_count() > 0; }, 3s))
        << "qb::io::async::tcp::acceptor::listen() is documented to auto-start";
    EXPECT_GE(server.session_count(), 1u);

    client.disconnect();
}

} // namespace listen_start_parity_test

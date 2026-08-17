/**
 * @file qbm/http/tests/system/server/listen-start-parity.cpp
 * @brief Pins `listen()` on the qbm HTTP servers against `listen()` on the qb base it derives
 *        from — the two halves asserted against each other, not each against itself.
 *
 * `qb::io::async::tcp::acceptor::listen()` binds **and** starts (its own comment says
 * "Auto-start") and ships `listen_no_start()` as the documented opt-out. Until 3.0
 * `qb::http::internal::server::listen()` and `qb::http2::internal::server::listen()` were
 * derived classes shadowing that name with a body that was semantically `listen_no_start()`:
 * same name, inverted postcondition, one level down the hierarchy.
 *
 * That asymmetry cost a debugging session every time it was met, because the failure was
 * silent and looked like anything but a missing call: `listen()` returned `true`, the port was
 * held so nothing else could bind it, no accept watcher was ever registered, and every client
 * hung to its own timeout with nothing in any log naming the cause. The examples corpus hit
 * exactly this, and `dual_stack_server::listen()` carried a `_http2->start()` that existed
 * only to paper over it.
 *
 * Nothing tested it because the suite only ever exercised the working sequence. Every server
 * test in this module called `listen()` and then `start()`, so "what happens if you stop after
 * the first call?" was never asked — the defining shape of a defect that survives a green
 * suite. This file asks it, in every polarity that matters:
 *
 *   - the qbm server's `listen()` accepts with no second call, exactly like the base's;
 *   - the base acceptor's `listen()` still auto-starts, so the pair is pinned, not assumed;
 *   - `listen_no_start()` still does NOT accept until `start()`, so the opt-out is real;
 *   - a redundant `start()` after `listen()` is harmless, which is what lets every existing
 *     caller keep its `listen(); start();` sequence across the change. That one is a claim
 *     about libev's idempotence (`qev_io_start` returns early on an active watcher), and a
 *     claim load-bearing for every user of this module is a claim that gets measured.
 *
 * Plaintext HTTP/1.1 deliberately: `qb::http2::internal::server` carries the identical
 * two-method shape (`listen()` forwarding to `listen_no_start()` plus `start()`), differing
 * only in the ALPN it pins, and gating this on SSL would only make it harder to run.
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

TEST_F(ListenStartParity, HttpListenBindsAndAccepts) {
    qb::http::Server<> server;

    // NOTE: no start() anywhere in this test — that is the point. Before 3.0 this same code
    // bound the port and then accepted nothing, forever.
    ASSERT_TRUE(server.listen(qb::io::uri("tcp://127.0.0.1:0"))) << "listen() failed to bind";
    const auto port = server.transport().local_endpoint().port();
    ASSERT_NE(port, 0) << "port 0 did not yield a kernel-assigned port";

    // The bind is real: a second server cannot take the same port.
    {
        qb::http::Server<> other;
        EXPECT_FALSE(other.listen(qb::io::uri("tcp://127.0.0.1:" + std::to_string(port)))) << "the port must genuinely be held after listen()";
    }

    qb::io::tcp::socket client;
    ASSERT_EQ(client.connect_v4("127.0.0.1", port), qb::io::SocketStatus::Done);

    EXPECT_TRUE(pump_until([&] { return server.session_count() > 0; }, 3s))
        << "listen() must register the accept watcher, exactly like the base acceptor's listen()";
    EXPECT_GE(server.session_count(), 1u);

    client.disconnect();
}

TEST_F(ListenStartParity, BaseAcceptorListenAlsoAutoStarts) {
    // The other half of the pair, so the agreement is asserted rather than assumed. If this
    // ever stops matching the case above, the two contracts have diverged again and the
    // @note on the qbm servers is stale.
    EchoServer server;
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

TEST_F(ListenStartParity, ListenNoStartDefersTheAcceptWatcher) {
    // The opt-out has to still work, or making listen() start would have removed a capability
    // rather than fixed a name. Same shape as the pre-3.0 listen(), now under the name that
    // says so — and the base offers the identical method, which is what "mirrors the base
    // pair" means.
    qb::http::Server<> server;

    ASSERT_TRUE(server.listen_no_start(qb::io::uri("tcp://127.0.0.1:0"))) << "listen_no_start() failed to bind";
    const auto port = server.transport().local_endpoint().port();
    ASSERT_NE(port, 0);

    // The client's connect() completes against the kernel backlog, so the client cannot tell;
    // only the server's session count can.
    qb::io::tcp::socket client;
    ASSERT_EQ(client.connect_v4("127.0.0.1", port), qb::io::SocketStatus::Done);

    EXPECT_FALSE(pump_until([&] { return server.session_count() > 0; }, 250ms))
        << "listen_no_start() must NOT register the accept watcher — that is the whole point of the name";
    EXPECT_EQ(server.session_count(), 0u);

    server.start();
    EXPECT_TRUE(pump_until([&] { return server.session_count() > 0; }, 3s))
        << "start() must arm the watcher and pick up the pending connection";
    EXPECT_GE(server.session_count(), 1u);

    client.disconnect();
}

TEST_F(ListenStartParity, RedundantStartAfterListenIsHarmless) {
    // Every caller written before 3.0 says `listen(); start();`, and that sequence has to keep
    // working or the change is a silent breakage of every server in every downstream tree.
    // The reason it is safe is libev's, not ours: qev_io_start() returns early when the
    // watcher is already active. Measured here rather than believed, because the failure mode
    // — a watcher stopped and not restarted — would look exactly like the defect this whole
    // file exists for.
    qb::http::Server<> server;

    ASSERT_TRUE(server.listen(qb::io::uri("tcp://127.0.0.1:0")));
    const auto port = server.transport().local_endpoint().port();
    ASSERT_NE(port, 0);

    server.start(); // the redundant call
    server.start(); // and again, for good measure

    qb::io::tcp::socket client;
    ASSERT_EQ(client.connect_v4("127.0.0.1", port), qb::io::SocketStatus::Done);

    EXPECT_TRUE(pump_until([&] { return server.session_count() > 0; }, 3s)) << "a redundant start() must not disarm the accept watcher";
    EXPECT_GE(server.session_count(), 1u);

    client.disconnect();
}

} // namespace listen_start_parity_test

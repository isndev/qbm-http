/**
 * @file qbm/http/tests/system/server/acceptor-disconnect.cpp
 * @brief When a qbm HTTP server's listening socket goes, its own `on(disconnected)` runs, the
 *        derived server hears it, and the listening watcher is stopped (Huly QB-252).
 *
 * The acceptor routes `event::disconnected` to its derived class only when
 * `qb::has_own_on<Derived, acceptor, event::disconnected>` sees a handler there; otherwise it
 * throws `std::runtime_error("Acceptor has been disconnected")`. Both qbm servers declare that
 * handler -- privately, the class's default access -- and befriend the acceptor so it can call
 * it. But the detection did not run in the acceptor: it ran in a qb::detail function no friend
 * declaration reaches, so the handler was reported absent and every server disconnect threw.
 *
 * The listener contains an exception escaping a handler (one WARN line), so nothing crashed --
 * which is what hid it. The throw left from inside `dispose()`, after `_is_disposed` was set and
 * before `_async_event.stop()`: the listening watcher stayed armed on a disposed acceptor. A
 * client then queued in the backlog keeps the socket readable, every pass dispatches the watcher,
 * `dispose()` returns at once, and the loop spins for as long as the connection waits -- while
 * the derived server never learns its listener is gone. Now the servers befriend the detector,
 * which `has_own_on` reads.
 *
 * `disconnect()` on the server is the acceptor's own (the `input<>` base): it feeds the event the
 * listening watcher dispatches on the next pass, the path a failing listening socket takes. Each
 * case pumps that pass, asserts what the server did with it, then queues a client and counts what
 * the loop dispatches afterwards: nothing, once the watcher is stopped.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <qb/io/async.h>
#include <qb/io/tcp/socket.h>
#include <qbm/http/http.h>
#ifdef QB_HAS_SSL
#include <qbm/http/2/http2.h>
#include "../../shared/ssl_test_resource.h"
#endif

namespace acceptor_disconnect_test {

class H1Server;

class H1Session : public qb::http::use<H1Session>::session<H1Server> {
public:
    explicit H1Session(H1Server &server)
        : session(server) {}
};

// A derived server that handles the forwarded event, as an application would.
class H1Server : public qb::http::use<H1Server>::server<H1Session> {
public:
    std::vector<int> reasons;
    void
    on(qb::http::event::disconnected &&event) {
        reasons.push_back(event.reason);
    }
};

#ifdef QB_HAS_SSL
class H2Server;

class H2Session : public qb::http2::use<H2Session>::session<H2Server> {
public:
    explicit H2Session(H2Server &server)
        : session(server) {}
};

class H2Server : public qb::http2::use<H2Server>::server<H2Session> {
public:
    std::vector<int> reasons;
    void
    on(qb::http::event::disconnected &&event) {
        reasons.push_back(event.reason);
    }
};
#endif

/// Run `passes` non-blocking loop passes; return how many events they dispatched.
std::size_t
dispatched_over(int passes) {
    std::size_t events = 0;
    for (int i = 0; i < passes; ++i)
        events += static_cast<std::size_t>(qb::io::async::run(EVRUN_NOWAIT));
    return events;
}

/// Queue a client in the listening socket's backlog -- the kernel completes the handshake; no
/// accept is needed -- and count what the loop dispatches while it waits there.
std::size_t
dispatched_with_a_pending_client(std::uint16_t port) {
    qb::io::tcp::socket client;
    EXPECT_EQ(client.connect_v4("127.0.0.1", port), qb::io::SocketStatus::Done);
    const auto events = dispatched_over(20);
    client.disconnect();
    return events;
}

class AcceptorDisconnect : public ::testing::Test {
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

} // namespace acceptor_disconnect_test

using namespace acceptor_disconnect_test;

TEST_F(AcceptorDisconnect, Http1ServerForwardsToTheDerivedServerAndStopsListening) {
    H1Server server;
    ASSERT_TRUE(server.listen(qb::io::uri("tcp://127.0.0.1:0")));
    const auto port = server.transport().local_endpoint().port();

    server.disconnect();
    dispatched_over(10);
    EXPECT_EQ(server.reasons, std::vector<int>{1}) << "the derived server must hear the user-initiated disconnect, once";
    EXPECT_EQ(dispatched_with_a_pending_client(port), 0u) << "the listening watcher must be stopped: a waiting client wakes nothing";
}

TEST_F(AcceptorDisconnect, Http1ServerWithNoDerivedHandlerStopsListening) {
    qb::http::Server<> server; // the shipped server: no on(qb::http::event::disconnected) of its own
    ASSERT_TRUE(server.listen(qb::io::uri("tcp://127.0.0.1:0")));
    const auto port = server.transport().local_endpoint().port();

    server.disconnect();
    dispatched_over(10);
    EXPECT_EQ(dispatched_with_a_pending_client(port), 0u) << "the listening watcher must be stopped: a waiting client wakes nothing";
}

#ifdef QB_HAS_SSL
TEST_F(AcceptorDisconnect, Http2ServerForwardsToTheDerivedServerAndStopsListening) {
    ASSERT_TRUE(qb::http::test::certs_available())
        << "Missing TLS test certificates (looked for " << qb::http::test::ssl_cert_path() << " and " << qb::http::test::ssl_key_path() << ")";
    H2Server server;
    server.transport().init(qb::io::ssl::Context::server(qb::http::test::ssl_cert_path().string(), qb::http::test::ssl_key_path().string())
                                .alpn({"h2", "http/1.1"}));
    ASSERT_EQ(server.transport().listen_v4(0, "127.0.0.1"), 0);
    server.start();
    const auto port = server.transport().local_endpoint().port();

    server.disconnect();
    dispatched_over(10);
    EXPECT_EQ(server.reasons, std::vector<int>{1}) << "the HTTP/2 server forwards to the derived server, as the HTTP/1.1 one does";
    EXPECT_EQ(dispatched_with_a_pending_client(port), 0u) << "the listening watcher must be stopped: a waiting client wakes nothing";
}
#endif

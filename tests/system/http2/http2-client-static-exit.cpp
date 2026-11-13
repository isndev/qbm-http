/**
 * @file qbm/http/tests/system/http2/http2-client-static-exit.cpp
 * @brief An HTTP/2 client with STATIC STORAGE ends cleanly when the process exits (Huly QB-1246): never connected, a
 *        connect in flight, its TLS handshake in flight, connected and idle, a request in flight (its callback
 *        pending, or a coroutine parked on it), disconnected by the program, a reconnection run under way.
 *
 * `exit()` destroys the main thread's thread-locals before the objects with static storage, and qb-io's
 * `listener::current` is one: a client a program keeps in static storage is destroyed AFTER its thread's event loop,
 * where nothing can be registered, armed or resumed any more -- a request for the loop there stops the process on a
 * line that names it, and a watcher started there writes into the freed loop. Each case asks, of the client in one
 * state: the process ends with the code its judge chose and its stderr is the judge's line and NOTHING else (no named
 * stop, no warning, no sanitizer report: under AddressSanitizer the destroyed listener is poisoned); the client's
 * destructor ran after the loop -- asserted, not assumed -- and returned; the peer of a connection reads a clean EOF
 * of its stream, never a reset; what was in flight ended as the module says it does (the judge's line carries how
 * many times its callback ran, whether after the loop, and with which status; whether the coroutine parked on it was
 * resumed, and when its frame was destroyed); LeakSanitizer, asked by the judge, has nothing to report.
 *
 * Every case is a CHILD process (a death test, re-executed) whose judge is an `atexit` handler registered before the
 * client is built. The server is this module's own, on a thread of its own, behind a relay the case steps by hand
 * (qb's `static_exit_support.h`): every octet of the TLS connection goes through it, and a case that stops stepping
 * it has a peer that is open and silent. The server's thread is joined before the process ends; the judge reads the
 * relay's accepted end. The other clients of the module are in `system/client/client-static-exit.cpp`.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <utility>

#include <gtest/gtest.h>

#include <qb/io/async.h>
#include <qb/io/async/coroutine.h>
#include <qbm/http/2/client.h>
#include <qbm/http/2/http2.h>
#include <qbm/http/http.h>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"
#include "static_exit_support.h"

using namespace std::chrono_literals;

namespace http2_client_static_exit_test {

namespace async = qb::io::async;
using namespace qb::io::test::static_exit;

qb::http::Request
get(std::string const &target) {
    return qb::http::Request{qb::http::method::GET, qb::io::uri(target)};
}

void
in_flight(qb::http::Response response) {
    called_with(static_cast<int>(response.status().code()));
}

class H2Server;

class H2Session : public qb::http2::use<H2Session>::session<H2Server> {
public:
    explicit H2Session(H2Server &server)
        : session(server) {}
};

/// `/served` answers at once. A request that must stay in flight is one the relay never passes on.
class H2Server : public qb::http2::use<H2Server>::server<H2Session> {
public:
    H2Server() {
        router().get("/served", [](auto ctx) {
            ctx->response().status() = qb::http::status::NO_CONTENT;
            ctx->complete();
        });
        router().compile();
    }
};

using h2_server_thread = qb::http::test::ServerThread<H2Server>;

h2_server_thread *g_h2_server = nullptr;

std::uint16_t
start_h2_server() {
    if (!qb::http::test::certs_available())
        setup_failed("the TLS test certificate is missing");
    const std::string cert = qb::http::test::ssl_cert_path().string();
    const std::string key  = qb::http::test::ssl_key_path().string();
    g_h2_server            = new h2_server_thread([cert, key](H2Server &server) -> bool {
        server.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2"}));
        if (server.transport().listen_v4(0, "127.0.0.1") != 0)
            return false;
        server.start();
        return true;
    });
    if (!g_h2_server->ready() || g_h2_server->port() == 0)
        setup_failed("the HTTP/2 server did not start");
    return g_h2_server->port();
}

/// The server's thread ends before the process does: from here on the relay is the client's peer, open and silent.
void
stop_h2_server() {
    delete std::exchange(g_h2_server, nullptr);
}

enum class h2 {
    never_connected,
    connecting,           ///< connect() asked, no pass of the loop since
    handshake,            ///< the transport is up, the TLS handshake unanswered
    idle,                 ///< connected, nothing asked
    request,              ///< a request written, its callback pending
    retried,              ///< a request written, whose callback pushes it again when it fails: the retry pattern
    coroutine,            ///< a coroutine parked on a request
    own_callback,         ///< `exit()` called by the callback of a response
    disconnected,         ///< disconnect() -- its GOAWAY queued -- and `exit()` at once
    disconnected_run,     ///< disconnect(), the loop run until the peer read the end
    reconnecting,         ///< the peer gone, a request waiting, the next attempt of the run scheduled
    reconnecting_retried, ///< the same, the request pushed again from the destructor's failure too: the retry pattern after the loop
};

qb::http2::Client *g_h2_client = nullptr;
std::string        g_h2_target;
int                g_h2_pushes                = 0;
bool               g_h2_pushed_after_the_loop = false;

void
h2_connect(qb::http2::Client &client, relay &peer) {
    bool up = false;
    if (!client.connect([&up](bool ok, std::string const &) { up = ok; }))
        setup_failed("connect() started nothing");
    if (!pump_until(&peer, [&] { return up && client.is_connected(); }))
        setup_failed("the HTTP/2 client never connected");
}

async::task<void>
h2_parked(qb::http2::Client &client, std::string target) {
    frame_local local;
    g.parked      = true;
    auto response = co_await client.push_request(get(target));
    ++g.resumed;
    g.outcome = static_cast<int>(response.status().code());
}

/// The retry pattern: a request that failed is pushed again, once.
void
h2_retry_once(qb::http::Response response) {
    in_flight(std::move(response));
    if (g.calls == 1)
        g_h2_client->push_request(get(g_h2_target), in_flight);
}

/// The retry pattern of a reconnection run: a request that failed is pushed again -- while its thread's loop lives.
void
h2_retry(qb::http::Response response) {
    in_flight(std::move(response));
    if (!loop_gone() && g_h2_pushes < 8) {
        ++g_h2_pushes;
        g_h2_client->push_request(get(g_h2_target), h2_retry);
    }
}

/// The same, and once more after the loop: the destructor's failure of the request pushes it again, with neither a connection
/// nor a connect in flight -- only the destructor's own second pass can fail it, and nothing may connect for it.
void
h2_retry_through_the_exit(qb::http::Response response) {
    in_flight(std::move(response));
    if (!loop_gone() && g_h2_pushes < 8) {
        ++g_h2_pushes;
        g_h2_client->push_request(get(g_h2_target), h2_retry_through_the_exit);
    } else if (loop_gone() && !std::exchange(g_h2_pushed_after_the_loop, true)) {
        g_h2_client->push_request(get(g_h2_target), h2_retry_through_the_exit);
    }
}

[[noreturn]] void
run_h2(h2 const state, site const where) {
    std::atexit(judge);
    relay &peer = new_peer();
    peer.through("127.0.0.1", start_h2_server());
    const std::string                                  url = "https://localhost:" + std::to_string(peer.port());
    static at_exit<std::shared_ptr<qb::http2::Client>> object{qb::http2::make_client(url)};
    qb::http2::Client                                 &client = *object.client;
    client.set_verify_peer(false); // the test's certificate is self-signed
    switch (state) {
        case h2::never_connected:
            break;
        case h2::connecting:
            if (!client.connect([](bool ok, std::string const &) { called_with(ok ? 1 : 2); }))
                setup_failed("connect() started nothing");
            break;
        case h2::handshake:
            peer.go_silent(); // the port completes the TCP handshake; nobody answers the ClientHello
            if (!client.connect([](bool ok, std::string const &) { called_with(ok ? 1 : 2); }))
                setup_failed("connect() started nothing");
            pump_for(nullptr, 50ms);
            if (!client.is_connecting())
                setup_failed("the HTTP/2 client is not connecting");
            break;
        case h2::idle:
            h2_connect(client, peer);
            g.want_peer = 0;
            break;
        case h2::request:
            h2_connect(client, peer);
            peer.go_silent();
            if (!client.push_request(get(url + "/served"), in_flight))
                setup_failed("the request was refused");
            pump_for(nullptr, 20ms);
            g.want_peer = 0;
            break;
        case h2::retried:
            h2_connect(client, peer);
            peer.go_silent();
            g_h2_client = &client;
            g_h2_target = url + "/served";
            if (!client.push_request(get(g_h2_target), h2_retry_once))
                setup_failed("the request was refused");
            pump_for(nullptr, 20ms);
            g.want_peer = 0;
            break;
        case h2::coroutine:
            h2_connect(client, peer);
            peer.go_silent();
            async::coro_scheduler().spawn(h2_parked(client, url + "/served"));
            if (!pump_until(nullptr, [] { return g.parked; }))
                setup_failed("the coroutine never reached its request");
            pump_for(nullptr, 20ms);
            g.want_peer = 0;
            break;
        case h2::own_callback:
            h2_connect(client, peer);
            // As for the HTTP/1.1 client: the dispatch that calls the callback holds the client, exit() never
            // unwinds it, and the connection is the process's to close.
            g.want_alive = true;
            g.want_peer  = 2;
            if (!client.push_request(get(url + "/served"), [](qb::http::Response response) {
                    in_flight(std::move(response));
                    stop_h2_server();
                    std::exit(3); // inside the client's own dispatch
                }))
                setup_failed("the request was refused");
            pump_for(&peer, 30s);
            setup_failed("the response never came");
        case h2::disconnected:
            h2_connect(client, peer);
            client.disconnect();
            g.want_peer = 0;
            break;
        case h2::disconnected_run:
            h2_connect(client, peer);
            client.disconnect();
            if (!pump_until(&peer, [&] { return peer.client_ended(); }))
                setup_failed("the peer never read the end of a connection the client disconnected");
            g.want_peer = 0;
            break;
        case h2::reconnecting:
        case h2::reconnecting_retried: {
            qb::http2::RetryPolicy policy;
            policy.with_initial_delay(1h).with_jitter(false).with_max_attempts(5);
            client.enable_auto_reconnect(std::move(policy));
        }
            h2_connect(client, peer);
            g_h2_client = &client;
            g_h2_target = url + "/served";
            peer.go_silent();
            ++g_h2_pushes;
            if (!client.push_request(get(g_h2_target), state == h2::reconnecting ? h2_retry : h2_retry_through_the_exit))
                setup_failed("the request was refused");
            pump_for(nullptr, 20ms);
            peer.go_away(); // the connection drops and the port refuses the next: attempt 1 fails, attempt 2 waits an hour
            if (!pump_until(nullptr, [&] { return client.is_reconnecting() && client.reconnect_attempts() >= 2 && !client.is_connecting(); }))
                setup_failed("the HTTP/2 client never scheduled the second attempt of its reconnection run");
            break;
    }
    stop_h2_server();
    leave(where);
}

class Http2ClientStaticExitDeathTest : public in_a_child_from {};

TEST_P(Http2ClientStaticExitDeathTest, NeverConnected) {
    EXPECT_EXIT(run_h2(h2::never_connected, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 0, 0, 0, 0, 0, 0)));
}

// The connect() that waits for the handshake hears `false` from the client's destructor, after the loop.
TEST_P(Http2ClientStaticExitDeathTest, InItsTlsHandshake) {
    EXPECT_EXIT(run_h2(h2::handshake, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
}

TEST_P(Http2ClientStaticExitDeathTest, ConnectedAndIdle) {
    EXPECT_EXIT(run_h2(h2::idle, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0)));
}

TEST_P(Http2ClientStaticExitDeathTest, ARequestInFlight) {
    EXPECT_EXIT(run_h2(h2::request, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 1, 1, 503, 0, 0, 0)));
}

// The retry pattern, from the client's destructor after the loop: the request pushed again queues and is failed in
// its turn -- no deadline is armed for it and no connection asked.
TEST_P(Http2ClientStaticExitDeathTest, ARequestInFlightWhoseCallbackPushesAgain) {
    EXPECT_EXIT(run_h2(h2::retried, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 2, 2, 503, 0, 0, 0)));
}

TEST_P(Http2ClientStaticExitDeathTest, ACoroutineParkedOnARequest) {
    EXPECT_EXIT(run_h2(h2::coroutine, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 1, 0)));
}

TEST_P(Http2ClientStaticExitDeathTest, DisconnectedThenExitAtOnce) {
    EXPECT_EXIT(run_h2(h2::disconnected, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0)));
}

TEST_P(Http2ClientStaticExitDeathTest, DisconnectedAndTheLoopRun) {
    EXPECT_EXIT(run_h2(h2::disconnected_run, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0)));
}

TEST_P(Http2ClientStaticExitDeathTest, InAReconnectionRun) {
    EXPECT_EXIT(run_h2(h2::reconnecting, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 3, 1, 503, 0, 0, 0)));
}

// The retry pattern through the exit, in a reconnection run: the destructor fails the request, its callback pushes it
// again with no connection and no connect in flight, and the destructor's second pass fails it too -- nothing armed,
// no connection asked for it (Huly QB-1246).
TEST_P(Http2ClientStaticExitDeathTest, InAReconnectionRunWhoseRequestIsPushedAgainAfterTheLoop) {
    EXPECT_EXIT(run_h2(h2::reconnecting_retried, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 4, 2, 503, 0, 0, 0)));
}

INSTANTIATE_TEST_SUITE_P(Exit, Http2ClientStaticExitDeathTest, ::testing::Values(site::main, site::callback), site_name);

class Http2ClientStaticExitOnceDeathTest : public in_a_child {};

// A connect() asked and no pass of the loop since: it hears `false` from the client's destructor, after the loop.
TEST_F(Http2ClientStaticExitOnceDeathTest, AConnectInFlight) {
    EXPECT_EXIT(run_h2(h2::connecting, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
}

// `exit()` from the callback of a response: the client's own dispatch is on the stack, and holds the client. Its
// static pointer is destroyed after the loop; the client is not, and its connection stays open to the end.
TEST_F(Http2ClientStaticExitOnceDeathTest, ExitFromTheCallbackOfAResponse) {
    EXPECT_EXIT(run_h2(h2::own_callback, site::main), ::testing::ExitedWithCode(0), stderr_is(left_alive(2, 1, 0, 204, 0, 0, 0)));
}

TEST_F(Http2ClientStaticExitOnceDeathTest, ACoroutineParkedOnARequestAndExitFromACoroutine) {
    EXPECT_EXIT(run_h2(h2::coroutine, site::coroutine), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0), abandoned(2)));
}

} // namespace http2_client_static_exit_test

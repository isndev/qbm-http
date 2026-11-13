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
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <qb/io/async.h>
#include <qb/io/async/coroutine.h>
#include <qbm/http/2/client.h>
#include <qbm/http/2/http2.h>
#include <qbm/http/http.h>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"
#include "../../shared/tls_closing_peer.h"
#include "static_exit_support.h"

#include "../../shared/static_exit_calls.h"

using namespace std::chrono_literals;

namespace http2_client_static_exit_test {

namespace async = qb::io::async;
using namespace qb::io::test::static_exit;
using qb::http::test::static_exit::answered_inside;
using qb::http::test::static_exit::heard;

qb::http::Request
get(std::string const &target) {
    return qb::http::Request{qb::http::method::GET, qb::io::uri(target)};
}

void
in_flight(qb::http::Response response) {
    heard(static_cast<int>(response.status().code()));
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

/// The peer of the `tls_ended` case: it ends each connection once its TLS handshake is complete.
qb::http::test::TlsClosingPeer *g_tls_closing = nullptr;

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
    delete std::exchange(g_tls_closing, nullptr);
}

enum class h2 {
    never_connected,
    connecting,            ///< connect() asked, no pass of the loop since
    connecting_redials,    ///< the same, and the callback that hears `false` calls connect() again
    connecting_throws,     ///< the same, and the callback that hears `false` throws
    handshake,             ///< connect() asked, the ClientHello read by a peer that answers nothing
    handshake_redials,     ///< the same, and the callback that hears `false` calls connect() again
    tls_ended,             ///< connect() asked of a peer that ends each connection once its TLS handshake is complete, and
                           ///< the callback that hears `false` calls connect() once more
    batch_throwing,        ///< two batches of two written, the callback of each throws, and the first pushes a third
    idle,                  ///< connected, nothing asked
    request,               ///< a request written, its callback pending
    retried,               ///< a request written, whose callback pushes it again when it fails: the retry pattern
    retried_on,            ///< the same, pushed again each time it fails after the loop: every generation is answered
    batches,               ///< a request written, whose failure pushes a batch, whose callback pushes the next, three in all
    throwing,              ///< two requests written, the callback of each throws, and the first pushes a third
    disconnecting,         ///< a request written, whose callback disconnects the client and pushes the request again
    coroutine,             ///< a coroutine parked on a request
    own_callback,          ///< `exit()` called by the callback of a response
    disconnected,          ///< disconnect() -- its GOAWAY queued -- and `exit()` at once
    disconnected_run,      ///< disconnect(), the loop run until the peer read the end
    reconnecting,          ///< the peer gone, a request waiting, the next attempt of the run scheduled
    reconnecting_retried,  ///< the same, the request pushed again from the destructor's failure too: the retry pattern after the loop
    reconnecting_connects, ///< the same, and the destructor's failure of the request calls connect()
};

qb::http2::Client *g_h2_client = nullptr;
std::string        g_h2_target;
int                g_h2_pushes                = 0;
int                g_h2_pushes_after_the_loop = 0;
bool               g_h2_pushed_after_the_loop = false;
bool               g_h2_redialled             = false;

/// How many times a request is pushed again after the loop by the cases that keep pushing: more than the passes a
/// destructor could make over its queues, so a generation left queued and never answered is counted.
constexpr int k_late_pushes = 4;

void
h2_connect(qb::http2::Client &client, relay &peer) {
    bool up = false;
    if (!client.connect([&up](bool ok, std::string const &) { up = ok; }))
        setup_failed("connect() started nothing");
    if (!pump_until(&peer, [&] { return up && client.is_connected(); }))
        setup_failed("the HTTP/2 client never connected");
}

/// The client has read everything the relay wrote to it. A request the server answers says so: the answer is the last
/// thing the server writes, and the client read every octet before it to read it. The relay can then fall silent with
/// nothing of its own left unread in the client's socket -- what a wait of 20 ms was trusted to give.
void
h2_read_all_the_relay_wrote(qb::http2::Client &client, relay &peer, std::string const &url) {
    bool answered = false;
    if (!client.push_request(get(url + "/served"), [&answered](qb::http::Response response) { answered = response.status().code() == 204; }))
        setup_failed("the request that settles the connection was refused");
    if (!pump_until(&peer, [&answered] { return answered; }))
        setup_failed("the request that settles the connection was never answered");
}

/// The peer falls silent once the client has read all it wrote: from here on a request stays in flight.
void
h2_silence(qb::http2::Client &client, relay &peer, std::string const &url) {
    h2_read_all_the_relay_wrote(client, peer, url);
    peer.go_silent();
}

/// `streams` requests are in flight: each has its stream, and the client has written all it had to write.
void
h2_in_flight(qb::http2::Client &client, std::size_t const streams) {
    if (!pump_until(nullptr, [&] { return client.get_active_request_count() == streams && client.out().size() == 0; }))
        setup_failed("the request never left the client");
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

/// The same, and again after the loop, `k_late_pushes` times: each failure the destructor delivers pushes the request again,
/// with neither a connection nor a connect in flight. Every generation is answered inside its push -- one callback a push --,
/// nothing is queued and nothing may connect for it. The first of them asks for a deadline too: none is armed.
void
h2_retry_through_the_exit(qb::http::Response response) {
    in_flight(std::move(response));
    if (!loop_gone() && g_h2_pushes < 8) {
        ++g_h2_pushes;
        g_h2_client->push_request(get(g_h2_target), h2_retry_through_the_exit);
    } else if (loop_gone() && g_h2_pushes_after_the_loop < k_late_pushes) {
        if (g_h2_pushes_after_the_loop++ == 0)
            g_h2_client->set_request_timeout(5s);
        answered_inside([] { g_h2_client->push_request(get(g_h2_target), h2_retry_through_the_exit); });
    }
}

/// The same, and after the loop the destructor's failure of the request calls connect() -- with neither a connection nor a
/// connect in flight, it would start one: it is refused by its return value alone, `false`, and its callback never runs
/// (it would record 4; a connection started records 3).
void
h2_connect_through_the_exit(qb::http::Response response) {
    in_flight(std::move(response));
    if (!loop_gone() && g_h2_pushes < 8) {
        ++g_h2_pushes;
        g_h2_client->push_request(get(g_h2_target), h2_connect_through_the_exit);
    } else if (loop_gone() && !std::exchange(g_h2_pushed_after_the_loop, true)) {
        if (g_h2_client->connect([](bool, std::string const &) { heard(4); }))
            heard(3); // a connection was started from the destructor
    }
}

/// The callback of a connect() still waiting when the client is destroyed: it hears `false` (2) and calls connect() again,
/// as a program that dials again does. That connect() is refused by its return value alone: its callback never runs (it
/// would record 4, and a callback that dialled again from there would never end), and nothing is started (3).
void
h2_redial(bool const ok, std::string const &) {
    heard(ok ? 1 : 2);
    if (!ok && g_h2_client->connect([](bool, std::string const &) { heard(4); }))
        heard(3);
}

/// The callback of a connect() whose connection the peer ended: it hears `false` (2) and calls connect() once more. That
/// attempt is its own -- the peer ends it too -- and its callback hears `false` as well, while the loop lives.
void
h2_redial_once(bool const ok, std::string const &) {
    heard(ok ? 1 : 2);
    if (!ok && !std::exchange(g_h2_redialled, true) && !g_h2_client->connect([](bool again, std::string const &) { heard(again ? 1 : 2); }))
        heard(3); // refused, with neither the destructor nor anything else in its way
}

/// The callback of a connect() that throws once it has recorded what it heard.
void
h2_connect_throws(bool const ok, std::string const &) {
    heard(ok ? 1 : 2);
    throw std::runtime_error("thrown by the callback of a connect() the destructor fails");
}

/// A batch of two, each member answered 503: the status the judge reads, 0 for any other answer.
int
h2_batch_outcome(std::vector<qb::http::Response> const &responses) {
    if (responses.size() != 2)
        return 0;
    for (auto const &response : responses)
        if (response.status().code() != 503)
            return 0;
    return 503;
}

/// A batch of two requests for the case's target.
std::vector<qb::http::Request>
h2_two_requests() {
    std::vector<qb::http::Request> batch;
    batch.push_back(get(g_h2_target));
    batch.push_back(get(g_h2_target));
    return batch;
}

/// The batch form of the retry pattern: each batch that fails pushes the next, three in all, every one after the loop
/// and answered inside its push.
void
h2_next_batch(std::vector<qb::http::Response> responses) {
    heard(h2_batch_outcome(responses));
    if (g_h2_pushes_after_the_loop < 3) {
        ++g_h2_pushes_after_the_loop;
        answered_inside([] {
            if (!g_h2_client->push_requests(h2_two_requests(), h2_next_batch))
                heard(-3); // a batch pushed while the client is destroyed is answered, not refused by the bound
        });
    }
}

/// The callback of a batch that throws once it has recorded its call, and first -- once -- pushes a batch whose callback
/// throws too. What that one throws stays inside the push: the line after it runs, and is counted as a call.
void
h2_batch_throws(std::vector<qb::http::Response> responses) {
    heard(h2_batch_outcome(responses));
    if (g_h2_pushes_after_the_loop++ == 0) {
        g_h2_client->push_requests(h2_two_requests(), h2_batch_throws);
        heard(503);
    }
    throw std::runtime_error("thrown by the callback of a batch the destructor fails");
}

/// A callback that throws once it has recorded its call: the destructor that runs it logs what it threw, and goes on.
void
h2_throws(qb::http::Response response) {
    in_flight(std::move(response));
    throw std::runtime_error("thrown by the callback of a request the destructor fails");
}

/// A callback that throws, and first -- once -- pushes a request whose callback throws too. What that one throws stays
/// inside the push: the line after it runs, and is counted as a call.
void
h2_throws_after_a_push(qb::http::Response response) {
    in_flight(std::move(response));
    if (g_h2_pushes_after_the_loop++ == 0) {
        g_h2_client->push_request(get(g_h2_target), h2_throws);
        heard(503);
    }
    throw std::runtime_error("thrown by the callback of a request the destructor fails");
}

/// A callback that disconnects the client that is destroying itself, then pushes the request again, once.
void
h2_disconnects(qb::http::Response response) {
    in_flight(std::move(response));
    if (g_h2_pushes_after_the_loop++ == 0) {
        g_h2_client->disconnect();
        g_h2_client->push_request(get(g_h2_target), in_flight);
    }
}

[[noreturn]] void
run_h2(h2 const state, site const where) {
    std::atexit(judge);
    relay &peer = new_peer();
    if (state == h2::tls_ended)
        g_tls_closing = new qb::http::test::TlsClosingPeer(2);
    else if (state != h2::handshake && state != h2::handshake_redials) // the peer of those reads the ClientHello and answers nothing
        peer.through("127.0.0.1", start_h2_server());
    const std::string url = "https://localhost:" + std::to_string(state == h2::tls_ended ? g_tls_closing->port() : peer.port());
    static at_exit<std::shared_ptr<qb::http2::Client>> object{qb::http2::make_client(url)};
    qb::http2::Client                                 &client = *object.client;
    client.set_verify_peer(false); // the test's certificate is self-signed
    switch (state) {
        case h2::never_connected:
            break;
        case h2::connecting:
            if (!client.connect([](bool ok, std::string const &) { heard(ok ? 1 : 2); }))
                setup_failed("connect() started nothing");
            break;
        case h2::connecting_redials:
        case h2::connecting_throws:
            g_h2_client = &client;
            if (!client.connect(state == h2::connecting_redials ? h2_redial : h2_connect_throws))
                setup_failed("connect() started nothing");
            break;
        case h2::handshake:
        case h2::handshake_redials:
            g_h2_client = &client;
            if (!client.connect(state == h2::handshake_redials ? h2_redial : [](bool ok, std::string const &) { heard(ok ? 1 : 2); }))
                setup_failed("connect() started nothing");
            if (!pump_until(&peer, [&] { return peer.from_client() != 0; })) // the transport is up: its first flight was read
                setup_failed("the ClientHello never reached the peer");
            if (!client.is_connecting())
                setup_failed("the HTTP/2 client is not in its handshake");
            g.want_peer = 0;
            break;
        case h2::tls_ended:
            g_h2_client = &client;
            if (!client.connect(h2_redial_once))
                setup_failed("connect() started nothing");
            if (!pump_until(nullptr, [] { return g.calls >= 1; }))
                setup_failed("the peer never ended the connection");
            static_cast<void>(pump_until(nullptr, [] { return g.calls >= 2; }, std::chrono::milliseconds(3000))); // the redial's own
            break;
        case h2::idle:
            h2_connect(client, peer);
            g.want_peer = 0;
            break;
        case h2::request:
            h2_connect(client, peer);
            h2_silence(client, peer, url);
            if (!client.push_request(get(url + "/served"), in_flight))
                setup_failed("the request was refused");
            h2_in_flight(client, 1);
            g.want_peer = 0;
            break;
        case h2::retried:
            h2_connect(client, peer);
            h2_silence(client, peer, url);
            g_h2_client = &client;
            g_h2_target = url + "/served";
            if (!client.push_request(get(g_h2_target), h2_retry_once))
                setup_failed("the request was refused");
            h2_in_flight(client, 1);
            g.want_peer = 0;
            break;
        case h2::retried_on:
            h2_connect(client, peer);
            h2_silence(client, peer, url);
            g_h2_client = &client;
            g_h2_target = url + "/served";
            g_h2_pushes = 8; // nothing is pushed again before the loop is gone
            if (!client.push_request(get(g_h2_target), h2_retry_through_the_exit))
                setup_failed("the request was refused");
            h2_in_flight(client, 1);
            g.want_peer = 0;
            break;
        case h2::batches:
            h2_connect(client, peer);
            h2_silence(client, peer, url);
            g_h2_client = &client;
            g_h2_target = url + "/served";
            if (!client.push_request(get(g_h2_target), [](qb::http::Response response) {
                    std::vector<qb::http::Response> first;
                    first.push_back(std::move(response));
                    first.push_back(first.front());
                    h2_next_batch(std::move(first)); // the request's failure counts as a batch of two 503
                }))
                setup_failed("the request was refused");
            h2_in_flight(client, 1);
            g.want_peer = 0;
            break;
        case h2::throwing:
        case h2::disconnecting: {
            void (*const callback)(qb::http::Response) = state == h2::throwing ? h2_throws_after_a_push : h2_disconnects;
            h2_connect(client, peer);
            h2_silence(client, peer, url);
            g_h2_client = &client;
            g_h2_target = url + "/served";
            if (!client.push_request(get(g_h2_target), callback) || (state == h2::throwing && !client.push_request(get(g_h2_target), callback)))
                setup_failed("a request was refused");
            h2_in_flight(client, state == h2::throwing ? 2 : 1);
            g.want_peer = 0;
            break;
        }
        case h2::batch_throwing:
            h2_connect(client, peer);
            h2_silence(client, peer, url);
            g_h2_client = &client;
            g_h2_target = url + "/served";
            if (!client.push_requests(h2_two_requests(), h2_batch_throws) || !client.push_requests(h2_two_requests(), h2_batch_throws))
                setup_failed("a batch was refused");
            h2_in_flight(client, 4);
            g.want_peer = 0;
            break;
        case h2::coroutine:
            h2_connect(client, peer);
            h2_silence(client, peer, url);
            async::coro_scheduler().spawn(h2_parked(client, url + "/served"));
            if (!pump_until(nullptr, [] { return g.parked; }))
                setup_failed("the coroutine never reached its request");
            h2_in_flight(client, 1);
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
        case h2::reconnecting_retried:
        case h2::reconnecting_connects: {
            qb::http2::RetryPolicy policy;
            policy.with_initial_delay(1h).with_jitter(false).with_max_attempts(5);
            client.enable_auto_reconnect(std::move(policy));
        }
            h2_connect(client, peer);
            g_h2_client = &client;
            g_h2_target = url + "/served";
            h2_silence(client, peer, url);
            ++g_h2_pushes;
            if (!client.push_request(get(g_h2_target), state == h2::reconnecting           ? h2_retry
                                                       : state == h2::reconnecting_retried ? h2_retry_through_the_exit
                                                                                           : h2_connect_through_the_exit))
                setup_failed("the request was refused");
            h2_in_flight(client, 1);
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

// The connect() that waits for the handshake hears `false` from the client's destructor, after the loop. The transport
// is up -- the peer has read the ClientHello, and answers nothing -- and the peer reads its end.
TEST_P(Http2ClientStaticExitDeathTest, InItsTlsHandshake) {
    EXPECT_EXIT(run_h2(h2::handshake, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 1, 1, 2, 0, 0, 0)));
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
// again with no connection and no connect in flight, and again each time that one fails -- `k_late_pushes` times. Every
// generation is answered inside its push: one callback a push (two before the loop, the destructor's own, then four),
// nothing armed -- not the deadline the first of them asks for --, no connection asked (Huly QB-1246). The destructor
// answered what it found in two passes over its queues: the generation pushed from the second was left queued, and
// destroyed unanswered.
TEST_P(Http2ClientStaticExitDeathTest, InAReconnectionRunWhoseRequestIsPushedAgainAfterTheLoop) {
    EXPECT_EXIT(run_h2(h2::reconnecting_retried, GetParam()), ::testing::ExitedWithCode(0),
                stderr_is(verdict(-1, 3 + k_late_pushes, 1 + k_late_pushes, 503, 0, 0, 0)));
}

// The same from a connection that is up: the request the destructor fails is pushed again `k_late_pushes` times, and each
// push is answered where it is made. The first was written to the connection the destructor was about to close.
TEST_P(Http2ClientStaticExitDeathTest, ARequestInFlightWhoseCallbackKeepsPushingAfterTheLoop) {
    EXPECT_EXIT(run_h2(h2::retried_on, GetParam()), ::testing::ExitedWithCode(0),
                stderr_is(verdict(0, 1 + k_late_pushes, 1 + k_late_pushes, 503, 0, 0, 0)));
}

// The batch form: the request's failure pushes a batch of two, whose callback pushes the next, three batches in all,
// each answered inside its push -- its two members 503, its callback called once (Huly QB-1246).
TEST_P(Http2ClientStaticExitDeathTest, ARequestInFlightWhoseFailurePushesBatchAfterBatch) {
    EXPECT_EXIT(run_h2(h2::batches, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 4, 4, 503, 0, 0, 0)));
}

// Callbacks that throw from the destructor: what one throws is logged and goes no further -- the process does not
// terminate, the request after it is answered all the same -- and what the callback of a request pushed from there
// throws stays inside that push. Four calls: the two requests, the one the first pushes, and the line after that push
// (Huly QB-1246).
TEST_P(Http2ClientStaticExitDeathTest, TwoRequestsInFlightWhoseCallbacksThrow) {
    EXPECT_EXIT(run_h2(h2::throwing, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 4, 4, 503, 0, 0, 0)));
}

// The same of batches: two batches of two, the callback of each throws, and the first pushes a third whose callback
// throws inside that push. Four calls: the two batches, the one the first pushes, and the line after that push.
TEST_P(Http2ClientStaticExitDeathTest, TwoBatchesInFlightWhoseCallbacksThrow) {
    EXPECT_EXIT(run_h2(h2::batch_throwing, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 4, 4, 503, 0, 0, 0)));
}

// A callback the destructor runs disconnects the client, then pushes the request again: the disconnect() closes what
// the destructor was about to close, and the push is answered where it is made.
TEST_P(Http2ClientStaticExitDeathTest, ARequestInFlightWhoseCallbackDisconnects) {
    EXPECT_EXIT(run_h2(h2::disconnecting, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 2, 2, 503, 0, 0, 0)));
}

// connect() called by a callback the destructor runs, in a reconnection run -- neither connected nor connecting: refused
// by its return value alone. Its callback never runs and nothing connects after the loop (Huly QB-1246).
TEST_P(Http2ClientStaticExitDeathTest, InAReconnectionRunWhoseFailureCallbackConnectsAfterTheLoop) {
    EXPECT_EXIT(run_h2(h2::reconnecting_connects, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 3, 1, 503, 0, 0, 0)));
}

// The connect() that waits for the handshake hears `false` once, and calls connect() again from there: refused by its
// return value alone -- the callback of the second never runs (Huly QB-1246).
TEST_P(Http2ClientStaticExitDeathTest, InItsTlsHandshakeWhoseCallbackConnectsAgain) {
    EXPECT_EXIT(run_h2(h2::handshake_redials, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 1, 1, 2, 0, 0, 0)));
}

// A connect() whose connection the peer ends once its TLS handshake is complete hears `false`, and its callback calls
// connect() once more: that attempt is its own -- the peer ends it too -- and its callback hears `false` as well, before
// the loop ends. Nothing is left for the destructor. The redial joined the attempt that had just ended: nothing started
// for it, and the destructor, which disconnects only a client connected or connecting, destroyed its callback unheard
// (Huly QB-1246).
TEST_P(Http2ClientStaticExitDeathTest, AConnectionThePeerEndsAfterItsTlsHandshakeWhoseCallbackConnectsAgain) {
    EXPECT_EXIT(run_h2(h2::tls_ended, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 2, 0, 2, 0, 0, 0)));
}

INSTANTIATE_TEST_SUITE_P(Exit, Http2ClientStaticExitDeathTest, ::testing::Values(site::main, site::callback), site_name);

class Http2ClientStaticExitOnceDeathTest : public in_a_child {};

// A connect() asked and no pass of the loop since: it hears `false` from the client's destructor, after the loop.
TEST_F(Http2ClientStaticExitOnceDeathTest, AConnectInFlight) {
    EXPECT_EXIT(run_h2(h2::connecting, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
}

// The same, and the callback that hears `false` calls connect() again: refused by its return value alone.
TEST_F(Http2ClientStaticExitOnceDeathTest, AConnectInFlightWhoseCallbackConnectsAgain) {
    EXPECT_EXIT(run_h2(h2::connecting_redials, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
}

// The same, and the callback that hears `false` throws: what it throws is logged, and goes no further than the destructor.
TEST_F(Http2ClientStaticExitOnceDeathTest, AConnectInFlightWhoseCallbackThrows) {
    EXPECT_EXIT(run_h2(h2::connecting_throws, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
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

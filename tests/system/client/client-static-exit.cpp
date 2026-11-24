/**
 * @file qbm/http/tests/system/client/client-static-exit.cpp
 * @brief A client of this module with STATIC STORAGE ends cleanly when the process exits (Huly QB-1246): the
 *        HTTP/1.1 client, the one-shot verbs, the three WebSocket clients and the HTTP/3 client, in every state a
 *        program can leave them in -- never connected, a connect in flight, a handshake in flight, connected and
 *        idle, a request in flight (its callback pending, or a coroutine parked on it), disconnected by the program.
 *
 * `exit()` destroys the main thread's thread-locals before the objects with static storage, and qb-io's
 * `listener::current` is one: a client a program keeps in static storage -- the most ordinary declaration there is
 * -- is destroyed AFTER its thread's event loop. What its destructor does then runs where nothing can be registered,
 * armed or resumed any more: since 3.4 a request for the loop there stops the process on a line that names it, and a
 * watcher started there writes into the freed loop. So each case asks, of one client in one state:
 *
 *   - the process ends with the code the judge chose, and its stderr is the judge's line and NOTHING else: no named
 *     stop, no warning, no sanitizer report (under AddressSanitizer the destroyed listener is poisoned, so a read of
 *     it is a report);
 *   - the client's destructor ran after the loop -- asserted, not assumed: MSVC orders the two like the Itanium ABI
 *     -- and returned;
 *   - the peer of a connection reads a clean EOF, never a reset;
 *   - what was in flight ended as the module says it does: the judge's line carries how many times its callback ran,
 *     whether after the loop, and with what; whether the coroutine parked on it was resumed, and when its frame
 *     was destroyed;
 *   - LeakSanitizer, asked by the judge, has nothing to report.
 *
 * Every case is a CHILD process (a death test, re-executed). Its judge is an `atexit` handler registered before the
 * object with static storage is built, so it runs after that object's destructor. The peer is a relay the case
 * steps by hand (`static_exit_support.h`): a case that stops stepping it has a peer that is open and silent. A case
 * ends the process in one of four places, because a program does: back in `main` with no dispatch on the stack,
 * from a callback of the loop, from a callback of the client itself, and from a coroutine -- where the thread's
 * scheduler abandons what it owns and says so on one line (qb-io's rule: `exit()` in a coroutine destroys none).
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
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <qb/io/async.h>
#include <qb/io/async/coroutine.h>
#include <qbm/http/1.1/client.h>
#include <qbm/http/http.h>

#ifdef QB_HAS_SSL
#include <qbm/http/ws/coro.h>
#include <qbm/http/ws/ws.h>

#include "../../shared/loopback_server.h"
#include "../../shared/ssl_test_resource.h"
#endif

#include "static_exit_support.h"

#include "../../shared/static_exit_calls.h"

using namespace std::chrono_literals;

namespace client_static_exit_test {

namespace async = qb::io::async;
using namespace qb::io::test::static_exit;
using qb::http::test::static_exit::heard;
using qb::http::test::static_exit::k_not_as_the_rule;

std::string
origin(char const *const scheme, relay const &peer) {
    return std::string(scheme) + "://127.0.0.1:" + std::to_string(peer.port());
}

qb::http::Request
get(std::string const &target) {
    return qb::http::Request{qb::http::method::GET, qb::io::uri(target)};
}

void
in_flight(qb::http::Response response) {
    heard(static_cast<int>(response.status().code()));
}

/// A callback that throws once it has recorded its call: the destructor that runs it lets nothing out, and goes on.
void
throws(qb::http::Response response) {
    in_flight(std::move(response));
    throw std::runtime_error("thrown by the callback of a request the destructor fails");
}

/// The callback of a connect() that throws once it has recorded what it heard.
void
connect_throws(bool const ok, std::string const &) {
    heard(ok ? 1 : 2);
    throw std::runtime_error("thrown by the callback of a connect() the destructor fails");
}

/// How many times a callback that keeps pushing would push its request again after the loop, were every push
/// answered: more than the two the rule lets it make, so a push answered against the rule is counted.
constexpr int k_late_pushes = 4;
int           g_late_pushes = 0;

/// A batch of two, each member answered 503: the status the judge reads, 0 for any other answer.
int
batch_outcome(std::vector<qb::http::Response> const &responses) {
    if (responses.size() != 2)
        return 0;
    for (auto const &response : responses)
        if (response.status().code() != 503)
            return 0;
    return 503;
}

/// The retry pattern of a client of type `Client`, kept up through its destruction. One client a child process.
template <typename Client>
struct through_the_exit {
    static inline Client     *client = nullptr;
    static inline std::string target;

    /// A request pushed again each time it fails -- it would be, `k_late_pushes` times. The push its first failure makes
    /// is answered inside the push; the one made from inside THAT answer is refused by the return value alone, its
    /// callback unheard, and the run ends there (Huly QB-1246): two callbacks in all. The first push asks for a deadline
    /// too: none is armed (a timer asked of the loop after it stops the process).
    static void
    retry(qb::http::Response response) {
        in_flight(std::move(response));
        if (g_late_pushes < k_late_pushes) {
            const int level = g_late_pushes++;
            if (level == 0)
                client->set_request_timeout(5s);
            const int  before   = qb::io::test::static_exit::g.calls;
            const bool accepted = client->push_request(get(target), retry);
            const bool answered = qb::io::test::static_exit::g.calls != before;
            if (level == 0 ? !(accepted && answered) : (accepted || answered))
                heard(k_not_as_the_rule);
        }
    }

    /// A batch of two requests for `target`.
    static std::vector<qb::http::Request>
    two_requests() {
        std::vector<qb::http::Request> batch;
        batch.push_back(get(target));
        batch.push_back(get(target));
        return batch;
    }

    /// The batch form: each batch that fails pushes the next -- it would, three times. The batch the request's failure
    /// pushes is answered inside its push; the one pushed from inside THAT answer is refused by the return value alone.
    static void
    next_batch(std::vector<qb::http::Response> responses) {
        heard(batch_outcome(responses));
        if (g_late_pushes < 3) {
            const int  level    = g_late_pushes++;
            const int  before   = qb::io::test::static_exit::g.calls;
            const bool accepted = client->push_requests(two_requests(), next_batch);
            const bool answered = qb::io::test::static_exit::g.calls != before;
            if (level == 0 ? !(accepted && answered) : (accepted || answered))
                heard(k_not_as_the_rule);
        }
    }

    /// The failure of one request, counted as a batch of two 503 that pushes the first real batch.
    static void
    first_batch(qb::http::Response response) {
        std::vector<qb::http::Response> first;
        first.push_back(response);
        first.push_back(std::move(response));
        next_batch(std::move(first));
    }

    /// A callback that throws, and first -- once -- pushes a request whose callback throws too. What that one throws
    /// stays inside the push: the line after it runs, and is counted as a call. What this one throws goes no further
    /// than the destructor.
    static void
    throws_after_a_push(qb::http::Response response) {
        in_flight(std::move(response));
        if (g_late_pushes++ == 0) {
            client->push_request(get(target), throws);
            heard(503);
        }
        throw std::runtime_error("thrown by the callback of a request the destructor fails");
    }

    /// The callback of a batch that throws once it has recorded its call, and first -- once -- pushes a batch whose
    /// callback throws too. What that one throws stays inside the push: the line after it runs, and is counted.
    static void
    batch_throws(std::vector<qb::http::Response> responses) {
        heard(batch_outcome(responses));
        if (g_late_pushes++ == 0) {
            client->push_requests(two_requests(), batch_throws);
            heard(503);
        }
        throw std::runtime_error("thrown by the callback of a batch the destructor fails");
    }

    /// A callback that disconnects the client that is destroying itself, then pushes the request again, once.
    static void
    disconnects(qb::http::Response response) {
        in_flight(std::move(response));
        if (g_late_pushes++ == 0) {
            client->disconnect();
            client->push_request(get(target), in_flight);
        }
    }

    /// The callback of a connect() still waiting when the client is destroyed: it hears `false` (2) and calls
    /// connect() again, as a program that dials again does. That connect() is refused by its return value alone: its
    /// callback never runs (it would record 4, and one that dialled again from there would never end), and nothing
    /// is started (3).
    static void
    redial(bool const ok, std::string const &) {
        heard(ok ? 1 : 2);
        if (!ok && client->connect([](bool, std::string const &) { heard(4); }))
            heard(3);
    }
};

/// A scripted HTTP/1.1 server: every request is answered 200, on a connection kept alive.
std::string
answer_200(std::string &unread) {
    if (unread.find("\r\n\r\n") == std::string::npos)
        return {};
    unread.clear();
    return "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
}

// ======================================================================================================================
// qb::http1::Client
// ======================================================================================================================

enum class h1 {
    never_connected,
    plain_object,       ///< `static qb::http1::Client client{...}`, no shared owner: it can only be built and destroyed
    connecting,         ///< connect() asked, no pass of the loop since
    connecting_redials, ///< the same, and the callback that hears `false` calls connect() again
    connecting_throws,  ///< the same, and the callback that hears `false` throws
    idle,               ///< connected, nothing asked
    request,            ///< a request written, its callback pending
    queued,             ///< one request written, a second queued behind it
    retried,            ///< a request written, whose callback pushes it again when it fails: the retry pattern
    retried_on,         ///< the same, pushed again each time it fails: the second push is refused, unheard
    batches,            ///< a request written, whose failure pushes a batch, whose callback pushes the next: refused
    throwing,           ///< one request written and one queued, the callback of each throws, and the first pushes a third
    batch_throwing,     ///< two batches of two, the callback of each throws, and the first pushes a third
    disconnecting,      ///< a request written, whose callback disconnects the client and pushes the request again
    coroutine,          ///< a coroutine parked on a request
    own_callback,       ///< `exit()` called by the callback of a response
    disconnected,       ///< disconnect() and `exit()` at once
    disconnected_run,   ///< disconnect(), the loop run until the peer read the end
    handshake_redials,  ///< https: the ClientHello read by a peer that answers nothing, and the callback that hears `false` connects again
};

void
h1_connect(qb::http1::Client &client, relay &peer) {
    bool up = false;
    if (!client.connect([&up](bool ok, std::string const &) { up = ok; }))
        setup_failed("connect() started nothing");
    if (!pump_until(&peer, [&] { return up && peer.has_client(); }))
        setup_failed("the HTTP/1.1 client never connected");
}

qb::http1::Client *g_h1_client = nullptr;
std::string        g_h1_target;

/// The retry pattern: a request that failed is pushed again, once.
void
h1_retry(qb::http::Response response) {
    in_flight(std::move(response));
    if (g.calls == 1)
        g_h1_client->push_request(get(g_h1_target), in_flight);
}

async::task<void>
h1_parked(qb::http1::Client &client, std::string target) {
    frame_local local;
    g.parked      = true;
    auto response = co_await client.push_request(get(target));
    ++g.resumed;
    g.outcome = static_cast<int>(response.status().code());
}

[[noreturn]] void
run_h1(h1 const state, site const where) {
    std::atexit(judge); // first: it runs after the destructor of `object`
    relay            &peer = new_peer();
    const std::string url  = origin(state == h1::handshake_redials ? "https" : "http", peer);
    if (state == h1::plain_object) {
        static at_exit<qb::http1::Client> plain{url};
        leave(where);
    }
    static at_exit<std::shared_ptr<qb::http1::Client>> object{qb::http1::make_client(url)};
    qb::http1::Client                                 &client = *object.client;
    switch (state) {
        case h1::never_connected:
        case h1::plain_object:
            break;
        case h1::connecting:
            if (!client.connect([](bool ok, std::string const &) { heard(ok ? 1 : 2); }))
                setup_failed("connect() started nothing");
            break;
        case h1::connecting_redials:
            through_the_exit<qb::http1::Client>::client = &client;
            if (!client.connect(through_the_exit<qb::http1::Client>::redial))
                setup_failed("connect() started nothing");
            break;
        case h1::connecting_throws:
            if (!client.connect(connect_throws))
                setup_failed("connect() started nothing");
            break;
        case h1::idle:
            h1_connect(client, peer);
            g.want_peer = 0;
            break;
        case h1::request:
        case h1::queued:
            h1_connect(client, peer);
            if (!client.push_request(get(url + "/first"), in_flight))
                setup_failed("the request was refused");
            if (state == h1::queued && !client.push_request(get(url + "/second"), in_flight))
                setup_failed("the second request was refused");
            if (!pump_until(&peer, [&] { return peer.from_client() != 0; }))
                setup_failed("the request never reached the peer");
            g.want_peer = 0;
            break;
        case h1::retried_on:
        case h1::batches:
        case h1::throwing:
        case h1::disconnecting: {
            using pattern = through_the_exit<qb::http1::Client>;
            h1_connect(client, peer);
            pattern::client                            = &client;
            pattern::target                            = url + "/again";
            void (*const callback)(qb::http::Response) = state == h1::retried_on ? pattern::retry
                                                         : state == h1::batches  ? pattern::first_batch
                                                         : state == h1::throwing ? pattern::throws_after_a_push
                                                                                 : pattern::disconnects;
            if (!client.push_request(get(url + "/first"), callback))
                setup_failed("the request was refused");
            if (state == h1::throwing && !client.push_request(get(url + "/second"), callback))
                setup_failed("the second request was refused");
            if (!pump_until(&peer, [&] { return peer.from_client() != 0; }))
                setup_failed("the request never reached the peer");
            g.want_peer = 0;
            break;
        }
        case h1::batch_throwing: {
            using pattern = through_the_exit<qb::http1::Client>;
            h1_connect(client, peer);
            pattern::client = &client;
            pattern::target = url + "/again";
            if (!client.push_requests(pattern::two_requests(), pattern::batch_throws)
                || !client.push_requests(pattern::two_requests(), pattern::batch_throws))
                setup_failed("a batch was refused");
            if (!pump_until(&peer, [&] { return peer.from_client() != 0; }))
                setup_failed("the first request never reached the peer");
            g.want_peer = 0;
            break;
        }
        case h1::handshake_redials:
            through_the_exit<qb::http1::Client>::client = &client;
            client.set_verify_peer(false);
            if (!client.connect(through_the_exit<qb::http1::Client>::redial))
                setup_failed("connect() started nothing");
            if (!pump_until(&peer, [&] { return peer.from_client() != 0; })) // the transport is up: its first flight was read
                setup_failed("the ClientHello never reached the peer");
            if (!client.is_connecting())
                setup_failed("the HTTP/1.1 client is not in its handshake");
            g.want_peer = 0;
            break;
        case h1::retried:
            h1_connect(client, peer);
            g_h1_client = &client;
            g_h1_target = url + "/again";
            if (!client.push_request(get(url + "/first"), h1_retry))
                setup_failed("the request was refused");
            if (!pump_until(&peer, [&] { return peer.from_client() != 0; }))
                setup_failed("the request never reached the peer");
            g.want_peer = 0;
            break;
        case h1::coroutine:
            h1_connect(client, peer);
            async::coro_scheduler().spawn(h1_parked(client, url + "/parked"));
            if (!pump_until(&peer, [&] { return g.parked && peer.from_client() != 0; }))
                setup_failed("the coroutine's request never reached the peer");
            g.want_peer = 0;
            break;
        case h1::own_callback:
            peer.answer(answer_200);
            h1_connect(client, peer);
            // The dispatch that calls the callback holds the client (its handlers lock a shared owner for their own
            // duration) and exit() never unwinds it: the static pointer goes, the client does not, and its
            // connection is the process's to close. Still open when the judge reads it.
            g.want_alive = true;
            g.want_peer  = 2;
            if (!client.push_request(get(url + "/answered"), [](qb::http::Response response) {
                    in_flight(std::move(response));
                    std::exit(3); // inside the client's own dispatch: its callback, its protocol, its io handler
                }))
                setup_failed("the request was refused");
            pump_for(&peer, 30s);
            setup_failed("the response never came");
        case h1::disconnected:
            h1_connect(client, peer);
            client.disconnect();
            g.want_peer = 0;
            break;
        case h1::disconnected_run:
            h1_connect(client, peer);
            client.disconnect();
            if (!pump_until(&peer, [&] { return peer.client_ended(); }))
                setup_failed("the peer never read the end of a connection the client disconnected");
            g.want_peer = 0;
            break;
    }
    leave(where);
}

class Http1ClientStaticExitDeathTest : public in_a_child_from {};

TEST_P(Http1ClientStaticExitDeathTest, NeverConnected) {
    EXPECT_EXIT(run_h1(h1::never_connected, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 0, 0, 0, 0, 0, 0)));
}

// The declaration a program writes first. Such a client has no shared owner, so it never connects (its connect()
// answers "no longer available"): it is built, and destroyed after the loop.
TEST_P(Http1ClientStaticExitDeathTest, APlainObjectWithStaticStorage) {
    EXPECT_EXIT(run_h1(h1::plain_object, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 0, 0, 0, 0, 0, 0)));
}

TEST_P(Http1ClientStaticExitDeathTest, ConnectedAndIdle) {
    EXPECT_EXIT(run_h1(h1::idle, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0)));
}

TEST_P(Http1ClientStaticExitDeathTest, ARequestInFlight) {
    EXPECT_EXIT(run_h1(h1::request, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 1, 1, 503, 0, 0, 0)));
}

TEST_P(Http1ClientStaticExitDeathTest, ARequestInFlightAndOneQueued) {
    EXPECT_EXIT(run_h1(h1::queued, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 2, 2, 503, 0, 0, 0)));
}

// The retry pattern: the callback of the request that fails pushes it again -- from the client's destructor, after
// the loop. The client has no owner left to connect for it: it fails at once, and no deadline is armed for it (a
// timer asked of the loop there is a request the loop stops the process for).
TEST_P(Http1ClientStaticExitDeathTest, ARequestInFlightWhoseCallbackPushesAgain) {
    EXPECT_EXIT(run_h1(h1::retried, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 2, 2, 503, 0, 0, 0)));
}

// The same, kept up: a callback that pushes the request again at every failure. The push its first failure makes is
// answered inside the push; the one it makes from inside that answer is refused by the return value alone, its
// callback unheard -- no later turn exists after the loop, and answered inside each push such a callback never ended.
// Two callbacks, and the deadline the first push asks for is not armed (Huly QB-1246).
TEST_P(Http1ClientStaticExitDeathTest, ARequestInFlightWhoseCallbackKeepsPushingAfterTheLoop) {
    EXPECT_EXIT(run_h1(h1::retried_on, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 2, 2, 503, 0, 0, 0)));
}

// The batch form: the request's failure pushes a batch of two, answered inside its push -- its two members 503, its
// callback called once --, and the batch that callback pushes is refused by the return value alone (Huly QB-1246).
TEST_P(Http1ClientStaticExitDeathTest, ARequestInFlightWhoseFailurePushesBatchAfterBatch) {
    EXPECT_EXIT(run_h1(h1::batches, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 2, 2, 503, 0, 0, 0)));
}

// Callbacks that throw from the destructor: what one throws goes no further -- the process does not terminate, the
// request queued behind it is answered all the same -- and what the callback of a request pushed from there throws
// stays inside that push. Four calls: the two requests, the one the first pushes, and the line after that push
// (Huly QB-1246).
TEST_P(Http1ClientStaticExitDeathTest, TwoRequestsWhoseCallbacksThrow) {
    EXPECT_EXIT(run_h1(h1::throwing, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 4, 4, 503, 0, 0, 0)));
}

// The same of batches: two batches of two, the callback of each throws, and the first pushes a third whose callback
// throws inside that push. Four calls: the two batches, the one the first pushes, and the line after that push.
TEST_P(Http1ClientStaticExitDeathTest, TwoBatchesWhoseCallbacksThrow) {
    EXPECT_EXIT(run_h1(h1::batch_throwing, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 4, 4, 503, 0, 0, 0)));
}

#ifdef QB_HAS_SSL
// The connect() that waits for the TLS handshake -- the transport is up, the peer has read the ClientHello and answers
// nothing -- hears `false` once from the client's destructor, and calls connect() again from there: refused by its return
// value alone, the callback of the second never runs, and the peer reads its end (Huly QB-1246).
TEST_P(Http1ClientStaticExitDeathTest, InItsTlsHandshakeWhoseCallbackConnectsAgain) {
    EXPECT_EXIT(run_h1(h1::handshake_redials, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 1, 1, 2, 0, 0, 0)));
}
#endif

// A callback the destructor runs disconnects the client, then pushes the request again: the disconnect() finds
// nothing left to close, and the push is answered where it is made.
TEST_P(Http1ClientStaticExitDeathTest, ARequestInFlightWhoseCallbackDisconnects) {
    EXPECT_EXIT(run_h1(h1::disconnecting, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 2, 2, 503, 0, 0, 0)));
}

TEST_P(Http1ClientStaticExitDeathTest, ACoroutineParkedOnARequest) {
    EXPECT_EXIT(run_h1(h1::coroutine, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 1, 0)));
}

TEST_P(Http1ClientStaticExitDeathTest, DisconnectedThenExitAtOnce) {
    EXPECT_EXIT(run_h1(h1::disconnected, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0)));
}

TEST_P(Http1ClientStaticExitDeathTest, DisconnectedAndTheLoopRun) {
    EXPECT_EXIT(run_h1(h1::disconnected_run, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0)));
}

INSTANTIATE_TEST_SUITE_P(Exit, Http1ClientStaticExitDeathTest, ::testing::Values(site::main, site::callback), site_name);

class Http1ClientStaticExitOnceDeathTest : public in_a_child {};

// A connect() asked and no pass of the loop since: the connector is the loop's, its completion never comes, and the
// callback that waited for it hears `false` from the client's destructor, once, as the HTTP/2 and HTTP/3 clients'
// does (Huly QB-1246). It was abandoned: destroyed without a word.
TEST_F(Http1ClientStaticExitOnceDeathTest, AConnectInFlight) {
    EXPECT_EXIT(run_h1(h1::connecting, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
}

// The same, and the callback that hears `false` calls connect() again: refused by its return value alone -- the
// callback of the second never runs, and nothing is started.
TEST_F(Http1ClientStaticExitOnceDeathTest, AConnectInFlightWhoseCallbackConnectsAgain) {
    EXPECT_EXIT(run_h1(h1::connecting_redials, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
}

// The same, and the callback that hears `false` throws: what it throws goes no further than the destructor.
TEST_F(Http1ClientStaticExitOnceDeathTest, AConnectInFlightWhoseCallbackThrows) {
    EXPECT_EXIT(run_h1(h1::connecting_throws, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
}

// `exit()` from the callback of a response: the client's own dispatch is on the stack, and holds the client. Its
// static pointer is destroyed after the loop; the client is not, and its connection stays open to the end.
TEST_F(Http1ClientStaticExitOnceDeathTest, ExitFromTheCallbackOfAResponse) {
    EXPECT_EXIT(run_h1(h1::own_callback, site::main), ::testing::ExitedWithCode(0), stderr_is(left_alive(2, 1, 0, 200, 0, 0, 0)));
}

// A coroutine that calls `exit()`: the thread's scheduler is destroyed from inside one of its coroutines, abandons the
// two it owns and says so; the frame parked on the request is never destroyed, and the completion the client's
// destructor gives it after the loop is dropped.
TEST_F(Http1ClientStaticExitOnceDeathTest, ACoroutineParkedOnARequestAndExitFromACoroutine) {
    EXPECT_EXIT(run_h1(h1::coroutine, site::coroutine), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0), abandoned(2)));
}

// ======================================================================================================================
// The one-shot verbs: qb::http::GET(request, callback) and co_await qb::http::GET(request)
// ======================================================================================================================

enum class verb { callback, coroutine };

async::task<void>
verb_parked(std::string target) {
    frame_local local;
    g.parked   = true;
    auto reply = co_await qb::http::GET(get(target), 30s);
    ++g.resumed;
    g.outcome = static_cast<int>(reply.response.status().code());
}

[[noreturn]] void
run_verb(verb const how, site const where) {
    std::atexit(judge);
    relay            &peer = new_peer();
    const std::string url  = origin("http", peer) + "/one-shot";
    // Nothing of the module has static storage here -- the session of a one-shot request is the loop's -- so the
    // object only says when the statics went.
    static at_exit<char> object{'s'};
    if (how == verb::callback)
        qb::http::GET(get(url), [](qb::http::async::Reply &&reply) { in_flight(std::move(reply.response)); }, 30s);
    else
        async::coro_scheduler().spawn(verb_parked(url));
    if (!pump_until(&peer, [&] { return peer.from_client() != 0; }))
        setup_failed("the one-shot request never reached the peer");
    g.want_peer = 0;
    leave(where);
}

class HttpVerbStaticExitDeathTest : public in_a_child_from {};

TEST_P(HttpVerbStaticExitDeathTest, ARequestInFlight) {
    EXPECT_EXIT(run_verb(verb::callback, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0)));
}

TEST_P(HttpVerbStaticExitDeathTest, ACoroutineParkedOnARequest) {
    EXPECT_EXIT(run_verb(verb::coroutine, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 1, 0)));
}

INSTANTIATE_TEST_SUITE_P(Exit, HttpVerbStaticExitDeathTest, ::testing::Values(site::main, site::callback), site_name);

// The session of a one-shot request is destroyed by the loop it waits on when that loop is cleared -- but not from
// inside its own callback, which the session's dispatch is still running: there the session ends itself, once the
// callback has returned and the loop has run again. No child here: AddressSanitizer is the judge of the first half,
// LeakSanitizer and the peer of the second.
TEST(HttpVerbLoopTeardown, AClearFromTheCallbackOfAOneShotRequestLeavesItsSessionToItsOwnPath) {
    relay peer;
    ASSERT_TRUE(peer.listen());
    peer.answer(answer_200);
    int answered = 0;
    qb::http::GET(
        get(origin("http", peer) + "/one-shot"),
        [&answered](qb::http::async::Reply &&reply) {
            answered = static_cast<int>(reply.response.status().code());
            async::listener::current.clear(); // every watcher of the thread is detached, this session's among them
        },
        30s);
    ASSERT_TRUE(pump_until(&peer, [&] { return answered != 0; })) << "the one-shot request was never answered";
    EXPECT_EQ(answered, 200);
    EXPECT_TRUE(pump_until(&peer, [&] { return peer.client_ended(); })) << "the session never closed its connection";
    async::listener::current.clear();
}

// A one-shot request in flight when its loop is cleared is destroyed there: its connection is closed, and the
// callback it would have run is released without being run.
TEST(HttpVerbLoopTeardown, AOneShotRequestInFlightIsDestroyedWithTheLoopItWaitsOn) {
    relay peer;
    ASSERT_TRUE(peer.listen());
    auto alive = std::make_shared<int>(0); // held by the callback alone, once the request owns it
    int  calls = 0;
    qb::http::GET(get(origin("http", peer) + "/one-shot"), [alive, &calls](qb::http::async::Reply &&) { ++calls; }, 30s);
    const std::weak_ptr<int> callback_state = alive;
    alive.reset();
    ASSERT_TRUE(pump_until(&peer, [&] { return peer.from_client() != 0; })) << "the one-shot request never reached the peer";
    ASSERT_FALSE(callback_state.expired());
    async::listener::current.clear();
    EXPECT_TRUE(callback_state.expired()) << "the session outlived the loop it waited on: its callback's state was never released";
    EXPECT_EQ(calls, 0) << "the loop's teardown ran the callback of a request it dropped";
    EXPECT_EQ(peer.client_end(), 0) << "the peer of a one-shot request destroyed with its loop did not read a clean EOF";
}

// A one-shot request that was answered is disposed by the next pass of its loop. A loop cleared before that pass
// destroys it as well -- nothing else would. The deadline is passed by hand here, outside a pass (the handler is the
// one the session's timer calls): answered inside a pass, a session is disposed before that pass returns.
TEST(HttpVerbLoopTeardown, AOneShotRequestAnsweredAndNotYetDisposedIsDestroyedWithTheLoop) {
    relay peer;
    ASSERT_TRUE(peer.listen());
    auto alive    = std::make_shared<int>(0); // held by the callback alone, once the session owns it
    int  answered = 0;
    auto callback = [alive, &answered](qb::http::async::Reply &&reply) {
        answered = static_cast<int>(reply.response.status().code());
    };
    const std::weak_ptr<int> callback_state = alive;
    alive.reset();
    qb::http::Request request = get(origin("http", peer) + "/one-shot");
    request.set_header("host", qb::http::host_header_value(request.uri()));
    auto *const session = new qb::http::async::HTTP<decltype(callback)>(std::move(callback), request); // as the verbs build it
    session->connect(30s);
    ASSERT_TRUE(pump_until(&peer, [&] { return peer.from_client() != 0; })) << "the one-shot request never reached the peer";
    const async::event::timeout deadline{async::listener::current.loop()};
    session->on(deadline); // 504 to the callback, and a disposal asked of the loop
    ASSERT_EQ(answered, 504);
    ASSERT_FALSE(callback_state.expired()) << "the session was disposed in the call: the case is no witness";
    async::listener::current.clear();
    EXPECT_TRUE(callback_state.expired()) << "a session answered and not yet disposed outlived the loop it waited on";
    EXPECT_EQ(peer.client_end(), 0) << "the peer of a one-shot request destroyed with its loop did not read a clean EOF";
}

#ifdef QB_HAS_SSL

// ======================================================================================================================
// The WebSocket clients: qb::http::ws::Client<>, a class of the program's over WebSocket<T>, coro_client<>
// ======================================================================================================================

bool g_ws_up = false; ///< the opening handshake completed

/// A scripted WebSocket server: it answers the opening handshake, then says nothing.
std::string
ws_accept(std::string &unread) {
    const auto end = unread.find("\r\n\r\n");
    if (end == std::string::npos)
        return {};
    std::string lower = unread.substr(0, end);
    for (auto &c : lower)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c - 'A' + 'a');
    constexpr std::string_view field = "sec-websocket-key:";
    const auto                 at    = lower.find(field);
    if (at == std::string::npos)
        setup_failed("the opening handshake carries no Sec-WebSocket-Key");
    auto       from = at + field.size();
    const auto to   = unread.find("\r\n", from);
    while (from < to && unread[from] == ' ')
        ++from;
    const std::string key = unread.substr(from, to - from);
    unread.erase(0, end + 4);
    return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
           + qb::protocol::detail::compute_accept_key(key) + "\r\n\r\n";
}

/// What a WebSocket client says of its connection, as the judge's outcome: none of it may come from a destructor.
enum : int { ws_disconnected = 3, ws_error = 4, ws_closed = 5 };

/// A WebSocket client of the program's own: the CRTP base, its events as member functions.
class own_ws : public qb::http::ws::WebSocket<own_ws> {
    using base = qb::http::ws::WebSocket<own_ws>;

public:
    void
    on(base::connected &&) {
        g_ws_up = true;
    }
    void
    on(base::message &&) {}
    void
    on(base::closed &&) {
        heard(ws_closed);
    }
    void
    on(base::error &&) {
        heard(ws_error);
    }
    void
    on(base::ping &&) {}
    void
    on(base::pong &&) {}
    void
    on(base::disconnected &&) {
        heard(ws_disconnected);
    }
};

enum class ws {
    never_connected,
    connecting,       ///< connect() asked, no pass of the loop since
    handshake,        ///< the transport is up, the server never answers the opening handshake
    idle,             ///< open, nothing said
    pinging,          ///< open, the keepalive timer armed
    disconnected,     ///< disconnect() and `exit()` at once
    disconnected_run, ///< disconnect(), the loop run until the peer read the end
    own_callback,     ///< `exit()` called by the client's own callback, as its opening handshake completes
};

template <typename Client>
[[noreturn]] void
drive_ws(Client &client, relay &peer, ws const state, site const where) {
    const qb::io::uri url{origin("ws", peer) + "/"};
    switch (state) {
        case ws::never_connected:
            break;
        case ws::connecting:
            client.connect(url);
            break;
        case ws::handshake:
            client.connect(url);
            if (!pump_until(&peer, [&] { return peer.from_client() != 0; }))
                setup_failed("the opening handshake never reached the peer");
            g.want_peer = 0;
            break;
        case ws::idle:
        case ws::pinging:
        case ws::disconnected:
        case ws::disconnected_run:
            peer.answer(ws_accept);
            client.connect(url);
            if (!pump_until(&peer, [&] { return g_ws_up; }))
                setup_failed("the WebSocket never opened");
            g.want_peer = 0;
            if (state == ws::pinging)
                client.set_ping_interval(1h);
            if (state == ws::disconnected || state == ws::disconnected_run)
                client.disconnect();
            if (state == ws::disconnected_run && !pump_until(&peer, [&] { return peer.client_ended(); }))
                setup_failed("the peer never read the end of a WebSocket the client disconnected");
            break;
        case ws::own_callback:
            peer.answer(ws_accept);
            g.want_peer = 0;
            client.connect(url);
            pump_for(&peer, 30s);
            setup_failed("the WebSocket never opened");
    }
    leave(where);
}

[[noreturn]] void
run_ws_callback(ws const state, site const where) {
    std::atexit(judge);
    relay                                 &peer = new_peer();
    static at_exit<qb::http::ws::Client<>> object;
    if (state == ws::own_callback)
        object.client.on_connected([](auto &) {
            heard(1);
            std::exit(3); // inside the client's own dispatch: its io handler, its protocol, its callback
        });
    else
        object.client.on_connected([](auto &) { g_ws_up = true; });
    object.client.on_disconnected([](auto &) { heard(ws_disconnected); });
    object.client.on_error([](auto &) { heard(ws_error); });
    object.client.on_closed([](auto &) { heard(ws_closed); });
    drive_ws(object.client, peer, state, where);
}

[[noreturn]] void
run_ws_own(ws const state, site const where) {
    std::atexit(judge);
    relay                 &peer = new_peer();
    static at_exit<own_ws> object;
    drive_ws(object.client, peer, state, where);
}

enum class ws_coro { connect, receive };

async::task<void>
ws_parked(qb::http::ws::coro_client<> &client, std::string url, bool then_receive) {
    frame_local local;
    g.parked           = true;
    const auto opening = co_await client.connect(std::string_view{url});
    g_ws_up            = opening.ok;
    if (!then_receive || !opening.ok) {
        ++g.resumed;
        co_return;
    }
    const auto frame = co_await client.receive();
    static_cast<void>(frame);
    ++g.resumed;
}

[[noreturn]] void
run_ws_coro(ws_coro const parked_on, site const where) {
    std::atexit(judge);
    relay                                      &peer = new_peer();
    static at_exit<qb::http::ws::coro_client<>> object;
    if (parked_on == ws_coro::receive)
        peer.answer(ws_accept);
    async::coro_scheduler().spawn(ws_parked(object.client, origin("ws", peer) + "/", parked_on == ws_coro::receive));
    if (!pump_until(&peer, [&] { return parked_on == ws_coro::receive ? g_ws_up : peer.from_client() != 0; }))
        setup_failed("the WebSocket coroutine never reached its wait");
    pump_for(&peer, 20ms); // parked on receive(), or still on connect()
    g.want_peer = 0;
    leave(where);
}

class WsClientStaticExitDeathTest : public in_a_child_from {};

/// The judge's line of a client the program disconnected just before it ended the process from `where`.
[[nodiscard]] std::string
after_disconnect(site const where) {
    return where == site::main ? verdict(0, 0, 0, 0, 0, 0, 0) : verdict(0, 1, 0, ws_disconnected, 0, 0, 0);
}

TEST_P(WsClientStaticExitDeathTest, CallbackClientNeverConnected) {
    EXPECT_EXIT(run_ws_callback(ws::never_connected, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 0, 0, 0, 0, 0, 0)));
}

TEST_P(WsClientStaticExitDeathTest, CallbackClientInItsOpeningHandshake) {
    EXPECT_EXIT(run_ws_callback(ws::handshake, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0)));
}

TEST_P(WsClientStaticExitDeathTest, CallbackClientOpenAndIdle) {
    EXPECT_EXIT(run_ws_callback(ws::idle, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0)));
}

TEST_P(WsClientStaticExitDeathTest, CallbackClientOpenWithItsKeepaliveArmed) {
    EXPECT_EXIT(run_ws_callback(ws::pinging, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0)));
}

// disconnect() says `disconnected` from the loop, at its next pass: once when a pass follows (the callback that ends
// the process comes after it), never when the process ends first -- the destructor says nothing in its place.
TEST_P(WsClientStaticExitDeathTest, CallbackClientDisconnectedThenExitAtOnce) {
    EXPECT_EXIT(run_ws_callback(ws::disconnected, GetParam()), ::testing::ExitedWithCode(0), stderr_is(after_disconnect(GetParam())));
}

TEST_P(WsClientStaticExitDeathTest, CallbackClientDisconnectedAndTheLoopRun) {
    EXPECT_EXIT(run_ws_callback(ws::disconnected_run, GetParam()), ::testing::ExitedWithCode(0),
                stderr_is(verdict(0, 1, 0, ws_disconnected, 0, 0, 0)));
}

TEST_P(WsClientStaticExitDeathTest, AClassOfTheProgramsOwnOpenAndIdle) {
    EXPECT_EXIT(run_ws_own(ws::idle, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 0, 0)));
}

TEST_P(WsClientStaticExitDeathTest, AClassOfTheProgramsOwnDisconnectedThenExitAtOnce) {
    EXPECT_EXIT(run_ws_own(ws::disconnected, GetParam()), ::testing::ExitedWithCode(0), stderr_is(after_disconnect(GetParam())));
}

TEST_P(WsClientStaticExitDeathTest, ACoroutineParkedOnConnect) {
    EXPECT_EXIT(run_ws_coro(ws_coro::connect, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 1, 0)));
}

TEST_P(WsClientStaticExitDeathTest, ACoroutineParkedOnReceive) {
    EXPECT_EXIT(run_ws_coro(ws_coro::receive, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 0, 0, 0, 0, 1, 0)));
}

INSTANTIATE_TEST_SUITE_P(Exit, WsClientStaticExitDeathTest, ::testing::Values(site::main, site::callback), site_name);

class WsClientStaticExitOnceDeathTest : public in_a_child {};

TEST_F(WsClientStaticExitOnceDeathTest, CallbackClientWithAConnectInFlight) {
    EXPECT_EXIT(run_ws_callback(ws::connecting, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 0, 0, 0, 0, 0, 0)));
}

// `exit()` from the client's own callback: its dispatch is on the stack when its destructor runs. Nothing shares a
// WebSocket client, so nothing holds it: it is destroyed after the loop, and its peer reads the end.
TEST_F(WsClientStaticExitOnceDeathTest, CallbackClientExitFromItsOwnCallback) {
    EXPECT_EXIT(run_ws_callback(ws::own_callback, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(0, 1, 0, 1, 0, 0, 0)));
}

TEST_F(WsClientStaticExitOnceDeathTest, ACoroutineParkedOnReceiveAndExitFromACoroutine) {
    EXPECT_EXIT(run_ws_coro(ws_coro::receive, site::coroutine), ::testing::ExitedWithCode(0),
                stderr_is(verdict(0, 0, 0, 0, 0, 0, 0), abandoned(2)));
}

#endif // QB_HAS_SSL

#ifdef QBM_HTTP_HAS_HTTP3

// ======================================================================================================================
// qb::http3::Client. QUIC runs on UDP: there is no stream for a peer to read the end of, and the server of the case
// is on the client's own thread (one loop drives both), reachable to the end so that LeakSanitizer does not count it.
// ======================================================================================================================

using h3_server = std::remove_reference_t<decltype(*qb::http3::make_server())>;

std::shared_ptr<h3_server>               g_h3_server;
std::shared_ptr<void const>              g_h3_held;      ///< the context of a request the server never answers
std::shared_ptr<void const>              g_h3_also_held; ///< and of a second one
std::vector<std::shared_ptr<void const>> g_h3_all_held;  ///< and of every request of the batches

std::string
start_h3_server() {
    if (!qb::http::test::certs_available())
        setup_failed("the TLS test certificate is missing");
    g_h3_server = qb::http3::make_server();
    g_h3_server->router().get("/served", [](auto ctx) {
        ctx->response().status() = qb::http::status::NO_CONTENT;
        ctx->complete();
    });
    g_h3_server->router().get("/held", [](auto ctx) { g_h3_held = ctx; });
    g_h3_server->router().get("/also-held", [](auto ctx) { g_h3_also_held = ctx; });
    g_h3_server->router().get("/all-held", [](auto ctx) { g_h3_all_held.push_back(ctx); });
    g_h3_server->router().compile();
    const std::string url = "https://127.0.0.1:" + std::to_string(qb::http::test::ephemeral_udp_port());
    if (!g_h3_server->listen(qb::io::uri(url), qb::http::test::ssl_cert_path(), qb::http::test::ssl_key_path()))
        setup_failed("the HTTP/3 server did not start");
    return url;
}

enum class h3 {
    never_connected,
    connecting,         ///< connect() asked, no pass of the loop since
    connecting_redials, ///< the same, and the callback that hears `false` calls connect() again
    connecting_throws,  ///< the same, and the callback that hears `false` throws
    handshake_redials,  ///< the first flight read by a peer that answers nothing, and the callback that hears `false` connects again
    batch_throwing,     ///< two batches of two the server holds, the callback of each throws, and the first pushes a third
    idle,               ///< connected, nothing asked
    request,            ///< a request the server holds, its callback pending
    retried,            ///< such a request, whose callback pushes it again when it fails: the retry pattern
    retried_on,         ///< the same, pushed again each time it fails: the second push is refused, unheard
    batches,            ///< such a request, whose failure pushes a batch, whose callback pushes the next: refused
    throwing,           ///< two such requests, the callback of each throws, and the first pushes a third
    disconnecting,      ///< such a request, whose callback disconnects the client and pushes the request again
    coroutine,          ///< a coroutine parked on such a request
    own_callback,       ///< `exit()` called by the callback of a response
    disconnected,       ///< disconnect(), then `exit()`
};

/// A UDP peer that reads what a client sends and answers nothing: the client's QUIC handshake stays in flight. On the heap
/// and never destroyed, as the relay of the other cases is.
qb::io::udp::socket *g_h3_silent_peer = nullptr;

std::string
start_h3_silent_peer() {
    g_h3_silent_peer = new qb::io::udp::socket;
    if (!g_h3_silent_peer->init(AF_INET) || g_h3_silent_peer->bind_v4(0, "127.0.0.1") != 0)
        setup_failed("the silent UDP peer did not bind");
    static_cast<void>(g_h3_silent_peer->set_nonblocking(true));
    return "https://127.0.0.1:" + std::to_string(g_h3_silent_peer->local_endpoint().port());
}

/// The silent peer read a datagram: the client's first flight left it.
bool
h3_silent_peer_read() {
    char             datagram[2048];
    qb::io::endpoint from;
    return g_h3_silent_peer->read(datagram, sizeof(datagram), from) > 0;
}

void
h3_connect(qb::http3::Client &client) {
    bool up = false;
    if (!client.connect([&up](bool ok, std::string const &) { up = ok; }))
        setup_failed("connect() started nothing");
    if (!pump_until(nullptr, [&] { return up && client.is_connected(); }))
        setup_failed("the HTTP/3 client never connected");
}

qb::http3::Client *g_h3_client = nullptr;
std::string        g_h3_target;

/// The retry pattern: a request that failed is pushed again, once, and the client asked to connect. Both are refused
/// in the call: the request with a 503, the connect() by its return value alone -- its callback never runs (it would
/// record 4), and nothing is started (3).
void
h3_retry(qb::http::Response response) {
    in_flight(std::move(response));
    if (g.calls == 1) {
        if (g_h3_client->connect([](bool, std::string const &) { heard(4); }))
            heard(3);
        g_h3_client->push_request(get(g_h3_target), in_flight);
    }
}

async::task<void>
h3_parked(qb::http3::Client &client, std::string target) {
    frame_local local;
    g.parked      = true;
    auto response = co_await client.push_request(get(target));
    ++g.resumed;
    g.outcome = static_cast<int>(response.status().code());
}

[[noreturn]] void
run_h3(h3 const state, site const where) {
    std::atexit(judge);
    static_cast<void>(async::listener::current.size()); // the thread's listener exists: the client goes after it
    const std::string                                  url = state == h3::handshake_redials ? start_h3_silent_peer() : start_h3_server();
    static at_exit<std::shared_ptr<qb::http3::Client>> object{qb::http3::make_client(url)};
    qb::http3::Client                                 &client = *object.client;
    client.set_verify_peer(false); // the test's certificate is self-signed
    switch (state) {
        case h3::never_connected:
            break;
        case h3::connecting:
            if (!client.connect([](bool ok, std::string const &) { heard(ok ? 1 : 2); }))
                setup_failed("connect() started nothing");
            break;
        case h3::connecting_redials:
            through_the_exit<qb::http3::Client>::client = &client;
            if (!client.connect(through_the_exit<qb::http3::Client>::redial))
                setup_failed("connect() started nothing");
            break;
        case h3::connecting_throws:
            if (!client.connect(connect_throws))
                setup_failed("connect() started nothing");
            break;
        case h3::handshake_redials: {
            through_the_exit<qb::http3::Client>::client = &client;
            if (!client.connect(through_the_exit<qb::http3::Client>::redial))
                setup_failed("connect() started nothing");
            bool first_flight_read = false;
            if (!pump_until(nullptr, [&] { return first_flight_read = first_flight_read || h3_silent_peer_read(); }))
                setup_failed("the client's first flight never reached the peer");
            if (!client.is_connecting())
                setup_failed("the HTTP/3 client is not in its handshake");
            break;
        }
        case h3::batch_throwing: {
            using pattern = through_the_exit<qb::http3::Client>;
            h3_connect(client);
            pattern::client = &client;
            pattern::target = url + "/all-held";
            if (!client.push_requests(pattern::two_requests(), pattern::batch_throws)
                || !client.push_requests(pattern::two_requests(), pattern::batch_throws))
                setup_failed("a batch was refused");
            if (!pump_until(nullptr, [] { return g_h3_all_held.size() == 4; }))
                setup_failed("the batches never reached the server");
            break;
        }
        case h3::idle:
            h3_connect(client);
            break;
        case h3::request:
        case h3::retried:
        case h3::retried_on:
        case h3::batches:
        case h3::throwing:
        case h3::disconnecting: {
            h3_connect(client);
            g_h3_client                                 = &client;
            g_h3_target                                 = url + "/held";
            through_the_exit<qb::http3::Client>::client = &client;
            through_the_exit<qb::http3::Client>::target = url + "/held";
            using pattern                               = through_the_exit<qb::http3::Client>;
            void (*const callback)(qb::http::Response)  = state == h3::retried         ? h3_retry
                                                          : state == h3::retried_on    ? pattern::retry
                                                          : state == h3::batches       ? pattern::first_batch
                                                          : state == h3::throwing      ? pattern::throws_after_a_push
                                                          : state == h3::disconnecting ? pattern::disconnects
                                                                                       : in_flight;
            if (!client.push_request(get(url + "/held"), callback))
                setup_failed("the request was refused");
            if (state == h3::throwing && !client.push_request(get(url + "/also-held"), callback))
                setup_failed("the second request was refused");
            if (!pump_until(nullptr, [&] { return g_h3_held != nullptr && (state != h3::throwing || g_h3_also_held != nullptr); }))
                setup_failed("the request never reached the server");
            break;
        }
        case h3::coroutine:
            h3_connect(client);
            async::coro_scheduler().spawn(h3_parked(client, url + "/held"));
            if (!pump_until(nullptr, [] { return g.parked && g_h3_held != nullptr; }))
                setup_failed("the coroutine's request never reached the server");
            break;
        case h3::own_callback:
            h3_connect(client);
            // The endpoint's dispatch holds the client while it calls the callback, and exit() never unwinds it: the
            // static pointer goes, the client does not.
            g.want_alive = true;
            if (!client.push_request(get(url + "/served"), [](qb::http::Response response) {
                    in_flight(std::move(response));
                    std::exit(3); // inside the client's own dispatch: its endpoint's read, its protocol, its callback
                }))
                setup_failed("the request was refused");
            pump_for(nullptr, 30s);
            setup_failed("the response never came");
        case h3::disconnected:
            h3_connect(client);
            client.disconnect();
            break;
    }
    leave(where);
}

class Http3ClientStaticExitDeathTest : public in_a_child_from {};

TEST_P(Http3ClientStaticExitDeathTest, NeverConnected) {
    EXPECT_EXIT(run_h3(h3::never_connected, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 0, 0, 0, 0, 0, 0)));
}

TEST_P(Http3ClientStaticExitDeathTest, ConnectedAndIdle) {
    EXPECT_EXIT(run_h3(h3::idle, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 0, 0, 0, 0, 0, 0)));
}

TEST_P(Http3ClientStaticExitDeathTest, ARequestInFlight) {
    EXPECT_EXIT(run_h3(h3::request, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 503, 0, 0, 0)));
}

// The retry pattern, from the client's destructor after the loop: the request pushed again is answered at once and
// the connect() asked with it is refused by its return value alone -- nothing is queued, armed or connected. Two
// calls after the loop: the request (503) and the request pushed again (503); the connect()'s callback never runs
// (Huly QB-1246). It heard `false` inside the call, where a callback that dials again on `false` never returns.
TEST_P(Http3ClientStaticExitDeathTest, ARequestInFlightWhoseCallbackPushesAgain) {
    EXPECT_EXIT(run_h3(h3::retried, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 2, 2, 503, 0, 0, 0)));
}

// The same, kept up: a callback that pushes the request again at every failure. The push its first failure makes is
// answered inside the push; the one made from inside that answer is refused by the return value alone, its callback
// unheard. Two callbacks, and the deadline the first push asks for is not armed.
TEST_P(Http3ClientStaticExitDeathTest, ARequestInFlightWhoseCallbackKeepsPushingAfterTheLoop) {
    EXPECT_EXIT(run_h3(h3::retried_on, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 2, 2, 503, 0, 0, 0)));
}

// The batch form: the request's failure pushes a batch of two, answered inside its push -- its two members 503, its
// callback called once --, and the batch that callback pushes is refused by the return value alone.
TEST_P(Http3ClientStaticExitDeathTest, ARequestInFlightWhoseFailurePushesBatchAfterBatch) {
    EXPECT_EXIT(run_h3(h3::batches, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 2, 2, 503, 0, 0, 0)));
}

// Callbacks that throw from the destructor: what one throws goes no further -- the process does not terminate, the
// request after it is answered all the same -- and what the callback of a request pushed from there throws stays
// inside that push. Four calls: the two requests, the one the first pushes, and the line after that push.
TEST_P(Http3ClientStaticExitDeathTest, TwoRequestsInFlightWhoseCallbacksThrow) {
    EXPECT_EXIT(run_h3(h3::throwing, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 4, 4, 503, 0, 0, 0)));
}

// The same of batches: two batches of two, the callback of each throws, and the first pushes a third whose callback
// throws inside that push. Four calls: the two batches, the one the first pushes, and the line after that push.
TEST_P(Http3ClientStaticExitDeathTest, TwoBatchesInFlightWhoseCallbacksThrow) {
    EXPECT_EXIT(run_h3(h3::batch_throwing, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 4, 4, 503, 0, 0, 0)));
}

// The connect() that waits for the QUIC handshake -- the peer has read the client's first flight and answers nothing --
// hears `false` once from the client's destructor, and calls connect() again from there: refused by its return value
// alone, the callback of the second never runs (Huly QB-1246).
TEST_P(Http3ClientStaticExitDeathTest, InItsHandshakeWhoseCallbackConnectsAgain) {
    EXPECT_EXIT(run_h3(h3::handshake_redials, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
}

// A callback the destructor runs disconnects the client, then pushes the request again: that disconnect() is the
// close -- the destructor's own, after it, finds nothing left to close -- and the push is answered where it is made.
TEST_P(Http3ClientStaticExitDeathTest, ARequestInFlightWhoseCallbackDisconnects) {
    EXPECT_EXIT(run_h3(h3::disconnecting, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 2, 2, 503, 0, 0, 0)));
}

TEST_P(Http3ClientStaticExitDeathTest, ACoroutineParkedOnARequest) {
    EXPECT_EXIT(run_h3(h3::coroutine, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 0, 0, 0, 0, 1, 0)));
}

TEST_P(Http3ClientStaticExitDeathTest, Disconnected) {
    EXPECT_EXIT(run_h3(h3::disconnected, GetParam()), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 0, 0, 0, 0, 0, 0)));
}

INSTANTIATE_TEST_SUITE_P(Exit, Http3ClientStaticExitDeathTest, ::testing::Values(site::main, site::callback), site_name);

class Http3ClientStaticExitOnceDeathTest : public in_a_child {};

// A connect() asked and no pass of the loop since: it hears `false` from the client's destructor, after the loop.
TEST_F(Http3ClientStaticExitOnceDeathTest, AConnectInFlight) {
    EXPECT_EXIT(run_h3(h3::connecting, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
}

// The same, and the callback that hears `false` calls connect() again: refused by its return value alone -- the
// callback of the second never runs, and nothing is started (Huly QB-1246).
TEST_F(Http3ClientStaticExitOnceDeathTest, AConnectInFlightWhoseCallbackConnectsAgain) {
    EXPECT_EXIT(run_h3(h3::connecting_redials, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
}

// The same, and the callback that hears `false` throws: what it throws goes no further than the destructor.
TEST_F(Http3ClientStaticExitOnceDeathTest, AConnectInFlightWhoseCallbackThrows) {
    EXPECT_EXIT(run_h3(h3::connecting_throws, site::main), ::testing::ExitedWithCode(0), stderr_is(verdict(-1, 1, 1, 2, 0, 0, 0)));
}

// `exit()` from the callback of a response: the client's own dispatch is on the stack, and holds the client. Its
// static pointer is destroyed after the loop; the client is not.
TEST_F(Http3ClientStaticExitOnceDeathTest, ExitFromTheCallbackOfAResponse) {
    EXPECT_EXIT(run_h3(h3::own_callback, site::main), ::testing::ExitedWithCode(0), stderr_is(left_alive(-1, 1, 0, 204, 0, 0, 0)));
}

#endif // QBM_HTTP_HAS_HTTP3

} // namespace client_static_exit_test

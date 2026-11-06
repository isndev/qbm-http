/**
 * @file qbm/http/tests/system/routing/sse-stream.cpp
 * @brief Server-Sent Events through `qb::http::sse` on HTTP/1.1, HTTP/2 and HTTP/3 (Huly QB-86): the head of an
 *        event stream, events read by the client BEFORE the stream ends, `Last-Event-ID`, the heartbeat and its
 *        timer's death with the stream, `send_async()` from a coroutine.
 *
 * The same routes serve three servers. On HTTP/1.1 the client is a raw TCP socket on the test thread, reading the
 * chunked wire; on HTTP/2 the raw HTTP/2 client of `shared/http2_raw_client.h`, reading DATA frames; on HTTP/3 the
 * module's own client on the one loop, with the peer's acknowledgements as the proof that the events arrived before
 * `end()`. The HTTP/2 and HTTP/3 parts compile under their gates; the HTTP/1.1 part always.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <gtest/gtest.h>

#include "../../shared/loopback_server.h"

#include <qb/io/async/coroutine.h>
#include <qb/io/tcp/socket.h>
#include <qbm/http/http.h>

#ifdef QB_HAS_SSL
#include "../../shared/http2_raw_client.h"
#include "../../shared/ssl_test_resource.h"
#endif

using namespace std::chrono_literals;
using qb::http::sse::Event;
using qb::http::test::ServerThread;

namespace sse_stream_test {

inline std::atomic<bool> g_release{false};
/// On the one-loop HTTP/3 case: the held event stream's framing, what it wrote, what the peer has not acknowledged.
struct Probe {
    int         framing = -1;
    std::size_t written = 0;
    std::size_t pending = 0;
    bool        ended   = false;
};
inline std::function<Probe()> g_probe;
/// The /events handler's own reading of its stream once its sends ran, for a test thread (the std::function above is
/// read on the one loop of the HTTP/3 case only): `ended`, `written`, published last by `set`.
inline std::atomic<bool>        g_events_ended{false};
inline std::atomic<std::size_t> g_events_written{0};
inline std::atomic<bool>        g_events_probe_set{false};
inline std::atomic<int>         g_begin_refused{0};       ///< begin_sse() returned nullptr (a response that cannot be streamed)
inline std::atomic<int>         g_post_sent{0};           ///< POST_RESPONSE_SEND executions on /hooked (one per response, on every protocol)
inline std::atomic<int>         g_post_sent_completed{0}; ///< ...of which saw the context completed

/// Holds the stream until the test releases it, then one more event and the end.
template <typename Events>
void
finish_when_released(std::shared_ptr<Events> events) {
    if (events->cancelled())
        return;
    if (!g_release) {
        qb::io::async::callback([events] { finish_when_released(events); }, 2ms);
        return;
    }
    (void) events->send(Event{.name = "done", .data = "4", .id = "4"});
    events->end();
}

/// The routes, the same on every protocol: `auto ctx` is the context of whichever session serves it.
template <typename Router>
void
install_routes(Router &r) {
    const auto events_route = [](auto ctx) {
        auto events = ctx->begin_sse();
        if (!events)
            return;
        (void) events->send(Event{.name = "tick", .data = "1", .id = "1"});
        (void) events->send(Event{.data = "line one\nline two"});
        (void) events->send(Event{.name = "tick", .data = "3", .id = "3"});
        g_probe = [weak = std::weak_ptr(events)]() -> Probe {
            if (auto e = weak.lock())
                return {static_cast<int>(e->stream()->framing()), e->stream()->written(), e->stream()->pending(), e->ended()};
            return {-1, 0, static_cast<std::size_t>(-1), false};
        };
        g_events_ended     = events->ended();
        g_events_written   = events->stream()->written();
        g_events_probe_set = true;
        // Held until the test releases it, on cancelled() alone: on a HEAD the stream is ended from the start and the
        // chain keeps the handle alive for the probe -- the hazard begin()'s doc names, deliberate here.
        finish_when_released(events);
    };
    r.get("/events", events_route);
    r.head("/events", events_route); // a HEAD: the head alone, the producer handed an ended stream
    // A synchronous handler that streams and ends inside route(): the response-sent hook runs once, after the context
    // completed -- HTTP/3 adopted the context early and ran it twice (review of Huly QB-86).
    const auto hooked = [](auto ctx) {
        ctx->add_lifecycle_hook([](auto &c, qb::http::HookPoint point) {
            if (point == qb::http::HookPoint::POST_RESPONSE_SEND) {
                ++g_post_sent;
                if (c.is_completed())
                    ++g_post_sent_completed;
            }
        });
        auto events = ctx->begin_sse();
        if (!events)
            return;
        (void) events->send(Event{.data = "once"});
        events->end();
    };
    r.get("/hooked", hooked);
    r.head("/hooked", hooked);
    // The same, from a coroutine that begins its stream after route() returned: the context is the session's by then.
    const auto hooked_async = [](auto ctx) -> qb::io::async::task<void> {
        ctx->add_lifecycle_hook([](auto &c, qb::http::HookPoint point) {
            if (point == qb::http::HookPoint::POST_RESPONSE_SEND) {
                ++g_post_sent;
                if (c.is_completed())
                    ++g_post_sent_completed;
            }
        });
        co_await qb::io::async::sleep(1ms);
        auto events = ctx->begin_sse();
        if (!events)
            co_return;
        (void) events->send(Event{.data = "once"});
        events->end();
    };
    r.get("/hooked-async", hooked_async);
    r.head("/hooked-async", hooked_async);
    r.get("/maybe-accel", [](auto ctx) {
        auto events = ctx->begin_sse(qb::http::sse::Options{.accel_buffering_off = true});
        if (!events) {
            ++g_begin_refused;
            return;
        }
        (void) events->send(Event{.data = "streamed"});
        events->end();
    });
    r.get("/maybe", [](auto ctx) {
        auto events = ctx->begin_sse();
        if (!events) {
            ++g_begin_refused; // a response that cannot be streamed: begin_sse() aborted the buffered stream (500)
            return;
        }
        (void) events->send(Event{.data = "streamed"});
        events->end();
    });
    r.get("/last", [](auto ctx) {
        auto events = ctx->begin_sse();
        if (!events)
            return;
        (void) events->send(Event{.name = "resume", .data = std::string(qb::http::sse::last_event_id(ctx->request()))});
        events->end();
    });
    r.get("/heartbeat", [](auto ctx) {
        auto events = ctx->begin_sse(qb::http::sse::Options{.retry = 2500ms, .heartbeat = 20ms});
        if (!events)
            return;
        g_probe = [weak = std::weak_ptr(events)]() -> Probe {
            if (auto e = weak.lock())
                return {static_cast<int>(e->stream()->framing()), e->stream()->written(), e->stream()->pending()};
            return {-1, 0, static_cast<std::size_t>(-1)};
        };
        finish_when_released(events);
    });
    r.get("/dropped", [](auto ctx) {
        auto events = ctx->begin_sse(qb::http::sse::Options{.heartbeat = 20ms});
        if (!events)
            return;
        (void) events->send(Event{.data = "then gone"});
        // The handle dies here, before end(): the stream is aborted and the heartbeat's timer finds nothing to beat.
    });
    r.get("/coro", [](auto ctx) -> qb::io::async::task<void> {
        auto events = ctx->begin_sse();
        if (!events)
            co_return;
        for (int i = 0; i < 3; ++i) {
            if (!co_await events->send_async(Event{.data = std::to_string(i)}))
                co_return;
        }
        events->end();
    });
    r.compile();
}

const std::string kEvent1 = "event: tick\nid: 1\ndata: 1\n\n";
const std::string kEvent2 = "data: line one\ndata: line two\n\n";
const std::string kEvent3 = "event: tick\nid: 3\ndata: 3\n\n";
const std::string kEvent4 = "event: done\nid: 4\ndata: 4\n\n";

// ------------------------------------------------------------------------------------------------ HTTP/1.1
class SseServer;
class SseSession : public qb::http::use<SseSession>::session<SseServer> {
public:
    explicit SseSession(SseServer &server)
        : session(server) {}
};
class SseServer : public qb::http::use<SseServer>::server<SseSession> {
public:
    SseServer() {
        install_routes(router());
    }
};

/// A raw TCP client reading an HTTP/1.1 response and de-chunking its body as it comes.
struct RawH1 {
    qb::io::tcp::socket sock;
    std::string         wire;
    std::string         head;
    std::string         body; ///< the de-chunked body so far
    bool                complete = false;
    bool                eof      = false;
    std::size_t         chunks   = 0;
    std::size_t         parsed   = 0; ///< bytes of `wire` consumed by the chunk parser

    bool
    connect(std::uint16_t port) {
        return sock.connect_v4("127.0.0.1", port) == 0 && sock.set_nonblocking(true) == 0;
    }
    bool
    send(std::string const &request) {
        std::string_view data(request);
        const auto       deadline = std::chrono::steady_clock::now() + 2s;
        while (!data.empty()) {
            const int n = sock.write(data.data(), data.size());
            if (n > 0) {
                data.remove_prefix(static_cast<std::size_t>(n));
                continue;
            }
            if (std::chrono::steady_clock::now() >= deadline)
                return false;
            std::this_thread::sleep_for(1ms);
        }
        return true;
    }
    bool
    read_some() {
        char      tmp[16384];
        const int n = sock.read(tmp, sizeof tmp);
        if (n > 0) {
            wire.append(tmp, static_cast<std::size_t>(n));
            parse();
            return true;
        }
        if (n == 0 || !qb::io::socket::not_recv_error(qb::io::socket::get_last_errno()))
            eof = true;
        return false;
    }
    void
    parse() {
        if (head.empty()) {
            const auto end = wire.find("\r\n\r\n");
            if (end == std::string::npos)
                return;
            head   = wire.substr(0, end + 2);
            parsed = end + 4;
        }
        while (!complete) {
            const auto line_end = wire.find("\r\n", parsed);
            if (line_end == std::string::npos)
                return;
            const std::size_t size = std::stoul(wire.substr(parsed, line_end - parsed), nullptr, 16);
            if (wire.size() < line_end + 2 + size + 2)
                return;
            if (size == 0) {
                complete = true;
                parsed   = line_end + 4;
                return;
            }
            body.append(wire, line_end + 2, size);
            ++chunks;
            parsed = line_end + 2 + size + 2;
        }
    }
    template <typename Pred>
    bool
    read_until(Pred &&pred, std::chrono::milliseconds budget = 5s) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!pred()) {
            if (eof || std::chrono::steady_clock::now() >= deadline)
                return pred();
            if (!read_some())
                std::this_thread::sleep_for(1ms);
        }
        return true;
    }
    /// Forget the response read so far: the next bytes on this connection start another one.
    void
    next_response() {
        wire.erase(0, parsed);
        parsed = 0;
        head.clear();
        body.clear();
        complete = false;
        chunks   = 0;
    }
    void
    read_for(std::chrono::milliseconds window) {
        const auto deadline = std::chrono::steady_clock::now() + window;
        while (!eof && std::chrono::steady_clock::now() < deadline)
            if (!read_some())
                std::this_thread::sleep_for(1ms);
    }
    [[nodiscard]] bool
    header_is(std::string name, std::string value) const {
        std::string h = head;
        for (auto *s : {&h, &name, &value})
            for (auto &c : *s)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return h.find("\r\n" + name + ": " + value + "\r\n") != std::string::npos;
    }
    [[nodiscard]] bool
    has_header(std::string name) const {
        std::string h = head;
        for (auto *s : {&h, &name})
            for (auto &c : *s)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return h.find("\r\n" + name + ":") != std::string::npos;
    }
    [[nodiscard]] std::size_t
    count(std::string const &needle) const {
        std::size_t n = 0;
        for (auto pos = body.find(needle); pos != std::string::npos; pos = body.find(needle, pos + 1))
            ++n;
        return n;
    }
};

class SseHttp1Test : public ::testing::Test {
protected:
    std::uint16_t                            port = 0;
    std::unique_ptr<ServerThread<SseServer>> server;

    void
    SetUp() override {
        g_release          = false;
        g_begin_refused    = 0;
        g_events_probe_set = false;
        server             = std::make_unique<ServerThread<SseServer>>([](SseServer &s) {
            if (s.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            s.start();
            return true;
        });
        ASSERT_TRUE(server->ready());
        port = server->port();
        ASSERT_NE(port, 0);
    }
    void
    TearDown() override {
        g_release = true;
        server.reset();
    }
    static std::string
    get(std::string const &path, std::string const &extra = {}) {
        return "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n" + extra + "\r\n";
    }
};

TEST_F(SseHttp1Test, TheHeadIsAnEventStreamAndEventsArriveBeforeTheEnd) {
    RawH1 c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/events")));
    ASSERT_TRUE(c.read_until([&] { return c.count("\n\n") >= 3; }));
    EXPECT_FALSE(c.complete) << "three events read while the producer is held: no last-chunk yet";
    EXPECT_EQ(c.head.substr(0, 12), "HTTP/1.1 200");
    EXPECT_TRUE(c.header_is("content-type", "text/event-stream; charset=utf-8")) << c.head;
    EXPECT_TRUE(c.header_is("cache-control", "no-cache")) << c.head;
    EXPECT_TRUE(c.header_is("connection", "keep-alive")) << c.head;
    EXPECT_TRUE(c.header_is("transfer-encoding", "chunked")) << c.head;
    EXPECT_FALSE(c.has_header("content-length")) << c.head;
    EXPECT_EQ(c.body, kEvent1 + kEvent2 + kEvent3);
    EXPECT_GE(c.chunks, 3u) << "one chunk per event: nothing waited for a buffer to fill";
    g_release = true;
    ASSERT_TRUE(c.read_until([&] { return c.complete; }));
    EXPECT_EQ(c.body, kEvent1 + kEvent2 + kEvent3 + kEvent4);
    c.read_for(50ms); // a close would be read here
    EXPECT_FALSE(c.eof) << "keep-alive: the connection outlives the stream";
    // The SAME connection serves the next request.
    c.next_response();
    ASSERT_TRUE(c.send(get("/last")));
    ASSERT_TRUE(c.read_until([&] { return c.complete; }));
    EXPECT_EQ(c.body, "event: resume\ndata: \n\n") << "no Last-Event-ID on this request";
    EXPECT_FALSE(c.eof);
}

TEST_F(SseHttp1Test, AHeadGetsTheHeadAloneAndTheProducerSeesAnEndedStream) {
    RawH1 c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send("HEAD /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
    ASSERT_TRUE(c.read_until([&] { return !c.head.empty(); }));
    EXPECT_EQ(c.head.substr(9, 3), "200") << c.head;
    EXPECT_TRUE(c.header_is("content-type", "text/event-stream; charset=utf-8")) << c.head;
    c.read_for(50ms);
    EXPECT_TRUE(c.body.empty()) << "the head alone";
    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (!g_events_probe_set && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(1ms);
    ASSERT_TRUE(g_events_probe_set.load()) << "the handler ran its sends";
    EXPECT_TRUE(g_events_ended.load()) << "the stream came back ended: a producer that loops on cancelled() must read ended() too";
    EXPECT_EQ(g_events_written.load(), 0u) << "nothing of the three events was written";
    EXPECT_FALSE(c.eof) << "the connection serves on";
    g_release = true; // the held producer finds an ended stream: send() answers closed, end() is a no-op
}

TEST_F(SseHttp1Test, AResponseThatCannotBeStreamedIsRefusedWith500) {
    RawH1 c;
    ASSERT_TRUE(c.connect(port));
    // HTTP/1.0 without a length: begin_stream() can only buffer, and an event stream buffered until its end is none.
    ASSERT_TRUE(c.send("GET /maybe HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"));
    ASSERT_TRUE(c.read_until([&] { return !c.head.empty() && c.eof; }));
    EXPECT_EQ(c.head.substr(9, 3), "500") << c.head; // an HTTP/1.1 status line answers a 1.0 request, as the server always does
    EXPECT_EQ(g_begin_refused.load(), 1) << "the handler was told: nullptr";
    EXPECT_FALSE(c.has_header("content-type")) << "the event stream's head is gone with the aborted stream: " << c.head;
    EXPECT_FALSE(c.has_header("cache-control")) << c.head;
    // (The `Connection` strip cannot be witnessed here: an HTTP/1.0 request without the field has keep_alive false, so
    // begin() never said it; with the field the session says it again itself.)
    RawH1 accel;
    ASSERT_TRUE(accel.connect(port));
    ASSERT_TRUE(accel.send("GET /maybe-accel HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"));
    ASSERT_TRUE(accel.read_until([&] { return !accel.head.empty() && accel.eof; }));
    EXPECT_EQ(accel.head.substr(9, 3), "500") << accel.head;
    EXPECT_FALSE(accel.has_header("x-accel-buffering")) << "the option's field is gone too: " << accel.head;
    EXPECT_EQ(g_begin_refused.load(), 2);
    RawH1 ok;
    ASSERT_TRUE(ok.connect(port));
    ASSERT_TRUE(ok.send(get("/maybe-accel")));
    ASSERT_TRUE(ok.read_until([&] { return ok.complete; }));
    EXPECT_EQ(ok.body, "data: streamed\n\n") << "HTTP/1.1 streams it";
    EXPECT_TRUE(ok.header_is("x-accel-buffering", "no")) << ok.head;
}

TEST_F(SseHttp1Test, ARequestThatAsksToCloseGetsNoKeepAlive) {
    RawH1 c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/last", "Connection: keep-alive, close\r\n"))); // `close` among other tokens: the parser's verdict counts
    ASSERT_TRUE(c.read_until([&] { return c.complete; }));
    EXPECT_FALSE(c.header_is("connection", "keep-alive")) << c.head;
    EXPECT_TRUE(c.header_is("connection", "close")) << "the session's own answer to Connection: close: " << c.head;
    ASSERT_TRUE(c.read_until([&] { return c.eof; })) << "and it closes after the stream";
}

TEST_F(SseHttp1Test, TheResponseSentHookRunsOnceForASynchronousStreamAndAHead) {
    g_post_sent = g_post_sent_completed = 0;
    RawH1 c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/hooked")));
    ASSERT_TRUE(c.read_until([&] { return c.complete; }));
    EXPECT_EQ(c.body, "data: once\n\n");
    std::this_thread::sleep_for(50ms); // HTTP/1.1 runs the hook at eos, once the socket took the last byte
    EXPECT_EQ(g_post_sent.load(), 1);
    EXPECT_EQ(g_post_sent_completed.load(), 1) << "after the context completed";
    RawH1 h;
    ASSERT_TRUE(h.connect(port));
    ASSERT_TRUE(h.send("HEAD /hooked HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
    ASSERT_TRUE(h.read_until([&] { return !h.head.empty(); }));
    EXPECT_EQ(h.head.substr(0, 12), "HTTP/1.1 200") << h.head;
    h.read_for(50ms);
    EXPECT_TRUE(h.body.empty()) << "a HEAD: the head alone";
    EXPECT_EQ(g_post_sent.load(), 2) << "once more for the HEAD";
    // A coroutine that begins its stream after route() returned: the same count, after the completion.
    RawH1 a;
    ASSERT_TRUE(a.connect(port));
    ASSERT_TRUE(a.send(get("/hooked-async")));
    ASSERT_TRUE(a.read_until([&] { return a.complete; }));
    EXPECT_EQ(a.body, "data: once\n\n");
    std::this_thread::sleep_for(50ms);
    EXPECT_EQ(g_post_sent.load(), 3);
    RawH1 ah;
    ASSERT_TRUE(ah.connect(port));
    ASSERT_TRUE(ah.send("HEAD /hooked-async HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
    ASSERT_TRUE(ah.read_until([&] { return !ah.head.empty(); }));
    ah.read_for(50ms);
    EXPECT_EQ(g_post_sent.load(), 4);
    EXPECT_EQ(g_post_sent_completed.load(), 4) << "every hook ran after its context completed";
}

TEST_F(SseHttp1Test, LastEventIdIsReadFromTheRequest) {
    RawH1 c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/last", "Last-Event-ID: 41\r\n")));
    ASSERT_TRUE(c.read_until([&] { return c.complete; }));
    EXPECT_EQ(c.body, "event: resume\ndata: 41\n\n");
    RawH1 none;
    ASSERT_TRUE(none.connect(port));
    ASSERT_TRUE(none.send(get("/last")));
    ASSERT_TRUE(none.read_until([&] { return none.complete; }));
    EXPECT_EQ(none.body, "event: resume\ndata: \n\n") << "absent: empty";
}

TEST_F(SseHttp1Test, TheHeartbeatWritesCommentsWhileIdleAndStopsWithTheStream) {
    RawH1 c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/heartbeat")));
    ASSERT_TRUE(c.read_until([&] { return c.count(": \n\n") >= 3; }, 2s)) << c.body;
    EXPECT_EQ(c.body.substr(0, 13), "retry: 2500\n\n") << "the retry line first";
    g_release = true;
    ASSERT_TRUE(c.read_until([&] { return c.complete; }));
    const auto comments_at_end = c.count(": \n\n");
    const auto wire_at_end     = c.wire.size();
    c.read_for(150ms); // seven heartbeat intervals: a timer still alive would have written
    EXPECT_EQ(c.count(": \n\n"), comments_at_end) << "no comment after the end";
    EXPECT_EQ(c.wire.size(), wire_at_end) << "not a byte after the last-chunk";
    EXPECT_FALSE(c.eof);
}

TEST_F(SseHttp1Test, ADroppedStreamAbortsAndItsHeartbeatDiesWithIt) {
    RawH1 c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/dropped")));
    ASSERT_TRUE(c.read_until([&] { return c.eof; })) << "a stream dropped before end() closes the connection";
    EXPECT_EQ(c.body, "data: then gone\n\n") << "no heartbeat beat before the drop (20 ms away), and none after it";
    EXPECT_FALSE(c.complete) << "no last-chunk: the message was cut, not ended";
    // The timer fires 20 ms later, finds no stream and stops: a timer that held the stream would have kept it alive,
    // and the connection open -- the EOF above is the witness.
}

TEST_F(SseHttp1Test, SendAsyncFromACoroutineWritesEveryEvent) {
    RawH1 c;
    ASSERT_TRUE(c.connect(port));
    ASSERT_TRUE(c.send(get("/coro")));
    ASSERT_TRUE(c.read_until([&] { return c.complete; }));
    EXPECT_EQ(c.body, "data: 0\n\ndata: 1\n\ndata: 2\n\n");
}

#ifdef QB_HAS_SSL
// ------------------------------------------------------------------------------------------------ HTTP/2
class SseH2Server;
class SseH2Session : public qb::http2::use<SseH2Session>::session<SseH2Server> {
public:
    explicit SseH2Session(SseH2Server &server)
        : session(server) {}
};
class SseH2Server : public qb::http2::use<SseH2Server>::server<SseH2Session> {
public:
    SseH2Server() {
        install_routes(router());
    }
};

class SseHttp2Test : public ::testing::Test {
protected:
    std::uint16_t                              port = 0;
    std::unique_ptr<ServerThread<SseH2Server>> server;

    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available()) << "Missing TLS test certificates";
        g_release              = false;
        const std::string cert = qb::http::test::ssl_cert_path().string();
        const std::string key  = qb::http::test::ssl_key_path().string();
        server                 = std::make_unique<ServerThread<SseH2Server>>([cert, key](SseH2Server &s) -> bool {
            s.transport().init(qb::io::ssl::Context::server(cert, key).alpn({"h2", "http/1.1"}));
            if (s.transport().listen_v4(0, "127.0.0.1") != 0)
                return false;
            s.start();
            return true;
        });
        ASSERT_TRUE(server->ready());
        port = server->port();
    }
    void
    TearDown() override {
        g_release = true;
        server.reset();
    }
};

TEST_F(SseHttp2Test, EventsGoAsDataFramesBeforeTheEndWithoutAHopByHopField) {
    qb::http::test::Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto id = c.request("/events");
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).data.size() >= 3; }));
    const auto &s = c.stream(id);
    EXPECT_FALSE(s.end_stream) << "three events read while the producer is held";
    EXPECT_EQ(s.status(), 200);
    EXPECT_EQ(s.header("content-type"), "text/event-stream; charset=utf-8");
    EXPECT_EQ(s.header("cache-control"), "no-cache");
    EXPECT_TRUE(s.header("connection").empty()) << "hop-by-hop: never on HTTP/2";
    EXPECT_TRUE(s.header("transfer-encoding").empty());
    EXPECT_TRUE(s.header("content-length").empty());
    EXPECT_EQ(s.data[0], kEvent1) << "one DATA frame per event";
    EXPECT_EQ(s.data[1], kEvent2);
    EXPECT_EQ(s.data[2], kEvent3);
    g_release = true;
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).end_stream; }));
    EXPECT_EQ(c.stream(id).body(), kEvent1 + kEvent2 + kEvent3 + kEvent4);
    EXPECT_FALSE(c.stream(id).reset);
    c.close();
}

TEST_F(SseHttp2Test, TheHeartbeatBeatsAsDataFramesAndADroppedStreamResetsItsStream) {
    qb::http::test::Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto beat = c.request("/heartbeat");
    ASSERT_TRUE(c.read_until([&] { return c.stream(beat).data.size() >= 4; }, 2s)) << "the retry line, then comments while idle";
    EXPECT_EQ(c.stream(beat).data[0], "retry: 2500\n\n");
    EXPECT_EQ(c.stream(beat).data[1], ": \n\n") << "one DATA frame per comment";
    EXPECT_FALSE(c.stream(beat).end_stream);
    g_release = true;
    ASSERT_TRUE(c.read_until([&] { return c.stream(beat).end_stream; }));
    const auto frames_at_end = c.stream(beat).data.size();
    c.read_for(150ms);
    EXPECT_EQ(c.stream(beat).data.size(), frames_at_end) << "no comment after the end: the timer stopped";
    g_release          = false;
    const auto dropped = c.request("/dropped");
    ASSERT_TRUE(c.read_until([&] { return c.stream(dropped).reset; })) << "the handle died before end(): the stream is reset";
    EXPECT_EQ(c.stream(dropped).reset_code, 0x2u) << "INTERNAL_ERROR";
    EXPECT_EQ(c.stream(dropped).body(), "data: then gone\n\n");
    EXPECT_FALSE(c.eof) << "the stream, never the connection";
    c.read_for(60ms); // the dropped stream's timer tick: nothing to beat, nothing on the wire
    EXPECT_EQ(c.stream(dropped).body(), "data: then gone\n\n");
    c.close();
}

TEST_F(SseHttp2Test, TheResponseSentHookRunsOnceForASynchronousStreamAndAHead) {
    g_post_sent = g_post_sent_completed = 0;
    qb::http::test::Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto id = c.request("/hooked");
    ASSERT_TRUE(c.read_until([&] { return c.stream(id).end_stream; }));
    EXPECT_EQ(c.stream(id).body(), "data: once\n\n");
    c.read_for(50ms);
    EXPECT_EQ(g_post_sent.load(), 1);
    EXPECT_EQ(g_post_sent_completed.load(), 1) << "after the context completed";
    const auto head = c.request("/hooked", "HEAD");
    ASSERT_TRUE(c.read_until([&] { return c.stream(head).end_stream; }));
    EXPECT_TRUE(c.stream(head).data.empty());
    c.read_for(50ms);
    EXPECT_EQ(g_post_sent.load(), 2) << "once more for the HEAD";
    const auto async_id = c.request("/hooked-async");
    ASSERT_TRUE(c.read_until([&] { return c.stream(async_id).end_stream; }));
    EXPECT_EQ(c.stream(async_id).body(), "data: once\n\n");
    c.read_for(50ms);
    EXPECT_EQ(g_post_sent.load(), 3);
    const auto async_head = c.request("/hooked-async", "HEAD");
    ASSERT_TRUE(c.read_until([&] { return c.stream(async_head).end_stream; }));
    c.read_for(50ms);
    EXPECT_EQ(g_post_sent.load(), 4);
    EXPECT_EQ(g_post_sent_completed.load(), 4) << "every hook ran after its context completed";
    c.close();
}

TEST_F(SseHttp2Test, LastEventIdAndTheCoroutineSenderWorkOverHttp2) {
    qb::http::test::Http2RawClient c;
    ASSERT_TRUE(c.connect(port));
    const auto last = c.request("/last", "GET", {{"last-event-id", "41"}});
    ASSERT_TRUE(c.read_until([&] { return c.stream(last).end_stream; }));
    EXPECT_EQ(c.stream(last).body(), "event: resume\ndata: 41\n\n");
    const auto coro = c.request("/coro");
    ASSERT_TRUE(c.read_until([&] { return c.stream(coro).end_stream; }));
    EXPECT_EQ(c.stream(coro).body(), "data: 0\n\ndata: 1\n\ndata: 2\n\n");
    c.close();
}
#endif // QB_HAS_SSL

#ifdef QBM_HTTP_HAS_HTTP3
// ------------------------------------------------------------------------------------------------ HTTP/3
class SseHttp3Test : public ::testing::Test {
protected:
    void
    SetUp() override {
        ASSERT_TRUE(qb::http::test::certs_available());
        qb::io::async::init();
        g_release = false;
        g_probe   = nullptr;
    }
    static bool
    pump(std::function<bool()> const &done, std::chrono::milliseconds budget = 5s) {
        const auto deadline = std::chrono::steady_clock::now() + budget;
        while (!done()) {
            if (std::chrono::steady_clock::now() >= deadline) {
                ADD_FAILURE() << "pump: predicate not satisfied within " << budget.count() << "ms";
                return false;
            }
            if (!qb::io::async::run(EVRUN_ONCE | EVRUN_NOWAIT))
                std::this_thread::sleep_for(1ms);
        }
        return true;
    }
};

TEST_F(SseHttp3Test, EventsAreAcknowledgedBeforeTheEndAndTheBodyIsWhole) {
    const auto        port   = qb::http::test::ephemeral_udp_port();
    const std::string origin = "https://127.0.0.1:" + std::to_string(port);
    auto              server = qb::http3::make_server();
    install_routes(server->router());
    ASSERT_TRUE(server->listen(qb::io::uri(origin), qb::http::test::ssl_cert_path(), qb::http::test::ssl_key_path()));
    auto client = qb::http3::make_client(origin);
    client->set_verify_peer(false);
    std::optional<qb::http::Response> response;
    ASSERT_TRUE(
        client->push_request(qb::http::Request{qb::io::uri(origin + "/events")}, [&](qb::http::Response r) { response = std::move(r); }));
    const std::size_t three        = kEvent1.size() + kEvent2.size() + kEvent3.size();
    bool              pending_seen = false; // the pieces were in flight before the peer acknowledged them
    int               framing      = -1;
    ASSERT_TRUE(pump([&] {
        if (!g_probe)
            return false;
        const auto p = g_probe();
        framing      = p.framing;
        pending_seen = pending_seen || p.pending > 0;
        return p.written == three && p.pending == 0;
    })) << "the peer acknowledged the three events while the stream is open";
    EXPECT_EQ(framing, static_cast<int>(qb::http::stream_framing::end_of_stream))
        << "streamed, not buffered (a buffered stream reads pending 0)";
    EXPECT_TRUE(pending_seen) << "the events were written and unacknowledged before they were acknowledged";
    EXPECT_FALSE(response.has_value()) << "no message yet: the stream has not ended";
    g_release = true;
    ASSERT_TRUE(pump([&] { return response.has_value(); }));
    EXPECT_EQ(response->status(), qb::http::status::OK);
    EXPECT_EQ(response->header("content-type"), "text/event-stream; charset=utf-8");
    EXPECT_TRUE(response->header("connection").empty()) << "hop-by-hop: never on HTTP/3";
    EXPECT_EQ(response->body().template as<std::string>(), kEvent1 + kEvent2 + kEvent3 + kEvent4);
    // Last-Event-ID and the coroutine sender, on the same connection.
    std::optional<qb::http::Response> last;
    qb::http::Request                 with_id{qb::io::uri(origin + "/last")};
    with_id.set_header("Last-Event-ID", "41");
    ASSERT_TRUE(client->push_request(std::move(with_id), [&](qb::http::Response r) { last = std::move(r); }));
    ASSERT_TRUE(pump([&] { return last.has_value(); }));
    EXPECT_EQ(last->body().template as<std::string>(), "event: resume\ndata: 41\n\n");
    std::optional<qb::http::Response> coro;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(origin + "/coro")}, [&](qb::http::Response r) { coro = std::move(r); }));
    ASSERT_TRUE(pump([&] { return coro.has_value(); }));
    EXPECT_EQ(coro->body().template as<std::string>(), "data: 0\n\ndata: 1\n\ndata: 2\n\n");
    // The heartbeat beats while the stream is held, and a dropped stream resets its stream (502), the connection serving on.
    g_release = false;
    std::optional<qb::http::Response> beat;
    ASSERT_TRUE(
        client->push_request(qb::http::Request{qb::io::uri(origin + "/heartbeat")}, [&](qb::http::Response r) { beat = std::move(r); }));
    ASSERT_TRUE(pump([&] { return g_probe && g_probe().written >= 13 + 4 * 3; }, 2s)) << "the retry line and three comments";
    g_release = true;
    ASSERT_TRUE(pump([&] { return beat.has_value(); }));
    EXPECT_EQ(beat->status(), qb::http::status::OK);
    const auto beats = beat->body().template as<std::string>();
    EXPECT_EQ(beats.substr(0, 13), "retry: 2500\n\n");
    EXPECT_NE(beats.find(": \n\n"), std::string::npos) << beats;
    std::optional<qb::http::Response> dropped;
    ASSERT_TRUE(
        client->push_request(qb::http::Request{qb::io::uri(origin + "/dropped")}, [&](qb::http::Response r) { dropped = std::move(r); }));
    ASSERT_TRUE(pump([&] { return dropped.has_value(); }));
    EXPECT_EQ(dropped->status(), qb::http::status::BAD_GATEWAY) << "the handle died before end(): the stream was reset";
    std::optional<qb::http::Response> after;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(origin + "/last")}, [&](qb::http::Response r) { after = std::move(r); }));
    ASSERT_TRUE(pump([&] { return after.has_value(); }));
    EXPECT_EQ(after->status(), qb::http::status::OK) << "the connection serves on";
    // The response-sent hook, once per response: a synchronous streamed GET, then a HEAD.
    g_post_sent = g_post_sent_completed = 0;
    std::optional<qb::http::Response> hooked;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(origin + "/hooked")}, [&](qb::http::Response r) { hooked = std::move(r); }));
    ASSERT_TRUE(pump([&] { return hooked.has_value(); }));
    EXPECT_EQ(hooked->body().template as<std::string>(), "data: once\n\n");
    ASSERT_TRUE(pump([&] { return g_post_sent.load() >= 1; }));
    qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_EQ(g_post_sent.load(), 1) << "once: not from mark_response_sent() AND attach_context()";
    EXPECT_EQ(g_post_sent_completed.load(), 1) << "after the context completed";
    std::optional<qb::http::Response> head;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::HEAD, qb::io::uri(origin + "/hooked")},
                                     [&](qb::http::Response r) { head = std::move(r); }));
    ASSERT_TRUE(pump([&] { return head.has_value(); }));
    EXPECT_EQ(head->status(), qb::http::status::OK);
    EXPECT_TRUE(head->body().empty());
    ASSERT_TRUE(pump([&] { return g_post_sent.load() >= 2; }));
    qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_EQ(g_post_sent.load(), 2) << "once more for the HEAD";
    // A coroutine that begins its stream after route() returned: the FIN the drain forwards at once must not run the
    // hook before the stream completed the context, nor drop the session's last reference to it.
    std::optional<qb::http::Response> hooked_async;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::io::uri(origin + "/hooked-async")},
                                     [&](qb::http::Response r) { hooked_async = std::move(r); }));
    ASSERT_TRUE(pump([&] { return hooked_async.has_value() && g_post_sent.load() >= 3; }));
    qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_EQ(hooked_async->body().template as<std::string>(), "data: once\n\n");
    EXPECT_EQ(g_post_sent.load(), 3);
    std::optional<qb::http::Response> hooked_async_head;
    ASSERT_TRUE(client->push_request(qb::http::Request{qb::http::method::HEAD, qb::io::uri(origin + "/hooked-async")},
                                     [&](qb::http::Response r) { hooked_async_head = std::move(r); }));
    ASSERT_TRUE(pump([&] { return hooked_async_head.has_value() && g_post_sent.load() >= 4; }));
    qb::io::async::run(EVRUN_NOWAIT);
    EXPECT_EQ(g_post_sent.load(), 4);
    EXPECT_EQ(g_post_sent_completed.load(), 4) << "every hook ran after its context completed";
    client->disconnect();
    server->close();
}
#endif // QBM_HTTP_HAS_HTTP3

} // namespace sse_stream_test

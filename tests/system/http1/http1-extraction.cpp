/**
 * @file qbm/http/tests/system/http1/http1-extraction.cpp
 * @brief An HTTP/1.1 session extracted from its server runs its extraction handler (Huly QB-1182).
 *
 * `extractSession()` hands a session's socket to another owner -- a WebSocket upgrade, an ownership transfer -- and the
 * HTTP/1.1 session's `on(event::extracted)` is what makes that safe: it stops the session's watcher, so the event loop no
 * longer reports the socket to a session that gave it away, and cancels the context it was answering (a no-op after
 * `suppress_response()`). io_handler runs that handler only when its probe, `qb::has_on<Session, event::extracted>`,
 * sees it on the CONCRETE session type -- and the handler was private, befriended only for the internal base: no
 * extraction of any HTTP/1.1 session ran it. A session class that declares an `on()` of its own hides the base's
 * handler from the probe as well (C++ name hiding); the server's extractSession() runs it for that one.
 *
 * Both shapes are driven here on one thread: a server and a raw client socket on the test's own event loop, a request
 * whose handler holds its context, then `extractSession()`. Each case asserts the behaviour, not the trait: the context
 * is cancelled, the session's watcher is stopped -- and, for the session with a disconnection hook, that bytes the peer
 * sends afterwards reach no handler of the stale session (with its watcher still on the socket, the session reads its
 * moved-out transport, fails, and is torn down: its hook counts the disconnection).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <chrono>
#include <memory>
#include <string_view>
#include <thread>

#include <gtest/gtest.h>

#include <qbm/http/http.h>

#include <qb/io/tcp/socket.h>

using namespace std::chrono_literals;

namespace http1_extraction_test {

/// The context of the request the server holds, and what the stale session saw.
inline std::shared_ptr<void> g_held;
inline int                   g_hook_disconnects = 0;

template <typename Session>
class ExtractServer;

/// A user session that declares no `on()`: the base's handlers are what the probes find.
class PlainSession : public qb::http::use<PlainSession>::session<ExtractServer<PlainSession>> {
public:
    explicit PlainSession(ExtractServer<PlainSession> &server)
        : session(server) {}

    /// Whether the session's I/O watcher is still registered with the event loop (the io base's: the inactivity timer
    /// has a watcher of its own).
    [[nodiscard]] bool
    watching() const noexcept {
        return this->base_io_t::_async_event.is_active();
    }
};

/// A user session with the disconnection hook the HTTP/1.1 session forwards: an `on()` of its own, which hides every
/// `on()` of the base from a probe on this type.
class HookedSession : public qb::http::use<HookedSession>::session<ExtractServer<HookedSession>> {
public:
    explicit HookedSession(ExtractServer<HookedSession> &server)
        : session(server) {}

    void
    on(qb::http::event::disconnected &&) {
        ++g_hook_disconnects;
    }

    [[nodiscard]] bool
    watching() const noexcept {
        return this->base_io_t::_async_event.is_active();
    }
};

template <typename Session>
class ExtractServer : public qb::http::use<ExtractServer<Session>>::template server<Session> {
public:
    ExtractServer() {
        this->router().get("/hold", [](std::shared_ptr<qb::http::Context<Session>> ctx) { g_held = ctx; }); // never answered
        this->router().compile();
    }
};

template <typename Pred>
bool
pump_until(Pred &&pred, std::chrono::milliseconds budget = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + budget;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        qb::io::async::run(EVRUN_NOWAIT);
        std::this_thread::sleep_for(1ms);
    }
    return true;
}

template <typename Session>
void
expect_extraction_runs_the_handler(bool expect_hook_silent) {
    using Ctx = qb::http::Context<Session>;
    qb::io::async::init();
    g_held.reset();
    g_hook_disconnects = 0;
    {
        ExtractServer<Session> server;
        ASSERT_EQ(server.transport().listen_v4(0, "127.0.0.1"), 0);
        server.start();
        const auto port = server.transport().local_endpoint().port();

        qb::io::tcp::socket client;
        ASSERT_EQ(client.connect_v4("127.0.0.1", port), 0); // the kernel completes it from the listen backlog
        constexpr std::string_view request = "GET /hold HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        ASSERT_EQ(client.write(request.data(), request.size()), static_cast<int>(request.size()));
        ASSERT_TRUE(pump_until([] { return g_held != nullptr; })) << "the request never reached its handler";

        auto ctx     = std::static_pointer_cast<Ctx>(g_held);
        auto session = ctx->session();
        ASSERT_NE(session, nullptr);
        ASSERT_TRUE(session->watching());
        ASSERT_FALSE(ctx->is_cancelled());

        auto [io, ok] = server.extractSession(session->id());
        ASSERT_TRUE(ok);
        EXPECT_TRUE(server.sessions().empty());
        EXPECT_TRUE(ctx->is_cancelled()) << "the extraction did not cancel the context its session was answering";
        EXPECT_FALSE(session->watching()) << "the session still watches a socket it gave away";

        // The peer writes on: the bytes are the new owner's. Once they are readable, the loop runs before anyone reads
        // them -- a watcher still on the socket would report them to the old session, which reads its moved-out
        // transport, fails and is torn down.
        constexpr std::string_view more = "GET /hold HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        ASSERT_EQ(client.write(more.data(), more.size()), static_cast<int>(more.size()));
        ASSERT_GT(qb::io::socket::handle_read_ready(io.native_handle(), std::chrono::seconds(5)), 0)
            << "the extracted socket never became readable";
        for (int pass = 0; pass < 20; ++pass)
            qb::io::async::run(EVRUN_NOWAIT);
        char buffer[256];
        int  got = 0;
        ASSERT_TRUE(pump_until([&] {
            const int n = io.read(buffer + got, sizeof(buffer) - static_cast<std::size_t>(got));
            if (n > 0)
                got += n;
            return got >= static_cast<int>(more.size());
        })) << "what the peer sent did not reach the extracted socket whole";
        if (expect_hook_silent) {
            EXPECT_EQ(g_hook_disconnects, 0) << "the stale session handled an event on the socket it gave away";
        }

        io.close();
        client.close();
        g_held.reset();
    }
    qb::io::async::listener::current.clear();
}

} // namespace http1_extraction_test

TEST(Http1Extraction, AnExtractedSessionCancelsItsContextAndStopsWatching) {
    http1_extraction_test::expect_extraction_runs_the_handler<http1_extraction_test::PlainSession>(false);
}

TEST(Http1Extraction, ASessionDeclaringItsOwnOnIsExtractedTheSameWay) {
    http1_extraction_test::expect_extraction_runs_the_handler<http1_extraction_test::HookedSession>(true);
}

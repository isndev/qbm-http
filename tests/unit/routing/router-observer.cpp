/**
 * @file qbm/http/tests/unit/routing/router-observer.cpp
 * @brief `IRequestObserver` / `Router::add_observer` and `Context::route_pattern()` (Huly QB-90).
 *
 * A router observer is told when a request is received and, exactly once, when its response is decided. Pinned:
 *   - every request the router routes reaches it, once at each end: a match, a 404, a 405, an error chain's 500,
 *     the early 400 of a path over the router's limit -- with the status and the route pattern of what was decided;
 *   - `on_response` comes after the `PRE_RESPONSE_SEND` hooks and the hand-over to the session (it sees a header a
 *     hook set, and the session already holds the response) and before `REQUEST_COMPLETE`;
 *   - an asynchronous handler is waited for, and its wait is in the duration;
 *   - a request whose session is gone ends `SESSION_GONE`; a suppressed response ends `SUPPRESSED`, once, when its
 *     context is destroyed;
 *   - observers run in registration order; a context keeps the observers it was created with; `clear()` removes
 *     them; a null observer is ignored;
 *   - `route_pattern()` is the canonical pattern -- whatever slashes the registration used, through a group --
 *     empty for a 404, and outlives the router.
 *
 * Pure logic: no event loop, no socket.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "../../shared/mock_session.h"

namespace router_observer_test {

using qb::http::test::create_request;
using qb::http::test::MockSession;
using Ctx = qb::http::Context<MockSession>;

struct Seen {
    std::string              event; ///< "request" or "response"
    std::string              pattern;
    int                      status = 0;
    qb::http::RequestOutcome outcome{};
    qb::duration             duration{};
    std::string              hook_header; ///< the X-Hook header the response carried when observed
    unsigned                 writes = 0;  ///< the session's response writes when observed
};

class Recorder final : public qb::http::IRequestObserver<MockSession> {
public:
    std::vector<Seen>  seen;
    std::vector<Seen> *shared = nullptr; ///< also appended to, tagged, for ordering across observers
    std::string        tag;
    MockSession       *session = nullptr;

    void
    on_request(Ctx const &ctx) noexcept override {
        seen.push_back(Seen{"request", std::string(ctx.route_pattern())});
        if (shared)
            shared->push_back(Seen{tag + ":request"});
    }
    void
    on_response(Ctx const &ctx, qb::http::RequestEnd const &end) noexcept override {
        Seen s{"response",   std::string(ctx.route_pattern()), static_cast<int>(ctx.response().status()),     end.outcome,
               end.duration, ctx.response().header("X-Hook"),  session ? session->response_write_count() : 0u};
        seen.push_back(s);
        if (shared)
            shared->push_back(Seen{tag + ":response"});
    }
};

class RouterObserverTest : public ::testing::Test {
protected:
    std::shared_ptr<MockSession>  session = std::make_shared<MockSession>();
    qb::http::Router<MockSession> router;
    std::shared_ptr<Recorder>     recorder = std::make_shared<Recorder>();

    void
    SetUp() override {
        recorder->session = session.get();
        router.add_observer(recorder);
    }

    void
    route(qb::http::method method, std::string const &path) {
        session->reset();
        router.route(session, create_request(method, path));
    }

    [[nodiscard]] std::vector<Seen>
    responses() const {
        std::vector<Seen> out;
        for (auto const &s : recorder->seen)
            if (s.event == "response")
                out.push_back(s);
        return out;
    }
};

TEST_F(RouterObserverTest, EveryRoutedRequestIsSeenOnceAtEachEnd) {
    router.get("/users/:id", [](std::shared_ptr<Ctx> ctx) { ctx->json(qb::json{{"ok", true}}); });
    router.get("/boom", [](std::shared_ptr<Ctx> ctx) {
        ctx->response().status() = qb::http::status::BAD_GATEWAY;
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    });
    router.compile();

    route(qb::http::method::GET, "/users/42");                  // a match
    route(qb::http::method::GET, "/nowhere");                   // 404
    route(qb::http::method::POST, "/users/42");                 // 405: the path matched
    route(qb::http::method::GET, "/boom");                      // ERROR without an error chain: 500
    route(qb::http::method::GET, "/" + std::string(5000, 'x')); // over the router's path limit: 400 before matching

    ASSERT_EQ(recorder->seen.size(), 10u);
    for (std::size_t i = 0; i < recorder->seen.size(); i += 2) {
        EXPECT_EQ(recorder->seen[i].event, "request") << i;
        EXPECT_EQ(recorder->seen[i + 1].event, "response") << i;
        EXPECT_EQ(recorder->seen[i + 1].outcome, qb::http::RequestOutcome::RESPONDED) << i;
        EXPECT_GE(recorder->seen[i + 1].duration.count(), 0) << i;
    }
    auto const r = responses();
    EXPECT_EQ(r[0].status, 200);
    EXPECT_EQ(r[0].pattern, "/users/:id");
    EXPECT_EQ(r[1].status, 404);
    EXPECT_EQ(r[1].pattern, "");
    EXPECT_EQ(r[2].status, 405);
    EXPECT_EQ(r[2].pattern, "/users/:id");
    EXPECT_EQ(r[3].status, 500);
    EXPECT_EQ(r[3].pattern, "/boom");
    EXPECT_EQ(r[4].status, 400);
    EXPECT_EQ(r[4].pattern, "");
    EXPECT_EQ(recorder->seen[0].pattern, "") << "on_request runs before matching";
}

TEST_F(RouterObserverTest, TheResponseIsSeenAfterItsHooksAndItsHandOverAndBeforeRequestComplete) {
    std::vector<std::string> order;
    router.add_lifecycle_hook([&order](Ctx &ctx, qb::http::HookPoint point) {
        if (point == qb::http::HookPoint::PRE_RESPONSE_SEND) {
            ctx.response().set_header("X-Hook", "set-before-send");
            order.push_back("pre-response-send");
        } else if (point == qb::http::HookPoint::REQUEST_COMPLETE) {
            order.push_back("request-complete");
        }
    });
    struct Order final : qb::http::IRequestObserver<MockSession> {
        std::vector<std::string> *order;
        explicit Order(std::vector<std::string> *o)
            : order(o) {}
        void
        on_response(Ctx const &, qb::http::RequestEnd const &) noexcept override {
            order->push_back("observer");
        }
    };
    router.add_observer(std::make_shared<Order>(&order));
    router.get("/x", [](std::shared_ptr<Ctx> ctx) { ctx->text("x"); });
    router.compile();

    route(qb::http::method::GET, "/x");

    auto const r = responses();
    ASSERT_EQ(r.size(), 1u);
    EXPECT_EQ(r[0].hook_header, "set-before-send");
    EXPECT_EQ(r[0].writes, 1u) << "the response was handed to the session before the observer ran";
    EXPECT_EQ(order, (std::vector<std::string>{"pre-response-send", "observer", "request-complete"}));
}

TEST_F(RouterObserverTest, AnAsynchronousHandlerIsWaitedForAndTimed) {
    std::shared_ptr<Ctx> held;
    router.get("/slow", [&held](std::shared_ptr<Ctx> ctx) { held = std::move(ctx); }); // completes later
    router.compile();

    route(qb::http::method::GET, "/slow");
    EXPECT_TRUE(responses().empty()) << "not decided yet";
    constexpr auto gap = std::chrono::milliseconds(20);
    std::this_thread::sleep_for(gap); // the property: the duration contains this wait, whatever the host
    held->text("late");
    held.reset();

    auto const r = responses();
    ASSERT_EQ(r.size(), 1u);
    EXPECT_EQ(r[0].status, 200);
    EXPECT_GE(r[0].duration, gap);
}

TEST_F(RouterObserverTest, ASessionGoneEndsSessionGone) {
    std::shared_ptr<Ctx> held;
    router.get("/slow", [&held](std::shared_ptr<Ctx> ctx) { held = std::move(ctx); });
    router.compile();

    route(qb::http::method::GET, "/slow");
    recorder->session = nullptr;
    session.reset(); // the client left
    held->cancel("client gone");
    held.reset();

    auto const r = responses();
    ASSERT_EQ(r.size(), 1u);
    EXPECT_EQ(r[0].outcome, qb::http::RequestOutcome::SESSION_GONE);
    EXPECT_EQ(r[0].status, 503);
}

TEST_F(RouterObserverTest, ASuppressedResponseEndsSuppressedOnceAtDestruction) {
    std::shared_ptr<Ctx> held;
    router.get("/upgrade", [&held](std::shared_ptr<Ctx> ctx) {
        ctx->suppress_response(); // handed over, as a WebSocket upgrade does
        held = std::move(ctx);
    });
    router.compile();

    route(qb::http::method::GET, "/upgrade");
    EXPECT_TRUE(responses().empty()) << "told when the context goes, not before";
    EXPECT_EQ(session->response_write_count(), 0u);
    held.reset();

    auto const r = responses();
    ASSERT_EQ(r.size(), 1u);
    EXPECT_EQ(r[0].outcome, qb::http::RequestOutcome::SUPPRESSED);
    EXPECT_EQ(r[0].pattern, "/upgrade");
}

TEST_F(RouterObserverTest, ObserversRunInOrderAndAContextKeepsItsOwn) {
    std::vector<Seen> order;
    auto              second = std::make_shared<Recorder>();
    recorder->shared         = &order;
    recorder->tag            = "first";
    second->shared           = &order;
    second->tag              = "second";
    router.add_observer(second);
    router.add_observer(nullptr); // ignored

    std::shared_ptr<Ctx> held;
    router.get("/slow", [&held](std::shared_ptr<Ctx> ctx) { held = std::move(ctx); });
    router.compile();

    route(qb::http::method::GET, "/slow");
    auto third = std::make_shared<Recorder>();
    router.add_observer(third); // registered while the request is in flight: not its observer
    held->text("done");
    held.reset();

    ASSERT_EQ(order.size(), 4u);
    EXPECT_EQ(order[0].event, "first:request");
    EXPECT_EQ(order[1].event, "second:request");
    EXPECT_EQ(order[2].event, "first:response");
    EXPECT_EQ(order[3].event, "second:response");
    EXPECT_TRUE(third->seen.empty());

    router.clear();
    router.get("/after", [](std::shared_ptr<Ctx> ctx) { ctx->text("after"); });
    router.compile();
    order.clear();
    recorder->seen.clear();
    route(qb::http::method::GET, "/after");
    EXPECT_TRUE(order.empty()) << "clear() removed every observer";
    EXPECT_TRUE(third->seen.empty());
}

TEST(RoutePattern, IsTheCanonicalPatternAndOutlivesTheRouter) {
    auto                              router = std::make_unique<qb::http::Router<MockSession>>();
    std::vector<std::shared_ptr<Ctx>> held;
    auto                              keep = [&held](std::shared_ptr<Ctx> ctx) {
        held.push_back(ctx);
        ctx->text("ok");
    };
    router->get("/", keep);
    router->get("//files//*path/", keep); // the slashes do not reach the pattern
    router->get("/a/:id", keep);
    router->post("/a/:id/", keep); // the same route, another method
    router->group("/api")->get("/v1/items/:item", keep);
    router->compile();

    const std::vector<std::pair<std::string, std::string>> cases = {
        {"/", "/"},         {"/files/x/y.txt", "/files/*path"},         {"/files/", "/files/*path"},
        {"/a/7", "/a/:id"}, {"/api/v1/items/3", "/api/v1/items/:item"},
    };
    for (auto const &[path, pattern] : cases)
        router->route(std::make_shared<MockSession>(), create_request(qb::http::method::GET, path));
    router->route(std::make_shared<MockSession>(), create_request(qb::http::method::POST, "/a/9"));
    ASSERT_EQ(held.size(), cases.size() + 1);
    for (std::size_t i = 0; i < cases.size(); ++i)
        EXPECT_EQ(held[i]->route_pattern(), cases[i].second) << cases[i].first;
    EXPECT_EQ(held.back()->route_pattern(), "/a/:id") << "two methods, one pattern";

    router.reset(); // the compiled route names stay with the contexts that matched them
    EXPECT_EQ(held[3]->route_pattern(), "/a/:id");
    EXPECT_EQ(held[4]->route_pattern(), "/api/v1/items/:item");
}

} // namespace router_observer_test

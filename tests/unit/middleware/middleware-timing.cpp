/**
 * @file qbm/http/tests/unit/middleware/middleware-timing.cpp
 * @brief Unit tests for qb::http::TimingMiddleware (request-duration flow-control).
 *
 * TimingMiddleware records a steady_clock start in the context on process(), then
 * registers a PRE_RESPONSE_SEND hook that computes the elapsed duration, reports it
 * to a user callback, and stamps an `X-Response-Time` header. The clock is internal
 * (steady_clock) and not injectable, so to keep the duration assertions deterministic
 * we drive the hook directly against a Context whose seeded start time we control: by
 * overwriting the start-time context key with a known past timestamp before firing the
 * hook, the elapsed duration has an exact floor with a generous, race-free ceiling —
 * no wall-clock `sleep_for`, no brittle EXPECT_NEAR/EXPECT_NE between two live runs.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>

#include "../http.h"
#include "../middleware/timing.h"
#include "../routing/middleware.h"

#include "../../shared/middleware_test_fixture.h"

using namespace std::chrono_literals;

namespace {

using TimingMW    = qb::http::TimingMiddleware<qb::http::test::MockMiddlewareSession>;
using SessionT    = qb::http::test::MockMiddlewareSession;
using TimePoint   = TimingMW::Clock::time_point;
using Ctx         = qb::http::Context<SessionT>;

/** @brief Parses an `X-Response-Time` header value of the form "<double>ms" into milliseconds. */
std::optional<double>
parse_response_time_ms(const std::string &header_value) {
    if (header_value.size() < 3 || header_value.substr(header_value.size() - 2) != "ms")
        return std::nullopt;
    try {
        return std::stod(header_value.substr(0, header_value.size() - 2));
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace

/**
 * @brief Fixture for TimingMiddleware: owns a session and a callback that records the last duration.
 */
class TimingMiddlewareTest : public qb::http::test::MiddlewareTestFixture<SessionT> {
protected:
    std::optional<std::chrono::milliseconds> _last_duration;
    TimingMW::TimingCallback                  _record_cb;

    void
    SetUp() override {
        MiddlewareTestFixture<SessionT>::SetUp();
        _last_duration.reset();
        _record_cb = [this](const std::chrono::milliseconds &d) { _last_duration = d; };
    }

    /** @brief Builds a standalone Context (no router) suitable for direct hook driving. */
    std::shared_ptr<Ctx>
    make_ctx() {
        return std::make_shared<Ctx>(create_request(qb::http::method::GET, "/timed"), qb::http::Response{}, _session,
                                     [](Ctx &) {}, std::weak_ptr<qb::http::RouterCore<SessionT>>{});
    }
};

// --- Deterministic duration via controlled start-time seeding ----------------

TEST_F(TimingMiddlewareTest, BasicTimingStampsHeaderAndReportsCallback) {
    auto mw  = qb::http::timing_middleware<SessionT>(_record_cb, "BasicTimer");
    auto ctx = make_ctx();

    mw->process(ctx); // registers hook, seeds start = Clock::now()
    ctx->execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND);

    ASSERT_TRUE(_last_duration.has_value());
    EXPECT_GE(_last_duration->count(), 0);

    // The X-Response-Time header must be present, well-formed, and agree with the callback
    // duration to integer-millisecond resolution.
    const std::string header = std::string(ctx->response().header(std::string("X-Response-Time")));
    ASSERT_FALSE(header.empty());
    auto parsed = parse_response_time_ms(header);
    ASSERT_TRUE(parsed.has_value()) << "X-Response-Time not '<double>ms': " << header;
    EXPECT_GE(*parsed, 0.0);
    EXPECT_EQ(static_cast<long>(*parsed), _last_duration->count());
}

TEST_F(TimingMiddlewareTest, ElapsedDurationMatchesSeededStart) {
    const std::string timer_name  = "SeededTimer";
    const std::string context_key = "__TimingMiddleware_StartTime_" + timer_name;

    auto mw  = qb::http::timing_middleware<SessionT>(_record_cb, timer_name);
    auto ctx = make_ctx();
    mw->process(ctx); // hook registered; start seeded to now

    // Steppable-clock equivalent: rewind the recorded start by a known offset so the
    // hook measures a deterministic minimum elapsed time (end is captured at hook time,
    // immediately after — the ceiling is generous and cannot race).
    constexpr auto offset = 50ms;
    ctx->set(context_key, TimingMW::Clock::now() - offset);

    ctx->execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND);

    ASSERT_TRUE(_last_duration.has_value());
    EXPECT_GE(_last_duration->count(), 50);
    EXPECT_LT(_last_duration->count(), 5000); // generous ceiling: never races

    auto parsed = parse_response_time_ms(std::string(ctx->response().header(std::string("X-Response-Time"))));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_GE(*parsed, 50.0);
}

TEST_F(TimingMiddlewareTest, ResponseHookSurvivesMiddlewareDestruction) {
    bool callback_invoked = false;
    auto mw               = qb::http::timing_middleware<SessionT>(
        [&callback_invoked](const std::chrono::milliseconds &d) {
            callback_invoked = true;
            EXPECT_GE(d.count(), 0);
        },
        "DetachedTimer");
    auto ctx = make_ctx();

    mw->process(ctx);
    mw.reset(); // destroy the middleware; the hook closure must outlive it

    ctx->execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND);

    EXPECT_TRUE(callback_invoked);
    EXPECT_FALSE(ctx->response().header(std::string("X-Response-Time")).empty());
}

// --- Callback contract -------------------------------------------------------

TEST_F(TimingMiddlewareTest, CallbackIsInvokedThroughRouter) {
    bool callback_invoked = false;
    auto mw               = qb::http::timing_middleware<SessionT>(
        [&callback_invoked](const std::chrono::milliseconds &) { callback_invoked = true; }, "RouterTimer");

    configure_router_and_run(mw, create_request(qb::http::method::GET, "/mw_test"), qb::http::status::OK, "/mw_test");

    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_TRUE(callback_invoked);
}

TEST_F(TimingMiddlewareTest, CustomNaming) {
    auto mw = qb::http::timing_middleware<SessionT>(_record_cb, "MyCustomTimerName");
    EXPECT_EQ(mw->name(), "MyCustomTimerName");
}

TEST_F(TimingMiddlewareTest, ConstructorAndFactoryThrowOnNullCallback) {
    EXPECT_THROW({ TimingMW bad_mw(nullptr, "NullCbTimer"); }, std::invalid_argument);
    EXPECT_THROW({ (void) qb::http::timing_middleware<SessionT>(nullptr, "NullCbFactory"); }, std::invalid_argument);
}

// --- Two middlewares with distinct names keep independent start keys ----------

TEST_F(TimingMiddlewareTest, DistinctNamesYieldIndependentTiming) {
    std::optional<std::chrono::milliseconds> d1, d2;
    auto mw1 = qb::http::timing_middleware<SessionT>([&](const std::chrono::milliseconds &d) { d1 = d; }, "Timer1");
    auto mw2 = qb::http::timing_middleware<SessionT>([&](const std::chrono::milliseconds &d) { d2 = d; }, "Timer2");

    auto ctx = make_ctx();
    mw1->process(ctx);
    mw2->process(ctx);

    // Seed Timer1's key 30ms in the past, Timer2's key 10ms in the past: the two callbacks
    // must report distinct, deterministic minimum durations — no live-run NEAR/NE coupling.
    const auto now = TimingMW::Clock::now();
    ctx->set(std::string("__TimingMiddleware_StartTime_Timer1"), now - 30ms);
    ctx->set(std::string("__TimingMiddleware_StartTime_Timer2"), now - 10ms);

    ctx->execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND);

    ASSERT_TRUE(d1.has_value());
    ASSERT_TRUE(d2.has_value());
    EXPECT_GE(d1->count(), 30);
    EXPECT_GE(d2->count(), 10);
    EXPECT_GT(d1->count(), d2->count());
}

// --- Same name twice: second process() overwrites the shared key -------------

TEST_F(TimingMiddlewareTest, DuplicateNameSharesStartKeyBothHooksFire) {
    int  invocations = 0;
    auto cb          = [&](const std::chrono::milliseconds &d) {
        ++invocations;
        EXPECT_GE(d.count(), 20);
    };
    auto mw1 = qb::http::timing_middleware<SessionT>(cb, "DuplicateNameTimer");
    auto mw2 = qb::http::timing_middleware<SessionT>(cb, "DuplicateNameTimer");

    auto ctx = make_ctx();
    mw1->process(ctx);
    mw2->process(ctx); // overwrites the shared start key with its own now()

    // Both hooks read the SAME (last-written) start key; seed it deterministically.
    ctx->set(std::string("__TimingMiddleware_StartTime_DuplicateNameTimer"), TimingMW::Clock::now() - 20ms);
    ctx->execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND);

    EXPECT_EQ(invocations, 2);
}

// --- Robustness: missing / wrong-typed start key, throwing callback ----------

TEST_F(TimingMiddlewareTest, WrongTypedStartKeyIsOverwrittenAndTimingStillRuns) {
    const std::string timer_name  = "CollisionTimer";
    const std::string context_key = "__TimingMiddleware_StartTime_" + timer_name;

    auto ctx = make_ctx();
    ctx->set(context_key, 12345); // wrong type set before the middleware

    auto mw = qb::http::timing_middleware<SessionT>(_record_cb, timer_name);
    mw->process(ctx); // overwrites with a proper TimePoint
    ctx->execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND);

    ASSERT_TRUE(_last_duration.has_value());
    EXPECT_GE(_last_duration->count(), 0);
}

TEST_F(TimingMiddlewareTest, ThrowingCallbackIsSuppressedResponseStillStamped) {
    bool callback_invoked = false;
    auto mw               = qb::http::timing_middleware<SessionT>(
        [&callback_invoked](const std::chrono::milliseconds &) {
            callback_invoked = true;
            throw std::runtime_error("callback boom");
        },
        "ThrowingTimer");
    auto ctx = make_ctx();
    mw->process(ctx);

    EXPECT_NO_THROW(ctx->execute_hook(qb::http::HookPoint::PRE_RESPONSE_SEND));
    EXPECT_TRUE(callback_invoked);
    // Header is stamped before the callback runs, so it survives the suppressed throw.
    EXPECT_FALSE(ctx->response().header(std::string("X-Response-Time")).empty());
}

TEST_F(TimingMiddlewareTest, TimingForNotFoundRoute) {
    auto mw = qb::http::timing_middleware<SessionT>(_record_cb, "NotFoundTimer");

    _router = std::make_unique<qb::http::Router<SessionT>>();
    _router->use(mw);
    _router->compile(); // no routes
    _session->reset();
    _router->route(_session, create_request(qb::http::method::GET, "/no_such_route"));

    EXPECT_TRUE(_last_duration.has_value());
    EXPECT_GE(_last_duration->count(), 0);
    EXPECT_EQ(_session->get_response_ref().status(), qb::http::status::NOT_FOUND);
}

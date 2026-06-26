/**
 * @file qbm/http/tests/unit/routing/routing-middleware.cpp
 * @brief Global / group middleware, short-circuit, context slots, lifecycle hooks,
 *        observable onion ordering, and the 405 middleware path.
 *
 * One of the four focused unit files carved out of the legacy `test-router.cpp`
 * monolith. Where the legacy `MultipleMiddleware` test only checked *header presence*
 * (and explicitly punted on order), this file makes middleware ordering **observable**
 * by recording each step into a shared `std::vector<std::string>` trace carried on the
 * context — both the pre-`next()` (downward) and the post-`next()` (onion-unwind)
 * passes — and asserts the exact sequence. It also adds the spec-mandated cases:
 *
 *   - Onion-unwind: code *after* `next()` post-processes the response (the documented
 *     synchronous-downstream contract in `routing/types.h`).
 *   - 405 path with global middleware: a method-mismatch still runs the global
 *     prefix middleware before the router's built-in 405 handler.
 *
 * Adopts shared @ref qb::http::test::MockSession / create_request.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "../http.h"
#include "../../shared/mock_session.h"

using qb::http::test::create_request;
using qb::http::test::MockSession;

namespace {

/** @brief Context slot key for the shared, ordered execution trace. */
constexpr const char *kTrace = "trace";

class RoutingMiddlewareTest : public ::testing::Test {
protected:
    std::shared_ptr<MockSession>  session = std::make_shared<MockSession>();
    qb::http::Router<MockSession> router;

    /**
     * @brief Installs a PRE_RESPONSE_SEND hook that snapshots the @ref kTrace slot
     *        into @p out while the context is still alive (avoids dangling after route()).
     */
    void
    capture_trace_on_send(std::vector<std::string> &out) {
        router.add_lifecycle_hook([&out](auto &ctx, qb::http::HookPoint point) {
            if (point == qb::http::HookPoint::PRE_RESPONSE_SEND) {
                if (auto *t = ctx.template get_if<std::vector<std::string>>(kTrace)) {
                    out = *t;
                }
            }
        });
    }
};

// --------------------------------------------------------------------------
// Single global middleware modifies the response
// --------------------------------------------------------------------------

TEST_F(RoutingMiddlewareTest, GlobalMiddlewareRunsBeforeHandler) {
    router.use(
        [](auto ctx, auto next) {
            ctx->response().set_header("X-Middleware-Applied", "true");
            next();
        },
        "GlobalMiddleware");

    router.get("/protected", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "Protected content";
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/protected"));

    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    ASSERT_TRUE(session->_response.has_header("X-Middleware-Applied"));
    EXPECT_EQ(session->_response.header("X-Middleware-Applied", 0), "true");
    EXPECT_EQ(session->_response.body().template as<std::string>(), "Protected content");
    EXPECT_EQ(session->response_write_count(), 1u);
}

// --------------------------------------------------------------------------
// Observable middleware ordering (downward pass) — replaces header-only check
// --------------------------------------------------------------------------

TEST_F(RoutingMiddlewareTest, MultipleMiddlewareRunInRegistrationOrder) {
    auto make_mw = [](std::string id) {
        return [id = std::move(id)](auto ctx, auto next) {
            auto *t = ctx->template get_if<std::vector<std::string>>(kTrace);
            if (!t) {
                ctx->set(kTrace, std::vector<std::string>{});
                t = ctx->template get_if<std::vector<std::string>>(kTrace);
            }
            t->push_back(id);
            next();
        };
    };

    router.use(make_mw("mw1"), "mw1");
    router.use(make_mw("mw2"), "mw2");

    router.get("/multi", [](auto ctx) {
        auto *t = ctx->template get_if<std::vector<std::string>>(kTrace);
        if (t) {
            t->push_back("handler");
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });

    std::vector<std::string> order;
    capture_trace_on_send(order);
    router.compile();
    router.route(session, create_request(qb::http::method::GET, "/multi"));

    EXPECT_EQ(order, (std::vector<std::string>{"mw1", "mw2", "handler"}));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
}

// --------------------------------------------------------------------------
// Onion-unwind: code after next() post-processes the response
// --------------------------------------------------------------------------

TEST_F(RoutingMiddlewareTest, OnionUnwindRunsPostNextInReverseOrder) {
    // Two onion middlewares: each records "<id>:in" before next() and "<id>:out"
    // after next(). For synchronous downstream chains the router runs the
    // downstream work during next(), so the post-next code observes the handler's
    // effects and unwinds in reverse (outer last).
    auto onion = [](std::string id) {
        return [id = std::move(id)](auto ctx, auto next) {
            auto ensure = [&]() -> std::vector<std::string> * {
                auto *t = ctx->template get_if<std::vector<std::string>>(kTrace);
                if (!t) {
                    ctx->set(kTrace, std::vector<std::string>{});
                    t = ctx->template get_if<std::vector<std::string>>(kTrace);
                }
                return t;
            };
            ensure()->push_back(id + ":in");
            next();
            ensure()->push_back(id + ":out");
        };
    };

    router.use(onion("outer"), "outer");
    router.use(onion("inner"), "inner");

    router.get("/onion", [](auto ctx) {
        auto *t = ctx->template get_if<std::vector<std::string>>(kTrace);
        if (t) {
            t->push_back("handler");
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });

    std::vector<std::string> order;
    capture_trace_on_send(order);
    router.compile();
    router.route(session, create_request(qb::http::method::GET, "/onion"));

    EXPECT_EQ(order, (std::vector<std::string>{"outer:in", "inner:in", "handler", "inner:out", "outer:out"}));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
}

// --------------------------------------------------------------------------
// Short-circuit: middleware completes the response; handler never runs
// --------------------------------------------------------------------------

TEST_F(RoutingMiddlewareTest, MiddlewareShortCircuitSkipsHandler) {
    bool handler_ran = false;

    router.use(
        [](auto ctx, auto /*next*/) {
            ctx->response().status() = qb::http::status::UNAUTHORIZED;
            ctx->response().body()   = "Access denied by middleware";
            ctx->response().set_header("X-ShortCircuit", "true");
            ctx->complete(); // Terminate without calling next().
        },
        "AuthMiddleware");

    router.get("/secret", [&handler_ran](auto ctx) {
        handler_ran              = true;
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "should not be seen";
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/secret"));

    EXPECT_EQ(session->_response.status(), qb::http::status::UNAUTHORIZED);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "Access denied by middleware");
    ASSERT_TRUE(session->_response.has_header("X-ShortCircuit"));
    EXPECT_FALSE(handler_ran) << "handler must not run after short-circuit";
    EXPECT_EQ(session->response_write_count(), 1u);
}

// --------------------------------------------------------------------------
// Context slots flow from middleware to handler
// --------------------------------------------------------------------------

TEST_F(RoutingMiddlewareTest, MiddlewareSetsContextSlotReadByHandler) {
    router.use(
        [](auto ctx, auto next) {
            ctx->set("middleware_flag", true);
            next();
        },
        "FlagSettingMiddleware");

    router.get("/check-flag", [](auto ctx) {
        auto flag = ctx->template get<bool>("middleware_flag");
        if (flag.has_value() && flag.value()) {
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "Flag was set";
        } else {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->response().body()   = "Flag not set";
        }
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/check-flag"));

    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "Flag was set");
}

// --------------------------------------------------------------------------
// Group-scoped middleware applies only inside the group
// --------------------------------------------------------------------------

TEST_F(RoutingMiddlewareTest, GroupMiddlewareScopedToGroupRoutes) {
    auto group = router.group("/api");
    group->use(
        [](auto ctx, auto next) {
            ctx->response().set_header("X-Api-Group", "true");
            next();
        },
        "ApiGroupMiddleware");
    group->get("/status", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "API Status OK";
        ctx->complete();
    });

    router.get("/non-api/status", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "Non-API Status OK";
        ctx->complete();
    });
    router.compile();

    // Inside the group: middleware header present.
    router.route(session, create_request(qb::http::method::GET, "/api/status"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(session->_response.has_header("X-Api-Group"));
    EXPECT_EQ(session->_response.body().template as<std::string>(), "API Status OK");

    session->reset();

    // Outside the group: middleware header absent.
    router.route(session, create_request(qb::http::method::GET, "/non-api/status"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_FALSE(session->_response.has_header("X-Api-Group"));
    EXPECT_EQ(session->_response.body().template as<std::string>(), "Non-API Status OK");
}

// --------------------------------------------------------------------------
// Lifecycle hooks observe pre-routing and pre-response-send
// --------------------------------------------------------------------------

TEST_F(RoutingMiddlewareTest, LifecycleHookSeesPreRoutingAndPreResponseSend) {
    std::vector<qb::http::HookPoint> observed;
    router.add_lifecycle_hook([&observed](auto & /*ctx*/, qb::http::HookPoint point) { observed.push_back(point); });

    router.get("/hooked", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/hooked"));

    ASSERT_FALSE(observed.empty());
    EXPECT_EQ(observed.front(), qb::http::HookPoint::PRE_ROUTING);
    EXPECT_NE(std::find(observed.begin(), observed.end(), qb::http::HookPoint::PRE_RESPONSE_SEND), observed.end());
}

// --------------------------------------------------------------------------
// 405 path still runs global middleware before the built-in 405 handler
// --------------------------------------------------------------------------

TEST_F(RoutingMiddlewareTest, GlobalMiddlewareRunsOnMethodNotAllowedPath) {
    bool mw_ran = false;
    router.use(
        [&mw_ran](auto ctx, auto next) {
            mw_ran = true;
            ctx->response().set_header("X-Global", "seen");
            next();
        },
        "GlobalMiddleware");

    router.get("/only-get", [](auto ctx) {
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });
    router.compile();

    // POST is not registered -> 405; the global prefix middleware still runs.
    router.route(session, create_request(qb::http::method::POST, "/only-get"));

    EXPECT_EQ(session->_response.status(), qb::http::status::METHOD_NOT_ALLOWED);
    EXPECT_TRUE(mw_ran) << "global middleware should run on the 405 chain";
    ASSERT_TRUE(session->_response.has_header("Allow"));
    EXPECT_TRUE(session->_response.has_header("X-Global"));
    EXPECT_EQ(session->response_write_count(), 1u);
}

// --------------------------------------------------------------------------
// Adapter task unit-tests: MiddlewareTask / FunctionalMiddleware
//
// Drives the middleware.h IAsyncTask adapters DIRECTLY (no router), pinning the
// null-argument guards, the catch(...) / no-context exception arms, the
// MiddlewareTask::cancel() delegation (incl. exception-swallow), and name().
// The catch(...) arms (a non-std throw escaping process()) and the
// `ctx == nullptr` log arms are only reachable by hand-driving the adapter.
// --------------------------------------------------------------------------

namespace {

std::shared_ptr<qb::http::Context<MockSession>>
make_bare_mw_ctx(std::shared_ptr<MockSession> sess) {
    return std::make_shared<qb::http::Context<MockSession>>(
        qb::http::Request{}, qb::http::Response{}, sess, [](qb::http::Context<MockSession> &) {},
        std::weak_ptr<qb::http::RouterCore<MockSession>>{});
}

// IMiddleware whose process()/cancel() behaviour is configurable.
class ConfigurableMiddleware : public qb::http::IMiddleware<MockSession> {
public:
    enum class Mode { Continue, ThrowStd, ThrowNonStd };

    explicit ConfigurableMiddleware(Mode mode)
        : _mode(mode) {}

    void
    process(std::shared_ptr<qb::http::Context<MockSession>> ctx) override {
        switch (_mode) {
            case Mode::Continue:
                ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
                break;
            case Mode::ThrowStd:
                throw std::runtime_error("mw std throw");
            case Mode::ThrowNonStd:
                throw 4242;
        }
    }

    void
    cancel() override {
        ++cancel_calls;
        if (_cancel_throws) {
            throw std::runtime_error("mw cancel throw");
        }
    }

    [[nodiscard]] std::string
    name() const override {
        return "ConfigurableMiddleware";
    }

    void
    set_cancel_throws(bool v) {
        _cancel_throws = v;
    }

    int cancel_calls = 0;

private:
    Mode _mode;
    bool _cancel_throws = false;
};

} // namespace

// --- Null-argument constructor guards --------------------------------------

TEST(MiddlewareAdapters, MiddlewareTaskNullPointerThrows) {
    std::shared_ptr<qb::http::IMiddleware<MockSession>> null_mw;
    EXPECT_THROW((qb::http::MiddlewareTask<MockSession>(null_mw)), std::invalid_argument);
}

TEST(MiddlewareAdapters, FunctionalMiddlewareNullHandlerThrows) {
    qb::http::MiddlewareHandlerFn<MockSession> null_fn;
    EXPECT_THROW((qb::http::FunctionalMiddleware<MockSession>(null_fn, "n")), std::invalid_argument);
}

// --- MiddlewareTask::execute exception handling ----------------------------

TEST(MiddlewareAdapters, MiddlewareTaskCatchesStdExceptionAndSets500) {
    auto sess = std::make_shared<MockSession>();
    auto ctx  = make_bare_mw_ctx(sess);
    auto mw   = std::make_shared<ConfigurableMiddleware>(ConfigurableMiddleware::Mode::ThrowStd);
    qb::http::MiddlewareTask<MockSession> task(mw, "StdThrowMw");
    EXPECT_EQ(task.name(), "StdThrowMw");
    task.execute(ctx);
    EXPECT_EQ(ctx->response().status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(ctx->is_completed());
}

TEST(MiddlewareAdapters, MiddlewareTaskCatchesNonStdExceptionAndSets500) {
    auto sess = std::make_shared<MockSession>();
    auto ctx  = make_bare_mw_ctx(sess);
    auto mw   = std::make_shared<ConfigurableMiddleware>(ConfigurableMiddleware::Mode::ThrowNonStd);
    qb::http::MiddlewareTask<MockSession> task(mw, "NonStdThrowMw");
    task.execute(ctx);
    EXPECT_EQ(ctx->response().status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(ctx->is_completed());
}

TEST(MiddlewareAdapters, MiddlewareTaskNullCtxStdExceptionDoesNotCrash) {
    auto mw = std::make_shared<ConfigurableMiddleware>(ConfigurableMiddleware::Mode::ThrowStd);
    qb::http::MiddlewareTask<MockSession> task(mw, "NullCtxStd");
    EXPECT_NO_THROW(task.execute(nullptr));
}

TEST(MiddlewareAdapters, MiddlewareTaskNullCtxNonStdExceptionDoesNotCrash) {
    auto mw = std::make_shared<ConfigurableMiddleware>(ConfigurableMiddleware::Mode::ThrowNonStd);
    qb::http::MiddlewareTask<MockSession> task(mw, "NullCtxNonStd");
    EXPECT_NO_THROW(task.execute(nullptr));
}

// --- MiddlewareTask::cancel delegation -------------------------------------

TEST(MiddlewareAdapters, MiddlewareTaskCancelDelegates) {
    auto mw = std::make_shared<ConfigurableMiddleware>(ConfigurableMiddleware::Mode::Continue);
    qb::http::MiddlewareTask<MockSession> task(mw);
    task.cancel();
    EXPECT_EQ(mw->cancel_calls, 1);
}

TEST(MiddlewareAdapters, MiddlewareTaskCancelSwallowsException) {
    auto mw = std::make_shared<ConfigurableMiddleware>(ConfigurableMiddleware::Mode::Continue);
    mw->set_cancel_throws(true);
    qb::http::MiddlewareTask<MockSession> task(mw);
    EXPECT_NO_THROW(task.cancel());
    EXPECT_EQ(mw->cancel_calls, 1);
}

// --- FunctionalMiddleware::process exception handling ----------------------

TEST(MiddlewareAdapters, FunctionalMiddlewareCatchesStdExceptionAndSets500) {
    auto sess = std::make_shared<MockSession>();
    auto ctx  = make_bare_mw_ctx(sess);
    qb::http::FunctionalMiddleware<MockSession> fm(
        [](std::shared_ptr<qb::http::Context<MockSession>> /*c*/, std::function<void()> /*next*/) { throw std::runtime_error("fm std throw"); },
        "FmStd");
    EXPECT_EQ(fm.name(), "FmStd");
    fm.process(ctx);
    EXPECT_EQ(ctx->response().status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(ctx->is_completed());
}

TEST(MiddlewareAdapters, FunctionalMiddlewareCatchesNonStdExceptionAndSets500) {
    auto sess = std::make_shared<MockSession>();
    auto ctx  = make_bare_mw_ctx(sess);
    qb::http::FunctionalMiddleware<MockSession> fm(
        [](std::shared_ptr<qb::http::Context<MockSession>> /*c*/, std::function<void()> /*next*/) { throw 3.14; }, "FmNonStd");
    fm.process(ctx);
    EXPECT_EQ(ctx->response().status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(ctx->is_completed());
}

TEST(MiddlewareAdapters, FunctionalMiddlewareNextCalledTwiceIgnoresSecond) {
    auto sess = std::make_shared<MockSession>();
    auto ctx  = make_bare_mw_ctx(sess);
    qb::http::FunctionalMiddleware<MockSession> fm(
        [](std::shared_ptr<qb::http::Context<MockSession>> /*c*/, std::function<void()> next) {
            next();
            next(); // second call must be ignored (one-shot guard)
        },
        "FmTwice");
    EXPECT_NO_THROW(fm.process(ctx));
}

TEST(MiddlewareAdapters, FunctionalMiddlewareCancelIsNoop) {
    qb::http::FunctionalMiddleware<MockSession> fm(
        [](std::shared_ptr<qb::http::Context<MockSession>> /*c*/, std::function<void()> next) { next(); }, "FmCancel");
    EXPECT_NO_THROW(fm.cancel());
}

} // namespace

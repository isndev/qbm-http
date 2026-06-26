/**
 * @file qbm/http/tests/unit/routing/router-middleware-chain.cpp
 * @brief Unit tests for the router's middleware-chain execution contract.
 *
 * Exercises the @ref qb::http::Router middleware state machine entirely in-process — ordering,
 * short-circuit (`AsyncTaskResult::COMPLETE`), error propagation into a configured error chain
 * (`AsyncTaskResult::ERROR`), cancellation (`Context::cancel` + `IAsyncTask::cancel`), the
 * not-found chain (`set_not_found_handler`), `FATAL_SPECIAL_HANDLER_ERROR`, and
 * `FunctionalMiddleware`'s "around" `next()` pre/post wrapping (one-shot `next`, post-`next`
 * exception-to-500). Async middleware is made deterministic via a shared
 * @ref qb::http::test::TaskExecutor pump — there is no event loop, socket, or wall-clock here.
 *
 * Execution order is asserted structurally against a `std::vector<std::string>` carried on the
 * session (no `;`-joined string markers).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <qb/uuid.h>

#include "../../shared/router_test_support.h"

using qb::http::test::TaskExecutor;

namespace {

/**
 * @brief Capturing session carrying an ordered execution trace (vector, not string markers).
 *
 * Satisfies the router's session concept (`operator<<`, `id()`) and additionally records the order
 * in which middlewares/handlers run so tests assert against an expected `std::vector<std::string>`.
 * Enforces a single finalization between resets (a second `operator<<` throws) — surfacing any
 * accidental double-finalization the router must never produce.
 */
struct TraceSession {
    qb::http::Response       _response;
    qb::uuid                 _session_id  = qb::generate_random_uuid();
    unsigned int             _write_count = 0;
    std::vector<std::string> _trace;
    bool                     _final_handler_called = false;

    [[nodiscard]] qb::http::Response &
    get_response_ref() {
        return _response;
    }

    TraceSession &
    operator<<(const qb::http::Response &response) {
        _response = response;
        if (++_write_count > 1) {
            throw std::runtime_error("TraceSession::operator<< called more than once between resets");
        }
        return *this;
    }

    [[nodiscard]] const qb::uuid &
    id() const noexcept {
        return _session_id;
    }

    void
    trace(const std::string &id) {
        _trace.push_back(id);
    }

    [[nodiscard]] const std::vector<std::string> &
    trace() const noexcept {
        return _trace;
    }

    [[nodiscard]] unsigned int
    write_count() const noexcept {
        return _write_count;
    }

    void
    reset() {
        _response             = qb::http::Response();
        _write_count          = 0;
        _final_handler_called = false;
        _trace.clear();
    }
};

// --- Middleware helpers (chain-shape specific; trace into the session vector) ----------------

/** @brief Base: carries an id, name(), and a no-op cancel(). */
class TraceMiddleware : public qb::http::IMiddleware<TraceSession> {
public:
    explicit TraceMiddleware(std::string id)
        : _id(std::move(id)) {}

    [[nodiscard]] std::string
    name() const override {
        return _id;
    }

    void
    cancel() noexcept override {}

protected:
    std::string _id;
};

/** @brief Records its id and continues the chain synchronously. */
class SyncAppendingMiddleware : public TraceMiddleware {
public:
    using TraceMiddleware::TraceMiddleware;

    void
    process(std::shared_ptr<qb::http::Context<TraceSession>> ctx) override {
        if (ctx->session()) {
            ctx->session()->trace(_id);
        }
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }
};

/** @brief Records `<id>_handle` synchronously, then `<id>_task` + CONTINUE via the pump. */
class AsyncAppendingMiddleware : public TraceMiddleware {
public:
    AsyncAppendingMiddleware(std::string id, TaskExecutor *executor)
        : TraceMiddleware(std::move(id))
        , _executor(executor) {}

    void
    process(std::shared_ptr<qb::http::Context<TraceSession>> ctx) override {
        if (ctx->session()) {
            ctx->session()->trace(_id + "_handle");
        }
        const std::string id = _id;
        _executor->addTask([ctx, id]() {
            if (ctx->is_cancelled()) {
                return; // Context is finalizing; do not advance.
            }
            if (ctx->session()) {
                ctx->session()->trace(id + "_task");
            }
            ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
        });
    }

protected:
    TaskExecutor *_executor;
};

/** @brief Records its id and short-circuits the chain with COMPLETE at a chosen status/body. */
class SyncShortCircuitMiddleware : public TraceMiddleware {
public:
    SyncShortCircuitMiddleware(std::string id, qb::http::status status)
        : TraceMiddleware(std::move(id))
        , _status(status) {}

    void
    process(std::shared_ptr<qb::http::Context<TraceSession>> ctx) override {
        if (ctx->session()) {
            ctx->session()->trace(_id);
        }
        ctx->response().status() = _status;
        ctx->response().body()   = _id + " short-circuited";
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    }

private:
    qb::http::status _status;
};

/** @brief Sync middleware whose handle phase invokes a test hook (used to cancel mid-handle). */
class HookableSyncMiddleware : public TraceMiddleware {
public:
    using Hook = std::function<void(std::shared_ptr<qb::http::Context<TraceSession>>)>;

    explicit HookableSyncMiddleware(std::string id)
        : TraceMiddleware(std::move(id)) {}

    void
    process(std::shared_ptr<qb::http::Context<TraceSession>> ctx) override {
        if (ctx->session()) {
            ctx->session()->trace(_id);
        }
        if (_hook) {
            _hook(ctx);
        }
        if (!ctx->is_cancelled()) {
            ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
        }
        // If the hook cancelled, Context::cancel already finalized — do not complete again.
    }

    void
    cancel() noexcept override {
        cancel_called = true;
    }

    bool cancel_called = false;
    Hook _hook;
};

/** @brief Async middleware whose cancel() sets a flag; used for cancel-before-task-finishes. */
class CancellableAsyncMiddleware : public AsyncAppendingMiddleware {
public:
    using AsyncAppendingMiddleware::AsyncAppendingMiddleware;

    void
    cancel() noexcept override {
        cancel_called = true;
    }

    bool cancel_called = false;
};

/** @brief A simple error-triggering middleware (records id, completes ERROR). */
class ErrorTriggerMiddleware : public TraceMiddleware {
public:
    using TraceMiddleware::TraceMiddleware;

    void
    process(std::shared_ptr<qb::http::Context<TraceSession>> ctx) override {
        if (ctx->session()) {
            ctx->session()->trace(_id);
        }
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    }
};

/** @brief Builds an HTTP/1.1 request from a method + path (TraceSession-local helper). */
qb::http::Request
make_request(qb::http::method method_val, const std::string &path) {
    qb::http::Request req;
    req.method()      = method_val;
    req.uri()         = qb::io::uri(path);
    req.major_version = 1;
    req.minor_version = 1;
    return req;
}

/** @brief Final handler that records its id, marks the session, sets 200 + body, completes. */
qb::http::RouteHandlerFn<TraceSession>
final_handler(const std::string &id = "final_handler") {
    return [id](std::shared_ptr<qb::http::Context<TraceSession>> ctx) {
        if (ctx->session()) {
            ctx->session()->trace(id);
            ctx->session()->_final_handler_called = true;
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = id + " executed";
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    };
}

/** @brief Builds a single-task error chain that records `id` and finalizes with the given status/body. */
std::vector<std::shared_ptr<qb::http::IAsyncTask<TraceSession>>>
make_error_chain(const std::string &id, qb::http::status status, const std::string &body) {
    return {std::make_shared<qb::http::MiddlewareTask<TraceSession>>(
        std::make_shared<qb::http::FunctionalMiddleware<TraceSession>>(
            [id, status, body](auto ctx, auto /*next*/) {
                if (ctx->session()) {
                    ctx->session()->trace(id);
                }
                ctx->response().status() = status;
                ctx->response().body()   = body;
                ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
            },
            id))};
}

} // namespace

// --- Fixture --------------------------------------------------------------------------------

class RouterMiddlewareChainTest : public ::testing::Test {
protected:
    std::shared_ptr<TraceSession> session;
    qb::http::Router<TraceSession> router;
    TaskExecutor                   executor;

    void
    SetUp() override {
        session = std::make_shared<TraceSession>();
    }

    void
    drain() {
        while (executor.hasTasks()) {
            executor.processAllTasks();
        }
    }

    using Trace = std::vector<std::string>;
};

// --- Empty chain ----------------------------------------------------------------------------

TEST_F(RouterMiddlewareChainTest, EmptyChainReachesHandlerDirectly) {
    router.get("/test", final_handler());
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/test"));

    EXPECT_EQ(session->trace(), (Trace{"final_handler"}));
    EXPECT_TRUE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->write_count(), 1u);
}

// --- Synchronous ordering -------------------------------------------------------------------

TEST_F(RouterMiddlewareChainTest, SingleSyncMiddleware) {
    router.use(std::make_shared<SyncAppendingMiddleware>("mw1"));
    router.get("/test", final_handler());
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/test"));

    EXPECT_EQ(session->trace(), (Trace{"mw1", "final_handler"}));
    EXPECT_TRUE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
}

TEST_F(RouterMiddlewareChainTest, MultipleSyncMiddlewareRunInRegistrationOrder) {
    router.use(std::make_shared<SyncAppendingMiddleware>("mw1"));
    router.use(std::make_shared<SyncAppendingMiddleware>("mw2"));
    router.use(std::make_shared<SyncAppendingMiddleware>("mw3"));
    router.get("/test", final_handler());
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/test"));

    EXPECT_EQ(session->trace(), (Trace{"mw1", "mw2", "mw3", "final_handler"}));
    EXPECT_TRUE(session->_final_handler_called);
}

TEST_F(RouterMiddlewareChainTest, SyncMiddlewareShortCircuitStopsChain) {
    router.use(std::make_shared<SyncAppendingMiddleware>("mw1"));
    router.use(std::make_shared<SyncShortCircuitMiddleware>("mw_sc", qb::http::status::ACCEPTED));
    router.use(std::make_shared<SyncAppendingMiddleware>("mw3_never"));
    router.get("/test", final_handler("handler_never"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/test"));

    EXPECT_EQ(session->trace(), (Trace{"mw1", "mw_sc"}));
    EXPECT_FALSE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::ACCEPTED);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "mw_sc short-circuited");
}

TEST_F(RouterMiddlewareChainTest, SyncMiddlewareErrorRoutesToErrorChain) {
    router.use(std::make_shared<SyncAppendingMiddleware>("mw1"));
    router.use(std::make_shared<ErrorTriggerMiddleware>("mw_err"));
    router.use(std::make_shared<SyncAppendingMiddleware>("mw3_never"));
    router.get("/test", final_handler("handler_never"));
    router.set_error_task_chain(
        make_error_chain("error_handler", qb::http::status::INTERNAL_SERVER_ERROR, "handled by error chain"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/test"));

    EXPECT_EQ(session->trace(), (Trace{"mw1", "mw_err", "error_handler"}));
    EXPECT_FALSE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "handled by error chain");
}

// --- Asynchronous ordering ------------------------------------------------------------------

TEST_F(RouterMiddlewareChainTest, SingleAsyncMiddleware) {
    router.use(std::make_shared<AsyncAppendingMiddleware>("amw1", &executor));
    router.get("/test", final_handler());
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/test"));
    EXPECT_EQ(session->trace(), (Trace{"amw1_handle"}));
    EXPECT_FALSE(session->_final_handler_called);

    drain();
    EXPECT_EQ(session->trace(), (Trace{"amw1_handle", "amw1_task", "final_handler"}));
    EXPECT_TRUE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
}

TEST_F(RouterMiddlewareChainTest, MixedSyncAndAsyncMiddlewareOrder) {
    router.use(std::make_shared<SyncAppendingMiddleware>("sync1"));
    router.use(std::make_shared<AsyncAppendingMiddleware>("async1", &executor));
    router.use(std::make_shared<SyncAppendingMiddleware>("sync2"));
    router.get("/test", final_handler());
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/test"));
    EXPECT_EQ(session->trace(), (Trace{"sync1", "async1_handle"}));

    drain();
    EXPECT_EQ(session->trace(), (Trace{"sync1", "async1_handle", "async1_task", "sync2", "final_handler"}));
    EXPECT_TRUE(session->_final_handler_called);
}

// --- Group middleware -----------------------------------------------------------------------

TEST_F(RouterMiddlewareChainTest, RouterThenGroupMiddlewareOrder) {
    router.use(std::make_shared<SyncAppendingMiddleware>("router_mw"));
    auto group = router.group("/group");
    group->use(std::make_shared<SyncAppendingMiddleware>("group_mw"));
    group->get("/test", final_handler());
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/group/test"));

    EXPECT_EQ(session->trace(), (Trace{"router_mw", "group_mw", "final_handler"}));
}

TEST_F(RouterMiddlewareChainTest, GroupMiddlewareIsolatedFromOtherRoutes) {
    router.use(std::make_shared<SyncAppendingMiddleware>("router_mw"));
    auto group = router.group("/group");
    group->use(std::make_shared<SyncAppendingMiddleware>("group_mw"));
    group->get("/test", final_handler("group_handler"));
    router.get("/other", final_handler("other_handler"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/group/test"));
    EXPECT_EQ(session->trace(), (Trace{"router_mw", "group_mw", "group_handler"}));

    session->reset();

    router.route(session, make_request(qb::http::method::GET, "/other"));
    EXPECT_EQ(session->trace(), (Trace{"router_mw", "other_handler"}));
}

TEST_F(RouterMiddlewareChainTest, NestedGroupMiddlewareOrder) {
    router.use(std::make_shared<SyncAppendingMiddleware>("router_mw"));
    auto group1 = router.group("/g1");
    group1->use(std::make_shared<SyncAppendingMiddleware>("g1_mw"));
    auto group2 = group1->group("/g2");
    group2->use(std::make_shared<SyncAppendingMiddleware>("g2_mw"));
    group2->get("/test", final_handler("g2_handler"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/g1/g2/test"));

    EXPECT_EQ(session->trace(), (Trace{"router_mw", "g1_mw", "g2_mw", "g2_handler"}));
    EXPECT_TRUE(session->_final_handler_called);
}

TEST_F(RouterMiddlewareChainTest, NestedGroupAsyncMiddlewareOrder) {
    router.use(std::make_shared<SyncAppendingMiddleware>("router_sync"));
    auto group1 = router.group("/g1");
    group1->use(std::make_shared<AsyncAppendingMiddleware>("g1_async", &executor));
    auto group2 = group1->group("/g2");
    group2->use(std::make_shared<SyncAppendingMiddleware>("g2_sync"));
    group2->get("/test", final_handler("g2_handler"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/g1/g2/test"));
    EXPECT_EQ(session->trace(), (Trace{"router_sync", "g1_async_handle"}));

    drain();
    EXPECT_EQ(session->trace(), (Trace{"router_sync", "g1_async_handle", "g1_async_task", "g2_sync", "g2_handler"}));
    EXPECT_TRUE(session->_final_handler_called);
}

// --- Not-found chain ------------------------------------------------------------------------

TEST_F(RouterMiddlewareChainTest, DefaultNotFoundHandler) {
    router.get("/exists", final_handler("handler_exists"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/missing"));
    drain();

    EXPECT_EQ(session->_response.status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "404 Not Found (Default)");
}

TEST_F(RouterMiddlewareChainTest, CustomNotFoundHandler) {
    router.set_not_found_handler([](auto ctx) {
        if (ctx->session()) {
            ctx->session()->trace("custom_404");
        }
        ctx->response().status() = qb::http::status::NOT_FOUND;
        ctx->response().body()   = "Custom 404 Page";
        ctx->complete();
    });
    router.get("/exists", final_handler("handler_exists"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/missing"));
    drain();

    EXPECT_EQ(session->_response.status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "Custom 404 Page");
    EXPECT_EQ(session->trace(), (Trace{"custom_404"}));
}

TEST_F(RouterMiddlewareChainTest, GlobalMiddlewareRunsBeforeCustomNotFoundHandler) {
    router.use(std::make_shared<SyncAppendingMiddleware>("global_mw"));
    router.set_not_found_handler([](auto ctx) {
        if (ctx->session()) {
            ctx->session()->trace("custom_404");
        }
        ctx->response().status() = qb::http::status::NOT_FOUND;
        ctx->response().body()   = "Custom 404 With Global MW";
        ctx->complete();
    });
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/missing"));
    drain();

    EXPECT_EQ(session->_response.status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(session->trace(), (Trace{"global_mw", "custom_404"}));
}

// --- Fatal-error contracts (canonical 500, pinned body) -------------------------------------

TEST_F(RouterMiddlewareChainTest, ErrorInCustomNotFoundHandlerIsFatal) {
    router.set_not_found_handler([](auto ctx) {
        if (ctx->session()) {
            ctx->session()->trace("custom_404_fatal");
        }
        ctx->complete(qb::http::AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR);
    });
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/missing"));
    drain();

    EXPECT_EQ(session->trace(), (Trace{"custom_404_fatal"}));
    EXPECT_EQ(session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    // Canonical contract: FATAL_SPECIAL_HANDLER_ERROR sets status 500 and finalizes the response
    // the handler left behind (no auto-filled body); the handler set none, so the body is empty.
    EXPECT_TRUE(session->_response.body().template as<std::string>().empty());
    EXPECT_EQ(session->write_count(), 1u) << "Fatal special-handler error finalizes exactly once.";
}

TEST_F(RouterMiddlewareChainTest, ErrorInUserErrorHandlerIsFatal) {
    router.use(std::make_shared<ErrorTriggerMiddleware>("trigger_initial_error"));
    router.set_error_task_chain(std::vector<std::shared_ptr<qb::http::IAsyncTask<TraceSession>>>{
        std::make_shared<qb::http::MiddlewareTask<TraceSession>>(
            std::make_shared<qb::http::FunctionalMiddleware<TraceSession>>(
                [](auto ctx, auto /*next*/) {
                    if (ctx->session()) {
                        ctx->session()->trace("faulty_error_handler");
                    }
                    ctx->complete(qb::http::AsyncTaskResult::ERROR); // error within the error chain
                },
                "faulty_error_handler"))});
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/test"));
    drain();

    EXPECT_EQ(session->trace(), (Trace{"trigger_initial_error", "faulty_error_handler"}));
    EXPECT_EQ(session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    // An ERROR raised while already in the ERROR_CHAIN phase forces 500 and finalizes (no loop);
    // the faulty handler set no body, so the canonical result is an empty body.
    EXPECT_TRUE(session->_response.body().template as<std::string>().empty());
    EXPECT_EQ(session->write_count(), 1u) << "Error-in-error-handler must finalize exactly once (no loop).";
}

TEST_F(RouterMiddlewareChainTest, ErrorInGlobalMiddlewareDuringNotFoundRoutesToErrorChain) {
    router.use(std::make_shared<ErrorTriggerMiddleware>("global_error_mw"));
    router.set_not_found_handler([](auto ctx) {
        if (ctx->session()) {
            ctx->session()->trace("custom_404_not_reached");
        }
        ctx->complete();
    });
    router.set_error_task_chain(
        make_error_chain("main_error_handler", qb::http::status::INTERNAL_SERVER_ERROR, "caught by main error handler"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/missing"));
    drain();

    EXPECT_EQ(session->trace(), (Trace{"global_error_mw", "main_error_handler"}));
    EXPECT_EQ(session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "caught by main error handler");
}

// --- Cancellation ---------------------------------------------------------------------------

TEST_F(RouterMiddlewareChainTest, CancellationDuringSyncGlobalMiddleware) {
    auto mw1 = std::make_shared<HookableSyncMiddleware>("mw1");
    mw1->_hook = [](std::shared_ptr<qb::http::Context<TraceSession>> ctx) { ctx->cancel("cancel during mw1 handle"); };
    router.use(mw1);
    router.use(std::make_shared<SyncAppendingMiddleware>("mw2_never"));
    router.get("/test", final_handler("handler_never"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/test"));
    drain();

    EXPECT_TRUE(mw1->cancel_called);
    EXPECT_EQ(session->trace(), (Trace{"mw1"}));
    EXPECT_FALSE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(session->write_count(), 1u);
}

TEST_F(RouterMiddlewareChainTest, CancellationDuringAsyncGlobalMiddlewareBeforeTaskFinishes) {
    auto amw = std::make_shared<CancellableAsyncMiddleware>("async_mw", &executor);
    router.use(amw);
    router.use(std::make_shared<SyncAppendingMiddleware>("mw2_never"));
    router.get("/test", final_handler("handler_never"));
    router.compile();

    auto ctx = router.route(session, make_request(qb::http::method::GET, "/test"));
    ASSERT_NE(ctx, nullptr);

    EXPECT_EQ(session->trace(), (Trace{"async_mw_handle"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    ctx->cancel("cancel before async task completes");
    drain();

    EXPECT_TRUE(amw->cancel_called);
    EXPECT_EQ(session->trace(), (Trace{"async_mw_handle"})); // task observed cancellation, did not advance
    EXPECT_FALSE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_FALSE(executor.hasTasks());
    EXPECT_EQ(session->write_count(), 1u);
}

TEST_F(RouterMiddlewareChainTest, CancellationDuringSyncGroupMiddleware) {
    auto group    = router.group("/group");
    auto group_mw = std::make_shared<HookableSyncMiddleware>("group_mw");
    group_mw->_hook = [](std::shared_ptr<qb::http::Context<TraceSession>> ctx) { ctx->cancel("cancel during group_mw"); };
    group->use(group_mw);
    group->use(std::make_shared<SyncAppendingMiddleware>("group_mw2_never"));
    group->get("/test", final_handler("handler_never"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/group/test"));
    drain();

    EXPECT_TRUE(group_mw->cancel_called);
    EXPECT_EQ(session->trace(), (Trace{"group_mw"}));
    EXPECT_FALSE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
}

TEST_F(RouterMiddlewareChainTest, CancellationDuringAsyncTaskBody) {
    // The async middleware's deferred task body cancels the context, then attempts CONTINUE; the
    // stale CONTINUE must be absorbed (the context already finalized with 503).
    router.use(std::make_shared<qb::http::FunctionalMiddleware<TraceSession>>(
        [exec = &executor](auto ctx, auto /*next*/) {
            if (ctx->session()) {
                ctx->session()->trace("body_handle");
            }
            exec->addTask([ctx]() {
                if (ctx->session()) {
                    ctx->session()->trace("body_task");
                }
                ctx->cancel("cancel inside async task body");
                ctx->complete(qb::http::AsyncTaskResult::CONTINUE); // stale; must be a no-op
            });
        },
        "BodyCancellingMiddleware"));
    router.use(std::make_shared<SyncAppendingMiddleware>("mw2_never"));
    router.get("/test", final_handler("handler_never"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/test"));
    EXPECT_EQ(session->trace(), (Trace{"body_handle"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    drain();

    EXPECT_EQ(session->trace(), (Trace{"body_handle", "body_task"}));
    EXPECT_FALSE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(session->write_count(), 1u) << "cancel() finalizes once; the trailing CONTINUE must not re-finalize.";
}

TEST_F(RouterMiddlewareChainTest, CancellationDuringGlobalMiddlewareInNotFoundChain) {
    auto global_mw = std::make_shared<HookableSyncMiddleware>("global_mw_404");
    global_mw->_hook = [](std::shared_ptr<qb::http::Context<TraceSession>> ctx) { ctx->cancel("cancel in 404 chain"); };
    router.use(global_mw);
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/missing"));
    drain();

    EXPECT_TRUE(global_mw->cancel_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(session->trace(), (Trace{"global_mw_404"}));
}

// --- Double-complete idempotency ------------------------------------------------------------

TEST_F(RouterMiddlewareChainTest, DoubleCompleteIsIdempotent) {
    // A route handler that completes COMPLETE twice must finalize exactly once and the first result
    // must win. TraceSession throws on a second write, so a non-idempotent complete() would surface
    // as that throw. (A route handler runs without FunctionalMiddleware's finalization-deferral
    // scope, so the first complete() finalizes immediately and the second is a true no-op.)
    router.use(std::make_shared<SyncAppendingMiddleware>("mw1"));
    router.get("/test", [](std::shared_ptr<qb::http::Context<TraceSession>> ctx) {
        if (ctx->session()) {
            ctx->session()->trace("handler");
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "first";
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        // Already Finalised -> these mutations and the second complete() are ignored.
        ctx->response().status() = qb::http::status::ACCEPTED;
        ctx->response().body()   = "second";
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    });
    router.compile();

    EXPECT_NO_THROW(router.route(session, make_request(qb::http::method::GET, "/test")));

    EXPECT_EQ(session->trace(), (Trace{"mw1", "handler"}));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "first");
    EXPECT_EQ(session->write_count(), 1u);
}

// --- FunctionalMiddleware "around" semantics ------------------------------------------------

TEST_F(RouterMiddlewareChainTest, FunctionalMiddlewareAroundBehavior) {
    router.use(std::make_shared<qb::http::FunctionalMiddleware<TraceSession>>(
        [](auto ctx, auto next_fn) {
            ctx->request().set_header("X-Pre-Process", "around");
            if (ctx->session()) {
                ctx->session()->trace("around_pre");
            }
            next_fn();
            ctx->response().set_header("X-Post-Process", "around");
            if (ctx->session()) {
                ctx->session()->trace("around_post");
            }
        },
        "AroundMiddleware"));
    router.use(std::make_shared<SyncAppendingMiddleware>("inner_mw"));
    router.get("/around", [](std::shared_ptr<qb::http::Context<TraceSession>> ctx) {
        EXPECT_EQ(ctx->request().header("X-Pre-Process"), "around");
        EXPECT_TRUE(ctx->response().header("X-Post-Process").empty()) << "Post-next mutation must not be visible yet.";
        if (ctx->session()) {
            ctx->session()->trace("handler");
            ctx->session()->_final_handler_called = true;
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    });
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/around"));

    EXPECT_TRUE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->trace(), (Trace{"around_pre", "inner_mw", "handler", "around_post"}));
    // Synchronous downstream completion is deferred until the around-MW returns, so the post-next
    // response mutation lands in the finalized response.
    EXPECT_EQ(session->_response.header("X-Post-Process"), "around");
}

TEST_F(RouterMiddlewareChainTest, FunctionalMiddlewarePostNextThrowBecomesError) {
    router.use(std::make_shared<qb::http::FunctionalMiddleware<TraceSession>>(
        [](auto ctx, auto next_fn) {
            if (ctx->session()) {
                ctx->session()->trace("pre");
            }
            next_fn();
            if (ctx->session()) {
                ctx->session()->trace("post");
            }
            throw std::runtime_error("post-next failure");
        },
        "PostNextThrowMiddleware"));
    router.get("/post-throws", [](std::shared_ptr<qb::http::Context<TraceSession>> ctx) {
        if (ctx->session()) {
            ctx->session()->trace("handler");
            ctx->session()->_final_handler_called = true;
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body()   = "ok before throw";
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    });
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/post-throws"));

    EXPECT_TRUE(session->_final_handler_called);
    EXPECT_EQ(session->trace(), (Trace{"pre", "handler", "post"}));
    EXPECT_EQ(session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "Internal Server Error");
}

TEST_F(RouterMiddlewareChainTest, FunctionalMiddlewareConditionalEarlyExit) {
    router.use(std::make_shared<qb::http::FunctionalMiddleware<TraceSession>>(
        [](auto ctx, auto next_fn) {
            if (ctx->request().has_header("X-Stop-Early")) {
                ctx->response().status() = qb::http::status::IM_A_TEAPOT;
                ctx->response().body()   = "stopped early";
                ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
            } else {
                next_fn();
            }
        },
        "ConditionalMiddleware"));
    router.use(std::make_shared<SyncAppendingMiddleware>("after_conditional"));
    router.get("/conditional", final_handler("conditional_handler"));
    router.compile();

    // Case 1: short-circuits.
    qb::http::Request stop = make_request(qb::http::method::GET, "/conditional");
    stop.set_header("X-Stop-Early", "true");
    router.route(session, std::move(stop));
    EXPECT_EQ(session->_response.status(), qb::http::status::IM_A_TEAPOT);
    EXPECT_EQ(session->_response.body().template as<std::string>(), "stopped early");
    EXPECT_FALSE(session->_final_handler_called);
    EXPECT_TRUE(session->trace().empty());

    // Case 2: continues.
    session->reset();
    router.route(session, make_request(qb::http::method::GET, "/conditional"));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_TRUE(session->_final_handler_called);
    EXPECT_EQ(session->trace(), (Trace{"after_conditional", "conditional_handler"}));
}

TEST_F(RouterMiddlewareChainTest, FunctionalMiddlewareNextIsOneShotEvenWhenCalledTwice) {
    router.use(std::make_shared<qb::http::FunctionalMiddleware<TraceSession>>(
        [](auto ctx, auto next_fn) {
            if (ctx->session()) {
                ctx->session()->trace("double_next_pre");
            }
            next_fn();
            next_fn(); // must be ignored
            if (ctx->session()) {
                ctx->session()->trace("double_next_post");
            }
        },
        "DoubleNextMiddleware"));
    router.use(std::make_shared<AsyncAppendingMiddleware>("async_mw", &executor));
    router.get("/double-next", final_handler("double_next_handler"));
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/double-next"));

    EXPECT_EQ(session->trace(), (Trace{"double_next_pre", "async_mw_handle", "double_next_post"}));
    EXPECT_FALSE(session->_final_handler_called);
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    drain();

    EXPECT_EQ(session->trace(),
              (Trace{"double_next_pre", "async_mw_handle", "double_next_post", "async_mw_task", "double_next_handler"}));
    EXPECT_TRUE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
}

TEST_F(RouterMiddlewareChainTest, MiddlewareStateSharingViaRequestHeaders) {
    router.use(std::make_shared<qb::http::FunctionalMiddleware<TraceSession>>(
        [](auto ctx, auto next_fn) {
            ctx->request().set_header("X-From-A", "hello");
            next_fn();
        },
        "MiddlewareA"));
    router.use(std::make_shared<qb::http::FunctionalMiddleware<TraceSession>>(
        [](auto ctx, auto next_fn) {
            if (ctx->request().header("X-From-A") == "hello") {
                ctx->request().set_header("X-From-B", "confirmed");
                if (ctx->session()) {
                    ctx->session()->trace("B_saw_A");
                }
            }
            next_fn();
        },
        "MiddlewareB"));
    router.get("/sharing", [](std::shared_ptr<qb::http::Context<TraceSession>> ctx) {
        EXPECT_EQ(ctx->request().header("X-From-B"), "confirmed");
        if (ctx->session()) {
            ctx->session()->trace("handler");
            ctx->session()->_final_handler_called = true;
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    });
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/sharing"));

    EXPECT_TRUE(session->_final_handler_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->trace(), (Trace{"B_saw_A", "handler"}));
}

// --- Error handling chain cancellation ------------------------------------------------------

TEST_F(RouterMiddlewareChainTest, CancellationDuringErrorHandlingMiddleware) {
    router.use(std::make_shared<ErrorTriggerMiddleware>("error_trigger"));

    auto cancellable_error_mw = std::make_shared<HookableSyncMiddleware>("cancellable_error_mw");
    cancellable_error_mw->_hook =
        [](std::shared_ptr<qb::http::Context<TraceSession>> ctx) { ctx->cancel("cancel during error handling"); };
    router.set_error_task_chain({std::make_shared<qb::http::MiddlewareTask<TraceSession>>(cancellable_error_mw)});
    router.compile();

    router.route(session, make_request(qb::http::method::GET, "/trigger_error"));
    drain();

    EXPECT_TRUE(cancellable_error_mw->cancel_called);
    EXPECT_EQ(session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(session->trace(), (Trace{"error_trigger", "cancellable_error_mw"}));
    EXPECT_EQ(session->write_count(), 1u);
}

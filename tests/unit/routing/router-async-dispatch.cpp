/**
 * @file qbm/http/tests/unit/routing/router-async-dispatch.cpp
 * @brief Unit tests for the router's deferred-task (asynchronous) dispatch state machine.
 *
 * The qb-http routing pipeline is fully asynchronous: a middleware or custom route may
 * defer its `ctx->complete(...)` to a later turn of the event loop. These tests drive
 * that machine deterministically by substituting a manual @ref qb::http::test::TaskExecutor
 * pump for the real loop, so each "tick" of the async chain is steppable from the test body.
 *
 * Execution order is recorded structurally into a shared `std::vector<std::string>` via the
 * shared trace-middleware family (no fragile `;`-joined string markers). A custom async route
 * (@ref OrderTracingAsyncRoute below) likewise records into that vector.
 *
 * Coverage: simple deferred dispatch across HTTP methods (param table), path-parameter capture,
 * sync+async middleware interplay, async-handler error signalling, async-middleware short-circuit
 * (COMPLETE), the full mixed sync-MW / async-MW / async-handler chain, async-MW error aborting the
 * chain, route-group async middleware, 404 with a global async middleware, async lambda handlers,
 * the cancellation matrix (before any task / after async MW / on an already-error context / during
 * the deferred task body), and `complete()` double-call idempotency.
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

#include "../../shared/mock_session.h"
#include "../../shared/router_test_support.h"

using qb::http::test::AsyncTraceMiddleware;
using qb::http::test::create_request;
using qb::http::test::MockSession;
using qb::http::test::SyncTraceMiddleware;
using qb::http::test::TaskExecutor;

namespace {

/// Shared sink the helpers publish the live context into, so cancellation tests can reach it
/// without coupling the canonical shared MockSession to a context-capture field.
using ContextSink = std::shared_ptr<std::weak_ptr<qb::http::Context<MockSession>>>;

/**
 * @brief Custom route that records its id into a shared order log and defers completion.
 *
 * On `process()` it appends `"<id>_handle"` immediately (the synchronous phase) and publishes the
 * live context into an optional @ref ContextSink for cancellation tests. It then enqueues a deferred
 * continuation onto the supplied @ref TaskExecutor. When that continuation runs it either:
 *   - observes cancellation (records `"<id>_cancelled"` and returns without completing), or
 *   - records `"<id>_task"`, snapshots path params, sets the status, and completes COMPLETE/ERROR.
 *
 * The `signal_error`/`auto_complete` flags model a final handler, an error-signalling handler, or a
 * handler whose task body runs but defers the `complete()` to an external trigger.
 */
class OrderTracingAsyncRoute : public qb::http::ICustomRoute<MockSession> {
public:
    OrderTracingAsyncRoute(std::string id, std::shared_ptr<std::vector<std::string>> order_log, TaskExecutor *executor,
                           bool signal_error = false, bool auto_complete = true, ContextSink sink = nullptr)
        : _id(std::move(id))
        , _order_log(std::move(order_log))
        , _executor(executor)
        , _signal_error(signal_error)
        , _auto_complete(auto_complete)
        , _sink(std::move(sink)) {}

    void
    process(std::shared_ptr<qb::http::Context<MockSession>> ctx) override {
        if (_sink) {
            *_sink = ctx;
        }
        record(_id + "_handle");

        const std::string id            = _id;
        auto              order_log     = _order_log;
        const bool        signal_error  = _signal_error;
        const bool        auto_complete = _auto_complete;
        _executor->addTask([ctx, id, order_log, signal_error, auto_complete]() {
            if (ctx->is_cancelled()) {
                if (order_log) {
                    order_log->push_back(id + "_cancelled");
                }
                return;
            }
            if (order_log) {
                order_log->push_back(id + "_task");
            }
            if (auto session = ctx->session()) {
                session->_handler_executed = true;
                session->_handler_id       = id;
                session->_captured_params  = ctx->path_parameters();
            }
            if (!auto_complete) {
                return; // Task body ran; an external trigger will complete the context.
            }
            if (signal_error) {
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->complete(qb::http::AsyncTaskResult::ERROR);
            } else {
                ctx->response().status() = qb::http::status::OK;
                ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
            }
        });
    }

    [[nodiscard]] std::string
    name() const override {
        return _id;
    }

    void
    cancel() override {}

private:
    void
    record(const std::string &marker) const {
        if (_order_log) {
            _order_log->push_back(marker);
        }
    }

    std::string                               _id;
    std::shared_ptr<std::vector<std::string>> _order_log;
    TaskExecutor                             *_executor;
    bool                                      _signal_error;
    bool                                      _auto_complete;
    ContextSink                               _sink;
};

/**
 * @brief Async middleware that records a *trailing* marker after CONTINUE (for chain-abort tests).
 *
 * Distinct from the shared @ref AsyncTraceMiddleware which only records on entry: this variant can
 * be configured to signal ERROR (aborting the chain) or to short-circuit with COMPLETE, recording
 * its task-phase marker into the shared log so the test can assert exactly what ran.
 */
class AsyncResultMiddleware : public qb::http::IMiddleware<MockSession> {
public:
    AsyncResultMiddleware(std::string id, std::shared_ptr<std::vector<std::string>> order_log, TaskExecutor *executor,
                          qb::http::AsyncTaskResult result, qb::http::status status)
        : _id(std::move(id))
        , _order_log(std::move(order_log))
        , _executor(executor)
        , _result(result)
        , _status(status) {}

    void
    process(std::shared_ptr<qb::http::Context<MockSession>> ctx) override {
        if (_order_log) {
            _order_log->push_back(_id + "_handle");
        }
        const std::string               id        = _id;
        auto                            order_log = _order_log;
        const qb::http::AsyncTaskResult result    = _result;
        const qb::http::status          status    = _status;
        _executor->addTask([ctx, id, order_log, result, status]() {
            if (ctx->is_cancelled()) {
                if (order_log) {
                    order_log->push_back(id + "_cancelled");
                }
                return;
            }
            if (order_log) {
                order_log->push_back(id + "_task");
            }
            ctx->response().status() = status;
            ctx->complete(result);
        });
    }

    [[nodiscard]] std::string
    name() const override {
        return _id;
    }

    void
    cancel() override {}

private:
    std::string                               _id;
    std::shared_ptr<std::vector<std::string>> _order_log;
    TaskExecutor                             *_executor;
    qb::http::AsyncTaskResult                 _result;
    qb::http::status                          _status;
};

} // namespace

// --- Fixture --------------------------------------------------------------------------------

class RouterAsyncDispatchTest : public ::testing::Test {
protected:
    std::shared_ptr<MockSession>              session;
    qb::http::Router<MockSession>             router;
    TaskExecutor                              executor;
    std::shared_ptr<std::vector<std::string>> order;
    ContextSink                               last_ctx; ///< Published context for cancellation tests.

    void
    SetUp() override {
        session  = std::make_shared<MockSession>();
        order    = std::make_shared<std::vector<std::string>>();
        last_ctx = std::make_shared<std::weak_ptr<qb::http::Context<MockSession>>>();
    }

    /** @brief Drains the executor until the async chain quiesces. */
    void
    drain() {
        while (executor.hasTasks()) {
            executor.processAllTasks();
        }
    }
};

// --- Deferred single-handler dispatch across HTTP methods (param table) ---------------------

struct MethodCase {
    qb::http::method method;
    const char      *path;
    const char      *label;
};

class RouterAsyncMethodDispatchTest
    : public RouterAsyncDispatchTest
    , public ::testing::WithParamInterface<MethodCase> {};

TEST_P(RouterAsyncMethodDispatchTest, SimpleDeferredHandlerCompletes) {
    const auto param   = GetParam();
    auto       handler = std::make_shared<OrderTracingAsyncRoute>("handler", order, &executor);
    router.add_route(param.path, param.method, [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(param.method, param.path));

    // Synchronous phase ran and deferred a single task; the body logic has not run yet.
    EXPECT_EQ(*order, (std::vector<std::string>{"handler_handle"}));
    EXPECT_FALSE(session->_handler_executed);
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);
    EXPECT_EQ(session->response_write_count(), 0u);

    executor.processAllTasks();

    EXPECT_EQ(*order, (std::vector<std::string>{"handler_handle", "handler_task"}));
    EXPECT_TRUE(session->_handler_executed);
    EXPECT_EQ(session->_handler_id, "handler");
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->response_write_count(), 1u);
}

INSTANTIATE_TEST_SUITE_P(Methods, RouterAsyncMethodDispatchTest,
                         ::testing::Values(MethodCase{qb::http::method::GET, "/async/get", "GET"},
                                           MethodCase{qb::http::method::POST, "/async/post", "POST"},
                                           MethodCase{qb::http::method::PUT, "/async/put", "PUT"},
                                           MethodCase{qb::http::method::DEL, "/async/delete", "DELETE"}),
                         [](const ::testing::TestParamInfo<MethodCase> &info) { return std::string(info.param.label); });

// --- Path parameters captured by the deferred task ------------------------------------------

TEST_F(RouterAsyncDispatchTest, DeferredHandlerCapturesPathParameters) {
    auto handler = std::make_shared<OrderTracingAsyncRoute>("params", order, &executor);
    router.get("/async/params/:id", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/async/params/123"));

    EXPECT_EQ(*order, (std::vector<std::string>{"params_handle"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    executor.processAllTasks();

    EXPECT_TRUE(session->_handler_executed);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(session->_captured_params.get("id").value_or(""), "123");
}

// --- Sync middleware then async handler -----------------------------------------------------

TEST_F(RouterAsyncDispatchTest, SyncMiddlewareThenDeferredHandler) {
    router.use(std::make_shared<SyncTraceMiddleware<MockSession>>("sync_mw", order));
    auto handler = std::make_shared<OrderTracingAsyncRoute>("handler", order, &executor);
    router.get("/async/with_sync_mw", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/async/with_sync_mw"));

    // Sync MW runs immediately; handler synchronous phase runs and defers.
    EXPECT_EQ(*order, (std::vector<std::string>{"sync_mw", "handler_handle"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    executor.processAllTasks();

    EXPECT_EQ(*order, (std::vector<std::string>{"sync_mw", "handler_handle", "handler_task"}));
    EXPECT_TRUE(session->_handler_executed);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
}

// --- Async middleware then async handler ----------------------------------------------------

TEST_F(RouterAsyncDispatchTest, AsyncMiddlewareThenDeferredHandler) {
    router.use(std::make_shared<AsyncTraceMiddleware<MockSession>>("async_mw", order, &executor));
    auto handler = std::make_shared<OrderTracingAsyncRoute>("handler", order, &executor);
    router.get("/async/mw_then_handler", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/async/mw_then_handler"));

    // Only the async MW's synchronous record has happened; its CONTINUE is deferred.
    EXPECT_EQ(*order, (std::vector<std::string>{"async_mw"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    executor.processAllTasks(); // MW CONTINUE -> handler synchronous phase defers its task.
    EXPECT_EQ(*order, (std::vector<std::string>{"async_mw", "handler_handle"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);
    EXPECT_FALSE(session->_handler_executed);

    executor.processAllTasks(); // Handler task -> COMPLETE -> finalize.
    EXPECT_EQ(*order, (std::vector<std::string>{"async_mw", "handler_handle", "handler_task"}));
    EXPECT_TRUE(session->_handler_executed);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
}

// --- Async handler signalling an error ------------------------------------------------------

TEST_F(RouterAsyncDispatchTest, DeferredHandlerSignalsError) {
    auto handler = std::make_shared<OrderTracingAsyncRoute>("err_handler", order, &executor, /*signal_error=*/true);
    router.get("/async/error", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/async/error"));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    executor.processAllTasks();

    EXPECT_EQ(*order, (std::vector<std::string>{"err_handler_handle", "err_handler_task"}));
    EXPECT_EQ(session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(session->response_write_count(), 1u);
}

// --- Async middleware short-circuit (COMPLETE) ----------------------------------------------

TEST_F(RouterAsyncDispatchTest, AsyncMiddlewareShortCircuitWithComplete) {
    router.use(
        std::make_shared<AsyncResultMiddleware>("sc_mw", order, &executor, qb::http::AsyncTaskResult::COMPLETE, qb::http::status::ACCEPTED));
    auto handler = std::make_shared<OrderTracingAsyncRoute>("never_handler", order, &executor);
    router.get("/async/short_circuit", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/async/short_circuit"));
    EXPECT_EQ(*order, (std::vector<std::string>{"sc_mw_handle"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    executor.processAllTasks(); // MW task short-circuits via COMPLETE; no handler dispatch.

    EXPECT_EQ(*order, (std::vector<std::string>{"sc_mw_handle", "sc_mw_task"}));
    EXPECT_FALSE(session->_handler_executed);
    EXPECT_EQ(session->_response.status(), qb::http::status::ACCEPTED);
    EXPECT_FALSE(executor.hasTasks()) << "Short-circuit must not dispatch the downstream handler.";
}

// --- Full mixed chain: sync MW -> async MW -> async handler ---------------------------------

TEST_F(RouterAsyncDispatchTest, MixedSyncMwAsyncMwAsyncHandler) {
    router.use(std::make_shared<SyncTraceMiddleware<MockSession>>("sync_mw", order));
    router.use(std::make_shared<AsyncTraceMiddleware<MockSession>>("async_mw", order, &executor));
    auto handler = std::make_shared<OrderTracingAsyncRoute>("handler", order, &executor);
    router.get("/async/mixed", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/async/mixed"));
    EXPECT_EQ(*order, (std::vector<std::string>{"sync_mw", "async_mw"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    executor.processAllTasks(); // async MW CONTINUE -> handler synchronous phase defers.
    EXPECT_EQ(*order, (std::vector<std::string>{"sync_mw", "async_mw", "handler_handle"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    executor.processAllTasks(); // handler task -> COMPLETE.
    EXPECT_EQ(*order, (std::vector<std::string>{"sync_mw", "async_mw", "handler_handle", "handler_task"}));
    EXPECT_TRUE(session->_handler_executed);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
}

// --- Async middleware error aborts the chain ------------------------------------------------

TEST_F(RouterAsyncDispatchTest, AsyncMiddlewareErrorAbortsChain) {
    router.use(std::make_shared<AsyncResultMiddleware>("err_mw", order, &executor, qb::http::AsyncTaskResult::ERROR,
                                                       qb::http::status::SERVICE_UNAVAILABLE));
    auto handler = std::make_shared<OrderTracingAsyncRoute>("never_handler", order, &executor);
    router.get("/async/mw_error", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/async/mw_error"));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    executor.processAllTasks(); // MW task signals ERROR; no error chain set -> generic 500.

    EXPECT_EQ(*order, (std::vector<std::string>{"err_mw_handle", "err_mw_task"}));
    EXPECT_FALSE(session->_handler_executed);
    EXPECT_EQ(session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_FALSE(executor.hasTasks()) << "No downstream handler task may be queued after a middleware error.";
}

// --- Route group with async middleware + async handler --------------------------------------

TEST_F(RouterAsyncDispatchTest, RouteGroupAsyncMiddlewareAndHandler) {
    auto group = router.group("/api/group");
    group->use(std::make_shared<AsyncTraceMiddleware<MockSession>>("group_mw", order, &executor));
    auto handler = std::make_shared<OrderTracingAsyncRoute>("group_handler", order, &executor);
    group->get("/resource", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/api/group/resource"));
    EXPECT_EQ(*order, (std::vector<std::string>{"group_mw"}));

    executor.processAllTasks(); // group MW CONTINUE -> handler synchronous phase.
    EXPECT_EQ(*order, (std::vector<std::string>{"group_mw", "group_handler_handle"}));

    executor.processAllTasks(); // handler task -> COMPLETE.
    EXPECT_EQ(*order, (std::vector<std::string>{"group_mw", "group_handler_handle", "group_handler_task"}));
    EXPECT_TRUE(session->_handler_executed);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
}

// --- 404 still runs the global async middleware ---------------------------------------------

TEST_F(RouterAsyncDispatchTest, NotFoundStillRunsGlobalAsyncMiddleware) {
    router.use(std::make_shared<AsyncTraceMiddleware<MockSession>>("global_mw", order, &executor));
    auto handler = std::make_shared<OrderTracingAsyncRoute>("known_handler", order, &executor);
    router.get("/known", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/does/not/exist"));
    EXPECT_EQ(*order, (std::vector<std::string>{"global_mw"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    drain(); // global MW CONTINUE -> no match -> default 404.

    EXPECT_EQ(*order, (std::vector<std::string>{"global_mw"}));
    EXPECT_FALSE(session->_handler_executed);
    EXPECT_EQ(session->_response.status(), qb::http::status::NOT_FOUND);
}

// --- Async lambda handler -------------------------------------------------------------------

TEST_F(RouterAsyncDispatchTest, AsyncLambdaHandlerDeferred) {
    auto local_order    = order;
    auto local_executor = &executor;
    router.get("/async/lambda", [local_order, local_executor](std::shared_ptr<qb::http::Context<MockSession>> ctx) {
        if (local_order) {
            local_order->push_back("lambda_handle");
        }
        local_executor->addTask([ctx, local_order]() {
            if (local_order) {
                local_order->push_back("lambda_task");
            }
            if (auto session = ctx->session()) {
                session->_handler_executed = true;
                session->_handler_id       = "lambda";
            }
            ctx->response().status() = qb::http::status::OK;
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        });
    });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/async/lambda"));
    EXPECT_EQ(*order, (std::vector<std::string>{"lambda_handle"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    executor.processAllTasks();

    EXPECT_EQ(*order, (std::vector<std::string>{"lambda_handle", "lambda_task"}));
    EXPECT_TRUE(session->_handler_executed);
    EXPECT_EQ(session->_response.status(), qb::http::status::OK);
}

// --- Cancellation matrix --------------------------------------------------------------------

TEST_F(RouterAsyncDispatchTest, CancelBeforeAnyTaskProcessed) {
    auto handler = std::make_shared<OrderTracingAsyncRoute>("handler", order, &executor, false, true, last_ctx);
    router.get("/async/cancel_early", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/async/cancel_early"));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);
    EXPECT_FALSE(session->_handler_executed);

    auto ctx = last_ctx->lock();
    ASSERT_TRUE(ctx) << "Custom route must have published the context.";
    ctx->cancel("test cancel before task");

    // cancel() finalizes immediately with 503.
    EXPECT_EQ(session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_TRUE(ctx->is_cancelled());
    EXPECT_TRUE(ctx->is_completed());

    executor.processAllTasks(); // The queued task observes cancellation and bows out.

    EXPECT_EQ(*order, (std::vector<std::string>{"handler_handle", "handler_cancelled"}));
    EXPECT_FALSE(session->_handler_executed);
    EXPECT_EQ(session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(session->response_write_count(), 1u) << "Cancellation must finalize exactly once.";
}

TEST_F(RouterAsyncDispatchTest, CancelAfterAsyncMiddlewareBeforeHandlerTask) {
    router.use(std::make_shared<AsyncTraceMiddleware<MockSession>>("async_mw", order, &executor));
    auto handler = std::make_shared<OrderTracingAsyncRoute>("handler", order, &executor, false, true, last_ctx);
    router.get("/async/mw_then_cancel/:id", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/async/mw_then_cancel/7"));
    executor.processAllTasks(); // async MW CONTINUE -> handler synchronous phase defers its task.

    EXPECT_EQ(*order, (std::vector<std::string>{"async_mw", "handler_handle"}));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    auto ctx = last_ctx->lock();
    ASSERT_TRUE(ctx);
    ctx->cancel("cancel after middleware, before handler task");
    EXPECT_EQ(session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);

    executor.processAllTasks(); // Handler task observes cancellation.

    EXPECT_EQ(*order, (std::vector<std::string>{"async_mw", "handler_handle", "handler_cancelled"}));
    EXPECT_FALSE(session->_handler_executed);
    EXPECT_TRUE(ctx->is_cancelled());
    EXPECT_TRUE(ctx->is_completed());
}

TEST_F(RouterAsyncDispatchTest, CancelOnAlreadyErroredContextOverridesTo503) {
    qb::http::Request req;
    req.method() = qb::http::method::GET;
    req.uri()    = qb::io::uri("/test");
    qb::http::Response resp_proto;

    auto                                                  temp_session = std::make_shared<MockSession>();
    std::function<void(qb::http::Context<MockSession> &)> on_finalized = [temp_session](qb::http::Context<MockSession> &ctx) {
        *temp_session << ctx.response();
    };
    auto ctx = std::make_shared<qb::http::Context<MockSession>>(std::move(req), std::move(resp_proto), temp_session, on_finalized,
                                                                router.get_router_core_weak_ptr());

    ctx->response().status() = qb::http::status::NOT_FOUND;

    ctx->cancel("cancel on a 404 context");

    EXPECT_EQ(ctx->response().status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(temp_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_TRUE(ctx->is_cancelled());
    EXPECT_TRUE(ctx->is_completed());
    EXPECT_EQ(temp_session->response_write_count(), 1u);
}

TEST_F(RouterAsyncDispatchTest, CancelDuringDeferredTaskBody) {
    // The handler's task body itself cancels the context, then continues; its own COMPLETE must be
    // a no-op because cancel() already finalized with 503.
    auto local_order    = order;
    auto local_executor = &executor;
    router.get("/async/cancel_in_body", [local_order, local_executor](std::shared_ptr<qb::http::Context<MockSession>> ctx) {
        if (local_order) {
            local_order->push_back("body_handle");
        }
        local_executor->addTask([ctx, local_order]() {
            if (local_order) {
                local_order->push_back("body_task");
            }
            ctx->cancel("cancel inside the deferred task body");
            // This stale completion attempt must be ignored by the finalized/cancelled context.
            ctx->response().status() = qb::http::status::OK;
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        });
    });
    router.compile();

    router.route(session, create_request(qb::http::method::GET, "/async/cancel_in_body"));
    EXPECT_EQ(executor.getPendingTaskCount(), 1u);

    executor.processAllTasks();

    EXPECT_EQ(*order, (std::vector<std::string>{"body_handle", "body_task"}));
    EXPECT_EQ(session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE)
        << "cancel() inside the task body wins; the trailing COMPLETE must not override 503.";
    EXPECT_EQ(session->response_write_count(), 1u) << "Exactly one finalization despite the trailing complete().";
}

// --- Double-complete idempotency ------------------------------------------------------------

TEST_F(RouterAsyncDispatchTest, DoubleCompleteIsIdempotent) {
    // A handler that completes COMPLETE twice must finalize exactly once (MockSession throws on a
    // second write between resets, so a non-idempotent complete() would surface as that throw).
    auto local_order = order;
    router.get("/async/double_complete", [local_order](std::shared_ptr<qb::http::Context<MockSession>> ctx) {
        if (local_order) {
            local_order->push_back("double");
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        // Second call: context is already Finalised -> must be a no-op.
        ctx->response().status() = qb::http::status::ACCEPTED;
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    });
    router.compile();

    EXPECT_NO_THROW(router.route(session, create_request(qb::http::method::GET, "/async/double_complete")));

    EXPECT_EQ(*order, (std::vector<std::string>{"double"}));
    EXPECT_EQ(session->_response.status(), qb::http::status::OK)
        << "The first COMPLETE wins; the second is ignored, so the mutated 202 never finalizes.";
    EXPECT_EQ(session->response_write_count(), 1u);
}

TEST_F(RouterAsyncDispatchTest, DeferredDoubleCompleteIsIdempotent) {
    // Same contract but across the deferred boundary: the task body defers, then the test drives
    // complete() three times. The handler runs with auto_complete=false, so its deferred task body
    // runs WITHOUT completing the context — completion is left to the external trigger below.
    //
    // Lifetime note: the only strong reference to the Context after route() returns is the one the
    // deferred task captures (Router::route() returns a shared_ptr<Context> we must hold ourselves).
    // Once processAllTasks() runs and clears that task, the captured shared_ptr drops; if we did not
    // keep our own strong reference the Context would be destroyed (its destructor finalizing it),
    // and last_ctx->lock() would be expired. So we keep the route()-returned shared_ptr alive across
    // the pump and drive the trailing complete() calls on it directly.
    auto handler = std::make_shared<OrderTracingAsyncRoute>("h", order, &executor, /*signal_error=*/false, /*auto_complete=*/false, last_ctx);
    router.get("/async/deferred_double", [handler](auto ctx) { handler->process(ctx); });
    router.compile();

    auto ctx = router.route(session, create_request(qb::http::method::GET, "/async/deferred_double"));
    ASSERT_TRUE(ctx) << "route() returns the live Context owning this request.";
    executor.processAllTasks(); // task body ran (auto_complete=false) but did not complete yet.

    // Nothing has finalized yet: the deferred body returned without completing.
    EXPECT_FALSE(ctx->is_completed());
    EXPECT_EQ(session->response_write_count(), 0u);

    // The external trigger completes the context. The FIRST terminal complete() wins and finalizes
    // exactly once; every subsequent complete() (COMPLETE or ERROR) is a no-op against the now-
    // Finalised context. The single-write guard on MockSession (operator<< throws on a second write
    // between resets) proves the idempotency: a non-idempotent complete() would surface as a throw.
    ctx->response().status() = qb::http::status::OK;
    EXPECT_NO_THROW(ctx->complete(qb::http::AsyncTaskResult::COMPLETE));
    EXPECT_TRUE(ctx->is_completed());
    ctx->response().status() = qb::http::status::ACCEPTED;               // must NOT reach the wire: already finalized.
    EXPECT_NO_THROW(ctx->complete(qb::http::AsyncTaskResult::COMPLETE)); // no-op
    EXPECT_NO_THROW(ctx->complete(qb::http::AsyncTaskResult::ERROR));    // no-op

    EXPECT_EQ(session->_response.status(), qb::http::status::OK)
        << "The first COMPLETE wins; the trailing complete() calls are ignored, so the mutated 202 never finalizes.";
    EXPECT_EQ(session->response_write_count(), 1u) << "Exactly one finalization despite three complete() calls.";
}

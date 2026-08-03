/**
 * @file qbm/http/tests/unit/routing/router-error-handling.cpp
 * @brief Authority for the qb-http router error/cancel/fatal state machine.
 *
 * Drives @ref qb::http::Router<Session> directly via `route()` + the shared
 * synchronous @ref qb::http::test::TaskExecutor pump and a capturing mock session.
 * No `qb::Main`, no event loop, no socket — fully deterministic unit tier.
 *
 * This file exercises every `AsyncTaskResult` transition reachable through the
 * error machinery: ERROR (→ error chain or default 500), FATAL_SPECIAL_HANDLER_ERROR,
 * thrown `std::exception`, thrown non-`std` (`throw 1337`), and `ctx->cancel()`, in
 * the route-handler, middleware, not-found-handler, and error-chain positions.
 *
 * Vocabulary: a single status/method vocabulary is used throughout —
 * `qb::http::status::*` enumerators and `qb::http::method::*` — never the legacy
 * `HTTP_STATUS_*` / `HTTP_GET` macros.
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "../../shared/router_test_support.h" // qb::http::test::TaskExecutor
#include <qbm/http/http.h>

using qb::http::test::TaskExecutor;

namespace {

// --- Mock session: captures the finalized Response + an execution-order log. ----
//
// The router writes the finalized response through `operator<<`. This local
// session adds a name-ordered execution log (a std::vector, not a string-marker
// concat) so error-chain ordering and "did NOT run" negatives are structural.
struct MockErrorSession {
    qb::http::Response       _response;
    bool                     _finalized = false;
    std::vector<std::string> _executed;                ///< Ordered names of tasks that ran.
    std::string              _last_error_handler_name; ///< Name of the error-chain handler that completed normally.

    void
    record(const std::string &name) {
        _executed.push_back(name);
    }

    void
    reset() {
        _response  = qb::http::Response();
        _finalized = false;
        _executed.clear();
        _last_error_handler_name.clear();
    }

    MockErrorSession &
    operator<<(const qb::http::Response &resp) {
        _response  = resp;
        _finalized = true;
        return *this;
    }
};

// --- Custom-route tasks (handlers) ---------------------------------------------
//
// Each task implements BOTH @ref qb::http::ICustomRoute (so it can be registered as
// a route handler via `router.get(path, shared_ptr<ICustomRoute>)`) AND
// @ref qb::http::IAsyncTask (so the SAME instance can be pushed directly into the
// error-task chain, which is a `vector<shared_ptr<IAsyncTask>>`). The shared base
// bridges `execute()` → `process()` and supplies name()/cancel(), so subclasses
// only define their `process()` behavior. This mirrors the router's own internal
// task model where a custom route is adapted into the async-task pipeline.
class ChainCustomRoute
    : public qb::http::IAsyncTask<MockErrorSession>
    , public qb::http::ICustomRoute<MockErrorSession> {
public:
    ChainCustomRoute(std::string name, std::shared_ptr<MockErrorSession> session)
        : _name(std::move(name))
        , _session(std::move(session)) {}

    // IAsyncTask entry point — delegate to the ICustomRoute body.
    void
    execute(std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) override {
        process(ctx);
    }

    // Disambiguate the two identical interface members with a single override each.
    [[nodiscard]] std::string
    name() const override {
        return _name;
    }
    void
    cancel() override {}

protected:
    std::string                       _name;
    std::shared_ptr<MockErrorSession> _session;
};

// Signals ERROR (optionally deferred via the executor).
class ErrorTask : public ChainCustomRoute {
public:
    ErrorTask(std::string name, std::shared_ptr<MockErrorSession> session, TaskExecutor *executor)
        : ChainCustomRoute(std::move(name), std::move(session))
        , _executor(executor) {}

    void
    process(std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) override {
        _session->record(_name);
        if (_executor) {
            _executor->addTask([ctx]() { ctx->complete(qb::http::AsyncTaskResult::ERROR); });
        } else {
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        }
    }

private:
    TaskExecutor *_executor;
};

// Throws std::runtime_error from process() — the route adapter must convert this
// into the error chain (or a default 500).
class ThrowingTask : public ChainCustomRoute {
public:
    ThrowingTask(std::string name, std::shared_ptr<MockErrorSession> session, std::string message = "Test exception from task")
        : ChainCustomRoute(std::move(name), std::move(session))
        , _message(std::move(message)) {}

    void
    process(std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) override {
        _session->record(_name);
        (void) ctx;
        throw std::runtime_error(_message);
    }

private:
    std::string _message;
};

// Completes normally with a chosen status/body (deferred). Used as an error-chain
// handler (records its name as "the error handler that ran") or a success handler.
class CompletingTask : public ChainCustomRoute {
public:
    CompletingTask(std::string name, std::shared_ptr<MockErrorSession> session, TaskExecutor *executor,
                   qb::http::status status = qb::http::status::OK, std::string body = "OK", bool is_error_handler = false)
        : ChainCustomRoute(std::move(name), std::move(session))
        , _executor(executor)
        , _status(status)
        , _body(std::move(body))
        , _is_error_handler(is_error_handler) {}

    void
    process(std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) override {
        _session->record(_name);
        auto run = [this, ctx]() {
            ctx->response().status() = _status;
            ctx->response().body()   = _body;
            if (_is_error_handler) {
                _session->_last_error_handler_name = _name;
            }
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        };
        if (_executor) {
            _executor->addTask(run);
        } else {
            run();
        }
    }

private:
    TaskExecutor    *_executor;
    qb::http::status _status;
    std::string      _body;
    bool             _is_error_handler;
};

// A CONTINUE-then-defer middleware-style task usable inside an error chain to
// prove multi-handler chains run in order (records its name, sets a header, then
// CONTINUEs to the next chain task).
class ContinuingHeaderTask : public ChainCustomRoute {
public:
    ContinuingHeaderTask(std::string name, std::shared_ptr<MockErrorSession> session, std::string header_key, std::string header_val)
        : ChainCustomRoute(std::move(name), std::move(session))
        , _header_key(std::move(header_key))
        , _header_val(std::move(header_val)) {}

    void
    process(std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) override {
        _session->record(_name);
        ctx->response().set_header(_header_key, _header_val);
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }

private:
    std::string _header_key;
    std::string _header_val;
};

// Signals FATAL_SPECIAL_HANDLER_ERROR (deferred).
class FatalTask : public ChainCustomRoute {
public:
    FatalTask(std::string name, std::shared_ptr<MockErrorSession> session, TaskExecutor *executor)
        : ChainCustomRoute(std::move(name), std::move(session))
        , _executor(executor) {}

    void
    process(std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) override {
        _session->record(_name);
        _executor->addTask([ctx]() { ctx->complete(qb::http::AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR); });
    }

private:
    TaskExecutor *_executor;
};

// --- Fixture -------------------------------------------------------------------

class RouterErrorHandlingTest : public ::testing::Test {
protected:
    TaskExecutor                                        _executor;
    std::shared_ptr<qb::http::Router<MockErrorSession>> _router;
    std::shared_ptr<MockErrorSession>                   _session;

    void
    SetUp() override {
        _session = std::make_shared<MockErrorSession>();
        _router  = std::make_shared<qb::http::Router<MockErrorSession>>();
    }

    void
    TearDown() override {
        while (_executor.hasTasks()) {
            _executor.processAllTasks();
        }
    }

    void
    make_request(qb::http::method method_val, const std::string &path) {
        qb::http::Request req;
        req.method()      = method_val;
        req.uri()         = qb::io::uri(path);
        req.major_version = 1;
        req.minor_version = 1;
        _router->route(_session, std::move(req));
        while (_executor.hasTasks()) {
            _executor.processAllTasks();
        }
    }

    [[nodiscard]] bool
    ran(const std::string &name) const {
        return std::find(_session->_executed.begin(), _session->_executed.end(), name) != _session->_executed.end();
    }

    [[nodiscard]] std::size_t
    run_count(const std::string &name) const {
        return static_cast<std::size_t>(std::count(_session->_executed.begin(), _session->_executed.end(), name));
    }

    // Wrap a single error-chain task into the router error chain.
    void
    set_error_chain(std::vector<std::shared_ptr<qb::http::IAsyncTask<MockErrorSession>>> chain) {
        _router->set_error_task_chain(std::move(chain));
    }

    std::shared_ptr<qb::http::FunctionalMiddleware<MockErrorSession>>
    make_functional_mw(qb::http::MiddlewareHandlerFn<MockErrorSession> fn, const std::string &name) {
        return std::make_shared<qb::http::FunctionalMiddleware<MockErrorSession>>(std::move(fn), name);
    }
};

// --- Route-handler error paths -------------------------------------------------

TEST_F(RouterErrorHandlingTest, ErrorInHandlerTriggersErrorChain) {
    auto error_handler = std::make_shared<CompletingTask>("ErrorHandlerInChain", _session, &_executor, qb::http::status::SERVICE_UNAVAILABLE,
                                                          "Handled by error chain", true);
    set_error_chain({error_handler});

    _router->get("/path_to_error", std::make_shared<ErrorTask>("ErroringRoute", _session, &_executor));
    _router->compile();

    make_request(qb::http::method::GET, "/path_to_error");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("ErroringRoute"));
    EXPECT_TRUE(ran("ErrorHandlerInChain"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled by error chain");
    EXPECT_EQ(_session->_last_error_handler_name, "ErrorHandlerInChain");
}

TEST_F(RouterErrorHandlingTest, ExceptionInHandlerTriggersErrorChain) {
    _router->get("/exception_path", std::make_shared<ThrowingTask>("RouteExceptionThrower", _session));

    auto error_handler = std::make_shared<CompletingTask>("ExceptionHandlerInChain", _session, &_executor,
                                                          qb::http::status::INTERNAL_SERVER_ERROR, "Handled (exception)", true);
    set_error_chain({error_handler});
    _router->compile();

    make_request(qb::http::method::GET, "/exception_path");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("RouteExceptionThrower"));
    EXPECT_TRUE(ran("ExceptionHandlerInChain"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled (exception)");
    EXPECT_EQ(_session->_last_error_handler_name, "ExceptionHandlerInChain");
}

// NEW (spec §2): an error chain with MULTIPLE successful handlers — each runs, in
// order, and a header set by an earlier CONTINUE chain task survives to the final
// response. Locks the chain-ordering contract beyond the legacy length-1 chains.
TEST_F(RouterErrorHandlingTest, ErrorChainWithMultipleSuccessfulHandlersRunsAllInOrder) {
    auto first  = std::make_shared<ContinuingHeaderTask>("ErrorChainStep1", _session, "X-Error-Stage", "one");
    auto second = std::make_shared<CompletingTask>("ErrorChainStep2", _session, &_executor, qb::http::status::BAD_GATEWAY, "two-handled", true);
    set_error_chain({first, second});

    _router->get("/multi_error", std::make_shared<ErrorTask>("MultiErrorRoute", _session, &_executor));
    _router->compile();

    make_request(qb::http::method::GET, "/multi_error");

    // Both chain handlers ran, in declared order, after the erroring route.
    ASSERT_EQ(_session->_executed.size(), 3u);
    EXPECT_EQ(_session->_executed[0], "MultiErrorRoute");
    EXPECT_EQ(_session->_executed[1], "ErrorChainStep1");
    EXPECT_EQ(_session->_executed[2], "ErrorChainStep2");
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "two-handled");
    EXPECT_EQ(_session->_response.header("X-Error-Stage"), "one");
    EXPECT_EQ(_session->_last_error_handler_name, "ErrorChainStep2");
}

TEST_F(RouterErrorHandlingTest, ErrorInMiddlewareTriggersErrorChain) {
    auto normal_handler = std::make_shared<CompletingTask>("NormalHandler", _session, &_executor, qb::http::status::OK, "OK from handler");

    auto erroring_mw = make_functional_mw(
        [this](std::shared_ptr<qb::http::Context<MockErrorSession>> ctx, std::function<void()> /*next*/) {
            _session->record("ErroringMiddleware");
            _executor.addTask([ctx]() {
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->complete(qb::http::AsyncTaskResult::ERROR);
            });
        },
        "ErroringMiddleware");

    // The same global middleware is re-prepended to the error chain, so it runs a
    // second time and errors again — proving the chain itself fails (default 500).
    auto global_mw_task = std::make_shared<qb::http::MiddlewareTask<MockErrorSession>>(erroring_mw, erroring_mw->name());
    auto chain_handler  = std::make_shared<CompletingTask>("MwErrorChainHandler", _session, &_executor, qb::http::status::INTERNAL_SERVER_ERROR,
                                                           "should not run", true);
    set_error_chain({global_mw_task, chain_handler});

    _router->use(erroring_mw);
    _router->get("/mw_error_path", normal_handler);
    _router->compile();

    make_request(qb::http::method::GET, "/mw_error_path");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_EQ(run_count("ErroringMiddleware"), 2u) << "Global MW runs once on the normal path, once in the error chain.";
    EXPECT_FALSE(ran("NormalHandler"));
    EXPECT_FALSE(ran("MwErrorChainHandler"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session->_last_error_handler_name.empty());
}

TEST_F(RouterErrorHandlingTest, GlobalMiddlewarePrependedToErrorChainSeesResponse) {
    std::shared_ptr<qb::http::FunctionalMiddleware<MockErrorSession>> global_mw;
    global_mw = make_functional_mw(
        [this, &global_mw](std::shared_ptr<qb::http::Context<MockErrorSession>> ctx, std::function<void()> next) {
            _session->record(global_mw->name());
            ctx->response().add_header("X-Global-MW", "Processed");
            _executor.addTask([next]() { next(); });
        },
        "GlobalMw");
    _router->use(global_mw);

    auto error_route    = std::make_shared<ErrorTask>("ErrorRoute", _session, &_executor);
    auto chain_handler  = std::make_shared<CompletingTask>("CustomErrorChainHandler", _session, &_executor, qb::http::status::CONFLICT,
                                                           "Custom error handled", true);
    auto global_mw_task = std::make_shared<qb::http::MiddlewareTask<MockErrorSession>>(global_mw, global_mw->name());
    set_error_chain({global_mw_task, chain_handler});

    _router->get("/global_error", error_route);
    _router->compile();

    make_request(qb::http::method::GET, "/global_error");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("ErrorRoute"));
    EXPECT_EQ(run_count("GlobalMw"), 2u);
    EXPECT_TRUE(ran("CustomErrorChainHandler"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::CONFLICT);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Custom error handled");
    EXPECT_EQ(_session->_last_error_handler_name, "CustomErrorChainHandler");
    EXPECT_EQ(_session->_response.header("X-Global-MW"), "Processed");
}

TEST_F(RouterErrorHandlingTest, ErrorWithNoChainSetDefaultsToFinalization) {
    _router->get("/no_chain", std::make_shared<ErrorTask>("NoChainHandler", _session, &_executor));
    _router->compile();

    make_request(qb::http::method::GET, "/no_chain");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("NoChainHandler"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session->_last_error_handler_name.empty());
}

TEST_F(RouterErrorHandlingTest, ErrorWithEmptyChainDefaultsToFinalization) {
    set_error_chain({}); // explicitly empty
    _router->get("/empty_chain", std::make_shared<ErrorTask>("EmptyChainHandler", _session, &_executor));
    _router->compile();

    make_request(qb::http::method::GET, "/empty_chain");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("EmptyChainHandler"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session->_last_error_handler_name.empty());
}

TEST_F(RouterErrorHandlingTest, ErrorInErrorChainHandlerItselfFinalizesTo500) {
    set_error_chain({std::make_shared<ErrorTask>("ErrorChainErrorSignaler", _session, &_executor)});
    _router->get("/error_in_chain", std::make_shared<ErrorTask>("InitialErrorTrigger", _session, &_executor));
    _router->compile();

    make_request(qb::http::method::GET, "/error_in_chain");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("InitialErrorTrigger"));
    EXPECT_TRUE(ran("ErrorChainErrorSignaler"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session->_last_error_handler_name.empty());
}

TEST_F(RouterErrorHandlingTest, ExceptionInMiddlewareTriggersDefault500WhenChainAlsoThrows) {
    auto normal_handler = std::make_shared<CompletingTask>("HandlerAfterThrow", _session, &_executor);

    auto throwing_mw = make_functional_mw(
        [this](std::shared_ptr<qb::http::Context<MockErrorSession>> /*ctx*/, std::function<void()> /*next*/) {
            _session->record("ThrowingMiddleware");
            throw std::runtime_error("Exception from middleware");
        },
        "ThrowingMiddleware");

    auto global_mw_task = std::make_shared<qb::http::MiddlewareTask<MockErrorSession>>(throwing_mw, throwing_mw->name());
    auto chain_handler  = std::make_shared<CompletingTask>("MwExceptionChainHandler", _session, &_executor, qb::http::status::BAD_GATEWAY,
                                                           "should not run", true);
    set_error_chain({global_mw_task, chain_handler});

    _router->use(throwing_mw);
    _router->get("/mw_exception", normal_handler);
    _router->compile();

    make_request(qb::http::method::GET, "/mw_exception");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_EQ(run_count("ThrowingMiddleware"), 2u);
    EXPECT_FALSE(ran("HandlerAfterThrow"));
    EXPECT_FALSE(ran("MwExceptionChainHandler"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session->_last_error_handler_name.empty());
}

TEST_F(RouterErrorHandlingTest, NonStdExceptionInMiddlewareTriggersErrorChain) {
    auto normal_handler = std::make_shared<CompletingTask>("HandlerAfterNonStdThrow", _session, &_executor);

    auto throwing_mw = make_functional_mw(
        [this](std::shared_ptr<qb::http::Context<MockErrorSession>> /*ctx*/, std::function<void()> /*next*/) {
            _session->record("NonStdThrowingMiddleware");
            throw 1337;
        },
        "NonStdThrowingMiddleware");

    auto chain_handler = std::make_shared<CompletingTask>("NonStdMwChainHandler", _session, &_executor, qb::http::status::BAD_GATEWAY,
                                                          "Handled (non-std)", true);
    set_error_chain({chain_handler});

    _router->use(throwing_mw);
    _router->get("/mw_non_std", normal_handler);
    _router->compile();

    make_request(qb::http::method::GET, "/mw_non_std");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("NonStdThrowingMiddleware"));
    EXPECT_FALSE(ran("HandlerAfterNonStdThrow"));
    EXPECT_TRUE(ran("NonStdMwChainHandler"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled (non-std)");
}

TEST_F(RouterErrorHandlingTest, ExceptionInErrorChainHandlerFinalizesTo500) {
    set_error_chain({std::make_shared<ThrowingTask>("ErrorChainExceptionThrower", _session, "Exception from chain task")});
    _router->get("/exception_in_chain", std::make_shared<ErrorTask>("InitialTrigger", _session, &_executor));
    _router->compile();

    make_request(qb::http::method::GET, "/exception_in_chain");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("InitialTrigger"));
    EXPECT_TRUE(ran("ErrorChainExceptionThrower"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session->_last_error_handler_name.empty());
}

// --- Cancellation paths --------------------------------------------------------

TEST_F(RouterErrorHandlingTest, CancellationDuringNormalProcessingFinalizesAndSkipsErrorChain) {
    auto cancelling_mw = make_functional_mw(
        [this](std::shared_ptr<qb::http::Context<MockErrorSession>> ctx, std::function<void()> /*next*/) {
            _session->record("CancellingMiddleware");
            _executor.addTask([ctx]() { ctx->cancel(); });
        },
        "CancellingMiddleware");

    auto handler = std::make_shared<CompletingTask>("HandlerAfterCancel", _session, &_executor);
    set_error_chain(
        {std::make_shared<CompletingTask>("ErrorChainOnCancel", _session, &_executor, qb::http::status::NOT_IMPLEMENTED, "ran on cancel!")});
    _router->use(cancelling_mw);
    _router->get("/cancel_path", handler);
    _router->compile();

    make_request(qb::http::method::GET, "/cancel_path");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("CancellingMiddleware"));
    EXPECT_FALSE(ran("HandlerAfterCancel"));
    EXPECT_FALSE(ran("ErrorChainOnCancel"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
}

TEST_F(RouterErrorHandlingTest, CancellationDuringErrorChainFinalizes) {
    auto cancelling_chain_task = std::make_shared<qb::http::RouteLambdaTask<MockErrorSession>>(
        [this](std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) {
            _session->record("ErrorChainCancellingTask");
            ctx->cancel();
        },
        "ErrorChainCancellingTask");
    auto subsequent =
        std::make_shared<CompletingTask>("ErrorChainSubsequent", _session, &_executor, qb::http::status::NOT_IMPLEMENTED, "ran after cancel!");
    set_error_chain({cancelling_chain_task, subsequent});

    _router->get("/cancel_in_chain", std::make_shared<ErrorTask>("InitialErrorForCancel", _session, &_executor));
    _router->compile();

    make_request(qb::http::method::GET, "/cancel_in_chain");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("InitialErrorForCancel"));
    EXPECT_TRUE(ran("ErrorChainCancellingTask"));
    EXPECT_FALSE(ran("ErrorChainSubsequent"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_TRUE(_session->_last_error_handler_name.empty());
}

// --- Not-found-handler error paths ---------------------------------------------

TEST_F(RouterErrorHandlingTest, ErrorInNotFoundHandlerResultsIn500) {
    _router->set_not_found_handler([this](std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) {
        _session->record("ErroringNotFound");
        _executor.addTask([ctx]() { ctx->complete(qb::http::AsyncTaskResult::FATAL_SPECIAL_HANDLER_ERROR); });
    });
    set_error_chain({std::make_shared<CompletingTask>("MainErrorHandlerShouldNotRun", _session, &_executor, qb::http::status::NOT_IMPLEMENTED,
                                                      "ran!", true)});
    _router->compile();

    make_request(qb::http::method::GET, "/unhandled");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("ErroringNotFound"));
    EXPECT_FALSE(ran("MainErrorHandlerShouldNotRun"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session->_last_error_handler_name.empty());
}

TEST_F(RouterErrorHandlingTest, ExceptionInNotFoundHandlerTriggersMainErrorChain) {
    _router->set_not_found_handler([this](std::shared_ptr<qb::http::Context<MockErrorSession>> /*ctx*/) {
        _session->record("ExceptionThrowingNotFound");
        throw std::runtime_error("Exception from not_found handler");
    });
    set_error_chain({std::make_shared<CompletingTask>("MainErrorHandlerForNotFound", _session, &_executor, qb::http::status::BAD_GATEWAY,
                                                      "Handled (not_found exception)", true)});
    _router->compile();

    make_request(qb::http::method::GET, "/unhandled_exception");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("ExceptionThrowingNotFound"));
    EXPECT_TRUE(ran("MainErrorHandlerForNotFound"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::BAD_GATEWAY);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Handled (not_found exception)");
    EXPECT_EQ(_session->_last_error_handler_name, "MainErrorHandlerForNotFound");
}

TEST_F(RouterErrorHandlingTest, GlobalMiddlewareErrorPreventsNotFoundHandler) {
    auto erroring_global = make_functional_mw(
        [this](std::shared_ptr<qb::http::Context<MockErrorSession>> ctx, std::function<void()> /*next*/) {
            _session->record("ErroringGlobalMw");
            _executor.addTask([ctx]() { ctx->complete(qb::http::AsyncTaskResult::ERROR); });
        },
        "ErroringGlobalMw");
    _router->use(erroring_global);

    _router->set_not_found_handler([this](std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) {
        _session->record("NotFoundShouldNotRun");
        ctx->response().status() = qb::http::status::NOT_FOUND;
        ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
    });

    auto global_mw_task = std::make_shared<qb::http::MiddlewareTask<MockErrorSession>>(erroring_global, erroring_global->name());
    set_error_chain(
        {global_mw_task,
         std::make_shared<CompletingTask>("MainErrorHandlerShouldNotRun", _session, &_executor, qb::http::status::BAD_GATEWAY, "x", true)});
    _router->compile();

    make_request(qb::http::method::GET, "/unhandled_global_error");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_EQ(run_count("ErroringGlobalMw"), 2u);
    EXPECT_FALSE(ran("NotFoundShouldNotRun"));
    EXPECT_FALSE(ran("MainErrorHandlerShouldNotRun"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
}

TEST_F(RouterErrorHandlingTest, CancellationFromNotFoundHandlerFinalizes) {
    _router->set_not_found_handler([this](std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) {
        _session->record("CancellingNotFound");
        _executor.addTask([ctx]() { ctx->cancel(); });
    });
    set_error_chain(
        {std::make_shared<CompletingTask>("ErrorChainShouldNotRun", _session, &_executor, qb::http::status::NOT_IMPLEMENTED, "ran!", true)});
    _router->compile();

    make_request(qb::http::method::GET, "/unhandled_cancel");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("CancellingNotFound"));
    EXPECT_FALSE(ran("ErrorChainShouldNotRun"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
}

// --- Fatal path ----------------------------------------------------------------

TEST_F(RouterErrorHandlingTest, FatalErrorInMainErrorChainIsStillFatal) {
    auto fatal      = std::make_shared<FatalTask>("FatalChainTask", _session, &_executor);
    auto subsequent = std::make_shared<CompletingTask>("SubsequentShouldNotRun", _session, &_executor, qb::http::status::NOT_IMPLEMENTED,
                                                       "ran after fatal!", true);
    set_error_chain({fatal, subsequent});

    _router->get("/fatal_in_chain", std::make_shared<ErrorTask>("InitialErrorForFatal", _session, &_executor));
    _router->compile();

    make_request(qb::http::method::GET, "/fatal_in_chain");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("InitialErrorForFatal"));
    EXPECT_TRUE(ran("FatalChainTask"));
    EXPECT_FALSE(ran("SubsequentShouldNotRun"));
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_TRUE(_session->_last_error_handler_name.empty());
}

// --- 405 path through the error machinery (NEW, spec §2) -----------------------

// A request whose path matches but whose METHOD does not yields 405 with an Allow
// header; the error chain is NOT involved (405 is a dedicated special handler, not
// the ERROR path). This pins the 405 contract alongside the error machinery.
TEST_F(RouterErrorHandlingTest, MethodMismatchYields405NotErrorChain) {
    _router->get("/resource", std::make_shared<CompletingTask>("GetHandler", _session, &_executor, qb::http::status::OK, "get"));
    _router->post("/resource", std::make_shared<CompletingTask>("PostHandler", _session, &_executor, qb::http::status::CREATED, "post"));
    set_error_chain(
        {std::make_shared<CompletingTask>("ErrorChainMustNotRun", _session, &_executor, qb::http::status::BAD_GATEWAY, "error!", true)});
    _router->compile();

    make_request(qb::http::method::DEL, "/resource");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_EQ(_session->_response.status(), qb::http::status::METHOD_NOT_ALLOWED);
    EXPECT_FALSE(ran("GetHandler"));
    EXPECT_FALSE(ran("PostHandler"));
    EXPECT_FALSE(ran("ErrorChainMustNotRun")) << "405 must not route through the error chain.";

    // Allow header lists the registered methods (order-independent).
    const std::string allow = std::string(_session->_response.header("Allow"));
    EXPECT_NE(allow.find("GET"), std::string::npos) << "Allow: " << allow;
    EXPECT_NE(allow.find("POST"), std::string::npos) << "Allow: " << allow;
    EXPECT_EQ(allow.find("DELETE"), std::string::npos) << "Allow must not list the rejected method. Allow: " << allow;
}

// --- complete() after a SYNCHRONOUS error chain is idempotent (spec §2) ---------

// First, the clean idempotency case the framework DOES guarantee: when the error
// chain finalizes SYNCHRONOUSLY (no executor), control only returns to the buggy
// late complete() AFTER the context is already Finalised. complete()'s terminal
// guard (`is_finalised_internal()`) then makes the late COMPLETE a true no-op:
// the error chain's status/body win and the session is finalized exactly once.
TEST_F(RouterErrorHandlingTest, CompleteAfterSynchronousErrorChainIsIdempotent) {
    // No executor passed to the error handler => it completes synchronously, INSIDE the
    // complete(ERROR) call below, driving the context to Finalised before complete(ERROR) returns.
    set_error_chain({std::make_shared<CompletingTask>("ErrorChainHandler", _session, /*executor=*/nullptr,
                                                      qb::http::status::SERVICE_UNAVAILABLE, "error-chain body", true)});

    _router->get("/double_complete_sync", [this](std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) {
        _session->record("DoubleCompleteHandler");
        _executor.addTask([ctx]() {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->complete(qb::http::AsyncTaskResult::ERROR); // error chain runs + finalizes synchronously here.
            // Buggy late completion: the context is already Finalised, so this is a guaranteed no-op.
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "late body that must be ignored";
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        });
    });
    _router->compile();

    make_request(qb::http::method::GET, "/double_complete_sync");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("DoubleCompleteHandler"));
    EXPECT_TRUE(ran("ErrorChainHandler"));
    // The error chain finalized first; the late COMPLETE was rejected by the Finalised guard.
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "error-chain body");
    EXPECT_EQ(_session->_last_error_handler_name, "ErrorChainHandler");
}

// --- complete() after an ASYNC error chain: first-to-finalize wins (spec §2) ----

// The subtler, truthful contract. When the error chain handler is ASYNCHRONOUS
// (deferred onto the executor), complete(ERROR) only *reseats* the task chain to
// the error chain and kicks off its first (deferred) task — it does NOT finalize
// before returning. Control then returns to the buggy late complete(COMPLETE) in
// the SAME task body, which finds the context still Running (not finalised, not
// cancelled) and therefore finalizes IMMEDIATELY with the late OK/body. When the
// deferred error-chain task later runs, the context is already Finalised, so its
// own complete() is the no-op.
//
// => The framework's real guard is "first call to reach finalize_processing_internal()
//    wins; subsequent complete() calls are dropped." It does NOT protect a chain that
//    has switched to the error phase from a stray complete() issued by the task that
//    already signaled ERROR while the (async) error chain is still in flight.
//
// ROBUSTNESS GAP (framework, not test): a task that calls complete(ERROR) and then
// erroneously calls complete() again can, with an asynchronous error chain, race
// ahead of and clobber the error chain's response. complete() guards only on
// is_finalised / is_cancelled, not on "an error chain is already in flight"
// (no ERROR_CHAIN-phase / task_in_flight re-entry guard). A correct handler must
// issue exactly one terminal complete(); this test pins the observable behavior
// when that contract is violated, it does not endorse it.
//
// ANTI-REGRESSION — do NOT "fix" this by adding a phase==ERROR_CHAIN guard to complete().
// It is proven unsound, not merely unimplemented:
//   * At the complete() seam the stray and the *legitimate* in-flight error-chain task's
//     completion are byte-for-byte identical — state, phase, task_in_flight, completion_count,
//     _current_task_index, last_result, re-entrancy depth. They differ ONLY by event-loop turn
//     (the stray is synchronous with complete(ERROR); the legit completion is a later turn), a
//     boundary the Context cannot observe. complete(ERROR) re-dispatches the error task BEFORE the
//     stray runs, so any flag/counter armed for the in-flight task is consumed by whichever call
//     comes next — the stray here, the legit completion in the no-stray case — indistinguishably.
//   * Empirically: the literal guard `if (result != CANCELLED && phase == ERROR_CHAIN &&
//     task_in_flight) return;` drops the legit completion too and breaks 7 tests in this suite
//     (ErrorChainWithMultipleSuccessfulHandlers, GlobalMiddlewarePrependedToErrorChainSeesResponse,
//     ErrorInErrorChainHandlerItselfFinalizesTo500, GlobalMiddlewareErrorPreventsNotFoundHandler,
//     FatalErrorInMainErrorChainIsStillFatal, CompleteAfterSynchronousErrorChainIsIdempotent, and
//     this one). In production it is worse: the dropped legit completion never finalises (the
//     session owns the only shared_ptr<Context>) and the connection hangs.
// The contract is enforced where it belongs — in the caller. See the "Completion contract" section
// on Context::complete(); the coro/middleware/next adapters guard with completion_count()/is_completed().
TEST_F(RouterErrorHandlingTest, CompleteAfterAsyncErrorChainLetsTheStrayCompleteWin) {
    set_error_chain({std::make_shared<CompletingTask>("ErrorChainHandler", _session, &_executor, qb::http::status::SERVICE_UNAVAILABLE,
                                                      "error-chain body", true)});

    _router->get("/double_complete_async", [this](std::shared_ptr<qb::http::Context<MockErrorSession>> ctx) {
        _session->record("DoubleCompleteHandler");
        _executor.addTask([ctx]() {
            ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            ctx->complete(qb::http::AsyncTaskResult::ERROR); // reseats to (deferred) error chain; does NOT finalize.
            // Stray late completion: context is still Running, so THIS finalizes first.
            ctx->response().status() = qb::http::status::OK;
            ctx->response().body()   = "late body that wins because the error chain is still in flight";
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        });
    });
    _router->compile();

    make_request(qb::http::method::GET, "/double_complete_async");

    EXPECT_TRUE(_session->_finalized);
    EXPECT_TRUE(ran("DoubleCompleteHandler"));
    // The error-chain handler still EXECUTES (it was already dispatched), but its complete() lands on
    // an already-Finalised context and is a no-op — so it never reaches the wire.
    EXPECT_TRUE(ran("ErrorChainHandler"));
    EXPECT_EQ(_session->_last_error_handler_name, "ErrorChainHandler")
        << "The error handler body ran (and recorded itself) before its no-op complete().";
    // First-to-finalize wins: the stray COMPLETE finalized before the deferred error chain could.
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "late body that wins because the error chain is still in flight");
}

// --- RouterCore::get_compiled_error_tasks() direct contract --------------------
//
// The accessor is normally consumed internally by Context only when a chain was
// explicitly set (is_error_chain_set() == true). Drive both arms directly through
// the exposed RouterCore so the nullptr (no-chain) and the materialised-list
// (chain-set) branches are both pinned.
TEST_F(RouterErrorHandlingTest, GetCompiledErrorTasksReflectsExplicitSet) {
    auto core = _router->get_router_core_weak_ptr().lock();
    ASSERT_TRUE(core) << "RouterCore must outlive the Router";

    // No chain ever set: accessor must report absence and return nullptr.
    EXPECT_FALSE(core->is_error_chain_set());
    EXPECT_EQ(core->get_compiled_error_tasks(), nullptr);

    // Explicitly set a non-empty chain.
    auto handler = std::make_shared<CompletingTask>("StandaloneErrorHandler", _session, &_executor);
    set_error_chain({handler});
    EXPECT_TRUE(core->is_error_chain_set());

    auto tasks = core->get_compiled_error_tasks();
    ASSERT_NE(tasks, nullptr) << "an explicitly-set chain materialises a shared, immutable list";
    EXPECT_EQ(tasks->size(), 1u);
    EXPECT_EQ((*tasks)[0], handler);
}

TEST_F(RouterErrorHandlingTest, GetCompiledErrorTasksHonoursExplicitlyEmptyChain) {
    auto core = _router->get_router_core_weak_ptr().lock();
    ASSERT_TRUE(core);

    // An explicitly-empty set still flips is_error_chain_set() true; the accessor
    // returns a non-null but empty list (NOT the nullptr no-chain sentinel).
    set_error_chain({});
    EXPECT_TRUE(core->is_error_chain_set());
    auto tasks = core->get_compiled_error_tasks();
    ASSERT_NE(tasks, nullptr);
    EXPECT_TRUE(tasks->empty());
}

} // namespace

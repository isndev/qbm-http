/**
 * @file qbm/http/tests/unit/routing/router-pipeline-integration.cpp
 * @brief End-to-end composition smoke for the qb-http routing pipeline.
 *
 * Composes every routing primitive at once — global middleware, nested groups,
 * controllers (mounted at top level and inside groups), sync/async lambda and
 * member handlers, custom routes, the 404 handler, and the error-task chain — then
 * drives requests through @ref qb::http::Router<Session> with the shared synchronous
 * @ref qb::http::test::TaskExecutor pump. Deterministic unit tier: no `qb::Main`, no
 * event loop, no socket.
 *
 * The legacy single 160-line `ComprehensiveScenario` was split here into one
 * `TEST_F` per scenario so a failure pinpoints the offending composition path
 * rather than failing the whole monolith. Full-trace equality is retained ONLY
 * where execution ORDER is the property under test; where the point is the matched
 * handler / status / body, those are asserted directly and the trace is left to the
 * order-focused cases.
 *
 * Static/param/wildcard precedence is NOT re-proven here — that is owned by
 * router-match.cpp (StaticOverParameter / StaticOverWildcard / ParameterOverWildcard).
 *
 * @author qb - C++ Actor Framework
 * @copyright Copyright (c) 2011-2026 qb - isndev (cpp.actor)
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * @ingroup Http
 */
#include <gtest/gtest.h>

#include <functional>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "../../shared/router_test_support.h" // qb::http::test::TaskExecutor
#include "../http.h"

using qb::http::test::TaskExecutor;

namespace {

// --- Mock session: captures the finalized Response + an execution trace. --------
struct MockAllInOneSession {
    qb::http::Response       _response;
    std::ostringstream       _execution_trace;
    bool                     _final_handler_called = false;
    qb::http::PathParameters _captured_params;
    std::string              _last_handler_id_executed;
    qb::http::status         _last_status_code_before_error_handler = qb::http::status::OK;

    qb::http::Response &
    get_response_ref() {
        return _response;
    }

    MockAllInOneSession &
    operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    void
    reset() {
        _response = qb::http::Response();
        _execution_trace.str("");
        _execution_trace.clear();
        _final_handler_called = false;
        _captured_params.clear();
        _last_handler_id_executed.clear();
        _last_status_code_before_error_handler = qb::http::status::OK;
    }

    void
    trace(const std::string &id) {
        if (!_execution_trace.str().empty()) {
            _execution_trace << ";";
        }
        _execution_trace << id;
    }

    [[nodiscard]] std::string
    get_trace() const {
        return _execution_trace.str();
    }
};

// --- Base helper for composable tasks (middleware / custom route). --------------
template <typename SessionType>
class BaseAllInOneTask {
public:
    BaseAllInOneTask(std::string id, TaskExecutor *executor, MockAllInOneSession *session_ptr)
        : _id(std::move(id))
        , _executor(executor)
        , _session_ptr(session_ptr) {}

    virtual ~BaseAllInOneTask() = default;

    [[nodiscard]] std::string
    get_id() const {
        return _id;
    }

protected:
    std::string          _id;
    TaskExecutor        *_executor;    ///< Nullable for sync tasks.
    MockAllInOneSession *_session_ptr; ///< To trace.

    void
    trace_exec(const std::string &point = "") {
        if (_session_ptr) {
            _session_ptr->trace(_id + (point.empty() ? "" : ("_" + point)));
        }
    }
};

// --- Composable middleware: CONTINUE / SHORT_CIRCUIT / SIGNAL_ERROR, sync/async. -
class AllInOneMiddleware
    : public BaseAllInOneTask<MockAllInOneSession>
    , public qb::http::IMiddleware<MockAllInOneSession> {
public:
    enum class Behavior { CONTINUE, SHORT_CIRCUIT, SIGNAL_ERROR };

    AllInOneMiddleware(std::string id, TaskExecutor *executor, MockAllInOneSession *session_ptr, bool is_async,
                       Behavior behavior = Behavior::CONTINUE, qb::http::status success_status = qb::http::status::OK,
                       std::string header_key = "", std::string header_val = "")
        : BaseAllInOneTask<MockAllInOneSession>(std::move(id), executor, session_ptr)
        , _is_async(is_async)
        , _behavior(behavior)
        , _success_status(success_status)
        , _header_key(std::move(header_key))
        , _header_val(std::move(header_val)) {}

    [[nodiscard]] std::string
    name() const override {
        return _id;
    }
    void
    cancel() override {
        trace_exec("cancelled");
    }

    void
    process(std::shared_ptr<qb::http::Context<MockAllInOneSession>> ctx) override {
        trace_exec("handle_entry");
        if (_is_async) {
            if (!_executor) {
                trace_exec("handle_NO_EXECUTOR_ERROR");
                ctx->complete(qb::http::AsyncTaskResult::ERROR);
                return;
            }
            auto shared_ctx = ctx;
            _executor->addTask([shared_ctx, this]() {
                trace_exec("task_exec");
                perform_action(shared_ctx);
            });
        } else {
            perform_action(ctx);
        }
    }

private:
    bool             _is_async;
    Behavior         _behavior;
    qb::http::status _success_status;
    std::string      _header_key;
    std::string      _header_val;

    void
    perform_action(std::shared_ptr<qb::http::Context<MockAllInOneSession>> ctx) {
        if (!_header_key.empty()) {
            if (_id == "MwSetsHeader") {
                ctx->request().set_header(_header_key, _header_val);
            } else {
                ctx->response().set_header(_header_key, _header_val);
            }
        }
        switch (_behavior) {
            case Behavior::SHORT_CIRCUIT:
                ctx->response().status() = _success_status;
                ctx->response().body()   = _id + " short-circuited.";
                ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
                break;
            case Behavior::SIGNAL_ERROR:
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->response().body()   = _id + " signaled error.";
                if (_session_ptr) {
                    _session_ptr->_last_status_code_before_error_handler = ctx->response().status();
                }
                ctx->complete(qb::http::AsyncTaskResult::ERROR);
                break;
            case Behavior::CONTINUE:
            default:
                ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
                break;
        }
    }
};

// --- Composable custom route: success/error, sync/async, captures params. -------
class AllInOneCustomRoute
    : public BaseAllInOneTask<MockAllInOneSession>
    , public qb::http::ICustomRoute<MockAllInOneSession> {
public:
    AllInOneCustomRoute(std::string id, TaskExecutor *executor, MockAllInOneSession *session_ptr, bool is_async, bool signal_error = false,
                        qb::http::status success_status = qb::http::status::OK, std::string response_body_prefix = "Response: ")
        : BaseAllInOneTask<MockAllInOneSession>(std::move(id), executor, session_ptr)
        , _is_async(is_async)
        , _signal_error(signal_error)
        , _success_status(success_status)
        , _response_body_prefix(std::move(response_body_prefix)) {}

    [[nodiscard]] std::string
    name() const override {
        return _id;
    }
    void
    cancel() override {
        trace_exec("cancelled");
    }

    void
    process(std::shared_ptr<qb::http::Context<MockAllInOneSession>> ctx) override {
        trace_exec("handle_entry");
        if (_is_async) {
            if (!_executor) {
                trace_exec("handle_NO_EXECUTOR_ERROR");
                if (_session_ptr) {
                    _session_ptr->_final_handler_called     = true;
                    _session_ptr->_last_handler_id_executed = _id + "_NO_EXECUTOR_ERROR";
                }
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                ctx->complete(qb::http::AsyncTaskResult::ERROR);
                return;
            }
            auto shared_ctx = ctx;
            _executor->addTask([shared_ctx, this]() {
                trace_exec("task_exec");
                perform_action(shared_ctx);
            });
        } else {
            perform_action(ctx);
        }
    }

private:
    bool             _is_async;
    bool             _signal_error;
    qb::http::status _success_status;
    std::string      _response_body_prefix;

    void
    perform_action(std::shared_ptr<qb::http::Context<MockAllInOneSession>> ctx) {
        if (_session_ptr) {
            _session_ptr->_final_handler_called     = true;
            _session_ptr->_last_handler_id_executed = _id;
            _session_ptr->_captured_params          = ctx->path_parameters();
        }
        ctx->response().body() = _response_body_prefix + _id;
        if (_signal_error) {
            ctx->response().status() = qb::http::status::EXPECTATION_FAILED;
            if (_session_ptr) {
                _session_ptr->_last_status_code_before_error_handler = ctx->response().status();
            }
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        } else {
            ctx->response().status() = _success_status;
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        }
    }
};

// --- Composable controller: sync/async lambda + member + custom routes. ---------
class AllInOneController : public qb::http::Controller<MockAllInOneSession> {
public:
    AllInOneController(std::string id_prefix, TaskExecutor *executor, MockAllInOneSession *session_ptr)
        : _id_prefix(std::move(id_prefix))
        , _executor(executor)
        , _session_ptr(session_ptr) {
        if (!_executor) {
            throw std::runtime_error("AllInOneController requires a non-null TaskExecutor.");
        }
        if (!_session_ptr) {
            throw std::runtime_error("AllInOneController requires a non-null MockAllInOneSession pointer.");
        }
    }

    void
    initialize_routes() override {
        this->use(std::make_shared<AllInOneMiddleware>(_id_prefix + "CtrlMwSync", nullptr, _session_ptr, false,
                                                       AllInOneMiddleware::Behavior::CONTINUE));
        this->use(std::make_shared<AllInOneMiddleware>(_id_prefix + "CtrlMwAsync", _executor, _session_ptr, true,
                                                       AllInOneMiddleware::Behavior::CONTINUE));

        this->get("/lambda_sync", [this](auto ctx) {
            _session_ptr->trace(_id_prefix + "LambdaSyncHandler");
            _session_ptr->_final_handler_called     = true;
            _session_ptr->_last_handler_id_executed = _id_prefix + "LambdaSyncHandler";
            ctx->response().body()                  = "Response: " + _id_prefix + "LambdaSyncHandler";
            ctx->response().status()                = qb::http::status::OK;
            ctx->complete();
        });

        this->post("/member_async", this, &AllInOneController::asyncMemberHandler);

        this->get<AllInOneCustomRoute>("/custom_sync", _id_prefix + "CtrlCustomSync", nullptr, _session_ptr, false);

        this->put<AllInOneCustomRoute>("/custom_async/:id", _id_prefix + "CtrlCustomAsyncWithParam", _executor, _session_ptr, true);

        this->get("/error_sync", [this](auto ctx) {
            _session_ptr->trace(_id_prefix + "ErrorSyncHandler");
            _session_ptr->_final_handler_called     = true;
            _session_ptr->_last_handler_id_executed = _id_prefix + "ErrorSyncHandler";
            ctx->response().status()                = qb::http::status::BAD_REQUEST;
            if (_session_ptr) {
                _session_ptr->_last_status_code_before_error_handler = ctx->response().status();
            }
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    }

    void
    asyncMemberHandler(std::shared_ptr<qb::http::Context<MockAllInOneSession>> ctx) {
        _session_ptr->trace(_id_prefix + "AsyncMemberHandler_entry");
        auto shared_ctx = ctx;
        _executor->addTask([shared_ctx, this]() {
            _session_ptr->trace(_id_prefix + "AsyncMemberHandler_task");
            _session_ptr->_final_handler_called     = true;
            _session_ptr->_last_handler_id_executed = _id_prefix + "AsyncMemberHandler";
            shared_ctx->response().body()           = "Response: " + _id_prefix + "AsyncMemberHandler";
            shared_ctx->response().status()         = qb::http::status::ACCEPTED;
            shared_ctx->complete();
        });
    }

    [[nodiscard]] std::string
    get_node_name() const override {
        return "AllInOneController_" + _id_prefix;
    }

private:
    std::string          _id_prefix;
    TaskExecutor        *_executor;
    MockAllInOneSession *_session_ptr;
};

// --- Fixture -------------------------------------------------------------------
class RouterPipelineTest : public ::testing::Test {
protected:
    std::shared_ptr<MockAllInOneSession>                   _session;
    std::unique_ptr<qb::http::Router<MockAllInOneSession>> _router;
    TaskExecutor                                           _task_executor;

    void
    SetUp() override {
        _session = std::make_shared<MockAllInOneSession>();
        _router  = std::make_unique<qb::http::Router<MockAllInOneSession>>();
        _task_executor.clearTasks();
    }

    qb::http::Request
    create_request(qb::http::method method_val, const std::string &target_path) {
        qb::http::Request req;
        req.method() = method_val;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "URI parse failure in create_request: " << target_path << " (" << e.what() << ")";
            req.uri() = qb::io::uri("/_ERROR_URI_");
        }
        req.major_version = 1;
        req.minor_version = 1;
        return req;
    }

    void
    make_request_and_process(qb::http::method method_val, const std::string &path_str) {
        _session->reset();
        _task_executor.clearTasks();
        _router->route(_session, create_request(method_val, path_str));
        while (_task_executor.hasTasks()) {
            _task_executor.processAllTasks();
        }
    }

    // Mounts the full composition shared by the per-scenario tests: global MWs,
    // groupA (+ async custom route), nested groupB with controllerB, a top-level
    // controllerTop, a custom 404 handler, and an error chain. Returns nothing —
    // the router is left compiled and ready.
    void
    build_full_pipeline() {
        // 1. Global middleware (sync + async).
        _router->use(
            std::make_shared<AllInOneMiddleware>("GlobalSyncMw", nullptr, _session.get(), false, AllInOneMiddleware::Behavior::CONTINUE));
        _router->use(std::make_shared<AllInOneMiddleware>("GlobalAsyncMw", &_task_executor, _session.get(), true,
                                                          AllInOneMiddleware::Behavior::CONTINUE));

        // 2. groupA + its middleware.
        auto groupA = _router->group("/groupA");
        groupA->use(
            std::make_shared<AllInOneMiddleware>("GroupASyncMw", nullptr, _session.get(), false, AllInOneMiddleware::Behavior::CONTINUE));
        groupA->use(std::make_shared<AllInOneMiddleware>("GroupAAsyncMw", &_task_executor, _session.get(), true,
                                                         AllInOneMiddleware::Behavior::CONTINUE));

        groupA->get("/direct_sync", [this](auto ctx) {
            _session->trace("GroupADirectSyncHandler");
            _session->_final_handler_called     = true;
            _session->_last_handler_id_executed = "GroupADirectSyncHandler";
            ctx->response().body()              = "Response: GroupADirectSyncHandler";
            ctx->response().status()            = qb::http::status::OK;
            ctx->complete();
        });
        groupA->get<AllInOneCustomRoute>("/custom_async_in_A", "GroupACustomAsync", &_task_executor, _session.get(), true);

        // 3. Nested groupB + controllerB.
        auto groupB = groupA->group("/groupB");
        groupB->use(
            std::make_shared<AllInOneMiddleware>("GroupBSyncMw", nullptr, _session.get(), false, AllInOneMiddleware::Behavior::CONTINUE));
        (void) groupB->template controller<AllInOneController>("/controllerB", "CtrlB_", &_task_executor, _session.get());

        // 4. Top-level controller.
        (void) _router->template controller<AllInOneController>("/controllerTop", "CtrlTop_", &_task_executor, _session.get());

        // 5. 404 + error chain.
        _router->set_not_found_handler([this](auto ctx) {
            _session->trace("CustomRouter404Handler");
            ctx->response().status() = qb::http::status::NOT_FOUND;
            ctx->response().body()   = "Custom Router 404 Page";
            ctx->complete();
        });

        std::vector<std::shared_ptr<qb::http::IAsyncTask<MockAllInOneSession>>> error_chain;
        error_chain.push_back(std::make_shared<qb::http::MiddlewareTask<MockAllInOneSession>>(
            std::make_shared<AllInOneMiddleware>("ErrorChainMwSync", nullptr, _session.get(), false, AllInOneMiddleware::Behavior::CONTINUE,
                                                 qb::http::status::OK, "X-Error-Chain", "Processed")));
        error_chain.push_back(std::make_shared<qb::http::CustomRouteAdapterTask<MockAllInOneSession>>(std::make_shared<AllInOneCustomRoute>(
            "ErrorChainFinalHandler", nullptr, _session.get(), false, false, qb::http::status::INTERNAL_SERVER_ERROR, "Error Handled By: ")));
        _router->set_error_task_chain(error_chain);

        ASSERT_NO_THROW(_router->compile());
    }
};

// --- Per-scenario composition smoke (was: ComprehensiveScenario, split). --------

TEST_F(RouterPipelineTest, GroupADirectSyncRouteFullChainOrder) {
    build_full_pipeline();
    make_request_and_process(qb::http::method::GET, "/groupA/direct_sync");

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: GroupADirectSyncHandler");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "GroupADirectSyncHandler");
    // Order IS the property here: global (sync, async) -> groupA (sync, async) -> handler.
    EXPECT_EQ(_session->get_trace(), "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;GroupASyncMw_handle_entry;"
                                     "GroupAAsyncMw_handle_entry;GroupAAsyncMw_task_exec;GroupADirectSyncHandler");
}

TEST_F(RouterPipelineTest, GroupAAsyncCustomRoute) {
    build_full_pipeline();
    make_request_and_process(qb::http::method::GET, "/groupA/custom_async_in_A");

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: GroupACustomAsync");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "GroupACustomAsync");
}

TEST_F(RouterPipelineTest, NestedControllerSyncLambdaRouteFullChainOrder) {
    build_full_pipeline();
    make_request_and_process(qb::http::method::GET, "/groupA/groupB/controllerB/lambda_sync");

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: CtrlB_LambdaSyncHandler");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "CtrlB_LambdaSyncHandler");
    // Order through 4 layers: globals -> groupA -> groupB -> controllerB MWs -> handler.
    EXPECT_EQ(_session->get_trace(), "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;GroupASyncMw_handle_entry;"
                                     "GroupAAsyncMw_handle_entry;GroupAAsyncMw_task_exec;GroupBSyncMw_handle_entry;CtrlB_CtrlMwSync_handle_"
                                     "entry;CtrlB_CtrlMwAsync_handle_entry;CtrlB_CtrlMwAsync_task_exec;CtrlB_LambdaSyncHandler");
}

TEST_F(RouterPipelineTest, NestedControllerAsyncMemberHandler) {
    build_full_pipeline();
    make_request_and_process(qb::http::method::POST, "/groupA/groupB/controllerB/member_async");

    EXPECT_EQ(_session->_response.status(), qb::http::status::ACCEPTED);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: CtrlB_AsyncMemberHandler");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "CtrlB_AsyncMemberHandler");
}

TEST_F(RouterPipelineTest, NestedControllerAsyncCustomRouteCapturesPathParam) {
    build_full_pipeline();
    make_request_and_process(qb::http::method::PUT, "/groupA/groupB/controllerB/custom_async/p123");

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: CtrlB_CtrlCustomAsyncWithParam");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "CtrlB_CtrlCustomAsyncWithParam");
    ASSERT_TRUE(_session->_captured_params.get("id").has_value());
    EXPECT_EQ(_session->_captured_params.get("id").value(), "p123");
}

TEST_F(RouterPipelineTest, TopLevelControllerSyncCustomRoute) {
    build_full_pipeline();
    make_request_and_process(qb::http::method::GET, "/controllerTop/custom_sync");

    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: CtrlTop_CtrlCustomSync");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "CtrlTop_CtrlCustomSync");
}

TEST_F(RouterPipelineTest, NotFoundRunsGlobalMiddlewareThenCustom404) {
    build_full_pipeline();
    make_request_and_process(qb::http::method::GET, "/this/path/does/not/exist");

    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Custom Router 404 Page");
    EXPECT_FALSE(_session->_final_handler_called);
    // Global middleware runs before the 404 handler is dispatched; group MWs do not.
    EXPECT_EQ(_session->get_trace(), "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;CustomRouter404Handler");
}

TEST_F(RouterPipelineTest, ControllerHandlerErrorRoutedThroughErrorChain) {
    build_full_pipeline();
    make_request_and_process(qb::http::method::GET, "/controllerTop/error_sync");

    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Error Handled By: ErrorChainFinalHandler");
    EXPECT_EQ(_session->_last_status_code_before_error_handler, qb::http::status::BAD_REQUEST);
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "ErrorChainFinalHandler");
    // The error-chain middleware's response header survives to the final response.
    EXPECT_EQ(_session->_response.header("X-Error-Chain"), "Processed");
    // Order: globals -> controllerTop MWs -> erroring handler -> error chain.
    EXPECT_EQ(_session->get_trace(), "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;CtrlTop_CtrlMwSync_handle_"
                                     "entry;CtrlTop_CtrlMwAsync_handle_entry;CtrlTop_CtrlMwAsync_task_exec;CtrlTop_ErrorSyncHandler;"
                                     "ErrorChainMwSync_handle_entry;ErrorChainFinalHandler_handle_entry");
}

// Short-circuit by a global middleware: standalone composition (the legacy
// ComprehensiveScenario rebuilt the router mid-test for this — now its own fixture
// instance keeps it isolated).
TEST_F(RouterPipelineTest, GlobalMiddlewareShortCircuitSkipsHandler) {
    _router->use(std::make_shared<AllInOneMiddleware>("GlobalShortCircuitMw", nullptr, _session.get(), false,
                                                      AllInOneMiddleware::Behavior::SHORT_CIRCUIT, qb::http::status::ACCEPTED));
    _router->get("/should_not_be_reached", [this](auto ctx) {
        _session->trace("UnreachableHandler");
        ctx->complete();
    });
    _router->compile();

    make_request_and_process(qb::http::method::GET, "/should_not_be_reached");
    EXPECT_EQ(_session->_response.status(), qb::http::status::ACCEPTED);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "GlobalShortCircuitMw short-circuited.");
    EXPECT_EQ(_session->get_trace(), "GlobalShortCircuitMw_handle_entry");
    EXPECT_FALSE(_session->_final_handler_called);
}

// --- Wildcard capture through groups and controllers ---------------------------
// (Precedence — static>param>wildcard — is owned by router-match.cpp; this case
//  only proves that a wildcard segment is captured correctly through a controller
//  and through a group, including a multi-segment tail.)

TEST_F(RouterPipelineTest, WildcardCaptureInControllerAndGroup) {
    class WildcardController : public qb::http::Controller<MockAllInOneSession> {
    public:
        explicit WildcardController(MockAllInOneSession *session_ptr)
            : _session_ptr_wc(session_ptr) {}

        void
        initialize_routes() override {
            this->get("/content/*path", [this](auto ctx) {
                if (_session_ptr_wc) {
                    _session_ptr_wc->trace("WildcardController_content_path");
                    _session_ptr_wc->_final_handler_called     = true;
                    _session_ptr_wc->_last_handler_id_executed = "WildcardController_content_path";
                    _session_ptr_wc->_captured_params          = ctx->path_parameters();
                }
                ctx->response().body()   = "CtrlWildcardPath: " + std::string(ctx->path_param("path"));
                ctx->response().status() = qb::http::status::OK;
                ctx->complete();
            });
        }

        [[nodiscard]] std::string
        get_node_name() const override {
            return "WildcardController";
        }

        MockAllInOneSession *_session_ptr_wc;
    };

    (void) _router->template controller<WildcardController>("/wc_ctrl", _session.get());

    auto data_group = _router->group("/data");
    data_group->use(
        std::make_shared<AllInOneMiddleware>("DataGroupMw", nullptr, _session.get(), false, AllInOneMiddleware::Behavior::CONTINUE));
    data_group->get("/content/*filepath", [this](auto ctx) {
        _session->trace("DataGroup_content_handler");
        _session->_final_handler_called     = true;
        _session->_last_handler_id_executed = "DataGroup_content_handler";
        _session->_captured_params          = ctx->path_parameters();
        ctx->response().body()              = "DataGroup File: " + std::string(ctx->path_param("filepath"));
        ctx->response().status()            = qb::http::status::OK;
        ctx->complete();
    });

    ASSERT_NO_THROW(_router->compile());

    // Controller wildcard captures a multi-segment tail.
    make_request_and_process(qb::http::method::GET, "/wc_ctrl/content/folder/file.txt");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "CtrlWildcardPath: folder/file.txt");
    EXPECT_EQ(_session->_captured_params.get("path").value(), "folder/file.txt");
    EXPECT_EQ(_session->get_trace(), "WildcardController_content_path");

    // Group wildcard captures its own multi-segment tail, with group MW running first.
    make_request_and_process(qb::http::method::GET, "/data/content/reports/annual.pdf");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "DataGroup File: reports/annual.pdf");
    ASSERT_TRUE(_session->_captured_params.get("filepath").has_value());
    EXPECT_EQ(_session->_captured_params.get("filepath").value(), "reports/annual.pdf");
    EXPECT_EQ(_session->get_trace(), "DataGroupMw_handle_entry;DataGroup_content_handler");
}

// --- Two same-type controllers + global MW isolation ---------------------------

TEST_F(RouterPipelineTest, MultipleControllersIsolatedWithSharedGlobalMiddleware) {
    auto controller1 = _router->template controller<AllInOneController>("/serviceA", "SvcA_", &_task_executor, _session.get());
    controller1->use(std::make_shared<AllInOneMiddleware>("SvcACtrlSpecificMw", nullptr, _session.get(), false,
                                                          AllInOneMiddleware::Behavior::CONTINUE, qb::http::status::OK, "X-SvcA-Ctrl",
                                                          "SetBySvcACtrlMw"));

    auto controller2 = _router->template controller<AllInOneController>("/serviceB", "SvcB_", &_task_executor, _session.get());
    controller2->use(std::make_shared<AllInOneMiddleware>("SvcBCtrlSpecificMw", nullptr, _session.get(), false,
                                                          AllInOneMiddleware::Behavior::CONTINUE, qb::http::status::OK, "X-SvcB-Ctrl",
                                                          "SetBySvcBCtrlMw"));

    _router->use(
        std::make_shared<AllInOneMiddleware>("MultiCtrlTestGlobalMw", nullptr, _session.get(), false, AllInOneMiddleware::Behavior::CONTINUE));

    ASSERT_NO_THROW(_router->compile());

    // Request to A: only A's controller-specific MW header appears.
    make_request_and_process(qb::http::method::GET, "/serviceA/lambda_sync");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: SvcA_LambdaSyncHandler");
    EXPECT_EQ(_session->_response.header("X-SvcA-Ctrl"), "SetBySvcACtrlMw");
    EXPECT_TRUE(_session->_response.header("X-SvcB-Ctrl").empty());
    EXPECT_EQ(_session->_last_handler_id_executed, "SvcA_LambdaSyncHandler");

    // Request to B: only B's controller-specific MW header appears.
    make_request_and_process(qb::http::method::POST, "/serviceB/member_async");
    EXPECT_EQ(_session->_response.status(), qb::http::status::ACCEPTED);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: SvcB_AsyncMemberHandler");
    EXPECT_EQ(_session->_response.header("X-SvcB-Ctrl"), "SetBySvcBCtrlMw");
    EXPECT_TRUE(_session->_response.header("X-SvcA-Ctrl").empty());
    EXPECT_EQ(_session->_last_handler_id_executed, "SvcB_AsyncMemberHandler");
}

// --- Error in a controller's own middleware → router error chain ----------------

TEST_F(RouterPipelineTest, ErrorInControllerMiddlewareRoutedToRouterErrorChain) {
    class ControllerWithErrorMw : public qb::http::Controller<MockAllInOneSession> {
    public:
        ControllerWithErrorMw(MockAllInOneSession *session_ptr, TaskExecutor *executor)
            : _session_ptr_err(session_ptr) {
            this->use(std::make_shared<AllInOneMiddleware>("CtrlErrorMw", executor, _session_ptr_err, false,
                                                           AllInOneMiddleware::Behavior::SIGNAL_ERROR));
            this->get("/path", [this](auto ctx) {
                if (_session_ptr_err) {
                    _session_ptr_err->trace("CtrlErrorMw_PathHandlerNeverReached");
                }
                ctx->complete();
            });
        }

        void
        initialize_routes() override {}

        [[nodiscard]] std::string
        get_node_name() const override {
            return "ControllerWithErrorMw";
        }

        MockAllInOneSession *_session_ptr_err;
    };

    (void) _router->template controller<ControllerWithErrorMw>("/ctrl_err_mw", _session.get(), &_task_executor);

    std::vector<std::shared_ptr<qb::http::IAsyncTask<MockAllInOneSession>>> error_chain;
    error_chain.push_back(std::make_shared<qb::http::CustomRouteAdapterTask<MockAllInOneSession>>(
        std::make_shared<AllInOneCustomRoute>("MainRouterErrorHandlerForCtrlMwError", nullptr, _session.get(), false, false,
                                              qb::http::status::SERVICE_UNAVAILABLE, "RouterHandledCtrlMwError: ")));
    _router->set_error_task_chain(error_chain);

    _router->use(
        std::make_shared<AllInOneMiddleware>("GlobalMwForCtrlErrTest", nullptr, _session.get(), false, AllInOneMiddleware::Behavior::CONTINUE));

    ASSERT_NO_THROW(_router->compile());

    make_request_and_process(qb::http::method::GET, "/ctrl_err_mw/path");
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "RouterHandledCtrlMwError: MainRouterErrorHandlerForCtrlMwError");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "MainRouterErrorHandlerForCtrlMwError");
    EXPECT_EQ(_session->get_trace(),
              "GlobalMwForCtrlErrTest_handle_entry;CtrlErrorMw_handle_entry;MainRouterErrorHandlerForCtrlMwError_handle_entry");
}

// --- Error WITHIN the error chain is fatal (default 500) ------------------------

TEST_F(RouterPipelineTest, ErrorWithinErrorChainIsFatal) {
    _router->get("/trigger_initial_error", [this](auto ctx) {
        _session->trace("InitialErrorHandler");
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    });

    std::vector<std::shared_ptr<qb::http::IAsyncTask<MockAllInOneSession>>> faulty_error_chain;
    faulty_error_chain.push_back(std::make_shared<qb::http::MiddlewareTask<MockAllInOneSession>>(
        std::make_shared<AllInOneMiddleware>("FaultyErrorChainMw1", nullptr, _session.get(), false, AllInOneMiddleware::Behavior::CONTINUE)));
    faulty_error_chain.push_back(std::make_shared<qb::http::MiddlewareTask<MockAllInOneSession>>(std::make_shared<AllInOneMiddleware>(
        "FaultyErrorChainMw2_SignalsError", nullptr, _session.get(), false, AllInOneMiddleware::Behavior::SIGNAL_ERROR)));
    faulty_error_chain.push_back(std::make_shared<qb::http::MiddlewareTask<MockAllInOneSession>>(std::make_shared<AllInOneMiddleware>(
        "FaultyErrorChainMw3_NeverReached", nullptr, _session.get(), false, AllInOneMiddleware::Behavior::CONTINUE)));
    _router->set_error_task_chain(faulty_error_chain);

    _router->use(std::make_shared<AllInOneMiddleware>("GlobalMwForFaultyErrorChainTest", nullptr, _session.get(), false,
                                                      AllInOneMiddleware::Behavior::CONTINUE));

    ASSERT_NO_THROW(_router->compile());

    make_request_and_process(qb::http::method::GET, "/trigger_initial_error");
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "FaultyErrorChainMw2_SignalsError signaled error.");
    EXPECT_FALSE(_session->_final_handler_called);
    EXPECT_EQ(_session->get_trace().find("FaultyErrorChainMw3_NeverReached"), std::string::npos)
        << "The chain task after the fatal one must not run.";
    // Order matters here: the chain ran up to and including the erroring MW, no further.
    EXPECT_EQ(_session->get_trace(), "GlobalMwForFaultyErrorChainTest_handle_entry;InitialErrorHandler;FaultyErrorChainMw1_handle_entry;"
                                     "FaultyErrorChainMw2_SignalsError_handle_entry");
}

// --- Middleware mutates the request for downstream tasks ------------------------

TEST_F(RouterPipelineTest, MiddlewareModifiesRequestForSubsequentTasks) {
    _router->use(std::make_shared<AllInOneMiddleware>("MwSetsHeader", nullptr, _session.get(), false, AllInOneMiddleware::Behavior::CONTINUE,
                                                      qb::http::status::OK, "X-Test-Data", "SetByMw"));

    _router->use(
        [this](std::shared_ptr<qb::http::Context<MockAllInOneSession>> ctx, std::function<void()> next) {
            const bool condition_met = (std::string(ctx->request().header("X-Test-Data")) == "SetByMw");
            if (condition_met) {
                _session->trace("MwReadsHeaderCorrectly");
                ctx->response().set_header("X-Mw-Confirmation", "HeaderRead");
            }
            next();
        },
        "FunctionalMwChecksHeader");

    _router->get("/mw_data_flow", [this](auto ctx) {
        _session->trace("FinalHandlerForDataFlow");
        EXPECT_EQ(ctx->request().header("X-Test-Data"), "SetByMw");
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });

    _router->compile();
    make_request_and_process(qb::http::method::GET, "/mw_data_flow");

    // The downstream MW saw the header the first MW set on the REQUEST.
    EXPECT_EQ(_session->get_trace(), "MwSetsHeader_handle_entry;MwReadsHeaderCorrectly;FinalHandlerForDataFlow");
    EXPECT_EQ(_session->_response.header("X-Mw-Confirmation"), "HeaderRead");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

} // namespace

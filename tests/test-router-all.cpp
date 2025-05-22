#include <gtest/gtest.h>
#include "../http.h" // Main include for all qb::http components
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <sstream>
#include <list>
#include <stdexcept> // For std::runtime_error

// --- Helper: TaskExecutor ---
class TaskExecutor {
public:
    void addTask(std::function<void()> task) {
        _tasks.push_back(std::move(task));
    }

    void processAllTasks() {
        while (!_tasks.empty()) {
            // Keep processing as long as tasks are being added
            std::vector<std::function<void()> > tasks_to_process = _tasks;
            _tasks.clear(); // Clear before processing to allow new tasks to be queued cleanly
            for (auto &task: tasks_to_process) {
                if (task) task();
            }
        }
    }

    size_t getPendingTaskCount() const {
        return _tasks.size();
    }

    void clearTasks() {
        _tasks.clear();
    }

private:
    std::vector<std::function<void()> > _tasks;
};

// --- Helper: MockAllInOneSession ---
struct MockAllInOneSession {
    qb::http::Response _response;
    std::string _session_id_str = "session_all_in_one_"; // Placeholder, qb::uuid might not be in http.h
    std::ostringstream _execution_trace;
    bool _final_handler_called = false;
    qb::http::PathParameters _captured_params;
    std::string _last_handler_id_executed;
    qb::http::status _last_status_code_before_error_handler = qb::http::status::OK;


    MockAllInOneSession() {
        // Simple unique ID generation if qb::uuid is not available/problematic
        static int instance_count = 0;
        _session_id_str += std::to_string(++instance_count);
    }

    qb::http::Response &get_response_ref() { return _response; }

    MockAllInOneSession &operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    [[nodiscard]] const std::string &id_str() const { return _session_id_str; } // Changed from id()

    void reset() {
        _response = qb::http::Response();
        _execution_trace.str("");
        _execution_trace.clear();
        _final_handler_called = false;
        _captured_params.clear();
        _last_handler_id_executed.clear();
        _last_status_code_before_error_handler = qb::http::status::OK;
    }

    void trace(const std::string &id) {
        if (!_execution_trace.str().empty()) {
            _execution_trace << ";";
        }
        _execution_trace << id;
    }

    std::string get_trace() const {
        return _execution_trace.str();
    }
};

// --- Base Helper for Tasks (Middleware/CustomRoute) ---
template<typename SessionType>
class BaseAllInOneTask {
public:
    BaseAllInOneTask(std::string id, TaskExecutor *executor, MockAllInOneSession *session_ptr)
        : _id(std::move(id)), _executor(executor), _session_ptr(session_ptr) {
    }

    virtual ~BaseAllInOneTask() = default;

    std::string get_id() const { return _id; }

protected:
    std::string _id;
    TaskExecutor *_executor; // Nullable for sync tasks
    MockAllInOneSession *_session_ptr; // To trace

    void trace_exec(const std::string &point = "") {
        if (_session_ptr) {
            _session_ptr->trace(_id + (point.empty() ? "" : ("_" + point)));
        }
    }
};

// --- Helper: AllInOneMiddleware ---
class AllInOneMiddleware : public BaseAllInOneTask<MockAllInOneSession>,
                           public qb::http::IMiddleware<MockAllInOneSession> {
public:
    enum class Behavior { CONTINUE, SHORT_CIRCUIT, SIGNAL_ERROR };

    AllInOneMiddleware(std::string id, TaskExecutor *executor, MockAllInOneSession *session_ptr,
                       bool is_async, Behavior behavior = Behavior::CONTINUE,
                       qb::http::status success_status = qb::http::status::OK,
                       std::string header_key = "", std::string header_val = "")
        : BaseAllInOneTask<MockAllInOneSession>(std::move(id), executor, session_ptr),
          _is_async(is_async), _behavior(behavior), _success_status(success_status),
          _header_key(std::move(header_key)), _header_val(std::move(header_val)) {
    }

    std::string name() const override { return _id; }
    void cancel() override { trace_exec("cancelled"); }

    void process(std::shared_ptr<qb::http::Context<MockAllInOneSession> > ctx) override {
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
    bool _is_async;
    Behavior _behavior;
    qb::http::status _success_status;
    std::string _header_key;
    std::string _header_val;

    void perform_action(std::shared_ptr<qb::http::Context<MockAllInOneSession> > ctx) {
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
                ctx->response().body() = _id + " short-circuited.";
                ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
                break;
            case Behavior::SIGNAL_ERROR:
                ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR; // Default error status
                ctx->response().body() = _id + " signaled error.";
                if (_session_ptr) _session_ptr->_last_status_code_before_error_handler = ctx->response().status();
                ctx->complete(qb::http::AsyncTaskResult::ERROR);
                break;
            case Behavior::CONTINUE:
            default:
                ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
                break;
        }
    }
};

// --- Helper: AllInOneCustomRoute ---
class AllInOneCustomRoute : public BaseAllInOneTask<MockAllInOneSession>,
                            public qb::http::ICustomRoute<MockAllInOneSession> {
public:
    AllInOneCustomRoute(std::string id, TaskExecutor *executor, MockAllInOneSession *session_ptr,
                        bool is_async, bool signal_error = false,
                        qb::http::status success_status = qb::http::status::OK,
                        std::string response_body_prefix = "Response: ")
        : BaseAllInOneTask<MockAllInOneSession>(std::move(id), executor, session_ptr),
          _is_async(is_async), _signal_error(signal_error), _success_status(success_status),
          _response_body_prefix(std::move(response_body_prefix)) {
    }

    std::string name() const override { return _id; }
    void cancel() override { trace_exec("cancelled"); }

    void process(std::shared_ptr<qb::http::Context<MockAllInOneSession> > ctx) override {
        trace_exec("handle_entry");
        if (_is_async) {
            if (!_executor) {
                trace_exec("handle_NO_EXECUTOR_ERROR");
                if (_session_ptr) {
                    _session_ptr->_final_handler_called = true; // mark attempt
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
    bool _is_async;
    bool _signal_error;
    qb::http::status _success_status;
    std::string _response_body_prefix;

    void perform_action(std::shared_ptr<qb::http::Context<MockAllInOneSession> > ctx) {
        if (_session_ptr) {
            _session_ptr->_final_handler_called = true;
            _session_ptr->_last_handler_id_executed = _id;
            _session_ptr->_captured_params = ctx->path_parameters();
        }

        ctx->response().body() = _response_body_prefix + _id;
        if (_signal_error) {
            ctx->response().status() = qb::http::status::EXPECTATION_FAILED; // Default error status for custom route
            if (_session_ptr) _session_ptr->_last_status_code_before_error_handler = ctx->response().status();
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        } else {
            ctx->response().status() = _success_status;
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        }
    }
};

// --- Helper: AllInOneController ---
class AllInOneController : public qb::http::Controller<MockAllInOneSession> {
public:
    AllInOneController(std::string id_prefix, TaskExecutor *executor, MockAllInOneSession *session_ptr)
        : _id_prefix(std::move(id_prefix)), _executor(executor), _session_ptr(session_ptr) {
        if (!_executor) throw std::runtime_error("AllInOneController requires a non-null TaskExecutor.");
        if (!_session_ptr) throw std::runtime_error(
            "AllInOneController requires a non-null MockAllInOneSession pointer.");
    }

    void initialize_routes() override {
        // Controller-specific middleware
        this->use(std::make_shared<AllInOneMiddleware>(_id_prefix + "CtrlMwSync", nullptr, _session_ptr, false,
                                                       AllInOneMiddleware::Behavior::CONTINUE));
        this->use(std::make_shared<AllInOneMiddleware>(_id_prefix + "CtrlMwAsync", _executor, _session_ptr, true,
                                                       AllInOneMiddleware::Behavior::CONTINUE));

        // Lambda route (sync)
        this->get("/lambda_sync", [this](auto ctx) {
            _session_ptr->trace(_id_prefix + "LambdaSyncHandler");
            _session_ptr->_final_handler_called = true;
            _session_ptr->_last_handler_id_executed = _id_prefix + "LambdaSyncHandler";
            ctx->response().body() = "Response: " + _id_prefix + "LambdaSyncHandler";
            ctx->response().status() = qb::http::status::OK;
            ctx->complete();
        });

        // Member handler route (async)
        this->post("/member_async", MEMBER_HANDLER(&AllInOneController::asyncMemberHandler));

        // Custom Route (sync)
        this->get<AllInOneCustomRoute>("/custom_sync", _id_prefix + "CtrlCustomSync", nullptr, _session_ptr, false);

        // Custom Route (async with param)
        this->put<AllInOneCustomRoute>("/custom_async/:id", _id_prefix + "CtrlCustomAsyncWithParam", _executor,
                                       _session_ptr, true);

        // Route that signals error (sync)
        this->get("/error_sync", [this](auto ctx) {
            _session_ptr->trace(_id_prefix + "ErrorSyncHandler");
            _session_ptr->_final_handler_called = true; // it was called
            _session_ptr->_last_handler_id_executed = _id_prefix + "ErrorSyncHandler";
            ctx->response().status() = qb::http::status::BAD_REQUEST; // status before error
            if (_session_ptr) _session_ptr->_last_status_code_before_error_handler = ctx->response().status();
            ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    }

    void asyncMemberHandler(std::shared_ptr<qb::http::Context<MockAllInOneSession> > ctx) {
        _session_ptr->trace(_id_prefix + "AsyncMemberHandler_entry");
        auto shared_ctx = ctx;
        _executor->addTask([shared_ctx, this]() {
            _session_ptr->trace(_id_prefix + "AsyncMemberHandler_task");
            _session_ptr->_final_handler_called = true;
            _session_ptr->_last_handler_id_executed = _id_prefix + "AsyncMemberHandler";
            shared_ctx->response().body() = "Response: " + _id_prefix + "AsyncMemberHandler";
            shared_ctx->response().status() = qb::http::status::ACCEPTED;
            shared_ctx->complete();
        });
    }

    std::string get_node_name() const override { return "AllInOneController_" + _id_prefix; }

private:
    std::string _id_prefix;
    TaskExecutor *_executor;
    MockAllInOneSession *_session_ptr;
};

// --- Test Fixture ---
class RouterAllInOneTest : public ::testing::Test {
protected:
    std::shared_ptr<MockAllInOneSession> _session;
    std::unique_ptr<qb::http::Router<MockAllInOneSession> > _router;
    TaskExecutor _task_executor;

    void SetUp() override {
        _session = std::make_shared<MockAllInOneSession>();
        _router = std::make_unique<qb::http::Router<MockAllInOneSession> >();
        _task_executor.clearTasks();
    }

    qb::http::Request create_request(qb::http::method method_val, const std::string &target_path) {
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

    void make_request_and_process(qb::http::method method_val, const std::string &path_str) {
        _session->reset();
        _task_executor.clearTasks();
        _router->route(_session, create_request(method_val, path_str));
        _task_executor.processAllTasks(); // Process all tasks until the queue is empty
    }
};

// --- Comprehensive Test Case ---
TEST_F(RouterAllInOneTest, ComprehensiveScenario) {
    // 1. Router-level (Global) Middleware
    _router->use(std::make_shared<AllInOneMiddleware>("GlobalSyncMw", nullptr, _session.get(), false,
                                                      AllInOneMiddleware::Behavior::CONTINUE));
    _router->use(std::make_shared<AllInOneMiddleware>("GlobalAsyncMw", &_task_executor, _session.get(), true,
                                                      AllInOneMiddleware::Behavior::CONTINUE));

    // 2. Top-level Group: groupA
    auto groupA = _router->group("/groupA");
    ASSERT_NE(groupA, nullptr);
    groupA->use(std::make_shared<AllInOneMiddleware>("GroupASyncMw", nullptr, _session.get(), false,
                                                     AllInOneMiddleware::Behavior::CONTINUE));
    groupA->use(std::make_shared<AllInOneMiddleware>("GroupAAsyncMw", &_task_executor, _session.get(), true,
                                                     AllInOneMiddleware::Behavior::CONTINUE));

    // Direct route in groupA
    groupA->get("/direct_sync", [this](auto ctx) {
        _session->trace("GroupADirectSyncHandler");
        _session->_final_handler_called = true;
        _session->_last_handler_id_executed = "GroupADirectSyncHandler";
        ctx->response().body() = "Response: GroupADirectSyncHandler";
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });

    // Custom async route in groupA
    groupA->get<AllInOneCustomRoute>("/custom_async_in_A", "GroupACustomAsync", &_task_executor, _session.get(), true);

    // 3. Nested Group: groupB in groupA
    auto groupB = groupA->group("/groupB");
    ASSERT_NE(groupB, nullptr);
    groupB->use(std::make_shared<AllInOneMiddleware>("GroupBSyncMw", nullptr, _session.get(), false,
                                                     AllInOneMiddleware::Behavior::CONTINUE));

    // Mount AllInOneController in groupB
    auto controllerB = groupB->template controller<AllInOneController>("/controllerB", "CtrlB_", &_task_executor,
                                                                       _session.get());
    ASSERT_NE(controllerB, nullptr);

    // 4. Top-level Controller: controllerTop
    auto controllerTop = _router->template controller<AllInOneController>(
        "/controllerTop", "CtrlTop_", &_task_executor, _session.get());
    ASSERT_NE(controllerTop, nullptr);

    // 5. Router-level 404 and Error Handlers
    _router->set_not_found_handler([this](auto ctx) {
        _session->trace("CustomRouter404Handler");
        ctx->response().status() = qb::http::status::NOT_FOUND;
        ctx->response().body() = "Custom Router 404 Page";
        ctx->complete();
    });

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockAllInOneSession> > > error_chain;
    error_chain.push_back(
        std::make_shared<qb::http::MiddlewareTask<MockAllInOneSession> >(
            std::make_shared<AllInOneMiddleware>("ErrorChainMwSync", nullptr, _session.get(), false,
                                                 AllInOneMiddleware::Behavior::CONTINUE, qb::http::status::OK,
                                                 "X-Error-Chain", "Processed")
        )
    );
    error_chain.push_back(
        std::make_shared<qb::http::CustomRouteAdapterTask<MockAllInOneSession> >(
            std::make_shared<AllInOneCustomRoute>("ErrorChainFinalHandler", nullptr, _session.get(), false, false,
                                                  qb::http::status::INTERNAL_SERVER_ERROR, "Error Handled By: ")
        )
    );
    _router->set_error_task_chain(error_chain);

    // Compile all routes
    ASSERT_NO_THROW(_router->compile());

    // --- Test Executions ---

    // Test 1: groupA direct sync route
    make_request_and_process(qb::http::method::GET, "/groupA/direct_sync");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: GroupADirectSyncHandler");
    EXPECT_EQ(_session->get_trace(),
              "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;GroupASyncMw_handle_entry;GroupAAsyncMw_handle_entry;GroupAAsyncMw_task_exec;GroupADirectSyncHandler");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "GroupADirectSyncHandler");

    // Test 2: groupA custom async route
    make_request_and_process(qb::http::method::GET, "/groupA/custom_async_in_A");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: GroupACustomAsync");
    EXPECT_EQ(_session->get_trace(),
              "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;GroupASyncMw_handle_entry;GroupAAsyncMw_handle_entry;GroupAAsyncMw_task_exec;GroupACustomAsync_handle_entry;GroupACustomAsync_task_exec");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "GroupACustomAsync");

    // Test 3: ControllerB sync lambda route
    make_request_and_process(qb::http::method::GET, "/groupA/groupB/controllerB/lambda_sync");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: CtrlB_LambdaSyncHandler");
    EXPECT_EQ(_session->get_trace(),
              "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;GroupASyncMw_handle_entry;GroupAAsyncMw_handle_entry;GroupAAsyncMw_task_exec;GroupBSyncMw_handle_entry;CtrlB_CtrlMwSync_handle_entry;CtrlB_CtrlMwAsync_handle_entry;CtrlB_CtrlMwAsync_task_exec;CtrlB_LambdaSyncHandler");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "CtrlB_LambdaSyncHandler");

    // Test 4: ControllerB async member handler route
    make_request_and_process(qb::http::method::POST, "/groupA/groupB/controllerB/member_async");
    EXPECT_EQ(_session->_response.status(), qb::http::status::ACCEPTED);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: CtrlB_AsyncMemberHandler");
    EXPECT_EQ(_session->get_trace(),
              "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;GroupASyncMw_handle_entry;GroupAAsyncMw_handle_entry;GroupAAsyncMw_task_exec;GroupBSyncMw_handle_entry;CtrlB_CtrlMwSync_handle_entry;CtrlB_CtrlMwAsync_handle_entry;CtrlB_CtrlMwAsync_task_exec;CtrlB_AsyncMemberHandler_entry;CtrlB_AsyncMemberHandler_task");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "CtrlB_AsyncMemberHandler");

    // Test 5: ControllerB custom async route with param
    make_request_and_process(qb::http::method::PUT, "/groupA/groupB/controllerB/custom_async/p123");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: CtrlB_CtrlCustomAsyncWithParam");
    EXPECT_EQ(_session->get_trace(),
              "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;GroupASyncMw_handle_entry;GroupAAsyncMw_handle_entry;GroupAAsyncMw_task_exec;GroupBSyncMw_handle_entry;CtrlB_CtrlMwSync_handle_entry;CtrlB_CtrlMwAsync_handle_entry;CtrlB_CtrlMwAsync_task_exec;CtrlB_CtrlCustomAsyncWithParam_handle_entry;CtrlB_CtrlCustomAsyncWithParam_task_exec");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "CtrlB_CtrlCustomAsyncWithParam");
    ASSERT_TRUE(_session->_captured_params.get("id").has_value());
    EXPECT_EQ(_session->_captured_params.get("id").value(), "p123");

    // Test 6: ControllerTop sync custom route
    make_request_and_process(qb::http::method::GET, "/controllerTop/custom_sync");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: CtrlTop_CtrlCustomSync");
    EXPECT_EQ(_session->get_trace(),
              "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;CtrlTop_CtrlMwSync_handle_entry;CtrlTop_CtrlMwAsync_handle_entry;CtrlTop_CtrlMwAsync_task_exec;CtrlTop_CtrlCustomSync_handle_entry");
    // Sync custom route, task_exec not part of ID for sync custom route
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "CtrlTop_CtrlCustomSync");

    // Test 7: Not Found
    make_request_and_process(qb::http::method::GET, "/this/path/does/not/exist");
    EXPECT_EQ(_session->_response.status(), qb::http::status::NOT_FOUND);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Custom Router 404 Page");
    // Global middleware runs before 404 handler is determined
    EXPECT_EQ(_session->get_trace(),
              "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;CustomRouter404Handler");
    EXPECT_FALSE(_session->_final_handler_called); // Our specific flag for main handlers

    // Test 8: Error in a controller handler, caught by router error chain
    make_request_and_process(qb::http::method::GET, "/controllerTop/error_sync");
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR); // From ErrorChainFinalHandler
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Error Handled By: ErrorChainFinalHandler");
    EXPECT_EQ(_session->_last_status_code_before_error_handler, qb::http::status::BAD_REQUEST);
    // Status set by CtrlTop_ErrorSyncHandler
    // Trace: Globals -> CtrlTop Mws -> Handler (signals error) -> ErrorChainMw -> ErrorChainFinalHandler
    EXPECT_EQ(_session->get_trace(),
              "GlobalSyncMw_handle_entry;GlobalAsyncMw_handle_entry;GlobalAsyncMw_task_exec;CtrlTop_CtrlMwSync_handle_entry;CtrlTop_CtrlMwAsync_handle_entry;CtrlTop_CtrlMwAsync_task_exec;CtrlTop_ErrorSyncHandler;ErrorChainMwSync_handle_entry;ErrorChainFinalHandler_handle_entry");
    EXPECT_TRUE(_session->_final_handler_called); // ErrorChainFinalHandler sets this
    EXPECT_EQ(_session->_last_handler_id_executed, "ErrorChainFinalHandler");
    EXPECT_EQ(_session->_response.header("X-Error-Chain"), "Processed");


    // Test 9: Short-circuit by a global middleware
    _router = std::make_unique<qb::http::Router<MockAllInOneSession> >(); // Re-initialize the router
    _router->use(std::make_shared<AllInOneMiddleware>("GlobalShortCircuitMw", nullptr, _session.get(), false,
                                                      AllInOneMiddleware::Behavior::SHORT_CIRCUIT,
                                                      qb::http::status::ACCEPTED));
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

TEST_F(RouterAllInOneTest, WildcardParametersInGroupsAndControllers) {
    // Ensure _router is reset at the very beginning of this test case for isolation
    _router = std::make_unique<qb::http::Router<MockAllInOneSession> >();

    // Controller with wildcard route
    class WildcardController : public qb::http::Controller<MockAllInOneSession> {
    public:
        MockAllInOneSession *_session_ptr_wc;

        WildcardController(MockAllInOneSession *session_ptr) : _session_ptr_wc(session_ptr) {
        }

        void initialize_routes() override {
            this->get("/content/*path", [this](auto ctx) {
                if (_session_ptr_wc) {
                    _session_ptr_wc->trace("WildcardController_content_path");
                    _session_ptr_wc->_final_handler_called = true;
                    _session_ptr_wc->_last_handler_id_executed = "WildcardController_content_path";
                    _session_ptr_wc->_captured_params = ctx->path_parameters();
                }
                ctx->response().body() = "CtrlWildcardPath: " + std::string(ctx->path_param("path"));
                ctx->response().status() = qb::http::status::OK;
                ctx->complete();
            });
        }

        std::string get_node_name() const override { return "WildcardController"; }
    };
    // Create a fresh router for this specific test section to avoid interference
    auto wc_ctrl = _router->template controller<WildcardController>("/wc_ctrl", _session.get());
    ASSERT_NE(wc_ctrl, nullptr);

    // Test 2: Group with a static path, route inside has wildcard.
    // Group path: /data. Route in group: /content/*filepath
    // Effective registered path: /data/content/*filepath (VALID)
    auto data_group = _router->group("/data");
    ASSERT_NE(data_group, nullptr);
    data_group->use(std::make_shared<AllInOneMiddleware>("DataGroupMw", nullptr, _session.get(), false,
                                                         AllInOneMiddleware::Behavior::CONTINUE));
    data_group->get("/content/*filepath", [this](auto ctx) {
        _session->trace("DataGroup_content_handler");
        _session->_final_handler_called = true;
        _session->_last_handler_id_executed = "DataGroup_content_handler";
        _session->_captured_params = ctx->path_parameters();
        ctx->response().body() = "DataGroup File: " + std::string(ctx->path_param("filepath"));
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });

    ASSERT_NO_THROW(_router->compile()); // This should now pass.

    // Test 1: Controller Wildcard (uses the _router configured above)
    make_request_and_process(qb::http::method::GET, "/wc_ctrl/content/folder/file.txt");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "CtrlWildcardPath: folder/file.txt");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "WildcardController_content_path");
    EXPECT_EQ(_session->_captured_params.get("path").value(), "folder/file.txt");
    // Trace for Test 1 - this will only include middleware/handlers for this specific router config
    // No global middleware were added to _this_ _router instance for this specific test section.
    EXPECT_EQ(_session->get_trace(), "WildcardController_content_path");

    // Test 2 (Revised): Accessing the valid wildcard route in data_group
    // This uses the same _router instance configured above with wc_ctrl and data_group
    make_request_and_process(qb::http::method::GET, "/data/content/reports/annual.pdf");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "DataGroup File: reports/annual.pdf");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "DataGroup_content_handler");
    ASSERT_TRUE(_session->_captured_params.get("filepath").has_value());
    EXPECT_EQ(_session->_captured_params.get("filepath").value(), "reports/annual.pdf");
    EXPECT_EQ(_session->get_trace(), "DataGroupMw_handle_entry;DataGroup_content_handler");
}

TEST_F(RouterAllInOneTest, MultipleControllersAndMiddlewareInteraction) {
    // Controller 1
    auto controller1 = _router->template controller<AllInOneController>("/serviceA", "SvcA_", &_task_executor,
                                                                        _session.get());
    ASSERT_NE(controller1, nullptr);
    controller1->use(std::make_shared<AllInOneMiddleware>("SvcACtrlSpecificMw", nullptr, _session.get(), false,
                                                          AllInOneMiddleware::Behavior::CONTINUE, qb::http::status::OK,
                                                          "X-SvcA-Ctrl", "SetBySvcACtrlMw"));

    // Controller 2 (different instance of same type)
    auto controller2 = _router->template controller<AllInOneController>("/serviceB", "SvcB_", &_task_executor,
                                                                        _session.get());
    ASSERT_NE(controller2, nullptr);
    controller2->use(std::make_shared<AllInOneMiddleware>("SvcBCtrlSpecificMw", nullptr, _session.get(), false,
                                                          AllInOneMiddleware::Behavior::CONTINUE, qb::http::status::OK,
                                                          "X-SvcB-Ctrl", "SetBySvcBCtrlMw"));

    // Global middleware for this test
    _router->use(std::make_shared<AllInOneMiddleware>("MultiCtrlTestGlobalMw", nullptr, _session.get(), false,
                                                      AllInOneMiddleware::Behavior::CONTINUE));

    ASSERT_NO_THROW(_router->compile());

    // Test 1: Request to Service A controller (sync lambda)
    make_request_and_process(qb::http::method::GET, "/serviceA/lambda_sync");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: SvcA_LambdaSyncHandler");
    EXPECT_EQ(_session->_response.header("X-SvcA-Ctrl"), "SetBySvcACtrlMw");
    EXPECT_TRUE(_session->_response.header("X-SvcB-Ctrl").empty()); // Ensure SvcB middleware didn't run
    EXPECT_EQ(_session->get_trace(),
              "MultiCtrlTestGlobalMw_handle_entry;SvcACtrlSpecificMw_handle_entry;SvcA_CtrlMwSync_handle_entry;SvcA_CtrlMwAsync_handle_entry;SvcA_CtrlMwAsync_task_exec;SvcA_LambdaSyncHandler");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "SvcA_LambdaSyncHandler");

    // Test 2: Request to Service B controller (async member handler)
    make_request_and_process(qb::http::method::POST, "/serviceB/member_async");
    EXPECT_EQ(_session->_response.status(), qb::http::status::ACCEPTED);
    EXPECT_EQ(_session->_response.body().as<std::string>(), "Response: SvcB_AsyncMemberHandler");
    EXPECT_EQ(_session->_response.header("X-SvcB-Ctrl"), "SetBySvcBCtrlMw");
    EXPECT_TRUE(_session->_response.header("X-SvcA-Ctrl").empty()); // Ensure SvcA middleware didn't run
    EXPECT_EQ(_session->get_trace(),
              "MultiCtrlTestGlobalMw_handle_entry;SvcBCtrlSpecificMw_handle_entry;SvcB_CtrlMwSync_handle_entry;SvcB_CtrlMwAsync_handle_entry;SvcB_CtrlMwAsync_task_exec;SvcB_AsyncMemberHandler_entry;SvcB_AsyncMemberHandler_task");
    EXPECT_TRUE(_session->_final_handler_called);
    EXPECT_EQ(_session->_last_handler_id_executed, "SvcB_AsyncMemberHandler");
}

TEST_F(RouterAllInOneTest, ErrorInControllerMiddleware) {
    // Controller that has a middleware which will signal an error
    class ControllerWithErrorMw : public qb::http::Controller<MockAllInOneSession> {
    public:
        MockAllInOneSession *_session_ptr_err_mw_ctrl;

        ControllerWithErrorMw(MockAllInOneSession *session_ptr, TaskExecutor *executor)
            : _session_ptr_err_mw_ctrl(session_ptr) {
            this->use(std::make_shared<AllInOneMiddleware>("CtrlErrorMw", executor, _session_ptr_err_mw_ctrl, false,
                                                           AllInOneMiddleware::Behavior::SIGNAL_ERROR));
            this->get("/path", [this](auto ctx) {
                if (_session_ptr_err_mw_ctrl) _session_ptr_err_mw_ctrl->trace("CtrlErrorMw_PathHandlerNeverReached");
                ctx->complete();
            });
        }

        void initialize_routes() override {
            /* Routes added in constructor for this example */
        }

        std::string get_node_name() const override { return "ControllerWithErrorMw"; }
    };

    _router->template controller<ControllerWithErrorMw>("/ctrl_err_mw", _session.get(), &_task_executor);

    // Setup a main error handler for the router
    std::list<std::shared_ptr<qb::http::IAsyncTask<MockAllInOneSession> > > error_chain;
    error_chain.push_back(
        std::make_shared<qb::http::CustomRouteAdapterTask<MockAllInOneSession> >(
            std::make_shared<AllInOneCustomRoute>("MainRouterErrorHandlerForCtrlMwError", nullptr, _session.get(),
                                                  false, false, qb::http::status::SERVICE_UNAVAILABLE,
                                                  "RouterHandledCtrlMwError: ")
        )
    );
    _router->set_error_task_chain(error_chain);

    _router->use(std::make_shared<AllInOneMiddleware>("GlobalMwForCtrlErrTest", nullptr, _session.get(), false,
                                                      AllInOneMiddleware::Behavior::CONTINUE));


    ASSERT_NO_THROW(_router->compile());

    make_request_and_process(qb::http::method::GET, "/ctrl_err_mw/path");
    EXPECT_EQ(_session->_response.status(), qb::http::status::SERVICE_UNAVAILABLE);
    EXPECT_EQ(_session->_response.body().as<std::string>(),
              "RouterHandledCtrlMwError: MainRouterErrorHandlerForCtrlMwError");
    EXPECT_EQ(_session->get_trace(),
              "GlobalMwForCtrlErrTest_handle_entry;CtrlErrorMw_handle_entry;MainRouterErrorHandlerForCtrlMwError_handle_entry");
    // CtrlErrorMw signals error, then main error handler runs.
    EXPECT_TRUE(_session->_final_handler_called); // The error handler is the 'final' handler in this case
    EXPECT_EQ(_session->_last_handler_id_executed, "MainRouterErrorHandlerForCtrlMwError");
}

TEST_F(RouterAllInOneTest, ErrorInErrorChainIsFatal) {
    _router->get("/trigger_initial_error", [this](auto ctx) {
        _session->trace("InitialErrorHandler");
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    });

    std::list<std::shared_ptr<qb::http::IAsyncTask<MockAllInOneSession> > > faulty_error_chain;
    faulty_error_chain.push_back(
        std::make_shared<qb::http::MiddlewareTask<MockAllInOneSession> >(
            std::make_shared<AllInOneMiddleware>("FaultyErrorChainMw1", nullptr, _session.get(), false,
                                                 AllInOneMiddleware::Behavior::CONTINUE)
        )
    );
    faulty_error_chain.push_back(
        std::make_shared<qb::http::MiddlewareTask<MockAllInOneSession> >(
            std::make_shared<AllInOneMiddleware>("FaultyErrorChainMw2_SignalsError", nullptr, _session.get(), false,
                                                 AllInOneMiddleware::Behavior::SIGNAL_ERROR) // This one errors
        )
    );
    faulty_error_chain.push_back(
        std::make_shared<qb::http::MiddlewareTask<MockAllInOneSession> >(
            std::make_shared<AllInOneMiddleware>("FaultyErrorChainMw3_NeverReached", nullptr, _session.get(), false,
                                                 AllInOneMiddleware::Behavior::CONTINUE)
        )
    );
    _router->set_error_task_chain(faulty_error_chain);

    _router->use(std::make_shared<AllInOneMiddleware>("GlobalMwForFaultyErrorChainTest", nullptr, _session.get(), false,
                                                      AllInOneMiddleware::Behavior::CONTINUE));

    ASSERT_NO_THROW(_router->compile());

    make_request_and_process(qb::http::method::GET, "/trigger_initial_error");
    EXPECT_EQ(_session->_response.status(), qb::http::status::INTERNAL_SERVER_ERROR); // Final fallback status
    // The body might be what FaultyErrorChainMw2_SignalsError set, or empty if status changed late.
    EXPECT_EQ(_session->_response.body().as<std::string>(), "FaultyErrorChainMw2_SignalsError signaled error.");
    EXPECT_EQ(_session->get_trace(),
              "GlobalMwForFaultyErrorChainTest_handle_entry;InitialErrorHandler;FaultyErrorChainMw1_handle_entry;FaultyErrorChainMw2_SignalsError_handle_entry");
    EXPECT_FALSE(_session->_final_handler_called);
    // No *normal* final handler, and error chain didn't complete successfully.
}

TEST_F(RouterAllInOneTest, StaticParamWildcardPriorityExplicit) {
    _router->get("/priority/static", [this](auto ctx) {
        _session->trace("StaticRoute");
        ctx->complete();
    });
    _router->get("/priority/:param", [this](auto ctx) {
        _session->trace("ParamRoute:" + std::string(ctx->path_param("param")));
        ctx->complete();
    });
    _router->get("/priority/*wildcard", [this](auto ctx) {
        _session->trace("WildcardRoute:" + std::string(ctx->path_param("wildcard")));
        ctx->complete();
    });
    _router->compile();

    make_request_and_process(qb::http::method::GET, "/priority/static");
    EXPECT_EQ(_session->get_trace(), "StaticRoute");

    make_request_and_process(qb::http::method::GET, "/priority/param_value");
    EXPECT_EQ(_session->get_trace(), "ParamRoute:param_value");

    make_request_and_process(qb::http::method::GET, "/priority/wild/card/value");
    EXPECT_EQ(_session->get_trace(), "WildcardRoute:wild/card/value");

    // Test what /priority/ matches - should be wildcard consuming empty string if that's the tree behavior
    make_request_and_process(qb::http::method::GET, "/priority/");
    EXPECT_EQ(_session->get_trace(), "WildcardRoute:");
}


TEST_F(RouterAllInOneTest, MiddlewareModifiesRequestForSubsequentTasks) {
    _router->use(std::make_shared<AllInOneMiddleware>("MwSetsHeader", nullptr, _session.get(), false,
                                                      AllInOneMiddleware::Behavior::CONTINUE, qb::http::status::OK,
                                                      "X-Test-Data", "SetByMw"));

    _router->use([this](std::shared_ptr<qb::http::Context<MockAllInOneSession> > ctx, std::function<void()> next) {
        auto val = ctx->request().header("X-Test-Data");
        bool condition_met = (std::string(val) == "SetByMw"); // Explicitly convert val to std::string for comparison
        // Temporary trace for debugging
        _session->trace(
            "FunctionalMw_Check_Header_Val:[" + std::string(val) + "]_CondMet:" + (condition_met ? "T" : "F"));

        if (condition_met) {
            _session->trace("MwReadsHeaderCorrectly");
            ctx->response().set_header("X-Mw-Confirmation", "HeaderRead");
        }
        next();
    }, "FunctionalMwChecksHeader");

    _router->get("/mw_data_flow", [this](auto ctx) {
        _session->trace("FinalHandlerForDataFlow");
        EXPECT_EQ(ctx->request().header("X-Test-Data"), "SetByMw");
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    });

    _router->compile();
    make_request_and_process(qb::http::method::GET, "/mw_data_flow");

    EXPECT_EQ(_session->get_trace(),
              "MwSetsHeader_handle_entry;FunctionalMw_Check_Header_Val:[SetByMw]_CondMet:T;MwReadsHeaderCorrectly;FinalHandlerForDataFlow");
    EXPECT_EQ(_session->_response.header("X-Mw-Confirmation"), "HeaderRead");
    EXPECT_EQ(_session->_response.status(), qb::http::status::OK);
}

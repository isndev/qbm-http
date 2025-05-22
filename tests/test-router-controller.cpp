#include <gtest/gtest.h>
#include "../http.h" // Provides qb::http::Router, Request, Response, Context, Controller, etc.
#include <qb/uuid.h>    // For qb::uuid and qb::generate_random_uuid
#include <memory>
#include <string>
#include <vector>
#include <functional> // For std::function
#include <iostream>

// --- Helper Classes for Controller Router Tests ---

// Simple Task Executor for testing deferred execution (copied from test-router-async.cpp)
class TaskExecutor {
public:
    void addTask(std::function<void()> task) {
        _tasks.push_back(std::move(task));
    }

    void processAllTasks() {
        std::vector<std::function<void()> > tasks_to_process = _tasks;
        _tasks.clear();
        for (auto &task: tasks_to_process) {
            task();
        }
    }

    size_t getPendingTaskCount() const {
        return _tasks.size();
    }

private:
    std::vector<std::function<void()> > _tasks;
};

// Mock Session for Controller Router Tests (adapted from MockAsyncSession)
struct MockControllerSession {
    qb::http::Response _response;
    qb::uuid _session_id = qb::generate_random_uuid();
    std::string _handler_id_executed; // Tracks which handler/method was called
    qb::http::PathParameters _captured_params;
    std::weak_ptr<qb::http::Context<MockControllerSession> > _last_context_seen;
    bool _controller_method_done = false; // Specific for controller async logic

    qb::http::Response &get_response_ref() { return _response; }

    MockControllerSession &operator<<(const qb::http::Response &resp) {
        _response = resp;
        return *this;
    }

    [[nodiscard]] const qb::uuid &id() const { return _session_id; }

    void reset() {
        _response = qb::http::Response();
        _handler_id_executed.clear();
        _captured_params = qb::http::PathParameters();
        _last_context_seen.reset();
        _controller_method_done = false;
    }
};

// Test Fixture for Controller Router Tests
class RouterControllerTest : public ::testing::Test {
protected:
    std::shared_ptr<MockControllerSession> _mock_session;
    qb::http::Router<MockControllerSession> _router;
    TaskExecutor _task_executor; // For testing async controller methods
    std::string _prefix_data;

    void SetUp() override {
        _mock_session = std::make_shared<MockControllerSession>();
    }

    qb::http::Request create_request(qb::http::method method_val, const std::string &target_path) {
        qb::http::Request req;
        req.method() = method_val;
        try {
            req.uri() = qb::io::uri(target_path);
        } catch (const std::exception &e) {
            ADD_FAILURE() << "Failed to parse URI: " << target_path << " - " << e.what();
            req.uri() = qb::io::uri("/__invalid_uri_due_to_parse_failure__");
        }
        req.major_version = 1;
        req.minor_version = 1;
        return req;
    }
};

// --- Example Test Controllers ---

// Synchronous Controller Example
class SyncTestController : public qb::http::Controller<MockControllerSession> {
public:
    SyncTestController(std::string prefix_data) : _prefix_data(std::move(prefix_data)) {
    }

    void initialize_routes() override {
        // Using RouteHandlerFn for direct lambda binding
        add_controller_route("/get_data", qb::http::method::GET,
                             [this](std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
                                 this->get_data_handler(ctx);
                             });

        // Using MEMBER_HANDLER macro
        add_controller_route("/post_data", qb::http::method::POST,
                             MEMBER_HANDLER(&SyncTestController::post_data_handler));
        add_controller_route("/item/:id", qb::http::method::GET, MEMBER_HANDLER(&SyncTestController::get_item_handler));
    }

    void get_data_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed = _prefix_data + "SyncTestController::get_data_handler";
        }
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Synchronous GET data";
        ctx->complete();
    }

    void post_data_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed = _prefix_data + "SyncTestController::post_data_handler";
        }
        ctx->response().status() = qb::http::status::CREATED;
        ctx->response().body() = "Synchronous POST data accepted";
        ctx->complete();
    }

    void get_item_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed = _prefix_data + "SyncTestController::get_item_handler";
            ctx->session()->_captured_params = ctx->path_parameters();
        }
        std::string item_id(ctx->path_parameters().get("id").value_or("not_found"));
        ctx->response().status() = qb::http::status::OK;
        ctx->response().body() = "Item ID: " + item_id;
        ctx->complete();
    }

private:
    std::string _prefix_data;
};

// Asynchronous Controller Example (methods defer completion via TaskExecutor)
class AsyncTestController : public qb::http::Controller<MockControllerSession> {
public:
    // Constructor taking a pointer to the test fixture's TaskExecutor
    AsyncTestController(TaskExecutor *executor, std::string prefix_data)
        : _executor(executor), _prefix_data(std::move(prefix_data)) {
        if (!_executor) {
            throw std::runtime_error("TaskExecutor cannot be null for AsyncTestController");
        }
    }

    void initialize_routes() override {
        add_controller_route("/async_get", qb::http::method::GET,
                             [this](std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
                                 this->async_get_handler(ctx);
                             });
        add_controller_route("/async_post", qb::http::method::POST,
                             MEMBER_HANDLER(&AsyncTestController::async_post_handler));
    }

    void async_get_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed = _prefix_data + "AsyncTestController::async_get_handler_CALLED";
        }
        auto shared_ctx = ctx; // Capture for lambda
        _executor->addTask([shared_ctx, this]() {
            if (shared_ctx->session()) {
                shared_ctx->session()->_handler_id_executed =
                        _prefix_data + "AsyncTestController::async_get_handler_EXECUTED";
                shared_ctx->session()->_controller_method_done = true;
            }
            shared_ctx->response().status() = qb::http::status::OK;
            shared_ctx->response().body() = "Asynchronous GET data";
            shared_ctx->complete();
        });
    }

    void async_post_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed = _prefix_data + "AsyncTestController::async_post_handler_CALLED";
        }
        auto shared_ctx = ctx; // Capture for lambda
        _executor->addTask([shared_ctx, this]() {
            if (shared_ctx->session()) {
                shared_ctx->session()->_handler_id_executed =
                        _prefix_data + "AsyncTestController::async_post_handler_EXECUTED";
                shared_ctx->session()->_controller_method_done = true;
            }
            shared_ctx->response().status() = qb::http::status::ACCEPTED;
            shared_ctx->response().body() = "Asynchronous POST data accepted";
            shared_ctx->complete();
        });
    }

private:
    TaskExecutor *_executor;
    std::string _prefix_data;
};


// --- New Helper Classes for Advanced Controller Tests ---

// Synchronous Middleware for Controller Tests
class TestControllerSyncMiddleware : public qb::http::IMiddleware<MockControllerSession> {
public:
    TestControllerSyncMiddleware(std::string id, std::string header_name, std::string header_value)
        : _id(std::move(id)), _header_name(std::move(header_name)), _header_value(std::move(header_value)) {
    }

    void process(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) override {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed += (_id + ";");
        }
        ctx->response().set_header(_header_name, _header_value);
        ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
    }

    std::string name() const override { return _id; }

    void cancel() override {
    }

private:
    std::string _id;
    std::string _header_name;
    std::string _header_value;
};

// Asynchronous Middleware for Controller Tests
class TestControllerAsyncMiddleware : public qb::http::IMiddleware<MockControllerSession> {
public:
    TestControllerAsyncMiddleware(std::string id, TaskExecutor *executor, std::string header_name,
                                  std::string header_value, bool signal_error = false)
        : _id(std::move(id)), _executor(executor), _header_name(std::move(header_name)),
          _header_value(std::move(header_value)), _signal_error(signal_error) {
        if (!_executor) throw std::runtime_error("TaskExecutor cannot be null for TestControllerAsyncMiddleware");
    }

    void process(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) override {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed += (_id + "_HANDLE_CALLED;");
        }
        auto shared_ctx = ctx;
        _executor->addTask([shared_ctx, this]() {
            if (shared_ctx->session()) {
                shared_ctx->session()->_handler_id_executed += (_id + "_TASK_EXECUTED;");
            }
            if (_signal_error) {
                shared_ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
                shared_ctx->response().set_header(_header_name, "ERROR_BY_" + _id);
                shared_ctx->complete(qb::http::AsyncTaskResult::ERROR);
            } else {
                shared_ctx->response().set_header(_header_name, _header_value);
                shared_ctx->complete(qb::http::AsyncTaskResult::CONTINUE);
            }
        });
    }

    std::string name() const override { return _id; }

    void cancel() override {
    }

private:
    std::string _id;
    TaskExecutor *_executor;
    std::string _header_name;
    std::string _header_value;
    bool _signal_error;
};

// Custom Route for Controller Tests
class MyCustomControllerRoute : public qb::http::ICustomRoute<MockControllerSession> {
public:
    MyCustomControllerRoute(std::string id,
                            TaskExecutor *executor = nullptr) : _id(std::move(id)), _executor(executor) {
    }

    void process(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) override {
        if (_executor) {
            // Async version
            if (ctx->session()) {
                ctx->session()->_handler_id_executed += (_id + "_CUSTOM_ASYNC_HANDLE_CALLED;");
            }
            auto shared_ctx = ctx;
            _executor->addTask([shared_ctx, this]() {
                if (shared_ctx->session()) {
                    shared_ctx->session()->_handler_id_executed += (_id + "_CUSTOM_ASYNC_TASK_EXECUTED;");
                    shared_ctx->session()->_controller_method_done = true;
                }
                shared_ctx->response().body() = "Response from " + _id + " (async custom route)";
                shared_ctx->response().status() = qb::http::status::OK;
                shared_ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
            });
        } else {
            // Sync version
            if (ctx->session()) {
                ctx->session()->_handler_id_executed += (_id + "_CUSTOM_SYNC_EXECUTED;");
                ctx->session()->_controller_method_done = true;
            }
            ctx->response().body() = "Response from " + _id + " (sync custom route)";
            ctx->response().status() = qb::http::status::OK;
            ctx->complete(qb::http::AsyncTaskResult::COMPLETE);
        }
    }

    std::string name() const override { return _id; }

    void cancel() override {
    }

private:
    std::string _id;
    TaskExecutor *_executor;
};

// Controller for testing middleware, errors, and custom routes
class ControllerWithAdvancedFeatures : public qb::http::Controller<MockControllerSession> {
public:
    ControllerWithAdvancedFeatures(TaskExecutor *executor, const std::string &marker)
        : _executor(executor), _marker(marker) {
        if (!_executor && marker.find("async") != std::string::npos) {
            // Basic check
            // Only throw if executor is needed for an async-prefixed marker test.
            // Some tests might use this controller for sync features only.
        }
    }

    void initialize_routes() override {
        // Route with controller-specific sync middleware
        add_controller_route("/sync_mw_route", qb::http::method::GET,
                             MEMBER_HANDLER(&ControllerWithAdvancedFeatures::basic_handler));

        // Route with controller-specific async middleware
        add_controller_route("/async_mw_route", qb::http::method::GET,
                             MEMBER_HANDLER(&ControllerWithAdvancedFeatures::basic_handler));

        // Route for sync error
        add_controller_route("/sync_error", qb::http::method::GET,
                             MEMBER_HANDLER(&ControllerWithAdvancedFeatures::sync_error_handler));

        // Route for async error (error in deferred task)
        add_controller_route("/async_error_deferred", qb::http::method::GET,
                             MEMBER_HANDLER(&ControllerWithAdvancedFeatures::async_error_deferred_handler));

        // Route for async error (error in handle method before deferring)
        add_controller_route("/async_error_immediate", qb::http::method::GET,
                             MEMBER_HANDLER(&ControllerWithAdvancedFeatures::async_error_immediate_handler));

        // Route using a synchronous ICustomRoute
        auto sync_custom_route = std::make_shared<MyCustomControllerRoute>(_marker + "SyncCustomRouteImpl");
        add_controller_route("/custom_sync", qb::http::method::GET, sync_custom_route);

        // Route using an asynchronous ICustomRoute
        auto async_custom_route = std::make_shared<
            MyCustomControllerRoute>(_marker + "AsyncCustomRouteImpl", _executor);
        add_controller_route("/custom_async", qb::http::method::GET, async_custom_route);

        // Add routes for throwing handlers
        add_controller_route("/throw_sync_direct", qb::http::method::GET,
                             MEMBER_HANDLER(&ControllerWithAdvancedFeatures::sync_throwing_handler_direct));
        add_controller_route("/throw_async_in_task", qb::http::method::GET,
                             MEMBER_HANDLER(&ControllerWithAdvancedFeatures::async_throwing_in_task_handler));
        add_controller_route("/throw_async_before_task", qb::http::method::GET,
                             MEMBER_HANDLER(&ControllerWithAdvancedFeatures::async_throwing_before_task_handler));
    }

    void basic_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed += (_marker + "_basic_handler;");
            ctx->session()->_controller_method_done = true;
        }
        ctx->response().body() = _marker + " basic_handler response";
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    }

    void sync_error_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed += (_marker + "_sync_error_handler;");
            ctx->session()->_controller_method_done = true;
        }
        ctx->response().body() = _marker + " sync error about to happen";
        ctx->response().status() = qb::http::status::GONE; // Some non-500 status before error
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
    }

    void async_error_immediate_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed += (_marker + "_async_error_immediate_handler;");
        }
        // Error happens before deferring to executor
        ctx->response().body() = _marker + " async immediate error";
        ctx->response().status() = qb::http::status::EXPECTATION_FAILED;
        ctx->complete(qb::http::AsyncTaskResult::ERROR);
        // No task added to executor
    }

    void async_error_deferred_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed += (_marker + "_async_error_deferred_handler_CALLED;");
        }
        auto shared_ctx = ctx;
        if (!_executor) {
            // Should be caught by constructor or test setup
            shared_ctx->response().body() = "NO EXECUTOR FOR ASYNC ERROR";
            shared_ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            shared_ctx->complete(qb::http::AsyncTaskResult::ERROR);
            return;
        }
        _executor->addTask([shared_ctx, this]() {
            if (shared_ctx->session()) {
                shared_ctx->session()->_handler_id_executed += (
                    _marker + "_async_error_deferred_handler_TASK_EXECUTED;");
                shared_ctx->session()->_controller_method_done = true; // Mark done even if erroring
            }
            shared_ctx->response().body() = _marker + " async deferred error";
            // Let's not set status code here, rely on RouterCore's default for ERROR (500)
            shared_ctx->complete(qb::http::AsyncTaskResult::ERROR);
        });
    }

    // New handler that throws synchronously
    void sync_throwing_handler_direct(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed = _marker + "_sync_throwing_handler_direct_CALLED";
        }
        throw std::runtime_error("Intentional sync exception from " + _marker + "_sync_throwing_handler_direct");
    }

    // New handler that throws from an async task
    void async_throwing_in_task_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed = _marker + "_async_throwing_in_task_handler_CALLED";
        }
        auto shared_ctx = ctx;
        if (!_executor) {
            shared_ctx->response().body() = "NO EXECUTOR FOR ASYNC THROWING TASK HANDLER";
            shared_ctx->response().status() = qb::http::status::INTERNAL_SERVER_ERROR;
            shared_ctx->complete(qb::http::AsyncTaskResult::ERROR);
            return;
        }
        _executor->addTask([shared_ctx, marker = _marker]() {
            // Capture marker
            try {
                if (shared_ctx->session()) {
                    shared_ctx->session()->_handler_id_executed += ";TASK_STARTED_FOR_THROW";
                }
                throw std::runtime_error("Intentional async exception from " + marker + "_async_throwing_in_task");
                // The following line would be unreachable, but shown for pattern
                // shared_ctx->complete(qb::http::AsyncTaskResult::COMPLETE); 
            } catch (const std::exception &e) {
                // Log or handle exception e if necessary, then signal error to context
                std::cerr << "Async task for " << marker << " caught exception: " << e.what() << std::endl;
                if (!shared_ctx->is_cancelled() && !shared_ctx->is_completed()) {
                    shared_ctx->complete(qb::http::AsyncTaskResult::ERROR);
                }
            } catch (...) {
                std::cerr << "Async task for " << marker << " caught unknown exception." << std::endl;
                if (!shared_ctx->is_cancelled() && !shared_ctx->is_completed()) {
                    shared_ctx->complete(qb::http::AsyncTaskResult::ERROR);
                }
            }
        });
    }

    // New handler that is designed to be async but throws before queueing task
    void async_throwing_before_task_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed = _marker + "_async_throwing_before_task_CALLED";
        }
        // Some condition or check leads to an immediate throw
        throw std::runtime_error("Intentional sync exception from " + _marker + "_async_throwing_before_task");

        // The following would be unreachable:
        // auto shared_ctx = ctx;
        // _executor->addTask([shared_ctx, marker = _marker]() { /* ... */ });
    }

private:
    TaskExecutor *_executor;
    std::string _marker;
};

class ThrowingConstructorController : public qb::http::Controller<MockControllerSession> {
public:
    ThrowingConstructorController(const std::string & /*marker*/) {
        throw std::runtime_error("Exception from ThrowingConstructorController constructor");
    }

    void initialize_routes() override {
        /* Will not be called */
    }
};

// Controller to test instance reusability and statefulness
class StatefulController : public qb::http::Controller<MockControllerSession> {
public:
    StatefulController(const std::string &base_id) : _base_id(base_id), _request_count(0) {
    }

    void initialize_routes() override {
        add_controller_route("/ping_and_set/:modifier", qb::http::method::GET,
                             MEMBER_HANDLER(&StatefulController::ping_and_set_handler));
        add_controller_route("/get_state", qb::http::method::GET,
                             MEMBER_HANDLER(&StatefulController::get_state_handler));
    }

    void ping_and_set_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        _request_count++;
        _last_modifier_id = ctx->path_parameters().get("modifier").value_or("unknown");
        if (ctx->session()) {
            ctx->session()->_handler_id_executed = _base_id + "_ping_set_" + _last_modifier_id;
        }
        ctx->response().body() = "Count: " + std::to_string(_request_count) + ", Last Modifier: " + _last_modifier_id;
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    }

    void get_state_handler(std::shared_ptr<qb::http::Context<MockControllerSession> > ctx) {
        if (ctx->session()) {
            ctx->session()->_handler_id_executed = _base_id + "_get_state";
        }
        ctx->response().body() = "Current Count: " + std::to_string(_request_count) + ", Last Modifier ID: " +
                                 _last_modifier_id;
        ctx->response().status() = qb::http::status::OK;
        ctx->complete();
    }

private:
    std::string _base_id;
    int _request_count;
    std::string _last_modifier_id;
};


// --- Basic Controller Tests ---

TEST_F(RouterControllerTest, MountAndCallSyncControllerGetMethod) {
    auto controller = _router.controller<SyncTestController>("/sync_api", "TestPrefix_");
    ASSERT_NE(controller, nullptr);
    _router.compile();

    auto request = create_request(HTTP_GET, "/sync_api/get_data");
    _router.route(_mock_session, std::move(request));

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Synchronous GET data");
    EXPECT_EQ(_mock_session->_handler_id_executed, "TestPrefix_SyncTestController::get_data_handler");
}

TEST_F(RouterControllerTest, MountAndCallSyncControllerPostMethod) {
    auto controller = _router.controller<SyncTestController>("/sync_api", "Test_");
    ASSERT_NE(controller, nullptr);
    _router.compile();

    auto request = create_request(HTTP_POST, "/sync_api/post_data");
    _router.route(_mock_session, std::move(request));

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_CREATED);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Synchronous POST data accepted");
    EXPECT_EQ(_mock_session->_handler_id_executed, "Test_SyncTestController::post_data_handler");
}

TEST_F(RouterControllerTest, SyncControllerWithPathParameter) {
    auto controller = _router.controller<SyncTestController>("/items_api", ""); // No prefix data
    ASSERT_NE(controller, nullptr);
    _router.compile();

    auto request = create_request(HTTP_GET, "/items_api/item/123xyz");
    _router.route(_mock_session, std::move(request));

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Item ID: 123xyz");
    EXPECT_EQ(_mock_session->_handler_id_executed, "SyncTestController::get_item_handler");
    EXPECT_EQ(_mock_session->_captured_params.get("id").value_or(""), "123xyz");
}

TEST_F(RouterControllerTest, MountAndCallAsyncControllerGetMethodDeferred) {
    // Pass the test fixture's _task_executor to the controller constructor
    auto controller = _router.controller<AsyncTestController>("/async_api", &_task_executor, "Async_");
    ASSERT_NE(controller, nullptr);
    _router.compile();

    auto request = create_request(HTTP_GET, "/async_api/async_get");
    _router.route(_mock_session, std::move(request));

    // Verify that the controller method was called and queued a task, but not yet fully executed
    EXPECT_EQ(_mock_session->_handler_id_executed, "Async_AsyncTestController::async_get_handler_CALLED");
    ASSERT_FALSE(_mock_session->_controller_method_done) << "Async controller logic ran prematurely.";
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1) << "Task was not enqueued by the AsyncTestController method.";

    _task_executor.processAllTasks(); // Manually process the queued task

    // Verify task completion and effects
    ASSERT_TRUE(_mock_session->_controller_method_done) << "Async controller logic did not complete.";
    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Asynchronous GET data");
    EXPECT_EQ(_mock_session->_handler_id_executed, "Async_AsyncTestController::async_get_handler_EXECUTED");
}

TEST_F(RouterControllerTest, MountAndCallAsyncControllerPostMethodDeferred) {
    auto controller = _router.controller<AsyncTestController>("/async_api", &_task_executor, "");
    ASSERT_NE(controller, nullptr);
    _router.compile();

    auto request = create_request(HTTP_POST, "/async_api/async_post");
    _router.route(_mock_session, std::move(request));

    EXPECT_EQ(_mock_session->_handler_id_executed, "AsyncTestController::async_post_handler_CALLED");
    ASSERT_FALSE(_mock_session->_controller_method_done);
    ASSERT_EQ(_task_executor.getPendingTaskCount(), 1);

    _task_executor.processAllTasks();

    ASSERT_TRUE(_mock_session->_controller_method_done);
    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_ACCEPTED);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Asynchronous POST data accepted");
    EXPECT_EQ(_mock_session->_handler_id_executed, "AsyncTestController::async_post_handler_EXECUTED");
}

TEST_F(RouterControllerTest, ControllerConstructorThrows) {
    // Expect the router.controller call itself to throw if the controller constructor fails.
    // The router should not store a partially constructed or invalid controller.
    EXPECT_THROW({
                 auto controller = _router.controller<ThrowingConstructorController>("/throwing_ctrl", "ThrowingMarker")
                 ;
                 // If controller() doesn't throw, we might want to fail or check if controller is null, 
                 // but the expectation is that it re-throws the constructor exception.
                 if (controller) {
                 // This part should ideally not be reached if EXPECT_THROW works as intended for constructor exceptions.
                 // If it is reached, it implies the exception wasn't propagated by controller() as expected.
                 }
                 }, std::runtime_error);

    // Ensure no routes were inadvertently compiled or that the router is still in a sane state.
    _router.compile(); // Should still work or be a no-op if nothing was added.
    auto request = create_request(HTTP_GET, "/throwing_ctrl/some_path");
    _router.route(_mock_session, std::move(request));
    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_NOT_FOUND); // No routes from this controller should exist.
}

TEST_F(RouterControllerTest, ControllerInstanceReusabilityAndState) {
    auto controller = _router.controller<StatefulController>("/stateful", "StatefulCtrl");
    ASSERT_NE(controller, nullptr);
    _router.compile();

    // Call 1: Ping and set
    _mock_session->reset();
    auto req1 = create_request(HTTP_GET, "/stateful/ping_and_set/mod1");
    _router.route(_mock_session, std::move(req1));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Count: 1, Last Modifier: mod1");
    EXPECT_EQ(_mock_session->_handler_id_executed, "StatefulCtrl_ping_set_mod1");

    // Call 2: Get state - should reflect Call 1 changes
    _mock_session->reset();
    auto req2 = create_request(HTTP_GET, "/stateful/get_state");
    _router.route(_mock_session, std::move(req2));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Current Count: 1, Last Modifier ID: mod1");
    EXPECT_EQ(_mock_session->_handler_id_executed, "StatefulCtrl_get_state");

    // Call 3: Ping and set again
    _mock_session->reset();
    auto req3 = create_request(HTTP_GET, "/stateful/ping_and_set/mod2");
    _router.route(_mock_session, std::move(req3));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Count: 2, Last Modifier: mod2");
    EXPECT_EQ(_mock_session->_handler_id_executed, "StatefulCtrl_ping_set_mod2");

    // Call 4: Get state again - should reflect Call 3 changes
    _mock_session->reset();
    auto req4 = create_request(HTTP_GET, "/stateful/get_state");
    _router.route(_mock_session, std::move(req4));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "Current Count: 2, Last Modifier ID: mod2");
    EXPECT_EQ(_mock_session->_handler_id_executed, "StatefulCtrl_get_state");
}

TEST_F(RouterControllerTest, ControllerMiddlewareAndCustomRouteOrdering) {
    auto controller = _router.controller<ControllerWithAdvancedFeatures>(
        "/adv_api_order_test", &_task_executor, "CtrlOrderTest");
    ASSERT_NE(controller, nullptr);

    // Add a controller-specific synchronous middleware
    controller->use(
        std::make_shared<TestControllerSyncMiddleware>("CtrlOrderSyncMw", "X-CtrlOrder-Sync", "AppliedCtrlOrder"));

    // The controller already has /custom_sync and /custom_async routes from its initialize_routes method.
    // We will test with the synchronous custom route first.
    _router.compile();

    // Test with Synchronous Custom Route
    _mock_session->reset();
    auto req_sync_custom = create_request(HTTP_GET, "/adv_api_order_test/custom_sync");
    _router.route(_mock_session, std::move(req_sync_custom));
    _task_executor.processAllTasks(); // Should be no tasks from this specific path if custom route is sync

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.header("X-CtrlOrder-Sync"), "AppliedCtrlOrder");
    // Expected trace: Controller Middleware -> Custom Route Handler
    EXPECT_EQ(_mock_session->_handler_id_executed,
              "CtrlOrderSyncMw;CtrlOrderTestSyncCustomRouteImpl_CUSTOM_SYNC_EXECUTED;");
    EXPECT_TRUE(_mock_session->_controller_method_done); // MyCustomControllerRoute sets this
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0);

    // Test with Asynchronous Custom Route
    _mock_session->reset();
    _mock_session->_controller_method_done = false; // Reset for async custom route
    auto req_async_custom = create_request(HTTP_GET, "/adv_api_order_test/custom_async");
    _router.route(_mock_session, std::move(req_async_custom));

    // Expected trace after sync part: Controller Middleware -> Custom Route ASYNC_HANDLE_CALLED
    EXPECT_EQ(_mock_session->_handler_id_executed,
              "CtrlOrderSyncMw;CtrlOrderTestAsyncCustomRouteImpl_CUSTOM_ASYNC_HANDLE_CALLED;");
    ASSERT_FALSE(_mock_session->_controller_method_done);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 1); // Task from MyCustomControllerRoute (async version)

    _task_executor.processAllTasks(); // Process the async task from custom route

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.header("X-CtrlOrder-Sync"), "AppliedCtrlOrder"); // Still there
    // Expected full trace
    EXPECT_EQ(_mock_session->_handler_id_executed,
              "CtrlOrderSyncMw;CtrlOrderTestAsyncCustomRouteImpl_CUSTOM_ASYNC_HANDLE_CALLED;CtrlOrderTestAsyncCustomRouteImpl_CUSTOM_ASYNC_TASK_EXECUTED;");
    EXPECT_TRUE(_mock_session->_controller_method_done);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0);
}


// --- Advanced Controller Tests ---

TEST_F(RouterControllerTest, ControllerWithSyncPrefixMiddleware) {
    auto controller = _router.controller<ControllerWithAdvancedFeatures>("/adv_api", &_task_executor, "TestSyncMw");
    ASSERT_NE(controller, nullptr);
    controller->use(std::make_shared<TestControllerSyncMiddleware>("CtrlSyncMw", "X-Ctrl-Sync", "Applied"));
    _router.compile();

    auto request = create_request(HTTP_GET, "/adv_api/sync_mw_route");
    _router.route(_mock_session, std::move(request));

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.header("X-Ctrl-Sync"), "Applied");
    EXPECT_EQ(_mock_session->_handler_id_executed, "CtrlSyncMw;TestSyncMw_basic_handler;");
    EXPECT_TRUE(_mock_session->_controller_method_done);
}

TEST_F(RouterControllerTest, ControllerWithAsyncPrefixMiddleware) {
    auto controller = _router.controller<ControllerWithAdvancedFeatures>("/adv_api", &_task_executor, "TestAsyncMw");
    ASSERT_NE(controller, nullptr);
    controller->use(
        std::make_shared<TestControllerAsyncMiddleware>("CtrlAsyncMw", &_task_executor, "X-Ctrl-Async",
                                                        "AppliedAsync"));
    _router.compile();

    auto request = create_request(HTTP_GET, "/adv_api/async_mw_route");
    _router.route(_mock_session, std::move(request));

    // Middleware handle called, task queued
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 1);
    EXPECT_EQ(_mock_session->_handler_id_executed, "CtrlAsyncMw_HANDLE_CALLED;");
    ASSERT_FALSE(_mock_session->_controller_method_done);

    _task_executor.processAllTasks(); // Process middleware task. It calls complete(CONTINUE), then basic_handler runs.

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.header("X-Ctrl-Async"), "AppliedAsync");
    EXPECT_EQ(_mock_session->_handler_id_executed,
              "CtrlAsyncMw_HANDLE_CALLED;CtrlAsyncMw_TASK_EXECUTED;TestAsyncMw_basic_handler;");
    EXPECT_TRUE(_mock_session->_controller_method_done);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0);
}

TEST_F(RouterControllerTest, ControllerSyncMethodSignalsError) {
    auto controller = _router.controller<ControllerWithAdvancedFeatures>("/adv_api", &_task_executor, "SyncErr");
    ASSERT_NE(controller, nullptr);
    _router.compile();

    auto request = create_request(HTTP_GET, "/adv_api/sync_error");
    _router.route(_mock_session, std::move(request));

    // RouterCore default error handling should set 500 if not overridden by error chain.
    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "SyncErr sync error about to happen");
    // Body set before error signal
    EXPECT_EQ(_mock_session->_handler_id_executed, "SyncErr_sync_error_handler;");
    EXPECT_TRUE(_mock_session->_controller_method_done);
}

TEST_F(RouterControllerTest, ControllerAsyncMethodSignalsErrorInDeferredTask) {
    auto controller = _router.controller<ControllerWithAdvancedFeatures>(
        "/adv_api", &_task_executor, "AsyncDeferredErr");
    ASSERT_NE(controller, nullptr);
    _router.compile();

    auto request = create_request(HTTP_GET, "/adv_api/async_error_deferred");
    _router.route(_mock_session, std::move(request));

    EXPECT_EQ(_mock_session->_handler_id_executed, "AsyncDeferredErr_async_error_deferred_handler_CALLED;");
    ASSERT_FALSE(_mock_session->_controller_method_done);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 1);

    _task_executor.processAllTasks(); // Process the task that signals error

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "AsyncDeferredErr async deferred error");
    EXPECT_EQ(_mock_session->_handler_id_executed,
              "AsyncDeferredErr_async_error_deferred_handler_CALLED;AsyncDeferredErr_async_error_deferred_handler_TASK_EXECUTED;");
    EXPECT_TRUE(_mock_session->_controller_method_done);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0);
}

TEST_F(RouterControllerTest, ControllerAsyncMethodSignalsErrorImmediatelyInHandle) {
    auto controller = _router.controller<ControllerWithAdvancedFeatures>(
        "/adv_api", &_task_executor, "AsyncImmediateErr");
    ASSERT_NE(controller, nullptr);
    _router.compile();

    auto request = create_request(HTTP_GET, "/adv_api/async_error_immediate");
    _router.route(_mock_session, std::move(request));

    // Error is immediate, no task queued for the handler's core logic
    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(), "AsyncImmediateErr async immediate error");
    EXPECT_EQ(_mock_session->_handler_id_executed, "AsyncImmediateErr_async_error_immediate_handler;");
    ASSERT_FALSE(_mock_session->_controller_method_done); // core async logic (task) not reached
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0);
}

TEST_F(RouterControllerTest, ControllerWithSyncCustomRoute) {
    auto controller = _router.controller<ControllerWithAdvancedFeatures>("/adv_api", &_task_executor, "CtrlSyncCustom");
    ASSERT_NE(controller, nullptr);
    // MyCustomControllerRoute is added inside ControllerWithAdvancedFeatures::initialize_routes
    _router.compile();

    auto request = create_request(HTTP_GET, "/adv_api/custom_sync");
    _router.route(_mock_session, std::move(request));

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(),
              "Response from CtrlSyncCustomSyncCustomRouteImpl (sync custom route)");
    EXPECT_EQ(_mock_session->_handler_id_executed, "CtrlSyncCustomSyncCustomRouteImpl_CUSTOM_SYNC_EXECUTED;");
    EXPECT_TRUE(_mock_session->_controller_method_done);
}

TEST_F(RouterControllerTest, ControllerWithAsyncCustomRoute) {
    auto controller = _router.controller<
        ControllerWithAdvancedFeatures>("/adv_api", &_task_executor, "CtrlAsyncCustom");
    ASSERT_NE(controller, nullptr);
    _router.compile();

    auto request = create_request(HTTP_GET, "/adv_api/custom_async");
    _router.route(_mock_session, std::move(request));

    EXPECT_EQ(_mock_session->_handler_id_executed, "CtrlAsyncCustomAsyncCustomRouteImpl_CUSTOM_ASYNC_HANDLE_CALLED;");
    ASSERT_FALSE(_mock_session->_controller_method_done);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 1);

    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_OK);
    EXPECT_EQ(_mock_session->_response.body().as<std::string>(),
              "Response from CtrlAsyncCustomAsyncCustomRouteImpl (async custom route)");
    EXPECT_EQ(_mock_session->_handler_id_executed,
              "CtrlAsyncCustomAsyncCustomRouteImpl_CUSTOM_ASYNC_HANDLE_CALLED;CtrlAsyncCustomAsyncCustomRouteImpl_CUSTOM_ASYNC_TASK_EXECUTED;");
    EXPECT_TRUE(_mock_session->_controller_method_done);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0);
}

// --- Tests for Controller Error Handling ---

TEST_F(RouterControllerTest, ControllerSyncMethodThrowsException) {
    auto controller = _router.controller<ControllerWithAdvancedFeatures>("/adv_api", &_task_executor, "SyncThrowTest");
    ASSERT_NE(controller, nullptr);
    // Routes are now added in ControllerWithAdvancedFeatures::initialize_routes

    _router.compile();

    auto request = create_request(HTTP_GET, "/adv_api/throw_sync_direct"); // Use the new path
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->_handler_id_executed, "SyncThrowTest_sync_throwing_handler_direct_CALLED");
    ASSERT_FALSE(_mock_session->_controller_method_done);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0);
}

TEST_F(RouterControllerTest, ControllerAsyncMethodThrowsExceptionInTask) {
    auto controller = _router.controller<ControllerWithAdvancedFeatures>(
        "/adv_api", &_task_executor, "AsyncThrowTaskTest");
    ASSERT_NE(controller, nullptr);
    // Routes are now added in ControllerWithAdvancedFeatures::initialize_routes

    _router.compile();

    auto request = create_request(HTTP_GET, "/adv_api/throw_async_in_task"); // Use the new path
    _router.route(_mock_session, std::move(request));

    EXPECT_EQ(_mock_session->_handler_id_executed, "AsyncThrowTaskTest_async_throwing_in_task_handler_CALLED");
    ASSERT_FALSE(_mock_session->_controller_method_done);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 1);

    _task_executor.processAllTasks();

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->_handler_id_executed,
              "AsyncThrowTaskTest_async_throwing_in_task_handler_CALLED;TASK_STARTED_FOR_THROW");
    ASSERT_FALSE(_mock_session->_controller_method_done);
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0);
}

TEST_F(RouterControllerTest, ControllerAsyncMethodThrowsExceptionBeforeTaskExecution) {
    auto controller = _router.controller<ControllerWithAdvancedFeatures>(
        "/adv_api", &_task_executor, "AsyncThrowBeforeTask");
    ASSERT_NE(controller, nullptr);
    _router.compile();

    auto request = create_request(HTTP_GET, "/adv_api/throw_async_before_task");
    _router.route(_mock_session, std::move(request));
    _task_executor.processAllTasks(); // Should be no tasks from this handler path

    EXPECT_EQ(_mock_session->_response.status(), HTTP_STATUS_INTERNAL_SERVER_ERROR);
    EXPECT_EQ(_mock_session->_handler_id_executed, "AsyncThrowBeforeTask_async_throwing_before_task_CALLED");
    ASSERT_FALSE(_mock_session->_controller_method_done); // Method did not complete its async part
    EXPECT_EQ(_task_executor.getPendingTaskCount(), 0); // No task should have been queued
}
